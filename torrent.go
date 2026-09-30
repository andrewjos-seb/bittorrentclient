package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// The .torrent metainfo layer.
//
// The one rule that matters here: the infohash is SHA-1 over the *info*
// dictionary's original bytes. We therefore hash info.raw — the exact span the
// bencode scanner consumed — rather than rebuilding the dictionary from a Go
// struct and hashing that. Rebuilding silently discards `files`, `private`,
// `source` and any vendor key, and fabricates `length` on multi-file torrents;
// every one of those changes the digest and makes the client unroutable.

// file_entry is one payload file. Single-file torrents get exactly one
// synthesised entry so that downstream code never needs to special-case them.
type file_entry struct {
	length int64
	path   []string // validated relative components
	offset int64    // absolute offset in the concatenated payload stream
}

type torrent_file struct {
	announce      string
	announce_list [][]string
	info_hash     [20]byte
	info_raw      []byte // verbatim bencoded info dictionary
	piece_hashes  [][20]byte
	piece_length  int64
	length        int64
	name          string
	files         []file_entry
	multi         bool
	private       bool
}

func open_torrent(file_path string) (*torrent_file, error) {
	raw, err := os.ReadFile(file_path)
	if err != nil {
		return nil, err
	}
	root, err := bdecode(raw)
	if err != nil {
		return nil, fmt.Errorf("metainfo: %w", err)
	}
	return torrent_from_meta(root)
}

func torrent_from_meta(root *bnode) (*torrent_file, error) {
	if root == nil || root.kind != bnode_dict {
		return nil, errors.New("metainfo: top level value is not a dictionary")
	}

	announce := root.get("announce").as_string()

	// announce-list (BEP 0012): a list of tiers, each tier a list of URLs.
	var announce_list [][]string
	if al := root.get("announce-list"); al != nil && al.kind == bnode_list {
		for _, tier := range al.list {
			if tier.kind != bnode_list {
				continue
			}
			var urls []string
			for _, item := range tier.list {
				if s := item.as_string(); s != "" {
					urls = append(urls, s)
				}
			}
			if len(urls) > 0 {
				announce_list = append(announce_list, urls)
			}
		}
	}

	return torrent_from_info(root.get("info"), announce, announce_list)
}

// torrent_from_info builds a torrent from an info dictionary alone. Magnet
// resolution uses this: BEP 0009 hands over the info dictionary and nothing
// else, so the tracker list has to come from the magnet link.
func torrent_from_info(info *bnode, announce string, announce_list [][]string) (*torrent_file, error) {
	if info == nil || info.kind != bnode_dict {
		return nil, errors.New("metainfo: missing info dictionary")
	}

	t := &torrent_file{
		announce:      announce,
		announce_list: announce_list,
		info_raw:      info.raw,
		info_hash:     sha1.Sum(info.raw),
	}

	if len(t.info_raw) == 0 {
		return nil, errors.New("metainfo: info dictionary has no bytes")
	}

	if priv := info.get("private"); priv != nil {
		if v, err := priv.as_int(); err == nil && v == 1 {
			t.private = true
		}
	}

	t.name = info.get("name").as_string()
	if t.name == "" {
		t.name = "unnamed"
	}

	piece_length, err := info.get("piece length").as_int()
	if err != nil {
		return nil, errors.New("metainfo: missing or invalid piece length")
	}
	if piece_length <= 0 {
		return nil, fmt.Errorf("metainfo: piece length %d is not positive", piece_length)
	}
	t.piece_length = piece_length

	pieces := info.get("pieces").as_bytes()
	if pieces == nil {
		return nil, errors.New("metainfo: missing pieces")
	}
	if len(pieces)%20 != 0 {
		return nil, fmt.Errorf("metainfo: malformed pieces: %d bytes is not a multiple of 20", len(pieces))
	}
	t.piece_hashes = make([][20]byte, len(pieces)/20)
	for i := range t.piece_hashes {
		copy(t.piece_hashes[i][:], pieces[i*20:(i+1)*20])
	}

	files, total, multi, err := parse_files(info)
	if err != nil {
		return nil, err
	}
	t.files = files
	t.length = total
	t.multi = multi

	if len(t.piece_hashes) == 0 && t.length > 0 {
		return nil, errors.New("metainfo: no piece hashes for a non-empty payload")
	}
	want := (t.length + t.piece_length - 1) / t.piece_length
	if int64(len(t.piece_hashes)) != want {
		return nil, fmt.Errorf("metainfo: %d piece hashes does not match %d pieces of %d bytes",
			len(t.piece_hashes), want, t.piece_length)
	}

	return t, nil
}

func parse_files(info *bnode) ([]file_entry, int64, bool, error) {
	list := info.get("files")
	if list == nil {
		length, err := info.get("length").as_int()
		if err != nil {
			return nil, 0, false, errors.New("metainfo: single-file torrent has no length")
		}
		if length < 0 {
			return nil, 0, false, errors.New("metainfo: negative length")
		}
		name := info.get("name").as_string()
		if err := validate_path_component(name); err != nil {
			return nil, 0, false, fmt.Errorf("metainfo: bad name %q: %w", name, err)
		}
		return []file_entry{{length: length, path: []string{name}}}, length, false, nil
	}

	if list.kind != bnode_list {
		return nil, 0, false, errors.New("metainfo: files is not a list")
	}
	if len(list.list) == 0 {
		return nil, 0, false, errors.New("metainfo: files list is empty")
	}

	var files []file_entry
	var offset int64
	for i, entry := range list.list {
		if entry.kind != bnode_dict {
			return nil, 0, false, fmt.Errorf("metainfo: files[%d] is not a dictionary", i)
		}
		length, err := entry.get("length").as_int()
		if err != nil {
			return nil, 0, false, fmt.Errorf("metainfo: files[%d] has no length", i)
		}
		if length < 0 {
			return nil, 0, false, fmt.Errorf("metainfo: files[%d] has negative length", i)
		}

		parts := entry.get("path")
		if parts == nil || parts.kind != bnode_list || len(parts.list) == 0 {
			return nil, 0, false, fmt.Errorf("metainfo: files[%d] has no path", i)
		}
		components := make([]string, 0, len(parts.list))
		for _, part := range parts.list {
			component := part.as_string()
			if err := validate_path_component(component); err != nil {
				return nil, 0, false, fmt.Errorf("metainfo: files[%d]: %w", i, err)
			}
			components = append(components, component)
		}

		files = append(files, file_entry{length: length, path: components, offset: offset})
		offset += length
	}
	return files, offset, true, nil
}

// validate_path_component rejects anything that could escape the output
// directory. A hostile torrent must not be able to write outside the tree.
func validate_path_component(component string) error {
	if component == "" {
		return errors.New("empty path component")
	}
	if component == "." || component == ".." {
		return errors.New("relative path component")
	}
	if strings.ContainsAny(component, `/\`) {
		return errors.New("path component contains a separator")
	}
	if strings.ContainsRune(component, 0) {
		return errors.New("path component contains a NUL")
	}
	if path.IsAbs(component) {
		return errors.New("absolute path component")
	}
	return nil
}

func (t *torrent_file) num_pieces() int {
	return len(t.piece_hashes)
}

// piece_size is the on-wire length of a piece. The final piece is usually
// short; if it is not, the metainfo was inconsistent and we said so already.
func (t *torrent_file) piece_size(index int) int64 {
	begin := int64(index) * t.piece_length
	if begin >= t.length {
		return 0
	}
	remaining := t.length - begin
	if remaining < t.piece_length {
		return remaining
	}
	return t.piece_length
}

func (t *torrent_file) piece_offset(index int) int64 {
	return int64(index) * t.piece_length
}

func (t *torrent_file) block_count(index int) int {
	return int((t.piece_size(index) + block_size - 1) / block_size)
}

// info_dict returns the verbatim info dictionary, which is what BEP 0009
// metadata exchange hands to magnet peers.
func (t *torrent_file) info_dict() []byte {
	return t.info_raw
}

// tracker_urls flattens announce plus announce-list tiers, keeping tier order.
func (t *torrent_file) tracker_urls() []string {
	var urls []string
	seen := make(map[string]bool)
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		urls = append(urls, u)
	}
	add(t.announce)
	for _, tier := range t.announce_list {
		for _, u := range tier {
			add(u)
		}
	}
	return urls
}

type peer struct {
	ip   [4]byte
	port uint16
}

func (p peer) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", p.ip[0], p.ip[1], p.ip[2], p.ip[3], p.port)
}

// unmarshal_peers decodes the compact form (BEP 0023): 6 bytes per peer.
func unmarshal_peers(data []byte) ([]peer, error) {
	if len(data)%6 != 0 {
		return nil, fmt.Errorf("malformed peers: length %d is not a multiple of 6", len(data))
	}

	peers := make([]peer, 0, len(data)/6)
	for i := 0; i+6 <= len(data); i += 6 {
		p := peer{port: binary.BigEndian.Uint16(data[i+4 : i+6])}
		copy(p.ip[:], data[i:i+4])
		if p.port == 0 || p.ip == [4]byte{} {
			continue
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// new_peer_id builds an Azureus-style peer id so the swarm can identify us.
func new_peer_id() ([20]byte, error) {
	var id [20]byte
	copy(id[:], []byte("-TC0001-"))
	if _, err := rand.Read(id[8:]); err != nil {
		return id, err
	}
	for i := 8; i < 20; i++ {
		id[i] = 'a' + id[i]%26
	}
	return id, nil
}
