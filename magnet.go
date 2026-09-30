package main

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Magnet link resolution (BEP 0009 metadata exchange over the BEP 0010
// extension protocol).
//
// A magnet link carries only the infohash, so there is no metainfo to read a
// piece map from. The client therefore introduces itself to peers with the
// extension bit set, asks each of them for the info dictionary in 16 KiB
// chunks, and rejects anything whose SHA-1 does not match the btih it was
// given. Without that final hash check a malicious peer could hand us a
// perfectly parseable torrent for the wrong swarm.

const (
	max_metadata_size = 8 << 20 // guard against a hostile metadata_size
	metadata_timeout  = 90 * time.Second
	max_magnet_peers  = 20
)

type magnet_link struct {
	info_hash    [20]byte
	display_name string
	trackers     []string
	length       int64
	peers        []peer
}

func parse_magnet(uri string) (*magnet_link, error) {
	trimmed := strings.TrimSpace(uri)
	if !strings.HasPrefix(strings.ToLower(trimmed), "magnet:") {
		return nil, errors.New("magnet: not a magnet URI")
	}

	// url.Parse treats a rootless scheme as an opaque URI and leaves the query
	// attached to Opaque, so the query is split off by hand.
	mark := strings.Index(trimmed, "?")
	if mark < 0 {
		return nil, errors.New("magnet: URI has no query string")
	}
	values, err := url.ParseQuery(trimmed[mark+1:])
	if err != nil {
		return nil, fmt.Errorf("magnet: malformed query: %w", err)
	}

	m := &magnet_link{display_name: values.Get("dn")}

	for _, xt := range values["xt"] {
		lower := strings.ToLower(xt)
		if !strings.HasPrefix(lower, "urn:btih:") {
			continue
		}
		hash_text := xt[len("urn:btih:"):]
		switch len(hash_text) {
		case 40:
			raw, err := hex.DecodeString(hash_text)
			if err != nil {
				return nil, fmt.Errorf("magnet: bad hex infohash %q", hash_text)
			}
			copy(m.info_hash[:], raw)
		case 32:
			// base32, per BEP 0009
			raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).
				DecodeString(strings.ToUpper(hash_text))
			if err != nil {
				return nil, fmt.Errorf("magnet: bad base32 infohash %q", hash_text)
			}
			copy(m.info_hash[:], raw)
		default:
			return nil, fmt.Errorf("magnet: infohash %q is neither 40 nor 32 characters", hash_text)
		}
	}

	if m.info_hash == ([20]byte{}) {
		return nil, errors.New("magnet: no btih infohash in the link")
	}

	m.trackers = values["tr"]

	if xl := values.Get("xl"); xl != "" {
		if size, err := strconv.ParseInt(xl, 10, 64); err == nil && size > 0 {
			m.length = size
		}
	}

	// BEP 0009 peers, as a convenience for links without trackers.
	for _, addr := range values["x.pe"] {
		if p, ok := parse_peer_address(addr); ok {
			m.peers = append(m.peers, p)
		}
	}

	return m, nil
}

func parse_peer_address(addr string) (peer, bool) {
	host, port_text, err := split_host_port(addr)
	if err != nil {
		return peer{}, false
	}
	port, err := strconv.Atoi(port_text)
	if err != nil || port <= 0 || port > 65535 {
		return peer{}, false
	}
	octets, err := parse_ipv4(host)
	if err != nil {
		return peer{}, false
	}
	p := peer{port: uint16(port)}
	copy(p.ip[:], octets)
	return p, true
}

func split_host_port(addr string) (string, string, error) {
	mark := strings.LastIndex(addr, ":")
	if mark <= 0 || mark == len(addr)-1 {
		return "", "", errors.New("address has no port")
	}
	return addr[:mark], addr[mark+1:], nil
}

func parse_ipv4(host string) ([]byte, error) {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return nil, errors.New("not an IPv4 address")
	}
	out := make([]byte, 4)
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return nil, errors.New("bad IPv4 octet")
		}
		out[i] = byte(value)
	}
	return out, nil
}

// resolve_metadata turns a magnet link into a full torrent by asking peers for
// the info dictionary.
func resolve_metadata(m *magnet_link, cfg *config, peer_id [20]byte, stats *stat_sink) (*torrent_file, error) {
	log.Printf("magnet: resolving %x (%s)", m.info_hash, m.display_name)

	var candidates []peer
	candidates = append(candidates, m.peers...)

	if len(m.trackers) > 0 {
		req := &announce_request{
			info_hash: m.info_hash,
			peer_id:   peer_id,
			port:      cfg.listen_port,
			left:      m.length,
			numwant:   100,
			event:     event_started,
		}
		peers, err := announce_peers(m.trackers, req)
		if err != nil {
			log.Printf("magnet: tracker announce failed: %v", err)
		} else {
			candidates = append(candidates, peers...)
		}
	}

	if len(candidates) == 0 {
		return nil, errors.New("magnet: no peers to fetch metadata from (DHT is out of scope, so a tracker or x.pe is required)")
	}

	seen := make(map[peer]bool)
	attempts := 0
	var last_err error

	for _, p := range candidates {
		if seen[p] || attempts >= max_magnet_peers {
			continue
		}
		seen[p] = true
		attempts++

		info, err := fetch_metadata(p, m.info_hash, peer_id, cfg, stats)
		if err != nil {
			last_err = fmt.Errorf("%s: %w", p, err)
			continue
		}
		if sha1.Sum(info) != m.info_hash {
			last_err = fmt.Errorf("%s: metadata does not hash to the requested infohash", p)
			continue
		}

		root, err := bdecode(info)
		if err != nil {
			last_err = fmt.Errorf("%s: metadata is not valid bencode: %w", p, err)
			continue
		}
		t, err := torrent_from_info(root, first_tracker(m.trackers), [][]string{m.trackers})
		if err != nil {
			last_err = fmt.Errorf("%s: metadata is not a usable info dictionary: %w", p, err)
			continue
		}
		if m.display_name != "" && t.name == "" {
			t.name = m.display_name
		}
		log.Printf("magnet: metadata verified (%d bytes, %d pieces, %d files)", len(info), t.num_pieces(), len(t.files))
		return t, nil
	}

	if last_err == nil {
		last_err = errors.New("no peer offered metadata")
	}
	return nil, fmt.Errorf("magnet: could not fetch metadata: %w", last_err)
}

func first_tracker(trackers []string) string {
	if len(trackers) == 0 {
		return ""
	}
	return trackers[0]
}

// fetch_metadata performs the ut_metadata dance against a single peer.
func fetch_metadata(p peer, info_hash [20]byte, peer_id [20]byte, cfg *config, stats *stat_sink) ([]byte, error) {
	conn, hello, err := dial_and_handshake(p, info_hash, peer_id, cfg, stats)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if !hello.reserved_extended {
		return nil, errors.New("peer does not advertise the extension protocol")
	}

	conn.SetDeadline(time.Now().Add(metadata_timeout))
	defer conn.SetDeadline(time.Time{})

	offer, err := format_extended(0, map[string]interface{}{
		"m":    map[string]interface{}{"ut_metadata": metadata_ext_id},
		"v":    "torrent-client 2.0",
		"reqq": 250,
	})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(offer.serialize()); err != nil {
		return nil, err
	}

	// Wait for the peer's extension handshake, which carries metadata_size.
	metadata_size := 0
	for metadata_size == 0 {
		msg, err := read_message(conn)
		if err != nil {
			return nil, err
		}
		if msg == nil || msg.id != msg_extended {
			continue
		}
		_, body, _, err := parse_extended_body(msg)
		if err != nil || body == nil {
			continue
		}
		if size, err := body.get("metadata_size").as_int(); err == nil {
			metadata_size = int(size)
		}
	}

	if metadata_size <= 0 || metadata_size > max_metadata_size {
		return nil, fmt.Errorf("peer advertised a metadata size of %d bytes", metadata_size)
	}

	pieces := (metadata_size + metadata_block_size - 1) / metadata_block_size
	chunks := make([][]byte, pieces)

	for i := 0; i < pieces; i++ {
		request, err := format_extended(metadata_ext_id, map[string]interface{}{
			"msg_type": metadata_request,
			"piece":    i,
		})
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write(request.serialize()); err != nil {
			return nil, err
		}
	}

	outstanding := pieces
	for outstanding > 0 {
		msg, err := read_message(conn)
		if err != nil {
			return nil, err
		}
		if msg == nil || msg.id != msg_extended {
			continue
		}
		_, body, tail, err := parse_extended_body(msg)
		if err != nil || body == nil {
			continue
		}

		msg_type, type_err := body.get("msg_type").as_int()
		piece, piece_err := body.get("piece").as_int()
		if type_err != nil || piece_err != nil {
			continue
		}
		if int(msg_type) == metadata_reject {
			return nil, fmt.Errorf("peer rejected metadata piece %d", piece)
		}
		if int(msg_type) != metadata_data || piece < 0 || int(piece) >= pieces {
			continue
		}
		if chunks[piece] != nil || len(tail) == 0 {
			continue
		}

		chunk := make([]byte, len(tail))
		copy(chunk, tail)
		chunks[piece] = chunk
		outstanding--
	}

	assembled := make([]byte, 0, metadata_size)
	for i, chunk := range chunks {
		if chunk == nil {
			return nil, fmt.Errorf("metadata piece %d never arrived", i)
		}
		assembled = append(assembled, chunk...)
	}
	if len(assembled) > metadata_size {
		assembled = assembled[:metadata_size]
	}
	return assembled, nil
}
