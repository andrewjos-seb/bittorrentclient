package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Shared fixtures. The info dictionary is built here by hand and kept as raw
// bytes, so every test can assert that the client's infohash equals SHA-1 of
// those very bytes.

func build_info(name string, piece_length int, payload []byte, extra map[string]interface{}) []byte {
	pieces := make([]byte, 0)
	for begin := 0; begin < len(payload); begin += piece_length {
		end := begin + piece_length
		if end > len(payload) {
			end = len(payload)
		}
		sum := sha1.Sum(payload[begin:end])
		pieces = append(pieces, sum[:]...)
	}

	info := map[string]interface{}{
		"length":       len(payload),
		"name":         name,
		"piece length": piece_length,
		"pieces":       pieces,
	}
	for k, v := range extra {
		info[k] = v
	}

	raw, err := bencode_bytes(info)
	if err != nil {
		panic(err)
	}
	return raw
}

func build_multi_info(name string, piece_length int, files []struct {
	path string
	data []byte
}, extra map[string]interface{}) ([]byte, []byte) {
	var payload []byte
	var entries []interface{}
	for _, f := range files {
		payload = append(payload, f.data...)
		entries = append(entries, map[string]interface{}{
			"length": len(f.data),
			"path":   []string{f.path},
		})
	}

	pieces := make([]byte, 0)
	for begin := 0; begin < len(payload); begin += piece_length {
		end := begin + piece_length
		if end > len(payload) {
			end = len(payload)
		}
		sum := sha1.Sum(payload[begin:end])
		pieces = append(pieces, sum[:]...)
	}

	info := map[string]interface{}{
		"files":        entries,
		"name":         name,
		"piece length": piece_length,
		"pieces":       pieces,
	}
	for k, v := range extra {
		info[k] = v
	}

	raw, err := bencode_bytes(info)
	if err != nil {
		panic(err)
	}
	return raw, payload
}

func build_torrent(announce string, info_raw []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("d")
	buf.WriteString("8:announce")
	encoded, err := bencode_bytes(announce)
	if err != nil {
		panic(err)
	}
	buf.Write(encoded)
	buf.WriteString("4:info")
	buf.Write(info_raw)
	buf.WriteString("e")
	return buf.Bytes()
}

func write_torrent(t *testing.T, dir, announce string, info_raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, "test.torrent")
	if err := os.WriteFile(path, build_torrent(announce, info_raw), 0o644); err != nil {
		t.Fatalf("could not write torrent: %v", err)
	}
	return path
}

func deterministic_payload(size int) []byte {
	out := make([]byte, size)
	state := uint32(0x9e3779b9)
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = byte(state >> 24)
	}
	return out
}

// --- the infohash ----------------------------------------------------------

func TestInfoHashIsSha1OfRawInfoDictionary(t *testing.T) {
	dir := t.TempDir()
	payload := deterministic_payload(4096)
	info_raw := build_info("hello.bin", 1024, payload, nil)
	path := write_torrent(t, dir, "http://tracker.invalid/announce", info_raw)

	torrent, err := open_torrent(path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	want := sha1.Sum(info_raw)
	if torrent.info_hash != want {
		t.Fatalf("infohash = %x, want %x", torrent.info_hash, want)
	}
	if !bytes.Equal(torrent.info_dict(), info_raw) {
		t.Fatal("info dictionary was not preserved verbatim")
	}
}

// This is the regression that mattered: the original code rebuilt the info
// dictionary from a Go struct and hashed the result. For a real-world
// multi-file torrent that drops `files` and `private` and invents `length`, so
// the digest cannot match — and passing the struct by pointer made
// bencode.Marshal panic outright.
func TestInfoHashSurvivesKeysTheStructDoesNotKnow(t *testing.T) {
	dir := t.TempDir()

	info_raw, _ := build_multi_info("bundle", 1024, []struct {
		path string
		data []byte
	}{
		{"a.txt", deterministic_payload(700)},
		{"b.txt", deterministic_payload(900)},
	}, map[string]interface{}{"private": 1, "source": "unit-test"})

	path := write_torrent(t, dir, "http://tracker.invalid/announce", info_raw)
	torrent, err := open_torrent(path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	want := sha1.Sum(info_raw)
	if torrent.info_hash != want {
		t.Fatalf("infohash = %x, want %x", torrent.info_hash, want)
	}
	if !torrent.multi {
		t.Fatal("multi-file torrent was not recognised")
	}
	if !torrent.private {
		t.Fatal("private flag was not parsed")
	}
	if torrent.length != 1600 {
		t.Fatalf("length = %d, want 1600", torrent.length)
	}

	// Show what the discarded approach would have produced: a dictionary
	// rebuilt from a struct that carries only the four canonical fields, with
	// a fabricated length and the files/private/source keys dropped.
	//
	// (The original also passed the struct by pointer, which bencode-go
	// refuses outright — so on a real multi-file torrent it did not merely
	// compute a wrong digest, it panicked.)
	decoded, err := bdecode(info_raw)
	if err != nil {
		t.Fatalf("bdecode info: %v", err)
	}
	legacy_bytes, err := bencode_bytes(map[string]interface{}{
		"length":       0,
		"name":         "bundle",
		"piece length": 1024,
		"pieces":       decoded.get("pieces").as_bytes(),
	})
	if err != nil {
		t.Fatalf("legacy encode: %v", err)
	}
	if sha1.Sum(legacy_bytes) == torrent.info_hash {
		t.Fatal("the re-marshal approach should not be able to reproduce this infohash")
	}
	if bytes.Equal(legacy_bytes, info_raw) {
		t.Fatal("the rebuilt dictionary should differ from the original bytes")
	}
}

func TestTorrentRejectsPathTraversal(t *testing.T) {
	escaping, _ := build_multi_info("bundle", 1024, []struct {
		path string
		data []byte
	}{
		{"../../etc/passwd", deterministic_payload(64)},
	}, nil)

	if _, err := torrent_from_meta(must_bdecode(t, build_info_dict_with_raw_info(t, escaping))); err == nil {
		t.Fatal("expected a traversal path to be rejected")
	}
}

func must_bdecode(t *testing.T, raw []byte) *bnode {
	t.Helper()
	node, err := bdecode(raw)
	if err != nil {
		t.Fatalf("bdecode: %v", err)
	}
	return node
}

func build_info_dict_with_raw_info(t *testing.T, info_raw []byte) []byte {
	t.Helper()
	return build_torrent("http://tracker.invalid/announce", info_raw)
}

func TestTorrentRejectsInconsistentPieceCount(t *testing.T) {
	// Payload claims 4096 bytes with a 1024 byte piece length, but only one
	// hash is supplied.
	info, err := bencode_bytes(map[string]interface{}{
		"length":       4096,
		"name":         "bad.bin",
		"piece length": 1024,
		"pieces":       make([]byte, 20),
	})
	if err != nil {
		t.Fatal(err)
	}
	root := must_bdecode(t, build_torrent("http://tracker.invalid/announce", info))
	if _, err := torrent_from_meta(root); err == nil {
		t.Fatal("expected an inconsistent piece count to be rejected")
	}
}

// --- bencode ---------------------------------------------------------------

func TestBencodeScannerPreservesRawSpans(t *testing.T) {
	raw := []byte("d1:ai1e1:bl1:x1:ye1:cd1:di2eee")
	root, err := bdecode(raw)
	if err != nil {
		t.Fatalf("bdecode: %v", err)
	}
	if !bytes.Equal(root.get("c").raw, []byte("d1:di2ee")) {
		t.Fatalf("nested dict span = %q", root.get("c").raw)
	}
	if !bytes.Equal(root.get("b").raw, []byte("l1:x1:ye")) {
		t.Fatalf("list span = %q", root.get("b").raw)
	}
	if root.get("a").num != 1 {
		t.Fatalf("integer = %d", root.get("a").num)
	}
}

func TestBencodeRejectsGarbageAndTruncation(t *testing.T) {
	for _, input := range []string{"", "i12", "d1:a", "l1:x", "3:ab", "i1ee", "x"} {
		if _, err := bdecode([]byte(input)); err == nil {
			t.Fatalf("bdecode(%q) should have failed", input)
		}
	}
}

// --- bitfield --------------------------------------------------------------

// The high bit of the first byte is piece 0. The original reader had the bit
// order inverted relative to the writer, which mirrors the whole availability
// map.
func TestBitfieldBitOrderMatchesTheSpec(t *testing.T) {
	bf := new_bitfield(8)
	bf.set_piece(0)
	if bf[0] != 0x80 {
		t.Fatalf("piece 0 set the byte to %#x, want 0x80", bf[0])
	}
	if !bf.has_piece(0) || bf.has_piece(7) {
		t.Fatal("has_piece disagrees with set_piece on byte 0")
	}

	// Wire form: byte 0x01 in the first byte means piece 7, not piece 0.
	from_wire := bitfield_from_bytes([]byte{0x01}, 8)
	if from_wire.has_piece(0) {
		t.Fatal("byte 0x01 marked piece 0 as available; the bit order is mirrored")
	}
	if !from_wire.has_piece(7) {
		t.Fatal("byte 0x01 should mark piece 7")
	}
}

func TestBitfieldRoundTripAndTrailingBits(t *testing.T) {
	const pieces = 21
	bf := new_bitfield(pieces)
	for _, index := range []int{0, 5, 7, 8, 19, 20} {
		bf.set_piece(index)
	}
	for i := 0; i < pieces; i++ {
		want := i == 0 || i == 5 || i == 7 || i == 8 || i == 19 || i == 20
		if bf.has_piece(i) != want {
			t.Fatalf("piece %d: has_piece = %v, want %v", i, bf.has_piece(i), want)
		}
	}
	if bf.count() != 6 {
		t.Fatalf("count = %d, want 6", bf.count())
	}

	// Trailing bits past the piece count must never read as available.
	full := make([]byte, (pieces+7)/8)
	for i := range full {
		full[i] = 0xff
	}
	cleaned := bitfield_from_bytes(full, pieces)
	if cleaned.has_piece(pieces) || cleaned.has_piece(pieces+1) {
		t.Fatal("trailing bits were not masked off")
	}
	if cleaned.count() != pieces {
		t.Fatalf("count = %d, want %d", cleaned.count(), pieces)
	}

	bf.clear_piece(8)
	if bf.has_piece(8) {
		t.Fatal("clear_piece did not clear")
	}
}

func TestBitfieldOutOfRangeIsSafe(t *testing.T) {
	bf := new_bitfield(3)
	if bf.has_piece(100) || bf.has_piece(-1) {
		t.Fatal("out-of-range lookups must report absent")
	}
	bf.set_piece(1000) // must not panic
	bf.clear_piece(-5) // must not panic
	if bf.count() != 0 {
		t.Fatal("out-of-range writes must not change the bitfield")
	}
}

// --- request framing -------------------------------------------------------

// Every wire integer is big-endian. The original wrote request payloads
// little-endian, so a request for index 1, offset 2, length 3 arrived as
// 0x01000000 / 0x02000000 / 0x03000000.
func TestRequestPayloadIsBigEndian(t *testing.T) {
	msg := format_request(1, 2, 3)
	want := []byte{
		0x00, 0x00, 0x00, 0x0d, // frame length: 12 payload + 1 id
		0x06,                   // request
		0x00, 0x00, 0x00, 0x01, // index
		0x00, 0x00, 0x00, 0x02, // begin
		0x00, 0x00, 0x00, 0x03, // length
	}
	got := msg.serialize()
	if !bytes.Equal(got, want) {
		t.Fatalf("request bytes = % x\nwant           % x", got, want)
	}

	parsed, err := parse_request(msg)
	if err != nil {
		t.Fatalf("parse_request: %v", err)
	}
	if parsed.index != 1 || parsed.begin != 2 || parsed.length != 3 {
		t.Fatalf("round trip = %+v", parsed)
	}
}

func TestMessageFramingRoundTrip(t *testing.T) {
	cases := []*message{
		{id: msg_choke},
		{id: msg_unchoke},
		{id: msg_interested},
		{id: msg_not_interested},
		{id: msg_have, payload: []byte{0, 0, 0, 7}},
		{id: msg_bitfield, payload: []byte{0xff, 0x80}},
		{id: msg_piece, payload: append([]byte{0, 0, 0, 1, 0, 0, 0, 0}, []byte("data")...)},
		{id: msg_cancel, payload: make([]byte, 12)},
		{id: msg_port, payload: []byte{0x1a, 0xe1}},
		{id: msg_extended, payload: []byte{0, 'd', 'e'}},
	}

	for _, outbound := range cases {
		raw := outbound.serialize()
		got, err := read_message(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("id %v: read_message: %v", outbound.id, err)
		}
		if got == nil {
			t.Fatalf("id %v: got nil", outbound.id)
		}
		if got.id != outbound.id || !bytes.Equal(got.payload, outbound.payload) {
			t.Fatalf("id %v round trip mismatch: id=%v payload=% x", outbound.id, got.id, got.payload)
		}
	}
}

func TestKeepAliveAndOversizeFrames(t *testing.T) {
	msg, err := read_message(bytes.NewReader(make([]byte, 4)))
	if err != nil || msg != nil {
		t.Fatalf("keep-alive = %v, %v; want nil, nil", msg, err)
	}

	oversize := make([]byte, 4)
	oversize[0] = 0x40 // 64 MiB
	if _, err := read_message(bytes.NewReader(oversize)); err == nil {
		t.Fatal("an oversized frame should be rejected")
	}
}

func TestHandshakeRoundTripAndValidation(t *testing.T) {
	var hash, id [20]byte
	copy(hash[:], "01234567890123456789")
	copy(id[:], "-TC0001-abcdefghijkl")

	raw := new_handshake(hash, id).serialize()
	if len(raw) != 68 {
		t.Fatalf("handshake is %d bytes, want 68", len(raw))
	}
	if raw[0] != 19 || string(raw[1:20]) != "BitTorrent protocol" {
		t.Fatalf("bad protocol string prefix: %q", raw[:20])
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		server.Write(raw)
	}()

	got, err := read_handshake(client)
	if err != nil {
		t.Fatalf("read_handshake: %v", err)
	}
	if got.info_hash != hash || got.peer_id != id {
		t.Fatal("handshake round trip mangled the hashes")
	}
	if got.reserved_extended {
		t.Fatal("extension bit should be clear")
	}

	extended := new_handshake(hash, id)
	extended.reserved_extended = true
	encoded := extended.serialize()
	if encoded[25]&reserved_extended_bit == 0 {
		t.Fatalf("extension reserved bit was not set: %#x", encoded[25])
	}
}

func TestHandshakeRejectsWrongProtocolString(t *testing.T) {
	var hash, id [20]byte
	raw := new_handshake(hash, id).serialize()
	copy(raw[1:20], "NotBitTorrentProto!")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { server.Write(raw) }()

	if _, err := read_handshake(client); err == nil {
		t.Fatal("a foreign protocol string should be rejected")
	}
}

// --- extended messages -----------------------------------------------------

func TestExtendedMessageCarriesBencodeAndTail(t *testing.T) {
	body := map[string]interface{}{"msg_type": 1, "piece": 2, "total_size": 300}
	tail := []byte("raw-metadata-bytes")

	msg, err := format_extended(3, body)
	if err != nil {
		t.Fatalf("format_extended: %v", err)
	}
	if msg.payload[0] != 3 {
		t.Fatalf("extension id = %d, want 3", msg.payload[0])
	}

	// Append a tail the way BEP 0009 metadata blocks do.
	framed := append(msg.payload, tail...)
	ext_id, parsed, got_tail, err := parse_extended_body(&message{id: msg_extended, payload: framed})
	if err != nil {
		t.Fatalf("parse_extended_body: %v", err)
	}
	if ext_id != 3 {
		t.Fatalf("ext id = %d", ext_id)
	}
	if v, _ := parsed.get("msg_type").as_int(); v != 1 {
		t.Fatalf("msg_type = %d", v)
	}
	if !bytes.Equal(got_tail, tail) {
		t.Fatalf("tail = %q, want %q", got_tail, tail)
	}
}

// --- magnet parsing --------------------------------------------------------

func TestParseMagnetHexAndBase32(t *testing.T) {
	raw := deterministic_payload(20)
	hex_hash := hex.EncodeToString(raw)

	link, err := parse_magnet("magnet:?xt=urn:btih:" + hex_hash +
		"&dn=My+Payload&tr=http%3A%2F%2Ftracker.invalid%2Fannounce&xl=12345&x.pe=127.0.0.1:6881")
	if err != nil {
		t.Fatalf("parse_magnet: %v", err)
	}
	if hex.EncodeToString(link.info_hash[:]) != hex_hash {
		t.Fatalf("infohash = %x", link.info_hash)
	}
	if link.display_name != "My Payload" {
		t.Fatalf("display name = %q", link.display_name)
	}
	if len(link.trackers) != 1 || link.trackers[0] != "http://tracker.invalid/announce" {
		t.Fatalf("trackers = %v", link.trackers)
	}
	if link.length != 12345 {
		t.Fatalf("length = %d", link.length)
	}
	if len(link.peers) != 1 || link.peers[0].String() != "127.0.0.1:6881" {
		t.Fatalf("peers = %v", link.peers)
	}

	base32_hash := base32_encode(raw)
	two, err := parse_magnet("magnet:?xt=urn:btih:" + base32_hash)
	if err != nil {
		t.Fatalf("base32 parse: %v", err)
	}
	if two.info_hash != link.info_hash {
		t.Fatal("base32 and hex forms disagree")
	}
}

func TestParseMagnetRejectsBadInput(t *testing.T) {
	bad := []string{
		"http://example.com",
		"magnet:?xt=urn:sha1:abc",
		"magnet:?dn=only-a-name",
		"magnet:?xt=urn:btih:zzzz",
	}
	for _, input := range bad {
		if _, err := parse_magnet(input); err == nil {
			t.Fatalf("parse_magnet(%q) should have failed", input)
		}
	}
}

func TestPieceSizing(t *testing.T) {
	dir := t.TempDir()
	payload := deterministic_payload(1000)
	info_raw := build_info("sizes.bin", 300, payload, nil)
	path := write_torrent(t, dir, "http://tracker.invalid/announce", info_raw)

	torrent, err := open_torrent(path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}
	if torrent.num_pieces() != 4 {
		t.Fatalf("pieces = %d, want 4", torrent.num_pieces())
	}
	sizes := []int64{300, 300, 300, 100}
	for i, want := range sizes {
		if got := torrent.piece_size(i); got != want {
			t.Fatalf("piece_size(%d) = %d, want %d", i, got, want)
		}
		if got := torrent.piece_offset(i); got != int64(i)*300 {
			t.Fatalf("piece_offset(%d) = %d", i, got)
		}
	}
	if torrent.piece_size(4) != 0 {
		t.Fatal("piece_size past the end should be 0")
	}
	if torrent.block_count(3) != 1 {
		t.Fatalf("block_count(3) = %d, want 1", torrent.block_count(3))
	}
}

func base32_encode(raw []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var sb strings.Builder
	buffer := 0
	bits := 0
	for _, b := range raw {
		buffer = buffer<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(buffer>>bits)&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(buffer<<(5-bits))&31])
	}
	return sb.String()
}

var _ = fmt.Sprintf
var _ = time.Second
