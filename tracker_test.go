package main

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- percent encoding ------------------------------------------------------

// The infohash is raw binary and can contain a space byte. Go's
// url.Values.Encode writes a space as "+", which a tracker decodes back to a
// space only by accident — strict %20 escaping is what every real client does.
func TestEscapeBytesUsesPercentEscapesOnly(t *testing.T) {
	cases := map[string]string{
		"abcXYZ019-_.~": "abcXYZ019-_.~",
		" ":             "%20",
		"+":             "%2B",
		"&":             "%26",
		"=":             "%3D",
		"/":             "%2F",
		"\x00":          "%00",
		"\xff":          "%FF",
	}
	for input, want := range cases {
		if got := escape_bytes([]byte(input)); got != want {
			t.Fatalf("escape_bytes(%q) = %q, want %q", input, got, want)
		}
	}

	// A whole 20 byte hash of spaces must never contain a plus sign.
	var spaces [20]byte
	for i := range spaces {
		spaces[i] = 0x20
	}
	encoded := escape_bytes(spaces[:])
	if strings.Contains(encoded, "+") {
		t.Fatal("a space byte was encoded as '+', which trackers do not decode")
	}
	if strings.Count(encoded, "%20") != 20 {
		t.Fatalf("expected twenty %%20 escapes, got %q", encoded)
	}
}

func TestAnnounceSendsExactInfoHashBytes(t *testing.T) {
	var (
		mu        sync.Mutex
		raw_query string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		raw_query = r.URL.RawQuery
		mu.Unlock()
		body, _ := bencode_bytes(map[string]interface{}{"interval": 60, "peers": []byte{}})
		w.Write(body)
	}))
	defer server.Close()

	req := &announce_request{
		info_hash: [20]byte{0x20},
		peer_id:   [20]byte{'+', '&'},
		port:      6881,
		left:      4242,
		numwant:   50,
		event:     event_started,
	}
	base, err := url.Parse(server.URL + "/announce")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := http_announce(base, req); err != nil {
		t.Fatalf("http_announce: %v", err)
	}

	mu.Lock()
	query := raw_query
	mu.Unlock()

	if strings.Contains(query, "+") {
		t.Fatalf("query contains '+': %q", query)
	}
	for _, want := range []string{"%20", "%2B", "%26", "compact=1", "left=4242", "event=started", "port=6881"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query %q is missing %q", query, want)
		}
	}
}

// --- HTTP tracker responses ------------------------------------------------

func TestParseHTTPAnnounceCompactPeers(t *testing.T) {
	compact := []byte{127, 0, 0, 1, 0x1a, 0xe1, 10, 0, 0, 5, 0x00, 0x50}
	body, err := bencode_bytes(map[string]interface{}{
		"interval":   900,
		"complete":   12,
		"incomplete": 3,
		"peers":      compact,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	resp, err := parse_http_announce(body)
	if err != nil {
		t.Fatalf("parse_http_announce: %v", err)
	}
	if len(resp.peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(resp.peers))
	}
	if resp.peers[0].String() != "127.0.0.1:6881" {
		t.Fatalf("first peer = %s", resp.peers[0])
	}
	if resp.seeders != 12 || resp.leechers != 3 {
		t.Fatalf("seeders/leechers = %d/%d", resp.seeders, resp.leechers)
	}
	if resp.interval != 900*time.Second {
		t.Fatalf("interval = %s", resp.interval)
	}
}

func TestParseHTTPAnnounceDictionaryModelPeers(t *testing.T) {
	body, err := bencode_bytes(map[string]interface{}{
		"interval": 30,
		"peers": []interface{}{
			map[string]interface{}{"ip": "192.168.1.10", "port": 51413, "peer id": "-XX0001-abcdefghijkl"},
			map[string]interface{}{"ip": "not-an-ip", "port": 1},
			map[string]interface{}{"ip": "10.0.0.9", "port": 0},
		},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	resp, err := parse_http_announce(body)
	if err != nil {
		t.Fatalf("parse_http_announce: %v", err)
	}
	if len(resp.peers) != 1 {
		t.Fatalf("peers = %d, want 1 (invalid entries dropped)", len(resp.peers))
	}
	if resp.peers[0].String() != "192.168.1.10:51413" {
		t.Fatalf("peer = %s", resp.peers[0])
	}
}

func TestParseHTTPAnnounceFailure(t *testing.T) {
	body, err := bencode_bytes(map[string]interface{}{"failure reason": "unregistered torrent"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := parse_http_announce(body); err == nil {
		t.Fatal("a failure reason should surface as an error")
	} else if !strings.Contains(err.Error(), "unregistered torrent") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseHTTPAnnounceRejectsNonBencode(t *testing.T) {
	if _, err := parse_http_announce([]byte("<html>not a tracker</html>")); err == nil {
		t.Fatal("an HTML body should be rejected")
	}
}

func TestUnmarshalPeersRejectsRaggedInput(t *testing.T) {
	if _, err := unmarshal_peers([]byte{1, 2, 3}); err == nil {
		t.Fatal("a 3 byte peer block should be rejected")
	}
	peers, err := unmarshal_peers([]byte{127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("unmarshal_peers: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("zero ports and zero addresses should be dropped, got %d", len(peers))
	}
}

func TestTrackerURLsDeduplicateAndKeepOrder(t *testing.T) {
	torrent := &torrent_file{
		announce:      "http://first/announce",
		announce_list: [][]string{{"http://second/announce"}, {"http://first/announce", "udp://third:6969"}},
	}
	urls := torrent.tracker_urls()
	want := []string{"http://first/announce", "http://second/announce", "udp://third:6969"}
	if len(urls) != len(want) {
		t.Fatalf("urls = %v", urls)
	}
	for i := range want {
		if urls[i] != want[i] {
			t.Fatalf("urls[%d] = %q, want %q", i, urls[i], want[i])
		}
	}
}

// --- BEP 0015 UDP tracker --------------------------------------------------

func TestUDPTrackerConnectAndAnnounce(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var (
		mu           sync.Mutex
		announced    bool
		got_infohash []byte
	)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			action := binary.BigEndian.Uint32(buf[8:12])
			tx := binary.BigEndian.Uint32(buf[12:16])

			switch action {
			case 0:
				reply := make([]byte, 16)
				binary.BigEndian.PutUint32(reply[0:4], 0)
				binary.BigEndian.PutUint32(reply[4:8], tx)
				binary.BigEndian.PutUint64(reply[8:16], 0x1122334455667788)
				listener.WriteTo(reply, addr)
			case 1:
				if n < 98 {
					continue
				}
				mu.Lock()
				announced = true
				got_infohash = append([]byte(nil), buf[16:36]...)
				mu.Unlock()

				reply := make([]byte, 20+6)
				binary.BigEndian.PutUint32(reply[0:4], 1)
				binary.BigEndian.PutUint32(reply[4:8], tx)
				binary.BigEndian.PutUint32(reply[8:12], 1800)
				binary.BigEndian.PutUint32(reply[12:16], 7)
				binary.BigEndian.PutUint32(reply[16:20], 9)
				copy(reply[20:], []byte{10, 20, 30, 40, 0x1a, 0xe1})
				listener.WriteTo(reply, addr)
			}
		}
	}()

	previous := udp_tracker_timeout
	udp_tracker_timeout = 2 * time.Second
	defer func() { udp_tracker_timeout = previous }()

	req := &announce_request{
		info_hash: [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		peer_id:   [20]byte{'a'},
		port:      6881,
		left:      1000,
		numwant:   25,
		event:     event_started,
	}

	resp, err := udp_announce(&url.URL{Scheme: "udp", Host: listener.LocalAddr().String()}, req)
	if err != nil {
		t.Fatalf("udp_announce: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !announced {
		t.Fatal("the tracker never received an announce")
	}
	if string(got_infohash) != string(req.info_hash[:]) {
		t.Fatalf("infohash on the wire = %v", got_infohash)
	}
	if len(resp.peers) != 1 || resp.peers[0].String() != "10.20.30.40:6881" {
		t.Fatalf("peers = %v", resp.peers)
	}
	if resp.interval != 1800*time.Second {
		t.Fatalf("interval = %s", resp.interval)
	}
	if resp.seeders != 9 || resp.leechers != 7 {
		t.Fatalf("seeders/leechers = %d/%d", resp.seeders, resp.leechers)
	}
}

func TestUDPTrackerReportsErrors(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			tx := binary.BigEndian.Uint32(buf[12:16])
			reply := make([]byte, 8+len("bad client"))
			binary.BigEndian.PutUint32(reply[0:4], 3) // error action
			binary.BigEndian.PutUint32(reply[4:8], tx)
			copy(reply[8:], "bad client")
			listener.WriteTo(reply, addr)
		}
	}()

	previous := udp_tracker_timeout
	udp_tracker_timeout = 2 * time.Second
	defer func() { udp_tracker_timeout = previous }()

	_, err = udp_announce(&url.URL{Scheme: "udp", Host: listener.LocalAddr().String()}, &announce_request{
		info_hash: [20]byte{9},
		peer_id:   [20]byte{'b'},
		port:      6881,
	})
	if err == nil {
		t.Fatal("an error action should surface as an error")
	}
	if !strings.Contains(err.Error(), "bad client") {
		t.Fatalf("error = %v", err)
	}
}
