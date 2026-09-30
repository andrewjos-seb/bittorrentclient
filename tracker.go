package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Tracker communication: HTTP(S) announce (BEP 0003) and UDP announce
// (BEP 0015), with announce-list tiers (BEP 0012).

const udp_tracker_magic = 0x41727101980

// udp_tracker_timeout is the base retransmit interval. The spec prescribes
// 15s and doubling; tests shrink it.
var udp_tracker_timeout = 15 * time.Second

type announce_event int

const (
	event_none announce_event = iota
	event_completed
	event_started
	event_stopped
)

type announce_request struct {
	info_hash  [20]byte
	peer_id    [20]byte
	port       uint16
	uploaded   int64
	downloaded int64
	left       int64
	numwant    int
	event      announce_event
	key        uint32
}

type announce_response struct {
	peers    []peer
	interval time.Duration
	seeders  int
	leechers int
}

const hex_digits = "0123456789ABCDEF"

// escape_bytes percent-encodes every byte outside the unreserved set. We do
// this by hand rather than with url.Values.Encode because Go encodes a space
// as "+", and an infohash is raw binary that can legitimately contain 0x20 —
// a tracker decoding "+" as a space would hash different bytes than we did and
// answer with "invalid infohash".
func escape_bytes(raw []byte) string {
	var sb strings.Builder
	for _, c := range raw {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hex_digits[c>>4])
		sb.WriteByte(hex_digits[c&0x0f])
	}
	return sb.String()
}

// request_peers walks the tracker list in tier order and returns the first
// usable peer set.
func (t *torrent_file) request_peers(req *announce_request) ([]peer, error) {
	trackers := t.tracker_urls()
	if len(trackers) == 0 {
		return nil, errors.New("no trackers in metainfo")
	}
	return announce_peers(trackers, req)
}

// announce_peers is the metainfo-free form, so a magnet link can use it too.
func announce_peers(trackers []string, req *announce_request) ([]peer, error) {
	var last_err error
	for _, tracker := range trackers {
		resp, err := announce(tracker, req)
		if err != nil {
			last_err = fmt.Errorf("%s: %w", tracker, err)
			continue
		}
		if len(resp.peers) == 0 {
			last_err = fmt.Errorf("%s: no peers available", tracker)
			continue
		}
		return resp.peers, nil
	}
	if last_err == nil {
		last_err = errors.New("no trackers returned peers")
	}
	return nil, last_err
}

func announce(tracker string, req *announce_request) (*announce_response, error) {
	parsed, err := url.Parse(tracker)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "udp":
		return udp_announce(parsed, req)
	case "http", "https":
		return http_announce(parsed, req)
	default:
		return nil, fmt.Errorf("unsupported tracker scheme %q", parsed.Scheme)
	}
}

func event_name(e announce_event) string {
	switch e {
	case event_started:
		return "started"
	case event_completed:
		return "completed"
	case event_stopped:
		return "stopped"
	}
	return ""
}

func http_announce(base *url.URL, req *announce_request) (*announce_response, error) {
	event := event_name(req.event)
	numwant := req.numwant
	if numwant <= 0 {
		numwant = 50
	}

	var query strings.Builder
	query.WriteString("?info_hash=" + escape_bytes(req.info_hash[:]))
	query.WriteString("&peer_id=" + escape_bytes(req.peer_id[:]))
	query.WriteString("&port=" + strconv.Itoa(int(req.port)))
	query.WriteString("&uploaded=" + strconv.FormatInt(req.uploaded, 10))
	query.WriteString("&downloaded=" + strconv.FormatInt(req.downloaded, 10))
	query.WriteString("&left=" + strconv.FormatInt(req.left, 10))
	query.WriteString("&compact=1")
	query.WriteString("&numwant=" + strconv.Itoa(numwant))
	if event != "" {
		query.WriteString("&event=" + event)
	}
	if req.key != 0 {
		query.WriteString("&key=" + strconv.FormatUint(uint64(req.key), 16))
	}

	target := *base
	target.RawQuery = strings.TrimPrefix(query.String(), "?")

	http_client := &http.Client{Timeout: 20 * time.Second}
	response, err := http_client.Get(target.String())
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("tracker returned HTTP %d", response.StatusCode)
	}

	return parse_http_announce(body)
}

// parse_http_announce reads a tracker response.
//
// The response schema is a union: `peers` may be a compact byte string
// (BEP 0023), a list of dictionaries, or a dictionary keyed by peer id. A
// struct-targeted decode cannot express that — a mismatched field is silently
// left empty rather than reported — so the response is walked with the
// byte-exact scanner, which reports every form faithfully.
func parse_http_announce(body []byte) (*announce_response, error) {
	root, err := bdecode(body)
	if err != nil {
		return nil, fmt.Errorf("tracker response is not bencode: %w", err)
	}
	if root.kind != bnode_dict {
		return nil, fmt.Errorf("tracker response is not a dictionary")
	}
	if failure := root.get("failure reason"); failure != nil {
		return nil, fmt.Errorf("tracker failure: %s", failure.as_string())
	}

	peers, err := peers_from_node(root.get("peers"))
	if err != nil {
		return nil, err
	}

	interval, _ := root.get("interval").as_int()
	complete, _ := root.get("complete").as_int()
	incomplete, _ := root.get("incomplete").as_int()

	return &announce_response{
		peers:    peers,
		interval: interval_or(int(interval), 30*time.Minute),
		seeders:  int(complete),
		leechers: int(incomplete),
	}, nil
}

func peers_from_node(node *bnode) ([]peer, error) {
	switch {
	case node == nil:
		return nil, nil

	case node.kind == bnode_str:
		return unmarshal_peers(node.as_bytes())

	case node.kind == bnode_list:
		peers := make([]peer, 0, len(node.list))
		for _, entry := range node.list {
			if p, ok := peer_from_dict(entry); ok {
				peers = append(peers, p)
			}
		}
		return peers, nil

	case node.kind == bnode_dict:
		peers := make([]peer, 0, len(node.dict))
		for _, key := range node.keys {
			if p, ok := peer_from_dict(node.dict[key]); ok {
				peers = append(peers, p)
			}
		}
		return peers, nil
	}

	return nil, fmt.Errorf("tracker sent an unrecognised peers value")
}

func peer_from_dict(node *bnode) (peer, bool) {
	if node == nil || node.kind != bnode_dict {
		return peer{}, false
	}
	port, err := node.get("port").as_int()
	if err != nil || port <= 0 || port > 65535 {
		return peer{}, false
	}
	address := node.get("ip").as_string()
	parsed := net.ParseIP(address)
	if parsed == nil || parsed.To4() == nil {
		return peer{}, false
	}
	p := peer{port: uint16(port)}
	copy(p.ip[:], parsed.To4())
	return p, true
}

func interval_or(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	d := time.Duration(seconds) * time.Second
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// --- BEP 0015: UDP tracker protocol ----------------------------------------

func udp_announce(base *url.URL, req *announce_request) (*announce_response, error) {
	conn, err := net.DialTimeout("udp", base.Host, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	connection_id, err := udp_connect(conn)
	if err != nil {
		return nil, err
	}

	var tx_id uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &tx_id); err != nil {
		return nil, err
	}
	key := req.key
	if key == 0 {
		if err := binary.Read(rand.Reader, binary.BigEndian, &key); err != nil {
			return nil, err
		}
	}

	packet := make([]byte, 98)
	binary.BigEndian.PutUint64(packet[0:8], connection_id)
	binary.BigEndian.PutUint32(packet[8:12], 1) // action: announce
	binary.BigEndian.PutUint32(packet[12:16], tx_id)
	copy(packet[16:36], req.info_hash[:])
	copy(packet[36:56], req.peer_id[:])
	binary.BigEndian.PutUint64(packet[56:64], uint64(req.downloaded))
	binary.BigEndian.PutUint64(packet[64:72], uint64(req.left))
	binary.BigEndian.PutUint64(packet[72:80], uint64(req.uploaded))
	binary.BigEndian.PutUint32(packet[80:84], uint32(req.event)) // 0 none, 1 completed, 2 started, 3 stopped
	binary.BigEndian.PutUint32(packet[84:88], 0)                 // default IP
	binary.BigEndian.PutUint32(packet[88:92], key)
	binary.BigEndian.PutUint32(packet[92:96], uint32(req.numwant))
	binary.BigEndian.PutUint16(packet[96:98], req.port)

	// The announce reply is 20 bytes of header plus 6 bytes per peer, so 20 is
	// the minimum acceptable size, not a target.
	reply, err := udp_exchange(conn, packet, tx_id, 1, 20)
	if err != nil {
		return nil, err
	}

	interval := int(binary.BigEndian.Uint32(reply[8:12]))
	leechers := int(binary.BigEndian.Uint32(reply[12:16]))
	seeders := int(binary.BigEndian.Uint32(reply[16:20]))

	peers, err := unmarshal_peers(reply[20:])
	if err != nil {
		return nil, err
	}

	return &announce_response{
		peers:    peers,
		interval: interval_or(interval, 30*time.Minute),
		seeders:  seeders,
		leechers: leechers,
	}, nil
}

func udp_connect(conn net.Conn) (uint64, error) {
	var tx_id uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &tx_id); err != nil {
		return 0, err
	}
	packet := make([]byte, 16)
	binary.BigEndian.PutUint64(packet[0:8], udp_tracker_magic)
	binary.BigEndian.PutUint32(packet[8:12], 0) // action: connect
	binary.BigEndian.PutUint32(packet[12:16], tx_id)

	reply, err := udp_exchange(conn, packet, tx_id, 0, 16)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(reply[8:16]), nil
}

// udp_exchange sends request and waits for a matching reply, retransmitting
// with the exponential backoff the spec requires.
func udp_exchange(conn net.Conn, request []byte, tx_id uint32, action uint32, reply_size int) ([]byte, error) {
	buf := make([]byte, 4096)

	for attempt := 0; attempt < 4; attempt++ {
		timeout := udp_tracker_timeout << uint(attempt)
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		if _, err := conn.Write(request); err != nil {
			return nil, err
		}

		for {
			n, err := conn.Read(buf)
			if err != nil {
				break // timeout: retransmit
			}
			if n < 8 {
				continue
			}
			got_action := binary.BigEndian.Uint32(buf[0:4])
			got_tx := binary.BigEndian.Uint32(buf[4:8])
			if got_tx != tx_id {
				continue
			}
			if got_action == 3 { // error action
				msg := ""
				if n > 8 {
					msg = string(buf[8:n])
				}
				return nil, fmt.Errorf("tracker error: %s", msg)
			}
			if got_action != action {
				return nil, fmt.Errorf("unexpected tracker action %d, want %d", got_action, action)
			}
			if n < reply_size {
				return nil, fmt.Errorf("tracker reply is %d bytes, want at least %d", n, reply_size)
			}
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
	}
	return nil, errors.New("udp tracker did not answer after 4 attempts")
}
