package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// One peer connection and everything we know about that peer.
//
// The connection is synchronous per peer: exactly one goroutine reads from it,
// which keeps choke/interest/availability state race-free. Other goroutines
// may still push messages out (for example a `have` broadcast when any peer
// completes a piece), so writes are serialised.

const (
	read_timeout  = 30 * time.Second
	write_timeout = 15 * time.Second
)

// stat_sink is the counter block the dashboard reads. It is passed down from
// the downloader so every peer reports into the same flight log.
type stat_sink struct {
	mu           sync.Mutex
	wire_down    int64
	wire_up      int64
	payload_down int64
	payload_up   int64
}

func (s *stat_sink) add_down(n int64)         { s.mu.Lock(); s.wire_down += n; s.mu.Unlock() }
func (s *stat_sink) add_up(n int64)           { s.mu.Lock(); s.wire_up += n; s.mu.Unlock() }
func (s *stat_sink) add_payload_down(n int64) { s.mu.Lock(); s.payload_down += n; s.mu.Unlock() }
func (s *stat_sink) add_payload_up(n int64)   { s.mu.Lock(); s.payload_up += n; s.mu.Unlock() }

func (s *stat_sink) snapshot() (wire_down, wire_up, payload_down, payload_up int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wire_down, s.wire_up, s.payload_down, s.payload_up
}

// metered_conn counts bytes so the dashboard can report real throughput
// without any of the protocol code knowing about it.
type metered_conn struct {
	net.Conn
	sink *stat_sink
}

func (c *metered_conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.sink.add_down(int64(n))
	}
	return n, err
}

func (c *metered_conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.sink.add_up(int64(n))
	}
	return n, err
}

type peer_conn struct {
	conn       net.Conn
	write_mu   sync.Mutex
	peer       peer
	info_hash  [20]byte
	peer_id    [20]byte
	their_id   [20]byte
	bitfield   bitfield
	num_pieces int

	choked     bool
	interested bool

	// BEP 0010 extension state
	supports_extended bool
	ext_ids           map[string]byte
	our_ext_ids       map[string]byte
	metadata_size     int
	metadata_ut_id    byte

	stats *stat_sink
	cfg   *config
}

func new_peer_conn(p peer, info_hash [20]byte, peer_id [20]byte, num_pieces int, cfg *config, stats *stat_sink) (*peer_conn, error) {
	conn, hello, err := dial_and_handshake(p, info_hash, peer_id, cfg, stats)
	if err != nil {
		return nil, err
	}

	return &peer_conn{
		conn:              conn,
		peer:              p,
		info_hash:         info_hash,
		peer_id:           peer_id,
		their_id:          hello.peer_id,
		bitfield:          new_bitfield(num_pieces),
		num_pieces:        num_pieces,
		choked:            true,
		supports_extended: hello.reserved_extended,
		ext_ids:           make(map[string]byte),
		our_ext_ids:       map[string]byte{"ut_metadata": metadata_ext_id},
		stats:             stats,
		cfg:               cfg,
	}, nil
}

// dial_and_handshake opens a connection, wraps it for metering and pacing, and
// completes the peer handshake. Shared by the download worker and by magnet
// metadata resolution.
func dial_and_handshake(p peer, info_hash [20]byte, peer_id [20]byte, cfg *config, stats *stat_sink) (net.Conn, *handshake, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(cfg.ctx, "tcp", p.String())
	if err != nil {
		return nil, nil, err
	}

	// Stack the wrappers: raw socket <- byte counter <- rate limiter.
	metered := &metered_conn{Conn: raw, sink: stats}
	conn := &throttled_conn{
		Conn: metered,
		ctx:  cfg.ctx,
		down: cfg.down_limiter,
		up:   cfg.up_limiter,
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	out := new_handshake(info_hash, peer_id)
	out.reserved_extended = true
	if _, err := conn.Write(out.serialize()); err != nil {
		conn.Close()
		return nil, nil, err
	}

	in, err := read_handshake(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if in.info_hash != info_hash {
		conn.Close()
		return nil, nil, fmt.Errorf("peer offered infohash %x, we asked for %x", in.info_hash, info_hash)
	}

	return conn, in, nil
}

// prime reads the opening volley (bitfield / have / choke / extension
// handshake) so the piece picker knows what this peer holds. A peer that sends
// no bitfield is not an error: it simply advertises nothing yet, and `have`
// messages will fill the map in as the transfer runs.
func (c *peer_conn) prime() error {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	if c.supports_extended {
		if err := c.send_extended_handshake(true); err != nil {
			return err
		}
	}

	for {
		msg, err := c.read()
		if err != nil {
			if is_timeout(err) {
				return nil
			}
			return err
		}
		if msg == nil {
			continue
		}

		switch msg.id {
		case msg_bitfield:
			c.bitfield = bitfield_from_bytes(msg.payload, c.num_pieces)
			return nil
		case msg_have:
			index, err := parse_have(msg)
			if err != nil {
				return err
			}
			c.bitfield.set_piece(index)
		case msg_choke:
			c.choked = true
		case msg_unchoke:
			c.choked = false
		case msg_extended:
			if err := c.handle_extended(msg); err != nil {
				return err
			}
		default:
			// Anything else this early is either noise or a protocol
			// violation; keep reading until the deadline.
		}
	}
}

func (c *peer_conn) read() (*message, error) {
	c.conn.SetReadDeadline(time.Now().Add(c.cfg.peer_timeout))
	return read_message(c.conn)
}

func (c *peer_conn) send(msg *message) error {
	c.write_mu.Lock()
	defer c.write_mu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(write_timeout))
	_, err := c.conn.Write(msg.serialize())
	return err
}

func (c *peer_conn) send_request(index int, begin, length int64) error {
	return c.send(format_request(index, begin, length))
}

func (c *peer_conn) send_interested() error {
	c.interested = true
	return c.send(&message{id: msg_interested})
}

func (c *peer_conn) send_not_interested() error {
	c.interested = false
	return c.send(&message{id: msg_not_interested})
}

func (c *peer_conn) send_unchoke() error {
	return c.send(&message{id: msg_unchoke})
}

func (c *peer_conn) send_choke() error {
	return c.send(&message{id: msg_choke})
}

func (c *peer_conn) send_have(index int) error {
	return c.send(format_have(index))
}

func (c *peer_conn) send_cancel(req block_request) error {
	return c.send(format_cancel(req))
}

func (c *peer_conn) send_port(port uint16) error {
	return c.send(format_port(port))
}

func (c *peer_conn) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// serving reads a block out of the store and pushes it to the peer. Uploading
// is the mirror image of downloading, and it is what keeps us from being
// throttled to death by the swarm's tit-for-tat policy.
func (c *peer_conn) serve_request(store *piece_store, req block_request) error {
	data, err := store.read_block(int64(req.index)*store.t.piece_length+req.begin, req.length)
	if err != nil {
		return err
	}
	if err := c.send(format_piece(req.index, req.begin, data)); err != nil {
		return err
	}
	c.stats.add_payload_up(int64(len(data)))
	return nil
}

// --- BEP 0010 --------------------------------------------------------------

const metadata_ext_id = 1

func (c *peer_conn) send_extended_handshake(offer_metadata bool) error {
	our_m := map[string]interface{}{}
	if offer_metadata {
		our_m["ut_metadata"] = metadata_ext_id
	}
	body := map[string]interface{}{
		"m":    our_m,
		"v":    "torrent-client 2.0",
		"reqq": 250,
	}
	if c.cfg.listen_port > 0 {
		body["p"] = int(c.cfg.listen_port)
	}
	msg, err := format_extended(0, body)
	if err != nil {
		return err
	}
	return c.send(msg)
}

func (c *peer_conn) handle_extended(msg *message) error {
	ext_id, body, err := parse_extended(msg)
	if err != nil {
		return err
	}
	if ext_id == 0 && body != nil {
		if m := body.get("m"); m != nil && m.kind == bnode_dict {
			for _, name := range m.keys {
				if v, err := m.get(name).as_int(); err == nil && v >= 0 && v < 256 {
					c.ext_ids[name] = byte(v)
				}
			}
		}
		if size, err := body.get("metadata_size").as_int(); err == nil {
			c.metadata_size = int(size)
		}
		if id, ok := c.ext_ids["ut_metadata"]; ok {
			c.metadata_ut_id = id
		}
	}
	return nil
}

func is_timeout(err error) bool {
	var net_err net.Error
	if errors.As(err, &net_err) && net_err.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

func log_peer(p peer, format string, args ...interface{}) {
	log.Printf("[peer %s] "+format, append([]interface{}{p}, args...)...)
}
