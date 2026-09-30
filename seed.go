package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The seeding side: a TCP listener that answers incoming peer handshakes and
// uploads pieces we already hold.
//
// It is deliberately the mirror image of the download worker: same framing,
// same handshake validation, and the same store is read for blocks. The only
// extra policy is a small unchoke budget, which is what every real client uses
// to decide who gets to pull from us.

const (
	metadata_block_size = 16384 // BEP 0009 metadata pieces are always 16 KiB
	upload_slots        = 8
)

type seeder struct {
	t         *torrent_file
	store     *piece_store
	peer_id   [20]byte
	cfg       *config
	stats     *stat_sink
	has_piece func(index int) bool

	listener net.Listener
	ctx      context.Context

	mu      sync.Mutex
	conns   map[*seed_session]bool
	slots   chan struct{}
	uploads int64
	closed  atomic.Bool
}

// seed_session is one inbound peer.
type seed_session struct {
	conn           net.Conn
	their_id       [20]byte
	interested     bool
	unchoked       bool
	holds_slot     bool
	ext_ids        map[string]byte
	metadata_id    byte
	wants_extended bool
}

func new_seeder(t *torrent_file, store *piece_store, peer_id [20]byte, cfg *config, stats *stat_sink, has_piece func(int) bool) (*seeder, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.listen_port))
	if err != nil {
		return nil, err
	}
	s := &seeder{
		t:         t,
		store:     store,
		peer_id:   peer_id,
		cfg:       cfg,
		stats:     stats,
		has_piece: has_piece,
		listener:  listener,
		conns:     make(map[*seed_session]bool),
		slots:     make(chan struct{}, upload_slots),
	}
	return s, nil
}

func (s *seeder) addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *seeder) serve(ctx context.Context) error {
	s.ctx = ctx
	go func() {
		<-ctx.Done()
		s.close()
	}()

	for {
		raw, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle_incoming(raw)
	}
}

func (s *seeder) close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	for session := range s.conns {
		session.conn.Close()
	}
	s.mu.Unlock()
	return nil
}

func (s *seeder) track(session *seed_session, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[session] = true
	} else {
		delete(s.conns, session)
	}
}

// broadcast_have pushes a freshly completed piece to every inbound peer, so a
// client that is still downloading can seed what it already has.
func (s *seeder) broadcast_have(index int) {
	s.mu.Lock()
	sessions := make([]*seed_session, 0, len(s.conns))
	for session := range s.conns {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()

	msg := format_have(index)
	for _, session := range sessions {
		session.conn.Write(msg.serialize())
	}
}

func (s *seeder) current_bitfield() bitfield {
	available := new_bitfield(s.t.num_pieces())
	for i := 0; i < s.t.num_pieces(); i++ {
		if s.has_piece(i) {
			available.set_piece(i)
		}
	}
	return available
}

func (s *seeder) handle_incoming(raw net.Conn) {
	session := &seed_session{
		ext_ids: make(map[string]byte),
	}
	defer func() {
		if session.holds_slot {
			<-s.slots
		}
		s.track(session, false)
		raw.Close()
	}()

	metered := &metered_conn{Conn: raw, sink: s.stats}
	conn := &throttled_conn{
		Conn: metered,
		ctx:  s.ctx,
		down: s.cfg.down_limiter,
		up:   s.cfg.up_limiter,
	}
	session.conn = conn

	raw.SetDeadline(time.Now().Add(20 * time.Second))
	hello, err := read_handshake(conn)
	if err != nil {
		log.Printf("seeding: bad handshake from %s: %v", raw.RemoteAddr(), err)
		return
	}
	if hello.info_hash != s.t.info_hash {
		log.Printf("seeding: %s asked for infohash %x, which we do not serve", raw.RemoteAddr(), hello.info_hash)
		return
	}
	session.their_id = hello.peer_id
	session.wants_extended = hello.reserved_extended

	reply := new_handshake(s.t.info_hash, s.peer_id)
	reply.reserved_extended = true
	if _, err := conn.Write(reply.serialize()); err != nil {
		return
	}
	raw.SetDeadline(time.Time{})

	if available := s.current_bitfield(); len(available) > 0 {
		if _, err := conn.Write((&message{id: msg_bitfield, payload: available}).serialize()); err != nil {
			return
		}
	}
	if session.wants_extended {
		// BEP 0009 requires the info dictionary size up front: a magnet peer
		// learns how many metadata blocks to ask for from this field.
		body := map[string]interface{}{
			"m":    map[string]interface{}{"ut_metadata": metadata_ext_id},
			"v":    "torrent-client 2.0",
			"reqq": 250,
		}
		if info := s.t.info_dict(); len(info) > 0 {
			body["metadata_size"] = len(info)
		}
		if msg, err := format_extended(0, body); err == nil {
			conn.Write(msg.serialize())
		}
	}

	s.track(session, true)
	log.Printf("seeding: %s connected (peer id %x)", raw.RemoteAddr(), session.their_id)

	for {
		if s.closed.Load() || s.ctx.Err() != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Minute))
		msg, err := read_message(conn)
		if err != nil {
			return
		}
		if msg == nil {
			continue
		}

		switch msg.id {
		case msg_interested:
			session.interested = true
			s.maybe_unchoke(session)

		case msg_not_interested:
			session.interested = false
			if session.holds_slot {
				<-s.slots
				session.holds_slot = false
			}
			session.unchoked = false
			conn.Write((&message{id: msg_choke}).serialize())

		case msg_request:
			req, err := parse_request(msg)
			if err != nil {
				return
			}
			if !session.unchoked {
				continue
			}
			if err := s.serve_block(session, req); err != nil {
				atomic.AddInt64(&s.uploads, 0)
				return
			}

		case msg_cancel:
			// Blocks are served synchronously, so there is nothing queued.

		case msg_bitfield, msg_have:
			// Remote availability is not needed to serve, only to log.

		case msg_extended:
			if err := s.handle_extended(session, msg); err != nil {
				return
			}

		case msg_choke, msg_unchoke, msg_port:
			// Nothing to do: we drive the choke state on this side.
		}
	}
}

func (s *seeder) maybe_unchoke(session *seed_session) {
	if session.unchoked {
		return
	}
	select {
	case s.slots <- struct{}{}:
		session.holds_slot = true
		session.unchoked = true
		session.conn.Write((&message{id: msg_unchoke}).serialize())
	default:
		// Upload budget is full; the peer stays choked for now.
	}
}

func (s *seeder) serve_block(session *seed_session, req block_request) error {
	if req.index < 0 || req.index >= s.t.num_pieces() {
		return fmt.Errorf("seeding: request for piece %d is out of range", req.index)
	}
	if !s.has_piece(req.index) {
		// We do not hold it after all: choke so the peer re-plans.
		session.unchoked = false
		if session.holds_slot {
			<-s.slots
			session.holds_slot = false
		}
		_, err := session.conn.Write((&message{id: msg_choke}).serialize())
		return err
	}

	data, err := s.store.read_block(s.t.piece_offset(req.index)+req.begin, req.length)
	if err != nil {
		return err
	}
	if _, err := session.conn.Write(format_piece(req.index, req.begin, data).serialize()); err != nil {
		return err
	}

	atomic.AddInt64(&s.uploads, int64(len(data)))
	s.stats.add_payload_up(int64(len(data)))
	return nil
}

// --- BEP 0009 metadata exchange --------------------------------------------

const (
	metadata_request = 0
	metadata_data    = 1
	metadata_reject  = 2
)

func (s *seeder) handle_extended(session *seed_session, msg *message) error {
	ext_id, body, tail, err := parse_extended_body(msg)
	if err != nil {
		return err
	}
	_ = tail

	if ext_id == 0 && body != nil {
		if m := body.get("m"); m != nil && m.kind == bnode_dict {
			for _, name := range m.keys {
				if v, err := m.get(name).as_int(); err == nil && v >= 0 && v < 256 {
					session.ext_ids[name] = byte(v)
				}
			}
		}
		if id, ok := session.ext_ids["ut_metadata"]; ok {
			session.metadata_id = id
		}
		return nil
	}

	if body == nil {
		return nil
	}
	msg_type, err := body.get("msg_type").as_int()
	if err != nil {
		return nil
	}
	piece, err := body.get("piece").as_int()
	if err != nil {
		return nil
	}

	switch int(msg_type) {
	case metadata_request:
		return s.serve_metadata(session, int(piece), ext_id)
	default:
		return nil
	}
}

// serve_metadata answers a magnet peer's request for a chunk of the info
// dictionary, which is how a link with no .torrent behind it gets bootstrapped.
func (s *seeder) serve_metadata(session *seed_session, piece int, ext_id byte) error {
	info := s.t.info_dict()
	if info == nil {
		return nil
	}

	pieces := (len(info) + metadata_block_size - 1) / metadata_block_size

	respond := func(body map[string]interface{}, data []byte) error {
		raw, err := bencode_bytes(body)
		if err != nil {
			return err
		}
		payload := make([]byte, 0, 1+len(raw)+len(data))
		payload = append(payload, ext_id)
		payload = append(payload, raw...)
		payload = append(payload, data...)
		_, err = session.conn.Write((&message{id: msg_extended, payload: payload}).serialize())
		return err
	}

	if piece < 0 || piece >= pieces {
		return respond(map[string]interface{}{
			"msg_type": metadata_reject,
			"piece":    piece,
		}, nil)
	}

	begin := piece * metadata_block_size
	end := begin + metadata_block_size
	if end > len(info) {
		end = len(info)
	}

	return respond(map[string]interface{}{
		"msg_type":   metadata_data,
		"piece":      piece,
		"total_size": len(info),
	}, info[begin:end])
}
