package main

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// The download engine.
//
// The original scheduling loop had two defects that compounded into a total
// stall, and both are addressed structurally here rather than patched:
//
//   - `backlog` was incremented when a block request was sent and never
//     decremented when the block arrived. Once the pipeline filled, the worker
//     could not issue another request, so a single lost block ended the
//     transfer.
//
//   - A worker that pulled a piece it did not hold pushed it straight back
//     onto the same channel it was reading from. With a full buffer that push
//     blocks forever and every worker wedges; even with room, every worker
//     spins re-offering work nobody can do. The peer count handed to the
//     connection was also derived from `len(work_ch)` — the channel's pending
//     work, not the torrent's piece count — so the availability map was
//     truncated and most pieces looked unowned.
//
// Here, the piece picker only ever hands a peer a piece that peer advertised,
// block-level state lives in the piece itself, and every failure path releases
// the piece back to the pool so a stalled peer cannot strand work.

const block_size = 16384

// max_backlog is the pipelining depth: how many block requests may be in
// flight to one peer before the worker waits for answers.
const max_backlog = 8

// max_workers caps concurrent peer connections.
const max_workers = 30

type piece_work struct {
	index  int
	hash   [20]byte
	length int64
}

type piece_result struct {
	index int
	data  []byte
}

type block_state uint8

const (
	block_missing block_state = iota
	block_pending
	block_have
)

// piece_progress is the receive state for one piece being pulled from one
// peer. `backlog` is the count of requests written but not yet answered, and
// it is decremented when a block lands — the bookkeeping the original was
// missing.
type piece_progress struct {
	index      int
	buf        []byte
	blocks     []block_state
	backlog    int
	downloaded int64
	requested  int64
}

func new_piece_progress(pw *piece_work) *piece_progress {
	return &piece_progress{
		index:  pw.index,
		buf:    make([]byte, pw.length),
		blocks: make([]block_state, (pw.length+block_size-1)/block_size),
	}
}

// fill_requests tops the pipeline up to max_backlog with the next blocks that
// are neither in flight nor already held.
func (pp *piece_progress) fill_requests(c *peer_conn) error {
	for i := range pp.blocks {
		if pp.backlog >= max_backlog {
			return nil
		}
		if pp.blocks[i] != block_missing {
			continue
		}

		begin := int64(i) * block_size
		length := int64(block_size)
		if begin+length > int64(len(pp.buf)) {
			length = int64(len(pp.buf)) - begin
		}
		if length <= 0 {
			continue
		}

		if err := c.send_request(pp.index, begin, length); err != nil {
			return err
		}
		pp.blocks[i] = block_pending
		pp.backlog++
		pp.requested += length
	}
	return nil
}

// accept files an incoming block. Duplicate blocks (which endgame mode elicits)
// are accepted silently the first time and ignored afterwards.
func (pp *piece_progress) accept(msg *message) (int, error) {
	index, begin, data, err := piece_header(msg)
	if err != nil {
		return 0, err
	}
	if index != pp.index {
		return 0, fmt.Errorf("expected piece %d, got %d", pp.index, index)
	}
	if begin < 0 || begin%block_size != 0 {
		return 0, fmt.Errorf("block begin %d is not on a block boundary", begin)
	}
	block := int(begin / block_size)
	if block >= len(pp.blocks) {
		return 0, fmt.Errorf("block %d is outside piece %d", block, pp.index)
	}

	if pp.blocks[block] == block_have {
		return 0, nil
	}

	n, err := parse_piece(pp.index, pp.buf, msg)
	if err != nil {
		return 0, err
	}
	_ = data

	previous := pp.blocks[block]
	pp.blocks[block] = block_have
	if previous == block_pending {
		pp.backlog--
	}
	pp.downloaded += int64(n)
	return n, nil
}

// reset_pending returns in-flight blocks to the pool after a peer gives up, so
// the next peer can request them.
func (pp *piece_progress) reset_pending() {
	for i, state := range pp.blocks {
		if state == block_pending {
			pp.blocks[i] = block_missing
		}
	}
	pp.backlog = 0
}

func (pp *piece_progress) complete() bool {
	for _, state := range pp.blocks {
		if state != block_have {
			return false
		}
	}
	return true
}

func hash_piece(data []byte) [20]byte {
	return sha1.Sum(data)
}

func check_integrity(pw *piece_work, data []byte) error {
	if hash_piece(data) != pw.hash {
		return fmt.Errorf("piece %d failed integrity check", pw.index)
	}
	return nil
}

type piece_state uint8

const (
	piece_missing piece_state = iota
	piece_in_progress
	piece_complete
)

type downloader struct {
	t       *torrent_file
	cfg     *config
	stats   *stat_sink
	store   *piece_store
	peer_id [20]byte

	mu           sync.Mutex
	states       []piece_state
	availability []int
	sessions     map[*peer_conn]bool
	known        map[peer]bool

	completed_pieces int
	completed_bytes  int64
	resumed_pieces   int
	last_progress    time.Time
	last_save        time.Time
	announce_fails   int
	tracker_interval time.Duration
	started          time.Time

	seeder *seeder
	dash   *dashboard

	// ctx scopes the transfer itself; root_ctx outlives it so the seeding
	// listener can keep serving after the download finishes.
	ctx      context.Context
	cancel   context.CancelFunc
	root_ctx context.Context

	wg           sync.WaitGroup
	worker_slots chan struct{}
}

func new_downloader(t *torrent_file, cfg *config, store *piece_store, peer_id [20]byte, stats *stat_sink) *downloader {
	d := &downloader{
		t:                t,
		cfg:              cfg,
		stats:            stats,
		store:            store,
		peer_id:          peer_id,
		states:           make([]piece_state, t.num_pieces()),
		availability:     make([]int, t.num_pieces()),
		sessions:         make(map[*peer_conn]bool),
		known:            make(map[peer]bool),
		last_progress:    time.Now(),
		tracker_interval: 30 * time.Minute,
		worker_slots:     make(chan struct{}, max_workers),
		root_ctx:         cfg.ctx,
	}
	// Peers belong to the transfer scope, so finishing the download tears
	// down every connection instead of leaving reads parked.
	d.ctx, d.cancel = context.WithCancel(cfg.ctx)
	cfg.ctx = d.ctx
	return d
}

// --- state access ----------------------------------------------------------

func (d *downloader) is_complete() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.completed_pieces >= d.t.num_pieces()
}

func (d *downloader) has_piece(index int) bool {
	if index < 0 || index >= len(d.states) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.states[index] == piece_complete
}

func (d *downloader) mark_progress() {
	d.mu.Lock()
	d.last_progress = time.Now()
	d.mu.Unlock()
}

// pick_piece chooses the rarest piece this peer actually holds and that nobody
// is holding a claim on. Returning -1 means "nothing for this peer", which the
// worker answers by idling — never by re-offering work back into a channel.
func (d *downloader) pick_piece(bf bitfield, endgame bool) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	best := -1
	best_availability := 0

	for i := 0; i < d.t.num_pieces(); i++ {
		if d.states[i] == piece_complete {
			continue
		}
		if !bf.has_piece(i) {
			continue
		}
		if d.states[i] == piece_in_progress {
			if !endgame {
				continue
			}
			return i
		}

		avail := d.availability[i]
		if best == -1 || avail < best_availability {
			best, best_availability = i, avail
		}
	}

	if best >= 0 {
		d.states[best] = piece_in_progress
	}
	return best
}

func (d *downloader) release_piece(index int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.states) {
		return
	}
	if d.states[index] == piece_in_progress {
		d.states[index] = piece_missing
	}
}

func (d *downloader) endgame() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.states {
		if d.states[i] == piece_missing && d.availability[i] > 0 {
			return false
		}
	}
	return true
}

func (d *downloader) register(c *peer_conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions[c] = true
	for i := 0; i < d.t.num_pieces(); i++ {
		if c.bitfield.has_piece(i) {
			d.availability[i]++
		}
	}
}

func (d *downloader) unregister(c *peer_conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, c)
	for i := 0; i < d.t.num_pieces(); i++ {
		if c.bitfield.has_piece(i) {
			if d.availability[i] > 0 {
				d.availability[i]--
			}
		}
	}
}

// broadcast_have tells the swarm we now hold a piece — both the peers we
// dialled and the peers that dialled us.
func (d *downloader) broadcast_have(index int) {
	d.mu.Lock()
	sessions := make([]*peer_conn, 0, len(d.sessions))
	for c := range d.sessions {
		sessions = append(sessions, c)
	}
	d.mu.Unlock()

	if d.seeder != nil {
		d.seeder.broadcast_have(index)
	}

	go func() {
		for _, c := range sessions {
			c.send_have(index)
		}
	}()
}

// --- the worker ------------------------------------------------------------

func (d *downloader) spawn_workers(peers []peer) int {
	started := 0
	for _, p := range peers {
		if d.ctx.Err() != nil {
			break
		}

		d.mu.Lock()
		if d.known[p] {
			d.mu.Unlock()
			continue
		}
		d.known[p] = true
		d.mu.Unlock()

		select {
		case d.worker_slots <- struct{}{}:
		default:
			d.mu.Lock()
			delete(d.known, p)
			d.mu.Unlock()
			return started
		}

		d.wg.Add(1)
		go func(p peer) {
			defer d.wg.Done()
			defer func() { <-d.worker_slots }()
			d.worker(p)
		}(p)
		started++
	}
	return started
}

func (d *downloader) active_workers() int {
	return len(d.worker_slots)
}

func (d *downloader) connected_peers() (total int, unchoked int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for c := range d.sessions {
		total++
		if !c.choked {
			unchoked++
		}
	}
	return total, unchoked
}

func (d *downloader) worker(p peer) {
	c, err := new_peer_conn(p, d.t.info_hash, d.peer_id, d.t.num_pieces(), d.cfg, d.stats)
	if err != nil {
		log_peer(p, "could not connect: %v", err)
		return
	}
	defer c.close()

	if err := c.prime(); err != nil {
		log_peer(p, "handshake/bitfield failed: %v", err)
		return
	}

	d.register(c)
	defer d.unregister(c)

	log_peer(p, "connected, holds %d/%d pieces", c.bitfield.count(), d.t.num_pieces())

	if err := c.send_interested(); err != nil {
		return
	}

	idle := 0
	for d.ctx.Err() == nil && !d.is_complete() {
		if c.choked {
			msg, alive := d.read_or_idle(c, &idle)
			if !alive {
				return
			}
			if msg != nil {
				if err := d.handle_message(c, msg); err != nil {
					return
				}
			}
			continue
		}

		index := d.pick_piece(c.bitfield, d.endgame())
		if index < 0 {
			msg, alive := d.read_or_idle(c, &idle)
			if !alive {
				return
			}
			if msg != nil {
				if err := d.handle_message(c, msg); err != nil {
					return
				}
			}
			continue
		}

		if err := d.fetch_piece(c, index); err != nil {
			d.release_piece(index)
			log_peer(p, "piece %d aborted: %v", index, err)
			return
		}
	}
}

// read_or_idle reads one message, tolerating an idle peer. A peer that says
// nothing for a while is dropped rather than kept alive forever.
func (d *downloader) read_or_idle(c *peer_conn, idle *int) (*message, bool) {
	msg, err := c.read()
	if err != nil {
		if is_timeout(err) {
			if d.ctx.Err() != nil || d.is_complete() {
				return nil, false
			}
			*idle++
			if *idle > 6 {
				return nil, false
			}
			return nil, true
		}
		return nil, false
	}
	*idle = 0
	return msg, true
}

func (d *downloader) fetch_piece(c *peer_conn, index int) error {
	pw := &piece_work{
		index:  index,
		hash:   d.t.piece_hashes[index],
		length: d.t.piece_size(index),
	}
	pp := new_piece_progress(pw)

	for !pp.complete() {
		if d.ctx.Err() != nil {
			return d.ctx.Err()
		}
		if c.choked {
			return errors.New("peer choked us mid-piece")
		}

		if err := pp.fill_requests(c); err != nil {
			return err
		}

		msg, err := c.read()
		if err != nil {
			return err
		}
		if msg == nil {
			continue
		}

		if msg.id == msg_piece {
			n, err := pp.accept(msg)
			if err != nil {
				return err
			}
			if n > 0 {
				d.stats.add_payload_down(int64(n))
				d.mark_progress()
			}
			continue
		}

		if err := d.handle_message(c, msg); err != nil {
			return err
		}
	}

	if err := check_integrity(pw, pp.buf); err != nil {
		return err
	}
	return d.commit_piece(index, pp.buf)
}

// handle_message deals with everything that is not a block we asked for. It
// doubles as the upload side: a peer that has unchoked and requested from us
// is served straight out of the store.
func (d *downloader) handle_message(c *peer_conn, msg *message) error {
	switch msg.id {
	case msg_choke:
		c.choked = true

	case msg_unchoke:
		c.choked = false

	case msg_have:
		index, err := parse_have(msg)
		if err != nil {
			return err
		}
		if index < 0 || index >= d.t.num_pieces() {
			return fmt.Errorf("have index %d is out of range", index)
		}
		if !c.bitfield.has_piece(index) {
			c.bitfield.set_piece(index)
			d.mu.Lock()
			d.availability[index]++
			d.mu.Unlock()
		}

	case msg_bitfield:
		c.bitfield = bitfield_from_bytes(msg.payload, d.t.num_pieces())

	case msg_interested:
		if err := c.send_unchoke(); err != nil {
			return err
		}

	case msg_not_interested:
		if err := c.send_choke(); err != nil {
			return err
		}

	case msg_request:
		req, err := parse_request(msg)
		if err != nil {
			return err
		}
		if !d.has_piece(req.index) {
			return c.send_choke()
		}
		if err := c.serve_request(d.store, req); err != nil {
			return err
		}

	case msg_cancel:
		// Nothing is queued for upload, so a cancel is already satisfied.

	case msg_extended:
		return c.handle_extended(msg)
	}
	return nil
}

func (d *downloader) commit_piece(index int, data []byte) error {
	if err := d.store.write_block(d.t.piece_offset(index), data); err != nil {
		return err
	}

	d.mu.Lock()
	if d.states[index] != piece_complete {
		d.states[index] = piece_complete
		d.completed_pieces++
		d.completed_bytes += int64(len(data))
	}
	d.mu.Unlock()

	d.mark_progress()
	d.broadcast_have(index)
	d.save_resume_throttled()
	return nil
}

// --- orchestration ---------------------------------------------------------

func (d *downloader) announce(event announce_event) error {
	req := &announce_request{
		info_hash: d.t.info_hash,
		peer_id:   d.peer_id,
		port:      d.cfg.listen_port,
		left:      d.remaining_bytes(),
		numwant:   100,
		event:     event,
	}
	downloaded, uploaded, _, _ := d.stats.snapshot()
	req.downloaded = downloaded
	req.uploaded = uploaded

	peers, err := d.t.request_peers(req)
	if err != nil {
		d.announce_fails++
		return err
	}
	d.announce_fails = 0
	if len(peers) > 0 {
		log.Printf("tracker returned %d peers", len(peers))
	}
	d.spawn_workers(peers)
	return nil
}

func (d *downloader) remaining_bytes() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	var done int64
	for i, state := range d.states {
		if state == piece_complete {
			done += d.t.piece_size(i)
		}
	}
	remaining := d.t.length - done
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (d *downloader) run() error {
	d.started = time.Now()
	log.Printf("starting download for %s (%d pieces, %d bytes, infohash %x)",
		d.t.name, d.t.num_pieces(), d.t.length, d.t.info_hash)

	if d.cfg.resume {
		resumed, err := d.load_resume()
		if err != nil {
			log.Printf("resume: %v", err)
		} else if resumed > 0 {
			d.resumed_pieces = resumed
			log.Printf("resume: %d pieces already verified, %d bytes remaining", resumed, d.remaining_bytes())
		}
	}

	if d.is_complete() {
		log.Printf("nothing to download: every piece is already on disk")
		d.finish()
		return nil
	}

	if d.cfg.listen_port > 0 && !d.cfg.no_seed {
		s, err := new_seeder(d.t, d.store, d.peer_id, d.cfg, d.stats, d.has_piece)
		if err != nil {
			log.Printf("seeding listener unavailable: %v", err)
		} else {
			d.seeder = s
			// Deliberately not in d.wg: with keep-seeding on, the listener
			// outlives the transfer and finish() must not block on it.
			go func() {
				if err := s.serve(d.root_ctx); err != nil && d.root_ctx.Err() == nil {
					log.Printf("seeding listener stopped: %v", err)
				}
			}()
			log.Printf("seeding on port %d", d.cfg.listen_port)
		}
	}

	if err := d.announce(event_started); err != nil {
		return fmt.Errorf("tracker announce failed: %w", err)
	}

	d.dash = new_dashboard(os.Stdout, d.cfg.dashboard)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	tracker_timer := time.NewTimer(2 * time.Minute)
	defer tracker_timer.Stop()

	last_wire_down, last_wire_up, _, _ := d.stats.snapshot()
	last_tick := time.Now()
	stalled_since := time.Now()

	for {
		if d.is_complete() {
			break
		}
		if d.ctx.Err() != nil {
			d.shutdown()
			return d.ctx.Err()
		}

		select {
		case <-d.ctx.Done():
			d.shutdown()
			return d.ctx.Err()

		case <-tracker_timer.C:
			if err := d.announce(event_none); err != nil {
				log.Printf("re-announce failed: %v", err)
			}
			tracker_timer.Reset(d.tracker_interval)

		case <-ticker.C:
			now := time.Now()
			wire_down, wire_up, payload_down, payload_up := d.stats.snapshot()
			elapsed := now.Sub(last_tick).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}

			snap := d.snapshot(
				float64(wire_down-last_wire_down)/elapsed,
				float64(wire_up-last_wire_up)/elapsed,
				payload_down,
				payload_up,
			)
			d.dash.render(snap)

			last_wire_down, last_wire_up = wire_down, wire_up
			last_tick = now

			// Watchdog: if nothing has moved and no worker is running, go
			// back to the tracker for fresh peers before giving up.
			if d.active_workers() == 0 {
				if now.Sub(stalled_since) > 10*time.Second {
					if err := d.announce(event_none); err != nil {
						log.Printf("no live peers; re-announce failed: %v", err)
					}
					stalled_since = now
				}
			} else {
				stalled_since = now
			}

			if d.announce_fails >= 3 && d.active_workers() == 0 && d.remaining_bytes() > 0 {
				d.dash.finish(snap)
				return fmt.Errorf("giving up: %d piece(s) still missing and no peer will supply them",
					d.pieces_remaining())
			}
		}
	}

	d.finish()
	return nil
}

func (d *downloader) pieces_remaining() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	count := 0
	for _, state := range d.states {
		if state != piece_complete {
			count++
		}
	}
	return count
}

// teardown stops the transfer scope so every peer read unblocks and the
// workers exit instead of parking until their deadlines expire.
func (d *downloader) teardown() {
	d.cancel()
	d.wg.Wait()
}

// shutdown is the interrupted path: keep whatever verified bytes we hold and
// record the piece map so the next run continues from here.
func (d *downloader) shutdown() {
	d.teardown()

	if err := d.store.sync(); err != nil {
		log.Printf("flush failed: %v", err)
	}
	if d.cfg.resume {
		if err := d.save_resume(true); err != nil {
			log.Printf("could not persist resume state: %v", err)
		}
	}
	if d.dash != nil {
		_, _, payload_down, payload_up := d.stats.snapshot()
		d.dash.finish(d.snapshot(0, 0, payload_down, payload_up))
	}
	if d.seeder != nil {
		d.seeder.close()
	}
	log.Printf("interrupted with %d piece(s) outstanding; progress saved", d.pieces_remaining())
}

func (d *downloader) finish() {
	d.teardown()

	if err := d.store.sync(); err != nil {
		log.Printf("flush failed: %v", err)
	}
	if err := d.announce(event_completed); err != nil {
		log.Printf("completed announce failed: %v", err)
	}
	if d.cfg.resume {
		if err := d.save_resume(true); err != nil {
			log.Printf("could not persist resume state: %v", err)
		}
	}

	if d.dash != nil {
		_, _, payload_down, payload_up := d.stats.snapshot()
		d.dash.finish(d.snapshot(0, 0, payload_down, payload_up))
	}

	// Keep serving the swarm if asked; otherwise close the listener.
	if d.seeder != nil {
		if d.cfg.keep_seeding {
			log.Printf("download complete; seeding on port %d until interrupted", d.cfg.listen_port)
			<-d.root_ctx.Done()
		}
		d.seeder.close()
	}
}

func (d *downloader) snapshot(down_rate, up_rate float64, payload_down, payload_up int64) progress_snapshot {
	connected, unchoked := d.connected_peers()

	d.mu.Lock()
	done_bytes := d.completed_bytes
	done_pieces := d.completed_pieces
	resumed := d.resumed_pieces
	d.mu.Unlock()

	var eta time.Duration
	remaining := d.t.length - done_bytes
	if remaining > 0 && down_rate > 0 {
		eta = time.Duration(float64(remaining)/down_rate) * time.Second
	}

	ratio := 0.0
	if payload_down > 0 {
		ratio = float64(payload_up) / float64(payload_down)
	}

	return progress_snapshot{
		name:           d.t.name,
		total_bytes:    d.t.length,
		done_bytes:     done_bytes,
		pieces_done:    done_pieces,
		pieces_total:   d.t.num_pieces(),
		down_rate:      down_rate,
		up_rate:        up_rate,
		eta:            eta,
		active_workers: d.active_workers(),
		connected:      connected,
		unchoked:       unchoked,
		uploaded:       payload_up,
		ratio:          ratio,
		resumed:        resumed,
		elapsed:        time.Since(d.started),
	}
}
