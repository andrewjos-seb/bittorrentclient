package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- test scaffolding ------------------------------------------------------

func test_config(t *testing.T, output string) *config {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &config{
		ctx:          ctx,
		root_ctx:     ctx,
		cancel:       cancel,
		output:       output,
		dashboard:    false,
		resume:       true,
		peer_timeout: 10 * time.Second,
		down_limiter: new_rate_limiter(0),
		up_limiter:   new_rate_limiter(0),
	}
}

func test_torrent(t *testing.T, pieces int, piece_length int) (*torrent_file, []byte) {
	t.Helper()
	dir := t.TempDir()
	payload := deterministic_payload(pieces * piece_length)
	info_raw := build_info("unit.bin", piece_length, payload, nil)
	path := write_torrent(t, dir, "http://tracker.invalid/announce", info_raw)

	torrent, err := open_torrent(path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}
	return torrent, payload
}

func test_downloader(t *testing.T, pieces int) *downloader {
	t.Helper()
	torrent, _ := test_torrent(t, pieces, 1024)
	cfg := test_config(t, filepath.Join(t.TempDir(), "out.bin"))
	store, err := new_piece_store(torrent, cfg.output)
	if err != nil {
		t.Fatalf("new_piece_store: %v", err)
	}
	t.Cleanup(func() { store.close() })
	return new_downloader(torrent, cfg, store, [20]byte{}, &stat_sink{})
}

// frame_reader drains everything the client writes into a buffered channel so
// a synchronous net.Pipe never blocks the code under test.
func frame_reader(conn net.Conn) <-chan *message {
	out := make(chan *message, 256)
	go func() {
		defer close(out)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			msg, err := read_message(conn)
			if err != nil {
				return
			}
			if msg != nil {
				out <- msg
			}
		}
	}()
	return out
}

// read_frames collects exactly want frames, so a test never waits on the
// reader goroutine to finish (it only stops when the pipe is closed).
func read_frames(t *testing.T, frames <-chan *message, want int) []*message {
	t.Helper()
	out := make([]*message, 0, want)
	for len(out) < want {
		select {
		case msg, ok := <-frames:
			if !ok {
				t.Fatalf("the frame reader closed after %d frames, want %d", len(out), want)
			}
			out = append(out, msg)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d frames arrived, want %d", len(out), want)
		}
	}
	return out
}

// --- the backlog defect ----------------------------------------------------

// The original worker incremented `backlog` when a request went out and never
// decremented it when the block came back. Once the window filled, no further
// request could be issued, so any dropped block ended the transfer. This walks
// a 16-block piece through an 8-deep window and demands it completes.
func TestPieceCompletesThroughABoundedPipeline(t *testing.T) {
	const blocks = 16
	pw := &piece_work{index: 0, hash: hash_piece(make([]byte, blocks*block_size)), length: blocks * block_size}
	pp := new_piece_progress(pw)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	pc := &peer_conn{conn: local, cfg: &config{peer_timeout: time.Second}}
	frames := frame_reader(remote)

	issued := 0
	for block := 0; block < blocks; block++ {
		before := pp.backlog
		if err := pp.fill_requests(pc); err != nil {
			t.Fatalf("fill_requests: %v", err)
		}
		if pp.backlog < before && pp.backlog != 0 {
			t.Fatalf("backlog went backwards from %d to %d", before, pp.backlog)
		}
		if pp.backlog > max_backlog {
			t.Fatalf("backlog = %d exceeds the %d deep window", pp.backlog, max_backlog)
		}

		payload := make([]byte, block_size)
		payload[0] = byte(block)
		if _, err := pp.accept(format_piece(0, int64(block*block_size), payload)); err != nil {
			t.Fatalf("accept block %d: %v", block, err)
		}
	}

	if !pp.complete() {
		t.Fatal("piece never completed: the pipeline stalled")
	}
	if pp.downloaded != pw.length {
		t.Fatalf("downloaded %d bytes, want %d", pp.downloaded, pw.length)
	}
	if pp.backlog != 0 {
		t.Fatalf("backlog = %d after every block landed, want 0", pp.backlog)
	}

	// Exactly one request per block reached the wire, in order.
	for i, msg := range read_frames(t, frames, blocks) {
		if msg.id != msg_request {
			t.Fatalf("frame %d is %v, want a request", i, msg.id)
		}
		req, err := parse_request(msg)
		if err != nil {
			t.Fatalf("parse_request: %v", err)
		}
		if req.index != 0 {
			t.Fatalf("request %d asked for piece %d", i, req.index)
		}
		if req.begin != int64(i*block_size) {
			t.Fatalf("request %d asked for offset %d, want %d", i, req.begin, i*block_size)
		}
		issued++
	}
	if issued != blocks {
		t.Fatalf("issued %d requests, want %d", issued, blocks)
	}
}

func TestBacklogIsNeverOverfilled(t *testing.T) {
	pw := &piece_work{index: 0, hash: [20]byte{}, length: 64 * block_size}
	pp := new_piece_progress(pw)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	pc := &peer_conn{conn: local, cfg: &config{peer_timeout: time.Second}}
	frames := frame_reader(remote)

	for round := 0; round < 4; round++ {
		if err := pp.fill_requests(pc); err != nil {
			t.Fatalf("fill_requests: %v", err)
		}
		if pp.backlog > max_backlog {
			t.Fatalf("round %d left %d requests in flight, cap is %d", round, pp.backlog, max_backlog)
		}
		if pp.backlog != max_backlog {
			t.Fatalf("round %d left %d requests in flight, want a full window of %d", round, pp.backlog, max_backlog)
		}
	}

	for i, msg := range read_frames(t, frames, max_backlog) {
		if msg.id != msg_request {
			t.Fatalf("frame %d is %v, want a request", i, msg.id)
		}
	}
}

// A stalled peer must not be able to strand a piece: whatever was in flight is
// returned to the pool so another peer can pick it up.
func TestStalledPeerReleasesInFlightBlocks(t *testing.T) {
	pw := &piece_work{index: 0, hash: [20]byte{}, length: 16 * block_size}
	pp := new_piece_progress(pw)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	pc := &peer_conn{conn: local, cfg: &config{peer_timeout: time.Second}}
	// The drainer must run so the synchronous pipe never blocks, but this test
	// only cares about the bookkeeping inside the piece.
	go frame_reader(remote)

	if err := pp.fill_requests(pc); err != nil {
		t.Fatalf("fill_requests: %v", err)
	}
	// Three blocks arrive, then the peer goes silent.
	for block := 0; block < 3; block++ {
		if _, err := pp.accept(format_piece(0, int64(block*block_size), make([]byte, block_size))); err != nil {
			t.Fatalf("accept: %v", err)
		}
	}
	if pp.downloaded != 3*block_size {
		t.Fatalf("downloaded = %d, want %d", pp.downloaded, 3*block_size)
	}

	pp.reset_pending()
	if pp.backlog != 0 {
		t.Fatalf("backlog = %d after releasing, want 0", pp.backlog)
	}
	for block := 0; block < 16; block++ {
		if pp.blocks[block] == block_pending {
			t.Fatalf("block %d is still marked in flight", block)
		}
	}

	// The five unanswered blocks can now be re-issued.
	before := 0
	for i := 0; i < 16; i++ {
		if pp.blocks[i] == block_have {
			before++
		}
	}
	if err := pp.fill_requests(pc); err != nil {
		t.Fatalf("fill_requests after release: %v", err)
	}
	if pp.backlog == 0 {
		t.Fatal("no requests were re-issued after the peer stalled")
	}
	if before != 3 {
		t.Fatalf("held blocks = %d, want 3", before)
	}
}

func TestDuplicateBlocksAreCountedOnce(t *testing.T) {
	pw := &piece_work{index: 0, hash: [20]byte{}, length: 2 * block_size}
	pp := new_piece_progress(pw)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	pc := &peer_conn{conn: local, cfg: &config{peer_timeout: time.Second}}
	go frame_reader(remote)

	if err := pp.fill_requests(pc); err != nil {
		t.Fatalf("fill_requests: %v", err)
	}

	piece := format_piece(0, 0, make([]byte, block_size))
	if _, err := pp.accept(piece); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if pp.downloaded != block_size {
		t.Fatalf("downloaded = %d", pp.downloaded)
	}
	if n, err := pp.accept(piece); err != nil || n != 0 {
		t.Fatalf("duplicate accept = %d, %v; want 0, nil", n, err)
	}
	if pp.downloaded != block_size {
		t.Fatalf("duplicate block was double counted: %d", pp.downloaded)
	}
}

func TestAcceptRejectsMisplacedBlocks(t *testing.T) {
	pw := &piece_work{index: 4, hash: [20]byte{}, length: 2 * block_size}
	pp := new_piece_progress(pw)

	if _, err := pp.accept(format_piece(5, 0, make([]byte, block_size))); err == nil {
		t.Fatal("a block for another piece should be rejected")
	}
	if _, err := pp.accept(format_piece(4, int64(block_size)+1, make([]byte, 8))); err == nil {
		t.Fatal("an unaligned offset should be rejected")
	}
	if _, err := pp.accept(format_piece(4, int64(8*block_size), make([]byte, 8))); err == nil {
		t.Fatal("an out-of-range block should be rejected")
	}
}

// --- the picker ------------------------------------------------------------

func TestPickerOnlyOffersPiecesThePeerHolds(t *testing.T) {
	d := test_downloader(t, 8)

	held := new_bitfield(8)
	held.set_piece(3)

	index := d.pick_piece(held, false)
	if index != 3 {
		t.Fatalf("picked %d, want 3", index)
	}
	if again := d.pick_piece(held, false); again != -1 {
		t.Fatalf("picked %d, but piece 3 is already claimed", again)
	}

	d.release_piece(3)
	if again := d.pick_piece(held, false); again != 3 {
		t.Fatalf("a released piece was not offered again (got %d)", again)
	}

	if got := d.pick_piece(new_bitfield(8), false); got != -1 {
		t.Fatalf("a peer holding nothing was handed piece %d", got)
	}
}

func TestPickerPrefersTheRarestPiece(t *testing.T) {
	d := test_downloader(t, 6)

	held := new_bitfield(6)
	for i := 0; i < 6; i++ {
		held.set_piece(i)
	}
	// Piece 4 is the rarest.
	d.mu.Lock()
	d.availability[0] = 9
	d.availability[1] = 9
	d.availability[2] = 9
	d.availability[3] = 9
	d.availability[4] = 1
	d.availability[5] = 9
	d.mu.Unlock()

	if got := d.pick_piece(held, false); got != 4 {
		t.Fatalf("picked %d, want the rarest piece 4", got)
	}
}

func TestEndgameAllowsDuplicates(t *testing.T) {
	d := test_downloader(t, 4)
	held := new_bitfield(4)
	for i := 0; i < 4; i++ {
		held.set_piece(i)
		d.mu.Lock()
		d.availability[i] = 5
		d.mu.Unlock()
	}

	if d.endgame() {
		t.Fatal("endgame should be off while unclaimed pieces remain")
	}

	first := d.pick_piece(held, false)
	if first < 0 {
		t.Fatal("expected a piece")
	}
	// Pretend every other piece is now in flight too.
	d.mu.Lock()
	for i := range d.states {
		d.states[i] = piece_in_progress
	}
	d.mu.Unlock()

	if !d.endgame() {
		t.Fatal("endgame should be on once every piece is claimed")
	}
	if got := d.pick_piece(held, true); got < 0 {
		t.Fatal("endgame should hand out a duplicate request")
	}
}

// --- resume ----------------------------------------------------------------

func TestResumeRoundTrip(t *testing.T) {
	d := test_downloader(t, 6)
	d.mu.Lock()
	for _, index := range []int{0, 2, 5} {
		d.states[index] = piece_complete
		d.completed_pieces++
	}
	d.mu.Unlock()

	if err := d.save_resume(true); err != nil {
		t.Fatalf("save_resume: %v", err)
	}
	path := d.resume_path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("resume file was not written: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary file was left behind; the write was not atomic")
	}

	restored := test_downloader_for(t, d.t, d.cfg.output)
	restored.mu.Lock()
	for i := range restored.states {
		restored.states[i] = piece_missing
	}
	restored.completed_pieces = 0
	restored.mu.Unlock()

	count, err := restored.load_resume()
	if err != nil {
		t.Fatalf("load_resume: %v", err)
	}
	if count != 3 {
		t.Fatalf("restored %d pieces, want 3", count)
	}
	if !restored.has_piece(0) || restored.has_piece(1) || !restored.has_piece(2) || !restored.has_piece(5) {
		t.Fatal("the restored piece map does not match what was saved")
	}
	if restored.is_complete() {
		t.Fatal("the torrent should not be complete")
	}
}

func test_downloader_for(t *testing.T, torrent *torrent_file, output string) *downloader {
	t.Helper()
	cfg := test_config(t, output)
	store, err := new_piece_store(torrent, output)
	if err != nil {
		t.Fatalf("new_piece_store: %v", err)
	}
	t.Cleanup(func() { store.close() })
	return new_downloader(torrent, cfg, store, [20]byte{}, &stat_sink{})
}

func TestResumeRejectsForeignInfohash(t *testing.T) {
	d := test_downloader(t, 4)
	if err := d.save_resume(true); err != nil {
		t.Fatalf("save_resume: %v", err)
	}

	raw, err := os.ReadFile(d.resume_path())
	if err != nil {
		t.Fatalf("read resume: %v", err)
	}
	var state resume_state
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	state.InfoHash = "0000000000000000000000000000000000000000"
	tampered, _ := json.Marshal(state)
	if err := os.WriteFile(d.resume_path(), tampered, 0o644); err != nil {
		t.Fatalf("write resume: %v", err)
	}

	if _, err := d.load_resume(); err == nil {
		t.Fatal("resume state for another infohash must be rejected")
	}
}

func TestResumeRejectsCorruptState(t *testing.T) {
	d := test_downloader(t, 4)

	write_bad := func(body string) {
		if err := os.WriteFile(d.resume_path(), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := d.load_resume(); err == nil {
			t.Fatalf("corrupt resume state %q was accepted", body)
		}
	}

	write_bad("{not json")
	write_bad(fmt.Sprintf(`{"version":%d,"info_hash":"%x","num_pieces":4,"length":%d,"piece_length":1024,"bitfield":"!!!not-base64!!!","completed_pieces":0}`,
		resume_version, d.t.info_hash, d.t.length))
	// Three bytes of bitfield describes 24 pieces, not 4.
	write_bad(fmt.Sprintf(`{"version":%d,"info_hash":"%x","num_pieces":4,"length":%d,"piece_length":1024,"bitfield":"AQID","completed_pieces":0}`,
		resume_version, d.t.info_hash, d.t.length))
}

func TestResumeMissingFileIsNotAnError(t *testing.T) {
	d := test_downloader(t, 4)
	count, err := d.load_resume()
	if err != nil {
		t.Fatalf("a missing resume file should not be an error: %v", err)
	}
	if count != 0 {
		t.Fatalf("restored %d pieces from nothing", count)
	}
}

func TestVerifyDemotesCorruptResumedPieces(t *testing.T) {
	torrent, payload := test_torrent(t, 4, 1024)
	output := filepath.Join(t.TempDir(), "out.bin")

	// Put the payload on disk, then corrupt one piece.
	if err := os.WriteFile(output, payload, 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	corrupted := append([]byte(nil), payload...)
	corrupted[1500] ^= 0xff
	if err := os.WriteFile(output, corrupted, 0o644); err != nil {
		t.Fatalf("write corrupt payload: %v", err)
	}

	d := test_downloader_for(t, torrent, output)
	d.cfg.verify = true

	d.mu.Lock()
	for i := 0; i < torrent.num_pieces(); i++ {
		d.states[i] = piece_complete
		d.completed_pieces++
	}
	d.mu.Unlock()

	if err := d.save_resume(true); err != nil {
		t.Fatalf("save_resume: %v", err)
	}

	restored := test_downloader_for(t, torrent, output)
	restored.cfg.verify = true
	count, err := restored.load_resume()
	if err != nil {
		t.Fatalf("load_resume: %v", err)
	}
	if count != 3 {
		t.Fatalf("verified %d pieces, want 3 (piece 1 is corrupt)", count)
	}
	if restored.has_piece(1) {
		t.Fatal("the corrupt piece was kept")
	}
	if !restored.has_piece(0) || !restored.has_piece(2) || !restored.has_piece(3) {
		t.Fatal("a good piece was wrongly discarded")
	}
}

func TestSaveResumeDisabledIsANoOp(t *testing.T) {
	d := test_downloader(t, 3)
	d.cfg.resume = false
	if err := d.save_resume(true); err != nil {
		t.Fatalf("save_resume: %v", err)
	}
	if _, err := os.Stat(d.resume_path()); !os.IsNotExist(err) {
		t.Fatal("resume state was written even though resuming is disabled")
	}
}

// --- rate limiting ---------------------------------------------------------

func TestRateLimiterPacesTransfers(t *testing.T) {
	const rate = 64 * 1024
	limiter := new_rate_limiter(rate)
	ctx := context.Background()

	// The bucket starts full, so the first burst is free. Eight quarter-rate
	// waits therefore consume one burst and have to refill for the rest.
	start := time.Now()
	for i := 0; i < 8; i++ {
		if err := limiter.wait(ctx, rate/4); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 800*time.Millisecond {
		t.Fatalf("eight quarter-bursts took %s, which is faster than the bucket allows", elapsed)
	}
	if elapsed > 6*time.Second {
		t.Fatalf("limiter was far too slow: %s", elapsed)
	}
}

func TestRateLimiterDisabledIsFree(t *testing.T) {
	limiter := new_rate_limiter(0)
	if limiter.enabled() {
		t.Fatal("a zero rate should mean unlimited")
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := limiter.wait(context.Background(), 1<<20); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a disabled limiter blocked for %s", elapsed)
	}
}

func TestRateLimiterStopsOnContextCancel(t *testing.T) {
	limiter := new_rate_limiter(1024)
	// Spend the bucket so the next reservation has to wait for a refill.
	if err := limiter.wait(context.Background(), 1024); err != nil {
		t.Fatalf("initial wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.wait(ctx, 1024); err == nil {
		t.Fatal("a cancelled context should abort the wait")
	}
}

func TestParseRate(t *testing.T) {
	cases := map[string]int64{
		"":        0,
		"0":       0,
		"off":     0,
		"500KB":   500000,
		"1kib":    1024,
		"2MiB":    2 << 20,
		"1.5mb/s": 1500000,
		"100":     100,
	}
	for input, want := range cases {
		got, err := parse_rate(input)
		if err != nil {
			t.Fatalf("parse_rate(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("parse_rate(%q) = %d, want %d", input, got, want)
		}
	}
	if _, err := parse_rate("banana"); err == nil {
		t.Fatal("a nonsense rate should be rejected")
	}
}

var _ = base64.StdEncoding
