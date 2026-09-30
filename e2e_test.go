package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// End to end tests: a real seeder listening on a real TCP port, a real HTTP
// tracker, and the real downloader talking to both over loopback. Nothing is
// stubbed inside the protocol stack, so a fault in framing, bit order or flow
// control fails these tests.

// --- a minimal tracker -----------------------------------------------------

type fake_tracker struct {
	server *httptest.Server

	mu        sync.Mutex
	peers     []byte
	announces int
	queries   []url.Values
	fail      bool
}

func new_fake_tracker() *fake_tracker {
	ft := &fake_tracker{}
	ft.server = httptest.NewServer(http.HandlerFunc(ft.handle))
	return ft
}

func (ft *fake_tracker) handle(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	ft.mu.Lock()
	ft.announces++
	ft.queries = append(ft.queries, query)
	peers := ft.peers
	fail := ft.fail
	ft.mu.Unlock()

	if fail {
		body, _ := bencode_bytes(map[string]interface{}{"failure reason": "tracker is unwell"})
		w.Write(body)
		return
	}

	body, err := bencode_bytes(map[string]interface{}{
		"complete":   1,
		"incomplete": 0,
		"interval":   1,
		"peers":      peers,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(body)
}

func (ft *fake_tracker) set_peer(p peer) {
	compact := make([]byte, 6)
	copy(compact[0:4], p.ip[:])
	binary.BigEndian.PutUint16(compact[4:6], p.port)
	ft.mu.Lock()
	ft.peers = compact
	ft.mu.Unlock()
}

func (ft *fake_tracker) announce_count() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.announces
}

func (ft *fake_tracker) recorded() []url.Values {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	out := make([]url.Values, len(ft.queries))
	copy(out, ft.queries)
	return out
}

func (ft *fake_tracker) close() { ft.server.Close() }

// --- a real seeder ---------------------------------------------------------

type seed_fixture struct {
	store  *piece_store
	seeder *seeder
	port   uint16
	stats  *stat_sink
}

func start_seeder(t *testing.T, torrent *torrent_file, target string) *seed_fixture {
	t.Helper()

	cfg := test_config(t, target)
	cfg.listen_port = 0 // let the kernel pick a free port

	store, err := new_piece_store(torrent, target)
	if err != nil {
		t.Fatalf("seeder store: %v", err)
	}
	t.Cleanup(func() { store.close() })

	stats := &stat_sink{}
	peer_id, err := new_peer_id()
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}

	s, err := new_seeder(torrent, store, peer_id, cfg, stats, func(int) bool { return true })
	if err != nil {
		t.Fatalf("new_seeder: %v", err)
	}
	go s.serve(cfg.root_ctx)
	t.Cleanup(func() { s.close() })

	return &seed_fixture{
		store:  store,
		seeder: s,
		port:   uint16(s.listener.Addr().(*net.TCPAddr).Port),
		stats:  stats,
	}
}

// wait_for_payload_up waits for the seeder's upload counter to reach a value,
// so a slow counter update cannot make a precise assertion flaky.
func (f *seed_fixture) wait_for_payload_up(t *testing.T, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, _, up := f.stats.snapshot()
		if up >= want || time.Now().After(deadline) {
			return up
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func run_downloader(t *testing.T, torrent *torrent_file, output string, tune func(*config)) (*downloader, *stat_sink) {
	t.Helper()

	cfg := test_config(t, output)
	if tune != nil {
		tune(cfg)
	}

	store, err := new_piece_store(torrent, output)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.close() })

	stats := &stat_sink{}
	peer_id, err := new_peer_id()
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}

	d := new_downloader(torrent, cfg, store, peer_id, stats)
	if err := d.run(); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	return d, stats
}

// --- single file -----------------------------------------------------------

func TestEndToEndSingleFileDownload(t *testing.T) {
	const piece_length = 262144
	payload := deterministic_payload(640000)

	info_raw := build_info("payload.bin", piece_length, payload, nil)
	tracker := new_fake_tracker()
	defer tracker.close()

	seed_path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write seed payload: %v", err)
	}

	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	seed := start_seeder(t, torrent, seed_path)
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: seed.port})

	output := filepath.Join(t.TempDir(), "payload.bin")
	d, dl_stats := run_downloader(t, torrent, output, nil)

	if d.pieces_remaining() != 0 {
		t.Fatalf("%d pieces are still missing", d.pieces_remaining())
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload differs from the original (%d vs %d bytes)", len(got), len(payload))
	}

	// Every byte crossed the wire exactly once.
	up := seed.wait_for_payload_up(t, int64(len(payload)))
	if up != int64(len(payload)) {
		t.Fatalf("seeder uploaded %d bytes, want exactly %d", up, len(payload))
	}

	if _, _, payload_down, _ := dl_stats.snapshot(); payload_down != int64(len(payload)) {
		t.Fatalf("downloader accepted %d payload bytes, want %d", payload_down, len(payload))
	}

	// The tracker must have seen our exact infohash bytes and a completed event.
	queries := tracker.recorded()
	if len(queries) == 0 {
		t.Fatal("the tracker was never contacted")
	}
	saw_start := false
	saw_complete := false
	for _, q := range queries {
		if q.Get("info_hash") != string(torrent.info_hash[:]) {
			t.Fatalf("tracker received infohash %x, want %x", q.Get("info_hash"), torrent.info_hash)
		}
		if q.Get("compact") != "1" {
			t.Fatalf("compact flag = %q", q.Get("compact"))
		}
		switch q.Get("event") {
		case "started":
			saw_start = true
		case "completed":
			saw_complete = true
		}
	}
	if !saw_start {
		t.Fatal("no started event was sent")
	}
	if !saw_complete {
		t.Fatal("no completed event was sent")
	}
}

func TestEndToEndUsesTheSeedPieceMap(t *testing.T) {
	// The seeder only holds some pieces; the downloader must take what it can
	// from it and fail cleanly rather than hanging forever.
	const piece_length = 65536
	payload := deterministic_payload(4 * piece_length)
	info_raw := build_info("partial.bin", piece_length, payload, nil)

	tracker := new_fake_tracker()
	defer tracker.close()

	seed_path := filepath.Join(t.TempDir(), "partial.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	cfg := test_config(t, seed_path)
	cfg.listen_port = 0
	store, err := new_piece_store(torrent, seed_path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.close()

	s, err := new_seeder(torrent, store, [20]byte{'s'}, cfg, &stat_sink{}, func(index int) bool {
		return index < 2 // only the first two pieces
	})
	if err != nil {
		t.Fatalf("new_seeder: %v", err)
	}
	go s.serve(cfg.root_ctx)
	defer s.close()

	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: uint16(s.listener.Addr().(*net.TCPAddr).Port)})

	output := filepath.Join(t.TempDir(), "partial.bin")
	leech_cfg := test_config(t, output)
	leech_store, err := new_piece_store(torrent, output)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer leech_store.close()

	d := new_downloader(torrent, leech_cfg, leech_store, [20]byte{'l'}, &stat_sink{})

	done := make(chan error, 1)
	go func() { done <- d.run() }()

	// Wait for the two pieces the peer does hold, without assuming how quickly
	// the handshake and unchoke resolve on a loaded machine.
	deadline := time.Now().Add(15 * time.Second)
	for !(d.has_piece(0) && d.has_piece(1)) {
		select {
		case err := <-done:
			t.Fatalf("the download should not finish while two pieces are unreachable (returned %v)", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("pieces 0 and 1 were never fetched (have 0=%v, 1=%v)", d.has_piece(0), d.has_piece(1))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// It must still be running: two pieces are unreachable, so a client that
	// returned here would have silently dropped them.
	select {
	case err := <-done:
		t.Fatalf("the download should not finish while two pieces are unreachable (returned %v)", err)
	default:
	}
	if d.is_complete() {
		t.Fatal("the client considers the torrent complete with two pieces missing")
	}

	d.cancel()
	if d.has_piece(2) || d.has_piece(3) {
		t.Fatal("pieces the peer never advertised should not have arrived")
	}
}

// --- multi-file ------------------------------------------------------------

func TestEndToEndMultiFileDownloadAcrossFileBoundary(t *testing.T) {
	type test_file struct {
		path string
		data []byte
	}
	files := []test_file{
		{"part-a.bin", deterministic_payload(200000)},
		{"part-b.bin", deterministic_payload(150000)},
	}

	// A piece length that does not divide the first file makes pieces straddle
	// the boundary between the two files.
	const piece_length = 150000
	info_raw, payload := build_multi_info("bundle", piece_length, []struct {
		path string
		data []byte
	}{
		{files[0].path, files[0].data},
		{files[1].path, files[1].data},
	}, nil)

	tracker := new_fake_tracker()
	defer tracker.close()

	seed_root := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(seed_root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(seed_root, f.path), f.data, 0o644); err != nil {
			t.Fatalf("write %s: %v", f.path, err)
		}
	}

	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}
	if !torrent.multi || len(torrent.files) != 2 {
		t.Fatalf("expected a two file torrent, got %d files (multi=%v)", len(torrent.files), torrent.multi)
	}
	if torrent.length != int64(len(payload)) {
		t.Fatalf("length = %d, want %d", torrent.length, len(payload))
	}

	seed := start_seeder(t, torrent, seed_root)
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: seed.port})

	output := filepath.Join(t.TempDir(), "bundle-out")
	run_downloader(t, torrent, output, nil)

	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(output, f.path))
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		if !bytes.Equal(got, f.data) {
			t.Fatalf("%s differs from the original", f.path)
		}
	}
}

// --- resume ----------------------------------------------------------------

func write_resume_state(t *testing.T, torrent *torrent_file, output string, complete []int) {
	t.Helper()

	available := new_bitfield(torrent.num_pieces())
	for _, index := range complete {
		available.set_piece(index)
	}

	state := resume_state{
		Version:     resume_version,
		InfoHash:    hex.EncodeToString(torrent.info_hash[:]),
		Name:        torrent.name,
		Length:      torrent.length,
		PieceLength: torrent.piece_length,
		NumPieces:   torrent.num_pieces(),
		Bitfield:    base64.StdEncoding.EncodeToString(available),
		Completed:   len(complete),
		UpdatedAt:   time.Now().UTC(),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal resume: %v", err)
	}
	if err := os.WriteFile(output+".resume", raw, 0o644); err != nil {
		t.Fatalf("write resume: %v", err)
	}
}

func TestResumeSkipsAlreadyVerifiedPieces(t *testing.T) {
	const piece_length = 100000
	payload := deterministic_payload(3 * piece_length)

	info_raw := build_info("resume.bin", piece_length, payload, nil)
	tracker := new_fake_tracker()
	defer tracker.close()

	seed_path := filepath.Join(t.TempDir(), "resume.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	seed := start_seeder(t, torrent, seed_path)
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: seed.port})

	output := filepath.Join(t.TempDir(), "resume.bin")
	// The two "already downloaded" pieces really are on disk, so nothing needs
	// re-fetching if resume works.
	if err := os.WriteFile(output, payload, 0o644); err != nil {
		t.Fatalf("write output: %v", err)
	}
	write_resume_state(t, torrent, output, []int{0, 1})

	d, _ := run_downloader(t, torrent, output, nil)
	if d.resumed_pieces != 2 {
		t.Fatalf("resumed %d pieces, want 2", d.resumed_pieces)
	}

	up := seed.wait_for_payload_up(t, int64(piece_length))
	if up != int64(piece_length) {
		t.Fatalf("seeder uploaded %d bytes, want exactly one piece (%d)", up, piece_length)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the finished file does not match the original")
	}
}

func TestVerifyRepairsCorruptPiecesOnDisk(t *testing.T) {
	const piece_length = 100000
	payload := deterministic_payload(3 * piece_length)

	info_raw := build_info("repair.bin", piece_length, payload, nil)
	tracker := new_fake_tracker()
	defer tracker.close()

	seed_path := filepath.Join(t.TempDir(), "repair.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	seed := start_seeder(t, torrent, seed_path)
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: seed.port})

	output := filepath.Join(t.TempDir(), "repair.bin")
	corrupt := append([]byte(nil), payload...)
	corrupt[10] ^= 0xff // damage piece 0
	if err := os.WriteFile(output, corrupt, 0o644); err != nil {
		t.Fatalf("write output: %v", err)
	}
	write_resume_state(t, torrent, output, []int{0, 1, 2})

	_, _ = run_downloader(t, torrent, output, func(cfg *config) { cfg.verify = true })

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("verification did not repair the damaged piece")
	}

	up := seed.wait_for_payload_up(t, int64(piece_length))
	if up != int64(piece_length) {
		t.Fatalf("seeder uploaded %d bytes, want only the repaired piece (%d)", up, piece_length)
	}
}

// --- magnet ----------------------------------------------------------------

func TestMagnetResolutionAndDownload(t *testing.T) {
	const piece_length = 65536
	payload := deterministic_payload(3 * piece_length)

	info_raw := build_info("magnet.bin", piece_length, payload, nil)

	tracker := new_fake_tracker()
	defer tracker.close()

	seed_path := filepath.Join(t.TempDir(), "magnet.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	seed := start_seeder(t, torrent, seed_path)
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: seed.port})

	link_uri := "magnet:?xt=urn:btih:" + hex.EncodeToString(torrent.info_hash[:]) +
		"&dn=magnet.bin&tr=" + url.QueryEscape(tracker.server.URL+"/announce")

	link, err := parse_magnet(link_uri)
	if err != nil {
		t.Fatalf("parse_magnet: %v", err)
	}

	cfg := test_config(t, filepath.Join(t.TempDir(), "magnet-out.bin"))
	resolved, err := resolve_metadata(link, cfg, [20]byte{'m'}, &stat_sink{})
	if err != nil {
		t.Fatalf("resolve_metadata: %v", err)
	}
	if resolved.info_hash != torrent.info_hash {
		t.Fatalf("resolved infohash = %x, want %x", resolved.info_hash, torrent.info_hash)
	}
	if resolved.num_pieces() != torrent.num_pieces() {
		t.Fatalf("resolved %d pieces, want %d", resolved.num_pieces(), torrent.num_pieces())
	}
	if resolved.piece_length != piece_length {
		t.Fatalf("resolved piece length = %d", resolved.piece_length)
	}
	if !bytes.Equal(resolved.info_dict(), torrent.info_dict()) {
		t.Fatal("resolved info dictionary differs from the original bytes")
	}

	// Now download with the metadata we just fetched.
	output := filepath.Join(t.TempDir(), "magnet-out.bin")
	run_downloader(t, resolved, output, nil)

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload fetched via magnet metadata does not match the original")
	}
}

// A hostile peer can answer the right infohash in its handshake and still hand
// over metadata for a completely different swarm. The hash check is the only
// thing standing between us and downloading the wrong payload.
func TestMagnetRejectsMetadataForAnotherTorrent(t *testing.T) {
	const piece_length = 16384

	wanted_info := build_info("wanted.bin", piece_length, deterministic_payload(piece_length), nil)
	wanted_path := write_torrent(t, t.TempDir(), "http://tracker.invalid/announce", wanted_info)
	wanted, err := open_torrent(wanted_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	impostor_info := build_info("impostor.bin", piece_length, deterministic_payload(2*piece_length), nil)
	impostor_path := write_torrent(t, t.TempDir(), "http://tracker.invalid/announce", impostor_info)
	impostor, err := open_torrent(impostor_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(15 * time.Second))

				if _, err := read_handshake(conn); err != nil {
					return
				}

				var impostor_id [20]byte
				copy(impostor_id[:], "-MO0001-impostor")
				reply := new_handshake(wanted.info_hash, impostor_id)
				reply.reserved_extended = true
				if _, err := conn.Write(reply.serialize()); err != nil {
					return
				}

				info := impostor.info_dict()
				handshake, err := format_extended(0, map[string]interface{}{
					"m":             map[string]interface{}{"ut_metadata": 1},
					"metadata_size": len(info),
				})
				if err != nil {
					return
				}
				if _, err := conn.Write(handshake.serialize()); err != nil {
					return
				}

				for {
					in, err := read_message(conn)
					if err != nil {
						return
					}
					if in == nil || in.id != msg_extended {
						continue
					}
					_, body, _, err := parse_extended_body(in)
					if err != nil || body == nil {
						continue
					}
					kind, err := body.get("msg_type").as_int()
					if err != nil || int(kind) != metadata_request {
						continue
					}
					piece, err := body.get("piece").as_int()
					if err != nil {
						continue
					}

					begin := int(piece) * metadata_block_size
					if begin > len(info) {
						begin = len(info)
					}
					end := begin + metadata_block_size
					if end > len(info) {
						end = len(info)
					}

					header, err := bencode_bytes(map[string]interface{}{
						"msg_type":   metadata_data,
						"piece":      int(piece),
						"total_size": len(info),
					})
					if err != nil {
						return
					}
					payload := append([]byte{metadata_ext_id}, header...)
					payload = append(payload, info[begin:end]...)
					if _, err := conn.Write((&message{id: msg_extended, payload: payload}).serialize()); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	tracker := new_fake_tracker()
	defer tracker.close()
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: uint16(listener.Addr().(*net.TCPAddr).Port)})

	link_uri := "magnet:?xt=urn:btih:" + hex.EncodeToString(wanted.info_hash[:]) +
		"&tr=" + url.QueryEscape(tracker.server.URL+"/announce")
	link, err := parse_magnet(link_uri)
	if err != nil {
		t.Fatalf("parse_magnet: %v", err)
	}

	cfg := test_config(t, filepath.Join(t.TempDir(), "never.bin"))
	if _, err := resolve_metadata(link, cfg, [20]byte{'m'}, &stat_sink{}); err == nil {
		t.Fatal("metadata that does not hash to the requested infohash must be rejected")
	}
}

// A peer serving an unrelated torrent must also be refused, at the handshake.
func TestMagnetRejectsPeerServingTheWrongTorrent(t *testing.T) {
	const piece_length = 16384

	wanted_info := build_info("wanted.bin", piece_length, deterministic_payload(piece_length), nil)
	wanted_path := write_torrent(t, t.TempDir(), "http://tracker.invalid/announce", wanted_info)
	wanted, err := open_torrent(wanted_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	other_info := build_info("other.bin", piece_length, deterministic_payload(piece_length), nil)
	other_path := write_torrent(t, t.TempDir(), "http://tracker.invalid/announce", other_info)
	other, err := open_torrent(other_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	other_payload := deterministic_payload(piece_length)
	seed_path := filepath.Join(t.TempDir(), "other.bin")
	if err := os.WriteFile(seed_path, other_payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	seed_cfg := test_config(t, seed_path)
	seed_cfg.listen_port = 0
	store, err := new_piece_store(other, seed_path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.close()

	s, err := new_seeder(other, store, [20]byte{'s'}, seed_cfg, &stat_sink{}, func(int) bool { return true })
	if err != nil {
		t.Fatalf("new_seeder: %v", err)
	}
	go s.serve(seed_cfg.root_ctx)
	defer s.close()

	tracker := new_fake_tracker()
	defer tracker.close()
	tracker.set_peer(peer{ip: [4]byte{127, 0, 0, 1}, port: uint16(s.listener.Addr().(*net.TCPAddr).Port)})

	link_uri := "magnet:?xt=urn:btih:" + hex.EncodeToString(wanted.info_hash[:]) +
		"&tr=" + url.QueryEscape(tracker.server.URL+"/announce")
	link, err := parse_magnet(link_uri)
	if err != nil {
		t.Fatalf("parse_magnet: %v", err)
	}

	cfg := test_config(t, filepath.Join(t.TempDir(), "never.bin"))
	if _, err := resolve_metadata(link, cfg, [20]byte{'m'}, &stat_sink{}); err == nil {
		t.Fatal("a peer serving a different torrent must not satisfy a magnet request")
	}
}

// --- tracker failure -------------------------------------------------------

func TestDownloadFailsWhenTheTrackerIsBroken(t *testing.T) {
	info_raw := build_info("nope.bin", 16384, deterministic_payload(16384), nil)
	tracker := new_fake_tracker()
	defer tracker.close()
	tracker.fail = true

	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	output := filepath.Join(t.TempDir(), "nope.bin")
	cfg := test_config(t, output)
	store, err := new_piece_store(torrent, output)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.close()

	d := new_downloader(torrent, cfg, store, [20]byte{'x'}, &stat_sink{})
	if err := d.run(); err == nil {
		t.Fatal("a tracker failure reason should surface as a download error")
	}
}

func TestDownloadFailsWithNoPeers(t *testing.T) {
	info_raw := build_info("empty.bin", 16384, deterministic_payload(16384), nil)
	tracker := new_fake_tracker()
	defer tracker.close()

	torrent_path := write_torrent(t, t.TempDir(), tracker.server.URL+"/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	output := filepath.Join(t.TempDir(), "empty.bin")
	cfg := test_config(t, output)
	store, err := new_piece_store(torrent, output)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.close()

	d := new_downloader(torrent, cfg, store, [20]byte{'x'}, &stat_sink{})
	if err := d.run(); err == nil {
		t.Fatal("a tracker with no peers should surface as a download error")
	}
	if tracker.announce_count() == 0 {
		t.Fatal("the tracker was never contacted")
	}
}

// --- seeding while downloading ---------------------------------------------

func TestSeederServesIncomingPeerHandshake(t *testing.T) {
	const piece_length = 16384
	payload := deterministic_payload(piece_length)
	info_raw := build_info("served.bin", piece_length, payload, nil)
	torrent_path := write_torrent(t, t.TempDir(), "http://tracker.invalid/announce", info_raw)
	torrent, err := open_torrent(torrent_path)
	if err != nil {
		t.Fatalf("open_torrent: %v", err)
	}

	seed_path := filepath.Join(t.TempDir(), "served.bin")
	if err := os.WriteFile(seed_path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	seed := start_seeder(t, torrent, seed_path)

	// A peer that speaks the wire protocol by hand.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(seed.port))), 5*time.Second)
	if err != nil {
		t.Fatalf("dial seeder: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var peer_id [20]byte
	copy(peer_id[:], "-TT0001-manualpeer000")
	hello := new_handshake(torrent.info_hash, peer_id)
	if _, err := conn.Write(hello.serialize()); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	reply, err := read_handshake(conn)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if reply.info_hash != torrent.info_hash {
		t.Fatalf("seeder answered with infohash %x", reply.info_hash)
	}

	// It should send a bitfield listing the piece it holds.
	msg, err := read_message(conn)
	if err != nil {
		t.Fatalf("read bitfield: %v", err)
	}
	if msg == nil || msg.id != msg_bitfield {
		t.Fatalf("expected a bitfield, got %v", msg)
	}
	available := bitfield_from_bytes(msg.payload, torrent.num_pieces())
	if !available.has_piece(0) {
		t.Fatal("the seeder did not advertise its piece")
	}

	// Ask for it.
	if _, err := conn.Write((&message{id: msg_interested}).serialize()); err != nil {
		t.Fatalf("write interested: %v", err)
	}

	unchoked := false
	for !unchoked {
		msg, err := read_message(conn)
		if err != nil {
			t.Fatalf("waiting for unchoke: %v", err)
		}
		if msg != nil && msg.id == msg_unchoke {
			unchoked = true
		}
	}

	if _, err := conn.Write(format_request(0, 0, 1024).serialize()); err != nil {
		t.Fatalf("write request: %v", err)
	}

	block, err := read_message(conn)
	if err != nil {
		t.Fatalf("read block: %v", err)
	}
	block_index, begin, data, err := piece_header(block)
	if err != nil {
		t.Fatalf("piece_header: %v", err)
	}
	if block_index != 0 || begin != 0 || len(data) != 1024 {
		t.Fatalf("block header = index %d begin %d len %d", block_index, begin, len(data))
	}
	if !bytes.Equal(data, payload[:1024]) {
		t.Fatal("the served block does not match the payload")
	}

	// A handshake for a different infohash must be refused.
	other, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(seed.port))), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer other.Close()
	other.SetDeadline(time.Now().Add(5 * time.Second))
	bogus := new_handshake([20]byte{0xaa}, peer_id)
	other.Write(bogus.serialize())
	if _, err := read_handshake(other); err == nil {
		t.Fatal("the seeder answered a handshake for the wrong infohash")
	}
}
