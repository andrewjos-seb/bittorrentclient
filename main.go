package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Command line entry point.

type config struct {
	// ctx scopes network work for the transfer. The downloader replaces it
	// with a child scope so finishing the transfer cancels every peer read,
	// while root_ctx keeps the seeding listener alive.
	ctx      context.Context
	root_ctx context.Context
	cancel   context.CancelFunc

	output       string
	resume_path  string
	listen_port  uint16
	no_seed      bool
	keep_seeding bool
	dashboard    bool
	resume       bool
	verify       bool
	seed_only    bool
	peer_timeout time.Duration

	down_limiter *rate_limiter
	up_limiter   *rate_limiter
}

func log_line(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func main() {
	log.SetFlags(log.Ltime)

	var (
		port         = flag.Int("port", 6881, "TCP port to listen on for incoming peers (0 disables seeding)")
		no_seed      = flag.Bool("no-seed", false, "do not open a listening port or upload")
		keep_seeding = flag.Bool("keep-seeding", false, "keep serving uploaded pieces after the download finishes")
		no_dashboard = flag.Bool("no-dashboard", false, "plain log lines instead of the live dashboard")
		no_resume    = flag.Bool("no-resume", false, "ignore and do not write resume state")
		verify       = flag.Bool("verify", false, "re-hash resumed pieces (and the store in --seed-only)")
		seed_only    = flag.Bool("seed-only", false, "serve the payload without downloading anything")
		info_only    = flag.Bool("info", false, "print metainfo and exit")
		down_limit   = flag.String("down-limit", "", "download cap, e.g. 500KB, 2MiB, 1.5mb/s (0 = unlimited)")
		up_limit     = flag.String("up-limit", "", "upload cap, e.g. 250KB")
		resume_file  = flag.String("resume-file", "", "override the resume state path")
		peer_timeout = flag.Duration("peer-timeout", 30*time.Second, "how long to wait on a silent peer")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "torrent-client — concurrent BitTorrent client (BEP 0003)\n\n")
		fmt.Fprintf(os.Stderr, "usage:\n  %s [flags] <file.torrent | magnet:?xt=urn:btih:...> [output]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nexamples:\n")
		fmt.Fprintf(os.Stderr, "  %s ubuntu.torrent ./ubuntu.iso\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --port 6882 --down-limit 2MiB 'magnet:?xt=urn:btih:...&tr=udp://tracker:6969' ./out\n", os.Args[0])
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	source := flag.Arg(0)

	down_cap, err := parse_rate(*down_limit)
	if err != nil {
		log.Fatalf("--down-limit: %v", err)
	}
	up_cap, err := parse_rate(*up_limit)
	if err != nil {
		log.Fatalf("--up-limit: %v", err)
	}

	root_ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		log.Printf("interrupted: shutting down and flushing state")
		cancel()
	}()

	cfg := &config{
		ctx:          root_ctx,
		root_ctx:     root_ctx,
		cancel:       cancel,
		listen_port:  uint16(*port),
		no_seed:      *no_seed,
		keep_seeding: *keep_seeding,
		dashboard:    !*no_dashboard,
		resume:       !*no_resume,
		verify:       *verify,
		seed_only:    *seed_only,
		resume_path:  *resume_file,
		peer_timeout: *peer_timeout,
		down_limiter: new_rate_limiter(down_cap),
		up_limiter:   new_rate_limiter(up_cap),
	}

	stats := &stat_sink{}

	peer_id, err := new_peer_id()
	if err != nil {
		log.Fatalf("could not generate a peer id: %v", err)
	}

	t, err := load_source(source, cfg, peer_id, stats)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if *info_only {
		print_info(t, cfg)
		return
	}

	cfg.output = flag.Arg(1)
	if cfg.output == "" {
		cfg.output = t.name
	}

	if cfg.seed_only {
		if err := run_seed_only(t, cfg, peer_id, stats); err != nil {
			log.Fatalf("seeding failed: %v", err)
		}
		return
	}

	store, err := new_piece_store(t, cfg.output)
	if err != nil {
		log.Fatalf("could not prepare the destination: %v", err)
	}
	defer store.close()

	d := new_downloader(t, cfg, store, peer_id, stats)
	if err := d.run(); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("interrupted: %d piece(s) still to fetch; rerun the same command to resume",
				d.pieces_remaining())
			return
		}
		log.Fatalf("download failed: %v", err)
	}

	log.Printf("downloaded %s to %s", t.name, cfg.output)
}

// load_source accepts either a .torrent file or a magnet URI.
func load_source(source string, cfg *config, peer_id [20]byte, stats *stat_sink) (*torrent_file, error) {
	if strings.HasPrefix(strings.ToLower(source), "magnet:") {
		link, err := parse_magnet(source)
		if err != nil {
			return nil, err
		}
		return resolve_metadata(link, cfg, peer_id, stats)
	}

	t, err := open_torrent(source)
	if err != nil {
		return nil, fmt.Errorf("could not open torrent file: %w", err)
	}
	return t, nil
}

func run_seed_only(t *torrent_file, cfg *config, peer_id [20]byte, stats *stat_sink) error {
	store, err := new_piece_store(t, cfg.output)
	if err != nil {
		return err
	}
	defer store.close()

	available, err := verify_store(t, store)
	if err != nil {
		return fmt.Errorf("could not read the payload: %w", err)
	}
	held := available.count()
	if held == 0 {
		return fmt.Errorf("no verified pieces in %s to seed", cfg.output)
	}
	log.Printf("verified %d/%d pieces on disk (%s)", held, t.num_pieces(), human_bytes(t.length))

	s, err := new_seeder(t, store, peer_id, cfg, stats, func(index int) bool {
		return available.has_piece(index)
	})
	if err != nil {
		return err
	}
	defer s.close()

	// Register with the tracker so peers can find us, then serve.
	if len(t.tracker_urls()) > 0 {
		_, err := announce_peers(t.tracker_urls(), &announce_request{
			info_hash: t.info_hash,
			peer_id:   peer_id,
			port:      cfg.listen_port,
			left:      0,
			numwant:   0,
			event:     event_started,
		})
		if err != nil {
			log.Printf("could not register with the tracker: %v", err)
		}
	}

	log.Printf("seeding %s on port %d; press Ctrl-C to stop", t.name, cfg.listen_port)
	return s.serve(cfg.root_ctx)
}

func print_info(t *torrent_file, cfg *config) {
	fmt.Printf("name          %s\n", t.name)
	fmt.Printf("infohash      %x\n", t.info_hash)
	fmt.Printf("length        %d bytes (%s)\n", t.length, human_bytes(t.length))
	fmt.Printf("piece length  %d bytes\n", t.piece_length)
	fmt.Printf("pieces        %d\n", t.num_pieces())
	fmt.Printf("multi-file    %v\n", t.multi)
	fmt.Printf("private       %v\n", t.private)
	for i, f := range t.files {
		fmt.Printf("  file[%d]     %s (%d bytes at offset %d)\n", i, strings.Join(f.path, "/"), f.length, f.offset)
	}
	for _, tracker := range t.tracker_urls() {
		fmt.Printf("tracker       %s\n", tracker)
	}
	fmt.Printf("info dict     %d bytes\n", len(t.info_dict()))
}

// parse_rate understands the usual shorthands: 500KB, 2MiB, 1.5mb/s.
func parse_rate(text string) (int64, error) {
	trimmed := strings.ToLower(strings.TrimSpace(text))
	switch trimmed {
	case "", "0", "none", "off", "unlimited":
		return 0, nil
	}

	suffixes := []struct {
		suffix     string
		multiplier int64
	}{
		{"kib/s", 1024}, {"mib/s", 1 << 20}, {"gib/s", 1 << 30},
		{"kb/s", 1000}, {"mb/s", 1000000}, {"gb/s", 1000000000},
		{"kib", 1024}, {"mib", 1 << 20}, {"gib", 1 << 30},
		{"kb", 1000}, {"mb", 1000000}, {"gb", 1000000000},
		{"k", 1024}, {"m", 1 << 20}, {"g", 1 << 30},
		{"b", 1},
	}

	multiplier := int64(1)
	for _, candidate := range suffixes {
		if strings.HasSuffix(trimmed, candidate.suffix) {
			multiplier = candidate.multiplier
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, candidate.suffix))
			break
		}
	}

	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q as a byte rate", text)
	}
	if value < 0 {
		return 0, fmt.Errorf("rate %q is negative", text)
	}
	return int64(value * float64(multiplier)), nil
}
