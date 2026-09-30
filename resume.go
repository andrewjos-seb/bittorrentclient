package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Download resuming.
//
// The piece map is persisted next to the output so an interrupted transfer
// picks up where it stopped instead of re-fetching verified bytes. The state
// is written atomically — a crash mid-write must never leave a truncated
// bitfield behind, because a corrupt map is worse than no map at all.

const resume_version = 1

const resume_save_interval = time.Second

type resume_state struct {
	Version     int       `json:"version"`
	InfoHash    string    `json:"info_hash"`
	Name        string    `json:"name"`
	Length      int64     `json:"length"`
	PieceLength int64     `json:"piece_length"`
	NumPieces   int       `json:"num_pieces"`
	Bitfield    string    `json:"bitfield"` // base64 of the raw availability bytes
	Completed   int       `json:"completed_pieces"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// resume_path sits beside the payload: for a multi-file torrent the output is
// a directory, and "<dir>.resume" is its sibling.
func (d *downloader) resume_path() string {
	if d.cfg.resume_path != "" {
		return d.cfg.resume_path
	}
	return d.cfg.output + ".resume"
}

func (d *downloader) save_resume_throttled() {
	d.mu.Lock()
	if time.Since(d.last_save) < resume_save_interval {
		d.mu.Unlock()
		return
	}
	d.last_save = time.Now()
	d.mu.Unlock()

	if err := d.save_resume(false); err != nil {
		log_resume("could not save resume state: %v", err)
	}
}

func (d *downloader) save_resume(force bool) error {
	if !d.cfg.resume {
		return nil
	}
	if !force {
		d.mu.Lock()
		if time.Since(d.last_save) < resume_save_interval {
			d.mu.Unlock()
			return nil
		}
		d.last_save = time.Now()
		d.mu.Unlock()
	}

	d.mu.Lock()
	available := new_bitfield(d.t.num_pieces())
	completed := 0
	for i, state := range d.states {
		if state == piece_complete {
			available.set_piece(i)
			completed++
		}
	}
	d.mu.Unlock()

	state := resume_state{
		Version:     resume_version,
		InfoHash:    fmt.Sprintf("%x", d.t.info_hash),
		Name:        d.t.name,
		Length:      d.t.length,
		PieceLength: d.t.piece_length,
		NumPieces:   d.t.num_pieces(),
		Bitfield:    base64.StdEncoding.EncodeToString(available),
		Completed:   completed,
		UpdatedAt:   time.Now().UTC(),
	}

	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	target := d.resume_path()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// load_resume restores the verified piece map. It refuses state belonging to a
// different infohash or a differently shaped torrent.
func (d *downloader) load_resume() (int, error) {
	target := d.resume_path()
	raw, err := os.ReadFile(target)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var state resume_state
	if err := json.Unmarshal(raw, &state); err != nil {
		return 0, fmt.Errorf("resume file is corrupt: %w", err)
	}
	if state.Version != resume_version {
		return 0, fmt.Errorf("resume file version %d is not supported", state.Version)
	}
	if state.InfoHash != fmt.Sprintf("%x", d.t.info_hash) {
		return 0, fmt.Errorf("resume file is for infohash %s, not %x", state.InfoHash, d.t.info_hash)
	}
	if state.NumPieces != d.t.num_pieces() || state.Length != d.t.length {
		return 0, fmt.Errorf("resume file describes a different torrent shape")
	}

	available, err := base64.StdEncoding.DecodeString(state.Bitfield)
	if err != nil {
		return 0, fmt.Errorf("resume bitfield is not decodable: %w", err)
	}
	if len(available) != len(new_bitfield(d.t.num_pieces())) {
		return 0, fmt.Errorf("resume bitfield is %d bytes, want %d", len(available),
			len(new_bitfield(d.t.num_pieces())))
	}

	restored := 0
	d.mu.Lock()
	for i := 0; i < d.t.num_pieces(); i++ {
		if bitfield(available).has_piece(i) {
			d.states[i] = piece_complete
			d.completed_pieces++
			d.completed_bytes += d.t.piece_size(i)
			restored++
		}
	}
	d.mu.Unlock()

	if d.cfg.verify {
		return d.verify_resumed()
	}
	return restored, nil
}

// verify_resumed re-hashes every piece the resume file claims to hold and
// drops the ones that do not match. This is the belt-and-braces pass for
// --verify, or for a store that was tampered with between runs.
func (d *downloader) verify_resumed() (int, error) {
	d.mu.Lock()
	candidates := make([]int, 0, d.completed_pieces)
	for i, state := range d.states {
		if state == piece_complete {
			candidates = append(candidates, i)
		}
	}
	d.mu.Unlock()

	good := 0
	for _, index := range candidates {
		data, err := d.store.read_block(d.t.piece_offset(index), d.t.piece_size(index))
		if err != nil {
			d.demote_piece(index)
			continue
		}
		if hash_piece(data) != d.t.piece_hashes[index] {
			d.demote_piece(index)
			continue
		}
		good++
	}

	rejected := len(candidates) - good
	if rejected > 0 {
		log_resume("%d resumed piece(s) failed verification and will be fetched again", rejected)
	}
	return good, nil
}

func (d *downloader) demote_piece(index int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.states[index] == piece_complete {
		d.states[index] = piece_missing
		d.completed_pieces--
		d.completed_bytes -= d.t.piece_size(index)
	}
}

// verify_store hashes everything on disk, which is what a pure seeder needs to
// know before it advertises pieces to the swarm.
func verify_store(t *torrent_file, store *piece_store) (bitfield, error) {
	available := new_bitfield(t.num_pieces())
	for index := 0; index < t.num_pieces(); index++ {
		data, err := store.read_block(t.piece_offset(index), t.piece_size(index))
		if err != nil {
			return available, err
		}
		if hash_piece(data) == t.piece_hashes[index] {
			available.set_piece(index)
		}
	}
	return available, nil
}

func log_resume(format string, args ...interface{}) {
	log_line("resume: "+format, args...)
}
