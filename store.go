package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// The piece store maps offsets in the concatenated payload stream onto real
// files. Downloads write here, seeding reads from here, and because the bytes
// land in the final location as they arrive, a resumed download does not have
// to be reassembled at the end.

type piece_store struct {
	t       *torrent_file
	target  string
	dir     string
	handles map[int]*os.File
	mu      sync.Mutex
	closed  bool
}

// new_piece_store prepares the destination. Single-file torrents get one
// preallocated file; multi-file torrents get a directory tree.
func new_piece_store(t *torrent_file, target string) (*piece_store, error) {
	if target == "" {
		return nil, fmt.Errorf("store: empty output path")
	}

	s := &piece_store{
		t:       t,
		target:  target,
		handles: make(map[int]*os.File),
	}

	if t.multi {
		s.dir = target
		if err := os.MkdirAll(s.dir, 0o755); err != nil {
			return nil, err
		}
		for _, entry := range t.files {
			full := filepath.Join(append([]string{s.dir}, entry.path...)...)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return nil, err
			}
			f, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0o644)
			if err != nil {
				return nil, err
			}
			if err := f.Truncate(entry.length); err != nil {
				f.Close()
				return nil, err
			}
			s.handles[index_of(s.t.files, entry)] = f
		}
		return s, nil
	}

	s.dir = filepath.Dir(target)
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(t.length); err != nil {
		f.Close()
		return nil, err
	}
	s.handles[0] = f
	return s, nil
}

func index_of(files []file_entry, want file_entry) int {
	for i, f := range files {
		if f.offset == want.offset && f.length == want.length {
			return i
		}
	}
	return 0
}

// file_at finds the payload file containing an absolute offset.
func (t *torrent_file) file_at(offset int64) int {
	return sort.Search(len(t.files), func(i int) bool {
		return t.files[i].offset+t.files[i].length > offset
	})
}

func (s *piece_store) handle(index int) (*os.File, error) {
	if f, ok := s.handles[index]; ok {
		return f, nil
	}
	entry := s.t.files[index]
	full := filepath.Join(append([]string{s.dir}, entry.path...)...)
	f, err := os.OpenFile(full, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	s.handles[index] = f
	return f, nil
}

// write_block stores a block that may straddle the boundary between two files.
func (s *piece_store) write_block(offset int64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store: closed")
	}

	for len(data) > 0 {
		index := s.t.file_at(offset)
		if index >= len(s.t.files) {
			return fmt.Errorf("store: offset %d is past the end of the payload", offset)
		}
		entry := s.t.files[index]
		f, err := s.handle(index)
		if err != nil {
			return err
		}
		within := offset - entry.offset
		room := entry.length - within
		if room <= 0 {
			return fmt.Errorf("store: offset %d lands outside file %d", offset, index)
		}
		chunk := int64(len(data))
		if chunk > room {
			chunk = room
		}
		if _, err := f.WriteAt(data[:chunk], within); err != nil {
			return err
		}
		data = data[chunk:]
		offset += chunk
	}
	return nil
}

// read_block pulls a block for seeding. It may span files.
func (s *piece_store) read_block(offset int64, length int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("store: closed")
	}
	if offset < 0 || offset+length > s.t.length {
		return nil, fmt.Errorf("store: read of %d bytes at %d is out of range", length, offset)
	}

	out := make([]byte, 0, length)
	cursor := offset
	remaining := length
	for remaining > 0 {
		index := s.t.file_at(cursor)
		if index >= len(s.t.files) {
			return nil, fmt.Errorf("store: offset %d is past the end of the payload", cursor)
		}
		entry := s.t.files[index]
		f, err := s.handle(index)
		if err != nil {
			return nil, err
		}
		within := cursor - entry.offset
		room := entry.length - within
		if room <= 0 {
			return nil, fmt.Errorf("store: offset %d lands outside file %d", cursor, index)
		}
		chunk := remaining
		if chunk > room {
			chunk = room
		}
		buf := make([]byte, chunk)
		if _, err := f.ReadAt(buf, within); err != nil {
			return nil, err
		}
		out = append(out, buf...)
		cursor += chunk
		remaining -= chunk
	}
	return out, nil
}

// sync flushes every open handle so an interrupted run keeps its bytes.
func (s *piece_store) sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.handles {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func (s *piece_store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var first error
	for _, f := range s.handles {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	s.handles = nil
	return first
}
