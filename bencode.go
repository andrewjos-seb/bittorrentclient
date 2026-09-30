package main

// A bencode reader/writer that keeps the exact byte span of every value it
// decodes.
//
// The reason for the byte spans: the infohash is the SHA-1 of the *info*
// dictionary exactly as it sits in the .torrent file. Decoding that dictionary
// into a Go struct and re-encoding it is lossy — it drops keys the struct does
// not know about, invents keys the struct has but the file did not, and can
// change integer framing. Anything that loses a byte produces an infohash the
// tracker and the swarm both reject. Keeping the original bytes around means we
// can hash the value we were actually handed, with no round-trip at all.

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

const (
	bnode_int  = 'i'
	bnode_str  = 's'
	bnode_list = 'l'
	bnode_dict = 'd'
)

var err_bencode_short = errors.New("bencode: value is truncated")

// bnode is one decoded bencode value. raw always holds the verbatim bytes this
// value occupied in the source buffer.
type bnode struct {
	kind byte
	raw  []byte

	str  []byte
	num  int64
	list []*bnode
	dict map[string]*bnode
	keys []string // insertion order, preserved for round-tripping
}

// bdecode parses a whole buffer and rejects trailing garbage.
func bdecode(data []byte) (*bnode, error) {
	node, next, err := bscan(data, 0)
	if err != nil {
		return nil, err
	}
	if next != len(data) {
		return nil, fmt.Errorf("bencode: %d trailing bytes after value", len(data)-next)
	}
	return node, nil
}

// bscan decodes the value starting at pos and reports where it ended.
func bscan(data []byte, pos int) (*bnode, int, error) {
	start := pos
	if pos >= len(data) {
		return nil, 0, err_bencode_short
	}

	switch c := data[pos]; {
	case c == 'i':
		idx := bytes.IndexByte(data[pos:], 'e')
		if idx < 0 {
			return nil, 0, err_bencode_short
		}
		end := pos + idx
		num, err := strconv.ParseInt(string(data[pos+1:end]), 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("bencode: malformed integer %q", data[start:end+1])
		}
		return &bnode{kind: bnode_int, num: num, raw: data[start : end+1]}, end + 1, nil

	case c >= '0' && c <= '9':
		colon := bytes.IndexByte(data[pos:], ':')
		if colon < 0 {
			return nil, 0, err_bencode_short
		}
		length, err := strconv.Atoi(string(data[pos : pos+colon]))
		if err != nil || length < 0 {
			return nil, 0, fmt.Errorf("bencode: malformed string length %q", data[start:pos+colon])
		}
		body := pos + colon + 1
		if body+length > len(data) {
			return nil, 0, err_bencode_short
		}
		return &bnode{kind: bnode_str, str: data[body : body+length], raw: data[start : body+length]}, body + length, nil

	case c == 'l':
		node := &bnode{kind: bnode_list}
		pos++
		for {
			if pos >= len(data) {
				return nil, 0, err_bencode_short
			}
			if data[pos] == 'e' {
				node.raw = data[start : pos+1]
				return node, pos + 1, nil
			}
			child, next, err := bscan(data, pos)
			if err != nil {
				return nil, 0, err
			}
			node.list = append(node.list, child)
			pos = next
		}

	case c == 'd':
		node := &bnode{kind: bnode_dict, dict: make(map[string]*bnode)}
		pos++
		for {
			if pos >= len(data) {
				return nil, 0, err_bencode_short
			}
			if data[pos] == 'e' {
				node.raw = data[start : pos+1]
				return node, pos + 1, nil
			}
			key, next, err := bscan(data, pos)
			if err != nil {
				return nil, 0, err
			}
			if key.kind != bnode_str {
				return nil, 0, errors.New("bencode: dictionary key is not a string")
			}
			value, after, err := bscan(data, next)
			if err != nil {
				return nil, 0, err
			}
			name := string(key.str)
			if _, seen := node.dict[name]; !seen {
				node.keys = append(node.keys, name)
			}
			node.dict[name] = value
			pos = after
		}

	default:
		return nil, 0, fmt.Errorf("bencode: unexpected byte %q at offset %d", c, pos)
	}
}

func (n *bnode) get(key string) *bnode {
	if n == nil || n.kind != bnode_dict {
		return nil
	}
	return n.dict[key]
}

func (n *bnode) as_bytes() []byte {
	if n == nil || n.kind != bnode_str {
		return nil
	}
	return n.str
}

func (n *bnode) as_string() string {
	return string(n.as_bytes())
}

func (n *bnode) as_int() (int64, error) {
	if n == nil || n.kind != bnode_int {
		return 0, errors.New("bencode: value is not an integer")
	}
	return n.num, nil
}

// bencode_encode writes v in bencode form. Dictionaries are written with their
// keys sorted, which is what the wire format requires.
func bencode_encode(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case int:
		fmt.Fprintf(buf, "i%de", t)
	case int64:
		fmt.Fprintf(buf, "i%de", t)
	case uint16:
		fmt.Fprintf(buf, "i%de", t)
	case string:
		fmt.Fprintf(buf, "%d:", len(t))
		buf.WriteString(t)
	case []byte:
		fmt.Fprintf(buf, "%d:", len(t))
		buf.Write(t)
	case []interface{}:
		buf.WriteByte('l')
		for _, item := range t {
			if err := bencode_encode(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	case []string:
		items := make([]interface{}, len(t))
		for i, s := range t {
			items[i] = s
		}
		return bencode_encode(buf, items)
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('d')
		for _, k := range keys {
			if err := bencode_encode(buf, k); err != nil {
				return err
			}
			if err := bencode_encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	default:
		return fmt.Errorf("bencode: cannot encode value of type %T", v)
	}
	return nil
}

func bencode_bytes(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := bencode_encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
