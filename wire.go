package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// The peer wire protocol (BEP 0003).
//
// Two conventions in here are easy to get subtly wrong, and both were wrong in
// the original code:
//
//  1. Every multi-byte field on the wire is big-endian. Request payloads were
//     being written little-endian, so index/begin/length arrived byte-swapped
//     and peers answered with garbage or dropped us.
//
//  2. A bitfield's *high* bit in the first byte is piece 0. Reading a bitfield
//     with the low bit first means the availability map is mirrored: a peer
//     that has piece 0 looks like it has piece 7, so the client spends the
//     whole session requesting pieces nobody has.

const (
	protocol_string    = "BitTorrent protocol"
	max_message_length = 1 << 21 // 2 MiB is far above any legal piece block
)

type bitfield []byte

func new_bitfield(num_pieces int) bitfield {
	if num_pieces <= 0 {
		return bitfield{}
	}
	return make(bitfield, (num_pieces+7)/8)
}

func bitfield_from_bytes(raw []byte, num_pieces int) bitfield {
	bf := new_bitfield(num_pieces)
	copy(bf, raw)
	// Trailing bits past the piece count must read as absent.
	for i := num_pieces; i < len(bf)*8; i++ {
		bf.clear_piece(i)
	}
	return bf
}

// has_piece reports whether the peer holds a piece. Bit 7 of the byte holding
// piece 0 is set for piece 0 — high bit first, matching set_piece.
func (bf bitfield) has_piece(index int) bool {
	if index < 0 {
		return false
	}
	byte_index := index / 8
	if byte_index >= len(bf) {
		return false
	}
	offset := uint(index % 8)
	return bf[byte_index]>>(7-offset)&1 != 0
}

func (bf bitfield) set_piece(index int) {
	if index < 0 {
		return
	}
	byte_index := index / 8
	if byte_index >= len(bf) {
		return
	}
	bf[byte_index] |= 1 << uint(7-index%8)
}

func (bf bitfield) clear_piece(index int) {
	if index < 0 {
		return
	}
	byte_index := index / 8
	if byte_index >= len(bf) {
		return
	}
	bf[byte_index] &^= 1 << uint(7-index%8)
}

func (bf bitfield) count() int {
	total := 0
	for _, b := range bf {
		for ; b != 0; b &= b - 1 {
			total++
		}
	}
	return total
}

func (bf bitfield) all_set(num_pieces int) bool {
	for i := 0; i < num_pieces; i++ {
		if !bf.has_piece(i) {
			return false
		}
	}
	return true
}

func (bf bitfield) clone() bitfield {
	out := make(bitfield, len(bf))
	copy(out, bf)
	return out
}

// keep_only intersects this bitfield with another, used to drop pieces the
// remote peer does not actually hold.
func (bf bitfield) keep_only(other bitfield) {
	for i := range bf {
		if i >= len(other) {
			bf[i] = 0
			continue
		}
		bf[i] &= other[i]
	}
}

type handshake struct {
	pstr      string
	info_hash [20]byte
	peer_id   [20]byte

	// The 8 reserved bytes carry feature bits. BEP 0010 claims bit 0x10 of
	// reserved byte 5 for the extension protocol.
	reserved_extended bool
}

const reserved_extended_bit = 0x10

func new_handshake(info_hash [20]byte, peer_id [20]byte) *handshake {
	return &handshake{
		pstr:      protocol_string,
		info_hash: info_hash,
		peer_id:   peer_id,
	}
}

func (h *handshake) serialize() []byte {
	buf := make([]byte, len(h.pstr)+49)
	// 49 = 1 (length prefix) + 8 (reserved) + 20 (infohash) + 20 (peer id)
	buf[0] = byte(len(h.pstr))

	curr := 1
	curr += copy(buf[curr:], h.pstr)

	reserved := make([]byte, 8)
	if h.reserved_extended {
		reserved[5] |= reserved_extended_bit
	}
	curr += copy(buf[curr:], reserved)

	curr += copy(buf[curr:], h.info_hash[:])
	copy(buf[curr:], h.peer_id[:])

	return buf
}

func read_handshake(conn net.Conn) (*handshake, error) {
	len_buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, len_buf); err != nil {
		return nil, err
	}

	pstr_len := int(len_buf[0])
	if pstr_len == 0 || pstr_len > 64 {
		return nil, fmt.Errorf("invalid pstr length %d", pstr_len)
	}

	buf := make([]byte, pstr_len+48)
	// 48 = 8 (reserved) + 20 (infohash) + 20 (peer id)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	pstr := string(buf[0:pstr_len])
	if pstr != protocol_string {
		return nil, fmt.Errorf("unexpected protocol string %q", pstr)
	}

	var info_hash, peer_id [20]byte
	copy(info_hash[:], buf[pstr_len+8:pstr_len+28])
	copy(peer_id[:], buf[pstr_len+28:])

	return &handshake{
		pstr:              pstr,
		info_hash:         info_hash,
		peer_id:           peer_id,
		reserved_extended: buf[pstr_len+5]&reserved_extended_bit != 0,
	}, nil
}

type message_id uint8

const (
	msg_choke          message_id = 0
	msg_unchoke        message_id = 1
	msg_interested     message_id = 2
	msg_not_interested message_id = 3
	msg_have           message_id = 4
	msg_bitfield       message_id = 5
	msg_request        message_id = 6
	msg_piece          message_id = 7
	msg_cancel         message_id = 8
	msg_port           message_id = 9
	msg_extended       message_id = 20 // BEP 0010
)

func (id message_id) String() string {
	switch id {
	case msg_choke:
		return "choke"
	case msg_unchoke:
		return "unchoke"
	case msg_interested:
		return "interested"
	case msg_not_interested:
		return "not_interested"
	case msg_have:
		return "have"
	case msg_bitfield:
		return "bitfield"
	case msg_request:
		return "request"
	case msg_piece:
		return "piece"
	case msg_cancel:
		return "cancel"
	case msg_port:
		return "port"
	case msg_extended:
		return "extended"
	}
	return fmt.Sprintf("unknown(%d)", uint8(id))
}

type message struct {
	id      message_id
	payload []byte
}

func (m *message) serialize() []byte {
	if m == nil {
		return make([]byte, 4) // keep-alive
	}
	length := uint32(len(m.payload) + 1)
	buf := make([]byte, length+4)
	binary.BigEndian.PutUint32(buf[0:4], length)
	buf[4] = byte(m.id)
	copy(buf[5:], m.payload)
	return buf
}

// read_message reads exactly one framed message. A zero length prefix is a
// keep-alive and is reported as (nil, nil).
func read_message(r io.Reader) (*message, error) {
	len_buf := make([]byte, 4)
	if _, err := io.ReadFull(r, len_buf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(len_buf)

	if length == 0 {
		return nil, nil
	}
	if length > max_message_length {
		return nil, fmt.Errorf("message length %d exceeds the %d byte cap", length, max_message_length)
	}

	msg_buf := make([]byte, length)
	if _, err := io.ReadFull(r, msg_buf); err != nil {
		return nil, err
	}

	return &message{
		id:      message_id(msg_buf[0]),
		payload: msg_buf[1:],
	}, nil
}

type block_request struct {
	index  int
	begin  int64
	length int64
}

// format_request encodes a request. Big-endian, always.
func format_request(index int, begin, length int64) *message {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uint32(index))
	binary.BigEndian.PutUint32(payload[4:8], uint32(begin))
	binary.BigEndian.PutUint32(payload[8:12], uint32(length))
	return &message{
		id:      msg_request,
		payload: payload,
	}
}

func parse_request(msg *message) (block_request, error) {
	if msg == nil || msg.id != msg_request {
		return block_request{}, fmt.Errorf("expected request, got %v", msg)
	}
	if len(msg.payload) != 12 {
		return block_request{}, fmt.Errorf("request payload is %d bytes, want 12", len(msg.payload))
	}
	req := block_request{
		index:  int(binary.BigEndian.Uint32(msg.payload[0:4])),
		begin:  int64(binary.BigEndian.Uint32(msg.payload[4:8])),
		length: int64(binary.BigEndian.Uint32(msg.payload[8:12])),
	}
	if req.length <= 0 || req.length > block_size*2 {
		return block_request{}, fmt.Errorf("request length %d is out of range", req.length)
	}
	return req, nil
}

func format_cancel(req block_request) *message {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uint32(req.index))
	binary.BigEndian.PutUint32(payload[4:8], uint32(req.begin))
	binary.BigEndian.PutUint32(payload[8:12], uint32(req.length))
	return &message{id: msg_cancel, payload: payload}
}

func format_piece(index int, begin int64, data []byte) *message {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(payload[0:4], uint32(index))
	binary.BigEndian.PutUint32(payload[4:8], uint32(begin))
	copy(payload[8:], data)
	return &message{id: msg_piece, payload: payload}
}

func format_have(index int) *message {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(index))
	return &message{
		id:      msg_have,
		payload: payload,
	}
}

// piece_header pulls the index, begin offset and data out of a piece message.
func piece_header(msg *message) (int, int64, []byte, error) {
	if msg == nil || msg.id != msg_piece {
		return 0, 0, nil, fmt.Errorf("expected piece message, got %v", msg)
	}
	if len(msg.payload) < 9 {
		return 0, 0, nil, fmt.Errorf("piece payload is %d bytes, want at least 9", len(msg.payload))
	}
	index := int(binary.BigEndian.Uint32(msg.payload[0:4]))
	begin := int64(binary.BigEndian.Uint32(msg.payload[4:8]))
	return index, begin, msg.payload[8:], nil
}

// parse_piece validates a piece message against the piece we asked for and
// copies the block into buf.
func parse_piece(index int, buf []byte, msg *message) (int, error) {
	parsed_index, begin, data, err := piece_header(msg)
	if err != nil {
		return 0, err
	}
	if parsed_index != index {
		return 0, fmt.Errorf("expected piece %d, got %d", index, parsed_index)
	}
	if begin < 0 || begin > int64(len(buf)) {
		return 0, fmt.Errorf("begin offset %d is out of range for a %d byte piece", begin, len(buf))
	}
	if begin+int64(len(data)) > int64(len(buf)) {
		return 0, fmt.Errorf("block overruns the piece: begin %d + %d > %d", begin, len(data), len(buf))
	}
	copy(buf[begin:], data)
	return len(data), nil
}

func parse_have(msg *message) (int, error) {
	if msg == nil || msg.id != msg_have {
		return 0, fmt.Errorf("expected have, got %v", msg)
	}
	if len(msg.payload) != 4 {
		return 0, fmt.Errorf("have payload is %d bytes, want 4", len(msg.payload))
	}
	return int(binary.BigEndian.Uint32(msg.payload)), nil
}

func format_port(port uint16) *message {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, port)
	return &message{id: msg_port, payload: payload}
}

// --- BEP 0010 extension protocol -------------------------------------------

// format_extended frames an extended message: one byte of negotiated extension
// id, then a bencoded body.
func format_extended(ext_id byte, body interface{}) (*message, error) {
	raw, err := bencode_bytes(body)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 1+len(raw))
	payload[0] = ext_id
	copy(payload[1:], raw)
	return &message{id: msg_extended, payload: payload}, nil
}

func parse_extended(msg *message) (byte, *bnode, error) {
	ext_id, body, _, err := parse_extended_body(msg)
	return ext_id, body, err
}

// parse_extended_body is the BEP 0009-aware form: metadata blocks arrive as
// one extended message carrying a bencoded header immediately followed by the
// raw block, so the bytes after the bencode value matter.
func parse_extended_body(msg *message) (byte, *bnode, []byte, error) {
	if msg == nil || msg.id != msg_extended {
		return 0, nil, nil, fmt.Errorf("expected extended message, got %v", msg)
	}
	if len(msg.payload) < 1 {
		return 0, nil, nil, errors.New("extended message has no extension id")
	}
	ext_id := msg.payload[0]
	if len(msg.payload) == 1 {
		return ext_id, nil, nil, nil
	}

	body, next, err := bscan(msg.payload, 1)
	if err != nil {
		return ext_id, nil, nil, err
	}
	return ext_id, body, msg.payload[next:], nil
}
