# BitTorrent Client

A concurrent BitTorrent client in Go implementing the peer wire protocol (BEP 0003), HTTP and
UDP tracker announces, and magnet link resolution.

```
torrent-client [flags] <file.torrent | magnet:?xt=urn:btih:...> [output]
```

## What is here

| Area | Implementation |
| --- | --- |
| Metainfo parsing | Byte-exact bencode scanner, single and multi-file layouts, `announce-list` tiers (BEP 0012) |
| Info-hash | SHA-1 over the verbatim bytes of the `info` dictionary |
| Trackers | HTTP(S) announce (BEP 0003), compact peers (BEP 0023), dictionary-model peers, `announce-list` fallback, **UDP tracker (BEP 0015)** |
| Wire protocol | Handshake, bitfield, choke/unchoke, interested, have, request/piece/cancel, byte-exact framing |
| Extension protocol | **BEP 0010** handshake and message framing, **BEP 0009** metadata exchange |
| Scheduling | Rarest-first piece picker, bounded request pipelining, endgame duplicate requests, stall recovery |
| Storage | Single-file and multi-file trees, blocks routed across file boundaries, preallocated output |
| Seeding | Listener for inbound handshakes, piece requests and metadata requests, unchoke budget |
| Resuming | Atomic JSON state file with the verified piece map, optional re-verification |
| Interface | Live multi-line terminal dashboard, non-TTY fallback, rate limiting in both directions |

The project has **no external dependencies** — standard library only.

## Build and run

```bash
go build -o torrent-client .

# download
./torrent-client --port 6881 ubuntu.torrent ./ubuntu.iso

# resume an interrupted download (same command; state is picked up automatically)
./torrent-client --port 6881 ubuntu.torrent ./ubuntu.iso

# magnet link, capped, verifying what is already on disk
./torrent-client --down-limit 2MiB --verify \
  'magnet:?xt=urn:btih:<40 hex or 32 base32>&tr=udp://tracker.example:6969/announce' ./out

# serve a payload you already have
./torrent-client --seed-only --port 6881 ubuntu.torrent ./ubuntu.iso

# inspect a torrent without transferring anything
./torrent-client --info ubuntu.torrent
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-port` | `6881` | TCP port for inbound peers; `0` disables the listener |
| `-no-seed` | off | Do not listen or upload |
| `-keep-seeding` | off | Keep serving after the download completes |
| `-seed-only` | off | Serve an existing payload, download nothing |
| `-no-dashboard` | off | Plain log lines instead of the live dashboard |
| `-no-resume` | off | Ignore and do not write resume state |
| `-verify` | off | Re-hash resumed pieces (and the store in `-seed-only`) |
| `-down-limit` / `-up-limit` | unlimited | `500KB`, `2MiB`, `1.5mb/s`, `0` |
| `-resume-file` | `<output>.resume` | Override the state path |
| `-peer-timeout` | `30s` | Silence tolerated from a peer |
| `-info` | off | Print metainfo and exit |

The dashboard reports download rate, peak rate, upload rate, ETA, piece progress, active workers,
connected/unchoked peers, share ratio and a throughput sparkline. When stdout is not a terminal it
degrades to one compact line every few seconds, so piping to a file stays readable.

## Defects that were present, and what they were

### 1. Info-hash generation — the client could not open a torrent at all

`bencode_info.hash()` re-encoded the parsed struct and hashed the result:

```go
if err := bencode.Marshal(&buf, i); err != nil {   // i is *bencode_info
```

Two independent faults:

* A **pointer** was passed where the encoder expects a value. Against a real `.torrent` this fails
  immediately — `could not open torrent file: bencode cannot encode value of type *main.bencode_info` —
  before a single byte reaches the network.
* Even as a value, rebuilding the dictionary is lossy. A four-field struct **drops** `files`,
  `private`, `source` and any vendor key, and **invents** `length` on a multi-file torrent, where the
  real dictionary has no such key at all. The digest cannot match, so the tracker and every peer
  reject the client.

The fix hashes `info.raw` — the exact span the scanner consumed — with no round trip:

```go
info_hash: sha1.Sum(info.raw)
```

Proven by `TestInfoHashIsSha1OfRawInfoDictionary` and
`TestInfoHashSurvivesKeysTheStructDoesNotKnow`, which asserts both that the digest matches the
original bytes and that the discarded approach cannot reproduce it.

### 2. Request framing — index/begin/length arrived byte-swapped

`format_request` wrote the request payload **little-endian**:

```go
binary.LittleEndian.PutUint32(payload[0:4], uint32(index))   // wrong
```

Every multi-byte field on the wire is big-endian, so peers read `index = 0x01000000` for `index = 1`
and answered with nonsense or dropped the connection. `TestRequestPayloadIsBigEndian` asserts the
exact 17 bytes of a request for `(index=1, begin=2, length=3)`.

Also fixed in the same layer: `has_piece` read the bitfield low-bit-first while `set_piece` wrote it
high-bit-first, so the availability map was **mirrored** — a peer holding piece 0 looked like it held
piece 7. Since a piece a peer does not have yields no data, the client spent the session asking for
things nobody had. Byte `0x01` in the first byte means piece 7, and
`TestBitfieldBitOrderMatchesTheSpec` pins that down. `read_handshake` now also validates the protocol
string and bounds the length prefix, and `read_message` rejects oversized frames.

### 3. Worker backlog — a single lost block ended the transfer

Two defects compounded into a hard stall:

```go
pp.backlog++                                  // on send
// ... no decrement anywhere on receipt
```

`backlog` gated the pipeline (`for pp.backlog < max_backlog`). Once the window filled it never
drained, so no further request could be issued; any dropped or lost block meant the piece could
never complete.

```go
if !c.bitfield.has_piece(pw.index) {
    work_ch <- pw        // back onto the same channel, forever
    continue
}
```

A worker holding a piece it could not use pushed it onto the channel it was reading from. With a
full buffer that push blocks permanently and every worker wedges; even with room, workers spin
re-offering work. The peer's piece count was also taken from `len(work_ch)` — the channel's pending
work, not the torrent's piece count — which truncated the availability map and made most pieces
look unowned.

The fix is structural rather than a patch:

* Block-level state (`missing` / `pending` / `have`) lives in the piece; `backlog` is decremented
  when a block arrives, and `reset_pending` returns in-flight blocks to the pool when a peer gives
  up, so a stalled peer cannot strand work.
* The picker only ever returns a piece the peer advertised, and returns `-1` when there is nothing
  to do. The worker idles on a read; work never travels back through a channel.
* The piece count comes from the metainfo.
* A per-piece stall is bounded by the read deadline, and the run has a watchdog that re-announces
  for fresh peers and fails with a clear message instead of hanging.

`TestPieceCompletesThroughABoundedPipeline` walks a 16-block piece through an 8-deep window and
demands completion; `TestBacklogIsNeverOverfilled`, `TestStalledPeerReleasesInFlightBlocks`,
`TestDuplicateBlocksAreCountedOnce` and `TestPickerOnlyOffersPiecesThePeerHolds` cover the rest.

Additional correctness work in the same pass: `parse_piece` bounds-checks against the piece, the
final short piece is handled, out-of-order blocks are accepted by offset, and duplicates (which
endgame mode deliberately elicits) are counted once.

## Feature extensions

### Live terminal dashboard

`progress.go` redraws a fixed block of lines in place (`\033[2K` plus a cursor-up) so speed, ETA,
worker count, peer counts, ratio and piece progress move in real time. Non-TTY output falls back to
periodic single lines. Byte counts come from a `metered_conn` wrapper that sits under the protocol
code, so no framing logic knows about reporting.

### Download resuming

`resume.go` persists the verified piece map next to the output as JSON — infohash, geometry, base64
bitfield, timestamp — written **atomically** (temp file plus rename) so a crash mid-write cannot
leave a truncated bitfield behind. Loading refuses state whose infohash or geometry does not match.
`-verify` re-hashes resumed pieces and demotes anything that fails, and blocks land in the final
output as they arrive, so a resumed download does not have to be reassembled at the end. Ctrl-C
routes through `shutdown()`, which flushes and saves before exiting:

```
12:51:23 interrupted with 5 piece(s) outstanding; progress saved
12:51:24 resume: 7 pieces already verified, 1310720 bytes remaining
```

### Seeding / upload handler

`seed.go` opens a TCP listener, validates inbound handshakes against our infohash, sends our
bitfield, answers `interested` with an unchoke (bounded by an upload-slot budget), serves `request`
messages out of the store by reading the block at its absolute offset, and chokes a peer that asks
for something we no longer hold. Peers that dial us receive `have` broadcasts as pieces complete,
so a client can seed while it is still downloading. `-seed-only` verifies the payload on disk and
then serves it.

### Magnet resolution (BEP 0009 over BEP 0010)

`magnet.go` parses `xt` in hex or base32, `dn`, `tr`, `xl` and `x.pe`, then introduces itself to
peers with the extension bit set, reads `metadata_size` from their extension handshake, requests
the info dictionary in 16 KiB blocks and **verifies SHA-1 against the requested btih** before using
it. Without that check a peer could hand over a perfectly parseable torrent for the wrong swarm;
`TestMagnetRejectsMetadataForAnotherTorrent` runs a deliberately hostile peer that answers the right
infohash and then serves a different dictionary.

### UDP trackers (BEP 0015)

Connect and announce over UDP with the 64-bit connection id, random transaction ids, error-action
handling and the prescribed exponential retransmit backoff.

### Multi-file torrents

`files` lists are parsed with path validation (no `..`, no separators, no absolute paths — a hostile
torrent must not escape the output directory), offsets are computed once, and the store routes
blocks across file boundaries in both directions, so a piece straddling two files reads and writes
correctly.

### Bandwidth rate limiting

A token bucket per direction, applied by wrapping the connection: bytes are reserved before the
read or write is issued, and a cancelled context aborts a wait.

## Architecture

```
main.go        CLI, flags, signal handling, source loading
torrent.go     metainfo: byte-exact info hash, files, piece geometry, peer ids
bencode.go     decoder that preserves the exact byte span of every value, plus an encoder
wire.go        handshake, message framing, bitfield, extension messages
client.go      one peer connection: dial, handshake, priming, choke state, metering, pacing
tracker.go     HTTP and UDP announce, peer parsing, percent encoding
p2p.go         download engine: picker, workers, block bookkeeping, endgame, watchdog
seed.go        inbound peers: handshake validation, unchoke policy, piece and metadata serving
store.go       offsets to files: single- and multi-file reads and writes
resume.go      state serialisation, verification
magnet.go      magnet parsing and metadata exchange
progress.go    terminal dashboard
ratelimit.go   token bucket and throttled connection
```

### Percent encoding

Trackers get strict `%XX` escaping (`escape_bytes`), not `url.Values.Encode`. Go encodes a space as
`+`, but an infohash is raw binary that can legitimately contain `0x20`; a tracker that decodes `+`
as a space would hash different bytes and answer `invalid infohash`. The infohash is also reported
as `left` in the announce, so a resumed transfer advertises the correct remaining byte count.

### On the bencode dependency

The original code used `github.com/jackpal/bencode-go`, and the metainfo path cannot work with a
struct-targeted decode: re-encoding a struct cannot reproduce the original dictionary. The tracker
response has the same problem in a different shape — `peers` is a union of a compact byte string, a
list of dictionaries, and a dictionary keyed by peer id, and a mismatched struct field is silently
left empty rather than reported, so dictionary-model peers were dropped without any error. Both
paths therefore use the byte-exact scanner in `bencode.go`, and the dependency was removed. The
build is now dependency-free.

## Tests

```bash
go test ./...            # 8s
go test -race ./...      # race-clean
```

The suite is in three layers:

* `protocol_test.go` — bencode spans, info-hash fidelity and failure modes, bit order, request
  framing byte-for-byte, message round trips, handshake validation, extension tails, magnet parsing,
  path traversal, piece geometry.
* `flow_test.go` — pipeline backlog behaviour including the lost-block case, picker policy and
  endgame, resume round trip and rejection of corrupt or foreign state, verification repair, rate
  limiter pacing.
* `tracker_test.go` / `e2e_test.go` — percent escaping on the wire, compact/dictionary/`failure
  reason` responses, a scripted UDP tracker, and full transfers against a real seeder and a real
  tracker over loopback: single-file, multi-file straddling a file boundary, resume skipping
  verified pieces, verification repairing a damaged piece, magnet resolution then download, hostile
  metadata, a peer that only holds part of the payload, and a hand-written peer pulling a block from
  our seeder.

## Scope and limits

* IPv4 only (`peer` holds a 4-byte address); `peers6` is accepted and ignored.
* No DHT, PEX or local peer discovery, so a magnet link needs a tracker or `x.pe` entry.
* Choking is a simple upload-slot budget rather than full tit-for-tat with optimistic unchoking.
* `ut_metadata` is served and requested; other extension names are recorded but unused.
