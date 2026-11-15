package reach

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A log SEGMENT is one run of lines Caddy wrote to a single file before rolling it. Caddy (lumberjack) renames
// access.log to access-<timestamp>.log when it reaches roll_size and, by default, then gzips it to
// access-<timestamp>.log.gz and removes the original. Neither the name nor the inode survives that, but the
// CONTENT does: a segment's first line carries a sub-microsecond timestamp, so a hash of that timestamp's
// TEXT is a stable identity for the segment through the rename and the compression, and a byte offset into the
// DECOMPRESSED stream means the same thing before and after. That is what the cursor is keyed on.
//
// PRIVACY: the id is derived from the first line's raw "ts" field text ONLY. It is never derived from any
// other part of the line (the remote IP, the User-Agent, the URI and the line's length all depend on a
// client), so file_id carries no personal data; it is a hash of a server timestamp.

const idPrefixBytes = 4096

// Hard bounds on the work one pass may do (docs/68 section 12, "Codex round 1"). Caddy rolls at 20 MiB, so a
// real segment is far below both; they exist so a bomb dropped into the shared volume (a gzip that inflates
// to terabytes) costs a bounded amount of CPU and I/O per pass and is then given up on.
const (
	// DefaultMaxSegmentBytes caps the DECOMPRESSED bytes read from one segment (skipping an already-counted
	// prefix included).
	DefaultMaxSegmentBytes int64 = 512 << 20
	// DefaultMaxPassBytes caps the decompressed bytes read across all segments in one pass.
	DefaultMaxPassBytes int64 = 2 << 30
)

var (
	errSegmentCap = errors.New("reach: segment exceeded the decompressed-byte cap")
	errPassBudget = errors.New("reach: pass byte budget exhausted")
	errRawCap     = errors.New("reach: compressed-byte cap exceeded")
)

// discoveryRawCap bounds the COMPRESSED bytes discovery may read from one file to learn its id (header and the
// first block). A real gzip needs a few KiB; a hostile one that wants more is not a segment.
const discoveryRawCap int64 = 1 << 20

// rawReader sits between the file and gzip.NewReader. Every compressed byte is charged to left (so the gzip
// header, whatever it holds, is bounded by the cap and not only by the library) and the context is checked on
// every read, so cancellation is honoured even while the header is being parsed.
type rawReader struct {
	r    io.Reader
	ctx  context.Context
	left int64
}

func (c *rawReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if c.left <= 0 {
		return 0, errRawCap
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// Segment is one readable log file.
type Segment struct {
	Path   string
	Name   string
	ID     string
	First  time.Time // timestamp of its first line (zero when that line does not parse); the read order
	Gz     bool
	Active bool // the file Caddy is still appending to
}

// ListSegments returns the readable segments of the log in dir, oldest first, the active file last. Files whose
// first line is not complete yet are left for the next run. When one segment exists twice (the .log and its
// .log.gz while the compressor runs) the uncompressed copy wins. Symlinks and anything not matching Caddy's
// roll naming are ignored: the directory is a shared volume and its contents are data.
func ListSegments(ctx context.Context, dir, base string) ([]Segment, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	stem := strings.TrimSuffix(base, ".log")
	byID := map[string]Segment{}
	for _, e := range ents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := e.Name()
		active := name == base
		rolled := strings.HasPrefix(name, stem+"-") && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz"))
		if !active && !rolled {
			continue
		}
		if !e.Type().IsRegular() { // not a symlink, directory or device
			continue
		}
		seg := Segment{Path: filepath.Join(dir, name), Name: name, Gz: strings.HasSuffix(name, ".gz"), Active: active}
		id, first, ok := identify(ctx, seg)
		if !ok {
			continue
		}
		seg.ID, seg.First = id, first
		if old, dup := byID[id]; dup && !old.Gz && seg.Gz {
			continue
		}
		byID[id] = seg
	}
	out := make([]Segment, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Active != b.Active {
			return b.Active
		}
		if !a.First.Equal(b.First) {
			return a.First.Before(b.First)
		}
		return a.Name < b.Name
	})
	if err := ctx.Err(); err != nil {
		return nil, err // a cancel during the last identify dropped that entry: never return a short list as whole
	}
	return out, nil
}

// limits bounds the decompressed bytes one opened segment may deliver, and carries the cancellation context so
// a read (including skipping an already-counted prefix) stops promptly instead of only between batches.
type limits struct {
	ctx      context.Context
	segLeft  int64
	passLeft *int64 // budget for NEW bytes (what is counted this pass)
	skipLeft *int64 // budget for bytes of an already-counted prefix that must be re-read (a gzip cannot seek), and the 64 KiB prefetch
	skipping bool
}

type countingReader struct {
	r io.Reader
	l *limits
}

func (c *countingReader) Read(p []byte) (int, error) {
	if err := c.l.ctx.Err(); err != nil {
		return 0, err
	}
	if c.l.segLeft <= 0 {
		return 0, errSegmentCap
	}
	budget := c.l.passLeft
	if c.l.skipping {
		budget = c.l.skipLeft
	}
	if *budget <= 0 {
		return 0, errPassBudget
	}
	if int64(len(p)) > c.l.segLeft {
		p = p[:c.l.segLeft]
	}
	if int64(len(p)) > *budget {
		p = p[:*budget]
	}
	n, err := c.r.Read(p)
	c.l.segLeft -= int64(n)
	*budget -= int64(n)
	return n, err
}

// openedSegment is a segment opened ONCE. Its identity is computed from the very handle that is then
// consumed, so a roll between discovery and reading can never pair one file's content with another's cursor.
type openedSegment struct {
	br      *bufio.Reader
	src     io.Reader // what br reads from (the file itself for an uncompressed segment, so it can be re-seated after a Seek)
	f       *os.File
	zr      *gzip.Reader
	ID      string
	First   time.Time
	Ready   bool // the first line is complete and carries a usable timestamp
	limited *limits
}

func (o *openedSegment) Close() error {
	if o.zr != nil {
		o.zr.Close()
	}
	return o.f.Close()
}

// openIdentified opens the segment's byte stream (decompressed for a .gz), peeks at its first line WITHOUT
// consuming it, and derives the id from that. lim may be nil (discovery needs no budget).
func (s Segment) openIdentified(ctx context.Context, lim *limits) (*openedSegment, error) {
	if err := ctx.Err(); err != nil { // before any file or gzip work
		return nil, err
	}
	rawCap := discoveryRawCap
	if lim != nil {
		lim.skipping = true // the identity peek (and the 64 KiB it prefetches) is charged to the skip budget
		rawCap = lim.segLeft
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	o := &openedSegment{f: f, limited: lim}
	var src io.Reader = f
	if s.Gz {
		// The file is wrapped BEFORE gzip.NewReader: header bytes are charged and a cancelled ctx stops the parse.
		zr, err := gzip.NewReader(&rawReader{r: f, ctx: ctx, left: rawCap})
		if err != nil {
			f.Close()
			return nil, err
		}
		o.zr = zr
		src = zr
	}
	if lim != nil {
		src = &countingReader{r: src, l: lim}
	}
	o.src = src
	o.br = bufio.NewReaderSize(src, 64<<10)
	prefix, perr := o.br.Peek(idPrefixBytes)
	if perr != nil && !errors.Is(perr, io.EOF) { // a budget stop, a cancellation or a corrupt stream
		o.Close()
		return nil, perr
	}
	o.ID, o.First, o.Ready = segmentID(prefix)
	return o, nil
}

// segmentID derives the segment's identity from the first line's raw "ts" text. ok is false when the file has
// no complete first line yet, or that line carries no usable timestamp.
func segmentID(prefix []byte) (id string, first time.Time, ok bool) {
	line := prefix
	if i := indexByte(prefix, '\n'); i >= 0 {
		line = prefix[:i+1]
	} else if len(prefix) < idPrefixBytes {
		return "", time.Time{}, false // the first line is still being written
	}
	ts, ok := rawTS(line)
	if !ok {
		return "", time.Time{}, false
	}
	sum := sha256.Sum256([]byte("deskrally-reach-segment-v2\x00" + ts))
	if e, perr := ParseLine(trimNL(line)); perr == nil {
		first = e.TS
	}
	return hex.EncodeToString(sum[:16]), first, true
}

// rawTS returns the text of the top-level "ts" number in a (possibly truncated) JSON object line, walking the
// keys in order so nothing after it needs to be well formed.
func rawTS(line []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	for dec.More() {
		kt, err := dec.Token()
		key, isStr := kt.(string)
		if err != nil || !isStr {
			return "", false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", false
		}
		if key != "ts" {
			continue
		}
		s := string(raw)
		if len(s) == 0 || len(s) > 32 || strings.Trim(s, "0123456789.eE+-") != "" {
			return "", false
		}
		return s, true
	}
	return "", false
}

// identify opens a segment only to learn its id (discovery).
func identify(ctx context.Context, s Segment) (id string, first time.Time, ok bool) {
	o, err := s.openIdentified(ctx, nil)
	if err != nil {
		return "", time.Time{}, false
	}
	defer o.Close()
	return o.ID, o.First, o.Ready
}

// seekTo positions an UNCOMPRESSED segment at offset without reading the counted prefix (a gzip cannot seek). An
// offset past the file's end is clamped to it. It returns the offset used.
func (o *openedSegment) seekTo(offset int64) (int64, error) {
	fi, err := o.f.Stat()
	if err != nil {
		return 0, err
	}
	if offset > fi.Size() {
		offset = fi.Size()
	}
	if _, err := o.f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	o.br.Reset(o.src) // drop the prefetched start of the file
	return offset, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// eofOrErr keeps io.EOF as the one quiet end of a segment and passes every other read error (a corrupt or truncated
// .log.gz, an I/O fault) through, so the caller can say so instead of silently stalling the cursor.
func eofOrErr(err error) error {
	if errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

// lineReader yields complete lines and counts the bytes each one consumed (newline included). A line with no
// newline yet is NOT returned and not counted: it is the writer's partial last line, read again next run.
type lineReader struct {
	br       *bufio.Reader
	Consumed int64 // bytes of complete lines returned so far, plus the skip offset the caller seeded
}

func newLineReader(r io.Reader, seed int64) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 64<<10), Consumed: seed}
}

// Next returns the next complete line (valid until the next call) and whether it exceeded the buffer, in which
// case line is nil and the whole over-long line has been discarded. It returns io.EOF at the end of the
// complete lines, and any other read error as it is.
func (l *lineReader) Next() (line []byte, oversize bool, err error) {
	b, err := l.br.ReadSlice('\n')
	switch {
	case err == nil:
		l.Consumed += int64(len(b))
		return trimNL(b), false, nil
	case errors.Is(err, bufio.ErrBufferFull):
		n := int64(len(b))
		for {
			rest, rerr := l.br.ReadSlice('\n')
			n += int64(len(rest))
			if rerr == nil {
				l.Consumed += n
				return nil, true, nil
			}
			if !errors.Is(rerr, bufio.ErrBufferFull) {
				return nil, false, eofOrErr(rerr) // io.EOF: the over-long line has no newline yet
			}
		}
	default:
		return nil, false, eofOrErr(err) // io.EOF (with a partial tail) ends the segment quietly; any other error is a real fault
	}
}
