package controlplane

// IVF -> WebM stream-copy muxer for central recording playback (docs/63 D7, §2a C7).
//
// The agent records VP8 into IVF segments; browsers cannot play IVF. The server therefore remuxes each
// IVF segment into a WebM file (no transcode, the VP8 payload bytes are copied verbatim) with a Go-native
// muxer — deliberately NOT ffmpeg, because the input is untrusted guest data and a native parser with
// hard, server-owned bounds is the smaller attack surface.
//
// THE INPUT IS UNTRUSTED. Even though the bytes arrive through an authenticated, digest-checked upload,
// the agent (or whoever holds its key) chose them. So the muxer is a two-pass design in which nothing the
// file says is believed before it has been checked against limits the SERVER owns:
//
//	pass 1  ScanIVF    stream the plaintext once, validate every header and the VP8 key-frame tags, and
//	                   build an index (size, timestamp, key flag per frame — 24 bytes per frame, at most
//	                   MuxLimits.MaxFrames of them). Nothing but the index is kept: memory is bounded by
//	                   the limits, not by the file.
//	plan    PlanWebM   pure arithmetic over the index: clusters, cues, every element size and position,
//	                   the exact output length. The output bound (<= 1.2 x input + a small constant) is
//	                   enforced HERE, before a single output byte exists, so an amplification input is
//	                   refused without doing the work.
//	pass 2  Write      stream the plaintext again and emit exactly the planned bytes. The frame headers are
//	                   re-checked against the index (the second read must see what the first saw) and the
//	                   output length must equal the plan to the byte.
//
// The envelope that stores the WebM copy records its total plaintext length in an authenticated header
// up front, which is why the exact output size must be known before the first byte is written — hence the
// plan. All integers are fixed-width in the output so every element size is independent of its value.
//
// Limits (C7, all enforced with checked arithmetic): frames <= 500k per segment, frame <= 4 MiB,
// dimensions <= 8192 x 8192, timestamps non-decreasing and inside the recording's window, input consumed
// EXACTLY (a truncated frame or trailing bytes is an error), output <= 1.2 x input (+4 KiB constant).
//
// What is validated about the VP8 itself is only what is needed to refuse garbage cheaply: the first
// frame must be a key frame, and every key frame carries the start code and the file header's dimensions.
// The muxer does not decode.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
)

// MuxLimits are the server-owned bounds. The zero value is NOT usable; start from DefaultMuxLimits.
type MuxLimits struct {
	MaxFrames     int   // per segment
	MaxFrameBytes int   // per frame
	MaxDimension  int   // width and height
	MaxSpanMs     int64 // the recording's window: no timestamp may exceed this many ms from the epoch
	MaxInputBytes int64
}

// DefaultMuxLimits are the production bounds (C7).
func DefaultMuxLimits() MuxLimits {
	return MuxLimits{
		MaxFrames:     500_000,
		MaxFrameBytes: 4 << 20,
		MaxDimension:  8192,
		MaxSpanMs:     48 * 3600 * 1000,
		MaxInputBytes: RecHardMaxBytes,
	}
}

const (
	muxOutNum   = 12 // output <= input x 1.2 ...
	muxOutDen   = 10
	muxOutSlack = 4096 // ... plus a constant for the container header of a tiny file

	ivfFileHeader  = 32
	ivfFrameHeader = 12

	muxClusterMaxSpanMs  = 30000   // a SimpleBlock's relative timecode is an int16; stay well inside it
	muxClusterSoftSpanMs = 2000    // start a new cluster at the next key frame after this much time
	muxClusterMaxBytes   = 8 << 20 // and never grow one past this (its size field is a 4-byte vint)

	muxBlockOverhead = 1 + 4 + 4 // SimpleBlock id + 4-byte size + (track vint, int16 timecode, flags)
	muxClusterHeader = 4 + 4     // Cluster id + 4-byte size; the cluster Timecode element (6 bytes) is in its body
	muxClusterTCLen  = 6
	muxSegHeaderLen  = 4 + 8 // Segment id + 8-byte size
)

// Mux error codes: a CLOSED set, safe to store and to show (they never carry file contents or paths).
const (
	MuxInvalid      = "invalid_ivf"      // malformed or unsupported container / bitstream
	MuxLimit        = "limit_exceeded"   // a server-owned bound was exceeded
	MuxTimeBudget   = "time_budget"      // the job ran out of time
	MuxIO           = "io_error"         // reading the evidence or writing the playback copy failed
	MuxInconsistent = "inconsistent_ivf" // the second pass saw something different from the first
)

// MuxError is a classified muxer failure.
type MuxError struct {
	Code string
	Msg  string
	Err  error
}

func (e *MuxError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("webm mux: %s: %s: %v", e.Code, e.Msg, e.Err)
	}
	return fmt.Sprintf("webm mux: %s: %s", e.Code, e.Msg)
}

func (e *MuxError) Unwrap() error { return e.Err }

func muxErr(code, format string, a ...any) *MuxError {
	return &MuxError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// ---- pass 1: scan -----------------------------------------------------------------------------

type ivfFrame struct {
	size uint32
	pts  uint64 // in timebase ticks
	key  bool
}

// IVFInfo is the validated shape of one IVF segment.
type IVFInfo struct {
	Width, Height int
	Rate, Scale   uint32 // timebase = Scale/Rate seconds per tick
	TotalBytes    int64  // the input length, consumed exactly
	frames        []ivfFrame
	firstPTS      uint64
	lastPTS       uint64
	headerFrames  uint32
}

// Frames returns the number of frames.
func (i *IVFInfo) Frames() int { return len(i.frames) }

// FirstMs and LastMs are the absolute (from the recording epoch) times of the first and last frame.
func (i *IVFInfo) FirstMs() int64 { v, _ := ticksToMs(i.firstPTS, i.Rate, i.Scale); return v }
func (i *IVFInfo) LastMs() int64  { v, _ := ticksToMs(i.lastPTS, i.Rate, i.Scale); return v }

// ticksToMs converts timebase ticks to whole milliseconds, rounding down, with a 128-bit intermediate so
// nothing can overflow. ok is false when the result does not fit.
func ticksToMs(t uint64, rate, scale uint32) (int64, bool) {
	if rate == 0 {
		return 0, false
	}
	hi, lo := bits.Mul64(t, uint64(scale)*1000) // scale < 2^32, so scale*1000 < 2^42: no overflow
	if hi >= uint64(rate) {
		return 0, false // the quotient would not fit in 64 bits
	}
	q, _ := bits.Div64(hi, lo, uint64(rate))
	if q > math.MaxInt64 {
		return 0, false
	}
	return int64(q), true
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ScanIVF validates one IVF segment of exactly `declared` bytes read from r and returns its index.
// It never allocates in proportion to the input: only the (bounded) frame index.
func ScanIVF(ctx context.Context, r io.Reader, declared int64, lim MuxLimits) (*IVFInfo, error) {
	if declared > lim.MaxInputBytes {
		return nil, muxErr(MuxLimit, "input of %d bytes exceeds the %d byte bound", declared, lim.MaxInputBytes)
	}
	if declared < ivfFileHeader+ivfFrameHeader+3 {
		return nil, muxErr(MuxInvalid, "input of %d bytes cannot hold a frame", declared)
	}
	br := bufio.NewReaderSize(ctxReader{ctx, io.LimitReader(r, declared)}, 64<<10)
	var consumed int64

	var hdr [ivfFileHeader]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, ioOrInvalid(ctx, err, "file header")
	}
	consumed += ivfFileHeader
	info, err := parseIVFHeader(hdr[:], lim.MaxDimension)
	if err != nil {
		return nil, err
	}
	info.TotalBytes = declared

	var fh [ivfFrameHeader]byte
	var head [10]byte
	var lastPTS uint64
	for consumed < declared {
		if err := ctx.Err(); err != nil { // checked per frame: buffered data must not outrun a cancellation
			return nil, err
		}
		if declared-consumed < ivfFrameHeader {
			return nil, muxErr(MuxInvalid, "%d trailing bytes after the last frame", declared-consumed)
		}
		if _, err := io.ReadFull(br, fh[:]); err != nil {
			return nil, ioOrInvalid(ctx, err, "frame header")
		}
		consumed += ivfFrameHeader
		size := binary.LittleEndian.Uint32(fh[0:4])
		pts := binary.LittleEndian.Uint64(fh[4:12])
		if size < 3 {
			return nil, muxErr(MuxInvalid, "frame %d is %d bytes: too small to be a VP8 frame", len(info.frames), size)
		}
		if int64(size) > int64(lim.MaxFrameBytes) {
			return nil, muxErr(MuxLimit, "frame %d is %d bytes (bound %d)", len(info.frames), size, lim.MaxFrameBytes)
		}
		if int64(size) > declared-consumed {
			return nil, muxErr(MuxInvalid, "frame %d claims %d bytes but only %d remain", len(info.frames), size, declared-consumed)
		}
		if len(info.frames) >= lim.MaxFrames {
			return nil, muxErr(MuxLimit, "more than %d frames", lim.MaxFrames)
		}
		if len(info.frames) > 0 && pts < lastPTS {
			return nil, muxErr(MuxInvalid, "frame %d goes back in time", len(info.frames))
		}
		ms, ok := ticksToMs(pts, info.Rate, info.Scale)
		if !ok || ms > lim.MaxSpanMs {
			return nil, muxErr(MuxLimit, "frame %d is outside the recording window", len(info.frames))
		}
		n := int(size)
		if n > len(head) {
			n = len(head)
		}
		if _, err := io.ReadFull(br, head[:n]); err != nil {
			return nil, ioOrInvalid(ctx, err, "frame")
		}
		key, err := checkVP8Frame(head[:n], int(size), info, len(info.frames))
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, br, int64(size)-int64(n)); err != nil {
			return nil, ioOrInvalid(ctx, err, "frame")
		}
		consumed += int64(size)
		if len(info.frames) == 0 {
			info.firstPTS = pts
		}
		info.lastPTS, lastPTS = pts, pts
		info.frames = append(info.frames, ivfFrame{size: size, pts: pts, key: key})
	}
	if len(info.frames) == 0 {
		return nil, muxErr(MuxInvalid, "no frames")
	}
	// EXACT consumption: the declared length was read in full, and the source has nothing more.
	if consumed != declared {
		return nil, muxErr(MuxInvalid, "consumed %d of %d bytes", consumed, declared)
	}
	if err := requireEOF(ctx, r, "end of the source", muxErr(MuxInvalid, "the source holds more than the declared %d bytes", declared)); err != nil {
		return nil, err
	}
	if !info.frames[0].key {
		return nil, muxErr(MuxInvalid, "the first frame is not a key frame")
	}
	if n := uint32(len(info.frames)); info.headerFrames != 0 && info.headerFrames != n {
		return nil, muxErr(MuxInvalid, "the header declares %d frames, the file holds %d", info.headerFrames, n)
	}
	return info, nil
}

// requireEOF demands that the source is at its end: exactly zero bytes AND io.EOF. A byte means the source is
// longer than expected (more); any other error — an authentication failure of the NEXT envelope frame, an
// I/O error, a cancellation — is propagated, never read as "no more data". The probe is what proves the
// final authenticated frame was the last one.
func requireEOF(ctx context.Context, r io.Reader, what string, more error) error {
	var extra [1]byte
	for tries := 0; tries < 8; tries++ {
		n, err := r.Read(extra[:])
		if n > 0 {
			return more
		}
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return ioOrInvalid(ctx, err, what)
		}
	}
	return &MuxError{Code: MuxIO, Msg: "reading the " + what, Err: io.ErrNoProgress}
}

func ioOrInvalid(ctx context.Context, err error, what string) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr // cancelled or out of time: the caller classifies
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return muxErr(MuxInvalid, "truncated in the %s", what)
	}
	return &MuxError{Code: MuxIO, Msg: "reading the " + what, Err: err}
}

func parseIVFHeader(h []byte, maxDim int) (*IVFInfo, error) {
	if string(h[0:4]) != "DKIF" {
		return nil, muxErr(MuxInvalid, "not an IVF file")
	}
	if binary.LittleEndian.Uint16(h[4:6]) != 0 {
		return nil, muxErr(MuxInvalid, "unsupported IVF version")
	}
	if binary.LittleEndian.Uint16(h[6:8]) != ivfFileHeader {
		return nil, muxErr(MuxInvalid, "unexpected IVF header length")
	}
	if string(h[8:12]) != "VP80" {
		return nil, muxErr(MuxInvalid, "unsupported codec (only VP8 is stored)")
	}
	w := int(binary.LittleEndian.Uint16(h[12:14]))
	ht := int(binary.LittleEndian.Uint16(h[14:16]))
	if w < 1 || ht < 1 || w > maxDim || ht > maxDim {
		return nil, muxErr(MuxLimit, "dimensions %dx%d are outside 1..%d", w, ht, maxDim)
	}
	rate := binary.LittleEndian.Uint32(h[16:20])
	scale := binary.LittleEndian.Uint32(h[20:24])
	if rate == 0 || scale == 0 {
		return nil, muxErr(MuxInvalid, "zero timebase")
	}
	return &IVFInfo{Width: w, Height: ht, Rate: rate, Scale: scale,
		headerFrames: binary.LittleEndian.Uint32(h[24:28])}, nil
}

// checkVP8Frame validates the part of a frame the muxer relies on and reports whether it is a key frame.
// head holds the first min(size, 10) bytes. A VP8 frame tag is 3 bytes, bit 0 clear = key frame; a key
// frame continues with the start code 9d 01 2a and 14-bit width and height (top 2 bits are scaling).
func checkVP8Frame(head []byte, size int, info *IVFInfo, idx int) (bool, error) {
	if len(head) < 3 { // defence in depth: the caller refuses frames under 3 bytes first, but never index blindly
		return false, muxErr(MuxInvalid, "frame %d is too short for a VP8 frame tag", idx)
	}
	key := head[0]&1 == 0
	if !key {
		return false, nil
	}
	if size < 10 || len(head) < 10 {
		return false, muxErr(MuxInvalid, "key frame %d is too short", idx)
	}
	if head[3] != 0x9d || head[4] != 0x01 || head[5] != 0x2a {
		return false, muxErr(MuxInvalid, "key frame %d has no VP8 start code", idx)
	}
	w := int(binary.LittleEndian.Uint16(head[6:8]) & 0x3fff)
	h := int(binary.LittleEndian.Uint16(head[8:10]) & 0x3fff)
	if w != info.Width || h != info.Height {
		return false, muxErr(MuxInvalid, "key frame %d is %dx%d but the file says %dx%d", idx, w, h, info.Width, info.Height)
	}
	return true, nil
}

// ---- EBML building blocks (fixed-width, so sizes never depend on values) ----------------------

const ebmlMasterSizeBytes = 4 // every master element's size field is a 4-byte vint (max 2^28-2)

func ebmlID(b []byte, id uint32) []byte {
	switch {
	case id > 0xffffff:
		return append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	case id > 0xffff:
		return append(b, byte(id>>16), byte(id>>8), byte(id))
	case id > 0xff:
		return append(b, byte(id>>8), byte(id))
	}
	return append(b, byte(id))
}

// ebmlSize appends v as a width-byte vint. v must be < 2^(7*width) - 1 (all-ones means "unknown").
// The planner bounds every size it passes, so the panic is a bug guard, not an input path.
func ebmlSize(b []byte, v uint64, width int) []byte {
	if width < 1 || width > 8 || v >= (uint64(1)<<(7*uint(width)))-1 {
		panic("ebml: size out of range for its width")
	}
	v |= uint64(1) << (7 * uint(width))
	for i := width - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*uint(i))))
	}
	return b
}

func ebmlUint(b []byte, id uint32, v uint64, width int) []byte {
	b = ebmlID(b, id)
	b = ebmlSize(b, uint64(width), 1)
	for i := width - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*uint(i))))
	}
	return b
}

func ebmlString(b []byte, id uint32, s string) []byte {
	b = ebmlID(b, id)
	b = ebmlSize(b, uint64(len(s)), 1)
	return append(b, s...)
}

func ebmlFloat64(b []byte, id uint32, f float64) []byte {
	b = ebmlID(b, id)
	b = ebmlSize(b, 8, 1)
	return binary.BigEndian.AppendUint64(b, math.Float64bits(f))
}

func ebmlMaster(b []byte, id uint32, body []byte) []byte {
	b = ebmlID(b, id)
	b = ebmlSize(b, uint64(len(body)), ebmlMasterSizeBytes)
	return append(b, body...)
}

// Element ids (Matroska / WebM).
const (
	idEBML            = 0x1A45DFA3
	idEBMLVersion     = 0x4286
	idEBMLReadVersion = 0x42F7
	idEBMLMaxIDLen    = 0x42F2
	idEBMLMaxSizeLen  = 0x42F3
	idDocType         = 0x4282
	idDocTypeVersion  = 0x4287
	idDocTypeReadVer  = 0x4285
	idSegment         = 0x18538067
	idSeekHead        = 0x114D9B74
	idSeek            = 0x4DBB
	idSeekID          = 0x53AB
	idSeekPosition    = 0x53AC
	idInfo            = 0x1549A966
	idTimecodeScale   = 0x2AD7B1
	idDuration        = 0x4489
	idMuxingApp       = 0x4D80
	idWritingApp      = 0x5741
	idTracks          = 0x1654AE6B
	idTrackEntry      = 0xAE
	idTrackNumber     = 0xD7
	idTrackUID        = 0x73C5
	idTrackType       = 0x83
	idFlagLacing      = 0x9C
	idCodecID         = 0x86
	idVideo           = 0xE0
	idPixelWidth      = 0xB0
	idPixelHeight     = 0xBA
	idCues            = 0x1C53BB6B
	idCuePoint        = 0xBB
	idCueTime         = 0xB3
	idCueTrackPos     = 0xB7
	idCueTrack        = 0xF7
	idCueClusterPos   = 0xF1
	idCluster         = 0x1F43B675
	idClusterTimecode = 0xE7
	idSimpleBlock     = 0xA3
)

// ---- plan -------------------------------------------------------------------------------------

type muxCluster struct {
	first, end int   // frame range [first, end)
	tcMs       int64 // cluster timecode (ms from the segment's first frame)
	body       int64 // cluster payload size (everything after its size field)
	offset     int64 // absolute position of the cluster element in the output
	cue        bool  // starts with a key frame: gets a cue point
}

// WebMPlan is the exact layout of the output for one IVF segment.
type WebMPlan struct {
	info       *IVFInfo
	clusters   []muxCluster
	seekPos    [3]uint64 // Segment-relative positions of Info, Tracks, Cues (SeekHead)
	preamble   int64     // bytes before the first cluster (EBML header .. Cues)
	segContent int64     // Segment element content size
	size       int64     // total output size
	durationMs int64
	startMs    int64 // absolute time (ms) of the first frame
}

// Size is the exact number of bytes Write will produce.
func (p *WebMPlan) Size() int64 { return p.size }

// DurationMs is the segment's playable duration (first frame to the end of the last one).
func (p *WebMPlan) DurationMs() int64 { return p.durationMs }

// StartMs is the absolute (from the recording epoch) time of the segment's first frame.
func (p *WebMPlan) StartMs() int64 { return p.startMs }

func (p *WebMPlan) relMs(ticks uint64) int64 {
	// Shift in ticks first so the first frame is exactly 0, then convert; the scan proved it fits.
	ms, _ := ticksToMs(ticks-p.info.firstPTS, p.info.Rate, p.info.Scale)
	return ms
}

// PlanWebM lays out the output for a scanned segment and enforces the amplification bound.
func PlanWebM(info *IVFInfo) (*WebMPlan, error) {
	p := &WebMPlan{info: info, startMs: info.FirstMs()}

	var cur *muxCluster
	var lastRel int64
	flush := func() {
		if cur != nil {
			p.clusters = append(p.clusters, *cur)
			cur = nil
		}
	}
	for i, f := range info.frames {
		rel := p.relMs(f.pts)
		lastRel = rel
		blk := int64(muxBlockOverhead) + int64(f.size)
		start := cur == nil ||
			rel-cur.tcMs > muxClusterMaxSpanMs ||
			cur.body+blk > muxClusterMaxBytes ||
			(f.key && rel-cur.tcMs >= muxClusterSoftSpanMs)
		if start {
			flush()
			cur = &muxCluster{first: i, tcMs: rel, body: muxClusterTCLen, cue: f.key}
		}
		cur.body += blk
		cur.end = i + 1
	}
	flush()
	if len(p.clusters) == 0 || !p.clusters[0].cue {
		return nil, muxErr(MuxInvalid, "no key frame to start the first cluster")
	}

	// Duration: the last frame's timestamp plus one typical frame interval (the format carries none).
	tail := int64(33)
	if n := len(info.frames); n >= 2 {
		if d := lastRel - p.relMs(info.frames[n-2].pts); d >= 1 && d <= 1000 {
			tail = d
		}
	}
	p.durationMs = lastRel + tail

	// The preamble's size does not depend on any position inside it (every field is fixed-width), so
	// build it once with zero positions to learn the lengths, then lay everything else out after it.
	parts := p.buildParts()
	p.seekPos = [3]uint64{uint64(len(parts.seekHead)), uint64(len(parts.seekHead) + len(parts.info)),
		uint64(len(parts.seekHead) + len(parts.info) + len(parts.tracks))}
	p.preamble = int64(len(parts.ebml)) + muxSegHeaderLen + int64(len(parts.seekHead)+len(parts.info)+len(parts.tracks)+len(parts.cues))
	off := p.preamble
	for i := range p.clusters {
		c := &p.clusters[i]
		c.offset = off
		off += muxClusterHeader + c.body
	}
	p.size = off
	p.segContent = p.size - int64(len(parts.ebml)) - muxSegHeaderLen

	// The cue and seek positions are 4-byte fields; nothing the input bounds allow can reach 4 GiB (the
	// output bound below is ~1.3 GiB), but state it as a check rather than an assumption.
	if p.size >= 1<<32 {
		return nil, muxErr(MuxLimit, "output of %d bytes is too large", p.size)
	}
	if p.size > info.TotalBytes*muxOutNum/muxOutDen+muxOutSlack {
		return nil, muxErr(MuxLimit, "output of %d bytes exceeds 1.2 x the %d byte input", p.size, info.TotalBytes)
	}
	return p, nil
}

type webmParts struct{ ebml, seekHead, info, tracks, cues []byte }

func (p *WebMPlan) buildParts() webmParts {
	var eb []byte
	eb = ebmlUint(eb, idEBMLVersion, 1, 1)
	eb = ebmlUint(eb, idEBMLReadVersion, 1, 1)
	eb = ebmlUint(eb, idEBMLMaxIDLen, 4, 1)
	eb = ebmlUint(eb, idEBMLMaxSizeLen, 8, 1)
	eb = ebmlString(eb, idDocType, "webm")
	eb = ebmlUint(eb, idDocTypeVersion, 4, 1)
	eb = ebmlUint(eb, idDocTypeReadVer, 2, 1)

	seekEntry := func(id uint32, at uint64) []byte {
		idb := ebmlID(nil, id)
		var body []byte
		body = ebmlID(body, idSeekID)
		body = ebmlSize(body, uint64(len(idb)), 1)
		body = append(body, idb...)
		body = ebmlUint(body, idSeekPosition, at, 4)
		return ebmlMaster(nil, idSeek, body)
	}
	var sb []byte
	sb = append(sb, seekEntry(idInfo, p.seekPos[0])...)
	sb = append(sb, seekEntry(idTracks, p.seekPos[1])...)
	sb = append(sb, seekEntry(idCues, p.seekPos[2])...)

	var ib []byte
	ib = ebmlUint(ib, idTimecodeScale, 1_000_000, 4)
	ib = ebmlFloat64(ib, idDuration, float64(p.durationMs))
	ib = ebmlString(ib, idMuxingApp, "deskrally-cp")
	ib = ebmlString(ib, idWritingApp, "deskrally-cp")

	var video []byte
	video = ebmlUint(video, idPixelWidth, uint64(p.info.Width), 2)
	video = ebmlUint(video, idPixelHeight, uint64(p.info.Height), 2)
	var te []byte
	te = ebmlUint(te, idTrackNumber, 1, 1)
	te = ebmlUint(te, idTrackUID, 1, 1)
	te = ebmlUint(te, idTrackType, 1, 1)
	te = ebmlUint(te, idFlagLacing, 0, 1)
	te = ebmlString(te, idCodecID, "V_VP8")
	te = ebmlMaster(te, idVideo, video)

	// Cue cluster positions are relative to the Segment content start (= after the EBML header and the
	// 12-byte Segment header). Before the clusters are laid out, offsets are 0 — same length.
	segStart := int64(len(ebmlMaster(nil, idEBML, eb))) + muxSegHeaderLen
	var cb []byte
	for _, c := range p.clusters {
		if !c.cue {
			continue
		}
		var tp []byte
		tp = ebmlUint(tp, idCueTrack, 1, 1)
		pos := c.offset - segStart
		if pos < 0 {
			pos = 0
		}
		tp = ebmlUint(tp, idCueClusterPos, uint64(pos), 4)
		var cp []byte
		cp = ebmlUint(cp, idCueTime, uint64(c.tcMs), 4)
		cp = ebmlMaster(cp, idCueTrackPos, tp)
		cb = ebmlMaster(cb, idCuePoint, cp)
	}
	return webmParts{
		ebml:     ebmlMaster(nil, idEBML, eb),
		seekHead: ebmlMaster(nil, idSeekHead, sb),
		info:     ebmlMaster(nil, idInfo, ib),
		tracks:   ebmlMaster(nil, idTracks, ebmlMaster(nil, idTrackEntry, te)),
		cues:     ebmlMaster(nil, idCues, cb),
	}
}

// preambleBytes assembles everything before the first cluster, with the real positions and sizes.
func (p *WebMPlan) preambleBytes() ([]byte, error) {
	parts := p.buildParts()
	out := make([]byte, 0, p.preamble)
	out = append(out, parts.ebml...)
	out = ebmlID(out, idSegment)
	out = ebmlSize(out, uint64(p.segContent), 8)
	out = append(out, parts.seekHead...)
	out = append(out, parts.info...)
	out = append(out, parts.tracks...)
	out = append(out, parts.cues...)
	if int64(len(out)) != p.preamble {
		return nil, muxErr(MuxInconsistent, "preamble length drift")
	}
	return out, nil
}

// ---- pass 2: write ----------------------------------------------------------------------------

type countWriter struct {
	dst  io.Writer
	n    int64
	werr error // the first error the DESTINATION returned (distinguishes it from a source error)
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.dst.Write(b)
	c.n += int64(n)
	if err != nil && c.werr == nil {
		c.werr = err
	}
	return n, err
}

// Write streams the second pass: it reads the SAME IVF bytes the scan saw from r and writes exactly
// p.Size() bytes to w. r is read to exactly EOF; any difference from the scan is an error.
func (p *WebMPlan) Write(ctx context.Context, r io.Reader, w io.Writer) error {
	pre, err := p.preambleBytes()
	if err != nil {
		return err
	}
	sink := &countWriter{dst: w}
	wfail := func(err error) error {
		return &MuxError{Code: MuxIO, Msg: "writing the playback copy", Err: err}
	}
	if _, err := sink.Write(pre); err != nil {
		return wfail(err)
	}

	br := bufio.NewReaderSize(ctxReader{ctx, r}, 64<<10)
	var hdr [ivfFileHeader]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return ioOrInvalid(ctx, err, "file header")
	}
	got, err := parseIVFHeader(hdr[:], 65535)
	if err != nil || got.Width != p.info.Width || got.Height != p.info.Height || got.Rate != p.info.Rate || got.Scale != p.info.Scale {
		return muxErr(MuxInconsistent, "the file header changed between passes")
	}

	var fh [ivfFrameHeader]byte
	var blk [muxBlockOverhead]byte
	copyBuf := make([]byte, 32<<10)
	for ci := range p.clusters {
		c := &p.clusters[ci]
		if sink.n != c.offset {
			return muxErr(MuxInconsistent, "layout drift before cluster %d", ci)
		}
		ch := make([]byte, 0, muxClusterHeader+muxClusterTCLen)
		ch = ebmlID(ch, idCluster)
		ch = ebmlSize(ch, uint64(c.body), 4)
		ch = ebmlUint(ch, idClusterTimecode, uint64(c.tcMs), 4)
		if _, err := sink.Write(ch); err != nil {
			return wfail(err)
		}
		for i := c.first; i < c.end; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			f := p.info.frames[i]
			if _, err := io.ReadFull(br, fh[:]); err != nil {
				return ioOrInvalid(ctx, err, "frame header")
			}
			if binary.LittleEndian.Uint32(fh[0:4]) != f.size || binary.LittleEndian.Uint64(fh[4:12]) != f.pts {
				return muxErr(MuxInconsistent, "frame %d changed between passes", i)
			}
			rel := p.relMs(f.pts) - c.tcMs
			if rel < 0 || rel > muxClusterMaxSpanMs {
				return muxErr(MuxInconsistent, "frame %d falls outside its cluster", i)
			}
			b := blk[:0]
			b = ebmlID(b, idSimpleBlock)
			b = ebmlSize(b, uint64(f.size)+4, 4)
			b = append(b, 0x81) // track number 1
			b = binary.BigEndian.AppendUint16(b, uint16(rel))
			flags := byte(0)
			if f.key {
				flags = 0x80
			}
			b = append(b, flags)
			if _, err := sink.Write(b); err != nil {
				return wfail(err)
			}
			n, err := io.CopyBuffer(sink, io.LimitReader(br, int64(f.size)), copyBuf)
			if sink.werr != nil {
				return wfail(sink.werr)
			}
			if err != nil {
				return ioOrInvalid(ctx, err, "frame")
			}
			if n != int64(f.size) {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return muxErr(MuxInconsistent, "frame %d is shorter than it was", i)
			}
		}
	}
	if err := requireEOF(ctx, br, "end of the source", muxErr(MuxInconsistent, "the file grew between passes")); err != nil {
		return err
	}
	if sink.n != p.size {
		return muxErr(MuxInconsistent, "wrote %d bytes, planned %d", sink.n, p.size)
	}
	return nil
}

// ---- sequential reader over an envelope -------------------------------------------------------

// Sequential returns an io.Reader that decrypts the envelope frame by frame, in order, holding one
// frame at a time. Every frame authenticates as it is read; the end of the reader is the end of the
// authenticated plaintext.
func (r *EnvelopeReader) Sequential() io.Reader { return &envSeqReader{r: r} }

type envSeqReader struct {
	r   *EnvelopeReader
	idx uint64
	buf []byte
}

func (s *envSeqReader) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		if s.idx >= s.r.c.hdr.FrameCount {
			return 0, io.EOF
		}
		pt, err := s.r.frame(s.idx)
		if err != nil {
			return 0, err
		}
		s.idx++
		s.buf = pt
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}
