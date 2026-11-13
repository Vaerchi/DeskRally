package controlplane

// Tests for the IVF -> WebM muxer (docs/63 C7). Three kinds, and each can fail:
//
//   - an INDEPENDENT oracle: parseWebM below walks the muxer's output as a generic EBML tree, using none
//     of the muxer's own builders, and checks every size, every position (SeekHead, Cues) and every frame
//     payload against the IVF that went in. A muxer that agrees only with itself fails here.
//   - refusals: one case per bound / malformation, asserting the CLOSED error code.
//   - golden: a committed IVF fixture whose WebM output has a pinned size and sha256, so an accidental
//     layout change is loud.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/bits"
	"os"
	"strings"
	"testing"
	"time"
)

// ---- synthetic IVF ----------------------------------------------------------------------------

type tFrame struct {
	size int
	pts  uint64 // ticks
	key  bool
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func lcgBytes(seed uint64, n int) []byte {
	b := make([]byte, n)
	x := seed*6364136223846793005 + 1442695040888963407
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = byte(x >> 56)
	}
	return b
}

// vp8Payload builds a frame body the muxer accepts: a key frame carries the tag, start code and the
// file's dimensions; an inter frame has bit 0 of the tag set.
func vp8Payload(idx int, f tFrame, w, h int) []byte {
	b := lcgBytes(uint64(idx)+1, f.size)
	if f.key {
		b[0] &^= 1
		if f.size >= 10 {
			b[3], b[4], b[5] = 0x9d, 0x01, 0x2a
			binary.LittleEndian.PutUint16(b[6:8], uint16(w))
			binary.LittleEndian.PutUint16(b[8:10], uint16(h))
		}
	} else {
		b[0] |= 1
	}
	return b
}

func ivfHeader(w, h int, rate, scale uint32, frames uint32) []byte {
	hd := make([]byte, 32)
	copy(hd, "DKIF")
	binary.LittleEndian.PutUint16(hd[6:8], 32)
	copy(hd[8:12], "VP80")
	binary.LittleEndian.PutUint16(hd[12:14], uint16(w))
	binary.LittleEndian.PutUint16(hd[14:16], uint16(h))
	binary.LittleEndian.PutUint32(hd[16:20], rate)
	binary.LittleEndian.PutUint32(hd[20:24], scale)
	binary.LittleEndian.PutUint32(hd[24:28], frames)
	return hd
}

func buildIVF(w, h int, rate, scale uint32, frames []tFrame, headerFrames uint32) []byte {
	out := ivfHeader(w, h, rate, scale, headerFrames)
	for i, f := range frames {
		var fh [12]byte
		binary.LittleEndian.PutUint32(fh[0:4], uint32(f.size))
		binary.LittleEndian.PutUint64(fh[4:12], f.pts)
		out = append(out, fh[:]...)
		out = append(out, vp8Payload(i, f, w, h)...)
	}
	return out
}

// goldenFrames is the committed fixture's shape: 60 frames at 90 kHz / 3000-tick steps, key frames at
// 0, 20, 40 and 31 (31 follows a 45 s gap, so it opens a cluster with a cue), and a NON-key frame (30)
// before the gap — the gap forces a cluster boundary without a key frame.
func goldenFrames() []tFrame {
	var fs []tFrame
	pts := uint64(0)
	for i := 0; i < 60; i++ {
		if i == 31 {
			pts += 45 * 90000 // a 45 s idle gap
		}
		f := tFrame{size: 200 + (i*37)%200, pts: pts}
		if i == 0 || i == 20 || i == 31 || i == 40 {
			f.key, f.size = true, 1500
		}
		fs = append(fs, f)
		pts += 3000
	}
	return fs
}

func goldenIVF() []byte { return buildIVF(320, 200, 90000, 1, goldenFrames(), 60) }

// ---- independent WebM oracle ------------------------------------------------------------------

type ebElem struct {
	id                        uint32
	start, dataStart, dataEnd int
}

func ebRead(t *testing.T, b []byte, off, limit int) ebElem {
	t.Helper()
	if off >= limit {
		t.Fatalf("ebml: element at %d beyond its parent (%d)", off, limit)
	}
	idLen := bits.LeadingZeros8(b[off]) + 1
	if idLen > 4 || off+idLen >= limit {
		t.Fatalf("ebml: bad id at %d", off)
	}
	var id uint32
	for i := 0; i < idLen; i++ {
		id = id<<8 | uint32(b[off+i])
	}
	sb := b[off+idLen]
	if sb == 0 {
		t.Fatalf("ebml: zero size byte at %d", off+idLen)
	}
	sl := bits.LeadingZeros8(sb) + 1
	if off+idLen+sl > limit {
		t.Fatalf("ebml: size field overruns parent at %d", off)
	}
	val := uint64(sb & (0xff >> uint(sl)))
	allOnes := val == uint64(0xff>>uint(sl))
	for i := 1; i < sl; i++ {
		c := b[off+idLen+i]
		val = val<<8 | uint64(c)
		allOnes = allOnes && c == 0xff
	}
	if allOnes {
		t.Fatalf("ebml: unknown-size element 0x%x at %d (the muxer must write known sizes)", id, off)
	}
	ds := off + idLen + sl
	if uint64(ds)+val > uint64(limit) {
		t.Fatalf("ebml: element 0x%x at %d claims %d bytes, parent has %d", id, off, val, limit-ds)
	}
	return ebElem{id: id, start: off, dataStart: ds, dataEnd: ds + int(val)}
}

func ebChildren(t *testing.T, b []byte, e ebElem) []ebElem {
	t.Helper()
	var out []ebElem
	off := e.dataStart
	for off < e.dataEnd {
		c := ebRead(t, b, off, e.dataEnd)
		out = append(out, c)
		off = c.dataEnd
	}
	if off != e.dataEnd {
		t.Fatalf("ebml: children of 0x%x do not fill it exactly (%d vs %d)", e.id, off, e.dataEnd)
	}
	return out
}

func ebUintVal(b []byte, e ebElem) uint64 {
	var v uint64
	for _, c := range b[e.dataStart:e.dataEnd] {
		v = v<<8 | uint64(c)
	}
	return v
}

type wBlock struct {
	rel     int16
	key     bool
	payload []byte
}
type wCluster struct {
	start int
	tc    int64
	blks  []wBlock
}
type wCue struct{ timeMs, pos uint64 }
type webmDoc struct {
	docType                  string
	segStart                 int
	scale                    uint64
	duration                 float64
	width, height            int
	codec                    string
	seek                     map[uint32]uint64
	cues                     []wCue
	clusters                 []wCluster
	infoAt, tracksAt, cuesAt int
}

func parseWebM(t *testing.T, b []byte) *webmDoc {
	t.Helper()
	d := &webmDoc{seek: map[uint32]uint64{}}
	top := ebRead(t, b, 0, len(b))
	if top.id != idEBML {
		t.Fatalf("file does not start with an EBML header: 0x%x", top.id)
	}
	for _, c := range ebChildren(t, b, top) {
		if c.id == idDocType {
			d.docType = string(b[c.dataStart:c.dataEnd])
		}
	}
	seg := ebRead(t, b, top.dataEnd, len(b))
	if seg.id != idSegment || seg.dataEnd != len(b) {
		t.Fatalf("segment 0x%x ends at %d, file is %d bytes", seg.id, seg.dataEnd, len(b))
	}
	d.segStart = seg.dataStart
	for _, e := range ebChildren(t, b, seg) {
		switch e.id {
		case idSeekHead:
			for _, s := range ebChildren(t, b, e) {
				if s.id != idSeek {
					t.Fatalf("seekhead child 0x%x", s.id)
				}
				var sid uint32
				var pos uint64
				for _, f := range ebChildren(t, b, s) {
					switch f.id {
					case idSeekID:
						for _, c := range b[f.dataStart:f.dataEnd] {
							sid = sid<<8 | uint32(c)
						}
					case idSeekPosition:
						pos = ebUintVal(b, f)
					}
				}
				d.seek[sid] = pos
			}
		case idInfo:
			d.infoAt = e.start
			for _, f := range ebChildren(t, b, e) {
				switch f.id {
				case idTimecodeScale:
					d.scale = ebUintVal(b, f)
				case idDuration:
					if f.dataEnd-f.dataStart != 8 {
						t.Fatalf("duration is not a float64")
					}
					d.duration = math.Float64frombits(binary.BigEndian.Uint64(b[f.dataStart:f.dataEnd]))
				}
			}
		case idTracks:
			d.tracksAt = e.start
			te := ebChildren(t, b, e)
			if len(te) != 1 || te[0].id != idTrackEntry {
				t.Fatalf("want exactly one TrackEntry, got %d", len(te))
			}
			for _, f := range ebChildren(t, b, te[0]) {
				switch f.id {
				case idCodecID:
					d.codec = string(b[f.dataStart:f.dataEnd])
				case idVideo:
					for _, v := range ebChildren(t, b, f) {
						switch v.id {
						case idPixelWidth:
							d.width = int(ebUintVal(b, v))
						case idPixelHeight:
							d.height = int(ebUintVal(b, v))
						}
					}
				}
			}
		case idCues:
			d.cuesAt = e.start
			for _, cp := range ebChildren(t, b, e) {
				if cp.id != idCuePoint {
					t.Fatalf("cues child 0x%x", cp.id)
				}
				var c wCue
				for _, f := range ebChildren(t, b, cp) {
					switch f.id {
					case idCueTime:
						c.timeMs = ebUintVal(b, f)
					case idCueTrackPos:
						for _, g := range ebChildren(t, b, f) {
							if g.id == idCueClusterPos {
								c.pos = ebUintVal(b, g)
							}
						}
					}
				}
				d.cues = append(d.cues, c)
			}
		case idCluster:
			cl := wCluster{start: e.start}
			kids := ebChildren(t, b, e)
			if len(kids) == 0 || kids[0].id != idClusterTimecode {
				t.Fatalf("cluster at %d does not start with its Timecode", e.start)
			}
			cl.tc = int64(ebUintVal(b, kids[0]))
			for _, k := range kids[1:] {
				if k.id != idSimpleBlock {
					t.Fatalf("cluster child 0x%x", k.id)
				}
				body := b[k.dataStart:k.dataEnd]
				if len(body) < 5 || body[0] != 0x81 {
					t.Fatalf("simpleblock header %x", body[:min(4, len(body))])
				}
				cl.blks = append(cl.blks, wBlock{rel: int16(binary.BigEndian.Uint16(body[1:3])), key: body[3]&0x80 != 0, payload: body[4:]})
			}
			d.clusters = append(d.clusters, cl)
		default:
			t.Fatalf("unexpected segment child 0x%x", e.id)
		}
	}
	return d
}

// verifyAgainstIVF checks a parsed WebM against the frames that went in.
func verifyAgainstIVF(t *testing.T, out []byte, frames []tFrame, w, h int, rate, scale uint32) *webmDoc {
	t.Helper()
	d := parseWebM(t, out)
	if d.docType != "webm" || d.scale != 1_000_000 || d.codec != "V_VP8" || d.width != w || d.height != h {
		t.Fatalf("header facts: doctype=%q scale=%d codec=%q %dx%d", d.docType, d.scale, d.codec, d.width, d.height)
	}
	// SeekHead entries point (Segment-relative) at the real elements.
	for id, at := range map[uint32]int{idInfo: d.infoAt, idTracks: d.tracksAt, idCues: d.cuesAt} {
		if got := int(d.seek[id]) + d.segStart; got != at {
			t.Errorf("seekhead for 0x%x points at %d, element is at %d", id, got, at)
		}
	}
	// Frames, in order, with exact payloads and timestamps.
	var n int
	var lastAbs int64
	first := frames[0].pts
	for _, cl := range d.clusters {
		for _, bl := range cl.blks {
			if n >= len(frames) {
				t.Fatalf("more blocks than frames")
			}
			f := frames[n]
			if !bytes.Equal(bl.payload, vp8Payload(n, f, w, h)) {
				t.Fatalf("frame %d payload differs from the IVF", n)
			}
			if bl.key != f.key {
				t.Errorf("frame %d key flag = %v, want %v", n, bl.key, f.key)
			}
			wantMs := int64((f.pts - first) * uint64(scale) * 1000 / uint64(rate))
			abs := cl.tc + int64(bl.rel)
			if abs != wantMs {
				t.Errorf("frame %d at %d ms, want %d", n, abs, wantMs)
			}
			if bl.rel < 0 {
				t.Errorf("frame %d has a negative relative timecode", n)
			}
			lastAbs = abs
			n++
		}
	}
	if n != len(frames) {
		t.Fatalf("%d blocks for %d frames", n, len(frames))
	}
	if d.duration <= float64(lastAbs) {
		t.Errorf("duration %v does not cover the last frame at %d", d.duration, lastAbs)
	}
	// Cues: one per cluster that STARTS with a key frame, at that cluster's real position and time.
	wantCues := 0
	for _, cl := range d.clusters {
		if cl.blks[0].key {
			wantCues++
		}
	}
	if len(d.cues) != wantCues {
		t.Fatalf("%d cues, want %d", len(d.cues), wantCues)
	}
	ci := 0
	for _, cl := range d.clusters {
		if !cl.blks[0].key {
			continue
		}
		cu := d.cues[ci]
		ci++
		if int(cu.pos)+d.segStart != cl.start || int64(cu.timeMs) != cl.tc {
			t.Errorf("cue (%d ms @ %d) does not match its cluster (%d ms @ %d)", cu.timeMs, int(cu.pos)+d.segStart, cl.tc, cl.start)
		}
	}
	// Clusters are bounded the way the plan promises.
	for i, cl := range d.clusters {
		last := cl.blks[len(cl.blks)-1]
		if int64(last.rel) > muxClusterMaxSpanMs {
			t.Errorf("cluster %d spans %d ms", i, last.rel)
		}
	}
	return d
}

func scanPlanWrite(t *testing.T, ivf []byte, lim MuxLimits) (*IVFInfo, *WebMPlan, []byte) {
	t.Helper()
	ctx := context.Background()
	info, err := ScanIVF(ctx, bytes.NewReader(ivf), int64(len(ivf)), lim)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	plan, err := PlanWebM(info)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var out bytes.Buffer
	if err := plan.Write(ctx, bytes.NewReader(ivf), &out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if int64(out.Len()) != plan.Size() {
		t.Fatalf("wrote %d bytes, planned %d", out.Len(), plan.Size())
	}
	return info, plan, out.Bytes()
}

// ---- tests ------------------------------------------------------------------------------------

func TestMuxGoldenFixtureStructure(t *testing.T) {
	const fixture = "testdata/recording_golden_v1.ivf"
	const expectFile = "testdata/recording_golden_v1.expect.json"
	ivf := goldenIVF()
	if os.Getenv("DESKRALLY_UPDATE_GOLDEN") == "1" {
		_, plan, out := scanPlanWrite(t, ivf, DefaultMuxLimits())
		sum := sha256.Sum256(out)
		exp, _ := json.MarshalIndent(map[string]any{"webm_size": plan.Size(), "webm_sha256": hex.EncodeToString(sum[:]),
			"clusters": len(parseWebM(t, out).clusters), "cues": len(parseWebM(t, out).cues), "frames": 60,
			"duration_ms": plan.DurationMs()}, "", "  ")
		if err := os.WriteFile(fixture, ivf, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(expectFile, append(exp, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	disk, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("golden IVF fixture: %v (regenerate with DESKRALLY_UPDATE_GOLDEN=1)", err)
	}
	if !bytes.Equal(disk, ivf) {
		t.Fatal("the committed IVF fixture no longer matches goldenFrames(): the generator and the fixture drifted")
	}
	var want struct {
		WebMSize   int64  `json:"webm_size"`
		SHA256     string `json:"webm_sha256"`
		Clusters   int    `json:"clusters"`
		Cues       int    `json:"cues"`
		Frames     int    `json:"frames"`
		DurationMs int64  `json:"duration_ms"`
	}
	raw, err := os.ReadFile(expectFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	info, plan, out := scanPlanWrite(t, disk, DefaultMuxLimits())
	d := verifyAgainstIVF(t, out, goldenFrames(), 320, 200, 90000, 1)
	sum := sha256.Sum256(out)
	if plan.Size() != want.WebMSize || hex.EncodeToString(sum[:]) != want.SHA256 {
		t.Errorf("golden output changed: size %d (want %d) sha256 %x (want %s)", plan.Size(), want.WebMSize, sum, want.SHA256)
	}
	if len(d.clusters) != want.Clusters || len(d.cues) != want.Cues || info.Frames() != want.Frames || plan.DurationMs() != want.DurationMs {
		t.Errorf("structure: %d clusters / %d cues / %d frames / %d ms, want %+v", len(d.clusters), len(d.cues), info.Frames(), plan.DurationMs(), want)
	}
	// What the fixture is designed to prove, stated independently of the pinned numbers: the 45 s gap
	// before frame 31 closed the cluster holding the non-key frame 30 (no int16 timecode overflowed — the
	// oracle checked every relative timecode), and the output stays inside the 1.2 x + 4 KiB bound (a
	// stream copy, not an expansion).
	if bound := int64(len(disk))*12/10 + 4096; int64(len(out)) > bound {
		t.Errorf("webm %d bytes exceeds the bound %d for a %d byte ivf", len(out), bound, len(disk))
	}
	if plan.StartMs() != 0 {
		t.Errorf("start = %d ms", plan.StartMs())
	}
}

func TestMuxClustersCuesAndGaps(t *testing.T) {
	// A gap of 31 s before a NON-key frame: the cluster must still break (relative timecode is int16),
	// and that cluster gets no cue (it does not start on a key frame).
	frames := []tFrame{
		{size: 100, pts: 0, key: true},
		{size: 100, pts: 3000},
		{size: 100, pts: 3000 + 31*90000}, // non-key, 31 s later
		{size: 100, pts: 3000 + 31*90000 + 3000},
		{size: 100, pts: 3000 + 31*90000 + 6000, key: true}, // < 2 s into this cluster: no break yet
	}
	_, _, out := scanPlanWrite(t, buildIVF(64, 48, 90000, 1, frames, 5), DefaultMuxLimits())
	d := verifyAgainstIVF(t, out, frames, 64, 48, 90000, 1)
	if len(d.clusters) != 2 {
		t.Fatalf("%d clusters, want 2 (the gap forces a break, the early key frame does not)", len(d.clusters))
	}
	if len(d.cues) != 1 || d.cues[0].timeMs != 0 {
		t.Errorf("cues = %+v, want exactly the first cluster's", d.cues)
	}
	if d.clusters[1].blks[0].key {
		t.Error("the cluster after the gap starts on a non-key frame in this fixture")
	}

	// A key frame >= 2 s into a cluster opens a new, cued cluster.
	frames2 := []tFrame{{size: 50, pts: 0, key: true}, {size: 50, pts: 90000}, {size: 50, pts: 2 * 90000, key: true}, {size: 50, pts: 2*90000 + 3000}}
	_, _, out2 := scanPlanWrite(t, buildIVF(64, 48, 90000, 1, frames2, 4), DefaultMuxLimits())
	d2 := verifyAgainstIVF(t, out2, frames2, 64, 48, 90000, 1)
	if len(d2.clusters) != 2 || len(d2.cues) != 2 {
		t.Errorf("clusters=%d cues=%d, want 2 and 2", len(d2.clusters), len(d2.cues))
	}
}

func TestMuxSegmentStartingLateIsRebasedToZero(t *testing.T) {
	// Later segments of a recording begin at their own wall-clock offset; the WebM starts at 0 and the
	// plan reports where it sits on the recording's timeline.
	frames := []tFrame{{size: 60, pts: 90000 * 600, key: true}, {size: 60, pts: 90000*600 + 4500}}
	info, plan, out := scanPlanWrite(t, buildIVF(32, 32, 90000, 1, frames, 2), DefaultMuxLimits())
	verifyAgainstIVF(t, out, frames, 32, 32, 90000, 1)
	if plan.StartMs() != 600_000 || info.FirstMs() != 600_000 || info.LastMs() != 600_050 {
		t.Errorf("start=%d first=%d last=%d", plan.StartMs(), info.FirstMs(), info.LastMs())
	}
}

func TestMuxOtherTimebases(t *testing.T) {
	// 1/1000 (ms ticks) and 1001/30000 (NTSC frame ticks) convert with a 128-bit intermediate.
	frames := []tFrame{{size: 40, pts: 0, key: true}, {size: 40, pts: 1}, {size: 40, pts: 2}}
	_, _, out := scanPlanWrite(t, buildIVF(16, 16, 30000, 1001, frames, 3), DefaultMuxLimits())
	d := parseWebM(t, out)
	// 1 tick = 1001/30000 s = 33.3667 ms -> floor.
	if got := d.clusters[0].tc + int64(d.clusters[0].blks[2].rel); got != 66 {
		t.Errorf("tick 2 at %d ms, want 66", got)
	}
}

type tReader struct{ r io.Reader }

func (t tReader) Read(p []byte) (int, error) { return t.r.Read(p) }

func TestMuxRefusals(t *testing.T) {
	ctx := context.Background()
	lim := DefaultMuxLimits()
	good := func() []byte {
		return buildIVF(64, 48, 90000, 1, []tFrame{{size: 100, pts: 0, key: true}, {size: 100, pts: 3000}}, 2)
	}
	frameAt := func(b []byte, n int) int { // offset of frame n's header
		off := 32
		for i := 0; i < n; i++ {
			off += 12 + int(binary.LittleEndian.Uint32(b[off:]))
		}
		return off
	}
	cases := []struct {
		name string
		mut  func([]byte) []byte
		lim  func(*MuxLimits)
		code string
	}{
		{"bad signature", func(b []byte) []byte { b[0] = 'X'; return b }, nil, MuxInvalid},
		{"bad version", func(b []byte) []byte { b[4] = 1; return b }, nil, MuxInvalid},
		{"bad header length", func(b []byte) []byte { b[6] = 33; return b }, nil, MuxInvalid},
		{"vp9 codec", func(b []byte) []byte { copy(b[8:12], "VP90"); return b }, nil, MuxInvalid},
		{"zero width", func(b []byte) []byte { b[12], b[13] = 0, 0; return b }, nil, MuxLimit},
		{"zero height", func(b []byte) []byte { b[14], b[15] = 0, 0; return b }, nil, MuxLimit},
		{"width over 8192", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[12:], 8193); return b }, nil, MuxLimit},
		{"height over 8192", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[14:], 8193); return b }, nil, MuxLimit},
		{"zero timebase rate", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:], 0); return b }, nil, MuxInvalid},
		{"zero timebase scale", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[20:], 0); return b }, nil, MuxInvalid},
		{"header frame count lies", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[24:], 3); return b }, nil, MuxInvalid},
		{"frame of 2 bytes", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[32:], 2); return b }, nil, MuxInvalid},
		{"frame of 0 bytes", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[32:], 0); return b }, nil, MuxInvalid},
		{"frame over the bound", func(b []byte) []byte { return b }, func(l *MuxLimits) { l.MaxFrameBytes = 99 }, MuxLimit},
		{"frame 4 GiB", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[32:], 0xFFFFFFFF); return b }, nil, MuxLimit},
		{"frame claims more than remains", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[frameAt(b, 1):], 101); return b }, nil, MuxInvalid},
		{"trailing 5 bytes", func(b []byte) []byte { return append(b, 1, 2, 3, 4, 5) }, nil, MuxInvalid},
		{"trailing frame header only", func(b []byte) []byte { return append(b, make([]byte, 12)...) }, nil, MuxInvalid},
		{"truncated mid-frame", func(b []byte) []byte { return b[:len(b)-7] }, nil, MuxInvalid},
		{"truncated in a frame header", func(b []byte) []byte { return b[:frameAt(b, 1)+5] }, nil, MuxInvalid},
		{"truncated after the file header", func(b []byte) []byte { return b[:32] }, nil, MuxInvalid},
		{"timestamp goes back", func(b []byte) []byte { binary.LittleEndian.PutUint64(b[frameAt(b, 0)+4:], 9000); return b }, nil, MuxInvalid},
		{"timestamp past the window", func(b []byte) []byte { binary.LittleEndian.PutUint64(b[frameAt(b, 1)+4:], 90000*3600); return b }, func(l *MuxLimits) { l.MaxSpanMs = 60_000 }, MuxLimit},
		{"timestamp overflows the conversion", func(b []byte) []byte { binary.LittleEndian.PutUint64(b[frameAt(b, 1)+4:], math.MaxUint64); return b }, nil, MuxLimit},
		{"first frame is not a key frame", func(b []byte) []byte { b[frameAt(b, 0)+12] |= 1; return b }, nil, MuxInvalid},
		{"key frame without the start code", func(b []byte) []byte { b[frameAt(b, 0)+12+3] = 0; return b }, nil, MuxInvalid},
		{"key frame with other dimensions", func(b []byte) []byte { b[frameAt(b, 0)+12+6]++; return b }, nil, MuxInvalid},
		{"key frame too short for its header", func(b []byte) []byte {
			return buildIVF(64, 48, 90000, 1, []tFrame{{size: 9, pts: 0, key: true}}, 1)
		}, nil, MuxInvalid},
		{"too many frames", func(b []byte) []byte { return b }, func(l *MuxLimits) { l.MaxFrames = 1 }, MuxLimit},
		{"input over the bound", func(b []byte) []byte { return b }, func(l *MuxLimits) { l.MaxInputBytes = 50 }, MuxLimit},
		{"no frames at all", func(b []byte) []byte { return b[:32] }, nil, MuxInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.mut(good())
			l := lim
			if c.lim != nil {
				c.lim(&l)
			}
			_, err := ScanIVF(ctx, bytes.NewReader(b), int64(len(b)), l)
			var me *MuxError
			if !errors.As(err, &me) || me.Code != c.code {
				t.Fatalf("err = %v, want code %s", err, c.code)
			}
		})
	}
}

func TestMuxRequiresExactConsumption(t *testing.T) {
	ctx := context.Background()
	b := buildIVF(64, 48, 90000, 1, []tFrame{{size: 100, pts: 0, key: true}, {size: 100, pts: 3000}}, 2)
	// The source holds more than the declared length: refused (never silently truncated).
	_, err := ScanIVF(ctx, bytes.NewReader(append(append([]byte{}, b...), 0xAA)), int64(len(b)), DefaultMuxLimits())
	var me *MuxError
	if !errors.As(err, &me) || me.Code != MuxInvalid || !strings.Contains(me.Msg, "more than") {
		t.Fatalf("extra source byte: %v", err)
	}
	// The source is shorter than declared: truncated.
	_, err = ScanIVF(ctx, bytes.NewReader(b[:len(b)-1]), int64(len(b)), DefaultMuxLimits())
	if !errors.As(err, &me) || me.Code != MuxInvalid {
		t.Fatalf("short source: %v", err)
	}
}

func TestMuxAmplificationIsRefusedByThePlan(t *testing.T) {
	// 1500 key frames of 10 bytes, 31 s apart: every one needs its own cluster and cue, so the WebM would
	// be ~2.5x the IVF. The plan refuses it before any output exists.
	var frames []tFrame
	for i := 0; i < 1500; i++ {
		frames = append(frames, tFrame{size: 10, pts: uint64(i) * 31 * 90000, key: true})
	}
	b := buildIVF(64, 48, 90000, 1, frames, 1500)
	lim := DefaultMuxLimits()
	info, err := ScanIVF(context.Background(), bytes.NewReader(b), int64(len(b)), lim)
	if err != nil {
		t.Fatalf("the input is VALID container data and must scan: %v", err)
	}
	_, err = PlanWebM(info)
	var me *MuxError
	if !errors.As(err, &me) || me.Code != MuxLimit || !strings.Contains(me.Msg, "1.2") {
		t.Fatalf("plan: %v, want the amplification refusal", err)
	}
}

func TestMuxOutputNeverExceedsTheBoundOnRealisticShapes(t *testing.T) {
	for name, frames := range map[string][]tFrame{
		"golden": goldenFrames(),
		"tiny frames": func() []tFrame {
			var f []tFrame
			for i := 0; i < 400; i++ {
				f = append(f, tFrame{size: 3 + i%5 + 10*b2i(i == 0), pts: uint64(i) * 3000, key: i == 0})
			}
			return f
		}(),
		"one frame": {{size: 10, pts: 0, key: true}},
	} {
		b := buildIVF(64, 48, 90000, 1, frames, 0)
		_, plan, out := scanPlanWrite(t, b, DefaultMuxLimits())
		if bound := int64(len(b))*12/10 + 4096; plan.Size() > bound || int64(len(out)) > bound {
			t.Errorf("%s: output %d > bound %d for input %d", name, len(out), bound, len(b))
		}
	}
}

func TestMuxCancellationAndTimeBudget(t *testing.T) {
	b := goldenIVF()
	// Cancelled before the scan.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanIVF(cctx, bytes.NewReader(b), int64(len(b)), DefaultMuxLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled scan: %v", err)
	}
	// A deadline already past.
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if _, err := ScanIVF(dctx, bytes.NewReader(b), int64(len(b)), DefaultMuxLimits()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired scan: %v", err)
	}
	// Cancelled in the middle of the WRITE pass: the source cancels after a few KiB.
	info, err := ScanIVF(context.Background(), bytes.NewReader(b), int64(len(b)), DefaultMuxLimits())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanWebM(info)
	if err != nil {
		t.Fatal(err)
	}
	wctx, wcancel := context.WithCancel(context.Background())
	src := &cancelAfter{r: bytes.NewReader(b), n: 4096, cancel: wcancel}
	var sink bytes.Buffer
	if err := plan.Write(wctx, src, &sink); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-write cancel: %v", err)
	}
	if int64(sink.Len()) >= plan.Size() {
		t.Error("the cancelled write still produced the whole output")
	}
}

type cancelAfter struct {
	r      io.Reader
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	if c.n <= 0 {
		c.cancel()
	}
	if len(p) > c.n && c.n > 0 {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= n
	return n, err
}

func TestMuxSecondPassMustSeeWhatTheFirstSaw(t *testing.T) {
	ctx := context.Background()
	b := goldenIVF()
	info, err := ScanIVF(ctx, bytes.NewReader(b), int64(len(b)), DefaultMuxLimits())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanWebM(info)
	if err != nil {
		t.Fatal(err)
	}
	mutants := map[string]func([]byte) []byte{
		"a frame size changed": func(x []byte) []byte { x[32] ^= 1; return x },
		"a timestamp changed":  func(x []byte) []byte { x[32+4] ^= 1; return x },
		"header dims changed":  func(x []byte) []byte { x[12]++; return x },
		"file shorter":         func(x []byte) []byte { return x[:len(x)-3] },
		"file longer":          func(x []byte) []byte { return append(x, 0) },
	}
	for name, mut := range mutants {
		t.Run(name, func(t *testing.T) {
			err := plan.Write(ctx, bytes.NewReader(mut(append([]byte{}, b...))), io.Discard)
			var me *MuxError
			if !errors.As(err, &me) {
				t.Fatalf("err = %v, want a MuxError", err)
			}
			if me.Code != MuxInconsistent && me.Code != MuxInvalid {
				t.Fatalf("code = %s", me.Code)
			}
		})
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after -= len(p)
	return len(p), nil
}

func TestMuxDestinationFailureIsAnIOError(t *testing.T) {
	ctx := context.Background()
	b := goldenIVF()
	info, _ := ScanIVF(ctx, bytes.NewReader(b), int64(len(b)), DefaultMuxLimits())
	plan, _ := PlanWebM(info)
	for _, after := range []int{0, 100, 3000} {
		err := plan.Write(ctx, bytes.NewReader(b), &failWriter{after: after})
		var me *MuxError
		if !errors.As(err, &me) || me.Code != MuxIO {
			t.Fatalf("destination fails after %d bytes: %v", after, err)
		}
	}
}

func TestTicksToMsIsOverflowSafe(t *testing.T) {
	if v, ok := ticksToMs(90000, 90000, 1); !ok || v != 1000 {
		t.Fatalf("1 s = %d %v", v, ok)
	}
	if v, ok := ticksToMs(3000, 90000, 1); !ok || v != 33 {
		t.Fatalf("3000 ticks = %d %v (floor)", v, ok)
	}
	if _, ok := ticksToMs(math.MaxUint64, 1, math.MaxUint32); ok {
		t.Fatal("2^64 * 2^32 * 1000 must not fit")
	}
	if _, ok := ticksToMs(math.MaxUint64, 1, 1); ok {
		t.Fatal("2^64 * 1000 / 1 must not fit in int64")
	}
	if v, ok := ticksToMs(math.MaxUint64, math.MaxUint32, 1); !ok || v <= 0 {
		t.Fatalf("large ticks over a large rate fit: %d %v", v, ok)
	}
	if _, ok := ticksToMs(1, 0, 1); ok {
		t.Fatal("rate 0")
	}
}

func TestEnvelopeSequentialReader(t *testing.T) {
	keys, err := NewRecordingKeyring(1, bytes.Repeat([]byte{7}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tenant, rec [16]byte
	tenant[0], rec[0] = 1, 2
	wrapped, kid, err := keys.NewDEK(tenant, rec)
	if err != nil {
		t.Fatal(err)
	}
	data := lcgBytes(5, 3*EnvFrameSize+777)
	f, err := os.CreateTemp(t.TempDir(), "env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	meta := EnvelopeMeta{TenantID: tenant, RecordingID: rec, Rep: RepWebM, Generation: 1, TotalLen: uint64(len(data))}
	w, err := CreateEnvelope(f, keys, EnvelopeKey{KeyID: kid, Wrapped: wrapped}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	open := func(allowPartial bool) *EnvelopeReader {
		rd, err := OpenEnvelope(f, st.Size(), keys, EnvelopeExpect{TenantID: tenant, RecordingID: rec, Rep: RepWebM, Generation: 1}, allowPartial)
		if err != nil {
			t.Fatal(err)
		}
		return rd
	}
	got, err := io.ReadAll(open(false).Sequential())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("sequential read: %d bytes, err %v", len(got), err)
	}
	// Tamper one ciphertext byte: the sequential read must fail with an authentication error, never
	// return the (wrong) plaintext.
	var one [1]byte
	pos := st.Size() - 100
	f.ReadAt(one[:], pos)
	one[0] ^= 0xff
	f.WriteAt(one[:], pos)
	if _, err := io.ReadAll(open(false).Sequential()); !errors.Is(err, ErrEnvelopeAuth) {
		t.Fatalf("tampered file read: %v", err)
	}
}

// A cluster is capped at 8 MiB (its size field is a 4-byte vint and a player buffers a cluster at a
// time): three 3 MiB frames cannot share one.
func TestMuxClusterSizeIsCapped(t *testing.T) {
	frames := []tFrame{
		{size: 3 << 20, pts: 0, key: true},
		{size: 3 << 20, pts: 3000},
		{size: 3 << 20, pts: 6000},
	}
	_, _, out := scanPlanWrite(t, buildIVF(64, 48, 90000, 1, frames, 3), DefaultMuxLimits())
	d := verifyAgainstIVF(t, out, frames, 64, 48, 90000, 1)
	if len(d.clusters) != 2 {
		t.Fatalf("%d clusters for 9 MiB of frames, want 2 (cap 8 MiB)", len(d.clusters))
	}
	for i, cl := range d.clusters {
		var sum int
		for _, b := range cl.blks {
			sum += len(b.payload)
		}
		if sum > muxClusterMaxBytes {
			t.Errorf("cluster %d holds %d bytes of frames", i, sum)
		}
	}
}
