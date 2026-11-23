package controlplane

// Fuzzing the IVF -> WebM muxer (docs/63 C7). The input is untrusted guest data; these targets assert the
// properties that matter whatever the bytes are:
//
//	no panic, no hang, no unbounded allocation        (implicit: the fuzz engine would report it)
//	every refusal is a classified *MuxError           (never a stray error from an index or conversion)
//	an ACCEPTED scan plans within the output bound    (output <= 1.2 x input + 4 KiB: amplification)
//	an accepted plan writes EXACTLY plan.Size() bytes (the envelope header needs the length up front)
//	the output is a well-formed WebM holding every frame byte-for-byte  (independent oracle)
//
// The seed corpus carries malformed and amplification inputs, so a plain `go test` already runs them; run
// the engine with e.g.  go test -run xxx -fuzz FuzzIVFScanPlanWrite -fuzztime 30s

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func muxFuzzLimits() MuxLimits {
	return MuxLimits{MaxFrames: 2000, MaxFrameBytes: 64 << 10, MaxDimension: 8192, MaxSpanMs: 48 * 3600 * 1000, MaxInputBytes: 8 << 20}
}

type countDiscard struct{ n int64 }

func (c *countDiscard) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// splitIVF is a deliberately naive, independent IVF reader for inputs the muxer has ACCEPTED.
func splitIVF(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var out [][]byte
	off := 32
	for off < len(data) {
		if off+12 > len(data) {
			t.Fatalf("accepted input has a partial frame header")
		}
		n := int(binary.LittleEndian.Uint32(data[off:]))
		if off+12+n > len(data) {
			t.Fatalf("accepted input has a partial frame")
		}
		out = append(out, data[off+12:off+12+n])
		off += 12 + n
	}
	return out
}

func FuzzIVFScanPlanWrite(f *testing.F) {
	g := goldenIVF()
	f.Add(g)
	f.Add(g[:len(g)-1])
	f.Add(g[:60])
	f.Add(append(append([]byte{}, g...), 1, 2, 3))
	f.Add(buildIVF(64, 48, 90000, 1, []tFrame{{size: 10, pts: 0, key: true}}, 1))
	f.Add(buildIVF(8192, 8192, 90000, 1, []tFrame{{size: 12, pts: 0, key: true}}, 1))
	f.Add(buildIVF(8193, 1, 90000, 1, []tFrame{{size: 12, pts: 0, key: true}}, 1))
	f.Add(buildIVF(0, 0, 90000, 1, nil, 0))
	f.Add(buildIVF(64, 48, 0, 0, []tFrame{{size: 10, pts: 0, key: true}}, 1))
	// Header lies about a frame's size (4 GiB), and about the frame count.
	lie := buildIVF(64, 48, 90000, 1, []tFrame{{size: 10, pts: 0, key: true}, {size: 10, pts: 1}}, 2)
	binary.LittleEndian.PutUint32(lie[32:], math.MaxUint32)
	f.Add(lie)
	lie2 := buildIVF(64, 48, 90000, 1, []tFrame{{size: 10, pts: 0, key: true}}, 999)
	f.Add(lie2)
	// Timestamps: backwards, and at the top of the range.
	f.Add(buildIVF(64, 48, 90000, 1, []tFrame{{size: 10, pts: 5000, key: true}, {size: 10, pts: 1}}, 2))
	f.Add(buildIVF(64, 48, 1, 1, []tFrame{{size: 10, pts: 0, key: true}, {size: 10, pts: math.MaxUint64}}, 2))
	// AMPLIFICATION: many tiny key frames far apart (each wants its own cluster and cue), and many tiny
	// inter frames (per-frame overhead).
	var amp, tiny []tFrame
	for i := 0; i < 300; i++ {
		amp = append(amp, tFrame{size: 10, pts: uint64(i) * 31 * 90000, key: true})
		tiny = append(tiny, tFrame{size: 3, pts: uint64(i), key: i == 0})
	}
	tiny[0].size = 10
	f.Add(buildIVF(64, 48, 90000, 1, amp, 300))
	f.Add(buildIVF(64, 48, 90000, 1, tiny, 300))
	f.Add([]byte("DKIF"))
	f.Add(make([]byte, 100))
	f.Add(bytes.Repeat([]byte{0xff}, 200))

	lim := muxFuzzLimits()
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		ctx := context.Background()
		info, err := ScanIVF(ctx, bytes.NewReader(data), int64(len(data)), lim)
		if err != nil {
			var me *MuxError
			if !errors.As(err, &me) {
				t.Fatalf("scan refused with an unclassified error: %v", err)
			}
			return
		}
		if info.Frames() < 1 || info.Frames() > lim.MaxFrames || info.Width > lim.MaxDimension || info.Height > lim.MaxDimension {
			t.Fatalf("accepted scan violates a bound: %d frames %dx%d", info.Frames(), info.Width, info.Height)
		}
		plan, err := PlanWebM(info)
		if err != nil {
			var me *MuxError
			if !errors.As(err, &me) {
				t.Fatalf("plan refused with an unclassified error: %v", err)
			}
			return
		}
		if bound := int64(len(data))*muxOutNum/muxOutDen + muxOutSlack; plan.Size() > bound {
			t.Fatalf("plan %d exceeds the amplification bound %d", plan.Size(), bound)
		}
		var buf bytes.Buffer
		if err := plan.Write(ctx, bytes.NewReader(data), &buf); err != nil {
			t.Fatalf("an accepted, planned input failed to write: %v", err)
		}
		if int64(buf.Len()) != plan.Size() {
			t.Fatalf("wrote %d bytes, planned %d", buf.Len(), plan.Size())
		}
		// Independent oracle: well-formed, and every frame byte-for-byte.
		d := parseWebM(t, buf.Bytes())
		want := splitIVF(t, data)
		var got [][]byte
		for _, cl := range d.clusters {
			for _, bl := range cl.blks {
				got = append(got, bl.payload)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%d blocks for %d frames", len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("frame %d differs", i)
			}
		}
	})
}

// FuzzIVFStructured builds VALID IVF files from a compact description so the fuzzer reaches the cluster /
// cue logic (gaps, key-frame spacing, big frames) that random bytes almost never get past the header to
// exercise, then holds the muxer to the full oracle.
func FuzzIVFStructured(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add(bytes.Repeat([]byte{200, 15, 255, 255}, 50)) // big gaps: every frame its own cluster
	f.Add(bytes.Repeat([]byte{3, 0, 0, 0}, 400))       // tiny frames, no gaps
	f.Add(bytes.Repeat([]byte{255, 15, 4, 4}, 120))    // large frames
	f.Add(bytes.Repeat([]byte{10, 1, 31, 40}, 90))     // ~2 s apart: soft cluster breaks on key frames
	lim := muxFuzzLimits()
	f.Fuzz(func(t *testing.T, spec []byte) {
		if len(spec) > 4*1500 {
			spec = spec[:4*1500]
		}
		frames := []tFrame{{size: 12, pts: 0, key: true}}
		pts := uint64(0)
		for i := 0; i+4 <= len(spec); i += 4 {
			size := 3 + int(spec[i]) | int(spec[i+1]&0x0f)<<8
			key := spec[i+1]&0x80 != 0
			if key && size < 10 {
				size = 10
			}
			pts += uint64(spec[i+2]) * uint64(spec[i+3]) * 500
			frames = append(frames, tFrame{size: size, pts: pts, key: key})
		}
		data := buildIVF(64, 48, 90000, 1, frames, uint32(len(frames)))
		ctx := context.Background()
		info, err := ScanIVF(ctx, bytes.NewReader(data), int64(len(data)), lim)
		if err != nil {
			spanMs := int64(pts) * 1000 / 90000
			var me *MuxError
			if errors.As(err, &me) && me.Code == MuxLimit && (spanMs > lim.MaxSpanMs || int64(len(data)) > lim.MaxInputBytes) {
				return // legitimately outside the recording window / size bound
			}
			t.Fatalf("a valid file was refused: %v", err)
		}
		plan, err := PlanWebM(info)
		if err != nil {
			var me *MuxError
			if errors.As(err, &me) && me.Code == MuxLimit {
				return // the amplification bound, by design
			}
			t.Fatalf("plan: %v", err)
		}
		var buf bytes.Buffer
		if err := plan.Write(ctx, bytes.NewReader(data), &buf); err != nil {
			t.Fatalf("write: %v", err)
		}
		if int64(buf.Len()) != plan.Size() {
			t.Fatalf("wrote %d, planned %d", buf.Len(), plan.Size())
		}
		verifyAgainstIVF(t, buf.Bytes(), frames, 64, 48, 90000, 1)
	})
}
