package controlplane

// D1 (review r2): the final EOF probe of both muxer passes must see exactly zero bytes AND io.EOF. An
// authentication failure of the frame AFTER the last expected byte (the envelope holds more than the IVF the
// muxer was told about) used to be swallowed because only the byte count was looked at.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// ivfOfExactLen builds a valid IVF of exactly n bytes (the last frame absorbs the difference).
func ivfOfExactLen(t *testing.T, n int) []byte {
	t.Helper()
	const head = ivfFileHeader + 2*ivfFrameHeader + 1500
	last := n - head
	if last < 3 {
		t.Fatalf("n=%d too small", n)
	}
	b := buildIVF(320, 200, 90000, 1, []tFrame{{size: 1500, pts: 0, key: true}, {size: last, pts: 3000}}, 2)
	if len(b) != n {
		t.Fatalf("built %d bytes, want %d", len(b), n)
	}
	return b
}

// envelopeOf writes plain as an envelope and returns the file, its size and the keyring.
func envelopeOf(t *testing.T, plain []byte) (*os.File, int64, *RecordingKeyring, EnvelopeExpect) {
	t.Helper()
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
	f, err := os.CreateTemp(t.TempDir(), "env")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	meta := EnvelopeMeta{TenantID: tenant, RecordingID: rec, Rep: RepIVF, Generation: 1, TotalLen: uint64(len(plain))}
	w, err := CreateEnvelope(f, keys, EnvelopeKey{KeyID: kid, Wrapped: wrapped}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	return f, st.Size(), keys, EnvelopeExpect{TenantID: tenant, RecordingID: rec, Rep: RepIVF, Generation: 1}
}

func corruptLastByte(t *testing.T, f *os.File, size int64) {
	t.Helper()
	var one [1]byte
	if _, err := f.ReadAt(one[:], size-1); err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0xff
	if _, err := f.WriteAt(one[:], size-1); err != nil {
		t.Fatal(err)
	}
}

func TestMuxPassesRefuseAnAuthFailureAfterTheFinalExpectedByte(t *testing.T) {
	// The IVF ends exactly on an envelope frame boundary (1 and 2 whole frames), and a further frame follows
	// it in the envelope: the scan and the write are told the IVF length, so their probe is what reads it.
	for _, frames := range []int{1, 2} {
		ivf := ivfOfExactLen(t, frames*EnvFrameSize)
		if len(ivf)%EnvFrameSize != 0 {
			t.Fatal("test bug: not on a frame boundary")
		}
		extra := lcgBytes(9, 500)
		plain := append(append([]byte{}, ivf...), extra...)
		lim := DefaultMuxLimits()
		ctx := context.Background()

		// Control: an untampered longer envelope is refused as "more than declared" by BOTH passes.
		f, size, keys, exp := envelopeOf(t, plain)
		rd, err := OpenEnvelope(f, size, keys, exp, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ScanIVF(ctx, rd.Sequential(), int64(len(ivf)), lim); err == nil {
			t.Fatalf("%d frame(s): scan accepted a source longer than declared", frames)
		}

		// Tamper the trailing frame (the last byte of the file is inside it).
		corruptLastByte(t, f, size)
		rd, err = OpenEnvelope(f, size, keys, exp, false)
		if err != nil {
			t.Fatal(err)
		}
		var me *MuxError
		_, err = ScanIVF(ctx, rd.Sequential(), int64(len(ivf)), lim)
		if err == nil {
			t.Fatalf("%d frame(s): scan returned success although the next frame fails authentication", frames)
		}
		if !errors.As(err, &me) || me.Code != MuxIO || !errors.Is(err, ErrEnvelopeAuth) {
			t.Fatalf("%d frame(s): scan error %v, want an I/O error carrying the authentication failure", frames, err)
		}

		// Pass 2: plan from the clean IVF, then write from the tampered envelope.
		info, err := ScanIVF(ctx, bytes.NewReader(ivf), int64(len(ivf)), lim)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := PlanWebM(info)
		if err != nil {
			t.Fatal(err)
		}
		rd, err = OpenEnvelope(f, size, keys, exp, false)
		if err != nil {
			t.Fatal(err)
		}
		err = plan.Write(ctx, rd.Sequential(), io.Discard)
		if err == nil {
			t.Fatalf("%d frame(s): write returned success although the next frame fails authentication", frames)
		}
		if !errors.Is(err, ErrEnvelopeAuth) {
			t.Fatalf("%d frame(s): write error %v, want the authentication failure", frames, err)
		}
	}
}

// The probe's other outcomes: a clean exact source passes, and a non-EOF error from the source is
// propagated rather than treated as the end.
func TestRequireEOFOutcomes(t *testing.T) {
	ctx := context.Background()
	more := errors.New("more")
	if err := requireEOF(ctx, bytes.NewReader(nil), "x", more); err != nil {
		t.Fatalf("clean EOF: %v", err)
	}
	if err := requireEOF(ctx, bytes.NewReader([]byte{1}), "x", more); !errors.Is(err, more) {
		t.Fatalf("a byte: %v", err)
	}
	boom := errors.New("disk on fire")
	if err := requireEOF(ctx, errReader{boom}, "x", more); !errors.Is(err, boom) {
		t.Fatalf("a read error: %v", err)
	}
	if err := requireEOF(ctx, zeroReader{}, "x", more); err == nil {
		t.Fatal("a source that never makes progress was accepted")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }
