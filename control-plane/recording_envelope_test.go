package controlplane

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func envTestKeyring(t *testing.T) *RecordingKeyring {
	t.Helper()
	k, err := NewRecordingKeyring(1, bytes.Repeat([]byte{7}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type envFixture struct {
	keys *RecordingKeyring
	key  EnvelopeKey
	meta EnvelopeMeta
}

func newEnvFixture(t *testing.T, total int) envFixture {
	t.Helper()
	keys := envTestKeyring(t)
	tn, _ := recParseUUID(goldenTenant)
	rc, _ := recParseUUID(goldenRec)
	w, id, err := keys.NewDEK(tn, rc)
	if err != nil {
		t.Fatal(err)
	}
	return envFixture{keys: keys, key: EnvelopeKey{KeyID: id, Wrapped: w},
		meta: EnvelopeMeta{TenantID: tn, RecordingID: rc, Segment: 3, Rep: RepIVF, Generation: 1, TotalLen: uint64(total)}}
}

func (e envFixture) expect() EnvelopeExpect {
	return EnvelopeExpect{TenantID: e.meta.TenantID, RecordingID: e.meta.RecordingID, Segment: e.meta.Segment, Rep: e.meta.Rep, Generation: e.meta.Generation}
}

func writeEnvFile(t *testing.T, e envFixture, plain []byte, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := CreateEnvelope(f, e.keys, e.key, e.meta)
	if err != nil {
		t.Fatal(err)
	}
	// Write in awkward pieces so buffering across frame boundaries is exercised.
	for off := 0; off < len(plain); {
		n := 4099
		if off+n > len(plain) {
			n = len(plain) - off
		}
		if _, err := w.Write(plain[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func openEnvFile(t *testing.T, e envFixture, path string, allowPartial bool) (*EnvelopeReader, error) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return OpenEnvelope(bytes.NewReader(b), int64(len(b)), e.keys, e.expect(), allowPartial)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestEnvelopeRoundTripAndRanges(t *testing.T) {
	for _, total := range []int{1, 31, EnvFrameSize - 1, EnvFrameSize, EnvFrameSize + 1, 3*EnvFrameSize + 17} {
		e := newEnvFixture(t, total)
		plain := randBytes(total)
		path := filepath.Join(t.TempDir(), "seg.enc")
		writeEnvFile(t, e, plain, path)

		st, _ := os.Stat(path)
		if st.Size() != EnvelopeDiskSize(uint64(total), len(e.key.Wrapped)) {
			t.Fatalf("total %d: file size %d, want %d", total, st.Size(), EnvelopeDiskSize(uint64(total), len(e.key.Wrapped)))
		}
		if bytes.Contains(mustRead(t, path), plain[:min(len(plain), 64)]) && total >= 64 {
			t.Fatalf("total %d: plaintext visible on disk", total)
		}
		r, err := openEnvFile(t, e, path, false)
		if err != nil {
			t.Fatalf("total %d: open: %v", total, err)
		}
		var out bytes.Buffer
		if _, err := r.WriteTo(&out); err != nil || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("total %d: full read err=%v equal=%v", total, err, bytes.Equal(out.Bytes(), plain))
		}
		// Ranges straddling frame boundaries.
		for _, rg := range [][2]int{{0, total}, {0, 1}, {total - 1, 1}, {EnvFrameSize - 3, 6}, {EnvFrameSize, 5}, {total / 2, total / 3}} {
			off, n := rg[0], rg[1]
			if off < 0 || off+n > total || n < 0 {
				continue
			}
			got, err := r.ReadRange(int64(off), int64(n))
			if err != nil || !bytes.Equal(got, plain[off:off+n]) {
				t.Fatalf("total %d range %v: err=%v", total, rg, err)
			}
		}
		if _, err := r.ReadRange(0, int64(total)+1); !errors.Is(err, ErrEnvelopeRange) {
			t.Fatalf("range past the end: %v", err)
		}
		if _, err := r.ReadRange(-1, 1); !errors.Is(err, ErrEnvelopeRange) {
			t.Fatalf("negative range: %v", err)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openBytes opens an in-memory file image and fully reads it; it returns the first error.
func readAllBytes(e envFixture, img []byte, expect EnvelopeExpect) error {
	r, err := OpenEnvelope(bytes.NewReader(img), int64(len(img)), e.keys, expect, false)
	if err != nil {
		return err
	}
	_, err = r.WriteTo(&bytes.Buffer{})
	return err
}

func TestEnvelopeTamperDetection(t *testing.T) {
	total := 3*EnvFrameSize + 100
	e := newEnvFixture(t, total)
	plain := randBytes(total)
	path := filepath.Join(t.TempDir(), "seg.enc")
	writeEnvFile(t, e, plain, path)
	img := mustRead(t, path)
	if err := readAllBytes(e, img, e.expect()); err != nil {
		t.Fatalf("pristine file refused: %v", err)
	}
	hdr := int(EnvelopeDiskSize(uint64(total), len(e.key.Wrapped))) - total - 4*envTagSize

	// Flip one bit in every region: each header field, a frame body, a frame tag.
	positions := map[string]int{}
	for i := 0; i < hdr; i++ { // EVERY header byte
		positions["header byte"+string(rune('A'+i%26))+itoa(i)] = i
	}
	positions["first frame body"] = hdr + 5
	positions["second frame body"] = hdr + EnvFrameSize + envTagSize + 9
	positions["first frame tag"] = hdr + EnvFrameSize + 2
	positions["last frame body"] = len(img) - envTagSize - 3
	positions["last frame tag"] = len(img) - 1
	for name, pos := range positions {
		m := append([]byte(nil), img...)
		m[pos] ^= 0x01
		if err := readAllBytes(e, m, e.expect()); err == nil {
			t.Errorf("flip at %s (offset %d) went undetected", name, pos)
		}
	}

	// Header fields no other check pins: with the generation left as "any", only the header's hash in every
	// frame's AAD can notice a flipped generation byte (and the same for the segment/representation bytes
	// when a caller does not state them).
	genOff := envHeadFixed + len(e.key.Wrapped) + 16 + 16 + 4 + 1
	for i := 0; i < 8; i++ {
		m := append([]byte(nil), img...)
		m[genOff+i] ^= 0x01
		x := e.expect()
		x.Generation = 0
		if err := readAllBytes(e, m, x); err == nil {
			t.Errorf("a flipped generation byte %d went undetected when the caller did not pin the generation", i)
		}
	}

	// Truncation: drop the final byte, the final frame, and a middle frame boundary.
	for _, cut := range []int{1, 20, EnvFrameSize, len(img) - hdr} {
		if err := readAllBytes(e, img[:len(img)-cut], e.expect()); err == nil {
			t.Errorf("truncation by %d accepted", cut)
		}
	}
	// A truncation that lands exactly on a frame boundary is refused even when partial reads are
	// allowed, because the prefix's frames carry the final flag only on the true last frame.
	pre := img[:hdr+2*(EnvFrameSize+envTagSize)]
	r, err := OpenEnvelope(bytes.NewReader(pre), int64(len(pre)), e.keys, e.expect(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteTo(&bytes.Buffer{}); err == nil {
		t.Error("a frame-aligned prefix read as a whole file")
	}
	// Trailing bytes.
	if err := readAllBytes(e, append(append([]byte(nil), img...), 0), e.expect()); err == nil {
		t.Error("trailing byte accepted")
	}
	// Frame reorder: swap the first two (equal-size) frames.
	fs := EnvFrameSize + envTagSize
	sw := append([]byte(nil), img...)
	copy(sw[hdr:hdr+fs], img[hdr+fs:hdr+2*fs])
	copy(sw[hdr+fs:hdr+2*fs], img[hdr:hdr+fs])
	if err := readAllBytes(e, sw, e.expect()); err == nil {
		t.Error("reordered frames accepted")
	}
	// Frame duplication in place of another.
	dup := append([]byte(nil), img...)
	copy(dup[hdr+fs:hdr+2*fs], img[hdr:hdr+fs])
	if err := readAllBytes(e, dup, e.expect()); err == nil {
		t.Error("duplicated frame accepted")
	}

	// Binding checks: right bytes, wrong expectation.
	for name, mut := range map[string]func(*EnvelopeExpect){
		"tenant":     func(x *EnvelopeExpect) { x.TenantID[0] ^= 1 },
		"recording":  func(x *EnvelopeExpect) { x.RecordingID[0] ^= 1 },
		"segment":    func(x *EnvelopeExpect) { x.Segment++ },
		"rep":        func(x *EnvelopeExpect) { x.Rep = RepWebM },
		"generation": func(x *EnvelopeExpect) { x.Generation++ },
	} {
		x := e.expect()
		mut(&x)
		if err := readAllBytes(e, img, x); err == nil {
			t.Errorf("wrong %s accepted", name)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// Frames from another file under the SAME data key never authenticate: the header hash is in the AAD.
func TestEnvelopeSpliceBetweenFilesFails(t *testing.T) {
	total := 2 * EnvFrameSize
	e := newEnvFixture(t, total)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	writeEnvFile(t, e, randBytes(total), a)
	writeEnvFile(t, e, randBytes(total), b) // same DEK, same meta, fresh nonce prefix
	ia, ib := mustRead(t, a), mustRead(t, b)
	hdr := len(ia) - total - 2*envTagSize
	mix := append([]byte(nil), ia...)
	copy(mix[hdr:], ib[hdr:])
	if err := readAllBytes(e, mix, e.expect()); err == nil {
		t.Fatal("frames spliced from another file authenticated")
	}
	if bytes.Equal(ia[hdr-16-8-8-4:hdr-8-8-4], ib[hdr-16-8-8-4:hdr-8-8-4]) {
		t.Fatal("two files share a nonce prefix")
	}
}

// The wrapped key is bound to tenant, recording and key id.
func TestEnvelopeWrappedKeyBinding(t *testing.T) {
	keys := envTestKeyring(t)
	tn, _ := recParseUUID(goldenTenant)
	rc, _ := recParseUUID(goldenRec)
	w, id, err := keys.NewDEK(tn, rc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.UnwrapDEK(w, tn, rc, id); err != nil {
		t.Fatal(err)
	}
	other := rc
	other[0] ^= 1
	if _, err := keys.UnwrapDEK(w, tn, other, id); err == nil {
		t.Error("wrapped key unwrapped for another recording")
	}
	otherT := tn
	otherT[0] ^= 1
	if _, err := keys.UnwrapDEK(w, otherT, rc, id); err == nil {
		t.Error("wrapped key unwrapped for another tenant")
	}
	if _, err := keys.UnwrapDEK(w, tn, rc, id+1); err == nil {
		t.Error("wrapped key unwrapped under another key id")
	}
	m := append([]byte(nil), w...)
	m[len(m)-1] ^= 1
	if _, err := keys.UnwrapDEK(m, tn, rc, id); err == nil {
		t.Error("tampered wrapped key accepted")
	}
	// A different master key cannot unwrap.
	k2, _ := NewRecordingKeyring(1, bytes.Repeat([]byte{8}, 32), nil)
	if _, err := k2.UnwrapDEK(w, tn, rc, id); err == nil {
		t.Error("wrong master key unwrapped")
	}
}

func TestEnvelopeWriterOverflowAndShort(t *testing.T) {
	e := newEnvFixture(t, 100)
	f, _ := os.Create(filepath.Join(t.TempDir(), "x"))
	defer f.Close()
	w, err := CreateEnvelope(f, e.keys, e.key, e.meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 101)); !errors.Is(err, ErrEnvelopeOverflow) {
		t.Fatalf("overflow: %v", err)
	}
	if _, err := w.Write(make([]byte, 99)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, ErrEnvelopeShort) {
		t.Fatalf("short close: %v", err)
	}
	if _, err := w.Write(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("exact close: %v", err)
	}
}

func TestEnvelopeResumeRefusesUnacknowledgedTailAndRestartGetsFreshNonces(t *testing.T) {
	total := 5*EnvFrameSize + 1000
	e := newEnvFixture(t, total)
	plain := randBytes(total)
	path := filepath.Join(t.TempDir(), "seg.enc")
	f, _ := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	w, err := CreateEnvelope(f, e.keys, e.key, e.meta)
	if err != nil {
		t.Fatal(err)
	}
	// Write 4 frames, but pretend only 2 were acknowledged (crash between fsync and the DB commit).
	if _, err := w.Write(plain[:4*EnvFrameSize]); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before, _ := os.ReadFile(path)
	hdr1, _, err := readEnvHeader(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	oldFrame2 := append([]byte(nil), before[hdr1.framePos(2):hdr1.framePos(3)]...)

	// A resume must NOT re-seal indexes 2 and 3 under the same prefix: it refuses and leaves the file alone.
	f, _ = os.OpenFile(path, os.O_RDWR, 0o600)
	if _, err := ResumeEnvelope(f, e.keys, e.key, e.meta, 2*EnvFrameSize); !errors.Is(err, ErrEnvelopeDirty) {
		t.Fatalf("resume over an unacknowledged tail: %v, want ErrEnvelopeDirty", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("the refused resume modified the file")
	}

	// The segment restarts (what the upload layer does on ErrEnvelopeDirty): a fresh prefix, DIFFERENT bytes
	// at the same frame index.
	other := randBytes(total)
	w, err = CreateEnvelope(f, e.keys, e.key, e.meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(other); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	img, _ := os.ReadFile(path)
	hdr2, _, err := readEnvHeader(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	for idx := uint64(0); idx < 4; idx++ {
		var n1, n2 [24]byte
		copy(n1[:16], hdr1.NoncePrefix[:])
		binary.BigEndian.PutUint64(n1[16:], idx)
		copy(n2[:16], hdr2.NoncePrefix[:])
		binary.BigEndian.PutUint64(n2[16:], idx)
		if n1 == n2 {
			t.Fatalf("frame %d was sealed twice under the same nonce", idx)
		}
	}
	if bytes.Equal(oldFrame2, img[hdr2.framePos(2):hdr2.framePos(3)]) {
		t.Fatal("identical ciphertext for different plaintext")
	}
	r, err := openEnvFile(t, e, path, false)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := r.WriteTo(&out); err != nil || !bytes.Equal(out.Bytes(), other) {
		t.Fatalf("restarted file does not read back the NEW bytes: %v", err)
	}
}

func TestEnvelopeResumeAtACleanBoundaryContinues(t *testing.T) {
	total := 5*EnvFrameSize + 1000
	e := newEnvFixture(t, total)
	plain := randBytes(total)
	path := filepath.Join(t.TempDir(), "seg.enc")
	f, _ := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	w, err := CreateEnvelope(f, e.keys, e.key, e.meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain[:2*EnvFrameSize]); err != nil {
		t.Fatal(err)
	}
	f.Close()

	f, _ = os.OpenFile(path, os.O_RDWR, 0o600)
	w, err = ResumeEnvelope(f, e.keys, e.key, e.meta, 2*EnvFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain[2*EnvFrameSize:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r, err := openEnvFile(t, e, path, false)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := r.WriteTo(&out); err != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("resumed file does not read back: %v", err)
	}
	// Refusals: unaligned offset, offset beyond what the file holds, a header for different meta.
	f, _ = os.OpenFile(path, os.O_RDWR, 0o600)
	defer f.Close()
	if _, err := ResumeEnvelope(f, e.keys, e.key, e.meta, 100); err == nil {
		t.Error("unaligned resume accepted")
	}
	short := filepath.Join(t.TempDir(), "short.enc")
	g, _ := os.OpenFile(short, os.O_RDWR|os.O_CREATE, 0o600)
	defer g.Close()
	if _, err := CreateEnvelope(g, e.keys, e.key, e.meta); err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeEnvelope(g, e.keys, e.key, e.meta, 2*EnvFrameSize); !errors.Is(err, ErrEnvelopeTruncate) {
		t.Errorf("resume beyond the file: %v", err)
	}
	m2 := e.meta
	m2.Segment++
	if _, err := ResumeEnvelope(f, e.keys, e.key, m2, 0); err == nil {
		t.Error("resume against a different segment's header accepted")
	}
}

func TestRecordingKeyringFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if k, err := RecordingKeyringFromEnv(env(nil)); k != nil || err != nil {
		t.Fatalf("unset must mean not configured: %v %v", k, err)
	}
	good := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	k, err := RecordingKeyringFromEnv(env(map[string]string{"RECORDING_MASTER_KEY": good}))
	if err != nil || k.CurrentID() != 1 {
		t.Fatalf("good key: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"all zero":    {"RECORDING_MASTER_KEY": "0000000000000000000000000000000000000000000000000000000000000000"},
		"short":       {"RECORDING_MASTER_KEY": "0102"},
		"not hex":     {"RECORDING_MASTER_KEY": "zz"},
		"zero id":     {"RECORDING_MASTER_KEY": good, "RECORDING_MASTER_KEY_ID": "0"},
		"dup id":      {"RECORDING_MASTER_KEY": good, "RECORDING_MASTER_KEY_PREVIOUS": "1:" + good},
		"bad prev":    {"RECORDING_MASTER_KEY": good, "RECORDING_MASTER_KEY_PREVIOUS": "nonsense"},
		"prev zeroes": {"RECORDING_MASTER_KEY": good, "RECORDING_MASTER_KEY_PREVIOUS": "2:" + "0000000000000000000000000000000000000000000000000000000000000000"},
	} {
		if _, err := RecordingKeyringFromEnv(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A rotated keyring still unwraps under the old id.
	old, _ := NewRecordingKeyring(1, bytes.Repeat([]byte{7}, 32), nil)
	tn, _ := recParseUUID(goldenTenant)
	rc, _ := recParseUUID(goldenRec)
	w, id, _ := old.NewDEK(tn, rc)
	rot, err := NewRecordingKeyring(2, bytes.Repeat([]byte{9}, 32), map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rot.UnwrapDEK(w, tn, rc, id); err != nil {
		t.Fatalf("rotated keyring cannot unwrap an old DEK: %v", err)
	}
	if _, nid, _ := rot.NewDEK(tn, rc); nid != 2 {
		t.Fatalf("new DEK wrapped under %d, want 2", nid)
	}
}
