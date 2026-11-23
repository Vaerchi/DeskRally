package controlplane

// Encrypted recording envelope (docs/63 §2a C5, D4).
//
// Every recording byte on the server's disk — the evidence copy, the playback copy AND the temp /
// incoming generations — lives in this envelope. There is no plaintext file anywhere.
//
//	header (authenticated: its sha256 is in every frame's AAD)
//	  magic "RMTREC01" | version u16 | key id u32 | wrapped-DEK length u16 | wrapped DEK
//	  tenant (16) | recording (16) | segment u32 | representation u8 (1 ivf, 2 webm) | generation u64
//	  file nonce prefix (16, random) | total plaintext length u64 | frame count u64 | frame size u32
//	frames, in order, each XChaCha20-Poly1305:
//	  nonce = prefix(16) || frame index u64 (big-endian)            (24 bytes)
//	  AAD   = header hash(32) || frame index u64 || plaintext length u32 || final flag u8
//	  frame = ciphertext(plaintext length) || tag(16)
//
// Frames are 64 KiB of plaintext (the last one may be shorter), so a byte range maps to a frame range
// arithmetically and seeking is cheap. The header states the total length and frame count up front
// (the upload API knows each segment's declared length at create time), so:
//
//   - a truncated file fails (exact EOF is checked against the authenticated header on a full read);
//   - dropping, duplicating or reordering frames fails (the index is in the nonce AND the AAD, and the
//     final flag is in the AAD so a prefix cannot masquerade as a whole);
//   - splicing frames in from another file fails (the header hash differs, so the AAD differs);
//   - a range read checks its frame index against the authenticated frame count.
//
// The per-recording data key (DEK) is random and wrapped by the master key (KEK, RECORDING_MASTER_KEY)
// with AAD = tenant || recording || key id, so a wrapped DEK lifted onto another recording does not
// unwrap. A rewrite of a file is a NEW generation with a NEW random prefix; a (key, nonce) pair is
// never reused because the prefix is 128 random bits per file and a frame index is sealed once per
// prefix: a writer that resumes a crashed upload refuses a file with unacknowledged frames past the
// committed offset (ErrEnvelopeDirty) rather than re-seal those indexes, and the segment restarts under
// a fresh prefix.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	envMagic     = "RMTREC01"
	envVersion   = uint16(1)
	EnvFrameSize = 64 * 1024
	envTagSize   = chacha20poly1305.Overhead // 16
	envMaxTotal  = uint64(8) << 30           // sanity bound on a header's declared plaintext length
	envMaxWrap   = 256
	envFixedTail = 16 + 16 + 4 + 1 + 8 + 16 + 8 + 8 + 4 // tenant..frame size, after the wrapped DEK
	envHeadFixed = 8 + 2 + 4 + 2                        // magic..wrapped length, before the wrapped DEK
)

// EnvRep is the representation a file carries.
type EnvRep byte

const (
	RepIVF  EnvRep = 1
	RepWebM EnvRep = 2
)

func (r EnvRep) ext() string {
	switch r {
	case RepIVF:
		return "ivf"
	case RepWebM:
		return "webm"
	}
	return ""
}

var (
	ErrEnvelopeFormat   = errors.New("recording envelope: malformed or unsupported header")
	ErrEnvelopeAuth     = errors.New("recording envelope: authentication failed")
	ErrEnvelopeTruncate = errors.New("recording envelope: file is truncated or has trailing bytes")
	ErrEnvelopeKey      = errors.New("recording envelope: key unavailable or wrapped key invalid")
	ErrEnvelopeOverflow = errors.New("recording envelope: more plaintext than the header declares")
	ErrEnvelopeRange    = errors.New("recording envelope: range outside the plaintext")
	ErrEnvelopeShort    = errors.New("recording envelope: fewer plaintext bytes than the header declares")
	ErrEnvelopeDirty    = errors.New("recording envelope: unacknowledged frames follow the committed offset; restart the segment under a fresh nonce prefix")
)

// ---- keyring ----------------------------------------------------------------------------------

// RecordingKeyring holds the master keys (KEKs). Exactly one is current (used to wrap new DEKs); older
// ones stay loadable until no envelope depends on them (rotation re-wraps, then retires them).
type RecordingKeyring struct {
	current uint32
	keys    map[uint32][32]byte
}

// NewRecordingKeyring builds a keyring. Keys must be 32 bytes and not all zero (a placeholder).
func NewRecordingKeyring(currentID uint32, current []byte, previous map[uint32][]byte) (*RecordingKeyring, error) {
	k := &RecordingKeyring{current: currentID, keys: map[uint32][32]byte{}}
	add := func(id uint32, b []byte) error {
		if len(b) != 32 {
			return fmt.Errorf("recording master key %d must be 32 bytes", id)
		}
		if isAllZeroBytes(b) {
			return fmt.Errorf("recording master key %d is all zeros — a placeholder, not a key", id)
		}
		if _, dup := k.keys[id]; dup {
			return fmt.Errorf("recording master key id %d configured twice", id)
		}
		var a [32]byte
		copy(a[:], b)
		k.keys[id] = a
		return nil
	}
	if currentID == 0 {
		return nil, errors.New("recording master key id must be non-zero")
	}
	if err := add(currentID, current); err != nil {
		return nil, err
	}
	for id, b := range previous {
		if id == 0 {
			return nil, errors.New("recording master key id must be non-zero")
		}
		if err := add(id, b); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// RecordingKeyringFromEnv reads RECORDING_MASTER_KEY (hex, 64 chars), RECORDING_MASTER_KEY_ID (default
// 1) and RECORDING_MASTER_KEY_PREVIOUS ("id:hexkey,id:hexkey"). Unset RECORDING_MASTER_KEY returns
// (nil, nil): central recording storage is then simply not mounted. This is deliberately a separate
// secret from GRANT_ISSUER_SEED and TOTP_ENCRYPTION_KEY — losing it loses every recording.
func RecordingKeyringFromEnv(getenv func(string) string) (*RecordingKeyring, error) {
	hexKey := strings.TrimSpace(getenv("RECORDING_MASTER_KEY"))
	if hexKey == "" {
		return nil, nil
	}
	cur, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("RECORDING_MASTER_KEY must be hex (generate one with: openssl rand -hex 32)")
	}
	id := uint32(1)
	if v := strings.TrimSpace(getenv("RECORDING_MASTER_KEY_ID")); v != "" {
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil || n == 0 {
			return nil, errors.New("RECORDING_MASTER_KEY_ID must be a positive integer")
		}
		id = uint32(n)
	}
	prev := map[uint32][]byte{}
	if v := strings.TrimSpace(getenv("RECORDING_MASTER_KEY_PREVIOUS")); v != "" {
		for _, part := range strings.Split(v, ",") {
			kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
			if len(kv) != 2 {
				return nil, errors.New("RECORDING_MASTER_KEY_PREVIOUS must look like id:hexkey,id:hexkey")
			}
			n, perr := strconv.ParseUint(kv[0], 10, 32)
			b, herr := hex.DecodeString(kv[1])
			if perr != nil || herr != nil {
				return nil, errors.New("RECORDING_MASTER_KEY_PREVIOUS has a malformed entry")
			}
			prev[uint32(n)] = b
		}
	}
	return NewRecordingKeyring(id, cur, prev)
}

// CurrentID is the key id new DEKs are wrapped under.
func (k *RecordingKeyring) CurrentID() uint32 { return k.current }

func wrapAAD(tenant, recording [16]byte, keyID uint32) []byte {
	aad := make([]byte, 0, 36)
	aad = append(aad, tenant[:]...)
	aad = append(aad, recording[:]...)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], keyID)
	return append(aad, b[:]...)
}

// NewDEK generates a fresh data key and returns it wrapped under the current master key.
func (k *RecordingKeyring) NewDEK(tenant, recording [16]byte) (wrapped []byte, keyID uint32, err error) {
	dek := make([]byte, 32)
	if _, err = rand.Read(dek); err != nil {
		return nil, 0, err
	}
	defer zeroBytes(dek)
	kek := k.keys[k.current]
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return nil, 0, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err = rand.Read(nonce); err != nil {
		return nil, 0, err
	}
	wrapped = aead.Seal(nonce, nonce, dek, wrapAAD(tenant, recording, k.current))
	return wrapped, k.current, nil
}

// UnwrapDEK recovers the data key; it fails for a wrong tenant/recording/key id or any tampering.
func (k *RecordingKeyring) UnwrapDEK(wrapped []byte, tenant, recording [16]byte, keyID uint32) ([]byte, error) {
	kek, ok := k.keys[keyID]
	if !ok || len(wrapped) < chacha20poly1305.NonceSizeX+envTagSize {
		return nil, ErrEnvelopeKey
	}
	aead, err := chacha20poly1305.NewX(kek[:])
	if err != nil {
		return nil, ErrEnvelopeKey
	}
	n := chacha20poly1305.NonceSizeX
	dek, err := aead.Open(nil, wrapped[:n], wrapped[n:], wrapAAD(tenant, recording, keyID))
	if err != nil || len(dek) != 32 {
		return nil, ErrEnvelopeKey
	}
	return dek, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---- header -----------------------------------------------------------------------------------

// EnvelopeMeta is what a file is bound to.
type EnvelopeMeta struct {
	TenantID    [16]byte
	RecordingID [16]byte
	Segment     uint32
	Rep         EnvRep
	Generation  uint64
	TotalLen    uint64
}

// EnvelopeKey is the wrapped data key as stored in the database row and in each header.
type EnvelopeKey struct {
	KeyID   uint32
	Wrapped []byte
}

type envHeader struct {
	EnvelopeMeta
	KeyID       uint32
	Wrapped     []byte
	NoncePrefix [16]byte
	FrameCount  uint64
	FrameSize   uint32
}

func envFrameCount(total uint64) uint64 { return (total + EnvFrameSize - 1) / EnvFrameSize }

func (h *envHeader) marshal() []byte {
	b := make([]byte, 0, envHeadFixed+len(h.Wrapped)+envFixedTail)
	b = append(b, envMagic...)
	b = binary.BigEndian.AppendUint16(b, envVersion)
	b = binary.BigEndian.AppendUint32(b, h.KeyID)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Wrapped)))
	b = append(b, h.Wrapped...)
	b = append(b, h.TenantID[:]...)
	b = append(b, h.RecordingID[:]...)
	b = binary.BigEndian.AppendUint32(b, h.Segment)
	b = append(b, byte(h.Rep))
	b = binary.BigEndian.AppendUint64(b, h.Generation)
	b = append(b, h.NoncePrefix[:]...)
	b = binary.BigEndian.AppendUint64(b, h.TotalLen)
	b = binary.BigEndian.AppendUint64(b, h.FrameCount)
	b = binary.BigEndian.AppendUint32(b, h.FrameSize)
	return b
}

func readEnvHeader(r io.ReaderAt) (*envHeader, []byte, error) {
	var head [envHeadFixed]byte
	if _, err := r.ReadAt(head[:], 0); err != nil {
		return nil, nil, ErrEnvelopeFormat
	}
	if string(head[:8]) != envMagic || binary.BigEndian.Uint16(head[8:10]) != envVersion {
		return nil, nil, ErrEnvelopeFormat
	}
	wl := int(binary.BigEndian.Uint16(head[14:16]))
	if wl == 0 || wl > envMaxWrap {
		return nil, nil, ErrEnvelopeFormat
	}
	raw := make([]byte, envHeadFixed+wl+envFixedTail)
	if _, err := r.ReadAt(raw, 0); err != nil {
		return nil, nil, ErrEnvelopeFormat
	}
	h := &envHeader{KeyID: binary.BigEndian.Uint32(raw[10:14])}
	h.Wrapped = append([]byte(nil), raw[envHeadFixed:envHeadFixed+wl]...)
	p := raw[envHeadFixed+wl:]
	copy(h.TenantID[:], p[0:16])
	copy(h.RecordingID[:], p[16:32])
	h.Segment = binary.BigEndian.Uint32(p[32:36])
	h.Rep = EnvRep(p[36])
	h.Generation = binary.BigEndian.Uint64(p[37:45])
	copy(h.NoncePrefix[:], p[45:61])
	h.TotalLen = binary.BigEndian.Uint64(p[61:69])
	h.FrameCount = binary.BigEndian.Uint64(p[69:77])
	h.FrameSize = binary.BigEndian.Uint32(p[77:81])
	if h.Rep != RepIVF && h.Rep != RepWebM {
		return nil, nil, ErrEnvelopeFormat
	}
	if h.FrameSize != EnvFrameSize || h.TotalLen == 0 || h.TotalLen > envMaxTotal || h.FrameCount != envFrameCount(h.TotalLen) {
		return nil, nil, ErrEnvelopeFormat
	}
	return h, raw, nil
}

func (h *envHeader) hdrLen() int64 { return int64(envHeadFixed + len(h.Wrapped) + envFixedTail) }

// EnvelopeDiskSize is the exact size of a complete file for total plaintext bytes and a wrapped DEK
// of wrappedLen bytes.
func EnvelopeDiskSize(total uint64, wrappedLen int) int64 {
	return int64(envHeadFixed+wrappedLen+envFixedTail) + int64(total) + int64(envFrameCount(total))*envTagSize
}

// envelopeDiskBound is the size EnvelopeDiskSize gives with the standard wrapped DEK (72 bytes); used
// for reservations.
const stdWrappedDEKLen = chacha20poly1305.NonceSizeX + 32 + envTagSize

func (h *envHeader) frameLen(idx uint64) int {
	if idx+1 < h.FrameCount {
		return EnvFrameSize
	}
	return int(h.TotalLen - idx*EnvFrameSize)
}

func (h *envHeader) framePos(idx uint64) int64 {
	return h.hdrLen() + int64(idx)*(EnvFrameSize+envTagSize)
}

type envCrypt struct {
	hdr     *envHeader
	hdrHash [32]byte
	aead    interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
}

func newEnvCrypt(h *envHeader, raw []byte, dek []byte) (*envCrypt, error) {
	a, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, ErrEnvelopeKey
	}
	return &envCrypt{hdr: h, hdrHash: sha256.Sum256(raw), aead: a}, nil
}

func (c *envCrypt) nonceAAD(idx uint64) (nonce [24]byte, aad [32 + 8 + 4 + 1]byte) {
	copy(nonce[:16], c.hdr.NoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[16:], idx)
	copy(aad[:32], c.hdrHash[:])
	binary.BigEndian.PutUint64(aad[32:40], idx)
	binary.BigEndian.PutUint32(aad[40:44], uint32(c.hdr.frameLen(idx)))
	if idx+1 == c.hdr.FrameCount {
		aad[44] = 1
	}
	return
}

func (c *envCrypt) seal(idx uint64, plain []byte) []byte {
	n, a := c.nonceAAD(idx)
	return c.aead.Seal(nil, n[:], plain, a[:])
}

func (c *envCrypt) open(idx uint64, ct []byte) ([]byte, error) {
	n, a := c.nonceAAD(idx)
	pt, err := c.aead.Open(nil, n[:], ct, a[:])
	if err != nil {
		return nil, ErrEnvelopeAuth
	}
	return pt, nil
}

// ---- writer -----------------------------------------------------------------------------------

// EnvFile is the file surface the envelope needs; *os.File satisfies it.
type EnvFile interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	Sync() error
}

// EnvelopeWriter writes a file's plaintext, which must total exactly meta.TotalLen. Write is an
// io.Writer: it buffers to frame boundaries and emits each frame when complete. The caller fsyncs with
// Sync before acknowledging bytes.
type EnvelopeWriter struct {
	f    EnvFile
	c    *envCrypt
	buf  []byte
	idx  uint64 // next frame to emit
	done uint64 // plaintext bytes accepted (emitted + buffered)
}

func (k *RecordingKeyring) dekFor(key EnvelopeKey, meta EnvelopeMeta) ([]byte, error) {
	return k.UnwrapDEK(key.Wrapped, meta.TenantID, meta.RecordingID, key.KeyID)
}

// CreateEnvelope starts a new file: writes the header (with a fresh random nonce prefix) at offset 0.
func CreateEnvelope(f EnvFile, keys *RecordingKeyring, key EnvelopeKey, meta EnvelopeMeta) (*EnvelopeWriter, error) {
	if meta.TotalLen == 0 || meta.TotalLen > envMaxTotal || (meta.Rep != RepIVF && meta.Rep != RepWebM) {
		return nil, ErrEnvelopeFormat
	}
	dek, err := keys.dekFor(key, meta)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	h := &envHeader{EnvelopeMeta: meta, KeyID: key.KeyID, Wrapped: append([]byte(nil), key.Wrapped...),
		FrameCount: envFrameCount(meta.TotalLen), FrameSize: EnvFrameSize}
	if _, err := rand.Read(h.NoncePrefix[:]); err != nil {
		return nil, err
	}
	raw := h.marshal()
	c, err := newEnvCrypt(h, raw, dek)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		return nil, err
	}
	if _, err := f.WriteAt(raw, 0); err != nil {
		return nil, err
	}
	return &EnvelopeWriter{f: f, c: c}, nil
}

// ResumeEnvelope continues a partially written file at a plaintext offset that is a whole number of
// frames (or the total). The header on disk must be exactly the one this meta+key would describe, and
// the file must hold exactly the committed frames: nothing beyond them.
//
// Bytes beyond the committed frames (written and fsynced, never acknowledged) are REFUSED with
// ErrEnvelopeDirty and left untouched; they are never truncated away and overwritten. Frame index i
// under one (DEK, nonce prefix) must only ever be sealed once: the unacknowledged frames are already
// exposed on disk, and a resumed writer re-sealing the same index with different plaintext would reuse
// the XChaCha20 nonce (a two-time pad). The caller starts the segment over instead: CreateEnvelope
// truncates the file and draws a fresh prefix, so every re-written frame has a fresh nonce.
func ResumeEnvelope(f EnvFile, keys *RecordingKeyring, key EnvelopeKey, meta EnvelopeMeta, committed uint64) (*EnvelopeWriter, error) {
	h, raw, err := readEnvHeader(f)
	if err != nil {
		return nil, err
	}
	if h.EnvelopeMeta != meta || h.KeyID != key.KeyID || !bytes.Equal(h.Wrapped, key.Wrapped) {
		return nil, ErrEnvelopeFormat
	}
	if committed > meta.TotalLen || (committed%EnvFrameSize != 0 && committed != meta.TotalLen) {
		return nil, ErrEnvelopeRange
	}
	dek, err := keys.dekFor(key, meta)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	c, err := newEnvCrypt(h, raw, dek)
	if err != nil {
		return nil, err
	}
	frames := envFrameCount(committed)
	end := h.hdrLen() + int64(committed) + int64(frames)*envTagSize
	// The file must already hold every committed frame; extra bytes beyond are unacknowledged.
	var probe [1]byte
	if end > h.hdrLen() {
		if _, err := f.ReadAt(probe[:], end-1); err != nil {
			return nil, ErrEnvelopeTruncate
		}
	}
	var tail [1]byte
	if n, _ := f.ReadAt(tail[:], end); n > 0 {
		return nil, ErrEnvelopeDirty
	}
	return &EnvelopeWriter{f: f, c: c, idx: frames, done: committed}, nil
}

// Write accepts plaintext. It fails (consuming nothing) if it would exceed the declared total.
func (w *EnvelopeWriter) Write(p []byte) (int, error) {
	if w.done+uint64(len(p)) > w.c.hdr.TotalLen {
		return 0, ErrEnvelopeOverflow
	}
	w.buf = append(w.buf, p...)
	w.done += uint64(len(p))
	for w.idx < w.c.hdr.FrameCount {
		need := w.c.hdr.frameLen(w.idx)
		if len(w.buf) < need {
			break
		}
		ct := w.c.seal(w.idx, w.buf[:need])
		if _, err := w.f.WriteAt(ct, w.c.hdr.framePos(w.idx)); err != nil {
			return 0, err
		}
		w.buf = w.buf[need:]
		w.idx++
	}
	return len(p), nil
}

// Buffered is the number of accepted bytes not yet emitted as a frame. A chunk that ends on a frame
// boundary, or completes the declared total, leaves it zero.
func (w *EnvelopeWriter) Buffered() int { return len(w.buf) }

// Accepted is the plaintext byte count accepted so far.
func (w *EnvelopeWriter) Accepted() uint64 { return w.done }

// Sync fsyncs the file.
func (w *EnvelopeWriter) Sync() error { return w.f.Sync() }

// Close verifies the declared length was written in full (it never closes the file) and fsyncs.
func (w *EnvelopeWriter) Close() error {
	if w.done != w.c.hdr.TotalLen || w.idx != w.c.hdr.FrameCount || len(w.buf) != 0 {
		return ErrEnvelopeShort
	}
	return w.f.Sync()
}

// ---- reader -----------------------------------------------------------------------------------

// EnvelopeExpect is what the caller requires the header to say. Generation 0 means "any".
type EnvelopeExpect struct {
	TenantID    [16]byte
	RecordingID [16]byte
	Segment     uint32
	Rep         EnvRep
	Generation  uint64
}

// EnvelopeReader reads an envelope. Open it with OpenEnvelope.
type EnvelopeReader struct {
	f io.ReaderAt
	c *envCrypt
}

// OpenEnvelope validates the header against expect, unwraps the DEK, and — unless allowPartial —
// requires the file to be exactly the size the authenticated header implies (so a truncated or
// extended file is refused before a single frame is trusted). size is the file's size.
func OpenEnvelope(f io.ReaderAt, size int64, keys *RecordingKeyring, expect EnvelopeExpect, allowPartial bool) (*EnvelopeReader, error) {
	h, raw, err := readEnvHeader(f)
	if err != nil {
		return nil, err
	}
	if h.TenantID != expect.TenantID || h.RecordingID != expect.RecordingID || h.Segment != expect.Segment ||
		h.Rep != expect.Rep || (expect.Generation != 0 && h.Generation != expect.Generation) {
		return nil, ErrEnvelopeFormat
	}
	dek, err := keys.UnwrapDEK(h.Wrapped, h.TenantID, h.RecordingID, h.KeyID)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	c, err := newEnvCrypt(h, raw, dek)
	if err != nil {
		return nil, err
	}
	want := EnvelopeDiskSize(h.TotalLen, len(h.Wrapped))
	if !allowPartial && size != want {
		return nil, ErrEnvelopeTruncate
	}
	if allowPartial && size > want {
		return nil, ErrEnvelopeTruncate
	}
	return &EnvelopeReader{f: f, c: c}, nil
}

// Meta returns what the (authenticated-on-first-frame) header declares.
func (r *EnvelopeReader) Meta() EnvelopeMeta { return r.c.hdr.EnvelopeMeta }

// Len is the total plaintext length.
func (r *EnvelopeReader) Len() int64 { return int64(r.c.hdr.TotalLen) }

func (r *EnvelopeReader) frame(idx uint64) ([]byte, error) {
	h := r.c.hdr
	if idx >= h.FrameCount { // checked against the AUTHENTICATED count, not the file size
		return nil, ErrEnvelopeRange
	}
	ct := make([]byte, h.frameLen(idx)+envTagSize)
	if _, err := r.f.ReadAt(ct, h.framePos(idx)); err != nil {
		return nil, ErrEnvelopeTruncate
	}
	return r.c.open(idx, ct)
}

// EnvMaxReadRange bounds one ReadRange call: it returns the range in a single slice, so an unbounded n
// (up to the 8 GiB an envelope may hold) would be an unbounded allocation. Callers stream larger spans in
// chunks (the playback route reads 256 KiB at a time; the upload re-send check reads one 1 MiB chunk).
const EnvMaxReadRange = 8 << 20

// ReadRange returns plaintext [off, off+n). The range must lie inside the plaintext and be at most
// EnvMaxReadRange bytes; nothing is allocated before both are checked.
func (r *EnvelopeReader) ReadRange(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > r.Len() || n > r.Len()-off || n > EnvMaxReadRange {
		return nil, ErrEnvelopeRange
	}
	out := make([]byte, 0, n)
	for n > 0 {
		idx := uint64(off) / EnvFrameSize
		pt, err := r.frame(idx)
		if err != nil {
			return nil, err
		}
		in := int(off - int64(idx)*EnvFrameSize)
		take := len(pt) - in
		if int64(take) > n {
			take = int(n)
		}
		out = append(out, pt[in:in+take]...)
		off += int64(take)
		n -= int64(take)
	}
	return out, nil
}

// WriteTo decrypts the whole file in order into dst. Every frame (including the final one) must
// authenticate; with a size-checked open that also proves exact EOF.
func (r *EnvelopeReader) WriteTo(dst io.Writer) (int64, error) {
	var total int64
	for idx := uint64(0); idx < r.c.hdr.FrameCount; idx++ {
		pt, err := r.frame(idx)
		if err != nil {
			return total, err
		}
		n, err := dst.Write(pt)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Disk-floor bounds (docs/63 C11, docs/20 §15). The recordings volume shares the root filesystem with
// Postgres on the reference host, so the floor is what keeps a burst of uploads from starving the
// database of space. Below the minimum a floor protects nothing; above the maximum it is almost
// certainly a unit mistake (bytes typed as MiB) that would refuse every upload for ever.
const (
	RecordingDefaultFloorBytes = uint64(5) << 30
	RecordingMinFloorMiB       = 512
	RecordingMaxFloorMiB       = 1 << 20 // 1 TiB
)

// RecordingFloorFromEnv parses the value of RECORDING_DISK_FLOOR_MIB (whole MiB; the caller passes
// os.Getenv("RECORDING_DISK_FLOOR_MIB") so the compose guard sees the variable name). Empty or unset means the built-in
// default (5 GiB). Anything else that is not an integer inside [512, 1048576] is an ERROR the caller must
// treat as fatal at startup: a mistyped floor must never silently fall back to a different number.
func RecordingFloorFromEnv(raw string) (uint64, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return RecordingDefaultFloorBytes, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	// The message names the variable and the bounds only: the raw value is operator input of unknown
	// provenance (a pasted secret in the wrong variable) and startup errors land in logs.
	if err != nil || n < RecordingMinFloorMiB || n > RecordingMaxFloorMiB {
		return 0, fmt.Errorf("RECORDING_DISK_FLOOR_MIB must be a whole number of MiB between %d and %d (empty = the default, 5120)",
			RecordingMinFloorMiB, RecordingMaxFloorMiB)
	}
	return n << 20, nil
}
