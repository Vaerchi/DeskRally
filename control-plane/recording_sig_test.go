package controlplane

// RMTAGENTUPLOADv1 golden vectors (docs/63 §2a C1). The vectors live in testdata/ as JSON so the Rust
// agent (R2) loads THE SAME FILE: the file is the contract, this test is one of its two readers.
//
// Regenerate (only when the format deliberately changes, which also means a version bump):
//
//	RECORDING_VECTORS_UPDATE=1 go test -run TestRecordingUploadGoldenVectors ./...

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const recVectorsFile = "testdata/recording_upload_v1_vectors.json"

type vecFields struct {
	Audience    string `json:"audience"`
	Operation   string `json:"operation"`
	OpCode      int    `json:"op_code"`
	Path        string `json:"path"`
	TenantID    string `json:"tenant_id"`
	DeviceID    string `json:"device_id"`
	KeyFP       string `json:"key_fingerprint_hex"`
	RecordingID string `json:"recording_id"`
	Generation  uint64 `json:"generation"`
	Segment     uint32 `json:"segment"`
	Offset      uint64 `json:"offset"`
	BodyLength  uint64 `json:"body_length"`
	BodySHA256  string `json:"body_sha256_hex"`
	TimestampMs uint64 `json:"timestamp_ms"`
}

type vecPositive struct {
	Name        string    `json:"name"`
	Fields      vecFields `json:"fields"`
	PreimageHex string    `json:"preimage_hex"`
	SignatureHx string    `json:"signature_hex"`
}

type vecNegative struct {
	Name         string    `json:"name"`
	Base         string    `json:"base"`
	Changed      string    `json:"changed"`
	Fields       vecFields `json:"fields"`
	PreimageHex  string    `json:"preimage_hex"`
	SignatureHex string    `json:"signature_hex"`
	ExpectVerify bool      `json:"expect_verify"`
}

type vecWindowCase struct {
	NowMs       int64  `json:"now_ms"`
	TimestampMs uint64 `json:"timestamp_ms"`
	Accept      bool   `json:"accept"`
}

type vecFile struct {
	Format     string          `json:"format"`
	Notes      []string        `json:"notes"`
	SeedHex    string          `json:"seed_hex"`
	PublicHex  string          `json:"public_hex"`
	KeyFPHex   string          `json:"key_fingerprint_hex"`
	Positive   []vecPositive   `json:"vectors"`
	Negative   []vecNegative   `json:"negative_vectors"`
	WindowMs   int64           `json:"window_ms"`
	WindowCase []vecWindowCase `json:"window_cases"`
}

func (v vecFields) toSig(t *testing.T) UploadSigFields {
	t.Helper()
	var f UploadSigFields
	f.Audience, f.Path, f.DeviceID = v.Audience, v.Path, v.DeviceID
	f.Op = UploadOp(v.OpCode)
	var ok bool
	if f.TenantID, ok = recParseUUID(v.TenantID); !ok {
		t.Fatalf("bad tenant %q", v.TenantID)
	}
	if f.RecordingID, ok = recParseUUID(v.RecordingID); !ok {
		t.Fatalf("bad recording %q", v.RecordingID)
	}
	if !decodeFixedHex(f.KeyFP[:], v.KeyFP) || !decodeFixedHex(f.BodySHA256[:], v.BodySHA256) {
		t.Fatal("bad hex in vector")
	}
	f.Generation, f.Segment, f.Offset, f.BodyLen, f.TimestampMs = v.Generation, v.Segment, v.Offset, v.BodyLength, v.TimestampMs
	return f
}

func vecFromSig(f UploadSigFields) vecFields {
	names := map[UploadOp]string{UploadOpCreate: "create", UploadOpPut: "put", UploadOpHead: "head", UploadOpFinish: "finish"}
	return vecFields{
		Audience: f.Audience, Operation: names[f.Op], OpCode: int(f.Op), Path: f.Path,
		TenantID: recFormatUUID(f.TenantID), DeviceID: f.DeviceID, KeyFP: hex.EncodeToString(f.KeyFP[:]),
		RecordingID: recFormatUUID(f.RecordingID), Generation: f.Generation, Segment: f.Segment,
		Offset: f.Offset, BodyLength: f.BodyLen, BodySHA256: hex.EncodeToString(f.BodySHA256[:]),
		TimestampMs: f.TimestampMs,
	}
}

func goldenKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func sha32(s string) [32]byte { return sha256.Sum256([]byte(s)) }

const (
	goldenTenant = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	goldenRec    = "f0e1d2c3-b4a5-4968-8776-655443322110"
)

func goldenBase(t *testing.T, key ed25519.PrivateKey) UploadSigFields {
	t.Helper()
	tn, _ := recParseUUID(goldenTenant)
	rc, _ := recParseUUID(goldenRec)
	return UploadSigFields{
		Audience: "https://main.deskrally.example", Op: UploadOpPut,
		Path:     "/agent/recordings/" + goldenRec + "/segments/2",
		TenantID: tn, DeviceID: "dev-0001", KeyFP: UploadKeyFingerprint(key.Public().(ed25519.PublicKey)),
		RecordingID: rc, Generation: 1, Segment: 2, Offset: 2097152, BodyLen: 1048576,
		BodySHA256: sha32("chunk-2"), TimestampMs: 1790000000000,
	}
}

func buildGoldenFile(t *testing.T) vecFile {
	t.Helper()
	key := goldenKey()
	pub := key.Public().(ed25519.PublicKey)
	base := goldenBase(t, key)

	mk := func(name string, f UploadSigFields) vecPositive {
		return vecPositive{Name: name, Fields: vecFromSig(f), PreimageHex: hex.EncodeToString(UploadPreimage(f)),
			SignatureHx: hex.EncodeToString(SignUpload(key, f))}
	}
	create := base
	create.Op, create.Path, create.Segment, create.Offset = UploadOpCreate, "/agent/recordings", 0, 0
	create.BodyLen, create.BodySHA256 = 311, sha32(`{"create":"body"}`)
	head := base
	head.Op, head.Offset, head.BodyLen, head.BodySHA256 = UploadOpHead, 0, 0, sha32("")
	finish := base
	finish.Op, finish.Path, finish.Segment, finish.Offset = UploadOpFinish, "/agent/recordings/"+goldenRec+"/finish", 0, 0
	finish.BodyLen, finish.BodySHA256 = 905, sha32(`{"finish":"body"}`)
	utf := base
	utf.DeviceID, utf.Audience, utf.Generation = "dev-é-ΩΩ", "https://rmt.example.org:8443", 7
	utf.TimestampMs = 1790000000001

	pos := []vecPositive{
		mk("create", create), mk("put-seg2", base), mk("head", head), mk("finish", finish), mk("put-utf8-device", utf),
	}

	var neg []vecNegative
	baseSig := hex.EncodeToString(SignUpload(key, base))
	addNeg := func(changed string, f UploadSigFields) {
		neg = append(neg, vecNegative{
			Name: "put-seg2 with " + changed + " changed", Base: "put-seg2", Changed: changed,
			Fields: vecFromSig(f), PreimageHex: hex.EncodeToString(UploadPreimage(f)), SignatureHex: baseSig,
			ExpectVerify: false,
		})
	}
	m := base
	m.Audience = "https://other.deskrally.example"
	addNeg("audience", m)
	m = base
	m.Op = UploadOpHead
	addNeg("operation", m)
	m = base
	m.Path = "/agent/recordings/" + goldenRec + "/segments/3"
	addNeg("path", m)
	m = base
	m.TenantID[15] ^= 1
	addNeg("tenant_id", m)
	m = base
	m.DeviceID = "dev-0002"
	addNeg("device_id", m)
	m = base
	m.KeyFP[0] ^= 1
	addNeg("key_fingerprint", m)
	m = base
	m.RecordingID[0] ^= 1
	addNeg("recording_id", m)
	m = base
	m.Generation = 2
	addNeg("generation", m)
	m = base
	m.Segment = 3
	addNeg("segment", m)
	m = base
	m.Offset += 1048576
	addNeg("offset", m)
	m = base
	m.BodyLen--
	addNeg("body_length", m)
	m = base
	m.BodySHA256[31] ^= 1
	addNeg("body_sha256", m)
	m = base
	m.TimestampMs++
	addNeg("timestamp", m)

	// domain tag and version are constants of the format, so they are mutated at the byte level.
	pre := UploadPreimage(base)
	dom := append([]byte(nil), pre...)
	dom[4] ^= 1 // first byte of the domain tag (after its 4-byte length)
	ver := append([]byte(nil), pre...)
	ver[4+len(UploadSigDomain)+4+3] ^= 1 // the version u32's low byte
	for _, c := range []struct {
		name string
		p    []byte
	}{{"domain_tag", dom}, {"version", ver}} {
		neg = append(neg, vecNegative{
			Name: "put-seg2 with " + c.name + " changed", Base: "put-seg2", Changed: c.name,
			Fields: vecFromSig(base), PreimageHex: hex.EncodeToString(c.p), SignatureHex: baseSig, ExpectVerify: false,
		})
	}
	// Signature-shape negatives: right preimage, wrong signature.
	flipped, _ := hex.DecodeString(baseSig)
	flipped[0] ^= 1
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	neg = append(neg,
		vecNegative{Name: "put-seg2 with a bit-flipped signature", Base: "put-seg2", Changed: "signature_bitflip",
			Fields: vecFromSig(base), PreimageHex: hex.EncodeToString(pre), SignatureHex: hex.EncodeToString(flipped), ExpectVerify: false},
		vecNegative{Name: "put-seg2 signed by a different key", Base: "put-seg2", Changed: "signer",
			Fields: vecFromSig(base), PreimageHex: hex.EncodeToString(pre),
			SignatureHex: hex.EncodeToString(SignUpload(other, base)), ExpectVerify: false},
		vecNegative{Name: "put-seg2 with a truncated signature", Base: "put-seg2", Changed: "signature_length",
			Fields: vecFromSig(base), PreimageHex: hex.EncodeToString(pre), SignatureHex: baseSig[:126], ExpectVerify: false},
	)

	now := int64(1790000000000)
	var win []vecWindowCase
	for _, d := range []int64{0, 1, -1, UploadSigWindowMs - 1, -(UploadSigWindowMs - 1), UploadSigWindowMs, -UploadSigWindowMs,
		UploadSigWindowMs + 1, -(UploadSigWindowMs + 1), 3600000, -3600000} {
		win = append(win, vecWindowCase{NowMs: now, TimestampMs: uint64(now + d), Accept: d <= UploadSigWindowMs && d >= -UploadSigWindowMs})
	}
	win = append(win, vecWindowCase{NowMs: now, TimestampMs: 0, Accept: false})

	return vecFile{
		Format: UploadSigDomain,
		Notes: []string{
			"Preimage = concatenation of 15 length-prefixed elements (u32 big-endian length, then bytes); see control-plane/recording_sig.go.",
			"Integers inside elements are big-endian: version u32, generation u64, segment u32, offset u64, body_length u64, timestamp u64.",
			"The signed message is the preimage itself; the signature is Ed25519 (RFC 8032) by the agent's enrolled key.",
			"path is the path as the control plane sees it, WITHOUT any reverse-proxy prefix such as /cp.",
			"Negative vectors: signature_hex is the BASE vector's signature; verification of preimage_hex under it MUST fail.",
			"window_cases: a timestamp is accepted iff |timestamp_ms - now_ms| <= window_ms and timestamp_ms != 0.",
		},
		SeedHex: hex.EncodeToString(key.Seed()), PublicHex: hex.EncodeToString(pub),
		KeyFPHex: hex.EncodeToString(base.KeyFP[:]),
		Positive: pos, Negative: neg, WindowMs: UploadSigWindowMs, WindowCase: win,
	}
}

func TestRecordingUploadGoldenVectors(t *testing.T) {
	want, err := json.MarshalIndent(buildGoldenFile(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv("RECORDING_VECTORS_UPDATE") == "1" {
		if err := os.WriteFile(filepath.FromSlash(recVectorsFile), want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.FromSlash(recVectorsFile))
	if err != nil {
		t.Fatalf("read vectors: %v (generate with RECORDING_VECTORS_UPDATE=1)", err)
	}
	// Normalise CRLF so a Windows checkout with autocrlf compares equal.
	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("the committed vector file differs from what the code produces — the wire format changed. " +
			"If that is deliberate it needs a version bump and the Rust twin; regenerate with RECORDING_VECTORS_UPDATE=1")
	}

	// Now consume the FILE exactly as the Rust reader will: nothing is taken from the generator.
	var vf vecFile
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(vf.PublicHex)
	for _, p := range vf.Positive {
		f := p.Fields.toSig(t)
		if hex.EncodeToString(UploadPreimage(f)) != p.PreimageHex {
			t.Errorf("%s: preimage mismatch", p.Name)
		}
		sig, _ := hex.DecodeString(p.SignatureHx)
		if !VerifyUploadSignature(pub, f, sig) {
			t.Errorf("%s: signature does not verify", p.Name)
		}
	}
	for _, n := range vf.Negative {
		pre, _ := hex.DecodeString(n.PreimageHex)
		sig, _ := hex.DecodeString(n.SignatureHex)
		if len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, pre, sig) {
			t.Errorf("%s: verified but must not", n.Name)
		}
		if n.Changed != "domain_tag" && n.Changed != "version" && n.Changed != "signature_bitflip" &&
			n.Changed != "signer" && n.Changed != "signature_length" {
			f := n.Fields.toSig(t)
			if VerifyUploadSignature(pub, f, sig) {
				t.Errorf("%s: field-level verify passed but must not", n.Name)
			}
		}
	}
	for _, c := range vf.WindowCase {
		if UploadTimestampOK(c.NowMs, c.TimestampMs) != c.Accept {
			t.Errorf("window case %+v", c)
		}
	}
	// Every field of the preimage is covered by at least one negative vector.
	seen := map[string]bool{}
	for _, n := range vf.Negative {
		seen[n.Changed] = true
	}
	for _, f := range []string{"audience", "operation", "path", "tenant_id", "device_id", "key_fingerprint", "recording_id",
		"generation", "segment", "offset", "body_length", "body_sha256", "timestamp", "domain_tag", "version"} {
		if !seen[f] {
			t.Errorf("no negative vector for %s", f)
		}
	}
}

// A preimage with different field SPLITS but the same concatenated bytes must differ: this is what the
// length prefixes buy.
func TestRecordingUploadPreimageHasNoSplitAmbiguity(t *testing.T) {
	key := goldenKey()
	a := goldenBase(t, key)
	b := a
	a.DeviceID, a.Audience = "ab", "c"
	b.DeviceID, b.Audience = "a", "bc"
	if bytes.Equal(UploadPreimage(a), UploadPreimage(b)) {
		t.Fatal("shifting bytes between adjacent fields produced the same preimage")
	}
}

// ---- header parsing ---------------------------------------------------------------------------

func goldenRequest(t *testing.T, f UploadSigFields, key ed25519.PrivateKey) *http.Request {
	t.Helper()
	r := httptest.NewRequest(map[UploadOp]string{UploadOpCreate: "POST", UploadOpPut: "PUT", UploadOpHead: "HEAD", UploadOpFinish: "POST"}[f.Op], f.Path, nil)
	r.Header.Set(HdrUploadDevice, f.DeviceID)
	r.Header.Set(HdrUploadTenant, recFormatUUID(f.TenantID))
	r.Header.Set(HdrUploadKeyFP, hex.EncodeToString(f.KeyFP[:]))
	r.Header.Set(HdrUploadRecording, recFormatUUID(f.RecordingID))
	r.Header.Set(HdrUploadGen, strconv.FormatUint(f.Generation, 10))
	r.Header.Set(HdrUploadSegment, strconv.FormatUint(uint64(f.Segment), 10))
	r.Header.Set(HdrUploadOffset, strconv.FormatUint(f.Offset, 10))
	r.Header.Set(HdrUploadBodySHA, hex.EncodeToString(f.BodySHA256[:]))
	r.Header.Set(HdrUploadTimestamp, strconv.FormatUint(f.TimestampMs, 10))
	r.Header.Set(HdrUploadSignature, hex.EncodeToString(SignUpload(key, f)))
	r.ContentLength = int64(f.BodyLen)
	return r
}

func TestParseUploadRequestRoundTripAndRefusals(t *testing.T) {
	key := goldenKey()
	f := goldenBase(t, key)
	r := goldenRequest(t, f, key)
	p, err := ParseUploadRequest(r, UploadOpPut, f.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if p.Fields != f {
		t.Fatalf("parsed fields differ:\n got %+v\nwant %+v", p.Fields, f)
	}
	if !VerifyUploadSignature(key.Public().(ed25519.PublicKey), p.Fields, p.Signature) {
		t.Fatal("parsed request does not verify")
	}

	bad := map[string]func(r *http.Request){
		"query string":           func(r *http.Request) { r.URL.RawQuery = "offset=1" },
		"force query":            func(r *http.Request) { r.URL.ForceQuery = true },
		"escaped path":           func(r *http.Request) { r.URL.RawPath = "/agent/recordings/%66" },
		"different path":         func(r *http.Request) { r.URL.Path = "/agent/recordings/" + goldenRec + "/segments/02" },
		"upper-case recording":   func(r *http.Request) { r.Header.Set(HdrUploadRecording, "F0E1D2C3-B4A5-4968-8776-655443322110") },
		"dashless tenant":        func(r *http.Request) { r.Header.Set(HdrUploadTenant, "0a1b2c3d4e5f4a6b8c7d9e0f1a2b3c4d") },
		"duplicate header":       func(r *http.Request) { r.Header.Add(HdrUploadDevice, "dev-0001") },
		"missing header":         func(r *http.Request) { r.Header.Del(HdrUploadSignature) },
		"empty header":           func(r *http.Request) { r.Header.Set(HdrUploadGen, "") },
		"leading zero number":    func(r *http.Request) { r.Header.Set(HdrUploadOffset, "02097152") },
		"signed number":          func(r *http.Request) { r.Header.Set(HdrUploadOffset, "+2097152") },
		"zero generation":        func(r *http.Request) { r.Header.Set(HdrUploadGen, "0") },
		"upper-case body hash":   func(r *http.Request) { r.Header.Set(HdrUploadBodySHA, "AB"+hex.EncodeToString(f.BodySHA256[:])[2:]) },
		"short signature":        func(r *http.Request) { r.Header.Set(HdrUploadSignature, "00") },
		"control char in device": func(r *http.Request) { r.Header.Set(HdrUploadDevice, "dev\x01") },
		"duplicate content-len":  func(r *http.Request) { r.Header.Add("Content-Length", "1"); r.Header.Add("Content-Length", "2") },
	}
	for name, mut := range bad {
		r := goldenRequest(t, f, key)
		mut(r)
		if _, err := ParseUploadRequest(r, UploadOpPut, f.Audience); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unused fields must be zero: a create with a segment, a head with an offset.
	cf := f
	cf.Op, cf.Path, cf.Segment, cf.Offset = UploadOpCreate, "/agent/recordings", 0, 0
	r = goldenRequest(t, cf, key)
	r.Header.Set(HdrUploadSegment, "1")
	if _, err := ParseUploadRequest(r, UploadOpCreate, f.Audience); err == nil {
		t.Error("create with a segment accepted")
	}
	hf := f
	hf.Op, hf.Offset = UploadOpHead, 0
	r = goldenRequest(t, hf, key)
	r.Header.Set(HdrUploadOffset, "1")
	if _, err := ParseUploadRequest(r, UploadOpHead, f.Audience); err == nil {
		t.Error("head with an offset accepted")
	}
	// A request for one op cannot be parsed as another (the path is derived from the op).
	if _, err := ParseUploadRequest(goldenRequest(t, f, key), UploadOpFinish, f.Audience); err == nil {
		t.Error("put request parsed as finish")
	}
}

func TestUploadTimestampWindow(t *testing.T) {
	now := int64(1790000000000)
	if !UploadTimestampOK(now, uint64(now+UploadSigWindowMs)) || !UploadTimestampOK(now, uint64(now-UploadSigWindowMs)) {
		t.Fatal("window edges must be accepted")
	}
	if UploadTimestampOK(now, uint64(now+UploadSigWindowMs+1)) || UploadTimestampOK(now, uint64(now-UploadSigWindowMs-1)) {
		t.Fatal("outside the window accepted")
	}
	if UploadTimestampOK(now, 0) {
		t.Fatal("zero accepted")
	}
}

func TestNormalizeRecordingAudience(t *testing.T) {
	good := map[string]string{
		"https://main.deskrally.com":     "https://main.deskrally.com",
		"https://Main.DeskRally.com/":    "https://main.deskrally.com",
		"HTTPS://main.deskrally.com:443": "https://main.deskrally.com",
		"https://cp.example.org:8443":    "https://cp.example.org:8443",
		"http://localhost:8081":          "http://localhost:8081",
		"http://127.0.0.1:80":            "http://127.0.0.1",
		"  https://main.deskrally.com  ": "https://main.deskrally.com",
	}
	for in, want := range good {
		if got, err := NormalizeRecordingAudience(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "main.deskrally.com", "https://", "https://u:p@main.example", "https://main.example/cp",
		"https://main.example?x=1", "https://main.example#f", "http://main.example", "ftp://main.example", "https://main.example/a/b"} {
		if got, err := NormalizeRecordingAudience(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
