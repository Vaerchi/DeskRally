package controlplane

// RMTAGENTUPLOADv1 — the signed request an agent presents to the recording upload API (docs/63 §2a C1).
//
// The signature is Ed25519 by the agent's enrolled key over a LENGTH-PREFIXED binary preimage. Every
// field is its own length-prefixed element, so no choice of field values can be re-parsed as a
// different field split (no delimiter ambiguity), and a field that is absent from the preimage is
// absent from the signature — which is why the list below is exhaustive:
//
//	1  domain tag                "RMTAGENTUPLOADv1"
//	2  version                   u32 = 1
//	3  deployment audience       the control plane's public origin (stops a request signed for one
//	                             deployment being replayed at another that pins the same agent key)
//	4  operation                 1 byte: 1 create | 2 put | 3 head | 4 finish
//	5  canonical path            as the CONTROL PLANE sees it (a reverse proxy's /cp prefix is not part of it)
//	6  tenant id                 16 raw bytes
//	7  device id                 UTF-8 text
//	8  enrollment key fingerprint  sha256 of the 32 raw pubkey bytes
//	9  recording id              16 raw bytes
//	10 upload generation         u64
//	11 segment index             u32 (0 for create / finish)
//	12 offset                    u64 (0 except put)
//	13 exact body length         u64
//	14 sha256(body)              32 raw bytes
//	15 timestamp                 u64 unix milliseconds
//
// The signed message is the preimage itself (it already begins with the length-prefixed domain tag, so
// it cannot be confused with the audit signature, whose message starts with "RMT-AUDIT-SIGN-v1").
//
// The Rust agent mirrors this byte for byte; testdata/recording_upload_v1_vectors.json is the shared
// golden fixture, including NEGATIVE vectors (each field changed, so verification must fail).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// UploadSigDomain is the first element of every preimage.
	UploadSigDomain  = "RMTAGENTUPLOADv1"
	uploadSigVersion = uint32(1)

	// UploadSigWindowMs is the accepted clock skew each way (±5 minutes), inclusive.
	UploadSigWindowMs = int64(5 * 60 * 1000)
)

// UploadOp is the signed operation enum. The SERVER derives it from the method and route, so a client
// cannot pick the operation a signature is checked against.
type UploadOp byte

const (
	UploadOpCreate UploadOp = 1
	UploadOpPut    UploadOp = 2
	UploadOpHead   UploadOp = 3
	UploadOpFinish UploadOp = 4
)

func (o UploadOp) valid() bool { return o >= UploadOpCreate && o <= UploadOpFinish }

// Signed-request header names. All of them are mirrored into the preimage; the verifier refuses a
// request that repeats any of them (a duplicate would let two components disagree about which value
// was signed).
const (
	HdrUploadDevice    = "X-Rmt-Device"
	HdrUploadTenant    = "X-Rmt-Tenant"
	HdrUploadKeyFP     = "X-Rmt-Key-Fp"
	HdrUploadRecording = "X-Rmt-Recording"
	HdrUploadGen       = "X-Rmt-Generation"
	HdrUploadSegment   = "X-Rmt-Segment"
	HdrUploadOffset    = "X-Rmt-Offset"
	HdrUploadBodySHA   = "X-Rmt-Body-Sha256"
	HdrUploadTimestamp = "X-Rmt-Timestamp"
	HdrUploadSignature = "X-Rmt-Signature"
)

// uploadSignedHeaders is every header the verifier requires exactly once.
var uploadSignedHeaders = []string{
	HdrUploadDevice, HdrUploadTenant, HdrUploadKeyFP, HdrUploadRecording, HdrUploadGen,
	HdrUploadSegment, HdrUploadOffset, HdrUploadBodySHA, HdrUploadTimestamp, HdrUploadSignature,
}

// UploadSigFields is the decoded content of one signed request.
type UploadSigFields struct {
	Audience    string
	Op          UploadOp
	Path        string
	TenantID    [16]byte
	DeviceID    string
	KeyFP       [32]byte
	RecordingID [16]byte
	Generation  uint64
	Segment     uint32
	Offset      uint64
	BodyLen     uint64
	BodySHA256  [32]byte
	TimestampMs uint64
}

func appendLP(dst, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	dst = append(dst, l[:]...)
	return append(dst, field...)
}

func lpU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return appendLP(dst, b[:])
}

func lpU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return appendLP(dst, b[:])
}

// UploadPreimage returns the exact bytes that are signed.
func UploadPreimage(f UploadSigFields) []byte {
	p := make([]byte, 0, 320)
	p = appendLP(p, []byte(UploadSigDomain))
	p = lpU32(p, uploadSigVersion)
	p = appendLP(p, []byte(f.Audience))
	p = appendLP(p, []byte{byte(f.Op)})
	p = appendLP(p, []byte(f.Path))
	p = appendLP(p, f.TenantID[:])
	p = appendLP(p, []byte(f.DeviceID))
	p = appendLP(p, f.KeyFP[:])
	p = appendLP(p, f.RecordingID[:])
	p = lpU64(p, f.Generation)
	p = lpU32(p, f.Segment)
	p = lpU64(p, f.Offset)
	p = lpU64(p, f.BodyLen)
	p = appendLP(p, f.BodySHA256[:])
	p = lpU64(p, f.TimestampMs)
	return p
}

// UploadKeyFingerprint is sha256 of the raw 32-byte Ed25519 public key.
func UploadKeyFingerprint(pub ed25519.PublicKey) [32]byte { return sha256.Sum256(pub) }

// SignUpload signs f with the agent key. Only tests and the golden-vector generator call it; the
// production signer is the Rust agent.
func SignUpload(priv ed25519.PrivateKey, f UploadSigFields) []byte {
	return ed25519.Sign(priv, UploadPreimage(f))
}

// VerifyUploadSignature reports whether sig is a valid Ed25519 signature by pub over f's preimage.
func VerifyUploadSignature(pub ed25519.PublicKey, f UploadSigFields, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, UploadPreimage(f), sig)
}

// UploadTimestampOK applies the ±5 minute window, inclusive at both edges. A timestamp of zero is
// never accepted (it is what a missing value parses to).
func UploadTimestampOK(nowMs int64, tsMs uint64) bool {
	if tsMs == 0 || tsMs > uint64(1<<62) {
		return false
	}
	d := int64(tsMs) - nowMs
	if d < 0 {
		d = -d
	}
	return d <= UploadSigWindowMs
}

// ---- canonical identifiers -------------------------------------------------------------------

// recParseUUID accepts ONLY the canonical lower-case hyphenated spelling. Every id that reaches the
// recording storage layer or a path goes through here, so there is exactly one spelling per id and a
// name like "../x", "ABC…" or a dashless form can never be turned into a path component.
func recParseUUID(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 36 {
		return out, false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return out, false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return out, false
			}
		}
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(out[:], []byte(h)); err != nil {
		return out, false
	}
	return out, true
}

func recFormatUUID(b [16]byte) string {
	var h [32]byte
	hex.Encode(h[:], b[:])
	return string(h[0:8]) + "-" + string(h[8:12]) + "-" + string(h[12:16]) + "-" + string(h[16:20]) + "-" + string(h[20:32])
}

func recIsUUID(s string) bool { _, ok := recParseUUID(s); return ok }

// Canonical route paths (as the control plane sees them — Caddy strips the /cp prefix).
const recRoutePrefix = "/agent/recordings"

func uploadCanonicalPath(op UploadOp, recording string, segment uint32) string {
	switch op {
	case UploadOpCreate:
		return recRoutePrefix
	case UploadOpPut, UploadOpHead:
		return recRoutePrefix + "/" + recording + "/segments/" + strconv.FormatUint(uint64(segment), 10)
	case UploadOpFinish:
		return recRoutePrefix + "/" + recording + "/finish"
	}
	return ""
}

// ---- request parsing -------------------------------------------------------------------------

var (
	errUploadMalformed = errors.New("malformed signed request")
	errUploadSignature = errors.New("signature verification failed")
	errUploadWindow    = errors.New("timestamp outside the accepted window")
)

// ParsedUpload is a request whose headers parsed cleanly. It is NOT yet authenticated.
type ParsedUpload struct {
	Fields    UploadSigFields
	Signature []byte
	// RecordingID and TenantID are the canonical string forms of the ids in Fields.
	RecordingID string
	TenantID    string
}

// ParseUploadRequest extracts the signed fields from r's headers, enforcing the C1 canonicalisation
// rules: no query string, no escaped/odd path encoding, no duplicated signed header, canonical
// lower-case ids and plain decimal numbers. op and audience come from the SERVER. The path must equal
// the canonical path for (op, recording id, segment) exactly.
func ParseUploadRequest(r *http.Request, op UploadOp, audience string) (*ParsedUpload, error) {
	if !op.valid() || audience == "" {
		return nil, errUploadMalformed
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		return nil, errUploadMalformed
	}
	vals := make(map[string]string, len(uploadSignedHeaders))
	for _, k := range uploadSignedHeaders {
		v := r.Header.Values(k)
		if len(v) != 1 || v[0] == "" || strings.TrimSpace(v[0]) != v[0] {
			return nil, errUploadMalformed
		}
		vals[k] = v[0]
	}
	// A repeated Content-Length would make "exact body length" ambiguous.
	if cl := r.Header.Values("Content-Length"); len(cl) > 1 {
		return nil, errUploadMalformed
	}

	var f UploadSigFields
	f.Audience = audience
	f.Op = op
	f.DeviceID = vals[HdrUploadDevice]
	if len(f.DeviceID) > 128 || !utf8Printable(f.DeviceID) {
		return nil, errUploadMalformed
	}
	var ok bool
	if f.TenantID, ok = recParseUUID(vals[HdrUploadTenant]); !ok {
		return nil, errUploadMalformed
	}
	if f.RecordingID, ok = recParseUUID(vals[HdrUploadRecording]); !ok {
		return nil, errUploadMalformed
	}
	if !decodeFixedHex(f.KeyFP[:], vals[HdrUploadKeyFP]) || !decodeFixedHex(f.BodySHA256[:], vals[HdrUploadBodySHA]) {
		return nil, errUploadMalformed
	}
	var err error
	if f.Generation, err = parseCanonU64(vals[HdrUploadGen]); err != nil || f.Generation == 0 {
		return nil, errUploadMalformed
	}
	seg, err := parseCanonU64(vals[HdrUploadSegment])
	if err != nil || seg > 0xffffffff {
		return nil, errUploadMalformed
	}
	f.Segment = uint32(seg)
	if f.Offset, err = parseCanonU64(vals[HdrUploadOffset]); err != nil {
		return nil, errUploadMalformed
	}
	if f.TimestampMs, err = parseCanonU64(vals[HdrUploadTimestamp]); err != nil {
		return nil, errUploadMalformed
	}
	sig := make([]byte, ed25519.SignatureSize)
	if !decodeFixedHex(sig, vals[HdrUploadSignature]) {
		return nil, errUploadMalformed
	}
	// The signed body length is the declared Content-Length; a body of unknown length (chunked) cannot
	// be bound to a signature before it is read, so it is refused.
	if r.ContentLength < 0 {
		return nil, errUploadMalformed
	}
	f.BodyLen = uint64(r.ContentLength)
	// Fields an operation does not use must be zero, so there is one encoding of each request.
	switch op {
	case UploadOpCreate, UploadOpFinish:
		if f.Segment != 0 || f.Offset != 0 {
			return nil, errUploadMalformed
		}
	case UploadOpHead:
		if f.Offset != 0 {
			return nil, errUploadMalformed
		}
	}
	rec := recFormatUUID(f.RecordingID)
	f.Path = uploadCanonicalPath(op, rec, f.Segment)
	if r.URL.Path != f.Path {
		return nil, errUploadMalformed
	}
	return &ParsedUpload{Fields: f, Signature: sig, RecordingID: rec, TenantID: recFormatUUID(f.TenantID)}, nil
}

func utf8Printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return false
		}
	}
	return s != ""
}

func decodeFixedHex(dst []byte, s string) bool {
	if len(s) != len(dst)*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	_, err := hex.Decode(dst, []byte(s))
	return err == nil
}

// parseCanonU64 accepts plain decimal digits with no sign, no leading zeros and no whitespace.
func parseCanonU64(s string) (uint64, error) {
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, errUploadMalformed
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errUploadMalformed
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

// NormalizeRecordingAudience canonicalises the control plane's public origin, which is signed into every
// upload request as the deployment audience. The agent applies the SAME rules to the control-plane URL
// it was enrolled against, so both sides sign and compare one string: lower-case scheme and host, no
// default port, no path, no userinfo, no query or fragment. https only — plain http is accepted solely
// for a loopback host (local development and tests).
func NormalizeRecordingAudience(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("CP_PUBLIC_ORIGIN is required when central recording is enabled (RECORDING_MASTER_KEY is set)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("CP_PUBLIC_ORIGIN must be an origin like https://main.example.com (scheme and host[:port] only)")
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	port := u.Port()
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", errors.New("CP_PUBLIC_ORIGIN must be https (plain http is accepted only for a loopback host)")
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", errors.New("CP_PUBLIC_ORIGIN must be an https origin")
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}
