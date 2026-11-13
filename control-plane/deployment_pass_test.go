package controlplane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The shared contract for the three verifiers (docs/48 "Compatibility tests"). Go generates it;
// Rust (Support) and C++/CNG (Setup) read the same file in their own test suites. Signatures are
// randomised, so regenerating rewrites every sig; the cases stay the same. Regenerate with:
//
//	go test -run TestGenerateDeploymentPassVectors -update-pass-vectors .
var updatePassVectors = flag.Bool("update-pass-vectors", false, "rewrite testdata/deployment-pass-vectors.json")

const passVectorsPath = "testdata/deployment-pass-vectors.json"

type passVectorFile struct {
	Description string       `json:"description"`
	CheckOrder  []string     `json:"check_order"`
	RootPubkey  string       `json:"root_pubkey"`
	TestScalar  string       `json:"test_root_private_scalar_TEST_ONLY"`
	Vectors     []passVector `json:"vectors"`
}

type passVector struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"` // "pass" or "release"
	Pubkey      string            `json:"pubkey,omitempty"`
	EnvelopeB64 string            `json:"envelope_b64"`
	Now         string            `json:"now"`
	Expect      string            `json:"expect"` // "ok" or a SignedObjectErrorKind
	Fields      map[string]string `json:"fields,omitempty"`
}

// testRootKey is a fixed TEST-ONLY P-256 key, so the vector file's root key is stable.
func testRootKey(t testing.TB, label string) *ecdsa.PrivateKey {
	t.Helper()
	d := sha256.Sum256([]byte("deskrally deployment-pass test vector key: " + label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		t.Fatalf("test key %s: %v", label, err)
	}
	return k
}

func signRaw(t testing.TB, k *ecdsa.PrivateKey, digest []byte) [64]byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func signEnvelope(t testing.TB, k *ecdsa.PrivateKey, domain string, body []byte) []byte {
	t.Helper()
	d := SignedObjectDigest(domain, body)
	return EncodeSignedObject(body, signRaw(t, k, d[:]))
}

var (
	vecIssued = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	vecNow    = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
)

func basePass() DeploymentPassClaims {
	return DeploymentPassClaims{
		PassID:            "3f6c1a2e-8b4d-4c1f-9e2a-7d5b6c8e9f01",
		IssuedTo:          "Example Managed Services, LLC",
		Origin:            "https://remote.example.com",
		GrantIssuerPubkey: strings.Repeat("a1", 32),
		ForSetup:          true,
		ForSupport:        true,
		MinAgentVersion:   "1.3.4",
		IssuedAt:          vecIssued,
		ExpiresAt:         vecIssued.Add(30 * 24 * time.Hour),
	}
}

func baseRelease() AgentReleaseClaims {
	return AgentReleaseClaims{
		MSISHA256:      strings.Repeat("5e", 32),
		MSISize:        12345678,
		ProductVersion: "1.3.5",
		ProductCode:    "{0F347057-1A2B-4C3D-8E9F-0123456789AB}",
		UpgradeCode:    "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
		Arch:           "x64",
		IssuedAt:       vecIssued,
		ExpiresAt:      vecIssued.Add(365 * 24 * time.Hour),
	}
}

func mustPassBody(t testing.TB, p DeploymentPassClaims) []byte {
	t.Helper()
	b, err := EncodeDeploymentPassBody(p)
	if err != nil {
		t.Fatalf("encode pass: %v", err)
	}
	return b
}

func mustReleaseBody(t testing.TB, r AgentReleaseClaims) []byte {
	t.Helper()
	b, err := EncodeAgentReleaseBody(r)
	if err != nil {
		t.Fatalf("encode release: %v", err)
	}
	return b
}

// replaceOnce edits a canonical body so a test can sign bytes the encoder would refuse.
func replaceOnce(t testing.TB, body []byte, old, new string) []byte {
	t.Helper()
	if bytes.Count(body, []byte(old)) != 1 {
		t.Fatalf("%q occurs %d times in %s", old, bytes.Count(body, []byte(old)), body)
	}
	return bytes.Replace(body, []byte(old), []byte(new), 1)
}

// verifiedPass / verifiedRelease wrap claims the generator has just encoded and signed itself,
// to compute the fields an ok vector must yield.
func verifiedPass(c DeploymentPassClaims) DeploymentPass { return DeploymentPass{c: c, ok: true} }
func verifiedRelease(c AgentReleaseClaims) AgentRelease  { return AgentRelease{c: c, ok: true} }

func passFields(p DeploymentPass) map[string]string {
	c := p.Claims()
	return map[string]string{
		"pass_id": c.PassID, "issued_to": c.IssuedTo, "origin": c.Origin, "host_port": p.HostPort(),
		"control_plane_url": p.ControlPlaneURL(), "signaling_url": p.SignalingURL(),
		"grant_issuer_pubkey": c.GrantIssuerPubkey, "for_setup": strconv.FormatBool(c.ForSetup),
		"for_support": strconv.FormatBool(c.ForSupport), "min_agent_version": c.MinAgentVersion,
		"issued_at": c.IssuedAt.Format(PassTimeLayout), "expires_at": c.ExpiresAt.Format(PassTimeLayout),
	}
}

func releaseFields(r AgentRelease) map[string]string {
	c := r.Claims()
	return map[string]string{
		"msi_sha256": c.MSISHA256, "msi_size": strconv.FormatInt(c.MSISize, 10),
		"product_version": c.ProductVersion, "product_code": c.ProductCode, "upgrade_code": c.UpgradeCode,
		"arch": c.Arch, "issued_at": c.IssuedAt.Format(PassTimeLayout), "expires_at": c.ExpiresAt.Format(PassTimeLayout),
	}
}

// buildPassVectors is the case list. Every case is built from a valid object and changed in one
// way, so each one tests exactly the rule its name says.
func buildPassVectors(t testing.TB) passVectorFile {
	root := testRootKey(t, "root")
	other := testRootKey(t, "other")
	rootHex, _ := DeploymentRootKeyHex(&root.PublicKey)
	otherHex, _ := DeploymentRootKeyHex(&other.PublicKey)
	bs := string('\\') // see pass-valid-escaped-ampersand: escapes are built, never typed
	var vs []passVector
	add := func(name, kind string, env []byte, at time.Time, expect SignedObjectErrorKind) *passVector {
		e := string(expect)
		if e == "" {
			e = "ok"
		}
		vs = append(vs, passVector{Name: name, Kind: kind, EnvelopeB64: base64.StdEncoding.EncodeToString(env), Now: at.Format(PassTimeLayout), Expect: e})
		return &vs[len(vs)-1]
	}
	passEnv := func(body []byte) []byte { return signEnvelope(t, root, DeploymentPassDomain, body) }
	relEnv := func(body []byte) []byte { return signEnvelope(t, root, AgentReleaseDomain, body) }
	okPass := func(name string, p DeploymentPassClaims, at time.Time) {
		add(name, "pass", passEnv(mustPassBody(t, p)), at, "").Fields = passFields(verifiedPass(p))
	}
	okRelease := func(name string, r AgentReleaseClaims, at time.Time) {
		add(name, "release", relEnv(mustReleaseBody(t, r)), at, "").Fields = releaseFields(verifiedRelease(r))
	}
	pb := mustPassBody(t, basePass())
	rb := mustReleaseBody(t, baseRelease())
	badPass := func(name, old, new string) {
		add(name, "pass", passEnv(replaceOnce(t, pb, old, new)), vecNow, SignedObjectBadBody)
	}
	badRelease := func(name, old, new string) {
		add(name, "release", relEnv(replaceOnce(t, rb, old, new)), vecNow, SignedObjectBadBody)
	}

	// ---- valid ----
	okPass("pass-valid", basePass(), vecNow)
	p := basePass()
	p.ForSetup = false
	okPass("pass-valid-support-only", p, vecNow)
	p = basePass()
	p.ForSupport = false
	okPass("pass-valid-setup-only", p, vecNow)
	p = basePass()
	p.Origin = "https://remote.example.com:8443"
	okPass("pass-valid-explicit-port", p, vecNow)
	p = basePass()
	p.Origin = "https://xn--bcher-kva.example"
	okPass("pass-valid-punycode-host", p, vecNow)
	p = basePass()
	p.ExpiresAt = p.IssuedAt.Add(DeploymentPassMaxLifetime)
	okPass("pass-valid-exactly-31-days", p, vecNow)
	okPass("pass-valid-at-skew-edge", basePass(), vecIssued.Add(-SignedObjectClockSkew))
	okPass("pass-valid-last-second", basePass(), basePass().ExpiresAt.Add(-time.Second))
	add("pass-valid-uses-reordered", "pass", passEnv(replaceOnce(t, pb, `["setup","support"]`, `["support","setup"]`)), vecNow, "").Fields = passFields(verifiedPass(basePass()))
	p = basePass()
	p.IssuedTo = "A&B Support"
	// The escape is assembled from parts: a literal JSON escape typed into this file was once
	// decoded by tooling into the character itself, leaving a vector that tested nothing.
	ampEsc := "A" + bs + "u0026B"
	escBody := replaceOnce(t, mustPassBody(t, p), "A&B", ampEsc)
	if !bytes.Contains(escBody, []byte{'A', '\\', 'u', '0', '0', '2', '6', 'B'}) {
		t.Fatal("the escaped-ampersand body lost its escape")
	}
	add("pass-valid-escaped-ampersand", "pass", passEnv(escBody), vecNow, "").Fields = passFields(verifiedPass(p))
	add("pass-valid-escaped-key", "pass", passEnv(replaceOnce(t, pb, `"v":1,`, `"`+bs+`u0076":1,`)), vecNow, "").Fields = passFields(verifiedPass(basePass()))
	// Exact-size boundaries: spaces between tokens are allowed, so pad a valid body to 2048 bytes
	// and a valid envelope to 4096; one more byte is the oversize vector further down.
	full := replaceOnce(t, pb, `"v":1,`, `"v":1,`+strings.Repeat(" ", MaxSignedBodyBytes-len(pb)))
	add("pass-valid-body-exactly-2048", "pass", passEnv(full), vecNow, "").Fields = passFields(verifiedPass(basePass()))
	valid := passEnv(pb)
	spaced := bytes.ReplaceAll(bytes.ReplaceAll(valid, []byte(`,"`), []byte(",\n  \"")), []byte(`{`), []byte("{ "))
	add("pass-valid-envelope-whitespace", "pass", spaced, vecNow, "").Fields = passFields(verifiedPass(basePass()))
	okRelease("release-valid", baseRelease(), vecNow)
	r := baseRelease()
	r.ExpiresAt = r.IssuedAt.Add(AgentReleaseMaxLifetime)
	okRelease("release-valid-exactly-396-days", r, vecNow)

	// ---- key ----
	x := rootHex[2:66]
	yInt, _ := new(big.Int).SetString(rootHex[66:], 16)
	yInt.Add(yInt, big.NewInt(1))
	offCurve := "04" + x + hex.EncodeToString(yInt.FillBytes(make([]byte, 32)))
	add("key-off-curve", "pass", valid, vecNow, SignedObjectBadKey).Pubkey = offCurve
	add("key-compressed", "pass", valid, vecNow, SignedObjectBadKey).Pubkey = "02" + x
	add("key-uppercase-hex", "pass", valid, vecNow, SignedObjectBadKey).Pubkey = strings.ToUpper(rootHex)
	add("key-infinity", "pass", valid, vecNow, SignedObjectBadKey).Pubkey = "04" + strings.Repeat("00", 64)

	// ---- envelope ----
	add("envelope-oversize", "pass", append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), MaxSignedObjectBytes+1-len(valid))...), vecNow, SignedObjectBadEnvelope)
	add("envelope-format-2", "pass", bytes.Replace(valid, []byte(`"format":1`), []byte(`"format":2`), 1), vecNow, SignedObjectBadEnvelope)
	add("envelope-format-string", "pass", bytes.Replace(valid, []byte(`"format":1`), []byte(`"format":"1"`), 1), vecNow, SignedObjectBadEnvelope)
	add("envelope-unknown-key", "pass", bytes.Replace(valid, []byte(`{"format":1`), []byte(`{"kid":"a","format":1`), 1), vecNow, SignedObjectBadEnvelope)
	add("envelope-duplicate-key", "pass", bytes.Replace(valid, []byte(`{"format":1`), []byte(`{"format":1,"format":1`), 1), vecNow, SignedObjectBadEnvelope)
	add("envelope-missing-sig", "pass", append(append([]byte{}, valid[:bytes.Index(valid, []byte(`,"sig"`))]...), '}'), vecNow, SignedObjectBadEnvelope)
	add("envelope-trailing-data", "pass", append(append([]byte{}, valid...), []byte("{}")...), vecNow, SignedObjectBadEnvelope)
	sigAt := bytes.Index(valid, []byte(`"sig":"`)) + len(`"sig":"`)
	sigHex := string(valid[sigAt : sigAt+128])
	withSig := func(h string) []byte {
		return append(append(append([]byte{}, valid[:sigAt]...), h...), valid[sigAt+128:]...)
	}
	add("envelope-sig-uppercase", "pass", withSig(strings.ToUpper(sigHex)), vecNow, SignedObjectBadEnvelope)
	add("envelope-sig-short", "pass", withSig(sigHex[:126]), vecNow, SignedObjectBadEnvelope)
	add("envelope-sig-der-length", "pass", withSig("3044"+sigHex), vecNow, SignedObjectBadEnvelope)
	b64 := base64.StdEncoding.EncodeToString(pb)
	withBody := func(s string) []byte { return bytes.Replace(valid, []byte(b64), []byte(s), 1) }
	add("envelope-body-urlsafe-base64", "pass", withBody(base64.URLEncoding.EncodeToString(pb)+"-_"), vecNow, SignedObjectBadEnvelope)
	padded := append([]byte{}, pb...)
	for len(padded)%3 == 0 {
		padded = append(padded, ' ')
	}
	add("envelope-body-unpadded", "pass", withBody(strings.TrimRight(base64.StdEncoding.EncodeToString(padded), "=")), vecNow, SignedObjectBadEnvelope)
	add("envelope-body-empty", "pass", withBody(""), vecNow, SignedObjectBadEnvelope)
	add("envelope-non-utf8", "pass", bytes.Replace(valid, []byte(`{"format":1`), []byte("{\"x\xff\":1,\"format\":1"), 1), vecNow, SignedObjectBadEnvelope)
	add("envelope-array", "pass", []byte(`[`+string(valid)+`]`), vecNow, SignedObjectBadEnvelope)
	add("pass-valid-envelope-exactly-4096", "pass", append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), MaxSignedObjectBytes-len(valid))...), vecNow, "").Fields = passFields(verifiedPass(basePass()))
	// Base64 must be the one canonical spelling. Go's decoder skips CR/LF even in Strict mode, so a
	// JSON-escaped newline inside the base64 text decodes to the signed body; it must still fail.
	add("envelope-body-base64-escaped-newline", "pass", withBody(b64[:40]+bs+"n"+b64[40:]), vecNow, SignedObjectBadEnvelope)
	add("envelope-body-base64-escaped-cr", "pass", withBody(b64[:40]+bs+"r"+b64[40:]), vecNow, SignedObjectBadEnvelope)
	add("envelope-body-base64-extra-padding", "pass", withBody(b64+"="), vecNow, SignedObjectBadEnvelope)
	// A body whose length is 1 mod 3 ends in "xx==": flipping the unused low bits of the last data
	// character decodes (leniently) to the same bytes, so only a canonical-spelling rule refuses it.
	two := replaceOnce(t, pb, `"v":1,`, `"v":1,`+strings.Repeat(" ", (3-(len(pb)-1)%3)%3))
	if len(two)%3 != 1 {
		t.Fatalf("padding setup: len %d", len(two))
	}
	twoEnv := passEnv(two)
	twoB64 := base64.StdEncoding.EncodeToString(two)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, twoB64[len(twoB64)-3])
	dirty := twoB64[:len(twoB64)-3] + string(alphabet[last|1]) + "=="
	if dirty == twoB64 {
		dirty = twoB64[:len(twoB64)-3] + string(alphabet[last|2]) + "=="
	}
	add("envelope-body-base64-nonzero-padding-bits", "pass", bytes.Replace(twoEnv, []byte(twoB64), []byte(dirty), 1), vecNow, SignedObjectBadEnvelope)

	// ---- check order: two faults at once, the earlier check must win ----
	add("order-key-before-envelope", "pass", []byte("not json"), vecNow, SignedObjectBadKey).Pubkey = "02" + x
	add("order-envelope-before-signature", "pass", bytes.Replace(withSig(strings.Repeat("0", 64)+sigHex[64:]), []byte(`"format":1`), []byte(`"format":2`), 1), vecNow, SignedObjectBadEnvelope)
	dupBody := replaceOnce(t, pb, `"v":1,`, `"v":1,"v":1,`)
	add("order-signature-before-body", "pass", EncodeSignedObject(dupBody, signRaw(t, root, func() []byte { d := SignedObjectDigest(DeploymentPassDomain, pb); return d[:] }())), vecNow, SignedObjectBadSignature)
	add("order-body-before-validity", "pass", passEnv(dupBody), basePass().ExpiresAt.Add(time.Hour), SignedObjectBadBody)

	// ---- signature ----
	add("signature-pass-body-signed-as-release", "pass", relEnv(pb), vecNow, SignedObjectBadSignature)
	add("signature-release-object-checked-as-pass", "pass", relEnv(rb), vecNow, SignedObjectBadSignature)
	add("signature-pass-object-checked-as-release", "release", passEnv(pb), vecNow, SignedObjectBadSignature)
	flipped := append([]byte{}, pb...)
	flipped[10] ^= 0x01
	add("signature-body-bit-flip", "pass", withBody(base64.StdEncoding.EncodeToString(flipped)), vecNow, SignedObjectBadSignature)
	add("signature-wrong-key", "pass", valid, vecNow, SignedObjectBadSignature).Pubkey = otherHex
	noDomain := sha256.Sum256(pb)
	add("signature-without-domain", "pass", EncodeSignedObject(pb, signRaw(t, root, noDomain[:])), vecNow, SignedObjectBadSignature)
	once := SignedObjectDigest(DeploymentPassDomain, pb)
	twice := sha256.Sum256(once[:])
	add("signature-hashed-twice", "pass", EncodeSignedObject(pb, signRaw(t, root, twice[:])), vecNow, SignedObjectBadSignature)
	n := hex.EncodeToString(elliptic.P256().Params().N.FillBytes(make([]byte, 32)))
	add("signature-r-zero", "pass", withSig(strings.Repeat("0", 64)+sigHex[64:]), vecNow, SignedObjectBadSignature)
	add("signature-s-zero", "pass", withSig(sigHex[:64]+strings.Repeat("0", 64)), vecNow, SignedObjectBadSignature)
	add("signature-r-equals-n", "pass", withSig(n+sigHex[64:]), vecNow, SignedObjectBadSignature)
	add("signature-s-equals-n", "pass", withSig(sigHex[:64]+n), vecNow, SignedObjectBadSignature)
	add("signature-s-all-ones", "pass", withSig(sigHex[:64]+strings.Repeat("f", 64)), vecNow, SignedObjectBadSignature)
	// s' = n - s is the other valid signature of the same message; docs/48 has no low-S rule, so
	// it must ACCEPT. A verifier that enforced low-S would refuse half of all honest signatures.
	sInt, _ := new(big.Int).SetString(sigHex[64:], 16)
	negS := new(big.Int).Sub(elliptic.P256().Params().N, sInt)
	add("pass-valid-negated-s", "pass", withSig(sigHex[:64]+hex.EncodeToString(negS.FillBytes(make([]byte, 32)))), vecNow, "").Fields = passFields(verifiedPass(basePass()))

	// ---- body: shape (all correctly signed) ----
	badPass("body-duplicate-key", `"v":1,`, `"v":1,"v":1,`)
	badPass("body-unknown-key", `"v":1,`, `"v":1,"note":"x",`)
	badPass("body-missing-key", `"v":1,`, ``)
	badPass("body-case-variant-key", `"origin":`, `"Origin":`)
	badPass("body-null-field", `"v":1`, `"v":null`)
	badPass("body-v-float", `"v":1`, `"v":1.0`)
	badPass("body-v-2", `"v":1`, `"v":2`)
	badPass("body-wrong-purpose", `"deskrally-deployment-pass"`, `"deskrally-agent-release"`)
	badPass("body-tab-between-tokens", `"v":1,`, "\"v\":1,\t")
	// A space is not a control byte, so JSON whitespace made of spaces is allowed in a body.
	add("pass-valid-space-between-tokens", "pass", passEnv(replaceOnce(t, pb, `"v":1,`, `"v": 1, `)), vecNow, "").Fields = passFields(verifiedPass(basePass()))
	add("body-trailing-newline", "pass", passEnv(append(append([]byte{}, pb...), '\n')), vecNow, SignedObjectBadBody)
	add("body-trailing-data", "pass", passEnv(append(append([]byte{}, pb...), []byte("{}")...)), vecNow, SignedObjectBadBody)
	add("body-oversize", "pass", passEnv(replaceOnce(t, pb, `"v":1,`, `"v":1,"pad":"`+strings.Repeat("x", MaxSignedBodyBytes)+`",`)), vecNow, SignedObjectBadBody)
	add("body-2049-bytes", "pass", passEnv(append(append([]byte{}, full[:len(full)-1]...), ' ', full[len(full)-1])), vecNow, SignedObjectBadBody)
	add("body-non-utf8", "pass", passEnv(replaceOnce(t, pb, "Example", "Ex\xc3ample")), vecNow, SignedObjectBadBody)
	add("body-lone-surrogate", "pass", passEnv(replaceOnce(t, pb, "Example", "Ex"+bs+"ud800ample")), vecNow, SignedObjectBadBody)
	// A high surrogate followed by a \u escape that is NOT a low surrogate (found by a C++ mutant).
	add("body-high-surrogate-then-non-low", "pass", passEnv(replaceOnce(t, pb, "Example", "Ex"+bs+"ud800"+bs+"u0041mple")), vecNow, SignedObjectBadBody)
	badPass("body-escaped-duplicate-key", `"v":1,`, `"v":1,"`+bs+`u0076":1,`)
	badPass("body-v-exponent", `"v":1`, `"v":1e0`)
	badPass("body-v-leading-zero", `"v":1`, `"v":01`)
	badPass("body-v-plus-sign", `"v":1`, `"v":+1`)

	// ---- body: pass fields ----
	badPass("body-issued-to-nul-escape", "Example", "Ex"+bs+"u0000ample")
	badPass("body-issued-to-newline-escape", "Example", "Ex"+bs+"nample")
	badPass("body-issued-to-empty", `"Example Managed Services, LLC"`, `""`)
	badPass("body-issued-to-65-chars", `"Example Managed Services, LLC"`, `"`+strings.Repeat("a", 65)+`"`)
	badPass("body-issued-to-angle-bracket", "Example", "<Example>")
	badPass("body-issued-to-non-ascii", "Example", "Exämple")
	badPass("body-pass-id-uppercase", "3f6c1a2e", "3F6C1A2E")
	badPass("body-pass-id-braced", `"3f6c1a2e-8b4d-4c1f-9e2a-7d5b6c8e9f01"`, `"{3f6c1a2e-8b4d-4c1f-9e2a-7d5b6c8e9f01}"`)
	badPass("body-grant-key-short", strings.Repeat("a1", 32), strings.Repeat("a1", 31))
	badPass("body-grant-key-uppercase", strings.Repeat("a1", 32), strings.Repeat("A1", 32))
	badPass("body-uses-empty", `["setup","support"]`, `[]`)
	badPass("body-uses-duplicate", `["setup","support"]`, `["setup","setup"]`)
	badPass("body-uses-unknown", `["setup","support"]`, `["setup","admin"]`)
	badPass("body-uses-not-array", `["setup","support"]`, `"setup"`)
	badPass("body-min-version-leading-zero", `"1.3.4"`, `"1.03.4"`)
	badPass("body-min-version-over-limit", `"1.3.4"`, `"256.0.0"`)
	badPass("body-min-version-two-fields", `"1.3.4"`, `"1.3"`)
	for _, o := range []struct{ name, origin string }{
		{"path", "https://remote.example.com/cp"},
		{"trailing-slash", "https://remote.example.com/"},
		{"userinfo", "https://user@remote.example.com"},
		{"port-443-written", "https://remote.example.com:443"},
		{"uppercase-host", "https://Remote.example.com"},
		{"unicode-host", "https://bücher.example"},
		{"http-scheme", "http://remote.example.com"},
		{"trailing-dot", "https://remote.example.com."},
		{"query", "https://remote.example.com?a=1"},
		{"fragment", "https://remote.example.com#a"},
		{"port-leading-zero", "https://remote.example.com:08443"},
		{"port-zero", "https://remote.example.com:0"},
		{"port-too-large", "https://remote.example.com:65536"},
		{"port-empty", "https://remote.example.com:"},
		{"ipv6-literal", "https://[::1]"},
		{"empty-label", "https://remote..example.com"},
		{"label-leading-hyphen", "https://-remote.example.com"},
		{"label-64-chars", "https://" + strings.Repeat("a", 64) + ".example.com"},
		{"backslash", `https://remote.example.com\\evil.example`},
		{"percent-encoded", "https://remote%2eexample.com"},
	} {
		badPass("body-origin-"+o.name, `"https://remote.example.com"`, `"`+o.origin+`"`)
	}

	// ---- body: timestamps and lifetime ----
	badPass("body-time-fractional", `"2026-10-01T00:00:00Z"`, `"2026-10-01T00:00:00.000Z"`)
	badPass("body-time-offset", `"2026-10-01T00:00:00Z"`, `"2026-10-01T00:00:00+00:00"`)
	badPass("body-time-lowercase-z", `"2026-10-01T00:00:00Z"`, `"2026-10-01t00:00:00z"`)
	badPass("body-time-invalid-date", `"2026-10-01T00:00:00Z"`, `"2026-02-30T00:00:00Z"`)
	badPass("body-time-epoch-number", `"2026-10-01T00:00:00Z"`, `1790812800`)
	p = basePass()
	p.ExpiresAt = p.IssuedAt.Add(DeploymentPassMaxLifetime)
	b31 := mustPassBody(t, p)
	add("body-lifetime-31-days-plus-1s", "pass", passEnv(replaceOnce(t, b31, `"expires_at":"2026-11-01T00:00:00Z"`, `"expires_at":"2026-11-01T00:00:01Z"`)), vecNow, SignedObjectBadBody)
	badPass("body-expires-equals-issued", `"expires_at":"2026-10-31T00:00:00Z"`, `"expires_at":"2026-10-01T00:00:00Z"`)
	badPass("body-expires-before-issued", `"expires_at":"2026-10-31T00:00:00Z"`, `"expires_at":"2026-09-30T00:00:00Z"`)

	// ---- body: release fields ----
	badRelease("release-body-msi-size-zero", `"msi_size":12345678`, `"msi_size":0`)
	badRelease("release-body-msi-size-negative", `"msi_size":12345678`, `"msi_size":-1`)
	badRelease("release-body-msi-size-2gib", `"msi_size":12345678`, `"msi_size":2147483648`)
	badRelease("release-body-msi-size-string", `"msi_size":12345678`, `"msi_size":"12345678"`)
	badRelease("release-body-msi-size-int64-overflow", `"msi_size":12345678`, `"msi_size":99999999999999999999`)
	badRelease("release-body-msi-size-fraction", `"msi_size":12345678`, `"msi_size":12345678.0`)
	badRelease("release-body-sha-uppercase", strings.Repeat("5e", 32), strings.Repeat("5E", 32))
	badRelease("release-body-product-code-lowercase", "{0F347057-1A2B-4C3D-8E9F-0123456789AB}", "{0f347057-1a2b-4c3d-8e9f-0123456789ab}")
	badRelease("release-body-upgrade-code-unbraced", `"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}"`, `"7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C"`)
	badRelease("release-body-arch-x86", `"x64"`, `"x86"`)
	badRelease("release-body-wrong-purpose", `"deskrally-agent-release"`, `"deskrally-deployment-pass"`)
	r = baseRelease()
	r.ExpiresAt = r.IssuedAt.Add(AgentReleaseMaxLifetime)
	r396 := mustReleaseBody(t, r)
	add("release-body-lifetime-396-days-plus-1s", "release", relEnv(replaceOnce(t, r396, `"expires_at":"2027-11-01T00:00:00Z"`, `"expires_at":"2027-11-01T00:00:01Z"`)), vecNow, SignedObjectBadBody)

	// ---- validity (clock) ----
	add("validity-expired-exactly", "pass", valid, basePass().ExpiresAt, SignedObjectNotValidNow)
	add("validity-expired-later", "pass", valid, basePass().ExpiresAt.Add(400*24*time.Hour), SignedObjectNotValidNow)
	add("validity-before-skew", "pass", valid, vecIssued.Add(-SignedObjectClockSkew-time.Second), SignedObjectNotValidNow)
	add("validity-release-expired", "release", relEnv(rb), baseRelease().ExpiresAt, SignedObjectNotValidNow)
	add("validity-release-future", "release", relEnv(rb), vecIssued.Add(-time.Hour), SignedObjectNotValidNow)

	return passVectorFile{
		Description: "Cross-language vectors for DeskRally deployment passes and agent release attestations " +
			"(docs/48 C). Every implementation must produce `expect` for every vector: \"ok\" (and the listed " +
			"fields), or the kind of the FIRST failing check in check_order. envelope_b64 is the exact file " +
			"bytes; now is the verifier's clock. The private scalar is a TEST key and signs nothing real.",
		CheckOrder: []string{"key", "envelope", "signature", "body", "validity"},
		RootPubkey: rootHex,
		TestScalar: hex.EncodeToString(root.D.FillBytes(make([]byte, 32))),
		Vectors:    vs,
	}
}

func TestGenerateDeploymentPassVectors(t *testing.T) {
	if !*updatePassVectors {
		t.Skip("run with -update-pass-vectors to rewrite " + passVectorsPath)
	}
	f := buildPassVectors(t)
	js, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passVectorsPath, append(js, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors to %s", len(f.Vectors), passVectorsPath)
}

// TestDeploymentPassVectors runs the committed vectors through the Go verifier: the same file the
// Rust and C++ verifiers must pass.
func TestDeploymentPassVectors(t *testing.T) {
	raw, err := os.ReadFile(passVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with -update-pass-vectors)", passVectorsPath, err)
	}
	var f passVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	want := buildPassVectors(t)
	if len(f.Vectors) != len(want.Vectors) {
		t.Fatalf("committed file has %d vectors, the generator has %d: regenerate", len(f.Vectors), len(want.Vectors))
	}
	kinds := map[string]int{}
	for i, v := range f.Vectors {
		if v.Name != want.Vectors[i].Name || v.Expect != want.Vectors[i].Expect {
			t.Fatalf("vector %d is %s/%s in the file but %s/%s in the generator: regenerate", i, v.Name, v.Expect, want.Vectors[i].Name, want.Vectors[i].Expect)
		}
		kinds[v.Expect]++
		t.Run(v.Name, func(t *testing.T) {
			env, err := base64.StdEncoding.DecodeString(v.EnvelopeB64)
			if err != nil {
				t.Fatal(err)
			}
			now, err := time.Parse(PassTimeLayout, v.Now)
			if err != nil {
				t.Fatal(err)
			}
			keyHex := f.RootPubkey
			if v.Pubkey != "" {
				keyHex = v.Pubkey
			}
			var fields map[string]string
			root, err := ParseDeploymentRootKey(keyHex)
			if err == nil {
				switch v.Kind {
				case "pass":
					var p DeploymentPass
					if p, err = VerifyDeploymentPass(root, env, now); err == nil {
						fields = passFields(p)
					}
				case "release":
					var r AgentRelease
					if r, err = VerifyAgentRelease(root, env, now); err == nil {
						fields = releaseFields(r)
					}
				default:
					t.Fatalf("unknown kind %q", v.Kind)
				}
			}
			got := "ok"
			if err != nil {
				got = string(SignedObjectErrorKindOf(err))
				if got == "" {
					t.Fatalf("unclassified error: %v", err)
				}
			}
			if got != v.Expect {
				t.Fatalf("got %s (%v), want %s", got, err, v.Expect)
			}
			if got == "ok" {
				if len(v.Fields) == 0 {
					t.Fatal("an ok vector must list its fields")
				}
				for k, w := range v.Fields {
					if fields[k] != w {
						t.Errorf("field %s = %q, want %q", k, fields[k], w)
					}
				}
			}
		})
	}
	for _, k := range []string{"ok", "key", "envelope", "signature", "body", "validity"} {
		if kinds[k] == 0 {
			t.Errorf("no vector expects %q", k)
		}
	}
}

func TestDeploymentPassEncodeRefusesWhatItCannotRead(t *testing.T) {
	p := basePass()
	p.IssuedAt = p.IssuedAt.Add(500 * time.Millisecond)
	if _, err := EncodeDeploymentPassBody(p); err == nil {
		t.Error("a sub-second issued_at must not encode (it would not round-trip)")
	}
	p = basePass()
	p.Origin = "https://remote.example.com:443"
	if _, err := EncodeDeploymentPassBody(p); SignedObjectErrorKindOf(err) != SignedObjectBadBody {
		t.Errorf("origin with :443 encoded: %v", err)
	}
	p = basePass()
	p.ForSetup, p.ForSupport = false, false
	if _, err := EncodeDeploymentPassBody(p); err == nil {
		t.Error("a pass with no uses encoded")
	}
	r := baseRelease()
	r.ExpiresAt = r.IssuedAt.Add(AgentReleaseMaxLifetime + time.Second)
	if _, err := EncodeAgentReleaseBody(r); err == nil {
		t.Error("an attestation over 396 days encoded")
	}
}

func TestDeploymentPassDerivedURLs(t *testing.T) {
	c := basePass()
	c.Origin = "https://remote.example.com:8443"
	p := verifiedPass(c)
	if p.ControlPlaneURL() != "https://remote.example.com:8443/cp" || p.SignalingURL() != "wss://remote.example.com:8443/ws" || p.HostPort() != "remote.example.com:8443" {
		t.Errorf("derived %s %s %s", p.ControlPlaneURL(), p.SignalingURL(), p.HostPort())
	}
}

func TestPassAdmitsRelease(t *testing.T) {
	p := verifiedPass(basePass()) // min 1.3.4
	for v, ok := range map[string]bool{"1.3.4": true, "1.3.5": true, "1.10.0": true, "1.3.3": false, "0.9.9": false, "1.2.10": false} {
		r := baseRelease()
		r.ProductVersion = v
		if err := PassAdmitsRelease(p, verifiedRelease(r)); (err == nil) != ok {
			t.Errorf("release %s: admitted=%v, want %v", v, err == nil, ok)
		}
	}
}

// TestDeploymentPassPackageCannotSign: the root key never comes near anything linked into the
// control plane, so no non-test file in this package may create or use an ECDSA private key.
// Reads the AST without comments, as TestServerPackageCannotSign does.
func TestDeploymentPassPackageCannotSign(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	saw := false
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if f == "deployment_pass.go" {
			saw = true
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "ecdsa" {
					switch sel.Sel.Name {
					case "Sign", "SignASN1", "GenerateKey", "ParseRawPrivateKey", "PrivateKey":
						t.Errorf("%s uses ecdsa.%s at %s: deployment-pass signing belongs only in cmd/rmt-pass-sign (docs/48)", f, sel.Sel.Name, fset.Position(sel.Pos()))
					}
				}
			}
			return true
		})
	}
	if !saw {
		t.Fatal("deployment_pass.go was not scanned: the guard is reading the wrong directory")
	}
}
