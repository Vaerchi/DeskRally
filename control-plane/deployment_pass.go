package controlplane

// Deployment passes and agent release attestations (docs/48 C, "Formats"): the wire format, the
// field rules and the VERIFIER. Go is one of three implementations (Rust in Support, C++/CNG in
// Setup); testdata/deployment-pass-vectors.json is the shared contract all three must pass.
//
// This package can verify a signed object but never produce a signature: the root key lives only
// on DeskRally's signing workstation, and ecdsa signing exists only in cmd/rmt-pass-sign.
// TestDeploymentPassPackageCannotSign enforces that, as TestServerPackageCannotSign does for
// update manifests.
//
// Check order is part of the contract, so the three implementations report the same failure kind
// for the same input:
//  1. key       the root public key (SEC1 uncompressed P-256, 130 lowercase hex, on the curve);
//  2. envelope  size (<= 4 KiB), UTF-8, exact JSON shape {"format":1,"body":"<b64>","sig":"<hex>"},
//     standard padded base64, sig exactly 128 lowercase hex;
//  3. signature r and s in [1, n-1], ECDSA P-256 over SHA-256(domain || body);
//  4. body      size (<= 2 KiB), no control bytes, UTF-8, exact-key JSON, every field's rules, and
//     the lifetime cap (31 days for a pass, 396 for a release attestation);
//  5. validity  issued_at - 5 min <= now < expires_at, by the caller's clock.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// SignedObjectFormat is the envelope's "format" value.
	SignedObjectFormat = 1
	// DeploymentPassDomain and AgentReleaseDomain prefix the signed bytes, so a signature made for
	// one purpose never verifies as the other. NUL-terminated ASCII.
	DeploymentPassDomain = "DRPASS1\x00"
	AgentReleaseDomain   = "DRREL1\x00"

	MaxSignedObjectBytes = 4096
	MaxSignedBodyBytes   = 2048

	DeploymentPassPurpose = "deskrally-deployment-pass"
	AgentReleasePurpose   = "deskrally-agent-release"

	// DeploymentPassMaxLifetime: revoking a pass means not renewing it, so its life bounds how long
	// a revoked customer keeps working (docs/48 principle 2).
	DeploymentPassMaxLifetime = 31 * 24 * time.Hour
	// AgentReleaseMaxLifetime is docs/48's "at most 13 months", fixed at 396 days so three
	// languages need no calendar arithmetic to agree on it.
	AgentReleaseMaxLifetime = 396 * 24 * time.Hour
	// SignedObjectClockSkew is how far before issued_at an object is already accepted.
	SignedObjectClockSkew = 5 * time.Minute

	// PassTimeLayout is the only accepted timestamp spelling: RFC 3339, UTC, whole seconds, "Z".
	PassTimeLayout = "2006-01-02T15:04:05Z"
)

// SignedObjectErrorKind classifies a refusal. The vectors pin the kind, not the message.
type SignedObjectErrorKind string

const (
	SignedObjectBadKey       SignedObjectErrorKind = "key"
	SignedObjectBadEnvelope  SignedObjectErrorKind = "envelope"
	SignedObjectBadSignature SignedObjectErrorKind = "signature"
	SignedObjectBadBody      SignedObjectErrorKind = "body"
	SignedObjectNotValidNow  SignedObjectErrorKind = "validity"
)

// SignedObjectError is every refusal this file returns.
type SignedObjectError struct {
	Kind SignedObjectErrorKind
	Err  error
}

func (e *SignedObjectError) Error() string { return string(e.Kind) + ": " + e.Err.Error() }
func (e *SignedObjectError) Unwrap() error { return e.Err }

// SignedObjectErrorKindOf returns the kind of a refusal from this file, or "" for any other error.
func SignedObjectErrorKindOf(err error) SignedObjectErrorKind {
	var se *SignedObjectError
	if errors.As(err, &se) {
		return se.Kind
	}
	return ""
}

func soErr(kind SignedObjectErrorKind, format string, a ...any) error {
	return &SignedObjectError{Kind: kind, Err: fmt.Errorf(format, a...)}
}

func soWrap(kind SignedObjectErrorKind, err error) error {
	if err == nil {
		return nil
	}
	if SignedObjectErrorKindOf(err) != "" {
		return err
	}
	return &SignedObjectError{Kind: kind, Err: err}
}

// ---------------------------------------------------------------------------------------------
// Keys, envelope, signature
// ---------------------------------------------------------------------------------------------

// ParseDeploymentRootKey parses the root public key: SEC1 uncompressed P-256, 130 lowercase hex
// characters. A point that is not on the curve is refused.
func ParseDeploymentRootKey(s string) (*ecdsa.PublicKey, error) {
	if len(s) != 130 || !isLowerHex(s) {
		return nil, soErr(SignedObjectBadKey, "root key must be 130 lowercase hex characters (SEC1 uncompressed P-256)")
	}
	raw, _ := hex.DecodeString(s)
	if raw[0] != 0x04 {
		return nil, soErr(SignedObjectBadKey, "root key must be an uncompressed point (0x04 prefix)")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, soErr(SignedObjectBadKey, "root key is not a valid P-256 point: %v", err)
	}
	return pub, nil
}

// DeploymentRootKeyHex is ParseDeploymentRootKey's inverse.
func DeploymentRootKeyHex(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// SignedObjectDigest is the one hash both signer and verifiers compute: SHA-256(domain || body).
func SignedObjectDigest(domain string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(body)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// EncodeSignedObject builds the envelope around a body and its 64-byte r||s signature. It holds no
// key and checks nothing; the signer verifies what it built before writing it.
func EncodeSignedObject(body []byte, sig [64]byte) []byte {
	return []byte(`{"format":1,"body":"` + base64.StdEncoding.EncodeToString(body) +
		`","sig":"` + hex.EncodeToString(sig[:]) + `"}`)
}

// openSignedObject runs checks 1-3 and returns the signed body bytes.
func openSignedObject(root *ecdsa.PublicKey, domain string, raw []byte) ([]byte, error) {
	if root == nil || root.Curve != elliptic.P256() {
		return nil, soErr(SignedObjectBadKey, "no P-256 root key")
	}
	if len(raw) > MaxSignedObjectBytes {
		return nil, soErr(SignedObjectBadEnvelope, "signed object is %d bytes, over the %d-byte limit", len(raw), MaxSignedObjectBytes)
	}
	if !utf8.Valid(raw) {
		return nil, soErr(SignedObjectBadEnvelope, "signed object is not valid UTF-8")
	}
	p := &strictJSON{b: raw, what: "envelope"}
	var format int64
	var bodyB64, sigHex string
	err := p.object([]string{"format", "body", "sig"}, func(key string) error {
		var err error
		switch key {
		case "format":
			format, err = p.integer()
		case "body":
			bodyB64, err = p.str()
		case "sig":
			sigHex, err = p.str()
		}
		return err
	})
	if err != nil {
		return nil, soWrap(SignedObjectBadEnvelope, err)
	}
	p.skipSpace()
	if p.i != len(p.b) {
		return nil, soErr(SignedObjectBadEnvelope, "trailing data after the envelope")
	}
	if format != SignedObjectFormat {
		return nil, soErr(SignedObjectBadEnvelope, "format %d is not supported (expected %d)", format, SignedObjectFormat)
	}
	if bodyB64 == "" {
		return nil, soErr(SignedObjectBadEnvelope, "empty body")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(bodyB64)
	// Go's decoder skips CR and LF even in Strict mode, so also require the canonical spelling:
	// exactly one base64 text per body, which is what Rust's and CNG's strict decoders accept.
	if err != nil || base64.StdEncoding.EncodeToString(body) != bodyB64 {
		return nil, soErr(SignedObjectBadEnvelope, "body is not canonical standard padded base64")
	}
	if len(sigHex) != 128 || !isLowerHex(sigHex) {
		return nil, soErr(SignedObjectBadEnvelope, "sig must be 128 lowercase hex characters (r || s)")
	}
	sig, _ := hex.DecodeString(sigHex)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, soErr(SignedObjectBadSignature, "r or s is outside [1, n-1]")
	}
	digest := SignedObjectDigest(domain, body)
	if !ecdsa.Verify(root, digest[:], r, s) {
		return nil, soErr(SignedObjectBadSignature, "signature does not verify under the root key for this purpose")
	}
	return body, nil
}

// ---------------------------------------------------------------------------------------------
// Deployment pass
// ---------------------------------------------------------------------------------------------

// DeploymentPass is a VERIFIED pass: only VerifyDeploymentPass makes a non-zero one, and its values
// cannot be changed after verification (Claims returns a copy). Its values are the only ones a
// caller may use for display, provisioning or network calls.
type DeploymentPass struct {
	c  DeploymentPassClaims
	ok bool // set only by VerifyDeploymentPass; the zero value is "not verified"
}

// Claims returns a copy of the verified claims.
func (p DeploymentPass) Claims() DeploymentPassClaims { return p.c }

// Verified reports whether p came from VerifyDeploymentPass (a zero DeploymentPass did not).
func (p DeploymentPass) Verified() bool { return p.ok }

// errNotVerified: a zero-value pass or release reached an API that needs a verified one, most
// likely after a verification error was ignored. Refused rather than evaluated.
var errNotVerified = soErr(SignedObjectBadSignature, "not a verified object (zero value)")

// DeploymentPassClaims is the signer's input and the verified pass's content.
type DeploymentPassClaims struct {
	PassID            string
	IssuedTo          string
	Origin            string // https://host[:port], canonical
	GrantIssuerPubkey string // 64 lowercase hex
	ForSetup          bool
	ForSupport        bool
	MinAgentVersion   string // A.B.C, Windows Installer limits
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

// HostPort is the origin without its scheme: what the consent dialogs show as "Server:".
func (p DeploymentPass) HostPort() string { return strings.TrimPrefix(p.c.Origin, "https://") }

// ControlPlaneURL is derived, never carried: origin + "/cp".
func (p DeploymentPass) ControlPlaneURL() string { return p.c.Origin + "/cp" }

// SignalingURL is derived, never carried: wss://host[:port]/ws.
func (p DeploymentPass) SignalingURL() string { return "wss://" + p.HostPort() + "/ws" }

// CheckValidAt applies check 5 at now (the control plane re-checks at bundle issuance).
func (p DeploymentPass) CheckValidAt(now time.Time) error {
	if !p.ok {
		return errNotVerified
	}
	return checkWindow("deployment pass", p.c.IssuedAt, p.c.ExpiresAt, now)
}

// VerifyDeploymentPass runs every check on a pass file's bytes, at now.
func VerifyDeploymentPass(root *ecdsa.PublicKey, raw []byte, now time.Time) (DeploymentPass, error) {
	body, err := openSignedObject(root, DeploymentPassDomain, raw)
	if err != nil {
		return DeploymentPass{}, err
	}
	c, err := parseDeploymentPassBody(body)
	if err != nil {
		return DeploymentPass{}, err
	}
	p := DeploymentPass{c: c, ok: true}
	if err := p.CheckValidAt(now); err != nil {
		return DeploymentPass{}, err
	}
	return p, nil
}

// parseDeploymentPassBody runs check 4 on a pass body. It does not look at the clock, and it is
// unexported so nothing outside this file can hold pass values that skipped the signature.
func parseDeploymentPassBody(body []byte) (DeploymentPassClaims, error) {
	var p DeploymentPassClaims
	if err := checkBodyBytes(body); err != nil {
		return p, err
	}
	sp := &strictJSON{b: body, what: "pass body"}
	var purpose, issuedAt, expiresAt string
	var v int64
	var uses []string
	keys := []string{"purpose", "v", "pass_id", "issued_to", "origin", "grant_issuer_pubkey", "uses", "min_agent_version", "issued_at", "expires_at"}
	err := sp.object(keys, func(key string) error {
		var err error
		switch key {
		case "purpose":
			purpose, err = sp.str()
		case "v":
			v, err = sp.integer()
		case "pass_id":
			p.PassID, err = sp.str()
		case "issued_to":
			p.IssuedTo, err = sp.str()
		case "origin":
			p.Origin, err = sp.str()
		case "grant_issuer_pubkey":
			p.GrantIssuerPubkey, err = sp.str()
		case "uses":
			uses, err = sp.strArray()
		case "min_agent_version":
			p.MinAgentVersion, err = sp.str()
		case "issued_at":
			issuedAt, err = sp.str()
		case "expires_at":
			expiresAt, err = sp.str()
		}
		return err
	})
	if err == nil {
		sp.skipSpace()
		if sp.i != len(sp.b) {
			err = sp.errf("trailing data after the body")
		}
	}
	if err != nil {
		return DeploymentPassClaims{}, soWrap(SignedObjectBadBody, err)
	}
	fail := func(field string, err error) (DeploymentPassClaims, error) {
		return DeploymentPassClaims{}, soErr(SignedObjectBadBody, "%s: %v", field, err)
	}
	if purpose != DeploymentPassPurpose {
		return fail("purpose", fmt.Errorf("%q is not %q", purpose, DeploymentPassPurpose))
	}
	if v != 1 {
		return fail("v", fmt.Errorf("version %d is not supported (expected 1)", v))
	}
	if err := checkPassUUID(p.PassID); err != nil {
		return fail("pass_id", err)
	}
	if err := checkIssuedTo(p.IssuedTo); err != nil {
		return fail("issued_to", err)
	}
	if err := CheckDeploymentOrigin(p.Origin); err != nil {
		return fail("origin", err)
	}
	if len(p.GrantIssuerPubkey) != 64 || !isLowerHex(p.GrantIssuerPubkey) {
		return fail("grant_issuer_pubkey", errors.New("expected 64 lowercase hex characters"))
	}
	if len(uses) == 0 {
		return fail("uses", errors.New("must name at least one of setup, support"))
	}
	for _, u := range uses {
		switch {
		case u == "setup" && !p.ForSetup:
			p.ForSetup = true
		case u == "support" && !p.ForSupport:
			p.ForSupport = true
		case u == "setup" || u == "support":
			return fail("uses", fmt.Errorf("%q is listed twice", u))
		default:
			return fail("uses", fmt.Errorf("%q is not setup or support", u))
		}
	}
	if err := checkUpdateProductVersion(p.MinAgentVersion); err != nil {
		return fail("min_agent_version", err)
	}
	if p.IssuedAt, err = parsePassTime(issuedAt); err != nil {
		return fail("issued_at", err)
	}
	if p.ExpiresAt, err = parsePassTime(expiresAt); err != nil {
		return fail("expires_at", err)
	}
	if err := checkLifetime(p.IssuedAt, p.ExpiresAt, DeploymentPassMaxLifetime); err != nil {
		return fail("expires_at", err)
	}
	return p, nil
}

// EncodeDeploymentPassBody produces the canonical compact body for p, and refuses any p whose body
// the verifier would not read back exactly. Used by the signer and the tests.
func EncodeDeploymentPassBody(p DeploymentPassClaims) ([]byte, error) {
	var uses []string
	if p.ForSetup {
		uses = append(uses, "setup")
	}
	if p.ForSupport {
		uses = append(uses, "support")
	}
	body, err := encodeCompact(struct {
		Purpose           string   `json:"purpose"`
		V                 int      `json:"v"`
		PassID            string   `json:"pass_id"`
		IssuedTo          string   `json:"issued_to"`
		Origin            string   `json:"origin"`
		GrantIssuerPubkey string   `json:"grant_issuer_pubkey"`
		Uses              []string `json:"uses"`
		MinAgentVersion   string   `json:"min_agent_version"`
		IssuedAt          string   `json:"issued_at"`
		ExpiresAt         string   `json:"expires_at"`
	}{DeploymentPassPurpose, 1, p.PassID, p.IssuedTo, p.Origin, p.GrantIssuerPubkey, uses,
		p.MinAgentVersion, p.IssuedAt.UTC().Format(PassTimeLayout), p.ExpiresAt.UTC().Format(PassTimeLayout)})
	if err != nil {
		return nil, err
	}
	back, err := parseDeploymentPassBody(body)
	if err != nil {
		return nil, err
	}
	if back != p {
		return nil, errors.New("pass does not round-trip (timestamps must be whole seconds in UTC)")
	}
	return body, nil
}

// ---------------------------------------------------------------------------------------------
// Agent release attestation
// ---------------------------------------------------------------------------------------------

// AgentRelease is a VERIFIED release attestation; only VerifyAgentRelease makes a non-zero one.
type AgentRelease struct {
	c  AgentReleaseClaims
	ok bool // set only by VerifyAgentRelease
}

// Claims returns a copy of the verified claims.
func (r AgentRelease) Claims() AgentReleaseClaims { return r.c }

// Verified reports whether r came from VerifyAgentRelease.
func (r AgentRelease) Verified() bool { return r.ok }

// AgentReleaseClaims is the signer's input and the verified attestation's content.
type AgentReleaseClaims struct {
	MSISHA256      string // 64 lowercase hex
	MSISize        int64
	ProductVersion string // A.B.C, Windows Installer limits
	ProductCode    string // braced uppercase GUID
	UpgradeCode    string // braced uppercase GUID
	Arch           string // "x64"
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

// MaxAttestedMSISize keeps msi_size inside a signed 32-bit integer for every implementation.
const MaxAttestedMSISize = 1<<31 - 1

// CheckValidAt applies check 5 at now.
func (r AgentRelease) CheckValidAt(now time.Time) error {
	if !r.ok {
		return errNotVerified
	}
	return checkWindow("agent release attestation", r.c.IssuedAt, r.c.ExpiresAt, now)
}

// VerifyAgentRelease runs every check on an attestation file's bytes, at now.
func VerifyAgentRelease(root *ecdsa.PublicKey, raw []byte, now time.Time) (AgentRelease, error) {
	body, err := openSignedObject(root, AgentReleaseDomain, raw)
	if err != nil {
		return AgentRelease{}, err
	}
	c, err := parseAgentReleaseBody(body)
	if err != nil {
		return AgentRelease{}, err
	}
	r := AgentRelease{c: c, ok: true}
	if err := r.CheckValidAt(now); err != nil {
		return AgentRelease{}, err
	}
	return r, nil
}

// parseAgentReleaseBody runs check 4 on a release attestation body (unexported, as for passes).
func parseAgentReleaseBody(body []byte) (AgentReleaseClaims, error) {
	var r AgentReleaseClaims
	if err := checkBodyBytes(body); err != nil {
		return r, err
	}
	sp := &strictJSON{b: body, what: "release body"}
	var purpose, issuedAt, expiresAt string
	var v int64
	keys := []string{"purpose", "v", "msi_sha256", "msi_size", "product_version", "product_code", "upgrade_code", "arch", "issued_at", "expires_at"}
	err := sp.object(keys, func(key string) error {
		var err error
		switch key {
		case "purpose":
			purpose, err = sp.str()
		case "v":
			v, err = sp.integer()
		case "msi_sha256":
			r.MSISHA256, err = sp.str()
		case "msi_size":
			r.MSISize, err = sp.integer()
		case "product_version":
			r.ProductVersion, err = sp.str()
		case "product_code":
			r.ProductCode, err = sp.str()
		case "upgrade_code":
			r.UpgradeCode, err = sp.str()
		case "arch":
			r.Arch, err = sp.str()
		case "issued_at":
			issuedAt, err = sp.str()
		case "expires_at":
			expiresAt, err = sp.str()
		}
		return err
	})
	if err == nil {
		sp.skipSpace()
		if sp.i != len(sp.b) {
			err = sp.errf("trailing data after the body")
		}
	}
	if err != nil {
		return AgentReleaseClaims{}, soWrap(SignedObjectBadBody, err)
	}
	fail := func(field string, err error) (AgentReleaseClaims, error) {
		return AgentReleaseClaims{}, soErr(SignedObjectBadBody, "%s: %v", field, err)
	}
	if purpose != AgentReleasePurpose {
		return fail("purpose", fmt.Errorf("%q is not %q", purpose, AgentReleasePurpose))
	}
	if v != 1 {
		return fail("v", fmt.Errorf("version %d is not supported (expected 1)", v))
	}
	if len(r.MSISHA256) != 64 || !isLowerHex(r.MSISHA256) {
		return fail("msi_sha256", errors.New("expected 64 lowercase hex characters"))
	}
	if r.MSISize < 1 || r.MSISize > MaxAttestedMSISize {
		return fail("msi_size", fmt.Errorf("%d is outside [1, %d]", r.MSISize, MaxAttestedMSISize))
	}
	if err := checkUpdateProductVersion(r.ProductVersion); err != nil {
		return fail("product_version", err)
	}
	if err := checkUpdateBracedGUID(r.ProductCode); err != nil {
		return fail("product_code", err)
	}
	if err := checkUpdateBracedGUID(r.UpgradeCode); err != nil {
		return fail("upgrade_code", err)
	}
	if r.Arch != "x64" {
		return fail("arch", fmt.Errorf("%q is not x64", r.Arch))
	}
	if r.IssuedAt, err = parsePassTime(issuedAt); err != nil {
		return fail("issued_at", err)
	}
	if r.ExpiresAt, err = parsePassTime(expiresAt); err != nil {
		return fail("expires_at", err)
	}
	if err := checkLifetime(r.IssuedAt, r.ExpiresAt, AgentReleaseMaxLifetime); err != nil {
		return fail("expires_at", err)
	}
	return r, nil
}

// EncodeAgentReleaseBody is EncodeDeploymentPassBody's twin.
func EncodeAgentReleaseBody(r AgentReleaseClaims) ([]byte, error) {
	body, err := encodeCompact(struct {
		Purpose        string `json:"purpose"`
		V              int    `json:"v"`
		MSISHA256      string `json:"msi_sha256"`
		MSISize        int64  `json:"msi_size"`
		ProductVersion string `json:"product_version"`
		ProductCode    string `json:"product_code"`
		UpgradeCode    string `json:"upgrade_code"`
		Arch           string `json:"arch"`
		IssuedAt       string `json:"issued_at"`
		ExpiresAt      string `json:"expires_at"`
	}{AgentReleasePurpose, 1, r.MSISHA256, r.MSISize, r.ProductVersion, r.ProductCode, r.UpgradeCode,
		r.Arch, r.IssuedAt.UTC().Format(PassTimeLayout), r.ExpiresAt.UTC().Format(PassTimeLayout)})
	if err != nil {
		return nil, err
	}
	back, err := parseAgentReleaseBody(body)
	if err != nil {
		return nil, err
	}
	if back != r {
		return nil, errors.New("attestation does not round-trip (timestamps must be whole seconds in UTC)")
	}
	return body, nil
}

// PassAdmitsRelease reports whether a pass's min_agent_version admits a release's product version.
func PassAdmitsRelease(p DeploymentPass, r AgentRelease) error {
	if !p.ok || !r.ok {
		return errNotVerified
	}
	if compareProductVersions(r.c.ProductVersion, p.c.MinAgentVersion) < 0 {
		return fmt.Errorf("agent release %s is older than the pass's min_agent_version %s", r.c.ProductVersion, p.c.MinAgentVersion)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Field rules
// ---------------------------------------------------------------------------------------------

// CheckDeploymentOrigin accepts exactly https://<host>[:<port>]: lowercase ASCII LDH labels
// (internationalised names in punycode), no trailing dot, the default port omitted, and no path,
// userinfo, query or fragment. One canonical spelling per server, so equality is string equality.
func CheckDeploymentOrigin(s string) error {
	const scheme = "https://"
	if !strings.HasPrefix(s, scheme) {
		return errors.New("must start with https://")
	}
	host := s[len(scheme):]
	port := ""
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host, port = host[:i], host[i+1:]
		if port == "" {
			return errors.New("empty port")
		}
	}
	if host == "" || len(host) > 253 {
		return errors.New("host must be 1-253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("each host label must be 1-63 characters (no empty labels or trailing dot)")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("a host label starts or ends with '-'")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return fmt.Errorf("host may contain only a-z, 0-9, '-' and '.' (got %q); use punycode and no path, userinfo, query or fragment", string(c))
			}
		}
	}
	if port != "" {
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return errors.New("port must be decimal digits only, with nothing after it")
			}
		}
		if port[0] == '0' || len(port) > 5 {
			return errors.New("port must be 1-65535 without leading zeros")
		}
		n, _ := strconv.Atoi(port)
		if n > 65535 {
			return errors.New("port must be 1-65535")
		}
		if n == 443 {
			return errors.New("omit the default port 443")
		}
	}
	return nil
}

// checkIssuedTo: 1-64 characters from [A-Za-z0-9 .,&'()-].
func checkIssuedTo(s string) error {
	if len(s) < 1 || len(s) > 64 {
		return errors.New("must be 1-64 characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte(" .,&'()-", c) >= 0
		if !ok {
			return fmt.Errorf("character %q is not allowed (A-Z a-z 0-9 space . , & ' ( ) -)", string(c))
		}
	}
	return nil
}

// checkPassUUID: canonical lowercase 8-4-4-4-12.
func checkPassUUID(s string) error {
	if len(s) != 36 {
		return errors.New("expected a 36-character lowercase UUID")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return errors.New("expected the 8-4-4-4-12 dash layout")
			}
		default:
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
				return errors.New("expected lowercase hex only")
			}
		}
	}
	return nil
}

func parsePassTime(s string) (time.Time, error) {
	t, err := time.Parse(PassTimeLayout, s)
	if err != nil || t.Format(PassTimeLayout) != s {
		return time.Time{}, fmt.Errorf("%q is not YYYY-MM-DDTHH:MM:SSZ (UTC, whole seconds)", s)
	}
	return t, nil
}

func checkLifetime(issued, expires time.Time, max time.Duration) error {
	if !expires.After(issued) {
		return errors.New("expires_at must be after issued_at")
	}
	if expires.Sub(issued) > max {
		return fmt.Errorf("lifetime %s exceeds the %s maximum", expires.Sub(issued), max)
	}
	return nil
}

func checkWindow(what string, issued, expires, now time.Time) error {
	if now.Before(issued.Add(-SignedObjectClockSkew)) {
		return soErr(SignedObjectNotValidNow, "%s is not valid until %s", what, issued.Format(PassTimeLayout))
	}
	if !now.Before(expires) {
		return soErr(SignedObjectNotValidNow, "%s expired at %s", what, expires.Format(PassTimeLayout))
	}
	return nil
}

// checkBodyBytes: size, no control bytes (so no NUL and no whitespace other than space), UTF-8.
func checkBodyBytes(body []byte) error {
	if len(body) > MaxSignedBodyBytes {
		return soErr(SignedObjectBadBody, "body is %d bytes, over the %d-byte limit", len(body), MaxSignedBodyBytes)
	}
	for i, c := range body {
		if c < 0x20 || c == 0x7f {
			return soErr(SignedObjectBadBody, "control byte 0x%02x at %d", c, i)
		}
	}
	if !utf8.Valid(body) {
		return soErr(SignedObjectBadBody, "body is not valid UTF-8")
	}
	return nil
}

func compareProductVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func encodeCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// strArray parses a JSON array of strings.
func (p *strictJSON) strArray() ([]string, error) {
	if p.i >= len(p.b) || p.b[p.i] != '[' {
		return nil, p.errf("expected an array")
	}
	p.i++
	out := []string{}
	for first := true; ; first = false {
		p.skipSpace()
		if p.i >= len(p.b) {
			return nil, p.errf("unexpected end of input")
		}
		if p.b[p.i] == ']' {
			p.i++
			return out, nil
		}
		if !first {
			if p.b[p.i] != ',' {
				return nil, p.errf("expected ',' or ']'")
			}
			p.i++
			p.skipSpace()
		}
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}
