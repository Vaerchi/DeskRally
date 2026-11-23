package controlplane

// Signed fleet directives (docs/65 F2 + D-C3 + D-C8): RMTDIRECTIVEv1, the artifact the control plane
// hands an agent to reinstall or remove itself, and RMTDIRACKv1, the device-key-signed acknowledgement
// that comes back.
//
// A DEDICATED KEY (D-C3). Directives are signed by the key derived from DIRECTIVE_SIGNING_SEED, never by
// the grant issuer (GRANT_ISSUER_SEED). The grant issuer signs everything a technician session needs, so a
// compromise of that one key must not also be able to order a fleet wipe; and an agent pins THIS key
// separately (at enrollment, from the enroll response, or via the MSI property DIRECTIVE_PUBKEY), so a
// compromised grant signer cannot swap it. An agent with no pinned directive key refuses every directive.
//
// RMTDIRECTIVEv1 preimage (all integers big-endian; lp = u32 length prefix + bytes):
//
//	[0..15]  "RMTDIRECTIVEv1\x00\x00"        domain tag (16 bytes)
//	u8       version (1)
//	16 bytes tenant id (raw UUID)
//	lp       device id (UTF-8, as stored)
//	16 bytes directive id (raw UUID)
//	lp       kind ("reinstall" | "uninstall")
//	32 bytes enrollment generation = SHA-256 of the device's pinned Ed25519 public key
//	16 bytes nonce
//	i64      issued_at_ms
//	i64      expires_at_ms
//
// The wire form is {"claims":{...},"sig":"<hex ed25519>"}; the claim field names are the contract the Rust
// verifier loads from testdata/directive-vectors.json (positive AND negative vectors, same fixture).
//
// RMTDIRACKv1 preimage (signed by the DEVICE key; the control plane verifies it against the key pinned for
// the device, so signaling - which only relays - can neither forge nor alter an acknowledgement):
//
//	[0..15]  "RMTDIRACKv1\x00\x00\x00\x00\x00"  domain tag (16 bytes)
//	u8       version (1)
//	16 bytes tenant id
//	lp       device id
//	16 bytes directive id
//	32 bytes enrollment generation (key fingerprint)
//	lp       from state
//	lp       to state
//	i64      ts_ms
//	lp       detail (UTF-8, <= 256 bytes)
//
// from/to bind the acknowledgement to ONE valid state transition: a captured ack cannot be replayed as a
// different transition, and an exact replay of the transition the row already shows is a no-op.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// directiveDomainTag: ASCII "RMTDIRECTIVEv1" + two 0x00 bytes (16 bytes). Distinct from every other tag
	// this repo signs (TestDirectiveTagsAreDistinct): none is a prefix of another.
	directiveDomainTag = []byte("RMTDIRECTIVEv1\x00\x00")
	// directiveAckDomainTag: ASCII "RMTDIRACKv1" + five 0x00 bytes (16 bytes).
	directiveAckDomainTag = []byte("RMTDIRACKv1\x00\x00\x00\x00\x00")
)

const (
	directiveVersion = 1

	// DirectiveFeature is what the control plane advertises on GET /internal/capabilities, what signaling
	// advertises to an agent in Registered.Features, and what the agent advertises back at register_agent.
	DirectiveFeature = "directive_v1"

	// Maximum lifetimes (D-C5: an agent rejects lifetimes beyond the maximum for the kind).
	directiveReinstallTTL = 24 * time.Hour
	directiveUninstallTTL = time.Hour
	// directiveClockSkew is how far in the future an issued_at may be and still verify (D-C5: 2 minutes).
	directiveClockSkew = 2 * time.Minute

	maxDirectiveDetailBytes = 256
)

// DirectiveKind is what a directive orders.
type DirectiveKind string

const (
	DirectiveReinstall DirectiveKind = "reinstall"
	DirectiveUninstall DirectiveKind = "uninstall"
)

// Valid reports whether k is a kind the agent understands.
func (k DirectiveKind) Valid() bool { return k == DirectiveReinstall || k == DirectiveUninstall }

// maxTTL is the longest lifetime a directive of this kind may carry.
func (k DirectiveKind) maxTTL() time.Duration {
	if k == DirectiveUninstall {
		return directiveUninstallTTL
	}
	return directiveReinstallTTL
}

// DirectiveClaims is the signed content of one directive.
type DirectiveClaims struct {
	TenantID    string `json:"tenant_id"`
	DeviceID    string `json:"device_id"`
	DirectiveID string `json:"directive_id"`
	Kind        string `json:"kind"`
	KeyFP       string `json:"key_fp"` // hex SHA-256 of the pinned device public key
	Nonce       string `json:"nonce"`  // hex, 16 bytes
	IssuedAtMs  int64  `json:"issued_at_ms"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// SignedDirective is the wire artifact.
type SignedDirective struct {
	Claims DirectiveClaims `json:"claims"`
	Sig    string          `json:"sig"`
}

// KeyFingerprint is the enrollment generation of a device key: lowercase hex SHA-256 of the raw 32-byte
// public key given as hex. A different key (a re-enrollment) is a different generation.
func KeyFingerprint(pubkeyHex string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pubkeyHex))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", errors.New("pubkey is not a hex-encoded 32-byte Ed25519 key")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func fpBytes(fp string) ([]byte, error) {
	raw, err := hex.DecodeString(fp)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("key_fp is not 32 hex-encoded bytes")
	}
	return raw, nil
}

// directiveSigningBytes builds the canonical RMTDIRECTIVEv1 preimage.
func directiveSigningBytes(c DirectiveClaims) ([]byte, error) {
	if !DirectiveKind(c.Kind).Valid() {
		return nil, fmt.Errorf("directive kind: unknown kind %q", c.Kind)
	}
	tenant, err := uuidBytes(c.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_id: %w", err)
	}
	dir, err := uuidBytes(c.DirectiveID)
	if err != nil {
		return nil, fmt.Errorf("directive_id: %w", err)
	}
	if c.DeviceID == "" {
		return nil, errors.New("device_id is empty")
	}
	fp, err := fpBytes(c.KeyFP)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 16 {
		return nil, errors.New("nonce is not 16 hex-encoded bytes")
	}
	var w canonicalWriter
	w.buf = append(w.buf, directiveDomainTag...)
	w.u8(directiveVersion)
	w.raw16(tenant)
	w.lpStr(c.DeviceID)
	w.raw16(dir)
	w.lpStr(c.Kind)
	w.buf = append(w.buf, fp...)
	w.buf = append(w.buf, nonce...)
	w.i64(c.IssuedAtMs)
	w.i64(c.ExpiresAtMs)
	return w.buf, nil
}

// DirectiveIssuer signs directives with the dedicated directive key.
type DirectiveIssuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewDirectiveIssuer derives the issuer from a 32-byte seed (DIRECTIVE_SIGNING_SEED, 64 hex chars).
func NewDirectiveIssuer(seed []byte) (*DirectiveIssuer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("directive signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &DirectiveIssuer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// NewDirectiveIssuerFromHex is NewDirectiveIssuer over a hex seed, refusing the all-zero placeholder.
func NewDirectiveIssuerFromHex(seedHex string) (*DirectiveIssuer, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, errors.New("DIRECTIVE_SIGNING_SEED must be hex")
	}
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
		}
	}
	if allZero {
		return nil, errors.New("DIRECTIVE_SIGNING_SEED is all zeros (a placeholder, not a key)")
	}
	return NewDirectiveIssuer(seed)
}

// PublicKeyHex is the key an agent pins (lowercase hex, 64 chars).
func (d *DirectiveIssuer) PublicKeyHex() string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.pub)
}

// newDirectiveNonce returns 16 random bytes (crypto/rand; no weaker fallback).
func newDirectiveNonce() ([]byte, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("directive nonce: %w", err)
	}
	return n, nil
}

// Sign signs claims and returns the wire JSON.
func (d *DirectiveIssuer) Sign(c DirectiveClaims) (string, error) {
	if d == nil {
		return "", errors.New("no directive issuer configured")
	}
	msg, err := directiveSigningBytes(c)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(SignedDirective{Claims: c, Sig: hex.EncodeToString(ed25519.Sign(d.priv, msg))})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DirectiveVerifyError carries the machine-readable reason a directive was refused. The codes are the
// "expect" values of the negative vectors in testdata/directive-vectors.json.
type DirectiveVerifyError struct{ Code string }

func (e *DirectiveVerifyError) Error() string { return "directive refused: " + e.Code }

// Verification codes, in check order (key, envelope, signature, binding, validity).
const (
	DirectiveRefusedNoKey           = "no_pinned_key"
	DirectiveRefusedMalformed       = "malformed"
	DirectiveRefusedSignature       = "signature"
	DirectiveRefusedDevice          = "device_mismatch"
	DirectiveRefusedTenant          = "tenant_mismatch"
	DirectiveRefusedKeyFP           = "key_fp_mismatch"
	DirectiveRefusedKind            = "unknown_kind"
	DirectiveRefusedNotYetValid     = "not_yet_valid"
	DirectiveRefusedExpired         = "expired"
	DirectiveRefusedLifetimeTooLong = "lifetime_too_long"
)

// DirectiveExpectation is what the verifying party knows about itself.
type DirectiveExpectation struct {
	DeviceID string
	TenantID string
	KeyFP    string
	NowMs    int64
}

// VerifyDirective is the reference verifier (the Rust agent implements the same checks in the same order
// and loads the same vectors). pub is the pinned directive key; nil/empty refuses everything.
func VerifyDirective(pub ed25519.PublicKey, artifact string, exp DirectiveExpectation) (*DirectiveClaims, error) {
	refuse := func(code string) (*DirectiveClaims, error) { return nil, &DirectiveVerifyError{Code: code} }
	if len(pub) != ed25519.PublicKeySize {
		return refuse(DirectiveRefusedNoKey)
	}
	var sd SignedDirective
	dec := json.NewDecoder(strings.NewReader(artifact))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sd); err != nil {
		return refuse(DirectiveRefusedMalformed)
	}
	sig, err := hex.DecodeString(sd.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return refuse(DirectiveRefusedMalformed)
	}
	c := sd.Claims
	if !DirectiveKind(c.Kind).Valid() {
		// An unknown kind has no defined preimage; refuse before signature so the code is specific.
		return refuse(DirectiveRefusedKind)
	}
	msg, err := directiveSigningBytes(c)
	if err != nil {
		return refuse(DirectiveRefusedMalformed)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return refuse(DirectiveRefusedSignature)
	}
	if c.DeviceID != exp.DeviceID {
		return refuse(DirectiveRefusedDevice)
	}
	if canonicalUUIDish(c.TenantID) != canonicalUUIDish(exp.TenantID) {
		return refuse(DirectiveRefusedTenant)
	}
	if c.KeyFP != exp.KeyFP {
		return refuse(DirectiveRefusedKeyFP)
	}
	issued, expires := time.UnixMilli(c.IssuedAtMs), time.UnixMilli(c.ExpiresAtMs)
	now := time.UnixMilli(exp.NowMs)
	if issued.After(now.Add(directiveClockSkew)) {
		return refuse(DirectiveRefusedNotYetValid)
	}
	if !expires.After(now) {
		return refuse(DirectiveRefusedExpired)
	}
	if expires.Sub(issued) > DirectiveKind(c.Kind).maxTTL() || !expires.After(issued) {
		return refuse(DirectiveRefusedLifetimeTooLong)
	}
	return &c, nil
}

// ---------------------------------------------------------------------------------------------------
// Acknowledgements (D-C8)
// ---------------------------------------------------------------------------------------------------

// DirectiveAck is the body an agent sends (relayed by signaling): the transition it claims, signed by the
// device key. The control plane derives tenant, device, key fingerprint and directive id from the STORED
// row when it verifies, so none of those are trusted from the message.
type DirectiveAck struct {
	DirectiveID string `json:"directive_id"`
	From        string `json:"from"`
	To          string `json:"to"`
	TsMs        int64  `json:"ts_ms"`
	Detail      string `json:"detail,omitempty"`
	Sig         string `json:"sig"`
}

// directiveAckSigningBytes builds the canonical RMTDIRACKv1 preimage.
func directiveAckSigningBytes(tenantID, deviceID, directiveID, keyFP, from, to string, tsMs int64, detail string) ([]byte, error) {
	tenant, err := uuidBytes(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_id: %w", err)
	}
	dir, err := uuidBytes(directiveID)
	if err != nil {
		return nil, fmt.Errorf("directive_id: %w", err)
	}
	fp, err := fpBytes(keyFP)
	if err != nil {
		return nil, err
	}
	if len(detail) > maxDirectiveDetailBytes {
		return nil, errors.New("detail too long")
	}
	var w canonicalWriter
	w.buf = append(w.buf, directiveAckDomainTag...)
	w.u8(directiveVersion)
	w.raw16(tenant)
	w.lpStr(deviceID)
	w.raw16(dir)
	w.buf = append(w.buf, fp...)
	w.lpStr(from)
	w.lpStr(to)
	w.i64(tsMs)
	w.lpStr(detail)
	return w.buf, nil
}

// VerifyDirectiveAck checks an ack's signature against the device's pinned public key, over values taken
// from the stored directive row (tenant, device, key fingerprint, directive id) plus the claimed transition.
func VerifyDirectiveAck(devicePub ed25519.PublicKey, tenantID, deviceID, directiveID, keyFP string, a DirectiveAck) bool {
	if len(devicePub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := directiveAckSigningBytes(tenantID, deviceID, directiveID, keyFP, a.From, a.To, a.TsMs, a.Detail)
	if err != nil {
		return false
	}
	return ed25519.Verify(devicePub, msg, sig)
}

// SignDirectiveAck is the reference signer (used by tests and the vector generator; the real signer is the
// agent).
func SignDirectiveAck(devicePriv ed25519.PrivateKey, tenantID, deviceID, directiveID, keyFP, from, to string, tsMs int64, detail string) (DirectiveAck, error) {
	msg, err := directiveAckSigningBytes(tenantID, deviceID, directiveID, keyFP, from, to, tsMs, detail)
	if err != nil {
		return DirectiveAck{}, err
	}
	return DirectiveAck{
		DirectiveID: directiveID, From: from, To: to, TsMs: tsMs, Detail: detail,
		Sig: hex.EncodeToString(ed25519.Sign(devicePriv, msg)),
	}, nil
}

// NamedSigningKey is a public key the control plane holds a private half for, with the name an operator
// would recognise it by.
type NamedSigningKey struct {
	Name      string
	PublicHex string
}

// CheckDirectiveKeyDistinct refuses a directive key that is also another signer's key (docs/65 D-C3 /
// review): a directive key equal to the grant issuer (which also signs elevation grants, session policies
// and session-end artifacts) would let one compromised seed forge a fleet wipe, which is exactly what the
// dedicated key exists to prevent. Keys compare case-insensitively; empty entries are ignored. The error
// names the clashing signer.
func CheckDirectiveKeyDistinct(directivePubHex string, others ...NamedSigningKey) error {
	dir := strings.ToLower(strings.TrimSpace(directivePubHex))
	if dir == "" {
		return errors.New("the directive public key is empty")
	}
	for _, o := range others {
		if p := strings.ToLower(strings.TrimSpace(o.PublicHex)); p != "" && p == dir {
			return fmt.Errorf("DIRECTIVE_SIGNING_SEED derives the same public key as the %s: the directive key must be a DEDICATED key", o.Name)
		}
	}
	return nil
}
