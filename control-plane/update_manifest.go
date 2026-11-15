package controlplane

// The signed agent-update MANIFEST (docs/21 §3, step 2 of §8) — its canonical signing bytes, its
// wire shape, and its VERIFICATION. Its Rust twin is `rmt_agent::update` (agent/src/update.rs), and
// the agent is the party that enforces it.
//
// ===========================================================================================
// THIS FILE DELIBERATELY CANNOT SIGN. Read this before adding anything to it.
// ===========================================================================================
//
// docs/21 §3 makes a claim that has to be true of the SHIPPED BINARY, not merely of its call graph:
// "the control plane stores and serves an already-signed manifest and CANNOT MINT ONE." So the
// split here is not stylistic:
//
//   - canonical bytes + verification live here, in package `controlplane`, which is linked into
//     `cmd/controlplane`;
//   - `ed25519.Sign` over these bytes lives ONLY in `control-plane/cmd/rmt-update-sign`, a separate
//     `package main` that is a separate binary and is never imported by the server.
//
// `UpdateManifestSigningBytes` is exported for that offline signer's benefit. Exporting the PREIMAGE
// costs nothing — the preimage is public information, printed in the golden vectors — while the
// SIGNATURE requires the key, and the key never comes near this process. `TestServerPackageCannotSign`
// (update_manifest_test.go) fails the build if either half of the split is quietly undone.
//
// ===========================================================================================
// WHY THIS ARTIFACT DOES NOT SHARE THE GRANT ISSUER KEY, WHEN THE OTHER FOUR DO
// ===========================================================================================
//
// `MintElevation` (elevation_mint.go) argues the OPPOSITE for its artifact, and it is right to:
// "Deliberately a method on GrantIssuer rather than a new issuer type … the agent pins ONE public
// key (`grant_issuer_pubkey`), so a second key would mean a second thing to provision and rotate.
// The domain tag — not a separate key — is what keeps the three artifact types from being
// confused." That reasoning holds for grants, session policies and elevations. **Updates are the
// deliberate exception**, and the two comments are not in conflict once the difference is named:
//
//   - Blast radius. A leaked GRANT_ISSUER_SEED mints backstage and elevation grants: serious, but
//     session-scoped, capability-bounded, single-use and audited. A leaked UPDATE key is arbitrary
//     code as SYSTEM on every managed machine, permanently, and the attacker then controls the
//     thing that writes the audit trail.
//   - Where the keys live. GRANT_ISSUER_SEED sits in a .env file on the internet-facing box. That
//     is an acceptable home for a key whose worst case is a session; it is not an acceptable home
//     for a key whose worst case is the fleet. If the update key never lives there, compromising
//     the control plane yields the ability to SERVE a manifest but not to SIGN one — "denial of
//     updates" instead of "fleet-wide RCE", which is a category of problem a deployment survives.
//
// There is therefore no `MintUpdateManifest` method on GrantIssuer, and adding one would delete the
// only structural guarantee this design has. The domain tag below is still distinct, as defence in
// depth for the day someone unifies the keys anyway — a configuration the agent's
// `UpdateTrust::from_config` refuses outright.
//
// The canonical preimage is a byte-for-byte port of Rust's `UpdateManifestClaims::signing_bytes`;
// TestUpdateManifestGoldenVectorV1 and the Rust `update::tests::golden_vector_v1` pin the SAME
// fixture to the SAME hex on both sides.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// updateDomainTag is the 12-byte update-v1 domain-separation tag: ASCII "RMTUPDATEv1" (11 bytes)
// followed by one 0x00 byte. Hex: 52 4d 54 55 50 44 41 54 45 76 31 00. Must equal Rust's
// UPDATE_DOMAIN_TAG.
//
// Unlike its four siblings this tag does NOT separate artifacts signed by the same key — the update
// key is a different key entirely (see the file header). It is here so that a deployment which
// nonetheless unified the keys could not have a signature minted over a SESSION POLICY (the most
// commonly produced artifact in the system) re-presented as a signed instruction naming an
// executable to install as SYSTEM on every machine. TestDomainTagsArePairwiseDistinct pins it apart
// from the rest.
var updateDomainTag = []byte("RMTUPDATEv1\x00")

// updateDomainTagV2 is the 12-byte update-v2 domain-separation tag: ASCII "RMTUPDATEv2" (11 bytes)
// followed by one 0x00 byte. Hex: 52 4d 54 55 50 44 41 54 45 76 32 00. Must equal Rust's
// UPDATE_V2_DOMAIN_TAG. Both formats are signed by the SAME update key, so this tag (not a second
// key) is what makes a signature over a v1 manifest useless as a v2 one; see update_manifest_v2.go.
var updateDomainTagV2 = []byte("RMTUPDATEv2\x00")

// MaxUpdateVersionLen / MaxUpdateURLLen mirror the Rust verifier's bounds. Signing a value the
// agent will refuse produces a manifest that is cryptographically perfect and functionally dead, so
// the signer refuses it here instead — the failure belongs at release time, in front of the person
// running the tool, not on ten thousand machines at 02:00.
const (
	MaxUpdateVersionLen = 64
	MaxUpdateURLLen     = 2048
	// RequiredUpdateURLScheme is checked at SIGN and VERIFY time both. http:// would put the
	// fleet's next binary on the wire in clear; file:// would turn a manifest into "run this
	// path". Neither is ever accepted, even though the signature already authenticates the bytes.
	RequiredUpdateURLScheme = "https://"
)

// ReleaseBody mirrors Rust `Release` (agent/src/update.rs). Field ORDER here is the JSON field
// order on the wire, and the wire string is pinned by goldenUpdateWireJSON — see that constant for
// why a struct-tag rename is invisible to every other test in this file.
type ReleaseBody struct {
	// Version is the release being published, e.g. "0.4.0".
	Version string `json:"version"`
	// SHA256 is the lowercase hex SHA-256 of the release binary, exactly 64 characters. Nothing in
	// step 2 computes or checks it against real bytes; it is carried so step 3's "verify sha256 AND
	// signature before the file moves" (docs/21 §6) has a value whose provenance is established.
	SHA256 string `json:"sha256"`
	// URL is where the release binary can be fetched. https:// only. NOTHING in step 2 fetches it.
	URL string `json:"url"`
	// MinUpgradableFrom is the oldest running version permitted to take this upgrade (docs/21 §7):
	// the mechanism for a build to refuse an upgrade path that was never tested.
	MinUpgradableFrom string `json:"min_upgradable_from"`
}

// updateManifestClaims mirrors Rust `UpdateManifestClaims`.
type updateManifestClaims struct {
	Release     ReleaseBody `json:"release"`
	IssuedAtMs  int64       `json:"issued_at_ms"`
	ExpiresAtMs int64       `json:"expires_at_ms"`
}

// SignedUpdateManifest mirrors Rust `SignedUpdateManifest`: the claims plus a hex Ed25519 signature
// over their canonical signing bytes. Marshals to the exact JSON the agent verifies, which is the
// exact content of C:\rmt-agent\update-manifest.json.
type SignedUpdateManifest struct {
	Claims updateManifestClaims `json:"claims"`
	Sig    string               `json:"sig"`
}

// NewSignedUpdateManifest assembles the wire value from already-computed parts.
//
// It takes the signature as bytes rather than producing one: this package has no key and no signing
// path (see the file header). The offline signer calls UpdateManifestSigningBytes, signs the result
// itself, and hands the signature here.
func NewSignedUpdateManifest(r ReleaseBody, issuedAtMs, expiresAtMs int64, sig []byte) SignedUpdateManifest {
	return SignedUpdateManifest{
		Claims: updateManifestClaims{Release: r, IssuedAtMs: issuedAtMs, ExpiresAtMs: expiresAtMs},
		Sig:    hex.EncodeToString(sig),
	}
}

// JSON renders the signed manifest as the wire string the agent reads off disk.
func (m SignedUpdateManifest) JSON() (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Release returns the release the manifest describes. Callers that have NOT verified the manifest
// must treat this as attacker-controlled input; VerifyUpdateManifest returns the same value only
// after the signature and the field shapes have passed.
func (m SignedUpdateManifest) Release() ReleaseBody { return m.Claims.Release }

// Window returns the manifest's validity window in Unix milliseconds.
func (m SignedUpdateManifest) Window() (issuedAtMs, expiresAtMs int64) {
	return m.Claims.IssuedAtMs, m.Claims.ExpiresAtMs
}

// UpdateManifestSigningBytes builds the canonical update-v1 preimage — a byte-for-byte port of
// Rust's UpdateManifestClaims::signing_bytes. All integers big-endian; every string is
// length-prefixed UTF-8. Layout:
//
//	updateDomainTag                                  // 12 bytes
//	|| u32be(len(version))             || version
//	|| u32be(len(sha256))              || sha256     // 64 LOWERCASE hex chars
//	|| u32be(len(url))                 || url        // https:// only
//	|| u32be(len(minUpgradableFrom))   || minUpgradableFrom
//	|| i64be(issuedAtMs)
//	|| i64be(expiresAtMs)
//
// Every field is inside the preimage, and the `url` one is the reason to care: it names what gets
// executed, so a preimage that omitted it would let anyone holding one genuine manifest redirect
// the fleet to a binary of their choosing while keeping the real signature.
//
// Returns an error when a field would not survive the agent's own verifier — a malformed digest, an
// uncomparable version, a non-https URL. Refusing here is the difference between a release engineer
// seeing a message and a fleet silently ignoring a manifest.
func UpdateManifestSigningBytes(version, sha256Hex, url, minUpgradableFrom string, issuedAtMs, expiresAtMs int64) ([]byte, error) {
	if err := checkUpdateSHA256(sha256Hex); err != nil {
		return nil, fmt.Errorf("sha256: %w", err)
	}
	if _, err := ParseUpdateVersion(version); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if _, err := ParseUpdateVersion(minUpgradableFrom); err != nil {
		return nil, fmt.Errorf("min_upgradable_from: %w", err)
	}
	if err := checkUpdateURL(url); err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	var w canonicalWriter
	w.updateTag()
	w.lpStr(version)
	w.lpStr(sha256Hex)
	w.lpStr(url)
	w.lpStr(minUpgradableFrom)
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	return w.buf, nil
}

// VerifyUpdateManifest checks a manifest exactly the way the agent does, in exactly the same order.
//
// SIGNATURE FIRST, so a forged manifest is refused before any field it carries is trusted, logged
// or compared; then not-yet-valid with the same one-sided 30 s skew tolerance the agent uses; then
// expiry, exact; then the field shapes. Rust's SignedUpdateManifest::verify is the authority and
// this mirrors it — TestUpdateManifestVerifyMatchesRustOrder pins the order by feeding a manifest
// that fails two checks at once and asserting WHICH one is reported.
//
// This exists so the offline signer can verify what it just produced (a signer that cannot check
// its own output is how a fleet finds out about a broken release at 02:00), and so a future route
// that SERVES a manifest can refuse to serve one it cannot verify. It is not, and must never
// become, an authorization decision on this side: the agent is the party that enforces.
func VerifyUpdateManifest(signer ed25519.PublicKey, m SignedUpdateManifest, nowMs int64) (ReleaseBody, error) {
	var zero ReleaseBody
	if len(signer) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("update manifest: signer key is %d bytes, want %d", len(signer), ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil {
		return zero, fmt.Errorf("update manifest: signature is not hex")
	}
	if len(sig) != ed25519.SignatureSize {
		return zero, fmt.Errorf("update manifest: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	r := m.Claims.Release
	// NOTE: the preimage builder validates the field shapes, so a manifest carrying a malformed
	// field cannot even be encoded for verification. That is deliberate and it is NOT a shortcut
	// past the ordering rule: a shape failure here means the manifest could never have been signed
	// by anyone, so reporting it before the signature leaks nothing an attacker did not already
	// author. The Rust agent, which must handle bytes it did not produce, checks the signature
	// first and the shapes after — see its verify() doc comment.
	msg, err := UpdateManifestSigningBytes(r.Version, r.SHA256, r.URL, r.MinUpgradableFrom,
		m.Claims.IssuedAtMs, m.Claims.ExpiresAtMs)
	if err != nil {
		return zero, fmt.Errorf("update manifest: %w", err)
	}
	if !ed25519.Verify(signer, msg, sig) {
		return zero, fmt.Errorf("update manifest: signature is invalid (wrong signing key, or the manifest was tampered with)")
	}
	// updateClockSkewMs mirrors Rust's CLOCK_SKEW_MS: one-sided, small, and applied to the
	// not-yet-valid check only. Expiry is exact.
	const updateClockSkewMs = 30_000
	if nowMs+updateClockSkewMs < m.Claims.IssuedAtMs {
		return zero, fmt.Errorf("update manifest: not yet valid (issued at %d, now %d)", m.Claims.IssuedAtMs, nowMs)
	}
	if nowMs >= m.Claims.ExpiresAtMs {
		return zero, fmt.Errorf("update manifest: expired at %d (now %d)", m.Claims.ExpiresAtMs, nowMs)
	}
	return r, nil
}

// checkUpdateSHA256 enforces the canonical digest form: exactly 64 LOWERCASE hex characters.
//
// Uppercase is refused rather than folded, matching Rust. The digest sits in the signed preimage as
// a STRING, so "AB…" and "ab…" are two different signed messages; accepting both would mean one
// side silently treats a value it was not handed as the value it was handed.
func checkUpdateSHA256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected exactly 64 hex characters, got %d", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("expected lowercase hex only (0-9, a-f)")
		}
	}
	return nil
}

// checkUpdateURL mirrors the Rust verifier's URL rules. See RequiredUpdateURLScheme.
func checkUpdateURL(s string) error {
	if len(s) > MaxUpdateURLLen {
		return fmt.Errorf("longer than the %d-character maximum", MaxUpdateURLLen)
	}
	if !strings.HasPrefix(s, RequiredUpdateURLScheme) {
		return fmt.Errorf("must be an %s URL", RequiredUpdateURLScheme)
	}
	if len(s) == len(RequiredUpdateURLScheme) {
		return fmt.Errorf("has a scheme but no host")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains control characters")
		}
	}
	return nil
}

// UpdateSemVer is a parsed major.minor.patch with semver build metadata already discarded.
type UpdateSemVer struct {
	Major uint64
	Minor uint64
	Patch uint64
}

// ParseUpdateVersion parses "<major>.<minor>.<patch>", discarding semver BUILD METADATA after the
// first '+'.
//
// A byte-for-byte behavioural port of Rust's `parse_version`, and it exists on this side for one
// reason: the offline signer must not be able to publish a version string the fleet cannot compare.
// Build metadata is ignored because semver §10 says it is ignored for precedence, and the agent's
// AGENT_VERSION is exactly "<crate version>+<short git sha>" — so two builds of 0.0.1 from
// different commits are the same VERSION and different BUILDS.
//
// Pre-release versions ("1.0.0-rc1") are REFUSED rather than ordered, matching Rust: implementing a
// subset of semver's pre-release precedence rules would mean quietly disagreeing with semver on
// some inputs, and a comparator that guesses is how a fleet gets told an update is available when
// it is not. TestUpdateVersionParsingMatchesRust pins the table against the Rust one.
func ParseUpdateVersion(s string) (UpdateSemVer, error) {
	var zero UpdateSemVer
	s = strings.TrimSpace(s)
	if s == "" {
		return zero, fmt.Errorf("empty version string")
	}
	if len(s) > MaxUpdateVersionLen {
		return zero, fmt.Errorf("longer than the %d-character maximum", MaxUpdateVersionLen)
	}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	if core == "" {
		return zero, fmt.Errorf("empty version string")
	}
	if strings.ContainsRune(core, '-') {
		return zero, fmt.Errorf("pre-release versions are not comparable here (%q)", s)
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return zero, fmt.Errorf("expected exactly 3 dot-separated components, found %d", len(parts))
	}
	var out [3]uint64
	for i, p := range parts {
		if p == "" {
			return zero, fmt.Errorf("component %d is empty", i)
		}
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return zero, fmt.Errorf("component %d (%q) is not a decimal number", i, p)
			}
		}
		// Semver forbids leading zeroes, and this refuses rather than normalizes: "01" and "1"
		// parsing to the same value would make two DIFFERENT signed manifests describe the same
		// release.
		if len(p) > 1 && p[0] == '0' {
			return zero, fmt.Errorf("component %d (%q) has a leading zero", i, p)
		}
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return zero, fmt.Errorf("component %d (%q) does not fit in a uint64", i, p)
		}
		out[i] = v
	}
	return UpdateSemVer{Major: out[0], Minor: out[1], Patch: out[2]}, nil
}

// CompareUpdateVersions orders two version strings by semver precedence, build metadata ignored.
// Returns -1, 0 or 1. An unparseable side is an error, never a fallback to string comparison.
func CompareUpdateVersions(a, b string) (int, error) {
	av, err := ParseUpdateVersion(a)
	if err != nil {
		return 0, fmt.Errorf("left: %w", err)
	}
	bv, err := ParseUpdateVersion(b)
	if err != nil {
		return 0, fmt.Errorf("right: %w", err)
	}
	switch {
	case av.Major != bv.Major:
		return cmpU64(av.Major, bv.Major), nil
	case av.Minor != bv.Minor:
		return cmpU64(av.Minor, bv.Minor), nil
	case av.Patch != bv.Patch:
		return cmpU64(av.Patch, bv.Patch), nil
	default:
		return 0, nil
	}
}

func cmpU64(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
