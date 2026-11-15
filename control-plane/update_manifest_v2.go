package controlplane

// The signed agent-update manifest, FORMAT 2 (the MSI-delivering one). Its Rust twin is
// `SignedUpdateManifestV2` in agent/src/update.rs, and the agent is the party that enforces it.
//
// Format 1 (update_manifest.go) describes a bare agent binary and stays exactly as it was, because
// agents in the field only understand it. Format 2 keeps the same trust model — one offline update
// key, signature first, then the window, then the field shapes — and changes the release body (a
// rollout ring, the MSI's digest and URL, the identifiers Windows Installer keys on) and the domain
// tag. Read update_manifest.go's header first: everything it says about why THIS FILE CANNOT SIGN
// applies here unchanged, and TestServerPackageCannotSign guards both files.
//
// The preimage is a byte-for-byte port of Rust's `UpdateManifestClaimsV2::signing_bytes`;
// TestUpdateManifestGoldenVectorV2 and the Rust `update::tests_v2::golden_vector_v2` pin the SAME
// fixture to the SAME hex on both sides.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// UpdateManifestFormatV2 is the only `format` value a format-2 manifest may carry. It is the wire
// discriminator, not part of the preimage (the domain tag already separates the formats under the
// signature): it lets a reader refuse a manifest of the wrong generation by name.
const UpdateManifestFormatV2 = 2

// UpdateRings is the closed set of rollout rings a format-2 release may name, matching Rust's
// RELEASE_RINGS.
var UpdateRings = []string{"canary", "early", "general"}

// ReleaseBodyV2 mirrors Rust `ReleaseV2`. Field ORDER here is the preimage order AND the JSON field
// order on the wire; the wire string is pinned by goldenUpdateV2WireJSON.
type ReleaseBodyV2 struct {
	// Ring is exactly one of UpdateRings.
	Ring string `json:"ring"`
	// Version is the agent semver, under the same rules as ReleaseBody.Version.
	Version string `json:"version"`
	// MSISHA256 is the lowercase hex SHA-256 of the MSI, exactly 64 characters.
	MSISHA256 string `json:"msi_sha256"`
	// MSIURL is where the MSI is fetched from. https:// only.
	MSIURL string `json:"msi_url"`
	// ProductVersion is the MSI ProductVersion: a.b.c with a, b <= 255 and c <= 65535.
	ProductVersion string `json:"product_version"`
	// ProductCode is the MSI ProductCode: a braced UPPERCASE GUID.
	ProductCode string `json:"product_code"`
	// UpgradeCode is the MSI UpgradeCode: a braced UPPERCASE GUID.
	UpgradeCode string `json:"upgrade_code"`
	// MinUpgradableFrom is the oldest running version permitted to take this upgrade, as in v1.
	MinUpgradableFrom string `json:"min_upgradable_from"`
}

// updateManifestClaimsV2 mirrors Rust `UpdateManifestClaimsV2`.
type updateManifestClaimsV2 struct {
	Release     ReleaseBodyV2 `json:"release"`
	IssuedAtMs  int64         `json:"issued_at_ms"`
	ExpiresAtMs int64         `json:"expires_at_ms"`
}

// SignedUpdateManifestV2 mirrors Rust `SignedUpdateManifestV2`:
// {"format":2,"claims":{...},"sig":"<128 hex>"}.
type SignedUpdateManifestV2 struct {
	Format int                    `json:"format"`
	Claims updateManifestClaimsV2 `json:"claims"`
	Sig    string                 `json:"sig"`
}

// NewSignedUpdateManifestV2 assembles the wire value from already-computed parts. Like its v1
// sibling it takes the signature as bytes: this package has no key and no signing path.
func NewSignedUpdateManifestV2(r ReleaseBodyV2, issuedAtMs, expiresAtMs int64, sig []byte) SignedUpdateManifestV2 {
	return SignedUpdateManifestV2{
		Format: UpdateManifestFormatV2,
		Claims: updateManifestClaimsV2{Release: r, IssuedAtMs: issuedAtMs, ExpiresAtMs: expiresAtMs},
		Sig:    hex.EncodeToString(sig),
	}
}

// JSON renders the signed manifest as the wire string the agent reads.
func (m SignedUpdateManifestV2) JSON() (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Release returns the release the manifest describes. Unverified input is attacker-controlled;
// VerifyUpdateManifestV2 returns the same value only after the checks have passed.
func (m SignedUpdateManifestV2) Release() ReleaseBodyV2 { return m.Claims.Release }

// UpdateManifestV2SigningBytes builds the canonical update-v2 preimage — a byte-for-byte port of
// Rust's UpdateManifestClaimsV2::signing_bytes. All integers big-endian; every string is
// length-prefixed (u32be) UTF-8. Layout:
//
//	updateDomainTagV2                                // 12 bytes: "RMTUPDATEv2\x00"
//	|| lp(ring) || lp(version) || lp(msi_sha256) || lp(msi_url)
//	|| lp(product_version) || lp(product_code) || lp(upgrade_code) || lp(min_upgradable_from)
//	|| i64be(issuedAtMs)
//	|| i64be(expiresAtMs)
//
// Returns an error when a field would not survive the agent's own verifier, so a release engineer
// sees a message instead of a fleet silently ignoring a manifest. Errors name the offending field.
func UpdateManifestV2SigningBytes(r ReleaseBodyV2, issuedAtMs, expiresAtMs int64) ([]byte, error) {
	if err := checkUpdateReleaseV2(r); err != nil {
		return nil, err
	}
	return updateManifestV2Preimage(r, issuedAtMs, expiresAtMs), nil
}

// updateManifestV2Preimage is the raw canonical encoding with NO validation: it encodes whatever it
// is given, exactly as Rust's signing_bytes does. Verification must use this, never the validating
// wrapper above, because the agent's order is signature, then window, then shapes.
func updateManifestV2Preimage(r ReleaseBodyV2, issuedAtMs, expiresAtMs int64) []byte {
	var w canonicalWriter
	w.updateV2Tag()
	w.lpStr(r.Ring)
	w.lpStr(r.Version)
	w.lpStr(r.MSISHA256)
	w.lpStr(r.MSIURL)
	w.lpStr(r.ProductVersion)
	w.lpStr(r.ProductCode)
	w.lpStr(r.UpgradeCode)
	w.lpStr(r.MinUpgradableFrom)
	w.i64(issuedAtMs)
	w.i64(expiresAtMs)
	return w.buf
}

// checkUpdateReleaseV2 applies every field-shape rule, in the same order as Rust's verify().
func checkUpdateReleaseV2(r ReleaseBodyV2) error {
	if err := checkUpdateRing(r.Ring); err != nil {
		return fmt.Errorf("ring: %w", err)
	}
	if _, err := ParseUpdateVersion(r.Version); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	if err := checkUpdateSHA256(r.MSISHA256); err != nil {
		return fmt.Errorf("msi_sha256: %w", err)
	}
	if err := checkUpdateURL(r.MSIURL); err != nil {
		return fmt.Errorf("msi_url: %w", err)
	}
	if err := checkUpdateProductVersion(r.ProductVersion); err != nil {
		return fmt.Errorf("product_version: %w", err)
	}
	if err := checkUpdateBracedGUID(r.ProductCode); err != nil {
		return fmt.Errorf("product_code: %w", err)
	}
	if err := checkUpdateBracedGUID(r.UpgradeCode); err != nil {
		return fmt.Errorf("upgrade_code: %w", err)
	}
	if _, err := ParseUpdateVersion(r.MinUpgradableFrom); err != nil {
		return fmt.Errorf("min_upgradable_from: %w", err)
	}
	return nil
}

// VerifyUpdateManifestV2 checks a format-2 manifest the way the agent does, in the same order as
// VerifyUpdateManifest: signature, then not-yet-valid (30 s one-sided skew), then expiry (exact), then field shapes.
// The field shapes are checked LAST, as in Rust: Ed25519 signs arbitrary preimages, so a malformed
// claim can carry a valid signature, and a malformed claim with a bad signature must report the
// signature. Verification therefore encodes with the unvalidated updateManifestV2Preimage; only the
// signing path (UpdateManifestV2SigningBytes) validates up front.
//
// `format` is checked first, as in Rust. This is for the offline signer to verify what it just
// produced and for any future serving route; it is not an authorization decision on this side.
func VerifyUpdateManifestV2(signer ed25519.PublicKey, m SignedUpdateManifestV2, nowMs int64) (ReleaseBodyV2, error) {
	var zero ReleaseBodyV2
	if m.Format != UpdateManifestFormatV2 {
		return zero, fmt.Errorf("update manifest: format %d is not supported here (expected %d)", m.Format, UpdateManifestFormatV2)
	}
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
	msg := updateManifestV2Preimage(m.Claims.Release, m.Claims.IssuedAtMs, m.Claims.ExpiresAtMs)
	if !ed25519.Verify(signer, msg, sig) {
		return zero, fmt.Errorf("update manifest: signature is invalid (wrong signing key, or the manifest was tampered with)")
	}
	// Mirrors Rust's CLOCK_SKEW_MS (and updateClockSkewMs in VerifyUpdateManifest).
	const updateClockSkewMs = 30_000
	if nowMs+updateClockSkewMs < m.Claims.IssuedAtMs {
		return zero, fmt.Errorf("update manifest: not yet valid (issued at %d, now %d)", m.Claims.IssuedAtMs, nowMs)
	}
	if nowMs >= m.Claims.ExpiresAtMs {
		return zero, fmt.Errorf("update manifest: expired at %d (now %d)", m.Claims.ExpiresAtMs, nowMs)
	}
	if err := checkUpdateReleaseV2(m.Claims.Release); err != nil {
		return zero, fmt.Errorf("update manifest: %w", err)
	}
	return m.Claims.Release, nil
}

// checkUpdateRing requires an exact, case-sensitive member of UpdateRings.
func checkUpdateRing(s string) error {
	for _, r := range UpdateRings {
		if s == r {
			return nil
		}
	}
	return fmt.Errorf("%q is not one of canary, early, general", s)
}

// checkUpdateProductVersion mirrors Rust's check_product_version: exactly three dot-separated
// decimal fields, each within Windows Installer's limits (255.255.65535), no leading zeros except a
// lone "0", no sign or whitespace. Refused rather than normalised, so "1.03.0" and "1.3.0" cannot
// be two signed spellings of one installed version.
func checkUpdateProductVersion(s string) error {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return fmt.Errorf("expected exactly 3 dot-separated fields")
	}
	limits := [3]uint64{255, 255, 65535}
	for i, p := range parts {
		if p == "" {
			return fmt.Errorf("a field is empty")
		}
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return fmt.Errorf("fields must be decimal digits only")
			}
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("a field has a leading zero")
		}
		// At most 5 digits can be in range; capping the length first means ParseUint cannot overflow.
		if len(p) > 5 {
			return fmt.Errorf("a field exceeds the Windows Installer limit (255.255.65535)")
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || n > limits[i] {
			return fmt.Errorf("a field exceeds the Windows Installer limit (255.255.65535)")
		}
	}
	return nil
}

// checkUpdateBracedGUID mirrors Rust's check_braced_guid: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX},
// hex digits 0-9 A-F only. Lowercase is refused, never folded.
func checkUpdateBracedGUID(s string) error {
	const length = 38
	if len(s) != length {
		return fmt.Errorf("expected exactly 38 characters")
	}
	if s[0] != '{' || s[length-1] != '}' {
		return fmt.Errorf("expected surrounding braces")
	}
	for i := 1; i < length-1; i++ {
		c := s[i]
		switch i {
		case 9, 14, 19, 24:
			if c != '-' {
				return fmt.Errorf("expected the 8-4-4-4-12 dash layout")
			}
		default:
			if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') {
				return fmt.Errorf("expected uppercase hex only (0-9, A-F)")
			}
		}
	}
	return nil
}
