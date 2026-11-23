package controlplane

// Time-based one-time passwords (RFC 6238 / RFC 4226) for optional 2FA on local login.
// Kept dependency-free (stdlib crypto only) and self-contained so it can be unit-tested
// against the published RFC 6238 test vectors without a database or an external library.
//
// Verification is constant-time and accepts a small ± step window to tolerate clock skew,
// which is the standard authenticator-app allowance.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTPConfig holds the OTP parameters. Defaults follow the ubiquitous authenticator
// convention (SHA-1, 6 digits, 30-second period) that Google Authenticator, Authy, 1Password
// etc. all assume when a URI omits them.
type TOTPConfig struct {
	Digits int           // number of output digits (6 is standard)
	Period time.Duration // time step
	Skew   int           // number of steps of clock drift tolerated on each side
}

// DefaultTOTPConfig is the standard authenticator-app profile.
var DefaultTOTPConfig = TOTPConfig{
	Digits: 6,
	Period: 30 * time.Second,
	Skew:   1,
}

// b32 is unpadded base32, the encoding authenticator apps expect for the shared secret.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh 160-bit secret encoded as unpadded base32 (the size
// RFC 4226 recommends for HMAC-SHA1). Store this per user; it is a credential — treat it
// like a password (encrypt at rest in production; never log it).
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return b32.EncodeToString(raw), nil
}

// TOTPKeyURI builds the otpauth:// provisioning URI that an authenticator app scans as a QR
// code. issuer is the product/tenant name; account is the user's login (usually the email).
func TOTPKeyURI(secretB32, issuer, account string, cfg TOTPConfig) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", cfg.Digits))
	q.Set("period", fmt.Sprintf("%d", int(cfg.Period.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode returns the OTP for a base32 secret at time t under cfg.
func TOTPCode(secretB32 string, t time.Time, cfg TOTPConfig) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secretB32)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(cfg.Period.Seconds())
	return hotp(key, counter, cfg.Digits), nil
}

// VerifyTOTP reports whether code is valid for the base32 secret at time t, accepting
// cfg.Skew steps of drift on each side. The comparison against each candidate is
// constant-time. A malformed secret returns (false, err).
//
// Callers that AUTHENTICATE with the result must use VerifyTOTPStep instead and record the
// returned step, so an accepted code cannot be replayed for the rest of the skew window
// (RFC 6238 §5.2).
func VerifyTOTP(secretB32, code string, t time.Time, cfg TOTPConfig) (bool, error) {
	_, ok, err := VerifyTOTPStep(secretB32, code, t, cfg)
	return ok, err
}

// VerifyTOTPStep is VerifyTOTP plus the RFC 4226 counter (time step) the code matched. That step
// is what makes single-use enforcement possible: the caller persists it and refuses any later
// presentation whose step is not strictly greater. The returned step is meaningless when ok is
// false. A malformed secret returns (0, false, err).
func VerifyTOTPStep(secretB32, code string, t time.Time, cfg TOTPConfig) (uint64, bool, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secretB32)))
	if err != nil {
		return 0, false, fmt.Errorf("decode totp secret: %w", err)
	}
	code = strings.TrimSpace(code)
	step := uint64(cfg.Period.Seconds())
	center := uint64(t.Unix()) / step
	// Iterate the whole window regardless of early match so timing does not reveal which
	// step (if any) matched.
	var ok bool
	var matched uint64
	for i := -cfg.Skew; i <= cfg.Skew; i++ {
		counter := center
		if i < 0 {
			counter -= uint64(-i)
		} else {
			counter += uint64(i)
		}
		candidate := hotp(key, counter, cfg.Digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			ok = true
			matched = counter
		}
	}
	return matched, ok, nil
}

// hotp is the RFC 4226 HMAC-based OTP core: HMAC-SHA1 over the 8-byte big-endian counter,
// dynamic-truncated to the requested number of decimal digits.
func hotp(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}
