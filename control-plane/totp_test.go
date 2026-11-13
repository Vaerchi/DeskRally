package controlplane

import (
	"strings"
	"testing"
	"time"
)

// rfcSeed is the 20-byte ASCII shared secret used by the RFC 4226 Appendix D and RFC 6238
// Appendix B test vectors for HMAC-SHA1.
var rfcSeed = []byte("12345678901234567890")

// TestHOTPRFC4226Vectors checks the HMAC-OTP core against the published RFC 4226 Appendix D
// 6-digit vectors for counters 0..9.
func TestHOTPRFC4226Vectors(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for c, w := range want {
		if got := hotp(rfcSeed, uint64(c), 6); got != w {
			t.Errorf("hotp(counter=%d) = %s, want %s", c, got, w)
		}
	}
}

// TestTOTPRFC6238Vectors checks the time-based wrapper against RFC 6238 Appendix B (SHA-1,
// 8 digits, 30-second step).
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := b32.EncodeToString(rfcSeed)
	cfg := TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 0}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got, err := TOTPCode(secret, time.Unix(c.unix, 0), cfg)
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("TOTPCode(t=%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTPAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := TOTPCode(secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	ok, err := VerifyTOTP(secret, code, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if !ok {
		t.Fatal("current code did not verify")
	}
}

func TestVerifyTOTPRejectsWrongCode(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	ok, err := VerifyTOTP(secret, "000000", now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if ok {
		t.Fatal("clearly wrong code was accepted")
	}
}

// A code from the previous 30-second step must verify within the ±1 default skew, but a
// code three steps in the past must not.
func TestVerifyTOTPSkewWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	prev := now.Add(-30 * time.Second)
	prevCode, _ := TOTPCode(secret, prev, DefaultTOTPConfig)

	ok, _ := VerifyTOTP(secret, prevCode, now, DefaultTOTPConfig)
	if !ok {
		t.Fatal("code from previous step should verify within ±1 skew")
	}

	old := now.Add(-90 * time.Second)
	oldCode, _ := TOTPCode(secret, old, DefaultTOTPConfig)
	if ok, _ := VerifyTOTP(secret, oldCode, now, DefaultTOTPConfig); ok {
		t.Fatal("code three steps old should be rejected by ±1 skew")
	}
}

// VerifyTOTPStep reports WHICH step matched, which is what single-use enforcement is keyed on:
// a code presented from a neighbouring step must report that step, not the verifier's "now".
func TestVerifyTOTPStepReportsMatchedStep(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	center := uint64(now.Unix()) / 30

	code, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	step, ok, err := VerifyTOTPStep(secret, code, now, DefaultTOTPConfig)
	if err != nil || !ok || step != center {
		t.Fatalf("current code → step %d ok=%v err=%v, want step %d ok", step, ok, err, center)
	}
	// A code from the previous step verifies (±1 skew) and reports the PREVIOUS step — if it
	// reported the center, replaying it would also consume the current step and lock out the
	// genuine current code.
	prevCode, _ := TOTPCode(secret, now.Add(-30*time.Second), DefaultTOTPConfig)
	step, ok, err = VerifyTOTPStep(secret, prevCode, now, DefaultTOTPConfig)
	if err != nil || !ok || step != center-1 {
		t.Fatalf("previous-step code → step %d ok=%v err=%v, want step %d ok", step, ok, err, center-1)
	}
	// A wrong code reports no step and does not verify.
	if _, ok, _ := VerifyTOTPStep(secret, "000000", now, DefaultTOTPConfig); ok {
		if code != "000000" && prevCode != "000000" {
			t.Fatal("wrong code verified")
		}
	}
}

func TestTOTPKeyURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := TOTPKeyURI(secret, "RMT Control Plane", "tech@example.com", DefaultTOTPConfig)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("bad scheme: %s", uri)
	}
	for _, want := range []string{"secret=" + secret, "algorithm=SHA1", "digits=6", "period=30", "issuer=RMT+Control+Plane"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri missing %q: %s", want, uri)
		}
	}
}

func TestVerifyTOTPMalformedSecret(t *testing.T) {
	if _, err := VerifyTOTP("not!valid!base32!", "123456", time.Now(), DefaultTOTPConfig); err == nil {
		t.Fatal("malformed secret should error")
	}
}
