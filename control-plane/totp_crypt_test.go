package controlplane

import (
	"bytes"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
)

// A valid 32-byte key, hex-encoded (64 characters).
func goodKey() string { return "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0" }

func newCipherT(t *testing.T) *TOTPCipher {
	t.Helper()
	c, err := NewTOTPCipher(goodKey())
	if err != nil {
		t.Fatalf("NewTOTPCipher: %v", err)
	}
	if c == nil {
		t.Fatal("NewTOTPCipher returned nil for a valid key")
	}
	return c
}

func TestTOTPSecretRoundTripsThroughTheEnvelope(t *testing.T) {
	c := newCipherT(t)
	const secret = "JBSWY3DPEHPK3PXP"

	sealed, err := c.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, encrypted, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != secret {
		t.Fatalf("round trip: got %q want %q", got, secret)
	}
	if !encrypted {
		t.Fatal("Open reported a sealed value as legacy plaintext")
	}
}

// THE ASSERTION THE WHOLE CHANGE EXISTS FOR. Everything else could pass while the column still held
// the secret: a round trip proves Seal and Open agree, not that Seal actually hid anything.
func TestASealedSecretDoesNotContainThePlaintext(t *testing.T) {
	c := newCipherT(t)
	const secret = "JBSWY3DPEHPK3PXP"

	sealed, err := c.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte(secret)) {
		t.Fatalf("the sealed value still contains the base32 secret verbatim: %q", sealed)
	}
	// Not even a fragment. A broken cipher that XORed with a short repeating key would pass the
	// whole-string check above while leaking most of the secret.
	for i := 0; i+4 <= len(secret); i++ {
		if bytes.Contains(sealed, []byte(secret[i:i+4])) {
			t.Fatalf("the sealed value contains the 4-char fragment %q from the secret", secret[i:i+4])
		}
	}
}

func TestTwoSealsOfTheSameSecretDiffer(t *testing.T) {
	// A fresh random nonce per seal. Without it, identical secrets produce identical rows and a
	// reader of the database learns which users share one — and a rotated-to-same-value secret is
	// visible as an unchanged row.
	c := newCipherT(t)
	a, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	b, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same secret produced identical bytes — the nonce is not random")
	}
}

func TestALegacyPlaintextRowStillOpens(t *testing.T) {
	// The compatibility promise: a deployment that upgrades before setting the key keeps working,
	// and one that sets it keeps verifying secrets enrolled before it existed. Without this, turning
	// encryption on would lock every already-enrolled user out of their own console.
	c := newCipherT(t)
	const legacy = "JBSWY3DPEHPK3PXP"

	got, encrypted, err := c.Open([]byte(legacy))
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy row: got %q want %q", got, legacy)
	}
	if encrypted {
		t.Fatal("a plaintext row was reported as encrypted")
	}
}

func TestNoBase32SecretCanBeMistakenForAnEnvelope(t *testing.T) {
	// The leading 0x00 is what makes the legacy check a decision rather than a guess. Base32's
	// alphabet is A-Z and 2-7, so no secret this code can generate starts with a NUL. Assert that
	// against the real generator rather than against an assumption about it.
	for i := 0; i < 200; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if hasTOTPEnvelope([]byte(s)) {
			t.Fatalf("generated secret %q was mistaken for an encrypted envelope", s)
		}
		if strings.ContainsRune(s, 0) {
			t.Fatalf("generated secret %q contains a NUL byte", s)
		}
	}
}

func TestAnEmptySecretStaysEmptyAndUnencrypted(t *testing.T) {
	// SetPendingTOTP writes ''::bytea into `secret` on a first enrollment and login reads a
	// zero-length secret as "not enrolled". Encrypting that sentinel would turn a well-known marker
	// into bytes that need a key to read, and would break ConfirmPendingTOTP's
	// `length(pending_secret) > 0`.
	c := newCipherT(t)
	sealed, err := c.Seal("")
	if err != nil {
		t.Fatalf("Seal empty: %v", err)
	}
	if len(sealed) != 0 {
		t.Fatalf("an empty secret sealed to %d bytes; it must stay empty", len(sealed))
	}
	got, encrypted, err := c.Open(nil)
	if err != nil || got != "" || encrypted {
		t.Fatalf("Open(nil) = (%q, %v, %v); want (\"\", false, nil)", got, encrypted, err)
	}
}

func TestAWrongKeyFailsLoudlyRatherThanReturningNothing(t *testing.T) {
	// The failure mode this guards is specific and bad: if a wrong key produced ("", nil) instead of
	// an error, scanUser would hand back an AuthUser whose TOTPSecret is "" — which auth.go reads as
	// "this user is not enrolled" and skips the second factor. A rotated key would then silently
	// downgrade every enrolled account to password-only.
	c := newCipherT(t)
	sealed, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	other, err := NewTOTPCipher("ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211ff")
	if err != nil {
		t.Fatalf("NewTOTPCipher other: %v", err)
	}
	got, encrypted, err := other.Open(sealed)
	if err == nil {
		t.Fatalf("a wrong key opened the secret as %q", got)
	}
	if !encrypted {
		t.Fatal("a sealed value under the wrong key must still be reported as encrypted, not legacy")
	}
	if got != "" {
		t.Fatalf("a failed open must return no secret, got %q", got)
	}
}

func TestATamperedRowDoesNotOpen(t *testing.T) {
	c := newCipherT(t)
	sealed, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a bit in the ciphertext body. AEAD must reject it rather than return garbage.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := c.Open(tampered); err == nil {
		t.Fatal("a tampered row opened; the value is not authenticated")
	}

	// And a re-labelled envelope version must not open either — the magic is additional data.
	relabelled := append([]byte(nil), sealed...)
	relabelled[len(totpEnvelopeMagic)-1] = '2'
	if _, _, err := c.Open(relabelled); err == nil {
		t.Fatal("a row with a rewritten envelope version opened")
	}
}

func TestAMissingKeyReadsLegacyRowsButRefusesToWrite(t *testing.T) {
	// The exact posture that lets this ship: no lockout on upgrade, no plaintext writes.
	var none *TOTPCipher // what NewTOTPCipher("") yields

	got, encrypted, err := none.Open([]byte("JBSWY3DPEHPK3PXP"))
	if err != nil || got != "JBSWY3DPEHPK3PXP" || encrypted {
		t.Fatalf("with no key, a legacy row must still read: (%q, %v, %v)", got, encrypted, err)
	}

	if _, err := none.Seal("JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("with no key configured, sealing a NEW secret must be refused, not silently plaintext")
	}

	// An already-encrypted row without a key is an error, not a silent "not enrolled".
	c := newCipherT(t)
	sealed, _ := c.Seal("JBSWY3DPEHPK3PXP")
	if _, _, err := none.Open(sealed); err == nil {
		t.Fatal("an encrypted row opened with no key configured")
	}
}

func TestTheKeyLoaderRejectsWhatItShould(t *testing.T) {
	if c, err := NewTOTPCipher(""); err != nil || c != nil {
		t.Fatalf("an empty key must be (nil, nil) — the 'not configured' state: (%v, %v)", c, err)
	}

	allZero := strings.Repeat("0", TOTPEncryptionKeySize*2)
	if _, err := NewTOTPCipher(allZero); err == nil {
		t.Fatal("the all-zero key was accepted; it is what a copied placeholder looks like")
	} else if !strings.Contains(err.Error(), "all zeros") {
		t.Fatalf("the all-zero refusal must say so, got: %v", err)
	}

	for _, bad := range []struct{ name, key string }{
		{"too short", goodKey()[:len(goodKey())-2]},
		{"too long", goodKey() + "00"},
		{"not hex", strings.Repeat("z", TOTPEncryptionKeySize*2)},
		{"odd length", goodKey()[:len(goodKey())-1]},
	} {
		if _, err := NewTOTPCipher(bad.key); err == nil {
			t.Fatalf("%s key was accepted", bad.name)
		}
	}

	// Sanity: the fixture really is the right length, so the "too short" case above is testing what
	// it claims and not a typo in the good key.
	raw, err := hex.DecodeString(goodKey())
	if err != nil || len(raw) != TOTPEncryptionKeySize {
		t.Fatalf("test fixture key is not %d bytes: %v (%d)", TOTPEncryptionKeySize, err, len(raw))
	}
}

// newPgUserStoreT builds a PgUserStore with a TOTP cipher configured, which is what production does
// whenever TOTP_ENCRYPTION_KEY is set.
//
// Tests go through this rather than NewPgUserStore directly so that every TOTP-touching test
// exercises the ENCRYPTED path. A test that quietly ran with a nil cipher would be testing the
// legacy-plaintext compatibility branch while appearing to cover the real one — the "fake and pg
// must agree" trap, one layer down: here the two paths are both real, and the one under test would
// be the wrong one.
func newPgUserStoreT(pool *pgxpool.Pool) *PgUserStore {
	s := NewPgUserStore(pool)
	c, err := NewTOTPCipher(goodKey())
	if err != nil {
		panic("test TOTP cipher: " + err.Error())
	}
	s.TOTP = c
	return s
}
