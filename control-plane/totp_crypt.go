package controlplane

// Encryption at rest for TOTP shared secrets.
//
// `migrations/0002_auth.sql:17-19` has instructed this since the table was created:
//
//	--   * user_totp stores the shared secret; it is a credential. The application layer should
//	--     encrypt it at rest (envelope/KMS) before insert. This migration keeps it as bytea and
//	--     does not itself provide encryption.
//
// and `GenerateTOTPSecret`'s own doc comment repeats it. Nothing implemented it. Password digests
// are argon2id and survive a database read; the second factor did not, so one `pg_dump` — a backup,
// a replica, a stolen volume — handed over every enrolled user's 2FA deployment-wide, and unlike a
// password a TOTP secret cannot be "reset" without the user re-enrolling their authenticator.
//
// # The key
//
// A SEPARATE `TOTP_ENCRYPTION_KEY`, deliberately not derived from `GRANT_ISSUER_SEED`. That seed
// already signs backstage grants, elevation grants, session policies and session tickets; widening
// its blast radius so that one compromised value also decrypts every second factor is the wrong
// direction. Two secrets that can be rotated independently is the whole point.
//
// # The envelope
//
//	0x00 || "RMTTOTP1" || nonce(24) || XChaCha20-Poly1305(secret)
//
// XChaCha20-Poly1305 rather than AES-GCM for one reason: its 192-bit nonce is safe to choose at
// random forever. AES-GCM's 96-bit nonce is fine at this volume but makes correctness depend on an
// argument about how many enrollments a deployment will ever see, and that is not an argument worth
// having about a credential store. `golang.org/x/crypto` is already a direct dependency (argon2), so
// this adds nothing to go.mod.
//
// The LEADING ZERO BYTE is what makes legacy rows unambiguous rather than guessed at. A pre-existing
// row holds the ASCII of an unpadded base32 string, whose alphabet is A-Z and 2-7 — a NUL can never
// be its first byte. So "starts with 0x00" is a decision, not a heuristic, and there is no input for
// which the two readings overlap.
//
// # Reading legacy rows
//
// `Open` accepts a plaintext row and says so. That is what lets this ship without locking anyone
// out: an operator who upgrades before setting the key keeps logging in, and one who sets it keeps
// verifying against secrets enrolled before it existed. `0018_credential_epoch.sql` set the
// precedent — it deliberately does not backfill and has the application interpret un-migrated rows —
// and `controlplane reencrypt-totp` converts them when the operator chooses.
//
// WRITES have no such tolerance. With no key configured, enrollment is REFUSED rather than storing
// a plaintext secret: reading what is already on disk is a compatibility question, but writing a new
// credential we cannot protect is a choice, and the answer to it is no.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// totpEnvelopeMagic prefixes every encrypted TOTP secret. The leading 0x00 is load-bearing: it
// cannot occur at the start of a base32 secret, so it distinguishes an encrypted row from a legacy
// plaintext one with no ambiguity. The trailing digit is a format version — a second cipher or a
// second key slot would bump it rather than reinterpret these bytes.
var totpEnvelopeMagic = []byte{0x00, 'R', 'M', 'T', 'T', 'O', 'T', 'P', '1'}

// TOTPEncryptionKeySize is the required raw key length (hex-encoded, so 64 characters in .env).
const TOTPEncryptionKeySize = chacha20poly1305.KeySize // 32

// ErrTOTPKeyMissing is returned by a write path when no encryption key is configured. It is a
// refusal, not a fallback: the caller must fail the request rather than store a bare secret.
var ErrTOTPKeyMissing = errors.New("TOTP_ENCRYPTION_KEY is not configured, so a new TOTP secret cannot be stored encrypted")

// TOTPCipher seals and opens TOTP secrets. The zero value is unusable; build one with
// NewTOTPCipher. A nil *TOTPCipher is the legitimate "no key configured" state and every method
// handles it, so callers do not need a nil check before every use.
type TOTPCipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
}

// NewTOTPCipher builds a cipher from the hex-encoded key in TOTP_ENCRYPTION_KEY.
//
// Validation is modelled on `ticketPubkeyFromEnv` in the signaling server, the strongest loader in
// the repo and the only one that rejects a weak VALUE rather than only a malformed shape. An
// all-zero key is refused for the same reason the all-zero ticket pubkey is: it is what a
// copy-pasted placeholder looks like, it is syntactically perfect, and accepting it would produce a
// deployment that encrypts everything under a key an attacker guesses first.
//
// An empty string returns (nil, nil) — "no key configured", which reads and refuses to write.
func NewTOTPCipher(hexKey string) (*TOTPCipher, error) {
	if hexKey == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != TOTPEncryptionKeySize {
		return nil, fmt.Errorf(
			"TOTP_ENCRYPTION_KEY must be a hex-encoded %d-byte key (%d hex characters); "+
				"generate one with: openssl rand -hex %d",
			TOTPEncryptionKeySize, TOTPEncryptionKeySize*2, TOTPEncryptionKeySize)
	}
	if isAllZeroBytes(key) {
		return nil, errors.New(
			"TOTP_ENCRYPTION_KEY is all zeros — that is a placeholder, not a key. Every TOTP secret " +
				"in the database would be encrypted under a value an attacker tries first, which is " +
				"indistinguishable from storing them in plaintext. Generate a real one with: " +
				"openssl rand -hex 32")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("build TOTP cipher: %w", err)
	}
	return &TOTPCipher{aead: aead}, nil
}

// isAllZeroBytes reports whether b is entirely zero. Mirrors signaling's `isAllZero`.
func isAllZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Seal encrypts a base32 TOTP secret for storage.
//
// An EMPTY secret is stored as empty, unencrypted, on purpose. `SetPendingTOTP` writes `''::bytea`
// into `secret` on a first-ever enrollment and login treats a zero-length secret as "not enrolled"
// (auth.go:547). Encrypting that sentinel would turn a well-known "no 2FA here" marker into 41
// bytes that decrypt to "" — costing a key just to read a value that is not a secret, and breaking
// `length(pending_secret) > 0` in ConfirmPendingTOTP's WHERE clause.
func (c *TOTPCipher) Seal(secretB32 string) ([]byte, error) {
	if secretB32 == "" {
		return []byte{}, nil
	}
	if c == nil {
		return nil, ErrTOTPKeyMissing
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("totp seal: nonce: %w", err)
	}
	out := make([]byte, 0, len(totpEnvelopeMagic)+len(nonce)+len(secretB32)+chacha20poly1305.Overhead)
	out = append(out, totpEnvelopeMagic...)
	out = append(out, nonce...)
	// The magic is authenticated as additional data, so a row cannot be re-labelled as a different
	// envelope version and still open.
	return c.aead.Seal(out, nonce, []byte(secretB32), totpEnvelopeMagic), nil
}

// Open decrypts a stored TOTP secret, tolerating a legacy plaintext row.
//
// `encrypted` reports which one it was, so a caller that cares — the re-encryption subcommand, and
// the tests that assert rows really are ciphertext — can tell without re-parsing the envelope.
// Callers that only need the secret ignore it, which is why this returns a value rather than
// logging: a warning per login for a deployment that has not yet re-encrypted would be noise, and
// the operator learns the real count from `reencrypt-totp`.
func (c *TOTPCipher) Open(stored []byte) (secretB32 string, encrypted bool, err error) {
	if len(stored) == 0 {
		return "", false, nil
	}
	if stored[0] != totpEnvelopeMagic[0] {
		// Legacy: the raw bytes of the base32 string, as written before this file existed.
		return string(stored), false, nil
	}
	// A leading NUL means the row CLAIMS to be an envelope — plaintext base32 can never begin with
	// one. So a claim that does not then match is an error, not a fallback.
	//
	// Falling back would be worse than it sounds and this is not hypothetical: the first version of
	// this function tested the whole magic before deciding, so flipping the version byte made a row
	// "legacy plaintext" and returned raw ciphertext AS the secret. Silent, and it turned a
	// tamper-detection question into a garbage-in-garbage-out one. A test written to assert the
	// tamper was caught is what found it.
	if !hasTOTPEnvelope(stored) {
		return "", true, errors.New(
			"stored TOTP secret carries an unrecognised envelope header; it was written by a newer " +
				"format version, or the row has been altered")
	}
	if c == nil {
		return "", true, errors.New(
			"this TOTP secret is encrypted but TOTP_ENCRYPTION_KEY is not configured; " +
				"set it to the key this deployment was using, or the second factor cannot be verified")
	}
	body := stored[len(totpEnvelopeMagic):]
	ns := c.aead.NonceSize()
	if len(body) < ns+chacha20poly1305.Overhead {
		return "", true, errors.New("stored TOTP secret is truncated")
	}
	plain, err := c.aead.Open(nil, body[:ns], body[ns:], totpEnvelopeMagic)
	if err != nil {
		// Wrong key or a tampered row. Deliberately not distinguished — both mean "cannot verify
		// this user's second factor", and saying which would tell an attacker with database read
		// access whether a guessed key was close.
		return "", true, errors.New(
			"stored TOTP secret failed to decrypt: TOTP_ENCRYPTION_KEY does not match the key it " +
				"was encrypted with, or the row has been altered")
	}
	return string(plain), true, nil
}

// hasTOTPEnvelope reports whether a stored value is one of ours rather than a legacy plaintext row.
func hasTOTPEnvelope(stored []byte) bool {
	if len(stored) < len(totpEnvelopeMagic) {
		return false
	}
	for i, b := range totpEnvelopeMagic {
		if stored[i] != b {
			return false
		}
	}
	return true
}
