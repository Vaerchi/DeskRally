package controlplane

// Local-login password hashing. This is security-critical: the control plane runs a
// SYSTEM-level remote-access product (docs/03-roadmap.md risk table — ScreenConnect's
// CVE-2024-1709 auth bypass is the cautionary tale), so credentials are stored only as an
// argon2id hash, never in plaintext, and verification is constant-time.
//
// The stored form is the standard PHC string:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<b64-salt>$<b64-hash>
//
// which self-describes its parameters, so a hash produced under old parameters still
// verifies after the defaults are tuned up (see NeedsRehash).

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the tunable cost parameters for argon2id. Increase Memory/Time as
// hardware improves; older hashes keep verifying because their parameters travel in the
// encoded string.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32 // iterations
	Threads uint8  // parallelism
	SaltLen uint32 // bytes
	KeyLen  uint32 // bytes
}

// DefaultArgon2Params is a sane interactive-login baseline: 64 MiB, 1 pass, 4 lanes. This
// meets the OWASP argon2id floor (>= 19 MiB, t=2 OR >= 46 MiB, t=1).
var DefaultArgon2Params = Argon2Params{
	Memory:  64 * 1024,
	Time:    1,
	Threads: 4,
	SaltLen: 16,
	KeyLen:  32,
}

// ErrInvalidHash is returned when a stored hash string is malformed.
var ErrInvalidHash = errors.New("invalid password hash encoding")

// ErrIncompatibleVersion is returned when the hash was produced by a newer argon2 version
// than this build understands.
var ErrIncompatibleVersion = errors.New("incompatible argon2 version")

// HashPassword hashes a plaintext password with argon2id under the default parameters and
// returns the PHC-encoded string suitable for storage in user_credential.password_hash.
//
// It WAITS for argon2 capacity rather than failing when the process is saturated — see
// password_limiter.go for why the non-context entry points must never return a "busy" error.
func HashPassword(plaintext string) (string, error) {
	return HashPasswordWith(plaintext, DefaultArgon2Params)
}

// HashPasswordCtx is HashPassword bounded by the process-wide argon2 limiter: it returns
// ErrHashBusy when there is no capacity and no room to queue, and ctx.Err() when the caller goes
// away while queued. HTTP handlers use this one so a saturated process answers 503 instead of
// allocating without limit; map the error with WriteHashBusy and do NOT charge throttle budget.
func HashPasswordCtx(ctx context.Context, plaintext string) (string, error) {
	return hashPasswordWith(ctx, plaintext, DefaultArgon2Params, true)
}

// HashPasswordWith hashes a plaintext password under explicit parameters, waiting for capacity.
func HashPasswordWith(plaintext string, p Argon2Params) (string, error) {
	return hashPasswordWith(context.Background(), plaintext, p, false)
}

func hashPasswordWith(ctx context.Context, plaintext string, p Argon2Params, bounded bool) (string, error) {
	// The salt is cheap; take it before queueing so a slot is held only for the argon2 call.
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	release, err := passwordLimiter().acquire(ctx, bounded)
	if err != nil {
		return "", err
	}
	defer release()
	enterArgon2()
	key := argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	leaveArgon2()
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether plaintext matches the PHC-encoded argon2id hash. The
// comparison is constant-time. A malformed encoding returns (false, ErrInvalidHash) rather
// than a silent false, so corrupt data is distinguishable from a wrong password.
//
// It WAITS for argon2 capacity. Its error set is unchanged — a caller's `if err != nil || !ok`
// still means "bad credential", which is exactly why this variant may not report saturation:
// doing so would let a load burst be recorded as somebody else's failed password guess.
func VerifyPassword(encoded, plaintext string) (bool, error) {
	return verifyPassword(context.Background(), encoded, plaintext, false)
}

// VerifyPasswordCtx is VerifyPassword bounded by the process-wide argon2 limiter. It returns
// ErrHashBusy when the process is saturated; callers MUST distinguish that from a wrong password
// (errors.Is(err, ErrHashBusy) → WriteHashBusy, no throttle Fail, no credential-failure audit).
func VerifyPasswordCtx(ctx context.Context, encoded, plaintext string) (bool, error) {
	return verifyPassword(ctx, encoded, plaintext, true)
}

func verifyPassword(ctx context.Context, encoded, plaintext string, bounded bool) (bool, error) {
	// Decode first: a malformed stored hash is a cheap, immediate answer and must not consume a
	// slot or wait behind a queue.
	p, salt, want, err := decodeArgon2(encoded)
	if err != nil {
		return false, err
	}
	release, aerr := passwordLimiter().acquire(ctx, bounded)
	if aerr != nil {
		return false, aerr
	}
	defer release()
	enterArgon2()
	got := argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	leaveArgon2()
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a stored hash was produced under weaker parameters than the
// current default and should be re-hashed on the next successful login.
func NeedsRehash(encoded string) bool {
	p, _, _, err := decodeArgon2(encoded)
	if err != nil {
		return true
	}
	d := DefaultArgon2Params
	return p.Memory < d.Memory || p.Time < d.Time || p.Threads < d.Threads
}

func decodeArgon2(encoded string) (Argon2Params, []byte, []byte, error) {
	// $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, ErrIncompatibleVersion
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(hash))
	return p, salt, hash, nil
}
