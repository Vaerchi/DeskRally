package controlplane

// Enrollment tokens (M1) — the bearer secrets an installer redeems to join the fleet, over the
// `enrollment_token` table that has existed since migrations/0001_core.sql.
//
// Like login sessions (session.go), the plaintext secret is NEVER stored or returned after
// mint: only its SHA-256 lands in `token_hash`, so a database read never yields a usable
// credential. Redemption is PRE-TENANT — the token is presented unauthenticated and IS the
// identity — so it goes through the SECURITY DEFINER cp_enrollment_token_redeem function
// (migrations/0007_enrollment.sql), which atomically validates and consumes one use.
//
// Follows the repo's interface-plus-fakes pattern: EnrollmentTokenStore interface, in-memory
// fake here, pgx implementation in pgstore_enrollment.go.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultEnrollmentTokenTTL bounds a token minted without an explicit ttl_seconds. Enrollment
// secrets are distribution credentials (pasted into installers), so they must not be immortal.
const DefaultEnrollmentTokenTTL = 24 * time.Hour

// MaxEnrollmentTokenTTL caps what a caller may ASK for. The default above said enrollment secrets
// "must not be immortal", and then `ttl_seconds` was accepted unbounded — so the sentence was true
// only of tokens nobody customised.
//
// What an unbounded one grants is worth being concrete about: whoever holds the plaintext can plant
// a machine into the named group, and a machine's group is what every downstream authorization
// check scopes against (BackstageCapsFor, RequireMachine). A ten-year token is therefore a standing
// right to add a controllable endpoint to that group — it outlives the admin who minted it, the
// rollout it was minted for, and any memory of its existence, and it appears in the token listing
// as nothing more alarming than a distant date.
//
// 30 days is chosen to be longer than any real deployment window (an MSP staging a fleet rollout
// over a few weeks never has to re-mint mid-project) while keeping "forever" off the menu. A caller
// who genuinely needs longer mints again, which is one API call and leaves a fresh audit event —
// the good outcome, since it puts the decision back in front of somebody.
const MaxEnrollmentTokenTTL = 30 * 24 * time.Hour

// defaultEnrollmentMaxUses is the mint default: single-use unless the caller widens it.
const defaultEnrollmentMaxUses = 1

// MaxEnrollmentTokenUses caps what a caller may ASK for in `max_uses`, and is the other half of
// MaxEnrollmentTokenTTL. Capping the lifetime alone bounded how LONG a distribution credential
// stays live while leaving unbounded how MANY machines it plants — and the second is the sharper
// quantity, because every redemption adds another controllable endpoint to the group the token
// names. A token with max_uses in the billions is an open door for its whole (now bounded) life.
//
// 500 is chosen where a fleet rollout stops being a rollout. The legitimate wide-use case is
// staging a site — mint once, bake the secret into an installer image, redeem per machine — and 500
// endpoints is beyond the largest single site an MSP stages in one batch. Past that the operator
// mints again: one API call, and it leaves a fresh enrollment_token.mint audit event, which is the
// good outcome, since re-minting puts "how many machines is this secret good for?" back in front of
// a human.
//
// The ceiling also keeps the value inside the range its storage can hold. `enrollment_token.max_uses`
// is a PostgreSQL `int` (migrations/0001) — 32 bits — while the Go field decoded from JSON is a
// 64-bit `int`, so an uncapped request could carry a number the INSERT cannot store at all. See
// TestMintEnrollmentTokenRejectsAnUnboundedMaxUses for what that did before the cap.
const MaxEnrollmentTokenUses = 500

// ErrEnrollmentTokenInvalid is the ONE error redemption returns for an unknown, revoked,
// expired, or exhausted token. Deliberately undifferentiated: the redeem endpoint is
// unauthenticated, so the caller must not learn which check failed.
var ErrEnrollmentTokenInvalid = errors.New("invalid enrollment token")

// ErrEnrollmentTokenNotFound is the sentinel for revoking a token id unknown in the tenant.
var ErrEnrollmentTokenNotFound = errors.New("enrollment token not found")

// EnrollmentToken is one token's METADATA as the management API exposes it. It never carries
// the plaintext secret or its hash — the plaintext exists only in MintToken's return value.
type EnrollmentToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	GroupID   string    `json:"group_id"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	Uses      int       `json:"uses"`
	Revoked   bool      `json:"revoked"`
}

// EnrollmentTokenStore is the persistence seam for enrollment tokens. Production wires
// PgEnrollmentTokenStore; tests and DEV wire InMemoryEnrollmentTokenStore.
type EnrollmentTokenStore interface {
	// MintToken generates the high-entropy secret, persists its hash + the caller-supplied
	// metadata (GroupID, ExpiresAt, MaxUses, CreatedBy) tenant-pinned, populates the
	// store-assigned fields (ID, TenantID, CreatedAt, Uses) into tok, and returns the
	// PLAINTEXT — the only time it ever exists outside the client.
	MintToken(ctx context.Context, tenantID string, tok *EnrollmentToken) (plaintext string, err error)
	// ListTokens returns the tenant's tokens (metadata only), newest first.
	ListTokens(ctx context.Context, tenantID string) ([]EnrollmentToken, error)
	// RevokeToken revokes a token by id. Idempotent — re-revoking succeeds; an id unknown in
	// the tenant returns ErrEnrollmentTokenNotFound.
	RevokeToken(ctx context.Context, tenantID, id string) error
	// RedeemToken atomically validates + consumes one use of the token whose hash matches the
	// plaintext, returning the row (which carries the tenant + group to enroll into). This is
	// the PRE-TENANT path: it runs on the pool directly, not tenant-pinned. Any invalid token
	// (unknown / revoked / expired / exhausted / belonging to a SUSPENDED tenant — the last only
	// on the pg path, which is the only implementation with a tenant registry to consult; see
	// migrations/0011) is ErrEnrollmentTokenInvalid — nothing more.
	RedeemToken(ctx context.Context, plaintext string) (*EnrollmentToken, error)
}

// newEnrollmentSecret returns a fresh 256-bit URL-safe bearer secret (same shape as session
// tokens: 32 random bytes, base64url).
func newEnrollmentSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate enrollment secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// -------------------------------------------------------------------------------------
// InMemoryEnrollmentTokenStore — concurrency-safe fake for tests and DEV mode. Redemption
// (validate + increment) runs under the mutex, so max_uses holds under concurrency exactly as
// the single-UPDATE pg path does.
// -------------------------------------------------------------------------------------

type memEnrollmentToken struct {
	EnrollmentToken
	hash string // hashKey of the secret's SHA-256; never exposed
}

type InMemoryEnrollmentTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*memEnrollmentToken // key: token id
	// Now is injectable for expiry tests; defaults to time.Now.
	Now func() time.Time
}

// NewInMemoryEnrollmentTokenStore constructs an empty in-memory enrollment token store.
func NewInMemoryEnrollmentTokenStore() *InMemoryEnrollmentTokenStore {
	return &InMemoryEnrollmentTokenStore{tokens: make(map[string]*memEnrollmentToken)}
}

var _ EnrollmentTokenStore = (*InMemoryEnrollmentTokenStore)(nil)

func (s *InMemoryEnrollmentTokenStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// MintToken implements EnrollmentTokenStore.
func (s *InMemoryEnrollmentTokenStore) MintToken(_ context.Context, tenantID string, tok *EnrollmentToken) (string, error) {
	plaintext, err := newEnrollmentSecret()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := memEnrollmentToken{EnrollmentToken: *tok, hash: hashKey(HashToken(plaintext))}
	cp.TenantID = tenantID
	cp.ID = newUUID()
	cp.CreatedAt = s.now()
	cp.Uses = 0
	cp.Revoked = false
	s.tokens[cp.ID] = &cp
	*tok = cp.EnrollmentToken
	return plaintext, nil
}

// ListTokens implements EnrollmentTokenStore.
func (s *InMemoryEnrollmentTokenStore) ListTokens(_ context.Context, tenantID string) ([]EnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []EnrollmentToken{}
	for _, t := range s.tokens {
		if t.TenantID == tenantID {
			out = append(out, t.EnrollmentToken)
		}
	}
	return out, nil
}

// RevokeToken implements EnrollmentTokenStore.
func (s *InMemoryEnrollmentTokenStore) RevokeToken(_ context.Context, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok || t.TenantID != tenantID {
		return ErrEnrollmentTokenNotFound
	}
	t.Revoked = true
	return nil
}

// RedeemToken implements EnrollmentTokenStore: the same validate-and-consume the pg path does
// in one UPDATE, here under the mutex.
func (s *InMemoryEnrollmentTokenStore) RedeemToken(_ context.Context, plaintext string) (*EnrollmentToken, error) {
	want := hashKey(HashToken(plaintext))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.hash != want {
			continue
		}
		if t.Revoked || !s.now().Before(t.ExpiresAt) || t.Uses >= t.MaxUses {
			return nil, ErrEnrollmentTokenInvalid
		}
		t.Uses++
		cp := t.EnrollmentToken
		return &cp, nil
	}
	return nil, ErrEnrollmentTokenInvalid
}
