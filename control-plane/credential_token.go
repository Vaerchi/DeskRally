package controlplane

// Credential-setup tokens — first-password provisioning and administrative reset, over
// `user_credential_token` (migrations/0020_credential_token.sql).
//
// The gap this closes: POST /me/password requires the CURRENT password, so an account with no
// credential could never acquire one and an account whose owner forgot theirs could never recover.
// Both needed a path that is authorized by something OTHER than a live session — because a session
// is the thing that gets stolen, and "set a first password from a session" would turn any session
// compromise into a permanent takeover.
//
// The answer is the same primitive the fleet already uses for unauthenticated enrollment: a
// high-entropy bearer secret an administrator mints for a NAMED user, stored only as its SHA-256,
// single-use, short-lived, revocable, and superseded by the next mint. Redemption is deliberately
// unauthenticated (the redeemer has no session — that is the point) and deliberately does NOT
// issue one, so possession of a link never becomes access to an account: it sets the password and
// the user then logs in through the one path that enforces TOTP.
//
// Follows the repo's interface-plus-fake pattern: CredentialTokenStore here with an in-memory
// implementation for tests/DEV, PgCredentialTokenStore in pgstore_credential_token.go.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultCredentialTokenTTL bounds a credential-setup token minted without an explicit TTL.
//
// It is far shorter than DefaultEnrollmentTokenTTL (24h) on purpose. An enrollment token is a
// distribution credential pasted into installer runs across a workday; a credential token is a
// standing ACCOUNT TAKEOVER primitive for whoever holds it — anyone who reads it out of a chat log
// or a mail spool sets that user's password. One hour is enough for "the admin tells the user the
// link is coming" and short enough that a leaked link is usually already dead.
const DefaultCredentialTokenTTL = time.Hour

// MaxCredentialTokenTTL caps what a caller may ask for. Without a ceiling, `ttl_seconds` on the
// mint endpoint would let an administrator (or anything that gets to make one request as one) mint
// an effectively immortal takeover link for another user's account, which is a longer-lived
// credential than any password this system issues.
const MaxCredentialTokenTTL = 24 * time.Hour

var (
	// ErrCredentialTokenInvalid is the ONE error redemption returns for an unknown, expired,
	// already-consumed, or revoked token — and equally for a disabled user or a suspended tenant.
	// Deliberately undifferentiated: the redeem endpoint is unauthenticated, so the caller must not
	// learn which check failed, or it becomes an oracle for which accounts exist and which are
	// disabled.
	ErrCredentialTokenInvalid = errors.New("invalid or expired credential token")
)

// CredentialToken is one token's METADATA. It never carries the plaintext secret or its hash —
// the plaintext exists only in Mint's return value, and the hash never leaves the database.
type CredentialToken struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Consumed  bool      `json:"consumed"`
	Revoked   bool      `json:"revoked"`
}

// CredentialTokenStore is the persistence seam for credential-setup tokens.
type CredentialTokenStore interface {
	// Mint generates the secret, revokes the user's outstanding tokens, persists the new one's
	// hash, and returns the PLAINTEXT — the only time it exists outside the client.
	//
	// The revocation and the insert MUST be one atomic operation. "Re-send the link" is the normal
	// way this endpoint is used, and if the two could interleave with another mint, a user could
	// end up with two live takeover links while the administrator believes there is one. Doing it
	// inside Mint (rather than leaving it to the caller) also means no future caller can forget.
	//
	// A userID outside tenantID MUST fail closed with ErrNoUser rather than minting: this is the
	// one write here that can hand somebody a login, so it does not trust the caller to have
	// resolved the user correctly.
	Mint(ctx context.Context, tenantID, userID, createdBy string, expiresAt time.Time) (plaintext string, tok *CredentialToken, err error)

	// Peek resolves a token to its (tenant, user) WITHOUT consuming it, applying every validity
	// condition Consume applies. It exists so the password policy — which needs the account's
	// email and display name, since it refuses a password echoing them — can be evaluated BEFORE
	// the one-shot token is spent. It grants nothing on its own; Consume is the gate.
	Peek(ctx context.Context, plaintext string) (*CredentialToken, error)

	// Consume atomically validates and marks the token used, returning it. Implementations MUST
	// make the check and the write one operation, so two concurrent redemptions cannot both
	// succeed, and MUST re-evaluate everything Peek checked rather than trusting the earlier call.
	Consume(ctx context.Context, plaintext string) (*CredentialToken, error)

	// RevokeForUser revokes every outstanding (unconsumed, unrevoked) token for a user, returning
	// how many were revoked. Tenant-pinned: the caller is authenticated here.
	RevokeForUser(ctx context.Context, tenantID, userID string) (int, error)
}

// -------------------------------------------------------------------------------------
// InMemoryCredentialTokenStore — concurrency-safe fake for tests and DEV. Mint's
// revoke-then-insert and Consume's validate-then-mark both run under the mutex, so they are as
// atomic here as the pg path's single transaction / single UPDATE.
// -------------------------------------------------------------------------------------

type memCredentialToken struct {
	CredentialToken
	hash string // hashKey of the secret's SHA-256; never exposed
}

// InMemoryCredentialTokenStore is the in-memory CredentialTokenStore.
//
// Users reports which (tenant, user) pairs exist and whether they are usable. The pg path gets
// that from the FK plus the disabled/suspended checks inside the SECURITY DEFINER functions; the
// fake has to be told, or it would happily mint for a user id that does not exist and hand tests a
// working token where production returns ErrNoUser.
type InMemoryCredentialTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*memCredentialToken // key: token id
	// Users is consulted by Mint (→ ErrNoUser) and by Peek/Consume (→ ErrCredentialTokenInvalid).
	// Optional: nil means "every user exists and is enabled", which is what the simplest handler
	// tests want.
	Users interface {
		FindUserByID(ctx context.Context, tenantID, userID string) (*AuthUser, error)
	}
	// Now is injectable for expiry tests; defaults to time.Now.
	Now func() time.Time
}

// NewInMemoryCredentialTokenStore constructs an empty in-memory credential-token store.
func NewInMemoryCredentialTokenStore() *InMemoryCredentialTokenStore {
	return &InMemoryCredentialTokenStore{tokens: make(map[string]*memCredentialToken)}
}

var _ CredentialTokenStore = (*InMemoryCredentialTokenStore)(nil)

func (s *InMemoryCredentialTokenStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// usable reports whether (tenantID, userID) names a user this store will mint or redeem for.
func (s *InMemoryCredentialTokenStore) usable(ctx context.Context, tenantID, userID string) bool {
	if s.Users == nil {
		return true
	}
	u, err := s.Users.FindUserByID(ctx, tenantID, userID)
	return err == nil && u != nil && !u.Disabled
}

// Mint implements CredentialTokenStore.
func (s *InMemoryCredentialTokenStore) Mint(ctx context.Context, tenantID, userID, createdBy string, expiresAt time.Time) (string, *CredentialToken, error) {
	if !s.usable(ctx, tenantID, userID) {
		return "", nil, ErrNoUser
	}
	plaintext, err := newEnrollmentSecret()
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Supersede first, in the same critical section as the insert.
	for _, t := range s.tokens {
		if t.TenantID == tenantID && t.UserID == userID && !t.Consumed && !t.Revoked {
			t.Revoked = true
		}
	}
	tok := memCredentialToken{
		CredentialToken: CredentialToken{
			ID:        newUUID(),
			TenantID:  tenantID,
			UserID:    userID,
			CreatedBy: createdBy,
			CreatedAt: s.now(),
			ExpiresAt: expiresAt,
		},
		hash: hashKey(HashToken(plaintext)),
	}
	s.tokens[tok.ID] = &tok
	out := tok.CredentialToken
	return plaintext, &out, nil
}

// findLocked returns the live token matching the plaintext, or nil. Caller holds s.mu.
func (s *InMemoryCredentialTokenStore) findLocked(ctx context.Context, plaintext string) *memCredentialToken {
	want := hashKey(HashToken(plaintext))
	for _, t := range s.tokens {
		if t.hash != want {
			continue
		}
		if t.Consumed || t.Revoked || !s.now().Before(t.ExpiresAt) {
			return nil
		}
		if !s.usable(ctx, t.TenantID, t.UserID) {
			return nil
		}
		return t
	}
	return nil
}

// Peek implements CredentialTokenStore.
func (s *InMemoryCredentialTokenStore) Peek(ctx context.Context, plaintext string) (*CredentialToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findLocked(ctx, plaintext)
	if t == nil {
		return nil, ErrCredentialTokenInvalid
	}
	cp := t.CredentialToken
	return &cp, nil
}

// Consume implements CredentialTokenStore: the same validate-and-mark the pg path does in one
// UPDATE, here under the mutex — so of two concurrent redemptions exactly one succeeds.
func (s *InMemoryCredentialTokenStore) Consume(ctx context.Context, plaintext string) (*CredentialToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findLocked(ctx, plaintext)
	if t == nil {
		return nil, ErrCredentialTokenInvalid
	}
	t.Consumed = true
	cp := t.CredentialToken
	return &cp, nil
}

// RevokeForUser implements CredentialTokenStore.
func (s *InMemoryCredentialTokenStore) RevokeForUser(_ context.Context, tenantID, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.tokens {
		if t.TenantID == tenantID && t.UserID == userID && !t.Consumed && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n, nil
}
