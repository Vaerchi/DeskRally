package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// issueSessionFor mints a session the way every REAL issue site does: stamped with the user's
// current credential epoch, taken from the same store read that would have returned the hash.
//
// Tests that hand-roll a zero epoch for a user who HAS a password are minting a session the
// authenticator is right to refuse (that is the whole point of migrations/0018), so they must go
// through here rather than calling Issue directly.
func issueSessionFor(t *testing.T, ctx context.Context, users UserStore, sessions *SessionManager,
	tenantID, userID string) string {
	t.Helper()
	u, err := users.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("FindUserByID(%s): %v", userID, err)
	}
	token, _, err := sessions.Issue(ctx, tenantID, userID, u.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

func TestSessionIssueAndValidate(t *testing.T) {
	ctx := context.Background()
	m := NewSessionManager(NewInMemorySessionStore())

	token, sess, err := m.Issue(ctx, "tenant-1", "user-1", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if sess.UserID != "user-1" || sess.TenantID != "tenant-1" {
		t.Fatalf("unexpected session: %+v", sess)
	}

	got, err := m.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.UserID != "user-1" || got.TenantID != "tenant-1" {
		t.Fatalf("validated session mismatch: %+v", got)
	}
}

// The plaintext token must never be persisted — only its hash.
func TestSessionStoresOnlyHash(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySessionStore()
	m := NewSessionManager(store)

	token, _, err := m.Issue(ctx, "t", "u", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// A lookup by the raw token bytes must miss; only the hash resolves.
	if _, err := store.GetByTokenHash(ctx, []byte(token)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("raw token resolved a session; store is not hash-only (err=%v)", err)
	}
	if _, err := store.GetByTokenHash(ctx, HashToken(token)); err != nil {
		t.Fatalf("hash lookup failed: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1_700_000_000, 0)
	m := NewSessionManager(NewInMemorySessionStore())
	m.TTL = time.Hour
	m.IdleTTL = 0 // isolate ABSOLUTE expiry; the idle timeout is exercised in TestSessionIdleTimeout
	m.Now = func() time.Time { return clock }

	token, _, err := m.Issue(ctx, "t", "u", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Still valid just before expiry.
	clock = clock.Add(59 * time.Minute)
	if _, err := m.Validate(ctx, token); err != nil {
		t.Fatalf("session should still be valid: %v", err)
	}
	// Expired after TTL elapses.
	clock = clock.Add(2 * time.Minute)
	if _, err := m.Validate(ctx, token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Validate after TTL = %v, want ErrSessionExpired", err)
	}
}

// TestSessionIdleTimeout: a session unused past IdleTTL is rejected even though its absolute
// ExpiresAt is far off; activity within the window keeps refreshing last-seen so it never idles out.
func TestSessionIdleTimeout(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1_700_000_000, 0)
	m := NewSessionManager(NewInMemorySessionStore())
	m.TTL = 12 * time.Hour // absolute expiry is nowhere near
	m.IdleTTL = 30 * time.Minute
	m.Now = func() time.Time { return clock }

	token, _, err := m.Issue(ctx, "t", "u", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Two requests 20 minutes apart each refresh last-seen, so neither idles out (40 min total).
	clock = clock.Add(20 * time.Minute)
	if _, err := m.Validate(ctx, token); err != nil {
		t.Fatalf("active session at +20m should be valid: %v", err)
	}
	clock = clock.Add(20 * time.Minute)
	if _, err := m.Validate(ctx, token); err != nil {
		t.Fatalf("active session at +40m (last seen +20m ago) should be valid: %v", err)
	}
	// Now go quiet past the idle window: idle-timed-out, despite the 12h absolute expiry.
	clock = clock.Add(31 * time.Minute)
	if _, err := m.Validate(ctx, token); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("idle session = %v, want ErrSessionIdle", err)
	}
}

func TestSessionRevoke(t *testing.T) {
	ctx := context.Background()
	m := NewSessionManager(NewInMemorySessionStore())

	token, _, err := m.Issue(ctx, "t", "u", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.Validate(ctx, token); err != nil {
		t.Fatalf("pre-revoke Validate: %v", err)
	}
	if err := m.Revoke(ctx, token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := m.Validate(ctx, token); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Validate after revoke = %v, want ErrSessionRevoked", err)
	}
}

func TestSessionUnknownToken(t *testing.T) {
	m := NewSessionManager(NewInMemorySessionStore())
	if _, err := m.Validate(context.Background(), "never-issued"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate(unknown) = %v, want ErrSessionNotFound", err)
	}
}
