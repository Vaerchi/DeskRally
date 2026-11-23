package controlplane

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPgRememberedSessionPolicyAndIsolation(t *testing.T) {
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	ctx := context.Background()
	ta, ua := provisionUser(t, su, "remember-a", "a@test.example", "Original-Passw0rd!")
	tb, ub := provisionUser(t, su, "remember-b", "b@test.example", "Original-Passw0rd!")
	app := newAppRolePool(t, ctx)
	store := NewPgSessionStore(app)
	users := newPgUserStoreT(app)
	u, err := users.FindUserByID(ctx, ta, ua)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := NewSessionManager(store)
	m.Now = func() time.Time { return now }
	remembered, issued, err := m.IssueRemembered(ctx, ta, ua, u.CredentialUpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, _, err := m.Issue(ctx, tb, ub, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetByTokenHash(ctx, HashToken(remembered))
	if err != nil || !got.Remembered || !got.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("remembered roundtrip: %v", err)
	}
	other, err := store.GetByTokenHash(ctx, HashToken(ordinary))
	if err != nil || other.Remembered {
		t.Fatalf("ordinary roundtrip: %v", err)
	}
	// Even a direct query by a restricted app connection sees only its pinned tenant.
	if err := withTenant(ctx, app, tb, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM user_session WHERE id=$1", got.ID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("remembered session visible across tenant boundary")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A restarted manager must read the policy from PostgreSQL, not process memory.
	restarted := NewSessionManager(NewPgSessionStore(app))
	restarted.Now = m.Now
	now = now.Add(6 * 24 * time.Hour)
	observe := context.WithValue(ctx, sessionObservationKey{}, true)
	if _, err := restarted.Validate(observe, remembered); err != nil {
		t.Fatalf("six-day remembered session: %v", err)
	}
	now = now.Add(24 * time.Hour)
	if _, err := restarted.Validate(ctx, remembered); err != ErrSessionIdle {
		t.Fatalf("seven-day idle boundary: %v", err)
	}
	// New session with current credential: credential rotation must reject it through
	// the real authenticator even though its 30-day session row remains unrevoked.
	fresh, _, err := m.IssueRemembered(ctx, ta, ua, u.CredentialUpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.SetPassword(ctx, ta, ua, u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	auth := &SessionAuthenticator{Sessions: m, Users: users}
	req := httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+fresh)
	if _, err := auth.Authenticate(req); err != ErrSessionCredentialStale {
		t.Fatalf("credential rotation: %v", err)
	}
	if err := m.Revoke(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(ctx, fresh); err != ErrSessionRevoked {
		t.Fatalf("revocation: %v", err)
	}
}
