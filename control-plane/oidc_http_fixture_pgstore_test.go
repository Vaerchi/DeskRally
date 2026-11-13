package controlplane

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newPgAuthTestServer assembles the real Postgres-backed authentication stack the SSO handler tests
// drive: PgUserStore (with the test's TOTP cipher), the PgSessionStore-backed SessionManager, the real
// SessionAuthenticator + PgBinder, AuthService with Secure (__Host-) cookies, and Postgres management
// audit — the same pieces mfa_session_pgstore_test.go wires, so the SSO paths are exercised against
// the production session, CSRF and origin middleware rather than a stand-in.
//
// The handler is built LAZILY on first request: Handler() mounts the SSO routes only when s.OIDC and
// s.TenantHostSuffix are set, and the tests set those (and swap newEntraClient for the fake IdP) after
// this returns.
func newPgAuthTestServer(t *testing.T, app *pgxpool.Pool, cipher *TOTPCipher) (*Server, http.Handler) {
	t.Helper()
	users := NewPgUserStore(app)
	users.TOTP = cipher
	sessions := NewSessionManager(NewPgSessionStore(app))
	audit := NewPgMgmtAuditStore(app)
	authSvc := &AuthService{
		Users:        users,
		Sessions:     sessions,
		Tenants:      NewPgTenantResolver(app),
		Issuer:       "RMT",
		SecureCookie: true,
		MgmtAudit:    audit,
	}
	// The authenticator must read the SAME cookie AuthService sets: with SecureCookie the session cookie
	// is __Host-cp_session (production's name), and a default-named authenticator would see no session.
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users,
		CookieName: authSvc.sessionCookie("", time.Now()).Name}, NewPgBinder(app))
	srv.AuthAPI = authSvc
	srv.MgmtAudit = audit
	var once sync.Once
	var h http.Handler
	return srv, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { h = srv.Handler() })
		h.ServeHTTP(w, r)
	})
}

// setPgTestTOTP plants a CONFIRMED, cipher-sealed TOTP enrollment for the user (what enroll + confirm
// leave behind), clears any consumed steps so a test's first code is not a replay, and keeps the
// user's mfa_generation as the fixture set it.
func setPgTestTOTP(t *testing.T, su *pgxpool.Pool, cipher *TOTPCipher, tenantID, userID, secret string) {
	t.Helper()
	sealed, err := cipher.Seal(secret)
	if err != nil {
		t.Fatalf("seal TOTP secret: %v", err)
	}
	ctx := context.Background()
	if _, err := su.Exec(ctx, `
		INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at, pending_secret)
		VALUES ($1, $2, $3, now(), NULL)
		ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, confirmed_at = now(), pending_secret = NULL`,
		userID, tenantID, sealed); err != nil {
		t.Fatalf("plant TOTP enrollment: %v", err)
	}
	// The replay ledger is user_totp.last_step (migrations/0012); a fresh enrollment has none, so the
	// ON CONFLICT path must clear it too or a reused fixture would refuse its first code as a replay.
	if _, err := su.Exec(ctx, `UPDATE user_totp SET last_step = NULL WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("clear TOTP replay step: %v", err)
	}
}
