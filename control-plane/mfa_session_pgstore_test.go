package controlplane

// Session-bound MFA (migrations/0054, platform-operator design v3) over real Postgres and the real
// HTTP handlers: which sessions are marked MFA-verified, for which generation, and when a second-factor
// change makes earlier marks stale.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type sessionMFA struct {
	verified   bool
	generation int64
}

func sessionMFAOf(t *testing.T, pool *pgxpool.Pool, c *http.Cookie) sessionMFA {
	t.Helper()
	var at *time.Time
	var gen *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT mfa_verified_at, mfa_generation FROM user_session WHERE token_hash = $1`,
		HashToken(c.Value)).Scan(&at, &gen); err != nil {
		t.Fatalf("session row: %v", err)
	}
	m := sessionMFA{verified: at != nil}
	if gen != nil {
		m.generation = *gen
	}
	return m
}

func userGeneration(t *testing.T, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	var g int64
	if err := pool.QueryRow(context.Background(), `SELECT mfa_generation FROM app_user WHERE email = $1`, email).Scan(&g); err != nil {
		t.Fatalf("generation: %v", err)
	}
	return g
}

func TestPgSessionMFAMarkingStepUpAndGenerationChange(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyAttendedMigration(t, pool)
	_, _ = provisionUser(t, pool, "acme", "op@acme.test", "password-1234")

	now := time.Unix(1_700_000_000, 0)
	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	authSvc := &AuthService{Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(pool),
		Issuer: "RMT", Now: func() time.Time { return now }}
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(pool))
	srv.AuthAPI = authSvc
	srv.Machines = NewPgMachineStore(pool)
	h := srv.Handler()
	creds := loginRequest{Tenant: "acme", Email: "op@acme.test", Password: "password-1234"}

	// A password-only session is never MFA-verified.
	login := doJSON(t, h, "POST", "/auth/login", creds, nil)
	c1 := sessionCookieFrom(login)
	csrfC1, csrfT1 := csrfFrom(t, login)
	if m := sessionMFAOf(t, pool, c1); m.verified {
		t.Fatalf("password-only session marked: %+v", m)
	}
	if g := userGeneration(t, pool, "op@acme.test"); g != 0 {
		t.Fatalf("generation before any enrollment = %d, want 0", g)
	}

	// Enroll + confirm bumps the generation.
	enroll := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{Password: "password-1234"}, csrfT1, c1, csrfC1)
	var er struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(enroll.Body.Bytes(), &er)
	code, _ := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code}, csrfT1, c1, csrfC1); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	gen1 := userGeneration(t, pool, "op@acme.test")
	if gen1 <= 0 {
		t.Fatalf("confirm did not bump the generation: %d", gen1)
	}
	// Confirmation is not a login: the enrolling session is still not MFA-verified.
	if m := sessionMFAOf(t, pool, c1); m.verified {
		t.Fatalf("confirming session got marked: %+v", m)
	}

	// A login that verified a code is marked, for the current generation.
	now = now.Add(90 * time.Second)
	withCode := creds
	withCode.TOTPCode, _ = TOTPCode(er.Secret, now, DefaultTOTPConfig)
	relogin := doJSON(t, h, "POST", "/auth/login", withCode, nil)
	if relogin.Code != http.StatusOK {
		t.Fatalf("2FA login = %d %s", relogin.Code, relogin.Body.String())
	}
	c2 := sessionCookieFrom(relogin)
	csrfC2, csrfT2 := csrfFrom(t, relogin)
	if m := sessionMFAOf(t, pool, c2); !m.verified || m.generation != gen1 {
		t.Fatalf("2FA login session = %+v, want verified for generation %d", m, gen1)
	}

	// Step-up on the password-only session c1 marks it; a replayed code is refused.
	now = now.Add(90 * time.Second)
	stepCode, _ := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: stepCode}, csrfT1, c1, csrfC1); rec.Code != http.StatusNoContent {
		t.Fatalf("step-up = %d %s", rec.Code, rec.Body.String())
	}
	if m := sessionMFAOf(t, pool, c1); !m.verified || m.generation != gen1 {
		t.Fatalf("after step-up: %+v", m)
	}
	if rec := doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: stepCode}, csrfT2, c2, csrfC2); rec.Code != http.StatusForbidden {
		t.Fatalf("replayed step-up code = %d, want 403", rec.Code)
	}
	// A wrong code is 403 too, never 401: the console signs the operator out on any 401.
	wrong, _ := TOTPCode(er.Secret, now.Add(10*time.Minute), DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: wrong}, csrfT2, c2, csrfC2); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong step-up code = %d, want 403", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: " "}, csrfT2, c2, csrfC2); rec.Code != http.StatusForbidden {
		t.Fatalf("blank step-up code = %d, want 403", rec.Code)
	}

	// Re-enrollment (a second-factor change) gives a new generation: both earlier marks are stale.
	now = now.Add(90 * time.Second)
	cur, _ := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	re := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{Code: cur}, csrfT2, c2, csrfC2)
	var er2 struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(re.Body.Bytes(), &er2)
	now = now.Add(90 * time.Second)
	code2, _ := TOTPCode(er2.Secret, now, DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code2}, csrfT2, c2, csrfC2); rec.Code != http.StatusOK {
		t.Fatalf("re-confirm = %d %s", rec.Code, rec.Body.String())
	}
	gen2 := userGeneration(t, pool, "op@acme.test")
	if gen2 <= gen1 {
		t.Fatalf("re-enrollment generation %d not above %d", gen2, gen1)
	}
	for _, c := range []*http.Cookie{c1, c2} {
		if m := sessionMFAOf(t, pool, c); m.generation == gen2 {
			t.Fatalf("an earlier session claims the new generation: %+v", m)
		}
	}
	// Stepping up with the NEW factor binds the session to the new generation.
	now = now.Add(90 * time.Second)
	code3, _ := TOTPCode(er2.Secret, now, DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: code3}, csrfT2, c2, csrfC2); rec.Code != http.StatusNoContent {
		t.Fatalf("step-up with the new factor = %d %s", rec.Code, rec.Body.String())
	}
	if m := sessionMFAOf(t, pool, c2); m.generation != gen2 {
		t.Fatalf("after step-up with the new factor: %+v, want generation %d", m, gen2)
	}
}

// MarkMFAVerified refuses a stale generation and a revoked session (the conditional UPDATE).
func TestPgMarkMFAVerifiedIsConditional(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	tid, uid := provisionUser(t, pool, "acme", "u@acme.test", "password-1234")
	mustExec(t, pool, `UPDATE app_user SET mfa_generation = 7 WHERE id = $1`, uid)
	store := NewPgSessionStore(pool)
	mgr := NewSessionManager(store)
	_, sess, err := mgr.Issue(ctx, tid, uid, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.MarkMFAVerified(ctx, tid, uid, sess.ID, 6); err != nil || ok {
		t.Fatalf("stale generation marked: %v %v", ok, err)
	}
	if ok, err := store.MarkMFAVerified(ctx, tid, uid, sess.ID, 7); err != nil || !ok {
		t.Fatalf("current generation not marked: %v %v", ok, err)
	}
	mustExec(t, pool, `UPDATE user_session SET revoked_at = now() WHERE id = $1`, sess.ID)
	if ok, _ := store.MarkMFAVerified(ctx, tid, uid, sess.ID, 7); ok {
		t.Fatal("revoked session marked")
	}
}
