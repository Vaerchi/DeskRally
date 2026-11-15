package controlplane

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// Security audit 2026-10-18: wrong step-up codes from one session are throttled on THAT session,
// and never lock the account owner out of signing in with the right code.
func TestPgStepUpFailuresDoNotLockTheOwnersLogin(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyAttendedMigration(t, pool)
	_, _ = provisionUser(t, pool, "acme", "op@acme.test", "password-1234")

	now := time.Unix(1_700_000_000, 0)
	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	authSvc := &AuthService{Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(pool),
		Issuer: "RMT", Now: func() time.Time { return now },
		Throttle: NewThrottle(ThrottleConfig{FreeAttempts: 1, BaseDelay: time.Hour, MaxDelay: time.Hour, Reset: time.Hour})}
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(pool))
	srv.AuthAPI = authSvc
	srv.Machines = NewPgMachineStore(pool)
	h := srv.Handler()
	creds := loginRequest{Tenant: "acme", Email: "op@acme.test", Password: "password-1234"}

	login := doJSON(t, h, "POST", "/auth/login", creds, nil)
	c1 := sessionCookieFrom(login)
	csrfC1, csrfT1 := csrfFrom(t, login)
	enroll := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{Password: "password-1234"}, csrfT1, c1, csrfC1)
	var er struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(enroll.Body.Bytes(), &er)
	code, _ := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code}, csrfT1, c1, csrfC1); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}

	// The rider of session c1 guesses: the session's own budget runs out (429, not 401).
	wrong, _ := TOTPCode(er.Secret, now.Add(10*time.Minute), DefaultTOTPConfig)
	last := 0
	for i := 0; i < 4; i++ {
		last = doJSONWith(t, h, "POST", "/auth/step-up", stepUpRequest{Code: wrong}, csrfT1, c1, csrfC1).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("step-up after repeated wrong codes = %d, want 429", last)
	}

	// The owner, elsewhere, signs in with password + the right code: not locked out.
	now = now.Add(90 * time.Second)
	withCode := creds
	withCode.TOTPCode, _ = TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if rec := doJSON(t, h, "POST", "/auth/login", withCode, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner login after another session's failed step-ups = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
