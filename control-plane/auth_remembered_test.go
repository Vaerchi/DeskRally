package controlplane

// Remembered-session tests: fakeclock coverage of the absolute/idle boundaries, active-touch
// invariants, revocation, credential-epoch enforcement, login opt-in verification, and an
// in-memory roundtrip for the Remembered flag.
//
// These are unit / integration tests over in-memory stores — no Postgres, no RLS, no binary.
// The Pg roundtrip (migrations/0053 + cp_session_by_token SELECT *) is separately covered by
// the pgstore integration suite; what is verified here is that the Go layer persists and
// retrieves the flag correctly for the in-memory path.
//
// Clock control: every SessionManager in this file uses a *fakeNow helper that starts at a
// fixed epoch and can be advanced with .Add. Injecting it via SessionManager.Now means the
// tests exercise real boundary arithmetic without sleeping.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeNow is a minimal injectable clock for session tests.
type fakeNow struct{ t time.Time }

func newFakeNow(t time.Time) *fakeNow      { return &fakeNow{t: t} }
func (f *fakeNow) Now() time.Time          { return f.t }
func (f *fakeNow) Advance(d time.Duration) { f.t = f.t.Add(d) }

// t0 is an arbitrary but fixed test epoch, far from zero to avoid corner cases.
var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// newRememberedManager returns a SessionManager with a fakeNow clock and ordinary IdleTTL.
func newRememberedManager(clk *fakeNow) *SessionManager {
	return &SessionManager{
		Store:   NewInMemorySessionStore(),
		TTL:     DefaultSessionTTL,
		IdleTTL: DefaultSessionIdleTTL,
		Now:     clk.Now,
	}
}

// TestRememberedSessionAbsoluteExpiry: a remembered session expires at exactly 30 days even when
// actively touched right up to the boundary — the absolute limit is unconditional.
func TestRememberedSessionAbsoluteExpiry(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	token, sess, err := m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("IssueRemembered: %v", err)
	}
	if !sess.Remembered {
		t.Fatal("IssueRemembered: Remembered flag not set on returned Session")
	}
	want := t0.Add(RememberedSessionTTL)
	if !sess.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
	}

	// Touch repeatedly up to 1 ns before expiry — must still be valid.
	for i := 0; i < 4; i++ {
		clk.Advance(6 * 24 * time.Hour)
		if _, err := m.Validate(context.Background(), token); err != nil {
			t.Fatalf("active session at day %d: %v", (i+1)*6, err)
		}
	}
	clk.Advance(6*24*time.Hour - time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate just before absolute expiry: %v", err)
	}

	// Advance one nanosecond past expiry.
	clk.Advance(time.Nanosecond)
	_, err = m.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected expiry error at absolute boundary, got nil")
	}
	if err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

// TestOrdinarySessionAbsoluteExpiry: ordinary sessions still expire at 12 hours — IssueRemembered
// does not affect the Issue path or its ExpiresAt.
func TestOrdinarySessionAbsoluteExpiry(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)
	m.IdleTTL = 0 // Isolate ordinary absolute expiry; idle enforcement has its own test.

	token, sess, err := m.Issue(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sess.Remembered {
		t.Fatal("Issue: Remembered must be false on ordinary session")
	}
	want := t0.Add(DefaultSessionTTL)
	if !sess.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
	}

	clk.Advance(DefaultSessionTTL - time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("ordinary session valid just before 12h: %v", err)
	}

	clk.Advance(time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired after 12h, got %v", err)
	}
}

// TestRememberedSessionIdleExpiry: a remembered session idles out after 7 days of inactivity.
func TestRememberedSessionIdleExpiry(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	token, _, err := m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("IssueRemembered: %v", err)
	}

	// Advance to just under 7-day idle limit — one touch happened at issue, so this is the gap.
	clk.Advance(RememberedSessionIdleTTL - time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate just before 7d idle: %v", err)
	}

	// Advance one more nanosecond from last-seen (the Validate above touched it).
	clk.Advance(RememberedSessionIdleTTL - time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate just before 7d idle after touch: %v", err)
	}

	// Now idle for exactly 7 days without touching.
	clk.Advance(RememberedSessionIdleTTL)
	_, err = m.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected idle-timeout error, got nil")
	}
	if err != ErrSessionIdle {
		t.Fatalf("expected ErrSessionIdle, got %v", err)
	}
}

// TestOrdinarySessionIdleExpiry: ordinary sessions idle out at 30 minutes — the remembered path
// does not change ordinary-session idle enforcement.
func TestOrdinarySessionIdleExpiry(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	token, _, err := m.Issue(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	clk.Advance(DefaultSessionIdleTTL - time.Nanosecond)
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("ordinary session valid just before 30min idle: %v", err)
	}

	// Advance 30 min from the touch set by the Validate above.
	clk.Advance(DefaultSessionIdleTTL)
	if _, err := m.Validate(context.Background(), token); err != ErrSessionIdle {
		t.Fatalf("expected ErrSessionIdle after 30min idle, got %v", err)
	}
}

// TestActiveTouchDoesNotExtendAbsolute: repeatedly touching a remembered session via Validate
// never moves ExpiresAt forward — the absolute deadline is set at issue and is immutable.
func TestActiveTouchDoesNotExtendAbsolute(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	token, sess, err := m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("IssueRemembered: %v", err)
	}
	absoluteExpiry := sess.ExpiresAt

	// Touch every 6 days for 24 days (within idle timeout each time).
	for i := 0; i < 4; i++ {
		clk.Advance(6 * 24 * time.Hour)
		got, err := m.Validate(context.Background(), token)
		if err != nil {
			t.Fatalf("Validate at day %d: %v", (i+1)*6, err)
		}
		if !got.ExpiresAt.Equal(absoluteExpiry) {
			t.Fatalf("ExpiresAt moved after touch (day %d): %v != %v", (i+1)*6, got.ExpiresAt, absoluteExpiry)
		}
	}

	// Day 30: absolute expiry must have fired by now (we're past 30 days from t0).
	clk.Advance(7 * 24 * time.Hour)
	if _, err := m.Validate(context.Background(), token); err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired at day 31, got %v", err)
	}
}

// TestObservingReadDoesNotTouchLastSeen: a request with sessionObservationKey does not refresh
// last-seen, so a genuinely idle session that is only "observed" will still idle out.
func TestObservingReadDoesNotTouchLastSeen(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	token, _, err := m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})
	if err != nil {
		t.Fatalf("IssueRemembered: %v", err)
	}

	// Advance to 6 days — below the 7-day idle limit.
	clk.Advance(6 * 24 * time.Hour)

	// Observe (status-check): must succeed but must NOT update last-seen.
	obsCtx := context.WithValue(context.Background(), sessionObservationKey{}, true)
	if _, err := m.Validate(obsCtx, token); err != nil {
		t.Fatalf("observing Validate at day 6: %v", err)
	}

	// Advance another 2 days (8 days total since last true touch, which was at issue).
	// If the observing read had touched last-seen, last-seen would be at day 6 and the idle
	// clock would reset — we'd only be 2 days idle. If it did NOT touch, we're 8 days idle
	// and the session must have idled out.
	clk.Advance(2 * 24 * time.Hour)
	if _, err := m.Validate(context.Background(), token); err != ErrSessionIdle {
		t.Fatalf("expected ErrSessionIdle 8 days after last real touch, got %v", err)
	}
}

// TestRevocationHonoured: Revoke immediately prevents Validate from succeeding, for both
// ordinary and remembered sessions.
func TestRevocationHonoured(t *testing.T) {
	for _, remembered := range []bool{false, true} {
		t.Run(map[bool]string{true: "remembered", false: "ordinary"}[remembered], func(t *testing.T) {
			clk := newFakeNow(t0)
			m := newRememberedManager(clk)

			var (
				token string
				err   error
			)
			if remembered {
				token, _, err = m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})
			} else {
				token, _, err = m.Issue(context.Background(), "t1", "u1", time.Time{})
			}
			if err != nil {
				t.Fatalf("issue session: %v", err)
			}

			clk.Advance(time.Minute)
			if _, err := m.Validate(context.Background(), token); err != nil {
				t.Fatalf("Validate before revoke: %v", err)
			}

			if err := m.Revoke(context.Background(), token); err != nil {
				t.Fatalf("Revoke: %v", err)
			}

			if _, err := m.Validate(context.Background(), token); err != ErrSessionRevoked {
				t.Fatalf("expected ErrSessionRevoked after Revoke, got %v", err)
			}
		})
	}
}

// TestCredentialEpochRefusesRememberedSession: if the credential epoch advances (password/email
// change), a remembered session is refused by SessionAuthenticator on the next request, just
// like an ordinary one. This test exercises the epoch check at the Go layer via
// CredentialEpochMatches.
func TestCredentialEpochRefusesRememberedSession(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)
	users := NewInMemoryUserStore()

	const (
		tenantID = "t-epoch"
		userID   = "u-epoch"
		email    = "epoch@test.local"
		pw       = "horse-battery-staple-epoch"
	)
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &AuthUser{ID: userID, TenantID: tenantID, Email: email, PasswordHash: hash}
	users.AddUser(u, NewGrant(userID, tenantID))

	u2, _ := users.FindUserByID(context.Background(), tenantID, userID)
	epoch := u2.CredentialUpdatedAt

	token, _, err := m.IssueRemembered(context.Background(), tenantID, userID, epoch)
	if err != nil {
		t.Fatalf("IssueRemembered: %v", err)
	}

	// Advance 1 day (within remembered limits) — session still valid.
	clk.Advance(24 * time.Hour)
	sess, err := m.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate before epoch change: %v", err)
	}
	if !CredentialEpochMatches(sess.CredentialEpoch, epoch) {
		t.Fatal("epoch mismatch on unmodified credential — test precondition")
	}

	// Simulate a password change: SetPassword advances CredentialUpdatedAt.
	newHash, _ := HashPassword("new-password-rotated")
	newEpoch, err := users.SetPassword(context.Background(), tenantID, userID, newHash)
	if err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// The session still validates fine from the store perspective — expiry/revocation are intact.
	sess, err = m.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate after epoch change (store layer): %v", err)
	}
	// But CredentialEpochMatches now sees the session's old epoch against the new credential epoch.
	if CredentialEpochMatches(sess.CredentialEpoch, newEpoch) {
		t.Fatal("CredentialEpochMatches should return false: old session epoch vs new credential epoch")
	}
	// SessionAuthenticator would return ErrSessionCredentialStale here — verifying the predicate
	// rather than wiring the full HTTP stack, which is already exercised in credential_epoch_test.go.
}

// TestLoginRememberDeviceFalseIssuesOrdinarySession: POST /auth/login without remember_device
// issues a 12-hour session.
func TestLoginRememberDeviceFalseIssuesOrdinarySession(t *testing.T) {
	clk := newFakeNow(t0)
	f := newAuthFixtureWithClock(t, clk)
	f.addUser(t, "acme", "u1", "alice@acme.test", "Original-Passw0rd!", RoleOwner)

	rec := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"tenant":          "acme",
		"email":           "alice@acme.test",
		"password":        "Original-Passw0rd!",
		"remember_device": false,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	want := t0.Add(DefaultSessionTTL)
	if !exp.Equal(want) {
		t.Fatalf("ordinary session expires_at = %v, want %v", exp, want)
	}
}

// TestLoginRememberDeviceTrueIssuesLongSession: POST /auth/login with remember_device=true
// issues a 30-day session.
func TestLoginRememberDeviceTrueIssuesLongSession(t *testing.T) {
	clk := newFakeNow(t0)
	f := newAuthFixtureWithClock(t, clk)
	f.addUser(t, "acme", "u1", "alice@acme.test", "Original-Passw0rd!", RoleOwner)

	rec := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"tenant":          "acme",
		"email":           "alice@acme.test",
		"password":        "Original-Passw0rd!",
		"remember_device": true,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	want := t0.Add(RememberedSessionTTL)
	if !exp.Equal(want) {
		t.Fatalf("remembered session expires_at = %v, want %v", exp, want)
	}
}

// TestLoginRememberDeviceRequiresPasswordVerification: remember_device=true with a WRONG password
// is rejected the same way as an ordinary failed login — the flag has no effect on credential checking.
func TestLoginRememberDeviceRequiresPasswordVerification(t *testing.T) {
	clk := newFakeNow(t0)
	f := newAuthFixtureWithClock(t, clk)
	f.addUser(t, "acme", "u1", "bob@acme.test", "Original-Passw0rd!", RoleOwner)

	rec := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"tenant":          "acme",
		"email":           "bob@acme.test",
		"password":        "WRONG-password-never-matches",
		"remember_device": true,
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password with remember_device=true, got %d %s",
			rec.Code, rec.Body.String())
	}
	// No session cookie must have been set.
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, DefaultSessionCookie) && c.Value != "" {
			t.Fatalf("session cookie set despite authentication failure: %s=%s", c.Name, c.Value)
		}
	}
}

// TestLoginRememberDeviceRequiresTOTP: when TOTP is enrolled, remember_device=true still requires
// a valid TOTP code before issuing the remembered session.
func TestLoginRememberDeviceRequiresTOTP(t *testing.T) {
	clk := newFakeNow(t0)
	f := newAuthFixtureWithClock(t, clk)
	f.addUser(t, "acme", "u1", "carol@acme.test", "Original-Passw0rd!", RoleOwner)

	// Arm TOTP on the user.
	if err := f.users.SetTOTP(context.Background(), "acme", "u1", "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	// Password correct but no TOTP code + remember_device=true → must return totp-required, not a session.
	rec := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"tenant":          "acme",
		"email":           "carol@acme.test",
		"password":        "Original-Passw0rd!",
		"remember_device": true,
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (totp required), got %d %s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody.Error != ErrTOTPRequired.Error() {
		t.Fatalf("error = %q, want %q", errBody.Error, ErrTOTPRequired.Error())
	}
	code, err := TOTPCode("JBSWY3DPEHPK3PXP", clk.Now(), DefaultTOTPConfig)
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]any{"tenant": "acme", "email": "carol@acme.test",
		"password": "Original-Passw0rd!", "totp_code": code, "remember_device": true}
	ok := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", creds, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("valid remembered TOTP login: %d", ok.Code)
	}
	cookie := sessionCookieFrom(ok)
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	sess, err := f.sessions.Validate(context.Background(), cookie.Value)
	if err != nil || !sess.Remembered {
		t.Fatalf("remembered TOTP session: %v", err)
	}
	if replay := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", creds, nil); replay.Code != http.StatusUnauthorized {
		t.Fatalf("remembered login accepted a replayed TOTP: %d", replay.Code)
	}
}

// TestInMemoryRoundtripRememberedFlag: Insert followed by GetByTokenHash preserves the
// Remembered flag on InMemorySessionStore (the flag travels through the fake store unchanged).
func TestInMemoryRoundtripRememberedFlag(t *testing.T) {
	store := NewInMemorySessionStore()
	for _, rem := range []bool{false, true} {
		sess := &Session{
			ID:         "test-" + map[bool]string{true: "rem", false: "ord"}[rem],
			TenantID:   "t1",
			UserID:     "u1",
			TokenHash:  HashToken("token-" + map[bool]string{true: "rem", false: "ord"}[rem]),
			CreatedAt:  t0,
			ExpiresAt:  t0.Add(DefaultSessionTTL),
			LastSeen:   t0,
			Remembered: rem,
		}
		if err := store.Insert(context.Background(), sess); err != nil {
			t.Fatalf("Insert (remembered=%v): %v", rem, err)
		}
		got, err := store.GetByTokenHash(context.Background(), sess.TokenHash)
		if err != nil {
			t.Fatalf("GetByTokenHash (remembered=%v): %v", rem, err)
		}
		if got.Remembered != rem {
			t.Errorf("Remembered roundtrip: got %v, want %v", got.Remembered, rem)
		}
	}
}

// TestRevokeAllForUserClearsRememberedSessions: RevokeAllForUser revokes remembered sessions along
// with ordinary ones — no session kind is exempt from a "sign out everywhere" sweep.
func TestRevokeAllForUserClearsRememberedSessions(t *testing.T) {
	clk := newFakeNow(t0)
	m := newRememberedManager(clk)

	ordToken, _, _ := m.Issue(context.Background(), "t1", "u1", time.Time{})
	remToken, _, _ := m.IssueRemembered(context.Background(), "t1", "u1", time.Time{})

	n, err := m.RevokeOtherSessions(context.Background(), "t1", "u1", "")
	if err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeOtherSessions revoked %d sessions, want 2", n)
	}

	for _, tok := range []string{ordToken, remToken} {
		if _, err := m.Validate(context.Background(), tok); err != ErrSessionRevoked {
			t.Errorf("expected ErrSessionRevoked for token, got %v", err)
		}
	}
}

// TestPasswordChangeIssuesOrdinarySession: after HandleChangePassword the replacement session
// must be ordinary (Remembered = false), regardless of what the prior session was. Re-opting
// in to "remember device" requires a fresh login.
func TestPasswordChangeIssuesOrdinarySession(t *testing.T) {
	clk := newFakeNow(t0)
	f := newAuthFixtureWithClock(t, clk)
	f.addUser(t, "acme", "u1", "dave@acme.test", "Original-Passw0rd!", RoleOwner)

	// Log in with remember_device=true.
	loginRec := doJSON(t, f.srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"tenant":          "acme",
		"email":           "dave@acme.test",
		"password":        "Original-Passw0rd!",
		"remember_device": true,
	}, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d", loginRec.Code)
	}
	cookie := sessionCookieFrom(loginRec)
	csrfCookie, csrfToken := csrfFrom(t, loginRec)

	// Change password — must revoke the remembered session and issue an ordinary replacement.
	chgRec := doJSONWith(t, f.srv.Handler(), http.MethodPost, "/me/password", map[string]any{
		"current_password": "Original-Passw0rd!",
		"new_password":     "Replacement-Passw0rd!",
	}, csrfToken, cookie, csrfCookie)
	if chgRec.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", chgRec.Code, chgRec.Body.String())
	}

	// Validate the new session cookie from the change response.
	newCookie := sessionCookieFrom(chgRec)
	if newCookie == nil {
		t.Fatal("no new session cookie after password change")
	}

	// Locate the new session in the store by validating via the manager.
	newSess, err := f.sessions.Validate(context.Background(), newCookie.Value)
	if err != nil {
		t.Fatalf("Validate new session: %v", err)
	}
	if newSess.Remembered {
		t.Fatal("replacement session after password change must be ordinary (Remembered = false)")
	}
}

// -------------------------------------------------------------------------------------
// authFixtureWithClock — like newAuthFixture but injects a fake clock into the SessionManager
// so the tests above can control session timing.
// -------------------------------------------------------------------------------------

func newAuthFixtureWithClock(t *testing.T, clk *fakeNow) *authFixture {
	t.Helper()
	users := NewInMemoryUserStore()
	sessions := &SessionManager{
		Store:   NewInMemorySessionStore(),
		TTL:     DefaultSessionTTL,
		IdleTTL: DefaultSessionIdleTTL,
		Now:     clk.Now,
	}
	authSvc := &AuthService{
		Users:           users,
		Sessions:        sessions,
		Issuer:          "RMT-Test",
		DisableThrottle: true,
		Now:             clk.Now,
	}
	sessionAuth := &SessionAuthenticator{Sessions: sessions, Users: users}
	srv := NewServer(sessionAuth, NoopBinder{})
	srv.AuthAPI = authSvc
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	return &authFixture{srv: srv, users: users, sessions: sessions, auth: authSvc}
}

func TestRememberedEmailChangeReplacesWithOrdinarySession(t *testing.T) {
	f := newAuthFixtureWithClock(t, newFakeNow(t0))
	f.addUser(t, "acme", "u1", "email@acme.test", "Original-Passw0rd!", RoleOwner)
	h := f.srv.Handler()
	login := doJSON(t, h, "POST", "/auth/login", map[string]any{
		"tenant": "acme", "email": "email@acme.test", "password": "Original-Passw0rd!", "remember_device": true,
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d", login.Code)
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrf := csrfFrom(t, login)
	changed := doJSONWith(t, h, "POST", "/me/email", map[string]any{
		"current_password": "Original-Passw0rd!", "new_email": "new@acme.test",
	}, csrf, cookie, csrfCookie)
	if changed.Code != http.StatusOK {
		t.Fatalf("email change: %d %s", changed.Code, changed.Body.String())
	}
	next := sessionCookieFrom(changed)
	if next == nil {
		t.Fatal("missing replacement session")
	}
	sess, err := f.sessions.Validate(context.Background(), next.Value)
	if err != nil || sess.Remembered {
		t.Fatalf("ordinary replacement: %v", err)
	}
	if _, err := f.sessions.Validate(context.Background(), cookie.Value); err != ErrSessionRevoked {
		t.Fatalf("old remembered session not revoked: %v", err)
	}
}

func TestRememberedDisabledAccountAndSuspendedTenant(t *testing.T) {
	for _, suspension := range []bool{false, true} {
		f := newAuthFixtureWithClock(t, newFakeNow(t0))
		f.addUser(t, "acme", "u1", "disabled@acme.test", "Original-Passw0rd!", RoleOwner)
		u, err := f.users.FindUserByID(context.Background(), "acme", "u1")
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := f.sessions.IssueRemembered(context.Background(), "acme", "u1", u.CredentialUpdatedAt)
		if err != nil {
			t.Fatal(err)
		}
		auth := &SessionAuthenticator{Sessions: f.sessions, Users: f.users}
		req := httptest.NewRequest("GET", "/machines", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if _, err := auth.Authenticate(req); err != nil {
			t.Fatalf("before disabling: %v", err)
		}
		want := ErrUserDisabled
		if suspension {
			f.users.SetTenantSuspended("acme", true)
			want = ErrTenantSuspended
		} else {
			u.Disabled = true
			f.users.AddUser(u, nil)
		}
		if _, err := auth.Authenticate(req); err != want {
			t.Fatalf("after disabling: %v, want %v", err, want)
		}
	}
}
