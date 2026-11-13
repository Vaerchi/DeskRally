package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// authFixture wires the real SessionAuthenticator + AuthService over in-memory fakes, the way
// production wires them over pgx — so the whole login → session → protected-request flow is
// exercised end-to-end without a database.
type authFixture struct {
	srv      *Server
	users    *InMemoryUserStore
	sessions *SessionManager
	auth     *AuthService
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	users := NewInMemoryUserStore()
	sessions := NewSessionManager(NewInMemorySessionStore())
	authSvc := &AuthService{Users: users, Sessions: sessions, Issuer: "RMT"}
	sessionAuth := &SessionAuthenticator{Sessions: sessions, Users: users}

	srv := NewServer(sessionAuth, NoopBinder{})
	srv.AuthAPI = authSvc
	// A permissive machine store so GET /machines (used to prove auth worked) reaches its handler
	// instead of failing on a missing store. These tests are about the session lifecycle, not D1.
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	return &authFixture{srv: srv, users: users, sessions: sessions, auth: authSvc}
}

// addUser registers a user with a hashed password and a single tenant-wide role.
func (f *authFixture) addUser(t *testing.T, tenantID, userID, email, password string, role Role) *AuthUser {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &AuthUser{ID: userID, TenantID: tenantID, Email: email, PasswordHash: hash}
	grant := NewGrant(userID, tenantID, NewMembership(role, AllGroups()))
	f.users.AddUser(u, grant)
	return u
}

// addUserWithGrant is addUser for a caller that needs a specific grant — a GROUP-SCOPED membership,
// or several memberships — rather than one tenant-wide role.
func (f *authFixture) addUserWithGrant(t *testing.T, tenantID, userID, email, password string, grant *Grant) *AuthUser {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &AuthUser{ID: userID, TenantID: tenantID, Email: email, PasswordHash: hash}
	f.users.AddUser(u, grant)
	return u
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, h, method, path, body, "", cookie)
}

// doJSONWith is doJSON plus the CSRF header (when csrfToken != "") and any number of cookies
// (nils skipped) — what a cookie-authenticated mutating request needs post-M4.
func doJSONWith(t *testing.T, h http.Handler, method, path string, body any, csrfToken string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		buf, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(buf)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	if csrfToken != "" {
		r.Header.Set(CSRFHeaderName, csrfToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == DefaultSessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

// csrfFrom returns the rmt_csrf cookie and the csrf_token from a login response body. They
// must match (double-submit) — a mismatch is a test failure, not a soft nil.
func csrfFrom(t *testing.T, rec *httptest.ResponseRecorder) (*http.Cookie, string) {
	t.Helper()
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login body: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName && c.Value != "" {
			if c.Value != body.CSRFToken {
				t.Fatalf("csrf cookie %q != body csrf_token %q", c.Value, body.CSRFToken)
			}
			return c, body.CSRFToken
		}
	}
	t.Fatal("login did not set the rmt_csrf cookie")
	return nil, ""
}

// Full happy path: log in, receive a session cookie, use it to reach a protected route.
func TestLoginThenAccessProtected(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "hunter2-long-enough", RoleTechnician)
	h := f.srv.Handler()

	// No session → protected route rejected.
	if rec := doJSON(t, h, "GET", "/machines", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /machines = %d, want 401", rec.Code)
	}

	rec := doJSON(t, h, "POST", "/auth/login", loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "hunter2-long-enough"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	if cookie == nil {
		t.Fatal("login did not set a session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	// The double-submit CSRF pair: non-HttpOnly cookie (the SPA reads it) matching the body.
	csrfCookie, _ := csrfFrom(t, rec)
	if csrfCookie.HttpOnly {
		t.Error("csrf cookie must NOT be HttpOnly (the client echoes it in X-CSRF-Token)")
	}

	// Technician has view_machines → 200 with the cookie.
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("authenticated /machines = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	// RBAC still enforced: technician lacks view_audit.
	if rec := doJSON(t, h, "GET", "/audit", nil, cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("technician /audit = %d, want 403", rec.Code)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleTechnician)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "wrong"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password login = %d, want 401", rec.Code)
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("failed login must not set a session cookie")
	}
}

func TestLoginUnknownUserOpaque(t *testing.T) {
	f := newAuthFixture(t)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "ghost@example.com", Password: "whatever"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-user login = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ErrInvalidCredentials.Error()) {
		t.Fatalf("unknown user should return the generic invalid-credentials message, got %s", rec.Body.String())
	}
}

// A TOTP-enrolled account: password alone is not enough; the correct code completes login.
func TestLoginWithTOTP(t *testing.T) {
	f := newAuthFixture(t)
	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	// Enroll + confirm directly in the store.
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	fixedNow := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return fixedNow }
	h := f.srv.Handler()

	// Password correct but no code → 401 totp required.
	rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("login without code = %d body %s, want 401 totp required", rec.Code, rec.Body.String())
	}

	// Wrong code → 401 invalid credentials (not "totp required").
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: "000000"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-code login = %d, want 401", rec.Code)
	}

	// Correct code → 200 with a session.
	code, _ := TOTPCode(secret, fixedNow, DefaultTOTPConfig)
	rec = doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login with correct code = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) == nil {
		t.Fatal("successful 2FA login did not set a session cookie")
	}
}

// RFC 6238 §5.2: a code that has already authenticated must not authenticate again. Without this,
// the ±1-step skew window keeps every code live for ~90 seconds — long enough for anyone who
// observes one (a shoulder-surf, a phished login, a proxy log, a replayed request) to log in as the
// user themselves.
func TestLoginTOTPCodeIsSingleUse(t *testing.T) {
	f := newAuthFixture(t)
	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	// Throttling off so the rejections below are provably the replay check, not a lockout.
	f.auth.DisableThrottle = true

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()

	code, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	creds := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code}

	if rec := doJSON(t, h, "POST", "/auth/login", creds, nil); rec.Code != http.StatusOK {
		t.Fatalf("first login = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// Same code, same instant → refused, with the opaque error (never "already used", which would
	// confirm to an attacker that the code was genuine).
	replay := doJSON(t, h, "POST", "/auth/login", creds, nil)
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), ErrInvalidCredentials.Error()) {
		t.Fatalf("replayed code = %d body %s, want 401 invalid credentials", replay.Code, replay.Body.String())
	}
	if sessionCookieFrom(replay) != nil {
		t.Fatal("replayed code must not establish a session")
	}
	// Still refused later in the SAME code's skew window — the whole point is that the window no
	// longer keeps it alive.
	now = now.Add(29 * time.Second)
	if rec := doJSON(t, h, "POST", "/auth/login", creds, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay inside the skew window = %d, want 401", rec.Code)
	}
	// A code from a LATER step still works: replay protection must not lock the account out.
	now = now.Add(61 * time.Second)
	next, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	if next == code {
		t.Fatal("test setup: expected a different code after advancing the clock")
	}
	fresh := creds
	fresh.TOTPCode = next
	if rec := doJSON(t, h, "POST", "/auth/login", fresh, nil); rec.Code != http.StatusOK {
		t.Fatalf("fresh code after a replay = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// And the spent step cannot be revisited by winding the clock back: last_step is monotonic.
	now = now.Add(-61 * time.Second)
	if rec := doJSON(t, h, "POST", "/auth/login", creds, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay after a clock rewind = %d, want 401", rec.Code)
	}
}

// The replay counter is per user: one user spending a step must never lock another user out, even
// when their codes and clocks line up.
func TestTOTPReplayCounterIsPerUser(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	for _, id := range []string{"u1", "u2"} {
		u := f.addUser(t, "tenant-1", id, id+"@example.com", "password-1234", RoleTechnician)
		if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
			t.Fatalf("SetTOTP %s: %v", id, err)
		}
	}
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()
	code, _ := TOTPCode(secret, now, DefaultTOTPConfig)

	for _, id := range []string{"u1", "u2"} {
		rec := doJSON(t, h, "POST", "/auth/login", loginRequest{
			Tenant: "tenant-1", Email: id + "@example.com", Password: "password-1234", TOTPCode: code,
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("login for %s = %d (body %s), want 200", id, rec.Code, rec.Body.String())
		}
	}
}

// TOTP enrollment through the protected HTTP endpoints, then confirmation activates 2FA.
func TestTOTPEnrollAndConfirmFlow(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	fixedNow := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return fixedNow }
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	cookie := sessionCookieFrom(login)
	if cookie == nil {
		t.Fatal("login failed to set cookie")
	}
	csrfCookie, csrfToken := csrfFrom(t, login)

	// A FIRST enrollment is a step-up: the current password proves the caller is the account owner
	// and not a session rider (HandleEnrollTOTP).
	enroll := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie)
	if enroll.Code != http.StatusOK {
		t.Fatalf("enroll = %d, want 200 (body %s)", enroll.Code, enroll.Body.String())
	}
	var er struct {
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(enroll.Body.Bytes(), &er); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	if er.Secret == "" || !strings.HasPrefix(er.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("bad enroll payload: %+v", er)
	}

	// The secret is PENDING, not enforced: login still succeeds without a code.
	pending, _ := f.users.FindUserByID(context.Background(), "tenant-1", "u1")
	if pending.TOTPPending != er.Secret || pending.TOTPSecret != "" || pending.TOTPConfirmed {
		t.Fatalf("after enroll: pending=%q secret=%q confirmed=%v", pending.TOTPPending, pending.TOTPSecret, pending.TOTPConfirmed)
	}

	// A wrong code is rejected while the enrollment is pending, and does not confirm it.
	if bad := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: "000000"}, csrfToken, cookie, csrfCookie); bad.Code != http.StatusForbidden {
		t.Fatalf("confirm with wrong code = %d, want 403", bad.Code)
	}

	// Confirm with a valid code.
	code, _ := TOTPCode(er.Secret, fixedNow, DefaultTOTPConfig)
	confirm := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code}, csrfToken, cookie, csrfCookie)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200 (body %s)", confirm.Code, confirm.Body.String())
	}

	// The pending secret was promoted, not merely flagged.
	u, _ := f.users.FindUserByID(context.Background(), "tenant-1", "u1")
	if !u.TOTPConfirmed || u.TOTPSecret != er.Secret || u.TOTPPending != "" {
		t.Fatalf("after confirm: secret=%q pending=%q confirmed=%v", u.TOTPSecret, u.TOTPPending, u.TOTPConfirmed)
	}

	// Nothing is pending any more, so a re-confirmation cannot re-activate anything.
	if again := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code}, csrfToken, cookie, csrfCookie); again.Code != http.StatusBadRequest {
		t.Fatalf("confirm with nothing pending = %d, want 400", again.Code)
	}
}

// The downgrade this closes: calling /auth/totp/enroll again on a 2FA-enabled account must not
// disarm the confirmed factor, and must not be possible at all without the CURRENT code.
func TestTOTPReEnrollCannotDisableConfirmed2FA(t *testing.T) {
	f := newAuthFixture(t)
	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	f.srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	f.auth.MgmtAudit = f.srv.MgmtAudit

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	// The clock is advanced deliberately before each code-bearing request below: a TOTP code is
	// accepted ONCE (RFC 6238 §5.2, enforced by ConsumeTOTPStep), and BOTH login and the re-enroll
	// step-up spend on that one ledger — so re-presenting an earlier code would be testing replay,
	// not the re-enrollment property this test is about.
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()

	code, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	creds := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code}
	login := doJSON(t, h, "POST", "/auth/login", creds, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("2FA login = %d (body %s)", login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	// (1) Re-enroll WITHOUT the current code is refused…
	bad := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{}, csrfToken, cookie, csrfCookie)
	if bad.Code != http.StatusForbidden {
		t.Fatalf("re-enroll without a code = %d, want 403 (body %s)", bad.Code, bad.Body.String())
	}
	// …and 2FA is untouched: password alone still cannot log in.
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("password-only login after refused re-enroll = %d body %s, want 401 totp required", rec.Code, rec.Body.String())
	}

	// (2) Re-enroll WITH a current code arms a PENDING secret only — the old authenticator still
	// logs in, and an abandoned re-enroll therefore leaves 2FA fully enforced. The clock moves on
	// first: `code` was spent by the login above, and the step-up consumes on that same ledger.
	now = now.Add(90 * time.Second)
	reCode, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	ok := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{Code: reCode}, csrfToken, cookie, csrfCookie)
	if ok.Code != http.StatusOK {
		t.Fatalf("re-enroll with the current code = %d (body %s)", ok.Code, ok.Body.String())
	}
	var er struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &er); err != nil || er.Secret == "" || er.Secret == secret {
		t.Fatalf("bad re-enroll payload (err %v): %s", err, ok.Body.String())
	}
	stored, _ := f.users.FindUserByID(context.Background(), "tenant-1", "u1")
	if stored.TOTPSecret != secret || !stored.TOTPConfirmed || stored.TOTPPending != er.Secret {
		t.Fatalf("re-enroll changed the enforced factor: %+v", stored)
	}
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("password-only login mid-re-enroll = %d body %s, want 401 totp required", rec.Code, rec.Body.String())
	}
	// The OLD authenticator still logs in — with a fresh code from a later time step, since the
	// earlier codes were spent by the login and the re-enroll step-up above.
	now = now.Add(90 * time.Second)
	freshCode, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	freshCreds := creds
	freshCreds.TOTPCode = freshCode
	if rec := doJSON(t, h, "POST", "/auth/login", freshCreds, nil); rec.Code != http.StatusOK {
		t.Fatalf("old authenticator mid-re-enroll = %d, want 200", rec.Code)
	}

	// (3) The 2FA lifecycle is on the management audit trail — BOTH legs of it. The refused
	// re-enrollment in (1) is the interesting one: something holding a live session tried to re-arm
	// the second factor and could not produce the current code, which is the shape of a session
	// rider and must not be invisible just because the request was denied.
	events, err := f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	// Assert on the TWO 2FA actions specifically — exactly one of each, both attributed to u1 —
	// rather than on the trail's total length. This flow also logs in twice, and those successful
	// logins are legitimately audited (auth.login); a total-count assertion would make this test
	// fail whenever any OTHER event is correctly added, which says nothing about the 2FA lifecycle
	// it exists to pin. The per-action counts keep the strength (a duplicate or missing leg still
	// fails) without the coupling.
	count := map[string]int{}
	seen := map[string]string{} // action → actor
	for _, e := range events {
		count[e.Action]++
		seen[e.Action] = e.ActorUserID
	}
	if count["totp.enroll"] != 1 || seen["totp.enroll"] != "u1" {
		t.Fatalf("totp.enroll count=%d actor=%q, want exactly 1 by u1; events = %+v",
			count["totp.enroll"], seen["totp.enroll"], events)
	}
	if count["auth.totp_enroll_denied"] != 1 || seen["auth.totp_enroll_denied"] != "u1" {
		t.Fatalf("auth.totp_enroll_denied count=%d actor=%q, want exactly 1 by u1; events = %+v",
			count["auth.totp_enroll_denied"], seen["auth.totp_enroll_denied"], events)
	}
}

// THE FIRST-ENROLLMENT STEP-UP. Arming an account's FIRST second factor decides what that factor
// will be forever, so a live session is not enough authority: someone riding a stolen session could
// otherwise enroll THEIR authenticator on an account that had none and hold a factor the real owner
// does not — after which the owner's password change no longer evicts them, because logging back in
// requires a code only the attacker can produce.
func TestFirstTOTPEnrollmentRequiresThePassword(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = audit
	f.auth.MgmtAudit = audit
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	// (1) A valid session with NO proof is refused …
	bare := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{}, csrfToken, cookie, csrfCookie)
	if bare.Code != http.StatusForbidden {
		t.Fatalf("first enroll with no password = %d, want 403 (body %s)", bare.Code, bare.Body.String())
	}
	if !strings.Contains(bare.Body.String(), "current password required") {
		t.Fatalf("refusal body = %s, want the password step-up message — a bare 401 could be the "+
			"session being rejected instead, which would make this test vacuous", bare.Body.String())
	}
	// … and so is a WRONG password.
	wrong := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "not-the-password"}, csrfToken, cookie, csrfCookie)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("first enroll with a wrong password = %d, want 403", wrong.Code)
	}
	// Nothing was armed by either refusal — no pending secret to later confirm.
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if u.TOTPPending != "" || u.TOTPSecret != "" {
		t.Fatalf("a refused enrollment armed a secret: pending=%q secret=%q", u.TOTPPending, u.TOTPSecret)
	}

	// (2) The correct password enrolls.
	ok := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie)
	if ok.Code != http.StatusOK {
		t.Fatalf("first enroll with the password = %d (body %s), want 200", ok.Code, ok.Body.String())
	}

	// (3) Both refusals are on the audit trail, and the success records which proof was accepted.
	events, err := audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	denied, enrolled := 0, 0
	var enrollMeta map[string]any
	for _, e := range events {
		switch e.Action {
		case "auth.totp_enroll_denied":
			denied++
		case "totp.enroll":
			enrolled++
			if err := json.Unmarshal(e.Metadata, &enrollMeta); err != nil {
				t.Fatalf("decode totp.enroll metadata: %v", err)
			}
		}
	}
	if denied != 2 || enrolled != 1 {
		t.Fatalf("audit: %d denied + %d enrolled, want 2 + 1 (events %+v)", denied, enrolled, events)
	}
	if enrollMeta["step_up"] != "password" {
		t.Fatalf("totp.enroll step_up = %v, want \"password\"", enrollMeta["step_up"])
	}
}

// An account with NO local credential has nothing to step up with, so it is answered 409 — the
// same refusal POST /me/password gives, for the same reason: a session alone must not be able to
// decide the account's second factor. Such an account is provisioned a password first
// (auth_password_reset.go).
func TestFirstTOTPEnrollmentWithoutACredentialIsRefused(t *testing.T) {
	f := newAuthFixture(t)
	// A user with a grant but no password at all.
	f.users.AddUser(&AuthUser{ID: "u1", TenantID: "tenant-1", Email: "federated@example.com"},
		NewGrant("u1", "tenant-1", NewMembership(RoleTechnician, AllGroups())))
	h := f.srv.Handler()

	// There is no password, so there is no login either — authenticate with a directly-issued
	// session, which is exactly the "holds a session, knows no secret" shape the step-up is about.
	token := issueSessionFor(t, t.Context(), f.users, f.sessions, "tenant-1", "u1")
	rec := doBearerJSON(t, h, "POST", "/auth/totp/enroll", token, enrollTOTPRequest{Password: "anything"}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("enroll with no credential = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ErrNoLocalCredential.Error()) {
		t.Fatalf("body = %s, want %q", rec.Body.String(), ErrNoLocalCredential.Error())
	}
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil || u.TOTPPending != "" {
		t.Fatalf("a refused enrollment armed a pending secret %q (err %v)", u.TOTPPending, err)
	}
}

// The two step-up branches do not substitute for each other: an account WITH a confirmed second
// factor must present a CODE, and the password — which is not the factor being re-armed — is not
// accepted in its place. Without this, "prove the current factor before replacing it" would be
// satisfiable by the one secret a session rider is most likely to have phished.
func TestReEnrollmentWillNotAcceptThePasswordInPlaceOfTheCode(t *testing.T) {
	f := newAuthFixture(t)
	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(t.Context(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }
	h := f.srv.Handler()

	code, _ := TOTPCode(secret, now, DefaultTOTPConfig)
	login := doJSON(t, h, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code,
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("2FA login = %d: %s", login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	rec := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("re-enroll with the password instead of a code = %d, want 403 (body %s)",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "current totp code required") {
		t.Fatalf("refusal body = %s, want the TOTP-code message — the password branch answering "+
			"here would mean the two proofs are interchangeable", rec.Body.String())
	}
	stored, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil || stored.TOTPPending != "" {
		t.Fatalf("the refused re-enrollment armed a pending secret %q (err %v)", stored.TOTPPending, err)
	}
}

// The step-up shares /me/password's PER-SESSION budget, which is the point: both verify the same
// secret presented from the same session, so an attacker riding one session gets a single
// allowance for the password instead of a fresh one on each endpoint to alternate between.
func TestEnrollmentStepUpSharesThePasswordThrottleBudget(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	// One free attempt, so the SECOND failure locks the key out — which means two guesses split
	// across the two endpoints are enough to prove they draw on one budget.
	f.auth.Throttle = NewThrottle(ThrottleConfig{
		FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Minute, Reset: time.Hour,
	})
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	// One wrong guess at each endpoint spends the shared allowance BETWEEN them…
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "wrong-one"}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("enroll guess = %d, want 403", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/me/password", map[string]string{
		"current_password": "wrong-two", "new_password": "Irrelevant-Passw0rd!",
	}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("password guess = %d, want 403", rec.Code)
	}
	// … so the third attempt is throttled REGARDLESS of which endpoint it arrives at. If the two
	// kept separate budgets, this would be another 401.
	if rec := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "wrong-three"}, csrfToken, cookie, csrfCookie); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third guess across the two endpoints = %d, want 429 (a shared per-session budget)", rec.Code)
	}
}

// Logout revokes the session server-side; the previously-good cookie stops working.
func TestLogoutRevokesSession(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	cookie := sessionCookieFrom(login)
	if cookie == nil {
		t.Fatal("login failed to set cookie")
	}
	csrfCookie, csrfToken := csrfFrom(t, login)
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("pre-logout /machines = %d, want 200", rec.Code)
	}

	// Logout is cookie-authenticated and mutating → it needs the CSRF pair too.
	if rec := doJSON(t, h, "POST", "/auth/logout", nil, cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf header = %d, want 403", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/auth/logout", nil, csrfToken, cookie, csrfCookie); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", rec.Code)
	}
	// Same cookie now rejected.
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /machines = %d, want 401", rec.Code)
	}
}

// Direct unit test of the credential core's disabled-user and TOTP-required branches.
func TestAuthenticateLocalBranches(t *testing.T) {
	f := newAuthFixture(t)
	ctx := context.Background()

	// Disabled user → invalid credentials even with the right password.
	hash, _ := HashPassword("pw-abcdef")
	f.users.AddUser(&AuthUser{ID: "d1", TenantID: "t", Email: "d@e.com", PasswordHash: hash, Disabled: true}, nil)
	if _, _, err := f.auth.authenticateLocal(ctx, loginRequest{Tenant: "t", Email: "d@e.com", Password: "pw-abcdef"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled user err = %v, want ErrInvalidCredentials", err)
	}
}

// TestLoginRequire2FABlocks: when a tenant has require_2fa=true, a member with no TOTP enrollment
// is refused at login with 403 ErrTOTPEnrollmentRequired — even though the password was correct.
func TestLoginRequire2FABlocks(t *testing.T) {
	f := newAuthFixture(t)
	hash, err := HashPassword("password-1234")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// AddUser copies the struct, so Require2FA must be set before the call.
	u := &AuthUser{ID: "u1", TenantID: "tenant-1", Email: "tech@example.com", PasswordHash: hash, Require2FA: true}
	f.users.AddUser(u, NewGrant("u1", "tenant-1", NewMembership(RoleTechnician, AllGroups())))

	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("require_2fa without enrollment = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ErrTOTPEnrollmentRequired.Error()) {
		t.Fatalf("403 body %q does not contain %q", rec.Body.String(), ErrTOTPEnrollmentRequired.Error())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("blocked login must not set a session cookie")
	}
}

// TestLoginRequire2FAAllowsEnrolled: a user who has TOTP confirmed can log in when require_2fa=true.
func TestLoginRequire2FAAllowsEnrolled(t *testing.T) {
	f := newAuthFixture(t)
	hash, err := HashPassword("password-1234")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u := &AuthUser{ID: "u1", TenantID: "tenant-1", Email: "tech@example.com", PasswordHash: hash, Require2FA: true}
	f.users.AddUser(u, NewGrant("u1", "tenant-1", NewMembership(RoleTechnician, AllGroups())))

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	fixedNow := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return fixedNow }

	code, _ := TOTPCode(secret, fixedNow, DefaultTOTPConfig)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enrolled user with require_2fa = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) == nil {
		t.Fatal("enrolled-user login did not set a session cookie")
	}
}
