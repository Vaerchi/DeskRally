package controlplane

// Unit tests for POST /me/email (HandleChangeEmail + InMemoryUserStore.SetEmail).
// These run against in-memory fakes — no database required. The companion
// email_change_pgstore_test.go proves the pg-level RLS and atomicity properties.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newEmailFixture wires an authFixture with a real MgmtAudit store so audit assertions work.
type emailFixture struct {
	*authFixture
	audit *InMemoryMgmtAuditStore
}

func newEmailFixture(t *testing.T) *emailFixture {
	t.Helper()
	f := newAuthFixture(t)
	audit := NewInMemoryMgmtAuditStore()
	f.auth.MgmtAudit = audit
	f.srv.MgmtAudit = audit
	return &emailFixture{authFixture: f, audit: audit}
}

// loginAndGetCSRF logs in and returns (sessionCookie, csrfCookie, csrfToken).
func loginAndGetCSRF(t *testing.T, h http.Handler, tenantID, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	rec := doJSON(t, h, "POST", "/auth/login", loginRequest{
		Tenant: tenantID, Email: email, Password: password,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	sessCookie := sessionCookieFrom(rec)
	csrfCookie, csrfToken := csrfFrom(t, rec)
	return sessCookie, csrfCookie, csrfToken
}

const (
	emailTenantID = "tid-email-tests"
	emailUserID   = "uid-email-tests"
	emailUserB    = "uid-email-b"
	emailTenantB  = "tid-email-b"
	emailOriginal = "dana@example.com"
	emailNew      = "dana.new@example.com"
	emailPassword = "Email-Test-Passw0rd!"
)

func setupEmailUser(t *testing.T, f *emailFixture) {
	t.Helper()
	f.addUser(t, emailTenantID, emailUserID, emailOriginal, emailPassword, RoleOwner)
}

// TestHandleChangeEmailHappyPath: the golden path — old email login fails, new succeeds; same userID/roles.
func TestHandleChangeEmailHappyPath(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()

	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	// A second session to prove all are revoked.
	otherSess, _, _ := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("change email = %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Changed         bool   `json:"changed"`
		Email           string `json:"email"`
		SessionsRevoked int    `json:"sessions_revoked"`
		CSRFToken       string `json:"csrf_token"`
		ExpiresAt       string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Changed || body.Email != emailNew {
		t.Fatalf("response = %+v, want changed with email %s", body, emailNew)
	}
	if body.SessionsRevoked != 2 {
		t.Fatalf("sessions_revoked = %d, want 2 (both sessions)", body.SessionsRevoked)
	}
	if body.CSRFToken == "" || body.ExpiresAt == "" {
		t.Fatalf("missing csrf_token or expires_at in response: %+v", body)
	}

	// Replacement session cookie must differ from the presented one.
	rotated := sessionCookieFrom(rec)
	if rotated == nil || rotated.Value == sessCookie.Value {
		t.Fatal("response did not issue a distinct replacement session cookie")
	}

	// Old email no longer works for login; new email does — same userID.
	if rec := doJSON(t, h, "POST", "/auth/login", loginRequest{
		Tenant: emailTenantID, Email: emailOriginal, Password: emailPassword,
	}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with OLD email = %d, want 401", rec.Code)
	}
	newLogin := doJSON(t, h, "POST", "/auth/login", loginRequest{
		Tenant: emailTenantID, Email: emailNew, Password: emailPassword,
	}, nil)
	if newLogin.Code != http.StatusOK {
		t.Fatalf("login with NEW email = %d: %s", newLogin.Code, newLogin.Body.String())
	}

	// Confirm the returned userID and roles are unchanged.
	u, err := f.users.FindUserByEmail(context.Background(), emailTenantID, emailNew)
	if err != nil {
		t.Fatalf("FindUserByEmail(new): %v", err)
	}
	if u.ID != emailUserID {
		t.Fatalf("userID changed: got %s, want %s", u.ID, emailUserID)
	}
	grant, err := f.users.GrantFor(context.Background(), emailTenantID, emailUserID)
	if err != nil {
		t.Fatalf("GrantFor: %v", err)
	}
	if len(grant.Members) == 0 {
		t.Fatal("roles were lost after email change")
	}

	// The original session and the other session are both dead.
	if rec := doJSON(t, h, "GET", "/machines", nil, sessCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("original session post-change = %d, want 401", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, otherSess); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session post-change = %d, want 401", rec.Code)
	}
	// Rotated session works.
	if rec := doJSON(t, h, "GET", "/machines", nil, rotated); rec.Code != http.StatusOK {
		t.Fatalf("rotated session post-change = %d, want 200", rec.Code)
	}
}

// TestHandleChangeEmailWrongPassword: step-up fails without expiring the login session.
func TestHandleChangeEmailWrongPassword(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: "wrong-password",
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong password = %d, want 403", rec.Code)
	}
	// Email unchanged.
	if _, err := f.users.FindUserByEmail(context.Background(), emailTenantID, emailOriginal); err != nil {
		t.Fatalf("original email no longer findable: %v", err)
	}
	if _, err := f.users.FindUserByEmail(context.Background(), emailTenantID, emailNew); err != ErrNoUser {
		t.Fatalf("new email should not exist yet, got err=%v", err)
	}
}

// TestHandleChangeEmailSameEmail: supplying the current email → 400.
func TestHandleChangeEmailSameEmail(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailOriginal,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("same email = %d, want 400", rec.Code)
	}
}

// TestHandleChangeEmailMalformed: invalid email shapes → 400.
func TestHandleChangeEmailMalformed(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	for _, bad := range []string{"", "notanemail", "@nodomain", "noat.com", strings.Repeat("a", 255) + "@b.c"} {
		rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
			CurrentPassword: emailPassword,
			NewEmail:        bad,
		}, csrfToken, sessCookie, csrfCookie)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed %q = %d, want 400", bad, rec.Code)
		}
	}
}

// TestHandleChangeEmailCSRFRefused: missing CSRF header → 403.
func TestHandleChangeEmailCSRFRefused(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()
	sessCookie, _, _ := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	// No CSRF token — doJSON passes empty string → no X-CSRF-Token header.
	rec := doJSON(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, sessCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no CSRF = %d, want 403", rec.Code)
	}
}

// TestHandleChangeEmailUnauthenticated: no session → 401.
func TestHandleChangeEmailUnauthenticated(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, "fake-csrf-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

// TestHandleChangeEmailDuplicateInTenant: new email already taken in the same tenant → 409.
func TestHandleChangeEmailDuplicateInTenant(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	// Add a second user holding the target address.
	f.addUser(t, emailTenantID, emailUserB, emailNew, "Other-Passw0rd!", RoleTechnician)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate in tenant = %d, want 409", rec.Code)
	}
}

// TestHandleChangeEmailSameAddressOtherTenant: the target address exists in another tenant → succeeds.
func TestHandleChangeEmailSameAddressOtherTenant(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	// Another tenant's user holds the same target address — must not block the change.
	f.addUser(t, emailTenantB, emailUserB, emailNew, "Other-Passw0rd!", RoleTechnician)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("cross-tenant same address = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// The other tenant's user is untouched.
	if _, err := f.users.FindUserByEmail(context.Background(), emailTenantB, emailNew); err != nil {
		t.Fatalf("other tenant's user email was altered: %v", err)
	}
}

// TestHandleChangeEmailNoLocalCredential: federated-only account → 409.
func TestHandleChangeEmailNoLocalCredential(t *testing.T) {
	f := newEmailFixture(t)
	// AddUser with empty hash simulates a credential-less account.
	f.users.AddUser(&AuthUser{
		ID: emailUserID, TenantID: emailTenantID, Email: emailOriginal,
		// No PasswordHash.
	}, nil)
	// We can't log in with a credential-less account the normal way; use stub auth directly.
	authSvc := f.auth
	_ = authSvc

	// Build a direct request with a fake session pinned to the credential-less user.
	users := f.users
	sessions := f.sessions
	// Issue a real session manually (no password required at the store level).
	token, sess, err := sessions.Issue(context.Background(), emailTenantID, emailUserID, time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_ = sess
	csrf := csrfTokenFor(token)
	sessCookie := &http.Cookie{Name: DefaultSessionCookie, Value: token}
	csrfCookie := &http.Cookie{Name: CSRFCookieName, Value: csrf}

	// The fixture's authMiddleware will call FindUserByID — the user exists (no credential), so
	// it resolves the principal. Then the handler checks PasswordHash == "" → 409.
	h := f.srv.Handler()
	_ = users
	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrf, sessCookie, csrfCookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("no credential = %d, want 409", rec.Code)
	}
}

// TestHandleChangeEmailStaleCredential: concurrent password change between verification and write → 409.
func TestHandleChangeEmailStaleCredential(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)

	// Directly call SetEmail with a stale (zero) epoch — the real epoch is non-zero.
	_, err := f.users.SetEmail(context.Background(), emailTenantID, emailUserID, emailNew, time.Time{})
	if err != ErrStaleCredential {
		t.Fatalf("SetEmail(stale epoch) = %v, want ErrStaleCredential", err)
	}
	// Email must be unchanged.
	if _, err := f.users.FindUserByEmail(context.Background(), emailTenantID, emailOriginal); err != nil {
		t.Fatalf("original email gone after stale write: %v", err)
	}
}

// TestHandleChangeEmailAuditTrail: success records auth.email_changed with old/new; wrong password
// records auth.email_change_failed.
func TestHandleChangeEmailAuditTrail(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)
	h := f.srv.Handler()
	sessCookie, csrfCookie, csrfToken := loginAndGetCSRF(t, h, emailTenantID, emailOriginal, emailPassword)

	// Failed attempt first.
	doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: "wrong",
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)

	// Successful change.
	doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)

	ctx := context.Background()
	events, err := f.audit.ListEvents(ctx, emailTenantID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var sawChanged, sawFailed bool
	for _, e := range events {
		switch e.Action {
		case "auth.email_changed":
			sawChanged = true
			if !strings.Contains(string(e.Metadata), emailOriginal) {
				t.Errorf("auth.email_changed metadata missing old_email: %s", e.Metadata)
			}
			if !strings.Contains(string(e.Metadata), emailNew) {
				t.Errorf("auth.email_changed metadata missing new_email: %s", e.Metadata)
			}
			if strings.Contains(string(e.Metadata), emailPassword) {
				t.Errorf("auth.email_changed metadata leaked password: %s", e.Metadata)
			}
		case "auth.email_change_failed":
			sawFailed = true
		}
	}
	if !sawChanged || !sawFailed {
		t.Fatalf("audit actions missing (changed=%v failed=%v): %+v", sawChanged, sawFailed, events)
	}
}

// TestHandleChangeEmailTOTPUnchanged: TOTP state is preserved after email change.
func TestHandleChangeEmailTOTPUnchanged(t *testing.T) {
	f := newEmailFixture(t)
	setupEmailUser(t, f)

	secret := "JBSWY3DPEHPK3PXP"
	if err := f.users.SetTOTP(context.Background(), emailTenantID, emailUserID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	h := f.srv.Handler()
	now := time.Now()
	f.auth.Now = func() time.Time { return now }
	code, err := TOTPCode(secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatal(err)
	}
	login := doJSON(t, h, "POST", "/auth/login", loginRequest{
		Tenant: emailTenantID, Email: emailOriginal, Password: emailPassword, TOTPCode: code,
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("TOTP login = %d: %s", login.Code, login.Body.String())
	}
	sessCookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	rec := doJSONWith(t, h, "POST", "/me/email", changeEmailRequest{
		CurrentPassword: emailPassword,
		NewEmail:        emailNew,
	}, csrfToken, sessCookie, csrfCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("change with TOTP armed = %d: %s", rec.Code, rec.Body.String())
	}

	u, err := f.users.FindUserByEmail(context.Background(), emailTenantID, emailNew)
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if u.TOTPSecret != secret || !u.TOTPConfirmed {
		t.Fatalf("TOTP state altered: secret=%q confirmed=%v", u.TOTPSecret, u.TOTPConfirmed)
	}
}

// TestInMemorySetEmailCrossTenant: SetEmail with the wrong tenantID must not modify the user.
func TestInMemorySetEmailCrossTenant(t *testing.T) {
	users := NewInMemoryUserStore()
	hash, _ := HashPassword("pw")
	uA := &AuthUser{ID: "uid-a", TenantID: "tid-a", Email: "a@a.test", PasswordHash: hash,
		CredentialUpdatedAt: time.Now().UTC()}
	users.AddUser(uA, nil)

	// Pin to tenant-b, try to modify uid-a.
	_, err := users.SetEmail(context.Background(), "tid-b", "uid-a", "new@a.test", uA.CredentialUpdatedAt)
	if err != ErrNoUser {
		t.Fatalf("cross-tenant SetEmail = %v, want ErrNoUser", err)
	}
	// Original email unchanged.
	if _, err := users.FindUserByEmail(context.Background(), "tid-a", "a@a.test"); err != nil {
		t.Fatalf("original email gone: %v", err)
	}
}
