package controlplane

// End-to-end tests for POST /me/password over the real middleware chain
// (csrf → auth → tenant) and the in-memory stores, mirroring how auth_test.go exercises login.
// The DB-backed half — that the credential UPDATE really runs under RLS as the least-privilege
// rmt_app role — is TestPgPasswordChangeAsAppRole in password_pgstore_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	pwOld = "Original-Passw0rd!"
	pwNew = "Replacement-Passw0rd!"
)

// pwFixture is an authFixture with a user, an audit store, and a logged-in session.
type pwFixture struct {
	*authFixture
	handler http.Handler
	audit   *InMemoryMgmtAuditStore
	cookie  *http.Cookie
	csrf    *http.Cookie
	token   string
}

func newPwFixture(t *testing.T) *pwFixture {
	t.Helper()
	f := newAuthFixture(t)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = audit
	f.auth.MgmtAudit = audit
	f.addUser(t, "tenant-1", "u1", "dana@acme.test", pwOld, RoleTechnician)
	h := f.srv.Handler()

	rec := pwLogin(t, h, pwOld)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup login = %d: %s", rec.Code, rec.Body.String())
	}
	csrfCookie, csrfTok := csrfFrom(t, rec)
	return &pwFixture{
		authFixture: f, handler: h, audit: audit,
		cookie: sessionCookieFrom(rec), csrf: csrfCookie, token: csrfTok,
	}
}

func pwLogin(t *testing.T, h http.Handler, password string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, "POST", "/auth/login", map[string]string{
		"tenant": "tenant-1", "email": "dana@acme.test", "password": password,
	}, nil)
}

// change posts a password change on the fixture's own (cookie + CSRF) session.
func (f *pwFixture) change(t *testing.T, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
		"current_password": current, "new_password": next,
	}, f.token, f.cookie, f.csrf)
}

// storedHash returns the user's currently stored PHC hash.
func (f *pwFixture) storedHash(t *testing.T) string {
	t.Helper()
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "u1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	return u.PasswordHash
}

func (f *pwFixture) auditActions(t *testing.T) []string {
	t.Helper()
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

// The whole point, proven at the login boundary: after a change the OLD password stops working
// and the NEW one works. Anything less (checking only the stored hash changed) would pass even if
// the endpoint hashed the wrong field.
func TestChangePasswordThenLoginWithNewPassword(t *testing.T) {
	f := newPwFixture(t)
	before := f.storedHash(t)

	rec := f.change(t, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}
	if after := f.storedHash(t); after == before {
		t.Fatal("stored hash unchanged")
	}
	// Never stored in plaintext, and the new hash is a fresh argon2id (fresh salt ⇒ different
	// encoding even for the same input).
	if hash := f.storedHash(t); hash == pwNew || !VerifyOK(t, hash, pwNew) {
		t.Fatalf("stored credential does not verify the new password: %q", hash)
	}

	if rec := pwLogin(t, f.handler, pwOld); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with OLD password = %d, want 401", rec.Code)
	}
	if rec := pwLogin(t, f.handler, pwNew); rec.Code != http.StatusOK {
		t.Fatalf("login with NEW password = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// VerifyOK is a test helper: does this stored hash verify that plaintext?
func VerifyOK(t *testing.T, encoded, plaintext string) bool {
	t.Helper()
	ok, err := VerifyPassword(encoded, plaintext)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	return ok
}

// A password change must EVICT every session — otherwise an attacker who already logged in keeps a
// valid session for its full lifetime and the change is cosmetic. The caller's OWN session is
// revoked too and ROTATED: the response carries a fresh session + CSRF cookie pair, so the client
// keeps working while the token it presented is retired.
func TestChangePasswordRevokesEverySessionAndRotatesTheCallers(t *testing.T) {
	f := newPwFixture(t)

	// A second, independent login — stand-in for the attacker's (or another device's) session.
	other := pwLogin(t, f.handler, pwOld)
	if other.Code != http.StatusOK {
		t.Fatalf("second login = %d", other.Code)
	}
	otherCookie := sessionCookieFrom(other)
	otherCSRFCookie, otherCSRF := csrfFrom(t, other)

	// Both sessions work before the change.
	for name, c := range map[string]*http.Cookie{"caller": f.cookie, "other": otherCookie} {
		if rec := doJSON(t, f.handler, "GET", "/machines", nil, c); rec.Code != http.StatusOK {
			t.Fatalf("%s session pre-change = %d, want 200", name, rec.Code)
		}
	}

	oldCookie := f.cookie
	rec := f.change(t, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Changed   bool   `json:"changed"`
		Revoked   int    `json:"sessions_revoked"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// BOTH live sessions were revoked — the other device's and the caller's own.
	if !body.Changed || body.Revoked != 2 {
		t.Fatalf("response = %+v, want changed with 2 revoked (other + caller's own)", body)
	}

	// The OTHER session is dead...
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, otherCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session post-change = %d, want 401", rec.Code)
	}
	// ...including for mutations with its own (still well-formed) CSRF pair, so the revocation is
	// the authenticator's doing and not merely a CSRF mismatch.
	if rec := doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
		"current_password": pwNew, "new_password": "Third-Passw0rd!",
	}, otherCSRF, otherCookie, otherCSRFCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session mutation post-change = %d, want 401", rec.Code)
	}

	// REGRESSION (adversarial review): the token the caller PRESENTED must also be dead. Keeping it
	// alive would have exempted precisely the credential most likely to have been copied — whoever
	// holds a duplicate of that token would be the one session that survived the eviction.
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, oldCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the caller's PRESENTED session survived the change (%d); it must be rotated", rec.Code)
	}

	// ...and the response handed the caller a working replacement, so the UX is a rotation and not
	// a forced logout.
	newCookie := sessionCookieFrom(rec)
	if newCookie == nil || newCookie.Value == oldCookie.Value {
		t.Fatalf("no NEW session cookie issued (got %+v, old %q)", newCookie, oldCookie.Value)
	}
	newCSRFCookie, newCSRF := csrfFrom(t, rec)
	if newCSRF == "" || newCSRF == f.token {
		t.Fatal("the CSRF token was not rotated with the session")
	}
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, newCookie); rec.Code != http.StatusOK {
		t.Fatalf("rotated session = %d, want 200", rec.Code)
	}
	// The rotated pair works for a mutation too (the CSRF value really is derived from the new token).
	if rec := doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
		"current_password": pwNew, "new_password": "Third-Different-Passw0rd!",
	}, newCSRF, newCookie, newCSRFCookie); rec.Code != http.StatusOK {
		t.Fatalf("mutation on the rotated session = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// REGRESSION (adversarial review): the throttle must be keyed on the SESSION, not the account.
// With an account key, the attacker riding a stolen session could spend the victim's budget and
// hold a 429 over the ONLY endpoint that evicts them — for the session's full 12-hour life.
func TestChangePasswordThrottleIsPerSessionNotPerAccount(t *testing.T) {
	f := newPwFixture(t)

	// The "attacker": a second live session for the same user.
	thief := pwLogin(t, f.handler, pwOld)
	if thief.Code != http.StatusOK {
		t.Fatalf("thief login = %d", thief.Code)
	}
	thiefCookie := sessionCookieFrom(thief)
	thiefCSRFCookie, thiefCSRF := csrfFrom(t, thief)

	// Burn the thief's budget until it is definitively locked.
	locked := false
	for range 20 {
		rec := doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
			"current_password": "wrong-guess", "new_password": pwNew,
		}, thiefCSRF, thiefCookie, thiefCSRFCookie)
		if rec.Code == http.StatusTooManyRequests {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("test premise: the thief's own session was never throttled")
	}

	// The VICTIM, on their own session, with the correct current password, must still be able to
	// change it — and thereby evict the thief.
	rec := f.change(t, pwOld, pwNew)
	if rec.Code != http.StatusOK {
		t.Fatalf("victim's change = %d (%s); a stolen session must not be able to lock the owner "+
			"out of the endpoint that evicts it", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, thiefCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("thief session after the victim's change = %d, want 401", rec.Code)
	}
}

// A live session is NOT sufficient authority: the current password must be proven. This is what
// keeps a stolen session from becoming a permanent account takeover.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	f := newPwFixture(t)
	before := f.storedHash(t)

	for _, wrong := range []string{"", "not-the-password", pwNew} {
		rec := f.change(t, wrong, pwNew)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("change with current=%q = %d, want 403", wrong, rec.Code)
		}
	}
	if f.storedHash(t) != before {
		t.Fatal("password changed despite a wrong current password")
	}
	if rec := pwLogin(t, f.handler, pwOld); rec.Code != http.StatusOK {
		t.Fatalf("original password stopped working = %d", rec.Code)
	}
	// Each failure is audited — a run of these is the signal a SOC wants out of GET /audit.
	actions := f.auditActions(t)
	n := 0
	for _, a := range actions {
		if a == "auth.password_change_failed" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("audit actions = %v, want 3 auth.password_change_failed", actions)
	}
}

// The complexity policy is enforced at the endpoint, and a policy rejection leaves the stored
// credential untouched.
func TestChangePasswordEnforcesPolicy(t *testing.T) {
	f := newPwFixture(t)
	before := f.storedHash(t)

	for _, weak := range []string{
		"short1!",          // below MinLen
		"alllowercaseonly", // one class, under the passphrase exemption
		"password1234",     // blocklist
		"my-dana-Passw0rd", // echoes the account's email local part
		"dana@acme.test",   // IS the email
	} {
		rec := f.change(t, pwOld, weak)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("change to %q = %d, want 400: %s", weak, rec.Code, rec.Body.String())
		}
		var body struct {
			Error   string   `json:"error"`
			Reasons []string `json:"reasons"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Reasons) == 0 {
			t.Fatalf("no machine-readable reasons for %q: %s", weak, rec.Body.String())
		}
	}
	if f.storedHash(t) != before {
		t.Fatal("a policy-rejected password was stored")
	}
}

// "Changing" a password to itself must be refused, not silently reported as success — otherwise a
// user believes a compromised password has been retired when it has not.
func TestChangePasswordRejectsUnchangedPassword(t *testing.T) {
	f := newPwFixture(t)
	rec := f.change(t, pwOld, pwOld)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no-op change = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// Policy failures must NOT spend throttle budget — a user fumbling the complexity rules is not an
// attacker — while wrong-current-password attempts must, and eventually 429.
func TestChangePasswordThrottlesOnlyCredentialFailures(t *testing.T) {
	f := newPwFixture(t)

	// A pile of policy rejections leaves the budget intact: a correct change still succeeds.
	for range 10 {
		if rec := f.change(t, pwOld, "weak"); rec.Code != http.StatusBadRequest {
			t.Fatalf("policy rejection = %d, want 400", rec.Code)
		}
	}
	changed := f.change(t, pwOld, pwNew)
	if changed.Code != http.StatusOK {
		t.Fatalf("change after policy rejections = %d, want 200 (budget must be intact): %s",
			changed.Code, changed.Body.String())
	}
	// The change ROTATED the caller's session, so continue on the replacement pair the response
	// handed back (the presented cookie is deliberately dead now).
	cookie := sessionCookieFrom(changed)
	csrfCookie, csrfTok := csrfFrom(t, changed)

	// Wrong current passwords DO burn budget and eventually lock the endpoint.
	got429 := false
	for range 20 {
		rec := doJSONWith(t, f.handler, "POST", "/me/password", map[string]string{
			"current_password": "wrong-password-here", "new_password": "Another-Passw0rd!",
		}, csrfTok, cookie, csrfCookie)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			break
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("wrong current password = %d, want 403 or 429: %s", rec.Code, rec.Body.String())
		}
	}
	if !got429 {
		t.Fatal("repeated wrong-current-password attempts were never throttled")
	}
}

// The endpoint is inside the protected chain: unauthenticated requests are rejected, and a
// cookie-authenticated request without the CSRF header is rejected BEFORE any credential work.
func TestChangePasswordRequiresAuthAndCSRF(t *testing.T) {
	f := newPwFixture(t)
	body := map[string]string{"current_password": pwOld, "new_password": pwNew}

	if rec := doJSON(t, f.handler, "POST", "/me/password", body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
	// Cookie present, CSRF header absent → 403 from csrfMiddleware.
	if rec := doJSONWith(t, f.handler, "POST", "/me/password", body, "", f.cookie, f.csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header = %d, want 403", rec.Code)
	}
	// Cookie present, WRONG CSRF value → 403.
	if rec := doJSONWith(t, f.handler, "POST", "/me/password", body,
		"0000000000000000000000000000000000000000000000000000000000000000", f.cookie, f.csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF token = %d, want 403", rec.Code)
	}
	if f.storedHash(t) == "" {
		t.Fatal("credential vanished")
	}
	if rec := pwLogin(t, f.handler, pwOld); rec.Code != http.StatusOK {
		t.Fatal("password was changed by a request that should have been refused")
	}
}

// A Bearer-authenticated caller (no cookie ⇒ CSRF-exempt, per csrfMiddleware) can change its
// password. Every session dies, INCLUDING the bearer token that made the request — a non-browser
// client is handed its replacement in the Set-Cookie header exactly like a browser, and must adopt
// it or log in again. A bearer client that could keep using its old token would be the copied-token
// hole the rotation exists to close.
func TestChangePasswordViaBearerTokenRevokesThatTokenToo(t *testing.T) {
	f := newPwFixture(t)
	token := issueSessionFor(t, t.Context(), f.users, f.sessions, "tenant-1", "u1")
	var body struct {
		Revoked int `json:"sessions_revoked"`
	}
	// The bearer session plus the fixture's cookie session exist; the change must revoke BOTH.
	code := apiJSONAuth(t, f.srv, "POST", "/me/password", token,
		`{"current_password":"`+pwOld+`","new_password":"`+pwNew+`"}`, &body)
	if code != http.StatusOK {
		t.Fatalf("bearer change = %d", code)
	}
	if body.Revoked != 2 {
		t.Fatalf("sessions_revoked = %d, want 2 (bearer + cookie)", body.Revoked)
	}
	if code := apiJSONAuth(t, f.srv, "GET", "/machines", token, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("the bearer token that made the change is still valid (%d); it must be rotated", code)
	}
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, f.cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie session after bearer change = %d, want 401", rec.Code)
	}
	// The NEW password logs in cleanly, so the account is usable, not bricked.
	if rec := pwLogin(t, f.handler, pwNew); rec.Code != http.StatusOK {
		t.Fatalf("login with the new password = %d, want 200", rec.Code)
	}
}

// An account with no local credential has nothing to verify against, so self-service must refuse
// rather than let a session alone mint a first password (which would turn any stolen session into
// permanent access). Provisioning is an admin path — see the handler doc.
func TestChangePasswordRefusedWithoutLocalCredential(t *testing.T) {
	f := newPwFixture(t)
	// Strip the credential. This ADVANCES the credential epoch, so the fixture's logged-in session
	// is now correctly stale (migrations/0018) and a fresh one is minted afterwards — the login-side
	// half of that behaviour is asserted by TestCredentialEpochRefusesASessionOlderThanTheCredential.
	// Bearer auth, so the request is CSRF-exempt and needs no cookie pair.
	if _, err := f.users.SetPassword(t.Context(), "tenant-1", "u1", ""); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token := issueSessionFor(t, t.Context(), f.users, f.sessions, "tenant-1", "u1")

	var body struct {
		Error string `json:"error"`
	}
	code := apiJSONAuth(t, f.srv, "POST", "/me/password", token,
		`{"current_password":"","new_password":"Federated-Passw0rd!"}`, &body)
	if code != http.StatusConflict {
		t.Fatalf("change without a credential = %d, want 409: %s", code, body.Error)
	}
	if f.storedHash(t) != "" {
		t.Fatal("a first password was set through the self-service path")
	}
}

// The successful change is audited with the revocation count, so the trail records both that the
// credential changed and how much access it cut.
func TestChangePasswordAuditsSuccess(t *testing.T) {
	f := newPwFixture(t)
	if rec := f.change(t, pwOld, pwNew); rec.Code != http.StatusOK {
		t.Fatalf("change = %d", rec.Code)
	}
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) == 0 || events[0].Action != "auth.password_changed" {
		t.Fatalf("newest audit event = %+v, want auth.password_changed", events)
	}
	e := events[0]
	if e.ActorUserID != "u1" || e.TargetKind != "user" || e.TargetID != "u1" {
		t.Fatalf("audit event actor/target = %+v", e)
	}
	var meta map[string]any
	if err := json.Unmarshal(e.Metadata, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if _, ok := meta["sessions_revoked"]; !ok {
		t.Fatalf("audit metadata = %v, want sessions_revoked", meta)
	}
	// The trail must never carry either password.
	if s := string(e.Metadata); strings.Contains(s, pwOld) || strings.Contains(s, pwNew) {
		t.Fatalf("audit metadata leaked a password: %s", s)
	}
}
