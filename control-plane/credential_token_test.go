package controlplane

// End-to-end tests for the credential-token surface over the real middleware chain
// (csrf → auth → tenant) and the in-memory stores:
//
//	POST   /users/{id}/password-reset
//	DELETE /users/{id}/password-reset
//	POST   /auth/password/redeem
//
// WHAT THIS FILE CARRIES AND WHAT IT DOES NOT. These tests pin the HANDLER contract — status
// codes, the capability and privilege-hierarchy checks, what a redemption does and does not touch,
// the audit actions. They run entirely against fakes, so they would stay green if the SQL wrote to
// the wrong tenant, dropped a column, or let a consumed token be consumed twice. The persistence
// guarantees are pinned separately against a real database in credential_token_pgstore_test.go
// (TestPgCredentialTokenUnderRLS and friends) — see the header there.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	ctAdminPw  = "Admin-Origin4l-Pass!"
	ctTargetPw = "Target-Origin4l-Pass!"
	ctNewPw    = "Brand-New-Passw0rd!"
)

// ctFixture: an admin (CapManageUsers) and a technician target, both logged in as needed.
type ctFixture struct {
	*authFixture
	handler http.Handler
	audit   *InMemoryMgmtAuditStore
	tokens  *InMemoryCredentialTokenStore
	// The admin's authenticated session.
	adminCookie *http.Cookie
	adminCSRF   *http.Cookie
	adminToken  string
}

// newCTFixture builds the two accounts and logs the admin in. targetHasPassword=false models the
// FIRST-PROVISIONING case: an account that exists with no credential at all, which is exactly the
// account POST /me/password answers 409 for.
func newCTFixture(t *testing.T, targetHasPassword bool) *ctFixture {
	t.Helper()
	f := newAuthFixture(t)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = audit
	f.auth.MgmtAudit = audit
	tokens := NewInMemoryCredentialTokenStore()
	tokens.Users = f.users
	f.auth.CredentialTokens = tokens

	f.addUser(t, "tenant-1", "admin", "admin@acme.test", ctAdminPw, RoleAdmin)
	if targetHasPassword {
		f.addUser(t, "tenant-1", "target", "dana@acme.test", ctTargetPw, RoleTechnician)
	} else {
		f.users.AddUser(&AuthUser{ID: "target", TenantID: "tenant-1", Email: "dana@acme.test"},
			NewGrant("target", "tenant-1", NewMembership(RoleTechnician, AllGroups())))
	}
	h := f.srv.Handler()

	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "admin@acme.test", Password: ctAdminPw}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("admin login = %d: %s", login.Code, login.Body.String())
	}
	csrfCookie, csrfTok := csrfFrom(t, login)
	return &ctFixture{
		authFixture: f, handler: h, audit: audit, tokens: tokens,
		adminCookie: sessionCookieFrom(login), adminCSRF: csrfCookie, adminToken: csrfTok,
	}
}

// issue mints a reset link for userID as the logged-in admin, supplying the admin's own password
// (the step-up HandleIssuePasswordReset requires) plus any extra body fields.
func (f *ctFixture) issue(t *testing.T, userID string, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"password": ctAdminPw}
	for k, v := range extra {
		body[k] = v
	}
	return f.issueRaw(t, userID, body)
}

// issueRaw posts an arbitrary body — for the tests that are ABOUT the step-up and must control it.
func (f *ctFixture) issueRaw(t *testing.T, userID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONWith(t, f.handler, "POST", "/users/"+userID+"/password-reset", body,
		f.adminToken, f.adminCookie, f.adminCSRF)
}

// issuedToken mints a link and returns the plaintext, failing the test if the mint did not succeed.
func (f *ctFixture) issuedToken(t *testing.T, userID string) string {
	t.Helper()
	rec := f.issue(t, userID, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue reset for %s = %d: %s", userID, rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("bad issue payload (err %v): %s", err, rec.Body.String())
	}
	return body.Token
}

// redeem posts an UNAUTHENTICATED redemption — no session, no CSRF, which is the whole point.
func (f *ctFixture) redeem(t *testing.T, token, newPassword string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, f.handler, "POST", "/auth/password/redeem", map[string]string{
		"token": token, "new_password": newPassword,
	}, nil)
}

func (f *ctFixture) login(t *testing.T, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, f.handler, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: email, Password: password}, nil)
}

func (f *ctFixture) auditActions(t *testing.T) []string {
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

// THE HEADLINE: an account with NO credential — the one /me/password answers 409 for — can be
// given its first password through mint → redeem, and the proof is at the LOGIN boundary, not at
// the store. Checking only that a hash appeared would pass even if the hash were unusable.
func TestFirstPasswordProvisioningEndToEnd(t *testing.T) {
	f := newCTFixture(t, false)

	// Precondition, stated rather than assumed: self-service is genuinely closed for this account.
	// (Logging in is impossible, so this is asserted through the store the handler reads.)
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "target")
	if err != nil || u.PasswordHash != "" {
		t.Fatalf("target should start with no credential (err %v, hash %q)", err, u.PasswordHash)
	}
	if rec := f.login(t, "dana@acme.test", ctNewPw); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login before provisioning = %d, want 401", rec.Code)
	}

	tok := f.issuedToken(t, "target")
	rec := f.redeem(t, tok, ctNewPw)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d: %s", rec.Code, rec.Body.String())
	}
	// Redemption hands back NO session: possession of a link must not be access.
	if c := sessionCookieFrom(rec); c != nil {
		t.Fatalf("redemption issued a session cookie %q — a link-holder must have to log in", c.Value)
	}
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "csrf_token") {
		t.Fatalf("redemption response leaks a csrf token: %s", rec.Body.String())
	}

	if login := f.login(t, "dana@acme.test", ctNewPw); login.Code != http.StatusOK {
		t.Fatalf("login with the provisioned password = %d: %s", login.Code, login.Body.String())
	}
	// first_provision is recorded, so a reviewer can tell "this account had no password" from
	// "somebody replaced a live one".
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var issued *MgmtAuditEvent
	for i := range events {
		if events[i].Action == "auth.password_reset_issued" {
			issued = &events[i]
		}
	}
	if issued == nil {
		t.Fatalf("no auth.password_reset_issued in %v", f.auditActions(t))
	}
	if issued.ActorUserID != "admin" || issued.TargetID != "target" {
		t.Fatalf("issued event actor=%q target=%q, want actor admin and target target",
			issued.ActorUserID, issued.TargetID)
	}
	var meta map[string]any
	if err := json.Unmarshal(issued.Metadata, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if meta["first_provision"] != true {
		t.Fatalf("first_provision = %v, want true (metadata %s)", meta["first_provision"], issued.Metadata)
	}
}

// A reset REPLACES a live credential: the old password stops working, the new one works, and every
// session the account had is gone. Proven at the login boundary in both directions.
func TestAdminResetReplacesTheCredentialAndEvictsSessions(t *testing.T) {
	f := newCTFixture(t, true)

	// The target logs in, so there is a live session for the reset to evict.
	victimLogin := f.login(t, "dana@acme.test", ctTargetPw)
	if victimLogin.Code != http.StatusOK {
		t.Fatalf("target login = %d: %s", victimLogin.Code, victimLogin.Body.String())
	}
	victimCookie := sessionCookieFrom(victimLogin)
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, victimCookie); rec.Code != http.StatusOK {
		t.Fatalf("target session should work before the reset, got %d", rec.Code)
	}

	tok := f.issuedToken(t, "target")
	red := f.redeem(t, tok, ctNewPw)
	if red.Code != http.StatusOK {
		t.Fatalf("redeem = %d: %s", red.Code, red.Body.String())
	}

	if rec := f.login(t, "dana@acme.test", ctTargetPw); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the OLD password = %d, want 401", rec.Code)
	}
	if rec := f.login(t, "dana@acme.test", ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("login with the NEW password = %d: %s", rec.Code, rec.Body.String())
	}

	// The pre-reset session is dead. NOTE WHAT THIS DOES AND DOES NOT PROVE, because mutation
	// testing caught it claiming more than it showed: deleting the handler's RevokeOtherSessions
	// call left this assertion green. The CREDENTIAL EPOCH (migrations/0018) refuses a session
	// stamped with the previous credential version on its next request, so the 401 below arrives
	// with or without the explicit revocation.
	if rec := doJSON(t, f.handler, "GET", "/machines", nil, victimCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pre-reset session still works after the reset: %d, want 401", rec.Code)
	}
	// So the revocation itself is asserted separately, through the count the handler reports —
	// which is the only externally visible evidence that the eviction is a fact in storage rather
	// than something that happens lazily as each stale session next shows up.
	var body struct {
		Revoked int `json:"sessions_revoked"`
	}
	if err := json.Unmarshal(red.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode redeem body: %v", err)
	}
	if body.Revoked != 1 {
		t.Fatalf("sessions_revoked = %d, want 1 (the target's live session)", body.Revoked)
	}
}

// A redeemed token is SPENT. Without this, a link lifted from a chat log or a mail spool stays a
// standing takeover primitive for its whole TTL rather than for one use.
func TestCredentialTokenIsSingleUse(t *testing.T) {
	f := newCTFixture(t, true)
	tok := f.issuedToken(t, "target")
	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("first redeem = %d: %s", rec.Code, rec.Body.String())
	}
	second := f.redeem(t, tok, "Second-Attempt-Passw0rd!")
	if second.Code != http.StatusForbidden {
		t.Fatalf("second redeem = %d, want 403", second.Code)
	}
	// The second attempt changed nothing: the FIRST redemption's password is still the live one.
	if rec := f.login(t, "dana@acme.test", ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("login after the refused second redeem = %d, want 200", rec.Code)
	}
}

// Minting supersedes the user's outstanding links. "Re-send the link" is the ordinary way this
// endpoint gets used, and it must not accumulate live takeover primitives.
func TestMintingSupersedesOutstandingTokens(t *testing.T) {
	f := newCTFixture(t, true)
	first := f.issuedToken(t, "target")
	second := f.issuedToken(t, "target")
	if first == second {
		t.Fatal("two mints returned the same secret")
	}
	if rec := f.redeem(t, first, ctNewPw); rec.Code != http.StatusForbidden {
		t.Fatalf("superseded token redeem = %d, want 403", rec.Code)
	}
	if rec := f.redeem(t, second, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("newest token redeem = %d: %s", rec.Code, rec.Body.String())
	}
}

// DELETE cancels outstanding links, which is the only way to take back a link sent to the wrong
// place without minting another live one.
func TestRevokingCancelsOutstandingTokens(t *testing.T) {
	f := newCTFixture(t, true)
	tok := f.issuedToken(t, "target")
	rec := doJSONWith(t, f.handler, "DELETE", "/users/target/password-reset", nil,
		f.adminToken, f.adminCookie, f.adminCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Revoked != 1 {
		t.Fatalf("revoke payload = %s (err %v), want revoked:1", rec.Body.String(), err)
	}
	if red := f.redeem(t, tok, ctNewPw); red.Code != http.StatusForbidden {
		t.Fatalf("revoked token redeem = %d, want 403", red.Code)
	}
	// Idempotent: revoking again is a zero, not an error.
	again := doJSONWith(t, f.handler, "DELETE", "/users/target/password-reset", nil,
		f.adminToken, f.adminCookie, f.adminCSRF)
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"revoked":0`) {
		t.Fatalf("second revoke = %d %s, want 200 revoked:0", again.Code, again.Body.String())
	}
	// Cancelling a credential is itself a credential-lifecycle event: an administrator who quietly
	// kills the link a locked-out user is waiting for must not be invisible in the trail.
	var revokedEvent *MgmtAuditEvent
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for i := range events {
		if events[i].Action == "auth.password_reset_revoked" {
			revokedEvent = &events[i]
		}
	}
	if revokedEvent == nil {
		t.Fatalf("no auth.password_reset_revoked in %v", f.auditActions(t))
	}
	if revokedEvent.ActorUserID != "admin" || revokedEvent.TargetID != "target" {
		t.Fatalf("revoked event actor=%q target=%q, want admin / target",
			revokedEvent.ActorUserID, revokedEvent.TargetID)
	}
}

// An expired link is dead. The TTL is what bounds the window in which a leaked link is dangerous,
// so it has to be enforced rather than merely recorded.
func TestExpiredCredentialTokenIsRefused(t *testing.T) {
	f := newCTFixture(t, true)
	tok := f.issuedToken(t, "target")
	// Move the store's clock past the token's expiry. The TTL asserted here is DECLARED LOCALLY
	// rather than read from DefaultCredentialTokenTTL: a regression test whose premise lives in the
	// constant it is testing goes quiet the moment somebody edits that constant.
	const ttlUnderTest = time.Hour
	// The guard comes FIRST: if the shipped TTL ever exceeds what this test advances the clock by,
	// the failure must say so, not surface as a confusing "want 403" from a token that is simply
	// still valid.
	if DefaultCredentialTokenTTL != ttlUnderTest {
		t.Fatalf("DefaultCredentialTokenTTL is %v but this test advances the clock by %v — "+
			"update the local constant so the token really is expired when it is presented",
			DefaultCredentialTokenTTL, ttlUnderTest)
	}
	f.tokens.Now = func() time.Time { return time.Now().Add(ttlUnderTest + time.Minute) }
	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusForbidden {
		t.Fatalf("expired token redeem = %d, want 403", rec.Code)
	}
}

// THE MINT STEP-UP. This endpoint hands out an account-takeover primitive, so a live session is
// not sufficient authority for it — otherwise a stolen admin session converts into a password,
// which is durable where the session is not, and that is exactly what /me/password refuses to let
// a session do.
func TestIssueResetRequiresTheCallersPassword(t *testing.T) {
	f := newCTFixture(t, true)

	// No proof at all → 401, and nothing is minted.
	bare := f.issueRaw(t, "target", map[string]any{})
	if bare.Code != http.StatusForbidden {
		t.Fatalf("mint with no password = %d, want 403 (body %s)", bare.Code, bare.Body.String())
	}
	if !strings.Contains(bare.Body.String(), "current password required") {
		t.Fatalf("refusal body = %s, want the step-up message — a bare 401 could be the session "+
			"being rejected instead, which would make this test vacuous", bare.Body.String())
	}
	// A WRONG password → 401.
	if wrong := f.issueRaw(t, "target", map[string]any{"password": "not-the-admins-password"}); wrong.Code != http.StatusForbidden {
		t.Fatalf("mint with a wrong password = %d, want 403", wrong.Code)
	}
	// Neither refusal left a usable link behind.
	n, err := f.tokens.RevokeForUser(t.Context(), "tenant-1", "target")
	if err != nil || n != 0 {
		t.Fatalf("refused mints left %d outstanding token(s) (err %v)", n, err)
	}
	// The refusals are audited: a run of them is a session rider guessing at the password behind
	// the session it stole.
	denied := 0
	for _, a := range f.auditActions(t) {
		if a == "auth.password_reset_denied" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("audited %d denials, want 2 (actions %v)", denied, f.auditActions(t))
	}
	// The correct password mints.
	if ok := f.issue(t, "target", nil); ok.Code != http.StatusCreated {
		t.Fatalf("mint with the correct password = %d: %s", ok.Code, ok.Body.String())
	}
}

// Minting for YOUR OWN account is a password change, and /me/password is the endpoint for that —
// it verifies the current password, rejects a no-op, and rotates every session. A second, weaker
// path to the same mutation is refused rather than quietly supported.
func TestIssueResetRefusesSelfTargeting(t *testing.T) {
	f := newCTFixture(t, true)
	rec := f.issue(t, "admin", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("self-targeted mint = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/me/password") {
		t.Fatalf("refusal body = %s, want it to name the right endpoint", rec.Body.String())
	}
	n, err := f.tokens.RevokeForUser(t.Context(), "tenant-1", "admin")
	if err != nil || n != 0 {
		t.Fatalf("self-targeted mint left %d token(s) behind (err %v)", n, err)
	}
}

// GROUP SCOPE IS PART OF AUTHORITY. An Admin scoped to one machine group must not be able to
// re-credential an account whose powers reach a group they hold no rights over: they would redeem
// the link themselves, log in as that account, and pass the RequireMachine / AllowsInGroup checks
// that their own grant fails. Comparing capabilities tenant-wide — which is what Grant.Allows
// does — misses this entirely, because every capability the target holds is one the Admin holds
// SOMEWHERE.
func TestResetCannotEscalateAcrossGroupScopes(t *testing.T) {
	f := newCTFixture(t, true)
	// Alice administers group-a ONLY. Bob is a technician in group-b.
	f.addUserWithGrant(t, "tenant-1", "alice", "alice@acme.test", ctAdminPw,
		NewGrant("alice", "tenant-1", NewMembership(RoleAdmin, Groups("group-a"))))
	f.addUserWithGrant(t, "tenant-1", "bob", "bob@acme.test", ctTargetPw,
		NewGrant("bob", "tenant-1", NewMembership(RoleTechnician, Groups("group-b"))))
	// …and a technician inside Alice's own group, to prove the guard is not simply refusing
	// everything (which would make the assertion above meaningless).
	f.addUserWithGrant(t, "tenant-1", "carol", "carol@acme.test", ctTargetPw,
		NewGrant("carol", "tenant-1", NewMembership(RoleTechnician, Groups("group-a"))))

	login := f.login(t, "alice@acme.test", ctAdminPw)
	if login.Code != http.StatusOK {
		t.Fatalf("alice login = %d: %s", login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfTok := csrfFrom(t, login)
	mint := func(target string) *httptest.ResponseRecorder {
		return doJSONWith(t, f.handler, "POST", "/users/"+target+"/password-reset",
			map[string]any{"password": ctAdminPw}, csrfTok, cookie, csrfCookie)
	}

	// PREMISE, asserted rather than assumed: Alice genuinely cannot act in group-b today.
	aliceGrant, err := f.users.GrantFor(t.Context(), "tenant-1", "alice")
	if err != nil {
		t.Fatalf("GrantFor: %v", err)
	}
	if aliceGrant.AllowsInGroup(CapStartSession, "group-b") {
		t.Fatal("premise broken: alice already reaches group-b, so this test proves nothing")
	}
	if !aliceGrant.Allows(CapStartSession) {
		t.Fatal("premise broken: the tenant-wide check would already refuse alice for the wrong reason")
	}

	if rec := mint("bob"); rec.Code != http.StatusForbidden {
		t.Fatalf("group-a admin minting for a group-b technician = %d, want 403 (body %s)",
			rec.Code, rec.Body.String())
	}
	if rec := mint("carol"); rec.Code != http.StatusCreated {
		t.Fatalf("group-a admin minting for a group-a technician = %d, want 201 (body %s)",
			rec.Code, rec.Body.String())
	}
}

// THE PRIVILEGE-HIERARCHY GUARD. CapManageUsers must not be a back door to every other capability:
// an Admin who could mint a reset link for the Owner could redeem it, set a password, and hold
// CapManageTenant — with the trail showing nothing worse than a password reset.
func TestResetCannotEscalateToAMorePrivilegedAccount(t *testing.T) {
	f := newCTFixture(t, true)
	// An Owner — strictly more capable than the Admin (CapManageTenant).
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", ctTargetPw, RoleOwner)

	rec := f.issue(t, "owner", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin minting a reset for the owner = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "capabilities you do not hold") {
		t.Fatalf("escalation refusal body = %s, want the escalation message (a bare 403 could be "+
			"any other check firing)", rec.Body.String())
	}
	// Nothing was minted: no token exists for the owner to be redeemed by anyone.
	n, err := f.tokens.RevokeForUser(t.Context(), "tenant-1", "owner")
	if err != nil || n != 0 {
		t.Fatalf("refused mint left %d outstanding token(s) (err %v)", n, err)
	}
	// The lateral case still works — an Admin may reset a Technician, whose capabilities are a
	// subset of theirs. Without this leg the test would also pass if the guard refused everything.
	if ok := f.issue(t, "target", nil); ok.Code != http.StatusCreated {
		t.Fatalf("admin minting a reset for a technician = %d, want 201 (body %s)", ok.Code, ok.Body.String())
	}
}

// A reset re-provisions the FIRST factor only. If it cleared TOTP, an administrator could use it to
// walk into any account in the tenant; because it does not, the owner's second factor still stands
// between them and the account even after the password is theirs.
func TestRedemptionDoesNotDisarmTOTP(t *testing.T) {
	f := newCTFixture(t, true)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(t.Context(), "tenant-1", "target", secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	tok := f.issuedToken(t, "target")
	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d: %s", rec.Code, rec.Body.String())
	}
	// The new password alone does NOT get in — the second factor is still enforced.
	rec := f.login(t, "dana@acme.test", ctNewPw)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("login after reset = %d body %s, want 401 %q", rec.Code, rec.Body.String(), ErrTOTPRequired.Error())
	}
	// …and the enrollment is untouched in the store, not merely still flagged.
	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "target")
	if err != nil || u.TOTPSecret != secret || !u.TOTPConfirmed {
		t.Fatalf("reset disturbed the second factor: secret==original %v confirmed=%v (err %v)",
			u.TOTPSecret == secret, u.TOTPConfirmed, err)
	}
	// With a code, the new password works — proving the refusal above was the second factor and
	// not a broken password write.
	code, err := TOTPCode(secret, time.Now(), DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	full := doJSON(t, f.handler, "POST", "/auth/login", loginRequest{
		Tenant: "tenant-1", Email: "dana@acme.test", Password: ctNewPw, TOTPCode: code,
	}, nil)
	if full.Code != http.StatusOK {
		t.Fatalf("login with the new password + code = %d: %s", full.Code, full.Body.String())
	}
}

// The redemption is a policy checkpoint like every other password write, and — crucially — a
// rejected password does NOT burn the one-shot link. Otherwise a user who fumbled the complexity
// rules would have to go back to an administrator for another one.
func TestRedemptionAppliesPolicyWithoutConsumingTheToken(t *testing.T) {
	f := newCTFixture(t, true)
	tok := f.issuedToken(t, "target")

	weak := f.redeem(t, tok, "short")
	if weak.Code != http.StatusBadRequest {
		t.Fatalf("weak password = %d, want 400 (body %s)", weak.Code, weak.Body.String())
	}
	var body struct {
		Reasons []string `json:"reasons"`
	}
	if err := json.Unmarshal(weak.Body.Bytes(), &body); err != nil || len(body.Reasons) == 0 {
		t.Fatalf("policy failure carried no reasons (err %v): %s", err, weak.Body.String())
	}
	// An echo of the account's own identity is refused too — the identity used is the TOKEN'S
	// user's, which is the only account the redeemer has named.
	if rec := f.redeem(t, tok, "dana@acme.test-Passw0rd"); rec.Code != http.StatusBadRequest {
		t.Fatalf("identity-echoing password = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	// The link survived both refusals.
	if ok := f.redeem(t, tok, ctNewPw); ok.Code != http.StatusOK {
		t.Fatalf("redeem after policy failures = %d, want 200 — the token was consumed by a "+
			"rejected password (body %s)", ok.Code, ok.Body.String())
	}
}

// The redeem endpoint must not become an oracle. Every failure mode answers with the SAME opaque
// message, so a caller holding a random string cannot learn whether it named a real token.
func TestRedeemFailuresAreIndistinguishable(t *testing.T) {
	f := newCTFixture(t, true)
	consumed := f.issuedToken(t, "target")
	if rec := f.redeem(t, consumed, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("setup redeem = %d: %s", rec.Code, rec.Body.String())
	}
	revoked := f.issuedToken(t, "target")
	if rec := doJSONWith(t, f.handler, "DELETE", "/users/target/password-reset", nil,
		f.adminToken, f.adminCookie, f.adminCSRF); rec.Code != http.StatusOK {
		t.Fatalf("setup revoke = %d", rec.Code)
	}

	for name, tok := range map[string]string{
		"never minted": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"consumed":     consumed,
		"revoked":      revoked,
	} {
		rec := f.redeem(t, tok, "Another-Valid-Passw0rd!")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s token = %d, want 403", name, rec.Code)
		}
		if got := strings.TrimSpace(rec.Body.String()); !strings.Contains(got, ErrCredentialTokenInvalid.Error()) {
			t.Fatalf("%s token body = %s, want the single opaque error %q", name, got, ErrCredentialTokenInvalid.Error())
		}
	}
}

// Minting is gated on CapManageUsers. A technician holds a session and a full set of session-y
// capabilities, and none of them may mint a credential for somebody else.
func TestIssueResetRequiresCapManageUsers(t *testing.T) {
	f := newCTFixture(t, true)
	login := f.login(t, "dana@acme.test", ctTargetPw)
	if login.Code != http.StatusOK {
		t.Fatalf("technician login = %d", login.Code)
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfTok := csrfFrom(t, login)

	rec := doJSONWith(t, f.handler, "POST", "/users/admin/password-reset", nil, csrfTok, cookie, csrfCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician minting a reset = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), string(CapManageUsers)) {
		t.Fatalf("denial body = %s, want it to name %q — a 403 from some other check would look "+
			"identical", rec.Body.String(), CapManageUsers)
	}
	// The DELETE half is gated too; it is a separate route and a separate check.
	del := doJSONWith(t, f.handler, "DELETE", "/users/admin/password-reset", nil, csrfTok, cookie, csrfCookie)
	if del.Code != http.StatusForbidden {
		t.Fatalf("technician revoking = %d, want 403", del.Code)
	}
}

// An id in another tenant is NOT FOUND, not minted for. The lookup is tenant-scoped, so the
// endpoint cannot be aimed across a tenant boundary even by an owner.
func TestIssueResetCannotCrossTenants(t *testing.T) {
	f := newCTFixture(t, true)
	f.users.AddUser(&AuthUser{ID: "outsider", TenantID: "tenant-2", Email: "x@other.test"},
		NewGrant("outsider", "tenant-2", NewMembership(RoleTechnician, AllGroups())))

	rec := f.issue(t, "outsider", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant mint = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	n, err := f.tokens.RevokeForUser(t.Context(), "tenant-2", "outsider")
	if err != nil || n != 0 {
		t.Fatalf("cross-tenant mint left %d token(s) behind (err %v)", n, err)
	}
}

// The TTL a caller may ask for is capped. Without a ceiling, one request mints a takeover link
// that outlives every other credential in the system.
func TestIssueResetRejectsAnUnboundedTTL(t *testing.T) {
	f := newCTFixture(t, true)
	// Declared locally on purpose (see TestExpiredCredentialTokenIsRefused): the premise is
	// "more than the cap", and reading the cap from the constant would make this test agree with
	// any future value of it, including no cap at all.
	const capUnderTest = 24 * time.Hour
	if MaxCredentialTokenTTL != capUnderTest {
		t.Fatalf("MaxCredentialTokenTTL is %v, this test was written against %v", MaxCredentialTokenTTL, capUnderTest)
	}
	over := f.issue(t, "target", map[string]any{"ttl_seconds": int((capUnderTest + time.Hour).Seconds())})
	if over.Code != http.StatusBadRequest {
		t.Fatalf("over-cap ttl = %d, want 400 (body %s)", over.Code, over.Body.String())
	}
	if neg := f.issue(t, "target", map[string]any{"ttl_seconds": -1}); neg.Code != http.StatusBadRequest {
		t.Fatalf("negative ttl = %d, want 400", neg.Code)
	}
	// THE OVERFLOW CASE, which the merely-over-cap value above does NOT reach — mutation testing
	// caught this test passing while the bug it was written for was reintroduced. 1e10 seconds is
	// 1e19 nanoseconds against an int64 ceiling of ~9.22e18, so `time.Duration(n) * time.Second`
	// wraps NEGATIVE; a ceiling compared on the Duration then reads "well under the maximum" and
	// mints a link whose expires_at is in the PAST, behind a 201, having already superseded the
	// user's live one. The check must therefore compare the SECONDS, before the multiplication.
	// A variable, not a constant: `const` makes the multiplication a compile-time expression that
	// Go REFUSES to build ("overflows int64"). The handler's value arrives at runtime from JSON,
	// where the same expression silently wraps instead — which is the whole reason the bug existed.
	overflowSeconds := 10_000_000_000
	if time.Duration(overflowSeconds)*time.Second > 0 {
		t.Fatalf("premise broken: %d seconds no longer overflows time.Duration, so this case "+
			"tests nothing", overflowSeconds)
	}
	over2 := f.issue(t, "target", map[string]any{"ttl_seconds": overflowSeconds})
	if over2.Code != http.StatusBadRequest {
		t.Fatalf("overflowing ttl = %d, want 400 (body %s)", over2.Code, over2.Body.String())
	}
	// And the refusal cost the user nothing: their existing live link is still redeemable, rather
	// than having been superseded by a dead one.
	live := f.issuedToken(t, "target")
	if over3 := f.issue(t, "target", map[string]any{"ttl_seconds": overflowSeconds}); over3.Code != http.StatusBadRequest {
		t.Fatalf("overflowing ttl (second attempt) = %d, want 400", over3.Code)
	}
	if rec := f.redeem(t, live, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("the live link stopped working after a refused mint = %d, want 200 (body %s)",
			rec.Code, rec.Body.String())
	}
	if ok := f.issue(t, "target", map[string]any{"ttl_seconds": 600}); ok.Code != http.StatusCreated {
		t.Fatalf("in-range ttl = %d, want 201 (body %s)", ok.Code, ok.Body.String())
	}
}

// Guessing the 256-bit secret is metered per source. The entropy is the real defence; this is the
// floor under it, and it must not cost anything on a MALFORMED request (which proves nothing about
// whether the caller is guessing).
func TestRedeemIsThrottledPerSource(t *testing.T) {
	f := newCTFixture(t, true)
	f.auth.Throttle = NewThrottle(ThrottleConfig{
		FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Minute, Reset: time.Hour,
	})
	for i := 0; i < 2; i++ {
		if rec := f.redeem(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ctNewPw); rec.Code != http.StatusForbidden {
			t.Fatalf("guess %d = %d, want 403", i+1, rec.Code)
		}
	}
	rec := f.redeem(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ctNewPw)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("guess 3 = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("throttled redemption carries no Retry-After")
	}
	// A missing token is a malformed request, not a guess: it is answered 400 and costs no budget.
	if bad := f.redeem(t, "", ctNewPw); bad.Code != http.StatusBadRequest {
		t.Fatalf("empty token = %d, want 400", bad.Code)
	}

	// THE POINT OF THE ORDERING: the lockout above is in force, and a GENUINE link still redeems.
	// Metering before the lookup — the obvious order, and how this was first written — would answer
	// 429 here, which behind the reverse proxy docs/10 documents (where clientIP is the proxy for
	// every caller) means one attacker's garbage denies account recovery to the whole deployment.
	tok := f.issuedToken(t, "target")
	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("valid link redeemed from a throttled source = %d, want 200 — a lockout must "+
			"never refuse a real link (body %s)", rec.Code, rec.Body.String())
	}
	// …and the source is still locked out for further GUESSING, so the floor is intact.
	if rec := f.redeem(t, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", ctNewPw); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-success guess = %d, want 429 — redeeming a valid token must not clear the "+
			"budget, or any link-holder could guess unmetered forever", rec.Code)
	}
}

// The redemption is audited against the USER whose credential changed, with the session count.
func TestRedemptionIsAudited(t *testing.T) {
	f := newCTFixture(t, true)
	if rec := f.login(t, "dana@acme.test", ctTargetPw); rec.Code != http.StatusOK {
		t.Fatalf("target login = %d", rec.Code)
	}
	tok := f.issuedToken(t, "target")
	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d: %s", rec.Code, rec.Body.String())
	}
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var redeemed *MgmtAuditEvent
	for i := range events {
		if events[i].Action == "auth.password_reset_redeemed" {
			redeemed = &events[i]
		}
	}
	if redeemed == nil {
		t.Fatalf("no auth.password_reset_redeemed in %v", f.auditActions(t))
	}
	if redeemed.TargetID != "target" {
		t.Fatalf("redeemed event target = %q, want target", redeemed.TargetID)
	}
	// The ACTOR must be EMPTY. Whoever presented the link proved possession of a secret, not an
	// identity; naming the account owner would make a stolen-link redemption indistinguishable in
	// the trail from the owner's own.
	if redeemed.ActorUserID != "" {
		t.Fatalf("redeemed event actor = %q, want empty (the redeemer is unauthenticated)",
			redeemed.ActorUserID)
	}
	var meta map[string]any
	if err := json.Unmarshal(redeemed.Metadata, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if n, ok := meta["sessions_revoked"].(float64); !ok || n < 1 {
		t.Fatalf("sessions_revoked = %v, want at least 1 (the login above)", meta["sessions_revoked"])
	}
	// issued_by is what still joins the two halves of the trail now that the actor is empty.
	if meta["issued_by"] != "admin" {
		t.Fatalf("issued_by = %v, want admin", meta["issued_by"])
	}
}

// first_provision must be able to be FALSE. Asserted only in the true direction (which is what the
// provisioning test does), a hardcoded `true` would pass — and every administrative reset of a LIVE
// credential would then be filed in the trail as routine first-time provisioning.
func TestFirstProvisionIsFalseWhenReplacingALiveCredential(t *testing.T) {
	f := newCTFixture(t, true) // the target HAS a password
	rec := f.issue(t, "target", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		FirstProvision bool `json:"first_provision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.FirstProvision {
		t.Fatal("first_provision is true for an account that already had a credential")
	}
	events, err := f.audit.ListEvents(t.Context(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for i := range events {
		if events[i].Action != "auth.password_reset_issued" {
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal(events[i].Metadata, &meta); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
		if meta["first_provision"] != false {
			t.Fatalf("audited first_provision = %v, want false", meta["first_provision"])
		}
		return
	}
	t.Fatalf("no auth.password_reset_issued in %v", f.auditActions(t))
}

// Disabling an account kills its outstanding links. Otherwise "disable this user" would leave a
// working back door into the account it was supposed to close.
func TestDisabledUserCannotRedeem(t *testing.T) {
	f := newCTFixture(t, true)
	tok := f.issuedToken(t, "target")

	u, err := f.users.FindUserByID(t.Context(), "tenant-1", "target")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	u.Disabled = true
	f.users.AddUser(u, NewGrant("target", "tenant-1", NewMembership(RoleTechnician, AllGroups())))

	if rec := f.redeem(t, tok, ctNewPw); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem for a disabled user = %d, want 403", rec.Code)
	}
	// And minting for one is refused up front rather than producing a dead link.
	if rec := f.issue(t, "target", nil); rec.Code != http.StatusConflict {
		t.Fatalf("mint for a disabled user = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

// The routes do not exist at all when no token store is wired: an unconfigured deployment has no
// reset path rather than one that 500s.
func TestCredentialTokenRoutesAbsentWithoutAStore(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", ctAdminPw, RoleAdmin)
	h := f.srv.Handler()
	login := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "admin@acme.test", Password: ctAdminPw}, nil)
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfTok := csrfFrom(t, login)

	// 404, not 500: the protected mux never learned the pattern.
	if rec := doJSONWith(t, h, "POST", "/users/admin/password-reset", nil, csrfTok, cookie, csrfCookie); rec.Code != http.StatusNotFound {
		t.Fatalf("mint without a store = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// The redeem path is different, and the difference is a property of the router rather than of
	// this feature: unmatched paths fall through the root mux's "/" catch-all into the PROTECTED
	// chain, so an unmounted public route is answered 401 by the authenticator, not 404. That is
	// still "no handler ran" — the assertion below is what makes it mean that, by showing the same
	// unauthenticated request reaches the handler (403 invalid token) once a store IS wired.
	redeemBody := map[string]string{"token": "x", "new_password": ctNewPw}
	if rec := doJSON(t, h, "POST", "/auth/password/redeem", redeemBody, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("redeem without a store = %d, want 401 (unmounted → caught by the auth chain), body %s",
			rec.Code, rec.Body.String())
	}
	f.auth.CredentialTokens = NewInMemoryCredentialTokenStore()
	if rec := doJSON(t, f.srv.Handler(), "POST", "/auth/password/redeem", redeemBody, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem WITH a store = %d, want 403 — if this is also 401 the test above proves "+
			"nothing about the route being absent (body %s)", rec.Code, rec.Body.String())
	}
}
