package controlplane

// Pass 12: real authenticated control-plane handler integration tests.
//
// What pass 11 was not: its seven tests used StubAuthenticator{Principal: p}, which
// bypasses the real session cookie, CSRF derivation, and credential-epoch checks.
// That is signing smoke, not auth proof. These tests drive the FULL production chain:
//
//   POST /auth/login  →  session cookie + CSRF cookie
//   protected route   →  csrfMiddleware → authMiddleware (SessionAuthenticator)
//                        → tenantMiddleware → handler
//
// Proofs in this file:
//   1. Two technicians in the same tenant + group (A=Alice, B=Bob) may each mint a
//      session on the same machine through the full login→cookie→capability chain.
//   2. A credential from a foreign tenant (C=Carol, tenant-beta) is refused with 404
//      on a tenant-alpha machine — not 403, so the machine's existence is not revealed.
//   3. A credential scoped to one group is refused with 403 on a machine in a
//      different group, resolved from the STORED record, not from caller-supplied data.
//   4. An administrator ending A's session stops A's next lease renewal (409) while
//      B's independent session on the same machine keeps renewing (200).
//   5. A calling POST /auth/logout revokes A's own auth (subsequent protected request
//      → 401) while B's independent session survives unchanged (200).
//   6. Every audit event carries the correct ActorUserID for its action.
//
// In-memory stores throughout. No Postgres, no RLS, no agent binary, no browser.
// PG/RLS, browser, and agent-transport gates remain explicitly pending.
// No claim is made that this replaces real transport tests; an independent fresh
// functional review is required before any security statement about the full stack.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// ─── personas and tenant constants ────────────────────────────────────────────

const (
	p12TenantAlpha = "tenant-alpha"
	p12TenantBeta  = "tenant-beta"
	p12GroupEast   = "group-east"  // Alice + Bob's scope; M1 lives here
	p12GroupWest   = "group-west"  // out-of-scope for Alice/Bob; M2 lives here (alpha)

	p12AliceID    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	p12BobID      = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	p12AdminAlpha = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	p12CarolID    = "dddddddd-dddd-dddd-dddd-dddddddddddd"

	p12AliceEmail = "alice@alpha.test"
	p12BobEmail   = "bob@alpha.test"
	p12AdminEmail = "admin@alpha.test"
	p12CarolEmail = "carol@beta.test"

	p12AlicePw = "alice-correct-horse-battery-staple"
	p12BobPw   = "bob-correct-horse-battery-staple"
	p12AdminPw = "admin-correct-horse-battery-staple"
	p12CarolPw = "carol-correct-horse-battery-staple"
)

// ─── fixture ──────────────────────────────────────────────────────────────────

type pass12Fixture struct {
	*authFixture
	machines *InMemoryMachineStore
	audit    *InMemoryMgmtAuditStore
	issuer   *GrantIssuer
	m1       *Machine // tenant-alpha / group-east  — Alice and Bob may start here
	m2       *Machine // tenant-alpha / group-west  — Alice and Bob are out-of-scope
	mc       *Machine // tenant-beta  / group-west  — Carol's; alpha users see 404
}

func newPass12Fixture(t *testing.T) *pass12Fixture {
	t.Helper()
	f := newAuthFixture(t)
	// Throttle gating is not the subject of this pass; disable it so repeated logins
	// in a single test do not accidentally trip the rate limiter.
	f.auth.DisableThrottle = true

	// Shared audit store: both the auth surface and the handler surface write here,
	// so every event (auth.login, session.start, session.end, auth.logout) is visible
	// in a single ListEvents call.
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = audit
	f.auth.MgmtAudit = audit

	// Strict (non-permissive) machine store: GetMachine for an unknown device ID
	// returns ErrMachineNotFound rather than synthesising a dev record. This is
	// necessary so the cross-tenant 404 test reflects a real refusal, not a fallback.
	machines := NewInMemoryMachineStore()
	f.srv.Machines = machines
	f.srv.SessionRecords = NewInMemorySessionRecordStore()

	// Grant issuer: required for POST /sessions/{id}/policy (lease renewal).
	// Device IDs are newUUID() — the canonical preimage parser requires real UUIDs.
	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("pass12: generate issuer: %v", err)
	}
	f.srv.Grants = iss

	// A = Alice: technician scoped to group-east within tenant-alpha.
	f.addUserWithGrant(t, p12TenantAlpha, p12AliceID, p12AliceEmail, p12AlicePw,
		NewGrant(p12AliceID, p12TenantAlpha,
			NewMembership(RoleTechnician, Groups(p12GroupEast))))

	// B = Bob: same tenant, same group scope, different identity.
	f.addUserWithGrant(t, p12TenantAlpha, p12BobID, p12BobEmail, p12BobPw,
		NewGrant(p12BobID, p12TenantAlpha,
			NewMembership(RoleTechnician, Groups(p12GroupEast))))

	// Admin: tenant-alpha, all groups — may end sessions and sign users out.
	f.addUser(t, p12TenantAlpha, p12AdminAlpha, p12AdminEmail, p12AdminPw, RoleAdmin)

	// C = Carol: technician in tenant-beta — a distinct tenant, different credential epoch.
	f.addUserWithGrant(t, p12TenantBeta, p12CarolID, p12CarolEmail, p12CarolPw,
		NewGrant(p12CarolID, p12TenantBeta,
			NewMembership(RoleTechnician, Groups(p12GroupWest))))

	// M1: the machine Alice and Bob are permitted to use.
	m1 := &Machine{DeviceID: newUUID(), GroupID: p12GroupEast, Name: "alpha-east-host"}
	if err := machines.EnrollMachine(context.Background(), p12TenantAlpha, m1); err != nil {
		t.Fatalf("enroll m1: %v", err)
	}

	// M2: same tenant as Alice/Bob but a different group — they lack the capability.
	m2 := &Machine{DeviceID: newUUID(), GroupID: p12GroupWest, Name: "alpha-west-host"}
	if err := machines.EnrollMachine(context.Background(), p12TenantAlpha, m2); err != nil {
		t.Fatalf("enroll m2: %v", err)
	}

	// MC: Carol's machine in tenant-beta — invisible to Alice/Bob as 404.
	mc := &Machine{DeviceID: newUUID(), GroupID: p12GroupWest, Name: "beta-west-host"}
	if err := machines.EnrollMachine(context.Background(), p12TenantBeta, mc); err != nil {
		t.Fatalf("enroll mc: %v", err)
	}

	return &pass12Fixture{
		authFixture: f,
		machines:    machines,
		audit:       audit,
		issuer:      iss,
		m1:          m1,
		m2:          m2,
		mc:          mc,
	}
}

// loginAs drives the full production login chain (real HashPassword+argon2 verify,
// session issue, cookie+CSRF derivation) for the named tenant/credential pair.
// Returns (sessionCookie, csrfCookie, csrfToken); fatals on non-200.
func (f *pass12Fixture) loginAs(t *testing.T, tenant, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: tenant, Email: email, Password: password}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s/%s = %d: %s", tenant, email, rec.Code, rec.Body.String())
	}
	sess := sessionCookieFrom(rec)
	csrfCookie, csrfTok := csrfFrom(t, rec)
	return sess, csrfCookie, csrfTok
}

// startSession calls POST /sessions with the caller's cookies and the given device
// ID. Returns the SessionRecord on 201; fatals otherwise.
func (f *pass12Fixture) startSession(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, deviceID string) *SessionRecord {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions",
		startSessionRequest{MachineID: deviceID}, csrfTok, sess, csrfCookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start session device=%s = %d: %s", deviceID, rec.Code, rec.Body.String())
	}
	var body struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode start-session body: %v (%s)", err, rec.Body.String())
	}
	return &body.Session
}

// endSession calls POST /sessions/{id}/end with the caller's cookies.
// Returns the HTTP status code.
func (f *pass12Fixture) endSession(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, sessionID string) int {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions/"+sessionID+"/end",
		nil, csrfTok, sess, csrfCookie)
	return rec.Code
}

// renewLease calls POST /sessions/{id}/policy with the caller's cookies.
// Returns the HTTP status code.
func (f *pass12Fixture) renewLease(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, sessionID string) int {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions/"+sessionID+"/policy",
		nil, csrfTok, sess, csrfCookie)
	return rec.Code
}

// logout calls POST /auth/logout with the caller's cookies. Fatals on non-2xx.
func (f *pass12Fixture) logout(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok string) {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/auth/logout",
		nil, csrfTok, sess, csrfCookie)
	if rec.Code < 200 || rec.Code >= 300 {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
}

// listSessions calls GET /sessions with the caller's session cookie (no CSRF needed
// — GET is CSRF-exempt). Returns the HTTP status code.
func (f *pass12Fixture) listSessions(t *testing.T, sess *http.Cookie) int {
	t.Helper()
	rec := doJSON(t, f.srv.Handler(), "GET", "/sessions", nil, sess)
	return rec.Code
}

// auditEventsFor returns all audit events for tenantID, newest first.
func (f *pass12Fixture) auditEventsFor(t *testing.T, tenantID string) []MgmtAuditEvent {
	t.Helper()
	events, err := f.audit.ListEvents(context.Background(), tenantID, 200)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

// firstEventWith returns the first (newest) audit event whose action and actor match,
// or fatals if none is found. This asserts both that the event was recorded and that
// the actor principal is correct — the audit-principal claim this pass exists to prove.
func firstEventWith(t *testing.T, events []MgmtAuditEvent, action, actorUserID string) MgmtAuditEvent {
	t.Helper()
	for _, e := range events {
		if e.Action == action && e.ActorUserID == actorUserID {
			return e
		}
	}
	t.Fatalf("no audit event with action=%q actor=%q in %d events", action, actorUserID, len(events))
	panic("unreachable")
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestPass12_SameGroupConcurrentSessions proves that two technicians sharing the
// same group scope in the same tenant may each independently mint a session on the
// same machine through the full authenticated handler chain. The concurrent-session
// cap defaults to 0 (unlimited) so both 201s are expected without conflict.
func TestPass12_SameGroupConcurrentSessions(t *testing.T) {
	f := newPass12Fixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p12TenantAlpha, p12AliceEmail, p12AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p12TenantAlpha, p12BobEmail, p12BobPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1.DeviceID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1.DeviceID)

	// Each session belongs to its technician and the shared machine.
	if sessionA.TechnicianID != p12AliceID {
		t.Fatalf("sessionA.TechnicianID = %q, want Alice %q", sessionA.TechnicianID, p12AliceID)
	}
	if sessionB.TechnicianID != p12BobID {
		t.Fatalf("sessionB.TechnicianID = %q, want Bob %q", sessionB.TechnicianID, p12BobID)
	}
	if sessionA.TenantID != p12TenantAlpha {
		t.Fatalf("sessionA.TenantID = %q, want %q", sessionA.TenantID, p12TenantAlpha)
	}
	if sessionA.MachineGroupID != p12GroupEast {
		t.Fatalf("sessionA.MachineGroupID = %q, want %q", sessionA.MachineGroupID, p12GroupEast)
	}
	// Sessions are distinct rows.
	if sessionA.ID == sessionB.ID {
		t.Fatalf("sessionA and sessionB share the same session ID %q — must be independent rows",
			sessionA.ID)
	}
	// Both sessions are open (no EndedAt).
	if sessionA.EndedAt != nil {
		t.Fatalf("sessionA already has EndedAt set — must be open after start")
	}
	if sessionB.EndedAt != nil {
		t.Fatalf("sessionB already has EndedAt set — must be open after start")
	}
}

// TestPass12_CrossTenantRejection proves that a credential issued for tenant-beta
// cannot start a session on a tenant-alpha machine. The machine is not visible across
// the tenant boundary — GetMachine scopes the lookup to the principal's own tenant —
// so the response is 404, not 403. Returning 403 would leak the machine's existence.
func TestPass12_CrossTenantRejection(t *testing.T) {
	f := newPass12Fixture(t)

	// Carol belongs to tenant-beta. She supplies M1's device ID, which is enrolled
	// under tenant-alpha. The handler calls GetMachine(ctx, "tenant-beta", m1.DeviceID)
	// → ErrMachineNotFound, because the store is keyed by (tenantID, deviceID) and
	// that combination does not exist.
	carolSess, carolCSRFCookie, carolCSRFTok := f.loginAs(t, p12TenantBeta, p12CarolEmail, p12CarolPw)

	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions",
		startSessionRequest{MachineID: f.m1.DeviceID},
		carolCSRFTok, carolSess, carolCSRFCookie)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant start session = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	// DESIGN NOTE: 404 rather than 403 is load-bearing. 403 would reveal that the
	// machine exists in some tenant, which is information Carol must not have. The
	// handler's GetMachine path returns ErrMachineNotFound and writes 404 without any
	// capability check — capability is gated AFTER machine resolution, so the refusal
	// is indistinguishable from a legitimately absent machine.
}

// TestPass12_OutOfScopeGroupRejection proves that a technician scoped to group-east
// is refused with 403 when targeting a machine in group-west of the same tenant.
// The group comes from the STORED machine record, not from anything the caller
// supplies — so the caller cannot widen their own scope by naming a different group
// in the request body.
func TestPass12_OutOfScopeGroupRejection(t *testing.T) {
	f := newPass12Fixture(t)

	// Alice is scoped to group-east only. M2 lives in group-west (same tenant).
	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p12TenantAlpha, p12AliceEmail, p12AlicePw)

	rec := doJSONWith(t, f.srv.Handler(), "POST", "/sessions",
		startSessionRequest{MachineID: f.m2.DeviceID},
		aliceCSRFTok, aliceSess, aliceCSRFCookie)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope group start session = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	// The same technician CAN start a session on a group-east machine. This confirms
	// the 403 above is specifically the group-scope gate, not a blanket denial — the
	// technician is NOT globally refused, only out-of-scope machines are refused.
	rec2 := doJSONWith(t, f.srv.Handler(), "POST", "/sessions",
		startSessionRequest{MachineID: f.m1.DeviceID},
		aliceCSRFTok, aliceSess, aliceCSRFCookie)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("in-scope group start session = %d, want 201 (negative control): %s",
			rec2.Code, rec2.Body.String())
	}
}

// TestPass12_AdminEndsSessionWhileOtherRenews proves the F03 fix under multi-principal
// load: an administrator ending A's session stops A's next lease renewal (409), while
// B's independent session on the same machine is unaffected and keeps renewing (200).
//
// This drives both the end and renew routes through the full authenticated chain,
// NOT by poking EndedAt into the store directly. The admin end is a second authenticated
// request from a distinct session — exactly how a real incident-response action arrives.
func TestPass12_AdminEndsSessionWhileOtherRenews(t *testing.T) {
	f := newPass12Fixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p12TenantAlpha, p12AliceEmail, p12AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p12TenantAlpha, p12BobEmail, p12BobPw)
	adminSess, adminCSRFCookie, adminCSRFTok := f.loginAs(t, p12TenantAlpha, p12AdminEmail, p12AdminPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1.DeviceID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1.DeviceID)

	// Both technicians must be able to renew before anything is ended — confirms
	// the fixture is wired correctly and isolates the effect of the end call below.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("Alice renew before end = %d, want 200", got)
	}
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew before end = %d, want 200", got)
	}

	// Administrator ends Alice's session through the production handler chain.
	if got := f.endSession(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("admin end Alice's session = %d, want 200", got)
	}

	// THE FINDING (F03): Alice's renewal is now refused — the ABSENCE of a fresh lease
	// is what actually terminates the remote session, since there is no push channel to
	// the agent. 409 Conflict means "session has ended", not "unknown session".
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusConflict {
		t.Fatalf("Alice renew after admin end = %d, want 409 (session ended)", got)
	}
	// And it stays refused — no race window where a retry might succeed.
	if got := f.renewLease(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, sessionA.ID); got != http.StatusConflict {
		t.Fatalf("Alice second renew after end = %d, want 409", got)
	}

	// Bob's session is entirely independent and must continue to renew without
	// disruption. An admin ending another technician's session must not affect this one.
	if got := f.renewLease(t, bobSess, bobCSRFCookie, bobCSRFTok, sessionB.ID); got != http.StatusOK {
		t.Fatalf("Bob renew after Alice's end = %d, want 200: Bob's session is independent", got)
	}
}

// TestPass12_LogoutRevokesAuthWhileOtherSurvives proves that POST /auth/logout through
// the full CSRF → session-cookie chain revokes exactly the caller's own session while
// leaving an independent second session completely intact. This is the per-session
// revocation contract: logout is not a tenant-wide or user-wide eviction.
func TestPass12_LogoutRevokesAuthWhileOtherSurvives(t *testing.T) {
	f := newPass12Fixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p12TenantAlpha, p12AliceEmail, p12AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p12TenantAlpha, p12BobEmail, p12BobPw)

	// Both are authenticated before the logout — a 200 on GET /sessions confirms the
	// session cookie is live. (GET is CSRF-exempt; technicians hold CapViewSessions.)
	if got := f.listSessions(t, aliceSess); got != http.StatusOK {
		t.Fatalf("Alice session before logout = %d, want 200", got)
	}
	if got := f.listSessions(t, bobSess); got != http.StatusOK {
		t.Fatalf("Bob session before logout = %d, want 200", got)
	}

	// Alice logs out through the production handler. POST /auth/logout is wrapped by
	// csrfMiddleware (line 495, http.go) so the full CSRF check runs here — this is
	// not a no-op POST.
	f.logout(t, aliceSess, aliceCSRFCookie, aliceCSRFTok)

	// Alice's session cookie is now stale: SessionAuthenticator.Validate fails →
	// authMiddleware returns 401. The cookie value has not changed — the token was
	// revoked in the session store, not merely cleared from the browser.
	if got := f.listSessions(t, aliceSess); got != http.StatusUnauthorized {
		t.Fatalf("Alice session after logout = %d, want 401", got)
	}

	// Bob never logged out and his session is independent. His cookie must still work.
	if got := f.listSessions(t, bobSess); got != http.StatusOK {
		t.Fatalf("Bob session after Alice's logout = %d, want 200: independent session must survive",
			got)
	}
	// Bob can still use CSRF-protected routes (demonstrates his credential epoch is intact).
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1.DeviceID)
	if sessionB.TechnicianID != p12BobID {
		t.Fatalf("post-logout Bob session technician = %q, want %q", sessionB.TechnicianID, p12BobID)
	}
}

// TestPass12_AuditPrincipals proves that every management audit event carries the
// correct ActorUserID for the principal who performed the action. This is the audit
// chain's identity claim — an audit trail that attributes events to the wrong actor
// is actively misleading in an incident investigation.
//
// Actions checked:
//   - session.start:  actor is the technician who opened the session (Alice, then Bob)
//   - session.end:    actor is the administrator who called /sessions/{id}/end (not Alice)
//   - auth.logout:    actor is the user who called /auth/logout (Alice)
func TestPass12_AuditPrincipals(t *testing.T) {
	f := newPass12Fixture(t)

	aliceSess, aliceCSRFCookie, aliceCSRFTok := f.loginAs(t, p12TenantAlpha, p12AliceEmail, p12AlicePw)
	bobSess, bobCSRFCookie, bobCSRFTok := f.loginAs(t, p12TenantAlpha, p12BobEmail, p12BobPw)
	adminSess, adminCSRFCookie, adminCSRFTok := f.loginAs(t, p12TenantAlpha, p12AdminEmail, p12AdminPw)

	sessionA := f.startSession(t, aliceSess, aliceCSRFCookie, aliceCSRFTok, f.m1.DeviceID)
	sessionB := f.startSession(t, bobSess, bobCSRFCookie, bobCSRFTok, f.m1.DeviceID)

	// Admin ends Alice's session — NOT Alice.
	if got := f.endSession(t, adminSess, adminCSRFCookie, adminCSRFTok, sessionA.ID); got != http.StatusOK {
		t.Fatalf("admin end = %d", got)
	}

	// Alice logs out.
	f.logout(t, aliceSess, aliceCSRFCookie, aliceCSRFTok)

	events := f.auditEventsFor(t, p12TenantAlpha)

	// ── session.start by Alice ────────────────────────────────────────────────
	evA := firstEventWith(t, events, "session.start", p12AliceID)
	if evA.TargetKind != "session" {
		t.Fatalf("session.start(Alice) TargetKind = %q, want %q", evA.TargetKind, "session")
	}
	if evA.TargetID != sessionA.ID {
		t.Fatalf("session.start(Alice) TargetID = %q, want sessionA.ID %q", evA.TargetID, sessionA.ID)
	}

	// ── session.start by Bob ──────────────────────────────────────────────────
	evB := firstEventWith(t, events, "session.start", p12BobID)
	if evB.TargetID != sessionB.ID {
		t.Fatalf("session.start(Bob) TargetID = %q, want sessionB.ID %q", evB.TargetID, sessionB.ID)
	}

	// ── session.end by Admin (NOT by Alice) ───────────────────────────────────
	// The critical assertion: the actor on session.end is the administrator who issued
	// the end command, not the session's technician. A trail that said Alice ended her
	// own session would obscure an admin's incident-response action.
	evEnd := firstEventWith(t, events, "session.end", p12AdminAlpha)
	if evEnd.TargetID != sessionA.ID {
		t.Fatalf("session.end actor=admin TargetID = %q, want sessionA.ID %q",
			evEnd.TargetID, sessionA.ID)
	}
	// Negative: there must be no session.end event attributed to Alice.
	for _, e := range events {
		if e.Action == "session.end" && e.ActorUserID == p12AliceID {
			t.Fatalf("session.end event attributed to Alice (actor=%q) — must be the admin who issued the end", e.ActorUserID)
		}
	}

	// ── auth.logout by Alice ──────────────────────────────────────────────────
	evLogout := firstEventWith(t, events, "auth.logout", p12AliceID)
	if evLogout.TenantID != p12TenantAlpha {
		t.Fatalf("auth.logout TenantID = %q, want %q", evLogout.TenantID, p12TenantAlpha)
	}
}
