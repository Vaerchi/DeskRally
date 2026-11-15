package controlplane

// Proofs for POST /sessions/{id}/policy — the session-LEASE renewal that makes a central
// "End session" actually terminate unattended remote access (docs/25 F03).
//
// The finding's own regression is the shape these tests take: "Keep a custom controller connected,
// end it from a second administrator, and verify video/input/commands cease within a specified bound
// without controller cooperation. Repeat for user disable, tenant suspension, and machine
// quarantine." The half of that which lives in Go is the refusal to RE-AUTHORIZE; the half that
// lives in the agent (a session tearing itself down when its lease lapses) is in
// `crates/agent-windows/tests/e2e_session_lease.rs` and `rmt_agent::session_policy`'s unit tests.
//
// These run through the REAL authenticator (SessionAuthenticator over the in-memory user store) and
// the REAL handler chain, deliberately: user disable and tenant suspension are enforced by the auth
// middleware rather than by this handler, so a test that called the handler directly would prove
// nothing about either — it would only prove that the code I wrote does what I wrote.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

const (
	leaseTenant  = "tenant-1"
	leasePw      = "correct-horse-battery-staple"
	leaseTechID  = "11111111-1111-1111-1111-111111111111"
	leaseAdminID = "22222222-2222-2222-2222-222222222222"
	leaseGroup   = "group-a"
)

// leaseFixture is an authFixture with everything a renewal needs: a wired issuer, a session-record
// store, a machine store holding one real (uuid-identified) machine, and one OPEN session on it
// owned by the technician.
type leaseFixture struct {
	*authFixture
	machines *InMemoryMachineStore
	groups   *InMemoryGroupSessionPolicyStore
	rec      *SessionRecord
	machine  *Machine
	issuer   *GrantIssuer
}

func newLeaseFixture(t *testing.T) *leaseFixture {
	t.Helper()
	f := newAuthFixture(t)
	// The permissive machine store newAuthFixture installs would answer GetMachine for ANY device
	// id, which would hide a store lookup that should have failed. A real store with one real row.
	machines := NewInMemoryMachineStore()
	f.srv.Machines = machines
	f.srv.SessionRecords = NewInMemorySessionRecordStore()
	f.srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	groups := NewInMemoryGroupSessionPolicyStore()
	f.srv.GroupSessionPolicies = groups
	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	f.srv.Grants = iss

	f.addUser(t, leaseTenant, leaseTechID, "tech@acme.test", leasePw, RoleTechnician)
	f.addUser(t, leaseTenant, leaseAdminID, "admin@acme.test", leasePw, RoleAdmin)

	// The device id must be a REAL uuid: the canonical preimage parses it to 16 raw bytes, so a
	// synthetic "m1" would turn every 200 below into a 400 for the wrong reason.
	m := &Machine{DeviceID: newUUID(), GroupID: leaseGroup, Name: "HOST"}
	if err := machines.EnrollMachine(context.Background(), leaseTenant, m); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	rec := f.seedSession(t, leaseTechID)
	return &leaseFixture{authFixture: f, machines: machines, groups: groups, rec: rec, machine: m, issuer: iss}
}

// seedSession opens a session record on the fixture's machine for `technicianID`.
func (f *authFixture) seedSession(t *testing.T, technicianID string) *SessionRecord {
	t.Helper()
	ms, err := f.srv.Machines.ListMachines(context.Background(), leaseTenant)
	if err != nil || len(ms) != 1 {
		t.Fatalf("expected exactly one seeded machine: %v %v", ms, err)
	}
	rec := &SessionRecord{
		MachineID:       ms[0].ID,
		TechnicianID:    technicianID,
		MachineGroupID:  ms[0].GroupID,
		MachineDeviceID: ms[0].DeviceID,
		MachineName:     ms[0].Name,
	}
	if err := f.srv.SessionRecords.StartSession(context.Background(), leaseTenant, rec); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return rec
}

type leaseRenewal struct {
	code    int
	body    string
	decoded struct {
		SessionPolicy struct {
			Access      string `json:"access"`
			Signed      string `json:"signed"`
			LeaseTTLMs  int64  `json:"lease_ttl_ms"`
			ExpiresAtMs int64  `json:"expires_at_ms"`
		} `json:"session_policy"`
	}
}

// renewAs logs `email` in and renews the fixture's session.
func (f *leaseFixture) renewAs(t *testing.T, email string) *leaseRenewal {
	t.Helper()
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, email, leasePw)
	return f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok)
}

// renewWith renews using credentials the caller already holds — so a test can prove that disabling a
// user or suspending a tenant evicts an ALREADY-ESTABLISHED session rather than merely blocking the
// next login, which is the only thing that matters to a technician who is already connected.
func (f *leaseFixture) renewWith(t *testing.T, sessionID string, sess, csrfCookie *http.Cookie, csrfTok string) *leaseRenewal {
	t.Helper()
	rr := doJSONWith(t, f.srv.Handler(), "POST", "/sessions/"+sessionID+"/policy", nil, csrfTok, sess, csrfCookie)
	out := &leaseRenewal{code: rr.Code, body: rr.Body.String()}
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &out.decoded); err != nil {
			t.Fatalf("decode renewal: %v (%s)", err, out.body)
		}
	}
	return out
}

// THE HAPPY PATH, and everything it has to be true of: a signature the agent's pinned issuer key
// verifies, bound to THIS session and THIS device, and a lease short enough to be a revocation
// window rather than a formality.
func TestRenewSessionLease(t *testing.T) {
	f := newLeaseFixture(t)
	got := f.renewAs(t, "tech@acme.test")
	if got.code != http.StatusOK {
		t.Fatalf("renew = %d, want 200: %s", got.code, got.body)
	}
	sp := got.decoded.SessionPolicy
	if sp.Access != string(SessionAccessControl) {
		t.Fatalf("access = %q, want control (the group enforces nothing)", sp.Access)
	}
	if sp.LeaseTTLMs != sessionPolicyLeaseTTL.Milliseconds() {
		t.Fatalf("lease_ttl_ms = %d, want %d", sp.LeaseTTLMs, sessionPolicyLeaseTTL.Milliseconds())
	}
	// The TTL is the revocation window, so it gets an assertion and not only a comment. Bounded on
	// BOTH sides: a one-sided "<= a minute" check would pass a zero-length lease, which would end
	// every session instantly, and a one-sided ">= a second" check would pass fifteen minutes, which
	// is the bug this whole change exists to remove.
	if sessionPolicyLeaseTTL.Seconds() < 5 || sessionPolicyLeaseTTL.Seconds() > 60 {
		t.Fatalf("sessionPolicyLeaseTTL = %v: a lease must be short enough to be a revocation window "+
			"and long enough to survive a WebRTC connect", sessionPolicyLeaseTTL)
	}
	// The signature must verify against the issuer public key an agent pins, over the canonical
	// preimage — not merely be 128 hex characters.
	assertLeaseVerifies(t, f, sp.Signed, SessionAccessControl)
}

// assertLeaseVerifies re-derives the canonical preimage from the returned claims and checks the
// Ed25519 signature with the issuer's PUBLIC key, exactly as the agent does. Also checks the two
// bindings that stop a captured lease being replayed: the session and the device.
func assertLeaseVerifies(t *testing.T, f *leaseFixture, signedJSON string, wantAccess SessionAccessLevel) {
	t.Helper()
	var sp SignedSessionPolicy
	if err := json.Unmarshal([]byte(signedJSON), &sp); err != nil {
		t.Fatalf("signed policy is not JSON: %v", err)
	}
	if sp.Claims.Policy.SessionID != f.rec.ID {
		t.Fatalf("lease session_id = %q, want %q", sp.Claims.Policy.SessionID, f.rec.ID)
	}
	if sp.Claims.Policy.MachineID != f.machine.DeviceID {
		t.Fatalf("lease machine_id = %q, want the DEVICE id %q", sp.Claims.Policy.MachineID, f.machine.DeviceID)
	}
	if sp.Claims.Policy.TechnicianID != leaseTechID {
		t.Fatalf("lease technician_id = %q, want %q", sp.Claims.Policy.TechnicianID, leaseTechID)
	}
	if sp.Claims.Policy.Access != wantAccess {
		t.Fatalf("lease access = %q, want %q", sp.Claims.Policy.Access, wantAccess)
	}
	msg, err := sessionPolicySigningBytes(sp.Claims.Policy.TechnicianID, sp.Claims.Policy.SessionID,
		sp.Claims.Policy.MachineID, sp.Claims.Policy.Access, sp.Claims.Policy.AllowRecording,
		sp.Claims.Policy.RequireRecording, sp.Claims.Policy.MaxSessionDurationSeconds, sp.Claims.Policy.MaxIdleSeconds, sp.Claims.IssuedAtMs, sp.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	pub, err := hex.DecodeString(f.issuer.PublicKeyHex())
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	sig, err := hex.DecodeString(sp.Sig)
	if err != nil {
		t.Fatalf("sig is not hex: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("the minted lease does not verify against the issuer public key an agent pins")
	}
	if sp.Claims.ExpiresAtMs <= sp.Claims.IssuedAtMs {
		t.Fatalf("lease window is empty: issued %d expires %d", sp.Claims.IssuedAtMs, sp.Claims.ExpiresAtMs)
	}
}

// **THE FINDING.** A second administrator ends the session; the technician's next renewal is
// refused. That refusal is the entire mechanism by which "End session" reaches an unattended
// desktop — the agent holds its last lease for at most sessionPolicyLeaseTTL and then tears the
// session down itself, with no cooperation from the controller at any point.
//
// Driven through the REAL end route as a SECOND administrator, exactly as the finding's regression
// describes, rather than by poking `EndedAt` into the store.
func TestRenewIsRefusedAfterAnAdministratorEndsTheSession(t *testing.T) {
	f := newLeaseFixture(t)
	if got := f.renewAs(t, "tech@acme.test"); got.code != http.StatusOK {
		t.Fatalf("renewal must work before the session is ended: %d %s", got.code, got.body)
	}

	adminSess, adminCSRFCookie, adminCSRF := loginFor(t, f.authFixture, "admin@acme.test", leasePw)
	rr := doJSONWith(t, f.srv.Handler(), "POST", "/sessions/"+f.rec.ID+"/end", nil, adminCSRF, adminSess, adminCSRFCookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin end session = %d: %s", rr.Code, rr.Body.String())
	}

	got := f.renewAs(t, "tech@acme.test")
	if got.code != http.StatusConflict {
		t.Fatalf("renew after end = %d, want 409 — an ended session must never be re-authorized: %s",
			got.code, got.body)
	}
	// And it stays refused: there is no window in which a retry succeeds.
	if again := f.renewAs(t, "tech@acme.test"); again.code != http.StatusConflict {
		t.Fatalf("second renew after end = %d, want 409", again.code)
	}
}

// A DISABLED principal cannot renew. Enforced by the auth middleware (SessionAuthenticator re-reads
// `disabled` on every request), which is why this drives the whole chain with a session cookie
// obtained BEFORE the disable: the handler contains no check for it, and a handler-level test would
// have proven nothing.
func TestRenewIsRefusedForADisabledPrincipal(t *testing.T) {
	f := newLeaseFixture(t)
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusOK {
		t.Fatalf("renewal must work before the technician is disabled: %d %s", got.code, got.body)
	}
	if err := f.users.SetUserDisabled(context.Background(), leaseTenant, leaseTechID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok)
	if got.code != http.StatusUnauthorized {
		t.Fatalf("renew as a disabled principal = %d, want 401: %s", got.code, got.body)
	}
}

// A SUSPENDED tenant cannot renew — every session in the tenant lapses within one lease.
func TestRenewIsRefusedForASuspendedTenant(t *testing.T) {
	f := newLeaseFixture(t)
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusOK {
		t.Fatalf("renewal must work before the tenant is suspended: %d %s", got.code, got.body)
	}
	f.users.SetTenantSuspended(leaseTenant, true)
	got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok)
	if got.code != http.StatusForbidden {
		t.Fatalf("renew in a suspended tenant = %d, want 403: %s", got.code, got.body)
	}
}

// A QUARANTINED machine cannot be renewed, so quarantine now CONTAINS a live session instead of
// only refusing new ones. Retired behaves the same way.
func TestRenewIsRefusedForAnOutOfServiceMachine(t *testing.T) {
	for _, status := range []string{MachineStatusQuarantined, MachineStatusRetired} {
		t.Run(status, func(t *testing.T) {
			f := newLeaseFixture(t)
			if got := f.renewAs(t, "tech@acme.test"); got.code != http.StatusOK {
				t.Fatalf("renewal must work while the machine is active: %d %s", got.code, got.body)
			}
			if err := f.machines.SetMachineStatus(context.Background(), leaseTenant, f.machine.ID, status); err != nil {
				t.Fatalf("set %s: %v", status, err)
			}
			got := f.renewAs(t, "tech@acme.test")
			if got.code != http.StatusConflict {
				t.Fatalf("renew on a %s machine = %d, want 409: %s", status, got.code, got.body)
			}
		})
	}
}

// Another technician — even an Admin holding the capability tenant-wide — cannot keep somebody
// else's session alive. Without this, an administrator ending a session could be undone by any admin
// account whose renewal the agent would happily accept, and nothing would be audited.
func TestOnlyTheHoldingTechnicianMayRenew(t *testing.T) {
	f := newLeaseFixture(t)
	got := f.renewAs(t, "admin@acme.test")
	if got.code != http.StatusForbidden {
		t.Fatalf("admin renewing another technician's session = %d, want 403: %s", got.code, got.body)
	}
	// The Admin genuinely holds authority over this session — so the 403 above isolates the OWNERSHIP
	// check rather than passing because the admin could not touch the session at all.
	adminSess, adminCSRFCookie, adminCSRF := loginFor(t, f.authFixture, "admin@acme.test", leasePw)
	if rr := doJSONWith(t, f.srv.Handler(), "POST", "/sessions/"+f.rec.ID+"/end", nil, adminCSRF, adminSess, adminCSRFCookie); rr.Code != http.StatusOK {
		t.Fatalf("the admin must hold session authority for this test to mean anything: %d", rr.Code)
	}
}

// The lease carries the group's CURRENT mandate, re-read on every renewal. An administrator who
// switches a group to view-only mid-session therefore binds the sessions ALREADY running: the next
// lease says view_only and the agent's one-way ratchet applies it.
func TestRenewCarriesTheGroupsCurrentMandate(t *testing.T) {
	f := newLeaseFixture(t)
	first := f.renewAs(t, "tech@acme.test")
	if first.code != http.StatusOK || first.decoded.SessionPolicy.Access != string(SessionAccessControl) {
		t.Fatalf("first lease = %d %q, want 200 control", first.code, first.decoded.SessionPolicy.Access)
	}
	if err := f.groups.Set(context.Background(), leaseTenant, leaseGroup,
		GroupSessionPolicy{GroupID: leaseGroup, EnforceViewOnly: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	second := f.renewAs(t, "tech@acme.test")
	if second.code != http.StatusOK {
		t.Fatalf("renew after the mandate changed = %d: %s", second.code, second.body)
	}
	if second.decoded.SessionPolicy.Access != string(SessionAccessViewOnly) {
		t.Fatalf("access = %q, want view_only once the group enforces it",
			second.decoded.SessionPolicy.Access)
	}
	assertLeaseVerifies(t, f, second.decoded.SessionPolicy.Signed, SessionAccessViewOnly)
}

// The capability is scoped to the machine's group, resolved from the STORED record rather than from
// anything the caller supplied. Both directions, so the refusal cannot be passing because the user
// simply holds nothing: the SAME role scoped to the machine's own group renews fine.
func TestRenewIsGroupScoped(t *testing.T) {
	const otherTechID = "33333333-3333-3333-3333-333333333333"
	for _, tc := range []struct {
		name  string
		scope GroupScope
		want  int
	}{
		{"scoped to another group", Groups("some-other-group"), http.StatusForbidden},
		{"scoped to the machine's group", Groups(leaseGroup), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLeaseFixture(t)
			f.addUserWithGrant(t, leaseTenant, otherTechID, "scoped@acme.test", leasePw,
				NewGrant(otherTechID, leaseTenant, NewMembership(RoleTechnician, tc.scope)))
			// Owned by THIS technician, so the ownership check cannot be what refuses them.
			rec := f.seedSession(t, otherTechID)
			sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "scoped@acme.test", leasePw)
			got := f.renewWith(t, rec.ID, sess, csrfCookie, csrfTok)
			if got.code != tc.want {
				t.Fatalf("renew %s = %d, want %d: %s", tc.name, got.code, tc.want, got.body)
			}
		})
	}
}

// A session that has exceeded the tenant's max_session_seconds is refused on the RENEWAL path and
// the record is stamped ended — the server-authoritative expiry for abandoned sessions. This closes
// the gap where a viewer tab closed without landing POST /sessions/{id}/end, leaving the row open
// forever if no further session start triggered ReapExpiredSessions.
func TestRenewIsRefusedAfterSessionExceedsMaxAge(t *testing.T) {
	f := newLeaseFixture(t)
	f.srv.SessionPolicies = NewInMemoryTenantSessionPolicyStore()
	if err := f.srv.SessionPolicies.Set(context.Background(), leaseTenant,
		SessionPolicy{MaxSessionSeconds: 60}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	// Plant a session started 2 hours ago — well past the 1-minute cap.
	old := &SessionRecord{
		MachineID:       f.machine.ID,
		TechnicianID:    leaseTechID,
		MachineGroupID:  f.machine.GroupID,
		MachineDeviceID: f.machine.DeviceID,
		MachineName:     f.machine.Name,
		StartedAt:       time.Now().Add(-2 * time.Hour),
	}
	if err := f.srv.SessionRecords.StartSession(context.Background(), leaseTenant, old); err != nil {
		t.Fatalf("seed old session: %v", err)
	}
	f.rec = old

	got := f.renewAs(t, "tech@acme.test")
	if got.code != http.StatusConflict {
		t.Fatalf("renew of max-age-expired session = %d, want 409: %s", got.code, got.body)
	}
	// The handler must have stamped ended_at so the record no longer holds a seat against the cap.
	stored, serr := f.srv.SessionRecords.GetSession(context.Background(), leaseTenant, old.ID)
	if serr != nil {
		t.Fatalf("get session after max-age expiry: %v", serr)
	}
	if stored.EndedAt == nil {
		t.Fatal("session record must have ended_at set after max-age expiry on the renewal path")
	}
	// Subsequent renewals are refused via the EndedAt check, not the age check — idempotent.
	if again := f.renewAs(t, "tech@acme.test"); again.code != http.StatusConflict {
		t.Fatalf("second renew after max-age expiry = %d, want 409", again.code)
	}
}

// NEGATIVE CONTROL: a session that has NOT yet reached max_session_seconds must still renew. Without
// this a misconfigured max age (e.g. equal to the renewal interval) would end every session on its
// second renewal.
func TestRenewNotRefusedForSessionUnderMaxAge(t *testing.T) {
	f := newLeaseFixture(t)
	f.srv.SessionPolicies = NewInMemoryTenantSessionPolicyStore()
	if err := f.srv.SessionPolicies.Set(context.Background(), leaseTenant,
		SessionPolicy{MaxSessionSeconds: 3600}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	// f.rec was seeded at ~time.Now — under the 1-hour limit.
	if got := f.renewAs(t, "tech@acme.test"); got.code != http.StatusOK {
		t.Fatalf("fresh session under max age = %d, want 200: %s", got.code, got.body)
	}
}

// NEGATIVE CONTROL: max_session_seconds = 0 means "no limit". An arbitrarily old session must still
// renew when the cap is unset. Without this a zero max age would end every session on its first
// renewal — 0 meaning "no cap" is a convention this codebase applies consistently.
func TestRenewNotRefusedWhenMaxAgeIsZero(t *testing.T) {
	f := newLeaseFixture(t)
	f.srv.SessionPolicies = NewInMemoryTenantSessionPolicyStore()
	if err := f.srv.SessionPolicies.Set(context.Background(), leaseTenant,
		SessionPolicy{MaxSessionSeconds: 0}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	old := &SessionRecord{
		MachineID:       f.machine.ID,
		TechnicianID:    leaseTechID,
		MachineGroupID:  f.machine.GroupID,
		MachineDeviceID: f.machine.DeviceID,
		MachineName:     f.machine.Name,
		StartedAt:       time.Now().Add(-48 * time.Hour),
	}
	if err := f.srv.SessionRecords.StartSession(context.Background(), leaseTenant, old); err != nil {
		t.Fatalf("seed old session: %v", err)
	}
	f.rec = old
	if got := f.renewAs(t, "tech@acme.test"); got.code != http.StatusOK {
		t.Fatalf("old session with no max age = %d, want 200: %s", got.code, got.body)
	}
}

// An unknown session id is a 404 — not a 500, and above all not a mint.
func TestRenewUnknownSessionIs404(t *testing.T) {
	f := newLeaseFixture(t)
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	got := f.renewWith(t, newUUID(), sess, csrfCookie, csrfTok)
	if got.code != http.StatusNotFound {
		t.Fatalf("renew unknown session = %d, want 404: %s", got.code, got.body)
	}
}

// The ownership check must precede the max-age mutation. Before the reorder, an admin calling the
// renewal endpoint for ANOTHER technician's over-age session would stamp ended_at (via the max-age
// EndSession) and THEN return 403 — state was mutated by an unauthorized caller.
func TestMaxAgeMutationRequiresOwnership(t *testing.T) {
	f := newLeaseFixture(t)
	f.srv.SessionPolicies = NewInMemoryTenantSessionPolicyStore()
	if err := f.srv.SessionPolicies.Set(context.Background(), leaseTenant,
		SessionPolicy{MaxSessionSeconds: 60}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	// Plant an expired session owned by the technician — 2h old, well past the 1-minute cap.
	old := &SessionRecord{
		MachineID:       f.machine.ID,
		TechnicianID:    leaseTechID,
		MachineGroupID:  f.machine.GroupID,
		MachineDeviceID: f.machine.DeviceID,
		MachineName:     f.machine.Name,
		StartedAt:       time.Now().Add(-2 * time.Hour),
	}
	if err := f.srv.SessionRecords.StartSession(context.Background(), leaseTenant, old); err != nil {
		t.Fatalf("seed old session: %v", err)
	}
	f.rec = old

	// Admin (NOT the session owner) calls the renewal endpoint.
	got := f.renewAs(t, "admin@acme.test")
	if got.code != http.StatusForbidden {
		t.Fatalf("admin renewing another tech's expired session = %d, want 403 "+
			"(ownership check must precede the max-age mutation): %s", got.code, got.body)
	}
	// The session must NOT have been ended — the caller was not authorized to trigger that write.
	stored, serr := f.srv.SessionRecords.GetSession(context.Background(), leaseTenant, old.ID)
	if serr != nil {
		t.Fatalf("get session after unauthorized renewal: %v", serr)
	}
	if stored.EndedAt != nil {
		t.Fatal("session was ended by an unauthorized caller — ownership check must come before the max-age mutation")
	}
}

// TestRenewDoesNotApplyNewGroupRestrictions verifies that the renewal path (Pass4) does NOT apply
// the four new group restrictions (require_recording, prohibit_recording, max_session_duration_seconds,
// max_idle_seconds) to the signed lease, even when those restrictions are set on the group mid-session.
//
// WHY: the admission gate refuses session STARTS when any of these are set. An operator who adds them
// to a group mid-session must not cause old agents (which pre-date 7c81bde) to silently receive
// unenforceable policy via renewal. The renewed lease must carry the safe defaults (allow_recording=true,
// require_recording=false, max_session_duration_seconds=0, max_idle_seconds=0).
func TestRenewDoesNotApplyNewGroupRestrictions(t *testing.T) {
	f := newLeaseFixture(t)

	// Verify baseline: a fresh lease has safe defaults.
	before := f.renewAs(t, "tech@acme.test")
	if before.code != http.StatusOK {
		t.Fatalf("baseline renew = %d: %s", before.code, before.body)
	}
	var beforeSP SignedSessionPolicy
	if err := json.Unmarshal([]byte(before.decoded.SessionPolicy.Signed), &beforeSP); err != nil {
		t.Fatalf("decode baseline: %v", err)
	}
	if !beforeSP.Claims.Policy.AllowRecording {
		t.Fatal("baseline lease has allow_recording=false — should default to true")
	}
	if beforeSP.Claims.Policy.RequireRecording {
		t.Fatal("baseline lease has require_recording=true — should be false")
	}
	if beforeSP.Claims.Policy.MaxSessionDurationSeconds != 0 {
		t.Fatalf("baseline max_session_duration_seconds = %d, want 0", beforeSP.Claims.Policy.MaxSessionDurationSeconds)
	}
	if beforeSP.Claims.Policy.MaxIdleSeconds != 0 {
		t.Fatalf("baseline max_idle_seconds = %d, want 0", beforeSP.Claims.Policy.MaxIdleSeconds)
	}

	// Now set all four new restrictions on the group mid-session.
	if err := f.groups.Set(context.Background(), leaseTenant, leaseGroup, GroupSessionPolicy{
		GroupID:                   leaseGroup,
		RequireRecording:          true,
		ProhibitRecording:         false, // can't be true with RequireRecording
		MaxSessionDurationSeconds: 3600,
		MaxIdleSeconds:            300,
	}); err != nil {
		t.Fatalf("set restrictive group policy: %v", err)
	}

	// Renewal must succeed (the session continues) and the new restrictions must NOT appear in the lease.
	after := f.renewAs(t, "tech@acme.test")
	if after.code != http.StatusOK {
		t.Fatalf("renew after new restrictions set = %d: %s — renewal must succeed; "+
			"existing sessions are not disrupted when a group gets new restrictions mid-session",
			after.code, after.body)
	}
	var afterSP SignedSessionPolicy
	if err := json.Unmarshal([]byte(after.decoded.SessionPolicy.Signed), &afterSP); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if !afterSP.Claims.Policy.AllowRecording {
		t.Fatal("lease after ProhibitRecording set has allow_recording=false — new restriction must not be applied")
	}
	if afterSP.Claims.Policy.RequireRecording {
		t.Fatal("lease after RequireRecording set has require_recording=true — new restriction must not be applied")
	}
	if afterSP.Claims.Policy.MaxSessionDurationSeconds != 0 {
		t.Fatalf("lease after duration set has max_session_duration_seconds=%d — new restriction must not be applied",
			afterSP.Claims.Policy.MaxSessionDurationSeconds)
	}
	if afterSP.Claims.Policy.MaxIdleSeconds != 0 {
		t.Fatalf("lease after idle set has max_idle_seconds=%d — new restriction must not be applied",
			afterSP.Claims.Policy.MaxIdleSeconds)
	}
}
