package controlplane

// LOOP 83: the redeem/connect SAMPLING WINDOW on the attended path (migration 0036).
//
// THE DEFECT THESE COVER, and it was created by loop 82's own design. Two halves of one decision are
// read at different moments:
//
//   * REDEEM tells the guest whether to open FLOORED (view-only until a signed policy verifies), and
//     the guest acts on that answer immediately and irrevocably for the session's whole life;
//   * CONNECT decides whether to MINT a policy, from the group's state right then.
//
// Clear `enforce_view_only` in between and the two disagree in the direction that hurts: the guest is
// floored and no policy will ever arrive to discharge it. It is stuck view-only with nothing on screen
// explaining why, and no amount of retrying by the technician helps, because the group no longer asks
// for anything. (The other order is benign and is pinned below too: flipped ON after redeem, the guest
// never opted in, connect still mints, and a cooperative viewer is restricted exactly as before.)
//
// The fix is MEMORY, not new agent behaviour: redeem records the promise on the session, and connect
// keeps it — minting whatever the group's CURRENT level is. `access=control` is precisely what the
// agent's ratchet accepts to discharge a PROVISIONAL floor, and only a provisional one.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// attendedRedeemedSession is the create+redeem+consent prefix of the connect dance, stopping short of
// connect so a test can change the world in between — which is the whole subject of this file.
type attendedRedeemedSession struct {
	SessionID   string
	AttendToken string
}

func driveAttendedToConsent(t *testing.T, srv *Server) attendedRedeemedSession {
	t.Helper()
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("consent: status %d", code)
	}
	return attendedRedeemedSession{SessionID: created.Session.ID, AttendToken: redeemed.AttendToken}
}

// connectAttended posts the connect for an already-consented session.
func connectAttended(t *testing.T, srv *Server, sessionID string) (int, attendedPolicyResp) {
	t.Helper()
	var out attendedPolicyResp
	code := apiJSON(t, srv, "POST", "/attended-sessions/"+sessionID+"/connect", "", &out)
	return code, out
}

// setGroupEnforcement points attendTestGroup's policy at `enforce` — used to move the world BETWEEN
// redeem and connect, which is the window under test.
func setGroupEnforcement(t *testing.T, srv *Server, enforce bool) {
	t.Helper()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant, attendTestGroup,
		GroupSessionPolicy{EnforceViewOnly: enforce}); err != nil {
		t.Fatalf("set group policy enforce=%t: %v", enforce, err)
	}
}

// storedFloor reads the flag back out of the store, i.e. what CONNECT will later see. Read through the
// store rather than the create/redeem response on purpose: the response is what the guest was TOLD, and
// the entire point of 0036 is that those two must not be able to diverge.
func storedFloor(t *testing.T, srv *Server, sessionID string) bool {
	t.Helper()
	sess, err := srv.Attended.Get(context.Background(), attendTestTenant, sessionID)
	if err != nil {
		t.Fatalf("get attended session %s: %v", sessionID, err)
	}
	return sess.RequireSessionPolicy
}

// Redemption must RECORD the floor it just promised, not merely announce it.
func TestAttendedRedeemRecordsTheFloorOnTheSession(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	if !storedFloor(t, srv, sess.SessionID) {
		t.Fatal("redeem told the guest to open FLOORED but recorded nothing on the session — connect " +
			"then has no way to know a floor is in force, which is exactly how a cleared group mandate " +
			"strands the guest in view-only forever")
	}
}

// The complement: an ordinary group must not leave the flag set, or every attended session would be
// minted a policy and the presence-is-the-signal rule would stop meaning anything on this path.
func TestAttendedRedeemRecordsNoFloorForAnOrdinaryGroup(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	sess := driveAttendedToConsent(t, srv)
	if storedFloor(t, srv, sess.SessionID) {
		t.Fatal("a group that enforces nothing recorded a floor on the session")
	}
}

// floorWriteFailsAttendedStore delegates everything to the real store except the floor write. Embedding
// the INTERFACE (not the concrete fake) means redeem/consent/connect all still work, so the test
// exercises the real sequence and only the one write fails.
type floorWriteFailsAttendedStore struct{ AttendedStore }

func (floorWriteFailsAttendedStore) SetRequireSessionPolicy(context.Context, string, string) error {
	return errors.New("attended store is down")
}

// FAIL CLOSED, and note which way "closed" points here. A guest told to floor while the control plane
// holds NO record of it is the precise state 0036 exists to prevent, so the redeem fails rather than
// answering `require_session_policy: true` on a promise nothing will keep. It costs the one-time code,
// which is the cheap half of the trade.
func TestAttendedRedeemFailsWhenTheFloorCannotBeRecorded(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)
	srv.Attended = floorWriteFailsAttendedStore{srv.Attended}

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	var out attendedRedeemPolicyResp
	code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`, &out)
	if code != http.StatusInternalServerError {
		t.Fatalf("redeem: status %d, want 500 — a floor that could not be recorded must not be promised", code)
	}
	// Status alone is not enough: this handler's error path is `writeError` followed by `return`, and a
	// missing `return` would send a 500 header AND a full body. Assert the guest was not simultaneously
	// told to floor and given the token to go do it with.
	if out.RequireSessionPolicy != nil && *out.RequireSessionPolicy {
		t.Fatal("a 500 response still told the guest to require a session policy")
	}
	if out.AttendToken != "" {
		t.Fatal("a failed redeem still handed out an attend token")
	}
}

// decodeSignedAccess pulls the access level out of the SIGNED blob — the only field the agent actually
// obeys. The cleartext `access` beside it is for display, so a test that read only that could pass while
// the agent received the opposite instruction.
func decodeSignedAccess(t *testing.T, signed string) string {
	t.Helper()
	var s struct {
		Claims struct {
			Policy struct {
				Access string `json:"access"`
			} `json:"policy"`
		} `json:"claims"`
	}
	if err := json.Unmarshal([]byte(signed), &s); err != nil {
		t.Fatalf("decode signed policy: %v (%s)", err, signed)
	}
	return s.Claims.Policy.Access
}

// ★ THE HEADLINE. Told to floor at redeem, mandate CLEARED before connect: a policy must still be minted,
// and it must carry `control` — the one thing that can discharge a provisional floor.
func TestAttendedConnectDischargesAFloorTheGroupNoLongerEnforces(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	if !storedFloor(t, srv, sess.SessionID) {
		t.Fatal("premise broken: the guest was not recorded as floored, so this test would pass for " +
			"the wrong reason")
	}
	setGroupEnforcement(t, srv, false) // the admin clears the mandate mid-session

	code, out := connectAttended(t, srv, sess.SessionID)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy == nil {
		t.Fatal("no policy was minted for a guest that had already been told to open FLOORED — it is " +
			"dropping the technician's input right now and nothing will ever arrive to release it: " +
			"stuck view-only for the session's whole life, with nothing explaining why")
	}
	if out.SessionPolicy.Access != string(SessionAccessControl) {
		t.Fatalf("access = %q, want %q — a view_only policy here would VERIFY the floor into place "+
			"permanently instead of discharging it", out.SessionPolicy.Access, SessionAccessControl)
	}
	if got := decodeSignedAccess(t, out.SessionPolicy.Signed); got != string(SessionAccessControl) {
		t.Fatalf("SIGNED access = %q but the response advertised %q — the agent obeys the signature, so "+
			"it is the blob that decides whether the guest is released", got, out.SessionPolicy.Access)
	}
}

// The mutation guard for the test above: `access` must come from the GROUP's current state, not from the
// flag. An implementation that returned `control` whenever the flag was set would pass the headline test
// while handing full control to every session in a group that DOES still enforce view-only — turning the
// fix into the very bypass the arc closed.
func TestAttendedConnectStillMintsViewOnlyWhileTheGroupEnforces(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	if !storedFloor(t, srv, sess.SessionID) {
		t.Fatal("premise broken: the guest was not recorded as floored")
	}
	// The mandate stays in force — nothing is cleared this time.

	code, out := connectAttended(t, srv, sess.SessionID)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy == nil {
		t.Fatal("no policy for a group that enforces view-only")
	}
	if out.SessionPolicy.Access != string(SessionAccessViewOnly) {
		t.Fatalf("access = %q, want %q — the floor flag must not OVERRIDE a live mandate",
			out.SessionPolicy.Access, SessionAccessViewOnly)
	}
	if got := decodeSignedAccess(t, out.SessionPolicy.Signed); got != string(SessionAccessViewOnly) {
		t.Fatalf("SIGNED access = %q, want %q", got, SessionAccessViewOnly)
	}
}

// The BENIGN direction, pinned so a later change cannot quietly turn it into the harmful one. Mandate
// flipped ON after redeem: this guest never opted into the floor, so it is not enforcing one — but the
// group asks for view-only now, so the mint happens and a cooperative viewer is restricted exactly as it
// was before 0036. Nothing is stranded, because nothing was floored.
func TestAttendedConnectMintsViewOnlyForAMandateAddedAfterRedeem(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	sess := driveAttendedToConsent(t, srv)
	if storedFloor(t, srv, sess.SessionID) {
		t.Fatal("premise broken: an ordinary group recorded a floor")
	}
	setGroupEnforcement(t, srv, true) // the admin ADDS the mandate mid-session

	code, out := connectAttended(t, srv, sess.SessionID)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy == nil {
		t.Fatal("no policy minted for a group that enforces view-only now")
	}
	if out.SessionPolicy.Access != string(SessionAccessViewOnly) {
		t.Fatalf("access = %q, want %q", out.SessionPolicy.Access, SessionAccessViewOnly)
	}
}

// Neither floored nor enforcing ⇒ still NO policy. This is the case that keeps `access=control` from
// leaking into the ordinary path: after 0036 the mint is reachable with `control`, and if the condition
// were widened by mistake, every agent that cannot verify a policy would fail closed to view-only — the
// fleet-wide interaction loop 80's review caught.
func TestAttendedConnectMintsNothingWhenNeitherFlooredNorEnforcing(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	sess := driveAttendedToConsent(t, srv)
	code, out := connectAttended(t, srv, sess.SessionID)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy != nil {
		t.Fatalf("a policy was minted for a session that is neither floored nor in an enforcing group: %+v",
			out.SessionPolicy)
	}
}

// FAIL CLOSED at CONNECT, and loop 83 raised the stakes of this guard enough to deserve a test.
//
// The lookup fails closed on both legs, but the reachable window is specifically "store up at redeem,
// down at connect" — a transient outage or a failover — because a store that is down for the whole
// session never lets the guest redeem at all. What changed: before this loop, failing OPEN here left a
// floored guest stranded (bad, but closed). After it, the same fall-through would mint `access=control`
// for a guest whose group may well still enforce view-only, i.e. it would hand over the very control the
// mandate exists to withhold. An adversarial review found this branch had no test and confirmed a
// `groupPolicy = GroupSessionPolicy{}` fall-through survived the whole suite.
func TestAttendedConnectFailsClosedWhenTheGroupPolicyCannotBeResolved(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv) // redeem sees a WORKING store, so the guest is floored
	if !storedFloor(t, srv, sess.SessionID) {
		t.Fatal("premise broken: the guest was not recorded as floored")
	}
	srv.GroupSessionPolicies = erroringGroupSessionPolicyStore{} // and it dies before connect

	code, out := connectAttended(t, srv, sess.SessionID)
	if code != http.StatusInternalServerError {
		t.Fatalf("connect: status %d, want 500 — an unresolvable group policy must not resolve to "+
			"\"mint whatever\", which after 0036 means handing out access=control", code)
	}
	// Status alone is not enough: this handler's error paths are writeError-then-return, and a missing
	// return would send a 500 header AND a body carrying a usable policy (the loop-54 trap).
	if out.SessionPolicy != nil {
		t.Fatalf("a 500 response still carried a session policy: %+v", out.SessionPolicy)
	}
}

// connectAuditMeta returns the metadata of the tenant's single `attended.connect` event.
func connectAuditMeta(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	ev, ok := auditActions(t, srv, attendTestTenant)["attended.connect"]
	if !ok {
		t.Fatal("no attended.connect audit event was recorded")
	}
	var meta map[string]any
	if len(ev.Metadata) > 0 {
		if err := json.Unmarshal(ev.Metadata, &meta); err != nil {
			t.Fatalf("decode audit metadata %q: %v", string(ev.Metadata), err)
		}
	}
	return meta
}

// The audit trail must record WHICH regime the session ran in, and this is the case that made it
// necessary: the first `access=control` policy the system has ever minted.
//
// Before loop 83 a policy's PRESENCE implied `view_only`, so `{device_id}` alone left the level
// inferable. It does not any more. Without the level on the record, an auditor asking "did this session
// have full control of a machine in a view-only group?" has to interleave `machine_group.*` events by
// timestamp and guess — and cannot answer at all if the mandate was cleared outside the audited path.
func TestAttendedConnectAuditRecordsTheDischargedFloor(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	setGroupEnforcement(t, srv, false)
	if code, _ := connectAttended(t, srv, sess.SessionID); code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}

	meta := connectAuditMeta(t, srv)
	if got := meta["session_policy_access"]; got != string(SessionAccessControl) {
		t.Fatalf("audit session_policy_access = %v, want %q — the trail cannot say whether this "+
			"session ran with full control", got, SessionAccessControl)
	}
	// The two inputs that decided it, so the record explains itself without a second query.
	if got := meta["group_enforces_view_only"]; got != false {
		t.Fatalf("audit group_enforces_view_only = %v, want false", got)
	}
	if got := meta["guest_told_to_floor"]; got != true {
		t.Fatalf("audit guest_told_to_floor = %v, want true — this is what made the mint happen at all", got)
	}
}

// The complement: a view-only session records `view_only`, so the two outcomes are distinguishable on
// the trail rather than merely both being present.
func TestAttendedConnectAuditRecordsAViewOnlyMandate(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	if code, _ := connectAttended(t, srv, sess.SessionID); code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	meta := connectAuditMeta(t, srv)
	if got := meta["session_policy_access"]; got != string(SessionAccessViewOnly) {
		t.Fatalf("audit session_policy_access = %v, want %q", got, SessionAccessViewOnly)
	}
	if got := meta["group_enforces_view_only"]; got != true {
		t.Fatalf("audit group_enforces_view_only = %v, want true", got)
	}
}

// And a session with NO policy must not claim a level. Otherwise every ordinary attended connect would
// read as a policy decision on the trail, which is the opposite failure: noise that hides the real ones.
func TestAttendedConnectAuditOmitsTheLevelWhenNoPolicyIsMinted(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	sess := driveAttendedToConsent(t, srv)
	if code, out := connectAttended(t, srv, sess.SessionID); code != http.StatusOK || out.SessionPolicy != nil {
		t.Fatalf("premise not met: status %d policy=%+v", code, out.SessionPolicy)
	}
	meta := connectAuditMeta(t, srv)
	if _, present := meta["session_policy_access"]; present {
		t.Fatalf("a connect that minted NO policy recorded a policy level: %v", meta)
	}
	if meta["device_id"] == nil || meta["device_id"] == "" {
		t.Fatalf("the device id went missing from the audit record: %v", meta)
	}
}

// The ordering half of the same fix: a connect that FAILS after MarkActive must leave no
// `attended.connect` on the chain. The audit used to be written immediately after MarkActive, so a
// later 500 (an unresolvable group policy, a failed mint) recorded a connect that handed the technician
// no ticket, no policy and no session — indistinguishable on the trail from one that worked.
func TestAttendedConnectRecordsNoAuditWhenItFails(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	sess := driveAttendedToConsent(t, srv)
	srv.GroupSessionPolicies = erroringGroupSessionPolicyStore{}
	if code, _ := connectAttended(t, srv, sess.SessionID); code != http.StatusInternalServerError {
		t.Fatalf("premise not met: connect = %d, want 500", code)
	}
	if ev, ok := auditActions(t, srv, attendTestTenant)["attended.connect"]; ok {
		t.Fatalf("a FAILED connect is on the audit trail as if it succeeded: %+v", ev)
	}
}
