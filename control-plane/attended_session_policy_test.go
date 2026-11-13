package controlplane

// The ATTENDED path and the per-group view-only mandate (docs/01 §5, loop 81).
//
// This file exists because loop 80's adversarial review found — twice, from two independent lenses —
// that a guest-initiated (attended) session bypassed the mandate entirely: the connect handler minted a
// session TICKET but no session POLICY, so an attended technician had full control of a machine in a
// group the console showed as view-only.
//
// The bypass was easy to miss because an attended machine is EPHEMERAL, which sounds group-less. It is
// not: AttendedStore.Redeem enrols that ephemeral machine INTO the invite's group
// (enrollEphemeral(tenant, device, t.GroupID, …)), and handleConnectAttended already authorizes against
// sess.GroupID. So the group is real, the mandate applies, and it simply was not enforced.

import (
	"encoding/json"
	"net/http"
	"testing"
)

// attendedPolicyResp is the slice of the connect response these tests care about.
type attendedPolicyResp struct {
	Session struct {
		ID       string `json:"id"`
		GroupID  string `json:"group_id"`
		DeviceID string `json:"device_id"`
	} `json:"session"`
	SessionPolicy *struct {
		Access string `json:"access"`
		Signed string `json:"signed"`
	} `json:"session_policy"`
}

// driveAttendedToConnect runs the full create → redeem → consent → connect dance and returns the
// decoded connect response plus its status. Mirrors TestAttendedConsentGate's sequence.
func driveAttendedToConnect(t *testing.T, srv *Server) (int, attendedPolicyResp) {
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
	var out attendedPolicyResp
	code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/connect", "", &out)
	return code, out
}

// THE REGRESSION. A group flagged enforce_view_only must restrict an ATTENDED session too, and the
// signed blob must agree with the advertised level.
func TestAttendedConnectMintsThePolicyForAnEnforcingGroup(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), "00000000-0000-0000-0000-0000000000bb",
		attendTestGroup, GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	code, out := driveAttendedToConnect(t, srv)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy == nil {
		t.Fatal("attended connect returned NO session_policy for a group that enforces view-only — " +
			"the mandate is bypassed by taking the attended route")
	}
	if out.SessionPolicy.Access != string(SessionAccessViewOnly) {
		t.Fatalf("access = %q, want %q", out.SessionPolicy.Access, SessionAccessViewOnly)
	}

	// The cleartext level is only for display; the SIGNED blob is what the agent enforces, so they must
	// agree, and it must be bound to THIS attended session and its ephemeral device.
	var signed struct {
		Claims struct {
			Policy struct {
				Access    string `json:"access"`
				SessionID string `json:"session_id"`
				MachineID string `json:"machine_id"`
			} `json:"policy"`
		} `json:"claims"`
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal([]byte(out.SessionPolicy.Signed), &signed); err != nil {
		t.Fatalf("decode signed policy: %v (%s)", err, out.SessionPolicy.Signed)
	}
	if signed.Claims.Policy.Access != string(SessionAccessViewOnly) {
		t.Fatalf("SIGNED access = %q but the response advertised %q", signed.Claims.Policy.Access,
			out.SessionPolicy.Access)
	}
	if signed.Claims.Policy.SessionID != out.Session.ID {
		t.Fatalf("policy session_id = %q, want the attended session %q",
			signed.Claims.Policy.SessionID, out.Session.ID)
	}
	if signed.Claims.Policy.MachineID != out.Session.DeviceID {
		t.Fatalf("policy machine_id = %q, want the EPHEMERAL device %q — the agent binds the policy to "+
			"its own device id, so a mismatch means it will reject it",
			signed.Claims.Policy.MachineID, out.Session.DeviceID)
	}
	if len(signed.Sig) != 128 {
		t.Fatalf("signature is %d hex chars, want 128", len(signed.Sig))
	}
}

// The complement, and the half that keeps this honest: a group that enforces NOTHING must get no policy.
// Without it, a handler that minted unconditionally would pass the test above while putting every agent
// that cannot verify a policy into view-only — the fleet-wide failure loop 80's review caught on the
// unattended path.
func TestAttendedConnectMintsNoPolicyForAnOrdinaryGroup(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	code, out := driveAttendedToConnect(t, srv)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy != nil {
		t.Fatalf("a policy was minted for a group that enforces nothing: %+v", out.SessionPolicy)
	}
}

// require_recording is INCOMPATIBLE with attended (guest) sessions.
//
// Attended agents are ephemeral downloads with no recording_dir configured — by design (loop 89, see
// host.rs ≈line 1054). They can never satisfy require_recording regardless of agent version. The
// control plane must reject such sessions BEFORE the attended agent connects and exposes the desktop,
// not after the policy is sent and silently ignored.
//
// This is the release-blocker the Codex independent review raised: the connect handler admitted
// attended sessions into require_recording groups without a capability gate. The attended agent's
// auto-start would silently skip (no dir) while the session proceeded with the desktop exposed.
func TestAttendedConnectRejectsRequireRecordingGroups(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant,
		attendTestGroup, GroupSessionPolicy{RequireRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	code, _ := driveAttendedToConnect(t, srv)
	if code != http.StatusForbidden {
		t.Fatalf("connect to a require_recording group returned %d, want 403 — an attended agent can "+
			"never satisfy require_recording (no recording_dir), so the session must be rejected before "+
			"the desktop is exposed, not after the policy is silently ignored", code)
	}
}

// prohibit_recording is also incompatible with attended (guest) sessions.
//
// Old attended binaries do not read the allow_recording field in the signed policy, so the ban
// would be silently unenforced. The control plane must reject before the desktop is exposed rather
// than deliver an unenforceable restriction. This supersedes the earlier "allows prohibit_recording"
// test: that test asserted incidental enforcement (no recorder configured), but did not prove
// safety for legacy attended agents that may have recording enabled.
func TestAttendedConnectRejectsProhibitRecordingGroups(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant,
		attendTestGroup, GroupSessionPolicy{ProhibitRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	code, _ := driveAttendedToConnect(t, srv)
	if code != http.StatusForbidden {
		t.Fatalf("connect to a prohibit_recording group returned %d, want 403 — enforcement cannot "+
			"be guaranteed for attended sessions; the control plane must reject before the desktop is "+
			"exposed rather than deliver an unenforceable policy", code)
	}
}

// max_session_duration_seconds cannot be enforced for attended sessions: attended agents use
// SessionLeaseMode::NotApplicable with no lease renewal path to carry the limit.
func TestAttendedConnectRejectsGroupsWithSessionDurationLimit(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant,
		attendTestGroup, GroupSessionPolicy{MaxSessionDurationSeconds: 3600}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	code, _ := driveAttendedToConnect(t, srv)
	if code != http.StatusForbidden {
		t.Fatalf("connect to a max_session_duration group returned %d, want 403 — duration limits "+
			"cannot be enforced on attended sessions (no lease renewal path)", code)
	}
}

// max_idle_seconds cannot be enforced for attended sessions for the same reason as duration limits.
func TestAttendedConnectRejectsGroupsWithIdleTimeout(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant,
		attendTestGroup, GroupSessionPolicy{MaxIdleSeconds: 300}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	code, _ := driveAttendedToConnect(t, srv)
	if code != http.StatusForbidden {
		t.Fatalf("connect to a max_idle_seconds group returned %d, want 403 — idle timeouts "+
			"cannot be enforced on attended sessions (no lease renewal path)", code)
	}
}

// An attended deployment with no group-policy store wired at all must still connect. This is the DEV /
// older-deployment path, and breaking it would take attended support down for everyone.
func TestAttendedConnectWithoutAPolicyStoreStillConnects(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = nil

	code, out := driveAttendedToConnect(t, srv)
	if code != http.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	if out.SessionPolicy != nil {
		t.Fatalf("a policy appeared with no store wired: %+v", out.SessionPolicy)
	}
}
