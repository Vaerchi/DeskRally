package controlplane

// LOOP 82: the attended guest's opt-in to the PROVISIONAL FLOOR (`require_session_policy`).
//
// THE GAP THESE COVER. Loop 81 made the attended CONNECT mint a signed policy for an enforcing group,
// which binds a viewer that forwards it. But the policy reaches the agent only BECAUSE the viewer
// forwards it, and the viewer is precisely the party the policy restricts — so a technician running a
// patched console can withhold the frame and the agent, never having heard of a policy, hands over full
// control. On the unattended path an operator closes that with config.json's `require_session_policy`.
// An attended guest has no config file and no argv flag, so that flag was UNREACHABLE and the mandate
// there bound a COOPERATIVE viewer only. Redemption is the one moment the control plane speaks to the
// guest directly and it already knows the invite's group, so it is the only place the instruction can
// come from.

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// The tenant newAttendedServer's principal belongs to. Named rather than repeated as a literal because
// the group policy is keyed on (tenant, group) and a wrong tenant here would silently look up an EMPTY
// policy — the test would then pass for the wrong reason.
const attendTestTenant = "00000000-0000-0000-0000-0000000000bb"

// attendedRedeemPolicyResp is the slice of the REDEEM response these tests care about. Both fields are
// optional on the wire, so they are POINTERS: "absent" and "present but false" are different claims and
// the coupling test below turns on telling them apart.
type attendedRedeemPolicyResp struct {
	AttendToken          string  `json:"attend_token"`
	GrantIssuerPubkey    *string `json:"grant_issuer_pubkey"`
	RequireSessionPolicy *bool   `json:"require_session_policy"`
}

// driveAttendedToRedeem runs create → redeem and returns the redeem status + decoded body, plus the
// session id so a caller can also inspect what was PERSISTED. The id used to be discarded, and that is
// exactly why the coupling test below could only check the response — see its comment.
func driveAttendedToRedeem(t *testing.T, srv *Server) (int, attendedRedeemPolicyResp, string) {
	t.Helper()
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}
	var out attendedRedeemPolicyResp
	code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`, &out)
	return code, out, created.Session.ID
}

// enforcingGroupPolicies wires a store in which attendTestGroup enforces view-only.
func enforcingGroupPolicies(t *testing.T, srv *Server) {
	t.Helper()
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	if err := srv.GroupSessionPolicies.Set(t.Context(), attendTestTenant,
		attendTestGroup, GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
}

// THE REGRESSION. An enforcing group must tell the guest to open FLOORED.
func TestAttendedRedeemRequiresASessionPolicyForAnEnforcingGroup(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)

	code, out, _ := driveAttendedToRedeem(t, srv)
	if code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if out.RequireSessionPolicy == nil || !*out.RequireSessionPolicy {
		t.Fatal("redeem did NOT tell the guest to require a session policy for a group that enforces " +
			"view-only — the guest opens unfloored, so a viewer that simply withholds the policy frame " +
			"keeps full control and the mandate is advisory")
	}
	// The floor and the means of LIFTING it must travel together; see the coupling test below.
	if out.GrantIssuerPubkey == nil || *out.GrantIssuerPubkey == "" {
		t.Fatal("required a session policy but advertised no grant issuer pubkey — the guest could " +
			"never verify one, so the session could never leave view-only")
	}
}

// The complement that keeps the test above honest: a handler that hard-coded `true` would pass it while
// stranding every ordinary attended session in view-only.
func TestAttendedRedeemDoesNotRequireASessionPolicyForAnOrdinaryGroup(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()

	code, out, _ := driveAttendedToRedeem(t, srv)
	if code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if out.RequireSessionPolicy != nil && *out.RequireSessionPolicy {
		t.Fatal("a group that enforces nothing told the guest to open VIEW-ONLY — every ordinary " +
			"attended session would start restricted")
	}
}

// THE COUPLING, and the one loop 80 paid for on the unattended path. A guest that pinned NO issuer key
// cannot verify ANY policy, so telling it to require one is a floor with no key: the session opens
// view-only and can never leave. The restriction and the means of lifting it must ship together.
func TestAttendedRedeemDoesNotRequireAPolicyTheGuestCouldNeverVerify(t *testing.T) {
	srv, _ := newAttendedServer(t)
	enforcingGroupPolicies(t, srv)
	srv.Grants = nil // no grant issuer ⇒ no pubkey is advertised at redeem

	code, out, sessionID := driveAttendedToRedeem(t, srv)
	if code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if out.GrantIssuerPubkey != nil {
		t.Fatalf("premise broken: a pubkey was advertised with no issuer configured (%q)",
			*out.GrantIssuerPubkey)
	}
	if out.RequireSessionPolicy != nil && *out.RequireSessionPolicy {
		t.Fatal("told the guest to require a session policy while advertising NO issuer key — it can " +
			"verify nothing, so the session is stranded in view-only with no way out. This is the " +
			"fleet-wide interaction loop 80's review caught on the unattended path")
	}
	// AND nothing was RECORDED. Asserting only the response left the coupling half-tested: an
	// adversarial review confirmed that hoisting the `pinned` check so the store write ran
	// unconditionally — gating only the response field on it — survived the entire suite. That state is
	// a session the control plane believes it floored and the guest never did, so a later connect would
	// hand `access=control` to a guest that never opted in. Harmless today (with no issuer configured,
	// connect 500s before any mint) but the guard on the WRITE has to be tested where it is, not
	// wherever it happens to be currently unreachable from.
	if storedFloor(t, srv, sessionID) {
		t.Fatal("recorded a floor on the session while advertising NO issuer key — the write is not " +
			"coupled to the pinned key, only the response is")
	}
}

// A deployment with no group-policy store at all (DEV, older installs) must still redeem.
func TestAttendedRedeemWithoutAPolicyStoreStillRedeems(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = nil

	code, out, _ := driveAttendedToRedeem(t, srv)
	if code != http.StatusCreated {
		t.Fatalf("redeem: status %d", code)
	}
	if out.RequireSessionPolicy != nil && *out.RequireSessionPolicy {
		t.Fatal("a floor was demanded with no policy store wired")
	}
	if out.AttendToken == "" {
		t.Fatal("redeem returned no attend token — the guest cannot make its callbacks")
	}
}

// erroringGroupSessionPolicyStore fails every Get. The embedded interface supplies the rest of the
// method set; only Get is reached on this path.
type erroringGroupSessionPolicyStore struct{ GroupSessionPolicyStore }

func (erroringGroupSessionPolicyStore) Get(context.Context, string, string) (GroupSessionPolicy, error) {
	return GroupSessionPolicy{}, errors.New("group policy store is down")
}

// FAIL CLOSED. "We cannot tell whether this group enforces" must not resolve to "open it unfloored" —
// that is exactly the bypass. Matches handleConnectAttended's behaviour on the same lookup.
func TestAttendedRedeemFailsClosedWhenTheGroupPolicyCannotBeResolved(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.GroupSessionPolicies = erroringGroupSessionPolicyStore{}

	code, out, _ := driveAttendedToRedeem(t, srv)
	if code != http.StatusInternalServerError {
		t.Fatalf("redeem: status %d, want 500 — an unresolvable group policy must not silently "+
			"produce an unfloored session", code)
	}
	if out.AttendToken != "" {
		t.Fatal("a failed redeem still handed out an attend token")
	}
}
