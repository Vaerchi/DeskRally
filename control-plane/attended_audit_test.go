package controlplane

// The two GUEST-side attended transitions must reach the management audit trail, as the guest-side
// enrollment transition already does.
//
// The trail is the product's tamper-evident record of who did what (migrations 0014–0016), and this
// file's four TECHNICIAN routes all write to it: attended.create, attended.connect, attended.promote,
// attended.end. Its two PUBLIC routes wrote nothing. That left two holes of different shapes:
//
//   - `POST /attended-sessions/redeem` plants an ephemeral machine into the tenant. The other public
//     route that plants a machine, `POST /enroll/redeem`, records `machine.enroll` with an EMPTY
//     actor — so the same act was audited or not depending on which door it came through.
//   - `POST /attended-sessions/consent` is the CONSENT DECISION, which docs/12 calls the
//     load-bearing rule of the whole feature: no consent, no ticket, no connection. It is the single
//     fact that authorizes a technician to see somebody's desktop, and it left no record at all.
//     "The guest agreed, at this time, under this name" is precisely what a reviewer comes here for.
//
// The actor is deliberately EMPTY on both, matching handleRedeemEnrollment: the guest is not a
// principal, and attributing their action to the technician who opened the session would put a
// claim in the trail that is not true.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// auditActions returns the tenant's trail as action→event, failing if an action is recorded twice
// (which would make "the event exists" true for the wrong reason).
func auditActions(t *testing.T, srv *Server, tenantID string) map[string]MgmtAuditEvent {
	t.Helper()
	events, err := srv.MgmtAudit.ListEvents(context.Background(), tenantID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	out := make(map[string]MgmtAuditEvent, len(events))
	for _, e := range events {
		if _, dup := out[e.Action]; dup {
			t.Fatalf("action %q recorded more than once", e.Action)
		}
		out[e.Action] = e
	}
	return out
}

func TestAttendedGuestTransitionsAreAudited(t *testing.T) {
	srv, _ := newAttendedServer(t)
	const tenant = "00000000-0000-0000-0000-0000000000bb"
	const technician = "00000000-0000-0000-0000-0000000000aa"

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("premise not met: create = %d, want 201", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("premise not met: redeem = %d, want 201", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("premise not met: consent = %d, want 200", code)
	}

	trail := auditActions(t, srv, tenant)

	// The technician's own transition is the control: it proves the store is wired and the tenant id
	// is the one being read, so a missing guest event below is a missing event and not a missing store.
	create, ok := trail["attended.create"]
	if !ok {
		t.Fatalf("premise not met: attended.create absent; trail = %v", actionsOf(trail))
	}
	if create.ActorUserID != technician {
		t.Fatalf("attended.create actor = %q, want the technician %q", create.ActorUserID, technician)
	}

	redeem, ok := trail["attended.redeem"]
	if !ok {
		t.Fatalf("the guest's redemption is not on the audit trail (trail = %v) — it plants an "+
			"ephemeral machine into the tenant, exactly as POST /enroll/redeem does, and that one "+
			"records machine.enroll", actionsOf(trail))
	}
	if redeem.ActorUserID != "" {
		t.Errorf("attended.redeem actor = %q, want empty — the guest is not a principal and the "+
			"technician did not do this", redeem.ActorUserID)
	}
	// Targets the SESSION, not the machine, matching this file's other four events — the ephemeral
	// machine is named by device_id in the metadata below. (`machine.enroll` targets the machine
	// because a permanently enrolled machine is the durable object there; here the session is.)
	if redeem.TargetKind != "attended_session" || redeem.TargetID != created.Session.ID {
		t.Errorf("attended.redeem target = %s/%q, want attended_session/%s",
			redeem.TargetKind, redeem.TargetID, created.Session.ID)
	}
	if got := metaString(t, redeem.Metadata, "device_id"); got != redeemed.DeviceID {
		t.Errorf("attended.redeem device_id = %q, want %q", got, redeemed.DeviceID)
	}

	consent, ok := trail["attended.consent"]
	if !ok {
		t.Fatalf("the CONSENT DECISION is not on the audit trail (trail = %v) — it is the fact that "+
			"authorizes a technician to see this desktop", actionsOf(trail))
	}
	if consent.ActorUserID != "" {
		t.Errorf("attended.consent actor = %q, want empty", consent.ActorUserID)
	}
	if consent.TargetKind != "attended_session" || consent.TargetID != created.Session.ID {
		t.Errorf("attended.consent target = %s/%q, want attended_session/%s",
			consent.TargetKind, consent.TargetID, created.Session.ID)
	}
	// The DECISION is the whole point of the record — an event that does not say accept-or-decline
	// would satisfy "the event exists" while answering none of the question a reviewer has.
	if got := metaString(t, consent.Metadata, "decision"); got != "accept" {
		t.Errorf("attended.consent decision = %q, want %q", got, "accept")
	}
	if got := metaString(t, consent.Metadata, "consent_user"); got != "alice" {
		t.Errorf("attended.consent consent_user = %q, want %q", got, "alice")
	}
}

// TestAttendedDeclineIsAudited pins the other decision. A trail that recorded only acceptances
// would read as complete while being systematically incomplete in the one direction that matters
// for a dispute — a guest who says they refused.
func TestAttendedDeclineIsAudited(t *testing.T) {
	srv, _ := newAttendedServer(t)
	const tenant = "00000000-0000-0000-0000-0000000000bb"

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("premise not met: create = %d, want 201", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("premise not met: redeem = %d, want 201", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"decline","consent_user":"bob"}`, nil); code != http.StatusOK {
		t.Fatalf("premise not met: decline = %d, want 200", code)
	}

	trail := auditActions(t, srv, tenant)
	consent, ok := trail["attended.consent"]
	if !ok {
		t.Fatalf("a DECLINED consent left no audit event (trail = %v)", actionsOf(trail))
	}
	if got := metaString(t, consent.Metadata, "decision"); got != "decline" {
		t.Errorf("declined consent recorded decision = %q, want %q", got, "decline")
	}
}

func actionsOf(trail map[string]MgmtAuditEvent) []string {
	out := make([]string, 0, len(trail))
	for a := range trail {
		out = append(out, a)
	}
	return out
}

func metaString(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("audit metadata is not an object (%s): %v", raw, err)
	}
	s, _ := m[key].(string)
	return s
}
