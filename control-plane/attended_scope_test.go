package controlplane

// GET /attended-sessions/{id} must scope to the SESSION'S GROUP, not merely to the tenant.
//
// The rule this restores is stated all over this service: a machine's group is what every
// downstream authorization check scopes against, so a group-scoped admin must not reach a machine —
// or a session on one — in a group they hold no rights over. Every neighbour of this handler
// already obeys it. /attended-sessions/{id}/connect, /promote and /end each resolve the session and
// then gate on `sess.GroupID`; POST /attended-sessions gates on the requested group; the machine
// twin of this very endpoint, GET /machines/{id}, resolves the machine and gates on `m.GroupID`;
// and both list endpoints filter with AllowsInGroup.
//
// This one handler checked `Require(CapViewSessions)` — the tenant-wide form — and then returned the
// record. So the pattern to notice is not a missing defence but an UNAPPLIED one: the group check
// exists, is used by four sibling handlers in the same file, and this route simply did not make it.
//
// What it hands over is the whole AttendedSession: the group, the technician who opened it, the
// ephemeral device, the state, and `reason` — free text a technician typed about somebody's machine
// ("payroll escalation" below stands in for the real thing). A uuid is needed to ask, but id secrecy
// is not the boundary here; group membership is, which is exactly why the other four check it.

import (
	"net/http"
	"strings"
	"testing"
)

// attendedServerAs returns a second server over base's stores, authenticating as p — the way to put
// a differently-scoped caller in front of the same attended session.
func attendedServerAs(base *Server, p *Principal) *Server {
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Machines = base.Machines
	srv.SessionRecords = base.SessionRecords
	srv.MgmtAudit = base.MgmtAudit
	srv.EnrollmentTokens = base.EnrollmentTokens
	srv.Attended = base.Attended
	srv.Grants = base.Grants
	return srv
}

func TestGetAttendedIsScopedToTheSessionsGroup(t *testing.T) {
	owner, _ := newAttendedServer(t)
	const tenant = "00000000-0000-0000-0000-0000000000bb"
	const otherGroup = "00000000-0000-0000-0000-0000000000dd"
	const secret = "payroll escalation"

	// The owner opens one session in each group.
	var theirs, mine attendedCreateResp
	if code := apiJSON(t, owner, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"`+secret+`"}`, &theirs); code != http.StatusCreated {
		t.Fatalf("premise not met: create in group cc = %d, want 201", code)
	}
	if code := apiJSON(t, owner, "POST", "/attended-sessions",
		`{"group_id":"`+otherGroup+`","reason":"routine"}`, &mine); code != http.StatusCreated {
		t.Fatalf("premise not met: create in group dd = %d, want 201", code)
	}

	// A technician scoped to otherGroup ONLY. RoleTechnician holds CapViewSessions (rbac.go), so a
	// denial below is provably the GROUP check rather than a missing capability — and the assertion
	// on the error text pins that distinction rather than trusting the status code alone.
	const techID = "00000000-0000-0000-0000-0000000000ee"
	scoped := attendedServerAs(owner, &Principal{
		UserID:   techID,
		TenantID: tenant,
		Grant:    NewGrant(techID, tenant, NewMembership(RoleTechnician, Groups(otherGroup))),
	})

	// Negative control FIRST: the caller can read the session in its own group. Without this leg a
	// handler that denied every read would satisfy the assertion below.
	var own struct {
		Session AttendedSession `json:"session"`
	}
	if code := apiJSON(t, scoped, "GET", "/attended-sessions/"+mine.Session.ID, "", &own); code != http.StatusOK {
		t.Fatalf("premise not met: reading a session in the caller's OWN group = %d, want 200", code)
	}
	if own.Session.ID != mine.Session.ID {
		t.Fatalf("own-group read returned %+v, want session %s", own.Session, mine.Session.ID)
	}

	// THE DEFECT.
	var leaked struct {
		Session AttendedSession `json:"session"`
		Error   string          `json:"error"`
	}
	code := apiJSON(t, scoped, "GET", "/attended-sessions/"+theirs.Session.ID, "", &leaked)
	if code != http.StatusForbidden {
		t.Fatalf("reading a session in a group the caller has no rights over = %d, want 403 — "+
			"the tenant is not the boundary here, the group is (session %+v)", code, leaked.Session)
	}
	if leaked.Session.ID != "" || leaked.Session.Reason != "" {
		t.Fatalf("the refused response still carried the record: %+v", leaked.Session)
	}
	if strings.Contains(strings.ToLower(leaked.Error), strings.ToLower(secret)) {
		t.Fatalf("the denial echoed the session's reason: %q", leaked.Error)
	}
	// Naming the group is what distinguishes "not in your scope" from "you lack the capability" —
	// this caller HAS CapViewSessions, so a capability-shaped denial would mean the wrong check ran.
	if !strings.Contains(leaked.Error, attendTestGroup) {
		t.Fatalf("denial %q does not name the out-of-scope group %s, so it is not the group check",
			leaked.Error, attendTestGroup)
	}

	// The family invariant this restores: the sibling routes were already scoped, and GET now matches
	// them. RoleTechnician holds CapEndSession too, so this is the same group-shaped denial.
	var ended struct {
		Error string `json:"error"`
	}
	if code := apiJSON(t, scoped, "POST", "/attended-sessions/"+theirs.Session.ID+"/end", "", &ended); code != http.StatusForbidden {
		t.Fatalf("ending an out-of-scope session = %d, want 403", code)
	}
	if !strings.Contains(ended.Error, attendTestGroup) {
		t.Fatalf("sibling denial %q does not name the group", ended.Error)
	}
}
