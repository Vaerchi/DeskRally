package controlplane

// Successful console authentication — and its deliberate end — must reach the management trail.
//
// PREMISE, declared locally: this product hands a technician the keyboard of somebody else's
// machine. "Who could have been at the console, and when" is the first question asked after an
// incident, and the tamper-evident per-tenant chain is where it must be answerable. The trail
// already records `auth.login_failed`, `auth.password_changed`, `totp.enroll` and `totp.confirm`.
//
// So the gap was not "nothing is audited here" — it is that only the FAILURES were. An attacker who
// guesses a password wrong twice and right once leaves two records of trying and none of arriving,
// and the successful session is then invisible until it starts a remote session. That asymmetry is
// the bug: a trail that logs rejections but not admissions inverts what it is for.
//
// Logout matters for the same reason and is cheaper to justify: it is the only event that bounds a
// session's window from the other end. Without it "logged in at 02:00" has no closing bracket.
//
// Both are recorded with the SAME actor convention as their neighbours: the successful events name
// the user (they authenticated — attribution is now provable), whereas `auth.login_failed`
// deliberately leaves the actor empty so an attacker cannot write another user's trail by guessing
// at their email.

import (
	"context"
	"net/http"
	"testing"
)

func TestSuccessfulLoginAndLogoutAreAudited(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "the-real-password", RoleTechnician)
	f.srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	f.auth.MgmtAudit = f.srv.MgmtAudit
	h := f.srv.Handler()

	// Negative control FIRST: a FAILED login is audited, and audited without an actor. Without this
	// leg a fixture whose audit store was simply not wired would satisfy the assertions below.
	bad := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "guess"}
	if rec := doJSON(t, h, "POST", "/auth/login", bad, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("premise not met: bad login = %d, want 401", rec.Code)
	}
	events, err := f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 || events[0].Action != "auth.login_failed" {
		t.Fatalf("premise not met: after a failed login the trail is %+v, want one auth.login_failed", events)
	}

	// The measurement: a SUCCESSFUL login.
	good := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "the-real-password"}
	rec := doJSON(t, h, "POST", "/auth/login", good, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("premise not met: good login = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	events, err = f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var login *MgmtAuditEvent
	for i := range events {
		if events[i].Action == "auth.login" {
			login = &events[i]
		}
	}
	if login == nil {
		t.Fatalf("AUDIT GAP: a successful login wrote no auth.login event; trail = %+v", actions(events))
	}
	// Attribution is the point: unlike the failure event, this one CAN name the user, because the
	// user proved who they were. An actor-less success record would not answer "who was at the
	// console", which is the whole reason for the event.
	if login.ActorUserID != "u1" {
		t.Fatalf("auth.login actor = %q, want the authenticated user u1 (event %+v)", login.ActorUserID, *login)
	}

	// And the closing bracket, driven with the real session + CSRF pair the login just issued.
	sessCookie := sessionCookieFrom(rec)
	csrfCookie, csrfToken := csrfFrom(t, rec)
	logoutRec := doJSONWith(t, h, "POST", "/auth/logout", nil, csrfToken, sessCookie, csrfCookie)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204 (body %s)", logoutRec.Code, logoutRec.Body.String())
	}
	events, err = f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "auth.logout" && e.ActorUserID == "u1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("AUDIT GAP: logout wrote no auth.logout event for u1; trail = %+v", actions(events))
	}
}

func actions(events []MgmtAuditEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action+"/"+e.ActorUserID)
	}
	return out
}
