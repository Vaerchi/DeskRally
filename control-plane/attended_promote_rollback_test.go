package controlplane

// An attended promotion that cannot be AUDITED must not still hand the guest a live enrollment token.
//
// PREMISE, declared locally: `handlePromoteAttended` does three things in order — mint an enrollment
// token, STASH it where the guest collects it on its next `/status` poll, then record
// `attended.promote`. Only the third can fail after the guest-visible effect already exists. A bare
// 500 therefore tells the technician the promotion failed while the token travels to the guest
// anyway, and a permanent unattended agent joins the group with nothing on the management trail.
//
// This is not a hypothetical failure mode: the per-tenant audit chain takes an advisory lock with a
// BOUNDED wait, so a busy tenant can genuinely time out on the append.
//
// The rule already exists in this codebase — `HandleIssuePasswordReset` mints a credential token and,
// when the audit event cannot be written, REVOKES it before returning 500, with a comment saying
// exactly why ("the caller would be told the mint failed while a live takeover link sat in the
// database"). This handler is the same shape and did not compensate. Pinning it here so the pair
// cannot drift apart again.

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// auditFailsAfterN wraps a real store and starts failing RecordEvent from the nth call onward, so a
// test can let the setup calls (e.g. attended.create) succeed and fail only the one under test.
type auditFailsAfterN struct {
	MgmtAuditStore
	calls    int
	failFrom int
}

func (a *auditFailsAfterN) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	a.calls++
	if a.calls >= a.failFrom {
		return errors.New("injected: mgmt audit chain unavailable")
	}
	return a.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

func TestPromoteRollsBackTheEnrollmentTokenWhenItCannotBeAudited(t *testing.T) {
	srv, _ := newAttendedServer(t)
	real := srv.MgmtAudit

	// Create the session with auditing healthy (create itself records attended.create).
	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"promote rollback"}`, &created); code != http.StatusCreated {
		t.Fatalf("premise not met: create = %d, want 201", code)
	}

	// Negative control FIRST: with auditing healthy, promote SUCCEEDS and the guest is handed a
	// token. Without this leg a handler that refused every promote would satisfy the assertions below.
	consentPromotionFixture(t, srv, created)
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/promote", `{}`, nil); code != http.StatusOK {
		t.Fatalf("premise not met: healthy promote = %d, want 200", code)
	}
	sess, err := srv.Attended.Get(context.Background(), "00000000-0000-0000-0000-0000000000bb", created.Session.ID)
	if err != nil {
		t.Fatalf("get after healthy promote: %v", err)
	}
	if sess.PromoteToken == "" {
		t.Fatalf("premise not met: a healthy promote did not stash a token for the guest")
	}

	// A second session, this time with the audit append failing on the promote.
	var second attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"promote rollback 2"}`, &second); code != http.StatusCreated {
		t.Fatalf("create 2 = %d, want 201", code)
	}
	consentPromotionFixture(t, srv, second)
	srv.MgmtAudit = &auditFailsAfterN{MgmtAuditStore: real, failFrom: 1}

	code := apiJSON(t, srv, "POST", "/attended-sessions/"+second.Session.ID+"/promote", `{}`, nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("promote with a failing audit = %d, want 500", code)
	}

	// The measurement: the guest must NOT be able to collect a token from that session.
	after, err := srv.Attended.Get(context.Background(), "00000000-0000-0000-0000-0000000000bb", second.Session.ID)
	if err != nil {
		t.Fatalf("get after failed promote: %v", err)
	}
	if after.PromoteToken != "" {
		t.Fatalf("SECURITY: an unauditable promote still stashed a live enrollment token for the guest (%q)",
			after.PromoteToken)
	}
}
