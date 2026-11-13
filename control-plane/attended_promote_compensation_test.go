package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The promote compensation must survive a technician who closes the tab at the wrong moment. On the
// real deployment a client disconnect cancels r.Context() AND closes the request's pinned tenant
// connection, so the audit append fails and, if the compensation ran on r.Context(), un-stashing the
// token failed too: the guest would collect a live, UNAUDITED enrollment token. These wrappers make
// the in-memory stores refuse a cancelled context the way the Postgres ones do.

type ctxHonoringAttended struct{ AttendedStore }

func (a ctxHonoringAttended) SetPromoteToken(ctx context.Context, tenantID, id, plaintext string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.AttendedStore.SetPromoteToken(ctx, tenantID, id, plaintext)
}

type ctxHonoringEnrollment struct{ EnrollmentTokenStore }

func (e ctxHonoringEnrollment) RevokeToken(ctx context.Context, tenantID, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.EnrollmentTokenStore.RevokeToken(ctx, tenantID, id)
}

// cancelThenFailAudit simulates the disconnect landing on the audit append: it cancels the request and
// fails, exactly when the promote token is already stashed for the guest.
type cancelThenFailAudit struct {
	MgmtAuditStore
	cancel context.CancelFunc
}

func (a cancelThenFailAudit) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if e != nil && e.Action == "attended.promote" {
		a.cancel()
		return errors.New("injected: client disconnected during the audit append")
	}
	return a.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

func TestPromoteCompensationSurvivesAClientDisconnect(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Attended = ctxHonoringAttended{AttendedStore: srv.Attended}
	srv.EnrollmentTokens = ctxHonoringEnrollment{EnrollmentTokenStore: srv.EnrollmentTokens}

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+attendTestGroup+`","reason":"promote disconnect"}`, &created); code != http.StatusCreated {
		t.Fatalf("premise not met: create = %d, want 201", code)
	}
	consentPromotionFixture(t, srv, created)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.MgmtAudit = cancelThenFailAudit{MgmtAuditStore: srv.MgmtAudit, cancel: cancel}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/attended-sessions/"+created.Session.ID+"/promote", strings.NewReader(`{}`)).WithContext(ctx)
	srv.Handler().ServeHTTP(w, r)
	if w.Code >= 200 && w.Code < 300 {
		t.Fatalf("an unauditable promote succeeded: %d %s", w.Code, w.Body.String())
	}

	after, err := srv.Attended.Get(context.Background(), "00000000-0000-0000-0000-0000000000bb", created.Session.ID)
	if err != nil {
		t.Fatalf("get after failed promote: %v", err)
	}
	if after.PromoteToken != "" {
		t.Fatalf("SECURITY: a promote whose client disconnected left a live, unaudited token stashed for the guest (%q)",
			after.PromoteToken)
	}
	// And the minted enrollment token is inert even if it had already been read.
	toks, err := srv.EnrollmentTokens.ListTokens(context.Background(), "00000000-0000-0000-0000-0000000000bb")
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) == 0 {
		t.Fatal("premise not met: the promote minted no enrollment token")
	}
	for _, tok := range toks {
		if !tok.Revoked {
			t.Fatalf("SECURITY: enrollment token %s minted by the failed promote is still live", tok.ID)
		}
	}
}
