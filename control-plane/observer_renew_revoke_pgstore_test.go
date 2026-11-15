package controlplane

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Against real Postgres under RLS: a control session whose holder's start_session was removed is
// refused its next lease, its row is stamped ended, and one session.end / access_revoked audit row
// is committed. A holder who keeps the capability renews as before.
func TestRenewPGEndsAndAuditsWhenHolderLosesStartSession(t *testing.T) {
	f := newObserverPGFixture(t)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	id := control.Session.ID
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions/"+id+"/policy", `{}`, nil); code != http.StatusOK {
		t.Fatalf("renewal while authorized = %d", code)
	}
	var ended bool
	if err := f.su.QueryRow(t.Context(), `SELECT ended_at IS NOT NULL FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, id).Scan(&ended); err != nil || ended {
		t.Fatalf("session must be open after an authorized renewal: ended=%v err=%v", ended, err)
	}

	reduced := f.serverFor(observerCustomPrincipal(f.owner, f.tenant, CapViewMachines, CapViewSessions, CapEndSession))
	if code := apiJSON(t, reduced, "POST", "/sessions/"+id+"/policy", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("renewal after losing start_session = %d, want 403", code)
	}
	if err := f.su.QueryRow(t.Context(), `SELECT ended_at IS NOT NULL FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, id).Scan(&ended); err != nil || !ended {
		t.Fatalf("revoked session must be ended: ended=%v err=%v", ended, err)
	}
	rows := observerAuditMetadata(t, f, "session.end", id)
	if len(rows) != 1 || rows[0]["reason"] != "access_revoked" {
		t.Fatalf("want one session.end audit row with reason access_revoked, got %v", rows)
	}
}

func revokeSessionOpen(t *testing.T, f *toolboxFixture, id string) bool {
	t.Helper()
	var ended bool
	if err := f.su.QueryRow(t.Context(), `SELECT ended_at IS NOT NULL FROM session_record WHERE tenant_id = $1 AND id = $2`, f.tenant, id).Scan(&ended); err != nil {
		t.Fatal(err)
	}
	return !ended
}

func revokeAuditCount(t *testing.T, f *toolboxFixture, id string) int {
	t.Helper()
	n := 0
	for _, m := range observerAuditMetadata(t, f, "session.end", id) {
		if m["reason"] == "access_revoked" {
			n++
		}
	}
	return n
}

// Two renewals racing on the same revoked session: both are refused with 403, exactly ONE audit row.
func TestRenewPGConcurrentRevokedRenewalsWriteOneAudit(t *testing.T) {
	f := newObserverPGFixture(t)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	id := control.Session.ID
	reduced := f.serverFor(observerCustomPrincipal(f.owner, f.tenant, CapViewMachines, CapViewSessions, CapEndSession))
	const racers = 8
	codes := make([]int, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = apiJSON(t, reduced, "POST", "/sessions/"+id+"/policy", `{}`, nil)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusForbidden {
			t.Fatalf("racer %d = %d, want 403 for winner and losers alike", i, c)
		}
	}
	if revokeSessionOpen(t, f, id) {
		t.Fatal("session must be ended")
	}
	if n := revokeAuditCount(t, f, id); n != 1 {
		t.Fatalf("access_revoked audit rows = %d, want exactly 1", n)
	}
}

// A session already ended by a normal end (or the agent's report) is not re-ended or re-attributed:
// the revoked renewal is refused and writes no access_revoked row, and the store-level transition
// reports that it did not end anything.
func TestRenewPGRevokedRenewalAfterNormalEndWritesNoSecondCause(t *testing.T) {
	f := newObserverPGFixture(t)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	id := control.Session.ID
	observerEnd(t, f, id)
	reduced := f.serverFor(observerCustomPrincipal(f.owner, f.tenant, CapViewMachines, CapViewSessions, CapEndSession))
	if code := apiJSON(t, reduced, "POST", "/sessions/"+id+"/policy", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("renewal after normal end = %d, want 403", code)
	}
	if n := revokeAuditCount(t, f, id); n != 0 {
		t.Fatalf("access_revoked rows after a normal end = %d, want 0", n)
	}
	ender := NewPgSessionRecordStore(f.app)
	ended, err := ender.EndOpenSessionWithAudit(t.Context(), f.tenant, id, time.Now().UTC(), NewPgMgmtAuditStore(f.app),
		&MgmtAuditEvent{Action: "session.end", TargetKind: "session", TargetID: id})
	if err != nil || ended {
		t.Fatalf("conditional transition on an ended row = %v, %v; want false, nil", ended, err)
	}
	if n := len(observerAuditMetadata(t, f, "session.end", id)); n != 0 {
		t.Fatalf("a loser wrote %d audit rows", n)
	}
}

// An audit failure rolls the END back: the session stays open, and the next renewal ends and audits it.
func TestRenewPGAuditFailureRollsBackTheEnd(t *testing.T) {
	f := newObserverPGFixture(t)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	id := control.Session.ID
	mustExec(t, f.su, `CREATE FUNCTION pg_temp_fail_end() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.action = 'session.end' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, f.su, `CREATE TRIGGER fail_session_end_audit BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION pg_temp_fail_end()`)
	dropped := false
	drop := func() {
		if !dropped {
			dropped = true
			mustExec(t, f.su, `DROP TRIGGER fail_session_end_audit ON audit_event`)
			mustExec(t, f.su, `DROP FUNCTION pg_temp_fail_end()`)
		}
	}
	defer drop()

	reduced := f.serverFor(observerCustomPrincipal(f.owner, f.tenant, CapViewMachines, CapViewSessions, CapEndSession))
	if code := apiJSON(t, reduced, "POST", "/sessions/"+id+"/policy", `{}`, nil); code != http.StatusInternalServerError {
		t.Fatalf("renewal with failing audit = %d, want 500", code)
	}
	if !revokeSessionOpen(t, f, id) {
		t.Fatal("a failed audit must roll the end back: the session must still be open")
	}
	drop()
	if code := apiJSON(t, reduced, "POST", "/sessions/"+id+"/policy", `{}`, nil); code != http.StatusForbidden {
		t.Fatalf("next renewal = %d, want 403", code)
	}
	if revokeSessionOpen(t, f, id) || revokeAuditCount(t, f, id) != 1 {
		t.Fatal("the next renewal must end the session and write exactly one audit row")
	}
}

// The transition itself, raced directly at the store (no handler pre-check in front): of N callers
// exactly one is told it ended the row, and exactly one audit row exists.
func TestRenewPGConditionalEndHasExactlyOneWinner(t *testing.T) {
	f := newObserverPGFixture(t)
	code, control := observerStart(t, f.ownerSrv, "control")
	if code != http.StatusCreated {
		t.Fatalf("control start = %d", code)
	}
	id := control.Session.ID
	store := NewPgSessionRecordStore(f.app)
	audit := NewPgMgmtAuditStore(f.app)
	const racers = 8
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ev := &MgmtAuditEvent{Action: "session.end", TargetKind: "session", TargetID: id, Metadata: []byte(`{"reason":"access_revoked"}`)}
			ended, err := store.EndOpenSessionWithAudit(t.Context(), f.tenant, id, time.Now().UTC(), audit, ev)
			if err != nil {
				t.Errorf("end: %v", err)
			}
			if ended {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if w := winners.Load(); w != 1 {
		t.Fatalf("winners = %d, want 1", w)
	}
	if n := revokeAuditCount(t, f, id); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
}
