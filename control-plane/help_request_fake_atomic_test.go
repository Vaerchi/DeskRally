package controlplane

// Review r2 #6: the in-memory fake must be as atomic as the Postgres transaction it stands in for. Each
// transition below has its audit write FAULT-INJECTED; afterwards no partial state may survive: the request is
// unchanged, no session was admitted, no audit row remains, and the call can simply be repeated.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// faultyAudit fails the audit write of one action while armed. It embeds the in-memory store, so the
// fake's rollback hook (discardEvents) is still reachable through it.
type faultyAudit struct {
	*InMemoryMgmtAuditStore
	action atomic.Value // string
}

var errInjectedAudit = errors.New("injected audit failure")

func (f *faultyAudit) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if a, _ := f.action.Load().(string); a != "" && e.Action == a {
		return errInjectedAudit
	}
	return f.InMemoryMgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

// appendBatch applies the injected failure to every event of the batch before anything is committed (the
// embedded store's promoted appendBatch would otherwise bypass RecordEvent above).
func (f *faultyAudit) appendBatch(ctx context.Context, tenantID string, events []*MgmtAuditEvent) error {
	if a, _ := f.action.Load().(string); a != "" {
		for _, e := range events {
			if e.Action == a {
				return errInjectedAudit
			}
		}
	}
	return f.InMemoryMgmtAuditStore.appendBatch(ctx, tenantID, events)
}

func (f *faultyAudit) arm(action string) { f.action.Store(action) }

func newFaultyHelpEnv(t *testing.T) (*helpEnv, *faultyAudit) {
	t.Helper()
	e := newFakeHelpEnv(t)
	fa := &faultyAudit{InMemoryMgmtAuditStore: e.audit.(*InMemoryMgmtAuditStore)}
	e.audit = fa
	e.store = NewInMemoryHelpRequestStore(e.machines, e.sessions, fa)
	return e, fa
}

func TestHelpFakeIsAtomicUnderAuditFailure(t *testing.T) {
	ctx := context.Background()
	state := func(t *testing.T, e *helpEnv, tenant, id string, at time.Time) string {
		t.Helper()
		v, _, err := e.store.Get(ctx, tenant, id, at)
		if err != nil {
			t.Fatal(err)
		}
		return v.Status
	}

	t.Run("create", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		fa.arm(AuditHelpRequested)
		if _, err := e.store.CreateForDevice(ctx, tenant, dev, "op", "n", helpT0); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		if cur, _ := e.store.CurrentForDevice(ctx, tenant, dev, helpT0); cur.Request != nil {
			t.Fatalf("a request survived its failed audit: %+v", cur.Request)
		}
		fa.arm("")
		// the op ledger kept nothing either: the retry CREATES, it does not replay a ghost
		if r := mustCreate(t, e, tenant, dev, "op", helpT0); !r.Created {
			t.Fatalf("retry = %+v", r)
		}
		if n := auditCount(t, e, tenant, AuditHelpRequested, ""); n != 1 {
			t.Fatalf("help.requested rows = %d, want 1", n)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		fa.arm(AuditHelpCancelled)
		if _, err := e.store.CancelForDevice(ctx, tenant, dev, r.ID, helpT0.Add(time.Minute)); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		if got := state(t, e, tenant, r.ID, helpT0.Add(time.Minute)); got != HelpStatusOpen {
			t.Fatalf("request = %s after a failed cancel audit", got)
		}
		fa.arm("")
		if c, err := e.store.CancelForDevice(ctx, tenant, dev, r.ID, helpT0.Add(2*time.Minute)); err != nil || !c.Changed {
			t.Fatalf("retry = %+v %v", c, err)
		}
		if n := auditCount(t, e, tenant, AuditHelpCancelled, r.ID); n != 1 {
			t.Fatalf("help.cancelled rows = %d, want 1", n)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		late := helpT0.Add(31 * time.Minute)
		fa.arm(AuditHelpExpired)
		if _, _, err := e.store.ListOpen(ctx, tenant, late); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		fa.arm("")
		// the failed expiry rolled back, so the next call performs it exactly once, with its audit row
		if got := state(t, e, tenant, r.ID, late); got != HelpStatusExpired {
			t.Fatalf("after the retry the request is %s", got)
		}
		if n := auditCount(t, e, tenant, AuditHelpExpired, r.ID); n != 1 {
			t.Fatalf("help.expired rows = %d, want exactly 1", n)
		}
	})

	t.Run("accept", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		fa.arm(AuditHelpAccepted)
		if _, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute))); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		if got := state(t, e, tenant, r.ID, helpT0.Add(time.Minute)); got != HelpStatusOpen {
			t.Fatalf("request = %s after a failed accept audit", got)
		}
		if n := openSessions(t, e, tenant, mid); n != 0 {
			t.Fatalf("%d session(s) admitted by an accept that failed: a ghost seat", n)
		}
		fa.arm("")
		if acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(2*time.Minute))); err != nil || acc.Outcome != HelpAcceptAccepted {
			t.Fatalf("retry = %+v %v", acc, err)
		}
		if n := openSessions(t, e, tenant, mid); n != 1 {
			t.Fatalf("open sessions = %d, want 1", n)
		}
	})

	t.Run("reopen", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
		if err != nil || acc.Outcome != HelpAcceptAccepted {
			t.Fatal(acc, err)
		}
		fa.arm(AuditHelpReopened)
		if _, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute)); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		v, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(2*time.Minute))
		if v.Status != HelpStatusAccepted || v.SessionID != acc.Record.ID || v.AcceptedBy != tech {
			t.Fatalf("a failed reopen left %+v", v.HelpRequest)
		}
		fa.arm("")
		if re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(3*time.Minute)); err != nil || !re.Changed || re.Request.Status != HelpStatusOpen {
			t.Fatalf("retry = %+v %v", re, err)
		}
	})

	t.Run("cancel for machine", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, _ := e.newTenant(t)
		dev, mid := e.newMachine(t, tenant, e.newGroup(t, tenant))
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		fa.arm(AuditHelpCancelled)
		if _, err := e.store.CancelForMachine(ctx, tenant, mid, HelpCancelRetired, helpT0.Add(time.Minute)); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		if got := state(t, e, tenant, r.ID, helpT0.Add(time.Minute)); got != HelpStatusOpen {
			t.Fatalf("request = %s after a failed machine-cancel audit", got)
		}
		fa.arm("")
		if res, err := e.store.CancelForMachine(ctx, tenant, mid, HelpCancelRetired, helpT0.Add(2*time.Minute)); err != nil || len(res.Events) != 1 {
			t.Fatalf("retry = %+v %v", res, err)
		}
	})

	t.Run("create after a lazy expiry: the expiry's audit row is rolled back with it", func(t *testing.T) {
		e, fa := newFaultyHelpEnv(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		d1, _ := e.newMachine(t, tenant, g)
		d2, _ := e.newMachine(t, tenant, g)
		old := mustCreate(t, e, tenant, d1, "op", helpT0).Request
		late := helpT0.Add(31 * time.Minute)
		fa.arm(AuditHelpRequested) // help.expired (old) is written first, then help.requested fails
		if _, err := e.store.CreateForDevice(ctx, tenant, d2, "op", "", late); !errors.Is(err, errInjectedAudit) {
			t.Fatalf("err = %v", err)
		}
		if n := auditCount(t, e, tenant, AuditHelpExpired, old.ID); n != 0 {
			t.Fatalf("help.expired rows = %d: the half-done transaction left an audit row for a transition that rolled back", n)
		}
		fa.arm("")
		if _, err := e.store.CreateForDevice(ctx, tenant, d2, "op", "", late); err != nil {
			t.Fatal(err)
		}
		if n := auditCount(t, e, tenant, AuditHelpExpired, old.ID); n != 1 {
			t.Fatalf("help.expired rows = %d after the retry, want exactly 1", n)
		}
	})
}
