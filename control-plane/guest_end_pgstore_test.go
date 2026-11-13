package controlplane

// Real rmt_app transactions exercise RLS and the UPDATE recheck after a competing commit.
import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestPgGuestEndContract(t *testing.T) {
	f := newToolboxFixture(t)
	ctx := context.Background()
	const device = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	const otherDevice = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	group, _ := seedGroupMachine(t, f.su, f.tenant, device)
	otherGroup, _ := seedGroupMachine(t, f.su, f.tenant, otherDevice)
	var machine, otherMachine string
	if err := f.su.QueryRow(ctx, `SELECT id::text FROM machine WHERE tenant_id = $1 AND group_id = $2`, f.tenant, group).Scan(&machine); err != nil {
		t.Fatal(err)
	}
	if err := f.su.QueryRow(ctx, `SELECT id::text FROM machine WHERE tenant_id = $1 AND group_id = $2`, f.tenant, otherGroup).Scan(&otherMachine); err != nil {
		t.Fatal(err)
	}
	records := NewPgSessionRecordStore(f.app)
	audit := NewPgMgmtAuditStore(f.app)
	store := NewPgGuestEndStore(f.app, audit)
	start := func(machine string) *SessionRecord {
		t.Helper()
		r := &SessionRecord{MachineID: machine, TechnicianID: f.owner, ConsentPolicy: "none", GrantedCaps: []string{}}
		if err := records.StartSession(ctx, f.tenant, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	call := func(tenant, id, device string, want GuestEndOutcome) {
		t.Helper()
		got, err := store.EndSessionForDevice(ctx, tenant, id, device, time.Now().UTC(), SessionEndReport{Reason: EndReasonGuestEnded})
		if err != nil || got != want {
			t.Fatalf("end = %s, %v; want %s", got, err, want)
		}
	}
	wantReason, wantQueueAge := "guest_ended", ""
	checkAudit := func(id, machine string, want int) {
		t.Helper()
		events, err := audit.ListEvents(ctx, f.tenant, 1000)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range events {
			if e.TargetID != id || e.Action != "session.end" {
				continue
			}
			n++
			if e.ActorUserID != "" || e.TargetKind != "session" {
				t.Fatalf("audit = %+v", e)
			}
			var meta map[string]string
			if err := json.Unmarshal(e.Metadata, &meta); err != nil {
				t.Fatal(err)
			}
			wantMeta := map[string]string{"actor_kind": "device", "device_id": device, "reason": wantReason, "via": "signaling", "machine_id": machine, "observed_by": "agent_report"}
			if wantQueueAge != "" {
				wantMeta["queue_age_ms"] = wantQueueAge
			}
			if len(meta) != len(wantMeta) {
				t.Fatalf("metadata = %v", meta)
			}
			for k, v := range wantMeta {
				if meta[k] != v {
					t.Fatalf("metadata %s = %q, want %q", k, meta[k], v)
				}
			}
		}
		if n != want {
			t.Fatalf("audit count = %d, want %d", n, want)
		}
	}
	checkEnded := func(id string, want bool) *SessionRecord {
		t.Helper()
		r, err := records.GetSession(ctx, f.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if (r.EndedAt != nil) != want {
			t.Fatalf("ended_at = %v, want ended %v", r.EndedAt, want)
		}
		return r
	}
	own := start(machine)
	call(f.tenant, own.ID, device, GuestEndEnded)
	first := checkEnded(own.ID, true)
	checkAudit(own.ID, machine, 1)
	call(f.tenant, own.ID, device, GuestEndAlreadyEnded)
	second := checkEnded(own.ID, true)
	if !first.EndedAt.Equal(*second.EndedAt) {
		t.Fatal("duplicate changed end time")
	}
	checkAudit(own.ID, machine, 1)
	// docs/49: a generalised agent report carries its reason into the same audited transition.
	leased := start(machine)
	age := int64(4321)
	if got, err := store.EndSessionForDevice(ctx, f.tenant, leased.ID, device, time.Now().UTC(), SessionEndReport{Reason: EndReasonLeaseLapsed, QueueAgeMs: &age}); err != nil || got != GuestEndEnded {
		t.Fatalf("lease_lapsed end = %s, %v", got, err)
	}
	checkEnded(leased.ID, true)
	wantReason, wantQueueAge = "lease_lapsed", "4321"
	checkAudit(leased.ID, machine, 1)
	wantReason, wantQueueAge = "guest_ended", ""
	wrong := start(otherMachine)
	call(f.tenant, wrong.ID, device, GuestEndOtherDevice)
	checkEnded(wrong.ID, false)
	checkAudit(wrong.ID, otherMachine, 0)
	// The same real record is invisible when the transaction is pinned to another tenant.
	call(f.other, wrong.ID, device, GuestEndNotFound)
	checkEnded(wrong.ID, false)
	call(f.tenant, "not-a-uuid", device, GuestEndNotFound)
	admin := start(machine)
	if _, err := records.EndSession(ctx, f.tenant, admin.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	call(f.tenant, admin.ID, device, GuestEndAlreadyEnded)
	checkAudit(admin.ID, machine, 0)
	concurrent := start(machine)
	at := time.Now().UTC()
	var wg sync.WaitGroup
	ready := make(chan struct{})
	type result struct {
		outcome GuestEndOutcome
		err     error
	}
	results := make(chan result, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			outcome, err := store.EndSessionForDevice(ctx, f.tenant, concurrent.ID, device, at, SessionEndReport{Reason: EndReasonGuestEnded})
			results <- result{outcome, err}
		}()
	}
	close(ready)
	wg.Wait()
	close(results)
	counts := map[GuestEndOutcome]int{}
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		counts[r.outcome]++
	}
	if counts[GuestEndEnded] != 1 || counts[GuestEndAlreadyEnded] != 7 {
		t.Fatalf("concurrent outcomes = %v", counts)
	}
	checkAudit(concurrent.ID, machine, 1)
	// GetSession is the persisted ended state consumed by subsequent renewal authorization.
	checkEnded(concurrent.ID, true)

	// AUDIT FAILURE ROLLS THE END BACK (Codex impl review): hold the tenant's audit-chain lock on
	// another connection so appendTx times out INSIDE the guest-end transaction. The record must stay
	// open with no audit row, and the agent's retry must then end it with exactly one.
	t.Run("audit failure rolls back and the retry audits once", func(t *testing.T) {
		prev := mgmtAuditLockWait
		mgmtAuditLockWait = 300 * time.Millisecond
		defer func() { mgmtAuditLockWait = prev }()
		rec := start(machine)
		holder, err := f.su.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		htx, err := holder.Begin(ctx)
		if err != nil {
			holder.Release()
			t.Fatal(err)
		}
		if _, err := htx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mgmt_audit_chain:' || $1, 0))`,
			canonicalUUIDish(f.tenant)); err != nil {
			t.Fatal(err)
		}
		if got, err := store.EndSessionForDevice(ctx, f.tenant, rec.ID, device, time.Now().UTC(), SessionEndReport{Reason: EndReasonGuestEnded}); err == nil {
			t.Fatalf("end with the audit chain locked = %s, nil; want an error", got)
		}
		checkEnded(rec.ID, false)
		checkAudit(rec.ID, machine, 0)
		_ = htx.Rollback(ctx)
		holder.Release()
		call(f.tenant, rec.ID, device, GuestEndEnded)
		checkEnded(rec.ID, true)
		checkAudit(rec.ID, machine, 1)
	})

	// An ADMIN end racing the guest end: whichever commits first ends the record; a guest audit row
	// exists exactly when the guest call reports `ended`, and never when the admin won.
	t.Run("admin end racing guest end", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			rec := start(machine)
			var wg sync.WaitGroup
			ready := make(chan struct{})
			var guestOutcome GuestEndOutcome
			var guestErr, adminErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-ready
				guestOutcome, guestErr = store.EndSessionForDevice(ctx, f.tenant, rec.ID, device, time.Now().UTC(), SessionEndReport{Reason: EndReasonGuestEnded})
			}()
			go func() {
				defer wg.Done()
				<-ready
				_, adminErr = records.EndSession(ctx, f.tenant, rec.ID, time.Now().UTC())
			}()
			close(ready)
			wg.Wait()
			if guestErr != nil || adminErr != nil {
				t.Fatalf("race %d: guest %v, admin %v", i, guestErr, adminErr)
			}
			checkEnded(rec.ID, true)
			switch guestOutcome {
			case GuestEndEnded:
				checkAudit(rec.ID, machine, 1)
			case GuestEndAlreadyEnded:
				checkAudit(rec.ID, machine, 0)
			default:
				t.Fatalf("race %d: guest outcome %s", i, guestOutcome)
			}
		}
	})
}
