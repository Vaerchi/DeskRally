package controlplane

// ONE suite, TWO stores (docs/64 §4: "fake = pg"). runHelpStoreSuite drives the HelpRequestStore contract
// against the in-memory fake (always) and against Postgres as rmt_app (when TEST_DATABASE_URL is set; the
// pg constructor is in help_request_pgstore_test.go). Every guard the contract names has a test whose
// failure was demonstrated by disabling the guard (see the mutation notes in the final report).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// helpEnv is the seam the suite needs from a backend.
type helpEnv struct {
	store    HelpRequestStore
	sessions SessionRecordStore
	audit    MgmtAuditStore
	machines MachineStore
	binder   TenantBinder

	newTenant   func(t *testing.T) (tenant, tech string)
	newTech     func(t *testing.T, tenant string) string
	newGroup    func(t *testing.T, tenant string) string
	newMachine  func(t *testing.T, tenant, group string) (device, machineID string)
	setStatus   func(t *testing.T, tenant, machineID, status string)
	moveMachine func(t *testing.T, tenant, machineID, group string)
}

func newFakeHelpEnv(t *testing.T) *helpEnv {
	t.Helper()
	ctx := context.Background()
	machines := NewInMemoryMachineStore()
	sessions := NewInMemorySessionRecordStore()
	audit := NewInMemoryMgmtAuditStore()
	return &helpEnv{
		store:    NewInMemoryHelpRequestStore(machines, sessions, audit),
		sessions: sessions,
		audit:    audit,
		machines: machines,
		binder:   NoopBinder{},
		newTenant: func(t *testing.T) (string, string) {
			return newUUID(), newUUID()
		},
		newTech:  func(t *testing.T, tenant string) string { return newUUID() },
		newGroup: func(t *testing.T, tenant string) string { return newUUID() },
		newMachine: func(t *testing.T, tenant, group string) (string, string) {
			m := &Machine{DeviceID: newUUID(), GroupID: group, Name: "host", Pubkey: testPubkeyHex(t)}
			if err := machines.EnrollMachine(ctx, tenant, m); err != nil {
				t.Fatal(err)
			}
			return m.DeviceID, m.ID
		},
		setStatus: func(t *testing.T, tenant, machineID, status string) {
			if err := machines.SetMachineStatus(ctx, tenant, machineID, status); err != nil {
				t.Fatal(err)
			}
		},
		moveMachine: func(t *testing.T, tenant, machineID, group string) {
			if err := machines.SetMachineGroup(ctx, tenant, machineID, group); err != nil {
				t.Fatal(err)
			}
		},
	}
}

func TestHelpStoreContractFake(t *testing.T) { runHelpStoreSuite(t, newFakeHelpEnv) }

// helpClock is a fixed base instant; subtests advance it explicitly so the fake and Postgres share a clock.
var helpT0 = time.Now().UTC().Truncate(time.Microsecond)

func mustCreate(t *testing.T, e *helpEnv, tenant, device, op string, at time.Time) *HelpCreateResult {
	t.Helper()
	r, err := e.store.CreateForDevice(context.Background(), tenant, device, op, "please help", at)
	if err != nil {
		t.Fatalf("create(%s): %v", op, err)
	}
	return r
}

func auditCount(t *testing.T, e *helpEnv, tenant, action, target string) int {
	t.Helper()
	evs, err := e.audit.ListEventsFiltered(context.Background(), tenant, 1000, AuditFilter{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ev := range evs {
		if target == "" || ev.TargetID == target {
			n++
		}
	}
	return n
}

// acceptInput builds the pre-transaction admission a handler would have computed for (machine, tech).
func acceptInput(t *testing.T, requestID, tech, machineID, group, op string, at time.Time) HelpAcceptInput {
	t.Helper()
	return HelpAcceptInput{
		RequestID: requestID, TechnicianID: tech, OpID: op, AdmissionGroupID: group, Now: at,
		Record: &SessionRecord{MachineID: machineID, TechnicianID: tech, GrantedCaps: []string{}, Access: "control",
			MachineGroupID: group},
		Limits:   SessionStartLimits{GroupID: group},
		Presence: func(string) HelpPresence { return HelpPresenceOnline },
	}
}

func openSessions(t *testing.T, e *helpEnv, tenant, machineID string) int {
	t.Helper()
	recs, err := e.sessions.ListSessions(context.Background(), tenant, SessionSummaryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range recs {
		if r.MachineID == machineID && r.EndedAt == nil {
			n++
		}
	}
	return n
}

func runHelpStoreSuite(t *testing.T, mk func(t *testing.T) *helpEnv) {
	ctx := context.Background()

	t.Run("create: identity row, expiry, note, one audit row", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		raw := "  need \x1b[31mhelp‮\n\twith\x00 printer  " + strings.Repeat("x", 300)
		r, err := e.store.CreateForDevice(ctx, tenant, dev, "op-1", raw, helpT0)
		if err != nil {
			t.Fatal(err)
		}
		q := r.Request
		if !r.Created || r.Replayed || q.Status != HelpStatusOpen || q.MachineID != mid || q.DeviceID != dev || q.GroupID != g {
			t.Fatalf("created = %+v (%+v)", q, r)
		}
		if !q.ExpiresAt.Equal(q.CreatedAt.Add(30 * time.Minute)) {
			t.Fatalf("expiry %v is not created+30m (%v)", q.ExpiresAt, q.CreatedAt)
		}
		if len([]rune(q.Note)) != 200 || !strings.HasPrefix(q.Note, "need [31mhelp  with printer  x") || strings.ContainsAny(q.Note, "\x1b\x00\n\t‮") {
			t.Fatalf("note not normalized: %q (%d runes)", q.Note, len([]rune(q.Note)))
		}
		if n := auditCount(t, e, tenant, AuditHelpRequested, q.ID); n != 1 || len(r.Events) != 1 {
			t.Fatalf("help.requested rows = %d, returned events = %d, want 1/1", n, len(r.Events))
		}
		var meta map[string]any
		if err := json.Unmarshal(r.Events[0].Metadata, &meta); err != nil {
			t.Fatal(err)
		}
		if meta["requested_from"] != "machine" || meta["actor_kind"] != "device" || meta["machine_id"] != mid {
			t.Fatalf("audit metadata = %v", meta)
		}
		if _, leaked := meta["note"]; leaked {
			t.Fatalf("the note's text must not enter the audit row: %v", meta)
		}
	})

	t.Run("create: invalid op ids refused", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		for _, op := range []string{"", strings.Repeat("a", 65), "has space", "semi;colon", "ünï"} {
			if _, err := e.store.CreateForDevice(ctx, tenant, dev, op, "", helpT0); !errors.Is(err, ErrHelpInvalidOp) {
				t.Fatalf("op %q: err = %v, want ErrHelpInvalidOp", op, err)
			}
		}
	})

	t.Run("one open request per machine is idempotent", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		a := mustCreate(t, e, tenant, dev, "op-a", helpT0)
		b := mustCreate(t, e, tenant, dev, "op-b", helpT0.Add(time.Minute))
		if b.Created || !b.Replayed || b.Request.ID != a.Request.ID {
			t.Fatalf("second op while open = %+v, want the first request back", b)
		}
		if !b.Request.ExpiresAt.Equal(a.Request.ExpiresAt) || b.Request.Note != a.Request.Note {
			t.Fatal("a repeated request must refresh nothing")
		}
		if n := auditCount(t, e, tenant, AuditHelpRequested, ""); n != 1 {
			t.Fatalf("help.requested rows = %d, want 1", n)
		}
		// op-a (the creating op) still replays after the cancel; op-b (an already-open return) left no row.
		if _, err := e.store.CancelForDevice(ctx, tenant, dev, a.Request.ID, helpT0.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		c := mustCreate(t, e, tenant, dev, "op-a", helpT0.Add(3*time.Minute))
		if c.Created || c.Request.ID != a.Request.ID || c.Request.Status != HelpStatusCancelled {
			t.Fatalf("replay of op-a after cancel = %+v", c.Request)
		}
	})

	t.Run("op_id dedup lasts 24 hours", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		a := mustCreate(t, e, tenant, dev, "op-x", helpT0)
		if _, err := e.store.CancelForDevice(ctx, tenant, dev, a.Request.ID, helpT0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		within := mustCreate(t, e, tenant, dev, "op-x", helpT0.Add(23*time.Hour))
		if within.Created || within.Request.ID != a.Request.ID {
			t.Fatalf("op replay within 24h = %+v", within)
		}
		after := mustCreate(t, e, tenant, dev, "op-x", helpT0.Add(25*time.Hour))
		if !after.Created || after.Request.ID == a.Request.ID {
			t.Fatalf("op reuse after 24h must create a new request: %+v", after)
		}
	})

	t.Run("ineligible machines and foreign tenants are refused", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		other, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		if _, err := e.store.CreateForDevice(ctx, other, dev, "op", "", helpT0); !errors.Is(err, ErrHelpMachineIneligible) {
			t.Fatalf("another tenant's device: err = %v", err)
		}
		if _, err := e.store.CreateForDevice(ctx, tenant, newUUID(), "op", "", helpT0); !errors.Is(err, ErrHelpMachineIneligible) {
			t.Fatalf("unknown device: err = %v", err)
		}
		for _, st := range []string{MachineStatusRetired, MachineStatusQuarantined} {
			e.setStatus(t, tenant, mid, st)
			if _, err := e.store.CreateForDevice(ctx, tenant, dev, "op-"+st, "", helpT0); !errors.Is(err, ErrHelpMachineIneligible) {
				t.Fatalf("%s machine: err = %v, want ErrHelpMachineIneligible", st, err)
			}
		}
		e.setStatus(t, tenant, mid, MachineStatusActive)
		mustCreate(t, e, tenant, dev, "op-ok", helpT0)
	})

	t.Run("durable per-device budgets: 3/hour, 10/day", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		at := helpT0
		for i := 0; i < 3; i++ {
			r := mustCreate(t, e, tenant, dev, "h"+string(rune('a'+i)), at)
			if _, err := e.store.CancelForDevice(ctx, tenant, dev, r.Request.ID, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Minute)
		}
		_, err := e.store.CreateForDevice(ctx, tenant, dev, "h-over", "", at)
		var le *HelpLimitError
		if !errors.As(err, &le) || le.Scope != helpLimitScopeDevHour || le.RetryAfter <= 0 || le.RetryAfter > time.Hour {
			t.Fatalf("4th in an hour: err = %v (%+v)", err, le)
		}
		// a replayed op does not spend budget and is not refused
		if r := mustCreate(t, e, tenant, dev, "ha", at); r.Created {
			t.Fatal("op replay must not create")
		}
		// the hour rolls off: three more fit in the NEXT hours, up to 10 in the day
		created := 3
		for i := 0; ; i++ {
			at = helpT0.Add(time.Duration(61+i*61) * time.Minute)
			if at.Sub(helpT0) >= 24*time.Hour {
				t.Fatal("never reached the daily limit")
			}
			r, err := e.store.CreateForDevice(ctx, tenant, dev, "d"+string(rune('a'+i)), "", at)
			if err != nil {
				if !errors.As(err, &le) || le.Scope != helpLimitScopeDevDay {
					t.Fatalf("after %d creations: err = %v, want the daily limit", created, err)
				}
				break
			}
			created++
			if _, err := e.store.CancelForDevice(ctx, tenant, dev, r.Request.ID, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		if created != helpDeviceDailyLimit {
			t.Fatalf("created %d in a day, want exactly %d", created, helpDeviceDailyLimit)
		}
	})

	t.Run("every create call is metered: 30/hour, replays and already-open included", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		dev2, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		at := helpT0.Truncate(time.Hour).Add(5 * time.Minute) // inside one UTC hour
		var le *HelpLimitError
		// an op_id replay loop: the first call creates, the next 29 replay it; the 31st is refused
		mustCreate(t, e, tenant, dev, "same-op", at)
		for i := 2; i <= helpDeviceCallsPerHour; i++ {
			if r := mustCreate(t, e, tenant, dev, "same-op", at.Add(time.Duration(i)*time.Second)); r.Created {
				t.Fatalf("call %d created a request", i)
			}
		}
		_, err := e.store.CreateForDevice(ctx, tenant, dev, "same-op", "", at.Add(40*time.Second))
		if !errors.As(err, &le) || le.Scope != helpLimitScopeDevCalls || le.RetryAfter <= 0 || le.RetryAfter > time.Hour {
			t.Fatalf("31st replayed call: err = %v, want the device_calls limit", err)
		}
		// an already-open loop with FRESH op ids: the same budget (and no creation is spent on it)
		mustCreate(t, e, tenant, dev2, "open-0", at)
		for i := 1; i < helpDeviceCallsPerHour; i++ {
			if r := mustCreate(t, e, tenant, dev2, "open-"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('A'+i/26)), at.Add(time.Duration(i)*time.Second)); r.Created {
				t.Fatalf("already-open call %d created", i)
			}
		}
		if _, err := e.store.CreateForDevice(ctx, tenant, dev2, "open-fresh", "", at.Add(45*time.Second)); !errors.As(err, &le) || le.Scope != helpLimitScopeDevCalls {
			t.Fatalf("31st already-open call: err = %v, want the device_calls limit", err)
		}
		// another device of the tenant is unaffected; the NEXT hour is open again
		dev3, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		mustCreate(t, e, tenant, dev3, "o", at.Add(50*time.Second))
		if _, err := e.store.CreateForDevice(ctx, tenant, dev, "same-op", "", at.Add(time.Hour)); err != nil {
			t.Fatalf("next hour: %v", err)
		}
	})

	t.Run("an already-open return records no op row (a fresh op id after the cancel creates anew)", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		a := mustCreate(t, e, tenant, dev, "op-a", helpT0)
		for _, op := range []string{"cycle-1", "cycle-2", "cycle-3"} {
			if b := mustCreate(t, e, tenant, dev, op, helpT0.Add(time.Minute)); b.Created || b.Request.ID != a.Request.ID {
				t.Fatalf("%s = %+v", op, b)
			}
		}
		if _, err := e.store.CancelForDevice(ctx, tenant, dev, a.Request.ID, helpT0.Add(2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		// had cycle-1 been recorded against the open request it would now replay the CANCELLED one
		c := mustCreate(t, e, tenant, dev, "cycle-1", helpT0.Add(3*time.Minute))
		if !c.Created || c.Request.ID == a.Request.ID {
			t.Fatalf("cycle-1 after the cancel = %+v, want a NEW request (no op row was recorded)", c.Request)
		}
	})

	t.Run("tenant open cap, hourly cap, and expiry before count", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		var devs []string
		for i := 0; i < helpTenantHourlyLimit+2; i++ {
			d, _ := e.newMachine(t, tenant, g)
			devs = append(devs, d)
		}
		var ids []string
		for i := 0; i < helpTenantOpenCap; i++ {
			ids = append(ids, mustCreate(t, e, tenant, devs[i], "o", helpT0.Add(time.Duration(i)*time.Second)).Request.ID)
		}
		at := helpT0.Add(2 * time.Minute)
		_, err := e.store.CreateForDevice(ctx, tenant, devs[100], "o", "", at)
		var le *HelpLimitError
		if !errors.As(err, &le) || le.Scope != helpLimitScopeTenOpen {
			t.Fatalf("101st open request: err = %v, want the open cap", err)
		}
		// EXPIRY BEFORE COUNT: once the 100 have lapsed they no longer hold the cap.
		at = helpT0.Add(33 * time.Minute)
		r, err := e.store.CreateForDevice(ctx, tenant, devs[100], "o", "", at)
		if err != nil {
			t.Fatalf("after expiry the cap must be free: %v", err)
		}
		if len(r.Events) != 100+1 {
			t.Fatalf("lazy expiry returned %d events, want 100 help.expired + 1 help.requested", len(r.Events))
		}
		if n := auditCount(t, e, tenant, AuditHelpExpired, ""); n != 100 {
			t.Fatalf("help.expired rows = %d, want 100", n)
		}
		if _, err := e.store.CancelForDevice(ctx, tenant, devs[100], r.Request.ID, at); err != nil {
			t.Fatal(err)
		}
		// 101 creations so far in the hour; 99 more (each cancelled at once) reach 200.
		for i := 101; i < helpTenantHourlyLimit; i++ {
			c := mustCreate(t, e, tenant, devs[i], "o", at)
			if _, err := e.store.CancelForDevice(ctx, tenant, devs[i], c.Request.ID, at); err != nil {
				t.Fatal(err)
			}
		}
		_, err = e.store.CreateForDevice(ctx, tenant, devs[helpTenantHourlyLimit], "o", "", at)
		if !errors.As(err, &le) || le.Scope != helpLimitScopeTenHour || le.RetryAfter <= 0 {
			t.Fatalf("201st creation in an hour: err = %v", err)
		}
		// another tenant is unaffected by this tenant's exhaustion
		other, _ := e.newTenant(t)
		od, _ := e.newMachine(t, other, e.newGroup(t, other))
		mustCreate(t, e, other, od, "o", at)
	})

	t.Run("cancel: by request id, only for the authenticated device", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		other, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		devA, _ := e.newMachine(t, tenant, g)
		devB, _ := e.newMachine(t, tenant, g)
		ra := mustCreate(t, e, tenant, devA, "a1", helpT0).Request
		rb := mustCreate(t, e, tenant, devB, "b1", helpT0).Request
		// another device cannot cancel it, and cannot tell it exists
		if _, err := e.store.CancelForDevice(ctx, tenant, devB, ra.ID, helpT0); !errors.Is(err, ErrHelpRequestNotFound) {
			t.Fatalf("cross-device cancel: err = %v", err)
		}
		if _, err := e.store.CancelForDevice(ctx, other, devA, ra.ID, helpT0); !errors.Is(err, ErrHelpRequestNotFound) {
			t.Fatalf("cross-tenant cancel: err = %v", err)
		}
		if _, err := e.store.CancelForDevice(ctx, tenant, devA, "not-a-uuid", helpT0); !errors.Is(err, ErrHelpRequestNotFound) {
			t.Fatalf("bad id: err = %v", err)
		}
		got, _, err := e.store.Get(ctx, tenant, ra.ID, helpT0)
		if err != nil || got.Status != HelpStatusOpen {
			t.Fatalf("a refused cancel changed the request: %+v %v", got, err)
		}
		c, err := e.store.CancelForDevice(ctx, tenant, devA, ra.ID, helpT0.Add(time.Minute))
		if err != nil || !c.Changed || c.Request.Status != HelpStatusCancelled || c.Request.CancelReason != HelpCancelGuest {
			t.Fatalf("cancel = %+v %v", c, err)
		}
		if n := auditCount(t, e, tenant, AuditHelpCancelled, ra.ID); n != 1 {
			t.Fatalf("help.cancelled rows = %d", n)
		}
		// a SECOND request is open; cancelling the FIRST id again must not touch it
		ra2 := mustCreate(t, e, tenant, devA, "a2", helpT0.Add(2*time.Minute)).Request
		again, err := e.store.CancelForDevice(ctx, tenant, devA, ra.ID, helpT0.Add(3*time.Minute))
		if err != nil || again.Changed || again.Conflict || again.Request.ID != ra.ID {
			t.Fatalf("repeated cancel = %+v %v", again, err)
		}
		if g2, _, _ := e.store.Get(ctx, tenant, ra2.ID, helpT0.Add(3*time.Minute)); g2.Status != HelpStatusOpen {
			t.Fatal("cancel-by-request-id cancelled a different request")
		}
		if g3, _, _ := e.store.Get(ctx, tenant, rb.ID, helpT0); g3.Status != HelpStatusOpen {
			t.Fatal("cancel touched another device's request")
		}
		if n := auditCount(t, e, tenant, AuditHelpCancelled, ""); n != 1 {
			t.Fatalf("total help.cancelled rows = %d, want 1", n)
		}
	})

	t.Run("expiry is lazy and applied before every decision", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		late := helpT0.Add(31 * time.Minute)
		// list at +31m: nothing open, and the expiry committed its audit row
		rows, res, err := e.store.ListOpen(ctx, tenant, late)
		if err != nil || len(rows) != 0 || len(res.Events) != 1 || res.Events[0].Action != AuditHelpExpired {
			t.Fatalf("list after expiry = %d rows, events %+v, err %v", len(rows), res, err)
		}
		if _, res2, _ := e.store.ListOpen(ctx, tenant, late.Add(time.Minute)); len(res2.Events) != 0 {
			t.Fatal("a second list must not expire (or audit) it again")
		}
		if n := auditCount(t, e, tenant, AuditHelpExpired, r.ID); n != 1 {
			t.Fatalf("help.expired rows = %d, want exactly 1", n)
		}
		if c, err := e.store.CancelForDevice(ctx, tenant, dev, r.ID, late); err != nil || !c.Conflict || c.Request.Status != HelpStatusExpired {
			t.Fatalf("cancel of an expired request = %+v %v, want conflict(expired)", c, err)
		}
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "", late))
		if err != nil || acc.Outcome != HelpAcceptConflict || acc.Request.Status != HelpStatusExpired {
			t.Fatalf("accept of an expired request = %+v %v", acc, err)
		}
		if openSessions(t, e, tenant, mid) != 0 {
			t.Fatal("an expired request produced a session")
		}
		// and accept does the expiry ITSELF when nothing else has run first
		r2 := mustCreate(t, e, tenant, dev, "op2", late).Request
		acc2, err := e.store.Accept(ctx, tenant, acceptInput(t, r2.ID, tech, mid, g, "", late.Add(31*time.Minute)))
		if err != nil || acc2.Outcome != HelpAcceptConflict || acc2.Request.Status != HelpStatusExpired || len(acc2.Events) != 1 {
			t.Fatalf("accept-time expiry = %+v %v", acc2, err)
		}
		// the agent sees the final state
		cur, err := e.store.CurrentForDevice(ctx, tenant, dev, late.Add(32*time.Minute))
		if err != nil || cur.Request == nil || cur.Request.ID != r2.ID || cur.Request.Status != HelpStatusExpired {
			t.Fatalf("current = %+v %v", cur, err)
		}
	})

	t.Run("current: open first, else latest, else none", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		dev, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		if c, err := e.store.CurrentForDevice(ctx, tenant, dev, helpT0); err != nil || c.Request != nil {
			t.Fatalf("no request yet: %+v %v", c, err)
		}
		if c, err := e.store.CurrentForDevice(ctx, tenant, newUUID(), helpT0); err != nil || c.Request != nil {
			t.Fatalf("unknown device must read as none: %+v %v", c, err)
		}
		a := mustCreate(t, e, tenant, dev, "a", helpT0).Request
		_, _ = e.store.CancelForDevice(ctx, tenant, dev, a.ID, helpT0.Add(time.Minute))
		if c, _ := e.store.CurrentForDevice(ctx, tenant, dev, helpT0.Add(2*time.Minute)); c.Request == nil || c.Request.ID != a.ID || c.Request.Status != HelpStatusCancelled {
			t.Fatalf("latest = %+v", c.Request)
		}
		b := mustCreate(t, e, tenant, dev, "b", helpT0.Add(3*time.Minute)).Request
		if c, _ := e.store.CurrentForDevice(ctx, tenant, dev, helpT0.Add(4*time.Minute)); c.Request == nil || c.Request.ID != b.ID || c.Request.Status != HelpStatusOpen {
			t.Fatalf("open = %+v", c.Request)
		}
		if c, _ := e.store.CurrentForDevice(ctx, tenant, dev, helpT0.Add(26*time.Hour)); c.Request != nil {
			t.Fatalf("older than 24h must read as none: %+v", c.Request)
		}
	})

	t.Run("list authorizes on the CURRENT group, not the stored one", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		gOld, gNew := e.newGroup(t, tenant), e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, gOld)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		e.moveMachine(t, tenant, mid, gNew)
		rows, _, err := e.store.ListOpen(ctx, tenant, helpT0)
		if err != nil || len(rows) != 1 {
			t.Fatalf("list = %d rows, %v", len(rows), err)
		}
		if rows[0].MachineGroupID != gNew || rows[0].GroupID != gOld {
			t.Fatalf("current group = %s (want %s), stored = %s (informational, was %s)", rows[0].MachineGroupID, gNew, rows[0].GroupID, gOld)
		}
		if rows[0].ID != r.ID || rows[0].MachineName == "" || rows[0].MachineDevice != dev {
			t.Fatalf("joined row = %+v", rows[0])
		}
		// the moved request is still open (a move re-scopes, never cancels)
		if rows[0].Status != HelpStatusOpen {
			t.Fatal("moving a machine must not cancel its request")
		}
	})

	t.Run("retire / quarantine cancels the open request", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		dev2, mid2 := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		keep := mustCreate(t, e, tenant, dev2, "op", helpT0).Request
		e.setStatus(t, tenant, mid, MachineStatusRetired)
		res, err := e.store.CancelForMachine(ctx, tenant, mid, HelpCancelRetired, helpT0.Add(time.Minute))
		if err != nil || len(res.Events) != 1 {
			t.Fatalf("CancelForMachine = %+v %v", res, err)
		}
		got, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(time.Minute))
		if got.Status != HelpStatusCancelled || got.CancelReason != HelpCancelRetired {
			t.Fatalf("after retire: %+v", got.HelpRequest)
		}
		if k, _, _ := e.store.Get(ctx, tenant, keep.ID, helpT0.Add(time.Minute)); k.Status != HelpStatusOpen {
			t.Fatal("another machine's request was cancelled")
		}
		if res2, _ := e.store.CancelForMachine(ctx, tenant, mid, HelpCancelRetired, helpT0.Add(2*time.Minute)); len(res2.Events) != 0 {
			t.Fatal("cancelling twice must not audit twice")
		}
		_ = mid2
	})

	t.Run("accept creates the bound session in one step", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		in := acceptInput(t, r.ID, tech, mid, g, "acc-1", helpT0.Add(time.Minute))
		acc, err := e.store.Accept(ctx, tenant, in)
		if err != nil || acc.Outcome != HelpAcceptAccepted {
			t.Fatalf("accept = %+v %v", acc, err)
		}
		if acc.Request.Status != HelpStatusAccepted || acc.Request.AcceptedBy != tech || acc.Request.SessionID == "" || acc.Record == nil || acc.Request.SessionID != acc.Record.ID {
			t.Fatalf("bound request = %+v record = %+v", acc.Request, acc.Record)
		}
		rec, err := e.sessions.GetSession(ctx, tenant, acc.Record.ID)
		if err != nil || rec.MachineID != mid || rec.TechnicianID != tech || rec.EndedAt != nil {
			t.Fatalf("session = %+v %v", rec, err)
		}
		if n := auditCount(t, e, tenant, AuditHelpAccepted, r.ID); n != 1 {
			t.Fatalf("help.accepted rows = %d", n)
		}
		var meta map[string]any
		_ = json.Unmarshal(acc.Events[0].Metadata, &meta)
		if meta["session_id"] != acc.Record.ID || acc.Events[0].ActorUserID != tech {
			t.Fatalf("accepted audit = %+v %v", acc.Events[0], meta)
		}
		// single use: a second accept (any technician) is refused with the current state
		other := e.newTech(t, tenant)
		second, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, other, mid, g, "acc-2", helpT0.Add(2*time.Minute)))
		if err != nil || second.Outcome != HelpAcceptConflict || second.Request.Status != HelpStatusAccepted {
			t.Fatalf("second accept = %+v %v", second, err)
		}
		if openSessions(t, e, tenant, mid) != 1 {
			t.Fatalf("open sessions = %d, want 1", openSessions(t, e, tenant, mid))
		}
		// the same technician retrying with the SAME key gets the SAME session back; a different key does not
		replay, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "acc-1", helpT0.Add(3*time.Minute)))
		if err != nil || replay.Outcome != HelpAcceptReplayed || replay.Record.ID != acc.Record.ID {
			t.Fatalf("idempotent retry = %+v %v", replay, err)
		}
		wrongKey, _ := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "acc-other", helpT0.Add(3*time.Minute)))
		if wrongKey.Outcome != HelpAcceptConflict {
			t.Fatalf("retry with a different key = %v", wrongKey.Outcome)
		}
		if thief, _ := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, other, mid, g, "acc-1", helpT0.Add(3*time.Minute))); thief.Outcome != HelpAcceptConflict {
			t.Fatalf("another technician reusing the key = %v, want conflict", thief.Outcome)
		}
		if openSessions(t, e, tenant, mid) != 1 {
			t.Fatal("a retry created a second session")
		}
		// a request id can never be attached to a different session: no second help.accepted either
		if n := auditCount(t, e, tenant, AuditHelpAccepted, ""); n != 1 {
			t.Fatalf("help.accepted rows = %d, want 1", n)
		}
	})

	t.Run("accept refuses a machine that left service or changed group", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g1, g2 := e.newGroup(t, tenant), e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g1)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		// admission computed for g1, then the machine moved
		e.moveMachine(t, tenant, mid, g2)
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g1, "", helpT0.Add(time.Minute)))
		if err != nil || acc.Outcome != HelpAcceptGroupChanged {
			t.Fatalf("stale admission = %+v %v", acc, err)
		}
		if got, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(time.Minute)); got.Status != HelpStatusOpen {
			t.Fatal("a refused accept must leave the request open")
		}
		// re-evaluated against the CURRENT group it goes through
		ok, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g2, "", helpT0.Add(2*time.Minute)))
		if err != nil || ok.Outcome != HelpAcceptAccepted {
			t.Fatalf("accept on the current group = %+v %v", ok, err)
		}
		// retired / quarantined: refused even if nothing cancelled the request first
		for _, st := range []string{MachineStatusRetired, MachineStatusQuarantined} {
			d2, m2 := e.newMachine(t, tenant, g1)
			r2 := mustCreate(t, e, tenant, d2, "op", helpT0).Request
			e.setStatus(t, tenant, m2, st)
			acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r2.ID, tech, m2, g1, "", helpT0.Add(time.Minute)))
			if err != nil || acc.Outcome != HelpAcceptIneligible {
				t.Fatalf("%s machine accept = %+v %v", st, acc, err)
			}
			if openSessions(t, e, tenant, m2) != 0 {
				t.Fatalf("%s machine got a session", st)
			}
		}
		// unknown id / foreign tenant
		if nf, err := e.store.Accept(ctx, tenant, acceptInput(t, newUUID(), tech, mid, g2, "", helpT0)); err != nil || nf.Outcome != HelpAcceptNotFound {
			t.Fatalf("unknown request = %+v %v", nf, err)
		}
		foreign, _ := e.newTenant(t)
		if nf, err := e.store.Accept(ctx, foreign, acceptInput(t, r.ID, tech, mid, g2, "", helpT0)); err != nil || nf.Outcome != HelpAcceptNotFound {
			t.Fatalf("another tenant's request = %+v %v", nf, err)
		}
	})

	t.Run("a fresh accept needs POSITIVE online evidence, evaluated inside the admission", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		with := func(p func(string) HelpPresence) HelpAcceptInput {
			in := acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute))
			in.Presence = p
			return in
		}
		for name, p := range map[string]func(string) HelpPresence{
			"no presence source": nil,
			"unknown":            func(string) HelpPresence { return HelpPresenceUnknown },
		} {
			acc, err := e.store.Accept(ctx, tenant, with(p))
			if err != nil || acc.Outcome != HelpAcceptPresenceUnknown {
				t.Fatalf("%s: accept = %+v %v, want presence_unknown", name, acc, err)
			}
		}
		acc, err := e.store.Accept(ctx, tenant, with(func(string) HelpPresence { return HelpPresenceOffline }))
		if err != nil || acc.Outcome != HelpAcceptOffline {
			t.Fatalf("offline: accept = %+v %v", acc, err)
		}
		if got, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(time.Minute)); got.Status != HelpStatusOpen {
			t.Fatalf("a refused accept changed the request: %s", got.Status)
		}
		if n := openSessions(t, e, tenant, mid); n != 0 {
			t.Fatalf("%d session(s) admitted for a machine not confirmed online", n)
		}
		var asked string
		ok, err := e.store.Accept(ctx, tenant, with(func(d string) HelpPresence { asked = d; return HelpPresenceOnline }))
		if err != nil || ok.Outcome != HelpAcceptAccepted || asked != dev {
			t.Fatalf("online: accept = %+v %v (asked about %q, want the machine's device %q)", ok, err, asked, dev)
		}
	})

	t.Run("accept is admitted through the seat caps", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		_, mid2 := e.newMachine(t, tenant, g)
		busy := &SessionRecord{MachineID: mid2, TechnicianID: tech, GrantedCaps: []string{}, MachineGroupID: g}
		if err := e.sessions.StartSession(ctx, tenant, busy); err != nil {
			t.Fatal(err)
		}
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		in := acceptInput(t, r.ID, tech, mid, g, "", helpT0.Add(time.Minute))
		in.Limits.Tenant = 1 // the tenant already holds one open session
		_, err := e.store.Accept(ctx, tenant, in)
		if !errors.Is(err, ErrConcurrentSessionLimit) {
			t.Fatalf("accept over the seat cap: err = %v, want ErrConcurrentSessionLimit", err)
		}
		if got, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(time.Minute)); got.Status != HelpStatusOpen || got.SessionID != "" {
			t.Fatalf("a refused admission must leave the request open and unbound: %+v", got.HelpRequest)
		}
		if openSessions(t, e, tenant, mid) != 0 {
			t.Fatal("a session exists for the refused accept")
		}
	})

	t.Run("accept single-use under concurrency", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		const n = 8
		techs := make([]string, n)
		for i := range techs {
			techs[i] = e.newTech(t, tenant)
		}
		outcomes := make([]HelpAcceptOutcome, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, techs[i], mid, g, "", helpT0.Add(time.Minute)))
				errs[i] = err
				if acc != nil {
					outcomes[i] = acc.Outcome
				}
			}(i)
		}
		close(start)
		wg.Wait()
		won := 0
		for i := range outcomes {
			if errs[i] != nil {
				t.Fatalf("accept %d: %v", i, errs[i])
			}
			switch outcomes[i] {
			case HelpAcceptAccepted:
				won++
			case HelpAcceptConflict:
			default:
				t.Fatalf("accept %d outcome = %s", i, outcomes[i])
			}
		}
		if won != 1 {
			t.Fatalf("%d accepts won, want exactly 1", won)
		}
		if got := openSessions(t, e, tenant, mid); got != 1 {
			t.Fatalf("open sessions = %d, want 1", got)
		}
		if n := auditCount(t, e, tenant, AuditHelpAccepted, r.ID); n != 1 {
			t.Fatalf("help.accepted rows = %d", n)
		}
	})

	t.Run("accept vs cancel vs expiry: the first commit wins", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		for i := 0; i < 12; i++ {
			dev, mid := e.newMachine(t, tenant, g)
			r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
			var accOut HelpAcceptOutcome
			var cancel *HelpTransitionResult
			var aerr, cerr error
			var wg sync.WaitGroup
			start := make(chan struct{})
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				a, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "", helpT0.Add(time.Minute)))
				aerr = err
				if a != nil {
					accOut = a.Outcome
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				cancel, cerr = e.store.CancelForDevice(ctx, tenant, dev, r.ID, helpT0.Add(time.Minute))
			}()
			close(start)
			wg.Wait()
			if aerr != nil || cerr != nil {
				t.Fatalf("iteration %d: accept err %v, cancel err %v", i, aerr, cerr)
			}
			final, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(time.Minute))
			switch final.Status {
			case HelpStatusAccepted:
				if accOut != HelpAcceptAccepted || !cancel.Conflict || cancel.Changed || openSessions(t, e, tenant, mid) != 1 {
					t.Fatalf("iteration %d: accepted won but accept=%s cancel=%+v sessions=%d", i, accOut, cancel, openSessions(t, e, tenant, mid))
				}
			case HelpStatusCancelled:
				if accOut != HelpAcceptConflict || !cancel.Changed || openSessions(t, e, tenant, mid) != 0 {
					t.Fatalf("iteration %d: cancel won but accept=%s cancel=%+v sessions=%d", i, accOut, cancel, openSessions(t, e, tenant, mid))
				}
			default:
				t.Fatalf("iteration %d: final status %s", i, final.Status)
			}
		}
	})

	t.Run("a start that fails after accept returns the request to open", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
		if err != nil || acc.Outcome != HelpAcceptAccepted {
			t.Fatal(acc, err)
		}
		if _, err := e.sessions.EndSession(ctx, tenant, acc.Record.ID, helpT0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		// a wrong session id never reopens someone else's accept
		if bad, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, newUUID(), helpT0.Add(2*time.Minute)); err != nil || bad.Changed || !bad.Conflict {
			t.Fatalf("reopen with the wrong session = %+v %v", bad, err)
		}
		re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
		if err != nil || !re.Changed || re.Request.Status != HelpStatusOpen || re.Request.SessionID != "" || re.Request.AcceptedBy != "" {
			t.Fatalf("reopen = %+v %v", re, err)
		}
		if n := auditCount(t, e, tenant, AuditHelpReopened, r.ID); n != 1 {
			t.Fatalf("help.reopened rows = %d", n)
		}
		// and it can be accepted again, by anyone, into a NEW session
		again, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, e.newTech(t, tenant), mid, g, "", helpT0.Add(3*time.Minute)))
		if err != nil || again.Outcome != HelpAcceptAccepted || again.Record.ID == acc.Record.ID {
			t.Fatalf("second accept = %+v %v", again, err)
		}
		// past its expiry it reopens as expired; with a newer open request it is superseded
		tn2, tc2 := e.newTenant(t)
		g2 := e.newGroup(t, tn2)
		d2, m2 := e.newMachine(t, tn2, g2)
		q := mustCreate(t, e, tn2, d2, "op", helpT0).Request
		a2, _ := e.store.Accept(ctx, tn2, acceptInput(t, q.ID, tc2, m2, g2, "", helpT0.Add(time.Minute)))
		late, err := e.store.ReopenAfterFailedStart(ctx, tn2, q.ID, a2.Record.ID, helpT0.Add(40*time.Minute))
		if err != nil || late.Request.Status != HelpStatusExpired || late.Request.SessionID != "" {
			t.Fatalf("late reopen = %+v %v", late, err)
		}
		q2 := mustCreate(t, e, tn2, d2, "op2", helpT0.Add(41*time.Minute)).Request
		a3, _ := e.store.Accept(ctx, tn2, acceptInput(t, q2.ID, tc2, m2, g2, "", helpT0.Add(42*time.Minute)))
		q3 := mustCreate(t, e, tn2, d2, "op3", helpT0.Add(43*time.Minute)) // a fresh request while q2 is accepted
		if !q3.Created {
			t.Fatalf("an accepted request must not block a new one: %+v", q3)
		}
		sup, err := e.store.ReopenAfterFailedStart(ctx, tn2, q2.ID, a3.Record.ID, helpT0.Add(44*time.Minute))
		if err != nil || sup.Request.Status != HelpStatusCancelled || sup.Request.CancelReason != HelpCancelSuperseded {
			t.Fatalf("superseded reopen = %+v %v", sup, err)
		}
	})

	t.Run("delivery is a compare-and-swap: a compensation may only claim an undelivered session", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		dev, mid := e.newMachine(t, tenant, g)
		r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
		if err != nil || acc.Outcome != HelpAcceptAccepted || acc.Request.Delivery != HelpDeliveryPending {
			t.Fatalf("accept = %+v %v, want delivery pending", acc, err)
		}
		if md, err := e.store.MarkDelivered(ctx, tenant, r.ID, newUUID(), helpT0.Add(time.Minute)); err != nil || md.Changed {
			t.Fatalf("MarkDelivered for another session = %+v %v, want no change", md, err)
		}
		md, err := e.store.MarkDelivered(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(time.Minute))
		if err != nil || !md.Changed || md.Request.Delivery != HelpDeliveryDelivered {
			t.Fatalf("MarkDelivered = %+v %v", md, err)
		}
		if again, _ := e.store.MarkDelivered(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(time.Minute)); again.Changed {
			t.Fatal("a second delivery mark changed something")
		}
		re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
		if err != nil || re.Changed || !re.Conflict {
			t.Fatalf("reopen of a DELIVERED session = %+v %v, want a conflict and no change", re, err)
		}
		if got, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(2*time.Minute)); got.Status != HelpStatusAccepted || got.SessionID != acc.Record.ID {
			t.Fatalf("a refused claim changed the request: %+v", got.HelpRequest)
		}
		if n := auditCount(t, e, tenant, AuditHelpReopened, r.ID); n != 0 {
			t.Fatal("a help.reopened row was written for a delivered session")
		}
	})

	t.Run("a start that fails after the machine left service cancels instead of reopening", func(t *testing.T) {
		for _, st := range []string{MachineStatusRetired, MachineStatusQuarantined} {
			e := mk(t)
			tenant, tech := e.newTenant(t)
			g := e.newGroup(t, tenant)
			dev, mid := e.newMachine(t, tenant, g)
			r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
			acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
			if err != nil || acc.Outcome != HelpAcceptAccepted {
				t.Fatal(acc, err)
			}
			// the machine is retired / quarantined while the accept is in flight; the cancel for the machine
			// finds nothing OPEN (the request is accepted), then the start fails
			e.setStatus(t, tenant, mid, st)
			if _, err := e.store.CancelForMachine(ctx, tenant, mid, HelpCancelRetired, helpT0.Add(90*time.Second)); err != nil {
				t.Fatal(err)
			}
			re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
			want := HelpCancelRetired
			if st == MachineStatusQuarantined {
				want = HelpCancelQuarantined
			}
			if err != nil || !re.Changed || re.Request.Status != HelpStatusCancelled || re.Request.CancelReason != want || re.Request.SessionID != "" {
				t.Fatalf("%s: reopen = %+v %v, want cancelled/%s", st, re, err, want)
			}
			if n := auditCount(t, e, tenant, AuditHelpCancelled, r.ID); n != 1 {
				t.Fatalf("%s: help.cancelled rows = %d, want 1", st, n)
			}
			if n := auditCount(t, e, tenant, AuditHelpReopened, r.ID); n != 0 {
				t.Fatalf("%s: a help.reopened row was written for an out-of-service machine", st)
			}
			if cur, _, _ := e.store.Get(ctx, tenant, r.ID, helpT0.Add(3*time.Minute)); cur.Status != HelpStatusCancelled {
				t.Fatalf("%s: request = %s", st, cur.Status)
			}
			if again, _ := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k2", helpT0.Add(4*time.Minute))); again.Outcome == HelpAcceptAccepted {
				t.Fatalf("%s: the request became acceptable again", st)
			}
		}
	})

	t.Run("a reopen never pushes the open queue above the tenant cap (cancelled with reason capacity)", func(t *testing.T) {
		e := mk(t)
		tenant, tech := e.newTenant(t)
		g := e.newGroup(t, tenant)
		var devs, mids []string
		for i := 0; i < helpTenantOpenCap+1; i++ {
			d, m := e.newMachine(t, tenant, g)
			devs, mids = append(devs, d), append(mids, m)
		}
		var first *HelpRequest
		for i := 0; i < helpTenantOpenCap; i++ {
			r := mustCreate(t, e, tenant, devs[i], "o", helpT0.Add(time.Duration(i)*time.Second)).Request
			if i == 0 {
				first = r
			}
		}
		// the accept frees device 0's slot (accepted is not open) ...
		acc, err := e.store.Accept(ctx, tenant, acceptInput(t, first.ID, tech, mids[0], g, "k", helpT0.Add(time.Minute)))
		if err != nil || acc.Outcome != HelpAcceptAccepted {
			t.Fatal(acc, err)
		}
		// ... another device fills it ...
		if _, err := e.store.CreateForDevice(ctx, tenant, devs[helpTenantOpenCap], "o", "", helpT0.Add(70*time.Second)); err != nil {
			t.Fatalf("the freed slot must be usable: %v", err)
		}
		// ... and the failed start's compensation must not reopen above the cap
		re, err := e.store.ReopenAfterFailedStart(ctx, tenant, first.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
		if err != nil || !re.Changed || re.Request.Status != HelpStatusCancelled || re.Request.CancelReason != HelpCancelCapacity {
			t.Fatalf("reopen at the cap = %+v %v, want cancelled/capacity", re, err)
		}
		if n := auditCount(t, e, tenant, AuditHelpCancelled, first.ID); n != 1 {
			t.Fatalf("help.cancelled rows = %d, want 1", n)
		}
		if n := auditCount(t, e, tenant, AuditHelpReopened, first.ID); n != 0 {
			t.Fatal("a help.reopened row was written for a request that was not reopened")
		}
		rows, _, err := e.store.ListOpen(ctx, tenant, helpT0.Add(3*time.Minute))
		if err != nil || len(rows) != helpTenantOpenCap {
			t.Fatalf("open queue = %d (%v), want exactly the cap %d", len(rows), err, helpTenantOpenCap)
		}
	})

	t.Run("sweep expires, prunes closed after 30 days, prunes the op ledger", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		g := e.newGroup(t, tenant)
		d1, _ := e.newMachine(t, tenant, g)
		d2, _ := e.newMachine(t, tenant, g)
		old := mustCreate(t, e, tenant, d1, "op", helpT0).Request
		if _, err := e.store.CancelForDevice(ctx, tenant, d1, old.ID, helpT0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		due := mustCreate(t, e, tenant, d2, "op", helpT0.Add(time.Hour)).Request
		// the sweep is cross-tenant (other subtests left open requests in this environment): count OUR events
		mine := func(sw *HelpSweepResult) (n int) {
			for _, ev := range sw.Events {
				if ev.TenantID == tenant && ev.Event.Action == AuditHelpExpired {
					n++
				}
			}
			return n
		}
		sw, err := e.store.Sweep(ctx, helpT0.Add(time.Hour+31*time.Minute))
		if err != nil || mine(sw) != 1 {
			t.Fatalf("sweep 1 = %+v %v (expiries for this tenant: %d)", sw, err, mine(sw))
		}
		if got, _, _ := e.store.Get(ctx, tenant, due.ID, helpT0.Add(2*time.Hour)); got.Status != HelpStatusExpired {
			t.Fatalf("swept request = %+v", got.HelpRequest)
		}
		if sw2, _ := e.store.Sweep(ctx, helpT0.Add(2*time.Hour)); mine(sw2) != 0 {
			t.Fatalf("a second sweep must find nothing to expire: %+v", sw2)
		}
		// 31 days on: both closed requests are older than the 30-day retention
		sw3, err := e.store.Sweep(ctx, helpT0.Add(31*24*time.Hour))
		if err != nil || sw3.Pruned < 2 {
			t.Fatalf("prune sweep = %+v %v", sw3, err)
		}
		if _, _, err := e.store.Get(ctx, tenant, old.ID, helpT0.Add(31*24*time.Hour)); !errors.Is(err, ErrHelpRequestNotFound) {
			t.Fatalf("pruned request still readable: %v", err)
		}
		// the op ledger went with it: the same op creates afresh instead of replaying a pruned id
		if r := mustCreate(t, e, tenant, d1, "op", helpT0.Add(31*24*time.Hour)); !r.Created {
			t.Fatalf("op replay after prune = %+v", r)
		}
	})

	t.Run("an open request is never pruned", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		d, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		r := mustCreate(t, e, tenant, d, "op", helpT0).Request
		sw, err := e.store.Sweep(ctx, helpT0.Add(10*time.Minute))
		if err != nil || sw.Pruned != 0 || sw.Expired != 0 {
			t.Fatalf("sweep = %+v %v", sw, err)
		}
		if got, _, err := e.store.Get(ctx, tenant, r.ID, helpT0.Add(10*time.Minute)); err != nil || got.Status != HelpStatusOpen {
			t.Fatalf("open request disturbed: %+v %v", got, err)
		}
	})

	t.Run("tenant isolation of reads", func(t *testing.T) {
		e := mk(t)
		tenant, _ := e.newTenant(t)
		other, _ := e.newTenant(t)
		d, _ := e.newMachine(t, tenant, e.newGroup(t, tenant))
		r := mustCreate(t, e, tenant, d, "op", helpT0).Request
		if rows, _, _ := e.store.ListOpen(ctx, other, helpT0); len(rows) != 0 {
			t.Fatalf("another tenant lists %d requests", len(rows))
		}
		if _, _, err := e.store.Get(ctx, other, r.ID, helpT0); !errors.Is(err, ErrHelpRequestNotFound) {
			t.Fatalf("another tenant's Get: %v", err)
		}
	})
}

// TestHelpAuditActionsArePinned pins the exact action names the console, webhooks and the web viewer's
// SERVER_ACTIONS mirror rely on.
func TestHelpAuditActionsArePinned(t *testing.T) {
	got := []string{AuditHelpRequested, AuditHelpCancelled, AuditHelpAccepted, AuditHelpExpired, AuditHelpReopened}
	want := []string{"help.requested", "help.cancelled", "help.accepted", "help.expired", "help.reopened"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("action %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeHelpNote(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"  hi  ":                 "hi",
		"a\nb\tc\rd":             "a b c d",
		"x\x00y\x1b[0mz":         "xy[0mz",
		"bidi‮txt​ok":            "biditxtok",
		"bad\xffutf8":            "bad�utf8",
		strings.Repeat("é", 250): strings.Repeat("é", 200),
	} {
		if got := normalizeHelpNote(in); got != want {
			t.Errorf("normalizeHelpNote(%q) = %q, want %q", in, got, want)
		}
	}
}
