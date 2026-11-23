package controlplane

// GROUP SCOPE on the MANAGEMENT audit trail (security review 2026-11-01 #4). One body of
// assertions (runMgmtAuditScopeChecks) runs against the in-memory stores AND against Postgres, so
// the two cannot drift: a scoped auditor sees only events about machines/groups inside their scope,
// never another group's command preview, never tenant-level events; the chain routes are 403.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mgmtScopeWorld struct {
	srv                 *Server
	tenant              string
	groupA, groupB      string
	machineA, machineB  string // machine PRIMARY KEYS (what management events record)
	sessionA, sessionB  string
	ghostMachine        string // resolves to nothing
	recordSessionBlindA string // a session event WITHOUT machine_id metadata (session lookup path)
	recordSessionBlindB string
}

func (w *mgmtScopeWorld) record(t *testing.T, action, kind, target string, meta map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(meta)
	if err := w.srv.MgmtAudit.RecordEvent(context.Background(), w.tenant,
		&MgmtAuditEvent{Action: action, TargetKind: kind, TargetID: target, Metadata: raw}); err != nil {
		t.Fatalf("record %s: %v", action, err)
	}
}

func (w *mgmtScopeWorld) get(t *testing.T, p *Principal, path string) *httptest.ResponseRecorder {
	t.Helper()
	w.srv.Auth = StubAuthenticator{Principal: p}
	rec := httptest.NewRecorder()
	w.srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func runMgmtAuditScopeChecks(t *testing.T, w *mgmtScopeWorld) {
	t.Helper()
	// Order matters: group B's events are the NEWEST, so a limit applied before scoping would
	// return only rows the group-A auditor may not see.
	w.record(t, "user.role_changed", "user", "dddddddd-5555-5555-5555-555555555555", map[string]any{"role": "admin"}) // tenant-level
	w.record(t, "session.start", "session", w.sessionA, map[string]any{"machine_id": w.machineA})                     // A
	w.record(t, "command.run_requested", "session", w.sessionA, map[string]any{"machine_id": w.machineA, "command_preview": "PREVIEW-OF-A"})
	w.record(t, "machine_group.renamed", "machine_group", w.groupA, map[string]any{"name": "a"})  // A (group target)
	w.record(t, "session.note_set", "session", w.recordSessionBlindA, map[string]any{})           // A via session lookup
	w.record(t, "session.start", "session", w.sessionB, map[string]any{"machine_id": w.machineB}) // B
	w.record(t, "command.run_requested", "session", w.sessionB, map[string]any{"machine_id": w.machineB, "command_preview": "SECRET-PREVIEW-OF-B"})
	w.record(t, "machine.alias_set", "machine", w.machineB, map[string]any{"alias": "b-alias"})  // B (machine target)
	w.record(t, "machine_group.renamed", "machine_group", w.groupB, map[string]any{"name": "b"}) // B (group target)
	w.record(t, "session.note_set", "session", w.recordSessionBlindB, map[string]any{})          // B via session lookup
	w.record(t, "machine.alias_set", "machine", w.ghostMachine, map[string]any{})                // unresolvable
	w.record(t, "tenant.branding.set", "tenant", w.tenant, map[string]any{})                     // tenant-level

	scoped := &Principal{UserID: "u-aud", TenantID: w.tenant,
		Grant: NewGrant("u-aud", w.tenant, NewMembership(RoleAuditor, Groups(w.groupA)))}
	wide := &Principal{UserID: "u-aud", TenantID: w.tenant,
		Grant: NewGrant("u-aud", w.tenant, NewMembership(RoleAuditor, AllGroups()))}

	decode := func(rec *httptest.ResponseRecorder) []MgmtAuditEvent {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Events []MgmtAuditEvent `json:"events"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Events
	}

	// Tenant-wide holder: unchanged, sees all 12 including B's preview.
	if got := decode(w.get(t, wide, "/audit?limit=100")); len(got) != 12 {
		t.Fatalf("tenant-wide auditor sees %d events, want 12", len(got))
	}

	// Scoped to A: exactly the four group-A events, newest first.
	rec := w.get(t, scoped, "/audit?limit=100")
	got := decode(rec)
	var actions []string
	for _, e := range got {
		actions = append(actions, e.Action+":"+e.TargetKind)
	}
	want := []string{"session.note_set:session", "machine_group.renamed:machine_group", "command.run_requested:session", "session.start:session"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("scoped (A) events = %v, want %v", actions, want)
	}
	if !strings.Contains(rec.Body.String(), "PREVIEW-OF-A") {
		t.Fatal("scoped auditor must see group A's own command preview")
	}
	for _, leak := range []string{"SECRET-PREVIEW-OF-B", "b-alias", w.machineB, w.sessionB, "dddddddd-5555-5555-5555-555555555555"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("scoped (A) response leaks %q: %s", leak, rec.Body.String())
		}
	}

	// limit applies AFTER scoping: the newest raw rows are all B/tenant-level, yet limit=1 still
	// returns A's newest event.
	if got := decode(w.get(t, scoped, "/audit?limit=1")); len(got) != 1 || got[0].Action != "session.note_set" {
		t.Fatalf("scoped limit=1 = %+v, want the newest group-A event", got)
	}
	// Filters still compose with scoping.
	if got := decode(w.get(t, scoped, "/audit?action=command.run_requested")); len(got) != 1 {
		t.Fatalf("scoped action filter = %d events, want 1", len(got))
	}

	// Symmetric: scoped to B sees B's preview and never A's.
	scopedB := &Principal{UserID: "u-aud", TenantID: w.tenant,
		Grant: NewGrant("u-aud", w.tenant, NewMembership(RoleAuditor, Groups(w.groupB)))}
	rec = w.get(t, scopedB, "/audit?limit=100")
	if !strings.Contains(rec.Body.String(), "SECRET-PREVIEW-OF-B") || strings.Contains(rec.Body.String(), "PREVIEW-OF-A") {
		t.Fatalf("scoped (B) response wrong: %s", rec.Body.String())
	}

	// Summary: counts only in-scope events for a scoped holder; tenant-wide unchanged.
	summary := func(p *Principal) map[string]int64 {
		rec := w.get(t, p, "/audit/summary")
		if rec.Code != http.StatusOK {
			t.Fatalf("summary status %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Summary []AuditActionCount `json:"summary"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		m := map[string]int64{}
		for _, c := range out.Summary {
			m[c.Action] = c.Count
		}
		return m
	}
	sa := summary(scoped)
	if len(sa) != 4 || sa["session.start"] != 1 || sa["command.run_requested"] != 1 || sa["machine_group.renamed"] != 1 || sa["session.note_set"] != 1 {
		t.Fatalf("scoped summary = %v", sa)
	}
	if sw := summary(wide); sw["session.start"] != 2 || sw["user.role_changed"] != 1 || sw["machine.alias_set"] != 2 {
		t.Fatalf("tenant-wide summary = %v", sw)
	}

	// Chain routes: tenant-wide only.
	for _, path := range []string{"/audit/export", "/audit/verify", "/audit/archive"} {
		if rec := w.get(t, scoped, path); rec.Code != http.StatusForbidden {
			t.Fatalf("scoped GET %s = %d, want 403", path, rec.Code)
		}
		if rec := w.get(t, wide, path); rec.Code != http.StatusOK {
			t.Fatalf("tenant-wide GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func TestMgmtAuditGroupScopeInMemory(t *testing.T) {
	const tenant = "tenant-123"
	srv, _ := newTestServer(&Principal{UserID: "x", TenantID: tenant})
	machines := NewInMemoryMachineStore() // strict: unknown ids are not given a group
	ctx := context.Background()
	w := &mgmtScopeWorld{srv: srv, tenant: tenant,
		groupA: "aaaaaaaa-1111-1111-1111-111111111111", groupB: "bbbbbbbb-1111-1111-1111-111111111111",
		machineA: "aaaaaaaa-2222-2222-2222-222222222222", machineB: "bbbbbbbb-2222-2222-2222-222222222222",
		ghostMachine: "cccccccc-2222-2222-2222-222222222222",
		sessionA:     "aaaaaaaa-3333-3333-3333-333333333333", sessionB: "bbbbbbbb-3333-3333-3333-333333333333",
		recordSessionBlindA: "aaaaaaaa-4444-4444-4444-444444444444", recordSessionBlindB: "bbbbbbbb-4444-4444-4444-444444444444"}
	for _, m := range []*Machine{
		{ID: w.machineA, DeviceID: "dev-a", GroupID: w.groupA, Name: "a"},
		{ID: w.machineB, DeviceID: "dev-b", GroupID: w.groupB, Name: "b"},
	} {
		if err := machines.EnrollMachine(ctx, tenant, m); err != nil {
			t.Fatal(err)
		}
	}
	srv.Machines = machines
	for _, r := range []*SessionRecord{
		{ID: w.recordSessionBlindA, MachineID: w.machineA, MachineGroupID: w.groupA},
		{ID: w.recordSessionBlindB, MachineID: w.machineB, MachineGroupID: w.groupB},
	} {
		if err := srv.SessionRecords.StartSession(ctx, tenant, r); err != nil {
			t.Fatal(err)
		}
		// The store assigns the id; re-point the world at it.
		if r.MachineID == w.machineA {
			w.recordSessionBlindA = r.ID
		} else {
			w.recordSessionBlindB = r.ID
		}
	}
	runMgmtAuditScopeChecks(t, w)
	runMgmtAuditPagingChecks(t, w)
}

func TestPgMgmtAuditGroupScope(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	ctx := context.Background()
	tid, uid := provisionUser(t, suPool, "mgmt-scope", "aud@mgmt-scope.test", "password-1234")
	gidA, midA := seedGroupMachine(t, suPool, tid, "dev-scope-a")
	gidB, midB := seedGroupMachine(t, suPool, tid, "dev-scope-b")
	appPool := newAppRolePool(t, ctx)

	srv := NewServer(nil, NewPgBinder(appPool))
	srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
	srv.Machines = NewPgMachineStore(appPool)
	srv.SessionRecords = NewPgSessionRecordStore(appPool)

	newSess := func(mid, gid string) string {
		r := &SessionRecord{MachineID: mid, MachineGroupID: gid, TechnicianID: uid, Access: "control"}
		if err := srv.SessionRecords.StartSession(ctx, tid, r); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		return r.ID
	}
	w := &mgmtScopeWorld{srv: srv, tenant: tid, groupA: gidA, groupB: gidB, machineA: midA, machineB: midB,
		ghostMachine: newUUID(), sessionA: newUUID(), sessionB: newUUID(),
		recordSessionBlindA: newSess(midA, gidA), recordSessionBlindB: newSess(midB, gidB)}
	runMgmtAuditScopeChecks(t, w)
	runMgmtAuditPagingChecks(t, w)
}

// Review repair 4: paging must not depend on timestamps. 1200 events share ONE OccurredAt (more than
// two scan pages of them); the scoped view must still return every in-scope event exactly once, a
// hit scan cap must be REPORTED (truncated + next_cursor, partial summary), and following the
// cursor must reach the rest.
func runMgmtAuditPagingChecks(t *testing.T, w *mgmtScopeWorld) {
	t.Helper()
	same := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 1200; i++ {
		machine, group := w.machineB, "B"
		if i%2 == 0 {
			machine, group = w.machineA, "A"
		}
		raw, _ := json.Marshal(map[string]any{"machine_id": machine, "group": group})
		if err := w.srv.MgmtAudit.RecordEvent(context.Background(), w.tenant,
			&MgmtAuditEvent{Action: "bulk.event", TargetKind: "session", TargetID: w.sessionA, OccurredAt: same, Metadata: raw}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	scoped := &Principal{UserID: "u-aud", TenantID: w.tenant,
		Grant: NewGrant("u-aud", w.tenant, NewMembership(RoleAuditor, Groups(w.groupA)))}
	fetch := func(path string) (events []MgmtAuditEvent, truncated bool, next string) {
		t.Helper()
		rec := w.get(t, scoped, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
		var out struct {
			Events     []MgmtAuditEvent `json:"events"`
			Truncated  bool             `json:"truncated"`
			NextCursor string           `json:"next_cursor"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Events, out.Truncated, out.NextCursor
	}
	countBulk := func(evs []MgmtAuditEvent, seen map[string]bool) int {
		n := 0
		for _, e := range evs {
			if e.Action != "bulk.event" {
				continue
			}
			if seen[e.ID] {
				t.Fatalf("event %s returned twice", e.ID)
			}
			seen[e.ID] = true
			n++
		}
		return n
	}

	// (1) Default page/cap: all 600 in-scope bulk events, across 3 raw pages, none of group B.
	evs, truncated, _ := fetch("/audit?limit=1000&action=bulk.event")
	if truncated || countBulk(evs, map[string]bool{}) != 600 {
		t.Fatalf("scoped bulk events = %d (truncated=%v), want all 600", len(evs), truncated)
	}
	for _, e := range evs {
		if !strings.Contains(string(e.Metadata), `"group":"A"`) {
			t.Fatalf("a group-B event leaked: %s", e.Metadata)
		}
	}

	// (2) A scan cap of one page: the answer says it is truncated and the cursor continues it.
	oldPage, oldCap := scopedAuditPage, scopedAuditScanCap
	scopedAuditPage, scopedAuditScanCap = 500, 500
	defer func() { scopedAuditPage, scopedAuditScanCap = oldPage, oldCap }()
	seen := map[string]bool{}
	path, hops := "/audit?limit=1000&action=bulk.event", 0
	for {
		evs, truncated, next := fetch(path)
		countBulk(evs, seen)
		if !truncated {
			break
		}
		if next == "" {
			t.Fatal("truncated without a next_cursor")
		}
		hops++
		if hops > 10 {
			t.Fatal("cursor does not advance")
		}
		path = "/audit?limit=1000&action=bulk.event&cursor=" + next
	}
	if hops < 1 {
		t.Fatal("a 500-event cap over 1200 events must report truncation")
	}
	if len(seen) != 600 {
		t.Fatalf("following the cursor reached %d of 600 in-scope events", len(seen))
	}
	// The summary under a hit cap is marked partial; under the default cap it is not.
	rec := w.get(t, scoped, "/audit/summary?action=bulk.event")
	if !strings.Contains(rec.Body.String(), `"partial":true`) {
		t.Fatalf("capped scoped summary must say partial: %s", rec.Body.String())
	}
	scopedAuditPage, scopedAuditScanCap = oldPage, oldCap
	rec = w.get(t, scoped, "/audit/summary?action=bulk.event")
	if strings.Contains(rec.Body.String(), "partial") || !strings.Contains(rec.Body.String(), `"count":600`) {
		t.Fatalf("complete scoped summary = %s", rec.Body.String())
	}
}
