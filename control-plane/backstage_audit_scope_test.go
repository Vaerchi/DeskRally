package controlplane

// GROUP SCOPE on GET /audit/backstage/export.
//
// The endpoint required CapViewAudit and stopped there — a tenant-wide check — so an auditor whose
// membership covered one machine group could export every group's backstage trail: the
// keystroke-level record of work on machines they have no authority over (docs/07 loops 11–12).
//
// These tests run against InMemoryAuditStore + InMemoryMachineStore, so they pin the HANDLER: which
// rows survive, what the cursor does, and what happens when the machine repository cannot answer.
// TestPgBackstageExportGroupScopeAcrossTheMachineJoin (backstage_audit_scope_pgstore_test.go)
// carries the part a map cannot: that an audit row's `machine_id` really does resolve to a `machine`
// row (a uuid column matched against a text `device_id`) in a real database.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

const (
	scopeGroupA = "aaaaaaaa-1111-1111-1111-111111111111"
	scopeGroupB = "bbbbbbbb-1111-1111-1111-111111111111"
	scopeDevA   = "aaaaaaaa-2222-2222-2222-222222222222"
	scopeDevB   = "bbbbbbbb-2222-2222-2222-222222222222"
	scopeDevGho = "cccccccc-2222-2222-2222-222222222222" // never enrolled
	scopeSessA  = "aaaaaaaa-3333-3333-3333-333333333333"
	scopeSessB  = "bbbbbbbb-3333-3333-3333-333333333333"
	scopeSessG  = "cccccccc-3333-3333-3333-333333333333"
)

// chainForMachine is chainRange with the MACHINE named, so a test can put two chains on two
// machines in two different groups. (chainRange hardcodes one machine id, which cannot express the
// only question this file asks.)
func chainForMachine(sessionID, machineID string, start, count uint64) []AuditEvent {
	total := start + count
	all := make([]AuditEvent, 0, total)
	prev := GenesisPrevHash
	for s := uint64(0); s < total; s++ {
		e := AuditEvent{
			ID:               fmt.Sprintf("00000000-0000-0000-0000-%012d", s),
			Seq:              s,
			SessionID:        sessionID,
			TechnicianID:     auditTechUser,
			MachineID:        machineID,
			OccurredAtUnixMs: int64(1000 + s),
			Action:           defaultAuditAction,
			Outcome:          defaultAuditOutcome,
			PrevHash:         prev,
		}
		h, err := recomputeHash(e)
		if err != nil {
			panic(fmt.Sprintf("chainForMachine(%s, %d): %v", sessionID, s, err))
		}
		e.Hash = h
		all = append(all, e)
		prev = e.Hash
	}
	return all[start:total]
}

// countingMachineStore counts GetMachine lookups so a test can assert the export resolves each
// DISTINCT machine once per page rather than once per event, and — the load-bearing use — that the
// tenant-wide fast path never consults the repository at all.
type countingMachineStore struct {
	MachineStore
	lookups int
	// failWith, when set, is returned by every lookup — a repository OUTAGE, which is deliberately
	// not the same thing as ErrMachineNotFound.
	failWith error
}

func (s *countingMachineStore) GetMachine(ctx context.Context, tenantID, deviceID string) (*Machine, error) {
	s.lookups++
	if s.failWith != nil {
		return nil, s.failWith
	}
	return s.MachineStore.GetMachine(ctx, tenantID, deviceID)
}

// auditorScoped builds an auditor principal whose CapViewAudit is limited to the given groups (none
// ⇒ tenant-wide, since Groups() with no ids means "all", matching the DB's `scoped_group_ids = {}`).
func auditorScoped(groups ...string) *Principal {
	scope := AllGroups()
	if len(groups) > 0 {
		scope = Groups(groups...)
	}
	return &Principal{
		UserID:   "u-aud",
		TenantID: "tenant-123",
		Grant:    NewGrant("u-aud", "tenant-123", NewMembership(RoleAuditor, scope)),
	}
}

// scopeFixture seeds two enrolled machines in two groups and returns a server for `p` plus the
// audit store to append chains to. `chains` are appended in order, so ingest order is the test's to
// choose — which is exactly what the cursor tests need.
func scopeFixture(t *testing.T, p *Principal, chains ...[]AuditEvent) (*Server, *countingMachineStore) {
	t.Helper()
	srv, store := auditServer(p)
	ctx := context.Background()
	inner := NewInMemoryMachineStore() // STRICT: an unknown device id is not silently given a group
	for _, m := range []*Machine{
		{DeviceID: scopeDevA, GroupID: scopeGroupA, Name: "a"},
		{DeviceID: scopeDevB, GroupID: scopeGroupB, Name: "b"},
	} {
		if err := inner.EnrollMachine(ctx, p.TenantID, m); err != nil {
			t.Fatalf("enroll %s: %v", m.DeviceID, err)
		}
	}
	machines := &countingMachineStore{MachineStore: inner}
	srv.Machines = machines
	for _, c := range chains {
		if _, err := store.AppendAudit(ctx, p.TenantID, c[0].SessionID, c); err != nil {
			t.Fatalf("seed %s: %v", c[0].SessionID, err)
		}
	}
	return srv, machines
}

// The defect itself: a group-A auditor must not export group B's backstage events — and a
// tenant-wide auditor over the SAME data still must, or "export nothing" would satisfy the
// assertion.
func TestBackstageExportHidesOtherGroupsFromAScopedAuditor(t *testing.T) {
	chains := [][]AuditEvent{
		chainForMachine(scopeSessA, scopeDevA, 0, 3),
		chainForMachine(scopeSessB, scopeDevB, 0, 2),
	}

	srv, machines := scopeFixture(t, auditorScoped(scopeGroupA), chains...)
	rec := getExport(srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped export = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	got := decodeNDJSON(t, rec.Body.String())
	if len(got) != 3 {
		t.Fatalf("group-A auditor exported %d events, want 3 (their own machine's chain)", len(got))
	}
	for _, e := range got {
		if e.MachineID != scopeDevA {
			t.Fatalf("scope leak: exported an event from machine %s (group B)", e.MachineID)
		}
	}
	// One lookup per DISTINCT machine on the page, not one per event.
	if machines.lookups != 2 {
		t.Fatalf("machine lookups = %d, want 2 (one per distinct machine on the page)", machines.lookups)
	}

	// NEGATIVE CONTROL — same store, tenant-wide auditor: all five events. Without this, a handler
	// that had simply broken the export would pass everything above.
	wide, _ := scopeFixture(t, auditorScoped(), chains...)
	if n := len(decodeNDJSON(t, getExport(wide, "").Body.String())); n != 5 {
		t.Fatalf("tenant-wide auditor exported %d events, want all 5", n)
	}
}

// THE CURSOR TRAP, and the reason this endpoint needs its own test rather than a filter bolted onto
// the existing ones.
//
// The group filter runs AFTER the store has produced a page. If the returned cursor were recomputed
// from the SURVIVING rows, a page whose rows all belong to another group would hand the caller back
// their own cursor — and a scoped collector would re-request that identical page forever, never
// reaching the events it is entitled to just beyond it. The cursor names a position in the INGEST
// LOG, so it must advance past filtered-out rows.
func TestBackstageExportCursorAdvancesPastAFullyFilteredPage(t *testing.T) {
	// Group B's chain is ingested FIRST, so with limit=2 the first page is ENTIRELY invisible to a
	// group-A auditor. Seeded the other way round the test would be decorative — the first page
	// would contain visible rows and any cursor rule would look correct.
	srv, _ := scopeFixture(t, auditorScoped(scopeGroupA),
		chainForMachine(scopeSessB, scopeDevB, 0, 2), // ingest_seq 0,1 — group B
		chainForMachine(scopeSessA, scopeDevA, 0, 2), // ingest_seq 2,3 — group A
	)

	first := getExport(srv, "?limit=2")
	if first.Code != http.StatusOK {
		t.Fatalf("first page = %d (body %s), want 200", first.Code, first.Body.String())
	}
	if first.Body.Len() != 0 {
		t.Fatalf("first page body = %q, want empty (every row is another group's)", first.Body.String())
	}
	cursor := first.Header().Get("X-Rmt-Next-After-Ingest-Seq")
	if cursor != "1" {
		t.Fatalf("cursor after a fully-filtered page = %q, want 1 (the last RAW row's ingest_seq); "+
			"a cursor computed from the surviving rows leaves a scoped collector spinning on this page forever",
			cursor)
	}

	second := getExport(srv, "?limit=2&after_ingest_seq="+cursor)
	page := decodeNDJSON(t, second.Body.String())
	if len(page) != 2 {
		t.Fatalf("second page returned %d events, want 2 (group A's chain) — the collector made no progress", len(page))
	}
	for _, e := range page {
		if e.MachineID != scopeDevA {
			t.Fatalf("second page leaked machine %s", e.MachineID)
		}
	}

	// And the whole loop terminates the way a collector runs it: keep going while the cursor moves,
	// stop when it stands still. (For a scoped caller an EMPTY page no longer means "caught up" —
	// only an unmoved cursor does.)
	var drained []AuditEvent
	cur := ""
	for i := 0; i < 10; i++ {
		q := "?limit=1"
		if cur != "" {
			q += "&after_ingest_seq=" + cur
		}
		rec := getExport(srv, q)
		drained = append(drained, decodeNDJSON(t, rec.Body.String())...)
		next := rec.Header().Get("X-Rmt-Next-After-Ingest-Seq")
		if next == cur || (cur == "" && next == strconv.FormatInt(auditExportStart, 10)) {
			break
		}
		cur = next
	}
	if len(drained) != 2 {
		t.Fatalf("draining one row at a time yielded %d events, want exactly group A's 2", len(drained))
	}
}

// The `scope.All` FAST PATH: a tenant-wide auditor — the SIEM collector — runs the same query it
// always did and never touches the machine repository. Asserted by wiring NO machine store at all:
// if the handler consulted it, this would fail closed with a 500.
func TestBackstageExportAllScopeNeverConsultsTheMachineStore(t *testing.T) {
	srv, store := auditServer(auditorScoped())
	srv.Machines = nil
	if _, err := store.AppendAudit(context.Background(), "tenant-123", scopeSessA,
		chainForMachine(scopeSessA, scopeDevA, 0, 2)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := getExport(srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant-wide export with no machine store = %d (body %s), want 200 — the fast path "+
			"must not depend on the machine repository", rec.Code, rec.Body.String())
	}
	if n := len(decodeNDJSON(t, rec.Body.String())); n != 2 {
		t.Fatalf("tenant-wide export returned %d events, want 2", n)
	}
}

// The mirror image: a SCOPED auditor whose groups cannot be resolved gets nothing, not everything.
// A 500 is the right answer — serving the unfiltered trail because the lookup failed is the bug
// this whole change exists to remove.
func TestBackstageExportScopedAuditorFailsClosedWithoutAMachineStore(t *testing.T) {
	srv, store := auditServer(auditorScoped(scopeGroupA))
	srv.Machines = nil
	if _, err := store.AppendAudit(context.Background(), "tenant-123", scopeSessB,
		chainForMachine(scopeSessB, scopeDevB, 0, 2)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := getExport(srv, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("scoped export with no machine store = %d (body %s), want 500", rec.Code, rec.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 body is not the JSON error envelope: %q", rec.Body.String())
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("500 body = %q, want an error envelope and certainly no audit events", rec.Body.String())
	}
}

// A machine repository OUTAGE is not "this machine has no group": answering it as invisible would
// silently turn a database blip into a short audit export, which is the one output nobody
// re-checks. It must be a 500.
func TestBackstageExportScopedAuditorFailsClosedOnAMachineStoreError(t *testing.T) {
	srv, machines := scopeFixture(t, auditorScoped(scopeGroupA),
		chainForMachine(scopeSessA, scopeDevA, 0, 2), // events the auditor IS entitled to
	)
	machines.failWith = errors.New("machine repository is down")

	rec := getExport(srv, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("scoped export during a machine-store outage = %d (body %s), want 500 — a truncated "+
			"export must not be reported as a complete one", rec.Code, rec.Body.String())
	}
}

// An event whose machine no longer resolves (retired, or an attended guest whose ephemeral row is
// gone) has no group to scope against, so a scoped auditor does not see it — while a tenant-wide
// auditor still does. Fail closed, and prove the tenant-wide path is unaffected by that choice.
func TestBackstageExportWithholdsUnresolvableMachinesFromAScopedAuditor(t *testing.T) {
	ghost := chainForMachine(scopeSessG, scopeDevGho, 0, 2)

	srv, _ := scopeFixture(t, auditorScoped(scopeGroupA),
		chainForMachine(scopeSessA, scopeDevA, 0, 1),
		ghost,
	)
	got := decodeNDJSON(t, getExport(srv, "").Body.String())
	if len(got) != 1 || got[0].MachineID != scopeDevA {
		t.Fatalf("scoped export = %+v, want only the one event on the enrolled group-A machine", got)
	}

	wide, _ := scopeFixture(t, auditorScoped(),
		chainForMachine(scopeSessA, scopeDevA, 0, 1),
		ghost,
	)
	if n := len(decodeNDJSON(t, getExport(wide, "").Body.String())); n != 3 {
		t.Fatalf("tenant-wide auditor exported %d events, want 3 — withholding unresolvable machines "+
			"must not narrow the tenant-wide trail", n)
	}
}
