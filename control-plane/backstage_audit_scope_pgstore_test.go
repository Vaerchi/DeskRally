package controlplane

// Group scope on GET /audit/backstage/export, against a REAL database and as the least-privilege
// rmt_app role.
//
// backstage_audit_scope_test.go pins the handler's decisions against maps. It cannot refute the one
// thing this endpoint's fix actually depends on: that an audit row's `machine_id` RESOLVES to a
// machine row. Those two columns are not even the same type — `backstage_audit_event.machine_id` is
// `uuid` (0004_audit.sql) while `machine.device_id` is `text` (0001_core.sql) — and they are joined
// through the machine repository because the trail records the agent's DEVICE id, the identity the
// grant is minted for (handleMintGrant) and the one the agent copies into every event it emits. A
// fake keyed on a Go string cannot tell whether that survives Postgres' uuid canonicalization.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// scopedExport issues the GET as `p` and returns the recorder, rebuilding the server so the
// principal can change between calls (StubAuthenticator holds one).
func scopedExport(t *testing.T, p *Principal, srv *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	srv.Auth = StubAuthenticator{Principal: p}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/audit/backstage/export"+query, nil))
	return rec
}

func TestPgBackstageExportGroupScopeAcrossTheMachineJoin(t *testing.T) {
	suPool := newTestPool(t) // skips without TEST_DATABASE_URL
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: PgMachineStore's projection reads ephemeral/expires_at
	applyAuditMigration(t, suPool)    // 0004 + 0019
	ctx := context.Background()

	// Same privilege fix-up TestPgBackstageAuditExportUnderRLS documents: 0005 ran before the audit
	// table existed here, so its grants have to be re-applied for that table by hand.
	execScript(t, suPool, `
		GRANT SELECT, INSERT ON backstage_audit_event TO rmt_app;
		REVOKE UPDATE, DELETE ON backstage_audit_event FROM rmt_app;
	`)

	tid, uid := provisionUser(t, suPool, "scope-export", "tech@scope-export.test", "password-1234")
	gidA := seedGroup(t, suPool, tid)
	gidB := seedGroup(t, suPool, tid)

	appPool := newAppRolePool(t, ctx)
	machines := NewPgMachineStore(appPool)
	audit := NewPgAuditStore(appPool)

	// Device ids are UUIDs because that is what enrollment mints (newUUID) and what the audit
	// table's `machine_id uuid` column can hold at all — an agent whose device id is not
	// uuid-shaped could never appear in this trail.
	devA, devB := newUUID(), newUUID()
	if err := machines.EnrollMachine(ctx, tid, &Machine{DeviceID: devA, GroupID: gidA, Name: "in-scope"}); err != nil {
		t.Fatalf("enroll A: %v", err)
	}
	if err := machines.EnrollMachine(ctx, tid, &Machine{DeviceID: devB, GroupID: gidB, Name: "out-of-scope"}); err != nil {
		t.Fatalf("enroll B: %v", err)
	}

	// Group B's chain is ingested FIRST so that a limit=2 page is entirely invisible to the
	// group-A auditor — the arrangement the cursor assertion below needs.
	const sessB = "11111111-4444-4444-4444-444444444444"
	const sessA = "22222222-4444-4444-4444-444444444444"
	if _, err := audit.AppendAudit(ctx, tid, sessB, chainForMachine(sessB, devB, 0, 2)); err != nil {
		t.Fatalf("seed group B chain: %v", err)
	}
	if _, err := audit.AppendAudit(ctx, tid, sessA, chainForMachine(sessA, devA, 0, 3)); err != nil {
		t.Fatalf("seed group A chain: %v", err)
	}

	srv := NewServer(nil, NewPgBinder(appPool))
	srv.Audit = audit
	srv.Machines = machines

	scoped := &Principal{
		UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleAuditor, Groups(gidA))),
	}
	wide := &Principal{
		UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleAuditor, AllGroups())),
	}

	// (1) The scoped auditor sees only their own group's chain — resolved through the real machine
	// table, not a map.
	rec := scopedExport(t, scoped, srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped export = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	got := decodeNDJSON(t, rec.Body.String())
	if len(got) != 3 {
		t.Fatalf("group-A auditor exported %d events, want 3", len(got))
	}
	for _, e := range got {
		if e.MachineID != devA {
			t.Fatalf("scope leak: exported machine %s (group B is %s)", e.MachineID, devB)
		}
	}
	// Every surviving row still re-hashes: filtering must not touch the bytes a collector verifies.
	for i, e := range got {
		h, err := recomputeHash(e)
		if err != nil || h != e.Hash {
			t.Fatalf("row %d does not re-hash after filtering (err %v)", i, err)
		}
	}

	// (2) NEGATIVE CONTROL, same server and same data: tenant-wide sees all five.
	all := decodeNDJSON(t, scopedExport(t, wide, srv, "").Body.String())
	if len(all) != 5 {
		t.Fatalf("tenant-wide auditor exported %d events, want all 5", len(all))
	}

	// (3) THE CURSOR, over a real store: a page that is entirely another group's must still advance
	// past those rows, or a scoped collector re-requests it forever.
	first := scopedExport(t, scoped, srv, "?limit=2")
	if first.Body.Len() != 0 {
		t.Fatalf("first scoped page = %q, want empty (both rows are group B's)", first.Body.String())
	}
	cursor := first.Header().Get("X-Rmt-Next-After-Ingest-Seq")
	if cursor != "1" {
		t.Fatalf("cursor after a fully-filtered page = %q, want 1 (the raw page's last ingest_seq)", cursor)
	}
	second := decodeNDJSON(t, scopedExport(t, scoped, srv, "?limit=2&after_ingest_seq="+cursor).Body.String())
	if len(second) != 2 {
		t.Fatalf("resumed scoped page returned %d events, want 2 — no progress was made", len(second))
	}
	for _, e := range second {
		if e.MachineID != devA {
			t.Fatalf("resumed page leaked machine %s", e.MachineID)
		}
	}
}
