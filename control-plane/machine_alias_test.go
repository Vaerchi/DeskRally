package controlplane

// Proofs for §4 machine ALIAS (friendly name): PATCH /machines/{id}/alias + MachineStore.SetMachineAlias.
// The alias is a tenant-owned display label that overrides the agent-reported hostname without touching it.
// Covered: the store (fake + pg under RLS, and BOTH machine projections — GetMachineByID and ListMachines —
// carry it), and the HTTP surface — the group-scoped CapManageMachines WRITE gate (a read-only viewer who
// can SEE a machine still cannot rename it; a group-scoped admin cannot rename a machine in a group they do
// not manage), validation (length + control chars), clearing, unknown machine, and audit.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInMemorySetMachineAlias(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := s.SetMachineAlias(ctx, "t1", m.ID, "Reception PC"); err != nil {
		t.Fatalf("set alias: %v", err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.Alias != "Reception PC" {
		t.Fatalf("alias = %q, want Reception PC", got.Alias)
	}
	// Clearing (empty) is a valid write.
	if err := s.SetMachineAlias(ctx, "t1", m.ID, ""); err != nil {
		t.Fatalf("clear alias: %v", err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.Alias != "" {
		t.Fatalf("alias after clear = %q, want empty", got.Alias)
	}
	// Unknown id and wrong tenant both miss.
	if err := s.SetMachineAlias(ctx, "t1", "no-such-pk", "x"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("unknown machine err = %v, want ErrMachineNotFound", err)
	}
	if err := s.SetMachineAlias(ctx, "t2", m.ID, "x"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant err = %v, want ErrMachineNotFound", err)
	}
}

func TestSetMachineAliasHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "u1", TenantID: tid,
		Grant: NewGrant("u1", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	srv.Machines = NewInMemoryMachineStore() // strict: unknown ids are ErrMachineNotFound

	gA := &MachineGroup{Name: "Group A"}
	gB := &MachineGroup{Name: "Group B"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, tid, gA); err != nil {
		t.Fatalf("create gA: %v", err)
	}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, tid, gB); err != nil {
		t.Fatalf("create gB: %v", err)
	}
	mA := &Machine{DeviceID: "dev-a", GroupID: gA.ID}
	mB := &Machine{DeviceID: "dev-b", GroupID: gB.ID}
	for _, m := range []*Machine{mA, mB} {
		if err := srv.Machines.EnrollMachine(ctx, tid, m); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	}
	patch := func(hh http.Handler, id, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("PATCH", "/machines/"+id+"/alias", strings.NewReader(body)))
		return rec
	}

	// Owner sets mA's alias → 200, the machine now reports the alias, it is STORED, and it is audited with
	// the alias value.
	rec := patch(srv.Handler(), mA.ID, `{"alias":"Reception PC"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner set alias = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Machine Machine `json:"machine"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Machine.Alias != "Reception PC" {
		t.Fatalf("returned alias = %q, want Reception PC", resp.Machine.Alias)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.Alias != "Reception PC" {
		t.Fatalf("stored alias = %q, want Reception PC", got.Alias)
	}
	events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	foundAudit := false
	for _, e := range events {
		if e.Action == "machine.alias_set" && e.TargetID == mA.ID {
			foundAudit = true
			if b, _ := json.Marshal(e.Metadata); !strings.Contains(string(b), "Reception PC") {
				t.Fatalf("audit metadata missing the alias: %s", b)
			}
		}
	}
	if !foundAudit {
		t.Fatalf("no machine.alias_set audit event for %s", mA.ID)
	}

	// Clearing (empty alias) → 200 and the stored alias is empty again.
	if rec := patch(srv.Handler(), mA.ID, `{"alias":""}`); rec.Code != http.StatusOK {
		t.Fatalf("clear alias = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.Alias != "" {
		t.Fatalf("stored alias after clear = %q, want empty", got.Alias)
	}

	// Validation: an over-long alias (>100 runes) and a control character both → 400 and leave it unchanged.
	if rec := patch(srv.Handler(), mA.ID, `{"alias":"`+strings.Repeat("x", 101)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("over-long alias = %d, want 400", rec.Code)
	}
	if rec := patch(srv.Handler(), mA.ID, `{"alias":"bad\u0007bell"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("control-char alias = %d, want 400", rec.Code)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.Alias != "" {
		t.Fatalf("alias changed by a rejected request: %q", got.Alias)
	}

	// Unknown machine → 404.
	if rec := patch(srv.Handler(), newUUID(), `{"alias":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown machine = %d, want 404", rec.Code)
	}

	// A READ-ONLY viewer (holds CapViewMachines but NOT CapManageMachines) can SEE the machine but cannot
	// rename it → 403. This isolates the WRITE-cap gate from the group scope (the viewer is on AllGroups).
	viewer := &Principal{UserID: "u3", TenantID: tid,
		Grant: NewGrant("u3", tid, NewMembership(RoleReadOnly, AllGroups()))}
	vsrv, _ := newTestServer(viewer)
	vsrv.Machines = srv.Machines
	vsrv.MachineGroups = srv.MachineGroups
	if rec := patch(vsrv.Handler(), mA.ID, `{"alias":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only rename = %d, want 403", rec.Code)
	}

	// GROUP SCOPE: an Admin scoped to group A ONLY can rename mA (group A) but not mB (group B).
	scoped := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleAdmin, Groups(gA.ID)))}
	ssrv, _ := newTestServer(scoped)
	ssrv.Machines = srv.Machines
	ssrv.MachineGroups = srv.MachineGroups
	if rec := patch(ssrv.Handler(), mA.ID, `{"alias":"A-managed"}`); rec.Code != http.StatusOK {
		t.Fatalf("scoped admin rename in-scope = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := patch(ssrv.Handler(), mB.ID, `{"alias":"B-blocked"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin rename out-of-scope = %d, want 403", rec.Code)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mB.ID); got.Alias != "" {
		t.Fatalf("mB renamed despite denial: %q", got.Alias)
	}
}

// TestPgSetMachineAliasUnderRLS drives PgMachineStore.SetMachineAlias as rmt_app: a real rename that both
// machine projections (GetMachineByID and ListMachines) reflect, clearing, a non-uuid id (→ ErrMachineNotFound
// before the DB), and RLS (another tenant cannot rename the machine, and it stays put).
func TestPgSetMachineAliasUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool) // 0013: GetMachineByID's projection includes machine.ephemeral/expires_at
	tidA, _ := provisionUser(t, suPool, "ma-a", "a@ma-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "ma-b", "b@ma-b.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tidA, "dev-alias") // a group + a machine in it
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	if err := store.SetMachineAlias(ctx, tidA, mid, "Front Desk"); err != nil {
		t.Fatalf("set alias: %v", err)
	}
	// BOTH projections carry the alias (the single-row read and the fleet listing).
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Alias != "Front Desk" {
		t.Fatalf("GetMachineByID alias = %q, want Front Desk", got.Alias)
	}
	list, err := store.ListMachines(ctx, tidA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listed *Machine
	for i := range list {
		if list[i].ID == mid {
			listed = &list[i]
		}
	}
	if listed == nil || listed.Alias != "Front Desk" {
		t.Fatalf("ListMachines alias = %v, want Front Desk", listed)
	}
	// Clearing writes the empty string back.
	if err := store.SetMachineAlias(ctx, tidA, mid, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Alias != "" {
		t.Fatalf("alias after clear = %q, want empty", got.Alias)
	}
	// A non-uuid id names no row → ErrMachineNotFound (before touching the DB).
	if err := store.SetMachineAlias(ctx, tidA, "not-a-uuid", "x"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("non-uuid id err = %v, want ErrMachineNotFound", err)
	}
	// Cross-tenant (pinned to B, A's machine invisible) → ErrMachineNotFound, and A's machine is untouched.
	if err := store.SetMachineAlias(ctx, tidA, mid, "Keeper"); err != nil {
		t.Fatalf("re-set alias: %v", err)
	}
	if err := store.SetMachineAlias(ctx, tidB, mid, "Hijack"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant err = %v, want ErrMachineNotFound", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.Alias != "Keeper" {
		t.Fatalf("A machine tampered cross-tenant: %q", got.Alias)
	}
}
