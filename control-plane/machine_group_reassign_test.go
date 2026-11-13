package controlplane

// Proofs for §4 machine GROUP REASSIGNMENT (POST /machines/{id}/group + MachineStore.SetMachineGroup): the
// store (fake + pg under RLS, composite-FK backstop) and the HTTP surface — the TWO-WAY authz (manage the
// CURRENT group AND the TARGET group, the loop-48 no-escalation pattern), target-group validation, and audit.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestInMemorySetMachineGroup(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineStore()
	m := &Machine{DeviceID: "dev-1", GroupID: "g1"}
	if err := s.EnrollMachine(ctx, "t1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := s.SetMachineGroup(ctx, "t1", m.ID, "g2"); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if got, _ := s.GetMachineByID(ctx, "t1", m.ID); got.GroupID != "g2" {
		t.Fatalf("group = %q, want g2", got.GroupID)
	}
	// Unknown id and wrong tenant both miss.
	if err := s.SetMachineGroup(ctx, "t1", "no-such-pk", "g2"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("unknown machine err = %v, want ErrMachineNotFound", err)
	}
	if err := s.SetMachineGroup(ctx, "t2", m.ID, "g2"); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant err = %v, want ErrMachineNotFound", err)
	}
}

func TestSetMachineGroupHandler(t *testing.T) {
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
	post := func(hh http.Handler, id, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("POST", "/machines/"+id+"/group", strings.NewReader(body)))
		return rec
	}

	// Owner reassigns mA from group A to group B → 200, the machine now reports group B, and it is audited
	// with from/to.
	rec := post(srv.Handler(), mA.ID, `{"group_id":"`+gB.ID+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner reassign = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Machine Machine `json:"machine"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Machine.GroupID != gB.ID {
		t.Fatalf("returned group = %q, want %q", resp.Machine.GroupID, gB.ID)
	}
	// The echoed group_name is recomputed from the TARGET group, not the stale (old) joined name.
	if resp.Machine.GroupName != gB.Name {
		t.Fatalf("returned group_name = %q, want %q (recomputed from the target)", resp.Machine.GroupName, gB.Name)
	}
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mA.ID); got.GroupID != gB.ID {
		t.Fatalf("stored group = %q, want %q", got.GroupID, gB.ID)
	}
	events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	foundAudit := false
	for _, e := range events {
		if e.Action == "machine.group_changed" && e.TargetID == mA.ID {
			foundAudit = true
			if b, _ := json.Marshal(e.Metadata); !strings.Contains(string(b), gB.ID) {
				t.Fatalf("audit metadata missing the target group: %s", b)
			}
		}
	}
	if !foundAudit {
		t.Fatalf("no machine.group_changed audit event for %s", mA.ID)
	}
	// Move mA back to A so the scoped tests below start from a known state.
	if rec := post(srv.Handler(), mA.ID, `{"group_id":"`+gA.ID+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("move-back = %d, want 200", rec.Code)
	}

	// An unknown target group → 404 (owner passes the RequireMachine on AllGroups, but the group does not exist).
	if rec := post(srv.Handler(), mA.ID, `{"group_id":"`+newUUID()+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown target group = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	// Empty group_id → 400; unknown machine → 404.
	if rec := post(srv.Handler(), mA.ID, `{"group_id":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty group = %d, want 400", rec.Code)
	}
	if rec := post(srv.Handler(), newUUID(), `{"group_id":"`+gB.ID+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown machine = %d, want 404", rec.Code)
	}

	// TWO-WAY authz: an Admin scoped to group A ONLY.
	scoped := &Principal{UserID: "u2", TenantID: tid,
		Grant: NewGrant("u2", tid, NewMembership(RoleAdmin, Groups(gA.ID)))}
	ssrv, _ := newTestServer(scoped)
	ssrv.Machines = srv.Machines
	ssrv.MachineGroups = srv.MachineGroups
	// Move-IN denied: mA (in group A, which they manage) → group B (which they do NOT) → 403.
	if rec := post(ssrv.Handler(), mA.ID, `{"group_id":"`+gB.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("move into unmanaged group = %d, want 403", rec.Code)
	}
	// Move-OUT denied: mB (in group B, which they do NOT manage) → group A → 403 (the CURRENT-group check).
	if rec := post(ssrv.Handler(), mB.ID, `{"group_id":"`+gA.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("move out of unmanaged group = %d, want 403", rec.Code)
	}
	// mB was NOT moved.
	if got, _ := srv.Machines.GetMachineByID(ctx, tid, mB.ID); got.GroupID != gB.ID {
		t.Fatalf("mB moved despite denial: %q", got.GroupID)
	}
}

// TestPgSetMachineGroupUnderRLS drives PgMachineStore.SetMachineGroup as rmt_app: a real reassignment, the
// composite-FK backstop (a non-existent/cross-tenant target group → ErrInvalidMachineGroup), and RLS (another
// tenant cannot move the machine — ErrMachineNotFound, and it stays put).
func TestPgSetMachineGroupUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAttendedMigration(t, suPool) // 0013: GetMachineByID's projection includes machine.ephemeral/expires_at
	tidA, _ := provisionUser(t, suPool, "mg-a", "a@mg-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "mg-b", "b@mg-b.test", "password-1234")
	_, mid := seedGroupMachine(t, suPool, tidA, "dev-reassign") // group 1 + a machine in it
	ctx := context.Background()

	// A second group in tenant A to move the machine into.
	var g2 string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&g2); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G2')`, g2, tidA)
		return err
	}); err != nil {
		t.Fatalf("insert g2: %v", err)
	}

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	if err := store.SetMachineGroup(ctx, tidA, mid, g2); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.GroupID != g2 {
		t.Fatalf("group = %q, want g2", got.GroupID)
	}
	// A non-existent target group fails the composite FK → ErrInvalidMachineGroup.
	if err := store.SetMachineGroup(ctx, tidA, mid, newUUID()); !errors.Is(err, ErrInvalidMachineGroup) {
		t.Fatalf("bad target group err = %v, want ErrInvalidMachineGroup", err)
	}
	// Cross-tenant (pinned to B, A's machine invisible) → ErrMachineNotFound, and A's machine is untouched.
	if err := store.SetMachineGroup(ctx, tidB, mid, g2); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("cross-tenant err = %v, want ErrMachineNotFound", err)
	}
	if got, _ := store.GetMachineByID(ctx, tidA, mid); got.GroupID != g2 {
		t.Fatalf("A machine tampered cross-tenant: %q", got.GroupID)
	}
}
