package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// --- pure no-escalation math: canAdministerUser composes with group scope (docs/55) ---

func TestCanAdministerUserComposesGroupScope(t *testing.T) {
	g := func(scope GroupScope) *Grant { return NewGrant("u", "t", NewMembership(RoleAdmin, scope)) }
	tenantWide := g(AllGroups())
	scopedA := g(Groups("gA"))

	// A tenant-wide actor may administer any scope.
	if err := canAdministerUser(tenantWide, g(AllGroups())); err != nil {
		t.Errorf("tenant-wide over tenant-wide: %v", err)
	}
	if err := canAdministerUser(tenantWide, scopedA); err != nil {
		t.Errorf("tenant-wide over scoped: %v", err)
	}
	// A group-A actor may administer a group-A target...
	if err := canAdministerUser(scopedA, g(Groups("gA"))); err != nil {
		t.Errorf("A over A: %v", err)
	}
	// ...but NOT a broader target (A,B), a different group (B), or a tenant-wide target.
	if err := canAdministerUser(scopedA, g(Groups("gA", "gB"))); err == nil {
		t.Error("A over {A,B} must be escalation")
	}
	if err := canAdministerUser(scopedA, g(Groups("gB"))); err == nil {
		t.Error("A over {B} must be escalation")
	}
	if err := canAdministerUser(scopedA, g(AllGroups())); err == nil {
		t.Error("A over tenant-wide must be escalation")
	}
}

func TestAssignmentScopeAndGroupIDs(t *testing.T) {
	if ids := AllGroups().GroupIDs(); ids != nil {
		t.Errorf("AllGroups().GroupIDs() = %v, want nil (tenant-wide)", ids)
	}
	if ids := Groups("b", "a").GroupIDs(); len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Errorf("GroupIDs() = %v, want sorted [a b]", ids)
	}
	// Preserve: a tenant-wide membership preserves tenant-wide; a scoped one preserves its ids.
	if s := NewGrant("u", "t", NewMembership(RoleAdmin, AllGroups())).AssignmentScope(); !s.All {
		t.Error("tenant-wide grant must preserve tenant-wide")
	}
	if ids := NewGrant("u", "t", NewMembership(RoleAdmin, Groups("gA"))).AssignmentScope().GroupIDs(); len(ids) != 1 || ids[0] != "gA" {
		t.Errorf("scoped grant preserve = %v, want [gA]", ids)
	}
	// A dangling id (a group since deleted) stays a deny, NEVER tenant-wide: the scope covers only
	// that id, and GroupIDs never returns nil for a non-empty set (which would read as AllGroups).
	dangling := Groups("deleted-group")
	if dangling.Covers("some-live-group") {
		t.Error("a scope to a deleted group must not cover a live group")
	}
	if dangling.GroupIDs() == nil {
		t.Error("a non-empty scope must never collapse to nil/tenant-wide")
	}
}

func TestInMemoryGroupScopedAssignmentRoundTrips(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	if err := s.CreateUser(ctx, "t1", "u1", "a@x.test", "A", RoleTechnician, []string{"gA"}); err != nil {
		t.Fatalf("create scoped: %v", err)
	}
	grant, err := s.GrantFor(ctx, "t1", "u1")
	if err != nil {
		t.Fatalf("grantfor: %v", err)
	}
	if grant.AllowsInGroup(CapViewMachines, "gA") != true || grant.AllowsInGroup(CapViewMachines, "gB") != false {
		t.Errorf("created scope: A=%v B=%v, want A=true B=false",
			grant.AllowsInGroup(CapViewMachines, "gA"), grant.AllowsInGroup(CapViewMachines, "gB"))
	}
	// Re-scope via SetUserRole.
	if err := s.SetUserRole(ctx, "t1", "u1", RoleTechnician, []string{"gB"}); err != nil {
		t.Fatalf("setrole scoped: %v", err)
	}
	grant, _ = s.GrantFor(ctx, "t1", "u1")
	if grant.AllowsInGroup(CapViewMachines, "gB") != true || grant.AllowsInGroup(CapViewMachines, "gA") != false {
		t.Error("re-scope to B did not take effect")
	}
	// ListUsers surfaces the effective scope (so the console can display + pre-fill it).
	if users, _ := s.ListUsers(ctx, "t1"); len(users) != 1 || len(users[0].ScopedGroupIDs) != 1 || users[0].ScopedGroupIDs[0] != "gB" {
		t.Errorf("ListUsers scope = %+v, want [gB]", users)
	}
	// Empty scope → tenant-wide.
	if err := s.SetUserRole(ctx, "t1", "u1", RoleTechnician, nil); err != nil {
		t.Fatalf("setrole tenant-wide: %v", err)
	}
	grant, _ = s.GrantFor(ctx, "t1", "u1")
	if !grant.AllowsInGroup(CapViewMachines, "any-group") {
		t.Error("nil scope must be tenant-wide")
	}
	if users, _ := s.ListUsers(ctx, "t1"); len(users) != 1 || len(users[0].ScopedGroupIDs) != 0 {
		t.Errorf("tenant-wide ListUsers scope = %+v, want [] (empty = all)", users[0].ScopedGroupIDs)
	}
}

// --- pg under RLS: the scoped assignment round-trips and validates transactionally (fake/pg parity) ---

func TestPgGroupScopedAssignmentUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "gs-a", "a@gs-a.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)
	groups := NewPgMachineGroupStore(appPool)

	gA := &MachineGroup{Name: "A"}
	if err := groups.CreateMachineGroup(ctx, tid, gA); err != nil {
		t.Fatalf("create group A: %v", err)
	}

	// Assign a group-A scope; GrantFor reads it back as a group-scoped membership.
	if err := store.SetUserRole(ctx, tid, uid, RoleReadOnly, []string{gA.ID}); err != nil {
		t.Fatalf("SetUserRole scoped: %v", err)
	}
	g, _ := store.GrantFor(ctx, tid, uid)
	if !g.AllowsInGroup(CapViewMachines, gA.ID) || g.AllowsInGroup(CapViewMachines, newUUID()) {
		t.Fatalf("scoped grant: A=%v other=%v, want A=true other=false",
			g.AllowsInGroup(CapViewMachines, gA.ID), g.AllowsInGroup(CapViewMachines, newUUID()))
	}
	// ListUsers surfaces the scope under RLS (the CTE: any tenant-wide membership → '{}', else union).
	if users, _ := store.ListUsers(ctx, tid); len(users) != 1 || len(users[0].ScopedGroupIDs) != 1 || users[0].ScopedGroupIDs[0] != gA.ID {
		t.Fatalf("pg ListUsers scope = %+v, want [%s]", users, gA.ID)
	}

	// Preserve across a group DELETION: deleting the (empty) assigned group leaves the membership's
	// id DANGLING. Re-persisting that scope (as the handler's preserve-on-absent does) must SUCCEED and
	// stay a scoped deny — it must NOT fail validation (that was the review's repair) nor widen to
	// tenant-wide. The store persists exactly what it is given; the dangling id covers no machine.
	if err := NewPgMachineGroupStore(appPool).DeleteMachineGroup(ctx, tid, gA.ID); err != nil {
		t.Fatalf("delete empty group A: %v", err)
	}
	if err := store.SetUserRole(ctx, tid, uid, RoleReadOnly, []string{gA.ID}); err != nil {
		t.Fatalf("preserving a dangling (deleted-group) scope must succeed, got: %v", err)
	}
	g, _ = store.GrantFor(ctx, tid, uid)
	if g.AllowsInGroup(CapViewMachines, newUUID()) {
		t.Fatal("a dangling scope must NOT become tenant-wide")
	}
	// docs/62 R1d: a dangling id expands to NOTHING, so the (now-deleted) group covers no machine at all —
	// not even itself — while the scope stays group-limited (the check above): safe deny, never a widen.
	if g.AllowsInGroup(CapViewMachines, gA.ID) {
		t.Fatal("a dangling id must cover nothing once its group is gone (docs/62 R1d)")
	}
	if ids := g.AssignmentScope().GroupIDs(); len(ids) != 1 || ids[0] != gA.ID {
		t.Fatalf("the stored scope must keep the dangling id as assigned, got %v", ids)
	}

	// Explicit empty → tenant-wide.
	if err := store.SetUserRole(ctx, tid, uid, RoleReadOnly, nil); err != nil {
		t.Fatalf("SetUserRole tenant-wide: %v", err)
	}
	g, _ = store.GrantFor(ctx, tid, uid)
	if !g.AllowsInGroup(CapViewMachines, newUUID()) {
		t.Fatal("nil scope must be tenant-wide in pg")
	}
}

// --- e2e through the real handler chain ---

// scopedFixture wires a machine-group store and returns two group ids.
func scopedFixture(t *testing.T) (*authFixture, string, string) {
	t.Helper()
	f := newUserAdminFixture(t)
	groups := NewInMemoryMachineGroupStore()
	f.srv.MachineGroups = groups
	f.auth.MachineGroups = groups
	a := &MachineGroup{Name: "Group A"}
	b := &MachineGroup{Name: "Group B"}
	if err := groups.CreateMachineGroup(context.Background(), "tenant-1", a); err != nil {
		t.Fatalf("create group A: %v", err)
	}
	if err := groups.CreateMachineGroup(context.Background(), "tenant-1", b); err != nil {
		t.Fatalf("create group B: %v", err)
	}
	return f, a.ID, b.ID
}

func TestGroupScopedInviteNoEscalation(t *testing.T) {
	f, gA, gB := scopedFixture(t)
	// A group-A-scoped admin (can manage users, but only within group A).
	f.addUserWithGrant(t, "tenant-1", "adminA", "admina@acme.test", uaPw,
		NewGrant("adminA", "tenant-1", NewMembership(RoleAdmin, Groups(gA))))
	h := f.srv.Handler()
	cookie, csrf, tok := loginFor(t, f, "admina@acme.test", uaPw)

	invite := func(email string, scope []string) int {
		body := map[string]any{"email": email, "display_name": "X", "role": string(RoleTechnician), "scoped_group_ids": scope}
		return doJSONWith(t, h, "POST", "/users", body, tok, cookie, csrf).Code
	}
	// Within the admin's scope → allowed (201 Created).
	if code := invite("in-a@acme.test", []string{gA}); code != http.StatusCreated {
		t.Errorf("invite scoped to A by an A-admin = %d, want 201", code)
	}
	// Beyond the admin's scope → forbidden (the no-escalation guard, composed with group scope).
	if code := invite("in-ab@acme.test", []string{gA, gB}); code != http.StatusForbidden {
		t.Errorf("invite scoped to {A,B} by an A-admin = %d, want 403", code)
	}
	if code := invite("in-b@acme.test", []string{gB}); code != http.StatusForbidden {
		t.Errorf("invite scoped to {B} by an A-admin = %d, want 403", code)
	}
	// Tenant-wide (explicit empty) is broader than the admin → forbidden.
	if code := invite("in-tw@acme.test", []string{}); code != http.StatusForbidden {
		t.Errorf("invite tenant-wide by an A-admin = %d, want 403", code)
	}
}

func TestGroupScopedRolePreservesScopeOnAbsentAndValidates(t *testing.T) {
	f, gA, _ := scopedFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)

	setRole := func(body map[string]any) *struct {
		code int
		ids  []string
	} {
		rec := doJSONWith(t, h, "POST", "/users/tech/role", body, tok, cookie, csrf)
		out := &struct {
			code int
			ids  []string
		}{code: rec.Code}
		var resp struct {
			ScopedGroupIDs []string `json:"scoped_group_ids"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		out.ids = resp.ScopedGroupIDs
		return out
	}

	// Scope the tech to group A.
	if r := setRole(map[string]any{"role": string(RoleTechnician), "scoped_group_ids": []string{gA}}); r.code != http.StatusOK || len(r.ids) != 1 || r.ids[0] != gA {
		t.Fatalf("scope to A = %d %v, want 200 [A]", r.code, r.ids)
	}
	// A role change that OMITS scoped_group_ids must PRESERVE the group-A scope (not widen to tenant-wide).
	if r := setRole(map[string]any{"role": string(RoleReadOnly)}); r.code != http.StatusOK || len(r.ids) != 1 || r.ids[0] != gA {
		t.Fatalf("preserve-on-absent = %d %v, want 200 [A] (must not widen)", r.code, r.ids)
	}
	// An EXPLICIT empty array is a deliberate tenant-wide assignment (the owner may do it).
	if r := setRole(map[string]any{"role": string(RoleReadOnly), "scoped_group_ids": []string{}}); r.code != http.StatusOK || len(r.ids) != 0 {
		t.Fatalf("explicit tenant-wide = %d %v, want 200 []", r.code, r.ids)
	}
	// Validation: an unknown group id → 400 (docs/62 R1a: a submitted scope names EXISTING groups only);
	// a malformed (non-uuid) id → 400.
	if r := setRole(map[string]any{"role": string(RoleReadOnly), "scoped_group_ids": []string{"00000000-0000-0000-0000-000000000000"}}); r.code != http.StatusBadRequest {
		t.Errorf("unknown group id = %d, want 400", r.code)
	}
	if r := setRole(map[string]any{"role": string(RoleReadOnly), "scoped_group_ids": []string{"not-a-uuid"}}); r.code != http.StatusBadRequest {
		t.Errorf("malformed group id = %d, want 400", r.code)
	}
}
