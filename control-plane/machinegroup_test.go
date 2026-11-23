package controlplane

// Proofs for static machine group management (docs/01 §4): the store (fake + pg under RLS), and the
// HTTP surface (CapManageGroups to create, CapViewMachines to list, validation + audit).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestInMemoryMachineGroupStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineGroupStore()

	// An empty tenant lists nothing.
	if gs, err := s.ListMachineGroups(ctx, "t1"); err != nil || len(gs) != 0 {
		t.Fatalf("empty list = %+v, %v", gs, err)
	}

	// Create assigns an id; the listing is ordered by (name, id). Duplicate names are allowed.
	a := &MachineGroup{Name: "Front Office"}
	b := &MachineGroup{Name: "Back Office"}
	dup := &MachineGroup{Name: "Front Office"}
	for _, g := range []*MachineGroup{a, b, dup} {
		if err := s.CreateMachineGroup(ctx, "t1", g); err != nil {
			t.Fatalf("create %q: %v", g.Name, err)
		}
		if g.ID == "" {
			t.Fatalf("create did not assign an id to %q", g.Name)
		}
	}
	// Another tenant is isolated.
	if err := s.CreateMachineGroup(ctx, "t2", &MachineGroup{Name: "Other"}); err != nil {
		t.Fatalf("create t2: %v", err)
	}

	gs, err := s.ListMachineGroups(ctx, "t1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(gs) != 3 {
		t.Fatalf("t1 groups = %d, want 3 (t2 excluded)", len(gs))
	}
	// Ordered by name: Back Office, then the two Front Office (tie-broken by id).
	if gs[0].Name != "Back Office" || gs[1].Name != "Front Office" || gs[2].Name != "Front Office" {
		t.Fatalf("order = %+v, want [Back Office, Front Office, Front Office]", gs)
	}
	if gs[1].ID >= gs[2].ID {
		t.Fatalf("duplicate names must tie-break by ascending id: %s vs %s", gs[1].ID, gs[2].ID)
	}
}

func machineGroupSrv(t *testing.T, role Role) (http.Handler, *Server) {
	t.Helper()
	p := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(role, AllGroups()))}
	srv, _ := newTestServer(p)
	return srv.Handler(), srv
}

func TestMachineGroupHandler(t *testing.T) {
	h, srv := machineGroupSrv(t, RoleOwner)
	post := func(hh http.Handler, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rec
	}
	get := func(hh http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	// Owner creates a group → 201 with the assigned id, and it is audited.
	rec := post(h, "/machine-groups", `{"name":"HQ"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var cr struct {
		MachineGroup MachineGroup `json:"machine_group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cr.MachineGroup.ID == "" || cr.MachineGroup.Name != "HQ" {
		t.Fatalf("created group = %+v", cr.MachineGroup)
	}
	audit := get(h, "/audit?action=machine_group.created")
	var ar struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	_ = json.Unmarshal(audit.Body.Bytes(), &ar)
	if len(ar.Events) != 1 || ar.Events[0].TargetID != cr.MachineGroup.ID {
		t.Fatalf("audit = %+v, want one machine_group.created for %s", ar.Events, cr.MachineGroup.ID)
	}

	// GET lists it.
	list := get(h, "/machine-groups")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"HQ"`) {
		t.Fatalf("list = %d body %s, want 200 with HQ", list.Code, list.Body.String())
	}

	// Empty name → 400; a control character → 400.
	if rec := post(h, "/machine-groups", `{"name":"   "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name = %d, want 400", rec.Code)
	}
	if rec := post(h, "/machine-groups", `{"name":"badbell"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("control-char name = %d, want 400", rec.Code)
	}

	// GATE: a Technician (no CapManageGroups) cannot create, but CAN list (CapViewMachines).
	techH, _ := machineGroupSrv(t, RoleTechnician)
	if rec := post(techH, "/machine-groups", `{"name":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("technician create = %d, want 403", rec.Code)
	}
	if rec := get(techH, "/machine-groups"); rec.Code != http.StatusOK {
		t.Fatalf("technician list = %d, want 200", rec.Code)
	}
	_ = srv
}

// TestMachineGroupListNarrowsToScope proves GET /machine-groups applies the SAME AllowsInGroup narrowing
// as GET /machines: a viewer scoped to one group sees only that group, never the others (no id/name leak
// of out-of-scope groups). A tenant-wide viewer sees all (a no-op).
func TestMachineGroupListNarrowsToScope(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryMachineGroupStore()
	g1 := &MachineGroup{Name: "Alpha"}
	g2 := &MachineGroup{Name: "Beta"}
	for _, g := range []*MachineGroup{g1, g2} {
		if err := store.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	list := func(p *Principal) []MachineGroup {
		srv, _ := newTestServer(p)
		srv.MachineGroups = store // inject the pre-populated store shared across principals
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/machine-groups", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		var lr struct {
			MachineGroups []MachineGroup `json:"machine_groups"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return lr.MachineGroups
	}

	// A viewer scoped to g1 ONLY sees g1.
	scoped := &Principal{UserID: "v", TenantID: "tenant-123",
		Grant: NewGrant("v", "tenant-123", NewMembership(RoleReadOnly, Groups(g1.ID)))}
	if got := list(scoped); len(got) != 1 || got[0].ID != g1.ID {
		t.Fatalf("scoped viewer groups = %+v, want only g1 (%s)", got, g1.ID)
	}
	// A tenant-wide viewer sees both.
	wide := &Principal{UserID: "o", TenantID: "tenant-123",
		Grant: NewGrant("o", "tenant-123", NewMembership(RoleReadOnly, AllGroups()))}
	if got := list(wide); len(got) != 2 {
		t.Fatalf("tenant-wide viewer groups = %+v, want both", got)
	}
}

func TestValidateMachineGroupName(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantOK   bool
		wantNorm string
	}{
		{"HQ", true, "HQ"},
		{"  Front Office  ", true, "Front Office"}, // trimmed
		{"", false, ""},
		{"   ", false, ""},
		{"bad\x07bell", false, "bad\x07bell"}, // BEL control char
		{strings.Repeat("x", maxMachineGroupNameLen), true, strings.Repeat("x", maxMachineGroupNameLen)},
		{strings.Repeat("x", maxMachineGroupNameLen+1), false, strings.Repeat("x", maxMachineGroupNameLen+1)},
	} {
		got, ok := validateMachineGroupName(tc.in)
		if ok != tc.wantOK || got != tc.wantNorm {
			t.Fatalf("validate(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.wantNorm, tc.wantOK)
		}
	}
}

func TestInMemoryMachineGroupRenameDelete(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachineGroupStore()
	g := &MachineGroup{Name: "A"}
	if err := s.CreateMachineGroup(ctx, "t1", g); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Rename.
	if err := s.RenameMachineGroup(ctx, "t1", g.ID, "B"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if gs, _ := s.ListMachineGroups(ctx, "t1"); len(gs) != 1 || gs[0].Name != "B" {
		t.Fatalf("after rename = %+v, want [B]", gs)
	}
	// Rename a missing id, or another tenant's id, is not-found (tenant isolation).
	if err := s.RenameMachineGroup(ctx, "t1", newUUID(), "X"); err != ErrMachineGroupNotFound {
		t.Fatalf("rename missing = %v, want not-found", err)
	}
	if err := s.RenameMachineGroup(ctx, "t2", g.ID, "X"); err != ErrMachineGroupNotFound {
		t.Fatalf("cross-tenant rename = %v, want not-found", err)
	}
	// Delete, then a second delete is not-found.
	if err := s.DeleteMachineGroup(ctx, "t1", g.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gs, _ := s.ListMachineGroups(ctx, "t1"); len(gs) != 0 {
		t.Fatalf("after delete = %+v, want empty", gs)
	}
	if err := s.DeleteMachineGroup(ctx, "t1", g.ID); err != ErrMachineGroupNotFound {
		t.Fatalf("delete again = %v, want not-found", err)
	}
}

func TestMachineGroupRenameDeleteHandler(t *testing.T) {
	h, srv := machineGroupSrv(t, RoleOwner)
	ctx := context.Background()
	do := func(hh http.Handler, method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	g := &MachineGroup{Name: "HQ"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	// RENAME → 200; the name changed.
	if rec := do(h, "PATCH", "/machine-groups/"+g.ID, `{"name":"Renamed HQ"}`); rec.Code != http.StatusOK {
		t.Fatalf("rename = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if gs, _ := srv.MachineGroups.ListMachineGroups(ctx, "tenant-123"); gs[0].Name != "Renamed HQ" {
		t.Fatalf("name after rename = %q, want Renamed HQ", gs[0].Name)
	}
	// Bad name → 400; a missing group → 404.
	if rec := do(h, "PATCH", "/machine-groups/"+g.ID, `{"name":"   "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rename empty = %d, want 400", rec.Code)
	}
	if rec := do(h, "PATCH", "/machine-groups/"+newUUID(), `{"name":"X"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("rename missing = %d, want 404", rec.Code)
	}

	// DELETE refused (409) while the group still has a machine.
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", &Machine{DeviceID: "dev-x", GroupID: g.ID}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if rec := do(h, "DELETE", "/machine-groups/"+g.ID, ""); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "machines") {
		t.Fatalf("delete with machine = %d body %q, want 409 (has machines)", rec.Code, rec.Body.String())
	}
	// An EMPTY group deletes cleanly (200); a second delete is 404.
	empty := &MachineGroup{Name: "Temp"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", empty); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	if rec := do(h, "DELETE", "/machine-groups/"+empty.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete empty = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "DELETE", "/machine-groups/"+empty.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again = %d, want 404", rec.Code)
	}

	// GATE: a Technician (no CapManageGroups) can neither rename nor delete.
	techH, _ := machineGroupSrv(t, RoleTechnician)
	if rec := do(techH, "PATCH", "/machine-groups/"+g.ID, `{"name":"nope"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("technician rename = %d, want 403", rec.Code)
	}
	if rec := do(techH, "DELETE", "/machine-groups/"+g.ID, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("technician delete = %d, want 403", rec.Code)
	}
}

// TestPgMachineGroupRenameDelete drives PgMachineGroupStore.Rename + Delete as rmt_app: rename is
// RLS-scoped (another tenant's group is not-found), delete refuses a group a machine FK-references
// (23503 → ErrMachineGroupInUse), and an empty group deletes then reports not-found on a repeat.
func TestPgMachineGroupRenameDelete(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "mgd-a", "a@mgd-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "mgd-b", "b@mgd-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineGroupStore(appPool)

	g := &MachineGroup{Name: "Orig"}
	if err := store.CreateMachineGroup(ctx, tidA, g); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.RenameMachineGroup(ctx, tidA, g.ID, "Renamed"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if gs, _ := store.ListMachineGroups(ctx, tidA); len(gs) != 1 || gs[0].Name != "Renamed" {
		t.Fatalf("after rename = %+v, want [Renamed]", gs)
	}
	// Cross-tenant rename is not-found (RLS hides A's group from B); a non-uuid id likewise.
	if err := store.RenameMachineGroup(ctx, tidB, g.ID, "Hax"); err != ErrMachineGroupNotFound {
		t.Fatalf("cross-tenant rename = %v, want not-found", err)
	}
	if err := store.RenameMachineGroup(ctx, tidA, "not-a-uuid", "x"); err != ErrMachineGroupNotFound {
		t.Fatalf("non-uuid rename = %v, want not-found", err)
	}

	// A machine FK-references the group → delete is refused with ErrMachineGroupInUse (23503).
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (tenant_id, device_id, group_id, pubkey) VALUES ($1,'dev-mgd',$2,'\x00')`, tidA, g.ID)
		return err
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	if err := store.DeleteMachineGroup(ctx, tidA, g.ID); err != ErrMachineGroupInUse {
		t.Fatalf("delete referenced group = %v, want ErrMachineGroupInUse", err)
	}

	// An empty group deletes cleanly, then a repeat is not-found.
	empty := &MachineGroup{Name: "Empty"}
	if err := store.CreateMachineGroup(ctx, tidA, empty); err != nil {
		t.Fatalf("create empty: %v", err)
	}
	if err := store.DeleteMachineGroup(ctx, tidA, empty.ID); err != nil {
		t.Fatalf("delete empty: %v", err)
	}
	if err := store.DeleteMachineGroup(ctx, tidA, empty.ID); err != ErrMachineGroupNotFound {
		t.Fatalf("delete again = %v, want not-found", err)
	}
}

// TestPgMachineGroupStore drives PgMachineGroupStore.Create + List as rmt_app: a created group is
// listed in the caller's tenant, ordered by (name, id), and is invisible in another tenant (RLS).
func TestPgMachineGroupStore(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "mg-a", "a@mg-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "mg-b", "b@mg-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineGroupStore(appPool)

	a := &MachineGroup{Name: "Zeta"}
	b := &MachineGroup{Name: "Alpha"}
	if err := store.CreateMachineGroup(ctx, tidA, a); err != nil {
		t.Fatalf("create A/Zeta: %v", err)
	}
	if err := store.CreateMachineGroup(ctx, tidA, b); err != nil {
		t.Fatalf("create A/Alpha: %v", err)
	}
	if a.ID == "" || b.ID == "" {
		t.Fatalf("pg create did not assign ids: %q %q", a.ID, b.ID)
	}
	if err := store.CreateMachineGroup(ctx, tidB, &MachineGroup{Name: "Bravo"}); err != nil {
		t.Fatalf("create B: %v", err)
	}

	// A's listing is RLS-scoped + ordered by name: Alpha before Zeta; B's group is absent.
	gsA, err := store.ListMachineGroups(ctx, tidA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(gsA) != 2 || gsA[0].Name != "Alpha" || gsA[1].Name != "Zeta" {
		t.Fatalf("A groups = %+v, want [Alpha, Zeta]", gsA)
	}
	for _, g := range gsA {
		if g.Name == "Bravo" {
			t.Fatal("A's listing leaked B's group")
		}
	}
	// Sanity: B sees only its own.
	gsB, _ := store.ListMachineGroups(ctx, tidB)
	if len(gsB) != 1 || gsB[0].Name != "Bravo" {
		t.Fatalf("B groups = %+v, want [Bravo]", gsB)
	}

	// The created group id is real — a machine can enroll into it (composite FK satisfied), proving the
	// group actually exists in the tenant.
	if err := withTenant(ctx, suPool, tidA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO machine (tenant_id, device_id, group_id, pubkey) VALUES ($1,'dev-mg',$2,'\x00')`, tidA, a.ID)
		return err
	}); err != nil {
		t.Fatalf("a machine could not enroll into the created group (FK): %v", err)
	}
}
