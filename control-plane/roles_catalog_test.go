package controlplane

// Proof for the §5 ROLES REFERENCE (GET /roles): the assignable preset roles + the capabilities each grants,
// sourced from AssignableRoles() + Role.Capabilities() (so it cannot drift from what the server enforces),
// gated on CapManageRoles (the role-assignment audience). Read-only reference — closes the role-assignment
// loop (loop 48 assigns roles by NAME; this shows what those names permit).

import (
	"encoding/json"
	"net/http"
	"testing"
)

func hasCap(caps []string, c Capability) bool {
	for _, x := range caps {
		if x == string(c) {
			return true
		}
	}
	return false
}

func TestListRolesHandler(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()

	// Owner (holds CapManageRoles) → 200 with the full catalog.
	ownerCookie, _, _ := loginFor(t, f, "owner@acme.test", uaPw)
	rec := doJSON(t, h, "GET", "/roles", nil, ownerCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner GET /roles = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Roles []struct {
			Role         string   `json:"role"`
			Capabilities []string `json:"capabilities"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byRole := map[string][]string{}
	for _, r := range resp.Roles {
		byRole[r.Role] = r.Capabilities
	}
	// All FIVE assignable presets are present (the catalog matches AssignableRoles()).
	if len(resp.Roles) != len(AssignableRoles()) || len(resp.Roles) != 5 {
		t.Fatalf("roles = %d, want 5: %+v", len(resp.Roles), resp.Roles)
	}
	// Owner grants EVERY capability (incl. tenant admin).
	if owner := byRole["owner"]; len(owner) != len(AllCapabilities) || !hasCap(owner, CapManageTenant) {
		t.Fatalf("owner caps = %v, want all %d incl. manage_tenant", owner, len(AllCapabilities))
	}
	// Technician grants the work subset but NEITHER tenant admin NOR role management (proves it's the REAL
	// per-role set, not a blanket list).
	tech := byRole["technician"]
	if !hasCap(tech, CapStartSession) || hasCap(tech, CapManageTenant) || hasCap(tech, CapManageRoles) {
		t.Fatalf("technician caps = %v, want start_session but NOT manage_tenant/manage_roles", tech)
	}
	// ReadOnly is view-only (no write cap).
	if ro := byRole["readonly"]; !hasCap(ro, CapViewMachines) || hasCap(ro, CapManageMachines) {
		t.Fatalf("readonly caps = %v, want view_machines but NOT manage_machines", ro)
	}

	// A Technician holds no CapManageRoles → 403 (the catalog is admin-only).
	techCookie, _, _ := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSON(t, h, "GET", "/roles", nil, techCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("technician GET /roles = %d, want 403", rec.Code)
	}
}
