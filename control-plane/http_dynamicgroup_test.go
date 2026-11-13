package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// newGroupServer wires a test server whose principal has `role` scoped to `scope`, tenant "tenant-123",
// with an in-memory dynamic-group store (newTestServer already wires Machines + MachineProperties).
func newGroupServer(role Role, scope GroupScope) *Server {
	p := &Principal{UserID: "u1", TenantID: "tenant-123", Grant: NewGrant("u1", "tenant-123", NewMembership(role, scope))}
	srv, _ := newTestServer(p)
	srv.DynamicGroups = NewInMemoryDynamicGroupStore()
	return srv
}

// createGroupID POSTs a dynamic group and returns its assigned id (fails the test on non-201).
func createGroupID(t *testing.T, srv *Server, body string) string {
	t.Helper()
	rec := doReq(srv, "POST", "/dynamic-groups", body, "", "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group %s = %d (%s)", body, rec.Code, rec.Body.String())
	}
	var resp struct {
		Group DynamicGroup `json:"group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Group.ID == "" {
		t.Fatalf("create response missing group.id: %s (%v)", rec.Body.String(), err)
	}
	return resp.Group.ID
}

// TestDynamicGroupCapabilityEnforcement: managing groups needs CapManageGroups (Owner/Admin); listing/
// resolving needs only CapViewMachines (a Technician has view but not manage).
func TestDynamicGroupCapabilityEnforcement(t *testing.T) {
	cases := []struct {
		role       Role
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{RoleTechnician, "POST", "/dynamic-groups", `{"name":"x","property_key":"site"}`, http.StatusForbidden}, // no manage
		{RoleTechnician, "DELETE", "/dynamic-groups/some-id", "", http.StatusForbidden},                        // no manage (before not-found)
		{RoleTechnician, "GET", "/dynamic-groups", "", http.StatusOK},                                          // has view
		{RoleReadOnly, "POST", "/dynamic-groups", `{"name":"x","property_key":"site"}`, http.StatusForbidden},
		{RoleAdmin, "POST", "/dynamic-groups", `{"name":"x","property_key":"site"}`, http.StatusCreated}, // has manage
	}
	for _, tc := range cases {
		srv := newGroupServer(tc.role, AllGroups())
		if rec := doReq(srv, tc.method, tc.path, tc.body, "", ""); rec.Code != tc.wantStatus {
			t.Fatalf("%s %s as %s = %d, want %d (%s)", tc.method, tc.path, tc.role, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}
}

// TestDynamicGroupRoundTrip: create → list → duplicate-name 409 → delete → 404 on re-delete.
func TestDynamicGroupRoundTrip(t *testing.T) {
	srv := newGroupServer(RoleOwner, AllGroups())

	id := createGroupID(t, srv, `{"name":"HQ machines","property_key":"site","property_value":"HQ"}`)

	if rec := doReq(srv, "GET", "/dynamic-groups", "", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "HQ machines") || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("list = %d %s, want the created group", rec.Code, rec.Body.String())
	}
	// A duplicate name (case-insensitive) is a 409.
	if rec := doReq(srv, "POST", "/dynamic-groups", `{"name":"hq machines","property_key":"x"}`, "", ""); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
	// Missing name/key is a 400.
	if rec := doReq(srv, "POST", "/dynamic-groups", `{"name":"","property_key":"site"}`, "", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name = %d, want 400", rec.Code)
	}
	if rec := doReq(srv, "DELETE", "/dynamic-groups/"+id, "", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doReq(srv, "GET", "/dynamic-groups", "", "", ""); strings.Contains(rec.Body.String(), id) {
		t.Fatalf("group survived delete: %s", rec.Body.String())
	}
	if rec := doReq(srv, "DELETE", "/dynamic-groups/"+id, "", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("re-delete = %d, want 404", rec.Code)
	}
}

// TestDynamicGroupResolveMembers: a group resolves LIVE to the machines matching its predicate — key
// only (any value) and key+value — and an unknown group id 404s.
func TestDynamicGroupResolveMembers(t *testing.T) {
	srv := newGroupServer(RoleOwner, AllGroups())
	ctx := context.Background()
	m1 := &Machine{DeviceID: "dev-1", GroupID: DevDefaultMachineGroupID, Name: "M1"}
	m2 := &Machine{DeviceID: "dev-2", GroupID: DevDefaultMachineGroupID, Name: "M2"}
	m3 := &Machine{DeviceID: "dev-3", GroupID: DevDefaultMachineGroupID, Name: "M3"}
	for _, m := range []*Machine{m1, m2, m3} {
		if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
			t.Fatalf("enroll %s: %v", m.Name, err)
		}
	}
	_ = srv.MachineProperties.SetProperty(ctx, "tenant-123", m1.ID, "site", "HQ")
	_ = srv.MachineProperties.SetProperty(ctx, "tenant-123", m2.ID, "site", "DR")
	// m3 has no `site` property.

	// A group keyed on site=HQ resolves to ONLY m1.
	hqID := createGroupID(t, srv, `{"name":"hq","property_key":"site","property_value":"HQ"}`)
	if rec := doReq(srv, "GET", "/dynamic-groups/"+hqID+"/machines", "", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), m1.ID) || strings.Contains(rec.Body.String(), m2.ID) || strings.Contains(rec.Body.String(), m3.ID) {
		t.Fatalf("resolve site=HQ = %d %s, want only m1", rec.Code, rec.Body.String())
	}
	// A group keyed on site (any value) resolves to m1 AND m2, but NOT m3 (no site property).
	anyID := createGroupID(t, srv, `{"name":"any-site","property_key":"site"}`)
	if rec := doReq(srv, "GET", "/dynamic-groups/"+anyID+"/machines", "", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), m1.ID) || !strings.Contains(rec.Body.String(), m2.ID) || strings.Contains(rec.Body.String(), m3.ID) {
		t.Fatalf("resolve site=any = %d %s, want m1 and m2 but not m3", rec.Code, rec.Body.String())
	}
	// An unknown group id is a 404.
	if rec := doReq(srv, "GET", "/dynamic-groups/00000000-0000-0000-0000-000000000000/machines", "", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("resolve unknown = %d, want 404", rec.Code)
	}
}

// TestDynamicGroupResolveNarrowsToVisible proves the resolution NEVER widens the caller's reach: a
// machine that MATCHES the predicate but sits in a group the caller cannot see is NOT returned — the
// same AllowsInGroup narrowing GET /machines uses.
func TestDynamicGroupResolveNarrowsToVisible(t *testing.T) {
	// Caller is an Owner but scoped to group-A ONLY.
	srv := newGroupServer(RoleOwner, Groups("group-A"))
	ctx := context.Background()
	visible := &Machine{DeviceID: "dev-a", GroupID: "group-A", Name: "A"}
	hidden := &Machine{DeviceID: "dev-b", GroupID: "group-B", Name: "B"}
	for _, m := range []*Machine{visible, hidden} {
		if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m); err != nil {
			t.Fatalf("enroll %s: %v", m.Name, err)
		}
	}
	// BOTH machines carry env=prod, so BOTH match the predicate — only group-scope should differ.
	_ = srv.MachineProperties.SetProperty(ctx, "tenant-123", visible.ID, "env", "prod")
	_ = srv.MachineProperties.SetProperty(ctx, "tenant-123", hidden.ID, "env", "prod")

	id := createGroupID(t, srv, `{"name":"prod","property_key":"env","property_value":"prod"}`)
	rec := doReq(srv, "GET", "/dynamic-groups/"+id+"/machines", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), visible.ID) {
		t.Fatalf("resolve missing the visible group-A machine: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), hidden.ID) {
		t.Fatalf("resolve LEAKED a group-B machine the caller cannot see: %s", rec.Body.String())
	}
}

// TestDynamicGroupStoreUnconfigured: the handlers fail CLOSED (500) when the store is not wired.
func TestDynamicGroupStoreUnconfigured(t *testing.T) {
	p := &Principal{UserID: "u1", TenantID: "tenant-123", Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(p) // does NOT wire DynamicGroups
	if rec := doReq(srv, "GET", "/dynamic-groups", "", "", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("unconfigured GET = %d, want 500", rec.Code)
	}
}
