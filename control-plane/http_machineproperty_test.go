package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMachinePropertyCapabilityEnforcement pins the group-scoped authz: reading properties needs
// CapViewMachines, writing needs CapManageMachines, both against the machine's REAL group. The
// permissive machine store resolves "m-1" to a synthetic machine in DevDefaultMachineGroupID and the
// AllGroups() membership covers it, so ONLY the capability differs across roles.
func TestMachinePropertyCapabilityEnforcement(t *testing.T) {
	cases := []struct {
		name       string
		role       Role
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{"readonly can list props", RoleReadOnly, "GET", "/machines/m-1/properties", "", http.StatusOK},
		{"readonly cannot set prop", RoleReadOnly, "PUT", "/machines/m-1/properties/site", `{"value":"HQ"}`, http.StatusForbidden},
		{"technician cannot set prop", RoleTechnician, "PUT", "/machines/m-1/properties/site", `{"value":"HQ"}`, http.StatusForbidden},
		{"admin can set prop", RoleAdmin, "PUT", "/machines/m-1/properties/site", `{"value":"HQ"}`, http.StatusOK},
		{"technician cannot delete prop", RoleTechnician, "DELETE", "/machines/m-1/properties/site", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Principal{
				UserID:   "u1",
				TenantID: "tenant-123",
				Grant:    NewGrant("u1", "tenant-123", NewMembership(tc.role, AllGroups())),
			}
			srv, binder := newTestServer(p)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s as %s = %d, want %d (body %s)",
					tc.method, tc.path, tc.role, rec.Code, tc.wantStatus, rec.Body.String())
			}
			// The RLS hook must have pinned the caller's tenant on any authorized request.
			if binder.bound != "tenant-123" {
				t.Fatalf("tenant middleware bound %q, want %q", binder.bound, "tenant-123")
			}
		})
	}
}

// TestMachinePropertyRoundTrip drives PUT -> GET -> DELETE -> DELETE(404) as an Owner (all caps),
// asserting the upsert value is echoed, listed, then a second delete of the gone key 404s.
func TestMachinePropertyRoundTrip(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	if rec := do("PUT", "/machines/m-1/properties/site", `{"value":"HQ"}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"HQ"`) || !strings.Contains(rec.Body.String(), `"property"`) {
		t.Fatalf("PUT = %d body %s, want 200 with {\"property\":{...\"HQ\"...}}", rec.Code, rec.Body.String())
	}
	if rec := do("GET", "/machines/m-1/properties", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"site"`) || !strings.Contains(rec.Body.String(), `"HQ"`) {
		t.Fatalf("GET = %d body %s, want 200 listing site=HQ", rec.Code, rec.Body.String())
	}
	if rec := do("DELETE", "/machines/m-1/properties/site", ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := do("GET", "/machines/m-1/properties", ""); rec.Code != http.StatusOK ||
		strings.Contains(rec.Body.String(), `"site"`) {
		t.Fatalf("GET after delete = %d body %s, want 200 without site", rec.Code, rec.Body.String())
	}
	if rec := do("DELETE", "/machines/m-1/properties/site", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("second DELETE = %d, want 404", rec.Code)
	}
}

// TestMachinePropertyStoreUnconfigured proves the handlers fail CLOSED (500) rather than nil-panic
// when the property store is not wired.
func TestMachinePropertyStoreUnconfigured(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	srv.MachineProperties = nil // unwire it
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/machines/m-1/properties", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET with no property store = %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
}

// TestMachineFleetPropertyFilter drives GET /machines?property_key=…[&property_value=…] and asserts
// the filter NARROWS the fleet to matching machines only — and never widens it.
func TestMachineFleetPropertyFilter(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)
	ctx := context.Background()

	// Two enrolled machines; site=HQ on m1 only.
	m1 := &Machine{DeviceID: "dev-1", GroupID: DevDefaultMachineGroupID, Name: "M1"}
	m2 := &Machine{DeviceID: "dev-2", GroupID: DevDefaultMachineGroupID, Name: "M2"}
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m1); err != nil {
		t.Fatalf("enroll m1: %v", err)
	}
	if err := srv.Machines.EnrollMachine(ctx, "tenant-123", m2); err != nil {
		t.Fatalf("enroll m2: %v", err)
	}
	if err := srv.MachineProperties.SetProperty(ctx, "tenant-123", m1.ID, "site", "HQ"); err != nil {
		t.Fatalf("set property: %v", err)
	}

	body := func(query string) string {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/machines"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /machines%s = %d (%s)", query, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	// Unfiltered: BOTH machines.
	if b := body(""); !strings.Contains(b, m1.ID) || !strings.Contains(b, m2.ID) {
		t.Fatalf("unfiltered listing missing a machine: %s", b)
	}
	// Filter by key (any value): only m1.
	if b := body("?property_key=site"); !strings.Contains(b, m1.ID) || strings.Contains(b, m2.ID) {
		t.Fatalf("?property_key=site should list only m1: %s", b)
	}
	// Filter by key+value: only m1.
	if b := body("?property_key=site&property_value=HQ"); !strings.Contains(b, m1.ID) || strings.Contains(b, m2.ID) {
		t.Fatalf("?property_key=site&property_value=HQ should list only m1: %s", b)
	}
	// Filter by a value nobody has: NEITHER machine.
	if b := body("?property_key=site&property_value=NOPE"); strings.Contains(b, m1.ID) || strings.Contains(b, m2.ID) {
		t.Fatalf("?property_value=NOPE should list no machines: %s", b)
	}
}
