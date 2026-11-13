package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingBinder proves the tenant (RLS) middleware ran and pinned the expected tenant.
type recordingBinder struct{ bound string }

func (b *recordingBinder) BindTenant(ctx context.Context, tenantID string) (context.Context, func(), error) {
	b.bound = tenantID
	return ctx, nil, nil
}

func newTestServer(p *Principal) (*Server, *recordingBinder) {
	b := &recordingBinder{}
	srv := NewServer(StubAuthenticator{Principal: p}, b)
	// Mirror DEV mode: a permissive machine store so any (unenrolled) machine id resolves to the
	// default group. Handlers therefore reach their capability checks instead of 404ing.
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	// In-memory machine-property store so the property handlers reach their capability checks.
	srv.MachineProperties = NewInMemoryMachinePropertyStore()
	// In-memory data-plane stores so the (now real) session/audit/tenant handlers have backing.
	srv.SessionRecords = NewInMemorySessionRecordStore()
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	ts := NewInMemoryTenantStore()
	// Seed the standard test tenant so writes (PUT security-policy, etc.) reach a real row.
	_ = ts.CreateTenant(context.Background(), "", &Tenant{ID: "tenant-123", Slug: "test-tenant"})
	srv.Tenants = ts
	srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore()
	srv.APITokens = NewInMemoryAPITokenStore()
	srv.TenantBranding = NewInMemoryTenantBrandingStore()
	srv.SessionPolicies = NewInMemoryTenantSessionPolicyStore()
	srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
	srv.MachineGroups = NewInMemoryMachineGroupStore()
	srv.Webhooks = NewInMemoryWebhookStore()
	return srv, b
}

func TestHandlerCapabilityEnforcement(t *testing.T) {
	cases := []struct {
		name       string
		role       Role
		method     string
		path       string
		wantStatus int
	}{
		{"auditor can view audit", RoleAuditor, "GET", "/audit", http.StatusOK},
		{"technician cannot view audit", RoleTechnician, "GET", "/audit", http.StatusForbidden},
		{"readonly can list machines", RoleReadOnly, "GET", "/machines", http.StatusOK},
		{"readonly cannot list tenants", RoleReadOnly, "GET", "/tenants", http.StatusForbidden},
		{"owner can list tenants", RoleOwner, "GET", "/tenants", http.StatusOK},
		{"technician can list sessions", RoleTechnician, "GET", "/sessions", http.StatusOK},
		{"auditor cannot list sessions? (auditor has view_sessions)", RoleAuditor, "GET", "/sessions", http.StatusOK},
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
			req := httptest.NewRequest(tc.method, tc.path, nil)

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

// A group-scoped session start: a Technician scoped to one group is enforced by the handler's
// RequireMachine path. The permissive store resolves the (unenrolled) machine to the default
// group, which a Technician scoped only to "group-a" does not cover, so the request is
// forbidden — demonstrating that the handler applies group scoping (from the resolved machine),
// not just capability presence.
func TestStartSessionGroupScopedDenied(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleTechnician, Groups("group-a"))),
	}
	srv, _ := newTestServer(p)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sessions", strings.NewReader(`{"machine_id":"m-1"}`))

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped technician POST /sessions = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// Unauthenticated requests (nil principal) are rejected before reaching a handler.
func TestUnauthenticatedRejected(t *testing.T) {
	srv, _ := newTestServer(nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/machines", nil)

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil principal GET /machines = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
