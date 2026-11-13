package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestGetTenantSecurityPolicy: GET /tenant/security-policy returns the stored policy.
func TestGetTenantSecurityPolicy(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	rec := doJSON(t, srv.Handler(), "GET", "/tenant/security-policy", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tenant/security-policy = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "require_2fa") {
		t.Fatalf("response %q missing require_2fa key", rec.Body.String())
	}
}

// TestSetTenantSecurityPolicyRequiresOwner: a Technician (no CapManageTenant) is denied.
func TestSetTenantSecurityPolicyRequiresOwner(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleTechnician, AllGroups())),
	}
	srv, _ := newTestServer(p)

	rec := doJSON(t, srv.Handler(), "PUT", "/tenant/security-policy", map[string]any{"require_2fa": false}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician PUT /tenant/security-policy = %d, want 403", rec.Code)
	}
}

// TestSetTenantSecurityPolicyRequire2FAWithNoAuthAPI: enabling require_2fa when AuthAPI is nil
// must fail closed (500) rather than skip the anti-lockout check and write the policy.
func TestSetTenantSecurityPolicyRequire2FAWithNoAuthAPI(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))
	// srv.AuthAPI is nil by default in newTestServer.

	rec := doJSON(t, srv.Handler(), "PUT", "/tenant/security-policy", map[string]any{"require_2fa": true}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("require_2fa=true with nil AuthAPI = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestSetTenantSecurityPolicyAntiLockout: an Owner without TOTP cannot enable require_2fa.
func TestSetTenantSecurityPolicyAntiLockout(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	// Wire a real AuthService with an in-memory user store. The caller (u1) has no TOTP enrollment.
	users := NewInMemoryUserStore()
	users.AddUser(&AuthUser{ID: "u1", TenantID: "tenant-123", Email: "owner@example.com"}, nil)
	srv.AuthAPI = &AuthService{Users: users, Sessions: NewSessionManager(NewInMemorySessionStore()), Issuer: "test"}

	rec := doJSON(t, srv.Handler(), "PUT", "/tenant/security-policy", map[string]any{"require_2fa": true}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("anti-lockout PUT require_2fa=true without enrollment = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "anti-lockout") {
		t.Fatalf("400 body %q missing anti-lockout message", rec.Body.String())
	}
}

// TestSetTenantSecurityPolicyAntiLockoutAllowsEnrolled: an Owner WITH TOTP confirmed CAN enable require_2fa.
func TestSetTenantSecurityPolicyAntiLockoutAllowsEnrolled(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	users := NewInMemoryUserStore()
	users.AddUser(&AuthUser{ID: "u1", TenantID: "tenant-123", Email: "owner@example.com"}, nil)
	secret, _ := GenerateTOTPSecret()
	_ = users.SetTOTP(context.Background(), "tenant-123", "u1", secret, true)
	srv.AuthAPI = &AuthService{Users: users, Sessions: NewSessionManager(NewInMemorySessionStore()), Issuer: "test"}

	rec := doJSON(t, srv.Handler(), "PUT", "/tenant/security-policy", map[string]any{"require_2fa": true}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enrolled owner enabling require_2fa = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	// Disabling require_2fa does NOT trigger the anti-lockout check.
	rec = doJSON(t, srv.Handler(), "PUT", "/tenant/security-policy", map[string]any{"require_2fa": false}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabling require_2fa = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}
