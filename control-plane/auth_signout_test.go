package controlplane

// Proofs for admin "sign out user" (POST /users/{id}/sign-out): it REVOKES the target's live login sessions
// (forcing re-login) WITHOUT disabling the account, gated exactly like disable — CapManageUsers + the
// canAdministerUser hierarchy — through the REAL login → session → protected-request flow.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestUserAdminSignOut(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", uaPw, RoleAdmin)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()

	// The tech logs in → a live session; a protected request with their cookie is NOT 401.
	techCookie, _, _ := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSON(t, h, "GET", "/machines", nil, techCookie); rec.Code == http.StatusUnauthorized {
		t.Fatalf("tech session should be live before sign-out (got 401)")
	}

	// Owner signs the tech out → 200 and revokes at least the one live session.
	ownerCookie, ownerCSRF, ownerTok := loginFor(t, f, "owner@acme.test", uaPw)
	rec := doJSONWith(t, h, "POST", "/users/tech/sign-out", nil, ownerTok, ownerCookie, ownerCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign out tech = %d: %s", rec.Code, rec.Body.String())
	}
	var sr struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr.Revoked < 1 {
		t.Fatalf("revoked = %d, want >= 1", sr.Revoked)
	}
	// The tech's session is now revoked → a protected request with their cookie is 401.
	if rec := doJSON(t, h, "GET", "/machines", nil, techCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tech session should be revoked after sign-out, got %d", rec.Code)
	}
	// BUT the tech can log in AGAIN — sign-out is not a disable.
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@acme.test", Password: uaPw}, nil); rec.Code != http.StatusOK {
		t.Fatalf("tech must log in again after sign-out (not disabled), got %d: %s", rec.Code, rec.Body.String())
	}

	// HIERARCHY: an Admin CANNOT sign out the Owner (Admin lacks CapManageTenant the Owner holds) → 403,
	// but CAN sign out a Technician (a subset of the Admin's authority) → 200.
	adminCookie, adminCSRF, adminTok := loginFor(t, f, "admin@acme.test", uaPw)
	if rec := doJSONWith(t, h, "POST", "/users/owner/sign-out", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin signing out owner = %d, want 403", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/users/tech/sign-out", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusOK {
		t.Fatalf("admin signing out tech = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// An unknown user → 404.
	if rec := doJSONWith(t, h, "POST", "/users/nobody/sign-out", nil, ownerTok, ownerCookie, ownerCSRF); rec.Code != http.StatusNotFound {
		t.Fatalf("sign out unknown = %d, want 404", rec.Code)
	}
	// A Technician holds no CapManageUsers → 403, even signing out THEMSELVES — a user they could otherwise
	// administer, which ISOLATES the capability gate from the hierarchy gate (only the missing cap stops it).
	techCookie2, techCSRF2, techTok2 := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSONWith(t, h, "POST", "/users/tech/sign-out", nil, techTok2, techCookie2, techCSRF2); rec.Code != http.StatusForbidden {
		t.Fatalf("technician signing self out = %d, want 403 (no CapManageUsers)", rec.Code)
	}
}
