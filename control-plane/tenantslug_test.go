package controlplane

import (
	"net/http"
	"strings"
	"testing"
)

func TestValidTenantSlug(t *testing.T) {
	for _, s := range []string{"main", "loam", "vc", "a", "acme-2", "9x", strings.Repeat("a", 63)} {
		if !ValidTenantSlug(s) {
			t.Errorf("ValidTenantSlug(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", strings.Repeat("a", 64), "Loam", "-x", "x-", "a_b", "a.b", "a b",
		"mäin", "www", "turn", "api", "download", "updater", "signaling"} {
		if ValidTenantSlug(s) {
			t.Errorf("ValidTenantSlug(%q) = true, want false", s)
		}
	}
}

// The platform create handler refuses a slug that cannot be a tenant hostname before reaching the
// store, and passes a valid one through.
func TestCreateTenantRefusesNonHostnameSlug(t *testing.T) {
	owner := &Principal{
		UserID:    "u1",
		TenantID:  "tenant-123",
		Grant:     NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
		SessionID: "11111111-0000-4000-8000-000000000002",
	}
	srv, _ := newTestServer(owner)
	fake := &fakePlatformStore{}
	srv.Platform = fake
	for _, slug := range []string{"Acme", "acme corp", "acme.example", "www", "turn", "-acme"} {
		body := `{"slug":"` + slug + `","name":"Acme"}`
		if code := apiJSON(t, srv, "POST", "/platform/tenants", body, nil); code != http.StatusBadRequest {
			t.Errorf("create tenant slug %q = %d, want 400", slug, code)
		}
	}
	if len(fake.created) != 0 {
		t.Fatalf("invalid slugs reached the store: %v", fake.created)
	}
	if code := apiJSON(t, srv, "POST", "/platform/tenants", `{"slug":"acme-2","name":"Acme"}`, nil); code != http.StatusCreated {
		t.Fatalf("create tenant slug acme-2 = %d, want 201", code)
	}
}
