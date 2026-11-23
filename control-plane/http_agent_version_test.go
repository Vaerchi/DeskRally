package controlplane

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestGetAgentVersionNotConfigured: when PublishedAgentVersion is empty, the endpoint
// returns 200 with configured=false and no version field.
func TestGetAgentVersionNotConfigured(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))
	// srv.PublishedAgentVersion is "" by default.

	rec := doJSON(t, srv.Handler(), "GET", "/agent-version", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /agent-version = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["configured"] != false {
		t.Fatalf("configured = %v, want false", resp["configured"])
	}
	if _, ok := resp["version"]; ok {
		t.Fatalf("version key must be absent when not configured, got %v", resp["version"])
	}
}

// TestGetAgentVersionConfigured: when PublishedAgentVersion is set, the endpoint returns the
// version string and configured=true.
func TestGetAgentVersionConfigured(t *testing.T) {
	const want = "0.0.1+abc1234"
	srv, _ := newTestServer(ownerPrincipal("u1"))
	srv.PublishedAgentVersion = want

	rec := doJSON(t, srv.Handler(), "GET", "/agent-version", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /agent-version = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["configured"] != true {
		t.Fatalf("configured = %v, want true", resp["configured"])
	}
	if resp["version"] != want {
		t.Fatalf("version = %v, want %q", resp["version"], want)
	}
}

// TestGetAgentVersionRequiresCapViewMachines: a principal without CapViewMachines is denied.
// Every preset role carries CapViewMachines; we construct a custom grant with only
// CapViewSessions to exercise the denial path without relying on a "no machines" preset.
func TestGetAgentVersionRequiresCapViewMachines(t *testing.T) {
	t.Run("owner can read", func(t *testing.T) {
		srv, _ := newTestServer(ownerPrincipal("u1"))
		srv.PublishedAgentVersion = "0.0.1+abc1234"
		rec := doJSON(t, srv.Handler(), "GET", "/agent-version", nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("owner GET /agent-version = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("technician can read (has CapViewMachines)", func(t *testing.T) {
		p := &Principal{
			UserID:   "u1",
			TenantID: "tenant-123",
			Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleTechnician, AllGroups())),
		}
		srv, _ := newTestServer(p)
		srv.PublishedAgentVersion = "0.0.1+abc1234"
		rec := doJSON(t, srv.Handler(), "GET", "/agent-version", nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("technician GET /agent-version = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
	})

	// Denial: a custom grant with CapViewSessions only — no CapViewMachines. All preset roles
	// carry CapViewMachines, so we must use NewCapabilityMembership to exercise the 403 path.
	t.Run("view-sessions-only grant denied", func(t *testing.T) {
		p := &Principal{
			UserID:   "u1",
			TenantID: "tenant-123",
			Grant:    NewGrant("u1", "tenant-123", NewCapabilityMembership([]Capability{CapViewSessions}, AllGroups())),
		}
		srv, _ := newTestServer(p)
		srv.PublishedAgentVersion = "0.0.1+abc1234"
		rec := doJSON(t, srv.Handler(), "GET", "/agent-version", nil, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("view-sessions-only grant GET /agent-version = %d, want 403 (body %s)",
				rec.Code, rec.Body.String())
		}
	})
}
