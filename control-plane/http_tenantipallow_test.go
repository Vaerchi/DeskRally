package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newAllowlistServer wires an in-memory per-tenant allow-list onto a test server for principal role,
// tenant "tenant-123". Returns the server and the store (so a test can seed entries directly).
func newAllowlistServer(role Role) (*Server, *InMemoryTenantIPAllowlistStore) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(role, AllGroups())),
	}
	srv, _ := newTestServer(p)
	store := NewInMemoryTenantIPAllowlistStore()
	srv.TenantIPAllowlist = store
	return srv, store
}

// doReq drives one request through the full Handler() chain. `remote`/`xff` set the source address the
// allow-list judges (default httptest RemoteAddr 192.0.2.1 when remote is "").
func doReq(srv *Server, method, path, body, remote, xff string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if remote != "" {
		req.RemoteAddr = remote
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// TestTenantIPAllowlistCapabilityEnforcement: managing the list needs CapManageTenant (Owner-only).
func TestTenantIPAllowlistCapabilityEnforcement(t *testing.T) {
	cases := []struct {
		role       Role
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{RoleOwner, "GET", "/tenant/ip-allowlist", "", http.StatusOK},
		{RoleAdmin, "GET", "/tenant/ip-allowlist", "", http.StatusForbidden},    // Admin lacks CapManageTenant
		{RoleAdmin, "POST", "/tenant/ip-allowlist", `{"cidr":"0.0.0.0/0"}`, http.StatusForbidden},
		{RoleReadOnly, "DELETE", "/tenant/ip-allowlist?cidr=10.0.0.0/8", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		srv, _ := newAllowlistServer(tc.role)
		if rec := doReq(srv, tc.method, tc.path, tc.body, "", ""); rec.Code != tc.wantStatus {
			t.Fatalf("%s %s as %s = %d, want %d (%s)", tc.method, tc.path, tc.role, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}
}

// TestTenantIPAllowlistRoundTrip: add a CIDR covering the caller, list it (+ your_ip), delete it,
// and prove a second delete of a gone entry 404s. Owner (all caps), default source 192.0.2.1.
func TestTenantIPAllowlistRoundTrip(t *testing.T) {
	srv, _ := newAllowlistServer(RoleOwner)

	// Add a CIDR that covers the default caller IP (192.0.2.1) so the anti-lockout allows it.
	if rec := doReq(srv, "POST", "/tenant/ip-allowlist", `{"cidr":"192.0.2.0/24"}`, "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"192.0.2.0/24"`) {
		t.Fatalf("POST = %d %s, want 200 echoing the CIDR", rec.Code, rec.Body.String())
	}
	// A bare IP is normalized to /32 and de-duplicated; re-adding the /24 is idempotent (still 200).
	if rec := doReq(srv, "POST", "/tenant/ip-allowlist", `{"cidr":"192.0.2.0/24"}`, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("idempotent re-POST = %d, want 200", rec.Code)
	}
	// GET lists the single entry AND echoes the caller's current source IP.
	if rec := doReq(srv, "GET", "/tenant/ip-allowlist", "", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"192.0.2.0/24"`) ||
		!strings.Contains(rec.Body.String(), `"your_ip":"192.0.2.1"`) {
		t.Fatalf("GET = %d %s, want 200 with the CIDR and your_ip 192.0.2.1", rec.Code, rec.Body.String())
	}
	// Delete via ?cidr= (a CIDR has a '/', so it cannot be a path segment). Removing the last entry
	// leaves an empty (open) list — the anti-lockout never blocks emptying.
	if rec := doReq(srv, "DELETE", "/tenant/ip-allowlist?cidr=192.0.2.0/24", "", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := doReq(srv, "GET", "/tenant/ip-allowlist", "", "", ""); rec.Code != http.StatusOK ||
		strings.Contains(rec.Body.String(), `"192.0.2.0/24"`) {
		t.Fatalf("GET after delete = %d %s, want 200 without the CIDR", rec.Code, rec.Body.String())
	}
	// A second delete of the now-absent entry 404s.
	if rec := doReq(srv, "DELETE", "/tenant/ip-allowlist?cidr=192.0.2.0/24", "", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("second DELETE = %d, want 404", rec.Code)
	}
}

// TestTenantIPAllowlistAntiLockout: the safeguard refuses any add/remove whose resulting NON-empty list
// would exclude the acting admin's own source IP — so an admin can never fence themselves out.
func TestTenantIPAllowlistAntiLockout(t *testing.T) {
	// ADD: from an empty list, adding a CIDR that excludes the caller (192.0.2.1) is refused, and the
	// store stays empty (nothing was written).
	srv, store := newAllowlistServer(RoleOwner)
	if rec := doReq(srv, "POST", "/tenant/ip-allowlist", `{"cidr":"10.0.0.0/8"}`, "", ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "lock you out") {
		t.Fatalf("lock-out POST = %d %s, want 400 lock-out", rec.Code, rec.Body.String())
	}
	if got, _ := store.ListCIDRs(context.Background(), "tenant-123"); len(got) != 0 {
		t.Fatalf("anti-lockout must not have written: store = %v", got)
	}

	// DELETE: seed a list that covers the caller via ONE entry plus an unrelated one. Removing the
	// covering entry (leaving only the unrelated one) would lock the caller out → refused; removing the
	// unrelated one (leaving the covering entry) is allowed.
	srv2, store2 := newAllowlistServer(RoleOwner)
	ctx := context.Background()
	_ = store2.AddCIDR(ctx, "tenant-123", "192.0.2.0/24") // covers 192.0.2.1 (the caller)
	_ = store2.AddCIDR(ctx, "tenant-123", "10.0.0.0/8")   // unrelated
	if rec := doReq(srv2, "DELETE", "/tenant/ip-allowlist?cidr=192.0.2.0/24", "", "", ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "lock you out") {
		t.Fatalf("removing the covering entry = %d %s, want 400 lock-out", rec.Code, rec.Body.String())
	}
	if rec := doReq(srv2, "DELETE", "/tenant/ip-allowlist?cidr=10.0.0.0/8", "", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("removing the unrelated entry = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestTenantIPAllowlistEnforcement: with a non-empty list, a request whose source IP is not covered is
// refused 403 for the WHOLE authenticated API (here GET /machines), while a covered source reaches the
// handler; an empty list is open. Uses trust-proxy + XFF to simulate distinct source IPs.
func TestTenantIPAllowlistEnforcement(t *testing.T) {
	srv, store := newAllowlistServer(RoleOwner)
	srv.SetTrustProxy(true)
	_ = store.AddCIDR(context.Background(), "tenant-123", "10.0.0.0/8")

	// Disallowed source (rightmost XFF 8.8.8.8) → 403 with the organization message, on a route that
	// has nothing to do with the allow-list (proves it gates the whole authenticated surface).
	if rec := doReq(srv, "GET", "/machines", "", "203.0.113.9:1", "8.8.8.8"); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "not allowed for your organization") {
		t.Fatalf("disallowed source = %d %s, want 403 org-refused", rec.Code, rec.Body.String())
	}
	// Allowed source (rightmost XFF inside 10/8) → reaches the handler (200 machine listing).
	if rec := doReq(srv, "GET", "/machines", "", "203.0.113.9:1", "10.1.2.3"); rec.Code != http.StatusOK {
		t.Fatalf("allowed source = %d %s, want 200", rec.Code, rec.Body.String())
	}
	// The allow-list's OWN management route is gated too: a locked-out admin cannot even read it.
	if rec := doReq(srv, "GET", "/tenant/ip-allowlist", "", "203.0.113.9:1", "8.8.8.8"); rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed source on the management route = %d, want 403", rec.Code)
	}
	// Emptying the list re-opens the API (backward-compatible default).
	_ = store.RemoveCIDR(context.Background(), "tenant-123", "10.0.0.0/8")
	if rec := doReq(srv, "GET", "/machines", "", "203.0.113.9:1", "8.8.8.8"); rec.Code != http.StatusOK {
		t.Fatalf("empty list must be open: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTenantIPAllowlistStoreUnconfigured: the handlers fail CLOSED (500) rather than nil-panic when the
// store is not wired (the middleware stays a no-op, so unrelated routes still work).
func TestTenantIPAllowlistStoreUnconfigured(t *testing.T) {
	p := &Principal{UserID: "u1", TenantID: "tenant-123", Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(p) // does NOT wire TenantIPAllowlist
	if rec := doReq(srv, "GET", "/tenant/ip-allowlist", "", "", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("unconfigured store GET = %d, want 500", rec.Code)
	}
	// An unrelated route is unaffected — the nil-safe middleware allowed it through.
	if rec := doReq(srv, "GET", "/machines", "", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("unrelated route with nil allow-list store = %d, want 200", rec.Code)
	}
}
