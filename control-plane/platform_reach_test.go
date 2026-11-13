package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The route-level gates of docs/68. Whether the caller IS an operator, and whether its MFA is fresh, is the
// database's decision (cp_platform_check; platform_reach_pgstore_test.go proves it). These tests pin what the
// handlers add: no interactive session never reaches the store, a store denial is an opaque 403, the range is
// bounded, and /adoption is Owner-only.

func TestPlatformReachRefusesCallersWithoutAnInteractiveSession(t *testing.T) {
	srv, fake := platformTestServer(t, "") // an API token has no session id
	if code := apiJSON(t, srv, "GET", "/platform/reach", "", nil); code != http.StatusForbidden {
		t.Fatalf("GET /platform/reach without a session = %d, want 403", code)
	}
	if len(fake.callers) != 0 || len(fake.reachRanges) != 0 {
		t.Fatalf("the store was reached without a session: %+v", fake.callers)
	}
	srv.Platform = nil // not mounted (dev mode)
	if code := apiJSON(t, srv, "GET", "/platform/reach", "", nil); code != http.StatusForbidden {
		t.Fatalf("with no platform store = %d, want 403", code)
	}
}

func TestPlatformReachDenialIsOpaque(t *testing.T) {
	srv, fake := platformTestServer(t, "11111111-0000-4000-8000-000000000006")
	fake.err = ErrPlatformDenied // a non-operator, or a stale second factor: the DB does not say which
	rec := serve(srv, "GET", "/platform/reach", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "platform operator access denied") {
		t.Fatalf("denied = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "mfa") {
		t.Fatalf("the denial names a condition: %s", rec.Body.String())
	}
}

func TestPlatformReachReturnsRowsWithCaveatsAndBoundsTheRange(t *testing.T) {
	srv, fake := platformTestServer(t, "11111111-0000-4000-8000-000000000007")
	completed := int64(3)
	fake.reach = []ReachRow{{Day: "2026-11-05", Artifact: "DeskRallySupport.exe", Class: "human", Requests: 5, Completed: &completed}}
	var out struct {
		From, To string
		Rows     []ReachRow
		Caveats  []string
	}
	if code := apiJSON(t, srv, "GET", "/platform/reach?from=2026-10-01&to=2026-11-05", "", &out); code != http.StatusOK {
		t.Fatalf("valid range = %d", code)
	}
	if len(out.Rows) != 1 || out.Rows[0].Requests != 5 || len(out.Caveats) < 4 || out.From != "2026-10-01" {
		t.Fatalf("response %+v", out)
	}
	if fake.reachRanges[0] != "2026-10-01..2026-11-05" {
		t.Fatalf("store saw %v", fake.reachRanges)
	}
	// The key names carry the honest labels.
	raw := serve(srv, "GET", "/platform/reach?from=2026-10-01&to=2026-11-05", "").Body.String()
	for _, k := range []string{`"completed_approx"`, `"unique_ish_clients"`, `"unique_ish_partial"`} {
		if !strings.Contains(raw, k) {
			t.Errorf("response lacks %s: %s", k, raw)
		}
	}
	// No query: the last 30 days, ending today.
	if code := apiJSON(t, srv, "GET", "/platform/reach", "", &out); code != http.StatusOK {
		t.Fatalf("default range = %d", code)
	}
	f, _ := time.Parse("2006-01-02", out.From)
	to, _ := time.Parse("2006-01-02", out.To)
	if d := int(to.Sub(f).Hours() / 24); d != 29 {
		t.Fatalf("default range spans %d days, want 29 (30 inclusive)", d)
	}
	for _, q := range []string{
		"from=2026-11-05&to=2026-11-01", // reversed
		"from=2025-01-01&to=2026-11-05", // more than 400 days
		"from=yesterday",
		"to=2026-13-40",
		"from=2026-10-01%27%3B--",
	} {
		before := len(fake.reachRanges)
		if code := apiJSON(t, srv, "GET", "/platform/reach?"+q, "", nil); code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, code)
		}
		if len(fake.reachRanges) != before {
			t.Errorf("?%s reached the store", q)
		}
	}
	// Both ends are inclusive: 400 days (399 apart) is the last allowed range; 401 days is refused.
	if code := apiJSON(t, srv, "GET", "/platform/reach?from=2025-10-01&to=2026-11-05", "", nil); code != http.StatusBadRequest {
		t.Fatalf("401 days = %d, want 400", code)
	}
	if code := apiJSON(t, srv, "GET", "/platform/reach?from=2025-10-02&to=2026-11-05", "", nil); code != http.StatusOK {
		t.Fatalf("400 days = %d, want 200", code)
	}
}

type fakeAdoption struct {
	tenants []string
	report  *AdoptionReport
	err     error
}

func (f *fakeAdoption) Report(_ context.Context, tenantID string, from, to time.Time) (*AdoptionReport, error) {
	f.tenants = append(f.tenants, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	r := *f.report
	r.From, r.To = from.Format("2006-01-02"), to.Format("2006-01-02")
	return &r, nil
}

func adoptionServer(t *testing.T, role Role) (*Server, *fakeAdoption) {
	t.Helper()
	p := &Principal{UserID: "u1", TenantID: "tenant-123", Grant: NewGrant("u1", "tenant-123", NewMembership(role, AllGroups())), SessionID: "s1"}
	srv, _ := newTestServer(p)
	fa := &fakeAdoption{report: &AdoptionReport{ActiveDevices30d: 7, NewDevicesPerWeek: []WeekCount{{Week: "2026-11-02", Count: 2}}}}
	srv.Adoption = fa
	return srv, fa
}

func TestAdoptionIsOwnerOnlyAndScopedToTheCallersTenant(t *testing.T) {
	srv, fa := adoptionServer(t, RoleTechnician)
	if code := apiJSON(t, srv, "GET", "/adoption", "", nil); code != http.StatusForbidden {
		t.Fatalf("a technician = %d, want 403", code)
	}
	if len(fa.tenants) != 0 {
		t.Fatal("the store was reached by a caller without manage_tenant")
	}

	srv, fa = adoptionServer(t, RoleOwner)
	var out AdoptionReport
	if code := apiJSON(t, srv, "GET", "/adoption?from=2026-10-01&to=2026-11-05", "", &out); code != http.StatusOK {
		t.Fatalf("owner = %d", code)
	}
	if out.ActiveDevices30d != 7 || out.From != "2026-10-01" || len(fa.tenants) != 1 || fa.tenants[0] != "tenant-123" {
		t.Fatalf("report %+v, store saw tenants %v (the tenant comes from the session, never from the request)", out, fa.tenants)
	}
	// A tenant id in the request is ignored: there is no parameter that selects another tenant.
	apiJSON(t, srv, "GET", "/adoption?tenant_id=tenant-999&tenant=tenant-999", "", nil)
	if last := fa.tenants[len(fa.tenants)-1]; last != "tenant-123" {
		t.Fatalf("store saw %s", last)
	}
	for _, q := range []string{"from=2026-11-05&to=2026-11-01", "from=2025-01-01&to=2026-11-05", "from=x"} {
		if code := apiJSON(t, srv, "GET", "/adoption?"+q, "", nil); code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, code)
		}
	}
	srv.Adoption = nil
	if code := apiJSON(t, srv, "GET", "/adoption", "", nil); code != http.StatusInternalServerError {
		t.Fatalf("unwired store = %d, want 500", code)
	}
}

func TestAdoptionJSONShape(t *testing.T) {
	srv, _ := adoptionServer(t, RoleOwner)
	var m map[string]json.RawMessage
	if code := apiJSON(t, srv, "GET", "/adoption", "", &m); code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	for _, k := range []string{"new_devices_per_week", "active_devices_30d", "attended_funnel", "agent_versions"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
}
