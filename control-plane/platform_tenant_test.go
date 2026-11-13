package controlplane

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func platformTestServer(t *testing.T, sessionID string) (*Server, *fakePlatformStore) {
	t.Helper()
	p := &Principal{
		UserID:    "11111111-0000-4000-8000-0000000000aa",
		TenantID:  "tenant-123",
		Grant:     NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
		SessionID: sessionID,
	}
	srv, _ := newTestServer(p)
	fake := &fakePlatformStore{tenants: []PlatformTenant{
		{ID: "22222222-0000-4000-8000-000000000001", Slug: "loam", Name: "Loam"},
	}}
	srv.Platform = fake
	return srv, fake
}

// Every tenant's Owner holds CapManageTenant, so the legacy route can never be the gate: it is gone.
func TestLegacyTenantCreationIsGone(t *testing.T) {
	srv, fake := platformTestServer(t, "11111111-0000-4000-8000-000000000003")
	if code := apiJSON(t, srv, "POST", "/tenants", `{"slug":"newco","name":"NewCo"}`, nil); code != http.StatusGone {
		t.Fatalf("POST /tenants = %d, want 410", code)
	}
	var listed struct {
		CanCreate bool `json:"can_create"`
	}
	if code := apiJSON(t, srv, "GET", "/tenants", "", &listed); code != http.StatusOK || listed.CanCreate {
		t.Fatalf("GET /tenants = %d can_create=%v, want 200 false", code, listed.CanCreate)
	}
	if len(fake.created) != 0 {
		t.Fatal("the legacy route reached the platform store")
	}
}

// API tokens (and any caller without an interactive session) never reach the platform store.
func TestPlatformRoutesRequireAnInteractiveSession(t *testing.T) {
	srv, fake := platformTestServer(t, "")
	for _, rt := range []struct{ method, path, body string }{
		{"GET", "/platform/tenants", ""},
		{"POST", "/platform/tenants", `{"slug":"newco","name":"NewCo"}`},
		{"POST", "/platform/tenants/22222222-0000-4000-8000-000000000001/suspend", `{"confirm_slug":"loam","reason":"x"}`},
	} {
		if code := apiJSON(t, srv, rt.method, rt.path, rt.body, nil); code != http.StatusForbidden {
			t.Errorf("%s %s without a session = %d, want 403", rt.method, rt.path, code)
		}
	}
	var me PlatformWhoami
	if code := apiJSON(t, srv, "GET", "/platform/me", "", &me); code != http.StatusOK || me.Operator {
		t.Fatalf("/platform/me without a session = %d %+v", code, me)
	}
	if len(fake.callers) != 0 {
		t.Fatalf("store reached without a session: %+v", fake.callers)
	}
}

func TestPlatformSuspendRequiresMatchingSlugAndReason(t *testing.T) {
	srv, fake := platformTestServer(t, "11111111-0000-4000-8000-000000000004")
	path := "/platform/tenants/22222222-0000-4000-8000-000000000001/suspend"
	for body, want := range map[string]int{
		`{"confirm_slug":"main","reason":"unpaid"}`: http.StatusBadRequest, // wrong row
		`{"confirm_slug":"loam","reason":"  "}`:     http.StatusBadRequest, // no reason
		`{"confirm_slug":"loam"}`:                   http.StatusBadRequest,
	} {
		if code := apiJSON(t, srv, "POST", path, body, nil); code != want {
			t.Errorf("suspend %s = %d, want %d", body, code, want)
		}
	}
	if len(fake.suspended) != 0 {
		t.Fatalf("store called despite a refused confirmation: %v", fake.suspended)
	}
	if code := apiJSON(t, srv, "POST", "/platform/tenants/33333333-0000-4000-8000-000000000009/suspend",
		`{"confirm_slug":"loam","reason":"x"}`, nil); code != http.StatusNotFound {
		t.Fatalf("unknown tenant = %d, want 404", code)
	}
	if code := apiJSON(t, srv, "POST", path, `{"confirm_slug":"loam","reason":"unpaid"}`, nil); code != http.StatusOK {
		t.Fatalf("valid suspend = %d", code)
	}
	if len(fake.suspended) != 1 || !strings.HasSuffix(fake.suspended[0], ":true:unpaid") {
		t.Fatalf("store saw %v", fake.suspended)
	}
	if code := apiJSON(t, srv, "POST", strings.Replace(path, "suspend", "resume", 1), `{"confirm_slug":"loam","reason":"paid"}`, nil); code != http.StatusOK ||
		!strings.HasSuffix(fake.suspended[1], ":false:paid") {
		t.Fatalf("resume = %d, store saw %v", code, fake.suspended)
	}
}

// A database denial is a plain 403 that says nothing about which condition failed.
func TestPlatformDenialIsOpaque(t *testing.T) {
	srv, fake := platformTestServer(t, "11111111-0000-4000-8000-000000000005")
	fake.err = ErrPlatformDenied
	rec := serve(srv, "GET", "/platform/tenants", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "platform operator access denied") {
		t.Fatalf("denied list = %d %s", rec.Code, rec.Body.String())
	}
	fake.err = errors.New("boom")
	if rec := serve(srv, "POST", "/platform/tenants", `{"slug":"newco","name":"NewCo"}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("store failure = %d", rec.Code)
	}
}
