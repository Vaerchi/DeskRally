package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hostnameServer: an operator principal (a session id is what platformCaller needs) over the fake store.
func hostnameServer(t *testing.T) (*Server, *InMemoryHostnameStore) {
	t.Helper()
	p := &Principal{
		UserID: "00000000-0000-0000-0000-0000000000aa", TenantID: "00000000-0000-0000-0000-0000000000bb",
		SessionID: "00000000-0000-0000-0000-0000000000dd",
		Grant:     NewGrant("00000000-0000-0000-0000-0000000000aa", "00000000-0000-0000-0000-0000000000bb", NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	store := &InMemoryHostnameStore{}
	srv.Hostnames = store
	srv.TenantHostSuffix = ".example.test"
	srv.HostPolicy = scopedPolicy(t)
	return srv, store
}

func hostnameCall(srv *Server, method, path, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

const hostTenantID = "00000000-0000-0000-0000-0000000000ee"

func TestPlatformHostnameAssignAndLifecycleRoutes(t *testing.T) {
	srv, store := hostnameServer(t)

	code, out := hostnameCall(srv, "POST", "/platform/tenants/"+hostTenantID+"/hostnames", `{"host":"Widget.Example.Test."}`)
	if code != http.StatusCreated {
		t.Fatalf("assign: %d %v", code, out)
	}
	a := out["hostname"].(map[string]any)
	id := a["id"].(string)
	if a["host"] != "widget.example.test" || a["state"] != "pending" {
		t.Fatalf("assign normalises and creates pending: %v", a)
	}
	if code, out = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/activate", `{}`); code != http.StatusOK || out["hostname"].(map[string]any)["state"] != "active" {
		t.Fatalf("activate: %d %v", code, out)
	}
	if code, _ = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/activate", `{}`); code != http.StatusConflict {
		t.Fatalf("activate twice: %d, want 409", code)
	}
	if code, out = hostnameCall(srv, "GET", "/platform/tenants/"+hostTenantID+"/hostnames", ""); code != http.StatusOK || len(out["hostnames"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	// release needs a reason; quarantine below 30 days is refused.
	if code, _ = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/release", `{}`); code != http.StatusBadRequest {
		t.Fatalf("release without a reason: %d", code)
	}
	if code, _ = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/release", `{"reason":"x","quarantine_days":7}`); code != http.StatusBadRequest {
		t.Fatalf("release with 7 days: %d", code)
	}
	if code, out = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/release", `{"reason":"customer left"}`); code != http.StatusOK || out["hostname"].(map[string]any)["state"] != "released" {
		t.Fatalf("release: %d %v", code, out)
	}
	if code, out = hostnameCall(srv, "POST", "/platform/hostnames/"+id+"/reactivate", `{"activate":true}`); code != http.StatusCreated {
		t.Fatalf("reactivate: %d %v", code, out)
	} else if n := out["hostname"].(map[string]any)["id"]; n == id {
		t.Fatalf("reactivation must mint a new assignment id")
	}
	if len(store.Audit) != 8 { // assign, activate, release, reactivate: two chains each
		t.Fatalf("audit lines = %d: %v", len(store.Audit), store.Audit)
	}
	if code, _ = hostnameCall(srv, "POST", "/platform/hostnames/not-a-uuid/activate", `{}`); code != http.StatusNotFound {
		t.Fatalf("bad id: %d", code)
	}
}

func TestPlatformHostnameAssignRefusalsAndOverrides(t *testing.T) {
	srv, _ := hostnameServer(t)
	assign := func(body string) (int, map[string]any) {
		return hostnameCall(srv, "POST", "/platform/tenants/"+hostTenantID+"/hostnames", body)
	}
	// Hard refusals.
	for _, host := range []string{
		"main.example.test", "loam.example.test", // default / legacy
		"www.example.test", "api.example.test", // reserved slugs
		"ab.example.test",          // too short
		"a.b.example.test",         // not a single label
		"widget.other.test",        // wrong suffix
		"widget.example.test:8443", // port
		"127.0.0.1", "",
	} {
		if code, out := assign(`{"host":"` + host + `"}`); code != http.StatusBadRequest {
			t.Errorf("host %q: %d %v, want 400", host, code, out)
		}
	}
	// A lookalike warning needs every code acknowledged AND a reason.
	code, out := assign(`{"host":"micr0soft.example.test"}`)
	if code != http.StatusConflict || out["warnings"] == nil {
		t.Fatalf("brand lookalike without acknowledgement: %d %v", code, out)
	}
	if code, _ = assign(`{"host":"micr0soft.example.test","acknowledge":["brand_denylist"]}`); code != http.StatusConflict {
		t.Fatalf("acknowledged but no reason: %d", code)
	}
	if code, _ = assign(`{"host":"micr0soft.example.test","acknowledge":["something_else"],"override_reason":"r"}`); code != http.StatusConflict {
		t.Fatalf("wrong code acknowledged: %d", code)
	}
	if code, out = assign(`{"host":"micr0soft.example.test","acknowledge":["brand_denylist"],"override_reason":"customer is Micro Soft Ltd, verified by phone"}`); code != http.StatusCreated {
		t.Fatalf("a full override must succeed: %d %v", code, out)
	}
}

func TestPlatformHostnameRoutesAreOperatorOnly(t *testing.T) {
	srv, _ := hostnameServer(t)
	srv.Hostnames = nil // not wired
	for _, c := range [][2]string{
		{"GET", "/platform/hostnames"}, {"POST", "/platform/tenants/" + hostTenantID + "/hostnames"},
		{"POST", "/platform/hostnames/" + hostTenantID + "/activate"},
	} {
		if code, _ := hostnameCall(srv, c[0], c[1], `{"host":"widget.example.test"}`); code != http.StatusForbidden {
			t.Errorf("%s %s unwired: %d, want 403", c[0], c[1], code)
		}
	}
	// A non-interactive principal (no session id, e.g. an API token) is refused before the store.
	srv, store := hostnameServer(t)
	store.Authorize = func(PlatformCaller) bool { return false }
	if code, _ := hostnameCall(srv, "GET", "/platform/hostnames", ""); code != http.StatusForbidden {
		t.Errorf("non-operator list: %d, want 403", code)
	}
	if code, _ := hostnameCall(srv, "POST", "/platform/tenants/"+hostTenantID+"/hostnames", `{"host":"widget.example.test"}`); code != http.StatusForbidden {
		t.Errorf("non-operator assign: %d, want 403", code)
	}
}
