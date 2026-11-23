package controlplane

// Handler-level tests for the data-plane surfaces (sessions, tenants, management audit) over
// the in-memory stores — the default no-DB path. The pgx twins live in
// dataplane_pgstore_test.go (DB-gated).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doJSON runs one request against the server and decodes the JSON response into out (when
// non-nil), returning the status code.
func apiJSON(t *testing.T, srv *Server, method, path, body string, out any) int {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, rdr)
	srv.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: bad JSON response %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

// TestSessionLifecycleHandlers drives enroll → start → list → end through the HTTP surface and
// checks the management audit trail recorded each step.
func TestSessionLifecycleHandlers(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)

	// Enroll a machine into group g1.
	var enrolled struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll",
		`{"machine_id":"dev-1","group_id":"g1","name":"FRONTDESK"}`, &enrolled); code != http.StatusCreated {
		t.Fatalf("enroll = %d", code)
	}
	if enrolled.Machine.ID == "" || enrolled.Machine.DeviceID != "dev-1" {
		t.Fatalf("enrolled machine = %+v", enrolled.Machine)
	}

	// Start a session against the DEVICE id; the record must carry the machine PK + real group.
	var started struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"dev-1"}`, &started); code != http.StatusCreated {
		t.Fatalf("start session = %d", code)
	}
	sess := started.Session
	if sess.ID == "" || sess.MachineID != enrolled.Machine.ID || sess.TechnicianID != "u1" {
		t.Fatalf("session = %+v", sess)
	}
	if sess.MachineGroupID != "g1" || sess.MachineDeviceID != "dev-1" {
		t.Fatalf("session machine denorm = %+v", sess)
	}
	if sess.EndedAt != nil {
		t.Fatal("fresh session already ended")
	}
	// Owner covers backstage_shell + manage_machines → admin-tier caps must be present.
	if len(sess.GrantedCaps) == 0 {
		t.Fatal("owner-started session carries no backstage caps")
	}

	// List shows it.
	var listed struct {
		Sessions []SessionRecord `json:"sessions"`
	}
	if code := apiJSON(t, srv, "GET", "/sessions", "", &listed); code != http.StatusOK {
		t.Fatalf("list sessions = %d", code)
	}
	if len(listed.Sessions) != 1 || listed.Sessions[0].ID != sess.ID {
		t.Fatalf("listed sessions = %+v", listed.Sessions)
	}

	// End it; ending again is idempotent (same end time), unknown id is a 404.
	var ended struct {
		Session SessionRecord `json:"session"`
	}
	if code := apiJSON(t, srv, "POST", "/sessions/"+sess.ID+"/end", "", &ended); code != http.StatusOK {
		t.Fatalf("end session = %d", code)
	}
	if ended.Session.EndedAt == nil {
		t.Fatal("ended session has no ended_at")
	}
	firstEnd := *ended.Session.EndedAt
	if code := apiJSON(t, srv, "POST", "/sessions/"+sess.ID+"/end", "", &ended); code != http.StatusOK {
		t.Fatalf("re-end session = %d", code)
	}
	if !ended.Session.EndedAt.Equal(firstEnd) {
		t.Fatalf("re-end moved ended_at: %v → %v", firstEnd, *ended.Session.EndedAt)
	}
	if code := apiJSON(t, srv, "POST", "/sessions/no-such-session/end", "", nil); code != http.StatusNotFound {
		t.Fatalf("end unknown session = %d, want 404", code)
	}

	// The audit trail recorded each mutation, newest first.
	var audit struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if code := apiJSON(t, srv, "GET", "/audit", "", &audit); code != http.StatusOK {
		t.Fatalf("list audit = %d", code)
	}
	var actions []string
	for _, e := range audit.Events {
		actions = append(actions, e.Action)
		if e.ActorUserID != "u1" {
			t.Fatalf("audit actor = %q, want u1 (event %+v)", e.ActorUserID, e)
		}
	}
	// Two session.end entries: the idempotent re-end above is still an audited action.
	want := []string{"session.end", "session.end", "session.start", "machine.enroll"}
	if len(actions) != len(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("audit actions = %v, want %v", actions, want)
		}
	}

	// ?limit= bounds the list; a malformed limit is a 400.
	if code := apiJSON(t, srv, "GET", "/audit?limit=1", "", &audit); code != http.StatusOK {
		t.Fatalf("limited audit = %d", code)
	}
	if len(audit.Events) != 1 || audit.Events[0].Action != "session.end" {
		t.Fatalf("limited audit = %+v", audit.Events)
	}
	if code := apiJSON(t, srv, "GET", "/audit?limit=abc", "", nil); code != http.StatusBadRequest {
		t.Fatalf("bad limit = %d, want 400", code)
	}
}

// TestListSessionsGroupScoped: a viewer whose membership covers only group-a must not see a
// session on a machine in another group, even inside the same tenant.
func TestListSessionsGroupScoped(t *testing.T) {
	owner := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(owner)
	if code := apiJSON(t, srv, "POST", "/enroll", `{"machine_id":"dev-1","group_id":"g1"}`, nil); code != http.StatusCreated {
		t.Fatalf("enroll = %d", code)
	}
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"dev-1"}`, nil); code != http.StatusCreated {
		t.Fatalf("start = %d", code)
	}

	// Same server (same stores), scoped caller: sees nothing from g1.
	srv.Auth = StubAuthenticator{Principal: &Principal{
		UserID:   "u2",
		TenantID: "tenant-123",
		Grant:    NewGrant("u2", "tenant-123", NewMembership(RoleReadOnly, Groups("group-a"))),
	}}
	var listed struct {
		Sessions []SessionRecord `json:"sessions"`
	}
	if code := apiJSON(t, srv, "GET", "/sessions", "", &listed); code != http.StatusOK {
		t.Fatalf("scoped list = %d", code)
	}
	if len(listed.Sessions) != 0 {
		t.Fatalf("group-a-scoped viewer sees %d sessions from g1, want 0", len(listed.Sessions))
	}
}

// TestTenantHandlers: provisioning + listing over the in-memory store.
func TestTenantHandlers(t *testing.T) {
	owner := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(owner)

	// Provisioning moved to POST /platform/tenants (platform operators only, DB-enforced); the
	// legacy route answers 410 for everyone, Owner included, and creates nothing.
	if code := apiJSON(t, srv, "POST", "/tenants", `{"slug":"acme","name":"Acme MSP"}`, nil); code != http.StatusGone {
		t.Fatalf("legacy create tenant = %d, want 410", code)
	}

	// Listing mirrors RLS: only the CALLER'S tenant row is visible — the newly provisioned
	// tenant belongs to a different isolation domain and must not appear.
	var listed struct {
		Tenants []Tenant `json:"tenants"`
	}
	if code := apiJSON(t, srv, "GET", "/tenants", "", &listed); code != http.StatusOK {
		t.Fatalf("list tenants = %d", code)
	}
	if len(listed.Tenants) != 1 || listed.Tenants[0].Slug != "test-tenant" {
		t.Fatalf("tenant listing = %+v, want only the caller's own tenant", listed.Tenants)
	}

	// Nothing was provisioned, so nothing was audited.
	var audit struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if code := apiJSON(t, srv, "GET", "/audit", "", &audit); code != http.StatusOK || len(audit.Events) != 0 {
		t.Fatalf("audit after a refused create = %d %+v", code, audit.Events)
	}

	// A ReadOnly caller cannot provision.
	srv.Auth = StubAuthenticator{Principal: &Principal{
		UserID:   "u2",
		TenantID: "tenant-123",
		Grant:    NewGrant("u2", "tenant-123", NewMembership(RoleReadOnly, AllGroups())),
	}}
	if code := apiJSON(t, srv, "POST", "/tenants", `{"slug":"nope","name":"Nope"}`, nil); code != http.StatusGone {
		t.Fatalf("readonly legacy create tenant = %d, want 410 (the route is gone for everyone)", code)
	}
}
