package controlplane

// Coverage gaps in the loop-78 per-group session cap, found by the retroactive adversarial review
// (loop 79). Each test here exists because a specific mutation SURVIVED the original suite:
//
//   - deleting the LIST handler's CapManageGroups check                → nothing failed
//   - dropping a `return` after writeError on any error path           → nothing failed (status-only asserts)
//   - swapping the tenant/group axis order in StartSessionWithinLimit  → nothing failed (never both full)
//   - auditing the wrong group id, or omitting the value               → nothing failed (action-only assert)
//
// Kept in their own file rather than appended to group_session_policy_test.go so the reason they exist
// stays attached to them.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The LIST endpoint's OWN capability gate. TestHandleGroupSessionPolicy checks the technician 403 on the
// per-group GET and PUT but never on GET /machine-groups/session-policies, so removing that handler's
// CapManageGroups check left the whole suite green — and the endpoint enumerates every capped group in
// the tenant, which is exactly what a scoped technician should not receive wholesale.
func TestHandleListGroupSessionPoliciesRequiresCapManageGroups(t *testing.T) {
	ctx := context.Background()
	const listPath = "/machine-groups/session-policies"
	do := func(hh http.Handler) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hh.ServeHTTP(rec, httptest.NewRequest("GET", listPath, nil))
		return rec
	}

	// An Owner (holds CapManageGroups) sees the capped group. This half matters: it establishes the
	// route WORKS, so the technician's 403 below cannot be credited to the endpoint simply being broken.
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	ownerSrv, _ := newTestServer(owner)
	g := &MachineGroup{Name: "Sales"}
	if err := ownerSrv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := ownerSrv.GroupSessionPolicies.Set(ctx, "tenant-123", g.ID, GroupSessionPolicy{MaxConcurrentSessions: 7}); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	if rec := do(ownerSrv.Handler()); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), g.ID) {
		t.Fatalf("owner list = %d body %q, want 200 carrying the capped group", rec.Code, rec.Body.String())
	}

	// A technician holds no CapManageGroups. The role is scoped over AllGroups() deliberately, so the
	// ONLY thing that can deny this request is the capability check — an over-determined 403 (denied by
	// scope as well) could not tell a working gate from a deleted one.
	tech := &Principal{UserID: "u2", TenantID: "tenant-123",
		Grant: NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups()))}
	techSrv, _ := newTestServer(tech)
	rec := do(techSrv.Handler())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician list = %d, want 403", rec.Code)
	}
	// …and the refusal carries no policy data: a handler that wrote the error and then fell through to
	// serialize the list anyway would still report 403.
	if strings.Contains(rec.Body.String(), "max_concurrent_sessions") {
		t.Fatalf("403 body leaked policy data: %s", rec.Body.String())
	}
}

// Error paths must write ONE response. The original cases assert only the status code, so a dropped
// return after writeError — which appends a second, successful-looking JSON body to the SAME 4xx
// response — passes them. This package has shipped that exact bug before (loop 54), so every error path
// on these handlers is checked for a body that carries no policy.
func TestGroupSessionPolicyErrorsWriteNoPolicyBody(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	g := &MachineGroup{Name: "Sales"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	h := srv.Handler()
	path := "/machine-groups/" + g.ID + "/session-policy"
	unknown := "/machine-groups/00000000-0000-0000-0000-000000000000/session-policy"

	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"negative cap", "PUT", path, `{"max_concurrent_sessions":-1}`, http.StatusBadRequest},
		{"absurd cap", "PUT", path, `{"max_concurrent_sessions":999999999}`, http.StatusBadRequest},
		{"malformed json", "PUT", path, `{"max_concurrent_sessions":`, http.StatusBadRequest},
		{"unknown group PUT", "PUT", unknown, `{"max_concurrent_sessions":2,"max_session_duration_seconds":3600}`, http.StatusNotFound},
		{"unknown group GET", "GET", unknown, "", http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)))
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
			continue
		}
		// The defect this guards produces TWO concatenated JSON values on one response --
		// {"error":...} immediately followed by the policy object -- so the sharp check is that the
		// body decodes as EXACTLY ONE value carrying an error, with nothing after it.
		//
		// Deliberately NOT a substring check for "max_concurrent_sessions": the validation error
		// message itself names that field, so a substring assertion fails on correct code (and would
		// have to be loosened until it proved nothing).
		dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
		var first map[string]any
		if err := dec.Decode(&first); err != nil {
			t.Errorf("%s: body is not JSON (%v): %s", c.name, err, rec.Body.String())
			continue
		}
		if _, hasErr := first["error"]; !hasErr {
			t.Errorf("%s: first JSON value carries no error field: %s", c.name, rec.Body.String())
		}
		if _, hasCap := first["group_id"]; hasCap {
			t.Errorf("%s: the error response IS a policy body: %s", c.name, rec.Body.String())
		}
		var trailing any
		if err := dec.Decode(&trailing); err == nil {
			t.Errorf("%s: a SECOND JSON value follows the error (a missing return after writeError?): %s",
				c.name, rec.Body.String())
		}
	}

	// And none of the rejected writes reached the store.
	if got, err := srv.GroupSessionPolicies.Get(ctx, "tenant-123", g.ID); err != nil || !got.IsDefault() {
		t.Fatalf("after the rejected writes the stored policy = (%+v, %v), want the default — a 4xx must not persist", got, err)
	}
}

// "The tenant axis is checked first" is asserted in both stores' doc comments, but the original fake test
// only ever fills ONE axis at a time — so the ORDER is never observed. The distinguishing case is both
// axes full at once: the caller must see ErrConcurrentSessionLimit (tenant), not the group error.
// Without this, swapping the two checks passes every other test.
func TestStartSessionWithinLimitReportsTheTenantAxisWhenBothAreFull(t *testing.T) {
	s := NewInMemorySessionRecordStore()
	ctx := context.Background()
	limits := SessionStartLimits{Tenant: 1, GroupID: "g1", Group: 1}

	// ONE session fills BOTH axes at once (tenant cap 1, group cap 1).
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g1"}, limits); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := s.StartSessionWithinLimit(ctx, "t1",
		&SessionRecord{MachineID: "m", MachineGroupID: "g1"}, limits); err != ErrConcurrentSessionLimit {
		t.Fatalf("both axes full = %v, want ErrConcurrentSessionLimit — the TENANT axis is checked "+
			"first, so it is the one reported when both are at capacity", err)
	}
}

// The audit event must name WHICH group was capped and to what. Asserting only the action string means a
// handler that audited the wrong group id — or omitted the value — still passes, and this trail is the
// only record of who throttled whose availability.
func TestGroupSessionPolicyAuditNamesTheGroupAndValue(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	// TWO groups, so an event naming the WRONG one is detectable — with a single group any id passes.
	capped := &MachineGroup{Name: "Sales"}
	other := &MachineGroup{Name: "Ops"}
	for _, g := range []*MachineGroup{capped, other} {
		if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
			t.Fatalf("create group %s: %v", g.Name, err)
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("PUT",
		"/machine-groups/"+capped.ID+"/session-policy",
		strings.NewReader(`{"max_concurrent_sessions":6,"max_session_duration_seconds":3600}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}

	events, err := srv.MgmtAudit.ListEvents(ctx, "tenant-123", 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found *MgmtAuditEvent
	for i := range events {
		if events[i].Action == "machine_group.session_policy.set" {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no machine_group.session_policy.set event in %+v", events)
	}
	if found.TargetID != capped.ID {
		t.Errorf("audit target = %q, want the CAPPED group %q (the untouched group is %q)",
			found.TargetID, capped.ID, other.ID)
	}
	if found.TargetKind != "machine_group" {
		t.Errorf("audit target kind = %q, want machine_group", found.TargetKind)
	}
	// The new cap value is recorded, so the trail shows WHAT availability was set to. Decoded from the
	// metadata JSON rather than string-matched, so "6" appearing anywhere else in the blob cannot pass it.
	var meta struct {
		MaxConcurrentSessions *int `json:"max_concurrent_sessions"`
	}
	if err := json.Unmarshal(found.Metadata, &meta); err != nil {
		t.Fatalf("decode audit metadata %s: %v", found.Metadata, err)
	}
	if meta.MaxConcurrentSessions == nil || *meta.MaxConcurrentSessions != 6 {
		t.Errorf("audit metadata max_concurrent_sessions = %v, want 6 (raw: %s)",
			meta.MaxConcurrentSessions, found.Metadata)
	}
}

// The PUT must persist every setting, and persist each INDEPENDENTLY of the others. Without this, a handler
// that decoded a field and dropped it would be caught only by the Playwright spec — and the settings share a
// row, so the interesting cases are the mixed ones.
//
// Three settings since migration 0040: the cap, enforce_view_only, and allow_backstage_under_view_only (the
// explicit opt-out that lets a view-only group still be issued backstage grants). The opt-out's zero value is
// the PROTECTED one, so the case that matters most is the one the test names "view-only, backstage still
// refused": a body that never mentions the field must read back as protected, because every client older than
// 0040 sends exactly that body and the PUT is a full overwrite.
func TestSetGroupSessionPolicyRoundTripsAllThreeSettings(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	g := &MachineGroup{Name: "Sales"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	h := srv.Handler()
	path := "/machine-groups/" + g.ID + "/session-policy"

	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("PUT", path, strings.NewReader(body)))
		return rec
	}
	get := func() GroupSessionPolicy {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
		}
		var out GroupSessionPolicy
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode GET: %v (%s)", err, rec.Body.String())
		}
		return out
	}

	cases := []struct {
		name         string
		body         string
		wantCap      int
		wantViewOnly bool
		wantAllow    bool
	}{
		// cap>0 requires max_session_duration_seconds>0 (NormalizeGroupSessionPolicy constraint).
		{"both set", `{"max_concurrent_sessions":2,"enforce_view_only":true,"max_session_duration_seconds":3600}`, 2, true, false},
		// View-only with NO cap is the case the store's delete rule turns on: the row must survive so the
		// mandate does, even though the cap is the zero value that used to delete it.
		{"view-only, no cap", `{"max_concurrent_sessions":0,"enforce_view_only":true}`, 0, true, false},
		{"cap, no view-only", `{"max_concurrent_sessions":5,"enforce_view_only":false,"max_session_duration_seconds":7200}`, 5, false, false},
		// A full overwrite: clearing everything really does clear everything.
		{"neither", `{"max_concurrent_sessions":0,"enforce_view_only":false}`, 0, false, false},

		// --- migration 0040: the backstage opt-out ---
		//
		// THE STALE-CLIENT CASE, and the reason the field is named for the permission. This body is exactly
		// what every console build, script and curl written before 0040 sends: no mention of the opt-out at
		// all. The PUT is a full overwrite, so the field IS written — and it must be written as the
		// PROTECTED value. If this ever reads back true, an old client is silently disabling a security
		// control on whichever group it edits.
		{"view-only, field omitted entirely → protected", `{"max_concurrent_sessions":0,"enforce_view_only":true}`, 0, true, false},
		// The opt-out set alongside the mandate: the deliberate unattended-maintenance combination.
		{"view-only WITH the backstage opt-out",
			`{"max_concurrent_sessions":0,"enforce_view_only":true,"allow_backstage_under_view_only":true}`, 0, true, true},
		// …and it can be taken away again. A one-way opt-out would be its own bug.
		{"opt-out revoked, mandate kept",
			`{"max_concurrent_sessions":0,"enforce_view_only":true,"allow_backstage_under_view_only":false}`, 0, true, false},
		// The opt-out is INDEPENDENT of the mandate and of the cap: it is stored where it was set even
		// though it is inert without view-only (NormalizeGroupSessionPolicy deliberately does not clear it),
		// and this is also the row-survival case for the third setting — a policy whose ONLY non-default
		// field is the opt-out must not be deleted by IsDefault().
		{"opt-out alone, no mandate and no cap",
			`{"max_concurrent_sessions":0,"enforce_view_only":false,"allow_backstage_under_view_only":true}`, 0, false, true},
		{"opt-out alongside a cap, no mandate",
			`{"max_concurrent_sessions":7,"enforce_view_only":false,"allow_backstage_under_view_only":true,"max_session_duration_seconds":3600}`, 7, false, true},
		// Clear everything again so the table does not end on a stored row.
		{"all three cleared", `{"max_concurrent_sessions":0,"enforce_view_only":false,"allow_backstage_under_view_only":false}`, 0, false, false},
	}
	for _, c := range cases {
		if rec := put(c.body); rec.Code != http.StatusOK {
			t.Fatalf("%s: PUT = %d: %s", c.name, rec.Code, rec.Body.String())
		}
		got := get()
		if got.MaxConcurrentSessions != c.wantCap || got.EnforceViewOnly != c.wantViewOnly ||
			got.AllowBackstageUnderViewOnly != c.wantAllow {
			t.Errorf("%s: read back {cap:%d viewOnly:%v allowBackstage:%v}, want {cap:%d viewOnly:%v allowBackstage:%v}",
				c.name, got.MaxConcurrentSessions, got.EnforceViewOnly, got.AllowBackstageUnderViewOnly,
				c.wantCap, c.wantViewOnly, c.wantAllow)
		}
	}
}

// The audit trail must record the WHOLE policy that was written, including the backstage opt-out. "Who
// re-opened backstage on a watch-only group, and when" has to be answerable from the events alone: the PUT is
// a full overwrite, so the values in the event ARE the resulting state, and an opt-out that never reached the
// trail would leave a security-relevant change indistinguishable from an ordinary cap edit.
func TestSetGroupSessionPolicyAuditsTheBackstageOptOut(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	ctx := context.Background()
	g := &MachineGroup{Name: "Patch Window"}
	if err := srv.MachineGroups.CreateMachineGroup(ctx, "tenant-123", g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("PUT", "/machine-groups/"+g.ID+"/session-policy",
		strings.NewReader(`{"max_concurrent_sessions":0,"enforce_view_only":true,"allow_backstage_under_view_only":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	events, err := srv.MgmtAudit.ListEvents(ctx, "tenant-123", 20)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found *MgmtAuditEvent
	for i := range events {
		if events[i].Action == "machine_group.session_policy.set" && events[i].TargetID == g.ID {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no machine_group.session_policy.set event for %s in %+v", g.ID, events)
	}
	// Decoded, not string-matched: a stray "true" elsewhere in the blob must not pass this. A POINTER so a
	// MISSING key is distinguishable from a present-but-false one — the failure mode being guarded is the
	// handler dropping the key, and `false` would look identical to "recorded as off" otherwise.
	var meta struct {
		AllowBackstage  *bool `json:"allow_backstage_under_view_only"`
		EnforceViewOnly *bool `json:"enforce_view_only"`
	}
	if err := json.Unmarshal(found.Metadata, &meta); err != nil {
		t.Fatalf("decode audit metadata %s: %v", found.Metadata, err)
	}
	if meta.EnforceViewOnly == nil || !*meta.EnforceViewOnly {
		t.Errorf("audit metadata enforce_view_only = %v, want true (raw: %s)", meta.EnforceViewOnly, found.Metadata)
	}
	if meta.AllowBackstage == nil || !*meta.AllowBackstage {
		t.Errorf("audit metadata allow_backstage_under_view_only = %v, want true (raw: %s)",
			meta.AllowBackstage, found.Metadata)
	}
}
