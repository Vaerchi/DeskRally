package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The EXACT public surface, maintained BY HAND and independently of publicapi.go (docs/59 review R1:
// a rule over capability labels bounds labels, not operations — only an explicit tuple set catches an
// excluded route smuggled in under a manage_* label, or a route silently dropped). Any addition,
// omission, duplicate, or capability change turns this red until it is changed HERE, deliberately.
//
// Note on the effective surface: Go's ServeMux also answers HEAD for every GET pattern with the same
// handler and no body — that is part of the HTTP contract of GET, not a distinct operation.
var pinnedPublicAPISurface = map[string]struct {
	op  string
	cap Capability
}{
	"GET /machines":                          {"listMachines", CapViewMachines},
	"GET /machines/{id}":                     {"getMachine", CapViewMachines},
	"GET /machine-groups":                    {"listMachineGroups", CapViewMachines},
	"GET /sessions":                          {"listSessions", CapViewSessions},
	"GET /audit":                             {"listAudit", CapViewAudit},
	"GET /audit/summary":                     {"auditSummary", CapViewAudit},
	"POST /machine-groups":                   {"createMachineGroup", CapManageGroups},
	"PATCH /machine-groups/{id}":             {"renameMachineGroup", CapManageGroups},
	"POST /machine-groups/{id}/move":         {"moveMachineGroup", CapManageGroups},
	"DELETE /machine-groups/{id}":            {"deleteMachineGroup", CapManageGroups},
	"POST /machines/{id}/group":              {"setMachineGroup", CapManageMachines},
	"POST /machines/bulk-group":              {"bulkSetMachineGroup", CapManageMachines},
	"PUT /machines/{id}/properties/{key}":    {"setMachineProperty", CapManageMachines},
	"DELETE /machines/{id}/properties/{key}": {"deleteMachineProperty", CapManageMachines},
}

// The write operations that carry a JSON request body (the others send none). Hand-maintained with
// the surface pin above; the spec-shape test asserts requestBody exists exactly here.
var pinnedBodyCarryingOps = map[string]bool{
	"createMachineGroup":  true,
	"renameMachineGroup":  true,
	"moveMachineGroup":    true,
	"setMachineGroup":     true,
	"bulkSetMachineGroup": true,
	"setMachineProperty":  true,
}

// TestPublicAPISurfaceIsPinned replaces the v1 read-only invariant (docs/59 widened the surface to
// the fleet writes) with something stronger: the exact operation set, pinned. On top of the tuple
// match: every capability must be token-grantable (the surface cannot outgrow what a token may
// hold), every GET must carry a view_* capability, and every write a manage_* one.
func TestPublicAPISurfaceIsPinned(t *testing.T) {
	viewCaps := map[Capability]bool{CapViewMachines: true, CapViewSessions: true, CapViewAudit: true}
	writeCaps := map[Capability]bool{CapManageMachines: true, CapManageGroups: true}

	got := map[string]publicAPIRoute{}
	seenOp := map[string]bool{}
	for _, rt := range publicAPIRoutes() {
		key := rt.Method + " " + rt.Path
		if _, dup := got[key]; dup {
			t.Errorf("route %s declared twice", key)
		}
		got[key] = rt
		if rt.OperationID == "" || seenOp[rt.OperationID] {
			t.Errorf("operationId %q is empty or duplicated", rt.OperationID)
		}
		seenOp[rt.OperationID] = true
		if rt.handler == nil {
			t.Errorf("%s has a nil handler selector", key)
		}
		if !strings.HasPrefix(rt.Path, "/") {
			t.Errorf("path %q must start with /", rt.Path)
		}
		if !IsAPITokenGrantableCapability(rt.Capability) {
			t.Errorf("%s requires %q, which is not token-grantable — no token could call it", key, rt.Capability)
		}
		if rt.Method == http.MethodGet && !viewCaps[rt.Capability] {
			t.Errorf("%s: a GET must carry a view capability, has %q", key, rt.Capability)
		}
		if rt.Method != http.MethodGet && !writeCaps[rt.Capability] {
			t.Errorf("%s: a write must carry manage_machines or manage_groups, has %q", key, rt.Capability)
		}
	}
	for key, want := range pinnedPublicAPISurface {
		rt, ok := got[key]
		if !ok {
			t.Errorf("pinned route %s is MISSING from the table", key)
			continue
		}
		if rt.OperationID != want.op || rt.Capability != want.cap {
			t.Errorf("%s = (%s, %s), pinned as (%s, %s)", key, rt.OperationID, rt.Capability, want.op, want.cap)
		}
	}
	for key := range got {
		if _, ok := pinnedPublicAPISurface[key]; !ok {
			t.Errorf("route %s is in the table but NOT pinned here — pin it deliberately or remove it", key)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Write fixtures: one per write route, giving a VALID request (with its prerequisites seeded), the
// expected success, the audit action, a verify of the persisted mutation, and a verify that a DENIED
// request changed nothing. docs/59 review R2: enforcement is proven by behavior through the mounted
// chain — a mutation read back from the store — never by table metadata or a 400-reaches-validation.
// ---------------------------------------------------------------------------------------------

type publicAPIWriteFixture struct {
	key         string // "METHOD path-template", matching the pinned surface
	wantStatus  int
	auditAction string
	auditCount  int // successful-mutation audit events expected (bulk moves two machines)
	// prepare seeds prerequisites on srv and returns the concrete path + request body.
	prepare func(t *testing.T, srv *Server) (path, body string)
	// verify asserts the response envelope and the PERSISTED state after success.
	verify func(t *testing.T, srv *Server, resp []byte)
	// verifyUnchanged asserts nothing persisted after a denial.
	verifyUnchanged func(t *testing.T, srv *Server)
}

func seedPublicAPIGroup(t *testing.T, srv *Server, name string) string {
	t.Helper()
	g := &MachineGroup{Name: name}
	if err := srv.MachineGroups.CreateMachineGroup(context.Background(), "tenant-123", g); err != nil {
		t.Fatalf("seed group %q: %v", name, err)
	}
	return g.ID
}

func seedPublicAPIMachine(t *testing.T, srv *Server, device, groupID string) string {
	t.Helper()
	m := &Machine{DeviceID: device, Name: device, GroupID: groupID}
	store, ok := srv.Machines.(*InMemoryMachineStore)
	if !ok {
		t.Fatalf("test server machine store is %T, want *InMemoryMachineStore", srv.Machines)
	}
	if err := store.EnrollMachine(context.Background(), "tenant-123", m); err != nil {
		t.Fatalf("seed machine %q: %v", device, err)
	}
	return m.ID
}

func groupNames(t *testing.T, srv *Server) []string {
	t.Helper()
	gs, err := srv.MachineGroups.ListMachineGroups(context.Background(), "tenant-123")
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	names := make([]string, 0, len(gs))
	for _, g := range gs {
		names = append(names, g.Name)
	}
	return names
}

func machineGroupOf(t *testing.T, srv *Server, machineID string) string {
	t.Helper()
	m, err := srv.Machines.GetMachineByID(context.Background(), "tenant-123", machineID)
	if err != nil {
		t.Fatalf("get machine %s: %v", machineID, err)
	}
	return m.GroupID
}

func propertiesOf(t *testing.T, srv *Server, machineID string) []MachineProperty {
	t.Helper()
	props, err := srv.MachineProperties.ListProperties(context.Background(), "tenant-123", machineID)
	if err != nil {
		t.Fatalf("list properties: %v", err)
	}
	return props
}

type seededIDs struct{ machineID, machineID2, fromID, toID string }

func publicAPIWriteFixtures() []publicAPIWriteFixture {
	// Per-fixture seeded-id state, shared between prepare/verify/verifyUnchanged by closure capture.
	// A later prepare() on a fresh server overwrites it only after the earlier verify has run.
	moveIDs := &seededIDs{}
	bulkIDs := &seededIDs{}
	propSetIDs := &seededIDs{}
	propDelIDs := &seededIDs{}
	moveGroupIDs := &struct{ parent, child string }{}
	return []publicAPIWriteFixture{
		{
			key: "POST /machine-groups", wantStatus: http.StatusCreated,
			auditAction: "machine_group.created", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				return publicAPIBasePath + "/machine-groups", `{"name":"API Group"}`
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				var out struct {
					MachineGroup MachineGroup `json:"machine_group"`
				}
				if err := json.Unmarshal(resp, &out); err != nil || out.MachineGroup.ID == "" || out.MachineGroup.Name != "API Group" {
					t.Fatalf("create envelope = %s (err %v)", resp, err)
				}
				if names := groupNames(t, srv); len(names) != 1 || names[0] != "API Group" {
					t.Fatalf("persisted groups = %v, want [API Group]", names)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				if names := groupNames(t, srv); len(names) != 0 {
					t.Fatalf("denied create persisted %v", names)
				}
			},
		},
		{
			key: "PATCH /machine-groups/{id}", wantStatus: http.StatusOK,
			auditAction: "machine_group.renamed", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				id := seedPublicAPIGroup(t, srv, "Before")
				return publicAPIBasePath + "/machine-groups/" + id, `{"name":"After"}`
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				if !strings.Contains(string(resp), `"machine_group"`) {
					t.Fatalf("rename envelope = %s", resp)
				}
				if names := groupNames(t, srv); len(names) != 1 || names[0] != "After" {
					t.Fatalf("persisted groups = %v, want [After]", names)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				if names := groupNames(t, srv); len(names) != 1 || names[0] != "Before" {
					t.Fatalf("denied rename left %v, want [Before]", names)
				}
			},
		},
		{
			// docs/62: the move verb. A token is tenant-wide, so every R3 coverage rule holds; the fixture
			// proves the persisted reparent and that a denied call left the tree alone.
			key: "POST /machine-groups/{id}/move", wantStatus: http.StatusOK,
			auditAction: "machine_group.reparented", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				parent := seedPublicAPIGroup(t, srv, "NewParent")
				child := seedPublicAPIGroup(t, srv, "Mover")
				moveGroupIDs.parent, moveGroupIDs.child = parent, child
				return publicAPIBasePath + "/machine-groups/" + child + "/move", `{"parent_id":"` + parent + `"}`
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				var out struct {
					MachineGroup MachineGroup `json:"machine_group"`
				}
				if err := json.Unmarshal(resp, &out); err != nil || out.MachineGroup.ID != moveGroupIDs.child ||
					out.MachineGroup.ParentID == nil || *out.MachineGroup.ParentID != moveGroupIDs.parent {
					t.Fatalf("move envelope = %s (err %v)", resp, err)
				}
				tree, _, err := srv.MachineGroups.GroupTree(context.Background(), "tenant-123")
				if err != nil || tree[moveGroupIDs.child] != moveGroupIDs.parent {
					t.Fatalf("persisted tree = %v (err %v), want %s under %s", tree, err, moveGroupIDs.child, moveGroupIDs.parent)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				tree, _, err := srv.MachineGroups.GroupTree(context.Background(), "tenant-123")
				if err != nil || tree[moveGroupIDs.child] != "" {
					t.Fatalf("denied move changed the tree: %v (err %v)", tree, err)
				}
			},
		},
		{
			key: "DELETE /machine-groups/{id}", wantStatus: http.StatusOK,
			auditAction: "machine_group.deleted", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				id := seedPublicAPIGroup(t, srv, "Doomed")
				return publicAPIBasePath + "/machine-groups/" + id, ""
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				var out struct {
					Deleted bool   `json:"deleted"`
					ID      string `json:"id"`
				}
				if err := json.Unmarshal(resp, &out); err != nil || !out.Deleted || out.ID == "" {
					t.Fatalf("delete envelope = %s (err %v)", resp, err)
				}
				if names := groupNames(t, srv); len(names) != 0 {
					t.Fatalf("group survived delete: %v", names)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				if names := groupNames(t, srv); len(names) != 1 {
					t.Fatalf("denied delete removed the group: %v", names)
				}
			},
		},
		{
			key: "POST /machines/{id}/group", wantStatus: http.StatusOK,
			auditAction: "machine.group_changed", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				from := seedPublicAPIGroup(t, srv, "From")
				to := seedPublicAPIGroup(t, srv, "To")
				m := seedPublicAPIMachine(t, srv, "dev-move", from)
				*moveIDs = seededIDs{machineID: m, fromID: from, toID: to}
				return publicAPIBasePath + "/machines/" + m + "/group", `{"group_id":"` + to + `"}`
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				if !strings.Contains(string(resp), `"machine"`) {
					t.Fatalf("move envelope = %s", resp)
				}
				fx := *moveIDs
				if got := machineGroupOf(t, srv, fx.machineID); got != fx.toID {
					t.Fatalf("machine group = %s, want the target %s", got, fx.toID)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				fx := *moveIDs
				if got := machineGroupOf(t, srv, fx.machineID); got != fx.fromID {
					t.Fatalf("denied move changed the group to %s", got)
				}
			},
		},
		{
			key: "POST /machines/bulk-group", wantStatus: http.StatusOK,
			auditAction: "machine.group_changed", auditCount: 2,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				from := seedPublicAPIGroup(t, srv, "From")
				to := seedPublicAPIGroup(t, srv, "To")
				m1 := seedPublicAPIMachine(t, srv, "dev-b1", from)
				m2 := seedPublicAPIMachine(t, srv, "dev-b2", from)
				*bulkIDs = seededIDs{machineID: m1, machineID2: m2, fromID: from, toID: to}
				body, _ := json.Marshal(map[string]any{"machine_ids": []string{m1, m2, "no-such-machine"}, "group_id": to})
				return publicAPIBasePath + "/machines/bulk-group", string(body)
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				var out struct {
					Results []struct {
						MachineID string `json:"machine_id"`
						OK        bool   `json:"ok"`
						Error     string `json:"error"`
					} `json:"results"`
				}
				if err := json.Unmarshal(resp, &out); err != nil || len(out.Results) != 3 {
					t.Fatalf("bulk envelope = %s (err %v), want 3 results", resp, err)
				}
				fx := *bulkIDs
				seen := map[string]bool{}
				for _, r := range out.Results {
					if seen[r.MachineID] {
						t.Fatalf("duplicate bulk result for %s", r.MachineID)
					}
					seen[r.MachineID] = true
					switch r.MachineID {
					case fx.machineID, fx.machineID2:
						if !r.OK {
							t.Fatalf("bulk item %s not ok: %s", r.MachineID, r.Error)
						}
					case "no-such-machine":
						if r.OK || r.Error == "" {
							t.Fatalf("unknown machine item = %+v, want ok:false with an error", r)
						}
					default:
						t.Fatalf("unexpected bulk result %+v", r)
					}
				}
				// Exactly the three submitted ids, each once (set equality, not just count+allowlist).
				for _, id := range []string{fx.machineID, fx.machineID2, "no-such-machine"} {
					if !seen[id] {
						t.Fatalf("bulk results missing an entry for %s", id)
					}
				}
				for _, id := range []string{fx.machineID, fx.machineID2} {
					if got := machineGroupOf(t, srv, id); got != fx.toID {
						t.Fatalf("bulk did not move %s (group %s, want %s)", id, got, fx.toID)
					}
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				fx := *bulkIDs
				for _, id := range []string{fx.machineID, fx.machineID2} {
					if got := machineGroupOf(t, srv, id); got != fx.fromID {
						t.Fatalf("denied bulk moved %s to %s", id, got)
					}
				}
			},
		},
		{
			key: "PUT /machines/{id}/properties/{key}", wantStatus: http.StatusOK,
			auditAction: "machine.property.set", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				g := seedPublicAPIGroup(t, srv, "PropGroup")
				m := seedPublicAPIMachine(t, srv, "dev-prop", g)
				propSetIDs.machineID = m
				return publicAPIBasePath + "/machines/" + m + "/properties/site", `{"value":"HQ"}`
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				var out struct {
					Property MachineProperty `json:"property"`
				}
				if err := json.Unmarshal(resp, &out); err != nil || out.Property.Key != "site" || out.Property.Value != "HQ" {
					t.Fatalf("set-property envelope = %s (err %v)", resp, err)
				}
				props := propertiesOf(t, srv, propSetIDs.machineID)
				if len(props) != 1 || props[0].Key != "site" || props[0].Value != "HQ" {
					t.Fatalf("persisted properties = %+v, want [site=HQ]", props)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				if props := propertiesOf(t, srv, propSetIDs.machineID); len(props) != 0 {
					t.Fatalf("denied set persisted %+v", props)
				}
			},
		},
		{
			key: "DELETE /machines/{id}/properties/{key}", wantStatus: http.StatusOK,
			auditAction: "machine.property.delete", auditCount: 1,
			prepare: func(t *testing.T, srv *Server) (string, string) {
				g := seedPublicAPIGroup(t, srv, "PropGroup")
				m := seedPublicAPIMachine(t, srv, "dev-propdel", g)
				if err := srv.MachineProperties.SetProperty(context.Background(), "tenant-123", m, "site", "HQ"); err != nil {
					t.Fatalf("seed property: %v", err)
				}
				propDelIDs.machineID = m
				return publicAPIBasePath + "/machines/" + m + "/properties/site", ""
			},
			verify: func(t *testing.T, srv *Server, resp []byte) {
				if !strings.Contains(string(resp), `"deleted":true`) {
					t.Fatalf("delete-property envelope = %s", resp)
				}
				if props := propertiesOf(t, srv, propDelIDs.machineID); len(props) != 0 {
					t.Fatalf("property survived delete: %+v", props)
				}
			},
			verifyUnchanged: func(t *testing.T, srv *Server) {
				if props := propertiesOf(t, srv, propDelIDs.machineID); len(props) != 1 {
					t.Fatalf("denied delete removed the property: %+v", props)
				}
			},
		},
	}
}

// publicAPIWriteRequest drives one fixture request through the full mounted chain.
func publicAPIWriteRequest(h http.Handler, key, path, body string) *httptest.ResponseRecorder {
	method := strings.SplitN(key, " ", 2)[0]
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPublicAPIWritesBehave: for each write route, a principal holding EXACTLY the documented
// capability (the same NewCapabilityMembership shape an API token resolves to) performs a valid
// request through the mounted chain; the response envelope, the PERSISTED state, and the audit
// trail's action + actor are all asserted. Then a principal holding every OTHER grantable capability
// is refused AND the state is proven unchanged. (docs/59 review R2.)
func TestPublicAPIWritesBehave(t *testing.T) {
	routeFor := func(key string) publicAPIRoute {
		for _, rt := range publicAPIRoutes() {
			if rt.Method+" "+rt.Path == key {
				return rt
			}
		}
		t.Fatalf("fixture %s has no route", key)
		return publicAPIRoute{}
	}
	allGrantableExcept := func(skip Capability) []Capability {
		var caps []Capability
		for _, c := range APITokenGrantableCapabilities() {
			if c != skip {
				caps = append(caps, c)
			}
		}
		return caps
	}
	fixtures := publicAPIWriteFixtures()
	if len(fixtures) != 8 {
		t.Fatalf("write fixtures = %d, want one per pinned write route (8)", len(fixtures))
	}
	for _, fx := range fixtures {
		t.Run(fx.key, func(t *testing.T) {
			rt := routeFor(fx.key)

			// Success path, with ONLY the documented capability.
			only := &Principal{UserID: "u-token", TenantID: "tenant-123",
				Grant: NewGrant("u-token", "tenant-123", NewCapabilityMembership([]Capability{rt.Capability}, AllGroups()))}
			srv, _ := newTestServer(only)
			path, body := fx.prepare(t, srv)
			rec := publicAPIWriteRequest(srv.Handler(), fx.key, path, body)
			if rec.Code != fx.wantStatus {
				t.Fatalf("%s with only %q = %d, want %d (body %s)", fx.key, rt.Capability, rec.Code, fx.wantStatus, rec.Body.String())
			}
			fx.verify(t, srv, rec.Body.Bytes())

			// The mutation is audited with the caller as actor.
			events, err := srv.MgmtAudit.ListEvents(context.Background(), "tenant-123", 50)
			if err != nil {
				t.Fatalf("list audit: %v", err)
			}
			matching := 0
			for _, e := range events {
				if e.Action == fx.auditAction {
					matching++
					if e.ActorUserID != "u-token" {
						t.Fatalf("audit %s actor = %q, want the calling principal u-token", e.Action, e.ActorUserID)
					}
				}
			}
			if matching != fx.auditCount {
				t.Fatalf("audit has %d %s events, want %d", matching, fx.auditAction, fx.auditCount)
			}

			// Denial path: every OTHER grantable capability, fresh server — refused, nothing changed.
			without := &Principal{UserID: "u-token", TenantID: "tenant-123",
				Grant: NewGrant("u-token", "tenant-123", NewCapabilityMembership(allGrantableExcept(rt.Capability), AllGroups()))}
			srv2, _ := newTestServer(without)
			path2, body2 := fx.prepare(t, srv2)
			rec2 := publicAPIWriteRequest(srv2.Handler(), fx.key, path2, body2)
			if rec2.Code != http.StatusForbidden {
				t.Fatalf("%s WITHOUT %q = %d, want 403 (body %s)", fx.key, rt.Capability, rec2.Code, rec2.Body.String())
			}
			fx.verifyUnchanged(t, srv2)
			if events, _ := srv2.MgmtAudit.ListEvents(context.Background(), "tenant-123", 50); len(events) != 0 {
				t.Fatalf("denied %s still recorded audit events: %+v", fx.key, events)
			}
		})
	}
}

// The /api/v1 alias must apply the identical auth → capability gating as the legacy path: a
// read-only principal can read, and a principal lacking the capability is forbidden — proving the
// alias is not a bypass.
func TestPublicAPIAliasEnforcesCapability(t *testing.T) {
	cases := []struct {
		name       string
		role       Role
		path       string
		wantStatus int
	}{
		{"readonly lists machines", RoleReadOnly, publicAPIBasePath + "/machines", http.StatusOK},
		{"auditor views audit", RoleAuditor, publicAPIBasePath + "/audit", http.StatusOK},
		{"technician cannot view audit", RoleTechnician, publicAPIBasePath + "/audit", http.StatusForbidden},
		{"technician lists sessions", RoleTechnician, publicAPIBasePath + "/sessions", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Principal{
				UserID:   "u1",
				TenantID: "tenant-123",
				Grant:    NewGrant("u1", "tenant-123", NewMembership(tc.role, AllGroups())),
			}
			srv, binder := newTestServer(p)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.path, nil)

			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("GET %s as %s = %d, want %d (body %s)",
					tc.path, tc.role, rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK && binder.bound != "tenant-123" {
				t.Fatalf("RLS hook bound %q, want tenant-123", binder.bound)
			}
		})
	}
}

// An unauthenticated caller is rejected on a versioned route by the same auth middleware as the
// legacy surface (the alias is behind the protected chain, not in front of it).
func TestPublicAPIAliasUnauthenticatedRejected(t *testing.T) {
	srv, _ := newTestServer(nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", publicAPIBasePath+"/machines", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil principal GET %s/machines = %d, want 401", publicAPIBasePath, rec.Code)
	}
}

// A mutating /api/v1 request that arrives with a SESSION COOKIE alongside its Bearer header is
// subject to the cookie's CSRF double-submit: without the CSRF header it is rejected BEFORE any
// mutation (docs/59 review R3 — the two credential systems must not disagree about a mutation).
// A pure-Bearer request (no cookie) is exempt and succeeds, which is what makes the cookie's
// presence the deciding factor. The invalid-token/no-cookie-fallback half lives with the real
// authenticator's tests (csrf_test.go, apitoken tests).
func TestPublicAPIWriteWithSessionCookieRequiresCSRF(t *testing.T) {
	p := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}

	// Cookie present, no CSRF header → refused, nothing persisted.
	srv, _ := newTestServer(p)
	rec := doBearerJSON(t, srv.Handler(), "POST", publicAPIBasePath+"/machine-groups", "rmt_api_x",
		map[string]any{"name": "Nope"}, &http.Cookie{Name: DefaultSessionCookie, Value: "sess"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cookie+bearer write without CSRF = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if names := groupNames(t, srv); len(names) != 0 {
		t.Fatalf("CSRF-refused write persisted %v", names)
	}

	// No cookie → the Bearer request is exempt from CSRF and the write lands.
	srv2, _ := newTestServer(p)
	rec2 := doBearerJSON(t, srv2.Handler(), "POST", publicAPIBasePath+"/machine-groups", "rmt_api_x",
		map[string]any{"name": "Yes"}, nil)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("pure-bearer write = %d, want 201 (body %s)", rec2.Code, rec2.Body.String())
	}
	if names := groupNames(t, srv2); len(names) != 1 || names[0] != "Yes" {
		t.Fatalf("pure-bearer write persisted %v, want [Yes]", names)
	}
}

// The spec is PUBLIC (served to a nil principal) and self-describing.
func TestPublicAPISpecIsPublic(t *testing.T) {
	srv, _ := newTestServer(nil)
	for _, path := range []string{"/api/openapi.json", publicAPIBasePath + "/openapi.json"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s (nil principal) = %d, want 200 (public)", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("GET %s content-type = %q, want application/json", path, ct)
		}
	}
}

// The served document must describe EXACTLY the routes that publicAPIRoutes() declares — no more,
// no fewer — and each documented operation must carry the capability the route enforces. This is
// the anti-drift contract: adding a route without documenting it, or documenting one that does not
// exist, turns this red. (The pinned-surface test above holds the table itself to the hand-written
// contract; this one holds the DOCUMENT to the table.)
func TestPublicAPISpecMatchesRouteTable(t *testing.T) {
	srv, _ := newTestServer(nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/openapi.json", nil))

	var doc struct {
		OpenAPI string `json:"openapi"`
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Cap         string `json:"x-required-capability"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec is not valid JSON: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", doc.OpenAPI)
	}
	if len(doc.Servers) != 1 {
		t.Errorf("servers = %+v, want exactly one", doc.Servers)
	}

	// Build the expected set from the table and compare both directions.
	type mp struct{ method, path string }
	want := map[mp]publicAPIRoute{}
	for _, rt := range publicAPIRoutes() {
		want[mp{strings.ToLower(rt.Method), rt.Path}] = rt
	}
	got := map[mp]struct{ op, cap string }{}
	for path, ops := range doc.Paths {
		for method, op := range ops {
			got[mp{method, path}] = struct{ op, cap string }{op.OperationID, op.Cap}
		}
	}
	if len(got) != len(want) {
		t.Errorf("spec documents %d operations, table declares %d", len(got), len(want))
	}
	for k, rt := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("route %s %s is in the table but NOT documented", k.method, k.path)
			continue
		}
		if g.op != rt.OperationID {
			t.Errorf("%s %s operationId = %q, want %q", k.method, k.path, g.op, rt.OperationID)
		}
		if g.cap != string(rt.Capability) {
			t.Errorf("%s %s x-required-capability = %q, want %q", k.method, k.path, g.cap, rt.Capability)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("route %s %s is documented but NOT in the table (phantom route)", k.method, k.path)
		}
	}
}

// Every documented operation must carry REAL shapes (docs/59): a typed success envelope (never the
// bare generic object), a requestBody exactly on the operations pinned as body-carrying, and every
// {param} in its path declared as a parameter — an undeclared {key} would make the document invalid
// for a code generator.
func TestPublicAPISpecSchemasAreTyped(t *testing.T) {
	srv, _ := newTestServer(nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/openapi.json", nil))

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Description string `json:"description"`
			RequestBody *struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec is not valid JSON: %v", err)
	}
	for path, ops := range doc.Paths {
		for method, op := range ops {
			// The retry caveat belongs on every write EXCEPT bulk, whose handler answers 200 with an
			// item-level audit error instead (review f8e839aa F1) and documents that itself.
			const caveat = "is a 500 even though the change persisted"
			if method != "get" {
				if op.OperationID == "bulkSetMachineGroup" {
					if strings.Contains(op.Description, caveat) {
						t.Errorf("%s %s: bulk carries the generated 500 caveat, but bulk answers 200 with an item-level audit error", method, path)
					}
					if !strings.Contains(op.Description, "could not record audit") {
						t.Errorf("%s %s: bulk's own audit caveat is missing from its description", method, path)
					}
				} else if !strings.Contains(op.Description, caveat) {
					t.Errorf("%s %s: write is missing the generated committed-then-500 retry caveat", method, path)
				}
			}
			// The success response is the one 2xx entry; its schema must carry properties.
			successes := 0
			for status, resp := range op.Responses {
				if !strings.HasPrefix(status, "2") {
					continue
				}
				successes++
				schema, ok := resp.Content["application/json"]
				if !ok {
					t.Errorf("%s %s %s: success response has no JSON content", method, path, status)
					continue
				}
				if props, ok := schema.Schema["properties"].(map[string]any); !ok || len(props) == 0 {
					t.Errorf("%s %s %s: success schema is generic (%v), want a typed envelope", method, path, status, schema.Schema)
				}
			}
			if successes != 1 {
				t.Errorf("%s %s: %d success responses, want exactly 1", method, path, successes)
			}
			// requestBody exactly where pinned.
			if pinnedBodyCarryingOps[op.OperationID] {
				if op.RequestBody == nil {
					t.Errorf("%s %s (%s): missing requestBody", method, path, op.OperationID)
				} else if schema, ok := op.RequestBody.Content["application/json"]; !ok {
					t.Errorf("%s %s: requestBody has no JSON content", method, path)
				} else if props, ok := schema.Schema["properties"].(map[string]any); !ok || len(props) == 0 {
					t.Errorf("%s %s: requestBody schema is generic", method, path)
				}
			} else if op.RequestBody != nil {
				t.Errorf("%s %s (%s): has a requestBody but is not pinned as body-carrying", method, path, op.OperationID)
			}
			// Every {param} in the path is declared.
			declared := map[string]bool{}
			for _, p := range op.Parameters {
				if p.In == "path" {
					declared[p.Name] = true
				}
			}
			for _, name := range pathParamNames(path) {
				if !declared[name] {
					t.Errorf("%s %s: path parameter {%s} is not declared", method, path, name)
				}
			}
			if len(declared) != len(pathParamNames(path)) {
				t.Errorf("%s %s: declares %d path params, path has %d", method, path, len(declared), len(pathParamNames(path)))
			}
		}
	}
}

// Every documented route must actually be MOUNTED on the server: a capable principal with a VALID
// request (per-route fixtures for the writes) gets the route's success, never the ServeMux's
// plain-text 404. This closes the gap the spec/table comparison cannot see — that a declared route
// is registered, not merely described.
func TestPublicAPIDocumentedRoutesAreMounted(t *testing.T) {
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	fixtures := map[string]publicAPIWriteFixture{}
	for _, fx := range publicAPIWriteFixtures() {
		fixtures[fx.key] = fx
	}
	for _, rt := range publicAPIRoutes() {
		key := rt.Method + " " + rt.Path
		srv, _ := newTestServer(p)
		var rec *httptest.ResponseRecorder
		want := http.StatusOK
		if rt.Method == http.MethodGet {
			// "{id}" resolves against the permissive machine store to a synthetic machine.
			path := publicAPIBasePath + strings.ReplaceAll(rt.Path, "{id}", "m-1")
			rec = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(rt.Method, path, nil))
		} else {
			fx, ok := fixtures[key]
			if !ok {
				t.Errorf("write route %s has no fixture — add one to publicAPIWriteFixtures", key)
				continue
			}
			path, body := fx.prepare(t, srv)
			rec = publicAPIWriteRequest(srv.Handler(), key, path, body)
			want = fx.wantStatus
		}
		if rec.Code == http.StatusNotFound && strings.TrimSpace(rec.Body.String()) == "404 page not found" {
			t.Errorf("%s is documented but not mounted (ServeMux 404)", key)
			continue
		}
		if rec.Code != want {
			t.Errorf("%s as owner = %d, want %d (body %s)", key, rec.Code, want, rec.Body.String())
		}
	}
}

// The capability the spec ADVERTISES for a route must be the capability the handler actually
// ENFORCES — not merely the one the table records. For each route: a principal holding ONLY the
// documented capability completes the operation, and a principal holding every other grantable
// capability but NOT the documented one is forbidden. (The write half of this now lives in
// TestPublicAPIWritesBehave, which additionally proves the mutation and its denial-leaves-state;
// this test keeps the read half and the full positive/negative capability sweep.)
func TestPublicAPIDocumentedCapabilityIsEnforced(t *testing.T) {
	allGrantableExcept := func(skip Capability) []Capability {
		var caps []Capability
		for _, c := range APITokenGrantableCapabilities() {
			if c != skip {
				caps = append(caps, c)
			}
		}
		return caps
	}
	fixtures := map[string]publicAPIWriteFixture{}
	for _, fx := range publicAPIWriteFixtures() {
		fixtures[fx.key] = fx
	}
	for _, rt := range publicAPIRoutes() {
		key := rt.Method + " " + rt.Path

		run := func(p *Principal) (*httptest.ResponseRecorder, int) {
			srv, _ := newTestServer(p)
			if rt.Method == http.MethodGet {
				path := publicAPIBasePath + strings.ReplaceAll(rt.Path, "{id}", "m-1")
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, httptest.NewRequest(rt.Method, path, nil))
				return rec, http.StatusOK
			}
			fx, ok := fixtures[key]
			if !ok {
				t.Fatalf("write route %s has no fixture", key)
			}
			path, body := fx.prepare(t, srv)
			return publicAPIWriteRequest(srv.Handler(), key, path, body), fx.wantStatus
		}

		// Positive: exactly the documented capability → the operation completes.
		only := &Principal{UserID: "u1", TenantID: "tenant-123",
			Grant: NewGrant("u1", "tenant-123", NewCapabilityMembership([]Capability{rt.Capability}, AllGroups()))}
		rec, want := run(only)
		if rec.Code != want {
			t.Errorf("%s with ONLY %q = %d, want %d (body %s)", key, rt.Capability, rec.Code, want, rec.Body.String())
		}

		// Negative: every other grantable capability but NOT the documented one → forbidden.
		without := &Principal{UserID: "u1", TenantID: "tenant-123",
			Grant: NewGrant("u1", "tenant-123", NewCapabilityMembership(allGrantableExcept(rt.Capability), AllGroups()))}
		rec2, _ := run(without)
		if rec2.Code != http.StatusForbidden {
			t.Errorf("%s WITHOUT %q (all other caps) = %d, want 403 — handler does not enforce the advertised capability",
				key, rt.Capability, rec2.Code)
		}
	}
}

// Production serves the control plane behind a proxy that strips "/cp", so the document is fetched
// as /cp/api/openapi.json while the handler sees /api/openapi.json. A client resolves the advertised
// server url against the URL it fetched the document FROM; from either spec location, under the
// prefix and without it, that must land on the versioned surface — and a documented path appended
// to it must reach a real route (401 to an anonymous caller, not the 404 of a wrong base).
func TestPublicAPISpecServerURLResolvesUnderAnyPrefix(t *testing.T) {
	srv, _ := newTestServer(nil)
	for _, specPath := range []string{"/api/openapi.json", publicAPIBasePath + "/openapi.json"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", specPath, nil))
		var doc struct {
			Servers []struct {
				URL string `json:"url"`
			} `json:"servers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Servers) != 1 {
			t.Fatalf("GET %s: servers = %+v (err %v), want exactly one", specPath, doc.Servers, err)
		}
		for _, prefix := range []string{"", "/cp"} {
			fetched, _ := url.Parse("https://deskrally.example" + prefix + specPath)
			ref, err := url.Parse(doc.Servers[0].URL)
			if err != nil {
				t.Fatalf("server url %q does not parse: %v", doc.Servers[0].URL, err)
			}
			base := fetched.ResolveReference(ref)
			if want := prefix + publicAPIBasePath; base.Path != want {
				t.Errorf("spec at %s%s: server url %q resolves to %q, want %q",
					prefix, specPath, doc.Servers[0].URL, base.Path, want)
				continue
			}
			// Strip the proxy prefix as Caddy's handle_path does, then call a documented route.
			routed := strings.TrimPrefix(base.Path, prefix) + "/machines"
			call := httptest.NewRecorder()
			srv.Handler().ServeHTTP(call, httptest.NewRequest("GET", routed, nil))
			if call.Code != http.StatusUnauthorized {
				t.Errorf("spec at %s%s: GET %s = %d, want 401 (a real, protected route)",
					prefix, specPath, routed, call.Code)
			}
		}
	}
}
