package controlplane

// Handler-level proofs for nested machine groups (docs/62 stage B) through the real middleware chain with
// real logins: D5 + R3 authorization of group create / rename / delete / policy / move, R9 parent_id
// visibility, the tree-conditional writes (R2) via a racing authenticator, the effective-policy merge and
// its R4 conflict refusals, and seat caps counted over a subtree at POST /sessions.
//
// The tree (all in tenant-1) is the asymmetric one from group_tree_test.go:
//
//	R ── P ── C ── G
//	  └─ S
//	X

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type treeCreds struct {
	cookie, csrfCookie *http.Cookie
	tok                string
}

type treeHTTP struct {
	t        *testing.T
	f        *authFixture
	h        http.Handler
	groups   *InMemoryMachineGroupStore
	machines *InMemoryMachineStore
	policies *InMemoryGroupSessionPolicyStore
	tr       tree5
	creds    map[string]treeCreds
}

const treeTenant = "tenant-1"

// treeUID is a stable, CANONICAL uuid per test user label (a lease renewal's signed preimage needs a real
// uuid technician id).
func treeUID(label string) string {
	h := sha1.Sum([]byte("group-tree-test-user:" + label))
	hx := hex.EncodeToString(h[:16])
	return hx[0:8] + "-" + hx[8:12] + "-4" + hx[13:16] + "-8" + hx[17:20] + "-" + hx[20:32]
}

// newTreeHTTP wires a server with linked in-memory stores, the standard tree and one login per entry of
// users (label -> role and scope; no scope = tenant-wide). wrap, if non-nil, decorates the authenticator.
func newTreeHTTP(t *testing.T, users map[string]struct {
	Role  Role
	Scope []string
}, scopeByName func(tr tree5, names []string) []string, wrap func(Authenticator) Authenticator, opts ...func(*authFixture)) *treeHTTP {
	t.Helper()
	f := newUserAdminFixture(t)
	f.auth.DisableThrottle = true
	for _, o := range opts {
		o(f)
	}
	groups := NewInMemoryMachineGroupStore()
	machines := NewInMemoryMachineStore()
	policies := NewInMemoryGroupSessionPolicyStore()
	LinkGroupStores(groups, f.users, machines)
	f.srv.MachineGroups = groups
	f.auth.MachineGroups = groups
	f.srv.Machines = machines
	f.srv.GroupSessionPolicies = policies
	sessions := NewInMemorySessionRecordStore()
	LinkGroupPolicyStores(groups, policies, sessions)
	f.srv.SessionRecords = sessions
	f.srv.EnrollmentTokens = NewInMemoryEnrollmentTokenStore()

	x := &treeHTTP{t: t, f: f, groups: groups, machines: machines, policies: policies, creds: map[string]treeCreds{}}
	mk := func(name, parent string) string {
		g := &MachineGroup{Name: name}
		if parent != "" {
			g.ParentID = &parent
		}
		if err := groups.CreateMachineGroup(context.Background(), treeTenant, g); err != nil {
			t.Fatalf("create group %s: %v", name, err)
		}
		return g.ID
	}
	x.tr.R = mk("R", "")
	x.tr.P = mk("P", x.tr.R)
	x.tr.C = mk("C", x.tr.P)
	x.tr.G = mk("G", x.tr.C)
	x.tr.S = mk("S", x.tr.R)
	x.tr.X = mk("X", "")

	for label, u := range users {
		id := treeUID(label)
		var scope GroupScope = AllGroups()
		if len(u.Scope) > 0 {
			scope = Groups(scopeByName(x.tr, u.Scope)...)
		}
		f.addUserWithGrant(t, treeTenant, id, label+"@acme.test", uaPw, NewGrant(id, treeTenant, NewMembership(u.Role, scope)))
	}
	if wrap != nil {
		f.srv.Auth = wrap(f.srv.Auth)
	}
	x.h = f.srv.Handler()
	for label := range users {
		cookie, csrfCookie, tok := loginFor(t, f, label+"@acme.test", uaPw)
		x.creds[label] = treeCreds{cookie, csrfCookie, tok}
	}
	return x
}

func nameScope(tr tree5, names []string) []string {
	ids := tr.ids()
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, ids[n])
	}
	return out
}

type userSpec = struct {
	Role  Role
	Scope []string
}

func (x *treeHTTP) call(who, method, path string, body any) *httptest.ResponseRecorder {
	x.t.Helper()
	c := x.creds[who]
	return doJSONWith(x.t, x.h, method, path, body, c.tok, c.cookie, c.csrfCookie)
}

func (x *treeHTTP) want(who, method, path string, body any, status int, label string) *httptest.ResponseRecorder {
	x.t.Helper()
	rec := x.call(who, method, path, body)
	if rec.Code != status {
		x.t.Errorf("%s: %s %s %s = %d, want %d (%s)", label, who, method, path, rec.Code, status, strings.TrimSpace(rec.Body.String()))
	}
	return rec
}

func (x *treeHTTP) parentOf(id string) string {
	x.t.Helper()
	tree, _, _ := x.groups.GroupTree(context.Background(), treeTenant)
	return tree[id]
}

func decodeGroup(t *testing.T, rec *httptest.ResponseRecorder) MachineGroup {
	t.Helper()
	var out struct {
		MachineGroup MachineGroup `json:"machine_group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode group: %v (%s)", err, rec.Body.String())
	}
	return out.MachineGroup
}

func TestGroupHandlersEnforceScopedManagement(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminP": {RoleAdmin, []string{"P"}},
		"adminC": {RoleAdmin, []string{"C"}},
	}, nameScope, nil)
	tr := x.tr
	g := func(id string) string { return "/machine-groups/" + id }

	// ---- create (D5): a ROOT needs a tenant-wide grant; under P needs coverage of P. ----
	x.want("adminP", "POST", "/machine-groups", map[string]any{"name": "root2"}, http.StatusForbidden, "scoped manager creating a ROOT group")
	x.want("adminP", "POST", "/machine-groups", map[string]any{"name": "k", "parent_id": tr.S}, http.StatusForbidden, "create under an uncovered sibling S")
	rec := x.want("adminP", "POST", "/machine-groups", map[string]any{"name": "P2", "parent_id": tr.P}, http.StatusCreated, "create under P")
	p2 := decodeGroup(t, rec)
	if p2.ParentID == nil || *p2.ParentID != tr.P {
		t.Errorf("created group's parent = %v, want P", p2.ParentID)
	}
	rec = x.want("adminP", "POST", "/machine-groups", map[string]any{"name": "C2", "parent_id": tr.C}, http.StatusCreated, "create under C (a child of the scope)")
	c2 := decodeGroup(t, rec).ID
	x.want("adminC", "POST", "/machine-groups", map[string]any{"name": "k", "parent_id": tr.P}, http.StatusForbidden, "{C} creating under its PARENT P")
	rec = x.want("adminC", "POST", "/machine-groups", map[string]any{"name": "C3", "parent_id": tr.C}, http.StatusCreated, "{C} creating under C")
	c3 := decodeGroup(t, rec).ID
	x.want("owner", "POST", "/machine-groups", map[string]any{"name": "root2"}, http.StatusCreated, "tenant-wide manager creating a root")
	x.want("owner", "POST", "/machine-groups", map[string]any{"name": "k", "parent_id": "not-a-uuid"}, http.StatusBadRequest, "malformed parent_id")
	x.want("owner", "POST", "/machine-groups", map[string]any{"name": "k", "parent_id": newUUID()}, http.StatusConflict, "unknown parent")

	// ---- rename (R3): needs coverage of THAT group. ----
	x.want("adminP", "PATCH", g(tr.C), map[string]any{"name": "C-renamed"}, http.StatusOK, "{P} renaming its child C")
	x.want("adminP", "PATCH", g(tr.S), map[string]any{"name": "nope"}, http.StatusForbidden, "{P} renaming S")
	x.want("adminC", "PATCH", g(tr.P), map[string]any{"name": "nope"}, http.StatusForbidden, "{C} renaming its parent P")
	x.want("adminC", "PATCH", g(tr.G), map[string]any{"name": "G-renamed"}, http.StatusOK, "{C} renaming its child G")

	// ---- policy (R3) ----
	if err := x.policies.Set(context.Background(), treeTenant, tr.S, GroupSessionPolicy{MaxConcurrentSessions: 3, MaxSessionDurationSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	pol := map[string]any{"max_concurrent_sessions": 0, "enforce_view_only": true}
	x.want("adminP", "PUT", g(tr.C)+"/session-policy", pol, http.StatusOK, "{P} setting C's policy")
	x.want("adminP", "PUT", g(tr.S)+"/session-policy", pol, http.StatusForbidden, "{P} setting S's policy")
	x.want("adminP", "GET", g(tr.S)+"/session-policy", nil, http.StatusForbidden, "{P} reading S's policy")
	x.want("adminC", "GET", g(tr.P)+"/session-policy", nil, http.StatusForbidden, "{C} reading its parent's policy")
	x.want("adminC", "GET", g(tr.C)+"/session-policy", nil, http.StatusOK, "{C} reading its own policy")
	rec = x.want("adminP", "GET", "/machine-groups/session-policies", nil, http.StatusOK, "list policies as {P}")
	if strings.Contains(rec.Body.String(), tr.S) || !strings.Contains(rec.Body.String(), tr.C) {
		t.Errorf("the policy list must hold C's row and NOT S's: %s", rec.Body.String())
	}

	// ---- move (D5/R3): cover the group, its old parent AND the new parent; root needs tenant-wide. ----
	rec = x.want("adminP", "POST", g(tr.G)+"/move", map[string]any{"parent_id": tr.P}, http.StatusOK, "{P} moving G from C to P")
	if mg := decodeGroup(t, rec); mg.ParentID == nil || *mg.ParentID != tr.P {
		t.Errorf("moved group's parent = %v, want P", mg.ParentID)
	}
	x.want("adminP", "POST", g(tr.S)+"/move", map[string]any{"parent_id": tr.P}, http.StatusForbidden, "{P} moving S (outside its scope)")
	x.want("adminP", "POST", g(tr.C)+"/move", map[string]any{"parent_id": nil}, http.StatusForbidden, "{P} making C a ROOT")
	x.want("adminP", "POST", g(tr.C)+"/move", map[string]any{"parent_id": tr.S}, http.StatusForbidden, "{P} moving C under uncovered S")
	x.want("adminC", "POST", g(tr.C)+"/move", map[string]any{"parent_id": tr.G}, http.StatusForbidden, "{C} moving C: its OLD parent P is not covered")
	x.want("adminP", "POST", g(c2)+"/move", map[string]any{"parent_id": tr.P}, http.StatusOK, "{P} moving C2 from C to P (all inside {P})")
	x.want("owner", "POST", g(newUUID())+"/move", map[string]any{"parent_id": nil}, http.StatusNotFound, "tenant-wide mover, unknown group")
	x.want("adminP", "POST", g(newUUID())+"/move", map[string]any{"parent_id": tr.P}, http.StatusForbidden, "scoped mover, unknown group answers like an uncovered one")
	// validation + structure (owner)
	x.want("owner", "POST", g(tr.S)+"/move", map[string]any{}, http.StatusBadRequest, "move without parent_id")
	x.want("owner", "POST", g(tr.S)+"/move", map[string]any{"parent_id": "nope"}, http.StatusBadRequest, "move to a malformed parent_id")
	x.want("owner", "POST", g(tr.P)+"/move", map[string]any{"parent_id": p2.ID}, http.StatusConflict, "move P under its own child (cycle)")
	x.want("owner", "POST", g(tr.S)+"/move", map[string]any{"parent_id": newUUID()}, http.StatusConflict, "move under an unknown parent")
	rec = x.want("owner", "POST", "/machine-groups", map[string]any{"name": "Z1", "parent_id": p2.ID}, http.StatusCreated, "level-4 group Z1")
	z1 := decodeGroup(t, rec).ID
	x.want("owner", "POST", "/machine-groups", map[string]any{"name": "Z2", "parent_id": z1}, http.StatusConflict, "a 5th level")
	x.want("owner", "POST", g(tr.X)+"/move", map[string]any{"parent_id": z1}, http.StatusConflict, "X under a level-4 parent")
	x.want("owner", "POST", g(tr.C)+"/move", map[string]any{"parent_id": p2.ID}, http.StatusConflict, "tall subtree C (height 2) under a level-3 parent")
	x.want("owner", "POST", g(tr.C)+"/move", map[string]any{"parent_id": nil}, http.StatusOK, "tenant-wide manager making C a root")
	if x.parentOf(tr.C) != "" {
		t.Error("C still has a parent after being made a root")
	}

	// ---- delete (R3 + D7) ----
	x.want("adminP", "DELETE", g(tr.S), nil, http.StatusForbidden, "{P} deleting S")
	x.want("adminP", "DELETE", g(p2.ID), nil, http.StatusConflict, "{P} deleting P2 which has a subgroup")
	x.want("adminC", "DELETE", g(tr.C), nil, http.StatusConflict, "{C} deleting C which has subgroups")
	x.want("adminC", "DELETE", g(tr.P), nil, http.StatusForbidden, "{C} deleting P")
	if x.parentOf(c3) != tr.C {
		t.Errorf("a refused delete re-rooted C3 (parent %q)", x.parentOf(c3))
	}
	x.want("adminC", "DELETE", g(c3), nil, http.StatusOK, "{C} deleting its leaf C3")
	x.want("adminC", "DELETE", g(tr.C), nil, http.StatusOK, "{C} deleting C once it is childless")
	x.want("owner", "DELETE", g(newUUID()), nil, http.StatusNotFound, "delete of an unknown group")

	// ---- audit: group created carries its parent; reparent carries both ends. ----
	var ar struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	rec = x.want("owner", "GET", "/audit?action=machine_group.created", nil, http.StatusOK, "audit created")
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	foundParent := false
	for _, e := range ar.Events {
		var m map[string]any
		_ = json.Unmarshal(e.Metadata, &m)
		if e.TargetID == p2.ID && m["parent_id"] == tr.P {
			foundParent = true
		}
	}
	if !foundParent {
		t.Errorf("no machine_group.created event for P2 carrying parent_id=P: %s", rec.Body.String())
	}
	rec = x.want("owner", "GET", "/audit?action=machine_group.reparented", nil, http.StatusOK, "audit reparented")
	ar.Events = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	foundMove := false
	for _, e := range ar.Events {
		var m map[string]any
		_ = json.Unmarshal(e.Metadata, &m)
		if e.TargetID == tr.G && m["from_parent_id"] == tr.C && m["to_parent_id"] == tr.P {
			foundMove = true
		}
	}
	if !foundMove {
		t.Errorf("no machine_group.reparented event for G from C to P: %s", rec.Body.String())
	}
}

func TestGroupListHidesParentsTheCallerCannotSee(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":   {RoleOwner, nil},
		"viewerP": {RoleReadOnly, []string{"P"}},
		"viewerC": {RoleReadOnly, []string{"C"}},
		"adminC":  {RoleAdmin, []string{"C"}},
	}, nameScope, nil)
	tr := x.tr
	listed := func(who string) map[string]*string {
		rec := x.want(who, "GET", "/machine-groups", nil, http.StatusOK, "list as "+who)
		var out struct {
			Groups []MachineGroup `json:"machine_groups"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]*string{}
		for _, g := range out.Groups {
			m[g.ID] = g.ParentID
		}
		return m
	}
	own := listed("owner")
	if len(own) != 6 || own[tr.C] == nil || *own[tr.C] != tr.P || own[tr.R] != nil {
		t.Errorf("tenant-wide listing = %v, want all 6 with real parents", own)
	}
	vp := listed("viewerP")
	if len(vp) != 3 {
		t.Errorf("{P} sees %d groups, want P, C, G", len(vp))
	}
	if p, ok := vp[tr.P]; !ok || p != nil {
		t.Errorf("{P}'s own root must read parent_id null (its parent R is not visible), got %v", p)
	}
	if p := vp[tr.C]; p == nil || *p != tr.P {
		t.Errorf("{P} must see C's parent P, got %v", p)
	}
	vc := listed("viewerC")
	if len(vc) != 2 {
		t.Errorf("{C} sees %d groups, want C and G", len(vc))
	}
	if p, ok := vc[tr.C]; !ok || p != nil {
		t.Errorf("{C} must see C as a TOP-LEVEL group (parent P hidden): parent_id = %v", p)
	}
	if _, leaked := vc[tr.P]; leaked {
		t.Error("{C} saw its parent group P")
	}
	if p := vc[tr.G]; p == nil || *p != tr.C {
		t.Errorf("{C} must see G's parent C, got %v", p)
	}
	// Mutation responses obey the same rule: {C} creating under C sees parent C; a rename of C answers
	// with a null parent (P is invisible to it) — never P's id.
	rec := x.want("adminC", "POST", "/machine-groups", map[string]any{"name": "C-kid", "parent_id": tr.C}, http.StatusCreated, "create as {C}")
	if g := decodeGroup(t, rec); g.ParentID == nil || *g.ParentID != tr.C {
		t.Errorf("created kid's parent = %v, want C", g.ParentID)
	}
	rec = x.want("adminC", "PATCH", "/machine-groups/"+tr.C, map[string]any{"name": "C2"}, http.StatusOK, "rename as {C}")
	if g := decodeGroup(t, rec); g.ParentID != nil {
		t.Errorf("rename response leaked the hidden parent: %v", *g.ParentID)
	}

	// The effective session policy obeys it too: P's cap still governs C (the value is shown, so the admin
	// sees why C is limited) but P's id is blanked for {C}, while a tenant-wide owner sees it.
	x.setPolicy(tr.P, GroupSessionPolicy{MaxConcurrentSessions: 5})
	seatCaps := func(who string) []GroupSeatCap {
		rec := x.want(who, "GET", "/machine-groups/"+tr.C+"/session-policy", nil, http.StatusOK, "C's policy as "+who)
		var out struct {
			Effective *EffectiveGroupPolicy `json:"effective"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Effective == nil {
			t.Fatalf("%s: no effective policy in the response", who)
		}
		return out.Effective.SeatCaps
	}
	if caps := seatCaps("adminC"); len(caps) != 1 || caps[0].Cap != 5 || caps[0].GroupID != "" {
		t.Errorf("{C}'s effective seat caps = %+v, want P's cap of 5 with the hidden group id blanked", caps)
	}
	if caps := seatCaps("owner"); len(caps) != 1 || caps[0].GroupID != tr.P {
		t.Errorf("owner's effective seat caps = %+v, want P's id visible", caps)
	}
}

// The list endpoint carries a server-computed effective map: a {C}-scoped admin must see the restriction it
// inherits from P although P's own row is not in "policies" and P's id is blanked in the seat caps.
func TestGroupSessionPolicyListCarriesServerEffectiveMap(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminC": {RoleAdmin, []string{"C"}},
	}, nameScope, nil)
	tr := x.tr
	x.setPolicy(tr.P, GroupSessionPolicy{EnforceViewOnly: true, MaxConcurrentSessions: 5})
	list := func(who string) (map[string]bool, map[string]EffectiveGroupPolicy) {
		rec := x.want(who, "GET", "/machine-groups/session-policies", nil, http.StatusOK, "list as "+who)
		var out struct {
			Policies  []GroupSessionPolicy            `json:"policies"`
			Effective map[string]EffectiveGroupPolicy `json:"effective"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		rows := map[string]bool{}
		for _, p := range out.Policies {
			rows[p.GroupID] = true
		}
		return rows, out.Effective
	}
	rows, eff := list("adminC")
	if rows[tr.P] {
		t.Error("{C}'s policies contain P's own row")
	}
	if _, leaked := eff[tr.P]; leaked {
		t.Error("{C}'s effective map contains P")
	}
	c, ok := eff[tr.C]
	if !ok || !c.EnforceViewOnly {
		t.Fatalf("effective[C] = %+v (present %v), want P's inherited enforce_view_only", c, ok)
	}
	if len(c.SeatCaps) != 1 || c.SeatCaps[0].Cap != 5 || c.SeatCaps[0].GroupID != "" {
		t.Errorf("{C}'s seat caps = %+v, want P's cap with the id blanked", c.SeatCaps)
	}
	_, effO := list("owner")
	if oc := effO[tr.C]; !oc.EnforceViewOnly || len(oc.SeatCaps) != 1 || oc.SeatCaps[0].GroupID != tr.P {
		t.Errorf("owner's effective[C] = %+v, want P's id visible", oc)
	}
	if len(effO) != 6 {
		t.Errorf("owner's effective map has %d groups, want 6", len(effO))
	}
}

// racingToggle authenticates through next and THEN runs an armed after() once — a concurrent change that
// lands between the grant being read and the handler's write, which is exactly the window the tree-version
// guard closes. Login traffic is left alone so arming it cannot be consumed by the test's own logins.
func TestWritesAuthorizedOnATreeThatChangedAreRefused(t *testing.T) {
	var racer *racingToggle
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminP": {RoleAdmin, []string{"P"}},
		"target": {RoleTechnician, []string{"C"}},
	}, nameScope, func(next Authenticator) Authenticator {
		racer = &racingToggle{next: next}
		return racer
	})
	tr := x.tr
	ctx := context.Background()
	bump := func() { // a concurrent hierarchy change by someone else
		if err := x.groups.CreateMachineGroup(ctx, treeTenant, &MachineGroup{Name: "concurrent"}); err != nil {
			t.Fatal(err)
		}
	}
	mkMachine := func(group string) *Machine {
		m := &Machine{DeviceID: newUUID(), GroupID: group, Name: "m"}
		if err := x.machines.EnrollMachine(ctx, treeTenant, m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// --- single machine move ---
	m := mkMachine(tr.C)
	racer.set(bump)
	rec := x.call("adminP", "POST", "/machines/"+m.ID+"/group", map[string]any{"group_id": tr.G})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "groups changed") {
		t.Fatalf("machine move on a tree that changed after the grant was read = %d %s, want 409 groups changed", rec.Code, rec.Body.String())
	}
	if got, _ := x.machines.GetMachineByID(ctx, treeTenant, m.ID); got.GroupID != tr.C {
		t.Fatalf("the refused move changed the machine's group to %s", got.GroupID)
	}
	// ...and retried against the settled tree it goes through.
	x.want("adminP", "POST", "/machines/"+m.ID+"/group", map[string]any{"group_id": tr.G}, http.StatusOK, "retry after the change")

	// --- bulk move: per-machine result carries the same refusal ---
	m2 := mkMachine(tr.C)
	racer.set(bump)
	rec = x.call("adminP", "POST", "/machines/bulk-group", map[string]any{"machine_ids": []string{m2.ID}, "group_id": tr.G})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "groups changed, retry") {
		t.Fatalf("bulk move on a changed tree = %d %s, want per-machine 'groups changed, retry'", rec.Code, rec.Body.String())
	}
	if got, _ := x.machines.GetMachineByID(ctx, treeTenant, m2.ID); got.GroupID != tr.C {
		t.Fatalf("the refused bulk move changed the machine's group to %s", got.GroupID)
	}

	// --- assignment edit ---
	racer.set(bump)
	rec = x.call("adminP", "POST", "/users/"+treeUID("target")+"/role", map[string]any{"role": string(RoleReadOnly), "scoped_group_ids": []string{tr.C}})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "groups changed") {
		t.Fatalf("assignment on a tree that changed = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if g, _ := x.f.users.StoredGrantFor(ctx, treeTenant, treeUID("target")); len(g.Members) != 1 || g.Members[0].Role != RoleTechnician {
		t.Fatalf("the refused assignment changed the target: %+v", g.Members)
	}
	x.want("adminP", "POST", "/users/"+treeUID("target")+"/role", map[string]any{"role": string(RoleReadOnly), "scoped_group_ids": []string{tr.C}}, http.StatusOK, "assignment retried on the settled tree")

	// --- invite ---
	racer.set(bump)
	rec = x.call("adminP", "POST", "/users", map[string]any{"email": "late@acme.test", "role": string(RoleReadOnly), "scoped_group_ids": []string{tr.C}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("invite on a tree that changed = %d %s, want 409", rec.Code, rec.Body.String())
	}
	x.want("adminP", "POST", "/users", map[string]any{"email": "late@acme.test", "role": string(RoleReadOnly), "scoped_group_ids": []string{tr.C}}, http.StatusCreated, "invite retried")
}

type racingToggle struct {
	next  Authenticator
	after func()
}

func (r *racingToggle) set(fn func()) { r.after = fn }

func (r *racingToggle) Authenticate(req *http.Request) (*Principal, error) {
	p, err := r.next.Authenticate(req)
	if err == nil && r.after != nil && !strings.HasPrefix(req.URL.Path, "/auth/") {
		fn := r.after
		r.after = nil
		fn()
	}
	return p, err
}

func TestAssignmentScopesAreResolvedAgainstExistingGroups(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminP": {RoleAdmin, []string{"P"}},
		"target": {RoleTechnician, []string{"C"}},
		"other":  {RoleTechnician, []string{"S"}},
	}, nameScope, nil)
	tr := x.tr
	role := func(who, target string, scope any) *httptest.ResponseRecorder {
		body := map[string]any{"role": string(RoleReadOnly)}
		if scope != nil {
			body["scoped_group_ids"] = scope
		}
		return x.call(who, "POST", "/users/"+target+"/role", body)
	}
	// R1a: a submitted scope names EXISTING groups of this tenant only.
	if rec := role("owner", treeUID("target"), []string{newUUID()}); rec.Code != http.StatusBadRequest {
		t.Errorf("assigning a dangling id = %d, want 400", rec.Code)
	}
	foreign := &MachineGroup{Name: "foreign"}
	if err := x.groups.CreateMachineGroup(context.Background(), "tenant-other", foreign); err != nil {
		t.Fatal(err)
	}
	if rec := role("owner", treeUID("target"), []string{foreign.ID}); rec.Code != http.StatusBadRequest {
		t.Errorf("assigning ANOTHER tenant's group = %d, want 400", rec.Code)
	}
	// R1b (asymmetric): {P} may assign {C} and {G}; never {S}, never tenant-wide.
	if rec := role("adminP", treeUID("target"), []string{tr.G}); rec.Code != http.StatusOK {
		t.Errorf("{P} assigning {G} = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := role("adminP", treeUID("target"), []string{tr.S}); rec.Code != http.StatusForbidden {
		t.Errorf("{P} assigning {S} = %d, want 403", rec.Code)
	}
	if rec := role("adminP", treeUID("target"), []string{}); rec.Code != http.StatusForbidden {
		t.Errorf("{P} assigning tenant-wide = %d, want 403", rec.Code)
	}
	// ...and a scoped actor cannot administer a user scoped OUTSIDE its subtree.
	if rec := role("adminP", treeUID("other"), []string{tr.C}); rec.Code != http.StatusForbidden {
		t.Errorf("{P} administering a {S}-scoped user = %d, want 403", rec.Code)
	}
	// R1c: preserve-on-absent carries a dangling id forward, and ONLY a tenant-wide actor may administer
	// such a user (a scoped actor never "includes" an id that expands to nothing).
	if err := x.f.users.SetUserAssignment(context.Background(), treeTenant, treeUID("other"),
		Assignment{Role: RoleTechnician, ScopedGroupIDs: []string{newUUID()}}); err != nil {
		t.Fatal(err)
	}
	if rec := role("adminP", treeUID("other"), nil); rec.Code != http.StatusForbidden {
		t.Errorf("{P} administering a dangling-scope user = %d, want 403", rec.Code)
	}
	rec := role("owner", treeUID("other"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a tenant-wide admin editing a dangling-scope user = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var out struct {
		Scope []string `json:"scoped_group_ids"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Scope) != 1 {
		t.Errorf("the preserved dangling scope = %v, want it carried forward (never collapsed to tenant-wide)", out.Scope)
	}
}

// TestPublicAPICarriesParentIDAndTheMoveVerb: additive only (the pinned envelope keys are unchanged); a
// token is tenant-wide, so it creates under a parent, sees the full tree and moves a group.
func TestPublicAPICarriesParentIDAndTheMoveVerb(t *testing.T) {
	caps := []Capability{CapViewMachines, CapManageGroups}
	p := &Principal{UserID: "u-token", TenantID: "tenant-123",
		Grant: NewGrant("u-token", "tenant-123", NewCapabilityMembership(caps, AllGroups()))}
	srv, _ := newTestServer(p)
	h := srv.Handler()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		return publicAPIWriteRequest(h, method+" "+path, publicAPIBasePath+path, body)
	}
	parent := decodeGroup(t, call("POST", "/machine-groups", `{"name":"Parent"}`))
	if parent.ParentID != nil {
		t.Fatalf("a top-level create answered parent_id %v, want null", *parent.ParentID)
	}
	rec := call("POST", "/machine-groups", `{"name":"Child","parent_id":"`+parent.ID+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create under a parent = %d %s", rec.Code, rec.Body.String())
	}
	child := decodeGroup(t, rec)
	if child.ParentID == nil || *child.ParentID != parent.ID {
		t.Fatalf("created child's parent = %v, want %s", child.ParentID, parent.ID)
	}
	rec = call("GET", "/machine-groups", "")
	var list struct {
		Groups []MachineGroup `json:"machine_groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Groups) != 2 {
		t.Fatalf("list = %s (err %v)", rec.Body.String(), err)
	}
	for _, g := range list.Groups {
		if g.ID == child.ID && (g.ParentID == nil || *g.ParentID != parent.ID) {
			t.Errorf("listed child's parent = %v, want %s", g.ParentID, parent.ID)
		}
		if g.ID == parent.ID && g.ParentID != nil {
			t.Errorf("listed root's parent = %v, want null", *g.ParentID)
		}
	}
	// The move verb: to root, back under, a cycle, and an absent parent_id.
	if rec := call("POST", "/machine-groups/"+child.ID+"/move", `{"parent_id":null}`); rec.Code != http.StatusOK {
		t.Fatalf("move to root = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("POST", "/machine-groups/"+parent.ID+"/move", `{"parent_id":"`+child.ID+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("move root under the former child = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("POST", "/machine-groups/"+child.ID+"/move", `{"parent_id":"`+parent.ID+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("a cycle through the API = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if rec := call("POST", "/machine-groups/"+child.ID+"/move", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("move without parent_id = %d, want 400", rec.Code)
	}
	// The generated document knows both: the nullable parent_id on create and the move operation.
	spec, _ := json.Marshal(buildOpenAPIDocument("./v1"))
	for _, want := range []string{`"moveMachineGroup"`, `"/machine-groups/{id}/move"`, `"parent_id"`} {
		if !strings.Contains(string(spec), want) {
			t.Errorf("the OpenAPI document lacks %s", want)
		}
	}
}

// TestEnrollmentTokensFollowInheritedCoverage: a token plants machines into exactly the group it names, so
// minting is gated on covering THAT group — a scope on a parent covers a child, a scope on a child never
// covers its parent or a sibling — and the token list is narrowed the same way.
func TestEnrollmentTokensFollowInheritedCoverage(t *testing.T) {
	x := newTreeHTTP(t, map[string]userSpec{
		"owner":  {RoleOwner, nil},
		"adminP": {RoleAdmin, []string{"P"}},
		"adminC": {RoleAdmin, []string{"C"}},
	}, nameScope, nil)
	tr := x.tr
	mint := func(who, group string, want int, label string) {
		x.want(who, "POST", "/enrollment-tokens", map[string]any{"group_id": group}, want, label)
	}
	mint("adminP", tr.C, http.StatusCreated, "{P} minting for its child C")
	mint("adminP", tr.G, http.StatusCreated, "{P} minting for its grandchild G")
	mint("adminP", tr.S, http.StatusForbidden, "{P} minting for the sibling S")
	mint("adminC", tr.C, http.StatusCreated, "{C} minting for C")
	mint("adminC", tr.P, http.StatusForbidden, "{C} minting for its PARENT P")
	mint("owner", tr.S, http.StatusCreated, "owner minting for S")
	rec := x.want("adminC", "GET", "/enrollment-tokens", nil, http.StatusOK, "list as {C}")
	var out struct {
		Tokens []EnrollmentToken `json:"enrollment_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	for _, tk := range out.Tokens {
		if tk.GroupID != tr.C && tk.GroupID != tr.G {
			t.Errorf("{C} listed a token for group %s outside its subtree", tk.GroupID)
		}
	}
	if len(out.Tokens) == 0 {
		t.Error("{C} listed no tokens, want its own")
	}
}

// TestLeaseRenewalFollowsAMoveThatRemovedTheScope: the freshness D3 promises. Grants are re-read on every
// request and lease renewal, so a reparent that takes a machine's group out from under a scoped technician
// ends their access at the next renewal; the negative control is the same renewal just before the move.
func TestLeaseRenewalFollowsAMoveThatRemovedTheScope(t *testing.T) {
	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatal(err)
	}
	x := newTreeHTTP(t, map[string]userSpec{
		"owner": {RoleOwner, nil},
		"techP": {RoleTechnician, []string{"P"}},
	}, nameScope, nil, func(f *authFixture) { f.srv.Grants = iss })
	tr := x.tr
	m := x.machineIn(tr.C) // inside {P} by inheritance
	rec := x.want("techP", "POST", "/sessions", startSessionRequest{MachineID: m.DeviceID}, http.StatusCreated, "start a session on C's machine")
	var started struct {
		Session SessionRecord `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil || started.Session.ID == "" {
		t.Fatalf("decode session: %v (%s)", err, rec.Body.String())
	}
	renew := "/sessions/" + started.Session.ID + "/policy"
	x.want("techP", "POST", renew, nil, http.StatusOK, "renewal while C is inside {P}")
	// An unrelated reparent leaves it alone...
	x.want("owner", "POST", "/machine-groups/"+tr.S+"/move", map[string]any{"parent_id": tr.X}, http.StatusOK, "move S under X")
	x.want("techP", "POST", renew, nil, http.StatusOK, "renewal after an unrelated move")
	// ...the move that takes C out of P's subtree ends the technician's access at the next renewal.
	x.want("owner", "POST", "/machine-groups/"+tr.C+"/move", map[string]any{"parent_id": tr.X}, http.StatusOK, "move C out of P")
	x.want("techP", "POST", renew, nil, http.StatusForbidden, "renewal after C left {P}")
}
