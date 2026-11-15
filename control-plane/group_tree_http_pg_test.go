package controlplane

// The group handlers (docs/62 stage B) over the REAL Postgres stores: the structure trigger's answers
// surface as the same 409s, R3 authorization runs against grants resolved through cp_group_subtree, the
// hierarchy mutations reload the actor inside their transaction, and the tree-conditional machine move
// refuses a stale grant. The fake-store twin of this is group_tree_http_test.go. Needs TEST_DATABASE_URL.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pgGrantAuth authenticates every request as userID with a FRESHLY resolved grant (what the session
// authenticator does), or — with frozen set — with a grant captured earlier (a request whose grant was read
// before something changed).
type pgGrantAuth struct {
	env    *treeEnv
	userID string
	frozen *Grant
}

func (a pgGrantAuth) Authenticate(_ *http.Request) (*Principal, error) {
	g := a.frozen
	if g == nil {
		var err error
		if g, err = a.env.users.GrantFor(a.env.ctx, a.env.tid, a.userID); err != nil {
			return nil, err
		}
	}
	return &Principal{UserID: a.userID, TenantID: a.env.tid, Grant: g}, nil
}

func (e *treeEnv) serverAs(auth Authenticator) http.Handler {
	srv := NewServer(auth, NoopBinder{})
	srv.MachineGroups = e.groups
	srv.Machines = e.machines
	srv.GroupSessionPolicies = NewPgGroupSessionPolicyStore(e.app)
	srv.SessionRecords = e.sessions
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	return srv.Handler()
}

func pgCall(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPgGroupHandlersOverTheRealStores(t *testing.T) {
	env := newPgTreeEnv(t)
	tr := env.standardTree()
	uP := env.newUser("adminP", RoleAdmin, tr.P)
	uOwner := env.newUser("owner", RoleOwner)
	hP := env.serverAs(pgGrantAuth{env: env, userID: uP})
	hOwner := env.serverAs(pgGrantAuth{env: env, userID: uOwner})

	expect := func(h http.Handler, method, path, body string, want int, label string) *httptest.ResponseRecorder {
		t.Helper()
		rec := pgCall(h, method, path, body)
		if rec.Code != want {
			t.Errorf("%s: %s %s = %d, want %d (%s)", label, method, path, rec.Code, want, strings.TrimSpace(rec.Body.String()))
		}
		return rec
	}
	g := func(id string) string { return "/machine-groups/" + id }

	// create (D5): ROOT needs tenant-wide; under P (covered via cp_group_subtree) works; under S does not.
	expect(hP, "POST", "/machine-groups", `{"name":"root2"}`, http.StatusForbidden, "scoped root create")
	expect(hP, "POST", "/machine-groups", `{"name":"k","parent_id":"`+tr.S+`"}`, http.StatusForbidden, "create under uncovered S")
	rec := expect(hP, "POST", "/machine-groups", `{"name":"under C","parent_id":"`+tr.C+`"}`, http.StatusCreated, "create under C")
	if got := decodeGroup(t, rec); got.ParentID == nil || *got.ParentID != tr.C {
		t.Errorf("created parent = %v", got.ParentID)
	}
	// a 5th level and a malformed / unknown parent, answered by the DB trigger / FK
	expect(hOwner, "POST", "/machine-groups", `{"name":"l5","parent_id":"`+tr.G+`"}`, http.StatusConflict, "5th level (trigger)")
	expect(hOwner, "POST", "/machine-groups", `{"name":"k","parent_id":"`+newUUID()+`"}`, http.StatusConflict, "unknown parent (FK)")
	// move: cycle, depth, covered/uncovered, root
	expect(hOwner, "POST", g(tr.R)+"/move", `{"parent_id":"`+tr.G+`"}`, http.StatusConflict, "cycle (trigger)")
	expect(hOwner, "POST", g(tr.X)+"/move", `{"parent_id":"`+tr.G+`"}`, http.StatusConflict, "depth (trigger)")
	expect(hP, "POST", g(tr.G)+"/move", `{"parent_id":"`+tr.P+`"}`, http.StatusOK, "{P} moves G from C to P")
	expect(hP, "POST", g(tr.S)+"/move", `{"parent_id":"`+tr.P+`"}`, http.StatusForbidden, "{P} moves uncovered S")
	expect(hP, "POST", g(tr.C)+"/move", `{"parent_id":null}`, http.StatusForbidden, "{P} makes C a root")
	expect(hOwner, "POST", g(tr.C)+"/move", `{"parent_id":null}`, http.StatusOK, "owner makes C a root")
	if env.parentOf(tr.C) != "" {
		t.Error("C still has a parent")
	}
	// rename / delete (R3, D7)
	expect(hP, "PATCH", g(tr.S), `{"name":"x"}`, http.StatusForbidden, "{P} renames S")
	expect(hP, "PATCH", g(tr.G), `{"name":"G2"}`, http.StatusOK, "{P} renames G")
	expect(hP, "DELETE", g(tr.S), "", http.StatusForbidden, "{P} deletes S")
	expect(hOwner, "DELETE", g(tr.P), "", http.StatusConflict, "delete P which has G under it")
	expect(hOwner, "DELETE", g(tr.G), "", http.StatusOK, "delete leaf G")
	expect(hOwner, "DELETE", g(newUUID()), "", http.StatusNotFound, "delete unknown")
	// policy (R3 + R4 conflict through the pg policy store)
	expect(hP, "PUT", g(tr.S)+"/session-policy", `{"enforce_view_only":true}`, http.StatusForbidden, "{P} sets S's policy")
	if err := NewPgGroupSessionPolicyStore(env.app).Set(env.ctx, env.tid, tr.P, GroupSessionPolicy{RequireRecording: true}); err != nil {
		t.Fatal(err)
	}
	expect(hOwner, "PUT", g(tr.X)+"/session-policy", `{"prohibit_recording":true}`, http.StatusOK, "unrelated group may prohibit")
	kid := &MachineGroup{Name: "kid", ParentID: &tr.P}
	if err := env.groups.CreateMachineGroup(env.ctx, env.tid, kid); err != nil {
		t.Fatal(err)
	}
	expect(hOwner, "PUT", g(kid.ID)+"/session-policy", `{"prohibit_recording":true}`, http.StatusConflict, "child prohibiting what P requires")
	rec = expect(hOwner, "GET", g(kid.ID)+"/session-policy", "", http.StatusOK, "effective policy read")
	if !strings.Contains(rec.Body.String(), `"effective"`) || !strings.Contains(rec.Body.String(), `"require_recording":true`) {
		t.Errorf("GET policy did not carry the effective merge: %s", rec.Body.String())
	}

	// R2: a machine move on a grant captured BEFORE a tree change is refused; on a fresh grant it moves.
	mid := env.newMachine(tr.P)
	frozen, err := env.users.GrantFor(env.ctx, env.tid, uP)
	if err != nil {
		t.Fatal(err)
	}
	env.mkGroup("bump", "")
	hStale := env.serverAs(pgGrantAuth{env: env, userID: uP, frozen: frozen})
	rec = expect(hStale, "POST", "/machines/"+mid+"/group", `{"group_id":"`+kid.ID+`"}`, http.StatusConflict, "stale-grant machine move")
	if !strings.Contains(rec.Body.String(), "groups changed") {
		t.Errorf("stale-grant refusal = %s", rec.Body.String())
	}
	expect(hP, "POST", "/machines/"+mid+"/group", `{"group_id":"`+kid.ID+`"}`, http.StatusOK, "fresh-grant machine move")
	if m, _ := env.machines.GetMachineByID(context.Background(), env.tid, mid); m.GroupID != kid.ID {
		t.Errorf("machine group = %s, want the kid group", m.GroupID)
	}
}
