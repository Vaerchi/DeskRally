package controlplane

// GROUP SCOPE on user administration (security review 2026-11-01 #13). A group-scoped
// CapManageUsers holder lists only users holding a membership in at least one group inside their
// scope (a tenant-wide membership counts: it holds authority over every group), and the per-user
// routes refuse any user they could not list. One body of assertions runs on both stores.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type userScopeWorld struct {
	srv    *Server
	users  UserStore
	tenant string
	gA, gB string
	// dropGrants removes every membership of a user (store-specific), producing a user in no group.
	dropGrants func(id string)
	// addWideMembership gives an existing user an ADDITIONAL tenant-wide membership (store-specific).
	addWideMembership func(id string, role Role)
}

func (w *userScopeWorld) call(t *testing.T, p *Principal, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w.srv.Auth = StubAuthenticator{Principal: p}
	rec := httptest.NewRecorder()
	w.srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func runUserAdminScopeChecks(t *testing.T, w *userScopeWorld) {
	t.Helper()
	ctx := context.Background()
	mk := func(email string, role Role, groups ...string) string {
		id := newUUID()
		if err := w.users.CreateUser(ctx, w.tenant, id, email, email, role, groups); err != nil {
			t.Fatalf("create %s: %v", email, err)
		}
		return id
	}
	actorID := mk("actor@a.test", RoleAdmin, w.gA)
	techA := mk("tech-a@a.test", RoleTechnician, w.gA)
	techB := mk("tech-b@b.test", RoleTechnician, w.gB)
	techAB := mk("tech-ab@ab.test", RoleTechnician, w.gA, w.gB)
	owner := mk("owner@wide.test", RoleAdmin) // tenant-wide
	nobody := mk("nobody@none.test", RoleTechnician, w.gA)
	w.dropGrants(nobody)
	// A tenant-wide membership MIXED with an in-scope group-A one: still not wholly in scope.
	mixed := mk("mixed@wide-and-a.test", RoleTechnician, w.gA)
	w.addWideMembership(mixed, RoleReadOnly)

	scoped := &Principal{UserID: actorID, TenantID: w.tenant,
		Grant: NewGrant(actorID, w.tenant, NewMembership(RoleAdmin, Groups(w.gA)))}
	wide := &Principal{UserID: "wide", TenantID: w.tenant,
		Grant: NewGrant("wide", w.tenant, NewMembership(RoleAdmin, AllGroups()))}

	list := func(p *Principal) map[string]bool {
		t.Helper()
		rec := w.call(t, p, "GET", "/users")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /users = %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Users []UserSummary `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]bool{}
		for _, u := range out.Users {
			m[u.ID] = true
		}
		return m
	}

	got := list(scoped)
	for id, want := range map[string]bool{actorID: true, techA: true, techAB: false, owner: false, techB: false, nobody: false, mixed: false} {
		if got[id] != want {
			t.Fatalf("scoped list: user %s visible=%v, want %v (list=%v)", id, got[id], want, got)
		}
	}
	if all := list(wide); len(all) < 6 || !all[techB] || !all[nobody] {
		t.Fatalf("tenant-wide list has %d users, want all (incl. out-of-scope)", len(all))
	}

	// Per-user routes: what the caller cannot list, the caller cannot act on.
	for _, path := range []string{"/users/" + techB + "/disable", "/users/" + techB + "/sign-out", "/users/" + nobody + "/disable",
		"/users/" + owner + "/disable", "/users/" + owner + "/sign-out", "/users/" + techAB + "/disable", "/users/" + techAB + "/sign-out",
		"/users/" + mixed + "/disable", "/users/" + mixed + "/sign-out"} {
		if rec := w.call(t, scoped, "POST", path); rec.Code != http.StatusForbidden {
			t.Fatalf("scoped POST %s = %d, want 403: %s", path, rec.Code, rec.Body.String())
		}
	}
	for _, id := range []string{techB, owner, techAB, nobody, mixed} {
		if u, err := w.users.FindUserByID(ctx, w.tenant, id); err != nil || u.Disabled {
			t.Fatalf("out-of-scope user %s must be untouched: %+v %v", id, u, err)
		}
	}
	// Assignment never grants beyond the caller's scope: re-roling an in-scope user to a group
	// outside the scope, or to tenant-wide, is refused; re-roling inside scope works.
	setRole := func(id string, body string) int {
		w.srv.Auth = StubAuthenticator{Principal: scoped}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/users/"+id+"/role", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if c := setRole(techA, `{"role":"technician","scoped_group_ids":["`+w.gB+`"]}`); c != http.StatusForbidden {
		t.Fatalf("assigning an out-of-scope group = %d, want 403", c)
	}
	if c := setRole(techA, `{"role":"technician","scoped_group_ids":[]}`); c != http.StatusForbidden {
		t.Fatalf("assigning tenant-wide scope = %d, want 403", c)
	}
	if c := setRole(owner, `{"role":"technician","scoped_group_ids":["`+w.gA+`"]}`); c != http.StatusForbidden {
		t.Fatalf("re-roling the tenant-wide user = %d, want 403", c)
	}
	if c := setRole(techA, `{"role":"technician","scoped_group_ids":["`+w.gA+`"]}`); c != http.StatusOK {
		t.Fatalf("re-roling inside scope = %d, want 200", c)
	}
	if rec := w.call(t, scoped, "POST", "/users/"+techA+"/sign-out"); rec.Code != http.StatusOK {
		t.Fatalf("scoped sign-out of an in-scope user = %d: %s", rec.Code, rec.Body.String())
	}
	// The tenant-wide admin is unaffected.
	if rec := w.call(t, wide, "POST", "/users/"+techB+"/sign-out"); rec.Code != http.StatusOK {
		t.Fatalf("tenant-wide sign-out = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserAdminGroupScopeInMemory(t *testing.T) {
	f := newAuthFixture(t)
	const tenant = "tenant-1"
	groups := NewInMemoryMachineGroupStore()
	f.srv.MachineGroups = groups
	f.auth.MachineGroups = groups
	ga, gb := &MachineGroup{Name: "Group A"}, &MachineGroup{Name: "Group B"}
	for _, g := range []*MachineGroup{ga, gb} {
		if err := groups.CreateMachineGroup(context.Background(), tenant, g); err != nil {
			t.Fatal(err)
		}
	}
	w := &userScopeWorld{srv: f.srv, users: f.users, tenant: tenant, gA: ga.ID, gB: gb.ID}
	w.dropGrants = func(id string) { f.users.mu.Lock(); delete(f.users.grants, userKey(tenant, id)); f.users.mu.Unlock() }
	w.addWideMembership = func(id string, role Role) {
		f.users.mu.Lock()
		g := f.users.grants[userKey(tenant, id)]
		g.Members = append(g.Members, NewMembership(role, AllGroups()))
		f.users.mu.Unlock()
	}
	runUserAdminScopeChecks(t, w)
}

func TestPgUserAdminGroupScope(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()
	tid, _ := provisionUser(t, suPool, "user-scope", "x@user-scope.test", "password-1234")
	gA, gB := seedGroup(t, suPool, tid), seedGroup(t, suPool, tid)
	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	authSvc := &AuthService{Users: store, Sessions: NewSessionManager(NewInMemorySessionStore()), Issuer: "RMT"}
	srv := NewServer(nil, NewPgBinder(appPool))
	authSvc.MachineGroups = NewPgMachineGroupStore(appPool)
	srv.MachineGroups = authSvc.MachineGroups
	srv.AuthAPI = authSvc
	w := &userScopeWorld{srv: srv, users: store, tenant: tid, gA: gA, gB: gB}
	w.dropGrants = func(id string) {
		if _, err := suPool.Exec(ctx, `DELETE FROM membership WHERE user_id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	w.addWideMembership = func(id string, role Role) {
		if _, err := suPool.Exec(ctx, `
			INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
			SELECT $1::uuid, $2::uuid, r.id, '{}'::uuid[] FROM role r WHERE r.key = $3 AND r.tenant_id IS NULL`,
			tid, id, string(role)); err != nil {
			t.Fatal(err)
		}
	}
	runUserAdminScopeChecks(t, w)
}
