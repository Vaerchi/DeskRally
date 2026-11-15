package controlplane

// Proofs for user management (docs/01 §5): the store (list + disable), the HTTP surface driven through
// the REAL login → session → protected-request flow (the CapManageUsers gate, the canAdministerUser
// hierarchy, self-disable refusal, and that a disabled user can no longer log in), and the pg store's
// RLS isolation.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestInMemoryUserAdminStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryUserStore()
	s.AddUser(&AuthUser{ID: "u2", TenantID: "t1", Email: "b@x.test", DisplayName: "Bee"}, nil)
	s.AddUser(&AuthUser{ID: "u1", TenantID: "t1", Email: "a@x.test", DisplayName: "Ay"}, nil)
	s.AddUser(&AuthUser{ID: "u3", TenantID: "t2", Email: "c@x.test"}, nil) // another tenant

	// ListUsers is tenant-scoped and ordered by email.
	users, err := s.ListUsers(ctx, "t1")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || users[0].Email != "a@x.test" || users[1].Email != "b@x.test" {
		t.Fatalf("users = %+v, want a@ then b@ (t2 excluded)", users)
	}

	// SetUserDisabled flips the flag; a missing user (or one in another tenant) is ErrNoUser.
	if err := s.SetUserDisabled(ctx, "t1", "u1", true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if u, _ := s.FindUserByID(ctx, "t1", "u1"); !u.Disabled {
		t.Fatal("u1 should be disabled")
	}
	if err := s.SetUserDisabled(ctx, "t1", "u1", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if u, _ := s.FindUserByID(ctx, "t1", "u1"); u.Disabled {
		t.Fatal("u1 should be enabled")
	}
	if err := s.SetUserDisabled(ctx, "t1", "u3", true); !errors.Is(err, ErrNoUser) {
		t.Fatalf("cross-tenant disable err = %v, want ErrNoUser", err)
	}
}

func TestSameUserID(t *testing.T) {
	// Exact match — the symbolic ids the in-memory stores / DEV use.
	if !sameUserID("owner", "owner") {
		t.Fatal("exact match must be same")
	}
	if sameUserID("owner", "tech") {
		t.Fatal("different symbolic ids are not the same")
	}
	// THE SELF-DISABLE BYPASS REGRESSION: the SAME uuid spelled differently (uppercase, {braces},
	// dashless — all of which Postgres resolves to one row) is recognized as the same user; a raw `==`
	// would miss it and let a caller disable their own account.
	const canon = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	for _, spelling := range []string{
		"A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11",   // uppercase
		"{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}", // brace-wrapped
		"a0eebc999c0b4ef8bb6d6bb9bd380a11",       // dashless
	} {
		if !sameUserID(spelling, canon) {
			t.Fatalf("sameUserID(%q, canonical) = false, want true (uuid is case/format-insensitive)", spelling)
		}
	}
	// Two genuinely different uuids are NOT the same.
	if sameUserID(canon, "b1ffcd00-0d1c-4fa9-8c7e-7cc0ce491b22") {
		t.Fatal("different uuids are not the same")
	}
}

// loginFor logs `email` in and returns its session cookie + CSRF cookie + CSRF token.
func loginFor(t *testing.T, f *authFixture, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	login := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: email, Password: password}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login %s = %d: %s", email, login.Code, login.Body.String())
	}
	csrfCookie, csrfTok := csrfFrom(t, login)
	return sessionCookieFrom(login), csrfCookie, csrfTok
}

func newUserAdminFixture(t *testing.T) *authFixture {
	t.Helper()
	f := newAuthFixture(t)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit = audit
	f.auth.MgmtAudit = audit
	return f
}

const uaPw = "correct-horse-battery-staple"

func TestUserAdminListDisableEnable(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)

	// LIST — both users, sorted by email.
	list := doJSON(t, h, "GET", "/users", nil, cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("GET /users = %d: %s", list.Code, list.Body.String())
	}
	var lr struct {
		Users []UserSummary `json:"users"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lr.Users) != 2 || lr.Users[0].Email != "owner@acme.test" || lr.Users[1].Email != "tech@acme.test" {
		t.Fatalf("users = %+v", lr.Users)
	}

	// DISABLE the tech → 200; a disabled user can no longer log in.
	if rec := doJSONWith(t, h, "POST", "/users/tech/disable", nil, tok, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("disable tech = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@acme.test", Password: uaPw}, nil); rec.Code == http.StatusOK {
		t.Fatalf("disabled tech must not log in, got %d", rec.Code)
	}
	// The listing reflects the disabled flag.
	if reListDisabled(t, h, cookie, "tech") != true {
		t.Fatal("tech should show disabled in the listing")
	}

	// ENABLE → the tech can log in again.
	if rec := doJSONWith(t, h, "POST", "/users/tech/enable", nil, tok, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("enable tech = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@acme.test", Password: uaPw}, nil); rec.Code != http.StatusOK {
		t.Fatalf("re-enabled tech must log in, got %d", rec.Code)
	}

	// SELF-DISABLE is refused (self-lockout).
	if rec := doJSONWith(t, h, "POST", "/users/owner/disable", nil, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-disable = %d, want 400", rec.Code)
	}
	// UNKNOWN user → 404.
	if rec := doJSONWith(t, h, "POST", "/users/nobody/disable", nil, tok, cookie, csrf); rec.Code != http.StatusNotFound {
		t.Fatalf("disable unknown = %d, want 404", rec.Code)
	}
}

func reListDisabled(t *testing.T, h http.Handler, cookie *http.Cookie, id string) bool {
	t.Helper()
	list := doJSON(t, h, "GET", "/users", nil, cookie)
	var lr struct {
		Users []UserSummary `json:"users"`
	}
	_ = json.Unmarshal(list.Body.Bytes(), &lr)
	for _, u := range lr.Users {
		if u.ID == id {
			return u.Disabled
		}
	}
	t.Fatalf("user %s not in listing", id)
	return false
}

func TestUserAdminGateAndHierarchy(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", uaPw, RoleAdmin)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()

	// A Technician holds no CapManageUsers → the list is forbidden.
	techCookie, _, _ := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSON(t, h, "GET", "/users", nil, techCookie); rec.Code != http.StatusForbidden {
		t.Fatalf("tech GET /users = %d, want 403", rec.Code)
	}

	adminCookie, adminCSRF, adminTok := loginFor(t, f, "admin@acme.test", uaPw)
	// An Admin CANNOT disable the Owner (canAdministerUser: Admin lacks CapManageTenant that Owner holds).
	if rec := doJSONWith(t, h, "POST", "/users/owner/disable", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin disabling owner = %d, want 403", rec.Code)
	}
	// But an Admin CAN disable a Technician (a subset of the Admin's authority).
	if rec := doJSONWith(t, h, "POST", "/users/tech/disable", nil, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusOK {
		t.Fatalf("admin disabling tech = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestAssignableRolesMatchPresets guards that the assignable-role list and the rolePresets map do not
// drift: every assignable role IS a preset, every preset IS assignable, and IsAssignableRole agrees.
func TestAssignableRolesMatchPresets(t *testing.T) {
	assignable := AssignableRoles()
	if len(assignable) != len(rolePresets) {
		t.Fatalf("AssignableRoles has %d entries, rolePresets has %d — they must match", len(assignable), len(rolePresets))
	}
	for _, r := range assignable {
		if _, ok := rolePresets[r]; !ok {
			t.Fatalf("assignable role %q is not a preset", r)
		}
		if !IsAssignableRole(r) {
			t.Fatalf("IsAssignableRole(%q) = false, want true", r)
		}
	}
	for r := range rolePresets {
		if !IsAssignableRole(r) {
			t.Fatalf("preset role %q is not assignable", r)
		}
	}
	// A non-preset (and the empty role) are never assignable.
	if IsAssignableRole("superadmin") || IsAssignableRole("") {
		t.Fatal("a non-preset / empty role must not be assignable")
	}
	// Mutating the returned slice must not affect the source (it is a copy).
	AssignableRoles()[0] = "tampered"
	if AssignableRoles()[0] == "tampered" {
		t.Fatal("AssignableRoles must return a defensive copy")
	}
}

// TestInMemoryUserRoleStore covers the fake's ListUsers role reporting and SetUserRole replacement,
// including the two fail-closed answers (unknown role, absent user) it must share with the pg store.
func TestInMemoryUserRoleStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryUserStore()
	s.AddUser(&AuthUser{ID: "u1", TenantID: "t1", Email: "a@x.test"},
		NewGrant("u1", "t1", NewMembership(RoleTechnician, AllGroups())))

	// ListUsers reports the user's role keys.
	users, err := s.ListUsers(ctx, "t1")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || len(users[0].Roles) != 1 || users[0].Roles[0] != "technician" {
		t.Fatalf("roles = %+v, want [technician]", users[0].Roles)
	}

	// SetUserRole REPLACES the membership (no accumulation): the user now holds exactly readonly.
	if err := s.SetUserRole(ctx, "t1", "u1", RoleReadOnly, nil); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	users, _ = s.ListUsers(ctx, "t1")
	if len(users[0].Roles) != 1 || users[0].Roles[0] != "readonly" {
		t.Fatalf("after set, roles = %+v, want [readonly]", users[0].Roles)
	}
	if g, _ := s.GrantFor(ctx, "t1", "u1"); g.Allows(CapViewAudit) || !g.Allows(CapViewMachines) {
		t.Fatal("readonly grant should allow view_machines but not view_audit")
	}

	// A non-preset role is ErrUnknownRole; an absent user is ErrNoUser.
	if err := s.SetUserRole(ctx, "t1", "u1", "superadmin", nil); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("unknown role err = %v, want ErrUnknownRole", err)
	}
	if err := s.SetUserRole(ctx, "t1", "ghost", RoleAdmin, nil); !errors.Is(err, ErrNoUser) {
		t.Fatalf("absent user err = %v, want ErrNoUser", err)
	}

	// A membership-less user reports a NON-nil empty Roles ([] not null) — the JSON contract the
	// console relies on, and the fake's half of the empty-case agreement with the pg store.
	s.AddUser(&AuthUser{ID: "u2", TenantID: "t1", Email: "z@x.test"}, nil)
	users, _ = s.ListUsers(ctx, "t1")
	var bare *UserSummary
	for i := range users {
		if users[i].ID == "u2" {
			bare = &users[i]
		}
	}
	if bare == nil || bare.Roles == nil || len(bare.Roles) != 0 {
		t.Fatalf("membership-less user Roles = %#v, want non-nil empty", bare)
	}
}

// reListRoles returns a user's role keys from GET /users.
func reListRoles(t *testing.T, h http.Handler, cookie *http.Cookie, id string) []string {
	t.Helper()
	list := doJSON(t, h, "GET", "/users", nil, cookie)
	var lr struct {
		Users []UserSummary `json:"users"`
	}
	_ = json.Unmarshal(list.Body.Bytes(), &lr)
	for _, u := range lr.Users {
		if u.ID == id {
			return u.Roles
		}
	}
	t.Fatalf("user %s not in listing", id)
	return nil
}

func TestUserAdminSetRole(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	ctx := context.Background()

	// Precondition: the tech holds technician (not admin's manage_users).
	if g, _ := f.users.GrantFor(ctx, "tenant-1", "tech"); g.Allows(CapManageUsers) {
		t.Fatal("tech should not start with manage_users")
	}

	// Owner promotes the tech to admin → 200, and the listing + resolved grant both reflect it.
	if rec := doJSONWith(t, h, "POST", "/users/tech/role", map[string]any{"role": "admin"}, tok, cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("set role = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if roles := reListRoles(t, h, cookie, "tech"); len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("tech roles = %v, want [admin]", roles)
	}
	if g, _ := f.users.GrantFor(ctx, "tenant-1", "tech"); !g.Allows(CapManageUsers) {
		t.Fatal("tech should hold manage_users after promotion to admin")
	}

	// The change is audited as user.role_set with the new role in metadata.
	audit := doJSON(t, h, "GET", "/audit?action=user.role_set", nil, cookie)
	var ar struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if err := json.Unmarshal(audit.Body.Bytes(), &ar); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(ar.Events) != 1 || ar.Events[0].TargetID != "tech" {
		t.Fatalf("audit events = %+v, want one user.role_set targeting tech", ar.Events)
	}

	// UNKNOWN role → 400; the tech's role is unchanged.
	if rec := doJSONWith(t, h, "POST", "/users/tech/role", map[string]any{"role": "superadmin"}, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown role = %d, want 400", rec.Code)
	}
	// UNKNOWN user → 404.
	if rec := doJSONWith(t, h, "POST", "/users/ghost/role", map[string]any{"role": "readonly"}, tok, cookie, csrf); rec.Code != http.StatusNotFound {
		t.Fatalf("role for unknown user = %d, want 404", rec.Code)
	}
	// SELF role change → 400 (the owner is the caller).
	if rec := doJSONWith(t, h, "POST", "/users/owner/role", map[string]any{"role": "admin"}, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("self role change = %d, want 400", rec.Code)
	}
}

func TestUserRoleGateAndEscalation(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", uaPw, RoleAdmin)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	f.addUser(t, "tenant-1", "peer", "peer@acme.test", uaPw, RoleReadOnly)
	h := f.srv.Handler()

	// A Technician holds no CapManageRoles → assigning a role is forbidden by the GATE alone. Target
	// `peer` (a readonly user the technician's own authority would otherwise cover, and NOT self), so
	// the 403 can ONLY come from the capability gate — not the escalation checks or the self-guard.
	techCookie, techCSRF, techTok := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSONWith(t, h, "POST", "/users/peer/role", map[string]any{"role": "readonly"}, techTok, techCookie, techCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("tech assigning a role = %d, want 403 (no CapManageRoles)", rec.Code)
	}

	adminCookie, adminCSRF, adminTok := loginFor(t, f, "admin@acme.test", uaPw)
	// ESCALATION #2: an Admin CANNOT mint an Owner (Owner holds CapManageTenant the Admin lacks).
	if rec := doJSONWith(t, h, "POST", "/users/tech/role", map[string]any{"role": "owner"}, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin granting owner = %d, want 403", rec.Code)
	}
	// ESCALATION #1: an Admin CANNOT re-role the Owner (cannot administer someone more privileged).
	if rec := doJSONWith(t, h, "POST", "/users/owner/role", map[string]any{"role": "readonly"}, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin re-roling owner = %d, want 403", rec.Code)
	}
	// But an Admin CAN re-role a Technician to readonly (both within the Admin's authority).
	if rec := doJSONWith(t, h, "POST", "/users/tech/role", map[string]any{"role": "readonly"}, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusOK {
		t.Fatalf("admin re-roling tech = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if roles := reListRoles(t, h, adminCookie, "tech"); len(roles) != 1 || roles[0] != "readonly" {
		t.Fatalf("tech roles = %v, want [readonly]", roles)
	}
}

// TestPgUserRoleUnderRLS drives PgUserStore.SetUserRole + the ListUsers role aggregate as rmt_app:
// the membership is REPLACED (roles reflect the new preset), and a cross-tenant assignment is refused.
func TestPgUserRoleUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tidA, uidA := provisionUser(t, suPool, "ur-a", "a@ur-a.test", "password-1234") // seeded technician
	tidB, uidB := provisionUser(t, suPool, "ur-b", "b@ur-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	// provisionUser seeds a technician membership; the listing reflects it.
	aUsers, err := store.ListUsers(ctx, tidA)
	if err != nil {
		t.Fatalf("ListUsers A: %v", err)
	}
	if len(aUsers) != 1 || len(aUsers[0].Roles) != 1 || aUsers[0].Roles[0] != "technician" {
		t.Fatalf("A roles = %+v, want [technician]", aUsers)
	}

	// Assign readonly → the membership is REPLACED (still exactly one role), and GrantFor resolves it.
	if err := store.SetUserRole(ctx, tidA, uidA, RoleReadOnly, nil); err != nil {
		t.Fatalf("SetUserRole A: %v", err)
	}
	aUsers, _ = store.ListUsers(ctx, tidA)
	if len(aUsers[0].Roles) != 1 || aUsers[0].Roles[0] != "readonly" {
		t.Fatalf("A roles after set = %+v, want [readonly]", aUsers[0].Roles)
	}
	if g, _ := store.GrantFor(ctx, tidA, uidA); g.Allows(CapBackstageShell) || !g.Allows(CapViewMachines) {
		t.Fatal("readonly grant should allow view_machines but not backstage_shell")
	}

	// A cross-tenant assignment (pinned to A, targeting B's id) is ErrNoUser, and B is untouched.
	if err := store.SetUserRole(ctx, tidA, uidB, RoleAdmin, nil); !errors.Is(err, ErrNoUser) {
		t.Fatalf("cross-tenant SetUserRole err = %v, want ErrNoUser", err)
	}
	bUsers, _ := store.ListUsers(ctx, tidB)
	if len(bUsers) != 1 || len(bUsers[0].Roles) != 1 || bUsers[0].Roles[0] != "technician" {
		t.Fatalf("B roles = %+v, want [technician] (unaffected)", bUsers)
	}
}

func TestNormalizeEmail(t *testing.T) {
	valid := map[string]string{
		"a@b.com":           "a@b.com",
		"  tech@dev.local ": "tech@dev.local",
		"x@y":               "x@y",
	}
	for in, want := range valid {
		if got, ok := normalizeEmail(in); !ok || got != want {
			t.Fatalf("normalizeEmail(%q) = (%q,%v), want (%q,true)", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "   ", "noat", "@x", "a@", "a@@b", "a b@c", "a@b c", "a@b\tc", "a@b\x00c"} {
		if _, ok := normalizeEmail(in); ok {
			t.Fatalf("normalizeEmail(%q) accepted, want rejected", in)
		}
	}
	// 254 bytes is the RFC 5321 maximum (allowed); 255 is the first rejected length. "@b.co" is 5 bytes.
	if _, ok := normalizeEmail(strings.Repeat("a", 249) + "@b.co"); !ok {
		t.Fatal("normalizeEmail must accept exactly 254 bytes")
	}
	if _, ok := normalizeEmail(strings.Repeat("a", 250) + "@b.co"); ok {
		t.Fatal("normalizeEmail must reject >254 bytes")
	}
}

func TestNormalizeDisplayName(t *testing.T) {
	if n, ok := normalizeDisplayName("  Alice  "); !ok || n != "Alice" {
		t.Fatalf("trim = (%q,%v), want (Alice,true)", n, ok)
	}
	if n, ok := normalizeDisplayName(""); !ok || n != "" {
		t.Fatalf("empty display name must be allowed, got (%q,%v)", n, ok)
	}
	if _, ok := normalizeDisplayName("bad\x07bell"); ok {
		t.Fatal("a control char must be rejected")
	}
	if _, ok := normalizeDisplayName(strings.Repeat("é", 201)); ok {
		t.Fatal(">200 runes must be rejected")
	}
	if _, ok := normalizeDisplayName(strings.Repeat("é", 200)); !ok {
		t.Fatal("exactly 200 runes must be allowed (rune count, not bytes)")
	}
}

func TestInMemoryUserCreate(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryUserStore()
	if err := s.CreateUser(ctx, "t1", "u1", "a@x.test", "Ay", RoleTechnician, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	users, _ := s.ListUsers(ctx, "t1")
	if len(users) != 1 || users[0].Email != "a@x.test" || len(users[0].Roles) != 1 || users[0].Roles[0] != "technician" {
		t.Fatalf("created = %+v", users)
	}
	// Duplicate email in the SAME tenant → ErrEmailExists; the same email in ANOTHER tenant is fine.
	if err := s.CreateUser(ctx, "t1", "u2", "a@x.test", "", RoleReadOnly, nil); !errors.Is(err, ErrEmailExists) {
		t.Fatalf("dup email err = %v, want ErrEmailExists", err)
	}
	if err := s.CreateUser(ctx, "t2", "u3", "a@x.test", "", RoleReadOnly, nil); err != nil {
		t.Fatalf("same email in another tenant: %v", err)
	}
	// A non-preset role is ErrUnknownRole.
	if err := s.CreateUser(ctx, "t1", "u4", "b@x.test", "", "superadmin", nil); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("unknown role err = %v, want ErrUnknownRole", err)
	}
}

func TestUserAdminCreate(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	h := f.srv.Handler()
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)

	// Create a technician → 201; the response carries the new user with the role.
	rec := doJSONWith(t, h, "POST", "/users",
		map[string]any{"email": "new@acme.test", "display_name": "New Tech", "role": "technician"}, tok, cookie, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var cr struct {
		User UserSummary `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cr.User.Email != "new@acme.test" || len(cr.User.Roles) != 1 || cr.User.Roles[0] != "technician" {
		t.Fatalf("created user = %+v", cr.User)
	}
	// It appears in the listing with the role, and is auditable as user.created.
	if roles := reListRoles(t, h, cookie, cr.User.ID); len(roles) != 1 || roles[0] != "technician" {
		t.Fatalf("listed roles = %v, want [technician]", roles)
	}
	audit := doJSON(t, h, "GET", "/audit?action=user.created", nil, cookie)
	var ar struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	_ = json.Unmarshal(audit.Body.Bytes(), &ar)
	if len(ar.Events) != 1 || ar.Events[0].TargetID != cr.User.ID {
		t.Fatalf("audit = %+v, want one user.created for the new id", ar.Events)
	}

	// Duplicate email → 409; invalid email → 400; unknown role → 400.
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "new@acme.test", "role": "readonly"}, tok, cookie, csrf); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate email = %d, want 409", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "not-an-email", "role": "technician"}, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad email = %d, want 400", rec.Code)
	}
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "ok@acme.test", "role": "superadmin"}, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role = %d, want 400", rec.Code)
	}
}

func TestUserCreateGateAndEscalation(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "admin", "admin@acme.test", uaPw, RoleAdmin)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	h := f.srv.Handler()

	// A Technician holds no CapManageUsers → creating a user is forbidden by the gate.
	techCookie, techCSRF, techTok := loginFor(t, f, "tech@acme.test", uaPw)
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "x@acme.test", "role": "readonly"}, techTok, techCookie, techCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("tech creating a user = %d, want 403 (no CapManageUsers)", rec.Code)
	}

	adminCookie, adminCSRF, adminTok := loginFor(t, f, "admin@acme.test", uaPw)
	// An Admin cannot create an Owner (Owner holds CapManageTenant the Admin lacks) → 403.
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "o@acme.test", "role": "owner"}, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("admin creating owner = %d, want 403", rec.Code)
	}
	// But an Admin CAN create a Technician → 201.
	if rec := doJSONWith(t, h, "POST", "/users", map[string]any{"email": "t2@acme.test", "role": "technician"}, adminTok, adminCookie, adminCSRF); rec.Code != http.StatusCreated {
		t.Fatalf("admin creating tech = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

// TestPgUserCreateUnderRLS drives PgUserStore.CreateUser as rmt_app: the new user is created with its
// role in the caller's tenant, is invisible in another tenant (RLS), a duplicate email is ErrEmailExists,
// and the SAME email is free in a different tenant (uniqueness is per-tenant).
func TestPgUserCreateUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tidA, _ := provisionUser(t, suPool, "uc-a", "a@uc-a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "uc-b", "b@uc-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	newID := newUUID()
	if err := store.CreateUser(ctx, tidA, newID, "created@uc-a.test", "Created", RoleReadOnly, nil); err != nil {
		t.Fatalf("create A: %v", err)
	}
	aUsers, _ := store.ListUsers(ctx, tidA)
	var found *UserSummary
	for i := range aUsers {
		if aUsers[i].ID == newID {
			found = &aUsers[i]
		}
	}
	if found == nil || found.Email != "created@uc-a.test" || len(found.Roles) != 1 || found.Roles[0] != "readonly" {
		t.Fatalf("created user in A = %+v", found)
	}
	if g, _ := store.GrantFor(ctx, tidA, newID); !g.Allows(CapViewMachines) || g.Allows(CapBackstageShell) {
		t.Fatal("created readonly user should allow view_machines but not backstage_shell")
	}
	// Invisible in B (RLS).
	bUsers, _ := store.ListUsers(ctx, tidB)
	for _, u := range bUsers {
		if u.ID == newID {
			t.Fatal("A's created user leaked into B's listing")
		}
	}
	// Duplicate email in A → ErrEmailExists; the same email is free in B (per-tenant uniqueness).
	if err := store.CreateUser(ctx, tidA, newUUID(), "created@uc-a.test", "Dup", RoleTechnician, nil); !errors.Is(err, ErrEmailExists) {
		t.Fatalf("dup email err = %v, want ErrEmailExists", err)
	}
	if err := store.CreateUser(ctx, tidB, newUUID(), "created@uc-a.test", "InB", RoleReadOnly, nil); err != nil {
		t.Fatalf("same email in B: %v", err)
	}
}

// TestPgUserAdminUnderRLS drives PgUserStore's list + disable as rmt_app: the listing is tenant-scoped,
// SetUserDisabled toggles disabled_at, and a cross-tenant disable is refused (RLS hides the row).
func TestPgUserAdminUnderRLS(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tidA, uidA := provisionUser(t, suPool, "ua-a", "a@ua-a.test", "password-1234")
	tidB, uidB := provisionUser(t, suPool, "ua-b", "b@ua-b.test", "password-1234")
	ctx := context.Background()
	appPool := newAppRolePool(t, ctx)
	store := newPgUserStoreT(appPool)

	// ListUsers is RLS-scoped: A sees only A's user, never B's.
	aUsers, err := store.ListUsers(ctx, tidA)
	if err != nil {
		t.Fatalf("ListUsers A: %v", err)
	}
	if len(aUsers) != 1 || aUsers[0].ID != uidA {
		t.Fatalf("ListUsers(A) = %+v, want [%s]", aUsers, uidA)
	}
	for _, u := range aUsers {
		if u.ID == uidB {
			t.Fatal("A's listing leaked B's user")
		}
	}

	// Disable sets disabled_at (FindUserByID reflects it); enable clears it.
	if err := store.SetUserDisabled(ctx, tidA, uidA, true); err != nil {
		t.Fatalf("disable A: %v", err)
	}
	if u, _ := store.FindUserByID(ctx, tidA, uidA); u == nil || !u.Disabled {
		t.Fatalf("A user should be disabled: %+v", u)
	}
	if err := store.SetUserDisabled(ctx, tidA, uidA, false); err != nil {
		t.Fatalf("enable A: %v", err)
	}
	if u, _ := store.FindUserByID(ctx, tidA, uidA); u == nil || u.Disabled {
		t.Fatalf("A user should be enabled: %+v", u)
	}

	// A cross-tenant disable (pinned to A, targeting B's id) affects 0 rows → ErrNoUser, and B is untouched.
	if err := store.SetUserDisabled(ctx, tidA, uidB, true); !errors.Is(err, ErrNoUser) {
		t.Fatalf("cross-tenant disable err = %v, want ErrNoUser", err)
	}
	if u, _ := store.FindUserByID(ctx, tidB, uidB); u == nil || u.Disabled {
		t.Fatalf("B user should be unaffected: %+v", u)
	}
}
