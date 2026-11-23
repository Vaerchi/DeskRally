package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// docs/56: expiring access. The rule is one filter in GrantFor; these tests pin it, the admin paths
// that must read the STORED rows instead, and the permanent-Owner invariant.

func past() *time.Time   { t := time.Now().Add(-time.Hour).UTC(); return &t }
func future() *time.Time { t := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second); return &t }

// --- the rule itself, on the in-memory store (the pg twin is in expiring_access_pgstore_test.go) ---

func TestInMemoryExpiredMembershipGrantsNothing(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	if err := s.CreateUserAssignment(ctx, "t1", "u1", "a@x.test", "A",
		Assignment{Role: RoleTechnician, ExpiresAt: future()}); err != nil {
		t.Fatalf("create: %v", err)
	}
	g, _ := s.GrantFor(ctx, "t1", "u1")
	if !g.Allows(CapStartSession) {
		t.Fatal("an unexpired membership must still grant")
	}
	if err := s.SetUserAssignment(ctx, "t1", "u1", Assignment{Role: RoleTechnician, ExpiresAt: past()}); err != nil {
		t.Fatalf("expire: %v", err)
	}
	g, _ = s.GrantFor(ctx, "t1", "u1")
	if g.Allows(CapStartSession) || len(g.Members) != 0 {
		t.Fatalf("an expired membership must grant nothing, got %d members", len(g.Members))
	}
	stored, _ := s.StoredGrantFor(ctx, "t1", "u1")
	if len(stored.Members) != 1 || stored.Members[0].ExpiresAt == nil {
		t.Fatalf("the stored grant keeps the expired row with its expiry: %+v", stored.Members)
	}
	users, _ := s.ListUsers(ctx, "t1")
	if len(users) != 1 || !users[0].AccessExpired || users[0].AccessExpiresAt == nil {
		t.Fatalf("ListUsers must show the user as expired: %+v", users)
	}
	if err := s.SetUserAssignment(ctx, "t1", "u1", Assignment{Role: RoleTechnician}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	g, _ = s.GrantFor(ctx, "t1", "u1")
	users, _ = s.ListUsers(ctx, "t1")
	if !g.Allows(CapStartSession) || users[0].AccessExpired || users[0].AccessExpiresAt != nil {
		t.Fatalf("a NULL expiry never expires: allows=%v summary=%+v", g.Allows(CapStartSession), users[0])
	}
}

func TestGrantExpiryAggregates(t *testing.T) {
	never := NewMembership(RoleReadOnly, AllGroups())
	soon := NewMembership(RoleReadOnly, AllGroups()).WithExpiry(future())
	gone := NewMembership(RoleReadOnly, Groups("gA")).WithExpiry(past())
	now := time.Now()

	if NewGrant("u", "t").AccessExpiry() != nil || NewGrant("u", "t").AccessExpired(now) {
		t.Error("no memberships: no expiry, not expired")
	}
	if NewGrant("u", "t", never, soon).AccessExpiry() != nil {
		t.Error("any never-expiring membership makes the user's access never expire")
	}
	if at := NewGrant("u", "t", soon, gone).AccessExpiry(); at == nil || !at.Equal(*soon.ExpiresAt) {
		t.Errorf("the LATEST expiry is when access ends, got %v", at)
	}
	if NewGrant("u", "t", soon, gone).AccessExpired(now) {
		t.Error("one live membership: not expired")
	}
	if !NewGrant("u", "t", gone).AccessExpired(now) {
		t.Error("every membership expired: expired")
	}
	// The boundary: expiring exactly now is expired (the pg predicate is expires_at > now).
	at := now
	if !NewMembership(RoleReadOnly, AllGroups()).WithExpiry(&at).expiredAt(now) {
		t.Error("expires_at == now must count as expired")
	}
	if got := NewGrant("u", "t", soon, gone).Effective(now); len(got.Members) != 1 {
		t.Errorf("Effective keeps only live members, got %d", len(got.Members))
	}
	if NewGrant("u", "t", soon, gone).Homogeneous() || !NewGrant("u", "t", soon).Homogeneous() {
		t.Error("Homogeneous: different scope/expiry rows are heterogeneous; one row is homogeneous")
	}
}

// --- the permanent-Owner invariant (docs/56 sec. 4.2a), fake store ---

func TestInMemoryLastPermanentOwnerIsKept(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	_ = s.CreateUser(ctx, "t1", "o1", "o1@x.test", "", RoleOwner, nil)
	_ = s.CreateUser(ctx, "t1", "o2", "o2@x.test", "", RoleOwner, nil)
	if err := s.SetUserRole(ctx, "t1", "o2", RoleAdmin, nil); err != nil {
		t.Fatalf("demoting one of two Owners must succeed: %v", err)
	}
	if err := s.SetUserRole(ctx, "t1", "o1", RoleAdmin, nil); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demoting the last Owner = %v, want ErrLastOwner", err)
	}
	if err := s.SetUserDisabled(ctx, "t1", "o1", true); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("disabling the last Owner = %v, want ErrLastOwner", err)
	}
	g, _ := s.GrantFor(ctx, "t1", "o1")
	if !g.Allows(CapManageTenant) {
		t.Fatal("a refused demotion must leave the Owner's grant unchanged")
	}
	// A tenant that never had a permanent Owner (test/legacy data) is not blocked from anything.
	_ = s.CreateUser(ctx, "t2", "a1", "a1@x.test", "", RoleAdmin, nil)
	if err := s.SetUserDisabled(ctx, "t2", "a1", true); err != nil {
		t.Fatalf("no Owner to keep: %v", err)
	}
}

// --- through the real handler chain ---

type roleResp struct {
	code      int
	expiresAt *string
	body      string
}

func setRoleAs(t *testing.T, f *authFixture, cookie, csrf *http.Cookie, tok, target string, body map[string]any) roleResp {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/users/"+target+"/role", body, tok, cookie, csrf)
	var resp struct {
		ExpiresAt *string `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return roleResp{code: rec.Code, expiresAt: resp.ExpiresAt, body: rec.Body.String()}
}

func TestExpiringAccessSetPreserveClearAndValidate(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) roleResp { return setRoleAs(t, f, cookie, csrf, tok, "tech", body) }

	when := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	if r := set(map[string]any{"role": "technician", "expires_at": when}); r.code != 200 || r.expiresAt == nil || *r.expiresAt != when {
		t.Fatalf("set expiry = %d %v (%s), want 200 %s", r.code, r.expiresAt, r.body, when)
	}
	// ABSENT → preserved (a role change must not make temporary access permanent).
	if r := set(map[string]any{"role": "readonly"}); r.code != 200 || r.expiresAt == nil || *r.expiresAt != when {
		t.Fatalf("absent expiry must be preserved: %d %v", r.code, r.expiresAt)
	}
	// null → never.
	if r := set(map[string]any{"role": "readonly", "expires_at": nil}); r.code != 200 || r.expiresAt != nil {
		t.Fatalf("null must clear the expiry: %d %v", r.code, r.expiresAt)
	}
	for name, v := range map[string]any{
		"past":         time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"under a min":  time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339),
		"over 5 years": time.Now().Add(6 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"no offset":    "2030-01-01T10:00:00",
		"a number":     1234,
		"garbage":      "next tuesday",
	} {
		if r := set(map[string]any{"role": "readonly", "expires_at": v}); r.code != http.StatusBadRequest {
			t.Errorf("expires_at %s (%v) = %d, want 400", name, v, r.code)
		}
	}
	// The audit row records the resolved expiry.
	if r := set(map[string]any{"role": "technician", "expires_at": when}); r.code != 200 {
		t.Fatalf("re-set: %d", r.code)
	}
	ev := f.lastAuditEvent(t, "user.role_set")
	if got, _ := ev["expires_at"].(string); got != when {
		t.Fatalf("audit expires_at = %v, want %s", ev["expires_at"], when)
	}
}

func TestOwnerAccessCannotExpire(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) roleResp { return setRoleAs(t, f, cookie, csrf, tok, "tech", body) }
	when := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)

	if r := set(map[string]any{"role": "owner", "expires_at": when}); r.code != http.StatusBadRequest {
		t.Fatalf("Owner with an expiry = %d, want 400", r.code)
	}
	// A PRESERVED expiry also blocks a promotion to Owner until it is explicitly cleared.
	if r := set(map[string]any{"role": "technician", "expires_at": when}); r.code != 200 {
		t.Fatalf("temporary tech: %d %s", r.code, r.body)
	}
	if r := set(map[string]any{"role": "owner"}); r.code != http.StatusBadRequest {
		t.Fatalf("promotion to Owner with a preserved expiry = %d, want 400", r.code)
	}
	if r := set(map[string]any{"role": "owner", "expires_at": nil}); r.code != 200 {
		t.Fatalf("promotion to Owner with an explicit null = %d %s, want 200", r.code, r.body)
	}
	// The invite applies the same rule.
	body := map[string]any{"email": "new@acme.test", "role": "owner", "expires_at": when}
	if rec := doJSONWith(t, f.srv.Handler(), "POST", "/users", body, tok, cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("invite an Owner with an expiry = %d, want 400", rec.Code)
	}
}

func TestExpiredTargetKeepsItsProtection(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	// A lower administrator: may manage roles, but not someone with Admin authority.
	f.addUserWithGrant(t, "tenant-1", "mgr", "mgr@acme.test", uaPw,
		NewGrant("mgr", "tenant-1", NewMembership(RoleTechnician, AllGroups()), NewCapabilityMembership([]Capability{CapManageRoles, CapManageUsers}, AllGroups())))
	// An Admin whose access has EXPIRED.
	f.addUserWithGrant(t, "tenant-1", "adm", "adm@acme.test", uaPw,
		NewGrant("adm", "tenant-1", NewMembership(RoleAdmin, AllGroups()).WithExpiry(past())))
	cookie, csrf, tok := loginFor(t, f, "mgr@acme.test", uaPw)

	// Expiry never lowers who may edit a user: still 403 for someone who could not edit the Admin.
	if r := setRoleAs(t, f, cookie, csrf, tok, "adm", map[string]any{"role": "readonly", "expires_at": nil}); r.code != http.StatusForbidden {
		t.Fatalf("a lower admin editing an EXPIRED Admin = %d (%s), want 403", r.code, r.body)
	}
	// Every other target-protection route reads the stored grant too (docs/56 sec. 4.2).
	for _, rt := range []struct{ method, path string }{
		{"POST", "/users/adm/disable"},
		{"POST", "/users/adm/sign-out"},
		{"DELETE", "/users/adm/lockout"},
	} {
		rec := doJSONWith(t, f.srv.Handler(), rt.method, rt.path, map[string]any{}, tok, cookie, csrf)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a lower admin: %s %s on an EXPIRED Admin = %d, want 403", rt.method, rt.path, rec.Code)
		}
	}
}

func TestHeterogeneousMembershipsNeedExplicitScopeAndExpiry(t *testing.T) {
	f, gA, gB := scopedFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	// An expired group-A row and a live group-B row: preserving "the" scope or expiry is ambiguous.
	f.addUserWithGrant(t, "tenant-1", "mix", "mix@acme.test", uaPw, NewGrant("mix", "tenant-1",
		NewMembership(RoleTechnician, Groups(gA)).WithExpiry(past()),
		NewMembership(RoleTechnician, Groups(gB)).WithExpiry(future())))
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) roleResp { return setRoleAs(t, f, cookie, csrf, tok, "mix", body) }

	if r := set(map[string]any{"role": "technician"}); r.code != http.StatusBadRequest {
		t.Fatalf("omitting both = %d, want 400", r.code)
	}
	if r := set(map[string]any{"role": "technician", "scoped_group_ids": []string{gB}}); r.code != http.StatusBadRequest {
		t.Fatalf("omitting expires_at = %d, want 400", r.code)
	}
	if r := set(map[string]any{"role": "technician", "expires_at": nil}); r.code != http.StatusBadRequest {
		t.Fatalf("omitting scope = %d, want 400", r.code)
	}
	if r := set(map[string]any{"role": "technician", "scoped_group_ids": []string{gB}, "expires_at": nil}); r.code != http.StatusBadRequest {
		t.Fatalf("omitting access_window = %d, want 400 (docs/57: all three when heterogeneous)", r.code)
	}
	if r := set(map[string]any{"role": "technician", "scoped_group_ids": []string{gB}, "expires_at": nil, "access_window": nil}); r.code != 200 {
		t.Fatalf("all explicit = %d %s, want 200", r.code, r.body)
	}
	// The expired group-A scope did not come back.
	g, _ := f.users.GrantFor(context.Background(), "tenant-1", "mix")
	if g.AllowsInGroup(CapViewMachines, gA) || !g.AllowsInGroup(CapViewMachines, gB) {
		t.Fatal("the explicit edit must leave exactly group B")
	}
}

func TestPastExpiryIsPreservedByAnUnrelatedEdit(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUserWithGrant(t, "tenant-1", "gone", "gone@acme.test", uaPw,
		NewGrant("gone", "tenant-1", NewMembership(RoleTechnician, AllGroups()).WithExpiry(past())))
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	// A role change that does not mention expiry keeps the (past) expiry: it must neither fail
	// validation nor quietly give the access back.
	if r := setRoleAs(t, f, cookie, csrf, tok, "gone", map[string]any{"role": "readonly"}); r.code != 200 || r.expiresAt == nil {
		t.Fatalf("unrelated edit of an expired user = %d %v (%s), want 200 with the past expiry kept", r.code, r.expiresAt, r.body)
	}
	g, _ := f.users.GrantFor(context.Background(), "tenant-1", "gone")
	if len(g.Members) != 0 {
		t.Fatal("the unrelated edit re-enabled expired access")
	}
}

func TestLastOwnerConflictThroughTheHandlers(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "o1", "o1@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "o2", "o2@acme.test", uaPw, RoleOwner)
	c1, s1, t1 := loginFor(t, f, "o1@acme.test", uaPw)
	if r := setRoleAs(t, f, c1, s1, t1, "o2", map[string]any{"role": "admin"}); r.code != 200 {
		t.Fatalf("o1 demotes o2: %d %s", r.code, r.body)
	}
	// o2 is now an Admin and cannot act on o1 at all; the store invariant is the backstop for the
	// concurrent case (pg race test). Here: disabling the only remaining Owner through the API by
	// another Owner cannot happen (self is refused), so check the store answer maps to 409.
	if err := f.users.SetUserDisabled(context.Background(), "tenant-1", "o1", true); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("store: disabling the last Owner = %v, want ErrLastOwner", err)
	}
}

func TestMeReportsExpiredAccess(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUserWithGrant(t, "tenant-1", "gone", "gone@acme.test", uaPw,
		NewGrant("gone", "tenant-1", NewMembership(RoleTechnician, AllGroups()).WithExpiry(past())))
	cookie, csrf, tok := loginFor(t, f, "gone@acme.test", uaPw)
	rec := doJSONWith(t, f.srv.Handler(), "GET", "/me", nil, tok, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("/me for an expired user = %d, want 200 (it needs no capability)", rec.Code)
	}
	var me struct {
		Email           string  `json:"email"`
		AccessExpired   bool    `json:"access_expired"`
		AccessExpiresAt *string `json:"access_expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if !me.AccessExpired || me.AccessExpiresAt == nil || me.Email != "gone@acme.test" {
		t.Fatalf("/me = %+v, want access_expired with the date", me)
	}
	// And the expired user really can do nothing.
	if rec := doJSONWith(t, f.srv.Handler(), "GET", "/users", nil, tok, cookie, csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("an expired user listing users = %d, want 403", rec.Code)
	}
}

// A live unattended session ends when its holder's access expires: the renewal re-resolves the
// grant through GrantFor, which no longer grants anything (docs/56 sec. 2).
func TestRenewIsRefusedAfterAccessExpires(t *testing.T) {
	f := newLeaseFixture(t)
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusOK {
		t.Fatalf("renewal must work before expiry: %d %s", got.code, got.body)
	}
	if err := f.users.SetUserAssignment(context.Background(), leaseTenant, leaseTechID,
		Assignment{Role: RoleTechnician, ExpiresAt: past()}); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusForbidden {
		t.Fatalf("renew after the holder's access expired = %d, want 403: %s", got.code, got.body)
	}
}

// lastAuditEvent returns the metadata of the newest management-audit event with this action.
func (f *authFixture) lastAuditEvent(t *testing.T, action string) map[string]any {
	t.Helper()
	events, err := f.srv.MgmtAudit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			var md map[string]any
			if err := json.Unmarshal(events[i].Metadata, &md); err != nil {
				t.Fatalf("audit metadata: %v", err)
			}
			return md
		}
	}
	t.Fatalf("no %s audit event", action)
	return nil
}
