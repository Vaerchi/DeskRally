package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAttendedListSharedScopedAndPaginated(t *testing.T) {
	owner, _ := newAttendedServer(t)
	const tenant = "00000000-0000-0000-0000-0000000000bb"
	const other = "00000000-0000-0000-0000-0000000000dd"
	const tech = "00000000-0000-0000-0000-0000000000ee"
	store := owner.Attended.(*InMemoryAttendedStore)
	store.Now = func() time.Time { return time.Unix(100, 0) }
	for _, group := range []string{attendTestGroup, other, attendTestGroup} {
		_, err := store.Create(context.Background(), tenant, &AttendedSession{GroupID: group, TechnicianID: "creator", PromoteToken: "secret-token", PromoteAttemptNonce: "secret-nonce", AgentPubkey: "secret-key"})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := store.Create(context.Background(), "foreign-tenant", &AttendedSession{GroupID: attendTestGroup, TechnicianID: "creator"})
	if err != nil {
		t.Fatal(err)
	}
	scoped := attendedServerAs(owner, &Principal{UserID: tech, TenantID: tenant, Grant: NewGrant(tech, tenant, NewMembership(RoleTechnician, Groups(attendTestGroup)))})
	type page struct {
		Sessions []AttendedSession `json:"sessions"`
		More     bool              `json:"has_more"`
	}
	var first, second, empty page
	if code := apiJSON(t, scoped, "GET", "/attended-sessions?limit=1", "", &first); code != 200 {
		t.Fatal(code)
	}
	if len(first.Sessions) != 1 || !first.More || first.Sessions[0].TechnicianID != "creator" || first.Sessions[0].GroupID != attendTestGroup {
		t.Fatalf("bad first page: %+v", first)
	}
	if code := apiJSON(t, scoped, "GET", "/attended-sessions?limit=1&offset=1", "", &second); code != 200 {
		t.Fatal(code)
	}
	if len(second.Sessions) != 1 || second.More || first.Sessions[0].ID <= second.Sessions[0].ID {
		t.Fatalf("bad second page: %+v", second)
	}
	if code := apiJSON(t, scoped, "GET", "/attended-sessions?limit=1&offset=2", "", &empty); code != 200 || empty.Sessions == nil || len(empty.Sessions) != 0 {
		t.Fatalf("bad empty page: %+v status %d", empty, code)
	}
	for _, query := range []string{"limit=0", "limit=101", "offset=-1", "offset=1000001", "limit=no", "limit=1&limit=2", "offset="} {
		if code := apiJSON(t, scoped, "GET", "/attended-sessions?"+query, "", nil); code != 400 {
			t.Errorf("%s: %d", query, code)
		}
	}
	rec := httptest.NewRecorder()
	scoped.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attended-sessions", nil))
	for _, secret := range []string{"secret-token", "secret-nonce", "secret-key", "code_hash", "join_code", "attend_token"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("leaked %s", secret)
		}
	}
	denied := attendedServerAs(owner, &Principal{UserID: tech, TenantID: tenant, Grant: NewGrant(tech, tenant)})
	if code := apiJSON(t, denied, "GET", "/attended-sessions", "", nil); code != 403 {
		t.Fatal(code)
	}
	foreign := attendedServerAs(owner, &Principal{UserID: tech, TenantID: "no-sessions", Grant: NewGrant(tech, "no-sessions", NewMembership(RoleOwner, AllGroups()))})
	if code := apiJSON(t, foreign, "GET", "/attended-sessions", "", &empty); code != 200 || len(empty.Sessions) != 0 {
		t.Fatalf("foreign tenant: %+v %d", empty, code)
	}
	// All-groups membership without view_sessions must not widen the scoped viewer membership.
	limited := NewMembership(RoleTechnician, Groups(attendTestGroup))
	noCaps := Membership{Scope: AllGroups()}
	mixed := attendedServerAs(owner, &Principal{UserID: tech, TenantID: tenant, Grant: NewGrant(tech, tenant, limited, noCaps)})
	var all page
	if code := apiJSON(t, mixed, "GET", "/attended-sessions", "", &all); code != 200 || len(all.Sessions) != 2 {
		t.Fatalf("mixed scope: %+v %d", all, code)
	}
	// The response must use an empty array, never null.
	b, _ := json.Marshal(empty)
	if !strings.Contains(string(b), `"sessions":[]`) {
		t.Fatal(string(b))
	}
}

func TestPgAttendedListTenantScopeAndPagination(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "list-one", "one@example.test", "password-1234")
	otherTenant, otherUser := provisionUser(t, pool, "list-two", "two@example.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	otherGid := seedGroup(t, pool, otherTenant)
	store := NewPgAttendedStore(pool)
	ctx := context.Background()
	var hiddenGroup string
	if err := pool.QueryRow(ctx, `INSERT INTO machine_group (tenant_id,name) VALUES ($1,'Hidden') RETURNING id::text`, tid).Scan(&hiddenGroup); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := store.Create(ctx, tid, &AttendedSession{GroupID: gid, TechnicianID: uid}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Create(ctx, otherTenant, &AttendedSession{GroupID: otherGid, TechnicianID: otherUser}); err != nil {
		t.Fatal(err)
	}
	// Newer inaccessible rows must not consume the scoped page limit.
	for i := 0; i < 4; i++ {
		if _, err := store.Create(ctx, tid, &AttendedSession{GroupID: hiddenGroup, TechnicianID: uid}); err != nil {
			t.Fatal(err)
		}
	}
	// Also exercise the restricted application role, not only the owner connection.
	for _, db := range []*PgAttendedStore{store, NewPgAttendedStore(newAppRolePool(t, ctx))} {
		rows, err := db.List(ctx, tid, Groups(gid), 2, 0)
		if err != nil || len(rows) != 2 {
			t.Fatalf("first: %v %+v", err, rows)
		}
		tail, err := db.List(ctx, tid, Groups(gid), 2, 2)
		if err != nil || len(tail) != 1 || tail[0].ID == rows[0].ID || tail[0].ID == rows[1].ID {
			t.Fatalf("tail: %v %+v", err, tail)
		}
		rows, err = db.List(ctx, tid, Groups(otherGid), 10, 0)
		if err != nil || len(rows) != 0 {
			t.Fatalf("scope leak: %v %+v", err, rows)
		}
		rows, err = db.List(ctx, tid, AllGroups(), 10, 0)
		if err != nil || len(rows) != 7 {
			t.Fatalf("tenant filter: %v %+v", err, rows)
		}
	}
}
