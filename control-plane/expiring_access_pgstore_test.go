package controlplane

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// docs/56 against Postgres under RLS (the app role): the same rules the in-memory tests pin, so the
// fake and pg agree.

func TestPgExpiredMembershipGrantsNothing(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "exp-a", "a@exp-a.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))

	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician, ExpiresAt: future()}); err != nil {
		t.Fatalf("set future expiry: %v", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); !g.Allows(CapStartSession) {
		t.Fatal("an unexpired membership must grant")
	}
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician, ExpiresAt: past()}); err != nil {
		t.Fatalf("set past expiry: %v", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); g.Allows(CapStartSession) || len(g.Members) != 0 {
		t.Fatalf("an expired membership must grant nothing in pg, got %d members", len(g.Members))
	}
	stored, err := store.StoredGrantFor(ctx, tid, uid)
	if err != nil || len(stored.Members) != 1 || stored.Members[0].ExpiresAt == nil || stored.Members[0].Role != RoleTechnician {
		t.Fatalf("StoredGrantFor must keep the expired row with its expiry: %+v %v", stored, err)
	}
	users, _ := store.ListUsers(ctx, tid)
	if len(users) != 1 || !users[0].AccessExpired || users[0].AccessExpiresAt == nil {
		t.Fatalf("pg ListUsers must show the user as expired: %+v", users)
	}
	if err := store.SetUserAssignment(ctx, tid, uid, Assignment{Role: RoleTechnician}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	g, _ := store.GrantFor(ctx, tid, uid)
	users, _ = store.ListUsers(ctx, tid)
	if !g.Allows(CapStartSession) || users[0].AccessExpired || users[0].AccessExpiresAt != nil {
		t.Fatalf("NULL never expires: allows=%v %+v", g.Allows(CapStartSession), users[0])
	}

	// The boundary, on the DATABASE clock: a membership expiring at the statement instant is expired.
	if _, err := suPool.Exec(ctx, `UPDATE membership SET expires_at = statement_timestamp() WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("set boundary: %v", err)
	}
	if g, _ := store.GrantFor(ctx, tid, uid); len(g.Members) != 0 {
		t.Fatal("expires_at at (or before) the current statement time must not grant")
	}
}

func TestPgMixedMembershipsGrantOnlyTheLiveOne(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "exp-b", "b@exp-b.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))
	groups := NewPgMachineGroupStore(newAppRolePool(t, ctx))
	gA, gB := &MachineGroup{Name: "A"}, &MachineGroup{Name: "B"}
	if err := groups.CreateMachineGroup(ctx, tid, gA); err != nil {
		t.Fatal(err)
	}
	if err := groups.CreateMachineGroup(ctx, tid, gB); err != nil {
		t.Fatal(err)
	}
	// Two rows: an expired group-A readonly and a live group-B technician (written directly: the
	// console only ever writes one row, but older or SSO data may hold several).
	if _, err := suPool.Exec(ctx, `DELETE FROM membership WHERE user_id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := suPool.Exec(ctx, `
		INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids, expires_at)
		SELECT $1::uuid, $2::uuid, r.id, ARRAY[$3::uuid], now() - interval '1 hour' FROM role r WHERE r.key = 'readonly' AND r.tenant_id IS NULL
		UNION ALL
		SELECT $1::uuid, $2::uuid, r.id, ARRAY[$4::uuid], now() + interval '1 day' FROM role r WHERE r.key = 'technician' AND r.tenant_id IS NULL`,
		tid, uid, gA.ID, gB.ID); err != nil {
		t.Fatalf("seed rows: %v", err)
	}
	g, _ := store.GrantFor(ctx, tid, uid)
	if g.AllowsInGroup(CapViewMachines, gA.ID) || !g.AllowsInGroup(CapStartSession, gB.ID) {
		t.Fatal("only the live group-B row may grant")
	}
	stored, _ := store.StoredGrantFor(ctx, tid, uid)
	if len(stored.Members) != 2 || stored.Homogeneous() {
		t.Fatalf("stored: both rows, heterogeneous: %+v", stored.Members)
	}
	users, _ := store.ListUsers(ctx, tid)
	if users[0].AccessExpired || users[0].AccessExpiresAt == nil {
		t.Fatalf("one live row: not expired, latest expiry shown: %+v", users[0])
	}
}

// Two Owners demoting each other at the same moment must not leave the tenant without one: the
// Owner-row lock serializes them and the second sees the first's commit (docs/56 sec. 4.2a).
func TestPgConcurrentOwnerDemotionsKeepAnOwner(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "exp-c", "c@exp-c.test", "password-1234")
	ctx := context.Background()
	store := newPgUserStoreT(newAppRolePool(t, ctx))
	other := newUUID()
	if err := store.CreateUser(ctx, tid, other, "o2@exp-c.test", "O2", RoleOwner, nil); err != nil {
		t.Fatalf("create second owner: %v", err)
	}
	for i := 0; i < 15; i++ {
		for _, id := range []string{uid, other} {
			if _, err := suPool.Exec(ctx, `DELETE FROM membership WHERE user_id = $1`, id); err != nil {
				t.Fatal(err)
			}
			if _, err := suPool.Exec(ctx, `
				INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
				SELECT $1, $2, r.id, '{}' FROM role r WHERE r.key = 'owner' AND r.tenant_id IS NULL`, tid, id); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for k, id := range []string{uid, other} {
			wg.Add(1)
			go func(k int, id string) {
				defer wg.Done()
				<-start
				errs[k] = store.SetUserRole(ctx, tid, id, RoleAdmin, nil)
			}(k, id)
		}
		close(start)
		wg.Wait()
		var owners int
		if err := suPool.QueryRow(ctx, `
			SELECT count(*) FROM membership m JOIN role r ON r.id = m.role_id
			WHERE m.tenant_id = $1 AND r.key = 'owner'`, tid).Scan(&owners); err != nil {
			t.Fatal(err)
		}
		if owners < 1 {
			t.Fatalf("iteration %d: concurrent demotions left NO Owner (errs %v)", i, errs)
		}
		refused := 0
		for _, err := range errs {
			if errors.Is(err, ErrLastOwner) {
				refused++
			} else if err != nil {
				t.Fatalf("iteration %d: unexpected error %v", i, err)
			}
		}
		if refused != 1 {
			t.Fatalf("iteration %d: exactly one demotion must be refused, got %d (errs %v)", i, refused, errs)
		}
	}
	// And disabling the last remaining permanent Owner is refused too.
	var lastOwner string
	if err := suPool.QueryRow(ctx, `
		SELECT m.user_id::text FROM membership m JOIN role r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND r.key = 'owner' LIMIT 1`, tid).Scan(&lastOwner); err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserDisabled(ctx, tid, lastOwner, true); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("disabling the last Owner = %v, want ErrLastOwner", err)
	}
}
