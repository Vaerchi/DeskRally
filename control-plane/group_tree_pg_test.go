package controlplane

// Postgres-only proofs for nested machine groups (docs/62, migration 0065): the structure trigger under TWO
// real connections (opposing moves, insertion under a concurrently moved subtree), the tree lock's
// ordering against tree-conditional writes, sibling admissions under a shared ancestor cap, tenant deletion
// with a tree, direct parent deletion, the composite FK / CHECK / immutable-key guards, the SQL helpers, RLS
// on group_tree_version and the migration's own existing-data assertion. The scenarios that also exist in
// the fake are in group_tree_store_test.go. Needs TEST_DATABASE_URL; verify-all.ps1 treats a skip as a
// failure.

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// beginTenantTx opens a transaction pinned to tenant tid on the pool, WITHOUT withTenant's commit-on-return,
// so a test can hold a mutation open across another connection's attempt.
func beginTenantTx(t *testing.T, pool *pgxpool.Pool, tid string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tid); err != nil {
		t.Fatalf("pin tenant: %v", err)
	}
	return tx
}

func sqlState(err error) string { return pgErrCode(err) }

// waitBlocked reports whether done stays open for the given time (the call is parked on a lock).
func waitBlocked(done <-chan error, d time.Duration) (blocked bool) {
	select {
	case <-done:
		return false
	case <-time.After(d):
		return true
	}
}

func TestPgOpposingMovesCannotFormACycle(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	a := env.mkGroup("A", "")
	b := env.mkGroup("B", "")

	tx1 := beginTenantTx(t, env.app, env.tid)
	if _, err := tx1.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, a, b); err != nil { // A under B
		t.Fatalf("tx1 move A under B: %v", err)
	}
	// tx2 (B under A) must WAIT for tx1's tree lock, then see A under B and refuse the cycle. Without the
	// lock it would pass its walk in isolation and BOTH would commit, leaving A -> B -> A.
	tx2 := beginTenantTx(t, env.app, env.tid)
	done := make(chan error, 1)
	go func() {
		_, err := tx2.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, b, a) // B under A
		done <- err
	}()
	if !waitBlocked(done, 400*time.Millisecond) {
		t.Fatal("the second reparent did not wait for the tenant tree lock")
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("tx1 commit: %v", err)
	}
	err := <-done
	if sqlState(err) != "GT001" {
		t.Fatalf("second opposing move = %v (SQLSTATE %q), want GT001 (cycle)", err, sqlState(err))
	}
	_ = tx2.Rollback(ctx)
	tree, _, _ := env.groups.GroupTree(ctx, env.tid)
	if tree[a] != b || tree[b] != "" {
		t.Fatalf("final tree a=%q b=%q, want A under B and B a root", tree[a], tree[b])
	}
}

func TestPgInsertUnderAConcurrentlyMovedSubtreeRespectsTheDepthCap(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	root := env.mkGroup("root", "")
	a := env.mkGroup("A", root) // level 2
	s := env.mkGroup("S", "")   // the moved subtree: S (1) -> Sc (2)
	sc := env.mkGroup("Sc", s)

	// tx1 moves S under A: S = 3, Sc = 4 — legal on its own.
	tx1 := beginTenantTx(t, env.app, env.tid)
	if _, err := tx1.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, s, a); err != nil {
		t.Fatalf("tx1 move S under A: %v", err)
	}
	// tx2 inserts a leaf under Sc: level 3 on its own — legal — but once S has moved it would be level 5.
	tx2 := beginTenantTx(t, env.app, env.tid)
	done := make(chan error, 1)
	go func() {
		_, err := tx2.Exec(ctx, `INSERT INTO machine_group (tenant_id, name, parent_id) VALUES ($1, 'leaf', $2)`, env.tid, sc)
		done <- err
	}()
	if !waitBlocked(done, 400*time.Millisecond) {
		t.Fatal("the insert did not wait for the tenant tree lock held by the concurrent move")
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; sqlState(err) != "GT002" {
		t.Fatalf("insert under the moved subtree = %v (SQLSTATE %q), want GT002 (depth)", err, sqlState(err))
	}
	_ = tx2.Rollback(ctx)
}

func TestPgTreeLockOrdersConditionalWritesAfterAHierarchyMutation(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	p := env.mkGroup("P", "")
	q := env.mkGroup("Q", "")
	mid := env.newMachine(p)
	ver := env.version()

	// A hierarchy mutation is in flight and uncommitted: it holds the tree lock EXCLUSIVELY.
	tx := beginTenantTx(t, env.app, env.tid)
	if err := lockGroupTreeTx(ctx, tx, env.tid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, q, p); err != nil {
		t.Fatal(err)
	}
	// A tree-conditional machine move captured the OLD version. It must park on the lock rather than
	// commit against a tree that is about to change, and then fail with ErrGroupTreeChanged.
	done := make(chan error, 1)
	go func() { done <- env.machines.SetMachineGroupIfTree(ctx, env.tid, mid, q, ver) }()
	if !waitBlocked(done, 400*time.Millisecond) {
		t.Fatal("a tree-conditional write did not wait for the in-flight hierarchy mutation")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrGroupTreeChanged) {
		t.Fatalf("the conditional write after the mutation = %v, want ErrGroupTreeChanged", err)
	}
	if m, _ := env.machines.GetMachineByID(ctx, env.tid, mid); m.GroupID != p {
		t.Fatalf("the refused move changed the machine's group to %s", m.GroupID)
	}
	// The same ordering holds for an assignment edit.
	u := env.newUser("u", RoleAdmin, p)
	tx2 := beginTenantTx(t, env.app, env.tid)
	if err := lockGroupTreeTx(ctx, tx2, env.tid, false); err != nil {
		t.Fatal(err)
	}
	cur := env.version()
	done2 := make(chan error, 1)
	go func() {
		done2 <- env.users.SetUserAssignment(ctx, env.tid, u,
			Assignment{Role: RoleAdmin, ScopedGroupIDs: []string{q}, ExpectTreeVersion: &cur})
	}()
	if !waitBlocked(done2, 400*time.Millisecond) {
		t.Fatal("a tree-conditional assignment did not wait for the in-flight hierarchy mutation")
	}
	if _, err := tx2.Exec(ctx, `INSERT INTO machine_group (tenant_id, name) VALUES ($1, 'bump')`, env.tid); err != nil {
		t.Fatal(err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done2; !errors.Is(err, ErrGroupTreeChanged) {
		t.Fatalf("the assignment after the mutation = %v, want ErrGroupTreeChanged", err)
	}
}

func TestPgSiblingAdmissionsUnderASharedAncestorCap(t *testing.T) {
	env := newPgTreeEnv(t)
	p := env.mkGroup("P", "")
	c1 := env.mkGroup("C1", p)
	c2 := env.mkGroup("C2", p)
	capP := GroupSeatCap{GroupID: p, Cap: 2}

	const attempts = 12
	var admitted, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		group := c1
		if i%2 == 1 {
			group = c2
		}
		mid := env.newMachine(group)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := &SessionRecord{TenantID: env.tid, MachineID: mid, TechnicianID: env.tech, Access: "control", MachineGroupID: group}
			err := env.sessions.StartSessionWithinLimit(env.ctx, env.tid, rec, SessionStartLimits{GroupID: group, GroupCaps: []GroupSeatCap{capP}})
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, ErrGroupConcurrentSessionLimit):
				refused.Add(1)
			default:
				t.Errorf("unexpected admission error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 2 || refused.Load() != attempts-2 {
		t.Fatalf("admitted %d refused %d, want EXACTLY 2 admitted under P's cap of 2 across both siblings", admitted.Load(), refused.Load())
	}
	if got := len(env.openSessions()); got != 2 {
		t.Fatalf("%d sessions open, want 2", got)
	}
}

func TestPgTenantDeletionWithATreeAndDirectParentDeletion(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	tr := env.standardTree()
	env.newMachine(tr.S) // NOT under P: a machine below the parent would itself block a cascading delete and mask the FK under test
	if _, err := env.users.GrantFor(ctx, env.tid, env.tech); err != nil {
		t.Fatal(err)
	}

	// A lone parent that still has children cannot be deleted, even directly in SQL by the owner role.
	_, err := env.su.Exec(ctx, `DELETE FROM machine_group WHERE id = $1`, tr.P)
	if sqlState(err) != "23503" {
		t.Fatalf("direct delete of a parent with children = %v (SQLSTATE %q), want 23503", err, sqlState(err))
	}
	var n int
	if err := env.su.QueryRow(ctx, `SELECT count(*) FROM machine_group WHERE tenant_id = $1::uuid`, env.tid).Scan(&n); err != nil || n != 6 {
		t.Fatalf("groups after the refused delete = %d (err %v), want all 6", n, err)
	}
	// ...and the children were NOT re-rooted (the old SET NULL behaviour).
	var parent *string
	if err := env.su.QueryRow(ctx, `SELECT parent_id::text FROM machine_group WHERE id = $1`, tr.C).Scan(&parent); err != nil || parent == nil || *parent != tr.P {
		t.Fatalf("C's parent after the refused delete = %v (err %v), want P", parent, err)
	}

	// Deleting the whole TENANT cascades parent and children in ONE statement: NO ACTION is checked at
	// statement end, so it succeeds. (An immediate FK would fail depending on the cascade order.)
	if _, err := env.su.Exec(ctx, `DELETE FROM tenant WHERE id = $1`, env.tid); err != nil {
		t.Fatalf("tenant deletion with a group tree: %v", err)
	}
	if err := env.su.QueryRow(ctx, `SELECT count(*) FROM machine_group WHERE tenant_id = $1::uuid`, env.tid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("groups left after the tenant was deleted = %d (err %v)", n, err)
	}
	if err := env.su.QueryRow(ctx, `SELECT count(*) FROM group_tree_version WHERE tenant_id = $1::uuid`, env.tid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("version rows left after the tenant was deleted = %d (err %v)", n, err)
	}
	// The other tenant is untouched.
	if _, _, err := env.groups.GroupTree(ctx, env.otherTid); err != nil {
		t.Fatalf("other tenant unreadable after the deletion: %v", err)
	}
}

func TestPgStructureGuardsInTheDatabase(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	a := env.mkGroup("A", "")
	other := &MachineGroup{Name: "B's"}
	if err := env.groups.CreateMachineGroup(ctx, env.otherTid, other); err != nil {
		t.Fatal(err)
	}

	// COMPOSITE FK: tenant A's row naming tenant B's group as its parent is refused even for a role that
	// bypasses RLS (the superuser), because (A, Bgroup) is not a machine_group (tenant_id, id) pair. A plain
	// single-column FK would have accepted it.
	// An INSERT naming it is refused earlier still, by the structure trigger's "the parent must exist in
	// THIS tenant first" rule (GT003); the composite FK is the backstop that an UPDATE reparent reaches.
	_, err := env.su.Exec(ctx, `INSERT INTO machine_group (tenant_id, name, parent_id) VALUES ($1, 'x', $2)`, env.tid, other.ID)
	if sqlState(err) != "GT003" {
		t.Errorf("cross-tenant parent insert as superuser = %v (SQLSTATE %q), want GT003", err, sqlState(err))
	}
	_, err = env.su.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, a, other.ID)
	if sqlState(err) != "23503" {
		t.Errorf("cross-tenant parent reparent as superuser = %v (SQLSTATE %q), want 23503", err, sqlState(err))
	}
	// ...and as the RLS-bound app role.
	tx := beginTenantTx(t, env.app, env.tid)
	_, err = tx.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, a, other.ID)
	if sqlState(err) != "23503" {
		t.Errorf("cross-tenant parent reparent as rmt_app = %v (SQLSTATE %q), want 23503", err, sqlState(err))
	}
	_ = tx.Rollback(ctx)

	// A row cannot be its own parent: refused on INSERT by the same GT003 rule (the row is not there yet).
	self := newUUID()
	_, err = env.su.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name, parent_id) VALUES ($1, $2, 'self', $1)`, self, env.tid)
	if sqlState(err) != "GT003" {
		t.Errorf("self-parent insert = %v (SQLSTATE %q), want GT003", err, sqlState(err))
	}
	// CHECK, the constraint behind it: with the structure trigger switched off (inside a rolled-back
	// transaction) the CHECK is what refuses a self-parent.
	stx, err := env.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stx.Exec(ctx, `ALTER TABLE machine_group DISABLE TRIGGER machine_group_check_structure`); err != nil {
		_ = stx.Rollback(ctx)
		t.Fatal(err)
	}
	_, err = stx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name, parent_id) VALUES ($1, $2, 'self', $1)`, self, env.tid)
	_ = stx.Rollback(ctx)
	if sqlState(err) != "23514" {
		t.Errorf("self-parent insert without the trigger = %v (SQLSTATE %q), want the 23514 check violation", err, sqlState(err))
	}

	// IMMUTABLE KEYS (R5): id and tenant_id cannot be rewritten.
	if _, err := env.su.Exec(ctx, `UPDATE machine_group SET id = $2 WHERE id = $1`, a, newUUID()); sqlState(err) != "23000" {
		t.Errorf("rewriting id = %v (SQLSTATE %q), want 23000", err, sqlState(err))
	}
	if _, err := env.su.Exec(ctx, `UPDATE machine_group SET tenant_id = $2 WHERE id = $1`, a, env.otherTid); sqlState(err) != "23000" {
		t.Errorf("rewriting tenant_id = %v (SQLSTATE %q), want 23000", err, sqlState(err))
	}
	// A rename is still fine (the guard is about the keys only).
	if _, err := env.su.Exec(ctx, `UPDATE machine_group SET name = 'A2' WHERE id = $1`, a); err != nil {
		t.Errorf("rename after the guard: %v", err)
	}
}

func TestPgSubtreeAndAncestorFunctions(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	tr := env.standardTree()
	foreign := &MachineGroup{Name: "foreign"}
	if err := env.groups.CreateMachineGroup(ctx, env.otherTid, foreign); err != nil {
		t.Fatal(err)
	}
	subtree := func(tenant string, roots ...string) []string {
		var out []string
		if err := env.su.QueryRow(ctx, `SELECT cp_group_subtree($1::uuid, $2::uuid[])::text[]`, tenant, roots).Scan(&out); err != nil {
			t.Fatalf("cp_group_subtree: %v", err)
		}
		return sortedCopy(out)
	}
	if got := subtree(env.tid, tr.P); !equalStrings(got, sortedCopy([]string{tr.P, tr.C, tr.G})) {
		t.Errorf("subtree(P) = %v, want P, C, G", got)
	}
	if got := subtree(env.tid, tr.C); !equalStrings(got, sortedCopy([]string{tr.C, tr.G})) {
		t.Errorf("subtree(C) = %v, want C, G (never its parent)", got)
	}
	if got := subtree(env.tid, newUUID()); len(got) != 0 {
		t.Errorf("subtree(dangling) = %v, want nothing", got)
	}
	if got := subtree(env.tid, foreign.ID); len(got) != 0 {
		t.Errorf("subtree(another tenant's group) pinned to this tenant = %v, want nothing (tenant-pinned)", got)
	}
	if got := subtree(env.tid); len(got) != 0 {
		t.Errorf("subtree(empty roots) = %v, want nothing (it is NOT tenant-wide)", got)
	}
	var anc []string
	if err := env.su.QueryRow(ctx, `SELECT cp_group_ancestors($1::uuid, $2::uuid)::text[]`, env.tid, tr.G).Scan(&anc); err != nil {
		t.Fatal(err)
	}
	if !equalStrings(anc, []string{tr.G, tr.C, tr.P, tr.R}) {
		t.Errorf("ancestors(G) = %v, want [G C P R] nearest first", anc)
	}
	if err := env.su.QueryRow(ctx, `SELECT cp_group_ancestors($1::uuid, $2::uuid)::text[]`, env.tid, foreign.ID).Scan(&anc); err != nil || len(anc) != 0 {
		t.Errorf("ancestors(another tenant's group) = %v (err %v), want nothing", anc, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPgGroupTreeVersionIsTenantIsolated(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	env.mkGroup("A", "")
	if err := env.groups.CreateMachineGroup(ctx, env.otherTid, &MachineGroup{Name: "B"}); err != nil {
		t.Fatal(err)
	}
	tx := beginTenantTx(t, env.app, env.tid)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_tree_version`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows visible to tenant A = %d (err %v), want only its own", n, err)
	}
	// A cross-tenant write to the version row is refused by the WITH CHECK.
	if _, err := tx.Exec(ctx, `UPDATE group_tree_version SET version = 99 WHERE tenant_id = $1::uuid`, env.otherTid); err != nil {
		t.Fatalf("update of an invisible row should simply match nothing: %v", err)
	}
	_ = tx.Rollback(ctx)
	var v int64
	if err := env.su.QueryRow(ctx, `SELECT version FROM group_tree_version WHERE tenant_id = $1::uuid`, env.otherTid).Scan(&v); err != nil || v == 99 {
		t.Fatalf("tenant B's version = %d (err %v): tenant A's session wrote it", v, err)
	}
}

// tryExecScript is execScript that returns the error (the migration's refusal is the point of the test).
func tryExecScript(pool *pgxpool.Pool, sql string) error {
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	_, err = conn.Conn().PgConn().Exec(ctx, sql).ReadAll()
	return err
}

func TestPgMigration0065RefusesExistingParentDataAtomically(t *testing.T) {
	su := newTestPool(t)
	resetSchemaWith(t, su, false) // the pre-0065 schema: the plain, unvalidated parent_id FK
	ctx := context.Background()
	var tid, parent, child string
	if err := su.QueryRow(ctx, `SELECT gen_random_uuid()::text, gen_random_uuid()::text, gen_random_uuid()::text`).Scan(&tid, &parent, &child); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,'mig','mig','self_hosted')`, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'p')`, parent, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name, parent_id) VALUES ($1,$2,'c',$3)`, child, tid, parent); err != nil {
		t.Fatalf("seed a pre-0065 parent_id (the old plain FK accepts it): %v", err)
	}
	b, err := os.ReadFile("migrations/0065_machine_group_tree.sql")
	if err != nil {
		t.Fatal(err)
	}

	// With a non-null parent_id present the migration must FAIL LOUDLY...
	err = tryExecScript(su, string(b))
	if err == nil || !strings.Contains(err.Error(), "parent_id is non-null") {
		t.Fatalf("migration over existing parent data = %v, want the loud refusal", err)
	}
	// ...and leave NOTHING half-applied: the old FK is still there, none of the new objects exist.
	var oldFK, newFK, versionTable bool
	if err := su.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'machine_group_parent_id_fkey'),
		       EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'machine_group_parent_fk'),
		       to_regclass('public.group_tree_version') IS NOT NULL`).Scan(&oldFK, &newFK, &versionTable); err != nil {
		t.Fatal(err)
	}
	if !oldFK || newFK || versionTable {
		t.Fatalf("after the refused migration: oldFK=%v newFK=%v versionTable=%v, want true/false/false (atomic)", oldFK, newFK, versionTable)
	}
	var fnExists bool
	if err := su.QueryRow(ctx, `SELECT to_regproc('cp_group_subtree') IS NOT NULL`).Scan(&fnExists); err != nil || fnExists {
		t.Fatalf("cp_group_subtree exists after a refused migration (err %v)", err)
	}

	// Cleared of parent data, it applies, backfills the version row and keeps the groups.
	if _, err := su.Exec(ctx, `UPDATE machine_group SET parent_id = NULL`); err != nil {
		t.Fatal(err)
	}
	if err := tryExecScript(su, string(b)); err != nil {
		t.Fatalf("migration over clean data: %v", err)
	}
	var groups, versions int
	if err := su.QueryRow(ctx, `SELECT (SELECT count(*) FROM machine_group), (SELECT count(*) FROM group_tree_version WHERE tenant_id = $1::uuid)`, tid).Scan(&groups, &versions); err != nil {
		t.Fatal(err)
	}
	if groups != 2 || versions != 1 {
		t.Fatalf("after the migration: %d groups %d version rows, want 2 and 1 (backfilled)", groups, versions)
	}
	// The old SET NULL behaviour is gone and the new FK is in force.
	if err := su.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'machine_group_parent_fk')`).Scan(&newFK); err != nil || !newFK {
		t.Fatalf("the composite FK was not installed (err %v)", err)
	}
}

// TestPgGroupTreeFunctionsAreInvokerAndPinned (R5): the structure trigger and its siblings are VOLATILE and
// SECURITY INVOKER (they run in the caller's tenant context, so RLS shows exactly that tenant's rows) with a
// pinned search_path; the helpers are STABLE (cp_group_tree_lock_key IMMUTABLE) and pinned too.
func TestPgGroupTreeFunctionsAreInvokerAndPinned(t *testing.T) {
	env := newPgTreeEnv(t)
	for _, tc := range []struct {
		name, volatility, path string
	}{
		{"machine_group_check_structure", "v", "search_path=pg_catalog, public"},
		{"machine_group_guard_keys", "v", "search_path=pg_catalog, public"},
		{"machine_group_lock_on_delete", "v", "search_path=pg_catalog, public"},
		{"machine_group_bump_version", "v", "search_path=pg_catalog, public"},
		{"cp_group_subtree", "s", "search_path=pg_catalog, public"},
		{"cp_group_ancestors", "s", "search_path=pg_catalog, public"},
		{"cp_group_tree_lock_key", "i", "search_path=pg_catalog"},
	} {
		var definer bool
		var vol, cfg string
		if err := env.su.QueryRow(env.ctx, `
			SELECT p.prosecdef, p.provolatile::text, COALESCE(p.proconfig::text, '')
			  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
			 WHERE n.nspname = 'public' AND p.proname = $1`, tc.name).Scan(&definer, &vol, &cfg); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if definer {
			t.Errorf("%s is SECURITY DEFINER; it must run as the caller (RLS-scoped)", tc.name)
		}
		if vol != tc.volatility {
			t.Errorf("%s volatility = %q, want %q", tc.name, vol, tc.volatility)
		}
		if !strings.Contains(cfg, tc.path) {
			t.Errorf("%s proconfig = %q, want it to pin %s", tc.name, cfg, tc.path)
		}
	}
}

// A delete is a hierarchy mutation too: it must queue behind an in-flight reparent of the same tenant (the
// delete trigger takes the tree lock), so a delete can never interleave with a move it depends on.
func TestPgDeleteWaitsForTheTenantTreeLock(t *testing.T) {
	env := newPgTreeEnv(t)
	ctx := env.ctx
	a := env.mkGroup("A", "")
	b := env.mkGroup("B", "")
	leaf := env.mkGroup("leaf", "")

	tx1 := beginTenantTx(t, env.app, env.tid)
	if _, err := tx1.Exec(ctx, `UPDATE machine_group SET parent_id = $2 WHERE id = $1`, b, a); err != nil {
		t.Fatal(err)
	}
	tx2 := beginTenantTx(t, env.app, env.tid)
	done := make(chan error, 1)
	go func() {
		_, err := tx2.Exec(ctx, `DELETE FROM machine_group WHERE id = $1`, leaf)
		done <- err
	}()
	if !waitBlocked(done, 400*time.Millisecond) {
		t.Fatal("a delete did not wait for the tenant tree lock held by an in-flight reparent")
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the delete after the reparent committed: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
