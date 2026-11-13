package controlplane

// The Postgres backend of the shared help-request suite, as rmt_app (RLS-bound), plus the proofs only
// Postgres can give: composite foreign keys, RLS, the one-open-per-machine index under raced inserts, and
// the sweep's SECURITY DEFINER tenant finder. Like every pgx test these SKIP without TEST_DATABASE_URL
// (scripts/verify-all.ps1 sets it and treats a skip as a failure).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type helpPg struct {
	su, app *pgxpool.Pool
	seq     atomic.Int64
	audit   *PgMgmtAuditStore
}

func newHelpPg(t *testing.T) *helpPg {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyAttendedMigration(t, su) // machine.ephemeral
	applyMigrationFile(t, su, "migrations/0069_help_request.sql")
	h := &helpPg{su: su}
	h.app = newAppRolePool(t, ctx)
	h.audit = NewPgMgmtAuditStore(h.app)
	return h
}

func (h *helpPg) env(t *testing.T) *helpEnv {
	t.Helper()
	ctx := context.Background()
	return &helpEnv{
		store:    NewPgHelpRequestStore(h.app, h.audit),
		sessions: NewPgSessionRecordStore(h.app),
		audit:    h.audit,
		machines: NewPgMachineStore(h.app),
		binder:   NewPgBinder(h.app),
		newTenant: func(t *testing.T) (string, string) {
			n := h.seq.Add(1)
			return provisionUser(t, h.su, fmt.Sprintf("help%d", n), fmt.Sprintf("tech%d@help.test", n), "password-1234")
		},
		newTech: func(t *testing.T, tenant string) string {
			n := h.seq.Add(1)
			var id string
			if err := h.su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
				t.Fatal(err)
			}
			mustExec(t, h.su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, $3)`,
				id, tenant, fmt.Sprintf("extra%d@help.test", n))
			return id
		},
		newGroup: func(t *testing.T, tenant string) string {
			var id string
			if err := h.su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
				t.Fatal(err)
			}
			mustExec(t, h.su, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1, $2, $3)`,
				id, tenant, "G"+id[:8])
			return id
		},
		newMachine: func(t *testing.T, tenant, group string) (string, string) {
			dev := newUUID()
			mid := seedNamedMachine(t, h.su, tenant, group, dev, "host-"+dev[:6])
			key, err := hex.DecodeString(testPubkeyHex(t))
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, h.su, `UPDATE machine SET pubkey = $3 WHERE tenant_id = $1 AND id = $2`, tenant, mid, key)
			return dev, mid
		},
		setStatus: func(t *testing.T, tenant, machineID, status string) {
			mustExec(t, h.su, `UPDATE machine SET status = $3 WHERE tenant_id = $1 AND id = $2`, tenant, machineID, status)
		},
		moveMachine: func(t *testing.T, tenant, machineID, group string) {
			mustExec(t, h.su, `UPDATE machine SET group_id = $3 WHERE tenant_id = $1 AND id = $2`, tenant, machineID, group)
		},
	}
}

// The whole shared contract, against Postgres as rmt_app.
func TestPgHelpStoreContract(t *testing.T) {
	h := newHelpPg(t)
	runHelpStoreSuite(t, func(t *testing.T) *helpEnv { return h.env(t) })
}

// Postgres-only: the migration's own guards.
func TestPgHelpRequestSchemaGuards(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, tech := e.newTenant(t)
	other, otherTech := e.newTenant(t)
	g := e.newGroup(t, tenant)
	og := e.newGroup(t, other)
	dev, mid := e.newMachine(t, tenant, g)
	_, omid := e.newMachine(t, other, og)

	insert := func(tenantID, machine, status string, _ string) error {
		_, err := h.su.Exec(ctx, `INSERT INTO help_request (tenant_id, machine_id, device_id, status, expires_at)
			VALUES ($1, $2, 'd', $3, now() + interval '30 minutes')`, tenantID, machine, status)
		return err
	}
	// composite FK: another tenant's machine cannot be named, even by the superuser (FKs bypass RLS).
	if err := insert(tenant, omid, "open", ""); err == nil {
		t.Fatal("a help_request naming another tenant's machine was accepted")
	}
	// one OPEN request per machine (partial unique index), under the superuser too.
	if err := insert(tenant, mid, "open", ""); err != nil {
		t.Fatal(err)
	}
	if err := insert(tenant, mid, "open", ""); err == nil {
		t.Fatal("two open requests for one machine were accepted")
	}
	// state shape: an accepted row must carry its session and technician; an open row must not be closed.
	if err := insert(tenant, mid, "accepted", ""); err == nil {
		t.Fatal("an accepted request without a session was accepted")
	}
	// the note cap is a database fact too
	if _, err := h.su.Exec(ctx, `UPDATE help_request SET note = $2 WHERE tenant_id = $1`, tenant, strings.Repeat("n", 201)); err == nil {
		t.Fatal("a 201-char note was accepted")
	}
	// FK to the accepting user and session are tenant-qualified
	var sess string
	if err := h.su.QueryRow(ctx, `INSERT INTO session_record (tenant_id, machine_id, technician_id, consent_policy, granted_caps)
		VALUES ($1, $2, $3, 'unattended', '{}') RETURNING id::text`, other, omid, otherTech).Scan(&sess); err != nil {
		t.Fatal(err)
	}
	if _, err := h.su.Exec(ctx, `UPDATE help_request SET status = 'accepted', closed_at = now(), accepted_by = $2, session_id = $3
		WHERE tenant_id = $1`, tenant, tech, sess); err == nil {
		t.Fatal("a request bound to another tenant's session was accepted")
	}
	if _, err := h.su.Exec(ctx, `UPDATE help_request SET status = 'accepted', closed_at = now(), accepted_by = $2, session_id = $3
		WHERE tenant_id = $1`, tenant, otherTech, sess); err == nil {
		t.Fatal("a request accepted by another tenant's user was accepted")
	}
	_ = dev

	// RLS: as rmt_app a tenant sees only its own rows, and cannot write into another tenant's.
	var n int
	if err := withTenant(ctx, h.app, other, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM help_request`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("tenant %s sees %d rows of another tenant (%v)", other, n, err)
	}
	if err := withTenant(ctx, h.app, other, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO help_request (tenant_id, machine_id, device_id, status, expires_at)
			VALUES ($1, $2, 'd', 'open', now() + interval '1 minute')`, tenant, mid)
		return err
	}); err == nil {
		t.Fatal("RLS WITH CHECK let one tenant insert into another")
	}
}

// Raced creations for ONE machine collapse to one open request, and raced creations across the tenant never
// exceed the open cap (the per-tenant lock + the partial index).
func TestPgHelpCreateRacesStaySerial(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, _ := e.newTenant(t)
	g := e.newGroup(t, tenant)
	dev, _ := e.newMachine(t, tenant, g)
	const n = 10
	ids := make([]string, n)
	created := int32(0)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r, err := e.store.CreateForDevice(ctx, tenant, dev, fmt.Sprintf("race-%d", i), "x", helpT0)
			if err != nil {
				t.Errorf("create %d: %v", i, err)
				return
			}
			ids[i] = r.Request.ID
			if r.Created {
				atomic.AddInt32(&created, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if created != 1 {
		t.Fatalf("%d concurrent creates inserted, want exactly 1", created)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("concurrent creates returned different requests: %v", ids)
		}
	}
	var open int
	if err := h.su.QueryRow(ctx, `SELECT count(*) FROM help_request WHERE tenant_id = $1 AND status = 'open'`, tenant).Scan(&open); err != nil || open != 1 {
		t.Fatalf("open rows = %d (%v)", open, err)
	}
}

// The sweep finds work across tenants through cp_help_request_due_tenants, and only those tenants.
func TestPgHelpSweepFindsOnlyTenantsWithWork(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	busy, _ := e.newTenant(t)
	idle, _ := e.newTenant(t)
	bd, _ := e.newMachine(t, busy, e.newGroup(t, busy))
	id, _ := e.newMachine(t, idle, e.newGroup(t, idle))
	mustCreate(t, e, busy, bd, "op", helpT0)
	rIdle := mustCreate(t, e, idle, id, "op", helpT0.Add(time.Hour)).Request // not due at the sweep instant
	sw, err := e.store.Sweep(ctx, helpT0.Add(35*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if sw.Tenants != 1 || sw.Expired != 1 || sw.Events[0].TenantID != busy {
		t.Fatalf("sweep = %+v", sw)
	}
	if got, _, _ := e.store.Get(ctx, idle, rIdle.ID, helpT0.Add(35*time.Minute)); got == nil || got.Status != HelpStatusOpen {
		t.Fatalf("the idle tenant's request was disturbed: %+v", got)
	}
}

// holdHelpTenantLock holds the per-tenant creation advisory lock in a transaction of its own until the
// returned release is called.
func holdHelpTenantLock(t *testing.T, h *helpPg, tenant string) (release func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('help_request:' || $1, 0))`, canonicalUUIDish(tenant)); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = tx.Rollback(ctx) }) }
	t.Cleanup(release)
	return release
}

// Review finding 1: replays and already-open returns never take the tenant lock and write no op row; only a
// call that must INSERT waits for it (and reports busy when it times out).
func TestPgHelpCreateTakesTheTenantLockOnlyToInsert(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, _ := e.newTenant(t)
	g := e.newGroup(t, tenant)
	dev, _ := e.newMachine(t, tenant, g)
	idle, _ := e.newMachine(t, tenant, g)
	first := mustCreate(t, e, tenant, dev, "op-1", helpT0).Request
	old := helpLockWait
	helpLockWait = 300 * time.Millisecond
	defer func() { helpLockWait = old }()

	release := holdHelpTenantLock(t, h, tenant)
	defer release()
	// already-open (fresh op) and op replay: answered while the lock is held
	for _, op := range []string{"op-1", "fresh-1", "fresh-2", "fresh-3"} {
		start := time.Now()
		r, err := e.store.CreateForDevice(ctx, tenant, dev, op, "", helpT0.Add(time.Minute))
		if err != nil || r.Created || r.Request.ID != first.ID {
			t.Fatalf("%s under a held tenant lock = %+v %v", op, r, err)
		}
		if time.Since(start) >= helpLockWait {
			t.Fatalf("%s waited for the tenant lock", op)
		}
	}
	// a call that has to INSERT does wait, and times out as busy
	_, err := e.store.CreateForDevice(ctx, tenant, idle, "op-idle", "", helpT0.Add(time.Minute))
	var le *HelpLimitError
	if !errors.As(err, &le) || le.Scope != "busy" {
		t.Fatalf("an inserting call under a held lock: err = %v, want busy", err)
	}
	release()
	var ops int
	if err := h.su.QueryRow(ctx, `SELECT count(*) FROM help_request_op WHERE tenant_id = $1`, tenant).Scan(&ops); err != nil || ops != 1 {
		t.Fatalf("op rows = %d (%v), want 1: already-open returns must not insert op rows", ops, err)
	}
}

// Review r1 #5 + r2 #2: the compensating reopen serializes with creation (it takes the tenant lock, because it
// ADDS an open request), so a creation holding the lock must not strand the request 'accepted': the reopen
// waits longer than a creation does and retries, bounded.
func TestPgHelpReopenWaitsOutAHeldTenantLockAndRetries(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, tech := e.newTenant(t)
	g := e.newGroup(t, tenant)
	dev, mid := e.newMachine(t, tenant, g)
	r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
	acc, err := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
	if err != nil || acc.Outcome != HelpAcceptAccepted {
		t.Fatal(acc, err)
	}
	oldWait, oldN := helpReopenLockWait, helpReopenAttempts
	helpReopenLockWait, helpReopenAttempts = 250*time.Millisecond, 6
	defer func() { helpReopenLockWait, helpReopenAttempts = oldWait, oldN }()
	release := holdHelpTenantLock(t, h, tenant)
	defer release()
	go func() { time.Sleep(700 * time.Millisecond); release() }() // longer than ONE attempt's wait
	start := time.Now()
	re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
	if d := time.Since(start); d < 600*time.Millisecond {
		t.Fatalf("the reopen finished after %v while the tenant lock was held: it does not serialize with creation", d)
	}
	if err != nil || !re.Changed || re.Request.Status != HelpStatusOpen {
		t.Fatalf("reopen across a held tenant lock = %+v %v (a lock timeout would strand the request accepted)", re, err)
	}
}

// A lock that never frees is reported (bounded attempts), not waited on forever.
func TestPgHelpReopenGivesUpBoundedlyWhenTheLockNeverFrees(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, tech := e.newTenant(t)
	g := e.newGroup(t, tenant)
	dev, mid := e.newMachine(t, tenant, g)
	r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
	acc, _ := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
	oldWait, oldN := helpReopenLockWait, helpReopenAttempts
	helpReopenLockWait, helpReopenAttempts = 100*time.Millisecond, 2
	defer func() { helpReopenLockWait, helpReopenAttempts = oldWait, oldN }()
	release := holdHelpTenantLock(t, h, tenant)
	defer release()
	start := time.Now()
	_, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(2*time.Minute))
	var le *HelpLimitError
	if !errors.As(err, &le) || le.Scope != "busy" {
		t.Fatalf("err = %v, want busy", err)
	}
	if d := time.Since(start); d < 180*time.Millisecond || d > 3*time.Second {
		t.Fatalf("gave up after %v, want about 2 x 100ms", d)
	}
}

// The superseded branch is decided by the one-open-per-machine index, including when the newer open request
// is inserted while the reopen is in flight (no lock orders them).
func TestPgHelpReopenSupersededByTheIndex(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, tech := e.newTenant(t)
	g := e.newGroup(t, tenant)
	dev, mid := e.newMachine(t, tenant, g)
	r := mustCreate(t, e, tenant, dev, "op", helpT0).Request
	acc, _ := e.store.Accept(ctx, tenant, acceptInput(t, r.ID, tech, mid, g, "k", helpT0.Add(time.Minute)))
	// a newer open request exists (inserted directly: the shared suite covers the store-made path)
	mustExec(t, h.su, `INSERT INTO help_request (tenant_id, machine_id, device_id, status, created_at, expires_at)
		VALUES ($1, $2, $3, 'open', $4, $5)`, tenant, mid, dev, helpT0.Add(2*time.Minute), helpT0.Add(32*time.Minute))
	re, err := e.store.ReopenAfterFailedStart(ctx, tenant, r.ID, acc.Record.ID, helpT0.Add(3*time.Minute))
	if err != nil || !re.Changed || re.Request.Status != HelpStatusCancelled || re.Request.CancelReason != HelpCancelSuperseded {
		t.Fatalf("reopen against a newer open request = %+v %v", re, err)
	}
	var open int
	if err := h.su.QueryRow(ctx, `SELECT count(*) FROM help_request WHERE tenant_id = $1 AND status = 'open'`, tenant).Scan(&open); err != nil || open != 1 {
		t.Fatalf("open rows = %d (%v)", open, err)
	}
}

// Review r2 #1: ONE lock order. A creation must not hold request-row locks (taken by the lazy expiry) while it
// waits for the tenant help lock, because Sweep takes the tenant lock FIRST and then those rows: a cycle.
// With the tenant lock held elsewhere, a creation that has due rows to expire must be waiting WITHOUT having
// locked them.
func TestPgHelpCreateWaitsForTheTenantLockBeforeLockingRows(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, _ := e.newTenant(t)
	g := e.newGroup(t, tenant)
	d1, _ := e.newMachine(t, tenant, g)
	d2, _ := e.newMachine(t, tenant, g)
	mustCreate(t, e, tenant, d1, "op", helpT0) // due at helpT0+31m
	old := helpLockWait
	helpLockWait = 10 * time.Second
	defer func() { helpLockWait = old }()
	release := holdHelpTenantLock(t, h, tenant)
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := e.store.CreateForDevice(ctx, tenant, d2, "op2", "", helpT0.Add(31*time.Minute))
		done <- err
	}()
	time.Sleep(500 * time.Millisecond) // the creation is now blocked on the tenant lock
	tx, err := h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, lockErr := tx.Exec(ctx, `SELECT id FROM help_request WHERE tenant_id = $1 AND status = 'open' FOR UPDATE NOWAIT`, tenant)
	_ = tx.Rollback(ctx)
	if lockErr != nil {
		t.Fatalf("the waiting creation already holds the due request's row lock (%v): it takes row locks before the tenant lock, the order Sweep reverses", lockErr)
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("creation never finished after the lock was released")
	}
}

// ...and the same interleaving raced for real: creations that expire due rows against sweeps never deadlock.
func TestPgHelpCreateAndSweepDoNotDeadlock(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, _ := e.newTenant(t)
	g := e.newGroup(t, tenant)
	for round := 0; round < 15; round++ {
		base := helpT0.Add(time.Duration(round) * 3 * time.Hour)
		for i := 0; i < 4; i++ {
			d, _ := e.newMachine(t, tenant, g)
			mustCreate(t, e, tenant, d, "op", base)
		}
		fresh, _ := e.newMachine(t, tenant, g)
		at := base.Add(31 * time.Minute)
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.store.CreateForDevice(ctx, tenant, fresh, "op", "", at)
			errs <- err
		}()
		go func() { defer wg.Done(); <-start; _, err := e.store.Sweep(ctx, at); errs <- err }()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
}

// Review r2 #3: the op ledger is read again AFTER the tenant lock; a concurrent call with the same op_id that
// committed while this one waited is replayed, never duplicated or overwritten.
func TestPgHelpSameOpIDRacingCallsReplayNotOverwrite(t *testing.T) {
	h := newHelpPg(t)
	e := h.env(t)
	ctx := context.Background()
	tenant, _ := e.newTenant(t)
	dev, mid := e.newMachine(t, tenant, e.newGroup(t, tenant))
	old := helpLockWait
	helpLockWait = 10 * time.Second
	defer func() { helpLockWait = old }()
	// The "first call": holds the tenant lock, and commits request R1 (already closed again) plus its op row.
	tx, err := h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('help_request:' || $1, 0))`, canonicalUUIDish(tenant)); err != nil {
		t.Fatal(err)
	}
	type result struct {
		r   *HelpCreateResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := e.store.CreateForDevice(ctx, tenant, dev, "op-x", "", helpT0.Add(time.Minute))
		done <- result{r, err}
	}()
	time.Sleep(500 * time.Millisecond) // the second call has missed the ledger and waits for the lock
	var r1 string
	if err := tx.QueryRow(ctx, `INSERT INTO help_request (tenant_id, machine_id, device_id, status, created_at, expires_at, closed_at, cancel_reason)
		VALUES ($1, $2, $3, 'cancelled', $4, $5, $4, 'guest') RETURNING id::text`,
		tenant, mid, dev, helpT0, helpT0.Add(30*time.Minute)).Scan(&r1); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO help_request_op (tenant_id, device_id, op_id, request_id, created_at) VALUES ($1, $2, 'op-x', $3, $4)`,
		tenant, dev, r1, helpT0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.r.Created || !res.r.Replayed || res.r.Request.ID != r1 {
		t.Fatalf("the second same-op call = %+v (created=%v), want the first call's request %s replayed", res.r.Request, res.r.Created, r1)
	}
	var mapped string
	if err := h.su.QueryRow(ctx, `SELECT request_id::text FROM help_request_op WHERE tenant_id = $1 AND device_id = $2 AND op_id = 'op-x'`, tenant, dev).Scan(&mapped); err != nil || mapped != r1 {
		t.Fatalf("op mapping = %s (%v), want it kept at %s", mapped, err, r1)
	}
}
