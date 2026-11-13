package controlplane

// DB-gated proof for the session-ticket redemption ledger (migrations/0023).
//
// WHAT THIS FILE CARRIES THAT ticketredemption_test.go CANNOT. Those tests run against
// InMemoryTicketRedemptionStore, so they pin the HANDLER: status codes, the service-token gate, the
// metering exception. They would stay green if the SQL let the same (tenant, session) be recorded
// twice, if two concurrent redemptions both won, or if the table were readable across tenants —
// because the fake decides all of that in Go, under one mutex, in one process. Only a real database
// can pin those, and the RLS half only as the LEAST-PRIVILEGE `rmt_app` role, the role Row-Level
// Security is actually enforced against (see the note at the top of 0005_app_role.sql).
//
// The ATOMICITY test is the load-bearing one. A SELECT-then-INSERT would pass every single-threaded
// test in this file and still be wrong: under READ COMMITTED the SELECT cannot see a concurrent
// UNCOMMITTED insert, so two replicas racing the same ticket would both read "unused". That trap
// has bitten this codebase before (0020's uq_user_credential_token_one_live), which is why the
// function is ONE statement and why this test drives N goroutines at it.
//
// Like every pgx test these need TEST_DATABASE_URL; scripts/verify-all.ps1 sets it and treats a
// skip as a failure.

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyTicketRedemptionMigration lays 0023 (session_ticket_redemption + cp_session_ticket_redeem)
// on top of the schema newTestPool applied. resetSchema DROPs both, so this is re-runnable.
func applyTicketRedemptionMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0023_session_ticket_redemption.sql")
	if err != nil {
		t.Fatalf("read 0023: %v", err)
	}
	execScript(t, pool, string(b))
	// 0061 redefines the function to also stamp session_record.redeemed_at (docs/51). Applied here so every
	// ledger test exercises the function production runs, not the 0023 original it replaces.
	b, err = os.ReadFile("migrations/0061_ticket_redeem_marks_session.sql")
	if err != nil {
		t.Fatalf("read 0061: %v", err)
	}
	execScript(t, pool, string(b))
}

// seedRedemptionTenant inserts a bare tenant row (the ledger's only foreign key) and returns its id.
func seedRedemptionTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	ctx := context.Background()
	var tid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&tid); err != nil {
		t.Fatalf("gen tenant uuid: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$2,'self_hosted')`,
			tid, slug)
		return err
	}); err != nil {
		t.Fatalf("seed tenant %s: %v", slug, err)
	}
	return tid
}

// newSessionID mints a uuid for a ticket's session_id claim.
func newSessionID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
		t.Fatalf("gen session uuid: %v", err)
	}
	return id
}

// The ledger over real SQL: first use records the row, the replay is refused, and the refusal is
// PER (tenant, session) rather than per session id alone.
func TestPgTicketRedemptionSingleUse(t *testing.T) {
	pool := newTestPool(t) // skips without TEST_DATABASE_URL
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenantA := seedRedemptionTenant(t, pool, "redeem-a")
	tenantB := seedRedemptionTenant(t, pool, "redeem-b")
	session := newSessionID(t, pool)
	device := "device-" + session
	exp := time.Now().Add(2 * time.Minute)

	store := NewPgTicketRedemptionStore(pool)

	rec, err := store.RedeemTicket(ctx, tenantA, session, device, exp)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if rec.TenantID != tenantA || rec.SessionID != session || rec.DeviceID != device {
		t.Fatalf("recorded row = %+v, want tenant %s session %s device %s", rec, tenantA, session, device)
	}
	if rec.RedeemedAt.IsZero() || !rec.ExpiresAt.Equal(exp.UTC().Truncate(time.Microsecond)) {
		// timestamptz has microsecond resolution; the Go value is truncated on the way in.
		t.Fatalf("recorded times = redeemed %s / expires %s, want expires %s",
			rec.RedeemedAt, rec.ExpiresAt, exp)
	}

	if _, err := store.RedeemTicket(ctx, tenantA, session, device, exp); err != ErrTicketAlreadyRedeemed {
		t.Fatalf("replay = %v, want ErrTicketAlreadyRedeemed", err)
	}
	// The SAME session id in another tenant is a different ticket — the key is composite.
	if _, err := store.RedeemTicket(ctx, tenantB, session, device, exp); err != nil {
		t.Fatalf("same session id in another tenant: %v", err)
	}
}

// A SECOND STORE INSTANCE — a second control-plane process over the same database — sees the same
// ledger. This is the property the whole change exists for: single use survives the boundary that a
// per-process map cannot cross.
func TestPgTicketRedemptionIsSharedAcrossProcesses(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenant := seedRedemptionTenant(t, pool, "redeem-shared")
	session := newSessionID(t, pool)
	exp := time.Now().Add(2 * time.Minute)

	if _, err := NewPgTicketRedemptionStore(pool).RedeemTicket(ctx, tenant, session, "dev-1", exp); err != nil {
		t.Fatalf("instance 1 first use: %v", err)
	}
	// A distinct store value over a distinct pool: no shared Go state whatsoever.
	second, err := pgxpool.New(ctx, testDBURL())
	if err != nil {
		t.Fatalf("second pool: %v", err)
	}
	t.Cleanup(second.Close)
	if _, err := NewPgTicketRedemptionStore(second).RedeemTicket(ctx, tenant, session, "dev-1", exp); err != ErrTicketAlreadyRedeemed {
		t.Fatalf("instance 2 replay = %v, want ErrTicketAlreadyRedeemed", err)
	}
}

// ATOMICITY, DETERMINISTICALLY — the test that actually pins the READ COMMITTED trap.
//
// The load test below does NOT pin it. Measured: replacing the single INSERT ... ON CONFLICT with
// an EXISTS-then-INSERT left it green, because sixteen goroutines over a connection pool never
// actually interleave inside the window — each redemption commits before the next one looks. A
// green race test that never raced is exactly the kind of false comfort this repo has been burned
// by, so the window is constructed by hand here instead of hoped for.
//
// The construction: transaction A redeems the ticket and is HELD OPEN. B then redeems the same
// ticket on another connection, in the regime that matters — A's row exists but is UNCOMMITTED, so
// no SELECT B could issue can see it. B blocks on the key. When A commits:
//
//   - the atomic version returns NO ROW to B, i.e. a clean "already redeemed";
//   - an EXISTS-then-INSERT gives B a duplicate-key ERROR, which the store reports as "the ledger
//     could not answer" — and the broker then FAILS OPEN and brokers the replay;
//   - an ON CONFLICT DO UPDATE hands B a row, i.e. a second winner outright.
//
// Only the first is a correct answer, and the assertion is on WHICH error, never merely on "an
// error happened".
func TestPgTicketRedemptionRedeemIsAtomicAgainstAnUncommittedPeer(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenant := seedRedemptionTenant(t, pool, "redeem-interleave")
	session := newSessionID(t, pool)
	exp := time.Now().Add(2 * time.Minute)

	// A: redeem inside an EXPLICIT transaction, and hold it open.
	connA, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer connA.Release()
	txA, err := connA.Begin(ctx)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	defer func() { _ = txA.Rollback(ctx) }() // no-op after a successful commit
	var gotA string
	if err := txA.QueryRow(ctx,
		`SELECT session_id::text FROM cp_session_ticket_redeem($1, $2, $3, $4)`,
		tenant, session, "dev-a", exp).Scan(&gotA); err != nil {
		t.Fatalf("A's redemption: %v", err)
	}

	// B: the same ticket, another connection, while A is still uncommitted.
	errB := make(chan error, 1)
	go func() {
		_, err := NewPgTicketRedemptionStore(pool).RedeemTicket(ctx, tenant, session, "dev-b", exp)
		errB <- err
	}()

	// B MUST be blocked here. If it has already returned, the interleaving this test is built on did
	// not happen and nothing below would mean anything — so that is a failure, not a pass.
	select {
	case err := <-errB:
		t.Fatalf("B returned (%v) while A's redemption was still uncommitted; the two never "+
			"overlapped, so this test proved nothing about atomicity", err)
	case <-time.After(750 * time.Millisecond):
	}

	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	select {
	case err := <-errB:
		if err != ErrTicketAlreadyRedeemed {
			t.Fatalf("B = %v, want ErrTicketAlreadyRedeemed. nil means two redeemers both won; any "+
				"other error means the ledger answered 'cannot say', which makes the broker fail OPEN "+
				"and broker the replay", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("B never returned after A committed")
	}

	// Exactly one row, and it is A's.
	var device string
	if err := pool.QueryRow(ctx,
		`SELECT device_id FROM session_ticket_redemption WHERE tenant_id = $1 AND session_id = $2`,
		tenant, session).Scan(&device); err != nil {
		t.Fatalf("read back the ledger row: %v", err)
	}
	if device != "dev-a" {
		t.Fatalf("ledger row device = %q, want dev-a (the winner's)", device)
	}
}

// The same property under load: sixteen goroutines redeem the SAME ticket at once, each on its own
// pooled connection, and exactly one may win.
//
// Kept as a smoke test, and deliberately NOT relied on for atomicity: measured, it stays green
// against an EXISTS-then-INSERT (see the test above for why, and for the version that does catch
// it). What it does cover is that the ordinary path returns a clean verdict — never an error — when
// many redeemers arrive at once.
func TestPgTicketRedemptionConcurrentRedeemersElectOneWinner(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenant := seedRedemptionTenant(t, pool, "redeem-race")
	session := newSessionID(t, pool)
	exp := time.Now().Add(2 * time.Minute)
	store := NewPgTicketRedemptionStore(pool)

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wins    int
		replays int
		other   []error
		start   = make(chan struct{})
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.RedeemTicket(ctx, tenant, session, "dev-race", exp)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case err == ErrTicketAlreadyRedeemed:
				replays++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected errors from concurrent redeemers: %v", other)
	}
	if wins != 1 || replays != racers-1 {
		t.Fatalf("concurrent redemption elected %d winners and %d replays, want exactly 1 and %d",
			wins, replays, racers-1)
	}
	// And the table holds exactly one row for the ticket.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM session_ticket_redemption WHERE tenant_id = $1 AND session_id = $2`,
		tenant, session).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("ledger holds %d rows for the ticket, want 1", n)
	}
}

// RLS, as the role it is actually enforced against. The redemption path itself runs SECURITY
// DEFINER and bypasses the policy by design (it is pre-tenant — the signaling server holds no
// tenant principal), so this pins the OTHER direction: anything reading the table through the
// binder is confined to the pinned tenant, and reading with NO tenant pinned is a loud error rather
// than a silent empty set (the 0022 lesson).
func TestPgTicketRedemptionRLSConfinesReaders(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyTicketRedemptionMigration(t, suPool)
	ctx := context.Background()

	tenantA := seedRedemptionTenant(t, suPool, "rls-redeem-a")
	tenantB := seedRedemptionTenant(t, suPool, "rls-redeem-b")
	sessionA := newSessionID(t, suPool)
	sessionB := newSessionID(t, suPool)
	exp := time.Now().Add(2 * time.Minute)

	store := NewPgTicketRedemptionStore(suPool)
	if _, err := store.RedeemTicket(ctx, tenantA, sessionA, "dev-a", exp); err != nil {
		t.Fatalf("seed redemption A: %v", err)
	}
	if _, err := store.RedeemTicket(ctx, tenantB, sessionB, "dev-b", exp); err != nil {
		t.Fatalf("seed redemption B: %v", err)
	}

	appPool := newAppRolePool(t, ctx)

	// Sanity: FORCE + ENABLE are really set, matching every other tenant-scoped table.
	var enabled, forced bool
	if err := suPool.QueryRow(ctx,
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'session_ticket_redemption'`).
		Scan(&enabled, &forced); err != nil {
		t.Fatalf("introspect RLS flags: %v", err)
	}
	if !enabled || !forced {
		t.Fatalf("session_ticket_redemption RLS: enabled=%v forced=%v, want both true", enabled, forced)
	}

	// Pinned to A: A's row is visible, B's is not — even named explicitly.
	if err := withTenant(ctx, appPool, tenantA, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM session_ticket_redemption`).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Fatalf("rmt_app pinned to tenant A sees %d rows, want 1", n)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM session_ticket_redemption WHERE session_id = $1`, sessionB).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("rmt_app pinned to tenant A sees tenant B's redemption (%d rows)", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("pinned read: %v", err)
	}

	// With NO tenant pinned the read ERRORS (unrecognized configuration parameter) rather than
	// quietly returning nothing. A request that reached the database without going through the
	// binder is a bug, and on every other table that bug is loud — see 0022.
	var n int
	err := appPool.QueryRow(ctx, `SELECT count(*) FROM session_ticket_redemption`).Scan(&n)
	if err == nil {
		t.Fatalf("unpinned read returned %d rows; it must ERROR like every other tenant-scoped table", n)
	}
}

// The reap keeps the ledger from growing without bound (this deployment has no background job), and
// — the load-bearing half — it can never take a row a LIVE ticket would have conflicted with. The
// window is an hour past expiry; a ticket that could still verify has an expiry in the FUTURE.
func TestPgTicketRedemptionReapsOnlyLongDeadRows(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenant := seedRedemptionTenant(t, pool, "redeem-reap")
	store := NewPgTicketRedemptionStore(pool)

	longDead := newSessionID(t, pool) // expired well beyond the grace window
	justDead := newSessionID(t, pool) // expired, but inside the grace window
	live := newSessionID(t, pool)     // a normal, live ticket
	for _, seed := range []struct {
		session string
		expires time.Time
	}{
		{longDead, time.Now().Add(-2 * time.Hour)},
		{justDead, time.Now().Add(-time.Minute)},
		{live, time.Now().Add(2 * time.Minute)},
	} {
		if _, err := store.RedeemTicket(ctx, tenant, seed.session, "dev", seed.expires); err != nil {
			t.Fatalf("seed %s: %v", seed.session, err)
		}
	}

	// Any redemption runs the reap.
	if _, err := store.RedeemTicket(ctx, tenant, newSessionID(t, pool), "dev", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("triggering redemption: %v", err)
	}

	for name, tc := range map[string]struct {
		session string
		want    int
	}{
		"long dead row is reaped":      {longDead, 0},
		"recently expired row is kept": {justDead, 1},
		"live row is kept":             {live, 1},
	} {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM session_ticket_redemption WHERE tenant_id = $1 AND session_id = $2`,
			tenant, tc.session).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		if n != tc.want {
			t.Fatalf("%s: %d rows, want %d", name, n, tc.want)
		}
	}

	// The reaped ticket is redeemable again — correctly so: it can no longer verify, so the ledger
	// entry protected nothing. The LIVE one is still refused, which is the property that matters.
	if _, err := store.RedeemTicket(ctx, tenant, live, "dev", time.Now().Add(2*time.Minute)); err != ErrTicketAlreadyRedeemed {
		t.Fatalf("replay of the live ticket = %v, want ErrTicketAlreadyRedeemed", err)
	}
}

// A tenant or session id that cannot name a uuid row is reported as an error, never as a
// redemption verdict — the caller must not read "the ledger could not answer" as "already
// redeemed", nor as a successful record.
func TestPgTicketRedemptionRejectsNonUUIDIdentifiers(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()

	tenant := seedRedemptionTenant(t, pool, "redeem-uuid")
	store := NewPgTicketRedemptionStore(pool)

	for name, tc := range map[string]struct{ tenantID, sessionID string }{
		"tenant not a uuid":  {"tenant-1", newSessionID(t, pool)},
		"session not a uuid": {tenant, "session-1"},
	} {
		_, err := store.RedeemTicket(ctx, tc.tenantID, tc.sessionID, "dev", time.Now().Add(time.Minute))
		if err == nil {
			t.Fatalf("%s: redemption succeeded, want an error", name)
		}
		if err == ErrTicketAlreadyRedeemed {
			t.Fatalf("%s: reported as a replay; an unanswerable lookup must not read as a verdict", name)
		}
	}
}

// The redemption function is SECURITY DEFINER, so its search_path is part of its security: pg_catalog
// first (built-ins cannot be shadowed by a same-named object in public) and pg_temp LAST (a temp object
// can never be resolved ahead of a real one). A rewrite of the function once dropped this along with the
// suspension guard (0061's first version, 2026-10-22); pin the exact settings so it cannot silently drift.
func TestPgTicketRedeemFunctionKeepsDefinerHardening(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)
	applyTicketRedemptionMigration(t, pool)
	ctx := context.Background()
	var config []string
	var definer bool
	var body string
	if err := pool.QueryRow(ctx, `SELECT proconfig, prosecdef, prosrc FROM pg_proc WHERE proname = 'cp_session_ticket_redeem'`).
		Scan(&config, &definer, &body); err != nil {
		t.Fatalf("read the function: %v", err)
	}
	if !definer {
		t.Fatal("cp_session_ticket_redeem must be SECURITY DEFINER")
	}
	if len(config) != 1 || config[0] != "search_path=pg_catalog, public, pg_temp" {
		t.Fatalf("proconfig = %q, want exactly [search_path=pg_catalog, public, pg_temp]", config)
	}
	// The two behaviours the platform suspension tests prove end to end (platform_pgstore_test.go, which
	// applies 0061 after 0055 as production does); named here so a reader of THIS file sees them.
	for _, must := range []string{"pg_advisory_xact_lock_shared", "disabled_at IS NULL"} {
		if !strings.Contains(body, must) {
			t.Fatalf("the function body lost %q", must)
		}
	}
}
