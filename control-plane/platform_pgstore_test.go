package controlplane

// Platform operator (migration 0054) against a live PostgreSQL with the least-privilege rmt_app role.
// Like every pgx test these SKIP without TEST_DATABASE_URL (verify-all treats a skip as a failure).

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type platformFixture struct {
	su, app            *pgxpool.Pool
	platform, customer string // tenant ids
	op, nonOp, custOwn string // user ids
	opSession          string
	opGen              int64
	store              *PgPlatformStore
	audit              *PgMgmtAuditStore
}

func applyMigrationFile(t *testing.T, pool *pgxpool.Pool, f string) {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read %s: %v", f, err)
	}
	execScript(t, pool, string(b))
}

func newPlatformFixture(t *testing.T) *platformFixture {
	t.Helper()
	ctx := context.Background()
	su := newTestPool(t) // resetSchema also drops the 0055 objects
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyMgmtAuditChainMigration(t, su)
	applyAttendedMigration(t, su)         // 0013: machine.ephemeral, used by cp_machine_identity_by_device_id
	applyTicketRedemptionMigration(t, su) // 0023: 0055 replaces cp_session_ticket_redeem
	// 0068 changed the identity function's return type, so the 0055 definition below needs a clean slate.
	execScript(t, su, `DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);`)
	applyMigrationFile(t, su, "migrations/0055_platform_operator.sql")
	applyLatestIdentityFunction(t, su) // production order: 0068 redefines the identity function AFTER 0055
	// PRODUCTION ORDER: 0061 redefines cp_session_ticket_redeem AFTER 0055. applyTicketRedemptionMigration
	// already applied it once, but 0055 then replaced it, so every suspension test here ran against 0055's
	// function and could not see a 0061 that dropped the suspension guard (which one did, 2026-10-22).
	applyMigrationFile(t, su, "migrations/0061_ticket_redeem_marks_session.sql")

	f := &platformFixture{su: su}
	f.platform, f.op = provisionUser(t, su, "main", "op@platform.test", "password-1234")
	f.customer, f.custOwn = provisionUser(t, su, "loam", "owner@loam.test", "password-1234")
	if err := su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&f.nonOp); err != nil {
		t.Fatal(err)
	}
	mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'other@platform.test')`, f.nonOp, f.platform)
	for _, u := range []struct{ id, tenant string }{{f.op, f.platform}, {f.nonOp, f.platform}, {f.custOwn, f.customer}} {
		mustExec(t, su, `INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at) VALUES ($1, $2, 'x', now())`, u.id, u.tenant)
		mustExec(t, su, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq') WHERE id = $1`, u.id)
	}
	if err := su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, f.op).Scan(&f.opGen); err != nil {
		t.Fatal(err)
	}
	f.opSession = newSession(t, su, f.platform, f.op, "now()", f.opGen)
	mustExec(t, su, `INSERT INTO platform_config (tenant_id, set_by) VALUES ($1, 'test')`, f.platform)
	mustExec(t, su, `INSERT INTO platform_operator (user_id, tenant_id, granted_by) VALUES ($1, $2, 'test')`, f.op, f.platform)

	f.app = newAppRolePool(t, ctx)
	f.audit = NewPgMgmtAuditStore(f.app)
	f.store = NewPgPlatformStore(f.app, f.audit)
	return f
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(sql)[0], err)
	}
}

// newSession inserts an interactive session whose MFA was verified at mfaAt (an SQL expression) for
// generation gen (0 = never verified).
func newSession(t *testing.T, pool *pgxpool.Pool, tenant, user, mfaAt string, gen int64) string {
	t.Helper()
	var id string
	q := `INSERT INTO user_session (tenant_id, user_id, token_hash, expires_at, mfa_verified_at, mfa_generation)
	      VALUES ($1, $2, gen_random_bytes(32), now() + interval '12 hours', ` + mfaAt + `, NULLIF($3, 0))
	      RETURNING id::text`
	if mfaAt == "" {
		q = strings.Replace(q, ", "+mfaAt+",", ", NULL,", 1)
	}
	if err := pool.QueryRow(context.Background(), q, tenant, user, gen).Scan(&id); err != nil {
		t.Fatalf("session: %v", err)
	}
	return id
}

func (f *platformFixture) caller(user, session string) PlatformCaller {
	return PlatformCaller{UserID: user, TenantID: f.platform, SessionID: session, Email: "op@platform.test"}
}

func verifyChain(t *testing.T, audit *PgMgmtAuditStore, tenant string) MgmtAuditVerifyResult {
	t.Helper()
	r, err := VerifyMgmtAuditChain(context.Background(), audit, tenant)
	if err != nil {
		t.Fatalf("verify %s: %v", tenant, err)
	}
	if !r.OK {
		t.Fatalf("chain of %s does not verify: %+v", tenant, r)
	}
	return r
}

func TestPgPlatformWhoamiAndList(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()

	w, err := f.store.Whoami(ctx, f.caller(f.op, f.opSession))
	if err != nil || !w.Operator || !w.MFAOK || !w.MFAFresh {
		t.Fatalf("operator whoami = %+v %v", w, err)
	}
	stale := newSession(t, f.su, f.platform, f.op, "now() - interval '20 minutes'", f.opGen)
	if w, _ := f.store.Whoami(ctx, f.caller(f.op, stale)); !w.Operator || !w.MFAOK || w.MFAFresh {
		t.Fatalf("20-min-old MFA: %+v, want operator, ok, not fresh", w)
	}
	old := newSession(t, f.su, f.platform, f.op, "now() - interval '13 hours'", f.opGen)
	if w, _ := f.store.Whoami(ctx, f.caller(f.op, old)); !w.Operator || w.MFAOK {
		t.Fatalf("13-h-old MFA: %+v, want operator but not ok", w)
	}
	nonOpSess := newSession(t, f.su, f.platform, f.nonOp, "now()", 1)
	if w, _ := f.store.Whoami(ctx, f.caller(f.nonOp, nonOpSess)); w.Operator {
		t.Fatalf("non-operator whoami = %+v", w)
	}

	list, err := f.store.ListTenants(ctx, f.caller(f.op, f.opSession))
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	for _, tn := range list {
		if tn.UserCount < 1 {
			t.Fatalf("user_count missing for %s", tn.Slug)
		}
	}
	// Reads accept MFA up to 12 h old.
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, stale)); err != nil {
		t.Fatalf("list with 20-min MFA: %v", err)
	}

	denied := map[string]PlatformCaller{
		"non-operator in platform tenant": f.caller(f.nonOp, nonOpSess),
		"MFA older than 12 h":             f.caller(f.op, old),
		"no session (API token)":          f.caller(f.op, ""),
		"session never MFA-verified":      f.caller(f.op, newSession(t, f.su, f.platform, f.op, "", 0)),
		"session of another user":         f.caller(f.op, nonOpSess),
		// A handler bug pairing an operator's session with another user's id must not pass.
		"operator session, other user id": f.caller(f.nonOp, f.opSession),
	}
	fromCustomer := f.caller(f.op, f.opSession)
	fromCustomer.TenantID = f.customer
	denied["operator request pinned to a customer tenant"] = fromCustomer
	for name, c := range denied {
		if _, err := f.store.ListTenants(ctx, c); !errors.Is(err, ErrPlatformDenied) {
			t.Errorf("%s: ListTenants err = %v, want ErrPlatformDenied", name, err)
		}
	}
}

func TestPgPlatformMFAGenerationChangeRevokesSessions(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	// A TOTP reset/re-enrollment assigns a NEW generation; sessions verified against the old one fail.
	mustExec(t, f.su, `UPDATE app_user SET mfa_generation = nextval('mfa_generation_seq') WHERE id = $1`, f.op)
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, f.opSession)); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("after generation change: %v, want denied", err)
	}
	// Removing the enrollment also denies, even for a session claiming the current generation.
	var gen int64
	_ = f.su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, f.op).Scan(&gen)
	fresh := newSession(t, f.su, f.platform, f.op, "now()", gen)
	mustExec(t, f.su, `UPDATE user_totp SET confirmed_at = NULL WHERE user_id = $1`, f.op)
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, fresh)); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("without a confirmed enrollment: %v, want denied", err)
	}
}

func TestPgPlatformGrantRevocationAndDisabledOperator(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	mustExec(t, f.su, `UPDATE app_user SET disabled_at = now() WHERE id = $1`, f.op)
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, f.opSession)); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("disabled operator: %v", err)
	}
	mustExec(t, f.su, `UPDATE app_user SET disabled_at = NULL WHERE id = $1`, f.op)
	mustExec(t, f.su, `DELETE FROM platform_operator WHERE user_id = $1`, f.op)
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, f.opSession)); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("revoked grant: %v", err)
	}
}

func TestPgPlatformCreateTenantAuditsBothChains(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	tn, err := f.store.CreateTenant(ctx, f.caller(f.op, f.opSession), "vc", "VCInnovations", "saas", "corr-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	verifyChain(t, f.audit, f.platform)
	if r := verifyChain(t, f.audit, tn.ID); r.CheckedEvents != 1 {
		t.Fatalf("new tenant chain events = %d, want 1", r.CheckedEvents)
	}
	if _, err := f.store.CreateTenant(ctx, f.caller(f.op, f.opSession), "vc", "dup", "saas", "corr-2"); !errors.Is(err, ErrTenantSlugTaken) {
		t.Fatalf("duplicate slug: %v", err)
	}
	stale := newSession(t, f.su, f.platform, f.op, "now() - interval '20 minutes'", f.opGen)
	if _, err := f.store.CreateTenant(ctx, f.caller(f.op, stale), "other", "Other", "saas", "corr-3"); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("create with 20-min-old MFA: %v, want denied (15-min rule)", err)
	}
	var n int
	_ = f.su.QueryRow(ctx, `SELECT count(*) FROM tenant WHERE slug = 'other'`).Scan(&n)
	if n != 0 {
		t.Fatal("a refused create left a tenant row")
	}
}

func TestPgPlatformSuspendResume(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	c := f.caller(f.op, f.opSession)
	tn, err := f.store.SetSuspended(ctx, c, f.customer, true, "unpaid", "corr-s")
	if err != nil || !tn.Disabled {
		t.Fatalf("suspend: %+v %v", tn, err)
	}
	verifyChain(t, f.audit, f.platform)
	verifyChain(t, f.audit, f.customer)
	var actions []string
	rows, _ := f.su.Query(ctx, `SELECT action FROM audit_event WHERE tenant_id = $1 ORDER BY seq`, f.customer)
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if len(actions) == 0 || actions[len(actions)-1] != "tenant.suspended_by_platform" {
		t.Fatalf("customer chain actions = %v", actions)
	}
	if tn, err := f.store.SetSuspended(ctx, c, f.customer, false, "paid", "corr-r"); err != nil || tn.Disabled {
		t.Fatalf("resume: %+v %v", tn, err)
	}
	for tenant, want := range map[string]string{f.customer: "tenant.resumed_by_platform", f.platform: "platform.tenant.resume"} {
		var last string
		_ = f.su.QueryRow(ctx, `SELECT action FROM audit_event WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenant).Scan(&last)
		if last != want {
			t.Fatalf("last action in %s = %q, want %q", tenant, last, want)
		}
	}
	if _, err := f.store.SetSuspended(ctx, c, f.platform, true, "x", "corr-p"); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("suspending the platform tenant: %v, want denied", err)
	}
	if _, err := f.store.SetSuspended(ctx, c, "11111111-2222-3333-4444-555555555555", true, "x", "corr-n"); !errors.Is(err, ErrPlatformNoTenant) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

// A failed append (here: the round-trip guard tripping on the target chain) rolls back the suspension
// AND the platform-chain event written earlier in the same transaction.
func TestPgPlatformSuspendRollsBackOnAuditFailure(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	var before int
	_ = f.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1`, f.platform).Scan(&before)
	f.audit.corrupt = func(e *MgmtAuditEvent) {
		if e.Action == "tenant.suspended_by_platform" {
			e.Action += "-normalized"
		}
	}
	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "corr"); err == nil {
		t.Fatal("suspend succeeded although the target-chain append failed")
	}
	var disabled bool
	var after int
	_ = f.su.QueryRow(ctx, `SELECT disabled_at IS NOT NULL FROM tenant WHERE id = $1`, f.customer).Scan(&disabled)
	_ = f.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1`, f.platform).Scan(&after)
	if disabled || after != before {
		t.Fatalf("not rolled back: disabled=%v platform events %d -> %d", disabled, before, after)
	}
}

// Concurrent suspend/resume and ordinary audit appends on the same chains: no deadlock, every chain
// verifies.
func TestPgPlatformConcurrentSuspendAndAppends(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	c := f.caller(f.op, f.opSession)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if _, err := f.store.SetSuspended(ctx, c, f.customer, i%2 == 0, "load", "corr"); err != nil {
				errs <- err
			}
		}(i)
		go func() {
			defer wg.Done()
			if err := f.audit.RecordEvent(ctx, f.customer, &MgmtAuditEvent{Action: "load.event"}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent op failed: %v", err)
	}
	verifyChain(t, f.audit, f.platform)
	verifyChain(t, f.audit, f.customer)
}

// rmt_app reaches the platform tables and the old tenant-creation function only through the
// definers; the suspended tenant's agents are refused at identity resolution.
func TestPgPlatformAppRoleBoundariesAndAgentRefusal(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	for _, q := range []string{
		`SELECT count(*) FROM platform_config`,
		`SELECT count(*) FROM platform_operator`,
		`INSERT INTO platform_operator (user_id, tenant_id, granted_by) VALUES (gen_random_uuid(), gen_random_uuid(), 'x')`,
		`SELECT cp_create_tenant('evil', 'Evil', 'saas')`,
		`SELECT cp_platform_check(gen_random_uuid(), gen_random_uuid(), interval '1 hour')`,
	} {
		if _, err := f.app.Exec(ctx, q); err == nil {
			t.Errorf("rmt_app could run: %s", q)
		}
	}
	var dev string
	mid := ""
	if err := withTenant(ctx, f.su, f.customer, func(tx pgx.Tx) error {
		var gid string
		if err := tx.QueryRow(ctx, `INSERT INTO machine_group (tenant_id, name) VALUES ($1, 'g') RETURNING id::text`, f.customer).Scan(&gid); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO machine (tenant_id, group_id, device_id, hostname, pubkey)
			VALUES ($1, $2, 'dev-1', 'h', '\x01'::bytea) RETURNING id::text, device_id`, f.customer, gid).Scan(&mid, &dev)
	}); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	lookup := func() int {
		var n int
		_ = f.app.QueryRow(ctx, `SELECT count(*) FROM cp_machine_identity_by_device_id($1)`, dev).Scan(&n)
		return n
	}
	if lookup() != 1 {
		t.Fatal("active tenant's agent not resolved")
	}
	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "c"); err != nil {
		t.Fatal(err)
	}
	if lookup() != 0 {
		t.Fatal("suspended tenant's agent still resolves")
	}
}

// The migration's backfill gives existing CONFIRMED enrollments a generation (so their next login can
// be MFA-bound) and leaves unconfirmed ones at 0.
func TestPgPlatformMigrationBackfillsMFAGeneration(t *testing.T) {
	ctx := context.Background()
	su := newTestPool(t)
	applyAppRoleMigration(t, su)
	applyTenantProvisionMigration(t, su)
	applyAttendedMigration(t, su) // 0013 precedes 0054 everywhere (machine.ephemeral)
	tid, confirmed := provisionUser(t, su, "pre", "a@pre.test", "password-1234")
	var pending string
	_ = su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&pending)
	mustExec(t, su, `INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, 'b@pre.test')`, pending, tid)
	mustExec(t, su, `INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at) VALUES ($1, $2, 'x', now())`, confirmed, tid)
	mustExec(t, su, `INSERT INTO user_totp (user_id, tenant_id, secret) VALUES ($1, $2, 'x')`, pending, tid)
	// The core schema already ran 0054 before these users existed; re-running it (idempotent) is what
	// an upgrade does to rows that pre-date it.
	applyMigrationFile(t, su, "migrations/0054_mfa_generation.sql")
	var gc, gp int64
	_ = su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, confirmed).Scan(&gc)
	_ = su.QueryRow(ctx, `SELECT mfa_generation FROM app_user WHERE id = $1`, pending).Scan(&gp)
	if gc <= 0 || gp != 0 {
		t.Fatalf("backfill: confirmed=%d (want > 0), unconfirmed=%d (want 0)", gc, gp)
	}
}

// The CLI administration: each change is audited on the platform chain in the same transaction, and
// changing the platform tenant drops every grant.
func TestPgPlatformAdminGrantRevokeSetTenant(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	// Re-run set-tenant on the same tenant: no-op, the existing grant survives.
	if _, err := PlatformSetTenant(ctx, f.su, "main", "cli:test"); err != nil {
		t.Fatal(err)
	}
	if w, _ := f.store.Whoami(ctx, f.caller(f.op, f.opSession)); !w.Operator {
		t.Fatal("grant lost on a no-op set-tenant")
	}
	// Grant the second platform user; revoke the first.
	if err := PlatformGrant(ctx, f.su, "other@platform.test", "cli:test"); err != nil {
		t.Fatal(err)
	}
	if err := PlatformGrant(ctx, f.su, "owner@loam.test", "cli:test"); err == nil {
		t.Fatal("a customer-tenant user was granted platform rights")
	}
	if err := PlatformRevoke(ctx, f.su, "op@platform.test", "cli:test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ListTenants(ctx, f.caller(f.op, f.opSession)); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("revoked operator still lists: %v", err)
	}
	slug, rows, err := PlatformList(ctx, f.su)
	if err != nil || slug != "main" || len(rows) != 1 || rows[0].Email != "other@platform.test" {
		t.Fatalf("list = %q %+v %v", slug, rows, err)
	}
	// Moving the platform to another tenant revokes every grant.
	if _, err := PlatformSetTenant(ctx, f.su, "loam", "cli:test"); err != nil {
		t.Fatal(err)
	}
	if _, rows, _ := PlatformList(ctx, f.su); len(rows) != 0 {
		t.Fatalf("grants survived a platform-tenant change: %+v", rows)
	}
	verifyChain(t, f.audit, f.platform)
	verifyChain(t, f.audit, f.customer)
	var actions []string
	r, _ := f.su.Query(ctx, `SELECT action FROM audit_event WHERE action LIKE 'platform.%' ORDER BY occurred_at, seq`)
	for r.Next() {
		var a string
		_ = r.Scan(&a)
		actions = append(actions, a)
	}
	r.Close()
	want := []string{"platform.operator.grant", "platform.operator.revoke", "platform.config.set_tenant"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audited actions = %v, want %v", actions, want)
	}
}

// set-tenant and grant are serialized: whatever order the race resolves in, no grant survives that
// names a tenant other than the configured platform tenant.
func TestPgPlatformAdminSerializesSetTenantAndGrant(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		target := "loam"
		if i%2 == 1 {
			target = "main"
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = PlatformSetTenant(ctx, f.su, target, "cli:race") }()
		go func() { defer wg.Done(); _ = PlatformGrant(ctx, f.su, "other@platform.test", "cli:race") }()
		wg.Wait()
		var stray int
		if err := f.su.QueryRow(ctx, `
			SELECT count(*) FROM platform_operator o JOIN platform_config c ON c.singleton
			 WHERE o.tenant_id <> c.tenant_id`).Scan(&stray); err != nil {
			t.Fatal(err)
		}
		if stray != 0 {
			t.Fatalf("round %d: %d grant(s) name a tenant that is not the platform tenant", i, stray)
		}
	}
	verifyChain(t, f.audit, f.platform)
	verifyChain(t, f.audit, f.customer)
}

func TestPgEnsureOwnerBypassesRLS(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	if err := EnsureOwnerBypassesRLS(ctx, f.su); err != nil {
		t.Fatalf("superuser refused: %v", err)
	}
	if err := EnsureOwnerBypassesRLS(ctx, f.app); err == nil {
		t.Fatal("rmt_app accepted as an owner connection")
	}
}

// Issuance (tickets, policies, grants) is serialized with suspension (design v5, issuance_guard.go).
func TestPgIssuanceIsSerializedWithSuspension(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	srv := NewServer(StubAuthenticator{}, NewPgBinder(f.app))
	binder := NewPgBinder(f.app)
	// Every bound connection and held lock is released through t.Cleanup / sync.Once, so a failing
	// assertion cannot leave a connection checked out (the pool's Close would then wait forever).
	bind := func() (context.Context, func()) {
		bctx, rel, err := binder.BindTenant(ctx, f.customer)
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		unbind := func() { once.Do(rel) }
		t.Cleanup(unbind)
		return bctx, unbind
	}
	hold := func(bctx context.Context) (func(), error) {
		rel, err := srv.holdIssuance(bctx, f.customer)
		if err != nil {
			return nil, err
		}
		var once sync.Once
		release := func() { once.Do(rel) }
		t.Cleanup(release)
		return release, nil
	}

	// 1. An in-flight issuance holding the shared lock makes the suspension WAIT until it releases.
	bctx, unbind := bind()
	release, err := hold(bctx)
	if err != nil {
		t.Fatalf("issuance on an active tenant: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "c")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("suspension committed while an issuance was in flight (err=%v)", err)
	case <-time.After(1500 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("suspension after the issuance released: %v", err)
	}
	unbind()

	// 2. After the commit every issuance is refused.
	bctx, unbind = bind()
	if _, err := hold(bctx); !errors.Is(err, errIssuanceSuspended) {
		t.Fatalf("issuance after suspension: %v, want errIssuanceSuspended", err)
	}
	unbind()
	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, false, "x", "c"); err != nil {
		t.Fatal(err)
	}

	// 3. An issuance arriving while a suspension is UNCOMMITTED waits, then sees it and is refused
	//    (the "renewal authenticated before the commit, resumed after it" case).
	tx, err := f.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, issuanceLockKey(f.customer)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1`, f.customer); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	bctx, _ = bind()
	var issueErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		rel, err := srv.holdIssuance(bctx, f.customer)
		if err == nil {
			rel()
		}
		issueErr = err
	}()
	// Registered AFTER bind, so it runs BEFORE the unbind cleanup: release the suspension lock (if
	// the test failed before committing) and wait for the goroutine to stop using the connection.
	t.Cleanup(func() {
		_ = tx.Rollback(context.Background())
		<-finished
	})
	select {
	case <-finished:
		t.Fatalf("issuance did not wait for the uncommitted suspension (err=%v)", issueErr)
	case <-time.After(1500 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-finished
	if !errors.Is(issueErr, errIssuanceSuspended) {
		t.Fatalf("issuance after the suspension committed: %v, want errIssuanceSuspended", issueErr)
	}
}

// A session ticket minted before a suspension cannot be redeemed (brokered) after it.
func TestPgSuspendedTenantTicketsAreNotRedeemable(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	ledger := NewPgTicketRedemptionStore(f.app)
	redeem := func() error {
		var sid string
		_ = f.su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&sid)
		_, err := ledger.RedeemTicket(ctx, f.customer, sid, "dev-1", time.Now().Add(time.Minute))
		return err
	}
	if err := redeem(); err != nil {
		t.Fatalf("active tenant redemption: %v", err)
	}
	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "c"); err != nil {
		t.Fatal(err)
	}
	if err := redeem(); !errors.Is(err, ErrTicketAlreadyRedeemed) {
		t.Fatalf("suspended tenant redemption: %v, want refused", err)
	}
	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, false, "x", "c"); err != nil {
		t.Fatal(err)
	}
	if err := redeem(); err != nil {
		t.Fatalf("resumed tenant redemption: %v", err)
	}
}

// TestPgTicketRedemptionIsSerializedWithSuspension: the two concurrent orderings the sequential test
// above cannot see.
//
//  1. A suspension in flight (exclusive issuance lock held, disabled_at written, not yet committed):
//     a redemption arriving now must WAIT, and after the commit it must be refused. Without the lock
//     it reads the still-committed active row and succeeds immediately.
//  2. A redemption in flight (its transaction open): the suspension must wait for it to commit, so
//     the redemption that succeeded is ordered before the suspension.
func TestPgTicketRedemptionIsSerializedWithSuspension(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	ledger := NewPgTicketRedemptionStore(f.app)
	newSID := func() string {
		var sid string
		if err := f.su.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&sid); err != nil {
			t.Fatal(err)
		}
		return sid
	}
	const blocked = 400 * time.Millisecond

	// 1. Suspension in flight, simulated with the same lock and write cp_platform_set_suspended makes.
	susp, err := f.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := susp.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tenant_issuance:' || $1::uuid::text, 0))`, f.customer); err != nil {
		t.Fatal(err)
	}
	if _, err := susp.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1`, f.customer); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ledger.RedeemTicket(ctx, f.customer, newSID(), "dev-1", time.Now().Add(time.Minute))
		done <- err
	}()
	select {
	case err := <-done:
		_ = susp.Rollback(ctx)
		t.Fatalf("redemption returned (%v) while the suspension held the issuance lock", err)
	case <-time.After(blocked):
	}
	if err := susp.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrTicketAlreadyRedeemed) {
			t.Fatalf("redemption after the suspension committed: %v, want refused", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("redemption never returned after the suspension committed")
	}
	if _, err := f.su.Exec(ctx, `UPDATE tenant SET disabled_at = NULL WHERE id = $1`, f.customer); err != nil {
		t.Fatal(err)
	}

	// 2. Redemption in flight: the real suspension waits for it.
	red, err := f.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = red.Rollback(ctx) }()
	var n int
	if err := red.QueryRow(ctx, `SELECT count(*) FROM cp_session_ticket_redeem($1, $2, 'dev-1', now() + interval '1 minute')`,
		f.customer, newSID()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("redeem in tx: n=%d err=%v", n, err)
	}
	suspended := make(chan error, 1)
	go func() {
		_, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "c")
		suspended <- err
	}()
	select {
	case err := <-suspended:
		t.Fatalf("suspension returned (%v) while a redemption was uncommitted", err)
	case <-time.After(blocked):
	}
	if err := red.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-suspended:
		if err != nil {
			t.Fatalf("suspension after the redemption committed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("suspension never completed")
	}
}

// TestPgRefusedSessionStartLeavesNoOpenRecord: a session start refused by the issuance guard (tenant
// suspended) must not leave an open session_record behind; a leaked open row holds a concurrency seat
// against max_concurrent_sessions until it is reaped. The guard is taken before the record is created.
func TestPgRefusedSessionStartLeavesNoOpenRecord(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	seedGroupMachine(t, f.su, f.customer, "refused-dev")
	principal := &Principal{
		UserID:   f.custOwn,
		TenantID: f.customer,
		Grant:    NewGrant(f.custOwn, f.customer, NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: principal}, NewPgBinder(f.app))
	srv.Machines = NewPgMachineStore(f.app)
	srv.SessionRecords = NewPgSessionRecordStore(f.app)
	srv.MgmtAudit = NewPgMgmtAuditStore(f.app)
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	srv.Grants = iss

	if _, err := f.store.SetSuspended(ctx, f.caller(f.op, f.opSession), f.customer, true, "x", "c"); err != nil {
		t.Fatal(err)
	}
	// The stub authenticator stands in for a request authenticated just before the suspension.
	if code := apiJSON(t, srv, "POST", "/sessions", `{"machine_id":"refused-dev"}`, nil); code != http.StatusForbidden {
		t.Fatalf("session start in a suspended tenant = %d, want 403", code)
	}
	var open int
	if err := f.su.QueryRow(ctx, `SELECT count(*) FROM session_record WHERE tenant_id = $1 AND ended_at IS NULL`, f.customer).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 0 {
		t.Fatalf("%d open session record(s) left by a refused start, want 0", open)
	}
}
