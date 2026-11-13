package controlplane

// Migration 0071 against a live PostgreSQL: the shared contract suite, then everything only the database can
// prove (guards that refuse a direct-SQL bypass, grants, composite foreign keys, bounded lock waits).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type pgHostFx struct {
	*hostContractFx
	pf       *platformFixture
	store    *PgAttendedStore
	hostsPg  *PgHostnameStore
	slugSeq  atomic.Int32
	tenantOf map[string]string // tenant id -> technician user id
	groupOf  map[string]string
}

// newPgHostFx lays the platform fixture, then 0021 (the latest definition of cp_attended_redeem before this
// work) and 0071 on top, in production order.
func newPgHostFx(t *testing.T) *pgHostFx {
	t.Helper()
	pf := newPlatformFixture(t)
	applyMigrationFile(t, pf.su, "migrations/0021_attended_redeem_tenant_active.sql")
	applyMigrationFile(t, pf.su, "migrations/0071_tenant_hostname.sql")

	fx := &pgHostFx{pf: pf, tenantOf: map[string]string{}, groupOf: map[string]string{}}
	fx.store = NewPgAttendedStore(pf.app)
	fx.hostsPg = NewPgHostnameStore(pf.app, pf.audit)
	ctx := context.Background()
	fx.hostContractFx = &hostContractFx{
		hosts:    fx.hostsPg,
		attended: fx.store,
		caller:   pf.caller(pf.op, pf.opSession),
		tenant: func(name string) string {
			n := fx.slugSeq.Add(1)
			tid, uid := provisionUser(t, pf.su, fmt.Sprintf("t%s%d", name, n), fmt.Sprintf("tech%d@%s.test", n, name), "password-1234")
			fx.tenantOf[tid] = uid
			fx.groupOf[tid] = seedGroup(t, pf.su, tid)
			return tid
		},
		newCode: func(tenant string) (string, string) {
			s := &AttendedSession{GroupID: fx.groupOf[tenant], TechnicianID: fx.tenantOf[tenant], Reason: "x"}
			code, err := fx.store.Create(ctx, tenant, s)
			if err != nil {
				t.Fatalf("create code: %v", err)
			}
			return code, s.ID
		},
		expire: func(id string) {
			mustExec(t, pf.su, `UPDATE attended_session SET expires_at = now() - interval '1 minute' WHERE id = $1`, id)
		},
		suspend: func(tenant string, on bool) {
			mustExec(t, pf.su, `UPDATE tenant SET disabled_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE id = $1`, tenant, on)
		},
		age: func(host string, d time.Duration) {
			ageReleasedPg(t, fx.pf, host, d)
		},
	}
	return fx
}

func ageReleasedPg(t *testing.T, pf *platformFixture, host string, d time.Duration) {
	t.Helper()
	mustExec(t, pf.su, `ALTER TABLE tenant_hostname_assignment DISABLE TRIGGER USER`)
	mustExec(t, pf.su, `UPDATE tenant_hostname_assignment
		SET released_at = released_at - $2::interval, quarantined_until = quarantined_until - $2::interval
		WHERE host = $1 AND state = 'released'`, host, fmt.Sprintf("%d seconds", int(d.Seconds())))
	mustExec(t, pf.su, `ALTER TABLE tenant_hostname_assignment ENABLE TRIGGER USER`)
}

func TestHostnameContractPg(t *testing.T) {
	fx := newPgHostFx(t)
	runHostnameContract(t, fx.hostContractFx)
}

// Both audit chains record every lifecycle change in the same transaction, and both chains verify.
func TestPgHostnameLifecycleIsAuditedOnBothChains(t *testing.T) {
	fx := newPgHostFx(t)
	ctx := context.Background()
	tn := fx.tenant("aud")
	a, err := fx.hosts.Assign(ctx, fx.caller, tn, "audited.example.test", map[string]any{"override_reason": "because"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, a.ID, 30, map[string]any{"reason": "done"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.hosts.Reactivate(ctx, fx.caller, a.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	count := func(tenant, prefix string) int {
		var n int
		if err := fx.pf.su.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action LIKE $2`, tenant, prefix+"%").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(fx.pf.platform, "platform.hostname."); n != 4 {
		t.Fatalf("platform chain hostname events = %d, want 4", n)
	}
	if n := count(tn, "tenant.hostname."); n != 4 {
		t.Fatalf("tenant chain hostname events = %d, want 4", n)
	}
	var meta string
	if err := fx.pf.su.QueryRow(ctx, `SELECT metadata::text FROM audit_event WHERE tenant_id = $1 AND action = 'platform.hostname.assign'`, fx.pf.platform).Scan(&meta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(meta, "override_reason") || !strings.Contains(meta, "platform_operator") {
		t.Fatalf("assign audit lacks the override or the operator: %s", meta)
	}
	verifyChain(t, fx.pf.audit, fx.pf.platform)
	verifyChain(t, fx.pf.audit, tn)

	// A failed change leaves NO audit row (it is one transaction).
	before := count(fx.pf.platform, "platform.hostname.")
	if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); !errors.Is(err, ErrHostnameState) && err != nil {
		// a.ID is released: the activate must fail
	}
	if after := count(fx.pf.platform, "platform.hostname."); after != before {
		t.Fatalf("a refused activation wrote audit rows: %d -> %d", before, after)
	}
}

// Operator authorization is the database's: a non-operator and a stale second factor are refused.
func TestPgHostnameRequiresAFreshOperator(t *testing.T) {
	fx := newPgHostFx(t)
	ctx := context.Background()
	tn := fx.tenant("auth")
	nonOpSess := newSession(t, fx.pf.su, fx.pf.platform, fx.pf.nonOp, "now()", 1)
	if _, err := fx.hosts.Assign(ctx, fx.pf.caller(fx.pf.nonOp, nonOpSess), tn, "nonop.example.test", nil); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("non-operator assign: %v", err)
	}
	stale := newSession(t, fx.pf.su, fx.pf.platform, fx.pf.op, "now() - interval '20 minutes'", fx.pf.opGen)
	if _, err := fx.hosts.Assign(ctx, fx.pf.caller(fx.pf.op, stale), tn, "stale.example.test", nil); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("stale MFA assign (mutations need 15 minutes): %v", err)
	}
	// reads accept the 12-hour freshness.
	if _, err := fx.hosts.List(ctx, fx.pf.caller(fx.pf.op, stale), ""); err != nil {
		t.Fatalf("list with 20-minute MFA: %v", err)
	}
	// An operator of the platform tenant is not an operator from another tenant's context.
	wrongCtx := PlatformCaller{UserID: fx.pf.op, TenantID: tn, SessionID: fx.pf.opSession}
	if _, err := fx.hosts.Assign(ctx, wrongCtx, tn, "wrongctx.example.test", nil); !errors.Is(err, ErrPlatformDenied) {
		t.Fatalf("operator acting from a customer tenant context: %v", err)
	}
	if _, err := fx.hosts.Assign(ctx, fx.caller, newUUID(), "ghost.example.test", nil); !errors.Is(err, ErrPlatformNoTenant) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

func hostPgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// The guards live in the schema: direct SQL (an importer, a seed, a console) cannot bypass them.
func TestPgHostnameSchemaGuardsRefuseDirectSQL(t *testing.T) {
	fx := newPgHostFx(t)
	su := fx.pf.su
	ctx := context.Background()
	A, B := fx.tenant("ga"), fx.tenant("gb")

	exec := func(sql string, args ...any) error { _, err := su.Exec(ctx, sql, args...); return err }

	// Quarantine: another tenant released the host 1 day ago (a released row with a 30-day quarantine).
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_at, released_by, quarantined_until)
		VALUES ('q.example.test', $1, 'released', 'x', now(), 'x', now() + interval '31 days')`, A); err != nil {
		t.Fatalf("seed a released row: %v", err)
	}
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('q.example.test', $1, 'pending', 'x')`, B); hostPgCode(err) != "HQ001" {
		t.Fatalf("direct INSERT into a quarantined host by another tenant: %v, want HQ001", err)
	}
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, activated_at) VALUES ('q.example.test', $1, 'active', 'x', now())`, B); hostPgCode(err) != "HQ001" {
		t.Fatalf("direct INSERT of an ACTIVE row into a quarantined host: %v, want HQ001", err)
	}
	// ...but the releasing tenant may take it back.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('q.example.test', $1, 'pending', 'x')`, A); err != nil {
		t.Fatalf("the releasing tenant must be allowed back: %v", err)
	}
	// Activation of a PENDING row is also guarded: seed a pending row for B on a free host, then quarantine it
	// by another tenant's release, then try to activate.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('late.example.test', $1, 'pending', 'x')`, B); err != nil {
		t.Fatal(err)
	}
	C := fx.tenant("gc")
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_at, released_by, quarantined_until)
		VALUES ('late.example.test', $1, 'released', 'x', now(), 'x', now() + interval '31 days')`, C); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET state = 'active', activated_at = now() WHERE host = 'late.example.test' AND state = 'pending'`); hostPgCode(err) != "HQ001" {
		t.Fatalf("activating into a quarantined host: %v, want HQ001", err)
	}

	// A released row must carry >= 30 days of quarantine (CHECK).
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, released_at, released_by, quarantined_until)
		VALUES ('short.example.test', $1, 'released', 'x', now(), 'x', now() + interval '1 day')`, A); hostPgCode(err) != "23514" {
		t.Fatalf("released with 1 day quarantine: %v, want a CHECK violation", err)
	}
	// Released is terminal and identity columns never change.
	if err := exec(`UPDATE tenant_hostname_assignment SET quarantined_until = now() WHERE host = 'q.example.test' AND state = 'released'`); hostPgCode(err) == "" {
		t.Fatal("a released row must be immutable")
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET host = 'other.example.test' WHERE host = 'q.example.test' AND state = 'pending'`); hostPgCode(err) != "23514" {
		t.Fatalf("host rewrite: %v", err)
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET tenant_id = $1 WHERE host = 'q.example.test' AND state = 'pending'`, B); hostPgCode(err) != "23514" {
		t.Fatalf("tenant rewrite: %v", err)
	}
	// Shape: an active row needs activated_at; a pending row cannot carry released fields.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('shape.example.test', $1, 'active', 'x')`, C); hostPgCode(err) != "23514" {
		t.Fatalf("active without activated_at: %v", err)
	}
	// One live row per host and per tenant.
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('q.example.test', $1, 'pending', 'x')`, A); hostPgCode(err) != "23505" {
		t.Fatalf("second live row for a host: %v", err)
	}
	// Host format: uppercase and single-label hosts are refused.
	for _, h := range []string{"Upper.example.test", "single", "a_b.example.test", ""} {
		if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ($1, $2, 'pending', 'x')`, h, C); hostPgCode(err) != "23514" {
			t.Fatalf("host %q: %v, want a CHECK violation", h, err)
		}
	}
	// Cannot regress an active row to pending.
	D := fx.tenant("gd")
	if err := exec(`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by, activated_at) VALUES ('act.example.test', $1, 'active', 'x', now())`, D); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE tenant_hostname_assignment SET state = 'pending', activated_at = NULL WHERE host = 'act.example.test'`); hostPgCode(err) != "23514" {
		t.Fatalf("active -> pending: %v", err)
	}
}

// Privileges (the application role) and the composite foreign keys of 2b.2.
func TestPgHostnameAndBrandingPointerPrivilegesAndKeys(t *testing.T) {
	fx := newPgHostFx(t)
	su, app := fx.pf.su, fx.pf.app
	ctx := context.Background()
	A, B := fx.tenant("pa"), fx.tenant("pb")
	a := fx.mustAssign(t, A, "pa.example.test")
	fx.mustAssign(t, B, "pb.example.test")

	// rmt_app: no direct writes to the assignment table, no execute on the internal helpers.
	for _, q := range []string{
		`INSERT INTO tenant_hostname_assignment (host, tenant_id, state, created_by) VALUES ('x.example.test', '` + A + `', 'pending', 'x')`,
		`UPDATE tenant_hostname_assignment SET state = 'released'`,
		`DELETE FROM tenant_hostname_assignment`,
		`SELECT cp_hostname_lock_tenant('` + A + `')`,
		`SELECT cp_hostname_clear_published('` + A + `')`,
	} {
		if _, err := app.Exec(ctx, q); hostPgCode(err) != "42501" {
			t.Errorf("rmt_app %q: %v, want permission denied", q, err)
		}
	}
	// Reads are RLS-scoped: a tenant sees only its own assignment.
	err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_hostname_assignment`).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("tenant A sees %d assignment rows, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The definer functions are not executable by PUBLIC; the scoped redeem is rmt_app's only.
	for _, fn := range []string{
		"cp_attended_redeem_scoped(bytea, bytea, text, text, bytea, timestamptz, text, boolean)",
		"cp_platform_hostname_assign(uuid, uuid, uuid, text, text)",
		"cp_platform_hostname_list(uuid, uuid, uuid)",
		"cp_hostname_live_among(text[])",
	} {
		var pub, appRole bool
		if err := su.QueryRow(ctx, `SELECT has_function_privilege('public', $1::regprocedure, 'EXECUTE'), has_function_privilege('rmt_app', $1::regprocedure, 'EXECUTE')`, fn).Scan(&pub, &appRole); err != nil {
			t.Fatal(err)
		}
		if pub || !appRole {
			t.Errorf("%s: public=%v rmt_app=%v, want false/true", fn, pub, appRole)
		}
		var cfg string
		if err := su.QueryRow(ctx, `SELECT coalesce(array_to_string(proconfig, ','), '') FROM pg_proc WHERE oid = $1::regprocedure`, fn).Scan(&cfg); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cfg, "search_path=pg_catalog, public, pg_temp") {
			t.Errorf("%s: search_path not pinned: %q", fn, cfg)
		}
		var definer bool
		if err := su.QueryRow(ctx, `SELECT prosecdef FROM pg_proc WHERE oid = $1::regprocedure`, fn).Scan(&definer); err != nil || !definer {
			t.Errorf("%s: SECURITY DEFINER = %v %v", fn, definer, err)
		}
	}

	// Revisions: composite (tenant_id, id); the Owner's role may INSERT and SELECT only.
	var revA, revB string
	if err := su.QueryRow(ctx, `INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, normalized_hash, created_by)
		VALUES ($1, 1, 'Acme', repeat('a', 64), 'o') RETURNING id::text`, A).Scan(&revA); err != nil {
		t.Fatal(err)
	}
	if err := su.QueryRow(ctx, `INSERT INTO tenant_branding_revision (tenant_id, seq, product_name, normalized_hash, created_by)
		VALUES ($1, 1, 'Bcorp', repeat('b', 64), 'o') RETURNING id::text`, B).Scan(&revB); err != nil {
		t.Fatal(err)
	}
	if err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant_branding_revision SET product_name = 'Evil' WHERE id = $1`, revA)
		return err
	}); hostPgCode(err) != "42501" {
		t.Errorf("rmt_app UPDATE of a revision: %v, want permission denied", err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_revision SET product_name = 'Evil' WHERE id = $1`, revA); hostPgCode(err) != "23514" {
		t.Errorf("even the owner cannot UPDATE a revision (trigger): %v", err)
	}
	if err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM tenant_branding_revision WHERE id = $1`, revA)
		return err
	}); hostPgCode(err) != "42501" {
		t.Errorf("rmt_app DELETE of a revision: %v, want permission denied", err)
	}
	// Under RLS tenant A cannot insert a revision for tenant B.
	if err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tenant_branding_revision (tenant_id, seq, normalized_hash, created_by) VALUES ($1, 9, repeat('c', 64), 'o')`, B)
		return err
	}); err == nil {
		t.Error("tenant A inserted a revision for tenant B")
	}

	// The pointer: a plain direct-SQL pointer cannot name ANOTHER tenant's revision or assignment.
	mustExec(t, su, `INSERT INTO tenant_branding_pointer (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, A)
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET draft_revision_id = $2 WHERE tenant_id = $1`, A, revB); hostPgCode(err) != "23503" {
		t.Errorf("draft pointer to another tenant's revision: %v, want a foreign-key violation", err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = repeat('b', 64),
		published_assignment_id = $3, published_by = 'op', published_at = now() WHERE tenant_id = $1`, A, revB, a.ID); hostPgCode(err) != "23503" {
		t.Errorf("published pointer to another tenant's revision: %v, want a foreign-key violation", err)
	}
	var bAssign string
	if err := su.QueryRow(ctx, `SELECT id::text FROM tenant_hostname_assignment WHERE tenant_id = $1`, B).Scan(&bAssign); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = repeat('a', 64),
		published_assignment_id = $3, published_by = 'op', published_at = now() WHERE tenant_id = $1`, A, revA, bAssign); hostPgCode(err) != "23503" {
		t.Errorf("published pointer to another tenant's assignment: %v, want a foreign-key violation", err)
	}
	if _, err := su.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = $2 WHERE tenant_id = $1`, A, revA); hostPgCode(err) != "23514" {
		t.Errorf("a half-set published triple: %v, want the all-or-none CHECK", err)
	}
	// The matching triple is accepted.
	mustExec(t, su, `UPDATE tenant_branding_pointer SET draft_revision_id = $2, published_revision_id = $2, published_revision_hash = repeat('a', 64),
		published_assignment_id = $3, published_by = 'op', published_at = now() WHERE tenant_id = $1`, A, revA, a.ID)

	// The Owner's role can move ITS draft pointer but can never write the published triple.
	if err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant_branding_pointer SET draft_revision_id = $1`, revA)
		return err
	}); err != nil {
		t.Errorf("owner moving its own draft pointer: %v", err)
	}
	if err := withTenant(ctx, app, A, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant_branding_pointer SET published_revision_id = NULL, published_revision_hash = NULL,
			published_assignment_id = NULL, published_by = NULL, published_at = NULL`)
		return err
	}); hostPgCode(err) != "42501" {
		t.Errorf("owner writing the published triple: %v, want permission denied", err)
	}

	// Assign / release / reactivate each clear the tenant's published pointer (never inherited, 2a.10, 2b.2).
	published := func() bool {
		var n int
		if err := su.QueryRow(ctx, `SELECT count(*) FROM tenant_branding_pointer WHERE tenant_id = $1 AND published_revision_id IS NOT NULL`, A).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !published() {
		t.Fatal("setup: expected a published pointer")
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, a.ID, 30, nil); err != nil {
		t.Fatal(err)
	}
	if published() {
		t.Error("release must clear the published pointer")
	}
	mustExec(t, su, `UPDATE tenant_branding_pointer SET published_revision_id = $2, published_revision_hash = repeat('a', 64),
		published_assignment_id = $3, published_by = 'op', published_at = now() WHERE tenant_id = $1`, A, revA, a.ID)
	if _, err := fx.hosts.Reactivate(ctx, fx.caller, a.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if published() {
		t.Error("reactivate must clear the published pointer (a new assignment id never inherits an approval)")
	}
}

// The wrapper keeps every predicate and is UNSCOPED; the scoped function with p_unscoped = true is the same.
func TestPgAttendedRedeemWrapperParity(t *testing.T) {
	fx := newPgHostFx(t)
	ctx := context.Background()
	A := fx.tenant("w")
	code, _ := fx.newCode(A)
	res, err := fx.store.Redeem(ctx, code, randPubkeyHex(t), "GUEST")
	if err != nil || res.TenantID != A {
		t.Fatalf("wrapper (Redeem): %+v %v", res, err)
	}
	if _, err := fx.store.Redeem(ctx, code, randPubkeyHex(t), "GUEST"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("wrapper, spent: %v", err)
	}
	code2, _ := fx.newCode(A)
	var sid string
	err = fx.pf.app.QueryRow(ctx, `SELECT session_id::text FROM cp_attended_redeem_scoped($1, $2, 'n', $3, $4, now() + interval '1 hour', '', true)`,
		HashToken(normalizeAttendCode(code2)), mustHex(t, randPubkeyHex(t)), newUUID(), HashToken("tok")).Scan(&sid)
	if err != nil || sid == "" {
		t.Fatalf("scoped with p_unscoped: %q %v", sid, err)
	}
	// The six-argument wrapper has the SAME body semantics for a suspended tenant (0021 parity).
	code3, _ := fx.newCode(A)
	fx.suspend(A, true)
	if _, err := fx.store.Redeem(ctx, code3, randPubkeyHex(t), "GUEST"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("wrapper on a suspended tenant: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v int
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &v); err != nil {
			t.Fatal(err)
		}
		b[i] = byte(v)
	}
	return b
}

// --- bounded lock wait (docs/66 2b.5) ------------------------------------------------------------------

type lockFx struct {
	fx    *pgHostFx
	A     string
	host  string
	code  string
	sid   string
	scope RedeemScope
}

// holdRow opens a transaction on the superuser pool that locks the session row FOR UPDATE.
func (l *lockFx) holdRowTx(t *testing.T, body func(tx pgx.Tx)) (finish func(commit bool)) {
	t.Helper()
	ctx := context.Background()
	tx, err := l.fx.pf.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if body == nil {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM attended_session WHERE id = $1 FOR UPDATE`, l.sid); err != nil {
			t.Fatal(err)
		}
	} else {
		body(tx)
	}
	return func(commit bool) {
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = tx.Rollback(ctx)
		}
	}
}

func newLockFx(t *testing.T) *lockFx {
	t.Helper()
	fx := newPgHostFx(t)
	A := fx.tenant("lk")
	a := fx.mustAssign(t, A, "lock.example.test")
	if _, err := fx.hosts.Activate(context.Background(), fx.caller, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	code, sid := fx.newCode(A)
	return &lockFx{fx: fx, A: A, host: "lock.example.test", code: code, sid: sid, scope: RedeemScope{Host: "lock.example.test"}}
}

func (l *lockFx) redeemTimed(t *testing.T) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	_, err := l.fx.store.RedeemScoped(context.Background(), l.code, randPubkeyHex(t), "GUEST", l.scope)
	return time.Since(start), err
}

// (1) The holder is a REDEMPTION that commits: the loser is rejected generically, before or after the commit.
func TestPgLockWaitHolderRedeemsAndCommits(t *testing.T) {
	l := newLockFx(t)
	ctx := context.Background()
	finish := l.holdRowTx(t, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `SELECT * FROM cp_attended_redeem_scoped($1, $2, 'H', $3, $4, now() + interval '1 hour', $5, false)`,
			HashToken(normalizeAttendCode(l.code)), mustHex(t, randPubkeyHex(t)), newUUID(), HashToken("holder"), l.host); err != nil {
			t.Fatal(err)
		}
	})
	done := make(chan error, 1)
	go func() { _, err := l.redeemTimed(t); done <- err }()
	time.Sleep(15 * time.Millisecond)
	finish(true) // commits while the loser is blocked (inside its 50 ms): it then finds state = 'redeemed'
	if err := <-done; !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("loser after the holder committed: %v, want the generic rejection", err)
	}
	if _, err := l.redeemTimed(t); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("retry after the winner: %v", err)
	}
}

// (2) The holder rolls back BEFORE the 50 ms elapse: the loser SUCCEEDS (SKIP LOCKED would have refused it).
func TestPgLockWaitHolderRollsBackInsideTheBound(t *testing.T) {
	l := newLockFx(t)
	finish := l.holdRowTx(t, nil)
	type out struct {
		d   time.Duration
		err error
	}
	done := make(chan out, 1)
	go func() { d, err := l.redeemTimed(t); done <- out{d, err} }()
	time.Sleep(15 * time.Millisecond)
	finish(false)
	o := <-done
	if o.err != nil {
		t.Fatalf("loser after a quick rollback: %v, want success", o.err)
	}
	if o.d < 10*time.Millisecond || o.d > 45*time.Millisecond {
		t.Errorf("the loser waited %v, expected roughly the holder's 15 ms", o.d)
	}
}

// (3) The holder rolls back AFTER the bound: the loser is rejected generically at ~50 ms; a retry succeeds.
func TestPgLockWaitHolderRollsBackAfterTheBound(t *testing.T) {
	l := newLockFx(t)
	finish := l.holdRowTx(t, nil)
	d, err := l.redeemTimed(t)
	if !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("loser blocked past the bound: %v, want the generic rejection", err)
	}
	if d < 40*time.Millisecond || d > 200*time.Millisecond {
		t.Errorf("the loser was released after %v, want ~50 ms (lock_timeout)", d)
	}
	finish(false)
	if _, err := l.redeemTimed(t); err != nil {
		t.Fatalf("retry after the holder rolled back: %v, want success (the code must not have been consumed)", err)
	}
}

// (4) A non-redemption update holding the row (a technician-side write) delays at most 50 ms and does not
// consume the code.
func TestPgLockWaitNonRedemptionHolderDoesNotConsumeTheCode(t *testing.T) {
	l := newLockFx(t)
	ctx := context.Background()
	finish := l.holdRowTx(t, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE attended_session SET reason = 'edited' WHERE id = $1`, l.sid); err != nil {
			t.Fatal(err)
		}
	})
	d, err := l.redeemTimed(t)
	if !errors.Is(err, ErrAttendedInvalid) || d > 200*time.Millisecond {
		t.Fatalf("blocked by a non-redemption update: %v after %v", err, d)
	}
	finish(true)
	if _, err := l.redeemTimed(t); err != nil {
		t.Fatalf("the code must survive a non-redemption holder: %v", err)
	}
}

// The wait bound is in the function, not just in the caller: with an unbounded wait this test blocks.
func TestPgLockWaitIsBoundedByTheFunctionItself(t *testing.T) {
	l := newLockFx(t)
	finish := l.holdRowTx(t, nil)
	defer finish(false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := l.fx.store.RedeemScoped(ctx, l.code, randPubkeyHex(t), "GUEST", l.scope)
	if !errors.Is(err, ErrAttendedInvalid) || time.Since(start) > time.Second {
		t.Fatalf("a held row must produce the generic rejection quickly, got %v after %v", err, time.Since(start))
	}
}

// The startup guard's count sees ACTIVE assignments only (a pending one scopes nothing).
func TestPgActiveHostnameCountAndGuard(t *testing.T) {
	fx := newPgHostFx(t)
	ctx := context.Background()
	count := func() int64 {
		n, err := ActiveHostnameCount(ctx, fx.pf.app)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 0 {
		t.Fatalf("empty database: %d", n)
	}
	A := fx.tenant("gc")
	a := fx.mustAssign(t, A, "guard.example.test")
	if n := count(); n != 0 {
		t.Fatalf("a PENDING assignment counted: %d", n)
	}
	if _, err := CheckThemingOffSafety(ctx, func(c context.Context) (int64, error) { return ActiveHostnameCount(c, fx.pf.app) }, ""); err != nil {
		t.Fatalf("pending only: %v", err)
	}
	if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 1 {
		t.Fatalf("active: %d", n)
	}
	_, err := CheckThemingOffSafety(ctx, func(c context.Context) (int64, error) { return ActiveHostnameCount(c, fx.pf.app) }, "")
	if !errors.Is(err, ErrThemingOffWithAssignments) {
		t.Fatalf("active assignment, policy off: %v, want the refusal", err)
	}
	if esc, err := CheckThemingOffSafety(ctx, func(c context.Context) (int64, error) { return ActiveHostnameCount(c, fx.pf.app) }, ThemingEscapeValue); err != nil || !esc {
		t.Fatalf("escape hatch: %v %v", esc, err)
	}
	if _, err := fx.hosts.Release(ctx, fx.caller, a.ID, 30, nil); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("after release: %d", n)
	}
}
