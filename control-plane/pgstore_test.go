package controlplane

// Integration tests for the pgx-backed stores. These require a live PostgreSQL and are gated
// behind an environment variable, so the default `go test ./...` (which uses the in-memory
// fakes) never needs a database and stays green in CI. To run them:
//
//	TEST_DATABASE_URL=postgres://user:pass@localhost:5432/rmt_test go test ./...
//
// The test database role should be a superuser or hold BYPASSRLS (the usual throwaway-test-DB
// setup): the SECURITY DEFINER bootstrap functions in 0003 bypass RLS only when their owner —
// the role that applied the migration — has that attribute, mirroring how tenant provisioning
// runs privileged in production.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDBURL() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return os.Getenv("DATABASE_URL")
}

// newTestPool connects, resets the schema, and applies migrations 0001–0003. It skips the
// test when no database URL is configured.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := testDBURL()
	if url == "" {
		t.Skip("set TEST_DATABASE_URL (or DATABASE_URL) to run pgx integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	resetSchema(t, pool)
	return pool
}

// execScriptRetries bounds how often execScript repeats a script that lost a race on a CLUSTER-WIDE catalog
// row (see isCatalogRace). A var so the mutation check can set it to 0. 8 lost TestExecScriptSurvivesCatalogRaces
// once in 71 full gates (its 320 ALTER ROLEs race the other packages' role edits too); 16 with the growing backoff
// gives a losing streak of ~5 s.
var execScriptRetries = 16

// isCatalogRace reports "tuple concurrently updated" (XX000): two sessions changed the same shared-catalog
// row at once. Roles live in pg_authid for the whole CLUSTER, so while this suite's migration applies
// `ALTER ROLE rmt_app` (0005) any OTHER test run on the same server - another worktree, another database -
// can collide with it, whichever database each uses. The scripts here are idempotent; the loser just reruns.
func isCatalogRace(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "XX000" && strings.Contains(pgErr.Message, "tuple concurrently updated")
}

// execScriptErr runs a multi-statement script (execScriptRaw) and then, when the script created a table or a
// definer function, hands the application definer functions to rmt_definer exactly as migration 0076 does in
// production (definer_owner_fixture_test.go: the fixture trap). It is safe to call from any goroutine.
func execScriptErr(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	if err := execScriptRaw(ctx, pool, sql); err != nil {
		return err
	}
	if fixtureDDLTrigger.MatchString(sql) && fixtureOwnsDefiners {
		return ownDefinersLikeProduction(ctx, pool)
	}
	return nil
}

// fixtureOwnsDefiners switches the ownership step off, for the mutation check that proves the trap test fails without it.
var fixtureOwnsDefiners = true

// execScriptRaw runs a multi-statement script, retrying a lost catalog race with a short jittered backoff.
func execScriptRaw(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	var err error
	for attempt := 0; attempt <= execScriptRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(20+rand.IntN(60)*attempt) * time.Millisecond)
		}
		err = func() error {
			conn, aerr := pool.Acquire(ctx)
			if aerr != nil {
				return aerr
			}
			defer conn.Release()
			_, eerr := conn.Conn().PgConn().Exec(ctx, sql).ReadAll()
			if eerr != nil {
				// a script with its own BEGIN leaves the session in an aborted transaction
				_, _ = conn.Conn().PgConn().Exec(ctx, "ROLLBACK").ReadAll()
			}
			return eerr
		}()
		if err == nil || !isCatalogRace(err) {
			return err
		}
	}
	return err
}

// execScript runs a multi-statement SQL string via the simple query protocol (pool.Exec uses
// the extended protocol, which rejects multiple statements), used to apply migration files.
func execScript(t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if err := execScriptErr(context.Background(), pool, sql); err != nil {
		t.Fatalf("exec script: %v", err)
	}
}

func resetSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	resetSchemaWith(t, pool, true)
}

// resetSchemaWith is resetSchema with a switch for migration 0065 (nested groups). Everything but the
// 0065 migration's own tests wants it ON (GrantFor reads cp_group_subtree on every authenticated request);
// the migration's existing-data assertion needs the pre-0065 schema to plant a parent_id first.
func resetSchemaWith(t *testing.T, pool *pgxpool.Pool, withGroupTree bool) {
	t.Helper()
	execScript(t, pool, `
		DROP TABLE IF EXISTS agent_directive, tenant_directive_policy CASCADE;
		DROP TABLE IF EXISTS tenant_branding_pointer, tenant_branding_revision, tenant_hostname_assignment CASCADE;
		DROP FUNCTION IF EXISTS cp_attended_redeem_scoped(bytea, bytea, text, text, bytea, timestamptz, text, boolean);
		DROP FUNCTION IF EXISTS cp_platform_hostname_assign(uuid, uuid, uuid, text, text);
		DROP FUNCTION IF EXISTS cp_platform_hostname_activate(uuid, uuid, uuid);
		DROP FUNCTION IF EXISTS cp_platform_hostname_release(uuid, uuid, uuid, text, integer);
		DROP FUNCTION IF EXISTS cp_platform_hostname_reactivate(uuid, uuid, uuid, text, boolean);
		DROP FUNCTION IF EXISTS cp_platform_hostname_list(uuid, uuid, uuid);
		DROP FUNCTION IF EXISTS cp_hostname_live_among(text[]);
		DROP FUNCTION IF EXISTS cp_hostname_active_count();
		DROP FUNCTION IF EXISTS cp_hostname_lock_tenant(uuid);
		DROP FUNCTION IF EXISTS cp_hostname_clear_published(uuid);
		DROP FUNCTION IF EXISTS cp_public_branding_lookup(text, boolean);
		DROP FUNCTION IF EXISTS cp_platform_branding_review(uuid, uuid, uuid);
		DROP FUNCTION IF EXISTS cp_platform_branding_peers(uuid, uuid);
		DROP FUNCTION IF EXISTS cp_platform_branding_approve(uuid, uuid, uuid, uuid, text, uuid, bigint, text);
		DROP FUNCTION IF EXISTS cp_platform_branding_withdraw(uuid, uuid, uuid);
		DROP FUNCTION IF EXISTS tenant_hostname_assignment_guard() CASCADE;
		DROP FUNCTION IF EXISTS tenant_branding_revision_immutable() CASCADE;
		DROP FUNCTION IF EXISTS machine_directive_guard() CASCADE;
		DROP FUNCTION IF EXISTS cp_directive_sweep_candidates(timestamptz, interval, integer);
		DROP FUNCTION IF EXISTS cp_machine_key_removed(bytea);
		DROP FUNCTION IF EXISTS cp_directive_final_ack_target(uuid);
		DROP FUNCTION IF EXISTS cp_group_subtree(uuid, uuid[]);
		DROP FUNCTION IF EXISTS cp_group_ancestors(uuid, uuid);
		DROP FUNCTION IF EXISTS cp_group_tree_lock_key(uuid);
		DROP FUNCTION IF EXISTS machine_group_guard_keys() CASCADE;
		DROP FUNCTION IF EXISTS machine_group_check_structure() CASCADE;
		DROP FUNCTION IF EXISTS machine_group_lock_on_delete() CASCADE;
		DROP FUNCTION IF EXISTS machine_group_bump_version() CASCADE;
	`)
	execScript(t, pool, `
		DROP FUNCTION IF EXISTS cp_resolve_tenant_by_slug(text);
		DROP FUNCTION IF EXISTS cp_create_tenant(text, text, text);
		DROP FUNCTION IF EXISTS cp_session_by_token(bytea);
		DROP FUNCTION IF EXISTS cp_session_revoke(bytea);
		DROP FUNCTION IF EXISTS cp_session_touch_last_seen(bytea, timestamptz);
		DROP FUNCTION IF EXISTS cp_enrollment_token_redeem(bytea);
		DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);
		DROP FUNCTION IF EXISTS cp_attended_redeem(bytea, bytea, text, text, bytea, timestamptz);
		DROP FUNCTION IF EXISTS cp_attended_by_token(bytea);
		DROP FUNCTION IF EXISTS cp_attended_consent(bytea, boolean, text);
		DROP FUNCTION IF EXISTS cp_credential_token_peek(bytea);
		DROP FUNCTION IF EXISTS cp_credential_token_consume(bytea);
		DROP FUNCTION IF EXISTS cp_session_ticket_redeem(uuid, uuid, text, timestamptz);
		DROP FUNCTION IF EXISTS cp_api_token_resolve(bytea);
		DROP FUNCTION IF EXISTS cp_platform_set_suspended(uuid, uuid, uuid, boolean);
		DROP FUNCTION IF EXISTS cp_platform_create_tenant(uuid, uuid, text, text, text);
		DROP FUNCTION IF EXISTS cp_platform_list_tenants(uuid, uuid);
		DROP FUNCTION IF EXISTS cp_platform_whoami(uuid, uuid);
		DROP FUNCTION IF EXISTS cp_platform_check(uuid, uuid, interval);
		DROP FUNCTION IF EXISTS cp_help_request_due_tenants(timestamptz, timestamptz, timestamptz);
		DROP FUNCTION IF EXISTS cp_platform_downloads(uuid, uuid, date, date);
		DROP TABLE IF EXISTS download_daily, download_ingest_cursor;
		DROP TABLE IF EXISTS platform_operator, platform_config;
		DROP SEQUENCE IF EXISTS mfa_generation_seq;
		DROP TABLE IF EXISTS
			help_request_call, help_request_op, help_request, group_tree_version, session_transfer, toolbox_item, session_ticket_redemption, api_token, tenant_branding, tenant_session_policy,
			group_session_policy,
			user_credential_token, machine_property, tenant_ip_allowlist, dynamic_group,
			user_session, user_totp, user_credential,
			audit_event, session_record, enrollment_token, attended_session, machine,
			membership, machine_group, role, app_user, tenant, throttle_counter CASCADE;
	`)
	// 0009, 0012, 0017 and 0018 are applied with the core because the pgx stores hard-depend on
	// their columns: pending_secret (which keeps an unconfirmed re-enrollment from disarming 2FA) is
	// in PgUserStore's projection, last_step (the TOTP replay counter) is written by every TOTP
	// login, 0017's machine.os / machine.last_seen are in PgMachineStore's projection and its
	// INSERT, and 0018's user_session.credential_epoch is in PgSessionStore's INSERT and its
	// by-token projection — the AUTHENTICATION path, so without it every DB-gated auth test fails on
	// a missing column. Unlike 0013, none of these CREATE OR REPLACEs a function, so applying them
	// with the core cannot silently revert a later migration's definition.
	// The remaining migrations stay opt-in per test, applied by the apply*Migration helpers.
	for _, f := range []string{
		"migrations/0001_core.sql",
		"migrations/0002_auth.sql",
		"migrations/0003_auth_bootstrap.sql",
		"migrations/0009_totp_pending.sql",
		"migrations/0012_totp_replay.sql",
		"migrations/0017_machine_presence.sql",
		"migrations/0018_credential_epoch.sql",
		// Session insertion and token lookup project remembered in every store call.
		"migrations/0053_remembered_session.sql",
		// 0054 adds app_user.mfa_generation (PgUserStore's projection) and the session MFA columns
		// (written at login / step-up), so it is always-on like 0053.
		"migrations/0054_mfa_generation.sql",
		// 0031 adds session_record.note, which is in PgSessionRecordStore's SELECT projection
		// (selectSessionRecord) and scanned by every session read, so it must exist before any
		// session-record test — applied with the core like 0017/0018, not opt-in.
		"migrations/0031_session_note.sql",
		// 0032 adds machine.alias, which is in PgMachineStore's SELECT projections (selectMachine and
		// ListMachines) and scanned by every machine read, so it must exist before any machine test —
		// applied with the core like 0031, not opt-in.
		"migrations/0032_machine_alias.sql",
		// 0033 adds machine.note, also in both PgMachineStore projections — same reasoning as 0032.
		"migrations/0033_machine_note.sql",
		// 0034 adds session_record.group_id (written by EVERY session insert now, for per-group seat
		// counting) plus the group_session_policy table, so it must exist before any session-record or
		// group-session-policy test — applied with the core like 0031/0033, not opt-in.
		"migrations/0034_group_session_policy.sql",
		// 0035 adds group_session_policy.enforce_view_only, read by handleStartSession on EVERY start
		// (it decides whether the session is minted a view-only policy), so it is always-on too.
		"migrations/0035_group_enforce_view_only.sql",
		// 0037 adds machine.require_session_policy, in BOTH PgMachineStore projections (selectMachine
		// and the separate inline ListMachines SELECT) and scanned by every machine read, AND read by
		// handleStartSession on every start — same reasoning as 0032/0033/0035, so always-on. (0036 is
		// NOT here: it touches attended_session only, and applyAttendedMigration owns it.)
		"migrations/0037_machine_require_session_policy.sql",
		// 0039 adds machine.agent_version + agent_version_seen_at, in BOTH PgMachineStore projections
		// and scanned by every machine read — same reasoning as 0032/0033/0037, so always-on. Without
		// this entry every DB-gated machine test fails on "column m.agent_version does not exist",
		// including tests that have nothing to do with versions. (0038 is NOT here: it touches the role
		// catalog only.)
		"migrations/0039_machine_agent_version.sql",
		// 0040 adds group_session_policy.allow_backstage_under_view_only, which is in ALL THREE of
		// PgGroupSessionPolicyStore's SQL sites (Get's SELECT, Set's INSERT/ON CONFLICT, List's SELECT) and
		// is read by handleMintGrant on every backstage mint — same reasoning as 0035, so always-on. Without
		// this entry every DB-gated group-session-policy test fails on a missing column.
		"migrations/0040_group_allow_backstage_under_view_only.sql",
		// 0043-0046 add recording/duration/idle columns to group_session_policy; all four are in
		// PgGroupSessionPolicyStore's Get SELECT and Set INSERT/ON CONFLICT, so present on every session
		// start that checks group policies — same reasoning as 0040.
		"migrations/0043_group_prohibit_recording.sql",
		"migrations/0044_group_require_recording.sql",
		"migrations/0045_group_max_session_duration.sql",
		"migrations/0046_group_max_idle_seconds.sql",
		// 0048 adds machine.logged_in_user, which is in both PgMachineStore projections (selectMachine
		// and the inline ListMachines SELECT) — same reasoning as 0032/0033/0037/0039.
		"migrations/0048_machine_logged_in_user.sql",
		// 0049 adds tenant.require_2fa, read in selectUser's JOIN on EVERY login attempt. Without it
		// every DB-gated authentication test fails with "column tn.require_2fa does not exist".
		"migrations/0049_tenant_require_2fa.sql",
		// 0058 adds session_record.access, written by EVERY session insert and in the session-record
		// projection, so it is always-on like 0031/0034. Without it every DB-gated session start fails
		// with a bare 500 ("could not start session"). Its preset-role UPDATE is idempotent, so the
		// observer tests that re-apply it are unaffected.
		"migrations/0058_observer.sql",
		// 0060 adds session_record.transferred_from / end_reason / agent_ended_at, which are in the
		// session-record projection (selectSessionRecord) and so scanned by every session read, plus
		// the session_transfer table and the UNIQUE (tenant_id, id) keys it references. Always-on.
		"migrations/0060_session_transfer.sql",
		// 0062 adds membership.expires_at, read by GrantFor on EVERY authenticated request (docs/56).
		// Without it every DB-gated login fails with "column m.expires_at does not exist". Always-on.
		"migrations/0062_membership_expiry.sql",
		// 0063 adds the membership window columns and membership_window_open, read by GrantFor on
		// EVERY authenticated request (docs/57). Always-on for the same reason as 0062.
		"migrations/0063_membership_window.sql",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		execScript(t, pool, string(b))
	}
	if withGroupTree {
		// 0065 makes machine_group nest (docs/62): GrantFor and StoredGrantFor call cp_group_subtree and
		// read group_tree_version on EVERY authenticated request, and the group store's INSERT fires the
		// structure trigger. Always-on for the same reason as 0062/0063.
		b, err := os.ReadFile("migrations/0065_machine_group_tree.sql")
		if err != nil {
			t.Fatalf("read 0065: %v", err)
		}
		execScript(t, pool, string(b))
	}
}

// provisionUser creates a tenant + user + local credential + technician membership, using
// client-generated UUIDs pinned via app.current_tenant so the RLS WITH CHECK is satisfied on
// every write (works whether the connection bypasses RLS or not). Returns tenantID, userID.
func provisionUser(t *testing.T, pool *pgxpool.Pool, slug, email, password string) (string, string) {
	t.Helper()
	ctx := context.Background()

	var tid, uid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&tid, &uid); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	provision(t, pool, tid, uid, slug, email, hash)
	return tid, uid
}

// provision inserts the tenant/user/credential/membership rows for a test, all tenant-pinned.
func provision(t *testing.T, pool *pgxpool.Pool, tid, uid, slug, email, hash string) {
	t.Helper()
	ctx := context.Background()
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name, deployment_mode) VALUES ($1,$2,$3,'self_hosted')`,
			tid, slug, slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO app_user (id, tenant_id, email) VALUES ($1,$2,$3)`,
			uid, tid, email); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_credential (user_id, tenant_id, password_hash) VALUES ($1,$2,$3)`,
			uid, tid, hash); err != nil {
			return err
		}
		var roleID string
		if err := tx.QueryRow(ctx,
			`SELECT id::text FROM role WHERE key='technician' AND tenant_id IS NULL`).Scan(&roleID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO membership (tenant_id, user_id, role_id) VALUES ($1,$2,$3)`,
			tid, uid, roleID)
		return err
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
}

func TestPgTenantResolver(t *testing.T) {
	pool := newTestPool(t)
	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")

	r := NewPgTenantResolver(pool)
	got, err := r.ResolveTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if got != tid {
		t.Fatalf("ResolveTenant = %s, want %s", got, tid)
	}
	if _, err := r.ResolveTenant(context.Background(), "no-such-slug"); err != ErrNoTenant {
		t.Fatalf("unknown slug err = %v, want ErrNoTenant", err)
	}
}

func TestPgUserStoreFindAndGrant(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := newPgUserStoreT(pool)
	ctx := context.Background()

	u, err := store.FindUserByEmail(ctx, tid, "tech@acme.test")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if u.ID != uid || u.TenantID != tid {
		t.Fatalf("user mismatch: %+v", u)
	}
	if ok, err := VerifyPassword(u.PasswordHash, "password-1234"); err != nil || !ok {
		t.Fatalf("stored hash did not verify: ok=%v err=%v", ok, err)
	}

	grant, err := store.GrantFor(ctx, tid, uid)
	if err != nil {
		t.Fatalf("GrantFor: %v", err)
	}
	if !grant.Allows(CapStartSession) {
		t.Fatal("technician grant should allow start_session")
	}
	if grant.Allows(CapViewAudit) {
		t.Fatal("technician grant should not allow view_audit")
	}

	// Unknown user → ErrNoUser.
	if _, err := store.FindUserByEmail(ctx, tid, "ghost@acme.test"); err != ErrNoUser {
		t.Fatalf("unknown user err = %v, want ErrNoUser", err)
	}
}

func TestPgUserStoreTOTPRoundTrip(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := newPgUserStoreT(pool)
	ctx := context.Background()

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	// Enroll unconfirmed, then confirm.
	if err := store.SetTOTP(ctx, tid, uid, secret, false); err != nil {
		t.Fatalf("SetTOTP enroll: %v", err)
	}
	u, _ := store.FindUserByID(ctx, tid, uid)
	if u.TOTPSecret != secret || u.TOTPConfirmed {
		t.Fatalf("after enroll: secret=%q confirmed=%v", u.TOTPSecret, u.TOTPConfirmed)
	}
	if err := store.SetTOTP(ctx, tid, uid, secret, true); err != nil {
		t.Fatalf("SetTOTP confirm: %v", err)
	}
	u, _ = store.FindUserByID(ctx, tid, uid)
	if !u.TOTPConfirmed {
		t.Fatal("after confirm: expected TOTPConfirmed true")
	}
}

// The pending-secret contract over real SQL (migrations/0009): arming a re-enrollment writes ONLY
// pending_secret, confirmation promotes it, and confirming with nothing pending is refused — the
// store-level guarantee that an unconfirmed re-enroll cannot disarm 2FA.
func TestPgUserStorePendingTOTP(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := newPgUserStoreT(pool)
	ctx := context.Background()

	old, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	fresh, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := store.SetTOTP(ctx, tid, uid, old, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	// Arming a re-enrollment leaves the ENFORCED secret and confirmed state untouched.
	if err := store.SetPendingTOTP(ctx, tid, uid, fresh); err != nil {
		t.Fatalf("SetPendingTOTP: %v", err)
	}
	u, err := store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if u.TOTPSecret != old || !u.TOTPConfirmed || u.TOTPPending != fresh {
		t.Fatalf("after SetPendingTOTP: secret=%q confirmed=%v pending=%q", u.TOTPSecret, u.TOTPConfirmed, u.TOTPPending)
	}

	// Confirmation promotes pending → enforced and clears the pending slot.
	if err := store.ConfirmPendingTOTP(ctx, tid, uid); err != nil {
		t.Fatalf("ConfirmPendingTOTP: %v", err)
	}
	u, _ = store.FindUserByID(ctx, tid, uid)
	if u.TOTPSecret != fresh || !u.TOTPConfirmed || u.TOTPPending != "" {
		t.Fatalf("after ConfirmPendingTOTP: secret=%q confirmed=%v pending=%q", u.TOTPSecret, u.TOTPConfirmed, u.TOTPPending)
	}

	// With nothing pending, confirmation is a no-op error — it can never re-activate an older
	// secret behind the user's back.
	if err := store.ConfirmPendingTOTP(ctx, tid, uid); !errors.Is(err, ErrNoPendingTOTP) {
		t.Fatalf("ConfirmPendingTOTP with nothing pending = %v, want ErrNoPendingTOTP", err)
	}
	// SetTOTP (the administrative path) clears any pending enrollment.
	if err := store.SetPendingTOTP(ctx, tid, uid, old); err != nil {
		t.Fatalf("SetPendingTOTP 2: %v", err)
	}
	if err := store.SetTOTP(ctx, tid, uid, fresh, true); err != nil {
		t.Fatalf("SetTOTP 2: %v", err)
	}
	if u, _ = store.FindUserByID(ctx, tid, uid); u.TOTPPending != "" {
		t.Fatalf("SetTOTP left a pending secret: %q", u.TOTPPending)
	}
}

func TestPgSessionStoreLifecycle(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()

	store := NewPgSessionStore(pool)
	m := NewSessionManager(store)

	token, sess, err := m.Issue(ctx, tid, uid, time.Time{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("Insert did not set the DB-assigned session id")
	}
	got, err := m.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.UserID != uid || got.TenantID != tid {
		t.Fatalf("validated session mismatch: %+v", got)
	}
	// Revoke → validation fails closed.
	if err := m.Revoke(ctx, token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := m.Validate(ctx, token); err != ErrSessionRevoked {
		t.Fatalf("post-revoke Validate = %v, want ErrSessionRevoked", err)
	}

	// Expired session → ErrSessionExpired. A NEGATIVE TTL does NOT work: ttl() clamps any
	// non-positive TTL to DefaultSessionTTL (defensive — never issue an already-dead session), so
	// `TTL: -time.Minute` would actually mint a 12h-valid session. Force expiry the way
	// TestSessionExpiry does: issue with a positive TTL, then validate with a clock advanced past
	// it. This also genuinely exercises the pgx round-trip of the `expires_at` timestamptz.
	clock := time.Now()
	expM := &SessionManager{Store: store, TTL: time.Minute, Now: func() time.Time { return clock }}
	expTok, _, err := expM.Issue(ctx, tid, uid, time.Time{})
	if err != nil {
		t.Fatalf("Issue expired: %v", err)
	}
	clock = clock.Add(2 * time.Minute) // past the 1-minute TTL
	if _, err := expM.Validate(ctx, expTok); err != ErrSessionExpired {
		t.Fatalf("expired Validate = %v, want ErrSessionExpired", err)
	}

	// Unknown token → ErrSessionNotFound.
	if _, err := m.Validate(ctx, "never-issued"); err != ErrSessionNotFound {
		t.Fatalf("unknown token Validate = %v, want ErrSessionNotFound", err)
	}
}

// End-to-end over pgx: log in by SLUG (privileged bootstrap resolves + pins the tenant), then
// authenticate a follow-up request with the issued token through SessionAuthenticator.
func TestPgLoginBootstrapAndAuthenticate(t *testing.T) {
	pool := newTestPool(t)
	_, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()

	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	auth := &AuthService{Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(pool), Issuer: "RMT"}

	// Wrong password rejected.
	if _, _, err := auth.authenticateLocal(ctx, loginRequest{Tenant: "acme", Email: "tech@acme.test", Password: "wrong"}); err != ErrInvalidCredentials {
		t.Fatalf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	// Correct login resolves the tenant by slug.
	u, tenantID, err := auth.authenticateLocal(ctx, loginRequest{Tenant: "acme", Email: "tech@acme.test", Password: "password-1234"})
	if err != nil {
		t.Fatalf("authenticateLocal: %v", err)
	}
	if tenantID != u.TenantID {
		t.Fatalf("resolved tenant = %q, want %q", tenantID, u.TenantID)
	}
	if u.ID != uid {
		t.Fatalf("logged in user = %s, want %s", u.ID, uid)
	}

	token, _, err := sessions.Issue(ctx, u.TenantID, u.ID, u.CredentialUpdatedAt)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	sa := &SessionAuthenticator{Sessions: sessions, Users: users}
	req := httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	p, err := sa.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != uid {
		t.Fatalf("principal user = %s, want %s", p.UserID, uid)
	}
	if err := p.Grant.Require(CapStartSession); err != nil {
		t.Fatalf("principal grant missing start_session: %v", err)
	}
}

// TOTP end-to-end over pgx, at the HTTP surface (M4): provision → login password-only →
// enroll + confirm TOTP through the protected endpoints (CSRF double-submit included, since
// the requests ride the session cookie) → logout → re-login now REQUIRES the second factor
// (absent and stale codes rejected, current code accepted) → the new session reaches a
// protected route through the full auth → tenant (RLS/PgBinder) chain.
func TestPgTOTPLoginEndToEnd(t *testing.T) {
	pool := newTestPool(t)
	applyAppRoleMigration(t, pool)  // 0005: 0013 below GRANTs to rmt_app, so the role must exist
	applyAttendedMigration(t, pool) // 0013: this test's srv.Machines is a PgMachineStore
	_, _ = provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")

	// The clock advances between successful code-bearing requests on purpose: a TOTP code is
	// accepted ONCE (RFC 6238 §5.2 / migrations/0012), and ALL THREE consumers — login, the enroll
	// step-up and confirmation — spend on that one ledger. So each leg below presents a code from a
	// later time step rather than re-presenting a spent one.
	now := time.Unix(1_700_000_000, 0)
	users := newPgUserStoreT(pool)
	sessions := NewSessionManager(NewPgSessionStore(pool))
	authSvc := &AuthService{
		Users: users, Sessions: sessions, Tenants: NewPgTenantResolver(pool),
		Issuer: "RMT", Now: func() time.Time { return now },
	}
	srv := NewServer(&SessionAuthenticator{Sessions: sessions, Users: users}, NewPgBinder(pool))
	srv.AuthAPI = authSvc
	srv.Machines = NewPgMachineStore(pool)
	h := srv.Handler()

	creds := loginRequest{Tenant: "acme", Email: "tech@acme.test", Password: "password-1234"}

	// 1. No TOTP enrolled yet → password alone logs in.
	login := doJSON(t, h, "POST", "/auth/login", creds, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("password-only login = %d (body %s), want 200", login.Code, login.Body.String())
	}
	cookie := sessionCookieFrom(login)
	csrfCookie, csrfToken := csrfFrom(t, login)

	// 2. Enroll through the protected endpoint (cookie-auth → CSRF pair required).
	enroll := doJSONWith(t, h, "POST", "/auth/totp/enroll",
		enrollTOTPRequest{Password: "password-1234"}, csrfToken, cookie, csrfCookie)
	if enroll.Code != http.StatusOK {
		t.Fatalf("enroll = %d (body %s), want 200", enroll.Code, enroll.Body.String())
	}
	var er struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(enroll.Body.Bytes(), &er); err != nil || er.Secret == "" {
		t.Fatalf("bad enroll payload (err %v): %s", err, enroll.Body.String())
	}

	// 3. Confirm with a code computed from the returned secret.
	code, err := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	confirm := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: code}, csrfToken, cookie, csrfCookie)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm = %d (body %s), want 200", confirm.Code, confirm.Body.String())
	}

	// 4. Logout (also cookie-auth + CSRF); the old session dies server-side.
	if rec := doJSONWith(t, h, "POST", "/auth/logout", nil, csrfToken, cookie, csrfCookie); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", rec.Code)
	}
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /machines = %d, want 401", rec.Code)
	}

	// 5. TOTP is now ENFORCED: password without a code is not enough…
	rec := doJSON(t, h, "POST", "/auth/login", creds, nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("login without code = %d body %s, want 401 totp required", rec.Code, rec.Body.String())
	}
	// …a STALE code (outside the ±1-step skew window) is rejected with the opaque error…
	stale, err := TOTPCode(er.Secret, now.Add(-10*time.Minute), DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode stale: %v", err)
	}
	withCode := creds
	withCode.TOTPCode = stale
	rec = doJSON(t, h, "POST", "/auth/login", withCode, nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), ErrInvalidCredentials.Error()) {
		t.Fatalf("stale-code login = %d body %s, want 401 invalid credentials", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("failed 2FA login must not set a session cookie")
	}
	// …the code that CONFIRMED the enrollment is spent and cannot also authenticate, over real SQL.
	//
	// This leg runs BEFORE the clock advance below, and the ordering is the whole of its value: 90
	// seconds puts `code` outside the ±1-step skew window, so a verify-only confirm handler would
	// have been refused here too — on staleness, not on the ledger. Asserted after the advance, this
	// passes with the defect present. (Measured: it did.)
	spentByConfirm := creds
	spentByConfirm.TOTPCode = code
	if rec := doJSON(t, h, "POST", "/auth/login", spentByConfirm, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the code that confirmed the enrollment = %d (body %s), want 401",
			rec.Code, rec.Body.String())
	}
	// …and a current code completes login. It must come from a LATER step than step 3's
	// confirmation, for the reason just asserted: /auth/totp/confirm SPENDS the code it accepts on
	// the same ledger login reads (auth_totp_confirm_replay_test.go).
	now = now.Add(90 * time.Second)
	loginCode, err := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (after confirmation): %v", err)
	}
	withCode.TOTPCode = loginCode
	relogin := doJSON(t, h, "POST", "/auth/login", withCode, nil)
	if relogin.Code != http.StatusOK {
		t.Fatalf("2FA login = %d (body %s), want 200", relogin.Code, relogin.Body.String())
	}
	cookie2 := sessionCookieFrom(relogin)
	if cookie2 == nil {
		t.Fatal("2FA login did not set a session cookie")
	}

	// 6. The fresh session works against a protected route through PgBinder + RLS.
	if rec := doJSON(t, h, "GET", "/machines", nil, cookie2); rec.Code != http.StatusOK {
		t.Fatalf("authenticated /machines = %d (body %s), want 200", rec.Code, rec.Body.String())
	}

	// 7. Re-enrolling from that session cannot silently downgrade the account: without the
	// CURRENT code it is refused, and the confirmed secret keeps being enforced at login.
	csrfCookie2, csrfToken2 := csrfFrom(t, relogin)
	if bad := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{}, csrfToken2, cookie2, csrfCookie2); bad.Code != http.StatusForbidden {
		t.Fatalf("re-enroll without a code = %d (body %s), want 403", bad.Code, bad.Body.String())
	}
	if rec := doJSON(t, h, "POST", "/auth/login", creds, nil); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("password-only login after refused re-enroll = %d body %s, want 401 totp required", rec.Code, rec.Body.String())
	}
	// With the current code it arms a PENDING secret only — pending_secret in the DB, the old
	// authenticator still the one that logs in. The clock moves on first: `loginCode` was spent by
	// the login in step 5, so this leg uses a code from a later step.
	now = now.Add(90 * time.Second)
	code2, err := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (later step): %v", err)
	}
	reEnroll := doJSONWith(t, h, "POST", "/auth/totp/enroll", enrollTOTPRequest{Code: code2}, csrfToken2, cookie2, csrfCookie2)
	if reEnroll.Code != http.StatusOK {
		t.Fatalf("re-enroll with the current code = %d (body %s)", reEnroll.Code, reEnroll.Body.String())
	}
	var re struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(reEnroll.Body.Bytes(), &re); err != nil || re.Secret == "" || re.Secret == er.Secret {
		t.Fatalf("bad re-enroll payload (err %v): %s", err, reEnroll.Body.String())
	}
	// The OLD authenticator still logs in — with a code from a LATER step, because the re-enroll
	// step-up above SPENT code2 on the same replay ledger login uses. (Presenting code2 here is
	// exactly the cross-endpoint replay auth_totp_reenroll_test.go forbids.)
	now = now.Add(90 * time.Second)
	code3, err := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (old authenticator, later step): %v", err)
	}
	withCode3 := creds
	withCode3.TOTPCode = code3
	if rec := doJSON(t, h, "POST", "/auth/login", withCode3, nil); rec.Code != http.StatusOK {
		t.Fatalf("old authenticator mid-re-enroll = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// The code that login just spent cannot be replayed (RFC 6238 §5.2), over real SQL.
	if rec := doJSON(t, h, "POST", "/auth/login", withCode3, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d (body %s), want 401", rec.Code, rec.Body.String())
	}
	// And the code the RE-ENROLL spent is equally dead at login — one ledger, both endpoints.
	withCode2 := creds
	withCode2.TOTPCode = code2
	if rec := doJSON(t, h, "POST", "/auth/login", withCode2, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the code the re-enroll step-up spent = %d (body %s), want 401",
			rec.Code, rec.Body.String())
	}
	// Confirming the pending secret switches enforcement over to it.
	now = now.Add(90 * time.Second)
	newCode, err := TOTPCode(re.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (re-enrolled): %v", err)
	}
	if rec := doJSONWith(t, h, "POST", "/auth/totp/confirm", confirmTOTPRequest{Code: newCode}, csrfToken2, cookie2, csrfCookie2); rec.Code != http.StatusOK {
		t.Fatalf("confirm re-enrollment = %d (body %s)", rec.Code, rec.Body.String())
	}
	// The confirmation code is spent like any other — it activated the new authenticator and cannot
	// also complete the first login against it.
	spentByReconfirm := creds
	spentByReconfirm.TOTPCode = newCode
	if rec := doJSON(t, h, "POST", "/auth/login", spentByReconfirm, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the code that confirmed the re-enrollment = %d (body %s), want 401",
			rec.Code, rec.Body.String())
	}
	// A code from a later step does log in, so enforcement really did switch to the new secret.
	now = now.Add(90 * time.Second)
	switchedCode, err := TOTPCode(re.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (re-enrolled, later step): %v", err)
	}
	switched := creds
	switched.TOTPCode = switchedCode
	if rec := doJSON(t, h, "POST", "/auth/login", switched, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with the re-enrolled authenticator = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	// The superseded authenticator is refused on its own merits, not merely because its codes were
	// spent: this is a FRESH code from the old secret at a later step, so a 401 can only mean the
	// enforced factor really did switch.
	now = now.Add(90 * time.Second)
	oldFresh, err := TOTPCode(er.Secret, now, DefaultTOTPConfig)
	if err != nil {
		t.Fatalf("TOTPCode (superseded secret): %v", err)
	}
	superseded := creds
	superseded.TOTPCode = oldFresh
	if rec := doJSON(t, h, "POST", "/auth/login", superseded, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("superseded authenticator = %d, want 401", rec.Code)
	}
}

// THE COLUMN ITSELF, read back raw. Every other TOTP test goes through the store, which decrypts on
// the way out — so all of them would pass unchanged if Seal were a no-op. This one bypasses the
// store and asks Postgres what is actually on disk, which is the only question `pg_dump` asks.
//
// `migrations/0002_auth.sql:17-19` instructed this from the beginning; nothing had ever checked it.
func TestPgTOTPSecretIsCiphertextOnDisk(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := newPgUserStoreT(pool)
	ctx := context.Background()

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := store.SetTOTP(ctx, tid, uid, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT secret FROM user_totp WHERE user_id = $1`, uid).Scan(&stored); err != nil {
		t.Fatalf("read raw column: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("the secret column is empty; nothing was stored")
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Fatalf("the base32 secret is on disk verbatim: %q", stored)
	}
	if !hasTOTPEnvelope(stored) {
		t.Fatalf("the stored value is not an encryption envelope: %q", stored)
	}

	// And it still round-trips through the store, so the encryption is not merely destroying it.
	u, err := store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if u.TOTPSecret != secret {
		t.Fatalf("secret did not survive the round trip: got %q want %q", u.TOTPSecret, secret)
	}

	// The PENDING column too — a re-enrollment writes a second secret, and it is exactly as
	// sensitive as the confirmed one. The audit's finding named `secret`; `pending_secret` was added
	// later by 0009 and is the same credential one step earlier.
	pendingSecret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret pending: %v", err)
	}
	if err := store.SetPendingTOTP(ctx, tid, uid, pendingSecret); err != nil {
		t.Fatalf("SetPendingTOTP: %v", err)
	}
	var storedPending []byte
	if err := pool.QueryRow(ctx, `SELECT pending_secret FROM user_totp WHERE user_id = $1`, uid).Scan(&storedPending); err != nil {
		t.Fatalf("read raw pending column: %v", err)
	}
	if bytes.Contains(storedPending, []byte(pendingSecret)) {
		t.Fatalf("the pending base32 secret is on disk verbatim: %q", storedPending)
	}
	if !hasTOTPEnvelope(storedPending) {
		t.Fatalf("the stored pending value is not an encryption envelope: %q", storedPending)
	}

	// Promotion is a DB-side copy of ciphertext (ConfirmPendingTOTP does `secret = pending_secret`),
	// so the promoted secret must still open. This is the step most likely to break under
	// encryption and the one no unit test can reach.
	if err := store.ConfirmPendingTOTP(ctx, tid, uid); err != nil {
		t.Fatalf("ConfirmPendingTOTP: %v", err)
	}
	u, err = store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID after confirm: %v", err)
	}
	if u.TOTPSecret != pendingSecret {
		t.Fatalf("promoted secret did not open: got %q want %q", u.TOTPSecret, pendingSecret)
	}
}

// A secret enrolled BEFORE encryption existed must keep verifying afterwards. Written as raw
// plaintext straight into the column, exactly as a pre-upgrade row looks, then read through a store
// that has a key configured.
//
// This is the no-lockout promise, and it cannot be tested any other way: a store-level write would
// encrypt it and prove nothing.
func TestPgALegacyPlaintextTOTPRowStillVerifies(t *testing.T) {
	pool := newTestPool(t)
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	store := newPgUserStoreT(pool)
	ctx := context.Background()

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_totp (user_id, tenant_id, secret, confirmed_at, pending_secret)
		VALUES ($1, $2, $3, now(), NULL)`, uid, tid, []byte(secret)); err != nil {
		t.Fatalf("plant legacy row: %v", err)
	}

	u, err := store.FindUserByID(ctx, tid, uid)
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if u.TOTPSecret != secret {
		t.Fatalf("a pre-encryption secret did not read back: got %q want %q", u.TOTPSecret, secret)
	}
	if !u.TOTPConfirmed {
		t.Fatal("the legacy row's confirmed_at was lost")
	}
}

// The cause of the bare "FAIL rmt/controlplane" seen on non-verbose pg runs: `ALTER ROLE rmt_app` (0005) edits
// a CLUSTER-WIDE catalog row, so concurrent runs against one server (other worktrees, other databases) lose
// the race with "tuple concurrently updated (XX000)". execScript now reruns the (idempotent) script. This test
// races the role statement from many sessions; without the retry it fails with the XX000.
func TestExecScriptSurvivesCatalogRaces(t *testing.T) {
	pool := newTestPool(t)
	const stmt = `ALTER ROLE rmt_app WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;`
	applyAppRoleMigration(t, pool) // the role exists
	ctx := context.Background()
	errs := make(chan error, 64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if err := execScriptErr(ctx, pool, stmt); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a script lost a catalog race and was not retried: %v", err)
	}
}

func TestIsCatalogRaceMatchesOnlyThatError(t *testing.T) {
	race := &pgconn.PgError{Code: "XX000", Message: "tuple concurrently updated"}
	if !isCatalogRace(race) || !isCatalogRace(fmt.Errorf("wrapped: %w", race)) {
		t.Fatal("the catalog race was not recognized")
	}
	for _, e := range []error{nil, errors.New("tuple concurrently updated"),
		&pgconn.PgError{Code: "XX000", Message: "something else"},
		&pgconn.PgError{Code: "23505", Message: "tuple concurrently updated"}} {
		if isCatalogRace(e) {
			t.Fatalf("%v must not be retried", e)
		}
	}
}
