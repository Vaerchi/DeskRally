package controlplane

// DB-gated integration tests for the enrollment-token store (M1): the SECURITY DEFINER
// cp_enrollment_token_redeem redemption AS the least-privilege rmt_app role, atomic max_uses
// exhaustion, expiry, revocation, and the full public /enroll/redeem chain pinning the agent
// pubkey into machine.pubkey. Like every pgx test these SKIP without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// applyEnrollmentMigration lays 0007 on top of whatever the test has applied (mirrors
// applyTenantProvisionMigration; resetSchema DROPs cp_enrollment_token_redeem first).
func applyEnrollmentMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0007_enrollment.sql")
	if err != nil {
		t.Fatalf("read 0007: %v", err)
	}
	execScript(t, pool, string(b))
}

// applyMachineDeviceUniqueMigration lays 0008 (the GLOBAL unique index on machine.device_id) on
// top of the schema newTestPool applied; the index is dropped with the table by resetSchema.
func applyMachineDeviceUniqueMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0008_machine_device_unique.sql")
	if err != nil {
		t.Fatalf("read 0008: %v", err)
	}
	execScript(t, pool, string(b))
}

// applyEnrollmentTenantActiveMigration lays 0011 (redemption additionally requires the token's
// tenant to be ACTIVE) on top of 0007 — apply applyEnrollmentMigration first; resetSchema DROPs
// cp_enrollment_token_redeem, which this replaces.
func applyEnrollmentTenantActiveMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0011_enrollment_tenant_active.sql")
	if err != nil {
		t.Fatalf("read 0011: %v", err)
	}
	execScript(t, pool, string(b))
}

// applyDeviceIdentityMigration lays 0010 (cp_machine_identity_by_device_id) on top of the schema
// newTestPool applied. It depends on machine.device_id being globally unique, so apply
// applyMachineDeviceUniqueMigration (0008) first; resetSchema DROPs the function.
func applyDeviceIdentityMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0010_device_identity.sql")
	if err != nil {
		t.Fatalf("read 0010: %v", err)
	}
	// 0068 changed the function's RETURN TYPE (it now returns the machine status), so an older definition cannot
	// be CREATE OR REPLACEd over it: drop first, apply the historical file, then land on the LATEST definition.
	execScript(t, pool, `DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);`)
	execScript(t, pool, string(b))
	applyLatestIdentityFunction(t, pool)
}

// applyLatestIdentityFunction (re)creates cp_machine_identity_by_device_id from its LATEST definition, the one
// inside migrations/0068_fleet_directives.sql (suspension, pubkey, ephemeral expiry, plus the status column and
// the removed refusal), WITHOUT the rest of 0068 (which needs tables most tests do not build). Every helper that
// applies an OLDER definition (0010, 0013, 0055) ends with this, so a test never runs against a stale function.
func applyLatestIdentityFunction(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	b, err := os.ReadFile("migrations/0068_fleet_directives.sql")
	if err != nil {
		t.Fatalf("read 0068: %v", err)
	}
	src := string(b)
	const start = "DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);"
	const end = "GRANT EXECUTE ON FUNCTION cp_machine_identity_by_device_id(text) TO PUBLIC;"
	i, j := strings.Index(src, start), strings.Index(src, end)
	if i < 0 || j < i {
		t.Fatal("0068 no longer contains the identity function block this helper extracts")
	}
	block := src[i : j+len(end)]
	// A test that applied only 0010 has no machine.ephemeral yet (0013 adds it); the predicate that reads it
	// is dropped for that schema, exactly as the 0010 definition it stands in for never had it.
	var hasEphemeral bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'machine' AND column_name = 'ephemeral')`).Scan(&hasEphemeral); err != nil {
		t.Fatalf("probe machine.ephemeral: %v", err)
	}
	if !hasEphemeral {
		var kept []string
		for _, line := range strings.Split(block, "\n") {
			if !strings.Contains(line, "m.ephemeral") {
				kept = append(kept, line)
			}
		}
		block = strings.Join(kept, "\n")
	}
	execScript(t, pool, block)
}

// seedGroup adds a machine_group to an existing tenant and returns its id.
func seedGroup(t *testing.T, pool *pgxpool.Pool, tid string) string {
	t.Helper()
	ctx := context.Background()
	var gid string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&gid); err != nil {
		t.Fatalf("gen group uuid: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gid, tid)
		return err
	}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	return gid
}

// TestPgEnrollmentTokenRedeemAsAppRole is the SECURITY DEFINER + RLS posture proof: everything
// runs as rmt_app. Mint/list are tenant-pinned (RLS-scoped); redemption runs pre-tenant on the
// pool — possible only because cp_enrollment_token_redeem executes with its owner's privileges
// — and the single-UPDATE semantics make max_uses exhaustion exact (mint 2, redeem 3× → third
// fails).
func TestPgEnrollmentTokenRedeemAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyEnrollmentMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgEnrollmentTokenStore(appPool)

	tok := &EnrollmentToken{GroupID: gid, CreatedBy: uid, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2}
	plaintext, err := store.MintToken(ctx, tid, tok)
	if err != nil {
		t.Fatalf("MintToken as rmt_app: %v", err)
	}
	if plaintext == "" || tok.ID == "" || tok.CreatedAt.IsZero() || tok.TenantID != tid || tok.Uses != 0 {
		t.Fatalf("minted token = %+v (plaintext %q)", tok, plaintext)
	}

	list, err := store.ListTokens(ctx, tid)
	if err != nil || len(list) != 1 || list[0].ID != tok.ID || list[0].CreatedBy != uid {
		t.Fatalf("ListTokens = %+v, %v", list, err)
	}

	// Sanity: rmt_app cannot read enrollment_token unpinned — the redeem below therefore only
	// works through the SECURITY DEFINER function.
	var n int
	if err := appPool.QueryRow(ctx, "SELECT count(*) FROM enrollment_token").Scan(&n); err == nil {
		t.Fatalf("rmt_app read enrollment_token unpinned (%d rows); RLS must raise", n)
	}

	// Redeem twice (max_uses=2), each returning the row with the incremented use count.
	red1, err := store.RedeemToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("redeem 1: %v", err)
	}
	if red1.TenantID != tid || red1.GroupID != gid || red1.Uses != 1 {
		t.Fatalf("redeem 1 = %+v", red1)
	}
	red2, err := store.RedeemToken(ctx, plaintext)
	if err != nil || red2.Uses != 2 {
		t.Fatalf("redeem 2 = %+v, %v", red2, err)
	}
	// Third redemption: exhausted → the one generic invalid error.
	if _, err := store.RedeemToken(ctx, plaintext); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("redeem 3 err = %v, want ErrEnrollmentTokenInvalid", err)
	}
	// Unknown plaintext → same error.
	if _, err := store.RedeemToken(ctx, "never-minted"); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("unknown token err = %v, want ErrEnrollmentTokenInvalid", err)
	}

	// The DB counted exactly 2 uses (superuser cross-check).
	if err := suPool.QueryRow(ctx,
		"SELECT uses FROM enrollment_token WHERE id = $1::uuid", tok.ID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("stored uses = %d (%v), want 2", n, err)
	}
}

// TestPgEnrollmentTokenExpiryAndRevocation: an expired or revoked token redeems as the same
// generic invalid; revocation is idempotent and 404s on an unknown id.
func TestPgEnrollmentTokenExpiryAndRevocation(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyEnrollmentMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgEnrollmentTokenStore(appPool)

	// Expired at mint time.
	expired := &EnrollmentToken{GroupID: gid, CreatedBy: uid, ExpiresAt: time.Now().Add(-time.Minute), MaxUses: 1}
	plainExpired, err := store.MintToken(ctx, tid, expired)
	if err != nil {
		t.Fatalf("mint expired: %v", err)
	}
	if _, err := store.RedeemToken(ctx, plainExpired); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("expired redeem err = %v, want ErrEnrollmentTokenInvalid", err)
	}

	// Revoked before use.
	revoked := &EnrollmentToken{GroupID: gid, CreatedBy: uid, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}
	plainRevoked, err := store.MintToken(ctx, tid, revoked)
	if err != nil {
		t.Fatalf("mint revoked: %v", err)
	}
	if err := store.RevokeToken(ctx, tid, revoked.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if err := store.RevokeToken(ctx, tid, revoked.ID); err != nil {
		t.Fatalf("re-RevokeToken = %v, want nil (idempotent)", err)
	}
	if _, err := store.RedeemToken(ctx, plainRevoked); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("revoked redeem err = %v, want ErrEnrollmentTokenInvalid", err)
	}
	if err := store.RevokeToken(ctx, tid, newUUID()); !errors.Is(err, ErrEnrollmentTokenNotFound) {
		t.Fatalf("revoke unknown err = %v, want ErrEnrollmentTokenNotFound", err)
	}
	// Listing reflects both tokens' revocation state.
	list, err := store.ListTokens(ctx, tid)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListTokens = %+v, %v", list, err)
	}
	for _, e := range list {
		if e.ID == revoked.ID && !e.Revoked {
			t.Fatalf("revoked token listed unrevoked: %+v", e)
		}
		if e.ID == expired.ID && e.Revoked {
			t.Fatalf("expired-but-unrevoked token listed revoked: %+v", e)
		}
	}
}

// TestPgRedeemEnrollChainAsAppRole is the end-to-end DB proof of the public redemption path:
// mint over HTTP as an authenticated owner, then POST /enroll/redeem UNAUTHENTICATED as
// rmt_app — the machine lands tenant-pinned with the Ed25519 pubkey genuinely stored in
// machine.pubkey (verified via superuser), a duplicate device_id conflicts 409, and the audit
// trail records machine.enroll with an empty actor.
func TestPgRedeemEnrollChainAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyEnrollmentMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool) // PgMgmtAuditStore writes chained rows (0014)
	applyAttendedMigration(t, suPool)       // 0013: machine.ephemeral, which 0068's identity function reads
	applyFleetDirectiveMigration(t, suPool) // 0068: the public redeem path asks cp_machine_key_removed (D-C9)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	principal := &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: principal}, NewPgBinder(appPool))
	srv.Machines = NewPgMachineStore(appPool)
	srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
	srv.EnrollmentTokens = NewPgEnrollmentTokenStore(appPool)

	var minted struct {
		Token           string          `json:"token"`
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens",
		`{"group_id":"`+gid+`","max_uses":3}`, &minted); code != http.StatusCreated {
		t.Fatalf("mint = %d", code)
	}
	if minted.Token == "" || minted.EnrollmentToken.TenantID != tid {
		t.Fatalf("minted = %+v", minted)
	}

	pubHex := testPubkeyHex(t)
	var redeemed struct {
		Machine Machine `json:"machine"`
	}
	const reportedOS = "Windows 11 Pro 25H2 (build 26200)"
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+minted.Token+`","device_id":"pg-redeem-dev","pubkey":"`+pubHex+`","name":"PGKIOSK","os":"`+reportedOS+`"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("redeem = %d", code)
	}
	m := redeemed.Machine
	// The caller-supplied device_id is ignored; the identity is minted server-side.
	if m.ID == "" || m.TenantID != tid || m.GroupID != gid || m.DeviceID == "" ||
		m.DeviceID == "pg-redeem-dev" || m.Pubkey != pubHex {
		t.Fatalf("redeemed machine = %+v", m)
	}

	// The pubkey round-tripped into machine.pubkey — superuser (RLS-bypassing) cross-check.
	var storedHex string
	if err := suPool.QueryRow(ctx,
		"SELECT encode(pubkey, 'hex') FROM machine WHERE tenant_id = $1::uuid AND device_id = $2",
		tid, m.DeviceID).Scan(&storedHex); err != nil {
		t.Fatalf("superuser pubkey read: %v", err)
	}
	if storedHex != pubHex {
		t.Fatalf("machine.pubkey = %s, want %s", storedHex, pubHex)
	}
	// machine.os round-tripped through the REAL INSERT, cross-checked as superuser. The in-memory
	// sibling test (TestRedeemEnrollmentPersistsReportedOS) cannot deliver this particular
	// guarantee: its fake store keeps whatever struct it is handed, so a pgstore INSERT that
	// omitted the `os` column would still pass there. This is the assertion that catches it.
	var storedOS string
	if err := suPool.QueryRow(ctx,
		"SELECT os FROM machine WHERE tenant_id = $1::uuid AND device_id = $2",
		tid, m.DeviceID).Scan(&storedOS); err != nil {
		t.Fatalf("superuser os read: %v", err)
	}
	if storedOS != reportedOS {
		t.Fatalf("machine.os = %q, want %q", storedOS, reportedOS)
	}
	// Nothing was ever stored under the name the redeemer asked for.
	var n int
	if err := suPool.QueryRow(ctx,
		"SELECT count(*) FROM machine WHERE device_id = 'pg-redeem-dev'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("caller-chosen device id landed in the DB (%d rows, err %v)", n, err)
	}

	// A second redemption of the same token mints a DIFFERENT machine rather than colliding.
	var second struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+minted.Token+`","device_id":"pg-redeem-dev","pubkey":"`+pubHex+`"}`, &second); code != http.StatusCreated {
		t.Fatalf("second redeem = %d, want 201", code)
	}
	if second.Machine.DeviceID == m.DeviceID {
		t.Fatalf("two redemptions minted the same device id %q", m.DeviceID)
	}

	// machine.enroll audited with an EMPTY actor (NULL actor_user_id) + token/device metadata.
	var actor *string
	var meta []byte
	if err := suPool.QueryRow(ctx, `
		SELECT actor_user_id::text, metadata FROM audit_event
		WHERE tenant_id = $1::uuid AND action = 'machine.enroll' AND metadata->>'device_id' = $2`,
		tid, m.DeviceID).Scan(&actor, &meta); err != nil {
		t.Fatalf("superuser audit read: %v", err)
	}
	if actor != nil {
		t.Fatalf("machine.enroll actor = %v, want NULL (unauthenticated redemption)", *actor)
	}
	if !containsJSONField(meta, "token_id", minted.EnrollmentToken.ID) ||
		!containsJSONField(meta, "device_id", m.DeviceID) {
		t.Fatalf("machine.enroll metadata = %s, want token_id + device_id %s", meta, m.DeviceID)
	}
}

// TestPgRedeemRefusedForSuspendedTenant is the proof for migrations/0011. Suspending a tenant
// already locks its humans out (cp_resolve_tenant_by_slug refuses a disabled tenant at login);
// before 0011 the same suspension did nothing to enrollment, so a token minted while the tenant was
// active kept admitting new agents into it indefinitely. The token here is deliberately created
// BEFORE the suspension, which is exactly the case the old function let through.
func TestPgRedeemRefusedForSuspendedTenant(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyEnrollmentMigration(t, suPool)
	applyEnrollmentTenantActiveMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	store := NewPgEnrollmentTokenStore(appPool)

	tok := &EnrollmentToken{GroupID: gid, CreatedBy: uid, ExpiresAt: time.Now().Add(time.Hour), MaxUses: 5}
	plaintext, err := store.MintToken(ctx, tid, tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	// Control: while the tenant is active the token redeems normally.
	if _, err := store.RedeemToken(ctx, plaintext); err != nil {
		t.Fatalf("redeem before suspension: %v", err)
	}

	// Suspend the tenant. The tenant table has FORCE RLS and a self-scoped policy, so even the
	// superuser pool must pin the tenant to touch its own row.
	if err := withTenant(ctx, suPool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant SET disabled_at = now() WHERE id = $1::uuid`, tid)
		return err
	}); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}

	// The same still-valid, still-unexhausted token is now refused — with the same generic error
	// every other invalid token gets, so a redeemer cannot tell suspension from a bad token.
	if _, err := store.RedeemToken(ctx, plaintext); !errors.Is(err, ErrEnrollmentTokenInvalid) {
		t.Fatalf("redeem after suspension = %v, want ErrEnrollmentTokenInvalid", err)
	}
	// And the refusal did NOT consume a use (the UPDATE matched no row at all).
	var uses int
	if err := suPool.QueryRow(ctx,
		"SELECT uses FROM enrollment_token WHERE id = $1::uuid", tok.ID).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("stored uses = %d (%v), want 1 — a refused redemption must not consume one", uses, err)
	}

	// Re-enabling the tenant restores enrollment: suspension is a state, not a token mutation.
	if err := withTenant(ctx, suPool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenant SET disabled_at = NULL WHERE id = $1::uuid`, tid)
		return err
	}); err != nil {
		t.Fatalf("re-enable tenant: %v", err)
	}
	if _, err := store.RedeemToken(ctx, plaintext); err != nil {
		t.Fatalf("redeem after re-enabling: %v", err)
	}
}

// TestPgMachineDeviceIDGloballyUnique is the schema proof for migrations/0008: the same device_id
// cannot exist in two tenants, so a tenant can never enroll a machine carrying ANOTHER tenant's
// device id and mint a session ticket the signaling server would broker to that tenant's agent.
func TestPgMachineDeviceIDGloballyUnique(t *testing.T) {
	suPool := newTestPool(t) // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, suPool)
	applyMachineDeviceUniqueMigration(t, suPool)
	applyAttendedMigration(t, suPool) // 0013: PgMachineStore projects machine.ephemeral
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "tenant-a", "tech@a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "tenant-b", "tech@b.test", "password-1234")
	gidA, gidB := seedGroup(t, suPool, tidA), seedGroup(t, suPool, tidB)

	// As the RLS-subject app role: the superuser pool would BYPASS the policies and see both
	// tenants' rows, which is exactly what the visibility assertion below must not rely on.
	store := NewPgMachineStore(newAppRolePool(t, ctx))
	victim := &Machine{DeviceID: newUUID(), GroupID: gidA, Name: "victim"}
	if err := store.EnrollMachine(ctx, tidA, victim); err != nil {
		t.Fatalf("EnrollMachine (tenant A): %v", err)
	}

	// Tenant B claiming tenant A's device id is rejected — the whole cross-tenant ticket path
	// starts with being able to create this row.
	impostor := &Machine{DeviceID: victim.DeviceID, GroupID: gidB, Name: "impostor"}
	if err := store.EnrollMachine(ctx, tidB, impostor); !errors.Is(err, ErrMachineDeviceIDTaken) {
		t.Fatalf("cross-tenant enroll err = %v, want ErrMachineDeviceIDTaken", err)
	}
	// …and tenant B still cannot resolve (or ticket for) the device.
	if _, err := store.GetMachine(ctx, tidB, victim.DeviceID); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("tenant B resolved tenant A's device: %v", err)
	}
	// Superuser cross-check (RLS-bypassing): exactly one row carries that device id, anywhere.
	var n int
	if err := suPool.QueryRow(ctx, "SELECT count(*) FROM machine WHERE device_id = $1", victim.DeviceID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("machine rows for the device id = %d (%v), want exactly 1", n, err)
	}
}

// containsJSONField reports whether the raw JSON object carries key with the given string value.
func containsJSONField(raw []byte, key, value string) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	v, ok := m[key].(string)
	return ok && v == value
}
