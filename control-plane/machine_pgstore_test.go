package controlplane

// Integration test for PgMachineStore. Like the other pgx tests it requires a live PostgreSQL and
// SKIPS (green) when TEST_DATABASE_URL is unset — so the default `go test ./...` never needs a
// database. Run with:
//
//	TEST_DATABASE_URL=postgres://user:pass@localhost:5432/rmt_test go test ./...
//
// Reuses newTestPool / provisionUser / withTenant from pgstore_test.go + pgstore.go (same package).
//
// These tests deliberately DISTINGUISH the two machine identifiers (0001_core.sql): the primary
// key `machine.id` (DB-assigned) and the stable agent identity `machine.device_id`. GetMachine
// resolves BY DEVICE ID (the identity the mint/session path carries); GetMachineByID resolves BY
// PK. They only pass with the `WHERE device_id` fix — the pre-fix `WHERE id` code resolves the two
// identifiers exactly backwards.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPgMachineStore(t *testing.T) {
	pool := newTestPool(t)          // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, pool)  // 0005: 0013 below GRANTs to rmt_app, so the role must exist
	applyAttendedMigration(t, pool) // 0013: PgMachineStore projects machine.ephemeral/expires_at
	tid, _ := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()

	// A machine's group must exist first (composite FK machine(tenant_id, group_id) →
	// machine_group(tenant_id, id)). Client-generate the ids, pinned to the tenant. deviceID is
	// generated INDEPENDENTLY of the machine's PK (which the DB assigns), so id != device_id.
	var gid, deviceID, unknown string
	if err := pool.QueryRow(ctx,
		"SELECT gen_random_uuid()::text, gen_random_uuid()::text, gen_random_uuid()::text",
	).Scan(&gid, &deviceID, &unknown); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gid, tid)
		return err
	}); err != nil {
		t.Fatalf("insert machine_group: %v", err)
	}

	store := NewPgMachineStore(pool)

	m := &Machine{DeviceID: deviceID, GroupID: gid, Name: "host-1"}
	if err := store.EnrollMachine(ctx, tid, m); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	// The DB assigned a primary key, read back into m.ID, and it is DISTINCT from device_id.
	if m.ID == "" || m.ID == deviceID {
		t.Fatalf("assigned PK id = %q, want a distinct non-empty uuid (device_id = %q)", m.ID, deviceID)
	}
	pk := m.ID

	// GetMachine resolves BY DEVICE ID.
	got, err := store.GetMachine(ctx, tid, deviceID)
	if err != nil {
		t.Fatalf("GetMachine(deviceID): %v", err)
	}
	if got.ID != pk || got.DeviceID != deviceID || got.GroupID != gid || got.TenantID != tid || got.Name != "host-1" {
		t.Fatalf("GetMachine = %+v, want id=%s device=%s group=%s tenant=%s name=host-1", got, pk, deviceID, gid, tid)
	}

	// GetMachineByID resolves BY PRIMARY KEY.
	byID, err := store.GetMachineByID(ctx, tid, pk)
	if err != nil || byID.DeviceID != deviceID {
		t.Fatalf("GetMachineByID(pk) = %+v, %v; want the enrolled machine", byID, err)
	}

	list, err := store.ListMachines(ctx, tid)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(list) != 1 || list[0].ID != pk || list[0].DeviceID != deviceID {
		t.Fatalf("ListMachines = %+v, want exactly the one enrolled machine (id=%s device=%s)", list, pk, deviceID)
	}

	// THE BUG GUARD: identifiers do not cross over.
	//   - GetMachine (device-id semantics) must REJECT the PK value (device_id lookup ≠ id).
	if _, err := store.GetMachine(ctx, tid, pk); err != ErrMachineNotFound {
		t.Fatalf("GetMachine(pk) err = %v, want ErrMachineNotFound (WHERE device_id must not match the PK)", err)
	}
	//   - GetMachineByID (pk semantics) must REJECT the device id.
	if _, err := store.GetMachineByID(ctx, tid, deviceID); err != ErrMachineNotFound {
		t.Fatalf("GetMachineByID(deviceID) err = %v, want ErrMachineNotFound", err)
	}
	// Unknown id → ErrMachineNotFound (RLS-scoped, strict).
	if _, err := store.GetMachine(ctx, tid, unknown); err != ErrMachineNotFound {
		t.Fatalf("unknown machine err = %v, want ErrMachineNotFound", err)
	}
}

// TestPgMintFlowResolvesGroupByDeviceID drives the SECURITY-CRITICAL path end-to-end against
// Postgres: enroll a real machine (distinct PK + device id) in group G, then POST /grant/mint with
// machine_id = the DEVICE ID and assert the grant is minted for group G's capabilities. It also
// asserts that minting for the PK value is rejected 404. This is the test that proves the real bug
// is fixed: with the pre-fix `WHERE id` lookup, mint-by-device-id would 404 (machine "not found")
// and mint-by-pk would succeed — exactly inverted from correct.
func TestPgMintFlowResolvesGroupByDeviceID(t *testing.T) {
	pool := newTestPool(t)          // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, pool)  // 0005: 0013 below GRANTs to rmt_app, so the role must exist
	applyAttendedMigration(t, pool) // 0013: PgMachineStore projects machine.ephemeral/expires_at
	tid, uid := provisionUser(t, pool, "acme", "tech@acme.test", "password-1234")
	ctx := context.Background()

	// deviceID must be a UUID: the mint path encodes machine_id into the signed grant as a uuid.
	var gid, deviceID string
	if err := pool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&gid, &deviceID); err != nil {
		t.Fatalf("gen uuids: %v", err)
	}
	if err := withTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO machine_group (id, tenant_id, name) VALUES ($1,$2,'G')`, gid, tid)
		return err
	}); err != nil {
		t.Fatalf("insert machine_group: %v", err)
	}

	store := NewPgMachineStore(pool)
	m := &Machine{DeviceID: deviceID, GroupID: gid, Name: "host-1"}
	if err := store.EnrollMachine(ctx, tid, m); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	if m.ID == "" || m.ID == deviceID {
		t.Fatalf("assigned PK id = %q, want distinct from device id %q", m.ID, deviceID)
	}

	// Owner over all groups so capability never blocks — the mint must resolve the group from the
	// stored machine (looked up by device id). The store manages its own tenant pinning, so the
	// server's binder can be a no-op.
	p := &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv := NewServer(StubAuthenticator{Principal: p}, NoopBinder{})
	srv.Grants = iss
	srv.Machines = store

	rec := postMint(t, srv, mintGrantRequest{MachineID: deviceID})
	if rec.Code != http.StatusOK {
		t.Fatalf("mint(deviceID) status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sg.Claims.Grant.MachineID != deviceID {
		t.Fatalf("grant machine_id = %q, want device id %q (H3 binding)", sg.Claims.Grant.MachineID, deviceID)
	}
	if caps := capSet(sg.Claims.Grant.Capabilities); !caps[BackSystemInfoRead] || !caps[BackShellAsSystem] {
		t.Fatalf("expected owner-tier caps for the resolved group G: %v", sg.Claims.Grant.Capabilities)
	}

	// Minting for the PK value (as if the caller mistakenly passed the primary key) must 404:
	// GetMachine looks up by device_id, and the PK is not a device_id.
	rec = postMint(t, srv, mintGrantRequest{MachineID: m.ID})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("mint(pk) status = %d, want 404 (device_id resolution must not match the PK)", rec.Code)
	}
}

// TestPgLookupDeviceIdentity is the DB proof for M3's cross-tenant identity lookup
// (migrations/0010). It runs as the RLS-SUBJECT rmt_app role, which is the whole point: a plain
// SELECT on `machine` without a pinned tenant is impossible for that role, so a green result here
// means the SECURITY DEFINER function really is doing the work. It also asserts that a machine
// enrolled WITHOUT a pinned key is reported as unknown, and that the answer carries the tenant of
// the machine — not of whoever asked.
func TestPgLookupDeviceIdentity(t *testing.T) {
	suPool := newTestPool(t) // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, suPool)
	applyMachineDeviceUniqueMigration(t, suPool)
	applyDeviceIdentityMigration(t, suPool)
	ctx := context.Background()

	tidA, _ := provisionUser(t, suPool, "tenant-a", "tech@a.test", "password-1234")
	tidB, _ := provisionUser(t, suPool, "tenant-b", "tech@b.test", "password-1234")
	gidA, gidB := seedGroup(t, suPool, tidA), seedGroup(t, suPool, tidB)

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)

	pubHex := testPubkeyHex(t)
	pinned := &Machine{DeviceID: newUUID(), GroupID: gidA, Name: "pinned", Pubkey: pubHex}
	if err := store.EnrollMachine(ctx, tidA, pinned); err != nil {
		t.Fatalf("EnrollMachine (pinned): %v", err)
	}
	// The legacy authenticated /enroll path: no key pinned.
	unpinned := &Machine{DeviceID: newUUID(), GroupID: gidB, Name: "unpinned"}
	if err := store.EnrollMachine(ctx, tidB, unpinned); err != nil {
		t.Fatalf("EnrollMachine (unpinned): %v", err)
	}

	// Sanity: rmt_app genuinely cannot read `machine` unpinned, so the lookup below can only be
	// working through the SECURITY DEFINER function.
	var n int
	if err := appPool.QueryRow(ctx, "SELECT count(*) FROM machine").Scan(&n); err == nil {
		t.Fatalf("rmt_app read machine unpinned (%d rows); RLS must raise", n)
	}

	got, err := store.LookupDeviceIdentity(ctx, pinned.DeviceID)
	if err != nil {
		t.Fatalf("LookupDeviceIdentity: %v", err)
	}
	if got.DeviceID != pinned.DeviceID || got.TenantID != tidA || got.Pubkey != pubHex {
		t.Fatalf("identity = %+v, want device %s tenant %s pubkey %s", got, pinned.DeviceID, tidA, pubHex)
	}
	// An enrolled machine with no pinned key is unauthenticatable BY DESIGN — indistinguishable
	// from an unknown device id, never a machine with an empty key to fall back on trusting.
	if _, err := store.LookupDeviceIdentity(ctx, unpinned.DeviceID); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("unpinned identity err = %v, want ErrMachineNotFound", err)
	}
	if _, err := store.LookupDeviceIdentity(ctx, newUUID()); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("unknown identity err = %v, want ErrMachineNotFound", err)
	}
	if _, err := store.LookupDeviceIdentity(ctx, ""); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("empty device id err = %v, want ErrMachineNotFound", err)
	}
	// The PK is not a device id (the same identifier guard the rest of this file enforces).
	if _, err := store.LookupDeviceIdentity(ctx, pinned.ID); !errors.Is(err, ErrMachineNotFound) {
		t.Fatalf("LookupDeviceIdentity(pk) err = %v, want ErrMachineNotFound", err)
	}
}

// TestPgDeviceIdentityEndpointAsAppRole drives the full HTTP surface against Postgres as rmt_app:
// the signaling server presents the service token and receives the tenant + pinned key, while a
// caller without the token learns nothing.
func TestPgDeviceIdentityEndpointAsAppRole(t *testing.T) {
	suPool := newTestPool(t) // skips when no TEST_DATABASE_URL
	applyAppRoleMigration(t, suPool)
	applyMachineDeviceUniqueMigration(t, suPool)
	applyDeviceIdentityMigration(t, suPool)
	ctx := context.Background()

	tid, _ := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)

	appPool := newAppRolePool(t, ctx)
	store := NewPgMachineStore(appPool)
	pubHex := testPubkeyHex(t)
	m := &Machine{DeviceID: newUUID(), GroupID: gid, Name: "host-1", Pubkey: pubHex}
	if err := store.EnrollMachine(ctx, tid, m); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	// No authenticated principal: the route deliberately sits outside the auth → tenant chain.
	srv := NewServer(StubAuthenticator{Principal: nil}, NewPgBinder(appPool))
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.DisableThrottle = true

	rec := getIdentity(t, srv, m.DeviceID, "Bearer "+deviceIdentityToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("identity endpoint = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	var got DeviceIdentity
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.DeviceID != m.DeviceID || got.TenantID != tid || got.Pubkey != pubHex {
		t.Fatalf("identity = %+v, want device %s tenant %s pubkey %s", got, m.DeviceID, tid, pubHex)
	}
	if rec := getIdentity(t, srv, m.DeviceID, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tokenless identity endpoint = %d, want 401", rec.Code)
	}
}
