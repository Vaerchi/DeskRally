package controlplane

// D1 tests — the machine repository and the security fix that resolves a machine's group from
// stored data instead of the request body. In-memory throughout (the pgx path is exercised,
// gated behind TEST_DATABASE_URL, in machine_pgstore_test.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Canonical UUIDs the mint path requires (they flow into the signed grant preimage). A machine has
// TWO distinct identifiers: machineInGroupG is the DEVICE ID (the stable agent identity the mint /
// start-session path carries and H3 binds the grant to), pkInGroupG is the DATABASE PRIMARY KEY.
// They are intentionally different so the tests catch the id-vs-device_id confusion: GetMachine
// (device-id semantics) must resolve the device id and REJECT the pk value, and vice versa.
const (
	machineInGroupG = "66666666-6666-4666-8666-666666666666" // device id (agent identity)
	pkInGroupG      = "77777777-7777-4777-8777-777777777777" // primary key (distinct from device id)
	groupG          = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	groupG2         = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

// strictGrantServer wires a real issuer (golden seed) + a caller-supplied (strict) machine store.
func strictGrantServer(p *Principal, machines MachineStore) *Server {
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		panic(err)
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Grants = iss
	srv.Machines = machines
	return srv
}

// -------------------------------------------------------------------------------------
// Store behaviour: strict vs permissive.
// -------------------------------------------------------------------------------------

func TestInMemoryMachineStoreEnrollGetList(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryMachineStore()

	// Enroll with a PK id AND a DIFFERENT device id.
	if err := store.EnrollMachine(ctx, "tenant-1", &Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG, Name: "host-1"}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	// GetMachine resolves BY DEVICE ID.
	got, err := store.GetMachine(ctx, "tenant-1", machineInGroupG)
	if err != nil {
		t.Fatalf("GetMachine(deviceID): %v", err)
	}
	if got.GroupID != groupG {
		t.Fatalf("resolved group = %q, want %q", got.GroupID, groupG)
	}
	if got.TenantID != "tenant-1" {
		t.Fatalf("tenant = %q, want tenant-1", got.TenantID)
	}
	if got.ID != pkInGroupG || got.DeviceID != machineInGroupG {
		t.Fatalf("identity = id:%q device:%q, want id:%q device:%q", got.ID, got.DeviceID, pkInGroupG, machineInGroupG)
	}

	// GetMachineByID resolves BY PRIMARY KEY.
	byID, err := store.GetMachineByID(ctx, "tenant-1", pkInGroupG)
	if err != nil || byID.DeviceID != machineInGroupG {
		t.Fatalf("GetMachineByID(pk) = %+v, %v; want the enrolled machine", byID, err)
	}

	list, err := store.ListMachines(ctx, "tenant-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListMachines = %v, %v; want 1 machine", list, err)
	}

	// THE BUG GUARD: the two identifiers do not cross over.
	//   - GetMachine (device-id semantics) must REJECT the pk value...
	if _, err := store.GetMachine(ctx, "tenant-1", pkInGroupG); err != ErrMachineNotFound {
		t.Fatalf("GetMachine(pk) err = %v, want ErrMachineNotFound (device_id lookup must not match the PK)", err)
	}
	//   - ...and GetMachineByID (pk semantics) must REJECT the device id.
	if _, err := store.GetMachineByID(ctx, "tenant-1", machineInGroupG); err != ErrMachineNotFound {
		t.Fatalf("GetMachineByID(deviceID) err = %v, want ErrMachineNotFound", err)
	}

	// Strict: an unknown id (and another tenant) → ErrMachineNotFound.
	if _, err := store.GetMachine(ctx, "tenant-1", groupG2); err != ErrMachineNotFound {
		t.Fatalf("unknown machine err = %v, want ErrMachineNotFound", err)
	}
	if _, err := store.GetMachine(ctx, "other-tenant", machineInGroupG); err != ErrMachineNotFound {
		t.Fatalf("cross-tenant machine err = %v, want ErrMachineNotFound", err)
	}
}

// A device id belongs to exactly ONE tenant (the global unique index in migrations/0008, mirrored
// by the fake). Without that, a tenant could enroll a machine carrying another tenant's device id
// and mint a session ticket the signaling server would broker to that tenant's agent.
func TestInMemoryMachineStoreDeviceIDGloballyUnique(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryMachineStore()

	if err := store.EnrollMachine(ctx, "tenant-victim", &Machine{DeviceID: machineInGroupG, GroupID: groupG}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	err := store.EnrollMachine(ctx, "tenant-attacker", &Machine{DeviceID: machineInGroupG, GroupID: groupG2})
	if err != ErrMachineDeviceIDTaken {
		t.Fatalf("cross-tenant enroll err = %v, want ErrMachineDeviceIDTaken", err)
	}
	if _, err := store.GetMachine(ctx, "tenant-attacker", machineInGroupG); err != ErrMachineNotFound {
		t.Fatalf("attacker tenant resolved the victim's device: %v", err)
	}
	// The same tenant re-enrolling its own device id is still the in-tenant conflict.
	if err := store.EnrollMachine(ctx, "tenant-victim", &Machine{DeviceID: machineInGroupG, GroupID: groupG}); err != ErrMachineDeviceIDTaken {
		t.Fatalf("in-tenant duplicate err = %v, want ErrMachineDeviceIDTaken", err)
	}
}

func TestPermissiveMachineStoreUnknownResolvesToDefault(t *testing.T) {
	ctx := context.Background()
	store := NewPermissiveMachineStore(DevDefaultMachineGroupID)

	// Any unknown id resolves (DEV-only) to a synthetic machine in the default group — never an
	// error — so dev/e2e minting for a fresh device works without a prior enroll.
	m, err := store.GetMachine(ctx, "tenant-1", "any-unenrolled-device")
	if err != nil {
		t.Fatalf("permissive GetMachine returned error: %v", err)
	}
	if m.GroupID != DevDefaultMachineGroupID {
		t.Fatalf("permissive default group = %q, want %q", m.GroupID, DevDefaultMachineGroupID)
	}

	// An explicitly enrolled machine (resolved by device id) still wins over the fallback.
	if err := store.EnrollMachine(ctx, "tenant-1", &Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	m, _ = store.GetMachine(ctx, "tenant-1", machineInGroupG)
	if m.GroupID != groupG {
		t.Fatalf("enrolled machine group = %q, want %q", m.GroupID, groupG)
	}
}

// -------------------------------------------------------------------------------------
// handleMintGrant: the group is resolved from the store, and an unknown machine is rejected.
// -------------------------------------------------------------------------------------

func TestMintResolvesGroupFromStore(t *testing.T) {
	// Technician scoped ONLY to group G. The machine is enrolled in G, so the resolved group is
	// covered → a grant is minted (read + operator tiers).
	p := &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(RoleTechnician, Groups(groupG))),
	}
	store := NewInMemoryMachineStore()
	// Enrolled with a distinct PK and device id; the mint resolves BY DEVICE ID.
	_ = store.EnrollMachine(context.Background(), "tenant-123", &Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG})

	srv := strictGrantServer(p, store)
	rec := postMint(t, srv, mintGrantRequest{MachineID: machineInGroupG})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sg.Claims.Grant.MachineID != machineInGroupG {
		t.Fatalf("machine_id = %q, want %q (H3 binding preserved)", sg.Claims.Grant.MachineID, machineInGroupG)
	}
	got := capSet(sg.Claims.Grant.Capabilities)
	if !got[BackSystemInfoRead] || !got[BackProcessKill] {
		t.Fatalf("expected read+operator caps for the resolved group: %v", sg.Claims.Grant.Capabilities)
	}
}

// TestMintRefusesAnOutOfServiceMachine pins the hole loop 88's adversarial review found: the
// operator's quarantine switch reached handleStartSession and (as of loop 88) handleMintElevation,
// but NOT this endpoint — so a technician refused an elevation grant on a machine quarantined
// mid-incident could still mint a BACKSTAGE grant against the same box, which carries strictly more
// capability and a longer TTL. Both are privilege issued against a machine the operator has pulled
// out of service.
//
// Both statuses, because a test that pinned only one would let the other be dropped. The PREMISE —
// the same caller and the same machine DO mint when the machine is active — is asserted last and
// locally, so a 409 from some unrelated cause cannot masquerade as this refusal.
func TestMintRefusesAnOutOfServiceMachine(t *testing.T) {
	for _, status := range []string{MachineStatusQuarantined, MachineStatusRetired} {
		t.Run(status, func(t *testing.T) {
			p := &Principal{
				UserID:   techUserUUID,
				TenantID: "tenant-123",
				Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(RoleTechnician, Groups(groupG))),
			}
			store := NewInMemoryMachineStore()
			_ = store.EnrollMachine(context.Background(), "tenant-123",
				&Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG, Status: status})

			srv := strictGrantServer(p, store)
			rec := postMint(t, srv, mintGrantRequest{MachineID: machineInGroupG})
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 — a %s machine must not be handed a backstage grant (body %s)",
					rec.Code, status, rec.Body.String())
			}
			// WHICH refusal, not merely that something refused: this handler also answers 404 and 403.
			if !strings.Contains(rec.Body.String(), status) {
				t.Fatalf("refused for some OTHER reason than the machine status: %s", rec.Body.String())
			}

			// PREMISE, declared locally: the identical request against an ACTIVE machine mints.
			active := NewInMemoryMachineStore()
			_ = active.EnrollMachine(context.Background(), "tenant-123",
				&Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG, Status: MachineStatusActive})
			ok := postMint(t, strictGrantServer(p, active), mintGrantRequest{MachineID: machineInGroupG})
			if ok.Code != http.StatusOK {
				t.Fatalf("premise not met: an ACTIVE machine = %d, want 200 (body %s)", ok.Code, ok.Body.String())
			}
		})
	}
}

// TestMintIgnoresBodyMachineGroup is the D1 security proof. The caller holds:
//   - Technician over group G   (backstage_shell, but NOT manage_machines → no admin tier)
//   - Admin      over group G2  (backstage_shell + manage_machines     → admin tier)
//
// The machine is really in group G. The request LIES, sending machine_group_id = G2. If the
// handler trusted the body it would resolve caps for G2 and hand out the admin tier. Because the
// group is resolved from the stored machine (G) instead, the minted grant must carry NO admin-tier
// capabilities.
func TestMintIgnoresBodyMachineGroup(t *testing.T) {
	p := &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant: NewGrant(techUserUUID, "tenant-123",
			NewMembership(RoleTechnician, Groups(groupG)),
			NewMembership(RoleAdmin, Groups(groupG2)),
		),
	}
	store := NewInMemoryMachineStore()
	_ = store.EnrollMachine(context.Background(), "tenant-123", &Machine{ID: pkInGroupG, DeviceID: machineInGroupG, GroupID: groupG})

	srv := strictGrantServer(p, store)
	// The body names G2 (where the caller is admin) — this must be ignored.
	rec := postMint(t, srv, mintGrantRequest{MachineID: machineInGroupG, MachineGroupID: groupG2})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := capSet(sg.Claims.Grant.Capabilities)
	// Read/operator present (backstage_shell in G)...
	if !got[BackSystemInfoRead] || !got[BackProcessKill] {
		t.Fatalf("expected read+operator caps from group G: %v", sg.Claims.Grant.Capabilities)
	}
	// ...but the admin tier MUST be absent: it would only appear if the body's G2 had been trusted.
	if got[BackShellAsSystem] || got[BackRegistryWrite] || got[BackLocalUserAdmin] {
		t.Fatalf("SECURITY: admin-tier caps leaked via body machine_group_id: %v", sg.Claims.Grant.Capabilities)
	}
}

func TestMintUnknownMachineRejectedStrict(t *testing.T) {
	// Owner over AllGroups(), so capability is never the blocker — the strict store's unknown
	// machine is. Mint must be refused with 404 rather than minting against a fabricated group.
	p := grantPrincipal(RoleOwner)
	srv := strictGrantServer(p, NewInMemoryMachineStore())
	rec := postMint(t, srv, mintGrantRequest{MachineID: machineInGroupG})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown machine (strict store)", rec.Code)
	}
}

// -------------------------------------------------------------------------------------
// handleEnroll + handleStartSession over the store.
// -------------------------------------------------------------------------------------

func TestEnrollHandlerCreatesMachine(t *testing.T) {
	p := grantPrincipal(RoleOwner)
	store := NewInMemoryMachineStore()
	srv := strictGrantServer(p, store)

	rec := postJSON(t, srv, "POST", "/enroll", map[string]any{"machine_id": machineInGroupG, "group_id": groupG, "name": "host-1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	// The machine is now resolvable BY DEVICE ID (the body's machine_id is the device id), in the
	// group it was enrolled into, and carries a distinct store-assigned primary key.
	m, err := store.GetMachine(context.Background(), p.TenantID, machineInGroupG)
	if err != nil || m.GroupID != groupG {
		t.Fatalf("after enroll GetMachine(deviceID) = %+v, %v; want group %q", m, err, groupG)
	}
	if m.DeviceID != machineInGroupG {
		t.Fatalf("enrolled device_id = %q, want %q", m.DeviceID, machineInGroupG)
	}
	if m.ID == "" || m.ID == machineInGroupG {
		t.Fatalf("enrolled PK id = %q, want a distinct non-empty id", m.ID)
	}
}

func TestStartSessionUnknownMachineRejectedStrict(t *testing.T) {
	p := grantPrincipal(RoleOwner)
	srv := strictGrantServer(p, NewInMemoryMachineStore())
	rec := postJSON(t, srv, "POST", "/sessions", map[string]any{"machine_id": machineInGroupG})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("start-session status = %d, want 404 for an unknown machine", rec.Code)
	}
}

// postJSON drives a request with a JSON body through the full middleware chain.
func postJSON(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// capSet indexes a backstage capability slice for membership checks.
func capSet(caps []BackstageCapability) map[BackstageCapability]bool {
	m := make(map[BackstageCapability]bool, len(caps))
	for _, c := range caps {
		m[c] = true
	}
	return m
}
