package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTORS (H1b) — the proof Go and Rust agree byte-for-byte.
//
// The SAME fixed fixture is hardcoded in agent/src/backstage/grant.rs (tests::golden_vector_v1).
// If either language's canonical encoder or Ed25519 signing diverges, its hex stops matching these
// constants. DO NOT change a value here without changing it identically in the Rust test.
//
//   seed (32 bytes, hex):
//     0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
//   issuer public key (hex, derived from the seed): goldenPubkeyHex
//   technician_id: 11111111-1111-1111-1111-111111111111
//   session_id:    22222222-2222-2222-2222-222222222222
//   machine_id:    33333333-3333-3333-3333-333333333333
//   capabilities:  [system_info_read, process_list, shell_as_system]   (slice order matters)
//   issued_at_ms:  1730000000000
//   expires_at_ms: 1730000900000
//
//   => canonical signing-bytes hex : goldenPreimageHex
//   => Ed25519 signature hex       : goldenSigHex
// =====================================================================================

const (
	goldenSeedHex     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	goldenPubkeyHex   = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	goldenPreimageHex = "524d544752414e5476310000111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333000000030000001073797374656d5f696e666f5f726561640000000c70726f636573735f6c6973740000000f7368656c6c5f61735f73797374656d00000192cc09140000000192cc16cfa0"
	goldenSigHex      = "4b299bb9963a14c9f62b8349139ba5eb29c6d3113b583f9e87b5a583548001c6d68679d5039a8dae95ebdfba27925c8808f451ddbf52d416e9a14578ac7d9800"

	goldenTechnicianID = "11111111-1111-1111-1111-111111111111"
	goldenSessionID    = "22222222-2222-2222-2222-222222222222"
	goldenMachineID    = "33333333-3333-3333-3333-333333333333"
	goldenIssuedAtMs   = int64(1730000000000)
	goldenExpiresAtMs  = int64(1730000900000)
)

var goldenCaps = []BackstageCapability{BackSystemInfoRead, BackProcessList, BackShellAsSystem}

func TestGoldenVectorV1(t *testing.T) {
	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	iss, err := NewGrantIssuerFromSeed(seed)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	if got := iss.PublicKeyHex(); got != goldenPubkeyHex {
		t.Fatalf("pubkey drift:\n got  %s\n want %s", got, goldenPubkeyHex)
	}

	msg, err := signingBytes(goldenTechnicianID, goldenSessionID, goldenMachineID, goldenCaps, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("signingBytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPreimageHex {
		t.Fatalf("canonical preimage drift:\n got  %s\n want %s", got, goldenPreimageHex)
	}

	signed, err := iss.Mint(goldenTechnicianID, goldenSessionID, goldenMachineID, goldenCaps, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if signed.Sig != goldenSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", signed.Sig, goldenSigHex)
	}

	// Emit the exact minted JSON so it can be pasted into the Rust interop test
	// (tests::verifies_go_minted_grant) verbatim, proving Go-mint → Rust-verify.
	blob, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed grant: %v", err)
	}
	t.Logf("GO-MINTED SignedGrant JSON: %s", blob)
}

// -------------------------------------------------------------------------------------
// Canonical encoder unit tests.
// -------------------------------------------------------------------------------------

func TestGrantDomainTagBytes(t *testing.T) {
	want := []byte{0x52, 0x4d, 0x54, 0x47, 0x52, 0x41, 0x4e, 0x54, 0x76, 0x31, 0x00, 0x00}
	if !bytes.Equal(grantDomainTag, want) {
		t.Fatalf("domain tag = % x, want % x", grantDomainTag, want)
	}
	if len(grantDomainTag) != 12 {
		t.Fatalf("domain tag length = %d, want 12", len(grantDomainTag))
	}
}

func TestUUIDBytesRoundTrip(t *testing.T) {
	b, err := uuidBytes("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("uuidBytes: %v", err)
	}
	for i, v := range b {
		if v != 0x11 {
			t.Fatalf("byte %d = %#x, want 0x11", i, v)
		}
	}
	for _, bad := range []string{"", "nope", "1111111-1111-1111-1111-1111111111111", strings.Repeat("z", 36)} {
		if _, err := uuidBytes(bad); err == nil {
			t.Fatalf("uuidBytes(%q) should have failed", bad)
		}
	}
}

func TestBackstageCapabilityNamesAreSnakeCase(t *testing.T) {
	// Every backstage capability's on-wire string must be non-empty lower snake_case (the shape the
	// agent's serde rename_all produces). The golden vector proves the exact bytes match Rust; this
	// is the cheap structural guard against a typo in a new capability.
	if len(AllBackstageCapabilities) != 19 {
		t.Fatalf("AllBackstageCapabilities has %d entries, want 19 (must mirror Rust Capability::ALL)", len(AllBackstageCapabilities))
	}
	seen := map[BackstageCapability]bool{}
	for _, c := range AllBackstageCapabilities {
		s := string(c)
		if s == "" {
			t.Fatal("empty backstage capability name")
		}
		if seen[c] {
			t.Fatalf("duplicate backstage capability %q", s)
		}
		seen[c] = true
		for _, r := range s {
			if !((r >= 'a' && r <= 'z') || r == '_') {
				t.Fatalf("capability %q is not lower snake_case", s)
			}
		}
	}
}

// -------------------------------------------------------------------------------------
// Mint endpoint tests — POST /grant/mint through the full auth → tenant middleware chain.
// -------------------------------------------------------------------------------------

// A valid UUID for a technician principal (p.UserID feeds the grant's technician_id, which Rust
// parses as a uuid, so it must be canonical).
const techUserUUID = "44444444-4444-4444-4444-444444444444"

func grantServer(p *Principal) *Server {
	iss, err := NewGrantIssuerFromSeedHexOrPanic(goldenSeedHex)
	if err != nil {
		panic(err)
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.Grants = iss
	// DEV-style permissive machine store: the golden/random machine ids in these tests are not
	// pre-enrolled, so they resolve to the default group. The principals here are scoped over
	// AllGroups(), so the resolved group never narrows their caps — these tests exercise the
	// capability tiers, while TestMintIgnoresBodyMachineGroup (machine_test.go) exercises the
	// group-resolution security fix directly.
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	return srv
}

func NewGrantIssuerFromSeedHexOrPanic(seedHex string) (*GrantIssuer, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	return NewGrantIssuerFromSeed(seed)
}

func grantPrincipal(role Role) *Principal {
	return &Principal{
		UserID:   techUserUUID,
		TenantID: "tenant-123",
		Grant:    NewGrant(techUserUUID, "tenant-123", NewMembership(role, AllGroups())),
	}
}

func postMint(t *testing.T, srv *Server, body mintGrantRequest) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/grant/mint", bytes.NewReader(buf))
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestMintReturnsWellFormedGrantScopedToTechnician(t *testing.T) {
	srv := grantServer(grantPrincipal(RoleTechnician))
	rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode signed grant: %v", err)
	}
	// Wire shape: technician_id == the authenticated user, machine_id echoed, session_id generated,
	// a hex signature, a validity window.
	if sg.Claims.Grant.TechnicianID != techUserUUID {
		t.Fatalf("technician_id = %q, want %q", sg.Claims.Grant.TechnicianID, techUserUUID)
	}
	if sg.Claims.Grant.MachineID != goldenMachineID {
		t.Fatalf("machine_id = %q, want %q", sg.Claims.Grant.MachineID, goldenMachineID)
	}
	if _, err := uuidBytes(sg.Claims.Grant.SessionID); err != nil {
		t.Fatalf("generated session_id is not a UUID: %q", sg.Claims.Grant.SessionID)
	}
	if len(sg.Sig) != 128 {
		t.Fatalf("sig length = %d, want 128 hex chars", len(sg.Sig))
	}
	if sg.Claims.ExpiresAtMs <= sg.Claims.IssuedAtMs {
		t.Fatalf("expires_at_ms %d must be after issued_at_ms %d", sg.Claims.ExpiresAtMs, sg.Claims.IssuedAtMs)
	}

	// Scoped to the technician's caps: a plain Technician gets read-only + operator, NOT the admin
	// tier (which requires CapManageMachines).
	got := map[BackstageCapability]bool{}
	for _, c := range sg.Claims.Grant.Capabilities {
		got[c] = true
	}
	if !got[BackSystemInfoRead] || !got[BackProcessKill] {
		t.Fatalf("technician grant missing expected read/operator caps: %v", sg.Claims.Grant.Capabilities)
	}
	if got[BackShellAsSystem] || got[BackRegistryWrite] {
		t.Fatalf("technician grant must NOT include admin-tier caps: %v", sg.Claims.Grant.Capabilities)
	}

	// The minted grant must actually verify against the issuer's public key.
	msg, err := signingBytes(sg.Claims.Grant.TechnicianID, sg.Claims.Grant.SessionID, sg.Claims.Grant.MachineID, sg.Claims.Grant.Capabilities, sg.Claims.IssuedAtMs, sg.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("rebuild signing bytes: %v", err)
	}
	if !verifyGolden(t, msg, sg.Sig) {
		t.Fatal("minted grant does not verify against the issuer public key")
	}
}

func TestMintBindsMachineID(t *testing.T) {
	// H3 device binding: the minted grant's machine_id MUST equal the requested machine_id, so an
	// agent bound to device D accepts only a grant minted for D. Uses a machine id distinct from the
	// golden fixture to prove the value is echoed from the request, not hardcoded.
	const reqMachine = "55555555-5555-5555-5555-555555555555"
	srv := grantServer(grantPrincipal(RoleTechnician))
	rec := postMint(t, srv, mintGrantRequest{MachineID: reqMachine})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sg.Claims.Grant.MachineID != reqMachine {
		t.Fatalf("machine_id = %q, want %q (mint must bind the grant to the requested machine)", sg.Claims.Grant.MachineID, reqMachine)
	}
	// The bound machine_id is inside the signed preimage, so the signature must still verify over it.
	msg, err := signingBytes(sg.Claims.Grant.TechnicianID, sg.Claims.Grant.SessionID, sg.Claims.Grant.MachineID, sg.Claims.Grant.Capabilities, sg.Claims.IssuedAtMs, sg.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("rebuild signing bytes: %v", err)
	}
	if !verifyGolden(t, msg, sg.Sig) {
		t.Fatal("grant bound to the requested machine does not verify against the issuer key")
	}
}

func TestMintAdminGetsAdminTier(t *testing.T) {
	// RoleAdmin holds CapManageMachines + CapBackstageShell, so it earns the admin backstage tier.
	srv := grantServer(grantPrincipal(RoleAdmin))
	rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var sg SignedGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &sg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[BackstageCapability]bool{}
	for _, c := range sg.Claims.Grant.Capabilities {
		got[c] = true
	}
	if !got[BackShellAsSystem] || !got[BackLocalUserAdmin] {
		t.Fatalf("admin grant should include admin-tier caps: %v", sg.Claims.Grant.Capabilities)
	}
}

func TestMintDeniedWithoutBackstageCapability(t *testing.T) {
	// ReadOnly holds neither CapBackstageShell nor anything operational — no grant may be minted.
	srv := grantServer(grantPrincipal(RoleReadOnly))
	rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a caller lacking backstage_shell (body %s)", rec.Code, rec.Body.String())
	}
}

// A group mandated VIEW-ONLY refuses BACKSTAGE grants too — the honesty fix for the label (migration 0040).
// enforce_view_only makes the agent drop input and refuse reboot / tool-launch / command-run / lock /
// log-off / shut-down, but backstage rides a separate trust axis the agent's backstage path never checks
// against the session's access level, so before this a technician holding CapBackstageShell could run
// commands as SYSTEM on a machine the console labelled "view only". handleMintElevation already refused an
// ELEVATION grant on exactly this mandate; the two privilege-issuing endpoints now agree.
//
// RoleAdmin throughout, so the refusal cannot be confused with a capability denial: this principal mints
// happily in every other test in this file, and the sub-test named "premise" re-proves it on this fixture.
func TestMintRefusedForAViewOnlyMandatedGroup(t *testing.T) {
	ctx := context.Background()
	const tid = "tenant-123"

	// The permissive DEV store resolves any unknown machine id into DevDefaultMachineGroupID, so that is
	// the group whose policy handleMintGrant will read for goldenMachineID. Asserted rather than assumed:
	// if the store ever stopped doing that, every case below would pass for the wrong reason (memory:
	// regression-test-premise-drift).
	if m, err := NewPermissiveMachineStore(DevDefaultMachineGroupID).GetMachine(ctx, tid, goldenMachineID); err != nil ||
		m.GroupID != DevDefaultMachineGroupID {
		t.Fatalf("premise not met: the fixture machine resolves to (%+v, %v), want group %q", m, err, DevDefaultMachineGroupID)
	}

	// A REAL audit store, not grantServer's nil one: the "nothing was audited" assertion below is only
	// evidence if a successful mint on the same fixture DOES produce a grant.mint event, which the premise
	// sub-test proves. Against a nil MgmtAudit that negative can never fail.
	newSrv := func(t *testing.T, policy GroupSessionPolicy) *Server {
		t.Helper()
		srv := grantServer(grantPrincipal(RoleAdmin))
		srv.MgmtAudit = NewInMemoryMgmtAuditStore()
		srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
		if err := srv.GroupSessionPolicies.Set(ctx, tid, DevDefaultMachineGroupID, policy); err != nil {
			t.Fatalf("set group policy: %v", err)
		}
		return srv
	}
	mintEvents := func(t *testing.T, srv *Server) int {
		t.Helper()
		events, err := srv.MgmtAudit.ListEvents(ctx, tid, 20)
		if err != nil {
			// CHECKED, not discarded: an errored listing yields a nil slice, the count is 0, and the
			// negative below silently becomes unfailable.
			t.Fatalf("list audit: %v", err)
		}
		n := 0
		for _, e := range events {
			if e.Action == "grant.mint" {
				n++
			}
		}
		return n
	}

	t.Run("premise: the same caller and machine DO mint with no mandate", func(t *testing.T) {
		// Without this the 409 below would also pass on a fixture that could never mint at all — and the
		// audit count proves grant.mint is a signal this fixture actually emits, which is what makes its
		// ABSENCE in the refused case mean something.
		srv := newSrv(t, GroupSessionPolicy{})
		if rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID}); rec.Code != http.StatusOK {
			t.Fatalf("= %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if n := mintEvents(t, srv); n != 1 {
			t.Fatalf("a successful mint recorded %d grant.mint events, want 1", n)
		}
	})

	t.Run("a view-only group refuses the mint", func(t *testing.T) {
		srv := newSrv(t, GroupSessionPolicy{EnforceViewOnly: true})
		rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
		if rec.Code != http.StatusConflict {
			t.Fatalf("= %d, want 409: %s", rec.Code, rec.Body.String())
		}
		// The status alone is over-determined — quarantine/retired answer 409 here too — so the body must
		// name the actual reason, or a machine refused for something else would pass this.
		if !strings.Contains(rec.Body.String(), "view-only") {
			t.Fatalf("a view-only-mandated group was refused for some OTHER reason: %s", rec.Body.String())
		}
		// Nothing may be audited by a refused mint. A grant is a bearer credential: if one were signed and
		// merely not returned it would still have been ISSUED, and the trail must not show a backstage
		// authorization handed out against a watch-only group.
		if n := mintEvents(t, srv); n != 0 {
			t.Fatalf("a refused mint was audited as if it had happened (%d grant.mint events)", n)
		}
	})

	t.Run("the explicit per-group opt-out lets it through", func(t *testing.T) {
		// The combination stays REACHABLE — deliberate unattended maintenance on machines that must
		// otherwise stay watch-only. This is the only thing that distinguishes the fix from deleting the
		// feature, so it is asserted, not assumed.
		srv := newSrv(t, GroupSessionPolicy{EnforceViewOnly: true, AllowBackstageUnderViewOnly: true})
		rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
		if rec.Code != http.StatusOK {
			t.Fatalf("= %d, want 200 with the opt-out set: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("the opt-out ALONE does not weaken anything", func(t *testing.T) {
		// An asymmetric case: the opt-out is meaningless without the mandate, and a refusal wired as
		// `!AllowBackstageUnderViewOnly` (forgetting the EnforceViewOnly conjunct) would refuse EVERY mint
		// in the fleet — the protection applied to groups nobody put under a mandate. 21 unit tests once
		// passed against fully inverted wiring (memory: asymmetric-case-catches-swapped-wiring).
		srv := newSrv(t, GroupSessionPolicy{AllowBackstageUnderViewOnly: true})
		if rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID}); rec.Code != http.StatusOK {
			t.Fatalf("= %d, want 200 (no mandate, so nothing to refuse): %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("another group's mandate does not reach this machine", func(t *testing.T) {
		// Scoping: the refusal must read the policy of the MACHINE's group. A handler that read some other
		// group — or every group — would refuse here.
		srv := grantServer(grantPrincipal(RoleAdmin))
		srv.GroupSessionPolicies = NewInMemoryGroupSessionPolicyStore()
		if err := srv.GroupSessionPolicies.Set(ctx, tid, "some-other-group",
			GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
			t.Fatalf("set group policy: %v", err)
		}
		if rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID}); rec.Code != http.StatusOK {
			t.Fatalf("= %d, want 200 (the mandate is on a DIFFERENT group): %s", rec.Code, rec.Body.String())
		}
	})
}

func TestMintUnauthenticatedRejected(t *testing.T) {
	srv := grantServer(nil) // StubAuthenticator returns nil → 401 before the handler
	rec := postMint(t, srv, mintGrantRequest{MachineID: goldenMachineID})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMintMissingMachineIDRejected(t *testing.T) {
	srv := grantServer(grantPrincipal(RoleTechnician))
	rec := postMint(t, srv, mintGrantRequest{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing machine_id", rec.Code)
	}
}

func TestGrantPubkeyEndpoint(t *testing.T) {
	srv := grantServer(grantPrincipal(RoleTechnician))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/grant/pubkey", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["grant_issuer_pubkey"] != goldenPubkeyHex {
		t.Fatalf("pubkey = %q, want %q", resp["grant_issuer_pubkey"], goldenPubkeyHex)
	}
}

// verifyGolden checks a signature over msg using the golden issuer public key.
func verifyGolden(t *testing.T, msg []byte, sigHex string) bool {
	t.Helper()
	pub, err := hex.DecodeString(goldenPubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	return ed25519.Verify(pub, msg, sig)
}
