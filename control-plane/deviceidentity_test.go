package controlplane

// M3 device-identity lookup (docs/11-agent-identity-contract.md §4): the cross-tenant read the
// signaling server uses to authenticate `register_agent`. In-memory throughout; the pgx twin lives
// in machine_pgstore_test.go (DB-gated).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// deviceIdentityToken is a valid (32+ char) service token for the tests.
const deviceIdentityToken = "0123456789abcdef0123456789abcdef"

// getIdentity issues GET /internal/devices/{id}/identity with the given Authorization header
// value ("" ⇒ no header) and returns the recorder.
func getIdentity(t *testing.T, srv *Server, deviceID, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/internal/devices/"+deviceID+"/identity", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// identityServer wires a strict machine store plus the service token, with throttling off so a
// test can drive many failures without tripping the limiter (metering itself is covered below).
func identityServer(t *testing.T) (*Server, *InMemoryMachineStore) {
	t.Helper()
	store := NewInMemoryMachineStore()
	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.DisableThrottle = true
	return srv, store
}

// The happy path plus every documented failure: the endpoint answers the tenant + pinned pubkey
// for an enrolled device, 401s without the service token, and 404s for an unknown device.
func TestDeviceIdentityLookup(t *testing.T) {
	srv, store := identityServer(t)
	ctx := context.Background()
	pubHex := testPubkeyHex(t)

	m := &Machine{DeviceID: machineInGroupG, GroupID: groupG, Name: "host-1", Pubkey: pubHex}
	if err := store.EnrollMachine(ctx, "tenant-123", m); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	rec := getIdentity(t, srv, machineInGroupG, "Bearer "+deviceIdentityToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("identity lookup = %d (body %s), want 200", rec.Code, rec.Body.String())
	}
	var got DeviceIdentity
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.DeviceID != machineInGroupG || got.TenantID != "tenant-123" || got.Pubkey != pubHex {
		t.Fatalf("identity = %+v, want device %s tenant tenant-123 pubkey %s", got, machineInGroupG, pubHex)
	}
	// The response carries the identity and NOTHING else about the machine.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if len(raw) != 4 || raw["status"] != "active" { // docs/65: the status is the one new field
		t.Fatalf("identity response has %d fields (%v), want exactly device_id/tenant_id/pubkey/status(active)", len(raw), raw)
	}

	// Auth failures — all the same opaque 401.
	for name, header := range map[string]string{
		"missing":     "",
		"wrong token": "Bearer " + deviceIdentityToken[:31] + "X",
		"not bearer":  deviceIdentityToken,
		"empty token": "Bearer ",
	} {
		if rec := getIdentity(t, srv, machineInGroupG, header); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s auth = %d, want 401", name, rec.Code)
		}
	}

	// Unknown device → 404 with the same message an unpinned one gets.
	if rec := getIdentity(t, srv, groupG2, "Bearer "+deviceIdentityToken); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown device = %d, want 404", rec.Code)
	}
}

// A machine enrolled through the LEGACY authenticated /enroll path has no pinned key. It must be
// reported as unknown, identically to a device that does not exist: an agent that cannot be
// authenticated fails closed rather than being waved through with an empty key.
func TestDeviceIdentityUnpinnedPubkeyIsUnknown(t *testing.T) {
	srv, store := identityServer(t)
	if err := store.EnrollMachine(context.Background(), "tenant-123",
		&Machine{DeviceID: machineInGroupG, GroupID: groupG}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	rec := getIdentity(t, srv, machineInGroupG, "Bearer "+deviceIdentityToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unpinned machine = %d (body %s), want 404", rec.Code, rec.Body.String())
	}
	unknown := getIdentity(t, srv, groupG2, "Bearer "+deviceIdentityToken)
	if rec.Body.String() != unknown.Body.String() {
		t.Fatalf("unpinned body %q != unknown body %q; the two must be indistinguishable",
			rec.Body.String(), unknown.Body.String())
	}
}

// THE ORACLE GUARD. The permissive (dev) store synthesizes an unknown MACHINE so local minting
// works without enrolling — it must NOT synthesize an IDENTITY. If it did, a dev control plane
// would hand out a valid tenant + pubkey for any device id, and signaling's proof-of-possession
// check would authenticate anyone against any device.
func TestPermissiveStoreNeverSynthesizesDeviceIdentity(t *testing.T) {
	ctx := context.Background()
	store := NewPermissiveMachineStore(DevDefaultMachineGroupID)

	// The permissive fallback is genuinely active for the machine lookup...
	if _, err := store.GetMachine(ctx, "tenant-123", machineInGroupG); err != nil {
		t.Fatalf("permissive GetMachine returned %v, want the synthetic machine", err)
	}
	// ...and genuinely absent for the identity lookup.
	if _, err := store.LookupDeviceIdentity(ctx, machineInGroupG); err != ErrMachineNotFound {
		t.Fatalf("permissive LookupDeviceIdentity = %v, want ErrMachineNotFound", err)
	}
	// Even for a machine it really holds, an unpinned key is not an identity.
	if err := store.EnrollMachine(ctx, "tenant-123", &Machine{DeviceID: machineInGroupG, GroupID: groupG}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}
	if _, err := store.LookupDeviceIdentity(ctx, machineInGroupG); err != ErrMachineNotFound {
		t.Fatalf("unpinned LookupDeviceIdentity = %v, want ErrMachineNotFound", err)
	}

	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.DisableThrottle = true
	if rec := getIdentity(t, srv, "any-device-at-all", "Bearer "+deviceIdentityToken); rec.Code != http.StatusNotFound {
		t.Fatalf("permissive-store identity lookup = %d, want 404 (the dev store must not be an identity oracle)", rec.Code)
	}
}

// The route EXISTS only when a long-enough token is configured. Unset or too short ⇒ 404 from the
// mux, so there is no unauthenticated mode to fall back to.
func TestDeviceIdentityRouteRequiresConfiguredToken(t *testing.T) {
	store := NewInMemoryMachineStore()
	if err := store.EnrollMachine(context.Background(), "tenant-123",
		&Machine{DeviceID: machineInGroupG, GroupID: groupG, Pubkey: testPubkeyHex(t)}); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	for name, token := range map[string]string{
		"unset":     "",
		"too short": deviceIdentityToken[:DeviceIdentityTokenMinLen-1],
	} {
		srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
		srv.Machines = store
		srv.DeviceIdentityToken = token
		srv.DisableThrottle = true
		// Unmounted: the request falls through to the protected "/" catch-all, whose stub
		// authenticator has a nil principal → 401/404, never 200 with an identity.
		rec := getIdentity(t, srv, machineInGroupG, "Bearer "+token)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s token served an identity (%d %s); the route must not be mounted",
				name, rec.Code, rec.Body.String())
		}
	}
}

// Failed lookups are metered per source, so probing the endpoint (for the service token, or for
// which device ids exist) runs into the same exponential backoff as /enroll/redeem.
func TestDeviceIdentityThrottlesFailures(t *testing.T) {
	store := NewInMemoryMachineStore()
	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2})

	// The free allowance is spent by failures, and the lockout only begins once a failure lands
	// BEYOND it — so the third 401 is what arms it.
	for i := 0; i < 3; i++ {
		if rec := getIdentity(t, srv, machineInGroupG, "Bearer wrong-token-wrong-token-wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i, rec.Code)
		}
	}
	rec := getIdentity(t, srv, machineInGroupG, "Bearer wrong-token-wrong-token-wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt past the free allowance = %d, want 429", rec.Code)
	}
	// The lockout applies to the source, so a correct token from it is refused too — the limiter
	// is not a per-credential counter an attacker can sidestep.
	if rec := getIdentity(t, srv, machineInGroupG, "Bearer "+deviceIdentityToken); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled source with a valid token = %d, want 429", rec.Code)
	}
}

// A run of 404s must NOT lock the route out — the CRITICAL from docs/23's internet-facing audit.
//
// The throttle key is `clientIP(r)`, and this is an INTERNAL route, so the client is always the
// signaling container: one key shared by every legitimate agent registration in every tenant.
// Signaling resolves a device identity BEFORE verifying the caller's Ed25519 signature, so an
// ANONYMOUS WebSocket can make it look up arbitrary device ids, and each miss landed on th.Fail.
// Five locked the key for 15 minutes, every further miss re-armed it, and th.Reset only runs on a
// success that could no longer happen. One unauthenticated peer could stop the whole fleet from
// registering, indefinitely.
//
// Throttling is deliberately LEFT ON here — the sibling fixtures disable it, which is precisely why
// nothing caught this.
func TestDeviceIdentityUnknownDeviceDoesNotThrottleTheSharedKey(t *testing.T) {
	store := NewInMemoryMachineStore()
	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	// Tight profile so the test is honest about the boundary rather than relying on the default.
	srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2})

	ctx := context.Background()
	real := &Machine{DeviceID: machineInGroupG, GroupID: groupG, Name: "host-1", Pubkey: testPubkeyHex(t)}
	if err := store.EnrollMachine(ctx, "tenant-123", real); err != nil {
		t.Fatalf("EnrollMachine: %v", err)
	}

	// The attack: many lookups for device ids that do not exist, all authorized by the service token
	// exactly as signaling's own calls are.
	for i := 0; i < 12; i++ {
		rec := getIdentity(t, srv, "00000000-0000-0000-0000-0000000000ff", "Bearer "+deviceIdentityToken)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("miss %d: got %d (body %s), want 404", i, rec.Code, rec.Body.String())
		}
	}

	// THE ASSERTION. A legitimate registration must still resolve. Before the fix this was 429, and
	// it would have stayed 429 for 15 minutes, re-armed by every further miss.
	rec := getIdentity(t, srv, machineInGroupG, "Bearer "+deviceIdentityToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("a real device lookup after 12 misses = %d (body %s), want 200 — unknown-device "+
			"lookups are consuming the throttle budget that EVERY agent registration in EVERY "+
			"tenant shares, so one anonymous peer can stop the whole fleet registering",
			rec.Code, rec.Body.String())
	}
}

// The negative control, and it is what stops the fix above from becoming a hole of its own: an
// UNAUTHORIZED caller must still be locked out. That arm is someone guessing the service token, and
// metering it is the entire point of having a throttle on this route.
func TestDeviceIdentityUnauthorizedStillThrottles(t *testing.T) {
	store := NewInMemoryMachineStore()
	srv := NewServer(StubAuthenticator{Principal: nil}, NoopBinder{})
	srv.Machines = store
	srv.DeviceIdentityToken = deviceIdentityToken
	srv.Throttle = NewThrottle(ThrottleConfig{FreeAttempts: 2})

	var sawThrottled bool
	for i := 0; i < 8; i++ {
		rec := getIdentity(t, srv, machineInGroupG, "Bearer wrong-token-wrong-token-wrong-token")
		if rec.Code == http.StatusTooManyRequests {
			sawThrottled = true
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401 or 429", i, rec.Code)
		}
	}
	if !sawThrottled {
		t.Fatal("token guessing was NEVER throttled — the 401 arm must still meter, or the fix to " +
			"the 404 arm has removed the protection this route exists to have")
	}
}
