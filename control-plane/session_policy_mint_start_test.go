package controlplane

// POST /sessions mints the SIGNED SESSION ACCESS POLICY (docs/01 §3/§5, loops 79/80) — the artifact the
// viewer installs on the agent and the agent enforces. These tests are the control-plane half of the
// vertical slice; the Rust half (verify + the ratchet) lives in agent/src/session_policy.rs.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startSessionResponse is the slice of POST /sessions' body these tests care about.
type startSessionResponse struct {
	Session struct {
		ID string `json:"id"`
	} `json:"session"`
	SessionPolicy *struct {
		Access string `json:"access"`
		Signed string `json:"signed"`
	} `json:"session_policy"`
}

// startForMintTest spins an owner-authenticated server with the grant issuer wired (the mint is skipped
// entirely without one) and starts a session, returning the decoded response.
func startForMintTest(t *testing.T, enforceViewOnly bool) (*Server, startSessionResponse) {
	t.Helper()
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)

	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	iss, err := NewGrantIssuerFromSeed(seed)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss

	if enforceViewOnly {
		// Every machine in the permissive store resolves to DevDefaultMachineGroupID, so that is the
		// group whose policy handleStartSession will read.
		if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
			GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
			t.Fatalf("set group policy: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"22222222-2222-4222-8222-222222222222"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("start = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var out startSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response: %v (%s)", err, rec.Body.String())
	}
	return srv, out
}

// The headline behaviour: a policy is minted ONLY for a group that actually enforces view-only, and it
// carries view_only.
//
// The negative half is the important one, and it is a deliberate design rule rather than an omission. An
// earlier revision minted a policy for EVERY session carrying the real level. Combined with the agent
// failing CLOSED on a policy it cannot verify, that would have taken remote control away from every
// installed agent WITHOUT a `grant_issuer_pubkey` — the common configuration — on behalf of groups that
// had asked for nothing. Minting only when something is being enforced makes the artifact's PRESENCE the
// signal, which is what lets the agent fail closed safely.
func TestStartSessionMintsAPolicyOnlyForAnEnforcingGroup(t *testing.T) {
	t.Run("ordinary group: NO policy is minted", func(t *testing.T) {
		_, out := startForMintTest(t, false)
		if out.SessionPolicy != nil {
			t.Fatalf("a policy was minted for a group that enforces nothing (%+v) — every agent that "+
				"cannot verify it would fail closed and lose remote control", out.SessionPolicy)
		}
	})

	for _, tc := range []struct {
		name    string
		enforce bool
		want    SessionAccessLevel
	}{
		{"group enforces view-only", true, SessionAccessViewOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, out := startForMintTest(t, tc.enforce)
			if out.SessionPolicy == nil {
				t.Fatal("no session_policy in the start response")
			}
			if out.SessionPolicy.Access != string(tc.want) {
				t.Fatalf("access = %q, want %q", out.SessionPolicy.Access, tc.want)
			}

			// The cleartext `access` is only for display — the SIGNED blob is authoritative, and it must
			// agree. A handler that reported one level and signed the other would pass an access-only
			// assertion while shipping the opposite policy to the agent.
			var signed struct {
				Claims struct {
					Policy struct {
						Access     string `json:"access"`
						SessionID  string `json:"session_id"`
						MachineID  string `json:"machine_id"`
						Technician string `json:"technician_id"`
					} `json:"policy"`
					IssuedAtMs  int64 `json:"issued_at_ms"`
					ExpiresAtMs int64 `json:"expires_at_ms"`
				} `json:"claims"`
				SigV1 string `json:"sig_v1"` // authoritative v1 sig
				Sig   string `json:"sig"`    // v0 compat sig
			}
			if err := json.Unmarshal([]byte(out.SessionPolicy.Signed), &signed); err != nil {
				t.Fatalf("decode signed policy: %v (%s)", err, out.SessionPolicy.Signed)
			}
			if signed.Claims.Policy.Access != string(tc.want) {
				t.Fatalf("SIGNED access = %q but the response advertised %q — they must agree",
					signed.Claims.Policy.Access, out.SessionPolicy.Access)
			}
			if len(signed.SigV1) != 128 {
				t.Fatalf("sig_v1 is %d hex chars, want 128", len(signed.SigV1))
			}
			if len(signed.Sig) != 128 {
				t.Fatalf("compat sig is %d hex chars, want 128", len(signed.Sig))
			}
			// Bound to THIS session and to the machine's DEVICE id (what the agent compares against).
			if signed.Claims.Policy.SessionID != out.Session.ID {
				t.Fatalf("policy session_id = %q, want this session %q",
					signed.Claims.Policy.SessionID, out.Session.ID)
			}
			if signed.Claims.Policy.MachineID != "22222222-2222-4222-8222-222222222222" {
				t.Fatalf("policy machine_id = %q, want the DEVICE id the agent binds to",
					signed.Claims.Policy.MachineID)
			}
			if signed.Claims.ExpiresAtMs <= signed.Claims.IssuedAtMs {
				t.Fatalf("policy window is empty: issued %d expires %d",
					signed.Claims.IssuedAtMs, signed.Claims.ExpiresAtMs)
			}
		})
	}
}

// The signature must actually verify against the issuer's public key over the canonical preimage — not
// merely be 128 hex characters. This is the control-plane-side check that the bytes the agent will
// re-derive are the bytes that were signed.
func TestStartSessionMintsAVerifiableSignature(t *testing.T) {
	_, out := startForMintTest(t, true)
	if out.SessionPolicy == nil {
		t.Fatal("no session_policy in the start response")
	}
	var signed struct {
		Claims struct {
			Policy struct {
				TechnicianID              string `json:"technician_id"`
				SessionID                 string `json:"session_id"`
				MachineID                 string `json:"machine_id"`
				Access                    string `json:"access"`
				AllowRecording            bool   `json:"allow_recording"`
				RequireRecording          bool   `json:"require_recording"`
				MaxSessionDurationSeconds uint32 `json:"max_session_duration_seconds"`
				MaxIdleSeconds            uint32 `json:"max_idle_seconds"`
			} `json:"policy"`
			IssuedAtMs  int64 `json:"issued_at_ms"`
			ExpiresAtMs int64 `json:"expires_at_ms"`
		} `json:"claims"`
		SigV1 string `json:"sig_v1"` // authoritative v1 signature — what new agents verify
	}
	if err := json.Unmarshal([]byte(out.SessionPolicy.Signed), &signed); err != nil {
		t.Fatalf("decode: %v", err)
	}

	msg, err := sessionPolicySigningBytes(
		signed.Claims.Policy.TechnicianID, signed.Claims.Policy.SessionID, signed.Claims.Policy.MachineID,
		SessionAccessLevel(signed.Claims.Policy.Access), signed.Claims.Policy.AllowRecording,
		signed.Claims.Policy.RequireRecording, signed.Claims.Policy.MaxSessionDurationSeconds, signed.Claims.Policy.MaxIdleSeconds, signed.Claims.IssuedAtMs, signed.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("rebuild preimage: %v", err)
	}
	sig, err := hex.DecodeString(signed.SigV1)
	if err != nil {
		t.Fatalf("sig_v1 hex: %v", err)
	}
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	pub, err := hex.DecodeString(iss.PublicKeyHex())
	if err != nil {
		t.Fatalf("pubkey hex: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the minted sig_v1 does not verify over the v1 canonical preimage")
	}
}

// Without a grant issuer there is nothing to sign with, so no policy is offered — and the session still
// starts. The viewer then installs nothing and the session behaves as it did before the feature (this is
// the DEV/dev-stub path, and the one the pre-loop-80 Playwright specs exercise).
func TestStartSessionWithoutAnIssuerMintsNoPolicy(t *testing.T) {
	owner := &Principal{UserID: "u1", TenantID: "tenant-123",
		Grant: NewGrant("u1", "tenant-123", NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner) // Grants left nil
	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"dev-1"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("start = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var out startSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SessionPolicy != nil {
		t.Fatalf("session_policy present with no issuer wired: %+v", out.SessionPolicy)
	}
}

// THE FAIL-OPEN / FAIL-CLOSED ASYMMETRY. A mint can legitimately fail — the canonical preimage needs REAL
// uuids, and DEV runs with synthetic device ids like "dev-1" — and what handleStartSession does about it
// depends entirely on what the policy would have SAID:
//
//   - the group enforces view-only → the start must FAIL, because continuing would hand the technician a
//     session with no floor while the console still shows the group as restricted.
//   - the group does not           → the start must SUCCEED without a policy, because the policy would have
//     said "control" (inert under the agent's ratchet) and failing would break every DEV/attended flow.
//
// Both halves are asserted together: a mutation that makes the handler uniformly fail-open OR uniformly
// fail-closed breaks exactly one of them, and neither half alone would catch both mutations.
func TestStartSessionMintFailureFailsClosedOnlyWhenEnforcing(t *testing.T) {
	newSrv := func(t *testing.T, enforce bool) *Server {
		t.Helper()
		owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
			Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
				NewMembership(RoleOwner, AllGroups()))}
		srv, _ := newTestServer(owner)
		seed, _ := hex.DecodeString(goldenSeedHex)
		iss, err := NewGrantIssuerFromSeed(seed)
		if err != nil {
			t.Fatalf("issuer: %v", err)
		}
		srv.Grants = iss
		if enforce {
			if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
				GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
				t.Fatalf("set group policy: %v", err)
			}
		}
		return srv
	}
	// "dev-1" is not a canonical uuid, so the canonical preimage cannot be built and the mint fails —
	// the same shape a DEV/self-hosted deployment hits for real.
	start := func(srv *Server) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
			strings.NewReader(`{"machine_id":"dev-1"}`)))
		return rec
	}

	t.Run("not enforcing: the session starts without a policy", func(t *testing.T) {
		rec := start(newSrv(t, false))
		if rec.Code != http.StatusCreated {
			t.Fatalf("start = %d, want 201 — a group that was never restricted must not be broken by an "+
				"unmintable policy (nor by the mint being skipped): %s", rec.Code, rec.Body.String())
		}
		var out startSessionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.SessionPolicy != nil {
			t.Fatalf("a policy was returned despite the mint failing: %+v", out.SessionPolicy)
		}
	})

	t.Run("enforcing: the start is refused", func(t *testing.T) {
		rec := start(newSrv(t, true))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("start = %d, want 500 — a group that REQUIRES view-only must never get a session with "+
				"no floor: %s", rec.Code, rec.Body.String())
		}
		// And the refusal is a clean error, not an error followed by a session body the viewer might use.
		if strings.Contains(rec.Body.String(), "session_policy") ||
			strings.Contains(rec.Body.String(), `"signaling"`) {
			t.Fatalf("the 500 also wrote session material: %s", rec.Body.String())
		}
	})
}

// A refused start must not strand its session record OPEN. handleStartSession inserts the record BEFORE
// it mints, so the fail-closed path has to clean up after itself — an open record holds a seat against
// BOTH the tenant and the per-group concurrency caps, and nothing ever ends a session the caller never
// learned about. Left unfixed, a few refused starts silently exhaust the very caps this package enforces.
func TestStartSessionRefusedForPolicyDoesNotLeakAnOpenSession(t *testing.T) {
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, err := NewGrantIssuerFromSeed(seed)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss
	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	// "dev-1" is not a canonical uuid, so the mint fails and the ENFORCING group makes the start 500.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"dev-1"}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start = %d, want 500: %s", rec.Code, rec.Body.String())
	}

	sessions, err := srv.SessionRecords.ListSessions(t.Context(), "tenant-123", SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	for _, s := range sessions {
		if s.EndedAt == nil {
			t.Fatalf("the refused start left session %s OPEN — it will hold a seat against the tenant "+
				"and group caps until the reaper (if any) collects it", s.ID)
		}
	}
	// A record IS expected to exist (it was inserted before the mint) — the requirement is that it is
	// CLOSED, not that it never happened. Asserting emptiness instead would pass on an implementation
	// that never inserted, which is a different design.
	if len(sessions) == 0 {
		t.Fatal("no session record at all; this test is no longer exercising the insert-then-refuse path")
	}
}

// TestStartSessionMaxIdleSecondsRefusedEvenWithRequireSessionPolicy asserts 403 for a machine
// WITH require_session_policy=true attempting to start into a group with max_idle_seconds set.
//
// Pass4 scope reduction: max_idle_seconds is refused unconditionally for unattended sessions.
// The Pass3 fix enrolled the machine with RequireSessionPolicy=true as a proxy for capability;
// Pass4 removes that condition — require_session_policy pre-dates migrations 0043–0046 and is
// not sufficient evidence that the agent understands these new fields.
func TestStartSessionMaxIdleSecondsRefusedEvenWithRequireSessionPolicy(t *testing.T) {
	const tenantID = "tenant-123"
	const deviceID = "44444444-4444-4444-8444-444444444444"

	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tenantID,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tenantID,
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.Machines.EnrollMachine(t.Context(), tenantID, &Machine{
		DeviceID:             deviceID,
		Name:                 "test-machine",
		GroupID:              DevDefaultMachineGroupID,
		RequireSessionPolicy: true,
		Status:               MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	if err := srv.GroupSessionPolicies.Set(t.Context(), tenantID, DevDefaultMachineGroupID,
		GroupSessionPolicy{MaxIdleSeconds: 300}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+deviceID+`"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into max_idle_seconds group with require_session_policy=true = %d, want 403 — "+
			"the unconditional Pass4 gate must fire regardless of require_session_policy: %s",
			rec.Code, rec.Body.String())
	}
}

// TestStartSessionMaxSessionDurationRefusedEvenWithRequireSessionPolicy asserts 403 for a machine
// WITH require_session_policy=true attempting to start into a group with max_session_duration_seconds.
//
// Pass4 scope reduction: max_session_duration_seconds is refused unconditionally for unattended sessions.
func TestStartSessionMaxSessionDurationRefusedEvenWithRequireSessionPolicy(t *testing.T) {
	const tenantID = "tenant-123"
	const deviceID = "55555555-5555-5555-8555-555555555555"

	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tenantID,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tenantID,
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.Machines.EnrollMachine(t.Context(), tenantID, &Machine{
		DeviceID:             deviceID,
		Name:                 "test-machine",
		GroupID:              DevDefaultMachineGroupID,
		RequireSessionPolicy: true,
		Status:               MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	if err := srv.GroupSessionPolicies.Set(t.Context(), tenantID, DevDefaultMachineGroupID,
		GroupSessionPolicy{MaxSessionDurationSeconds: 3600}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+deviceID+`"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into max_session_duration group with require_session_policy=true = %d, want 403 — "+
			"the unconditional Pass4 gate must fire regardless of require_session_policy: %s",
			rec.Code, rec.Body.String())
	}
}

// UNATTENDED RECORDING ADMISSION GATE (old-agent gap).
//
// require_recording enforcement lives entirely in the agent (host.rs P1-B: auto-start recording on
// policy install, fail-closed if it fails). Old agents (pre-7c81bde) do not understand the
// require_recording field and will proceed without recording — "silently succeeding under old semantics."
//
// Since the control plane cannot determine at session-start whether the connecting agent is new, it
// uses m.RequireSessionPolicy as a proxy: a machine that the operator has explicitly placed in
// policy-enforcing mode is necessary (though not sufficient) evidence that the operator has also
// ensured the agent is post-7c81bde. Machines that have NOT been configured with require_session_policy
// are refused with 403 so the recording requirement does not silently pass.

// TestStartSessionRequireRecordingRefusesWithoutRequireSessionPolicy asserts 403 when a machine
// lacking require_session_policy attempts to connect into a require_recording group.
func TestStartSessionRequireRecordingRefusesWithoutRequireSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{RequireRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	// The permissive store fabricates a machine with RequireSessionPolicy=false (zero value), which is
	// the "old-agent, not opted into enforcing mode" case.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"22222222-2222-4222-8222-222222222222"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into require_recording group without require_session_policy = %d, want 403 — "+
			"the recording mandate must not silently pass on a machine not in enforcing mode: %s",
			rec.Code, rec.Body.String())
	}
}

// TestStartSessionRequireRecordingRefusedEvenWithRequireSessionPolicy asserts 403 for a machine
// WITH require_session_policy=true attempting to start into a require_recording group.
//
// Pass4 scope reduction: require_recording is refused unconditionally for unattended sessions
// regardless of require_session_policy. The flag predates migrations 0043–0046; a machine with
// it set may run an agent that pre-dates 7c81bde and would silently ignore require_recording.
// This test verifies the Pass3 "admitted" path is now refused — the unconditional gate fires.
func TestStartSessionRequireRecordingRefusedEvenWithRequireSessionPolicy(t *testing.T) {
	const tenantID = "tenant-123"
	const deviceID = "33333333-3333-4333-8333-333333333333"

	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tenantID,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tenantID,
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	// Pre-enroll with require_session_policy=true — the deployed-agent condition the Pass3 gate
	// admitted. Pass4 refuses unconditionally regardless.
	if err := srv.Machines.EnrollMachine(t.Context(), tenantID, &Machine{
		DeviceID:             deviceID,
		Name:                 "test-machine",
		GroupID:              DevDefaultMachineGroupID,
		RequireSessionPolicy: true,
		Status:               MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}

	if err := srv.GroupSessionPolicies.Set(t.Context(), tenantID, DevDefaultMachineGroupID,
		GroupSessionPolicy{RequireRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+deviceID+`"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into require_recording group with require_session_policy=true = %d, want 403 — "+
			"the unconditional Pass4 gate must fire regardless of require_session_policy: %s",
			rec.Code, rec.Body.String())
	}
}

// --- UNATTENDED OLD-AGENT GATE for prohibit_recording / max_session_duration / max_idle ---
//
// These fields require a policy-capable agent. require_session_policy is the best available
// CP-side proxy: it is agent-asserted at enrollment and refreshed on register, but it pre-dates
// these features — an old agent enrolled with the flag may not enforce them. Machines not
// configured with require_session_policy receive 403 so the restrictions cannot silently pass.

// TestStartSessionProhibitRecordingRefusesWithoutRequireSessionPolicy asserts 403 when a machine
// lacking require_session_policy attempts to connect into a prohibit_recording group.
func TestStartSessionProhibitRecordingRefusesWithoutRequireSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{ProhibitRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	// The permissive store fabricates a machine with RequireSessionPolicy=false (the old-agent case).
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"22222222-2222-4222-8222-222222222222"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into prohibit_recording group without require_session_policy = %d, want 403: %s",
			rec.Code, rec.Body.String())
	}
}

// TestStartSessionMaxSessionDurationRefusesWithoutRequireSessionPolicy asserts 403 when a machine
// lacking require_session_policy attempts to connect into a group with a duration limit.
func TestStartSessionMaxSessionDurationRefusesWithoutRequireSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{MaxSessionDurationSeconds: 3600}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"22222222-2222-4222-8222-222222222222"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into max_session_duration group without require_session_policy = %d, want 403: %s",
			rec.Code, rec.Body.String())
	}
}

// TestStartSessionMaxIdleSecondsRefusesWithoutRequireSessionPolicy asserts 403 when a machine
// lacking require_session_policy attempts to connect into a group with an idle timeout.
func TestStartSessionMaxIdleSecondsRefusesWithoutRequireSessionPolicy(t *testing.T) {
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: "tenant-123",
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", "tenant-123",
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", DevDefaultMachineGroupID,
		GroupSessionPolicy{MaxIdleSeconds: 300}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"22222222-2222-4222-8222-222222222222"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into max_idle_seconds group without require_session_policy = %d, want 403: %s",
			rec.Code, rec.Body.String())
	}
}

// --- Pass4: new tests verifying unconditional gate fires even with require_session_policy=true ---

// TestStartSessionProhibitRecordingRefusedEvenWithRequireSessionPolicy verifies that prohibit_recording
// is refused unconditionally regardless of require_session_policy, matching attended behavior.
func TestStartSessionProhibitRecordingRefusedEvenWithRequireSessionPolicy(t *testing.T) {
	const tenantID = "tenant-123"
	const deviceID = "66666666-6666-4666-8666-666666666666"

	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tenantID,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tenantID,
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.Machines.EnrollMachine(t.Context(), tenantID, &Machine{
		DeviceID:             deviceID,
		Name:                 "test-machine",
		GroupID:              DevDefaultMachineGroupID,
		RequireSessionPolicy: true,
		Status:               MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	if err := srv.GroupSessionPolicies.Set(t.Context(), tenantID, DevDefaultMachineGroupID,
		GroupSessionPolicy{ProhibitRecording: true}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+deviceID+`"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("start into prohibit_recording group with require_session_policy=true = %d, want 403 — "+
			"unconditional Pass4 gate must fire: %s", rec.Code, rec.Body.String())
	}
}

// TestStartSessionPermissiveGroupWithRequireSessionPolicySucceeds is the success CONTROL: a machine
// with require_session_policy=true into a group with NO new restrictions must succeed (201). This
// ensures the gate is scoped to the four new restrictions and does not block all policy-enforcing
// machines, and that view-only enforcement (a pre-existing restriction) still works.
func TestStartSessionPermissiveGroupWithRequireSessionPolicySucceeds(t *testing.T) {
	const tenantID = "tenant-123"
	const deviceID = "77777777-7777-4777-8777-777777777777"

	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tenantID,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tenantID,
			NewMembership(RoleOwner, AllGroups()))}
	srv, _ := newTestServer(owner)
	seed, _ := hex.DecodeString(goldenSeedHex)
	iss, _ := NewGrantIssuerFromSeed(seed)
	srv.Grants = iss

	if err := srv.Machines.EnrollMachine(t.Context(), tenantID, &Machine{
		DeviceID:             deviceID,
		Name:                 "test-machine",
		GroupID:              DevDefaultMachineGroupID,
		RequireSessionPolicy: true,
		Status:               MachineStatusActive,
	}); err != nil {
		t.Fatalf("enroll machine: %v", err)
	}
	// No new restrictions — group is permissive. EnforceViewOnly=false, no recording restrictions,
	// no duration limits. A machine with RequireSessionPolicy=true still gets a signed policy.
	if err := srv.GroupSessionPolicies.Set(t.Context(), tenantID, DevDefaultMachineGroupID,
		GroupSessionPolicy{}); err != nil {
		t.Fatalf("set group policy: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+deviceID+`"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("start into permissive group with require_session_policy=true = %d, want 201 — "+
			"no restrictions means no gate should fire: %s", rec.Code, rec.Body.String())
	}
}
