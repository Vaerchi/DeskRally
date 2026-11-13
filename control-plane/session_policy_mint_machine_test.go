package controlplane

// Loop 86: POST /sessions mints a session policy when the MACHINE reported require_session_policy,
// not only when its GROUP enforces view-only (migration 0037).
//
// THE BUG THIS CLOSES. `require_session_policy` is an operator config flag on an installed agent: with
// it set, the agent opens every session VIEW-ONLY and stays there until a signed policy verifies. The
// control plane only ever minted for an enforcing GROUP, and the flag's own doc said "Set BOTH for an
// enforcing deployment" without mentioning groups. So an agent shipped with the flag, in a group whose
// mandate an admin later cleared — or never set — was view-only forever: no input, no reboot, no
// command bar, retrying never helps, nothing on screen explaining why.
//
// THE LEVEL IS THE WHOLE POINT, so most of what follows is about it. A `view_only` mint would not fix
// anything (the agent is already view-only); only `control` discharges the provisional floor. That is
// why this change had to spend the containment `const access = SessionAccessViewOnly` used to buy, and
// why the agent-side session binding in agent/src/session_policy.rs is its replacement rather than a
// nice-to-have. See the comment block at handleStartSession's mint site.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	floorTestDevice = "22222222-2222-4222-8222-222222222222"
	floorTestGroup  = "33333333-3333-4333-8333-333333333333"
)

// startForFloorMintTest is startForMintTest's sibling for a REAL (strict-store) machine, because the
// flag lives on a machine row and the permissive dev store fabricates rows that have no flag at all.
// Returns the server and the decoded POST /sessions response.
func startForFloorMintTest(t *testing.T, machineFlagged, groupEnforces bool) (*Server, *httptest.ResponseRecorder, startSessionResponse) {
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

	// STRICT store: the permissive one fabricates a machine per device id, and a fabricated machine
	// can never carry a reported flag. Using it here would make every arm below vacuous.
	machines := NewInMemoryMachineStore()
	srv.Machines = machines
	m := &Machine{
		DeviceID:             floorTestDevice,
		GroupID:              floorTestGroup,
		Name:                 "HOST",
		RequireSessionPolicy: machineFlagged,
	}
	if err := machines.EnrollMachine(t.Context(), "tenant-123", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if groupEnforces {
		if err := srv.GroupSessionPolicies.Set(t.Context(), "tenant-123", floorTestGroup,
			GroupSessionPolicy{EnforceViewOnly: true}); err != nil {
			t.Fatalf("set group policy: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"`+floorTestDevice+`"}`)))
	var out startSessionResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode start response: %v (%s)", err, rec.Body.String())
		}
	}
	return srv, rec, out
}

// The full truth table of (machine flagged × group enforces). All four arms matter, and three of them
// would pass on a wrong implementation if the fourth were missing.
func TestStartSessionMintsForAFlaggedMachineAtTheGroupsCurrentLevel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flagged   bool
		enforces  bool
		wantMint  bool
		wantLevel SessionAccessLevel
		why       string
	}{
		{
			name: "neither: no policy", flagged: false, enforces: false, wantMint: false,
			why: "an agent nobody floored, in a group that asked for nothing, must be left alone — " +
				"minting here would fail closed on every agent without a pinned issuer key",
		},
		{
			name: "group only: view_only", flagged: false, enforces: true, wantMint: true, wantLevel: SessionAccessViewOnly,
			why: "the pre-loop-86 behaviour, unchanged: the mandate binds the technician",
		},
		{
			name: "machine only: CONTROL", flagged: true, enforces: false, wantMint: true, wantLevel: SessionAccessControl,
			why: "THE FIX. The agent floored itself and only a `control` policy discharges that floor; " +
				"minting `view_only` here would leave it exactly as stranded as minting nothing",
		},
		{
			name: "both: view_only wins", flagged: true, enforces: true, wantMint: true, wantLevel: SessionAccessViewOnly,
			why: "the mandate is a RESTRICTION and the self-floor is a request to be told the level — " +
				"a flagged machine must never be able to talk its way up out of its group's mandate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, rec, out := startForFloorMintTest(t, tc.flagged, tc.enforces)
			if rec.Code != http.StatusCreated {
				t.Fatalf("start = %d, want 201: %s", rec.Code, rec.Body.String())
			}
			if !tc.wantMint {
				if out.SessionPolicy != nil {
					t.Fatalf("a policy was minted (%+v): %s", out.SessionPolicy, tc.why)
				}
				return
			}
			if out.SessionPolicy == nil {
				t.Fatalf("NO policy was minted: %s", tc.why)
			}
			if out.SessionPolicy.Access != string(tc.wantLevel) {
				t.Fatalf("access = %q, want %q: %s", out.SessionPolicy.Access, tc.wantLevel, tc.why)
			}
			// The cleartext `access` is a convenience for the viewer; the SIGNED claims are what the
			// agent enforces. They must agree, or the console shows one thing and the agent does
			// another — and only the signed half is authoritative.
			var signed SignedSessionPolicy
			if err := json.Unmarshal([]byte(out.SessionPolicy.Signed), &signed); err != nil {
				t.Fatalf("decode signed policy: %v", err)
			}
			if signed.Access() != tc.wantLevel {
				t.Fatalf("SIGNED access = %q but the cleartext said %q", signed.Access(), tc.wantLevel)
			}
		})
	}
}

// The policy a flagged machine gets must be a REAL, verifiable artifact bound to this session and this
// device — not a well-shaped placeholder. This is the assertion the agent's own verify() mirrors.
func TestAFlaggedMachinesPolicyVerifiesAndIsBoundToThisSession(t *testing.T) {
	_, rec, out := startForFloorMintTest(t, true, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("start = %d: %s", rec.Code, rec.Body.String())
	}
	if out.SessionPolicy == nil {
		t.Fatal("no policy minted for a flagged machine")
	}
	var signed SignedSessionPolicy
	if err := json.Unmarshal([]byte(out.SessionPolicy.Signed), &signed); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Bound to THIS session. The agent compares this against the session id signaling reports from
	// the verified ticket, so a mismatch here is a policy no agent could ever install.
	if signed.Claims.Policy.SessionID != out.Session.ID {
		t.Fatalf("policy session_id = %q, want this session %q — the agent's session binding would "+
			"reject its own session's policy", signed.Claims.Policy.SessionID, out.Session.ID)
	}
	// Bound to the DEVICE id (not the machine PK), matching the H3 binding the agent checks.
	if signed.Claims.Policy.MachineID != floorTestDevice {
		t.Fatalf("policy machine_id = %q, want the device id %q", signed.Claims.Policy.MachineID, floorTestDevice)
	}
	if signed.Claims.ExpiresAtMs <= signed.Claims.IssuedAtMs {
		t.Fatalf("policy is already expired: %+v", signed.Claims)
	}

	// And the signature is real, against the issuer's own key.
	pub, err := hex.DecodeString(goldenPubkeyHex)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	msg, err := sessionPolicySigningBytes(
		signed.Claims.Policy.TechnicianID, signed.Claims.Policy.SessionID, signed.Claims.Policy.MachineID,
		signed.Claims.Policy.Access, signed.Claims.Policy.AllowRecording,
		signed.Claims.Policy.RequireRecording, signed.Claims.Policy.MaxSessionDurationSeconds, signed.Claims.Policy.MaxIdleSeconds, signed.Claims.IssuedAtMs, signed.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	sig, err := hex.DecodeString(signed.Sig)
	if err != nil {
		t.Fatalf("sig hex: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("the policy minted for a flagged machine does not verify against the issuer key")
	}
}

// FAIL CLOSED in the DISCHARGE direction too. When the mint cannot happen — a non-uuid device id, the
// DEV/self-hosted shape — the start is REFUSED rather than quietly handing back a session the agent has
// already floored and nothing will ever release.
//
// Silently degrading here would be the worst outcome available: the technician gets a session that
// looks fine in the console and is inert on the desk, which is precisely the symptom loop 86 exists to
// remove. An error at least says so.
func TestStartSessionFailsClosedWhenAFlaggedMachinesPolicyCannotBeMinted(t *testing.T) {
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

	machines := NewInMemoryMachineStore()
	srv.Machines = machines
	// A NON-UUID device id: the canonical preimage needs real uuids, so the mint fails.
	m := &Machine{DeviceID: "dev-1", GroupID: floorTestGroup, Name: "HOST", RequireSessionPolicy: true}
	if err := machines.EnrollMachine(t.Context(), "tenant-123", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/sessions",
		strings.NewReader(`{"machine_id":"dev-1"}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start = %d, want 500 — a flagged machine whose policy cannot be minted must be "+
			"refused, not handed a permanently floored session: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "signaling") || strings.Contains(rec.Body.String(), "session_policy") {
		t.Fatalf("the refusal leaked a usable session: %s", rec.Body.String())
	}

	// And it must not strand an OPEN session record holding a concurrency seat against both caps.
	recs, err := srv.SessionRecords.ListSessions(t.Context(), "tenant-123", SessionSummaryFilter{})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("premise not met: no session record was inserted, so there is nothing to have leaked")
	}
	for i := range recs {
		if recs[i].EndedAt == nil {
			t.Fatalf("session %s was left OPEN after the refusal — it holds a seat until reaped", recs[i].ID)
		}
	}
}
