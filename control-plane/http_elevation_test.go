package controlplane

// Proofs for POST /sessions/{id}/elevation (docs/01 §3, loop 87) — the HTTP surface that mints a
// signed, single-use elevation grant for one live session. The artifact itself (canonical bytes,
// domain separation, token kind, TTL) is proven in elevation_mint_test.go; this file is about WHO
// may ask for one, WHEN, and what the audit trail records.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// elevationTestServer builds a server whose stores are shared-able across principals, with a wired
// grant issuer (the route is only mounted when one exists) and one OPEN session owned by `owner`.
func elevationTestServer(t *testing.T, p *Principal) (*Server, *SessionRecord) {
	t.Helper()
	srv, _ := newTestServer(p)
	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv.Grants = iss
	// The device id must be a REAL uuid: the canonical preimage parses it to 16 raw bytes, so a
	// synthetic "m1" would fail the mint and turn every 200 below into a 400 for the wrong reason.
	rec := &SessionRecord{
		MachineID:       newUUID(),
		TechnicianID:    p.UserID,
		MachineGroupID:  "group-a",
		MachineDeviceID: newUUID(),
		MachineName:     "HOST",
	}
	if err := srv.SessionRecords.StartSession(context.Background(), p.TenantID, rec); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return srv, rec
}

func postElevation(h http.Handler, id string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/sessions/"+id+"/elevation", nil))
	return rr
}

type elevationResponse struct {
	Elevation struct {
		ElevationID string `json:"elevation_id"`
		Token       string `json:"token"`
		ExpiresAtMs int64  `json:"expires_at_ms"`
		Signed      string `json:"signed"`
	} `json:"elevation"`
}

// The happy path, and everything it must be true of: a verifiable grant naming THIS session and
// THIS device, a fresh single-use id, a `linked_elevated` token, a bounded window, and an audit
// event that records the token kind (not merely that something happened).
func TestMintElevationHandler(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	owner := &Principal{UserID: "11111111-1111-1111-1111-111111111111", TenantID: tid,
		Grant: NewGrant("11111111-1111-1111-1111-111111111111", tid, NewMembership(RoleOwner, AllGroups()))}
	srv, rec := elevationTestServer(t, owner)

	before := time.Now().UTC().UnixMilli()
	rr := postElevation(srv.Handler(), rec.ID)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp elevationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Elevation.Token != string(ElevationTokenLinkedElevated) {
		t.Fatalf("token = %q, want linked_elevated", resp.Elevation.Token)
	}
	if _, err := uuidBytes(resp.Elevation.ElevationID); err != nil {
		t.Fatalf("elevation_id is not a uuid: %v", err)
	}
	// The window is elevationGrantTTL, not the session policy's 15 minutes. Asserted against the
	// constant rather than a literal, so the two cannot drift — and BOUNDED BELOW as well as above:
	// a one-sided `<= TTL` check admits a zero-length (or already-expired) window, which is the
	// mistake that would make every mint fail at the agent for a reason the console cannot see.
	if got := resp.Elevation.ExpiresAtMs - before; got < elevationGrantTTL.Milliseconds()-2_000 ||
		got > elevationGrantTTL.Milliseconds()+2_000 {
		t.Fatalf("expires_at_ms is %d ms from now, want ~%d", got, elevationGrantTTL.Milliseconds())
	}

	// The blob is a real, verifiable SignedElevationGrant naming this session and this device.
	var signed SignedElevationGrant
	if err := json.Unmarshal([]byte(resp.Elevation.Signed), &signed); err != nil {
		t.Fatalf("signed blob does not decode: %v", err)
	}
	if signed.Claims.Elevation.SessionID != rec.ID {
		t.Fatalf("grant session_id = %q, want %q", signed.Claims.Elevation.SessionID, rec.ID)
	}
	if signed.Claims.Elevation.MachineID != rec.MachineDeviceID {
		t.Fatalf("grant machine_id = %q, want the DEVICE id %q — the agent compares against its own "+
			"device uuid, so a machine PK here would be refused by every agent",
			signed.Claims.Elevation.MachineID, rec.MachineDeviceID)
	}
	if signed.Claims.Elevation.ElevationID != resp.Elevation.ElevationID {
		t.Fatalf("the response's elevation_id and the signed one differ (%q vs %q) — the audit trail "+
			"would then name an id the agent never sees",
			resp.Elevation.ElevationID, signed.Claims.Elevation.ElevationID)
	}
	// The TOKEN KIND inside the SIGNED claims, not the plaintext echo beside it. The echo is what
	// the console displays; the claims are what the agent enforces. A handler that echoed
	// "linked_elevated" while signing `base` would authorize nothing, and every assertion that read
	// only the echo would still pass.
	if signed.Claims.Elevation.Token != ElevationTokenLinkedElevated {
		t.Fatalf("the SIGNED token kind is %q, want linked_elevated — the response echo says %q, so "+
			"this mint authorizes nothing while looking correct",
			signed.Claims.Elevation.Token, resp.Elevation.Token)
	}
	// Likewise the window: the signed expiry is what the agent checks, the echoed one is decoration.
	if signed.Claims.ExpiresAtMs != resp.Elevation.ExpiresAtMs {
		t.Fatalf("the signed expiry (%d) and the echoed one (%d) differ",
			signed.Claims.ExpiresAtMs, resp.Elevation.ExpiresAtMs)
	}
	if got := signed.Claims.ExpiresAtMs - signed.Claims.IssuedAtMs; got != elevationGrantTTL.Milliseconds() {
		t.Fatalf("the signed window is %d ms, want exactly elevationGrantTTL (%d ms)",
			got, elevationGrantTTL.Milliseconds())
	}
	if signed.Claims.Elevation.TechnicianID != owner.UserID {
		t.Fatalf("the grant names technician %q, want the caller %q — the audit trail attributes "+
			"elevation to whoever the CLAIMS say",
			signed.Claims.Elevation.TechnicianID, owner.UserID)
	}
	// And the signature actually verifies against the issuer's key over the canonical preimage.
	msg, err := elevationSigningBytes(signed.Claims.Elevation.TechnicianID, signed.Claims.Elevation.SessionID,
		signed.Claims.Elevation.MachineID, signed.Claims.Elevation.ElevationID,
		signed.Claims.Elevation.Token, signed.Claims.IssuedAtMs, signed.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	pub, perr := hex.DecodeString(srv.Grants.PublicKeyHex())
	if perr != nil {
		t.Fatalf("decode pubkey: %v", perr)
	}
	sigBytes, serr := hex.DecodeString(signed.Sig)
	if serr != nil {
		t.Fatalf("decode sig: %v", serr)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sigBytes) {
		t.Fatal("the minted grant does not verify against the issuer's public key")
	}

	// A SECOND mint yields a DIFFERENT single-use id. Reusing one would make the technician's second
	// elevated command look to the agent like a replay of their first.
	rr2 := postElevation(srv.Handler(), rec.ID)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second mint = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 elevationResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	if resp2.Elevation.ElevationID == resp.Elevation.ElevationID {
		t.Fatal("two mints shared one elevation_id — the agent's single-use ledger would refuse the second")
	}

	// AUDIT: one event per mint, naming the token kind and the single-use id.
	events, err := srv.MgmtAudit.ListEvents(ctx, tid, 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	minted := 0
	var mintedIDs []string
	for _, e := range events {
		if e.Action != "session.elevation_minted" {
			continue
		}
		minted++
		if e.TargetKind != "session" || e.TargetID != rec.ID {
			t.Fatalf("audit target = %s/%s, want session/%s", e.TargetKind, e.TargetID, rec.ID)
		}
		var meta map[string]any
		b, _ := json.Marshal(e.Metadata)
		if err := json.Unmarshal(b, &meta); err != nil {
			t.Fatalf("audit metadata is not an object: %s", b)
		}
		// By VALUE, not by key presence. `"elevation_id"` appearing in the JSON says nothing about
		// whether it names the grant the agent will actually burn — an empty string, or the wrong
		// id, would satisfy a substring check and leave the trail uncorrelatable with the command
		// that ran.
		if meta["token"] != string(ElevationTokenLinkedElevated) {
			t.Fatalf("audit token = %v, want linked_elevated: %s", meta["token"], b)
		}
		if meta["device_id"] != rec.MachineDeviceID {
			t.Fatalf("audit device_id = %v, want %q: %s", meta["device_id"], rec.MachineDeviceID, b)
		}
		id, _ := meta["elevation_id"].(string)
		if _, err := uuidBytes(id); err != nil {
			t.Fatalf("audit elevation_id %q is not a uuid: %s", id, b)
		}
		mintedIDs = append(mintedIDs, id)
	}
	if minted != 2 {
		t.Fatalf("got %d session.elevation_minted events, want one per mint (2)", minted)
	}
	// The two events name the two DIFFERENT grants, and between them the pair the caller received.
	// Without this, an audit trail that recorded the same id twice would pass everything above while
	// making the second elevated command untraceable.
	if len(mintedIDs) != 2 || mintedIDs[0] == mintedIDs[1] {
		t.Fatalf("the audit events do not name distinct grants: %v", mintedIDs)
	}
	if !slices.Contains(mintedIDs, resp.Elevation.ElevationID) ||
		!slices.Contains(mintedIDs, resp2.Elevation.ElevationID) {
		t.Fatalf("the audited ids %v do not match the minted ones (%s, %s)",
			mintedIDs, resp.Elevation.ElevationID, resp2.Elevation.ElevationID)
	}
}

// THE GROUP SCOPE. The capability is checked with RequireMachine against the session's machine
// group, not tenant-wide with Require. This principal holds CapElevateSession AND owns the session,
// so the ONLY thing that can refuse is the group scope — which is what makes downgrading
// `RequireMachine` to `Require` a lethal mutation instead of an invisible one.
func TestMintElevationIsScopedToTheMachineGroup(t *testing.T) {
	tid := "tenant-123"
	uid := "33333333-3333-3333-3333-333333333333"
	// An Admin (holds the capability) scoped to group-b only. The fixture's session is in group-a.
	scoped := &Principal{UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleAdmin, Groups("group-b")))}
	srv, rec := elevationTestServer(t, scoped)

	// PREMISE, stated locally: the principal DOES hold the capability, and DOES own the session. A
	// 403 below could otherwise mean either of those instead of the scope.
	if !RoleAdmin.Has(CapElevateSession) {
		t.Fatal("premise not met: Admin no longer holds CapElevateSession")
	}
	if !sameUserID(scoped.UserID, rec.TechnicianID) {
		t.Fatalf("premise not met: the fixture session is not owned by this principal")
	}
	if rec.MachineGroupID != "group-a" {
		t.Fatalf("premise not met: the fixture session is in %q, not group-a", rec.MachineGroupID)
	}
	if rr := postElevation(srv.Handler(), rec.ID); rr.Code != http.StatusForbidden {
		t.Fatalf("a group-b admin elevating a group-a session = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	// …and the SAME principal scoped to group-a succeeds, so the 403 is the scope and not the fixture.
	wide := &Principal{UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleAdmin, Groups("group-a")))}
	srv2, _ := newTestServer(wide)
	iss, err := GenerateGrantIssuer()
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	srv2.Grants = iss
	srv2.SessionRecords = srv.SessionRecords
	if rr := postElevation(srv2.Handler(), rec.ID); rr.Code != http.StatusOK {
		t.Fatalf("a group-a admin = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// THE CAPABILITY GATE. A Technician holds CapStartSession and CapEndSession and owns this very
// session — everything except the new capability — so a 403 here can only come from
// CapElevateSession. That is deliberate: an over-determined 403 (one the hierarchy would also
// produce) cannot mutation-test the gate.
func TestMintElevationRequiresTheElevateCapability(t *testing.T) {
	tid := "tenant-123"
	tech := &Principal{UserID: "22222222-2222-2222-2222-222222222222", TenantID: tid,
		Grant: NewGrant("22222222-2222-2222-2222-222222222222", tid, NewMembership(RoleTechnician, AllGroups()))}
	srv, rec := elevationTestServer(t, tech)

	// PREMISE, stated locally: this principal CAN act on the session in every other way. Without
	// this the 403 below would also pass for a technician who simply could not see the session.
	if err := tech.Grant.RequireMachine(CapEndSession, rec.MachineGroupID); err != nil {
		t.Fatalf("premise not met: a technician cannot even end this session: %v", err)
	}
	if rr := postElevation(srv.Handler(), rec.ID); rr.Code != http.StatusForbidden {
		t.Fatalf("technician = %d, want 403 — a technician may run commands but may not take the "+
			"guest's admin identity: %s", rr.Code, rr.Body.String())
	}
	// …and the roles that SHOULD hold it, do. Asserted through the role model rather than the
	// handler so a preset drift fails here too.
	for _, r := range []Role{RoleOwner, RoleAdmin} {
		if !r.Has(CapElevateSession) {
			t.Fatalf("%s must hold CapElevateSession", r)
		}
	}
	for _, r := range []Role{RoleTechnician, RoleReadOnly, RoleAuditor} {
		if r.Has(CapElevateSession) {
			t.Fatalf("%s must NOT hold CapElevateSession", r)
		}
	}
}

// An API TOKEN must never be able to hold this capability. The exclusion is structural (the mint
// path validates against the closed apiTokenGrantableCaps whitelist), so this asserts the whitelist
// rather than a runtime branch — a runtime "is this a token?" check cannot exist, because a token
// principal is indistinguishable from a DEV-mode stub principal by any field on Principal.
func TestElevateSessionIsNotGrantableToAnAPIToken(t *testing.T) {
	if IsAPITokenGrantableCapability(CapElevateSession) {
		t.Fatal("elevate_session is API-token-grantable — a principal with no user row and no " +
			"interactive session could mint a grant that runs a command with a guest's admin token")
	}
	// The whitelist is not simply empty: a capability that IS meant to be grantable still is.
	if !IsAPITokenGrantableCapability(CapViewMachines) {
		t.Fatal("premise not met: view_machines is no longer API-token-grantable, so the assertion " +
			"above proves nothing about elevate_session specifically")
	}
}

// The refusals that are specific to elevation.
func TestMintElevationRefusals(t *testing.T) {
	tid := "tenant-123"
	ctx := context.Background()
	uid := "11111111-1111-1111-1111-111111111111"
	owner := &Principal{UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups()))}

	t.Run("unknown session is 404", func(t *testing.T) {
		srv, _ := elevationTestServer(t, owner)
		if rr := postElevation(srv.Handler(), newUUID()); rr.Code != http.StatusNotFound {
			t.Fatalf("= %d, want 404", rr.Code)
		}
	})

	t.Run("an ENDED session cannot be elevated", func(t *testing.T) {
		srv, rec := elevationTestServer(t, owner)
		if _, err := srv.SessionRecords.EndSession(ctx, tid, rec.ID, time.Now().UTC()); err != nil {
			t.Fatalf("end: %v", err)
		}
		rr := postElevation(srv.Handler(), rec.ID)
		if rr.Code != http.StatusConflict {
			t.Fatalf("= %d, want 409: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "ended") {
			t.Fatalf("unhelpful body: %s", rr.Body.String())
		}
	})

	t.Run("another technician's session cannot be elevated, even by an Owner", func(t *testing.T) {
		srv, rec := elevationTestServer(t, owner)
		// Hand the session to someone else and re-ask as the Owner, who holds the capability for the
		// whole tenant. The grant would be unusable to them, but the audit trail must never record an
		// elevation of a session its actor was not on.
		other := &SessionRecord{
			MachineID:       rec.MachineID,
			TechnicianID:    "99999999-9999-9999-9999-999999999999",
			MachineGroupID:  rec.MachineGroupID,
			MachineDeviceID: rec.MachineDeviceID,
		}
		if err := srv.SessionRecords.StartSession(ctx, tid, other); err != nil {
			t.Fatalf("seed: %v", err)
		}
		rr := postElevation(srv.Handler(), other.ID)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("= %d, want 403: %s", rr.Code, rr.Body.String())
		}
		// And nothing was audited for the refused attempt beyond what the successful path writes.
		events, _ := srv.MgmtAudit.ListEvents(ctx, tid, 10)
		for _, e := range events {
			if e.Action == "session.elevation_minted" && e.TargetID == other.ID {
				t.Fatal("a refused mint was audited as if it had happened")
			}
		}
	})

	t.Run("an ATTENDED (ephemeral) machine cannot be elevated", func(t *testing.T) {
		srv, rec := elevationTestServer(t, owner)
		// Swap in a strict store holding this device as EPHEMERAL — the shape an attended guest has.
		strict := NewInMemoryMachineStore()
		if err := strict.EnrollMachine(ctx, tid, &Machine{
			ID: rec.MachineID, DeviceID: rec.MachineDeviceID, TenantID: tid,
			GroupID: rec.MachineGroupID, Status: MachineStatusActive, Ephemeral: true,
		}); err != nil {
			t.Fatalf("enroll: %v", err)
		}
		srv.Machines = strict
		rr := postElevation(srv.Handler(), rec.ID)
		if rr.Code != http.StatusConflict {
			t.Fatalf("= %d, want 409: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "UAC") {
			t.Fatalf("the refusal does not say WHY an attended session cannot elevate: %s", rr.Body.String())
		}
		// PREMISE: the same session on a NON-ephemeral machine does mint, so the 409 above is the
		// ephemeral check and not a broken fixture.
		strict2 := NewInMemoryMachineStore()
		if err := strict2.EnrollMachine(ctx, tid, &Machine{
			ID: rec.MachineID, DeviceID: rec.MachineDeviceID, TenantID: tid,
			GroupID: rec.MachineGroupID, Status: MachineStatusActive,
		}); err != nil {
			t.Fatalf("enroll 2: %v", err)
		}
		srv.Machines = strict2
		if rr := postElevation(srv.Handler(), rec.ID); rr.Code != http.StatusOK {
			t.Fatalf("premise not met: a permanent machine = %d, want 200: %s", rr.Code, rr.Body.String())
		}
	})

	// Quarantine is the operator's "stop using this box" switch, and it does NOT end sessions already
	// open on the machine — so this handler is the only place that can stop a machine pulled out of
	// service mid-incident from continuing to hand out the guest's full admin token. Both
	// out-of-service statuses, because a test that only pinned one would let the other be dropped.
	for _, status := range []string{MachineStatusQuarantined, MachineStatusRetired} {
		t.Run("a "+status+" machine cannot be elevated", func(t *testing.T) {
			srv, rec := elevationTestServer(t, owner)
			strict := NewInMemoryMachineStore()
			if err := strict.EnrollMachine(ctx, tid, &Machine{
				ID: rec.MachineID, DeviceID: rec.MachineDeviceID, TenantID: tid,
				GroupID: rec.MachineGroupID, Status: status,
			}); err != nil {
				t.Fatalf("enroll: %v", err)
			}
			srv.Machines = strict
			rr := postElevation(srv.Handler(), rec.ID)
			if rr.Code != http.StatusConflict {
				t.Fatalf("= %d, want 409: %s", rr.Code, rr.Body.String())
			}
			// WHICH refusal denied it, not merely that something did: the ephemeral and view-only
			// branches also answer 409, so asserting the status alone would pass if this machine were
			// refused for an unrelated reason (memory: regression-test-premise-drift).
			if !strings.Contains(rr.Body.String(), status) {
				t.Fatalf("a %s machine was refused for some OTHER reason: %s", status, rr.Body.String())
			}
			// Nothing may be audited as an elevation that was refused. The error is CHECKED, not
			// discarded: an errored listing yields a nil slice, the loop body never runs, and the
			// assertion silently becomes `true` — a negative that cannot fail.
			events, lerr := srv.MgmtAudit.ListEvents(ctx, tid, 10)
			if lerr != nil {
				t.Fatalf("list audit: %v", lerr)
			}
			for _, e := range events {
				if e.Action == "session.elevation_minted" && e.TargetID == rec.ID {
					t.Fatal("a refused mint was audited as if it had happened")
				}
			}
			// PREMISE, declared locally: the SAME session on an otherwise identical ACTIVE machine
			// does mint. Without this the 409 above would also pass on a fixture that could never
			// mint at all.
			active := NewInMemoryMachineStore()
			if err := active.EnrollMachine(ctx, tid, &Machine{
				ID: rec.MachineID, DeviceID: rec.MachineDeviceID, TenantID: tid,
				GroupID: rec.MachineGroupID, Status: MachineStatusActive,
			}); err != nil {
				t.Fatalf("enroll active: %v", err)
			}
			srv.Machines = active
			if rr := postElevation(srv.Handler(), rec.ID); rr.Code != http.StatusOK {
				t.Fatalf("premise not met: an active machine = %d, want 200: %s", rr.Code, rr.Body.String())
			}
		})
	}

	t.Run("a view-only-mandated group cannot be elevated", func(t *testing.T) {
		srv, rec := elevationTestServer(t, owner)
		if err := srv.GroupSessionPolicies.Set(ctx, tid, rec.MachineGroupID, GroupSessionPolicy{
			GroupID: rec.MachineGroupID, EnforceViewOnly: true,
		}); err != nil {
			t.Fatalf("set group policy: %v", err)
		}
		rr := postElevation(srv.Handler(), rec.ID)
		if rr.Code != http.StatusConflict {
			t.Fatalf("= %d, want 409: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "view-only") {
			t.Fatalf("unhelpful body: %s", rr.Body.String())
		}
	})
}

// The route only exists when an issuer is wired — the same rule /grant/mint follows. Without an
// issuer there is nothing to sign with, and a 404 is a truer answer than a 500.
func TestMintElevationIsNotMountedWithoutAnIssuer(t *testing.T) {
	tid := "tenant-123"
	uid := "11111111-1111-1111-1111-111111111111"
	owner := &Principal{UserID: uid, TenantID: tid,
		Grant: NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups()))}
	srv, rec := elevationTestServer(t, owner)
	srv.Grants = nil
	if rr := postElevation(srv.Handler(), rec.ID); rr.Code != http.StatusNotFound {
		t.Fatalf("= %d, want 404 (route unmounted)", rr.Code)
	}
}
