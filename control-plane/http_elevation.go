package controlplane

// POST /sessions/{id}/elevation — mint ONE signed, single-use elevation grant for a live session
// (docs/01 §3 "Elevate client to admin mid-session", loop 87).
//
// The viewer calls this once per elevated command, forwards the returned blob to the agent inside a
// Control-channel `ElevatedRun`, and the agent verifies + burns it. There is no elevated "mode": the
// grant authorizes exactly one command, which is what makes the audit event below meaningful (one
// event per elevated command, not one per session).
//
// See elevation_mint.go for the artifact itself and why it is deliberately NOT a session policy.

import (
	"errors"
	"net/http"
	"time"
)

// handleMintElevation mints an elevation grant for the session named in the path.
//
// The order of checks mirrors handleEndSession / handleSetSessionNote: resolve the session from the
// STORE (never from the caller), gate on the capability scoped to that session's machine group, then
// act. THREE refusals are specific to elevation, listed here in the order the code applies them:
//
//   - a session that has ENDED can never legitimately be elevated;
//   - an ATTENDED (ephemeral) machine cannot be elevated AT ALL, because its agent runs as the guest
//     at medium integrity and Windows will not let it create a high-integrity process without a UAC
//     consent no remote peer can supply (loop 84 measured this on LAB-VM). That refusal is
//     UNREACHABLE-BY-CONSTRUCTION defence in depth rather than a live gate: `session_record` has one
//     production writer (handleStartSession), and it already refuses to create a record for an
//     ephemeral machine at all, so GetSession above 404s first for every attended session that exists
//     today. Kept so the invariant survives a future second writer of session_record, and because it
//     is not the enforcement either way: the agent refuses elevation on that host too
//     (`can_elevate()`), the control plane not being the party that knows which host it is talking
//     to. A test pins it by writing such a record directly;
//   - an administratively out-of-service (quarantined/retired) machine is refused —
//     refuseOutOfServiceMachine, shared with handleStartSession and handleMintGrant since loop 88.
//     READ THAT HELPER'S COMMENT before describing this as containment: quarantine does NOT end open
//     sessions, and this does not contain them either. The same live session keeps arbitrary SYSTEM
//     command execution, tool launch, reboot and shutdown, all ungated on the plain Control channel.
//     What it buys is that no new signed, AUDITED authorization is issued against a box the operator
//     has closed.
//
// (Two more complete the ladder and are not elevation-specific: the capability check, and the 403
// for a technician who does not hold this session.)
//
// The GetMachine round trip is load-bearing regardless of any of them: the mint signs `m.DeviceID`
// and the audit event records `m.ID`.
func (s *Server) handleMintElevation(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	rec, err := s.SessionRecords.GetSession(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			writeError(w, http.StatusNotFound, "unknown session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve session")
		return
	}
	// Group-scoped on the STORED record's machine group, so the caller cannot widen their own scope
	// by naming a session they cannot see. Note this is the machine's LIVE group (see the
	// SessionRecord doc): a machine moved into a group the caller does not administer stops being
	// elevatable by them immediately, which is the behaviour an operator would expect from a move.
	if err := p.Grant.RequireMachine(CapElevateSession, rec.MachineGroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if rec.EndedAt != nil {
		writeError(w, http.StatusConflict, "session has ended")
		return
	}
	// Only the technician whose session this is may elevate it. Not redundant with the capability:
	// an Admin holds CapElevateSession for the whole tenant, and without this they could mint a
	// grant naming someone else's live session. It would be useless to them — the grant is bound to
	// a session id only that technician's peer connection can present — but it would appear in the
	// audit trail as an elevation of a session they were never on, which is exactly the kind of
	// record an auditor must be able to trust.
	if !sameUserID(p.UserID, rec.TechnicianID) {
		writeError(w, http.StatusForbidden, "only the technician holding this session may elevate it")
		return
	}
	// Admission mode survives group-policy changes; observers never receive an
	// actuating grant even if the group's current mandate permits control.
	if rec.Access == "view_only" {
		writeError(w, http.StatusForbidden, "this session is an observer; elevation is forbidden")
		return
	}
	m, err := s.Machines.GetMachine(r.Context(), p.TenantID, rec.MachineDeviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if m.Ephemeral {
		writeError(w, http.StatusConflict,
			"an attended session cannot be elevated: the agent runs at the guest's own integrity "+
				"level and Windows will not let it elevate without a UAC prompt")
		return
	}
	if refuseOutOfServiceMachine(w, m, "elevate") {
		return
	}
	// A group mandated view-only refuses every write-action at the agent already, so an elevation
	// minted for it could never be used. Refusing at the mint keeps the mandate legible: an operator
	// who set the group to view-only should not see elevation grants being issued against it in the
	// audit trail, however inert they are.
	if s.GroupSessionPolicies != nil && rec.MachineGroupID != "" {
		eff, gerr := s.EffectivePolicy(r.Context(), p.TenantID, rec.MachineGroupID)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve group session policy")
			return
		}
		if eff.Conflict != "" {
			writeError(w, http.StatusConflict, eff.Conflict)
			return
		}
		gp := eff.GroupSessionPolicy
		if gp.EnforceViewOnly {
			writeError(w, http.StatusConflict,
				"this machine's group is mandated view-only; elevation cannot apply")
			return
		}
	}

	// A FRESH id per mint — this is the value the agent burns to make the grant single-use. Reusing
	// one would make the technician's second elevated command look like a replay of their first.
	elevationID := newUUID()
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	now := issuanceNow()
	expires := now + elevationGrantTTL.Milliseconds()
	// machine_id is the DEVICE id, matching the binding the agent checks (it compares against its own
	// device uuid) and matching how a backstage grant and a session policy are minted.
	signed, err := s.Grants.MintElevation(p.UserID, rec.ID, m.DeviceID, elevationID,
		ElevationTokenLinkedElevated, now, expires)
	if err != nil {
		// The canonical preimage needs REAL uuids, and DEV/self-hosted deployments run with synthetic
		// ids ("dev-1"). Refusing is the only safe answer: a grant that cannot be minted must not
		// degrade into an unelevated command the technician believes was elevated.
		writeError(w, http.StatusBadRequest,
			"could not mint an elevation grant for this session: "+err.Error())
		return
	}
	signedJSON, jerr := signed.JSON()
	if jerr != nil {
		writeError(w, http.StatusInternalServerError, "could not encode the elevation grant")
		return
	}
	// Audited BEFORE the grant leaves the process, and an audit failure FAILS the request: a
	// privilege handed out without a record is exactly the event an auditor needs. Nothing to undo on
	// failure — unlike a password reset, the artifact has not escaped yet.
	//
	// The TOKEN KIND is recorded, not merely the fact of a mint, so "was anything AUTHORIZED to run
	// elevated on this session, and with which token?" is answerable from the trail alone. Read the
	// question precisely: this event attests the AUTHORIZATION, not the execution. The agent may
	// still refuse the grant (no elevatable host, no pinned issuer, expired, already burned) or the
	// command may never be sent, so the trail is an over-approximation of what actually ran
	// elevated. That is the safe direction for an audit trail to err, and closing the gap would mean
	// trusting an endpoint's report of its own privilege use. The elevation_id ties this event to
	// the at-most-one command the agent could have run with it.
	if err := s.recordMgmtAudit(r, "session.elevation_minted", "session", rec.ID, map[string]any{
		"machine_id":   m.ID,
		"device_id":    m.DeviceID,
		"elevation_id": elevationID,
		"token":        string(ElevationTokenLinkedElevated),
		"expires_at":   time.UnixMilli(expires).UTC().Format(time.RFC3339),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"elevation": map[string]any{
			"elevation_id":  elevationID,
			"token":         string(ElevationTokenLinkedElevated),
			"expires_at_ms": expires,
			"signed":        signedJSON,
		},
	})
}
