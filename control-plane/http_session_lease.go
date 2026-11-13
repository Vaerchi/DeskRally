package controlplane

// POST /sessions/{id}/policy — RENEW the signed access policy of one live unattended session
// (docs/25 F03, "central End session does not terminate unattended remote access").
//
// WHAT THIS ENDPOINT IS FOR
//
// `POST /sessions/{id}/end` stamps `ended_at`, writes a `session.end` audit row and returns success.
// It sends nothing to signaling and nothing to the agent, and it never could: the only agent →
// control-plane call in this product is one-shot enrollment, so there is no authenticated channel on
// which to push a revocation to a running agent. An unattended session therefore closed only for a
// peer's COOPERATIVE `EndSession` control message, a local stop, a transport failure or the session
// lifetime bound — and a hostile controller simply never sends the cooperative message. The
// administrator's primary incident-response control was cosmetic.
//
// The chosen fix is a short renewable LEASE rather than a pushed revocation. The agent already
// verifies an Ed25519 `SignedSessionPolicy` bound to (technician, session, machine) against a pinned
// issuer key, with `issued_at_ms` / `expires_at_ms` in the signed body; it simply never re-evaluated
// it after install. So a lease is a TTL change plus a periodic re-check plus this renewal path — no
// new cryptosystem, no new agent authentication protocol, no new key to provision.
//
// THE RULE THAT MAKES IT WORK
//
// **The ABSENCE of a fresh lease ends the session; a bad lease ending it is not enough.** Renewal is
// performed by the viewer — the party the policy restrains — which sounds fatal and is not: a
// controller that stops renewing kills its own session, and one that wants to persist has to keep
// asking HERE, where every refusal below applies. There is nothing it can withhold that helps it.
//
// WHY THE CHECKS ARE RE-RUN RATHER THAN THE SIGNATURE JUST REISSUED
//
// docs/25 F03 says it explicitly: "Ticket redemption must reject ended/revoked sessions and disabled
// principals, not just duplicate ticket IDs." Signaling's ticket check is a signature plus a
// single-use ledger and knows nothing about session state, so the authorization re-check has to
// happen somewhere. It happens here, on a path the session cannot avoid, every ten seconds or so:
//
//   - a DISABLED principal or a SUSPENDED tenant cannot authenticate at all, so they never reach
//     this handler (SessionAuthenticator re-reads both on every request — see auth.go's
//     ErrUserDisabled / ErrTenantSuspended). That is why there is no explicit check for either
//     below, and why the tests for them drive the whole handler chain rather than this function;
//   - an ENDED session is refused here;
//   - a QUARANTINED or RETIRED machine is refused here, through the same refuseOutOfServiceMachine
//     that start / grant-mint / elevation use. Quarantine now actually contains a live session
//     instead of merely refusing new ones — read that helper's comment, which says the opposite,
//     because it was written before leases existed;
//   - the capability is re-resolved against the machine's CURRENT group, so moving a machine out of
//     a caller's scope ends their session within one lease.
//
// It also re-reads the group's view-only mandate, so an administrator who switches a group to
// view-only mid-session has the NEXT lease carry `view_only`, and the agent's ratchet drops the live
// session to view-only within one renewal instead of at the next session.
//
// NOT AUDITED, DELIBERATELY. A renewal fires every ten seconds per live session; recording each one
// would bury the trail this product's audit chain exists to make readable, and it would attest
// nothing new — `session.start` already records that the session exists and `session.end` records
// the decision that stops these renewals succeeding. The interesting events are the ones that are
// already written.

import (
	"net/http"
	"time"
)

// handleRenewSessionPolicy mints the next lease for a live unattended session.
//
// The order of checks mirrors handleMintElevation deliberately — resolve the session from the STORE
// (never from the caller), gate the capability on that session's machine group, then act — so a
// reader who knows one route knows this one. The capability is CapStartSession rather than a new
// one: renewing is continuing to hold a session, and anyone who may open a session on a machine may
// keep holding it.
func (s *Server) handleRenewSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// Every authorization condition lives in checkHeldSession (session_authz.go), shared with the
	// toolbox run endpoint so "may this holder keep acting on the session" has one definition. Its
	// order is the one this handler always had: resolve the session from the STORE, gate the
	// capability on the stored record's (live) machine group, refuse an ended session (409, so a
	// console can tell "someone ended this" from "no such session"), require the caller to be the
	// technician holding it, then the tenant's max-age, the machine's service state, and finally the
	// group's CURRENT access mandate, re-read on every renewal: flipping a group to view-only binds the
	// running sessions at their next lease, and the agent's one-way ratchet keeps it there.
	held, refusal := s.checkHeldSession(r.Context(), p, r.PathValue("id"), "renew a session lease")
	// A session handed over (docs/51) stops renewing the moment the receiver accepts: the holder's
	// viewer closes within one renewal interval and says why, instead of the generic ended error. Only
	// the HOLDER learns the recipient's name. S1 is still open while releasing and already ended once
	// accepted, so both the success and the "ended" refusal are checked.
	if refusal == nil || refusal.Status == http.StatusConflict && refusal.Msg == "session has ended" {
		if s.transferredRefusal(w, r.Context(), p, r.PathValue("id"), heldRec(held)) {
			return
		}
	}
	if refusal != nil {
		// Server-authoritative max-age expiry: the one renewal step that WRITES. Stamp the session
		// ended (idempotent; EndSession writes ended_at once) and refuse the mint; the agent's current
		// lease runs out within sessionPolicyLeaseTTL and it tears the session down itself. Reached
		// only after the holder check, so an unauthorized caller can never trigger the write.
		if refusal.Expired {
			rec := held.Rec
			if _, endErr := s.SessionRecords.EndSession(r.Context(), p.TenantID, rec.ID, time.Now().UTC()); endErr != nil {
				writeError(w, http.StatusInternalServerError, "could not end expired session")
				return
			}
			if err := s.recordMgmtAudit(r, "session.end", "session", rec.ID,
				map[string]any{"machine_id": rec.MachineID, "reason": "maximum_duration"}); err != nil {
				writeError(w, http.StatusInternalServerError, "could not record audit event")
				return
			}
		}
		refusal.write(w)
		return
	}
	rec, m, access := held.Rec, held.Machine, held.Access
	if rec.Access == "view_only" {
		// The admission mode is immutable. Clearing a group mandate cannot upgrade an
		// observer, and losing the additional observe permission stops further leases.
		if err := p.Grant.RequireMachine(CapObserveSession, m.GroupID); err != nil {
			writeDenied(w, err)
			return
		}
		access = SessionAccessViewOnly
	}
	// Pass4: the four group restrictions (prohibit_recording, require_recording,
	// max_session_duration_seconds, max_idle_seconds) are not applied at renewal. Session starts are
	// refused when any of these are set (handleStartSession), so no live session should carry them;
	// and an operator adding them to a group mid-session must not silently acquire unenforceable
	// policy on an already-running old agent. They stay at their zero-value defaults.
	allowRecording := true
	requireRecording := false
	var maxSessionDurationSeconds uint32
	var maxIdleSeconds uint32
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	now := issuanceNow()
	expires := now + sessionPolicyLeaseTTL.Milliseconds()
	// TechnicianID from the RECORD, not p.UserID. They are equal by the check above; using the
	// record's keeps the signed `technician_id` identical across every lease of a session even if
	// that check is ever relaxed, so an agent-side comparison would not start seeing it move.
	// machine_id is the DEVICE id, matching the binding the agent checks against its own device uuid.
	signed, err := s.Grants.MintSessionPolicy(rec.TechnicianID, rec.ID, m.DeviceID, access, allowRecording, requireRecording, maxSessionDurationSeconds, maxIdleSeconds, now, expires)
	if err != nil {
		// The canonical preimage needs REAL uuids and DEV/self-hosted deployments run with synthetic
		// ids ("dev-1"). A 400 is the honest answer: nothing is wrong with the request, the
		// deployment cannot mint this artifact at all. Such a deployment also runs signaling without
		// ticket verification, so its agents derive "not leased" and never ask for one — nothing
		// breaks, and a console that asks anyway learns why.
		writeError(w, http.StatusBadRequest,
			"could not mint a session lease for this session: "+err.Error())
		return
	}
	signedJSON, jerr := signed.JSON()
	if jerr != nil {
		writeError(w, http.StatusInternalServerError, "could not encode the session access policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_policy": map[string]any{
			"access":    string(access),
			"view_only": access == SessionAccessViewOnly,
			"signed":    signedJSON,
			// `lease_ttl_ms` is a DURATION, not an instant, and that is the point: the viewer
			// schedules its next renewal from it without needing its clock to agree with the control
			// plane's. `expires_at_ms` is there for logging and for a console that wants to show a
			// countdown; it is not what the renewal cadence is computed from.
			"lease_ttl_ms":  sessionPolicyLeaseTTL.Milliseconds(),
			"expires_at_ms": expires,
		},
	})
}
