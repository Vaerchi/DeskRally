package controlplane

// Backstage grant minting (H1b). Split out of http.go (routing and middleware stay there).

import (
	"errors"
	"net/http"
)

// -------------------------------------------------------------------------------------
// Backstage grant minting (H1b)
// -------------------------------------------------------------------------------------

// mintGrantRequest is the body of POST /grant/mint: the target machine, plus an optional session
// id (generated when absent).
type mintGrantRequest struct {
	// MachineID is the agent's DEVICE ID (the stable agent identity the console mints for and H3
	// binds the grant to) — NOT the database primary key. It is resolved via GetMachine (device id).
	MachineID string `json:"machine_id"`
	// MachineGroupID is DEPRECATED and IGNORED as of D1. It used to carry the machine's group
	// from the (untrusted) request body, which let a caller pick whichever group granted them the
	// widest backstage tier. The group is now resolved from the stored machine row instead. The
	// field is retained only so older clients that still send it deserialize cleanly; its value
	// has no effect on authorization.
	MachineGroupID string `json:"machine_group_id"`
	// SessionID is optional; a fresh UUID is minted when empty.
	SessionID string `json:"session_id"`
}

// refuseOutOfServiceMachine writes a 409 and returns true when `m` is administratively out of
// service — the operator's "stop using this box" switch. `verb` completes the sentence "reactivate
// it to <verb>".
//
// ONE function because there are now FOUR endpoints that hand a technician privilege against a
// named machine — handleStartSession, handleMintGrant, handleMintElevation and (since docs/25 F03)
// handleRenewSessionPolicy, which is the one that KEEPS privilege rather than granting it — and loop 88 found
// them disagreeing: the status refusal had been written twice and the third site had never had it,
// so quarantining a machine mid-incident stopped new sessions and elevation grants while a BACKSTAGE
// grant (strictly more capability, and a longer TTL) could still be minted against the same box on
// the session already open. That is this project's `defence-built-but-not-applied` lesson exactly:
// a new guard's call sites must be diffed against its siblings. Route the fourth one through here.
//
// READ WHAT THIS DOES AND DOES NOT BUY, because the first version of this comment over-claimed and
// the answer has since CHANGED — in one direction only, so read both halves.
//
// What it always bought: no new signed, audited authorization is ISSUED against a machine the
// operator has pulled out of service, so the audit trail cannot show privilege being granted on a box
// that was administratively closed, and every path a policy could later be attached to refuses.
//
// What it did NOT buy, and still does not on an UNLEASED session: quarantine does not end a session
// already open. That session keeps arbitrary SYSTEM command execution, tool launch, reboot and
// shutdown, all ungated on the plain Control channel (see `rmt_agent::elevation`'s "what this gate
// IS — and, precisely, what it is not"). An unleased session is one the agent cannot have revoked:
// dev/LAN (signaling vouches for no control-plane session), attended (revoked by its own three-second
// status poll instead), or an agent with no `grant_issuer_pubkey` pinned to verify a lease with.
//
// What it buys SINCE docs/25 F03: on a LEASED session the fifth call site — handleRenewSessionPolicy
// — makes this refusal terminate the live session. The agent holds no authority beyond its current
// lease, the renewal is refused here, and the session tears itself down within one
// sessionPolicyLeaseTTL. Quarantine finally contains rather than merely closes the door behind it.
func refuseOutOfServiceMachine(w http.ResponseWriter, m *Machine, verb string) bool {
	if msg := outOfServiceMachineMsg(m, verb); msg != "" {
		writeError(w, http.StatusConflict, msg)
		return true
	}
	return false
}

// handleMintGrant mints a short-TTL, signed backstage grant for the authenticated technician. It
// runs behind the auth → tenant (RLS) chain, resolves the technician's backstage capabilities for
// the target machine's group (BackstageCapsFor — mandatory CapBackstageShell, admin tier gated on
// CapManageMachines), signs the canonical claims with the issuer key, and returns the SignedGrant
// JSON the browser forwards to the agent via Control::InstallGrant.
func (s *Server) handleMintGrant(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())

	var req mintGrantRequest
	// docs/25 F05. As at handleStartSession the decode precedes authorization and has to: the tier
	// this route grants is computed by BackstageCapsFor against the group the STORE resolves for
	// req.MachineID, so the body is the input to the authorization decision. The cap is what bounds
	// an unauthorized caller's cost here.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed mint request body"); err != nil {
		return
	}
	if req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}

	// D1 SECURITY FIX: resolve the machine's group from stored data, NOT from req.MachineGroupID
	// (which is ignored). Authorization — BackstageCapsFor — is then scoped to the machine's REAL
	// group, so a caller can no longer name a group to widen their capability tier.
	m, err := s.Machines.GetMachine(r.Context(), p.TenantID, req.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}

	caps, ok := BackstageCapsFor(p.Grant, m.GroupID)
	if !ok {
		writeDenied(w, &DeniedError{Capability: CapBackstageShell, GroupID: m.GroupID})
		return
	}
	// AFTER the capability check, so an unauthorized caller learns nothing about the machine's
	// administrative state (the same ordering the elevation mint uses). Added in loop 88: this was
	// the one privilege-issuing endpoint the operator's quarantine switch did not reach, which made
	// the switch bypassable by minting a backstage grant instead of an elevation one.
	if refuseOutOfServiceMachine(w, m, "use Under the Hood tools") {
		return
	}
	// A group mandated VIEW-ONLY refuses backstage grants too, unless the group carries the explicit
	// opt-out. This is the honesty fix for the label: enforce_view_only makes the AGENT drop input and
	// refuse reboot / tool-launch / command-run / lock / log-off / shut-down (AccessLevel::ViewOnly,
	// agent/src/session_policy.rs), but backstage — the remote shell and the tool panels — rides a
	// SEPARATE trust axis and the agent's backstage path never consults the session's access level. So
	// without this a technician holding CapBackstageShell could run commands as SYSTEM on a machine the
	// console labelled "view only". The two axes stay separate on purpose (see GroupSessionPolicy's scope
	// header); what is closed is the ISSUING of a new authorization against a group the operator declared
	// watch-only.
	//
	// Consistency, not novelty: handleMintElevation (http_elevation.go) has refused an ELEVATION grant on
	// exactly this mandate since it was written. Two privilege-issuing endpoints answering differently
	// about the same admin decision was the actual defect.
	//
	// AllowBackstageUnderViewOnly is the deliberate per-group opt-out for unattended maintenance — a patch
	// window, a scripted remediation — and its FALSE (zero) value is the protected one on purpose; see the
	// field comment and migration 0040. The nil-store and empty-group guards match the elevation twin and
	// the attended path: a deployment with no group-policy store wired (DEV) has no mandate to enforce, and
	// a machine in no group has no group policy to read.
	//
	// On an unattended host this is attribution and policy, not a privilege boundary — the agent already
	// runs as SYSTEM. What it buys is that no signed, audited backstage authorization is ISSUED against
	// such a group, which is the same thing refuseOutOfServiceMachine above buys for a quarantined machine.
	if s.GroupSessionPolicies != nil && m.GroupID != "" {
		eff, gerr := s.EffectivePolicy(r.Context(), p.TenantID, m.GroupID)
		if gerr != nil {
			// Fail CLOSED and say WHICH failure: an unreadable policy is not "no policy" (memory:
			// fail-closed-must-say-which-failure).
			writeError(w, http.StatusInternalServerError, "could not resolve group session policy")
			return
		}
		if eff.Conflict != "" { // docs/62 R4: an unsatisfiable merged policy mints nothing
			writeError(w, http.StatusConflict, eff.Conflict)
			return
		}
		gp := eff.GroupSessionPolicy
		if gp.EnforceViewOnly && !gp.AllowBackstageUnderViewOnly {
			writeError(w, http.StatusConflict,
				"this machine's group is mandated view-only; Under the Hood tools cannot be used on it")
			return
		}
	}

	// An OBSERVER session never receives a backstage grant (security audit 2026-10-18). Without this
	// a technician could open a view_only session — counted against the observer cap and recorded
	// as watch-only — then mint a grant naming it; the agent accepts any grant that matches the live
	// session and technician. The agent also refuses mutating backstage requests on an observer, so
	// this is the issuing side of the same rule, as handleMintElevation already applies it. A
	// session id with no session_record (attended sessions, legacy callers) is not an observer.
	if req.SessionID != "" && s.SessionRecords != nil {
		rec, rerr := s.SessionRecords.GetSession(r.Context(), p.TenantID, req.SessionID)
		switch {
		case rerr == nil && rec.Access == "view_only":
			writeError(w, http.StatusForbidden, "this session is an observer; Under the Hood tools are forbidden")
			return
		case rerr != nil && !errors.Is(rerr, ErrSessionRecordNotFound):
			writeError(w, http.StatusInternalServerError, "could not resolve session")
			return
		}
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = newUUID()
	}

	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	now := issuanceNow()
	signed, err := s.Grants.Mint(p.UserID, sessionID, req.MachineID, caps, now, now+backstageGrantTTL.Milliseconds())
	if err != nil {
		// A malformed technician/machine/session UUID lands here — the grant cannot be built.
		writeError(w, http.StatusBadRequest, "could not mint grant: "+err.Error())
		return
	}
	if err := s.recordMgmtAudit(r, "grant.mint", "machine", m.ID,
		map[string]any{"device_id": m.DeviceID, "session_id": sessionID, "caps": len(caps)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, signed)
}

// handleGrantPubkey returns the issuer's Ed25519 public key (hex) so it can be provisioned into
// agent config.json as `grant_issuer_pubkey`.
func (s *Server) handleGrantPubkey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"grant_issuer_pubkey": s.Grants.PublicKeyHex()})
}
