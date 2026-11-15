package controlplane

// The admission and brokering steps of POST /sessions, factored out of handleStartSession so session
// transfer (http_session_transfer.go) starts S2 through EXACTLY the same checks and mints its ticket and
// initial policy exactly as a fresh start does (docs/51 §7.1, §8.3). handleStartSession stays the one
// place the issuance guard lives (the reap and the limit-error mapping are shared helpers at the foot of this
// file, because a help-request accept starts its session through them too).

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// sessionAdmission is what resolveSessionAdmission decides: the record to insert, the seat limits to
// admit it under, and the policies it read on the way (the brokering step and the reaps reuse them).
type sessionAdmission struct {
	Rec                     *SessionRecord
	Limits                  SessionStartLimits
	GroupPolicy             GroupSessionPolicy
	TenantMaxSessionSeconds int
}

// outOfServiceMachineMsg is the refusal for a quarantined or retired machine ("" when it is in service).
func outOfServiceMachineMsg(m *Machine, verb string) string {
	if m.Status == MachineStatusQuarantined || m.Status == MachineStatusRetired || m.Status == MachineStatusRemoved {
		return "machine is " + m.Status + "; reactivate it to " + verb
	}
	return ""
}

// resolveSessionAdmission runs every check a session start makes against the machine as it is NOW, for
// (userID, grant): the capability on the machine's group, the observer extras, the attended-guest and
// out-of-service refusals, and the tenant and group policies (including the PASS4 absolute gates). It
// writes nothing. Used by handleStartSession and by session-transfer accept/finalize, which is why the
// grant is a parameter: a finalize runs with no request, re-deriving the ACCEPTOR's authority.
func (s *Server) resolveSessionAdmission(ctx context.Context, tenantID, userID string, grant *Grant, m *Machine, access string) (*sessionAdmission, *sessionRefusal) {
	if err := grant.RequireMachine(CapStartSession, m.GroupID); err != nil {
		return nil, &sessionRefusal{Denied: err}
	}
	if access == "view_only" {
		// Observe is an additional mode permission; all Connect checks below still apply.
		if err := grant.RequireMachine(CapObserveSession, m.GroupID); err != nil {
			return nil, &sessionRefusal{Denied: err}
		}
		// The control plane does not record multi-session capability; every installed agent since the
		// F2 multi-tech helper serves sessions through the mux, and 0.1.3 is the first agent that honours
		// the ticket's access. The version gate therefore implies both.
		if !observerAgentSupported(m.AgentVersion) {
			return nil, &sessionRefusal{Status: http.StatusConflict,
				Msg: "observing requires a multi-session-capable machine running agent 0.1.3 or later"}
		}
		if s.Grants == nil {
			return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "observing requires a configured ticket and policy issuer"}
		}
	}
	// An attended guest is NOT a fleet machine. Its consent gate lives in
	// POST /attended-sessions/{id}/connect (which refuses to mint a ticket until the guest agrees),
	// and this route has no way to consult it — so reaching a guest through here would route around
	// consent entirely. It would also FK a session_record to a row that
	// `ON DELETE CASCADE` destroys when the attended session ends, silently erasing that session's
	// own history. Ephemeral rows are already hidden from GET /machines; this closes the direct call.
	if m.Ephemeral {
		return nil, &sessionRefusal{Status: http.StatusConflict,
			Msg: "attended guest: connect via POST /attended-sessions/{id}/connect (consent gate)"}
	}
	// A quarantined or retired machine is administratively out of service — refuse a new session (the
	// operator's "stop connecting to this box" switch). Active and dev-synthesized machines pass.
	// Shared with the two mints since loop 88, so the three cannot drift again — see
	// refuseOutOfServiceMachine.
	if msg := outOfServiceMachineMsg(m, "start a session"); msg != "" {
		return nil, &sessionRefusal{Status: http.StatusConflict, Msg: msg}
	}
	if s.SessionRecords == nil {
		return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "session store not configured"}
	}
	// The capabilities the session CARRIES are the backstage tier the caller's memberships
	// resolve to for the machine's group — the same computation the mint path uses, so
	// session_record.granted_caps documents what a subsequently minted grant could contain.
	// A session without backstage rights simply carries none.
	var grantedCaps []string
	if caps, ok := BackstageCapsFor(grant, m.GroupID); ok {
		grantedCaps = make([]string, len(caps))
		for i, c := range caps {
			grantedCaps[i] = string(c)
		}
	}
	rec := &SessionRecord{
		TenantID:     tenantID,
		MachineID:    m.ID, // session_record.machine_id FKs the machine PRIMARY KEY, not the device id
		TechnicianID: userID,
		GrantedCaps:  grantedCaps,
		Access:       access,

		MachineGroupID:  m.GroupID,
		MachineDeviceID: m.DeviceID,
		MachineName:     m.Name,
	}
	// Enforce the concurrent-session limits (docs/01 §5 seat metering): the tenant-wide cap (loop 56) AND
	// the target machine group's own cap (loop 78), together, atomically inside the store (advisory-locked
	// in pg), so a burst of concurrent starts cannot each pass the check and overshoot either. 0 / no policy
	// / no store = unlimited on that axis. GroupID is the group the session is admitted against.
	limits := SessionStartLimits{GroupID: m.GroupID}
	if rec.Access == "view_only" {
		limits.MaxObserversPerMachine = 2
	}
	var tenantMaxSessionSeconds int
	if s.SessionPolicies != nil {
		pol, perr := s.SessionPolicies.Get(ctx, tenantID)
		if perr != nil {
			return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve session policy"}
		}
		limits.Tenant = pol.MaxConcurrentSessions
		tenantMaxSessionSeconds = pol.MaxSessionSeconds
	}
	// The machine group's policy drives BOTH the seat cap (below, enforced in the store) and the ACCESS
	// LEVEL this session is admitted at (used further down to mint the signed session policy).
	groupPolicy := GroupSessionPolicy{GroupID: m.GroupID}
	if s.GroupSessionPolicies != nil && m.GroupID != "" {
		// The EFFECTIVE policy: the strictest merge along the ancestor chain (docs/62 D4). An unsatisfiable
		// merge (require AND prohibit recording) DENIES here (R4) — it is the fail-closed backstop for what
		// the policy-edit and reparent pre-checks cannot see.
		eff, gerr := s.EffectivePolicy(ctx, tenantID, m.GroupID)
		if gerr != nil {
			return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve group session policy"}
		}
		if eff.Conflict != "" {
			return nil, &sessionRefusal{Status: http.StatusConflict, Msg: eff.Conflict}
		}
		gp := eff.GroupSessionPolicy
		groupPolicy = gp
		// Seat caps (R7): EVERY ancestor-or-self with a cap is enforced against ITS OWN subtree's live
		// count, inside the store's per-tenant admission lock. Group/GroupID stay the displayed effective
		// cap for callers that read them.
		limits.Group = gp.MaxConcurrentSessions
		limits.GroupCaps = eff.SeatCaps
		if len(eff.SeatCaps) > 0 && s.MachineGroups != nil {
			if tree, _, terr := s.MachineGroups.GroupTree(ctx, tenantID); terr == nil {
				limits.Tree = tree
			} else {
				return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve group session policy"}
			}
		}
		// PASS4 ABSOLUTE GATE: all four new group restrictions are refused for unattended
		// sessions until per-session agent capability negotiation ships.
		//
		// require_session_policy pre-dates migrations 0043–0046. A machine with that flag
		// set may still run an agent that pre-dates 7c81bde and would silently ignore these
		// restrictions. Refusing unconditionally — regardless of require_session_policy —
		// matches the attended-session gate (http_attended.go) and prevents silent
		// non-enforcement on any deployed agent. Configuration is retained; sessions into
		// groups using any of these restrictions receive 403 with an explicit explanation.
		if gp.RequireRecording {
			return nil, &sessionRefusal{Status: http.StatusForbidden, Msg: "require_recording is temporarily not supported for unattended sessions; " +
				"this restriction will be enabled once agent capability negotiation is available"}
		}
		if gp.ProhibitRecording || gp.MaxSessionDurationSeconds > 0 || gp.MaxIdleSeconds > 0 {
			return nil, &sessionRefusal{Status: http.StatusForbidden, Msg: "prohibit_recording, max_session_duration_seconds, and max_idle_seconds are temporarily " +
				"not supported for unattended sessions; these restrictions will be enforced once " +
				"agent capability negotiation is available"}
		}
	}
	return &sessionAdmission{Rec: rec, Limits: limits, GroupPolicy: groupPolicy, TenantMaxSessionSeconds: tenantMaxSessionSeconds}, nil
}

// brokerSessionStart is the rendezvous half of a session start: the signaling coordinates plus a
// short-TTL signed ticket, and the signed session policy when the group, the machine or the observer
// mode needs one. It returns the POST /sessions response body. The caller holds the issuance guard
// (holdIssuance) and ends rec on a refusal.
func (s *Server) brokerSessionStart(rec *SessionRecord, m *Machine, userID, tenantID string, groupPolicy GroupSessionPolicy) (map[string]any, *sessionRefusal) {
	// M2 (ADR-002): broker the rendezvous. When the issuer is wired, hand back the signaling
	// coordinates plus a short-TTL signed session ticket the signaling server verifies before
	// brokering connect_request → this device (server/signaling/ticket.go).
	resp := map[string]any{"session": rec}
	if s.Grants != nil {
		url := s.SignalingURL
		if url == "" {
			url = DefaultSignalingURL
		}
		now := issuanceNow() // under the issuance guard taken before the record was created
		ticket := s.Grants.MintSessionTicket(rec.ID, userID, tenantID, m.DeviceID,
			now, now+sessionTicketTTL.Milliseconds())
		if rec.Access == "view_only" {
			ticket = s.Grants.MintObserverSessionTicket(rec.ID, userID, tenantID, m.DeviceID,
				now, now+sessionTicketTTL.Milliseconds())
		}
		resp["signaling"] = map[string]any{
			"url":        url,
			"device_id":  m.DeviceID,
			"session_id": rec.ID,
			"ticket":     ticket,
		}
		// The SIGNED SESSION POLICY (docs/01 §3/§5, loops 79/80): what the ORGANISATION says this session
		// may do, as opposed to what the technician asks for. The viewer installs it over the Control
		// channel (Control::InstallSessionPolicy); the agent verifies it against the SAME pinned issuer key
		// it uses for backstage grants (they are separated by a domain tag in the signed bytes, not a second
		// key) and enforces it as a one-way ratchet the technician cannot lift.
		//
		// MINTED ONLY FOR A GROUP THAT ACTUALLY ENFORCES. An earlier revision minted one for every
		// session carrying the real level, on the theory that a uniform code path is safer. It is not,
		// and the interaction is worth spelling out because it nearly shipped:
		//
		//   the agent fails CLOSED on a policy it cannot verify (tampered, expired, or no pinned issuer
		//   key at all) → an installed agent WITHOUT `grant_issuer_pubkey`, which is the common
		//   configuration today, would receive a perfectly ordinary "control" policy, fail to verify it,
		//   and drop to VIEW-ONLY. Minting for everyone would have taken remote control away from every
		//   such agent in the fleet, on behalf of groups that had asked for nothing.
		//
		// Restricting the mint to enforcing groups makes the artifact MEAN something: a policy arriving
		// is itself the signal that this session is restricted, so failing closed on one that will not
		// verify is exactly right, and an agent that never receives one is no worse off than before the
		// feature existed. The remaining gap — a hostile viewer that WITHHOLDS the frame — is closed on
		// the agent side by `require_session_policy`, not by minting more.
		//
		// SCOPE OF THAT RULE — and the SECOND case, added by loop 86 (migration 0037). The argument
		// above says: do not mint for a group that asked for nothing, because an agent that cannot verify
		// would fail closed to view-only for no reason. That argument is about agents which are NOT
		// already floored. It stops applying the moment an agent floors ITSELF.
		//
		// `require_session_policy` is an OPERATOR CONFIG FLAG on an installed agent
		// (crates/agent-windows/src/config.rs): with it set, the agent opens EVERY session view-only and
		// stays there until a signed policy verifies. Its own doc said "Set BOTH for an enforcing
		// deployment" and never mentioned groups — so an agent shipped with the flag, in a group whose
		// mandate an admin later cleared or never set, was stranded VIEW-ONLY FOREVER: no input, no
		// reboot, no command bar, retrying never helps, and nothing on screen explains why. Withholding
		// the mint is what takes control away, exactly as on the attended path. The machine now REPORTS
		// the flag (at enrollment, and again on every register), so this path can keep the promise.
		//
		// The ATTENDED path (handleConnectAttended) is the same shape for a guest that redemption told
		// to open FLOORED — migration 0036, which this mirrors.
		//
		// machine_id is the DEVICE id, matching the H3 device binding the agent checks (it compares
		// against its own device uuid) and matching how a backstage grant is minted.
		// An observer always receives a policy, independently of the group's mandate and
		// the agent's provisional floor. The ticket establishes its mode before first input.
		if rec.Access != "view_only" && !groupPolicy.EnforceViewOnly && !m.RequireSessionPolicy && groupPolicy.AllowRecording() &&
			!groupPolicy.RequireRecording && groupPolicy.MaxSessionDurationSeconds == 0 && groupPolicy.MaxIdleSeconds == 0 {
			return resp, nil
		}
		// THE LEVEL CARRIES THE GROUP'S CURRENT MANDATE — `view_only` while one stands, `control` once it
		// does not. `control` is exactly what the agent's ratchet accepts to discharge a PROVISIONAL
		// floor, and ONLY a provisional one: a floor that arrived as a verified view_only policy is not
		// liftable by anything.
		//
		// WHAT THIS COSTS, AND WHAT PAYS FOR IT. Until loop 86 this was `const access =
		// SessionAccessViewOnly`, and its comment called that a LOAD-BEARING CONSTANT: it confined every
		// `control` policy the system minted to an EPHEMERAL attended device id, one that would never
		// exist again, which is what made a captured `control` policy unreplayable (the full argument is
		// at the attended mint site in http_attended.go). Minting `control` for a PERMANENT machine
		// spends that containment — a captured policy would otherwise be replayable at that machine, for
		// its whole TTL, against any later session whose only floor is the provisional one.
		//
		// It is replaced by SESSION BINDING, not dropped. The policy's session_id is in the signed
		// preimage and the agent now CHECKS it (`SessionPolicy::verify` in agent/src/session_policy.rs),
		// against the live session id it learns from the ticket the signaling server verified. A policy
		// captured in one session is therefore rejected in any other — and rejection is terminal for that
		// session, so the attempt costs the attacker the session rather than gaining them one. Do not
		// re-widen this level without checking that binding is still in place.
		access := SessionAccessControl
		if rec.Access == "view_only" || groupPolicy.EnforceViewOnly {
			access = SessionAccessViewOnly
		}
		// A mint can still fail: the canonical preimage needs REAL uuids, and DEV/self-hosted
		// deployments run with synthetic ids ("dev-1") and a permissive machine store. Refusing the start
		// is the only safe response in BOTH directions. Enforcing group: continuing would hand the
		// technician a session with no floor while the console still shows the group as restricted, which
		// is indistinguishable from a working mandate. Flagged machine: continuing would hand back a
		// session the agent has already floored and nothing will ever discharge — safe, but useless, and
		// silently so. (A permissive dev machine is fabricated with the flag FALSE, so it only reaches
		// here via an enforcing group, exactly as before.)
		// sessionPolicyLeaseTTL, not sessionPolicyTTL (docs/25 F03). This policy is the FIRST lease of
		// an unattended session, and a lease's whole purpose is that it runs out — so it cannot be
		// the fifteen-minute artifact this used to mint, or a hostile controller would hold that
		// fifteen minutes and the revocation window would be the longest-lived policy it ever
		// received rather than the shortest.
		//
		// The cost is transit: this is minted BEFORE ICE, DTLS and the data channel, and nothing can
		// renew it until the Control channel exists. Thirty seconds is a six-to-ten-fold margin on a
		// real WebRTC connect. A LEASED agent that receives it late no longer treats the expiry as
		// terminal — it says so and waits for the renewal that is already on its way (host.rs, the
		// `Expired` arm of InstallSessionPolicy). An agent too old to lease still treats it as
		// terminal, so on that one combination — an old agent, in a view-only-mandated group, on a
		// connect slower than thirty seconds — the session would open view-only and stay there.
		var startMaxDuration uint32
		if groupPolicy.MaxSessionDurationSeconds > 0 {
			startMaxDuration = uint32(groupPolicy.MaxSessionDurationSeconds)
		}
		var startMaxIdle uint32
		if groupPolicy.MaxIdleSeconds > 0 {
			startMaxIdle = uint32(groupPolicy.MaxIdleSeconds)
		}
		signedPolicy, perr := s.Grants.MintSessionPolicy(userID, rec.ID, m.DeviceID, access,
			groupPolicy.AllowRecording(), groupPolicy.RequireRecording, startMaxDuration, startMaxIdle, now, now+sessionPolicyLeaseTTL.Milliseconds())
		if perr == nil {
			policyJSON, jerr := signedPolicy.JSON()
			if jerr != nil {
				return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not encode the session access policy"}
			}
			resp["session_policy"] = map[string]any{
				"access":    string(access),
				"view_only": access == SessionAccessViewOnly,
				"signed":    policyJSON,
			}
		} else {
			// Refusing AFTER the record was inserted would strand it OPEN forever: nothing
			// ever ends a session the caller never learned about, and an open record holds a seat
			// against BOTH the tenant and the per-group concurrency caps. A handful of these would
			// silently exhaust the very caps this file enforces. So end it before returning.
			//
			// The CALLER ends the record on any refusal (handleStartSession's deferred compensation, the
			// ticket endpoint's own), and the reap (max_session_seconds) is the backstop.
			log.Printf("session %s: machine %s needs a %s access policy (group_enforces=%t machine_requires=%t) "+
				"but it could not be minted: %v",
				rec.ID, m.ID, access, groupPolicy.EnforceViewOnly, m.RequireSessionPolicy, perr)
			return nil, &sessionRefusal{Status: http.StatusInternalServerError,
				Msg: "this session requires a signed access policy, but it could not be minted"}
		}
	}
	return resp, nil
}

// reapBeforeSessionStart is the reap handleStartSession runs BEFORE its seat count (and that a help-request
// accept runs before its own, docs/64 H-C1): expired leaked rows must not hold seats. Best-effort - a reap
// failure never fails a legitimate start. Extracted unchanged so both starts reap identically.
func (s *Server) reapBeforeSessionStart(r *http.Request, p *Principal, adm *sessionAdmission) {
	limits, groupPolicy, tenantMaxSessionSeconds := adm.Limits, adm.GroupPolicy, adm.TenantMaxSessionSeconds
	// Reap open sessions BEFORE the count so accumulated leaked rows don't hold seats indefinitely.
	// Two independent axes, each scoped to its own domain:
	//   Tenant axis: max_session_seconds from the tenant's session policy, applied TENANT-WIDE.
	//     Honoured for all tenants with a configured limit, even uncapped ones — allows table-maintenance
	//     without a seat cap. Tenant-wide because the tenant admin set an absolute age limit.
	//   Group axis: max_session_duration_seconds from the group's session policy, applied to THIS GROUP
	//     ONLY (ReapExpiredGroupSessions). This is critical for cross-group correctness: a group with a
	//     1-hour policy must not reap sessions from other groups that may have a 4-hour (or no) limit.
	//     API validation (NormalizeGroupSessionPolicy) requires this to be > 0 whenever
	//     max_concurrent_sessions > 0, so leaked rows older than the group's stated duration are safely
	//     reaped. Legacy groups (cap>0, duration=0, only reachable via direct store write): warning logged,
	//     no reap.
	// Best-effort: a reap failure must not fail a legitimate start. See docs/26 §Field finding.
	if tenantReapAge := time.Duration(tenantMaxSessionSeconds) * time.Second; tenantReapAge > 0 {
		if reaped, rerr := s.SessionRecords.ReapExpiredSessions(r.Context(), p.TenantID, tenantReapAge); rerr != nil {
			log.Printf("session reap failed for tenant %s: %v", p.TenantID, rerr)
		} else if reaped > 0 {
			if err := s.recordMgmtAudit(r, "session.reaped", "tenant", p.TenantID,
				map[string]any{
					"count":                      reaped,
					"max_session_seconds":        tenantMaxSessionSeconds,
					"effective_reap_age_seconds": int(tenantReapAge.Seconds()),
					"scope":                      "tenant",
				}); err != nil {
				log.Printf("reaped %d expired session(s) for tenant %s but the audit failed: %v", reaped, p.TenantID, err)
			}
		}
	}
	if limits.Group > 0 {
		groupDuration := time.Duration(groupPolicy.MaxSessionDurationSeconds) * time.Second
		if groupDuration <= 0 {
			log.Printf("group %s has max_concurrent_sessions=%d but no max_session_duration_seconds; "+
				"leaked seats cannot be auto-reclaimed — set max_session_duration_seconds to enable automatic cleanup",
				groupPolicy.GroupID, groupPolicy.MaxConcurrentSessions)
		} else {
			if reaped, rerr := s.SessionRecords.ReapExpiredGroupSessions(r.Context(), p.TenantID, groupPolicy.GroupID, groupDuration); rerr != nil {
				log.Printf("group session reap failed for tenant %s group %s: %v", p.TenantID, groupPolicy.GroupID, rerr)
			} else if reaped > 0 {
				if err := s.recordMgmtAudit(r, "session.reaped", "tenant", p.TenantID,
					map[string]any{
						"count":                      reaped,
						"group_id":                   groupPolicy.GroupID,
						"effective_reap_age_seconds": int(groupDuration.Seconds()),
						"scope":                      "group",
					}); err != nil {
					log.Printf("reaped %d expired session(s) for group %s but the audit failed: %v", reaped, groupPolicy.GroupID, err)
				}
			}
		}
	}
}

// writeStartAdmissionError answers the errors StartSessionWithinLimit (and a help accept, which admits through
// the same protocol) can return. It always writes a response.
func writeStartAdmissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrConcurrentSessionLimit):
		writeError(w, http.StatusConflict, "concurrent session limit reached for this tenant")
	case errors.Is(err, ErrGroupConcurrentSessionLimit):
		writeError(w, http.StatusConflict, "concurrent session limit reached for this machine group")
	case errors.Is(err, ErrObserverSessionLimit):
		writeError(w, http.StatusConflict, "observer limit reached: this machine already has two open observers")
	case errors.Is(err, ErrGroupTreeChanged): // the tree lock was held by a long hierarchy mutation
		writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
	default:
		writeError(w, http.StatusInternalServerError, "could not start session")
	}
}
