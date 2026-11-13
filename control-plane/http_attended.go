package controlplane

// HTTP handlers for attended (on-demand) support sessions — docs/12-attended-sessions-contract.md.
//
// The load-bearing rule is the CONSENT GATE: handleConnectAttended mints the technician's session
// ticket only once the guest has reported consent (state ∈ {consented,active}). Signaling already
// refuses to broker without a valid ticket, so no consent ⇒ no ticket ⇒ no connection — the gate is
// enforced here, on the authorization path, not merely drawn in the UI.
//
// Attended is "starting a session on demand", so it reuses the existing session capabilities rather
// than minting a new one (which would need a role-seed migration): create/connect require
// CapStartSession in the group, view requires CapViewSessions, end requires CapEndSession, and
// promote requires CapEnrollMachine. Group scoping mirrors handleStartSession.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxAttendedBodyBytes caps the UNAUTHENTICATED guest bodies (redeem/consent), matching the redeem
// endpoint's cap so a single request cannot make the process buffer arbitrary memory pre-auth.
const maxAttendedBodyBytes = 1 << 16

// maxAttendRedeemBodyBytes caps the redeem POST (a code, a 64-hex key and a name): docs/66 2e.2.
const maxAttendRedeemBodyBytes = 4 << 10

// attendedPromoteTokenTTL bounds the enrollment token minted by /promote. Short: the guest picks it
// up on its next status poll and redeems immediately.
const attendedPromoteTokenTTL = 1 * time.Hour

// attendBearer extracts the attend token from the Authorization header, or "" if absent. (Distinct
// from auth.go's bearerToken, which also reads the session cookie — the guest is not a session.)
func attendBearer(r *http.Request) string {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(tok)
}

// validAttendPubkey reports whether s is a hex-encoded 32-byte Ed25519 public key.
func validAttendPubkey(s string) bool {
	pub, err := hex.DecodeString(s)
	return err == nil && len(pub) == ed25519.PublicKeySize
}

// validAttendTokenShape checks the length and alphabet of a server-minted attend token:
// 43 ASCII base64url characters, no padding. Minted by newEnrollmentSecret: 32 random bytes
// encoded with base64.RawURLEncoding — alphabet A-Z a-z 0-9 - _. Rejected before any store call
// so visibly malformed tokens never spend a database round-trip (partial F18 mitigation).
// This does not authenticate the token or enforce canonical trailing base64 pad bits.
func validAttendTokenShape(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// -------------------------------------------------------------------------------------
// Technician-facing (behind auth → tenant RLS)
// -------------------------------------------------------------------------------------

type createAttendedRequest struct {
	GroupID string `json:"group_id"`
	Reason  string `json:"reason"`
}

func (s *Server) handleCreateAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req createAttendedRequest
	// docs/25 F05. The decode precedes the capability check and must: the check is
	// RequireMachine(CapStartSession, req.GroupID) and the group is named in the body. The cap is
	// therefore what bounds an unauthorized caller here — 64 KiB, rather than whatever they care to
	// send while the request holds a pooled tenant connection.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed create-attended request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// The attended session plants an ephemeral machine into req.GroupID and everything downstream
	// (the ticket, promote) scopes to it, so the caller must be able to start sessions in THAT group.
	if err := p.Grant.RequireMachine(CapStartSession, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if len(req.Reason) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "reason is too long")
		return
	}
	sess := &AttendedSession{GroupID: req.GroupID, TechnicianID: p.UserID, Reason: req.Reason}
	code, err := s.Attended.Create(r.Context(), p.TenantID, sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create attended session")
		return
	}
	if err := s.recordMgmtAudit(r, "attended.create", "attended_session", sess.ID,
		map[string]any{"group_id": sess.GroupID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// The code (grouped for display) and join link are shown ONCE, here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{
		"session":   sess,
		"code":      GroupAttendCode(code),
		"join_code": code,
		"join_url":  "/join#" + code,
	})
}

// handleGetAttended reads one attended session. Resolve FIRST, then gate on the group the store
// says the session belongs to — the same order and the same reason as handleGetMachine, and as this
// file's other four handlers.
//
// It used the tenant-wide Require(CapViewSessions), which is the one place on this surface where
// the tenant was treated as the authorization boundary. It is not: a group-scoped technician who
// may not connect to, promote or end a session could still read it whole — group, technician,
// ephemeral device, state, and the free-text `reason` written about somebody's machine.
func (s *Server) handleGetAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	sess, err := s.Attended.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrAttendedNotFound) {
			writeError(w, http.StatusNotFound, "unknown attended session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve attended session")
		return
	}
	// The group comes from the STORE, never from the caller. RequireMachine checks the capability
	// and the scope together, so it subsumes the tenant-wide check this replaces.
	if err := p.Grant.RequireMachine(CapViewSessions, sess.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sess})
}

// handleConnectAttended is the CONSENT GATE. It resolves the session, checks the caller may start a
// session in its group, then mints an RMTTICKETv1 for the ephemeral device — but only if the guest
// has consented (MarkActive enforces consented/active, else ErrAttendedNotConsented → 409).
func (s *Server) handleConnectAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	sess, err := s.Attended.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrAttendedNotFound) {
			writeError(w, http.StatusNotFound, "unknown attended session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve attended session")
		return
	}
	if err := p.Grant.RequireMachine(CapStartSession, sess.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Grants == nil {
		writeError(w, http.StatusInternalServerError, "grant issuer not configured")
		return
	}
	// The gate: only transitions consented→active; a session still awaiting consent is refused.
	active, err := s.Attended.MarkActive(r.Context(), p.TenantID, sess.ID)
	if err != nil {
		switch {
		case errors.Is(err, ErrAttendedNotConsented):
			writeError(w, http.StatusConflict, "attended session is awaiting consent")
		case errors.Is(err, ErrAttendedNotFound):
			writeError(w, http.StatusNotFound, "unknown attended session")
		default:
			writeError(w, http.StatusInternalServerError, "could not activate attended session")
		}
		return
	}
	if active.DeviceID == "" {
		writeError(w, http.StatusConflict, "attended session has no device yet")
		return
	}
	url := s.SignalingURL
	if url == "" {
		url = DefaultSignalingURL
	}
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	now := issuanceNow()
	ticket := s.Grants.MintSessionTicket(active.ID, p.UserID, p.TenantID, active.DeviceID,
		now, now+sessionTicketTTL.Milliseconds())
	resp := map[string]any{
		"session": active,
		"signaling": map[string]any{
			"url":        url,
			"device_id":  active.DeviceID,
			"session_id": active.ID,
			"ticket":     ticket,
		},
	}

	// The SIGNED SESSION ACCESS POLICY (docs/01 §5, loops 79-81), exactly as POST /sessions mints it.
	//
	// This path needs it for a reason that is easy to miss: an attended session's machine is EPHEMERAL,
	// which makes it sound group-less and therefore out of scope for a per-group mandate — but it is not.
	// Redemption enrolls that ephemeral machine INTO the invite's group
	// (AttendedStore.Redeem -> enrollEphemeral(tenant, device, t.GroupID, ...)), and this handler already
	// authorizes against `sess.GroupID`. So a group flagged enforce_view_only is fully reachable through a
	// guest-initiated session, and without this the mandate was bypassed by taking the attended route —
	// the console would show the group as view-only while an attended technician had full control.
	//
	// The unattended path mints ONLY for a group that actually enforces, so a policy's PRESENCE is the
	// signal. On THIS path presence is no longer sufficient, and the ACCESS FIELD is load-bearing —
	// loop 83, migration 0036. A guest that was told at redeem to open FLOORED is enforcing a floor
	// right now, and the only thing that can lift it is a policy it can verify. So:
	//
	//   * group enforces          → mint view_only (as before);
	//   * guest was told to floor → mint the group's CURRENT level, whatever it is.
	//
	// When those disagree — the mandate was cleared between redeem and connect — the second rule wins
	// and the guest gets `access=control`, which the agent's ratchet accepts SPECIFICALLY to discharge a
	// PROVISIONAL floor (a floor that arrived as a verified view_only policy is not liftable by one).
	// Without this the guest stays view-only for the session's whole life with nothing explaining why.
	// The outcome, for the audit record below: "" when no policy was minted.
	policyAccess := ""
	groupEnforces := false
	if s.GroupSessionPolicies != nil && active.GroupID != "" {
		eff, gerr := s.EffectivePolicy(r.Context(), p.TenantID, active.GroupID)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve group session policy")
			return
		}
		if eff.Conflict != "" { // docs/62 R4
			writeError(w, http.StatusConflict, eff.Conflict)
			return
		}
		groupPolicy := eff.GroupSessionPolicy
		// Attended agents are ephemeral downloads with no recording_dir configured — they can
		// never satisfy require_recording regardless of agent version. Reject before exposing
		// the desktop so the policy is actually enforced.
		if groupPolicy.RequireRecording {
			writeError(w, http.StatusForbidden,
				"this machine group requires session recording, which is not supported for attended (guest) sessions")
			return
		}
		// prohibit_recording is temporarily not supported for any session type pending agent
		// capability negotiation. Reject rather than deliver an unenforceable policy.
		if groupPolicy.ProhibitRecording {
			writeError(w, http.StatusForbidden,
				"this machine group prohibits session recording; this restriction is temporarily "+
					"not supported and will be available once agent capability negotiation is complete")
			return
		}
		// max_session_duration_seconds and max_idle_seconds cannot be enforced for attended
		// sessions: attended agents use SessionLeaseMode::NotApplicable and have no lease renewal
		// path to carry the limit. Old attended binaries ignore these fields entirely.
		if groupPolicy.MaxSessionDurationSeconds > 0 {
			writeError(w, http.StatusForbidden,
				"this machine group has a session duration limit that cannot be enforced for attended (guest) sessions")
			return
		}
		if groupPolicy.MaxIdleSeconds > 0 {
			writeError(w, http.StatusForbidden,
				"this machine group has an idle timeout that cannot be enforced for attended (guest) sessions")
			return
		}
		if groupPolicy.EnforceViewOnly || active.RequireSessionPolicy || !groupPolicy.AllowRecording() || groupPolicy.RequireRecording || groupPolicy.MaxSessionDurationSeconds > 0 || groupPolicy.MaxIdleSeconds > 0 {
			access := SessionAccessControl
			if groupPolicy.EnforceViewOnly {
				access = SessionAccessViewOnly
			}
			// WHY MINTING `control` IS REPLAY-SAFE, and the invariant it rests on. A policy is a signed
			// bearer artifact with a TTL, and the agent cannot judge freshness — so the design's safety
			// comes from a policy only ever being able to RESTRICT. `control` is the one exception, and
			// it is contained by the DEVICE BINDING: verification requires machine_id to equal the
			// agent's own device id, and the id below is the session's EPHEMERAL machine, minted fresh
			// by this one redemption and reaped when the session ends. So a captured `control` policy
			// names a device that will never exist again — it cannot be replayed into a later session,
			// and it certainly cannot be replayed at a PERMANENT machine. (Verified against promote too:
			// promotion mints a FRESH device id at enrollment rather than reusing the ephemeral one.)
			//
			// That argument leans on one more fact, named here because it lives in another crate and a
			// change there would silently invalidate this comment: **an attended guest serves exactly
			// ONE session per process.** `run_attend` calls `serve_session_with_ice` once and then
			// exits, so there is no second session on that ephemeral device to replay into. If the
			// attended path ever gains a reconnect loop, revisit this.
			//
			// UPDATE (loop 86): that containment WAS spent, deliberately, and paid for. handleStartSession
			// used to hard-code `const access = SessionAccessViewOnly` precisely to preserve it; it now
			// mints `control` for a PERMANENT machine that reported `require_session_policy` (migration
			// 0037), because withholding the mint stranded exactly that agent view-only forever. So the
			// ephemeral-device argument above is no longer the ONLY thing standing between a captured
			// `control` policy and a replay — SESSION BINDING is: the policy's session_id is checked in
			// `SessionPolicy::verify` against the live session id the agent learns from the verified
			// ticket, so a policy captured in one session is rejected, terminally, in any other. The
			// ephemeral device id remains a second, independent containment for THIS path. If session
			// binding is ever removed, this comment's original warning comes straight back.
			var attendedMaxDuration uint32
			if groupPolicy.MaxSessionDurationSeconds > 0 {
				attendedMaxDuration = uint32(groupPolicy.MaxSessionDurationSeconds)
			}
			var attendedMaxIdle uint32
			if groupPolicy.MaxIdleSeconds > 0 {
				attendedMaxIdle = uint32(groupPolicy.MaxIdleSeconds)
			}
			signedPolicy, perr := s.Grants.MintSessionPolicy(p.UserID, active.ID, active.DeviceID,
				access, groupPolicy.AllowRecording(), groupPolicy.RequireRecording, attendedMaxDuration, attendedMaxIdle, now, now+sessionPolicyTTL.Milliseconds())
			if perr != nil {
				// Fail CLOSED: handing back a connection with no floor for a group that requires one is
				// the failure this whole feature exists to prevent. The session stays `active` (the
				// transition happened above) — the operator can retry or end it, and an attended session
				// that is active but never connected is inert, unlike an orphaned session_record it holds
				// no concurrency seat. It fails closed in the DISCHARGE direction too: a guest that was
				// told to floor and gets no policy stays view-only, which is safe but useless, so it is
				// still an error and not a silently degraded session.
				log.Printf("attended %s: group %s needs a %s access policy (group_enforces=%t guest_floored=%t) "+
					"but it could not be minted: %v",
					active.ID, active.GroupID, access, groupPolicy.EnforceViewOnly, active.RequireSessionPolicy, perr)
				writeError(w, http.StatusInternalServerError,
					"this session requires a signed access policy, but it could not be minted")
				return
			}
			policyJSON, jerr := signedPolicy.JSON()
			if jerr != nil {
				writeError(w, http.StatusInternalServerError, "could not encode the session access policy")
				return
			}
			// `access` and not a literal: this used to be the only reachable value, and after 0036 it is
			// not. A hardcoded "view_only" here would ship a body that CONTRADICTS the signed blob beside
			// it — the viewer would show the session as floored while the agent, reading the signature,
			// released control.
			resp["session_policy"] = map[string]any{
				"access": string(access),
				"signed": policyJSON,
			}
			policyAccess, groupEnforces = string(access), groupPolicy.EnforceViewOnly
		}
	}
	// AUDIT LAST, and audit the OUTCOME. Two things were wrong with recording this before the mint.
	//
	// It was written immediately after MarkActive, so a 500 from the group-policy read or the mint left
	// `attended.connect` on the hash chain for a connect that returned the technician nothing — no
	// ticket, no policy, no session. The trail asserted connects that did not happen, and they were
	// indistinguishable from real ones.
	//
	// And its metadata was `{device_id}` only. That was sufficient while a policy's PRESENCE implied
	// view_only, because the level was then inferable. Loop 83 gave this handler a third outcome
	// (`access=control`, minted to discharge a floor the guest is already enforcing) and the first
	// `control` policy this system has ever issued would otherwise have left NO trace: an auditor asking
	// "did this session run with full control of a machine in a view-only group?" would have to
	// interleave `machine_group.session_policy.set` events by timestamp and guess — and could not answer
	// at all if the mandate was cleared outside the audited path. So the level goes on the record, with
	// the two inputs that decided it.
	audit := map[string]any{"device_id": active.DeviceID}
	// THE HANDOFF, last: only a connect that has produced its ticket and policy takes the session
	// over, so a failed peer connect never strips the live technician's ownership. The technician
	// replaced comes from the locked row, not the snapshot read above (a concurrent connect may have
	// moved it), and goes on the record.
	prev, rerr := s.Attended.ReassignTechnician(r.Context(), p.TenantID, active.ID, p.UserID)
	if rerr != nil {
		writeError(w, http.StatusInternalServerError, "could not assign the attended session")
		return
	}
	if !sameUserID(prev, p.UserID) {
		audit["handoff_from_technician_id"] = prev
	}
	if policyAccess != "" {
		audit["session_policy_access"] = policyAccess
		audit["group_enforces_view_only"] = groupEnforces
		audit["guest_told_to_floor"] = active.RequireSessionPolicy
	}
	if err := s.recordMgmtAudit(r, "attended.connect", "attended_session", active.ID, audit); err != nil {
		// The handoff is NOT rolled back. Every rollback design reviewed (unconditional, then
		// compare-and-set on the user) could undo a later successful connect that overlapped this
		// one. The cost of leaving it: an audit-store failure at exactly this point leaves the
		// session with the technician who asked for it, without a ticket; they retry.
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePromoteAttended mints an enrollment token for the session's group and stashes it for the
// guest to pick up on its next status poll — the guest then runs the EXISTING enroll + service
// install to become a permanent unattended agent. Requires CapEnrollMachine in the group.
func (s *Server) handlePromoteAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.EnrollmentTokens == nil {
		writeError(w, http.StatusInternalServerError, "enrollment token store not configured")
		return
	}
	sess, err := s.Attended.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrAttendedNotFound) {
			writeError(w, http.StatusNotFound, "unknown attended session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve attended session")
		return
	}
	if err := p.Grant.RequireMachine(CapEnrollMachine, sess.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if !attendedCanPromote(sess.State) {
		writeError(w, http.StatusConflict, ErrAttendedNotPromotable.Error())
		return
	}
	ttl := attendedPromoteTokenTTL
	if s.ManagedInstaller != nil {
		ttl = managedInstallTTL
	}
	tok := &EnrollmentToken{
		GroupID:   sess.GroupID,
		CreatedBy: p.UserID,
		ExpiresAt: time.Now().Add(ttl),
		MaxUses:   defaultEnrollmentMaxUses,
	}
	plaintext, err := s.EnrollmentTokens.MintToken(r.Context(), p.TenantID, tok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint enrollment token")
		return
	}
	if err := s.Attended.SetPromoteToken(r.Context(), p.TenantID, sess.ID, plaintext); err != nil {
		// End may win after Get but before the atomic stash. Do not leave this newly
		// minted token live when the promotion was rejected or storage failed.
		ctx, cancel := compensationContext(r)
		rerr := s.EnrollmentTokens.RevokeToken(ctx, p.TenantID, tok.ID)
		cancel()
		if rerr != nil {
			log.Printf("enrollment token %q could not be stashed for promotion or revoked: %q", tok.ID, rerr)
		}
		if errors.Is(err, ErrAttendedNotPromotable) {
			writeError(w, http.StatusConflict, ErrAttendedNotPromotable.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not stash promote token")
		return
	}
	if err := s.recordMgmtAudit(r, "attended.promote", "attended_session", sess.ID,
		map[string]any{"group_id": sess.GroupID, "enrollment_token_id": tok.ID}); err != nil {
		// An unauditable promotion must be loud AND undone. By this point the token exists and has
		// already been stashed where the GUEST will collect it on its next /status poll, so a bare
		// 500 tells the technician the promotion failed while a live enrollment token travels to the
		// guest anyway — it enrols a permanent unattended agent into the group with no
		// `attended.promote` on the trail. The audit failure is not hypothetical: the per-tenant
		// chain takes an advisory lock with a bounded wait, so a busy tenant can genuinely time out.
		//
		// This is the same compensation HandleIssuePasswordReset performs for exactly this shape
		// (mint → cannot audit → revoke before failing). Both legs are attempted and logged
		// independently: clearing the stash is what stops the guest, revoking is what makes the
		// token inert if it was already read.
		ctx, cancel := compensationContext(r)
		cerr := s.Attended.SetPromoteToken(ctx, p.TenantID, sess.ID, "")
		cancel()
		if cerr != nil {
			log.Printf("attended %s: promote could not be audited AND the promote token could not be un-stashed: %v", sess.ID, cerr)
		}
		ctx, cancel = compensationContext(r)
		rerr := s.EnrollmentTokens.RevokeToken(ctx, p.TenantID, tok.ID)
		cancel()
		if rerr != nil {
			log.Printf("enrollment token %s was minted for attended promote, could not be audited, AND could not be revoked: %v", tok.ID, rerr)
		}
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"promoted": true})
}

func (s *Server) handleEndAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	sess, err := s.Attended.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrAttendedNotFound) {
			writeError(w, http.StatusNotFound, "unknown attended session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve attended session")
		return
	}
	if err := p.Grant.RequireMachine(CapEndSession, sess.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	ended, err := s.Attended.End(r.Context(), p.TenantID, sess.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not end attended session")
		return
	}
	if err := s.recordMgmtAudit(r, "attended.end", "attended_session", ended.ID, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": ended})
}

// -------------------------------------------------------------------------------------
// Guest-facing (PUBLIC / attend-token; on the root mux, outside the auth → tenant chain)
// -------------------------------------------------------------------------------------

type redeemAttendedRequest struct {
	Code   string `json:"code"`
	Pubkey string `json:"pubkey"`
	Name   string `json:"name"`
}

// handleRedeemAttended is UNAUTHENTICATED: the attend code is the authorization. It mints the
// ephemeral machine (device_id server-side), pins the guest pubkey, and returns the identity +
// signaling coordinates + the attend token for the guest's later callbacks. Metered per source like
// /enroll/redeem; every invalid/expired/spent code is the same generic 403.
func (s *Server) handleRedeemAttended(w http.ResponseWriter, r *http.Request) {
	// ADMISSION FIRST (docs/66 2b.4): before the body is read and before any class-dependent work. Beyond the
	// per-process caps the answer is one uniform 429 for every host and code class: no failure is recorded, no
	// audit row is written. Every response on this route has a bounded write deadline, rejections included.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(redeemWriteDeadline))
	release, admitted := s.redeemPool().Acquire(clientIP(r))
	if !admitted {
		writeThrottled(w, time.Second)
		return
	}
	// The permit is held until the LOOKUP GOROUTINE exits, not until this handler returns (docs/66 2e.1, 2f): a
	// stalled lookup keeps its slot, so the caps bound outstanding cleanup work too.
	handedOff := false
	defer func() {
		if !handedOff {
			release()
		}
	}()
	admittedAt := time.Now()

	var req redeemAttendedRequest
	if err := decodeJSONBodyDetailed(w, r, maxAttendRedeemBodyBytes, &req, "malformed redeem request body"); err != nil {
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	if len(req.Name) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if !validAttendPubkey(req.Pubkey) {
		writeError(w, http.StatusBadRequest, "pubkey must be a hex-encoded 32-byte Ed25519 public key")
		return
	}
	th := s.throttle()
	keys := []string{ipKey("attend-redeem", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	// docs/65 D-C9: a key that was pinned on a REMOVED machine is a tombstone on this door too.
	// It depends on the pubkey only, never on the code, so it reveals nothing about codes. It is bounded like the
	// lookup below (the work deadline, on the lookup pool) so a slow database cannot hold an anonymous request
	// here unbounded (docs/66 release gate R1).
	if s.Machines != nil {
		tombCtx, cancelTomb := context.WithTimeout(r.Context(), s.RedeemTuning.workDeadline())
		tombstoned, terr := s.Machines.KeyTombstoned(tombCtx, strings.ToLower(req.Pubkey))
		cancelTomb()
		if terr != nil {
			writeError(w, http.StatusInternalServerError, "could not check the agent identity")
			return
		} else if tombstoned {
			writeError(w, http.StatusForbidden, "this agent identity was removed")
			return
		}
	}
	// The class-dependent work runs under its own deadline (250 ms): the host-scope read, the code lookup and
	// the bounded 50 ms lock wait all happen inside this one store call (docs/66 2a.1, 2b.5). The scope is
	// decided from the Host header and CONFIGURATION ONLY; the store resolves the host's current assignment in
	// the same statement as the redemption.
	// The lookup runs on its OWN goroutine under its own context (admission + work deadline); the handler waits
	// for it with a timer and, on expiry, answers the generic rejection WITHOUT waiting for the lookup to exit
	// (2e.1). The store bounds the lookup itself (socket deadline, destroyed connection: 2f).
	workDeadline := s.RedeemTuning.workDeadline()
	lookupCtx, cancelLookup := context.WithTimeout(context.WithoutCancel(r.Context()), workDeadline)
	scope := s.HostPolicy.ScopeFor(r.Host)
	type lookupResult struct {
		res *AttendedRedeem
		err error
		cut bool // the lookup context had expired when the store returned (read BEFORE the deferred cancel)
	}
	out := make(chan lookupResult, 1)
	handedOff = true
	go func() {
		defer release()
		defer cancelLookup()
		res, err := s.Attended.RedeemScoped(lookupCtx, req.Code, req.Pubkey, req.Name, scope)
		out <- lookupResult{res, err, lookupCtx.Err() != nil}
	}()
	workTimer := time.NewTimer(workDeadline)
	defer workTimer.Stop()
	var res *AttendedRedeem
	var err error
	workCut := false
	select {
	case o := <-out:
		res, err = o.res, o.err
		workCut = err != nil && o.cut
	case <-workTimer.C:
		workCut, err = true, context.DeadlineExceeded
	case <-r.Context().Done():
		workCut, err = true, context.DeadlineExceeded
	}
	if err != nil {
		// Every rejected class is ONE answer: missing, expired, spent, suspended tenant, foreign tenant on a
		// scoped host, host not active, lock timeout, and a deadline-cut lookup (transient, retryable). Same
		// status, bytes and headers, exactly one Fail on the same key, no audit row. The floor sleeps with no
		// database connection held (the store call has returned).
		if errors.Is(err, ErrAttendedInvalid) || workCut {
			th.Fail(keys...)
			s.redeemRejectFloor(r.Context(), admittedAt)
			writeError(w, http.StatusForbidden, "invalid attended code")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem attended code")
		return
	}
	th.Reset(keys...)
	// The redemption plants an ephemeral machine into the tenant, so it belongs on the tamper-evident
	// trail for exactly the reason POST /enroll/redeem's machine.enroll does — the same act should
	// not be audited or not depending on which door it came through.
	//
	// Recorded directly rather than via recordMgmtAudit, which reads the actor and tenant from the
	// request principal: this route is public and there is no principal. The actor stays EMPTY —
	// attributing the guest's action to the technician who opened the session would put a claim in
	// the trail that is not true. A recording failure still fails the request, as it does there.
	if s.MgmtAudit != nil {
		meta, err := json.Marshal(map[string]any{
			"device_id": res.DeviceID, "group_id": res.GroupID, "ip": clientIP(r),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
		if err := s.MgmtAudit.RecordEvent(r.Context(), res.TenantID, &MgmtAuditEvent{
			Action: "attended.redeem", TargetKind: "attended_session", TargetID: res.SessionID,
			Metadata: meta,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	url := s.SignalingURL
	if url == "" {
		url = DefaultSignalingURL
	}
	body := map[string]any{
		"device_id":     res.DeviceID,
		"tenant_id":     res.TenantID,
		"signaling_url": url,
		"attend_token":  res.AttendToken,
	}
	// H1 trust anchor for the guest. An attended guest has no config file to provision, so this
	// redeem response is the only channel that can tell it which issuer to trust — without it the
	// guest cannot verify a signed grant at all, and used to compensate by self-issuing one carrying
	// every capability (ShellAsSystem included). Publishing the PUBLIC half here is safe: it is the
	// same value GET /grant/pubkey serves to the console, it authorizes nothing on its own, and it
	// can only make the guest STRICTER.
	//
	// Omitted when no issuer is configured; the guest reads that as "deny backstage".
	if s.Grants != nil {
		body["grant_issuer_pubkey"] = s.Grants.PublicKeyHex()
	}
	// Loop 82: tell the guest to open the session FLOORED (view-only until a policy verifies) when the
	// invite's group enforces view-only.
	//
	// Why it has to come from HERE. `require_session_policy` is the agent-side setting that closes the
	// WITHHELD-FRAME hole: the signed policy reaches the agent because the VIEWER forwards it, and the
	// viewer is exactly the party the policy binds, so a technician running a patched console can simply
	// never send Control::InstallSessionPolicy. On the unattended path an operator sets that flag in
	// config.json. An attended guest has NO config file and no argv flag, so the flag was unreachable and
	// the mandate bound a COOPERATIVE viewer only. Redemption is the one moment the control plane speaks
	// to the guest directly, and it already knows the invite's group — so it is the only channel.
	//
	// COUPLED TO THE ISSUER KEY, deliberately. A guest that pinned no issuer cannot verify ANY policy, so
	// telling it to require one would strand the session in view-only with no way out. That is the same
	// interaction that nearly shipped fleet-wide in loop 80 (see the mint comment in http.go): the fix
	// there and here is to keep the restriction and the means of lifting it inseparable. Both fields or
	// neither.
	//
	// A lookup FAILURE fails the redeem, matching handleConnectAttended: "we cannot tell whether this
	// group enforces" must not resolve to "open it unfloored", which is precisely the bypass.
	if _, pinned := body["grant_issuer_pubkey"]; pinned && s.GroupSessionPolicies != nil && res.GroupID != "" {
		eff, gerr := s.EffectivePolicy(r.Context(), res.TenantID, res.GroupID)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve group session policy")
			return
		}
		if eff.Conflict != "" { // docs/62 R4
			writeError(w, http.StatusConflict, eff.Conflict)
			return
		}
		groupPolicy := eff.GroupSessionPolicy
		if groupPolicy.EnforceViewOnly {
			// RECORD BEFORE TELLING (loop 83, migration 0036). The guest is about to open the session
			// floored on the strength of this answer, but whether a policy is minted is decided later,
			// at connect, from the group's state THEN. Persisting the promise first is what lets connect
			// keep it even if an admin clears the group's mandate in between — see the migration header
			// for the stranding this closes.
			//
			// A write failure FAILS THE REDEEM, which also burns the one-time code. That is the right
			// trade: the alternative is a guest that was told to floor while the control plane holds no
			// record of it — the exact state this flag exists to prevent — and the operator's remedy
			// (issue a new invite) is cheap and obvious.
			if err := s.Attended.SetRequireSessionPolicy(r.Context(), res.TenantID, res.SessionID); err != nil {
				log.Printf("attended %s: group %s enforces view-only but the floor could not be recorded: %v",
					res.SessionID, res.GroupID, err)
				writeError(w, http.StatusInternalServerError,
					"this machine group requires view-only sessions, but that could not be recorded for this session")
				return
			}
			body["require_session_policy"] = true
		}
	}
	writeJSON(w, http.StatusCreated, body)
}

type consentAttendedRequest struct {
	Decision    string `json:"decision"` // "accept" | "decline"
	ConsentUser string `json:"consent_user"`
}

func (s *Server) handleConsentAttended(w http.ResponseWriter, r *http.Request) {
	token := attendBearer(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "attend token required")
		return
	}
	if !validAttendTokenShape(token) {
		writeError(w, http.StatusForbidden, "invalid attend token")
		return
	}
	// F18: per-source budget for valid-shaped token guesses. Fires AFTER the shape guard (malformed
	// tokens never reach here) and BEFORE the store call (an exhausted source drives no DB work).
	// Namespace "attend-consent" is intentionally separate from "attend-status": the two endpoints
	// serve distinct protocol phases and a guest who polls status heavily should not accidentally
	// consume consent budget. An attacker gets FreeAttempts free reads per endpoint per window
	// rather than one shared pool — acceptable given the low cost of a DB token lookup.
	// Body-parse / input-validation errors (400) do NOT charge the budget: the token may be
	// valid; the body was malformed. Backend errors (500) are also not charged — an infrastructure
	// blip must not lock out the legitimate guest.
	th := s.throttle()
	thKeys := []string{ipKey("attend-consent", clientIP(r))}
	if retry, ok := th.Allow(thKeys...); !ok {
		writeThrottled(w, retry)
		return
	}
	var req consentAttendedRequest
	if err := decodeJSONBodyDetailed(w, r, maxAttendedBodyBytes, &req, "malformed consent request body"); err != nil {
		return
	}
	accept := req.Decision == "accept"
	if req.Decision != "accept" && req.Decision != "decline" {
		writeError(w, http.StatusBadRequest, `decision must be "accept" or "decline"`)
		return
	}
	if len(req.ConsentUser) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "consent_user is too long")
		return
	}
	sess, err := s.Attended.Consent(r.Context(), token, accept, req.ConsentUser)
	if err != nil {
		if errors.Is(err, ErrAttendedInvalid) {
			th.Fail(thKeys...)
			writeError(w, http.StatusForbidden, "invalid attend token")
			return
		}
		// Not a token guess — do not charge budget (see comment above).
		writeError(w, http.StatusInternalServerError, "could not record consent")
		return
	}
	th.Reset(thKeys...)
	// THE consent decision — docs/12's load-bearing rule, and the single fact that authorizes a
	// technician to see this desktop. It left no audit event at all, which is the one record a
	// reviewer or a disputing guest actually comes here for. Both decisions are recorded: a trail
	// carrying only acceptances would read as complete while being incomplete in exactly the
	// direction that matters. Empty actor and direct RecordEvent for the same reasons as
	// handleRedeemAttended above.
	if s.MgmtAudit != nil {
		meta, err := json.Marshal(map[string]any{
			"decision": req.Decision, "consent_user": req.ConsentUser, "ip": clientIP(r),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
		if err := s.MgmtAudit.RecordEvent(r.Context(), sess.TenantID, &MgmtAuditEvent{
			Action: "attended.consent", TargetKind: "attended_session", TargetID: sess.ID,
			Metadata: meta,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": sess.State})
}

// handleStatusAttended lets the guest poll for end + promote by presenting its attend token. When a
// promote enrollment token has been stashed, it is returned here (once the guest picks it up and
// enrolls, its single-use enrollment semantics protect it).
func (s *Server) handleStatusAttended(w http.ResponseWriter, r *http.Request) {
	token := attendBearer(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "attend token required")
		return
	}
	if !validAttendTokenShape(token) {
		writeError(w, http.StatusForbidden, "invalid attend token")
		return
	}
	// F18: per-source budget, namespace "attend-status". Intentionally separate from "attend-consent"
	// (see that handler's comment). A real guest polling with its valid token always resets the
	// counter; an attacker cycling through guesses accumulates failures without driving unlimited
	// database reads. Backend errors (500) are not charged — see handleConsentAttended for rationale.
	th := s.throttle()
	thKeys := []string{ipKey("attend-status", clientIP(r))}
	if retry, ok := th.Allow(thKeys...); !ok {
		writeThrottled(w, retry)
		return
	}
	sess, err := s.Attended.ByToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, ErrAttendedInvalid) {
			th.Fail(thKeys...)
			writeError(w, http.StatusForbidden, "invalid attend token")
			return
		}
		// Not a token guess — do not charge budget.
		writeError(w, http.StatusInternalServerError, "could not resolve attended session")
		return
	}
	th.Reset(thKeys...)
	resp := map[string]any{"state": sess.State, "device_id": sess.DeviceID}
	if sess.PromoteToken != "" {
		resp["promote"] = map[string]any{
			"enrollment_token":    sess.PromoteToken,
			"installer_available": s.ManagedInstaller != nil,
			"attempt_nonce":       sess.PromoteAttemptNonce,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePromoteCompleteAttended is the guest-facing endpoint that records whether the permanent
// install attempt initiated by /promote succeeded or failed. The technician panel polls
// GET /attended-sessions/{id} and surfaces the result so the technician knows the install outcome
// without waiting for the machine to appear in the fleet.
//
// Auth: attend token Bearer (same pre-tenant path as /status, /consent). Rate-limited using the
// same "attend-status" namespace — an attacker would need the real token to post anything, and
// legitimate calls are at most one per session.
func (s *Server) handlePromoteCompleteAttended(w http.ResponseWriter, r *http.Request) {
	token := attendBearer(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "attend token required")
		return
	}
	if !validAttendTokenShape(token) {
		writeError(w, http.StatusForbidden, "invalid attend token")
		return
	}

	th := s.throttle()
	thKeys := []string{ipKey("attend-status", clientIP(r))}
	if retry, ok := th.Allow(thKeys...); !ok {
		writeThrottled(w, retry)
		return
	}

	var req struct {
		Success      bool   `json:"success"`
		Error        string `json:"error"`
		AttemptNonce string `json:"attempt_nonce"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAttendedBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result := PromoteResult{Success: req.Success, Error: req.Error, At: time.Now().UTC()}
	err := s.Attended.SetPromoteResult(r.Context(), token, req.AttemptNonce, result)
	if err != nil {
		if errors.Is(err, ErrAttendedInvalid) {
			th.Fail(thKeys...)
			writeError(w, http.StatusForbidden, "invalid attend token")
			return
		}
		if errors.Is(err, ErrAttendedPromoteCompleteConflict) {
			writeError(w, http.StatusConflict, "no pending promotion for this session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not record promote result")
		return
	}
	th.Reset(thKeys...)
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

func (s *Server) handleListAttended(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	scope, _ := p.Grant.ScopeFor(CapViewSessions)
	limit, offset := 50, 0
	for _, param := range []struct {
		name     string
		value    *int
		min, max int
	}{
		{"limit", &limit, 1, 100}, {"offset", &offset, 0, 1000000},
	} {
		if values, present := r.URL.Query()[param.name]; present {
			if len(values) != 1 {
				writeError(w, http.StatusBadRequest, "invalid pagination")
				return
			}
			n, err := strconv.Atoi(values[0])
			if err != nil || n < param.min || n > param.max {
				writeError(w, http.StatusBadRequest, "invalid pagination")
				return
			}
			*param.value = n
		}
	}
	rows, err := s.Attended.List(r.Context(), p.TenantID, scope, limit+1, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list attended sessions")
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []AttendedSession{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": rows, "has_more": more})
}
