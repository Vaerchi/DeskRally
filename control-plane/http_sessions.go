package controlplane

// Session-ticket redemption and the session records: list, start, end, notes. Split out of http.go (routing and middleware stay there).

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// -------------------------------------------------------------------------------------
// Session-ticket redemption — the shared single-use ledger (ticketredemption.go)
// -------------------------------------------------------------------------------------

// sessionTicketRedeemRequest is the body of POST /internal/session-tickets/redeem: the identifying
// claims of a session ticket the SIGNALING SERVER HAS ALREADY VERIFIED. Nothing here is a
// credential — signature, version, expiry, tenant binding and device binding were all checked by
// the caller before it asked, and this endpoint's own authorization is the service token.
type sessionTicketRedeemRequest struct {
	TenantID    string `json:"tenant_id"`
	SessionID   string `json:"session_id"`
	DeviceID    string `json:"device_id"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// sessionTicketRedemptionMaxTTL caps how far in the future a redemption row may be dated. See the
// clamp in handleRedeemSessionTicket for why the caller's number is not simply trusted.
const sessionTicketRedemptionMaxTTL = time.Hour

// handleRedeemSessionTicket answers POST /internal/session-tickets/redeem for the signaling server:
// record this ticket's single use, and say whether it was NEW.
//
//	200 {"redeemed": true}  — first use; the caller may broker.
//	409                     — DEFINITIVE replay; the caller must refuse.
//	anything else           — the ledger could not answer. The caller proceeds on its LOCAL verdict
//	                          and logs loudly (server/signaling/ticketredeem.go documents why).
//
// Posture, deliberately parallel to handleDeviceIdentity above:
//   - Service-token auth (constant-time), never a tenant principal — the ledger is cross-tenant and
//     signaling belongs to no tenant. The route is not even mounted without the token.
//   - Metered per source, so token guessing runs into the same exponential backoff. But a 409 is
//     NOT metered, and that exception is load-bearing: an attacker replaying one captured ticket in
//     a loop would otherwise lock out the signaling server's own IP, and every subsequent
//     redemption would fail open — turning the defence's own rate limiter into the switch that
//     disables it. Only a failed AUTH counts against the source.
//   - NOT recorded in the management audit trail. This fires once per brokered session, on the
//     interactive path, and would drown the trail that exists to record human actions.
func (s *Server) handleRedeemSessionTicket(w http.ResponseWriter, r *http.Request) {
	th := s.throttle()
	keys := []string{ipKey("ticket-redeem", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.TicketRedemptions == nil {
		// Unreachable through Handler() (the route is mounted only when the store is wired), kept
		// because a 500 is the honest answer if that ever stops being true — never a silent 200,
		// which would claim a ticket had been recorded when nothing was.
		writeError(w, http.StatusInternalServerError, "ticket redemption store not configured")
		return
	}
	var req sessionTicketRedeemRequest
	if err := decodeJSONBodyDetailed(w, r, maxRedeemBodyBytes, &req, "malformed redeem request body"); err != nil {
		return
	}
	if req.TenantID == "" || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id and session_id are required")
		return
	}

	// The row's expiry is the TICKET's own exp_ms: that is exactly how long remembering the
	// redemption is worth anything, because from then on verifyTicket refuses the ticket unaided.
	// It is CLAMPED rather than trusted — the caller is authenticated by a shared service token
	// alone, so a compromised or simply buggy one could otherwise date rows years out and pin them
	// past every reap. The ceiling is generous next to the 2-minute sessionTicketTTL, so ordinary
	// clock skew between the two hosts can never shorten a live ticket's entry.
	expiresAt := time.Now().Add(sessionTicketRedemptionMaxTTL)
	if req.ExpiresAtMs > 0 {
		if claimed := time.UnixMilli(req.ExpiresAtMs); claimed.Before(expiresAt) {
			expiresAt = claimed
		}
	}

	if _, err := s.TicketRedemptions.RedeemTicket(r.Context(), req.TenantID, req.SessionID, req.DeviceID, expiresAt); err != nil {
		if errors.Is(err, ErrTicketAlreadyRedeemed) {
			// The one answer the caller acts on. Distinguishable ON PURPOSE — a generic error here
			// would be indistinguishable from an outage and would therefore be ignored.
			writeError(w, http.StatusConflict, ErrTicketAlreadyRedeemed.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem session ticket")
		return
	}
	th.Reset(keys...)
	writeJSON(w, http.StatusOK, map[string]any{"redeemed": true})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapViewSessions); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
		return
	}
	since, until, ok := parseSinceUntil(w, r)
	if !ok {
		return
	}
	all, err := s.SessionRecords.ListSessions(r.Context(), p.TenantID, SessionSummaryFilter{Since: since, Until: until})
	if err != nil {
		writeListError(w, err, "could not list sessions")
		return
	}
	// RLS already scoped to the tenant; now, like machine listing, confine visibility to the
	// machine groups the caller's memberships actually cover.
	visible := make([]SessionRecord, 0, len(all))
	for _, rec := range all {
		if p.Grant.AllowsInGroup(CapViewSessions, rec.MachineGroupID) {
			visible = append(visible, rec)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.withRecordingIDs(r.Context(), p, visible)})
}

// sessionListRow is a session record plus, when the CALLER may know of it, the id of the session's central recording.
type sessionListRow struct {
	SessionRecord
	RecordingID string `json:"recording_id,omitempty"`
}

// withRecordingIDs adds `recording_id` to the rows whose machine group the caller holds CapViewRecordings over (docs/63
// C8 scope: the machine's CURRENT group, the same AllowsInGroup the recordings routes use). The existence of a recording
// is information, so for a caller without that capability on that group the field is simply absent: not null, not
// false. API tokens never get it (they cannot hold view_recordings), nor does a deployment whose recording routes are
// not mounted. A lookup failure omits the field; it never fails the session list.
func (s *Server) withRecordingIDs(ctx context.Context, p *Principal, rows []SessionRecord) []sessionListRow {
	out := make([]sessionListRow, len(rows))
	for i := range rows {
		out[i].SessionRecord = rows[i]
	}
	if p.APIToken || s.Recording.Store == nil || !s.Recording.ready() || s.MgmtAudit == nil || s.Machines == nil || len(rows) > RecIDsBySessionMax {
		return out
	}
	if p.Grant.Require(CapViewRecordings) != nil {
		return out
	}
	// Rule 4 of the recording routes: the machine's CURRENT group, not the session-time
	// MachineGroupID, so a machine moved out of scope (or deleted) hides its recording ids too.
	var ids []string
	allowed := make(map[string]bool, len(rows))
	groups := map[string]string{}
	for i := range rows {
		ok, err := s.recMachineAllowed(ctx, p, rows[i].MachineID, groups)
		if err != nil {
			log.Printf("session list: recording scope: %v", err)
			return out
		}
		if ok {
			allowed[rows[i].ID] = true
			ids = append(ids, rows[i].ID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	byID, err := s.Recording.Store.RecordingIDsBySession(ctx, p.TenantID, ids)
	if err != nil {
		log.Printf("session list: recording ids: %v", err)
		return out
	}
	for i := range out {
		if rid, ok := byID[rows[i].ID]; ok && allowed[rows[i].ID] {
			out[i].RecordingID = rid
		}
	}
	return out
}

// startSessionRequest is the body of POST /sessions: the target machine to open a session on.
// machine_id is the agent's DEVICE ID (same identifier as the mint path), resolved via GetMachine.
type startSessionRequest struct {
	MachineID string `json:"machine_id"`
	// omitempty: Go callers (tests, tools) that leave Access unset send no field, which means control.
	// A PRESENT empty string is still refused by startSessionAccess.UnmarshalJSON.
	Access startSessionAccess `json:"access,omitempty"`
}

// compensationContext is for compensating writes that undo a partial success after a later failure.
// It inherits neither the request's cancellation nor its pinned connection: a client disconnect
// cancels r.Context() and closes that connection. The timeout bounds how long compensation can
// hold the handler. Callers must cancel the context immediately after the compensating write.
func compensationContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(withoutBoundConn(context.WithoutCancel(r.Context())), 10*time.Second)
}

func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "machine store not configured")
		return
	}
	var req startSessionRequest
	// docs/25 F05, and the endpoint the external review actually reproduced against. The decode still
	// runs BEFORE authorization, deliberately: the capability enforced here is group-scoped
	// (RequireMachine against the group the STORE says the target machine belongs to), and the target
	// is named in the body — there is nothing to authorize until the body has been read. What the
	// review demonstrated, a read-only principal forcing a >1 MiB buffer before its 403, is closed by
	// the bound instead: the most any caller can now make this handler buffer is 64 KiB, held against
	// the pinned tenant connection for at most the server's ReadTimeout. A tenant-wide
	// Require(CapStartSession) pre-check would refuse a read-only caller before the read entirely, but
	// that is a change to the authorization model rather than to the body bound, and is not made here.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed start-session request body"); err != nil {
		return
	}
	if req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	if req.Access == "" {
		req.Access = "control"
	}
	// Resolve the target machine's REAL group from the store, then gate StartSession on THAT
	// group — not on anything the caller supplied.
	m, err := s.Machines.GetMachine(r.Context(), p.TenantID, req.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	adm, refusal := s.resolveSessionAdmission(r.Context(), p.TenantID, p.UserID, p.Grant, m, string(req.Access))
	if refusal != nil {
		refusal.write(w)
		return
	}
	rec, limits, groupPolicy := adm.Rec, adm.Limits, adm.GroupPolicy
	rec.SourceIP = sourceIPFrom(r.Context()) // session_record.source_ip: where the technician started it from
	s.reapBeforeSessionStart(r, p, adm)
	// Issuance guard (issuance_guard.go), held from BEFORE the session record exists until return: a
	// refusal must not leave an open record holding a concurrency seat (a leaked seat counts against
	// max_concurrent_sessions until reaped). Lock order matches the suspension's: issuance key first,
	// then the audit chain written below.
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	if err := s.SessionRecords.StartSessionWithinLimit(r.Context(), p.TenantID, rec, limits); err != nil {
		writeStartAdmissionError(w, err)
		return
	}
	// Any failure after admission must release the observer slot as well as its seats.
	// Existing explicit EndSession on mint failure remains harmlessly idempotent.
	startDelivered := false
	defer func() {
		if !startDelivered {
			ctx, cancel := compensationContext(r)
			_, err := s.SessionRecords.EndSession(ctx, p.TenantID, rec.ID, time.Now().UTC())
			cancel()
			if err != nil {
				log.Printf("session %s: could not close failed start: %v", rec.ID, err)
			}
		}
	}()
	if err := s.recordMgmtAudit(r, "session.start", "session", rec.ID,
		// agent_version: docs/49's measurement keys each session to the agent build that served it
		// (its last reported identity), so leak and end-reason rates can be compared per release.
		map[string]any{"machine_id": m.ID, "device_id": m.DeviceID, "access": rec.Access, "agent_version": m.AgentVersion}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	resp, brokerRefusal := s.brokerSessionStart(rec, m, p.UserID, p.TenantID, groupPolicy)
	if brokerRefusal != nil {
		// The deferred compensation above ends the record just created, so a refusal never strands a seat.
		brokerRefusal.write(w)
		return
	}
	startDelivered = true
	writeJSON(w, http.StatusCreated, resp)
}

// handleEndSession stamps ended_at on a session (POST /sessions/{id}/end). The session's
// machine group — resolved from the STORED record, never the caller — scopes the EndSession
// capability, mirroring how start/mint resolve the machine's real group.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
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
	if err := p.Grant.RequireMachine(CapEndSession, rec.MachineGroupID); err != nil {
		writeDenied(w, err)
		return
	}
	ended, err := s.SessionRecords.EndSession(r.Context(), p.TenantID, rec.ID, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not end session")
		return
	}
	if err := s.recordMgmtAudit(r, "session.end", "session", ended.ID,
		map[string]any{"machine_id": ended.MachineID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": ended})
}

// maxSessionNoteRunes bounds a session note. Generous for a handoff note yet small enough that the
// column and the audit log stay sane; enforced by rune count so multi-byte text is not mis-measured.
const maxSessionNoteRunes = 4000

// setSessionNoteRequest is the body of PATCH /sessions/{id}/note. An absent/empty note clears it.
type setSessionNoteRequest struct {
	Note string `json:"note"`
}

// normalizeSessionNote validates a free-text session note: it caps the length and rejects control
// characters other than tab / newline / carriage-return. NUL cannot live in a Postgres text column,
// and the other C0 controls have no place in a human note and could garble a console that renders it.
// The note is otherwise returned verbatim (no trimming) so it round-trips exactly as typed.
func normalizeSessionNote(note string) (string, error) {
	if len([]rune(note)) > maxSessionNoteRunes {
		return "", errors.New("note must be at most 4000 characters")
	}
	for _, r := range note {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", errors.New("note contains a control character")
		}
	}
	return note, nil
}

// handleSetSessionNote (PATCH /sessions/{id}/note) overwrites a session's free-text operator note
// (docs/01 §7). Gated exactly like ending a session — CapEndSession for the session's machine group
// (a session-MANAGEMENT write, so a read-only viewer who can see the session still cannot annotate it),
// resolved from the STORED session row so group scope cannot be spoofed. The note CONTENT is not put in
// the audit metadata (it may be sensitive); the event records only that a note was set.
func (s *Server) handleSetSessionNote(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "session store not configured")
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
	if err := p.Grant.RequireMachine(CapEndSession, rec.MachineGroupID); err != nil {
		writeDenied(w, err)
		return
	}
	var req setSessionNoteRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	note, err := normalizeSessionNote(req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.SessionRecords.SetSessionNote(r.Context(), p.TenantID, rec.ID, note)
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			writeError(w, http.StatusNotFound, "unknown session")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set session note")
		return
	}
	if err := s.recordMgmtAudit(r, "session.note_set", "session", updated.ID,
		map[string]any{"machine_id": updated.MachineID}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": updated})
}
