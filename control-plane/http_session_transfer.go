package controlplane

// Session transfer / escalation HTTP surface (docs/51; §7-§9 supersede §3-§5):
//
//	POST   /sessions/{id}/transfer             the holder offers S1 to a colleague or the machine's group
//	GET    /sessions/{id}/transfer-candidates  who the holder may name (the same rule as the 422)
//	DELETE /session-transfers/{id}             the sender cancels a pending offer
//	GET    /session-transfers/incoming         offers I could accept
//	GET    /session-transfers/outgoing         my live offers
//	GET    /session-transfers/{id}             status; the acceptor's poll also finalizes
//	POST   /session-transfers/{id}/accept      claim an offer (pending -> releasing)
//	POST   /session-transfers/{id}/ticket      S2's ticket and initial policy, once it exists
//
// AUTHORITY IS RE-DERIVED, NEVER CACHED (docs/51 §7.1, §9.2). An offer id is not a bearer credential: at
// offer, at accept AND at finalize the caller's authority is recomputed against the machine as it is NOW,
// through the same resolveSessionAdmission POST /sessions runs. A finalize has no request, so it loads the
// ACCEPTOR's grant from the user store (transferAdmitter) and runs the very same checks.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// sessionTransferView is what the API returns for an offer: the stored fields plus the display names
// and machine label a console needs, resolved server-side so the viewer needs no extra lookups.
type sessionTransferView struct {
	SessionTransfer
	MachineName    string `json:"machine_name,omitempty"`
	FromName       string `json:"from_name,omitempty"`
	ToName         string `json:"to_name,omitempty"`
	AcceptedByName string `json:"accepted_by_name,omitempty"`
}

func (s *Server) transferUsers() UserStore {
	if s.AuthAPI == nil {
		return nil
	}
	return s.AuthAPI.Users
}

// userLabel is a user's display name (falling back to their email), or "" when unknown.
func (s *Server) userLabel(ctx context.Context, tenantID, userID string) string {
	users := s.transferUsers()
	if users == nil || userID == "" {
		return ""
	}
	u, err := users.FindUserByID(ctx, tenantID, userID)
	if err != nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func (s *Server) transferView(ctx context.Context, tenantID string, t *SessionTransfer) sessionTransferView {
	v := sessionTransferView{SessionTransfer: *t}
	if s.Machines != nil {
		if m, err := s.Machines.GetMachineByID(ctx, tenantID, t.MachineID); err == nil {
			v.MachineName = m.Name
			if m.Alias != "" {
				v.MachineName = m.Alias
			}
		}
	}
	v.FromName = s.userLabel(ctx, tenantID, t.FromUserID)
	v.ToName = s.userLabel(ctx, tenantID, t.ToUserID)
	v.AcceptedByName = s.userLabel(ctx, tenantID, t.AcceptedBy)
	return v
}

func (s *Server) transferViews(ctx context.Context, tenantID string, ts []SessionTransfer) []sessionTransferView {
	out := make([]sessionTransferView, 0, len(ts))
	for i := range ts {
		out = append(out, s.transferView(ctx, tenantID, &ts[i]))
	}
	return out
}

func (s *Server) transfersConfigured(w http.ResponseWriter) bool {
	if s.SessionTransfers == nil || s.SessionRecords == nil || s.Machines == nil {
		writeError(w, http.StatusInternalServerError, "session transfer is not configured")
		return false
	}
	return true
}

// recipientEligible is the rule for who may be NAMED in an offer: an existing, enabled member of the
// tenant who holds CapStartSession on the machine's CURRENT group. The offer, the candidate list and
// (re-run) accept and finalize all use it, so it has one definition. A group-less machine is judged
// like any other: a null group is never "unrestricted" (RequireMachine decides).
func (s *Server) recipientEligible(ctx context.Context, tenantID, userID, machineGroupID string) (bool, error) {
	users := s.transferUsers()
	if users == nil {
		return false, errors.New("user store not configured")
	}
	u, err := users.FindUserByID(ctx, tenantID, userID)
	if errors.Is(err, ErrNoUser) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if u.Disabled || u.TenantSuspended {
		return false, nil
	}
	g, err := users.GrantFor(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	return g.RequireMachine(CapStartSession, machineGroupID) == nil, nil
}

// transferAdmissionFor re-derives userID's authority to take the transfer's machine NOW and builds S2's
// admission: the offer's addressing, the ordinary POST /sessions checks (current group, quarantine, group
// policy, caps), and the agent gate. Shared by accept (the caller's grant) and finalize (the acceptor's
// grant, loaded from the user store).
func (s *Server) transferAdmissionFor(ctx context.Context, tenantID string, t *SessionTransfer, userID string, grant *Grant, m *Machine) (*TransferAdmission, *sessionRefusal) {
	if sameUserID(t.FromUserID, userID) {
		return nil, &sessionRefusal{Status: http.StatusForbidden, Msg: "you cannot accept your own offer"}
	}
	if t.ToUserID != "" && !sameUserID(t.ToUserID, userID) {
		return nil, &sessionRefusal{Status: http.StatusForbidden, Msg: "this offer is addressed to someone else"}
	}
	adm, refusal := s.resolveSessionAdmission(ctx, tenantID, userID, grant, m, "control")
	if refusal != nil {
		return nil, refusal
	}
	if !transferAgentSupported(m.AgentVersion) {
		return nil, &sessionRefusal{Status: http.StatusUnprocessableEntity, Msg: transferAgentTooOld}
	}
	adm.Rec.TransferredFrom = t.SessionID
	return &TransferAdmission{
		Rec: adm.Rec, Limits: adm.Limits,
		StartMeta: map[string]any{"device_id": m.DeviceID, "access": adm.Rec.Access, "agent_version": m.AgentVersion},
	}, nil
}

const transferAgentTooOld = "update this machine's agent to hand off a live session"

// transferAdmitter is the finalize-time TransferAdmitter (docs/51 §9.2): it re-loads the ACCEPTOR from
// the user store (active membership, current grant) and the machine as it is now, then runs
// transferAdmissionFor. An authority failure is a TransferRefusedError (the offer fails with the reason);
// anything that is merely the stores being unavailable is returned as-is and the finalize is retried.
func (s *Server) transferAdmitter(tenantID string) TransferAdmitter {
	return func(ctx context.Context, t *SessionTransfer) (*TransferAdmission, error) {
		users := s.transferUsers()
		if users == nil || s.Machines == nil {
			return nil, errors.New("session transfer is not configured")
		}
		u, err := users.FindUserByID(ctx, tenantID, t.AcceptedBy)
		if errors.Is(err, ErrNoUser) {
			return nil, &TransferRefusedError{Reason: "the acceptor is no longer a member of this tenant"}
		}
		if err != nil {
			return nil, err
		}
		if u.Disabled || u.TenantSuspended {
			return nil, &TransferRefusedError{Reason: "the acceptor can no longer start sessions"}
		}
		grant, err := users.GrantFor(ctx, tenantID, t.AcceptedBy)
		if err != nil {
			return nil, err
		}
		m, err := s.Machines.GetMachineByID(ctx, tenantID, t.MachineID)
		if errors.Is(err, ErrMachineNotFound) {
			return nil, &TransferRefusedError{Reason: "the machine no longer exists"}
		}
		if err != nil {
			return nil, err
		}
		adm, refusal := s.transferAdmissionFor(ctx, tenantID, t, t.AcceptedBy, grant, m)
		if refusal != nil {
			if refusal.Status >= 500 {
				return nil, errors.New(refusal.Msg)
			}
			msg := refusal.Msg
			if refusal.Denied != nil {
				msg = "the acceptor is no longer permitted to start sessions on this machine"
			}
			return nil, &TransferRefusedError{Reason: msg}
		}
		return adm, nil
	}
}

// transferredRefusal answers S1's holder, whose session was handed over, with the reason: 409 "session
// transferred" naming the recipient. Only the HOLDER learns it (a non-holder with the capability gets the
// ordinary refusals). Reports whether it wrote a response.
func (s *Server) transferredRefusal(w http.ResponseWriter, ctx context.Context, p *Principal, sessionID string, rec *SessionRecord) bool {
	if s.SessionTransfers == nil || s.SessionRecords == nil {
		return false
	}
	if rec == nil {
		var err error
		if rec, err = s.SessionRecords.GetSession(ctx, p.TenantID, sessionID); err != nil {
			return false
		}
	}
	if !sameUserID(p.UserID, rec.TechnicianID) {
		return false
	}
	t, err := s.SessionTransfers.LiveForSession(ctx, p.TenantID, sessionID)
	if err != nil || t == nil {
		return false
	}
	name := s.userLabel(ctx, p.TenantID, t.AcceptedBy)
	if t.State == TransferFailed {
		// Once a hand-off reached releasing, S1 never renews again, even if the hand-off failed
		// (docs/51 §8.4): otherwise a viewer that keeps renewing would keep S1 alive indefinitely.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "session handed off; the transfer did not complete", "transferred_to": name})
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]string{"error": "session transferred", "transferred_to": name})
	return true
}

type transferOfferRequest struct {
	ToUserID string `json:"to_user_id"`
	Note     string `json:"note"`
}

// handleOfferTransfer is POST /sessions/{id}/transfer.
func (s *Server) handleOfferTransfer(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	var req transferOfferRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed transfer request body"); err != nil {
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if utf8.RuneCountInString(req.Note) > maxTransferNoteRunes {
		writeError(w, http.StatusBadRequest, "note is too long")
		return
	}
	// Only the session's HOLDER (checkHeldSession); an Admin's tenant-wide capability is not enough.
	held, refusal := s.checkHeldSession(r.Context(), p, r.PathValue("id"), "transfer a session")
	if refusal != nil {
		refusal.write(w)
		return
	}
	rec, m := held.Rec, held.Machine
	if rec.Access != "control" && rec.Access != "" {
		writeError(w, http.StatusConflict, "only a control session can be transferred")
		return
	}
	if !transferAgentSupported(m.AgentVersion) {
		writeError(w, http.StatusUnprocessableEntity, transferAgentTooOld)
		return
	}
	// S1 must be signaling-vouched: the agent's end report (which releases it) reaches the control plane
	// only for a session signaling brokered, and the redemption row is the control plane's evidence.
	if s.TicketRedemptions == nil {
		writeError(w, http.StatusInternalServerError, "session transfer cannot verify the session: ticket ledger not configured")
		return
	}
	vouched, err := s.TicketRedemptions.WasRedeemed(r.Context(), p.TenantID, rec.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not verify the session")
		return
	}
	if !vouched {
		writeError(w, http.StatusUnprocessableEntity, "this session was not brokered through signaling and cannot be handed off")
		return
	}
	if req.ToUserID != "" {
		if sameUserID(req.ToUserID, p.UserID) {
			writeError(w, http.StatusUnprocessableEntity, "you cannot transfer a session to yourself")
			return
		}
		ok, err := s.recipientEligible(r.Context(), p.TenantID, req.ToUserID, m.GroupID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve the recipient")
			return
		}
		if !ok {
			writeError(w, http.StatusUnprocessableEntity, "that user cannot take sessions on this machine")
			return
		}
	}
	t, err := s.SessionTransfers.CreateOffer(r.Context(), p.TenantID, TransferOfferInput{
		SessionID: rec.ID, FromUserID: p.UserID, ToUserID: req.ToUserID, Note: req.Note})
	switch {
	case errors.Is(err, ErrSessionRecordNotFound):
		writeError(w, http.StatusNotFound, "unknown session")
	case errors.Is(err, ErrTransferSessionNotHeld):
		writeError(w, http.StatusConflict, "session is not open and held by you")
	case errors.Is(err, ErrTransferReleasing):
		writeError(w, http.StatusConflict, "a transfer of this session is already in progress")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not create the transfer offer")
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"transfer": s.transferView(r.Context(), p.TenantID, t)})
	}
}

// handleTransferCandidates is GET /sessions/{id}/transfer-candidates: the colleagues the holder may name.
func (s *Server) handleTransferCandidates(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	held, refusal := s.checkHeldSession(r.Context(), p, r.PathValue("id"), "transfer a session")
	if refusal != nil {
		refusal.write(w)
		return
	}
	users := s.transferUsers()
	if users == nil {
		writeError(w, http.StatusInternalServerError, "user store not configured")
		return
	}
	all, err := users.ListUsers(r.Context(), p.TenantID)
	if err != nil {
		writeListError(w, err, "could not list users")
		return
	}
	type candidate struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}
	out := []candidate{}
	for _, u := range all {
		if u.Disabled || sameUserID(u.ID, p.UserID) {
			continue
		}
		ok, err := s.recipientEligible(r.Context(), p.TenantID, u.ID, held.Machine.GroupID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve candidates")
			return
		}
		if ok {
			out = append(out, candidate{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName})
		}
	}
	group := map[string]string{"id": held.Machine.GroupID}
	if s.MachineGroups != nil && held.Machine.GroupID != "" {
		if gs, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID); err == nil {
			for _, g := range gs {
				if sameUserID(g.ID, held.Machine.GroupID) {
					group["name"] = g.Name
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"candidates": out, "group": group})
}

// transferStatusRefusal words the 409 for an offer that is not (or no longer) acceptable.
func transferStatusRefusal(w http.ResponseWriter, t *SessionTransfer) {
	msg := "this offer is no longer available"
	if t != nil {
		msg += " (" + string(t.State) + ")"
	}
	writeError(w, http.StatusConflict, msg)
}

// handleCancelTransfer is DELETE /session-transfers/{id}.
func (s *Server) handleCancelTransfer(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	t, err := s.SessionTransfers.Cancel(r.Context(), p.TenantID, r.PathValue("id"), p.UserID)
	switch {
	case errors.Is(err, ErrTransferNotFound):
		writeError(w, http.StatusNotFound, "unknown transfer")
	case errors.Is(err, ErrTransferForbidden):
		writeError(w, http.StatusForbidden, "only the sender may cancel an offer")
	case errors.Is(err, ErrTransferNotPending):
		transferStatusRefusal(w, t)
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not cancel the transfer offer")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"transfer": s.transferView(r.Context(), p.TenantID, t)})
	}
}

// handleIncomingTransfers is GET /session-transfers/incoming. Authority is re-checked per offer BEFORE any
// machine name or note is returned: CapStartSession on the machine's CURRENT group, and the machine in
// service. Never the caller's own offers.
func (s *Server) handleIncomingTransfers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	all, err := s.SessionTransfers.ListIncoming(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		writeListError(w, err, "could not list transfers")
		return
	}
	visible := []SessionTransfer{}
	for _, t := range all {
		m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, t.MachineID)
		if err != nil {
			continue
		}
		if p.Grant.RequireMachine(CapStartSession, m.GroupID) != nil || outOfServiceMachineMsg(m, "") != "" {
			continue
		}
		visible = append(visible, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"transfers": s.transferViews(r.Context(), p.TenantID, visible)})
}

// handleOutgoingTransfers is GET /session-transfers/outgoing: the caller's live offers.
func (s *Server) handleOutgoingTransfers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	all, err := s.SessionTransfers.ListOutgoing(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		writeListError(w, err, "could not list transfers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transfers": s.transferViews(r.Context(), p.TenantID, all)})
}

// handleGetTransfer is GET /session-transfers/{id}: the offer's status for the sender, the addressee and
// the recorded acceptor (anyone else is told 404). The ACCEPTOR's poll is what finalizes a releasing
// offer once the agent has reported S1 gone; everyone's read applies the 5-minute and 60-second rules.
func (s *Server) handleGetTransfer(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	t, err := s.SessionTransfers.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, ErrTransferNotFound) {
		writeError(w, http.StatusNotFound, "unknown transfer")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the transfer")
		return
	}
	isAcceptor := t.AcceptedBy != "" && sameUserID(t.AcceptedBy, p.UserID)
	allowed := sameUserID(t.FromUserID, p.UserID) || isAcceptor || t.ToUserID != "" && sameUserID(t.ToUserID, p.UserID)
	if !allowed && t.ToUserID == "" && t.State == TransferPending {
		// A group escalation is visible to those who could accept it, judged on the CURRENT group.
		if m, merr := s.Machines.GetMachineByID(r.Context(), p.TenantID, t.MachineID); merr == nil {
			allowed = p.Grant.RequireMachine(CapStartSession, m.GroupID) == nil
		}
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "unknown transfer")
		return
	}
	var admit TransferAdmitter
	if isAcceptor && t.State == TransferReleasing {
		admit = s.transferAdmitter(p.TenantID)
	}
	t, err = s.SessionTransfers.Reconcile(r.Context(), p.TenantID, t.ID, admit)
	if errors.Is(err, ErrTransferNotFound) {
		writeError(w, http.StatusNotFound, "unknown transfer")
		return
	}
	if err != nil {
		log.Printf("session transfer %s: reconcile failed: %v", r.PathValue("id"), err)
		writeError(w, http.StatusServiceUnavailable, "could not refresh the transfer; retry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transfer": s.transferView(r.Context(), p.TenantID, t)})
}

// handleAcceptTransfer is POST /session-transfers/{id}/accept: pending -> releasing. S1 stays open until
// the agent reports it gone; S2 is admitted then, not now (finalize).
func (s *Server) handleAcceptTransfer(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	t, err := s.SessionTransfers.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, ErrTransferNotFound) {
		writeError(w, http.StatusNotFound, "unknown transfer")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the transfer")
		return
	}
	if sameUserID(t.FromUserID, p.UserID) {
		writeError(w, http.StatusForbidden, "you cannot accept your own offer")
		return
	}
	if t.ToUserID != "" && !sameUserID(t.ToUserID, p.UserID) {
		writeError(w, http.StatusForbidden, "this offer is addressed to someone else")
		return
	}
	switch t.State {
	case TransferReleasing, TransferAccepted, TransferFailed:
		if t.AcceptedBy != "" && sameUserID(t.AcceptedBy, p.UserID) {
			// A repeated accept is a status read: no mutation, no audit (docs/51 §9.3). It confers no new
			// authority, so it is not re-authorized.
			writeJSON(w, http.StatusOK, map[string]any{"transfer": s.transferView(r.Context(), p.TenantID, t)})
			return
		}
	}
	if t.State != TransferPending {
		transferStatusRefusal(w, t)
		return
	}
	// The ordinary POST /sessions authorization and policy checks, on the machine as it is NOW.
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, t.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	if _, refusal := s.transferAdmissionFor(r.Context(), p.TenantID, t, p.UserID, p.Grant, m); refusal != nil {
		refusal.write(w)
		return
	}
	t, err = s.SessionTransfers.Accept(r.Context(), p.TenantID, t.ID, p.UserID)
	switch {
	case errors.Is(err, ErrTransferNotFound):
		writeError(w, http.StatusNotFound, "unknown transfer")
	case errors.Is(err, ErrTransferForbidden):
		writeError(w, http.StatusForbidden, "you cannot accept this offer")
	case errors.Is(err, ErrTransferExpired):
		writeError(w, http.StatusConflict, "this offer has expired")
	case errors.Is(err, ErrTransferSessionEnded):
		writeError(w, http.StatusConflict, "the session has ended")
	case errors.Is(err, ErrTransferNotPending):
		transferStatusRefusal(w, t)
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not accept the transfer")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"transfer": s.transferView(r.Context(), p.TenantID, t)})
	}
}

// handleTransferTicket is POST /session-transfers/{id}/ticket: S2's ticket and initial policy, minted
// exactly as POST /sessions mints them (brokerSessionStart). Acceptor only; S2 must exist and be open.
//
// Idempotent BEFORE redemption: while S2's id has no redemption row, every call mints a fresh ticket and
// the unredeemed earlier one is simply superseded. AFTER redemption the transfer is complete and the
// acceptor is S2's holder; a lost connection is recovered through the viewer's session-recovery path
// (POST /sessions), so this answers 409 `already connected; reconnect` and never mints a second ticket
// for an id signaling has already spent.
func (s *Server) handleTransferTicket(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !s.transfersConfigured(w) {
		return
	}
	t, err := s.SessionTransfers.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if errors.Is(err, ErrTransferNotFound) {
		writeError(w, http.StatusNotFound, "unknown transfer")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the transfer")
		return
	}
	if t.AcceptedBy == "" || !sameUserID(t.AcceptedBy, p.UserID) {
		writeError(w, http.StatusForbidden, "only the technician who accepted this transfer may fetch its ticket")
		return
	}
	if t.State != TransferAccepted || t.NewSessionID == "" {
		transferStatusRefusal(w, t)
		return
	}
	// The ordinary holder checks on S2: capability on the machine's group, still open, held by the caller,
	// machine in service.
	held, refusal := s.checkHeldSession(r.Context(), p, t.NewSessionID, "fetch this session's ticket")
	if refusal != nil {
		refusal.write(w)
		return
	}
	if s.TicketRedemptions == nil {
		writeError(w, http.StatusInternalServerError, "ticket redemption ledger not configured")
		return
	}
	redeemed, err := s.TicketRedemptions.WasRedeemed(r.Context(), p.TenantID, t.NewSessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the session ticket")
		return
	}
	if redeemed {
		writeError(w, http.StatusConflict, "already connected; reconnect")
		return
	}
	// Re-run EVERY start-time check against the machine as it is NOW, exactly as POST /sessions does
	// (Codex impl round 3): a restriction an administrator enabled between finalize and this fetch (the
	// PASS4 absolute gates: require/prohibit recording, duration and idle limits, which deployed agents
	// cannot yet enforce) must refuse the ticket here, as it refuses an ordinary start. The group policy
	// the ticket and initial policy are minted from comes from the same read.
	adm, arefusal := s.resolveSessionAdmission(r.Context(), p.TenantID, p.UserID, p.Grant, held.Machine, "control")
	if arefusal != nil {
		arefusal.write(w)
		return
	}
	groupPolicy := adm.GroupPolicy
	// Issuance guard, as at POST /sessions: a suspended tenant mints nothing.
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	resp, refusal := s.brokerSessionStart(held.Rec, held.Machine, p.UserID, p.TenantID, groupPolicy)
	if refusal != nil {
		refusal.write(w)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// noteTransferAgentEnded is the end-report hook (handleSessionEndReport): stamp agent_ended_at on the
// reported session (first report wins) and finalize its releasing transfer, in the transfer store's lock
// order. It runs for both outcomes that mean "the session is closed" (ended, already_ended), so an agent
// retry after a failed finalize completes it. Returns false when the stores could not answer, which the
// handler answers 503 so the agent retries.
func (s *Server) noteTransferAgentEnded(ctx context.Context, tenantID, sessionID string) bool {
	if s.SessionTransfers == nil {
		return true
	}
	if err := s.SessionTransfers.RecordAgentEnded(ctx, tenantID, sessionID, time.Now().UTC(), s.transferAdmitter(tenantID)); err != nil {
		log.Printf("session %s: could not record the agent's end report for transfer: %v", sessionID, err)
		return false
	}
	return true
}

// heldRec is the held session's record, or nil when checkHeldSession refused.
func heldRec(h *heldSession) *SessionRecord {
	if h == nil {
		return nil
	}
	return h.Rec
}
