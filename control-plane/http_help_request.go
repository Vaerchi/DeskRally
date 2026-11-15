package controlplane

// The HTTP surface of guest help requests (docs/64, contracts H-C1..H-C7).
//
//	POST /internal/devices/{device_id}/help-request   device -> signaling -> here: create (op_id, note)
//	POST /internal/devices/{device_id}/help-cancel    cancel exactly {request_id}
//	POST /internal/devices/{device_id}/help-status    the device's open / latest request
//	GET  /help-requests                               technicians: open requests in their CURRENT scope
//	POST /help-requests/{id}/accept                   technician: accept = the bound session, one transaction
//
// The three internal routes are authorized EXACTLY like guest_end.go: the shared device-identity service
// token, the failure throttle on the signaling source, the device resolved to its tenant through
// LookupDeviceIdentity, and the body's tenant_id compared with it. Identity is the authenticated
// connection's - the body carries no device id (the path does, and it is the one signaling verified).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// helpRequestBody / helpCancelBody / helpStatusBody reject unknown fields (the shared raw decoder uses
// json.Unmarshal, so each type opts in, like guestEndRequest).
type helpRequestBody struct {
	TenantID string `json:"tenant_id"`
	OpID     string `json:"op_id"`
	Note     string `json:"note"`
}
type helpCancelBody struct {
	TenantID  string `json:"tenant_id"`
	RequestID string `json:"request_id"`
}
type helpStatusBody struct {
	TenantID string `json:"tenant_id"`
}

func strictUnmarshal(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func (b *helpRequestBody) UnmarshalJSON(raw []byte) error {
	type body helpRequestBody
	var out body
	if err := strictUnmarshal(raw, &out); err != nil {
		return err
	}
	*b = helpRequestBody(out)
	return nil
}
func (b *helpCancelBody) UnmarshalJSON(raw []byte) error {
	type body helpCancelBody
	var out body
	if err := strictUnmarshal(raw, &out); err != nil {
		return err
	}
	*b = helpCancelBody(out)
	return nil
}
func (b *helpStatusBody) UnmarshalJSON(raw []byte) error {
	type body helpStatusBody
	var out body
	if err := strictUnmarshal(raw, &out); err != nil {
		return err
	}
	*b = helpStatusBody(out)
	return nil
}

// helpDeviceView is what the AGENT sees of a request: no tenant, machine or group ids.
type helpDeviceView struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func deviceViewOf(r *HelpRequest) *helpDeviceView {
	if r == nil {
		return nil
	}
	return &helpDeviceView{ID: r.ID, Status: r.Status, Note: r.Note, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
}

// dispatchHelpEvents fires the webhooks for audit events a store call committed. Called AFTER the
// commit, once per transition; best-effort and at-least-once like every other dispatch (H-C6).
func (s *Server) dispatchHelpEvents(tenantID string, res *HelpResult) {
	if res == nil || s.Dispatcher == nil {
		return
	}
	for _, e := range res.Events {
		s.Dispatcher.Dispatch(tenantID, e)
	}
}

// helpInternalAuth is guest_end.go's authorization, shared by the three internal routes. It returns the
// canonical tenant and device ids once the token, throttle, device and tenant checks pass, with the
// still-undecoded body handled by decode (which runs AFTER the token check and BEFORE the identity
// lookup, as in the guest-end handler). On any failure it has written the response.
func (s *Server) helpInternalAuth(w http.ResponseWriter, r *http.Request, decode func() (tenantID string, ok bool)) (tenant, device string, ok bool) {
	th := s.throttle()
	keys := []string{ipKey("help-internal", clientIP(r))}
	if retry, allowed := th.Allow(keys...); !allowed {
		writeThrottled(w, retry)
		return "", "", false
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return "", "", false
	}
	if s.HelpRequests == nil || s.Machines == nil {
		writeError(w, http.StatusServiceUnavailable, "help requests are not available")
		return "", "", false
	}
	bodyTenant, decoded := decode()
	if !decoded {
		return "", "", false
	}
	tenant, tenantOK := parsePgUUID(bodyTenant)
	device, deviceOK := parsePgUUID(r.PathValue("device_id"))
	if !tenantOK || !deviceOK {
		writeError(w, http.StatusBadRequest, "invalid UUID")
		return "", "", false
	}
	identity, err := s.Machines.LookupDeviceIdentity(r.Context(), device)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		}
		return "", "", false
	}
	if canonicalUUIDish(identity.TenantID) != tenant {
		writeError(w, http.StatusForbidden, "device not in tenant")
		return "", "", false
	}
	return tenant, device, true
}

func writeHelpLimit(w http.ResponseWriter, le *HelpLimitError) {
	secs := int((le.RetryAfter + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "help request limit reached", "scope": le.Scope, "retry_after_seconds": secs})
}

// handleHelpRequestCreate: POST /internal/devices/{device_id}/help-request.
func (s *Server) handleHelpRequestCreate(w http.ResponseWriter, r *http.Request) {
	var body helpRequestBody
	tenant, device, ok := s.helpInternalAuth(w, r, func() (string, bool) {
		if err := decodeStrictJSONBody(w, r, 2048, &body, "invalid help request"); err != nil {
			return "", false
		}
		return body.TenantID, true
	})
	if !ok {
		return
	}
	if !validHelpOpID(body.OpID) {
		writeError(w, http.StatusBadRequest, "invalid op_id")
		return
	}
	res, err := s.HelpRequests.CreateForDevice(r.Context(), tenant, device, body.OpID, body.Note, time.Now().UTC())
	if err != nil {
		var le *HelpLimitError
		switch {
		case errors.As(err, &le):
			writeHelpLimit(w, le)
		case errors.Is(err, ErrHelpMachineIneligible):
			writeJSON(w, http.StatusConflict, map[string]any{"error": "this machine cannot request help", "refused": true})
		case errors.Is(err, ErrHelpTenantSuspended):
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "tenant suspended", "refused": true})
		case errors.Is(err, ErrHelpInvalidOp):
			writeError(w, http.StatusBadRequest, "invalid op_id")
		default:
			log.Printf("help request create for device %s: %v", device, err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		}
		return
	}
	s.dispatchHelpEvents(tenant, &res.HelpResult)
	code := http.StatusOK
	if res.Created {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"request": deviceViewOf(res.Request), "created": res.Created})
}

// handleHelpRequestCancel: POST /internal/devices/{device_id}/help-cancel.
func (s *Server) handleHelpRequestCancel(w http.ResponseWriter, r *http.Request) {
	var body helpCancelBody
	tenant, device, ok := s.helpInternalAuth(w, r, func() (string, bool) {
		if err := decodeStrictJSONBody(w, r, 2048, &body, "invalid help cancel"); err != nil {
			return "", false
		}
		return body.TenantID, true
	})
	if !ok {
		return
	}
	id, idOK := parsePgUUID(body.RequestID)
	if !idOK {
		writeError(w, http.StatusBadRequest, "invalid request_id")
		return
	}
	res, err := s.HelpRequests.CancelForDevice(r.Context(), tenant, device, id, time.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrHelpRequestNotFound) {
			writeError(w, http.StatusNotFound, "help request not found")
			return
		}
		log.Printf("help request cancel for device %s: %v", device, err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		return
	}
	s.dispatchHelpEvents(tenant, &res.HelpResult)
	if res.Conflict {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "help request is " + res.Request.Status, "request": deviceViewOf(res.Request)})
		return
	}
	outcome := "cancelled"
	if !res.Changed {
		outcome = "already_cancelled"
	}
	writeJSON(w, http.StatusOK, map[string]any{"outcome": outcome, "request": deviceViewOf(res.Request)})
}

// handleHelpRequestStatus: POST /internal/devices/{device_id}/help-status - the agent's re-query on every
// reconnect and on its 60 s timer while a request is open (H-C4).
func (s *Server) handleHelpRequestStatus(w http.ResponseWriter, r *http.Request) {
	var body helpStatusBody
	tenant, device, ok := s.helpInternalAuth(w, r, func() (string, bool) {
		if err := decodeStrictJSONBody(w, r, 1024, &body, "invalid help status"); err != nil {
			return "", false
		}
		return body.TenantID, true
	})
	if !ok {
		return
	}
	res, err := s.HelpRequests.CurrentForDevice(r.Context(), tenant, device, time.Now().UTC())
	if err != nil {
		log.Printf("help request status for device %s: %v", device, err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		return
	}
	s.dispatchHelpEvents(tenant, &res.HelpResult)
	writeJSON(w, http.StatusOK, map[string]any{"request": deviceViewOf(res.Request)})
}

// helpTechnicianView is what a TECHNICIAN sees. The note is the guest machine's own words: the console
// renders it as plain text under the label NoteSource ("from the guest's machine"), and attribution is
// "requested from the machine" - an enrolled-device assertion relayed by signaling, never proof of a
// person or of consent (H-C7).
type helpTechnicianView struct {
	ID            string    `json:"id"`
	MachineID     string    `json:"machine_id"`
	MachineName   string    `json:"machine_name"`
	MachineAlias  string    `json:"machine_alias,omitempty"`
	GroupID       string    `json:"group_id"` // the machine's CURRENT group
	Note          string    `json:"note"`
	NoteSource    string    `json:"note_source"`
	RequestedFrom string    `json:"requested_from"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Online        *bool     `json:"online,omitempty"`
	CanAccept     bool      `json:"can_accept"`
}

func technicianViewOf(v *HelpRequestWithMachine, online *bool) helpTechnicianView {
	canAccept := v.Status == HelpStatusOpen && v.MachineStatus == MachineStatusActive && (online == nil || *online)
	return helpTechnicianView{
		ID: v.ID, MachineID: v.MachineID, MachineName: v.MachineName, MachineAlias: v.MachineAlias,
		GroupID: v.MachineGroupID, Note: v.Note, NoteSource: "guest_machine", RequestedFrom: "machine",
		Status: v.Status, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, Online: online, CanAccept: canAccept,
	}
}

// helpOnlineFn returns a per-device online lookup from ONE presence snapshot, or one that answers "unknown"
// (nil) when presence is unwired or unreachable: nothing is authorized on presence, it only decides whether
// an accept button is worth showing.
func (s *Server) helpOnlineFn(r *http.Request) func(device string) *bool {
	if s.Presence == nil {
		return func(string) *bool { return nil }
	}
	snap, err := s.Presence.FetchPresence(r.Context())
	if err != nil || snap == nil {
		return func(string) *bool { return nil }
	}
	return func(device string) *bool { on := snap.IsOnline(device); return &on }
}

// helpPresenceOf is the accept's presence question with a bounded wait: POSITIVE evidence or nothing.
func (s *Server) helpPresenceOf(ctx context.Context, device string) HelpPresence {
	if s.Presence == nil {
		return HelpPresenceUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	snap, err := s.Presence.FetchPresence(ctx)
	if err != nil || snap == nil {
		return HelpPresenceUnknown
	}
	if snap.IsOnline(device) {
		return HelpPresenceOnline
	}
	return HelpPresenceOffline
}

func writePresenceUnknown(w http.ResponseWriter, state string) {
	w.Header().Set("Retry-After", "2")
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "presence is unavailable, so the machine cannot be confirmed online; retry", "state": state, "retry": true})
}

// handleListHelpRequests: GET /help-requests. A request is listed only when the caller's CURRENT grant
// allows starting a session in the machine's CURRENT group (docs/62 inheritance applies through
// AllowsInGroup); the stored group on the request is never consulted (H-C5).
func (s *Server) handleListHelpRequests(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.HelpRequests == nil {
		writeError(w, http.StatusInternalServerError, "help request store not configured")
		return
	}
	rows, res, err := s.HelpRequests.ListOpen(r.Context(), p.TenantID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list help requests")
		return
	}
	s.dispatchHelpEvents(p.TenantID, res)
	online := s.helpOnlineFn(r)
	out := make([]helpTechnicianView, 0, len(rows))
	for i := range rows {
		if !p.Grant.AllowsInGroup(CapStartSession, rows[i].MachineGroupID) {
			continue
		}
		out = append(out, technicianViewOf(&rows[i], online(rows[i].MachineDevice)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

type acceptHelpBody struct {
	OpID string `json:"op_id"`
}

func (b *acceptHelpBody) UnmarshalJSON(raw []byte) error {
	type body acceptHelpBody
	var out body
	if err := strictUnmarshal(raw, &out); err != nil {
		return err
	}
	*b = acceptHelpBody(out)
	return nil
}

// helpIssuanceGrace is how long a pending (not yet delivered) accept is assumed to still be in the hands of
// the handler that created it. A var so a test can shorten it.
var helpIssuanceGrace = 20 * time.Second

// handleAcceptHelpRequest: POST /help-requests/{id}/accept (H-C1). It resolves the machine's CURRENT
// state, runs the SAME admission POST /sessions runs (policy, seat caps incl. subgroup scope, observer and
// out-of-service refusals, the reap and the issuance guard), then the store marks the request accepted and
// inserts the bound session in one transaction. The response is POST /sessions' own, plus the request.
func (s *Server) handleAcceptHelpRequest(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.HelpRequests == nil || s.Machines == nil || s.SessionRecords == nil {
		writeError(w, http.StatusInternalServerError, "help request store not configured")
		return
	}
	var body acceptHelpBody
	if r.ContentLength != 0 {
		if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &body, "malformed accept body"); err != nil {
			return
		}
	}
	opID := strings.TrimSpace(body.OpID)
	if opID == "" {
		opID = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	if opID != "" && !validHelpOpID(opID) {
		writeError(w, http.StatusBadRequest, "invalid op_id")
		return
	}
	id, idOK := parsePgUUID(r.PathValue("id"))
	if !idOK {
		writeError(w, http.StatusNotFound, "unknown help request")
		return
	}
	now := time.Now().UTC()
	v, res, err := s.HelpRequests.Get(r.Context(), p.TenantID, id, now)
	s.dispatchHelpEvents(p.TenantID, res)
	if err != nil {
		if errors.Is(err, ErrHelpRequestNotFound) {
			writeError(w, http.StatusNotFound, "unknown help request")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve help request")
		return
	}
	// The caller's CURRENT coverage of the machine's CURRENT group. An uncovered caller learns nothing
	// about whether the request exists: the same 404 as an unknown id.
	if !p.Grant.AllowsInGroup(CapStartSession, v.MachineGroupID) {
		writeError(w, http.StatusNotFound, "unknown help request")
		return
	}
	retry := v.Status == HelpStatusAccepted && opID != "" && v.AcceptedBy == canonicalUUIDish(p.UserID)
	if v.Status != HelpStatusOpen && !retry {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "help request is " + v.Status, "state": v.Status})
		return
	}
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, v.MachineID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown help request")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	// A FRESH accept needs POSITIVE online evidence: presence missing or unreachable is a retryable 503, not a
	// pass. (The store asks again inside the accept admission, so a machine that dropped meanwhile is refused.)
	online := s.helpOnlineFn(r)(m.DeviceID)
	if !retry {
		switch s.helpPresenceOf(r.Context(), m.DeviceID) {
		case HelpPresenceOffline:
			writeJSON(w, http.StatusConflict, map[string]any{"error": "machine is offline", "state": v.Status})
			return
		case HelpPresenceUnknown:
			writePresenceUnknown(w, v.Status)
			return
		}
	}
	adm, refusal := s.resolveSessionAdmission(r.Context(), p.TenantID, p.UserID, p.Grant, m, "control")
	if refusal != nil {
		refusal.write(w)
		return
	}
	if !retry {
		s.reapBeforeSessionStart(r, p, adm)
	}
	release, gerr := s.holdIssuance(r.Context(), p.TenantID)
	if gerr != nil {
		writeIssuanceRefused(w, gerr)
		return
	}
	defer release()
	acc, err := s.HelpRequests.Accept(r.Context(), p.TenantID, HelpAcceptInput{
		RequestID: id, TechnicianID: p.UserID, OpID: opID, Record: adm.Rec, Limits: adm.Limits,
		AdmissionGroupID: m.GroupID, Now: time.Now().UTC(),
		Presence: func(device string) HelpPresence { return s.helpPresenceOf(r.Context(), device) },
	})
	if err != nil {
		writeStartAdmissionError(w, err)
		return
	}
	s.dispatchHelpEvents(p.TenantID, &acc.HelpResult)
	switch acc.Outcome {
	case HelpAcceptNotFound:
		writeError(w, http.StatusNotFound, "unknown help request")
		return
	case HelpAcceptConflict:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "help request is " + acc.Request.Status, "state": acc.Request.Status})
		return
	case HelpAcceptIneligible:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "machine is out of service", "state": acc.Request.Status})
		return
	case HelpAcceptGroupChanged:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the machine's group changed; reload and retry", "state": acc.Request.Status})
		return
	case HelpAcceptOffline:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "machine is offline", "state": acc.Request.Status})
		return
	case HelpAcceptPresenceUnknown:
		writePresenceUnknown(w, acc.Request.Status)
		return
	}
	rec := acc.Record
	replayed := acc.Outcome == HelpAcceptReplayed
	if replayed && rec.EndedAt != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the session for this request already ended", "state": acc.Request.Status})
		return
	}
	// ISSUANCE is serialized per accepted session by the persisted help_request.delivery state. The handler
	// that created the accept (the OWNER) either marks the session delivered once its ticket is minted, or - if
	// issuing fails - CLAIMS it (the reopen is a compare-and-swap on "pending") before it ends the session. A
	// retry that finds the delivery still pending does not mint a ticket of its own: the original is still
	// issuing, so it is told to retry shortly; only when that pending state is stale (the original handler is
	// gone) does the retry take over as owner. Delivered sessions are never ended by a compensation.
	owner := !replayed
	if replayed && acc.Request.Delivery == HelpDeliveryPending {
		if acc.Request.AcceptedAt != nil && time.Since(*acc.Request.AcceptedAt) < helpIssuanceGrace {
			w.Header().Set("Retry-After", "2")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "the session is still being prepared; retry shortly",
				"state": acc.Request.Status, "retry": true})
			return
		}
		owner = true
	}
	delivered := !owner
	defer func() {
		if delivered {
			return
		}
		ctx, cancel := compensationContext(r)
		defer cancel()
		// Claim first: a lost claim means the session was delivered, so it is not ours to end.
		re, err := s.HelpRequests.ReopenAfterFailedStart(ctx, p.TenantID, id, rec.ID, time.Now().UTC())
		if err != nil {
			log.Printf("help accept: request %s: could not reopen after failed start: %v", id, err)
			return
		}
		if !re.Changed {
			return
		}
		if _, err := s.SessionRecords.EndSession(ctx, p.TenantID, rec.ID, time.Now().UTC()); err != nil {
			log.Printf("help accept: session %s: could not close failed start: %v", rec.ID, err)
		}
		s.dispatchHelpEvents(p.TenantID, &re.HelpResult)
	}()
	if !replayed {
		if err := s.recordMgmtAudit(r, "session.start", "session", rec.ID,
			map[string]any{"machine_id": m.ID, "device_id": m.DeviceID, "access": rec.Access,
				"agent_version": m.AgentVersion, "help_request_id": id}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	resp, brokerRefusal := s.brokerSessionStart(rec, m, p.UserID, p.TenantID, adm.GroupPolicy)
	if brokerRefusal != nil {
		brokerRefusal.write(w)
		return
	}
	if owner {
		md, err := s.HelpRequests.MarkDelivered(r.Context(), p.TenantID, id, rec.ID, time.Now().UTC())
		if err != nil {
			log.Printf("help accept: request %s: could not record delivery: %v", id, err)
			writeError(w, http.StatusInternalServerError, "could not record the delivery")
			return
		}
		if !md.Changed {
			// The claim moved on without us. Another owner delivered this very session: carry on. Anything
			// else means the session is gone or reassigned: report it, and touch nothing.
			delivered = true
			if md.Request == nil || md.Request.Status != HelpStatusAccepted || md.Request.SessionID != rec.ID {
				state := ""
				if md.Request != nil {
					state = md.Request.Status
				}
				writeJSON(w, http.StatusConflict, map[string]any{"error": "the help request is no longer accepted for this session", "state": state})
				return
			}
		}
	}
	delivered = true
	rv := technicianViewOf(&HelpRequestWithMachine{HelpRequest: *acc.Request, MachineName: m.Name, MachineAlias: m.Alias,
		MachineGroupID: m.GroupID, MachineStatus: m.Status, MachineDevice: m.DeviceID}, online)
	resp["help_request"] = rv
	code := http.StatusCreated
	if replayed {
		code = http.StatusOK
	}
	writeJSON(w, code, resp)
}

// cancelHelpForMachine is the status-change hook (H-C5), called right after SetMachineStatus succeeds. On
// retire / quarantine the machine's open request is cancelled; on REACTIVATION (a non-active machine going
// back to active) any request still open is cancelled too, so one that survived a failed cancel can never
// become acceptable again. Its audit row is committed by the store; webhooks dispatch after. Best-effort -
// the machine IS out of service either way, and a later accept refuses an out-of-service machine.
func (s *Server) cancelHelpForMachine(r *http.Request, tenantID, machineID, prevStatus, status string) {
	if s.HelpRequests == nil {
		return
	}
	reason := HelpCancelRetired
	switch {
	case status == MachineStatusQuarantined:
		reason = HelpCancelQuarantined
	case status == MachineStatusActive:
		if prevStatus == "" || prevStatus == MachineStatusActive {
			return // not a reactivation: a live machine's open request is legitimate
		}
		reason = HelpCancelReactivated
	}
	res, err := s.HelpRequests.CancelForMachine(r.Context(), tenantID, machineID, reason, time.Now().UTC())
	if err != nil {
		log.Printf("machine %s %s but cancelling its help request failed: %v", machineID, status, err)
		return
	}
	s.dispatchHelpEvents(tenantID, res)
}

// RunHelpRequestSweep is one pass of the help-request reaper: expire due requests (each with its audit row),
// prune closed requests older than 30 days and the op ledger. Correctness never depends on it - expiry is
// applied lazily inside every deciding call.
func (s *Server) RunHelpRequestSweep(ctx context.Context) {
	if s.HelpRequests == nil {
		return
	}
	res, err := s.HelpRequests.Sweep(ctx, time.Now().UTC())
	if err != nil {
		log.Printf("background help sweep: %v", err)
		return
	}
	for _, e := range res.Events {
		if s.Dispatcher != nil {
			s.Dispatcher.Dispatch(e.TenantID, e.Event)
		}
	}
	if res.Expired > 0 || res.Pruned > 0 {
		log.Printf("background help sweep: expired %d, pruned %d across %d tenant(s)", res.Expired, res.Pruned, res.Tenants)
	}
}
