package controlplane

// Fleet agent directives - HTTP surface (docs/65, review r1 contracts D-C1..D-C9).
//
//	POST /machines/{id}/directives        request a reinstall or uninstall (CapRemoveAgent on the machine's group)
//	GET  /machines/{id}/directives        a machine's directives (CapViewMachines)
//	GET  /directives/{id}                 one directive (CapViewMachines on its machine's CURRENT group)
//	POST /directives/{id}/approve         the second approver (never the requester)
//	POST /directives/{id}/cancel          cancel inside the 15-minute window
//	GET|PUT /tenant/directive-policy      the "require a second approver" policy
//	POST /machines/{id}/forget            an Owner's "forget this machine" (docs/65 sec. 8)
//
//	GET  /internal/devices/{device_id}/directives/pending   signaling asks what to relay to the authenticated device
//	POST /internal/directives/{id}/delivered                signaling reports a relay
//	POST /internal/directives/{id}/ack                      signaling forwards a device-key-signed acknowledgement
//
// There is deliberately NO bulk or id-list route: a 200-id loop would be a fleet wipe in a few calls.
//
// AUTHORITY IS RE-DERIVED, NEVER CACHED (D-C4, D-C8): every human endpoint authorizes against the machine's
// CURRENT group (AllowsInGroup, descendants included - docs/62 sec. 2a); a directive id is not a bearer
// credential; the internal routes derive tenant, device and key fingerprint from the STORED row and the
// authenticated device, never from a caller-supplied claim.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// DirectiveNotifier tells signaling a directive is waiting for a device (F3). It carries no directive
// content: signaling asks the control plane for what is pending, so a forged or replayed notification can
// only cause a harmless fetch.
type DirectiveNotifier interface {
	Notify(ctx context.Context, deviceID string) error
}

func (s *Server) directivesConfigured(w http.ResponseWriter) bool {
	if s.Directives == nil || s.Machines == nil || s.DirectiveIssuer == nil {
		writeError(w, http.StatusInternalServerError, "fleet directives are not configured")
		return false
	}
	return true
}

// directiveAuthority is the issuance-time DirectiveAuthority (D-C4): the user is still an enabled member of
// a non-suspended tenant and still holds CapRemoveAgent on the machine's CURRENT group.
func (s *Server) directiveAuthority(tenantID string) DirectiveAuthority {
	return func(ctx context.Context, who DirectiveActor, groupID string) error {
		users := s.transferUsers()
		if users == nil {
			return errors.New("user store not configured")
		}
		userID := who.UserID
		u, err := users.FindUserByID(ctx, tenantID, userID)
		if errors.Is(err, ErrNoUser) {
			return ErrDirectiveAuthorityLost
		}
		if err != nil {
			return err
		}
		if u.Disabled || u.TenantSuspended {
			return ErrDirectiveAuthorityLost
		}
		// The credentials they acted under must be unchanged: a password change (credential epoch moved) or
		// an MFA reset/re-enrollment (generation moved) since the request ends it, and the session that
		// asked must still be a live session (sign-out, revoke-all, expiry).
		if who.SessionID == "" || u.CredentialUpdatedAt.After(who.CredentialEpoch) || u.MFAGeneration != who.MFAGeneration {
			return ErrDirectiveAuthorityLost
		}
		if s.AuthAPI == nil || s.AuthAPI.Sessions == nil || s.AuthAPI.Sessions.Store == nil {
			return errors.New("session store not configured")
		}
		live, err := s.AuthAPI.Sessions.Store.SessionLive(ctx, tenantID, userID, who.SessionID)
		if err != nil {
			return err
		}
		if !live {
			return ErrDirectiveAuthorityLost
		}
		g, err := users.GrantFor(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if g.RequireMachine(CapRemoveAgent, groupID) != nil {
			return ErrDirectiveAuthorityLost
		}
		return nil
	}
}

// writeDirectiveError maps a store outcome to its HTTP answer.
func writeDirectiveError(w http.ResponseWriter, err error) {
	var refused *DirectiveRefusedError
	switch {
	case errors.Is(err, ErrDirectiveNotFound), errors.Is(err, ErrMachineNotFound):
		writeError(w, http.StatusNotFound, "unknown directive or machine")
	case errors.As(err, &refused):
		writeError(w, http.StatusConflict, "the directive was cancelled: "+refused.Reason)
	case errors.Is(err, ErrDirectiveSelfApproval), errors.Is(err, ErrDirectiveTenantSuspended):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrDirectiveMachineRetired):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrDirectiveQuota):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, ErrDirectiveExpired):
		writeError(w, http.StatusGone, err.Error())
	case errors.Is(err, ErrDirectiveNoKey):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, ErrDirectiveMachineRemoved), errors.Is(err, ErrDirectiveNotRetired),
		errors.Is(err, ErrDirectiveActiveExists), errors.Is(err, ErrDirectiveMachineChanged),
		errors.Is(err, ErrDirectiveNotPending), errors.Is(err, ErrDirectiveNotCancellable),
		errors.Is(err, ErrDirectiveNotIssuable), errors.Is(err, ErrDirectiveTooEarly),
		errors.Is(err, ErrDirectiveNeedsApproval), errors.Is(err, ErrDirectiveAlreadyApproved),
		errors.Is(err, ErrDirectiveApprovalNotNeeded), errors.Is(err, ErrDirectiveAuthorityLost):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "could not complete the directive operation")
	}
}

// requireInteractive refuses an API-token principal: the uninstall gates (step-up, confirmation, second
// approver) all assume a person with a session.
func requireInteractive(w http.ResponseWriter, p *Principal) bool {
	if p == nil || p.SessionID == "" {
		writeError(w, http.StatusForbidden, "this action requires an interactive signed-in session")
		return false
	}
	return true
}

// stepUpFresh is the FIRST READER of Session.MFAVerifiedAt: has this session proven the second factor within
// maxAge, against the user's current mfa generation?
func (s *Server) stepUpFresh(ctx context.Context, p *Principal, maxAge time.Duration) (bool, error) {
	if s.AuthAPI == nil || s.AuthAPI.Sessions == nil || s.AuthAPI.Sessions.Store == nil {
		return false, errors.New("session store not configured")
	}
	return s.AuthAPI.Sessions.Store.MFAFresh(ctx, p.TenantID, p.UserID, p.SessionID, maxAge)
}

// directiveActor reads the caller's CURRENT credential state (epoch, mfa generation) beside the session they
// are using, to be recorded on the directive and compared again at issuance.
func (s *Server) directiveActor(ctx context.Context, p *Principal) (DirectiveActor, error) {
	users := s.transferUsers()
	if users == nil {
		return DirectiveActor{}, errors.New("user store not configured")
	}
	u, err := users.FindUserByID(ctx, p.TenantID, p.UserID)
	if err != nil {
		return DirectiveActor{}, err
	}
	return DirectiveActor{UserID: p.UserID, SessionID: p.SessionID, CredentialEpoch: u.CredentialUpdatedAt, MFAGeneration: u.MFAGeneration}, nil
}

// directiveStepUp is the step-up check AND the credential snapshot in ONE read of the live session
// (SessionStore.StepUpSnapshot): the returned actor carries the exact mfa generation the verification was
// made against. A separate read of the user's current generation after the check would let an MFA reset in
// between record the NEW generation for an OLD verification.
func (s *Server) directiveStepUp(ctx context.Context, p *Principal, maxAge time.Duration) (DirectiveActor, bool, error) {
	if s.AuthAPI == nil || s.AuthAPI.Sessions == nil || s.AuthAPI.Sessions.Store == nil {
		return DirectiveActor{}, false, errors.New("session store not configured")
	}
	snap, err := s.AuthAPI.Sessions.Store.StepUpSnapshot(ctx, p.TenantID, p.UserID, p.SessionID, maxAge)
	if err != nil {
		return DirectiveActor{}, false, err
	}
	if s.testAfterStepUp != nil {
		s.testAfterStepUp()
	}
	actor := DirectiveActor{UserID: p.UserID, SessionID: p.SessionID, CredentialEpoch: snap.CredentialEpoch, MFAGeneration: snap.MFAGeneration}
	if snap.Fresh && actor.CredentialEpoch.IsZero() {
		// The store could not see the credential (the fake): read the epoch alone. The generation stays the
		// snapshot's.
		if u, uerr := s.transferUsers().FindUserByID(ctx, p.TenantID, p.UserID); uerr == nil {
			actor.CredentialEpoch = u.CredentialUpdatedAt
		}
	}
	return actor, snap.Fresh, nil
}

type directiveRequestBody struct {
	Kind    string `json:"kind"`
	Confirm string `json:"confirm"`
}

// machineNameConfirmed is the typed-confirmation rule of every irreversible machine action (an uninstall request
// and forget): the typed text, trimmed, must equal the machine's name (hostname) or its tenant-chosen alias
// EXACTLY, and an empty entry never matches. One rule, so the two dialogs cannot disagree.
func machineNameConfirmed(typed string, m *Machine) bool {
	typed = strings.TrimSpace(typed)
	return typed != "" && (typed == m.Name || (m.Alias != "" && typed == m.Alias))
}

// handleRequestDirective is POST /machines/{id}/directives.
func (s *Server) handleRequestDirective(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	// The machine's CURRENT group, resolved from the store (never the body).
	if err := p.Grant.RequireMachine(CapRemoveAgent, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if !requireInteractive(w, p) {
		return
	}
	var req directiveRequestBody
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed directive request body"); err != nil {
		return
	}
	kind := DirectiveKind(req.Kind)
	if !kind.Valid() {
		writeError(w, http.StatusBadRequest, "kind must be reinstall or uninstall")
		return
	}
	var actor DirectiveActor
	if m.Status == MachineStatusRemoved {
		writeError(w, http.StatusConflict, ErrDirectiveMachineRemoved.Error())
		return
	}
	if kind == DirectiveUninstall {
		if m.Status != MachineStatusRetired {
			writeError(w, http.StatusConflict, ErrDirectiveNotRetired.Error())
			return
		}
		// Typed confirmation of the machine's name (hostname or the tenant's alias), exactly.
		if !machineNameConfirmed(req.Confirm, m) {
			writeError(w, http.StatusUnprocessableEntity, "type the machine's name to confirm removal")
			return
		}
		// Step-up freshness at REQUEST time; the request is immutable from then on. The credential snapshot
		// recorded on the directive comes from the SAME read.
		var fresh bool
		actor, fresh, err = s.directiveStepUp(r.Context(), p, directiveStepUpMaxAge)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check the second factor")
			return
		}
		if !fresh {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "a recent second-factor verification is required", "code": "step_up_required"})
			return
		}
	}
	if kind != DirectiveUninstall {
		// A reinstall makes no second-factor claim: the user's current credential state is recorded.
		actor, err = s.directiveActor(r.Context(), p)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not read the caller's credentials")
			return
		}
	}
	d, err := s.Directives.Request(r.Context(), p.TenantID, DirectiveRequestInput{
		MachineID: m.ID, Kind: kind, RequestedBy: p.UserID, ExpectGroupID: m.GroupID,
		RequestedSession: actor.SessionID, RequestedEpoch: actor.CredentialEpoch, RequestedMFAGen: actor.MFAGeneration})
	if err != nil {
		writeDirectiveError(w, err)
		return
	}
	if kind == DirectiveReinstall {
		// No cancel window and no approval for a repair: issue now (the same re-checks run).
		issued, ierr := s.issueDirective(r.Context(), p.TenantID, d.ID)
		if issued != nil {
			d = issued
		}
		if ierr != nil && !errors.Is(ierr, ErrDirectiveTooEarly) {
			writeDirectiveError(w, ierr)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"directive": d})
}

// forgetMachineBody is the body of POST /machines/{id}/forget: the machine's name, typed.
type forgetMachineBody struct {
	Confirm string `json:"confirm"`
}

// handleForgetMachine is POST /machines/{id}/forget (docs/65 sec. 8): an Owner's deliberate, irreversible end of
// a machine whose removal will never be confirmed (the agent's final acknowledgement never arrived) or that is
// simply gone. It uninstalls nothing: it makes the control plane forget the machine.
//
// The authority is the removal's: CapRemoveAgent for the machine's CURRENT group (Owner preset only, never
// API-token grantable), an interactive session, a fresh TOTP step-up (directiveStepUpMaxAge) and the machine's
// name typed exactly. Only a RETIRED machine can be forgotten (retire first, then forget).
//
//	200 {"outcome":"forgotten","machine":M,"closed_directives":[D...]}  done now
//	200 {"outcome":"already_removed","machine":M}                       it was already removed (a confirmed removal or an
//	                                                                    earlier forget): nothing was written, no second audit row
//	400 malformed or missing body
//	403 no remove_agent for this machine's group (Admin, Technician, an API token, a group scope elsewhere), not an
//	    interactive session, or no fresh second factor ({"code":"step_up_required"})
//	404 unknown machine (another tenant's id answers exactly like a missing one)
//	409 the machine is not retired (active or quarantined: retire it first), or it moved to another group since
//	    the caller authorized (retry)
//	422 the typed confirmation is not the machine's name
//
// Every check below is repeated, authoritatively, under the machine row lock inside the store; the handler's
// reads only decide which refusal to show.
func (s *Server) handleForgetMachine(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown machine")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve machine")
		return
	}
	// The machine's CURRENT group, resolved from the store (never the body).
	if err := p.Grant.RequireMachine(CapRemoveAgent, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	if !requireInteractive(w, p) {
		return
	}
	var req forgetMachineBody
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed forget request body"); err != nil {
		return
	}
	forgetDone := func(outcome string, closed []AgentDirective) {
		got, gerr := s.Machines.GetMachineByID(r.Context(), p.TenantID, m.ID)
		if gerr != nil {
			cp := *m
			cp.Status = MachineStatusRemoved
			got = &cp
		}
		if closed == nil {
			closed = []AgentDirective{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"outcome": outcome, "machine": got, "closed_directives": closed})
	}
	// Idempotent: a machine that is already removed (by a confirmed removal or an earlier forget, e.g. a retry
	// whose response was lost) is answered with its current state. Nothing changes, so nothing needs the
	// confirmation or the second factor, and no second audit row is written.
	if m.Status == MachineStatusRemoved {
		forgetDone("already_removed", nil)
		return
	}
	if m.Status != MachineStatusRetired {
		writeError(w, http.StatusConflict, ErrForgetNotRetired.Error())
		return
	}
	if !machineNameConfirmed(req.Confirm, m) {
		writeError(w, http.StatusUnprocessableEntity, "type the machine's name to confirm that it is forgotten")
		return
	}
	fresh, err := s.stepUpFresh(r.Context(), p, directiveStepUpMaxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the second factor")
		return
	}
	if !fresh {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "a recent second-factor verification is required", "code": "step_up_required"})
		return
	}
	res, err := s.Directives.ForgetMachine(r.Context(), p.TenantID, ForgetMachineInput{
		MachineID: m.ID, ActorID: p.UserID, ExpectGroupID: m.GroupID})
	if err != nil {
		switch {
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, "unknown machine")
		case errors.Is(err, ErrForgetNotRetired), errors.Is(err, ErrDirectiveMachineChanged):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not forget the machine")
		}
		return
	}
	if res.AlreadyRemoved {
		forgetDone("already_removed", nil)
		return
	}
	forgetDone("forgotten", res.Closed)
}

// directiveForHuman loads a directive and authorizes the caller on its machine's CURRENT group.
func (s *Server) directiveForHuman(w http.ResponseWriter, r *http.Request, cap Capability) (*Principal, *AgentDirective, *Machine, bool) {
	if !s.directivesConfigured(w) {
		return nil, nil, nil, false
	}
	p := principalFrom(r.Context())
	d, err := s.Directives.Get(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		writeDirectiveError(w, err)
		return nil, nil, nil, false
	}
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, d.MachineID)
	if err != nil {
		writeDirectiveError(w, err)
		return nil, nil, nil, false
	}
	if err := p.Grant.RequireMachine(cap, m.GroupID); err != nil {
		// A caller outside the group learns nothing about the directive's existence.
		writeError(w, http.StatusNotFound, "unknown directive or machine")
		return nil, nil, nil, false
	}
	return p, d, m, true
}

// handleGetDirective is GET /directives/{id}.
func (s *Server) handleGetDirective(w http.ResponseWriter, r *http.Request) {
	_, d, _, ok := s.directiveForHuman(w, r, CapViewMachines)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"directive": d})
}

// handleListMachineDirectives is GET /machines/{id}/directives.
func (s *Server) handleListMachineDirectives(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	m, err := s.Machines.GetMachineByID(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		writeDirectiveError(w, err)
		return
	}
	if err := p.Grant.RequireMachine(CapViewMachines, m.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	ds, err := s.Directives.List(r.Context(), p.TenantID, m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list directives")
		return
	}
	if ds == nil {
		ds = []AgentDirective{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"directives": ds})
}

// directiveListItem is a directive plus the machine's display facts, so a tenant-wide view needs no second
// lookup. The embedded struct marshals flat: every AgentDirective field keeps its name.
type directiveListItem struct {
	AgentDirective
	MachineName   string `json:"machine_name"`
	MachineAlias  string `json:"machine_alias,omitempty"`
	MachineStatus string `json:"machine_status"`
}

const (
	directiveListDefaultLimit = 100
	directiveListMaxPages     = 10 // store pages scanned per request: bounds the work for a narrowly scoped caller
)

// handleListActiveDirectives is GET /directives?state=active[&limit=N][&before=<next_before>&before_id=<next_before_id>]: the tenant's
// ACTIVE directives (requested, issued, accepted, executing, reboot_pending, removal_unconfirmed) that this
// caller may act on. Each row is authorized against the machine's CURRENT group with the same check the
// request, approve and cancel routes use (RequireMachine(CapRemoveAgent)); a row the caller may not act on is
// simply absent. Newest first, bounded by `limit` (default 100, at most 200). When more may follow,
// `next_before` and `next_before_id` are the keyset cursor (requested_at, id) to pass back as `before` and
// `before_id` (both or neither, else 400); rows are ordered requested_at DESC, id ASC.
func (s *Server) handleListActiveDirectives(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapRemoveAgent); err != nil {
		writeDenied(w, err)
		return
	}
	q := r.URL.Query()
	if q.Get("state") != "active" {
		writeError(w, http.StatusBadRequest, "state must be active")
		return
	}
	limit := directiveListDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > directiveListLimit {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = n
	}
	// The keyset cursor is the pair (before, before_id): both or neither.
	var cursor time.Time
	var cursorID string
	if (q.Get("before") == "") != (q.Get("before_id") == "") {
		writeError(w, http.StatusBadRequest, "before and before_id must be given together")
		return
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be an RFC 3339 time")
			return
		}
		id, ok := parsePgUUID(q.Get("before_id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "before_id must be a UUID")
			return
		}
		cursor, cursorID = t, id
	}
	machines := map[string]*Machine{} // nil = unknown / not visible
	out := make([]directiveListItem, 0, limit)
	nextBefore, nextBeforeID := "", ""
scan:
	for page := 0; page < directiveListMaxPages; page++ {
		rows, err := s.Directives.ListActive(r.Context(), p.TenantID, cursor, cursorID, directiveListLimit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list directives")
			return
		}
		for _, d := range rows {
			m, seen := machines[d.MachineID]
			if !seen {
				got, merr := s.Machines.GetMachineByID(r.Context(), p.TenantID, d.MachineID)
				if merr != nil && !errors.Is(merr, ErrMachineNotFound) {
					writeError(w, http.StatusInternalServerError, "could not resolve machine")
					return
				}
				if merr == nil {
					m = got
				}
				machines[d.MachineID] = m
			}
			// The machine's CURRENT group, never the group recorded on the directive.
			if m == nil || p.Grant.RequireMachine(CapRemoveAgent, m.GroupID) != nil {
				continue
			}
			out = append(out, directiveListItem{AgentDirective: d, MachineName: m.Name, MachineAlias: m.Alias, MachineStatus: m.Status})
			if len(out) == limit {
				nextBefore, nextBeforeID = d.RequestedAt.UTC().Format(time.RFC3339Nano), d.ID
				break scan
			}
		}
		if len(rows) < directiveListLimit {
			break
		}
		last := rows[len(rows)-1]
		cursor, cursorID = last.RequestedAt, last.ID
		if page == directiveListMaxPages-1 {
			nextBefore, nextBeforeID = cursor.UTC().Format(time.RFC3339Nano), cursorID // scan budget spent: the caller may continue
		}
	}
	resp := map[string]any{"directives": out}
	if nextBefore != "" {
		resp["next_before"] = nextBefore
		resp["next_before_id"] = nextBeforeID
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleApproveDirective is POST /directives/{id}/approve.
func (s *Server) handleApproveDirective(w http.ResponseWriter, r *http.Request) {
	p, d, _, ok := s.directiveForHuman(w, r, CapRemoveAgent)
	if !ok {
		return
	}
	if !requireInteractive(w, p) {
		return
	}
	// The approver proves the second factor too: a stolen session alone must not be able to approve a
	// removal (the request side already needs it).
	actor, fresh, err := s.directiveStepUp(r.Context(), p, directiveStepUpMaxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the second factor")
		return
	}
	if !fresh {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "a recent second-factor verification is required", "code": "step_up_required"})
		return
	}
	got, err := s.Directives.Approve(r.Context(), p.TenantID, d.ID, actor)
	if err != nil {
		writeDirectiveError(w, err)
		return
	}
	// The window may already have passed (a slow approver): try to issue now rather than wait for the
	// sweeper. The store decides on ITS clock (database time); a too-early attempt changes nothing.
	if issued, ierr := s.issueDirective(r.Context(), p.TenantID, got.ID); issued != nil && ierr == nil {
		got = issued
	} else if ierr != nil && !errors.Is(ierr, ErrDirectiveTooEarly) {
		log.Printf("directive %s approved but issuance did not happen: %v", got.ID, ierr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"directive": got})
}

type directiveCancelBody struct {
	Reason string `json:"reason"`
}

// handleCancelDirective is POST /directives/{id}/cancel: the same scoped authorization as the request.
func (s *Server) handleCancelDirective(w http.ResponseWriter, r *http.Request) {
	p, d, _, ok := s.directiveForHuman(w, r, CapRemoveAgent)
	if !ok {
		return
	}
	if !requireInteractive(w, p) {
		return
	}
	var req directiveCancelBody
	if r.ContentLength != 0 {
		if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed cancel body"); err != nil {
			return
		}
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if utf8.RuneCountInString(req.Reason) > maxCancelReasonRunes {
		writeError(w, http.StatusBadRequest, "reason is too long")
		return
	}
	got, err := s.Directives.Cancel(r.Context(), p.TenantID, d.ID, p.UserID, req.Reason)
	if err != nil {
		writeDirectiveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"directive": got})
}

type directivePolicyBody struct {
	RequireSecondApprover bool `json:"require_second_approver"`
}

// handleGetDirectivePolicy is GET /tenant/directive-policy.
func (s *Server) handleGetDirectivePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapRemoveAgent); err != nil {
		writeDenied(w, err)
		return
	}
	pol, err := s.Directives.Policy(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the directive policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": pol})
}

// handleSetDirectivePolicy is PUT /tenant/directive-policy: Owner-only (CapRemoveAgent), interactive, and
// behind a fresh step-up (loosening it removes a protection).
func (s *Server) handleSetDirectivePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.directivesConfigured(w) {
		return
	}
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapRemoveAgent); err != nil {
		writeDenied(w, err)
		return
	}
	if !requireInteractive(w, p) {
		return
	}
	var req directivePolicyBody
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed policy body"); err != nil {
		return
	}
	fresh, err := s.stepUpFresh(r.Context(), p, directiveStepUpMaxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check the second factor")
		return
	}
	if !fresh {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "a recent second-factor verification is required", "code": "step_up_required"})
		return
	}
	pol, err := s.Directives.SetPolicy(r.Context(), p.TenantID, p.UserID, req.RequireSecondApprover)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the directive policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": pol})
}

// -------------------------------------------------------------------------------------
// Issuance, notification and the sweeper
// -------------------------------------------------------------------------------------

// issueDirective runs the atomic issuance and, on success, tells signaling (after commit, best effort: the
// sweeper renotifies an undelivered directive and signaling fetches pending on every registration).
func (s *Server) issueDirective(ctx context.Context, tenantID, id string) (*AgentDirective, error) {
	d, err := s.Directives.Issue(ctx, tenantID, id, DirectiveIssueDeps{
		Authority: s.directiveAuthority(tenantID), Issuer: s.DirectiveIssuer})
	if err == nil && d != nil {
		s.notifyDirective(d.DeviceID)
	}
	return d, err
}

func (s *Server) notifyDirective(deviceID string) {
	n := s.DirectiveNotifier
	if n == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := n.Notify(ctx, deviceID); err != nil {
			log.Printf("directive notification for device %q failed (it will be retried by the sweeper): %v", clipLog(deviceID), err)
		}
	}()
}

func clipLog(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// SweepDirectivesOnce does one pass of the background work: issue what is due (the cancel window ended),
// expire what lapsed, conclude what never reported, renotify what was never delivered. Every action
// re-checks its condition under lock in the store, so overlapping sweepers and replicas are harmless.
func (s *Server) SweepDirectivesOnce(ctx context.Context) (int, error) {
	if s.Directives == nil {
		return 0, nil
	}
	items, err := s.Directives.SweepCandidates(ctx, 100)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		var aerr error
		switch it.Action {
		case "issue":
			_, aerr = s.issueDirective(ctx, it.TenantID, it.DirectiveID)
			if errors.Is(aerr, ErrDirectiveNeedsApproval) || errors.Is(aerr, ErrDirectiveTooEarly) ||
				errors.Is(aerr, ErrDirectiveNotIssuable) || errors.Is(aerr, ErrDirectiveTenantSuspended) {
				aerr = nil // waiting, or someone else decided: not an error, not progress
				continue
			}
			var refused *DirectiveRefusedError
			if errors.As(aerr, &refused) || errors.Is(aerr, ErrDirectiveExpired) {
				aerr = nil // the refusal is the recorded outcome
			}
		case "expire":
			_, aerr = s.Directives.Expire(ctx, it.TenantID, it.DirectiveID)
		case "unconfirmed":
			_, aerr = s.Directives.MarkUnconfirmed(ctx, it.TenantID, it.DirectiveID)
		case "renotify":
			if d, gerr := s.Directives.Get(ctx, it.TenantID, it.DirectiveID); gerr == nil {
				s.notifyDirective(d.DeviceID)
			}
		}
		if aerr != nil {
			log.Printf("directive sweep: %s %s: %v", it.Action, it.DirectiveID, aerr)
			continue
		}
		n++
	}
	return n, nil
}

// RunDirectiveSweeper sweeps every interval until ctx ends.
func (s *Server) RunDirectiveSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.SweepDirectivesOnce(ctx); err != nil {
			log.Printf("directive sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// -------------------------------------------------------------------------------------
// Internal routes for signaling (service token)
// -------------------------------------------------------------------------------------

const maxInternalDirectiveBody = 1 << 14

// internalDirectiveAuth meters and authenticates a signaling call. A wrong token is a failure that backs the
// source off (someone guessing the secret); an ordinary 404 is not (the caller proved it holds the token).
func (s *Server) internalDirectiveAuth(w http.ResponseWriter, r *http.Request) bool {
	th := s.throttle()
	keys := []string{ipKey("directive-internal", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return false
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	th.Reset(keys...)
	return true
}

// directiveDevice resolves the authenticated device's tenant and CURRENT pinned key. A retired device
// resolves (restricted mode is exactly for it); a removed or unknown one does not.
func (s *Server) directiveDevice(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	return s.Machines.LookupDeviceIdentity(ctx, deviceID)
}

type pendingDirectiveWire struct {
	DirectiveID string `json:"directive_id"`
	Artifact    string `json:"artifact"`
}

// handleInternalDirectivesPending is GET /internal/devices/{device_id}/directives/pending.
func (s *Server) handleInternalDirectivesPending(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	id, err := s.directiveDevice(r.Context(), r.PathValue("device_id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve device identity")
		return
	}
	fp, err := KeyFingerprint(id.Pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown device")
		return
	}
	ds, err := s.Directives.PendingForDevice(r.Context(), id.TenantID, id.DeviceID, fp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read pending directives")
		return
	}
	out := make([]pendingDirectiveWire, 0, len(ds))
	for _, d := range ds {
		if d.Artifact != "" {
			out = append(out, pendingDirectiveWire{DirectiveID: d.ID, Artifact: d.Artifact})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"directives": out})
}

type directiveDeliveredBody struct {
	DeviceID string `json:"device_id"`
}

func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInternalDirectiveBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

// handleInternalDirectiveDelivered is POST /internal/directives/{id}/delivered.
func (s *Server) handleInternalDirectiveDelivered(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	var body directiveDeliveredBody
	if !decodeStrict(w, r, &body) {
		return
	}
	id, err := s.directiveDevice(r.Context(), body.DeviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve device identity")
		return
	}
	if err := s.Directives.MarkDelivered(r.Context(), id.TenantID, r.PathValue("id"), id.DeviceID); err != nil {
		writeDirectiveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

type directiveAckBody struct {
	DeviceID string `json:"device_id"`
	From     string `json:"from"`
	To       string `json:"to"`
	TsMs     int64  `json:"ts_ms"`
	Detail   string `json:"detail"`
	Sig      string `json:"sig"`
}

// handleInternalDirectiveAck is POST /internal/directives/{id}/ack (D-C8). Signaling forwards the agent's
// acknowledgement verbatim with the AUTHENTICATED device id. Here: the device's tenant and current key come
// from the identity store, the directive from the stored row (which must belong to that device), the
// signature is verified over the ROW's tenant/device/key-fingerprint/directive id plus the claimed
// transition, and the transition is validated against the stored state.
func (s *Server) handleInternalDirectiveAck(w http.ResponseWriter, r *http.Request) {
	if !s.internalDirectiveAuth(w, r) {
		return
	}
	var body directiveAckBody
	if !decodeStrict(w, r, &body) {
		return
	}
	dirID := r.PathValue("id")
	if validateDirectiveID(dirID) != nil || len(body.Detail) > maxDirectiveDetailBytes || len(body.From) > 32 || len(body.To) > 32 {
		writeError(w, http.StatusBadRequest, "malformed acknowledgement")
		return
	}
	id, err := s.directiveDevice(r.Context(), body.DeviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve device identity")
		return
	}
	d, err := s.Directives.Get(r.Context(), id.TenantID, dirID)
	if err != nil || d.DeviceID != id.DeviceID {
		writeError(w, http.StatusNotFound, "unknown directive")
		return
	}
	ack := DirectiveAck{DirectiveID: d.ID, From: body.From, To: body.To, TsMs: body.TsMs, Detail: body.Detail, Sig: body.Sig}
	if err := verifyDirectiveAckFor(d, id.Pubkey, ack); err != nil {
		if errors.Is(err, ErrDirectiveKeyChanged) {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusForbidden, err.Error())
		}
		return
	}
	got, applied, err := s.Directives.ApplyAck(r.Context(), id.TenantID, d.ID, id.DeviceID, ack)
	if err != nil {
		switch {
		case errors.Is(err, ErrDirectiveBadTransition), errors.Is(err, ErrDirectiveKeyChanged), errors.Is(err, ErrDirectiveBadTimestamp),
			errors.Is(err, ErrDirectiveStaleAck), errors.Is(err, ErrDirectiveExpired):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeDirectiveError(w, err)
		}
		return
	}
	outcome := "replay"
	if applied {
		outcome = "applied"
	}
	writeJSON(w, http.StatusOK, map[string]string{"outcome": outcome, "state": string(got.State)})
}

// directiveInternalMounted reports whether the internal directive routes (and the capability) exist.
func (s *Server) directiveInternalMounted() bool {
	return s.Directives != nil && s.DirectiveIssuer != nil && s.Machines != nil
}

// HTTPDirectiveNotifier is the DirectiveNotifier that POSTs signaling's internal notification route.
type HTTPDirectiveNotifier struct {
	BaseURL string // e.g. http://signaling:8080
	Token   string // the shared service token (SIGNALING_DEVICE_IDENTITY_TOKEN)
	Client  *http.Client
}

var _ DirectiveNotifier = (*HTTPDirectiveNotifier)(nil)

func (n *HTTPDirectiveNotifier) Notify(ctx context.Context, deviceID string) error {
	if n == nil || n.BaseURL == "" || n.Token == "" {
		return errors.New("directive notifier is not configured")
	}
	c := n.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(n.BaseURL, "/")+"/internal/devices/"+url.PathEscape(deviceID)+"/directive-pending", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return errors.New("signaling answered " + resp.Status)
	}
	return nil
}
