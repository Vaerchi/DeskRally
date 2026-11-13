package controlplane

// /toolbox — Shared Toolbox v1 (docs/design-shared-toolbox.md). Personal items and run requests
// require CapStartSession; SHARED items are managed with CapManageToolbox ALONE (a custom role may hold
// either); listing needs either one. A
// personal item is visible only to its owner: another user gets 404 for it on every route, whatever
// version they send (no existence oracle).
//
// A run is a REQUEST: the control plane authorizes it against the held session exactly as a lease
// renewal would be authorized (checkHeldSession), records toolbox.run_requested with outcome
// "unknown" and only then returns the command; it cannot know whether the browser sends it or what
// the agent does, and the browser could type the same command into the command bar.

import (
	"errors"
	"net/http"
	"strconv"
)

type toolboxItemRequest struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	Scope           string `json:"scope"` // create only: "shared" | "personal"
	Shell           string `json:"shell"`
	RunAs           string `json:"run_as"`
	Body            string `json:"body"`
	ExpectedVersion int64  `json:"expected_version"` // update only
}

func (req *toolboxItemRequest) fields() ToolboxFields {
	return ToolboxFields{Name: req.Name, Description: req.Description, Shell: req.Shell, RunAs: req.RunAs, Body: req.Body}
}

type toolboxRunBody struct {
	SessionID       string `json:"session_id"`
	ExpectedVersion int64  `json:"expected_version"`
}

// toolboxItemView is an item as the console sees it.
type toolboxItemView struct {
	ToolboxItem
	Scope string `json:"scope"`
	Mine  bool   `json:"mine"`
}

func toolboxView(it ToolboxItem, callerID string) toolboxItemView {
	return toolboxItemView{ToolboxItem: it, Scope: it.Scope(), Mine: it.Owner != nil && sameUserID(*it.Owner, callerID)}
}

func writeToolboxErr(w http.ResponseWriter, err error) {
	var verr *ToolboxValidationError
	switch {
	case errors.As(err, &verr):
		writeError(w, http.StatusBadRequest, verr.Msg)
	case errors.Is(err, ErrToolboxNotFound):
		writeError(w, http.StatusNotFound, "no such toolbox item")
	case errors.Is(err, ErrToolboxVersion):
		writeError(w, http.StatusConflict, "this item was changed since you loaded it; reload and try again")
	case errors.Is(err, ErrToolboxNameTaken):
		writeError(w, http.StatusConflict, ErrToolboxNameTaken.Error())
	case errors.Is(err, ErrToolboxSharedDenied):
		writeError(w, http.StatusForbidden, ErrToolboxSharedDenied.Error())
	case errors.Is(err, ErrToolboxPersonalDenied):
		writeError(w, http.StatusForbidden, ErrToolboxPersonalDenied.Error())
	default:
		writeError(w, http.StatusInternalServerError, "toolbox operation failed")
	}
}

// toolboxCaller returns the principal when the toolbox is mounted and the caller holds at least one
// of `caps` (each route names exactly the capabilities that can serve it).
func (s *Server) toolboxCaller(w http.ResponseWriter, r *http.Request, caps ...Capability) (*Principal, bool) {
	p := principalFrom(r.Context())
	if s.Toolbox == nil {
		writeError(w, http.StatusNotImplemented, "the toolbox is not available on this server")
		return nil, false
	}
	// Interactive sign-ins only. An API token's principal carries the TOKEN's id as UserID, which is
	// no app_user: it could own no personal item, hold no session, and must not manage shared scripts.
	if p.SessionID == "" {
		writeError(w, http.StatusForbidden, "the toolbox requires an interactive sign-in (API tokens cannot use it)")
		return nil, false
	}
	if err := p.Grant.RequireAny(caps...); err != nil {
		writeDenied(w, err)
		return nil, false
	}
	return p, true
}

func toolboxPerms(p *Principal) ToolboxPerms {
	return ToolboxPerms{ManageShared: p.Grant.Allows(CapManageToolbox), UsePersonal: p.Grant.Allows(CapStartSession)}
}

func (s *Server) dispatchToolboxEvent(tenantID string, ev *MgmtAuditEvent) {
	if ev != nil && s.Dispatcher != nil {
		s.Dispatcher.Dispatch(tenantID, ev)
	}
}

func (s *Server) handleListToolbox(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession, CapManageToolbox)
	if !ok {
		return
	}
	items, err := s.Toolbox.List(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	views := make([]toolboxItemView, 0, len(items))
	for _, it := range items {
		views = append(views, toolboxView(it, p.UserID))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":                views,
		"can_manage_shared":    p.Grant.Allows(CapManageToolbox),
		"max_powershell_bytes": MaxToolboxPowerShellBytes,
		"max_cmd_units":        MaxToolboxCmdUnits,
	})
}

func (s *Server) handleCreateToolboxItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession, CapManageToolbox)
	if !ok {
		return
	}
	var req toolboxItemRequest
	if err := decodeStrictJSONBody(w, r, maxToolboxRequestBytes, &req, "malformed toolbox item"); err != nil {
		return
	}
	var personal bool
	switch req.Scope {
	case "personal":
		if err := p.Grant.Require(CapStartSession); err != nil {
			writeDenied(w, err)
			return
		}
		personal = true
	case "shared":
		if err := p.Grant.Require(CapManageToolbox); err != nil {
			writeDenied(w, err)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, `scope must be "shared" or "personal"`)
		return
	}
	it, ev, err := s.Toolbox.Create(r.Context(), p.TenantID, p.UserID, personal, req.fields(), newUUID())
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	s.dispatchToolboxEvent(p.TenantID, ev)
	writeJSON(w, http.StatusCreated, map[string]any{"item": toolboxView(*it, p.UserID)})
}

func (s *Server) handleUpdateToolboxItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession, CapManageToolbox)
	if !ok {
		return
	}
	var req toolboxItemRequest
	if err := decodeStrictJSONBody(w, r, maxToolboxRequestBytes, &req, "malformed toolbox item"); err != nil {
		return
	}
	if req.Scope != "" {
		writeError(w, http.StatusBadRequest, "an item's scope cannot be changed; create a copy instead")
		return
	}
	if req.ExpectedVersion < 1 {
		writeError(w, http.StatusBadRequest, "expected_version is required")
		return
	}
	it, ev, err := s.Toolbox.Update(r.Context(), p.TenantID, p.UserID, toolboxPerms(p),
		r.PathValue("id"), req.ExpectedVersion, req.fields())
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	s.dispatchToolboxEvent(p.TenantID, ev)
	writeJSON(w, http.StatusOK, map[string]any{"item": toolboxView(*it, p.UserID)})
}

func (s *Server) handleDeleteToolboxItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession, CapManageToolbox)
	if !ok {
		return
	}
	v, err := strconv.ParseInt(r.URL.Query().Get("expected_version"), 10, 64)
	if err != nil || v < 1 {
		writeError(w, http.StatusBadRequest, "expected_version is required")
		return
	}
	ev, err := s.Toolbox.Delete(r.Context(), p.TenantID, p.UserID, toolboxPerms(p), r.PathValue("id"), v)
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	s.dispatchToolboxEvent(p.TenantID, ev)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRunToolboxItem(w http.ResponseWriter, r *http.Request) {
	p, ok := s.toolboxCaller(w, r, CapStartSession)
	if !ok {
		return
	}
	var req toolboxRunBody
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed run request"); err != nil {
		return
	}
	if req.ExpectedVersion < 1 || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id and expected_version are required")
		return
	}
	// The item first (404 for anything the caller cannot see, before any session detail is revealed),
	// then the session exactly as a lease renewal would authorize it. Nothing is minted or extended.
	if _, err := s.Toolbox.Get(r.Context(), p.TenantID, p.UserID, r.PathValue("id")); err != nil {
		writeToolboxErr(w, err)
		return
	}
	held, refusal := s.checkHeldSession(r.Context(), p, req.SessionID, "run a toolbox item")
	if refusal != nil {
		refusal.write(w)
		return
	}
	// A cleared group mandate must never make an observer's held record actuating.
	if held.Rec.Access == "view_only" {
		writeError(w, http.StatusForbidden, "this session is an observer; toolbox commands cannot run")
		return
	}
	if held.Access == SessionAccessViewOnly {
		writeError(w, http.StatusConflict, "this session is view-only; commands cannot run")
		return
	}
	run, ev, err := s.Toolbox.RecordRun(r.Context(), p.TenantID, p.UserID, r.PathValue("id"), req.ExpectedVersion,
		held.Rec.ID, held.Rec.MachineID, newUUID())
	if err != nil {
		writeToolboxErr(w, err)
		return
	}
	// The audit has committed; only now is the command handed out.
	s.dispatchToolboxEvent(p.TenantID, ev)
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": run.RequestID,
		"shell":      run.Item.Shell,
		"run_as":     run.Item.RunAs,
		"command":    run.Command,
		"item":       toolboxView(run.Item, p.UserID),
	})
}
