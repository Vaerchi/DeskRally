package controlplane

// /platform/* — the platform operator's console API (migration 0055, platform.go). The handlers add
// only what the database cannot: an interactive session is required (API tokens have no SessionID and
// are refused here and again by the DB check), request bodies are bounded and validated, and the
// suspend confirmation must name the target's slug. Whether the caller is an operator, and whether its
// session's second factor is fresh enough, is decided by cp_platform_check; a denial is a plain 403
// that says nothing about which condition failed.

import (
	"errors"
	"net/http"
	"strings"
)

func (s *Server) platformCaller(r *http.Request) (PlatformCaller, bool) {
	p := principalFrom(r.Context())
	if p == nil || p.SessionID == "" {
		return PlatformCaller{}, false
	}
	c := PlatformCaller{UserID: p.UserID, TenantID: p.TenantID, SessionID: p.SessionID}
	if s.AuthAPI != nil && s.AuthAPI.Users != nil {
		if u, err := s.AuthAPI.Users.FindUserByID(r.Context(), p.TenantID, p.UserID); err == nil && u != nil {
			c.Email = u.Email
		}
	}
	return c, true
}

func writePlatformErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPlatformDenied):
		writeError(w, http.StatusForbidden, "platform operator access denied")
	case errors.Is(err, ErrPlatformNoTenant):
		writeError(w, http.StatusNotFound, "no such tenant")
	case errors.Is(err, ErrTenantSlugTaken):
		writeError(w, http.StatusConflict, "tenant slug already in use")
	default:
		writeError(w, http.StatusInternalServerError, "platform operation failed")
	}
}

// GET /platform/me — for the console: show the Platform area, and whether to ask for a step-up.
// Any authenticated caller; reveals only facts about the caller.
func (s *Server) handlePlatformMe(w http.ResponseWriter, r *http.Request) {
	c, ok := s.platformCaller(r)
	if !ok || s.Platform == nil {
		writeJSON(w, http.StatusOK, PlatformWhoami{})
		return
	}
	who, err := s.Platform.Whoami(r.Context(), c)
	if err != nil {
		writeJSON(w, http.StatusOK, PlatformWhoami{})
		return
	}
	writeJSON(w, http.StatusOK, who)
}

func (s *Server) handlePlatformListTenants(w http.ResponseWriter, r *http.Request) {
	c, ok := s.platformCaller(r)
	if !ok || s.Platform == nil {
		writeError(w, http.StatusForbidden, "platform operator access denied")
		return
	}
	list, err := s.Platform.ListTenants(r.Context(), c)
	if err != nil {
		writePlatformErr(w, err)
		return
	}
	if list == nil {
		list = []PlatformTenant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": list})
}

type platformCreateRequest struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	DeploymentMode string `json:"deployment_mode"`
}

func (s *Server) handlePlatformCreateTenant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.platformCaller(r)
	if !ok || s.Platform == nil {
		writeError(w, http.StatusForbidden, "platform operator access denied")
		return
	}
	var req platformCreateRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed create-tenant request body"); err != nil {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 {
		writeError(w, http.StatusBadRequest, "name is required (at most 200 characters)")
		return
	}
	if !ValidTenantSlug(req.Slug) {
		writeError(w, http.StatusBadRequest,
			"slug must be 1-63 lowercase letters, digits or hyphens, start and end with a letter or digit, and not be a reserved name")
		return
	}
	mode := req.DeploymentMode
	if mode == "" {
		mode = "saas"
	}
	if !ValidDeploymentMode(mode) {
		writeError(w, http.StatusBadRequest, "deployment_mode must be \"saas\" or \"self_hosted\"")
		return
	}
	t, err := s.Platform.CreateTenant(r.Context(), c, req.Slug, req.Name, mode, newUUID())
	if err != nil {
		writePlatformErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tenant": t})
}

type platformSuspendRequest struct {
	ConfirmSlug string `json:"confirm_slug"`
	Reason      string `json:"reason"`
}

func (s *Server) handlePlatformSetSuspended(suspended bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.platformCaller(r)
		if !ok || s.Platform == nil {
			writeError(w, http.StatusForbidden, "platform operator access denied")
			return
		}
		id := r.PathValue("id")
		if !isUUID(id) {
			writeError(w, http.StatusNotFound, "no such tenant")
			return
		}
		var req platformSuspendRequest
		if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
			return
		}
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Reason == "" || len(req.Reason) > 500 {
			writeError(w, http.StatusBadRequest, "a reason is required (at most 500 characters)")
			return
		}
		// The typed slug must match the target (checked against the DB's own row below, in the same
		// listing the operator sees), so a mis-click on the wrong row cannot suspend a customer.
		list, err := s.Platform.ListTenants(r.Context(), c)
		if err != nil {
			writePlatformErr(w, err)
			return
		}
		var slug string
		for _, t := range list {
			if strings.EqualFold(t.ID, id) {
				slug = t.Slug
			}
		}
		if slug == "" {
			writeError(w, http.StatusNotFound, "no such tenant")
			return
		}
		if req.ConfirmSlug != slug {
			writeError(w, http.StatusBadRequest, "confirm_slug does not match the tenant")
			return
		}
		t, err := s.Platform.SetSuspended(r.Context(), c, id, suspended, req.Reason, newUUID())
		if err != nil {
			writePlatformErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenant": t})
	}
}
