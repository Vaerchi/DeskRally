package controlplane

// /platform hostname routes (docs/66 stage 1a): a platform operator assigns, activates, releases and
// reactivates a tenant's public hostname. Authorization (an interactive session, a configured operator, a
// fresh second factor) is the database's, exactly as for suspend; the handlers add request validation, the
// label vetting of hostlabel.go, and the override acknowledgement. Both audit chains are written by the store
// in the same transaction as the change.

import (
	"errors"
	"net/http"
	"strings"
)

func writeHostnameErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPlatformDenied):
		writeError(w, http.StatusForbidden, "platform operator access denied")
	case errors.Is(err, ErrPlatformNoTenant):
		writeError(w, http.StatusNotFound, "no such tenant")
	case errors.Is(err, ErrHostnameNotFound):
		writeError(w, http.StatusNotFound, "no such hostname assignment")
	case errors.Is(err, ErrHostnameTaken):
		writeError(w, http.StatusConflict, "hostname or tenant already has a live assignment")
	case errors.Is(err, ErrHostnameQuarantined):
		writeError(w, http.StatusConflict, "hostname is quarantined after a release by another tenant")
	case errors.Is(err, ErrHostnameState):
		writeError(w, http.StatusConflict, "assignment is not in a valid state for this operation")
	case errors.Is(err, ErrHostnameInvalid):
		writeError(w, http.StatusBadRequest, "invalid hostname request")
	case errors.Is(err, ErrHostnameBusy):
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "hostname assignment is busy; retry")
	default:
		writeError(w, http.StatusInternalServerError, "hostname operation failed")
	}
}

func (s *Server) hostnameCaller(w http.ResponseWriter, r *http.Request) (PlatformCaller, bool) {
	c, ok := s.platformCaller(r)
	if !ok || s.Hostnames == nil {
		writeError(w, http.StatusForbidden, "platform operator access denied")
		return PlatformCaller{}, false
	}
	return c, true
}

// GET /platform/hostnames and GET /platform/tenants/{id}/hostnames.
func (s *Server) handlePlatformHostnames(w http.ResponseWriter, r *http.Request) {
	c, ok := s.hostnameCaller(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	if tenantID != "" && !isUUID(tenantID) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	list, err := s.Hostnames.List(r.Context(), c, tenantID)
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	if list == nil {
		list = []HostnameAssignment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostnames": list})
}

type hostnameAssignRequest struct {
	Host           string   `json:"host"`
	Acknowledge    []string `json:"acknowledge"`
	OverrideReason string   `json:"override_reason"`
}

// POST /platform/tenants/{id}/hostnames {host, acknowledge[], override_reason}: creates a PENDING assignment.
// The host must be <label><CP_TENANT_HOST_SUFFIX>. Hard refusals (shape, reserved, short, a default or legacy
// host) are 400. Lookalike warnings (IDN, skeleton collision, denylisted brand) are 409 with the findings
// listed, until the operator acknowledges EVERY listed code and gives a reason; the override is recorded on
// both audit chains.
func (s *Server) handlePlatformHostnameAssign(w http.ResponseWriter, r *http.Request) {
	c, ok := s.hostnameCaller(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	if !isUUID(tenantID) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	var req hostnameAssignRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed hostname request body"); err != nil {
		return
	}
	host, hok := NormalizeAuthority(strings.TrimSpace(req.Host))
	suffix := s.TenantHostSuffix
	if !hok || suffix == "" || !strings.HasSuffix(host, suffix) {
		writeError(w, http.StatusBadRequest, "host must be <label>"+suffix+" (tenant host suffix must be configured)")
		return
	}
	label := strings.TrimSuffix(host, suffix)
	if strings.Contains(label, ".") {
		writeError(w, http.StatusBadRequest, "host must be a single label under "+suffix)
		return
	}
	lctx := HostLabelContext{}
	if s.HostPolicy != nil {
		if s.HostPolicy.IsReservedHost(host) {
			writeError(w, http.StatusBadRequest, "that host is a default or legacy host and cannot be assigned")
			return
		}
		for _, rh := range s.HostPolicy.ReservedHosts() {
			if strings.HasSuffix(rh, suffix) {
				lctx.ReservedLabels = append(lctx.ReservedLabels, strings.TrimSuffix(rh, suffix))
			}
		}
	}
	// Skeleton collisions are judged against every assignment this operator can see, released/quarantined
	// included (a look-alike of a quarantined name is still a look-alike).
	all, err := s.Hostnames.List(r.Context(), c, "")
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	for _, a := range all {
		if strings.HasSuffix(a.Host, suffix) {
			lctx.ExistingLabels = append(lctx.ExistingLabels, strings.TrimSuffix(a.Host, suffix))
		}
	}
	refusals, warnings := CheckHostLabel(label, lctx)
	if len(refusals) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": refusals[0], "refusals": refusals})
		return
	}
	extra := map[string]any{}
	if len(warnings) > 0 {
		acked := map[string]bool{}
		for _, a := range req.Acknowledge {
			acked[a] = true
		}
		reason := strings.TrimSpace(req.OverrideReason)
		for _, wf := range warnings {
			if !acked[wf.Code] || reason == "" || len(reason) > 500 {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":    "label has lookalike warnings; acknowledge every code and give a reason (at most 500 characters)",
					"warnings": warnings,
				})
				return
			}
		}
		codes := make([]string, 0, len(warnings))
		for _, wf := range warnings {
			codes = append(codes, wf.Code)
		}
		extra["override_codes"] = codes
		extra["override_reason"] = reason
	}
	a, err := s.Hostnames.Assign(r.Context(), c, tenantID, host, extra)
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"hostname": a})
}

// POST /platform/hostnames/{id}/activate: pending -> active, keeping the id.
func (s *Server) handlePlatformHostnameActivate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.hostnameCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		writeError(w, http.StatusNotFound, "no such hostname assignment")
		return
	}
	a, err := s.Hostnames.Activate(r.Context(), c, id, nil)
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostname": a})
}

type hostnameReleaseRequest struct {
	Reason         string `json:"reason"`
	QuarantineDays int    `json:"quarantine_days"`
}

// POST /platform/hostnames/{id}/release {reason, quarantine_days?}: terminal for the row; quarantine at
// least 30 days (the default).
func (s *Server) handlePlatformHostnameRelease(w http.ResponseWriter, r *http.Request) {
	c, ok := s.hostnameCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		writeError(w, http.StatusNotFound, "no such hostname assignment")
		return
	}
	var req hostnameReleaseRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed release request body"); err != nil {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "a reason is required (at most 500 characters)")
		return
	}
	days := req.QuarantineDays
	if days == 0 {
		days = HostnameQuarantineDays
	}
	if days < HostnameQuarantineDays || days > 3650 {
		writeError(w, http.StatusBadRequest, "quarantine_days must be between 30 and 3650")
		return
	}
	a, err := s.Hostnames.Release(r.Context(), c, id, days, map[string]any{"reason": req.Reason, "quarantine_days": days})
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostname": a})
}

type hostnameReactivateRequest struct {
	Activate bool `json:"activate"`
}

// POST /platform/hostnames/{id}/reactivate {activate?}: a NEW assignment (new id) for the released row's host
// and tenant; any earlier branding approval no longer matches it.
func (s *Server) handlePlatformHostnameReactivate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.hostnameCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		writeError(w, http.StatusNotFound, "no such hostname assignment")
		return
	}
	var req hostnameReactivateRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed reactivate request body"); err != nil {
		return
	}
	a, err := s.Hostnames.Reactivate(r.Context(), c, id, req.Activate, map[string]any{"activate": req.Activate})
	if err != nil {
		writeHostnameErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"hostname": a})
}
