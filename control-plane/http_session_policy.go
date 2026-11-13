package controlplane

// Per-tenant session-policy handlers (docs/01 §5 seat metering): GET /tenant/session-policy (any
// authenticated member reads the concurrency limit — e.g. to display it) and PUT /tenant/session-policy
// (CapManageTenant sets it). Both are tenant-scoped by the pinned tenant + RLS. Enforcement of the
// limit is NOT here — it is at POST /sessions (handleStartSession), atomically.

import (
	"net/http"
)

func (s *Server) handleGetSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// No capability check: the concurrency limit is not sensitive and a member may want to see it
	// (e.g. to understand a "limit reached" refusal). It stays tenant-scoped (the pinned tenant + RLS).
	if s.SessionPolicies == nil {
		writeError(w, http.StatusInternalServerError, "session policy store not configured")
		return
	}
	pol, err := s.SessionPolicies.Get(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read session policy")
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) handleSetSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.SessionPolicies == nil {
		writeError(w, http.StatusInternalServerError, "session policy store not configured")
		return
	}
	var req SessionPolicy
	// docs/25 F05: two integers. The CapManageTenant gate above already precedes the decode, so this
	// bounds what an authorized Owner can make the handler buffer against the pinned connection.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed session policy body"); err != nil {
		return
	}
	if req.MaxConcurrentSessions > 0 && req.MaxSessionSeconds == 0 {
		writeError(w, http.StatusBadRequest, "a concurrency limit requires max_session_seconds so abandoned sessions expire")
		return
	}
	norm, ok := NormalizeSessionPolicy(req)
	if !ok {
		writeError(w, http.StatusBadRequest,
			"invalid session policy: max_concurrent_sessions must be 0 (unlimited) to 100000, and "+
				"max_session_seconds must be 0 (no maximum) or between 60 and 2592000")
		return
	}
	if err := s.SessionPolicies.Set(r.Context(), p.TenantID, norm); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save session policy")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.session_policy.set", "tenant", p.TenantID,
		map[string]any{"max_concurrent_sessions": norm.MaxConcurrentSessions, "max_session_seconds": norm.MaxSessionSeconds}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Echo the normalized value the server stored, so the console adopts exactly that.
	writeJSON(w, http.StatusOK, norm)
}
