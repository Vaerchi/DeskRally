package controlplane

// Tenant security-policy handlers (docs/01 §10 "TOTP 2FA — enforcement policy").
//
// GET /tenant/security-policy — no cap check; any authenticated member reads the policy to
//   understand whether 2FA is required on their tenant before they attempt enrollment.
// PUT /tenant/security-policy — CapManageTenant; sets require_2fa.
//
// Anti-lockout invariant on PUT: a caller may only set require_2fa = true when they
// themselves have a confirmed TOTP enrollment. This prevents an Owner from enabling the
// policy and immediately losing access because they forgot to enroll first. The check reads
// the SAME AuthUser the session authenticator loaded for this request (FindUserByID), which
// is the same row as the one the login flow checks — no possibility of disagreement.

import (
	"net/http"
)

func (s *Server) handleGetTenantSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// No capability check: the policy is not sensitive (it's just a bool), and every member
	// needs to know whether they must enroll 2FA before their next login attempt.
	if s.Tenants == nil {
		writeError(w, http.StatusInternalServerError, "tenant store not configured")
		return
	}
	policy, err := s.Tenants.GetSecurityPolicy(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read security policy")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) handleSetTenantSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Tenants == nil {
		writeError(w, http.StatusInternalServerError, "tenant store not configured")
		return
	}
	var req TenantSecurityPolicy
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed security policy body"); err != nil {
		return
	}

	// Anti-lockout: an Owner who enables require_2fa must themselves have a confirmed TOTP
	// enrollment. Without this guard, one request could lock every tenant member (including
	// the caller) out of the console until someone enrolls via a separate recovery path.
	// Fail CLOSED when AuthAPI is nil: skip the guard and write the policy would silently
	// lock every unenrolled member out on next login.
	if req.Require2FA {
		if s.AuthAPI == nil {
			writeError(w, http.StatusInternalServerError, "authentication service not available")
			return
		}
		caller, err := s.AuthAPI.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
		if err != nil || !caller.TOTPConfirmed {
			writeError(w, http.StatusBadRequest,
				"you must have TOTP enrolled before enabling the 2FA requirement (anti-lockout)")
			return
		}
	}

	if err := s.Tenants.SetRequire2FA(r.Context(), p.TenantID, req.Require2FA); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save security policy")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.security_policy.set", "tenant", p.TenantID,
		map[string]any{"require_2fa": req.Require2FA}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, req)
}
