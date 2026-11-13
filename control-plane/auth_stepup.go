package controlplane

// POST /auth/step-up — prove the second factor again inside an existing session (platform-operator
// design v3). Operations gated on a recent MFA verification (platform lifecycle changes: 15 minutes)
// ask the console for a step-up instead of a full re-login.
//
// The code is checked exactly as at login: the same account-wide TOTP throttle key (so step-up
// cannot be used to brute-force the factor around the login budget), the same replay protection
// (ConsumeTOTPStep), and the session is marked only for the generation read together with the
// secret, conditionally (MarkMFAVerified): a re-enrollment committed in between leaves it unmarked.
// The session's absolute expiry is never extended. Interactive sessions only: an API token has no
// session to mark.
//
// A wrong, missing or replayed code is 403, not 401: the SESSION is authenticated, only this extra
// proof failed, and the console treats any 401 on a protected route as an expired sign-in and signs
// the operator out (web/viewer/src/lib/auth_session.ts). 401 is kept for a session whose user no
// longer resolves.

import (
	"net/http"
	"strings"
)

type stepUpRequest struct {
	Code string `json:"code"`
}

// HandleMe is the protected GET /me: the signed-in user's own email, for the console header.
func (s *AuthService) HandleMe(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		return
	}
	user, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		return
	}
	// docs/56/57: say when (or that) this user's access ended, or that it is outside its hours, so the
	// console can explain an empty, all-403 console. From the store's access summary: evaluated by the
	// store at ONE instant (pg: the same SQL as ListUsers), never recomputed on the app clock here.
	sum, err := s.Users.AccessSummary(r.Context(), p.TenantID, p.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve access")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"email":                 user.Email,
		"user_id":               p.UserID,
		"capabilities":          meCapabilities(p.Grant),
		"access_expires_at":     expiryJSON(sum.AccessExpiresAt),
		"access_expired":        sum.AccessExpired,
		"access_window":         windowJSON(sum.AccessWindow),
		"access_window_varies":  sum.AccessWindowVaries,
		"access_outside_window": sum.AccessOutsideWindow,
	})
}

// meCapability is one capability the caller holds and WHERE (GET /me). A console decides per machine whether
// to offer an action by asking the same question the server asks: all_groups, or the machine's CURRENT group
// is in group_ids (assigned groups plus their descendants, i.e. exactly Grant.AllowsInGroup's coverage).
type meCapability struct {
	Capability string   `json:"capability"`
	AllGroups  bool     `json:"all_groups"`
	GroupIDs   []string `json:"group_ids"` // empty when all_groups
}

// meCapabilities lists every capability the grant holds with its group coverage, in AllCapabilities order.
// It is informational (the console hides controls with it); every route still authorizes for itself.
func meCapabilities(g *Grant) []meCapability {
	out := []meCapability{}
	if g == nil {
		return out
	}
	for _, c := range AllCapabilities {
		scope, ok := g.ScopeFor(c)
		if !ok {
			continue
		}
		ids := scope.CoveredIDs()
		if ids == nil {
			ids = []string{}
		}
		out = append(out, meCapability{Capability: string(c), AllGroups: scope.All, GroupIDs: ids})
	}
	return out
}

// HandleStepUp is the protected POST /auth/step-up.
func (s *AuthService) HandleStepUp(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil || p.SessionID == "" {
		writeError(w, http.StatusForbidden, "step-up requires an interactive session")
		return
	}
	var req stepUpRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed step-up request body"); err != nil {
		return
	}
	user, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidCredentials.Error())
		return
	}
	if !user.TOTPConfirmed || user.TOTPSecret == "" {
		writeError(w, http.StatusForbidden, "enroll a second factor first")
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusForbidden, ErrTOTPRequired.Error())
		return
	}
	// Metered PER SESSION, not on the account's "login-totp" key (security audit 2026-10-18). A
	// session rider who lacks the code could otherwise post wrong codes here and lock the real owner
	// out of signing in, re-arming it for the stolen session's whole life — the trade-off
	// passwordThrottleKey already makes for /me/password. A per-session budget still bounds guessing:
	// another session needs the password.
	totpKey := accountKey("step-up|"+p.SessionID, p.TenantID, user.ID)
	if retry, allowed := s.throttle().Allow(totpKey); !allowed {
		writeThrottled(w, retry)
		return
	}
	step, valid, terr := VerifyTOTPStep(user.TOTPSecret, req.Code, s.now(), s.totpCfg())
	if terr != nil || !valid {
		s.throttle().Fail(totpKey)
		writeError(w, http.StatusForbidden, ErrInvalidCredentials.Error())
		return
	}
	fresh, cerr := s.Users.ConsumeTOTPStep(r.Context(), p.TenantID, user.ID, step)
	if cerr != nil || !fresh {
		s.throttle().Fail(totpKey)
		writeError(w, http.StatusForbidden, ErrInvalidCredentials.Error())
		return
	}
	s.throttle().Reset(totpKey)
	ok, merr := s.Sessions.Store.MarkMFAVerified(r.Context(), p.TenantID, user.ID, p.SessionID, user.MFAGeneration)
	if merr != nil {
		writeError(w, http.StatusInternalServerError, "could not record the verification")
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "your session ended or your second factor changed; sign in again")
		return
	}
	_ = s.recordAuthEvent(r.Context(), p.TenantID, user.ID, "auth.step_up", map[string]any{"ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
