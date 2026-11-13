package controlplane

// HandleChangeEmail is the protected POST /me/email endpoint: the authenticated caller changes
// THEIR OWN login email. It follows the same security shape as HandleChangePassword:
//
//   - current-password step-up (a live session alone must not be enough to change the login identifier)
//   - separate per-session throttle (cannot burn the login or password-change budget)
//   - atomic epoch check in the store (concurrent password reset cannot bypass the verification)
//   - revoke ALL sessions + issue replacement (email is the login identifier, so existing proofs
//     must be retired along with the old address)
//
// No email verification or mail delivery: email is an opaque login identifier in this product.
// The caller is responsible for communicating the new address to whoever needs it.

import (
	"errors"
	"log"
	"net/http"
	"time"
)

type changeEmailRequest struct {
	CurrentPassword string `json:"current_password"`
	NewEmail        string `json:"new_email"`
}

// emailThrottleKey meters POST /me/email per session, for the same reason passwordThrottleKey
// does: an account-keyed budget would let a session rider exhaust it and lock the real owner out
// of this recovery path. Separate namespace ("email") so exhausting one does not deny the other.
func emailThrottleKey(p *Principal) string {
	if p.SessionID == "" {
		return accountKey("email", p.TenantID, p.UserID)
	}
	return accountKey("email|"+p.SessionID, p.TenantID, p.UserID)
}

// HandleChangeEmail is POST /me/email.
func (s *AuthService) HandleChangeEmail(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req changeEmailRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}

	th := s.throttle()
	keys := []string{emailThrottleKey(p)}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}

	u, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || u == nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user")
		return
	}
	if u.PasswordHash == "" {
		writeError(w, http.StatusConflict, ErrNoLocalCredential.Error())
		return
	}

	ok, verr := VerifyPasswordCtx(r.Context(), u.PasswordHash, req.CurrentPassword)
	if IsHashCapacityError(verr) {
		WriteHashBusy(w)
		return
	}
	if verr != nil || !ok {
		th.Fail(keys...)
		if aerr := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, "auth.email_change_failed",
			map[string]any{"ip": clientIP(r)}); aerr != nil {
			log.Printf("could not record auth.email_change_failed for tenant %s: %v", p.TenantID, aerr)
		}
		// The login session is valid; only step-up failed. Reserve 401 for
		// session expiry so the browser can show this error without signing out.
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	th.Reset(keys...)

	// Capture the epoch the verification was performed against. SetEmail will reject the write if
	// a concurrent credential change (password reset, rotation) advanced it between now and then.
	verifiedEpoch := u.CredentialUpdatedAt

	newEmail, valid := normalizeEmail(req.NewEmail)
	if !valid {
		writeError(w, http.StatusBadRequest, "new_email is not a valid address")
		return
	}
	if newEmail == u.Email {
		writeError(w, http.StatusBadRequest, "new email must differ from the current one")
		return
	}

	// Verify sessions are available BEFORE changing any data: a deployment with no session store
	// cannot issue the replacement, leaving the caller signed out everywhere with no way back.
	if s.Sessions == nil {
		writeError(w, http.StatusInternalServerError, "sessions not configured")
		return
	}

	epoch, err := s.Users.SetEmail(r.Context(), p.TenantID, p.UserID, newEmail, verifiedEpoch)
	if err != nil {
		switch {
		case errors.Is(err, ErrEmailExists):
			writeError(w, http.StatusConflict, ErrEmailExists.Error())
		case errors.Is(err, ErrStaleCredential):
			writeError(w, http.StatusConflict, ErrStaleCredential.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not update email")
		}
		return
	}

	// From here the email IS changed. Every remaining failure says so explicitly.
	revoked, rerr := s.Sessions.RevokeOtherSessions(r.Context(), p.TenantID, p.UserID, "")
	if rerr != nil {
		log.Printf("email changed for user %s but sessions could not be revoked: %v", p.UserID, rerr)
		writeError(w, http.StatusInternalServerError,
			"email was changed but existing sessions could not be revoked; sign in with the new email")
		return
	}
	token, sess, err := s.Sessions.Issue(r.Context(), p.TenantID, p.UserID, epoch)
	if err != nil {
		log.Printf("email changed for user %s but replacement session could not be issued: %v", p.UserID, err)
		writeError(w, http.StatusInternalServerError,
			"email was changed and all sessions were signed out; sign in with the new email")
		return
	}
	if aerr := s.recordAuthEvent(r.Context(), p.TenantID, p.UserID, "auth.email_changed", map[string]any{
		"old_email":        u.Email,
		"new_email":        newEmail,
		"sessions_revoked": revoked,
		"ip":               clientIP(r),
	}); aerr != nil {
		writeError(w, http.StatusInternalServerError,
			"email was changed but the audit event could not be recorded; sign in with the new email")
		return
	}
	csrf := csrfTokenFor(token)
	// The rotated token is known-good: register it with the credential guard so its holder is not refused by a
	// failure budget an attacker sharing this source ran down (credential_guard.go). After the Issue error check,
	// so only a token that exists is registered.
	s.Guard.NoteValid(token)
	http.SetCookie(w, s.sessionCookie(token, sess.ExpiresAt))
	http.SetCookie(w, s.csrfCookie(csrf, sess.ExpiresAt))
	writeJSON(w, http.StatusOK, map[string]any{
		"changed":          true,
		"email":            newEmail,
		"sessions_revoked": revoked,
		"csrf_token":       csrf,
		"expires_at":       sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
