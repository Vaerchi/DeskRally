package controlplane

// API-token management handlers (docs/01 §8): POST/GET/DELETE /api-tokens, all gated on
// CapManageTenant (Owner-only). The RESOLVE path — turning a presented token into a Principal —
// is NOT here; it is the APITokenAuthenticator wired ahead of the session authenticator (main.go).
//
// Gating on CapManageTenant is the deliberate choice: only an Owner mints tokens, and an Owner
// holds every capability, so any grantable subset a token carries is authority the minter already
// has — no escalation is possible, and no per-capability subset check is needed. (The
// defense-in-depth Grant.Allows check below still runs, so this stays correct if the gate is ever
// widened to a role that is not all-powerful.)

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// maxAPITokenNameLen bounds the human label. A name is administrative metadata shown in the
// listing; a few hundred characters is generous, and a cap keeps a pathological body out of the row.
const maxAPITokenNameLen = 200

type mintAPITokenRequest struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	// ExpiresInDays is optional: 0 (or omitted) mints a token that never expires — a visible,
	// revocable choice. A positive value is capped at MaxAPITokenTTLDays.
	ExpiresInDays int `json:"expires_in_days"`
}

func (s *Server) handleMintAPIToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	var req mintAPITokenRequest
	// docs/25 F05: the Owner-only gate above runs first, so this bounds an authorized caller's body
	// while the request's tenant connection is pinned. `capabilities` is a short list of names, each
	// validated against the catalogue below.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed mint-token request body"); err != nil {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(name) > maxAPITokenNameLen {
		writeError(w, http.StatusBadRequest, "name exceeds the maximum length")
		return
	}
	caps, err := parseAPITokenCapabilities(req.Capabilities)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Defense in depth: a token may never carry authority its minter lacks. With the Owner-only
	// gate above this is always satisfied (the Owner holds every capability), but it keeps the
	// invariant true if the gate is ever widened — the escalation canAdministerUser guards against.
	for _, c := range caps {
		if !p.Grant.Allows(c) {
			writeError(w, http.StatusForbidden, "cannot grant a capability you do not hold: "+string(c))
			return
		}
	}
	var expiresAt *time.Time
	switch {
	case req.ExpiresInDays < 0:
		writeError(w, http.StatusBadRequest, "expires_in_days must be positive")
		return
	case req.ExpiresInDays > MaxAPITokenTTLDays:
		writeError(w, http.StatusBadRequest, "expires_in_days exceeds the maximum API-token lifetime")
		return
	case req.ExpiresInDays > 0:
		t := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}
	plaintext, tok, err := s.APITokens.Mint(r.Context(), p.TenantID, name, caps, p.UserID, expiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint api token")
		return
	}
	meta := map[string]any{"name": tok.Name, "capabilities": tok.Capabilities}
	if tok.ExpiresAt != nil {
		meta["expires_at"] = tok.ExpiresAt
	}
	if err := s.recordMgmtAudit(r, "api_token.mint", "api_token", tok.ID, meta); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// The plaintext is shown ONCE, here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "api_token": tok})
}

func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	tokens, err := s.APITokens.List(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list api tokens")
		return
	}
	// RLS already scoped the query to the tenant. Unlike enrollment tokens there is no per-group
	// visibility to further confine: an API token is tenant-wide, and the gate is CapManageTenant
	// (Owner), which is tenant-wide by definition.
	if tokens == nil {
		tokens = []APIToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_tokens": tokens})
}

func (s *Server) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	id := r.PathValue("id")
	if err := s.APITokens.Revoke(r.Context(), p.TenantID, id); err != nil {
		if errors.Is(err, ErrAPITokenNotFound) {
			writeError(w, http.StatusNotFound, "unknown api token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not revoke api token")
		return
	}
	if err := s.recordMgmtAudit(r, "api_token.revoke", "api_token", id, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
}
