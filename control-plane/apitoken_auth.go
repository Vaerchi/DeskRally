package controlplane

// APITokenAuthenticator — the auth-path front for API tokens. It wraps the ordinary
// (session/stub) Authenticator: a request carrying an `Authorization: Bearer rmt_api_…` header is
// resolved to a token principal here; everything else falls straight through to Next unchanged.
// This keeps SessionAuthenticator (the tested cookie/session path) untouched — the new credential
// type is purely additive.
//
// Two deliberate properties:
//
//   - The token is read ONLY from the Authorization header, never a cookie (headerBearerToken).
//     A browser cannot set an Authorization header cross-site, so the API-token path is inherently
//     CSRF-safe, and a token can never be smuggled in via the session cookie the CSRF layer keys on.
//
//   - A request whose header IS prefixed rmt_api_ but does NOT resolve is REJECTED, not passed to
//     Next. The prefix is an unambiguous "this is an API token" signal; falling through would let a
//     malformed/expired/revoked token be re-interpreted as a (also-failing) session and blur the
//     error. Fail closed on the credential the caller actually presented.

import (
	"errors"
	"net/http"
	"strings"
)

// APITokenAuthenticator resolves API-token bearer credentials, delegating everything else to Next.
type APITokenAuthenticator struct {
	Tokens APITokenStore
	Next   Authenticator
}

var _ Authenticator = (*APITokenAuthenticator)(nil)

// Authenticate implements Authenticator.
func (a *APITokenAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	tok := headerBearerToken(r)
	if !strings.HasPrefix(tok, APITokenPrefix) {
		// Not an API token (cookie session, session bearer, or no credential) — the ordinary path.
		return a.Next.Authenticate(r)
	}
	resolved, err := a.Tokens.Resolve(r.Context(), tok)
	if err != nil {
		// Unknown / revoked / expired / suspended tenant — all indistinguishable, all rejected.
		// Only that verdict is collapsed: a store FAULT (connection refused, pool exhausted) is returned
		// as it is, so the credential guard can tell "this token is bad" from "the database blinked" and
		// not charge a legitimate source's failure budget for the latter (credential_guard.go). Either
		// way the caller is refused with the same opaque 401.
		if errors.Is(err, ErrAPITokenNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	// The token IS the principal: its capabilities become a single tenant-wide membership, its id
	// becomes the actor id (a token has no user), and it carries no session.
	grant := NewGrant(resolved.ID, resolved.TenantID,
		NewCapabilityMembership(resolved.Capabilities, AllGroups()))
	return &Principal{UserID: resolved.ID, TenantID: resolved.TenantID, Grant: grant, APIToken: true}, nil
}

// headerBearerToken returns the token from the Authorization header ONLY (never the cookie), so an
// API token can be presented only the way a programmatic client presents one, and the cookie path
// stays exclusively the session authenticator's.
func headerBearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
