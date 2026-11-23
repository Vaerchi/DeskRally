package controlplane

// CSRF protection for COOKIE-authenticated requests (M4), double-submit pattern — no schema
// change. Login sets a second, NON-HttpOnly cookie carrying a random value and returns the
// same value in the login response as csrf_token; every mutating request authenticated via
// the session cookie must echo it back in the X-CSRF-Token header. A cross-site attacker can
// make the browser SEND both cookies but can neither read the csrf cookie nor set the header
// cross-origin, so the pair only ever matches for the legitimate client.
//
// Bearer-token requests are exempt: the Authorization header is not ambient authority — a
// cross-site page cannot attach it — so there is nothing to forge. Whether a request is
// "authenticated via cookie" is decided by cookieSessionToken (auth.go), the SAME cookie-first
// precedence SessionAuthenticator's bearerToken applies, so the middleware and the
// authenticator can never disagree about which credential a request rode in on.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// CSRFCookieName is the non-HttpOnly cookie carrying the CSRF token (readable by the SPA).
const CSRFCookieName = "rmt_csrf"

// CSRFHeaderName is the request header that must echo the rmt_csrf cookie value on mutating
// cookie-authenticated requests.
const CSRFHeaderName = "X-CSRF-Token"

// csrfDomainTag separates this derivation from every other hash of a session token in the system
// (HashToken, which keys the session row) so the two can never collide or be substituted.
const csrfDomainTag = "RMTCSRFv1\x00"

// csrfTokenFor derives the CSRF token BOUND TO a session token: SHA-256 over a domain tag and the
// session's bearer secret, hex-encoded.
//
// Deriving rather than randomising is what makes the pair non-transplantable. With an independent
// random value the middleware could only check "cookie equals header", which two cookies from
// DIFFERENT sessions satisfy just as well — so an attacker able to write one of the browser's
// cookies (a sibling-subdomain foothold, a cookie-tossing bug, cleartext injection) could pair a
// session cookie with a CSRF cookie it does not belong to. Here the expected value is recomputed
// from the session cookie actually presented, so a mismatched pair is rejected.
//
// The derivation is one-way: the CSRF value is readable by page scripts and travels in headers and
// logs, and SHA-256 preimage resistance means none of that leaks the HttpOnly session token.
func csrfTokenFor(sessionToken string) string {
	sum := sha256.Sum256([]byte(csrfDomainTag + sessionToken))
	return hex.EncodeToString(sum[:])
}

// sessionCookieName is the session cookie the CSRF check keys on — the AuthAPI's configured
// name when wired, else the default (the RBAC-skeleton tests run cookieless stubs).
func (s *Server) sessionCookieName() string {
	if s.AuthAPI != nil {
		return s.AuthAPI.cookieName()
	}
	return DefaultSessionCookie
}

// csrfMiddleware enforces the double-submit check. Scope:
//   - GET/HEAD/OPTIONS pass untouched (safe methods).
//   - Requests WITHOUT a session cookie pass untouched — Bearer/unauthenticated requests carry
//     no ambient authority (a present session cookie always wins in bearerToken, so a request
//     carrying both cookie and Authorization header IS cookie-authenticated and is checked).
//   - Cookie-authenticated mutating requests 403 unless X-CSRF-Token equals the rmt_csrf
//     cookie value AND both equal the value derived from the PRESENTED SESSION COOKIE
//     (constant-time compares), so a cookie pair borrowed from another session is refused.
//
// It wraps the whole protected chain plus POST /auth/logout; the public /auth/login and
// /enroll/redeem stay outside it (no session exists yet — the credentials in the body are the
// authorization). Login has its own pre-session defence: originMiddleware.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		session := cookieSessionToken(r, s.sessionCookieName())
		if session == "" {
			next.ServeHTTP(w, r)
			return
		}
		expected := []byte(csrfTokenFor(session))
		header := r.Header.Get(CSRFHeaderName)
		name := CSRFCookieName
		if s.AuthAPI != nil {
			name = s.AuthAPI.csrfCookieName()
		}
		c, err := r.Cookie(name)
		if err != nil || c.Value == "" || header == "" ||
			subtle.ConstantTimeCompare([]byte(c.Value), expected) != 1 ||
			subtle.ConstantTimeCompare([]byte(header), expected) != 1 {
			writeError(w, http.StatusForbidden, "csrf token missing or invalid")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originMiddleware rejects a mutating request that a BROWSER tells us came from another site.
//
// This is the pre-session half of CSRF defence, and POST /auth/login is why it exists. Login cannot
// use the double-submit check — there is no session to double-submit against — and the session
// cookie is SameSite=Lax, which permits a top-level cross-site POST's response to set cookies. So
// an attacker's auto-submitting form can log a victim's browser into an ATTACKER-CONTROLLED
// account; the victim then keeps working, and everything they do (machines they enroll, files they
// transfer, sessions they open) lands in the attacker's tenant where the attacker can read it.
//
// The signal is taken from the browser, in this order:
//
//	Sec-Fetch-Site  authoritative when present (browsers set it on every fetch and forbid pages
//	                from spoofing it). "cross-site" is refused; "same-origin" and
//	                "none" (a user typing the URL / a bookmark) pass. "same-site" is accepted so a
//	                console served from a sibling host of the API keeps working — the same
//	                boundary SameSite=Lax already draws for the cookie itself.
//	Origin          fallback for browsers that do not send Sec-Fetch-Site: its host must equal the
//	                request's Host.
//
// A request with NEITHER header is allowed: that is a non-browser client (the agent installer,
// curl, an integration), which has no ambient cookies to be abused in the first place. This is what
// keeps the same-origin viewer and every existing test working while closing the browser path.
//
// DEPLOYMENT NOTE: the Origin fallback compares against r.Host, so a reverse proxy in front of this
// process must pass the client's Host through unchanged. A proxy that rewrites Host to its upstream
// target (Vite's `changeOrigin: true`, for one) makes the fallback see a mismatch — harmless while
// the browser also sends Sec-Fetch-Site, which is checked first and settles it.
func (s *Server) originMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !requestIsSameSite(r) {
			writeError(w, http.StatusForbidden, "cross-site request forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsSameSite implements originMiddleware's decision. Absent browser signals ⇒ true.
func requestIsSameSite(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site":
		return false
	case "same-origin", "none":
		return true
	case "same-site":
		if strings.TrimSpace(r.Header.Get("Origin")) == "" {
			return false
		}
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, "null") {
		// An opaque origin: a sandboxed iframe or a data:/file: document. Never the console.
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
