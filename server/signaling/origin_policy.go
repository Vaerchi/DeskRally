package main

// originPolicy controls which browser Origins may upgrade to a WebSocket (docs/25 F09 residual).
//
// Native clients (the Rust agent, Go CLI tools) do not send an Origin header on a WebSocket
// handshake — they are always permitted regardless of the policy. Browsers always send Origin
// and cannot suppress it via script, so a request with no Origin is definitively non-browser.
//
// Two modes:
//
//   - warn-only (allowed is nil/empty): every Origin is allowed. This is the default so that
//     existing deployments are not broken on upgrade. The operator is warned at startup.
//
//   - enforcing (non-empty allowed list): only requests whose Origin matches one of the listed
//     values exactly are allowed; all others are rejected with 403.
//
// This is not a CORS policy: no response headers are added. It is purely an admission decision
// on the upgrade request, and it runs before the WebSocket slot is acquired.

import (
	"fmt"
	"net/http"
	"strings"
)

// originPolicy is the parsed result of SIGNALING_ALLOWED_ORIGINS. The zero value is warn-only.
type originPolicy struct {
	allowed []string // nil or empty = warn-only; non-nil non-empty = enforcing
	// wild holds wildcard entries "https://*.suffix": one subdomain label under the suffix.
	wild []wildOrigin
	// any is the EXPLICIT, unsafe allow-all (SIGNALING_ALLOWED_ORIGINS=*): distinguishes a chosen
	// open policy from a forgotten empty one (which production mode refuses).
	any bool
}

type wildOrigin struct{ scheme, suffix string } // suffix includes the leading dot, e.g. ".deskrally.com"

// matchesWild reports whether origin is scheme + exactly one DNS label + suffix (a port is allowed).
func (w wildOrigin) matches(origin string) bool {
	rest, ok := strings.CutPrefix(origin, w.scheme)
	if !ok {
		return false
	}
	host := rest
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		host = rest[:i]
	}
	label, ok := strings.CutSuffix(host, w.suffix)
	if !ok || label == "" || strings.ContainsAny(label, ".:/@ 	?#") {
		return false
	}
	return true
}

// ParseOriginPolicy parses the value of SIGNALING_ALLOWED_ORIGINS.
//
//   - Empty string returns a warn-only policy (all Origins permitted).
//   - Non-empty values are split on commas; each entry is trimmed and must carry a scheme
//     (https:// or http://). Blank entries are silently skipped. A comma-only string yields
//     warn-only (no valid entries found).
//
// Comparison is byte-exact (Go ==). The Origin header value is scheme+host, with the port
// included ONLY when it is non-default for the scheme. Browsers typically send
// "https://host" (no :443), NOT "https://host:443". Use the form browsers actually send;
// the two forms are distinct and a mismatch will 403 legitimate connections.
// The literal string "null" (from file:// or sandboxed iframes) is not a valid scheme and is
// blocked in enforcing mode, which is the correct outcome for those contexts.
func ParseOriginPolicy(raw string) (*originPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return &originPolicy{}, nil
	}
	if raw == "*" {
		return &originPolicy{any: true}, nil
	}
	parts := strings.Split(raw, ",")
	allowed := make([]string, 0, len(parts))
	var wild []wildOrigin
entries:
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "https://") && !strings.HasPrefix(p, "http://") {
			return nil, fmt.Errorf("SIGNALING_ALLOWED_ORIGINS: %q is not a valid origin (want https:// or http:// prefix)", p)
		}
		if p == "*" {
			return nil, fmt.Errorf("SIGNALING_ALLOWED_ORIGINS: \"*\" (allow any origin) must be the only entry")
		}
		for _, scheme := range []string{"https://", "http://"} {
			if rest, ok := strings.CutPrefix(p, scheme); ok && strings.HasPrefix(rest, "*.") {
				if strings.Contains(rest[2:], "*") || len(rest) < 4 {
					return nil, fmt.Errorf("SIGNALING_ALLOWED_ORIGINS: %q is not a valid wildcard origin", p)
				}
				wild = append(wild, wildOrigin{scheme: scheme, suffix: rest[1:]})
				continue entries
			}
		}
		allowed = append(allowed, p)
	}
	if len(allowed) == 0 && len(wild) == 0 {
		return &originPolicy{}, nil
	}
	return &originPolicy{allowed: allowed, wild: wild}, nil
}

// WithTenantSuffix returns the policy extended with the wildcard "https://*<suffix>" (the console is
// also served from <tenant>.<suffix> when SSO tenant hosts are enabled). An empty suffix or an
// open/warn-only policy is returned unchanged.
func (p *originPolicy) WithTenantSuffix(suffix string) *originPolicy {
	suffix = strings.TrimSpace(suffix)
	if suffix == "" || !strings.HasPrefix(suffix, ".") || !p.enforcing() {
		return p
	}
	q := *p
	q.wild = append(append([]wildOrigin(nil), p.wild...), wildOrigin{scheme: "https://", suffix: suffix})
	return &q
}

// enforcing reports whether the policy blocks Origins absent from the allowlist.
func (p *originPolicy) enforcing() bool {
	return len(p.allowed) > 0 || len(p.wild) > 0
}

// allow returns true when the request may proceed.
//
//   - No Origin header → true (native client; browsers cannot suppress Origin).
//   - Warn-only mode (empty allowlist) → true.
//   - Enforcing mode → true only if Origin is in the allowlist.
//
// The literal string "null" (browsers inside sandboxed iframes or file:// documents) has a
// non-empty Origin header and falls through to the allowlist check. It is correctly blocked in
// enforcing mode (no sane allowlist contains "null") and correctly allowed in warn-only mode.
func (p *originPolicy) allow(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // native client
	}
	if !p.enforcing() {
		return true // warn-only or explicit allow-any
	}
	for _, a := range p.allowed {
		if a == origin {
			return true
		}
	}
	for _, w := range p.wild {
		if w.matches(origin) {
			return true
		}
	}
	return false
}
