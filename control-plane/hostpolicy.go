package controlplane

// Host resolution for per-tenant hostname theming (docs/66 sections 2a.1, 2a.2, 2b.1, 2b.6, 2c.1).
//
// There are exactly four outcomes for the authority a request arrived on, and NONE of them is "unknown, so
// treat it as the default":
//
//	HostRefused  malformed (or not normalisable) authority: never scoped to a tenant, never Default.
//	HostDefault  a host in CP_DEFAULT_HOSTS (main): unscoped, neutral.
//	HostLegacy   a host in CP_LEGACY_UNSCOPED_HOSTS (loam, vc today): unscoped, each named explicitly.
//	HostTenant   anything else: the SQL decides, in the same statement as the redemption, whether the host is
//	             an ACTIVE assignment and for which tenant. No active assignment means no result row, which is
//	             the generic invalid-code answer.
//
// There is NO cache and NO coalescing anywhere in this file or its callers (docs/66 2b.1, 2c.1): the only
// memoised data is configuration read once at startup (the default / legacy / public-authority sets).
//
// The PUBLIC-INGRESS authority gate (2b.6) acts only on requests carrying the Caddy edge marker. A request
// without the marker is "internal" (signaling, health probes, the compose network) and is never
// authority-gated: those callers use service hostnames that are not, and must not need to be, public
// authorities.

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// EdgeMarkerHeader is set by Caddy (after deleting any client-supplied copy) on every request it proxies.
const EdgeMarkerHeader = "X-DeskRally-Edge"

// EdgeMarkerMinLen: the marker is a shared secret between Caddy and the control plane.
const EdgeMarkerMinLen = 32

// HostClass is the outcome of classifying an authority.
type HostClass int

const (
	HostRefused HostClass = iota
	HostDefault
	HostLegacy
	HostTenant
)

func (c HostClass) String() string {
	switch c {
	case HostDefault:
		return "default"
	case HostLegacy:
		return "legacy"
	case HostTenant:
		return "tenant"
	}
	return "refused"
}

// hostnameRE is the same shape tenant_hostname_assignment.host enforces (migration 0071): lowercase labels,
// at least two of them (a single-label name such as a compose service is never a public authority).
var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// NormalizeAuthority turns a Host header value into the one canonical spelling, or refuses it. Accepted and
// normalised: any letter case, exactly one trailing dot, an explicit port of exactly 443. Refused: an empty
// value, any other port (or an empty one), whitespace or control characters, userinfo, '/' or '\', a
// non-ASCII byte, an IP literal (v4, v6 or a numeric-looking name), more than one trailing dot, a name that is
// not a plain dotted DNS name, or anything over 253 bytes.
func NormalizeAuthority(raw string) (string, bool) {
	if raw == "" || len(raw) > 260 {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c <= 0x20 || c >= 0x7f || c == '/' || c == '\\' || c == '@' || c == '[' || c == ']' || c == '?' || c == '#' || c == '%' {
			return "", false
		}
	}
	host := raw
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		if strings.Count(raw, ":") != 1 || raw[i+1:] != "443" {
			return "", false
		}
		host = raw[:i]
	}
	if strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
		if strings.HasSuffix(host, ".") {
			return "", false
		}
	}
	host = strings.ToLower(host)
	if len(host) == 0 || len(host) > 253 || !hostnameRE.MatchString(host) {
		return "", false
	}
	if net.ParseIP(host) != nil {
		return "", false
	}
	// A purely numeric last label is never a registrable name (it is how 127.1 or 0x7f.1 style IP spellings
	// slip through a regexp); refuse it.
	last := host[strings.LastIndexByte(host, '.')+1:]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
		}
	}
	if allDigits {
		return "", false
	}
	return host, true
}

// HostPolicyConfig is the configuration of the host policy.
type HostPolicyConfig struct {
	// DefaultHosts: the neutral, unscoped default host(s) (CP_DEFAULT_HOSTS, default main<suffix>).
	DefaultHosts []string
	// LegacyUnscopedHosts: explicit, individually named legacy hosts that keep unscoped redemption.
	LegacyUnscopedHosts []string
	// PublicAuthorities: the allowlist the edge gate enforces (CP_PUBLIC_AUTHORITIES). Empty = default
	// hosts plus legacy hosts.
	PublicAuthorities []string
	// EdgeSecret: the shared secret Caddy sends in EdgeMarkerHeader. Empty = the gate is not installed.
	EdgeSecret string
	// Theming mirrors CP_HOST_THEMING. It controls PUBLISHING branding only (stage 1b); it never removes an
	// active host's redemption scope (docs/66 2a.1).
	Theming bool
}

// HostPolicy classifies authorities. Immutable after construction, so safe for concurrent use.
type HostPolicy struct {
	defaults    map[string]bool
	legacy      map[string]bool
	authorities map[string]bool
	edgeSecret  string
	theming     bool
}

// NewHostPolicy validates and freezes the configuration. A host that is both default and legacy, or a value
// that does not normalise, is a startup error rather than a silently ignored line.
func NewHostPolicy(cfg HostPolicyConfig) (*HostPolicy, error) {
	p := &HostPolicy{defaults: map[string]bool{}, legacy: map[string]bool{}, authorities: map[string]bool{},
		edgeSecret: cfg.EdgeSecret, theming: cfg.Theming}
	add := func(set map[string]bool, what string, hosts []string) error {
		for _, h := range hosts {
			n, ok := NormalizeAuthority(strings.TrimSpace(h))
			if !ok || strings.Contains(strings.TrimSpace(h), ":") {
				return fmt.Errorf("%s: %q is not a plain host name", what, h)
			}
			set[n] = true
		}
		return nil
	}
	if err := add(p.defaults, "CP_DEFAULT_HOSTS", cfg.DefaultHosts); err != nil {
		return nil, err
	}
	if err := add(p.legacy, "CP_LEGACY_UNSCOPED_HOSTS", cfg.LegacyUnscopedHosts); err != nil {
		return nil, err
	}
	for h := range p.defaults {
		if p.legacy[h] {
			return nil, fmt.Errorf("host %q is in both CP_DEFAULT_HOSTS and CP_LEGACY_UNSCOPED_HOSTS", h)
		}
	}
	if err := add(p.authorities, "CP_PUBLIC_AUTHORITIES", cfg.PublicAuthorities); err != nil {
		return nil, err
	}
	if len(cfg.PublicAuthorities) == 0 {
		for h := range p.defaults {
			p.authorities[h] = true
		}
		for h := range p.legacy {
			p.authorities[h] = true
		}
	}
	if cfg.EdgeSecret != "" && len(cfg.EdgeSecret) < EdgeMarkerMinLen {
		return nil, fmt.Errorf("the edge marker secret must be at least %d characters", EdgeMarkerMinLen)
	}
	return p, nil
}

// Classify normalises raw (a Host header value) and says what kind of host it is. The returned host is the
// normalised spelling, empty when refused. Pure: no I/O, no cache.
func (p *HostPolicy) Classify(raw string) (string, HostClass) {
	h, ok := NormalizeAuthority(raw)
	if !ok {
		return "", HostRefused
	}
	switch {
	case p.defaults[h]:
		return h, HostDefault
	case p.legacy[h]:
		return h, HostLegacy
	}
	return h, HostTenant
}

// IsReservedHost reports whether h (already normalised) is a default or legacy host, which may never be
// assigned to a tenant.
func (p *HostPolicy) IsReservedHost(h string) bool { return p.defaults[h] || p.legacy[h] }

// ReservedHosts lists default and legacy hosts (startup collision check against active assignments).
func (p *HostPolicy) ReservedHosts() []string {
	out := make([]string, 0, len(p.defaults)+len(p.legacy))
	for h := range p.defaults {
		out = append(out, h)
	}
	for h := range p.legacy {
		out = append(out, h)
	}
	return out
}

// Theming reports CP_HOST_THEMING (publishing only; see HostPolicyConfig).
func (p *HostPolicy) Theming() bool { return p.theming }

// IsPublicAuthority reports whether h (already normalised) is on the public authority allowlist: the only
// hosts whose public branding is ever looked up in the database (docs/66 2a.9, 2b.1).
func (p *HostPolicy) IsPublicAuthority(h string) bool { return p != nil && p.authorities[h] }

// GateInstalled reports whether the edge authority gate is active.
func (p *HostPolicy) GateInstalled() bool { return p.edgeSecret != "" }

// RedeemScope is how a redemption is scoped to the host it arrived on, decided from configuration only.
type RedeemScope struct {
	// Unscoped: the default host or an explicit legacy host. No tenant predicate.
	Unscoped bool
	// Host: the normalised host whose CURRENT active assignment the store must resolve and enforce in the same
	// call as the redemption. Empty with Unscoped=false matches nothing (a refused authority).
	Host string
}

// ScopeFor is the redemption scope for a request's Host header value.
func (p *HostPolicy) ScopeFor(raw string) RedeemScope {
	if p == nil {
		return RedeemScope{Unscoped: true}
	}
	h, class := p.Classify(raw)
	switch class {
	case HostDefault, HostLegacy:
		return RedeemScope{Unscoped: true, Host: h}
	case HostTenant:
		return RedeemScope{Host: h}
	}
	return RedeemScope{}
}

// errMisdirected is the single answer of the gate.
var errMisdirected = errors.New("misdirected request")

// edgeGateExempt: routes that never carry public-ingress authority semantics. The internal service routes and
// the health probes are reached by service name on the compose network (docs/66 2b.6).
func edgeGateExempt(path string) bool {
	return strings.HasPrefix(path, "/internal/") || path == "/healthz" || path == "/readyz"
}

// EdgeAuthorityGate refuses (421, before any resolver or DB work) a request that arrived through the public
// ingress, i.e. carries the edge marker, whose authority is not on the public allowlist, is malformed or
// duplicated, or whose marker value is not the configured secret (a forged marker is untrusted). Requests
// without the marker are internal and pass through untouched.
func (p *HostPolicy) EdgeAuthorityGate(next http.Handler) http.Handler {
	if p == nil || p.edgeSecret == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		marker := r.Header.Values(EdgeMarkerHeader)
		if len(marker) == 0 || edgeGateExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if len(marker) != 1 || subtle.ConstantTimeCompare([]byte(marker[0]), []byte(p.edgeSecret)) != 1 {
			writeError(w, http.StatusMisdirectedRequest, errMisdirected.Error())
			return
		}
		if len(r.Header.Values("Host")) > 1 {
			writeError(w, http.StatusMisdirectedRequest, errMisdirected.Error())
			return
		}
		h, ok := NormalizeAuthority(r.Host)
		if !ok || !p.authorities[h] {
			writeError(w, http.StatusMisdirectedRequest, errMisdirected.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}
