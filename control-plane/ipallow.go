package controlplane

// IP allow-listing for the console/host API (docs/01 §14 "IP allow-listing for admin/host access").
//
// A deployment-wide guard for self-hosted operators who front the control plane with a VPN or an
// office network: set CP_ADMIN_IP_ALLOWLIST to a comma/space/semicolon-separated list of CIDRs (or
// bare IPs) and only those source addresses reach the AUTHENTICATED console API (`protectedChain`).
// The agent-enroll and guest-attend routes stay open — agents and guests connect from anywhere, and
// they carry their own bearer authorization.
//
// An EMPTY spec means NO restriction (open), so an operator who never sets the env var is unaffected —
// the backward-compatible default. The check runs at the EDGE, before auth/CSRF, so a disallowed
// source is refused without touching the session store.

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// IPAllowlist is a parsed set of permitted source networks. A nil *IPAllowlist means "open" — every
// method is nil-safe so callers need not branch on whether one was configured.
type IPAllowlist struct {
	nets []*net.IPNet
	// trustProxy: take the client IP from the RIGHTMOST X-Forwarded-For entry (the address the
	// immediate trusted reverse proxy saw) instead of the direct RemoteAddr. Set ONLY when exactly
	// one trusted reverse proxy fronts the control plane — otherwise a client spoofs its IP by
	// sending its own X-Forwarded-For.
	trustProxy bool
	// trustedProxyNets, when non-empty, gates the XFF trust to TCP peers whose address falls in
	// one of these networks (F14). Only requests from a peer in the list are allowed to set XFF;
	// all others are judged on RemoteAddr regardless of trustProxy. Nil/empty falls back to the
	// legacy trustProxy bool (any peer may set XFF when trustProxy is true).
	trustedProxyNets []*net.IPNet
}

func splitAllowlist(r rune) bool {
	return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// ParseIPAllowlist builds an allowlist from `spec` (CIDRs or bare IPs, any of comma/space/semicolon
// separated). A bare IPv4 becomes a /32, IPv6 a /128. An empty/whitespace spec yields a nil allowlist
// (open). A malformed entry is a hard error — a typo in an access-control list must fail loudly at
// startup, never silently widen or narrow access.
func ParseIPAllowlist(spec string, trustProxy bool) (*IPAllowlist, error) {
	fields := strings.FieldsFunc(spec, splitAllowlist)
	if len(fields) == 0 {
		return nil, nil // open
	}
	a := &IPAllowlist{trustProxy: trustProxy}
	for _, f := range fields {
		cidr := f
		if !strings.Contains(f, "/") {
			ip := net.ParseIP(f)
			if ip == nil {
				return nil, fmt.Errorf("ip allowlist: %q is not a valid IP or CIDR", f)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr = fmt.Sprintf("%s/%d", f, bits)
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("ip allowlist: %q is not a valid CIDR: %w", f, err)
		}
		a.nets = append(a.nets, n)
	}
	return a, nil
}

// clientIP is the source address to test: the direct RemoteAddr by default, or the rightmost
// X-Forwarded-For hop when trustProxy is set. Returns nil when it cannot be parsed.
func (a *IPAllowlist) clientIP(r *http.Request) net.IP {
	return resolveClientIP(r, a.trustProxy, a.trustedProxyNets)
}

// resolveClientIP is the shared source-address resolution used by BOTH the deployment-wide allow-list
// (via the method above) and the per-tenant allow-list (Server.SetTrustProxy, in http.go): the direct
// RemoteAddr by default, or the rightmost X-Forwarded-For hop when trustProxy is set.
//
// trustedNets (F14): when non-empty, X-Forwarded-For is only honoured when the TCP peer's address
// is in one of these networks. An untrusted peer's XFF header is ignored regardless of trustProxy.
// When trustedNets is nil or empty the old behaviour applies: trustProxy=true trusts XFF from any
// peer (warn at startup with CP_TRUST_PROXY_IP and no CP_TRUSTED_PROXIES for the insecure path).
//
// Returns nil when the client address cannot be parsed.
func resolveClientIP(r *http.Request, trustProxy bool, trustedNets []*net.IPNet) net.IP {
	if len(trustedNets) > 0 {
		// F14-secure path: validate the TCP peer before honouring XFF.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		peer := net.ParseIP(host)
		if peer != nil && netContains(trustedNets, peer) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
					return ip
				}
			}
			// Trusted peer but no usable XFF: fall through to return the peer's IP.
			return peer
		}
		// Untrusted peer or malformed RemoteAddr: return the peer IP (may be nil).
		return peer
	}
	// Legacy path: trust XFF from any peer when trustProxy is set.
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // RemoteAddr without a port (rare; e.g. some test harnesses)
	}
	return net.ParseIP(host)
}

// ParseTrustedProxies parses a whitespace/comma/semicolon-separated list of IP addresses or CIDR
// ranges that are permitted to set X-Forwarded-For (the CP_TRUSTED_PROXIES value). A bare IPv4
// becomes a /32 and a bare IPv6 a /128. An empty spec returns nil (no proxies trusted). A malformed
// entry is a hard error — a typo in a security-critical list must fail loudly at startup.
func ParseTrustedProxies(spec string) ([]*net.IPNet, error) {
	fields := strings.FieldsFunc(spec, splitAllowlist)
	if len(fields) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(fields))
	for _, f := range fields {
		cidr := f
		if !strings.Contains(f, "/") {
			ip := net.ParseIP(f)
			if ip == nil {
				return nil, fmt.Errorf("trusted proxies: %q is not a valid IP or CIDR", f)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr = fmt.Sprintf("%s/%d", f, bits)
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("trusted proxies: %q is not a valid CIDR: %w", f, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// netContains reports whether ip falls in any of the given networks.
func netContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeCIDR validates a single allow-list entry and returns its CANONICAL CIDR string: a bare IPv4
// becomes a /32, a bare IPv6 a /128, and a network is masked to its base address (e.g. "10.0.0.5/8" ->
// "10.0.0.0/8"). Storing the canonical form makes equality de-duplicate correctly (so an add is
// idempotent and a delete matches) and keeps the enforcement re-parse exact. A malformed entry is an
// error — the same "fail loud on a typo in an access-control list" rule ParseIPAllowlist follows.
func normalizeCIDR(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", fmt.Errorf("ip allowlist: empty CIDR")
	}
	cidr := entry
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil {
			return "", fmt.Errorf("ip allowlist: %q is not a valid IP or CIDR", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		cidr = fmt.Sprintf("%s/%d", entry, bits)
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("ip allowlist: %q is not a valid CIDR: %w", entry, err)
	}
	return n.String(), nil
}

// ipAllowMiddleware refuses a request whose source IP is not on s.IPAllowlist (403), before any other
// middleware runs. Nil-safe: an unconfigured allowlist allows every request, so this is always mounted
// and costs a single nil check when the feature is off.
func (s *Server) ipAllowMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.IPAllowlist.Allows(r) {
			writeError(w, http.StatusForbidden, "access from this network is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Allows reports whether r's client IP is permitted. A nil allowlist (unconfigured) allows everything;
// a configured one denies a source it cannot parse — an address that cannot be shown to be on the list
// is not on the list.
func (a *IPAllowlist) Allows(r *http.Request) bool {
	if a == nil || len(a.nets) == 0 {
		return true
	}
	ip := a.clientIP(r)
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
