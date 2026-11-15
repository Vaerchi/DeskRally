package main

// Per-source connection quota and trusted-proxy IP resolution (docs/25 F09 residual).
//
// The global counters in websocket_limits.go bound the TOTAL connection count; a single source IP
// can still monopolize all those slots. This file adds a per-source ceiling: once a source IP
// holds maxPerIP connections, further attempts from that IP receive 503 until at least one
// existing connection from it closes.
//
// Client-IP resolution:
//
//   - By default (no SIGNALING_TRUSTED_PROXIES): the TCP peer address (r.RemoteAddr) is used
//     directly. Behind a reverse proxy this is the proxy's IP, making the per-source bucket
//     useless for distinguishing clients. Set SIGNALING_TRUSTED_PROXIES to the proxy's subnet.
//
//   - When trustedNets is non-empty: X-Forwarded-For is honoured only when the TCP peer falls
//     inside a trusted network (same "F14-secure" approach the control plane uses for
//     CP_TRUSTED_PROXIES). All other peers are bucketed by their RemoteAddr.
//
//   - An unparseable RemoteAddr (rare; a few test harnesses omit the port) returns "" which is
//     treated as "allow through without counting" — a safety valve, not a bypass.
//
// The quota is disabled (unlimited) when maxPerIP is zero, which is the default so that
// existing deployments are unaffected on upgrade.

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// ParseSignalingTrustedProxies parses a whitespace/comma/semicolon-separated list of IP
// addresses or CIDR ranges that are permitted to set X-Forwarded-For on the signaling
// WebSocket path.  A bare IPv4 becomes /32, a bare IPv6 /128.  An empty spec returns nil
// (no proxies trusted).  A malformed entry is a hard error — a typo in a security-critical
// list must fail loudly at startup, never silently widen or narrow access.
func ParseSignalingTrustedProxies(spec string) ([]*net.IPNet, error) {
	split := func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	fields := strings.FieldsFunc(spec, split)
	if len(fields) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(fields))
	for _, f := range fields {
		cidr := f
		if !strings.Contains(f, "/") {
			ip := net.ParseIP(f)
			if ip == nil {
				return nil, fmt.Errorf("SIGNALING_TRUSTED_PROXIES: %q is not a valid IP or CIDR", f)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr = fmt.Sprintf("%s/%d", f, bits)
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("SIGNALING_TRUSTED_PROXIES: %q is not a valid CIDR: %w", f, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// signalingClientIP extracts the effective client IP for admission accounting.
//
// When trustedNets is non-empty and the TCP peer falls inside one of the listed networks,
// the rightmost X-Forwarded-For hop is used (the address the trusted proxy observed).
// In all other cases the TCP peer's address (RemoteAddr) is returned as-is.
//
// SINGLE-PROXY CONSTRAINT: the rightmost-XFF approach is correct only when the trusted
// network contains exactly one reverse proxy hop. With two or more proxies (e.g. a CDN in
// front of Caddy) the innermost proxy's XFF append is the rightmost entry, and the
// outermost-client address sits one further left — potentially spoofable by the CDN peer.
// Set SIGNALING_TRUSTED_PROXIES to cover only the single innermost proxy's CIDR.
//
// IPv4-mapped IPv6 normalization: Go's net.ParseIP returns a 16-byte slice for any input.
// ip.String() on an IPv4-mapped value (e.g. net.ParseIP("::ffff:1.2.3.4")) yields
// "::ffff:1.2.3.4", which is a DIFFERENT map key from "1.2.3.4" for the same host.
// To prevent a bypass where an attacker uses "::ffff:1.2.3.4" in XFF to get a separate
// quota bucket, all IPs are canonicalized to their 4-byte IPv4 form (via ip.To4()) when
// they represent IPv4 addresses.
//
// Returns "" when the address cannot be parsed; callers MUST treat "" as "allow through
// without decrementing a per-source slot" — the slot is never incremented for an empty key.
func signalingClientIP(r *http.Request, trustedNets []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Some test harnesses pass a bare IP with no port.
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return ""
	}
	peer = normalizeIP(peer)
	if len(trustedNets) > 0 && signalingNetContains(trustedNets, peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			rightmost := strings.TrimSpace(parts[len(parts)-1])
			if ip := net.ParseIP(rightmost); ip != nil {
				return normalizeIP(ip).String()
			}
		}
		// Trusted peer but no usable XFF — use the peer's own address.
	}
	return peer.String()
}

// normalizeIP collapses an IPv4-mapped IPv6 address to its 4-byte IPv4 form so that
// "1.2.3.4" and "::ffff:1.2.3.4" always produce the same map key. Pure IPv6 addresses
// are returned unchanged.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// signalingNetContains reports whether ip falls in any of the given networks.
// Kept here rather than shared with the control plane to keep the signaling package
// self-contained — both are trivial single-liners, and a shared import would couple the two
// binaries' dependency graphs.
func signalingNetContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sourceQuota tracks per-IP WebSocket connection counts.
//
// The zero value is unusable; always allocate with newSourceQuota.
type sourceQuota struct {
	mu       sync.Mutex
	maxPerIP int
	byIP     map[string]int
}

// newSourceQuota builds a quota gate.  maxPerIP == 0 means disabled (unlimited).
// A positive value is the maximum number of concurrent connections any single IP may hold.
func newSourceQuota(maxPerIP int) *sourceQuota {
	return &sourceQuota{maxPerIP: maxPerIP, byIP: make(map[string]int)}
}

// enabled reports whether the per-IP limit is active (maxPerIP > 0).
func (sq *sourceQuota) enabled() bool {
	return sq.maxPerIP > 0
}

// tryAcquire reserves one slot for ip.
//
//   - Disabled (maxPerIP == 0): always returns true without touching the map.
//   - Empty ip: always returns true (unparseable address; no slot is incremented so none
//     must later be released — callers check ip before releasing).
//   - At limit (byIP[ip] >= maxPerIP): returns false.
//   - Otherwise: increments byIP[ip] and returns true.
//
// The caller is responsible for calling release exactly once on success; Release is idempotent
// and safe to call on "" even though tryAcquire would have been a no-op.
func (sq *sourceQuota) tryAcquire(ip string) bool {
	if !sq.enabled() || ip == "" {
		return true
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	if sq.byIP[ip] >= sq.maxPerIP {
		return false
	}
	sq.byIP[ip]++
	return true
}

// release returns one slot to ip.  Safe to call on "" (no-op) and on an ip whose count
// is already zero (idempotent underflow guard).  Cleans up zero-count map entries to bound
// memory on a server that sees many ephemeral source IPs.
func (sq *sourceQuota) release(ip string) {
	if ip == "" {
		return
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	if sq.byIP[ip] <= 0 {
		return
	}
	sq.byIP[ip]--
	if sq.byIP[ip] == 0 {
		delete(sq.byIP, ip)
	}
}
