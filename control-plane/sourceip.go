package controlplane

import (
	"context"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Persisted client source address (audit_event.source_ip, session_record.source_ip,
// user_session.source_ip / user_agent; all declared in 0001/0002, written since this file).
//
// WHICH DERIVATION. Two exist: the package-level clientIP(r) (throttle identity, 24 call sites) and
// resolveClientIP(r, s.trustProxyIP, s.trustedProxyNets), which the admin/tenant IP allow-list and
// callerIPString use. Both end in resolveClientIP and are armed together by SetTrustedProxies, but the
// allow-list one is the security-relevant path (it decides who may reach the API), so the persisted
// address uses exactly that one: RemoteAddr unless the TCP peer is a trusted proxy (CP_TRUSTED_PROXIES),
// in which case the rightmost X-Forwarded-For hop. An untrusted peer's header is never read.
//
// HOW IT TRAVELS. Computed once per request by sourceIPMiddleware and carried in the context, so the
// stores (which already receive the request context) need no new parameters and a handler cannot
// forget it. Callers without an HTTP request (background jobs, agent-internal paths that do not pass
// through the middleware) simply have none, and the column stays NULL.
//
// SERVICE-TO-SERVICE ROUTES carry none either. Everything under /internal/ is called by signaling (session
// ended, guest ended, help request relayed from an agent, directives), authenticated by the device-identity
// token, so its TCP peer is signaling's container address (production saw 172.18.x.x on a session.end).
// No client chose that request; recording the caller's address would attribute a server event to the
// Docker network. The column stays NULL for them.

type sourceCtxKey struct{}

type requestSource struct {
	ip        string // canonical text of a valid IP, or ""
	userAgent string // sanitised and truncated, or ""
}

// maxStoredUserAgent bounds user_session.user_agent. The header is attacker-controlled and unbounded
// up to the server's header limit; a few hundred bytes identify a browser and bound the row size.
const maxStoredUserAgent = 256

func (s *Server) sourceIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var src requestSource
		if !isServiceRoute(r.URL.Path) {
			src.userAgent = sanitizeUserAgent(r.Header.Get("User-Agent"))
			if ip := resolveClientIP(r, s.trustProxyIP, s.trustedProxyNets); ip != nil {
				src.ip = ip.String()
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sourceCtxKey{}, src)))
	})
}

// isServiceRoute reports a signaling -> control-plane route (see "SERVICE-TO-SERVICE ROUTES" above).
func isServiceRoute(path string) bool {
	return path == "/internal" || strings.HasPrefix(path, "/internal/")
}

// sourceIPFrom returns the request's trusted source address, or "" (stored as NULL) when the context
// carries none or the value is not a valid IP. Revalidated here so no caller can persist garbage.
func sourceIPFrom(ctx context.Context) string {
	src, _ := ctx.Value(sourceCtxKey{}).(requestSource)
	return validIPText(src.ip)
}

func userAgentFrom(ctx context.Context) string {
	src, _ := ctx.Value(sourceCtxKey{}).(requestSource)
	return src.userAgent
}

// validIPText returns the canonical form of s when it is an IP address, else "".
func validIPText(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// sanitizeUserAgent makes a header value storable in a text column: invalid UTF-8 and control
// characters (NUL cannot be stored at all) are dropped, then it is cut to maxStoredUserAgent bytes on
// a rune boundary.
func sanitizeUserAgent(ua string) string {
	var b strings.Builder
	for _, r := range ua {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxStoredUserAgent {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
