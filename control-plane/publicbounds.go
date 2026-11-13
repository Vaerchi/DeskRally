package controlplane

// Universal bound on PUBLIC exchanges (docs/66 2d.2, 2e.2). Every request that arrives through the public
// ingress (it carries the edge marker, valid or forged) runs under:
//
//   - a request context cancelled at 2 s after the request was accepted,
//   - a write deadline of 2 s (so a stalled reader cannot hold the exchange, and an immediate 421/429/403
//     refusal is not allowed to hold a connection longer than an admitted request),
//   - a read deadline of 2 s for the body (a stalled body is cut; the server-level ReadTimeout stays 5 s),
//   - `Connection: close` on any response that starts after the limit has already passed, so a timed-out
//     exchange is never kept alive for reuse.
//
// This wrapper sits OUTSIDE the authority gate, so the gate's own 421 refusals are bounded too.
//
// EXCEPTIONS (documented, they keep their own deadlines): central-recording upload (per-route deadlines through
// http.ResponseController, http_recording_upload.go), recording playback / download, and the audit export,
// archive and backstage-export streams. Internal (unmarked) requests are never touched: signaling, health
// probes and the compose network keep their own limits.

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultPublicExchangeLimit is the 2 s bound.
const DefaultPublicExchangeLimit = 2 * time.Second

func publicBoundsExempt(path string) bool {
	for _, p := range []string{recRoutePrefix, "/recordings", "/audit/export", "/audit/archive", "/audit/backstage/export"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// boundedWriter marks the connection for closing when the response starts after the exchange limit.
type boundedWriter struct {
	http.ResponseWriter
	start time.Time
	limit time.Duration
	ctx   context.Context
}

func (b *boundedWriter) WriteHeader(code int) {
	if b.ctx.Err() != nil || time.Since(b.start) >= b.limit {
		b.ResponseWriter.Header().Set("Connection", "close")
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	// An implicit WriteHeader inside Write must pass through ours.
	if b.ResponseWriter.Header().Get("Connection") == "" && (b.ctx.Err() != nil || time.Since(b.start) >= b.limit) {
		b.ResponseWriter.Header().Set("Connection", "close")
	}
	return b.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the real connection's deadlines and Flush.
func (b *boundedWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

func (s *Server) publicExchangeBounds(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.HostPolicy == nil || !s.HostPolicy.GateInstalled() ||
			len(r.Header.Values(EdgeMarkerHeader)) == 0 || publicBoundsExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		limit := s.PublicExchangeLimit
		if limit <= 0 {
			limit = DefaultPublicExchangeLimit
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), limit)
		defer cancel()
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(start.Add(limit))
		_ = rc.SetReadDeadline(start.Add(limit))
		// INDEPENDENT EXPIRY ACTION: at the limit, close the underlying connection itself. Context cancellation and
		// socket deadlines only act on a handler that does I/O or watches the context; a handler stalled without
		// either (before or after the headers went out) loses its connection here. The timer is stopped when the
		// handler returns. The handler goroutine may finish later: its writes then fail harmlessly.
		if c, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok {
			expiry := time.AfterFunc(limit, func() { _ = c.Close() })
			defer expiry.Stop()
		}
		next.ServeHTTP(&boundedWriter{ResponseWriter: w, start: start, limit: limit, ctx: ctx}, r.WithContext(ctx))
	})
}

// Flush forwards to the underlying writer when it can flush.
func (b *boundedWriter) Flush() {
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
