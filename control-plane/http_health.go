package controlplane

// Health endpoints for load balancers, orchestrators, and uptime monitoring. Both are PUBLIC
// (unauthenticated) and mounted on the root mux, like the signaling server's /healthz:
//
//	GET /healthz → 200 "ok" if the process is serving. LIVENESS: no dependency is touched, so a
//	    restart loop is driven only by the process being up, never by a transient DB blip.
//	GET /readyz  → 200 "ready" when the backing database is reachable, 503 "not ready" otherwise.
//	    READINESS: used to hold traffic off an instance whose DB is unreachable. Nil Ready probe
//	    (DEV / no DB) reports ready. The result is CACHED for a short TTL so a flood of probes cannot
//	    be amplified into a flood of DB pings (an unauthenticated endpoint must not be a DB-load lever).

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const (
	// readinessTTL bounds how often the DB is actually pinged: within the window, probes get the last
	// result. Short enough that a real outage surfaces quickly, long enough that probe spam is cheap.
	readinessTTL = 2 * time.Second
	// readinessPingTimeout bounds a single DB ping so a hung database cannot wedge the probe.
	readinessPingTimeout = 2 * time.Second
)

// readinessGate caches the result of the readiness probe. One ping at a time (the mutex is held
// across the check), so concurrent probes within a window collapse onto a single DB round-trip.
type readinessGate struct {
	check func(context.Context) error
	now   func() time.Time // injectable for tests

	mu        sync.Mutex
	primed    bool
	checkedAt time.Time
	lastErr   error
}

func newReadinessGate(check func(context.Context) error) *readinessGate {
	return &readinessGate{check: check, now: time.Now}
}

// ready reports the (possibly cached) readiness. A nil check is always ready.
//
// The probe runs on an INDEPENDENT context (context.Background + the ping timeout), NOT the triggering
// request's: the result is shared across all probes, so if it inherited the caller's context a single
// client disconnecting mid-ping would cache a cancellation error and make this healthy instance report
// 503 to every orchestrator probe for the TTL — a trivial way to knock a healthy instance out of the
// rotation. Only a real ping timeout or a real DB error is ever cached.
func (g *readinessGate) ready() error {
	if g.check == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.primed && g.now().Sub(g.checkedAt) < readinessTTL {
		return g.lastErr
	}
	pctx, cancel := context.WithTimeout(context.Background(), readinessPingTimeout)
	defer cancel()
	g.lastErr = g.check(pctx)
	g.checkedAt = g.now()
	g.primed = true
	return g.lastErr
}

// handleLivez is the liveness probe: the process is serving, so 200. No dependency is consulted.
func handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// makeReadyzHandler returns the readiness probe over the given gate.
func makeReadyzHandler(gate *readinessGate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if err := gate.ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}
}
