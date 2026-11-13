package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func getPath(srv *Server, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestHealthzIsPublicLiveness(t *testing.T) {
	srv, _ := newTestServer(nil) // NO principal: /healthz must answer before the auth chain.
	rec := getPath(srv, "/healthz")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("GET /healthz = %d %q, want 200 \"ok\"", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("healthz cache-control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestReadyzReportsDependencyHealth(t *testing.T) {
	// No Ready probe wired (DEV / no DB) → ready.
	devSrv, _ := newTestServer(nil)
	if rec := getPath(devSrv, "/readyz"); rec.Code != http.StatusOK || rec.Body.String() != "ready" {
		t.Fatalf("readyz with no probe = %d %q, want 200 \"ready\"", rec.Code, rec.Body.String())
	}

	// A healthy DB probe → 200 ready.
	okSrv, _ := newTestServer(nil)
	okSrv.Ready = func(context.Context) error { return nil }
	if rec := getPath(okSrv, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz with healthy probe = %d, want 200", rec.Code)
	}

	// A failing DB probe → 503 not ready (hold traffic off this instance).
	downSrv, _ := newTestServer(nil)
	downSrv.Ready = func(context.Context) error { return errors.New("db unreachable") }
	rec := getPath(downSrv, "/readyz")
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready" {
		t.Fatalf("readyz with failing probe = %d %q, want 503 \"not ready\"", rec.Code, rec.Body.String())
	}
}

func TestReadinessGateCachesWithinTTL(t *testing.T) {
	var calls int32
	fakeNow := time.Unix(1000, 0)
	g := newReadinessGate(func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	g.now = func() time.Time { return fakeNow }

	// First probe pings; two more within the TTL are served from cache (one DB round-trip total) —
	// so an unauthenticated probe flood cannot amplify into a DB-ping flood.
	for i := 0; i < 3; i++ {
		if err := g.ready(); err != nil {
			t.Fatalf("ready: %v", err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("checks within TTL = %d, want 1 (cached)", got)
	}

	// Past the TTL, it re-checks.
	fakeNow = fakeNow.Add(readinessTTL + time.Millisecond)
	_ = g.ready()
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("checks after TTL = %d, want 2 (re-checked)", got)
	}
}

func TestReadinessGateNilCheckIsReady(t *testing.T) {
	if err := newReadinessGate(nil).ready(); err != nil {
		t.Fatalf("nil check should be ready, got %v", err)
	}
}

// The probe must run on an INDEPENDENT context, so a disconnecting client cannot poison the shared
// cached result with a cancellation error (which would make a healthy instance report 503 for the TTL).
func TestReadinessGateUsesIndependentContext(t *testing.T) {
	var arrivedCancelled bool
	g := newReadinessGate(func(ctx context.Context) error {
		arrivedCancelled = ctx.Err() != nil
		return nil
	})
	_ = g.ready()
	if arrivedCancelled {
		t.Error("the readiness probe context must not arrive already cancelled (not the caller's context)")
	}
}
