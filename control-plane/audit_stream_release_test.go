package controlplane

// Review repair 3 (#5 for exports): the management export and the archive release the request's
// pinned tenant connection before streaming, and exports are capped per tenant.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func auditStreamServer(t *testing.T, onWrite func(w http.ResponseWriter, held int64)) (*httptest.Server, *countBinder) {
	t.Helper()
	p := auditorPrincipal()
	srv, _ := newTestServer(p)
	srv.Audit = NewInMemoryAuditStore()
	cb := &countBinder{}
	srv.Binder = cb
	seedMgmt(t, srv, 5)
	inner := srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(&obsWriter{ResponseWriter: w, onWrite: func() { onWrite(w, cb.held.Load()) }}, r)
	}))
	t.Cleanup(ts.Close)
	return ts, cb
}

func TestAuditExportAndArchiveReleaseTheTenantConnectionBeforeStreaming(t *testing.T) {
	for _, route := range []string{"/audit/export", "/audit/archive"} {
		var mu sync.Mutex
		var held []int64
		ts, cb := auditStreamServer(t, func(w http.ResponseWriter, h int64) {
			ct := w.Header().Get("Content-Type")
			if ct == "application/x-ndjson" || ct == "application/zip" {
				mu.Lock()
				held = append(held, h)
				mu.Unlock()
			}
		})
		resp, err := http.Get(ts.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", route, resp.StatusCode)
		}
		mu.Lock()
		if len(held) == 0 {
			t.Fatalf("%s: no body writes observed", route)
		}
		for i, h := range held {
			if h != 0 {
				t.Fatalf("%s: body write %d happened with %d pinned connection(s)", route, i, h)
			}
		}
		mu.Unlock()
		if cb.held.Load() != 0 {
			t.Fatalf("%s: %d connections held after the request", route, cb.held.Load())
		}
	}
}

func TestAuditExportsAreCappedPerTenant(t *testing.T) {
	for _, route := range []string{"/audit/export", "/audit/archive"} {
		gate := make(chan struct{})
		entered := make(chan struct{}, 4)
		ts, _ := auditStreamServer(t, func(w http.ResponseWriter, _ int64) {
			ct := w.Header().Get("Content-Type")
			if ct != "application/x-ndjson" && ct != "application/zip" {
				return
			}
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		})
		var done sync.WaitGroup
		var okCount atomic.Int64
		for i := 0; i < auditExportPerTenant; i++ {
			done.Add(1)
			go func() {
				defer done.Done()
				resp, err := http.Get(ts.URL + route)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					okCount.Add(1)
				}
			}()
		}
		for i := 0; i < auditExportPerTenant; i++ {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: a stream never started", route)
			}
		}
		resp, err := http.Get(ts.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%s: third concurrent export = %d, want 429 with Retry-After", route, resp.StatusCode)
		}
		close(gate)
		done.Wait()
		if okCount.Load() != int64(auditExportPerTenant) {
			t.Fatalf("%s: %d of the held exports completed OK", route, okCount.Load())
		}
	}
}
