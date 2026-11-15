package controlplane

// Security review 2026-11-01 #5: recording playback/download must not hold the request's pinned
// tenant DB connection while streaming bytes, and must be capped per tenant and per user.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countBinder is a TenantBinder whose "connection" is a counter, so a test can see whether a
// handler still holds its pinned connection at any instant.
type countBinder struct{ held atomic.Int64 }

func (b *countBinder) BindTenant(ctx context.Context, tenantID string) (context.Context, func(), error) {
	bc := &boundConn{tenantID: tenantID}
	b.held.Add(1)
	bc.releaseFn = func() { b.held.Add(-1) }
	return context.WithValue(ctx, boundConnKey{}, bc), bc.release, nil
}

// obsWriter observes every body Write of a handler and can stall it (a slow-reading client).
type obsWriter struct {
	http.ResponseWriter
	onWrite func()
}

func (o *obsWriter) Write(p []byte) (int, error) {
	o.onWrite()
	return o.ResponseWriter.Write(p)
}
func (o *obsWriter) SetWriteDeadline(t time.Time) error {
	return http.NewResponseController(o.ResponseWriter).SetWriteDeadline(t)
}
func (o *obsWriter) Unwrap() http.ResponseWriter { return o.ResponseWriter }

// While the body is being written, the request holds NO pinned connection; it did hold one before.
func TestConsoleStreamAndDownloadReleaseTheTenantConnectionBeforeStreaming(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(bigFrames(120, 3000))
	cb := &countBinder{}
	c.srv.Binder = cb
	inner := c.srv.Handler()

	for _, route := range []string{"/segments/0/stream", "/download"} {
		var mu sync.Mutex
		var heldAtWrite []int64
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(&obsWriter{ResponseWriter: w, onWrite: func() {
				mu.Lock()
				heldAtWrite = append(heldAtWrite, cb.held.Load())
				mu.Unlock()
			}}, r)
		}))
		req, _ := http.NewRequest("GET", ts.URL+fx.path(route), nil)
		req.Header.Set("X-Test-Principal", "owner")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		ts.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", route, resp.StatusCode)
		}
		mu.Lock()
		if len(heldAtWrite) == 0 {
			t.Fatalf("%s: no body writes observed", route)
		}
		for i, h := range heldAtWrite {
			if h != 0 {
				t.Fatalf("%s: write %d happened while %d pinned connection(s) were held", route, i, h)
			}
		}
		mu.Unlock()
		if got := cb.held.Load(); got != 0 {
			t.Fatalf("%s: %d connections still held after the request", route, got)
		}
	}
}

// A refused (non-streaming) request still hands its connection back through the middleware.
func TestReleaseBoundConnIsIdempotentAndHidesTheConnection(t *testing.T) {
	cb := &countBinder{}
	ctx, release, _ := cb.BindTenant(context.Background(), "t1")
	if boundConnFrom(ctx) == nil || cb.held.Load() != 1 {
		t.Fatal("bound connection should be visible and held")
	}
	releaseBoundConn(ctx)
	releaseBoundConn(ctx)
	release() // the middleware's deferred call
	if boundConnFrom(ctx) != nil {
		t.Fatal("a released connection must no longer be returned to stores")
	}
	if cb.held.Load() != 0 {
		t.Fatalf("held = %d after release, want 0 (and never negative)", cb.held.Load())
	}
}

// Per-tenant and per-user caps on concurrent content streams, with a deterministic slow client:
// the server side blocks inside Write until the gate opens.
func TestConsoleStreamAndDownloadConcurrencyCaps(t *testing.T) {
	c := newConsoleH(t)
	fx := c.ready(bigFrames(120, 3000))
	c.srv.Recording.StreamsPerTenant = 3
	c.srv.Recording.StreamsPerUser = 2
	inner := c.srv.Handler()

	for _, route := range []string{"/segments/0/stream", "/download"} {
		gate := make(chan struct{})
		entered := make(chan struct{}, 8)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var once sync.Once
			inner.ServeHTTP(&obsWriter{ResponseWriter: w, onWrite: func() {
				// Only CONTENT writes stall; a refusal's JSON body must go straight out.
				if ct := w.Header().Get("Content-Type"); ct != "video/webm" && ct != "application/zip" {
					return
				}
				once.Do(func() { entered <- struct{}{} })
				<-gate
			}}, r)
		}))
		type result struct {
			code  int
			retry string
		}
		start := func(who string) chan result {
			ch := make(chan result, 1)
			go func() {
				req, _ := http.NewRequest("GET", ts.URL+fx.path(route), nil)
				req.Header.Set("X-Test-Principal", who)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					ch <- result{code: -1}
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				ch <- result{resp.StatusCode, resp.Header.Get("Retry-After")}
			}()
			return ch
		}
		waitEntered := func() {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: a stream never reached its body", route)
			}
		}
		quick := func(who, method string) result {
			req, _ := http.NewRequest(method, ts.URL+fx.path(route), nil)
			req.Header.Set("X-Test-Principal", who)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", route, err)
			}
			resp.Body.Close()
			return result{resp.StatusCode, resp.Header.Get("Retry-After")}
		}

		o1, o2 := start("owner"), start("owner")
		waitEntered()
		waitEntered()
		// Per-user cap: the owner's third concurrent stream is refused.
		if r := quick("owner", "GET"); r.code != http.StatusTooManyRequests || r.retry == "" {
			t.Fatalf("%s: third stream of one user = %+v, want 429 with Retry-After", route, r)
		}
		// A different user in the same tenant still fits (tenant 2 of 3)...
		a1 := start("admin")
		waitEntered()
		// ...and then the TENANT cap (3) refuses a third user, though that user holds none.
		if r := quick("auditor", "GET"); r.code != http.StatusTooManyRequests {
			t.Fatalf("%s: tenant over its cap = %+v, want 429", route, r)
		}
		// A HEAD releases no content and takes no slot.
		if r := quick("auditor", "HEAD"); r.code != http.StatusOK {
			t.Fatalf("%s: HEAD at the cap = %d, want 200", route, r.code)
		}
		close(gate)
		for _, ch := range []chan result{o1, o2, a1} {
			if r := <-ch; r.code != http.StatusOK {
				t.Fatalf("%s: held stream finished with %d", route, r.code)
			}
		}
		// Slots are returned: the same user streams again.
		if r := quick("owner", "GET"); r.code != http.StatusOK {
			t.Fatalf("%s: after release = %d, want 200", route, r.code)
		}
		ts.Close()
	}
}

func TestRecStreamLimiterAccounting(t *testing.T) {
	var l recStreamLimiter
	r1, ok1 := l.acquire("t", "u", 2, 2)
	r2, ok2 := l.acquire("t", "u", 2, 2)
	if !ok1 || !ok2 {
		t.Fatal("first two must fit")
	}
	if _, ok := l.acquire("t", "v", 2, 2); ok {
		t.Fatal("tenant cap of 2 must refuse a third")
	}
	r1()
	r1() // double release must not free a second slot
	if _, ok := l.acquire("t", "v", 2, 2); !ok {
		t.Fatal("a freed slot must be reusable")
	}
	if _, ok := l.acquire("t", "v", 2, 2); ok {
		t.Fatal("a double release freed more than one slot")
	}
	r2()
	if _, ok := l.acquire("other-tenant", "u", 2, 2); !ok {
		t.Fatal("another tenant has its own budget")
	}
}
