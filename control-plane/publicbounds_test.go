package controlplane

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deadlineRecorder is a ResponseWriter that exposes the connection deadlines the way the real server does.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	write, read time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.write = t; return nil }
func (d *deadlineRecorder) SetReadDeadline(t time.Time) error  { d.read = t; return nil }

func boundsServer(t *testing.T, limit time.Duration) *Server {
	t.Helper()
	srv, _ := newAttendedServer(t)
	srv.HostPolicy = testPolicy(t, gateSecret)
	srv.PublicExchangeLimit = limit
	srv.RedeemTuning = RedeemTuning{Floor: -1}
	return srv
}

// Every public exchange, including an IMMEDIATE refusal (421 from the gate, 429 from admission), gets the
// 2 s write and read deadlines; internal (unmarked) requests and the documented exceptions get none.
func TestPublicExchangesGetDeadlinesEvenWhenRefusedImmediately(t *testing.T) {
	srv := boundsServer(t, 0) // default 2 s
	h := srv.Handler()
	do := func(host, path string, marked bool) (*deadlineRecorder, time.Time) {
		req := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		req.Host = host
		if marked {
			req.Header.Set(EdgeMarkerHeader, gateSecret)
		}
		rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		at := time.Now()
		h.ServeHTTP(rec, req)
		return rec, at
	}
	near := func(what string, got, at time.Time) {
		t.Helper()
		if d := got.Sub(at); got.IsZero() || d < 1900*time.Millisecond || d > 2100*time.Millisecond {
			t.Errorf("%s: deadline %v after the request, want ~2 s", what, d)
		}
	}
	// 421 from the authority gate (bad authority).
	rec, at := do("evil.example.com", "/attended-sessions/redeem", true)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("gate refusal: %d", rec.Code)
	}
	near("421 write", rec.write, at)
	near("421 read", rec.read, at)
	// A FORGED marker is bounded too.
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec2 := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req.Header.Set(EdgeMarkerHeader, "forged")
	req.URL.Path = "/auth/session"
	h.ServeHTTP(rec2, req)
	if rec2.write.IsZero() {
		t.Error("a forged-marker request was not bounded")
	}
	// 429 from admission (pool exhausted by one IP).
	srv.RedeemTuning = RedeemTuning{AdmitPerIP: 1, AdmitGlobal: 1, Floor: -1}
	release, ok := srv.redeemPool().Acquire("192.0.2.1")
	if !ok {
		t.Fatal("setup")
	}
	defer release()
	req = httptest.NewRequest("POST", "/attended-sessions/redeem", strings.NewReader(`{}`))
	req.Host = "main.deskrally.com"
	req.RemoteAddr = "192.0.2.1:1"
	req.Header.Set(EdgeMarkerHeader, gateSecret)
	rec3 := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	at = time.Now()
	h.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("admission refusal: %d", rec3.Code)
	}
	near("429 write", rec3.write, at)

	// Internal (no marker) and the documented exceptions are untouched.
	for _, c := range []struct {
		path   string
		marked bool
	}{{"/healthz", false}, {"/recordings/abc/download", true}, {"/audit/export", true}, {recRoutePrefix + "/x/finish", true}} {
		req := httptest.NewRequest("GET", c.path, nil)
		req.Host = "main.deskrally.com"
		if c.marked {
			req.Header.Set(EdgeMarkerHeader, gateSecret)
		}
		rr := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		h.ServeHTTP(rr, req)
		if !rr.write.IsZero() || !rr.read.IsZero() {
			t.Errorf("%s (marked=%v) must keep its own limits, got deadlines %v %v", c.path, c.marked, rr.write, rr.read)
		}
	}
}

// The request context is cancelled at the limit, and a response that starts late closes the connection.
func TestPublicExchangeContextIsCancelledAndLateResponsesCloseTheConnection(t *testing.T) {
	srv := boundsServer(t, 150*time.Millisecond)
	slow := srv.publicExchangeBounds(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set(EdgeMarkerHeader, gateSecret)
	rec := httptest.NewRecorder()
	start := time.Now()
	slow.ServeHTTP(rec, req)
	if d := time.Since(start); d < 140*time.Millisecond || d > 600*time.Millisecond {
		t.Errorf("handler ran %v, want it cancelled at the 150 ms limit", d)
	}
	if rec.Header().Get("Connection") != "close" {
		t.Errorf("a response released after the limit must say Connection: close, headers %v", rec.Header())
	}
	// A prompt response is NOT forced closed.
	fast := srv.publicExchangeBounds(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	rec = httptest.NewRecorder()
	fast.ServeHTTP(rec, req)
	if rec.Header().Get("Connection") != "" {
		t.Errorf("a prompt response was marked close: %v", rec.Header())
	}
}

// REAL TCP: a client that stalls its request body on a public route is cut at the limit, not at the 5 s
// server ReadTimeout, and the connection is not reused.
func TestPublicRouteStalledBodyIsCutAtTheLimit(t *testing.T) {
	srv := boundsServer(t, 300*time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := NewPublicServer("", srv.Handler(), PublicServerConfig{})
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("POST /attended-sessions/redeem HTTP/1.1\r\nHost: main.deskrally.com\r\n" + EdgeMarkerHeader + ": " + gateSecret +
		"\r\nContent-Length: 200\r\nContent-Type: application/json\r\n\r\n{\"code\":"))
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n') // either an HTTP error status or EOF: never a hang
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("the stalled body held the exchange for %v (limit 300 ms, ReadTimeout 5 s): %q", d, line)
	}
	// The connection is gone: a further read returns EOF/closed, not data.
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	for {
		if _, err := c.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the connection was left open after the timed-out exchange")
			}
			break
		}
	}
}

// REAL TCP: a handler that ignores cancellation and does NO I/O loses its connection at the limit, whether or not
// the headers were already sent; the handler goroutine finishing later causes no panic and no leak.
func TestStalledHandlerLosesItsConnectionAtTheLimit(t *testing.T) {
	for _, afterHeaders := range []bool{false, true} {
		name := map[bool]string{false: "before-headers", true: "after-headers"}[afterHeaders]
		t.Run(name, func(t *testing.T) {
			srv := boundsServer(t, 250*time.Millisecond)
			finished := make(chan struct{})
			var panicked atomic.Bool
			stalled := srv.publicExchangeBounds(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if recover() != nil {
						panicked.Store(true)
					}
					close(finished)
				}()
				if afterHeaders {
					w.Header().Set("Content-Length", "100")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				}
				time.Sleep(900 * time.Millisecond) // deaf to the context, no I/O at all
				_, _ = w.Write([]byte("late"))     // the connection is gone: must fail quietly
			}))
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			hs := NewPublicServer("", stalled, PublicServerConfig{})
			go func() { _ = hs.Serve(ln) }()
			defer hs.Close()

			before := runtime.NumGoroutine()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = c.Write([]byte("GET /x HTTP/1.1\r\nHost: main.deskrally.com\r\n" + EdgeMarkerHeader + ": " + gateSecret + "\r\n\r\n"))
			start := time.Now()
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err = io.Copy(io.Discard, c) // returns when the server closes the connection
			el := time.Since(start)
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || el < 200*time.Millisecond || el > 600*time.Millisecond {
				t.Fatalf("the connection was closed after %v (err %v), want ~250 ms, long before the handler's 900 ms", el, err)
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("the handler goroutine never finished")
			}
			if panicked.Load() {
				t.Fatal("the late write panicked")
			}
			eventually(t, 2*time.Second, "goroutines", func() bool { return runtime.NumGoroutine() <= before+2 })
		})
	}
}

// A prompt exchange is untouched, the expiry timer is stopped, and the keep-alive connection stays usable
// beyond the limit.
func TestExpiryTimerIsCancelledWhenTheHandlerReturns(t *testing.T) {
	srv := boundsServer(t, 150*time.Millisecond)
	fast := srv.publicExchangeBounds(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := NewPublicServer("", fast, PublicServerConfig{})
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	req := "GET /x HTTP/1.1\r\nHost: main.deskrally.com\r\n" + EdgeMarkerHeader + ": " + gateSecret + "\r\n\r\n"
	for i := 0; i < 2; i++ {
		_, _ = c.Write([]byte(req))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 204") {
			t.Fatalf("request %d: %q %v", i, line, err)
		}
		for {
			l, _ := br.ReadString('\n')
			if l == "\r\n" || l == "" {
				break
			}
		}
		time.Sleep(250 * time.Millisecond) // well past the limit: the (stopped) timer must not close the connection
	}
}
