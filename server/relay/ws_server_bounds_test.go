package main

// Tests pinning the pre-upgrade HTTP bounds that newWSServer applies. Existing
// tests use httptest.NewServer(wsRelayHandler(...)) and never exercise the real
// server construction, so nothing else would notice a dropped timeout.

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// serveNewWSServer serves a newWSServer-built server on a loopback listener.
// wrap, if non-nil, decorates the handler before serving starts (no race).
func serveNewWSServer(t *testing.T, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newWSServer(ln.Addr().String(), "/relay", NewBroker(5*time.Second, 0))
	if wrap != nil {
		srv.Handler = wrap(srv.Handler)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestNewWSServerStillPairsPeers(t *testing.T) {
	addr := serveNewWSServer(t, nil)
	url := "ws://" + addr + "/relay"

	dial := func() *websocket.Conn {
		ws, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = ws.Close() })
		if err := ws.WriteMessage(websocket.TextMessage, []byte(tokenA)); err != nil {
			t.Fatalf("write token: %v", err)
		}
		return ws
	}
	a, b := dial(), dial()

	expect := func(from, to *websocket.Conn, payload string) {
		t.Helper()
		if err := from.WriteMessage(websocket.BinaryMessage, []byte(payload)); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		_ = to.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, got, err := to.ReadMessage()
		if err != nil {
			t.Fatalf("read %q: %v", payload, err)
		}
		if string(got) != payload {
			t.Fatalf("got %q, want %q", got, payload)
		}
	}
	expect(a, b, "ping-from-a")
	expect(b, a, "pong-from-b")
}

func TestNewWSServerClosesStalledHeaders(t *testing.T) {
	old := wsReadHeaderTimeout
	wsReadHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { wsReadHeaderTimeout = old })

	addr := serveNewWSServer(t, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Request line and Host only; no terminating blank line.
	if _, err := c.Write([]byte("GET /relay HTTP/1.1\r\nHost: " + addr + "\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue // a 408 body may precede the close; keep draining
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("server never closed a connection with unfinished headers: %v", err)
		}
		return // EOF or reset: closed by the server
	}
}

func TestNewWSServerRejectsOversizedHeaders(t *testing.T) {
	var reached atomic.Int32
	addr := serveNewWSServer(t, func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Add(1)
			inner.ServeHTTP(w, r)
		})
	})

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Well beyond wsMaxHeaderBytes (net/http allows a small slack on top).
	req := "GET /relay HTTP/1.1\r\nHost: " + addr + "\r\nX-Pad: " +
		strings.Repeat("a", 4*wsMaxHeaderBytes) + "\r\n\r\n"
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte(req)) // the server may reset mid-write; that is acceptable

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("status = %d, want 431", resp.StatusCode)
		}
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server neither answered nor closed: %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("oversized request reached the handler %d time(s)", n)
	}
}

func TestNewWSServerDeclaresBounds(t *testing.T) {
	srv := newWSServer("127.0.0.1:0", "/relay", NewBroker(time.Second, 0))
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want > 0", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != wsMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, wsMaxHeaderBytes)
	}
	// Long-lived relayed sessions must not be cut by blanket timeouts.
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || srv.IdleTimeout != 0 {
		t.Fatalf("unexpected blanket timeouts: read=%v write=%v idle=%v",
			srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
