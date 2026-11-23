package controlplane

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicServerSettingsAreTheDocumentedBounds(t *testing.T) {
	s := NewPublicServer("127.0.0.1:0", http.NotFoundHandler(), PublicServerConfig{})
	if s.Protocols == nil || !s.Protocols.HTTP1() || s.Protocols.HTTP2() || s.Protocols.UnencryptedHTTP2() {
		t.Errorf("Protocols must be HTTP/1 only, got %v", s.Protocols)
	}
	if s.TLSNextProto == nil || len(s.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto must be an EMPTY NON-NIL map (HTTP/1.1 only), got %v", s.TLSNextProto)
	}
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 5*time.Second {
		t.Errorf("read timeouts: header %v body %v, want 5s/5s", s.ReadHeaderTimeout, s.ReadTimeout)
	}
	if s.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d, want 16 KiB", s.MaxHeaderBytes)
	}
	if s.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", s.IdleTimeout)
	}
	if DefaultMaxConns != 1024 {
		t.Errorf("default connection cap = %d, want 1024", DefaultMaxConns)
	}
}

func startPublic(t *testing.T, cfg PublicServerConfig, maxConns int, h http.Handler) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewPublicServer("", h, cfg)
	go func() { _ = s.Serve(LimitListener(ln, maxConns)) }()
	return ln.Addr().String(), func() { _ = s.Close() }
}

func TestLimitListenerCapsSimultaneousConnections(t *testing.T) {
	var active, peak atomic.Int32
	addr, stop := startPublic(t, PublicServerConfig{}, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
		active.Add(-1)
	}))
	defer stop()
	done := make(chan struct{}, 6)
	for i := 0; i < 6; i++ {
		go func() {
			c, err := net.Dial("tcp", addr)
			if err == nil {
				_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x.example.test\r\nConnection: close\r\n\r\n"))
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 6; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("connections were not served after earlier ones closed")
		}
	}
	if p := peak.Load(); p > 2 {
		t.Fatalf("peak concurrent handlers = %d with a connection cap of 2", p)
	}
	if peak.Load() < 2 {
		t.Fatalf("peak = %d, the cap should have allowed 2 at once", peak.Load())
	}
}

func readStatusLine(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && line == "" {
		return "EOF:" + err.Error()
	}
	return strings.TrimSpace(line)
}

func TestPublicServerRefusesOversizedHeadersAndHTTP2(t *testing.T) {
	addr, stop := startPublic(t, PublicServerConfig{}, 16, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x.example.test\r\nX-Big: " + strings.Repeat("a", 20<<10) + "\r\n\r\n"))
	if line := readStatusLine(t, c); !strings.HasPrefix(line, "HTTP/1.1 431") {
		t.Errorf("a 20 KiB header: %q, want 431", line)
	}

	// An HTTP/2 prior-knowledge attempt is never multiplexed: the answer is an HTTP/1.1 error, not h2 frames.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_, _ = c2.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if line := readStatusLine(t, c2); !strings.HasPrefix(line, "HTTP/1.1 ") && !strings.HasPrefix(line, "EOF") {
		t.Errorf("h2 preface: %q, want an HTTP/1.1 answer (or a close), never h2 frames", line)
	}
}

func TestPublicServerClosesASlowHeaderConnection(t *testing.T) {
	addr, stop := startPublic(t, PublicServerConfig{ReadHeaderTimeout: 200 * time.Millisecond}, 16, http.NotFoundHandler())
	defer stop()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x.exa")) // never finishes
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, c)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a stalled header was held for %v", d)
	}
}

func TestLimitListenerReleasesTheSlotWhenAConnectionCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(ln, 1)
	defer l.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	c1, _ := net.Dial("tcp", ln.Addr().String())
	defer c1.Close()
	first := <-accepted
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	select {
	case <-accepted:
		t.Fatal("a second connection was accepted beyond the cap")
	case <-time.After(150 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close() // double close must not release twice
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the slot was not released")
	}
}
