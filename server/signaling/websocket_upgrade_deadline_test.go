package main

import (
	"bufio"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise handleWS's real Gorilla upgrade against a pipe whose client never reads the101.
// No production network or fake replacement of admission/upgrade logic is involved.
func TestUpgradeWriteIsBoundedByPreAuthWindow(t *testing.T) {
	srv, err := NewServer(time.Minute, "unused:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetAdmissionLimits(admissionLimits{maxTotal: 1, maxPending: 1, preAuthTimeout: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	deadlines := make(chan time.Time, 1)
	conn := &observedDeadlineConn{Conn: serverConn, deadlines: deadlines}
	writer := &pipeUpgradeWriter{ResponseRecorder: httptest.NewRecorder(), conn: conn}
	req := httptest.NewRequest("GET", "http://localhost/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("upgrade handler did not stop")
		}
	})
	started := time.Now()
	go func() { defer close(done); srv.handleWS(writer, req) }()
	select {
	case deadline := <-deadlines:
		if deadline.After(started.Add(500 * time.Millisecond)) {
			t.Fatal("upgrade write deadline ignored the shorter pre-auth window")
		}
	case <-time.After(time.Second):
		t.Fatal("Gorilla did not arm an upgrade write deadline")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("non-reading handshake outlived its pre-auth window")
	}
	if _, total, pending := srv.admission.snapshot(); total != 0 || pending != 0 {
		t.Fatal("failed upgrade did not release both reservations")
	}
}

type observedDeadlineConn struct {
	net.Conn
	deadlines chan time.Time
}

func (c *observedDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		select {
		case c.deadlines <- deadline:
		default:
		}
	}
	return c.Conn.SetWriteDeadline(deadline)
}

type pipeUpgradeWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *pipeUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
