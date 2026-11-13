package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// logBuf is a goroutine-safe log sink: the handlers log from their own goroutines
// while the test reads the buffer.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog redirects the standard logger into a buffer and restores the
// previous writer when the test ends.
func captureLog(t *testing.T) *logBuf {
	t.Helper()
	buf := &logBuf{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// waitForLog polls the buffer until it contains want or the deadline passes. The
// broker closes the connection BEFORE Handle returns and the handler logs, so a
// peer-side EOF does not prove the line has been written yet.
func waitForLog(t *testing.T, buf *logBuf, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		out := buf.String()
		if strings.Contains(out, want) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for log line containing %q; got %q", want, out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRedactTokenHelper: stable, distinct per token, never the full token.
func TestRedactTokenHelper(t *testing.T) {
	a1, a2, b := redactToken(tokenA), redactToken(tokenA), redactToken(tokenB)
	if a1 != a2 {
		t.Fatalf("not stable: %q vs %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("different tokens share fingerprint %q", a1)
	}
	for _, tc := range []struct{ token, got string }{{tokenA, a1}, {tokenB, b}} {
		if strings.Contains(tc.got, tc.token) {
			t.Fatalf("fingerprint %q contains full token", tc.got)
		}
		if len(tc.got) >= len(tc.token) {
			t.Fatalf("fingerprint %q is not shorter than the token", tc.got)
		}
	}
}

// TestTCPTimeoutLogDoesNotLeakToken: a half-connection that times out over real
// TCP logs the transport label and the timeout error, but not the pairing token.
func TestTCPTimeoutLogDoesNotLeakToken(t *testing.T) {
	buf := captureLog(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = serveTCP(ctx, ln, NewBroker(100*time.Millisecond, 0)) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(tokenA + "\n")); err != nil {
		t.Fatalf("write token: %v", err)
	}
	// The server closes the conn on timeout; the log line may land just after.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("waiting for server close: %v", err)
	}

	// Wait for the fingerprinted line: the handler logs after Handle returns,
	// which can be after the client already saw EOF.
	out := waitForLog(t, buf, redactToken(tokenA))
	// Negative control: the buffer really receives the relay's log line.
	if !strings.Contains(out, "relay tcp") || !strings.Contains(out, ErrTimeout.Error()) {
		t.Fatalf("log capture missing tcp timeout line: %q", out)
	}
	if strings.Contains(out, tokenA) {
		t.Fatalf("log leaks full token: %q", out)
	}
	if !strings.Contains(out, redactToken(tokenA)) {
		t.Fatalf("log lacks token fingerprint: %q", out)
	}
	log.Printf("control %s", tokenA)
	if !strings.Contains(buf.String(), tokenA) {
		t.Fatalf("negative control: buffer did not capture a line containing the token")
	}
}

// TestWSTimeoutLogDoesNotLeakToken: same property for the WebSocket handler.
func TestWSTimeoutLogDoesNotLeakToken(t *testing.T) {
	buf := captureLog(t)

	srv := httptest.NewServer(wsRelayHandler("/relay", NewBroker(100*time.Millisecond, 0)))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay"
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, []byte(tokenA)); err != nil {
		t.Fatalf("write token: %v", err)
	}
	// The server closes the conn on timeout; the log line may land just after.
	_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatalf("expected the server to close the unpaired connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server never closed the unpaired connection: %v", err)
	}

	out := waitForLog(t, buf, redactToken(tokenA))
	if !strings.Contains(out, "relay ws") || !strings.Contains(out, ErrTimeout.Error()) {
		t.Fatalf("log capture missing ws timeout line: %q", out)
	}
	if strings.Contains(out, tokenA) {
		t.Fatalf("log leaks full token: %q", out)
	}
	if !strings.Contains(out, redactToken(tokenA)) {
		t.Fatalf("log lacks token fingerprint: %q", out)
	}
	log.Printf("control %s", tokenA)
	if !strings.Contains(buf.String(), tokenA) {
		t.Fatalf("negative control: buffer did not capture a line containing the token")
	}
}

const (
	tokenA = "11111111-1111-1111-1111-111111111111"
	tokenB = "22222222-2222-2222-2222-222222222222"
)

// handle runs one half-connection through the broker and reports the result
// on the returned channel, so tests can assert on ErrTimeout etc.
func handle(b *Broker, token string, s stream) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- b.Handle(token, s) }()
	return ch
}

// startWrite writes p to c from a background goroutine (net.Pipe writes block
// until the peer reads) and reports the write's outcome on the returned
// channel. It never touches *testing.T, so it is safe to run off the test
// goroutine.
func startWrite(c net.Conn, p []byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Write(p)
		done <- err
	}()
	return done
}

// awaitWrite fails the test (from the test goroutine) if the write did not
// complete cleanly.
func awaitWrite(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("write blocked; peers were not spliced")
	}
}

// readN reads exactly n bytes from c with a deadline.
func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// TestSplicePairsAndFlowsBothWays: two in-memory pipes presenting the same
// token are spliced and bytes flow in both directions.
func TestSplicePairsAndFlowsBothWays(t *testing.T) {
	b := NewBroker(2 * time.Second, 0)

	srvA, cliA := net.Pipe()
	srvB, cliB := net.Pipe()
	defer cliA.Close()
	defer cliB.Close()

	_ = handle(b, tokenA, srvA)
	_ = handle(b, tokenA, srvB)

	// A -> B
	ping := []byte("ping")
	w := startWrite(cliA, ping)
	if got := readN(t, cliB, len(ping)); !bytes.Equal(got, ping) {
		t.Fatalf("A->B: got %q want %q", got, ping)
	}
	awaitWrite(t, w)

	// B -> A
	pong := []byte("pong")
	w = startWrite(cliB, pong)
	if got := readN(t, cliA, len(pong)); !bytes.Equal(got, pong) {
		t.Fatalf("B->A: got %q want %q", got, pong)
	}
	awaitWrite(t, w)

	// A larger blob to exercise the io.Copy loop across many pipe reads.
	blob := bytes.Repeat([]byte("x"), 64*1024)
	w = startWrite(cliA, blob)
	if got := readN(t, cliB, len(blob)); !bytes.Equal(got, blob) {
		t.Fatalf("A->B blob mismatch: %d bytes", len(got))
	}
	awaitWrite(t, w)
}

// TestMismatchedTokensDoNotPair: connections with different tokens never
// splice; both are reaped as timeouts.
func TestMismatchedTokensDoNotPair(t *testing.T) {
	b := NewBroker(100 * time.Millisecond, 0)

	srvA, cliA := net.Pipe()
	srvB, cliB := net.Pipe()
	defer cliA.Close()
	defer cliB.Close()

	errA := handle(b, tokenA, srvA)
	errB := handle(b, tokenB, srvB)

	for i, ch := range []<-chan error{errA, errB} {
		select {
		case err := <-ch:
			if err != ErrTimeout {
				t.Fatalf("conn %d: got %v, want ErrTimeout", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("conn %d: never returned; it should have timed out", i)
		}
	}
}

// TestUnpairedTimesOut: a lone half-connection is reaped after the timeout.
func TestUnpairedTimesOut(t *testing.T) {
	b := NewBroker(100 * time.Millisecond, 0)

	srv, cli := net.Pipe()
	defer cli.Close()

	start := time.Now()
	select {
	case err := <-handle(b, tokenA, srv):
		if err != ErrTimeout {
			t.Fatalf("got %v, want ErrTimeout", err)
		}
		if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
			t.Fatalf("timed out too early after %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("lone connection never timed out")
	}

	// After timeout the broker must hold no waiter for the token, so a fresh
	// pair can still form on the same token.
	b.mu.Lock()
	_, still := b.waiting[tokenA]
	b.mu.Unlock()
	if still {
		t.Fatalf("waiter left registered after timeout")
	}
}

// TestArrivalAfterTimeoutReparks: if a peer arrives only after the first side
// was reaped, it must not splice onto the dead connection — it re-parks and
// then times out on its own.
func TestArrivalAfterTimeoutReparks(t *testing.T) {
	b := NewBroker(80 * time.Millisecond, 0)

	srvA, cliA := net.Pipe()
	defer cliA.Close()
	if err := <-handle(b, tokenA, srvA); err != ErrTimeout {
		t.Fatalf("first conn: got %v, want ErrTimeout", err)
	}

	srvB, cliB := net.Pipe()
	defer cliB.Close()
	if err := <-handle(b, tokenA, srvB); err != ErrTimeout {
		t.Fatalf("late second conn: got %v, want ErrTimeout", err)
	}
}

// fencedConn wraps a net.Conn and blocks the very first Read until gate is
// closed. Used by TestFusedTokenPayloadLeftoverPath to guarantee that all
// client bytes have landed in the kernel's TCP receive buffer before
// bufio.Fill runs, making hs.Buffered() deterministically nonzero.
//
// On the first unblocked Read it drains exactly fusedLen bytes from the
// underlying connection via io.ReadFull, storing them in prefill. Subsequent
// calls drain prefill before falling through to the real connection. This
// guarantees bufio.Reader.Fill receives all fused bytes in one call, so
// hs.Buffered() == payloadLen after ReadString — not merely likely, but
// structural.
type fencedConn struct {
	net.Conn
	gate     <-chan struct{}
	once     sync.Once
	fusedLen int    // total bytes in the fused write: len(token)+1+len(payload)
	prefill  []byte // bytes collected by the first ReadFull; drained by Read
}

func (c *fencedConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		<-c.gate
		buf := make([]byte, c.fusedLen)
		if _, err := io.ReadFull(c.Conn, buf); err == nil {
			c.prefill = buf
		}
	})
	if len(c.prefill) > 0 {
		n := copy(p, c.prefill)
		c.prefill = c.prefill[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// TestFusedTokenPayloadLeftoverPath verifies that bytes written past the token
// newline in a single client write survive the handshake and arrive at the
// paired peer intact, exercising the collect-and-prepend path at main.go:150-157:
//
//	leftover := make([]byte, hs.Buffered())
//	io.MultiReader(bytes.NewReader(leftover), conn)
//
// Entry into the leftover path is made deterministic via fencedConn: the
// server's first Read is blocked until clientA.Write returns, then
// io.ReadFull collects exactly fusedLen bytes (36-byte UUID + newline +
// 32-byte payload = 69 bytes) in one syscall. bufio.Fill therefore sees all
// 69 bytes in a single call and hs.Buffered() == 32 after ReadString — not
// just likely, but structural.
//
// Mutation that must fail: replacing io.MultiReader(bytes.NewReader(leftover),conn)
// with just conn on line 157 drops the 32 buffered bytes; B's ReadFull never
// completes within the deadline and the test fails.
func TestFusedTokenPayloadLeftoverPath(t *testing.T) {
	broker := NewBroker(5 * time.Second, 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const tok = "6f1c9a2e-4b7d-4c8e-9a1f-2d3e4b5c6a7b"
	// 32-byte payload; total fused write = 36 (UUID) + 1 (newline) + 32 = 69
	// bytes, well within the LimitReader cap of 129, so every payload byte
	// lands in the bufio buffer before ReadString returns.
	payload := bytes.Repeat([]byte("Z"), 32)
	fusedLen := len(tok) + 1 + len(payload) // computed before accept loop

	gate := make(chan struct{})
	// Only the first accepted connection (client A) is fenced; B proceeds normally.
	// The accept loop is a single goroutine so `first` needs no mutex.
	first := true
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if first {
				first = false
				go handleTCP(&fencedConn{Conn: c, gate: gate, fusedLen: fusedLen}, broker)
			} else {
				go handleTCP(c, broker)
			}
		}
	}()

	clientA, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer clientA.Close()

	fused := append([]byte(tok+"\n"), payload...)
	_ = clientA.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := clientA.Write(fused); err != nil {
		t.Fatalf("write fused: %v", err)
	}
	// Write has returned: all 69 bytes are now in the kernel's TCP receive
	// buffer. Open the gate so fencedConn.Read unblocks and calls
	// io.ReadFull for exactly fusedLen bytes, forcing hs.Buffered() == 32.
	close(gate)

	clientB, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer clientB.Close()

	_ = clientB.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := clientB.Write([]byte(tok + "\n")); err != nil {
		t.Fatalf("write token B: %v", err)
	}

	// The relay splices A's session stream (leftover ++ conn) to B. All 32
	// payload bytes must arrive. Without the leftover prepend B reads nothing
	// before the deadline and the test fails, catching the mutation.
	got := make([]byte, len(payload))
	_ = clientB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientB, got); err != nil {
		t.Fatalf("B did not receive all %d payload bytes (%v) — leftover-prepend path broken",
			len(payload), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted at B: got %q, want %q", got, payload)
	}
}

func TestNormalizeToken(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		ok    bool
	}{
		{tokenA + "\n", tokenA, true},
		{"  " + tokenA + "  ", tokenA, true},
		{"11111111-1111-1111-1111-111111111111", tokenA, true},
		{"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\r\n", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", true},
		{"", "", false},
		{"not-a-uuid", "", false},
		{"11111111111111111111111111111111", "", false}, // no dashes
		{"11111111-1111-1111-1111-11111111111g", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeToken(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("normalizeToken(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
