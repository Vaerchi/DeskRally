package main

// Admission limit tests for the relay broker.
//
// PREMISE, declared locally: the relay's -max-connections / RELAY_MAX_CONNECTIONS limit must be
// enforced BEFORE any bytes are read from the arriving connection. Without that ordering a peer at
// the limit could still push a full 10-second handshake read through the server before being
// rejected, which costs a goroutine, a socket and a receive buffer per attempt.
//
// Four mutations are targeted:
//   M1: remove the `b.activeConns < b.maxConns` guard → cap is never enforced
//   M2: change `<` to `<=` → one extra connection is admitted past the limit
//   M3: remove the `b.activeConns++` increment → the count never grows; limit never reached
//   M4: remove the `b.activeConns--` decrement in Release → freed slots are never reclaimed
//
// Integration mutation (TestHandleTCPAdmissionLimit, TestHandleWSAdmissionLimit):
//   M5: remove the `if !broker.TryAcquire()` block in handleTCP → an over-limit connection is not
//       closed immediately; instead it blocks on the 10-second handshake read deadline, so the
//       100ms assertion window expires with a timeout error.
//   M6: remove the `if !broker.TryAcquire()` block from the newWSServer HTTP handler → an
//       over-limit WebSocket upgrade succeeds (101) instead of returning 503.

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)


// TestBrokerAdmissionUnlimited verifies that a broker with maxConns=0 always
// admits connections regardless of how many are already active.
func TestBrokerAdmissionUnlimited(t *testing.T) {
	b := NewBroker(time.Second, 0)
	for i := 0; i < 100; i++ {
		if !b.TryAcquire() {
			t.Fatalf("TryAcquire %d: got false for unlimited broker", i+1)
		}
	}
	// Release is a no-op for unlimited brokers; confirm it does not panic.
	for i := 0; i < 100; i++ {
		b.Release()
	}
}

// TestBrokerAdmissionRejectsAtCap verifies that TryAcquire returns false once
// the cap is reached.
//
// Mutations targeted:
//   M1: guard removed → third TryAcquire returns true → FAILS
//   M2: `<` → `<=` → third TryAcquire returns true → FAILS
//   M3: `activeConns++` removed → third TryAcquire returns true → FAILS
func TestBrokerAdmissionRejectsAtCap(t *testing.T) {
	b := NewBroker(time.Second, 2)

	if !b.TryAcquire() {
		t.Fatal("first TryAcquire: got false, want true")
	}
	if !b.TryAcquire() {
		t.Fatal("second TryAcquire: got false, want true")
	}
	if b.TryAcquire() {
		t.Fatal("third TryAcquire: got true at cap of 2, want false")
	}
}

// TestBrokerAdmissionReleaseFreesSlot verifies that Release reclaims a slot so
// the next TryAcquire succeeds.
//
// Mutation targeted:
//   M4: `activeConns--` removed in Release → slot never freed → FAILS
func TestBrokerAdmissionReleaseFreesSlot(t *testing.T) {
	b := NewBroker(time.Second, 1)

	if !b.TryAcquire() {
		t.Fatal("first TryAcquire: got false, want true")
	}
	if b.TryAcquire() {
		t.Fatal("second TryAcquire: got true at cap of 1, want false")
	}

	b.Release() // free the one slot

	if !b.TryAcquire() {
		t.Fatal("TryAcquire after Release: got false, want true — Release did not free the slot")
	}
}

// TestHandleTCPAdmissionLimit is an integration test: a real TCP listener runs
// handleTCP against a broker limited to one connection. Client A parks in the
// broker (holding the single slot); client B's connection must be closed
// immediately — before the 10-second handshake deadline — because the relay
// checks admission before reading any bytes.
//
// Mutation targeted (M5):
//   Remove the `if !broker.TryAcquire()` guard in handleTCP. B is now admitted
//   and handleTCP proceeds to SetReadDeadline(10s) then blocks on a token read.
//   B never sends a token, so the deadline fires after 10s. The 100ms assertion
//   window catches this: the Read returns a timeout error instead of EOF/reset,
//   and the test fails with a clear message.
//
// Real TCP is used (not net.Pipe) because the admission check must fire BEFORE
// the server reads anything. With net.Pipe a client write blocks until the
// server reads, so the client's own write deadline becomes the discriminator
// rather than the server's admission logic — exactly the class of problem
// documented in the relay's own handshake bound tests.
func TestHandleTCPAdmissionLimit(t *testing.T) {
	// pair-timeout 400ms >> the ~0ms expected close time for B; << the 10s
	// handshake deadline that governs the mutant path.
	broker := NewBroker(400*time.Millisecond, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go handleTCP(c, broker)
		}
	}()

	// Client A: connect and send a valid token so it parks in the broker,
	// holding the sole admission slot.
	clientA, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer clientA.Close()

	_ = clientA.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := clientA.Write([]byte(tokenA + "\n")); err != nil {
		t.Fatalf("A token write: %v", err)
	}

	// Wait until A is visible in the broker's waiting map. This proves that
	// handleTCP has already called TryAcquire (consuming the slot) before B
	// arrives — no race.
	admitDeadline := time.After(2 * time.Second)
	for {
		broker.mu.Lock()
		_, parked := broker.waiting[tokenA]
		broker.mu.Unlock()
		if parked {
			break
		}
		select {
		case <-admitDeadline:
			t.Fatal("client A never parked in broker; handshake may have failed")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Client B: connect but send nothing. The admission-correct relay closes
	// the connection before reading, so B sees EOF/reset promptly. The mutant
	// (admission check removed) enters a 10-second handshake read — the
	// 100ms deadline catches that.
	clientB, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer clientB.Close()

	_ = clientB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, rerr := clientB.Read(make([]byte, 1))
	if rerr == nil {
		t.Fatal("relay sent data to an over-limit connection")
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("relay held an over-limit connection open for ≥100ms: " +
			"admission check missing or not running before the handshake read")
	}
	// Any non-timeout error (io.EOF, connection reset) is correct: the relay
	// closed the connection without reading.
	if rerr != io.EOF {
		// net.OpError wrapping a "connection reset" or "broken pipe" is also fine.
		t.Logf("B close reason: %v (non-EOF close is fine)", rerr)
	}
}

// TestHandleWSAdmissionLimit verifies that the WebSocket HTTP handler returns
// HTTP 503 when the broker is at capacity, WITHOUT completing the WebSocket
// upgrade (101). This is the SEC-001 fix: the admission check must run BEFORE
// gorilla's Upgrade so a refused connection never completes the HTTP handshake.
//
// Mutation targeted (M6):
//   Remove the `if !broker.TryAcquire()` guard from the HTTP handler in
//   newWSServer. Gorilla's Upgrade succeeds and returns 101, so
//   websocket.DefaultDialer.Dial returns nil error instead of an upgrade
//   error. The t.Fatal at "WS dial succeeded at capacity" fires.
func TestHandleWSAdmissionLimit(t *testing.T) {
	broker := NewBroker(time.Second, 1)

	// Use wsRelayHandler (the production handler extracted from newWSServer) so
	// a mutation of wsRelayHandler is directly caught — not a test-only copy.
	srv := httptest.NewServer(wsRelayHandler("/relay", broker))
	defer srv.Close()

	// Fill the sole admission slot directly — no real connection needed.
	if !broker.TryAcquire() {
		t.Fatal("pre-fill TryAcquire failed")
	}
	defer broker.Release()

	// Attempt a WebSocket dial while the broker is at capacity.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("WS dial succeeded at capacity: admission check bypassed (upgrade returned 101)")
	}
	if resp == nil {
		t.Fatalf("expected HTTP 503, got nil response (no HTTP response at all); err=%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503 ServiceUnavailable, got %d: "+
			"admission check is not rejecting before the upgrade", resp.StatusCode)
	}
}
