package main

// Tests for the per-connection message-rate budget (msg_rate.go, docs/25 F09).
//
// Unit tests drive connRateLimiter directly with a synthetic clock; integration tests exercise
// the ACTUAL handleWS over an httptest loopback so the budget runs in the real read loop rather
// than a re-wired stand-in.
//
// Mutations guarded:
//   M1: remove the `if !rateLimiter.allow()` block in handleWS  → TestMsgRateLimitEnforcedInHandleWS FAILS
//   M2: return true from allow() unconditionally                 → TestMsgRateLimitEnforcedInHandleWS FAILS
//   M3: remove `r.tokens -= 1.0` from allow()                   → TestConnRateLimiterExceedsBudget FAILS

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --------------------------------------------------------------------------------------------
// Unit tests — connRateLimiter (no network)
// --------------------------------------------------------------------------------------------

// TestConnRateLimiterDisabled verifies that maxPerSec=0 means allow() always returns true
// regardless of how many times it is called. The clock is frozen so no token refill occurs.
func TestConnRateLimiterDisabled(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	r := newConnRateLimiter(0, clk)
	for i := 0; i < 1000; i++ {
		if !r.allow() {
			t.Fatalf("disabled limiter (maxPerSec=0) returned false at call %d", i+1)
		}
	}
}

// TestConnRateLimiterStartsFull verifies that a new limiter starts with a full token bucket so
// the first maxPerSec messages are immediately permitted on a frozen clock.
func TestConnRateLimiterStartsFull(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	for _, max := range []int{1, 3, 10} {
		r := newConnRateLimiter(max, clk)
		for i := 0; i < max; i++ {
			if !r.allow() {
				t.Errorf("maxPerSec=%d: allow() returned false at call %d/%d (token bucket should start full)", max, i+1, max)
			}
		}
	}
}

// TestConnRateLimiterExceedsBudget verifies that the (maxPerSec+1)th call returns false on a
// frozen clock. This is the M3 mutation guard: removing `r.tokens -= 1.0` means tokens are
// never consumed and every call succeeds — this test catches that.
func TestConnRateLimiterExceedsBudget(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	r := newConnRateLimiter(3, clk)

	for i := 0; i < 3; i++ {
		if !r.allow() {
			t.Fatalf("allow() returned false at call %d/3; bucket should have tokens", i+1)
		}
	}
	if r.allow() {
		t.Fatal("4th allow() on a 3-msg/s limiter with frozen clock returned true; expected false (over-budget)")
	}
}

// TestConnRateLimiterRefillsAfterElapsed verifies that advancing the clock refills the bucket so
// a connection that hit the ceiling can send again after a full second.
func TestConnRateLimiterRefillsAfterElapsed(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	r := newConnRateLimiter(5, clk)

	// Drain all 5 tokens.
	for i := 0; i < 5; i++ {
		if !r.allow() {
			t.Fatalf("drain: allow() false at call %d/5", i+1)
		}
	}
	if r.allow() {
		t.Fatal("6th call before refill succeeded; expected over-budget")
	}

	// Advance the clock by exactly 1 second → 5 new tokens.
	now = now.Add(time.Second)
	if !r.allow() {
		t.Fatal("allow() false after 1s advance; expected refill to restore the budget")
	}
}

// TestConnRateLimiterBackwardClock verifies that a backward clock step (e.g. NTP correction,
// live-VM migration) does not drain the token bucket below zero. Without the clamp, a negative
// elapsed would subtract tokens — a 2s correction at maxPerSec=5 would drive tokens from 0 to
// -10, blocking the connection for two further seconds after the clock recovered.
//
// The test proves the clamp by calling allow() at the backward-clock position (which must
// update lastCheck), then advancing 1s forward and confirming the bucket refills normally.
// Without the clamp, the 1s advance adds 5 tokens to -10, leaving tokens at -5 → still denied.
func TestConnRateLimiterBackwardClock(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	r := newConnRateLimiter(5, clk) // lastCheck=T, tokens=5

	// Drain all 5 tokens. After: lastCheck=T, tokens=0.
	for i := 0; i < 5; i++ {
		if !r.allow() {
			t.Fatalf("drain: allow() false at call %d/5", i+1)
		}
	}

	// Step clock BACKWARD by 2s. now=T-2s.
	now = now.Add(-2 * time.Second)

	// Call allow() at the backward-clock position. The bucket is empty so allow() must return
	// false. The important thing is what happens to lastCheck and tokens internally:
	//   With clamp:    elapsed=0 → tokens stays 0; lastCheck moves to T-2s.
	//   Without clamp: elapsed=-2 → tokens += -10 = -10; lastCheck moves to T-2s.
	if r.allow() {
		t.Fatal("allow() returned true on empty bucket after backward clock; expected false")
	}

	// Advance 1s forward from the backward position. now=T-1s.
	// elapsed = (T-1s) - (T-2s) = 1s → tokens += 5.
	//   With clamp:    0 + 5 = 5 → allow() returns true  ✓
	//   Without clamp: -10 + 5 = -5 → allow() returns false  (bug)
	now = now.Add(time.Second)
	if !r.allow() {
		t.Fatal("allow() false after 1s forward step from backward-clock position; " +
			"the backward step must not have drained the bucket below zero")
	}
}

// TestConnRateLimiterCappedAtMax verifies that the bucket never accumulates more than maxPerSec
// tokens, even when a long interval elapses. This prevents a parked connection from banking an
// unlimited burst when it eventually wakes up.
func TestConnRateLimiterCappedAtMax(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	r := newConnRateLimiter(4, clk)

	// Drain all 4 tokens.
	for i := 0; i < 4; i++ {
		_ = r.allow()
	}
	// Advance 10 seconds — would add 40 tokens without the cap.
	now = now.Add(10 * time.Second)

	// Allow 4 messages (the cap).
	for i := 0; i < 4; i++ {
		if !r.allow() {
			t.Fatalf("allow() false at call %d/4 after 10s advance; expected capped refill to 4", i+1)
		}
	}
	// The 5th should be denied — proving the cap held at 4.
	if r.allow() {
		t.Fatal("5th allow() after 10s advance succeeded; token bucket must be capped at maxPerSec=4")
	}
}

// --------------------------------------------------------------------------------------------
// Integration tests — real handleWS over httptest loopback
// --------------------------------------------------------------------------------------------

// candidateFrame is a well-formed candidate message that dispatches to broker.RelayCandidate.
// RelayCandidate fails silently (no session exists, just logs), so no server response is sent —
// making it ideal for consuming rate-limiter tokens without cluttering the client read queue.
// candidate must be the full Candidate struct (addr+kind), not a bare string.
const candidateFrame = `{"type":"candidate","session":"fake-session","candidate":{"addr":"192.0.2.1:8000","kind":"host"}}`

// TestMsgRateLimitEnforcedInHandleWS verifies that a connection whose message rate exceeds the
// ceiling receives a Rejected frame ("message rate limit exceeded") and is then closed.
//
// Mutation guards:
//   M1: remove `if !rateLimiter.allow() { ... }` from handleWS → no Rejected, readUntil times
//       out → FAILS.
//   M2: return true unconditionally from allow() → same failure → FAILS.
func TestMsgRateLimitEnforcedInHandleWS(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       10,
		maxPending:     10,
		preAuthTimeout: 5 * time.Second,
	})

	// Freeze the server clock so the token bucket never refills between sends.
	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }
	// maxPerSec=2: two messages succeed, the third hits the ceiling.
	ts.srv.SetMsgRateLimit(2)

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 3 messages. On a frozen clock only 2 tokens are available; the third triggers the
	// rate limit. Use candidate frames — they produce no server reply on relay failure, so the
	// only "rejected" frame the client will see comes from the rate limiter.
	for i := 0; i < 3; i++ {
		if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
			t.Fatalf("write candidate %d: %v", i+1, err)
		}
	}

	// The server must send a Rejected message before closing.
	raw := readUntil(t, c, "rejected", 3*time.Second)
	var rej Rejected
	if err := json.Unmarshal(raw, &rej); err != nil {
		t.Fatalf("decode rejected: %v", err)
	}
	if !strings.Contains(rej.Reason, "rate limit") {
		t.Fatalf("Rejected.Reason = %q, want \"rate limit\"", rej.Reason)
	}

	// The connection must close after the rejection.
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("connection remained open after rate-limit rejection; expected server to close it")
	}
}

// TestMsgRateLimitSlotReturnedOnClose verifies that the admission slot is released when the
// server closes a rate-limited connection. A leaked slot would lock the server out of accepting
// new connections up to the configured cap.
func TestMsgRateLimitSlotReturnedOnClose(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       2,
		maxPending:     2,
		preAuthTimeout: 5 * time.Second,
	})

	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }
	ts.srv.SetMsgRateLimit(1) // 1 message allowed, 2nd triggers rate limit

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 2 messages — first succeeds, second triggers the rate limit.
	for i := 0; i < 2; i++ {
		_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_ = c.WriteMessage(websocket.TextMessage, []byte(candidateFrame))
	}
	_ = readUntil(t, c, "rejected", 3*time.Second)
	waitForClose(c, 2*time.Second)

	// Both the total and pending admission slots must return to zero.
	if err := ts.waitCounters(0, 0, 2*time.Second); err != nil {
		t.Fatalf("slot not returned after rate-limit close: %v", err)
	}
}

// TestMsgRateLimitDisabledAllowsMany verifies that when msgRateLimit is 0 (disabled, the
// default), many messages can be sent without triggering any rate-limit rejection.
func TestMsgRateLimitDisabledAllowsMany(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       10,
		maxPending:     10,
		preAuthTimeout: 5 * time.Second,
	})
	// msgRateLimit defaults to 0 in NewServer — deliberately not calling SetMsgRateLimit.

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 20 candidate messages as fast as the test can write them.
	for i := 0; i < 20; i++ {
		if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
			t.Fatalf("write candidate %d: %v", i+1, err)
		}
	}

	// The connection must still be alive — no rate-limit rejection should have closed it.
	// waitForClose returns false if no close arrives within the window.
	if waitForClose(c, 300*time.Millisecond) {
		t.Fatal("connection closed unexpectedly with rate limiting disabled; expected it to remain open")
	}
}

// TestMsgRateLimitDepletesAtMinBudget verifies that a maxPerSec=1 budget is depleted after the
// first message and the second triggers rejection through the real handleWS loop.
//
// This is the M3 integration guard: removing `r.tokens -= 1.0` from allow() means the first
// message never consumes a token, so the second message is permitted instead of rejected —
// this test catches that failure at the integration level.
func TestMsgRateLimitDepletesAtMinBudget(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       10,
		maxPending:     10,
		preAuthTimeout: 5 * time.Second,
	})

	// Freeze the clock so the single token is never refilled between sends.
	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }
	ts.srv.SetMsgRateLimit(1) // exactly 1 message allowed; 2nd must be rejected

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// First candidate: consumes the only token. No server response.
	if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
		t.Fatalf("write candidate 1: %v", err)
	}

	// Second candidate: budget is empty (token never refills on frozen clock). Must be rejected.
	if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
		t.Fatalf("write candidate 2: %v", err)
	}

	raw := readUntil(t, c, "rejected", 3*time.Second)
	var rej Rejected
	if err := json.Unmarshal(raw, &rej); err != nil {
		t.Fatalf("decode rejected: %v", err)
	}
	if !strings.Contains(rej.Reason, "rate limit") {
		t.Fatalf("Rejected.Reason = %q, want \"rate limit\" (M3 guard: token was not consumed)", rej.Reason)
	}
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("connection not closed after rate-limit rejection at min budget (maxPerSec=1)")
	}
}

// TestMsgRateLimitAuthenticatedConnectionEnforced verifies that the rate limit applies to
// authenticated (promoted) connections as well — the budget is per-connection lifetime, not
// only during the pre-auth window.
func TestMsgRateLimitAuthenticatedConnectionEnforced(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       10,
		maxPending:     10,
		preAuthTimeout: 5 * time.Second,
	})

	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }
	ts.srv.SetMsgRateLimit(3)

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Authenticate in dev mode (nil resolver) so the pending slot is released, proving the
	// rate limit continues after Promote().
	if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline for register_agent: %v", err)
	}
	reg := []byte(`{"type":"register_agent","device":"dev-001","pubkey":"","tenant":"","nat":"none","os":"TestOS"}`)
	if err := c.WriteMessage(websocket.TextMessage, reg); err != nil {
		t.Fatalf("write register_agent: %v", err)
	}
	// Consume the registered reply — this message counted as the 1st token.
	readUntil(t, c, "registered", 2*time.Second)

	// Register_agent consumed 1 token; 2 remain. Send 2 candidate frames to exhaust the budget.
	for i := 0; i < 2; i++ {
		if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
			t.Fatalf("write candidate %d: %v", i+1, err)
		}
	}
	// 4th message triggers the rate limit on the authenticated (promoted) connection.
	if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline for over-budget: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
		t.Fatalf("write over-budget candidate: %v", err)
	}

	raw := readUntil(t, c, "rejected", 3*time.Second)
	var rej Rejected
	if err := json.Unmarshal(raw, &rej); err != nil {
		t.Fatalf("decode rejected: %v", err)
	}
	if !strings.Contains(rej.Reason, "rate limit") {
		t.Fatalf("Rejected.Reason = %q, want \"rate limit\"", rej.Reason)
	}
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("connection not closed after rate-limit rejection on authenticated connection")
	}
}
