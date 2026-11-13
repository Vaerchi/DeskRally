package main

// Tests for the per-connection diagnostic log rate limiter (conn_log_limiter.go, docs/25 F19).
//
// Unit tests drive connLogLimiter directly with a synthetic clock; those that verify log
// output use captureLog and must NOT call t.Parallel (global logger redirected). Those that
// verify only return values and counter state are safe to run in parallel.
//
// Integration tests exercise the ACTUAL handleWS over an httptest loopback. These too must
// NOT call t.Parallel because they redirect the global logger.
//
// Mutations guarded:
//   M1: remove `if l.tokens < 1.0 { l.suppressed++; return false }` in logf
//       → suppression never fires → TestConnLogLimiterSuppressesOverBudget FAILS
//   M2: remove `l.tokens -= 1.0` in logf
//       → tokens never consumed → TestConnLogLimiterSuppressesOverBudget FAILS
//   M3: remove flush call from cleanup (main.go)
//       → TestConnLogLimiterFlushOnConnectionClose FAILS

import (
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --------------------------------------------------------------------------------------------
// Unit tests — connLogLimiter (no network, no logger redirect)
// --------------------------------------------------------------------------------------------

// TestConnLogLimiterDisabled verifies that maxPerSec=0 means logf always returns true
// regardless of how many calls are made, with a frozen clock so no refill occurs.
func TestConnLogLimiterDisabled(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	l := newConnLogLimiter(0, clk)
	for i := 0; i < 100; i++ {
		if !l.logf("disabled %d", i) {
			t.Fatalf("disabled limiter (maxPerSec=0) returned false at call %d", i+1)
		}
	}
}

// TestConnLogLimiterStartsFull verifies that a new limiter starts with a full token bucket so
// the first maxPerSec calls return true on a frozen clock.
func TestConnLogLimiterStartsFull(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	for _, max := range []int{1, 3, 10} {
		l := newConnLogLimiter(max, clk)
		for i := 0; i < max; i++ {
			if !l.logf("start full max=%d call=%d", max, i) {
				t.Errorf("maxPerSec=%d: logf false at call %d/%d (bucket should start full)", max, i+1, max)
			}
		}
	}
}

// TestConnLogLimiterSuppressesOverBudget verifies that the (maxPerSec+1)th call on a frozen
// clock returns false and that the suppressed counter increments for each further call.
//
// Mutation guards:
//   M1: skip suppression check → logf always returns true → t.Fatal("over-budget") fires.
//   M2: skip token decrement  → tokens never consumed → all calls return true → same failure.
func TestConnLogLimiterSuppressesOverBudget(t *testing.T) {
	t.Parallel()
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	const max = 3
	l := newConnLogLimiter(max, clk)

	for i := 0; i < max; i++ {
		if !l.logf("within budget %d", i) {
			t.Fatalf("logf false at call %d/%d; bucket should have tokens", i+1, max)
		}
	}
	if l.logf("over budget") {
		t.Fatal("(maxPerSec+1)th logf on frozen clock returned true; expected false (over-budget)")
	}
	if l.suppressed != 1 {
		t.Fatalf("suppressed = %d after one over-budget call, want 1", l.suppressed)
	}
	for i := 0; i < 5; i++ {
		if l.logf("extra %d", i) {
			t.Fatalf("extra over-budget call %d returned true; expected false", i+1)
		}
	}
	if l.suppressed != 6 {
		t.Fatalf("suppressed = %d after 6 over-budget calls, want 6", l.suppressed)
	}
}

// TestConnLogLimiterRefillsAfterElapsed verifies that advancing the synthetic clock refills
// the bucket so a connection at its ceiling can log again after a full second.
func TestConnLogLimiterRefillsAfterElapsed(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	l := newConnLogLimiter(5, clk)

	for i := 0; i < 5; i++ {
		if !l.logf("drain %d", i) {
			t.Fatalf("drain: logf false at call %d/5", i+1)
		}
	}
	if l.logf("over budget before refill") {
		t.Fatal("over-budget call before refill returned true; expected false")
	}
	now = now.Add(time.Second)
	if !l.logf("after refill") {
		t.Fatal("logf false after 1s advance; expected refill to restore budget")
	}
}

// TestConnLogLimiterBackwardClock verifies that a negative elapsed is clamped to zero so an
// NTP step-back does not drain the bucket and suppress legitimate log lines.
func TestConnLogLimiterBackwardClock(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	l := newConnLogLimiter(5, clk) // tokens=5

	for i := 0; i < 5; i++ {
		if !l.logf("drain %d", i) {
			t.Fatalf("drain: logf false at call %d/5", i+1)
		}
	}
	// Step backward 2s. elapsed is negative → clamp to 0 → tokens stay 0.
	now = now.Add(-2 * time.Second)
	if l.logf("at backward clock") {
		t.Fatal("logf returned true on empty bucket at backward-clock position; expected false")
	}
	// Step forward 1s from the backward position → +5 tokens.
	// With clamp:    0 + 5 = 5 → true.
	// Without clamp: -10 + 5 = -5 → false (bug).
	now = now.Add(time.Second)
	if !l.logf("after 1s forward from backward position") {
		t.Fatal("logf false after 1s forward from backward-clock position; " +
			"backward step must not drain the bucket below zero")
	}
}

// TestConnLogLimiterCappedAtMax verifies that the token bucket never accumulates above
// maxPerSec even after a long idle period. Without the cap, a connection idle for 100s at
// maxPerSec=4 would bank 400 tokens and emit 400 lines in a burst.
//
// This guards the `if l.tokens > float64(l.maxPerSec) { l.tokens = ... }` cap in logf:
// removing it allows unlimited token accumulation; the 5th call below would succeed instead
// of returning false, breaking the assertion.
func TestConnLogLimiterCappedAtMax(t *testing.T) {
	t.Parallel()
	var now time.Time = time.Now()
	clk := func() time.Time { return now }
	const max = 4
	l := newConnLogLimiter(max, clk)

	// Drain all 4 tokens.
	for i := 0; i < max; i++ {
		if !l.logf("drain %d", i) {
			t.Fatalf("drain: logf false at call %d/%d", i+1, max)
		}
	}

	// Advance 100 seconds — without the cap this would accumulate 400 tokens.
	now = now.Add(100 * time.Second)

	// Should emit exactly maxPerSec times (cap held), not maxPerSec*100.
	for i := 0; i < max; i++ {
		if !l.logf("after idle %d", i) {
			t.Fatalf("after 100s idle: logf false at call %d/%d; cap must refill to maxPerSec=%d, not zero",
				i+1, max, max)
		}
	}
	// The (maxPerSec+1)th call must be denied — proves tokens did not accumulate past the cap.
	if l.logf("excess after idle") {
		t.Fatalf("(maxPerSec+1)th call after long idle returned true; token cap must prevent burst above %d", max)
	}
}

// TestConnLogLimiterNilFlushNoop verifies that flush on a nil receiver is a no-op (no panic).
func TestConnLogLimiterNilFlushNoop(t *testing.T) {
	t.Parallel()
	var l *connLogLimiter
	l.flush("device") // must not panic
}

// --------------------------------------------------------------------------------------------
// Unit tests that verify log content — NO t.Parallel (captureLog redirects global logger)
// --------------------------------------------------------------------------------------------

// TestConnLogLimiterNilReceiverEmits verifies that a nil connLogLimiter emits unconditionally
// and returns true, so test-constructed peers with logLimiter=nil still see log output.
func TestConnLogLimiterNilReceiverEmits(t *testing.T) {
	// No t.Parallel: captureLog redirects the global logger.
	w := captureLog(t)
	var l *connLogLimiter
	if !l.logf("nil receiver probe %s", "abc") {
		t.Fatal("nil connLogLimiter.logf returned false; should emit unconditionally")
	}
	if !strings.Contains(w.captured(), "nil receiver probe abc") {
		t.Fatalf("nil connLogLimiter.logf did not emit the expected line; captured: %q", w.captured())
	}
}

// TestConnLogLimiterFlushEmitsSummary verifies that flush emits a "suppressed" summary line
// and resets the counter to zero.
func TestConnLogLimiterFlushEmitsSummary(t *testing.T) {
	// No t.Parallel: captureLog redirects the global logger.
	w := captureLog(t)
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	l := newConnLogLimiter(1, clk)

	l.logf("first call — emits") // consumes the only token
	l.logf("suppressed 1")
	l.logf("suppressed 2")

	if l.suppressed != 2 {
		t.Fatalf("suppressed = %d before flush, want 2", l.suppressed)
	}
	l.flush("my-device")

	out := w.captured()
	if !strings.Contains(out, "2 diagnostic log line(s) suppressed") {
		t.Fatalf("flush did not emit a suppression summary; captured: %q", out)
	}
	if !strings.Contains(out, `"my-device"`) {
		t.Fatalf("flush summary missing device attribution; captured: %q", out)
	}
	if l.suppressed != 0 {
		t.Fatalf("suppressed = %d after flush, want 0 (counter must reset)", l.suppressed)
	}
}

// TestConnLogLimiterFlushNoopWhenZeroSuppressed verifies that flush emits nothing when no
// lines have been suppressed — no spurious summary on well-behaved connections.
func TestConnLogLimiterFlushNoopWhenZeroSuppressed(t *testing.T) {
	// No t.Parallel: captureLog redirects the global logger.
	w := captureLog(t)
	frozen := time.Now()
	clk := func() time.Time { return frozen }
	l := newConnLogLimiter(10, clk)

	l.logf("normal call")
	// Capture everything written so far (normal calls), then reset for flush check.
	beforeFlush := w.captured()
	_ = beforeFlush

	l.flush("quiet-device")
	afterFlush := w.captured()
	if strings.Contains(afterFlush, "suppressed") {
		t.Fatalf("flush emitted a suppression summary when suppressed=0; captured: %q", afterFlush)
	}
}

// --------------------------------------------------------------------------------------------
// Integration tests — real handleWS over httptest loopback
// --------------------------------------------------------------------------------------------

// TestConnLogLimiterBoundsDispatchLogVolume verifies that a connection flooding the server
// with relay messages produces at most defaultConnLogLinesPerSecond log entries — the
// per-connection rate limiter suppresses the excess.
//
// Mutation M1/M2: removing the suppression check or token decrement lets every message
// produce a log line; the count exceeds defaultConnLogLinesPerSecond and the test FAILS.
func TestConnLogLimiterBoundsDispatchLogVolume(t *testing.T) {
	// No t.Parallel: captureLog redirects the global logger.
	w := captureLog(t)
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 4, maxPending: 4, preAuthTimeout: 10 * time.Second,
	})

	// Freeze the server clock so tokens never refill between sends. The entire budget is the
	// initial full bucket of defaultConnLogLinesPerSecond tokens.
	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}

	// Send (defaultConnLogLinesPerSecond * 2) candidate frames. Each calls
	// self.logLimiter.logf("candidate relay: ...") on relay failure (no session). On a frozen
	// clock the first defaultConnLogLinesPerSecond emit; the rest are suppressed.
	const total = defaultConnLogLinesPerSecond * 2
	for i := 0; i < total; i++ {
		if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
			t.Fatalf("write candidate %d: %v", i+1, err)
		}
	}

	// Heartbeat from an unregistered peer generates a "rejected" reply without logging.
	// Receiving it proves all prior candidates have been dispatched by the server.
	writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: "sync-barrier"})
	readUntil(t, c, "rejected", 3*time.Second)

	count := strings.Count(w.captured(), "candidate relay:")
	if count > defaultConnLogLinesPerSecond {
		t.Fatalf("log produced %d \"candidate relay:\" lines for %d messages; "+
			"want ≤ %d (per-connection rate limit must suppress the excess)",
			count, total, defaultConnLogLinesPerSecond)
	}
	if count == 0 {
		t.Fatal("zero \"candidate relay:\" log lines observed; the limiter may have been fully disabled")
	}
}

// TestConnLogLimiterFlushOnConnectionClose verifies that the suppressed-count summary appears
// in the log after the connection closes, confirming that cleanup() calls flush().
//
// Mutation M3: removing flush() from cleanup() means the summary never appears; the
// strings.Contains check below fails.
func TestConnLogLimiterFlushOnConnectionClose(t *testing.T) {
	// No t.Parallel: captureLog redirects the global logger.
	w := captureLog(t)
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 4, maxPending: 4, preAuthTimeout: 10 * time.Second,
	})

	frozen := time.Now()
	ts.srv.now = func() time.Time { return frozen }

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}

	// Send enough candidates to exhaust the initial budget AND produce suppressed lines.
	const total = defaultConnLogLinesPerSecond + 5
	for i := 0; i < total; i++ {
		if err := c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := c.WriteMessage(websocket.TextMessage, []byte(candidateFrame)); err != nil {
			t.Fatalf("write candidate %d: %v", i+1, err)
		}
	}

	// Sync barrier: all candidates dispatched before we close.
	writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: "sync-barrier"})
	readUntil(t, c, "rejected", 3*time.Second)

	// Close the client; wait for the server's cleanup() to run (admission counters both → 0).
	_ = c.Close()
	if err := ts.waitCounters(0, 0, 3*time.Second); err != nil {
		t.Fatalf("cleanup did not finish within 3s: %v", err)
	}

	if !strings.Contains(w.captured(), "suppressed by per-connection rate limiter") {
		t.Fatalf("suppressed-count summary not found in log after connection close; "+
			"flush() must be called from cleanup(). Captured log:\n%s", w.captured())
	}
}
