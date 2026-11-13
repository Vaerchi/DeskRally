package main

import (
	"log"
	"time"
)

// defaultConnLogLinesPerSecond is the per-connection diagnostic log ceiling (docs/25 F19).
// Hardcoded (not env-configurable) because this is a safety bound, not a capacity setting:
// legitimate connections emit far fewer log lines per second than this; an adversarial
// connection must be bounded regardless of operator configuration choices.
const defaultConnLogLinesPerSecond = 10

// connLogLimiter is a per-connection log-rate limiter (docs/25 F19). It caps diagnostic log
// output to maxPerSec lines per second to bound the log volume a noisy or adversarial
// connection can generate. When the budget is exceeded, lines are counted but not emitted;
// flush() emits a summary on connection close so suppressed counts are never silently lost.
//
// NOT goroutine-safe: dispatch (the sole caller of logf) runs serially in the read goroutine
// per connection. The token-bucket algorithm mirrors connRateLimiter (msg_rate.go).
type connLogLimiter struct {
	maxPerSec  int
	tokens     float64
	lastCheck  time.Time
	suppressed int64
	now        func() time.Time
}

// newConnLogLimiter creates a rate limiter seeded with a full token bucket. maxPerSec=0
// disables rate limiting (logf always emits). The injected now function is the clock;
// pass s.now from the Server so tests can freeze time without spinning real goroutines.
func newConnLogLimiter(maxPerSec int, now func() time.Time) *connLogLimiter {
	return &connLogLimiter{
		maxPerSec: maxPerSec,
		tokens:    float64(maxPerSec),
		lastCheck: now(),
		now:       now,
	}
}

// logf emits a formatted log line if within the per-second budget, otherwise increments
// the suppressed counter and returns false. A nil receiver emits unconditionally — this
// covers test peers that bypass handleWS and have logLimiter=nil.
func (l *connLogLimiter) logf(format string, args ...any) bool {
	if l == nil {
		log.Printf(format, args...)
		return true
	}
	if l.maxPerSec == 0 {
		log.Printf(format, args...)
		return true
	}
	now := l.now()
	elapsed := now.Sub(l.lastCheck).Seconds()
	l.lastCheck = now
	// Clamp: a backward clock step (NTP correction, live-VM migration) produces a negative
	// elapsed that would drain the bucket and suppress legitimate log lines for the correction
	// window. Ignoring negative elapsed is safe because lastCheck has already advanced to now.
	if elapsed < 0 {
		elapsed = 0
	}
	l.tokens += elapsed * float64(l.maxPerSec)
	if l.tokens > float64(l.maxPerSec) {
		l.tokens = float64(l.maxPerSec)
	}
	if l.tokens < 1.0 {
		l.suppressed++
		return false
	}
	l.tokens -= 1.0
	log.Printf(format, args...)
	return true
}

// flush emits a summary of suppressed lines (if any) and resets the counter. A nil receiver
// is a no-op. Call on connection close to ensure suppressed counts are not silently lost.
// device is used for attribution; it may be empty for pre-authentication connections.
func (l *connLogLimiter) flush(device string) {
	if l == nil || l.suppressed == 0 {
		return
	}
	log.Printf("connection %q: %d diagnostic log line(s) suppressed by per-connection rate limiter", device, l.suppressed)
	l.suppressed = 0
}
