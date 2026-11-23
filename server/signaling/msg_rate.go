package main

import "time"

// connRateLimiter is a per-connection token-bucket rate limiter for inbound WebSocket messages
// (docs/25 F09 — message-rate budget). It is NOT goroutine-safe: the WebSocket read loop is
// its sole caller, and that loop runs in a single goroutine per connection.
//
// Tokens accumulate at maxPerSec per second and are capped at maxPerSec (no burst above the
// per-second ceiling). Each received message consumes one token, regardless of its type or
// validity. When the bucket is empty, allow() returns false and handleWS closes the connection.
type connRateLimiter struct {
	maxPerSec int
	tokens    float64
	lastCheck time.Time
	now       func() time.Time
}

// newConnRateLimiter creates a rate limiter seeded with a full token bucket. maxPerSec=0
// disables rate limiting (allow() always returns true). The injected now function is the clock;
// pass s.now from the Server so tests can freeze time without spinning real goroutines.
func newConnRateLimiter(maxPerSec int, now func() time.Time) *connRateLimiter {
	return &connRateLimiter{
		maxPerSec: maxPerSec,
		tokens:    float64(maxPerSec), // start full: first burst up to maxPerSec is permitted
		lastCheck: now(),
		now:       now,
	}
}

// allow refills the bucket for elapsed time, then consumes one token. Returns false (over-budget)
// when the bucket is empty after refill. Always returns true when disabled (maxPerSec==0).
func (r *connRateLimiter) allow() bool {
	if r.maxPerSec == 0 {
		return true
	}
	now := r.now()
	elapsed := now.Sub(r.lastCheck).Seconds()
	r.lastCheck = now
	// Clamp: a backward clock step (NTP correction, live migration) produces a negative elapsed
	// that would drain the bucket and block legitimate traffic for the correction window.
	// Ignoring negative elapsed is safe because we have already advanced lastCheck to now —
	// the next call will see a positive interval from this moment forward.
	if elapsed < 0 {
		elapsed = 0
	}
	r.tokens += elapsed * float64(r.maxPerSec)
	if r.tokens > float64(r.maxPerSec) {
		r.tokens = float64(r.maxPerSec)
	}
	if r.tokens < 1.0 {
		return false
	}
	r.tokens -= 1.0
	return true
}

