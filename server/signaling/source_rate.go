package main

// Per-source connection-RATE limit for /ws (audit 2026-11-01 #6).
//
// The pool caps bound how many sockets are open; they say nothing about how fast one source may
// open them. An anonymous host churning connections drove an unauthenticated control-plane
// identity lookup per socket. A token bucket per source, checked at the very top of handleWS
// (before admission, before any upgrade, before any control-plane call), bounds that.
//
// Memory: the table is capped. A bucket that has refilled to full is indistinguishable from an
// absent one, so full buckets are swept when the table fills (at most once a second). If the table
// is still full of hot sources, new sources share one overflow bucket, so a many-source flood is
// limited in aggregate rather than growing the map.

import (
	"sync"
	"time"
)

const (
	defaultConnectRatePerSecond = 10 // sustained new connections per second per source
	connectRateBurstFactor      = 6  // bucket depth = rate * factor (a fleet restart behind one NAT)
	maxConnectRateSources       = 10000
	connectRateOverflowKey      = "\x00overflow"
)

type sourceRateBucket struct {
	tokens float64
	last   time.Time
}

type sourceRateLimiter struct {
	mu        sync.Mutex
	rate      float64 // tokens per second; 0 disables
	burst     float64
	now       func() time.Time
	buckets   map[string]*sourceRateBucket
	lastSweep time.Time
	maxKeys   int
}

// newSourceRateLimiter: perSecond == 0 disables the limiter (allow always).
func newSourceRateLimiter(perSecond int, now func() time.Time) *sourceRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &sourceRateLimiter{
		rate: float64(perSecond), burst: float64(perSecond * connectRateBurstFactor),
		now: now, buckets: make(map[string]*sourceRateBucket), maxKeys: maxConnectRateSources,
	}
}

func (l *sourceRateLimiter) enabled() bool { return l.rate > 0 }

// allow spends one token for source and reports whether the connection may proceed.
func (l *sourceRateLimiter) allow(source string) bool {
	if !l.enabled() {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[source]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweepLocked(now)
		}
		if len(l.buckets) >= l.maxKeys {
			source = connectRateOverflowKey
			b = l.buckets[source]
		}
		if b == nil {
			b = &sourceRateBucket{tokens: l.burst, last: now}
			l.buckets[source] = b
		}
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have refilled to full. At most one sweep per second so a full
// table of hot sources cannot make every insert O(n).
func (l *sourceRateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Second {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
