package controlplane

// Admission limits for the recording upload routes (docs/63 §2a C3): global, per-tenant and per-device
// CONCURRENCY with a bounded wait queue, a per-device request RATE, and a per-source-address budget of
// FAILED authentications that is consulted BEFORE any database work.
//
// The ORDER matters (a rate limiter as the off switch, memory a-rate-limiter-as-the-off-switch):
//   - the per-device budget is spent only AFTER the signature has verified, so an anonymous caller who
//     merely NAMES a victim device in a header cannot exhaust that device's budget;
//   - the per-address budget is charged only by FAILED attempts, never by successful ones, so legitimate
//     fleet traffic (which may all arrive from one proxy address when the proxy is not trusted for
//     X-Forwarded-For) never spends it. What an attacker can do is burn their own failure budget; behind
//     an untrusted proxy that address is shared, which is exactly why CP_TRUST_PROXY_IP exists.

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

var (
	errAdmissionBusy = errors.New("recording upload: server busy")
	errAdmissionRate = errors.New("recording upload: rate limit")
)

type tokenBucket struct {
	key    string
	tokens float64
	last   time.Time
}

// rateLimiter keeps one token bucket per key in a table bounded to maxKeys. The table is an LRU
// (map + doubly-linked list): a lookup, an insert and an eviction are all O(1), so a many-source
// attacker cannot turn each new key into a scan of the whole table under the mutex (audit
// 2026-11-01 #18; the old code walked all 100000 entries per insert once full).
//
// Debt is never forgotten: when the table is full only an IDLE bucket (fully refilled, so it carries
// no information) may be evicted, and only the evictionProbe least-recently-used entries are
// examined (bounded work). If none of them is idle, the new key is charged to ONE shared overflow
// bucket instead of being inserted, so a many-source attacker cycling more than maxKeys addresses
// shares a single budget rather than minting a fresh burst per address.
type rateLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*list.Element // value: *tokenBucket
	lru     *list.List               // front = most recently used
	maxKeys int
	// overflow is the shared bucket charged for new keys while the table is saturated with live
	// (non-idle) buckets. Never stored in buckets/lru.
	overflow *tokenBucket
}

// evictionProbe bounds how many LRU-tail entries one insert examines.
const evictionProbe = 8

func newRateLimiter(perSec float64, burst int, maxKeys int) *rateLimiter {
	if maxKeys < 1 {
		maxKeys = 1
	}
	return &rateLimiter{perSec: perSec, burst: float64(burst), buckets: map[string]*list.Element{}, lru: list.New(), maxKeys: maxKeys}
}

// peek reports whether key has at least one token, without spending it.
func (l *rateLimiter) peek(key string, now time.Time) bool {
	if l.perSec <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys && l.overflow != nil {
			return l.overflow.tokens+now.Sub(l.overflow.last).Seconds()*l.perSec >= 1
		}
		return true
	}
	b := e.Value.(*tokenBucket)
	return b.tokens+now.Sub(b.last).Seconds()*l.perSec >= 1
}

// idleLocked: the bucket has fully refilled, so dropping it loses nothing.
func (l *rateLimiter) idleLocked(b *tokenBucket, now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst
}

// spend takes one token for key (down to zero) whether or not one was available.
func (l *rateLimiter) spend(key string, now time.Time) {
	l.allow(key, now)
}

// allow spends one token for key at now.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	if l.perSec <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *tokenBucket
	if e, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(e)
		b = e.Value.(*tokenBucket)
	} else {
		if len(l.buckets) >= l.maxKeys {
			// Examine at most evictionProbe entries from the LRU tail for an idle bucket.
			var victim *list.Element
			for e, n := l.lru.Back(), 0; e != nil && n < evictionProbe; e, n = e.Prev(), n+1 {
				if l.idleLocked(e.Value.(*tokenBucket), now) {
					victim = e
					break
				}
			}
			if victim == nil {
				// Saturated with live debtors: share one overflow budget, insert nothing.
				if l.overflow == nil {
					l.overflow = &tokenBucket{tokens: l.burst, last: now}
				}
				b = l.overflow
			} else {
				delete(l.buckets, victim.Value.(*tokenBucket).key)
				l.lru.Remove(victim)
			}
		}
		if b == nil {
			b = &tokenBucket{key: key, tokens: l.burst, last: now}
			l.buckets[key] = l.lru.PushFront(b)
		}
	}
	b.tokens += now.Sub(b.last).Seconds() * l.perSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type uploadAdmission struct {
	mu        sync.Mutex
	global    int
	tenant    map[string]int
	device    map[string]int
	waiting   int
	wake      chan struct{}
	maxGlobal int
	maxTenant int
	maxDevice int
	maxQueue  int
}

func newUploadAdmission(g, t, d, queue int) *uploadAdmission {
	return &uploadAdmission{tenant: map[string]int{}, device: map[string]int{}, wake: make(chan struct{}),
		maxGlobal: g, maxTenant: t, maxDevice: d, maxQueue: queue}
}

func (a *uploadAdmission) canLocked(tenant, device string) bool {
	return a.global < a.maxGlobal && a.tenant[tenant] < a.maxTenant && a.device[device] < a.maxDevice
}

// acquire admits one request or fails with errAdmissionBusy: immediately when the wait queue is full,
// or after `wait` when a slot never opened. The returned release MUST be called.
func (a *uploadAdmission) acquire(ctx context.Context, tenant, device string, wait time.Duration) (func(), error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		a.mu.Lock()
		if a.canLocked(tenant, device) {
			a.global++
			a.tenant[tenant]++
			a.device[device]++
			a.mu.Unlock()
			return func() { a.release(tenant, device) }, nil
		}
		if a.waiting >= a.maxQueue {
			a.mu.Unlock()
			return nil, errAdmissionBusy
		}
		a.waiting++
		ch := a.wake
		a.mu.Unlock()

		select {
		case <-ch:
		case <-timer.C:
			a.dequeue()
			return nil, errAdmissionBusy
		case <-ctx.Done():
			a.dequeue()
			return nil, ctx.Err()
		}
		a.dequeue()
	}
}

func (a *uploadAdmission) dequeue() {
	a.mu.Lock()
	a.waiting--
	a.mu.Unlock()
}

func (a *uploadAdmission) release(tenant, device string) {
	a.mu.Lock()
	a.global--
	if a.tenant[tenant]--; a.tenant[tenant] <= 0 {
		delete(a.tenant, tenant)
	}
	if a.device[device]--; a.device[device] <= 0 {
		delete(a.device, device)
	}
	close(a.wake)
	a.wake = make(chan struct{})
	a.mu.Unlock()
}
