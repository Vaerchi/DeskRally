package controlplane

// Anonymous support-bundle download limits (audit 2026-11-01 #11/#15).
//
// POST /attended-sessions/support-bundle is unauthenticated and does not verify the code (it only
// packages it), so a single process-global bucket let any anonymous caller keep it at 429 for every
// tenant and guest. The allowance is now charged to the CALLER first:
//
//  1. per client IP   (burst 4, one refill per 15 s, 2 concurrent)  - the caller's own budget
//  2. per session code (burst 3, one refill per 30 s)               - one code cannot be hammered
//  3. a generous GLOBAL backstop (burst 64, 2/s refill, 32 concurrent), only reached after (1)/(2)
//     pass, so a caller refused by its own budget never touches it.
//
// Keyed tables are bounded: idle (fully refilled, nothing in flight) keys are swept when a table
// fills, and if it is still full new keys share one overflow bucket, so a many-source flood cannot
// grow memory and is limited in aggregate.

import (
	"sync"
	"time"
)

const (
	supportIPBurst, supportIPRefill     = 4.0, 15 * time.Second
	supportIPConcurrent                 = 2
	supportCodeBurst, supportCodeRefill = 3.0, 30 * time.Second
	supportGlobalBurst                  = 64.0
	supportGlobalRefillPerSec           = 2.0
	supportGlobalConcurrent             = 32
	supportMaxKeys                      = 10000
	supportOverflowKey                  = "\x00overflow"
)

type keyedBucket struct {
	tokens float64
	last   time.Time
	active int
}

type keyedBuckets struct {
	mu        sync.Mutex
	burst     float64
	refill    time.Duration // time to earn one token
	maxActive int           // 0 = no concurrency bound
	maxKeys   int
	m         map[string]*keyedBucket
	lastSweep time.Time
}

func newKeyedBuckets(burst float64, refill time.Duration, maxActive int) *keyedBuckets {
	return &keyedBuckets{burst: burst, refill: refill, maxActive: maxActive, maxKeys: supportMaxKeys, m: map[string]*keyedBucket{}}
}

func (k *keyedBuckets) refillLocked(b *keyedBucket, now time.Time) {
	if el := now.Sub(b.last); el > 0 {
		b.tokens += float64(el) / float64(k.refill)
		if b.tokens > k.burst {
			b.tokens = k.burst
		}
		b.last = now
	}
}

// take spends one token (and one concurrency slot) for key; the returned key is the one actually
// charged (the overflow key when the table is saturated) and must be passed to done.
func (k *keyedBuckets) take(key string, now time.Time) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.m[key]
	if !ok {
		if len(k.m) >= k.maxKeys {
			k.sweepLocked(now)
		}
		if len(k.m) >= k.maxKeys {
			key = supportOverflowKey
			b = k.m[key]
		}
		if b == nil {
			b = &keyedBucket{tokens: k.burst, last: now}
			k.m[key] = b
		}
	}
	k.refillLocked(b, now)
	if b.tokens < 1 || (k.maxActive > 0 && b.active >= k.maxActive) {
		return key, false
	}
	b.tokens--
	b.active++
	return key, true
}

func (k *keyedBuckets) done(key string) {
	k.mu.Lock()
	if b := k.m[key]; b != nil && b.active > 0 {
		b.active--
	}
	k.mu.Unlock()
}

// sweepLocked drops idle keys, at most once a second so a table full of hot keys cannot make each
// insert O(n).
func (k *keyedBuckets) sweepLocked(now time.Time) {
	if now.Sub(k.lastSweep) < time.Second {
		return
	}
	k.lastSweep = now
	for key, b := range k.m {
		k.refillLocked(b, now)
		if b.active == 0 && b.tokens >= k.burst {
			delete(k.m, key)
		}
	}
}

type supportLimits struct {
	once   sync.Once
	ip     *keyedBuckets
	code   *keyedBuckets
	global *keyedBuckets
}

func (m *ManagedInstaller) supportLimiter() *supportLimits {
	m.supportLim.once.Do(func() {
		m.supportLim.ip = newKeyedBuckets(supportIPBurst, supportIPRefill, supportIPConcurrent)
		m.supportLim.code = newKeyedBuckets(supportCodeBurst, supportCodeRefill, 0)
		m.supportLim.global = newKeyedBuckets(supportGlobalBurst, time.Duration(float64(time.Second)/supportGlobalRefillPerSec), supportGlobalConcurrent)
	})
	return &m.supportLim
}

// acquireSupportFor charges the caller's own budgets first (IP, then code) and only then the
// global backstop. It returns a release func on success. A refusal from the caller's own budget
// never consumes any global allowance.
func (m *ManagedInstaller) acquireSupportFor(ip, code string) (release func(), ok bool) {
	l := m.supportLimiter()
	now := m.clock()
	ipKey, ok := l.ip.take(ip, now)
	if !ok {
		return nil, false
	}
	codeKey, ok := l.code.take(code, now)
	if !ok {
		l.ip.done(ipKey)
		return nil, false
	}
	gKey, ok := l.global.take("global", now)
	if !ok {
		l.ip.done(ipKey)
		l.code.done(codeKey)
		return nil, false
	}
	return func() { l.ip.done(ipKey); l.code.done(codeKey); l.global.done(gKey) }, true
}
