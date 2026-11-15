package controlplane

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Per-token rate limit on the public API's WRITE routes (docs/59 §5 residual risk, closed).
//
// A leaked token holding manage_machines / manage_groups can already make every change its capability
// allows; what the limit removes is SPEED: without it, one script could rewrite a whole fleet's
// grouping or properties in seconds, faster than anyone could notice and revoke the token.
//
// The key is the AUTHENTICATED token (tenant + token id), charged only after authentication succeeded
// — the "rate limiter as the off switch" lesson: a budget keyed on anything a caller can choose (an IP,
// a claimed id) lets one caller spend another's. Here a token can only ever spend its own budget, so
// the limit cannot be used to lock a different integration out. Reads are not limited, and neither are
// console users (a person's session is not an API token), so the console cannot be throttled by this.
//
// Token bucket: apiWriteBurst writes at once, refilled at apiWriteRefillPerSecond. A bulk move (up to
// 200 machines) is ONE write, so ordinary automation stays well inside the budget.
const (
	apiWriteBurst           = 60
	apiWriteRefillPerSecond = 1.0
	// apiWriteKeysPerTenant bounds memory PER TENANT (a bucket is well under 200 bytes). Buckets live in
	// a table per tenant, so one tenant's tokens can only ever crowd that tenant (Codex review r2: a single
	// process-wide table let one Owner minting many tokens block other tenants' new tokens).
	//
	// Only FULL buckets are ever dropped: a full bucket is indistinguishable from an absent one, and a
	// spent bucket refills completely within burst/refill seconds. A spent bucket is NEVER evicted, because
	// recreating it would hand that token a fresh burst (Codex review r1). If a tenant's table is full of
	// spent buckets, that tenant's NEW tokens are refused until one refills. The scan that frees full
	// buckets runs at most once per possible refill (nextFree), so a refused caller cannot make every
	// request rescan the table (Codex review r2).
	apiWriteKeysPerTenant = 1024
	// apiWriteSweepEvery: a periodic pass drops full buckets and empty tenant tables everywhere, so memory
	// follows recent activity rather than every token that ever wrote.
	apiWriteSweepEvery = 10 * time.Minute
)

type apiWriteBucket struct {
	tokens float64
	last   time.Time
}

type apiWriteTenant struct {
	buckets  map[string]*apiWriteBucket
	nextFree time.Time // when the table is full: no slot can free up before this instant
}

type apiWriteLimiter struct {
	mu        sync.Mutex
	burst     float64
	refill    float64 // tokens per second
	maxKeys   int     // per tenant
	now       func() time.Time
	tenants   map[string]*apiWriteTenant
	nextSweep time.Time
}

func newAPIWriteLimiter(burst int, refillPerSecond float64, maxKeysPerTenant int, now func() time.Time) *apiWriteLimiter {
	if now == nil {
		now = time.Now
	}
	return &apiWriteLimiter{burst: float64(burst), refill: refillPerSecond, maxKeys: maxKeysPerTenant, now: now,
		tenants: map[string]*apiWriteTenant{}}
}

var defaultAPIWriteLimiter = newAPIWriteLimiter(apiWriteBurst, apiWriteRefillPerSecond, apiWriteKeysPerTenant, nil)

// level returns b's token count at t (refilled, capped at burst).
func (l *apiWriteLimiter) level(b *apiWriteBucket, t time.Time) float64 {
	elapsed := t.Sub(b.last).Seconds()
	if elapsed < 0 {
		elapsed = 0 // a clock step backwards never mints tokens
	}
	return math.Min(l.burst, b.tokens+elapsed*l.refill)
}

// take charges one write to the token in tenant. It returns ok, or the wait until a write is available.
func (l *apiWriteLimiter) take(tenant, token string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if !t.Before(l.nextSweep) {
		l.sweepLocked(t)
	}
	tt := l.tenants[tenant]
	if tt == nil {
		tt = &apiWriteTenant{buckets: map[string]*apiWriteBucket{}}
		l.tenants[tenant] = tt
	}
	b, found := tt.buckets[token]
	if !found {
		if len(tt.buckets) >= l.maxKeys {
			if t.Before(tt.nextFree) {
				return false, tt.nextFree.Sub(t) // nothing can have refilled yet: no rescan
			}
			l.dropFullLocked(tt, t)
			if len(tt.buckets) >= l.maxKeys {
				return false, tt.nextFree.Sub(t) // fail closed: never mint a burst by forgetting a spent bucket
			}
		}
		b = &apiWriteBucket{tokens: l.burst, last: t}
		tt.buckets[token] = b
		tt.nextFree = time.Time{} // the table changed: the next time it is full, scan it afresh
	}
	b.tokens = l.level(b, t)
	b.last = t
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.refill * float64(time.Second))
	return false, wait
}

// dropFullLocked removes tt's full buckets (they carry no state) and records in tt.nextFree when the
// fullest remaining bucket will be full: the soonest a slot can free up. Buckets only refill between
// scans (a take lowers its own bucket), so no slot can free up before nextFree.
func (l *apiWriteLimiter) dropFullLocked(tt *apiWriteTenant, t time.Time) {
	soonest := time.Duration(-1)
	for k, b := range tt.buckets {
		lv := l.level(b, t)
		if lv >= l.burst {
			delete(tt.buckets, k)
			continue
		}
		if d := time.Duration((l.burst - lv) / l.refill * float64(time.Second)); soonest < 0 || d < soonest {
			soonest = d
		}
	}
	// The EXACT deadline (Codex review r3: clamping it delayed admission past a real refill). The
	// Retry-After header is rounded up to whole seconds where it is written, not here. Rescans stay
	// bounded: each one happens at a deadline where a bucket has just become full and is dropped.
	if soonest < 0 {
		soonest = 0
	}
	tt.nextFree = t.Add(soonest)
}

// sweepLocked drops every full bucket and every empty tenant table, then schedules the next sweep.
func (l *apiWriteLimiter) sweepLocked(t time.Time) {
	for id, tt := range l.tenants {
		l.dropFullLocked(tt, t)
		if len(tt.buckets) == 0 {
			delete(l.tenants, id)
		}
	}
	l.nextSweep = t.Add(apiWriteSweepEvery)
}

func (s *Server) apiWriteLimiter() *apiWriteLimiter {
	if s.APIWriteLimiter != nil {
		return s.APIWriteLimiter
	}
	return defaultAPIWriteLimiter
}

// limitAPITokenWrites wraps a public API write handler: an API-token principal is charged one write,
// and refused with 429 + Retry-After once its budget is spent. Anything else passes through.
func (s *Server) limitAPITokenWrites(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p != nil && p.APIToken {
			if ok, wait := s.apiWriteLimiter().take(p.TenantID, p.UserID); !ok {
				secs := int(math.Ceil(wait.Seconds()))
				if secs < 1 {
					secs = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				writeError(w, http.StatusTooManyRequests, "API token write rate limit reached; retry later")
				return
			}
		}
		next(w, r)
	}
}
