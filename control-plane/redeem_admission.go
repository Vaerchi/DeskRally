package controlplane

// Redemption admission and the rejection floor (docs/66 2b.4, 2b.5, 2d.2).
//
// ADMISSION comes first, before any class-dependent work (no code lookup, no assignment read, no hashing of
// the code): at most 64 redemptions in flight per process and 4 per client IP. Beyond that the answer is the
// same 429 with Retry-After for every code class and every host, no failure is recorded and no audit row is
// written. The pools are per PROCESS: with N replicas the service-wide bound is N x 64 (docs/66 2d.2); there
// is deliberately no cross-replica coordination.
//
// The REJECTION FLOOR applies only to rejections of admitted requests. A rejection is released no earlier than
// `floor` (default 60 ms) plus a uniform jitter of 0..`jitter` (default 20 ms) after admission, so floor plus
// jitter never exceeds 100 ms. The sleep holds NO database connection: the store call has returned (and its
// connection with it) before the handler sleeps. The class-dependent work (assignment read, code lookup, the
// 50 ms bounded lock wait of migration 0071) runs under a 250 ms deadline; a deadline-cut redemption is the
// same generic rejection as any invalid code (a transient, retryable answer).

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	// DefaultRedeemAdmitGlobal / PerIP are the in-flight caps of 2b.4.
	DefaultRedeemAdmitGlobal = 64
	DefaultRedeemAdmitPerIP  = 4
	// DefaultRedeemFloor + DefaultRedeemJitter <= 100 ms (the ceiling 2b.4 never lets either exceed).
	DefaultRedeemFloor        = 60 * time.Millisecond
	DefaultRedeemJitter       = 20 * time.Millisecond
	DefaultRedeemWorkDeadline = 250 * time.Millisecond
	// redeemWriteDeadline bounds every public redemption response, rejections and 429s included.
	redeemWriteDeadline = 2 * time.Second
)

// RedeemTuning overrides the redemption admission and timing. The zero value means the documented defaults;
// a negative Floor switches the floor off (tests that hammer the endpoint).
type RedeemTuning struct {
	AdmitGlobal  int
	AdmitPerIP   int
	Floor        time.Duration
	Jitter       time.Duration
	WorkDeadline time.Duration
}

func (t RedeemTuning) floor() time.Duration {
	if t.Floor < 0 {
		return 0
	}
	if t.Floor == 0 {
		return DefaultRedeemFloor
	}
	return t.Floor
}

func (t RedeemTuning) jitter() time.Duration {
	if t.Floor < 0 {
		return 0
	}
	if t.Jitter == 0 {
		return DefaultRedeemJitter
	}
	return t.Jitter
}

func (t RedeemTuning) workDeadline() time.Duration {
	if t.WorkDeadline <= 0 {
		return DefaultRedeemWorkDeadline
	}
	return t.WorkDeadline
}

// admissionPool is a zero-queue counting gate: global and per-key in-flight caps.
type admissionPool struct {
	mu        sync.Mutex
	inflight  int
	perKey    map[string]int
	maxGlobal int
	maxPerKey int
}

func newAdmissionPool(maxGlobal, maxPerKey int) *admissionPool {
	if maxGlobal <= 0 {
		maxGlobal = DefaultRedeemAdmitGlobal
	}
	if maxPerKey <= 0 {
		maxPerKey = DefaultRedeemAdmitPerIP
	}
	return &admissionPool{perKey: make(map[string]int), maxGlobal: maxGlobal, maxPerKey: maxPerKey}
}

// Acquire admits one request or refuses it immediately (no waiting). The returned release must be called
// exactly once (a second call is a no-op).
func (p *admissionPool) Acquire(key string) (release func(), ok bool) {
	p.mu.Lock()
	if p.inflight >= p.maxGlobal || p.perKey[key] >= p.maxPerKey {
		p.mu.Unlock()
		return nil, false
	}
	p.inflight++
	p.perKey[key]++
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.inflight--
			if p.perKey[key]--; p.perKey[key] <= 0 {
				delete(p.perKey, key)
			}
			p.mu.Unlock()
		})
	}, true
}

// stats reports the current load (tests and the load gate).
func (p *admissionPool) stats() (inflight, keys int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inflight, len(p.perKey)
}

func (s *Server) redeemPool() *admissionPool {
	s.redeemAdmitOnce.Do(func() {
		s.redeemAdmit = newAdmissionPool(s.RedeemTuning.AdmitGlobal, s.RedeemTuning.AdmitPerIP)
	})
	return s.redeemAdmit
}

// redeemRejectFloor sleeps until floor + jitter after start (admission), or until the client goes away. It
// is called with no database connection held.
func (s *Server) redeemRejectFloor(ctx context.Context, start time.Time) {
	floor := s.RedeemTuning.floor()
	if floor <= 0 {
		return
	}
	target := start.Add(floor)
	if j := s.RedeemTuning.jitter(); j > 0 {
		target = target.Add(time.Duration(rand.Int64N(int64(j) + 1)))
	}
	d := time.Until(target)
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
