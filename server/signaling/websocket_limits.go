package main

// WebSocket admission bounds (docs/25 F09 — bounded subset).
//
// The upgrade path used to be unbounded: any TCP client that could reach the listener could open
// as many sockets as it liked and keep them alive with traffic, because the only
// bound on an anonymous peer was the per-message read limit and the silence-refreshing read
// deadline (main.go). This file adds two things and nothing else:
//
//  1. Two per-server counters — TOTAL accepted sockets and PENDING (unauthenticated) sockets —
//     checked BEFORE the WebSocket upgrade completes, so an over-cap client is rejected with a
//     plain 503 without creating a hijacked WebSocket peer. The HTTP handler already exists.
//
//  2. An absolute pre-auth lifetime timer per accepted socket, armed on arrival and cancellable
//     only by successful authentication (register_agent proof-of-possession, or a successfully
//     brokered connect_request from a controller). Read deadlines cannot bound a goroutine
//     blocked in dispatch/write, and are refreshed by chatty-but-anonymous traffic anyway, so
//     the timer is the only thing that guarantees an unauthenticated socket eventually goes
//     away in bounded time regardless of what it sends.
//
// This file is deliberately scoped to these two mechanisms. Per-source quota
// (SIGNALING_MAX_CONNECTIONS_PER_IP, source_quota.go), Origin allowlist
// (SIGNALING_ALLOWED_ORIGINS, origin_policy.go), and per-connection message-rate budget
// (SIGNALING_MAX_MESSAGES_PER_SECOND, msg_rate.go) were implemented in subsequent rounds.
// Each mechanism defaults to warn-only (not enforced) when its env var is unset. F09 is
// fully mitigated only when all four env vars are configured for the deployment.

import (
	"errors"
	"io"
	"sync"
	"time"
)

// Defaults sized for a self-host fleet of a few thousand agents plus their controllers. A
// deployment that wants tighter or looser bounds passes -max-websocket-connections /
// -max-pending-auth / -pre-auth-timeout on startup.
const (
	defaultMaxWebSocketConnections = 4096
	defaultMaxPendingAuth          = 256
	defaultMaxPendingPerSource     = 32
	defaultMaxAuthenticatedPerIP   = 4096
	defaultPreAuthTimeout          = 60 * time.Second

	// Gorilla uses this to bound writing the upgrade response, after net/http reads the request.
	// It does NOT protect slow HTTP headers or connections that have not reached handleWS.
	upgradeHandshakeTimeout = 10 * time.Second
)

// admissionLimits is the tuple main() passes in on startup. Positive and pending<=total is
// validated by SetAdmissionLimits; callers pass raw values.
type admissionLimits struct {
	maxTotal       int
	maxPending     int
	preAuthTimeout time.Duration
	// maxPendingPerSource caps how many PENDING (unauthenticated) leases one source may hold at
	// once. 0 disables the per-source cap (only the pool-wide cap applies). A source at its cap
	// can only replace its OWN oldest pending lease; it never displaces another source's.
	maxPendingPerSource int
}

// admissionState is the per-server admission gate. It is NOT a package global on purpose: two
// test servers running in the same process must not share counters, and a self-host operator
// that wanted two signaling instances in the same binary later would be surprised if they did.
type admissionState struct {
	mu      sync.Mutex
	limits  admissionLimits
	total   int
	pending int
	leases  []*admissionLease
}

// newAdmissionState builds a state configured with the secure defaults. NewServer wires it in
// automatically; SetAdmissionLimits later replaces the limits from flags but must run before
// the listener has accepted anything.
func newAdmissionState() *admissionState {
	return &admissionState{limits: admissionLimits{
		maxTotal:       defaultMaxWebSocketConnections,
		maxPending:     defaultMaxPendingAuth,
		preAuthTimeout: defaultPreAuthTimeout,
	}}
}

// configure replaces the limits. It is safe to call at any time (the mutex covers the swap),
// but the contract with callers — see Server.SetAdmissionLimits — is that it runs before the
// listener is armed, so an in-flight connection never sees a mid-flight change. Validation is
// deliberate: a zero cap would silently reject every connection, and pending>total would let a
// pending peer occupy a slot that could not be counted against the total cap.
func (a *admissionState) configure(l admissionLimits) error {
	if l.maxTotal <= 0 {
		return errors.New("max-websocket-connections must be positive")
	}
	if l.maxPending <= 0 {
		return errors.New("max-pending-auth must be positive")
	}
	if l.preAuthTimeout <= 0 {
		return errors.New("pre-auth-timeout must be positive")
	}
	if l.maxPendingPerSource < 0 {
		return errors.New("max-pending-per-source must not be negative")
	}
	if l.maxPendingPerSource > l.maxPending {
		return errors.New("max-pending-per-source must not exceed max-pending-auth")
	}
	if l.maxPending > l.maxTotal {
		return errors.New("max-pending-auth must not exceed max-websocket-connections")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total != 0 {
		return errors.New("cannot reconfigure websocket admission with active connections")
	}
	a.limits = l
	return nil
}

// snapshot returns the current counters and limits for tests and metrics. Copies under the
// mutex so a reader never sees a torn view of an atomic increment split across fields.
func (a *admissionState) snapshot() (limits admissionLimits, total, pending int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limits, a.total, a.pending
}

// tryAcquire reserves one total slot and one pending slot atomically, or reports full. Both
// checks are done under the same mutex so the two counters cannot disagree with themselves
// under concurrent Acquire/Release.
//
// Called from handleWS BEFORE Upgrader.Upgrade: an over-cap client is rejected with 503 and
// avoids allocating a WebSocket peer; pre-handler HTTP/TCP resources remain outside this gate.
func (a *admissionState) tryAcquire() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.limits.maxTotal {
		return false
	}
	if a.pending >= a.limits.maxPending {
		return false
	}
	a.total++
	a.pending++
	return true
}

// releasePending returns one pending slot to the pool. Guarded against underflow because an
// idempotent lease.Release must be safe to call after Promote has already released.
func (a *admissionState) releasePending() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending > 0 {
		a.pending--
	}
}

// releaseTotal returns one total slot to the pool. Same underflow guard as releasePending, for
// the same reason.
func (a *admissionState) releaseTotal() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total > 0 {
		a.total--
	}
}

// leaseStage tracks a lease's life; total stays charged through handler cleanup in every stage.
type leaseStage int

const (
	leasePending leaseStage = iota
	leasePromoted
	leaseExpired
	leaseReleased
)

// State transitions take state.mu before mu. Expiry and promotion commit under the same
// admission lock so an expired lease can never subsequently become authenticated.
// External cancellation and Close run outside both locks after committing the transition.
type admissionLease struct {
	state    *admissionState
	conn     io.Closer
	deadline time.Time
	source   string // admission source (client IP)
	cancel   func()

	mu    sync.Mutex
	stage leaseStage
	timer *time.Timer
}

// acquireLease reserves before Upgrade, including a cancellation handle for that phase.
// It NEVER evicts or cancels an existing handshake: when the pool is full, or the source is at its
// per-source pending cap, or the total cap is reached, the NEW connection is refused (nil) and the
// caller answers 503 with Retry-After. Only the pre-auth timeout (and promotion) frees a pending
// slot. (Eviction, first global-oldest and then own-source-oldest, let a flood, or a whole
// office reconnecting at once, cancel in-progress registrations: audit 2026-11-01 #1 and review.)
func (a *admissionState) acquireLease(cancel func(), arrivedAt time.Time, source string) *admissionLease {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.limits.maxTotal || a.pending >= a.limits.maxPending {
		return nil
	}
	if a.limits.maxPendingPerSource > 0 {
		n := 0
		for _, l := range a.leases {
			if l.source == source {
				n++
			}
		}
		if n >= a.limits.maxPendingPerSource {
			return nil
		}
	}
	a.total++
	a.pending++
	lease := a.startLeaseLocked(nil, cancel, arrivedAt)
	lease.source = source
	return lease
}

func (a *admissionState) removeLeaseLocked(lease *admissionLease) {
	for i, candidate := range a.leases {
		if candidate == lease {
			copy(a.leases[i:], a.leases[i+1:])
			a.leases[len(a.leases)-1] = nil
			a.leases = a.leases[:len(a.leases)-1]
			return
		}
	}
}

// The split reservation/start helpers remain for focused tests. handleWS uses acquireLease
// so F09 eviction also covers reservations whose Upgrade has not completed yet.
func (a *admissionState) startLease(conn io.Closer) *admissionLease {
	return a.startLeaseAt(conn, time.Now())
}

func (a *admissionState) startLeaseAt(conn io.Closer, arrivedAt time.Time) *admissionLease {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startLeaseLocked(conn, nil, arrivedAt)
}

func (a *admissionState) startLeaseLocked(conn io.Closer, cancel func(), arrivedAt time.Time) *admissionLease {
	lease := &admissionLease{
		state: a, conn: conn, cancel: cancel,
		deadline: arrivedAt.Add(a.limits.preAuthTimeout),
		stage:    leasePending,
	}
	a.leases = append(a.leases, lease)
	lease.timer = time.AfterFunc(time.Until(lease.deadline), lease.expire)
	return lease
}

// attach closes an Upgrade that completed after eviction or expiry; cancellation alone does
// not guarantee that Gorilla has stopped writing the handshake (F09 pending-slot exhaustion).
func (l *admissionLease) attach(conn io.Closer) bool {
	l.state.mu.Lock()
	l.mu.Lock()
	ok := l.stage == leasePending || l.stage == leasePromoted
	if ok {
		l.conn = conn
	}
	l.mu.Unlock()
	l.state.mu.Unlock()
	if !ok {
		_ = conn.Close()
	}
	return ok
}

func (l *admissionLease) close(conn io.Closer) {
	if l.cancel != nil {
		l.cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

// Ordinary expiry retains both reservations through handler cleanup. Under F09 pressure,
// an expired reservation is also replaceable: its handler is already on the way out.
func (l *admissionLease) expire() {
	l.state.mu.Lock()
	l.mu.Lock()
	if l.stage != leasePending {
		l.mu.Unlock()
		l.state.mu.Unlock()
		return
	}
	l.stage = leaseExpired
	conn := l.conn
	l.mu.Unlock()
	l.state.mu.Unlock()
	l.close(conn)
}

// The deadline comparison prevents a delayed timer from admitting an expired peer. The
// shared admission lock also prevents F09 eviction from closing a successfully promoted peer.
func (l *admissionLease) Promote() bool {
	l.state.mu.Lock()
	l.mu.Lock()
	if l.stage != leasePending {
		l.mu.Unlock()
		l.state.mu.Unlock()
		return false
	}
	if !time.Now().Before(l.deadline) {
		l.stage = leaseExpired
		l.timer.Stop()
		conn := l.conn
		l.mu.Unlock()
		l.state.mu.Unlock()
		l.close(conn)
		return false
	}
	l.stage = leasePromoted
	l.timer.Stop()
	l.state.pending--
	l.state.removeLeaseLocked(l)
	l.mu.Unlock()
	l.state.mu.Unlock()
	return true
}

// Release returns total exactly once. F09 eviction already returned pending, as did promotion;
// ordinary expiry retains pending until this cleanup entry runs.
func (l *admissionLease) Release() {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stage == leaseReleased {
		return
	}
	if l.stage == leasePending || l.stage == leaseExpired {
		l.state.pending--
		l.state.removeLeaseLocked(l)
	}
	l.stage = leaseReleased
	l.timer.Stop()
	l.state.total--
}
