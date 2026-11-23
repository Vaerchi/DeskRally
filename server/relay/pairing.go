package main

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrTimeout is returned to a half-connection that waited for a peer with the
// same RelayToken but none arrived before the broker's timeout elapsed.
var ErrTimeout = errors.New("relay: unpaired connection timed out")

// ErrCapacity is returned from TryAcquire when the relay is already serving
// maxConns connections and cannot admit another.
var ErrCapacity = errors.New("relay: admission limit reached")

// stream is the minimal contract the broker needs from a half-connection.
// Both the raw-TCP adapter (bufConn) and the WebSocket adapter (wsConn)
// satisfy it, which is how a single pairing implementation serves both
// listeners. The broker never looks inside the bytes — it only shovels them
// (ADR-002 / ADR-004: the relay is E2E-blind).
type stream = io.ReadWriteCloser

// waiter is a half-connection parked in the broker waiting for its peer.
type waiter struct {
	s        stream
	done     chan struct{} // closed exactly once when this waiter's fate is sealed
	timer    *time.Timer
	timedOut bool
}

// Broker pairs half-connections by RelayToken and splices matched pairs.
//
// It is deliberately dumb: a token->waiter map guarded by a mutex. The first
// connection to present a token parks; the second connection presenting the
// same token is spliced to the first and bytes flow in both directions until
// either side closes. Unpaired waiters are reaped after `timeout`.
type Broker struct {
	mu          sync.Mutex
	waiting     map[string]*waiter
	timeout     time.Duration
	maxConns    int // 0 = unlimited
	activeConns int // guarded by mu
}

// NewBroker returns a Broker that reaps unpaired half-connections after the
// given timeout. maxConns is the maximum number of simultaneously active
// connections across both transports; 0 means unlimited.
//
// A zero or negative timeout is never honoured: it would make every parked
// half-connection expire immediately, so no session could ever pair. Such a
// value is replaced by defaultWait.
func NewBroker(timeout time.Duration, maxConns int) *Broker {
	return &Broker{
		waiting:  make(map[string]*waiter),
		timeout:  effectivePairTimeout(timeout),
		maxConns: maxConns,
	}
}

// effectivePairTimeout returns defaultWait when d is zero or negative and d
// otherwise.
func effectivePairTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultWait
	}
	return d
}

// TryAcquire reports whether a new connection may be admitted and, if so,
// increments the active count. The caller must pair each successful TryAcquire
// with exactly one Release call (typically via defer). A false return means
// the relay is at capacity; the caller must close the connection without
// calling Handle.
func (b *Broker) TryAcquire() bool {
	if b.maxConns <= 0 {
		return true
	}
	b.mu.Lock()
	ok := b.activeConns < b.maxConns
	if ok {
		b.activeConns++
	}
	b.mu.Unlock()
	return ok
}

// Release decrements the active connection count. It must be called exactly
// once per successful TryAcquire, typically via defer in the transport handler.
func (b *Broker) Release() {
	if b.maxConns <= 0 {
		return
	}
	b.mu.Lock()
	b.activeConns--
	b.mu.Unlock()
}

// Handle drives one half-connection through its whole lifetime and blocks
// until the session is over. It returns nil once a spliced session completes
// normally, or ErrTimeout if no peer arrived in time.
//
// The caller is responsible for closing `s`; Handle (via splice) will also
// close both ends when a session ends, so a double Close must be tolerated by
// the adapter — net.Conn, io.Pipe halves and the WebSocket adapter all do.
func (b *Broker) Handle(token string, s stream) error {
	b.mu.Lock()

	// Second arrival: a peer is already parked for this token. Take it,
	// cancel its reaper, and splice the two together.
	if peer, ok := b.waiting[token]; ok {
		delete(b.waiting, token)
		peer.timer.Stop()
		b.mu.Unlock()

		splice(peer.s, s)
		close(peer.done) // wake the parked first goroutine
		return nil
	}

	// First arrival: park and arm a reaper.
	w := &waiter{s: s, done: make(chan struct{})}
	w.timer = time.AfterFunc(b.timeout, func() {
		b.mu.Lock()
		// Only reap if *this* waiter is still the parked one for the token.
		// If the peer already claimed it, cur != w (or the entry is gone)
		// and we must not touch it.
		if cur, ok := b.waiting[token]; ok && cur == w {
			delete(b.waiting, token)
			b.mu.Unlock()
			w.timedOut = true
			s.Close() // unblock any read the caller may be doing
			close(w.done)
			return
		}
		b.mu.Unlock()
	})
	b.waiting[token] = w
	b.mu.Unlock()

	<-w.done
	if w.timedOut {
		return ErrTimeout
	}
	return nil
}

// splice copies bytes in both directions between two half-connections until
// either side closes, then tears both down. It blocks until both copy
// directions have finished.
func splice(a, b stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src stream) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Closing both ends collapses the other direction's blocking Read
		// so its io.Copy returns and the session unwinds promptly.
		_ = dst.Close()
		_ = src.Close()
	}

	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}
