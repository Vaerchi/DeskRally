package main

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// pairTimeoutRun is one started Broker.Handle call.
type pairTimeoutRun struct {
	done chan struct{} // closed when Handle has returned
	err  error         // valid once done is closed
}

// pairTimeoutHandle runs b.Handle in a goroutine and registers an
// unconditional cleanup that closes the stream, releases the waiter if it is
// still parked (closing a stream does not wake an unpaired Handle, which would
// otherwise sit until the timer fires) and waits, bounded, for Handle to
// return. It is safe to call on every path, including early test failures.
func pairTimeoutHandle(t *testing.T, b *Broker, token string, s stream) *pairTimeoutRun {
	t.Helper()
	r := &pairTimeoutRun{done: make(chan struct{})}
	go func() {
		r.err = b.Handle(token, s)
		close(r.done)
	}()
	t.Cleanup(func() {
		_ = s.Close()
		// The Handle goroutine may not have registered its waiter yet, so a
		// single inspection could find nothing and then leave Handle parked
		// for the full timeout. Re-inspect until Handle has returned.
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			b.mu.Lock()
			if w, ok := b.waiting[token]; ok && w.s == s {
				delete(b.waiting, token)
				w.timer.Stop()
				b.mu.Unlock()
				close(w.done)
			} else {
				b.mu.Unlock()
			}
			select {
			case <-r.done:
				return
			case <-deadline.C:
				t.Errorf("Handle for token %q did not return during cleanup (goroutine leak)", token)
				return
			case <-tick.C:
			}
		}
	})
	return r
}

// pairTimeoutPipe returns a (relay side, client side) net.Pipe pair, both
// closed on cleanup.
func pairTimeoutPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	relaySide, client := net.Pipe()
	t.Cleanup(func() {
		_ = relaySide.Close()
		_ = client.Close()
	})
	return relaySide, client
}

func TestBrokerPositiveTimeoutStillReapsUnpaired(t *testing.T) {
	b := NewBroker(100*time.Millisecond, 0)
	relaySide, _ := pairTimeoutPipe(t)

	start := time.Now()
	run := pairTimeoutHandle(t, b, "tok-positive", relaySide)
	select {
	case <-run.done:
		if !errors.Is(run.err, ErrTimeout) {
			t.Fatalf("Handle error = %v, want ErrTimeout", run.err)
		}
		if el := time.Since(start); el < 80*time.Millisecond {
			t.Fatalf("reaped after %v, want about 100ms", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unpaired half-connection was never reaped")
	}
}

func TestNewBrokerNonPositiveTimeoutUsesDefault(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		if got := NewBroker(d, 0).timeout; got != defaultWait {
			t.Errorf("NewBroker(%v, 0).timeout = %v, want %v", d, got, defaultWait)
		}
	}
}

func TestBrokerZeroTimeoutStillPairs(t *testing.T) {
	b := NewBroker(0, 0)
	relayA, clientA := pairTimeoutPipe(t)
	relayB, clientB := pairTimeoutPipe(t)

	runA := pairTimeoutHandle(t, b, "tok-zero", relayA)
	// Let the first half park before the peer arrives.
	select {
	case <-runA.done:
		t.Fatalf("first half returned early with %v", runA.err)
	case <-time.After(150 * time.Millisecond):
	}
	runB := pairTimeoutHandle(t, b, "tok-zero", relayB)

	deadline := time.Now().Add(5 * time.Second)
	_ = clientA.SetDeadline(deadline)
	_ = clientB.SetDeadline(deadline)

	roundTrip := func(from, to net.Conn, msg string) {
		t.Helper()
		werr := make(chan error, 1)
		go func() {
			_, err := from.Write([]byte(msg))
			werr <- err
		}()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(to, buf); err != nil {
			t.Fatalf("read %q: %v", msg, err)
		}
		if string(buf) != msg {
			t.Fatalf("got %q, want %q", buf, msg)
		}
		if err := <-werr; err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
	}
	roundTrip(clientA, clientB, "a-to-b")
	roundTrip(clientB, clientA, "b-to-a")

	// End the session; both Handle calls must return nil.
	_ = clientA.Close()
	for i, run := range []*pairTimeoutRun{runA, runB} {
		select {
		case <-run.done:
			if run.err != nil {
				t.Fatalf("Handle %d returned %v, want nil", i, run.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Handle %d did not return after session close", i)
		}
	}
}

func TestBrokerZeroTimeoutKeepsFirstHalfParked(t *testing.T) {
	b := NewBroker(0, 0)
	relaySide, client := pairTimeoutPipe(t)

	// Cleanup registered here releases the parked waiter on every path.
	run := pairTimeoutHandle(t, b, "tok-parked", relaySide)

	select {
	case <-run.done:
		t.Fatalf("Handle returned %v within 300ms, want still parked", run.err)
	case <-time.After(300 * time.Millisecond):
	}

	// A closed connection would report EOF/closed; a parked one just times out.
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := client.Read(make([]byte, 1))
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read on parked connection = %v, want a deadline timeout (connection still open)", err)
	}
	if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
		t.Fatalf("parked connection was closed: %v", err)
	}
}

func TestEffectivePairTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero", 0, defaultWait},
		{"negative", -time.Second, defaultWait},
		{"one nanosecond", time.Nanosecond, time.Nanosecond},
		{"five seconds", 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectivePairTimeout(tc.in); got != tc.want {
				t.Fatalf("effectivePairTimeout(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
