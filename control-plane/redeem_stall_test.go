package controlplane

// docs/66 2e.1 + 2f: a stalled database must not hold a goroutine, a pooled connection or an admission permit
// beyond the bound, and must not delay the generic rejection. REAL TCP: a fake Postgres endpoint that accepts
// and never answers, and one that completes the startup and then stalls mid-query.
//
// The 5-minute soak of the release gate is HOST_STALL_SOAK=300s; the unit suite runs a few seconds.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakePG struct {
	ln    net.Listener
	mode  string // "silent": accept and never answer; "midquery": answer the startup, stall every query
	open  atomic.Int32
	total atomic.Int32
}

func newFakePG(t *testing.T, mode string) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{ln: ln, mode: mode}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.open.Add(1)
			f.total.Add(1)
			go f.serve(c)
		}
	}()
	return f
}

func pgMsg(typ byte, body []byte) []byte {
	b := make([]byte, 5+len(body))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], uint32(4+len(body)))
	copy(b[5:], body)
	return b
}

func (f *fakePG) serve(c net.Conn) {
	defer func() { _ = c.Close(); f.open.Add(-1) }()
	if f.mode == "silent" {
		_, _ = io.Copy(io.Discard, c) // never answers; ends when the client closes
		return
	}
	var l [4]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return
	}
	startup := make([]byte, binary.BigEndian.Uint32(l[:])-4)
	if _, err := io.ReadFull(c, startup); err != nil {
		return
	}
	out := pgMsg('R', []byte{0, 0, 0, 0})
	for _, kv := range [][2]string{{"server_version", "16.4"}, {"client_encoding", "UTF8"}, {"standard_conforming_strings", "on"}, {"integer_datetimes", "on"}} {
		out = append(out, pgMsg('S', append(append([]byte(kv[0]), 0), append([]byte(kv[1]), 0)...))...)
	}
	out = append(out, pgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})...)
	out = append(out, pgMsg('Z', []byte{'I'})...)
	if _, err := c.Write(out); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c) // every query is read and never answered
}

func (f *fakePG) pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://u:p@%s/db?sslmode=disable&pool_max_conns=8", f.ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.ConnectTimeout = time.Second
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func eventually(t *testing.T, within time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < within {
		if cond() {
			return time.Since(start)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: not recovered within %v", what, within)
	return 0
}

// Store level, no context deadline: the raw SOCKET deadline (now + 1 s) is the backstop that ends a stalled
// lookup, and the connection is destroyed, not returned to the pool.
func TestStalledLookupIsEndedByTheSocketDeadlineAndTheConnectionIsDestroyed(t *testing.T) {
	f := newFakePG(t, "midquery")
	pool := f.pool(t)
	store := NewPgAttendedStore(pool)
	start := time.Now()
	_, err := store.RedeemScoped(context.Background(), "CODE", randPubkeyHex(t), "G", RedeemScope{Host: "acme.example.test"})
	d := time.Since(start)
	if err == nil {
		t.Fatal("a stalled lookup returned success")
	}
	if d < 900*time.Millisecond || d > 1600*time.Millisecond {
		t.Fatalf("with no context deadline the socket deadline must end the lookup at ~1 s, took %v (%v)", d, err)
	}
	eventually(t, time.Second, "connection destroyed", func() bool { return pool.Stat().TotalConns() == 0 && f.open.Load() == 0 })
}

// Store level, 250 ms context: cancellation ends it at the work deadline, same destruction.
func TestStalledLookupIsEndedByContextCancellation(t *testing.T) {
	f := newFakePG(t, "midquery")
	pool := f.pool(t)
	store := NewPgAttendedStore(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := store.RedeemScoped(ctx, "CODE", randPubkeyHex(t), "G", RedeemScope{Host: "acme.example.test"})
	if err == nil || time.Since(start) > 700*time.Millisecond {
		t.Fatalf("cancellation: %v after %v", err, time.Since(start))
	}
	eventually(t, time.Second, "connection destroyed", func() bool { return pool.Stat().TotalConns() == 0 && f.open.Load() == 0 })
}

// A database that accepts and never answers the CONNECT: the acquire is bounded by the context and the
// half-open connection by ConnectTimeout (1 s), so nothing lingers.
func TestSilentEndpointAcquireIsBoundedAndNothingLingers(t *testing.T) {
	f := newFakePG(t, "silent")
	pool := f.pool(t)
	store := NewPgAttendedStore(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := store.RedeemScoped(ctx, "CODE", randPubkeyHex(t), "G", RedeemScope{Host: "acme.example.test"})
	if err == nil || time.Since(start) > 700*time.Millisecond {
		t.Fatalf("acquire against a silent endpoint: %v after %v", err, time.Since(start))
	}
	eventually(t, 1500*time.Millisecond, "half-open connection closed", func() bool { return f.open.Load() == 0 && pool.Stat().TotalConns() == 0 })
}

func stallServer(t *testing.T, store AttendedStore) *Server {
	t.Helper()
	srv, _ := newAttendedServer(t)
	srv.Attended = store
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = RedeemTuning{AdmitGlobal: 24, AdmitPerIP: 4}
	return srv
}

// HTTP level under load, for both stall shapes: every response is the generic 403 released ON SCHEDULE (the
// 250 ms work cutoff, not the database), and goroutines, permits and connections return to baseline within 1 s
// of the deadline, wave after wave, with no growth.
func TestStalledDatabaseRespondsOnScheduleAndEverythingRecovers(t *testing.T) {
	soak := 4 * time.Second
	if v, err := time.ParseDuration(os.Getenv("HOST_STALL_SOAK")); err == nil && v > 0 {
		soak = v
	}
	for _, mode := range []string{"midquery", "silent"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakePG(t, mode)
			pool := f.pool(t)
			srv := stallServer(t, NewPgAttendedStore(pool))
			runtime.GC()
			baseline := runtime.NumGoroutine()
			deadline := time.Now().Add(soak)
			wave := 0
			var maxGoroutines int
			for time.Now().Before(deadline) {
				wave++
				var wg sync.WaitGroup
				lat := make([]time.Duration, 12)
				codes := make([]int, 12)
				for i := range lat {
					wg.Add(1)
					go func() {
						defer wg.Done()
						start := time.Now()
						rec := postRedeem(srv, "acme.example.test", fmt.Sprintf("10.%d.%d.%d", 50, wave%200, i+1), "CODE")
						lat[i], codes[i] = time.Since(start), rec.Code
						if rec.Code != http.StatusForbidden || rec.Body.String() != `{"error":"invalid attended code"}`+"\n" {
							t.Errorf("wave %d: %d %q, want the generic rejection", wave, rec.Code, rec.Body.String())
						}
					}()
				}
				wg.Wait()
				for i, d := range lat {
					if d < 230*time.Millisecond || d > 900*time.Millisecond {
						t.Errorf("wave %d request %d: released after %v, want ~250 ms (the work cutoff)", wave, i, d)
					}
				}
				rec := eventually(t, 1250*time.Millisecond, "permits, connections and goroutines", func() bool {
					in, _ := srv.redeemPool().stats()
					// Nothing is checked out and no socket outlives its pool slot. (A never-used connection that finished
					// dialing after its caller gave up may sit IDLE in the pool: bounded by pool_max_conns, and every
					// lookup on it is itself bounded.)
					st := pool.Stat()
					return in == 0 && st.AcquiredConns() == 0 && st.TotalConns() <= 8 && int32(st.TotalConns()) == f.open.Load()
				})
				if rec > 1250*time.Millisecond {
					t.Errorf("recovery took %v", rec)
				}
				if g := runtime.NumGoroutine(); g > maxGoroutines {
					maxGoroutines = g
				}
			}
			eventually(t, 2*time.Second, "goroutine baseline", func() bool { return runtime.NumGoroutine() <= baseline+6 })
			t.Logf("%s: %d waves, baseline %d goroutines, peak %d, now %d, connections accepted %d", mode, wave, baseline, maxGoroutines, runtime.NumGoroutine(), f.total.Load())
		})
	}
}

// 2e.1: a lookup that IGNORES cancellation entirely: the response is still released on schedule, the permit is
// held until the lookup actually exits (so the caps bound outstanding work), exhausted permits give the uniform
// 429, and everything recovers once the stall clears.
type deafAttended struct {
	AttendedStore
	release chan struct{}
	entered atomic.Int32
}

func (d *deafAttended) RedeemScoped(context.Context, string, string, string, RedeemScope) (*AttendedRedeem, error) {
	d.entered.Add(1)
	<-d.release // deaf to the context
	return nil, ErrAttendedInvalid
}

func TestLookupThatIgnoresCancellationKeepsItsPermitButNotTheResponse(t *testing.T) {
	srv, _ := newAttendedServer(t)
	d := &deafAttended{AttendedStore: srv.Attended, release: make(chan struct{})}
	srv.Attended = d
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = RedeemTuning{AdmitGlobal: 3, AdmitPerIP: 3}
	before := runtime.NumGoroutine()

	for i := 0; i < 3; i++ {
		start := time.Now()
		rec := postRedeem(srv, "acme.example.test", fmt.Sprintf("10.60.0.%d", i+1), "CODE")
		if el := time.Since(start); rec.Code != http.StatusForbidden || el < 230*time.Millisecond || el > 900*time.Millisecond {
			t.Fatalf("stalled lookup %d: %d after %v, want the generic 403 at ~250 ms", i, rec.Code, el)
		}
	}
	if in, _ := srv.redeemPool().stats(); in != 3 {
		t.Fatalf("permits held by the 3 deaf lookups = %d, want 3 (held until the lookup exits)", in)
	}
	// Capacity exhausted by outstanding cleanup work: the uniform 429, immediately.
	start := time.Now()
	rec := postRedeem(srv, "acme.example.test", "10.60.1.1", "CODE")
	if rec.Code != http.StatusTooManyRequests || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("with permits exhausted: %d after %v, want an immediate 429", rec.Code, time.Since(start))
	}
	close(d.release) // the stall clears
	eventually(t, time.Second, "permits and goroutines", func() bool {
		in, _ := srv.redeemPool().stats()
		return in == 0 && runtime.NumGoroutine() <= before+3
	})
	if rec := postRedeem(srv, "acme.example.test", "10.60.2.1", "CODE"); rec.Code != http.StatusForbidden {
		t.Fatalf("after recovery: %d", rec.Code)
	}
}

// The hard socket deadline is admission + 1 s when the lookup context carries the 250 ms work deadline.
func TestLookupHardDeadlineIsAdmissionPlusOneSecond(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultRedeemWorkDeadline)
	defer cancel()
	dl, _ := ctx.Deadline()
	if got := lookupHardDeadline(ctx).Sub(dl); got != 750*time.Millisecond {
		t.Fatalf("grace = %v, want 750 ms (250 ms + 750 ms = 1 s from admission)", got)
	}
	if got := time.Until(lookupHardDeadline(context.Background())); got < 900*time.Millisecond || got > time.Second {
		t.Fatalf("no context deadline: %v, want ~1 s from now", got)
	}
}

// Any lookup failure destroys the connection explicitly: it is never returned to the pool, even when the socket
// is still healthy (a driver that failed to close it itself cannot leak a suspect connection).
func TestAFailedLookupDestroysItsConnectionEvenIfTheSocketIsHealthy(t *testing.T) {
	f := newFakePG(t, "midquery")
	pool := f.pool(t)
	err := boundedLookup(context.Background(), pool, func(c *pgxpool.Conn) error { return fmt.Errorf("lookup failed") })
	if err == nil {
		t.Fatal("error swallowed")
	}
	eventually(t, time.Second, "connection destroyed", func() bool { return pool.Stat().TotalConns() == 0 && f.open.Load() == 0 })
	// A clean no-row keeps the (healthy) connection.
	f2 := newFakePG(t, "midquery")
	pool2 := f2.pool(t)
	if err := boundedLookup(context.Background(), pool2, func(c *pgxpool.Conn) error { return pgx.ErrNoRows }); err != pgx.ErrNoRows {
		t.Fatalf("no-rows: %v", err)
	}
	if pool2.Stat().TotalConns() != 1 {
		t.Fatalf("a clean no-row destroyed the connection (total %d)", pool2.Stat().TotalConns())
	}
}
