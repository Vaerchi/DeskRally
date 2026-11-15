package controlplane

// The bounded lookup lifecycle (docs/66 2f). The control plane's only database driver is jackc/pgx v5 over TCP.
// A public lookup must never hold a goroutine, a connection or an admission permit past a fixed bound, even if
// the database stops answering:
//
//  1. the connection is ACQUIRED explicitly (not through Pool.QueryRow), so we own its lifecycle;
//  2. an explicit SOCKET deadline is armed on the underlying net.Conn at (lookup deadline + lookupHardGrace),
//     i.e. admission + 1 s: even a cancellation path that misbehaves cannot block a read or write past it;
//  3. context cancellation (pgx's context watcher forces the net.Conn deadline into the past and closes the
//     connection) ends the lookup at the work deadline;
//  4. if the lookup failed for ANY reason other than a clean "no row", the connection is DESTROYED, never
//     returned to the pool: hijacked out of the pool and closed at the socket;
//  5. on success the socket deadline is cleared before the connection goes back.
//
// The caller (the redeem handler) runs the lookup on its own goroutine holding the admission permit until this
// function returns, and releases its generic rejection on schedule without waiting for it.

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lookupHardGrace is added to the lookup context's deadline to give the socket deadline (admission + 1 s when
// the work deadline is 250 ms).
const lookupHardGrace = 750 * time.Millisecond

// lookupHardDeadline is when the raw socket gives up: the context deadline plus the grace, or now + 1 s when
// the context has no deadline.
func lookupHardDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl.Add(lookupHardGrace)
	}
	return time.Now().Add(time.Second)
}

// DefaultLookupPoolConns is the size of the dedicated pool for anonymous lookups (public branding, attended
// redeem), separate from the shared control-plane pool so that anonymous traffic on a slow database cannot hold
// the connections the console needs (docs/66 release gate R1). A lookup holds its connection for about a
// millisecond and returns it before the response floor, so a few connections serve far more than the admitted rate.
const DefaultLookupPoolConns = 8

// LookupPoolConfig derives the dedicated lookup pool's configuration from the shared pool's: the same DSN, role,
// ConnectTimeout and statement_timeout (it MUST stay a copy: the role/RLS verification, docs/25 F13, runs on the
// shared pool only and covers this one because the DSN and role are the same), conns connections (the default when
// conns <= 0), and every one of them kept open. A lookup that has to dial waits for connection set-up inside its
// 100 ms work window: in the release gate's cold path (docs/66), with one connection kept open, a burst after an idle
// spell lost about 30% of its lookups to the cutoff, so a branded host answered neutral to its first visitors.
func LookupPoolConfig(shared *pgxpool.Config, conns int) *pgxpool.Config {
	c := shared.Copy()
	if conns <= 0 {
		conns = DefaultLookupPoolConns
	}
	c.MaxConns = int32(conns)
	c.MinConns = int32(conns)
	return c
}

// lookupPoolOr returns the dedicated lookup pool when one is wired, else the shared pool.
func lookupPoolOr(lookup, shared *pgxpool.Pool) *pgxpool.Pool {
	if lookup != nil {
		return lookup
	}
	return shared
}

// boundedLookup runs fn on an explicitly acquired connection under the lifecycle above.
func boundedLookup(ctx context.Context, pool *pgxpool.Pool, fn func(c *pgxpool.Conn) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	nc := conn.Conn().PgConn().Conn()
	_ = nc.SetDeadline(lookupHardDeadline(ctx))
	err = fn(conn)
	// A clean "no row" leaves the connection healthy; everything else (cancellation, timeout, a broken
	// connection, a protocol error) destroys it.
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		if !conn.Conn().IsClosed() {
			_ = nc.SetDeadline(time.Time{})
		}
		conn.Release()
		return err
	}
	destroyConn(conn, nc)
	return err
}

// destroyConn removes the connection from the pool and closes its socket immediately (no Terminate message,
// no waiting on a peer that may never answer).
func destroyConn(conn *pgxpool.Conn, nc net.Conn) {
	_ = nc.Close()
	hijacked := conn.Hijack()
	_ = hijacked.PgConn().Conn().Close()
}
