package controlplane

// PgBinder — the REAL TenantBinder (the RLS hook http.go's seam documents).
//
// The tenant middleware calls BindTenant once per authenticated request. PgBinder acquires a
// dedicated pooled connection, pins the caller's tenant on it at SESSION level with
// `SELECT set_config('app.current_tenant', $1, false)`, and stashes the pinned connection on
// the request context. From that point EVERY query the request issues through that connection
// — the pgx stores (withTenant picks the bound connection up automatically) and any future
// ad-hoc handler query — is confined to the caller's tenant by PostgreSQL Row-Level Security,
// not by application discipline. This is what makes RLS load-bearing for the general handler
// path rather than only for the stores that self-pin.
//
// Connection hygiene: pooled connections are REUSED across requests (and therefore across
// tenants), so the release function returned by BindTenant resets the GUC before handing the
// connection back. If the reset cannot be executed the underlying connection is closed instead
// of being returned pinned — a stale app.current_tenant on a recycled connection would be a
// cross-tenant time bomb. Defense in depth: the stores' withTenant additionally re-pins the
// tenant transaction-locally (set_config is_local=true) and refuses a context bound to a
// DIFFERENT tenant, so even a bookkeeping bug cannot silently cross tenants.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// boundConn is the per-request tenant-pinned connection carried on the request context.
type boundConn struct {
	conn     *pgxpool.Conn
	tenantID string

	// releaseFn gives the connection back (reset GUC, return to the pool). It runs AT MOST ONCE, via
	// release(): the tenant middleware defers it, and a handler that is about to stream bytes for a
	// long time calls releaseBoundConn first so it does not pin one of the few pooled connections
	// for the whole transfer (security review 2026-11-01 #5).
	releaseFn   func()
	releaseOnce sync.Once
	released    atomic.Bool
}

// release is idempotent. It marks the connection released BEFORE giving it back, so a later
// boundConnFrom answers nil and stores fall back to a fresh pool connection.
func (bc *boundConn) release() {
	bc.releaseOnce.Do(func() {
		bc.released.Store(true)
		if bc.releaseFn != nil {
			bc.releaseFn()
		}
	})
}

// releaseBoundConn returns the request's pinned tenant connection to the pool NOW. Call it after
// every database read/write the request needs is done and before streaming a large body; any
// later store call transparently uses a fresh pool connection (withTenant re-pins per
// transaction), and the middleware's deferred release becomes a no-op.
func releaseBoundConn(ctx context.Context) {
	if bc, _ := ctx.Value(boundConnKey{}).(*boundConn); bc != nil {
		bc.release()
	}
}

// boundConnKey is the private context key for the bound connection.
type boundConnKey struct{}

// boundConnFrom returns the request's tenant-pinned connection, or nil when the request was
// bound by a non-DB binder (NoopBinder in dev) or no binding has happened (pre-auth paths).
func boundConnFrom(ctx context.Context) *boundConn {
	bc, _ := ctx.Value(boundConnKey{}).(*boundConn)
	if bc != nil && bc.released.Load() {
		return nil
	}
	return bc
}

// withoutBoundConn returns ctx with NO request-pinned connection, so stores fall back to a fresh pool
// connection (withTenant still pins the tenant per transaction, so RLS is unchanged). For work that
// must outlive the request: when the client disconnects, the request's pinned connection is closed,
// and a cleanup that reused it failed with "conn closed" even on an uncancelled context.
func withoutBoundConn(ctx context.Context) context.Context {
	return context.WithValue(ctx, boundConnKey{}, (*boundConn)(nil))
}

// PgBinder is the pgx-backed TenantBinder.
type PgBinder struct {
	Pool *pgxpool.Pool
}

// NewPgBinder constructs a PgBinder.
func NewPgBinder(pool *pgxpool.Pool) *PgBinder { return &PgBinder{Pool: pool} }

var _ TenantBinder = (*PgBinder)(nil)

// releaseTimeout bounds the post-request GUC reset. The request context is typically already
// done by the time release runs, so the reset uses its own deadline.
const releaseTimeout = 5 * time.Second

// BindTenant implements TenantBinder: acquire a connection, pin the tenant on it for the
// lifetime of the request, and return the carrying context plus the release function the
// middleware must defer. Fails closed on an empty tenant id.
func (b *PgBinder) BindTenant(ctx context.Context, tenantID string) (context.Context, func(), error) {
	if tenantID == "" {
		return nil, nil, errors.New("empty tenant id")
	}
	acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := b.Pool.Acquire(acquireCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("acquire connection: %w", err)
	}
	// Session-level pin (is_local = false): survives across the multiple per-store
	// transactions a handler runs on this connection, until release resets it.
	if _, err := conn.Exec(ctx, "SELECT set_config('app.current_tenant', $1, false)", tenantID); err != nil {
		conn.Release()
		return nil, nil, fmt.Errorf("pin tenant: %w", err)
	}
	bc := &boundConn{conn: conn, tenantID: tenantID}
	bc.releaseFn = func() {
		rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		// A handler that panicked between holdIssuance and its deferred release would return this
		// connection still holding a shared issuance lock, blocking that tenant's suspension for as
		// long as the pool kept it. Drop every session-level advisory lock before reuse.
		if _, err := conn.Exec(rctx, "SELECT pg_advisory_unlock_all()"); err != nil {
			_ = conn.Conn().Close(rctx)
		}
		if _, err := conn.Exec(rctx, "RESET app.current_tenant"); err != nil {
			// Never return a still-pinned connection to the pool: close the underlying
			// connection so the pool discards it instead of recycling it into another
			// tenant's request. (RESET leaves the GUC empty/unset; either state makes the
			// RLS policies RAISE rather than match, so a missed re-pin stays loud.)
			_ = conn.Conn().Close(rctx)
		}
		conn.Release()
	}
	return context.WithValue(ctx, boundConnKey{}, bc), bc.release, nil
}
