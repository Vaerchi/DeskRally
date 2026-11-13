package controlplane

// The pg half of review #5: releaseBoundConn really returns the pinned pooled connection (asserted
// from the pool's own statistics), later store calls still work through a fresh pool connection,
// and the middleware's deferred release does not double-release.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPgReleaseBoundConnReturnsThePooledConnectionEarly(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	ctx := context.Background()
	tid, _ := provisionUser(t, suPool, "bound-release", "x@bound-release.test", "password-1234")
	pool := newAppRolePool(t, ctx)
	b := NewPgBinder(pool)

	bctx, release, err := b.BindTenant(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.Stat().AcquiredConns(); got != 1 {
		t.Fatalf("bound request holds %d pooled connections, want 1", got)
	}
	// Work on the pinned connection while it is held.
	if err := withTenant(bctx, pool, tid, func(tx pgx.Tx) error { _, e := tx.Exec(bctx, "SELECT 1"); return e }); err != nil {
		t.Fatalf("query on the pinned connection: %v", err)
	}

	releaseBoundConn(bctx)
	if got := pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("after releaseBoundConn the request still holds %d pooled connections, want 0", got)
	}
	// A later store call (e.g. a post-stream audit) works, on a fresh connection that is returned too.
	if err := withTenant(bctx, pool, tid, func(tx pgx.Tx) error { _, e := tx.Exec(bctx, "SELECT 1"); return e }); err != nil {
		t.Fatalf("query after release: %v", err)
	}
	if got := pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("a post-release store call leaked %d connections", got)
	}
	release() // the middleware's deferred release: must be a no-op
	if got := pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("double release changed the pool: %d acquired", got)
	}
	// The recycled connection no longer carries the tenant pin.
	var cur string
	if err := pool.QueryRow(ctx, "SELECT coalesce(current_setting('app.current_tenant', true), '')").Scan(&cur); err != nil || cur != "" {
		t.Fatalf("recycled connection still pinned to %q (%v)", cur, err)
	}
}
