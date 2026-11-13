package controlplane

// docs/66 release gate R1: the anonymous lookups (public branding, attended redeem) run on the dedicated LookupPool
// when one is wired, never on the shared pool. Proof by exhaustion: a one-connection lookup pool whose connection is
// held makes the lookup wait (and fail at its deadline) while the shared pool is idle. Releasing it makes the same
// lookup answer. With no LookupPool wired the store keeps using the shared pool (the negative control).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// heldOneConnPool returns a pool of exactly one connection to the same database as shared, with that connection
// acquired, and a release func.
func heldOneConnPool(t *testing.T, shared *pgxpool.Pool) (*pgxpool.Pool, func()) {
	t.Helper()
	cfg := shared.Config().Copy()
	cfg.MaxConns, cfg.MinConns = 1, 0
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			c.Release()
		}
	}
	t.Cleanup(release)
	return p, release
}

func shortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestPgAttendedRedeemUsesTheLookupPool(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool) // 0008
	applyDeviceIdentityMigration(t, pool)      // 0010
	applyAttendedMigration(t, pool)            // 0013

	lookup, release := heldOneConnPool(t, pool)

	// Negative control: no LookupPool wired, so the held lookup pool is irrelevant and a bad code answers at once.
	plain := NewPgAttendedStore(pool)
	if _, err := plain.Redeem(shortCtx(t), "ZZZZZZZZZZZZ", attendTestPubkey, ""); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("without a LookupPool: err=%v, want ErrAttendedInvalid", err)
	}

	store := NewPgAttendedStore(pool)
	store.LookupPool = lookup
	if _, err := store.Redeem(shortCtx(t), "ZZZZZZZZZZZZ", attendTestPubkey, ""); err == nil || errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("with the lookup pool exhausted: err=%v, want a deadline error (the lookup must wait on LookupPool, not use the shared pool)", err)
	}
	release()
	if _, err := store.Redeem(shortCtx(t), "ZZZZZZZZZZZZ", attendTestPubkey, ""); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("after releasing the lookup connection: err=%v, want ErrAttendedInvalid", err)
	}
}

func TestPgPublicBrandingLookupUsesTheLookupPool(t *testing.T) {
	fx := newPgBrandFx(t)
	shared := fx.h.pf.app
	lookup, release := heldOneConnPool(t, shared)

	plain := NewPgBrandingRevisionStore(shared, fx.h.pf.audit)
	if p, err := plain.PublicLookup(shortCtx(t), "unmapped.example.test", false); err != nil || p != nil {
		t.Fatalf("without a LookupPool: (%v, %v), want (nil, nil) for an unmapped host", p, err)
	}

	store := NewPgBrandingRevisionStore(shared, fx.h.pf.audit)
	store.LookupPool = lookup
	if _, err := store.PublicLookup(shortCtx(t), "unmapped.example.test", false); err == nil {
		t.Fatal("with the lookup pool exhausted: the lookup answered, so it did not use LookupPool")
	}
	release()
	if p, err := store.PublicLookup(shortCtx(t), "unmapped.example.test", false); err != nil || p != nil {
		t.Fatalf("after releasing the lookup connection: (%v, %v), want (nil, nil)", p, err)
	}
}

func TestPgKeyTombstonedUsesTheLookupPool(t *testing.T) {
	ctx := context.Background()
	su := freshMigrationDatabase(t)
	if _, err := Migrate(ctx, su, "migrations", MigrateOptions{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := su.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "rmt_app", ""
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	lookup, release := heldOneConnPool(t, app)
	const key = "11aa22bb33cc44dd55ee66ff7788990011aa22bb33cc44dd55ee66ff77889900"

	if gone, err := NewPgMachineStore(app).KeyTombstoned(shortCtx(t), key); err != nil || gone {
		t.Fatalf("without a LookupPool: (%v, %v), want (false, nil)", gone, err)
	}
	store := NewPgMachineStore(app)
	store.LookupPool = lookup
	if _, err := store.KeyTombstoned(shortCtx(t), key); err == nil {
		t.Fatal("with the lookup pool exhausted: KeyTombstoned answered, so it did not use LookupPool")
	}
	release()
	if gone, err := store.KeyTombstoned(shortCtx(t), key); err != nil || gone {
		t.Fatalf("after releasing the lookup connection: (%v, %v), want (false, nil)", gone, err)
	}
}

// The lookup pool is a copy of the shared pool's configuration (the F13 role check covers it only because DSN and role
// are the same) with every connection kept open: the release gate's cold path lost about 30% of a burst's lookups to
// the 100 ms cutoff while only one connection was kept (docs/66). No database needed.
func TestLookupPoolConfigCopiesTheSharedPoolAndKeepsEveryConnectionOpen(t *testing.T) {
	shared, err := pgxpool.ParseConfig("postgres://rmt_app@db.example:5432/rmt?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	shared.MaxConns = 16
	shared.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	for _, tc := range []struct{ conns, want int32 }{{8, 8}, {3, 3}, {0, DefaultLookupPoolConns}, {-1, DefaultLookupPoolConns}} {
		c := LookupPoolConfig(shared, int(tc.conns))
		if c.MaxConns != tc.want || c.MinConns != tc.want {
			t.Errorf("conns=%d: MaxConns=%d MinConns=%d, want both %d", tc.conns, c.MaxConns, c.MinConns, tc.want)
		}
		if c.ConnConfig.Host != "db.example" || c.ConnConfig.User != "rmt_app" || c.ConnConfig.Database != "rmt" ||
			c.ConnConfig.ConnectTimeout != time.Second || c.ConnConfig.RuntimeParams["statement_timeout"] != "10000" {
			t.Errorf("conns=%d: not a copy of the shared configuration: %+v", tc.conns, c.ConnConfig)
		}
	}
	// A copy, not an alias: changing the lookup configuration leaves the shared one alone.
	c := LookupPoolConfig(shared, 8)
	c.ConnConfig.RuntimeParams["statement_timeout"] = "1"
	if shared.MaxConns != 16 || shared.MinConns != 0 || shared.ConnConfig.RuntimeParams["statement_timeout"] != "10000" {
		t.Errorf("the shared configuration changed: MaxConns=%d MinConns=%d params=%v", shared.MaxConns, shared.MinConns, shared.ConnConfig.RuntimeParams)
	}
}
