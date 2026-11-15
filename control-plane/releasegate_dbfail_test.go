//go:build releasegate

package controlplane

// The docs/66 release gate's database-failure states (plan step 3). Each failure host is seeded exactly like the
// published one, so a healthy store would answer its branding; a test-only router sends its lookups to a store whose
// database fails in one real way:
//
//	refused  the pool dials a loopback port nobody listens on
//	reset    the pool dials a listener that resets every connection the moment it is accepted
//	timeout  the real database, but the session's search_path resolves cp_public_branding_lookup to a shadow that
//	         sleeps, so the read's own SET LOCAL statement_timeout = 100 ends it with a real 57014
//
// Every such lookup must fail, every response must be the neutral one, and the timing statistic must hold across
// all states, failures included. The proof step: the router counts each routed lookup's outcome, and every one of
// them must have FAILED (a fault that never fired would prove nothing).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type gateFault struct {
	ok, failed atomic.Int64
	mu         sync.Mutex
	kinds      map[string]int
}

// gateRouter is the test-only decorator: hosts in routes read from their fault store, everything else from the real
// one.
type gateRouter struct {
	BrandingRevisionStore
	routes map[string]BrandingRevisionStore
	faults map[string]*gateFault
	// deadline counts the routed lookups that ended at the work deadline, per route ("json" / "logo"): the cuts the
	// faults themselves cause, which the warm-path rule excuses one by one.
	deadline map[string]*atomic.Int64
}

func (r *gateRouter) PublicLookup(ctx context.Context, host string, wantLogo bool) (*PublishedBranding, error) {
	s, ok := r.routes[host]
	if !ok {
		return r.BrandingRevisionStore.PublicLookup(ctx, host, wantLogo)
	}
	p, err := s.PublicLookup(ctx, host, wantLogo)
	f := r.faults[host]
	if err == nil {
		f.ok.Add(1)
		return p, nil
	}
	f.failed.Add(1)
	if errors.Is(err, context.DeadlineExceeded) {
		rt := "json"
		if wantLogo {
			rt = "logo"
		}
		r.deadline[rt].Add(1)
	}
	f.mu.Lock()
	f.kinds[gateErrKind(err)]++
	f.mu.Unlock()
	return p, err
}

// gateErrKind names a failure for the record: the SQLSTATE when the server answered, otherwise the transport's own
// words, cut to a few.
func gateErrKind(err error) string {
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe):
		return "sqlstate " + pe.Code
	case errors.Is(err, context.DeadlineExceeded):
		return "work deadline"
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{"refused", "reset", "forcibly closed", "eof", "timeout"} {
		if strings.Contains(s, k) {
			return k
		}
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// gateDeadPort is a loopback port nobody listens on (bound, then released).
func gateDeadPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return uint16(port)
}

// gateResetListener accepts every connection and resets it at once (SO_LINGER 0).
func gateResetListener(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// gateFaultPool is a pool with the production lookup configuration pointed elsewhere (or with a search_path), never
// pre-dialled.
func gateFaultPool(t *testing.T, base *pgxpool.Pool, mutate func(*pgxpool.Config)) *pgxpool.Pool {
	t.Helper()
	cfg := base.Config().Copy()
	cfg.MinConns = 0
	mutate(cfg)
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// gateFaultStates are the failure hosts, seeded as published (see newGateBrandEnv's Fault states).
var gateFaultStates = []gateState{
	{Name: "dbfail-refused", Host: "dbfail-refused.gate.test", Fault: true},
	{Name: "dbfail-reset", Host: "dbfail-reset.gate.test", Fault: true},
	{Name: "dbfail-timeout", Host: "dbfail-timeout.gate.test", Fault: true},
}

// gateInstallFaults routes the failure hosts to their fault stores.
func gateInstallFaults(t *testing.T, e *gateBrandEnv) *gateRouter {
	t.Helper()
	ctx := context.Background()
	// The shadow function for the timeout state lives in its own schema, reachable only through that pool's
	// search_path; the real function and every other session are untouched.
	mustExec(t, e.su, `DROP SCHEMA IF EXISTS gate_slow CASCADE`)
	mustExec(t, e.su, `CREATE SCHEMA gate_slow`)
	mustExec(t, e.su, `CREATE FUNCTION gate_slow.cp_public_branding_lookup(p_host text, p_want_logo boolean)
		RETURNS TABLE (product_name text, accent_color text, support_text text, support_contact_kind text,
		               support_contact_value text, logo_sha256 text, logo_png bytea)
		LANGUAGE plpgsql VOLATILE AS $$
		BEGIN
		  PERFORM pg_sleep(2); -- plpgsql: a SQL body with WHERE false let the planner skip the sleep (the proof step caught it)
		  RETURN;
		END
		$$`)
	mustExec(t, e.su, `GRANT USAGE ON SCHEMA gate_slow TO rmt_app`)
	mustExec(t, e.su, `GRANT EXECUTE ON FUNCTION gate_slow.cp_public_branding_lookup(text, boolean) TO rmt_app`)
	t.Cleanup(func() { _, _ = e.su.Exec(ctx, `DROP SCHEMA IF EXISTS gate_slow CASCADE`) })

	store := func(p *pgxpool.Pool) BrandingRevisionStore {
		s := NewPgBrandingRevisionStore(p, NewPgMgmtAuditStore(p))
		s.LookupPool = p
		return s
	}
	dead, reset := gateDeadPort(t), gateResetListener(t)
	refusedPool := gateFaultPool(t, e.lookup, func(c *pgxpool.Config) { c.ConnConfig.Host, c.ConnConfig.Port = "127.0.0.1", dead })
	resetPool := gateFaultPool(t, e.lookup, func(c *pgxpool.Config) { c.ConnConfig.Host, c.ConnConfig.Port = "127.0.0.1", reset })
	slowPool := gateFaultPool(t, e.lookup, func(c *pgxpool.Config) { c.ConnConfig.RuntimeParams["search_path"] = "gate_slow, public" })

	r := &gateRouter{BrandingRevisionStore: e.srv.BrandingRevisions, routes: map[string]BrandingRevisionStore{
		"dbfail-refused.gate.test": store(refusedPool),
		"dbfail-reset.gate.test":   store(resetPool),
		"dbfail-timeout.gate.test": store(slowPool),
	}, faults: map[string]*gateFault{}, deadline: map[string]*atomic.Int64{"json": {}, "logo": {}}}
	for h := range r.routes {
		r.faults[h] = &gateFault{kinds: map[string]int{}}
	}
	// The fault stores must actually fail, and the healthy store must actually find the same hosts (the premise that
	// a neutral answer under fault is the fault's doing, not a missing row).
	for h, s := range r.routes {
		if p, err := s.PublicLookup(ctx, h, false); err == nil {
			t.Fatalf("release gate: the %s fault store answered %v; the fault is not installed", h, p)
		}
		if p, err := e.srv.BrandingRevisions.PublicLookup(ctx, h, false); err != nil || p == nil {
			t.Fatalf("release gate: %s is not published in the healthy store (%v, %v)", h, p, err)
		}
	}
	e.srv.BrandingRevisions = r // before any request: the handler reads the field per request
	e.excusedCuts = func(route string) int64 { return r.deadline[route].Load() }
	return r
}

// 2c.3, database-failure states: three ways the anonymous read can fail, each on a host that is really published.
// The responses must be neutral and indistinguishable in time from every other state; every routed lookup must have
// failed.
func TestReleaseGateBrandingDBFailure(t *testing.T) {
	e := newGateBrandEnv(t, gateEnvOpts{faults: gateFaultStates})
	r := gateInstallFaults(t, e)
	for _, f := range runGateBranding(t, e, 16, false) {
		t.Errorf("release gate FAIL: %s", f)
	}
	hosts := make([]string, 0, len(r.faults))
	for h := range r.faults {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		f := r.faults[h]
		f.mu.Lock()
		kinds := fmt.Sprint(f.kinds)
		f.mu.Unlock()
		t.Logf("fault %s: failed=%d succeeded=%d kinds=%s", h, f.failed.Load(), f.ok.Load(), kinds)
		if f.ok.Load() != 0 || f.failed.Load() < int64(gateMinSamples) {
			t.Errorf("release gate: the %s fault did not fire on every lookup (failed=%d succeeded=%d)", h, f.failed.Load(), f.ok.Load())
		}
	}
}
