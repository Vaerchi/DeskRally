package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// registerVerified puts an identity-verified agent in the registry, as handleAgentAuthResponse would.
func registerVerified(srv *Server, device, tenant, pubkey string) *fakeConn {
	conn := &fakeConn{}
	srv.reg.Register(&Peer{DeviceId: device, Tenant: tenant, Pubkey: pubkey, conn: conn, registered: true, LastSeen: time.Now()})
	return conn
}

func closeCode(t *testing.T, conn *fakeConn) int {
	t.Helper()
	conn.mu.Lock()
	defer conn.mu.Unlock()
	for _, f := range conn.rawFrames {
		if f.messageType == websocket.CloseMessage && len(f.data) >= 2 {
			return int(f.data[0])<<8 | int(f.data[1])
		}
	}
	return 0
}

// TestRevalidateDropsOnlyAgentsTheControlPlaneDisowns: one sweep drops an agent whose device the
// control plane no longer resolves (suspended tenant / removed machine), one that moved tenant and one
// whose pinned key changed, and keeps the agent that still resolves identically. Asymmetric on purpose:
// a sweep that dropped everyone, or no one, fails.
func TestRevalidateDropsOnlyAgentsTheControlPlaneDisowns(t *testing.T) {
	const tenantA, tenantB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	resolver := &fakeResolver{identities: map[string]*DeviceIdentity{
		"keep":  {DeviceID: "keep", TenantID: tenantA, Pubkey: "aa"},
		"moved": {DeviceID: "moved", TenantID: tenantB, Pubkey: "bb"},
		"rekey": {DeviceID: "rekey", TenantID: tenantA, Pubkey: "new"},
	}}
	srv := authServer(t, resolver)
	keep := registerVerified(srv, "keep", tenantA, "aa")
	gone := registerVerified(srv, "gone", tenantA, "cc")
	moved := registerVerified(srv, "moved", tenantA, "bb")
	rekey := registerVerified(srv, "rekey", tenantA, "old")

	if n := srv.RevalidateAgents(context.Background()); n != 3 {
		t.Fatalf("dropped %d agents, want 3", n)
	}
	if _, ok := srv.reg.Lookup("keep"); !ok {
		t.Fatal("the agent the control plane still vouches for was dropped")
	}
	if keep.closed || closeCode(t, keep) != 0 {
		t.Fatal("the kept agent's socket was closed")
	}
	for name, c := range map[string]*fakeConn{"gone": gone, "moved": moved, "rekey": rekey} {
		if _, ok := srv.reg.Lookup(name); ok {
			t.Fatalf("%s is still registered", name)
		}
		if !c.closed {
			t.Fatalf("%s socket not closed", name)
		}
		if code := closeCode(t, c); code != websocket.ClosePolicyViolation {
			t.Fatalf("%s close code = %d, want %d", name, code, websocket.ClosePolicyViolation)
		}
	}
}

// TestRevalidateKeepsAgentsWhenControlPlaneIsDown: an outage is not a verdict; nobody is dropped.
func TestRevalidateKeepsAgentsWhenControlPlaneIsDown(t *testing.T) {
	srv := authServer(t, &fakeResolver{err: errors.New("dial tcp: connection refused")})
	conn := registerVerified(srv, "dev", "11111111-1111-1111-1111-111111111111", "aa")
	if n := srv.RevalidateAgents(context.Background()); n != 0 {
		t.Fatalf("dropped %d agents during an outage", n)
	}
	if _, ok := srv.reg.Lookup("dev"); !ok || conn.closed {
		t.Fatal("agent dropped during a control-plane outage")
	}
}

// TestRevalidateDevModeTouchesNothing: without a resolver there is no authority to re-check against.
func TestRevalidateDevModeTouchesNothing(t *testing.T) {
	srv := authServer(t, nil)
	conn := registerVerified(srv, "dev", "t", "k")
	if n := srv.RevalidateAgents(context.Background()); n != 0 || conn.closed {
		t.Fatal("dev-mode sweep dropped an agent")
	}
}

// TestRevalidateBypassesThePositiveCache: the real resolver answered "known" before the suspension and
// cached it for minutes; the sweep must ask the control plane again, not be served the stale positive.
func TestRevalidateBypassesThePositiveCache(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	stub := &identityStub{status: http.StatusOK, body: okBody("dev", tenant, agentAuthGoldenPubkeyHex)}
	r, _ := testResolver(t, stub)
	if _, err := r.Resolve(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	srv := authServer(t, r)
	conn := registerVerified(srv, "dev", tenant, agentAuthGoldenPubkeyHex)

	stub.status, stub.body = http.StatusNotFound, ""
	if n := srv.RevalidateAgents(context.Background()); n != 1 || !conn.closed {
		t.Fatalf("dropped=%d closed=%v: the sweep was served the cached positive", n, conn.closed)
	}
	// And the negative answer is now cached for the next registration attempt.
	before := stub.requests
	if _, err := r.Resolve(context.Background(), "dev"); !errors.Is(err, ErrDeviceUnknown) || stub.requests != before {
		t.Fatalf("err=%v requests %d->%d: the sweep's answer was not cached", err, before, stub.requests)
	}
}

// slowResolver hangs on every device except `gone` until the lookup's context ends, and records the
// most lookups it ever had in flight at once.
type slowResolver struct {
	gone              string
	mu                sync.Mutex
	inFlight, maxSeen int
}

func (r *slowResolver) Resolve(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	if deviceID == r.gone {
		return nil, ErrDeviceUnknown
	}
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.maxSeen {
		r.maxSeen = r.inFlight
	}
	r.mu.Unlock()
	<-ctx.Done()
	r.mu.Lock()
	r.inFlight--
	r.mu.Unlock()
	return nil, ctx.Err()
}

// TestRevalidateSlowLookupsDoNotStarveTheSweep: with many hanging lookups ahead of it, the disowned
// agent is still reached and dropped, because each lookup has its own deadline and the sweep runs
// revalidateConcurrency of them at once; the hanging ones (errors, not verdicts) keep their agents.
func TestRevalidateSlowLookupsDoNotStarveTheSweep(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	resolver := &slowResolver{gone: "gone"}
	srv := authServer(t, resolver)
	srv.revalidateLookupTimeout = 30 * time.Millisecond
	const slow = 4 * revalidateConcurrency
	for i := 0; i < slow; i++ {
		registerVerified(srv, fmt.Sprintf("slow-%d", i), tenant, "aa")
	}
	gone := registerVerified(srv, "gone", tenant, "bb")

	// The sweep's own deadline is far beyond what the bounded lookups need (~4 rounds of 30 ms); a sweep
	// that only finishes because this deadline ended (a lookup without its own deadline) fails.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if n := srv.RevalidateAgents(ctx); n != 1 || !gone.closed {
		t.Fatalf("dropped=%d gone.closed=%v: the disowned agent was not reached", n, gone.closed)
	}
	if ctx.Err() != nil {
		t.Fatal("the sweep ran until its deadline: a hanging lookup was not bounded by its own deadline")
	}
	if srv.reg.Len() != slow {
		t.Fatalf("registry has %d agents, want the %d whose lookups only timed out", srv.reg.Len(), slow)
	}
	if resolver.maxSeen != revalidateConcurrency {
		t.Fatalf("max lookups in flight = %d, want exactly %d", resolver.maxSeen, revalidateConcurrency)
	}
}

// TestRevalidateStopsSchedulingAtTheSweepDeadline: an ended sweep context schedules nothing more and
// drops nobody it did not check.
func TestRevalidateStopsSchedulingAtTheSweepDeadline(t *testing.T) {
	srv := authServer(t, &fakeResolver{identities: map[string]*DeviceIdentity{}})
	conn := registerVerified(srv, "gone", "11111111-1111-1111-1111-111111111111", "aa")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Scheduling races the closed context against a free worker, so either outcome is legal for one
	// sweep; what must hold is that the call returns and is consistent.
	n := srv.RevalidateAgents(ctx)
	if (n == 1) != conn.closed {
		t.Fatalf("dropped=%d but closed=%v", n, conn.closed)
	}
}
