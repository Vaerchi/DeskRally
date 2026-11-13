package main

// Review round 3 of docs/65 (fleet directives), signaling side: each test fails without its fix.

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gateResolver lets a test hold individual lookups before (pre) and after (post) their control-plane read,
// so lookup START order and control-plane READ order can be inverted at will.
type gateResolver struct {
	inner IdentityResolver
	calls atomic.Int32
	pre   map[int32]chan struct{} // call n waits on pre[n] before reading the control plane
	post  map[int32]chan struct{} // call n waits on post[n] after reading it
	read  map[int32]chan struct{} // closed when call n has read the control plane
}

func newGateResolver(inner IdentityResolver, calls ...int32) *gateResolver {
	g := &gateResolver{inner: inner, pre: map[int32]chan struct{}{}, post: map[int32]chan struct{}{}, read: map[int32]chan struct{}{}}
	for _, n := range calls {
		g.pre[n], g.post[n], g.read[n] = make(chan struct{}), make(chan struct{}), make(chan struct{})
	}
	return g
}

func (g *gateResolver) Resolve(ctx context.Context, device string) (*DeviceIdentity, error) {
	n := g.calls.Add(1)
	if ch, ok := g.pre[n]; ok {
		<-ch
	}
	id, err := g.inner.Resolve(ctx, device)
	if ch, ok := g.read[n]; ok {
		close(ch)
	}
	if ch, ok := g.post[n]; ok {
		<-ch
	}
	return id, err
}

// ---- 6. a retired publication removes the normal incumbent, and an older lookup cannot undo it ----

func TestRetiredRegistrationRemovesTheNormalIncumbentBeforeRevalidation(t *testing.T) {
	cp, srv, _, clock := directiveEnv(t)
	normal, normalConn := registerGolden(t, srv, dirFeature)
	if normal.restricted {
		t.Fatal("setup: the first registration should be a normal one")
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok {
		t.Fatal("setup: the active device is not registered")
	}
	cp.setStatus(agentAuthGoldenDevice, "retired")
	*clock = clock.Add(time.Hour) // past the resolver's identity cache
	retired, _ := registerGolden(t, srv, dirFeature)
	if !retired.restricted || !retired.registered {
		t.Fatalf("registered=%v restricted=%v, want a restricted registration", retired.registered, retired.restricted)
	}
	// No revalidation tick has run: the old normal socket must already be gone from presence and the broker.
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("the retired machine's old normal socket is still brokerable")
	}
	if n := len(srv.reg.Snapshot()); n != 0 {
		t.Fatalf("presence lists %d devices, want none", n)
	}
	if srv.reg.Len() != 0 {
		t.Fatalf("Len = %d, want 0", srv.reg.Len())
	}
	waitUntil(t, "the old normal socket is closed", func() bool { return normalConn.closed })
}

// TestOlderActiveAnswerCannotEvictANewerRetiredRegistration is the inverted-ordering scenario: lookup 1
// starts first but reads the control plane LAST; lookup 2 starts second, reads ACTIVE and is held before it
// publishes; the machine is retired; lookup 1 then reads RETIRED and publishes the restricted registration;
// finally lookup 2 is released with its older ACTIVE answer. That answer must not evict the restricted
// connection or restore normal admission. (Ordering publications by lookup START, as the first version did,
// let it through: 2 > 1.)
func TestOlderActiveAnswerCannotEvictANewerRetiredRegistration(t *testing.T) {
	cp, srv, res, clock := directiveEnv(t)
	gate := newGateResolver(res, 1, 2)
	srv.identity = gate
	close(gate.pre[2]) // lookup 2 may read the control plane as soon as it starts

	connect := func() (*Peer, *fakeConn, chan struct{}) {
		conn := &fakeConn{}
		peer := &Peer{conn: conn}
		srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
			Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen, Features: dirFeature,
		}})
		nonce := challengeNonce(t, conn)
		done := make(chan struct{})
		go func() {
			srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
				Device: agentAuthGoldenDevice, Nonce: hex.EncodeToString(nonce),
				Sig: signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, dirTenantID, nonce),
			}})
			close(done)
		}()
		return peer, conn, done
	}
	waitCalls := func(n int32) {
		t.Helper()
		waitUntil(t, "lookup started", func() bool { return gate.calls.Load() >= n })
	}

	peer1, _, done1 := connect()
	waitCalls(1) // lookup 1 is held BEFORE it reads the control plane
	peer2, conn2, done2 := connect()
	// With per-device serialization lookup 2 cannot start while lookup 1 holds the device; without it, it
	// starts at once and reads ACTIVE. Either way, let lookup 2 read if it can.
	select {
	case <-gate.read[2]:
	case <-time.After(700 * time.Millisecond):
	}

	cp.setStatus(agentAuthGoldenDevice, "retired")
	*clock = clock.Add(time.Hour) // past the resolver's identity cache
	close(gate.pre[1])            // lookup 1 reads RETIRED now
	close(gate.post[1])
	select {
	case <-done1:
	case <-time.After(10 * time.Second):
		// Serialized: lookup 1 holds the device until it is published, which needs no help from lookup 2.
		t.Fatal("lookup 1 never finished")
	}
	if !peer1.restricted || !srv.reg.isCurrent(peer1) {
		t.Fatalf("setup: the retired lookup did not publish (restricted=%v)", peer1.restricted)
	}

	// Release lookup 2: its answer (ACTIVE if it read before the retirement) is older than what is published.
	close(gate.post[2])
	select {
	case <-done2:
	case <-time.After(10 * time.Second):
		t.Fatal("lookup 2 never finished")
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("an older ACTIVE answer restored normal admission after the machine was retired")
	}
	if peer2.registered && !peer2.restricted {
		t.Fatal("the older connection is registered as a normal agent")
	}
	if !srv.reg.isCurrent(peer1) && !srv.reg.isCurrent(peer2) {
		t.Fatal("no restricted registration is left for the retired machine")
	}
	for _, p := range []*Peer{peer1, peer2} {
		if srv.reg.isCurrent(p) && !p.restricted {
			t.Fatal("a normal registration is current")
		}
	}
	_ = conn2
	if n := srv.authLocks.size(); n != 0 {
		t.Fatalf("%d per-device lock entries left behind", n)
	}
	_ = peer1
}

// ---- 7. acks reach the control plane in the order the agent sent them -------------------------------

type delayAckTransport struct{ inner http.RoundTripper }

// The first transition (to "accepted") is delayed on the wire, so unserialized forwarding would let the
// second overtake it.
func (d delayAckTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil && strings.Contains(r.URL.Path, "/ack") {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		if bytes.Contains(b, []byte(`"to":"accepted"`)) {
			time.Sleep(400 * time.Millisecond)
		}
	}
	return d.inner.RoundTrip(r)
}

func TestDirectiveAcksReachTheControlPlaneInReceiveOrder(t *testing.T) {
	cp, srv, _, _ := directiveEnv(t)
	peer, conn := registerGolden(t, srv, dirFeature)
	srv.guestEnd.client.Transport = delayAckTransport{inner: http.DefaultTransport}
	const id = "11111111-aaaa-4aaa-8aaa-111111111111"
	for _, step := range [][2]string{{"issued", "accepted"}, {"accepted", "executing"}, {"executing", "complete"}} {
		srv.dispatch(peer, ClientToServer{Payload: &DirectiveAck{DirectiveID: id, From: step[0], To: step[1], TsMs: 1, Sig: "00"}})
	}
	waitUntil(t, "three acks forwarded", func() bool { return len(cp.ackList()) == 3 })
	var got []string
	for _, a := range cp.ackList() {
		got = append(got, a.body["to"].(string))
	}
	if strings.Join(got, ",") != "accepted,executing,complete" {
		t.Fatalf("the control plane received the acks as %v, want the order the agent sent them", got)
	}
	waitUntil(t, "three results to the agent", func() bool {
		n := 0
		for _, m := range conn.messages() {
			if _, ok := m.Payload.(DirectiveAckResult); ok {
				n++
			}
		}
		return n == 3
	})
}

func TestDeviceLocksAreBoundedAndCleanedUp(t *testing.T) {
	var d deviceLocks
	rel1, ok := d.acquire("dev-a", time.Second)
	if !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := d.acquire("dev-a", 50*time.Millisecond); ok {
		t.Fatal("a second holder got the same device's lock")
	}
	rel2, ok := d.acquire("dev-b", time.Second)
	if !ok {
		t.Fatal("another device was blocked by dev-a")
	}
	rel1()
	rel1() // idempotent
	rel2()
	if n := d.size(); n != 0 {
		t.Fatalf("%d lock entries left after every holder and waiter left", n)
	}
}
