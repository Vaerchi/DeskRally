package main

// Tests for the WebSocket admission bounds (websocket_limits.go).
//
// These exercise the ACTUAL handleWS over an httptest loopback with real Gorilla clients — a
// fake conn would sail past the bit under test, which is the interaction of Upgrader, the
// admission counters, and the pre-auth timer. Each server owns its own admission state
// (per-server, not a package global), so tests are safely parallel.
//
// Every socket has bounded I/O. Positive authenticated round trips after the original deadline
// distinguish timeout enforcement from indiscriminate disconnection. Cleanup closes test clients
// before joining hijacked handlers; httptest.Server alone does not own those connections.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --------------------------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------------------------

// testSignaling is a signaling Server behind an httptest loopback. It owns a WaitGroup that
// tracks handleWS goroutines so cleanup can join them — httptest.Server itself decrements its
// internal wg on Hijack, so it will not wait for the read loop by itself.
type testSignaling struct {
	t        *testing.T
	srv      *Server
	http     *httptest.Server
	handlers sync.WaitGroup
	wsURL    string
}

// newTestSignaling wires a Server with `limits` and mounts /ws on a loopback listener. Any
// resolver, ticket pubkey, and heartbeat TTL the test needs are passed through.
func newTestSignaling(t *testing.T, heartbeat time.Duration, ticketPub ed25519.PublicKey, resolver IdentityResolver, limits admissionLimits) *testSignaling {
	t.Helper()
	srv, err := NewServer(heartbeat, "relay-1:4444", ticketPub, resolver)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.SetAdmissionLimits(limits); err != nil {
		t.Fatalf("SetAdmissionLimits: %v", err)
	}
	ts := &testSignaling{t: t, srv: srv}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ts.handlers.Add(1)
		defer ts.handlers.Done()
		srv.handleWS(w, r)
	})
	ts.http = httptest.NewServer(mux)
	t.Cleanup(ts.close)
	u, err := url.Parse(ts.http.URL)
	if err != nil {
		t.Fatalf("parse test url: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/ws"
	ts.wsURL = u.String()
	return ts
}

// close halts the listener, drops any lingering client conns, and joins every handleWS. A
// leaked handler is a test defect, not a benign slow shutdown, so a missed join is reported.
func (ts *testSignaling) close() {
	ts.http.CloseClientConnections()
	ts.http.Close()
	done := make(chan struct{})
	go func() { ts.handlers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		ts.t.Errorf("handleWS goroutines did not exit within 3s (leaked from a hijacked upgrade)")
	}
}

// dialWS opens a WebSocket to /ws with a short handshake deadline. Returns the raw client and
// its cleanup closer bound to t.Cleanup so a fatal assertion cannot leak the socket.
func (ts *testSignaling) dialWS() (*websocket.Conn, *http.Response, error) {
	dialer := &websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	c, resp, err := dialer.Dial(ts.wsURL, nil)
	if err != nil && resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if c != nil {
		ts.t.Cleanup(func() { _ = c.Close() })
	}
	return c, resp, err
}

// waitCounters polls the admission snapshot until it matches or the deadline expires. Poll,
// not sleep-then-assert: sleep-then-assert flakes on a slow scheduler and hides a genuine
// counter leak because the release ran a millisecond after the check.
func (ts *testSignaling) waitCounters(total, pending int, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		_, gotTotal, gotPending := ts.srv.admission.snapshot()
		if gotTotal == total && gotPending == pending {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("admission counters = (total=%d, pending=%d), want (total=%d, pending=%d)",
				gotTotal, gotPending, total, pending)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --------------------------------------------------------------------------------------------
// configure() validation — cheap unit assertions, no server needed.
// --------------------------------------------------------------------------------------------

func TestAdmissionLimitsValidation(t *testing.T) {
	t.Parallel()
	a := newAdmissionState()
	cases := []struct {
		name string
		l    admissionLimits
	}{
		{"zero total", admissionLimits{maxTotal: 0, maxPending: 1, preAuthTimeout: time.Second}},
		{"negative total", admissionLimits{maxTotal: -1, maxPending: 1, preAuthTimeout: time.Second}},
		{"zero pending", admissionLimits{maxTotal: 10, maxPending: 0, preAuthTimeout: time.Second}},
		{"zero timeout", admissionLimits{maxTotal: 10, maxPending: 1, preAuthTimeout: 0}},
		{"pending exceeds total", admissionLimits{maxTotal: 4, maxPending: 5, preAuthTimeout: time.Second}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := a.configure(c.l); err == nil {
				t.Fatal("configure accepted invalid limits")
			}
		})
	}
	if err := a.configure(admissionLimits{maxTotal: 10, maxPending: 10, preAuthTimeout: time.Second}); err != nil {
		t.Fatalf("valid limits (pending == total) rejected: %v", err)
	}
}

// --------------------------------------------------------------------------------------------
// Pre-Upgrade rejection: pending and total caps
// --------------------------------------------------------------------------------------------

// At the pending cap the NEWCOMER is refused (503 + Retry-After); an existing in-progress
// handshake is never cancelled. Only the pre-auth timeout or authentication frees a slot.
func TestPendingCapRefusesNewcomerAndKeepsExistingHandshakes(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 8, maxPending: 2, preAuthTimeout: 10 * time.Second,
	})
	oldest, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.waitCounters(2, 2, time.Second); err != nil {
		t.Fatal(err)
	}
	_, resp, err := ts.dialWS()
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("newcomer at pending cap: resp=%v err=%v, want 503 with Retry-After", resp, err)
	}
	for _, c := range []*websocket.Conn{oldest, second} {
		writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: "pending"})
		readUntil(t, c, "rejected", time.Second) // still alive: not cancelled
	}
	if err := ts.waitCounters(2, 2, time.Second); err != nil {
		t.Fatal(err)
	}
}

// A promoted (authenticated) lease frees its pending slot, and nobody else is cancelled meanwhile.
func TestPromotionFreesPendingSlotWithoutCancellingOthers(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	if err := state.configure(admissionLimits{maxTotal: 8, maxPending: 2, preAuthTimeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	closes := &countingCloser{}
	promoted := state.acquireLease(nil, time.Now(), "")
	defer promoted.Release()
	promoted.attach(closes)
	other := state.acquireLease(nil, time.Now(), "")
	defer other.Release()
	if extra := state.acquireLease(nil, time.Now(), ""); extra != nil {
		extra.Release()
		t.Fatal("pool at its pending cap admitted a newcomer")
	}
	if !promoted.Promote() {
		t.Fatal("fresh lease did not promote")
	}
	next := state.acquireLease(nil, time.Now(), "")
	if next == nil {
		t.Fatal("promotion did not free a pending slot")
	}
	defer next.Release()
	if closes.count.Load() != 0 || other.stage != leasePending {
		t.Fatal("something was cancelled")
	}
	if _, total, pending := state.snapshot(); total != 3 || pending != 2 {
		t.Fatalf("counters: total=%d pending=%d", total, pending)
	}
}

// F09 replacement must not let a source over its own quota evict anyone else.
func TestSourceQuotaRefusesBeforePendingEviction(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 4, maxPending: 1, preAuthTimeout: 10 * time.Second,
	})
	ts.srv.SetSourceQuota(1)
	occupier, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	_, resp, err := ts.dialWS()
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over-quota dial: resp=%v err=%v, want 503", resp, err)
	}
	writeJSONMsg(t, occupier, "heartbeat", Heartbeat{Device: "pending"})
	readUntil(t, occupier, "rejected", time.Second)
	if err := ts.waitCounters(1, 1, time.Second); err != nil {
		t.Fatal(err)
	}
}

// F09 replacement cannot bypass total even when its oldest occupant is still pending.
func TestTotalCapRefusesWithoutEvictingPending(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	if err := state.configure(admissionLimits{maxTotal: 1, maxPending: 1, preAuthTimeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	lease := state.acquireLease(nil, time.Now(), "")
	defer lease.Release()
	if extra := state.acquireLease(nil, time.Now(), ""); extra != nil {
		extra.Release()
		t.Fatal("total cap admitted a replacement")
	}
	if lease.stage != leasePending {
		t.Fatal("total-cap refusal changed its pending occupant")
	}
}

// Promotion, release and a concurrent acquire never leak counters (run with -race).
func TestPromotionRacesAcquireAndRelease(t *testing.T) {
	t.Parallel()
	for i := 0; i < 500; i++ {
		state := newAdmissionState()
		if err := state.configure(admissionLimits{maxTotal: 4, maxPending: 1, preAuthTimeout: time.Hour}); err != nil {
			t.Fatal(err)
		}
		closes := &countingCloser{}
		lease := state.acquireLease(nil, time.Now(), "")
		lease.attach(closes)
		var promoted bool
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); promoted = lease.Promote() }()
		go func() {
			defer wg.Done()
			if l := state.acquireLease(nil, time.Now(), ""); l != nil {
				l.Release()
			}
		}()
		go func() { defer wg.Done(); lease.Release() }()
		wg.Wait()
		if promoted && closes.count.Load() != 0 {
			t.Fatal("a lease that won promotion was closed")
		}
		lease.Release()
		if _, total, pending := state.snapshot(); total != 0 || pending != 0 {
			t.Fatalf("race leaked counters: total=%d pending=%d", total, pending)
		}
	}
}

// The same at the total cap: a second dial with maxTotal=1 gets 503 even though pending is
// well below its own cap. Distinct assertion because tryAcquire checks both counters.
func TestTotalCapReturns503BeforeUpgrade(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 1, maxPending: 1, preAuthTimeout: 2 * time.Second,
	})

	occupier, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("first ws dial: %v", err)
	}
	defer occupier.Close()
	writeJSONMsg(t, occupier, "register_agent", RegisterAgent{Device: "total-cap-agent", Pubkey: "dev", Nat: NatOpen})
	readUntil(t, occupier, "registered", time.Second)
	if err := ts.waitCounters(1, 0, time.Second); err != nil {
		t.Fatalf("promoted occupier did not retain only the total slot: %v", err)
	}

	_, resp, err := ts.dialWS()
	if err == nil {
		t.Fatal("second dial succeeded despite total cap; expected 503")
	}
	if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second dial: resp=%v err=%v, want 503", resp, err)
	}
}

// --------------------------------------------------------------------------------------------
// Failed-Upgrade release: a garbage handshake must not eat a slot.
// --------------------------------------------------------------------------------------------

// A plain HTTP GET to /ws reserves a slot in tryAcquire, then Upgrade fails (no ws headers).
// Both counters must decrement so a follow-up legitimate dial succeeds. If the release path
// were missing, the very next dial would 503.
func TestFailedUpgradeReleasesBothSlots(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 1, maxPending: 1, preAuthTimeout: 2 * time.Second,
	})

	// GET without WebSocket headers → Upgrade rejects. Body drained so the server sees it as
	// completed and cleanup runs.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ts.http.URL + "/ws")
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("plain GET was rejected at the admission gate; it should reach Upgrade and fail there")
	}
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("failed upgrade leaked a slot: %v", err)
	}

	// Positive control: a slot released by failure is reusable by a valid dial.
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial after failed upgrade: %v", err)
	}
	_ = c.Close()
}

// --------------------------------------------------------------------------------------------
// Close from the client releases both slots.
// --------------------------------------------------------------------------------------------

func TestClosingAnonymousReleasesBothSlots(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: 2 * time.Second,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := ts.waitCounters(1, 1, time.Second); err != nil {
		t.Fatalf("counters after dial: %v", err)
	}
	_ = c.Close()
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("close did not release both slots: %v", err)
	}
}

// --------------------------------------------------------------------------------------------
// Dev-mode registration promotes: pending returns, total stays until disconnect.
// --------------------------------------------------------------------------------------------

// A dev-mode (nil resolver) register_agent completes without proof, and the ADMISSION contract
// says that path counts as authenticated too — the pending slot must return while the total
// slot stays until the socket actually closes. Dev-mode registration is NOT asserted here as a
// proof of enforced authentication (see the enforced case below); the assertion is purely
// about the admission bookkeeping.
func TestDevModeRegisterPromotesReleasingOnlyPending(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: 2 * time.Second,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	writeJSONMsg(t, c, "register_agent", RegisterAgent{
		Device: "dev-1", Pubkey: "ed25519:x", Tenant: "t", Nat: NatOpen,
	})
	// Wait for `registered` to arrive so we know dispatch has actually run promotion.
	readUntil(t, c, "registered", time.Second)
	if err := ts.waitCounters(1, 0, time.Second); err != nil {
		t.Fatalf("promotion did not release the pending slot: %v", err)
	}
	// Total holds until disconnect.
	if _, gotTotal, _ := ts.srv.admission.snapshot(); gotTotal != 1 {
		t.Fatalf("total = %d, want 1 (promotion must not release the total slot)", gotTotal)
	}
	_ = c.Close()
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("close did not release total: %v", err)
	}
}

// --------------------------------------------------------------------------------------------
// Absolute pre-auth lifetime — quiet AND chatty peers cannot extend it.
// --------------------------------------------------------------------------------------------

// A silent anonymous peer must be closed by the pre-auth timer, and both slots must return.
// The separate enforced-agent/controller cases prove authenticated sockets survive this gate.
func TestQuietAnonymousExpiresAtDeadline(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: 100 * time.Millisecond,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("silent anonymous socket outlived its pre-auth deadline")
	}
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("expired socket did not release slots: %v", err)
	}
}

// A chatty anonymous peer that sends a valid JSON message AND drives ping/pong every 20ms must
// still be closed by the absolute pre-auth deadline. This is the whole point of the timer over
// the silence-refreshing read deadline that already exists.
func TestChattyAnonymousCannotExtendAbsoluteLifetime(t *testing.T) {
	t.Parallel()
	timeout := 200 * time.Millisecond
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: timeout,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// A background heartbeat pump: valid JSON at high frequency + a pong every tick. Neither
	// should extend the pre-auth window. Uses a channel to stop cleanly, no unbounded sleep.
	stop := make(chan struct{})
	pumpDone := make(chan struct{})
	var stopOnce sync.Once
	var messages, pongs atomic.Int64
	stopPump := func() { stopOnce.Do(func() { close(stop) }) }
	t.Cleanup(func() {
		stopPump()
		_ = c.Close()
		select {
		case <-pumpDone:
		case <-time.After(time.Second):
			t.Error("traffic pump did not stop")
		}
	})
	go func() {
		defer close(pumpDone)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				// Heartbeat is JSON the server parses successfully but rejects for an unregistered
				// peer — a "successful read" that must NOT re-arm any bound. Flat envelope, per
				// the wire format used by messages.go's marshalTagged.
				_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				if err := c.WriteJSON(map[string]any{"type": "heartbeat", "device": "x"}); err != nil {
					return
				}
				messages.Add(1)
				if err := c.WriteControl(websocket.PongMessage, nil, time.Now().Add(500*time.Millisecond)); err != nil {
					return
				}
				pongs.Add(1)
			}
		}
	}()
	// Wait past the deadline for the timer to fire.
	closed := waitForClose(c, timeout+time.Second)
	stopPump()
	<-pumpDone
	if !closed {
		t.Fatal("chatty anonymous socket outlived its pre-auth deadline — traffic must not extend it")
	}
	if messages.Load() < 2 || pongs.Load() < 2 {
		t.Fatal("peer closed before chatty JSON/pong traffic exercised the deadline")
	}
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("expired chatty socket did not release slots: %v", err)
	}
}

// A merely-issued challenge must not flip the peer to authenticated — the pre-auth timer must
// still fire. Enforced mode with a golden resolver; the client sends register_agent, receives
// a challenge, then does nothing. If the challenge issuance were treated as promotion, the
// timer would be stopped and this assertion would fail.
func TestIssuedChallengeDoesNotPromote(t *testing.T) {
	t.Parallel()
	timeout := 150 * time.Millisecond
	ts := newTestSignaling(t, time.Minute, nil, goldenResolver(), admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: timeout,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	writeJSONMsg(t, c, "register_agent", RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	})
	readUntil(t, c, "agent_auth_challenge", time.Second)
	// Pending must still hold — the challenge is NOT a promotion.
	if _, _, pending := ts.srv.admission.snapshot(); pending != 1 {
		t.Fatalf("pending = %d after challenge only, want 1", pending)
	}
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("issuing a challenge extended the pre-auth lifetime")
	}
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("expired socket did not release slots: %v", err)
	}
}

// A rejected ticket must not promote. Enforced ticket mode + an invalid ticket. The broker
// returns an error, dispatch does NOT call markAuthenticated, and the pre-auth timer still
// fires.
func TestRejectedTicketDoesNotPromote(t *testing.T) {
	t.Parallel()
	timeout := 750 * time.Millisecond
	ts := newTestSignaling(t, time.Minute, ticketGoldenPubkey(t), nil, admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: timeout,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The target exists so this request reaches signature validation, not an unknown-target exit.
	agent := mkPeer("ticket-target", "dev", NatOpen, &fakeConn{})
	ts.srv.reg.Register(agent)
	claims := ticketGoldenClaims()
	claims.DeviceID = "ticket-target"
	claims.IssuedAtMs = time.Now().UnixMilli()
	claims.ExpiresAtMs = claims.IssuedAtMs + 60_000
	bad := mintTicket(t, claims)
	bad.Sig = strings.Repeat("00", 64)
	writeJSONMsg(t, c, "connect_request", ConnectRequest{
		Target: "ticket-target", Ticket: bad,
	})
	readUntil(t, c, "rejected", time.Second)
	if _, _, pending := ts.srv.admission.snapshot(); pending != 1 {
		t.Fatalf("pending = %d after rejected ticket, want 1", pending)
	}
	if !waitForClose(c, 2*time.Second) {
		t.Fatal("a rejected ticket extended the pre-auth lifetime")
	}
}

// --------------------------------------------------------------------------------------------
// Enforced Ed25519 registration survives past the pre-auth deadline.
// --------------------------------------------------------------------------------------------

// The positive-control counterpart to the timer tests: an agent that actually proves
// possession must be allowed to continue past the original pre-auth window while it keeps
// heartbeating and answering pings. Uses the SAME wire path (dial /ws, send register_agent),
// so a false positive on "did the deadline fire" cannot be excused as an unrelated close.
func TestEnforcedAgentSurvivesPastPreAuthDeadline(t *testing.T) {
	t.Parallel()
	timeout := 750 * time.Millisecond
	ts := newTestSignaling(t, time.Minute, nil, goldenResolver(), admissionLimits{
		maxTotal: 2, maxPending: 2, preAuthTimeout: timeout,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	writeJSONMsg(t, c, "register_agent", RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	})
	ch := readChallenge(t, c, time.Second)
	nonce, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		t.Fatalf("decode challenge nonce: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(mustHex(t, agentAuthGoldenSeedHex))
	sig := ed25519.Sign(priv, agentAuthSigningBytes(agentAuthGoldenDevice, agentAuthGoldenTenant, nonce))
	writeJSONMsg(t, c, "agent_auth_response", AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    hex.EncodeToString(sig),
	})
	readUntil(t, c, "registered", time.Second)
	if err := ts.waitCounters(1, 0, time.Second); err != nil {
		t.Fatalf("registered agent did not release pending: %v", err)
	}

	// Cross the deadline, then require a new application round trip; a read timeout is not liveness.
	time.Sleep(timeout + 50*time.Millisecond)
	writeJSONMsg(t, c, "register_agent", RegisterAgent{Device: agentAuthGoldenDevice})
	readUntil(t, c, "rejected", time.Second) // already registered, but the socket remains live
	_ = c.Close()
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("close did not release total: %v", err)
	}
}

// --------------------------------------------------------------------------------------------
// Fresh slots recover after timeouts and after normal disconnect.
// --------------------------------------------------------------------------------------------

func TestFreshSlotsRecoverAfterTimeoutAndDisconnect(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 1, maxPending: 1, preAuthTimeout: 100 * time.Millisecond,
	})
	// (a) fill via a socket that expires
	c1, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	if err := ts.waitCounters(1, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if !waitForClose(c1, 2*time.Second) {
		t.Fatal("first anonymous connection did not expire")
	}
	if err := ts.waitCounters(0, 0, 2*time.Second); err != nil {
		t.Fatalf("expiry recovery: %v", err)
	}
	// (b) new dial reuses the recovered slot
	c2, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	_ = c2.Close()
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatalf("disconnect recovery: %v", err)
	}
	// (c) and another after normal disconnect
	c3, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	_ = c3.Close()
}

// --------------------------------------------------------------------------------------------
// Focused deterministic tests for the lease itself: race, idempotency, deadline comparison.
// --------------------------------------------------------------------------------------------

// A concurrent Promote and Release must together decrement each counter exactly once. Runs
// under -race in CI. The connection stub is a no-op closer.
func TestLeasePromoteAndReleaseAreIdempotentUnderRace(t *testing.T) {
	t.Parallel()
	for i := 0; i < 500; i++ {
		state := newAdmissionState()
		_ = state.configure(admissionLimits{maxTotal: 1, maxPending: 1, preAuthTimeout: time.Second})
		if !state.tryAcquire() {
			t.Fatal("tryAcquire failed on a fresh state")
		}
		lease := state.startLease(nopCloser{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); lease.Promote() }()
		go func() { defer wg.Done(); lease.Promote() }()
		go func() { defer wg.Done(); lease.Release() }()
		go func() { defer wg.Done(); lease.expire() }()
		wg.Wait()
		// Also call Release a second time to prove idempotency of the terminal transition.
		lease.Release()
		if _, total, pending := state.snapshot(); total != 0 || pending != 0 {
			t.Fatalf("iter %d: leftover counters total=%d pending=%d", i, total, pending)
		}
	}
}

// A Promote that arrives AFTER the absolute deadline must NOT flip the state, so a delayed
// callback cannot admit an expired peer. Stop a distant timer, then install a past deadline:
// timer state cannot make this pass when the explicit deadline comparison is missing.
func TestLeasePromoteAfterDeadlineRefused(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	_ = state.configure(admissionLimits{maxTotal: 1, maxPending: 1, preAuthTimeout: time.Hour})
	if !state.tryAcquire() {
		t.Fatal("tryAcquire failed on a fresh state")
	}
	closes := &countingCloser{}
	lease := state.startLease(closes)
	lease.mu.Lock()
	lease.timer.Stop()
	lease.deadline = time.Now().Add(-time.Second)
	lease.mu.Unlock()
	if lease.Promote() {
		t.Fatal("Promote succeeded after the absolute deadline had passed")
	}
	if closes.count.Load() != 1 {
		t.Fatal("expired promotion did not close its own connection")
	}
	if _, total, pending := state.snapshot(); total != 1 || pending != 1 {
		t.Fatal("expiry released quota before handler cleanup")
	}
	// Release is still the sole owner of the counter accounting; both must be zero.
	lease.Release()
	if _, total, pending := state.snapshot(); total != 0 || pending != 0 {
		t.Fatalf("late-promote release leaked counters: total=%d pending=%d", total, pending)
	}
}

// A timer expire that fires AFTER Release is a no-op — it must not double-close or panic.
func TestLeaseExpireAfterReleaseIsNoop(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	_ = state.configure(admissionLimits{maxTotal: 1, maxPending: 1, preAuthTimeout: time.Second})
	if !state.tryAcquire() {
		t.Fatal("tryAcquire failed")
	}
	closes := &countingCloser{}
	lease := state.startLease(closes)
	lease.Release()
	lease.expire()
	if closes.count.Load() != 0 {
		t.Fatalf("expire after Release closed the conn %d times, want 0", closes.count.Load())
	}
}

func TestSignedControllerSurvivesPreAuthDeadline(t *testing.T) {
	t.Parallel()
	timeout := 750 * time.Millisecond
	ts := newTestSignaling(t, time.Minute, ticketGoldenPubkey(t), goldenResolver(), admissionLimits{
		maxTotal: 2, maxPending: 1, preAuthTimeout: timeout,
	})
	agent, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	writeJSONMsg(t, agent, "register_agent", RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	})
	challenge := readChallenge(t, agent, time.Second)
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(mustHex(t, agentAuthGoldenSeedHex))
	sig := ed25519.Sign(priv, agentAuthSigningBytes(agentAuthGoldenDevice, agentAuthGoldenTenant, nonce))
	writeJSONMsg(t, agent, "agent_auth_response", AgentAuthResponse{
		Device: agentAuthGoldenDevice, Nonce: challenge.Nonce, Sig: hex.EncodeToString(sig),
	})
	readUntil(t, agent, "registered", time.Second)
	if err := ts.waitCounters(1, 0, time.Second); err != nil {
		t.Fatal(err)
	}

	controller, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	claims := ticketGoldenClaims()
	claims.DeviceID, claims.TenantID = agentAuthGoldenDevice, agentAuthGoldenTenant
	claims.IssuedAtMs = time.Now().UnixMilli()
	claims.ExpiresAtMs = claims.IssuedAtMs + 60_000
	writeJSONMsg(t, controller, "connect_request", ConnectRequest{Target: claims.DeviceID, Ticket: mintTicket(t, claims)})
	readUntil(t, controller, "brokered", time.Second)
	readUntil(t, agent, "brokered", time.Second)
	if err := ts.waitCounters(2, 0, time.Second); err != nil {
		t.Fatal(err)
	}
	// Total is full even though both peers have returned their pending-auth slots.
	_, response, err := ts.dialWS()
	if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("authenticated connections did not retain the total quota")
	}
	time.Sleep(timeout + 50*time.Millisecond)
	// Controllers are not registered agents: heartbeat gets a rejection, proving a fresh response.
	writeJSONMsg(t, controller, "heartbeat", Heartbeat{Device: "controller"})
	readUntil(t, controller, "rejected", time.Second)
	writeJSONMsg(t, agent, "register_agent", RegisterAgent{Device: agentAuthGoldenDevice})
	readUntil(t, agent, "rejected", time.Second)
	_ = controller.Close()
	_ = agent.Close()
	if err := ts.waitCounters(0, 0, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestPreAuthDeadlineIncludesUpgradeTime(t *testing.T) {
	state := newAdmissionState()
	if !state.tryAcquire() {
		t.Fatal("empty admission state refused")
	}
	lease := state.startLeaseAt(nopCloser{}, time.Now().Add(-time.Hour))
	defer lease.Release()
	if lease.Promote() {
		t.Fatal("upgrade time was excluded from the absolute pre-auth deadline")
	}
	if _, total, pending := state.snapshot(); total != 1 || pending != 1 {
		t.Fatal("expired connection released quota before cleanup")
	}
}

func TestPromotedLeaseIgnoresStaleExpiry(t *testing.T) {
	state := newAdmissionState()
	if !state.tryAcquire() {
		t.Fatal("empty admission state refused")
	}
	closes := &countingCloser{}
	lease := state.startLease(closes)
	defer lease.Release()
	if !lease.Promote() {
		t.Fatal("fresh lease did not promote")
	}
	lease.expire()
	if closes.count.Load() != 0 {
		t.Fatal("stale timer closed a promoted connection")
	}
	if _, total, pending := state.snapshot(); total != 1 || pending != 0 {
		t.Fatal("promotion did not retain total while releasing pending")
	}
}

func TestAdmissionConfigurationRejectsActiveState(t *testing.T) {
	state := newAdmissionState()
	if !state.tryAcquire() {
		t.Fatal("empty admission state refused")
	}
	lease := state.startLease(nopCloser{})
	defer lease.Release()
	if err := state.configure(admissionLimits{maxTotal: 2, maxPending: 1, preAuthTimeout: time.Second}); err == nil {
		t.Fatal("configuration changed while a connection was active")
	}
}

func TestExpiredLeaseHoldsQuotaUntilHandlerRelease(t *testing.T) {
	state := newAdmissionState()
	if !state.tryAcquire() {
		t.Fatal("empty admission state refused")
	}
	lease := state.startLease(nopCloser{})
	defer lease.Release()
	lease.expire()
	if _, total, pending := state.snapshot(); total != 1 || pending != 1 {
		t.Fatal("expiry returned admission while the handler could still be doing work")
	}
	lease.Release()
	if _, total, pending := state.snapshot(); total != 0 || pending != 0 {
		t.Fatal("handler release did not return both reservations")
	}
}

// --------------------------------------------------------------------------------------------
// Wire helpers
// --------------------------------------------------------------------------------------------

// writeJSONMsg encodes a message in the flat wire form the server expects: the payload's own
// fields at the top level, plus a "type" discriminator (marshalTagged in messages.go).
func writeJSONMsg(t *testing.T, c *websocket.Conn, tag string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("flatten payload: %v", err)
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	tagRaw, _ := json.Marshal(tag)
	fields["type"] = tagRaw
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal flat envelope: %v", err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if err := c.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("write %s: %v", tag, err)
	}
}

// readUntil reads text frames from c until one arrives whose "type" tag equals `want`, or the
// deadline expires. Returns the whole frame (flat envelope) so callers can decode fields of
// their choice.
func readUntil(t *testing.T, c *websocket.Conn, want string, within time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if err := c.SetReadDeadline(deadline); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			continue
		}
		if probe.Type == want {
			return data
		}
	}
	t.Fatalf("did not receive a %q message within %v", want, within)
	return nil
}

// readChallenge is the common shape: read until an agent_auth_challenge arrives. The frame is
// a flat object, so unmarshalling into AgentAuthChallenge picks up its fields directly.
func readChallenge(t *testing.T, c *websocket.Conn, within time.Duration) AgentAuthChallenge {
	t.Helper()
	raw := readUntil(t, c, "agent_auth_challenge", within)
	var ch AgentAuthChallenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return ch
}

// waitForClose reports whether c goes to an unexpected close within the window. A returning
// ReadMessage error that is not just a timeout counts as closed. Distinguishes deadline-close
// from a parse error by returning true only on a socket-level failure.
func waitForClose(c *websocket.Conn, within time.Duration) bool {
	deadline := time.Now().Add(within)
	if err := c.SetReadDeadline(deadline); err != nil {
		return false
	}
	for time.Now().Before(deadline) {
		_, _, err := c.ReadMessage()
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return false // Gorilla read errors are terminal; never retry a timed-out connection.
		}
		return true
	}
	return false
}

// TestDispatchMalformedMessageRejected dials a real handleWS WebSocket, writes a raw frame whose
// "type" tag is unknown, and asserts that the server replies with a "rejected" message whose
// Reason starts with "malformed message:".
//
// Mutation guard: removing the json.Unmarshal error branch at main.go:199-201 causes dispatch to
// receive a zero-value ClientToServer, which hits the default case and emits "unsupported message
// type" — a different Reason — breaking the strings.Contains assertion below.
func TestDispatchMalformedMessageRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, 30*time.Second, nil, nil, admissionLimits{
		maxTotal:       10,
		maxPending:     10,
		preAuthTimeout: 5 * time.Second,
	})

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if err := c.WriteMessage(websocket.TextMessage, []byte(`{"type":"unknown_type_xyz"}`)); err != nil {
		t.Fatalf("write unknown frame: %v", err)
	}

	raw := readUntil(t, c, "rejected", 2*time.Second)
	var rej Rejected
	if err := json.Unmarshal(raw, &rej); err != nil {
		t.Fatalf("decode rejected: %v", err)
	}
	if !strings.Contains(rej.Reason, "malformed message:") {
		t.Fatalf("Rejected.Reason = %q, want prefix \"malformed message:\"", rej.Reason)
	}
}

// nopCloser is an io.Closer that does nothing, used by lease unit tests that never open a
// socket.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// countingCloser records how many times Close was invoked, to prove expire-after-Release is a
// no-op.
type countingCloser struct{ count atomic.Int64 }

func (c *countingCloser) Close() error { c.count.Add(1); return nil }
