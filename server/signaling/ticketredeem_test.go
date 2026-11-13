package main

// The SHARED single-use ledger (ticketredeem.go) as the broker uses it.
//
// Every test here has to defeat the same confound: the LOCAL spentTickets map already refuses a
// second use, so a broker that never called the ledger at all would look identical to one that
// called it and obeyed the answer. Two habits keep the mechanism isolated —
//
//   - the replay is always presented to a SECOND, freshly constructed broker (a second replica, or
//     this one after a restart), whose local map is empty, so only the shared ledger can refuse it;
//   - the fake redeemer COUNTS its calls, so "it brokered" is always distinguishable from "the
//     check never ran".

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeRedeemer is a controllable TicketRedeemer that records every call. `ledger`, when shared
// between two fakes, models one control plane serving two signaling instances.
type fakeRedeemer struct {
	mu     sync.Mutex
	calls  []TicketClaims
	ledger map[string]bool // session id -> already redeemed
	err    error           // when non-nil, returned instead of consulting the ledger
}

func newFakeRedeemer() *fakeRedeemer {
	return &fakeRedeemer{ledger: make(map[string]bool)}
}

// sharing returns a SECOND redeemer over the SAME ledger: a different signaling instance talking to
// the same control plane.
func (f *fakeRedeemer) sharing() *fakeRedeemer {
	return &fakeRedeemer{ledger: f.ledger}
}

func (f *fakeRedeemer) Redeem(_ context.Context, claims TicketClaims) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, claims)
	if f.err != nil {
		return f.err
	}
	if f.ledger[claims.SessionID] {
		return ErrTicketAlreadyRedeemed
	}
	f.ledger[claims.SessionID] = true
	return nil
}

func (f *fakeRedeemer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// redeemingBroker is ticketBroker with a shared ledger attached, over its own registry — so two of
// them are genuinely two instances.
func redeemingBroker(t *testing.T, agentDevice string, redeemer TicketRedeemer) (*Broker, *Peer, *fakeConn) {
	t.Helper()
	broker, controller, ctrlConn := ticketBroker(t, agentDevice)
	broker = broker.WithTicketRedeemer(redeemer)
	return broker, controller, ctrlConn
}

// LEG 1 OF THE BLIP POLICY: a DEFINITIVE "already redeemed" refuses the broker.
//
// The replay is presented to a second instance whose local map is empty, so the refusal can only
// have come from the shared ledger. The negative control at the end is what makes that claim
// checkable: the same second instance WITHOUT a redeemer brokers the very same ticket — which is
// the defect this change closes, measured rather than asserted.
func TestBrokerRejectsTicketRedeemedAtAnotherInstance(t *testing.T) {
	claims := ticketGoldenClaims()
	cp := newFakeRedeemer()

	instanceA, controllerA, connA := redeemingBroker(t, claims.DeviceID, cp)
	if _, err := instanceA.ConnectRequest(controllerA, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("first use at instance A: %v", err)
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("the first, legitimate use should have brokered")
	}
	if cp.callCount() != 1 {
		t.Fatalf("instance A made %d ledger calls, want 1", cp.callCount())
	}

	// Instance B: a different signaling process over the same control plane. Empty local map.
	cpB := cp.sharing()
	instanceB, _, _ := redeemingBroker(t, claims.DeviceID, cpB)
	thiefConn := &fakeConn{}
	thief := &Peer{DeviceId: "thief", Pubkey: "ed25519:thief", conn: thiefConn}
	if _, err := instanceB.ConnectRequest(thief, claims.DeviceID, mintTicket(t, claims)); err == nil {
		t.Fatal("a ticket already redeemed at another instance must not broker")
	}
	if cpB.callCount() != 1 {
		t.Fatalf("instance B made %d ledger calls, want 1 — the refusal must come from the ledger, "+
			"not from a check that never ran", cpB.callCount())
	}
	rej, ok := findMsg[Rejected](thiefConn.messages())
	if !ok {
		t.Fatal("the replaying peer should have received rejected")
	}
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("rejection reason %q leaks the failing check", rej.Reason)
	}
	if _, ok := findMsg[Brokered](thiefConn.messages()); ok {
		t.Fatal("a ticket redeemed elsewhere must not broker")
	}

	// NEGATIVE CONTROL / the measured defect: with no shared ledger, that same second instance
	// happily brokers the replay. If this ever starts failing, the test above has stopped proving
	// what it claims — the local map would be doing the work.
	unledgered, _, _ := redeemingBroker(t, claims.DeviceID, nil)
	replayConn := &fakeConn{}
	replayer := &Peer{DeviceId: "thief-2", Pubkey: "ed25519:thief", conn: replayConn}
	if _, err := unledgered.ConnectRequest(replayer, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("without a shared ledger a second instance is expected to broker the replay "+
			"(that is the defect); got %v", err)
	}
}

// LEG 2 OF THE BLIP POLICY: a TRANSPORT failure does NOT refuse the broker.
//
// Refusing here would mean a control-plane restart, a rolling deploy or one slow query stops the
// whole fleet from opening any session — an outage far worse, and far likelier, than the replay the
// ledger defends against. The call-count assertion is what separates "brokered because the check
// ran and failed open" from "brokered because the check never happened".
func TestBrokerProceedsWhenTicketLedgerIsUnavailable(t *testing.T) {
	claims := ticketGoldenClaims()

	for name, failure := range map[string]error{
		"timeout":            context.DeadlineExceeded,
		"connection refused": errors.New("ticket redemption: dial tcp 127.0.0.1:8081: connect: connection refused"),
		"server error":       errors.New("ticket redemption: control plane returned 503"),
		"unauthorized":       errors.New("ticket redemption: control plane returned 401"),
		"route absent":       errors.New("ticket redemption: control plane returned 404"),
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeRedeemer()
			cp.err = failure
			broker, controller, ctrlConn := redeemingBroker(t, claims.DeviceID, cp)

			if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
				t.Fatalf("a control-plane blip must not stop brokering: %v", err)
			}
			if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
				t.Fatal("the requester should have been brokered despite the ledger being unavailable")
			}
			if cp.callCount() != 1 {
				t.Fatalf("ledger calls = %d, want 1 — otherwise this test cannot tell 'failed open' "+
					"from 'never asked'", cp.callCount())
			}

			// The LOCAL map is still enforcing during the blip: it is the first line of defence and
			// the only one that works while the control plane is unreachable.
			dupConn := &fakeConn{}
			dup := &Peer{DeviceId: "dup", Pubkey: "ed25519:dup", conn: dupConn}
			if _, err := broker.ConnectRequest(dup, claims.DeviceID, mintTicket(t, claims)); err == nil {
				t.Fatal("the local single-use map must still refuse a same-instance replay during a blip")
			}
		})
	}
}

// A ledger that answers normally does not disturb the ordinary path: one call per brokered session,
// carrying the ticket's own claims (so the control plane records the right row).
func TestBrokerRedeemsWithTheTicketsOwnClaims(t *testing.T) {
	claims := ticketGoldenClaims()
	cp := newFakeRedeemer()
	broker, controller, _ := redeemingBroker(t, claims.DeviceID, cp)

	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.calls) != 1 {
		t.Fatalf("ledger calls = %d, want exactly 1 per brokered session", len(cp.calls))
	}
	got := cp.calls[0]
	if got.TenantID != claims.TenantID || got.SessionID != claims.SessionID ||
		got.DeviceID != claims.DeviceID || got.ExpiresAtMs != claims.ExpiresAtMs {
		t.Fatalf("redeemed claims = %+v, want the ticket's own %+v", got, claims)
	}
}

// The ledger is consulted only AFTER every local check has passed, so a request that was going to
// be refused anyway never reaches the control plane. Two consequences worth pinning: an unauthorized
// prober cannot make signaling generate control-plane traffic, and a ticket is never recorded as
// spent for a session that did not happen.
func TestBrokerDoesNotRedeemWhenTheRequestIsRefusedEarlier(t *testing.T) {
	claims := ticketGoldenClaims()

	t.Run("bad ticket", func(t *testing.T) {
		cp := newFakeRedeemer()
		broker, controller, _ := redeemingBroker(t, claims.DeviceID, cp)
		bad := mintTicket(t, claims)
		bad.Sig = "zz"
		if _, err := broker.ConnectRequest(controller, claims.DeviceID, bad); err == nil {
			t.Fatal("expected the malformed ticket to be refused")
		}
		if cp.callCount() != 0 {
			t.Fatalf("ledger called %d times for a ticket that never verified", cp.callCount())
		}
	})

	t.Run("target offline", func(t *testing.T) {
		cp := newFakeRedeemer()
		reg := NewRegistry(time.Minute)
		broker := NewBroker(reg, "ed25519:server", "relay-1:4444", ticketGoldenPubkey(t)).WithTicketRedeemer(cp)
		broker.nowMs = func() int64 { return claims.IssuedAtMs }
		controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}

		if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err == nil {
			t.Fatal("expected the offline agent to be rejected")
		}
		if cp.callCount() != 0 {
			t.Fatalf("ledger called %d times for a session that was never brokered", cp.callCount())
		}
		// …and the ticket is genuinely unburned: the agent comes online and it still works, at this
		// instance AND at the shared ledger.
		reg.Register(mkPeer(claims.DeviceID, "ed25519:agent", NatOpen, &fakeConn{}))
		if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
			t.Fatalf("ticket was burned by a rejected attempt: %v", err)
		}
	})
}

// =====================================================================================
// The HTTP redeemer — the wire contract with control-plane/http.go handleRedeemSessionTicket.
// The two live in separate Go modules, so (as with the device-identity lookup) a stub control plane
// pins the request shape here and control-plane/ticketredemption_test.go pins the answer shape
// there. The literal field names below are the contract; drift breaks one side loudly.
// =====================================================================================

// redeemStub is a stand-in control plane recording what the redeemer actually sent.
type redeemStub struct {
	status   int
	body     string
	requests int
	lastAuth string
	lastPath string
	lastCT   string
	lastBody map[string]any
}

func (s *redeemStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests++
	s.lastAuth = r.Header.Get("Authorization")
	s.lastPath = r.URL.EscapedPath()
	s.lastCT = r.Header.Get("Content-Type")
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	s.lastBody = nil
	_ = json.Unmarshal(raw, &s.lastBody)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(s.status)
	_, _ = w.Write([]byte(s.body))
}

func testRedeemer(t *testing.T, stub *redeemStub) *httpTicketRedeemer {
	t.Helper()
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	r, err := newHTTPTicketRedeemer(srv.URL, testIdentityToken)
	if err != nil {
		t.Fatalf("newHTTPTicketRedeemer: %v", err)
	}
	return r
}

func TestHTTPTicketRedeemerRequestShape(t *testing.T) {
	stub := &redeemStub{status: http.StatusOK, body: `{"redeemed":true}`}
	r := testRedeemer(t, stub)
	claims := ticketGoldenClaims()

	if err := r.Redeem(context.Background(), claims); err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if stub.lastPath != "/internal/session-tickets/redeem" {
		t.Fatalf("path = %q, want /internal/session-tickets/redeem", stub.lastPath)
	}
	if stub.lastAuth != "Bearer "+testIdentityToken {
		t.Fatalf("Authorization = %q, want the bearer service token", stub.lastAuth)
	}
	if stub.lastCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", stub.lastCT)
	}
	// The identifying claims, under the names the control plane decodes.
	want := map[string]any{
		"tenant_id":     claims.TenantID,
		"session_id":    claims.SessionID,
		"device_id":     claims.DeviceID,
		"expires_at_ms": float64(claims.ExpiresAtMs),
	}
	for k, v := range want {
		if stub.lastBody[k] != v {
			t.Fatalf("body[%q] = %v, want %v (full body %v)", k, stub.lastBody[k], v, stub.lastBody)
		}
	}
	// The signature is NOT sent: the control plane does not re-verify, and a ticket signature in a
	// second place is a second place it can leak from.
	if _, ok := stub.lastBody["sig"]; ok {
		t.Fatalf("body carries the ticket signature: %v", stub.lastBody)
	}
}

// Status mapping — the single most important behaviour in this file. Exactly one status is a
// verdict; every other answer must be an ordinary error, which the broker converts into "proceed".
func TestHTTPTicketRedeemerStatusMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		body    string
		wantErr error // nil = success; ErrTicketAlreadyRedeemed = definitive; other = "cannot answer"
	}{
		"200 first use":     {http.StatusOK, `{"redeemed":true}`, nil},
		"409 replay":        {http.StatusConflict, `{"error":"session ticket already redeemed"}`, ErrTicketAlreadyRedeemed},
		"401 bad token":     {http.StatusUnauthorized, `{"error":"unauthorized"}`, errors.New("any")},
		"404 no such route": {http.StatusNotFound, ``, errors.New("any")},
		"429 throttled":     {http.StatusTooManyRequests, ``, errors.New("any")},
		"500 broken":        {http.StatusInternalServerError, `{"error":"could not redeem session ticket"}`, errors.New("any")},
		"200 but garbage":   {http.StatusOK, `not json at all`, nil}, // the STATUS is the answer
	} {
		t.Run(name, func(t *testing.T) {
			r := testRedeemer(t, &redeemStub{status: tc.status, body: tc.body})
			err := r.Redeem(context.Background(), ticketGoldenClaims())
			switch {
			case tc.wantErr == nil:
				if err != nil {
					t.Fatalf("Redeem = %v, want nil", err)
				}
			case errors.Is(tc.wantErr, ErrTicketAlreadyRedeemed):
				if !errors.Is(err, ErrTicketAlreadyRedeemed) {
					t.Fatalf("Redeem = %v, want ErrTicketAlreadyRedeemed — only a definitive replay may refuse a broker", err)
				}
			default:
				if err == nil {
					t.Fatalf("Redeem = nil for status %d; an unanswerable lookup must not read as success", tc.status)
				}
				if errors.Is(err, ErrTicketAlreadyRedeemed) {
					t.Fatalf("status %d reported as a definitive replay; only 409 may be", tc.status)
				}
			}
		})
	}
}

// A dead control plane surfaces as an ordinary error (never as a replay), and the whole call is
// bounded — the broker cannot be parked on the interactive path by an unresponsive endpoint.
func TestHTTPTicketRedeemerUnreachableControlPlane(t *testing.T) {
	srv := httptest.NewServer(&redeemStub{status: http.StatusOK, body: `{"redeemed":true}`})
	url := srv.URL
	srv.Close() // nothing is listening now

	r, err := newHTTPTicketRedeemer(url, testIdentityToken)
	if err != nil {
		t.Fatalf("newHTTPTicketRedeemer: %v", err)
	}
	err = r.Redeem(context.Background(), ticketGoldenClaims())
	if err == nil {
		t.Fatal("a dead control plane must surface as an error")
	}
	if errors.Is(err, ErrTicketAlreadyRedeemed) {
		t.Fatalf("a dead control plane reported as a replay: %v", err)
	}
	if r.client.Timeout != ticketRedeemTimeout {
		t.Fatalf("client timeout = %s, want %s — this call is on the interactive path", r.client.Timeout, ticketRedeemTimeout)
	}
}

// Configuration: the redeemer is built from the SAME pair as the device-identity resolver (no new
// secret), refuses a token too short to be one, and is absent — not broken — when unconfigured.
func TestTicketRedeemerFromEnv(t *testing.T) {
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "")
	if r, err := ticketRedeemerFromEnv(); r != nil || err != nil {
		t.Fatalf("unconfigured = (%v, %v), want (nil, nil)", r, err)
	}

	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "http://cp.example:8081")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", testIdentityToken)
	r, err := ticketRedeemerFromEnv()
	if err != nil || r == nil {
		t.Fatalf("configured = (%v, %v), want a redeemer", r, err)
	}

	// A too-short token is a startup error, not a silent downgrade — the same wiring-time refusal
	// newHTTPIdentityResolver makes about the same secret.
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", testIdentityToken[:deviceIdentityTokenMinLen-1])
	if _, err := ticketRedeemerFromEnv(); err == nil {
		t.Fatal("a token shorter than the minimum must be refused at wiring time")
	}
	// Same for a base URL that is not http(s).
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", testIdentityToken)
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "cp.example:8081")
	if _, err := ticketRedeemerFromEnv(); err == nil {
		t.Fatal("a base URL without an http(s) scheme must be refused at wiring time")
	}
}

// THE DEFENCE MUST ACTUALLY BE APPLIED. Everything above tests a broker somebody handed a
// redeemer to; this pins that the REAL constructor does the handing. A ledger that is built,
// tested, and never wired protects nothing, and nothing else in this package would notice.
func TestNewServerWiresTheTicketLedgerFromEnv(t *testing.T) {
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "http://cp.example:8081")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", testIdentityToken)
	srv, err := NewServer(time.Minute, "relay-1:4444", ticketGoldenPubkey(t), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.broker.redeemer == nil {
		t.Fatal("NewServer did not wire the shared session-ticket ledger onto the broker")
	}

	// Unconfigured is a degradation, not a startup failure: the local map still enforces single use
	// per process, so refusing to start would trade a bounded replay window for no service at all.
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "")
	srv, err = NewServer(time.Minute, "relay-1:4444", ticketGoldenPubkey(t), nil)
	if err != nil {
		t.Fatalf("NewServer without the endpoint configured must still start: %v", err)
	}
	if srv.broker.redeemer != nil {
		t.Fatal("an unconfigured endpoint must leave the broker with no redeemer, not a broken one")
	}

	// A misconfigured one IS a startup error — a token too short to be a secret is a mistake, not a
	// policy choice, and starting anyway would leave the ledger silently unreachable.
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "http://cp.example:8081")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", "too-short")
	if _, err := NewServer(time.Minute, "relay-1:4444", ticketGoldenPubkey(t), nil); err == nil {
		t.Fatal("NewServer accepted a device-identity token too short to be a secret")
	}
}

// Dev mode (no ticket verification at all): the ledger is never consulted, because there is no
// verified ticket to record. Without this, -insecure-no-ticket-verification would start making
// control-plane calls with empty claims.
func TestBrokerWithoutTicketVerificationNeverRedeems(t *testing.T) {
	cp := newFakeRedeemer()
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:server", "relay-1:4444", nil).WithTicketRedeemer(cp)
	reg.Register(mkPeer("agent-dev", "ed25519:agent", NatOpen, &fakeConn{}))
	controller := &Peer{DeviceId: "ctrl-dev", Pubkey: "ed25519:ctrl", conn: &fakeConn{}}

	if _, err := broker.ConnectRequest(controller, "agent-dev", nil); err != nil {
		t.Fatalf("dev-mode ConnectRequest without ticket: %v", err)
	}
	if cp.callCount() != 0 {
		t.Fatalf("ledger called %d times in dev mode, want 0", cp.callCount())
	}
}

// =====================================================================================
// STRICT MODE (SIGNALING_STRICT_TICKET_REDEMPTION) — F12 remediation
//
// WithStrictTicketRedemption flips the ledger-failure posture from fail-open to fail-closed:
// any ledger error that is not a definitive replay (ErrTicketAlreadyRedeemed) refuses the
// broker rather than warning and proceeding. These tests are paired: one proves the strict
// mode DOES refuse on ledger uncertainty; the symmetric negative control proves the default
// mode STILL proceeds on the same error (so the test above cannot pass simply because
// something else in the code refused).
// =====================================================================================

// STRICT MODE POSITIVE: a ledger error that is not a definitive replay refuses the broker.
//
// Three error shapes are tested: timeout, connection failure, and unexpected status — the three
// common faces of "the control plane did not answer". All three must refuse in strict mode;
// the call-count assertion rules out the check never running.
func TestBrokerStrictModeRefusesOnLedgerUncertainty(t *testing.T) {
	claims := ticketGoldenClaims()

	for name, failure := range map[string]error{
		"timeout":      context.DeadlineExceeded,
		"unreachable":  errors.New("ticket redemption: dial tcp 127.0.0.1:8081: connect: connection refused"),
		"server error": errors.New("ticket redemption: control plane returned 503"),
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeRedeemer()
			cp.err = failure
			broker, controller, ctrlConn := redeemingBroker(t, claims.DeviceID, cp)
			broker = broker.WithStrictTicketRedemption()

			_, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims))
			if err == nil {
				t.Fatal("strict mode: a ledger error must refuse the broker, not proceed")
			}
			if _, ok := findMsg[Brokered](ctrlConn.messages()); ok {
				t.Fatal("strict mode: brokered must not be sent when the ledger is uncertain")
			}
			rej, ok := findMsg[Rejected](ctrlConn.messages())
			if !ok {
				t.Fatal("strict mode: the requester must receive rejected on ledger uncertainty")
			}
			if rej.Reason != "connect request not authorized" {
				t.Fatalf("strict mode: rejection reason %q leaks the failing check", rej.Reason)
			}
			if cp.callCount() != 1 {
				t.Fatalf("ledger calls = %d, want 1 — otherwise this test cannot tell 'refused because "+
					"strict' from 'refused because the check never ran'", cp.callCount())
			}
		})
	}
}

// STRICT MODE NEGATIVE CONTROL: the same ledger errors in DEFAULT (fail-open) mode must still
// proceed. This is the counterfactual that makes the test above meaningful: if fail-open started
// refusing too, both tests would pass and neither would tell us anything.
func TestBrokerDefaultModeStillProceedsOnLedgerUncertainty(t *testing.T) {
	claims := ticketGoldenClaims()

	cp := newFakeRedeemer()
	cp.err = errors.New("ticket redemption: control plane returned 503")
	// No WithStrictTicketRedemption — the default fail-open posture.
	broker, controller, ctrlConn := redeemingBroker(t, claims.DeviceID, cp)

	if _, err := broker.ConnectRequest(controller, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("default mode: a ledger error must not stop brokering: %v", err)
	}
	if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
		t.Fatal("default mode: must broker despite ledger uncertainty")
	}
	if cp.callCount() != 1 {
		t.Fatalf("ledger calls = %d, want 1 — otherwise this test cannot tell 'brokered because "+
			"fail-open' from 'brokered because the check never ran'", cp.callCount())
	}
}

// STRICT MODE DEFINITIVE REPLAY: ErrTicketAlreadyRedeemed must refuse in BOTH modes — strict mode
// must not accidentally widen the definitive case, and the existing replay test above already
// covers the normal path; this confirms the strict-mode path also handles 409 correctly.
func TestBrokerStrictModeStillRefusesDefinitiveReplay(t *testing.T) {
	claims := ticketGoldenClaims()

	// First use on instance A (strict mode); record it in the shared ledger.
	cp := newFakeRedeemer()
	instanceA, controllerA, _ := redeemingBroker(t, claims.DeviceID, cp)
	instanceA = instanceA.WithStrictTicketRedemption()
	if _, err := instanceA.ConnectRequest(controllerA, claims.DeviceID, mintTicket(t, claims)); err != nil {
		t.Fatalf("strict mode: first legitimate use must succeed: %v", err)
	}

	// Second use on instance B (strict mode, same shared ledger). Ledger returns 409 → definitive.
	cpB := cp.sharing()
	instanceB, _, _ := redeemingBroker(t, claims.DeviceID, cpB)
	instanceB = instanceB.WithStrictTicketRedemption()
	thiefConn := &fakeConn{}
	thief := &Peer{DeviceId: "thief", Pubkey: "ed25519:thief", conn: thiefConn}
	if _, err := instanceB.ConnectRequest(thief, claims.DeviceID, mintTicket(t, claims)); err == nil {
		t.Fatal("strict mode: a definitively already-redeemed ticket must still be refused")
	}
	if _, ok := findMsg[Brokered](thiefConn.messages()); ok {
		t.Fatal("strict mode: a brokered message must not be sent for a replayed ticket")
	}
}

// NewServer wires strict mode from the environment, not from a constructor argument, so the
// environment toggle that operators set is the one that actually changes broker behaviour.
func TestNewServerWiresStrictModeFromEnv(t *testing.T) {
	t.Setenv("SIGNALING_DEVICE_IDENTITY_URL", "http://cp.example:8081")
	t.Setenv("SIGNALING_DEVICE_IDENTITY_TOKEN", testIdentityToken)

	t.Setenv("SIGNALING_STRICT_TICKET_REDEMPTION", "")
	srv, err := NewServer(time.Minute, "relay-1:4444", ticketGoldenPubkey(t), nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.broker.ticketStrict {
		t.Fatal("unset SIGNALING_STRICT_TICKET_REDEMPTION must leave the broker in fail-open mode")
	}

	for _, val := range []string{"1", "true", "yes", "on"} {
		t.Setenv("SIGNALING_STRICT_TICKET_REDEMPTION", val)
		srv, err = NewServer(time.Minute, "relay-1:4444", ticketGoldenPubkey(t), nil)
		if err != nil {
			t.Fatalf("NewServer with SIGNALING_STRICT_TICKET_REDEMPTION=%q: %v", val, err)
		}
		if !srv.broker.ticketStrict {
			t.Fatalf("SIGNALING_STRICT_TICKET_REDEMPTION=%q must set strict mode on the broker", val)
		}
	}
}
