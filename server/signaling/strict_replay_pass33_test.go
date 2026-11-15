package main

// Pass 33: strict shared-ticket redemption/replay against a REAL control-plane ledger.
//
// All prior passes tested single-use enforcement with in-memory fakes (fakeRedeemer) or HTTP stubs
// (redeemStub). This file wires a real httpTicketRedeemer against a live cptestfixture subprocess
// and proves the whole chain end-to-end.
//
// Gate requirements:
//
//   - Valid authenticated ticket admits first; CP ledger records the use (200).
//   - Replay of the SAME ticket at a SECOND broker instance (empty local map) is refused because
//     the CP returns 409, NOT because the agent is busy — proven by the multi-session agent
//     having spare capacity and the rejection reason being "connect request not authorized".
//   - First connection is unaffected after the replay is refused.
//   - Fresh second ticket (different session_id) is admitted, proving the ledger is per-ticket
//     not per-device.
//   - Invalid tickets (bad signature, wrong tenant, wrong device, expired, nil) are refused BEFORE
//     reaching the CP. Redemption call count asserted zero in each case.
//   - STRICT mode (SIGNALING_STRICT_TICKET_REDEMPTION) refuses the broker when the CP is
//     unreachable rather than warning and proceeding.
//   - Concurrent duplicate race: two broker instances race to redeem the same ticket at the same
//     real CP. Exactly one wins (200); the other receives a definitive 409.
//   - No "WARNING: session-ticket ledger" log line appears in strict mode with a healthy CP.
//
// Fixture wiring:
//
//   cptestfixture is started with CP_DEVICE_IDENTITY_TOKEN=<p33Token> and
//   CP_FIXTURE_GRANT_SEED=<p33GrantSeedHex>. The test signs tickets locally with the same seed,
//   so the broker's grant pubkey matches what the fixture would issue, and the redemption endpoint
//   records every use in its InMemoryTicketRedemptionStore.
//
//   Tenant "16161616-0000-4000-8000-000000000016" is the fixture's fixtureTenantID (control-plane/cmd/cptestfixture/main.go).
//   The test agent is NOT enrolled in the fixture's machine store — redemption records the
//   (tenant_id, session_id) pair, which is what the ledger enforces, not enrollment state.
//
// Run:
//
//	go test ./server/signaling -run TestPass33_ -v -count=1
//
// Skip condition: if ../../control-plane/cptestfixture.exe does not exist, each test skips.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── constants ────────────────────────────────────────────────────────────────

const (
	// p33GrantSeedHex is the 32-byte Ed25519 seed passed to cptestfixture as CP_FIXTURE_GRANT_SEED.
	// The test signs tickets with the same key, so the broker's pubkey matches the fixture's issuer.
	p33GrantSeedHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

	// p33Token is the shared service token; it must be ≥ DeviceIdentityTokenMinLen (32) characters.
	p33Token = "p33-service-token-0123456789abcdef" // 34 chars

	// p33Tenant must match cptestfixture's fixtureTenantID ("16161616-0000-4000-8000-000000000016").
	p33Tenant = "16161616-0000-4000-8000-000000000016"

	// p33TechID is a UUID that lives inside the signed ticket claims (TechnicianID).
	// It matches fixtureTechAID in the fixture so the technician field is non-empty.
	p33TechID = "aaaaaaaa-0000-4000-8000-000000000002"

	// p33DeviceID is the test agent's device identifier. It is NOT enrolled in the fixture's
	// machine store; the redemption endpoint only cares about (tenant_id, session_id).
	p33DeviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

// ─── fixture startup ──────────────────────────────────────────────────────────

// p33FixtureReady is the subset of cptestfixture's fixtureReady JSON we need.
type p33FixtureReady struct {
	ListenAddr string `json:"listen_addr"`
}

// p33FixtureBin is the path to the cptestfixture binary relative to the test's working directory
// (server/signaling/).
func p33FixtureBin() string {
	name := filepath.Join("..", "..", "control-plane", "cptestfixture")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// p33StartFixture launches cptestfixture with the pass-33 seed and token, waits for FIXTURE_READY,
// and returns the HTTP base URL (e.g. "http://127.0.0.1:PORT"). The process is killed in t.Cleanup.
// Skips the test if the binary is absent.
func p33StartFixture(t *testing.T) string {
	t.Helper()
	bin := p33FixtureBin()
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("cptestfixture binary not found at %s — build with: go build -o cptestfixture.exe ./cmd/cptestfixture (in control-plane/)", bin)
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"CP_LISTEN=127.0.0.1:0",
		"CP_FIXTURE_GRANT_SEED="+p33GrantSeedHex,
		"CP_DEVICE_IDENTITY_TOKEN="+p33Token,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cptestfixture: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// Scan stdout until FIXTURE_READY appears (the fixture emits it before accepting connections).
	var ready p33FixtureReady
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		if payload, ok := strings.CutPrefix(line, "FIXTURE_READY "); ok {
			if err := json.Unmarshal([]byte(payload), &ready); err != nil {
				t.Fatalf("parse FIXTURE_READY JSON: %v (line %q)", err, line)
			}
			break
		}
	}
	if ready.ListenAddr == "" {
		t.Fatal("cptestfixture did not emit FIXTURE_READY within stdout — check the binary")
	}
	return "http://" + ready.ListenAddr
}

// ─── ticket issuer ────────────────────────────────────────────────────────────

// p33Issuer holds the Ed25519 key pair derived from p33GrantSeedHex. The private key signs
// test tickets; the public key is what the broker enforces against.
type p33Issuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newP33Issuer(t *testing.T) *p33Issuer {
	t.Helper()
	seed, err := hex.DecodeString(p33GrantSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("decode p33GrantSeedHex: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &p33Issuer{pub: priv.Public().(ed25519.PublicKey), priv: priv}
}

// mint signs claims with the pass-33 issuer key, matching what the fixture's GrantIssuer would
// emit for the same seed.
func (k *p33Issuer) mint(claims TicketClaims) *SignedSessionTicket {
	sig := ed25519.Sign(k.priv, ticketSigningBytes(claims))
	return &SignedSessionTicket{Claims: claims, Sig: hex.EncodeToString(sig)}
}

// p33Claims returns fresh TicketClaims for the test device with a unique session_id.
func p33Claims(t *testing.T) TicketClaims {
	t.Helper()
	sessionID, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID: %v", err)
	}
	now := time.Now().UnixMilli()
	return TicketClaims{
		V:            1,
		SessionID:    sessionID,
		TechnicianID: p33TechID,
		TenantID:     p33Tenant,
		DeviceID:     p33DeviceID,
		IssuedAtMs:   now,
		ExpiresAtMs:  now + 120_000, // 2 minutes — matches CP sessionTicketTTL
	}
}

// ─── counting redeemer ────────────────────────────────────────────────────────

// p33Redeemer wraps a real httpTicketRedeemer and counts every Redeem call so tests can assert
// "the CP was consulted exactly N times" — distinguishing "refusal came from the ledger" from
// "the check was never attempted".
type p33Redeemer struct {
	inner   TicketRedeemer
	mu      sync.Mutex
	n       int
	lastErr error
}

func newP33Redeemer(t *testing.T, baseURL string) *p33Redeemer {
	t.Helper()
	inner, err := newHTTPTicketRedeemer(baseURL, p33Token)
	if err != nil {
		t.Fatalf("newHTTPTicketRedeemer(%s): %v", baseURL, err)
	}
	return &p33Redeemer{inner: inner}
}

func (r *p33Redeemer) Redeem(ctx context.Context, claims TicketClaims) error {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	err := r.inner.Redeem(ctx, claims)
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
	return err
}

func (r *p33Redeemer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// lastError returns the error returned by the most recent Redeem call.
// Used by tests to assert that a CP 409 (ErrTicketAlreadyRedeemed) is the causal
// refusal reason, distinguishing a shared-ledger rejection from a local-map or
// availability failure.
func (r *p33Redeemer) lastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// ─── broker builder ───────────────────────────────────────────────────────────

// p33Broker builds a STRICT-mode broker with one multi-session-capable agent registered under
// p33Tenant and p33DeviceID. "Strict" means any ledger error that is not a definitive 409 refuses
// the broker rather than warning and proceeding.
func p33Broker(t *testing.T, key *p33Issuer, redeemer TicketRedeemer) (*Broker, *Peer, *fakeConn) {
	t.Helper()
	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:srv-p33", "relay:4444", key.pub).
		WithTicketRedeemer(redeemer).
		WithStrictTicketRedemption()
	agent := mkPeer(p33DeviceID, "ed25519:agent-p33", NatOpen, &fakeConn{})
	agent.Tenant = p33Tenant
	agent.MultiSessionCapable = boolPtr(true) // spare multi-session capacity throughout
	reg.Register(agent)
	ctrlConn := &fakeConn{}
	ctrl := &Peer{DeviceId: "ctrl-p33", Pubkey: "ed25519:ctrl-p33", conn: ctrlConn}
	return broker, ctrl, ctrlConn
}

// ─── tests ────────────────────────────────────────────────────────────────────
// captureLog is provided by log_escaping_test.go in this package.
// It returns *syncLogWriter; use .captured() to read the buffer.

// TestPass33_RealCP_ValidTicketAdmitsFirst proves that a ticket signed by the same issuer key
// as the fixture admits on first presentation. The CP ledger records the use (200). STRICT mode
// is active; the success path logs nothing (no WARNING, no ERROR).
func TestPass33_RealCP_ValidTicketAdmitsFirst(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)
	rd := newP33Redeemer(t, baseURL)
	broker, ctrl, ctrlConn := p33Broker(t, key, rd)
	logBuf := captureLog(t)

	claims := p33Claims(t)
	ticket := key.mint(claims)

	_, err := broker.ConnectRequest(ctrl, p33DeviceID, ticket)
	if err != nil {
		t.Fatalf("first use: ConnectRequest = %v, want nil", err)
	}
	if _, ok := findMsg[Brokered](ctrlConn.messages()); !ok {
		t.Fatal("first use: controller did not receive brokered")
	}
	if rd.count() != 1 {
		t.Fatalf("CP ledger calls = %d, want 1 — the check must run and record the first use", rd.count())
	}
	// The success path (CP returns 200) logs nothing. Any WARNING here would mean the broker
	// fell open without reaching the CP, which contradicts the call-count assertion above.
	if strings.Contains(logBuf.captured(), "WARNING: session-ticket ledger") {
		t.Fatalf("fail-open WARNING appeared on a healthy CP success path:\n%s", logBuf.captured())
	}
	if strings.Contains(logBuf.captured(), "ERROR: session-ticket ledger") {
		t.Fatalf("ledger ERROR appeared on a healthy CP success path:\n%s", logBuf.captured())
	}
}

// TestPass33_RealCP_ReplayRefusedNotAgentBusy proves that presenting the same ticket at a SECOND
// broker instance (empty local map, same CP) is refused because the CP returns 409 — not because
// the agent is busy. Key assertions:
//
//   - The second instance makes exactly 1 CP call (the refusal came from the ledger, not from a
//     check that never ran).
//   - The rejection reason is the generic "connect request not authorized", not a busy/offline hint.
//   - The first instance's session is untouched after the replay attempt.
func TestPass33_RealCP_ReplayRefusedNotAgentBusy(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)

	// Instance A: first legitimate use — admits and holds its session.
	rdA := newP33Redeemer(t, baseURL)
	brokerA, ctrlA, connA := p33Broker(t, key, rdA)
	claims := p33Claims(t)
	ticket := key.mint(claims)

	if _, err := brokerA.ConnectRequest(ctrlA, p33DeviceID, ticket); err != nil {
		t.Fatalf("instance A first use: %v", err)
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("instance A: controller did not receive brokered")
	}
	if rdA.count() != 1 {
		t.Fatalf("instance A: %d CP calls, want 1", rdA.count())
	}

	// Instance B: fresh broker (empty local map), same CP. Replays the same ticket.
	rdB := newP33Redeemer(t, baseURL)
	brokerB, _, _ := p33Broker(t, key, rdB)
	thiefConn := &fakeConn{}
	thief := &Peer{DeviceId: "thief-p33", Pubkey: "ed25519:thief-p33", conn: thiefConn}

	_, err := brokerB.ConnectRequest(thief, p33DeviceID, ticket)
	if err == nil {
		t.Fatal("instance B replay must be refused — CP returned 409")
	}
	if rdB.count() != 1 {
		t.Fatalf("instance B: %d CP calls, want 1 — refusal must come from the CP ledger, not a skipped check", rdB.count())
	}
	if !errors.Is(rdB.lastError(), ErrTicketAlreadyRedeemed) {
		t.Fatalf("instance B replay: rdB.lastError() = %v, want ErrTicketAlreadyRedeemed — "+
			"the CP must have returned 409 as the causal refusal", rdB.lastError())
	}
	rej, ok := findMsg[Rejected](thiefConn.messages())
	if !ok {
		t.Fatal("replay: thief peer did not receive a rejected message")
	}
	// The rejection reason must not reveal which check failed. Specifically it must NOT say
	// "busy" or "offline" — those would mask the replay as an availability issue.
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("replay rejection reason = %q; want the generic opaque reason", rej.Reason)
	}
	if strings.Contains(rej.Reason, "busy") {
		t.Fatalf("replay disguised as agent-busy: %q", rej.Reason)
	}
	if strings.Contains(rej.Reason, "offline") || strings.Contains(rej.Reason, "not registered") {
		t.Fatalf("replay disguised as device-offline: %q", rej.Reason)
	}
	// First connection unaffected: instance A still holds its session.
	brokerA.mu.Lock()
	sessCount := len(brokerA.sessions)
	brokerA.mu.Unlock()
	if sessCount != 1 {
		t.Fatalf("instance A session count = %d after B's replay; the first connection must be unaffected", sessCount)
	}
	// The thief must NOT have received brokered.
	if _, ok := findMsg[Brokered](thiefConn.messages()); ok {
		t.Fatal("thief received brokered despite the CP returning 409")
	}
}

// TestPass33_RealCP_FreshSecondTicketAdmits proves that a fresh ticket (distinct session_id) is
// admitted after a replay of the first ticket was refused. The CP ledger is per-ticket, not
// per-device; the multi-session agent has spare capacity throughout.
func TestPass33_RealCP_FreshSecondTicketAdmits(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)

	// Ticket A: admit on instance 1.
	rdA := newP33Redeemer(t, baseURL)
	brokerA, ctrlA, connA := p33Broker(t, key, rdA)
	claimsA := p33Claims(t)
	ticketA := key.mint(claimsA)
	if _, err := brokerA.ConnectRequest(ctrlA, p33DeviceID, ticketA); err != nil {
		t.Fatalf("ticket A first use: %v", err)
	}
	if _, ok := findMsg[Brokered](connA.messages()); !ok {
		t.Fatal("ticket A: no brokered on first use")
	}

	// Replay ticket A on instance 2: must be refused by the CP (409).
	rdB := newP33Redeemer(t, baseURL)
	brokerB, _, _ := p33Broker(t, key, rdB)
	thief := &Peer{DeviceId: "thief-p33", Pubkey: "ed25519:thief-p33", conn: &fakeConn{}}
	if _, err := brokerB.ConnectRequest(thief, p33DeviceID, ticketA); err == nil {
		t.Fatal("ticket A replay on instance 2 must be refused")
	}
	if rdB.count() != 1 {
		t.Fatalf("ticket A replay: %d CP calls on instance 2, want 1 — refusal must reach the CP ledger", rdB.count())
	}
	if !errors.Is(rdB.lastError(), ErrTicketAlreadyRedeemed) {
		t.Fatalf("ticket A replay: rdB.lastError() = %v, want ErrTicketAlreadyRedeemed — "+
			"CP must have returned 409 as the causal refusal", rdB.lastError())
	}

	// Ticket B: fresh claims (new session_id), admitted on instance 3.
	rdC := newP33Redeemer(t, baseURL)
	brokerC, ctrlC, connC := p33Broker(t, key, rdC)
	claimsB := p33Claims(t)
	ticketB := key.mint(claimsB)
	if _, err := brokerC.ConnectRequest(ctrlC, p33DeviceID, ticketB); err != nil {
		t.Fatalf("fresh ticket B: %v", err)
	}
	if _, ok := findMsg[Brokered](connC.messages()); !ok {
		t.Fatal("fresh ticket B: no brokered")
	}
	if rdC.count() != 1 {
		t.Fatalf("fresh ticket B: %d CP calls, want 1", rdC.count())
	}
}

// TestPass33_RealCP_InvalidTicketsNeverReachCP proves that six categories of invalid tickets
// are refused by the broker's LOCAL checks before any CP call is made. A redemption call would
// be wrong for two reasons: it would record a use for a session that is never brokered, and it
// would generate CP traffic from an unauthenticated prober.
func TestPass33_RealCP_InvalidTicketsNeverReachCP(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)

	cases := map[string]func(TicketClaims) *SignedSessionTicket{
		"nil ticket": func(_ TicketClaims) *SignedSessionTicket {
			return nil
		},
		"bad signature": func(c TicketClaims) *SignedSessionTicket {
			tk := key.mint(c)
			// Flip the first byte of the signature — still valid hex, wrong Ed25519 value.
			sigBytes, _ := hex.DecodeString(tk.Sig)
			sigBytes[0] ^= 0xFF
			tk.Sig = hex.EncodeToString(sigBytes)
			return tk
		},
		"wrong device": func(c TicketClaims) *SignedSessionTicket {
			// Ticket bound to a different device; re-signed so the signature is valid.
			c.DeviceID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			return key.mint(c)
		},
		"wrong tenant": func(c TicketClaims) *SignedSessionTicket {
			// Correct device, wrong tenant; the tenant cross-check fires after registry lookup.
			c.TenantID = "wrong-tenant-p33"
			return key.mint(c)
		},
		"expired": func(c TicketClaims) *SignedSessionTicket {
			c.ExpiresAtMs = c.IssuedAtMs - 1
			return key.mint(c)
		},
		"empty technician": func(c TicketClaims) *SignedSessionTicket {
			c.TechnicianID = ""
			return key.mint(c)
		},
	}

	for name, mkTicket := range cases {
		t.Run(name, func(t *testing.T) {
			rd := newP33Redeemer(t, baseURL)
			broker, ctrl, ctrlConn := p33Broker(t, key, rd)
			claims := p33Claims(t)
			ticket := mkTicket(claims)

			_, err := broker.ConnectRequest(ctrl, p33DeviceID, ticket)
			if err == nil {
				t.Fatalf("%s: ConnectRequest succeeded — invalid ticket must be refused", name)
			}
			if _, ok := findMsg[Brokered](ctrlConn.messages()); ok {
				t.Fatalf("%s: brokered was sent for an invalid ticket", name)
			}
			if rd.count() != 0 {
				t.Fatalf("%s: %d CP calls; the CP must not be reached before local checks pass", name, rd.count())
			}
			// The rejection the controller sees must not expose which check failed.
			rej, ok := findMsg[Rejected](ctrlConn.messages())
			if !ok {
				t.Fatalf("%s: controller did not receive rejected", name)
			}
			if rej.Reason != "connect request not authorized" {
				t.Fatalf("%s: rejection reason = %q; want the opaque generic reason", name, rej.Reason)
			}
		})
	}
}

// TestPass33_RealCP_StrictModeRefusesOnCPDown proves that STRICT mode refuses the broker when
// the CP is unreachable, and logs ERROR (not WARNING). The test uses a dead server — not the
// fixture — to keep it deterministic and self-contained.
func TestPass33_RealCP_StrictModeRefusesOnCPDown(t *testing.T) {
	// Fail if the fixture binary is absent: a missing binary is a build defect, not a skip condition.
	if _, err := os.Stat(p33FixtureBin()); err != nil {
		t.Fatalf("cptestfixture binary not found at %s — build with: go build -o cptestfixture.exe ./cmd/cptestfixture (in control-plane/)", p33FixtureBin())
	}
	key := newP33Issuer(t)

	// Use an unreachable endpoint (connection refused). This is the same approach as
	// TestHTTPTicketRedeemerUnreachableControlPlane; the distinction here is the BROKER's
	// behaviour under STRICT mode, not the redeemer's.
	badRedeemer, err := newHTTPTicketRedeemer("http://127.0.0.1:1", p33Token)
	if err != nil {
		t.Fatalf("newHTTPTicketRedeemer: %v", err)
	}

	reg := NewRegistry(time.Minute)
	broker := NewBroker(reg, "ed25519:srv-p33", "relay:4444", key.pub).
		WithTicketRedeemer(badRedeemer).
		WithStrictTicketRedemption()
	agent := mkPeer(p33DeviceID, "ed25519:agent-p33", NatOpen, &fakeConn{})
	agent.Tenant = p33Tenant
	agent.MultiSessionCapable = boolPtr(true)
	reg.Register(agent)
	ctrlConn := &fakeConn{}
	ctrl := &Peer{DeviceId: "ctrl-p33", Pubkey: "ed25519:ctrl-p33", conn: ctrlConn}

	claims := p33Claims(t)
	ticket := key.mint(claims)
	logBuf := captureLog(t)

	_, err = broker.ConnectRequest(ctrl, p33DeviceID, ticket)
	if err == nil {
		t.Fatal("strict mode + unreachable CP: ConnectRequest must be refused")
	}
	if _, ok := findMsg[Brokered](ctrlConn.messages()); ok {
		t.Fatal("strict mode: brokered must not be sent when the CP is unreachable")
	}
	rej, ok := findMsg[Rejected](ctrlConn.messages())
	if !ok {
		t.Fatal("strict mode: controller must receive rejected on CP unavailability")
	}
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("strict mode: rejection reason = %q", rej.Reason)
	}
	// Strict mode takes the ERROR branch, not the WARNING branch.
	if strings.Contains(logBuf.captured(), "WARNING: session-ticket ledger") {
		t.Fatalf("strict mode logged WARNING instead of ERROR:\n%s", logBuf.captured())
	}
	if !strings.Contains(logBuf.captured(), "ERROR: session-ticket ledger unavailable") {
		t.Fatalf("strict mode did not log the expected ERROR message:\n%s", logBuf.captured())
	}
}

// TestPass33_RealCP_ConcurrentDuplicateRace proves that two broker instances racing to redeem
// the same ticket at the same real CP produce exactly one success and one definitive refusal.
// The CP's InMemoryTicketRedemptionStore serialises concurrent inserts under its own mutex, so
// the race winner is non-deterministic but the outcome is always 1-win / 1-lose.
func TestPass33_RealCP_ConcurrentDuplicateRace(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)

	// Both instances share the same real CP, each with a fresh empty local map.
	rdA := newP33Redeemer(t, baseURL)
	rdB := newP33Redeemer(t, baseURL)

	regA := NewRegistry(time.Minute)
	agentA := mkPeer(p33DeviceID, "ed25519:agent-p33-a", NatOpen, &fakeConn{})
	agentA.Tenant = p33Tenant
	agentA.MultiSessionCapable = boolPtr(true)
	regA.Register(agentA)
	brokerA := NewBroker(regA, "ed25519:srv-p33-a", "relay:4444", key.pub).
		WithTicketRedeemer(rdA).
		WithStrictTicketRedemption()
	connA := &fakeConn{}
	ctrlA := &Peer{DeviceId: "ctrl-p33-a", Pubkey: "ed25519:ctrl-p33-a", conn: connA}

	regB := NewRegistry(time.Minute)
	agentB := mkPeer(p33DeviceID, "ed25519:agent-p33-b", NatOpen, &fakeConn{})
	agentB.Tenant = p33Tenant
	agentB.MultiSessionCapable = boolPtr(true)
	regB.Register(agentB)
	brokerB := NewBroker(regB, "ed25519:srv-p33-b", "relay:4444", key.pub).
		WithTicketRedeemer(rdB).
		WithStrictTicketRedemption()
	connB := &fakeConn{}
	ctrlB := &Peer{DeviceId: "ctrl-p33-b", Pubkey: "ed25519:ctrl-p33-b", conn: connB}

	// Same ticket — the value the race is over.
	claims := p33Claims(t)
	ticket := key.mint(claims)

	// raceResult carries both the outcome and which controller conn to inspect, so the loser
	// can be identified correctly regardless of goroutine scheduling order.
	type raceResult struct {
		err  error
		conn *fakeConn
	}
	results := make(chan raceResult, 2)

	// Close a channel to release both goroutines simultaneously, maximising contention.
	ready := make(chan struct{})
	go func() {
		<-ready
		_, err := brokerA.ConnectRequest(ctrlA, p33DeviceID, ticket)
		results <- raceResult{err, connA}
	}()
	go func() {
		<-ready
		_, err := brokerB.ConnectRequest(ctrlB, p33DeviceID, ticket)
		results <- raceResult{err, connB}
	}()
	close(ready)

	r1 := <-results
	r2 := <-results

	var winner, loser raceResult
	switch {
	case r1.err == nil && r2.err != nil:
		winner, loser = r1, r2
	case r2.err == nil && r1.err != nil:
		winner, loser = r2, r1
	case r1.err == nil && r2.err == nil:
		t.Fatalf("concurrent race: both goroutines succeeded — the CP did not enforce single-use")
	default:
		t.Fatalf("concurrent race: both goroutines failed; errs = %v, %v", r1.err, r2.err)
	}
	_ = winner

	// Both instances must have reached the CP: the winning call got 200, the losing one got 409.
	// A total of 2 proves neither was short-circuited by a non-CP path.
	totalCP := rdA.count() + rdB.count()
	if totalCP != 2 {
		t.Fatalf("total CP calls = %d, want 2 — both instances must attempt before the race resolves", totalCP)
	}
	// Exactly one redeemer must have received ErrTicketAlreadyRedeemed (the CP's 409).
	// The winner got nil (200); the loser got the definitive replay error.
	rdALast := rdA.lastError()
	rdBLast := rdB.lastError()
	nAlreadyRedeemed := 0
	if errors.Is(rdALast, ErrTicketAlreadyRedeemed) {
		nAlreadyRedeemed++
	}
	if errors.Is(rdBLast, ErrTicketAlreadyRedeemed) {
		nAlreadyRedeemed++
	}
	if nAlreadyRedeemed != 1 {
		t.Fatalf("concurrent race: exactly one redeemer must return ErrTicketAlreadyRedeemed "+
			"(rdA.lastError()=%v, rdB.lastError()=%v)", rdALast, rdBLast)
	}

	// The loser's controller must have received rejected, not brokered.
	if _, ok := findMsg[Brokered](loser.conn.messages()); ok {
		t.Fatal("the losing racer received brokered despite the CP returning 409")
	}
	rej, ok := findMsg[Rejected](loser.conn.messages())
	if !ok {
		t.Fatal("the losing racer did not receive rejected")
	}
	if rej.Reason != "connect request not authorized" {
		t.Fatalf("loser rejection reason = %q", rej.Reason)
	}
}

// TestPass33_RealCP_NoFailOpenWarning proves that in STRICT mode with a healthy CP, the log
// produces no "WARNING: session-ticket ledger" lines. This covers both paths: the success path
// (CP returns 200) and the replay path (CP returns 409 to a second instance), neither of which
// takes the fail-open branch.
func TestPass33_RealCP_NoFailOpenWarning(t *testing.T) {
	baseURL := p33StartFixture(t)
	key := newP33Issuer(t)
	logBuf := captureLog(t)

	// First use on instance 1: success path.
	rd1 := newP33Redeemer(t, baseURL)
	broker1, ctrl1, _ := p33Broker(t, key, rd1)
	claims := p33Claims(t)
	ticket := key.mint(claims)
	if _, err := broker1.ConnectRequest(ctrl1, p33DeviceID, ticket); err != nil {
		t.Fatalf("first use: %v", err)
	}

	// Replay on instance 2: 409 path. Neither path warns.
	rd2 := newP33Redeemer(t, baseURL)
	broker2, _, _ := p33Broker(t, key, rd2)
	thief := &Peer{DeviceId: "thief-p33", Pubkey: "ed25519:thief-p33", conn: &fakeConn{}}
	if _, err := broker2.ConnectRequest(thief, p33DeviceID, ticket); err == nil {
		t.Fatal("replay on instance 2 must be refused")
	}

	// Neither the 200 path nor the 409 path ever reaches the fail-open WARNING branch.
	if strings.Contains(logBuf.captured(), "WARNING: session-ticket ledger") {
		t.Fatalf("fail-open WARNING appeared in strict mode with a healthy CP:\n%s", logBuf.captured())
	}
}
