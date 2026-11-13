package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTOR (M3) — the proof this builder and the Rust builder in
// crates/protocol/src/agent_auth.rs produce the SAME canonical bytes. The identical fixture (and
// expected hex) lives there; if either language's encoder drifts, its golden test fails.
// DO NOT change a value here without changing it identically there.
// =====================================================================================

const (
	agentAuthGoldenSeedHex   = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	agentAuthGoldenPubkeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"

	agentAuthGoldenDevice   = "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7"
	agentAuthGoldenTenant   = "11111111-2222-3333-4444-555555555555"
	agentAuthGoldenNonceHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"

	agentAuthGoldenPreimageHex = "524d544147454e544155544876310000010000002439663163326333612d346235642d346536662d383039312d6132623363346435653666370000002431313131313131312d323232322d333333332d343434342d35353535353535353535353500000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	agentAuthGoldenSigHex      = "b8ba719cba0e4301aba3d1d83b811eead5806461d7cd3633e3f27ae4cd15ecbb5480493e0eee099eb64234214f1fd874b5dafa95fc6d31ad2267788d2352f601"
)

// agentAuthWrongSeedHex is any key that is NOT the pinned one — the "I know the device id but not
// its private key" attacker.
const agentAuthWrongSeedHex = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestAgentAuthGoldenVectorMatchesRust(t *testing.T) {
	nonce := mustHex(t, agentAuthGoldenNonceHex)
	preimage := agentAuthSigningBytes(agentAuthGoldenDevice, agentAuthGoldenTenant, nonce)
	if len(preimage) != 61+len(agentAuthGoldenDevice)+len(agentAuthGoldenTenant) {
		t.Fatalf("preimage length %d, want %d", len(preimage), 61+len(agentAuthGoldenDevice)+len(agentAuthGoldenTenant))
	}
	if got := hex.EncodeToString(preimage); got != agentAuthGoldenPreimageHex {
		t.Fatalf("canonical preimage drift vs crates/protocol/src/agent_auth.rs:\n got  %s\n want %s",
			got, agentAuthGoldenPreimageHex)
	}

	priv := ed25519.NewKeyFromSeed(mustHex(t, agentAuthGoldenSeedHex))
	if got := hex.EncodeToString(ed25519.Sign(priv, preimage)); got != agentAuthGoldenSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", got, agentAuthGoldenSigHex)
	}
	pub := ed25519.PublicKey(mustHex(t, agentAuthGoldenPubkeyHex))
	if !ed25519.Verify(pub, preimage, mustHex(t, agentAuthGoldenSigHex)) {
		t.Fatal("golden signature does not verify against the golden public key")
	}
}

// The domain tag must be unmistakable for the ticket/grant tags, or a preimage under one could be
// replayed as the other.
func TestAgentAuthDomainTagIsDistinct(t *testing.T) {
	if got := hex.EncodeToString(agentAuthDomainTag); got != "524d544147454e544155544876310000" {
		t.Fatalf("domain tag = %s, want 524d544147454e544155544876310000", got)
	}
	if len(agentAuthDomainTag) != 16 {
		t.Fatalf("domain tag is %d bytes, want 16", len(agentAuthDomainTag))
	}
	if strings.HasPrefix(string(agentAuthDomainTag), string(ticketDomainTag)) {
		t.Fatal("agent-auth tag must not be a prefix of the ticket tag")
	}
}

// ---------------------------------------------------------------------------
// Handshake harness.
// ---------------------------------------------------------------------------

// fakeResolver is a stand-in for the control plane's device-identity endpoint.
type fakeResolver struct {
	identities map[string]*DeviceIdentity
	err        error // when non-nil, every lookup is a transport failure (control plane down)
	calls      int
	mu         sync.Mutex // the revalidation sweep resolves concurrently
}

func (f *fakeResolver) Resolve(_ context.Context, deviceID string) (*DeviceIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	id, ok := f.identities[deviceID]
	if !ok {
		return nil, ErrDeviceUnknown
	}
	return id, nil
}

// goldenResolver pins the golden device to the golden key, as a real enrollment would.
func goldenResolver() *fakeResolver {
	return &fakeResolver{identities: map[string]*DeviceIdentity{
		agentAuthGoldenDevice: {
			DeviceID: agentAuthGoldenDevice,
			TenantID: agentAuthGoldenTenant,
			Pubkey:   agentAuthGoldenPubkeyHex,
		},
	}}
}

// authServer builds an enforcing signaling server over the given resolver.
func authServer(t *testing.T, resolver IdentityResolver) *Server {
	t.Helper()
	srv, err := NewServer(time.Minute, "relay-1:4444", nil, resolver)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// challengeNonce returns the raw nonce from the most recent agent_auth_challenge sent to conn.
func challengeNonce(t *testing.T, conn *fakeConn) []byte {
	t.Helper()
	var last *AgentAuthChallenge
	for _, m := range conn.messages() {
		if c, ok := m.Payload.(AgentAuthChallenge); ok {
			cc := c
			last = &cc
		}
	}
	if last == nil {
		t.Fatal("no agent_auth_challenge was sent")
	}
	if len(last.Nonce) != 2*agentAuthNonceLen {
		t.Fatalf("challenge nonce %q is %d chars, want %d", last.Nonce, len(last.Nonce), 2*agentAuthNonceLen)
	}
	return mustHex(t, last.Nonce)
}

// signAgentAuth signs the canonical preimage with the given seed, as the agent does.
func signAgentAuth(t *testing.T, seedHex, device, tenant string, nonce []byte) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(mustHex(t, seedHex))
	return hex.EncodeToString(ed25519.Sign(priv, agentAuthSigningBytes(device, tenant, nonce)))
}

// registerAndProve drives the full handshake for one connection and returns it.
func registerAndProve(t *testing.T, srv *Server, conn *fakeConn, seedHex string) *Peer {
	t.Helper()
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, seedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	return peer
}

func rejectionReason(t *testing.T, conn *fakeConn) string {
	t.Helper()
	rej, ok := findMsg[Rejected](conn.messages())
	if !ok {
		t.Fatal("expected a rejected message")
	}
	return rej.Reason
}

// ---------------------------------------------------------------------------
// State machine.
// ---------------------------------------------------------------------------

// register_agent alone must produce a challenge and NOTHING else: no registry entry, no ack.
func TestRegisterAgentIssuesChallengeWithoutRegistering(t *testing.T) {
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})

	ch, ok := findMsg[AgentAuthChallenge](conn.messages())
	if !ok {
		t.Fatal("register_agent did not produce an agent_auth_challenge")
	}
	if ch.Device != agentAuthGoldenDevice {
		t.Fatalf("challenge echoes device %q, want %q", ch.Device, agentAuthGoldenDevice)
	}
	if ch.ExpiresAtMs <= time.Now().UnixMilli() {
		t.Fatalf("challenge expires_at_ms %d is not in the future", ch.ExpiresAtMs)
	}
	if _, ok := findMsg[Registered](conn.messages()); ok {
		t.Fatal("an unproven register_agent must not be acked with registered")
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("an unproven register_agent must not enter the registry")
	}
	if peer.registered {
		t.Fatal("peer marked registered before proving possession")
	}
	// The identity lookup happens at agent_auth_response time, so register_agent is not a
	// device-existence oracle.
	if calls := srv.identity.(*fakeResolver).calls; calls != 0 {
		t.Fatalf("register_agent made %d control-plane lookups, want 0", calls)
	}
}

// Each challenge is fresh: two connections never get the same nonce.
func TestAgentAuthNoncesAreUnique(t *testing.T) {
	srv := authServer(t, goldenResolver())
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		conn := &fakeConn{}
		srv.dispatch(&Peer{conn: conn}, ClientToServer{Payload: &RegisterAgent{
			Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
		}})
		nonce := hex.EncodeToString(challengeNonce(t, conn))
		if seen[nonce] {
			t.Fatalf("nonce %s was issued twice", nonce)
		}
		seen[nonce] = true
	}
}

// A valid proof registers the peer and adopts the CONTROL PLANE's tenant and pubkey, discarding
// whatever the client declared on the wire.
func TestAgentAuthAdoptsControlPlaneIdentity(t *testing.T) {
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice,
		Pubkey: strings.ToUpper(agentAuthGoldenPubkeyHex), // announced in a different case
		Tenant: "attacker-chosen-tenant",
		Nat:    NatFullCone,
		OS:     "Windows 11 Pro 25H2 (build 26200)",
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})

	if _, ok := findMsg[Registered](conn.messages()); !ok {
		t.Fatal("valid proof was not acked with registered")
	}
	got, ok := srv.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatal("valid proof did not register the peer")
	}
	if got != peer {
		t.Fatal("registry holds a different Peer than the proving connection")
	}
	if got.Tenant != agentAuthGoldenTenant {
		t.Fatalf("tenant = %q, want the control plane's %q (client-declared value must be discarded)",
			got.Tenant, agentAuthGoldenTenant)
	}
	if got.Pubkey != agentAuthGoldenPubkeyHex {
		t.Fatalf("pubkey = %q, want the pinned lowercase hex %q", got.Pubkey, agentAuthGoldenPubkeyHex)
	}
	if got.Nat != NatFullCone {
		t.Fatalf("nat = %q, want full_cone", got.Nat)
	}
	// Unlike tenant/pubkey, os has no authoritative control-plane copy to adopt — the asserted
	// value must survive the challenge round-trip into the registration (pendingAuth carries it).
	if got.OS != "Windows 11 Pro 25H2 (build 26200)" {
		t.Fatalf("os = %q, want the asserted description to survive the auth handshake", got.OS)
	}
	if conn.closed {
		t.Fatal("a successfully authenticated connection must stay open")
	}
}

// Every failure mode: the same generic reason, no registration, connection closed.
func TestAgentAuthRejections(t *testing.T) {
	// mutate rewrites the response the agent would otherwise have sent correctly; srv/nonce are
	// supplied so a case can also tamper with server state.
	tests := []struct {
		name     string
		resolver func() *fakeResolver
		announce string // pubkey announced at register_agent
		mutate   func(t *testing.T, srv *Server, resp *AgentAuthResponse, nonce []byte)
	}{
		{
			name: "signature from the wrong key",
			mutate: func(t *testing.T, _ *Server, resp *AgentAuthResponse, nonce []byte) {
				resp.Sig = signAgentAuth(t, agentAuthWrongSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce)
			},
		},
		{
			name: "signature over a different nonce",
			mutate: func(t *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				other := mustHex(t, agentAuthGoldenNonceHex)
				resp.Nonce = hex.EncodeToString(other)
				resp.Sig = signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, other)
			},
		},
		{
			name: "signature over a different tenant",
			mutate: func(t *testing.T, _ *Server, resp *AgentAuthResponse, nonce []byte) {
				resp.Sig = signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, "some-other-tenant", nonce)
			},
		},
		{
			name: "response names another device",
			mutate: func(_ *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				resp.Device = "44444444-4444-4444-4444-444444444444"
			},
		},
		{
			name: "nonce is not 32 bytes",
			mutate: func(_ *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				resp.Nonce = "abcd"
			},
		},
		{
			name: "nonce is not hex",
			mutate: func(_ *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				resp.Nonce = strings.Repeat("zz", agentAuthNonceLen)
			},
		},
		{
			name: "garbage signature",
			mutate: func(_ *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				resp.Sig = "not-a-signature"
			},
		},
		{
			name: "truncated signature",
			mutate: func(_ *testing.T, _ *Server, resp *AgentAuthResponse, _ []byte) {
				resp.Sig = resp.Sig[:len(resp.Sig)-2]
			},
		},
		{
			name: "challenge expired",
			mutate: func(_ *testing.T, srv *Server, _ *AgentAuthResponse, _ []byte) {
				at := time.Now().Add(agentAuthChallengeTTL + time.Second)
				srv.now = func() time.Time { return at }
			},
		},
		{
			name:     "device unknown to the control plane",
			resolver: func() *fakeResolver { return &fakeResolver{identities: map[string]*DeviceIdentity{}} },
		},
		{
			name: "control plane unreachable",
			resolver: func() *fakeResolver {
				return &fakeResolver{err: errors.New("dial tcp: connection refused")}
			},
		},
		{
			name: "device has no pinned pubkey",
			resolver: func() *fakeResolver {
				return &fakeResolver{identities: map[string]*DeviceIdentity{
					agentAuthGoldenDevice: {DeviceID: agentAuthGoldenDevice, TenantID: agentAuthGoldenTenant},
				}}
			},
		},
		{
			name:     "announced pubkey is not the pinned one",
			announce: "00" + agentAuthGoldenPubkeyHex[2:],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := goldenResolver()
			if tt.resolver != nil {
				resolver = tt.resolver()
			}
			srv := authServer(t, resolver)
			conn := &fakeConn{}
			peer := &Peer{conn: conn}

			announce := agentAuthGoldenPubkeyHex
			if tt.announce != "" {
				announce = tt.announce
			}
			srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
				Device: agentAuthGoldenDevice, Pubkey: announce, Nat: NatOpen,
			}})
			nonce := challengeNonce(t, conn)
			resp := &AgentAuthResponse{
				Device: agentAuthGoldenDevice,
				Nonce:  hex.EncodeToString(nonce),
				Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
			}
			if tt.mutate != nil {
				tt.mutate(t, srv, resp, nonce)
			}
			srv.dispatch(peer, ClientToServer{Payload: resp})

			if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
				t.Fatalf("rejection reason %q leaks the failing check, want %q", reason, agentAuthRejectionReason)
			}
			if _, ok := findMsg[Registered](conn.messages()); ok {
				t.Fatal("a failed proof must not be acked with registered")
			}
			if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
				t.Fatal("a failed proof must not enter the registry")
			}
			if !conn.closed {
				t.Fatal("a failed proof must close the connection")
			}
		})
	}
}

// TestAgentAuthRejectsNilIdentityFromResolver covers agentauth.go:162-164: when the resolver maps
// a device key to a nil *DeviceIdentity (ok == true, id == nil), the guard converts that into a
// handled rejection rather than a nil pointer dereference on identity.Pubkey at line 165.
func TestAgentAuthRejectsNilIdentityFromResolver(t *testing.T) {
	resolver := &fakeResolver{identities: map[string]*DeviceIdentity{
		agentAuthGoldenDevice: nil,
	}}
	srv := authServer(t, resolver)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})

	if !conn.closed {
		t.Fatal("a nil identity from the resolver must close the connection")
	}
	if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
		t.Fatalf("rejection reason %q leaks the failing check, want %q", reason, agentAuthRejectionReason)
	}
	if _, ok := findMsg[Registered](conn.messages()); ok {
		t.Fatal("a nil identity must not be acked with registered")
	}
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); ok {
		t.Fatal("a nil identity must not enter the registry")
	}
}

// A nonce is single-use: the same connection cannot answer twice, and a captured (nonce, sig) pair
// is worthless on a fresh connection because that connection gets its own nonce.
func TestAgentAuthNonceIsSingleUse(t *testing.T) {
	srv := authServer(t, goldenResolver())

	victimConn := &fakeConn{}
	victim := &Peer{conn: victimConn}
	srv.dispatch(victim, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	nonce := challengeNonce(t, victimConn)
	captured := &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}
	srv.dispatch(victim, ClientToServer{Payload: captured})
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok {
		t.Fatal("valid proof did not register")
	}

	// A wiretapper replays the captured proof on its own connection.
	attackerConn := &fakeConn{}
	attacker := &Peer{conn: attackerConn}
	srv.dispatch(attacker, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	srv.dispatch(attacker, ClientToServer{Payload: captured})

	if reason := rejectionReason(t, attackerConn); reason != agentAuthRejectionReason {
		t.Fatalf("replay rejection reason %q, want %q", reason, agentAuthRejectionReason)
	}
	if !attackerConn.closed {
		t.Fatal("a replayed proof must close the attacker's connection")
	}
	if victimConn.closed {
		t.Fatal("a replayed proof must not close the legitimate agent's connection")
	}
	if got, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok || got != victim {
		t.Fatal("the legitimate agent must remain the registered peer")
	}
}

// An agent_auth_response with no challenge outstanding is refused (there is nothing to answer).
func TestAgentAuthResponseWithoutChallengeRejected(t *testing.T) {
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	srv.dispatch(&Peer{conn: conn}, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  agentAuthGoldenNonceHex,
		Sig:    agentAuthGoldenSigHex,
	}})
	if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
		t.Fatalf("reason %q, want %q", reason, agentAuthRejectionReason)
	}
	if !conn.closed {
		t.Fatal("an unsolicited agent_auth_response must close the connection")
	}
	if srv.identity.(*fakeResolver).calls != 0 {
		t.Fatal("an unsolicited response must not reach the control plane")
	}
}

// THE HIJACK: a connection that claims a device id but never proves possession must leave the
// incumbent untouched — still registered, socket still open, still brokerable.
func TestUnprovenRegistrationDoesNotDisplaceIncumbent(t *testing.T) {
	srv := authServer(t, goldenResolver())
	incumbentConn := &fakeConn{}
	incumbent := registerAndProve(t, srv, incumbentConn, agentAuthGoldenSeedHex)
	if _, ok := srv.reg.Lookup(agentAuthGoldenDevice); !ok {
		t.Fatal("incumbent did not register")
	}

	// (a) the attacker asks for a challenge and simply never answers.
	silentConn := &fakeConn{}
	srv.dispatch(&Peer{conn: silentConn}, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	if incumbentConn.closed {
		t.Fatal("an unanswered register_agent closed the incumbent's socket")
	}
	if silentConn.closed {
		t.Fatal("an unanswered challenge must leave the socket open and usable")
	}
	if got, _ := srv.reg.Lookup(agentAuthGoldenDevice); got != incumbent {
		t.Fatal("an unanswered register_agent displaced the incumbent")
	}

	// (b) the attacker answers with a key it does not own.
	forgerConn := &fakeConn{}
	forger := &Peer{conn: forgerConn}
	srv.dispatch(forger, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	nonce := challengeNonce(t, forgerConn)
	srv.dispatch(forger, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthWrongSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	if !forgerConn.closed {
		t.Fatal("a forged proof must close the forger's connection")
	}
	if incumbentConn.closed {
		t.Fatal("a forged proof closed the incumbent's socket — the hijack is still open")
	}
	if got, _ := srv.reg.Lookup(agentAuthGoldenDevice); got != incumbent {
		t.Fatal("a forged proof displaced the incumbent")
	}
}

// Displacement after a VALID proof is intended: a reconnecting agent supersedes its stale socket.
func TestValidProofDisplacesIncumbent(t *testing.T) {
	srv := authServer(t, goldenResolver())
	staleConn := &fakeConn{}
	registerAndProve(t, srv, staleConn, agentAuthGoldenSeedHex)

	freshConn := &fakeConn{}
	fresh := registerAndProve(t, srv, freshConn, agentAuthGoldenSeedHex)

	if !staleConn.closed {
		t.Fatal("a reconnecting agent that proved possession should supersede the stale socket")
	}
	if got, _ := srv.reg.Lookup(agentAuthGoldenDevice); got != fresh {
		t.Fatal("the reconnected agent is not the registered peer")
	}
	if freshConn.closed {
		t.Fatal("the reconnected agent's socket must stay open")
	}
}

// A connection cannot mint challenges indefinitely.
func TestRegisterAgentAttemptCap(t *testing.T) {
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	reg := ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}}

	for i := 0; i < maxRegisterAttempts; i++ {
		srv.dispatch(peer, reg)
		if conn.closed {
			t.Fatalf("connection closed after %d attempts, cap is %d", i+1, maxRegisterAttempts)
		}
	}
	srv.dispatch(peer, reg)
	if !conn.closed {
		t.Fatalf("attempt %d must close the connection", maxRegisterAttempts+1)
	}
	if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
		t.Fatalf("reason %q, want %q", reason, agentAuthRejectionReason)
	}
}

// Re-registering on an already-registered connection must not re-open the auth window.
func TestRegisterAgentOnRegisteredConnectionRefused(t *testing.T) {
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	peer := registerAndProve(t, srv, conn, agentAuthGoldenSeedHex)

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "44444444-4444-4444-4444-444444444444", Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})

	if reason := rejectionReason(t, conn); reason != "already registered" {
		t.Fatalf("reason %q, want %q", reason, "already registered")
	}
	if peer.pendingAuth != nil {
		t.Fatal("a refused re-registration must not open a new challenge")
	}
	if peer.DeviceId != agentAuthGoldenDevice || peer.Tenant != agentAuthGoldenTenant {
		t.Fatalf("existing registration was mutated: %+v", peer)
	}
	if _, ok := srv.reg.Lookup("44444444-4444-4444-4444-444444444444"); ok {
		t.Fatal("a refused re-registration must not register the new device id")
	}
}

// An unregistered peer's heartbeat must not refresh a registry entry it does not own.
func TestHeartbeatFromUnregisteredPeerRejected(t *testing.T) {
	srv := authServer(t, goldenResolver())
	registerAndProve(t, srv, &fakeConn{}, agentAuthGoldenSeedHex)

	conn := &fakeConn{}
	srv.dispatch(&Peer{conn: conn}, ClientToServer{Payload: &Heartbeat{Device: agentAuthGoldenDevice}})
	if reason := rejectionReason(t, conn); reason != "heartbeat for unregistered device" {
		t.Fatalf("reason %q, want %q", reason, "heartbeat for unregistered device")
	}
}

// Dev mode (-insecure-no-agent-auth ⇒ nil resolver) keeps the pre-M3 behaviour the Playwright
// specs depend on: register_agent registers immediately, with no challenge and no control plane.
func TestDevModeRegistersWithoutProof(t *testing.T) {
	srv := authServer(t, nil)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-local", Pubkey: "ed25519:rmt-agent", Tenant: "tenant-1", Nat: NatOpen,
		OS: "Windows 11 Home 25H2 (build 26200)",
	}})

	if _, ok := findMsg[Registered](conn.messages()); !ok {
		t.Fatal("dev mode did not ack register_agent with registered")
	}
	if _, ok := findMsg[AgentAuthChallenge](conn.messages()); ok {
		t.Fatal("dev mode must not issue a challenge")
	}
	got, ok := srv.reg.Lookup("dev-local")
	if !ok || got != peer {
		t.Fatal("dev mode did not register the peer")
	}
	if got.Tenant != "tenant-1" || got.Pubkey != "ed25519:rmt-agent" {
		t.Fatalf("dev-mode registration = %+v, want the client-declared identity", got)
	}
	if got.OS != "Windows 11 Home 25H2 (build 26200)" {
		t.Fatalf("dev-mode os = %q, want the declared description", got.OS)
	}

	// Heartbeats work for a dev-mode registration.
	srv.dispatch(peer, ClientToServer{Payload: &Heartbeat{Device: "dev-local"}})
	if _, ok := findMsg[Rejected](conn.messages()); ok {
		t.Fatal("dev-mode heartbeat was rejected")
	}
}

// The os bound is applied ON RECEIPT, on both registration paths — an agent that ships an
// oversized string must not be able to push it into the registry (and from there into the
// presence feed) through either door. Registration itself must survive: this is inventory, and
// killing a live agent over a display column would be the wrong trade.
func TestOversizedOSIsBoundedOnBothRegistrationPaths(t *testing.T) {
	huge := strings.Repeat("y", 4096)

	// Dev path.
	srv := authServer(t, nil)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-big-os", Pubkey: "ed25519:rmt-agent", Nat: NatOpen, OS: huge,
	}})
	got, ok := srv.reg.Lookup("dev-big-os")
	if !ok {
		t.Fatal("dev-mode registration with an oversized os must still register")
	}
	if len(got.OS) != maxOSDescriptionBytes {
		t.Fatalf("dev-mode os = %d bytes, want bounded to %d", len(got.OS), maxOSDescriptionBytes)
	}

	// Enforced path: the bound must hold through the challenge round-trip (newPendingAuth is the
	// choke point there).
	srv = authServer(t, goldenResolver())
	conn = &fakeConn{}
	peer = &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen, OS: huge,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	got, ok = srv.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatal("enforced registration with an oversized os must still register")
	}
	if len(got.OS) != maxOSDescriptionBytes {
		t.Fatalf("enforced os = %d bytes, want bounded to %d", len(got.OS), maxOSDescriptionBytes)
	}
}

// The agent_version bound is applied ON RECEIPT on both registration paths — an agent that ships
// an oversized string must not be able to push it into the registry through either door.
// Registration itself must survive: dropping an agent over a display column is the wrong trade.
func TestOversizedAgentVersionIsBoundedOnBothRegistrationPaths(t *testing.T) {
	huge := strings.Repeat("y", 4096)

	// Dev path: nil resolver → dispatch registers immediately without a challenge round-trip.
	srv := authServer(t, nil)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-big-av", Pubkey: "ed25519:rmt-agent", Nat: NatOpen, AgentVersion: huge,
	}})
	got, ok := srv.reg.Lookup("dev-big-av")
	if !ok {
		t.Fatal("dev-mode registration with an oversized agent_version must still register")
	}
	if len(got.AgentVersion) != maxAgentVersionBytes {
		t.Fatalf("dev-mode agent_version = %d bytes, want bounded to %d", len(got.AgentVersion), maxAgentVersionBytes)
	}

	// Enforced path: the bound must hold through the challenge round-trip (newPendingAuth stores
	// boundAgentVersion; main.go copies it into the registered Peer on AgentAuthResponse).
	srv = authServer(t, goldenResolver())
	conn = &fakeConn{}
	peer = &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen, AgentVersion: huge,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	got, ok = srv.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatal("enforced registration with an oversized agent_version must still register")
	}
	if len(got.AgentVersion) != maxAgentVersionBytes {
		t.Fatalf("enforced agent_version = %d bytes, want bounded to %d", len(got.AgentVersion), maxAgentVersionBytes)
	}
}

// ptrBool returns a pointer to v. Needed because require_session_policy is a *bool tri-state where
// nil (not sent) and *false (explicitly cleared) are wire-distinct.
func ptrBool(v bool) *bool { return &v }

// TestRequireSessionPolicyPreservedOnBothRegistrationPaths proves that the require_session_policy
// *bool tri-state survives dispatch onto the registered Peer on both registration paths.
// The *false case is load-bearing: a dispatch that collapses *false to nil would strand a machine
// in require_session_policy=true forever after an operator clears the flag, because the control
// plane only writes the DB column for agents that report a non-nil value.
// presence_test.go cannot catch this because those tests construct Peers directly, bypassing
// dispatch entirely.
func TestRequireSessionPolicyPreservedOnBothRegistrationPaths(t *testing.T) {
	// Dev path (nil resolver): dispatch registers immediately without a challenge round-trip.
	// Use *false — the load-bearing case that distinguishes "explicitly cleared" from "never sent".
	srv := authServer(t, nil)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-policy-false", Pubkey: "ed25519:rmt-agent", Nat: NatOpen,
		RequireSessionPolicy: ptrBool(false),
	}})
	got, ok := srv.reg.Lookup("dev-policy-false")
	if !ok {
		t.Fatal("dev-mode registration with require_session_policy=false must register")
	}
	if got.RequireSessionPolicy == nil {
		t.Fatal("dev-mode: RequireSessionPolicy is nil, want *false (nil and false are wire-distinct)")
	}
	if *got.RequireSessionPolicy != false {
		t.Fatalf("dev-mode: *RequireSessionPolicy = %v, want false", *got.RequireSessionPolicy)
	}

	// Enforced path: the value must survive the challenge/response round-trip (newPendingAuth
	// stores it; main.go copies pending.RequireSessionPolicy into the registered Peer on response).
	srv = authServer(t, goldenResolver())
	conn = &fakeConn{}
	peer = &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
		RequireSessionPolicy: ptrBool(true),
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: agentAuthGoldenDevice,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	got, ok = srv.reg.Lookup(agentAuthGoldenDevice)
	if !ok {
		t.Fatal("enforced registration with require_session_policy=true must register")
	}
	if got.RequireSessionPolicy == nil {
		t.Fatal("enforced: RequireSessionPolicy is nil, want *true")
	}
	if *got.RequireSessionPolicy != true {
		t.Fatalf("enforced: *RequireSessionPolicy = %v, want true", *got.RequireSessionPolicy)
	}
}

// TestNatPreservedOnDevPath proves that the Nat field declared by the agent survives dispatch onto
// the registered Peer on the dev path (nil resolver). NatSymmetric is chosen because it is the
// opposite end of the enum from NatOpen — a mutation of main.go:303 that hardcodes self.Nat =
// NatOpen would make this test fail immediately, whereas every existing dev-path caller sends
// NatOpen and never asserts got.Nat.
func TestNatPreservedOnDevPath(t *testing.T) {
	srv := authServer(t, nil)
	conn := &fakeConn{}
	peer := &Peer{conn: conn}

	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: "dev-nat-sym", Pubkey: "ed25519:rmt-agent", Nat: NatSymmetric,
	}})

	got, ok := srv.reg.Lookup("dev-nat-sym")
	if !ok {
		t.Fatal("dev-mode registration did not register the peer")
	}
	if got.Nat != NatSymmetric {
		t.Fatalf("dev-mode: got.Nat = %v, want NatSymmetric", got.Nat)
	}
}

// TestClipForLog covers the pure helper that bounds peer-supplied strings before they are logged.
func TestClipForLog(t *testing.T) {
	t.Run("short unchanged", func(t *testing.T) {
		if got := clipForLog("abc"); got != "abc" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("exactly the limit unchanged", func(t *testing.T) {
		s := strings.Repeat("a", maxLogFieldBytes)
		if got := clipForLog(s); got != s {
			t.Fatalf("a %d-byte string must pass through unchanged, got %d bytes", len(s), len(got))
		}
	})
	t.Run("oversized ASCII is clipped with a length marker", func(t *testing.T) {
		s := strings.Repeat("a", maxLogFieldBytes+1000)
		want := strings.Repeat("a", maxLogFieldBytes) + "...(1128 bytes)"
		if got := clipForLog(s); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("a rune straddling the cut is not split", func(t *testing.T) {
		// 127 ASCII bytes, then a 2-byte rune occupying bytes 127-128: the cut lands inside it.
		s := strings.Repeat("a", maxLogFieldBytes-1) + "é" + strings.Repeat("b", 50)
		got := clipForLog(s)
		if !utf8.ValidString(got) {
			t.Fatalf("clipped output is not valid UTF-8: %q", got)
		}
		want := strings.Repeat("a", maxLogFieldBytes-1) + "...(179 bytes)"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("a multibyte rune ending exactly at the limit is kept", func(t *testing.T) {
		s := strings.Repeat("a", maxLogFieldBytes-2) + "é" + "zzz"
		got := clipForLog(s)
		if !strings.HasPrefix(got, strings.Repeat("a", maxLogFieldBytes-2)+"é...(") || !utf8.ValidString(got) {
			t.Fatalf("got %q", got)
		}
	})
}

// captureAuthLog redirects the standard logger into a buffer for the test and restores it afterwards.
func captureAuthLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// driveDeviceMismatch registers the golden device, then answers the challenge naming `device`.
func driveDeviceMismatch(t *testing.T, device string) (*fakeConn, string) {
	t.Helper()
	buf := captureAuthLog(t)
	srv := authServer(t, goldenResolver())
	conn := &fakeConn{}
	peer := &Peer{conn: conn}
	srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
		Device: agentAuthGoldenDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	}})
	nonce := challengeNonce(t, conn)
	srv.dispatch(peer, ClientToServer{Payload: &AgentAuthResponse{
		Device: device,
		Nonce:  hex.EncodeToString(nonce),
		Sig:    signAgentAuth(t, agentAuthGoldenSeedHex, agentAuthGoldenDevice, agentAuthGoldenTenant, nonce),
	}})
	return conn, buf.String()
}

func TestAgentAuthRejectionLogBoundsOversizedDevice(t *testing.T) {
	huge := strings.Repeat("D", 60*1024)
	conn, logged := driveDeviceMismatch(t, huge)

	// Negative control: the buffer really does receive the rejection line.
	if !strings.Contains(logged, "agent auth rejected for device") {
		t.Fatalf("rejection line missing from captured log: %q", logged)
	}
	if strings.Contains(logged, huge) || strings.Contains(logged, strings.Repeat("D", 1024)) {
		t.Fatal("oversized device string reached the log")
	}
	if len(logged) > 1024 {
		t.Fatalf("log output is %d bytes, want a short line", len(logged))
	}
	if !strings.Contains(logged, "...(61440 bytes)") {
		t.Fatalf("length marker missing: %q", logged)
	}
	if !conn.closed {
		t.Fatal("connection must be closed")
	}
	if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
		t.Fatalf("reason = %q, want %q", reason, agentAuthRejectionReason)
	}
}

func TestAgentAuthRejectionLogKeepsShortMismatchedDeviceInFull(t *testing.T) {
	const other = "44444444-4444-4444-4444-444444444444"
	conn, logged := driveDeviceMismatch(t, other)
	// main.go logs the error with %q, so the error's own quotes appear backslash-escaped.
	if !strings.Contains(logged, `response names device \"`+other+`\", challenge was issued for \"`+agentAuthGoldenDevice+`\"`) {
		t.Fatalf("short mismatch must be logged in full, got %q", logged)
	}
	if strings.Contains(logged, "bytes)") {
		t.Fatalf("short values must not carry a clip marker: %q", logged)
	}
	if !conn.closed {
		t.Fatal("connection must be closed")
	}
}

// TestRegisterAgentRejectsBlankOrOversizedDeviceId proves that handleRegisterAgent closes the
// connection and sends Rejected when the Device field is empty or exceeds the 128-byte cap
// (main.go:278-282). A mutation removing those lines would silently admit blank or 200-byte
// device IDs without closing the connection — this test catches it.
func TestRegisterAgentRejectsBlankOrOversizedDeviceId(t *testing.T) {
	cases := []struct {
		name   string
		device string
	}{
		{"empty", ""},
		{"oversized", strings.Repeat("x", 129)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := authServer(t, nil)
			conn := &fakeConn{}
			peer := &Peer{conn: conn}

			srv.dispatch(peer, ClientToServer{Payload: &RegisterAgent{
				Device: tc.device, Pubkey: "ed25519:rmt-agent", Nat: NatOpen,
			}})

			if !conn.closed {
				t.Fatalf("device=%q: connection must be closed, got open", tc.device)
			}
			if reason := rejectionReason(t, conn); reason != agentAuthRejectionReason {
				t.Fatalf("device=%q: reason = %q, want %q", tc.device, reason, agentAuthRejectionReason)
			}
		})
	}
}
