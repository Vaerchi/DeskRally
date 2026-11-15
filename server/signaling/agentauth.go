package main

// Agent identity proof of possession (M3 — docs/11-agent-identity-contract.md).
//
// `register_agent` used to be an unauthenticated assertion: the connection named a device id and
// Registry.Register closed the incumbent's socket for it, so anyone who learned a device id could
// evict the real agent and receive the next technician's brokered session. A device id is an
// identifier, not a secret.
//
// Now a registration is admitted only after the connection signs a server-chosen 32-byte nonce
// with the private half of the Ed25519 key the control plane pinned for that device id
// (machine.pubkey, pinned at POST /enroll/redeem). Registry.Register is reached ONLY on the
// valid-proof edge, so a pending or failed registration can never displace a healthy agent.
//
// !!! The canonical bytes built here MUST stay BYTE-IDENTICAL to the Rust builder in
// crates/protocol/src/agent_auth.rs (domain tag "RMTAGENTAUTHv1\x00\x00", u8 version, then u32
// big-endian length-prefixed device id, tenant id and nonce). Both languages pin the SAME golden
// fixture (agentauth_test.go <-> crates/protocol/src/agent_auth.rs), so any drift breaks a test
// loudly. DO NOT change a byte here without changing it identically there. !!!

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// agentAuthDomainTag is the 16-byte domain-separation tag: ASCII "RMTAGENTAUTHv1" + two 0x00
// bytes. It differs from "RMTTICKETv1\x00" and "RMTGRANTv1\x00\x00" at byte 3, so no preimage
// under one tag can ever verify as another.
var agentAuthDomainTag = []byte("RMTAGENTAUTHv1\x00\x00")

const (
	// agentAuthVersion is the only canonical preimage version this server builds or accepts.
	agentAuthVersion = 1
	// agentAuthNonceLen is the exact challenge length; any other length is rejected.
	agentAuthNonceLen = 32
	// agentAuthChallengeTTL bounds how long a nonce stays answerable. The nonce's server-side
	// lifetime is the freshness bound — no timestamp is signed.
	agentAuthChallengeTTL = 30 * time.Second
	// maxRegisterAttempts caps register_agent messages per connection so a single socket cannot
	// mint challenges indefinitely.
	maxRegisterAttempts = 5
	// agentAuthRejectionReason is the ONLY reason string reported for every authentication
	// failure. Mirrors ticket.go's errTicketInvalid posture: a prober must not learn whether the
	// device exists, whether the pubkey matched, or whether the signature was bad. The specific
	// cause is logged server-side only.
	agentAuthRejectionReason = "registration not authorized"
)

// agentAuthSigningBytes builds the canonical v1 preimage an agent signs to prove possession of its
// enrolled key. deviceID and tenantID are the SERVER-AUTHORITATIVE values (the device the
// challenge was issued for, and the tenant the control plane reports for it), never what the
// client declared. Total length is 61 + len(deviceID) + len(tenantID).
func agentAuthSigningBytes(deviceID, tenantID string, nonce []byte) []byte {
	buf := append([]byte{}, agentAuthDomainTag...)
	buf = append(buf, byte(agentAuthVersion))
	lp := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	lp([]byte(deviceID))
	lp([]byte(tenantID))
	lp(nonce)
	return buf
}

// pendingAuth is the outstanding challenge for one connection. It lives on the *Peer, never in a
// global map: a nonce is answerable only by the socket it was issued to.
type pendingAuth struct {
	// resolveSeq is the registry sequence number taken right before the identity lookup (see verifyAgentAuth).
	resolveSeq uint64
	Device     string
	Pubkey     string // the pubkey announced at register_agent, cross-checked against the pinned one
	Nat        NatType
	// OS is the bounded os description announced at register_agent, held so the eventual
	// registration carries it. Asserted inventory — proof of possession authenticates the DEVICE
	// that said it, not the string's truth.
	OS string
	// RequireSessionPolicy is the asserted floor flag from register_agent, held for the same reason
	// as OS and on the same terms: proof of possession authenticates the DEVICE that said it, not
	// the assertion's truth. Nil means the agent said nothing.
	RequireSessionPolicy *bool
	// AgentVersion is the bounded build identity announced at register_agent, held for the same
	// reason as OS: the registration that eventually lands has to carry what the peer said BEFORE
	// it proved anything. Proof of possession authenticates the DEVICE that said it, not the
	// string's truth.
	AgentVersion string
	// LoggedInUser is the bounded interactive-session user announced at register_agent (e.g.
	// "CORP\alice"), held for the same reason as OS and AgentVersion. Proof of possession
	// authenticates the DEVICE that said it, not the user string's truth.
	LoggedInUser string
	// MultiSessionCapable is the bounded advisory capability flag from register_agent. Held for the
	// same reason as OS and AgentVersion: the registration carries what the peer said before proof.
	MultiSessionCapable *bool
	// Features is the bounded feature list announced at register_agent (boundFeatures), held for the
	// same reason as OS: the registration carries what the peer said before proof. The device that
	// proved possession is the authority on what it understands.
	Features    []string
	Nonce       []byte
	ExpiresAtMs int64
}

// newPendingAuth mints a challenge for a register_agent. The nonce comes from crypto/rand and
// there is no weaker fallback: a read error aborts the registration.
func (s *Server) newPendingAuth(p *RegisterAgent) (*pendingAuth, error) {
	nonce := make([]byte, agentAuthNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("mint agent-auth nonce: %w", err)
	}
	return &pendingAuth{
		Device:               p.Device,
		Pubkey:               p.Pubkey,
		Nat:                  p.Nat,
		OS:                   boundOSDescription(p.OS),
		RequireSessionPolicy: p.RequireSessionPolicy,
		AgentVersion:         boundAgentVersion(p.AgentVersion),
		LoggedInUser:         boundLoggedInUser(p.LoggedInUser),
		MultiSessionCapable:  p.MultiSessionCapable,
		Features:             boundFeatures(p.Features),
		Nonce:                nonce,
		ExpiresAtMs:          s.now().Add(agentAuthChallengeTTL).UnixMilli(),
	}, nil
}

// challenge renders the pending auth as the wire message.
func (a *pendingAuth) challenge() AgentAuthChallenge {
	return AgentAuthChallenge{
		Device:      a.Device,
		Nonce:       hex.EncodeToString(a.Nonce),
		ExpiresAtMs: a.ExpiresAtMs,
	}
}

// maxLogFieldBytes caps how much of an attacker-controlled string reaches a server log line.
const maxLogFieldBytes = 128

// clipForLog bounds a peer-supplied string before it is logged. It returns s unchanged when it is
// at most maxLogFieldBytes long; otherwise a prefix of at most maxLogFieldBytes bytes, cut on a rune
// boundary, followed by a marker recording the original byte length.
func clipForLog(s string) string {
	if len(s) <= maxLogFieldBytes {
		return s
	}
	cut := maxLogFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(" + strconv.Itoa(len(s)) + " bytes)"
}

// verifyAgentAuth runs the contract's checks in order, stopping at the first failure, and returns
// the control-plane identity the registration must adopt. The caller has already taken and cleared
// the pending challenge, so a nonce is single-use whatever the outcome.
//
// The identity lookup happens HERE, not at register_agent time: controllers (which never answer a
// challenge) cost zero control-plane calls, and register_agent cannot be used as a device-existence
// oracle because the reply is a challenge either way.
func (s *Server) verifyAgentAuth(pending *pendingAuth, msg *AgentAuthResponse) (*DeviceIdentity, error) {
	if pending == nil {
		return nil, errors.New("no challenge outstanding on this connection")
	}
	if nowMs := s.now().UnixMilli(); nowMs > pending.ExpiresAtMs {
		return nil, fmt.Errorf("challenge expired at %d (now %d)", pending.ExpiresAtMs, nowMs)
	}
	if msg.Device != pending.Device {
		return nil, fmt.Errorf("response names device %q, challenge was issued for %q", clipForLog(msg.Device), clipForLog(pending.Device))
	}
	nonce, err := hex.DecodeString(msg.Nonce)
	if err != nil || len(nonce) != agentAuthNonceLen {
		return nil, errors.New("nonce is not 32 hex-encoded bytes")
	}
	if subtle.ConstantTimeCompare(nonce, pending.Nonce) != 1 {
		return nil, errors.New("nonce does not match the outstanding challenge")
	}
	sig, err := hex.DecodeString(msg.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("signature is not 64 hex-encoded bytes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), deviceIdentityTimeout)
	defer cancel()
	// The sequence is taken immediately before the lookup, so it orders this answer against every other
	// lookup for the device (Registry.staleAuthLocked).
	pending.resolveSeq = s.reg.NextAuthSeq()
	identity, err := s.identity.Resolve(ctx, pending.Device)
	if err != nil {
		return nil, fmt.Errorf("resolve device identity: %w", err)
	}
	if identity == nil {
		return nil, errors.New("resolver returned no identity")
	}
	pub, err := hex.DecodeString(identity.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("pinned pubkey is not a hex-encoded 32-byte Ed25519 key")
	}
	// Defence in depth: the announced pubkey must be the pinned one. The signature check below is
	// the real gate — it uses the PINNED key regardless of what was announced.
	if !strings.EqualFold(pending.Pubkey, identity.Pubkey) {
		return nil, fmt.Errorf("announced pubkey %q is not the key pinned for this device", clipForLog(pending.Pubkey))
	}
	if !ed25519.Verify(pub, agentAuthSigningBytes(pending.Device, identity.TenantID, nonce), sig) {
		return nil, errors.New("signature does not verify against the pinned key")
	}
	return identity, nil
}
