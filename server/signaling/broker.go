package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Broker errors that embed an unauthenticated identifier (a connect_request target, a trickled
// session id) are logged by the caller, and the log limiter bounds lines per second, not line size,
// so those ids go through clipForLog (agentauth.go). Only the error text is clipped: lookups keep
// using the full value.

// Session pairs the two peers of a brokered connection so trickled candidates can be routed
// between them by SessionId. Requester is the connect_request originator (typically the
// controller); Target is the registered agent it asked to reach.
type Session struct {
	Id           string
	Requester    *Peer
	Target       *Peer
	TechnicianID string
	Access       string
}

// peer returns the far side of the session relative to `from`, or nil if `from` is not a
// member of this session.
func (s *Session) peer(from *Peer) *Peer {
	switch from {
	case s.Requester:
		return s.Target
	case s.Target:
		return s.Requester
	default:
		return nil
	}
}

// Broker turns connect_requests into brokered sessions and relays candidates between the two
// peers of a session. It is the authoritative control plane: it never sees session plaintext,
// only pins identities and hands out relay tokens.
type Broker struct {
	reg          *Registry
	serverPubkey string
	relayAddr    string

	// TURN/STUN issuance policy (turn.go). Zero value = none configured, which is the LAN default
	// and yields an empty (but still sent) ice_servers list.
	turn TurnConfig
	// Caps on OUTSTANDING (unexpired) TURN credentials (0 = package default). coturn's
	// allocation quota is global, so one user or tenant must not be able to hold all of it.
	turnMaxPerUser, turnMaxPerTenant int
	turnLedger                       turnLedger

	// ticketPub, when non-nil, makes connect_request REQUIRE a valid control-plane session
	// ticket (ticket.go) — the M2 authorization gate. Nil = dev mode: any client may broker
	// (main() logs a loud warning). nowMs is the expiry clock, swappable in tests.
	ticketPub ed25519.PublicKey
	nowMs     func() int64

	// spent makes each verified ticket usable for exactly one brokered session (ticket.go). It is
	// the FAST PATH and the first line of defence: process-local, so it costs nothing and keeps
	// working when the control plane does not.
	spent *spentTickets

	// redeemer, when non-nil, is the control plane's SHARED ledger (ticketredeem.go) — the half of
	// single-use enforcement that a per-process map cannot provide, since it spans replicas and
	// survives restarts. Nil = local map only (dev, or no control-plane endpoint configured).
	redeemer TicketRedeemer

	// ticketStrict controls the ledger-failure posture (SIGNALING_STRICT_TICKET_REDEMPTION).
	// false (default): any non-definitive ledger error warns and proceeds on the local map alone.
	// true: any ledger error that is not a definitive "already redeemed" refuses the broker.
	// See ticketredeem.go for the design trade-off between these two stances.
	ticketStrict bool

	mu       sync.Mutex
	sessions map[string]*Session
	// deviceSessions maps a target agent DeviceId to the set of session IDs currently active for
	// that device, enabling concurrent multi-session tracking and SessionParticipants broadcasts.
	// Keyed by DeviceId → set of Session.Id. Written under mu.
	deviceSessions map[string]map[string]*Session
}

// NewBroker constructs a broker over the given registry. serverPubkey is echoed for pinning;
// relayAddr is the relay both peers are pointed at as the guaranteed fallback path. ticketPub
// (nil to disable) is the control plane's grant-issuer Ed25519 key that session tickets must
// verify against.
func NewBroker(reg *Registry, serverPubkey, relayAddr string, ticketPub ed25519.PublicKey) *Broker {
	return &Broker{
		reg:            reg,
		serverPubkey:   serverPubkey,
		relayAddr:      relayAddr,
		ticketPub:      ticketPub,
		nowMs:          func() int64 { return time.Now().UnixMilli() },
		spent:          newSpentTickets(),
		sessions:       make(map[string]*Session),
		deviceSessions: make(map[string]map[string]*Session),
	}
}

// WithTurn attaches the ICE/TURN issuance policy and returns the broker, for construction-time
// chaining in main().
//
// Deliberately NOT a plain setter: `turn` is read from ConnectRequest without holding b.mu, which
// is safe only because it is written once before any connection exists. A `SetTurnConfig` invited
// at some later date from a config-reload path would be a data race with no compiler complaint —
// the shape of this method is what says "construction time only".
func (b *Broker) WithTurn(cfg TurnConfig) *Broker {
	b.turn = cfg
	return b
}

// WithTicketRedeemer attaches the control plane's shared single-use ledger and returns the broker,
// for construction-time chaining in NewServer.
//
// Deliberately NOT a plain setter, for the same reason WithTurn is not: `redeemer` is read from
// ConnectRequest without holding b.mu, which is safe only because it is written once before any
// connection exists.
func (b *Broker) WithTicketRedeemer(r TicketRedeemer) *Broker {
	b.redeemer = r
	return b
}

// WithStrictTicketRedemption switches the ledger-failure posture from fail-open to fail-closed:
// any ledger error that is not a definitive "already redeemed" (HTTP 409) refuses the broker
// instead of warning and proceeding on the local map alone.
//
// The trade-off: fail-open lets the fleet keep brokering sessions during a control-plane restart
// or rolling deploy, at the cost of a bounded replay window while the ledger is unreachable.
// Fail-closed closes that window at the cost of blocking new sessions while the ledger is down.
// Choose based on which risk matters more for the deployment. Set SIGNALING_STRICT_TICKET_REDEMPTION
// in the environment to enable; without it the default fail-open posture applies.
//
// Deliberately NOT a plain setter for the same reason WithTurn is not.
func (b *Broker) WithStrictTicketRedemption() *Broker {
	b.ticketStrict = true
	return b
}

// ConnectRequest authorizes and brokers a request from `requester` to reach `target` by
// DeviceId. When a ticket pubkey is configured, the request's session ticket must verify
// (signature, expiry, tenant + device binding) or the request is rejected with a GENERIC reason —
// a probing client must not learn which check failed. On success it creates a session, sends
// `brokered` (with each peer's pinned pubkey) and a shared `relay_assignment` to both peers,
// and returns the session. If the target is unknown/offline it sends `rejected` to the
// requester and returns an error.
//
// The ticket's signature/expiry/device checks run BEFORE the registry lookup, so an unauthorized
// client cannot use the reply to probe which device ids are online; the tenant cross-check needs
// the resolved agent, so it runs immediately after and rejects with the same generic reason.
//
// A verified ticket brokers exactly ONE session, so a captured ticket cannot be replayed for the
// remainder of its TTL. That is enforced in two places, because one is not enough: the local
// spentTickets map (ticket.go) covers this process, and the control plane's shared ledger
// (ticketredeem.go) covers the deployment — replicas and restarts, which no in-memory map can.
//
// The `brokered` messages also carry the ticket's CONTROL-PLANE session id, which is what lets the
// agent bind a signed session policy to this session rather than accepting any unexpired policy for
// its device. That value is only ever taken from a ticket this function VERIFIED — see
// controlPlaneSessionOf below for why the dev path deliberately sends nothing.
func (b *Broker) ConnectRequest(requester *Peer, target string, ticket *SignedSessionTicket) (*Session, error) {
	if b.ticketPub != nil {
		if err := verifyTicket(b.ticketPub, ticket, b.nowMs(), target); err != nil {
			_ = requester.Send(Rejected{Reason: "connect request not authorized"})
			return nil, fmt.Errorf("connect_request: %w", err)
		}
	}
	agent, ok := b.reg.Lookup(target)
	if !ok {
		_ = requester.Send(Rejected{Reason: fmt.Sprintf("device %s is not registered or offline", target)})
		return nil, fmt.Errorf("connect_request: target %s not available", clipForLog(target))
	}
	if b.ticketPub != nil {
		if err := verifyTicketTenant(ticket, agent.Tenant); err != nil {
			_ = requester.Send(Rejected{Reason: "connect request not authorized"})
			return nil, fmt.Errorf("connect_request: %w", err)
		}
	}
	if agent == requester {
		_ = requester.Send(Rejected{Reason: "cannot connect to self"})
		return nil, fmt.Errorf("connect_request: self-connect rejected for %s", clipForLog(target))
	}
	// Commit point: burn the ticket. Everything above is a check that can be retried with the same
	// ticket; from here the request is authorized and consumes its single use.
	//
	// TWO ledgers, in this order. The local map is checked first because it is free and always
	// available; the control plane's shared ledger then catches what a per-process map structurally
	// cannot — the same ticket presented to a DIFFERENT replica, or to this one after a restart.
	// The order also means a same-instance replay never reaches the network.
	if b.ticketPub != nil {
		if !b.spent.consume(ticket.Claims.SessionID, ticket.Claims.ExpiresAtMs, b.nowMs()) {
			_ = requester.Send(Rejected{Reason: "connect request not authorized"})
			// Signed claims are issuer-authenticated but carry no length bound; diagnostics clip them
			// (lookups and the spent/ledger keys use the full values).
			return nil, fmt.Errorf("connect_request: %w: ticket for session %s was already used",
				errTicketInvalid, clipForLog(ticket.Claims.SessionID))
		}
		if err := b.redeemTicket(ticket); err != nil {
			_ = requester.Send(Rejected{Reason: "connect request not authorized"})
			return nil, fmt.Errorf("connect_request: %w: ticket for session %s was already redeemed "+
				"elsewhere in the deployment", errTicketInvalid, clipForLog(ticket.Claims.SessionID))
		}
	}

	sessionID, err := newUUID()
	if err != nil {
		_ = requester.Send(Rejected{Reason: "internal error allocating session"})
		return nil, fmt.Errorf("connect_request: allocate session id: %w", err)
	}
	// Snapshot attribution only after verification and redemption have succeeded.
	// In dev mode, supplied tickets are untrusted and cannot select observer mode.
	access := "control"
	if b.ticketPub != nil && ticket != nil && ticket.Claims.V == 2 {
		access = ticket.Claims.Access
	}
	sess := &Session{
		Id: sessionID, Requester: requester, Target: agent,
		TechnicianID: b.technicianOf(ticket), Access: access,
	}

	b.mu.Lock()
	// Atomically check single-session admission and add the session in one critical section.
	// We hold b.mu across both the check and the insert so two concurrent connect_requests
	// cannot both see 0 existing sessions and both proceed.
	if multiCap := agent.MultiSessionCapable; multiCap == nil || !*multiCap {
		if existing := len(b.deviceSessions[agent.DeviceId]); existing > 0 {
			b.mu.Unlock()
			_ = requester.Send(Rejected{
				Reason: "agent busy: single-session agent already has an active session; " +
					"upgrade the agent to connect multiple technicians simultaneously",
			})
			return nil, fmt.Errorf("connect_request: device %s is single-session and "+
				"already has %d active session(s)", target, existing)
		}
	}
	b.sessions[sessionID] = sess
	if b.deviceSessions[agent.DeviceId] == nil {
		b.deviceSessions[agent.DeviceId] = make(map[string]*Session)
	}
	b.deviceSessions[agent.DeviceId][sessionID] = sess
	b.mu.Unlock()

	// ICE servers FIRST, before `brokered`. The ordering is load-bearing, not stylistic: both
	// clients construct their RTCPeerConnection the moment they see `brokered`, and ICE servers
	// cannot be added to a live peer connection without renegotiation — so a list arriving even a
	// millisecond later is silently useless and the session quietly loses its relayed path. A
	// WebSocket delivers in order per connection, which turns "send it first" into a guarantee
	// rather than a race. (See the doc comment on the Rust `ServerToClient::IceServers`.)
	//
	// Send failures are ignored deliberately, exactly like the relay assignment below: ICE servers
	// are an OPTIMISATION over host candidates. A peer that never receives them still connects on
	// the LAN, and failing the whole broker because an optional message could not be written would
	// turn a degraded path into no path at all. If the peer is genuinely gone, the `brokered` send
	// immediately below reports it.
	withTurn := b.turn.Enabled() && b.turnAdmit(ticket)
	ice := IceServers{
		Session: sessionID,
		Servers: b.iceServersForSession(sessionID, withTurn),
	}
	_ = agent.Send(ice)
	if b.turn.Enabled() && !withTurn {
		// Tell the requester explicitly instead of silently degrading (optional field; older
		// viewers ignore it).
		ice.RelayNotice = turnRelayNotice
		log.Printf("turn: %s over its outstanding-credential cap; session %s brokers without relay", clipForLog(b.technicianOf(ticket)), sessionID)
	}
	_ = requester.Send(ice)

	// Tell each side about the other, pinning the peer's pubkey. Both also learn the CONTROL-PLANE
	// session id: the agent needs it to bind a session policy, and the requester supplied the ticket
	// it came from, so telling it back discloses nothing it did not already hold.
	cpSession := b.controlPlaneSessionOf(ticket)
	technician := b.technicianOf(ticket)
	if err := agent.Send(Brokered{
		Session:             sessionID,
		PeerDevice:          requester.DeviceId,
		PeerPubkey:          requester.Pubkey,
		ControlPlaneSession: cpSession,
		TechnicianID:        technician,
		Access:              sess.Access,
		AccessVersion:       1,
	}); err != nil {
		b.dropSession(sessionID)
		_ = requester.Send(Rejected{Reason: "peer became unreachable"})
		return nil, fmt.Errorf("connect_request: notify agent: %w", err)
	}
	if err := requester.Send(Brokered{
		Session:             sessionID,
		PeerDevice:          agent.DeviceId,
		PeerPubkey:          agent.Pubkey,
		ControlPlaneSession: cpSession,
		TechnicianID:        technician,
		Access:              sess.Access,
		AccessVersion:       1,
	}); err != nil {
		b.dropSession(sessionID)
		return nil, fmt.Errorf("connect_request: notify requester: %w", err)
	}

	// Choose and hand out a relay (the guaranteed fallback). Both peers present the same
	// token to the same relay node, which pairs their half-connections.
	token, err := newUUID()
	if err != nil {
		return sess, fmt.Errorf("connect_request: allocate relay token: %w", err)
	}
	assignment := RelayAssignment{Session: sessionID, RelayAddr: b.relayAddr, Token: token}
	_ = agent.Send(assignment)
	_ = requester.Send(assignment)

	// Broadcast the updated participant list to all peers on this device (agent + all controllers).
	// This tells the new controller how many other techs are already connected, tells the existing
	// controllers a new tech joined, and tells the agent it is now in a multi-tech session.
	// Failures are logged at debug but never fatal (participant lists are advisory).
	b.broadcastParticipants(agent)

	return sess, nil
}

// buildParticipantList returns the current SessionParticipants message for the given agent.
// Must be called with b.mu held.
func (b *Broker) buildParticipantList(agentDeviceId string) SessionParticipants {
	sp := SessionParticipants{
		DeviceID:     agentDeviceId,
		Participants: make([]SessionParticipantEntry, 0),
	}
	for _, s := range b.deviceSessions[agentDeviceId] {
		entry := SessionParticipantEntry{
			SessionID:    s.Id,
			TechnicianID: s.TechnicianID,
			Access:       s.Access,
		}
		sp.Participants = append(sp.Participants, entry)
	}
	return sp
}

// broadcastParticipants sends a SessionParticipants update to the agent and all its controllers.
// Must be called WITHOUT b.mu held (it acquires the lock to build the list).
func (b *Broker) broadcastParticipants(agent *Peer) {
	b.mu.Lock()
	sp := b.buildParticipantList(agent.DeviceId)
	// Collect current peers under the lock so we don't hold the lock during sends.
	recipients := make([]*Peer, 0, len(sp.Participants)+1)
	recipients = append(recipients, agent)
	for _, s := range b.deviceSessions[agent.DeviceId] {
		if s.Requester != nil && s.Requester != agent {
			recipients = append(recipients, s.Requester)
		}
	}
	b.mu.Unlock()

	for _, p := range recipients {
		if err := p.Send(sp); err != nil {
			log.Printf("session_participants: failed to notify %q: %v", p.DeviceId, err)
		}
	}
}

// redeemTicket records the ticket's single use in the control plane's SHARED ledger and reports
// whether the broker must be refused.
//
// It returns an error ONLY for a definitive "already redeemed" answer. Every other outcome — no
// redeemer configured, timeout, connection refused, 401, 404, 5xx — returns nil and lets the broker
// proceed on the LOCAL verdict, loudly logged. That posture is the opposite of the device-identity
// resolver's fail-closed one; ticketredeem.go's header sets out why the two differ, and the short
// version is that this call de-duplicates an already-verified, tenant-bound, device-bound,
// ~2-minute credential, so refusing on a control-plane blip would turn a restart into a fleet-wide
// brokering outage — a worse and likelier event than the replay it defends against.
func (b *Broker) redeemTicket(ticket *SignedSessionTicket) error {
	if b.redeemer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ticketRedeemTimeout)
	defer cancel()

	err := b.redeemer.Redeem(ctx, ticket.Claims)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTicketAlreadyRedeemed):
		return err
	default:
		if b.ticketStrict {
			// Strict (fail-closed) mode: any ledger uncertainty refuses the broker. The operator
			// has chosen the security stance over the availability one. A control-plane restart or
			// rolling deploy will block new sessions until the ledger recovers. See
			// WithStrictTicketRedemption for the design trade-off.
			log.Printf("ERROR: session-ticket ledger unavailable (%q) — refusing session %q for device %q "+
				"(SIGNALING_STRICT_TICKET_REDEMPTION is set; unset it to allow brokering during ledger outages). "+
				"The ticket is locally spent and cannot be retried; the technician must obtain a new session ticket.",
				err, clipForLog(ticket.Claims.SessionID), ticket.Claims.DeviceID)
			return fmt.Errorf("session-ticket ledger unavailable: %w", err)
		}
		// Fail-open (default) mode: LOUD on purpose, and at WARNING rather than a debug line: while
		// this is happening, a captured ticket really can be replayed at another replica, and the
		// only symptom is that sessions keep working. Nothing else in the log would reveal it.
		log.Printf("WARNING: session-ticket ledger unavailable (%q) — brokering session %q for device %q "+
			"on this instance's local single-use check ALONE; a ticket replayed at another signaling "+
			"instance would not be detected while this persists",
			err, clipForLog(ticket.Claims.SessionID), ticket.Claims.DeviceID)
		return nil
	}
}

// RelayCandidate forwards a trickled candidate from `from` to the other peer of `session`.
// It returns an error if the session is unknown or `from` is not a member of it.
func (b *Broker) RelayCandidate(session string, from *Peer, cand Candidate) error {
	b.mu.Lock()
	sess, ok := b.sessions[session]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("candidate: unknown session %s", clipForLog(session))
	}
	dst := sess.peer(from)
	if dst == nil {
		return fmt.Errorf("candidate: sender is not a member of session %s", clipForLog(session))
	}
	return dst.Send(CandidateMsg{Session: session, Candidate: cand})
}

// RelaySdp forwards an SDP offer/answer from `from` to the other peer of `session`, opaquely
// (the server never parses the SDP). Returns an error if the session is unknown or `from` is not
// a member of it. Mirrors RelayCandidate.
func (b *Broker) RelaySdp(session string, from *Peer, sdp string, kind SdpKind) error {
	b.mu.Lock()
	sess, ok := b.sessions[session]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("sdp: unknown session %s", clipForLog(session))
	}
	dst := sess.peer(from)
	if dst == nil {
		return fmt.Errorf("sdp: sender is not a member of session %s", clipForLog(session))
	}
	return dst.Send(SdpMsg{Session: session, Sdp: sdp, Kind: kind})
}

// dropSession removes a session (e.g. after a peer proved unreachable mid-broker).
// It also cleans up deviceSessions and notifies remaining participants.
func (b *Broker) dropSession(id string) {
	b.mu.Lock()
	sess, had := b.sessions[id]
	delete(b.sessions, id)
	if had && sess != nil && sess.Target != nil {
		delete(b.deviceSessions[sess.Target.DeviceId], id)
		if len(b.deviceSessions[sess.Target.DeviceId]) == 0 {
			delete(b.deviceSessions, sess.Target.DeviceId)
		}
	}
	var agent *Peer
	if had && sess != nil {
		agent = sess.Target
	}
	b.mu.Unlock()
	if agent != nil {
		b.broadcastParticipants(agent)
	}
}

// RemovePeerSessions tears down every session the given peer participates in. Called when a
// connection drops so the session table does not leak. Sends SessionParticipants updates to
// any remaining participants on the same devices.
func (b *Broker) RemovePeerSessions(p *Peer) {
	if p == nil {
		return
	}
	// Collect affected agents BEFORE the lock so we can notify after.
	b.mu.Lock()
	var affectedAgents []*Peer
	for id, s := range b.sessions {
		if s.Requester == p || s.Target == p {
			delete(b.sessions, id)
			if s.Target != nil {
				delete(b.deviceSessions[s.Target.DeviceId], id)
				if len(b.deviceSessions[s.Target.DeviceId]) == 0 {
					delete(b.deviceSessions, s.Target.DeviceId)
				}
				// Collect the agent to notify remaining participants (but only if agent itself isn't gone).
				if s.Target != p {
					affectedAgents = append(affectedAgents, s.Target)
				}
			}
		}
	}
	b.mu.Unlock()
	for _, agent := range affectedAgents {
		b.broadcastParticipants(agent)
	}
}

// controlPlaneSessionOf returns the control-plane session id to advertise on `brokered`, or "" for
// "this server cannot vouch for one".
//
// It reports a value ONLY when ticket verification is switched on (b.ticketPub != nil), because that
// is the only case in which the id has been proven: verifyTicket has checked the control plane's
// signature over the claims, the device binding, the expiry, and a non-empty session id, and the
// caller has burned the ticket single-use. With `-insecure-no-ticket-verification` the ticket is
// usually nil and, when present, is entirely unverified attacker input — advertising it would let a
// caller NAME the session an agent binds its policy to, which is the opposite of the point.
//
// Empty is the fail-closed answer: the agent reads a missing id as "unknown" and rejects every
// session policy rather than accepting one it cannot bind.
func (b *Broker) controlPlaneSessionOf(ticket *SignedSessionTicket) string {
	if b.ticketPub == nil || ticket == nil {
		return ""
	}
	return ticket.Claims.SessionID
}

// technicianOf returns the technician id to advertise on `brokered`, or "" for "this server cannot
// vouch for one". Identical gate to controlPlaneSessionOf, and for a sharper reason: this value ends
// up inside the HASHED preimage of every audit event the agent seals, and it is the identity the
// control plane compares against the authenticated forwarder. An unverified ticket's claim is
// attacker-chosen, so advertising it would let a caller name SOMEBODY ELSE as the technician on a
// machine — the forgery POST /audit/ingest's 403 exists to prevent, moved one hop upstream where the
// 403 could not see it (the forwarder would be the real caller, and the event would name the victim).
//
// Empty is fail-closed twice over: the agent chains with a nil technician, and the control plane then
// REFUSES the batch rather than storing an unattributed record. A session with no verified ticket
// keeps its local trail (helper log + the recording's sidecar) and ships nothing centrally.
func (b *Broker) technicianOf(ticket *SignedSessionTicket) string {
	if b.ticketPub == nil || ticket == nil {
		return ""
	}
	return ticket.Claims.TechnicianID
}

// newUUID returns a random RFC 4122 v4 UUID string, matching the format the Rust
// DeviceId/SessionId/RelayToken newtypes serialize to. Uses crypto/rand to avoid an external
// dependency.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
