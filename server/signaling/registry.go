package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// peerConn is the subset of *gorilla/websocket.Conn the server needs to push messages to a
// peer. Narrowing to an interface keeps the registry and broker unit-testable without a real
// socket.
type peerConn interface {
	WriteJSON(v interface{}) error
	// SetWriteDeadline bounds how long a single write may block. It is part of this interface
	// because the deadline is a property of SENDING, and Send is the only place that knows a write
	// is about to happen — see the comment on Send.
	SetWriteDeadline(t time.Time) error
	// WriteMessage sends a raw WebSocket frame. Used to deliver a close frame (opcode 8) to a
	// superseded connection before tearing it down, so the remote sees code 1000 rather than 1006.
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// peerWriteTimeout bounds a single write to a peer. Every message this server sends is small JSON
// (the largest is a session/relay assignment), so a peer that cannot accept one within this window
// is not slow, it is not reading.
const peerWriteTimeout = 10 * time.Second

// Peer is a live signaling connection plus the pinned identity announced at registration.
// A controller that only issues connect_requests is also represented as a Peer, but is not
// necessarily entered into the registry (only registered agents are looked up by DeviceId).
type Peer struct {
	DeviceId string
	Pubkey   string
	// Tenant is the control-plane tenant the agent declared at register_agent (optional on the
	// wire). When non-empty, ConnectRequest requires a session ticket's tenant claim to match it,
	// so a ticket minted in another tenant can never be brokered to this agent (ticket.go).
	Tenant   string
	Nat      NatType
	LastSeen time.Time
	// OS is the agent-asserted OS description from register_agent, already bounded by
	// boundOSDescription. Inventory carried for the presence feed; nothing in the broker or the
	// auth path reads it.
	OS string
	// RequireSessionPolicy is the agent-asserted floor flag from register_agent, carried for the
	// presence feed on the same terms as OS. Nil means this peer asserted nothing (a controller, a
	// dev peer, or an older agent) and the control plane must leave the stored value alone.
	RequireSessionPolicy *bool
	// GrantKeyPinned is the agent-asserted "I have a pinned grant issuer key" posture (audit #9), derived
	// from register_agent.features: nil when the agent does not report posture (older build / controller),
	// otherwise whether signed session policy, leases and grants are actually verifiable on that machine.
	GrantKeyPinned *bool
	// SessionPolicyRequired is the agent-asserted "require_session_policy is on" posture, same derivation and
	// nil semantics as GrantKeyPinned. A pinned key alone does not make policy mandatory.
	SessionPolicyRequired *bool
	// AgentVersion is the agent-asserted build identity from register_agent, already bounded by
	// boundAgentVersion. Inventory carried for the presence feed on the same terms as OS; nothing
	// in the broker or the auth path reads it, and nothing may start.
	AgentVersion string
	// LoggedInUser is the interactive Windows session user announced at register_agent, already
	// bounded by boundLoggedInUser (e.g. "CORP\alice"). Inventory for the presence feed on
	// the same terms as OS — display-only, never read by the broker or the auth path.
	LoggedInUser string
	// MultiSessionCapable mirrors the register_agent field: true when the agent declared it can
	// handle concurrent sessions targeting the same device. Nil when the agent did not declare a
	// value (older agents). Re-emitted in the presence feed; never read by the broker or auth path.
	MultiSessionCapable *bool

	conn    peerConn
	writeMu sync.Mutex // gorilla/websocket forbids concurrent writers

	// sessionEndedStale: this peer qualified for session_ended_v1 (authenticated, tenanted) but its
	// Registered left it out, because the capability probe had not confirmed it yet. Agents learn
	// features only from their first Registered, so when the probe flips to supported such a peer
	// is reconnected (sessionended.go) to learn it. Written at registration, read by the bounce.
	sessionEndedStale atomic.Bool

	// M3 registration state (agentauth.go). These belong to the connection's own read goroutine —
	// dispatch is the only writer and it runs serially per socket — so they need no lock.
	//
	// pendingAuth is the outstanding agent-auth challenge, registered records that this connection
	// completed registration, and registerAttempts caps challenge minting per socket.
	pendingAuth      *pendingAuth
	registered       bool
	registerAttempts int

	// A rolling window prevents a minute boundary from admitting two bursts. Like registration
	// state, this bounded history belongs exclusively to the connection's read goroutine.
	guestEndTimes []time.Time
	// featuresTold is the bitmask of optional features this peer's Registered advertised (sessionended.go).
	featuresTold atomic.Uint32

	// admission is the pre-auth lifecycle handle owned by handleWS (websocket_limits.go). Nil on
	// peers built by tests that bypass handleWS: dispatch only calls Promote through nil-guarded
	// helpers so those tests keep working.
	admission *admissionLease

	// clientIP is the effective source IP used for per-source quota accounting (source_quota.go).
	// Empty for peers built by tests that bypass handleWS; release is a no-op on "".
	clientIP string
	// holdsPendingQuota / holdsAuthQuota record which per-source counter this peer currently
	// occupies, so each is released exactly once (handleWS cleanup, or markAuthenticated).
	holdsPendingQuota atomic.Bool
	holdsAuthQuota    atomic.Bool

	// logLimiter caps per-connection diagnostic log output (conn_log_limiter.go, docs/25 F19).
	// Nil for test peers that bypass handleWS; logf is a no-op on a nil receiver.
	logLimiter *connLogLimiter

	// restricted marks a RETIRED machine's connection (docs/65 D-C1): it lives only in the
	// registry's separate restricted map, is never brokerable or present, and may only receive
	// directives and send directive_ack. directiveV1 records that the agent advertised the
	// "directive_v1" feature at register_agent. Both are written once at registration, BEFORE the
	// peer is published to the registry, and are read-only afterwards (the registry lock orders the
	// publication), so they need no lock of their own.
	restricted  bool
	directiveV1 bool

	// directiveStale is sessionEndedStale's twin: the agent advertised directive_v1 and this
	// connection qualified, but Registered left the feature out because the capability probe had not
	// confirmed it yet; a later flip reconnects the peer so it learns it.
	directiveStale atomic.Bool

	// directiveSent holds the directive ids already relayed on THIS connection, so a directive is
	// never sent (or reported delivered) twice per connection. Touched from relay goroutines.
	directiveMu   sync.Mutex
	directiveSent map[string]struct{}

	// directiveAckTimes is the rolling window for directive_ack, owned by the read goroutine.
	directiveAckTimes []time.Time

	// directiveAcks is this connection's bounded, ORDER-PRESERVING queue of acknowledgements waiting to be
	// forwarded to the control plane, drained by ONE worker goroutine (started lazily by the read goroutine,
	// stopped when cleanup closes the queue). Independent goroutines per ack could reach the control plane
	// out of order, and an out-of-order ack is a conflict the agent is told is terminal.
	directiveAcks    chan DirectiveAck
	directiveAckOnce sync.Once

	// authSeq is the registry's sequence number taken immediately BEFORE this connection's control-plane
	// identity lookup (0 = none, dev mode / tests). Publication is refused when a newer lookup for the same
	// device has already published: an older, slower answer must never overwrite a newer one.
	authSeq uint64
}

// Send pushes a server message to the peer, tagging it with the correct discriminant.
//
// The write deadline is set HERE rather than once in handleWS, because a write deadline is consumed
// by the write it bounds: it must be re-armed per message, and Send is the only choke point every
// message passes through.
//
// Why it is needed at all, given handleWS already sets a READ limit and read deadline: those are
// only consulted inside ReadMessage. A goroutine blocked in WriteJSON is not in ReadMessage, so the
// read deadline can never fire for it, handleWS never returns, and its `defer s.cleanup` — the only
// thing that closes the socket and evicts the registry entry — never runs. gorilla's Upgrade()
// explicitly clears any deadline the HTTP server had set, and WriteJSON has no timeout of its own,
// so without this a peer that stops draining its receive buffer parks the writing goroutine
// indefinitely.
//
// That matters in two directions. A peer can wedge ITSELF pre-auth (pipeline malformed frames, never
// read the rejections). Worse, relaying crosses goroutines — broker.go writes to the PEER's socket
// from the SENDER's read goroutine — so one controller that stops reading can wedge the goroutine
// serving an AGENT, which then stops processing heartbeats and goes stale. `writeMu` is held across
// the write, so every later sender to that peer queues behind it too.
//
// A failed write returns an error to the caller and leaves the connection to be torn down by the
// read loop, which is the existing contract for a dead peer.
func (p *Peer) Send(payload any) error {
	tag, ok := serverTag(payload)
	if !ok {
		return fmt.Errorf("cannot send unknown server payload type %T", payload)
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	// A deadline this cannot set (a fake in tests, an odd transport) must not stop the send: the
	// bound is defence in depth, not a correctness precondition.
	_ = p.conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout))
	return p.conn.WriteJSON(ServerToClient{Type: tag, Payload: payload})
}

// Registry is the in-memory PeerMap: DeviceId -> Peer, guarded by a mutex. Freshness is
// derived from LastSeen and a TTL, so a peer whose heartbeats lapsed is treated as offline.
type Registry struct {
	mu    sync.RWMutex
	peers map[string]*Peer
	// restricted holds RETIRED machines' connections (docs/65 D-C1), device id -> peer. It is a
	// separate map on purpose: Lookup, Heartbeat, Snapshot (presence) and the broker read only
	// `peers`, so nothing in it can ever be brokered to or reported online. Same lock as `peers`.
	restricted map[string]*Peer
	// lastAuth is, per device, the highest authSeq that has been published (normal or restricted).
	lastAuth map[string]uint64
	authSeq  atomic.Uint64
	ttl      time.Duration
	now      func() time.Time // injectable clock for deterministic expiry tests
	// help is the per-DEVICE help message budget and in-flight cap (helprequest.go). It lives here, not on
	// the Peer, so it survives a reconnect: a device that drops its socket does not get a fresh budget.
	help *helpGate
}

// NewRegistry builds an empty registry. ttl is the heartbeat freshness window: a peer not
// seen within ttl is considered expired by Lookup.
func NewRegistry(ttl time.Duration) *Registry {
	return &Registry{
		peers:      make(map[string]*Peer),
		restricted: make(map[string]*Peer),
		lastAuth:   make(map[string]uint64),
		ttl:        ttl,
		now:        time.Now,
		help:       newHelpGate(),
	}
}

// Register inserts (or replaces) an agent keyed by its DeviceId, stamping it fresh. The same
// *Peer that owns the live connection is stored (so its write mutex is shared with every code
// path that sends to it — never a second Peer over the same socket). If a different peer was
// already registered under this DeviceId, its stale connection is closed after publishing the replacement (last
// registration wins — a reconnecting agent supersedes a dead socket).
//
// That incumbent-closing branch is why this must never be reached on an unauthenticated path. In
// enforced mode (M3) the ONLY caller is handleAgentAuthResponse's valid-proof edge, so displacing
// an agent requires a signature from the key the control plane pinned for that device id; a
// connection that merely claims the device id is never entered here.
func (r *Registry) Register(p *Peer) *Peer {
	r.mu.Lock()
	if r.staleAuthLocked(p) {
		r.mu.Unlock()
		return nil
	}
	old := r.peers[p.DeviceId]
	// A normal registration supersedes a restricted one for the same device (the machine is active
	// again): the restricted entry is dropped and its connection closed like any superseded socket.
	oldRestricted := r.restricted[p.DeviceId]
	delete(r.restricted, p.DeviceId)
	p.LastSeen = r.now()
	r.peers[p.DeviceId] = p
	r.mu.Unlock()
	// Socket writes and the peer write lock must never stall the shared registry.
	// Remove's connection identity check protects the newly published replacement.
	if old != nil && old != p && old.conn != nil && old.conn != p.conn {
		closePeer(old, "superseded by re-registration")
	}
	if oldRestricted != nil && oldRestricted != p && oldRestricted.conn != nil && oldRestricted.conn != p.conn {
		closePeer(oldRestricted, "superseded by re-registration")
	}
	return p
}

// NextAuthSeq returns the next sequence number for a control-plane identity lookup. It is taken
// immediately BEFORE the lookup, so a larger number means the answer reflects at least as fresh a view.
func (r *Registry) NextAuthSeq() uint64 { return r.authSeq.Add(1) }

// staleAuthLocked reports whether p's lookup is OLDER than one already published for the same device, and
// otherwise records it as the newest. Caller holds r.mu. A peer without a sequence (dev mode, tests) is
// never stale.
func (r *Registry) staleAuthLocked(p *Peer) bool {
	if p.authSeq == 0 {
		return false
	}
	if p.authSeq < r.lastAuth[p.DeviceId] {
		return true
	}
	r.lastAuth[p.DeviceId] = p.authSeq
	return false
}

// RegisterRestricted publishes a retired machine's connection. It lives in the restricted map ONLY, so it
// is never found by Lookup/the broker and never appears in presence. Because the control plane has just
// said the machine is RETIRED, a normal incumbent for the same device is no longer vouched for: it is
// removed from `peers` in the SAME critical section (presence and the broker stop seeing it at once, not at
// the next revalidation tick) and its socket is closed outside the lock. A previous restricted connection
// is superseded. It returns false (publishing nothing) when a newer identity lookup for the device has
// already published - an older answer must not overwrite a newer one.
func (r *Registry) RegisterRestricted(p *Peer) bool {
	r.mu.Lock()
	if r.staleAuthLocked(p) {
		r.mu.Unlock()
		return false
	}
	old := r.restricted[p.DeviceId]
	oldNormal := r.peers[p.DeviceId]
	delete(r.peers, p.DeviceId)
	p.LastSeen = r.now()
	r.restricted[p.DeviceId] = p
	r.mu.Unlock()
	if old != nil && old != p && old.conn != nil && old.conn != p.conn {
		closePeer(old, "superseded by re-registration")
	}
	if oldNormal != nil && oldNormal != p && oldNormal.conn != nil && oldNormal.conn != p.conn {
		closePeer(oldNormal, "machine retired")
	}
	return true
}

// directivePeers returns the connections that may be sent directives for a device: its fresh normal
// peer and its restricted peer, when present. Read-only (no lazy eviction).
func (r *Registry) directivePeers(device string) []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Peer
	if p, ok := r.peers[device]; ok && !r.expired(p) {
		out = append(out, p)
	}
	if p, ok := r.restricted[device]; ok {
		out = append(out, p)
	}
	return out
}

// directiveStalePeers snapshots the peers (normal or restricted) that advertised directive_v1 but
// were not told the feature (see Server.registeredMsg).
func (r *Registry) directiveStalePeers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Peer
	for _, p := range r.peers {
		if p.directiveStale.Load() {
			out = append(out, p)
		}
	}
	for _, p := range r.restricted {
		if p.directiveStale.Load() {
			out = append(out, p)
		}
	}
	return out
}

// closePeer sends a normal-closure frame (so the remote sees 1000, not 1006) and closes the socket.
// The connection's read loop then runs the usual cleanup. Never call it holding the registry lock.
func closePeer(p *Peer, reason string) {
	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason)
	p.writeMu.Lock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout))
	_ = p.conn.WriteMessage(websocket.CloseMessage, closeMsg)
	p.writeMu.Unlock()
	_ = p.conn.Close()
}

// sessionEndedStalePeers snapshots the registered peers whose Registered left out session_ended_v1
// although they qualified for it (see Server.registeredMsg).
func (r *Registry) sessionEndedStalePeers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Peer
	for _, p := range r.peers {
		if p.bounceWorthwhile() {
			out = append(out, p)
		}
	}
	return out
}

// isCurrent reports whether p is still the entry registered under its device id (no expiry check).
func (r *Registry) isCurrent(p *Peer) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[p.DeviceId] == p || r.restricted[p.DeviceId] == p
}

// Heartbeat refreshes a registered peer's LastSeen. Returns false if the device is unknown.
func (r *Registry) Heartbeat(device string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[device]
	if !ok {
		return false
	}
	p.LastSeen = r.now()
	return true
}

// Lookup returns a peer by DeviceId only if it is registered and still fresh. An expired peer
// (heartbeats lapsed beyond ttl) is reported as absent and lazily evicted.
func (r *Registry) Lookup(device string) (*Peer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[device]
	if !ok {
		return nil, false
	}
	if r.expired(p) {
		delete(r.peers, device)
		return nil, false
	}
	return p, true
}

// Remove evicts a peer. It only removes the entry if it still refers to the given connection,
// so a race where a reconnect replaced the entry does not evict the fresh peer. Pass nil conn
// to force removal regardless.
func (r *Registry) Remove(device string, conn peerConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.peers[device]; ok && (conn == nil || p.conn == conn) {
		delete(r.peers, device)
	}
	if p, ok := r.restricted[device]; ok && (conn == nil || p.conn == conn) {
		delete(r.restricted, device)
	}
}

// Len reports the number of currently-registered peers (fresh or not).
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// expired reports whether the peer's last heartbeat is older than the TTL. Caller holds the
// lock. A non-positive TTL disables expiry.
func (r *Registry) expired(p *Peer) bool {
	if r.ttl <= 0 {
		return false
	}
	return r.now().Sub(p.LastSeen) > r.ttl
}

// deviceLocks hands out one mutex per device id, created on demand and DELETED when the last holder or
// waiter leaves, so the map is bounded by the number of devices currently authenticating. The zero value is
// ready to use.
type deviceLocks struct {
	mu sync.Mutex
	m  map[string]*deviceLock
}

type deviceLock struct {
	ch   chan struct{} // capacity 1: a token held = locked
	refs int           // holders + waiters, guarded by deviceLocks.mu
}

// acquire takes the device's lock, waiting at most wait. The returned release is idempotent. ok is false
// (nothing held) when the wait timed out.
func (d *deviceLocks) acquire(device string, wait time.Duration) (release func(), ok bool) {
	d.mu.Lock()
	if d.m == nil {
		d.m = make(map[string]*deviceLock)
	}
	l := d.m[device]
	if l == nil {
		l = &deviceLock{ch: make(chan struct{}, 1)}
		d.m[device] = l
	}
	l.refs++
	d.mu.Unlock()

	leave := func() {
		d.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(d.m, device)
		}
		d.mu.Unlock()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case l.ch <- struct{}{}:
	case <-timer.C:
		leave()
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-l.ch
			leave()
		})
	}, true
}

// size is the number of devices with a live lock entry (tests).
func (d *deviceLocks) size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.m)
}
