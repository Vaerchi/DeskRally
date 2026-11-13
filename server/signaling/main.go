package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Server is the signaling control plane: an HTTP endpoint that upgrades connections to
// WebSocket, a registry of live agents, and a broker that pairs peers into sessions.
type Server struct {
	// authLocks serializes each device's identity lookup THROUGH its publication (see deviceAuthLock).
	authLocks deviceLocks

	reg      *Registry
	broker   *Broker
	upgrader websocket.Upgrader

	// identity, when non-nil, makes register_agent REQUIRE proof of possession of the enrolled
	// agent key (agentauth.go) — the M3 authentication gate. Nil = dev mode
	// (-insecure-no-agent-auth): registration is admitted on assertion alone and no control plane
	// is contacted. now is the challenge-expiry clock, swappable in tests.
	identity IdentityResolver
	// Configured before serving, using the same endpoint and credential as ticket redemption.
	guestEnd *GuestEndReporter
	// bounceDelay overrides the random per-peer reconnect delay of the session_ended_v1 bounce
	// (sessionended.go). Nil in production; tests set it.
	bounceDelay func() time.Duration
	// directiveThrottle and directiveNotifyWindow coalesce control-plane "directive pending"
	// notifications per device (directives.go). The window defaults to 2 s; tests override it.
	directiveThrottle     directiveThrottle
	directiveNotifyWindow time.Duration
	// revalidateLookupTimeout overrides revalidateLookupTimeout (revalidate.go) when positive; tests only.
	revalidateLookupTimeout time.Duration
	now                     func() time.Time

	// readTimeout bounds how long a connection may stay silent before it is reaped, derived from
	// the heartbeat TTL in NewServer so a correctly heartbeating agent is never cut off.
	readTimeout time.Duration

	// admission bounds accepted and pending-unauthenticated WebSockets and owns the absolute
	// pre-auth lifetime timer (websocket_limits.go). Constructed with secure defaults by
	// NewServer; main() may replace the limits via SetAdmissionLimits before ListenAndServe.
	admission *admissionState

	// originPolicy governs which browser Origins may connect (origin_policy.go, docs/25 F09).
	// Defaults to warn-only (all Origins permitted) in NewServer; main() replaces it via
	// SetOriginPolicy from SIGNALING_ALLOWED_ORIGINS before ListenAndServe.
	originPolicy *originPolicy

	// sourceQuota limits per-source-IP concurrent connections (source_quota.go, docs/25 F09).
	// Defaults to disabled (maxPerIP=0) in NewServer; main() replaces it via SetSourceQuota
	// from SIGNALING_MAX_CONNECTIONS_PER_IP before ListenAndServe.
	sourceQuota *sourceQuota

	// connRate is the per-source new-connection rate limit (source_rate.go, audit #6). Disabled
	// by default in NewServer; main() enables it from SIGNALING_MAX_CONNECTS_PER_SECOND_PER_IP.
	connRate *sourceRateLimiter

	// authQuota is the per-source ceiling on AUTHENTICATED (long-lived) sockets. sourceQuota above
	// counts only UNAUTHENTICATED/pending sockets: a peer's slot there is released when it
	// authenticates (markAuthenticated), so an office with hundreds of agents behind one NAT is
	// never locked out by an anonymous-flood limit. This one is only a large backstop.
	authQuota *sourceQuota

	// trustedProxyNets, when non-empty, gates X-Forwarded-For trust for source-IP resolution:
	// only requests whose TCP peer falls in one of these networks honour XFF. Set by main()
	// from SIGNALING_TRUSTED_PROXIES before ListenAndServe; not protected by a mutex because,
	// like originPolicy, it is replaced only before the listener is armed.
	trustedProxyNets []*net.IPNet

	// msgRateLimit is the per-connection message-rate ceiling in messages/second (docs/25 F09).
	// 0 = disabled (unlimited). Defaults to 0 in NewServer; main() sets it from
	// SIGNALING_MAX_MESSAGES_PER_SECOND before ListenAndServe. Each handleWS creates a
	// connRateLimiter (msg_rate.go) seeded from this value; no mutex needed because the field
	// is read-only after ListenAndServe arms the listener.
	msgRateLimit int
}

// maxSignalingMessageBytes caps a single inbound WebSocket frame. Every legitimate message is small
// JSON — the largest, register_agent, carries a hex pubkey, a tenant id, and an OS string already
// bounded to maxOSDescriptionBytes — so 64 KiB is orders of magnitude of headroom. The point is that
// the cap exists BEFORE authentication: the upgrade completes before register_agent, so without it
// an anonymous peer can make the server buffer an arbitrarily large frame.
const maxSignalingMessageBytes = 64 << 10

// minPeerReadTimeout floors the silence window regardless of a very short configured heartbeat TTL,
// so a slow network or a paused VM does not drop live agents.
const minPeerReadTimeout = 60 * time.Second

// NewServer wires a registry + broker with the given heartbeat TTL and relay address, and
// generates the server's Ed25519 identity (echoed to clients for pinning). ticketPub, when
// non-nil, is the control plane's grant-issuer public key that connect_request session tickets
// must verify against (M2); nil disables verification (dev mode). identity, when non-nil, is the
// control-plane device-identity resolver that register_agent proofs are checked against (M3); nil
// disables agent authentication (dev mode).
//
// The broker's shared session-ticket ledger (ticketredeem.go) is wired here from the environment
// rather than taken as an argument, because it introduces no configuration of its own — it reuses
// the device-identity URL and token.
func NewServer(heartbeatTTL time.Duration, relayAddr string, ticketPub ed25519.PublicKey, identity IdentityResolver) (*Server, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serverPubkey := "ed25519:" + hex.EncodeToString(pub)

	// The SHARED single-use ledger for session tickets (ticketredeem.go). Read from the environment
	// here rather than passed in, like turnConfigFromEnv above it, because it needs no new
	// configuration of its own: it reuses the device-identity endpoint and token.
	redeemer, err := ticketRedeemerFromEnv()
	if err != nil {
		return nil, err
	}
	// SIGNALING_STRICT_TICKET_REDEMPTION=1: any ledger error that is not a definitive replay
	// (HTTP 409) refuses the broker rather than warning and proceeding (see broker.go
	// WithStrictTicketRedemption for the full trade-off). Unset = fail-open (default).
	ticketStrict := envFlagOn("SIGNALING_STRICT_TICKET_REDEMPTION")
	if ticketPub != nil && redeemer == nil {
		// NOT fatal, and the asymmetry with the two log.Fatalf gates in main() is the point: those
		// guard checks that would otherwise not happen AT ALL, whereas single-use enforcement still
		// happens here — just per process. Refusing to start would trade a bounded replay window for
		// a signaling server that will not run.
		strictNote := ""
		if ticketStrict {
			strictNote = " NOTE: SIGNALING_STRICT_TICKET_REDEMPTION is set but has no effect without a configured ledger."
		}
		log.Printf("WARNING: SIGNALING_DEVICE_IDENTITY_URL/SIGNALING_DEVICE_IDENTITY_TOKEN are not set — "+
			"session tickets are single-use PER PROCESS only. A second signaling instance, or this one "+
			"after a restart, will honour a ticket this one has already spent, for the rest of its TTL. "+
			"Set SIGNALING_STRICT_TICKET_REDEMPTION=1 to refuse sessions when the ledger is unreachable.%s",
			strictNote)
	} else if ticketPub != nil && redeemer != nil && !ticketStrict {
		log.Printf("INFO: session-ticket ledger configured (fail-open mode). Set SIGNALING_STRICT_TICKET_REDEMPTION=1 " +
			"to refuse new sessions when the ledger is temporarily unreachable, closing the cross-instance replay window.")
	} else if ticketPub != nil && redeemer != nil && ticketStrict {
		log.Printf("INFO: session-ticket ledger configured (fail-CLOSED mode, SIGNALING_STRICT_TICKET_REDEMPTION). " +
			"New sessions will be refused when the ledger is unreachable.")
	}

	reg := NewRegistry(heartbeatTTL)
	// Two heartbeat intervals of slack, floored: an agent that misses one heartbeat is not dropped,
	// but a peer that has gone silent does not hold a goroutine and socket indefinitely.
	readTimeout := 2 * heartbeatTTL
	if readTimeout < minPeerReadTimeout {
		readTimeout = minPeerReadTimeout
	}
	broker := NewBroker(reg, serverPubkey, relayAddr, ticketPub).
		WithTurn(turnConfigFromEnv()).
		WithTurnLimits(envNonNegInt("SIGNALING_TURN_MAX_PER_USER", 0), envNonNegInt("SIGNALING_TURN_MAX_PER_TENANT", 0)).
		WithTicketRedeemer(redeemer)
	if ticketStrict {
		broker = broker.WithStrictTicketRedemption()
	}
	return &Server{
		reg:         reg,
		broker:      broker,
		readTimeout: readTimeout,
		upgrader: websocket.Upgrader{
			// Native agents and browser viewers share this endpoint. Origin allowlisting remains
			// a separate F09 policy change; this patch preserves the existing compatibility policy.
			CheckOrigin: func(*http.Request) bool { return true },
			// Bound writing the upgrade response. This does not cover HTTP headers read before
			// handleWS is entered; ingress HTTP/TCP admission is outside this WebSocket gate.
			HandshakeTimeout: upgradeHandshakeTimeout,
		},
		identity:         identity,
		now:              time.Now,
		admission:        newAdmissionState(),
		originPolicy:     &originPolicy{},   // warn-only default; replaced by SetOriginPolicy from main()
		sourceQuota:      newSourceQuota(0), // disabled default; replaced by SetSourceQuota from main()
		connRate:         newSourceRateLimiter(0, nil),
		authQuota:        newSourceQuota(0),
		trustedProxyNets: nil, // no XFF trust by default; replaced by SetTrustedProxyNets from main()
	}, nil
}

// SetAdmissionLimits replaces the WebSocket admission bounds installed by NewServer. Intended
// for main() (or a test setup) to apply operator-chosen flags BEFORE the listener is armed;
// a mid-run reconfigure would be safe against races but not against a client already inside
// the upgrader that has committed to the old limits.
func (s *Server) SetAdmissionLimits(l admissionLimits) error {
	return s.admission.configure(l)
}

// SetOriginPolicy replaces the Origin admission policy installed by NewServer with the one
// parsed from SIGNALING_ALLOWED_ORIGINS. Like SetAdmissionLimits, this must run before the
// listener is armed; concurrent handleWS reads of s.originPolicy are not protected by a mutex.
func (s *Server) SetOriginPolicy(p *originPolicy) {
	s.originPolicy = p
}

// SetSourceQuota replaces the per-source connection limit installed by NewServer. maxPerIP=0
// disables the quota (unlimited). Like the other Set* methods, this must run before
// ListenAndServe; concurrent handleWS reads of s.sourceQuota are not mutex-protected.
func (s *Server) SetSourceQuota(maxPerIP int) {
	s.sourceQuota = newSourceQuota(maxPerIP)
}

// envNonNegInt reads a non-negative integer env var, falling back to def when unset and exiting
// on a malformed value (a typo in a security knob must fail loudly, not silently disable it).
func envNonNegInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Fatalf("%s=%q is not a non-negative integer", name, raw)
	}
	return n
}

// SetAuthenticatedQuota sets the per-source ceiling on authenticated sockets (0 = unlimited).
func (s *Server) SetAuthenticatedQuota(maxPerIP int) {
	s.authQuota = newSourceQuota(maxPerIP)
}

// SetConnectRate enables the per-source new-connection rate limit (0 disables). Call before
// ListenAndServe.
func (s *Server) SetConnectRate(perSecond int) {
	s.connRate = newSourceRateLimiter(perSecond, s.now)
}

// SetTrustedProxyNets sets the CIDRs whose TCP peers may set X-Forwarded-For for client-IP
// resolution in source-quota accounting. Nil/empty means XFF is not trusted (RemoteAddr only).
// Like the other Set* methods, this must run before ListenAndServe.
func (s *Server) SetTrustedProxyNets(nets []*net.IPNet) {
	s.trustedProxyNets = nets
}

// SetMsgRateLimit sets the per-connection message-rate ceiling. maxPerSec=0 disables rate
// limiting (unlimited). Like the other Set* methods, call before ListenAndServe. Each new
// connection reads the value when its handleWS goroutine starts; mid-run changes are not
// picked up by connections that are already open.
func (s *Server) SetMsgRateLimit(maxPerSec int) {
	s.msgRateLimit = maxPerSec
}

// serverPubkey exposes the pinned server identity for the registered handshake reply.
func (s *Server) serverPubkey() string { return s.broker.serverPubkey }

// handleWS upgrades an HTTP request to a WebSocket and runs the per-connection message loop.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	arrivedAt := time.Now()
	// Reject browsers from Origins not in the allowlist. Native clients (Rust agent, CLI tools)
	// send no Origin header and always pass. This check runs before quota/admission so a policy-
	// blocked browser does not consume any slot.
	if !s.originPolicy.allow(r) {
		http.Error(w, "origin not permitted", http.StatusForbidden)
		return
	}
	// Per-source quota: resolve the effective client IP and check whether it has reached its
	// individual connection ceiling. Runs before admission.tryAcquire so an over-quota source
	// does not consume a server-wide slot. An empty clientIP (unparseable RemoteAddr, rare)
	// passes through without counting — logged so this bypass is visible in operator logs.
	clientIP := signalingClientIP(r, s.trustedProxyNets)
	if clientIP == "" {
		log.Printf("WARNING: per-source quota bypassed for connection with unparseable RemoteAddr %q", r.RemoteAddr)
	}
	// Connection-RATE limit per source, before admission and long before any control-plane lookup.
	if !s.connRate.allow(clientIP) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many connection attempts", http.StatusTooManyRequests)
		return
	}
	if !s.sourceQuota.tryAcquire(clientIP) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "per-source connection limit reached", http.StatusServiceUnavailable)
		return
	}
	// The HTTP handler already has a goroutine; reject before creating a hijacked WebSocket peer.
	// If this fails, release the per-source slot we just acquired above.
	// F09 pending-slot exhaustion: reserve an evictable lease before upgrading, after the
	// per-source check, so an over-quota source cannot evict another pending connection.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	lease := s.admission.acquireLease(cancel, arrivedAt, clientIP)
	if lease == nil {
		s.sourceQuota.release(clientIP)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "signaling admission at capacity", http.StatusServiceUnavailable)
		return
	}
	defer lease.Release()
	limits, _, _ := s.admission.snapshot()
	remaining := time.Until(arrivedAt.Add(limits.preAuthTimeout))
	if remaining <= 0 {
		s.sourceQuota.release(clientIP)
		http.Error(w, "authentication deadline expired", http.StatusRequestTimeout)
		return
	}
	// Do not allow the upgrade response to consume more than the remaining authentication window.
	// Copy the configuration rather than racing other handlers by mutating the shared upgrader.
	upgrader := s.upgrader
	if upgrader.HandshakeTimeout <= 0 || upgrader.HandshakeTimeout > remaining {
		upgrader.HandshakeTimeout = remaining
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// The slots were reserved before Upgrade; a failed handshake must release everything so a
		// probing client cannot exhaust the admission or per-source pool with malformed GETs.
		s.sourceQuota.release(clientIP)
		log.Printf("ws upgrade failed: %q", err)
		return
	}
	// The absolute deadline includes time spent upgrading after handler entry. Only successful
	// authentication (register_agent proof-of-possession, or a brokered connect_request) can
	// cancel it; chatty JSON, malformed frames, pongs, or repeated challenges cannot.
	if !lease.attach(conn) {
		s.sourceQuota.release(clientIP)
		return
	}
	// Every connection is a Peer immediately (a controller that only issues connect_requests
	// is never registered but still needs an addressable Send target). register_agent promotes
	// this peer into the registry. clientIP is stored so cleanup can release the per-source slot.
	// logLimiter caps diagnostic log volume for this connection (F19).
	self := &Peer{conn: conn, admission: lease, clientIP: clientIP, logLimiter: newConnLogLimiter(defaultConnLogLinesPerSecond, s.now)}
	self.holdsPendingQuota.Store(clientIP != "")
	defer s.cleanup(self)

	// Per-connection message-rate budget (docs/25 F09). A token-bucket seeded from the server's
	// configured ceiling; zero = disabled (unlimited). The limiter is NOT goroutine-safe — only
	// the read loop below calls allow(), and it runs in this single goroutine.
	rateLimiter := newConnRateLimiter(s.msgRateLimit, s.now)

	// Bound what an UNAUTHENTICATED peer can make this process allocate and hold.
	//
	// Anyone who can reach the listener can open a socket and start sending: the upgrade happens
	// before register_agent, so none of the auth machinery has run yet. Without a read limit,
	// ReadMessage buffers a whole frame in memory before returning, so a single connection could
	// announce and stream a multi-gigabyte message and the server would faithfully accumulate it —
	// with no capability, no ticket, and no identity. Every legitimate message here is small JSON
	// (the largest is register_agent with a pubkey, tenant, and OS string, all separately bounded).
	//
	// The deadline closes the other half: a peer that connects and then sends nothing costs a
	// goroutine and a socket forever. It is refreshed on every successful read and by pongs, so an
	// idle-but-live agent that is heartbeating is unaffected — only a silent one is reaped.
	conn.SetReadLimit(maxSignalingMessageBytes)
	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	})

	for {
		_, data, err := conn.ReadMessage()
		// Any successful read proves the peer is alive; extend the silence window.
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("read error from %q: %q", self.DeviceId, err)
			}
			return
		}
		// Message-rate budget: every received frame (valid or malformed) consumes one token.
		// A connection over its per-second ceiling gets a final Rejected before the socket is
		// closed. This runs before json.Unmarshal so even malformed frames count against the
		// budget — the cost of parsing is irrelevant; the cost of receiving is what matters.
		if !rateLimiter.allow() {
			_ = self.Send(Rejected{Reason: "message rate limit exceeded"})
			_ = self.conn.Close()
			return
		}
		var msg ClientToServer
		if err := json.Unmarshal(data, &msg); err != nil {
			_ = self.Send(Rejected{Reason: "malformed message: " + err.Error()})
			continue
		}
		// Help frames carry a <= 200 char note: anything past 1 KiB is refused before it is dispatched or
		// forwarded (docs/64 H-C2).
		if len(data) > maxHelpFrameBytes && isHelpMessage(msg) {
			_ = self.Send(HelpRequestResult{Op: msg.Type, Outcome: "refused"})
			continue
		}
		s.dispatch(self, msg)
	}
}

// dispatch routes one decoded client message.
func (s *Server) dispatch(self *Peer, msg ClientToServer) {
	// A RESTRICTED (retired) connection may only acknowledge directives; everything else is silently
	// IGNORED (docs/65 D-C1). It used to be answered with Rejected, but every agent (old and new)
	// ends its mux on Rejected and reconnects, so a retired machine's periodic heartbeat turned into
	// a reconnect loop every ~12 s (found in the 1.3.19 VM run). Ignoring keeps the connection open
	// for directive delivery and still grants nothing.
	if self.restricted {
		if ack, ok := msg.Payload.(*DirectiveAck); ok {
			s.handleDirectiveAck(self, ack)
		}
		return
	}
	switch p := msg.Payload.(type) {
	case *DirectiveAck:
		s.handleDirectiveAck(self, p)

	case *RegisterAgent:
		s.handleRegisterAgent(self, p)

	case *AgentAuthResponse:
		s.handleAgentAuthResponse(self, p)

	case *GuestEndedSession:
		s.handleGuestEndedSession(self, p)

	case *SessionEnded:
		s.handleSessionEnded(self, p)

	case *HelpRequest:
		s.handleHelpRequest(self, p)

	case *HelpCancel:
		s.handleHelpCancel(self, p)

	case *HelpStatus:
		s.handleHelpStatus(self, p)

	case *Heartbeat:
		// A peer that has not completed registration never refreshes a registry entry — otherwise
		// an unproven connection could keep a stale incumbent alive for a device it does not own.
		//
		// The device refreshed is the one THIS connection proved it owns (`self.DeviceId`, set by a
		// completed register_agent + Ed25519 challenge), never the one named in the message. The
		// body's `device` is attacker-chosen: honouring it let any registered agent keep ANY other
		// device's entry alive — which is exactly the "unproven connection keeps a stale incumbent
		// alive" case the check above was written to prevent, reached through the front door.
		// Freshness is what Lookup gates brokering on, so a lapsed agent that a stranger keeps warm
		// stays a valid broker target after it is gone.
		if !self.registered {
			_ = self.Send(Rejected{Reason: "heartbeat for unregistered device"})
			break
		}
		if p.Device != "" && p.Device != self.DeviceId {
			// Surfaced rather than silently ignored: a mismatch is either a client bug or an attempt.
			// p.Device is peer-sized (up to the read cap) and the limiter bounds lines, not their size.
			self.logLimiter.logf("heartbeat from %q named a different device %q", self.DeviceId, clipForLog(p.Device))
			_ = self.Send(Rejected{Reason: "heartbeat device does not match this connection"})
			break
		}
		if !s.reg.Heartbeat(self.DeviceId) {
			_ = self.Send(Rejected{Reason: "heartbeat for unregistered device"})
		}

	case *ConnectRequest:
		if _, err := s.broker.ConnectRequest(self, p.Target, p.Ticket); err != nil {
			self.logLimiter.logf("connect_request from %q: %q", self.DeviceId, err)
		} else {
			// A controller never issues register_agent; a successfully brokered connect_request
			// (which required a verified ticket in enforced mode) is what promotes it past the
			// pre-auth gate. A rejected ticket leaves the peer pending, so the absolute timer
			// still bounds it.
			s.markAuthenticated(self)
		}

	case *CandidateMsg:
		if err := s.broker.RelayCandidate(p.Session, self, p.Candidate); err != nil {
			self.logLimiter.logf("candidate relay: %q", err)
		}

	case *SdpMsg:
		if err := s.broker.RelaySdp(p.Session, self, p.Sdp, p.Kind); err != nil {
			self.logLimiter.logf("sdp relay: %q", err)
		}

	default:
		_ = self.Send(Rejected{Reason: "unsupported message type"})
	}
}

// handleRegisterAgent runs the register_agent edge of the M3 state machine.
//
// In enforced mode it only ISSUES a challenge: nothing about this connection is recorded in the
// registry, so an unproven registration cannot displace a healthy incumbent, and Broker can never
// resolve a connect_request to it. In dev mode (-insecure-no-agent-auth) it registers immediately,
// exactly as before M3.
//
// A register_agent on an already-registered connection is refused and otherwise ignored: the
// connection keeps its existing registration, so re-registering is not a way to re-open the auth
// window.
func (s *Server) handleRegisterAgent(self *Peer, p *RegisterAgent) {
	if len(p.Device) == 0 || len(p.Device) > 128 {
		_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
		_ = self.conn.Close()
		return
	}
	if self.registered {
		_ = self.Send(Rejected{Reason: "already registered"})
		return
	}
	self.registerAttempts++
	if self.registerAttempts > maxRegisterAttempts {
		log.Printf("closing connection: more than %d register_agent attempts (last device %q)",
			maxRegisterAttempts, p.Device)
		_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
		_ = self.conn.Close()
		return
	}

	if s.identity == nil {
		// Dev mode: the connection asserts its own device id, tenant and pubkey. `tenant`, when
		// supplied, is the tenant a session ticket must be minted in to reach this agent
		// (broker.go).
		self.DeviceId = p.Device
		self.Pubkey = p.Pubkey
		self.Tenant = p.Tenant
		self.Nat = p.Nat
		self.OS = boundOSDescription(p.OS)
		self.RequireSessionPolicy = p.RequireSessionPolicy
		self.AgentVersion = boundAgentVersion(p.AgentVersion)
		self.LoggedInUser = boundLoggedInUser(p.LoggedInUser)
		self.MultiSessionCapable = p.MultiSessionCapable
		self.directiveV1 = hasFeature(boundFeatures(p.Features), directiveFeature)
		self.GrantKeyPinned = grantKeyPinnedFrom(boundFeatures(p.Features))
		self.SessionPolicyRequired = sessionPolicyRequiredFrom(boundFeatures(p.Features))
		self.registered = true
		s.reg.Register(self)
		s.markAuthenticated(self)
		if err := self.Send(s.registeredMsg(self)); err != nil {
			log.Printf("failed to ack registration for %q: %q", p.Device, err)
		}
		return
	}

	pending, err := s.newPendingAuth(p)
	if err != nil {
		log.Printf("agent auth for %q: %q", p.Device, err)
		_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
		_ = self.conn.Close()
		return
	}
	// At most one outstanding challenge per connection: a second register_agent replaces the
	// pending one and kills the previous nonce.
	self.pendingAuth = pending
	if err := self.Send(pending.challenge()); err != nil {
		log.Printf("failed to send agent auth challenge for %q: %q", p.Device, err)
	}
}

// handleAgentAuthResponse verifies proof of possession and, only then, admits the registration.
// This is the ONLY path that reaches Registry.Register in enforced mode, so displacing an
// incumbent socket always requires a valid signature from the control-plane-pinned key.
//
// Every failure reports the SAME generic reason and closes the connection; the specific cause is
// logged server-side only. A challenge that is simply never answered is not a failure — the
// connection stays open and unregistered, which is what keeps controllers (who use the same
// register_agent message) working.
func (s *Server) handleAgentAuthResponse(self *Peer, p *AgentAuthResponse) {
	// Single-use: take and clear the challenge BEFORE verifying, whatever the outcome.
	pending := self.pendingAuth
	self.pendingAuth = nil

	// One identity lookup per device at a time, held from BEFORE the control-plane read until the answer is
	// PUBLISHED: lookups for a device therefore publish in the order their control-plane snapshots were
	// taken, and a slow older answer can never overwrite (evict) a newer one. Never held across devices, and
	// never the registry lock. The wait is bounded; on timeout the attempt fails like any other.
	unlock := func() {}
	if pending != nil {
		u, ok := s.authLocks.acquire(pending.Device, 2*deviceIdentityTimeout)
		if !ok {
			log.Printf("agent auth for device %q: another lookup for it did not finish in time", clipForLog(pending.Device))
			_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
			_ = self.conn.Close()
			return
		}
		unlock = u
	}
	defer unlock()

	identity, err := s.verifyAgentAuth(pending, p)
	if err != nil {
		log.Printf("agent auth rejected for device %q: %q", clipForLog(p.Device), err)
		_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
		_ = self.conn.Close()
		return
	}

	// The control plane is authoritative for tenant and pubkey; anything the client declared at
	// register_agent is discarded. Peer.Tenant is what the broker's cross-tenant ticket guard
	// compares against, so it must not be client-chosen.
	self.DeviceId = pending.Device
	self.Pubkey = identity.Pubkey
	self.Tenant = identity.TenantID
	self.Nat = pending.Nat
	// The os is the agent's own assertion, carried through from register_agent (already bounded).
	// Unlike tenant/pubkey there is no authoritative source to overwrite it with — the device that
	// just proved possession IS the authority on what OS it runs.
	self.OS = pending.OS
	// Same reasoning as os: the device that just proved possession IS the authority on whether its
	// own config floors its sessions. There is nothing more authoritative to overwrite it with.
	self.RequireSessionPolicy = pending.RequireSessionPolicy
	// And again the same reasoning for the build identity: the control plane has no authoritative
	// version to overwrite it with — the device that just proved possession is the only thing that
	// knows what binary it is running.
	self.AgentVersion = pending.AgentVersion
	self.LoggedInUser = pending.LoggedInUser
	self.MultiSessionCapable = pending.MultiSessionCapable
	self.directiveV1 = hasFeature(pending.Features, directiveFeature)
	self.GrantKeyPinned = grantKeyPinnedFrom(pending.Features)
	self.SessionPolicyRequired = sessionPolicyRequiredFrom(pending.Features)
	// A RETIRED machine (the control plane answered only because we sent restricted=1) gets the
	// restricted channel (docs/65 D-C1): entered ONLY in the restricted map, so it is never
	// brokerable, never present, and cannot displace a normal incumbent. Set before publication.
	self.restricted = identity.Status == identityStatusRetired
	self.registered = true
	self.authSeq = pending.resolveSeq
	var published bool
	if self.restricted {
		published = s.reg.RegisterRestricted(self)
	} else {
		published = s.reg.Register(self) != nil
	}
	if !published {
		// A newer identity lookup for this device published first: this answer is stale. Treat it like any
		// other failed authentication (the agent reconnects and is resolved afresh).
		self.registered = false
		log.Printf("agent auth for device %q: superseded by a newer identity lookup, rejecting", clipForLog(pending.Device))
		_ = self.Send(Rejected{Reason: agentAuthRejectionReason})
		_ = self.conn.Close()
		return
	}
	unlock() // published: the next lookup for this device may now read the control plane
	s.markAuthenticated(self)
	// The ONLY log line that reports an admitted authenticated registration. Failures were logged
	// from the start; without this a successful proof of possession left no trace, so an operator
	// could not distinguish "the fleet authenticates" from "no agent has connected at all" — and a
	// silent downgrade to dev mode would look identical in the log.
	log.Printf("agent auth OK: device %q registered with its control-plane-pinned key (tenant %q)",
		pending.Device, identity.TenantID)
	if self.restricted {
		log.Printf("agent auth: device %q registered in RESTRICTED mode (retired): directives only", pending.Device)
	}
	if err := self.Send(s.registeredMsg(self)); err != nil {
		log.Printf("failed to ack registration for %q: %q", pending.Device, err)
	}
	// Directives follow the Registered message, so the agent has learned the feature first.
	s.startDirectiveRelay(self)
}

// cleanup evicts a dropped connection from the registry and tears down its sessions.
func (s *Server) cleanup(self *Peer) {
	// Flush any suppressed log lines before tearing down. All dispatch calls for this
	// connection have completed at this point (the read loop has exited), so the full
	// suppressed count is final.
	self.logLimiter.flush(self.DeviceId)
	if self.DeviceId != "" {
		s.reg.Remove(self.DeviceId, self.conn)
	}
	// No more dispatch calls: let the ack worker drain what was already queued (in order) and exit.
	if self.directiveAcks != nil {
		close(self.directiveAcks)
	}
	s.broker.RemovePeerSessions(self)
	_ = self.conn.Close()
	// Retain admission through socket close and session cleanup. Release is idempotent even when
	// promotion or the pre-auth timer already ran.
	if self.admission != nil {
		self.admission.Release()
	}
	// Return the per-source slot. No-op when clientIP is "" (test peers that bypass handleWS)
	// or when the quota is disabled. Idempotent on underflow.
	if self.holdsPendingQuota.CompareAndSwap(true, false) {
		s.sourceQuota.release(self.clientIP)
	}
	if self.holdsAuthQuota.CompareAndSwap(true, false) {
		s.authQuota.release(self.clientIP)
	}
}

// markAuthenticated promotes a peer past the pre-auth admission gate. It is the ONLY caller
// that returns a pending slot to the pool. Guarded on self.admission because tests build peers
// without going through handleWS (see dispatch's callers in agentauth_test.go).
//
// Auth is defined narrowly on purpose. Only two things count: register_agent proof-of-possession
// (dev mode's assertion-only path is included because dev mode has no proof to demand), and a
// successfully brokered connect_request (which required a verified ticket in enforced mode). A
// merely-issued challenge, a malformed frame, a heartbeat attempt, or a rejected ticket must
// NOT flip this — otherwise the absolute pre-auth lifetime bound is defeated by the noisiest
// unauthenticated peer.
func (s *Server) markAuthenticated(self *Peer) {
	if self.admission != nil {
		self.admission.Promote()
	}
	// The peer proved itself: it stops counting against the per-source PENDING quota (an anonymous-
	// flood limit) and counts against the large authenticated backstop instead. Once only.
	if self.holdsPendingQuota.CompareAndSwap(true, false) {
		s.sourceQuota.release(self.clientIP)
		if !s.authQuota.tryAcquire(self.clientIP) {
			log.Printf("authenticated connection from %s refused: per-source authenticated ceiling reached", self.clientIP)
			_ = self.conn.Close()
			return
		}
		self.holdsAuthQuota.Store(true)
	}
}

// turnConfigFromEnv reads the ICE/TURN issuance policy handed to peers at broker time.
//
//	SIGNALING_STUN_URLS  comma-separated, e.g. "stun:stun.example:3478"
//	SIGNALING_TURN_URLS  comma-separated, e.g. "turn:turn.example:3478?transport=udp,turn:turn.example:3478?transport=tcp"
//	SIGNALING_TURN_SECRET  shared with coturn's `static-auth-secret` (use-auth-secret mode)
//	SIGNALING_TURN_TTL     credential lifetime, Go duration (default 2h; a credential is bound to its session id and cannot outlive a working session by much)
//
// Unset is a legal, common configuration: a LAN deployment needs no ICE servers at all, and peers
// connect on host candidates. Unlike SIGNALING_TICKET_PUBKEY this is NOT a startup error, because
// its absence removes an optimisation rather than an authorization check — nothing becomes
// reachable that was not already.
//
// A HALF configuration is different and is reported: URLs without a secret (or the reverse) would
// hand every peer an ICE server it will try, fail to authenticate against, and abandon — losing the
// relayed path silently, and only on the networks where it was the one that mattered.
func turnConfigFromEnv() TurnConfig {
	cfg := TurnConfig{
		URLs:     splitList(os.Getenv("SIGNALING_TURN_URLS")),
		Secret:   strings.TrimSpace(os.Getenv("SIGNALING_TURN_SECRET")),
		StunURLs: splitList(os.Getenv("SIGNALING_STUN_URLS")),
		TTL:      2 * time.Hour,
	}
	if raw := strings.TrimSpace(os.Getenv("SIGNALING_TURN_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			cfg.TTL = d
		} else {
			log.Printf("SIGNALING_TURN_TTL=%q is not a positive Go duration; using %s", raw, cfg.TTL)
		}
	}
	switch {
	case cfg.Enabled():
		log.Printf("TURN enabled: %d url(s), credentials valid %s", len(cfg.URLs), cfg.TTL)
	case len(cfg.URLs) > 0 && cfg.Secret == "":
		log.Printf("WARNING: SIGNALING_TURN_URLS is set but SIGNALING_TURN_SECRET is empty — TURN is " +
			"DISABLED. Peers behind symmetric NAT will fail to connect with no error of their own.")
	case cfg.Secret != "" && len(cfg.URLs) == 0:
		log.Printf("WARNING: SIGNALING_TURN_SECRET is set but SIGNALING_TURN_URLS is empty — TURN is DISABLED.")
	}
	if len(cfg.StunURLs) > 0 {
		log.Printf("STUN advertised to peers: %v", cfg.StunURLs)
	}
	return cfg
}

// ticketPubkeyFromEnv parses SIGNALING_TICKET_PUBKEY (the control plane's grant-issuer Ed25519
// public key, 64 hex chars — GET /grant/pubkey). Returns nil when unset; main() then refuses to
// start unless -insecure-no-ticket-verification was passed explicitly.
func ticketPubkeyFromEnv() (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(os.Getenv("SIGNALING_TICKET_PUBKEY"))
	if raw == "" {
		return nil, nil
	}
	pub, err := hex.DecodeString(raw)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("SIGNALING_TICKET_PUBKEY must be a hex-encoded 32-byte Ed25519 public key (64 hex chars)")
	}
	// REFUSE THE PLACEHOLDER. deploy/.env.example ships 64 zeros and the runbook tells the operator
	// to boot stage 1 with them, because the real value cannot be known until the control plane has
	// run once and printed it — a genuine chicken-and-egg, not sloppiness.
	//
	// The danger is what happens if they never come back and replace it. All-zeros is a well-formed
	// 32-byte value, so this function used to accept it, and Ed25519 verification against a
	// low-order point does not fail the way an operator would expect: session tickets become
	// universally forgeable, and NOTHING looks wrong. Signaling starts, agents register, sessions
	// broker. The deployment is wide open and completely quiet about it.
	//
	// Failing closed here converts that into a loud startup error at exactly the moment the operator
	// would otherwise proceed — stage 2, when signaling first runs. It cannot break the staged
	// bring-up, because stage 1 starts only postgres and the control plane.
	//
	// Checked against ANY all-zero key rather than only the literal placeholder: the property that
	// makes it unsafe is being a low-order point, not being the string we happen to ship.
	if isAllZero(pub) {
		return nil, errors.New(
			"SIGNALING_TICKET_PUBKEY is all zeros — that is the placeholder from deploy/.env.example, " +
				"not a key. It is a low-order Ed25519 point, so tickets signed by ANYONE would verify " +
				"against it and every session would be forgeable. Read the real value from the control " +
				"plane's startup log (grant_issuer_pubkey=...) and put THAT here")
	}
	return ed25519.PublicKey(pub), nil
}

// isAllZero reports whether b is entirely zero bytes. Not constant-time on purpose: the input is a
// PUBLIC key read from this process's own configuration, not a secret, and there is no attacker to
// leak timing to.
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	relayAddr := flag.String("relay", "relay-1.example:4444", "relay address handed to peers")
	heartbeat := flag.Duration("heartbeat-ttl", 30*time.Second, "peer freshness window")
	insecure := flag.Bool("insecure-no-ticket-verification", false,
		"LOCAL DEV ONLY: start without SIGNALING_TICKET_PUBKEY, accepting connect_request from any client")
	// Deliberately NOT coupled to -insecure-no-ticket-verification: the two gate different halves
	// (who may reach an agent vs. who may BE an agent), and a deployment that gets one right must
	// not silently inherit the other's opt-out.
	insecureAgentAuth := flag.Bool("insecure-no-agent-auth", false,
		"LOCAL DEV ONLY: accept register_agent without proof of possession of the enrolled agent key — "+
			"ANY WebSocket client can then displace ANY agent")
	// WebSocket admission bounds (docs/25 F09, bounded subset). Exposed as flags so a self-host
	// fleet can size them deliberately for its scale: a two-thousand-agent deployment wants a
	// higher total cap than an in-house one, and both want the pending-auth cap tight regardless.
	maxWS := flag.Int("max-websocket-connections", defaultMaxWebSocketConnections,
		"hard cap on concurrently accepted WebSocket connections; over-cap clients get 503 before Upgrade")
	maxPending := flag.Int("max-pending-auth", defaultMaxPendingAuth,
		"cap on unauthenticated (pre-registration, pre-connect_request) sockets; must not exceed "+
			"-max-websocket-connections")
	preAuth := flag.Duration("pre-auth-timeout", defaultPreAuthTimeout,
		"absolute lifetime for an unauthenticated socket; cannot be extended by any traffic and closes "+
			"the socket on expiry")
	flag.Parse()

	ticketPub, err := ticketPubkeyFromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	// Fail CLOSED: without the issuer key the M2 authorization gate does not exist — any WebSocket
	// client could broker a session to any registered agent — so a missing key is a startup error,
	// never a warning that a deployment can miss.
	if ticketPub == nil {
		if !*insecure {
			log.Fatalf("SIGNALING_TICKET_PUBKEY is not set: connect_request session tickets could not " +
				"be verified, so ANY WebSocket client could broker a session to ANY agent. Set it to the " +
				"control plane's grant-issuer public key (GET /grant/pubkey, 64 hex chars), or pass " +
				"-insecure-no-ticket-verification for local development.")
		}
		log.Printf("WARNING: -insecure-no-ticket-verification — connect_request session tickets are " +
			"NOT verified, so ANY WebSocket client may broker a session to ANY agent. Local dev only.")
	}

	// Fail CLOSED on the other half: without the device-identity endpoint there is no way to check
	// that a register_agent comes from the enrolled agent, so a missing endpoint is a startup
	// error. Enforcement is off only when an operator types the flag — there is no environment
	// variable that disables it and no degradation to permissive mode when the control plane is
	// unreachable.
	var identity IdentityResolver
	if *insecureAgentAuth {
		log.Printf("WARNING: -insecure-no-agent-auth — register_agent is NOT authenticated, so ANY " +
			"WebSocket client may displace ANY agent and receive its brokered sessions. Local dev only.")
	} else {
		resolver, err := identityResolverFromEnv()
		if err != nil {
			log.Fatalf("%v", err)
		}
		if resolver == nil {
			log.Fatalf("SIGNALING_DEVICE_IDENTITY_URL/SIGNALING_DEVICE_IDENTITY_TOKEN are not set: " +
				"register_agent could not be authenticated, so ANY WebSocket client could displace ANY " +
				"agent and receive its brokered sessions. Point them at the control plane's " +
				"device-identity endpoint, or pass -insecure-no-agent-auth for local development.")
		}
		identity = resolver
	}

	guestEnd, err := guestEndReporterFromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}

	srv, err := NewServer(*heartbeat, *relayAddr, ticketPub, identity)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}
	srv.guestEnd = guestEnd
	// docs/49: advertise session_ended_v1 only while the control plane confirms its /ended route.
	// A flip to supported reconnects agents that registered before it (they read features once).
	go guestEnd.RunCapabilityProbe(context.Background(), func() { srv.bounceSessionEndedStale() })
	// SIGNALING_MAX_PENDING_PER_SOURCE: how many unauthenticated sockets one source may hold at
	// once (default 32, clamped to the pool). A source at its cap can only replace its OWN oldest
	// pending socket; it never evicts another source's. 0 disables.
	pendingPerSource := envNonNegInt("SIGNALING_MAX_PENDING_PER_SOURCE", defaultMaxPendingPerSource)
	if pendingPerSource > *maxPending {
		pendingPerSource = *maxPending
	}
	if err := srv.SetAdmissionLimits(admissionLimits{
		maxTotal:            *maxWS,
		maxPending:          *maxPending,
		preAuthTimeout:      *preAuth,
		maxPendingPerSource: pendingPerSource,
	}); err != nil {
		log.Fatalf("invalid websocket admission limits: %v", err)
	}

	// SIGNALING_ALLOWED_ORIGINS: comma-separated list of browser Origins that may connect to /ws.
	// Native agents (no Origin header) are always permitted regardless of this setting.
	// Unset = warn-only (all Origins allowed, F09 browser-recruitment gap remains open).
	// Set to the console URL in production, e.g.: https://console.deskrally.com
	// When SIGNALING_ALLOWED_ORIGINS is blank it is derived from SIGNALING_SITE_ADDRESS (a Caddy-style
	// host list; each host -> https://host, see site_origins.go). An explicit value always wins.
	rawOrigins, err := effectiveAllowedOrigins(os.Getenv("SIGNALING_ALLOWED_ORIGINS"), os.Getenv("SIGNALING_SITE_ADDRESS"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	originPol, err := ParseOriginPolicy(rawOrigins)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// The console is also served from <tenant>.<suffix> when SSO tenant hosts are enabled; its
	// browsers send that Origin. The production overlay forwards CP_TENANT_HOST_SUFFIX here.
	originPol = originPol.WithTenantSuffix(os.Getenv("SIGNALING_ALLOWED_TENANT_HOST_SUFFIX"))
	srv.SetOriginPolicy(originPol)
	if originPol.enforcing() {
		log.Printf("INFO: WebSocket Origin policy enforcing %d allowed origin(s)", len(originPol.allowed))
	} else {
		log.Printf("WARNING: SIGNALING_ALLOWED_ORIGINS is not set — any browser Origin may reach the " +
			"signaling WebSocket. Set it to the console URL to close the F09 browser-recruitment gap " +
			"(native agents without an Origin header are always permitted).")
	}

	// SIGNALING_TRUSTED_PROXIES: CIDRs of reverse proxies permitted to set X-Forwarded-For for
	// client-IP resolution in the per-source quota. Set to the Caddy container's Docker network
	// CIDR (e.g. "172.20.0.0/24") so real client IPs are used instead of the proxy's IP.
	trustedProxyNets, err := ParseSignalingTrustedProxies(os.Getenv("SIGNALING_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	srv.SetTrustedProxyNets(trustedProxyNets)
	if len(trustedProxyNets) > 0 {
		log.Printf("INFO: signaling trusted proxy CIDRs: %d network(s) may set X-Forwarded-For", len(trustedProxyNets))
	}

	// SIGNALING_MAX_CONNECTIONS_PER_IP: per-source connection ceiling (docs/25 F09). 0 = unlimited.
	// Set to a value appropriate for your fleet (e.g. 32) to close the per-source quota gap.
	// IMPORTANT: meaningful only behind a reverse proxy when SIGNALING_TRUSTED_PROXIES is also set.
	maxPerIP := 0
	if raw := strings.TrimSpace(os.Getenv("SIGNALING_MAX_CONNECTIONS_PER_IP")); raw != "" {
		n, parseErr := strconv.Atoi(raw)
		if parseErr != nil || n < 0 {
			log.Fatalf("SIGNALING_MAX_CONNECTIONS_PER_IP=%q is not a non-negative integer", raw)
		}
		maxPerIP = n
	}
	srv.SetSourceQuota(maxPerIP)
	// SIGNALING_MAX_AUTHENTICATED_PER_IP: large backstop on AUTHENTICATED sockets per source (default
	// 4096). SIGNALING_MAX_CONNECTIONS_PER_IP above counts only unauthenticated/pending sockets, so
	// an office whose many agents share one NAT is never locked out by it.
	srv.SetAuthenticatedQuota(envNonNegInt("SIGNALING_MAX_AUTHENTICATED_PER_IP", defaultMaxAuthenticatedPerIP))
	// Re-check registered agents against the control plane so a suspended tenant's (or a removed
	// machine's) agents are disconnected within one interval (revalidate.go). Dev mode (no identity
	// resolver) skips it.
	if identity != nil {
		srv.StartAgentRevalidation(context.Background(), AgentRevalidationInterval)
	}
	if maxPerIP > 0 {
		if len(trustedProxyNets) == 0 {
			log.Printf("WARNING: SIGNALING_MAX_CONNECTIONS_PER_IP=%d is set but SIGNALING_TRUSTED_PROXIES is not — "+
				"all clients behind a reverse proxy share the proxy's IP as their quota bucket, making the "+
				"per-source limit ineffective. Set SIGNALING_TRUSTED_PROXIES to the proxy's CIDR.", maxPerIP)
		} else {
			log.Printf("INFO: per-source WebSocket limit: %d connection(s) per IP (XFF trusted from %d network(s))",
				maxPerIP, len(trustedProxyNets))
		}
	} else {
		log.Printf("WARNING: SIGNALING_MAX_CONNECTIONS_PER_IP is not set — a single source IP may hold " +
			"all WebSocket slots up to the global cap. Set it to close the F09 per-source quota gap.")
	}

	// SIGNALING_MAX_CONNECTS_PER_SECOND_PER_IP: per-source new-connection rate (token bucket,
	// burst = 6x), checked before admission and any control-plane lookup. 0 disables.
	connectRate := envNonNegInt("SIGNALING_MAX_CONNECTS_PER_SECOND_PER_IP", defaultConnectRatePerSecond)
	srv.SetConnectRate(connectRate)

	// SIGNALING_MAX_MESSAGES_PER_SECOND: per-connection message-rate ceiling (docs/25 F09).
	// 0 = unlimited. Set to a value appropriate for your deployment (e.g. 50) to close the F09
	// message-rate gap. Any connection that exceeds this rate receives a Rejected and is closed.
	maxMsgPerSec := 0
	if raw := strings.TrimSpace(os.Getenv("SIGNALING_MAX_MESSAGES_PER_SECOND")); raw != "" {
		n, parseErr := strconv.Atoi(raw)
		if parseErr != nil || n < 0 {
			log.Fatalf("SIGNALING_MAX_MESSAGES_PER_SECOND=%q is not a non-negative integer", raw)
		}
		maxMsgPerSec = n
	}
	srv.SetMsgRateLimit(maxMsgPerSec)
	if err := logPosture(signalingPosture{
		production:       strings.TrimSpace(os.Getenv("SIGNALING_PRODUCTION")) != "",
		originEnforcing:  originPol.enforcing(),
		originAny:        originPol.any,
		trustedProxies:   len(trustedProxyNets),
		maxPerIP:         maxPerIP,
		connectRate:      connectRate,
		pendingPerSource: pendingPerSource,
		strictTickets:    envFlagOn("SIGNALING_STRICT_TICKET_REDEMPTION"),
		messageRate:      maxMsgPerSec,
		maxPendingAuth:   *maxPending,
	}, log.Printf); err != nil {
		log.Fatalf("%v", err)
	}
	if maxMsgPerSec > 0 {
		log.Printf("INFO: per-connection message rate limit: %d message(s) per second", maxMsgPerSec)
	} else {
		log.Printf("WARNING: SIGNALING_MAX_MESSAGES_PER_SECOND is not set — a single connection may " +
			"send messages at any rate. Set it to close the F09 message-rate gap.")
	}

	// F19: per-connection diagnostic log rate limit is always active (hardcoded, not configurable).
	log.Printf("INFO: per-connection diagnostic log rate: %d line(s)/s (F19 protection, always active)",
		defaultConnLogLinesPerSecond)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", srv.handleWS)
	// Agent presence feed for the control-plane console (presence.go). Service-token gated; not
	// mounted at all without a long enough SIGNALING_PRESENCE_TOKEN.
	mountPresence(mux, srv.reg, os.Getenv("SIGNALING_PRESENCE_TOKEN"))
	// docs/65: the control plane tells signaling a directive was issued. Same service token as the
	// control plane's internal routes; not mounted without it.
	srv.mountDirectiveNotify(mux, strings.TrimSpace(os.Getenv("SIGNALING_DEVICE_IDENTITY_TOKEN")))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("signaling server listening on %s (relay=%s, server_pubkey=%s)",
		*addr, *relayAddr, srv.serverPubkey())
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}
