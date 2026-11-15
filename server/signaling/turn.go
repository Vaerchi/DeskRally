package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TURN credential issuance for WAN media (coturn `use-auth-secret` mode).
//
// # Why the SERVER issues these
//
// A TURN password baked into every agent's config.json is a durable, fleet-wide credential sitting
// on every endpoint we do not control — exactly the machines most likely to be compromised, and
// rotating it means touching all of them. coturn's shared-secret ("REST API") mode replaces that
// with credentials the server derives per session and that expire on their own: the secret never
// leaves the signaling server, and a stolen credential is worthless within TurnTTL.
//
// It is also the right authorization boundary. Relaying media through our TURN server costs
// bandwidth, so the ability to do it should follow the same gate as everything else: you get
// credentials when you are brokered into a session, and not before.
//
// # The scheme (coturn `use-auth-secret` / draft-uberti-behave-turn-rest-00)
//
//	username = "<unix-expiry>:<name>"
//	password = base64( HMAC-SHA1( static-auth-secret, username ) )
//
// SHA-1 here is not a security choice we are making — it is the algorithm coturn implements for
// this mode, used as an HMAC (where SHA-1's collision weakness does not apply) over a value that
// expires with its credential (TurnTTL). Changing it would simply fail to authenticate.

// TurnConfig is the signaling server's TURN issuance policy, built from the environment.
// A zero value means "no TURN configured", which is the LAN/dev default.
type TurnConfig struct {
	// URLs of the TURN server, e.g. {"turn:turn.example.com:3478?transport=udp",
	// "turn:turn.example.com:3478?transport=tcp"}. All entries share one credential.
	URLs []string
	// Secret shared with coturn's `static-auth-secret`. Never leaves this process.
	Secret string
	// How long an issued credential stays valid.
	TTL time.Duration
	// STUN URLs handed out alongside TURN. Separate because STUN needs no credential and is
	// useful even when TURN is not configured.
	StunURLs []string
}

// Enabled reports whether TURN credentials can actually be issued. URLs without a secret (or the
// reverse) is a misconfiguration that would hand clients unusable ICE servers, so it counts as
// disabled and main() logs it loudly rather than pretending.
func (t TurnConfig) Enabled() bool {
	return len(t.URLs) > 0 && t.Secret != ""
}

// IceServerSpec mirrors the Rust `rmt_protocol::signaling::IceServerSpec` and the TypeScript
// `IceServerSpec`. Field names and omitempty behaviour are the WIRE CONTRACT — the Rust side emits
// `username`/`credential` only when present, and `crates/protocol/src/signaling.rs`'s
// `ice_servers_round_trips_with_and_without_credentials` pins the exact bytes from the other side.
type IceServerSpec struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// IceServers is the message both peers receive immediately BEFORE `brokered`.
//
// The ordering is load-bearing, not incidental: both clients build their RTCPeerConnection the
// moment they see `brokered`, and ICE servers cannot be added afterwards without renegotiation.
// WebSocket delivery is ordered per connection, so sending this first is a guarantee rather than a
// race. See the doc comment on the Rust `ServerToClient::IceServers`.
//
// **Tag-free, like every other payload in messages.go**: the `ServerToClient` envelope injects the
// `"type":"ice_servers"` discriminant (see `serverTag`). A `Type` field here would be marshalled as
// a second, competing `type` key rather than becoming the tag.
type IceServers struct {
	Session string `json:"session"`
	// Never `nil` on the wire. `json.Marshal` renders a nil slice as `null`, and `null` fails to
	// deserialize into the Rust `Vec<IceServerSpec>` — which drops the whole message rather than
	// yielding an empty list. `iceServersFor` therefore always returns a non-nil slice.
	Servers []IceServerSpec `json:"servers"`
	// RelayNotice, when set, tells the REQUESTER that no relay credential was issued because its account
	// is at its outstanding-credential cap. Optional and additive: absent otherwise, ignored by older clients.
	RelayNotice string `json:"relay_notice,omitempty"`
}

// turnCredential derives the coturn shared-secret username/password pair valid until `now + ttl`.
//
// `name` is a label only — coturn does not resolve it to an account in this mode — but it is worth
// setting to something identifying, because it is what appears in coturn's logs when you are
// working out who is relaying.
func turnCredential(secret, name string, now time.Time, ttl time.Duration) (string, string) {
	expiry := now.Add(ttl).Unix()
	username := fmt.Sprintf("%d:%s", expiry, name)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// iceServersFor builds the per-session ICE server list.
//
// STUN entries carry no credential; the TURN entry groups every configured URL under ONE
// credential, which is what lets a client fall back from UDP to TCP (and, if configured, TLS)
// without a second issuance — the transports that matter precisely when UDP is blocked, which is
// the situation TURN exists for.
//
// Returns an empty slice when nothing is configured. That is a legal, meaningful answer ("host
// candidates only"), and it is what a LAN deployment gets.
func (t TurnConfig) iceServersFor(session, name string, now time.Time) []IceServerSpec {
	out := make([]IceServerSpec, 0, 2)
	if len(t.StunURLs) > 0 {
		out = append(out, IceServerSpec{URLs: append([]string(nil), t.StunURLs...)})
	}
	if t.Enabled() {
		user, pass := turnCredential(t.Secret, session+":"+name, now, t.TTL)
		out = append(out, IceServerSpec{
			URLs:       append([]string(nil), t.URLs...),
			Username:   user,
			Credential: pass,
		})
	}
	return out
}

// splitList parses a comma-separated environment value, trimming blanks. Empty in, empty out.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Outstanding-credential caps (audit #14/#16). A TURN credential outlives its session (it is valid
// until its expiry), so the cap counts ISSUED, UNEXPIRED credentials, not live sessions: otherwise
// start / collect / end / repeat leaves arbitrarily many valid usernames. coturn's --total-quota is
// global (deploy/docker-compose.turn.yml), so these stay well under what one tenant could otherwise take.
// The defaults are what production runs with TURN_TTL=2h: replaying a month of one technician's real
// sessions, 6 / 24 denied the relay to 10-17% of them and 20 / 80 to none (docs/10).
const (
	defaultTurnMaxPerUser   = 20
	defaultTurnMaxPerTenant = 80
	// turnMaxUnverified bounds ONE explicit global bucket for sessions with no verified admission
	// identity (dev mode / -insecure-no-ticket-verification, where the ticket's claims are
	// attacker-chosen). Never a per-connection allowance, never shared with a real tenant.
	turnMaxUnverified = 4
	turnUnverifiedKey = "unverified"
)

// turnRelayNotice is shown to the requester when a session brokers without a relay credential.
const turnRelayNotice = "relay capacity exhausted for your account; direct connection only"

// turnLedger tracks outstanding credential expiries per principal and per tenant.
type turnLedger struct {
	mu     sync.Mutex
	byUser map[string][]int64 // key -> expiry unix ms of each outstanding credential
	byTen  map[string][]int64
}

func (l *turnLedger) sweep(m map[string][]int64, nowMs int64) {
	for k, exps := range m {
		kept := exps[:0]
		for _, e := range exps {
			if e > nowMs {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(m, k)
		} else {
			m[k] = kept
		}
	}
}

// reserve records one credential expiring at expMs for (userKey, tenantKey) when both are under their
// caps after lazily dropping expired reservations. Reports whether the credential may be issued.
func (l *turnLedger) reserve(userKey, tenantKey string, nowMs, expMs int64, maxUser, maxTenant int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byUser == nil {
		l.byUser, l.byTen = map[string][]int64{}, map[string][]int64{}
	}
	l.sweep(l.byUser, nowMs)
	l.sweep(l.byTen, nowMs)
	if len(l.byUser[userKey]) >= maxUser || len(l.byTen[tenantKey]) >= maxTenant {
		return false
	}
	l.byUser[userKey] = append(l.byUser[userKey], expMs)
	l.byTen[tenantKey] = append(l.byTen[tenantKey], expMs)
	return true
}

// WithTurnLimits sets the per-user and per-tenant caps on OUTSTANDING TURN credentials. Zero keeps
// the default. Construction time only, like WithTurn.
func (b *Broker) WithTurnLimits(perUser, perTenant int) *Broker {
	b.turnMaxPerUser, b.turnMaxPerTenant = perUser, perTenant
	return b
}

// turnAdmit reserves a credential for this admission. Quotas key on the VERIFIED ticket's
// tenant and technician (both minted by the control plane from the authenticated principal on every
// production path: POST /sessions incl. observer tickets, and the attended-session connect, where the
// technician connecting is the principal). A session with no verified identity (no ticket verifier, or
// empty claims) shares the single small turnUnverifiedKey bucket.
func (b *Broker) turnAdmit(ticket *SignedSessionTicket) bool {
	maxUser, maxTenant := b.turnMaxPerUser, b.turnMaxPerTenant
	if maxUser <= 0 {
		maxUser = defaultTurnMaxPerUser
	}
	if maxTenant <= 0 {
		maxTenant = defaultTurnMaxPerTenant
	}
	userKey, tenantKey := turnUnverifiedKey, turnUnverifiedKey
	if b.ticketPub != nil && ticket != nil && ticket.Claims.TechnicianID != "" && ticket.Claims.TenantID != "" {
		userKey = "u:" + ticket.Claims.TenantID + "/" + ticket.Claims.TechnicianID
		tenantKey = "t:" + ticket.Claims.TenantID
	} else {
		maxUser, maxTenant = turnMaxUnverified, turnMaxUnverified
	}
	now := b.nowMs()
	exp := now + b.turn.TTL.Milliseconds()
	return b.turnLedger.reserve(userKey, tenantKey, now, exp, maxUser, maxTenant)
}

// iceServersForSession is iceServersFor with the credential withheld (STUN only) when the session
// is over its TURN cap. The clock is the broker's, so expiry is testable.
func (b *Broker) iceServersForSession(sessionID string, withTurn bool) []IceServerSpec {
	cfg := b.turn
	if !withTurn {
		cfg.Secret = ""
	}
	return cfg.iceServersFor(sessionID, "rmt", time.UnixMilli(b.nowMs()))
}
