// Package main implements the rendezvous/signaling server (ADR-002). This file mirrors the
// Rust `rmt-protocol::signaling` wire types: JSON messages tagged with a snake_case "type"
// field. The ID newtypes on the Rust side (DeviceId/SessionId/RelayToken) serialize
// transparently as their inner UUID, so on the wire they are plain JSON strings — modeled
// here as `string`.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// NatType classifies a peer's NAT, informing whether a direct path is even possible
// (symmetric-to-symmetric essentially always requires a relay). Snake_case on the wire.
type NatType string

const (
	NatUnknown        NatType = "unknown"
	NatOpen           NatType = "open"
	NatFullCone       NatType = "full_cone"
	NatRestrictedCone NatType = "restricted_cone"
	NatPortRestricted NatType = "port_restricted"
	NatSymmetric      NatType = "symmetric"
)

// CandidateKind is an ICE-style candidate classification.
type CandidateKind string

const (
	CandidateHost            CandidateKind = "host"
	CandidateServerReflexive CandidateKind = "server_reflexive"
	CandidateRelayed         CandidateKind = "relayed"
)

// Candidate is a network candidate for connectivity establishment (ICE-style). The server
// relays these opaquely between peers during hole-punching; it never dials them itself.
type Candidate struct {
	Addr string        `json:"addr"`
	Kind CandidateKind `json:"kind"`
}

// ---------------------------------------------------------------------------
// Client -> server payloads.
// ---------------------------------------------------------------------------

// RegisterAgent announces an agent. Pubkey is the long-term Ed25519 identity (hex); the
// server pins it so it can't later be silently swapped (the malicious-server MITM gap).
//
// Tenant is the control-plane tenant the agent belongs to. It is OPTIONAL on the wire (older
// agents omit it), but when present the broker requires a connect_request's session ticket to
// carry the same tenant — the cross-tenant brokering guard in ticket.go.
type RegisterAgent struct {
	Device          string  `json:"device"`
	Pubkey          string  `json:"pubkey"`
	Tenant          string  `json:"tenant,omitempty"`
	Nat             NatType `json:"nat"`
	EnrollmentToken *string `json:"enrollment_token,omitempty"`
	// OS is the agent's current OS description (the composed string enrollment sends for
	// machine.os). ADVISORY INVENTORY, never identity: it is re-emitted in the presence feed so
	// the control plane can refresh the otherwise write-once machine.os. Optional on the wire
	// (older agents and controllers omit it) and BOUNDED on receipt via boundOSDescription (control characters removed, then truncated).
	OS string `json:"os,omitempty"`
	// RequireSessionPolicy is the agent's local require_session_policy config flag: set means it
	// opens every session VIEW-ONLY until a control-plane-signed access policy verifies. Advisory
	// inventory like OS, re-emitted in the presence feed so the control plane can refresh
	// machine.require_session_policy (migrations/0037) and mint the policy that discharges the floor.
	//
	// A POINTER, and the pointer is load-bearing. `false` and "not sent" are DIFFERENT: an agent
	// always sends an explicit value (including false, so clearing the flag propagates), while a
	// controller, a dev peer or a pre-loop-86 agent sends nothing at all. Collapsing the two into a
	// plain bool would make every silent peer look like one that had just turned the flag off.
	RequireSessionPolicy *bool `json:"require_session_policy,omitempty"`
	// AgentVersion is the agent's build identity — rmt_agent_core::version::AGENT_VERSION, shaped
	// "<semver>+<short git sha>" (e.g. "0.0.1+0594362"). ADVISORY INVENTORY on exactly the same
	// terms as OS: re-emitted in the presence feed so the control plane can refresh
	// machine.agent_version (migrations/0039), which is what makes "what is actually deployed out
	// there" answerable — the prerequisite for every part of agent auto-update (docs/21 §2).
	//
	// A plain string with omitempty, NOT a pointer like RequireSessionPolicy. The tri-state there
	// exists because `false` and "not sent" are genuinely different; here the empty string already
	// means "said nothing", and an agent that has a version always has a non-empty one.
	//
	// Optional on the wire (controllers, dev peers and pre-loop-96 agents omit it) and BOUNDED on
	// receipt via boundAgentVersion — it arrives BEFORE proof of possession, so it is
	// attacker-controlled on the unauthenticated edge. Control characters are removed too.
	//
	// The Rust half of this contract is ClientToServer::RegisterAgent in
	// crates/protocol/src/signaling.rs. No compiler sees across the wire, so each side names the
	// other by path and TestExactWireShape pins the same literal the Rust test does.
	AgentVersion string `json:"agent_version,omitempty"`
	// LoggedInUser is the Windows interactive session user announced at register_agent (e.g.
	// "CORP\alice" or "alice"). ADVISORY INVENTORY on the same terms as OS and AgentVersion:
	// re-emitted in the presence feed so the control plane can refresh machine.logged_in_user
	// (migrations/0048) — closing the docs/01 §4 Access Panel gap "Missing: the last-USER field".
	//
	// A plain string with omitempty — the same convention as AgentVersion. The empty string means
	// "said nothing" (no user logged in, or an older agent), and an agent that has a user always
	// has a non-empty value. BOUNDED on receipt via boundLoggedInUser; attacker-controlled before
	// proof of possession, so the bound is a safety constraint, not a completeness one. Control
	// characters are removed (not rejected) on receipt.
	LoggedInUser string `json:"logged_in_user,omitempty"`
	// MultiSessionCapable signals that this agent supports concurrent sessions targeting the same
	// device (multiple technicians controlling the same machine simultaneously). An agent that does
	// NOT set this field (or sets false) supports only one session at a time.
	//
	// A POINTER so nil ("not sent") is distinguishable from false: an old agent that omits the
	// field must not look like one that reported false. The control plane and viewer capability-gate
	// the "Invite technician" flow on this flag. Re-emitted in the presence feed so the control
	// plane can cache the capability without consulting the signaling server on every request.
	// ADVISORY INVENTORY, never identity — the broker never uses this for authorization.
	MultiSessionCapable *bool `json:"multi_session_capable,omitempty"`
	// Features lists the optional protocol features THIS agent understands (docs/65: "directive_v1").
	// The agent's own assertion, never identity: it only decides what the server may send it. BOUNDED
	// on receipt via boundFeatures (it arrives before proof of possession).
	Features []string `json:"features,omitempty"`
}

// Fleet-directive limits (docs/65). Directives are signed by the control plane and verified by the
// agent; signaling only relays, so these bounds exist to keep an unauthenticated or hostile peer
// from making the relay carry arbitrary volume.
const (
	// maxAgentFeatures and maxFeatureBytes bound register_agent's features list.
	maxAgentFeatures = 8
	maxFeatureBytes  = 32
	// maxDirectiveArtifactBytes bounds the opaque signed directive the control plane hands us.
	maxDirectiveArtifactBytes = 4096
	maxDirectiveDetailBytes   = 256
	maxDirectiveSigBytes      = 128
	maxDirectiveAddrBytes     = 32 // the ack's from/to state names
	directiveFeature          = "directive_v1"
	// postureFeature / grantKeyPinnedFeature: see rmt_protocol::signaling::POSTURE_FEATURE.
	postureFeature          = "posture_v1"
	grantKeyPinnedFeature   = "grant_key_pinned"
	sessionPolicyReqFeature = "session_policy_required"
)

// validFeatureName accepts 1..maxFeatureBytes bytes of [a-z0-9_].
func validFeatureName(s string) bool {
	if len(s) == 0 || len(s) > maxFeatureBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// boundFeatures keeps at most the first maxAgentFeatures entries, drops any that is not a valid
// feature name, and removes duplicates. Dropped, not rejected: a live agent connection is never
// killed over an advisory list (same posture as the inventory strings).
func boundFeatures(in []string) []string {
	if len(in) > maxAgentFeatures {
		in = in[:maxAgentFeatures]
	}
	var out []string
	seen := make(map[string]struct{}, len(in))
	for _, f := range in {
		if !validFeatureName(f) {
			continue
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

func hasFeature(features []string, want string) bool {
	for _, f := range features {
		if f == want {
			return true
		}
	}
	return false
}

// DirectiveAck is the agent's signed acknowledgement of a directive (agent -> server). Signaling
// forwards every field VERBATIM to the control plane and never authors or alters one; the device id
// comes from the authenticated connection, which is why the decoder is strict and refuses a
// message that names a device (or anything else it does not know).
type DirectiveAck struct {
	DirectiveID string `json:"directive_id"`
	From        string `json:"from"`
	To          string `json:"to"`
	TsMs        int64  `json:"ts_ms"`
	Detail      string `json:"detail"`
	Sig         string `json:"sig"`
}

// validate enforces the wire bounds. directive_id must be a canonical UUID.
func (a *DirectiveAck) validate() error {
	switch {
	case !validGuestEndSessionID(a.DirectiveID):
		return fmt.Errorf("directive_ack: directive_id is not a canonical UUID")
	case len(a.From) > maxDirectiveAddrBytes || len(a.To) > maxDirectiveAddrBytes:
		return fmt.Errorf("directive_ack: from/to exceed %d bytes", maxDirectiveAddrBytes)
	case len(a.Detail) > maxDirectiveDetailBytes:
		return fmt.Errorf("directive_ack: detail exceeds %d bytes", maxDirectiveDetailBytes)
	case len(a.Sig) > maxDirectiveSigBytes:
		return fmt.Errorf("directive_ack: sig exceeds %d bytes", maxDirectiveSigBytes)
	}
	return nil
}

// decodeDirectiveAck decodes a directive_ack strictly: unknown fields (a smuggled device_id, say)
// are an error, as are out-of-bound values.
func decodeDirectiveAck(data []byte) (*DirectiveAck, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	delete(fields, "type") // the envelope's own discriminant
	stripped, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(stripped)))
	dec.DisallowUnknownFields()
	var a DirectiveAck
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("directive_ack: %w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// maxOSDescriptionBytes bounds the register_agent os string, matching the control plane's 255-byte
// cap on machine.os at enrollment. The bound here TRUNCATES rather than rejects: enrollment is a
// request that may fail, but killing a live agent connection over an oversized inventory string
// would trade a working session for a display column.
const maxOSDescriptionBytes = 255

// maxAgentVersionBytes bounds the register_agent agent_version string. Deliberately far smaller
// than the OS cap: a build identity is "<semver>+<short sha>", so 64 bytes is already generous,
// and the tighter the bound the less an unauthenticated peer can push into the registry and the
// presence feed before proving anything.
const maxAgentVersionBytes = 64

// maxLoggedInUserBytes bounds the register_agent logged_in_user string. A Windows username is at
// most 20 characters, a NetBIOS domain name at most 15, plus the backslash — 37 bytes covers any
// real DOMAIN\user pair; 64 is generous and keeps the bound consistent with maxAgentVersionBytes.
const maxLoggedInUserBytes = 64

// stripControlChars removes every control rune (unicode.IsControl: C0 incl. NUL/CR/LF/TAB, DEL and
// C1) from s. These inventory strings arrive before proof of possession and are re-emitted in the
// presence feed, so a newline or NUL must not reach it. STRIP rather than reject: a live agent
// connection is never killed over a display string. Printable and non-ASCII text is untouched, and
// a string with no control rune is returned as-is (no allocation).
func stripControlChars(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// boundOSDescription removes control characters (stripControlChars) and then truncates s to
// maxOSDescriptionBytes without splitting a UTF-8 sequence (a localized ProductName is multi-byte,
// and emitting broken UTF-8 into the presence feed would push the problem onto every consumer).
// Stripping comes first so control characters never consume cap bytes.
func boundOSDescription(s string) string {
	s = stripControlChars(s)
	if len(s) <= maxOSDescriptionBytes {
		return s
	}
	cut := maxOSDescriptionBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 { // back off continuation bytes to a rune boundary
		cut--
	}
	return s[:cut]
}

// boundAgentVersion strips control characters and truncates s to maxAgentVersionBytes on the same
// rune boundary rule as boundOSDescription, and for the same reason: TRUNCATE rather than reject,
// because killing a live agent connection over an oversized inventory string would trade a working
// session for a display column.
func boundAgentVersion(s string) string {
	s = stripControlChars(s)
	if len(s) <= maxAgentVersionBytes {
		return s
	}
	cut := maxAgentVersionBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 { // back off continuation bytes to a rune boundary
		cut--
	}
	return s[:cut]
}

// boundLoggedInUser strips control characters and truncates s to maxLoggedInUserBytes on the same
// rune boundary rule as boundOSDescription. Truncation rather than rejection for the same reason as
// boundAgentVersion.
func boundLoggedInUser(s string) string {
	s = stripControlChars(s)
	if len(s) <= maxLoggedInUserBytes {
		return s
	}
	cut := maxLoggedInUserBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 { // back off continuation bytes to a rune boundary
		cut--
	}
	return s[:cut]
}

// AgentAuthResponse answers an AgentAuthChallenge with proof of possession of the enrolled agent
// key: Sig is the hex-encoded 64-byte Ed25519 signature over the canonical preimage built by
// agentAuthSigningBytes (agentauth.go). Nonce echoes the challenge's nonce, hex-encoded.
type AgentAuthResponse struct {
	Device string `json:"device"`
	Nonce  string `json:"nonce"`
	Sig    string `json:"sig"`
}

// GuestEndedSession names only the session: identity comes from the authenticated connection.
type GuestEndedSession struct {
	ControlPlaneSession string `json:"control_plane_session"`
}

// SessionEnded is the generalised end report (docs/49): one of this agent's sessions ended for
// Reason. Identity comes from the authenticated connection, as for GuestEndedSession. QueueAgeMs
// is how long the report waited in the agent's queue.
type SessionEnded struct {
	ControlPlaneSession string `json:"control_plane_session"`
	Reason              string `json:"reason"`
	QueueAgeMs          *int64 `json:"queue_age_ms,omitempty"`
}

// HelpRequest asks for a technician (docs/64, help_request_v1). Identity comes from the authenticated
// connection, never from this body; OpID is the agent's idempotency key (H-C3).
type HelpRequest struct {
	OpID string `json:"op_id"`
	Note string `json:"note,omitempty"`
}

// HelpCancel withdraws exactly one request, only the authenticated device's own (H-C3).
type HelpCancel struct {
	RequestID string `json:"request_id"`
}

// HelpStatus asks for the device's open (else latest) request: the agent's re-query on reconnect and on
// its timer while a request is open (H-C4).
type HelpStatus struct{}

// Heartbeat keeps liveness and the NAT mapping fresh.
type Heartbeat struct {
	Device string `json:"device"`
}

// ConnectRequest asks the server to reach an agent by DeviceId. Ticket is the control-plane-
// signed session ticket authorizing this rendezvous (ticket.go); optional on the wire for
// backward compatibility, but REQUIRED when the server is started with SIGNALING_TICKET_PUBKEY.
type ConnectRequest struct {
	Target string               `json:"target"`
	Ticket *SignedSessionTicket `json:"ticket,omitempty"`
}

// CandidateMsg trickles a locally-gathered candidate to the peer via the server. It is used
// in both directions ("candidate" tag), so a single struct models both.
type CandidateMsg struct {
	Session   string    `json:"session"`
	Candidate Candidate `json:"candidate"`
}

// SdpKind distinguishes an SDP offer from an answer.
type SdpKind string

const (
	SdpOffer  SdpKind = "offer"
	SdpAnswer SdpKind = "answer"
)

// SdpMsg carries an SDP offer or answer between the two peers of a session. The server relays it
// opaquely (exactly like a candidate) — it never parses the SDP. Used in both directions ("sdp"
// tag), so a single struct models both.
type SdpMsg struct {
	Session string  `json:"session"`
	Sdp     string  `json:"sdp"`
	Kind    SdpKind `json:"kind"`
}

// ---------------------------------------------------------------------------
// Server -> client payloads.
// ---------------------------------------------------------------------------

// Registered accepts a registration and echoes the server's own signed identity for pinning.
type Registered struct {
	ServerPubkey string `json:"server_pubkey"`
	// Features lists optional protocol features this connection may use (docs/49:
	// "session_ended_v1", docs/64: "help_request_v1"). Omitted when empty, so older agents see the message unchanged.
	Features []string `json:"features,omitempty"`
}

// AgentAuthChallenge demands proof of possession of the enrolled agent key before a register_agent
// is admitted (M3). Device echoes the device id from the register_agent that produced the
// challenge, so a client juggling reconnects can tell which registration it answers. Nonce is 32
// random bytes, hex-encoded. ExpiresAtMs is informational — the server clock is authoritative.
type AgentAuthChallenge struct {
	Device      string `json:"device"`
	Nonce       string `json:"nonce"`
	ExpiresAtMs int64  `json:"expires_at_ms"`
}

// Brokered tells a peer that a session was brokered, carrying the other peer's pinned pubkey.
//
// ControlPlaneSession is the CONTROL-PLANE session id from the ticket this broker verified, which is
// a DIFFERENT value from Session (the broker's own id for the peer pairing). It is the agent's only
// channel to its own control-plane session id, and it exists so the agent can bind a signed session
// policy to the live session — see the field doc on ServerToClient::Brokered in
// crates/protocol/src/signaling.rs. `omitempty` so a server that verifies no tickets emits the
// pre-loop-86 wire shape exactly, which the agent reads as "unknown" and fails CLOSED on.
//
// TechnicianID is the same hop, added in loop 91 for the SESSION-scoped audit chain. The agent seals
// audit events itself and stamps `technician_id` into the hashed preimage, and POST /audit/ingest
// answers 403 unless that id equals the authenticated forwarder (control-plane/audit.go). So the
// agent has to learn WHO the technician is, from a source neither it nor the browser can choose:
// this broker verified the ticket's control-plane signature, and `technician_id` is inside it. The
// viewer must NOT stamp it — a technician self-attributing is the exact forgery that 403 closes.
// Same `omitempty` + fail-closed reading as ControlPlaneSession: no id means no central trail, never
// a trail attributed to nobody.
type Brokered struct {
	Session             string `json:"session"`
	PeerDevice          string `json:"peer_device"`
	PeerPubkey          string `json:"peer_pubkey"`
	ControlPlaneSession string `json:"control_plane_session,omitempty"`
	TechnicianID        string `json:"technician_id,omitempty"`
	// Access and AccessVersion are always emitted together by the broker.
	Access        string `json:"access"`
	AccessVersion int    `json:"access_version"`
}

// RelayAssignment nominates a relay both peers present the token to (the guaranteed fallback).
type RelayAssignment struct {
	Session   string `json:"session"`
	RelayAddr string `json:"relay_addr"`
	Token     string `json:"token"`
}

// GuestEndedResult lets the agent retain a report until it receives a terminal answer.
type GuestEndedResult struct {
	ControlPlaneSession string `json:"control_plane_session"`
	Outcome             string `json:"outcome"`
}

// SessionEndedResult answers a SessionEnded. Outcomes as GuestEndedResult: ended, already_ended
// and refused are terminal; unavailable means keep the report and retry.
type SessionEndedResult struct {
	ControlPlaneSession string `json:"control_plane_session"`
	Outcome             string `json:"outcome"`
}

// Directive relays one control-plane-signed directive to an agent that advertised directive_v1.
// Artifact is opaque to signaling (at most maxDirectiveArtifactBytes); the agent verifies it.
type Directive struct {
	DirectiveID string `json:"directive_id"`
	Artifact    string `json:"artifact"`
}

// DirectiveAckResult answers a DirectiveAck. applied and replay are terminal successes, refused is
// terminal, unavailable means retry later. From, To and TsMs echo the acknowledgement this answers, so the
// agent correlates a result with the exact transition it sent (never by arrival order); they are empty only
// when the ack itself was malformed.
type DirectiveAckResult struct {
	DirectiveID string `json:"directive_id"`
	Outcome     string `json:"outcome"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	TsMs        int64  `json:"ts_ms,omitempty"`
}

// HelpRequestInfo is the agent's view of a request (no tenant, machine or group ids).
type HelpRequestInfo struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Note      string `json:"note,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// HelpRequestResult answers help_request, help_cancel and help_status. Outcome: ok (Request holds the
// current state; nil Request on a status = none), refused (terminal), limited (RetryAfterSeconds says
// when), conflict (Request holds the current state: the first committed transition won), not_found and
// unavailable (retry later). OpID echoes a help_request's key.
type HelpRequestResult struct {
	Op                string           `json:"op"`
	OpID              string           `json:"op_id,omitempty"`
	Outcome           string           `json:"outcome"`
	Request           *HelpRequestInfo `json:"request,omitempty"`
	RetryAfterSeconds int              `json:"retry_after_seconds,omitempty"`
	// CancelOf echoes the request id a help_cancel answer is about, for EVERY outcome (incl. not_found,
	// which carries no Request), so the agent can correlate it instead of guessing.
	CancelOf string `json:"cancel_of,omitempty"`
}

// Rejected refuses a request (unknown/offline device, unauthorized, rate-limited).
type Rejected struct {
	Reason string `json:"reason"`
}

// SessionParticipantEntry is one live technician in a concurrent multi-session view.
type SessionParticipantEntry struct {
	// SessionID is the broker's session id for this technician's connection (not the control-plane id).
	SessionID string `json:"session_id"`
	// TechnicianID is the verified technician identity from the session ticket, or "" when the
	// broker was not in ticket-enforced mode (dev / no-ticket path). Absent when empty.
	TechnicianID string `json:"technician_id,omitempty"`
	Access       string `json:"access"`
}

// SessionParticipants is sent by the server to both the agent and all controllers connected to a
// device whenever a session targeting that device starts or ends. It provides a live view of
// concurrent sessions so technicians know they are not alone, and agents know to share resources.
//
// SECURITY: this message carries only session ids and verified technician ids — no keys, no
// credentials, no IP addresses. The broker sends it only to peers that are already members of a
// session targeting DeviceID (the agent itself or a verified controller). A passive observer cannot
// receive it.
//
// WIRE COMPATIBILITY: old clients (pre-multi-session) ignore unknown message types. Old agents
// continue to serve sessions normally; they simply never see participant lists.
type SessionParticipants struct {
	// DeviceID is the agent's device id that all participants are targeting.
	DeviceID     string                    `json:"device_id"`
	Participants []SessionParticipantEntry `json:"participants"`
}

// ---------------------------------------------------------------------------
// Discriminated envelopes.
//
// Each concrete payload struct above is tag-free; the envelope injects/reads the "type"
// field. Marshalling merges the tag into the payload object; unmarshalling is a two-pass
// decode (probe the tag, then decode into the concrete type).
// ---------------------------------------------------------------------------

// ClientToServer is a tagged message received from a controller or agent.
type ClientToServer struct {
	Type    string
	Payload any
}

// ServerToClient is a tagged message the server sends to a controller or agent.
type ServerToClient struct {
	Type    string
	Payload any
}

// clientTag returns the wire "type" tag for a client payload.
func clientTag(payload any) (string, bool) {
	switch payload.(type) {
	case *RegisterAgent, RegisterAgent:
		return "register_agent", true
	case *AgentAuthResponse, AgentAuthResponse:
		return "agent_auth_response", true
	case *Heartbeat, Heartbeat:
		return "heartbeat", true
	case *GuestEndedSession, GuestEndedSession:
		return "guest_ended_session", true
	case *SessionEnded, SessionEnded:
		return "session_ended", true
	case *DirectiveAck, DirectiveAck:
		return "directive_ack", true
	case *HelpRequest, HelpRequest:
		return "help_request", true
	case *HelpCancel, HelpCancel:
		return "help_cancel", true
	case *HelpStatus, HelpStatus:
		return "help_status", true
	case *ConnectRequest, ConnectRequest:
		return "connect_request", true
	case *CandidateMsg, CandidateMsg:
		return "candidate", true
	case *SdpMsg, SdpMsg:
		return "sdp", true
	default:
		return "", false
	}
}

// serverTag returns the wire "type" tag for a server payload.
func serverTag(payload any) (string, bool) {
	switch payload.(type) {
	case *Registered, Registered:
		return "registered", true
	case *AgentAuthChallenge, AgentAuthChallenge:
		return "agent_auth_challenge", true
	case *Brokered, Brokered:
		return "brokered", true
	case *RelayAssignment, RelayAssignment:
		return "relay_assignment", true
	case *IceServers, IceServers:
		return "ice_servers", true
	case *CandidateMsg, CandidateMsg:
		return "candidate", true
	case *SdpMsg, SdpMsg:
		return "sdp", true
	case *Rejected, Rejected:
		return "rejected", true
	case *GuestEndedResult, GuestEndedResult:
		return "guest_ended_result", true
	case *SessionEndedResult, SessionEndedResult:
		return "session_ended_result", true
	case *Directive, Directive:
		return "directive", true
	case *DirectiveAckResult, DirectiveAckResult:
		return "directive_ack_result", true
	case *HelpRequestResult, HelpRequestResult:
		return "help_request_result", true
	case *SessionParticipants, SessionParticipants:
		return "session_participants", true
	default:
		return "", false
	}
}

// marshalTagged marshals payload as a JSON object and injects the discriminant "type" field.
func marshalTagged(tag string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("tagged payload for %q must be a JSON object: %w", tag, err)
	}
	tagRaw, err := json.Marshal(tag)
	if err != nil {
		return nil, err
	}
	fields["type"] = tagRaw
	return json.Marshal(fields)
}

// MarshalJSON implements the discriminated encoding for client messages.
func (m ClientToServer) MarshalJSON() ([]byte, error) {
	tag := m.Type
	if tag == "" {
		t, ok := clientTag(m.Payload)
		if !ok {
			return nil, fmt.Errorf("unknown client payload type %T", m.Payload)
		}
		tag = t
	}
	return marshalTagged(tag, m.Payload)
}

// UnmarshalJSON implements the two-pass discriminated decode for client messages.
func (m *ClientToServer) UnmarshalJSON(data []byte) error {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	m.Type = probe.Type
	var (
		payload any
		err     error
	)
	switch probe.Type {
	case "register_agent":
		var p RegisterAgent
		err = json.Unmarshal(data, &p)
		payload = &p
	case "agent_auth_response":
		var p AgentAuthResponse
		err = json.Unmarshal(data, &p)
		payload = &p
	case "heartbeat":
		var p Heartbeat
		err = json.Unmarshal(data, &p)
		payload = &p
	case "guest_ended_session":
		var p GuestEndedSession
		err = json.Unmarshal(data, &p)
		payload = &p
	case "session_ended":
		var p SessionEnded
		err = json.Unmarshal(data, &p)
		payload = &p
	case "directive_ack":
		var p *DirectiveAck
		p, err = decodeDirectiveAck(data)
		payload = p
	case "help_request":
		var p HelpRequest
		err = json.Unmarshal(data, &p)
		payload = &p
	case "help_cancel":
		var p HelpCancel
		err = json.Unmarshal(data, &p)
		payload = &p
	case "help_status":
		var p HelpStatus
		err = json.Unmarshal(data, &p)
		payload = &p
	case "connect_request":
		var p ConnectRequest
		err = json.Unmarshal(data, &p)
		payload = &p
	case "candidate":
		var p CandidateMsg
		err = json.Unmarshal(data, &p)
		payload = &p
	case "sdp":
		var p SdpMsg
		err = json.Unmarshal(data, &p)
		payload = &p
	default:
		return fmt.Errorf("unknown client message type %q", probe.Type)
	}
	if err != nil {
		return err
	}
	m.Payload = payload
	return nil
}

// MarshalJSON implements the discriminated encoding for server messages.
func (m ServerToClient) MarshalJSON() ([]byte, error) {
	tag := m.Type
	if tag == "" {
		t, ok := serverTag(m.Payload)
		if !ok {
			return nil, fmt.Errorf("unknown server payload type %T", m.Payload)
		}
		tag = t
	}
	return marshalTagged(tag, m.Payload)
}

// UnmarshalJSON implements the two-pass discriminated decode for server messages.
func (m *ServerToClient) UnmarshalJSON(data []byte) error {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	m.Type = probe.Type
	var (
		payload any
		err     error
	)
	switch probe.Type {
	case "registered":
		var p Registered
		err = json.Unmarshal(data, &p)
		payload = &p
	case "agent_auth_challenge":
		var p AgentAuthChallenge
		err = json.Unmarshal(data, &p)
		payload = &p
	case "brokered":
		var p Brokered
		err = json.Unmarshal(data, &p)
		payload = &p
	case "relay_assignment":
		var p RelayAssignment
		err = json.Unmarshal(data, &p)
		payload = &p
	case "ice_servers":
		var p IceServers
		err = json.Unmarshal(data, &p)
		payload = &p
	case "candidate":
		var p CandidateMsg
		err = json.Unmarshal(data, &p)
		payload = &p
	case "sdp":
		var p SdpMsg
		err = json.Unmarshal(data, &p)
		payload = &p
	case "rejected":
		var p Rejected
		err = json.Unmarshal(data, &p)
		payload = &p
	case "guest_ended_result":
		var p GuestEndedResult
		err = json.Unmarshal(data, &p)
		payload = &p
	case "session_ended_result":
		var p SessionEndedResult
		err = json.Unmarshal(data, &p)
		payload = &p
	case "directive":
		var p Directive
		err = json.Unmarshal(data, &p)
		payload = &p
	case "directive_ack_result":
		var p DirectiveAckResult
		err = json.Unmarshal(data, &p)
		payload = &p
	case "help_request_result":
		var p HelpRequestResult
		err = json.Unmarshal(data, &p)
		payload = &p
	case "session_participants":
		var p SessionParticipants
		err = json.Unmarshal(data, &p)
		payload = &p
	default:
		return fmt.Errorf("unknown server message type %q", probe.Type)
	}
	if err != nil {
		return err
	}
	m.Payload = payload
	return nil
}

// grantKeyPinnedFrom derives the agent-reported grant-key posture from its (bounded) feature list
// (audit #9). Nil when the agent did not announce posture_v1: silence is unknown, never "unpinned",
// so an older agent is not mislabelled. The claim is advisory inventory (the agent is the only party
// that knows) and gates nothing here.
func grantKeyPinnedFrom(features []string) *bool {
	if !hasFeature(features, postureFeature) {
		return nil
	}
	v := hasFeature(features, grantKeyPinnedFeature)
	return &v
}

// sessionPolicyRequiredFrom: same derivation as grantKeyPinnedFrom, for the session_policy_required posture.
func sessionPolicyRequiredFrom(features []string) *bool {
	if !hasFeature(features, postureFeature) {
		return nil
	}
	v := hasFeature(features, sessionPolicyReqFeature)
	return &v
}
