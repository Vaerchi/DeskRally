//! Rendezvous/signaling message set (ADR-002). The signaling server is authoritative: agents
//! register their identity + public key + network candidates; controllers ask to reach an
//! agent by DeviceId; the server authorizes and brokers, then issues a RelayToken both sides
//! present to the (dumb, E2E-blind) relay. Peers never self-dial — offer/answer routes here.
//!
//! These are the JSON messages over the signaling connection (WebSocket in v1). The media/data
//! path is separate and E2E-encrypted; the server never sees session plaintext.

use crate::{DeviceId, RelayToken, SessionId};
use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize an untrusted, server-echoed device id without ever failing.
///
/// Anything that is not a well-formed UUID string — an empty id (the broker's echo for an
/// unregistered peer), a `null`, or a value some other client asserted — becomes `None` instead of
/// aborting the enclosing message's decode. Only use this for fields whose value is advisory; an
/// identity that authorizes something must stay strict.
fn lenient_device_id<'de, D: Deserializer<'de>>(de: D) -> Result<Option<DeviceId>, D::Error> {
    let raw = Option::<String>::deserialize(de)?;
    Ok(raw
        .as_deref()
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
        .map(DeviceId))
}

/// Deserialize a server-supplied CONTROL-PLANE session id without ever failing, for the same reason
/// as [`lenient_device_id`]: a hard decode error here would drop the entire `brokered` message.
///
/// Unlike `peer_device`, a value that arrives is NOT merely advisory — the agent binds a session
/// policy to it. That is safe because the failure direction is closed: anything unparseable becomes
/// `None`, and `None` makes the agent REJECT every policy rather than accept an unbound one.
fn lenient_session_uuid<'de, D: Deserializer<'de>>(de: D) -> Result<Option<uuid::Uuid>, D::Error> {
    let raw = Option::<String>::deserialize(de)?;
    Ok(raw.as_deref().and_then(|s| s.parse::<uuid::Uuid>().ok()))
}

/// A `brokered` field the agent must CLASSIFY rather than trust, captured without ever failing the
/// enclosing decode (a decode error drops the whole `brokered` and hangs the agent, see
/// [`lenient_device_id`]). Anything that is neither a string nor an integer is `Malformed`, which the
/// classifier treats as a refusal, never as "absent".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokeredField {
    Text(String),
    Integer(i64),
    Malformed,
}

impl Serialize for BrokeredField {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            BrokeredField::Text(t) => ser.serialize_str(t),
            BrokeredField::Integer(i) => ser.serialize_i64(*i),
            BrokeredField::Malformed => ser.serialize_unit(),
        }
    }
}

/// A PRESENT field (including an explicit `null`) becomes `Some`; only an absent key stays `None`
/// (via `#[serde(default)]`). That distinction is the point: presence of `access_version` is the
/// marker that the server speaks the observer protocol.
fn present_field<'de, D: Deserializer<'de>>(de: D) -> Result<Option<BrokeredField>, D::Error> {
    use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
    struct Field;
    impl<'de> Visitor<'de> for Field {
        type Value = BrokeredField;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E>(self, v: &str) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Text(v.to_owned()))
        }
        fn visit_i64<E>(self, v: i64) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Integer(v))
        }
        fn visit_u64<E>(self, v: u64) -> Result<BrokeredField, E> {
            Ok(i64::try_from(v).map(BrokeredField::Integer).unwrap_or(BrokeredField::Malformed))
        }
        fn visit_f64<E>(self, _: f64) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Malformed)
        }
        fn visit_bool<E>(self, _: bool) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Malformed)
        }
        fn visit_unit<E>(self) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Malformed)
        }
        fn visit_none<E>(self) -> Result<BrokeredField, E> {
            Ok(BrokeredField::Malformed)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<BrokeredField, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(BrokeredField::Malformed)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<BrokeredField, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(BrokeredField::Malformed)
        }
    }
    de.deserialize_any(Field).map(Some)
}

/// How a brokered session may act, as signaling states it (observer design v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokeredAccess {
    /// No `access_version` marker: an older signaling server. Legacy control, which is safe because
    /// the control plane only issues observer tickets to observer-capable agents behind new signaling,
    /// and an observer is a technician already entitled to control (design v2, scope decision).
    Legacy,
    Control,
    /// A view-only OBSERVER: no input, clipboard to the guest, uploads, commands, recording control
    /// or other actuation, from the first frame, and nothing the technician can switch off.
    ViewOnly,
    /// The marker is present but the pair is not exactly `access_version: 1` with `control` or
    /// `view_only`, or `access` arrived without the marker. Never defaults to control: the agent
    /// refuses the session.
    Invalid,
}

/// Classify `brokered.access` / `brokered.access_version`. Pure, so every row is unit-tested.
pub fn classify_brokered_access(access: Option<&BrokeredField>, access_version: Option<&BrokeredField>) -> BrokeredAccess {
    match (access_version, access) {
        (None, None) => BrokeredAccess::Legacy,
        (Some(BrokeredField::Integer(1)), Some(BrokeredField::Text(a))) if a == "control" => BrokeredAccess::Control,
        (Some(BrokeredField::Integer(1)), Some(BrokeredField::Text(a))) if a == "view_only" => BrokeredAccess::ViewOnly,
        _ => BrokeredAccess::Invalid,
    }
}

/// A network candidate for connectivity establishment (ICE-style). The server relays these
/// between peers during hole-punching; it does not connect to them itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Opaque transport-specific address string (e.g. an ICE candidate line).
    pub addr: String,
    pub kind: CandidateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// Directly attached local address.
    Host,
    /// Public address discovered via STUN (server-reflexive).
    ServerReflexive,
    /// Relayed address (TURN / our relay) — the guaranteed fallback.
    Relayed,
}

/// Distinguishes an SDP offer from an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdpKind {
    Offer,
    Answer,
}

/// NAT classification, informs whether a direct path is even possible (symmetric ⇒ relay).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    Unknown,
    Open,
    FullCone,
    RestrictedCone,
    PortRestricted,
    /// Symmetric-to-symmetric essentially always requires a relay.
    Symmetric,
}

/// The claims the control plane signs into a session ticket (ADR-002). Field names are the WIRE
/// contract, byte-shared with `control-plane/ticket.go` and `server/signaling/ticket.go`
/// (`TicketClaims`) and `web/viewer/src/lib/protocol.ts` (`SessionTicketClaims`) — do not rename.
///
/// This is pure carried data: the Rust side never mints or verifies a ticket (the control plane
/// signs, the signaling server verifies), so there is deliberately no crypto here and no new
/// canonical preimage to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTicketClaims {
    /// Canonical claims version; the signaling server accepts only 1.
    pub v: u32,
    pub session_id: String,
    pub technician_id: String,
    pub tenant_id: String,
    pub device_id: String,
    pub iat_ms: i64,
    pub exp_ms: i64,
}

/// A session ticket plus its hex-encoded 64-byte Ed25519 signature over the canonical
/// `RMTTICKETv1` preimage of `claims`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionTicket {
    pub claims: SessionTicketClaims,
    /// Lowercase hex, 128 chars.
    pub sig: String,
}

/// Controller/agent -> signaling server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToServer {
    /// Agent announces itself. `pubkey` is the long-term Ed25519 identity, **bare lowercase hex**
    /// (64 chars) — the same encoding `machine.pubkey` stores, because the server compares the two.
    ///
    /// This message is an *assertion*, not a proof. In enforced mode (M3) the server answers with
    /// an [`ServerToClient::AgentAuthChallenge`] and only registers the connection once the
    /// matching [`ClientToServer::AgentAuthResponse`] verifies against the control-plane-pinned key.
    RegisterAgent {
        device: DeviceId,
        pubkey: String,
        /// Tenant the agent believes it belongs to. **Advisory only**: in enforced mode the server
        /// overwrites it with the tenant the control plane reports for `device`. Sent because dev
        /// mode uses it and it keeps the Rust and Go structs aligned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant: Option<String>,
        nat: NatType,
        /// Optional enrollment token proving this agent is allowed to join this tenant.
        enrollment_token: Option<String>,
        /// The agent's current OS description (same composed string enrollment sends for
        /// `machine.os`). OPTIONAL and advisory inventory, never identity: the signaling server
        /// re-emits it in the presence feed so the control plane can refresh `machine.os` — which
        /// is otherwise WRITE-ONCE at enrollment and goes stale on the first OS upgrade. Absent on
        /// controllers, older agents, and dev peers; the server bounds it (255 bytes) on receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os: Option<String>,
        /// Whether this agent's local `require_session_policy` config flag is set — i.e. whether it
        /// opens every session VIEW-ONLY until a control-plane-signed access policy verifies.
        /// Advisory inventory like `os`, never identity: the signaling server re-emits it in the
        /// presence feed so the control plane can refresh `machine.require_session_policy`
        /// (migrations/0037) and mint the policy that discharges the floor. Without this hop, an
        /// operator who sets the flag on an ALREADY-ENROLLED agent strands it view-only forever.
        ///
        /// TRI-STATE ON PURPOSE. An agent always sends `Some(_)`, INCLUDING `Some(false)`, because
        /// clearing the flag has to reach the control plane too — omitting it when false would leave
        /// a machine flagged forever after the operator turned it off. `None` therefore means "this
        /// peer said nothing about it" (a controller, a dev peer, or a pre-loop-86 agent) and the
        /// control plane leaves the stored value alone, rather than reading silence as `false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        require_session_policy: Option<bool>,
        /// The agent's build identity — `rmt_agent_core::version::AGENT_VERSION`, shaped
        /// `<semver>+<short git sha>` (e.g. `0.0.1+0594362`).
        ///
        /// OPTIONAL and advisory inventory, never identity — the same category as `os`. The
        /// signaling server bounds it on receipt and re-emits it in the presence feed so the control
        /// plane can refresh `machine.agent_version` (migrations/0039). Absent on controllers, on
        /// dev peers, and on any agent built before this field existed.
        ///
        /// WHY IT EXISTS: until it did, "what version is actually deployed out there" was
        /// unanswerable, and every part of agent auto-update (docs/21) depends on that answer — a
        /// rollout that cannot be observed cannot be staged, canaried, soaked or rolled back.
        ///
        /// NEVER AN AUTHORIZATION INPUT. It is asserted by the peer and arrives BEFORE proof of
        /// possession, so it is attacker-controlled on the unauthenticated edge. It is a string for
        /// a human to read. It must never be parsed to decide what an agent may do, and it must
        /// never enter [`crate::agent_auth::agent_auth_signing_bytes`], whose preimage is
        /// byte-pinned to the Go verifier by golden vectors on both sides.
        ///
        /// Absent-not-null, like every optional field on this struct: Go's `omitempty` means the key
        /// is MISSING, and `register_agent_stays_backward_compatible_without_a_tenant` pins that.
        /// The Go half of this contract is `server/signaling/messages.go`'s `RegisterAgent`, pinned
        /// by `TestExactWireShape` in `server/signaling/messages_test.go` — no compiler sees across
        /// the wire, so each side names the other by path on purpose.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_version: Option<String>,
        /// The interactive Windows session user at the time of registration — the username visible in
        /// the Windows login screen or Start menu (e.g. `"CORP\\alice"` or `"alice"`).
        ///
        /// OPTIONAL and advisory inventory, never identity — the same category as `os` and
        /// `agent_version`. The signaling server bounds it on receipt (64 bytes) and re-emits it in
        /// the presence feed so the control plane can refresh `machine.logged_in_user`
        /// (migrations/0048). Absent on controllers, on dev peers, and on any agent built before
        /// this field existed, or when no interactive user is currently logged in.
        ///
        /// The Go half of this contract is `server/signaling/messages.go`'s `RegisterAgent.LoggedInUser`,
        /// pinned by `TestExactWireShape` in `server/signaling/messages_test.go`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        logged_in_user: Option<String>,
        /// Advisory capability flag: whether this agent supports concurrent multi-tech sessions
        /// (multiple controllers connected to the same machine at the same time). Advisory inventory
        /// on the same terms as `os` and `agent_version`: re-emitted in the presence feed so the
        /// control plane can refresh `machine.multi_session_capable`.
        ///
        /// TRI-STATE ON PURPOSE, mirroring `require_session_policy`:
        ///  - `Some(true)`:  agent explicitly claims multi-session support.
        ///  - `Some(false)`: agent explicitly declares it does NOT support concurrent sessions.
        ///  - `None`:        older agent that never sent this field; treated as unknown.
        ///
        /// `None` is absence, not false: a pre-multi-session agent's silence must never clear a
        /// flag the operator already observed. The Go half of this contract is
        /// `server/signaling/messages.go`'s `RegisterAgent.MultiSessionCapable`, pinned by
        /// `TestExactWireShape` in `server/signaling/messages_test.go`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        multi_session_capable: Option<bool>,
        /// Optional protocol features THIS agent understands (docs/65: [`crate::directive::DIRECTIVE_FEATURE`]).
        /// The agent's own assertion, never identity: it only decides what the server may send it. Absent when
        /// empty (the older-agent shape). The Go half is `server/signaling/messages.go`'s `RegisterAgent.Features`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
    },
    /// Proof of possession answering an [`ServerToClient::AgentAuthChallenge`]. `sig` is the
    /// hex-encoded 64-byte Ed25519 signature over
    /// [`crate::agent_auth::agent_auth_signing_bytes`]; `nonce` echoes the challenge's hex nonce.
    AgentAuthResponse {
        device: DeviceId,
        nonce: String,
        sig: String,
    },
    /// Report guest consent ending independently of the viewer's transport. Only an
    /// authenticated agent connection may send this; the server supplies the device identity.
    GuestEndedSession { control_plane_session: uuid::Uuid },
    /// docs/49: one of this agent's sessions ended, for `reason`. Sent ONLY on a connection whose
    /// [`ServerToClient::Registered`] listed [`SESSION_ENDED_FEATURE`]; identity comes from the
    /// authenticated connection, as for `GuestEndedSession`. `queue_age_ms` is how long the
    /// report waited in the agent before this send.
    SessionEnded {
        control_plane_session: uuid::Uuid,
        reason: SessionEndReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_age_ms: Option<u64>,
    },
    /// docs/65 D-C8: the agent's DEVICE-KEY-signed acknowledgement of a fleet directive ([`crate::directive::SignedAck`]).
    /// Sent only on a connection that advertised [`crate::directive::DIRECTIVE_FEATURE`]; signaling forwards every
    /// field verbatim and takes the device id from the authenticated connection.
    DirectiveAck {
        directive_id: String,
        from: String,
        to: String,
        ts_ms: i64,
        detail: String,
        sig: String,
    },
    /// docs/64: ask for a technician. Sent ONLY on a connection whose `Registered` listed [`HELP_REQUEST_FEATURE`];
    /// identity (tenant, device) is the authenticated connection's, never this body. `op_id` is the idempotency key
    /// (1..64 of `[A-Za-z0-9._:-]`); `note` is at most [`HELP_NOTE_MAX_CHARS`] characters and omitted when empty.
    HelpRequest {
        op_id: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        note: String,
    },
    /// docs/64: withdraw exactly one request (the device's own). Same feature gate as [`ClientToServer::HelpRequest`].
    HelpCancel { request_id: String },
    /// docs/64: ask for the device's open (else latest) request. Same feature gate.
    HelpStatus {},
    /// Liveness + keep the NAT mapping fresh. Sent every few seconds.
    Heartbeat { device: DeviceId },
    /// Controller wants to reach an agent. Auth (which controller may reach which device) is
    /// enforced server-side before brokering.
    ///
    /// `ticket` is the control plane's `RMTTICKETv1` session ticket (ADR-002). An ENFORCING
    /// signaling server (started with `SIGNALING_TICKET_PUBKEY`) refuses to broker without a
    /// valid, unexpired, unspent one bound to `target`; a dev server started with
    /// `-insecure-no-ticket-verification` ignores it. Absent ⇒ the key is OMITTED, never `null`,
    /// matching Go's `json:"ticket,omitempty"` (server/signaling/messages.go).
    ConnectRequest {
        target: DeviceId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ticket: Option<SignedSessionTicket>,
    },
    /// Trickle a locally-gathered candidate to the peer via the server.
    Candidate { session: SessionId, candidate: Candidate },
    /// Deliver an SDP offer/answer to the peer via the server (relayed opaquely).
    Sdp {
        session: SessionId,
        sdp: String,
        kind: SdpKind,
    },
}

/// One ICE server as issued by the signaling server, in the shape both peers hand to their WebRTC
/// stack (`RTCIceServer`).
///
/// `username`/`credential` are `None` for STUN and `Some` for TURN. They are deliberately
/// `Option<String>` rather than empty strings so "no credential" and "an empty credential" stay
/// distinguishable — coturn rejects the latter, and a client that sent `""` would look to an
/// operator like a credential that was issued and refused rather than one that was never issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServerSpec {
    /// One or more URLs for the SAME server, e.g. `["turn:turn.example:3478?transport=udp",
    /// "turn:turn.example:3478?transport=tcp"]`. Grouping them lets one credential cover several
    /// transports, which matters on networks that block UDP — the case TURN mostly exists for.
    pub urls: Vec<String>,
    /// TURN username. For coturn's `use-auth-secret` mode this is `<unix-expiry>:<name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// TURN credential (password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// The feature a signaling server lists in `Registered.features` when it forwards
/// [`ClientToServer::SessionEnded`] to a control plane that serves it (docs/49).
pub const SESSION_ENDED_FEATURE: &str = "session_ended_v1";

/// The feature a signaling server lists in `Registered.features` when it forwards the help messages (docs/64) to a
/// control plane that serves them. Never listed for a RETIRED machine's restricted connection (docs/65 D-C1).
pub const HELP_REQUEST_FEATURE: &str = "help_request_v1";
/// Advertised in `register_agent.features` by an agent that reports its enforcement posture (audit #9).
/// Its presence makes the posture features below authoritative: an agent listing this but not
/// [`GRANT_KEY_PINNED_FEATURE`] is stating that it has NO pinned grant issuer key, whereas an older
/// agent that lists neither is merely silent (unknown). Advisory inventory, never identity.
pub const POSTURE_FEATURE: &str = "posture_v1";
/// Advertised (with [`POSTURE_FEATURE`]) only when the agent has pinned the control plane's grant issuer
/// key, i.e. it can verify signed session policy, session leases and grants. Without it those controls are
/// advisory on that machine.
pub const GRANT_KEY_PINNED_FEATURE: &str = "grant_key_pinned";
/// Advertised (with [`POSTURE_FEATURE`]) only when the agent's `require_session_policy` is on: it opens every
/// session view-only until a control-plane-signed policy verifies. A pinned key alone does not make policy
/// mandatory; the console calls a machine "enforced" only when BOTH features are present.
pub const SESSION_POLICY_REQUIRED_FEATURE: &str = "session_policy_required";
/// The longest help note, in characters (signaling's `maxHelpNoteRunes`, the control plane's `helpNoteMaxRunes`).
pub const HELP_NOTE_MAX_CHARS: usize = 200;

/// The agent's view of a help request (no tenant, machine or group ids). Go: `HelpRequestInfo` in `messages.go`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelpRequestInfo {
    pub id: String,
    /// `open`, `accepted`, `cancelled` or `expired` (unknown values must be tolerated).
    pub status: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub expires_at: String,
}

/// Why an agent session ended (docs/49). Recorded in the control plane's audit; it never changes
/// what the end does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    GuestEnded,
    ViewerLeft,
    LeaseLapsed,
    MaxDuration,
    Idle,
    Policy,
    ServiceStop,
    Other,
}

/// Whether a guest-end report may be forgotten or must remain pending for another attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestEndOutcome {
    Ended,
    AlreadyEnded,
    Refused,
    Unavailable,
}

/// Signaling server -> controller/agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToClient {
    /// Acknowledges the control-plane result, so a successful socket send alone never loses
    /// an unprocessed guest-end report.
    GuestEndedResult {
        control_plane_session: uuid::Uuid,
        outcome: GuestEndOutcome,
    },
    /// docs/65: a control-plane-signed fleet directive relayed to an agent that advertised `directive_v1`. The
    /// artifact is opaque here; the AGENT verifies it (signaling is a relay, never an authority).
    Directive { directive_id: String, artifact: String },
    /// Answers a [`ClientToServer::DirectiveAck`]: `applied` and `replay` are terminal successes, `refused` is
    /// terminal, `unavailable` means retry later.
    DirectiveAckResult {
        directive_id: String,
        outcome: String,
        /// The acknowledgement this answers (echoed by signaling): the exact transition and its timestamp, which is the request id.
        /// Optional for robustness; a result WITHOUT the echo is unattributable and must be ignored, never used to settle anything.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_ms: Option<i64>,
    },
    /// Registration accepted; server echoes its own signed identity for pinning.
    ///
    /// `features` lists optional protocol features this connection may use (docs/49:
    /// [`SESSION_ENDED_FEATURE`]). Absent from older servers, hence the default.
    Registered {
        server_pubkey: String,
        #[serde(default)]
        features: Vec<String>,
    },
    /// docs/64: answers help_request, help_cancel and help_status. `outcome` is `ok` (`request` = current state; none on a
    /// status = no request), `refused` (terminal), `limited` (see `retry_after_seconds`), `conflict` (`request` = the state
    /// that won the race), `not_found` or `unavailable` (retry later). `op_id` echoes a help_request's key. Strings, not
    /// enums, so a newer server's outcome never fails the decode (a decode failure drops the message).
    HelpRequestResult {
        #[serde(default)]
        op: String,
        #[serde(default)]
        op_id: String,
        #[serde(default)]
        outcome: String,
        #[serde(default)]
        request: Option<HelpRequestInfo>,
        #[serde(default)]
        retry_after_seconds: u32,
        /// On a help_cancel answer, the request id the answer is ABOUT, for every outcome including `not_found`
        /// (Go: `CancelOf`, omitempty). Empty from an older signaling, whose cancel answers cannot be attributed.
        #[serde(default)]
        cancel_of: String,
    },
    /// Answers a [`ClientToServer::SessionEnded`]; same outcome vocabulary as `GuestEndedResult`.
    SessionEndedResult {
        control_plane_session: uuid::Uuid,
        outcome: GuestEndOutcome,
    },
    /// Prove you hold the private half of the key enrolled for `device` before we register you
    /// (M3). `nonce` is 32 server-chosen random bytes as lowercase hex; `expires_at_ms` is
    /// informational — the server clock is authoritative. Answer with
    /// [`ClientToServer::AgentAuthResponse`]. Controllers ignore this message; not answering
    /// leaves the connection usable but unregistered.
    AgentAuthChallenge {
        device: DeviceId,
        nonce: String,
        expires_at_ms: i64,
    },
    /// A peer wants to connect to you (agent side) or your request was accepted (controller
    /// side). Both sides receive the peer's pinned pubkey + a session id and begin hole-punch.
    Brokered {
        session: SessionId,
        /// The peer's identity as ECHOED by the broker. **Untrusted and optional.**
        ///
        /// It is `None` whenever the far side has no registry entry, which on an ENFORCING
        /// signaling server is the normal state of every controller: controllers never answer the
        /// agent-auth challenge, so they never register and the broker echoes an empty device id
        /// (docs/11-agent-identity-contract.md §2.6). It is also `None` for anything the far side
        /// asserted that is not a UUID — in dev mode `register_agent` takes the device id verbatim.
        ///
        /// This MUST NOT be a hard decode failure. `ServerToClient` is dropped wholesale on a
        /// deserialization error (crates/transport-webrtc/src/signaling.rs), so a strict
        /// `DeviceId` here silently swallowed the whole `brokered` message and hung the agent
        /// until its connect timeout — the exact failure the secure-posture e2e caught. The
        /// technician's authority comes from the M2 session ticket, never from this echo.
        #[serde(default, deserialize_with = "lenient_device_id")]
        peer_device: Option<DeviceId>,
        peer_pubkey: String,
        /// The CONTROL-PLANE session id this rendezvous belongs to, copied from the session ticket
        /// the signaling server verified. **Not the same value as `session`**, which is the broker's
        /// own id for the peer pairing.
        ///
        /// This is the agent's only channel to its own control-plane session id, and it exists so
        /// the agent can BIND a signed session policy to the live session: `SessionPolicy::verify`
        /// compares the policy's `session_id` against this, so a `control` policy captured in an
        /// earlier session cannot be replayed into a later one at the same machine. Before loop 86
        /// nothing needed it, because every `control` policy named an ephemeral attended device id
        /// that would never exist again; migration 0037 ended that, and this replaces it.
        ///
        /// Trustworthy because of WHERE it comes from: signaling only sets it from a ticket whose
        /// control-plane signature it verified, whose target device matched, and which it burned
        /// single-use against a 2-minute TTL. `None` when the server verifies no tickets at all
        /// (`-insecure-no-ticket-verification`, dev/LAN/e2e), when the peer is an older server, or
        /// when the value did not parse — and `None` is FAIL-CLOSED: the agent then rejects every
        /// policy rather than accepting one it cannot bind.
        #[serde(default, deserialize_with = "lenient_session_uuid")]
        control_plane_session: Option<uuid::Uuid>,
        /// The TECHNICIAN this rendezvous belongs to, copied from the same verified session ticket
        /// as `control_plane_session` (loop 91).
        ///
        /// It exists because the agent seals its own audit events: `technician_id` is inside the
        /// hashed canonical preimage, and `POST /audit/ingest` answers **403** unless the id in the
        /// event equals the console user who forwards it. The agent has no other notion of who the
        /// technician is, and the two parties who could volunteer one — the viewer and an unverified
        /// ticket — are exactly the two that must not: a technician naming themselves is the
        /// self-attribution that 403 closes, moved one hop upstream where the 403 cannot see it.
        ///
        /// Trustworthy for the same reason and to the same degree as `control_plane_session`: only
        /// set from a ticket whose control-plane signature signaling verified, whose target device
        /// matched, and which it burned single-use. `None` under `-insecure-no-ticket-verification`,
        /// against an older server, or when the value did not parse — and `None` is FAIL-CLOSED in
        /// the useful direction: the chain is sealed with a nil technician, the control plane refuses
        /// that batch, and the session keeps only its LOCAL trail (helper log, recording sidecar)
        /// rather than gaining a central record attributed to nobody.
        #[serde(default, deserialize_with = "lenient_session_uuid")]
        technician_id: Option<uuid::Uuid>,
        /// The session's ACCESS (`control` or `view_only`), copied by signaling from the verified,
        /// signed session ticket (ticket v2 signs it). Classify with [`classify_brokered_access`]
        /// together with `access_version`; never read it alone.
        #[serde(default, deserialize_with = "present_field", skip_serializing_if = "Option::is_none")]
        access: Option<BrokeredField>,
        /// Marker that the server speaks the observer protocol (always `1` today). Its PRESENCE is what
        /// turns a missing or unknown `access` into a refusal instead of legacy control.
        #[serde(default, deserialize_with = "present_field", skip_serializing_if = "Option::is_none")]
        access_version: Option<BrokeredField>,
    },
    /// Use this relay if a direct path can't be established. Both peers present the token to
    /// the same relay node, which pairs their half-connections.
    ///
    /// **This is the project's own byte-splicing relay, NOT a TURN server** — a distinction that
    /// has already misled documentation once. It pairs two half-connections at the application
    /// layer; it plays no part in ICE. TURN configuration travels in [`ServerToClient::IceServers`].
    RelayAssignment {
        session: SessionId,
        relay_addr: String,
        token: RelayToken,
    },
    /// ICE servers (STUN and/or TURN) for this session, issued by the signaling server.
    ///
    /// # Why the server issues these rather than each peer configuring its own
    ///
    /// TURN credentials should be **short-lived and per-session**. coturn's `use-auth-secret` mode
    /// derives them from a shared secret held only by the server, so a compromised agent config
    /// cannot yield a durable TURN credential — and there is no static password to rotate across a
    /// fleet. A peer that has not been brokered has no business relaying media, so binding issuance
    /// to brokering is also the right authorization boundary.
    ///
    /// # Ordering is load-bearing
    ///
    /// The server MUST send this **before** [`ServerToClient::Brokered`] for the same session. Both
    /// clients build their `RTCPeerConnection` the moment they see `Brokered` — ICE servers cannot
    /// be added to a peer connection afterwards without renegotiation — so a message arriving after
    /// it would be silently useless. WebSocket delivery is ordered per connection, which makes
    /// "send it first" a sufficient guarantee rather than a race.
    ///
    /// # Compatibility
    ///
    /// An older client that does not know this variant fails to deserialize it and **skips the
    /// message** (`crates/transport-webrtc/src/signaling.rs` maps a decode error to `continue`);
    /// the browser's `decodeSignaling` only validates the `type` tag. Either way the peer proceeds
    /// with whatever ICE configuration it had, which is exactly the pre-TURN behaviour. This is why
    /// the servers are a NEW message and not a field on `Brokered`: a malformed addition there
    /// would drop the whole `Brokered` message and hang the peer until its connect timeout — see
    /// the `peer_device` note above, which records that exact failure happening once already.
    IceServers {
        session: SessionId,
        /// In preference order. Empty is legal and means "nothing beyond host candidates".
        servers: Vec<IceServerSpec>,
    },
    /// A trickled candidate from the peer.
    Candidate { session: SessionId, candidate: Candidate },
    /// An SDP offer/answer from the peer (relayed opaquely by the server).
    Sdp {
        session: SessionId,
        sdp: String,
        kind: SdpKind,
    },
    /// Request refused (unknown/offline device, unauthorized, rate-limited).
    Rejected { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_end_messages_match_the_go_wire_contract() {
        let id = uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let msg = ClientToServer::GuestEndedSession { control_plane_session: id };
        let json = r#"{"type":"guest_ended_session","control_plane_session":"11111111-2222-3333-4444-555555555555"}"#;
        assert_eq!(serde_json::to_string(&msg).unwrap(), json);
        assert_eq!(serde_json::from_str::<ClientToServer>(json).unwrap(), msg);

        for (outcome, wire) in [
            (GuestEndOutcome::Ended, "ended"),
            (GuestEndOutcome::AlreadyEnded, "already_ended"),
            (GuestEndOutcome::Refused, "refused"),
            (GuestEndOutcome::Unavailable, "unavailable"),
        ] {
            let msg = ServerToClient::GuestEndedResult {
                control_plane_session: id,
                outcome,
            };
            let json = format!(
                r#"{{"type":"guest_ended_result","control_plane_session":"{id}","outcome":"{wire}"}}"#
            );
            assert_eq!(serde_json::to_string(&msg).unwrap(), json);
            assert_eq!(serde_json::from_str::<ServerToClient>(&json).unwrap(), msg);
        }
    }

    #[test]
    fn session_ended_messages_match_the_go_wire_contract() {
        let id = uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let msg = ClientToServer::SessionEnded {
            control_plane_session: id,
            reason: SessionEndReason::LeaseLapsed,
            queue_age_ms: Some(1500),
        };
        let json = r#"{"type":"session_ended","control_plane_session":"11111111-2222-3333-4444-555555555555","reason":"lease_lapsed","queue_age_ms":1500}"#;
        assert_eq!(serde_json::to_string(&msg).unwrap(), json);
        assert_eq!(serde_json::from_str::<ClientToServer>(json).unwrap(), msg);
        // No age: the field is omitted, as the Go side's omitempty expects.
        let msg = ClientToServer::SessionEnded { control_plane_session: id, reason: SessionEndReason::Other, queue_age_ms: None };
        assert!(!serde_json::to_string(&msg).unwrap().contains("queue_age_ms"));
        for (reason, wire) in [
            (SessionEndReason::GuestEnded, "guest_ended"),
            (SessionEndReason::ViewerLeft, "viewer_left"),
            (SessionEndReason::LeaseLapsed, "lease_lapsed"),
            (SessionEndReason::MaxDuration, "max_duration"),
            (SessionEndReason::Idle, "idle"),
            (SessionEndReason::Policy, "policy"),
            (SessionEndReason::ServiceStop, "service_stop"),
            (SessionEndReason::Other, "other"),
        ] {
            assert_eq!(serde_json::to_string(&reason).unwrap(), format!(r#""{wire}""#));
        }
        let json = format!(r#"{{"type":"session_ended_result","control_plane_session":"{id}","outcome":"already_ended"}}"#);
        assert_eq!(
            serde_json::from_str::<ServerToClient>(&json).unwrap(),
            ServerToClient::SessionEndedResult { control_plane_session: id, outcome: GuestEndOutcome::AlreadyEnded },
        );
    }

    #[test]
    fn registered_features_are_optional_on_the_wire() {
        // An older server sends no features; a newer one lists them.
        let old: ServerToClient = serde_json::from_str(r#"{"type":"registered","server_pubkey":"k"}"#).unwrap();
        assert_eq!(old, ServerToClient::Registered { server_pubkey: "k".into(), features: vec![] });
        let new: ServerToClient = serde_json::from_str(
            r#"{"type":"registered","server_pubkey":"k","features":["session_ended_v1"]}"#,
        ).unwrap();
        assert_eq!(new, ServerToClient::Registered { server_pubkey: "k".into(), features: vec![SESSION_ENDED_FEATURE.into()] });
    }

    #[test]
    fn client_messages_serialize_with_a_type_tag() {
        let msg = ClientToServer::RegisterAgent {
            device: DeviceId::new(),
            pubkey: "ed25519:abc".into(),
            tenant: Some("11111111-2222-3333-4444-555555555555".into()),
            nat: NatType::PortRestricted,
            enrollment_token: Some("tok".into()),
            os: Some("Windows 11 Pro 25H2 (build 26200)".into()),
            require_session_policy: Some(true),
            agent_version: Some("0.4.0+abc1234".into()),
            logged_in_user: Some("CORP\\alice".into()),
            multi_session_capable: Some(true),
            features: vec![],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"register_agent\""));
        assert!(json.contains("\"tenant\":\"11111111-2222-3333-4444-555555555555\""));
        // The os field rides the same message under the same key the Go struct declares.
        assert!(json.contains("\"os\":\"Windows 11 Pro 25H2 (build 26200)\""));
        // So does the floor flag — same key as the Go struct, or the presence refresh never lands.
        assert!(json.contains("\"require_session_policy\":true"));
        // And so does the build identity. THE LITERAL "0.4.0+abc1234" IS SHARED: the Go half of
        // this contract asserts the same string in server/signaling/messages_test.go
        // (TestExactWireShape). Two modules, no shared compiler — the only thing that can keep the
        // key names aligned is one test per side naming the same value.
        assert!(json.contains("\"agent_version\":\"0.4.0+abc1234\""));
        // Same for the logged-in user — the key name must match the Go struct's json tag.
        assert!(json.contains("\"logged_in_user\":\"CORP\\\\alice\""));
        // Same for the multi-session capability flag.
        assert!(json.contains("\"multi_session_capable\":true"));
        let back: ClientToServer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn register_agent_stays_backward_compatible_without_a_tenant() {
        // Peers built before M3 emit no `tenant` key at all — and peers built before the presence
        // os refresh emit no `os` key. Those messages must still decode, and we must not emit a
        // null for an absent field (Go's `omitempty` mirrors this).
        let device = DeviceId::new();
        let json = format!(
            r#"{{"type":"register_agent","device":"{device}","pubkey":"deadbeef","nat":"unknown","enrollment_token":null}}"#
        );
        let back: ClientToServer = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back,
            ClientToServer::RegisterAgent {
                device,
                pubkey: "deadbeef".into(),
                tenant: None,
                nat: NatType::Unknown,
                enrollment_token: None,
                os: None,
                require_session_policy: None,
                agent_version: None,
                logged_in_user: None,
                multi_session_capable: None,
                features: vec![],
            }
        );
        let out = serde_json::to_string(&back).unwrap();
        assert!(!out.contains("tenant"), "an absent tenant is omitted, not serialized as null");
        assert!(!out.contains("\"os\""), "an absent os is omitted, not serialized as null");
        assert!(
            !out.contains("require_session_policy"),
            "an absent floor flag is omitted, not serialized as null"
        );
        // An agent built before this field existed sends no key at all, and MUST NOT be read as
        // reporting an empty version — an empty string would blank a version the control plane
        // already recorded. Absence has to keep meaning "this peer said nothing".
        assert!(
            !out.contains("agent_version"),
            "an absent agent_version is omitted, not serialized as null"
        );
        // Same for logged_in_user: an older agent's silence must never blank a stored user name.
        assert!(
            !out.contains("logged_in_user"),
            "an absent logged_in_user is omitted, not serialized as null"
        );
        // Same for multi_session_capable: an older agent's silence must not blank a stored flag.
        assert!(
            !out.contains("multi_session_capable"),
            "an absent multi_session_capable is omitted, not serialized as null"
        );
    }

    #[test]
    fn register_agent_reports_a_cleared_floor_flag_as_false_not_as_absence() {
        // The flag is TRI-STATE and `Some(false)` must survive the round trip as an explicit false.
        // If it were omitted when false, an operator who turns the flag OFF could never tell the
        // control plane: the machine would stay flagged forever, minting `control` policies for a
        // floor that no longer exists. Absence has to keep meaning "this peer said nothing".
        let device = DeviceId::new();
        let msg = ClientToServer::RegisterAgent {
            device,
            pubkey: "deadbeef".into(),
            tenant: None,
            nat: NatType::Unknown,
            enrollment_token: None,
            os: None,
            require_session_policy: Some(false),
            agent_version: None,
            logged_in_user: None,
            multi_session_capable: None,
            features: vec![],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(
            json.contains("\"require_session_policy\":false"),
            "an explicit false must reach the wire, not be elided: {json}"
        );
        assert_eq!(serde_json::from_str::<ClientToServer>(&json).unwrap(), msg);
    }

    #[test]
    fn directive_messages_have_the_exact_go_wire_shape() {
        // server/signaling/messages.go: type tags directive / directive_ack / directive_ack_result; features is omitted when empty.
        let ack = ClientToServer::DirectiveAck {
            directive_id: "d".into(), from: "issued".into(), to: "accepted".into(), ts_ms: 5, detail: "ok".into(), sig: "ab".into(),
        };
        assert_eq!(
            serde_json::to_string(&ack).unwrap(),
            r#"{"type":"directive_ack","directive_id":"d","from":"issued","to":"accepted","ts_ms":5,"detail":"ok","sig":"ab"}"#
        );
        let d: ServerToClient = serde_json::from_str(r#"{"type":"directive","directive_id":"d","artifact":"{}"}"#).unwrap();
        assert_eq!(d, ServerToClient::Directive { directive_id: "d".into(), artifact: "{}".into() });
        let r: ServerToClient = serde_json::from_str(r#"{"type":"directive_ack_result","directive_id":"d","outcome":"applied"}"#).unwrap();
        assert_eq!(r, ServerToClient::DirectiveAckResult { directive_id: "d".into(), outcome: "applied".into(), from: None, to: None, ts_ms: None });
        let echoed: ServerToClient = serde_json::from_str(r#"{"type":"directive_ack_result","directive_id":"d","outcome":"applied","from":"issued","to":"accepted","ts_ms":77}"#).unwrap();
        assert_eq!(echoed, ServerToClient::DirectiveAckResult { directive_id: "d".into(), outcome: "applied".into(), from: Some("issued".into()), to: Some("accepted".into()), ts_ms: Some(77) });
        let reg = |features: Vec<String>| ClientToServer::RegisterAgent {
            device: DeviceId::new(), pubkey: "k".into(), tenant: None, nat: NatType::Unknown, enrollment_token: None, os: None,
            require_session_policy: None, agent_version: None, logged_in_user: None, multi_session_capable: None, features,
        };
        assert!(!serde_json::to_string(&reg(vec![])).unwrap().contains("features"), "empty features stay off the wire");
        assert!(serde_json::to_string(&reg(vec!["directive_v1".into()])).unwrap().contains(r#""features":["directive_v1"]"#));
    }

    #[test]
    fn help_messages_have_the_exact_go_wire_shape() {
        // server/signaling/messages.go: HelpRequest / HelpCancel / HelpStatus / HelpRequestResult / HelpRequestInfo.
        let req = ClientToServer::HelpRequest { op_id: "op-1".into(), note: "printer".into() };
        assert_eq!(serde_json::to_string(&req).unwrap(), r#"{"type":"help_request","op_id":"op-1","note":"printer"}"#);
        let bare = ClientToServer::HelpRequest { op_id: "op-1".into(), note: String::new() };
        assert_eq!(serde_json::to_string(&bare).unwrap(), r#"{"type":"help_request","op_id":"op-1"}"#, "an empty note is omitted (omitempty)");
        assert_eq!(
            serde_json::to_string(&ClientToServer::HelpCancel { request_id: "r-1".into() }).unwrap(),
            r#"{"type":"help_cancel","request_id":"r-1"}"#
        );
        assert_eq!(serde_json::to_string(&ClientToServer::HelpStatus {}).unwrap(), r#"{"type":"help_status"}"#);
        assert_eq!(serde_json::from_str::<ClientToServer>(r#"{"type":"help_status"}"#).unwrap(), ClientToServer::HelpStatus {});

        let ok: ServerToClient = serde_json::from_str(
            r#"{"type":"help_request_result","op":"help_request","op_id":"op-1","outcome":"ok","request":{"id":"r-1","status":"open","note":"printer","created_at":"2026-11-02T10:00:00Z","expires_at":"2026-11-02T10:30:00Z"}}"#,
        ).unwrap();
        assert_eq!(ok, ServerToClient::HelpRequestResult {
            op: "help_request".into(), op_id: "op-1".into(), outcome: "ok".into(),
            request: Some(HelpRequestInfo { id: "r-1".into(), status: "open".into(), note: "printer".into(), created_at: "2026-11-02T10:00:00Z".into(), expires_at: "2026-11-02T10:30:00Z".into() }),
            retry_after_seconds: 0, cancel_of: String::new(),
        });
        let limited: ServerToClient = serde_json::from_str(r#"{"type":"help_request_result","op":"help_request","outcome":"limited","retry_after_seconds":900}"#).unwrap();
        assert_eq!(limited, ServerToClient::HelpRequestResult {
            op: "help_request".into(), op_id: String::new(), outcome: "limited".into(), request: None, retry_after_seconds: 900, cancel_of: String::new(),
        });
        let cancel: ServerToClient = serde_json::from_str(r#"{"type":"help_request_result","op":"help_cancel","outcome":"not_found","cancel_of":"r-1"}"#).unwrap();
        assert_eq!(cancel, ServerToClient::HelpRequestResult {
            op: "help_cancel".into(), op_id: String::new(), outcome: "not_found".into(), request: None, retry_after_seconds: 0, cancel_of: "r-1".into(),
        });
        // A server that adds fields or outcomes must not break the decode.
        assert!(serde_json::from_str::<ServerToClient>(r#"{"type":"help_request_result","op":"help_status","outcome":"future","extra":1}"#).is_ok());
    }

    fn golden_ticket() -> SignedSessionTicket {
        // The claims half of the cross-module golden fixture pinned in
        // server/signaling/ticket_test.go and control-plane/ticket_test.go.
        SignedSessionTicket {
            claims: SessionTicketClaims {
                v: 1,
                session_id: "22222222-2222-2222-2222-222222222222".into(),
                technician_id: "11111111-1111-1111-1111-111111111111".into(),
                tenant_id: "tenant-golden".into(),
                device_id: "33333333-3333-3333-3333-333333333333".into(),
                iat_ms: 1_730_000_000_000,
                exp_ms: 1_730_000_120_000,
            },
            sig: "b9a0410a9c14acba175a98d04a9a482bde5f08c682b17b708c08268e9eb17df2\
                  5b691924e587403a69d180afcb2d90d4463e0097ed60c46e970c74d65aa78a06"
                .into(),
        }
    }

    #[test]
    fn connect_request_carries_the_ticket_with_gos_field_names() {
        // The wire contract is server/signaling/messages.go's ConnectRequest + ticket.go's
        // SignedSessionTicket/TicketClaims. Every key here must match those json tags exactly,
        // or an enforcing server rejects the request with its deliberately generic reason.
        let target = DeviceId::new();
        let msg = ClientToServer::ConnectRequest {
            target,
            ticket: Some(golden_ticket()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"connect_request\""));
        for key in [
            "\"ticket\":", "\"claims\":", "\"sig\":", "\"v\":1", "\"session_id\":",
            "\"technician_id\":", "\"tenant_id\":", "\"device_id\":",
            "\"iat_ms\":1730000000000", "\"exp_ms\":1730000120000",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
        let back: ClientToServer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn connect_request_omits_an_absent_ticket_and_decodes_the_legacy_shape() {
        // Go's `json:"ticket,omitempty"` means ABSENT, not null — and a pre-ticket peer's
        // message (no `ticket` key at all) must still decode.
        let target = DeviceId::new();
        let msg = ClientToServer::ConnectRequest { target, ticket: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("ticket"), "an absent ticket is omitted, not null: {json}");

        let legacy = format!(r#"{{"type":"connect_request","target":"{target}"}}"#);
        let back: ClientToServer = serde_json::from_str(&legacy).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn agent_auth_challenge_and_response_round_trip() {
        let device = DeviceId::new();
        let nonce = "a0".repeat(32);
        let challenge = ServerToClient::AgentAuthChallenge {
            device,
            nonce: nonce.clone(),
            expires_at_ms: 1_730_000_030_000,
        };
        let json = serde_json::to_string(&challenge).unwrap();
        assert!(json.contains("\"type\":\"agent_auth_challenge\""));
        assert!(json.contains("\"expires_at_ms\":1730000030000"));
        let back: ServerToClient = serde_json::from_str(&json).unwrap();
        assert_eq!(back, challenge);

        let response = ClientToServer::AgentAuthResponse {
            device,
            nonce,
            sig: "b8".repeat(64),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"type\":\"agent_auth_response\""));
        let back: ClientToServer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, response);
    }

    #[test]
    fn agent_auth_challenge_decodes_the_documented_wire_shape() {
        // Byte-for-byte the example in docs/11-agent-identity-contract.md §2.3, which is what the
        // Go server emits. Ids are plain JSON strings, the tag is snake_case.
        let json = r#"{
            "type": "agent_auth_challenge",
            "device": "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7",
            "nonce": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "expires_at_ms": 1730000030000
        }"#;
        match serde_json::from_str::<ServerToClient>(json).unwrap() {
            ServerToClient::AgentAuthChallenge { device, nonce, expires_at_ms } => {
                assert_eq!(device.to_string(), "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7");
                assert_eq!(nonce.len(), 64);
                assert!(crate::agent_auth::decode_nonce_hex(&nonce).is_some());
                assert_eq!(expires_at_ms, 1_730_000_030_000);
            }
            other => panic!("expected an agent_auth_challenge, got {other:?}"),
        }
    }

    #[test]
    fn sdp_message_round_trips_with_snake_case_tag() {
        let s = SessionId::new();
        let offer = ClientToServer::Sdp {
            session: s,
            sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\n".into(),
            kind: SdpKind::Offer,
        };
        let json = serde_json::to_string(&offer).unwrap();
        assert!(json.contains("\"type\":\"sdp\""));
        assert!(json.contains("\"kind\":\"offer\""));
        let back: ClientToServer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, offer);

        let answer = ServerToClient::Sdp {
            session: s,
            sdp: "v=0\r\n".into(),
            kind: SdpKind::Answer,
        };
        let json = serde_json::to_string(&answer).unwrap();
        assert!(json.contains("\"kind\":\"answer\""));
        let back: ServerToClient = serde_json::from_str(&json).unwrap();
        assert_eq!(back, answer);
    }

    fn brokered_access_of(extra: &str) -> BrokeredAccess {
        let sid = SessionId::new().0;
        let json = format!(r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"x"{extra}}}"#);
        match serde_json::from_str::<ServerToClient>(&json).expect("an access field must never fail the decode") {
            ServerToClient::Brokered { access, access_version, .. } => {
                classify_brokered_access(access.as_ref(), access_version.as_ref())
            }
            other => panic!("expected a brokered, got {other:?}"),
        }
    }

    #[test]
    fn brokered_access_is_classified_fail_closed() {
        use BrokeredAccess::*;
        for (extra, want) in [
            ("", Legacy),
            (r#","access":"control","access_version":1"#, Control),
            (r#","access":"view_only","access_version":1"#, ViewOnly),
            // Marker present, access missing / null / empty / unknown / wrong type: refuse.
            (r#","access_version":1"#, Invalid),
            (r#","access":null,"access_version":1"#, Invalid),
            (r#","access":"","access_version":1"#, Invalid),
            (r#","access":"VIEW_ONLY","access_version":1"#, Invalid),
            (r#","access":"admin","access_version":1"#, Invalid),
            (r#","access":7,"access_version":1"#, Invalid),
            // Unknown or malformed marker: refuse, never legacy.
            (r#","access":"view_only","access_version":2"#, Invalid),
            (r##","access":"control","access_version":"1""##, Invalid),
            (r#","access":"control","access_version":null"#, Invalid),
            (r#","access":"control","access_version":1.5"#, Invalid),
            // access without the marker is not something any signaling sends: refuse.
            (r#","access":"view_only""#, Invalid),
            (r#","access":"control""#, Invalid),
        ] {
            assert_eq!(brokered_access_of(extra), want, "brokered extra {extra:?}");
        }
    }

    #[test]
    fn brokered_access_round_trips_and_absent_stays_absent() {
        let msg = ServerToClient::Brokered {
            session: SessionId::new(),
            peer_device: None,
            peer_pubkey: "x".into(),
            control_plane_session: None,
            technician_id: None,
            access: Some(BrokeredField::Text("view_only".into())),
            access_version: Some(BrokeredField::Integer(1)),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""access":"view_only""#) && json.contains(r#""access_version":1"#), "{json}");
        assert_eq!(serde_json::from_str::<ServerToClient>(&json).unwrap(), msg);
        let legacy = ServerToClient::Brokered {
            session: SessionId::new(),
            peer_device: None,
            peer_pubkey: "x".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        };
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(!json.contains("access"), "absent fields must not be serialized: {json}");
    }

    #[test]
    fn brokered_decodes_when_the_peer_has_no_device_id() {
        // REGRESSION: an ENFORCING signaling server never registers a controller (the controller
        // does not answer the agent-auth challenge), so the agent's `brokered` carries
        // `"peer_device": ""`. A strict DeviceId there failed to deserialize, the transport dropped
        // the whole message (`Err(_) => continue`), and the agent hung until its 20 s connect
        // timeout — i.e. the secure posture could not establish a session at all.
        let session = SessionId::new();
        let sid = session.0;
        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"7f{}"}}"#,
            "aa".repeat(31)
        );
        match serde_json::from_str::<ServerToClient>(&json).expect("must decode, not drop") {
            ServerToClient::Brokered { session: got, peer_device, .. } => {
                assert_eq!(got, session, "the session id is what the agent actually needs");
                assert_eq!(peer_device, None);
            }
            other => panic!("expected a brokered, got {other:?}"),
        }

        // Same for anything else the far side may have asserted: dev mode takes `register_agent`'s
        // device id verbatim, so it need not be a UUID at all.
        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"not-a-uuid","peer_pubkey":"x"}}"#
        );
        assert!(matches!(
            serde_json::from_str::<ServerToClient>(&json).expect("must decode"),
            ServerToClient::Brokered { peer_device: None, .. }
        ));

        // A real device id still decodes into a real DeviceId.
        let peer = DeviceId::new();
        let pid = peer.0;
        let json =
            format!(r#"{{"type":"brokered","session":"{sid}","peer_device":"{pid}","peer_pubkey":"x"}}"#);
        assert!(matches!(
            serde_json::from_str::<ServerToClient>(&json).expect("must decode"),
            ServerToClient::Brokered { peer_device: Some(d), .. } if d == peer
        ));
    }


    /// The two IDENTITY fields on `brokered`, decoded on the Rust side — the hop's receiving half.
    ///
    /// There was no Rust test for either of these. Loop 86 added `control_plane_session` and pinned
    /// it only in Go; loop 91 added `technician_id` beside it. Both are read straight out of a
    /// verified session ticket by the signaling server and both are fail-closed on the agent, so the
    /// whole safety argument rests on the DECODE doing three specific things:
    ///
    ///  1. carrying a well-formed value through;
    ///  2. turning a malformed one into `None` rather than dropping the whole message — `brokered` is
    ///     dropped WHOLESALE on a decode error (`Err(_) => continue` in the transport), which is the
    ///     scar the `peer_device` test above records: the agent hung until its connect timeout; and
    ///  3. reading an ABSENT key as `None`, so an older server still brokers.
    ///
    /// They are asserted TOGETHER and cross-checked against each other because they are adjacent
    /// `Option<Uuid>` fields with the same deserializer — a swap would type-check, decode cleanly,
    /// and attribute every audit event in the session to the session's own id.
    #[test]
    fn brokered_carries_the_control_plane_session_and_the_technician() {
        let session = SessionId::new();
        let sid = session.0;
        let cp = "11111111-1111-4111-8111-111111111111";
        let tech = "22222222-2222-4222-8222-222222222222";

        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"x",
                 "control_plane_session":"{cp}","technician_id":"{tech}"}}"#
        );
        match serde_json::from_str::<ServerToClient>(&json).expect("must decode") {
            ServerToClient::Brokered { control_plane_session, technician_id, .. } => {
                assert_eq!(
                    control_plane_session.map(|u| u.to_string()).as_deref(),
                    Some(cp),
                    "the agent binds its session policy to this"
                );
                assert_eq!(
                    technician_id.map(|u| u.to_string()).as_deref(),
                    Some(tech),
                    "the agent stamps this into every audit event it seals"
                );
                // Not the same value, and not the broker's own session id. A field swap here is
                // invisible in every log and produces a whole session's trail attributed to a
                // session rather than a person.
                assert_ne!(control_plane_session, technician_id);
                assert_ne!(control_plane_session.map(|u| u.to_string()), Some(sid.to_string()));
            }
            other => panic!("expected a brokered, got {other:?}"),
        }

        // ABSENT: a server that verifies no tickets emits the pre-loop-86 shape. Both read as
        // "unknown", which is the fail-closed answer on both axes — no policy may bind, and the
        // agent seals a chain nothing will forward rather than one naming the wrong person.
        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"x"}}"#
        );
        assert!(matches!(
            serde_json::from_str::<ServerToClient>(&json).expect("must decode"),
            ServerToClient::Brokered { control_plane_session: None, technician_id: None, .. }
        ));

        // MALFORMED: `None`, and — the part that matters — the message still decodes. A hard decode
        // error here would drop the entire `brokered` and hang the agent, trading an unknown
        // technician for no session at all.
        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"x",
                 "control_plane_session":"not-a-uuid","technician_id":"also-not"}}"#
        );
        assert!(matches!(
            serde_json::from_str::<ServerToClient>(&json)
                .expect("a malformed id must not drop the whole message"),
            ServerToClient::Brokered { control_plane_session: None, technician_id: None, .. }
        ));

        // And explicit JSON null, which is what a Go `omitempty` field set to "" would never emit but
        // a hand-written or proxied message might.
        let json = format!(
            r#"{{"type":"brokered","session":"{sid}","peer_device":"","peer_pubkey":"x",
                 "control_plane_session":null,"technician_id":null}}"#
        );
        assert!(matches!(
            serde_json::from_str::<ServerToClient>(&json).expect("must decode"),
            ServerToClient::Brokered { control_plane_session: None, technician_id: None, .. }
        ));
    }

    /// The `ice_servers` wire shape, pinned on the Rust side.
    ///
    /// NOTE what this does and does not pin. serde emits fields in declaration order, so these
    /// literals are exact for anything Rust *produces*. The Go server does **not** emit the same
    /// byte order: its envelope injects the `type` tag by re-marshalling through a
    /// `map[string]json.RawMessage`, and Go sorts map keys. That is fine — JSON object key order is
    /// not significant and both sides decode by name — so the cross-language contract is the field
    /// NAMES and the omitted-when-absent behaviour, which `server/signaling/turn_test.go` asserts
    /// structurally from the other side.
    #[test]
    fn ice_servers_round_trips_with_and_without_credentials() {
        let s = SessionId::new();

        // `SessionId` has no `Display`; its inner uuid is what serde writes.
        let sid = s.0;

        // STUN: no credentials, and the fields are OMITTED rather than emitted as null — a null
        // username reaches the browser as `username: null`, which is not the same as absent when it
        // is handed to `RTCIceServer`.
        let stun = ServerToClient::IceServers {
            session: s,
            servers: vec![IceServerSpec {
                urls: vec!["stun:stun.example:3478".into()],
                username: None,
                credential: None,
            }],
        };
        let json = serde_json::to_string(&stun).expect("serialize");
        assert_eq!(
            json,
            format!(
                r#"{{"type":"ice_servers","session":"{sid}","servers":[{{"urls":["stun:stun.example:3478"]}}]}}"#
            )
        );
        assert_eq!(serde_json::from_str::<ServerToClient>(&json).expect("decode"), stun);

        // TURN: one credential covering both transports, which is how it is issued in practice.
        let turn = ServerToClient::IceServers {
            session: s,
            servers: vec![IceServerSpec {
                urls: vec![
                    "turn:turn.example:3478?transport=udp".into(),
                    "turn:turn.example:3478?transport=tcp".into(),
                ],
                username: Some("1700000000:rmt".into()),
                credential: Some("bm90LWEtcmVhbC1jcmVk".into()),
            }],
        };
        let json = serde_json::to_string(&turn).expect("serialize");
        assert_eq!(
            json,
            format!(
                r#"{{"type":"ice_servers","session":"{sid}","servers":[{{"urls":["turn:turn.example:3478?transport=udp","turn:turn.example:3478?transport=tcp"],"username":"1700000000:rmt","credential":"bm90LWEtcmVhbC1jcmVk"}}]}}"#
            )
        );
        assert_eq!(serde_json::from_str::<ServerToClient>(&json).expect("decode"), turn);
    }

    /// An empty list is legal and must not be confused with the message being absent: it is the
    /// server saying "I have no ICE servers for you", which a peer answers by using host candidates
    /// only — the LAN case.
    #[test]
    fn an_empty_ice_server_list_is_legal() {
        let s = SessionId::new();
        let sid = s.0;
        let msg = ServerToClient::IceServers { session: s, servers: vec![] };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert_eq!(json, format!(r#"{{"type":"ice_servers","session":"{sid}","servers":[]}}"#));
        assert_eq!(serde_json::from_str::<ServerToClient>(&json).expect("decode"), msg);
    }

    #[test]
    fn broker_and_relay_round_trip() {
        let s = SessionId::new();
        let msg = ServerToClient::RelayAssignment {
            session: s,
            relay_addr: "relay-eu-1.example:4444".into(),
            token: RelayToken(uuid::Uuid::new_v4()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerToClient = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }
}
