//! Real WebRTC data-plane transport (ADR-001/002).
//!
//! Implements [`rmt_agent_core::transport::Transport`] over a webrtc-rs peer connection with a
//! single reliable/ordered SCTP **data channel** carrying length-prefixed [`Frame`]s (the same
//! bytes the relay/loopback transports move). SDP offer/answer is exchanged through the Go
//! signaling server via the shared `rmt_protocol::signaling` messages; ICE uses **non-trickle**
//! gathering (we wait for gathering-complete so the SDP carries host/srflx candidates) — the
//! simplest reliable path for LAN/loopback, and it also works through a STUN server for WAN.
//!
//! Roles:
//! * [`Role::Controller`] initiates (`connect_request`), creates the data channel and the offer.
//! * [`Role::Agent`] registers and answers; its data channel arrives via `on_data_channel`.
//!
//! The E2E crypto lives *above* this in `agent-core::Session`; this transport only ever moves
//! opaque channel-tagged frames (WebRTC's own DTLS is a separate, lower layer).

mod route_iface;
mod signaling;
pub mod tls_trust;
pub mod turn_stream;

#[cfg(test)]
mod inbound_framing_tests;
pub mod audio;
pub mod video;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{Bytes, BytesMut};
use rmt_agent_core::transport::{Transport, TransportError, TransportResult};
pub use rmt_protocol::signaling::BrokeredAccess;
use rmt_protocol::signaling::{
    classify_brokered_access, ClientToServer, NatType, SdpKind, ServerToClient, SignedSessionTicket,
};
use rmt_protocol::{DeviceId, Frame, SessionId};
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use rmt_agent_core::CapturedFrame;

use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_credential_type::RTCIceCredentialType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::{RTCRtpTransceiver, RTCRtpTransceiverInit};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

pub use signaling::{SignalingClient, PING_EVERY as SIGNALING_PING_EVERY, PONG_DEADLINE as SIGNALING_PONG_DEADLINE};

/// Re-exported so a session driver can name the encoder's colour mode without depending on the
/// `video` module path (M11). The `agent_core::quality::ColorMode` → this conversion happens once,
/// in the driver, so neither crate has to know the other's vocabulary.
pub use video::ChromaMode;

/// Which end of the connection this peer is.
pub enum Role {
    /// The controller initiates the session by asking the server to reach `target`.
    Controller {
        target: DeviceId,
        /// The control plane's `RMTTICKETv1` session ticket for this rendezvous (from
        /// `POST /sessions` or an attended session's `/connect`). REQUIRED against an enforcing
        /// signaling server, which otherwise rejects the request with the deliberately generic
        /// "connect request not authorized"; `None` is the dev/LAN path against a server run with
        /// `-insecure-no-ticket-verification`.
        ///
        /// A ticket is SINGLE-USE (the server burns `claims.session_id` on the first successful
        /// broker) and short-lived (2 minutes), so a reconnect needs a freshly minted one.
        ticket: Option<Box<SignedSessionTicket>>,
    },
    /// The agent registers under `device` (with its `pubkey`) and waits to be reached.
    Agent {
        device: DeviceId,
        /// Long-term Ed25519 identity, bare lowercase hex (64 chars) — the encoding the control
        /// plane pins in `machine.pubkey` and the signaling server compares against.
        pubkey: String,
        /// Tenant from enrollment. Required to build the `RMTAGENTAUTHv1` preimage, since the
        /// server binds the tenant it resolved for this device into the signed bytes.
        tenant: Option<String>,
        /// Signs the `RMTAGENTAUTHv1` preimage. `None` ⇒ dev/unauthenticated agent: challenges go
        /// unanswered, which leaves the connection open but unregistered on an enforcing server.
        signer: Option<Arc<dyn ChallengeSigner>>,
        /// Current OS description for `register_agent`'s advisory `os` field (the same composed
        /// string enrollment sends). Inventory, never identity: the signaling server re-emits it
        /// in the presence feed so the control plane can refresh the otherwise write-once
        /// `machine.os`. `None` omits the field on the wire (older-agent shape).
        os: Option<String>,
        /// Whether this agent floors every session until a signed policy verifies (its
        /// `require_session_policy` config flag). Rides the same presence hop as `os` so the
        /// control plane can refresh `machine.require_session_policy` and mint the policy that
        /// discharges the floor. A plain `bool`, not an `Option`: an agent always KNOWS its own
        /// flag, and it must report `false` as loudly as `true` or clearing the flag never
        /// propagates. Only a controller or a dev peer sends nothing (see `rendezvous_announcement`).
        require_session_policy: bool,
        /// This agent's build identity (`rmt_agent_core::version::AGENT_VERSION`), for
        /// `register_agent`'s advisory `agent_version` field. Rides the same presence hop as `os`
        /// so the control plane can refresh `machine.agent_version` — the column that makes "what
        /// is actually deployed out there" answerable, which every part of agent auto-update
        /// depends on (docs/21 §2).
        ///
        /// `Option<String>` and not a plain `String` deliberately, mirroring `os` rather than
        /// `require_session_policy`: this crate must not know the agent's build identity. The value
        /// is supplied by the host (`agent-windows`), and `None` omits the key on the wire, which
        /// is the shape a controller, a dev peer and any pre-loop-96 agent all produce.
        agent_version: Option<String>,
        /// The interactive Windows session user at the time of registration (e.g. `"CORP\\alice"`).
        /// Advisory inventory on the same terms as `os` and `agent_version`: re-emitted in the
        /// presence feed so the control plane can refresh `machine.logged_in_user`
        /// (migrations/0048). `None` when no user is logged in, or for a controller/dev peer, or
        /// when the agent predates this field.
        logged_in_user: Option<String>,
        /// Advisory capability flag: whether this agent supports concurrent multi-tech sessions.
        /// `Some(true)` = explicitly supports it; `Some(false)` = explicitly does not; `None` =
        /// older agent that never sent this field (the pre-multi-session shape). Re-emitted in the
        /// presence feed so the control plane can refresh `machine.multi_session_capable`.
        multi_session_capable: Option<bool>,
        /// Optional protocol features this agent advertises at `register_agent` (docs/65: `directive_v1`, only
        /// when a directive key is pinned). Empty omits the key (older-agent shape).
        features: Vec<String>,
    },
}

impl Role {
    /// A dev/unauthenticated agent: no tenant, no signer, no os. An enforcing signaling server
    /// will never register such a peer (its `agent_auth_challenge` goes unanswered); it exists for
    /// the LAN/loopback and e2e paths that run signaling with `-insecure-no-agent-auth`.
    pub fn dev_agent(device: DeviceId, pubkey: impl Into<String>) -> Self {
        Role::Agent {
            device,
            pubkey: pubkey.into(),
            tenant: None,
            signer: None,
            os: None,
            // A dev peer has no config file, so it asserts nothing about a floor it does not have.
            require_session_policy: false,
            // Nor a build identity to report: a dev peer is a test fixture, not a managed machine,
            // and a fleet view must not gain a row for it.
            agent_version: None,
            // Nor a logged-in user: a dev peer has no interactive session to report.
            logged_in_user: None,
            // A dev peer emits no multi_session_capable: it is a test fixture, not a managed
            // machine, and its absence is the pre-multi-session shape all older agents produce.
            multi_session_capable: None,
            features: Vec::new(),
        }
    }

    /// A controller presenting a control-plane session ticket — the BROKERED path an enforcing
    /// signaling server requires.
    pub fn controller(target: DeviceId, ticket: SignedSessionTicket) -> Self {
        Role::Controller { target, ticket: Some(Box::new(ticket)) }
    }

    /// A controller with NO ticket: only brokered by a signaling server run with
    /// `-insecure-no-ticket-verification` (dev/LAN/e2e).
    pub fn dev_controller(target: DeviceId) -> Self {
        Role::Controller { target, ticket: None }
    }
}

/// The `register_agent` a peer opens the rendezvous with. Factored out of `connect` so a unit test
/// can pin what each role puts on the wire — the agent's advisory `os` in particular: the
/// `machine.os` refresh rides it end to end, and dropping the field here would be invisible to
/// every socket-level test while the whole feature quietly reverted to write-once-at-enrollment.
fn rendezvous_announcement(role: &Role) -> ClientToServer {
    match role {
        // A controller announces a throwaway identity purely so the broker has something to echo;
        // it has no machine row, so it never announces an os.
        Role::Controller { .. } => ClientToServer::RegisterAgent {
            device: DeviceId::new(),
            pubkey: "ed25519:controller".into(),
            tenant: None,
            nat: NatType::Unknown,
            enrollment_token: None,
            os: None,
            require_session_policy: None,
            // A controller has no machine row, so it announces no build identity, user, or
            // capability flags — same argument as `os: None`. If it did, the presence feed would
            // grow a ghost entry.
            agent_version: None,
            logged_in_user: None,
            multi_session_capable: None,
            features: Vec::new(),
        },
        Role::Agent { device, pubkey, tenant, os, require_session_policy, agent_version, logged_in_user, multi_session_capable, features, .. } => ClientToServer::RegisterAgent {
            device: *device,
            pubkey: pubkey.clone(),
            tenant: tenant.clone(),
            nat: NatType::Unknown,
            enrollment_token: None,
            // ALWAYS Some for an agent, including Some(false): the control plane has to be able to
            // learn that the operator CLEARED the flag, and an omitted key means "said nothing".
            require_session_policy: Some(*require_session_policy),
            os: os.clone(),
            agent_version: agent_version.clone(),
            logged_in_user: logged_in_user.clone(),
            multi_session_capable: *multi_session_capable,
            features: features.clone(),
        },
    }
}

/// Signs an agent-auth preimage with the agent's long-term Ed25519 key.
///
/// Kept as a trait so this crate needs no key material and no crypto dependency: the agent host
/// owns the private key and hands in an implementation.
pub trait ChallengeSigner: Send + Sync {
    fn sign(&self, preimage: &[u8]) -> [u8; 64];
}

/// Answer one `agent_auth_challenge`: build the `RMTAGENTAUTHv1` preimage for
/// (device, tenant, nonce) and return the hex-encoded 64-byte signature to put on the wire.
///
/// Returns `None` when the server's nonce is not exactly 32 hex-decoded bytes — the same length the
/// verifier enforces, so we never sign a preimage it would not have built. The tenant is the one
/// enrollment recorded; an absent tenant signs the empty string, which fails verification against a
/// real (tenant-bound) device rather than silently succeeding.
fn sign_agent_auth_challenge(
    signer: &dyn ChallengeSigner,
    device: &DeviceId,
    tenant: Option<&str>,
    nonce_hex: &str,
) -> Option<String> {
    let nonce = rmt_protocol::agent_auth::decode_nonce_hex(nonce_hex)?;
    let preimage = rmt_protocol::agent_auth::agent_auth_signing_bytes(
        &device.to_string(),
        tenant.unwrap_or(""),
        &nonce,
    );
    Some(hex::encode(signer.sign(&preimage)))
}

/// How long to wait, IDLE, for the broker to pair us with a peer.
///
/// **This deliberately does NOT cover the negotiation it triggers** — that is
/// [`NEGOTIATE_TIMEOUT`], and the split is load-bearing. Until 2026-09-04 a single 20s budget
/// wrapped "signaling broker + SDP + ICE + data channel open" together, so the idle wait ATE the
/// negotiation's time: a controller that reached an agent 18s into its window got 2s to complete
/// SDP + ICE + DTLS + data channel, which a WAN/TURN path routinely cannot. The session died with
/// no error on either side — the viewer showed a null `app-error` and no video, the agent logged
/// its ordinary idle line — and it cost ~22% of connects. Measured: failures clustered at a median
/// 3.5s of remaining budget against 13.3s for successes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the negotiation gets ONCE A PEER HAS ACTUALLY ARRIVED — a fresh budget, started at the
/// moment the broker pairs us, never shared with the idle wait above.
///
/// Full-length rather than a few seconds because this is the path that has to survive a relayed
/// TURN candidate on a slow WAN, which is exactly the case the old shared budget starved.
const NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(20);

/// The exact error string [`WebRtcTransport::connect_with_ice`] returns when [`CONNECT_TIMEOUT`]
/// elapses.
///
/// For an AGENT this is the ordinary idle outcome — "no controller asked for me in the last 20s" —
/// not a fault, and a caller's reconnect loop must not treat it as one. It is a public constant so
/// that classification has a single source of truth instead of a duplicated literal (an agent that
/// misclassifies it backs off exponentially while perfectly healthy and stops being reachable).
pub const CONNECT_TIMED_OUT: &str = "webrtc connect timed out";

/// Returned when a peer WAS brokered to us but the negotiation did not complete within
/// [`NEGOTIATE_TIMEOUT`].
///
/// Distinct from [`CONNECT_TIMED_OUT`] on purpose: that one means "nobody asked for me", this one
/// means "someone asked and we failed them", which is a real failure and must be visible. It was
/// previously indistinguishable from the idle case, which is the main reason the ~22% went
/// undiagnosed for days. A reconnect loop should still NOT back off exponentially on it — the peer
/// is gone either way and staying registered is what keeps the machine reachable — but it must say
/// so loudly rather than logging the ordinary idle line.
pub const NEGOTIATE_TIMED_OUT: &str = "webrtc negotiation timed out after broker";

/// How long [`WebRtcTransport::register_for_mux`] waits for a `Registered` reply before assuming
/// the server predates that message and proceeding.
///
/// Old signaling servers never send `Registered`. The timeout must be large enough to survive a
/// slow server under load but small enough not to stall the helper start. 3 s is generous for a
/// co-located server and almost irrelevant on the reconnect path (auth challenge + Registered
/// typically round-trip in a few milliseconds on LAN).
const REGISTER_FOR_MUX_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a brokered session may wait for its controller to open the data channel (see
/// `from_brokered`). A live controller does it in seconds, non-trickle gathering included; one that
/// has not by now has abandoned the session.
const BROKERED_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
static BROKERED_OPEN_TIMEOUT_TEST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn brokered_open_timeout() -> Duration {
    #[cfg(test)]
    {
        let ms = BROKERED_OPEN_TIMEOUT_TEST_MS.load(std::sync::atomic::Ordering::SeqCst);
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    BROKERED_OPEN_TIMEOUT
}

/// A STUN/TURN ICE server for WAN NAT traversal (ADR-002), in this crate's own vocabulary so
/// callers don't depend on webrtc-rs types.
///
/// For LAN/loopback none are needed (host candidates suffice) — that's why [`WebRtcTransport::connect`]
/// uses an empty set. For WAN, add a **STUN** server so peers learn their server-reflexive
/// candidates, and a **TURN** server (with credentials) as the relayed last resort for symmetric
/// NAT. In production the TURN entry comes from the signaling server's `RelayAssignment` (a
/// short-lived credential), not a static config.
#[derive(Debug, Clone)]
pub struct IceServer {
    /// One or more URLs for the same server, e.g. `stun:stun.example:3478` or
    /// `turn:turn.example:3478?transport=udp`.
    pub urls: Vec<String>,
    /// TURN username (omitted for STUN).
    pub username: Option<String>,
    /// TURN credential/password (omitted for STUN).
    pub credential: Option<String>,
}

impl IceServer {
    /// A STUN server (no credentials): peers use it to discover their server-reflexive candidates.
    pub fn stun(url: impl Into<String>) -> Self {
        Self { urls: vec![url.into()], username: None, credential: None }
    }

    /// A TURN server with long-term credentials: relays media when direct/reflexive paths fail
    /// (symmetric NAT). Prefer short-lived credentials from the signaling `RelayAssignment`.
    pub fn turn(url: impl Into<String>, username: impl Into<String>, credential: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    fn to_rtc(&self) -> RTCIceServer {
        // `credential_type` MUST be `Password` whenever a credential is present.
        //
        // It defaults to `RTCIceCredentialType::Unspecified`, and webrtc-rs validates ICE servers
        // when the peer connection is built: a TURN URL carrying credentials of an unspecified type
        // is rejected outright with "invalid turn server credentials", which fails the ENTIRE
        // connect — not just the relay path. So `..Default::default()` here silently made TURN
        // unusable while every unit test still passed; it took an end-to-end run against a
        // TURN-configured signaling server to surface it.
        //
        // STUN entries must keep `Unspecified`: setting `Password` with empty credentials fails the
        // same validation from the other direction.
        let credential_type = if self.username.is_some() && self.credential.is_some() {
            RTCIceCredentialType::Password
        } else {
            RTCIceCredentialType::Unspecified
        };
        RTCIceServer {
            urls: self.urls.clone(),
            username: self.username.clone().unwrap_or_default(),
            credential: self.credential.clone().unwrap_or_default(),
            credential_type,
        }
    }

    /// Whether this entry is a TURN (relay) server rather than STUN.
    ///
    /// Used for logging how many relay candidates a session was given, which is the first thing
    /// worth knowing when a WAN connect fails: "0 relay servers" and "the relay was refused" look
    /// identical from the outside otherwise.
    pub fn is_turn(&self) -> bool {
        self.urls
            .iter()
            .any(|u| u.starts_with("turn:") || u.starts_with("turns:"))
    }
}

/// A connected WebRTC transport. Holds the peer connection alive and bridges the inbound data
/// channel into a channel that [`Transport::recv_frame`] awaits.
/// The two identity fields a `brokered` message vouches for.
///
/// Both come from ONE session ticket whose control-plane signature the signaling server verified,
/// whose target device it matched, and which it burned single-use — so they are trustworthy to
/// exactly the same degree and for exactly the same reason, and neither is ever taken from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrokeredIdentities {
    /// The CONTROL-PLANE session id, which a signed session policy and an elevation grant bind to.
    pub control_plane_session: Option<uuid::Uuid>,
    /// The TECHNICIAN, which the agent stamps into the hashed preimage of every audit event it seals
    /// for this session.
    pub technician: Option<uuid::Uuid>,
    /// How the session may act (observer design v2), classified from `access` + `access_version`
    /// copied by signaling from the same verified ticket. The AGENT enforces it: `Invalid` refuses the
    /// session and `ViewOnly` starts it under the non-revocable observer floor.
    pub access: BrokeredAccess,
}

impl Default for BrokeredIdentities {
    /// What every non-`brokered` message yields. Only the `Brokered` arm ever READS the identities,
    /// so the `access` here is never consulted; `Legacy` matches a server that vouched for nothing.
    fn default() -> Self {
        Self { control_plane_session: None, technician: None, access: BrokeredAccess::Legacy }
    }
}

/// Read the identities off a signaling message: both `None` for anything that is not `brokered`, and
/// for a `brokered` from a server that vouched for neither.
///
/// **This function exists to be testable, not to be reusable.** Reading the two fields inline at the
/// capture site was correct code and completely unguarded: they are adjacent `Option<Uuid>` fields
/// with the same lenient deserializer, so exchanging them type-checks, decodes cleanly, logs
/// plausibly, and produces a whole session's audit trail attributed to the session's own id instead
/// of to a person. Nothing downstream — not the control plane, which only compares the technician to
/// the authenticated forwarder and would simply 403 — could tell you which of the two mistakes you
/// had made. Pulling the read into one pure function makes a swap a unit-test failure.
pub(crate) fn brokered_identities(msg: &ServerToClient) -> BrokeredIdentities {
    match msg {
        ServerToClient::Brokered { control_plane_session, technician_id, access, access_version, .. } => {
            BrokeredIdentities {
                control_plane_session: *control_plane_session,
                technician: *technician_id,
                access: classify_brokered_access(access.as_ref(), access_version.as_ref()),
            }
        }
        _ => BrokeredIdentities::default(),
    }
}

pub struct WebRtcTransport {
    pc: Arc<RTCPeerConnection>,
    dc: Arc<RTCDataChannel>,
    inbound: mpsc::Receiver<Frame>,
    /// Agent side: the encoder thread's single, totally-ordered command queue. Frames and control
    /// commands (bitrate, chroma, keyframe) share it so a retarget lands cleanly *between* frames
    /// rather than racing one.
    video_in: Option<mpsc::UnboundedSender<EncoderCommand>>,
    /// Agent side: shared counters the RTCP loop, the encoder thread and the session driver read.
    video_rate: Option<Arc<VideoRateState>>,
    /// Controller side: payload sizes of inbound AUDIO RTP packets — proof the Opus track flows.
    /// Deliberately just the size: nothing on this side decodes audio (the browser does), so
    /// carrying the payload would be storing bytes no one reads.
    audio_rtp: Option<mpsc::UnboundedReceiver<usize>>,
    /// Agent side: PCM into the Opus encoder thread. `None` when the session opened without audio
    /// (the controller side, or an agent whose audio capture is off/unavailable).
    audio_in: Option<mpsc::UnboundedSender<Vec<f32>>>,
    /// Controller side: RTP video payloads received on the inbound track (proof of flow, plus the
    /// payload type each one actually carried).
    video_rtp: Option<mpsc::UnboundedReceiver<VideoRtpPacket>>,
    /// Controller side: the SSRC of the inbound video track, learned from the first RTP packet.
    /// Needed to address RTCP back at the sender.
    video_ssrc: Option<Arc<std::sync::atomic::AtomicU32>>,
    /// Controller side: the codec the inbound video track was negotiated as. `None` until the
    /// first `on_track` fires.
    video_codec: Option<Arc<Mutex<Option<NegotiatedVideoCodec>>>>,
    /// The CONTROL-PLANE session id this connection belongs to, as reported on `brokered` by a
    /// signaling server that VERIFIED a session ticket. `None` when the server verifies no tickets
    /// (dev/LAN/e2e), when it predates the field, or when the value did not parse.
    ///
    /// Distinct from the broker's own `session` id, which pairs the two peers and means nothing to
    /// the control plane. Retained because it is the agent's only way to bind a signed session
    /// policy to the session it is actually serving.
    control_plane_session: Option<uuid::Uuid>,
    /// The TECHNICIAN this connection was brokered for, from the same verified ticket (loop 91).
    /// `None` under exactly the same conditions as `control_plane_session`, and with the same
    /// fail-closed reading: the agent seals its audit chain with a nil technician, which the control
    /// plane then refuses rather than storing an unattributed record.
    session_technician: Option<uuid::Uuid>,
    /// The session's access as signaling stated it (observer design v2); see [`Self::session_access`].
    session_access: BrokeredAccess,
    /// Set once the peer connection reaches a terminal state (or the data channel closes).
    ///
    /// The inbound frame channel CANNOT signal this by itself: its sender is cloned into the
    /// `on_message` / `on_data_channel` callbacks, which the peer-connection objects own, so it stays
    /// alive for as long as the transport does and `inbound.recv()` would simply block forever after
    /// the peer went away. Without this flag `recv_frame` never returned `Closed`, so an agent had no
    /// way to learn its controller had left.
    peer_gone: Arc<std::sync::atomic::AtomicBool>,
    /// Woken alongside `peer_gone` so a `recv_frame` already parked on `inbound.recv()` returns
    /// promptly instead of waiting for a frame that will never come.
    peer_gone_notify: Arc<Notify>,
    /// The host-candidate restriction fallback for this connection's ICE attempt (see
    /// [`IceAttempt`]). Only its `Drop` matters.
    _ice_attempt: IceAttempt,
}

/// A cloneable handle that resolves once the transport's peer connection has gone terminal (or its
/// data channel closed) — the same signal that makes [`Transport::recv_frame`] return `Closed`.
///
/// It exists for a caller that has STOPPED calling `recv_frame` but still needs to learn the peer
/// left: the agent's session loop stops reading input after a failed data-channel send yet keeps
/// streaming video, and video sends only queue, so nothing else would ever tell it to stop. Holding
/// this handle borrows nothing from the transport, so it can sit in the same `select!` as an arm that
/// holds `&mut transport`.
#[derive(Clone)]
pub struct PeerGone {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl PeerGone {
    /// Whether the peer has already gone.
    pub fn is_gone(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Resolve once the peer has gone; immediately if it already has.
    ///
    /// The waiter is ENABLED before the flag is read. `notify_waiters` stores no permit, so reading
    /// the flag first would leave a window in which the flag is set and the wake-up delivered between
    /// the read and the registration — a wake-up nobody receives, and a wait that never ends.
    pub async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_gone() {
                return;
            }
            notified.await;
        }
    }
}

/// How long a peer connection may stay `Disconnected` before the session treats the peer as gone.
///
/// `Disconnected` is NOT terminal: ICE enters it after a few seconds without consent responses and
/// returns to `Connected` by itself when packets flow again. Treating it as terminal ended a live
/// session on every short network blip: a 4 s route loss in the lab VM (2026-10-23, run N) ended the
/// session as "viewer left" 2 s after the first failed send, while the viewer was still there. A peer
/// that is really gone either closes the data channel (a browser navigating away, at once) or stays
/// `Disconnected` past this grace and then reaches `Failed`; whichever comes first ends the session.
const DISCONNECTED_GRACE: Duration = Duration::from_secs(10);

/// Turns peer-connection state changes into the [`PeerGone`] signal.
///
/// `Failed` and `Closed` mark the peer gone at once. `Disconnected` starts a grace timer that marks it
/// gone only if no later state change has arrived when the timer fires.
///
/// ONE lock serialises every state change and the timer's commit: the timer re-checks the epoch and
/// marks the peer gone while holding it, so a recovery can never land between "still disconnected?"
/// and "end the session" (Codex round 2: with a bare atomic, a recovery in that window ended a
/// session that had already recovered). The grace is measured from the FIRST Disconnected of a run:
/// a repeated Disconnected callback does not extend it.
struct PeerStateWatch {
    gone: PeerGone,
    grace: Duration,
    state: Arc<std::sync::Mutex<WatchState>>,
}

#[derive(Default)]
struct WatchState {
    epoch: u64,
    disconnected_at: Option<Instant>,
}

impl PeerStateWatch {
    fn new(gone: PeerGone, grace: Duration) -> Self {
        Self { gone, grace, state: Arc::new(std::sync::Mutex::new(WatchState::default())) }
    }

    fn mark_gone(gone: &PeerGone) {
        gone.flag.store(true, Ordering::Relaxed);
        gone.notify.notify_waiters();
    }

    fn on_state(&self, s: RTCPeerConnectionState) {
        let mut st = self.state.lock().expect("peer state lock");
        st.epoch += 1;
        let epoch = st.epoch;
        match s {
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                st.disconnected_at = None;
                Self::mark_gone(&self.gone);
            }
            RTCPeerConnectionState::Disconnected => {
                let first = *st.disconnected_at.get_or_insert_with(Instant::now);
                let remaining = self.grace.saturating_sub(first.elapsed());
                tracing::warn!(grace_ms = self.grace.as_millis() as u64, remaining_ms = remaining.as_millis() as u64,
                    "peer connection disconnected; waiting for ICE to recover before ending the session");
                let (gone, state) = (self.gone.clone(), self.state.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(remaining).await;
                    let st = state.lock().expect("peer state lock");
                    if st.epoch == epoch {
                        tracing::warn!("peer connection stayed disconnected past the grace; ending the session");
                        Self::mark_gone(&gone);
                    }
                });
            }
            _ => {
                if let Some(since) = st.disconnected_at.take() {
                    tracing::info!(state = %s, disconnected_ms = since.elapsed().as_millis() as u64,
                        "peer connection recovered from disconnected");
                }
            }
        }
    }
}

impl WebRtcTransport {
    /// A handle on this transport's peer-gone signal. See [`PeerGone`].
    pub fn peer_gone(&self) -> PeerGone {
        PeerGone { flag: self.peer_gone.clone(), notify: self.peer_gone_notify.clone() }
    }

    /// Establish a session through the signaling server at `signaling_url`, using host candidates
    /// only (LAN/loopback). For WAN, use [`WebRtcTransport::connect_with_ice`] with STUN/TURN.
    pub async fn connect(signaling_url: &str, role: Role) -> Result<Self, String> {
        Self::connect_with_ice(signaling_url, role, Vec::new()).await
    }

    /// Like [`connect`](Self::connect) but with STUN/TURN [`IceServer`]s for WAN NAT traversal.
    /// Pass an empty `ice` for LAN/loopback (identical to `connect`).
    pub async fn connect_with_ice(
        signaling_url: &str,
        role: Role,
        ice: Vec<IceServer>,
    ) -> Result<Self, String> {
        // TWO deadlines, in sequence, never one shared budget — see the [`CONNECT_TIMEOUT`] and
        // [`NEGOTIATE_TIMEOUT`] docs for the ~22%-of-connects bug that a single budget caused.
        //
        // Phase 1 is the IDLE wait: run the connect until either it finishes on its own (a
        // controller's connect completes here), the idle deadline fires, or `connect_inner` tells
        // us a peer has been brokered. Phase 2 hands the SAME in-flight future a fresh budget, so
        // the negotiation's clock starts when the peer arrives rather than when we started waiting.
        Self::connect_with_ice_timeouts(signaling_url, role, ice, CONNECT_TIMEOUT, NEGOTIATE_TIMEOUT)
            .await
    }

    /// [`connect_with_ice`](Self::connect_with_ice) with both deadlines supplied, so a test can make
    /// the idle window short enough to demonstrate the split deterministically.
    ///
    /// Hidden rather than private because the crate's e2e tests live outside it. **A test that
    /// injects both budgets does not exercise the shipped ones** — the constants themselves need a
    /// test that calls [`connect`](Self::connect), or a zeroed default would sail through exactly
    /// as the "untested shipped constant" lesson describes.
    #[doc(hidden)]
    pub async fn connect_with_ice_timeouts(
        signaling_url: &str,
        role: Role,
        ice: Vec<IceServer>,
        idle: Duration,
        negotiate: Duration,
    ) -> Result<Self, String> {
        let (brokered_tx, mut brokered_rx) = tokio::sync::oneshot::channel();
        let mut fut = std::pin::pin!(Self::connect_inner(signaling_url, role, ice, Some(brokered_tx)));
        {
            let mut idle = std::pin::pin!(tokio::time::sleep(idle));
            tokio::select! {
                // Biased so a ready result is taken before an equally-ready deadline: at the
                // exact boundary the honest answer is "it connected", not "it timed out".
                biased;
                res = fut.as_mut() => return res,
                // A dropped sender (`connect_inner` returned without brokering) resolves Err
                // here; leaving phase 1 is still right, because `fut` is then already finishing
                // and phase 2's timeout will simply observe it.
                _ = &mut brokered_rx => {},
                _ = idle.as_mut() => return Err(CONNECT_TIMED_OUT.to_string()),
            }
        }
        tokio::time::timeout(negotiate, fut)
            .await
            .map_err(|_| NEGOTIATE_TIMED_OUT.to_string())?
    }

    /// `brokered_tx` fires the instant the broker pairs us with a peer, which is the seam where
    /// [`connect_with_ice`](Self::connect_with_ice) swaps the idle deadline for a fresh negotiation
    /// one. Everything before that signal is waiting; everything after it is work.
    async fn connect_inner(
        signaling_url: &str,
        role: Role,
        ice: Vec<IceServer>,
        brokered_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<Self, String> {
        let mut brokered_tx = brokered_tx;
        let (sig, mut sig_in) = SignalingClient::connect(signaling_url).await?;
        let is_controller = matches!(role, Role::Controller { .. });
        let tag0 = if is_controller { "controller" } else { "agent" };

        // Agent-auth material (M3). `None` for a controller — controllers never answer a challenge,
        // and under the identity contract they simply never become registry entries on an enforcing
        // server. `None` for an agent with no signer too: the unauthenticated dev/LAN path.
        let agent_auth: Option<(Option<String>, Arc<dyn ChallengeSigner>)> = match &role {
            Role::Agent { tenant, signer: Some(signer), .. } => {
                Some((tenant.clone(), signer.clone()))
            }
            _ => None,
        };

        // Kick off the rendezvous. Both peers announce an identity so the broker has something to
        // echo as `Brokered.peer_device`. That echo is advisory only: on an ENFORCING server a
        // controller never becomes a registry entry, so the agent's copy is empty — which the
        // protocol tolerates by design (see the `peer_device` doc in rmt-protocol's signaling.rs).
        sig.send(rendezvous_announcement(&role))?;
        if let Role::Controller { target, ticket } = &role {
            sig.send(ClientToServer::ConnectRequest {
                target: *target,
                ticket: ticket.as_deref().cloned(),
            })?;
        }
        tracing::debug!(role = tag0, "signaling: rendezvous started");

        // Wait for the broker to pair us and hand back a session id (ignore Registered / relay
        // assignment on the way), answering an agent-auth challenge if one arrives first.
        //
        // ICE servers issued by the server arrive HERE, before `brokered`, and are captured into
        // this slot — see the ordering note on `ServerToClient::IceServers`. They cannot be applied
        // after the peer connection is built, so there is nowhere else they could be collected.
        let mut issued_ice: Vec<IceServer> = Vec::new();
        // Declared without an initializer, deliberately: the ONLY path out of the loop below that
        // reaches the code after it is the `Brokered` arm, which assigns this first. An `= None`
        // initializer compiled to a dead store (`unused_assignments`) and, worse, read as though
        // some other exit could leave it unset — which would be a fail-OPEN default for a value the
        // session policy and the elevation grant both bind to.
        let control_plane_session: Option<uuid::Uuid>;
        // Same no-initializer discipline, same reason: the `Brokered` arm is the only way out, and an
        // `= None` default here would be a silently-unattributed audit chain rather than a loud one.
        let session_technician: Option<uuid::Uuid>;
        // Same discipline again: an `= Legacy` default would be a fail-OPEN reading for an observer.
        let session_access: BrokeredAccess;
        let session: SessionId = loop {
            let msg = sig_in.recv().await.ok_or("signaling closed before broker")?;
            // `brokered_identities` reads the two identity fields off the WHOLE message, so borrow it
            // before the match moves the variant's fields out.
            let ids = brokered_identities(&msg);
            match msg {
                ServerToClient::AgentAuthChallenge { device, nonce, .. } => {
                    // Prove possession of the enrolled key. Any *local* failure (no signer, a
                    // malformed nonce) just keeps us waiting — the connect timeout is the bound and
                    // a fabricated signature would be worse than none. An enforcing server closes
                    // the socket on a bad proof, which surfaces here as "closed before broker".
                    let Some((tenant, signer)) = agent_auth.as_ref() else {
                        tracing::debug!(role = tag0, "signaling: agent_auth_challenge ignored (no signer)");
                        continue;
                    };
                    let Some(proof) =
                        sign_agent_auth_challenge(signer.as_ref(), &device, tenant.as_deref(), &nonce)
                    else {
                        tracing::warn!(role = tag0, "signaling: agent_auth_challenge nonce is not 32 hex bytes");
                        continue;
                    };
                    sig.send(ClientToServer::AgentAuthResponse { device, nonce, sig: proof })?;
                    tracing::debug!(role = tag0, %device, "signaling: answered agent_auth_challenge");
                    continue;
                }
                ServerToClient::IceServers { servers, .. } => {
                    issued_ice = servers
                        .into_iter()
                        .map(|s| IceServer {
                            urls: s.urls,
                            username: s.username,
                            credential: s.credential,
                        })
                        .collect();
                    tracing::debug!(
                        role = tag0,
                        count = issued_ice.len(),
                        "signaling: received ICE servers"
                    );
                    continue;
                }
                ServerToClient::Brokered { session, .. } => {
                    // Captured, not merely logged: the agent binds its session policy to the session
                    // id and stamps the technician into every audit event it seals. A server that
                    // sends neither leaves both None, which is the FAIL-CLOSED reading on both axes.
                    //
                    // Read through `brokered_identities` rather than destructured here, so that a
                    // SWAP of the two is a test failure instead of a silent misattribution: they are
                    // adjacent `Option<Uuid>` fields, so exchanging them type-checks, decodes
                    // cleanly, logs plausibly, and attributes a whole session's audit trail to the
                    // session's own id. Nothing downstream could tell.
                    control_plane_session = ids.control_plane_session;
                    session_technician = ids.technician;
                    session_access = ids.access;
                    let cp = control_plane_session;
                    tracing::debug!(
                        role = tag0,
                        cp_session = cp.map(|u| u.to_string()).unwrap_or_else(|| "<none>".into()),
                        "signaling: brokered"
                    );
                    // The idle wait is over and the negotiation starts HERE. Tell the wrapper so it
                    // can start a fresh clock; a send error just means nobody is listening (the
                    // no-timeout paths), which is fine.
                    if let Some(tx) = brokered_tx.take() {
                        let _ = tx.send(());
                    }
                    break session;
                }
                ServerToClient::Rejected { reason } => return Err(format!("rejected: {reason}")),
                _ => continue,
            }
        };

        // Build the peer connection. LAN/loopback needs no ICE servers (host candidates); for WAN
        // we use whatever the signaling server issued for this session (STUN, and TURN with
        // short-lived credentials) plus anything the caller configured statically.
        //
        // Server-issued entries come FIRST because ICE tries them in order and the server knows the
        // deployment's own STUN/TURN, which a caller's static list generally does not. Both are
        // kept rather than one overriding the other: the static list is how a LAN/dev caller (and
        // the e2e harness) supplies servers when no signaling-issued ones exist, and dropping it
        // whenever the server sent an empty list would silently disable it.
        let tag = if is_controller { "controller" } else { "agent" };
        let mut effective_ice = issued_ice;
        effective_ice.extend(ice.iter().cloned());
        tracing::info!(
            role = tag,
            ?session,
            ice_total = effective_ice.len(),
            ice_relay = effective_ice.iter().filter(|s| s.is_turn()).count(),
            "signaling: brokered"
        );
        let rtc_config = RTCConfiguration {
            ice_servers: effective_ice.iter().map(IceServer::to_rtc).collect(),
            ..Default::default()
        };

        // Build the API with a media engine that knows VP8 (for the video track) plus the
        // default interceptors (RTP/RTCP, NACK, etc.). webrtc-rs's default codec set already
        // includes VP8 at payload type 96, clock rate 90000, empty fmtp — exactly what
        // `video::NEGOTIATED_MIME_TYPE` asks for — so no explicit `register_codec` is needed.
        let mut media = MediaEngine::default();
        media.register_default_codecs().map_err(|e| e.to_string())?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media).map_err(|e| e.to_string())?;
        // TURN over TCP/TLS for relay gathering (turn_stream.rs), registered before the first peer.
        turn_stream::install();
        let (api, ice_restricted) = build_api(media, registry, sig.ice_route_ip(), effective_ice.iter().any(IceServer::is_turn), tag);
        let pc = Arc::new(
            api.new_peer_connection(rtc_config)
                .await
                .map_err(|e| e.to_string())?,
        );
        let ice_attempt = log_ice_path(&pc, tag, ice_restricted);

        // Video media track: the controller offers a recvonly video m-line; the agent fills it
        // with a sendonly VP8 track. (The browser controller already adds this transceiver.)
        let mut video_in: Option<mpsc::UnboundedSender<EncoderCommand>> = None;
        let mut video_rate: Option<Arc<VideoRateState>> = None;
        let mut video_rtp: Option<mpsc::UnboundedReceiver<VideoRtpPacket>> = None;
        let mut video_ssrc: Option<Arc<std::sync::atomic::AtomicU32>> = None;
        let mut video_codec: Option<Arc<Mutex<Option<NegotiatedVideoCodec>>>> = None;
        let mut audio_in: Option<mpsc::UnboundedSender<Vec<f32>>> = None;
        let mut audio_rtp: Option<mpsc::UnboundedReceiver<usize>> = None;
        if is_controller {
            let (rx, codec, ssrc, arx) = setup_video_receiver(&pc).await?;
            video_rtp = Some(rx);
            video_codec = Some(codec);
            video_ssrc = Some(ssrc);
            audio_rtp = Some(arx);
        } else {
            let (tx, rate) = setup_video_sender(&pc).await?;
            video_in = Some(tx);
            video_rate = Some(rate);
            // Audio is BEST EFFORT and deliberately not fatal. A machine with no render endpoint,
            // or one whose session cannot open it, must still get a picture and a mouse — losing
            // the whole session because the guest has no speakers would be a plainly worse product
            // than a silent one. The failure is logged and the session continues without an audio
            // track, which is exactly what a controller sees for an agent that predates this.
            match setup_audio_sender(&pc).await {
                Ok(tx) => audio_in = Some(tx),
                Err(e) => tracing::warn!(error = %e, "audio track unavailable; continuing without audio"),
            }
        }

        // Terminal peer-connection states mean the session is over. Recording it here is what makes
        // `recv_frame` able to return `Closed` (see the `peer_gone` field), which is how a looping
        // agent learns to stop streaming and go back to waiting for the next controller.
        let peer_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer_gone_notify = Arc::new(Notify::new());
        {
            let peer_gone = peer_gone.clone();
            let peer_gone_notify = peer_gone_notify.clone();
            let watch = PeerStateWatch::new(
                PeerGone { flag: peer_gone, notify: peer_gone_notify },
                DISCONNECTED_GRACE,
            );
            pc.on_peer_connection_state_change(Box::new(move |s| {
                tracing::debug!(role = tag, state = %s, "pc state");
                watch.on_state(s);
                Box::pin(async {})
            }));
        }

        // BOUNDED (docs/25 F02): an unbounded queue let a fast peer outrun the session loop and
        // grow it without limit. `try_send` in `wire_data_channel` turns a full queue into a
        // teardown rather than silent growth.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Frame>(MAX_INBOUND_FRAMES);
        let open = Arc::new(Notify::new());

        // Data channel: controller creates it; agent receives it via on_data_channel.
        let (dc_tx, dc_rx) = oneshot::channel::<Arc<RTCDataChannel>>();
        let dc_slot = Arc::new(Mutex::new(Some(dc_tx)));

        let ready_dc: Option<Arc<RTCDataChannel>> = if is_controller {
            let dc = pc
                .create_data_channel("frames", None)
                .await
                .map_err(|e| e.to_string())?;
            wire_data_channel(
                &dc,
                inbound_tx.clone(),
                open.clone(),
                peer_gone.clone(),
                peer_gone_notify.clone(),
            );
            Some(dc)
        } else {
            let inbound_tx = inbound_tx.clone();
            let open = open.clone();
            let dc_slot = dc_slot.clone();
            let peer_gone = peer_gone.clone();
            let peer_gone_notify = peer_gone_notify.clone();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let inbound_tx = inbound_tx.clone();
                let open = open.clone();
                let dc_slot = dc_slot.clone();
                let peer_gone = peer_gone.clone();
                let peer_gone_notify = peer_gone_notify.clone();
                Box::pin(async move {
                    // Exactly ONE data channel per peer connection (security audit 2026-10-18). A
                    // second channel used to be wired anyway, each with its own 4 MiB reassembler, so
                    // a brokered peer could open hundreds of them, park a near-complete frame in each
                    // and hold gigabytes in the agent. Claim the slot FIRST; any later channel is
                    // closed before a callback or a buffer exists for it.
                    let Some(tx) = dc_slot.lock().await.take() else {
                        tracing::warn!(role = "agent", "refused an extra data channel from the peer");
                        let _ = dc.close().await;
                        return;
                    };
                    wire_data_channel(&dc, inbound_tx, open, peer_gone, peer_gone_notify);
                    let _ = tx.send(dc);
                })
            }));
            None
        };

        // Background task: apply inbound SDP/candidates to the peer connection for the life of the
        // connection. The agent creates+sends its answer here when the offer arrives.
        {
            let pc = pc.clone();
            let sig = sig.clone();
            tokio::spawn(async move {
                while let Some(msg) = sig_in.recv().await {
                    match msg {
                        ServerToClient::Sdp { sdp, kind, .. } => match kind {
                            SdpKind::Offer => {
                                tracing::debug!(role = tag, media = %sdp_media_summary(&sdp), "remote OFFER media sections");
                                let Ok(offer) = RTCSessionDescription::offer(sdp) else { continue };
                                if let Err(e) = pc.set_remote_description(offer).await {
                                    tracing::warn!(role = tag, error = %e, "set_remote(offer)");
                                    continue;
                                }
                                let answer = match pc.create_answer(None).await {
                                    Ok(a) => a,
                                    Err(e) => { tracing::warn!(role = tag, error = %e, "create_answer"); continue }
                                };
                                // Gather fully before sending (non-trickle).
                                let mut gather = pc.gathering_complete_promise().await;
                                if pc.set_local_description(answer).await.is_err() {
                                    continue;
                                }
                                let _ = gather.recv().await;
                                if let Some(local) = pc.local_description().await {
                                    tracing::debug!(role = tag, media = %sdp_media_summary(&local.sdp), "local ANSWER media sections");
                                    let _ = sig.send(ClientToServer::Sdp {
                                        session,
                                        sdp: local.sdp,
                                        kind: SdpKind::Answer,
                                    });
                                    tracing::debug!(role = tag, "sent answer");
                                }
                            }
                            SdpKind::Answer => {
                                if let Ok(answer) = RTCSessionDescription::answer(sdp) {
                                    if let Err(e) = pc.set_remote_description(answer).await {
                                        tracing::warn!(role = tag, error = %e, "set_remote(answer)");
                                    }
                                }
                            }
                        },
                        ServerToClient::Candidate { candidate, .. } => {
                            // We gather non-trickle (our own candidates ride in our SDP), but a
                            // browser peer trickles ITS candidates separately — accept those so
                            // browser↔agent ICE can complete.
                            let init = RTCIceCandidateInit {
                                candidate: candidate.addr,
                                sdp_mid: Some("0".to_string()),
                                sdp_mline_index: Some(0),
                                username_fragment: None,
                            };
                            if let Err(e) = pc.add_ice_candidate(init).await {
                                tracing::debug!(role = tag, error = %e, "add trickled candidate");
                            }
                        }
                        _ => {}
                    }
                }
            });
        }

        // Controller drives the offer now (after wiring, so ICE gathering can start).
        if is_controller {
            let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
            let mut gather = pc.gathering_complete_promise().await;
            pc.set_local_description(offer)
                .await
                .map_err(|e| e.to_string())?;
            let _ = gather.recv().await;
            let local = pc
                .local_description()
                .await
                .ok_or("no local description after gathering")?;
            sig.send(ClientToServer::Sdp {
                session,
                sdp: local.sdp,
                kind: SdpKind::Offer,
            })?;
            tracing::debug!(role = tag, "sent offer");
        }

        // Resolve the data channel (agent awaits on_data_channel), then wait for it to open.
        let dc = match ready_dc {
            Some(dc) => dc,
            None => dc_rx.await.map_err(|_| "agent never got a data channel".to_string())?,
        };
        open.notified().await;

        Ok(Self {
            pc,
            dc,
            inbound: inbound_rx,
            video_in,
            video_rate,
            audio_in,
            audio_rtp,
            video_rtp,
            video_ssrc,
            video_codec,
            control_plane_session,
            session_technician,
            session_access,
            peer_gone,
            peer_gone_notify,
            _ice_attempt: ice_attempt,
        })
    }

    /// Connect to the signaling server, register the agent role, and handle auth challenges.
    ///
    /// Returns the signaling client and its receiver once `Registered` is received (or the
    /// connection closes before `Registered`, which older servers do not send — see below).
    ///
    /// # When to use
    ///
    /// Use this when building a [`SignalingMux`] for multi-session support:
    /// ```text
    /// let (sig, sig_rx) = WebRtcTransport::register_for_mux(url, &role).await?;
    /// // sig_rx is positioned AFTER auth challenges and Registered — hand it to SignalingMux.
    /// let mux = SignalingMux::new(sig, sig_rx, Some(device_id)); // spawns heartbeat task
    /// ```
    ///
    /// # Older signaling servers
    ///
    /// Servers that predate the `Registered` message never send it. The function returns after
    /// [`REGISTER_FOR_MUX_TIMEOUT`] if `Registered` has not arrived; the caller receives the
    /// receiver positioned after any auth challenge exchange, ready for the mux.
    pub async fn register_for_mux(
        signaling_url: &str,
        role: &Role,
    ) -> Result<(SignalingClient, mpsc::UnboundedReceiver<ServerToClient>), String> {
        Self::register_for_mux_with_features(signaling_url, role).await.map(|(sig, rx, _)| (sig, rx))
    }

    /// [`register_for_mux`](Self::register_for_mux), also returning the `features` the server's
    /// `Registered` listed (docs/49). Empty when the server listed none or never sent `Registered`.
    pub async fn register_for_mux_with_features(
        signaling_url: &str,
        role: &Role,
    ) -> Result<(SignalingClient, mpsc::UnboundedReceiver<ServerToClient>, Vec<String>), String> {
        let (sig, mut sig_rx) = SignalingClient::connect(signaling_url).await?;
        let mut features = Vec::new();

        let agent_auth: Option<(Option<String>, Arc<dyn ChallengeSigner>)> = match role {
            Role::Agent { tenant, signer: Some(signer), .. } => {
                Some((tenant.clone(), Arc::clone(signer)))
            }
            _ => None,
        };

        sig.send(rendezvous_announcement(role))?;
        tracing::debug!("register_for_mux: registration sent");

        // Wait for Registered, handling auth challenges on the way. Use a timeout so that old
        // servers (pre-Registered) do not stall the caller indefinitely; see doc above.
        let deadline = tokio::time::sleep(REGISTER_FOR_MUX_TIMEOUT);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    tracing::debug!("register_for_mux: timed out waiting for Registered; continuing");
                    break;
                }
                msg = sig_rx.recv() => {
                    match msg {
                        None => return Err("signaling closed before registration".into()),
                        Some(ServerToClient::Registered { features: listed, .. }) => {
                            tracing::debug!(features = ?listed, "register_for_mux: registered");
                            features = listed;
                            break;
                        }
                        Some(ServerToClient::Rejected { reason }) => {
                            return Err(format!("register_for_mux: rejected: {reason}"));
                        }
                        Some(ServerToClient::AgentAuthChallenge { device, nonce, .. }) => {
                            let Some((tenant, signer)) = agent_auth.as_ref() else {
                                tracing::debug!("register_for_mux: auth challenge ignored (no signer)");
                                continue;
                            };
                            let Some(proof) = sign_agent_auth_challenge(
                                signer.as_ref(),
                                &device,
                                tenant.as_deref(),
                                &nonce,
                            ) else {
                                tracing::warn!("register_for_mux: auth challenge nonce malformed");
                                continue;
                            };
                            sig.send(ClientToServer::AgentAuthResponse { device, nonce, sig: proof })?;
                        }
                        Some(_) => continue,
                    }
                }
            }
        }

        Ok((sig, sig_rx, features))
    }

    /// Build a transport from an already-brokered session, for use with a signaling multiplexer.
    ///
    /// Call this inside the per-session task that a `SignalingMux` acceptor loop spawns:
    /// ```text
    /// let mut mux = SignalingMux::new(sig, sig_rx, Some(device_id));
    /// while let Some(bs) = mux.accept().await {
    ///     let ice = convert_ice(&bs.issued_ice, &static_ice);
    ///     tokio::spawn(async move {
    ///         let transport = WebRtcTransport::from_brokered(bs.session, bs.sig, bs.rx,
    ///             bs.control_plane_session, bs.technician_id, ice).await?;
    ///         run_one_session(transport, shared_capture.subscribe(), ...).await;
    ///     });
    /// }
    /// ```
    ///
    /// The `sig_rx` parameter is the per-session inbound channel from the mux — it delivers
    /// `RelayAssignment`, `Sdp`, and `Candidate` messages for THIS session only.
    ///
    /// `ice` should be `server_issued_ice + static_ice` (caller merges them from `BrokeredSession
    /// .issued_ice` and its own config), in that order (server-issued first, as in `connect_inner`).
    pub async fn from_brokered(
        session: SessionId,
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        control_plane_session: Option<uuid::Uuid>,
        session_technician: Option<uuid::Uuid>,
        session_access: BrokeredAccess,
        ice: Vec<IceServer>,
    ) -> Result<Self, String> {
        // Agent side only (controller never uses a SignalingMux).
        let tag = "agent";
        let is_controller = false;

        tracing::info!(
            role = tag,
            ?session,
            ice_total = ice.len(),
            ice_relay = ice.iter().filter(|s| s.is_turn()).count(),
            "signaling: brokered (from_brokered)"
        );

        let rtc_config = RTCConfiguration {
            ice_servers: ice.iter().map(IceServer::to_rtc).collect(),
            ..Default::default()
        };

        let mut media = MediaEngine::default();
        media.register_default_codecs().map_err(|e| e.to_string())?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media).map_err(|e| e.to_string())?;
        // TURN over TCP/TLS for relay gathering (turn_stream.rs), registered before the first peer.
        turn_stream::install();
        let (api, ice_restricted) = build_api(media, registry, sig.ice_route_ip(), ice.iter().any(IceServer::is_turn), tag);
        let pc = Arc::new(
            api.new_peer_connection(rtc_config).await.map_err(|e| e.to_string())?,
        );
        let ice_attempt = log_ice_path(&pc, tag, ice_restricted);

        let (video_in, video_rate) = {
            let (tx, rate) = setup_video_sender(&pc).await?;
            (Some(tx), Some(rate))
        };
        let audio_in = match setup_audio_sender(&pc).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                tracing::warn!(error = %e, "audio track unavailable; continuing without audio");
                None
            }
        };

        let peer_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer_gone_notify = Arc::new(Notify::new());
        {
            let peer_gone = peer_gone.clone();
            let peer_gone_notify = peer_gone_notify.clone();
            let watch = PeerStateWatch::new(
                PeerGone { flag: peer_gone, notify: peer_gone_notify },
                DISCONNECTED_GRACE,
            );
            pc.on_peer_connection_state_change(Box::new(move |s| {
                tracing::debug!(role = tag, state = %s, "pc state");
                watch.on_state(s);
                Box::pin(async {})
            }));
        }

        let (inbound_tx, inbound_rx) = mpsc::channel::<Frame>(MAX_INBOUND_FRAMES);
        let open = Arc::new(Notify::new());
        let (dc_tx, dc_rx) = oneshot::channel::<Arc<RTCDataChannel>>();
        let dc_slot = Arc::new(tokio::sync::Mutex::new(Some(dc_tx)));

        // Agent receives the data channel via on_data_channel.
        let inbound_tx_dc = inbound_tx.clone();
        let open_dc = open.clone();
        let dc_slot_dc = dc_slot.clone();
        let peer_gone_dc = peer_gone.clone();
        let peer_gone_notify_dc = peer_gone_notify.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let inbound_tx = inbound_tx_dc.clone();
            let open = open_dc.clone();
            let dc_slot = dc_slot_dc.clone();
            let peer_gone = peer_gone_dc.clone();
            let peer_gone_notify = peer_gone_notify_dc.clone();
            Box::pin(async move {
                // One data channel per peer connection; see the twin in `connect` above.
                let Some(tx) = dc_slot.lock().await.take() else {
                    tracing::warn!(role = "agent", "refused an extra data channel from the peer");
                    let _ = dc.close().await;
                    return;
                };
                wire_data_channel(&dc, inbound_tx, open, peer_gone, peer_gone_notify);
                let _ = tx.send(dc);
            })
        }));

        // Background task: apply inbound SDP/candidates for this session's lifetime. Its handle is
        // kept so an abandoned session can abort it (below) instead of waiting for the channel to drain.
        let sig_task = {
            let pc = pc.clone();
            let sig = sig.clone();
            tokio::spawn(async move {
                let mut rx = sig_rx;
                while let Some(msg) = rx.recv().await {
                    match msg {
                        ServerToClient::Sdp { sdp, kind, .. } => match kind {
                            SdpKind::Offer => {
                                tracing::debug!(role = tag, media = %sdp_media_summary(&sdp), "remote OFFER media sections");
                                let Ok(offer) = RTCSessionDescription::offer(sdp) else { continue };
                                if let Err(e) = pc.set_remote_description(offer).await {
                                    tracing::warn!(role = tag, error = %e, "set_remote(offer)");
                                    continue;
                                }
                                let answer = match pc.create_answer(None).await {
                                    Ok(a) => a,
                                    Err(e) => {
                                        tracing::warn!(role = tag, error = %e, "create_answer");
                                        continue;
                                    }
                                };
                                let mut gather = pc.gathering_complete_promise().await;
                                if pc.set_local_description(answer).await.is_err() {
                                    continue;
                                }
                                let _ = gather.recv().await;
                                if let Some(local) = pc.local_description().await {
                                    tracing::debug!(role = tag, media = %sdp_media_summary(&local.sdp), "local ANSWER media sections");
                                    let _ = sig.send(ClientToServer::Sdp {
                                        session,
                                        sdp: local.sdp,
                                        kind: SdpKind::Answer,
                                    });
                                    tracing::debug!(role = tag, "sent answer");
                                }
                            }
                            SdpKind::Answer => {
                                if let Ok(answer) = RTCSessionDescription::answer(sdp) {
                                    if let Err(e) = pc.set_remote_description(answer).await {
                                        tracing::warn!(role = tag, error = %e, "set_remote(answer)");
                                    }
                                }
                            }
                        },
                        ServerToClient::Candidate { candidate, .. } => {
                            let init = RTCIceCandidateInit {
                                candidate: candidate.addr,
                                sdp_mid: Some("0".to_string()),
                                sdp_mline_index: Some(0),
                                username_fragment: None,
                            };
                            if let Err(e) = pc.add_ice_candidate(init).await {
                                tracing::debug!(role = tag, error = %e, "add trickled candidate");
                            }
                        }
                        _ => {}
                    }
                }
            })
        };

        // Agent never drives the offer; the controller creates it.
        let _ = is_controller;

        // BOUNDED. A controller that abandons a brokered session before its data channel opens (a
        // double-click brokers two sessions and the viewer keeps one) used to leave this await
        // pending forever: `dc_tx` lives in the peer connection's own callback, so nothing ever
        // cancels it. The caller's whole session task leaked with it, including its update
        // idle-barrier guard, which blocked agent updates on a lab machine for a day
        // (observed 2026-10-21).
        let opened = async {
            let dc = dc_rx.await.map_err(|_| "agent never got a data channel".to_string())?;
            open.notified().await;
            Ok::<_, String>(dc)
        };
        let dc = match tokio::time::timeout(brokered_open_timeout(), opened).await {
            Ok(r) => r?,
            Err(_) => {
                sig_task.abort();
                // Bounded too: this path exists to guarantee the caller returns.
                let _ = tokio::time::timeout(Duration::from_secs(5), pc.close()).await;
                return Err(format!(
                    "the controller did not open the session within {}s; abandoned",
                    brokered_open_timeout().as_secs()
                ));
            }
        };

        Ok(Self {
            pc,
            dc,
            inbound: inbound_rx,
            video_in,
            video_rate,
            audio_in,
            audio_rtp: None,
            video_rtp: None,
            video_ssrc: None,
            video_codec: None,
            control_plane_session,
            session_technician,
            session_access,
            peer_gone,
            peer_gone_notify,
            _ice_attempt: ice_attempt,
        })
    }

    /// Agent side: queue one captured BGRA frame for VP8 encode + send on the video track.
    /// Cheap and non-blocking (hands the pixels to the encoder thread). No-op error on the
    /// controller side, which has no video sender.
    pub fn send_video_frame(&self, frame: &CapturedFrame) -> Result<(), String> {
        match &self.video_in {
            Some(tx) => tx
                .send(EncoderCommand::Frame(
                    frame.bytes.clone(),
                    frame.width as usize,
                    frame.height as usize,
                    Instant::now(),
                ))
                .map_err(|_| "video encode pipeline closed".to_string()),
            None => Err("this peer has no video sender (controller side)".to_string()),
        }
    }

    /// Controller side: await the next inbound AUDIO RTP payload size. `None` once the track ends
    /// or on the agent side.
    pub async fn recv_audio_packet(&mut self) -> Option<usize> {
        match &mut self.audio_rtp {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Agent side: queue captured PCM for Opus encode + send on the audio track.
    ///
    /// Takes **any length** of interleaved `f32` at the track's channel count — WASAPI hands over
    /// whatever the endpoint had ready and it does not divide into 20 ms frames. The encoder thread
    /// owns a [`audio::FrameAccumulator`] that joins the blocks, so a caller never has to frame and
    /// a remainder is never dropped (a dropped remainder is an audible click a few times a second).
    ///
    /// Cheap and non-blocking. `Err` on the controller side, which has no audio sender.
    pub fn send_audio_samples(&self, pcm: &[f32]) -> Result<(), String> {
        match &self.audio_in {
            Some(tx) => tx
                .send(pcm.to_vec())
                .map_err(|_| "audio encode pipeline closed".to_string()),
            None => Err("this peer has no audio sender".to_string()),
        }
    }

    /// Agent side: a cheap `Clone`able handle to the audio-send path that does not borrow the
    /// transport — the same borrow-hazard fix as [`Self::video_sender`], for the same reason.
    pub fn audio_sender(&self) -> Option<AudioSampleSender> {
        Some(AudioSampleSender {
            tx: self.audio_in.clone()?,
        })
    }

    /// Agent side: obtain a cheap, `Clone`able handle to the video-send path that does **not**
    /// borrow the transport.
    ///
    /// This exists to break a borrow hazard: streaming video needs to push frames while the same
    /// task calls [`Transport::recv_frame`] (`&mut self`) to receive input. `send_video_frame`
    /// borrows `&self`, which would conflict with the `&mut self` receive. The returned
    /// [`VideoFrameSender`] wraps only the internal encoder-feeding channel, so the owned transport
    /// stays free for the input-receive loop. Returns `None` on the controller side (no video
    /// sender).
    pub fn video_sender(&self) -> Option<VideoFrameSender> {
        let tx = self.video_in.clone()?;
        let rate = self.video_rate.clone()?;
        Some(VideoFrameSender { tx, rate })
    }

    /// Agent side: a non-borrowing handle for sampling the encoder's own view of the stream (M11).
    ///
    /// Same shape and same reason as [`video_sender`](Self::video_sender): the session driver polls
    /// this on a timer inside the `select!` loop that also holds `&mut self` for `recv_frame`.
    pub fn video_stats(&self) -> Option<VideoStatsHandle> {
        self.video_rate.clone().map(VideoStatsHandle::new)
    }

    /// Controller side: the SSRC of the inbound video track, i.e. the **agent's** sender SSRC.
    /// `None` until the first RTP packet has arrived. Needed to address RTCP back at the sender —
    /// an RTCP receiver report is routed by the SSRCs its report blocks name.
    pub fn inbound_video_ssrc(&self) -> Option<u32> {
        match &self.video_ssrc {
            Some(s) => match s.load(std::sync::atomic::Ordering::Relaxed) {
                0 => None,
                v => Some(v),
            },
            None => None,
        }
    }

    /// The CONTROL-PLANE session id this connection was brokered for, as vouched for by a signaling
    /// server that verified the controller's session ticket.
    ///
    /// `None` means the server did not vouch for one — it verifies no tickets, it predates the
    /// field, or the value was unparseable. Callers must treat `None` as "unknown", never as "any":
    /// it is what makes a session policy unbindable, and an unbindable policy is REJECTED.
    ///
    /// Read this ONCE into a local right after `connect`. The agent session loop holds `&mut self`
    /// for `recv_frame`, so a `&self` call inside that loop fights the borrow checker for no reason
    /// — the value never changes for the life of the connection.
    pub fn control_plane_session(&self) -> Option<uuid::Uuid> {
        self.control_plane_session
    }

    /// The TECHNICIAN this connection was brokered for, as vouched for by a signaling server that
    /// verified the controller's session ticket (loop 91).
    ///
    /// `None` means the server did not vouch for one, and the caller must NOT substitute anything:
    /// the only other candidates are the viewer (self-attribution — the forgery
    /// `POST /audit/ingest` answers 403 to) and an unverified ticket (attacker-chosen). Sealing the
    /// chain with a nil technician is the honest answer, and the control plane refuses that batch,
    /// so the session keeps its local trail and gains no false central record.
    ///
    /// Read this ONCE into a local right after `connect`, for the same borrow reason as
    /// [`Self::control_plane_session`].
    pub fn session_technician(&self) -> Option<uuid::Uuid> {
        self.session_technician
    }

    /// TEST HOOK: open an ADDITIONAL data channel from this side of an established connection.
    /// Production peers open exactly one; this exists so the e2e suite can prove the agent refuses
    /// a second one (security audit 2026-10-18) without reaching into the peer connection.
    #[doc(hidden)]
    pub async fn open_extra_data_channel(&self, label: &str) -> Result<ExtraDataChannel, String> {
        let dc = self.pc.create_data_channel(label, None).await.map_err(|e| e.to_string())?;
        Ok(ExtraDataChannel { dc })
    }

    /// How this session may act, as the signaling server stated it from the verified ticket
    /// (observer design v2). The agent enforces it before the first frame: `Invalid` ends the session,
    /// `ViewOnly` starts it under the non-revocable observer floor, `Control` and `Legacy` are today's
    /// controlling session. Read ONCE into a local, like [`Self::control_plane_session`].
    pub fn session_access(&self) -> BrokeredAccess {
        self.session_access
    }

    /// Write RTCP to the peer, exactly as a real receiver's stack would.
    ///
    /// This is what makes a network constraint reproducible in a test: a crafted `ReceiverReport`
    /// addressed to the agent's SSRC traverses the interceptor chain, DTLS/SRTP, the wire, the
    /// agent's SRTCP demux and its `RTCRtpSender::read` loop — every layer production code. The only
    /// test-only thing about it is who authored the packet, and that is exactly what a browser
    /// authors.
    pub async fn write_rtcp(
        &self,
        pkts: &[Box<dyn webrtc::rtcp::packet::Packet + Send + Sync>],
    ) -> Result<(), String> {
        self.pc.write_rtcp(pkts).await.map(|_| ()).map_err(|e| e.to_string())
    }

    /// Controller side: report packet loss to the sender, as RFC 3550 says a receiver should.
    ///
    /// `media_ssrc` names the stream being reported on — get it from
    /// [`inbound_video_ssrc`](Self::inbound_video_ssrc). That field is what routes the report: a
    /// peer's SRTCP layer demuxes on the SSRCs a report block names, so a report addressed to the
    /// wrong SSRC is silently discarded and looks exactly like "the sender ignored my feedback".
    ///
    /// `fraction_lost_256` is the RFC 3550 fraction in 1/256 units (77 ≈ 30 %).
    ///
    /// The RTCP vocabulary lives here rather than in the caller because this crate already owns it;
    /// a caller would otherwise take a dependency on `webrtc` and `bytes` to construct one struct.
    ///
    /// `last_sender_report` is left at zero, which is the documented "no sender report seen yet"
    /// value: a receiver that has not heard an SR cannot compute a round trip, and reporting zero
    /// makes the sender's arithmetic yield "unknown" rather than a fabricated number.
    pub async fn send_receiver_report(
        &self,
        media_ssrc: u32,
        fraction_lost_256: u8,
        total_lost: u32,
    ) -> Result<(), String> {
        use webrtc::rtcp::receiver_report::ReceiverReport;
        use webrtc::rtcp::reception_report::ReceptionReport;
        let rr = ReceiverReport {
            // The reporter's own SSRC. Arbitrary — the peer routes on the report block's SSRC.
            ssrc: 0xDEAD_BEEF,
            reports: vec![ReceptionReport {
                ssrc: media_ssrc,
                fraction_lost: fraction_lost_256,
                total_lost,
                last_sequence_number: 0,
                jitter: 0,
                last_sender_report: 0,
                delay: 0,
            }],
            profile_extensions: Bytes::new(),
        };
        self.write_rtcp(&[Box::new(rr)]).await
    }

    /// Controller side: ask the sender for a keyframe with an RTCP Picture Loss Indication (RFC 4585),
    /// as a browser does when it cannot decode. Routed like [`send_receiver_report`](Self::send_receiver_report):
    /// the peer's SRTCP layer demuxes on `media_ssrc`, so take it from
    /// [`inbound_video_ssrc`](Self::inbound_video_ssrc); a PLI naming another SSRC is discarded.
    pub async fn send_pli(&self, media_ssrc: u32) -> Result<(), String> {
        use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
        let pli = PictureLossIndication { sender_ssrc: 0xDEAD_BEEF, media_ssrc };
        self.write_rtcp(&[Box::new(pli)]).await
    }

    /// Controller side: await the next received RTP video payload size (proof the media track is
    /// flowing). Returns `None` if there is no video receiver or the track closed.
    pub async fn recv_video_rtp(&mut self) -> Option<usize> {
        self.recv_video_packet().await.map(|p| p.payload_len)
    }

    /// Controller side: like [`recv_video_rtp`](Self::recv_video_rtp) but also reports the RTP
    /// **payload type** the packet carried, so a test can prove *which codec* is on the wire and
    /// not merely that bytes moved.
    pub async fn recv_video_packet(&mut self) -> Option<VideoRtpPacket> {
        match &mut self.video_rtp {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Controller side: the codec the inbound video track was negotiated as (mime type + dynamic
    /// payload type), once the remote track has arrived. `None` before that, or on the agent side.
    ///
    /// This is the authoritative answer to "what codec is this session actually using?" — it comes
    /// from the negotiated `RTCRtpCodecParameters`, i.e. from the SDP both peers agreed on.
    pub async fn negotiated_video_codec(&self) -> Option<NegotiatedVideoCodec> {
        match &self.video_codec {
            Some(slot) => slot.lock().await.clone(),
            None => None,
        }
    }
}

/// One inbound RTP video packet's observable facts — everything a **receiver** can honestly say
/// about the stream without asking the sender.
///
/// The four fields beyond `payload_len` exist because the quality knobs are only separable from the
/// receiving end if they are measured against *different* observables. Bytes/sec alone cannot tell a
/// bitrate cut from a frame-rate cut from a resolution cut; together these can:
///
/// | knob | the observable that moves |
/// |---|---|
/// | bitrate ceiling | payload bytes/sec |
/// | frame rate | distinct `timestamp`s per second, and the delta between them |
/// | resolution | `vp8.dimensions` from the next keyframe header |
/// | colour | payload bytes/sec, corroborated by the `color.rs` unit pair |
///
/// A measurement that moved only *one* of these when several should have moved is a failed run,
/// not a passed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoRtpPacket {
    /// Size of the RTP payload in bytes. Excludes the RTP header, extensions, the SRTP auth tag and
    /// UDP/IP — so it is directly comparable with the *encoder's* output accounting, and runs a few
    /// percent below what a link-level capture would report.
    pub payload_len: usize,
    /// The RTP payload type from the packet header. Must equal the negotiated codec's payload type
    /// ([`NegotiatedVideoCodec::payload_type`]).
    pub payload_type: u8,
    /// The 90 kHz RTP timestamp. Successive distinct values are the frame rate the sender is
    /// *claiming*, which is the only way to catch a stream whose wall-clock pacing and whose RTP
    /// clock disagree.
    pub timestamp: u32,
    /// The marker bit — set on the last packet of a frame, so counting it counts whole frames.
    pub marker: bool,
    /// When this packet was read off the track. Stamped **inside** the receive loop, never in the
    /// consumer: a busy consumer would smear a step change into a ramp and make a sharp adaptation
    /// look like a slow one.
    pub at: Instant,
    /// What the VP8 payload descriptor and (for a keyframe) the VP8 header reveal.
    pub vp8: video::Vp8PacketInfo,
}

/// The agent-side counters shared between the encoder thread, the RTCP loop and the session driver.
///
/// Ceiling inputs are serialized across operator and dimension changes. Independent telemetry
/// counters use relaxed atomics; the epoch publishes ceiling updates to the controller.
#[derive(Debug, Default)]
pub(crate) struct VideoRateState {
    /// Operator base ceiling and encoded dimensions; one source of truth for ceiling inputs.
    ceiling_inputs: std::sync::Mutex<(u32, u32, u32, Option<u32>)>,
    /// Effective pixel-scaled ceiling, consumed by the controller and encoder.
    pub ceiling_bps: AtomicU32,
    /// Configured administrative limit after pixel scaling; zero means unconfigured.
    hard_cap_bps: AtomicU32,
    /// Whether adaptation is permitted. Written by `set_quality`, read by the RTCP loop.
    pub adaptive: AtomicBool,
    /// Current target; the RTCP loop adapts it and ceiling changes re-clamp it.
    pub target_bps: AtomicU32,
    /// Newest acted-on fraction lost, 1/256 units. Written by the RTCP loop only.
    pub fraction_lost_256: AtomicU32,
    /// Newest measured round-trip time, ms. Written by the RTCP loop only.
    pub rtt_ms: AtomicU32,
    /// SSRC-matched report blocks the rate controller has consumed. Written by the RTCP loop only.
    ///
    /// This is the **anti-"my stimulus never arrived" counter**: a measurement that depends on
    /// feedback is not believable until this number is seen moving, because "the controller ignored
    /// the loss" and "the loss reports never reached the controller" are otherwise identical from
    /// the outside.
    pub feedback_reports: AtomicU64,
    /// What libvpx was last successfully told. Written by the encoder thread only, and only after
    /// `set_bitrate` returned `Ok` — so it reports the encoder's state, not our intention.
    pub applied_bps: AtomicU32,
    /// Dimensions actually encoded. Written by the encoder thread only.
    pub enc_w: AtomicU32,
    /// Height actually encoded. Written by the encoder thread only.
    pub enc_h: AtomicU32,
    /// Total encoded AU bytes this session. Written by the encoder thread only.
    pub encoded_bytes: AtomicU64,
    /// Total encoded frames this session. Written by the encoder thread only.
    pub encoded_frames: AtomicU64,
    /// Frames handed to the encoder pipeline but not yet encoded — the queue DEPTH.
    ///
    /// Incremented by `VideoFrameSender::send`, decremented by the encoder thread when a frame
    /// leaves the queue (encoded or dropped). This is the instrument for the back-pressure defect:
    /// the capture side's `bounded(4)` channel is drained in the time of one memcpy into an
    /// UNBOUNDED command queue, so a capture rate above what the encoder sustains accumulates here
    /// — 8.3 MB per frame at 1080p — with nothing bounding it and nothing dropping a stale frame.
    ///
    /// Not merely diagnostic: `queued_peak` is what a fix has to be measured against, and both
    /// numbers are reported on the per-second encode-rate log line.
    pub queued_frames: AtomicU64,
    /// High-water mark of [`queued_frames`](Self::queued_frames) since the last report.
    pub queued_peak: AtomicU64,
    /// Raw frames dropped by drain-to-latest or because the encoded output queue was full.
    /// A climbing value signals that capture is outrunning encode or the RTP writer.
    pub dropped_frames: AtomicU64,
    /// Encoder output over the last ~1 s window, bits/sec. Written by the encoder thread only.
    ///
    /// Exists separately from the session totals because the REMB saturation gate needs to know
    /// whether the encoder is spending its target **now**. A session-lifetime average would answer
    /// a different question and would smooth away exactly the transition the gate exists to detect.
    pub measured_bps: AtomicU32,
    /// Bumped for operator changes and effective ceiling changes caused by encoded dimensions.
    ///
    /// The RTCP loop watches this rather than the ceiling value itself, so that "set the same
    /// ceiling again" and "the ceiling changed and changed back between two reports" are both
    /// noticed — the rate controller has to re-clamp and refresh its hysteresis baseline either way,
    /// or its idea of what the encoder is doing silently diverges from the truth.
    pub quality_epoch: AtomicU64,
}

/// Scale the operator ceiling by encoded pixels relative to one 1080p display.
fn effective_video_ceiling(base: u32, width: u32, height: u32) -> (u32, f64) {
    let factor = ((u64::from(width) * u64::from(height)) as f64 / 2_073_600.0)
        .clamp(1.0, 3.0);
    let effective = (f64::from(base) * factor).min(f64::from(video::MAX_BITRATE_BPS)) as u32;
    (effective, factor)
}

impl VideoRateState {
    /// Called with ceiling_inputs held, only when an input changes.
    fn refresh_ceiling(&self, base: u32, width: u32, height: u32) -> u32 {
        let (scaled, factor) = effective_video_ceiling(base, width, height);
        let ceiling = scaled.min(match self.hard_cap_bps.load(Ordering::Relaxed) { 0 => video::MAX_BITRATE_BPS, cap => cap });
        let previous = self.ceiling_bps.swap(ceiling, Ordering::Relaxed);
        let want = if self.adaptive.load(Ordering::Relaxed) {
            self.target_bps.load(Ordering::Relaxed)
                .clamp(video::rate::FLOOR_BPS.min(ceiling), ceiling)
        } else {
            ceiling
        };
        self.target_bps.store(want, Ordering::Relaxed);
        if previous != ceiling {
            self.quality_epoch.fetch_add(1, Ordering::Release);
            tracing::info!(base_kbps = base / 1000, effective_kbps = ceiling / 1000,
                width, height, factor, "video effective bitrate ceiling changed");
        }
        want
    }

    /// Store a controller decision as the target, unless a ceiling change (an epoch bump, always made
    /// under `ceiling_inputs`) happened after the decision's inputs were adopted at `seen_epoch`.
    fn publish_decision(&self, seen_epoch: u64, bps: u32) -> bool {
        let _inputs = self.ceiling_inputs.lock().unwrap();
        let current = self.quality_epoch.load(Ordering::Acquire) == seen_epoch;
        if current {
            self.target_bps.store(bps, Ordering::Relaxed);
        }
        current
    }

    fn encoded_dimensions_changed(&self, width: u32, height: u32) -> Option<u32> {
        let mut inputs = self.ceiling_inputs.lock().unwrap();
        if (inputs.1, inputs.2) == (width, height) {
            return None;
        }
        *inputs = (inputs.0, width, height, inputs.3);
        let previous = self.ceiling_bps.load(Ordering::Relaxed);
        let want = self.refresh_ceiling(inputs.0, width, height);
        (previous != self.ceiling_bps.load(Ordering::Relaxed)).then_some(want)
    }

    fn note_encoded(&self, au: &video::EncodedAu) {
        self.encoded_bytes.fetch_add(au.data.len() as u64, Ordering::Relaxed);
        self.encoded_frames.fetch_add(1, Ordering::Relaxed);
        self.enc_w.store(au.width, Ordering::Relaxed);
        self.enc_h.store(au.height, Ordering::Relaxed);
    }
}

/// The operator's quality choice, as the transport sees it (M11).
///
/// Deliberately carries **no** `scale_div` and no `fps`: capture resolution and capture cadence
/// belong to the caller's capture thread, which owns the capturer. One knob, one owner — splitting
/// a setting across two components is how they drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoQuality {
    /// Colour handling.
    pub color: video::ChromaMode,
    /// Bounded operator request, before pixel scaling; QualityApplied reports this value.
    pub max_bitrate_bps: u32,
    /// Explicit administrative limit on the effective ceiling, after pixel scaling.
    /// Transport-only; effective ceilings are reported in logs/telemetry, not QualityApplied.
    pub hard_cap_bps: Option<u32>,
    /// Whether the agent may adapt below that ceiling.
    pub adaptive: bool,
}

/// A snapshot of the encoder's own view of the stream, for the agent's 1 Hz telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VideoSendStats {
    /// What libvpx was last successfully told, bits/sec.
    pub encoder_bitrate_bps: u32,
    /// Encoder output over the window since the previous sample, bits/sec.
    pub measured_bitrate_bps: u32,
    /// Newest acted-on fraction lost, 1/256 units.
    pub fraction_lost_256: u32,
    /// Newest measured round-trip time, ms (0 = not yet measurable).
    pub rtt_ms: u32,
    /// Encoded width.
    pub width: u32,
    /// Encoded height.
    pub height: u32,
    /// Report blocks the rate controller has consumed this session.
    pub feedback_reports: u64,
    /// Frames encoded over the window since the previous sample.
    pub frames_in_window: u64,
    /// The length of that window, in milliseconds — **measured, not assumed**.
    ///
    /// Without it a receiver holding `frames_in_window` has to divide by a nominal 1 s tick, which
    /// is exactly the assumption [`VideoStatsHandle::sample`] refuses to make for the bitrate. A
    /// slipped timer would then be reported as a frame-rate drop that never happened — and "the
    /// achieved frame rate is not what you asked for" is precisely the kind of number that gets
    /// believed and acted on.
    pub window_ms: u32,
    /// Raw frames dropped by drain-to-latest or a full encoded output queue, session-total.
    ///
    /// Session-total rather than per-window, matching `feedback_reports`: a monotone counter needs
    /// no window to interpret, and a reader that wants a rate can difference two samples. This is
    /// the *cause* an operator needs when the achieved frame rate is below the one they set.
    pub dropped_frames: u64,
}

impl VideoSendStats {
    /// Achieved encoded frame rate over the sampled window, in hundredths of a frame per second.
    ///
    /// Derived here rather than at the send site so the arithmetic sits next to the two numbers it
    /// reads and can be tested without a session. `0` means "not yet measurable" — a window too
    /// short to divide by, which is a different statement from "zero frames were encoded" and must
    /// not be rendered as a frame rate of zero.
    pub fn achieved_fps_x100(&self) -> u32 {
        if self.window_ms == 0 {
            return 0;
        }
        let hundredths = self.frames_in_window * 100 * 1_000 / self.window_ms as u64;
        hundredths.min(u32::MAX as u64) as u32
    }
}

/// A non-borrowing handle for sampling [`VideoSendStats`]. Obtained from
/// [`WebRtcTransport::video_stats`].
pub struct VideoStatsHandle {
    rate: Arc<VideoRateState>,
    prev_bytes: u64,
    prev_frames: u64,
    prev_at: Instant,
}

impl VideoStatsHandle {
    fn new(rate: Arc<VideoRateState>) -> Self {
        Self {
            prev_bytes: rate.encoded_bytes.load(Ordering::Relaxed),
            prev_frames: rate.encoded_frames.load(Ordering::Relaxed),
            rate,
            prev_at: Instant::now(),
        }
    }

    /// What libvpx was last successfully told, **without** touching the measurement window.
    ///
    /// Exists so a caller answering a request (rather than reporting on a timer) cannot steal the
    /// 1 Hz reporter's window: [`sample`](Self::sample) is destructive by design — it measures
    /// since the previous call and resets the baseline — so using it to answer an on-demand query
    /// makes the next scheduled sample cover a few milliseconds instead of a second.
    pub fn encoder_bitrate_bps(&self) -> u32 {
        self.rate.applied_bps.load(Ordering::Relaxed)
    }

    /// Whether an explicit administrative cap reduces the pixel-scaled request.
    pub fn capped_by_bitrate_policy(&self) -> bool {
        let inputs = self.rate.ceiling_inputs.lock().unwrap();
        inputs.3.is_some_and(|cap| effective_video_ceiling(inputs.0, inputs.1, inputs.2).0 > cap)
    }

    /// Sample, computing the measured bitrate over the window since the **previous** call.
    ///
    /// The window is measured, not assumed to be one second: a caller whose timer slipped would
    /// otherwise report a proportionally wrong bitrate, and "the encoder is at 60 % of target" is
    /// precisely the kind of number that gets believed.
    pub fn sample(&mut self) -> VideoSendStats {
        let now = Instant::now();
        let bytes = self.rate.encoded_bytes.load(Ordering::Relaxed);
        let frames = self.rate.encoded_frames.load(Ordering::Relaxed);
        let elapsed = now.saturating_duration_since(self.prev_at).as_secs_f64();
        // Both deltas are taken BEFORE the previous values are overwritten.
        let delta = bytes.saturating_sub(self.prev_bytes);
        let frames_in_window = frames.saturating_sub(self.prev_frames);
        let measured = if elapsed > 0.001 {
            ((delta as f64 * 8.0) / elapsed).min(u32::MAX as f64) as u32
        } else {
            0
        };
        self.prev_bytes = bytes;
        self.prev_frames = frames;
        self.prev_at = now;
        VideoSendStats {
            encoder_bitrate_bps: self.rate.applied_bps.load(Ordering::Relaxed),
            measured_bitrate_bps: measured,
            fraction_lost_256: self.rate.fraction_lost_256.load(Ordering::Relaxed),
            rtt_ms: self.rate.rtt_ms.load(Ordering::Relaxed),
            width: self.rate.enc_w.load(Ordering::Relaxed),
            height: self.rate.enc_h.load(Ordering::Relaxed),
            feedback_reports: self.rate.feedback_reports.load(Ordering::Relaxed),
            frames_in_window,
            // The SAME `elapsed` the bitrate was normalised by, so the two numbers in this sample
            // can never describe different windows.
            window_ms: (elapsed * 1_000.0).min(u32::MAX as f64) as u32,
            dropped_frames: self.rate.dropped_frames.load(Ordering::Relaxed),
        }
    }
}

/// The video codec a connection negotiated, as agreed in SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedVideoCodec {
    /// e.g. `video/VP8`.
    pub mime_type: String,
    /// The dynamic RTP payload type assigned to it (96 for VP8 with webrtc-rs's default codecs).
    pub payload_type: u8,
    /// RTP clock rate (90000 for video).
    pub clock_rate: u32,
}

/// A cheap, `Clone`able handle to the agent's video-send path, decoupled from the transport's
/// lifetime borrow. Obtained via [`WebRtcTransport::video_sender`]. Pushing a frame hands its
/// pixels to the encoder thread (non-blocking); it never touches the peer connection or the
/// inbound receive path, so it can be used freely alongside a `&mut` [`Transport::recv_frame`]
/// loop on the owned transport.
#[derive(Clone)]
pub struct VideoFrameSender {
    tx: mpsc::UnboundedSender<EncoderCommand>,
    rate: Arc<VideoRateState>,
}

impl VideoFrameSender {
    /// Queue one captured BGRA frame for VP8 encode + send on the video track. Errors only if
    /// the encode pipeline has shut down.
    ///
    /// The frame is stamped with `Instant::now()` **here**, at hand-off, because that is the moment
    /// the capture pacer actually produced it. Stamping later — on the encoder thread, say — would
    /// fold the encoder's own queueing delay into the frame duration and hand libvpx a frame rate
    /// that drifts with load.
    pub fn send(&self, frame: &CapturedFrame) -> Result<(), String> {
        // Counted BEFORE the enqueue, and rolled back if the enqueue fails.
        //
        // The obvious order — send, then count — carries a race an adversarial review of this
        // change raised and I could not dismiss. Between the send and the increment the encoder
        // thread can dequeue that very frame and run `fetch_sub(1 + dropped)`, taking an UNSIGNED
        // counter below zero: in release it wraps to `u64::MAX`, and `queued_peak`'s `fetch_max`
        // then latches ~1.8e19 for the rest of the session, so the back-pressure instrument reports
        // nonsense exactly once it has been under load; in debug the following `+ 1` overflows and
        // panics. The window is one instruction wide, which is precisely the kind of thing that
        // never shows up in testing and then does in the field.
        //
        // Counting first makes a decrement impossible to observe before its matching increment.
        // The rollback preserves what the previous ordering was actually protecting: a closed
        // pipeline must not inflate the depth.
        let depth = self.rate.queued_frames.fetch_add(1, Ordering::Relaxed) + 1;
        match self.tx.send(EncoderCommand::Frame(
            frame.bytes.clone(),
            frame.width as usize,
            frame.height as usize,
            Instant::now(),
        )) {
            Ok(()) => {
                // The peak is latched only for a frame that really entered the queue.
                self.rate.queued_peak.fetch_max(depth, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.rate.queued_frames.fetch_sub(1, Ordering::Relaxed);
                Err("video encode pipeline closed".to_string())
            }
        }
    }

    /// Force the next encoded frame to be a keyframe (intra), the same command an inbound RTCP
    /// PLI/FIR triggers.
    ///
    /// The caller uses this to REPAIR a receiver unconditionally — a fresh keyframe stands alone, so
    /// it fixes a decoder whose reference frames are damaged, which merely re-sending the last delta
    /// frame would not. It exists because two independent conditions can leave a receiver stuck on a
    /// broken picture with no repair arriving: a browser that never negotiated `nack pli` (so it
    /// never asks), and a static desktop where DXGI produces no new frames to carry a keyframe. The
    /// agent pairs this with a re-send of the last captured frame to cover both.
    pub fn request_keyframe(&self) -> Result<(), String> {
        self.tx
            .send(EncoderCommand::Keyframe)
            .map_err(|_| "video encode pipeline closed".to_string())
    }

    /// Apply the operator's quality choice (M11).
    ///
    /// Sends the colour mode and an **immediate** bitrate command, so the change lands on the next
    /// frame rather than waiting for the next receiver report. The bitrate sent is the current
    /// adaptive target re-clamped into the new ceiling, not the ceiling itself: an operator who
    /// raises the cap on a link the controller has already backed off should not instantly re-flood
    /// it. Recovery stays the rate controller's job.
    pub fn set_quality(&self, q: VideoQuality) -> Result<(), String> {
        let ceiling = q
            .max_bitrate_bps
            .clamp(video::MIN_BITRATE_BPS, video::MAX_BITRATE_BPS);
        let mut inputs = self.rate.ceiling_inputs.lock().unwrap();
        let base_changed = inputs.0 != ceiling || inputs.3 != q.hard_cap_bps;
        inputs.3 = q.hard_cap_bps;
        self.rate.hard_cap_bps.store(q.hard_cap_bps.map(|cap| cap.clamp(video::MIN_BITRATE_BPS, video::MAX_BITRATE_BPS)).unwrap_or(0), Ordering::Relaxed);
        inputs.0 = ceiling;
        self.rate.adaptive.store(q.adaptive, Ordering::Relaxed);
        let want = if base_changed {
            self.rate.refresh_ceiling(inputs.0, inputs.1, inputs.2)
        } else {
            let effective = self.rate.ceiling_bps.load(Ordering::Relaxed);
            let want = if q.adaptive {
                self.rate.target_bps.load(Ordering::Relaxed)
                    .clamp(video::rate::FLOOR_BPS.min(effective), effective)
            } else {
                effective
            };
            self.rate.target_bps.store(want, Ordering::Relaxed);
            want
        };
        self.rate.quality_epoch.fetch_add(1, Ordering::Release);
        self.tx
            .send(EncoderCommand::SetChroma(q.color))
            .map_err(|_| "video encode pipeline closed".to_string())?;
        self.tx
            .send(EncoderCommand::SetBitrate(want))
            .map_err(|_| "video encode pipeline closed".to_string())
    }

    /// Install (or remove) the session recorder's tee (loop 89).
    ///
    /// `Some(sink)` starts copying every subsequent encoded access unit to `sink`; `None` stops.
    /// Both take effect between two frames, because the command rides the same totally-ordered
    /// queue as [`Self::send`] rather than a shared flag — see [`EncoderCommand::SetRecording`].
    ///
    /// **A start also requests a keyframe**, so the recording opens with a self-contained frame and
    /// the file is decodable from byte zero.
    ///
    /// The caller must keep its own handle to the sink: the encoder thread drops its `Arc` on
    /// `None`, but it may still be mid-`offer` when this returns, which is why the recorder's own
    /// `stop` is what decides a recording is over (see `rmt_agent_windows::recording`).
    pub fn set_recording(
        &self,
        sink: Option<Arc<dyn video::RecordingSink>>,
    ) -> Result<(), String> {
        self.tx
            .send(EncoderCommand::SetRecording(sink))
            .map_err(|_| "video encode pipeline closed".to_string())
    }
}

/// A one-line summary of an SDP's MEDIA SECTIONS: kind, mid and direction, in SDP order.
///
/// Deliberately not the whole SDP — that carries ICE credentials and DTLS fingerprints, which have
/// no business in a log file. This is only the part that answers the question a silent media-less
/// session actually poses: did my track get an m-line, and which way does it point?
fn sdp_media_summary(sdp: &str) -> String {
    // (kind, mid, direction) per m= section, in SDP order.
    let mut sections: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("m=") {
            let kind = rest.split_whitespace().next().unwrap_or("?").to_string();
            sections.push((kind, None, None));
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            if let Some(s) = sections.last_mut() {
                s.1 = Some(mid.to_string());
            }
        } else if matches!(line, "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive") {
            if let Some(s) = sections.last_mut() {
                s.2 = Some(line[2..].to_string());
            }
        }
    }
    // A missing mid or direction prints as `?` rather than being omitted: a summary that silently
    // drops the field you are looking for is worse than one that says it could not find it.
    sections
        .into_iter()
        .map(|(kind, mid, dir)| {
            format!(
                "{kind}(mid={},{})",
                mid.as_deref().unwrap_or("?"),
                dir.as_deref().unwrap_or("?")
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Controller: add a recvonly video transceiver (so the offer carries a video m-line the agent can
/// answer) and bridge inbound RTP packet sizes to a channel.
async fn setup_video_receiver(
    pc: &Arc<RTCPeerConnection>,
) -> Result<
    (
        mpsc::UnboundedReceiver<VideoRtpPacket>,
        Arc<Mutex<Option<NegotiatedVideoCodec>>>,
        Arc<AtomicU32>,
        mpsc::UnboundedReceiver<usize>,
    ),
    String,
> {
    pc.add_transceiver_from_kind(
        RTPCodecType::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    // A recvonly AUDIO m-line, so the agent's Opus track has somewhere to go. Without it the offer
    // carries no audio section and the agent's track is negotiated away silently — the session
    // works, sounds like nothing, and reports no error anywhere.
    pc.add_transceiver_from_kind(
        RTPCodecType::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    let (audio_tx, audio_rx) = mpsc::unbounded_channel::<usize>();
    let audio_count_for_cb = Some(audio_tx);

    let (tx, rx) = mpsc::unbounded_channel::<VideoRtpPacket>();
    let codec_slot: Arc<Mutex<Option<NegotiatedVideoCodec>>> = Arc::new(Mutex::new(None));
    let codec_for_cb = codec_slot.clone();
    // The agent's media SSRC, learned from the first packet. Needed to address RTCP back at it —
    // a receiver report is routed by the SSRCs its report blocks name, so a report sent to the
    // wrong SSRC is silently dropped by the peer's SRTCP demux and looks exactly like "the agent
    // ignored my feedback".
    let ssrc_slot = Arc::new(AtomicU32::new(0));
    let ssrc_for_cb = ssrc_slot.clone();
    pc.on_track(Box::new(
        move |track: Arc<TrackRemote>, _r: Arc<RTCRtpReceiver>, _t: Arc<RTCRtpTransceiver>| {
            let tx = tx.clone();
            let codec_slot = codec_for_cb.clone();
            let ssrc_slot = ssrc_for_cb.clone();
            let audio_count_for_cb = audio_count_for_cb.clone();
            Box::pin(async move {
                // ONE `on_track` handler fires for EVERY inbound track, and since the agent gained
                // an Opus track that is no longer only video. Without this filter an audio track
                // would be recorded as the negotiated VIDEO codec and its RTP counted as video —
                // `negotiated_video_codec()` would answer "audio/opus", and the codec assertion
                // that exists to catch a silent revert to H.264 would be reporting on the wrong
                // track entirely.
                let params = track.codec();
                let is_video = params
                    .capability
                    .mime_type
                    .to_ascii_lowercase()
                    .starts_with("video/");

                if is_video {
                    // Record what SDP actually settled on for this track before reading a byte.
                    let negotiated = NegotiatedVideoCodec {
                        mime_type: params.capability.mime_type.clone(),
                        payload_type: params.payload_type,
                        clock_rate: params.capability.clock_rate,
                    };
                    tracing::debug!(
                        codec = %negotiated.mime_type,
                        pt = negotiated.payload_type,
                        "inbound video track negotiated"
                    );
                    *codec_slot.lock().await = Some(negotiated);
                }

                // THE READ LOOP MUST NOT RUN INLINE HERE. webrtc-rs AWAITS this handler before it
                // dispatches the next track, and a read loop runs for the whole session — so
                // reading inline meant the FIRST track to carry RTP permanently prevented
                // `on_track` from ever firing for the SECOND one.
                //
                // Not hypothetical: it is exactly how a session that carried audio arrived with no
                // video at all. The agent's SDP was correct (`video sendonly`, `audio sendonly`),
                // the encoder ran, the samples were written — but the agent's audio pump starts
                // before its capture loop, so Opus RTP landed first, this handler blocked on it
                // forever, and the video track was never dispatched. `negotiated_video_codec()`
                // then reported "no video track negotiated" about a track that had negotiated
                // perfectly. A browser is unaffected (it dispatches tracks independently), so the
                // symptom was "the Rust controller sees no video while Chrome shows a picture" —
                // which reads like a capture fault and is nothing of the kind.
                //
                // Spawn and return: one task per inbound track, ending when that track does.
                tokio::spawn(async move {
                    if is_video {
                        while let Ok((pkt, _)) = track.read_rtp().await {
                            if pkt.payload.is_empty() {
                                continue;
                            }
                            // Record the sender's SSRC from the packet itself rather than from
                            // `TrackRemote::ssrc()`, so it is whatever is genuinely on the wire.
                            ssrc_slot.store(pkt.header.ssrc, Ordering::Relaxed);
                            let out = VideoRtpPacket {
                                payload_len: pkt.payload.len(),
                                payload_type: pkt.header.payload_type,
                                timestamp: pkt.header.timestamp,
                                marker: pkt.header.marker,
                                // Stamped HERE, in the read loop. A consumer that is busy handling
                                // a control message would otherwise smear a step change into a
                                // ramp and make a sharp adaptation look like a slow one.
                                at: Instant::now(),
                                vp8: video::vp8_rtp::inspect_vp8_payload(&pkt.payload),
                            };
                            if tx.send(out).is_err() {
                                break;
                            }
                        }
                    } else if let Some(atx) = audio_count_for_cb {
                        // Audio: count payload bytes so a test can prove the track flows, and read
                        // it to completion so the stack does not stall on an unread track.
                        while let Ok((pkt, _)) = track.read_rtp().await {
                            if pkt.payload.is_empty() {
                                continue;
                            }
                            if atx.send(pkt.payload.len()).is_err() {
                                break;
                            }
                        }
                    }
                });
            })
        },
    ));
    Ok((rx, codec_slot, ssrc_slot, audio_rx))
}

/// What the encoder thread can be asked to do.
///
/// Frames ride this queue too (rather than a second channel funnelled into it), so the encoder
/// thread sees **one totally-ordered stream**: a bitrate change lands cleanly between two frames
/// instead of racing one that is already in flight, and there is no funnel task to keep alive.
/// A `Clone`able handle to the audio-send path, independent of the transport's borrow.
///
/// Mirrors [`VideoFrameSender`] and exists for the same reason: the session driver pushes audio
/// while the same task calls `recv_frame` (`&mut self`).
#[derive(Clone)]
pub struct AudioSampleSender {
    tx: mpsc::UnboundedSender<Vec<f32>>,
}

impl AudioSampleSender {
    /// Queue interleaved PCM of any length. See [`WebRtcTransport::send_audio_samples`].
    pub fn send(&self, pcm: &[f32]) -> Result<(), String> {
        self.tx
            .send(pcm.to_vec())
            .map_err(|_| "audio encode pipeline closed".to_string())
    }
}

enum EncoderCommand {
    /// BGRA pixels, dimensions, and the instant the frame was handed over — the timestamp from
    /// which this frame's duration is measured.
    Frame(Vec<u8>, usize, usize, Instant),
    /// The receiver sent an RTCP PLI/FIR — it cannot decode and needs an intra frame.
    Keyframe,
    /// Retarget the live encoder (M11 rate control).
    SetBitrate(u32),
    /// Change colour handling for subsequent frames (M11).
    SetChroma(video::ChromaMode),
    /// Start teeing encoded frames to a sink, or stop (loop 89, session recording).
    ///
    /// Rides this queue rather than a shared atomic for the reason stated above: the encoder thread
    /// sees ONE totally-ordered stream, so "recording started" lands cleanly between two frames.
    /// With a flag, a frame already in flight could land on either side of the start and the
    /// recording's first frame would be non-deterministic — which matters here more than for a
    /// bitrate change, because the first frame of a recording must be a keyframe.
    SetRecording(Option<std::sync::Arc<dyn video::RecordingSink>>),
}

/// One 30 fps frame in 90 kHz ticks — the duration assumed for the very first frame, before any
/// interval between two hand-offs has been observed.
const NOMINAL_TICKS: u32 = video::VIDEO_CLOCK_RATE / 30;
/// Shortest frame duration accepted, i.e. 120 fps.
const MIN_TICKS: u32 = video::VIDEO_CLOCK_RATE / 120;
/// Longest frame duration accepted, i.e. `quality::MIN_FPS` = 1 fps.
///
/// Load-bearing, not defensive: a monitor-sleep stall (a known gate on the streaming e2e) would
/// otherwise hand libvpx a thirty-second frame duration, and its rate controller would conclude the
/// frame rate is 0.03 fps and budget a colossal per-frame target for the frame after the stall.
const MAX_TICKS: u32 = video::VIDEO_CLOCK_RATE;

/// Convert a 90 kHz tick count into the `Sample::duration` that reproduces it exactly.
///
/// webrtc-rs computes `samples = (duration.as_secs_f64() * clock_rate) as u32` — a **truncating**
/// cast — and then advances the packetizer's RTP timestamp by exactly `samples`. This is the exact
/// inverse of that expression, including the small bias needed to survive the truncation: without
/// it, 3000 ticks becomes 33_333_333 ns, which multiplies back to 2999.99997 and truncates to
/// **2999**. 5 µs is ~0.45 of a tick — far too small to shift any real duration, far too large to
/// be eaten by the truncation.
/// Where encoded samples go: the media track, or a test double.
#[async_trait::async_trait]
trait SampleSink: Send + Sync {
    async fn write(&self, sample: &Sample) -> Result<(), String>;
}

#[async_trait::async_trait]
impl SampleSink for webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample {
    async fn write(&self, sample: &Sample) -> Result<(), String> {
        self.write_sample(sample).await.map_err(|e| e.to_string())
    }
}

/// The producer side of a sample writer: the bounded (video) or unbounded (audio) channel.
#[async_trait::async_trait]
trait SampleSource<T: Send>: Send {
    async fn next(&mut self) -> Option<T>;
}

#[async_trait::async_trait]
impl<T: Send> SampleSource<T> for mpsc::Receiver<T> {
    async fn next(&mut self) -> Option<T> {
        self.recv().await
    }
}

#[async_trait::async_trait]
impl<T: Send> SampleSource<T> for mpsc::UnboundedReceiver<T> {
    async fn next(&mut self) -> Option<T> {
        self.recv().await
    }
}

/// Encoded audio frames (20 ms each) the writer may fall behind by before new ones are dropped: 1 s.
const AUDIO_PACKET_QUEUE: usize = 50;

/// How often a run of failed sample writes is reported (the first failure is reported at once).
const SAMPLE_WRITE_REPORT_EVERY: Duration = Duration::from_secs(10);

/// Push samples onto a track until the producer ends (the session's encoder stops at teardown).
///
/// A failed write is NOT the end of the stream. It used to `break`, and one transient send failure
/// (WSAENETUNREACH, os error 10051, when a route briefly vanished: the operator's Desktop has several Hyper-V
/// virtual adapters) stopped ALL further video or audio for the session, and the host then ended the
/// session ("video encode pipeline closed"). Seen on the Desktop on 2026-10-20 and 2026-10-23. ICE
/// recovers from that by itself, so the writer keeps going: the first failure and then a count every
/// SAMPLE_WRITE_REPORT_EVERY are logged, and the recovery is logged too. A dead connection is ended by
/// the session's own lifecycle (transport state, lease), which drops the producer and ends this loop.
async fn run_sample_writer<T: Send + 'static>(
    mut rx: impl SampleSource<T>,
    sink: Arc<dyn SampleSink>,
    to_sample: impl Fn(T) -> Sample + Send + 'static,
    kind: &'static str,
) -> u64 {
    let mut failing_since: Option<Instant> = None;
    let mut failures: u64 = 0;
    let mut last_report = Instant::now();
    let mut written: u64 = 0;
    while let Some(item) = rx.next().await {
        let sample = to_sample(item);
        match sink.write(&sample).await {
            Ok(()) => {
                written += 1;
                if let Some(since) = failing_since.take() {
                    tracing::info!(kind, failures, failing_for_ms = since.elapsed().as_millis() as u64,
                        "sample writes recovered; the stream continues");
                    failures = 0;
                }
            }
            Err(e) => {
                failures += 1;
                if failing_since.is_none() {
                    failing_since = Some(Instant::now());
                    last_report = Instant::now();
                    tracing::warn!(kind, error = %e, "the track refused a sample; continuing (ICE may recover)");
                } else if last_report.elapsed() >= SAMPLE_WRITE_REPORT_EVERY {
                    last_report = Instant::now();
                    tracing::warn!(kind, failures, error = %e, "sample writes still failing");
                }
            }
        }
    }
    written
}

fn ticks_to_duration(ticks: u32) -> Duration {
    Duration::from_nanos(ticks as u64 * 1_000_000_000 / video::VIDEO_CLOCK_RATE as u64 + 5_000)
}

/// Classify one inbound RTCP packet into the feedback the rate controller understands.
///
/// **Per report BLOCK, not per packet.** One Receiver Report legitimately carries blocks for
/// several SSRCs, and the SRTCP layer routes the whole packet to every stream it names (it demuxes
/// on `destination_ssrc()`, which for an RR returns *all* of its block SSRCs). So a packet arriving
/// on our sender's RTCP stream may well contain a block about somebody else, and acting on it would
/// be a real bug — one that no amount of SRTP-level filtering can prevent.
fn classify(
    pkt: &(dyn webrtc::rtcp::packet::Packet + Send + Sync),
    our_ssrc: u32,
    now_ntp_mid32: u32,
) -> Option<video::rate::Feedback> {
    use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
    use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    use webrtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
    use webrtc::rtcp::receiver_report::ReceiverReport;

    let any = pkt.as_any();
    if any.downcast_ref::<PictureLossIndication>().is_some()
        || any.downcast_ref::<FullIntraRequest>().is_some()
    {
        return Some(video::rate::Feedback::Keyframe);
    }
    if let Some(rr) = any.downcast_ref::<ReceiverReport>() {
        // Exactly the block that names US — see the doc comment.
        let block = rr.reports.iter().find(|b| b.ssrc == our_ssrc)?;
        // RTT from LSR/DLSR (RFC 3550 §6.4.1), in the middle-32 NTP format the report carries.
        // `last_sender_report == 0` means the receiver has not yet seen a sender report, so the
        // arithmetic would be meaningless rather than merely imprecise.
        let rtt = if block.last_sender_report == 0 {
            None
        } else {
            let ticks = now_ntp_mid32
                .wrapping_sub(block.last_sender_report)
                .wrapping_sub(block.delay);
            let ms = (ticks as u64 * 1000) / 65536;
            // A bogus clock on either side must not park the decrease gate forever.
            Some(Duration::from_millis(ms.min(10_000)))
        };
        return Some(video::rate::Feedback::Rr {
            fraction_lost_256: block.fraction_lost,
            rtt,
        });
    }
    if let Some(remb) = any.downcast_ref::<ReceiverEstimatedMaximumBitrate>() {
        if !remb.ssrcs.contains(&our_ssrc) {
            return None;
        }
        // REMB carries a float; a NaN/negative/absurd value must not become a bitrate.
        let bps = remb.bitrate;
        if !bps.is_finite() || bps <= 0.0 {
            return None;
        }
        return Some(video::rate::Feedback::Remb {
            bps: bps.min(video::MAX_BITRATE_BPS as f32) as u32,
        });
    }
    None
}

/// Counts which RTCP feedback types a session actually received.
///
/// This is a **deliverable, not decoration**: it converts "what does a real browser send us?" from
/// an argument into a measured finding, and it is the tripwire for a webrtc-rs upgrade that
/// silently switched the receiver from REMB to transport-cc — after which the REMB branch would be
/// dead code and nothing else would say so.
#[derive(Debug, Default)]
struct FeedbackCensus {
    rr: u64,
    remb: u64,
    twcc: u64,
    pli: u64,
    fir: u64,
    other: u64,
    logged: bool,
}

impl FeedbackCensus {
    fn count(&mut self, pkt: &(dyn webrtc::rtcp::packet::Packet + Send + Sync)) {
        use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
        use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
        use webrtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
        use webrtc::rtcp::receiver_report::ReceiverReport;
        use webrtc::rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
        let any = pkt.as_any();
        if any.downcast_ref::<ReceiverReport>().is_some() {
            self.rr += 1;
        } else if any.downcast_ref::<ReceiverEstimatedMaximumBitrate>().is_some() {
            self.remb += 1;
        } else if any.downcast_ref::<TransportLayerCc>().is_some() {
            // Counted EXPLICITLY, not folded into `other`: transport-cc is what a modern browser
            // sends INSTEAD of REMB, and the agent's rate controller does not consume it yet (see
            // classify_rtcp — RR/REMB/PLI/FIR only). A high `twcc` with `remb=0` is the signal that
            // the bandwidth estimate is riding RR fraction-lost alone. That is the census's whole job.
            self.twcc += 1;
        } else if any.downcast_ref::<PictureLossIndication>().is_some() {
            self.pli += 1;
        } else if any.downcast_ref::<FullIntraRequest>().is_some() {
            self.fir += 1;
        } else {
            self.other += 1;
        }
    }

    fn log_once_after(&mut self, since: Instant, after: Duration) {
        if self.logged || since.elapsed() < after {
            return;
        }
        self.logged = true;
        // This is a ONE-TIME EARLY SNAPSHOT, not a session total, and the wording says so on purpose:
        // an earlier "observed this session" line was read as a summary and led to a wrong diagnosis
        // (pli=0 half a second in is "none yet", not "feedback is broken"). `elapsed_ms` makes WHEN it
        // was taken explicit. REMB/transport-cc need ~1s+ to appear and PLI only fires after loss, so
        // read low counts here as "not yet", never as "never".
        tracing::info!(
            elapsed_ms = since.elapsed().as_millis() as u64,
            rr = self.rr,
            remb = self.remb,
            twcc = self.twcc,
            pli = self.pli,
            fir = self.fir,
            other = self.other,
            "RTCP feedback types seen so far (one-time snapshot, not a session total)"
        );
    }
}

/// Receiver-report loss over a fixed window, summarised for the log (see the RTCP loop).
struct LinkWindow {
    since: Instant,
    reports: u32,
    loss_sum_256: u64,
    loss_max_256: u8,
}

/// One window's summary, in percent with one decimal.
#[derive(Debug, PartialEq)]
struct LinkSummary {
    reports: u32,
    loss_avg_pct: f32,
    loss_max_pct: f32,
}

impl LinkWindow {
    const PERIOD: Duration = Duration::from_secs(30);

    fn new(now: Instant) -> Self {
        Self { since: now, reports: 0, loss_sum_256: 0, loss_max_256: 0 }
    }

    fn record(&mut self, fraction_lost_256: u8) {
        self.reports += 1;
        self.loss_sum_256 += u64::from(fraction_lost_256);
        self.loss_max_256 = self.loss_max_256.max(fraction_lost_256);
    }

    /// The summary once a full period has passed with at least one report; the window then starts again.
    fn take_if_due(&mut self, now: Instant) -> Option<LinkSummary> {
        if now.saturating_duration_since(self.since) < Self::PERIOD || self.reports == 0 {
            return None;
        }
        let pct = |v: f64| ((v * 100.0 / 256.0) * 10.0).round() as f32 / 10.0;
        let s = LinkSummary {
            reports: self.reports,
            loss_avg_pct: pct(self.loss_sum_256 as f64 / f64::from(self.reports)),
            loss_max_pct: pct(f64::from(self.loss_max_256)),
        };
        *self = Self::new(now);
        Some(s)
    }
}

/// The current NTP middle-32 timestamp, the unit RTCP's LSR/DLSR fields use.
fn now_ntp_mid32() -> u32 {
    (webrtc::rtp::extension::abs_send_time_extension::unix2ntp(SystemTime::now()) >> 16) as u32
}

/// Apply a live bitrate retarget, warning at most once per session if the backend refuses.
///
/// Extracted because the encoder loop applies a `SetBitrate` from two places — the head of the
/// queue, and the drain-to-latest pass — and a rate command that is honoured in one path but not
/// the other is exactly the silent divergence this fix exists to prevent.
fn apply_bitrate(
    enc: &mut dyn video::VideoEncoder,
    warned: &mut bool,
    rate: &VideoRateState,
    bps: u32,
) {
    // A queued command may be older than the state it was meant to express (Codex 1.3.24 r3: published,
    // then delayed while the picture shrank and regrew). So a bitrate command means "apply the CURRENT
    // target": the shared target, which publish_decision / refresh_ceiling / set_quality maintain under
    // `ceiling_inputs`, read together with the ceiling under that lock. The command's own value is used
    // only before any target exists (0). A stale value can therefore never be applied.
    let bps = {
        let _inputs = rate.ceiling_inputs.lock().unwrap();
        let ceiling = rate.ceiling_bps.load(Ordering::Relaxed);
        let current = rate.target_bps.load(Ordering::Relaxed);
        let want = if current == 0 { bps } else { current };
        if ceiling == 0 {
            want
        } else if rate.adaptive.load(Ordering::Relaxed) {
            want.min(ceiling)
        } else {
            ceiling
        }
    };
    match enc.set_bitrate(bps) {
        Ok(()) => {
            // Recorded only AFTER libvpx accepted it, so this reports the encoder's state rather
            // than our intention.
            rate.applied_bps.store(bps, Ordering::Relaxed);
            tracing::info!(kbps = bps / 1000, "encoder target bitrate changed");
        }
        Err(e) => {
            if !*warned {
                *warned = true;
                tracing::warn!(error = %e, codec = enc.codec_name(),
                    "encoder cannot retarget a live bitrate; keeping the previous target");
            }
        }
    }
}

/// Apply a colour-mode change, warning at most once per session if the backend refuses.
fn apply_chroma(enc: &mut dyn video::VideoEncoder, warned: &mut bool, mode: video::ChromaMode) {
    if let Err(e) = enc.set_chroma_mode(mode) {
        if !*warned {
            *warned = true;
            tracing::warn!(error = %e, codec = enc.codec_name(),
                "encoder cannot change colour mode");
        }
    }
}

// Bound encoded work waiting for the RTP writer as well as dropping stale raw frames.
const MAX_PENDING_VIDEO_AUS: usize = 4;

/// The encoder thread's entire body.
///
/// Extracted from the `std::thread::spawn` in [`setup_video_sender`] purely so tests can drive
/// **this** loop — the shipped one — with an injected encoder. Production behaviour is unchanged
/// by the extraction; the encoder is still built inside the thread (it is `!Send`) and handed in.
fn run_encoder_loop(
    mut enc: Box<dyn video::VideoEncoder>,
    mut cmd_rx: mpsc::UnboundedReceiver<EncoderCommand>,
    au_tx: mpsc::Sender<video::EncodedAu>,
    rate_enc: Arc<VideoRateState>,
) {
    tracing::debug!(codec = enc.codec_name(), "video encoder ready");
    // An encoder backend that cannot honour a control says so once per session, not once per
    // command — the h264 backend refuses both, by design.
    let mut warned_bitrate = false;
    let mut warned_chroma = false;
    let mut prev_at: Option<Instant> = None;
    let mut encoded_dimensions = (0, 0);
    // The session recorder's tee, when one is installed (loop 89). `None` for the whole session is
    // the normal case.
    let mut recording: Option<std::sync::Arc<dyn video::RecordingSink>> = None;
    // Rolling 1 s output window, maintained here because this thread is the only writer of the
    // byte counter. The RTCP loop's REMB gate reads it.
    let mut window_start = Instant::now();
    let mut window_bytes = 0u64;
    while let Some(cmd) = cmd_rx.blocking_recv() {
        match cmd {
            EncoderCommand::Keyframe => enc.request_keyframe(),
            EncoderCommand::SetChroma(mode) => {
                apply_chroma(enc.as_mut(), &mut warned_chroma, mode)
            }
            EncoderCommand::SetRecording(sink) => {
                // A keyframe on START, so the recording's first frame is self-contained and the file
                // is playable from byte zero. Requested rather than waited for: `KF_MAX_TICKS` is only a
                // 60 s last-resort backstop now, and a recording that opens with undecodable
                // interframes looks broken to whoever plays it.
                if sink.is_some() {
                    enc.request_keyframe();
                }
                recording = sink;
            }
            EncoderCommand::SetBitrate(bps) => {
                apply_bitrate(enc.as_mut(), &mut warned_bitrate, &rate_enc, bps)
            }
            EncoderCommand::Frame(bgra, w, h, at) => {
                // DRAIN-TO-LATEST — the back-pressure the capture side's `bounded(4)` channel
                // only *appears* to provide. That channel is drained by an async `select!` loop in
                // the time of one `Vec` clone, straight into THIS unbounded queue, so the only
                // real consumer rate is this thread's. Measured before this existed: a 600 ms
                // overload peaked 106 frames deep and an 1800 ms one 315 — linear in elapsed time,
                // ~175 frames/s, i.e. 1.4 GiB/s of 1080p BGRA with nothing bounding it and a
                // session cap of four hours.
                //
                // A stale screen frame has no value: the receiver wants what the screen looks like
                // NOW, so encoding a backlog spends CPU and bandwidth arriving late at a picture
                // that is already wrong. Keep the newest, count the rest.
                //
                // Non-`Frame` commands drained in this pass are APPLIED, never discarded. Dropping
                // a `SetBitrate` here would disable rate control at exactly the moment overload
                // makes it necessary — and M11 deliberately routes rate control through this same
                // queue, so that is not a hypothetical. They are applied in queue order, before the
                // surviving frame is encoded; a command that followed the last frame therefore
                // lands one frame early, which is the harmless direction (a keyframe request or a
                // retarget taking effect sooner than asked).
                let (mut bgra, mut w, mut h, mut at) = (bgra, w, h, at);
                let mut dropped = 0u64;
                loop {
                    match cmd_rx.try_recv() {
                        Ok(EncoderCommand::Frame(b2, w2, h2, at2)) => {
                            // Overwriting frees the superseded buffer here, at the moment it
                            // became worthless, rather than at the end of the batch.
                            bgra = b2;
                            w = w2;
                            h = h2;
                            at = at2;
                            dropped += 1;
                        }
                        Ok(EncoderCommand::Keyframe) => enc.request_keyframe(),
                        Ok(EncoderCommand::SetChroma(mode)) => {
                            apply_chroma(enc.as_mut(), &mut warned_chroma, mode)
                        }
                        Ok(EncoderCommand::SetBitrate(bps)) => {
                            apply_bitrate(enc.as_mut(), &mut warned_bitrate, &rate_enc, bps)
                        }
                        // Applied, not discarded, like its siblings — and the direction is
                        // especially clear for this one: dropping a STOP here would keep writing
                        // frames the operator has already stopped recording, and dropping a START
                        // would silently produce a recording missing its opening. Landing one frame
                        // early is harmless in both directions.
                        Ok(EncoderCommand::SetRecording(sink)) => {
                            if sink.is_some() {
                                enc.request_keyframe();
                            }
                            recording = sink;
                        }
                        // Empty (caught up) or Disconnected (the last sender is gone). Either way
                        // there is nothing more to take right now; encode what we have and let the
                        // outer `blocking_recv` decide whether the loop is over.
                        Err(_) => break,
                    }
                }
                // Every frame that left the queue is accounted for: this one plus the superseded
                // ones. Counting only this one would make the depth gauge drift permanently
                // upward and misreport a healthy session as an overloaded one.
                rate_enc.queued_frames.fetch_sub(1 + dropped, Ordering::Relaxed);
                if dropped > 0 {
                    rate_enc.dropped_frames.fetch_add(dropped, Ordering::Relaxed);
                }
                // Reserve BEFORE encoding: discarding an encoded interframe would break the
                // decoder's reference chain. A full writer queue instead drops raw pixels, which
                // have no dependencies, and leaves keyframe requests pending in the encoder.
                // Never block this thread on the writer: it must keep draining raw frames and
                // applying controls. Keep prev_at unchanged so the next encode includes the gap.
                let permit = match au_tx.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        rate_enc.dropped_frames.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                };
                // This frame's real duration, measured between hand-offs. Measured from the
                // SURVIVING frame's hand-off instant, so the span of the frames just dropped is
                // folded into it — which is correct rather than merely convenient: libvpx derives
                // its rate-control frame rate from the interval between presentation timestamps
                // (docs/07, proven by mutation), and dropping frames genuinely *is* a lower frame
                // rate. Charging the dropped span to nobody would have the encoder budget bits for
                // a frame rate it is no longer delivering. The clamp is
                // load-bearing on both ends — see MIN_TICKS / MAX_TICKS.
                let ticks = match prev_at {
                    None => NOMINAL_TICKS,
                    Some(p) => {
                        let secs = at.saturating_duration_since(p).as_secs_f64();
                        (secs * video::VIDEO_CLOCK_RATE as f64).round() as u32
                    }
                }
                .clamp(MIN_TICKS, MAX_TICKS);
                prev_at = Some(at);
                // Both shipped backends crop odd input dimensions to even encoded sizes.
                // Capture has already applied scale_div before submitting these pixels.
                let dimensions = (w & !1, h & !1);
                if encoded_dimensions != dimensions {
                    encoded_dimensions = dimensions;
                    if let Some(want) = rate_enc.encoded_dimensions_changed(
                        dimensions.0 as u32, dimensions.1 as u32,
                    ) {
                        apply_bitrate(enc.as_mut(), &mut warned_bitrate, &rate_enc, want);
                    }
                }
                match enc.encode_bgra(&bgra, w, h, ticks) {
                    Ok(au) => {
                        window_bytes += au.data.len() as u64;
                        let elapsed = window_start.elapsed();
                        if elapsed >= Duration::from_secs(1) {
                            let bps = ((window_bytes as f64 * 8.0) / elapsed.as_secs_f64())
                                .min(u32::MAX as f64)
                                as u32;
                            rate_enc.measured_bps.store(bps, Ordering::Relaxed);
                            // `queued`/`queued_peak`/`dropped` are the back-pressure instrument.
                            // A peak that grows without bound across reports is capture
                            // outrunning encode with nothing to stop it; `dropped` climbing is
                            // the drain-to-latest doing its job.
                            tracing::debug!(
                                kbps = bps / 1000,
                                target_kbps = rate_enc.applied_bps.load(Ordering::Relaxed) / 1000,
                                frames = rate_enc.encoded_frames.load(Ordering::Relaxed),
                                queued = rate_enc.queued_frames.load(Ordering::Relaxed),
                                queued_peak = rate_enc.queued_peak.swap(0, Ordering::Relaxed),
                                dropped = rate_enc.dropped_frames.load(Ordering::Relaxed),
                                "video encode rate"
                            );
                            window_start = Instant::now();
                            window_bytes = 0;
                        }
                        rate_enc.note_encoded(&au);
                        // THE RECORDING TEE (loop 89). Placed here on purpose: after the encode, so
                        // it records what was ENCODED rather than what survived the network; and
                        // BEFORE the RTP hand-off, so a recorder that misbehaves cannot delay the
                        // live frame — `offer` is contractually non-blocking (see `RecordingSink`).
                        //
                        // `at` and not `ticks`: `ticks` has already been clamped to MAX_TICKS above,
                        // which would compress every idle gap in the recording. See `RecordedFrame::at`.
                        if let Some(sink) = recording.as_ref() {
                            sink.offer(video::RecordedFrame {
                                data: &au.data,
                                keyframe: au.keyframe,
                                at,
                                width: au.width,
                                height: au.height,
                            });
                        }
                        permit.send(au);
                    }
                    Err(e) => tracing::debug!(error = %e, "video encode error"),
                }
            }
        }
    }
}

/// Agent: add a sendonly **Opus audio** track and start the encode pipeline.
///
/// Returns a sender that [`WebRtcTransport::send_audio_samples`] pushes arbitrary-length
/// interleaved PCM into. Framing into 20 ms Opus frames happens on the encoder thread — see
/// [`audio::FrameAccumulator`] for why that must live in exactly one place.
///
/// Shaped like [`setup_video_sender`], minus a rate controller: Opus at 96 kbps with DTX is small
/// next to the video track and does not need one, and adding an untested controller to a stream
/// that costs 400 bps while nobody is talking would be machinery in search of a problem. The RTCP
/// reader is still here and is NOT optional — the stack needs the reports drained.
async fn setup_audio_sender(
    pc: &Arc<RTCPeerConnection>,
) -> Result<mpsc::UnboundedSender<Vec<f32>>, String> {
    // STEREO, matching what a desktop's mix format almost always is. A mono endpoint is downmixed
    // by the capture side rather than renegotiated here: the channel count is in the SDP, so
    // varying it per machine would make the answer depend on the guest's speakers.
    const CHANNELS: u16 = 2;

    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: audio::OPUS_SAMPLE_RATE,
            channels: CHANNELS as u16,
            ..Default::default()
        },
        "audio".to_owned(),
        "rmt-agent".to_owned(),
    ));
    let sender = pc
        .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(|e| e.to_string())?;

    let (pcm_tx, mut pcm_rx) = mpsc::unbounded_channel::<Vec<f32>>();
    // BOUNDED: if the writer stalls, audio older than AUDIO_PACKET_QUEUE frames is worthless to a live
    // listener, so new packets are dropped rather than queued without limit (Codex round 2).
    let (pkt_tx, pkt_rx) = mpsc::channel::<Vec<u8>>(AUDIO_PACKET_QUEUE);

    // The encoder is raw C state: not Sync, and cheap enough per frame that a dedicated thread is
    // simpler than a blocking task per 20 ms. Same shape as the video encoder thread.
    let mut encoder = audio::OpusEncoder::new(CHANNELS).map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut acc = audio::FrameAccumulator::new(encoder.samples_per_frame());
        let mut frame: Vec<f32> = Vec::new();
        let mut dropped: u64 = 0;
        while let Some(pcm) = pcm_rx.blocking_recv() {
            acc.push(&pcm);
            while acc.take_frame(&mut frame) {
                match encoder.encode(&frame) {
                    Ok(packet) => {
                        match pkt_tx.try_send(packet.to_vec()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                dropped += 1;
                                if dropped == 1 || dropped % 500 == 0 {
                                    tracing::warn!(dropped, "audio writer is behind; dropping stale audio");
                                }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return, // the writer task is gone
                        }
                    }
                    // One bad frame must not end the stream: the next one is independent, and Opus
                    // has no inter-frame state a caller can corrupt from here.
                    Err(e) => tracing::debug!(error = %e, "opus encode failed; dropping one frame"),
                }
            }
        }
    });

    // Sample-writer task: push each encoded packet onto the media track (see run_sample_writer).
    let sink: Arc<dyn SampleSink> = track.clone();
    tokio::spawn(run_sample_writer(pkt_rx, sink, |packet: Vec<u8>| Sample {
        data: packet.into(),
        // A CONSTANT duration here is correct, unlike video: an Opus frame IS exactly
        // 20 ms by construction (the encoder refuses any other size), so this is the
        // measured value, not an assumption about pacing.
        duration: Duration::from_millis(audio::FRAME_MS as u64),
        ..Default::default()
    }, "audio"));

    // Drain RTCP from the audio sender. Required — the stack processes receiver reports here — and
    // the returned reports are discarded because nothing acts on them: there is no audio rate
    // controller (see above). Ends when the sender is gone.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while sender.read(&mut buf).await.is_ok() {}
    });

    Ok(pcm_tx)
}

/// Agent: add a sendonly video track (codec per [`video::NEGOTIATED_MIME_TYPE`]) and start the
/// encode pipeline. Returns a sender that [`WebRtcTransport::send_video_frame`] pushes raw BGRA
/// frames into.
///
/// The encoder is a `Box<dyn video::VideoEncoder>` — the transport never names a codec type. It is
/// not `Send` (raw C encoder state), so it lives on its own OS thread and only owned byte buffers
/// cross the async boundary.
async fn setup_video_sender(
    pc: &Arc<RTCPeerConnection>,
) -> Result<(mpsc::UnboundedSender<EncoderCommand>, Arc<VideoRateState>), String> {
    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: video::NEGOTIATED_MIME_TYPE.to_owned(),
            ..Default::default()
        },
        "video".to_owned(),
        "rmt-agent".to_owned(),
    ));
    let sender = pc
        .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(|e| e.to_string())?;

    // ONE queue: frames and control commands share it, so the encoder thread sees a single totally
    // ordered stream and a retarget lands cleanly between two frames.
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<EncoderCommand>();
    let (au_tx, au_rx) = mpsc::channel::<video::EncodedAu>(MAX_PENDING_VIDEO_AUS);

    let rate = Arc::new(VideoRateState::default());
    rate.ceiling_inputs.lock().unwrap().0 = video::DEFAULT_BITRATE_BPS;
    rate.ceiling_bps.store(video::DEFAULT_BITRATE_BPS, Ordering::Relaxed);
    rate.adaptive.store(true, Ordering::Relaxed);
    rate.target_bps.store(video::DEFAULT_BITRATE_BPS, Ordering::Relaxed);
    rate.applied_bps.store(video::DEFAULT_BITRATE_BPS, Ordering::Relaxed);

    // Our own media SSRC — the one a receiver's report blocks will name. Read once here rather than
    // per packet; `add_track` has already assigned it.
    let our_ssrc = sender
        .get_parameters()
        .await
        .encodings
        .first()
        .map(|e| e.ssrc)
        .unwrap_or(0);

    // Drain RTCP from the sender (required so the stack processes receiver reports), turn PLI/FIR
    // into a keyframe request, and drive the M11 rate controller. Without the first, a receiver
    // that joins late or loses the keyframe stays on a black/frozen picture until `kf_max_dist`
    // expires.
    {
        // A WEAK sender, deliberately. The encoder thread exits when every `cmd_tx` has dropped,
        // which is how its libvpx context (several MB of reference frames at 1080p) gets freed. A
        // strong clone here would tie that lifetime to this RTCP loop as well — and this loop ends
        // only when `sender.read()` errors, which nothing guarantees promptly: the crate never
        // calls `pc.close()`, and the task owns its own `Arc<RTCRtpSender>`. Since the agent
        // service reconnects in a loop, that is a thread plus an encoder context accumulating per
        // session. Weak keeps keyframe requests working while the session is live and lets the
        // frame source alone decide when the encoder dies.
        //
        // The rate controller lives inside this same loop and inherits the rule: no new task holds
        // a strong `cmd_tx`.
        let cmd_tx = cmd_tx.downgrade();
        let rate = rate.clone();
        tokio::spawn(async move {
            // Same call the old drain used (`RTCRtpSender::read` already unmarshals in
            // webrtc-rs 0.11), so the loop's lifetime is unchanged — it ends only when the sender
            // is gone. We now look at what came back instead of throwing it away.
            //
            // There is deliberately NO timer in this loop: `sender.read`'s cancel-safety is not
            // documented, so it is never `select!`ed. Receiver reports arrive at ~1 Hz, which IS
            // the decision cadence we want, so both the decrease and increase legs are
            // report-driven and need no clock of their own.
            // Start from ONE consistent snapshot of the ceiling state (Codex 1.3.24 r2): the encoder may
            // already have scaled the ceiling for a large first frame before this task runs, and a
            // controller that started at that ceiling while the encoder still sat at its old target would
            // see clean reports at "the ceiling" and never command anything. Every epoch bump happens
            // under `ceiling_inputs`, so holding it makes the epoch, target, ceiling and flag agree.
            let (mut bwe, mut seen_epoch) = {
                let _inputs = rate.ceiling_inputs.lock().unwrap();
                let ceiling = rate.ceiling_bps.load(Ordering::Relaxed);
                let mut bwe = video::rate::LossBasedBwe::new(ceiling);
                bwe.adopt_target(
                    rate.target_bps.load(Ordering::Relaxed),
                    Instant::now(),
                    ceiling,
                    rate.adaptive.load(Ordering::Relaxed),
                );
                (bwe, rate.quality_epoch.load(Ordering::Acquire))
            };
            let mut census = FeedbackCensus::default();
            let started = Instant::now();
            let mut link = LinkWindow::new(started);
            let mut buf = vec![0u8; 1500];
            while let Ok((packets, _)) = sender.read(&mut buf).await {
                // The operator or encoded dimensions changed the ceiling: adopt it before deciding
                // anything, so the controller's own target and hysteresis baseline agree with what
                // the encoder was just told. Without this the next decision is measured against a
                // rate the encoder no longer has.
                let epoch = rate.quality_epoch.load(Ordering::Acquire);
                if epoch != seen_epoch {
                    seen_epoch = epoch;
                    bwe.adopt_target(
                        rate.target_bps.load(Ordering::Relaxed),
                        Instant::now(),
                        rate.ceiling_bps.load(Ordering::Relaxed),
                        rate.adaptive.load(Ordering::Relaxed),
                    );
                }
                let ntp = now_ntp_mid32();
                for pkt in packets {
                    census.count(&*pkt);
                    match classify(&*pkt, our_ssrc, ntp) {
                        Some(video::rate::Feedback::Keyframe) => {
                            tracing::debug!("RTCP PLI/FIR: forcing a keyframe");
                            // Upgrade fails once the encoder has shut down — nothing left to ask.
                            match cmd_tx.upgrade() {
                                Some(tx) if tx.send(EncoderCommand::Keyframe).is_ok() => {}
                                _ => return,
                            }
                        }
                        Some(fb) => {
                            rate.feedback_reports.fetch_add(1, Ordering::Relaxed);
                            if let video::rate::Feedback::Rr { fraction_lost_256, rtt } = fb {
                                rate.fraction_lost_256
                                    .store(fraction_lost_256 as u32, Ordering::Relaxed);
                                if let Some(r) = rtt {
                                    rate.rtt_ms.store(r.as_millis() as u32, Ordering::Relaxed);
                                }
                                link.record(fraction_lost_256);
                            }
                            let inputs = video::rate::RateInputs {
                                ceiling_bps: rate.ceiling_bps.load(Ordering::Relaxed),
                                adaptive: rate.adaptive.load(Ordering::Relaxed),
                                encoded_bytes: rate.encoded_bytes.load(Ordering::Relaxed),
                                measured_bps: rate.measured_bps.load(Ordering::Relaxed),
                            };
                            if let Some(bps) = bwe.on_feedback(fb, Instant::now(), inputs) {
                                // Publish only if no ceiling change landed since this decision's inputs
                                // were adopted (Codex 1.3.24 r2): otherwise a decision made against the old
                                // ceiling would overwrite a concurrent shrink's clamped target, and a regrow
                                // before the next report would adopt that stale value. A discarded decision
                                // costs nothing: the next report adopts the new state and decides again.
                                if !rate.publish_decision(seen_epoch, bps) {
                                    continue;
                                }
                                match cmd_tx.upgrade() {
                                    Some(tx)
                                        if tx.send(EncoderCommand::SetBitrate(bps)).is_ok() => {}
                                    _ => return,
                                }
                            }
                        }
                        None => {}
                    }
                }
                census.log_once_after(started, Duration::from_secs(5));
                if let Some(s) = link.take_if_due(Instant::now()) {
                    // 2026-11-10: a fuzzy picture could not be told apart from Wi-Fi loss or a starved CPU,
                    // because nothing recorded what the receiver reported. One line per 30 s while reports flow.
                    tracing::info!(
                        reports = s.reports,
                        loss_avg_pct = s.loss_avg_pct,
                        loss_max_pct = s.loss_max_pct,
                        rtt_ms = rate.rtt_ms.load(Ordering::Relaxed),
                        target_kbps = rate.target_bps.load(Ordering::Relaxed) / 1000,
                        ceiling_kbps = rate.ceiling_inputs.lock().unwrap().0 / 1000,
                        effective_ceiling_kbps = rate.ceiling_bps.load(Ordering::Relaxed) / 1000,
                        "video link (last 30 s)"
                    );
                }
            }
        });
    }

    // Encoder thread: owns the !Send encoder behind the `VideoEncoder` seam.
    //
    // The encoder is constructed INSIDE the thread because `Box<dyn VideoEncoder>` is deliberately
    // not `Send` (raw C encoder state). The loop body itself lives in `run_encoder_loop` so a test
    // can drive the SHIPPED loop with an injected encoder rather than assert against a copy of it.
    let rate_enc = rate.clone();
    std::thread::spawn(move || {
        let enc = match video::new_video_encoder(video::DEFAULT_BITRATE_BPS) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "video encoder init failed; no video");
                return;
            }
        };
        run_encoder_loop(enc, cmd_rx, au_tx, rate_enc);
    });

    // Sample-writer task: push each encoded frame onto the media track (run_sample_writer: a failed
    // write is reported, never the end of the stream).
    let sink: Arc<dyn SampleSink> = track.clone();
    tokio::spawn(run_sample_writer(au_rx, sink, |au: video::EncodedAu| Sample {
        data: au.data.into(),
        // The MEASURED duration, not a constant. webrtc-rs turns this into the RTP
        // timestamp step, so a hardcoded 33 ms claims 30.30 fps forever — merely imprecise
        // at 30 fps, and a threefold lie at 10 fps that inflates the receiver's jitter
        // estimate and corrupts its frame-rate stats. Driving both libvpx and RTP from the
        // same echoed number is what keeps them in step by construction.
        duration: ticks_to_duration(au.duration_90khz),
        ..Default::default()
    }, "video"));

    Ok((cmd_tx, rate))
}

/// Upper bound on bytes held in ONE data channel's reassembly buffer, and therefore the largest
/// frame this transport will reassemble.
///
/// Deliberately far below [`rmt_protocol::frame::MAX_FRAME_LEN`] (64 MiB), which is the protocol's
/// ceiling for every transport including the TCP relay. Nothing this product sends over the WebRTC
/// DATA channel approaches 4 MiB: video rides the RTP track, not here; file-transfer and screenshot
/// payloads are chunked at `file_transfer::MAX_CHUNK_DATA` (48 KiB); shell output is capped at
/// `command_run::MAX_OUTPUT_BYTES` (64 KiB); the largest single frame is a backstage envelope such
/// as a process list, orders of magnitude under this. 4 MiB is ~60x the biggest known producer, so
/// it cannot refuse legitimate traffic, while bounding what one hostile peer can pin per session.
const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;

/// Depth of the inbound frame queue. Bounded so a peer that sends valid frames faster than the
/// session loop consumes them cannot grow the queue without limit (docs/25 F02, second half).
const MAX_INBOUND_FRAMES: usize = 1024;

/// What the sink did with a frame — the seam that lets [`drain_frames`] be driven by a test without
/// a live data channel or tokio channel.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SinkResult {
    Accepted,
    /// The consumer is not keeping up. Overload, which the caller escalates to teardown.
    Full,
    /// The receiver is gone (the transport was dropped). Not a fault.
    Closed,
}

/// Why reassembly stopped for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainFault {
    /// `UnknownChannel` / `TooLong` — the peer is not speaking this protocol.
    HardFrameError,
    /// Appending this message would exceed [`MAX_REASSEMBLY_BYTES`].
    ReassemblyCap,
    /// The header declares a frame larger than we will ever reassemble, so waiting is pointless.
    DeclaredTooLong,
    /// The inbound queue is full.
    QueueOverflow,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DrainOutcome {
    /// Every complete frame was delivered; anything left is a genuine partial frame.
    Ok,
    /// The consumer went away. Stop, but the peer did nothing wrong.
    ConsumerGone,
    /// Tear the session down.
    Fatal(DrainFault),
}

/// Append one data-channel message to `buf` and deliver every frame that completes.
///
/// THIS IS THE FIX FOR docs/25 F02, and it lives in a free function rather than inline in the
/// `on_message` closure for one reason: a closure owned by the webrtc peer connection cannot be
/// driven by a test, so the previous inline loop had no regression coverage at all and the bug sat
/// in it unnoticed. `run_encoder_loop` in this file was extracted for exactly the same reason —
/// a test must drive the SHIPPED loop, not a copy of it.
///
/// WHAT WENT WRONG BEFORE. The old loop was `Err(_) => break`, collapsing all three `FrameError`
/// variants into "need more bytes". `Frame::decode` consumes nothing on error (deliberately — that
/// is the streaming contract), so a permanently-invalid header such as `07 00 00 00 00` stayed at
/// the front of the buffer forever: every later message appended, nothing ever decoded again, and
/// the buffer grew without limit. The channel was dead while the session stayed up, silently.
///
/// Three bounds are enforced here, and all three are load-bearing:
///   1. Only `Incomplete` continues; `UnknownChannel`/`TooLong` are fatal, matching what
///      `relay_transport.rs` and the browser's `FrameDecoder` already did. This was a
///      single-site parity defect, not a design gap.
///   2. The buffer is capped. Necessary even with (1), because a VALID channel byte with a large
///      declared length legitimately reports `Incomplete` while the payload arrives — so error
///      classification alone still lets one header reserve a very large buffer.
///   3. A declared length beyond the cap is rejected on sight rather than accumulated toward.
pub(crate) struct Reassembler {
    buf: BytesMut,
    /// Set by the first fatal fault. A wedge must be TERMINAL: setting `peer_gone` tells the
    /// session loop to stop, but it does not unregister this data channel's `on_message` callback,
    /// which the peer connection keeps invoking for every message the peer chooses to send. Without
    /// this flag the accumulator kept appending after the fault — the very growth the fix exists to
    /// stop, merely capped instead of infinite. Found by the regression test below, which measured
    /// the review's exact 65,541 bytes against the "fixed" code.
    failed: Option<DrainFault>,
}

impl Reassembler {
    pub(crate) fn new() -> Self {
        Self { buf: BytesMut::new(), failed: None }
    }

    /// Bytes currently held. Zero once a fault has released the buffer.
    ///
    /// Test-only: this is the instrumentation the docs/25 F02 regression reads to prove the
    /// accumulator never reaches the 65,541 bytes the reviewer measured. `cfg(test)` rather than
    /// `allow(dead_code)` so that if the regression ever stops calling it, the method disappears
    /// with it instead of lingering as an unread accessor that looks like a live API.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn push<S: FnMut(Frame) -> SinkResult>(
        &mut self,
        incoming: &[u8],
        max_buffered: usize,
        sink: S,
    ) -> DrainOutcome {
        if let Some(fault) = self.failed {
            // Already wedged: buffer nothing, decode nothing, allocate nothing.
            return DrainOutcome::Fatal(fault);
        }
        let outcome = self.drain(incoming, max_buffered, sink);
        if let DrainOutcome::Fatal(fault) = outcome {
            self.failed = Some(fault);
            // Release what we were holding. The session is over; retaining a partial frame for a
            // peer we will never read again is pure leak.
            self.buf.clear();
            self.buf = BytesMut::new();
        }
        outcome
    }

    fn drain<S: FnMut(Frame) -> SinkResult>(
        &mut self,
        incoming: &[u8],
        max_buffered: usize,
        mut sink: S,
    ) -> DrainOutcome {
        // Check BEFORE appending, so the cap holds even for a single oversized message.
        if self.buf.len().saturating_add(incoming.len()) > max_buffered {
            return DrainOutcome::Fatal(DrainFault::ReassemblyCap);
        }
        self.buf.extend_from_slice(incoming);
        loop {
            match Frame::decode(&mut self.buf) {
                Ok(frame) => match sink(frame) {
                    SinkResult::Accepted => {}
                    SinkResult::Full => return DrainOutcome::Fatal(DrainFault::QueueOverflow),
                    SinkResult::Closed => return DrainOutcome::ConsumerGone,
                },
                Err(rmt_protocol::frame::FrameError::Incomplete) => {
                    // Genuinely partial — but only if the frame it is waiting for could ever fit.
                    if let Some(declared) = declared_frame_total(&self.buf) {
                        if declared > max_buffered {
                            return DrainOutcome::Fatal(DrainFault::DeclaredTooLong);
                        }
                    }
                    return DrainOutcome::Ok;
                }
                Err(_) => return DrainOutcome::Fatal(DrainFault::HardFrameError),
            }
        }
    }
}

/// Total bytes (header + payload) the buffered header declares, once 5 bytes are present.
fn declared_frame_total(buf: &BytesMut) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    Some(len.saturating_add(5))
}

/// Wire a data channel's inbound messages into `inbound_tx` (decoding one [`Frame`] per SCTP
/// message) and fire `open` when it opens.
fn wire_data_channel(
    dc: &Arc<RTCDataChannel>,
    inbound_tx: mpsc::Sender<Frame>,
    open: Arc<Notify>,
    peer_gone: Arc<std::sync::atomic::AtomicBool>,
    peer_gone_notify: Arc<Notify>,
) {
    // Reassembly buffer shared across messages: a large frame may be split over several SCTP
    // messages by the sender ([`send_frame`]'s chunking), so we accumulate bytes and drain every
    // complete length-prefixed frame — the standard streaming-decoder contract (`Incomplete` leaves
    // the buffer intact). Small frames still decode in a single pass with no behavior change.
    let acc = Arc::new(std::sync::Mutex::new(Reassembler::new()));
    {
        let peer_gone = peer_gone.clone();
        let peer_gone_notify = peer_gone_notify.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let inbound_tx = inbound_tx.clone();
            let acc = acc.clone();
            let peer_gone = peer_gone.clone();
            let peer_gone_notify = peer_gone_notify.clone();
            Box::pin(async move {
                let outcome = {
                    let mut acc = acc.lock().expect("frame accumulator poisoned");
                    acc.push(&msg.data[..], MAX_REASSEMBLY_BYTES, |frame| {
                        match inbound_tx.try_send(frame) {
                            Ok(()) => SinkResult::Accepted,
                            Err(mpsc::error::TrySendError::Full(_)) => SinkResult::Full,
                            Err(mpsc::error::TrySendError::Closed(_)) => SinkResult::Closed,
                        }
                    })
                };
                if let DrainOutcome::Fatal(fault) = outcome {
                    // The peer is either not speaking this protocol or is deliberately outrunning
                    // us. Either way this channel can never recover: drop the accumulator's claim
                    // by ending the session, which is the same signal `on_close` raises and which
                    // `recv_frame` already turns into `TransportError::Closed`.
                    tracing::warn!(
                        ?fault,
                        "inbound framing fault — tearing down the session (docs/25 F02)"
                    );
                    peer_gone.store(true, std::sync::atomic::Ordering::Relaxed);
                    peer_gone_notify.notify_waiters();
                }
            })
        }));
    }

    dc.on_open(Box::new(move || {
        let open = open.clone();
        Box::pin(async move {
            tracing::debug!("data channel open");
            open.notify_one();
        })
    }));

    // A closed data channel is the earliest reliable "the controller is gone" signal — a browser
    // that navigates away closes it well before the peer connection reaches `Disconnected` (which
    // can take tens of seconds of ICE timeout).
    dc.on_close(Box::new(move || {
        let peer_gone = peer_gone.clone();
        let peer_gone_notify = peer_gone_notify.clone();
        Box::pin(async move {
            tracing::debug!("data channel closed");
            peer_gone.store(true, std::sync::atomic::Ordering::Relaxed);
            peer_gone_notify.notify_waiters();
        })
    }));
}

/// Max bytes per SCTP data-channel message. A single `RTCDataChannel.send` larger than the peer's
/// negotiated `max-message-size` fails (Chrome advertises 256 KiB), which silently dropped large
/// frames — notably a backstage `ProcessList`. We split oversized frames into ≤ this many bytes per
/// message; the receiver ([`wire_data_channel`], and the browser's `FrameDecoder`) reassembles the
/// length-prefixed frame across messages. 16 KiB is the widely-safe data-channel chunk size.
const MAX_DC_MSG: usize = 16 * 1024;

impl Transport for WebRtcTransport {
    async fn send_frame(&mut self, frame: Frame) -> TransportResult<()> {
        let bytes: Bytes = frame.to_bytes();
        // Fast path: one SCTP message when the whole frame fits under the peer's limit.
        if bytes.len() <= MAX_DC_MSG {
            return self
                .dc
                .send(&bytes)
                .await
                .map(|_| ())
                .map_err(|e| TransportError::Other(format!("data channel send: {e}")));
        }
        // Oversized frame: send its bytes in order across multiple messages. The channel is
        // reliable+ordered, so the receiver appends them and decodes the single frame. `send_frame`
        // takes `&mut self`, so no other frame interleaves between these chunks.
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + MAX_DC_MSG).min(bytes.len());
            self.dc
                .send(&bytes.slice(offset..end))
                .await
                .map(|_| ())
                .map_err(|e| TransportError::Other(format!("data channel send (chunk): {e}")))?;
            offset = end;
        }
        Ok(())
    }

    /// Await the next frame, or report [`TransportError::Closed`] once the peer has gone.
    ///
    /// Already-queued frames win over the closed signal (`biased` + the up-front drain), so a peer
    /// that sent a final frame and immediately hung up does not lose it.
    async fn recv_frame(&mut self) -> TransportResult<Frame> {
        // Register for the wake-up BEFORE reading the flag (see `PeerGone::wait` for the lost-wake-up
        // window this closes); otherwise a peer that leaves between the two parks this call forever.
        let notify = self.peer_gone_notify.clone();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.peer_gone.load(std::sync::atomic::Ordering::Relaxed) {
            return match self.inbound.try_recv() {
                Ok(frame) => Ok(frame),
                Err(_) => Err(TransportError::Closed),
            };
        }
        tokio::select! {
            biased;
            frame = self.inbound.recv() => frame.ok_or(TransportError::Closed),
            _ = notified => match self.inbound.try_recv() {
                Ok(frame) => Ok(frame),
                Err(_) => Err(TransportError::Closed),
            },
        }
    }
}

#[cfg(test)]
mod publish_decision_tests {
    use super::*;

    /// Codex 1.3.24 r2: a decision computed before a concurrent shrink must not overwrite the shrink's
    /// clamped target. Interleaving: adopt at epoch E -> shrink (epoch E+1, target clamped to 3 Mbps)
    /// -> the stale 9 Mbps decision is published -> must be refused, and the target stays 3 Mbps.
    #[test]
    fn a_decision_made_before_a_ceiling_change_is_not_published() {
        let rate = VideoRateState::default();
        {
            let mut i = rate.ceiling_inputs.lock().unwrap();
            i.0 = 3_000_000;
        }
        rate.adaptive.store(true, Ordering::Relaxed);
        rate.target_bps.store(3_000_000, Ordering::Relaxed);
        rate.ceiling_bps.store(3_000_000, Ordering::Relaxed);
        assert!(rate.encoded_dimensions_changed(5120, 2486).is_some());
        assert_eq!(rate.ceiling_bps.load(Ordering::Relaxed), 9_000_000);
        // The controller has since climbed to the canvas ceiling.
        rate.target_bps.store(9_000_000, Ordering::Relaxed);
        let seen = rate.quality_epoch.load(Ordering::Acquire);
        // A shrink lands between the adoption and the publication.
        let _ = rate.encoded_dimensions_changed(1920, 1080);
        assert_eq!(rate.target_bps.load(Ordering::Relaxed), 3_000_000, "the shrink clamps the target");
        assert!(!rate.publish_decision(seen, 9_000_000), "a stale decision is refused");
        assert_eq!(rate.target_bps.load(Ordering::Relaxed), 3_000_000);
        // With nothing in between, a decision publishes.
        let seen = rate.quality_epoch.load(Ordering::Acquire);
        assert!(rate.publish_decision(seen, 2_500_000));
        assert_eq!(rate.target_bps.load(Ordering::Relaxed), 2_500_000);
    }
}

#[cfg(test)]
mod link_window_tests {
    use super::*;

    #[test]
    fn summarises_loss_once_per_period_and_only_with_reports() {
        let t0 = Instant::now();
        let mut w = LinkWindow::new(t0);
        assert_eq!(w.take_if_due(t0 + Duration::from_secs(31)), None, "no reports: nothing to say");
        w.record(0);
        w.record(26); // ~10.2 %
        w.record(13); // ~5.1 %
        assert_eq!(w.take_if_due(t0 + Duration::from_secs(29)), None, "not before the period");
        assert_eq!(
            w.take_if_due(t0 + Duration::from_secs(31)),
            Some(LinkSummary { reports: 3, loss_avg_pct: 5.1, loss_max_pct: 10.2 })
        );
        // The window restarts: the next summary covers only what came after.
        w.record(0);
        assert_eq!(w.take_if_due(t0 + Duration::from_secs(40)), None);
        assert_eq!(
            w.take_if_due(t0 + Duration::from_secs(62)),
            Some(LinkSummary { reports: 1, loss_avg_pct: 0.0, loss_max_pct: 0.0 })
        );
    }
}

#[cfg(test)]
mod sdp_summary_tests {
    //! [`sdp_media_summary`] is a DIAGNOSTIC, and a diagnostic that misreports is worse than none:
    //! this one exists to answer "did my track get an m-line, and which way does it point?", and
    //! that answer decides whether to go looking in capture or in negotiation. CRLF line endings
    //! throughout, because that is what SDP on the wire actually uses.

    use super::*;

    /// The shape the real fault presented as: two media sections plus the data channel, each with
    /// its own mid and direction. Asserted as one whole string because the ORDER carries the
    /// meaning — m-lines are matched positionally between offer and answer.
    #[test]
    fn summarizes_each_media_section_with_its_mid_and_direction() {
        let sdp = [
            "v=0",
            "m=video 9 UDP/TLS/RTP/SAVPF 96",
            "a=mid:0",
            "a=sendonly",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111",
            "a=mid:1",
            "a=recvonly",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "a=mid:2",
            "a=sendrecv",
        ]
        .join("\r\n");
        assert_eq!(
            sdp_media_summary(&sdp),
            "video(mid=0,sendonly) audio(mid=1,recvonly) application(mid=2,sendrecv)"
        );
    }

    /// A section missing its direction must still print a BALANCED, readable entry. The first
    /// version appended the closing paren only when a direction was found, so exactly the SDP a
    /// reader would be squinting at — one where the direction is the missing thing — printed
    /// `video(mid=0` and read as truncated output rather than as an absent attribute.
    #[test]
    fn a_section_with_no_direction_says_so_instead_of_truncating() {
        let sdp = ["m=video 9 UDP/TLS/RTP/SAVPF 96", "a=mid:0"].join("\r\n");
        assert_eq!(sdp_media_summary(&sdp), "video(mid=0,?)");
    }

    /// `a=` attributes may legally appear at SESSION level, before any `m=` section. Those must be
    /// ignored rather than panic on `last_mut()` of an empty list — a diagnostic that crashes the
    /// session it is diagnosing would be a spectacular own goal.
    #[test]
    fn session_level_attributes_before_any_m_line_are_ignored() {
        let sdp = ["v=0", "a=mid:0", "a=sendonly"].join("\r\n");
        assert_eq!(sdp_media_summary(&sdp), "");
        assert_eq!(sdp_media_summary(""), "");
    }
}

#[cfg(test)]
mod m11_tests {
    //! M11: the two pure functions that stand between a measured frame duration and the wire, and
    //! between an RTCP packet and the rate controller.
    //!
    //! Both exist because a mutation run found them untested: reverting `Sample::duration` to the
    //! old hardcoded 33 ms, dropping the rounding bias, and accepting a report block for somebody
    //! else's SSRC all left the suite green.

    use super::*;

    /// **The premise, declared locally so this test cannot rot silently.**
    ///
    /// webrtc-rs turns a `Sample::duration` into an RTP timestamp step with
    /// `samples = (duration.as_secs_f64() * clock_rate) as u32` — a *truncating* cast — and then
    /// advances the packetizer by exactly `samples`. This helper must be the exact inverse of THAT
    /// expression, not of an idealised one; the whole point of the `+5 µs` bias is to survive the
    /// truncation. So the assertion re-implements the library's arithmetic here rather than
    /// comparing against a nicer formula that would agree with a wrong implementation.
    fn webrtc_rs_samples_for(d: Duration) -> u32 {
        (d.as_secs_f64() * video::VIDEO_CLOCK_RATE as f64) as u32
    }

    #[test]
    fn ticks_to_duration_round_trips_through_webrtc_rss_own_arithmetic() {
        // Every tick count from 1 (impossibly fast) to 90_000 (1 fps, our MAX_TICKS) must survive
        // the round trip exactly. Without the bias, 3000 -> 33_333_333 ns -> 2999.99997 -> 2999:
        // a permanent one-tick undercount on every single frame at 30 fps.
        for t in 1..=video::VIDEO_CLOCK_RATE {
            let back = webrtc_rs_samples_for(ticks_to_duration(t));
            assert_eq!(back, t, "ticks {t} came back as {back}");
        }
    }

    #[test]
    fn the_frame_duration_clamps_line_up_with_the_wire_limits() {
        // MAX_TICKS is exactly one second, i.e. `quality::MIN_FPS`; MIN_TICKS is 120 fps, above the
        // wire's MAX_FPS so the clamp never bites a legal frame rate. Changing either constant
        // alone breaks the correspondence these two facts rest on.
        assert_eq!(MAX_TICKS, video::VIDEO_CLOCK_RATE / rmt_agent_core::quality::MIN_FPS);
        assert!(MIN_TICKS < video::VIDEO_CLOCK_RATE / rmt_agent_core::quality::MAX_FPS);
        assert_eq!(NOMINAL_TICKS, 3000, "one 30 fps frame");
        assert!(MIN_TICKS <= NOMINAL_TICKS && NOMINAL_TICKS <= MAX_TICKS);
    }

    fn rr_with(blocks: &[(u32, u8)]) -> Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> {
        use webrtc::rtcp::receiver_report::ReceiverReport;
        use webrtc::rtcp::reception_report::ReceptionReport;
        Box::new(ReceiverReport {
            ssrc: 0x1234,
            reports: blocks
                .iter()
                .map(|&(ssrc, fraction_lost)| ReceptionReport {
                    ssrc,
                    fraction_lost,
                    total_lost: 0,
                    last_sequence_number: 0,
                    jitter: 0,
                    last_sender_report: 0,
                    delay: 0,
                })
                .collect(),
            profile_extensions: Bytes::new(),
        })
    }

    /// **The only test that can tell our per-block filter apart from the SRTP demux.**
    ///
    /// One Receiver Report legitimately carries blocks for several SSRCs, and the SRTCP layer
    /// routes the WHOLE packet to every stream it names — so a compound report about us *and*
    /// somebody else really does arrive on our sender's RTCP stream. Acting on the foreign block
    /// would feed another stream's loss into our rate controller. A live test cannot distinguish
    /// this from the demux; a pure one can.
    #[test]
    fn classify_reads_only_the_report_block_that_names_us() {
        const OURS: u32 = 0xAAAA_BBBB;
        const THEIRS: u32 = 0x1111_2222;

        // Ours second, so a "just take the first block" implementation picks the wrong one.
        let compound = rr_with(&[(THEIRS, 200), (OURS, 13)]);
        match classify(&*compound, OURS, 0) {
            Some(video::rate::Feedback::Rr { fraction_lost_256, .. }) => {
                assert_eq!(fraction_lost_256, 13, "must read OUR block, not the first one");
            }
            other => panic!("expected an Rr for our block, got {other:?}"),
        }

        // A report that names only somebody else tells us nothing at all.
        let foreign = rr_with(&[(THEIRS, 200)]);
        assert!(
            classify(&*foreign, OURS, 0).is_none(),
            "a report block for another SSRC must be ignored entirely"
        );
    }

    #[test]
    fn classify_reports_no_rtt_when_the_receiver_has_seen_no_sender_report() {
        // `last_sender_report == 0` means "I have not heard an SR yet", so the LSR/DLSR arithmetic
        // has no basis. Reporting a number derived from it would be inventing a round-trip time,
        // and the rate controller's decrease gate is spaced by exactly that number.
        let rr = rr_with(&[(7, 40)]);
        match classify(&*rr, 7, 0x1234_5678) {
            Some(video::rate::Feedback::Rr { rtt, .. }) => assert!(rtt.is_none()),
            other => panic!("expected Rr, got {other:?}"),
        }
    }

    #[test]
    fn classify_still_maps_pli_and_fir_to_a_keyframe_request() {
        // A regression net on the arm that existed before M11: the rate controller must never see
        // these, and the keyframe path must never stop seeing them.
        use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
        use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
        let pli: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> =
            Box::new(PictureLossIndication { sender_ssrc: 1, media_ssrc: 2 });
        assert_eq!(classify(&*pli, 2, 0), Some(video::rate::Feedback::Keyframe));
        let fir: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> =
            Box::new(FullIntraRequest { sender_ssrc: 1, media_ssrc: 2, fir: vec![] });
        assert_eq!(classify(&*fir, 2, 0), Some(video::rate::Feedback::Keyframe));
        // ...and they are routed by the keyframe arm regardless of SSRC match, exactly as before.
        assert_eq!(classify(&*pli, 999, 0), Some(video::rate::Feedback::Keyframe));
    }

    #[test]
    fn classify_rejects_a_remb_that_is_not_about_us_or_is_nonsense() {
        use webrtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate as Remb;
        const OURS: u32 = 55;
        let ok: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> = Box::new(Remb {
            sender_ssrc: 1,
            bitrate: 800_000.0,
            ssrcs: vec![OURS],
        });
        assert_eq!(
            classify(&*ok, OURS, 0),
            Some(video::rate::Feedback::Remb { bps: 800_000 })
        );
        let theirs: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> = Box::new(Remb {
            sender_ssrc: 1,
            bitrate: 800_000.0,
            ssrcs: vec![OURS + 1],
        });
        assert!(classify(&*theirs, OURS, 0).is_none(), "a REMB about another stream");
        // A float field can carry values a bitrate cannot. None of these may become a target.
        for bad in [f32::NAN, f32::INFINITY, -1.0, 0.0] {
            let junk: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> = Box::new(Remb {
                sender_ssrc: 1,
                bitrate: bad,
                ssrcs: vec![OURS],
            });
            assert!(classify(&*junk, OURS, 0).is_none(), "REMB bitrate {bad} must be rejected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        brokered_identities, rendezvous_announcement, sign_agent_auth_challenge, BrokeredIdentities,
        ChallengeSigner, IceServer, RTCIceCredentialType, Role,
    };
    use rmt_protocol::signaling::{BrokeredAccess, BrokeredField, ClientToServer, ServerToClient};
    use rmt_protocol::{DeviceId, SessionId};
    use std::sync::{Arc, Mutex};

    /// The `brokered` identity read, pinned so a SWAP of the two fields cannot ship.
    ///
    /// This is the receiving end of the hop the signaling server tests cover from the other side.
    /// The values are deliberately DISTINCT and each is asserted by name, because the failure being
    /// guarded against is not "a value was lost" — it is "the right values arrived in the wrong
    /// slots", which every log line, every type check and the control plane's own validation would
    /// all report as normal.
    #[test]
    fn brokered_identities_reads_each_field_into_its_own_slot() {
        let cp: uuid::Uuid = "11111111-1111-4111-8111-111111111111".parse().unwrap();
        let tech: uuid::Uuid = "22222222-2222-4222-8222-222222222222".parse().unwrap();
        let msg = ServerToClient::Brokered {
            session: SessionId::new(),
            peer_device: None,
            peer_pubkey: String::new(),
            control_plane_session: Some(cp),
            technician_id: Some(tech),
            access: Some(BrokeredField::Text("view_only".into())),
            access_version: Some(BrokeredField::Integer(1)),
        };

        let ids = brokered_identities(&msg);
        assert_eq!(
            ids.control_plane_session,
            Some(cp),
            "the session policy and the elevation grant bind to this"
        );
        assert_eq!(
            ids.technician,
            Some(tech),
            "every audit event this session seals is stamped with this"
        );
        // Belt and braces against a copy-paste that reads one field twice.
        assert_ne!(ids.control_plane_session, ids.technician);
        assert_eq!(ids.access, BrokeredAccess::ViewOnly, "the observer floor keys on this");
    }

    /// A server that vouched for NEITHER yields `None` for both — the fail-closed reading — and a
    /// message that is not `brokered` at all yields the same rather than panicking.
    ///
    /// The second half matters because the read now happens for EVERY inbound signaling message,
    /// before the match that decides what the message is.
    #[test]
    fn brokered_identities_is_none_for_an_unvouched_broker_and_for_other_messages() {
        let bare = ServerToClient::Brokered {
            session: SessionId::new(),
            peer_device: None,
            peer_pubkey: String::new(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        };
        assert_eq!(brokered_identities(&bare), BrokeredIdentities::default());
        assert_eq!(brokered_identities(&bare).access, BrokeredAccess::Legacy, "an older server is legacy control");

        let other = ServerToClient::Rejected { reason: "nope".into() };
        assert_eq!(brokered_identities(&other), BrokeredIdentities::default());

        // One present and one absent is a legitimate wire state only in the sense that the decoder
        // permits it (a malformed technician degrades to None while the session id survives). It
        // must be reported as-is, never coalesced to "both unknown" — the session policy can still
        // bind, and only the audit trail is lost.
        let half = ServerToClient::Brokered {
            session: SessionId::new(),
            peer_device: None,
            peer_pubkey: String::new(),
            control_plane_session: Some(uuid::Uuid::from_u128(7)),
            technician_id: None,
            access: Some(BrokeredField::Text("view_only".into())),
            access_version: None,
        };
        let ids = brokered_identities(&half);
        assert_eq!(ids.control_plane_session, Some(uuid::Uuid::from_u128(7)));
        assert_eq!(ids.technician, None);
        // access without its marker is refused, never read as legacy control.
        assert_eq!(ids.access, BrokeredAccess::Invalid);
    }

    /// Records the preimage it was asked to sign and returns a fixed signature, so a test can
    /// assert *what* gets signed without pulling a crypto dependency into this crate.
    struct RecordingSigner {
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl ChallengeSigner for RecordingSigner {
        fn sign(&self, preimage: &[u8]) -> [u8; 64] {
            self.seen.lock().unwrap().push(preimage.to_vec());
            [0xab; 64]
        }
    }

    fn golden_device() -> DeviceId {
        DeviceId("9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7".parse().unwrap())
    }

    const GOLDEN_NONCE_HEX: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

    #[test]
    fn challenge_is_signed_over_the_canonical_preimage() {
        let signer = RecordingSigner { seen: Mutex::new(Vec::new()) };
        let out = sign_agent_auth_challenge(
            &signer,
            &golden_device(),
            Some("11111111-2222-3333-4444-555555555555"),
            GOLDEN_NONCE_HEX,
        )
        .expect("a well-formed nonce is signable");
        assert_eq!(out, "ab".repeat(64), "the wire carries hex of the 64-byte signature");

        // Exactly the bytes docs/11-agent-identity-contract.md §3.3 pins — the same preimage the
        // Go verifier rebuilds server-side.
        let seen = signer.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            hex::encode(&seen[0]),
            concat!(
                "524d544147454e544155544876310000010000002439663163326333612d3462",
                "35642d346536662d383039312d61326233633464356536663700000024313131",
                "31313131312d323232322d333333332d343434342d3535353535353535353535",
                "3500000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9ba",
                "bbbcbdbebf",
            )
        );
    }

    #[test]
    fn a_malformed_nonce_is_never_signed() {
        let signer = RecordingSigner { seen: Mutex::new(Vec::new()) };
        for bad in ["", "zz", &GOLDEN_NONCE_HEX[..62], &format!("{GOLDEN_NONCE_HEX}ff")] {
            assert!(
                sign_agent_auth_challenge(&signer, &golden_device(), Some("t"), bad).is_none(),
                "nonce {bad:?} must be refused"
            );
        }
        assert!(
            signer.seen.lock().unwrap().is_empty(),
            "a refused challenge must not reach the signing key at all"
        );
    }

    #[test]
    fn a_missing_tenant_signs_the_empty_string_rather_than_guessing() {
        let signer = RecordingSigner { seen: Mutex::new(Vec::new()) };
        sign_agent_auth_challenge(&signer, &golden_device(), None, GOLDEN_NONCE_HEX).unwrap();
        let seen = signer.seen.lock().unwrap();
        // 61 fixed bytes + 36-char device + 0-char tenant.
        assert_eq!(seen[0].len(), 61 + 36);
    }

    #[test]
    fn dev_agent_carries_no_tenant_and_no_signer() {
        // The loopback/e2e path: an enforcing server must not be able to register this peer.
        match Role::dev_agent(golden_device(), "ed25519:rmt-agent") {
            Role::Agent { tenant, signer, os, require_session_policy, agent_version, .. } => {
                assert!(tenant.is_none());
                assert!(signer.is_none());
                assert!(os.is_none(), "dev_agent announces no os");
                assert!(!require_session_policy, "dev_agent asserts no floor it does not have");
                assert!(
                    agent_version.is_none(),
                    "dev_agent is a test fixture, not a managed machine: it reports no build identity"
                );
            }
            _ => panic!("dev_agent must build an Agent role"),
        }
    }

    #[test]
    fn the_agent_announcement_carries_the_role_os_and_a_controllers_does_not() {
        // This is the pin on the SENDING side of the machine.os refresh AND of the loop-86
        // require_session_policy refresh: host_main builds an Agent role carrying both, and this
        // function is the only place that turns a role into the register_agent on the wire.
        // Dropping either here would leave every other test green while the feature silently
        // reverted — os to write-once-at-enrollment, the floor flag to never reported at all.
        let device = golden_device();
        let role = Role::Agent {
            device,
            pubkey: "aa".repeat(32),
            tenant: Some("t-1".into()),
            signer: None,
            os: Some("Windows 11 Pro 25H2 (build 26200)".into()),
            require_session_policy: true,
            agent_version: Some("0.4.0+abc1234".into()),
            logged_in_user: Some("CORP\\alice".into()),
            multi_session_capable: Some(true),
            features: vec!["directive_v1".into()],
        };
        match rendezvous_announcement(&role) {
            ClientToServer::RegisterAgent {
                device: d,
                pubkey,
                tenant,
                os,
                require_session_policy,
                agent_version,
                logged_in_user,
                features,
                ..
            } => {
                assert_eq!(d, device);
                assert_eq!(pubkey, "aa".repeat(32));
                assert_eq!(tenant.as_deref(), Some("t-1"));
                assert_eq!(os.as_deref(), Some("Windows 11 Pro 25H2 (build 26200)"));
                assert_eq!(require_session_policy, Some(true));
                // The build identity rides the SAME hop as os. Dropping it here would leave every
                // socket-level test green while machine.agent_version silently stopped refreshing,
                // which would make a rollout look like it landed when it had not.
                assert_eq!(agent_version.as_deref(), Some("0.4.0+abc1234"));
                // The logged-in user rides the same hop — dropping it here would leave every
                // socket-level test green while machine.logged_in_user silently stopped refreshing.
                assert_eq!(logged_in_user.as_deref(), Some("CORP\\alice"));
            }
            other => panic!("expected a register_agent, got {other:?}"),
        }
        // A CLEARED flag must reach the wire as an explicit false, not as an omission: the control
        // plane cannot otherwise learn the operator turned it off, and the machine would keep being
        // minted policies for a floor that no longer exists.
        let cleared = Role::Agent {
            device,
            pubkey: "aa".repeat(32),
            tenant: None,
            signer: None,
            os: None,
            require_session_policy: false,
            agent_version: None,
            logged_in_user: None,
            multi_session_capable: None,
            features: Vec::new(),
        };
        match rendezvous_announcement(&cleared) {
            ClientToServer::RegisterAgent { require_session_policy, .. } => {
                assert_eq!(
                    require_session_policy,
                    Some(false),
                    "a cleared flag must be reported, not omitted"
                );
            }
            other => panic!("expected a register_agent, got {other:?}"),
        }
        // A controller has no machine row to refresh, so it must announce none.
        match rendezvous_announcement(&Role::dev_controller(device)) {
            ClientToServer::RegisterAgent { os, require_session_policy, agent_version, .. } => {
                assert!(os.is_none(), "a controller must not announce an os");
                assert!(
                    require_session_policy.is_none(),
                    "a controller has no machine row and must assert nothing about a floor"
                );
                assert!(
                    agent_version.is_none(),
                    "a controller has no machine row: announcing a version would put a ghost \
                     entry in the presence feed for every open console tab"
                );
            }
            other => panic!("expected a register_agent, got {other:?}"),
        }
    }

    #[test]
    fn a_signer_is_usable_behind_an_arc_dyn() {
        // `Role::Agent.signer` is an `Arc<dyn ChallengeSigner>`; keep that object-safe.
        let signer: Arc<dyn ChallengeSigner> =
            Arc::new(RecordingSigner { seen: Mutex::new(Vec::new()) });
        assert_eq!(signer.sign(b"x"), [0xab; 64]);
    }

    #[test]
    fn stun_server_has_no_credentials() {
        let s = IceServer::stun("stun:stun.example:3478");
        assert_eq!(s.urls, vec!["stun:stun.example:3478".to_string()]);
        assert!(s.username.is_none() && s.credential.is_none());
        let rtc = s.to_rtc();
        assert_eq!(rtc.urls, vec!["stun:stun.example:3478".to_string()]);
        // Absent credentials map to empty strings (webrtc-rs's "no credential" representation).
        assert!(rtc.username.is_empty() && rtc.credential.is_empty());
    }

    #[test]
    fn turn_server_carries_credentials() {
        let s = IceServer::turn("turn:turn.example:3478?transport=udp", "user", "pass");
        let rtc = s.to_rtc();
        assert_eq!(rtc.urls, vec!["turn:turn.example:3478?transport=udp".to_string()]);
        assert_eq!(rtc.username, "user");
        assert_eq!(rtc.credential, "pass");
    }

    /// **A TURN entry must declare `credential_type: Password`, and a STUN entry must not.**
    ///
    /// webrtc-rs validates ICE servers when the peer connection is constructed. A TURN URL with
    /// credentials of the default `Unspecified` type is rejected with "invalid turn server
    /// credentials" and fails the WHOLE connect — not merely the relay path — so the mistake is
    /// total rather than degrading. It is also invisible to any test that stops at "the URL and
    /// password were carried through", which is what the test above does.
    ///
    /// Found by running the real thing against a TURN-configured signaling server; this is the
    /// regression net so it is not reintroduced by a `..Default::default()`.
    #[test]
    fn credential_type_is_set_for_turn_and_left_unspecified_for_stun() {
        let turn = IceServer::turn("turn:turn.example:3478", "u", "p").to_rtc();
        assert_eq!(
            turn.credential_type,
            RTCIceCredentialType::Password,
            "a TURN entry with Unspecified credentials is rejected by webrtc-rs at construction"
        );

        let stun = IceServer::stun("stun:stun.example:3478").to_rtc();
        assert_eq!(
            stun.credential_type,
            RTCIceCredentialType::Unspecified,
            "declaring Password with empty credentials fails the same validation the other way"
        );
        assert!(stun.username.is_empty() && stun.credential.is_empty());
    }

    /// The RTCP/ICE distinction the whole WAN path rests on: `is_turn` must recognise a relay
    /// server, and must not mistake a STUN one for it. It is what the `ice_relay=N` diagnostic
    /// reports, and that number is the difference between "TURN was not needed" and "TURN was
    /// never configured".
    #[test]
    fn is_turn_recognises_relay_servers_only() {
        assert!(IceServer::turn("turn:t.example:3478", "u", "p").is_turn());
        assert!(IceServer::turn("turns:t.example:5349?transport=tcp", "u", "p").is_turn());
        assert!(!IceServer::stun("stun:s.example:3478").is_turn());
        // A grouped entry counts as relay if ANY url is one — that is how a single credential
        // covers udp+tcp.
        let grouped = IceServer {
            urls: vec!["stun:s.example:3478".into(), "turn:t.example:3478".into()],
            username: Some("u".into()),
            credential: Some("p".into()),
        };
        assert!(grouped.is_turn());
    }
}

/// The encoder queue's back-pressure behaviour, driven through the **shipped** loop
/// ([`run_encoder_loop`]) with an injected encoder of known, controllable speed.
///
/// Why an injected encoder rather than libvpx: the defect is a queueing property, and it only
/// appears when capture outruns encode. Real VP8 on this box encodes a small frame in well under a
/// millisecond, so reproducing the overload with the real encoder would need a frame rate no
/// capturer produces — the experiment could not fail, which makes it worthless (see docs/07 on
/// content-gated rate tests). A fixed `per_frame` cost makes the overload exact and repeatable.
///
/// Everything else is production: the real `VideoFrameSender::send` (so the depth counter is
/// incremented exactly as it is in the field), the real `EncoderCommand` queue, the real loop.
#[cfg(test)]
mod encoder_queue_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// One call the fake encoder recorded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Encoded {
        /// Frame identity, read back out of the BGRA bytes — this is how a test tells WHICH frame
        /// survived a drain. A counter would only say how many did.
        marker: u32,
        /// The duration the loop computed for this frame, in 90 kHz ticks.
        ticks: u32,
        /// Whether a keyframe had been requested when this frame was encoded.
        keyframe: bool,
    }

    #[derive(Default, Debug)]
    struct EncoderLog {
        encodes: Vec<Encoded>,
        bitrates: Vec<u32>,
        chromas: Vec<video::ChromaMode>,
    }

    /// Blocks the encoder inside its FIRST `encode_bgra` until the test releases it.
    ///
    /// This is what makes the drain tests deterministic instead of a race against a `sleep`: while
    /// the encoder is held, everything the test enqueues is guaranteed to be sitting in the queue
    /// when the drain pass runs, so the assertions are about the loop's logic and not about how
    /// busy the box was.
    struct Gate {
        entered_tx: std::sync::mpsc::Sender<()>,
        release_rx: std::sync::mpsc::Receiver<()>,
    }

    /// The test's end of a [`Gate`].
    struct GateControl {
        entered_rx: std::sync::mpsc::Receiver<()>,
        release_tx: std::sync::mpsc::Sender<()>,
    }

    impl GateControl {
        /// Block until the encoder is inside its first encode — i.e. that frame has left the queue.
        fn wait_entered(&self) {
            self.entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("encoder entered its first encode");
        }
        fn release(&self) {
            self.release_tx.send(()).expect("encoder still waiting");
        }
    }

    /// A `VideoEncoder` that costs a fixed wall-clock time per frame and records what it was told.
    struct SlowEncoder {
        per_frame: Duration,
        log: Arc<StdMutex<EncoderLog>>,
        kf_pending: bool,
        gate: Option<Gate>,
    }

    impl video::VideoEncoder for SlowEncoder {
        fn encode_bgra(
            &mut self,
            bgra: &[u8],
            w: usize,
            h: usize,
            duration_90khz: u32,
        ) -> Result<video::EncodedAu, String> {
            let marker = u32::from_le_bytes([bgra[0], bgra[1], bgra[2], bgra[3]]);
            let keyframe = std::mem::take(&mut self.kf_pending);
            self.log.lock().unwrap().encodes.push(Encoded {
                marker,
                ticks: duration_90khz,
                keyframe,
            });
            // One-shot: `take` means only the first frame is held.
            if let Some(g) = self.gate.take() {
                let _ = g.entered_tx.send(());
                let _ = g.release_rx.recv();
            }
            std::thread::sleep(self.per_frame);
            // The marker is echoed into the ENCODED bytes, not just the log, so a consumer
            // downstream of the encoder (the recording tee) can say WHICH frames it received rather
            // than only how many. A real encoder's output depends on its input too; a fake that
            // emitted a constant would let a tee that duplicated or reordered frames pass.
            let mut data = vec![0u8; 64];
            data[..4].copy_from_slice(&marker.to_le_bytes());
            Ok(video::EncodedAu {
                data,
                keyframe,
                duration_90khz,
                width: w as u32,
                height: h as u32,
            })
        }
        fn request_keyframe(&mut self) {
            self.kf_pending = true;
        }
        fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), String> {
            self.log.lock().unwrap().bitrates.push(bitrate_bps);
            Ok(())
        }
        fn set_chroma_mode(&mut self, mode: video::ChromaMode) -> Result<(), String> {
            self.log.lock().unwrap().chromas.push(mode);
            Ok(())
        }
        fn webrtc_mime_type(&self) -> &'static str {
            video::NEGOTIATED_MIME_TYPE
        }
        fn codec_name(&self) -> &'static str {
            "slow-test-encoder"
        }
    }

    /// A running encode pipeline: the shipped loop on its own thread, plus the production
    /// `VideoFrameSender` that feeds it.
    struct Harness {
        sender: Option<VideoFrameSender>,
        rate: Arc<VideoRateState>,
        log: Arc<StdMutex<EncoderLog>>,
        join: Option<std::thread::JoinHandle<()>>,
        au_rx: mpsc::Receiver<video::EncodedAu>,
    }

    impl Harness {
        fn start(per_frame: Duration) -> Self {
            Self::start_inner(per_frame, None).0
        }

        /// Start with the encoder held inside its first encode until the returned control releases
        /// it.
        fn start_gated(per_frame: Duration) -> (Self, GateControl) {
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (h, ()) = Self::start_inner(
                per_frame,
                Some(Gate {
                    entered_tx,
                    release_rx,
                }),
            );
            (
                h,
                GateControl {
                    entered_rx,
                    release_tx,
                },
            )
        }

        fn start_inner(per_frame: Duration, gate: Option<Gate>) -> (Self, ()) {
            let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<EncoderCommand>();
            let (au_tx, au_rx) = mpsc::channel::<video::EncodedAu>(MAX_PENDING_VIDEO_AUS);
            let rate = Arc::new(VideoRateState::default());
            let log = Arc::new(StdMutex::new(EncoderLog::default()));
            let (rate_t, log_t) = (rate.clone(), log.clone());
            let join = std::thread::spawn(move || {
                let enc: Box<dyn video::VideoEncoder> = Box::new(SlowEncoder {
                    per_frame,
                    log: log_t,
                    kf_pending: false,
                    gate,
                });
                run_encoder_loop(enc, cmd_rx, au_tx, rate_t);
            });
            (
                Self {
                    sender: Some(VideoFrameSender {
                        tx: cmd_tx,
                        rate: rate.clone(),
                    }),
                    rate,
                    log,
                    join: Some(join),
                    au_rx,
                },
                (),
            )
        }

        fn sender(&self) -> &VideoFrameSender {
            self.sender.as_ref().expect("sender still held")
        }

        /// Push one 8x8 BGRA frame carrying `marker` in its first four bytes, through the
        /// production `VideoFrameSender::send` — so the depth counter is incremented by the same
        /// code the agent runs.
        fn push(&self, marker: u32) {
            let mut bytes = vec![0u8; 8 * 8 * 4];
            bytes[..4].copy_from_slice(&marker.to_le_bytes());
            self.sender()
                .send(&CapturedFrame {
                    monitor_id: 0,
                    width: 8,
                    height: 8,
                    bytes,
                    is_keyframe: false,
                })
                .expect("pipeline open");
        }

        /// Enqueue a non-`Frame` command directly. The interleaving with frames is the thing under
        /// test, and `set_quality` can only ever produce one fixed pair.
        fn command(&self, cmd: EncoderCommand) {
            self.sender().tx.send(cmd).expect("pipeline open");
        }

        fn depth(&self) -> u64 {
            self.rate.queued_frames.load(Ordering::Relaxed)
        }

        fn dropped(&self) -> u64 {
            self.rate.dropped_frames.load(Ordering::Relaxed)
        }

        /// Block until the encoder has produced one access unit.
        ///
        /// This is what lets a test pace the producer by the CONSUMER instead of by a `sleep`, so
        /// "only one frame is ever in flight" is a fact rather than a hope on a loaded box.
        fn wait_encoded(&mut self) {
            self.au_rx
                .blocking_recv()
                .expect("encoder produced an access unit");
        }

        /// Drop the sender and wait for the loop to finish the backlog it still holds.
        fn finish(mut self) -> EncoderLog {
            drop(self.sender.take());
            // That was the last strong `cmd_tx`; the loop drains what is buffered and exits.
            self.join.take().unwrap().join().expect("encoder loop");
            std::mem::take(&mut *self.log.lock().unwrap())
        }
    }

    /// Codex 1.3.24 r3: a SetBitrate published at 9 Mbps, delayed while the picture shrank (target
    /// clamped to 3 Mbps) and regrew (ceiling 9 Mbps again, target still 3 Mbps), must not leave the
    /// encoder at 9 Mbps: a bitrate command applies the CURRENT shared target.
    #[test]
    fn a_delayed_bitrate_command_applies_the_current_target_not_its_own_value() {
        let mut h = Harness::start(Duration::ZERO);
        h.sender().set_quality(VideoQuality {
            color: video::ChromaMode::Full,
            max_bitrate_bps: 3_000_000,
            hard_cap_bps: None,
            adaptive: true,
        }).unwrap();
        let frame = |h: &mut Harness, w: usize, ht: usize| {
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(vec![0; 4], w, ht, Instant::now()));
            h.wait_encoded();
        };
        frame(&mut h, 5120, 2486);
        assert_eq!(h.rate.ceiling_bps.load(Ordering::Relaxed), 9_000_000);
        // The controller climbed and published 9 Mbps; its command is still in flight.
        h.rate.target_bps.store(9_000_000, Ordering::Relaxed);
        frame(&mut h, 1920, 1080); // shrink: target clamped to 3 Mbps
        frame(&mut h, 5120, 2486); // regrow: ceiling 9 Mbps, target stays 3 Mbps
        assert_eq!(h.rate.target_bps.load(Ordering::Relaxed), 3_000_000);
        h.command(EncoderCommand::SetBitrate(9_000_000)); // the delayed command
        frame(&mut h, 5120, 2486);
        assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), 3_000_000, "the stale 9 Mbps must not be applied");
        h.finish();
    }

    #[test]
    fn pixel_ceiling_factor_and_wire_bound() {
        for (w, h) in [(1920, 1080), (1280, 720), (0, 1080), (1920, 0), (0, 0)] {
            assert_eq!(effective_video_ceiling(3_000_000, w, h), (3_000_000, 1.0));
        }
        assert_eq!(effective_video_ceiling(3_000_000, 5120, 2486), (9_000_000, 3.0));
        let (bps, factor) = effective_video_ceiling(3_000_000, 2560, 1440);
        assert!((factor - 16.0 / 9.0).abs() < 0.000001);
        assert_eq!(bps, 5_333_333);
        for base in [3_000_000, 8_000_000, u32::MAX] {
            assert!(effective_video_ceiling(base, u32::MAX, u32::MAX).0 <= video::MAX_BITRATE_BPS);
        }
    }

    #[test]
    fn encoded_canvas_retargets_and_1080p_immediately_clamps() {
        let mut h = Harness::start(Duration::ZERO);
        h.sender().set_quality(VideoQuality {
            color: video::ChromaMode::Full,
            max_bitrate_bps: 3_000_000,
            hard_cap_bps: None,
            adaptive: false,
        }).unwrap();
        for (width, height, expected) in [(5120, 2486, 9_000_000), (1920, 1080, 3_000_000)] {
            let epoch = h.rate.quality_epoch.load(Ordering::Acquire);
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            // The injected encoder only reads the marker; dimensions travel through the real loop.
            h.command(EncoderCommand::Frame(vec![0; 4], width, height, Instant::now()));
            h.wait_encoded();
            assert_eq!(h.rate.ceiling_bps.load(Ordering::Relaxed), expected);
            assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), expected);
            assert_eq!(h.rate.target_bps.load(Ordering::Relaxed), expected);
            assert!(h.rate.quality_epoch.load(Ordering::Acquire) > epoch);
            assert_eq!(h.log.lock().unwrap().bitrates.last(), Some(&expected));
        }
        h.finish();
    }

    #[test]
    fn shrink_grow_between_reports_recovers_from_encoder_target() {
        let mut h = Harness::start(Duration::ZERO);
        h.sender().set_quality(VideoQuality { color: video::ChromaMode::Full,
            max_bitrate_bps: 3_000_000, hard_cap_bps: None, adaptive: false }).unwrap();
        for (w, ht) in [(5120, 2486)] {
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(vec![0; 4], w, ht, Instant::now()));
            h.wait_encoded();
        }
        h.sender().set_quality(VideoQuality { color: video::ChromaMode::Full,
            max_bitrate_bps: 3_000_000, hard_cap_bps: None, adaptive: true }).unwrap();
        let mut bwe = video::rate::LossBasedBwe::new(9_000_000);
        let epoch = h.rate.quality_epoch.load(Ordering::Acquire);
        for (w, ht) in [(1920, 1080), (5120, 2486)] {
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(vec![0; 4], w, ht, Instant::now()));
            h.wait_encoded();
        }
        assert!(h.rate.quality_epoch.load(Ordering::Acquire) > epoch);
        let now = Instant::now();
        let adopted = bwe.adopt_target(h.rate.target_bps.load(Ordering::Relaxed), now,
            h.rate.ceiling_bps.load(Ordering::Relaxed), true);
        assert_eq!(adopted, 3_000_000);
        assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), adopted);
        assert_eq!(bwe.on_feedback(video::rate::Feedback::Rr { fraction_lost_256: 0, rtt: None },
            now, video::rate::RateInputs { ceiling_bps: 9_000_000, adaptive: true, encoded_bytes: 100_000, measured_bps: adopted }), None);
        let mut previous = adopted;
        for i in 1..=4 {
            let bps = bwe.on_feedback(video::rate::Feedback::Rr { fraction_lost_256: 0, rtt: None },
                now + Duration::from_secs(i), video::rate::RateInputs {
                    ceiling_bps: 9_000_000, adaptive: true, encoded_bytes: i * 500_000, measured_bps: previous,
                }).expect("clean feedback climbs from adopted target");
            assert!(bps > previous);
            h.rate.target_bps.store(bps, Ordering::Relaxed);
            h.command(EncoderCommand::SetBitrate(bps));
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(vec![0; 4], 5120, 2486, Instant::now()));
            h.wait_encoded();
            assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), bps);
            previous = bps;
        }
        h.finish();
    }

    #[test]
    fn configured_cap_binds_scaled_canvas() {
        for (cap, expected) in [(Some(3_000_000), 3_000_000), (None, 9_000_000)] {
            let mut h = Harness::start(Duration::ZERO);
            h.sender().set_quality(VideoQuality { color: video::ChromaMode::Full,
                max_bitrate_bps: 3_000_000, hard_cap_bps: cap, adaptive: false }).unwrap();
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(vec![0; 4], 5120, 2486, Instant::now()));
            h.wait_encoded();
            assert_eq!(h.rate.ceiling_bps.load(Ordering::Relaxed), expected);
            assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), expected);
            assert_eq!(VideoStatsHandle::new(h.rate.clone()).capped_by_bitrate_policy(), cap.is_some());
            h.finish();
        }
    }

    #[test]
    fn adaptive_canvas_preserves_backoff_and_clamps_on_shrink() {
        let mut h = Harness::start(Duration::ZERO);
        h.sender().set_quality(VideoQuality {
            color: video::ChromaMode::Full,
            max_bitrate_bps: 3_000_000,
            hard_cap_bps: None,
            adaptive: true,
        }).unwrap();
        h.rate.target_bps.store(2_000_000, Ordering::Relaxed);
        h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
        h.command(EncoderCommand::Frame(vec![0; 4], 5120, 2486, Instant::now()));
        h.wait_encoded();
        assert_eq!(h.rate.ceiling_bps.load(Ordering::Relaxed), 9_000_000);
        assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), 2_000_000);
        // An operator base change uses the current canvas dimensions.
        h.sender().set_quality(VideoQuality {
            color: video::ChromaMode::Full,
            max_bitrate_bps: 8_000_000,
            hard_cap_bps: None,
            adaptive: true,
        }).unwrap();
        assert_eq!(h.rate.ceiling_bps.load(Ordering::Relaxed), video::MAX_BITRATE_BPS);
        // Model a controller that has recovered above the single-display ceiling.
        h.rate.target_bps.store(12_000_000, Ordering::Relaxed);
        h.command(EncoderCommand::SetBitrate(12_000_000));
        h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
        h.command(EncoderCommand::Frame(vec![0; 4], 1920, 1080, Instant::now()));
        h.wait_encoded();
        assert_eq!(h.rate.applied_bps.load(Ordering::Relaxed), 8_000_000);
        assert_eq!(h.rate.target_bps.load(Ordering::Relaxed), 8_000_000);
        h.finish();
    }

    #[test]
    fn stalled_writer_bounds_aus_without_losing_references_or_pending_controls() {
        let mut h = Harness::start(Duration::ZERO);
        let start = Instant::now();
        let push_at = |h: &Harness, marker: u32| {
            let mut bytes = vec![0; 8 * 8 * 4];
            bytes[..4].copy_from_slice(&marker.to_le_bytes());
            h.rate.queued_frames.fetch_add(1, Ordering::Relaxed);
            h.command(EncoderCommand::Frame(
                bytes, 8, 8, start + Duration::from_millis(marker as u64 * 10),
            ));
        };
        let wait_for = |condition: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !condition() {
                assert!(Instant::now() < deadline, "encoder did not make progress");
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        // Fill the actual AU queue, pacing each submission so raw-frame draining cannot hide
        // an unbounded output queue. No RTP writer consumes anything during the overload.
        for marker in 0..MAX_PENDING_VIDEO_AUS as u32 {
            push_at(&h, marker);
            wait_for(&|| h.au_rx.len() == marker as usize + 1);
        }
        h.command(EncoderCommand::Keyframe);
        h.command(EncoderCommand::SetBitrate(777_000));
        h.command(EncoderCommand::SetChroma(video::ChromaMode::Gray));
        for marker in MAX_PENDING_VIDEO_AUS as u32..24 {
            push_at(&h, marker);
            wait_for(&|| h.dropped() == (marker + 1 - MAX_PENDING_VIDEO_AUS as u32) as u64);
            assert_eq!(h.au_rx.len(), MAX_PENDING_VIDEO_AUS);
        }
        assert_eq!(h.depth(), 0);
        assert_eq!(h.log.lock().unwrap().encodes.len(), MAX_PENDING_VIDEO_AUS);
        // All old AUs still form the original chain; nothing encoded was discarded or reordered.
        for marker in 0..MAX_PENDING_VIDEO_AUS as u32 {
            let au = h.au_rx.try_recv().unwrap();
            assert_eq!(u32::from_le_bytes(au.data[..4].try_into().unwrap()), marker);
        }
        push_at(&h, 24);
        let resumed = h.au_rx.blocking_recv().unwrap();
        assert_eq!(u32::from_le_bytes(resumed.data[..4].try_into().unwrap()), 24);
        assert!(resumed.keyframe, "full queue must not consume a pending repair request");
        assert_eq!(resumed.duration_90khz, 18_900, "include the raw frames skipped after frame 3");
        let log = h.finish();
        assert_eq!(log.bitrates, vec![777_000]);
        assert_eq!(log.chromas, vec![video::ChromaMode::Gray]);
        assert_eq!(log.encodes.len(), MAX_PENDING_VIDEO_AUS + 1);
    }

    #[test]
    fn closed_writer_stops_encoder_before_encoding() {
        let mut h = Harness::start(Duration::ZERO);
        h.au_rx.close();
        h.push(0);
        let log = h.finish();
        assert!(log.encodes.is_empty());
    }

    /// Run a sustained overload: push frames every `interval` for `run`, sampling the queue depth,
    /// and return `(peak_depth, frames_pushed)`.
    fn overload(h: &mut Harness, interval: Duration, run: Duration) -> (u64, u32) {
        let start = Instant::now();
        let mut peak = 0u64;
        let mut marker = 0u32;
        while start.elapsed() < run {
            // These tests isolate a slow ENCODER. Keep the writer caught up so bounded output
            // does not replace the raw-input overload with the separate stalled-writer case.
            while h.au_rx.try_recv().is_ok() {}
            h.push(marker);
            marker += 1;
            peak = peak.max(h.depth());
            std::thread::sleep(interval);
        }
        (peak.max(h.depth()), marker)
    }

    /// **The measurement.** An unbounded queue's peak depth grows with the length of the overload;
    /// a drain-to-latest queue's does not. Both durations are run and both peaks printed, because
    /// seeing them side by side is the evidence a human reads.
    ///
    /// The ASSERTION, though, is deliberately not `peak_long ≈ peak_short`. That comparison is
    /// brittle on a loaded box for a reason unrelated to the property: one scheduling stall of the
    /// encoder thread lets the producer pile up frames, spiking a peak that has nothing to do with
    /// boundedness — and it flaked exactly that way during this loop's own workspace run.
    ///
    /// Asserted instead: **peak depth is a small fraction of throughput, rather than proportional
    /// to it.** That is stall-immune (a stall inflates the peak by a bounded burst, not by a factor
    /// of the run length) and it separates the two behaviours by a wide margin — measured before
    /// the fix, peak was ~78 % of everything pushed (106 of 136, 315 of 403); after, ~1–4 %
    /// (5 of 136, 5 of 403). A quarter is far above the latter and far below the former.
    ///
    /// Ratios, never absolutes, because the encode cost is a `sleep` on a shared CI-less dev box.
    #[test]
    fn queue_depth_does_not_grow_with_the_length_of_the_overload() {
        // 4 ms capture cadence (250 fps-equivalent) against a 20 ms encoder: capture outruns encode
        // 5:1, the same shape as 60 fps capture against a 1080p encode that cannot keep up.
        let mut short = Harness::start(Duration::from_millis(20));
        let (peak_short, pushed_short) = overload(&mut short, Duration::from_millis(4), Duration::from_millis(600));
        let mut long = Harness::start(Duration::from_millis(20));
        let (peak_long, pushed_long) = overload(&mut long, Duration::from_millis(4), Duration::from_millis(1800));

        println!(
            "MEASURE overload: 600ms pushed={pushed_short} peak={peak_short} | \
             1800ms pushed={pushed_long} peak={peak_long}"
        );

        // Sanity: the experiment must actually have been an overload, or it proves nothing.
        assert!(
            pushed_short > 50 && pushed_long > 150,
            "producer did not run: pushed {pushed_short}/{pushed_long}"
        );

        // The property, stated stall-immunely: depth stays a small fraction of throughput in BOTH
        // runs. An unbounded queue cannot satisfy this at any duration, because every frame the
        // producer emits during the overload is still sitting in it.
        for (label, peak, pushed) in [
            ("600ms", peak_short, pushed_short as u64),
            ("1800ms", peak_long, pushed_long as u64),
        ] {
            assert!(
                peak * 4 < pushed,
                "{label} run: peak depth {peak} of {pushed} frames pushed — the queue is holding a \
                 large fraction of everything captured, i.e. nothing is dropping a stale frame \
                 (600ms peak {peak_short}, 1800ms peak {peak_long})"
            );
        }

        let short_log = short.finish();
        let long_log = long.finish();
        println!(
            "MEASURE encoded: short={} of {} | long={} of {}",
            short_log.encodes.len(),
            pushed_short,
            long_log.encodes.len(),
            pushed_long
        );
    }

    /// The *semantic* claim, stated exactly rather than statistically: when frames pile up behind a
    /// busy encoder, the one that survives is the NEWEST — the picture the screen actually shows —
    /// and every superseded frame is counted, not silently vanished.
    ///
    /// Deterministic via the gate: frame 0 is held inside the encoder, so frames 1..=9 are provably
    /// all in the queue when the drain pass runs.
    #[test]
    fn the_newest_frame_survives_a_drain_and_the_stale_ones_are_counted() {
        let (h, gate) = Harness::start_gated(Duration::ZERO);
        h.push(0);
        gate.wait_entered();
        for m in 1..=9 {
            h.push(m);
        }
        assert_eq!(h.depth(), 9, "frame 0 has left the queue; 1..=9 are waiting");
        gate.release();
        let log = h.finish();

        let markers: Vec<u32> = log.encodes.iter().map(|e| e.marker).collect();
        assert_eq!(
            markers,
            vec![0, 9],
            "only the held frame and the newest survivor should be encoded"
        );
        // 1..=8 were superseded. 9 was not dropped — it was encoded.
        assert_eq!(log.encodes.len(), 2);
    }

    /// The depth gauge must be EXACT, not merely bounded. A drain that decremented once per pass
    /// instead of once per frame would leave the counter permanently high, and the operator-facing
    /// `queued`/`dropped` log line would then report a healthy session as an overloaded one — the
    /// instrument lying in precisely the situation it exists for.
    #[test]
    fn the_depth_and_dropped_counters_account_for_every_frame() {
        let (h, gate) = Harness::start_gated(Duration::ZERO);
        h.push(0);
        gate.wait_entered();
        for m in 1..=9 {
            h.push(m);
        }
        gate.release();
        let rate = h.rate.clone();
        let log = h.finish();

        let encoded = log.encodes.len() as u64;
        let dropped = rate.dropped_frames.load(Ordering::Relaxed);
        assert_eq!(encoded, 2, "2 encoded");
        assert_eq!(dropped, 8, "8 superseded");
        assert_eq!(encoded + dropped, 10, "every pushed frame is accounted for");
        assert_eq!(
            rate.queued_frames.load(Ordering::Relaxed),
            0,
            "the depth gauge returns to zero"
        );
        assert_eq!(rate.encoded_frames.load(Ordering::Relaxed), encoded);
    }

    /// **The requirement the fix could most easily have got wrong.** A drain that threw away
    /// everything it did not keep would discard `SetBitrate` — disabling rate control at exactly
    /// the moment overload makes it necessary, which is the defect's own aggravating factor (M11
    /// deliberately routes rate control through this queue). `SetChroma` and `Keyframe` are on the
    /// same queue and must survive for the same reason.
    #[test]
    fn a_drained_batch_still_applies_bitrate_chroma_and_keyframe_commands() {
        let (h, gate) = Harness::start_gated(Duration::ZERO);
        h.push(0);
        gate.wait_entered();
        // Interleaved exactly as the live session produces them: the RTCP loop and the operator
        // both write into the same queue the capture path is filling.
        h.push(1);
        h.command(EncoderCommand::SetBitrate(777_000));
        h.push(2);
        h.command(EncoderCommand::SetChroma(video::ChromaMode::Gray));
        h.push(3);
        h.command(EncoderCommand::Keyframe);
        h.push(4);
        gate.release();
        let rate = h.rate.clone();
        let log = h.finish();

        assert_eq!(
            log.bitrates,
            vec![777_000],
            "the retarget must survive the drain"
        );
        assert_eq!(
            log.chromas,
            vec![video::ChromaMode::Gray],
            "the colour-mode change must survive the drain"
        );
        assert_eq!(
            rate.applied_bps.load(Ordering::Relaxed),
            777_000,
            "and be reported as applied, since libvpx accepted it"
        );
        let markers: Vec<u32> = log.encodes.iter().map(|e| e.marker).collect();
        assert_eq!(markers, vec![0, 4], "the newest frame is still the survivor");
        assert!(
            log.encodes[1].keyframe,
            "the keyframe request must survive the drain and land on the surviving frame"
        );
        assert_eq!(rate.dropped_frames.load(Ordering::Relaxed), 3);
    }

    /// Dropping frames lowers the frame rate, and libvpx learns the frame rate from the gap between
    /// presentation timestamps (docs/07 — proven by mutation: a constant PTS step dies, a constant
    /// `duration` argument survives). So the surviving frame must be charged the WHOLE span of the
    /// frames it superseded.
    ///
    /// The discriminator: a drain that kept the newest pixels but the *head* frame's hand-off
    /// instant would report one frame interval here instead of three, and libvpx would budget bits
    /// for a frame rate the pipeline is no longer delivering.
    #[test]
    fn the_superseded_frames_span_is_charged_to_the_surviving_frame() {
        const STEP: Duration = Duration::from_millis(30);
        let (h, gate) = Harness::start_gated(Duration::ZERO);
        h.push(0);
        gate.wait_entered();
        for m in 1..=3 {
            std::thread::sleep(STEP);
            h.push(m);
        }
        gate.release();
        let log = h.finish();

        assert_eq!(log.encodes.len(), 2);
        assert_eq!(
            log.encodes[0].ticks, NOMINAL_TICKS,
            "the very first frame has no predecessor to measure against"
        );
        // Three 30 ms steps ≈ 8100 ticks. One step alone would be ~2700, so the floor below is far
        // clear of the wrong answer while leaving room for Windows' ~15.6 ms timer granularity.
        let ticks = log.encodes[1].ticks;
        let one_step = (STEP.as_secs_f64() * video::VIDEO_CLOCK_RATE as f64) as u32;
        assert!(
            ticks > one_step * 2,
            "surviving frame charged {ticks} ticks; a single step is ~{one_step}, so the dropped \
             span was not folded in"
        );
        // Deliberately NO `assert!(ticks <= MAX_TICKS)` here. It reads like clamp coverage but the
        // loop clamps before calling the encoder, so it cannot fail — a tautology whose message
        // claims a guarantee the test does not provide. The clamp is pinned for real by
        // `the_frame_duration_clamps_line_up_with_the_wire_limits`.
    }

    /// `0` must mean "not yet measurable", never "the stream stalled". A window shorter than a
    /// millisecond cannot be divided by, and a renderer that treated the result as a real frame
    /// rate would show a freeze that is not happening.
    #[test]
    fn achieved_fps_is_not_measurable_over_a_zero_length_window() {
        let s = VideoSendStats {
            frames_in_window: 30,
            window_ms: 0,
            ..Default::default()
        };
        assert_eq!(s.achieved_fps_x100(), 0);
    }

    /// The arithmetic, pinned against the window it is actually measured over — not against an
    /// assumed 1 Hz tick. A timer that slipped to 2 s must report the same 15 fps, not 30.
    #[test]
    fn achieved_fps_is_a_rate_over_the_measured_window_not_a_raw_count() {
        let over = |frames, window_ms| {
            VideoSendStats {
                frames_in_window: frames,
                window_ms,
                ..Default::default()
            }
            .achieved_fps_x100()
        };
        assert_eq!(over(30, 1_000), 3_000, "30 frames in 1 s = 30.00 fps");
        assert_eq!(
            over(30, 2_000),
            1_500,
            "the SAME 30 frames over a slipped 2 s window is 15.00 fps — the whole reason the \
             window is on the wire"
        );
        assert_eq!(over(14, 970), 1_443, "14 frames in 970 ms = 14.43 fps");
        assert_eq!(over(0, 1_000), 0, "a genuine zero is still zero");
    }

    /// **The finding, closed.** An operator who commands a frame rate the pipeline cannot deliver
    /// must be told the achieved one. Drive the real `VideoStatsHandle::sample()` over a real
    /// overloaded encode and assert it reports the rate the encoder ACTUALLY delivered — not the
    /// rate anything was asked for.
    #[test]
    fn the_sampled_frame_rate_reports_what_the_encoder_delivered_not_what_was_asked() {
        // A 20 ms encoder can deliver at most 50 fps however fast capture pushes.
        const ENCODE_MS: u64 = 20;
        let mut h = Harness::start(Duration::from_millis(ENCODE_MS));
        let rate = h.rate.clone();
        let mut stats = VideoStatsHandle::new(h.rate.clone());
        let _ = stats.sample(); // establish the baseline, as the 1 Hz reporter does at arming
        let (_, pushed) = overload(&mut h, Duration::from_millis(4), Duration::from_millis(1_000));
        let s = stats.sample();
        let log = h.finish();

        println!(
            "MEASURE telemetry: pushed={pushed} fps_x100={} window_ms={} dropped={} encoded={}",
            s.achieved_fps_x100(),
            s.window_ms,
            s.dropped_frames,
            log.encodes.len()
        );

        assert!(s.window_ms > 500, "the window must be measured: {}", s.window_ms);
        let fps = s.achieved_fps_x100();
        // The encoder's own cost caps it at 1000/ENCODE_MS fps however fast capture pushes; the
        // producer pushed roughly 250 fps. The assertion is deliberately a WIDE band rather than a
        // tight one around the ceiling: a loaded box legitimately encodes slower, and a test that
        // fails because the machine was busy teaches nothing. What must never happen is this
        // number coming back anywhere near what was PUSHED — that would mean it restates the
        // operator's request instead of measuring the encoder.
        let ceiling = (1_000 / ENCODE_MS) as u32 * 100;
        assert!(
            fps > 200,
            "achieved {fps} (x100) — the stream is not moving at all, so this run measured nothing"
        );
        assert!(
            fps <= ceiling + 500,
            "achieved {fps} (x100) exceeds the encoder's own {ceiling} ceiling — this is reporting \
             the capture rate (~25000 x100 was pushed), not the encode rate"
        );
        // ...and the operator must be told WHY it is below what they set. Stated as a comparison
        // against the frames that DID encode, not merely `> 0`: a `dropped_frames` wired to the
        // wrong counter would satisfy "greater than zero" while reporting the opposite quantity.
        //
        // A MAJORITY, not a fixed multiple. This read `> frames_in_window * 2` until loop 91, and it
        // failed inside `verify-all` (dropped 70, encoded 38) while passing on an idle box five runs
        // out of five (dropped ~189, encoded ~50). The property did not change; the PACING did. The
        // producer paces on `sleep(4ms)`, and under the gate's own load that sleep lands nearer 9 ms
        // while the encoder's 20 ms stretches proportionally less — so the drop:encode ratio fell
        // from ~3.8:1 to ~2.8:1 and the window's own counts from 3.8:1 to 1.8:1, straddling a
        // threshold that had no margin. That is `pace-tests-by-the-consumer-not-a-sleep`: an
        // assertion whose band assumes a push rate the box does not guarantee.
        //
        // The band that survives is the one the PREMISE actually supports — the harness constructs a
        // producer faster than the encoder, so most frames must be superseded — and it keeps every
        // bit of the discriminating power, because the mis-wirings are all outside it:
        //   * wired to the ENCODED counter  ⇒ dropped == frames_in_window, fails here;
        //   * never incremented             ⇒ 0, fails here;
        //   * wired to everything PUSHED    ⇒ passes here, and fails the exact-accounting assertion
        //                                     below, which is load-independent.
        assert!(
            s.dropped_frames > s.frames_in_window,
            "more frames must be superseded ({}) than encoded ({}) under this overload",
            s.dropped_frames,
            s.frames_in_window
        );
        // Exact accounting once the pipeline has drained: nothing vanished.
        assert_eq!(
            rate.dropped_frames.load(Ordering::Relaxed) as usize + log.encodes.len(),
            pushed as usize,
            "every pushed frame was either encoded or counted as superseded"
        );
    }

    /// A send into a closed pipeline must leave the depth gauge exactly where it was.
    ///
    /// The counter is incremented BEFORE the enqueue (so the encoder can never decrement a frame
    /// the gauge has not yet counted), which means the failure path now has a rollback — and an
    /// un-rolled-back increment would make a dead session look permanently backed up, in the one
    /// number an operator would use to decide the agent is overloaded.
    #[test]
    fn a_send_into_a_closed_pipeline_leaves_the_depth_gauge_untouched() {
        // Built from the parts rather than through `Harness`: what must be gone is the RECEIVER,
        // and the harness owns that inside its encoder thread.
        let (tx, rx) = mpsc::unbounded_channel::<EncoderCommand>();
        let rate = Arc::new(VideoRateState::default());
        let sender = VideoFrameSender {
            tx,
            rate: rate.clone(),
        };
        drop(rx); // no encoder on the other end

        let err = sender
            .send(&CapturedFrame {
                monitor_id: 0,
                width: 8,
                height: 8,
                bytes: vec![0u8; 8 * 8 * 4],
                is_keyframe: false,
            })
            .expect_err("a send with no receiver must fail");
        assert!(err.contains("closed"), "and say so: {err}");
        assert_eq!(
            rate.queued_frames.load(Ordering::Relaxed),
            0,
            "a refused send must not leave a phantom frame on the depth gauge"
        );
        assert_eq!(
            rate.queued_peak.load(Ordering::Relaxed),
            0,
            "nor move the high-water mark for a frame that never entered the queue"
        );
    }

    /// **A sample covers its own window, not the session.** Found by an adversarial review of this
    /// change: every other test that drives `sample()` takes its baseline on a fresh harness, so
    /// `prev_frames` is 0 and `frames.saturating_sub(prev_frames)` is numerically identical to
    /// `frames`. Dropping the subtraction survived the whole suite — and the single property this
    /// field exists to have is that it is a RATE over a window, not a running total.
    ///
    /// The discriminator is the SECOND window: a session total would report 8 there, not 3. That is
    /// what a live session would show — an achieved frame rate climbing 30, 60, 90… for the life of
    /// the connection, in the one number the operator is told to trust over the rate they commanded.
    #[test]
    fn each_sample_covers_only_its_own_window_while_session_totals_keep_climbing() {
        let mut h = Harness::start(Duration::ZERO);
        let mut stats = VideoStatsHandle::new(h.rate.clone());

        for m in 0..5 {
            h.push(m);
            h.wait_encoded();
        }
        assert_eq!(stats.sample().frames_in_window, 5, "the first window is the first batch");

        for m in 5..8 {
            h.push(m);
            h.wait_encoded();
        }
        assert_eq!(
            stats.sample().frames_in_window,
            3,
            "the second window must cover ONLY the second batch — a session total reports 8 here"
        );

        // Nothing happened since the previous sample.
        assert_eq!(
            stats.sample().frames_in_window,
            0,
            "an idle window is genuinely empty, not the session's history again"
        );
        assert_eq!(
            h.rate.encoded_frames.load(Ordering::Relaxed),
            8,
            "...while the session total itself stands at everything encoded"
        );
        h.finish();
    }

    /// The deliberate ASYMMETRY, pinned: `frames_in_window` resets with each sample and
    /// `dropped_frames` does not. Both travel in the same struct and it would be easy to "fix" one
    /// into the other; the docs say which is which, and now so does a test.
    #[test]
    fn a_sample_resets_the_window_but_not_the_session_dropped_total() {
        let (mut h, gate) = Harness::start_gated(Duration::ZERO);
        let mut stats = VideoStatsHandle::new(h.rate.clone());
        h.push(0);
        gate.wait_entered();
        for m in 1..=5 {
            h.push(m);
        }
        gate.release();
        h.wait_encoded(); // frame 0, which the gate held
        h.wait_encoded(); // the drain's survivor, frame 5

        let first = stats.sample();
        assert_eq!(first.dropped_frames, 4, "frames 1..=4 were superseded by 5");
        assert_eq!(first.frames_in_window, 2, "two frames actually reached the encoder");

        let second = stats.sample();
        assert_eq!(
            second.dropped_frames, 4,
            "a session total must survive a sample — only the WINDOW resets"
        );
        assert_eq!(second.frames_in_window, 0, "...and the window really did reset");
        h.finish();
    }

    /// The window on the wire must be the one that actually elapsed. A reporter that stamped a
    /// nominal 1000 ms would look right on a healthy box and lie precisely when the agent is
    /// loaded enough for the telemetry timer to slip — the case the number exists to describe.
    #[test]
    fn the_reported_window_is_the_one_that_actually_elapsed() {
        let h = Harness::start(Duration::ZERO);
        let mut stats = VideoStatsHandle::new(h.rate.clone());
        let _ = stats.sample();
        // Compared against the interval THIS test measured, not against the nominal 300 ms. Both
        // clocks stretch together when the box stalls, so the comparison holds under load while a
        // hardcoded nominal window still fails it — an absolute band would flake instead.
        let t0 = Instant::now();
        std::thread::sleep(Duration::from_millis(300));
        let s = stats.sample();
        let actual_ms = t0.elapsed().as_millis() as u32;
        let slack = actual_ms / 4 + 20;
        assert!(
            s.window_ms.abs_diff(actual_ms) <= slack,
            "reported window {} ms but {actual_ms} ms actually elapsed — the window is not the one \
             that was measured",
            s.window_ms
        );
        h.finish();
    }

    /// The other half of the claim: on a HEALTHY session the drain is a no-op. A fix that dropped
    /// frames when the encoder was keeping up would silently cost the operator frame rate, and
    /// nothing else in the system would report it.
    ///
    /// **Paced by the CONSUMER, not by a `sleep`.** An earlier version pushed on a 20 ms timer
    /// against a 1 ms encoder and called the 20:1 margin "not a race" — it flaked the first time it
    /// ran alongside a loaded workspace test run, because the margin only has to be lost once. Here
    /// the producer waits for each access unit before pushing the next, so "at most one frame is in
    /// flight" is a fact and `dropped == 0` cannot be lost to scheduling.
    ///
    /// The elapsed-time bound is the second half, and it catches a different wrong implementation:
    /// a drain that WAITS for more work to batch (rather than `try_recv`-ing what is already there)
    /// would both drop live frames and add its window to every frame's latency. With a zero-cost
    /// encoder this loop should finish in milliseconds; a 25 ms batching window would need ~500 ms.
    #[test]
    fn a_healthy_session_drops_nothing_and_never_waits_for_more_work() {
        const FRAMES: u32 = 20;
        let mut h = Harness::start(Duration::ZERO);
        let started = Instant::now();
        for m in 0..FRAMES {
            h.push(m);
            h.wait_encoded();
        }
        let elapsed = started.elapsed();
        assert_eq!(h.dropped(), 0, "nothing may be dropped when encode keeps up");
        let rate = h.rate.clone();
        let log = h.finish();

        let markers: Vec<u32> = log.encodes.iter().map(|e| e.marker).collect();
        assert_eq!(
            markers,
            (0..FRAMES).collect::<Vec<u32>>(),
            "every frame encoded, in order"
        );
        assert_eq!(rate.dropped_frames.load(Ordering::Relaxed), 0);
        assert_eq!(rate.queued_frames.load(Ordering::Relaxed), 0);
        // Generous by 10x against a no-op path, and still 2x under the cheapest batching window
        // anyone would plausibly write.
        assert!(
            elapsed < Duration::from_millis(250),
            "{FRAMES} zero-cost frames took {elapsed:?} — the drain is waiting for work rather \
             than taking what is already queued"
        );
    }

    // ---- the recording tee (loop 89, docs/01 §5) -------------------------------------------

    /// What a [`video::RecordingSink`] was offered.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Offered {
        marker: u32,
        keyframe: bool,
        width: u32,
        height: u32,
    }

    /// A sink that records what it was handed. Deliberately does no work: the production contract
    /// is that `offer` must not block the encoder thread, and a test sink that slept would be
    /// testing the wrong thing.
    #[derive(Default)]
    struct SpySink {
        seen: StdMutex<Vec<Offered>>,
        /// The raw instants, kept so a test can prove the tee hands over the CLOCK READING rather
        /// than anything derived from the clamped `duration_90khz`.
        instants: StdMutex<Vec<Instant>>,
    }

    impl video::RecordingSink for SpySink {
        fn offer(&self, f: video::RecordedFrame<'_>) {
            // The 8x8 test frames carry their marker in the first four BGRA bytes; the encoder
            // echoes the input bytes back, so the marker survives into the encoded AU and the sink
            // can say WHICH frames it saw rather than merely how many.
            let marker = u32::from_le_bytes([f.data[0], f.data[1], f.data[2], f.data[3]]);
            self.seen.lock().unwrap().push(Offered {
                marker,
                keyframe: f.keyframe,
                width: f.width,
                height: f.height,
            });
            self.instants.lock().unwrap().push(f.at);
        }
    }

    /// The tee fires for every encoded frame while a sink is installed, and for none after it is
    /// removed.
    ///
    /// This is the assertion that would fail if the recorder were inert — the shape that has caught
    /// three features in this codebase already (see docs/07 on `canElevate`). Everything else about
    /// recording can be correct while the tee is never called, and nothing else in the repo notices.
    #[test]
    fn the_recording_tee_sees_exactly_the_frames_recorded_between_start_and_stop() {
        let mut h = Harness::start(Duration::ZERO);
        let sink = Arc::new(SpySink::default());

        // BEFORE: two frames that must NOT be recorded. Without this leg the test could not tell a
        // tee that respects start/stop from one that records the whole session.
        for m in 0..2u32 {
            h.push(m);
            h.wait_encoded();
        }
        assert!(
            sink.seen.lock().unwrap().is_empty(),
            "frames were teed before recording started"
        );

        h.command(EncoderCommand::SetRecording(Some(
            sink.clone() as Arc<dyn video::RecordingSink>
        )));
        for m in 10..14u32 {
            h.push(m);
            h.wait_encoded();
        }

        h.command(EncoderCommand::SetRecording(None));
        // AFTER: two more that must not be recorded either.
        for m in 20..22u32 {
            h.push(m);
            h.wait_encoded();
        }
        let log = h.finish();

        let seen = sink.seen.lock().unwrap().clone();
        assert_eq!(
            seen.iter().map(|o| o.marker).collect::<Vec<_>>(),
            vec![10, 11, 12, 13],
            "the tee must see exactly the frames encoded while a sink was installed"
        );
        // Dimensions ride along, because IVF's width/height are file-global: without them the sink
        // cannot know when to roll a new segment, and a mid-session resolution change would be
        // written into a file whose header says otherwise.
        assert!(seen.iter().all(|o| o.width == 8 && o.height == 8), "dimensions: {seen:?}");
        // Installing a sink asks for a keyframe, so a recording opens with a self-contained frame
        // rather than up to KF_MAX_TICKS of undecodable interframes.
        assert!(
            seen[0].keyframe,
            "the first recorded frame must be a keyframe — SetRecording(Some) requests one"
        );
        // PREMISE, declared locally: the frames really did keep flowing to the LIVE path throughout,
        // so "the tee saw only four" is about the tee and not about a pipeline that stopped.
        assert_eq!(
            log.encodes.iter().map(|e| e.marker).collect::<Vec<_>>(),
            vec![0, 1, 10, 11, 12, 13, 20, 21],
            "every frame must still reach the encoder; recording must not gate the live session"
        );

        // The tee hands over the frame's own INSTANT. It is an `Instant` and not a tick count by
        // design: a clamped duration cannot be represented here, so the "idle gaps compress the
        // recording" bug is unrepresentable at this seam rather than merely absent.
        let instants = sink.instants.lock().unwrap().clone();
        assert_eq!(instants.len(), 4);
        assert!(
            instants.windows(2).all(|w| w[1] >= w[0]),
            "instants must be monotonic in frame order"
        );
    }
}

/// A brokered session whose controller never opens the data channel (it abandoned the session)
/// must give up, not hang: the hang leaked the whole session task and its update idle-barrier guard
/// (observed on a lab machine, 2026-10-21).
#[cfg(test)]
mod brokered_open_timeout_tests {
    use super::*;
    use futures_util::StreamExt;

    #[tokio::test]
    async fn an_abandoned_brokered_session_gives_up_instead_of_hanging() {
        // A real (local) signaling peer that accepts and reads, so the client stays connected.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            while let Some(Ok(_)) = ws.next().await {}
        });
        let (sig, _inbound) = SignalingClient::connect(&format!("ws://127.0.0.1:{port}")).await.unwrap();
        // The per-session channel stays open (its sender is held) and nothing ever arrives on it:
        // exactly a controller that went away after being brokered.
        let (_held, sig_rx) = mpsc::unbounded_channel::<ServerToClient>();
        BROKERED_OPEN_TIMEOUT_TEST_MS.store(400, std::sync::atomic::Ordering::SeqCst);
        let started = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            WebRtcTransport::from_brokered(
                SessionId::new(),
                sig,
                sig_rx,
                None,
                None,
                rmt_protocol::signaling::BrokeredAccess::Control,
                vec![],
            ),
        )
        .await
        .expect("from_brokered must not hang on an abandoned session");
        let err = r.err().expect("an abandoned session is an error");
        assert!(err.contains("did not open the session"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        BROKERED_OPEN_TIMEOUT_TEST_MS.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod peer_gone_tests {
    //! [`PeerGone`] is what ends an agent session whose input side has already closed, so both of its
    //! answers matter: it must resolve once the peer leaves, and it must NOT resolve while the peer is
    //! still there (a false positive ends a healthy video-only tail).

    use super::*;
    use std::time::Duration;

    const TEST_GRACE: Duration = Duration::from_millis(150);

    #[tokio::test]
    async fn disconnected_then_recovered_keeps_the_session() {
        let h = handle();
        let w = PeerStateWatch::new(h.clone(), TEST_GRACE);
        w.on_state(RTCPeerConnectionState::Connected);
        w.on_state(RTCPeerConnectionState::Disconnected);
        assert!(!h.is_gone(), "Disconnected alone must not end the session");
        tokio::time::sleep(TEST_GRACE / 3).await;
        w.on_state(RTCPeerConnectionState::Connected);
        tokio::time::sleep(TEST_GRACE * 3).await;
        assert!(!h.is_gone(), "a recovery inside the grace must cancel the pending end");
    }

    #[tokio::test]
    async fn disconnected_past_the_grace_ends_the_session() {
        let h = handle();
        let w = PeerStateWatch::new(h.clone(), TEST_GRACE);
        w.on_state(RTCPeerConnectionState::Connected);
        w.on_state(RTCPeerConnectionState::Disconnected);
        tokio::time::timeout(TEST_GRACE * 10, h.wait())
            .await
            .expect("a peer that never recovers must be marked gone after the grace");
    }

    #[tokio::test]
    async fn a_second_disconnect_after_recovery_gets_its_own_grace() {
        // The first disconnect's timer must not fire into the second disconnect's window.
        let h = handle();
        let w = PeerStateWatch::new(h.clone(), TEST_GRACE);
        w.on_state(RTCPeerConnectionState::Disconnected);
        tokio::time::sleep(TEST_GRACE * 2 / 3).await;
        w.on_state(RTCPeerConnectionState::Connected);
        w.on_state(RTCPeerConnectionState::Disconnected);
        tokio::time::sleep(TEST_GRACE / 2).await;
        assert!(!h.is_gone(), "the stale first timer ended the session early");
        tokio::time::timeout(TEST_GRACE * 10, h.wait()).await.expect("the second grace must still end it");
    }

    #[tokio::test]
    async fn a_repeated_disconnected_does_not_extend_the_grace() {
        let h = handle();
        let w = PeerStateWatch::new(h.clone(), TEST_GRACE);
        w.on_state(RTCPeerConnectionState::Disconnected);
        tokio::time::sleep(TEST_GRACE * 2 / 3).await;
        w.on_state(RTCPeerConnectionState::Disconnected);
        // Measured from the FIRST Disconnected: gone by ~1x grace, not ~1.67x.
        tokio::time::timeout(TEST_GRACE * 2 / 3, h.wait())
            .await
            .expect("a repeated Disconnected restarted the grace");
    }

    #[tokio::test]
    async fn failed_and_closed_end_the_session_at_once() {
        for s in [RTCPeerConnectionState::Failed, RTCPeerConnectionState::Closed] {
            let h = handle();
            let w = PeerStateWatch::new(h.clone(), Duration::from_secs(3600));
            w.on_state(RTCPeerConnectionState::Connected);
            assert!(!h.is_gone());
            w.on_state(s);
            assert!(h.is_gone(), "{s} must be terminal immediately");
        }
    }

    #[test]
    fn both_peer_connections_use_the_grace_watch() {
        // Both connect paths (connect_with_ice and the brokered one) must route state changes through
        // PeerStateWatch; a copy that still matched Disconnected as terminal re-opens the bug.
        let src = include_str!("lib.rs");
        let needle = concat!("PeerStateWatch::new(", "\n");
        assert_eq!(src.matches(needle).count(), 2, "expected exactly two PeerStateWatch hooks");
        let stale = concat!("RTCPeerConnectionState::Disconnected", "\n                        | RTCPeerConnectionState::Failed");
        assert_eq!(src.matches(stale).count(), 0, "a hook still treats Disconnected as terminal");
    }

    fn handle() -> PeerGone {
        PeerGone { flag: Arc::new(AtomicBool::new(false)), notify: Arc::new(Notify::new()) }
    }

    /// What the peer-connection state callback does on a terminal state.
    fn mark_gone(h: &PeerGone) {
        h.flag.store(true, Ordering::Relaxed);
        h.notify.notify_waiters();
    }

    #[tokio::test]
    async fn resolves_immediately_when_the_peer_already_left() {
        let h = handle();
        mark_gone(&h);
        tokio::time::timeout(Duration::from_secs(5), h.wait())
            .await
            .expect("an already-gone peer must resolve at once");
        assert!(h.is_gone());
    }

    #[tokio::test]
    async fn a_parked_wait_wakes_when_the_peer_leaves() {
        let h = handle();
        let waiter = tokio::spawn({
            let h = h.clone();
            async move { h.wait().await }
        });
        // Let the waiter park on the notification before the peer leaves.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!waiter.is_finished(), "must not resolve while the peer is present");
        mark_gone(&h);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("a parked wait must wake when the peer leaves")
            .unwrap();
    }

    #[tokio::test]
    async fn a_wake_up_without_departure_keeps_waiting() {
        let h = handle();
        let waiter = tokio::spawn({
            let h = h.clone();
            async move { h.wait().await }
        });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        // A stray wake-up with the flag still clear (nothing in the transport sends one, but the loop
        // must not mistake it for a departure) is ignored: `wait` re-checks the flag and re-parks.
        h.notify.notify_waiters();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!waiter.is_finished(), "a present peer must keep the wait pending");
        assert!(!h.is_gone());
        waiter.abort();
    }
}

/// See [`WebRtcTransport::open_extra_data_channel`].
#[doc(hidden)]
pub struct ExtraDataChannel {
    dc: Arc<RTCDataChannel>,
}

impl ExtraDataChannel {
    /// Send one small frame on this channel (errors ignored: the agent may already have closed it).
    pub async fn send_frame(&self, frame: Frame) {
        let _ = self.dc.send(&frame.to_bytes()).await;
    }

    /// The channel's current ready state, for test diagnostics.
    pub fn state(&self) -> String {
        format!("{:?}", self.dc.ready_state())
    }
}

#[cfg(test)]
mod sample_writer_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A track that refuses the first `fail_first` writes (as a vanished route does), then accepts.
    struct FlakyTrack {
        fail_first: usize,
        seen: StdMutex<usize>,
        accepted: StdMutex<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl SampleSink for FlakyTrack {
        async fn write(&self, sample: &Sample) -> Result<(), String> {
            let mut seen = self.seen.lock().unwrap();
            *seen += 1;
            if *seen <= self.fail_first {
                return Err("io error: A socket operation was attempted to an unreachable network. (os error 10051)".into());
            }
            self.accepted.lock().unwrap().push(sample.data[0]);
            Ok(())
        }
    }

    /// The operator's Desktop, 2026-10-20 and 2026-10-23: one WSAENETUNREACH stopped ALL video and audio for the
    /// session. A run of failed writes must not end the stream: every sample after the network comes
    /// back is delivered, in order, and the writer ends only when its producer does.
    #[tokio::test]
    async fn a_run_of_failed_writes_does_not_end_the_stream() {
        let track = Arc::new(FlakyTrack { fail_first: 5, seen: StdMutex::new(0), accepted: StdMutex::new(Vec::new()) });
        let (tx, rx) = mpsc::channel::<u8>(64);
        let sink: Arc<dyn SampleSink> = track.clone();
        let writer = tokio::spawn(run_sample_writer(rx, sink, |b: u8| Sample { data: vec![b].into(), ..Default::default() }, "video"));
        for i in 0..20u8 {
            tx.send(i).await.unwrap();
        }
        drop(tx); // the session ends: the producer goes away
        let written = tokio::time::timeout(Duration::from_secs(5), writer).await.expect("ends with its producer").unwrap();
        assert_eq!(written, 15, "every sample after the failures was written");
        assert_eq!(*track.accepted.lock().unwrap(), (5..20).collect::<Vec<u8>>(), "in order, none lost after recovery");
    }

    /// The unbounded (audio) source behaves the same.
    #[tokio::test]
    async fn the_audio_source_also_survives_failures() {
        let track = Arc::new(FlakyTrack { fail_first: 2, seen: StdMutex::new(0), accepted: StdMutex::new(Vec::new()) });
        let (tx, rx) = mpsc::unbounded_channel::<u8>();
        let sink: Arc<dyn SampleSink> = track.clone();
        for i in 0..6u8 {
            tx.send(i).unwrap();
        }
        drop(tx);
        let written = run_sample_writer(rx, sink, |b: u8| Sample { data: vec![b].into(), ..Default::default() }, "audio").await;
        assert_eq!(written, 4);
    }
}

/// The WebRTC API for one peer connection.
///
/// With `route_ip` (the signaling socket's local address) and at least one relay server, ICE gathers
/// HOST candidates only on the network adapter that owns `route_ip`: every address of that
/// adapter, IPv4 and IPv6, and none of the machine's other adapters ([`route_iface`]). Server-reflexive and relay
/// candidates bind unspecified sockets, so they follow the OS route and are unaffected.
///
/// Every interface is gathered, as before, when:
/// - there is no route IP (loopback signaling, unknown);
/// - the session has no relay server. Then a host candidate on another interface may be the only
///   working path (signaling over a VPN, the operator on the physical LAN), so none is removed;
/// - the route IP is not found on any adapter (or the adapter list cannot be read);
/// - a restricted attempt in this process recently ended without ICE ever connecting
///   ([`ICE_RESTRICTION`]). A configured relay is not proof of a usable one (blocked, down, stale
///   credentials), so the next attempt gets every interface back.
///
/// Returns the API and whether host candidates were restricted (for [`log_ice_path`]).
fn build_api(
    media: MediaEngine,
    registry: Registry,
    route_ip: Option<std::net::IpAddr>,
    has_relay: bool,
    role: &str,
) -> (webrtc::api::API, bool) {
    let mut setting = webrtc::api::setting_engine::SettingEngine::default();
    let mut restricted = false;
    if let Some(ip) = route_ip {
        let suspended = !ICE_RESTRICTION.allowed(unix_ms());
        let allowed = if has_relay && !suspended {
            ice_route_addresses(&route_iface::adapter_address_groups(), ip)
        } else {
            None
        };
        match allowed {
            Some(addrs) => {
                tracing::info!(role, %ip, adapter = ?addrs, "ice: host candidates limited to the signaling route's adapter");
                setting.set_ip_filter(Box::new(move |candidate: std::net::IpAddr| addrs.contains(&candidate)));
                restricted = true;
            }
            None => {
                tracing::info!(role, %ip, has_relay, suspended, "ice: host candidates on every interface");
            }
        }
    }
    let api = APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting)
        .build();
    (api, restricted)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How long the host-candidate restriction stays off after a restricted session failed ICE.
const ICE_RESTRICTION_SUSPEND_MS: u64 = 30 * 60 * 1000;

/// The fallback for the host-candidate restriction: a restricted session whose ICE FAILED without
/// ever connecting turns the restriction off for [`ICE_RESTRICTION_SUSPEND_MS`] in this process,
/// so the viewer's retry (or the operator's next Connect) gathers every interface.
static ICE_RESTRICTION: IceRestrictionGate = IceRestrictionGate::new();

struct IceRestrictionGate {
    suspended_until_ms: std::sync::atomic::AtomicU64,
}

impl IceRestrictionGate {
    const fn new() -> Self {
        Self { suspended_until_ms: std::sync::atomic::AtomicU64::new(0) }
    }

    fn allowed(&self, now_ms: u64) -> bool {
        now_ms >= self.suspended_until_ms.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn restricted_session_failed(&self, now_ms: u64) {
        self.suspended_until_ms
            .fetch_max(now_ms.saturating_add(ICE_RESTRICTION_SUSPEND_MS), std::sync::atomic::Ordering::SeqCst);
    }
}

/// Logs the path a session's media actually takes: every ICE connection state change and every
/// selected candidate pair (type, protocol, address, port on both sides). One line per change, so
/// a "connects but no video" report can be read from helper.log without a packet capture.
///
/// Returns the attempt's [`IceAttempt`] guard, which the caller holds for the life of the
/// connection: a restricted attempt that ends without ICE ever connecting suspends the restriction
/// ([`ICE_RESTRICTION`]), whether it ends by ICE Failed/Closed or by being abandoned (a timeout or
/// any error return drops the guard first, so the suspension is in place before a retry starts).
fn log_ice_path(pc: &RTCPeerConnection, role: &'static str, restricted: bool) -> IceAttempt {
    let attempt = IceAttempt::new(&ICE_RESTRICTION, role, restricted);
    let cb = attempt.clone_state();
    pc.on_ice_connection_state_change(Box::new(move |s| {
        tracing::info!(role, state = %s, "ice: connection state");
        use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState as S;
        match s {
            S::Connected | S::Completed => cb.connected(),
            S::Failed | S::Closed => cb.ended(),
            _ => {}
        }
        Box::pin(async {})
    }));
    pc.sctp()
        .transport()
        .ice_transport()
        .on_selected_candidate_pair_change(Box::new(move |pair| {
            tracing::info!(role, %pair, "ice: selected candidate pair");
            Box::pin(async {})
        }));
    attempt
}

/// One peer connection's ICE attempt, for the restriction fallback. Held by the transport (and by
/// the constructor's locals before that), so it drops exactly when the attempt is abandoned or the
/// connection is torn down.
struct IceAttempt {
    state: IceAttemptState,
}

#[derive(Clone)]
struct IceAttemptState {
    gate: &'static IceRestrictionGate,
    role: &'static str,
    restricted: bool,
    connected: Arc<AtomicBool>,
    /// Set once this attempt has suspended the restriction, so it is logged and applied once.
    reported: Arc<AtomicBool>,
}

impl IceAttempt {
    fn new(gate: &'static IceRestrictionGate, role: &'static str, restricted: bool) -> Self {
        Self {
            state: IceAttemptState {
                gate,
                role,
                restricted,
                connected: Arc::new(AtomicBool::new(false)),
                reported: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    fn clone_state(&self) -> IceAttemptState {
        self.state.clone()
    }
}

impl IceAttemptState {
    fn connected(&self) {
        self.connected.store(true, Ordering::SeqCst);
    }

    /// The attempt ended (ICE Failed or Closed, or the guard dropped). Suspends the restriction if
    /// this attempt was restricted and never connected.
    fn ended(&self) {
        if self.restricted
            && !self.connected.load(Ordering::SeqCst)
            && !self.reported.swap(true, Ordering::SeqCst)
        {
            self.gate.restricted_session_failed(unix_ms());
            tracing::warn!(
                role = self.role,
                "ice: a restricted attempt ended without connecting; every interface is gathered for the next 30 min"
            );
        }
    }
}

impl Drop for IceAttempt {
    fn drop(&mut self) {
        self.state.ended();
    }
}

/// The host addresses ICE may gather: every address of the adapter that owns `route_ip` (from
/// [`route_iface::adapter_address_groups`]). `None` means "gather every interface": the route
/// address is on no known adapter.
fn ice_route_addresses(
    groups: &[Vec<std::net::IpAddr>],
    route_ip: std::net::IpAddr,
) -> Option<Vec<std::net::IpAddr>> {
    groups.iter().find(|g| g.contains(&route_ip)).cloned()
}

#[cfg(test)]
mod ice_route_filter_tests {
    use super::{ice_route_addresses, IceAttempt, IceRestrictionGate, ICE_RESTRICTION_SUSPEND_MS};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The laptop of 2026-11-12: a datacenter LAN (IPv4 + IPv6), Wi-Fi, and a Hyper-V switch.
    fn dual_homed() -> Vec<Vec<IpAddr>> {
        vec![
            vec![ip("192.0.2.101"), ip("2001:db8::65"), ip("fe80::65")],
            vec![ip("198.51.100.250"), ip("fe80::250")],
            vec![ip("203.0.113.1")],
        ]
    }

    #[test]
    fn host_candidates_follow_the_adapter_that_owns_the_signaling_address() {
        assert_eq!(
            ice_route_addresses(&dual_homed(), ip("192.0.2.101")),
            Some(vec![ip("192.0.2.101"), ip("2001:db8::65"), ip("fe80::65")])
        );
        assert_eq!(ice_route_addresses(&dual_homed(), ip("198.51.100.250")), Some(vec![ip("198.51.100.250"), ip("fe80::250")]));
    }

    #[test]
    fn ipv6_signaling_keeps_the_same_adapter_ipv4_address() {
        let allowed = ice_route_addresses(&dual_homed(), ip("2001:db8::65")).unwrap();
        assert!(allowed.contains(&ip("192.0.2.101")));
        assert!(!allowed.contains(&ip("198.51.100.250")));
    }

    #[test]
    fn an_unknown_route_address_is_not_filtered() {
        assert_eq!(ice_route_addresses(&dual_homed(), ip("192.0.2.9")), None);
        assert_eq!(ice_route_addresses(&[], ip("192.0.2.101")), None);
    }

    #[test]
    fn a_failed_restricted_session_suspends_the_restriction_for_a_while() {
        let gate = IceRestrictionGate::new();
        assert!(gate.allowed(1_000));
        gate.restricted_session_failed(1_000);
        assert!(!gate.allowed(1_000));
        assert!(!gate.allowed(1_000 + ICE_RESTRICTION_SUSPEND_MS - 1));
        assert!(gate.allowed(1_000 + ICE_RESTRICTION_SUSPEND_MS));
    }

    #[test]
    fn an_older_failure_never_shortens_a_later_suspension() {
        let gate = IceRestrictionGate::new();
        gate.restricted_session_failed(5_000);
        gate.restricted_session_failed(1_000);
        assert!(!gate.allowed(5_000 + ICE_RESTRICTION_SUSPEND_MS - 1));
    }

    // Each lifecycle test gets its own gate (a leaked static), so tests running in parallel never
    // share the process-wide one.
    fn gate() -> &'static IceRestrictionGate {
        Box::leak(Box::new(IceRestrictionGate::new()))
    }

    fn far_future() -> u64 {
        super::unix_ms() + ICE_RESTRICTION_SUSPEND_MS / 2
    }

    #[test]
    fn an_abandoned_restricted_attempt_suspends_before_any_retry() {
        // A timeout or error return drops the guard without ICE ever reporting Failed or Closed.
        let g = gate();
        drop(IceAttempt::new(g, "agent", true));
        assert!(!g.allowed(super::unix_ms()), "the very next attempt must gather every interface");
        assert!(!g.allowed(far_future()));
    }

    #[test]
    fn closed_or_failed_before_connecting_suspends() {
        for _ in 0..2 {
            let g = gate();
            let a = IceAttempt::new(g, "agent", true);
            a.clone_state().ended();
            assert!(!g.allowed(super::unix_ms()));
        }
    }

    #[test]
    fn a_connected_attempt_never_suspends_when_it_ends() {
        let g = gate();
        let a = IceAttempt::new(g, "agent", true);
        let s = a.clone_state();
        s.connected();
        s.ended();
        drop(a);
        assert!(g.allowed(super::unix_ms()));
    }

    #[test]
    fn an_unrestricted_attempt_never_suspends() {
        let g = gate();
        drop(IceAttempt::new(g, "agent", false));
        assert!(g.allowed(super::unix_ms()));
    }
}
