//! Signaling multiplexer for concurrent multi-technician sessions (F2 multi-tech).
//!
//! # Problem
//!
//! The current `serve_session_with_ice` creates ONE WebSocket connection and it is consumed by
//! the first `Brokered` message. A second technician connecting to the same agent requires a
//! second connection (and therefore a second registration), which would either fail or race.
//!
//! # Solution
//!
//! `SignalingMux` takes an already-connected `SignalingClient` (post-registration) and fans its
//! single `UnboundedReceiver<ServerToClient>` stream out to per-session channels:
//!
//! - New `Brokered` messages trigger a new per-session channel and deliver a [`BrokeredSession`]
//!   to the caller's acceptor loop.
//! - `Candidate`, `Sdp`, `RelayAssignment`, `IceServers` are routed by their `session` field to
//!   the correct per-session channel.
//! - Connection-level messages (`Registered`, `AgentAuthChallenge`, `Rejected`) are handled by
//!   the mux internally.
//!
//! # Heartbeat
//!
//! When a `DeviceId` is supplied to [`SignalingMux::new`], the mux spawns one connection-owned
//! heartbeat task that sends `Heartbeat { device }` every [`HEARTBEAT_INTERVAL`] seconds.
//!
//! The server's default registry TTL is 30 s; 10 s beats well under that bound so one missed
//! interval is harmless. The task is owned exclusively by the mux: it is aborted when the mux
//! is dropped, stops itself if the signaling send fails (connection gone), and is never started
//! for controller connections (which pass `device: None`).
//!
//! # Connection ownership and cancellation
//!
//! `SignalingMux` holds a `_conn_owner: SignalingClient` clone whose sole purpose is to call
//! [`SignalingClient::cancel`] on drop. This retires the underlying WebSocket reader and writer
//! tasks independent of how many `BrokeredSession.sig` clones are still alive in WebRTC
//! callbacks. After cancellation, sends on retained clones fail immediately and both tasks exit
//! within one scheduler tick. Established WebRTC peer connections are unaffected: their per-session
//! `mpsc` buffers are independent of the mux lifetime.
//!
//! The dispatch task also calls `sig.cancel()` when it exits normally (EOF or Rejection) so the
//! reader and writer tasks are retired even if the mux is never dropped explicitly.
//!
//! # Wire compatibility
//!
//! The mux consumes the same `ServerToClient` stream as the existing `connect_inner`. Old
//! signaling servers send exactly one `Brokered` per connection; the mux delivers exactly one
//! `BrokeredSession`, preserving the current behaviour. New signaling servers can send multiple
//! `Brokered` messages to one connection; the mux delivers each as an independent session.
//!
//! # Caller contract
//!
//! ```text
//! let (sig, rx) = SignalingClient::connect(url).await?;
//! sig.send(RegisterAgent { ... })?;            // caller performs registration
//! let mux = SignalingMux::new(sig, rx, Some(device_id));
//! let session = mux.accept().await?;           // wait for next brokered tech
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_agent_core::guest_end::GuestEndReports;

use rmt_protocol::signaling::{ClientToServer, IceServerSpec, ServerToClient, SESSION_ENDED_FEATURE};
use rmt_protocol::{DeviceId, SessionId};
use tokio::sync::mpsc;

use rmt_transport_webrtc::SignalingClient;

/// Heartbeat interval for the mux connection. Must be well under the server's default 30 s TTL.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

// ── BrokeredSession ───────────────────────────────────────────────────────────────────────────────

/// A newly brokered session delivered to the acceptor loop.
///
/// Contains everything the session handler needs for ICE/SDP negotiation:
/// - A per-session inbound receiver (`rx`) carrying `RelayAssignment`, `Candidate`, and `Sdp`
///   messages for this session only. Note: `IceServers` is extracted from the pre-registration
///   buffer and placed in `issued_ice` rather than `rx` so the caller never has to race a channel
///   read to learn what ICE servers to use before building the peer connection.
/// - A shared `SignalingClient` sender (`sig`) for outbound responses (SDP answer, ICE
///   candidates). Cheap to clone and share with WebRTC callbacks.
pub struct BrokeredSession {
    /// Broker-assigned pairing session id. Pass to [`SignalingMux::deregister`] on teardown.
    pub session: SessionId,
    /// Peer identity echoed by the broker (advisory; see `ServerToClient::Brokered`).
    pub peer_device: Option<rmt_protocol::DeviceId>,
    pub peer_pubkey: String,
    /// Control-plane session id, from the verified ticket. Fail-closed `None`.
    pub control_plane_session: Option<uuid::Uuid>,
    /// Technician id, from the verified ticket. Fail-closed `None`.
    pub technician_id: Option<uuid::Uuid>,
    /// The session's access from the same verified ticket (observer design v2), already classified.
    /// The host refuses `Invalid` and floors `ViewOnly` before the first frame.
    pub access: rmt_protocol::signaling::BrokeredAccess,
    /// ICE servers from the server's `IceServers` message for this session.
    ///
    /// The signaling server sends `IceServers` BEFORE `Brokered` (load-bearing ordering; see
    /// broker.go). The mux buffers any pre-registration `IceServers` and extracts them here so
    /// the caller can build `RTCPeerConnection` without needing to drain the per-session channel.
    /// Empty when the server sent no `IceServers` (LAN/dev mode).
    pub issued_ice: Vec<IceServerSpec>,
    /// Shared outbound signaling client. Clone for WebRTC callbacks.
    pub sig: SignalingClient,
    /// Per-session inbound channel. `RelayAssignment`, `Sdp`, `Candidate` arrive here.
    /// Closed when the mux drops the sender (after deregister).
    pub rx: mpsc::UnboundedReceiver<ServerToClient>,
}

// ── Session routing table ─────────────────────────────────────────────────────────────────────────

type SessionMap = Arc<Mutex<HashMap<SessionId, mpsc::UnboundedSender<ServerToClient>>>>;

// ── SignalingMux ──────────────────────────────────────────────────────────────────────────────────

/// Multiplexes one persistent signaling connection across concurrent sessions.
///
/// Constructed with an already-registered `SignalingClient`. Drives an internal Tokio task that
/// routes inbound messages; the caller drives the acceptor loop via [`accept`](Self::accept).
///
/// When `device` is `Some`, a connection-owned heartbeat task is spawned. It is aborted when
/// the `SignalingMux` is dropped, and stops itself on send failure. See module-level docs.
pub struct SignalingMux {
    new_session_rx: mpsc::Receiver<BrokeredSession>,
    sessions: SessionMap,
    /// Abort handle for the inbound dispatch task. Always present. Aborted on drop so the task
    /// does not outlive the mux and leak the sig_rx (WebSocket reader) reference.
    dispatch_abort: tokio::task::AbortHandle,
    /// Abort handle for the connection-owned heartbeat task. `None` when no heartbeat was
    /// requested (controller path: `device = None`).
    heartbeat_abort: Option<tokio::task::AbortHandle>,
    /// Delivery belongs to this connection; the shared pending set survives its cancellation.
    guest_end_abort: Option<tokio::task::AbortHandle>,
    /// Whether this connection's `Registered` advertised `session_ended_v1` (docs/49).
    session_ended_capable: bool,
    /// docs/65: the directive hub this connection feeds and acknowledges through (detached on drop).
    directive_hub: Option<std::sync::Arc<crate::directive_hub::DirectiveHub>>,
    /// docs/64: the help hub this connection feeds and sends through, with this connection's generation (detached on drop).
    help_hub: Option<(std::sync::Arc<crate::help_request::HelpHub>, u64)>,
    /// One clone of the SignalingClient held solely to call `cancel()` on drop, retiring the
    /// underlying WebSocket reader and writer tasks independent of any other retained clones.
    _conn_owner: SignalingClient,
}

impl Drop for SignalingMux {
    fn drop(&mut self) {
        // Cancel dispatch first so it stops referencing sig_rx (retires the reader socket).
        self.dispatch_abort.abort();
        // Retire the underlying reader + writer tasks independent of retained sig clone count.
        // After this, sends on any BrokeredSession.sig clone fail immediately.
        self._conn_owner.cancel();
        if let Some(h) = self.heartbeat_abort.take() {
            h.abort();
        }
        if let Some(h) = self.guest_end_abort.take() {
            h.abort();
        }
        if let Some(hub) = self.directive_hub.take() {
            hub.detach();
        }
        if let Some((hub, generation)) = self.help_hub.take() {
            hub.detach(generation, Instant::now());
        }
    }
}

impl SignalingMux {
    /// Wrap an already-registered `SignalingClient`. Spawns the inbound dispatch task.
    ///
    /// Pass `device: Some(id)` for an agent connection — the mux will spawn a heartbeat task to
    /// keep the registry entry alive. Pass `device: None` for a controller connection (no
    /// heartbeat). The caller is responsible for sending `RegisterAgent` before calling `new`.
    pub fn new(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
    ) -> Self {
        Self::new_with_interval(sig, sig_rx, device, HEARTBEAT_INTERVAL)
    }

    /// Like [`new`](Self::new) but with a caller-supplied heartbeat interval. Private — only
    /// used by tests that need a short interval to exercise lifecycle without real 10 s waits.
    fn new_with_interval(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
        heartbeat_interval: Duration,
    ) -> Self {
        Self::new_internal(sig, sig_rx, device, heartbeat_interval, None, false, None, None, false)
    }

    /// Attach the helper's retained reports only after registration and authentication complete.
    /// Existing callers may continue using `new` without a reporting handle.
    ///
    /// `features` is what this connection's `Registered` listed. With
    /// [`SESSION_ENDED_FEATURE`] every report is sent as `SessionEnded`; without it only
    /// `guest_ended` reports can be carried (as `GuestEndedSession`) and the rest wait (docs/49).
    pub fn new_with_reports(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
        reports: Option<GuestEndReports>,
        features: &[String],
    ) -> Self {
        let capable = features.iter().any(|f| f == SESSION_ENDED_FEATURE);
        Self::new_internal(sig, sig_rx, device, HEARTBEAT_INTERVAL, reports, capable, None, None, false)
    }

    /// [`new_with_reports`](Self::new_with_reports) plus the docs/65 directive hub: relayed `Directive` messages and their
    /// `DirectiveAckResult`s are handed to it, and it sends its signed acknowledgements on THIS connection until the mux drops.
    pub fn new_with_directives(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
        reports: Option<GuestEndReports>,
        features: &[String],
        hub: Option<std::sync::Arc<crate::directive_hub::DirectiveHub>>,
    ) -> Self {
        Self::new_with_help(sig, sig_rx, device, reports, features, hub, None)
    }

    /// [`new_with_directives`](Self::new_with_directives) plus the docs/64 help hub: relayed `help_request_result`s are
    /// handed to it, and it sends its requests on THIS connection until the mux drops. The hub is told whether this
    /// connection's `Registered` listed `help_request_v1`; without it (a retired machine, an old server) nothing help-related
    /// is ever sent.
    pub fn new_with_help(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
        reports: Option<GuestEndReports>,
        features: &[String],
        hub: Option<std::sync::Arc<crate::directive_hub::DirectiveHub>>,
        help: Option<std::sync::Arc<crate::help_request::HelpHub>>,
    ) -> Self {
        let capable = features.iter().any(|f| f == SESSION_ENDED_FEATURE);
        let help_advertised = crate::help_request::advertised(features);
        Self::new_internal(sig, sig_rx, device, HEARTBEAT_INTERVAL, reports, capable, hub, help, help_advertised)
    }

    fn new_internal(
        sig: SignalingClient,
        sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
        device: Option<DeviceId>,
        heartbeat_interval: Duration,
        reports: Option<GuestEndReports>,
        session_ended_capable: bool,
        directive_hub: Option<std::sync::Arc<crate::directive_hub::DirectiveHub>>,
        help: Option<std::sync::Arc<crate::help_request::HelpHub>>,
        help_advertised: bool,
    ) -> Self {
        let (new_session_tx, new_session_rx) = mpsc::channel::<BrokeredSession>(8);
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

        // Claim and send synchronously so the new registration immediately retries retained ids.
        // Sending is nonblocking; the state lock is released before accessing the connection.
        if let Some(reports) = reports.as_ref() {
            reports.pending.lock().unwrap().on_reregistered(Instant::now());
            let _ = send_due_guest_ends(&sig, reports, session_ended_capable);
        }

        // Clone before moving sig into tasks so we can hold one for connection ownership.
        let conn_owner = sig.clone();

        // docs/65: acknowledgements leave on THIS connection from now on (the hub re-sends any step unanswered on the last one).
        let hub_generation = directive_hub.as_ref().map(|hub| (hub.clone(), hub.attach(std::sync::Arc::new(SigSink(sig.clone())))));

        // docs/64: help requests leave on THIS connection from now on, if it advertised the feature.
        let help_hub = help.map(|hub| {
            let generation = hub.attach(std::sync::Arc::new(HelpSigSink(sig.clone())), help_advertised, Instant::now());
            (hub, generation)
        });

        let sessions_d = Arc::clone(&sessions);
        let dispatch_abort =
            tokio::spawn(dispatch_task_with_reports(
                sig_rx, sig.clone(), new_session_tx, sessions_d, reports.clone(), hub_generation, help_hub.clone(),
            ))
                .abort_handle();

        let heartbeat_abort = device.map(|dev| {
            tokio::spawn(heartbeat_task(sig.clone(), dev, heartbeat_interval)).abort_handle()
        });

        let guest_end_abort = reports.map(|reports| {
            tokio::spawn(guest_end_task(sig.clone(), reports, session_ended_capable)).abort_handle()
        });

        Self {
            new_session_rx, sessions, dispatch_abort, heartbeat_abort, guest_end_abort,
            session_ended_capable,
            directive_hub,
            help_hub,
            _conn_owner: conn_owner,
        }
    }

    /// How long since the signaling server last echoed this connection's keepalive probe; small
    /// means the server is reading this connection. See `rmt_transport_webrtc::SIGNALING_PONG_DEADLINE`.
    pub fn pong_age(&self) -> Duration {
        self._conn_owner.pong_age()
    }

    /// When this connection's liveness evidence expires (absolute; see
    /// `SignalingClient::proof_expiry`).
    pub fn proof_expiry(&self) -> std::time::Instant {
        self._conn_owner.proof_expiry()
    }

    /// Whether this connection carries every session-end reason (docs/49).
    pub fn session_ended_capable(&self) -> bool {
        self.session_ended_capable
    }

    /// Wait for the next brokered session. Returns `None` when the signaling connection closes.
    pub async fn accept(&mut self) -> Option<BrokeredSession> {
        self.new_session_rx.recv().await
    }

    /// Shutdown: stop admitting sessions and hand back every one already brokered but not yet
    /// accepted, deregistered from routing. Each was vouched by signaling, so the caller must report
    /// it (docs/49): dropping the mux would discard them silently and leave their control-plane rows
    /// open (Codex 1.3.7 release review v3). A session the dispatcher is still trying to queue gets a
    /// send error once the queue is closed, and the dispatcher reports that one itself.
    pub fn close_accept(&mut self) -> Vec<BrokeredSession> {
        self.new_session_rx.close();
        let mut queued = Vec::new();
        while let Ok(bs) = self.new_session_rx.try_recv() {
            self.sessions.lock().unwrap().remove(&bs.session);
            queued.push(bs);
        }
        queued
    }

    /// Deregister a session by `SessionId`. The mux stops routing messages for it.
    ///
    /// Call from the session handler on teardown. Messages arriving for an unknown session are
    /// silently discarded.
    pub fn deregister(&self, session: &SessionId) {
        self.sessions.lock().unwrap().remove(session);
        tracing::debug!(?session, "signaling_mux: session deregistered");
    }

    /// Return a lightweight handle that a spawned session task can use to deregister itself.
    ///
    /// `SignalingMux` is not `Clone` (it owns the accept receiver), but spawned session tasks need
    /// to call `deregister` after teardown. This handle carries only the `Arc` to the shared
    /// routing table, so it is cheap to clone and safe to move into a `tokio::spawn` closure.
    pub fn deregister_handle(&self) -> SignalingMuxHandle {
        SignalingMuxHandle { sessions: Arc::clone(&self.sessions) }
    }
}

/// Lightweight handle for deregistering a session from a spawned task.
///
/// Obtained from [`SignalingMux::deregister_handle`]. Clone once per session and move into the
/// `tokio::spawn` closure; call [`deregister`](Self::deregister) after the session ends so the
/// mux dispatch task does not accumulate stale sender entries.
#[derive(Clone)]
pub struct SignalingMuxHandle {
    sessions: SessionMap,
}

impl SignalingMuxHandle {
    /// Remove `session` from the mux routing table. Idempotent; safe to call after session
    /// teardown even if messages for the session are still in flight (they will be discarded).
    pub fn deregister(&self, session: &SessionId) {
        self.sessions.lock().unwrap().remove(session);
        tracing::debug!(?session, "signaling_mux: session deregistered");
    }
}

/// The live connection as the help hub's sink.
struct HelpSigSink(SignalingClient);

impl crate::help_request::HelpSink for HelpSigSink {
    fn send(&self, msg: ClientToServer) -> bool {
        self.0.send(msg).is_ok()
    }
}

/// The live connection as the directive hub's acknowledgement sink.
struct SigSink(SignalingClient);

impl crate::directive_hub::AckSink for SigSink {
    fn send(&self, ack: &rmt_protocol::directive::SignedAck) -> bool {
        self.0.send(crate::directive_win::ack_message(ack)).is_ok()
    }
}

// ── Heartbeat task ────────────────────────────────────────────────────────────────────────────────

/// Sends `Heartbeat { device }` on `sig` every `interval`. Exits on send failure (connection
/// gone) or when aborted via the [`AbortHandle`](tokio::task::AbortHandle) stored in
/// [`SignalingMux`].
///
/// One instance runs per registered agent mux connection. Controllers and per-brokered-session
/// transports never spawn this task. The task holds only a cloned sender — no receiver — so it
/// cannot block the dispatch task from draining `sig_rx`.
async fn heartbeat_task(sig: SignalingClient, device: DeviceId, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        if sig.send(ClientToServer::Heartbeat { device }).is_err() {
            tracing::debug!("signaling_mux: heartbeat send failed; connection closed");
            break;
        }
        tracing::debug!(?device, "signaling_mux: heartbeat sent");
    }
    tracing::debug!("signaling_mux: heartbeat task exiting");
}

/// Claim under the state lock, then release it before touching the connection. A capable
/// connection sends every reason as `SessionEnded` with its queue age; an older one sends only the
/// `guest_ended` reports, as `GuestEndedSession` (`due` leaves the rest unclaimed).
fn send_due_guest_ends(sig: &SignalingClient, reports: &GuestEndReports, session_ended_capable: bool) -> bool {
    let due = reports.pending.lock().unwrap().due(Instant::now(), session_ended_capable);
    for report in due {
        let msg = if session_ended_capable {
            ClientToServer::SessionEnded {
                control_plane_session: report.id,
                reason: report.reason,
                queue_age_ms: Some(u64::try_from(report.queue_age.as_millis()).unwrap_or(u64::MAX)),
            }
        } else {
            ClientToServer::GuestEndedSession { control_plane_session: report.id }
        };
        if sig.send(msg).is_err() {
            return false;
        }
    }
    true
}

/// Notifications give an end report immediate delivery; polling also handles retry deadlines.
async fn guest_end_task(sig: SignalingClient, reports: GuestEndReports, session_ended_capable: bool) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = reports.notify.notified() => {},
            _ = tick.tick() => {},
        }
        if !send_due_guest_ends(&sig, &reports, session_ended_capable) {
            break;
        }
    }
}

// ── Pre-registration buffer ───────────────────────────────────────────────────────────────────────

/// Most distinct sessions the pre-`Brokered` buffer tracks at once. A legitimate rendezvous needs one slot for the
/// few milliseconds between its `IceServers` and its `Brokered`.
const PRE_BROKERED_MAX_SESSIONS: usize = 64;
/// Most messages buffered for ONE session (a real one sends `IceServers` and maybe a `RelayAssignment`).
const PRE_BROKERED_MAX_MESSAGES: usize = 32;
/// Most estimated bytes buffered for ONE session.
const PRE_BROKERED_MAX_SESSION_BYTES: usize = 256 * 1024;
/// Most estimated bytes buffered across ALL sessions (the SYSTEM agent's memory bound for this buffer).
const PRE_BROKERED_MAX_TOTAL_BYTES: usize = 1024 * 1024;
/// A buffered session (or a poisoned one) that is not brokered within this long is forgotten: its `Brokered` is not coming.
const PRE_BROKERED_TTL: Duration = Duration::from_secs(30);

/// Rough heap size of a message, for the buffer's byte bound. Over-counting is harmless; under-counting is not.
fn approx_message_bytes(msg: &ServerToClient) -> usize {
    const BASE: usize = 64;
    BASE + match msg {
        ServerToClient::IceServers { servers, .. } => servers
            .iter()
            .map(|s| {
                32 + s.urls.iter().map(|u| u.len() + 24).sum::<usize>()
                    + s.username.as_ref().map_or(0, String::len)
                    + s.credential.as_ref().map_or(0, String::len)
            })
            .sum(),
        ServerToClient::RelayAssignment { relay_addr, .. } => relay_addr.len() + 16,
        ServerToClient::Candidate { candidate, .. } => candidate.addr.len(),
        ServerToClient::Sdp { sdp, .. } => sdp.len(),
        _ => 0,
    }
}

/// Why the buffer refused a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreBrokeredDrop {
    /// This session already overflowed: its buffer was discarded and it is refused from here on.
    Poisoned,
    /// The session exceeded its own message or byte budget; its buffer was discarded and it is now poisoned.
    SessionOverflow,
    /// The session table (or the shared byte budget) is full of OTHER sessions; this message was dropped.
    TableFull,
}

struct PreBrokeredEntry {
    first_seen: Instant,
    bytes: usize,
    msgs: Vec<ServerToClient>,
}

/// Messages that arrive for a session before its `Brokered` is processed, BOUNDED in sessions, per-session
/// messages and bytes, total bytes and age (security audit 2026-11-01 #8: a brokered peer could grow this without
/// limit inside the SYSTEM agent). A session that blows its own budget is discarded AND poisoned: it can never
/// be brokered here, so a hostile id cannot park a large buffer and then claim it.
#[derive(Default)]
struct PreBrokered {
    entries: HashMap<SessionId, PreBrokeredEntry>,
    poisoned: HashMap<SessionId, Instant>,
    total_bytes: usize,
    dropped: u64,
}

impl PreBrokered {
    fn expire(&mut self, now: Instant) {
        let stale: Vec<SessionId> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.first_seen) > PRE_BROKERED_TTL)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.remove(&k);
        }
        self.poisoned.retain(|_, at| now.saturating_duration_since(*at) <= PRE_BROKERED_TTL);
    }

    fn push(&mut self, sid: SessionId, msg: ServerToClient, now: Instant) -> Result<(), PreBrokeredDrop> {
        self.expire(now);
        if self.poisoned.contains_key(&sid) {
            return Err(PreBrokeredDrop::Poisoned);
        }
        let bytes = approx_message_bytes(&msg);
        let (entry_msgs, entry_bytes) = self.entries.get(&sid).map_or((0, 0), |e| (e.msgs.len(), e.bytes));
        if entry_msgs + 1 > PRE_BROKERED_MAX_MESSAGES || entry_bytes + bytes > PRE_BROKERED_MAX_SESSION_BYTES {
            self.remove(&sid);
            // The poison table is bounded by the same session cap; beyond it the flood is simply dropped.
            if self.poisoned.len() < PRE_BROKERED_MAX_SESSIONS {
                self.poisoned.insert(sid, now);
            }
            return Err(PreBrokeredDrop::SessionOverflow);
        }
        if !self.entries.contains_key(&sid) && self.entries.len() >= PRE_BROKERED_MAX_SESSIONS {
            return Err(PreBrokeredDrop::TableFull);
        }
        if self.total_bytes + bytes > PRE_BROKERED_MAX_TOTAL_BYTES {
            return Err(PreBrokeredDrop::TableFull);
        }
        let entry = self.entries.entry(sid).or_insert_with(|| PreBrokeredEntry { first_seen: now, bytes: 0, msgs: Vec::new() });
        entry.bytes += bytes;
        entry.msgs.push(msg);
        self.total_bytes += bytes;
        Ok(())
    }

    /// Take a session's buffered messages (it was brokered), and forget it.
    fn take(&mut self, sid: &SessionId) -> Vec<ServerToClient> {
        match self.entries.remove(sid) {
            Some(e) => {
                self.total_bytes = self.total_bytes.saturating_sub(e.bytes);
                e.msgs
            }
            None => Vec::new(),
        }
    }

    fn remove(&mut self, sid: &SessionId) {
        let _ = self.take(sid);
    }

    /// Whether this session overflowed: it must not be brokered (its first messages are gone).
    fn is_poisoned(&self, sid: &SessionId) -> bool {
        self.poisoned.contains_key(sid)
    }

    /// Count a drop and say whether to log it: the first, then every 1024th, so a flood cannot also flood the log.
    fn note_drop(&mut self) -> bool {
        self.dropped += 1;
        self.dropped == 1 || self.dropped % 1024 == 0
    }
}

// ── Dispatch task ─────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
async fn dispatch_task(
    sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
    sig: SignalingClient,
    new_session_tx: mpsc::Sender<BrokeredSession>,
    sessions: SessionMap,
) {
    dispatch_task_with_reports(sig_rx, sig, new_session_tx, sessions, None, None, None).await;
}

async fn dispatch_task_with_reports(
    mut sig_rx: mpsc::UnboundedReceiver<ServerToClient>,
    sig: SignalingClient,
    new_session_tx: mpsc::Sender<BrokeredSession>,
    sessions: SessionMap,
    reports: Option<GuestEndReports>,
    directive_hub: Option<(std::sync::Arc<crate::directive_hub::DirectiveHub>, u64)>,
    help_hub: Option<(std::sync::Arc<crate::help_request::HelpHub>, u64)>,
) {
    // Buffer for messages that arrive BEFORE their session's `Brokered` is processed.
    //
    // The signaling server sends `IceServers` (and sometimes `RelayAssignment`) BEFORE the
    // `Brokered` message — this ordering is load-bearing (see broker.go). A naive mux would drop
    // them because the session routing table has no entry yet. Instead we park them here and flush
    // to the per-session channel the moment `Brokered` registers the session.
    let mut pre_brokered = PreBrokered::default();

    while let Some(msg) = sig_rx.recv().await {
        match msg {
            // ── Connection-level ───────────────────────────────────────────────────────────────
            ServerToClient::Registered { .. } => {
                tracing::debug!("signaling_mux: registered");
            }
            ServerToClient::AgentAuthChallenge { .. } => {
                // Auth challenges need the agent's signing key; we cannot handle them here
                // without access to the key. The caller should handle challenges BEFORE handing
                // the receiver to SignalingMux, or extend the API with a challenge callback.
                // For now: log and ignore. The signaling server will close the connection if
                // the challenge is unanswered (enforcing mode).
                tracing::warn!(
                    "signaling_mux: received AgentAuthChallenge after handing off to mux — \
                     challenge cannot be answered; add auth handling before constructing the mux"
                );
            }
            ServerToClient::GuestEndedResult { control_plane_session, outcome }
            | ServerToClient::SessionEndedResult { control_plane_session, outcome } => {
                if let Some(reports) = reports.as_ref() {
                    reports.pending.lock().unwrap().on_result(
                        control_plane_session, outcome, Instant::now(),
                    );
                }
            }
            // docs/65: a control-plane-signed directive relayed to this authenticated device, and the answer to an ack. The mux
            // verifies NOTHING: the engine does, against the pinned key. Without a hub (directives not enabled) both are ignored.
            ServerToClient::Directive { directive_id, artifact } => {
                if let Some((hub, _)) = directive_hub.as_ref() {
                    hub.on_directive(directive_id, artifact);
                } else {
                    tracing::debug!("signaling_mux: ignoring a directive (no directive key pinned)");
                }
            }
            ServerToClient::DirectiveAckResult { directive_id, outcome, from, to, ts_ms } => {
                // Tagged with THIS connection's generation: an answer is applied only if that generation is still the current one.
                if let Some((hub, generation)) = directive_hub.as_ref() {
                    hub.on_ack_result(*generation, crate::directive_hub::AckResult { directive_id, outcome, from, to, ts_ms });
                }
            }
            // docs/64: the answer to a help_request / help_cancel / help_status. Tagged with THIS connection's generation, so
            // an answer from a previous connection can never settle the new one's state. Without a hub it is ignored.
            ServerToClient::HelpRequestResult { op, op_id, outcome, request, retry_after_seconds, cancel_of } => {
                if let Some((hub, generation)) = help_hub.as_ref() {
                    hub.on_result(
                        *generation,
                        crate::help_request::HelpResult { op, op_id, outcome, request, retry_after_seconds, cancel_of },
                        Instant::now(),
                    );
                }
            }
            ServerToClient::Rejected { reason } => {
                // A signaling server that predates guest_ended_session answers it with exactly this
                // reason and KEEPS the connection (main.go's dispatch default arm). Ending the mux here
                // would turn every guest End against an old server into a re-register → re-send →
                // reject loop, so this one reason is a per-message refusal: back the reports off and
                // keep serving. The only message this agent can send that an older server does not
                // know is the guest-end report.
                if reason == "unsupported message type" {
                    if let Some(reports) = reports.as_ref() {
                        reports.pending.lock().unwrap().on_rejected_unsupported(Instant::now());
                    }
                    tracing::info!("signaling_mux: server does not support guest-end reports; retrying later");
                    continue;
                }
                tracing::warn!(%reason, "signaling_mux: rejected by server");
                break;
            }

            // ── New brokered session ───────────────────────────────────────────────────────────
            ServerToClient::Brokered {
                session,
                peer_device,
                peer_pubkey,
                control_plane_session,
                technician_id,
                access,
                access_version,
            } => {
                // A second Brokered for a session that is still live is refused (security audit
                // 2026-10-18): inserting it replaced the live session's route, so the first session
                // silently lost its remaining ICE/SDP mid-negotiation and a second BrokeredSession
                // with the same id reached the acceptor.
                if sessions.lock().unwrap().contains_key(&session) {
                    tracing::warn!(?session, "signaling_mux: refused a duplicate Brokered for a live session");
                    continue;
                }
                // docs/49 fence: a control-plane id that already ended in this process never gets a
                // second lifetime, so its end report cannot close a live session. The control plane
                // mints one ticket per id (enforced by its AST guard); this is defence in depth.
                if let (Some(reports), Some(cp)) = (reports.as_ref(), control_plane_session) {
                    if reports.ended.lock().unwrap().contains(cp, Instant::now()) {
                        tracing::warn!(?session, control_plane_session = %cp,
                            "signaling_mux: refused a Brokered for a control-plane session that already ended here");
                        pre_brokered.remove(&session);
                        continue;
                    }
                }
                // A session whose pre-registration buffer overflowed lost its first messages (and the hostile
                // peer that flooded it is the only thing that could have): it is never started here.
                if pre_brokered.is_poisoned(&session) {
                    tracing::warn!(?session, "signaling_mux: refused a Brokered for a session whose pre-registration buffer overflowed");
                    if let (Some(reports), Some(cp)) = (reports.as_ref(), control_plane_session) {
                        let _ = reports.report_end(cp, rmt_protocol::signaling::SessionEndReason::Other, Instant::now());
                    }
                    continue;
                }
                let access = rmt_protocol::signaling::classify_brokered_access(access.as_ref(), access_version.as_ref());
                let (session_tx, session_rx) = mpsc::unbounded_channel();
                // Extract IceServers from the pre-registration buffer, route everything else
                // into the session channel. The server sends IceServers BEFORE Brokered
                // (load-bearing ordering), so IceServers will always be in the buffer when
                // a real signaling server is used.
                let mut issued_ice = Vec::new();
                {
                    for m in pre_brokered.take(&session) {
                        match m {
                            ServerToClient::IceServers { servers, .. } => {
                                // Accumulate, not assign: the server may send separate STUN and
                                // TURN entries as multiple IceServers messages. Replacing would
                                // silently drop all but the last.
                                issued_ice.extend(servers);
                            }
                            other => {
                                let _ = session_tx.send(other);
                            }
                        }
                    }
                }
                sessions.lock().unwrap().insert(session, session_tx);
                tracing::debug!(?session, n_ice = issued_ice.len(), "signaling_mux: new brokered session");
                let bs = BrokeredSession {
                    session,
                    peer_device,
                    peer_pubkey,
                    control_plane_session,
                    technician_id,
                    access,
                    issued_ice,
                    sig: sig.clone(),
                    rx: session_rx,
                };
                if let Err(refused) = new_session_tx.send(bs).await {
                    // The acceptor closed the queue (shutdown) or is gone: this vouched session will
                    // never start, so report it here, or nothing closes its control-plane row.
                    let bs = refused.0;
                    sessions.lock().unwrap().remove(&bs.session);
                    if let (Some(reports), Some(id)) = (reports.as_ref(), bs.control_plane_session) {
                        let _ = reports.report_end(id, rmt_protocol::signaling::SessionEndReason::ServiceStop, Instant::now());
                    }
                    // KEEP DISPATCHING. A closed accept queue means a shutdown is draining reports over
                    // THIS connection, and their acknowledgements arrive through this loop; leaving it
                    // would cancel the connection below and strand them (Codex 1.3.7 release review
                    // v4). A mux that is really gone aborts this task from its Drop instead.
                    continue;
                }
            }

            // ── Per-session routing ────────────────────────────────────────────────────────────
            msg => {
                let sid = session_id_of(&msg);
                if let Some(sid) = sid {
                    let map = sessions.lock().unwrap();
                    match map.get(&sid) {
                        Some(tx) => {
                            if tx.send(msg).is_err() {
                                tracing::debug!(
                                    ?sid,
                                    "signaling_mux: session channel closed; dropping message"
                                );
                            }
                        }
                        None => {
                            // Session not yet registered (message arrived before Brokered).
                            // Buffer it; will be flushed when Brokered registers the session.
                            drop(map);
                            match pre_brokered.push(sid, msg, Instant::now()) {
                                Ok(()) => tracing::debug!(
                                    ?sid,
                                    "signaling_mux: buffering pre-registration message"
                                ),
                                Err(why) => {
                                    if pre_brokered.note_drop() {
                                        tracing::warn!(?sid, reason = ?why, dropped = pre_brokered.dropped,
                                            "signaling_mux: pre-registration buffer bound hit; message dropped");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Normal exit (EOF, Rejected, or acceptor gone): cancel the underlying connection so the
    // reader and writer tasks exit bounded. When dispatch is aborted (mux dropped), this line is
    // never reached — the mux Drop calls _conn_owner.cancel() for that path.
    sig.cancel();
    tracing::debug!("signaling_mux: dispatch task exiting");
}

/// Extract the `SessionId` from session-specific `ServerToClient` variants.
/// Returns `None` for connection-level variants that have no session id.
fn session_id_of(msg: &ServerToClient) -> Option<SessionId> {
    match msg {
        ServerToClient::IceServers { session, .. } => Some(*session),
        ServerToClient::RelayAssignment { session, .. } => Some(*session),
        ServerToClient::Candidate { session, .. } => Some(*session),
        ServerToClient::Sdp { session, .. } => Some(*session),
        _ => None,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt as _;
    use rmt_protocol::{signaling::CandidateKind, DeviceId, SessionId};

    fn sid() -> SessionId { SessionId(uuid::Uuid::new_v4()) }
    fn did() -> DeviceId { DeviceId(uuid::Uuid::new_v4()) }

    /// Spin up a loopback WebSocket server that accepts one connection and stays open.
    /// Returns the bound port.
    ///
    /// The server drains incoming frames until the client closes the connection, keeping the
    /// socket alive for the duration of the test. Without the drain loop the WebSocket would be
    /// dropped immediately after `accept_async`, closing the TCP connection and causing the
    /// client's writer task to fail on its first write attempt.
    async fn loopback_accept_and_hold() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(_) = rx.next().await {}
        });
        port
    }

    /// Capture actual outbound frames while injecting inbound messages through the mux receiver.
    async fn reporting_mux(
        reports: GuestEndReports,
        features: Vec<String>,
    ) -> (
        SignalingMux,
        mpsc::UnboundedSender<ServerToClient>,
        mpsc::UnboundedReceiver<String>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, frames_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_writer, mut reader) = ws.split();
            while let Some(Ok(frame)) = reader.next().await {
                if let Ok(text) = frame.into_text() {
                    let _ = frames_tx.send(text.to_string());
                }
            }
        });
        let (sig, _rx) = SignalingClient::connect(&format!("ws://127.0.0.1:{port}"))
            .await.unwrap();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let mux = SignalingMux::new_with_reports(sig, inbound_rx, None, Some(reports), &features);
        (mux, inbound_tx, frames_rx)
    }

    async fn assert_guest_end_frame(frames: &mut mpsc::UnboundedReceiver<String>, id: uuid::Uuid) {
        let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
            .await.unwrap().unwrap();
        assert_eq!(frame, format!(
            r#"{{"type":"guest_ended_session","control_plane_session":"{id}"}}"#
        ));
    }

    /// Brokered delivery is a dispatch barrier: earlier results have been processed when it arrives.
    async fn dispatch_barrier(mux: &mut SignalingMux, tx: &mpsc::UnboundedSender<ServerToClient>) {
        tx.send(ServerToClient::Brokered {
            session: sid(), peer_device: None, peer_pubkey: "pk".into(),
            control_plane_session: None, technician_id: None, access: None, access_version: None,
        }).unwrap();
        tokio::time::timeout(Duration::from_secs(2), mux.accept()).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pending_guest_end_is_sent_and_terminal_result_removes_it() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::GuestEndOutcome;
        let reports = GuestEndShared::new();
        let id = uuid::Uuid::new_v4();
        let (mut mux, tx, mut frames) = reporting_mux(reports.clone(), vec![]).await;
        reports.pending.lock().unwrap().add(id, rmt_protocol::signaling::SessionEndReason::GuestEnded, Instant::now());
        reports.notify.notify_one();
        assert_guest_end_frame(&mut frames, id).await;
        tx.send(ServerToClient::GuestEndedResult {
            control_plane_session: id, outcome: GuestEndOutcome::Ended,
        }).unwrap();
        dispatch_barrier(&mut mux, &tx).await;
        assert_eq!(reports.pending.lock().unwrap().len(), 0);
        assert!(session_id_of(&ServerToClient::GuestEndedResult {
            control_plane_session: id, outcome: GuestEndOutcome::Ended,
        }).is_none());
    }

    #[tokio::test]
    async fn unavailable_schedules_retry_and_fresh_mux_resends_pending() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::GuestEndOutcome;
        let reports = GuestEndShared::new();
        let id = uuid::Uuid::new_v4();
        reports.pending.lock().unwrap().add(id, rmt_protocol::signaling::SessionEndReason::GuestEnded, Instant::now());
        let (mut mux, tx, mut frames) = reporting_mux(reports.clone(), vec![]).await;
        assert_guest_end_frame(&mut frames, id).await;
        tx.send(ServerToClient::GuestEndedResult {
            control_plane_session: id, outcome: GuestEndOutcome::Unavailable,
        }).unwrap();
        dispatch_barrier(&mut mux, &tx).await;
        {
            let mut pending = reports.pending.lock().unwrap();
            assert_eq!(pending.len(), 1);
            assert!(pending.due(Instant::now(), false).is_empty());
            assert_eq!(pending.due(Instant::now() + Duration::from_secs(3), false).iter().map(|d| d.id).collect::<Vec<_>>(), vec![id]);
        }
        drop(mux);
        // The previous claim has an outstanding ACK timeout; registration overrides it.
        let (_mux, _tx, mut frames) = reporting_mux(reports.clone(), vec![]).await;
        assert_guest_end_frame(&mut frames, id).await;
        assert_eq!(reports.pending.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unsupported_rejection_retains_reports_and_keeps_serving() {
        // An older signaling server refuses the unknown guest-end report but KEEPS the connection.
        // The mux must back the report off and keep dispatching — ending here would turn every guest
        // End against an old server into a re-register/re-send/reject loop.
        use rmt_agent_core::guest_end::GuestEndShared;
        let reports = GuestEndShared::new();
        let id = uuid::Uuid::new_v4();
        reports.pending.lock().unwrap().add(id, rmt_protocol::signaling::SessionEndReason::GuestEnded, Instant::now());
        let (mut mux, tx, mut frames) = reporting_mux(reports.clone(), vec![]).await;
        assert_guest_end_frame(&mut frames, id).await;
        tx.send(ServerToClient::Rejected { reason: "unsupported message type".into() }).unwrap();
        let session = sid();
        tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "pk".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        })
        .unwrap();
        let bs = tokio::time::timeout(Duration::from_secs(2), mux.accept())
            .await
            .expect("dispatch must still be running after the unsupported-type rejection")
            .expect("a brokered session after the rejection must still be accepted");
        assert_eq!(bs.session, session);
        let mut pending = reports.pending.lock().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending.due(Instant::now() + Duration::from_secs(30), false).is_empty());
        assert_eq!(pending.due(Instant::now() + Duration::from_secs(61), false).iter().map(|d| d.id).collect::<Vec<_>>(), vec![id]);
    }

    async fn next_frame(frames: &mut mpsc::UnboundedReceiver<String>) -> serde_json::Value {
        let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
            .await.expect("no frame within 2 s").expect("frame stream closed");
        serde_json::from_str(&frame).unwrap()
    }

    // docs/49: a connection whose Registered advertised session_ended_v1 carries every reason as
    // session_ended, with the queue age; the session_ended_result acknowledges it.
    #[tokio::test]
    async fn capable_connection_sends_session_ended_with_reason_and_age() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::{GuestEndOutcome, SessionEndReason};
        let reports = GuestEndShared::new();
        let id = uuid::Uuid::new_v4();
        reports.pending.lock().unwrap().add(id, SessionEndReason::LeaseLapsed, Instant::now() - Duration::from_millis(1200));
        let (mut mux, tx, mut frames) = reporting_mux(reports.clone(), vec![SESSION_ENDED_FEATURE.into()]).await;
        assert!(mux.session_ended_capable());
        let frame = next_frame(&mut frames).await;
        assert_eq!(frame["type"], "session_ended");
        assert_eq!(frame["control_plane_session"], id.to_string());
        assert_eq!(frame["reason"], "lease_lapsed");
        let age = frame["queue_age_ms"].as_u64().expect("queue_age_ms");
        assert!((1200..60_000).contains(&age), "queue age {age} ms");
        tx.send(ServerToClient::SessionEndedResult { control_plane_session: id, outcome: GuestEndOutcome::Ended }).unwrap();
        dispatch_barrier(&mut mux, &tx).await;
        assert!(reports.pending.lock().unwrap().is_empty());
    }

    // An older connection can carry only guest_ended: the other report stays queued, unsent.
    #[tokio::test]
    async fn older_connection_holds_non_guest_reasons() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::SessionEndReason;
        let reports = GuestEndShared::new();
        let lapsed = uuid::Uuid::new_v4();
        let guest = uuid::Uuid::new_v4();
        reports.pending.lock().unwrap().add(lapsed, SessionEndReason::LeaseLapsed, Instant::now());
        let (mux, _tx, mut frames) = reporting_mux(reports.clone(), vec!["some_other_feature".into()]).await;
        assert!(!mux.session_ended_capable());
        reports.pending.lock().unwrap().add(guest, SessionEndReason::GuestEnded, Instant::now());
        reports.notify.notify_one();
        // The first frame is the guest report: the lapsed one was never sent ahead of it.
        assert_guest_end_frame(&mut frames, guest).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(frames.try_recv().is_err(), "a non-guest report was sent on an older connection");
        assert_eq!(reports.pending.lock().unwrap().sendable_len(true), 2);
    }

    // The ended-ids fence refuses a Brokered for a control-plane id that already ended here.
    #[tokio::test]
    async fn brokered_for_an_ended_control_plane_session_is_refused() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::SessionEndReason;
        let reports = GuestEndShared::new();
        let ended = uuid::Uuid::new_v4();
        reports.report_end(ended, SessionEndReason::ViewerLeft, Instant::now());
        let (mut mux, tx, _frames) = reporting_mux(reports.clone(), vec![SESSION_ENDED_FEATURE.into()]).await;
        let brokered = |session, cp| ServerToClient::Brokered {
            session, peer_device: None, peer_pubkey: "pk".into(), control_plane_session: Some(cp),
            technician_id: None, access: None, access_version: None,
        };
        tx.send(brokered(sid(), ended)).unwrap();
        let fresh = uuid::Uuid::new_v4();
        let second = sid();
        tx.send(brokered(second, fresh)).unwrap();
        let bs = tokio::time::timeout(Duration::from_secs(2), mux.accept()).await.unwrap().unwrap();
        assert_eq!(bs.session, second, "the fenced Brokered must not reach the acceptor");
        assert_eq!(bs.control_plane_session, Some(fresh));
    }

    /// Codex 1.3.7 release review v3 [medium]: at shutdown, vouched sessions brokered but never
    /// accepted must not vanish with the mux. Nine are brokered and none accepted: eight fill the
    /// queue and come back from close_accept (deregistered) for the host to report; the ninth is
    /// blocked in the dispatcher's send, which fails once the queue closes, and the dispatcher
    /// reports it itself.
    #[tokio::test]
    async fn shutdown_hands_back_every_queued_session_and_reports_the_one_being_queued() {
        use rmt_agent_core::guest_end::GuestEndShared;
        use rmt_protocol::signaling::{GuestEndOutcome, SessionEndReason};
        let reports = GuestEndShared::new();
        let (mut mux, tx, mut frames) = reporting_mux(reports.clone(), vec![SESSION_ENDED_FEATURE.into()]).await;
        let mut cps = Vec::new();
        for _ in 0..9 {
            let cp = uuid::Uuid::new_v4();
            cps.push(cp);
            tx.send(ServerToClient::Brokered {
                session: sid(), peer_device: None, peer_pubkey: "pk".into(), control_plane_session: Some(cp),
                technician_id: None, access: None, access_version: None,
            }).unwrap();
        }
        // Let the dispatcher fill the eight-slot queue and block on the ninth.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let queued = mux.close_accept();
        assert_eq!(queued.len(), 8, "every queued session is handed back");
        let got: Vec<_> = queued.iter().map(|b| b.control_plane_session.unwrap()).collect();
        assert_eq!(got, cps[..8].to_vec(), "in brokering order");
        for bs in &queued {
            assert!(!mux.sessions.lock().unwrap().contains_key(&bs.session), "deregistered from routing");
        }
        // The ninth: the dispatcher's blocked send fails once the queue closes, and it reports it.
        let ninth = cps[8];
        let reported = async {
            loop {
                if reports.ended.lock().unwrap().contains(ninth, Instant::now()) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(2), reported).await
            .expect("the session the dispatcher was queuing is reported, not dropped");
        // DELIVERY, not just recording (Codex 1.3.7 review v4: the dispatcher used to exit here and
        // cancel the connection the drain needs). The host reports the eight it got back; all nine
        // must go out on the wire, and the server's acknowledgements must drain the pending set.
        for bs in &queued {
            reports.report_end(bs.control_plane_session.unwrap(), SessionEndReason::ServiceStop, Instant::now());
        }
        let mut sent = std::collections::HashSet::new();
        while sent.len() < 9 {
            let frame = next_frame(&mut frames).await;
            if frame["type"] == "session_ended" {
                assert_eq!(frame["reason"], "service_stop");
                sent.insert(frame["control_plane_session"].as_str().unwrap().to_string());
            }
        }
        for cp in &cps {
            assert!(sent.contains(&cp.to_string()), "report for {cp} went out");
            tx.send(ServerToClient::SessionEndedResult { control_plane_session: *cp, outcome: GuestEndOutcome::Ended }).unwrap();
        }
        let drained = async {
            while !reports.pending.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3), drained).await
            .expect("every report is acknowledged: the connection outlived the closed accept queue");
        assert!(mux.accept().await.is_none(), "nothing more is admitted after close_accept");
    }

    // ── Existing routing tests (unchanged) ────────────────────────────────────────────────────

    /// `session_id_of` extracts the right id from each routable variant.
    #[test]
    fn session_id_of_extracts_from_routable_variants() {
        let s = sid();
        assert_eq!(
            session_id_of(&ServerToClient::IceServers { session: s, servers: vec![] }),
            Some(s)
        );
        assert_eq!(
            session_id_of(&ServerToClient::RelayAssignment {
                session: s,
                relay_addr: "host:1".into(),
                token: rmt_protocol::RelayToken(uuid::Uuid::nil()),
            }),
            Some(s)
        );
        assert_eq!(
            session_id_of(&ServerToClient::Candidate {
                session: s,
                candidate: rmt_protocol::signaling::Candidate {
                    addr: "x".into(),
                    kind: CandidateKind::Host,
                },
            }),
            Some(s)
        );
        assert_eq!(
            session_id_of(&ServerToClient::Sdp {
                session: s,
                sdp: "v=0".into(),
                kind: rmt_protocol::signaling::SdpKind::Offer,
            }),
            Some(s)
        );
    }

    /// Connection-level variants return `None` from `session_id_of`.
    #[test]
    fn session_id_of_returns_none_for_connection_level_variants() {
        let d = did();
        assert!(session_id_of(&ServerToClient::Registered { server_pubkey: "k".into(), features: vec![] }).is_none());
        assert!(session_id_of(&ServerToClient::AgentAuthChallenge {
            device: d,
            nonce: "n".into(),
            expires_at_ms: 0,
        })
        .is_none());
        assert!(session_id_of(&ServerToClient::Rejected { reason: "r".into() }).is_none());
    }

    /// The dispatch task delivers a `BrokeredSession` when it receives a `Brokered` message.
    #[tokio::test]
    async fn dispatch_delivers_brokered_session() {
        let session = sid();
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        // Build a real-ish SignalingClient with a real WebSocket connection to get a sender.
        // For testing dispatch in isolation we need a SignalingClient — but it requires a live
        // Use a real loopback WebSocket to get a valid SignalingClient sender.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
            // Server just stays open; we only need the client sender half.
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let sessions_d = Arc::clone(&sessions);
        let sig_d = sig.clone();
        tokio::spawn(dispatch_task(inbound_rx, sig_d, new_tx, sessions_d));

        inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "pk".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        }).unwrap();

        let bs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            new_rx.recv(),
        )
        .await
        .expect("must deliver BrokeredSession within 2s")
        .expect("channel must not close");

        assert_eq!(bs.session, session);
        assert_eq!(bs.peer_pubkey, "pk");
    }

    /// A message for an unknown session is silently discarded (no panic, no stall).
    #[tokio::test]
    async fn message_for_unknown_session_is_discarded() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, _new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, sessions));

        let unknown = sid();
        inbound_tx.send(ServerToClient::Candidate {
            session: unknown,
            candidate: rmt_protocol::signaling::Candidate {
                addr: "x".into(),
                kind: CandidateKind::Host,
            },
        }).unwrap();

        tokio::task::yield_now().await;
        // Reaching here without panic = test passes.
    }

    /// Routing routes per-session messages to the correct session channel.
    #[tokio::test]
    async fn routing_delivers_ice_servers_to_correct_session() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let session = sid();
        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        // First: Brokered → register session
        inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "p".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        }).unwrap();

        let mut bs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            new_rx.recv(),
        )
        .await.unwrap().unwrap();

        // Then: IceServers for that session
        inbound_tx.send(ServerToClient::IceServers {
            session,
            servers: vec![],
        }).unwrap();

        let routed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bs.rx.recv(),
        )
        .await
        .expect("IceServers must arrive within 2s")
        .expect("channel must not close");

        assert!(
            matches!(routed, ServerToClient::IceServers { .. }),
            "routed message must be IceServers"
        );
    }

    /// IceServers arriving BEFORE Brokered (as the server does it) are buffered and flushed
    /// to the per-session rx when Brokered finally registers the session.
    #[tokio::test]
    async fn ice_servers_before_brokered_are_buffered_and_flushed() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let session = sid();
        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        // Server ordering: IceServers FIRST (load-bearing; see broker.go), THEN Brokered.
        inbound_tx.send(ServerToClient::IceServers {
            session,
            servers: vec![],
        }).unwrap();
        inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "p".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        }).unwrap();

        let bs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            new_rx.recv(),
        )
        .await.unwrap().unwrap();

        // IceServers arriving before Brokered must be extracted into BrokeredSession.issued_ice,
        // not left in rx (so the caller never needs to drain the channel before building the peer
        // connection).
        assert_eq!(bs.issued_ice.len(), 0, "empty server list must arrive in issued_ice");
    }

    /// IceServers arriving BEFORE Brokered with real server entries are extracted correctly.
    #[tokio::test]
    async fn ice_servers_with_servers_before_brokered_end_up_in_issued_ice() {
        use rmt_protocol::signaling::IceServerSpec;

        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let session = sid();
        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        inbound_tx.send(ServerToClient::IceServers {
            session,
            servers: vec![IceServerSpec {
                urls: vec!["stun:stun.example.com:3478".into()],
                username: None,
                credential: None,
            }],
        }).unwrap();
        inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "p".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        }).unwrap();

        let bs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            new_rx.recv(),
        )
        .await.unwrap().unwrap();

        assert_eq!(bs.issued_ice.len(), 1, "must find one ice server in issued_ice");
        assert_eq!(bs.issued_ice[0].urls[0], "stun:stun.example.com:3478");
    }

    /// Two IceServers messages for the same session arrive before Brokered (e.g. STUN entry then
    /// TURN entry). Both must survive in issued_ice — not just the last one.
    #[tokio::test]
    async fn two_ice_servers_messages_before_brokered_both_survive() {
        use rmt_protocol::signaling::IceServerSpec;

        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_tungstenite::accept_async(tcp).await.unwrap();
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let session = sid();
        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        // First IceServers (STUN), then second IceServers (TURN), then Brokered.
        inbound_tx.send(ServerToClient::IceServers {
            session,
            servers: vec![IceServerSpec {
                urls: vec!["stun:stun.example.com:3478".into()],
                username: None,
                credential: None,
            }],
        }).unwrap();
        inbound_tx.send(ServerToClient::IceServers {
            session,
            servers: vec![IceServerSpec {
                urls: vec!["turn:turn.example.com:3478".into()],
                username: Some("user".into()),
                credential: Some("cred".into()),
            }],
        }).unwrap();
        inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "p".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        }).unwrap();

        let bs = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            new_rx.recv(),
        )
        .await.unwrap().unwrap();

        assert_eq!(
            bs.issued_ice.len(), 2,
            "both IceServers messages must be accumulated in issued_ice (not last-wins)"
        );
        assert_eq!(bs.issued_ice[0].urls[0], "stun:stun.example.com:3478");
        assert_eq!(bs.issued_ice[1].urls[0], "turn:turn.example.com:3478");
    }

    // ── Heartbeat lifecycle tests ─────────────────────────────────────────────────────────────

    /// The heartbeat task exits promptly when the signaling connection is closed — i.e. when
    /// `sig.send()` fails because the writer task's receive end has gone away.
    ///
    /// Lifecycle invariant: stop on send failure.
    #[tokio::test]
    async fn heartbeat_task_exits_on_send_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Server accepts and immediately drops the WebSocket (close).
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(tokio_tungstenite::accept_async(tcp).await.unwrap());
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let device = did();
        // With a 10 ms interval the heartbeat will fire, fail on the closed socket, and exit.
        // The test asserts the whole task completes well within 2 s.
        tokio::time::timeout(
            Duration::from_secs(2),
            heartbeat_task(sig, device, Duration::from_millis(10)),
        )
        .await
        .expect("heartbeat_task must exit within 2 s when the connection is closed");
    }

    /// Aborting the heartbeat task's AbortHandle terminates it at its next await point.
    ///
    /// Lifecycle invariant: timer ownership — the task is owned and cancellable.
    #[tokio::test]
    async fn heartbeat_task_aborted_by_abort_handle() {
        let port = loopback_accept_and_hold().await;
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let device = did();
        // Use a long interval so the task is parked in sleep when we abort it.
        let handle = tokio::spawn(heartbeat_task(sig, device, Duration::from_secs(60)));
        let abort = handle.abort_handle();
        // Yield once to let the task start and reach its first sleep.
        tokio::task::yield_now().await;
        abort.abort();
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("aborted task must resolve within 2 s");
        assert!(result.is_err(), "aborted task must resolve with JoinError::Cancelled");
    }

    /// When `SignalingMux` is dropped, the connection-owned heartbeat task is aborted and no
    /// further heartbeat messages arrive at the server.
    ///
    /// Lifecycle invariant: timer cancellation on mux drop.
    #[tokio::test]
    async fn mux_drop_cancels_heartbeat() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (hb_tx, mut hb_rx) = mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(Ok(msg)) = rx.next().await {
                if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                    if t.contains("heartbeat") {
                        let _ = hb_tx.send(());
                    }
                }
            }
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, sig_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let device = did();
        let mux = SignalingMux::new_with_interval(sig, sig_rx, Some(device), Duration::from_millis(20));

        // Wait for at least one heartbeat to confirm the task is active.
        tokio::time::timeout(Duration::from_secs(2), hb_rx.recv())
            .await
            .expect("at least one heartbeat must arrive within 2 s")
            .expect("channel closed unexpectedly");

        // Drop the mux — this must abort the heartbeat task.
        drop(mux);

        // Drain any heartbeats that were already in-flight at the moment of drop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        while hb_rx.try_recv().is_ok() {}

        // No further heartbeats should arrive in the next 150 ms (≥ 7 × 20 ms intervals).
        tokio::time::sleep(Duration::from_millis(150)).await;
        let stray = std::iter::from_fn(|| hb_rx.try_recv().ok()).count();
        assert_eq!(stray, 0, "no heartbeats must arrive after the mux is dropped");
    }

    /// Creating a `SignalingMux` with `device = None` (controller path) must not spawn a
    /// heartbeat task and must not send any heartbeat messages.
    ///
    /// Lifecycle invariant: controller exclusion.
    #[tokio::test]
    async fn mux_without_device_sends_no_heartbeats() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (hb_tx, mut hb_rx) = mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(Ok(msg)) = rx.next().await {
                if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                    if t.contains("heartbeat") {
                        let _ = hb_tx.send(());
                    }
                }
            }
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, sig_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        // device = None → no heartbeat task should be spawned.
        let _mux = SignalingMux::new_with_interval(sig, sig_rx, None, Duration::from_millis(20));

        // Wait longer than several intervals and verify nothing arrived.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let count = std::iter::from_fn(|| hb_rx.try_recv().ok()).count();
        assert_eq!(count, 0, "no heartbeat must be sent when device is None (controller path)");
    }

    // ── Pass-22 lifecycle tests ───────────────────────────────────────────────────────────────

    /// Dropping `SignalingMux` aborts the dispatch task: a `Brokered` message injected after drop
    /// is never routed into the session map.
    ///
    /// Lifecycle invariant: dispatch cancellation on mux drop.
    #[tokio::test]
    async fn mux_drop_aborts_dispatch_new_brokered_not_routed() {
        // Use a synthetic inbound channel so we can inject messages independently of the WebSocket.
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let port = loopback_accept_and_hold().await;
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _real_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let mux = SignalingMux::new_with_interval(sig, inbound_rx, None, Duration::from_millis(10));
        let handle = mux.deregister_handle();

        // Drop the mux — abort handle fires, dispatch task is cancelled.
        drop(mux);
        // Yield multiple times to let the Tokio runtime propagate the cancellation.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        // Inject a Brokered message after dispatch has been aborted.
        let session = sid();
        let _ = inbound_tx.send(ServerToClient::Brokered {
            session,
            peer_device: None,
            peer_pubkey: "p".into(),
            control_plane_session: None,
            technician_id: None,
            access: None,
            access_version: None,
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        let map = handle.sessions.lock().unwrap();
        assert!(
            !map.contains_key(&session),
            "dispatch must be aborted after mux drop: Brokered must not populate session map"
        );
    }

    /// When the server sends `Rejected`, the dispatch task exits its message loop promptly.
    ///
    /// Lifecycle invariant: rejection retires dispatch (caller should then drop the mux to retire
    /// the heartbeat timer).
    #[tokio::test]
    async fn rejected_message_causes_dispatch_to_exit() {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();
        let (new_tx, _new_rx) = mpsc::channel::<BrokeredSession>(8);
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

        let port = loopback_accept_and_hold().await;
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let handle =
            tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        inbound_tx.send(ServerToClient::Rejected { reason: "auth-test".into() }).unwrap();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatch must exit within 2 s on Rejected")
            .expect("dispatch task must not panic on Rejected");
    }

    /// When the inbound channel closes (reader EOF), the dispatch task exits its message loop.
    ///
    /// Lifecycle invariant: EOF retires dispatch.
    #[tokio::test]
    async fn reader_eof_causes_dispatch_to_exit() {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();
        let (new_tx, _new_rx) = mpsc::channel::<BrokeredSession>(8);
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

        let port = loopback_accept_and_hold().await;
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let handle =
            tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        // Closing the sender makes recv() return None → dispatch loop exits.
        drop(inbound_tx);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("dispatch must exit within 2 s on reader EOF")
            .expect("dispatch task must not panic on EOF");
    }

    /// After dropping a mux and reconnecting with a new one, exactly one fresh heartbeat task
    /// runs — the old task was cancelled, the new one starts. Connection identity is tagged by
    /// device UUID so we can prove no old-connection traffic arrives after retirement.
    ///
    /// Lifecycle invariant: reconnect starts exactly one new heartbeat source; old source silent.
    #[tokio::test]
    async fn reconnect_no_old_heartbeat_after_retirement() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Each heartbeat carries the device UUID in JSON; forward it as a String tag.
        let (hb_tx, mut hb_rx) = mpsc::unbounded_channel::<String>();

        // Server: accept multiple connections, extract device UUID from each heartbeat frame.
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let hb_tx2 = hb_tx.clone();
                tokio::spawn(async move {
                    let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    let (_, mut rx) = ws.split();
                    while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) =
                        rx.next().await
                    {
                        if t.contains("heartbeat") {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                                if let Some(dev) = v["device"].as_str() {
                                    let _ = hb_tx2.send(dev.to_string());
                                }
                            }
                        }
                    }
                });
            }
        });

        let url = format!("ws://127.0.0.1:{port}");
        let device1 = did();
        let device2 = did();
        let dev1_uuid = device1.0.to_string();
        let dev2_uuid = device2.0.to_string();

        // Mux1 with device1: confirm heartbeat arrives with correct tag.
        let (sig1, sig_rx1) =
            rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let mux1 =
            SignalingMux::new_with_interval(sig1, sig_rx1, Some(device1), Duration::from_millis(20));
        let first_hb = tokio::time::timeout(Duration::from_secs(2), hb_rx.recv())
            .await
            .expect("mux1 must send at least one heartbeat within 2 s")
            .expect("channel closed unexpectedly");
        assert_eq!(first_hb, dev1_uuid, "mux1 heartbeat must carry device1 UUID");

        // Drop mux1 and drain any in-flight heartbeats from the old connection.
        drop(mux1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        let mut in_flight = 0usize;
        while let Ok(hb) = hb_rx.try_recv() {
            assert_eq!(hb, dev1_uuid, "in-flight heartbeats after mux1 drop must be from device1");
            in_flight += 1;
        }
        let _ = in_flight; // recorded for log evidence if needed

        // Mux2 with device2 (fresh connection): confirm fresh heartbeat arrives.
        let (sig2, sig_rx2) =
            rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let _mux2 =
            SignalingMux::new_with_interval(sig2, sig_rx2, Some(device2), Duration::from_millis(20));
        let first_hb2 = tokio::time::timeout(Duration::from_secs(2), hb_rx.recv())
            .await
            .expect("mux2 must send at least one heartbeat within 2 s after reconnect")
            .expect("channel closed unexpectedly");
        assert_eq!(first_hb2, dev2_uuid, "post-reconnect heartbeat must carry device2 UUID, not stale device1");

        // Extra window: ensure no device1 heartbeats arrive after mux1 was retired.
        tokio::time::sleep(Duration::from_millis(100)).await;
        while let Ok(hb) = hb_rx.try_recv() {
            assert_ne!(
                hb, dev1_uuid,
                "no device1 heartbeats must arrive after mux1 retirement (stale connection leaking)"
            );
        }
    }

    /// After the mux is dropped, messages already buffered in an established session's channel
    /// remain readable from the BrokeredSession.rx — the per-session buffer is independent of
    /// the mux lifetime.
    ///
    /// Lifecycle invariant: per-session channel buffer survives mux drop.
    ///
    /// NOTE: this test verifies the per-session `mpsc` buffer only. It does not instantiate a
    /// WebRtcTransport, decode video, or exercise the post-reconnect media path. Real media
    /// survival across reconnects is a separate open gap (see codex-heartbeat-pass22-review.md).
    #[tokio::test]
    async fn buffered_session_messages_readable_after_mux_drop() {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();

        let port = loopback_accept_and_hold().await;
        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();

        let mut mux =
            SignalingMux::new_with_interval(sig, inbound_rx, None, Duration::from_millis(10));

        // Broker a session.
        let session = sid();
        inbound_tx
            .send(ServerToClient::Brokered {
                session,
                peer_device: None,
                peer_pubkey: "p".into(),
                control_plane_session: None,
                technician_id: None,
                access: None,
                access_version: None,
            })
            .unwrap();

        let mut bs = tokio::time::timeout(Duration::from_secs(2), mux.accept())
            .await
            .expect("BrokeredSession must arrive within 2 s")
            .expect("mux must not close before delivering session");

        // Route a message to the session before dropping the mux.
        inbound_tx
            .send(ServerToClient::IceServers { session, servers: vec![] })
            .unwrap();

        // Give dispatch time to route the message into the session channel.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Drop the mux (aborts dispatch and heartbeat; cancels reader+writer).
        drop(mux);

        // Messages already buffered in the session's channel must still be readable.
        let msg = tokio::time::timeout(Duration::from_secs(2), bs.rx.recv())
            .await
            .expect("session rx must deliver buffered message after mux drop")
            .expect("session channel must not close while BrokeredSession is held");

        assert!(
            matches!(msg, ServerToClient::IceServers { .. }),
            "buffered IceServers must be delivered from session channel after mux drop"
        );
    }

    /// Functional independent source review: heartbeat messages reach the WebSocket server with
    /// the correct JSON shape (`type=heartbeat`) and the exact device UUID that was registered.
    ///
    /// This test independently verifies the wire format — it does not share assumptions with
    /// `mux_drop_cancels_heartbeat` or `mux_without_device_sends_no_heartbeats`.
    #[tokio::test]
    async fn heartbeat_messages_contain_correct_device_id() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (msg_tx, mut msg_rx) = mpsc::channel::<String>(16);
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) = rx.next().await {
                if t.contains("heartbeat") {
                    if msg_tx.send(t).await.is_err() { break; }
                }
            }
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let device = did();
        let device_uuid = device.0.to_string();

        // Run heartbeat_task directly with a short interval.
        let task = tokio::spawn(heartbeat_task(sig, device, Duration::from_millis(20)));

        // Collect 3 consecutive heartbeats.
        for i in 0..3 {
            let raw = tokio::time::timeout(Duration::from_secs(2), msg_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("heartbeat {i} did not arrive within 2 s"))
                .expect("message channel closed");

            let v: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("heartbeat {i} is not valid JSON: {e} — raw={raw:?}"));
            assert_eq!(
                v["type"].as_str().unwrap_or(""),
                "heartbeat",
                "heartbeat {i}: type field must be 'heartbeat'"
            );
            assert_eq!(
                v["device"].as_str().unwrap_or(""),
                device_uuid,
                "heartbeat {i}: device field must match the registered device UUID"
            );
        }

        task.abort();
    }

    // ── Pass-24 connection lifecycle tests ────────────────────────────────────────────────────
    //
    // These tests verify that the underlying WebSocket reader and writer tasks exit bounded when
    // the mux owner retires, and that retained SignalingClient clones cannot send after retirement.
    // They directly detect the gap identified in codex-heartbeat-pass22-review.md: the reader
    // blocking in read.next() with no wakeup when sig_rx is dropped.

    /// Dropping the mux causes the server to see connection close and retained sig clones to fail
    /// sends — both tasks (reader and writer) exit bounded, independent of retained clone count.
    ///
    /// Lifecycle invariant: owner drop yields server close; sends fail; tasks finish.
    #[tokio::test]
    async fn owner_drop_yields_server_close_sends_fail_tasks_finish() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (close_tx, mut close_rx) = mpsc::unbounded_channel::<()>();

        // Server: accept, drain, signal when connection is closed (EOF or close frame).
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(_) = rx.next().await {}
            let _ = close_tx.send(());
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, sig_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let sig_retained = sig.clone(); // simulates a retained BrokeredSession.sig clone

        let mux = SignalingMux::new_with_interval(sig, sig_rx, None, Duration::from_millis(10));

        // Drop the mux — must retire reader and writer independent of sig_retained.
        drop(mux);

        // Server must see connection close within 2 s (writer exited and sent close frame).
        tokio::time::timeout(Duration::from_secs(2), close_rx.recv())
            .await
            .expect("server must see connection close within 2 s after mux drop")
            .expect("close signal channel closed unexpectedly");

        // Retained clone's send must fail after retirement.
        let send_result = sig_retained.send(ClientToServer::Heartbeat { device: did() });
        assert!(
            send_result.is_err(),
            "retained sig clone send must fail after mux drop retires the connection"
        );
    }

    /// When the peer closes the connection (server EOF), the reader exits, the dispatch cascade
    /// calls cancel(), and the writer exits — accept() returns None and sends fail.
    ///
    /// Lifecycle invariant: peer EOF retires reader and writer.
    #[tokio::test]
    async fn peer_eof_retires_reader_and_writer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server: accept and immediately drop the WebSocket (server-side EOF).
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(tokio_tungstenite::accept_async(tcp).await.unwrap());
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, sig_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let sig_retained = sig.clone();

        let mut mux = SignalingMux::new_with_interval(sig, sig_rx, None, Duration::from_millis(10));

        // Dispatch exits when reader sees EOF and drops in_tx → sig_rx EOF → dispatch exits.
        // accept() returns None when dispatch drops new_session_tx.
        let accepted = tokio::time::timeout(Duration::from_secs(2), mux.accept())
            .await
            .expect("accept must return within 2 s on peer EOF (dispatch must exit)");
        assert!(accepted.is_none(), "accept must return None when peer closes connection");

        // After dispatch exit calls sig.cancel(), sends must fail.
        // Allow a brief moment for the cancel cascade to propagate.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let send_result = sig_retained.send(ClientToServer::Heartbeat { device: did() });
        assert!(
            send_result.is_err(),
            "sends must fail after peer EOF retires the connection via dispatch cancel cascade"
        );
    }

    /// When the server sends Rejected, dispatch exits and calls cancel() — the WebSocket reader
    /// and writer tasks exit bounded. The server sees the connection close.
    ///
    /// Lifecycle invariant: mux rejection retires reader and writer.
    #[tokio::test]
    async fn mux_rejection_retires_reader_and_writer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (close_tx, mut close_rx) = mpsc::unbounded_channel::<()>();

        // Server: hold the connection alive until the client closes it.
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            while let Some(_) = rx.next().await {}
            let _ = close_tx.send(());
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (sig, _real_rx) = rmt_transport_webrtc::SignalingClient::connect(&url).await.unwrap();
        let sig_retained = sig.clone();

        // Use a synthetic inbound channel so we can inject Rejected independently of the socket.
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();
        let mut mux = SignalingMux::new_with_interval(sig, inbound_rx, None, Duration::from_millis(10));

        // Inject Rejected — dispatch breaks its loop and calls sig.cancel().
        inbound_tx.send(ServerToClient::Rejected { reason: "test-rejection".into() }).unwrap();

        // Dispatch exits → accept returns None.
        let accepted = tokio::time::timeout(Duration::from_secs(2), mux.accept())
            .await
            .expect("accept must return within 2 s after Rejected");
        assert!(accepted.is_none(), "accept must return None after server Rejected");

        // Server must see connection close (writer exited after dispatch called cancel()).
        tokio::time::timeout(Duration::from_secs(2), close_rx.recv())
            .await
            .expect("server must see connection close within 2 s after Rejected")
            .expect("close signal channel closed unexpectedly");

        // Sends on retained clones must fail.
        let send_result = sig_retained.send(ClientToServer::Heartbeat { device: did() });
        assert!(
            send_result.is_err(),
            "sends must fail after Rejected retires the connection"
        );
    }

    // docs/65: a relayed directive reaches the hub through the mux, and the hub's signed ack leaves on the SAME connection.
    #[tokio::test]
    async fn a_relayed_directive_is_accepted_and_its_signed_ack_goes_out_on_the_connection() {
        use crate::directive::testkit::{mint, rig, DIRECTIVE_ID};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, mut frames) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_writer, mut reader) = ws.split();
            while let Some(Ok(frame)) = reader.next().await {
                if let Ok(text) = frame.into_text() {
                    let _ = frames_tx.send(text.to_string());
                }
            }
        });
        let (sig, _rx) = SignalingClient::connect(&format!("ws://127.0.0.1:{port}")).await.unwrap();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let r = rig();
        let store = r.store.clone();
        let hub = crate::directive_hub::DirectiveHub::new(r.engine);
        let _mux = SignalingMux::new_with_directives(sig, inbound_rx, None, None, &[], Some(hub.clone()));
        inbound_tx
            .send(ServerToClient::Directive { directive_id: DIRECTIVE_ID.into(), artifact: mint("reinstall", DIRECTIVE_ID) })
            .unwrap();
        // The mux only QUEUES the directive (bounded ingress); the pump verifies and persists it (the production pump task does this
        // on its own timer). Pump until the mux has dispatched it.
        for _ in 0..100 {
            let h = hub.clone();
            tokio::task::spawn_blocking(move || h.pump()).await.unwrap();
            if store.get(DIRECTIVE_ID).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(store.get(DIRECTIVE_ID).is_some(), "the directive was verified and persisted");
        let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv()).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "directive_ack");
        assert_eq!((v["from"].as_str(), v["to"].as_str()), (Some("issued"), Some("accepted")));
        assert_eq!(v["directive_id"], DIRECTIVE_ID);
        assert!(v.get("device_id").is_none(), "signaling takes the device from the connection, never from the message");
    }

    #[tokio::test]
    async fn a_directive_without_a_hub_is_ignored_and_changes_nothing() {
        use crate::directive::testkit::{mint, DIRECTIVE_ID};
        let (reports, features) = (rmt_agent_core::guest_end::GuestEndShared::new(), Vec::<String>::new());
        let (mut mux, tx, _frames) = reporting_mux(reports, features).await;
        tx.send(ServerToClient::Directive { directive_id: DIRECTIVE_ID.into(), artifact: mint("uninstall", DIRECTIVE_ID) }).unwrap();
        tx.send(ServerToClient::DirectiveAckResult { directive_id: DIRECTIVE_ID.into(), outcome: "applied".into(), from: None, to: None, ts_ms: None }).unwrap();
        dispatch_barrier(&mut mux, &tx).await; // the mux is still serving after both
    }

    // ── Security audit 2026-11-01 #8: the pre-registration buffer is bounded ───────────────────────

    fn sdp_for(session: SessionId, len: usize) -> ServerToClient {
        ServerToClient::Sdp { session, sdp: "x".repeat(len), kind: rmt_protocol::signaling::SdpKind::Offer }
    }

    fn cand_for(session: SessionId) -> ServerToClient {
        ServerToClient::Candidate {
            session,
            candidate: rmt_protocol::signaling::Candidate { addr: "1.2.3.4:5".into(), kind: CandidateKind::Host },
        }
    }

    /// One session flooding tiny messages cannot buffer more than its message budget, and is then poisoned.
    #[test]
    fn a_message_flood_for_one_session_is_bounded_and_poisons_it() {
        let mut buf = PreBrokered::default();
        let (s, now) = (sid(), Instant::now());
        let mut accepted = 0;
        for _ in 0..100_000 {
            if buf.push(s, cand_for(s), now).is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, PRE_BROKERED_MAX_MESSAGES, "exactly the per-session budget is accepted");
        assert!(buf.is_poisoned(&s), "overflow poisons the session");
        assert!(buf.entries.get(&s).is_none(), "the overflowing buffer is discarded, not kept");
        assert_eq!(buf.total_bytes, 0);
        assert_eq!(buf.push(s, cand_for(s), now), Err(PreBrokeredDrop::Poisoned));
    }

    /// One huge message (or a few) cannot exceed the per-session byte budget.
    #[test]
    fn a_byte_flood_for_one_session_is_bounded() {
        let mut buf = PreBrokered::default();
        let (s, now) = (sid(), Instant::now());
        let mut kept = 0usize;
        for _ in 0..1000 {
            match buf.push(s, sdp_for(s, 100 * 1024), now) {
                Ok(()) => kept += 1,
                Err(_) => break,
            }
            assert!(buf.total_bytes <= PRE_BROKERED_MAX_SESSION_BYTES);
        }
        assert!(kept >= 1 && kept < 4, "a couple of 100 KiB messages fit, then the byte budget trips (kept {kept})");
        assert!(buf.is_poisoned(&s));
        assert_eq!(buf.total_bytes, 0);
        // A single message larger than the whole session budget is refused outright.
        let big = sid();
        assert_eq!(buf.push(big, sdp_for(big, 10 * 1024 * 1024), now), Err(PreBrokeredDrop::SessionOverflow));
        assert_eq!(buf.total_bytes, 0);
    }

    /// A flood of DISTINCT session ids is bounded by the session table and the shared byte budget.
    #[test]
    fn a_flood_of_distinct_sessions_is_bounded_in_count_and_total_bytes() {
        let mut buf = PreBrokered::default();
        let now = Instant::now();
        for _ in 0..10_000 {
            let s = sid();
            let _ = buf.push(s, cand_for(s), now);
            assert!(buf.entries.len() <= PRE_BROKERED_MAX_SESSIONS);
        }
        assert_eq!(buf.entries.len(), PRE_BROKERED_MAX_SESSIONS);
        assert!(buf.poisoned.len() <= PRE_BROKERED_MAX_SESSIONS);

        // Large buffers across many sessions hit the shared byte budget long before the table.
        let mut buf = PreBrokered::default();
        for _ in 0..1000 {
            let s = sid();
            let _ = buf.push(s, sdp_for(s, 200 * 1024), now);
            assert!(buf.total_bytes <= PRE_BROKERED_MAX_TOTAL_BYTES);
        }
        assert!(buf.entries.len() < PRE_BROKERED_MAX_SESSIONS, "the byte budget, not the table, was the limit");
        assert!(buf.total_bytes > 0);
    }

    /// The legitimate shape (IceServers, RelayAssignment before Brokered) is untouched, in order, and frees its bytes.
    #[test]
    fn a_normal_rendezvous_is_buffered_in_order_and_released() {
        let mut buf = PreBrokered::default();
        let (s, now) = (sid(), Instant::now());
        buf.push(s, ServerToClient::IceServers { session: s, servers: vec![] }, now).unwrap();
        buf.push(s, cand_for(s), now).unwrap();
        assert!(buf.total_bytes > 0);
        let got = buf.take(&s);
        assert_eq!(got.len(), 2);
        assert!(matches!(got[0], ServerToClient::IceServers { .. }));
        assert_eq!(buf.total_bytes, 0);
        assert!(buf.entries.is_empty());
    }

    /// A session that never gets its Brokered stops holding a slot (and a poisoned id stops being refused).
    #[test]
    fn stale_entries_and_poison_expire() {
        let mut buf = PreBrokered::default();
        let t0 = Instant::now();
        let stale = sid();
        buf.push(stale, cand_for(stale), t0).unwrap();
        let hog = sid();
        for _ in 0..=PRE_BROKERED_MAX_MESSAGES {
            let _ = buf.push(hog, cand_for(hog), t0);
        }
        assert!(buf.is_poisoned(&hog));
        let later = t0 + PRE_BROKERED_TTL + Duration::from_secs(1);
        let fresh = sid();
        buf.push(fresh, cand_for(fresh), later).unwrap();
        assert!(buf.entries.get(&stale).is_none(), "the stale entry was dropped");
        assert!(!buf.is_poisoned(&hog), "the poison lapsed");
        assert_eq!(buf.entries.len(), 1);
    }

    /// End to end through the dispatch task: a flooded session is refused at Brokered, a normal one still works,
    /// and nothing the flood buffered reaches a session.
    #[tokio::test]
    async fn a_flooded_session_is_refused_at_brokered_and_a_normal_one_still_works() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (new_tx, mut new_rx) = mpsc::channel::<BrokeredSession>(8);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<ServerToClient>();
        let port = loopback_accept_and_hold().await;
        let (sig, _rx) = rmt_transport_webrtc::SignalingClient::connect(&format!("ws://127.0.0.1:{port}")).await.unwrap();
        tokio::spawn(dispatch_task(inbound_rx, sig, new_tx, Arc::clone(&sessions)));

        let hostile = sid();
        for _ in 0..(PRE_BROKERED_MAX_MESSAGES * 10) {
            inbound_tx.send(cand_for(hostile)).unwrap();
        }
        let brokered = |session| ServerToClient::Brokered {
            session, peer_device: None, peer_pubkey: "p".into(),
            control_plane_session: None, technician_id: None, access: None, access_version: None,
        };
        inbound_tx.send(brokered(hostile)).unwrap();
        let good = sid();
        inbound_tx.send(ServerToClient::IceServers { session: good, servers: vec![] }).unwrap();
        inbound_tx.send(brokered(good)).unwrap();
        let bs = tokio::time::timeout(Duration::from_secs(2), new_rx.recv()).await.unwrap().unwrap();
        assert_eq!(bs.session, good, "the flooded session was refused; the next normal one is the first delivered");
        assert!(!sessions.lock().unwrap().contains_key(&hostile));
    }

    // ── docs/64 H3: the help hub rides the mux connection ──────────────────────────────────────────

    async fn help_mux(features: Vec<String>) -> (
        SignalingMux,
        mpsc::UnboundedSender<ServerToClient>,
        mpsc::UnboundedReceiver<String>,
        Arc<crate::help_request::HelpHub>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (frames_tx, frames_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let (_writer, mut reader) = ws.split();
            while let Some(Ok(frame)) = reader.next().await {
                if let Ok(text) = frame.into_text() {
                    let _ = frames_tx.send(text.to_string());
                }
            }
        });
        let (sig, _rx) = SignalingClient::connect(&format!("ws://127.0.0.1:{port}")).await.unwrap();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let hub = crate::help_request::HelpHub::new();
        let mux = SignalingMux::new_with_help(sig, inbound_rx, None, None, &features, None, Some(hub.clone()));
        (mux, inbound_tx, frames_rx, hub)
    }

    #[tokio::test]
    async fn a_connection_that_advertised_help_carries_requests_and_their_answers() {
        use crate::help_request::ViewPhase;
        let (mut mux, tx, mut frames, hub) = help_mux(vec![rmt_protocol::signaling::HELP_REQUEST_FEATURE.into()]).await;
        // Attach re-queries the device's open request.
        let first = tokio::time::timeout(Duration::from_secs(2), frames.recv()).await.unwrap().unwrap();
        assert_eq!(first, r#"{"type":"help_status"}"#);
        hub.request("printer", Instant::now()).unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv()).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "help_request");
        assert_eq!(v["note"], "printer");
        let op_id = v["op_id"].as_str().unwrap().to_string();
        tx.send(ServerToClient::HelpRequestResult {
            op: "help_request".into(), op_id, outcome: "ok".into(),
            request: Some(rmt_protocol::signaling::HelpRequestInfo {
                id: "r1".into(), status: "open".into(), note: String::new(), created_at: String::new(), expires_at: String::new(),
            }),
            retry_after_seconds: 0, cancel_of: String::new(),
        }).unwrap();
        dispatch_barrier(&mut mux, &tx).await;
        assert_eq!(hub.view(Instant::now()).phase, ViewPhase::Open, "the mux routed the answer into the hub");
        // The mux ending (connection retired) takes the menu away: nothing can be sent on a dead connection.
        drop(mux);
        assert!(!hub.view(Instant::now()).available);
    }

    /// A RETIRED machine's restricted connection (and an old server) is not told about help_request_v1: the hub must stay
    /// unavailable and put nothing on the wire, because a restricted connection answers an unknown message with Rejected,
    /// which ends the mux.
    #[tokio::test]
    async fn a_connection_without_the_feature_sends_no_help_message() {
        let (mut mux, tx, mut frames, hub) = help_mux(vec!["session_ended_v1".into()]).await;
        assert!(!hub.view(Instant::now()).available);
        assert_eq!(hub.request("x", Instant::now()), Err(crate::help_request::RequestError::NotAvailable));
        assert_eq!(hub.cancel("r1", Instant::now()), Err(crate::help_request::CancelError::NotAvailable));
        hub.tick(Instant::now() + Duration::from_secs(3600));
        // An answer that nobody asked for changes nothing.
        tx.send(ServerToClient::HelpRequestResult {
            op: "help_status".into(), op_id: String::new(), outcome: "ok".into(), request: None, retry_after_seconds: 0, cancel_of: String::new(),
        }).unwrap();
        dispatch_barrier(&mut mux, &tx).await;
        assert!(tokio::time::timeout(Duration::from_millis(300), frames.recv()).await.is_err(), "no frame may leave");
    }
}
