//! Minimal WebSocket client for the Go rendezvous/signaling server. Speaks the shared
//! `rmt_protocol::signaling` message set (JSON, `type`-tagged). Low-volume control plane, so it
//! uses unbounded channels and background reader/writer tasks; the transport awaits `ServerToClient`
//! messages on the returned receiver and pushes `ClientToServer` messages via [`SignalingClient::send`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rmt_protocol::signaling::{ClientToServer, ServerToClient};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
use tokio_tungstenite::tungstenite::Message;

/// Keepalive (1.3.1). The client sends a numbered ping every PING_EVERY; the signaling server
/// (gorilla/websocket, default ping handler) answers with a pong echoing that number from inside its
/// read loop for THIS connection. Only such an echo counts as liveness: other inbound traffic proves
/// the server can write, not that it is reading what the client sends. A watchdog task, independent
/// of the writer (whose sends can block), retires the connection once no matching pong has arrived
/// for PONG_DEADLINE, so a half-open, backpressured or read-stalled connection ends within
/// PONG_DEADLINE + PING_EVERY and its owner reconnects. Consumers that need proof of a live
/// connection use [`SignalingClient::pong_age`].
pub const PING_EVERY: Duration = Duration::from_secs(20);
pub const PONG_DEADLINE: Duration = Duration::from_secs(60);

/// Probe bookkeeping shared by the writer (sends probes), reader (matches echoes) and watchdog.
/// Times are milliseconds since `epoch`; the handshake counts as the first proof.
struct Liveness {
    epoch: Instant,
    deadline: Duration,
    /// Number of the last probe reserved for sending (0 = none yet). Reserved before the write so
    /// a fast echo is never mistaken for an unsent probe.
    sent: AtomicU64,
    /// Highest probe number echoed back.
    echoed: AtomicU64,
    last_pong_ms: AtomicU64,
}

impl Liveness {
    fn new(deadline: Duration) -> Self {
        Self {
            epoch: Instant::now(),
            deadline,
            sent: AtomicU64::new(0),
            echoed: AtomicU64::new(0),
            last_pong_ms: AtomicU64::new(0),
        }
    }
    /// Reserve the next probe number and its 8-byte payload.
    fn next_probe(&self) -> Vec<u8> {
        (self.sent.fetch_add(1, Ordering::SeqCst) + 1).to_be_bytes().to_vec()
    }
    /// A pong counts only when it echoes a probe this connection sent and has not been echoed yet.
    fn on_pong(&self, payload: &[u8]) -> bool {
        let Ok(bytes) = <[u8; 8]>::try_from(payload) else { return false };
        let n = u64::from_be_bytes(bytes);
        if n == 0 || n > self.sent.load(Ordering::SeqCst) || self.echoed.fetch_max(n, Ordering::SeqCst) >= n {
            return false;
        }
        let ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_pong_ms.fetch_max(ms, Ordering::SeqCst);
        true
    }
    fn pong_age(&self) -> Duration {
        let last = Duration::from_millis(self.last_pong_ms.load(Ordering::SeqCst));
        self.epoch.elapsed().saturating_sub(last)
    }
    /// The absolute instant the current evidence stops counting: last matched echo (or the
    /// handshake) plus the deadline. It does not move while nothing new is echoed, so a caller that
    /// is delayed after reading it cannot stretch it.
    fn proof_expiry(&self) -> Instant {
        self.epoch + Duration::from_millis(self.last_pong_ms.load(Ordering::SeqCst)) + self.deadline
    }
}

/// Ping settings for [`run_writer`].
struct Pinger {
    every: Duration,
    liveness: Arc<Liveness>,
}

/// Retires the connection (shared cancel) once `liveness` has no matching pong for `deadline`,
/// checked every `every`. Runs apart from the writer so a blocked socket write cannot stop it.
async fn run_watchdog(
    liveness: Arc<Liveness>,
    every: Duration,
    deadline: Duration,
    cancel_tx: Arc<watch::Sender<bool>>,
) {
    let mut cancel_rx = cancel_tx.subscribe();
    // Already retired before this task first ran: a fresh subscription would never see the change.
    if *cancel_rx.borrow_and_update() {
        return;
    }
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => break,
            _ = tick.tick() => {
                if liveness.pong_age() > deadline {
                    let _ = cancel_tx.send(true);
                    break;
                }
            }
        }
    }
}

/// Inner writer loop: drives `sink` from `out_rx`, selecting cancellation at every await so an
/// in-flight write cannot outlive the connection owner. The best-effort close frame is bounded by
/// a short timeout; if the peer is not consuming data, the sink is dropped without completing the
/// handshake rather than blocking indefinitely.
///
/// Extracted as a named function so tests can inject a non-cooperative sink.
async fn run_writer<S>(
    mut sink: S,
    mut out_rx: mpsc::UnboundedReceiver<ClientToServer>,
    mut cancel_rx: watch::Receiver<bool>,
    pinger: Option<Pinger>,
) where
    S: SinkExt<Message> + Unpin,
{
    // With no pinger the tick is a full day away and never acted on.
    let every = pinger.as_ref().map_or(Duration::from_secs(86_400), |p| p.every);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => break,
            _ = ping.tick(), if pinger.is_some() => {
                let Some(p) = pinger.as_ref() else { continue };
                // The deadline is enforced by run_watchdog, not here: this send can block.
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    result = sink.send(Message::Ping(p.liveness.next_probe())) => {
                        if result.is_err() { break; }
                    }
                }
            }
            item = out_rx.recv() => {
                match item {
                    Some(msg) => {
                        let Ok(json) = serde_json::to_string(&msg) else { continue };
                        // Inner select: cancel can interrupt the write itself, not just the
                        // wait-for-next-message. Without this, a backpressured peer keeps
                        // the writer alive indefinitely after cancel().
                        tokio::select! {
                            biased;
                            _ = cancel_rx.changed() => break,
                            result = sink.send(Message::Text(json)) => {
                                if result.is_err() { break; }
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }
    // Best-effort Normal Closure (1000). Bounded so a non-reading peer cannot stall exit.
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        sink.send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        }))),
    )
    .await;
}

/// A connected signaling client. Cheap to clone (just the outbound sender + shared cancel token),
/// so it can be shared into webrtc callbacks that need to trickle candidates.
///
/// The connection is owned by whoever holds the `SignalingMux` (or by the single-session
/// `connect_inner` path). When the owner retires the connection — by calling [`cancel`] — the
/// background reader and writer tasks exit bounded even if other clones are still alive. Sends on
/// retained clones fail immediately after cancellation.
#[derive(Clone)]
pub struct SignalingClient {
    out_tx: mpsc::UnboundedSender<ClientToServer>,
    liveness: Arc<Liveness>,
    /// Shared cancellation sender. Cancelling any clone cancels the connection. After the first
    /// `cancel()` call the reader and writer tasks exit at their next `await` point, and all
    /// subsequent `send()` calls return an error immediately without touching the socket.
    cancel_tx: Arc<watch::Sender<bool>>,
    /// The local address of this connection's TCP socket: the interface the OS actually routes to the
    /// signaling server through. ICE limits its host candidates to it (see `ice_route_ip`).
    local_ip: Option<std::net::IpAddr>,
}

fn socket_local_ip(stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>) -> Option<std::net::IpAddr> {
    match stream {
        tokio_tungstenite::MaybeTlsStream::Plain(s) => s.local_addr().ok().map(|a| a.ip()),
        tokio_tungstenite::MaybeTlsStream::Rustls(s) => s.get_ref().0.local_addr().ok().map(|a| a.ip()),
        _ => None,
    }
}

impl SignalingClient {
    /// Connect to the signaling server at `url` (e.g. `ws://127.0.0.1:8080/ws`). Returns the
    /// client plus a receiver of inbound server messages.
    pub async fn connect(
        url: &str,
    ) -> Result<(Self, mpsc::UnboundedReceiver<ServerToClient>), String> {
        Self::connect_with_keepalive(url, PING_EVERY, PONG_DEADLINE).await
    }

    /// [`connect`](Self::connect) with explicit keepalive timing (tests use short values).
    async fn connect_with_keepalive(
        url: &str,
        ping_every: Duration,
        pong_deadline: Duration,
    ) -> Result<(Self, mpsc::UnboundedReceiver<ServerToClient>), String> {
        // Trust roots come from `tls_trust` (OS store UNION bundled public roots), not from the
        // tokio-tungstenite feature. The connector only applies to `wss://`; `ws://` stays plain.
        let tls = Connector::Rustls(Arc::new(crate::tls_trust::client_config()?));
        let (ws, _resp) = connect_async_tls_with_config(url, None, false, Some(tls))
            .await
            .map_err(|e| e.to_string())?;
        let local_ip = socket_local_ip(ws.get_ref());
        let (write, mut read) = ws.split();

        let (out_tx, out_rx) = mpsc::unbounded_channel::<ClientToServer>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerToClient>();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let cancel_tx = Arc::new(cancel_tx);
        let liveness = Arc::new(Liveness::new(pong_deadline));

        // Writer task: see run_writer for cancellation, pings and bounded-close semantics. Whatever
        // ends it also retires the connection, so the reader and retained clones see it at once.
        let cancel_rx_w = cancel_rx.clone();
        let pinger = Pinger { every: ping_every, liveness: Arc::clone(&liveness) };
        let cancel_tx_w = Arc::clone(&cancel_tx);
        tokio::spawn(async move {
            run_writer(write, out_rx, cancel_rx_w, Some(pinger)).await;
            let _ = cancel_tx_w.send(true);
        });

        // Watchdog: retires the connection when probes stop being echoed (see PONG_DEADLINE).
        tokio::spawn(run_watchdog(Arc::clone(&liveness), ping_every, pong_deadline, Arc::clone(&cancel_tx)));

        // Reader task: decode inbound server messages and forward them. Exits when the socket
        // closes (EOF or Close frame), when the inbound channel is full/closed, or when the
        // connection owner calls cancel(); its exit also retires the connection.
        let mut cancel_rx_r = cancel_rx;
        let liveness_r = Arc::clone(&liveness);
        let cancel_tx_r = Arc::clone(&cancel_tx);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx_r.changed() => break,
                    item = read.next() => {
                        match item {
                            Some(Ok(msg)) => {
                                let text = match msg {
                                    Message::Text(t) => t,
                                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                                    Message::Close(_) => break,
                                    // Only an echo of one of our probes is liveness evidence.
                                    Message::Pong(payload) => { liveness_r.on_pong(&payload); continue }
                                    _ => continue,
                                };
                                match serde_json::from_str::<ServerToClient>(&text) {
                                    Ok(s2c) => {
                                        if in_tx.send(s2c).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => continue,
                                }
                            }
                            _ => break, // None (EOF) or Err (socket error)
                        }
                    }
                }
            }
            let _ = cancel_tx_r.send(true);
        });

        Ok((Self { out_tx, liveness, cancel_tx, local_ip }, in_rx))
    }

    /// The local IP this connection reaches the signaling server from, when it is routable (not
    /// loopback or unspecified). A dual-homed machine (2026-11-12: Wi-Fi plus a datacenter LAN)
    /// connected but never carried video while both interfaces were up; each interface alone worked.
    /// The exact cause is unproven (two plain NICs on one subnet work), but offering host candidates
    /// on an interface the server does not route through can only add dead or wrong pairs. ICE is
    /// limited to the interface the OS already routes to us through. Loopback (local dev, e2e) is
    /// never filtered.
    pub fn ice_route_ip(&self) -> Option<std::net::IpAddr> {
        self.local_ip.filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
    }

    /// How long since the server last echoed one of this connection's keepalive probes (or since the
    /// handshake, before the first echo). The connection retires itself once this passes
    /// [`PONG_DEADLINE`]; until then a small value proves the server is reading this connection.
    pub fn pong_age(&self) -> Duration {
        self.liveness.pong_age()
    }

    /// When the current liveness evidence expires (last matched echo, or the handshake, plus
    /// [`PONG_DEADLINE`]). Absolute, so it can be carried to delayed work and re-checked there.
    pub fn proof_expiry(&self) -> Instant {
        self.liveness.proof_expiry()
    }

    /// Signal the background reader and writer tasks to exit, independent of how many `SignalingClient`
    /// clones are still alive. After this call returns, all subsequent `send()` calls on any clone
    /// fail immediately. The writer task sends a WebSocket close frame before exiting.
    ///
    /// Idempotent: calling `cancel()` more than once is harmless.
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Queue a message to the signaling server. Fails if the connection is gone OR if the
    /// connection has been cancelled (via [`cancel`]) even if the writer channel is still open.
    pub fn send(&self, msg: ClientToServer) -> Result<(), String> {
        if *self.cancel_tx.borrow() {
            return Err("signaling connection closed".to_string());
        }
        self.out_tx
            .send(msg)
            .map_err(|_| "signaling connection closed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{Sink, StreamExt};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, watch};
    use tokio_tungstenite::{
        accept_async,
        tungstenite::{
            protocol::{frame::coding::CloseCode, CloseFrame},
            Message,
        },
    };

    /// Sink that never becomes ready. Simulates a peer that has stopped consuming data
    /// (backpressure / blocked write). Used to prove cancel() and bounded-close semantics
    /// without requiring a real peer.
    struct NeverReadySink;

    /// Sink that signals once via a oneshot when `poll_ready` is first called, then stays
    /// Pending forever. Used by `cancel_unblocks_in_flight_text_write` to establish an explicit
    /// handshake: the test waits for the signal before calling `cancel_tx.send(true)`, so the
    /// cancel always arrives while the writer is demonstrably blocked inside the inner select —
    /// not just hoped-so after a single yield_now().
    struct SignalOnReadySink {
        signaled: bool,
        ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl Sink<Message> for NeverReadySink {
        type Error = std::convert::Infallible;

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            unreachable!("poll_ready never returns Ready")
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    impl Sink<Message> for SignalOnReadySink {
        type Error = std::convert::Infallible;

        fn poll_ready(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if !self.signaled {
                self.signaled = true;
                if let Some(tx) = self.ready_tx.take() {
                    let _ = tx.send(());
                }
            }
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            unreachable!("poll_ready never returns Ready")
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    /// A server that keeps reading answers the client's pings (tungstenite, like gorilla, replies
    /// from its read loop), so inbound_age stays small and the connection stays up past the deadline.
    #[tokio::test]
    async fn keepalive_pongs_keep_a_reading_server_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(tcp).await.unwrap();
            // Reading drives the automatic pong replies.
            while let Some(Ok(_)) = ws.next().await {}
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (client, _rx) = SignalingClient::connect_with_keepalive(
            &url, Duration::from_millis(50), Duration::from_millis(300)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(client.pong_age() < Duration::from_millis(300), "pongs refresh liveness: {:?}", client.pong_age());
        assert!(client.send(rmt_protocol::signaling::ClientToServer::Heartbeat {
            device: rmt_protocol::DeviceId(uuid::Uuid::nil()) }).is_ok(), "still connected");
    }

    /// A server that stops reading (accepted, never polls the socket) never pongs: the client
    /// retires the connection on its own within deadline + ping interval, so its owner reconnects.
    #[tokio::test]
    async fn keepalive_retires_a_silent_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.unwrap();
            let _ = hold_rx.await; // hold the socket open without ever reading it
            drop(ws);
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (client, mut rx) = SignalingClient::connect_with_keepalive(
            &url, Duration::from_millis(50), Duration::from_millis(300)).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await;
        assert!(matches!(ended, Ok(None)), "reader must end after the silence deadline: {ended:?}");
        assert!(client.pong_age() > Duration::from_millis(300));
        assert!(client.send(rmt_protocol::signaling::ClientToServer::Heartbeat {
            device: rmt_protocol::DeviceId(uuid::Uuid::nil()) }).is_err(), "connection retired");
        let _ = hold_tx.send(());
    }

    /// A server that keeps WRITING application messages but has stopped reading never answers a
    /// probe: inbound traffic alone is not liveness, and the connection is still retired.
    #[tokio::test]
    async fn keepalive_retires_a_server_that_writes_but_never_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.unwrap();
            let (mut tx, _never_read) = ws.split();
            let msg = serde_json::to_string(&rmt_protocol::signaling::ServerToClient::Rejected {
                reason: "x".into() }).unwrap();
            loop {
                if tx.send(Message::Text(msg.clone())).await.is_err() { break; }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        });
        let url = format!("ws://127.0.0.1:{port}");
        let (client, mut rx) = SignalingClient::connect_with_keepalive(
            &url, Duration::from_millis(50), Duration::from_millis(300)).await.unwrap();
        let mut got_text = false;
        let ended = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(_m) = rx.recv().await { got_text = true; }
        }).await;
        assert!(got_text, "the server's application traffic did arrive");
        assert!(ended.is_ok(), "reader must end although the server keeps writing");
        assert!(client.pong_age() > Duration::from_millis(300));
    }

    /// The watchdog retires the connection even while the writer is stuck in a send that never
    /// completes (a backpressured socket), with no external cancel().
    #[tokio::test]
    async fn watchdog_retires_despite_a_permanently_blocked_writer() {
        let liveness = Arc::new(Liveness::new(Duration::from_millis(150)));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let cancel_tx = Arc::new(cancel_tx);
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<ClientToServer>();
        let writer = tokio::spawn(run_writer(
            NeverReadySink, out_rx, cancel_rx,
            Some(Pinger { every: Duration::from_millis(20), liveness: Arc::clone(&liveness) })));
        tokio::spawn(run_watchdog(Arc::clone(&liveness), Duration::from_millis(20),
            Duration::from_millis(150), Arc::clone(&cancel_tx)));
        let done = tokio::time::timeout(Duration::from_secs(2), writer).await;
        assert!(done.is_ok(), "blocked writer must exit once the watchdog retires the connection");
        assert!(*cancel_tx.borrow(), "the watchdog published the shared cancel");
    }

    /// The proof expiry is absolute: it does not drift while time passes without a new echo, and a
    /// matched echo moves it to (echo time + deadline).
    #[test]
    fn proof_expiry_is_absolute_and_moves_only_on_a_matched_echo() {
        let l = Liveness::new(Duration::from_millis(500));
        let first = l.proof_expiry();
        assert!(first >= l.epoch + Duration::from_millis(500) && first <= l.epoch + Duration::from_millis(501));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(l.proof_expiry(), first, "a pause does not stretch the evidence");
        let p = l.next_probe();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(l.proof_expiry(), first, "sending a probe is not evidence");
        assert!(l.on_pong(&p));
        assert!(l.proof_expiry() >= first + Duration::from_millis(30), "a matched echo renews it");
    }

    /// A connection retired before the watchdog task first runs: the watchdog must notice the
    /// already-published cancel at once instead of lingering until its own deadline.
    #[tokio::test]
    async fn watchdog_exits_at_once_when_already_retired() {
        let liveness = Arc::new(Liveness::new(Duration::from_secs(3600)));
        let (cancel_tx, _rx) = watch::channel(false);
        let cancel_tx = Arc::new(cancel_tx);
        let _ = cancel_tx.send(true);
        let done = tokio::time::timeout(
            Duration::from_millis(200),
            run_watchdog(liveness, Duration::from_secs(3600), Duration::from_secs(3600), cancel_tx),
        )
        .await;
        assert!(done.is_ok(), "watchdog must return immediately for an already-retired connection");
    }

    /// Only an echo of a probe this connection sent, not yet echoed, counts.
    #[test]
    fn pong_must_echo_an_outstanding_probe() {
        let l = Liveness::new(Duration::from_secs(60));
        assert!(!l.on_pong(&1u64.to_be_bytes()), "nothing sent yet");
        let p1 = l.next_probe();
        let p2 = l.next_probe();
        assert!(!l.on_pong(&[]), "empty payload is not an echo");
        assert!(!l.on_pong(&9u64.to_be_bytes()), "a probe never sent");
        assert!(l.on_pong(&p2), "latest probe echoed");
        assert!(!l.on_pong(&p1), "an older probe after a newer echo does not count");
        assert!(!l.on_pong(&p2), "a repeated echo does not count");
        assert!(!l.on_pong(&0u64.to_be_bytes()), "zero is never a probe");
    }

    /// Dropping a [`SignalingClient`] must send a WebSocket close frame with code 1000 (Normal
    /// Closure) before the underlying TCP connection closes.
    ///
    /// **Why this matters:** the agent's idle re-registration path drops the client every ~20 s.
    /// Without the close frame the server receives a bare TCP close, which the WebSocket layer
    /// logs as 1006 (Abnormal Closure) — the same code a real transport failure produces. A
    /// reader seeing 1006 on every idle window cannot tell intent from fault.
    ///
    /// **Mutation target (two ways to break this test):**
    /// 1. Remove the `write.send(Message::Close(...))` line → server's `saw_close` stays false.
    /// 2. Change `CloseCode::Normal` to `None` → server receives code 1005 (NoStatusReceived),
    ///    not 1000; the `cf.code == CloseCode::Normal` arm does not match.
    #[tokio::test]
    async fn drop_sends_close_frame() {
        // Bind a local WebSocket server on an OS-assigned port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task: accept the connection and wait for either a close frame or EOF.
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            let mut saw_normal_close = false;
            while let Some(msg) = rx.next().await {
                if let Ok(Message::Close(Some(CloseFrame { code, .. }))) = msg {
                    if code == CloseCode::Normal {
                        saw_normal_close = true;
                        break;
                    }
                }
            }
            saw_normal_close
        });

        let url = format!("ws://127.0.0.1:{}", addr.port());
        let (client, _rx) = SignalingClient::connect(&url).await.unwrap();

        // Dropping `client` drops `out_tx`; the writer task detects the closed channel and
        // sends the close frame. The server receives it and exits with `saw_normal_close = true`.
        drop(client);

        let saw_normal_close = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server task must complete within 5 s after client drop")
            .expect("server task must not panic");
        assert!(
            saw_normal_close,
            "dropping SignalingClient must send a WebSocket close frame with code 1000 \
             (Normal Closure) so the signaling server does not log 1006 (Abnormal Closure)"
        );
    }

    /// Calling `cancel()` on any clone retires the connection: the writer exits and sends a close
    /// frame; subsequent `send()` calls fail immediately on all clones.
    #[tokio::test]
    async fn cancel_retires_connection_sends_close_frame_and_fails_sends() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (close_tx, mut close_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = accept_async(tcp).await.unwrap();
            let (_, mut rx) = ws.split();
            let mut saw_normal_close = false;
            while let Some(msg) = rx.next().await {
                if let Ok(Message::Close(Some(CloseFrame { code, .. }))) = msg {
                    if code == CloseCode::Normal {
                        saw_normal_close = true;
                        break;
                    }
                }
            }
            let _ = close_tx.send(saw_normal_close);
        });

        let url = format!("ws://127.0.0.1:{port}");
        let (client, _rx) = SignalingClient::connect(&url).await.unwrap();
        let clone = client.clone();

        // Cancel via the original; send via the clone must fail immediately.
        client.cancel();
        let send_result = clone.send(rmt_protocol::signaling::ClientToServer::Heartbeat {
            device: rmt_protocol::DeviceId(uuid::Uuid::new_v4()),
        });
        assert!(send_result.is_err(), "send must fail after cancel()");

        // Server must see the close frame within 2 s.
        let saw_close = tokio::time::timeout(Duration::from_secs(2), close_rx.recv())
            .await
            .expect("server must receive close frame within 2 s after cancel()")
            .expect("close channel closed unexpectedly");
        assert!(saw_close, "cancel() must cause writer to send a Normal Closure close frame");
    }

    /// cancel() must retire run_writer even while a Text write is in-flight against a
    /// backpressured sink. The outer biased select cannot interrupt a nested .await; the inner
    /// select is required. Without it a non-reading peer would keep the writer alive indefinitely.
    ///
    /// Mutation targets:
    /// 1. Remove inner select, replace with plain `.await` → task never completes (timeout fires).
    /// 2. Remove the `biased;` from the inner select → possible livelock on a cooperative sink
    ///    (not observable here, but cancel arm no longer wins the race deterministically).
    ///
    /// Sink-entry handshake: `SignalOnReadySink` fires a oneshot the moment `poll_ready` is
    /// first invoked by the writer — proving the write is in-flight before cancel() fires.
    /// The prior `yield_now()` approach was racy: the scheduler could resume the test future
    /// before the writer task ran even once.
    #[tokio::test]
    async fn cancel_unblocks_in_flight_text_write() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<ClientToServer>();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

        // Pre-queue a message so the writer immediately enters the in-flight write branch.
        out_tx
            .send(ClientToServer::Heartbeat {
                device: rmt_protocol::DeviceId(uuid::Uuid::new_v4()),
            })
            .unwrap();

        let sink = SignalOnReadySink { signaled: false, ready_tx: Some(ready_tx) };
        let task = tokio::spawn(run_writer(sink, out_rx, cancel_rx, None));

        // Explicit sink-entry handshake: wait until poll_ready has been called, proving the
        // writer is parked inside the inner select before cancel() arrives.
        tokio::time::timeout(Duration::from_millis(500), ready_rx)
            .await
            .expect("SignalOnReadySink must receive poll_ready within 500 ms — writer must enter in-flight branch")
            .expect("ready channel closed unexpectedly");

        // Cancel — must wake the inner select's cancel arm and retire the writer.
        let _ = cancel_tx.send(true);

        // Assert task completion: writer exits and the task resolves (not just a timeout fire).
        let join_result = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("writer must complete within 500 ms after cancel() with blocked sink");
        assert!(join_result.is_ok(), "writer task must not panic after cancel()");
    }

    /// The best-effort close frame send at the end of run_writer is bounded even when the sink
    /// is permanently blocked. Without the timeout the writer would stall indefinitely after
    /// normal channel-close with a non-reading peer.
    ///
    /// Mutation target: replace `timeout(200ms, ...)` with plain `.await` → task never completes.
    #[tokio::test]
    async fn close_frame_bounded_on_blocked_sink() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (_, out_rx) = mpsc::unbounded_channel::<ClientToServer>();

        // Cancel before spawning: writer exits its outer loop immediately and goes straight to
        // the close-frame send, which NeverReadySink will block.
        let _ = cancel_tx.send(true);

        let task = tokio::spawn(run_writer(NeverReadySink, out_rx, cancel_rx, None));

        // 200 ms timeout inside run_writer + scheduler overhead; outer bound is 500 ms.
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("writer must complete within 500 ms when close frame is blocked by peer")
            .expect("writer task must not panic");
    }
}
