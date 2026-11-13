//! End-to-end **in-session chat** test (M12 deliverable): a controller exchanges chat over a REAL
//! WebRTC session, and the transcript survives a **reconnect** — which is the whole point of the
//! feature and the only part that a codec unit test cannot prove.
//!
//! Modelled on `e2e_multimonitor.rs` / `e2e_quality.rs`: same self-skip, and it runs under
//! `verify-all.ps1`, which treats a SKIP as a FAILURE.
//!
//! # What the second session proves that the first cannot
//!
//! Session 1 sends messages and reads them back. That alone would pass against an agent that kept
//! the transcript in a local variable and threw it away — which is exactly the thing "persistent
//! history" is not. Session 2 is a **fresh transport, a fresh `serve_session_with_ice` call, and a
//! fresh `Transcript` object**, and it must still be able to replay what session 1 said and
//! continue the sequence past it.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_chat -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmt_agent_core::chat::{self, ChatEntry, ChatFrom, ChatMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

struct NoopSink;
impl InputSink for NoopSink {
    fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
        Ok(())
    }
}

fn signaling_url() -> String {
    std::env::var("SIGNALING_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string())
}

async fn signaling_reachable(url: &str) -> bool {
    tokio::time::timeout(Duration::from_millis(800), async {
        tokio_tungstenite::connect_async(url).await.is_ok()
    })
    .await
    .unwrap_or(false)
}

async fn connect_controller(url: &str, device: DeviceId) -> WebRtcTransport {
    // Bounded by ATTEMPTS, not by a wall clock — and that distinction is the whole point.
    //
    // The first version used a 20-second deadline, which looked equivalent and was not:
    // `WebRtcTransport::connect` has its own ~20 s internal timeout, so a single slow attempt
    // consumed the entire budget and the loop retried exactly zero times. It passed when run alone
    // and failed under `verify-all.ps1`, where every e2e binary runs concurrently and ICE is slow
    // enough for one attempt to time out. A retry loop that cannot retry is worse than none: it
    // reads as robust while providing nothing.
    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match WebRtcTransport::connect(url, Role::dev_controller(device)).await {
            Ok(t) => return t,
            Err(e) => {
                eprintln!("connect attempt {attempt}/{ATTEMPTS} to {device} failed: {e}");
                last = e;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!("controller never connected to {device} in {ATTEMPTS} attempts (last error: {last})");
}

async fn send_chat(c: &mut WebRtcTransport, msg: &ChatMessage) {
    c.send_frame(Frame::new(ChannelId::Chat, chat::encode(msg)))
        .await
        .expect("controller send chat frame");
}

/// Await the next decoded `ChannelId::Chat` message, ignoring traffic on other channels.
async fn recv_chat(c: &mut WebRtcTransport, secs: u64) -> Option<ChatMessage> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), c.recv_frame()).await {
            Ok(Ok(f)) if f.channel == ChannelId::Chat => {
                return Some(chat::decode(&f.payload).expect("decode chat reply"));
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// Spawn one agent session against a transfer dir whose PARENT holds the chat transcript.
fn spawn_agent(
    url: String,
    device: DeviceId,
    stop: Arc<AtomicBool>,
    transfer_dir: std::path::PathBuf,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(320, 240, 30);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session_with_ice(
            &url,
            device,
            capturer,
            30,
            stop,
            Vec::new(),
            SessionOptions { sink, transfer_dir, ..Default::default() },
        )
        .await
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chat_round_trips_and_its_history_survives_a_reconnect() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    // A private state dir per run, so the transcript under test is this run's and not a previous
    // one's. `transfer_dir`'s PARENT is where the agent puts chat.jsonl.
    let root = std::env::temp_dir().join(format!("rmt_chat_e2e_{}", uuid::Uuid::new_v4()));
    let transfer_dir = root.join("transfers");
    let chat_file = root.join("chat.jsonl");

    // ---- session 1 --------------------------------------------------------------------------
    let device = DeviceId::new();
    let stop1 = Arc::new(AtomicBool::new(false));
    let agent1 = spawn_agent(url.clone(), device, stop1.clone(), transfer_dir.clone());
    let mut c = connect_controller(&url, device).await;

    // A brand-new machine has nothing to replay.
    send_chat(&mut c, &ChatMessage::RequestHistory { since_seq: 0 }).await;
    match recv_chat(&mut c, 5).await.expect("history reply") {
        ChatMessage::History { entries, truncated } => {
            assert!(entries.is_empty(), "a fresh machine has no transcript, got {entries:?}");
            assert!(!truncated);
        }
        other => panic!("expected History, got {other:?}"),
    }

    // Post two messages, one from each side, and check what comes back is what the AGENT recorded
    // — sequence and timestamp assigned by it, not by us.
    send_chat(
        &mut c,
        &ChatMessage::Send { from: ChatFrom::Technician, body: "can you see this?".into() },
    )
    .await;
    let first = match recv_chat(&mut c, 5).await.expect("posted echo") {
        ChatMessage::Posted { entry } => entry,
        other => panic!("expected Posted, got {other:?}"),
    };
    assert_eq!(first.seq, 1, "the first message on a fresh machine is sequence 1");
    assert_eq!(first.from, ChatFrom::Technician);
    assert_eq!(first.body, "can you see this?");
    assert!(first.at_unix_ms > 1_600_000_000_000, "the agent stamped a real time, got {}", first.at_unix_ms);

    // PREMISE (changed deliberately, and stated here rather than assumed): the controller may not
    // author a line attributed to the GUEST. This transport has two peers — the agent (the machine
    // the guest is sitting at) and the controller (the remote technician) — so a `Send` arriving
    // over it is the technician's by construction, and the agent now decides the role instead of
    // believing the claim. Before this, a technician could plant fabricated guest statements in the
    // persisted support transcript. This send deliberately CLAIMS `Guest` and asserts the agent
    // overrode it; the claim is the stimulus, not the expectation.
    send_chat(&mut c, &ChatMessage::Send { from: ChatFrom::Guest, body: "yes, hello".into() }).await;
    let second = match recv_chat(&mut c, 5).await.expect("posted echo") {
        ChatMessage::Posted { entry } => entry,
        other => panic!("expected Posted, got {other:?}"),
    };
    assert_eq!(second.seq, 2, "sequences increase");
    assert_eq!(
        second.from,
        ChatFrom::Technician,
        "a controller-claimed `Guest` must be recorded as Technician — the role is the agent's to \
         know, not the peer's to assert"
    );
    assert_eq!(second.body, "yes, hello", "and the message itself is still delivered, not dropped");

    // A body over the cap is TRUNCATED and delivered, never silently dropped.
    let huge = "z".repeat(chat::MAX_BODY_CHARS * 2);
    send_chat(&mut c, &ChatMessage::Send { from: ChatFrom::Technician, body: huge }).await;
    let third = match recv_chat(&mut c, 5).await.expect("posted echo") {
        ChatMessage::Posted { entry } => entry,
        other => panic!("expected Posted, got {other:?}"),
    };
    assert_eq!(third.seq, 3, "an over-long message is still recorded");
    assert_eq!(third.body.chars().count(), chat::MAX_BODY_CHARS, "truncated to the cap");

    // The cursor returns exactly the gap, not the whole transcript.
    send_chat(&mut c, &ChatMessage::RequestHistory { since_seq: 1 }).await;
    match recv_chat(&mut c, 5).await.expect("history reply") {
        ChatMessage::History { entries, .. } => {
            assert_eq!(
                entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
                vec![2, 3],
                "since_seq must return the gap, not a duplicate of everything"
            );
        }
        other => panic!("expected History, got {other:?}"),
    }

    // End session 1 completely: transport closed, driver returned, its Transcript dropped.
    drop(c);
    stop1.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(15), agent1).await;

    // The transcript really is on disk — the mechanism, checked directly, so a failure below can be
    // attributed to the reload rather than the save.
    let saved = std::fs::read_to_string(&chat_file).expect("the agent must persist chat.jsonl");
    let lines: Vec<&str> = saved.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "three entries persisted, got:\n{saved}");
    let parsed: ChatEntry = serde_json::from_str(lines[0]).expect("JSONL: one entry per line");
    assert_eq!(parsed.seq, 1);

    // ---- session 2: a fresh agent session, fresh transport, fresh Transcript ------------------
    //
    // A NEW device id, deliberately, and it makes the test stronger rather than weaker.
    //
    // The transcript's identity is the agent's **state directory** (`transfer_dir`'s parent), not
    // the connection — so pointing a second session at the same directory is exactly the scenario
    // that matters in production: a *different technician, later*, opening a session to the same
    // machine and needing to see what was already said.
    //
    // Reusing the first session's device id instead makes the test race the signaling server's
    // de-registration: the old registration outlives `serve_session_with_ice` returning, so the
    // second connect brokers to a dead peer and times out. Measured — under `verify-all.ps1` the
    // reused id failed with "webrtc connect timed out" twice and "not registered or offline" twice
    // across four attempts. That race is about the registry, not about chat, and letting it decide
    // this test would make a persistence failure and a timing failure indistinguishable.
    let device2 = DeviceId::new();
    let stop2 = Arc::new(AtomicBool::new(false));
    let agent2 = spawn_agent(url.clone(), device2, stop2.clone(), transfer_dir.clone());
    let mut c2 = connect_controller(&url, device2).await;

    send_chat(&mut c2, &ChatMessage::RequestHistory { since_seq: 0 }).await;
    let replayed = match recv_chat(&mut c2, 5).await.expect("history reply after reconnect") {
        ChatMessage::History { entries, .. } => entries,
        other => panic!("expected History, got {other:?}"),
    };
    assert_eq!(
        replayed.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the whole conversation must survive the reconnect — this is the 'persistent' in \
         'persistent history', and it is what a purely in-memory transcript would fail"
    );
    assert_eq!(replayed[0].body, "can you see this?", "and the CONTENT survived, not just the count");
    // …including the role the AGENT decided, which is what got persisted — not the `Guest` the
    // controller claimed when it sent this line. The normalization has to survive the round trip
    // through `chat.jsonl`, or a forged role would simply reappear after a reconnect.
    assert_eq!(replayed[1].from, ChatFrom::Technician, "…including who the agent recorded");

    // The sequence CONTINUES past the restored high-water mark. A transcript that restarted at 1
    // would answer a reconnecting viewer's `since_seq: 3` with nothing, silently losing the rest of
    // the conversation.
    send_chat(&mut c2, &ChatMessage::Send { from: ChatFrom::Technician, body: "still here".into() }).await;
    let fourth = match recv_chat(&mut c2, 5).await.expect("posted echo") {
        ChatMessage::Posted { entry } => entry,
        other => panic!("expected Posted, got {other:?}"),
    };
    assert_eq!(fourth.seq, 4, "the sequence continued past the restored transcript");

    send_chat(&mut c2, &ChatMessage::RequestHistory { since_seq: 3 }).await;
    match recv_chat(&mut c2, 5).await.expect("history reply") {
        ChatMessage::History { entries, .. } => {
            assert_eq!(entries.len(), 1, "the reconnecting viewer gets exactly what it missed");
            assert_eq!(entries[0].body, "still here");
        }
        other => panic!("expected History, got {other:?}"),
    }

    stop2.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(15), agent2).await;
    let _ = std::fs::remove_dir_all(&root);
}

// =================================================================================================
// Guest ingress — the guest window's half of the conversation.
// =================================================================================================

/// A [`GuestUi`] that records what the window would show and can type on the guest's behalf.
///
/// This drives 100 % of the production ingress path — the session's `select!` arm, the transcript,
/// the persistence, the wire frame — with only the Win32 shell replaced. The shell itself is what
/// the VM runs prove; everything on this side of the `chat_tx` channel is proven here, on any
/// machine, with no desktop.
#[derive(Clone, Default)]
struct FakeGuestUi {
    shown: Arc<std::sync::Mutex<Vec<(ChatFrom, String)>>>,
    seeded: Arc<std::sync::Mutex<Vec<(ChatFrom, String)>>>,
    ended: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    /// Handed back to the test so it can type as the guest (or press End).
    typed_tx: Arc<
        std::sync::Mutex<
            Option<tokio::sync::mpsc::UnboundedSender<rmt_agent_core::guest_ui::GuestToHost>>,
        >,
    >,
}

struct FakeSurface {
    shown: Arc<std::sync::Mutex<Vec<(ChatFrom, String)>>>,
    seeded: Arc<std::sync::Mutex<Vec<(ChatFrom, String)>>>,
    ended: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
}

impl rmt_agent_core::guest_ui::GuestUi for FakeGuestUi {
    fn open(
        &self,
        to_host: tokio::sync::mpsc::UnboundedSender<rmt_agent_core::guest_ui::GuestToHost>,
    ) -> Result<Box<dyn rmt_agent_core::guest_ui::GuestSurface>, String> {
        *self.typed_tx.lock().unwrap() = Some(to_host);
        Ok(Box::new(FakeSurface {
            shown: Arc::clone(&self.shown),
            seeded: Arc::clone(&self.seeded),
            ended: Arc::clone(&self.ended),
            closed: Arc::clone(&self.closed),
        }))
    }
}

impl rmt_agent_core::guest_ui::GuestSurface for FakeSurface {
    fn posted(&self, from: ChatFrom, body: &str, _at_unix_ms: i64) {
        self.shown.lock().unwrap().push((from, body.to_string()));
    }
    fn seed(&self, from: ChatFrom, body: &str, _at_unix_ms: i64) {
        self.seeded.lock().unwrap().push((from, body.to_string()));
    }
    fn ended(&self) {
        self.ended.store(true, Ordering::Relaxed);
    }
    fn set_view_only(&self, _view_only: bool) {
        // The chat e2e does not drive view-only; the indicator is covered by guest_ui/guest_window
        // unit tests and the VM title-flip proof. A no-op keeps this fake to the surface it exercises.
    }
    fn set_recording(&self, _recording: bool) {
        // Same: the recording indicator is covered by the guest_ui unit tests and by
        // `e2e_recording`, which asserts the SURFACE is told (a no-op fake here would not).
    }
    fn clipboard_shared(&self, _to_technician: bool) {
        // Same again: the chat e2e drives no clipboard. Covered by the guest_ui unit tests and by
        // `e2e_clipboard`, whose surface records the direction of every crossing.
    }
    fn close(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_the_guest_types_is_recorded_as_the_guests_and_reaches_the_controller() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_guestui_e2e_{}", uuid::Uuid::new_v4()));
    let transfer_dir = root.join("transfers");

    let ui = FakeGuestUi::default();
    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent = {
        let url = url.clone();
        let transfer_dir = transfer_dir.clone();
        let stop = stop.clone();
        let ui = ui.clone();
        tokio::spawn(async move {
            let capturer = SyntheticCapturer::new(320, 240, 30);
            let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
            serve_session_with_ice(
                &url,
                device,
                capturer,
                30,
                stop,
                Vec::new(),
                SessionOptions {
                    sink,
                    transfer_dir,
                    guest_ui: Some(Box::new(ui)),
                    ..Default::default()
                },
            )
            .await
        })
    };
    let mut c = connect_controller(&url, device).await;

    // 1. A technician line must reach the GUEST'S SCREEN. Before this window existed, nothing on
    //    the machine displayed an incoming message — chat was a technician talking into a log.
    send_chat(&mut c, &ChatMessage::Send { from: ChatFrom::Technician, body: "are you there?".into() }).await;
    match recv_chat(&mut c, 5).await.expect("posted echo") {
        ChatMessage::Posted { entry } => assert_eq!(entry.seq, 1),
        other => panic!("expected Posted, got {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while ui.shown.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        ui.shown.lock().unwrap().as_slice(),
        &[(ChatFrom::Technician, "are you there?".to_string())],
        "the technician's line must be shown to the guest"
    );
    // A fresh machine has no history, so nothing was seeded. The distinction matters: seeding and
    // posting are the same picture but only one of them counts as unread, and routing live traffic
    // through the seed path would silently disable the unread badge for the whole session.
    assert!(
        ui.seeded.lock().unwrap().is_empty(),
        "a live message must arrive as POSTED, never as replayed history"
    );

    // 2. THE POINT OF THE FEATURE: the guest types, and the line is recorded as the GUEST'S.
    //    `ChatFrom::Guest` was unreachable in production before this path existed — the agent could
    //    only ever mint `Technician`, so the "two-way" conversation had exactly one direction.
    let typed_tx = ui.typed_tx.lock().unwrap().clone().expect("the surface was opened");
    typed_tx
        .send(rmt_agent_core::guest_ui::GuestToHost::Chat(
            "  yes, the printer is dead  ".to_string(),
        ))
        .expect("guest types");

    let posted = match recv_chat(&mut c, 5).await.expect("the guest's line reaches the controller") {
        ChatMessage::Posted { entry } => entry,
        other => panic!("expected Posted, got {other:?}"),
    };
    assert_eq!(posted.from, ChatFrom::Guest, "the agent decides the role at the local ingress too");
    assert_eq!(posted.seq, 2, "the transcript numbers it in the same sequence as the technician's");
    assert_eq!(
        posted.body, "  yes, the printer is dead  ",
        "the agent stores what it was handed; trimming is the window's job, not the transcript's"
    );

    // 3. And it is persisted, so a reconnecting technician still sees the guest's half.
    let chat_file = root.join("chat.jsonl");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut on_disk = String::new();
    while Instant::now() < deadline {
        on_disk = std::fs::read_to_string(&chat_file).unwrap_or_default();
        if on_disk.lines().count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(on_disk.lines().count(), 2, "both halves of the conversation are on disk");
    assert!(on_disk.contains("\"Guest\""), "the guest's role survived to disk: {on_disk}");

    // 4. Teardown tells the window the session is over BEFORE closing it, and closes it. A surface
    //    that were only dropped would leave a window on the guest's screen still saying ACTIVE.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent).await;
    assert!(ui.ended.load(Ordering::Relaxed), "the window must be told the session ended");
    assert!(ui.closed.load(Ordering::Relaxed), "and then closed, not leaked");

    // ---- session 2: the replay must arrive as SEEDED, not POSTED ----------------------------
    //
    // The two look identical on screen and differ in exactly one respect: seeded lines are never
    // counted as unread. Replaying through `posted` is the natural way to write this and it makes a
    // machine with any support history open its window announcing a pile of "unread" messages from
    // previous sessions — a badge asserting the guest missed something that predates the window.
    // Nothing above can catch that: a FRESH machine has no history to replay, so this needs a second
    // session over the same state dir.
    let ui2 = FakeGuestUi::default();
    // A NEW device id, for the reason session 2 of the test above documents from measurement: the
    // first registration outlives `serve_session_with_ice` returning, so reusing the id races the
    // signaling registry and brokers to a dead peer. The transcript's identity is the STATE
    // DIRECTORY, not the device id, so a fresh id still replays the same conversation — which is
    // also the real production scenario (a different technician, later, same machine).
    let device2 = DeviceId::new();
    let stop2 = Arc::new(AtomicBool::new(false));
    let agent2 = {
        let url = url.clone();
        let transfer_dir = transfer_dir.clone();
        let stop2 = stop2.clone();
        let ui2 = ui2.clone();
        tokio::spawn(async move {
            let capturer = SyntheticCapturer::new(320, 240, 30);
            let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
            serve_session_with_ice(
                &url, device2, capturer, 30, stop2, Vec::new(),
                SessionOptions { sink, transfer_dir, guest_ui: Some(Box::new(ui2)), ..Default::default() },
            )
            .await
        })
    };
    let c2 = connect_controller(&url, device2).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while ui2.seeded.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let seeded = ui2.seeded.lock().unwrap().clone();
    assert_eq!(seeded.len(), 2, "both prior lines are replayed into the new window: {seeded:?}");
    assert_eq!(seeded[0], (ChatFrom::Technician, "are you there?".to_string()));
    assert_eq!(seeded[1], (ChatFrom::Guest, "  yes, the printer is dead  ".to_string()));
    assert!(
        ui2.shown.lock().unwrap().is_empty(),
        "replayed history must NOT arrive as `posted` — that is what makes it count as unread"
    );

    stop2.store(true, Ordering::Relaxed);
    drop(c2);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent2).await;

    let _ = std::fs::remove_dir_all(&root);
}

/// **The guest ends the session from the window (docs/12 §5).** Pressing End does not merely close
/// the window — it tears the whole session down, the guest revoking access to their own machine.
///
/// This drives the production `select!` arm end to end: `GuestToHost::End` on the ingress channel
/// must make `serve_session_with_ice` **return on its own**, with `stop` never set. If the End arm
/// did not drop both `input_open` and `video_open`, the agent future would run until the test's
/// timeout and this fails — which is exactly the mutation (`video_open = false` deleted) it exists
/// to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_pressing_end_tears_the_session_down_without_any_external_stop() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_guestend_e2e_{}", uuid::Uuid::new_v4()));
    let transfer_dir = root.join("transfers");

    let ui = FakeGuestUi::default();
    let device = DeviceId::new();
    // NEVER set — the whole point is that End, not this flag, ends the session.
    let stop = Arc::new(AtomicBool::new(false));
    let agent = {
        let url = url.clone();
        let transfer_dir = transfer_dir.clone();
        let stop = stop.clone();
        let ui = ui.clone();
        tokio::spawn(async move {
            let capturer = SyntheticCapturer::new(320, 240, 30);
            let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
            serve_session_with_ice(
                &url,
                device,
                capturer,
                30,
                stop,
                Vec::new(),
                SessionOptions {
                    sink,
                    transfer_dir,
                    guest_ui: Some(Box::new(ui)),
                    ..Default::default()
                },
            )
            .await
        })
    };

    let mut c = connect_controller(&url, device).await;

    // Prove the session is genuinely live first: a technician line reaches the guest's window.
    send_chat(&mut c, &ChatMessage::Send { from: ChatFrom::Technician, body: "hi".into() }).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while ui.shown.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(!ui.shown.lock().unwrap().is_empty(), "the session must be live before we end it");

    // The guest presses End.
    let typed_tx = ui.typed_tx.lock().unwrap().clone().expect("the surface was opened");
    typed_tx
        .send(rmt_agent_core::guest_ui::GuestToHost::End)
        .expect("guest presses End");

    // The agent must return ON ITS OWN. `stop` is never set, so a completed future here can only be
    // the End arm tearing the session down.
    let ended = tokio::time::timeout(Duration::from_secs(20), agent).await;
    assert!(
        ended.is_ok(),
        "End did not tear the session down: serve_session_with_ice was still running when stop was \
         never set"
    );
    assert!(!stop.load(Ordering::Relaxed), "the external stop flag was never touched — End did the work");
    assert!(ui.ended.load(Ordering::Relaxed), "the window must be told the session ended before closing");
    assert!(ui.closed.load(Ordering::Relaxed), "and the surface closed, not leaked");

    let _ = std::fs::remove_dir_all(&root);
}
