//! End-to-end proof that OBSERVER sessions enforce their permanent view-only floor in the agent.
//!
//! A real WebRTC controller exercises input, recording, guest input blocking, session ending and
//! upload refusal. A controlling-session negative control proves that the input path works.
//! This file proves agent enforcement via force_observer; it does NOT prove signaling-to-agent
//! access parsing, which is unit-tested in rmt-protocol/transport.
//!
//! mock_input: true prevents real OS input hooks; RecordingSink records rather than injects input.
//! Self-skips (prints SKIP: and returns green) when signaling is unreachable, unless
//! RMT_E2E_REQUIRE_SIGNALING is set, which turns an unreachable server into a failure.
//!
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe
//! cargo test -p rmt-agent-windows --test e2e_observer -- --nocapture
//! ```

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::file_transfer::{self, Message as FtMessage, Offer};
use rmt_agent_core::platform::{InputButton, InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::{input_codec, SyntheticCapturer};
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};
use uuid::Uuid;

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<InputEvent>>,
}

impl InputSink for RecordingSink {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        self.events.lock().unwrap().push(event);
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

async fn can_run() -> bool {
    let url = signaling_url();
    if signaling_reachable(&url).await {
        true
    } else {
        // Acceptance runs set RMT_E2E_REQUIRE_SIGNALING=1, so a missing server is a FAILURE there
        // rather than a green run that exercised nothing (the no-skip gate rule).
        if std::env::var_os("RMT_E2E_REQUIRE_SIGNALING").is_some() {
            panic!("RMT_E2E_REQUIRE_SIGNALING is set but no signaling server is reachable at {url}");
        }
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        false
    }
}

async fn send_control(controller: &mut WebRtcTransport, msg: &ControlMessage) {
    controller
        .send_frame(Frame::new(ChannelId::Control, control::encode(msg)))
        .await
        .expect("controller send control frame");
}

/// Ignore video, quality reports and unrelated control replies until the requested reply arrives.
async fn recv_control<T>(
    controller: &mut WebRtcTransport,
    timeout_secs: u64,
    pick: impl Fn(&ControlMessage) -> Option<T>,
) -> Option<T> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                if let Ok(msg) = control::decode(&frame.payload) {
                    if let Some(value) = pick(&msg) {
                        return Some(value);
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

async fn recv_ft(controller: &mut WebRtcTransport, timeout_secs: u64) -> FtMessage {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for file-transfer reply");
        match tokio::time::timeout(Duration::from_secs(1), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::FileTransfer => {
                return file_transfer::decode(&frame.payload).expect("decode file-transfer reply");
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => panic!("controller data channel closed before a reply arrived"),
            Err(_) => continue,
        }
    }
}

async fn session(force_observer: bool) -> (
    WebRtcTransport,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<Result<(), String>>,
    Arc<AtomicBool>,
    Arc<RecordingSink>,
) {
    let url = signaling_url();
    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let uninstall = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(RecordingSink::default());
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_uninstall = uninstall.clone();
    let agent_sink: Arc<dyn InputSink> = sink.clone();
    let agent = tokio::spawn(async move {
        serve_session_with_ice(
            &agent_url,
            device,
            SyntheticCapturer::new(64, 64, 8),
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink: agent_sink,
                transfer_dir: std::env::temp_dir().join(format!("rmt_observer_e2e_{}", Uuid::new_v4())),
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                mock_input: true,
                force_observer,
                uninstall_requested: agent_uninstall,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| e.to_string())
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let controller = WebRtcTransport::connect(&url, Role::dev_controller(device))
        .await
        .expect("controller connect");
    (controller, stop, agent, uninstall, sink)
}

async fn stop_session(stop: Arc<AtomicBool>, agent: tokio::task::JoinHandle<Result<(), String>>) {
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}

async fn send_input(controller: &mut WebRtcTransport) {
    let events = [
        InputEvent::Key { code: 65, down: true },
        InputEvent::Key { code: 65, down: false },
        InputEvent::MouseMove { x: 60000, y: 50000 },
        InputEvent::MouseButton { button: InputButton::Left, down: true },
        InputEvent::MouseButton { button: InputButton::Left, down: false },
        InputEvent::Scroll { dx: -1, dy: 3 },
    ];
    for event in &events {
        controller
            .send_frame(Frame::new(ChannelId::Input, input_codec::encode(event)))
            .await
            .expect("controller send input");
    }
}

/// Run exactly the same input and downgrade sequence for observer and controlling sessions.
async fn input_sequence(force_observer: bool) {
    let (mut controller, stop, agent, _uninstall, sink) = session(force_observer).await;
    send_input(&mut controller).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let first_count = sink.events.lock().unwrap().len();

    send_control(&mut controller, &ControlMessage::SetViewOnly { enabled: false }).await;
    let applied = recv_control(&mut controller, 10, |msg| match msg {
        ControlMessage::ViewOnlyApplied { enabled } => Some(*enabled),
        _ => None,
    })
    .await;
    // Clear before the second probe so the negative control must demonstrate input again.
    sink.events.lock().unwrap().clear();
    send_input(&mut controller).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let second_count = sink.events.lock().unwrap().len();
    stop_session(stop, agent).await;

    assert_eq!(applied, Some(force_observer), "view-only floor acknowledgement");
    if force_observer {
        assert_eq!(first_count, 0, "observer input reached the guest");
        assert_eq!(second_count, 0, "observer input reached the guest after SetViewOnly(false)");
    } else {
        assert!(first_count > 0, "negative control: initial input path did not work");
        assert!(second_count > 0, "negative control: input path did not work after SetViewOnly(false)");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observer_input_never_reaches_the_guest() {
    if !can_run().await { return; }
    input_sequence(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlling_input_reaches_the_guest_negative_control() {
    if !can_run().await { return; }
    input_sequence(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observer_cannot_control_recording() {
    if !can_run().await { return; }
    let (mut controller, stop, agent, _uninstall, _sink) = session(true).await;
    send_control(&mut controller, &ControlMessage::StartRecording).await;
    let reply = recv_control(&mut controller, 5, |msg| match msg {
        ControlMessage::Error { message } => Some(message.clone()),
        ControlMessage::RecordingStarted { .. } => Some("APPLIED recording".to_string()),
        _ => None,
    }).await;
    stop_session(stop, agent).await;
    let message = reply.expect("agent never answered StartRecording");
    assert!(message.contains("observer"), "unexpected recording reply: {message}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observer_cannot_block_guest_input() {
    if !can_run().await { return; }
    let (mut controller, stop, agent, _uninstall, _sink) = session(true).await;
    send_control(&mut controller, &ControlMessage::SetInputBlocked { blocked: true }).await;
    let reply = recv_control(&mut controller, 5, |msg| match msg {
        ControlMessage::Error { message } => Some(message.clone()),
        ControlMessage::InputBlockApplied { blocked } => Some(format!("APPLIED blocked={blocked}")),
        _ => None,
    }).await;
    stop_session(stop, agent).await;
    let message = reply.expect("agent never answered input-block request");
    assert!(message.contains("view-only"), "unexpected input-block reply: {message}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observer_end_session_never_uninstalls() {
    if !can_run().await { return; }
    let (mut controller, stop, agent, uninstall, _sink) = session(true).await;
    send_control(&mut controller, &ControlMessage::EndSession { uninstall: true, directive: None }).await;
    let ending = recv_control(&mut controller, 10, |msg| match msg {
        ControlMessage::SessionEnding { uninstall } => Some(*uninstall),
        _ => None,
    }).await;
    let ended = tokio::time::timeout(Duration::from_secs(15), agent).await;
    stop.store(true, Ordering::Relaxed);
    assert_eq!(ending, Some(false), "SessionEnding must report uninstall actually in force");
    ended.expect("observer session did not end")
        .expect("agent task panicked")
        .expect("agent session failed");
    assert!(!uninstall.load(Ordering::SeqCst), "observer armed self-uninstall");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observer_upload_is_refused() {
    if !can_run().await { return; }
    let (mut controller, stop, agent, _uninstall, _sink) = session(true).await;
    let id = Uuid::new_v4();
    let bytes = b"observer upload probe";
    let offer = FtMessage::Offer(Offer {
        id,
        name: "observer_probe.bin".into(),
        size: bytes.len() as u64,
        sha256: file_transfer::sha256_hex(bytes),
    });
    controller.send_frame(Frame::new(ChannelId::FileTransfer, file_transfer::encode(&offer)))
        .await.expect("controller send offer");
    let reply = recv_ft(&mut controller, 15).await;
    stop_session(stop, agent).await;
    match reply {
        FtMessage::Error { id: reply_id, message } => {
            assert_eq!(reply_id, id);
            assert!(message.contains("observer"), "unexpected upload refusal: {message}");
        }
        other => panic!("expected observer upload Error, got {other:?}"),
    }
}
