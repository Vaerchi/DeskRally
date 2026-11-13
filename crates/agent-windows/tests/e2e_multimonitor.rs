//! End-to-end multi-monitor test (M10 deliverable): a controller enumerates the agent's monitors
//! and switches which one is streamed, over a REAL WebRTC data channel on [`ChannelId::Control`],
//! against an agent running [`rmt_agent_windows::host::serve_session_with_ice`] with a **2-monitor
//! [`SyntheticCapturer`]** (320×240 primary + 640×480 secondary).
//!
//! One live session exercises the whole M10 control flow:
//!  * **Enumerate**: the controller sends `RequestMonitors`; the test asserts a `MonitorList` with
//!    exactly the two monitors (ids 0 + 1, correct sizes, primary flags) comes back.
//!  * **Select**: the controller sends `SelectMonitor { id: 1 }`. Because RTP frame dimensions are
//!    not trivially observable from the data channel, the switch is confirmed **deterministically**
//!    via a [`CaptureObserver`] the test attached to the SyntheticCapturer: after the select, the
//!    capturer's `last_monitor` becomes 1 and its `frames` counter keeps climbing — proving the
//!    capture thread is now capturing monitor 1 *and* the stream is still flowing.
//!  * **Reject**: `SelectMonitor { id: 99 }` (not in the list) comes back as a `ControlMessage::Error`.
//!
//! The control flow rides the same session the input/clipboard/file-transfer e2e tests use (the
//! SyntheticCapturer feeds the video half so the session stays live). It **self-skips** (prints
//! `SKIP:` and returns green) when no signaling server is reachable.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_multimonitor -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::{CaptureObserver, SyntheticCapturer};
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// A no-op input sink: this test drives the control channel, not input.
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

/// Send one control message as a `ChannelId::Control` frame.
async fn send_control(controller: &mut WebRtcTransport, msg: &ControlMessage) {
    let payload = control::encode(msg);
    controller
        .send_frame(Frame::new(ChannelId::Control, payload))
        .await
        .expect("controller send control frame");
}

/// Await the next decoded `ChannelId::Control` message within `timeout_secs`, or `None` on timeout.
/// Ignores frames on other channels (video keyframes, etc.).
async fn recv_control(controller: &mut WebRtcTransport, timeout_secs: u64) -> Option<ControlMessage> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                return Some(control::decode(&frame.payload).expect("decode control reply"));
            }
            Ok(Ok(_)) => continue,     // other channel; keep waiting
            Ok(Err(_)) => return None, // data channel closed
            Err(_) => continue,        // recv timeout; re-check deadline
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monitors_enumerate_and_switch_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // Two distinct virtual monitors + a shared observer the test watches to confirm the switch.
    let observer = Arc::new(CaptureObserver::default());
    let agent_observer = observer.clone();

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        // 320x240 (primary, id 0) + 640x480 (id 1); both even dims. Keyframe every frame.
        let capturer = SyntheticCapturer::with_monitors(&[(320, 240), (640, 480)], 0)
            .observing(agent_observer);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session_with_ice(
            &agent_url,
            agent_device,
            capturer,
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink,
                transfer_dir: std::env::temp_dir().join("rmt_multimon_e2e_unused"),
                ..Default::default()
            },
        )
        .await
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    // The list must arrive without a request, so a client that asked too early can recover.
    // Consume this announcement separately from the requested reply below: both are valid
    // Control messages, and leaving one queued would confuse the later Error assertion.
    match recv_control(&mut controller, 5).await {
        Some(ControlMessage::MonitorList { monitors }) => {
            assert_eq!(monitors.len(), 2, "initial announcement must include both displays");
        }
        other => panic!("expected unsolicited MonitorList, got {other:?}"),
    }

    // ---- (a) ENUMERATE: RequestMonitors → MonitorList -----------------------------------------
    send_control(&mut controller, &ControlMessage::RequestMonitors).await;
    // The agent advertises its transfer folder unsolicited right after the channel opens (docs/58),
    // so TransferDir can race the MonitorList reply; skip advertisements, stay strict on the rest.
    let monitors = loop {
        let list = recv_control(&mut controller, 5).await.expect("no MonitorList reply");
        match list {
            ControlMessage::MonitorList { monitors } => break monitors,
            ControlMessage::TransferDir { .. } => continue,
            other => panic!("expected MonitorList, got {other:?}"),
        }
    };
    assert_eq!(monitors.len(), 2, "agent advertised both virtual monitors");
    assert_eq!(
        (monitors[0].id, monitors[0].width, monitors[0].height, monitors[0].primary),
        (0, 320, 240, true),
        "monitor 0 is the 320x240 primary",
    );
    assert_eq!(
        (monitors[1].id, monitors[1].width, monitors[1].height, monitors[1].primary),
        (1, 640, 480, false),
        "monitor 1 is the 640x480 secondary",
    );

    // Sanity: while nothing is selected, the capture thread is streaming the primary (id 0).
    // (It has certainly captured frames by now — the video half runs at 30fps.)
    let mut saw_primary = false;
    for _ in 0..30 {
        if observer.last_monitor.load(Ordering::Relaxed) == 0
            && observer.frames.load(Ordering::Relaxed) > 0
        {
            saw_primary = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(saw_primary, "capture thread should stream the primary (id 0) by default");

    // ---- (b) SELECT: SelectMonitor{1} → capture thread switches to monitor 1 -------------------
    send_control(&mut controller, &ControlMessage::SelectMonitor { id: 1 }).await;

    // Deterministic confirmation: the capturer's last-captured monitor becomes 1 (bounded wait).
    let mut switched = false;
    for _ in 0..50 {
        if observer.last_monitor.load(Ordering::Relaxed) == 1 {
            switched = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(switched, "capture thread never switched to the selected monitor (id 1)");

    // ---- still streaming: the frame counter keeps climbing on monitor 1 -----------------------
    let before = observer.frames.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = observer.frames.load(Ordering::Relaxed);
    assert!(after > before, "video stopped flowing after the monitor switch");
    assert_eq!(
        observer.last_monitor.load(Ordering::Relaxed),
        1,
        "capture thread is still on monitor 1 after the switch",
    );

    // ---- (c) REJECT: SelectMonitor for an unknown id → Error -----------------------------------
    send_control(&mut controller, &ControlMessage::SelectMonitor { id: 99 }).await;
    let err = recv_control(&mut controller, 5).await;
    match err {
        Some(ControlMessage::Error { message }) => {
            assert!(message.contains("99"), "error should name the bad id: {message:?}");
        }
        other => panic!("expected an Error for an unknown monitor id, got {other:?}"),
    }
    // The bad select must NOT have changed the stream: still on monitor 1.
    assert_eq!(
        observer.last_monitor.load(Ordering::Relaxed),
        1,
        "a rejected SelectMonitor must not retarget the stream",
    );

    // ---- (d) VIEW-ALL: SelectMonitor{COMPOSITE_MONITOR_ID} is accepted and keeps streaming --------
    // The reserved view-all id must be ACCEPTED (silent, unlike the unknown id above), and the
    // capture thread must keep producing frames — now a stitched composite of both monitors per tick.
    let before_all = observer.frames.load(Ordering::Relaxed);
    send_control(
        &mut controller,
        &ControlMessage::SelectMonitor { id: rmt_agent_core::platform::COMPOSITE_MONITOR_ID },
    )
    .await;
    // A successful select is silent; an unknown id would have produced an Error in this window.
    let reply = recv_control(&mut controller, 1).await;
    assert!(
        !matches!(reply, Some(ControlMessage::Error { .. })),
        "view-all composite id must be accepted, not rejected: {reply:?}",
    );
    // DECISIVE composite proof (not just "no Error + frames climb", which a silent primary-only
    // fallback would also satisfy): the SyntheticCapturer publishes the STITCHED width — Σ monitor
    // widths = 320 + 640 = 960 — on the observer ONLY via the composite path. A fall-through to a
    // single monitor would leave last_width at 320 or 640, so this fails red if composite regressed.
    let mut composited = false;
    for _ in 0..50 {
        if observer.last_width.load(Ordering::Relaxed) == 960 {
            composited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        composited,
        "view-all never produced a stitched composite frame (expected width 960 = 320+640); \
         did it silently fall back to a single monitor?",
    );
    let after_all = observer.frames.load(Ordering::Relaxed);
    assert!(after_all > before_all, "video stopped flowing after selecting the view-all composite");

    // Stop the agent and let it drain.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!(
        "MULTIMONITOR OVER WEBRTC: listed {} monitors (0:{}x{} primary, 1:{}x{}), selected id 1, \
         still streaming (frames {} → {}), unknown-id rejected, view-all composite accepted \
         (frames {} → {})",
        monitors.len(),
        monitors[0].width, monitors[0].height,
        monitors[1].width, monitors[1].height,
        before, after,
        before_all, after_all,
    );
}
