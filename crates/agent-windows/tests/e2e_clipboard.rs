//! End-to-end clipboard-sync test (M9 deliverable): a controller drives **bidirectional** text
//! clipboard sync over a REAL WebRTC data channel on [`ChannelId::Clipboard`], against an agent
//! running [`rmt_agent_windows::host::serve_session_with_ice`] with an in-memory **fake** clipboard.
//!
//! Both directions are exercised against one live session, plus echo suppression:
//!  * **Down** (controller→agent): the controller sends `Text("…")`; the test asserts the fake
//!    clipboard's `set_text` received exactly that string.
//!  * **Echo suppression**: after the remote-set above, the test asserts the agent does **not** bounce
//!    that same text back on `ChannelId::Clipboard` (a naive implementation would loop).
//!  * **Up** (agent→controller): the test simulates a LOCAL clipboard change by mutating + bumping the
//!    fake's sequence; the agent's worker detects it and forwards the text, which the controller
//!    receives on `ChannelId::Clipboard`.
//!
//! The clipboard rides the same session the input/backstage/file-transfer e2e tests use (a
//! [`SyntheticCapturer`] feeds the video half so the session stays live). It **self-skips** (prints
//! `SKIP:` and returns green) when no signaling server is reachable.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_clipboard -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_agent_core::chat::ChatFrom;
use rmt_agent_core::clipboard::{self, Clipboard, ClipboardMessage};
use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::guest_ui::{GuestSurface, GuestToHost, GuestUi};
use rmt_agent_windows::config::ClipboardMode;
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// A no-op input sink: this test drives clipboard, not input.
struct NoopSink;
impl InputSink for NoopSink {
    fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
        Ok(())
    }
}

/// Shared in-memory clipboard state, so the test can inspect `set_text` calls and simulate a local
/// change (by mutating `text` + bumping `seq`) while the agent worker owns the `Box<dyn Clipboard>`.
#[derive(Default)]
struct FakeState {
    /// Current clipboard text (what `get_text` returns).
    text: Option<String>,
    /// Monotonic sequence token; a real `set_text` and a simulated local change both bump it.
    seq: u64,
    /// Every string passed to `set_text`, in order (the "down" direction assertion).
    sets: Vec<String>,
}

/// A fake [`Clipboard`] over shared [`FakeState`]. `set_text` bumps the sequence (as the real Win32
/// clipboard does), which is what the worker's echo suppression must account for.
#[derive(Clone)]
struct FakeClipboard {
    state: Arc<Mutex<FakeState>>,
}

impl Clipboard for FakeClipboard {
    fn get_text(&self) -> Option<String> {
        self.state.lock().unwrap().text.clone()
    }
    fn set_text(&self, text: &str) -> Result<(), String> {
        let mut s = self.state.lock().unwrap();
        s.text = Some(text.to_string());
        s.sets.push(text.to_string());
        s.seq += 1; // a write advances the sequence, exactly like GetClipboardSequenceNumber
        Ok(())
    }
    fn sequence(&self) -> u64 {
        self.state.lock().unwrap().seq
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

/// Send one clipboard message as a `ChannelId::Clipboard` frame.
async fn send_clip(controller: &mut WebRtcTransport, msg: &ClipboardMessage) {
    let payload = clipboard::encode(msg);
    controller
        .send_frame(Frame::new(ChannelId::Clipboard, payload))
        .await
        .expect("controller send clipboard frame");
}

/// Await the next `ChannelId::Clipboard` frame's text within `timeout_secs`, or `None` on timeout.
/// Ignores frames on other channels (video keyframes, etc.).
async fn recv_clip_text(controller: &mut WebRtcTransport, timeout_secs: u64) -> Option<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::Clipboard => {
                match clipboard::decode(&frame.payload).expect("decode clipboard reply") {
                    ClipboardMessage::Text(t) => return Some(t),
                }
            }
            Ok(Ok(_)) => continue,   // other channel; keep waiting
            Ok(Err(_)) => return None, // data channel closed
            Err(_) => continue,      // recv timeout; re-check deadline
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clipboard_flows_both_directions_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // Shared fake clipboard: the agent worker owns a Box<dyn Clipboard> over this state; the test
    // keeps a clone of the Arc to inspect `sets` and to simulate a local change.
    let state = Arc::new(Mutex::new(FakeState::default()));
    let fake = FakeClipboard { state: state.clone() };
    let flags = Arc::new(Mutex::new(ClipFlags { calls: Vec::new() }));

    // Agent: run the real session driver (video via SyntheticCapturer + clipboard worker).
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_flags = Arc::clone(&flags);
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
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
                transfer_dir: std::env::temp_dir().join("rmt_clip_e2e_unused"),
                clipboard: Some(Box::new(fake)),
                // This test drives the clipboard channel only; backstage stays denied (the default).
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                guest_ui: Some(Box::new(FakeGuestUi { flags: agent_flags })),
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

    // ---- (a) DOWN: controller → agent set_text ------------------------------------------------
    let down_text = "clip from controller — 🦀 café 日本語";
    send_clip(&mut controller, &ClipboardMessage::Text(down_text.to_string())).await;

    // Poll the fake until the worker applies the remote set (bounded).
    let mut down_ok = false;
    for _ in 0..40 {
        if state.lock().unwrap().sets.iter().any(|s| s == down_text) {
            down_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(down_ok, "agent never applied the controller's clipboard text via set_text");
    assert_eq!(
        state.lock().unwrap().sets,
        vec![down_text.to_string()],
        "exactly one set_text with the controller's text",
    );

    // ---- echo suppression: the remote-set must NOT bounce back ---------------------------------
    // After applying our write, the worker recorded the resulting sequence, so its local-change
    // detection must stay silent. Allow a couple of poll cycles (~300ms each) then assert no frame.
    let echo = recv_clip_text(&mut controller, 1).await;
    assert!(
        echo.is_none(),
        "remote-set clipboard text was echoed back (echo suppression failed): {echo:?}",
    );

    // ---- (b) UP: simulate a LOCAL clipboard change on the agent --------------------------------
    let up_text = "local copy on agent — 🎉 ünïcode";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(up_text.to_string());
        s.seq += 1; // bump beyond what set_text left behind → a genuine local change
    }

    let got = recv_clip_text(&mut controller, 5).await;
    assert_eq!(
        got.as_deref(),
        Some(up_text),
        "controller did not receive the agent's local clipboard change",
    );

    // ---- (c) THE GUEST WAS TOLD, both times and in the right direction -------------------------
    // A perfectly worded disclosure the session loop never calls discloses nothing, so the surface
    // itself is the assertion. Order matters: the inbound write happened first (false), then the
    // outbound copy (true) — "told twice" and "told the wrong way round" are both distinguishable
    // from correct here.
    let calls = flags.lock().unwrap().calls.clone();
    assert_eq!(
        calls,
        vec![false, true],
        "the guest window must be told about each clipboard crossing, in direction order",
    );

    // Stop the agent and let it drain.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!(
        "CLIPBOARD OVER WEBRTC: down set_text ok (\"{}\"), echo suppressed ok, up local-change delivered ok (\"{}\")",
        &down_text[..12.min(down_text.len())],
        &up_text[..12.min(up_text.len())],
    );
}

/// A guest surface that records the DIRECTION of every clipboard crossing it is told about.
///
/// The point of the fake is the assertion it enables: a presenter that words the disclosure
/// perfectly proves nothing if the session loop never calls it. `true` is outbound (the guest's
/// clipboard went to the technician), `false` is inbound.
struct ClipFlags {
    calls: Vec<bool>,
}

struct FakeGuestUi {
    flags: Arc<Mutex<ClipFlags>>,
}

struct FakeSurface {
    flags: Arc<Mutex<ClipFlags>>,
}

impl GuestUi for FakeGuestUi {
    fn open(
        &self,
        _to_host: tokio::sync::mpsc::UnboundedSender<GuestToHost>,
    ) -> Result<Box<dyn GuestSurface>, String> {
        Ok(Box::new(FakeSurface { flags: Arc::clone(&self.flags) }))
    }
}

impl GuestSurface for FakeSurface {
    fn posted(&self, _from: ChatFrom, _body: &str, _at_unix_ms: i64) {}
    fn seed(&self, _from: ChatFrom, _body: &str, _at_unix_ms: i64) {}
    fn ended(&self) {}
    fn set_view_only(&self, _view_only: bool) {}
    fn set_recording(&self, _recording: bool) {}
    fn clipboard_shared(&self, to_technician: bool) {
        self.flags.lock().unwrap().calls.push(to_technician);
    }
    fn close(&mut self) {}
}

/// A COPY MADE UNDER VIEW-ONLY DOES NOT ESCAPE WHEN VIEW-ONLY IS LIFTED A MOMENT LATER.
///
/// The sub-poll race, and the reason the gate could not live only at the send site. The worker
/// notices a local copy at its own 300 ms cadence, while the session loop evaluates view-only when a
/// message is DELIVERED. Those are different clocks:
///
///   T+0     guest copies a password; view-only is in force
///   T+50ms  technician lifts view-only
///   T+300ms the worker's first poll since the copy — it reads the password, and the send site now
///           sees view_only == false and ships it
///
/// The secret was copied under view-only and left the machine anyway. The other view-only test
/// cannot catch this: it blocks for three seconds in `recv_clip_text` before lifting, so the poll
/// has always already happened and the drop is a foregone conclusion. Here the lift is issued
/// IMMEDIATELY after the copy, inside one poll window, which is the only arrangement that exercises
/// it.
///
/// Closed at both ends — the worker checks permission before it reads, and rebaselines when egress
/// re-opens so a change made while it was shut is consumed rather than deferred.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_made_under_view_only_does_not_escape_when_view_only_is_lifted_immediately() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    let state = Arc::new(Mutex::new(FakeState::default()));
    let fake = FakeClipboard { state: state.clone() };

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
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
                transfer_dir: std::env::temp_dir().join("rmt_clip_race_e2e_unused"),
                clipboard: Some(Box::new(fake)),
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                ..Default::default()
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    send_control(&mut controller, &ControlMessage::SetViewOnly { enabled: true }).await;
    assert_eq!(
        recv_view_only_ack(&mut controller, 10).await,
        Some(true),
        "agent never acked view-only",
    );

    // Copy the secret and lift view-only in the SAME poll window. No await between them beyond the
    // frame send itself, so the worker cannot have polled in between.
    let secret = "password copied one instant before the lift";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(secret.to_string());
        s.seq += 1;
    }
    send_control(&mut controller, &ControlMessage::SetViewOnly { enabled: false }).await;
    assert_eq!(
        recv_view_only_ack(&mut controller, 10).await,
        Some(false),
        "agent never lifted view-only",
    );

    // Several poll cycles: if the worker is going to read and ship the secret, this is when.
    let leaked = recv_clip_text(&mut controller, 3).await;
    assert_eq!(
        leaked, None,
        "a copy made while view-only was in force escaped once view-only was lifted",
    );

    // NEGATIVE CONTROL: the session is genuinely usable afterwards. Without this the assertion above
    // would pass just as well against a clipboard that stopped working at the lift.
    let after = "copied well after the lift";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(after.to_string());
        s.seq += 1;
    }
    assert_eq!(
        recv_clip_text(&mut controller, 5).await.as_deref(),
        Some(after),
        "the clipboard never recovered after the lift, so the assertion above proves nothing",
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!("CLIPBOARD SUB-POLL RACE: the pre-lift copy stayed, a later copy flowed");
}

/// THE MACHINE'S CEILING IS WIRED TO THE DIRECTIONS IT NAMES.
///
/// `ClipboardMode::ToGuest` is deliberately the ASYMMETRIC mode, and it is the only kind of case
/// that can catch the mistake this test exists for. The accessors have their own truth table in
/// `config.rs`, but a truth table cannot tell whether `allows_to_guest()` was wired to the inbound
/// arm or the outbound one. Swap the two call sites in host.rs and every unit test still passes
/// while the machine does exactly the opposite of what its administrator configured — a clipboard
/// that was supposed to keep the guest's copies in, quietly sending them out.
///
/// Under `ToGuest`: the technician MAY write into the guest's clipboard; the guest's clipboard MUST
/// NOT leave the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_configured_to_guest_only_accepts_writes_but_sends_nothing_out() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    let state = Arc::new(Mutex::new(FakeState::default()));
    let fake = FakeClipboard { state: state.clone() };
    let flags = Arc::new(Mutex::new(ClipFlags { calls: Vec::new() }));

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_flags = Arc::clone(&flags);
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
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
                transfer_dir: std::env::temp_dir().join("rmt_clip_mode_e2e_unused"),
                clipboard: Some(Box::new(fake)),
                clipboard_mode: ClipboardMode::ToGuest,
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                guest_ui: Some(Box::new(FakeGuestUi { flags: agent_flags })),
                ..Default::default()
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    // ---- INBOUND is PERMITTED under ToGuest ----------------------------------------------------
    let allowed_in = "the technician may still paste to the guest";
    send_clip(&mut controller, &ClipboardMessage::Text(allowed_in.to_string())).await;
    let mut down_ok = false;
    for _ in 0..40 {
        if state.lock().unwrap().sets.iter().any(|s| s == allowed_in) {
            down_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        down_ok,
        "ToGuest must still allow the technician to write into the guest's clipboard; \
         if this fails the two accessors are wired to the wrong arms",
    );

    // ---- OUTBOUND is REFUSED under ToGuest -----------------------------------------------------
    let secret = "a local copy that must not leave a to_guest machine";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(secret.to_string());
        s.seq += 1;
    }
    let leaked = recv_clip_text(&mut controller, 3).await;
    assert!(
        leaked.is_none(),
        "a to_guest machine sent the guest's clipboard to the technician: {leaked:?}",
    );

    // The guest was told about the write, and about nothing else.
    let calls = flags.lock().unwrap().calls.clone();
    assert_eq!(
        calls,
        vec![false],
        "exactly one disclosure — the inbound write — and no claim that anything went out",
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!("CLIPBOARD MODE to_guest: inbound accepted, outbound refused, one disclosure");
}

/// Send one control message as a `ChannelId::Control` frame.
async fn send_control(controller: &mut WebRtcTransport, msg: &ControlMessage) {
    let payload = control::encode(msg);
    controller
        .send_frame(Frame::new(ChannelId::Control, payload))
        .await
        .expect("controller send control frame");
}

/// Await the next `ViewOnlyApplied` ack within `timeout_secs`, returning the state in force.
/// Ignores every other channel and every other control message.
async fn recv_view_only_ack(controller: &mut WebRtcTransport, timeout_secs: u64) -> Option<bool> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                if let Ok(ControlMessage::ViewOnlyApplied { enabled }) =
                    control::decode(&frame.payload)
                {
                    return Some(enabled);
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// VIEW-ONLY GOVERNS THE CLIPBOARD, IN BOTH DIRECTIONS — and the paired negative control.
///
/// The clipboard was ungoverned in both directions and on by default. Outbound, a view-only session
/// silently exfiltrated everything the guest copied, which is the direction a screen-watching threat
/// model misses: the frame buffer shows what is DISPLAYED, but the clipboard holds what was COPIED —
/// routinely a password-manager secret that never renders. Inbound, the controller could stage
/// arbitrary text in the guest's clipboard, written by `SetClipboardData` running as SYSTEM.
///
/// This test is deliberately ONE session with the toggle driven both ways, rather than two sessions
/// with a constant. A test that only ever ran view-only ON would pass just as happily against a
/// clipboard that was broken outright, so each blocked assertion is paired with the same assertion
/// passing once view-only is lifted:
///
///   1. view-only ON  → inbound `set_text` never happens, outbound frame never arrives
///   2. view-only OFF → both directions work again (this is the negative control)
///
/// Step 3 is the regression the gate's placement exists for. The gate sits INSIDE the outbound arm
/// rather than on its `if` condition, so a text copied while view-only is in force is RECEIVED AND
/// DROPPED, not left queued in the unbounded channel. Gating the arm's condition instead would hold
/// the backlog and flush every secret copied during the restricted period the instant view-only was
/// lifted — a leak that arrives late rather than one that is prevented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_only_session_moves_no_clipboard_in_either_direction() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    let state = Arc::new(Mutex::new(FakeState::default()));
    let fake = FakeClipboard { state: state.clone() };
    let flags = Arc::new(Mutex::new(ClipFlags { calls: Vec::new() }));

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_flags = Arc::clone(&flags);
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
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
                transfer_dir: std::env::temp_dir().join("rmt_clip_vo_e2e_unused"),
                clipboard: Some(Box::new(fake)),
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                guest_ui: Some(Box::new(FakeGuestUi { flags: agent_flags })),
                // NOT `require_session_policy`: the session opens CONTROLLING, and the technician's
                // own toggle drives it view-only. That is the realistic path, and it is the only one
                // that can also be lifted again — the provisional floor is deliberately not liftable
                // by the toggle, so it could not express the negative control below.
                ..Default::default()
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    // ---- turn view-only ON, and wait for the agent to say it is in force -----------------------
    send_control(&mut controller, &ControlMessage::SetViewOnly { enabled: true }).await;
    let applied = recv_view_only_ack(&mut controller, 10).await;
    assert_eq!(
        applied,
        Some(true),
        "agent never acked view-only; the rest of this test would prove nothing",
    );

    // ---- (1a) INBOUND is refused: no set_text on the guest's clipboard -------------------------
    let blocked_in = "controller text that must NEVER reach the guest clipboard";
    send_clip(&mut controller, &ClipboardMessage::Text(blocked_in.to_string())).await;

    // Wait well past the worker's 300ms poll so this is a real absence, not an unlucky race.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    {
        let sets = state.lock().unwrap().sets.clone();
        assert!(
            sets.is_empty(),
            "view-only session WROTE the controller's text into the guest clipboard: {sets:?}",
        );
    }

    // ---- (1b) OUTBOUND is refused: a local copy does not leave the machine ---------------------
    let secret = "secret copied while view-only — must never leave";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(secret.to_string());
        s.seq += 1;
    }
    let leaked = recv_clip_text(&mut controller, 3).await;
    assert!(
        leaked.is_none(),
        "view-only session EXFILTRATED the guest's clipboard: {leaked:?}",
    );

    // ---- (1c) AND THE GUEST WAS NOT TOLD ANYTHING HAPPENED -------------------------------------
    // A disclosure fired for a crossing that was refused is a false alarm, and a guest who sees
    // "what you copied was sent to the technician" on a session where nothing was sent learns to
    // disbelieve the notice on the session where something was.
    {
        let calls = flags.lock().unwrap().calls.clone();
        assert!(
            calls.is_empty(),
            "the guest was told their clipboard crossed while view-only refused both directions: {calls:?}",
        );
    }

    // ---- (2) NEGATIVE CONTROL: lift view-only and prove both directions still work -------------
    // Without this half, every assertion above would also pass against a clipboard that was simply
    // broken, or against a session whose channel never opened at all.
    send_control(&mut controller, &ControlMessage::SetViewOnly { enabled: false }).await;
    let applied = recv_view_only_ack(&mut controller, 10).await;
    assert_eq!(applied, Some(false), "agent never lifted view-only");

    // ---- (3) REGRESSION: the secret copied DURING view-only must not arrive late ---------------
    // The gate drops on receipt rather than disabling the arm, so nothing was queued. Give the
    // worker several poll cycles to produce a backlog if one exists.
    let late = recv_clip_text(&mut controller, 2).await;
    assert!(
        late.is_none(),
        "text copied while view-only was in force was DELIVERED after it was lifted \
         (the gate queued instead of draining): {late:?}",
    );

    // Inbound works again.
    let allowed_in = "controller text after view-only was lifted";
    send_clip(&mut controller, &ClipboardMessage::Text(allowed_in.to_string())).await;
    let mut down_ok = false;
    for _ in 0..40 {
        if state.lock().unwrap().sets.iter().any(|s| s == allowed_in) {
            down_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        down_ok,
        "clipboard stayed blocked after view-only was lifted — the gate is stuck on, so the \
         blocked assertions above prove nothing about view-only",
    );

    // Outbound works again, for a copy made AFTER the lift.
    let after = "local copy after the lift — 🎉";
    {
        let mut s = state.lock().unwrap();
        s.text = Some(after.to_string());
        s.seq += 1;
    }
    let got = recv_clip_text(&mut controller, 5).await;
    assert_eq!(
        got.as_deref(),
        Some(after),
        "outbound clipboard stayed blocked after view-only was lifted",
    );

    // Once lifted, the crossings are real and the guest IS told — the positive half of (1c).
    let calls = flags.lock().unwrap().calls.clone();
    assert_eq!(
        calls,
        vec![false, true],
        "after view-only was lifted the guest must be told about each real crossing, and only those",
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!(
        "CLIPBOARD VIEW-ONLY: inbound refused, outbound refused, guest told nothing while refused, \
         no late flush after the lift, and both directions verified working again once lifted",
    );
}
