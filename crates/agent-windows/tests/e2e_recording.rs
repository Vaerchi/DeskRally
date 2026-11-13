//! End-to-end **session recording** test (loop 89, docs/01 §5): a controller starts and stops a
//! recording over a REAL WebRTC session, and what lands on disk is a playable file whose digest
//! matches its own sidecar.
//!
//! Modelled on `e2e_quality.rs` / `e2e_chat.rs` — same self-skip, and it runs under
//! `verify-all.ps1`, which treats a SKIP as a FAILURE.
//!
//! # What this proves that the unit tests cannot
//!
//! `recording.rs` and `video/ivf.rs` each have unit tests, and between them they cover the muxer,
//! the two clocks, the DACL, both budgets and the sweep. Every one of those drives the recorder
//! **directly**, by constructing frames and calling `offer`. That is exactly the shape of test this
//! project has twice found passing against a feature that was not connected to anything — most
//! recently in loop 88, where the viewer's whole elevation path was inert and five mutations were
//! unkillable by any suite. Before this file existed, `cargo` said so out loud:
//! `warning: variant SetRecording is never constructed`.
//!
//! So every assertion here goes through the SHIPPED path and nothing else: a control message on a
//! real data channel → `serve_session_with_ice`'s dispatch → `VideoFrameSender::set_recording` →
//! the encoder thread's tee → the writer thread → files. Specifically:
//!
//! 1. **The tee is installed at all** — frames encoded for the live stream reach the recording.
//! 2. **The guest is told.** `FakeSurface::set_recording` is recorded, so an agent that writes a
//!    video of someone's screen without lighting up their window fails here. docs/01 §9 has wanted
//!    that indicator since loop 18.
//! 3. **The artifact is self-describing and honest** — the sidecar's SHA-256 is recomputed from the
//!    bytes on disk, and the frame count in `RecordingStopped` matches what the file header says.
//! 4. **Both refusals are real refusals**, not silent no-ops: a second `StartRecording` and a
//!    `StopRecording` with nothing running each answer `Error`.
//! 5. **A host with no recording location cannot be talked into recording** — the negative control.
//! 6. **A session that ends mid-recording still finalizes** the files and the sidecar, on the
//!    teardown path where no `StopRecording` is ever sent.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_recording -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::chat::ChatFrom;
use rmt_agent_core::guest_ui::{GuestSurface, GuestToHost, GuestUi};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_agent_windows::recording::Sidecar;
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

struct NoopSink;
impl InputSink for NoopSink {
    fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
        Ok(())
    }
}

/// A guest surface that only records whether it was told about a recording.
///
/// The point of the fake is the ASSERTION it enables, so unlike the chat e2e's it does not no-op
/// `set_recording`: an agent that records without telling the guest must fail this test.
#[derive(Default)]
struct RecordingFlags {
    /// Every `set_recording` value, in order — so "told, then untold" is distinguishable from
    /// "told twice" and from "never told".
    calls: Vec<bool>,
}

struct FakeGuestUi {
    flags: Arc<Mutex<RecordingFlags>>,
}

struct FakeSurface {
    flags: Arc<Mutex<RecordingFlags>>,
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
    fn set_recording(&self, recording: bool) {
        self.flags.lock().unwrap().calls.push(recording);
    }
    fn clipboard_shared(&self, _to_technician: bool) {
        // This fake exists to prove the RECORDING indicator is told; clipboard disclosure is covered
        // by the guest_ui unit tests and by e2e_clipboard's own surface.
    }
    fn close(&mut self) {}
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

async fn send_control(controller: &mut WebRtcTransport, msg: &ControlMessage) {
    controller
        .send_frame(Frame::new(ChannelId::Control, control::encode(msg)))
        .await
        .expect("controller send control frame");
}

/// Await the next control message the agent sends, ignoring video/other channels.
///
/// Filters out periodic `QualityStats` and the initial `MonitorList` announcement.
/// Neither is a recording reply; errors and recording responses must still reach the assertions.
async fn recv_control(controller: &mut WebRtcTransport, secs: u64) -> Option<ControlMessage> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), controller.recv_frame()).await {
            Ok(Ok(f)) if f.channel == ChannelId::Control => {
                match control::decode(&f.payload) {
                    Ok(ControlMessage::QualityStats { .. }
                    | ControlMessage::MonitorList { .. }
                    // The agent advertises its transfer folder unsolicited after the channel opens
                    // (docs/58); recording tests only ever await solicited replies.
                    | ControlMessage::TransferDir { .. }) => continue,
                    Ok(m) => return Some(m),
                    Err(e) => panic!("undecodable control frame from the agent: {e}"),
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// Retry the connect while the agent finishes registering — bounded by ATTEMPTS, not a wall clock
/// (see `e2e_quality`'s note: a wall-clock budget makes the inner timeout retry zero times).
async fn connect_controller(url: &str, device: DeviceId) -> WebRtcTransport {
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

fn spawn_agent(
    url: String,
    device: DeviceId,
    stop: Arc<AtomicBool>,
    root: std::path::PathBuf,
    recording_dir: Option<std::path::PathBuf>,
    flags: Arc<Mutex<RecordingFlags>>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        // Noise, not the default gradient: a smooth gradient codes to almost nothing, and a
        // recording of ~50-byte frames would satisfy every size assertion here while proving
        // nothing about real content (the trap `e2e_quality`'s header documents).
        let capturer = SyntheticCapturer::new(320, 240, 30).with_noise();
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
                transfer_dir: root.join("transfers"),
                recording_dir,
                guest_ui: Some(Box::new(FakeGuestUi { flags })),
                ..Default::default()
            },
        )
        .await
    })
}

/// Wall-clock milliseconds, from the same helper the agent's sweep reads.
fn recording_now_ms() -> i64 {
    rmt_agent_windows::recording::now_unix_ms()
}

/// Write a recording from an EARLIER session into `dir`: one segment plus a sidecar carrying
/// `delete_after_unix_ms`. Returns the sidecar's path.
///
/// Deliberately a hand-built artifact and not a real recording — the point is the DEADLINE, and a
/// real one would carry `now + 72h` and could never be made expired without waiting three days.
/// The segment name is prefixed so it cannot collide with (or be mistaken for) this session's own,
/// which are named `rec-<start-ms>-NNNN.ivf`.
fn plant_recording(dir: &std::path::Path, tag: &str, delete_after_unix_ms: i64) -> std::path::PathBuf {
    let seg = format!("{tag}-0000.ivf");
    std::fs::write(dir.join(&seg), b"an earlier session's bytes").expect("write planted segment");
    let side = serde_json::json!({
        "kind": "rmt.session-recording.v1",
        "device_id": "an-earlier-device",
        "session_id": null,
        "started_at_unix_ms": 0,
        "ended_at_unix_ms": 0,
        "delete_after_unix_ms": delete_after_unix_ms,
        "segments": [{
            "file": seg, "width": 8, "height": 8, "frames": 1, "payload_bytes": 1, "sha256": "x"
        }],
        "truncated": null,
        "dropped_frames": 0,
        "disclaimer": "planted by e2e_recording",
    });
    let path = dir.join(format!("{tag}.json"));
    std::fs::write(&path, serde_json::to_vec(&side).expect("serialize")).expect("write sidecar");
    path
}

/// The one sidecar in `dir`, parsed. Panics with the directory listing if there is not exactly one.
fn read_sidecar(dir: &std::path::Path) -> Sidecar {
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("recording dir {} unreadable: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        // `rec-` is the recorder's own stem (`rec-<start-ms>`), so this counts what THIS SESSION
        // produced and ignores anything `plant_recording` left behind. Still "exactly one": a
        // session that somehow wrote two recordings is a fact worth failing on.
        .filter(|p| {
            p.extension().and_then(|s| s.to_str()) == Some("json")
                && p.file_name().and_then(|s| s.to_str()).is_some_and(|n| n.starts_with("rec-"))
        })
        .collect();
    found.sort();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one recording sidecar in {}, found {found:?}",
        dir.display()
    );
    let text = std::fs::read_to_string(&found[0]).expect("read sidecar");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("sidecar {text} did not parse: {e}"))
}

/// Read an IVF file's header the way an independent tool would: signature, dimensions, frame count.
///
/// Deliberately parsed here from the raw bytes rather than through `IvfWriter`'s own reader. The
/// writer's unit tests already round-trip it through `webrtc-media`'s `IVFReader`; what this file
/// needs to know is that the bytes the SESSION produced say what the session claims they say, and
/// re-using the writer's helper to check the writer's output is the self-consistency trap.
fn ivf_header(bytes: &[u8]) -> (u16, u16, u32) {
    assert!(bytes.len() >= 32, "an IVF file is at least its 32-byte header, got {}", bytes.len());
    assert_eq!(&bytes[0..4], b"DKIF", "IVF signature");
    assert_eq!(&bytes[8..12], b"VP80", "the recording must be a VP8 stream");
    let w = u16::from_le_bytes([bytes[12], bytes[13]]);
    let h = u16::from_le_bytes([bytes[14], bytes[15]]);
    let frames = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    (w, h, frames)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_session_leaves_a_playable_file_and_tells_the_guest_it_is_happening() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_rec_e2e_{}", uuid::Uuid::new_v4()));
    let rec_dir = root.join("recordings");
    let flags = Arc::new(Mutex::new(RecordingFlags::default()));

    // Plant two recordings from EARLIER sessions before the agent starts, so the session-start
    // sweep has something to do. This is the sweep's CALL SITE under test, not `sweep_expired`
    // itself: loop 89's mutation sweep replaced the call in `serve_session_with_ice` with a no-op
    // and every test in the repo stayed green, because `recording.rs`'s unit tests call the
    // function directly. Without a sweep that actually runs, the 72-hour TTL — the one mechanism
    // that keeps a staging area from becoming a permanent video vault on a customer's machine —
    // is a function nobody invokes.
    std::fs::create_dir_all(&rec_dir).expect("pre-create the recording dir");
    let expired = plant_recording(&rec_dir, "stale", recording_now_ms() - 1);
    let live = plant_recording(&rec_dir, "fresh", recording_now_ms() + 3_600_000);

    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent = spawn_agent(
        url.clone(),
        device,
        stop.clone(),
        root.clone(),
        Some(rec_dir.clone()),
        Arc::clone(&flags),
    );
    let mut c = connect_controller(&url, device).await;

    // The sweep runs at session start, before the transport is even brokered, so by the time the
    // controller is connected it has run.
    assert!(
        !expired.exists(),
        "the session start did not sweep an expired recording — {} is still there",
        expired.display()
    );
    assert!(
        live.exists(),
        "the sweep took a recording that had not expired: {} — a sweep that deletes everything \
         would satisfy the assertion above while destroying the operator's evidence",
        live.display()
    );

    // ---- start ---------------------------------------------------------------------------------
    send_control(&mut c, &ControlMessage::StartRecording).await;
    let started_at = match recv_control(&mut c, 10).await.expect("a reply to StartRecording") {
        ControlMessage::RecordingStarted { started_at_unix_ms, audit } => {
            // **The fail-closed leg of the loop-91 audit trail, asserted where it actually runs.**
            // This stack's signaling verifies no tickets (`-insecure-no-ticket-verification`), so it
            // vouches for no control-plane session and no technician. The agent must therefore seal
            // NOTHING — not a nil-identity event.
            //
            // That is not fastidiousness about a placeholder uuid. `POST /audit/ingest` refuses a
            // batch whose `technician_id` is not the authenticated forwarder, and the console builds
            // no forwarder without a session id, so such an event could never be delivered — and an
            // undelivered event is a `seq` HOLE, which `verifyLinkage` turns into a permanent
            // rejection of every later event in the session. Sealing here would not add a record; it
            // would destroy the ones that came after.
            //
            // A positive control cannot live in this file — it needs a stack started with
            // `-EnforceTickets -DevControlPlane`. `host_ft_audit_tests` and `recording_audit`'s unit
            // tests carry that half.
            assert!(
                audit.is_none(),
                "an agent whose signaling vouched for no session must seal no audit event; got                  {audit:?}"
            );
            started_at_unix_ms
        }
        other => panic!("expected RecordingStarted, got {other:?}"),
    };
    assert!(
        started_at > 1_600_000_000_000,
        "the agent stamped a real wall-clock start, got {started_at}"
    );
    assert_eq!(
        flags.lock().unwrap().calls,
        vec![true],
        "the guest's window must be told the moment recording starts — this is the indicator \
         docs/01 §9 asks for, and it is what makes recording without asking permission defensible"
    );

    // A SECOND start is an error, not a silent ack. The operator's belief about which file their
    // session is in has to stay true.
    send_control(&mut c, &ControlMessage::StartRecording).await;
    match recv_control(&mut c, 10).await.expect("a reply to the second StartRecording") {
        ControlMessage::Error { message } => {
            assert!(
                message.contains("already recording"),
                "the refusal must say why, got {message:?}"
            );
        }
        other => panic!("a second StartRecording must be refused, got {other:?}"),
    }
    assert_eq!(
        flags.lock().unwrap().calls,
        vec![true],
        "a refused start must not re-signal the guest"
    );

    // ---- let the session actually encode something ---------------------------------------------
    // Long enough at 30 fps for the tee to see many frames. Sleeping is the honest instrument here:
    // there is no controller-visible signal for "the encoder has produced N frames", and the
    // assertion below is a floor (">= 5"), not a rate, so a slow box under `verify-all` makes it
    // late rather than wrong.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ---- stop ----------------------------------------------------------------------------------
    send_control(&mut c, &ControlMessage::StopRecording).await;
    let (segments, frames, payload_bytes, dir) =
        match recv_control(&mut c, 10).await.expect("a reply to StopRecording") {
            ControlMessage::RecordingStopped {
                segments,
                frames,
                payload_bytes,
                truncated,
                dropped_frames_total,
                directory,
                audit,
            } => {
                // Same fail-closed reading as the start ack above.
                assert!(audit.is_none(), "no vouched session ⇒ no sealed event; got {audit:?}");
                assert_eq!(
                    truncated, None,
                    "a recording that was stopped normally must NOT be marked truncated — a \
                     truncated flag here would mean the tee was still installed when the recorder \
                     stopped, and every clean stop would look lossy"
                );
                assert_eq!(dropped_frames_total, 0, "nothing should have been dropped");
                (segments, frames, payload_bytes, directory)
            }
            other => panic!("expected RecordingStopped, got {other:?}"),
        };
    assert_eq!(segments, 1, "one resolution for the whole session ⇒ one segment");
    assert!(frames >= 5, "two seconds at 30 fps must reach the file; got {frames} frames");
    assert!(payload_bytes > 0, "a noise source must encode to something");
    assert_eq!(
        std::path::Path::new(&dir),
        rec_dir,
        "the operator is told where the files are"
    );
    assert_eq!(
        flags.lock().unwrap().calls,
        vec![true, false],
        "the guest must be told when it STOPS as well — an indicator that only ever lights up is \
         worse than none"
    );

    // ---- what is actually on disk --------------------------------------------------------------
    let side = read_sidecar(&rec_dir);
    assert_eq!(side.kind, "rmt.session-recording.v1");
    assert_eq!(side.device_id, device.to_string(), "the sidecar names the machine");
    assert_eq!(side.started_at_unix_ms, started_at, "the wire and the artifact agree on the start");
    assert!(side.ended_at_unix_ms >= side.started_at_unix_ms);
    assert_eq!(
        side.delete_after_unix_ms,
        side.ended_at_unix_ms + 72 * 3_600_000,
        "the artifact states its own 72-hour deadline, so the sweep never has to infer policy from \
         an mtime a copy or a restore would reset"
    );
    assert!(
        !side.disclaimer.is_empty() && side.disclaimer.contains("local"),
        "the disclaimer travels WITH the artifact, so it cannot be separated from it: {:?}",
        side.disclaimer
    );
    assert_eq!(side.segments.len(), segments as usize);

    let seg = &side.segments[0];
    assert_eq!(seg.frames, frames, "the wire figure is the artifact's figure");
    assert_eq!((seg.width, seg.height), (320, 240), "the encoded dimensions");
    let bytes = std::fs::read(rec_dir.join(&seg.file)).expect("read the IVF file");
    let (w, h, header_frames) = ivf_header(&bytes);
    assert_eq!((u32::from(w), u32::from(h)), (seg.width, seg.height), "header dimensions");
    assert_eq!(
        u64::from(header_frames),
        seg.frames,
        "finalize must patch the file header's frame count — an unfinalized file declares 0 and \
         plays as empty"
    );
    assert_eq!(
        bytes.len() as u64,
        32 + 12 * seg.frames + seg.payload_bytes,
        "IVF is 32 bytes of file header plus 12 per frame plus the payload, exactly"
    );
    let digest = rmt_agent_core::file_transfer::sha256_hex(&bytes);
    assert_eq!(
        digest, seg.sha256,
        "the sidecar's digest must be reproducible from the bytes a reviewer receives"
    );

    stop.store(true, Ordering::Relaxed);
    drop(c);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_recording_location_refuses_and_writes_nothing() {
    // The negative control for the whole feature. Recording is not something an agent does because
    // it was asked; it does it because the deployment configured a place for it. The ATTENDED host
    // is exactly this configuration (see `attend_session_options`), so this is that host's
    // behaviour under test, not a hypothetical.
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_rec_off_e2e_{}", uuid::Uuid::new_v4()));
    let flags = Arc::new(Mutex::new(RecordingFlags::default()));
    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent =
        spawn_agent(url.clone(), device, stop.clone(), root.clone(), None, Arc::clone(&flags));
    let mut c = connect_controller(&url, device).await;

    send_control(&mut c, &ControlMessage::StartRecording).await;
    match recv_control(&mut c, 10).await.expect("a reply to StartRecording") {
        ControlMessage::Error { message } => assert!(
            message.contains("not available"),
            "the refusal must name the reason, got {message:?}"
        ),
        other => panic!("a host with no recording location must refuse, got {other:?}"),
    }

    // Stopping something that never started is also an error, not a courtesy ack: a controller that
    // believes it stopped a recording believes a file exists.
    send_control(&mut c, &ControlMessage::StopRecording).await;
    match recv_control(&mut c, 10).await.expect("a reply to StopRecording") {
        ControlMessage::Error { message } => {
            assert!(message.contains("not recording"), "got {message:?}")
        }
        other => panic!("StopRecording with nothing running must be refused, got {other:?}"),
    }

    assert!(
        flags.lock().unwrap().calls.is_empty(),
        "a refused recording must never light the guest's indicator — an indicator that can be lit \
         without a recording is one the guest learns to ignore"
    );

    stop.store(true, Ordering::Relaxed);
    drop(c);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent).await;
    // Nothing may have been written anywhere under the session's root.
    if root.exists() {
        let stray: Vec<_> = walk(&root)
            .into_iter()
            .filter(|p| {
                matches!(p.extension().and_then(|s| s.to_str()), Some("ivf") | Some("json"))
            })
            .collect();
        assert!(stray.is_empty(), "a refused recording left files behind: {stray:?}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_ends_while_recording_still_finalizes_the_artifact() {
    // The path nobody sends a message on. A recording is stopped by the operator on the happy path
    // and by TEARDOWN on every other one — peer gone, guest End, max-session. Without the teardown
    // hook the writer thread is dropped holding an IVF whose header still says zero frames, and no
    // sidecar at all: the file plays as empty and nothing on the machine knows when to delete it.
    // So this test kills the controller instead of asking politely.
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_rec_tdn_e2e_{}", uuid::Uuid::new_v4()));
    let rec_dir = root.join("recordings");
    let flags = Arc::new(Mutex::new(RecordingFlags::default()));
    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent = spawn_agent(
        url.clone(),
        device,
        stop.clone(),
        root.clone(),
        Some(rec_dir.clone()),
        Arc::clone(&flags),
    );
    let mut c = connect_controller(&url, device).await;

    send_control(&mut c, &ControlMessage::StartRecording).await;
    match recv_control(&mut c, 10).await.expect("a reply to StartRecording") {
        ControlMessage::RecordingStarted { .. } => {}
        other => panic!("expected RecordingStarted, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The session ends WITHOUT a StopRecording — the controller drops its transport and the agent's
    // own stop flag fires, which is the `stop`/max-session teardown trigger.
    //
    // Deliberately not relying on the dropped peer alone. It does end the session, but only once
    // ICE gives up on a connection whose other end vanished without a close — tens of seconds,
    // wall-clock, and unbounded from this test's point of view. The teardown BLOCK is shared by
    // every exit path (it sits after the select! loop, and there is only one way out of that
    // function), so which trigger fires it is not what this test is about; a deterministic one just
    // means the assertions below are about the recorder rather than about ICE timers.
    drop(c);
    stop.store(true, Ordering::Relaxed);
    let ended = tokio::time::timeout(Duration::from_secs(30), agent).await;
    assert!(ended.is_ok(), "the agent session must end and run its teardown");

    let side = read_sidecar(&rec_dir);
    assert_eq!(side.segments.len(), 1, "the segment was finalized, not abandoned");
    let seg = &side.segments[0];
    assert!(seg.frames >= 5, "frames reached the file before teardown, got {}", seg.frames);
    let bytes = std::fs::read(rec_dir.join(&seg.file)).expect("read the IVF file");
    let (_, _, header_frames) = ivf_header(&bytes);
    assert_eq!(
        u64::from(header_frames),
        seg.frames,
        "the header's frame count was patched — an abandoned writer leaves it at 0"
    );
    assert_eq!(
        rmt_agent_core::file_transfer::sha256_hex(&bytes),
        seg.sha256,
        "the digest covers the FINALIZED bytes"
    );
    assert_eq!(
        side.truncated, None,
        "a session ending is not a truncation: every frame the tee accepted reached the file"
    );
    assert_eq!(
        flags.lock().unwrap().calls,
        vec![true, false],
        "the guest's window is told the recording stopped even though nothing asked it to"
    );

    stop.store(true, Ordering::Relaxed);
    let _ = std::fs::remove_dir_all(&root);
}

/// Every file under `dir`, recursively.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
