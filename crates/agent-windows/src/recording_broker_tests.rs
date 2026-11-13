// Tests for recording_broker private helpers and wire protocol.
// Included as `mod tests` inside recording_broker; `super::` is the broker module.
use super::{
    client_protocol, receive, send, validate_frame, validate_start, verify_server, ClientSink,
    Reply, Request,
};
use crate::recording::Sidecar;
use rmt_transport_webrtc::video::{RecordedFrame, RecordingSink};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

const DEV: &str = "550e8400-e29b-41d4-a716-446655440000";
const SES: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const MAX_MICROS: u64 = 3_600_000_000; // MAX_DURATION = 3600 s in µs

fn fake_sidecar() -> Sidecar {
    Sidecar {
        kind: "recording".into(),
        device_id: DEV.into(),
        session_id: None,
        started_at_unix_ms: 0,
        ended_at_unix_ms: 1,
        delete_after_unix_ms: 9999,
        segments: vec![],
        truncated: None,
        dropped_frames: 0,
        disclaimer: "test".into(),
    }
}

fn make_sink(cap: usize) -> (Arc<ClientSink>, tokio::sync::mpsc::Receiver<Request>) {
    let (tx, rx) = tokio::sync::mpsc::channel(cap);
    let sink = Arc::new(ClientSink {
        tx,
        epoch: Mutex::new(None),
        failed: AtomicBool::new(false),
        finish: AtomicBool::new(false),
    });
    (sink, rx)
}

// ── validate_start ──────────────────────────────────────────────────────────

#[test]
fn validate_start_rejects_wrong_version() {
    assert!(validate_start(0, DEV, None).is_err(), "version 0 must fail");
    assert!(validate_start(2, DEV, None).is_err(), "version 2 must fail");
}

#[test]
fn validate_start_rejects_invalid_device_uuid() {
    assert!(validate_start(1, "not-a-uuid", None).is_err());
    assert!(validate_start(1, "", None).is_err());
    assert!(validate_start(1, "123", None).is_err());
}

#[test]
fn validate_start_rejects_invalid_session_uuid() {
    assert!(validate_start(1, DEV, Some("bad-session")).is_err());
}

#[test]
fn validate_start_accepts_valid() {
    assert!(validate_start(1, DEV, None).is_ok());
    assert!(validate_start(1, DEV, Some(SES)).is_ok());
}

// ── validate_frame ──────────────────────────────────────────────────────────

#[test]
fn validate_frame_rejects_time_regression() {
    let data = vec![1u8; 100];
    assert!(validate_frame(50, 100, 1280, 720, &data).is_err(), "micros < previous must fail");
}

#[test]
fn validate_frame_rejects_zero_dimensions() {
    let data = vec![1u8; 100];
    assert!(validate_frame(0, 0, 0, 720, &data).is_err());
    assert!(validate_frame(0, 0, 1280, 0, &data).is_err());
}

#[test]
fn validate_frame_rejects_max_dimension_exceeded() {
    let data = vec![1u8; 100];
    assert!(validate_frame(0, 0, 16385, 720, &data).is_err(), "width >16384 must fail");
    assert!(validate_frame(0, 0, 1280, 16385, &data).is_err(), "height >16384 must fail");
}

#[test]
fn validate_frame_accepts_max_dimensions() {
    let data = vec![1u8; 100];
    assert!(validate_frame(0, 0, 16384, 16384, &data).is_ok());
}

#[test]
fn validate_frame_rejects_max_duration_exceeded() {
    let data = vec![1u8; 100];
    assert!(validate_frame(MAX_MICROS + 1, 0, 1280, 720, &data).is_err());
}

#[test]
fn validate_frame_accepts_max_duration_boundary() {
    let data = vec![1u8; 100];
    assert!(validate_frame(MAX_MICROS, 0, 1280, 720, &data).is_ok());
}

#[test]
fn validate_frame_rejects_empty_data() {
    assert!(validate_frame(0, 0, 1280, 720, &[]).is_err(), "empty data must fail");
}

#[test]
fn validate_frame_rejects_oversized_data() {
    let data = vec![0u8; super::MAX_FRAME + 1];
    assert!(validate_frame(0, 0, 1280, 720, &data).is_err());
}

#[test]
fn validate_frame_accepts_valid() {
    let data = vec![1u8; 512];
    assert!(validate_frame(1000, 0, 1280, 720, &data).is_ok());
    assert!(validate_frame(1000, 1000, 1280, 720, &data).is_ok(), "equal micros must be accepted");
}

// ── Request serde: deny_unknown_fields ─────────────────────────────────────

#[test]
fn request_serde_denies_path_field() {
    // `directory` is a real Reply::Ready field; must not be accepted in Request::Start.
    let json = r#"{"op":"Start","version":1,"device":"550e8400-e29b-41d4-a716-446655440000","session":null,"directory":"/tmp/bad"}"#;
    assert!(
        serde_json::from_str::<Request>(json).is_err(),
        "path field `directory` must be rejected by deny_unknown_fields"
    );
}

#[test]
fn request_serde_roundtrip_poll() {
    let s = serde_json::to_string(&Request::Poll).unwrap();
    let back: Request = serde_json::from_str(&s).unwrap();
    assert!(matches!(back, Request::Poll));
}

// ── send / receive wire protocol ────────────────────────────────────────────

#[tokio::test]
async fn send_receive_duplex_roundtrip() {
    let (mut a, mut b) = tokio::io::duplex(8192);
    send(&mut a, &Reply::Alive).await.unwrap();
    let got: Reply = receive(&mut b).await.unwrap();
    assert!(matches!(got, Reply::Alive));
}

#[tokio::test]
async fn receive_zero_length_fails_with_invalid_length_error() {
    let (mut writer, mut reader) = tokio::io::duplex(8192);
    use tokio::io::AsyncWriteExt;
    writer.write_u32_le(0).await.unwrap();
    let _guard = writer; // keep open so EOF cannot be the rejection trigger
    let err = receive::<Request, _>(&mut reader).await.expect_err("zero length must fail");
    assert!(
        err.to_string().contains("invalid recording broker message length"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn receive_oversized_length_fails_with_invalid_length_error() {
    let (mut writer, mut reader) = tokio::io::duplex(65536);
    use tokio::io::AsyncWriteExt;
    writer.write_u32_le((super::MAX_MESSAGE + 1) as u32).await.unwrap();
    let _guard = writer; // keep open so the length guard, not a body error, fires
    let err = receive::<Request, _>(&mut reader).await.expect_err("oversized length must fail");
    assert!(
        err.to_string().contains("invalid recording broker message length"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn receive_truncated_body_times_out_in_3s_window() {
    let (mut writer, mut reader) = tokio::io::duplex(8192);
    use tokio::io::AsyncWriteExt;
    writer.write_u32_le(64).await.unwrap();
    let _guard = writer; // hold open — must block on data, not EOF
    let start = Instant::now();
    let err = receive::<Request, _>(&mut reader).await.expect_err("truncated body must fail");
    let elapsed = start.elapsed();
    assert!(err.to_string().contains("timeout"), "expected timeout error, got: {err}");
    assert!(elapsed >= Duration::from_millis(2500), "fired too early: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "took too long: {elapsed:?}");
}

// ── ClientSink: full queue flips failed flag ────────────────────────────────

#[test]
fn client_sink_full_queue_sets_failed() {
    let (sink, _rx) = make_sink(1);
    let d1 = vec![1u8; 512];
    sink.offer(RecordedFrame { data: &d1, keyframe: true, at: Instant::now(), width: 640, height: 480 });
    assert!(!sink.failed.load(Ordering::Acquire), "first offer must succeed");
    let d2 = vec![2u8; 512];
    sink.offer(RecordedFrame { data: &d2, keyframe: false, at: Instant::now(), width: 640, height: 480 });
    let d3 = vec![3u8; 512];
    sink.offer(RecordedFrame { data: &d3, keyframe: false, at: Instant::now(), width: 640, height: 480 });
    assert!(sink.failed.load(Ordering::Acquire), "failed must be set after queue overflow");
}

// ── allow_cli_recording defaults to false ──────────────────────────────────

#[test]
fn config_allow_cli_recording_defaults_off() {
    let cfg: crate::config::HelperConfig = serde_json::from_str("{}").unwrap();
    assert!(!cfg.allow_cli_recording, "allow_cli_recording must default to false");
}

// ── verify_server: rejects a standard-user-owned named pipe ────────────────

#[tokio::test]
async fn verify_server_rejects_user_owned_pipe() {
    let pipe_name = format!(r"\\.\pipe\DeskRallyTest.RecBroker.{}", uuid::Uuid::new_v4());
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .expect("create test named pipe");
    let name2 = pipe_name.clone();
    let client_task = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
        for _ in 0..30 {
            match ClientOptions::new().open(&name2) {
                Ok(c) => return Ok(c),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        ClientOptions::new().open(&name2)
    });
    tokio::time::timeout(Duration::from_secs(5), server.connect())
        .await.expect("server.connect timed out").expect("server accept");
    let client = tokio::time::timeout(Duration::from_secs(5), client_task)
        .await.expect("client_task timed out").unwrap().expect("client connect");
    let err = verify_server(&client).expect_err("verify_server must reject a user-owned pipe");
    assert!(err.to_string().contains("SYSTEM"), "got: {err}");
}

// ── client_protocol duplex tests ────────────────────────────────────────────

// Helper: run a fake server peer on one side of a duplex, return the join handle.
// The peer_fn receives the server half and drives the conversation.
async fn run_protocol<F, Fut>(
    peer_fn: F,
) -> (
    std::io::Result<Sidecar>,
    std::sync::mpsc::Receiver<(i64, std::path::PathBuf)>,
)
where
    F: FnOnce(tokio::io::DuplexStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (client_half, server_half) = tokio::io::duplex(65536);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (sink, rx) = make_sink(8);
    let start_req = Request::Start {
        version: 1,
        device: DEV.into(),
        session: None,
    };
    let peer = tokio::spawn(peer_fn(server_half));
    let mut client_half = client_half;
    let result = client_protocol(&mut client_half, start_req, rx, &sink, ready_tx).await;
    peer.await.unwrap(); // fatal: peer assertion failures must not be swallowed
    (result, ready_rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_start_receives_ready_before_exposing_ready_channel() {
    // Real ordering test: peer observes ready_rx empty before Ready is sent,
    // then non-empty after the client's first loop message confirms delivery.
    // No timing-based finish: request_finish is called only after the ordering
    // check passes, ensuring Stop(false) is clean and deterministic.
    let (mut client_half, server_half) = tokio::io::duplex(65536);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<(i64, std::path::PathBuf)>(1);
    let (sink, rx) = make_sink(8);
    let sink_peer = sink.clone();
    let start_req = Request::Start { version: 1, device: DEV.into(), session: None };
    let sidecar = fake_sidecar();

    let client_fut = client_protocol(&mut client_half, start_req, rx, &sink, ready_tx);
    let peer_fut = async move {
        let mut srv = server_half;
        let _start: Request = receive(&mut srv).await.unwrap();

        // Ordering assertion 1: ready must NOT be delivered before Ready is sent.
        assert!(
            ready_rx.try_recv().is_err(),
            "ready channel must be empty before Ready is sent"
        );

        send(&mut srv, &Reply::Ready { started_at: 42, directory: "C:\\fake".into() })
            .await
            .unwrap();

        // client_protocol calls ready.send() before entering the loop that sends Poll.
        // Receiving the first loop message is therefore a sequenced-after proof.
        let first: Request = receive(&mut srv).await.unwrap();
        assert!(
            matches!(first, Request::Poll | Request::Frame { .. }),
            "expected Poll or Frame as first loop message, got: {first:?}"
        );

        // Ordering assertion 2: ready must be delivered by the time the first loop message arrives.
        let (ts, dir) = ready_rx
            .try_recv()
            .expect("ready channel must be populated after first loop message");
        assert_eq!(ts, 42, "started_at must match Ready payload");
        assert_eq!(
            dir,
            std::path::PathBuf::from("C:\\fake"),
            "directory must match Ready payload"
        );

        // Signal finish and complete the protocol cleanly (no timing sleep).
        sink_peer.request_finish();
        send(&mut srv, &Reply::Alive).await.unwrap(); // reply to `first`

        let stop: Request = receive(&mut srv).await.unwrap();
        assert!(
            matches!(stop, Request::Stop { truncated: false }),
            "expected clean Stop, got: {stop:?}"
        );
        send(&mut srv, &Reply::Finished { sidecar }).await.unwrap();
    };

    let (client_result, ()) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(client_fut, peer_fut) })
            .await
            .expect("test timed out");

    assert!(client_result.is_ok(), "protocol must succeed: {:?}", client_result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_unexpected_startup_reply_fails_no_ready() {
    let (proto_result, ready_rx) = tokio::time::timeout(Duration::from_secs(5), async {
        run_protocol(|mut srv| async move {
            let _start: Request = receive(&mut srv).await.unwrap();
            // Reply with Alive instead of Ready — protocol violation.
            send(&mut srv, &Reply::Alive).await.unwrap();
        })
        .await
    })
    .await
    .expect("test timed out");

    assert!(proto_result.is_err(), "unexpected startup reply must fail");
    assert!(
        ready_rx.try_recv().is_err(),
        "ready channel must NOT be populated on startup failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_disconnect_during_startup_fails_no_ready() {
    let (proto_result, ready_rx) = tokio::time::timeout(Duration::from_secs(5), async {
        run_protocol(|mut srv| async move {
            let _start: Request = receive(&mut srv).await.unwrap();
            drop(srv); // close without replying
        })
        .await
    })
    .await
    .expect("test timed out");

    assert!(proto_result.is_err(), "disconnect during startup must fail");
    assert!(
        ready_rx.try_recv().is_err(),
        "ready channel must NOT be populated on disconnect"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_clean_stop_drains_prequeued_frame_before_stop() {
    // Pre-queue a frame in the channel before the protocol even starts so the loop
    // must drain it and only then send Stop(false).
    let (client_half, server_half) = tokio::io::duplex(65536);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (sink, rx) = make_sink(8);

    // Pre-queue a frame and then request finish BEFORE the protocol thread reads it.
    let frame_data = vec![9u8; 512];
    sink.offer(RecordedFrame {
        data: &frame_data,
        keyframe: true,
        at: Instant::now(),
        width: 1280,
        height: 720,
    });
    sink.request_finish();

    let start_req = Request::Start { version: 1, device: DEV.into(), session: None };
    let sidecar = fake_sidecar();
    let peer = tokio::spawn(async move {
        let mut srv = server_half;
        let _start: Request = receive(&mut srv).await.unwrap();
        send(&mut srv, &Reply::Ready { started_at: 1, directory: "C:\\fake".into() })
            .await.unwrap();
        // Expect a Frame message before Stop.
        let req: Request = receive(&mut srv).await.unwrap();
        assert!(matches!(req, Request::Frame { .. }), "expected Frame before Stop, got: {req:?}");
        send(&mut srv, &Reply::Alive).await.unwrap();
        // Now expect Stop(false) — clean, not truncated.
        let req: Request = receive(&mut srv).await.unwrap();
        assert!(matches!(req, Request::Stop { truncated: false }), "expected Stop(false), got: {req:?}");
        send(&mut srv, &Reply::Finished { sidecar }).await.unwrap();
    });

    let mut client_half = client_half;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client_protocol(&mut client_half, start_req, rx, &sink, ready_tx),
    )
    .await
    .expect("test timed out");

    peer.await.unwrap();
    assert!(result.is_ok(), "clean drain must succeed: {:?}", result);
    assert!(ready_rx.try_recv().is_ok(), "ready channel must be populated");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_failed_sink_sends_stop_truncated() {
    let (client_half, server_half) = tokio::io::duplex(65536);
    let (ready_tx, _ready_rx) = std::sync::mpsc::sync_channel(1);
    let (sink, rx) = make_sink(1);
    // Force failed BEFORE the protocol loop by pre-filling and overflowing the channel.
    let d = vec![0u8; 512];
    let t = Instant::now();
    sink.offer(RecordedFrame { data: &d, keyframe: true, at: t, width: 640, height: 480 });
    sink.offer(RecordedFrame { data: &d, keyframe: false, at: t, width: 640, height: 480 });
    sink.offer(RecordedFrame { data: &d, keyframe: false, at: t, width: 640, height: 480 });
    assert!(sink.failed.load(Ordering::Acquire), "sink must be failed before protocol");

    let start_req = Request::Start { version: 1, device: DEV.into(), session: None };
    let sidecar = fake_sidecar();
    let peer = tokio::spawn(async move {
        let mut srv = server_half;
        let _start: Request = receive(&mut srv).await.unwrap();
        send(&mut srv, &Reply::Ready { started_at: 1, directory: "C:\\fake".into() })
            .await.unwrap();
        let req: Request = receive(&mut srv).await.unwrap();
        assert!(
            matches!(req, Request::Stop { truncated: true }),
            "expected Stop(true) from failed sink, got: {req:?}"
        );
        send(&mut srv, &Reply::Finished { sidecar }).await.unwrap();
    });

    let mut client_half = client_half;
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client_protocol(&mut client_half, start_req, rx, &sink, ready_tx),
    )
    .await
    .expect("test timed out");

    peer.await.unwrap();
    assert!(result.is_ok(), "protocol with failed sink must still return sidecar: {:?}", result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_unexpected_finished_before_stop_fails() {
    let (proto_result, _ready_rx) = tokio::time::timeout(Duration::from_secs(5), async {
        run_protocol(|mut srv| async move {
            let _start: Request = receive(&mut srv).await.unwrap();
            send(&mut srv, &Reply::Ready { started_at: 1, directory: "C:\\fake".into() })
                .await.unwrap();
            // Read the first loop message (Poll or Frame), reply with Finished prematurely.
            let _req: Request = receive(&mut srv).await.unwrap();
            let sc = fake_sidecar();
            send(&mut srv, &Reply::Finished { sidecar: sc }).await.unwrap();
        })
        .await
    })
    .await
    .expect("test timed out");

    assert!(
        proto_result.is_err(),
        "unexpected Finished before Stop must fail: {:?}", proto_result
    );
}

#[test]
fn offer_after_request_finish_is_not_queued() {
    let (sink, mut rx) = make_sink(8);
    sink.request_finish();
    let d = vec![1u8; 512];
    sink.offer(RecordedFrame { data: &d, keyframe: true, at: Instant::now(), width: 640, height: 480 });
    // Channel must be empty — the offer must have been dropped.
    assert!(rx.try_recv().is_err(), "offer after request_finish must not reach the channel");
}

// ── Physical identity helpers (used by the two opt-in tests below) ──────────

/// Returns true iff the current process token's user SID is NT AUTHORITY\SYSTEM.
fn current_process_is_system() -> bool {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            self, CreateWellKnownSid, EqualSid, GetTokenInformation,
            PSID, TOKEN_QUERY, TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .expect("current_process_is_system: OpenProcessToken failed");
        let mut buf = [0usize; 32];
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            Security::TokenUser,
            Some(buf.as_mut_ptr().cast()),
            std::mem::size_of_val(&buf) as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        if !ok || (returned as usize) < std::mem::size_of::<TOKEN_USER>() {
            panic!("current_process_is_system: GetTokenInformation failed or returned too few bytes");
        }
        let user_sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut sys_buf = [0u64; 16];
        let sys_sid = PSID(sys_buf.as_mut_ptr().cast());
        let mut size = std::mem::size_of_val(&sys_buf) as u32;
        CreateWellKnownSid(Security::WinLocalSystemSid, None, sys_sid, &mut size)
            .expect("current_process_is_system: CreateWellKnownSid failed");
        EqualSid(user_sid, sys_sid).is_ok()
    }
}

/// Returns true iff the current process token has a full (elevated) privilege level.
fn current_process_is_elevated() -> bool {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .expect("current_process_is_elevated: OpenProcessToken failed");

        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elev as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        assert!(ok, "current_process_is_elevated: GetTokenInformation failed");
        elev.TokenIsElevated != 0
    }
}

// ── Physical opt-in tests — both #[ignore]; Codex runs via bounded scheduled task ──

/// Physical server-side test: must be invoked as NT AUTHORITY\SYSTEM.
///
/// Starts the actual `ServiceWorker` (creates the SDDL-protected production named pipe,
/// owns the service-storage root), prints `SERVER_STARTED` so the Codex harness knows to
/// launch `physical_interactive_client`, then stays alive for up to 60 seconds before
/// dropping cleanly. No service registration, no elevation, no config mutation.
///
/// Run with:
///   cargo test -p rmt-agent-windows --lib recording_broker::tests::physical_system_server
///   --no-fail-fast -- --ignored --nocapture
#[test]
#[ignore = "physical: must run as NT AUTHORITY\\SYSTEM via bounded scheduled task; do not invoke directly"]
fn physical_system_server() {
    assert!(
        current_process_is_system(),
        "physical_system_server must run as NT AUTHORITY\\SYSTEM — current process is not SYSTEM"
    );

    let worker = super::ServiceWorker::start()
        .expect("ServiceWorker::start() failed — check C:\\rmt-agent\\cli-recordings ACL");

    // Signal readiness to the Codex harness before blocking.
    println!("SERVER_STARTED");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    // Stay alive so the client test can connect and complete. Cap at 60 s.
    std::thread::sleep(Duration::from_secs(60));

    // Drop triggers the stop flag and waits up to 8 s for the broker thread.
    drop(worker);
}

/// Physical client-side test: must run as an ordinary interactive user (non-SYSTEM, non-elevated)
/// while `physical_system_server` is listening on the production named pipe.
///
/// Connects to the running ServiceWorker via the production broker pipe, offers one small
/// synthetic frame (container bytes, no real capture), stops cleanly, and asserts:
/// - sidecar has ≥1 segment, zero dropped frames, no truncation
/// - sidecar session_id matches the requested UUID
/// - recording directory is under C:\rmt-agent\cli-recordings (fixed broker root)
/// - direct `read_dir` on the recording directory is denied for the ordinary token
///
/// Run with (after physical_system_server is listening):
///   cargo test -p rmt-agent-windows --lib recording_broker::tests::physical_interactive_client
///   --no-fail-fast -- --ignored --nocapture
#[test]
#[ignore = "physical: must run as interactive standard user while physical_system_server is listening"]
fn physical_interactive_client() {
    assert!(
        !current_process_is_system(),
        "physical_interactive_client must NOT run as SYSTEM"
    );
    assert!(
        !current_process_is_elevated(),
        "physical_interactive_client must NOT run elevated"
    );

    let device = uuid::Uuid::new_v4().to_string();
    let session = uuid::Uuid::new_v4().to_string();

    // Connect to the running ServiceWorker via the production named pipe.
    // dir is ignored when via_service=true (RemoteRecorder drives the path).
    let recorder = super::SessionRecorder::start(
        std::path::Path::new("."),
        true, // via_service: use production broker pipe
        &device,
        Some(&session),
        crate::recording::DEFAULT_MAX_BYTES,
        crate::recording::DEFAULT_MIN_FREE_BYTES,
    )
    .expect("SessionRecorder::start (service path) failed — is physical_system_server running?");

    // Offer one small dummy frame: synthetic container bytes, 2×2, keyframe.
    // No real video capture; tests the end-to-end path without a live desktop.
    let frame_data = [0x1a_u8, 0x45, 0xdf, 0xa3, 0x01, 0x00, 0x00, 0x00];
    recorder.sink().offer(RecordedFrame {
        data: &frame_data,
        keyframe: true,
        at: Instant::now(),
        width: 2,
        height: 2,
    });

    let rec_dir = recorder.dir().to_path_buf();
    let started_at = recorder.started_at_unix_ms();

    let sidecar = recorder.stop().expect("recorder.stop() failed");

    // No truncation.
    assert!(
        sidecar.truncated.is_none(),
        "sidecar must not be truncated; got: {:?}",
        sidecar.truncated
    );
    // Session and device IDs round-trip.
    assert_eq!(
        sidecar.session_id.as_deref(),
        Some(session.as_str()),
        "sidecar session_id must match requested session UUID"
    );
    assert_eq!(sidecar.device_id, device, "sidecar device_id must match requested device UUID");
    // Exactly one segment with exactly one frame (single dummy frame offered).
    assert_eq!(sidecar.segments.len(), 1, "sidecar must contain exactly one segment");
    assert_eq!(sidecar.segments[0].frames, 1, "segment must contain exactly one frame");
    // No frames dropped.
    assert_eq!(sidecar.dropped_frames, 0, "no frames must be dropped");
    // Recording directory is under the fixed broker root.
    let broker_root = std::path::Path::new(super::DIRECTORY);
    assert!(
        rec_dir.starts_with(broker_root),
        "recording dir {:?} must be under broker root {:?}",
        rec_dir,
        broker_root
    );
    // Direct read_dir on the service-owned recording directory must be denied to an ordinary token.
    let deny = std::fs::read_dir(&rec_dir);
    assert!(
        deny.is_err(),
        "read_dir on {:?} must be denied for a standard user; got Ok",
        rec_dir
    );
    assert_eq!(
        deny.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied,
        "expected PermissionDenied on read_dir"
    );

    // Print path and metadata — no content read.
    println!("recording_path:      {}", rec_dir.display());
    println!("started_at_unix_ms:  {started_at}");
    println!("segment_count:       {}", sidecar.segments.len());
    println!("dropped_frames:      {}", sidecar.dropped_frames);
    println!("truncated:           {:?}", sidecar.truncated);
    std::io::Write::flush(&mut std::io::stdout()).ok();
}
