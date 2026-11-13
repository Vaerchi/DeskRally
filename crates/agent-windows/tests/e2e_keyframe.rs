//! End-to-end **keyframe policy** test over a REAL WebRTC session against
//! [`rmt_agent_windows::host::serve_session_with_ice`].
//!
//! Why it exists: every keyframe on the constant-bitrate stream is coded coarse (measured: ~33 dB
//! against a ~50 dB steady state, see `vp8::idle_quality`), so the old 4-second time backstop put a
//! visible blur flash on the screen every four seconds, which the operator reported as "a pulse".
//! The backstop is now a 60 s last resort, and recovery is receiver-driven. This test proves both
//! halves on the real stack, not on the encoder in isolation:
//!
//! 1. **No cadence.** 6.5 s of streaming carries only the session's initial keyframe. The old 4 s
//!    backstop shows a second one around t = 4 s and fails here.
//! 2. **Negative control.** A PLI addressed to a BOGUS media SSRC produces no keyframe, so the
//!    positive result below is caused by the PLI reaching OUR stream, not by something else.
//! 3. **Receiver-driven recovery.** A real RTCP PLI, written by the controller through
//!    `WebRtcTransport::send_pli` (`RTCPeerConnection::write_rtcp`) and addressed to the agent's real
//!    video SSRC, travels the
//!    interceptor chain, DTLS/SRTP, the agent's SRTCP demux and its `RTCRtpSender::read` loop (every
//!    layer production code) and must produce a keyframe within 1.5 s.
//!
//! To run it for real (it self-skips without signaling, and `verify-all.ps1` treats a skip as a
//! failure):
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe -insecure-no-ticket-verification -insecure-no-agent-auth
//! cargo test -p rmt-agent-windows --test e2e_keyframe -- --nocapture
//! ```

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::DeviceId;
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

/// Bounded by attempts, not a wall clock (one `connect` can itself take ~20 s; see e2e_quality).
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

/// Keyframe start times (seconds since `t0`) seen while draining video for `secs`. Inbound data
/// frames are drained too, so the data channel never backs up.
async fn keyframes_for(c: &mut WebRtcTransport, secs: f64, t0: Instant) -> Vec<f64> {
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(20), c.recv_video_packet()).await {
            Ok(Some(p)) => {
                if p.vp8.frame_start && p.vp8.keyframe {
                    out.push(t0.elapsed().as_secs_f64());
                }
                continue;
            }
            Ok(None) => break,
            Err(_) => {}
        }
        let _ = tokio::time::timeout(Duration::from_millis(5), c.recv_frame()).await;
    }
    out
}

async fn send_pli(c: &WebRtcTransport, media_ssrc: u32) {
    c.send_pli(media_ssrc).await.expect("write PLI");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyframes_come_from_the_receiver_not_a_timer() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }
    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let (agent_url, agent_stop) = (url.clone(), stop.clone());
    let agent = tokio::spawn(async move {
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session_with_ice(
            &agent_url,
            agent_device,
            SyntheticCapturer::new(640, 480, 300),
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink,
                transfer_dir: std::env::temp_dir().join("rmt_keyframe_e2e_unused"),
                ..Default::default()
            },
        )
        .await
    });

    let mut c = connect_controller(&url, agent_device).await;
    let t0 = Instant::now();

    // 1. No cadence: only the session's initial keyframe in 6.5 s (the old backstop fired at ~4 s).
    let first = keyframes_for(&mut c, 6.5, t0).await;
    assert_eq!(first.len(), 1, "expected only the initial keyframe in 6.5 s, saw them at {first:?}");

    let ssrc = c.inbound_video_ssrc().expect("the inbound video SSRC is known once video flows");

    // 2. Negative control: a PLI for some OTHER stream is not ours to answer.
    send_pli(&c, ssrc ^ 0x5A5A_5A5A).await;
    let bogus = keyframes_for(&mut c, 1.5, t0).await;
    assert!(bogus.is_empty(), "a PLI for a foreign SSRC produced keyframes at {bogus:?}");

    // 3. A real PLI for our stream produces a keyframe promptly.
    let sent_at = t0.elapsed().as_secs_f64();
    send_pli(&c, ssrc).await;
    let answered = keyframes_for(&mut c, 1.5, t0).await;
    assert!(
        !answered.is_empty(),
        "a PLI for our video SSRC (sent at {sent_at:.2}s) produced no keyframe within 1.5 s"
    );
    eprintln!("initial keyframe {first:?}; PLI at {sent_at:.2}s answered at {answered:?}");

    stop.store(true, Ordering::Relaxed);
    drop(c);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}
