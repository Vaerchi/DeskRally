//! End-to-end live-capture streaming test (M1 deliverable): the agent captures THIS machine's real
//! display with the product's own desktop-following capturer, drives it through
//! [`rmt_agent_windows::host::stream_screen`]
//! (capture → VP8 encode → WebRTC video track), and a controller peer receives it as decodable
//! VP8 RTP. Mirrors `rmt-transport-webrtc`'s `video_track_flows_over_webrtc`, but with REAL pixels
//! instead of a `SyntheticCapturer`.
//!
//! It **self-skips** (prints a `SKIP:` line and returns green) when either half of the hardware/
//! environment isn't present, so the default suite stays green:
//!   * no signaling server reachable (start `server/signaling`), OR
//!   * `DxgiCapturer::new()` fails (Session 0 / no interactive display), or the display goes away
//!     mid-test (a sleeping monitor stops Desktop Duplication). A display that is merely IDLE is
//!     NOT a skip — the streaming capturer falls back to GDI, so a motionless screen still streams.
//!
//! To run it for real (needs a display in the interactive session + a signaling server):
//! ```
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_stream -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use rmt_agent_windows::capture::{CaptureError, DxgiCapturer};
use rmt_agent_windows::host::stream_screen;
use rmt_protocol::DeviceId;
use rmt_transport_webrtc::{Role, WebRtcTransport};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_screen_streams_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    // Prove a real display is capturable before we commit to the full flow. This also warms the
    // duplication object so the streaming loop's first AcquireNextFrame returns pixels promptly.
    let mut capturer = match DxgiCapturer::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: DxgiCapturer::new() failed (Session 0 / no display?): {e}");
            return;
        }
    };
    // ONE acquire is not a fair test of a display, and reading it as one made this test SKIP on any
    // machine whose screen happened to be still — silently losing the only live-capture coverage
    // there is. Two reasons a healthy display yields nothing: DXGI's first acquire after
    // `DuplicateOutput` reports "no change" by design (the surface is blank), and DXGI yields only
    // on a screen CHANGE, so an idle desktop keeps reporting it.
    //
    // So retry briefly — and treat "no new frame" as PROOF OF A DISPLAY rather than a reason to
    // skip. Creating the duplication at all is the part that requires one; `Ok(None)` means the
    // duplication exists and the screen is simply still. Only a hard error means Session 0 / no
    // display, and only that skips.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut live: Option<(u32, u32, usize)> = None;
    loop {
        match capturer.capture_frame_typed(0) {
            Ok(Some(f)) => {
                live = Some((f.width, f.height, f.bytes.len()));
                break;
            }
            Ok(None) | Err(CaptureError::Timeout) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("SKIP: no capturable display (Session 0 / no display?): {e}");
                return;
            }
        }
    }
    match live {
        Some((w, h, n)) => {
            eprintln!("live capture OK: {w}x{h} ({n} bytes) — starting stream")
        }
        // Deliberately NOT a skip: the duplication was created, so a display is there.
        None => eprintln!(
            "live capture: display present but idle (no screen change in 3s) — streaming anyway"
        ),
    }

    // Release the preflight duplication BEFORE the streaming capturer builds its own: an output can
    // be duplicated only once per process, and holding both makes the second `DuplicateOutput` fail
    // with E_INVALIDARG against a display that is perfectly healthy.
    drop(capturer);

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // Agent: run the real streaming driver against the capturer the PRODUCT uses — the
    // desktop-following tier selector, not a bare `DxgiCapturer`.
    //
    // It used to be the bare one, and that made the test hostage to whether anything happened to
    // move on screen while it ran: DXGI hands back a frame only on a desktop CHANGE, so a still
    // screen starves it and there is nothing to stream. (It passed anyway for a long time only
    // because every pointer-move and metadata-only acquire was being read back and sent as a full
    // duplicate frame — the test was green on frames that carried no new picture.)
    //
    // `FollowingCapturer` cannot starve: DXGI serves it while the screen is changing and GDI serves
    // it when the screen is still. So the test is deterministic, AND it now exercises the tier
    // selection, the monitor-id resolution and the desktop following that a real session depends
    // on, instead of one tier in isolation.
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let live = rmt_agent_windows::following_capturer::FollowingCapturer::new();
        stream_screen(&agent_url, agent_device, live, 30, agent_stop).await
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    // Collect inbound RTP video packets from the live-captured VP8 track.
    let mut packets = 0usize;
    let mut bytes = 0usize;
    let mut payload_types: Vec<u8> = Vec::new();
    while packets < 20 {
        match tokio::time::timeout(Duration::from_secs(5), controller.recv_video_packet()).await {
            Ok(Some(p)) => {
                packets += 1;
                bytes += p.payload_len;
                if !payload_types.contains(&p.payload_type) {
                    payload_types.push(p.payload_type);
                }
            }
            _ => break,
        }
    }

    let codec = controller.negotiated_video_codec().await;

    // Stop the agent's stream and let it drain.
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    // A live-capture stream that delivered NOTHING is ambiguous: either the console became
    // uncapturable AFTER the preflight (the display locked / a fast-user-switch / Session-0 took
    // over mid-test — an ENVIRONMENT gate, exactly like the preflight checks above), or the
    // streaming path genuinely broke. A fresh capturer decides it: if it too can't grab a frame the
    // live display is gone → gate (using the wording `verify-all.ps1`'s GatedSkipRegex recognises);
    // if it CAN still capture, a zero-packet stream is a real regression and must red the build.
    if packets == 0 {
        // A capturer that cannot starve delivered nothing, so the only remaining innocent
        // explanation is that the display itself went away mid-test. A fresh capturer decides it.
        //
        // The cause is usually NOT a locked console — that guess sent one investigation down the
        // wrong path. On this box the monitor powers off after 180 s (powercfg SUB_VIDEO/VIDEOIDLE),
        // and Desktop Duplication stops delivering when the display sleeps even though the session
        // stays unlocked and Active.
        let display_gone = match DxgiCapturer::new() {
            // A hard error means no capturable display. "No new frame" does NOT: it means the
            // display is there and still, which `FollowingCapturer` handles via GDI — so it stays
            // a real failure rather than becoming a gate.
            Ok(mut c) => matches!(c.capture_frame_typed(0), Err(CaptureError::Unavailable(_)))
                || matches!(c.capture_frame_typed(0), Err(CaptureError::Windows(_))),
            Err(_) => true,
        };
        if display_gone {
            // Wording `verify-all.ps1`'s GatedSkipRegex recognises.
            eprintln!(
                "SKIP: first live capture failed (live display no longer capturable mid-test — \
                 monitor asleep? check powercfg SUB_VIDEO/VIDEOIDLE; also Session 0 / locked console)"
            );
            return;
        }
    }
    assert!(
        packets >= 10,
        "expected inbound VP8 RTP packets from live capture, got {packets}"
    );
    let codec = codec.expect("an inbound video track was negotiated");
    assert_eq!(
        codec.mime_type, "video/VP8",
        "live capture must stream VP8, got {}",
        codec.mime_type
    );
    assert_eq!(
        payload_types,
        vec![codec.payload_type],
        "every RTP packet carried the negotiated VP8 payload type {} (saw {payload_types:?})",
        codec.payload_type
    );
    eprintln!(
        "LIVE SCREEN OVER WEBRTC: {packets} RTP packets, {bytes} bytes of {} (payload type {}) from real screen capture",
        codec.mime_type, codec.payload_type
    );
}
