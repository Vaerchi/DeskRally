//! End-to-end WebRTC transport test: two peers (agent + controller) rendezvous through the REAL
//! Go signaling server, negotiate a real WebRTC peer connection, and move frames over a live SCTP
//! data channel. Mirrors `agent-core/tests/e2e_relay.rs` — it self-skips when no signaling server
//! is listening, so the default suite stays green.
//!
//! To run it for real:
//! ```
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! # in another shell:
//! cargo test -p rmt-transport-webrtc --test e2e_webrtc -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

use std::time::Duration;

use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

fn signaling_url() -> String {
    std::env::var("SIGNALING_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string())
}

/// Probe whether a signaling server is reachable; if not, the test self-skips.
async fn signaling_reachable(url: &str) -> bool {
    tokio::time::timeout(Duration::from_millis(800), tokio_probe(url))
        .await
        .unwrap_or(false)
}

async fn tokio_probe(url: &str) -> bool {
    // A successful WebSocket upgrade is enough to know the server is up (dropping closes it).
    tokio_tungstenite::connect_async(url).await.is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_data_channel_through_signaling() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    const N: usize = 20;
    let agent_device = DeviceId::new();

    // Agent: register and wait to be reached, then receive N frames.
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let mut t = WebRtcTransport::connect(
            &agent_url,
            Role::dev_agent(agent_device, "ed25519:test-agent"),
        )
        .await
        .expect("agent connect");

        let mut got = Vec::with_capacity(N);
        for _ in 0..N {
            got.push(t.recv_frame().await.expect("agent recv"));
        }
        got
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Controller: reach the agent and send N frames.
    let mut controller = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    use rmt_agent_core::transport::Transport;
    for i in 0..N {
        let payload = format!("frame-{i}").into_bytes();
        controller
            .send_frame(Frame::new(ChannelId::Video, payload))
            .await
            .expect("controller send");
    }

    let got = tokio::time::timeout(Duration::from_secs(10), agent)
        .await
        .expect("agent task timed out")
        .expect("agent task panicked");

    assert_eq!(got.len(), N, "received all frames");
    for (i, frame) in got.iter().enumerate() {
        assert_eq!(frame.channel, ChannelId::Video);
        assert_eq!(
            &frame.payload[..],
            format!("frame-{i}").as_bytes(),
            "frame {i} intact and in order"
        );
    }
    eprintln!("RAN THROUGH REAL WEBRTC: {N} frames over a live data channel, in order");
}

/// The full secure stack: X25519 handshake + ChaCha20-Poly1305 sealing (the `agent-core::Session`)
/// carried over a real WebRTC data channel. Same crypto path as `e2e_relay`, different transport —
/// proving the `Transport` seam holds and the WebRTC link only ever moves ciphertext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_frames_over_webrtc() {
    use rmt_agent_core::{
        frame_number, Handshake, Role as CryptoRole, ScreenCapturer, Session, SyntheticCapturer,
    };
    use rmt_protocol::SessionId;

    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url}");
        return;
    }

    const N: u64 = 20;
    let agent_device = DeviceId::new();

    // Derive a shared session key pair out-of-band (signaling would broker the pubkeys).
    let id = SessionId::new();
    let controller_hs = Handshake::new(CryptoRole::Controller);
    let agent_hs = Handshake::new(CryptoRole::Agent);
    let cpub = controller_hs.public_bytes();
    let apub = agent_hs.public_bytes();
    let mut controller_session = Session::new(id, controller_hs.complete(&apub));
    let mut agent_session = Session::new(id, agent_hs.complete(&cpub));

    // Agent: connect, then seal + send N synthetic frames.
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let mut link = WebRtcTransport::connect(
            &agent_url,
            Role::dev_agent(agent_device, "ed25519:test-agent"),
        )
        .await
        .expect("agent connect");

        let mut cap = SyntheticCapturer::new(48, 48, 5);
        for _ in 0..N {
            let f = cap.capture_frame(0).expect("capture");
            agent_session
                .send(&mut link, ChannelId::Video, &f.bytes)
                .await
                .expect("agent sealed send");
        }
        // Hold open briefly so the last frames flush before teardown.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut link = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    for expected in 0..N {
        let (channel, plaintext) =
            tokio::time::timeout(Duration::from_secs(10), controller_session.recv(&mut link))
                .await
                .expect("recv timed out")
                .expect("controller recv+decrypt");
        assert_eq!(channel, ChannelId::Video);
        assert_eq!(
            frame_number(&plaintext),
            Some(expected),
            "frame {expected} decrypts intact and in order over WebRTC"
        );
    }

    agent.await.unwrap();
    eprintln!("SEALED OVER WEBRTC: {N} encrypted frames decrypted in order");
}

/// The video media-track path: the agent **VP8**-encodes captured frames and writes them to a
/// WebRTC video track; the controller receives them as RTP on an inbound track (what a browser
/// decodes natively into `<video>`). Proves capture → software VP8 → media track → receive, end to
/// end.
///
/// Crucially this asserts **which codec** is on the wire, not just that bytes flowed:
///   1. the negotiated `RTCRtpCodecParameters` for the inbound track must be `video/VP8`, and
///   2. every RTP packet's payload type must equal that codec's negotiated payload type.
///
/// A packet-count-only assertion passes identically for H.264 and VP8 and would have proved
/// nothing about this migration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn video_track_flows_over_webrtc() {
    use rmt_agent_core::{ScreenCapturer, SyntheticCapturer};

    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url}");
        return;
    }

    let agent_device = DeviceId::new();

    // Agent: connect, then encode + send ~60 frames (~1.2s of video) on the track.
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let link = WebRtcTransport::connect(
            &agent_url,
            Role::dev_agent(agent_device, "ed25519:test-agent"),
        )
        .await
        .expect("agent connect");

        let mut cap = SyntheticCapturer::new(128, 128, 7);
        for _ in 0..60 {
            let f = cap.capture_frame(0).expect("capture");
            let _ = link.send_video_frame(&f);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Keep the connection open so the last samples packetize and flush.
        tokio::time::sleep(Duration::from_millis(600)).await;
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    // Collect inbound RTP video packets, recording the payload type each one carried.
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

    let codec = controller
        .negotiated_video_codec()
        .await
        .expect("an inbound video track was negotiated");

    agent.await.unwrap();

    assert!(packets >= 10, "expected inbound video RTP packets, got {packets}");

    // (1) SDP settled on VP8 — not H.264, not VP9.
    assert_eq!(
        codec.mime_type, "video/VP8",
        "negotiated video codec must be VP8, got {}",
        codec.mime_type
    );
    assert_eq!(codec.clock_rate, 90000, "video clock rate");

    // (2) The bytes on the wire really were that codec's payload type.
    assert_eq!(
        payload_types,
        vec![codec.payload_type],
        "every RTP packet carried the negotiated VP8 payload type {} (saw {payload_types:?})",
        codec.payload_type
    );

    eprintln!(
        "VIDEO OVER WEBRTC: {packets} RTP packets, {bytes} bytes of {} (payload type {}) received",
        codec.mime_type, codec.payload_type
    );
}

/// The Opus AUDIO track flows over a real peer connection.
///
/// Mirrors `video_track_flows_over_webrtc`, and exists for the same reason: an audio track that is
/// negotiated away — because the offer carried no audio m-line, or the codec did not match —
/// produces a session that works, sounds like nothing, and reports no error anywhere. Only bytes
/// arriving at the far end distinguish that from a working one.
///
/// It feeds a TONE rather than silence on purpose. Opus with DTX collapses silence to one byte per
/// frame, so a silent test would pass on a stream carrying no audio at all — the assertion would be
/// satisfied by exactly the failure it is meant to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_track_flows_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url}");
        return;
    }

    let agent_device = DeviceId::new();

    // Agent: connect, then push ~1.5 s of a 440 Hz tone in RAGGED blocks — deliberately not frame
    // sized, because that is what WASAPI hands over and the accumulator is what makes it work.
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let link = WebRtcTransport::connect(
            &agent_url,
            Role::dev_agent(agent_device, "ed25519:test-agent"),
        )
        .await
        .expect("agent connect");

        let mut phase = 0f32;
        for i in 0..75 {
            // 401 and 137 samples: neither is a multiple of the 1920-sample stereo frame.
            let n = if i % 2 == 0 { 401 } else { 137 };
            let mut block = Vec::with_capacity(n * 2);
            for _ in 0..n {
                phase += std::f32::consts::TAU * 440.0 / 48_000.0;
                let s = 0.4 * phase.sin();
                block.push(s);
                block.push(s);
            }
            let _ = link.send_audio_samples(&block);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Keep the connection open so the last packets packetize and flush.
        tokio::time::sleep(Duration::from_millis(600)).await;
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    let mut packets = 0usize;
    let mut bytes = 0usize;
    while packets < 20 {
        match tokio::time::timeout(Duration::from_secs(5), controller.recv_audio_packet()).await {
            Ok(Some(len)) => {
                packets += 1;
                bytes += len;
            }
            _ => break,
        }
    }

    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    assert!(
        packets >= 10,
        "expected inbound Opus RTP from the agent's audio track, got {packets}"
    );
    // A tone must cost real bytes. DTX makes a silent frame ONE byte, so an average this size is
    // also the check that actual audio — not silence — made it across.
    let mean = bytes / packets;
    assert!(
        mean > 20,
        "mean Opus payload {mean} B is too small to be a tone — is the stream silent?"
    );
    eprintln!("AUDIO OVER WEBRTC: {packets} Opus RTP packets, {bytes} bytes (mean {mean} B/packet)");
}

/// Video and audio **at the same time**, which is what every real session actually is.
///
/// `video_track_flows_over_webrtc` and `audio_track_flows_over_webrtc` each pass on their own, and
/// both passed for the whole marathon in which the agent gained its audio pump — while a real
/// session carrying both delivered NO VIDEO AT ALL. Two green tests, one broken product: neither
/// test could see the defect because neither ever put a second track on the peer connection.
///
/// So this asserts the pair — BOTH directions, because the defect is a race and not a fixed
/// winner: whichever track delivers RTP first captures `on_track` and starves the other. In the
/// product the audio pump starts before the capture loop, so Opus won and the picture vanished;
/// in THIS harness the video sender is spawned first, so video wins and audio starves. Measured,
/// not assumed — reverted against the pre-fix code this test fails `20 video RTP, 0 Opus RTP`.
/// That is why neither assertion may be dropped: either one alone would pass on the broken code
/// half the time, and on this harness specifically the video-only assertion would ALWAYS pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn video_and_audio_tracks_flow_together_over_webrtc() {
    use rmt_agent_core::{ScreenCapturer, SyntheticCapturer};

    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url}");
        return;
    }

    let agent_device = DeviceId::new();

    // Agent: push BOTH streams concurrently, at their natural cadences — 50 fps video and 10 ms
    // audio blocks — rather than interleaving them on one clock, because the product's two
    // producers are genuinely independent (a capture thread and a WASAPI pump).
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let link = WebRtcTransport::connect(
            &agent_url,
            Role::dev_agent(agent_device, "ed25519:test-agent"),
        )
        .await
        .expect("agent connect");

        let vid = {
            let link = link.video_sender().expect("agent has a video sender");
            tokio::spawn(async move {
                let mut cap = SyntheticCapturer::new(128, 128, 7);
                for _ in 0..100 {
                    let f = cap.capture_frame(0).expect("capture");
                    let _ = link.send(&f);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };

        let mut phase = 0f32;
        for i in 0..100 {
            let n = if i % 2 == 0 { 401 } else { 137 };
            let mut block = Vec::with_capacity(n * 2);
            for _ in 0..n {
                phase += std::f32::consts::TAU * 440.0 / 48_000.0;
                let s = 0.4 * phase.sin();
                block.push(s);
                block.push(s);
            }
            let _ = link.send_audio_samples(&block);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = vid.await;
        tokio::time::sleep(Duration::from_millis(600)).await;
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    // Alternate between the two receivers rather than draining one then the other: draining video
    // first would simply block for the whole budget on exactly the failure being tested, and report
    // it as "no audio either". Both `recv_*` are `UnboundedReceiver::recv`, which is cancel-safe, so
    // a timed-out poll loses nothing.
    let mut video = 0usize;
    let mut audio = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while (video < 20 || audio < 20) && std::time::Instant::now() < deadline {
        if video < 20 {
            if let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_millis(100), controller.recv_video_packet())
                    .await
            {
                video += 1;
            }
        }
        if audio < 20 {
            if let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_millis(100), controller.recv_audio_packet())
                    .await
            {
                audio += 1;
            }
        }
    }

    let codec = controller.negotiated_video_codec().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    eprintln!("VIDEO+AUDIO TOGETHER: {video} video RTP, {audio} Opus RTP, codec {codec:?}");

    assert!(
        video >= 10,
        "the agent sent video AND audio; the controller received {video} video RTP packets \
         (audio: {audio}). A session that carries audio must still carry a picture"
    );
    assert!(
        audio >= 10,
        "expected inbound Opus RTP alongside video, got {audio} (video: {video})"
    );
}

/// Security audit 2026-10-18: the agent accepts exactly ONE data channel per peer connection. A
/// frame sent on a second channel never reaches the agent (the channel is refused before any
/// reassembly buffer exists for it), and the first channel keeps working.
///
/// The observable is delivery, not the second channel's state: the agent closes it, but webrtc-rs
/// does not surface a remote close to the opener, so "Open" on the controller says nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_refuses_a_second_data_channel() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url}");
        return;
    }
    let agent_device = DeviceId::new();
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let mut t = WebRtcTransport::connect(&agent_url, Role::dev_agent(agent_device, "ed25519:test-agent"))
            .await
            .expect("agent connect");
        t.recv_frame().await.expect("agent recv")
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    let extra = controller.open_extra_data_channel("extra").await.expect("open extra channel");
    // Let the extra channel open (DCEP) and its frame cross before the legitimate one is sent.
    tokio::time::sleep(Duration::from_millis(500)).await;
    extra.send_frame(Frame::new(ChannelId::Video, b"via-extra".to_vec())).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    use rmt_agent_core::transport::Transport;
    controller
        .send_frame(Frame::new(ChannelId::Video, b"via-first".to_vec()))
        .await
        .expect("controller send on the first channel");
    let got = tokio::time::timeout(Duration::from_secs(10), agent)
        .await
        .expect("agent task timed out")
        .expect("agent task panicked");
    assert_eq!(
        &got.payload[..],
        b"via-first",
        "the agent's first frame must come from the first channel, not the extra one (extra state: {})",
        extra.state()
    );
}
