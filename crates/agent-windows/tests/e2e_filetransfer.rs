//! End-to-end file-transfer test (M8 deliverable): a controller drives **bidirectional** file
//! transfer over a REAL WebRTC data channel on [`ChannelId::FileTransfer`], against an agent running
//! [`rmt_agent_windows::host::serve_session`].
//!
//! Two directions are exercised against one live session:
//!  * **Upload** (controller→agent): the controller sends `Offer` + multiple binary `Chunk`s +
//!    `Done` for a 200 KB deterministic blob; the test asserts the file lands in the agent's temp
//!    transfer dir with matching bytes + SHA-256 and that an `Ack{ok:true}` came back.
//!  * **Download** (controller→agent `Request`): the test pre-writes a file into the transfer dir,
//!    the controller `Request`s it, and the test reassembles the `Offer`+`Chunk`s+`Done` reply and
//!    asserts the bytes + SHA-256 match.
//!
//! The file transfer rides the same [`serve_session`] the input/backstage e2e tests use (a
//! [`SyntheticCapturer`] feeds the video half so the session stays live). It **self-skips** (prints
//! `SKIP:` and returns green) when no signaling server is reachable.
//!
//! To run it for real:
//! ```
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_filetransfer -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmt_agent_core::file_transfer::{self, Chunk, Message as FtMessage, Offer};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::serve_session;
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};
use uuid::Uuid;

/// A no-op input sink: this test drives file transfer, not input.
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

/// Deterministic pseudo-random blob (a simple LCG) so the test is reproducible and the assert on
/// bytes is meaningful without depending on any RNG.
fn deterministic_blob(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// Send one file-transfer message as a `ChannelId::FileTransfer` frame.
async fn send_ft(controller: &mut WebRtcTransport, msg: &FtMessage) {
    let payload = file_transfer::encode(msg);
    controller
        .send_frame(Frame::new(ChannelId::FileTransfer, payload))
        .await
        .expect("controller send file-transfer frame");
}

/// Await the next `ChannelId::FileTransfer` frame and decode it (ignoring other channels), with a
/// deadline.
async fn recv_ft(controller: &mut WebRtcTransport, timeout_secs: u64) -> FtMessage {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for a file-transfer reply");
        }
        match tokio::time::timeout(Duration::from_secs(1), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::FileTransfer => {
                return file_transfer::decode(&frame.payload).expect("decode file-transfer reply");
            }
            Ok(Ok(_)) => continue,      // some other channel; keep waiting
            Ok(Err(_)) => panic!("controller data channel closed before a reply arrived"),
            Err(_) => continue,          // 1s recv timeout; re-check the deadline
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_flow_both_directions_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    // Unique per-run transfer dir so uploads/downloads don't collide with other runs.
    let transfer_dir =
        std::env::temp_dir().join(format!("rmt_ft_e2e_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&transfer_dir).expect("create transfer dir");

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // Agent: run the real session driver (video via SyntheticCapturer + file-transfer handler).
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_dir = transfer_dir.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session(&agent_url, agent_device, capturer, 30, sink, agent_stop, agent_dir).await
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    // ---- (a) UPLOAD: controller → agent, 200 KB multi-chunk ------------------------------------
    let up_bytes = deterministic_blob(200 * 1024, 0xABCD_1234);
    let up_sha = file_transfer::sha256_hex(&up_bytes);
    let up_id = Uuid::new_v4();
    let up_name = "upload_blob.bin";

    send_ft(
        &mut controller,
        &FtMessage::Offer(Offer {
            id: up_id,
            name: up_name.into(),
            size: up_bytes.len() as u64,
            sha256: up_sha.clone(),
        }),
    )
    .await;
    for chunk in file_transfer::chunk_file(up_id, &up_bytes) {
        send_ft(&mut controller, &FtMessage::Chunk(chunk)).await;
    }
    send_ft(&mut controller, &FtMessage::Done { id: up_id }).await;

    // Expect an Ack{ok:true}.
    let ack = recv_ft(&mut controller, 15).await;
    match ack {
        FtMessage::Ack { id, ok, message } => {
            assert_eq!(id, up_id, "ack id");
            assert!(ok, "upload ack not ok: {message}");
        }
        other => panic!("expected Ack for upload, got {other:?}"),
    }

    // ADR-008: the Ack is followed by the tamper-evident AUDIT record for the upload, carrying the
    // digest and byte count the agent ACTUALLY computed over what landed on disk.
    let up_audit = match recv_ft(&mut controller, 15).await {
        FtMessage::Audit { id, event } => {
            assert_eq!(id, up_id, "upload audit id");
            event
        }
        other => panic!("expected an Audit record after the upload Ack, got {other:?}"),
    };
    assert_eq!(up_audit["action"]["kind"], "file_transfer", "upload audit action kind");
    assert_eq!(up_audit["action"]["direction"], "input", "upload audit direction");
    assert_eq!(up_audit["action"]["sha256"], up_sha, "upload audit sha256");
    assert_eq!(
        up_audit["action"]["bytes"].as_u64(),
        Some(up_bytes.len() as u64),
        "upload audit byte count"
    );
    assert_eq!(up_audit["outcome"]["result"], "ok", "upload audit outcome");
    assert!(
        up_audit["action"]["path"]
            .as_str()
            .is_some_and(|p| p.ends_with(up_name)),
        "upload audit path should name the committed file, got {:?}",
        up_audit["action"]["path"]
    );
    let up_seq = up_audit["seq"].as_u64().expect("audit seq");
    let up_hash = up_audit["hash"].as_str().expect("audit hash").to_string();
    assert_eq!(up_hash.len(), 64, "audit hash must be a full sha256 hex digest");

    // The committed file must exist with matching bytes + SHA-256.
    let landed = transfer_dir.join(up_name);
    let got = std::fs::read(&landed).expect("uploaded file must exist");
    assert_eq!(got.len(), up_bytes.len(), "uploaded size");
    assert_eq!(got, up_bytes, "uploaded bytes match");
    assert_eq!(file_transfer::sha256_hex(&got), up_sha, "uploaded sha256 match");
    let upload_ok = got == up_bytes;

    // ---- (b) DOWNLOAD: agent → controller via Request ------------------------------------------
    let down_bytes = deterministic_blob(150 * 1024 + 777, 0x5EED_9999);
    let down_sha = file_transfer::sha256_hex(&down_bytes);
    let down_name = "download_blob.bin";
    std::fs::write(transfer_dir.join(down_name), &down_bytes).expect("pre-write download file");

    let down_id = Uuid::new_v4();
    send_ft(
        &mut controller,
        &FtMessage::Request {
            id: down_id,
            path: down_name.into(),
        },
    )
    .await;

    // Reassemble Offer + Chunks + Done.
    let offer = match recv_ft(&mut controller, 15).await {
        FtMessage::Offer(o) => o,
        other => panic!("expected Offer reply to Request, got {other:?}"),
    };
    assert_eq!(offer.id, down_id, "download offer id");
    assert_eq!(offer.size, down_bytes.len() as u64, "download offer size");
    assert_eq!(offer.sha256, down_sha, "download offer sha256");

    let mut reassembled: Vec<u8> = Vec::with_capacity(offer.size as usize);
    let mut next_seq: u32 = 0;
    loop {
        match recv_ft(&mut controller, 15).await {
            FtMessage::Chunk(Chunk { id, seq, data }) => {
                assert_eq!(id, down_id, "download chunk id");
                assert_eq!(seq, next_seq, "download chunk seq in order");
                next_seq += 1;
                reassembled.extend_from_slice(&data);
            }
            FtMessage::Done { id } => {
                assert_eq!(id, down_id, "download done id");
                break;
            }
            other => panic!("unexpected message during download: {other:?}"),
        }
    }
    assert_eq!(reassembled.len(), down_bytes.len(), "download reassembled size");
    assert_eq!(reassembled, down_bytes, "download bytes match");
    assert_eq!(
        file_transfer::sha256_hex(&reassembled),
        down_sha,
        "download sha256 match"
    );
    let download_ok = reassembled == down_bytes;

    // ADR-008: the download is audited too, and — the property that makes the trail tamper-evident —
    // it CHAINS onto the upload's event: the next seq, and prev_hash equal to the upload's hash.
    let down_audit = match recv_ft(&mut controller, 15).await {
        FtMessage::Audit { id, event } => {
            assert_eq!(id, down_id, "download audit id");
            event
        }
        other => panic!("expected an Audit record after the download Done, got {other:?}"),
    };
    assert_eq!(down_audit["action"]["kind"], "file_transfer", "download audit action kind");
    assert_eq!(down_audit["action"]["direction"], "output", "download audit direction");
    assert_eq!(down_audit["action"]["sha256"], down_sha, "download audit sha256");
    assert_eq!(
        down_audit["action"]["bytes"].as_u64(),
        Some(down_bytes.len() as u64),
        "download audit byte count"
    );
    assert_eq!(down_audit["outcome"]["result"], "ok", "download audit outcome");
    assert_eq!(
        down_audit["seq"].as_u64(),
        Some(up_seq + 1),
        "the download event must be the next seq in the session's chain"
    );
    assert_eq!(
        down_audit["prev_hash"].as_str(),
        Some(up_hash.as_str()),
        "the download event must chain onto the upload event's hash"
    );
    // Both events belong to the SAME session chain — one ordered narrative, not two trails.
    assert_eq!(
        up_audit["session_id"], down_audit["session_id"],
        "both file-transfer events must be in one session chain"
    );

    // Stop the agent and let it drain.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
    let _ = std::fs::remove_dir_all(&transfer_dir);

    eprintln!(
        "FILE OVER WEBRTC: uploaded {} bytes {} (sha {}), downloaded {} bytes {} (sha {}); \
         audited seq {}→{} chained (ADR-008)",
        up_bytes.len(),
        if upload_ok { "ok" } else { "FAIL" },
        &up_sha[..12],
        down_bytes.len(),
        if download_ok { "ok" } else { "FAIL" },
        &down_sha[..12],
        up_seq,
        up_seq + 1,
    );
}
