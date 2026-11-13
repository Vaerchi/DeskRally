//! End-to-end **signed-grant** backstage-over-WebRTC test (H1 deliverable).
//!
//! Proves the full H1 trust flow over a REAL WebRTC session, with the agent running
//! [`serve_session_with_ice`] in **secure grant mode** (a control-plane issuer key is pinned):
//!
//! 1. **No grant → denied.** A backstage [`Request`] sent *before* any grant is installed comes
//!    back as a well-formed `ok:false` "denied" envelope — the agent has no dispatcher yet.
//! 2. **Wrong issuer → rejected.** A `Control::InstallGrant` signed by the WRONG identity is
//!    rejected with a `Control::Error` and does NOT arm the dispatcher; backstage stays denied.
//! 3. **Correct issuer → accepted + scoped.** A `Control::InstallGrant` signed by the pinned issuer,
//!    scoped to read-only caps, verifies (`Control::GrantInstalled` ack); the subsequent
//!    `Request{GetSystemInfo}` is authorized (`ok:true`) and carries an audit hash.
//!
//! `GetSystemInfo` is a read-only capability backed by the cross-platform `sysinfo` crate, so the
//! test needs no elevation and makes no system changes. The video side is fed a
//! [`SyntheticCapturer`] so the capture half has something to stream.
//!
//! The signed-grant case owns an enforcing loopback broker and fails if its binary is missing.
//! The two legacy dev/denial cases self-skip when no external dev broker is reachable.
//!
//! To run it for real:
//! ```
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_backstage -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmt_agent::backstage::grant::GrantClaims;
use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, BackstageAuth, SessionOptions};
use rmt_crypto::Identity;
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_protocol::signaling::{SessionTicketClaims, SignedSessionTicket};
use std::process::{Child, Command, Stdio};
use std::os::windows::process::CommandExt;
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// A no-op input sink: this test drives the backstage/control channels, not input.
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

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Build a `SignedGrant` JSON blob (as carried in `Control::InstallGrant`) scoped to read-only caps,
/// signed by `issuer`, valid now, and bound to `machine_id` (H3 device binding — must equal the
/// agent session's device for the agent to accept it).
fn signed_grant_json(issuer: &Identity, machine_id: uuid::Uuid, session_id: uuid::Uuid, technician_id: uuid::Uuid) -> String {
    let now = now_ms();
    let claims = GrantClaims {
        grant: Grant {
            technician_id,
            session_id,
            machine_id,
            // Scoped: read-only. Enough for GetSystemInfo; deliberately NOT a full grant.
            capabilities: vec![Capability::SystemInfoRead, Capability::ProcessList],
        },
        issued_at_ms: now - 5_000,
        expires_at_ms: now + 5 * 60_000,
    };
    claims.sign(issuer).to_json().expect("serialize signed grant")
}

// Own a loopback broker so a surrounding dev broker cannot supply unverified identity.
struct TicketBroker { child: Child, url: String }
impl Drop for TicketBroker {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}
async fn ticket_broker(issuer: &Identity) -> TicketBroker {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let exe = repo.join("server/signaling/signaling.exe");
    assert!(exe.exists(), "build server/signaling/signaling.exe before running this test");
    let child = Command::new(exe)
        .args(["-addr", &addr.to_string(), "-insecure-no-agent-auth"])
        .env("SIGNALING_TICKET_PUBKEY", issuer.public_hex())
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn().expect("start ticket-enforcing loopback signaling");
    let broker = TicketBroker { child, url: format!("ws://{addr}/ws") };
    for _ in 0..40 {
        if signaling_reachable(&broker.url).await { return broker; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ticket-enforcing signaling did not become ready");
}
fn session_ticket(issuer: &Identity, device: DeviceId, session: uuid::Uuid, tech: uuid::Uuid) -> SignedSessionTicket {
    let now = now_ms();
    let claims = SessionTicketClaims {
        v: 1, session_id: session.to_string(), technician_id: tech.to_string(),
        tenant_id: uuid::Uuid::new_v4().to_string(), device_id: device.to_string(),
        iat_ms: now - 1_000, exp_ms: now + 120_000,
    };
    // Same domain-separated preimage as transport-webrtc/tests/e2e_ticket.rs (golden-vector pinned).
    let mut bytes = b"RMTTICKETv1\x00".to_vec();
    bytes.push(claims.v as u8);
    for field in [&claims.session_id, &claims.technician_id, &claims.tenant_id, &claims.device_id] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes.extend_from_slice(&claims.iat_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.exp_ms.to_be_bytes());
    SignedSessionTicket { sig: hex::encode(issuer.sign(&bytes)), claims }
}

/// Receive frames from `controller` until one arrives on `channel` (ignoring others), or panic on
/// `what` after ~12s. Video is a media track, so only data-channel frames appear here.
async fn recv_on_channel(
    controller: &mut WebRtcTransport,
    channel: ChannelId,
    what: &str,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for {what} on {channel:?}");
        }
        match tokio::time::timeout(Duration::from_secs(1), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == channel => {
                // The agent also announces monitors/quality/lease state on Control.
                // Those unsolicited messages are not an InstallGrant response.
                if channel == ChannelId::Control && !matches!(control::decode(&frame.payload),
                    Ok(ControlMessage::Error { .. } | ControlMessage::GrantInstalled)) { continue; }
                return frame.payload.to_vec();
            },
            Ok(Ok(_)) => continue, // some other channel; keep waiting
            Ok(Err(_)) => panic!("controller data channel closed before {what}"),
            Err(_) => continue, // 1s recv timeout; re-check the deadline
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_grant_gates_backstage_over_webrtc() {
    // The pinned control-plane issuer. The controller signs grants with the private half; the agent
    // is handed only the public half and verifies against it.
    let issuer = Identity::generate();
    let issuer_public = issuer.public();
    let broker = ticket_broker(&issuer).await;
    let url = broker.url.clone();
    let session_id = uuid::Uuid::new_v4();
    let technician_id = uuid::Uuid::new_v4();
    // A different identity — grants signed by this must be rejected by the agent.
    let attacker = Identity::generate();

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // Agent: run the real session driver in SECURE grant mode (issuer key pinned).
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
        let dir = std::env::temp_dir().join(format!("rmt_bk_h1_{}", uuid::Uuid::new_v4()));
        serve_session_with_ice(
            &agent_url,
            agent_device,
            capturer,
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink: Arc::new(NoopSink),
                transfer_dir: dir,
                clipboard: None,
                backstage_auth: BackstageAuth::SignedBy(issuer_public),
                identity: None,    ..Default::default()
            },
        )
        .await
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::controller(agent_device, session_ticket(&issuer, agent_device, session_id, technician_id)))
        .await
        .expect("controller connect");

    let request_json = r#"{"type":"GetSystemInfo"}"#;

    // --- Case 1: backstage request BEFORE any grant → denied -------------------------------------
    controller
        .send_frame(Frame::new(ChannelId::Backstage, request_json.as_bytes().to_vec()))
        .await
        .expect("send pre-grant backstage request");
    let denied: serde_json::Value = {
        let payload = recv_on_channel(&mut controller, ChannelId::Backstage, "pre-grant denial").await;
        serde_json::from_slice(&payload).expect("denial envelope is valid JSON")
    };
    assert_eq!(denied["ok"], false, "pre-grant request must be denied: {denied}");
    assert_eq!(denied["error"]["kind"], "denied", "pre-grant denial kind: {denied}");
    let no_grant_denied = denied["ok"] == false;

    // --- Case 2: InstallGrant signed by the WRONG issuer → Control Error, still denied -----------
    let bad_blob = signed_grant_json(&attacker, agent_device.0, session_id, technician_id);
    controller
        .send_frame(Frame::new(
            ChannelId::Control,
            control::encode(&ControlMessage::InstallGrant { signed_grant: bad_blob }),
        ))
        .await
        .expect("send wrong-issuer InstallGrant");
    let ctrl = recv_on_channel(&mut controller, ChannelId::Control, "wrong-issuer rejection").await;
    let wrong_issuer_rejected = matches!(
        control::decode(&ctrl).expect("decode control reply"),
        ControlMessage::Error { .. }
    );
    assert!(wrong_issuer_rejected, "wrong-issuer grant must be rejected with Control::Error");

    // Backstage must STILL be denied (no dispatcher armed by a rejected grant).
    controller
        .send_frame(Frame::new(ChannelId::Backstage, request_json.as_bytes().to_vec()))
        .await
        .expect("send post-reject backstage request");
    let still_denied: serde_json::Value = {
        let payload = recv_on_channel(&mut controller, ChannelId::Backstage, "post-reject denial").await;
        serde_json::from_slice(&payload).expect("denial envelope is valid JSON")
    };
    assert_eq!(still_denied["ok"], false, "backstage must stay denied after a rejected grant: {still_denied}");

    // --- Case 2b: InstallGrant signed by the CORRECT issuer but for a DIFFERENT machine → rejected.
    // H3 device binding: a grant minted for another device is not replayable to this agent.
    let wrong_machine_blob = signed_grant_json(&issuer, uuid::Uuid::new_v4(), session_id, technician_id);
    controller
        .send_frame(Frame::new(
            ChannelId::Control,
            control::encode(&ControlMessage::InstallGrant { signed_grant: wrong_machine_blob }),
        ))
        .await
        .expect("send wrong-machine InstallGrant");
    let ctrl = recv_on_channel(&mut controller, ChannelId::Control, "wrong-machine rejection").await;
    let wrong_machine_rejected = matches!(
        control::decode(&ctrl).expect("decode control reply"),
        ControlMessage::Error { .. }
    );
    assert!(wrong_machine_rejected, "grant for a different machine must be rejected with Control::Error");

    // Correct signatures do not authorize another session or technician on this connection.
    for (session, tech, reason) in [
        (uuid::Uuid::new_v4(), technician_id, "session"),
        (session_id, uuid::Uuid::new_v4(), "technician"),
    ] {
        let signed_grant = signed_grant_json(&issuer, agent_device.0, session, tech);
        controller.send_frame(Frame::new(ChannelId::Control,
            control::encode(&ControlMessage::InstallGrant { signed_grant }))).await.unwrap();
        let reply = recv_on_channel(&mut controller, ChannelId::Control, reason).await;
        assert!(matches!(control::decode(&reply).unwrap(), ControlMessage::Error { .. }),
            "grant for another {reason} must be refused");
    }

    // --- Case 3: InstallGrant signed by the CORRECT issuer, bound to THIS device → accepted --------
    let good_blob = signed_grant_json(&issuer, agent_device.0, session_id, technician_id);
    controller
        .send_frame(Frame::new(
            ChannelId::Control,
            control::encode(&ControlMessage::InstallGrant { signed_grant: good_blob }),
        ))
        .await
        .expect("send correct-issuer InstallGrant");
    let ctrl = recv_on_channel(&mut controller, ChannelId::Control, "grant-installed ack").await;
    let grant_accepted = matches!(
        control::decode(&ctrl).expect("decode control reply"),
        ControlMessage::GrantInstalled
    );
    assert!(grant_accepted, "correct-issuer grant must be accepted (GrantInstalled ack)");

    controller
        .send_frame(Frame::new(ChannelId::Backstage, request_json.as_bytes().to_vec()))
        .await
        .expect("send authorized backstage request");
    let envelope: serde_json::Value = {
        let payload = recv_on_channel(&mut controller, ChannelId::Backstage, "authorized envelope").await;
        serde_json::from_slice(&payload).expect("envelope reply is valid JSON")
    };

    // Stop the agent and let it drain.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    // Assert the authorized request ran end-to-end over the transport, scoped by the signed grant.
    assert_eq!(envelope["ok"], true, "authorized envelope: {envelope}");
    assert_eq!(
        envelope["response"]["type"], "SystemInfo",
        "expected a SystemInfo response, got: {envelope}"
    );
    let hash = envelope["audit"]["hash"].as_str().unwrap_or("");
    assert!(!hash.is_empty(), "audit hash must be present and non-empty: {envelope}");

    eprintln!(
        "SIGNED-GRANT BACKSTAGE OVER WEBRTC: no-grant denied={no_grant_denied}, \
         wrong-issuer rejected={wrong_issuer_rejected}, wrong-machine rejected={wrong_machine_rejected}, \
         signed-grant accepted+scoped ok={} \
         response.type={} audit.hash={}",
        envelope["ok"], envelope["response"]["type"], hash
    );
}

/// Dev-mode coverage: with **no** grant issuer configured (the plain [`serve_session`] path the CLI
/// + local flow use), backstage falls back to the self-issued demo grant, so a `GetSystemInfo`
/// request succeeds immediately with no `InstallGrant`. Proves the H1 change did not break the
/// insecure-but-convenient dev path. Self-skips without a signaling server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dev_mode_backstage_uses_demo_grant() {
    use rmt_agent_windows::host::serve_session;

    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        let dir = std::env::temp_dir().join(format!("rmt_bk_dev_{}", uuid::Uuid::new_v4()));
        // serve_session pins no issuer ⇒ dev mode / demo grant.
        serve_session(&agent_url, agent_device, capturer, 30, sink, agent_stop, dir).await
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    controller
        .send_frame(Frame::new(ChannelId::Backstage, r#"{"type":"GetSystemInfo"}"#.as_bytes().to_vec()))
        .await
        .expect("send backstage request");
    let envelope: serde_json::Value = {
        let payload = recv_on_channel(&mut controller, ChannelId::Backstage, "dev-mode envelope").await;
        serde_json::from_slice(&payload).expect("envelope reply is valid JSON")
    };

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    assert_eq!(envelope["ok"], true, "dev-mode demo grant must authorize GetSystemInfo: {envelope}");
    assert_eq!(envelope["response"]["type"], "SystemInfo", "envelope: {envelope}");
    eprintln!("DEV-MODE BACKSTAGE OVER WEBRTC: demo grant authorized ok={}", envelope["ok"]);
}

/// An ATTENDED (on-demand) guest must never self-issue a backstage grant.
///
/// PREMISE, declared locally so this test cannot drift into passing for the wrong reason: the
/// attended guest is a member of the public who ran `agent_host attend --code …` and consented to a
/// *support session*. Consent to being viewed is not consent to `ShellAsSystem`. Whatever the
/// control plane decided the technician may do (`BackstageCapsFor` in control-plane/grant.go) is
/// expressed as a SIGNED grant, so the guest's session must deny every backstage request until such
/// a grant verifies — exactly like the unattended secure path.
///
/// The trust policy under test is taken from production code via
/// [`attend_backstage_auth`], NOT restated here: if `attend_command` ever goes back to
/// self-issuing, this test fails rather than silently testing a policy nothing uses.
///
/// `KillProcess` is the probe because it needs the admin-tier `ProcessKill` capability that a
/// self-issued demo grant hands out and a scoped grant would not. It is aimed at a PID that cannot
/// exist (`u32::MAX`), so authorization is the ONLY thing being measured — if the request were
/// authorized it would fail at the OS layer with a non-`denied` error kind, never killing anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attended_guest_denies_backstage_without_a_signed_grant() {
    use rmt_agent_windows::host::attend_backstage_auth;

    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));

    // The control plane advertised NO issuer key (older/misconfigured deployment). This is the
    // fail-CLOSED case: the guest cannot verify a grant, so it must grant nothing.
    let policy = attend_backstage_auth(None);

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
        let dir = std::env::temp_dir().join(format!("rmt_bk_attend_{}", uuid::Uuid::new_v4()));
        serve_session_with_ice(
            &agent_url,
            agent_device,
            capturer,
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink: Arc::new(NoopSink),
                transfer_dir: dir,
                clipboard: None,
                backstage_auth: policy,
                identity: None,    ..Default::default()
            },
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    let kill_json =
        r#"{"type":"KillProcess","data":{"pid":4294967295,"image":"nonexistent.exe","owner":""}}"#;
    controller
        .send_frame(Frame::new(ChannelId::Backstage, kill_json.as_bytes().to_vec()))
        .await
        .expect("send un-granted privileged backstage request");
    let envelope: serde_json::Value = {
        let payload =
            recv_on_channel(&mut controller, ChannelId::Backstage, "attended denial").await;
        serde_json::from_slice(&payload).expect("denial envelope is valid JSON")
    };

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    assert_eq!(
        envelope["ok"], false,
        "an attended guest must NOT authorize ProcessKill with no signed grant: {envelope}"
    );
    assert_eq!(
        envelope["error"]["kind"], "denied",
        "denial must come from the capability check, not from the OS failing the kill — a \
         non-`denied` kind means authorization PASSED and only the bogus pid saved us: {envelope}"
    );
    eprintln!(
        "ATTENDED BACKSTAGE OVER WEBRTC: un-granted ProcessKill denied ok={} kind={}",
        envelope["ok"], envelope["error"]["kind"]
    );
}
