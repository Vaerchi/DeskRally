//! docs/69 §3.4: a session binding verifies ONE DTLS association, so the agent applies exactly one remote
//! description per connection and refuses any later one (no renegotiation). This pins the single-session path
//! (`connect_inner`), the one the attended guest and the CLI stream use (Codex onedesc r1 coverage gap).
//!
//! The controller here is scripted directly on webrtc-rs and the signaling client, because the real controller
//! never re-offers. After a normal offer/answer and a delivered frame, it makes a GENUINE renegotiation offer on
//! the same peer connection (a new video transceiver) and sends it through the same brokered session. An agent
//! that applied it would answer; the guard means no second answer arrives, and the original data channel keeps
//! carrying frames.
//!
//! Loopback only: the scripted peer gathers 127.0.0.1 candidates with mDNS off, like the agent under
//! RMT_TEST_ICE_LOOPBACK (.cargo/config.toml), so no socket opens on a real interface (no firewall prompt).

use std::sync::Arc;
use std::time::Duration;

use rmt_agent_core::transport::Transport;
use rmt_protocol::signaling::{ClientToServer, SdpKind, ServerToClient};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, SignalingClient, WebRtcTransport};
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;

fn url() -> String {
    std::env::var("SIGNALING_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string())
}

/// Same no-false-green rule as e2e_late_broker: a skip is tolerated only when no harness pointed us at a server.
async fn signaling_ready() -> bool {
    let ok = tokio::time::timeout(Duration::from_millis(800), tokio_tungstenite::connect_async(url()))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !ok {
        assert!(std::env::var_os("SIGNALING_WS_URL").is_none(), "SIGNALING_WS_URL is set but no signaling server answered");
        eprintln!("SKIP: no signaling server at {}", url());
    }
    ok
}

/// The next message of interest, skipping ICE-server and relay notices. `None` on timeout.
async fn next_relevant(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ServerToClient>, within: Duration) -> Option<ServerToClient> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.checked_duration_since(tokio::time::Instant::now())?;
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(ServerToClient::IceServers { .. })) | Ok(Some(ServerToClient::RelayAssignment { .. })) => continue,
            Ok(Some(m)) => return Some(m),
            _ => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_single_session_agent_refuses_a_renegotiation_offer() {
    if !signaling_ready().await {
        return;
    }
    let agent_device = DeviceId::new();
    let agent_url = url();
    let agent = tokio::spawn(async move {
        let mut t = WebRtcTransport::connect(&agent_url, Role::dev_agent(agent_device, "ed25519:test-agent"))
            .await
            .expect("agent connect");
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(t.recv_frame().await.expect("agent recv"));
        }
        got
    });
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Scripted controller: loopback-only, mDNS off.
    let mut media = MediaEngine::default();
    media.register_default_codecs().unwrap();
    let mut setting = SettingEngine::default();
    setting.set_include_loopback_candidate(true);
    setting.set_ip_filter(Box::new(|ip: std::net::IpAddr| ip.is_loopback()));
    setting.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
    let api = APIBuilder::new().with_media_engine(media).with_setting_engine(setting).build();
    let pc = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await.unwrap());
    let dc = pc.create_data_channel("frames", None).await.unwrap();
    let (open_tx, mut open_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    dc.on_open(Box::new(move || {
        let _ = open_tx.send(());
        Box::pin(async {})
    }));

    let (sig, mut rx) = SignalingClient::connect(&url()).await.expect("signaling");
    sig.send(ClientToServer::ConnectRequest { target: agent_device, ticket: None }).unwrap();
    let session = match next_relevant(&mut rx, Duration::from_secs(10)).await {
        Some(ServerToClient::Brokered { session, .. }) => session,
        other => panic!("expected brokered, got {other:?}"),
    };

    // First (honest) offer -> answer.
    let offer = pc.create_offer(None).await.unwrap();
    let mut gather = pc.gathering_complete_promise().await;
    pc.set_local_description(offer).await.unwrap();
    let _ = gather.recv().await;
    let sdp = pc.local_description().await.unwrap().sdp;
    sig.send(ClientToServer::Sdp { session, sdp, kind: SdpKind::Offer }).unwrap();
    let answer = loop {
        match next_relevant(&mut rx, Duration::from_secs(15)).await {
            Some(ServerToClient::Sdp { sdp, kind: SdpKind::Answer, .. }) => break sdp,
            Some(ServerToClient::Candidate { .. }) => continue,
            other => panic!("expected the agent's answer, got {other:?}"),
        }
    };
    pc.set_remote_description(RTCSessionDescription::answer(answer).unwrap()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), open_rx.recv()).await.expect("data channel open").unwrap();
    dc.send(&Frame::new(ChannelId::Video, b"before".to_vec()).to_bytes()).await.unwrap();

    // A GENUINE renegotiation of the same peer connection (new media section). An agent that applied it would
    // answer it; the guard refuses it.
    pc.add_transceiver_from_kind(RTPCodecType::Video, None).await.unwrap();
    let reoffer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(reoffer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sdp2 = pc.local_description().await.unwrap().sdp;
    sig.send(ClientToServer::Sdp { session, sdp: sdp2, kind: SdpKind::Offer }).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while let Some(m) = next_relevant(&mut rx, deadline.saturating_duration_since(tokio::time::Instant::now())).await {
        if let ServerToClient::Sdp { kind, .. } = m {
            panic!("the agent answered a second remote description ({kind:?}): renegotiation must be refused");
        }
    }

    // The original association still carries frames.
    dc.send(&Frame::new(ChannelId::Video, b"after".to_vec()).to_bytes()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), agent).await.expect("agent task timed out").expect("agent task");
    assert_eq!(&got[0].payload[..], &b"before"[..]);
    assert_eq!(&got[1].payload[..], &b"after"[..]);
    let _ = pc.close().await;
}
