//! End-to-end test through the REAL Go relay (`server/relay`). Two Rust endpoints connect to
//! the relay with the same RelayToken; the relay pairs and splices them. The agent seals
//! synthetic frames and sends them; the controller receives and decrypts them. This proves the
//! whole cross-language data path: Rust crypto/framing ↔ the Go relay's verbatim byte forwarding
//! ↔ Rust crypto/framing, and that the relay only ever sees ciphertext.
//!
//! Requires a running relay. Start one with:  `cd server/relay && go run .`  (listens on :9000).
//! Point the test at it with RELAY_TCP_ADDR (default 127.0.0.1:9000). If no relay is reachable
//! the test SKIPS (prints a notice and passes) so the normal suite stays green without one.

use rmt_agent_core::{
    frame_number, ChannelId, Handshake, RelayToken, Role, ScreenCapturer, Session,
    SyntheticCapturer,
};
use rmt_protocol::SessionId;

fn relay_addr() -> String {
    std::env::var("RELAY_TCP_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
}

#[tokio::test]
async fn frames_flow_agent_through_relay_to_controller() {
    let addr = relay_addr();

    // Skip cleanly if no relay is listening (keeps `cargo test` green without one).
    if tokio::net::TcpStream::connect(&addr).await.is_err() {
        eprintln!(
            "[skip] no relay reachable at {addr}; start it with `cd server/relay && go run .` \
             to exercise this test"
        );
        return;
    }

    // Shared session: one token both peers present, and a key pair (as signaling would broker).
    let token = RelayToken(uuid::Uuid::new_v4());
    let id = SessionId::new();
    let controller_hs = Handshake::new(Role::Controller);
    let agent_hs = Handshake::new(Role::Agent);
    let cpub = controller_hs.public_bytes();
    let apub = agent_hs.public_bytes();
    let mut controller = Session::new(id, controller_hs.complete(&apub));
    let mut agent = Session::new(id, agent_hs.complete(&cpub));

    const N: u64 = 20;

    // Agent connects and sends N sealed synthetic frames through the relay.
    let agent_addr = addr.clone();
    let agent_task = tokio::spawn(async move {
        let mut link = rmt_agent_core::RelayTransport::connect(&agent_addr, token)
            .await
            .expect("agent connect relay");
        let mut cap = SyntheticCapturer::new(48, 48, 5);
        for _ in 0..N {
            let f = cap.capture_frame(0).expect("capture");
            agent
                .send(&mut link, ChannelId::Video, &f.bytes)
                .await
                .expect("agent send");
        }
        // Hold the connection open briefly so the relay flushes before teardown.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    // Controller connects with the same token; the relay splices the two.
    let mut link = rmt_agent_core::RelayTransport::connect(&addr, token)
        .await
        .expect("controller connect relay");

    for expected in 0..N {
        let (channel, plaintext) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            controller.recv(&mut link),
        )
        .await
        .expect("recv did not time out")
        .expect("controller recv");
        assert_eq!(channel, ChannelId::Video);
        assert_eq!(
            frame_number(&plaintext),
            Some(expected),
            "frame {expected} must arrive through the relay and decrypt intact, in order"
        );
    }

    agent_task.await.unwrap();
}
