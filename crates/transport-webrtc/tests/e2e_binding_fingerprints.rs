//! docs/69 §3.3 over a REAL WebRTC connection: each end's `BindingSource` reports the same certificate
//! pair, mirrored. The binding transcript is only consistent if the agent's `local` equals the
//! controller's `remote` and vice versa; this proves webrtc-rs gives both sides the same view.
//!
//! Needs a signaling server (like e2e_webrtc.rs); the gate starts one.

use std::time::Duration;

use rmt_protocol::DeviceId;
use rmt_transport_webrtc::{parse_colon_hex_fingerprint, Role, WebRtcTransport};

fn signaling_url() -> String {
    std::env::var("SIGNALING_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string())
}

async fn signaling_reachable(url: &str) -> bool {
    tokio::time::timeout(Duration::from_millis(800), async { tokio_tungstenite::connect_async(url).await.is_ok() })
        .await
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_ends_see_the_same_certificate_pair() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }
    let agent_device = DeviceId::new();
    let agent_url = url.clone();
    let agent = tokio::spawn(async move {
        let t = WebRtcTransport::connect(&agent_url, Role::dev_agent(agent_device, "ed25519:test-agent"))
            .await
            .expect("agent connect");
        let src = t.binding_source();
        // The remote certificate is known once DTLS completes; connect returns with the channel open.
        let fps = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(f) = src.fingerprints().await {
                    return f;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("agent fingerprints");
        (t, fps)
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");
    let c = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(f) = controller.binding_source().fingerprints().await {
                return f;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("controller fingerprints");
    let (_agent_transport, a) = tokio::time::timeout(Duration::from_secs(10), agent)
        .await
        .expect("agent task timed out")
        .expect("agent task panicked");

    assert_ne!(a.local, a.remote, "the two ends must have different certificates");
    assert_eq!(a.local, c.remote, "agent's own certificate == the certificate the controller received");
    assert_eq!(a.remote, c.local, "controller's own certificate == the certificate the agent received");
    eprintln!("BINDING FINGERPRINTS AGREE over a live DTLS association");
}

#[test]
fn colon_hex_fingerprints_parse_strictly() {
    let ok = vec!["AB"; 32].join(":");
    assert_eq!(parse_colon_hex_fingerprint(&ok), Some([0xab; 32]));
    assert_eq!(parse_colon_hex_fingerprint(&ok.to_lowercase()), Some([0xab; 32]));
    assert_eq!(parse_colon_hex_fingerprint(&vec!["AB"; 31].join(":")), None);
    assert_eq!(parse_colon_hex_fingerprint(&vec!["AB"; 33].join(":")), None);
    assert_eq!(parse_colon_hex_fingerprint(&format!("+1:{}", vec!["AB"; 31].join(":"))), None);
    assert_eq!(parse_colon_hex_fingerprint(&vec!["ABC"; 32].join(":")), None);
    assert_eq!(parse_colon_hex_fingerprint(""), None);
}
