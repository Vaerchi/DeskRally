//! Negative control for turn_tcp.rs (docs/50): with NO dialer registered, the vendored webrtc-ice
//! behaves exactly like upstream: a `turn:…?transport=tcp` server yields no relay candidate.
//! A separate test binary, because the dialer is process-global.

use std::sync::Arc;
use std::time::Duration;

use webrtc::ice::agent::agent_config::AgentConfig;
use webrtc::ice::agent::Agent;
use webrtc::ice::candidate::{Candidate, CandidateType};
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::url::Url;

#[tokio::test]
async fn without_a_dialer_tcp_turn_yields_no_relay_candidate() {
    // A listening port that would accept a TCP connection, so only the missing dialer explains it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut u = Url::parse_url(&format!("turn:127.0.0.1:{port}?transport=tcp")).unwrap();
    u.username = "agent".into();
    u.password = "s3cret".into();
    let agent = Agent::new(AgentConfig {
        urls: vec![u],
        network_types: vec![NetworkType::Udp4],
        candidate_types: vec![CandidateType::Relay],
        ..Default::default()
    })
    .await
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    agent.on_candidate(Box::new(move |c: Option<Arc<dyn Candidate + Send + Sync>>| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(c.map(|c| c.candidate_type()));
        })
    }));
    agent.gather_candidates().unwrap();
    // Gathering ends with a `None` candidate; nothing relay-typed may come before it.
    let first = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("gathering finishes").unwrap();
    assert_eq!(first, None, "no relay candidate without the dialer");
    drop(listener);
    let _ = agent.close().await;
}
