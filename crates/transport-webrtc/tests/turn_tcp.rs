//! TURN over TCP and TLS, end to end against a real TURN server (the `turn` crate's, over the same
//! stream framing), and through the vendored webrtc-ice relay gathering (docs/50).
//!
//! The negative control (no dialer registered: no relay candidate) is `turn_tcp_unregistered.rs`, a
//! separate binary, because the dialer is process-global.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rmt_transport_webrtc::turn_stream::{StreamConn, TurnStreamDialer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use webrtc::ice::relay_dialer::{set_relay_stream_dialer, RelayStreamDialer};
use webrtc::ice::url::Url;
use webrtc::turn::auth::{generate_auth_key, AuthHandler};
use webrtc::turn::relay::relay_static::RelayAddressGeneratorStatic;
use webrtc::turn::server::config::{ConnConfig, ServerConfig};
use webrtc::turn::server::Server;
use webrtc::util::vnet::net::Net;
use webrtc::util::Conn;

const USER: &str = "agent";
const PASS: &str = "s3cret";
const REALM: &str = "deskrally.test";

struct StaticAuth;
impl AuthHandler for StaticAuth {
    fn auth_handle(&self, username: &str, realm: &str, _src: SocketAddr) -> Result<Vec<u8>, webrtc::turn::Error> {
        if username == USER {
            Ok(generate_auth_key(username, realm, PASS))
        } else {
            Err(webrtc::turn::Error::ErrNoSuchUser)
        }
    }
}

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A self-signed certificate for `name` (an IP or DNS name) and the server TLS config serving it.
fn tls_server(name: &str) -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    (cert, Arc::new(cfg))
}

fn tls_client(trusted: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted.clone()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(ring())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A TURN server on 127.0.0.1 accepting ONE stream connection (TLS when `tls` is set). Returns its
/// port; the server lives until the test process exits.
async fn turn_server(tls: Option<Arc<rustls::ServerConfig>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let local = tcp.local_addr().unwrap();
        let conn: Arc<dyn Conn + Send + Sync> = match tls {
            Some(cfg) => match tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await {
                Ok(s) => Arc::new(StreamConn::new(s, local, peer)),
                Err(_) => return, // the client refused our certificate: the test checks that side
            },
            None => Arc::new(StreamConn::new(tcp, local, peer)),
        };
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: REALM.to_owned(),
            auth_handler: Arc::new(StaticAuth),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .unwrap();
        std::mem::forget(server);
    });
    port
}

fn url(scheme: &str, host: &str, port: u16) -> Url {
    let mut u = Url::parse_url(&format!("{scheme}:{host}:{port}?transport=tcp")).unwrap();
    u.username = USER.to_owned();
    u.password = PASS.to_owned();
    u
}

/// Counts the frames the TURN client writes, by kind, so the test can require that the ChannelData
/// path (the one that needs stream padding) was really exercised, not only Send indications.
struct Counting {
    inner: Arc<dyn Conn + Send + Sync>,
    channel_data_sent: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl Conn for Counting {
    async fn connect(&self, a: SocketAddr) -> Result<(), webrtc::util::Error> { self.inner.connect(a).await }
    async fn recv(&self, b: &mut [u8]) -> Result<usize, webrtc::util::Error> { self.inner.recv(b).await }
    async fn recv_from(&self, b: &mut [u8]) -> Result<(usize, SocketAddr), webrtc::util::Error> { self.inner.recv_from(b).await }
    async fn send(&self, b: &[u8]) -> Result<usize, webrtc::util::Error> { self.inner.send(b).await }
    async fn send_to(&self, b: &[u8], t: SocketAddr) -> Result<usize, webrtc::util::Error> {
        if b.first().is_some_and(|x| x >> 6 == 0b01) {
            self.channel_data_sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.send_to(b, t).await
    }
    fn local_addr(&self) -> Result<SocketAddr, webrtc::util::Error> { self.inner.local_addr() }
    fn remote_addr(&self) -> Option<SocketAddr> { self.inner.remote_addr() }
    async fn close(&self) -> Result<(), webrtc::util::Error> { self.inner.close().await }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) { self }
}

/// Allocate through `dialer` and move datagrams both ways between the relay and a UDP peer.
async fn allocate_and_relay(dialer: &TurnStreamDialer, u: &Url) {
    let channel_data_sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let conn: Arc<dyn Conn + Send + Sync> =
        Arc::new(Counting { inner: dialer.dial(u).await.expect("dial"), channel_data_sent: channel_data_sent.clone() });
    let client = webrtc::turn::client::Client::new(webrtc::turn::client::ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: format!("{}:{}", u.host, u.port),
        username: USER.to_owned(),
        password: PASS.to_owned(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn,
        vnet: None,
    })
    .await
    .unwrap();
    client.listen().await.unwrap();
    let relay = client.allocate().await.expect("allocate over the stream");
    let relay_addr = relay.local_addr().unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    // The first rounds go as Send indications (STUN); once the client's channel binding is ready
    // they go as ChannelData. Keep going until 4 rounds AFTER the first ChannelData. Payload lengths
    // 5, 6 and 7 are never 4-aligned, so every ChannelData frame needs stream padding.
    let mut after_switch = 0;
    for i in 0..60u8 {
        if channel_data_sent.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            after_switch += 1;
            if after_switch > 4 {
                break;
            }
        }
        let out = vec![i; 5 + (i % 3) as usize];
        relay.send_to(&out, peer_addr).await.unwrap();
        let mut buf = [0u8; 1500];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&out[..], relay_addr), "round {i}: relay -> peer");

        let back = vec![0xA0 | (i & 0x0F); 5 + ((i + 1) % 3) as usize];
        peer.send_to(&back, relay_addr).await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&back[..], peer_addr), "round {i}: peer -> relay");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        channel_data_sent.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the client never switched to ChannelData: the padded framing path was not exercised"
    );
    let _ = relay.close().await;
    let _ = client.close().await;
}

#[tokio::test]
async fn turn_over_tcp_allocates_and_relays_both_ways() {
    let port = turn_server(None).await;
    allocate_and_relay(&TurnStreamDialer::new(None), &url("turn", "127.0.0.1", port)).await;
}

#[tokio::test]
async fn turns_over_tls_allocates_and_relays_both_ways() {
    let (cert, server_tls) = tls_server("127.0.0.1");
    let port = turn_server(Some(server_tls)).await;
    allocate_and_relay(&TurnStreamDialer::new(Some(tls_client(&cert))), &url("turns", "127.0.0.1", port)).await;
}

#[tokio::test]
async fn turns_refuses_a_certificate_for_another_name() {
    let (cert, server_tls) = tls_server("other.example");
    let port = turn_server(Some(server_tls)).await;
    let dialer = TurnStreamDialer::new(Some(tls_client(&cert)));
    let err = dialer.dial(&url("turns", "127.0.0.1", port)).await.err().expect("must refuse");
    assert!(err.contains("TLS handshake"), "{err}");
}

#[tokio::test]
async fn turns_without_trust_roots_fails_cleanly() {
    let (_, server_tls) = tls_server("127.0.0.1");
    let port = turn_server(Some(server_tls)).await;
    let err = TurnStreamDialer::new(None).dial(&url("turns", "127.0.0.1", port)).await.err().expect("no roots");
    assert!(err.contains("no TLS trust roots"), "{err}");
}

/// The patched webrtc-ice path itself: an ICE agent configured with ONLY a `turn:…?transport=tcp`
/// server gathers a relay candidate on the TURN server's relay address.
#[tokio::test]
async fn ice_gathers_a_relay_candidate_over_tcp_turn() {
    use webrtc::ice::agent::agent_config::AgentConfig;
    use webrtc::ice::agent::Agent;
    use webrtc::ice::candidate::{Candidate, CandidateType};
    use webrtc::ice::network_type::NetworkType;

    assert!(set_relay_stream_dialer(Arc::new(TurnStreamDialer::new(None))), "first registration in this binary");
    let port = turn_server(None).await;
    let agent = Agent::new(AgentConfig {
        urls: vec![url("turn", "127.0.0.1", port)],
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
            if let Some(c) = c {
                let _ = tx.send((c.candidate_type(), c.address(), c.port()));
            }
        })
    }));
    agent.gather_candidates().unwrap();
    let (kind, address, _) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a candidate").unwrap();
    assert_eq!(kind, CandidateType::Relay);
    assert_eq!(address, "127.0.0.1", "the TURN server's relay address");
    let _ = agent.close().await;
}
