//! Connection-bound Wake-on-LAN verification, clock recovery and UDP delivery.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmt_protocol::signaling::{ClientToServer, LAN_FEATURE, WAKE_FEATURE};
use rmt_protocol::wake::{verify_wake, WakeError, WakeExpectation, WakeOrder};
use rmt_protocol::DeviceId;
use rmt_transport_webrtc::SignalingClient;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use uuid::Uuid;
use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

use crate::lan_facts::{self, Mac};

const CLOCK_INTERVAL: Duration = Duration::from_secs(30);
const CLOCK_TOLERANCE: Duration = Duration::from_secs(10);
static TIME_CHANGED: Notify = Notify::const_new();

pub(crate) fn on_time_change() {
    TIME_CHANGED.notify_one();
}

pub(crate) fn features(installed: bool, wake: Option<&WakeAgent>) -> impl Iterator<Item = String> {
    [installed.then_some(LAN_FEATURE), wake.map(|_| WAKE_FEATURE)]
        .into_iter()
        .flatten()
        .map(str::to_owned)
}

pub(crate) struct WakeAgent {
    pin: [u8; 32],
    tenant: String,
    device: String,
    key_hash: [u8; 32],
    rate: Mutex<Rate>,
}

impl WakeAgent {
    pub(crate) fn new(
        cfg: &crate::config::HelperConfig,
        device: DeviceId,
        tenant: &str,
        public_key_hex: &str,
    ) -> Option<Self> {
        let pin = hex::decode(crate::directive_pin::pinned(cfg)?)
            .ok()?
            .try_into()
            .ok()?;
        let raw_public_key: [u8; 32] = hex::decode(public_key_hex).ok()?.try_into().ok()?;
        Some(Self {
            pin,
            tenant: tenant.to_owned(),
            device: device.to_string(),
            key_hash: Sha256::digest(raw_public_key).into(),
            rate: Mutex::default(),
        })
    }
}

struct Clock {
    wall: SystemTime,
    mono: Instant,
}

fn unix_ms(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

impl Clock {
    fn estimate_wall(&self, now: Instant) -> Option<SystemTime> {
        self.wall
            .checked_add(now.saturating_duration_since(self.mono))
    }

    fn estimate(&self, now: Instant) -> i64 {
        self.estimate_wall(now).map_or(i64::MAX, unix_ms)
    }

    fn stepped(&self, now: Instant, wall: SystemTime) -> bool {
        self.estimate_wall(now).map_or(true, |estimate| {
            wall.duration_since(estimate)
                .unwrap_or_else(|difference| difference.duration())
                > CLOCK_TOLERANCE
        })
    }
}

#[derive(Default)]
struct Replay(Mutex<HashMap<[u8; 16], i64>>);

impl Replay {
    fn reserve(
        &self,
        order: &WakeOrder,
        sample_now: impl FnOnce() -> i64,
    ) -> Result<(), &'static str> {
        let mut live = self.0.lock().unwrap();
        let now = sample_now();
        live.retain(|_, expires| *expires > now);
        if order.expires_at_ms <= now {
            return Err("expired");
        }
        if live.contains_key(&order.request_id) {
            return Err("replay");
        }
        if live.len() >= 64 {
            return Err("busy");
        }
        live.insert(order.request_id, order.expires_at_ms);
        Ok(())
    }
}

#[derive(Default)]
struct Rate(VecDeque<Instant>);

impl Rate {
    fn admit(&mut self, now: Instant) -> bool {
        while self
            .0
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(60))
        {
            self.0.pop_front();
        }
        if self.0.len() >= 6 {
            return false;
        }
        self.0.push_back(now);
        true
    }
}

pub(crate) struct Connection {
    agent: Arc<WakeAgent>,
    challenge: [u8; 16],
    clock: Arc<Clock>,
    replay: Replay,
}

impl Connection {
    pub(crate) fn begin(sig: &SignalingClient, agent: Arc<WakeAgent>) -> io::Result<Self> {
        let mut challenge = [0; 16];
        // SAFETY: The system RNG requires a null algorithm handle and writes to this buffer.
        unsafe {
            BCryptGenRandom(
                BCRYPT_ALG_HANDLE::default(),
                &mut challenge,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
            .ok()
            .map_err(io::Error::other)?;
        }
        let (wall, mono) = sig.connected_at();
        sig.send(ClientToServer::WakeHello {
            challenge: hex::encode(challenge),
        })
        .map_err(io::Error::other)?;
        Ok(Self {
            agent,
            challenge,
            clock: Arc::new(Clock { wall, mono }),
            replay: Replay::default(),
        })
    }

    pub(crate) fn monitor_clock(&self, sig: SignalingClient) -> tokio::task::AbortHandle {
        let clock = self.clock.clone();
        tokio::spawn(async move {
            let start = tokio::time::Instant::from_std(clock.mono) + CLOCK_INTERVAL;
            let mut timer = tokio::time::interval_at(start, CLOCK_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = sig.closed() => return,
                    _ = TIME_CHANGED.notified() => {}
                    _ = timer.tick() => {}
                }
                if clock.stepped(Instant::now(), SystemTime::now()) {
                    tracing::info!("wake: reconnecting after a clock correction");
                    sig.cancel();
                    return;
                }
            }
        })
        .abort_handle()
    }

    fn expectation(&self, now: Instant) -> WakeExpectation<'_> {
        WakeExpectation {
            tenant_id: &self.agent.tenant,
            relay_device_id: &self.agent.device,
            relay_key_sha256: self.agent.key_hash,
            wake_challenge: self.challenge,
            now_ms: self.clock.estimate(now),
        }
    }

    async fn attempt(&self, artifact: &[u8]) -> Result<(), Refusal> {
        let order = check_order(
            &self.agent.pin,
            artifact,
            self.expectation(Instant::now()),
            || unix_ms(SystemTime::now()),
        )?;
        self.replay
            .reserve(&order, || self.clock.estimate(Instant::now()))
            .map_err(Refusal::Check)?;

        let target = order.target_mac;
        let adapter = tokio::task::spawn_blocking(move || lan_facts::wake_adapter(&order))
            .await
            .map_err(|_| Refusal::Check("adapter"))?
            .map_err(Refusal::Check)?;
        let broadcast =
            directed_broadcast(adapter.network, adapter.prefix).ok_or(Refusal::Check("adapter"))?;
        {
            let mut rate = self.agent.rate.lock().unwrap();
            if !rate.admit(Instant::now()) {
                return Err(Refusal::Check("rate"));
            }
        }
        send_packets(
            adapter.address,
            adapter.index,
            SocketAddrV4::new(broadcast, 9),
            target,
        )
        .await
        .map_err(|_| Refusal::Send)
    }

    pub(crate) async fn handle(&self, sig: &SignalingClient, artifact: Value) {
        let bytes = artifact.to_string();
        let result = tokio::select! {
            biased;
            _ = sig.closed() => Err(Refusal::Check("connection")),
            result = self.attempt(bytes.as_bytes()) => result,
        };
        finish(sig, &artifact, result);
    }
}

fn finish(sig: &SignalingClient, artifact: &Value, result: Result<(), Refusal>) {
    match result {
        Ok(()) => log(artifact, "sent"),
        Err(Refusal::Send) => log(artifact, "send_failed"),
        Err(Refusal::Check(code)) => log(artifact, &format!("refused:{code}")),
        Err(Refusal::Clock) => {
            log(artifact, "refused:clock");
            sig.cancel();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Check(&'static str),
    Clock,
    Send,
}

fn check_order(
    pin: &[u8],
    artifact: &[u8],
    mut expected: WakeExpectation<'_>,
    wall_now: impl FnOnce() -> i64,
) -> Result<WakeOrder, Refusal> {
    match verify_wake(pin, artifact, &expected) {
        Ok(order) => Ok(order),
        Err(error) => {
            // Only these errors can change with time. The verifier reaches them after
            // checking the signature and every binding, including the connection challenge.
            if matches!(error, WakeError::NotYetValid | WakeError::Expired) {
                expected.now_ms = wall_now();
                if verify_wake(pin, artifact, &expected).is_ok() {
                    return Err(Refusal::Clock);
                }
            }
            Err(Refusal::Check(error.code()))
        }
    }
}

pub(crate) fn log(artifact: &Value, outcome: &str) {
    // Format only a parsed UUID. Untrusted text and any addressing data stay out of logs.
    let request_id = artifact["claims"]["request_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok());
    tracing::info!(request_id = ?request_id, outcome, "wake");
}

fn directed_broadcast(network: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if !(16..=30).contains(&prefix) {
        return None;
    }
    let broadcast = Ipv4Addr::from(u32::from(network) | (u32::MAX >> prefix));
    (broadcast != Ipv4Addr::BROADCAST).then_some(broadcast)
}

fn magic_packet(target: Mac) -> [u8; 102] {
    let mut bytes = [0xff; 102];
    for chunk in bytes[6..].chunks_exact_mut(6) {
        chunk.copy_from_slice(&target);
    }
    bytes
}

async fn send_packets(
    address: Ipv4Addr,
    index: u32,
    dest: SocketAddrV4,
    target: Mac,
) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(address, 0))?;
    socket.set_nonblocking(true)?;
    socket.set_broadcast(true)?;
    // SAFETY: The live UDP socket and the network-order UINT32 option buffer remain valid
    // for the duration of this setsockopt call.
    let result = unsafe {
        setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            IPPROTO_IP.0,
            IP_UNICAST_IF as i32,
            Some(&index.to_be_bytes()),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe {
            windows::Win32::Networking::WinSock::WSAGetLastError().0
        }));
    }
    let packet = magic_packet(target);
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if socket.send_to(&packet, dest)? != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete wake datagram",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Vec<Value> {
        let testdata: Value =
            serde_json::from_str(include_str!("../../protocol/testdata/wake-vectors.json"))
                .unwrap();
        testdata["wake_vectors"].as_array().unwrap().clone()
    }

    fn expectation(case: &Value) -> WakeExpectation<'_> {
        let exp = &case["expectation"];
        WakeExpectation {
            tenant_id: exp["tenant_id"].as_str().unwrap(),
            relay_device_id: exp["relay_device_id"].as_str().unwrap(),
            relay_key_sha256: hex::decode(exp["relay_key_sha256"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            wake_challenge: hex::decode(exp["wake_challenge"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            now_ms: exp["now_ms"].as_i64().unwrap(),
        }
    }

    fn valid() -> Value {
        vectors()
            .into_iter()
            .find(|case| case["name"] == "valid")
            .unwrap()
    }

    fn pin(case: &Value) -> Vec<u8> {
        hex::decode(case["pinned_public_key_hex"].as_str().unwrap()).unwrap()
    }

    fn artifact(case: &Value) -> &[u8] {
        case["artifact"].as_str().unwrap().as_bytes()
    }

    #[test]
    fn every_verification_outcome_is_preserved_at_the_agent_call_site() {
        for case in vectors() {
            let exp = expectation(&case);
            let now = exp.now_ms;
            let got = check_order(&pin(&case), artifact(&case), exp, || now);
            let code = match got {
                Ok(_) => "ok",
                Err(Refusal::Check(code)) => code,
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(code, case["expect"].as_str().unwrap(), "{}", case["name"]);
        }
    }

    #[test]
    fn advertisement_requires_a_usable_dedicated_pin() {
        let case = valid();
        let key = case["pinned_public_key_hex"].as_str().unwrap().to_owned();
        let mut cfg = crate::config::HelperConfig::default();
        let build = |cfg: &crate::config::HelperConfig| {
            WakeAgent::new(
                cfg,
                DeviceId(Uuid::nil()),
                expectation(&case).tenant_id,
                &key,
            )
        };
        assert_eq!(
            features(true, build(&cfg).as_ref()).collect::<Vec<_>>(),
            [LAN_FEATURE]
        );
        cfg.directive_pubkey = Some("broken".into());
        assert_eq!(
            features(true, build(&cfg).as_ref()).collect::<Vec<_>>(),
            [LAN_FEATURE]
        );
        cfg.directive_pubkey = Some(key.clone());
        cfg.grant_issuer_pubkey = Some(key.clone());
        assert_eq!(
            features(true, build(&cfg).as_ref()).collect::<Vec<_>>(),
            [LAN_FEATURE]
        );
        cfg.grant_issuer_pubkey = None;
        let agent = build(&cfg).unwrap();
        assert_eq!(
            features(true, Some(&agent)).collect::<Vec<_>>(),
            [LAN_FEATURE, WAKE_FEATURE]
        );
        let public_key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
        assert_eq!(agent.key_hash, <[u8; 32]>::from(Sha256::digest(public_key)));
    }

    fn order() -> WakeOrder {
        let case = valid();
        let exp = expectation(&case);
        check_order(&pin(&case), artifact(&case), exp, || unreachable!()).unwrap()
    }

    #[test]
    fn concurrent_replay_has_one_winner_and_expiry_is_rechecked_under_the_lock() {
        let order = order();
        let replay = Replay::default();
        let barrier = std::sync::Barrier::new(2);
        let now = order.issued_at_ms;
        let reserve = || {
            barrier.wait();
            replay.reserve(&order, || now)
        };
        let pair = std::thread::scope(|s| {
            let a = s.spawn(&reserve);
            let b = s.spawn(&reserve);
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert!(pair.contains(&Ok(())));
        assert!(pair.contains(&Err("replay")));
        assert_eq!(replay.reserve(&order, || now), Err("replay"));
        assert_eq!(
            replay.reserve(&order, || order.expires_at_ms),
            Err("expired")
        );
        assert!(replay.0.lock().unwrap().is_empty());
    }

    #[test]
    fn live_capacity_fails_closed_and_expiry_allows_more_than_64_wakes() {
        let mut order = order();
        let replay = Replay::default();
        let now = order.issued_at_ms;
        for index in 0..65u128 {
            order.request_id = index.to_be_bytes();
            assert_eq!(
                replay.reserve(&order, || now),
                if index < 64 { Ok(()) } else { Err("busy") }
            );
        }

        let replay = Replay::default();
        let mut rate = Rate::default();
        let start = Instant::now();
        for index in 0..100u64 {
            let now = 60_000 * index as i64;
            order.request_id = u128::from(index).to_be_bytes();
            order.issued_at_ms = now;
            order.expires_at_ms = now + 60_000;
            assert_eq!(replay.reserve(&order, || now), Ok(()));
            assert!(rate.admit(start + Duration::from_secs(60 * index)));
        }
        assert_eq!(replay.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn rate_limits_a_sliding_minute() {
        let mut rate = Rate::default();
        let now = Instant::now();
        assert!((0..6).all(|_| rate.admit(now)));
        assert!(!rate.admit(now + Duration::from_secs(59)));
        assert!(rate.admit(now + Duration::from_secs(60)));
    }

    #[test]
    fn large_steps_in_either_direction_are_detected_without_reviving_old_orders() {
        let case = valid();
        let mut exp = expectation(&case);
        let order = order();
        let wall = UNIX_EPOCH + Duration::from_millis(order.issued_at_ms as u64);
        let clock = Clock {
            wall,
            mono: Instant::now(),
        };
        let now = clock.mono + Duration::from_secs(60);
        assert!(clock.stepped(now, wall + Duration::from_secs(49)));
        assert!(clock.stepped(now, wall + Duration::from_secs(71)));
        assert!(!clock.stepped(now, wall + Duration::from_secs(50)));
        exp.now_ms = clock.estimate(now);
        let corrected_wall = unix_ms(wall + Duration::from_secs(52));
        assert_eq!(
            check_order(&pin(&case), artifact(&case), exp.clone(), || corrected_wall),
            Err(Refusal::Clock)
        );
        exp.wake_challenge[0] ^= 1;
        exp.now_ms = corrected_wall;
        assert_eq!(
            check_order(&pin(&case), artifact(&case), exp, || unreachable!()),
            Err(Refusal::Check("challenge"))
        );
    }

    #[tokio::test]
    async fn eight_second_correction_refuses_and_closes_the_signaling_connection() {
        let case = valid();
        let mut exp = expectation(&case);
        let issued = order().issued_at_ms;
        exp.now_ms = issued - 34_000;
        assert_eq!(
            check_order(&pin(&case), artifact(&case), exp.clone(), || issued
                - 34_000),
            Err(Refusal::Check("not_yet_valid"))
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            use futures_util::StreamExt;
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                assert!(!message.is_text(), "wake outcomes never go on the wire");
            }
        });
        let (sig, _rx) = SignalingClient::connect(&url).await.unwrap();
        let result = check_order(&pin(&case), artifact(&case), exp.clone(), || {
            issued - 26_000
        });
        assert_eq!(result, Err(Refusal::Clock));
        finish(
            &sig,
            &serde_json::from_slice(artifact(&case)).unwrap(),
            result.map(|_| ()),
        );
        tokio::time::timeout(Duration::from_secs(2), sig.closed())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();

        exp.now_ms = issued - 26_000;
        assert!(check_order(&pin(&case), artifact(&case), exp.clone(), || unreachable!()).is_ok());
        exp.wake_challenge[0] ^= 1;
        assert_eq!(
            check_order(&pin(&case), artifact(&case), exp, || unreachable!()),
            Err(Refusal::Check("challenge"))
        );
    }

    #[tokio::test]
    async fn a_replacement_connection_sends_a_new_challenge_and_rejects_a_captured_order() {
        use futures_util::StreamExt;

        let case = valid();
        let original = expectation(&case);
        assert!(check_order(
            &pin(&case),
            artifact(&case),
            original.clone(),
            || unreachable!()
        )
        .is_ok());
        let agent = Arc::new(WakeAgent {
            pin: pin(&case).try_into().unwrap(),
            tenant: original.tenant_id.to_owned(),
            device: original.relay_device_id.to_owned(),
            key_hash: original.relay_key_sha256,
            rate: Mutex::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
            serde_json::from_str::<ClientToServer>(&first).unwrap()
        });
        let (sig, _rx) = SignalingClient::connect(&url).await.unwrap();
        let replacement = Connection::begin(&sig, agent).unwrap();
        assert_ne!(replacement.challenge, original.wake_challenge);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            ClientToServer::WakeHello {
                challenge: hex::encode(replacement.challenge)
            }
        );
        assert_eq!(
            check_order(
                &replacement.agent.pin,
                artifact(&case),
                replacement.expectation(Instant::now()),
                || unreachable!()
            ),
            Err(Refusal::Check("challenge"))
        );
        sig.cancel();
    }

    #[test]
    fn magic_packet_bytes_and_directed_broadcast() {
        let mac = [2, 1, 2, 3, 4, 5];
        let payload = magic_packet(mac);
        assert_eq!(&payload[..6], &[0xff; 6]);
        assert_eq!(&payload[6..], &mac.repeat(16));
        for (network, prefix, expected) in [
            ([192, 168, 1, 0], 24, [192, 168, 1, 255]),
            ([10, 2, 0, 0], 16, [10, 2, 255, 255]),
            ([10, 0, 0, 4], 30, [10, 0, 0, 7]),
        ] {
            assert_eq!(
                directed_broadcast(network.into(), prefix),
                Some(expected.into())
            );
        }
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(255, 255, 255, 0), 24),
            None
        );
    }

    #[tokio::test]
    async fn sends_three_packets_only_to_the_injected_loopback_destination() {
        use windows::Win32::NetworkManagement::IpHelper::GetBestInterface;

        let ip = Ipv4Addr::LOCALHOST;
        let receiver = UdpSocket::bind(SocketAddrV4::new(ip, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let dest = match receiver.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!(),
        };
        let mut index = 0;
        // The route lookup selects Windows' loopback interface using a loopback destination.
        assert_eq!(
            unsafe { GetBestInterface(u32::from_ne_bytes(ip.octets()), &mut index) },
            0
        );
        let target = [2, 1, 2, 3, 4, 5];
        send_packets(ip, index, dest, target).await.unwrap();
        for _ in 0..3 {
            let mut data = [0; 102];
            let (size, source) = receiver.recv_from(&mut data).unwrap();
            assert!(source.ip().is_loopback());
            assert_eq!(size, 102);
            assert_eq!(data, magic_packet(target));
        }
    }
}
