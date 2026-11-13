//! End-to-end **session lease** test (docs/25 F03): a leased session that is never re-authorized
//! tears ITSELF down, over a REAL WebRTC transport, without the controller cooperating in any way.
//!
//! # What this proves that the unit tests cannot
//!
//! `rmt_agent::session_policy`'s tests prove the lease TRUTH TABLE — when a lease is held, when the
//! grace window closes, that a renewed lease never lapses. They say nothing about whether the
//! session loop is wired to it. That wiring is precisely where this repo has shipped inert features
//! before: `host.rs` has a `biased;` `select!` whose 500 ms "periodic re-check" arm is documented as
//! effectively dead because a frame arrives every ~33 ms, so a revocation hung off an in-body
//! `sleep` would compile, unit-test green, and never fire. These tests drive the production
//! `serve_session_with_ice` and require it to RETURN ON ITS OWN.
//!
//! `stop` is never set in either test. A completed agent future can therefore only be the lease arm.
//!
//! # Why `SessionLeaseMode::Required`
//!
//! In production the lease is derived from the session binding — the control-plane session id a
//! signaling server reports only for a ticket whose control-plane signature it verified. The e2e
//! signaling server runs WITHOUT ticket verification, so `control_plane_session` is `None` here and
//! the deriving mode would (correctly) decide "not leased", leaving the teardown path with no
//! coverage at all. `Required` forces the same code path the derivation reaches in production.
//!
//! For the same reason the FIRST test cannot be "install a valid lease and watch it hold": a policy
//! can only verify against a bound session (`SessionBinding::Unknown` rejects every policy), and the
//! binding needs a real ticket-verifying signaling server. The "a renewed session keeps running"
//! negative control therefore lives in `rmt_agent::session_policy::tests`, and the negative control
//! HERE is the second test: an ordinary unleased session must run on untouched.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_session_lease -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmt_agent::session_policy::SessionLeaseMode;
use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId};
use rmt_transport_webrtc::{Role, WebRtcTransport};

struct NoopSink;
impl InputSink for NoopSink {
    fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
        Ok(())
    }
}

/// The grace window these tests run with. Short enough that a test does not take twenty seconds,
/// long enough that a slow ICE handshake on a loaded CI box does not make the teardown look
/// instantaneous when it was not.
const TEST_GRACE: Duration = Duration::from_secs(6);

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

async fn connect_controller(url: &str, device: DeviceId) -> WebRtcTransport {
    // Bounded by ATTEMPTS, not by a wall clock: `WebRtcTransport::connect` has its own ~20 s
    // internal timeout, so a deadline-bounded loop would retry exactly zero times when one attempt
    // is slow — the "retry loop that cannot retry" this repo has already been bitten by.
    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match WebRtcTransport::connect(url, Role::dev_controller(device)).await {
            Ok(t) => return t,
            Err(e) => {
                eprintln!("connect attempt {attempt}/{ATTEMPTS} to {device} failed: {e}");
                last = e;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!("controller never connected to {device} in {ATTEMPTS} attempts (last error: {last})");
}

fn spawn_agent(
    url: String,
    device: DeviceId,
    stop: Arc<AtomicBool>,
    transfer_dir: std::path::PathBuf,
    lease: SessionLeaseMode,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(320, 240, 30);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session_with_ice(
            &url,
            device,
            capturer,
            30,
            stop,
            Vec::new(),
            SessionOptions {
                sink,
                transfer_dir,
                session_lease: lease,
                session_lease_grace: TEST_GRACE,
                ..Default::default()
            },
        )
        .await
    })
}

/// Wait for the agent's `SessionLeaseRequired` announcement, ignoring every other frame.
async fn await_lease_announcement(c: &mut WebRtcTransport, within: Duration) -> Option<u64> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), c.recv_frame()).await {
            Ok(Ok(f)) if f.channel == ChannelId::Control => {
                if let Ok(ControlMessage::SessionLeaseRequired { renew_within_ms }) =
                    control::decode(&f.payload)
                {
                    return Some(renew_within_ms);
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// Prove the session is genuinely SERVING, not merely un-ended: ask for the monitor list and require
/// the answer. A future that is hung rather than alive would satisfy "did not complete" without this.
async fn assert_session_is_live(c: &mut WebRtcTransport, when: &str) {
    c.send_frame(rmt_protocol::Frame::new(
        ChannelId::Control,
        control::encode(&ControlMessage::RequestMonitors),
    ))
    .await
    .unwrap_or_else(|e| panic!("controller could not send RequestMonitors {when}: {e}"));
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(400), c.recv_frame()).await {
            Ok(Ok(f)) if f.channel == ChannelId::Control => {
                if let Ok(ControlMessage::MonitorList { .. }) = control::decode(&f.payload) {
                    return;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => panic!("transport died {when}: {e}"),
            Err(_) => continue,
        }
    }
    panic!("the agent never answered RequestMonitors {when} — the session was not live");
}

/// **THE REGRESSION docs/25 F03 ASKS FOR**, in the form the agent can prove locally: a leased
/// session whose lease is never installed ends itself, on time, with the controller doing nothing.
///
/// In production the missing lease is the control plane REFUSING to mint one for a session an
/// administrator ended (`POST /sessions/{id}/policy` → 409, proved in
/// `control-plane/http_session_lease_test.go`). Here it is a controller that simply never installs
/// one, which is the same fact from the agent's side and is also the hostile case: a custom
/// controller that never cooperates.
///
/// THE TIMING IS ASSERTED IN BOTH DIRECTIONS. A session that dies immediately would satisfy "the
/// future completed" while being a total product outage, so the elapsed time must also be at least
/// most of the grace window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leased_session_with_no_lease_tears_itself_down_at_the_grace_deadline() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_lease_e2e_{}", uuid::Uuid::new_v4()));
    let device = DeviceId::new();
    // NEVER set — the whole point is that the LEASE, not this flag, ends the session.
    let stop = Arc::new(AtomicBool::new(false));
    let agent = spawn_agent(
        url.clone(),
        device,
        stop.clone(),
        root.join("transfers"),
        SessionLeaseMode::Required,
    );

    let mut c = connect_controller(&url, device).await;
    let connected_at = Instant::now();
    // The session must be genuinely serving BEFORE the lease ends it, or "it stopped" proves
    // nothing — it might never have started.
    assert_session_is_live(&mut c, "before the grace deadline").await;

    // The agent must ASK for a lease. Without this the test would still pass on an agent that
    // silently killed every session, and the console would have no way to know it should renew.
    let announced = await_lease_announcement(&mut c, Duration::from_secs(5)).await;
    let announced = announced.expect(
        "the agent must announce SessionLeaseRequired — a controller that is never told to renew \
         cannot renew, and the session would die for a reason nobody can act on",
    );
    assert!(
        announced <= TEST_GRACE.as_millis() as u64,
        "announced renew_within_ms {announced} exceeds the grace window {TEST_GRACE:?} — the \
         deadline must be absolute from session start, never extended by re-announcing"
    );

    // The controller now does NOTHING, which is exactly what a hostile one does.
    let ended = tokio::time::timeout(TEST_GRACE + Duration::from_secs(20), agent).await;
    let elapsed = connected_at.elapsed();
    // `Ok(Ok(Ok(())))` and nothing weaker, and this precision was EARNED: an earlier version
    // asserted only `ended.is_ok()` — "the task finished" — and a mutation that broke the grace
    // comparison made the session loop PANIC instead of ending, which finished the task and passed
    // the test. A revocation must be a clean, ordinary teardown (input block released, recording
    // finalized, guest window told), so the test insists on the return value that says so.
    match ended {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => panic!("the session ended with an error rather than cleanly: {e}"),
        Ok(Err(join)) => panic!("the session loop PANICKED instead of ending its lease cleanly: {join}"),
        Err(_) => panic!(
            "the leased session was still running {elapsed:?} after connect with no lease \
             installed — `stop` was never set, so nothing else was ever going to end it"
        ),
    }
    assert!(
        !stop.load(Ordering::Relaxed),
        "the external stop flag was never touched — the lease did the work"
    );
    // The other direction: it must not have died instantly. A "fix" that ended every session on the
    // first tick would pass every assertion above.
    assert!(
        elapsed >= TEST_GRACE / 2,
        "the session ended after only {elapsed:?}, well inside the {TEST_GRACE:?} grace window — a \
         lease that kills sessions before the controller can possibly install one is an outage, \
         not a revocation"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **THE NEGATIVE CONTROL.** An ordinary session — the deriving mode, against a signaling server
/// that vouches for no control-plane session — is NOT leased and must run on untouched.
///
/// Without this, a change that ended every session after the grace window would pass the test above
/// and every unit test with it, while taking the whole product offline. It runs for well over twice
/// the grace window before giving up on the session being ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unleased_session_is_never_ended_by_the_lease_arm() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let root = std::env::temp_dir().join(format!("rmt_lease_neg_e2e_{}", uuid::Uuid::new_v4()));
    let device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent = spawn_agent(
        url.clone(),
        device,
        stop.clone(),
        root.join("transfers"),
        // The PRODUCTION default. Against this signaling server it derives "not leased".
        SessionLeaseMode::FromSessionBinding,
    );

    let mut c = connect_controller(&url, device).await;
    let mut agent = agent;
    assert_session_is_live(&mut c, "immediately after connect").await;

    // It must not even ASK: announcing on an unleased session would tell a console to renew a lease
    // that is not required, and a console acting on it would install a policy on an agent that may
    // have no issuer key to verify it — dropping that session to view-only for nothing.
    assert!(
        await_lease_announcement(&mut c, Duration::from_secs(3)).await.is_none(),
        "an unleased session must not announce SessionLeaseRequired"
    );

    // Well past the grace window plus a lease TTL. If the lease arm is firing on unleased sessions,
    // the agent future completes here and this fails.
    let still_running = tokio::time::timeout(TEST_GRACE * 3, &mut agent).await;
    assert!(
        still_running.is_err(),
        "an unleased session ended on its own within {:?} — the lease arm must be inert for every \
         session the control plane cannot revoke (dev/LAN, attended, no pinned issuer key)",
        TEST_GRACE * 3
    );

    // Still SERVING, not merely un-ended: a hung future would satisfy the assertion above.
    assert_session_is_live(&mut c, "three grace windows after connect").await;

    drop(c);
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(20), agent).await;
    let _ = std::fs::remove_dir_all(&root);
}
