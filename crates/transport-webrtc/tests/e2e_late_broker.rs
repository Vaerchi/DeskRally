//! The connect budget must NOT be shared between the idle wait and the negotiation it triggers.
//!
//! THE BUG THIS PINS (2026-09-04): `connect_with_ice` wrapped the whole of `connect_inner` in ONE
//! `CONNECT_TIMEOUT`, and `connect_inner` waits idle for the broker *before* doing SDP + ICE +
//! data-channel. So the idle wait ate the negotiation's time. An agent reached 18s into its 20s
//! window had 2s to complete a handshake that a WAN/TURN path routinely cannot, and it failed
//! SILENTLY: the viewer showed no video with a null `app-error`, the agent logged its ordinary
//! "no controller within the connect window" line. It cost ~22% of connects, measured over 32
//! trials on the live deployment — failures clustered at a median 3.5s of budget remaining against
//! 13.3s for successes.
//!
//! WHY THE BUDGETS ARE INJECTED HERE. The first version of this test used the real 20s constant and
//! had the controller arrive 400ms before the deadline — and it PASSED against the deliberately
//! reintroduced bug, because a loopback handshake finishes inside 400ms. It was asserting nothing.
//! Discriminating on wall-clock margin needs the leftover to be smaller than a real handshake,
//! which on loopback means single-digit milliseconds and a flaky test. Injecting a short idle
//! window instead makes the asymmetry structural: with a shared budget the negotiation gets
//! `IDLE - ARRIVAL` and cannot finish; with split budgets it gets the full `NEGOTIATE`.
//! `real_constants_still_connect` is the paired test that keeps the SHIPPED constants covered, so
//! the injection cannot hide a zeroed default.

use std::time::Duration;

use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// The signaling server these tests dial.
///
/// **`SIGNALING_WS_URL` is honoured because ignoring it produced a FALSE GREEN.**
/// `scripts/verify-all.ps1` runs signaling on a deliberately uncontended port (:18080 — this box
/// has an unrelated service on :8080), and every other e2e file in the repo already reads this
/// variable. This one hardcoded :8080, so under the gate all four tests found nothing, printed
/// `SKIP:` and reported `ok` — which means the test that pins the split connect budget, the entire
/// point of this file, had never once run. The no-skip harness caught it on the first gate run
/// after the fix landed; the targeted `cargo test -p rmt-transport-webrtc` that "verified" the fix
/// did not, because it skipped too.
///
/// Returns `&'static str` so it is a drop-in for the constant it replaced, including inside the
/// `async move` blocks below, which a captured `String` would have forced to clone.
fn url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("SIGNALING_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string())
    })
}

/// Long enough for the agent to register and the controller to be brokered, short enough that the
/// leftover after `ARRIVAL` cannot complete a handshake.
const IDLE: Duration = Duration::from_millis(1500);
/// When the controller arrives, measured from the agent starting to wait. Leaves 60ms under a
/// shared budget — far below any handshake — and the whole of `NEGOTIATE` under split budgets.
const ARRIVAL: Duration = Duration::from_millis(1440);
/// The negotiation's own budget. Generous on purpose: this is the path that must survive TURN.
const NEGOTIATE: Duration = Duration::from_secs(20);

/// Probe the URL we will actually dial, with a real WebSocket handshake.
///
/// A bare TCP connect would call ANY listener on that port a signaling server. On this box :8080 is
/// exactly where an unrelated service lives, so the old probe could report "reachable" and then
/// strand the test in a confusing mid-run failure instead of an honest one.
async fn signaling_reachable() -> bool {
    tokio::time::timeout(Duration::from_millis(800), async {
        tokio_tungstenite::connect_async(url()).await.is_ok()
    })
    .await
    .unwrap_or(false)
}

/// `true` when these tests may run.
///
/// Skipping is tolerated ONLY for a developer running `cargo test` with nothing started. When the
/// harness explicitly pointed us at a server, an unreachable one is a HARD FAILURE: a skip is
/// reported as a pass, and "green without running" is the precise defect this file shipped with.
async fn signaling_ready() -> bool {
    if signaling_reachable().await {
        return true;
    }
    assert!(
        std::env::var_os("SIGNALING_WS_URL").is_none(),
        "SIGNALING_WS_URL={} is set but no signaling server answered there. Skipping would \
         be reported as a pass, which is how all four tests in this file went green without \
         ever running.",
        url(),
    );
    eprintln!("SKIP: no signaling server at {} (set SIGNALING_WS_URL to point at one)", url());
    false
}

/// One session, with the controller arriving `arrival` after the agent begins waiting. Returns the
/// agent's connect result so a caller can assert on the error string, not just success.
async fn session_with(
    idle: Duration,
    negotiate: Duration,
    arrival: Duration,
) -> Result<(), String> {
    let device = DeviceId::new();

    let agent = tokio::spawn(async move {
        WebRtcTransport::connect_with_ice_timeouts(
            url(),
            Role::dev_agent(device, "ed25519:test-agent"),
            Vec::new(),
            idle,
            negotiate,
        )
        .await
    });

    tokio::time::sleep(arrival).await;

    let controller = WebRtcTransport::connect(url(), Role::dev_controller(device))
        .await
        .map_err(|e| format!("controller connect: {e}"))?;

    let mut agent_transport = agent
        .await
        .map_err(|e| format!("agent task: {e}"))?
        .map_err(|e| format!("agent connect: {e}"))?;

    // Connecting is not the same as carrying traffic: assert a frame actually crosses, so a
    // handshake that "succeeded" into a dead data channel cannot pass.
    let mut controller = controller;
    use rmt_agent_core::transport::Transport;
    controller
        .send_frame(Frame::new(ChannelId::Video, b"late-broker".to_vec()))
        .await
        .map_err(|e| format!("controller send: {e}"))?;
    let got = tokio::time::timeout(Duration::from_secs(10), agent_transport.recv_frame())
        .await
        .map_err(|_| "agent never received the frame".to_string())?
        .map_err(|e| format!("agent recv: {e}"))?;
    assert_eq!(got.payload.as_ref(), b"late-broker".as_slice());
    Ok(())
}

/// POSITIVE CONTROL. A controller arriving early in the same short window must succeed. Without it,
/// the late test failing would not distinguish the shared-budget bug from a harness that simply
/// cannot connect — and it is what proves `IDLE` is long enough to broker in at all.
#[tokio::test]
async fn controller_arriving_early_establishes_a_session() {
    if !signaling_ready().await {
        return;
    }
    session_with(IDLE, NEGOTIATE, Duration::from_millis(700))
        .await
        .expect("a promptly-arriving controller must establish a session");
}

/// END-TO-END SMOKE ONLY — read this before trusting it. A controller arriving late in the window
/// must still establish a real session. This CANNOT discriminate the shared-budget bug on loopback:
/// a loopback handshake finishes in under 60ms, so it passed against the deliberately reintroduced
/// bug. It is kept because "a late controller still works end to end" is worth pinning, but the
/// test that actually catches the regression is
/// [`negotiation_gets_its_own_budget_after_brokering`].
#[tokio::test]
async fn controller_arriving_late_still_establishes_a_session_end_to_end() {
    if !signaling_ready().await {
        return;
    }
    assert!(
        ARRIVAL < IDLE,
        "premise: the controller must arrive while the agent is still waiting",
    );
    session_with(IDLE, NEGOTIATE, ARRIVAL)
        .await
        .expect("a controller arriving late in the idle window must still establish a session");
}

/// THE REGRESSION TEST. Asserts the BUDGET rather than the outcome, which is the only thing that
/// discriminates here: broker a peer that never negotiates, then measure how long the agent is
/// willing to wait afterwards, and which failure it names.
///
///   * split budgets (correct) — the agent waits the full `NEGOTIATE` *after* brokering and fails
///     with `NEGOTIATE_TIMED_OUT`, total ≈ `ARRIVAL + NEGOTIATE`.
///   * shared budget (the bug) — the agent gives up when the single window expires and fails with
///     `CONNECT_TIMED_OUT`, total ≈ `IDLE`, having granted the negotiation only `IDLE - ARRIVAL`.
///
/// Asserting WHICH error denies, not merely that one did: the two failures are the whole point, and
/// `CONNECT_TIMED_OUT` here would be the silent misreport that hid this bug in production.
#[tokio::test]
async fn negotiation_gets_its_own_budget_after_brokering() {
    if !signaling_ready().await {
        return;
    }
    // Short so the test is quick, but comfortably longer than `IDLE - ARRIVAL` so the two outcomes
    // are separated by seconds rather than milliseconds.
    const NEGOTIATE_SHORT: Duration = Duration::from_secs(2);
    let device = DeviceId::new();

    let agent = tokio::spawn(async move {
        WebRtcTransport::connect_with_ice_timeouts(
            url(),
            Role::dev_agent(device, "ed25519:test-agent"),
            Vec::new(),
            IDLE,
            NEGOTIATE_SHORT,
        )
        .await
    });

    // A SILENT controller: ask the broker to pair us with the agent, then never send an SDP offer.
    // This is what puts the agent past the broker (ending the idle wait) and into a negotiation
    // that can only end in a timeout — the clean way to observe which budget bounds it.
    tokio::time::sleep(ARRIVAL).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(url())
        .await
        .expect("silent controller websocket");
    let req = serde_json::json!({ "type": "connect_request", "target": device.to_string() });
    futures_util::SinkExt::send(
        &mut ws,
        tokio_tungstenite::tungstenite::Message::Text(req.to_string()),
    )
    .await
    .expect("send connect_request");

    let started = std::time::Instant::now();
    // Matched rather than `expect_err`: `WebRtcTransport` is not `Debug`.
    let err = match agent.await.expect("agent task") {
        Ok(_) => panic!("a peer that never sent an SDP offer cannot produce a session"),
        Err(e) => e,
    };
    let elapsed = started.elapsed();

    assert_eq!(
        err,
        rmt_transport_webrtc::NEGOTIATE_TIMED_OUT,
        "after brokering, the failure must name the NEGOTIATION budget; {:?} means the idle wait \
         still bounds the handshake",
        err,
    );
    // The timing half, so a hand-written error string could not satisfy this on its own: the agent
    // must actually have waited its negotiation budget, not the idle remainder.
    let leftover_under_the_bug = IDLE.saturating_sub(ARRIVAL);
    assert!(
        elapsed > leftover_under_the_bug * 2,
        "negotiation lasted {elapsed:?}, which is within the {leftover_under_the_bug:?} a shared \
         budget would have left — the budgets are still coupled",
    );
}

/// Keeps the SHIPPED constants covered. The two tests above inject their budgets, so on their own
/// they would pass even if `CONNECT_TIMEOUT`/`NEGOTIATE_TIMEOUT` were zeroed; this one goes through
/// the ordinary `connect` path with no injection at all.
#[tokio::test]
async fn real_constants_still_connect() {
    if !signaling_ready().await {
        return;
    }
    let device = DeviceId::new();
    let agent = tokio::spawn(async move {
        WebRtcTransport::connect(url(), Role::dev_agent(device, "ed25519:test-agent")).await
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _controller = WebRtcTransport::connect(url(), Role::dev_controller(device))
        .await
        .expect("controller connect");
    agent
        .await
        .expect("agent task")
        .expect("agent connect on the shipped constants");
}
