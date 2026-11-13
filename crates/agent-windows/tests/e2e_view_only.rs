//! End-to-end proof that VIEW-ONLY is a guarantee for the CONTROL channel's actuating messages,
//! not merely a label the console applies to itself.
//!
//! docs/23's audit found three siblings of the `ChannelId::Input` gate that were never gated, and a
//! later review found the list was itself incomplete. This file covers the two the audit named:
//!
//!  * **`SetInputBlocked`** (finding #15) — freezing the guest's own keyboard and mouse. The worst
//!    of them, because every other view-only gate stops the technician doing something TO the
//!    machine, while this one takes away the guest's ability to intervene on their own computer.
//!    Their keyboard and mouse are the only in-band way to revoke a session they are unhappy with,
//!    the guest window's End button included, since a frozen guest cannot click it.
//!  * **`EndSession { uninstall: true }`** (finding #14) — removing the agent permanently. It also
//!    underwrites finding #3: `perform_self_uninstall` runs `rmdir /s /q` as SYSTEM against the
//!    directory `current_exe()` sits in, which for a promoted download stub is the guest's Downloads
//!    folder. Gating this does not fix #3, but it removes the view-only route to it.
//!
//! The input-block test asserts the REFUSAL and then the same action SUCCEEDING once view-only is
//! lifted. A test that only ever ran view-only ON would pass identically against a control that was
//! broken, or against a session whose control channel never opened. The uninstall pair now asserts
//! refusal in BOTH modes: since docs/65 D-C2 only a signed uninstall directive authorizes it (the
//! positive case is a directive_hub unit test).
//!
//! `mock_input: true` throughout — `InputBlocker::new(!mock_input)` then installs no real OS hooks.
//! Without it a gate run on a developer's box would genuinely freeze that box's keyboard and mouse,
//! which is the "mock every actuating control" rule this repo learned the hard way.
//!
//! Self-skips (prints `SKIP:` and returns green) when no signaling server is reachable.
//!
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe
//! cargo test -p rmt-agent-windows --test e2e_view_only -- --nocapture
//! ```

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

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

async fn send_control(controller: &mut WebRtcTransport, msg: &ControlMessage) {
    let payload = control::encode(msg);
    controller
        .send_frame(Frame::new(ChannelId::Control, payload))
        .await
        .expect("controller send control frame");
}

/// Await the next `ControlMessage` the agent sends that `pick` accepts, or `None` on timeout.
/// Ignores other channels and other control messages, so a video keyframe or a quality report
/// arriving mid-test cannot be mistaken for the reply under test.
async fn recv_control<T>(
    controller: &mut WebRtcTransport,
    timeout_secs: u64,
    pick: impl Fn(&ControlMessage) -> Option<T>,
) -> Option<T> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), controller.recv_frame()).await {
            Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                if let Ok(msg) = control::decode(&frame.payload) {
                    if let Some(v) = pick(&msg) {
                        return Some(v);
                    }
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return None,
            Err(_) => continue,
        }
    }
    None
}

async fn set_view_only(controller: &mut WebRtcTransport, enabled: bool) {
    send_control(controller, &ControlMessage::SetViewOnly { enabled }).await;
    let applied = recv_control(controller, 10, |m| match m {
        ControlMessage::ViewOnlyApplied { enabled } => Some(*enabled),
        _ => None,
    })
    .await;
    assert_eq!(
        applied,
        Some(enabled),
        "agent never acked SetViewOnly({enabled}); nothing after this would prove anything",
    );
}

/// Stand up an agent session and a connected controller. Returns the controller, the stop flag, the
/// agent's join handle, and the shared uninstall flag the session sets on an honoured uninstall.
async fn session() -> (
    WebRtcTransport,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<Result<(), String>>,
    Arc<AtomicBool>,
) {
    let url = signaling_url();
    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let uninstall_flag = Arc::new(AtomicBool::new(false));

    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_uninstall = Arc::clone(&uninstall_flag);
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(64, 64, 8);
        let sink: Arc<dyn InputSink> = Arc::new(NoopSink);
        serve_session_with_ice(
            &agent_url,
            agent_device,
            capturer,
            30,
            agent_stop,
            Vec::new(),
            SessionOptions {
                sink,
                transfer_dir: std::env::temp_dir().join("rmt_view_only_e2e_unused"),
                backstage_auth: rmt_agent_windows::host::BackstageAuth::Deny,
                identity: None,
                // THE LINE THAT KEEPS THIS TEST OFF THE DEVELOPER'S KEYBOARD.
                mock_input: true,
                uninstall_requested: Arc::clone(&agent_uninstall),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| e.to_string())
    });

    tokio::time::sleep(Duration::from_millis(700)).await;
    let controller = WebRtcTransport::connect(&url, Role::dev_controller(agent_device))
        .await
        .expect("controller connect");

    (controller, stop, agent, uninstall_flag)
}

/// A view-only session may not FREEZE the guest's own keyboard and mouse — and may still UNFREEZE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_only_session_cannot_block_the_guests_own_input() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }
    let (mut controller, stop, agent, _uninstall) = session().await;

    set_view_only(&mut controller, true).await;

    // ---- REFUSED, and LOUDLY -------------------------------------------------------------------
    // A silent drop would leave the console showing "input blocked" over a machine whose guest is
    // typing freely, so the refusal has to come back as an error rather than as nothing.
    send_control(&mut controller, &ControlMessage::SetInputBlocked { blocked: true }).await;
    let refusal = recv_control(&mut controller, 5, |m| match m {
        ControlMessage::Error { message } => Some(message.clone()),
        // If the agent applied it instead, capture that so the failure names what happened.
        ControlMessage::InputBlockApplied { blocked } => Some(format!("APPLIED blocked={blocked}")),
        _ => None,
    })
    .await;
    let refusal = refusal.expect("agent said nothing at all about the input-block request");
    assert!(
        refusal.contains("view-only"),
        "a view-only session BLOCKED the guest's own keyboard and mouse (reply was: {refusal})",
    );

    // ---- UNBLOCKING stays allowed even while view-only -----------------------------------------
    // The gate is on the REQUEST, not the message: a session that became view-only while a block was
    // in force must still be able to release it, or the guest is stranded frozen with session
    // teardown as the only way out.
    send_control(&mut controller, &ControlMessage::SetInputBlocked { blocked: false }).await;
    let unblock = recv_control(&mut controller, 5, |m| match m {
        ControlMessage::InputBlockApplied { blocked } => Some(*blocked),
        _ => None,
    })
    .await;
    assert_eq!(
        unblock,
        Some(false),
        "a view-only session could not UNBLOCK input; the gate is on the message, not the request",
    );

    // ---- NEGATIVE CONTROL: with view-only lifted, blocking works --------------------------------
    set_view_only(&mut controller, false).await;
    send_control(&mut controller, &ControlMessage::SetInputBlocked { blocked: true }).await;
    let applied = recv_control(&mut controller, 5, |m| match m {
        ControlMessage::InputBlockApplied { blocked } => Some(*blocked),
        ControlMessage::Error { message } => Some(message.contains("__never__")),
        _ => None,
    })
    .await;
    assert_eq!(
        applied,
        Some(true),
        "input-block stayed refused after view-only was lifted, so the refusal above proves nothing",
    );

    // Release it before teardown so nothing outlives the test even under a real blocker.
    send_control(&mut controller, &ControlMessage::SetInputBlocked { blocked: false }).await;
    let _ = recv_control(&mut controller, 5, |m| match m {
        ControlMessage::InputBlockApplied { blocked } => Some(*blocked),
        _ => None,
    })
    .await;

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
    eprintln!("VIEW-ONLY INPUT-BLOCK: block refused, unblock allowed, block works once lifted");
}

/// A view-only session may END, but may not UNINSTALL the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_only_session_can_end_but_cannot_uninstall_the_agent() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }
    let (mut controller, stop, agent, uninstall) = session().await;

    set_view_only(&mut controller, true).await;

    // The session is asked to end AND to remove the agent. Only the first is allowed.
    send_control(&mut controller, &ControlMessage::EndSession { uninstall: true, directive: None }).await;
    let ending = recv_control(&mut controller, 10, |m| match m {
        ControlMessage::SessionEnding { uninstall } => Some(*uninstall),
        _ => None,
    })
    .await;

    assert_eq!(
        ending,
        Some(false),
        "SessionEnding must report the uninstall flag ACTUALLY in force, not the one requested",
    );
    assert!(
        !uninstall.load(Ordering::SeqCst),
        "a view-only session armed the agent's self-uninstall — the SYSTEM-privileged \
         rmdir /s /q that docs/23 finding #3 describes was reachable from a floored session",
    );

    // The session really did end: the agent task returns rather than hanging.
    let ended = tokio::time::timeout(Duration::from_secs(15), agent).await;
    assert!(
        ended.is_ok(),
        "the session did not end — downgrading the uninstall must not also swallow the end",
    );
    stop.store(true, Ordering::Relaxed);

    eprintln!("VIEW-ONLY END-SESSION: uninstall refused and not armed, session still ended");
}

/// docs/65 D-C2: a BARE `EndSession { uninstall: true }` is no longer an authorization, from ANY session — an
/// uninstall needs a valid signed uninstall directive for this device. So with view-only OFF the same message
/// still does NOT arm the uninstall (this used to be the positive control; the positive case — a valid signed
/// directive carried in EndSession arms it, once — is `directive_hub::only_a_valid_signed_uninstall_for_this_
/// device_authorizes_and_it_is_single_use`, which needs a pinned directive key this e2e harness does not set up).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bare_uninstall_flag_is_refused_even_from_a_controlling_session() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }
    let (mut controller, stop, agent, uninstall) = session().await;

    // No SetViewOnly: the session opens controlling.
    send_control(&mut controller, &ControlMessage::EndSession { uninstall: true, directive: None }).await;
    let ending = recv_control(&mut controller, 10, |m| match m {
        ControlMessage::SessionEnding { uninstall } => Some(*uninstall),
        _ => None,
    })
    .await;

    assert_eq!(ending, Some(false), "a bare uninstall flag must not authorize an uninstall (docs/65 D-C2)");
    assert!(
        !uninstall.load(Ordering::SeqCst),
        "the uninstall flag was armed by a bare EndSession {{ uninstall: true }}",
    );

    let _ = tokio::time::timeout(Duration::from_secs(15), agent).await;
    stop.store(true, Ordering::Relaxed);
    eprintln!("CONTROLLING END-SESSION: bare uninstall flag refused (docs/65 D-C2)");
}
