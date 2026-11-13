//! End-to-end input-injection test (M2 deliverable): a controller sends input events over a REAL
//! WebRTC data channel; the agent (running [`rmt_agent_windows::host::serve_session`]) receives the
//! `Frame`s on [`ChannelId::Input`], [`input_codec::decode`](rmt_agent_core::input_codec)s them, and
//! injects them into a **RecordingSink** — proving controller → real WebRTC → agent decode → inject.
//!
//! One event does NOT arrive at the sink as it left the controller: since c7600af the agent remaps
//! a `MouseMove` from the selected monitor's frame into virtual-desktop coordinates before
//! injecting it, so the expectation for that event is computed from the live host geometry rather
//! than hardcoded. See the c7600af note beside `expected` in the test body.
//!
//! The sink here RECORDS events rather than calling `SendInput`, so the test needs no desktop and
//! makes no on-screen changes. (Real on-screen `SendInput` verification is a separate VM step: run
//! the `agent_host stream` CLI, which wires the same path to a `SendInputSink`.) The video side is
//! fed a [`SyntheticCapturer`] so `serve_session`'s capture half has something to stream while the
//! input half is exercised.
//!
//! It **self-skips** (prints `SKIP:` and returns green) when no signaling server is reachable, so
//! the default suite stays green.
//!
//! To run it for real:
//! ```
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_input -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_agent_core::platform::{InputButton, InputEvent, InputSink, PlatformResult, ScreenCapturer};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::{input_codec, SyntheticCapturer};
use rmt_agent_windows::host::serve_session;
use rmt_agent_windows::input::{norm, remap_input_for_monitor, virtual_desktop_rect};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// Records every injected event in order, so the test can assert the agent decoded exactly what the
/// controller sent.
#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<InputEvent>>,
}
impl InputSink for RecordingSink {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

/// The synthetic capturer the agent below runs on: ONE monitor, `CAP_W`×`CAP_H`, at the
/// virtual-desktop origin. The injected-MouseMove expectation is built from this same geometry, so
/// the agent's capturer and the test's expectation cannot drift apart.
const CAP_W: u32 = 64;
const CAP_H: u32 = 64;
/// `serve_session` initialises its monitor selection to id 0, and that is the id it feeds to the
/// input remap; the expectation has to use the same one.
const SELECTED_MONITOR: u32 = 0;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_events_flow_controller_to_agent_sink() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    // The exact sequence the controller will send — covers every InputEvent variant. This is the
    // WIRE form; what the agent must INJECT is `expected` below, which differs for the MouseMove.
    //
    // The pointer probe sits near the FAR corner of the frame and is deliberately asymmetric
    // (x != y): far from the origin is where the pre-c7600af bug was largest, and unequal axes
    // would catch a swapped-axis remap that a diagonal point cannot see.
    let sent = vec![
        InputEvent::MouseMove { x: 60000, y: 50000 },
        InputEvent::MouseButton { button: InputButton::Left, down: true },
        InputEvent::MouseButton { button: InputButton::Left, down: false },
        InputEvent::MouseButton { button: InputButton::Right, down: true },
        InputEvent::Scroll { dx: -1, dy: 3 },
        InputEvent::Key { code: 65, down: true },
        InputEvent::Key { code: 65, down: false },
        InputEvent::Text("hi rmt".into()),
        // The Secure Attention Sequence (Ctrl+Alt+Del) rides the SAME input channel as a unit
        // variant. Here it lands in the RecordingSink like any other event, proving it survives
        // encode → real WebRTC → decode; the actual SendSAS effect is a VM-only step (docs/07).
        InputEvent::Sas,
    ];

    // --- What the agent must INJECT, which is NOT what the controller sent (c7600af) ------------
    //
    // `serve_session` routes every drained controller event through
    // `input::remap_input_for_monitor`, which maps a MouseMove out of FRAME-normalized 0..=65535
    // (across the SELECTED monitor — all the viewer can compute, since it only ever receives that
    // one monitor's frame) into VIRTUAL-DESKTOP-normalized 0..=65535, which is what the injector's
    // `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` actually interprets. That transform is the
    // shipped multi-monitor pointer fix, not drift: before it, "middle of the captured monitor"
    // injected as "middle of ALL monitors".
    //
    // So the injected MouseMove depends on THIS host's display metrics and must never be
    // hardcoded — `virtual_desktop_rect()` reads the real machine, while the agent's capturer is a
    // 64×64 synthetic monitor. Build the expectation from the same two inputs the agent uses: the
    // SyntheticCapturer's own monitor list and the live virtual rect. Only element 0 is remapped;
    // every other variant is asserted byte-identical to the wire form, which is what would catch a
    // remap that started mangling keys, scrolls or the SAS.
    let vdesk = virtual_desktop_rect();
    let synth_monitors = SyntheticCapturer::new(CAP_W, CAP_H, 8)
        .monitors()
        .expect("synthetic capturer reports its monitor list");
    let mut expected = sent.clone();
    expected[0] =
        remap_input_for_monitor(sent[0].clone(), SELECTED_MONITOR, &synth_monitors, vdesk);

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(RecordingSink::default());

    // Agent: run the real session driver (video via SyntheticCapturer + input recv→inject).
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent_sink: Arc<dyn InputSink> = sink.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(CAP_W, CAP_H, 8);
        let dir = std::env::temp_dir().join(format!("rmt_ft_input_{}", uuid::Uuid::new_v4()));
        serve_session(&agent_url, agent_device, capturer, 30, agent_sink, agent_stop, dir).await
    });

    // Give the agent a moment to register before the controller asks to reach it.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut controller = WebRtcTransport::connect(
        &url,
        Role::dev_controller(agent_device),
    )
    .await
    .expect("controller connect");

    // Send each input event as an Input-channel frame carrying its canonical codec payload.
    for ev in &sent {
        let payload = input_codec::encode(ev);
        controller
            .send_frame(Frame::new(ChannelId::Input, payload))
            .await
            .expect("controller send input");
    }

    // Wait until the sink has recorded all events (or time out).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if sink.events.lock().unwrap().len() >= expected.len() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Stop the agent and let it drain.
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

    let got = sink.events.lock().unwrap().clone();
    assert_eq!(
        got, expected,
        "agent injected exactly the controller's events — decoded, in order, and with the \
         MouseMove remapped onto the selected monitor (see the c7600af note above)"
    );

    // --- The non-tautological half -------------------------------------------------------------
    //
    // The equality above is exact but self-referential: `expected[0]` came from the very function
    // the agent calls, so if `remap_input_for_monitor` silently became the identity, `expected`
    // would degrade back to `sent` and the assert would still pass. Pin the PROPERTY the remap
    // exists for instead, from facts measured on this host: the injected pointer must land inside
    // the SELECTED monitor's slice of the virtual desktop, expressed in the absolute units the
    // injector reads. A no-op remap injects the raw frame coordinate, which lands somewhere else
    // entirely on any host whose virtual desktop is larger than the 64×64 synthetic monitor.
    //
    // State the precondition locally rather than assuming it (this box's layout is not a fact this
    // test may assume): the check only proves something when the RAW wire point is measurably
    // outside that slice. On a degenerate host — a virtual desktop no bigger than the synthetic
    // monitor, where frame space and virtual-desktop space coincide — it is reported and skipped,
    // and only the exact-value assert above applies.
    let m = synth_monitors[0];
    let (lo_x, lo_y) = norm::point_to_absolute(m.left, m.top, vdesk);
    let (hi_x, hi_y) = norm::point_to_absolute(
        m.left + m.width as i32 - 1,
        m.top + m.height as i32 - 1,
        vdesk,
    );
    let unwrap_move = |ev: &InputEvent, what: &str| match *ev {
        InputEvent::MouseMove { x, y } => (x as i32, y as i32),
        ref other => panic!("{what} should be a MouseMove, got {other:?}"),
    };
    let (raw_x, raw_y) = unwrap_move(&sent[0], "the wire event");
    let (inj_x, inj_y) = unwrap_move(&got[0], "the injected event");
    eprintln!(
        "REMAP: host virtual desktop {vdesk:?}; monitor {SELECTED_MONITOR} ({}×{} at {},{}) spans \
         absolute x {lo_x}..={hi_x} y {lo_y}..={hi_y}; wire ({raw_x},{raw_y}) → injected \
         ({inj_x},{inj_y})",
        m.width, m.height, m.left, m.top
    );
    let raw_outside_monitor =
        raw_x < lo_x || raw_x > hi_x || raw_y < lo_y || raw_y > hi_y;
    if raw_outside_monitor {
        assert_ne!(
            got[0], sent[0],
            "the injected MouseMove equals the raw wire value — the remap did not run at the \
             injection site (c7600af regression)"
        );
        assert!(
            inj_x >= lo_x && inj_x <= hi_x && inj_y >= lo_y && inj_y <= hi_y,
            "injected pointer ({inj_x},{inj_y}) fell outside monitor {SELECTED_MONITOR}'s \
             absolute band x {lo_x}..={hi_x} y {lo_y}..={hi_y} — the remap placed it on the \
             wrong part of the virtual desktop"
        );
    } else {
        eprintln!(
            "REMAP: this host's virtual desktop {vdesk:?} is no larger than the {CAP_W}×{CAP_H} \
             synthetic monitor, so the raw wire point already sits inside the monitor's band and \
             cannot distinguish a no-op remap; only the exact-value assert applies here"
        );
    }

    eprintln!(
        "INPUT OVER WEBRTC: {} events controller→agent decoded + injected in order",
        got.len()
    );
}
