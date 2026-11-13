//! End-to-end **quality control** test (M11 deliverable): a controller negotiates quality over a
//! REAL WebRTC session and observes the result on the wire, against an agent running
//! [`rmt_agent_windows::host::serve_session_with_ice`].
//!
//! Modelled on `e2e_multimonitor.rs` — same self-skip, same [`CaptureObserver`] technique — and it
//! runs under `verify-all.ps1`, which treats a SKIP as a FAILURE.
//!
//! # What each phase proves, and against which observable
//!
//! Bytes/sec alone cannot separate the four knobs: a quarter of the pixels and a sixth of the
//! frames would each move it. So every phase is verified against the observable that its lever
//! actually controls, and no phase changes two levers at once:
//!
//! | lever | observable |
//! |---|---|
//! | `max_bitrate_bps` | RTP payload bytes/sec |
//! | `fps` | distinct RTP timestamps/sec, and the mean timestamp delta |
//! | `scale_div` | the dimensions in the next VP8 keyframe header, plus `QualityStats.width` |
//! | `color` | bytes/sec, corroborated by the `color.rs` unit pair |
//! | arming | the ABSENCE of any quality frame in a session that never asked |
//!
//! # Two traps this test is built to avoid
//!
//! 1. **A vacuous ceiling assertion.** The default [`SyntheticCapturer`] paints a smooth gradient
//!    that VP8 codes for almost nothing, so the encoder is content-limited long before any target
//!    binds and a bitrate assertion against it passes whatever the target is. Hence
//!    [`SyntheticCapturer::with_noise`], plus an explicit *validity gate*: the baseline must reach a
//!    substantial fraction of its commanded rate, or the run FAILS rather than passing having
//!    measured nothing.
//! 2. **A resolution assertion that never sees a keyframe.** VP8 carries dimensions only in a
//!    keyframe header, so the check waits for one rather than sampling whatever arrives.
//!
//! To run it for real:
//! ```text
//! cd server/signaling && go build -o signaling.exe . && ./signaling.exe   # listens on :8080
//! cargo test -p rmt-agent-windows --test e2e_quality -- --nocapture
//! ```
//! Override the URL with `SIGNALING_WS_URL` (default `ws://127.0.0.1:8080/ws`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmt_agent_core::control::{self, ControlMessage};
use rmt_agent_core::platform::{InputEvent, InputSink, PlatformResult};
use rmt_agent_core::quality::{ColorMode, QualitySettings};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::SyntheticCapturer;
use rmt_agent_windows::host::{serve_session_with_ice, QualityPolicy, SessionOptions};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

/// A no-op input sink: this test drives the control channel, not input.
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
    controller
        .send_frame(Frame::new(ChannelId::Control, control::encode(msg)))
        .await
        .expect("controller send control frame");
}

/// Connect the controller, retrying while the agent has not finished registering.
///
/// A fixed `sleep` before connecting is the obvious approach and is a race: the signaling server
/// answers `device … is not registered or offline` for a connect that arrives even slightly early,
/// which reads as a broken feature rather than a slow start-up. Retrying turns the race into a
/// bounded wait, and a genuine failure still fails — just after the deadline instead of before the
/// agent existed.
async fn connect_controller(url: &str, device: DeviceId) -> WebRtcTransport {
    // Bounded by ATTEMPTS, not by a wall clock — and that distinction is the whole point.
    //
    // The first version used a 20-second deadline, which looked equivalent and was not:
    // `WebRtcTransport::connect` has its own ~20 s internal timeout, so a single slow attempt
    // consumed the entire budget and the loop retried exactly zero times. It passed when run alone
    // and failed under `verify-all.ps1`, where every e2e binary runs concurrently and ICE is slow
    // enough for one attempt to time out. A retry loop that cannot retry is worse than none: it
    // reads as robust while providing nothing.
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

/// What a measurement window observed. The four fields are the four independent observables.
#[derive(Debug, Default, Clone)]
struct Window {
    packets: u64,
    bytes: u64,
    /// RTP timestamp -> total payload bytes for that frame.
    ///
    /// A MAP, not a set, because the count of frames on the wire and the count of frames carrying a
    /// PICTURE are different quantities and this test needs both. The keep-alive re-send that keeps
    /// the receiver's pipeline fed is a near-empty delta of a frame the receiver already has; it
    /// gets its own RTP timestamp and is indistinguishable from a real frame by timestamp alone.
    frames: std::collections::BTreeMap<u32, u64>,
    keyframe_dims: Option<(u32, u32)>,
    keyframes: u64,
    /// Bytes belonging to keyframe FRAMES (attributed by timestamp — a keyframe spans several RTP
    /// packets and only the first carries the keyframe flag). Kept so [`Window::sustained_kbps`] can
    /// exclude the one-off keyframe cost, which the bitrate target does not govern.
    keyframe_bytes: u64,
    /// Timestamps of keyframe frames seen this window (recorded on the frame-start packet), so every
    /// continuation packet of the same frame is attributed to `keyframe_bytes`.
    keyframe_ts: std::collections::BTreeSet<u32>,
}

impl Window {
    fn kbps(&self, secs: f64) -> f64 {
        (self.bytes as f64 * 8.0) / 1000.0 / secs
    }
    /// The **sustained** (delta-frame) bitrate — total minus keyframe bytes. This is what a
    /// `SetQuality` bitrate command actually controls; the periodic keyframe is a fixed cost whose
    /// presence-or-absence in a short window would otherwise make a base/low ratio flaky (a window that
    /// misses the base's keyframe but catches low's inflates the ratio). A command that does NOTHING
    /// still leaves `sustained_low ≈ sustained_base`, so excluding keyframes cannot mask a regression.
    fn sustained_kbps(&self, secs: f64) -> f64 {
        (self.bytes.saturating_sub(self.keyframe_bytes) as f64 * 8.0) / 1000.0 / secs
    }
    /// The **sustained per-frame bit cost** — sustained (non-keyframe) bits divided by the number of
    /// DELTA frames. This is what a `SetQuality` bitrate command actually sets (libvpx targets
    /// `bitrate / fps` bits per frame), and — unlike bits-per-SECOND — it is INDEPENDENT of the actual
    /// capture rate. Under `verify-all.ps1` every e2e binary runs at once, so the synthetic capturer is
    /// CPU-starved to ~15 fps early (when `base` is measured) and recovers to ~25 fps later (when `low`
    /// is measured); a bits-per-second ratio folds that fps swing into the bitrate and flakes, while
    /// bits-per-frame does not. Non-masking: a command that changed nothing leaves the two equal.
    fn sustained_bits_per_frame(&self) -> f64 {
        let delta_frames = self.frames.len().saturating_sub(self.keyframes as usize);
        if delta_frames == 0 {
            return 0.0;
        }
        (self.bytes.saturating_sub(self.keyframe_bytes) as f64 * 8.0) / delta_frames as f64
    }
    /// Frames per second ON THE WIRE — every RTP timestamp, keep-alives included.
    fn fps(&self, secs: f64) -> f64 {
        self.frames.len() as f64 / secs
    }

    /// Frames per second carrying an actual PICTURE — the rate the operator is paying for.
    ///
    /// This is the distinction the fps assertion needed and did not have. Delivery cadence is
    /// floored for LIVENESS (a starved receiver blinks), so at 5 fps commanded the wire carries
    /// ~15 fps: 5 real frames plus keep-alives filling the gaps. Asserting on wire fps therefore
    /// measured the floor and called the preset a liar; asserting on CONTENT measures what the
    /// operator actually asked for.
    ///
    /// A keep-alive is a re-encode of an unchanged picture — a near-empty VP8 delta of a few tens
    /// of bytes. A real frame from the synthetic capturer at these bitrates is thousands. The
    /// threshold sits in the middle of a gap two orders of magnitude wide, so its exact value is
    /// not load-bearing.
    fn content_fps(&self, secs: f64) -> f64 {
        const KEEPALIVE_MAX_BYTES: u64 = 500;
        self.frames.values().filter(|b| **b > KEEPALIVE_MAX_BYTES).count() as f64 / secs
    }
    /// Mean RTP timestamp delta in 90 kHz ticks — 3000 at 30 fps, 18000 at 5 fps.
    fn ts_delta(&self) -> f64 {
        let ts: Vec<u32> = self.frames.keys().copied().collect();
        if ts.len() < 2 {
            return 0.0;
        }
        let sum: u64 = ts.windows(2).map(|w| w[1].wrapping_sub(w[0]) as u64).sum();
        sum as f64 / (ts.len() - 1) as f64
    }
}

/// Collect RTP for `secs`, also draining any inbound Control frames so `QualityApplied` /
/// `QualityStats` are captured rather than left to pile up in the transport.
///
/// The two halves ALTERNATE rather than running in a `select!`, because `recv_video_packet` and
/// `recv_frame` both take `&mut self` and cannot be polled at once. Nothing is lost by alternating:
/// both are backed by queues, so a packet that arrives while we are checking the other side simply
/// waits. The same structure `stream_probe` uses, and it also keeps a control message from smearing
/// a measurement boundary.
async fn measure(
    c: &mut WebRtcTransport,
    secs: f64,
    control_out: &mut Vec<ControlMessage>,
) -> Window {
    let mut w = Window::default();
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    while Instant::now() < deadline {
        // Video first and with the longer slice: it is the higher-rate stream and the thing being
        // measured.
        match tokio::time::timeout(Duration::from_millis(20), c.recv_video_packet()).await {
            Ok(Some(p)) => {
                w.packets += 1;
                w.bytes += p.payload_len as u64;
                *w.frames.entry(p.timestamp).or_insert(0) += p.payload_len as u64;
                if p.vp8.frame_start && p.vp8.keyframe {
                    w.keyframes += 1;
                    w.keyframe_ts.insert(p.timestamp);
                    if let Some(d) = p.vp8.dimensions {
                        w.keyframe_dims = Some(d);
                    }
                }
                // Attribute every packet of a keyframe FRAME (by timestamp — the frame-start packet
                // was just inserted above, and continuation packets share its timestamp) so
                // `sustained_kbps` can subtract the whole keyframe, not just its first packet.
                if w.keyframe_ts.contains(&p.timestamp) {
                    w.keyframe_bytes += p.payload_len as u64;
                }
                continue; // drain the video queue eagerly while it has packets
            }
            Ok(None) => break, // the track closed
            Err(_) => {}       // nothing queued right now
        }
        match tokio::time::timeout(Duration::from_millis(5), c.recv_frame()).await {
            Ok(Ok(f)) if f.channel == ChannelId::Control => {
                if let Ok(m) = control::decode(&f.payload) {
                    control_out.push(m);
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break, // the data channel closed
            Err(_) => {}
        }
    }
    w
}

/// The whole M11 control flow over one live session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quality_control_changes_the_stream_over_webrtc() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        // 640x480 with DEMANDING content — see the module docs' trap #1. A keyframe every 300
        // frames so the synthetic capturer's own keyframe flag does not drown the encoder's.
        let capturer = SyntheticCapturer::new(640, 480, 300).with_noise();
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
                transfer_dir: std::env::temp_dir().join("rmt_quality_e2e_unused"),
                // An administrator's EXPLICIT 3 Mbps cap (1.3.24: an unconfigured machine no longer caps a
                // request at 3 Mbps; see QualityPolicy). Phase 0 proves a configured cap binds and says so.
                quality_policy: QualityPolicy {
                    max_bitrate_bps: 3_000_000,
                    bitrate_cap_configured: true,
                    ..QualityPolicy::default()
                },
                ..Default::default()
            },
        )
        .await
    });

    let mut c = connect_controller(&url, agent_device).await;
    let mut msgs: Vec<ControlMessage> = Vec::new();

    // --- Phase 0: the ADMINISTRATIVE ceiling binds, and says so -------------------------------
    //
    // This machine's configured policy caps it at 3 Mbps, so a technician cannot make it consume more of a
    // customer's uplink than the administrator allowed. Asking for more must come back reduced AND flagged, so
    // the operator can tell "I asked for too much" from "this machine is capped".
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings {
                max_bitrate_bps: 12_000_000,
                adaptive: false,
                ..QualitySettings::DEFAULT
            },
        },
    )
    .await;
    let mut msgs0 = Vec::new();
    let _ = measure(&mut c, 1.0, &mut msgs0).await;
    let policy_ack = msgs0
        .iter()
        .rev()
        .find_map(|m| match m {
            ControlMessage::QualityApplied { quality, capped_by_policy, .. } => {
                Some((*quality, *capped_by_policy))
            }
            _ => None,
        })
        .expect("the agent must answer an over-ask");
    assert_eq!(
        policy_ack.0.max_bitrate_bps, 3_000_000,
        "the machine's configured policy ceiling must bind"
    );
    assert!(
        policy_ack.1,
        "capped_by_policy must be TRUE when the MACHINE's ceiling reduced the ask — otherwise the \
         operator cannot tell an administrative cap from their own mistake"
    );

    // --- Phase 1: baseline, adaptation OFF so only the commanded value is in play -------------
    //
    // At the policy ceiling, not above it: every later ratio is relative to what this machine will
    // actually do.
    const HIGH: u32 = 3_000_000;
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings { max_bitrate_bps: HIGH, adaptive: false, ..QualitySettings::DEFAULT },
        },
    )
    .await;
    // Discard the connect transient (first keyframe, ICE settling) AND give libvpx's rate control time
    // to ramp UP to the 3 Mbps ceiling before measuring — under `verify-all.ps1`, where every e2e
    // binary runs concurrently, a short warm-up caught the encoder mid-ramp and the baseline read low,
    // narrowing the Phase 2 cut ratio into flakiness. A longer settle is non-masking: it cannot make a
    // stuck encoder look fast.
    let _ = measure(&mut c, 3.0, &mut msgs).await;
    let base = measure(&mut c, 3.0, &mut msgs).await;
    eprintln!(
        "phase1 baseline: {:.0} kbps ({:.0} sustained), wire {:.1} fps, content {:.1} fps, ts_delta {:.0}, dims {:?}",
        base.kbps(3.0),
        base.sustained_kbps(3.0),
        base.fps(3.0),
        base.content_fps(3.0),
        base.ts_delta(),
        base.keyframe_dims
    );

    assert!(base.packets > 20, "the stream must be flowing ({} packets)", base.packets);

    // The ack came back, carrying the CLAMPED settings.
    let applied = msgs
        .iter()
        .rev()
        .find_map(|m| match m {
            ControlMessage::QualityApplied { quality, .. } => Some(*quality),
            _ => None,
        })
        .expect("the agent must answer SetQuality with QualityApplied");
    assert_eq!(applied.max_bitrate_bps, HIGH, "an ask AT the policy ceiling passes through");
    assert!(!applied.adaptive);
    assert!(
        !msgs.iter().any(|m| matches!(
            m,
            ControlMessage::QualityApplied { capped_by_policy: true, .. }
        ) && matches!(m, ControlMessage::QualityApplied { quality, .. } if quality.max_bitrate_bps == HIGH)),
        "an ask at (not above) the ceiling must NOT be flagged as capped"
    );

    // THE RUN-VALIDITY GATE. A content-limited encoder is the most likely false negative here and
    // it produces a GREEN run — every later "the bitrate fell" assertion would pass because the
    // encoder never reached the ceiling in the first place. Turn that into an explicit failure.
    //
    // Measured as the SUSTAINED PER-FRAME bit cost — the same fps-independent basis Phase 2's cut is
    // judged on (see `sustained_bits_per_frame`). The ceiling's per-frame budget is `HIGH / 30` (the
    // default 30 fps timebase); a content-limited encoder that never approached it would produce a
    // GREEN run, so require the baseline to reach a real fraction of it.
    let base_bpf = base.sustained_bits_per_frame();
    let ceiling_bpf = HIGH as f64 / 30.0;
    assert!(
        base_bpf >= ceiling_bpf * 0.30,
        "baseline {base_bpf:.0} bits/frame is far below the commanded ceiling's {ceiling_bpf:.0} \
         bits/frame — the encoder is CONTENT-limited, so this run cannot detect a bitrate change at \
         all and must not report one. (Is SyntheticCapturer::with_noise still in use?)"
    );

    // --- Phase 2: bitrate only. Frames must NOT change; bytes must. ---------------------------
    const LOW: u32 = 400_000;
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings { max_bitrate_bps: LOW, adaptive: false, ..QualitySettings::DEFAULT },
        },
    )
    .await;
    // Let libvpx's rate control settle DOWN to 400 kbps. A 1 s warm-up was too short under concurrent
    // gate load — the window caught the encoder still shedding bits from the 3 Mbps baseline, reading
    // `low` high and the cut ratio into flakiness. Non-masking: more settle cannot make a command that
    // did nothing look like it cut the rate.
    let _ = measure(&mut c, 3.0, &mut msgs).await;
    let low = measure(&mut c, 3.0, &mut msgs).await;
    eprintln!(
        "phase2 bitrate: {:.0} kbps ({:.0} sustained), {:.1} fps, ts_delta {:.0}, kf {}",
        low.kbps(3.0),
        low.sustained_kbps(3.0),
        low.fps(3.0),
        low.ts_delta(),
        low.keyframes
    );
    // Judge the cut on the SUSTAINED PER-FRAME bit cost the bitrate command actually governs — NOT
    // bits-per-second, which folds in the capture-fps swing that concurrent gate load causes (base
    // measured at ~15 fps, low at ~25 fps), and NOT the one-off keyframe. This cannot mask a broken
    // command: a no-op leaves low_bpf ≈ base_bpf. (The content floor keeps low_bpf well above the
    // literal 400 kbps/30 target, which is exactly why the ratio, not an absolute, is the assertion.)
    let low_bpf = low.sustained_bits_per_frame();
    assert!(
        low_bpf < base_bpf * 0.6,
        "a 3 Mbps -> 400 kbps command must cut the per-frame bit cost: {low_bpf:.0} vs {base_bpf:.0} bits/frame",
    );
    // The frame rate is untouched, so the drop is attributable to the bitrate lever alone.
    assert!(
        low.fps(3.0) > base.fps(3.0) * 0.6,
        "the frame rate must be unchanged by a bitrate command: {:.1} vs {:.1}",
        low.fps(3.0),
        base.fps(3.0)
    );
    // And it cost no keyframe STORM — a re-init per adjustment would be catastrophic here.
    //
    // Deliberately `<= 1` rather than `== 0`: the encoder's own keyframe backstop (60 s since
    // 2026-10-14, 4 s before) is free to fire inside any 3-second window, and at this level it is indistinguishable from one caused
    // by the command. The DECISIVE proof that `set_bitrate` uses `vpx_codec_enc_config_set` and not
    // a re-init is the unit test `set_bitrate_changes_a_live_context_without_a_keyframe`, which
    // controls the frame timeline exactly and asserts zero. Asserting `== 0` here would be a flaky
    // test masquerading as a strong one.
    assert!(
        low.keyframes <= 1,
        "a bitrate change produced {} keyframes in 3 s — that is a re-init per adjustment, not a \
         live reconfigure",
        low.keyframes
    );

    // --- Phase 3: frame rate only. The RTP CLOCK must follow, not just the packet count. -------
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings {
                fps: 5,
                max_bitrate_bps: LOW,
                adaptive: false,
                ..QualitySettings::DEFAULT
            },
        },
    )
    .await;
    let _ = measure(&mut c, 1.0, &mut msgs).await;
    let slow = measure(&mut c, 4.0, &mut msgs).await;
    eprintln!(
        "phase3 fps: {:.0} kbps, wire {:.1} fps, content {:.1} fps, ts_delta {:.0}",
        slow.kbps(4.0),
        slow.fps(4.0),
        slow.content_fps(4.0),
        slow.ts_delta()
    );
    // Assert on CONTENT, not on wire cadence. The commanded rate is a budget for NEW PICTURE; the
    // delivery cadence is floored separately so the receiver's pipeline is never starved (that
    // starvation is the "blink"). This assertion used to read wire fps and therefore measured the
    // floor — it reported 14.5 for a 5 fps preset and called the label a lie, when what it had
    // actually caught was two different quantities sharing one number.
    assert!(
        slow.content_fps(4.0) < base.content_fps(3.0) * 0.5,
        "5 fps must deliver visibly fewer PICTURES than 30: {:.1} vs {:.1} content fps",
        slow.content_fps(4.0),
        base.content_fps(3.0)
    );
    // And the operator must actually get the bandwidth saving they chose the preset for — the whole
    // point of "Text (slow link)", and a property no frame count can express.
    assert!(
        slow.kbps(4.0) < base.kbps(3.0) * 0.5,
        "5 fps must cost visibly less bandwidth than 30: {:.0} vs {:.0} kbps",
        slow.kbps(4.0),
        base.kbps(3.0)
    );
    // THE constraint that the pre-M11 hardcoded 33 ms `Sample::duration` could not satisfy: the RTP
    // timestamps must advance at the REAL delivery rate, not a constant 30 fps. Delivery is floored
    // at ~15 fps (6000 ticks), so this no longer expects the 18000 of a bare 5 fps — but a hardcoded
    // 30 fps duration would still report ~3000, which this catches with room to spare.
    let d = slow.ts_delta();
    assert!(
        d > 4500.0,
        "the mean RTP timestamp delta is {d:.0}, at or below the 3000 ticks a hardcoded 30 fps \
         duration would produce — the RTP clock is not following the real delivery rate"
    );

    // --- Phase 4: resolution only, verified from the VP8 KEYFRAME HEADER -----------------------
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings {
                scale_div: 2,
                max_bitrate_bps: LOW,
                adaptive: false,
                ..QualitySettings::DEFAULT
            },
        },
    )
    .await;
    let scaled = measure(&mut c, 4.0, &mut msgs).await;
    eprintln!("phase4 scale: dims {:?}, kf {}", scaled.keyframe_dims, scaled.keyframes);
    assert_eq!(
        scaled.keyframe_dims,
        Some((320, 240)),
        "a scale_div of 2 on a 640x480 capture must produce a 320x240 keyframe header"
    );
    // The agent's own telemetry must agree with what the wire showed. Two independent observables
    // of the same fact: if only one moved, something other than the encoder changed.
    let stats_dims = msgs
        .iter()
        .rev()
        .find_map(|m| match m {
            ControlMessage::QualityStats { width, height, .. } if *width > 0 => {
                Some((*width, *height))
            }
            _ => None,
        })
        .expect("the agent must have sent 1 Hz QualityStats after arming");
    assert_eq!(
        stats_dims,
        (320, 240),
        "the agent's QualityStats must agree with the keyframe header"
    );

    // --- Phase 5: hostile values are clamped, and the session survives -------------------------
    // scale_div 0 divides by zero in the scaler, fps 0 panics the capture thread's pacing division,
    // and a 1 bps ceiling makes the encoder refuse to construct. All three must be clamped rather
    // than obeyed, and the stream must keep flowing.
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings {
                scale_div: 0,
                fps: 0,
                color: ColorMode::Full,
                max_bitrate_bps: 1,
                adaptive: true,
            },
        },
    )
    .await;
    let after = measure(&mut c, 3.0, &mut msgs).await;
    let clamped = msgs
        .iter()
        .rev()
        .find_map(|m| match m {
            ControlMessage::QualityApplied { quality, .. } => Some(*quality),
            _ => None,
        })
        .expect("QualityApplied for the hostile request");
    assert_eq!(clamped.scale_div, 1, "scale_div 0 must clamp to 1");
    assert_eq!(clamped.fps, 1, "fps 0 must clamp to 1");
    assert_eq!(clamped.max_bitrate_bps, 100_000, "1 bps must clamp to the floor");
    assert!(
        after.packets > 0,
        "the session must survive a hostile quality request (a divide-by-zero would have killed \
         the capture thread and the stream with it)"
    );

    // --- Phase 6: restore. The knobs must go back UP, not only down. ---------------------------
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings { max_bitrate_bps: HIGH, adaptive: false, ..QualitySettings::DEFAULT },
        },
    )
    .await;
    let _ = measure(&mut c, 1.5, &mut msgs).await;
    let restored = measure(&mut c, 3.0, &mut msgs).await;
    eprintln!(
        "phase6 restored: {:.0} kbps, {:.1} fps, dims {:?}",
        restored.kbps(3.0),
        restored.fps(3.0),
        restored.keyframe_dims
    );
    assert!(
        restored.kbps(3.0) > low.kbps(3.0) * 1.5,
        "restoring the ceiling must raise the rate again: {:.0} vs {:.0} kbps",
        restored.kbps(3.0),
        low.kbps(3.0)
    );
    assert!(
        restored.fps(3.0) > slow.fps(4.0) * 2.0,
        "restoring the frame rate must raise it again: {:.1} vs {:.1}",
        restored.fps(3.0),
        slow.fps(4.0)
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}

/// **The fail-safe.** A controller that never mentions quality must receive NOTHING new.
///
/// This is the test that protects an older viewer bundle: its `decodeControl` throws on an unknown
/// variant, and it is called inside a loop over the frames coalesced into one SCTP message — so one
/// unsolicited `QualityStats` would discard its innocent siblings too. The agent not speaking first
/// is the defence that does not depend on the controller being new.
///
/// Mutation that must turn this red: drop the `quality_armed` gate in `serve_session_with_ice`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unarmed_session_never_sends_a_quality_frame() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(320, 240, 30);
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
                transfer_dir: std::env::temp_dir().join("rmt_quality_e2e_unused"),
                ..Default::default()
            },
        )
        .await
    });

    let mut c = connect_controller(&url, agent_device).await;

    // Behave exactly like a pre-M11 controller: ask for monitors, never mention quality.
    send_control(&mut c, &ControlMessage::RequestMonitors).await;

    let mut msgs = Vec::new();
    let w = measure(&mut c, 5.0, &mut msgs).await;

    // The session is genuinely alive — otherwise "no quality frames" would be trivially true.
    assert!(w.packets > 20, "the stream must be flowing ({} packets)", w.packets);
    assert!(
        msgs.iter().any(|m| matches!(m, ControlMessage::MonitorList { .. })),
        "the control channel must be working (no MonitorList arrived), or this test proves nothing"
    );
    let quality_frames: Vec<&ControlMessage> = msgs
        .iter()
        .filter(|m| {
            matches!(
                m,
                ControlMessage::QualityApplied { .. } | ControlMessage::QualityStats { .. }
            )
        })
        .collect();
    assert!(
        quality_frames.is_empty(),
        "an unarmed session sent {} quality frame(s): {quality_frames:?}",
        quality_frames.len()
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}

/// **The clean-link no-op.** With adaptation ON and no loss, the agent must never retarget the
/// encoder: the controller starts at the operator's ceiling, so the only available move is an
/// increase toward a ceiling it already occupies.
///
/// The second half of the assertion is what makes it meaningful — `feedback_reports` must be
/// CLIMBING. Otherwise "the rate never changed" is equally consistent with "no feedback ever
/// arrived", and the test would pass against a completely disconnected rate controller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_link_never_retargets_the_encoder() {
    let url = signaling_url();
    if !signaling_reachable(&url).await {
        eprintln!("SKIP: no signaling server reachable at {url} (start server/signaling to run this)");
        return;
    }

    let agent_device = DeviceId::new();
    let stop = Arc::new(AtomicBool::new(false));
    let agent_url = url.clone();
    let agent_stop = stop.clone();
    let agent = tokio::spawn(async move {
        let capturer = SyntheticCapturer::new(640, 480, 300).with_noise();
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
                transfer_dir: std::env::temp_dir().join("rmt_quality_e2e_unused"),
                ..Default::default()
            },
        )
        .await
    });

    let mut c = connect_controller(&url, agent_device).await;

    const CEILING: u32 = 2_000_000;
    send_control(
        &mut c,
        &ControlMessage::SetQuality {
            quality: QualitySettings {
                max_bitrate_bps: CEILING,
                adaptive: true,
                ..QualitySettings::DEFAULT
            },
        },
    )
    .await;

    let mut msgs = Vec::new();
    let _ = measure(&mut c, 10.0, &mut msgs).await;

    let stats: Vec<(u32, u64)> = msgs
        .iter()
        .filter_map(|m| match m {
            ControlMessage::QualityStats { encoder_bitrate_bps, feedback_reports, .. } => {
                Some((*encoder_bitrate_bps, *feedback_reports))
            }
            _ => None,
        })
        .collect();
    assert!(
        stats.len() >= 5,
        "expected ~1 Hz QualityStats over 10 s, got {} — is the reporter on a `sleep` arm that \
         never fires? (see the interval comment in serve_session_with_ice)",
        stats.len()
    );

    // PACE ON THE ENCODER'S OWN SIGNAL, not on t=0. `QualityStats.encoder_bitrate_bps` reports
    // `applied_bps` — "what libvpx was last successfully told" — which is initialised to the
    // session default (`DEFAULT_MAX_BITRATE_BPS`, 3 Mbps, ABOVE this 2 Mbps CEILING) and only
    // becomes the ceiling once the `SetBitrate` for our request has travelled the encoder-command
    // queue and libvpx has accepted it. That application is strictly LATER than the `QualityApplied`
    // ack (which echoes the target directly, without waiting for the encoder), so the 1 Hz reporter
    // can emit its first sample while `applied_bps` still carries the pre-request default. Asserting
    // over *every* sample from t=0 therefore races the encoder-command queue — it passed 5/5 in
    // isolation and only failed under the gate's concurrent load, where that first sample slips in.
    //
    // The teeth are preserved precisely because the predicate is `> CEILING`, not `!= CEILING`: the
    // clean-link controller starts AT the ceiling and can only HOLD or LOWER (divergence 2 in
    // `rate.rs`), so a value *above* the ceiling is unambiguously the un-applied default and can
    // only ever appear as a LEADING run. A spurious retarget is a value *below* the ceiling — never
    // in the leading run, never skipped, and still caught by the exact-equality check below. We drop
    // only the leading over-ceiling transient; the very first at-or-below-ceiling sample ends the
    // skip, so a mid-stream drop after settling still fails.
    let settled: Vec<(u32, u64)> = stats
        .iter()
        .copied()
        .skip_while(|(bps, _)| *bps > CEILING)
        .collect();
    assert!(
        settled.len() >= 3,
        "after the encoder applied the ceiling only {} sample(s) remained (all {} were {stats:?}) \
         — too few to prove the rate then HELD at the ceiling. Did the encoder never settle to the \
         ceiling within the window?",
        settled.len(),
        stats.len()
    );
    for (bps, _) in &settled {
        assert_eq!(
            *bps, CEILING,
            "a clean link must leave the encoder AT the ceiling once applied; saw {bps} in \
             {settled:?} (a value BELOW the ceiling is a spurious retarget the fail-safe must \
             prevent; a value ABOVE it would be the un-applied default and is skipped as the \
             leading transient — this one was neither)"
        );
    }
    // The negative control's negative control: the absence of change must not be the absence of
    // feedback. Loopback RTCP is real — webrtc-rs registers a ReceiverReport interceptor at 1 Hz.
    // Measured across the SETTLED window, so "feedback kept arriving while the rate held" is what is
    // actually asserted, not "feedback arrived during the startup transient".
    let first = settled.first().expect("settled is non-empty (checked above)").1;
    let last = settled.last().expect("settled is non-empty (checked above)").1;
    assert!(
        last > first,
        "feedback_reports never moved ({first} -> {last}) while the rate held; the rate controller \
         received nothing, so 'it did not change the rate' proves nothing"
    );

    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;
}
