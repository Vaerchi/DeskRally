//! Loss-based send-side bandwidth estimation (M11), ported from libwebrtc's
//! `SendSideBandwidthEstimation` loss path.
//!
//! # Pure by construction
//!
//! No I/O, no clock, no libvpx, no async. Time is a **parameter**. That is the single most
//! important decision in this file: the table tests below run in microseconds, deterministically,
//! with no `sleep` and no flake, and every constant can be exercised at its exact boundary.
//!
//! # The signal, and why it is this one
//!
//! RTCP **Receiver Reports**. webrtc-rs registers a `ReceiverReport` interceptor on every peer by
//! default, at a 1 Hz interval, carrying a genuinely computed RFC 3550 `fraction lost` plus
//! LSR/DLSR for round-trip time — so both a browser and our own `stream_probe` already report to us
//! unprompted, with no SDP change. `goog-remb` is also negotiated on VP8, so a browser additionally
//! sends REMB, which is handled here as a *conditional* cap (see below).
//!
//! Transport-wide congestion control (TWCC) would be the better estimator, and is deliberately out
//! of scope: webrtc-rs configures TWCC **receiver-only**, so our outbound RTP carries no transport
//! sequence numbers and no peer can produce TWCC feedback for us — and webrtc-rs has no pacer, so a
//! delay-based estimator would read our own burstiness as queue growth. Both blockers are
//! structural, and [`Feedback`] is the plug-in point when they are lifted.
//!
//! # Three deliberate divergences from libwebrtc
//!
//! 1. **`fraction_lost` is used directly**, rather than libwebrtc's cumulative `ext_seq`/`total_lost`
//!    accounting. Cumulative counters are correct for a single reporter and produce garbage the
//!    moment two report sources exist for one SSRC — which is exactly what the deterministic
//!    crafted-RTCP test harness creates (the probe's own interceptor keeps reporting alongside the
//!    injected packets). `fraction_lost` is self-describing per report, so it is immune. libwebrtc's
//!    `kLimitNumPackets` sample-size guard is replaced by [`MIN_BYTES_BETWEEN_DECISIONS`], measured
//!    from **our own** encoded-byte counter — same purpose, immune to reporter mixing.
//! 2. **The controller starts AT the ceiling**, not at a low probe. libwebrtc starts low because it
//!    knows nothing about the link; we have a human-chosen ceiling. The consequence is the
//!    fail-safe: on a link with no loss the only available move is an increase toward a ceiling
//!    already occupied, which clamps to a no-op and is suppressed — so **no command is ever
//!    emitted and the encoder is never touched**. Today's behaviour is preserved by construction,
//!    provable by a unit test rather than asserted by a flag.
//! 3. **REMB is gated on encoder saturation.** libwebrtc caps on REMB unconditionally because its
//!    pacer keeps the link busy, making the receive-side estimate a real capacity estimate. With no
//!    pacer, a mostly-idle desktop sends ~200 kbps, the receiver estimates ~200 kbps, and an
//!    unconditional cap would pin us there forever — unable to burst on a scroll. So REMB is
//!    trusted only when our own encoder is spending at least [`REMB_TRUST_RATIO_PCT`] of its target,
//!    i.e. when the target genuinely binds and REMB is describing the link rather than our idleness.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long an increase looks back for its "sliding minimum" reference — libwebrtc's
/// `kBweIncreaseInterval`.
pub const BWE_INCREASE_INTERVAL: Duration = Duration::from_millis(1000);
/// Minimum spacing between two decreases, on top of one RTT — libwebrtc's `kBweDecreaseInterval`.
/// Without it, a burst of reports describing the *same* congestion event multiplies the cut.
pub const BWE_DECREASE_INTERVAL: Duration = Duration::from_millis(300);
/// After this long with no feedback the loss estimate is stale; the next report re-establishes the
/// baseline instead of being acted on (1.2 × libwebrtc's `kMaxRtcpFeedbackInterval`).
pub const LOSS_REPORT_VALIDITY: Duration = Duration::from_millis(6000);
/// Below this fraction lost (in 1/256 units) the link is clean — libwebrtc's
/// `kDefaultLowLossThreshold`, 0.02 × 256.
pub const LOW_LOSS_256: u8 = 5;
/// Above this fraction lost the link is congested — `kDefaultHighLossThreshold`, 0.10 × 256.
/// Between the two is a deliberate dead band: wireless jitter must not oscillate the rate.
pub const HIGH_LOSS_256: u8 = 26;
/// Absolute floor, bits/sec. Below this, screen content stops being legible at any resolution and
/// a frozen picture would be preferable to what we would send.
pub const FLOOR_BPS: u32 = 250_000;
/// Encoded bytes that must accumulate between two decisions (~20 × 1200-byte packets). This is the
/// sample-size guard: without it a burst of reports about one already-answered event keeps cutting.
pub const MIN_BYTES_BETWEEN_DECISIONS: u64 = 24_000;
/// Trust a REMB only when our encoder is spending at least this percentage of its target — see the
/// module docs' third divergence.
pub const REMB_TRUST_RATIO_PCT: u64 = 70;
/// RTT assumed until a report carries LSR/DLSR.
pub const DEFAULT_RTT: Duration = Duration::from_millis(100);
/// Per-report increase, in percent of the sliding minimum (libwebrtc's 1.08 factor).
pub const INCREASE_PCT: u32 = 108;
/// Additive term on top of the multiplicative increase, bits/sec — keeps recovery from stalling at
/// very low rates where 8 % is a rounding error.
pub const INCREASE_ADDITIVE_BPS: u32 = 1_000;
/// A new target is only emitted when it differs from the applied one by at least this percentage.
/// Turns "a decision every second" into roughly 20 encoder reconfigurations per decade of rate.
pub const APPLY_HYSTERESIS_PCT: u32 = 5;

/// One piece of receiver feedback the controller understands, already SSRC-matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// PLI or FIR: the receiver cannot decode. Handled by the keyframe path, never by the rate
    /// controller — a keyframe is the opposite of what a congested link needs.
    Keyframe,
    /// A Receiver Report block naming our SSRC.
    Rr {
        /// RFC 3550 fraction lost, 1/256 units.
        fraction_lost_256: u8,
        /// Round-trip time from LSR/DLSR, when measurable.
        rtt: Option<Duration>,
    },
    /// A receiver-estimated maximum bitrate (`goog-remb`) naming our SSRC.
    Remb {
        /// The receiver's estimate, bits/sec.
        bps: u32,
    },
}

/// What the controller currently knows about the encoder and the operator's wishes. Passed in per
/// decision rather than stored, so the controller owns no shared state and stays pure.
#[derive(Debug, Clone, Copy)]
pub struct RateInputs {
    /// The operator's ceiling, bits/sec. The controller never exceeds it.
    pub ceiling_bps: u32,
    /// Whether the operator allows adaptation at all. `false` pins the target at the ceiling.
    pub adaptive: bool,
    /// Total encoded bytes so far this session — the sample-size clock.
    pub encoded_bytes: u64,
    /// Bits/sec the encoder actually produced over the last window. Used only by the REMB gate.
    pub measured_bps: u32,
}

/// The loss-based estimator. One per session, owned by the RTCP loop (single writer).
#[derive(Debug)]
pub struct LossBasedBwe {
    target_bps: u32,
    /// `(when, target)` samples inside [`BWE_INCREASE_INTERVAL`], kept as a monotone queue whose
    /// front is the minimum. Increases are computed from that minimum, never from the current
    /// value — see [`LossBasedBwe::on_feedback`].
    min_history: VecDeque<(Instant, u32)>,
    last_decrease: Option<Instant>,
    last_feedback: Option<Instant>,
    rtt: Duration,
    bytes_at_last_decision: u64,
    /// The last value handed to the encoder, for the hysteresis comparison.
    emitted_bps: u32,
}

impl LossBasedBwe {
    /// Start at the operator's ceiling. See divergence 2 in the module docs: this is what makes a
    /// clean link a guaranteed no-op rather than a hoped-for one.
    pub fn new(ceiling_bps: u32) -> Self {
        Self {
            target_bps: ceiling_bps,
            min_history: VecDeque::new(),
            last_decrease: None,
            last_feedback: None,
            rtt: DEFAULT_RTT,
            bytes_at_last_decision: 0,
            emitted_bps: ceiling_bps,
        }
    }

    /// Feed one piece of feedback. Returns `Some(bps)` when the encoder should be retargeted.
    ///
    /// Returning `None` is the common case and the important one: it means no FFI call, no
    /// reconfiguration, and no risk. A clean link produces nothing but `None`.
    pub fn on_feedback(
        &mut self,
        fb: Feedback,
        now: Instant,
        inputs: RateInputs,
    ) -> Option<u32> {
        // A keyframe request is not a rate signal.
        if matches!(fb, Feedback::Keyframe) {
            return None;
        }

        // The operator's hard off. Snap to the ceiling in BOTH directions — a technician who
        // unticks "adapt automatically" on a degraded link expects the rate to go back up.
        if !inputs.adaptive {
            self.target_bps = inputs.ceiling_bps;
            self.min_history.clear();
            return self.emit(self.target_bps);
        }

        // Sample-size guard (libwebrtc's kLimitNumPackets, measured our way — see divergence 1).
        // Deliberately after the `!adaptive` branch: turning adaptation off must take effect at
        // once, not after 24 KB of video.
        if inputs.encoded_bytes.saturating_sub(self.bytes_at_last_decision)
            < MIN_BYTES_BETWEEN_DECISIONS
        {
            return None;
        }

        let floor = FLOOR_BPS.min(inputs.ceiling_bps);

        match fb {
            Feedback::Keyframe => unreachable!("handled above"),
            Feedback::Remb { bps } => {
                // Only trust a receive-side estimate while our encoder is genuinely saturating its
                // target; otherwise REMB is measuring our idleness, not the link.
                let saturating = (inputs.measured_bps as u64) * 100
                    >= (self.target_bps as u64) * REMB_TRUST_RATIO_PCT;
                if !saturating || bps == 0 {
                    return None;
                }
                self.target_bps = self.target_bps.min(bps.max(floor));
            }
            Feedback::Rr { fraction_lost_256, rtt } => {
                if let Some(r) = rtt {
                    self.rtt = r;
                }
                // A long feedback gap means the estimate is stale (the link may have healed or
                // collapsed while we heard nothing). Re-establish the baseline instead of acting on
                // a report that describes an unknown interval.
                let stale = self
                    .last_feedback
                    .is_none_or(|prev| now.saturating_duration_since(prev) > LOSS_REPORT_VALIDITY);
                self.last_feedback = Some(now);
                if stale {
                    return None;
                }

                if fraction_lost_256 <= LOW_LOSS_256 {
                    // Increase from the SLIDING MINIMUM of the last second, not from the current
                    // value. On an oscillating link the current value ping-pongs, and compounding
                    // from it lets the target ratchet upward across the oscillation — recovering to
                    // a rate the link never actually sustained.
                    //
                    // PRUNE FIRST. The queue is only pruned by `update_min_history`, which runs at
                    // the END of a decision — so reading the front here without pruning reads a
                    // minimum that may already have expired, and recovery is then anchored to a
                    // rate from further back than one second. "The minimum of the last second" is
                    // the property the whole mechanism is named for; letting it silently mean "the
                    // minimum of the last second *as of the previous decision*" makes recovery
                    // slower than designed and, worse, makes it depend on report timing.
                    self.prune_min_history(now);
                    let base = self.min_history.front().map_or(self.target_bps, |&(_, v)| v);
                    self.target_bps = ((base as u64 * INCREASE_PCT as u64) / 100)
                        .saturating_add(INCREASE_ADDITIVE_BPS as u64)
                        .min(u32::MAX as u64) as u32;
                } else if fraction_lost_256 > HIGH_LOSS_256 {
                    // One decrease per congestion event, not one per report.
                    let ready = self
                        .last_decrease
                        .is_none_or(|prev| {
                            now.saturating_duration_since(prev) >= BWE_DECREASE_INTERVAL + self.rtt
                        });
                    if !ready {
                        return None;
                    }
                    // libwebrtc's multiplicative decrease: x (1 - loss/2).
                    self.target_bps = ((self.target_bps as u64
                        * (512 - fraction_lost_256 as u64))
                        / 512) as u32;
                    self.last_decrease = Some(now);
                } else {
                    return None; // the 2%-10% dead band: hold
                }
            }
        }

        self.target_bps = self.target_bps.clamp(floor, inputs.ceiling_bps);
        self.update_min_history(now, self.target_bps);
        self.bytes_at_last_decision = inputs.encoded_bytes;
        self.emit_bounded(self.target_bps, floor, inputs.ceiling_bps)
    }

    /// Re-clamp after the operator moved the ceiling, without waiting for feedback.
    ///
    /// Lowering the ceiling must bind immediately. Raising it must **not** teleport the target: on a
    /// link the controller has already backed off, jumping straight to a new higher ceiling would
    /// re-flood it. Recovery stays the increase path's job.
    pub fn on_ceiling_changed(&mut self, ceiling_bps: u32, adaptive: bool) -> u32 {
        if !adaptive {
            self.target_bps = ceiling_bps;
        } else {
            let floor = FLOOR_BPS.min(ceiling_bps);
            self.target_bps = self.target_bps.clamp(floor, ceiling_bps);
        }
        self.emitted_bps = self.target_bps;
        self.target_bps
    }

    /// Adopt the target established by the encoder ceiling path, including intervening shrinks.
    /// Reset hysteresis and the sliding minimum so recovery starts at that actual target.
    pub fn adopt_target(&mut self, target_bps: u32, now: Instant, ceiling_bps: u32, adaptive: bool) -> u32 {
        self.target_bps = if adaptive {
            target_bps.clamp(FLOOR_BPS.min(ceiling_bps), ceiling_bps)
        } else { ceiling_bps };
        self.emitted_bps = self.target_bps;
        self.min_history.clear();
        self.update_min_history(now, self.target_bps);
        self.target_bps
    }

    /// Suppress a change smaller than [`APPLY_HYSTERESIS_PCT`]. Each emitted value costs an FFI
    /// reconfiguration; one per second per 1 % wobble is noise, not control.
    fn emit(&mut self, bps: u32) -> Option<u32> {
        let prev = self.emitted_bps;
        let delta = bps.abs_diff(prev) as u64;
        if delta * 100 < prev as u64 * APPLY_HYSTERESIS_PCT as u64 {
            return None;
        }
        self.emitted_bps = bps;
        Some(bps)
    }

    /// [`emit`](Self::emit), but a value that lands **exactly on a boundary** is always emitted.
    ///
    /// Measured, not anticipated: recovery approaches the ceiling multiplicatively, so the final
    /// step is small — from 3.87 Mbps to a 4 Mbps ceiling is 3.4 %, under the 5 % hysteresis. Plain
    /// hysteresis therefore *permanently* parks the encoder just below the rate the operator
    /// explicitly chose, and no later report can fix it because every subsequent step is smaller
    /// still. The floor has the mirror problem on the way down.
    ///
    /// A boundary is a value the operator or the policy named, so arriving at it is worth one FFI
    /// call. Everything between them is still subject to the hysteresis.
    fn emit_bounded(&mut self, bps: u32, floor: u32, ceiling: u32) -> Option<u32> {
        if (bps == ceiling || bps == floor) && bps != self.emitted_bps {
            self.emitted_bps = bps;
            return Some(bps);
        }
        self.emit(bps)
    }

    /// Drop samples older than [`BWE_INCREASE_INTERVAL`] from the front, so the front is the
    /// minimum target of the last second **as of `now`**.
    ///
    /// Separate from [`update_min_history`](Self::update_min_history) because the increase path
    /// must prune *before* it reads the front, while the update path prunes on the way in — one
    /// helper called from both keeps the two from drifting.
    fn prune_min_history(&mut self, now: Instant) {
        while self
            .min_history
            .front()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) > BWE_INCREASE_INTERVAL)
        {
            self.min_history.pop_front();
        }
    }

    /// Monotone-minimum queue over [`BWE_INCREASE_INTERVAL`]: drop expired samples from the front,
    /// drop trailing samples no smaller than the new one, then push. The front is therefore always
    /// the minimum target of the last second.
    fn update_min_history(&mut self, now: Instant, target: u32) {
        self.prune_min_history(now);
        while self.min_history.back().is_some_and(|&(_, v)| v >= target) {
            self.min_history.pop_back();
        }
        self.min_history.push_back((now, target));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CEILING: u32 = 4_000_000;

    fn inputs(bytes: u64) -> RateInputs {
        RateInputs {
            ceiling_bps: CEILING,
            adaptive: true,
            encoded_bytes: bytes,
            measured_bps: CEILING, // saturating, so the REMB gate is open unless a test says otherwise
        }
    }

    fn clean() -> Feedback {
        Feedback::Rr { fraction_lost_256: 0, rtt: Some(Duration::from_millis(20)) }
    }

    fn lossy(pct: u32) -> Feedback {
        Feedback::Rr {
            fraction_lost_256: ((pct * 256) / 100) as u8,
            rtt: Some(Duration::from_millis(20)),
        }
    }

    /// Drive `n` reports one second apart, returning every emitted target.
    fn drive(bwe: &mut LossBasedBwe, start: Instant, n: u32, fb: impl Fn(u32) -> Feedback) -> Vec<u32> {
        let mut out = Vec::new();
        let mut bytes = 0u64;
        for i in 0..n {
            bytes += 500_000; // well over MIN_BYTES_BETWEEN_DECISIONS
            let at = start + Duration::from_millis(1000 * (i as u64 + 1));
            if let Some(v) = bwe.on_feedback(fb(i), at, inputs(bytes)) {
                out.push(v);
            }
        }
        out
    }

    #[test]
    fn adoption_reanchors_target_and_history() {
        let mut bwe = LossBasedBwe::new(9_000_000);
        let now = Instant::now();
        bwe.update_min_history(now, 100_000);
        assert_eq!(bwe.adopt_target(3_000_000, now, 9_000_000, true), 3_000_000);
        assert_eq!(bwe.emitted_bps, 3_000_000);
        assert_eq!(bwe.min_history.front().unwrap().1, 3_000_000);
        assert_eq!(bwe.adopt_target(0, now, 9_000_000, true), FLOOR_BPS);
        assert_eq!(bwe.adopt_target(3_000_000, now, 9_000_000, false), 9_000_000);
    }

    /// **The constraint-6 proof.** On a link with no loss the controller must emit NOTHING — not
    /// "roughly the same value", not "the ceiling again": no command at all, so
    /// `vpx_codec_enc_config_set` is never called and behaviour is byte-identical to pre-M11.
    ///
    /// Mutation: make `LossBasedBwe::new` start below the ceiling. Then the increase path has room
    /// to move and this fails immediately.
    #[test]
    fn a_clean_link_never_changes_the_target() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        // The first report only establishes the baseline (nothing preceded it).
        let emitted = drive(&mut bwe, t0, 30, |_| clean());
        assert!(
            emitted.is_empty(),
            "30 seconds of a clean link emitted {emitted:?}; it must emit nothing"
        );
        assert_eq!(bwe.target_bps, CEILING, "and the target never left the ceiling");
    }

    /// The decrease is libwebrtc's exact formula, not merely "went down". A test that only asserted
    /// a fall would pass for any decreasing function, including ones that collapse the link.
    #[test]
    fn loss_decreases_by_exactly_the_libwebrtc_formula() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        // Establish the feedback baseline first (a stale first report is not acted on).
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let loss = 38u8; // ~15%
        let at = t0 + Duration::from_millis(1000);
        let got = bwe
            .on_feedback(
                Feedback::Rr { fraction_lost_256: loss, rtt: Some(Duration::from_millis(20)) },
                at,
                inputs(600_000),
            )
            .expect("a decrease");
        let expect = ((CEILING as u64 * (512 - loss as u64)) / 512) as u32;
        assert_eq!(got, expect, "x (1 - loss/2), exactly");
        assert!(got < CEILING);
    }

    /// A burst of reports describing ONE congestion event must produce ONE decrease.
    /// Mutation: delete the `BWE_DECREASE_INTERVAL + rtt` gate.
    #[test]
    fn two_loss_reports_100ms_apart_produce_one_decrease() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let first = bwe
            .on_feedback(lossy(30), t0 + Duration::from_millis(500), inputs(600_000))
            .expect("first decrease");
        // 100 ms later, well inside 300 ms + 20 ms RTT.
        let second = bwe.on_feedback(lossy(30), t0 + Duration::from_millis(600), inputs(1_200_000));
        assert_eq!(second, None, "the second report must be gated, not compounded");
        // ...and once the interval has passed, it decreases again.
        let third = bwe
            .on_feedback(lossy(30), t0 + Duration::from_millis(1000), inputs(1_800_000))
            .expect("gate released");
        assert!(third < first, "{third} should be below {first}");
    }

    /// The 2 %–10 % dead band. A naive "any loss ⇒ reduce" controller fails only this test — which
    /// is exactly why it exists: wireless links lose a couple of percent all the time, and a
    /// controller that chases it oscillates forever.
    #[test]
    fn five_percent_loss_holds() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let emitted = drive(&mut bwe, t0, 10, |_| lossy(5));
        assert!(emitted.is_empty(), "5% loss must hold, got {emitted:?}");
        assert_eq!(bwe.target_bps, CEILING);
        // The boundaries themselves: LOW_LOSS_256 is still "clean", HIGH_LOSS_256 still "hold".
        assert!(LOW_LOSS_256 < HIGH_LOSS_256);
        let mut b2 = LossBasedBwe::new(CEILING);
        let t = Instant::now();
        assert_eq!(b2.on_feedback(clean(), t, inputs(100_000)), None);
        assert_eq!(
            b2.on_feedback(
                Feedback::Rr { fraction_lost_256: HIGH_LOSS_256, rtt: None },
                t + Duration::from_millis(1000),
                inputs(600_000)
            ),
            None,
            "exactly HIGH_LOSS_256 is still inside the dead band"
        );
    }

    /// Recovery climbs ~8 % per report and stops cleanly at the ceiling — it must not overshoot and
    /// then be clamped back, which would emit a spurious command every second forever.
    #[test]
    fn recovery_increases_and_stops_at_the_ceiling() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        // Crash it to the floor with sustained heavy loss.
        let mut bytes = 100_000u64;
        for i in 1..40u64 {
            bytes += 500_000;
            let _ = bwe.on_feedback(lossy(50), t0 + Duration::from_millis(1000 * i), inputs(bytes));
        }
        assert_eq!(bwe.target_bps, FLOOR_BPS, "sustained 50% loss reaches the floor");

        // Now recover.
        let mut prev = bwe.target_bps;
        let mut steps = 0;
        for i in 40..200u64 {
            bytes += 500_000;
            if let Some(v) =
                bwe.on_feedback(clean(), t0 + Duration::from_millis(1000 * i), inputs(bytes))
            {
                assert!(v > prev, "recovery must be monotone: {v} after {prev}");
                assert!(v <= CEILING, "must never exceed the operator's ceiling");
                prev = v;
                steps += 1;
            }
            if prev == CEILING {
                break;
            }
        }
        assert_eq!(prev, CEILING, "recovery reached the ceiling in {steps} steps");
        // At the ceiling it goes quiet again — no per-second no-op commands.
        let quiet = drive(&mut bwe, t0 + Duration::from_secs(300), 10, |_| clean());
        assert!(quiet.is_empty(), "at the ceiling, a clean link is silent again: {quiet:?}");
    }

    /// **The sliding-minimum property, stated so that it can only be satisfied one way.**
    ///
    /// Two clean reports arriving inside one [`BWE_INCREASE_INTERVAL`] must produce ONE increase
    /// worth of recovery, not two compounded. Increasing from the sliding minimum gives both
    /// reports the same base, so the second is a no-op; increasing from the current value compounds
    /// (+8 % then +8 % again), which is how a target ratchets up to a rate the link never sustained.
    ///
    /// The obvious formulation — "alternate loss and clean, assert it does not trend upward" —
    /// **cannot distinguish the mutation**, and I wrote it that way first: 1.08 × 0.80 < 1, so both
    /// the correct code and the mutant trend downward and the assertion passes either way. The
    /// distinguishing property is specifically about two increases sharing a window.
    #[test]
    fn two_increases_in_one_window_do_not_compound() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        // Drop once, so there is headroom to recover into.
        let dropped = bwe
            .on_feedback(lossy(40), t0 + Duration::from_millis(1000), inputs(700_000))
            .expect("a decrease");

        // Two clean reports, 400 ms apart — both inside the 1 s increase window.
        let first = bwe.on_feedback(clean(), t0 + Duration::from_millis(1400), inputs(1_400_000));
        let second = bwe.on_feedback(clean(), t0 + Duration::from_millis(1800), inputs(2_100_000));

        let expected_once = (dropped as u64 * INCREASE_PCT as u64 / 100) as u32 + INCREASE_ADDITIVE_BPS;
        assert_eq!(
            bwe.target_bps, expected_once,
            "two reports in one window must recover ONE step ({expected_once}), not compound"
        );
        assert!(first.is_some() || second.is_some(), "recovery did start");
        // Compounding would have reached ~1.166x instead of 1.08x.
        let compounded = (dropped as u64 * 108 * 108 / 10_000) as u32;
        assert!(
            bwe.target_bps < compounded,
            "target {} reached the compounded value {compounded}",
            bwe.target_bps
        );
    }

    /// The sliding minimum must be pruned **before** it is read, not only when it is written.
    ///
    /// Found by review. `update_min_history` runs at the END of a decision, so reading the front at
    /// the start of the next one saw a sample that may already have expired — recovery was anchored
    /// to a rate from further back than one second, and by an amount that depended on report
    /// timing. The property is in the name: "the minimum of the last second", as of *now*.
    /// The sliding minimum must be pruned **before** it is read, not only when it is written.
    ///
    /// The obvious formulation of this test does not work, and I wrote it that way first: drop
    /// once, wait a second, then send a clean report. There the queue's only entry IS the current
    /// target, so pruning it changes nothing and the mutation survives. The stale entry has to be
    /// *lower than the current target* for its expiry to be observable — which needs an increase in
    /// between, inside the same window.
    ///
    /// Sequence: decrease to D; two clean reports inside the window (which both increase from D,
    /// not compounding — that is the sliding-minimum property) leaving the queue as
    /// `[(t=100, D), (t=300, 1.08 D)]`; then a clean report just past t=1100, by which time the
    /// `D` sample has expired. Pruned, the base is 1.08 D and the target reaches ~1.166 D. Unpruned,
    /// the base is the stale D and the target stays at 1.08 D — recovery anchored a full second in
    /// the past.
    #[test]
    fn the_increase_base_is_the_minimum_of_the_last_second_as_of_now() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);

        let d = bwe
            .on_feedback(lossy(50), at(100), inputs(700_000))
            .expect("a decrease");

        // Two increases inside the window: both anchored on `d`, so the target lands at 1.08 d and
        // the queue keeps the older, lower `d` at its front.
        bwe.on_feedback(clean(), at(200), inputs(1_400_000));
        bwe.on_feedback(clean(), at(300), inputs(2_100_000));
        let after_window_increases = bwe.target_bps;
        let once = (d as u64 * INCREASE_PCT as u64 / 100) as u32 + INCREASE_ADDITIVE_BPS;
        assert_eq!(after_window_increases, once, "two in-window increases do not compound");
        assert_eq!(
            bwe.min_history.front().expect("history").1,
            d,
            "the older, lower sample is still the minimum while it is inside the window"
        );

        // Past t=100 + BWE_INCREASE_INTERVAL: the `d` sample has expired.
        bwe.on_feedback(clean(), at(1101), inputs(2_800_000));

        let from_pruned =
            (after_window_increases as u64 * INCREASE_PCT as u64 / 100) as u32 + INCREASE_ADDITIVE_BPS;
        assert_eq!(
            bwe.target_bps, from_pruned,
            "recovery must anchor on the minimum of the LAST SECOND, not on a sample that expired \
             (unpruned it would still read {d} and stay at {once})"
        );
        assert_ne!(from_pruned, once, "the two outcomes must actually differ, or this proves nothing");
        assert!(
            bwe.min_history
                .iter()
                .all(|&(t, _)| at(1101).saturating_duration_since(t) <= BWE_INCREASE_INTERVAL),
            "an expired sample survived in the sliding window"
        );
    }

    /// The companion property, over many cycles: an oscillating link must not trend upward.
    /// Weaker than the test above (it cannot catch the compounding mutation on its own), but it is
    /// the end-to-end statement of what the sliding minimum is for.
    #[test]
    fn oscillating_loss_does_not_trend_upward() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let mut bytes = 100_000u64;
        let mut first_peak = None;
        let mut last_peak = 0u32;
        for i in 1..60u64 {
            bytes += 500_000;
            let fb = if i % 2 == 1 { lossy(40) } else { clean() };
            let _ = bwe.on_feedback(fb, t0 + Duration::from_millis(1000 * i), inputs(bytes));
            if i % 2 == 0 {
                // A local maximum: just after a clean (increasing) report.
                if first_peak.is_none() {
                    first_peak = Some(bwe.target_bps);
                }
                last_peak = bwe.target_bps;
            }
        }
        let first = first_peak.expect("at least one recovery peak");
        assert!(
            last_peak <= first,
            "peaks trended UP across the oscillation: {first} -> {last_peak}"
        );
        assert!(bwe.target_bps < CEILING, "and it stayed below the ceiling");
    }

    /// The floor is absolute, and a ceiling BELOW the floor is still honoured — an operator who
    /// sets 100 kbps gets 100 kbps, not a controller that insists on 250.
    #[test]
    fn never_below_the_floor_and_a_low_ceiling_is_honoured() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let mut bytes = 100_000u64;
        for i in 1..100u64 {
            bytes += 500_000;
            let _ = bwe.on_feedback(lossy(60), t0 + Duration::from_millis(1000 * i), inputs(bytes));
            assert!(bwe.target_bps >= FLOOR_BPS, "fell below the floor at report {i}");
        }
        assert_eq!(bwe.target_bps, FLOOR_BPS);

        // A ceiling under the floor.
        let low = 100_000u32;
        let mut b2 = LossBasedBwe::new(low);
        let t = Instant::now();
        let lo_inputs = |bytes: u64| RateInputs {
            ceiling_bps: low,
            adaptive: true,
            encoded_bytes: bytes,
            measured_bps: low,
        };
        assert_eq!(b2.on_feedback(clean(), t, lo_inputs(100_000)), None);
        for i in 1..20u64 {
            let _ = b2.on_feedback(
                lossy(60),
                t + Duration::from_millis(1000 * i),
                lo_inputs(100_000 + 500_000 * i),
            );
        }
        assert_eq!(b2.target_bps, low, "a ceiling below FLOOR_BPS is the effective floor");
    }

    /// A long silence makes the estimate stale; the next report re-establishes the baseline rather
    /// than being acted on as if it described the intervening minute.
    #[test]
    fn no_feedback_for_six_seconds_freezes_then_resumes() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let after_gap = t0 + LOSS_REPORT_VALIDITY + Duration::from_millis(1);
        assert_eq!(
            bwe.on_feedback(lossy(50), after_gap, inputs(600_000)),
            None,
            "the first report after a long gap only re-establishes the baseline"
        );
        assert_eq!(bwe.target_bps, CEILING, "and it did not act on it");
        // The next one, promptly after, is acted on normally.
        let got = bwe.on_feedback(lossy(50), after_gap + Duration::from_millis(1000), inputs(1_200_000));
        assert!(got.is_some(), "feedback resumed");
    }

    /// Lowering the ceiling binds at once; raising it must not teleport onto a bad link.
    #[test]
    fn lowering_the_ceiling_binds_but_raising_does_not_teleport() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        let mut bytes = 100_000u64;
        for i in 1..12u64 {
            bytes += 500_000;
            let _ = bwe.on_feedback(lossy(40), t0 + Duration::from_millis(1000 * i), inputs(bytes));
        }
        let degraded = bwe.target_bps;
        assert!(degraded < CEILING);

        // Raise the ceiling: the target must stay where the link put it.
        let after_raise = bwe.on_ceiling_changed(20_000_000, true);
        assert_eq!(after_raise, degraded, "raising the ceiling must not re-flood a bad link");

        // Lower it below the current target: that binds immediately.
        let after_lower = bwe.on_ceiling_changed(300_000, true);
        assert_eq!(after_lower, 300_000, "a lower ceiling binds at once");
    }

    /// `adaptive: false` is a HARD off in both directions.
    #[test]
    fn adaptive_false_pins_the_target_at_the_ceiling() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        let pinned = |bytes: u64| RateInputs {
            ceiling_bps: CEILING,
            adaptive: false,
            encoded_bytes: bytes,
            measured_bps: CEILING,
        };
        // Heavy sustained loss changes nothing.
        let mut bytes = 0u64;
        for i in 0..30u64 {
            bytes += 500_000;
            let _ = bwe.on_feedback(lossy(60), t0 + Duration::from_millis(1000 * i), pinned(bytes));
            assert_eq!(bwe.target_bps, CEILING, "pinned at report {i}");
        }
        // And a controller that had already backed off snaps back UP when adaptation is turned off.
        let mut b2 = LossBasedBwe::new(CEILING);
        let t = Instant::now();
        assert_eq!(b2.on_feedback(clean(), t, inputs(100_000)), None);
        for i in 1..12u64 {
            let _ = b2.on_feedback(lossy(40), t + Duration::from_millis(1000 * i), inputs(500_000 * i));
        }
        assert!(b2.target_bps < CEILING);
        let restored = b2
            .on_feedback(lossy(40), t + Duration::from_secs(20), pinned(20_000_000))
            .expect("turning adaptation off must restore the ceiling");
        assert_eq!(restored, CEILING);
    }

    /// The REMB saturation gate, both ways. This is divergence 3, and it is the difference between
    /// a viewer that can burst on a scroll and one pinned at its own idle rate forever.
    #[test]
    fn remb_is_ignored_when_content_limited_and_caps_when_saturating() {
        let t0 = Instant::now();

        // Content-limited: the encoder is spending 30% of its target, so a low REMB is describing
        // our idleness, not the link.
        let mut idle = LossBasedBwe::new(CEILING);
        let got = idle.on_feedback(
            Feedback::Remb { bps: 800_000 },
            t0,
            RateInputs {
                ceiling_bps: CEILING,
                adaptive: true,
                encoded_bytes: 500_000,
                measured_bps: CEILING * 30 / 100,
            },
        );
        assert_eq!(got, None, "a content-limited encoder must ignore REMB");
        assert_eq!(idle.target_bps, CEILING);

        // Saturating: the target genuinely binds, so REMB is describing the link.
        let mut busy = LossBasedBwe::new(CEILING);
        let got = busy
            .on_feedback(
                Feedback::Remb { bps: 800_000 },
                t0,
                RateInputs {
                    ceiling_bps: CEILING,
                    adaptive: true,
                    encoded_bytes: 500_000,
                    measured_bps: CEILING * 95 / 100,
                },
            )
            .expect("a saturating encoder must honour REMB");
        assert_eq!(got, 800_000);
        // A REMB never RAISES the target above what loss control decided.
        let after = busy.on_feedback(
            Feedback::Remb { bps: 10_000_000 },
            t0 + Duration::from_millis(1000),
            RateInputs {
                ceiling_bps: CEILING,
                adaptive: true,
                encoded_bytes: 5_000_000,
                measured_bps: 790_000,
            },
        );
        assert_eq!(after, None, "REMB is a cap, never a licence to increase");
        assert_eq!(busy.target_bps, 800_000);
    }

    /// Without a sample-size guard, a flood of reports about one already-answered event keeps
    /// cutting the rate.
    ///
    /// **This test previously passed for the wrong reason and the mutation run caught it.** The
    /// second report was 8 seconds after the first, which trips `LOSS_REPORT_VALIDITY` (6 s) — so
    /// the staleness path returned `None` and the assertion held even with the byte guard deleted.
    /// A second mechanism satisfying the assertion is exactly the failure mode to watch for, so the
    /// timings below are chosen to leave the byte guard as the ONLY thing that can hold the report:
    /// inside the validity window, and past the decrease interval.
    #[test]
    fn fewer_than_the_minimum_bytes_between_decisions_holds() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(1_000_000)), None);
        let first = bwe
            .on_feedback(lossy(40), t0 + Duration::from_millis(1000), inputs(2_000_000))
            .expect("first decrease");

        // t+2000: 1 s after the last report (well inside LOSS_REPORT_VALIDITY) and 1 s after the
        // last decrease (well past BWE_DECREASE_INTERVAL + rtt). Neither of those can hold it.
        let at = t0 + Duration::from_millis(2000);
        let second = bwe.on_feedback(
            lossy(40),
            at,
            inputs(2_000_000 + MIN_BYTES_BETWEEN_DECISIONS - 1),
        );
        assert_eq!(
            second, None,
            "not enough new video to justify another decision — and nothing ELSE was in a position \
             to hold it"
        );
        assert_eq!(bwe.target_bps, first);

        // The control that proves the above was really the byte guard: one more byte and the same
        // report at the same instant DOES decide.
        let mut bwe2 = LossBasedBwe::new(CEILING);
        assert_eq!(bwe2.on_feedback(clean(), t0, inputs(1_000_000)), None);
        let first2 = bwe2
            .on_feedback(lossy(40), t0 + Duration::from_millis(1000), inputs(2_000_000))
            .expect("first decrease");
        let third = bwe2.on_feedback(
            lossy(40),
            at,
            inputs(2_000_000 + MIN_BYTES_BETWEEN_DECISIONS),
        );
        assert!(
            third.is_some() && bwe2.target_bps < first2,
            "with the byte threshold met, the identical report must decide"
        );
    }

    /// Hysteresis: a change smaller than 5 % is not worth an encoder reconfiguration.
    #[test]
    fn a_sub_five_percent_change_is_not_emitted() {
        let mut bwe = LossBasedBwe::new(CEILING);
        let t0 = Instant::now();
        assert_eq!(bwe.on_feedback(clean(), t0, inputs(100_000)), None);
        // ~3% loss is in the dead band; use a tiny decrease instead by driving loss just over the
        // high threshold, which yields x(1 - 27/512) ~= -5.3%... so instead assert the mechanism
        // directly on `emit`.
        let before = bwe.emitted_bps;
        assert_eq!(bwe.emit(before), None, "an identical value is never emitted");
        let tiny = before - before / 100; // -1%
        assert_eq!(bwe.emit(tiny), None, "a 1% change is below the hysteresis");
        let big = before - before / 5; // -20%
        assert_eq!(bwe.emit(big), Some(big), "a 20% change is emitted");
    }

    /// **The shipped constants, driven through the real constructor.**
    ///
    /// Every other test in this file injects its own numbers. Exactly one must exercise the values
    /// that actually ship, through the real entry point — otherwise a zeroed or transposed shipped
    /// constant passes the whole suite (docs/07, "an untested shipped constant").
    #[test]
    fn the_shipped_defaults_hold_together() {
        let ceiling = rmt_agent_core::quality::DEFAULT_MAX_BITRATE_BPS;
        assert!(FLOOR_BPS < ceiling, "the floor must be below the shipped ceiling");
        assert!(ceiling <= crate::video::MAX_BITRATE_BPS);
        assert!(LOW_LOSS_256 < HIGH_LOSS_256, "the dead band must be non-empty");
        assert!(INCREASE_PCT > 100, "the increase must actually increase");
        assert!(APPLY_HYSTERESIS_PCT > 0, "zero hysteresis is one FFI call per report");
        assert!(BWE_DECREASE_INTERVAL < LOSS_REPORT_VALIDITY);

        // And a clean link at the shipped default is a no-op — the same fail-safe, but reached
        // through the constants a real session uses rather than this file's CEILING.
        let mut bwe = LossBasedBwe::new(ceiling);
        let t0 = Instant::now();
        let mut bytes = 0u64;
        for i in 0..20u64 {
            bytes += 400_000;
            let got = bwe.on_feedback(
                clean(),
                t0 + Duration::from_millis(1000 * i),
                RateInputs {
                    ceiling_bps: ceiling,
                    adaptive: true,
                    encoded_bytes: bytes,
                    measured_bps: ceiling,
                },
            );
            assert_eq!(got, None, "the shipped defaults must not touch a clean link (report {i})");
        }
        assert_eq!(bwe.target_bps, ceiling);
    }
}
