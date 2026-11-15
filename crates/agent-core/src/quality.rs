//! Session **quality settings** (M11): the operator-chosen resolution / framerate / colour /
//! bitrate ceiling that rides the [`crate::control`] channel, plus the one clamp every path funnels
//! through.
//!
//! This module holds only *data and pure logic* so both ends can share it: the Rust agent decodes a
//! [`crate::control::ControlMessage::SetQuality`] into a [`QualitySettings`], and the browser
//! controller (`web/viewer/src/lib/quality.ts` + `control.ts`) produces byte-identical frames.
//!
//! # Why every field is an integer or a unit enum
//!
//! [`crate::control::ControlMessage`] derives `Eq`, which floats would break — and the wire is
//! pinned by exact JSON string literals in tests on both sides, which floats would make
//! formatting-dependent. `scale_div` is an integer *divisor* rather than a percentage for the same
//! reason, plus a real one: every legal value is then an exact k×k box the scaler can average
//! without resampling artefacts.
//!
//! # Why [`QualitySettings`] is COMPLETE (no `Option`, no `skip_serializing_if`)
//!
//! An "absent means…" rule on a settings struct is exactly the shape that shipped an `Option`
//! whose `None` granted all 19 backstage capabilities (docs/07). A controller changing one knob
//! does read-modify-write against the last `QualityApplied` it received. There is no way to send a
//! partial update, so there is no default-when-absent to get wrong.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Pre-encode colour reduction.
///
/// VP8 is **always** 8-bit YUV 4:2:0, so this is not a codec bit depth: it is how much colour
/// entropy the encoder is handed. [`ColorMode::Gray`] forces U = V = 128, which makes both chroma
/// planes constant (VP8 codes them as skipped blocks for essentially nothing) and is the only tier
/// that saves bits *by construction* rather than content-dependently.
///
/// Serialized as a bare string (`"Full"` / `"Gray"`) — serde's default for a unit-only enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorMode {
    /// Full colour: the byte-identical code path this project shipped before M11.
    Full,
    /// Greyscale: luma untouched at full 8 bits, both chroma planes filled with 128.
    Gray,
}

impl Default for ColorMode {
    fn default() -> Self {
        Self::Full
    }
}

/// One **complete** quality request. See the module docs for why there are no optional fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualitySettings {
    /// Integer capture downscale divisor, [`MIN_SCALE_DIV`]..=[`MAX_SCALE_DIV`]
    /// (1 = 100 %, 2 = 50 %, 3 = 33 %, 4 = 25 %).
    pub scale_div: u32,
    /// Capture pacing target in frames/sec, [`MIN_FPS`]..=[`MAX_FPS`].
    pub fps: u32,
    /// Pre-encode colour reduction.
    pub color: ColorMode,
    /// The operator's bitrate **ceiling** in bits/sec,
    /// [`MIN_MAX_BITRATE_BPS`]..=[`MAX_MAX_BITRATE_BPS`]. The agent's adaptive controller may sit
    /// below it; it never exceeds it.
    pub max_bitrate_bps: u32,
    /// Whether the agent's loss-based controller may lower the encoder bitrate below the ceiling.
    /// `false` is a hard off — the encoder is pinned at `max_bitrate_bps`.
    pub adaptive: bool,
}

/// Smallest accepted [`QualitySettings::scale_div`].
pub const MIN_SCALE_DIV: u32 = 1;
/// Largest accepted [`QualitySettings::scale_div`]. 4 is where a 1080p desktop becomes 480×270 —
/// past legibility for the text a support session exists to read.
pub const MAX_SCALE_DIV: u32 = 4;
/// Smallest accepted [`QualitySettings::fps`]. Never 0: see [`QualitySettings::clamped`].
pub const MIN_FPS: u32 = 1;
/// Largest accepted [`QualitySettings::fps`].
pub const MAX_FPS: u32 = 60;
/// Smallest accepted [`QualitySettings::max_bitrate_bps`].
pub const MIN_MAX_BITRATE_BPS: u32 = 100_000;
/// Largest accepted [`QualitySettings::max_bitrate_bps`]. A technician is a semi-trusted peer; this
/// is the wire-level bound on how much of a customer's uplink one can be asked to consume.
pub const MAX_MAX_BITRATE_BPS: u32 = 20_000_000;

/// The shipped default bitrate ceiling — **must equal** `rmt_transport_webrtc::video::DEFAULT_BITRATE_BPS`.
///
/// `rmt-agent-core` cannot depend on `rmt-transport-webrtc` (that would cycle), so the cross-crate
/// equality is asserted from the *other* side, in `transport-webrtc`'s own test suite.
pub const DEFAULT_MAX_BITRATE_BPS: u32 = 3_000_000;

impl QualitySettings {
    /// **Exactly** the behaviour this project shipped before M11: full resolution, 30 fps, full
    /// colour, the 3 Mbps encoder default. `adaptive` is `true`, which is *not* a behaviour change:
    /// the controller starts at the ceiling and a link with no loss gives it nothing to do (see
    /// `rmt_transport_webrtc::video::rate`).
    pub const DEFAULT: Self = Self {
        scale_div: 1,
        fps: 30,
        color: ColorMode::Full,
        max_bitrate_bps: DEFAULT_MAX_BITRATE_BPS,
        adaptive: true,
    };

    /// Clamp every field into range — **never reject**.
    ///
    /// This is the one choke point, and it is called before any field is read. It is
    /// security-relevant rather than cosmetic, because each out-of-range value has a distinct way
    /// of taking the session down:
    ///
    /// * `fps: 0` → `Duration::from_secs(1) / 0` **panics** the capture thread;
    /// * `scale_div: 0` → divide-by-zero in the scaler;
    /// * `max_bitrate_bps: 0` → `Vp8Encoder::new` returns `Err` and the session has no video at all.
    ///
    /// Saturating (not modular) and idempotent, both pinned by tests.
    pub fn clamped(self) -> Self {
        Self {
            scale_div: self.scale_div.clamp(MIN_SCALE_DIV, MAX_SCALE_DIV),
            fps: self.fps.clamp(MIN_FPS, MAX_FPS),
            color: self.color,
            max_bitrate_bps: self
                .max_bitrate_bps
                .clamp(MIN_MAX_BITRATE_BPS, MAX_MAX_BITRATE_BPS),
            adaptive: self.adaptive,
        }
    }
}

impl Default for QualitySettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Capture pacing interval for a target frame rate.
///
/// The `.clamp` is a **second** belt against divide-by-zero: [`QualitySettings::clamped`] is the
/// first, but this helper is also called with a caller-supplied `target_fps` that never went
/// through the wire, and `Duration::from_secs(1) / 0` panics.
pub fn frame_interval(fps: u32) -> Duration {
    Duration::from_secs(1) / fps.clamp(MIN_FPS, MAX_FPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_default_is_todays_behaviour() {
        // Field by field, deliberately: this is the "an old controller sees no change" contract,
        // and a single struct-equality assertion against another constant would be circular.
        let d = QualitySettings::DEFAULT;
        assert_eq!(d.scale_div, 1, "full resolution");
        assert_eq!(d.fps, 30, "the fps every existing caller passes");
        assert_eq!(d.color, ColorMode::Full);
        assert_eq!(d.max_bitrate_bps, 3_000_000, "== video::DEFAULT_BITRATE_BPS");
        assert!(d.adaptive, "adaptive on, but a clean link gives it nothing to do");
        assert_eq!(QualitySettings::default(), d, "Default impl agrees with DEFAULT");
    }

    #[test]
    fn clamped_saturates_at_both_extremes() {
        let zeroed = QualitySettings {
            scale_div: 0,
            fps: 0,
            color: ColorMode::Gray,
            max_bitrate_bps: 0,
            adaptive: false,
        }
        .clamped();
        assert_eq!(zeroed.scale_div, MIN_SCALE_DIV);
        assert_eq!(zeroed.fps, MIN_FPS);
        assert_eq!(zeroed.max_bitrate_bps, MIN_MAX_BITRATE_BPS);
        // Non-numeric fields pass through untouched.
        assert_eq!(zeroed.color, ColorMode::Gray);
        assert!(!zeroed.adaptive);

        let maxed = QualitySettings {
            scale_div: u32::MAX,
            fps: u32::MAX,
            color: ColorMode::Full,
            max_bitrate_bps: u32::MAX,
            adaptive: true,
        }
        .clamped();
        assert_eq!(maxed.scale_div, MAX_SCALE_DIV);
        assert_eq!(maxed.fps, MAX_FPS);
        assert_eq!(maxed.max_bitrate_bps, MAX_MAX_BITRATE_BPS);
    }

    #[test]
    fn clamped_is_idempotent_and_leaves_legal_values_alone() {
        let legal = QualitySettings {
            scale_div: 2,
            fps: 15,
            color: ColorMode::Gray,
            max_bitrate_bps: 1_000_000,
            adaptive: true,
        };
        assert_eq!(legal.clamped(), legal, "a legal value is untouched");
        assert_eq!(legal.clamped().clamped(), legal.clamped(), "idempotent");
        let wild = QualitySettings {
            scale_div: 99,
            fps: 0,
            color: ColorMode::Full,
            max_bitrate_bps: 1,
            adaptive: false,
        };
        assert_eq!(wild.clamped().clamped(), wild.clamped(), "idempotent from out of range too");
    }

    #[test]
    fn frame_interval_never_zero_never_panics() {
        // `Duration::from_secs(1) / 0` panics, and 0 is exactly what a hostile or buggy controller
        // sends. Drive the boundary values through the real helper.
        for fps in [0u32, 1, 15, 30, 60, 61, u32::MAX] {
            let iv = frame_interval(fps);
            assert!(iv > Duration::ZERO, "fps={fps} produced a zero interval");
            assert!(iv <= Duration::from_secs(1), "fps={fps} produced {iv:?}");
        }
        // 1s / 30 divides exactly in nanoseconds; asserting the truncated microsecond value would
        // be asserting a different function.
        assert_eq!(frame_interval(30), Duration::from_nanos(33_333_333));
        assert_eq!(frame_interval(1), Duration::from_secs(1));
        assert_eq!(frame_interval(0), frame_interval(MIN_FPS), "0 clamps to MIN_FPS");
        assert_eq!(frame_interval(u32::MAX), frame_interval(MAX_FPS));
    }

    #[test]
    fn the_bounds_hold_together() {
        // A shipped-constant sanity net: the default must be inside the range the clamp enforces,
        // or `DEFAULT.clamped() != DEFAULT` and every "no change by default" claim is false.
        assert_eq!(
            QualitySettings::DEFAULT.clamped(),
            QualitySettings::DEFAULT,
            "the shipped default must survive its own clamp"
        );
        assert!(MIN_MAX_BITRATE_BPS < DEFAULT_MAX_BITRATE_BPS);
        assert!(DEFAULT_MAX_BITRATE_BPS < MAX_MAX_BITRATE_BPS);
        assert!(MIN_SCALE_DIV < MAX_SCALE_DIV);
        assert!(MIN_FPS < MAX_FPS);
    }
}
