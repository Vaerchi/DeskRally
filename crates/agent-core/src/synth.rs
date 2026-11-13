//! A synthetic [`ScreenCapturer`] that generates deterministic test frames without any real
//! display. Used for end-to-end bring-up and integration tests: it lets the whole pipeline
//! (capture → seal → mux → transport → relay → open → decode) run and be verified on a machine
//! with no GPU/session, which is exactly the environment where the real DXGI capturer can't.
//!
//! Each frame is a small BGRA image whose bytes encode the frame number **and the monitor id**, so
//! a receiver can assert it got frame N of monitor M intact. Every `keyframe_interval`-th frame is
//! marked a keyframe.
//!
//! # Multi-monitor (M10)
//!
//! Constructed with [`SyntheticCapturer::new`] it emits one virtual monitor (id 0), as before.
//! [`SyntheticCapturer::with_monitors`] gives it several, each a distinct size, so a test can prove
//! the capture thread switched monitors: the returned [`CapturedFrame`]'s `monitor_id`/dimensions
//! differ per monitor, and — when a [`CaptureObserver`] is attached via
//! [`SyntheticCapturer::observing`] — the capturer publishes the last-captured monitor id and a
//! running frame count that a test can watch from another thread without introspecting RTP.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use crate::platform::{CapturedFrame, MonitorInfo, PlatformError, PlatformResult, ScreenCapturer};

/// A test-observable window into what a [`SyntheticCapturer`] is doing, shared across threads.
///
/// The capturer lives on the (blocking) capture thread inside `serve_session`, out of a test's
/// reach; attaching one of these (see [`SyntheticCapturer::observing`]) lets the test — which keeps
/// a clone of the `Arc` — watch the capture thread deterministically: `last_monitor` proves *which*
/// monitor is being streamed, `frames` proves the stream is still *flowing* (the count keeps rising).
#[derive(Debug, Default)]
pub struct CaptureObserver {
    /// The `monitor_id` of the most recently captured frame (or
    /// [`crate::platform::COMPOSITE_MONITOR_ID`] after a view-all composite capture).
    pub last_monitor: AtomicU32,
    /// The pixel width of the most recently captured/produced frame. For a view-all composite this
    /// is the *summed* width of all monitors — which lets a test tell a real stitched composite apart
    /// from a silent primary-only fallback (both of which otherwise only bump `frames`).
    pub last_width: AtomicU32,
    /// Total frames captured so far (monotonically increasing while streaming).
    pub frames: AtomicU64,
}

/// Generates deterministic frames for one or more virtual monitors.
pub struct SyntheticCapturer {
    /// The virtual monitors this capturer reports and can capture (at least one).
    monitors: Vec<MonitorInfo>,
    frame_no: u64,
    keyframe_interval: u64,
    /// Optional test-observability handle updated on every capture (see [`CaptureObserver`]).
    observer: Option<Arc<CaptureObserver>>,
    /// Paint demanding block content instead of the smooth gradient — see [`SyntheticCapturer::with_noise`].
    noisy: bool,
}

impl SyntheticCapturer {
    /// A virtual capturer with a single monitor (id 0) of the given size. `keyframe_interval` of 0
    /// makes every frame a keyframe. Unchanged from the original single-monitor API.
    pub fn new(width: u32, height: u32, keyframe_interval: u64) -> Self {
        Self {
            monitors: vec![MonitorInfo { id: 0, width, height, dpi_scale: 1.0, left: 0, top: 0 }],
            frame_no: 0,
            keyframe_interval,
            observer: None,
            noisy: false,
        }
    }

    /// A virtual capturer with one monitor per `(width, height)` in `dims`, assigned ids `0..N`
    /// and **laid out edge to edge from left to right**, monitor 0 at the virtual-desktop origin.
    /// Each monitor's distinct size makes the captured frame distinguishable per monitor, so a test
    /// can prove which monitor the capture thread is streaming. `dims` must be non-empty; an empty
    /// slice degrades to a single 64×64 monitor rather than an unusable zero-monitor capturer.
    ///
    /// The layout is not decoration. Monitors used to be reported all at `(0, 0)`, which is not a
    /// desktop that can exist — the origin *is* the primary's top-left, so at most one monitor sits
    /// there. Anything deriving a fact from position (which monitor is primary, where a pointer
    /// lands after the multi-monitor input remap) reads nonsense from an overlapping fixture, and
    /// reads it consistently enough to look like agreement.
    pub fn with_monitors(dims: &[(u32, u32)], keyframe_interval: u64) -> Self {
        let monitors: Vec<MonitorInfo> = if dims.is_empty() {
            vec![MonitorInfo { id: 0, width: 64, height: 64, dpi_scale: 1.0, left: 0, top: 0 }]
        } else {
            let mut left = 0i32;
            dims.iter()
                .enumerate()
                .map(|(i, &(width, height))| {
                    let m = MonitorInfo {
                        id: i as u32,
                        width,
                        height,
                        dpi_scale: 1.0,
                        left,
                        top: 0,
                    };
                    left += width as i32;
                    m
                })
                .collect()
        };
        Self { monitors, frame_no: 0, keyframe_interval, observer: None, noisy: false }
    }

    /// Attach a [`CaptureObserver`] the capturer updates on every capture. Builder-style so a test
    /// can construct + observe in one expression. Returns `self` for chaining.
    pub fn observing(mut self, observer: Arc<CaptureObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Render **compressible-but-demanding** content instead of the default gradient (M11).
    ///
    /// The default [`render`](Self::render) is a smooth per-byte ramp offset by the frame number.
    /// VP8 codes that for almost nothing — so **any test that asserts an encoder respected a
    /// bitrate ceiling against the default capturer is vacuous**: the encoder is content-limited
    /// long before the target binds, and the assertion passes whatever the target is.
    ///
    /// This mode paints a grid of flat, pseudo-randomly coloured blocks over a **static
    /// background**, re-randomising only a minority of blocks per frame — which is what a real
    /// desktop looks like (mostly still, with a window or a caret changing) and, measured, is what
    /// keeps the encoder genuinely rate-controlled across the whole 300 kbps..3 Mbps range these
    /// tests span.
    ///
    /// Both extremes fail, and both failures were measured rather than reasoned about:
    /// * the default gradient is so cheap the encoder never approaches any ceiling, so a ceiling
    ///   assertion passes whatever the ceiling is;
    /// * re-randomising *every* block every frame is the opposite trap — at 640×480 it pins libvpx
    ///   against `rc_max_quantizer` around 2.2 Mbps, so a test asserting it reached 400 kbps fails
    ///   against **correct** code.
    ///
    /// The 12-byte frame-number/monitor-id header is preserved, so every existing receiver-side
    /// assertion still works.
    ///
    /// Builder-style, like [`observing`](Self::observing).
    pub fn with_noise(mut self) -> Self {
        self.noisy = true;
        self
    }

    /// The current frame counter (number of frames produced so far).
    pub fn frames_produced(&self) -> u64 {
        self.frame_no
    }

    /// Deterministic BGRA pixels for a given frame. The first 8 bytes carry the frame number
    /// (big-endian) and the next 4 the monitor id, so a receiver can verify both integrity and
    /// which monitor produced it; the rest is a cheap gradient seeded by the frame number so
    /// successive frames differ (like a changing screen).
    fn render(width: u32, height: u32, frame_no: u64, monitor_id: u32) -> Vec<u8> {
        let px = (width as usize) * (height as usize) * 4;
        let mut bytes = vec![0u8; px.max(12)];
        bytes[..8].copy_from_slice(&frame_no.to_be_bytes());
        bytes[8..12].copy_from_slice(&monitor_id.to_be_bytes());
        let seed = frame_no as u8;
        for (i, b) in bytes.iter_mut().enumerate().skip(12) {
            *b = (i as u8).wrapping_add(seed);
        }
        bytes
    }

    /// [`render`](Self::render)'s noisy counterpart — see [`with_noise`](Self::with_noise).
    fn render_noisy(width: u32, height: u32, frame_no: u64, monitor_id: u32) -> Vec<u8> {
        /// Flat block size in pixels. Larger than a VP8 macroblock (16), so a changed block is
        /// several macroblocks of real work rather than a single one the encoder can hide.
        const BLOCK: usize = 16;
        /// One block in this many is re-randomised per frame; the rest hold their static colour.
        /// A mostly-static frame is what lets the encoder actually reach a low target — an
        /// all-change frame cannot, at any quantizer.
        const CHANGE_ONE_IN: u32 = 8;

        let (w, h) = (width as usize, height as usize);
        let px = w * h * 4;
        let mut bytes = vec![0u8; px.max(12)];
        let hash = |mut s: u32| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for y in 0..h {
            let by = (y / BLOCK) as u32;
            for x in 0..w {
                let bx = (x / BLOCK) as u32;
                // A block's identity — fixed for the life of the stream.
                let ident = hash(bx.wrapping_mul(0x9E37_79B9) ^ by.wrapping_mul(0x85EB_CA6B));
                // Which frames touch this block: a per-block phase spreads the churn out, so every
                // frame changes roughly 1/CHANGE_ONE_IN of the screen rather than all-or-nothing.
                let s = if (frame_no as u32).wrapping_add(ident) % CHANGE_ONE_IN == 0 {
                    hash(ident ^ (frame_no as u32).wrapping_mul(0xC2B2_AE35))
                } else {
                    ident
                };
                let i = (y * w + x) * 4;
                if i + 3 < bytes.len() {
                    bytes[i] = s as u8;
                    bytes[i + 1] = (s >> 8) as u8;
                    bytes[i + 2] = (s >> 16) as u8;
                    bytes[i + 3] = 0xFF;
                }
            }
        }
        // The header goes on LAST so it survives the fill — receivers identify frames by it.
        if bytes.len() >= 12 {
            bytes[..8].copy_from_slice(&frame_no.to_be_bytes());
            bytes[8..12].copy_from_slice(&monitor_id.to_be_bytes());
        }
        bytes
    }
}

impl ScreenCapturer for SyntheticCapturer {
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        Ok(self.monitors.clone())
    }

    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
        let mon = self
            .monitors
            .iter()
            .find(|m| m.id == monitor_id)
            .copied()
            .ok_or(PlatformError::UnknownMonitor(monitor_id))?;
        let n = self.frame_no;
        self.frame_no += 1;
        if let Some(obs) = &self.observer {
            obs.last_monitor.store(monitor_id, Ordering::Relaxed);
            obs.last_width.store(mon.width, Ordering::Relaxed);
            obs.frames.fetch_add(1, Ordering::Relaxed);
        }
        let is_keyframe = self.keyframe_interval == 0 || n % self.keyframe_interval == 0;
        let bytes = if self.noisy {
            Self::render_noisy(mon.width, mon.height, n, monitor_id)
        } else {
            Self::render(mon.width, mon.height, n, monitor_id)
        };
        Ok(CapturedFrame {
            monitor_id,
            width: mon.width,
            height: mon.height,
            bytes,
            is_keyframe,
        })
    }

    /// Override the default [`ScreenCapturer::capture_composite`] to ALSO publish the composite's
    /// identity to the observer. The composition itself is identical to the default (enumerate →
    /// capture each → [`crate::platform::composite_frames`]); the extra bookkeeping lets a test tell
    /// a real view-all composite apart from a silent primary-only fallback (both otherwise only bump
    /// `frames`), by exposing the stitched `last_width` (Σ monitor widths).
    fn capture_composite(&mut self) -> PlatformResult<CapturedFrame> {
        let mons = self.monitors()?;
        let mut frames = Vec::with_capacity(mons.len());
        for m in &mons {
            frames.push(self.capture_frame(m.id)?);
        }
        let composite = crate::platform::composite_frames(&frames);
        if let Some(obs) = &self.observer {
            obs.last_monitor
                .store(crate::platform::COMPOSITE_MONITOR_ID, Ordering::Relaxed);
            obs.last_width.store(composite.width, Ordering::Relaxed);
        }
        Ok(composite)
    }
}

/// Read back the frame number a [`SyntheticCapturer`] encoded into a captured frame's bytes.
/// Lets a receiver verify it decrypted the exact frame that was captured.
///
/// Works in both render modes: [`SyntheticCapturer::with_noise`] writes its header last, precisely
/// so this keeps working.
pub fn frame_number(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(bytes[..8].try_into().unwrap()))
}

/// Read back the monitor id a [`SyntheticCapturer`] encoded into a captured frame's bytes (the 4
/// bytes after the frame number). Lets a test prove *which* monitor a frame came from.
pub fn monitor_number(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 12 {
        return None;
    }
    Some(u32::from_be_bytes(bytes[8..12].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_numbered_and_recoverable() {
        let mut cap = SyntheticCapturer::new(16, 16, 4);
        let f0 = cap.capture_frame(0).unwrap();
        let f1 = cap.capture_frame(0).unwrap();
        assert_eq!(frame_number(&f0.bytes), Some(0));
        assert_eq!(frame_number(&f1.bytes), Some(1));
        assert_eq!(monitor_number(&f0.bytes), Some(0));
        assert!(f0.is_keyframe); // frame 0 with interval 4
        assert!(!f1.is_keyframe);
        assert_ne!(f0.bytes, f1.bytes, "successive frames differ");
    }

    #[test]
    fn unknown_monitor_errors() {
        let mut cap = SyntheticCapturer::new(8, 8, 0);
        assert!(matches!(cap.capture_frame(9), Err(PlatformError::UnknownMonitor(9))));
    }

    /// `with_noise` must keep every receiver-side contract the default mode offers, and must
    /// genuinely produce harder content — the whole reason it exists is that the default gradient
    /// makes a bitrate-ceiling assertion vacuous, so a noisy mode that merely *looked* different
    /// would be no better.
    #[test]
    fn noisy_mode_keeps_the_header_and_is_harder_to_compress() {
        let mut plain = SyntheticCapturer::new(64, 64, 4);
        let mut noisy = SyntheticCapturer::new(64, 64, 4).with_noise();
        let p0 = plain.capture_frame(0).unwrap();
        let n0 = noisy.capture_frame(0).unwrap();

        // The header survives: every existing receiver assertion keeps working.
        assert_eq!(frame_number(&n0.bytes), Some(0));
        assert_eq!(monitor_number(&n0.bytes), Some(0));
        assert_eq!((n0.width, n0.height), (p0.width, p0.height));
        assert_eq!(n0.bytes.len(), p0.bytes.len());
        assert!(n0.is_keyframe, "keyframe cadence is unchanged");

        // Successive frames differ (a static image would make every delta free).
        let n1 = noisy.capture_frame(0).unwrap();
        assert_eq!(frame_number(&n1.bytes), Some(1));
        assert_ne!(n0.bytes, n1.bytes, "successive noisy frames differ");

        // And it is genuinely harder: the default ramp is monotone byte-to-byte, so almost every
        // adjacent pair differs by exactly 1. Count how often that holds — it is a cheap, direct
        // proxy for "trivially predictable", and it is what makes the default content vacuous.
        let smoothness = |b: &[u8]| {
            b[12..].windows(2).filter(|w| w[1].wrapping_sub(w[0]) == 1).count() as f64
                / (b.len() - 13) as f64
        };
        let plain_smooth = smoothness(&p0.bytes);
        let noisy_smooth = smoothness(&n0.bytes);
        assert!(
            plain_smooth > 0.9,
            "the default render really is a smooth ramp ({plain_smooth:.2})"
        );
        assert!(
            noisy_smooth < 0.5,
            "noisy content must not be a ramp ({noisy_smooth:.2})"
        );
    }

    #[test]
    fn with_monitors_empty_dims_falls_back_to_single_monitor() {
        let cap = SyntheticCapturer::with_monitors(&[], 0);
        let mons = cap.monitors().unwrap();
        assert_eq!(mons.len(), 1);
        assert_eq!(mons[0].id, 0);
        assert_eq!(mons[0].width, 64);
        assert_eq!(mons[0].height, 64);
    }

    #[test]
    fn multi_monitor_enumerates_and_distinguishes() {
        let mut cap = SyntheticCapturer::with_monitors(&[(320, 240), (640, 480)], 0);
        let mons = cap.monitors().unwrap();
        assert_eq!(mons.len(), 2);
        assert_eq!((mons[0].id, mons[0].width, mons[0].height), (0, 320, 240));
        assert_eq!((mons[1].id, mons[1].width, mons[1].height), (1, 640, 480));
        // The fixture must describe a desktop that could EXIST: exactly one monitor at the origin
        // (that is what "primary" means), the rest laid out beside it without overlapping. A
        // fixture with every monitor at (0,0) silently breaks anything that reads position — which
        // is now how the Windows host decides which display is the primary.
        assert_eq!((mons[0].left, mons[0].top), (0, 0), "monitor 0 IS the origin");
        assert_eq!((mons[1].left, mons[1].top), (320, 0), "monitor 1 starts where monitor 0 ends");
        assert_eq!(
            mons.iter().filter(|m| m.left == 0 && m.top == 0).count(),
            1,
            "exactly one monitor sits at the virtual-desktop origin"
        );

        // Each monitor's frame is self-identifying (dimensions + encoded id differ).
        let f0 = cap.capture_frame(0).unwrap();
        let f1 = cap.capture_frame(1).unwrap();
        assert_eq!((f0.monitor_id, f0.width, f0.height), (0, 320, 240));
        assert_eq!((f1.monitor_id, f1.width, f1.height), (1, 640, 480));
        assert_eq!(monitor_number(&f0.bytes), Some(0));
        assert_eq!(monitor_number(&f1.bytes), Some(1));

        // An id outside the set is still an error (the capture thread falls back to primary).
        assert!(matches!(cap.capture_frame(5), Err(PlatformError::UnknownMonitor(5))));
    }

    #[test]
    fn capture_composite_stitches_all_monitors() {
        use crate::platform::COMPOSITE_MONITOR_ID;
        // 4x4 primary + 2x2 secondary → composite 6x4 (widths summed, max height), via the default
        // `capture_composite` trait method composing per-monitor `capture_frame` results.
        let mut cap = SyntheticCapturer::with_monitors(&[(4, 4), (2, 2)], 0);
        let comp = cap.capture_composite().unwrap();
        assert_eq!(comp.monitor_id, COMPOSITE_MONITOR_ID);
        assert_eq!((comp.width, comp.height), (6, 4));
        assert_eq!(comp.bytes.len(), 6 * 4 * 4);
        assert!(comp.bytes.iter().any(|&b| b != 0), "composite should carry the monitors' pixels");
    }

    #[test]
    fn observer_tracks_last_monitor_and_frame_count() {
        let obs = Arc::new(CaptureObserver::default());
        let mut cap =
            SyntheticCapturer::with_monitors(&[(320, 240), (640, 480)], 0).observing(obs.clone());
        cap.capture_frame(0).unwrap();
        assert_eq!(obs.last_monitor.load(Ordering::Relaxed), 0);
        assert_eq!(obs.frames.load(Ordering::Relaxed), 1);
        cap.capture_frame(1).unwrap();
        assert_eq!(obs.last_monitor.load(Ordering::Relaxed), 1);
        assert_eq!(obs.frames.load(Ordering::Relaxed), 2);
    }
}
