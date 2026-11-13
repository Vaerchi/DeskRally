//! Spend a canvas session's bitrate on the displays the viewer is watching.
//!
//! On a multi-display machine a canvas session streams the whole virtual desktop and the viewer crops
//! locally. With a `WatchedMonitors` hint from the viewer, the session paints every UNWATCHED display a
//! flat colour ([`BLANK_BGRA`]) and keeps updating only the watched ones. The frame keeps its size and
//! layout, so nothing about the crop or input mapping changes; a flat, unchanging region costs the
//! encoder almost nothing, so the bitrate goes to the watched display.
//!
//! Why blank and not "frozen at the last real pixels": when the operator switches to another display,
//! the viewer shows it before the agent has heard about the switch. Frozen pixels would show an OLD
//! picture the operator might click on; a blank shows nothing clickable for the ~one round trip until
//! the real picture arrives (Codex review rounds 1-2: proving freshness end to end needs frame identity).
//!
//! Off while recording (the recording must hold the whole desktop), and screenshots use the raw frame.
use std::time::{Duration, Instant};
use rmt_agent_core::{control::MonitorCanvas, platform::CapturedFrame};

/// Unwatched displays: the viewer's own background (#202329) as BGRA.
pub(crate) const BLANK_BGRA: [u8; 4] = [0x29, 0x23, 0x20, 0xFF];
/// A hint naming more displays than this is ignored (no real machine has this many).
const MAX_HINT_IDS: usize = 64;
/// At most one hint-driven full rebuild per this interval: a burst of hints cannot force a stream of
/// full-canvas (tens of MB) copies. Recording transitions are not throttled.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(150);

/// Copy the watched rectangles' pixels from `src` into `composed` (both packed BGRA, stride = width*4).
pub(crate) fn refresh_watched(composed: &mut [u8], src: &[u8], width: u32, height: u32,
    rects: &[(u32, u32, u32, u32)]) {
    let Some(stride) = (width as usize).checked_mul(4) else { return };
    let Some(len) = stride.checked_mul(height as usize) else { return };
    if composed.len() != len || src.len() != len { return; }
    for &(x, y, w, h) in rects {
        let right = x.saturating_add(w).min(width);
        let bottom = y.saturating_add(h).min(height);
        if x >= right || y >= bottom { continue; }
        for row in y..bottom {
            let start = row as usize * stride + x as usize * 4;
            let end = row as usize * stride + right as usize * 4;
            composed[start..end].copy_from_slice(&src[start..end]);
        }
    }
}

/// Drop unknown ids, sort, dedup; "every display" and "none" both mean "all" (None).
pub(crate) fn normalize(ids: Option<Vec<u32>>, canvas: Option<&MonitorCanvas>) -> Option<Vec<u32>> {
    let mut ids = ids?;
    if let Some(canvas) = canvas { ids.retain(|id| canvas.monitors.iter().any(|m| m.id == *id)); }
    ids.sort_unstable(); ids.dedup();
    if ids.is_empty() || canvas.is_some_and(|c| c.monitors.iter().all(|m| ids.contains(&m.id))) { None } else { Some(ids) }
}

/// Whether blanking applies to this frame at all.
pub(crate) fn active(ids: Option<&Vec<u32>>, canvas: Option<&MonitorCanvas>, frame: &CapturedFrame,
    recording: bool) -> bool {
    !recording && ids.is_some_and(|ids| !ids.is_empty()) && canvas.is_some_and(|c|
        frame.width == c.width && frame.height == c.height && frame.width > 0 && frame.height > 0 &&
        (frame.width as usize).checked_mul(frame.height as usize).and_then(|n| n.checked_mul(4)) == Some(frame.bytes.len()))
}

fn watched_rects(canvas: &MonitorCanvas, ids: &[u32]) -> Vec<(u32, u32, u32, u32)> {
    canvas.monitors.iter().filter(|m| ids.contains(&m.id)).map(|m| (m.x, m.y, m.width, m.height)).collect()
}

/// A full frame with only the watched displays' pixels; everything else is [`BLANK_BGRA`].
fn compose(f: &CapturedFrame, canvas: &MonitorCanvas, ids: &[u32]) -> CapturedFrame {
    let mut bytes = BLANK_BGRA.repeat(f.bytes.len() / 4);
    refresh_watched(&mut bytes, &f.bytes, f.width, f.height, &watched_rects(canvas, ids));
    CapturedFrame { monitor_id: f.monitor_id, width: f.width, height: f.height, bytes, is_keyframe: f.is_keyframe }
}

/// One session's state. host.rs feeds it every captured frame, the viewer's hint and the recording
/// state, and asks it what to hand the encoder.
#[derive(Default)]
pub(crate) struct FreezeState {
    /// The newest normalized hint.
    watched: Option<Vec<u32>>,
    /// The hint the current composition uses (lags `watched` while throttled).
    applied: Option<Vec<u32>>,
    composed: Option<CapturedFrame>,
    active: bool,
    dirty: bool,
    recording: bool,
    last_refresh: Option<Instant>,
}

impl FreezeState {
    /// Apply a hint. Returns whether the normalized set changed (only then is a rebuild needed).
    pub(crate) fn set_watched(&mut self, monitors: Option<Vec<u32>>, canvas: Option<&MonitorCanvas>) -> bool {
        if monitors.as_ref().is_some_and(|ids| ids.len() > MAX_HINT_IDS) {
            tracing::debug!("ignoring oversized watched monitors hint");
            return false;
        }
        let next = normalize(monitors, canvas);
        let changed = next != self.watched;
        self.watched = next;
        self.dirty |= changed;
        changed
    }

    pub(crate) fn watched(&self) -> Option<&Vec<u32>> {
        self.watched.as_ref()
    }

    /// Run before waiting for the next event, including on an idle desktop. Returns true when the
    /// caller must send [`Self::outgoing`] right now: the hint changed, or recording started/stopped.
    pub(crate) fn reconcile(&mut self, last: Option<&CapturedFrame>, canvas: Option<&MonitorCanvas>, recording: bool, now: Instant) -> bool {
        let transition = recording != self.recording;
        self.recording = recording;
        let active = last.is_some_and(|f| self::active(self.watched.as_ref(), canvas, f, recording));
        if !self.dirty && !transition && active == self.active {
            return false;
        }
        if self.dirty && !transition && last.is_some()
            && self.last_refresh.is_some_and(|t| now.saturating_duration_since(t) < MIN_REFRESH_INTERVAL) {
            return false; // retried on a later loop iteration (the cadence tick wakes the loop)
        }
        self.dirty = false;
        self.applied = self.watched.clone();
        if last.is_some() { self.last_refresh = Some(now); }
        self.active = active;
        self.composed = match (active, last, canvas, self.applied.as_ref()) {
            (true, Some(f), Some(c), Some(ids)) => Some(compose(f, c, ids)),
            _ => None,
        };
        last.is_some()
    }

    /// Recording is about to start: stop blanking now, so the encoder's retained frame is raw.
    /// Returns whether the caller must send the raw frame before installing the recording tee.
    pub(crate) fn suspend_for_recording(&mut self) -> bool {
        let needed = self.active || self.composed.is_some();
        self.composed = None;
        self.active = false;
        needed
    }

    /// A new captured frame: returns what to encode.
    pub(crate) fn on_frame<'a>(&'a mut self, f: &'a CapturedFrame, canvas: Option<&MonitorCanvas>, recording: bool) -> &'a CapturedFrame {
        let (Some(c), Some(ids)) = (canvas, self.applied.as_ref()) else {
            self.active = false;
            self.composed = None;
            return f;
        };
        if !self::active(Some(ids), Some(c), f, recording) {
            self.active = false;
            self.composed = None;
            return f;
        }
        let rebuild = !self.active || self.composed.as_ref().map_or(true, |x| x.width != f.width || x.height != f.height);
        if rebuild {
            self.composed = Some(compose(f, c, ids));
        } else if let Some(x) = self.composed.as_mut() {
            refresh_watched(&mut x.bytes, &f.bytes, f.width, f.height, &watched_rects(c, ids));
            x.is_keyframe = f.is_keyframe;
        }
        self.active = true;
        self.composed.as_ref().unwrap_or(f)
    }

    /// What to (re)send outside the frame arm: the composition while blanking, else the raw frame.
    pub(crate) fn outgoing<'a>(&'a self, last: Option<&'a CapturedFrame>) -> Option<&'a CapturedFrame> {
        self.composed.as_ref().or(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u8 = BLANK_BGRA[0];

    /// Two 2x1 displays side by side; each frame paints display 0 with `a` and display 1 with `b`.
    fn frame(a: u8, b: u8) -> CapturedFrame {
        let mut bytes = vec![a; 2 * 4];
        bytes.extend(vec![b; 2 * 4]);
        CapturedFrame { monitor_id: u32::MAX, width: 4, height: 1, bytes, is_keyframe: false }
    }
    fn two() -> MonitorCanvas {
        MonitorCanvas { width: 4, height: 1, monitors: (0..2).map(|id|
            rmt_agent_core::control::CanvasMonitor { id, x: id * 2, y: 0, width: 2, height: 1 }).collect() }
    }
    fn halves(f: &CapturedFrame) -> (u8, u8) { (f.bytes[0], f.bytes[8]) }
    fn later(s: u64) -> Instant { Instant::now() + Duration::from_secs(s) }

    #[test]
    fn an_unwatched_display_is_blank_never_an_old_picture() {
        let c = two();
        let mut s = FreezeState::default();
        // No hint yet: frames pass through untouched.
        assert_eq!(halves(s.on_frame(&frame(1, 1), Some(&c), false)), (1, 1));
        // Watch display 0: an immediate send in which display 1 is blank.
        assert!(s.set_watched(Some(vec![0]), Some(&c)));
        let last = frame(2, 2);
        assert!(s.reconcile(Some(&last), Some(&c), false, later(1)));
        assert_eq!(halves(s.outgoing(Some(&last)).unwrap()), (2, B));
        assert!(!s.reconcile(Some(&last), Some(&c), false, later(1)), "only once");
        // Display 1 changes but stays blank; display 0 follows.
        assert_eq!(halves(s.on_frame(&frame(3, 9), Some(&c), false)), (3, B));
        assert_eq!(halves(s.outgoing(Some(&frame(3, 9))).unwrap()), (3, B));
        // Switch to display 1: its REAL current pixels at once, display 0 blank. Never the old 2.
        assert!(s.set_watched(Some(vec![1]), Some(&c)));
        let last = frame(4, 8);
        assert!(s.reconcile(Some(&last), Some(&c), false, later(2)));
        assert_eq!(halves(s.outgoing(Some(&last)).unwrap()), (B, 8));
        assert_eq!(halves(s.on_frame(&frame(5, 7), Some(&c), false)), (B, 7));
    }

    #[test]
    fn recording_or_watching_everything_sends_raw_frames() {
        let c = two();
        let mut s = FreezeState::default();
        s.set_watched(Some(vec![0]), Some(&c));
        assert!(s.reconcile(Some(&frame(1, 1)), Some(&c), false, later(1)));
        assert_eq!(halves(s.on_frame(&frame(2, 9), Some(&c), false)), (2, B));
        // Recording starts: the caller sends raw first, then frames stay raw.
        assert!(s.suspend_for_recording());
        assert_eq!(halves(s.outgoing(Some(&frame(2, 9))).unwrap()), (2, 9));
        assert!(s.reconcile(Some(&frame(2, 9)), Some(&c), true, later(1)), "the transition resends");
        assert_eq!(halves(s.on_frame(&frame(3, 8), Some(&c), true)), (3, 8));
        // Recording stops: blanking resumes at once, even within the hint throttle window.
        assert!(s.reconcile(Some(&frame(3, 8)), Some(&c), false, later(1)));
        assert_eq!(halves(s.on_frame(&frame(4, 6), Some(&c), false)), (4, B));
        // Watching every display is "all": raw frames.
        s.set_watched(Some(vec![0, 1]), Some(&c));
        assert!(s.reconcile(Some(&frame(4, 6)), Some(&c), false, later(5)));
        assert_eq!(halves(s.outgoing(Some(&frame(4, 6))).unwrap()), (4, 6));
        assert_eq!(halves(s.on_frame(&frame(5, 5), Some(&c), false)), (5, 5));
    }

    #[test]
    fn a_failed_recording_start_resumes_blanking() {
        let c = two(); let f = frame(1, 2);
        let mut s = FreezeState::default();
        assert!(!s.suspend_for_recording(), "nothing to undo when not blanking");
        s.set_watched(Some(vec![0]), Some(&c));
        s.reconcile(Some(&f), Some(&c), false, later(1));
        assert!(s.suspend_for_recording());
        // set_recording failed, so recording stays false: the next reconcile restores blanking.
        assert!(s.reconcile(Some(&f), Some(&c), false, later(1)));
        assert_eq!(halves(s.outgoing(Some(&f)).unwrap()), (1, B));
    }

    #[test]
    fn unchanged_hints_do_nothing_and_changes_are_throttled() {
        let c = two(); let f = frame(1, 2); let t = later(1);
        let mut s = FreezeState::default();
        assert!(s.set_watched(Some(vec![0]), Some(&c)));
        assert!(s.reconcile(Some(&f), Some(&c), false, t));
        assert!(!s.set_watched(Some(vec![0, 0, 99]), Some(&c)), "same set after normalizing");
        assert!(!s.reconcile(Some(&f), Some(&c), false, t));
        // A change 50 ms later waits; frames keep using the applied set meanwhile.
        assert!(s.set_watched(Some(vec![1]), Some(&c)));
        assert!(!s.reconcile(Some(&f), Some(&c), false, t + Duration::from_millis(50)));
        assert_eq!(halves(s.on_frame(&frame(3, 9), Some(&c), false)), (3, B));
        // At 150 ms it applies.
        assert!(s.reconcile(Some(&f), Some(&c), false, t + Duration::from_millis(150)));
        assert_eq!(halves(s.outgoing(Some(&f)).unwrap()), (B, 2));
        assert!(!s.reconcile(Some(&f), Some(&c), false, t + Duration::from_millis(151)));
    }

    #[test]
    fn oversized_hints_are_ignored_and_no_frame_means_no_send() {
        let c = two(); let mut s = FreezeState::default();
        assert!(s.set_watched(Some(vec![0]), Some(&c)));
        assert!(!s.reconcile(None, Some(&c), false, later(1)), "nothing to send yet");
        assert!(!s.set_watched(Some(vec![0; MAX_HINT_IDS + 1]), Some(&c)));
        assert_eq!(s.watched(), Some(&vec![0]));
        // The first frame then arrives already composed.
        assert_eq!(halves(s.on_frame(&frame(4, 4), Some(&c), false)), (4, B));
    }

    #[test]
    fn a_frame_that_is_not_the_canvas_passes_through() {
        let c = two();
        let mut s = FreezeState::default();
        s.set_watched(Some(vec![0]), Some(&c));
        s.reconcile(None, Some(&c), false, later(1));
        let small = CapturedFrame { monitor_id: 0, width: 2, height: 1, bytes: vec![7; 8], is_keyframe: false };
        assert_eq!(s.on_frame(&small, Some(&c), false).width, 2);
        assert!(s.outgoing(None).is_none());
    }

    fn canvas() -> MonitorCanvas {
        MonitorCanvas { width: 2, height: 1, monitors: (0..2).map(|id|
            rmt_agent_core::control::CanvasMonitor { id, x: id, y: 0, width: 1, height: 1 }).collect() }
    }
    #[test]
    fn normalizes_interest() {
        let c = canvas();
        assert_eq!(normalize(Some(vec![1, 1, 99]), Some(&c)), Some(vec![1]));
        assert_eq!(normalize(Some(vec![0, 1]), Some(&c)), None);
        assert_eq!(normalize(Some(vec![99]), Some(&c)), None);
        assert_eq!(normalize(Some(vec![]), Some(&c)), None);
        assert_eq!(normalize(None, Some(&c)), None);
    }
    #[test]
    fn activation_requires_raw_canvas_and_no_recording() {
        let c = canvas(); let ids = vec![0];
        let mut f = CapturedFrame { monitor_id: u32::MAX, width: 2, height: 1, bytes: vec![0; 8], is_keyframe: false };
        assert!(active(Some(&ids), Some(&c), &f, false));
        assert!(!active(Some(&ids), Some(&c), &f, true));
        assert!(!active(None, Some(&c), &f, false));
        assert!(!active(Some(&vec![]), Some(&c), &f, false));
        assert!(!active(Some(&ids), None, &f, false));
        f.width = 1;
        assert!(!active(Some(&ids), Some(&c), &f, false));
        f.width = 2; f.bytes.pop();
        assert!(!active(Some(&ids), Some(&c), &f, false));
    }
    #[test]
    fn copies_only_watched_rows_and_clamps() {
        let mut dst = vec![0; 3 * 2 * 4];
        let src: Vec<u8> = (1..=24).collect();
        refresh_watched(&mut dst, &src, 3, 2, &[(1, 0, 1, 2), (2, 1, u32::MAX, u32::MAX), (99, 99, 1, 1)]);
        assert_eq!(&dst[0..4], &[0; 4]); assert_eq!(&dst[4..8], &src[4..8]);
        assert_eq!(&dst[8..16], &[0; 8]); assert_eq!(&dst[16..24], &src[16..24]);
    }
    #[test]
    fn malformed_buffers_are_unchanged() {
        let mut dst = vec![7; 8];
        refresh_watched(&mut dst, &[1; 7], 2, 1, &[(0, 0, 2, 1)]);
        assert_eq!(dst, vec![7; 8]);
        refresh_watched(&mut dst, &[1; 8], u32::MAX, u32::MAX, &[(0, 0, 1, 1)]);
        assert_eq!(dst, vec![7; 8]);
    }
}
