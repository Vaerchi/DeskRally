//! [`FollowingCapturer`] — a [`ScreenCapturer`] that follows the active **input desktop** and
//! captures it with the appropriate tier (M7).
//!
//! This is the productized form of `host::helper_worker`'s proof loop: instead of writing a BMP per
//! iteration, each [`ScreenCapturer::capture_frame`] call
//!
//! 1. [`DesktopFollower::poll`]s the input desktop — which calls `SetThreadDesktop` **on the calling
//!    thread**, binding it to `Default` / `Winlogon` / the screensaver desktop as they come and go;
//! 2. [`CaptureLoop::invalidate`]s the desktop-bound DXGI tier on a switch (it dies with the old
//!    desktop);
//! 3. picks the tier that works there ([`CaptureLoop::capture`]) and returns the frame.
//!
//! # The single-thread constraint (why this type exists)
//!
//! `SetThreadDesktop` binds the **calling** thread, and both screen capture of the secure desktop
//! **and** `SendInput` injection act on the calling thread's desktop. Therefore, for the SYSTEM
//! helper, capture and input injection must happen on the *same* thread — the one this capturer's
//! `poll()` binds. [`crate::host::serve_session_with_ice`] runs the capturer on a dedicated
//! `std::thread` and (M7) marshals decoded controller input onto that same thread, so both land on
//! the followed input desktop. Consequently a `FollowingCapturer` must live on exactly one thread.

use rmt_agent_core::platform::{MonitorInfo, PlatformError, PlatformResult};
use rmt_agent_core::{CapturedFrame, ScreenCapturer, TopologySnapshot};

use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN, SM_REMOTESESSION,
};

use crate::capture_loop::CaptureLoop;
use crate::service::DesktopFollower;

/// A [`ScreenCapturer`] that binds its thread to the live input desktop and captures it.
///
/// Owns a [`DesktopFollower`] (the `SetThreadDesktop` follower) and a [`CaptureLoop`] (the
/// DXGI→GDI tier selector). See the module docs for the single-thread requirement — and
/// [`CaptureLoop`]'s for why the WGC tier is not in that chain: a WGC capture would permanently
/// prevent this very thread from following a desktop switch.
pub struct FollowingCapturer {
    /// The capture tier of the last frame, for the change log line.
    last_tier: Option<&'static str>,
    /// Binds the calling thread to the active input desktop; `poll()` reports a switch.
    follower: DesktopFollower,
    /// The tier selector; rebuilt against the new desktop after each switch.
    cap: CaptureLoop,
    /// Whether a desktop has been bound yet. `DesktopFollower::poll` reports the FIRST bind as a
    /// switch (it compares against "no desktop"), so without this every session would open with a
    /// line claiming the desktop "switched" when nothing had changed — an event log that invents
    /// events is worse than one that omits them.
    bound: bool,
    /// The DXGI canvas (docs/52) for the composite stream on the Default desktop; dropped on every
    /// desktop switch and rebuilt lazily.
    canvas: Option<crate::dxgi_canvas::DxgiCanvas<crate::dxgi_source::DxgiFactory, crate::dxgi_source::CanvasGdi>>,
    /// The virtual-desktop rect the canvas was built for (a change rebuilds it).
    canvas_vrect: Option<crate::dxgi_canvas::Rect>,
    /// The monitor rects the canvas was built for, re-read at most every second: a monitor moved,
    /// resized, added or removed INSIDE the same bounds also rebuilds it (Codex implementation r1).
    canvas_rects: Vec<crate::dxgi_canvas::Rect>,
    canvas_rects_checked: Option<std::time::Instant>,
    /// When a canvas may be (re)built after one gave up (see [`CanvasRetry`]).
    canvas_retry: CanvasRetry,
    /// `false` when `config.json` says `"canvas_capture": "gdi"` (docs/52 §4.6 escape hatch).
    canvas_enabled: bool,
    /// How each canvas region was served at the last log line, to log changes only.
    canvas_sources: Vec<String>,
}

// SAFETY: `DesktopFollower` holds an `HDESK` (a raw desktop handle) which is not auto-`Send`, so
// `FollowingCapturer` is not auto-`Send`. It is nonetheless safe to *move* between threads exactly
// once, because it is used under a strict single-owner, single-thread discipline: it is constructed
// on one thread, moved into `serve_session_with_ice`'s dedicated capture thread, and every method
// (`poll`/`SetThreadDesktop`/`capture`) runs only on that thread thereafter. It is never shared
// (`&`) across threads and never touched from two threads at once. Indeed the follower's semantics
// *require* single-thread use — `SetThreadDesktop` binds the calling thread — so this transfer-then-
// pin-to-one-thread pattern is the only correct way to use it. It is never `Sync`.
unsafe impl Send for FollowingCapturer {}

impl FollowingCapturer {
    /// Build a follower-backed capturer. Cheap; the desktop-bound DXGI context is created
    /// lazily on the first [`capture_frame`](ScreenCapturer::capture_frame) (which also performs the
    /// first `poll` + `SetThreadDesktop` on the calling thread).
    pub fn new() -> Self {
        Self {
            follower: DesktopFollower::new(),
            cap: CaptureLoop::new(),
            bound: false,
            last_tier: None,
            canvas: None,
            canvas_vrect: None,
            canvas_rects: Vec::new(),
            canvas_rects_checked: None,
            canvas_retry: CanvasRetry::new(),
            canvas_enabled: true,
            canvas_sources: Vec::new(),
        }
    }

    /// Whether the composite stream may use the DXGI canvas (docs/52). `false` keeps the GDI
    /// composite for this helper's life (`config.json` `"canvas_capture": "gdi"`).
    pub fn with_canvas(mut self, enabled: bool) -> Self {
        self.canvas_enabled = enabled;
        self
    }

    /// Follow the input desktop: bind on first use, and on a switch drop everything bound to the old
    /// desktop (the tier chain's DXGI and cached GDI surface, and the canvas). Returns whether the
    /// current desktop is a secure one.
    fn follow(&mut self) -> PlatformResult<bool> {
        let switched = self
            .follower
            .poll()
            .map_err(|e| PlatformError::CaptureUnavailable(e.to_string()))?;
        let desk = self.follower.current().unwrap_or("<none>");
        let secure = is_secure_desktop(desk);
        if switched {
            // The old desktop's DXGI duplications are dead; force a rebuild.
            self.cap.invalidate();
            self.canvas = None;
            self.canvas_vrect = None;
            self.canvas_retry.reset();
            // Which desktop this thread is bound to is the most load-bearing state in this
            // component: it decides the capture tier AND where SendInput lands (module docs).
            // Delivered to helper.log by crate::logging's subscriber (installed in host_main) —
            // this line was deliberately absent while tracing had no subscriber (docs/07 loop 6
            // §2), and its presence across a real lock/unlock is VM-verified, not assumed.
            //
            // The first poll of a session is a BIND, not a switch, and is reported as such: on the
            // lab VM every session opens on `Default`, and a line reading "switched" there would
            // manufacture a desktop change that never happened.
            if self.bound {
                tracing::info!(
                    desktop = desk,
                    secure,
                    "capture: input desktop SWITCHED — tiers invalidated; injection follows this desktop"
                );
            } else {
                self.bound = true;
                tracing::info!(
                    desktop = desk,
                    secure,
                    "capture: bound to the input desktop; injection follows this desktop"
                );
            }
        }
        Ok(secure)
    }

    fn log_tier(&mut self, tier: &'static str, secure: bool, remote: bool) {
        if self.last_tier != Some(tier) {
            tracing::info!(tier, secure, remote, "capture: tier in use");
            self.last_tier = Some(tier);
        }
    }

    /// Today's composite: one GDI blit of the whole virtual desktop.
    fn gdi_composite(&mut self, secure: bool, remote: bool) -> PlatformResult<CapturedFrame> {
        if let Some(frame) = self.cap.capture_virtual_desktop(crate::input::virtual_desktop_rect()) {
            self.log_tier("gdi-composite", secure, remote);
            return Ok(frame);
        }
        // A horizontal stitch has different coordinates from the virtual desktop.
        // Never substitute it under the same stream identity: existing buffered input
        // and canvas viewports must keep the exact virtual-desktop coordinate space.
        Err(PlatformError::CaptureUnavailable("virtual desktop capture unavailable".into()))
    }

    /// Drop the canvas (and with it every duplication it holds) and leave the GDI composite in
    /// charge until [`CanvasRetry`] allows a rebuild.
    fn give_up_canvas(&mut self, now: std::time::Instant, why: &str) {
        let wait = self.canvas_retry.give_up(now);
        tracing::warn!(why, retry_in_s = wait.as_secs(), "capture: DXGI canvas dropped; the GDI composite serves until the retry");
        self.discard_canvas();
    }

    /// Release the canvas, for any reason. Its health time goes with it: a later canvas must earn
    /// CANVAS_HEALTHY_FOR on its own (Codex canvas-retry r1).
    fn discard_canvas(&mut self) {
        self.canvas = None;
        self.canvas_vrect = None;
        self.canvas_sources.clear();
        self.canvas_retry.canvas_changed();
    }

    /// Build the canvas for the current monitors if it is missing or stale. Leaves it `None` (and
    /// the GDI composite in charge until the retry) when no monitor can be DXGI.
    fn ensure_canvas(&mut self) {
        let (vx, vy, vw, vh) = crate::input::virtual_desktop_rect();
        let vrect = crate::dxgi_canvas::Rect { x: vx, y: vy, w: vw.max(0) as u32, h: vh.max(0) as u32 };
        if self.canvas.is_some() && self.canvas_vrect != Some(vrect) {
            self.discard_canvas();
        }
        let now = std::time::Instant::now();
        if self.canvas.is_none() && !self.canvas_retry.may_build(now) {
            return;
        }
        if self.canvas.is_some() && self.canvas_rects_checked.is_some_and(|t| now.saturating_duration_since(t) < std::time::Duration::from_secs(1)) {
            return;
        }
        // The CHECKED enumeration: a partial one must never build a canvas with missing regions (and
        // an unavailable observation keeps the canvas there is).
        let Some(monitors) = crate::capture_gdi::try_enumerate_monitors_checked() else {
            return;
        };
        let rects: Vec<crate::dxgi_canvas::Rect> = monitors
            .iter()
            .map(|m| crate::dxgi_canvas::Rect { x: m.rect.left, y: m.rect.top, w: m.width().max(0) as u32, h: m.height().max(0) as u32 })
            .collect();
        self.canvas_rects_checked = Some(now);
        if self.canvas.is_some() {
            if rects == self.canvas_rects {
                return;
            }
            tracing::info!("capture: the monitor layout changed inside the same bounds; rebuilding the DXGI canvas");
            self.discard_canvas();
        }
        // An output can be duplicated only once per process: release the tier chain's duplication.
        self.cap.release_dxgi();
        let built = crate::dxgi_source::DxgiFactory::new()
            .ok()
            .and_then(|f| crate::dxgi_canvas::DxgiCanvas::new(vrect, &rects, f, crate::dxgi_source::CanvasGdi::new()));
        match built {
            Some(c) => {
                tracing::info!(sources = ?c.sources(), width = vrect.w, height = vrect.h, "capture: DXGI canvas built");
                self.canvas_retry.canvas_changed();
                self.canvas = Some(c);
                self.canvas_vrect = Some(vrect);
                self.canvas_rects = rects;
            }
            None => self.give_up_canvas(now, "no display can be served by DXGI duplication"),
        }
    }
}

/// The first wait before rebuilding a canvas that gave up; doubled per give-up up to
/// [`CANVAS_RETRY_MAX`].
const CANVAS_RETRY_FIRST: std::time::Duration = std::time::Duration::from_secs(30);
const CANVAS_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(600);
/// How long a canvas must keep at least one validated DXGI region before the backoff starts over.
/// A fresh canvas reports its regions as DXGI before any check, so resetting on the first frame
/// would rebuild every [`CANVAS_RETRY_FIRST`] for as long as the duplication stays silent.
const CANVAS_HEALTHY_FOR: std::time::Duration = std::time::Duration::from_secs(60);

/// When a DXGI canvas may be built again after one gave up (docs/52 §8's re-promotion follow-up,
/// pulled into 1.3.12).
///
/// 1.3.11 kept a canvas whose every region had been demoted to GDI until the next desktop switch.
/// Found on the operator's Desktop 2026-10-26: with the monitors ASLEEP, Desktop Duplication delivers nothing,
/// the self-check (correctly) moves both regions to GDI, and the canvas then costs MORE than the
/// plain GDI composite (two per-monitor reads, 51 ms vs 35 ms per call) for as long as no desktop
/// switch happens, which on an unattended machine can be days. So a canvas that has nothing left
/// on DXGI is dropped, the single-blit GDI composite serves, and a new canvas is tried after a
/// backoff. A rebuilt canvas goes through exactly the build-time path (GDI seed, self-check), so no
/// unvalidated DDA pixel is ever trusted on the way back.
#[derive(Debug)]
struct CanvasRetry {
    /// No canvas may be built before this.
    until: Option<std::time::Instant>,
    /// The wait the next give-up schedules.
    backoff: std::time::Duration,
    /// Since when the current canvas has served with at least one validated DXGI region.
    healthy_since: Option<std::time::Instant>,
}

impl CanvasRetry {
    fn new() -> Self {
        Self { until: None, backoff: CANVAS_RETRY_FIRST, healthy_since: None }
    }

    /// A desktop switch: the old desktop's failures say nothing about the new one.
    fn reset(&mut self) {
        *self = Self::new();
    }

    fn may_build(&self, now: std::time::Instant) -> bool {
        self.until.map_or(true, |t| now >= t)
    }

    /// The canvas gave up (or could not be built): no rebuild for the returned wait, and the next
    /// give-up waits twice as long.
    fn give_up(&mut self, now: std::time::Instant) -> std::time::Duration {
        let wait = self.backoff;
        self.until = Some(now + wait);
        self.backoff = (self.backoff * 2).min(CANVAS_RETRY_MAX);
        self.healthy_since = None;
        wait
    }

    /// The canvas was built, replaced or discarded: health time belongs to ONE canvas.
    fn canvas_changed(&mut self) {
        self.healthy_since = None;
    }

    /// One canvas capture call happened; `any_dxgi` = at least one region is on validated DXGI and
    /// the call published or had no news (a call that could not publish passes `false`).
    fn served(&mut self, any_dxgi: bool, now: std::time::Instant) {
        if !any_dxgi {
            self.healthy_since = None;
            return;
        }
        let since = *self.healthy_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= CANVAS_HEALTHY_FOR {
            self.backoff = CANVAS_RETRY_FIRST;
        }
    }
}

/// Whether every region of a canvas is served by GDI (nothing left that DXGI makes cheaper).
fn every_region_gdi(sources: &[String]) -> bool {
    !sources.is_empty() && sources.iter().all(|s| s.starts_with("gdi"))
}

impl Default for FollowingCapturer {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the named desktop is a **secure** desktop (GDI-only tier). Anything other than the
/// normal interactive `Default` desktop — `Winlogon` (login / UAC / Ctrl-Alt-Del), the secure
/// screensaver — can only be read by GDI. Factored out so the tier decision is unit-testable
/// without a live desktop.
pub(crate) fn is_secure_desktop(name: &str) -> bool {
    name != "Default"
}

impl ScreenCapturer for FollowingCapturer {
    /// Enumerate the attached monitors (M10) so the streaming driver can advertise them to the
    /// controller. Delegates to [`CaptureLoop::monitors`] (GDI `EnumDisplayMonitors` is
    /// authoritative — it is the only enumeration that sees indirect/DisplayLink displays — with
    /// DXGI as the fallback). If enumeration yields nothing (headless / secure desktop with no
    /// output), reports a single primary monitor from the display metrics so the list is never
    /// empty.
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        let mons = self.cap.monitors();
        if !mons.is_empty() {
            return Ok(mons);
        }
        // SAFETY: GetSystemMetrics takes a constant index and returns an int; no pointers.
        let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
        Ok(vec![MonitorInfo {
            id: 0,
            width: w.max(0) as u32,
            height: h.max(0) as u32,
            dpi_scale: 1.0,
            // Last-resort fallback (enumeration returned nothing): a single primary at the origin.
            left: 0,
            top: 0,
        }])
    }

    /// Observe the current display topology via **checked GDI enumeration**. WGC is deliberately
    /// not consulted (see the module docs: WGC would permanently pin the capture thread to a
    /// desktop). A `None` return is unavailability — the host preserves its baseline rather than
    /// treating it as a change.
    fn topology_snapshot(&self) -> Option<TopologySnapshot> {
        let entries = crate::capture_gdi::try_enumerate_monitors_checked()?;
        Some(crate::capture_gdi::snapshot_from_entries(&entries))
    }

    /// Follow the input desktop and capture one frame of `monitor_id` with the working tier (M10).
    ///
    /// Every tier honors `monitor_id`: the id resolves to a virtual-desktop rect and each tier
    /// addresses the panel at that rect (see [`CaptureLoop::capture`]). A desktop switch
    /// invalidates the DXGI tier so the next capture rebuilds it against the new desktop; if every
    /// applicable tier fails the error is
    /// the retryable [`PlatformError::CaptureUnavailable`], matching how the capture thread treats a
    /// transient loss (back off one interval, retry).
    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
        let secure = self.follow()?;
        // An output can be duplicated only once per process: a single-monitor capture releases the
        // canvas's duplications (the canvas is rebuilt if the composite is asked for again).
        if self.canvas.is_some() {
            self.discard_canvas();
        }
        // In an RDP/RDS session DXGI Desktop Duplication returns black; WGC keeps working.
        // SAFETY: GetSystemMetrics(SM_REMOTESESSION) takes a constant index, no pointers.
        let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;

        let got = self.cap.capture(secure, remote, monitor_id);
        // Which tier produced the picture, logged when it CHANGES: privacy mode's exclusion and the
        // pill's are per tier, and without this line nobody could say which tier a lab result (or a
        // customer's session) was on (Codex 1.3.8 round 2 asked exactly that).
        if let Some((tier, _)) = got.as_ref() {
            self.log_tier(tier, secure, remote);
        }
        got.map(|(_tier, f)| f)
            .ok_or_else(|| PlatformError::CaptureUnavailable("all capture tiers failed".into()))
    }

    /// A viewer joined a single-monitor stream on an idle screen: without this, DXGI's "unchanged"
    /// is reported as no news and the joiner never gets a first frame (the composite path gets the
    /// same guarantee from `capture_composite_if_changed(force)`).
    fn force_next_frame(&mut self) {
        self.cap.force_next_frame();
    }

    /// The "view all" composite: always a complete frame (see `capture_composite_if_changed`).
    fn capture_composite(&mut self) -> PlatformResult<CapturedFrame> {
        match self.capture_composite_if_changed(true)? {
            Some(frame) => Ok(frame),
            None => {
                let secure = self.follow()?;
                // SAFETY: GetSystemMetrics takes a constant index.
                let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
                self.gdi_composite(secure, remote)
            }
        }
    }

    /// The composite, from the DXGI canvas on the Default desktop of a console session (docs/52),
    /// otherwise **one GDI blit of the whole virtual desktop** — never a stitch of per-monitor
    /// captures (a stitch came back BLACK on real multi-monitor boxes and has the wrong geometry; see
    /// [`CaptureLoop::capture_virtual_desktop`]).
    ///
    /// The secure desktop (DDA cannot read it) and RDP (DDA returns black as a success) always use the
    /// GDI composite. A canvas call that cannot publish returns a GDI composite frame for that call;
    /// a canvas that demotes itself, or has every region on GDI, hands over to the GDI composite
    /// until [`CanvasRetry`] allows a rebuild (or the next desktop switch).
    fn capture_composite_if_changed(&mut self, force: bool) -> PlatformResult<Option<CapturedFrame>> {
        // Bind to the input desktop first — same contract as `capture_frame`.
        let secure = self.follow()?;
        // SAFETY: GetSystemMetrics takes a constant index.
        let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
        if self.canvas_enabled && !secure && !remote {
            self.ensure_canvas();
            if let Some(canvas) = self.canvas.as_mut() {
                let (width, height) = canvas.size();
                let now = std::time::Instant::now();
                match canvas.capture(force, now) {
                    crate::dxgi_canvas::CanvasOutcome::Frame(bytes) => {
                        let sources = canvas.sources();
                        if sources != self.canvas_sources {
                            tracing::info!(?sources, "capture: DXGI canvas regions");
                            self.canvas_sources = sources.clone();
                        }
                        self.log_tier("dxgi-canvas", secure, remote);
                        // This frame is valid either way; with nothing left on DXGI, the next call
                        // goes to the cheaper single-blit GDI composite (see CanvasRetry).
                        if every_region_gdi(&sources) {
                            self.give_up_canvas(now, "every canvas region is served by GDI");
                        } else {
                            self.canvas_retry.served(sources.iter().any(|s| s == "dxgi"), now);
                        }
                        return Ok(Some(CapturedFrame {
                            monitor_id: rmt_agent_core::COMPOSITE_MONITOR_ID,
                            width,
                            height,
                            bytes,
                            is_keyframe: true,
                        }));
                    }
                    crate::dxgi_canvas::CanvasOutcome::NoNews => {
                        let any_dxgi = canvas.sources().iter().any(|s| s == "dxgi");
                        self.canvas_retry.served(any_dxgi, now);
                        return Ok(None);
                    }
                    crate::dxgi_canvas::CanvasOutcome::Fallback(why) => {
                        tracing::debug!(why, "capture: DXGI canvas cannot publish this call; GDI composite frame instead");
                        // A call that could not publish is not healthy, whatever the regions report.
                        self.canvas_retry.served(false, now);
                    }
                    crate::dxgi_canvas::CanvasOutcome::Demoted(why) => self.give_up_canvas(now, why),
                }
            }
        }
        self.gdi_composite(secure, remote).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_desktop_is_not_secure_others_are() {
        assert!(!is_secure_desktop("Default"));
        assert!(is_secure_desktop("Winlogon"));
        assert!(is_secure_desktop("Screen-saver"));
        assert!(is_secure_desktop("<none>"));
    }

    #[test]
    fn every_region_gdi_needs_all_regions_on_gdi() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(every_region_gdi(&s(&["gdi(self-check)", "gdi(rotated)"])));
        assert!(!every_region_gdi(&s(&["gdi(self-check)", "dxgi"])), "one DXGI region still saves a read");
        assert!(!every_region_gdi(&s(&["gdi(self-check)", "dxgi-quarantined"])), "quarantine can still lift");
        assert!(!every_region_gdi(&[]), "no regions is not 'all GDI'");
    }

    #[test]
    fn a_canvas_that_gives_up_is_retried_with_a_doubling_backoff() {
        let t = std::time::Instant::now();
        let mut r = CanvasRetry::new();
        assert!(r.may_build(t), "nothing has failed yet");
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST);
        assert!(!r.may_build(t + CANVAS_RETRY_FIRST - std::time::Duration::from_millis(1)));
        assert!(r.may_build(t + CANVAS_RETRY_FIRST), "rebuilt once the wait is over");
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 2);
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 4);
        for _ in 0..10 {
            r.give_up(t);
        }
        assert_eq!(r.give_up(t), CANVAS_RETRY_MAX, "capped");
    }

    /// A rebuilt canvas reports DXGI before any check has passed, so a silent duplication (monitors
    /// asleep) would otherwise be rebuilt every CANVAS_RETRY_FIRST forever.
    #[test]
    fn the_backoff_starts_over_only_after_a_sustained_healthy_canvas() {
        let t = std::time::Instant::now();
        let mut r = CanvasRetry::new();
        r.give_up(t);
        r.give_up(t); // next wait: 4x
        r.served(true, t);
        r.served(true, t + CANVAS_HEALTHY_FOR - std::time::Duration::from_millis(1));
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 4, "a briefly healthy canvas keeps the backoff");
        r.served(true, t);
        r.served(false, t + std::time::Duration::from_secs(1)); // a region fell to GDI: the clock restarts
        r.served(true, t + CANVAS_HEALTHY_FOR);
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 8, "healthy time must be continuous");
        r.served(true, t);
        r.served(true, t + CANVAS_HEALTHY_FOR);
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST, "a canvas healthy for CANVAS_HEALTHY_FOR resets it");
    }

    /// Codex canvas-retry r1: health time must be continuous AND belong to one canvas.
    #[test]
    fn an_unpublishable_call_or_a_replaced_canvas_restarts_the_health_clock() {
        let t = std::time::Instant::now();
        let s = |n: u64| t + std::time::Duration::from_secs(n);
        let mut r = CanvasRetry::new();
        r.give_up(t);
        r.give_up(t); // next wait: 4x
        // A Fallback (served(false)) in the middle of an otherwise healthy minute.
        r.served(true, s(0));
        r.served(false, s(30));
        r.served(true, s(60));
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 4, "an unpublishable call interrupts health");
        // A canvas replaced half-way: the new one does not inherit the old one's time.
        r.served(true, s(0));
        r.canvas_changed();
        r.served(true, s(30));
        r.served(true, s(60));
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST * 8, "health time belongs to one canvas");
    }

    #[test]
    fn a_desktop_switch_forgets_the_backoff() {
        let t = std::time::Instant::now();
        let mut r = CanvasRetry::new();
        r.give_up(t);
        r.give_up(t);
        r.reset();
        assert!(r.may_build(t));
        assert_eq!(r.give_up(t), CANVAS_RETRY_FIRST);
    }

    #[test]
    fn constructs_and_reports_at_least_a_primary_monitor() {
        // Construction touches no desktop (poll happens on first capture), so this is safe headless.
        // monitors() now enumerates real displays (M10): at least one, and the primary is id 0. On
        // a multi-monitor box it reports more; the list is never empty (metrics fallback).
        let cap = FollowingCapturer::new();
        let mons = cap.monitors().expect("monitors query");
        assert!(!mons.is_empty(), "FollowingCapturer reports at least one monitor");
        assert!(mons.iter().any(|m| m.id == 0), "primary monitor id 0 is present");
    }
}
