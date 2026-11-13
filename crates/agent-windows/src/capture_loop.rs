//! Reusable capture-tier selector (ADR-005), factored out of [`crate::host::helper_worker`] so
//! the proof-BMP helper and the WebRTC streaming driver share one tier policy.
//!
//! # Tier policy
//!
//! * **GDI** on the Winlogon **secure** desktop (the only tier that can read the login/UAC screen).
//! * **GDI** in an **RDP/RDS** session (DXGI Desktop Duplication returns black there — and returns
//!   it as a *successful* capture, so DXGI is not merely useless there, it is actively wrong).
//! * **DXGI** on the local `Default` desktop (fast, zero-copy capable), GDI as the fallback.
//!
//! DXGI binds to the desktop that was current when it was created, so a desktop switch must
//! [`CaptureLoop::invalidate`] it; the next capture rebuilds a fresh context against the new
//! desktop. Any capture error also drops that tier's context so the following call self-heals.
//!
//! # Why WGC is NOT in this chain
//!
//! [`crate::capture_wgc`] exists, works, and captures any monitor — but it must never run on the
//! thread this type runs on, and that thread is the only one that uses it.
//!
//! **A WGC capture permanently prevents `SetThreadDesktop` on the calling thread**, which fails
//! afterwards with `ERROR_BUSY` (0x800700AA) — the documented failure when a thread has windows or
//! hooks on its desktop. Measured on real hardware, with a DXGI control that passes, and dropping
//! the capturer does NOT release it: the thread is spoiled for the rest of its life
//! (`capture_wgc::tests::wgc_does_not_leave_the_thread_unable_to_switch_desktops`).
//!
//! That thread is [`crate::following_capturer::FollowingCapturer`]'s — the one that binds itself to
//! the active input desktop AND the one `SendInput` injects from, because both must be the same
//! thread. So a single WGC capture, anywhere in a session, silently costs the agent every desktop
//! switch after it: a UAC prompt, a lock screen, Ctrl+Alt+Del. Capture keeps showing the desktop it
//! was stuck on, and every injected click lands there instead of on the secure desktop — which from
//! the technician's chair is exactly "the mouse does not work at the login screen".
//!
//! And it fired constantly: DXGI yields a frame only on a screen CHANGE, so any idle screen timed
//! out and fell through to WGC. The most ordinary thing a session does — sit still — disabled the
//! secure desktop.
//!
//! Restoring WGC (it is the better RDP tier) means running it on its OWN thread and shipping frames
//! across, so nothing it does can touch the desktop-following thread. Until then GDI serves RDP:
//! slower, and correct.
//!
//! # One id space, three tiers: monitors are addressed BY RECT
//!
//! Each tier has its own idea of what "monitor 2" means — DXGI numbers outputs per adapter, WGC
//! takes an `HMONITOR`, GDI enumerates devices. Worse, they do not even see the same set of
//! displays: **DXGI Desktop Duplication cannot see indirect displays at all** (DisplayLink and
//! other USB-dock panels, Miracast, most virtual displays), so on a docked laptop it reports the
//! one built-in screen and knows nothing of the two on the desk.
//!
//! So the id space is anchored to GDI's `EnumDisplayMonitors` — the only enumeration that sees
//! every attached panel — ordered by position ([`crate::capture_gdi::order_entries`]), and a
//! capture resolves that id to a **virtual-desktop rect** first. The rect is the one thing all
//! three tiers agree on:
//!
//! * DXGI captures the output whose `DesktopCoordinates` equal the rect (native and fast) — and
//!   reports *no such output* for an indirect display, which is the signal to fall through;
//! * GDI `BitBlt`s the rect out of the desktop DC, which works for every display there is;
//! * WGC (not in the chain, see above) captures the `HMONITOR` at the rect's centre.
//!
//! The alternative — publishing the GDI list while capture still selected "the Nth DXGI output" —
//! would stream the *wrong panel* for a given id, and every frame would still look like a perfectly
//! valid screen, so nothing downstream would ever notice.

use std::time::{Duration, Instant};

use rmt_agent_core::{CapturedFrame, MonitorInfo};

use crate::capture::{CaptureError, DxgiCapturer};
use crate::capture_gdi::{enumerate_monitors_ordered, monitor_infos, GdiCapturer, MonitorEntry};

/// How long a monitor enumeration is reused before being re-read.
///
/// Enumeration is cheap (a synchronous `EnumDisplayMonitors` walk), but it happens on the capture
/// hot path, so it is not re-run per frame. One second is short enough that a hotplug or a
/// resolution change is picked up while the session is still connected, and long enough that a
/// 30 fps stream re-enumerates 30x less often than it captures.
const MONITOR_TABLE_TTL: Duration = Duration::from_secs(1);

/// The resolved capture target: a public monitor id and the virtual-desktop rect it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Target {
    /// The public [`MonitorInfo::id`] — stamped onto the frame whichever tier serves it, so the
    /// controller always gets back the id it asked for and never a tier's internal index.
    id: u32,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
}

impl Target {
    /// The rect in the `(left, top, right, bottom)` form DXGI reports `DesktopCoordinates` in.
    fn dxgi_rect(&self) -> (i32, i32, i32, i32) {
        (
            self.left,
            self.top,
            self.left + self.width,
            self.top + self.height,
        )
    }
}

/// What one tier had to say about a frame.
///
/// The distinction that matters is `Unchanged` vs `Failed`. Collapsing them into "no frame" is what
/// made an idle screen fall through the whole tier chain on every single iteration — re-capturing
/// and re-encoding a picture the receiver already had, and (while WGC was still in the chain)
/// spoiling the thread's ability to follow a desktop switch while doing it.
enum Grab {
    /// A fresh frame.
    Frame(CapturedFrame),
    /// The tier is healthy; the screen simply has not changed since the last frame.
    Unchanged,
    /// The tier could not serve this monitor — try the next one.
    Failed,
}

/// Owns the capture tiers and picks the one that works on the current desktop.
///
/// The caller supplies the desktop *state* (`secure`, `remote`) per iteration — this type does not
/// track the input desktop itself (that is [`crate::service::DesktopFollower`]'s job); it just
/// selects and self-heals the capturer. Reused by both `helper_worker` (proof BMPs) and
/// [`crate::host::stream_screen`]'s CLI path when a full tier selector is wanted.
pub struct CaptureLoop {
    /// DXGI Desktop Duplication — primary tier on the local `Default` desktop. Rebuilt on demand.
    dxgi: Option<DxgiCapturer>,
    /// Which monitor the last delivered frame was of, if any. See [`Self::unchanged_is_no_news`].
    last_produced_for: Option<u32>,
    /// GDI `BitBlt` — universal fallback and the only secure-desktop tier. Cheap to hold always.
    gdi: GdiCapturer,
    /// The monitor table backing id → rect resolution, and when it was read (see
    /// [`MONITOR_TABLE_TTL`]).
    table: Vec<MonitorEntry>,
    table_read: Option<Instant>,
    /// Memoized rect → DXGI output index. Keyed by the rect so a display-layout change re-resolves
    /// on its own; dropped whenever the DXGI tier is.
    dxgi_output: Option<((i32, i32, i32, i32), u32)>,
    /// Test seam: substitute the OS enumeration so the guard/resolve path can be exercised
    /// deterministically without a display. Production always reads `enumerate_monitors_ordered`.
    #[cfg(test)]
    enumerate_override: Option<Box<dyn FnMut() -> Vec<MonitorEntry> + Send>>,
}

impl Default for CaptureLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureLoop {
    /// Build an empty selector; DXGI/WGC contexts are created lazily on first use.
    pub fn new() -> Self {
        Self {
            dxgi: None,
            gdi: GdiCapturer::new(),
            last_produced_for: None,
            table: Vec::new(),
            table_read: None,
            dxgi_output: None,
            #[cfg(test)]
            enumerate_override: None,
        }
    }

    /// Invalidate the desktop-bound tiers (DXGI, WGC). Call on every input-desktop switch — those
    /// duplication objects are tied to the desktop current at creation and go black otherwise.
    ///
    /// The monitor table is dropped too: a desktop switch is also the moment a resolution or
    /// layout change is most likely to have happened underneath us.
    /// Drop the DXGI tier's duplication (an output can be duplicated only once per process; the
    /// DXGI canvas needs it). It is rebuilt lazily if a single-monitor capture needs it again.
    pub fn release_dxgi(&mut self) {
        self.dxgi = None;
        self.dxgi_output = None;
    }

    /// The next [`Self::capture`] delivers a complete frame even if the screen has not changed (a new
    /// viewer joined the stream and has no picture): forgetting what was delivered makes an
    /// "unchanged" tier fall through to one that always yields a frame, exactly as the first capture does.
    pub fn force_next_frame(&mut self) {
        self.last_produced_for = None;
    }

    pub fn invalidate(&mut self) {
        self.dxgi = None;
        self.dxgi_output = None;
        // The cached GDI DC belongs to the desktop being left; the next capture makes a new one.
        self.gdi.invalidate();
        // Whatever was delivered belonged to the OLD desktop. Forget it, so the first capture on
        // the new one produces a real frame instead of reporting "nothing has changed" — switching
        // to the login screen and showing the desktop behind it is the whole failure being avoided.
        self.last_produced_for = None;
        self.table_read = None;
    }

    /// Enumerate the attached monitors so the streaming driver can advertise them (M10).
    ///
    /// **GDI is authoritative** — `EnumDisplayMonitors` is the only enumeration that sees indirect
    /// displays (DisplayLink / USB docks / Miracast), which DXGI Desktop Duplication has no output
    /// for; ids are positions in that list, left to right. DXGI enumeration is the fallback for the
    /// case GDI cannot serve (no monitors reported at all), and it reports a flat output index, so
    /// the two orderings must never be mixed — see the module docs.
    pub fn monitors(&self) -> Vec<MonitorInfo> {
        let mons = monitor_infos(&enumerate_monitors_ordered());
        if !mons.is_empty() {
            return mons;
        }
        DxgiCapturer::new()
            .ok()
            .and_then(|d| d.enumerate_monitors().ok())
            .unwrap_or_default()
    }

    /// The monitor table, re-read when older than [`MONITOR_TABLE_TTL`].
    fn table(&mut self) -> &[MonitorEntry] {
        let stale = self
            .table_read
            .map(|t| t.elapsed() >= MONITOR_TABLE_TTL)
            .unwrap_or(true);
        if stale {
            self.table = self.read_enumeration();
            self.table_read = Some(Instant::now());
        }
        &self.table
    }

    /// Where the monitor table comes from. Production goes to `EnumDisplayMonitors`; tests may
    /// install a scripted source via `enumerate_override` so the guard path is provable without
    /// a display.
    fn read_enumeration(&mut self) -> Vec<MonitorEntry> {
        #[cfg(test)]
        if let Some(f) = self.enumerate_override.as_mut() {
            return f();
        }
        enumerate_monitors_ordered()
    }

    /// Resolve a public monitor id to its virtual-desktop rect.
    ///
    /// `None` means the FINAL enumeration (after the forced re-read below) does not know this id —
    /// either the list is empty (no enumerable display: headless, session 0), or the monitor was
    /// unplugged, or the entry is degenerate. The guard in [`Self::capture_with`] then decides
    /// whether that None means "fall back to the legacy backend-index path" (empty enumeration
    /// only) or "refuse this capture" (enumeration exists but has no such id).
    fn resolve(&mut self, monitor_id: u32) -> Option<Target> {
        // Force one re-read if the id is unknown: a monitor plugged in mid-session should not have
        // to wait out the TTL before it can be captured. The guard reads the table AFTER this
        // refresh, never the pre-refresh snapshot.
        if self.table().len() as u64 <= monitor_id as u64 {
            self.table_read = None;
        }
        let table = self.table();
        let e = table.get(monitor_id as usize)?;
        let (width, height) = (e.width(), e.height());
        if width <= 0 || height <= 0 {
            return None;
        }
        Some(Target {
            id: monitor_id,
            left: e.rect.left,
            top: e.rect.top,
            width,
            height,
        })
    }

    /// Capture one frame of monitor `monitor_id` with the tier appropriate to the desktop state.
    ///
    /// * `secure` — the current input desktop is the Winlogon/secure desktop (GDI only).
    /// * `remote` — running inside an RDP/RDS session (`SM_REMOTESESSION`): WGC first, GDI last.
    /// * `monitor_id` — which monitor to capture (M10), a public id from [`Self::monitors`]. Every
    ///   tier honours it: the id resolves to a virtual-desktop rect, and each tier addresses the
    ///   panel at that rect (see the module docs). The returned frame is always stamped with the
    ///   requested id, never a tier's internal index.
    ///
    /// Returns `Some((tier_name, frame))` on success, or `None` for an unresolved id in a nonempty
    /// monitor table or if every applicable tier failed
    /// (each failed tier is dropped so the next call rebuilds it).
    pub fn capture(
        &mut self,
        secure: bool,
        remote: bool,
        monitor_id: u32,
    ) -> Option<(&'static str, CapturedFrame)> {
        self.capture_with(monitor_id, |this, id, target| {
            if secure {
                // Only GDI can read the Winlogon secure desktop.
                this.gdi_capture(id, target).map(|f| ("gdi", f))
            } else if remote {
                // RDP/RDS. NOT DXGI: Desktop Duplication returns BLACK frames in a remote session,
                // and returns them as a SUCCESS, so trying it first would serve a black screen
                // forever rather than fall through. WGC is the better tier here and is deliberately
                // unavailable (see the module docs) — GDI is slower and correct.
                this.gdi_capture(id, target).map(|f| ("gdi", f))
            } else {
                // Local Default desktop: DXGI (fast/zero-copy capable), GDI as the fallback.
                match this.dxgi_capture(id, target) {
                    Grab::Frame(f) => Some(("dxgi", f)),
                    // The screen has not changed since the last frame. Re-capturing it with ANOTHER
                    // tier would hand the encoder a picture the receiver already has — a full
                    // GDI blit and readback for every idle frame, forever, on the customer's box.
                    // The session loop's minimum-cadence re-send is what keeps the receiver fed;
                    // the right answer here is simply "nothing new". Before the first frame exists
                    // there is nothing to re-send, so that case still falls through.
                    Grab::Unchanged if this.unchanged_is_no_news(id) => None,
                    _ => this
                        .gdi_capture(id, target)
                        .map(|f| ("gdi-fallback", f)),
                }
            }
        })
    }

    /// Shared refresh → guard → dispatch routing seam.
    ///
    /// Owns the whole topology-safety wiring in one place so the same code runs in production
    /// `capture()` and in the deterministic tests: run `resolve` (which may force a re-read),
    /// observe the FINAL table, and only then decide whether to dispatch.
    ///
    /// The guard: `target.is_none() && !self.table.is_empty()` refuses the capture without
    /// touching any backend — the "wrong monitor, right label" failure the review flagged, where
    /// the legacy backend-INDEX fallback in [`Self::dxgi_capture`] / [`Self::gdi_capture`] would
    /// serve some other display under the requested id. A degenerate zero-area entry lands here
    /// too (resolve returns None with the table nonempty) and is likewise refused.
    ///
    /// The empty-enumeration route is preserved: with no enumerable displays (headless /
    /// session 0 / early boot) the dispatch is invoked with `target = None` and the tier's
    /// legacy backend-index path is attempted — the documented no-enumeration fallback.
    fn capture_with<D>(
        &mut self,
        monitor_id: u32,
        dispatch: D,
    ) -> Option<(&'static str, CapturedFrame)>
    where
        D: FnOnce(&mut Self, u32, Option<Target>) -> Option<(&'static str, CapturedFrame)>,
    {
        let target = self.resolve(monitor_id);
        let table_nonempty = !self.table.is_empty();
        if target.is_none() && table_nonempty {
            return None;
        }
        let out = dispatch(self, monitor_id, target);
        if out.is_some() {
            self.last_produced_for = Some(monitor_id);
        }
        out
    }

    /// Whether a tier's "the screen has not changed" may be reported to the caller as *no news*,
    /// rather than falling through to a tier that always yields something.
    ///
    /// Only when the last frame actually delivered was **of this same monitor**. "Unchanged" is a
    /// statement about the SCREEN; "the caller already has this picture" is a statement about the
    /// STREAM, and they coincide only while the selected monitor stays put.
    ///
    /// Getting this wrong is not subtle in effect but is invisible in the code: with a single
    /// global "have we ever produced a frame" flag, a technician switching to their second monitor
    /// on an idle desktop gets NOTHING — DXGI reports unchanged (it is, nothing is moving), the
    /// capture reports no news, and the session's minimum-cadence re-send keeps feeding the
    /// receiver the LAST frame, which is the *other* monitor. The picker says Display 2 and the
    /// picture stays on Display 1, indefinitely, until something happens to move on the new screen.
    fn unchanged_is_no_news(&self, monitor_id: u32) -> bool {
        self.last_produced_for == Some(monitor_id)
    }

    /// Capture the **whole virtual desktop** as one frame — the "view all" composite.
    ///
    /// One GDI `BitBlt` of the entire virtual-desktop rect, rather than capturing each monitor and
    /// stitching the results. Two reasons, both learned the hard way:
    ///
    /// * **The stitch comes back BLACK on a real multi-monitor box.** Capturing monitor 0 then
    ///   monitor 1 makes DXGI tear down and recreate its duplication on every single call (one
    ///   duplication per capturer, and the active output keeps changing), and the first
    ///   `AcquireNextFrame` on a fresh duplication yields a blank surface. So the "view all" frame
    ///   was two blanks side by side — captured successfully, at a plausible size, at 50 fps.
    /// * **The stitch has the wrong geometry.** It lays monitors out in a left-to-right strip,
    ///   which is not the desktop unless the monitors happen to be arranged in exactly that line
    ///   with no vertical offset and no gaps. A single blit of the virtual rect reproduces the true
    ///   arrangement for free — and, because the frame is then exactly the rect that
    ///   `MOUSEEVENTF_VIRTUALDESK` normalizes against, a click in view-all mode lands where the
    ///   operator pointed instead of somewhere in a fictional strip.
    ///
    /// `vrect` is `(origin_x, origin_y, width, height)` from the live display metrics; the origin
    /// is negative when a monitor sits left of or above the primary.
    pub fn capture_virtual_desktop(
        &mut self,
        vrect: (i32, i32, i32, i32),
    ) -> Option<CapturedFrame> {
        let (vx, vy, vw, vh) = vrect;
        if vw <= 0 || vh <= 0 {
            return None;
        }
        self.gdi
            .capture_rect(rmt_agent_core::COMPOSITE_MONITOR_ID, vx, vy, vw, vh)
            .ok()
    }

    /// DXGI tier. Resolves the target rect to a Desktop Duplication output and captures it.
    ///
    /// Returns `None` — falling through to WGC/GDI — when the monitor is an **indirect display**
    /// DXGI has no output for. That is the whole reason a docked laptop's extra screens were
    /// invisible: DXGI enumerated one output, so the list published one monitor.
    fn dxgi_capture(&mut self, monitor_id: u32, target: Option<Target>) -> Grab {
        if self.dxgi.is_none() {
            self.dxgi = DxgiCapturer::new().ok();
            self.dxgi_output = None;
        }
        // Which DXGI output serves this monitor. With no resolved rect (enumeration unavailable)
        // fall back to treating the id as the flat output index, which is what this tier did before
        // rects existed and is correct for the single-monitor case that path implies.
        let index = match target {
            Some(t) => {
                let want = t.dxgi_rect();
                match self.dxgi_output {
                    Some((cached, idx)) if cached == want => idx,
                    _ => {
                        let Some(dxgi) = self.dxgi.as_ref() else {
                            return Grab::Failed;
                        };
                        match dxgi.output_index_for_rect(want) {
                            Ok(Some(idx)) => {
                                self.dxgi_output = Some((want, idx));
                                idx
                            }
                            // No output covers this rect: an indirect display. Not an error, and
                            // not something a rebuild fixes — hand it to a tier that can see it.
                            Ok(None) => return Grab::Failed,
                            Err(_) => {
                                self.dxgi = None;
                                self.dxgi_output = None;
                                return Grab::Failed;
                            }
                        }
                    }
                }
            }
            None => monitor_id,
        };
        let Some(dxgi) = self.dxgi.as_mut() else {
            return Grab::Failed;
        };
        match dxgi.capture_frame_typed(index) {
            Ok(Some(mut f)) => {
                f.monitor_id = monitor_id;
                Grab::Frame(f)
            }
            // "Nothing new since the last frame" — DXGI only yields on a screen CHANGE, so this is
            // the NORMAL state of an idle desktop, not a fault. Keep the duplication: tearing it
            // down here would rebuild one every ~100 ms for as long as nobody touches the machine.
            Ok(None) | Err(CaptureError::Timeout) => Grab::Unchanged,
            Err(_) => {
                self.dxgi = None; // rebuild next time
                self.dxgi_output = None;
                Grab::Failed
            }
        }
    }

    /// GDI tier. `BitBlt`s the target rect out of the desktop DC — the only tier that can read the
    /// secure desktop, and the one that can read *any* display, indirect ones included.
    fn gdi_capture(&mut self, monitor_id: u32, target: Option<Target>) -> Option<CapturedFrame> {
        let result = match target {
            Some(t) => self.gdi.capture_rect(monitor_id, t.left, t.top, t.width, t.height),
            None => self.gdi.capture(monitor_id),
        };
        match result {
            Ok(mut f) => {
                f.monitor_id = monitor_id;
                Some(f)
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::RECT;

    fn rect(left: i32, top: i32, w: i32, h: i32) -> RECT {
        RECT {
            left,
            top,
            right: left + w,
            bottom: top + h,
        }
    }

    /// A `CaptureLoop` with a pinned monitor table, so id → rect resolution can be tested without
    /// a display. The TTL is defeated by stamping `table_read` now.
    fn loop_with_table(entries: Vec<MonitorEntry>) -> CaptureLoop {
        let mut c = CaptureLoop::new();
        c.table = entries;
        c.table_read = Some(Instant::now());
        c
    }

    fn entry(left: i32, top: i32, w: i32, h: i32) -> MonitorEntry {
        MonitorEntry {
            rect: rect(left, top, w, h),
            dpi_x: 96,
            primary: left == 0 && top == 0,
            device: format!(r"\\.\DISPLAY{left}"),
        }
    }

    #[test]
    fn resolve_maps_each_id_to_its_own_rect() {
        // ASYMMETRIC on purpose: different origins AND different sizes, so a swapped or constant
        // mapping cannot pass. Id 2 is the DisplayLink panel DXGI cannot see.
        let mut c = loop_with_table(vec![
            entry(-1280, 0, 1280, 1024),
            entry(0, 0, 1920, 1080),
            entry(1920, 0, 2560, 1440),
        ]);
        assert_eq!(
            c.resolve(0),
            Some(Target { id: 0, left: -1280, top: 0, width: 1280, height: 1024 })
        );
        assert_eq!(
            c.resolve(1),
            Some(Target { id: 1, left: 0, top: 0, width: 1920, height: 1080 })
        );
        assert_eq!(
            c.resolve(2),
            Some(Target { id: 2, left: 1920, top: 0, width: 2560, height: 1440 })
        );
    }

    #[test]
    fn dxgi_rect_is_left_top_right_bottom() {
        // The DXGI side compares against `DesktopCoordinates`, which is a RECT (right/bottom), not
        // a size. Getting this wrong would make every non-origin monitor "an indirect display" and
        // silently demote the whole fleet to the GDI tier.
        let t = Target { id: 1, left: 1920, top: -120, width: 2560, height: 1440 };
        assert_eq!(t.dxgi_rect(), (1920, -120, 4480, 1320));
    }

    #[test]
    fn a_single_monitor_desktop_resolves_to_the_origin_rect() {
        // The regression guard for the overwhelmingly common case: one display → id 0 → (0,0),
        // which makes the GDI blit and the DXGI output selection identical to the pre-rect code.
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080)]);
        assert_eq!(
            c.resolve(0),
            Some(Target { id: 0, left: 0, top: 0, width: 1920, height: 1080 })
        );
    }

    #[test]
    fn an_unknown_id_resolves_to_nothing_rather_than_the_wrong_monitor() {
        // A stale selection (monitor unplugged mid-session) must not silently capture a neighbour.
        // Resolution returns None; the topology-safety guard in `capture_with` then refuses the
        // capture whenever the enumeration is nonempty, so the legacy backend-INDEX fallback
        // (which could serve a different panel under the requested id) is never reached — see the
        // guard tests below.
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080)]);
        assert_eq!(c.resolve(7), None);
    }

    #[test]
    fn a_zero_area_monitor_is_not_a_capture_target() {
        // A detached/degenerate entry would otherwise reach BitBlt as a 0x0 blit.
        let mut c = loop_with_table(vec![entry(0, 0, 0, 0)]);
        assert_eq!(c.resolve(0), None);
    }

    /// Hotplug: an id past the end of the cached table must force a re-read rather than wait out
    /// the TTL, or a monitor plugged in mid-session stays uncapturable for a second.
    ///
    /// # This test used to depend on the HOST having more than one monitor
    ///
    /// It asserted `table_read.is_none() || table.len() > 1`. Neither clause says what it looks
    /// like it says. `resolve` invalidates the cache and then calls `table()` again, which
    /// immediately re-reads and re-stamps `table_read` — so `is_none()` can NEVER be observed once
    /// `resolve` has returned. That left `table.len() > 1`, i.e. "this machine has at least two
    /// displays", which is true on the dev box (three) and false on a hosted CI runner (Session 0,
    /// no interactive desktop). It passed here for months and failed the first time CI ever built
    /// this branch.
    ///
    /// So it now observes the re-read DIRECTLY and without asking anything of the host: plant a
    /// table no real enumeration could return, and require that it is gone afterwards. That holds
    /// whether the host has three monitors, one, or none.
    #[test]
    fn an_unknown_id_busts_the_table_cache() {
        // Deliberately impossible: a rect at an absurd origin with an absurd size, so "the table
        // changed" cannot be confused with "the host happens to look like the fixture".
        let planted = vec![entry(31337, 31337, 4242, 2424)];
        let mut c = loop_with_table(planted.clone());
        assert!(c.table_read.is_some(), "the fixture starts with a warm cache");

        let _ = c.resolve(3); // past the end of a one-entry table

        assert_ne!(
            c.table.first().map(|e| e.rect.left),
            planted.first().map(|e| e.rect.left),
            "an out-of-range id must invalidate the cached table and force a re-read; the planted \
             sentinel is still in place, so no re-read happened"
        );
    }

    /// The NEGATIVE CONTROL for the test above, and the half that gives it meaning: an id the
    /// cached table can already answer must NOT trigger a re-read. Without this, a `resolve` that
    /// re-enumerated on every single call would pass the hotplug test perfectly while throwing away
    /// the cache the TTL exists to provide.
    #[test]
    fn an_in_range_id_leaves_the_cached_table_alone() {
        let planted = vec![entry(31337, 31337, 4242, 2424), entry(0, 0, 1920, 1080)];
        let mut c = loop_with_table(planted.clone());

        let got = c.resolve(0);

        assert_eq!(
            got,
            Some(Target { id: 0, left: 31337, top: 31337, width: 4242, height: 2424 }),
            "an in-range id resolves from the CACHED table, not from a fresh enumeration"
        );
        assert_eq!(
            c.table.len(),
            planted.len(),
            "resolving a known id must not re-enumerate — the cached table was replaced"
        );
    }

    #[test]
    fn unchanged_is_only_no_news_for_the_monitor_already_being_streamed() {
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080), entry(1920, 0, 1920, 1080)]);
        // Nothing delivered yet: an idle screen must still be captured somehow, or a session that
        // opens on a motionless desktop shows nothing at all.
        assert!(!c.unchanged_is_no_news(0));

        c.last_produced_for = Some(0);
        assert!(c.unchanged_is_no_news(0), "same monitor, nothing new — the receiver has it");
        // THE case a global flag gets wrong: the operator just switched to Display 2. The screen
        // being unchanged says nothing about a picture the receiver has never seen.
        assert!(
            !c.unchanged_is_no_news(1),
            "a monitor the receiver has never been shown must produce a frame even when idle"
        );
    }

    #[test]
    fn invalidate_forgets_which_monitor_was_delivered() {
        // A desktop switch (to Winlogon, say) must yield a real frame immediately: the previous
        // frame was of the desktop we just left, so reporting "unchanged" would leave the
        // technician looking at the old desktop while the machine sits at the login screen.
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080)]);
        c.last_produced_for = Some(0);
        c.invalidate();
        assert!(!c.unchanged_is_no_news(0));
    }

    #[test]
    fn force_next_frame_makes_an_unchanged_screen_produce_a_frame() {
        // A viewer joining an idle stream has no picture: "unchanged" must not be no news for it.
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080)]);
        c.last_produced_for = Some(0);
        c.force_next_frame();
        assert!(!c.unchanged_is_no_news(0));
    }

    fn fake_frame(id: u32, w: u32, h: u32) -> CapturedFrame {
        CapturedFrame {
            monitor_id: id,
            width: w,
            height: h,
            bytes: Vec::new(),
            is_keyframe: true,
        }
    }

    /// Enumeration source that never runs. Installed in tests whose cached table already answers
    /// every resolve — so an unexpected re-read (from a broken TTL / missed cache seed) TRIPS
    /// deterministically instead of silently reaching the real OS on the dev box.
    fn forbid_enumeration() -> Box<dyn FnMut() -> Vec<MonitorEntry> + Send> {
        Box::new(|| panic!("unexpected enumeration: this test scripted its own table"))
    }

    /// A `CaptureLoop` with a scripted enumeration source and a warm cache seeded from the same
    /// initial table. Every new test starts from here so no test path can escape to a real OS
    /// enumeration.
    fn scripted(
        initial: Vec<MonitorEntry>,
        next: Box<dyn FnMut() -> Vec<MonitorEntry> + Send>,
    ) -> CaptureLoop {
        let mut c = CaptureLoop::new();
        c.table = initial;
        c.table_read = Some(Instant::now());
        c.enumerate_override = Some(next);
        c
    }

    #[test]
    fn guard_refuses_unknown_id_when_enumeration_is_nonempty() {
        // The core of the review: a stale/removed id must NOT reach a backend that would then
        // serve some other display under the requested label. Cache is nonempty; the forced
        // re-read on the unknown id also returns nonempty (same scripted table), so the guard
        // sees table_nonempty=true and refuses without dispatch.
        let mut c = scripted(
            vec![entry(0, 0, 1920, 1080)],
            Box::new(|| vec![entry(0, 0, 1920, 1080)]),
        );

        let mut calls = 0u32;
        let out = c.capture_with(7, |_this, _id, _target| {
            calls += 1;
            Some(("fake", fake_frame(7, 1, 1)))
        });

        assert!(out.is_none(), "guard returned before any backend was consulted");
        assert_eq!(calls, 0, "no dispatch on an unknown id when enumeration is nonempty");
        assert_eq!(c.last_produced_for, None, "nothing produced, nothing to remember");
    }

    #[test]
    fn guard_preserves_empty_enumeration_fallback() {
        // The one path that legitimately dispatches with `None`: no enumerable displays at all
        // (headless / session 0). The legacy backend-INDEX fallback must still run.
        let mut c = scripted(vec![], Box::new(Vec::new));

        let mut seen: Option<(u32, Option<Target>)> = None;
        let out = c.capture_with(0, |_this, id, target| {
            seen = Some((id, target));
            Some(("fake", fake_frame(id, 1, 1)))
        });

        assert!(out.is_some(), "empty-enumeration path still dispatches");
        assert_eq!(seen, Some((0, None)), "backend saw no resolved rect — legacy index route");
    }

    #[test]
    fn guard_dispatches_valid_target_with_asymmetric_geometry() {
        // Positive control: a valid id reaches the backend with the RIGHT rect. Asymmetric on
        // purpose (different origin AND different size) so a swapped-axis or constant-rect
        // mutation cannot pass.
        let mut c = scripted(
            vec![entry(0, 0, 1920, 1080), entry(1920, -120, 2560, 1440)],
            forbid_enumeration(), // id 1 is in-range, no re-read expected
        );

        let want = Target { id: 1, left: 1920, top: -120, width: 2560, height: 1440 };
        let mut seen: Option<(u32, Option<Target>)> = None;
        let out = c.capture_with(1, |_this, id, target| {
            seen = Some((id, target));
            Some(("fake", fake_frame(id, 2560, 1440)))
        });

        assert!(out.is_some());
        assert_eq!(seen, Some((1, Some(want))));
        assert_eq!(c.last_produced_for, Some(1));
    }

    #[test]
    fn guard_refuses_after_a_valid_capture_when_the_display_is_removed() {
        // The full mid-session removal story: capture id 1 successfully first, then unplug that
        // panel, invalidate the cache deterministically, and prove the second capture is refused
        // by the guard rather than substituted onto the surviving display.
        let mut c = scripted(
            vec![entry(0, 0, 1920, 1080), entry(1920, 0, 1920, 1080)],
            forbid_enumeration(), // first capture: id 1 in-range, no re-read
        );

        let mut first_seen: Option<(u32, Option<Target>)> = None;
        let out1 = c.capture_with(1, |_this, id, target| {
            first_seen = Some((id, target));
            Some(("fake", fake_frame(id, 1920, 1080)))
        });
        assert!(out1.is_some(), "id 1 captured while both displays were present");
        assert_eq!(
            first_seen,
            Some((1, Some(Target { id: 1, left: 1920, top: 0, width: 1920, height: 1080 })))
        );

        // Monitor unplugged. Swap the scripted enumeration and force the cache stale so the next
        // resolve reads the refreshed one-entry table deterministically.
        c.enumerate_override = Some(Box::new(|| vec![entry(0, 0, 1920, 1080)]));
        c.table_read = None;

        let mut calls = 0u32;
        let out2 = c.capture_with(1, |_this, _id, _target| {
            calls += 1;
            Some(("fake", fake_frame(1, 1, 1)))
        });
        assert!(out2.is_none(), "removed display refused by the guard");
        assert_eq!(calls, 0, "no substitution onto the surviving panel");
        assert_eq!(c.table.len(), 1, "FINAL snapshot is the one-entry table");
    }

    #[test]
    fn guard_refuses_a_degenerate_zero_size_entry() {
        // A detached / zero-area entry resolves to None with the table nonempty. Guard refuses
        // rather than let the backend attempt a 0x0 blit under the requested id.
        let mut c = scripted(
            vec![entry(0, 0, 0, 0)],
            forbid_enumeration(), // id 0 in-range, no re-read
        );

        let mut calls = 0u32;
        let out = c.capture_with(0, |_this, _id, _target| {
            calls += 1;
            Some(("fake", fake_frame(0, 1, 1)))
        });

        assert!(out.is_none());
        assert_eq!(calls, 0);
    }

    #[test]
    fn guard_finds_a_newly_added_id_after_the_forced_reread() {
        // Hotplug: cached table has one entry; the id past the end forces a fresh enumeration
        // that has two. The FINAL snapshot answers the resolve, and dispatch sees the new rect —
        // proving the guard reads the post-refresh table, not the stale one.
        let mut c = scripted(
            vec![entry(0, 0, 1920, 1080)],
            Box::new(|| vec![entry(0, 0, 1920, 1080), entry(1920, 0, 2560, 1440)]),
        );

        let want = Target { id: 1, left: 1920, top: 0, width: 2560, height: 1440 };
        let mut seen: Option<(u32, Option<Target>)> = None;
        let out = c.capture_with(1, |_this, id, target| {
            seen = Some((id, target));
            Some(("fake", fake_frame(id, 2560, 1440)))
        });

        assert!(out.is_some());
        assert_eq!(seen, Some((1, Some(want))));
    }

    #[test]
    fn cached_empty_then_refreshed_nonempty_but_id_still_missing_refuses() {
        // Transition: the CACHED snapshot is empty (which alone would take the legacy fallback),
        // but the forced re-read for an unknown id yields a nonempty table that STILL does not
        // contain the requested id. The guard must read the post-refresh table and refuse.
        let mut c = scripted(vec![], Box::new(|| vec![entry(0, 0, 1920, 1080)]));

        let mut calls = 0u32;
        let out = c.capture_with(5, |_this, _id, _target| {
            calls += 1;
            Some(("fake", fake_frame(5, 1, 1)))
        });

        assert!(out.is_none(), "refresh brought a table that does not know id 5 — refuse");
        assert_eq!(calls, 0);
        assert_eq!(c.table.len(), 1, "the guard's decision used the REFRESHED snapshot");
    }

    #[test]
    fn cached_nonempty_then_refreshed_empty_preserves_fallback() {
        // Transition the other way: the cached snapshot has entries, but the forced re-read
        // (triggered by an out-of-range id) returns an empty enumeration. That is now a genuine
        // no-enumeration state — the legacy backend-INDEX fallback must still run.
        let mut c = scripted(vec![entry(0, 0, 1920, 1080)], Box::new(Vec::new));

        let mut seen: Option<(u32, Option<Target>)> = None;
        let out = c.capture_with(9, |_this, id, target| {
            seen = Some((id, target));
            Some(("fake", fake_frame(id, 1, 1)))
        });

        assert!(out.is_some(), "refresh reports no enumeration — legacy fallback preserved");
        assert_eq!(seen, Some((9, None)));
        assert!(c.table.is_empty(), "FINAL snapshot is the empty refreshed table");
    }

    #[test]
    fn invalidate_drops_the_desktop_bound_state() {
        let mut c = loop_with_table(vec![entry(0, 0, 1920, 1080)]);
        c.dxgi_output = Some(((0, 0, 1920, 1080), 0));
        c.invalidate();
        assert!(c.dxgi_output.is_none(), "a desktop switch re-resolves the DXGI output");
        assert!(c.table_read.is_none(), "a desktop switch re-reads the monitor table");
    }
}
