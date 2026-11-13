//! The composite ("canvas") picture built from persistent per-output DXGI duplications — the logic
//! of docs/52, independent of Direct3D so every rule is unit-testable.
//!
//! The canvas is the whole virtual-desktop rect (the same rect the GDI composite blits). Each GDI
//! monitor is one [`Region`] of it, served either by a DXGI duplication of the output with exactly that
//! rect ([`DdaSource`], created by a [`DdaFactory`]) or by GDI ([`GdiReader`]). The rules, with the
//! design section that fixes each:
//!
//! - **Seeding (§4.2).** A duplication's first acquire is blank, so a region is filled by one
//!   SUCCESSFUL GDI read before anything is published; until then it is invalid.
//! - **No news (§4.3).** Nothing new from any region and no GDI region → [`CanvasOutcome::NoNews`].
//! - **Self-check (§4.5).** Every [`CHECK_INTERVAL`], every DDA region is validated against GDI over
//!   all its pixels (RGB), never against the presented canvas, and whether or not the screen is
//!   moving. If a first GDI read equals DDA's own image (`dda_image`), the region is valid. Otherwise
//!   DDA gets up to [`CHECK_GRACE_MS`] to deliver the frame it may be behind on, and GDI is read a
//!   SECOND time: a pixel that differs between the two GDI reads is genuinely moving and cannot be
//!   judged by value; every STABLE pixel must equal DDA's image. A stable pixel that does not is a
//!   fault (a frozen area beside motion, a stale or black image, alternating wrong images over a
//!   stable screen); so is a duplication that is NOT changing where the screen is moving (most moving
//!   pixels unchanged in DDA's image since the last check: frozen, or the same black image repeated,
//!   over video). Every PASSED check synchronises the whole presented region with what it validated:
//!   stable pixels with their validated value, moving pixels (whose DDA value can never be confirmed)
//!   with the newest GDI read. A live duplication overwrites moving pixels with its next frame anyway;
//!   one frozen on a subset of a moving area is repaired every check (stale for at most
//!   [`CHECK_INTERVAL`]); and no earlier repair can outlive a check. Leaving quarantine needs a check
//!   with no moving pixels: the canvas is repaired from GDI at once and the region QUARANTINED (presented
//!   from GDI, DDA only validated) until a check passes; [`DEMOTE_AFTER`] consecutive faults make it a
//!   GDI region. Leaving quarantine copies DDA's complete validated image into the canvas.
//!   (Measured on a real desktop: comparing one GDI read with an older DDA image while the screen kept
//!   changing struck a healthy duplication by TIMING; the second read is what separates motion from
//!   a fault without letting motion elsewhere exempt anything.)
//! - **Health (§4.2).** A region is publishable only while valid AND confirmed current within
//!   [`HEALTH_WINDOW`] — by a passed check (DDA regions) or a successful GDI presentation (GDI and
//!   quarantined regions), never by DDA activity alone; a call that cannot publish asks the caller for a whole-desktop GDI frame
//!   ([`CanvasOutcome::Fallback`]); [`DEMOTE_CANVAS_AFTER`] of continuous fallback demotes the canvas.
//! - **Loss (§4.4).** `AccessLost` drops one duplication (recreated and re-seeded next call); a device
//!   loss drops every duplication on that adapter; [`MAX_RECREATE_FAILURES`] failed creations in a row
//!   make a region GDI.

use std::time::{Duration, Instant};

/// How often every DDA region is checked against a GDI read (§4.5).
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(2);
/// After a first-read mismatch, how long DDA gets to deliver the frame it may be behind on (a few
/// presents at 60 Hz) before the second GDI read.
pub(crate) const CHECK_GRACE_MS: u32 = 50;
/// Consecutive self-check mismatches that turn a DDA region into a GDI region (§4.5).
pub(crate) const DEMOTE_AFTER: u32 = 3;
/// A region not confirmed current for this long makes the canvas unpublishable (§4.2).
pub(crate) const HEALTH_WINDOW: Duration = Duration::from_secs(5);
/// Continuous unpublishable time after which the canvas gives up (§4.2).
pub(crate) const DEMOTE_CANVAS_AFTER: Duration = Duration::from_secs(5);
/// Failed duplication creations in a row that turn a region into a GDI region (§4.2).
pub(crate) const MAX_RECREATE_FAILURES: u32 = 3;

/// A rectangle in virtual-desktop coordinates (physical pixels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    fn bytes(&self) -> usize {
        self.w as usize * self.h as usize * 4
    }
}

/// Why a DDA acquire failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DdaError {
    /// The duplication is gone (desktop switch, mode change, full-screen app): recreate it.
    AccessLost,
    /// The adapter's device was removed or reset: every duplication on it must be rebuilt.
    DeviceLost,
    /// Anything else: treated like `AccessLost`, and counted.
    Other,
}

/// Why a duplication could not be created for a region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DdaCreateError {
    /// This region can never be DDA (no output with this exact rect, rotated, wrong size or format):
    /// it becomes a GDI region for good.
    Unsupported(String),
    /// A transient failure; retried, and counted toward [`MAX_RECREATE_FAILURES`].
    Failed(String),
}

/// One region's live duplication.
pub(crate) trait DdaSource {
    /// Non-blocking acquire into `image`, which holds the region's PREVIOUS image (tightly packed BGRA,
    /// exactly the region's size): only the areas that changed are rewritten, and returned as
    /// region-local rects (a whole-region rect when the change is not described more finely).
    /// `Ok(None)`: nothing new (including the blank first frame). `timeout_ms` 0 never waits.
    fn acquire(&mut self, image: &mut [u8], timeout_ms: u32) -> Result<Option<Vec<Rect>>, DdaError>;
}

/// Creates duplications; one adapter's device is shared by its outputs.
pub(crate) trait DdaFactory {
    /// A duplication for the output whose desktop rect is exactly `rect`, with the adapter it lives on.
    fn create(&mut self, rect: Rect) -> Result<(Box<dyn DdaSource>, u64), DdaCreateError>;
    /// The adapter's device was lost: rebuild it on the next `create`.
    fn reset_adapter(&mut self, adapter: u64);
}

/// Reads a virtual-desktop rect with GDI into a tightly packed BGRA buffer of the rect's size.
pub(crate) trait GdiReader {
    fn read(&mut self, rect: Rect, out: &mut [u8]) -> bool;
}

/// What one canvas capture produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CanvasOutcome {
    /// A complete, current picture of the whole canvas.
    Frame(Vec<u8>),
    /// Nothing changed since the last frame (and no join is pending).
    NoNews,
    /// The canvas cannot publish this call; the caller publishes a whole-desktop GDI frame instead.
    Fallback(&'static str),
    /// Unpublishable for [`DEMOTE_CANVAS_AFTER`]: the caller drops the canvas and uses GDI.
    Demoted(&'static str),
}

enum Source {
    Dxgi {
        dupl: Option<(Box<dyn DdaSource>, u64)>,
        /// The region as DDA last delivered it, or as seeded. Never written by a repair.
        dda_image: Vec<u8>,
        /// `dda_image` as it was at the last completed check: where the screen is moving, a live
        /// duplication must have changed since then.
        dda_at_check: Vec<u8>,
        quarantined: bool,
        strikes: u32,
        recreate_failures: u32,
    },
    Gdi { reason: String },
}

struct Region {
    rect: Rect,
    /// When this region's next self-check is due (it runs at the first QUIET call at or after it).
    check_due: Option<Instant>,
    /// Byte offset of the region's top-left in the canvas.
    offset: usize,
    valid: bool,
    last_good: Option<Instant>,
    source: Source,
}

/// Per-capture counters, for telemetry and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanvasCounters {
    pub dda_frames: u64,
    pub gdi_reads: u64,
    pub gdi_failures: u64,
    pub checks: u64,
    pub mismatches: u64,
    pub demotions: u64,
    pub recreates: u64,
}

/// The canvas (see the module docs).
pub(crate) struct DxgiCanvas<F: DdaFactory, G: GdiReader> {
    origin: (i32, i32),
    width: u32,
    height: u32,
    pixels: Vec<u8>,
    regions: Vec<Region>,
    factory: F,
    gdi: G,
    changed: bool,
    unpublishable_since: Option<Instant>,
    scratch: Vec<u8>,
    pub(crate) counters: CanvasCounters,
}

impl<F: DdaFactory, G: GdiReader> DxgiCanvas<F, G> {
    /// Build the canvas for `monitors` (the CHECKED GDI enumeration) inside `vrect`. `None` when no
    /// region can be DDA (the caller keeps the GDI composite) or a monitor lies outside `vrect`.
    pub(crate) fn new(vrect: Rect, monitors: &[Rect], mut factory: F, gdi: G) -> Option<Self> {
        if monitors.is_empty() || vrect.w == 0 || vrect.h == 0 {
            return None;
        }
        let stride = vrect.w as usize * 4;
        let mut regions = Vec::with_capacity(monitors.len());
        for &m in monitors {
            let (dx, dy) = (i64::from(m.x) - i64::from(vrect.x), i64::from(m.y) - i64::from(vrect.y));
            if dx < 0 || dy < 0 || dx + i64::from(m.w) > i64::from(vrect.w) || dy + i64::from(m.h) > i64::from(vrect.h) || m.w == 0 || m.h == 0 {
                return None;
            }
            let source = match factory.create(m) {
                Ok(d) => Source::Dxgi { dupl: Some(d), dda_image: vec![0; m.bytes()], dda_at_check: vec![0; m.bytes()], quarantined: false, strikes: 0, recreate_failures: 0 },
                Err(DdaCreateError::Unsupported(r)) => Source::Gdi { reason: r },
                Err(DdaCreateError::Failed(_)) => Source::Dxgi { dupl: None, dda_image: vec![0; m.bytes()], dda_at_check: vec![0; m.bytes()], quarantined: false, strikes: 0, recreate_failures: 1 },
            };
            regions.push(Region { rect: m, check_due: None, offset: dy as usize * stride + dx as usize * 4, valid: false, last_good: None, source });
        }
        if !regions.iter().any(|r| matches!(r.source, Source::Dxgi { .. })) {
            return None;
        }
        Some(Self {
            origin: (vrect.x, vrect.y),
            width: vrect.w,
            height: vrect.h,
            pixels: vec![0; vrect.w as usize * vrect.h as usize * 4],
            regions,
            factory,
            gdi,
            changed: false,
            unpublishable_since: None,
            scratch: Vec::new(),
            counters: CanvasCounters::default(),
        })
    }

    /// Canvas size in pixels.
    pub(crate) fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The canvas's virtual-desktop origin.
    pub(crate) fn origin(&self) -> (i32, i32) {
        self.origin
    }

    /// How each region is currently served, for telemetry: `dxgi`, `dxgi-quarantined`, `gdi(<why>)`.
    pub(crate) fn sources(&self) -> Vec<String> {
        self.regions
            .iter()
            .map(|r| match &r.source {
                Source::Dxgi { quarantined: true, .. } => "dxgi-quarantined".to_string(),
                Source::Dxgi { .. } => "dxgi".to_string(),
                Source::Gdi { reason } => format!("gdi({reason})"),
            })
            .collect()
    }

    /// One capture (see the module docs). `force`: publish a complete frame even if nothing changed.
    pub(crate) fn capture(&mut self, force: bool, now: Instant) -> CanvasOutcome {
        let stride = self.width as usize * 4;
        for i in 0..self.regions.len() {
            self.ensure_duplication(i);
            self.dda_region(i, stride, now);
        }
        for i in 0..self.regions.len() {
            let gdi_presented = match &self.regions[i].source {
                Source::Gdi { .. } => true,
                Source::Dxgi { quarantined, dupl, .. } => *quarantined || dupl.is_none(),
            };
            if gdi_presented {
                self.gdi_into_canvas(i, stride, now);
            }
        }
        self.self_check(stride, now);

        let publishable = self
            .regions
            .iter()
            .all(|r| r.valid && r.last_good.is_some_and(|t| now.saturating_duration_since(t) < HEALTH_WINDOW));
        if !publishable {
            let since = *self.unpublishable_since.get_or_insert(now);
            let why = if self.regions.iter().any(|r| !r.valid) { "a region has no valid picture" } else { "a region is not confirmed current" };
            if now.saturating_duration_since(since) >= DEMOTE_CANVAS_AFTER {
                return CanvasOutcome::Demoted(why);
            }
            return CanvasOutcome::Fallback(why);
        }
        self.unpublishable_since = None;
        if force || self.changed {
            self.changed = false;
            return CanvasOutcome::Frame(self.pixels.clone());
        }
        CanvasOutcome::NoNews
    }

    fn ensure_duplication(&mut self, i: usize) {
        let rect = self.regions[i].rect;
        let Source::Dxgi { dupl, recreate_failures, .. } = &mut self.regions[i].source else { return };
        if dupl.is_some() {
            return;
        }
        self.counters.recreates += 1;
        match self.factory.create(rect) {
            Ok(d) => {
                *dupl = Some(d);
                *recreate_failures = 0;
                // A new duplication starts blank: the region must be re-seeded before it publishes.
                self.regions[i].valid = false;
            }
            Err(DdaCreateError::Unsupported(r)) => self.regions[i].source = Source::Gdi { reason: r },
            Err(DdaCreateError::Failed(r)) => {
                *recreate_failures += 1;
                if *recreate_failures >= MAX_RECREATE_FAILURES {
                    tracing::warn!(?rect, error = %r, "canvas: duplication keeps failing; region served by GDI");
                    self.counters.demotions += 1;
                    self.regions[i].source = Source::Gdi { reason: format!("create failed: {r}") };
                }
            }
        }
    }

    fn dda_region(&mut self, i: usize, stride: usize, now: Instant) {
        let rect = self.regions[i].rect;
        let offset = self.regions[i].offset;
        // Seed an invalid region with a successful GDI read before trusting DDA for it.
        let needs_seed = !self.regions[i].valid
            && matches!(&self.regions[i].source, Source::Dxgi { dupl: Some(_), quarantined: false, .. });
        if needs_seed {
            self.scratch.resize(rect.bytes(), 0);
            self.counters.gdi_reads += 1;
            if self.gdi.read(rect, &mut self.scratch) {
                blit(&mut self.pixels, stride, offset, rect, &self.scratch);
                if let Source::Dxgi { dda_image, dda_at_check, .. } = &mut self.regions[i].source {
                    dda_image.copy_from_slice(&self.scratch);
                    dda_at_check.copy_from_slice(&self.scratch);
                }
                let r = &mut self.regions[i];
                r.valid = true;
                r.last_good = Some(now);
                self.changed = true;
            } else {
                self.counters.gdi_failures += 1;
                return;
            }
        }
        let Source::Dxgi { dupl: Some((src, _)), dda_image, quarantined, .. } = &mut self.regions[i].source else { return };
        // The source rewrites only the changed areas of dda_image (dirty and moved rects).
        match src.acquire(dda_image, 0) {
            Ok(None) => {}
            Ok(Some(rects)) => {
                self.counters.dda_frames += 1;
                if !*quarantined {
                    for r in &rects {
                        blit_rect(&mut self.pixels, stride, offset, rect.w, dda_image, *r);
                    }
                    self.changed = true;
                }
            }
            Err(e) => self.dda_failed(i, e),
        }
    }

    /// A DDA acquire failed (regular or grace): drop the duplication (re-seeded on recreation); on
    /// device loss drop EVERY duplication on that adapter and have the factory rebuild its device.
    fn dda_failed(&mut self, i: usize, e: DdaError) {
        let Source::Dxgi { dupl, recreate_failures, .. } = &mut self.regions[i].source else { return };
        let adapter = dupl.as_ref().map(|(_, a)| *a);
        if e == DdaError::DeviceLost {
            if let Some(adapter) = adapter {
                for r in &mut self.regions {
                    if let Source::Dxgi { dupl, .. } = &mut r.source {
                        if dupl.as_ref().is_some_and(|(_, a)| *a == adapter) {
                            *dupl = None;
                            r.valid = false;
                        }
                    }
                }
                self.factory.reset_adapter(adapter);
            }
            return;
        }
        *dupl = None;
        if e == DdaError::Other {
            *recreate_failures += 1;
        }
        self.regions[i].valid = false;
    }

    fn gdi_into_canvas(&mut self, i: usize, stride: usize, now: Instant) {
        let rect = self.regions[i].rect;
        self.scratch.resize(rect.bytes(), 0);
        self.counters.gdi_reads += 1;
        if self.gdi.read(rect, &mut self.scratch) {
            blit(&mut self.pixels, stride, self.regions[i].offset, rect, &self.scratch);
            let r = &mut self.regions[i];
            r.valid = true;
            r.last_good = Some(now);
            self.changed = true;
        } else {
            // Keep the last pixels; health (last_good) is NOT refreshed, so a region that keeps failing
            // makes the canvas unpublishable within HEALTH_WINDOW.
            self.counters.gdi_failures += 1;
        }
    }

    fn self_check(&mut self, stride: usize, now: Instant) {
        for i in 0..self.regions.len() {
            let rect = self.regions[i].rect;
            if !matches!(&self.regions[i].source, Source::Dxgi { dupl: Some(_), .. }) || !self.regions[i].valid {
                continue;
            }
            if self.regions[i].check_due.is_some_and(|t| now < t) {
                continue;
            }
            self.regions[i].check_due = Some(now + CHECK_INTERVAL);
            self.counters.checks += 1;
            // First read.
            self.scratch.resize(rect.bytes(), 0);
            self.counters.gdi_reads += 1;
            if !self.gdi.read(rect, &mut self.scratch) {
                self.counters.gdi_failures += 1;
                continue; // a failed check refreshes nothing
            }
            let offset = self.regions[i].offset;
            let mut second = Vec::new();
            let verdict = {
                let Source::Dxgi { dupl: Some((src, _)), dda_image, .. } = &mut self.regions[i].source else { continue };
                if same_rgb(dda_image, &self.scratch) {
                    Verdict::Pass { moving: 0 }
                } else {
                    // Grace: DDA may be a few presents behind. Then a second GDI read separates
                    // genuinely moving pixels (they differ between the reads) from stable ones, which
                    // must equal DDA's image.
                    let grace = src.acquire(dda_image, CHECK_GRACE_MS);
                    second.resize(rect.bytes(), 0);
                    self.counters.gdi_reads += 1;
                    let second_ok = self.gdi.read(rect, &mut second);
                    match grace {
                        Err(e) => {
                            self.dda_failed(i, e);
                            continue;
                        }
                        Ok(Some(rects)) => {
                            self.counters.dda_frames += 1;
                            let Source::Dxgi { dda_image, quarantined, .. } = &self.regions[i].source else { continue };
                            if !*quarantined {
                                for r in &rects {
                                    blit_rect(&mut self.pixels, stride, offset, rect.w, dda_image, *r);
                                }
                                self.changed = true;
                            }
                        }
                        Ok(None) => {}
                    }
                    if !second_ok {
                        self.counters.gdi_failures += 1;
                        continue;
                    }
                    let Source::Dxgi { dda_image, dda_at_check, .. } = &self.regions[i].source else { continue };
                    judge(&self.scratch, &second, dda_image, dda_at_check)
                }
            };
            let Source::Dxgi { dda_image, dda_at_check, quarantined, strikes, .. } = &mut self.regions[i].source else { continue };
            dda_at_check.copy_from_slice(dda_image);
            if let Verdict::Pass { moving } = verdict {
                *strikes = 0;
                // Leave quarantine only on a FULL validation (nothing moving).
                if *quarantined && moving == 0 {
                    *quarantined = false;
                }
                // Synchronise the WHOLE presented region with what this check validated: on the fast
                // path DDA's image (it equalled the screen); otherwise the second GDI read, which
                // equals DDA's image on every stable pixel and is the newest value of every moving
                // one. No earlier repair or stale pixel survives a passed check, and the region's
                // health is refreshed only with these pixels actually in the canvas.
                let validated: &[u8] = if second.is_empty() { dda_image } else { &second };
                if sync_region(&mut self.pixels, stride, offset, rect, validated) {
                    self.changed = true;
                }
                self.regions[i].last_good = Some(now);
                continue;
            }
            if !matches!(verdict, Verdict::Fault) {
                continue;
            }
            self.counters.mismatches += 1;
            *strikes += 1;
            *quarantined = true;
            let demote = *strikes >= DEMOTE_AFTER;
            // Re-validate at the next call rather than CHECK_INTERVAL later: a stuck duplication is
            // demoted sooner, and a one-off is lifted sooner.
            self.regions[i].check_due = Some(now);
            // Repair the PICTURE now with the newest screen read, whatever the cause; dda_image keeps
            // what DDA delivered. This presentation is a successful GDI read: the region is current.
            let newest = if second.is_empty() { &self.scratch } else { &second };
            blit(&mut self.pixels, stride, offset, rect, newest);
            self.changed = true;
            self.regions[i].last_good = Some(now);
            if demote {
                tracing::warn!(?rect, "canvas: duplication disagrees with the screen on {DEMOTE_AFTER} checks in a row; region served by GDI");
                self.counters.demotions += 1;
                self.regions[i].source = Source::Gdi { reason: "self-check".into() };
            }
        }
    }
}

/// Make the canvas region equal `src` (colour), copying only rows that differ. Returns whether
/// anything changed (so an idle, already-correct region still reports "no news").
fn sync_region(canvas: &mut [u8], stride: usize, offset: usize, rect: Rect, src: &[u8]) -> bool {
    let row = rect.w as usize * 4;
    let mut changed = false;
    for y in 0..rect.h as usize {
        let d = offset + y * stride;
        let s = &src[y * row..(y + 1) * row];
        if !same_rgb(&canvas[d..d + row], s) {
            canvas[d..d + row].copy_from_slice(s);
            changed = true;
        }
    }
    changed
}

/// A check's outcome for one region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// No fault. `moving` pixels changed between the two screen reads: DDA was changing there, but
    /// their values were not confirmed (so quarantine is not lifted on this verdict).
    Pass { moving: usize },
    Fault,
}

/// Judge DDA's image against two screen reads (`first`, `second`): every pixel STABLE across the reads
/// must equal DDA's image; and where the screen is MOVING, a live duplication must have changed since
/// the last check (`dda_at_check`) — most moving pixels unchanged there means frozen (no new frames,
/// or the same black image repeated) over motion. Colour only.
fn judge(first: &[u8], second: &[u8], dda: &[u8], dda_at_check: &[u8]) -> Verdict {
    let (mut moving, mut stale) = (0usize, 0usize);
    for (((a, b), d), old) in first.chunks_exact(4).zip(second.chunks_exact(4)).zip(dda.chunks_exact(4)).zip(dda_at_check.chunks_exact(4)) {
        if a[..3] == b[..3] {
            if b[..3] != d[..3] {
                return Verdict::Fault;
            }
        } else {
            moving += 1;
            if d[..3] == old[..3] {
                stale += 1;
            }
        }
    }
    if moving > 0 && stale * 2 > moving {
        return Verdict::Fault;
    }
    Verdict::Pass { moving }
}

/// Copy a tightly packed `rect`-sized BGRA image into the canvas at `offset` (canvas `stride`).
fn blit(canvas: &mut [u8], stride: usize, offset: usize, rect: Rect, src: &[u8]) {
    let row = rect.w as usize * 4;
    for y in 0..rect.h as usize {
        let d = offset + y * stride;
        canvas[d..d + row].copy_from_slice(&src[y * row..(y + 1) * row]);
    }
}

/// Copy the region-local rect `r` of a region image (`region_w` wide) into the canvas.
fn blit_rect(canvas: &mut [u8], stride: usize, offset: usize, region_w: u32, src: &[u8], r: Rect) {
    let src_stride = region_w as usize * 4;
    let (x, w) = (r.x.max(0) as usize * 4, r.w as usize * 4);
    for y in r.y.max(0) as usize..(r.y.max(0) as usize + r.h as usize) {
        let s = y * src_stride + x;
        let d = offset + y * stride + x;
        if s + w > src.len() || d + w > canvas.len() {
            break;
        }
        canvas[d..d + w].copy_from_slice(&src[s..s + w]);
    }
}

/// Whether two region images (`region_w` wide) match in colour inside the region-local rect `r`.
fn same_rgb_rect(a: &[u8], b: &[u8], region_w: u32, r: Rect) -> bool {
    let stride = region_w as usize * 4;
    let (x, w) = (r.x.max(0) as usize * 4, r.w as usize * 4);
    (r.y.max(0) as usize..r.y.max(0) as usize + r.h as usize).all(|y| {
        let o = y * stride + x;
        o + w <= a.len() && o + w <= b.len() && same_rgb(&a[o..o + w], &b[o..o + w])
    })
}

/// Whether two BGRA images match in every pixel's colour (alpha ignored).
fn same_rgb(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.chunks_exact(4).zip(b.chunks_exact(4)).all(|(p, q)| p[..3] == q[..3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::rc::Rc;

    /// One queued DDA delivery: per-pixel values for the region, optionally limited to a sub-rect.
    type Delivery = Result<Option<(Vec<u8>, Option<Rect>)>, DdaError>;

    /// The fake machine. Regions are keyed by their x. One byte per pixel stands for its colour.
    #[derive(Default)]
    struct World {
        sizes: HashMap<i32, (u32, u32)>,
        /// The real screen, per pixel.
        screen: HashMap<i32, Vec<u8>>,
        /// Pixels that change on EVERY GDI read (genuine motion between two reads).
        moving: HashMap<i32, HashSet<usize>>,
        /// Queued DDA deliveries per region (regular and grace acquires both pop from here).
        dda: HashMap<i32, VecDeque<Delivery>>,
        gdi_fails: HashSet<i32>,
        /// Fail exactly this many upcoming GDI reads of a region, then succeed.
        gdi_fail_next: HashMap<i32, u32>,
        create: HashMap<i32, VecDeque<Result<u64, DdaCreateError>>>,
        created: u32,
        resets: Vec<u64>,
    }
    type W = Rc<RefCell<World>>;

    struct FakeDda { x: i32, w: u32, h: u32, world: W }
    impl DdaSource for FakeDda {
        fn acquire(&mut self, image: &mut [u8], _timeout_ms: u32) -> Result<Option<Vec<Rect>>, DdaError> {
            let next = self.world.borrow_mut().dda.get_mut(&self.x).and_then(|q| q.pop_front()).unwrap_or(Ok(None));
            let Some((vals, sub)) = next? else { return Ok(None) };
            let r = sub.unwrap_or(Rect { x: 0, y: 0, w: self.w, h: self.h });
            for y in r.y as usize..(r.y as usize + r.h as usize) {
                for x in r.x as usize..(r.x as usize + r.w as usize) {
                    let k = y * self.w as usize + x;
                    image[k * 4..k * 4 + 3].fill(vals[k]);
                    image[k * 4 + 3] = 255;
                }
            }
            Ok(Some(vec![r]))
        }
    }
    struct FakeFactory(W);
    impl DdaFactory for FakeFactory {
        fn create(&mut self, rect: Rect) -> Result<(Box<dyn DdaSource>, u64), DdaCreateError> {
            let mut w = self.0.borrow_mut();
            w.created += 1;
            let r = w.create.get_mut(&rect.x).and_then(|q| q.pop_front()).unwrap_or(Ok(1));
            r.map(|adapter| (Box::new(FakeDda { x: rect.x, w: rect.w, h: rect.h, world: Rc::clone(&self.0) }) as Box<dyn DdaSource>, adapter))
        }
        fn reset_adapter(&mut self, adapter: u64) {
            self.0.borrow_mut().resets.push(adapter);
        }
    }
    struct FakeGdi(W);
    impl GdiReader for FakeGdi {
        fn read(&mut self, rect: Rect, out: &mut [u8]) -> bool {
            let mut w = self.0.borrow_mut();
            if w.gdi_fails.contains(&rect.x) {
                return false;
            }
            if let Some(n) = w.gdi_fail_next.get_mut(&rect.x) {
                if *n > 0 {
                    *n -= 1;
                    return false;
                }
            }
            let moving = w.moving.get(&rect.x).cloned().unwrap_or_default();
            let px = w.screen.get_mut(&rect.x).expect("screen");
            for (k, v) in px.iter_mut().enumerate() {
                out[k * 4..k * 4 + 3].fill(*v);
                out[k * 4 + 3] = 255;
                if moving.contains(&k) {
                    *v = v.wrapping_add(1);
                }
            }
            true
        }
    }

    const A: Rect = Rect { x: 0, y: 0, w: 2, h: 2 };
    const B: Rect = Rect { x: 2, y: 0, w: 2, h: 1 }; // shorter: a gap below it
    const V: Rect = Rect { x: 0, y: 0, w: 4, h: 2 };

    fn world(a: u8, b: u8) -> W {
        let w = W::default();
        {
            let mut m = w.borrow_mut();
            m.sizes.insert(0, (2, 2));
            m.sizes.insert(2, (2, 1));
            m.screen.insert(0, vec![a; 4]);
            m.screen.insert(2, vec![b; 2]);
        }
        w
    }
    fn canvas(world: &W) -> DxgiCanvas<FakeFactory, FakeGdi> {
        DxgiCanvas::new(V, &[A, B], FakeFactory(Rc::clone(world)), FakeGdi(Rc::clone(world))).expect("canvas")
    }
    /// Time passes: every moving pixel changes once (real motion is continuous, not only at reads).
    fn advance(w: &W) {
        let mut m = w.borrow_mut();
        let moving = m.moving.clone();
        for (x, set) in moving {
            if let Some(px) = m.screen.get_mut(&x) {
                for k in set {
                    px[k] = px[k].wrapping_add(1);
                }
            }
        }
    }
    fn screen(w: &W, x: i32, vals: &[u8]) {
        w.borrow_mut().screen.insert(x, vals.to_vec());
    }
    fn screen_all(w: &W, x: i32, v: u8) {
        let n = w.borrow().screen[&x].len();
        screen(w, x, &vec![v; n]);
    }
    /// Queue a full DDA image of uniform value `v` for region x.
    fn dda(w: &W, x: i32, v: u8) {
        let n = w.borrow().screen[&x].len();
        w.borrow_mut().dda.entry(x).or_default().push_back(Ok(Some((vec![v; n], None))));
    }
    fn dda_px(w: &W, x: i32, vals: &[u8]) {
        w.borrow_mut().dda.entry(x).or_default().push_back(Ok(Some((vals.to_vec(), None))));
    }
    fn dda_none(w: &W, x: i32) {
        w.borrow_mut().dda.entry(x).or_default().push_back(Ok(None));
    }
    fn dda_err(w: &W, x: i32, e: DdaError) {
        w.borrow_mut().dda.entry(x).or_default().push_back(Err(e));
    }
    /// Pixel (column, row) of a frame.
    fn px(f: &[u8], c: usize, r: usize) -> u8 {
        f[(r * 4 + c) * 4]
    }
    fn frame(o: CanvasOutcome) -> Vec<u8> {
        match o {
            CanvasOutcome::Frame(f) => f,
            other => panic!("expected a frame, got {other:?}"),
        }
    }
    fn ms(t: Instant, n: u64) -> Instant {
        t + Duration::from_millis(n)
    }

    #[test]
    fn regions_land_at_their_offsets_and_a_still_desktop_is_seeded_not_blank() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let f = frame(c.capture(false, Instant::now()));
        assert_eq!((px(&f, 0, 0), px(&f, 1, 1)), (10, 10), "region A seeded from GDI");
        assert_eq!(px(&f, 2, 0), 20, "region B at x=2");
        assert_eq!(px(&f, 3, 1), 0, "the gap below the shorter monitor stays black");
        assert_eq!(f.len(), 4 * 2 * 4);
    }

    #[test]
    fn nothing_new_is_no_news_and_force_publishes_anyway() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        assert_eq!(c.capture(false, ms(t, 30)), CanvasOutcome::NoNews);
        assert_eq!(px(&frame(c.capture(true, ms(t, 60))), 0, 0), 10, "a forced frame is the complete current picture");
    }

    #[test]
    fn a_dda_image_updates_its_region_only_and_a_partial_change_only_its_rect() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 11);
        dda(&w, 0, 11);
        let f = frame(c.capture(false, ms(t, 30)));
        assert_eq!((px(&f, 0, 0), px(&f, 2, 0)), (11, 20));
        screen(&w, 0, &[11, 11, 11, 66]);
        w.borrow_mut().dda.entry(0).or_default().push_back(Ok(Some((vec![0, 0, 0, 66], Some(Rect { x: 1, y: 1, w: 1, h: 1 })))));
        let f = frame(c.capture(false, ms(t, 60)));
        assert_eq!((px(&f, 0, 0), px(&f, 1, 0), px(&f, 0, 1), px(&f, 1, 1)), (11, 11, 11, 66));
    }

    #[test]
    fn a_failed_seed_publishes_nothing_of_that_region_and_recovers_when_gdi_does() {
        let w = world(10, 20);
        w.borrow_mut().gdi_fails.insert(0);
        let mut c = canvas(&w);
        let t = Instant::now();
        assert!(matches!(c.capture(false, t), CanvasOutcome::Fallback(_)), "never black-as-picture");
        w.borrow_mut().gdi_fails.clear();
        assert_eq!(px(&frame(c.capture(false, ms(t, 30))), 0, 0), 10);
    }

    #[test]
    fn a_region_that_cannot_be_confirmed_for_five_seconds_falls_back_then_demotes_the_canvas() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().gdi_fails.insert(0); // every check of A now fails
        let mut last = CanvasOutcome::NoNews;
        for s in 1..=12 {
            last = c.capture(false, t + Duration::from_secs(s));
            if s < 5 {
                assert!(!matches!(last, CanvasOutcome::Fallback(_) | CanvasOutcome::Demoted(_)), "healthy until 5 s: {s}");
            }
        }
        assert!(matches!(last, CanvasOutcome::Demoted(_)), "demoted after 5 s of fallback: {last:?}");
    }

    #[test]
    fn access_lost_without_a_desktop_switch_recreates_reseeds_and_recovers() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        dda_err(&w, 0, DdaError::AccessLost);
        screen_all(&w, 0, 12);
        assert_eq!(px(&frame(c.capture(false, ms(t, 30))), 0, 0), 12, "GDI serves the region the call it lost its duplication");
        let created = w.borrow().created;
        screen_all(&w, 0, 13);
        assert_eq!(px(&frame(c.capture(false, ms(t, 60))), 0, 0), 13, "re-seeded with the current screen");
        assert_eq!(w.borrow().created, created + 1, "recreated");
        assert_eq!(c.sources()[0], "dxgi", "back on DDA");
    }

    #[test]
    fn device_loss_rebuilds_every_duplication_on_that_adapter() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        let before = w.borrow().created;
        dda_err(&w, 0, DdaError::DeviceLost);
        let _ = c.capture(false, ms(t, 30));
        assert_eq!(w.borrow().resets, vec![1]);
        let _ = c.capture(false, ms(t, 60));
        assert_eq!(w.borrow().created - before, 2, "both regions on adapter 1 were recreated");
    }

    /// Review finding (implementation r1): a device loss reported FIRST by the check's grace acquire
    /// must get the same adapter-wide handling as one from a regular acquire.
    #[test]
    fn device_loss_during_the_grace_acquire_rebuilds_the_adapter() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 30); // a mismatch at the next check, so its grace acquire runs
        dda_none(&w, 0); // the regular acquire of that call
        dda_err(&w, 0, DdaError::DeviceLost); // the grace acquire
        let before = w.borrow().created;
        let _ = c.capture(false, t + CHECK_INTERVAL);
        assert_eq!(w.borrow().resets, vec![1], "the adapter was reset");
        let _ = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(30));
        assert_eq!(w.borrow().created - before, 2, "every duplication on that adapter was recreated");
        assert_eq!(c.sources(), vec!["dxgi".to_string(), "dxgi".to_string()], "nothing demoted");
    }

    #[test]
    fn creation_that_keeps_failing_makes_the_region_gdi() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        for _ in 0..3 {
            w.borrow_mut().create.entry(0).or_default().push_back(Err(DdaCreateError::Failed("busy".into())));
        }
        dda_err(&w, 0, DdaError::AccessLost);
        for k in 1..=4 {
            let _ = c.capture(false, ms(t, 30 * k));
        }
        assert!(c.sources()[0].starts_with("gdi("), "{:?}", c.sources());
    }

    #[test]
    fn an_unsupported_output_is_gdi_and_a_canvas_with_no_dda_region_is_not_built() {
        let w = world(10, 20);
        w.borrow_mut().create.entry(2).or_default().push_back(Err(DdaCreateError::Unsupported("indirect display".into())));
        let c = canvas(&w);
        assert_eq!(c.sources(), vec!["dxgi".to_string(), "gdi(indirect display)".to_string()]);
        let w2 = world(10, 20);
        for x in [0, 2] {
            w2.borrow_mut().create.entry(x).or_default().push_back(Err(DdaCreateError::Unsupported("rotated".into())));
        }
        assert!(DxgiCanvas::new(V, &[A, B], FakeFactory(Rc::clone(&w2)), FakeGdi(Rc::clone(&w2))).is_none());
    }

    /// DDA silently stops; the screen changes once: repaired and quarantined at the next check, and
    /// (re-checked every call) demoted within three checks.
    #[test]
    fn a_silent_duplication_is_repaired_at_once_and_demoted_within_three_checks() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 99);
        let f = frame(c.capture(false, t + CHECK_INTERVAL));
        assert_eq!(px(&f, 0, 0), 99, "repaired from GDI at the first check");
        assert_eq!(c.sources()[0], "dxgi-quarantined");
        let _ = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(30));
        let _ = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(60));
        assert_eq!(c.sources()[0], "gdi(self-check)", "demoted after {DEMOTE_AFTER} faults");
    }

    /// Review finding (implementation r1): a FROZEN area beside continuous motion must not be exempted
    /// by the motion. Pixel 0 moves and DDA delivers it live; pixel 3 changed on screen and DDA never
    /// shows it.
    #[test]
    fn a_frozen_area_beside_motion_is_caught() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().moving.insert(0, [0usize].into_iter().collect());
        screen(&w, 0, &[40, 10, 10, 77]); // pixel 3 changed and stays changed
        for k in 1..=40u64 {
            let p0 = w.borrow().screen[&0][0];
            dda_px(&w, 0, &[p0, 10, 10, 10]); // live for pixel 0, frozen at 10 for pixel 3
            let out = c.capture(false, t + Duration::from_millis(100 * k));
            if c.sources()[0] == "gdi(self-check)" {
                break;
            }
            if k > 20 {
                if let CanvasOutcome::Frame(f) = out {
                    assert_eq!(px(&f, 1, 1), 77, "the frozen pixel must have been repaired");
                }
            }
        }
        assert_eq!(c.sources()[0], "gdi(self-check)", "a frozen area beside motion must be demoted");
    }

    /// Review finding (implementation r1): DDA alternating between WRONG images over a stable screen
    /// is a fault, not motion.
    #[test]
    fn alternating_wrong_images_over_a_stable_screen_are_caught() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        for k in 1..=40u64 {
            dda(&w, 0, if k % 2 == 0 { 11 } else { 12 });
            let _ = c.capture(false, t + Duration::from_millis(100 * k));
        }
        assert_eq!(c.sources()[0], "gdi(self-check)");
    }

    /// Measured on a real desktop: a constantly changing screen made a healthy duplication look wrong
    /// by timing. Pixels that move between the check's two reads are not judged; a live duplication of
    /// a fully moving region is never struck, and stays publishable.
    #[test]
    fn genuine_motion_never_strikes_a_live_duplication() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().moving.insert(0, (0..4).collect());
        for k in 1..=300u64 {
            // DDA is one step BEHIND the moving screen, so every check's first read mismatches and
            // only the second read (the pixels moved again) shows it is motion, not a fault.
            advance(&w);
            let behind: Vec<u8> = w.borrow().screen[&0].iter().map(|v| v.wrapping_sub(1)).collect();
            dda_px(&w, 0, &behind);
            let out = c.capture(false, t + Duration::from_millis(33 * k));
            assert!(matches!(out, CanvasOutcome::Frame(_)), "call {k}: {out:?}");
        }
        assert_eq!(c.sources()[0], "dxgi");
        assert_eq!(c.counters.mismatches, 0);
    }

    /// At a check DDA can be a few presents behind; when the grace acquire delivers what the screen
    /// shows, the check passes.
    #[test]
    fn a_duplication_a_few_presents_behind_is_not_struck() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        for k in 1..=6u32 {
            let v = 10 + k as u8;
            screen_all(&w, 0, v);
            dda_none(&w, 0); // the regular acquire sees nothing yet...
            dda(&w, 0, v); // ...the grace acquire delivers it
            let _ = c.capture(false, t + CHECK_INTERVAL * k);
        }
        assert_eq!(c.sources()[0], "dxgi");
        assert_eq!(c.counters.mismatches, 0);
    }

    #[test]
    fn stale_images_after_a_repair_never_regress_the_picture() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // repaired to 50, quarantined
        for k in 1..=2 {
            dda(&w, 0, 10);
            if let CanvasOutcome::Frame(f) = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(30 * k)) {
                assert_eq!(px(&f, 0, 0), 50, "a published frame regressed to the stale image");
            }
        }
    }

    /// The quarantine guard matters when the GDI read presenting a quarantined region FAILS: a
    /// changing but wrong DDA image must not be published in its place.
    #[test]
    fn a_quarantined_region_never_shows_dda_even_when_its_gdi_read_fails() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // repaired to 50, quarantined
        w.borrow_mut().gdi_fails.insert(0);
        dda(&w, 0, 11);
        if let CanvasOutcome::Frame(f) = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(30)) {
            assert_eq!(px(&f, 0, 0), 50, "a quarantined region published a DDA image");
        }
    }

    /// Review finding (implementation r1): while quarantined, changing DDA images must NOT keep the
    /// region healthy when the GDI reads that present it keep failing.
    #[test]
    fn a_quarantined_region_whose_gdi_keeps_failing_is_not_kept_healthy_by_dda() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // quarantined
        w.borrow_mut().gdi_fails.insert(0);
        let mut last = CanvasOutcome::NoNews;
        for k in 1..=120u64 {
            dda(&w, 0, (k % 200) as u8 + 1); // changing images, every call
            last = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(100 * k));
        }
        assert!(matches!(last, CanvasOutcome::Demoted(_) | CanvasOutcome::Fallback(_)), "{last:?}");
    }

    /// Review finding (implementation r1): leaving quarantine copies DDA's complete validated image
    /// into the canvas. Here the presenting GDI read fails, the check's read succeeds and matches a
    /// newer DDA image, and then nothing changes: no stale repaired pixel may survive.
    #[test]
    fn leaving_quarantine_resyncs_the_whole_region_from_dda() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // repaired to 50, quarantined, re-check next call
        // Next call: DDA delivers the true current image (60); the presenting GDI read fails; the check
        // reads 60 = DDA → quarantine lifted.
        screen_all(&w, 0, 60);
        dda(&w, 0, 60);
        w.borrow_mut().gdi_fail_next.insert(0, 1);
        let _ = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(30));
        assert_eq!(c.sources()[0], "dxgi", "quarantine lifted");
        let f = frame(c.capture(true, t + CHECK_INTERVAL + Duration::from_millis(60)));
        for (col, row) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            assert_eq!(px(&f, col, row), 60, "pixel ({col},{row}) kept a stale repaired value");
        }
    }

    /// Implementation review r2: a FROZEN duplication over a fully moving screen (video) must be
    /// caught; excluding moving pixels from the value comparison must not exempt it.
    #[test]
    fn a_frozen_duplication_over_a_fully_moving_screen_is_caught() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().moving.insert(0, (0..4).collect()); // every pixel moves; DDA delivers nothing
        for k in 1..=40u64 {
            advance(&w);
            let _ = c.capture(false, t + Duration::from_millis(100 * k));
        }
        assert_eq!(c.sources()[0], "gdi(self-check)");
    }

    /// Implementation review r2: the same BLACK image delivered over and over while the screen moves.
    #[test]
    fn a_repeated_black_image_over_a_fully_moving_screen_is_caught() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().moving.insert(0, (0..4).collect());
        // The first black image IS a change (from the real picture), so the first check cannot call it
        // stale; the next one does: repaired within two checks, demoted right after.
        for k in 1..=60u64 {
            advance(&w);
            dda(&w, 0, 0);
            let _ = c.capture(false, t + Duration::from_millis(100 * k));
        }
        assert_eq!(c.sources()[0], "gdi(self-check)");
    }

    /// Implementation review r2: a quarantined region whose differing pixels all MOVE between the two
    /// reads must not leave quarantine (its DDA values were never confirmed), so a wrong DDA image is
    /// never republished; it leaves only on a full validation.
    #[test]
    fn quarantine_is_not_lifted_while_pixels_are_moving() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // quarantined
        w.borrow_mut().moving.insert(0, (0..4).collect());
        for k in 1..=30u64 {
            advance(&w);
            // DDA keeps changing, but delivers WRONG values (200+, never reached by the screen, which
            // stays below 200 in this test), never what the screen shows.
            dda(&w, 0, 200 + (k % 50) as u8);
            if let CanvasOutcome::Frame(f) = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(100 * k)) {
                assert!(px(&f, 0, 0) < 200, "a quarantined region republished a DDA value: {}", px(&f, 0, 0));
            }
            assert_ne!(c.sources()[0], "dxgi", "quarantine lifted while pixels were moving (call {k})");
        }
        // The screen stops and DDA delivers the true picture: a full validation lifts the quarantine.
        w.borrow_mut().moving.clear();
        let cur = w.borrow().screen[&0].clone();
        dda_px(&w, 0, &cur);
        for k in 31..=70u64 {
            let _ = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(100 * k));
        }
        assert_eq!(c.sources()[0], "dxgi", "a full validation lifts the quarantine");
    }

    /// Implementation review r3: a FROZEN MINORITY of moving pixels beside a live majority is repaired
    /// at every check (bounded staleness), whatever DDA does there.
    #[test]
    fn a_frozen_moving_minority_beside_live_motion_is_repaired_every_check() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        w.borrow_mut().moving.insert(0, (0..4).collect());
        let mut repaired_after_check = 0;
        for k in 1..=60u64 {
            advance(&w);
            // DDA is live on the top row only (pixels 0,1); the bottom row (pixels 2,3) stays frozen at 10.
            let cur = w.borrow().screen[&0].clone();
            w.borrow_mut().dda.entry(0).or_default().push_back(Ok(Some((cur.clone(), Some(Rect { x: 0, y: 0, w: 2, h: 1 })))));
            if let CanvasOutcome::Frame(f) = c.capture(false, t + Duration::from_millis(100 * k)) {
                if k >= 20 && px(&f, 0, 1) != 10 && px(&f, 1, 1) != 10 {
                    repaired_after_check += 1;
                }
                if k >= 21 {
                    assert_ne!(px(&f, 0, 1), 10, "a frozen moving pixel outlived a check (call {k})");
                }
            }
        }
        assert!(repaired_after_check > 0);
    }

    /// Implementation review r3: a quarantined region whose PRESENTING reads fail, while its checks
    /// pass with moving pixels, must present the check's GDI image (never keep stale pixels healthy).
    #[test]
    fn a_quarantined_region_with_failing_presentation_presents_the_checks_image() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        screen_all(&w, 0, 50);
        frame(c.capture(false, t + CHECK_INTERVAL)); // quarantined (picture repaired to 50)
        w.borrow_mut().moving.insert(0, (0..4).collect());
        let mut seen = std::collections::BTreeSet::new();
        for k in 1..=70u64 {
            advance(&w);
            dda(&w, 0, 200 + (k % 50) as u8); // DDA changing (so checks pass as motion), never right
            w.borrow_mut().gdi_fail_next.insert(0, 1); // the presenting read of this call fails
            if let CanvasOutcome::Frame(f) = c.capture(false, t + CHECK_INTERVAL + Duration::from_millis(100 * k)) {
                assert!(px(&f, 0, 0) < 200, "a quarantined region republished a DDA value");
                seen.insert(px(&f, 0, 0));
            }
        }
        assert!(seen.len() > 1, "the check's GDI image must have been presented: {seen:?}");
    }

    /// Implementation review r4: a moving minority repaired from GDI that then STOPS at its frozen
    /// DDA value (and gets no more dirty rects) must publish that validated value, not the old repair.
    #[test]
    fn a_repair_never_outlives_a_passed_check() {
        let w = world(10, 20);
        let mut c = canvas(&w);
        let t = Instant::now();
        frame(c.capture(false, t));
        // Pixel 3 is frozen in DDA at 10; the screen moves there (and on pixels 0-2, which DDA tracks).
        w.borrow_mut().moving.insert(0, (0..4).collect());
        for k in 1..=25u64 {
            advance(&w);
            let mut cur = w.borrow().screen[&0].clone();
            cur[3] = 10;
            w.borrow_mut().dda.entry(0).or_default().push_back(Ok(Some((cur, Some(Rect { x: 0, y: 0, w: 2, h: 1 })))));
            let _ = c.capture(false, t + Duration::from_millis(100 * k));
        }
        // The screen stops, with pixel 3 back at exactly the value DDA has frozen (10); no more DDA.
        w.borrow_mut().moving.clear();
        // DDA tracked only the top row, so the whole bottom row (pixels 2 and 3) is frozen at 10:
        // the screen stops with both back at exactly that value.
        let mut stopped = w.borrow().screen[&0].clone();
        stopped[2] = 10;
        stopped[3] = 10;
        // DDA's other pixels: deliver the stopped top row once so they agree.
        w.borrow_mut().dda.entry(0).or_default().push_back(Ok(Some((stopped.clone(), Some(Rect { x: 0, y: 0, w: 2, h: 1 })))));
        screen(&w, 0, &stopped);
        let mut last = None;
        for k in 26..=80u64 {
            if let CanvasOutcome::Frame(f) = c.capture(true, t + Duration::from_millis(100 * k)) {
                last = Some(f);
            }
        }
        let f = last.expect("frames");
        assert_eq!((px(&f, 0, 1), px(&f, 1, 1)), (10, 10), "a stale repair outlived passed checks");
        assert_eq!(c.sources()[0], "dxgi");
    }

    #[test]
    fn same_rgb_and_judge() {
        assert!(same_rgb(&[1, 2, 3, 0], &[1, 2, 3, 255]));
        assert!(!same_rgb(&[1, 2, 3, 0], &[1, 2, 4, 0]));
        assert!(!same_rgb(&[1, 2, 3, 0], &[1, 2, 3, 0, 1, 2, 3, 0]));
        // A stable pixel must equal DDA.
        assert_eq!(judge(&[1, 1, 1, 0], &[1, 1, 1, 0], &[9, 9, 9, 0], &[9, 9, 9, 0]), Verdict::Fault);
        assert_eq!(judge(&[1, 1, 1, 0], &[1, 1, 1, 0], &[1, 1, 1, 7], &[0, 0, 0, 0]), Verdict::Pass { moving: 0 });
        // A moving pixel: not judged by value, but DDA must have changed there since the last check.
        assert_eq!(judge(&[1, 1, 1, 0], &[2, 2, 2, 0], &[9, 9, 9, 0], &[8, 8, 8, 0]), Verdict::Pass { moving: 1 });
        assert_eq!(judge(&[1, 1, 1, 0], &[2, 2, 2, 0], &[9, 9, 9, 0], &[9, 9, 9, 0]), Verdict::Fault);
    }
}
