//! Screen capture via **GDI `BitBlt`** — the universal fallback capture tier of ADR-005.
//!
//! # Why a GDI tier exists
//!
//! DXGI Desktop Duplication ([`crate::capture::DxgiCapturer`]) is the primary, high-FPS,
//! zero-copy tier. But two situations defeat it, and GDI is the answer to both:
//!
//! * **The Winlogon secure desktop** (login screen, UAC elevation, Ctrl+Alt+Del). DDA and WGC
//!   both refuse it; only a GDI `BitBlt` of a DC bound to that desktop can read it. This is the
//!   linchpin of the "see and click through a UAC prompt" feature and was proven end-to-end on
//!   a real machine (the secure-desktop spike captured the Winlogon sign-in screen this way).
//! * **RDP / RDS sessions**, where DDA commonly returns black frames. GDI keeps working, which
//!   matters for the session-shadowing story.
//!
//! GDI's cost is real — it is a synchronous CPU-side blit with no dirty-rectangle metadata, so
//! every frame is a full keyframe and the frame rate is modest. ADR-005 accepts exactly this
//! trade: high-FPS DDA on the Default desktop, low-FPS GDI where DDA can't reach.
//!
//! # Output shape
//!
//! To be a drop-in peer of [`DxgiCapturer`], this tier produces the **same pixel convention**:
//! tightly packed **BGRA8** rows (the desktop's `B8G8R8A8` order), top-down, no row padding
//! (32-bpp DIB rows are always 4-byte aligned, so the DIB stride already equals `width * 4`).
//! Every GDI frame is standalone, so `is_keyframe` is always `true`.
//!
//! # Desktop binding is the caller's job
//!
//! Like `SendInput`, `BitBlt` reads whatever desktop the *calling thread* is bound to. Capturing
//! the secure desktop therefore requires the hosting thread to have `SetThreadDesktop`'d onto
//! `Winlogon` first — the per-session SYSTEM helper's responsibility (see [`crate::service`]).
//! This capturer holds no desktop handle and makes no assumption about which desktop is current;
//! it captures the display as the bound thread sees it.

use rmt_agent_core::platform::{PlatformError, PlatformResult};
use rmt_agent_core::{CapturedFrame, MonitorInfo, ScreenCapturer};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{BOOL, LPARAM, RECT, TRUE};
#[cfg(test)]
use windows::Win32::Graphics::Gdi::{CreateCompatibleBitmap, GetDIBits};
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDCW, CreateDIBSection, DeleteDC,
    DeleteObject, EnumDisplayMonitors, GdiFlush, GetDeviceCaps, GetMonitorInfoW,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ, HMONITOR,
    HORZRES, MONITORINFO, MONITORINFOEXW, SRCCOPY, VERTRES,
};
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};

/// `MONITORINFOF_PRIMARY` — the `MONITORINFO::dwFlags` bit marking the primary display. Spelled out
/// because the `windows` crate does not re-export it from `Win32::Graphics::Gdi`.
const MONITORINFOF_PRIMARY: u32 = 0x0000_0001;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

/// Errors from the GDI capture path.
#[derive(Debug, thiserror::Error)]
pub enum GdiError {
    /// The requested monitor id is not present in the current enumeration.
    #[error("no such monitor: {0}")]
    NoSuchMonitor(u32),

    /// A GDI object/DC creation or blit failed. Carries the Win32 last-error where useful.
    #[error("GDI operation failed: {0}")]
    Gdi(String),
}

impl From<GdiError> for PlatformError {
    fn from(e: GdiError) -> Self {
        match e {
            GdiError::NoSuchMonitor(id) => PlatformError::UnknownMonitor(id),
            GdiError::Gdi(msg) => PlatformError::CaptureUnavailable(msg),
        }
    }
}

/// One physical monitor as discovered by `EnumDisplayMonitors`.
///
/// This is the **authoritative** monitor record for the whole Windows agent: `EnumDisplayMonitors`
/// is the only enumeration that sees *every* attached display, including the indirect ones
/// (DisplayLink / USB docks / Miracast) that DXGI Desktop Duplication has no output for. See
/// [`crate::capture_loop::CaptureLoop::monitors`] for why the id space is anchored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonitorEntry {
    /// Monitor rectangle in virtual-desktop coordinates.
    pub(crate) rect: RECT,
    /// Effective DPI (x axis); 96 = 100%.
    pub(crate) dpi_x: u32,
    /// True for the primary display. Equivalent to `rect.left == 0 && rect.top == 0` (the primary
    /// *defines* the virtual-desktop origin), but read from `MONITORINFOF_PRIMARY` rather than
    /// inferred.
    pub(crate) primary: bool,
    /// GDI device name (`\\.\DISPLAY1`). Diagnostics only — never an id.
    pub(crate) device: String,
}

impl MonitorEntry {
    pub(crate) fn width(&self) -> i32 {
        (self.rect.right - self.rect.left).max(0)
    }
    pub(crate) fn height(&self) -> i32 {
        (self.rect.bottom - self.rect.top).max(0)
    }
}

/// Sort monitors into the **published id order**: left to right across the virtual desktop, then
/// top to bottom for a vertical stack. The index into this ordering is the public
/// [`MonitorInfo::id`].
///
/// Why position and not `EnumDisplayMonitors` order or "primary first":
///
/// * `EnumDisplayMonitors` order is an OS implementation detail (it tracks the device list, so
///   `\\.\DISPLAY2` can enumerate before `\\.\DISPLAY1`) — it would put "Display 1" on an arbitrary
///   panel and shuffle the picker when a monitor is re-plugged.
/// * The **composite** "view all" frame stitches monitors left-to-right *in list order*
///   ([`rmt_agent_core::platform::composite_frames`]), so any order but positional produces a
///   view-all whose panes are in the wrong places.
///
/// The primary is therefore *not* guaranteed to be id 0 (a monitor placed left of the primary has a
/// negative `left` and sorts first) — which is why `primary` is carried explicitly and why the
/// streaming host seeds its initial selection from the flag rather than from `id == 0`.
pub(crate) fn order_entries(mut entries: Vec<MonitorEntry>) -> Vec<MonitorEntry> {
    entries.sort_by_key(|e| (e.rect.left, e.rect.top));
    entries
}

/// Project ordered entries onto the public [`MonitorInfo`] list (id = position in the ordering).
pub(crate) fn monitor_infos(entries: &[MonitorEntry]) -> Vec<MonitorInfo> {
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| MonitorInfo {
            id: i as u32,
            width: e.width().max(0) as u32,
            height: e.height().max(0) as u32,
            dpi_scale: e.dpi_x as f32 / 96.0,
            // Virtual-desktop origin from the monitor rect, for the input remap (see MonitorInfo).
            left: e.rect.left,
            top: e.rect.top,
        })
        .collect()
}

/// Enumerate every attached display via `EnumDisplayMonitors`, in published id order
/// ([`order_entries`]). Free-standing so [`crate::capture_loop::CaptureLoop`] can resolve a
/// monitor id to a rect without owning a capturer.
pub(crate) fn enumerate_monitors_ordered() -> Vec<MonitorEntry> {
    let mut entries: Vec<MonitorEntry> = Vec::new();
    // SAFETY: null hdc + null clip = enumerate every monitor on the virtual desktop; the
    // callback pushes into `entries` via the LPARAM. `entries` outlives the synchronous call.
    unsafe {
        let _ = EnumDisplayMonitors(
            HDC::default(),
            None,
            Some(monitor_enum_proc),
            LPARAM(&mut entries as *mut Vec<MonitorEntry> as isize),
        );
    }
    order_entries(entries)
}

/// Attempt a **checked** enumeration of every attached display.
///
/// Returns `None` when the underlying API cannot deliver a complete observation on THIS call:
///
/// * `EnumDisplayMonitors` itself returns FALSE;
/// * the enumeration callback saw at least one monitor whose `GetMonitorInfoW` call failed
///   (`incomplete_callback == true`) — an incomplete list would be indistinguishable from a
///   removal, and a spurious "removal" would end the session for a live display;
/// * the resulting list is empty or contains a degenerate (zero-area) entry.
///
/// A `None` is the caller's cue to treat the observation as **unavailable** rather than
/// "topology changed". See [`rmt_agent_core::TopologySnapshot`] for the contract.
pub(crate) fn try_enumerate_monitors_checked() -> Option<Vec<MonitorEntry>> {
    let mut acc = EnumAccumulator::default();
    // SAFETY: null hdc + null clip = enumerate every monitor on the virtual desktop; the
    // callback pushes into `acc` via the LPARAM. `acc` outlives the synchronous call.
    let ok = unsafe {
        EnumDisplayMonitors(
            HDC::default(),
            None,
            Some(monitor_enum_proc_checked),
            LPARAM(&mut acc as *mut EnumAccumulator as isize),
        )
    };
    finalize_enumeration(ok.as_bool(), acc)
}

/// Pure projector for the checked enumeration — takes the raw API success bit and the accumulator
/// filled in by the callback, and returns `Some(ordered)` only when the observation is
/// unambiguously complete. Extracted so OS-free tests can script every branch without opening a
/// real DC. See [`try_enumerate_monitors_checked`] for the wired-up caller.
///
/// Returns `None` when ANY of these hold: the API returned FALSE; any callback saw a
/// `GetMonitorInfoW` failure (`incomplete_callback`); any callback saw a `GetDpiForMonitor`
/// failure (`dpi_failed` — the default-96 fallback would masquerade as a DPI *change* against a
/// prior baseline whose DPI *was* observed); the list is empty; or any entry is degenerate
/// (zero-area). All of these must be indistinguishable from "no signal" — a false positive here
/// would end a live session.
pub(crate) fn finalize_enumeration(
    api_ok: bool,
    acc: EnumAccumulator,
) -> Option<Vec<MonitorEntry>> {
    if !api_ok || acc.incomplete_callback || acc.dpi_failed || acc.entries.is_empty() {
        return None;
    }
    if acc.entries.iter().any(|e| e.width() <= 0 || e.height() <= 0) {
        return None;
    }
    Some(order_entries(acc.entries))
}

#[derive(Default)]
pub(crate) struct EnumAccumulator {
    pub(crate) entries: Vec<MonitorEntry>,
    pub(crate) incomplete_callback: bool,
    /// A `GetDpiForMonitor` call failed for at least one monitor. The Win32 fallback of 96 DPI
    /// looks identical to a real 100%-scaling monitor, so a later observation whose DPI *was*
    /// read would flip the equality check and be misread as a topology change. Refuse instead.
    pub(crate) dpi_failed: bool,
}

unsafe extern "system" fn monitor_enum_proc_checked(
    hmon: HMONITOR,
    _hdc: HDC,
    _clip: *mut RECT,
    data: LPARAM,
) -> BOOL {
    let acc = &mut *(data.0 as *mut EnumAccumulator);
    let mut mi = MONITORINFOEXW::default();
    mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    if !GetMonitorInfoW(hmon, &mut mi as *mut MONITORINFOEXW as *mut MONITORINFO).as_bool() {
        acc.incomplete_callback = true;
        return TRUE;
    }
    let mut dpi_x = 96u32;
    let mut dpi_y = 96u32;
    if GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y).is_err() {
        acc.dpi_failed = true;
        return TRUE;
    }
    let dev = &mi.szDevice;
    let len = dev.iter().position(|&c| c == 0).unwrap_or(dev.len());
    acc.entries.push(MonitorEntry {
        rect: mi.monitorInfo.rcMonitor,
        dpi_x,
        primary: mi.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
        device: String::from_utf16_lossy(&dev[..len]),
    });
    TRUE
}

/// Project a checked-enumeration result into the platform-neutral [`TopologySnapshot`].
pub(crate) fn snapshot_from_entries(
    entries: &[MonitorEntry],
) -> rmt_agent_core::TopologySnapshot {
    rmt_agent_core::TopologySnapshot {
        monitors: monitor_infos(entries),
        names: entries.iter().map(|e| e.device.clone()).collect(),
    }
}

/// A [`ScreenCapturer`] backed by GDI `BitBlt`.
///
/// Cheap to construct: no OS handles until the first capture. Every capture re-enumerates
/// monitors (so hotplug and resolution changes are picked up for free).
///
/// The blit target is cached between captures of the same size ([`GdiSurface`]): measured on a
/// two-monitor 3840x1080 desktop, allocating a device bitmap and converting it with `GetDIBits`
/// on every frame cost ~16 ms of a 53 ms capture. The cache is dropped by [`Self::invalidate`]
/// on every desktop switch (a DC is never carried from one desktop to another), on a size
/// change, and after any failed blit, so the next capture builds a fresh one exactly as before.
#[derive(Debug, Default)]
pub struct GdiCapturer {
    surface: Option<GdiSurface>,
}

impl Clone for GdiCapturer {
    /// A clone starts with no cached surface: OS handles are never shared between capturers.
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// The reusable blit target: the display DC, a memory DC, and a top-down 32-bpp DIB section
/// selected into it, whose pixels are read directly (no `GetDIBits` conversion).
#[derive(Debug)]
struct GdiSurface {
    screen: HDC,
    mem: HDC,
    dib: HBITMAP,
    old: HGDIOBJ,
    bits: *const u8,
    w: i32,
    h: i32,
}

// SAFETY: the handles are process-wide GDI objects, and the surface is only ever used through
// `&mut GdiCapturer`, so never from two threads at once. It is created and used by the capturing
// thread, and dropped on a desktop switch, so it never reads a desktop other than the one it was
// created on.
unsafe impl Send for GdiSurface {}

impl GdiSurface {
    /// # Safety
    /// Must be called on the thread (and desktop) that will capture.
    unsafe fn new(w: i32, h: i32) -> Result<Self, GdiError> {
        // A DC bound to the current thread's desktop. NULL device is the key: it captures whatever
        // desktop this thread is on (Default *or* Winlogon).
        let screen = CreateDCW(w!("DISPLAY"), PCWSTR::null(), PCWSTR::null(), None);
        if screen.is_invalid() {
            return Err(GdiError::Gdi(format!("CreateDCW(DISPLAY) failed le={}", last_err())));
        }
        let mem = CreateCompatibleDC(screen);
        if mem.is_invalid() {
            let le = last_err();
            let _ = DeleteDC(screen);
            return Err(GdiError::Gdi(format!("CreateCompatibleDC le={le}")));
        }
        let mut bi = BITMAPINFO::default();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h; // negative = top-down, the same row order GetDIBits produced
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = 0; // BI_RGB
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let dib = match CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &mut bits, None, 0) {
            Ok(b) if !b.is_invalid() && !bits.is_null() => b,
            other => {
                let le = last_err();
                if let Ok(b) = other {
                    let _ = DeleteObject(b);
                }
                let _ = DeleteDC(mem);
                let _ = DeleteDC(screen);
                return Err(GdiError::Gdi(format!("CreateDIBSection {w}x{h} le={le}")));
            }
        };
        let old = SelectObject(mem, dib);
        Ok(Self { screen, mem, dib, old, bits: bits as *const u8, w, h })
    }

    /// Blit `(src_x, src_y)` of the display into the section and copy the pixels out.
    ///
    /// # Safety
    /// Same thread/desktop contract as [`Self::new`].
    unsafe fn grab(&mut self, src_x: i32, src_y: i32) -> Result<Vec<u8>, GdiError> {
        BitBlt(self.mem, 0, 0, self.w, self.h, self.screen, src_x, src_y, SRCCOPY)
            .map_err(|_| GdiError::Gdi(format!("BitBlt failed le={}", last_err())))?;
        // GDI may batch drawing calls; flush before reading the section's memory directly.
        let _ = GdiFlush();
        let len = (self.w as usize) * (self.h as usize) * 4;
        // SAFETY: `bits` points at the DIB section's w*h*4 bytes (32 bpp, 4-byte aligned rows), alive
        // until the section is deleted in Drop.
        Ok(std::slice::from_raw_parts(self.bits, len).to_vec())
    }
}

impl Drop for GdiSurface {
    fn drop(&mut self) {
        // SAFETY: each handle was created in `new` and is released exactly once, the section
        // deselected before it is deleted.
        unsafe {
            SelectObject(self.mem, self.old);
            let _ = DeleteObject(self.dib);
            let _ = DeleteDC(self.mem);
            let _ = DeleteDC(self.screen);
        }
    }
}

impl GdiCapturer {
    /// Create a GDI capturer. The hosting process should already be PerMonitorV2 DPI-aware
    /// (see [`crate::set_process_dpi_awareness`]) so the enumerated pixel sizes are physical.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop the cached blit surface: the thread switched desktops (or is about to). The next
    /// capture creates a fresh DC on whatever desktop the thread is then bound to.
    pub fn invalidate(&mut self) {
        self.surface = None;
    }

    /// Enumerate attached monitors in published id order. The index is the [`MonitorInfo::id`]
    /// used by [`Self::capture`] and everywhere else. See [`enumerate_monitors_ordered`].
    fn enumerate(&self) -> Vec<MonitorEntry> {
        enumerate_monitors_ordered()
    }

    /// Capture monitor `monitor_id` of the current desktop as tightly packed top-down BGRA8.
    ///
    /// Uses the null-device `CreateDCW("DISPLAY", NULL, …)` DC — the form proven (by the
    /// secure-desktop spike, on a live VM) to read the **Winlogon** desktop that the bound
    /// thread is on. A per-adapter device DC (`\\.\DISPLAYn`) does *not* read the secure
    /// desktop — it returns black — which is why this tier deliberately uses that DC.
    ///
    /// # Multi-monitor
    ///
    /// That DC spans the whole **virtual desktop**, with its origin at the primary monitor's
    /// top-left — which is exactly the coordinate space `EnumDisplayMonitors` reports rects in. So
    /// a monitor is captured by blitting its rect out of that one DC: `BitBlt(src_x = rect.left,
    /// src_y = rect.top)`. For the primary that is `(0, 0)` **by definition** (the primary defines
    /// the virtual-desktop origin), so the single-monitor and primary-monitor paths issue byte-for-
    /// byte the same call they always did — the secure-desktop capture this tier exists for is
    /// unchanged.
    ///
    /// An id with no matching monitor (hotplug race, or enumeration unavailable on a headless
    /// desktop) falls back to the whole-DC blit of the primary rather than failing: the caller gets
    /// a frame, not a stall.
    pub fn capture(&mut self, monitor_id: u32) -> Result<CapturedFrame, GdiError> {
        let target = self
            .enumerate()
            .into_iter()
            .nth(monitor_id as usize)
            .filter(|e| e.width() > 0 && e.height() > 0);
        match target {
            Some(e) => self.capture_rect(monitor_id, e.rect.left, e.rect.top, e.width(), e.height()),
            None => self.capture_primary_dc(),
        }
    }

    /// Blit `w`x`h` at virtual-desktop `(src_x, src_y)` out of the current desktop's display DC.
    ///
    /// `captured_id` is stamped onto the frame; it is the caller's public monitor id, since the
    /// rect is how a monitor is addressed here.
    pub(crate) fn capture_rect(
        &mut self,
        captured_id: u32,
        src_x: i32,
        src_y: i32,
        w: i32,
        h: i32,
    ) -> Result<CapturedFrame, GdiError> {
        if w <= 0 || h <= 0 {
            return Err(GdiError::Gdi(format!("bad monitor rect {w}x{h}")));
        }
        if self.surface.as_ref().is_some_and(|c| c.w != w || c.h != h) {
            self.surface = None;
        }
        if self.surface.is_none() {
            // SAFETY: called on the capturing thread, which owns this capturer.
            self.surface = Some(unsafe { GdiSurface::new(w, h)? });
        }
        let surface = self.surface.as_mut().expect("created above");
        // SAFETY: same thread; the surface was created on the desktop this thread is bound to
        // (a desktop switch drops it through `invalidate`).
        let bytes = match unsafe { surface.grab(src_x, src_y) } {
            Ok(b) => b,
            Err(e) => {
                // Never reuse a surface that failed: the next capture starts fresh.
                self.surface = None;
                return Err(e);
            }
        };
        Ok(CapturedFrame {
            monitor_id: captured_id,
            width: w as u32,
            height: h as u32,
            bytes,
            // GDI carries no dirty-rect metadata: every frame stands alone.
            is_keyframe: true,
        })
    }

    /// Last-resort path when enumeration cannot resolve the id: blit the display DC's own extent
    /// (the primary), sized from `GetDeviceCaps` with a `GetSystemMetrics` backstop. This is the
    /// pre-multimonitor behaviour, kept for headless/degraded desktops where `EnumDisplayMonitors`
    /// returns nothing.
    fn capture_primary_dc(&mut self) -> Result<CapturedFrame, GdiError> {
        // SAFETY: "DISPLAY" is a valid driver name; all other args are null/none.
        let hdc_screen =
            unsafe { CreateDCW(w!("DISPLAY"), PCWSTR::null(), PCWSTR::null(), None) };
        if hdc_screen.is_invalid() {
            return Err(GdiError::Gdi(format!(
                "CreateDCW(DISPLAY) failed le={}",
                last_err()
            )));
        }
        // SAFETY: hdc_screen is a valid display DC.
        let (mut w, mut h) = unsafe {
            (
                GetDeviceCaps(hdc_screen, HORZRES),
                GetDeviceCaps(hdc_screen, VERTRES),
            )
        };
        // SAFETY: hdc_screen came from CreateDCW and is deleted exactly once.
        unsafe {
            let _ = DeleteDC(hdc_screen);
        }
        if w <= 0 || h <= 0 {
            // SAFETY: GetSystemMetrics takes a constant index.
            unsafe {
                w = GetSystemMetrics(SM_CXSCREEN);
                h = GetSystemMetrics(SM_CYSCREEN);
            }
        }
        if w <= 0 || h <= 0 {
            return Err(GdiError::Gdi(format!("bad display metrics {w}x{h}")));
        }
        self.capture_rect(0, 0, 0, w, h)
    }
}

/// Blit the `w`x`h` region at `(src_x, src_y)` of `hdc_screen` into a memory bitmap and read it out
/// as packed top-down BGRA8.
///
/// `(src_x, src_y)` is in **virtual-desktop coordinates** (origin = the primary monitor's top-left,
/// so a monitor placed left of or above the primary has negative coordinates). `(0, 0)` is the
/// primary's top-left, i.e. the whole-screen blit this function used to hardcode.
///
/// # Safety
/// `hdc_screen` must be a valid display DC covering the requested region.
#[cfg(test)]
unsafe fn blit_and_read(
    hdc_screen: HDC,
    src_x: i32,
    src_y: i32,
    w: i32,
    h: i32,
) -> Result<Vec<u8>, GdiError> {
    let hdc_mem = CreateCompatibleDC(hdc_screen);
    if hdc_mem.is_invalid() {
        return Err(GdiError::Gdi(format!("CreateCompatibleDC le={}", last_err())));
    }
    let hbm = CreateCompatibleBitmap(hdc_screen, w, h);
    if hbm.is_invalid() {
        let _ = DeleteDC(hdc_mem);
        return Err(GdiError::Gdi(format!(
            "CreateCompatibleBitmap le={}",
            last_err()
        )));
    }
    let old = SelectObject(hdc_mem, HGDIOBJ(hbm.0));

    let blit = BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, src_x, src_y, SRCCOPY);

    let read = if blit.is_ok() {
        // Read pixels as 32bpp top-down (negative height) BGRA, BI_RGB.
        let mut bi = BITMAPINFO::default();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h; // negative = top-down
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = 0; // BI_RGB

        let mut pixels = vec![0u8; (w as usize) * (h as usize) * 4];
        let lines = GetDIBits(
            hdc_mem,
            hbm,
            0,
            h as u32,
            Some(pixels.as_mut_ptr() as *mut std::ffi::c_void),
            &mut bi,
            DIB_RGB_COLORS,
        );
        if lines == 0 {
            Err(GdiError::Gdi(format!("GetDIBits returned 0 le={}", last_err())))
        } else {
            Ok(pixels)
        }
    } else {
        Err(GdiError::Gdi(format!("BitBlt failed le={}", last_err())))
    };

    // Restore + free GDI objects regardless of outcome.
    SelectObject(hdc_mem, old);
    let _ = DeleteObject(HGDIOBJ(hbm.0));
    let _ = DeleteDC(hdc_mem);
    read
}

/// `EnumDisplayMonitors` callback: append each monitor's device name, rect, and DPI to the
/// `Vec<MonitorEntry>` pointed to by `data`.
unsafe extern "system" fn monitor_enum_proc(
    hmon: HMONITOR,
    _hdc: HDC,
    _clip: *mut RECT,
    data: LPARAM,
) -> BOOL {
    // SAFETY: `data` is the &mut Vec we passed to EnumDisplayMonitors; the call is synchronous.
    let out = &mut *(data.0 as *mut Vec<MonitorEntry>);

    let mut mi = MONITORINFOEXW::default();
    mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    // GetMonitorInfoW fills szDevice because cbSize covers the EX struct.
    if GetMonitorInfoW(hmon, &mut mi as *mut MONITORINFOEXW as *mut MONITORINFO).as_bool() {
        let mut dpi_x = 96u32;
        let mut dpi_y = 96u32;
        // GetDpiForMonitor is best-effort; default 96 (100%) on failure.
        let _ = GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y);
        // szDevice is a NUL-padded fixed array of UTF-16; take up to the first NUL.
        let dev = &mi.szDevice;
        let len = dev.iter().position(|&c| c == 0).unwrap_or(dev.len());
        out.push(MonitorEntry {
            rect: mi.monitorInfo.rcMonitor,
            dpi_x,
            primary: mi.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
            device: String::from_utf16_lossy(&dev[..len]),
        });
    }
    TRUE // keep enumerating
}

fn last_err() -> u32 {
    // SAFETY: GetLastError takes no arguments and is always valid to call.
    unsafe { windows::Win32::Foundation::GetLastError().0 }
}

impl ScreenCapturer for GdiCapturer {
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        Ok(monitor_infos(&self.enumerate()))
    }

    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
        Ok(GdiCapturer::capture(self, monitor_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an entry at a virtual-desktop position. `primary` is set from the position so the
    /// fixtures cannot accidentally describe a desktop with no origin.
    fn entry(left: i32, top: i32, w: i32, h: i32, dpi: u32, device: &str) -> MonitorEntry {
        MonitorEntry {
            rect: RECT {
                left,
                top,
                right: left + w,
                bottom: top + h,
            },
            dpi_x: dpi,
            primary: left == 0 && top == 0,
            device: device.to_string(),
        }
    }

    #[test]
    fn new_capturer_is_cheap() {
        // Construction must not touch the display or allocate OS handles.
        let c = GdiCapturer::new();
        assert!(c.surface.is_none());
    }

    /// The cached surface produces the same pixels as the original per-frame path (fresh DC,
    /// device bitmap, GetDIBits), is reused across same-size captures, rebuilt on a size change
    /// and dropped by `invalidate`. Reads the real display: ignored by default, run on the lab VM
    /// or a desktop with `--ignored`.
    #[test]
    #[ignore = "reads the real display"]
    fn the_cached_surface_matches_the_original_path_and_is_reused() {
        let mut c = GdiCapturer::new();
        let a = c.capture_rect(0, 0, 0, 64, 48).expect("cached capture");
        let first = c.surface.as_ref().map(|s| s.dib.0).expect("surface cached");
        // SAFETY: test thread; the reference path creates and frees its own handles.
        let reference = unsafe {
            let screen = CreateDCW(w!("DISPLAY"), PCWSTR::null(), PCWSTR::null(), None);
            let r = blit_and_read(screen, 0, 0, 64, 48).expect("reference capture");
            let _ = DeleteDC(screen);
            r
        };
        let same = a.bytes.chunks(4).zip(reference.chunks(4)).filter(|(x, y)| x[..3] == y[..3]).count();
        assert!(same * 100 >= 64 * 48 * 99, "cached and reference pixels differ: {same}/{} equal", 64 * 48);
        let _ = c.capture_rect(0, 0, 0, 64, 48).unwrap();
        assert_eq!(c.surface.as_ref().map(|s| s.dib.0), Some(first), "same size reuses the surface");
        let b = c.capture_rect(0, 0, 0, 32, 24).unwrap();
        assert_eq!((b.width, b.height, b.bytes.len()), (32, 24, 32 * 24 * 4));
        assert_eq!(c.surface.as_ref().map(|s| (s.w, s.h)), Some((32, 24)), "a size change rebuilds it");
        c.invalidate();
        assert!(c.surface.is_none(), "invalidate drops it");
    }

    #[test]
    fn ids_run_left_to_right_regardless_of_enumeration_order() {
        // The trap this ordering exists for: `EnumDisplayMonitors` hands back the DEVICE list
        // order, which on a real box need not be positional (this build box enumerates
        // \\.\DISPLAY2 — the primary — before \\.\DISPLAY1, which sits to its right). Ordering by
        // position makes "Display 1" the leftmost panel no matter how the OS enumerates, which is
        // also what the composite "view all" stitch (left-to-right in list order) requires.
        let ordered = order_entries(vec![
            entry(0, 0, 1920, 1080, 96, r"\\.\DISPLAY2"),
            entry(1920, 0, 2560, 1440, 144, r"\\.\DISPLAY1"),
            entry(-1280, 0, 1280, 1024, 96, r"\\.\DISPLAY3"),
        ]);
        let devices: Vec<&str> = ordered.iter().map(|e| e.device.as_str()).collect();
        assert_eq!(
            devices,
            vec![r"\\.\DISPLAY3", r"\\.\DISPLAY2", r"\\.\DISPLAY1"],
            "monitors sort left-to-right across the virtual desktop"
        );
        // The primary is NOT id 0 here — a monitor left of it sorts first. Anything that wants the
        // primary must read the flag (or the (0,0) origin), never assume id 0.
        assert!(ordered[1].primary, "the (0,0) monitor is the primary");
        assert!(!ordered[0].primary && !ordered[2].primary);
    }

    #[test]
    fn a_vertical_stack_orders_top_to_bottom() {
        // Same x, so the tie-break (top) decides. Deliberately fed bottom-first.
        let ordered = order_entries(vec![
            entry(0, 1080, 1920, 1080, 96, "below"),
            entry(0, 0, 1920, 1080, 96, "primary"),
            entry(0, -1080, 1920, 1080, 96, "above"),
        ]);
        let devices: Vec<&str> = ordered.iter().map(|e| e.device.as_str()).collect();
        assert_eq!(devices, vec!["above", "primary", "below"]);
    }

    #[test]
    fn monitor_infos_carry_id_size_origin_and_dpi() {
        // An ASYMMETRIC fixture: different sizes AND different DPI per monitor, so a swapped or
        // constant projection cannot pass (see the swapped-wiring lesson).
        let infos = monitor_infos(&order_entries(vec![
            entry(1920, 0, 2560, 1440, 144, "right"),
            entry(0, 0, 1920, 1080, 96, "primary"),
        ]));
        assert_eq!(infos.len(), 2);
        assert_eq!(
            (infos[0].id, infos[0].width, infos[0].height, infos[0].left, infos[0].top),
            (0, 1920, 1080, 0, 0)
        );
        assert_eq!(infos[0].dpi_scale, 1.0);
        assert_eq!(
            (infos[1].id, infos[1].width, infos[1].height, infos[1].left, infos[1].top),
            (1, 2560, 1440, 1920, 0)
        );
        assert_eq!(infos[1].dpi_scale, 1.5, "144 DPI is 150% scale");
    }

    // ---- finalize_enumeration --------------------------------------------------------------
    // OS-free coverage of the checked-enumeration projector. The real callback is not exercised
    // here (it needs an HMONITOR); the accumulator is scripted directly, which is the shape of
    // every branch that decides between `Some(ordered)` and `None`.

    fn acc_with(entries: Vec<MonitorEntry>) -> EnumAccumulator {
        EnumAccumulator { entries, incomplete_callback: false, dpi_failed: false }
    }

    #[test]
    fn finalize_returns_none_when_api_reports_failure() {
        // A single perfect entry cannot rescue a FALSE from EnumDisplayMonitors — an incomplete
        // enumeration is indistinguishable from a removal, and a spurious removal ends sessions.
        let acc = acc_with(vec![entry(0, 0, 1920, 1080, 96, "P")]);
        assert!(finalize_enumeration(false, acc).is_none());
    }

    #[test]
    fn finalize_returns_none_when_callback_marked_incomplete() {
        let mut acc = acc_with(vec![entry(0, 0, 1920, 1080, 96, "P")]);
        acc.incomplete_callback = true;
        assert!(finalize_enumeration(true, acc).is_none());
    }

    #[test]
    fn finalize_returns_none_when_dpi_lookup_failed() {
        // The default-96 fallback would look like a real 100% monitor and flip the equality check
        // against a prior baseline whose DPI was observed — refuse rather than lie.
        let mut acc = acc_with(vec![entry(0, 0, 1920, 1080, 96, "P")]);
        acc.dpi_failed = true;
        assert!(finalize_enumeration(true, acc).is_none());
    }

    #[test]
    fn finalize_returns_none_on_empty_enumeration() {
        assert!(finalize_enumeration(true, acc_with(Vec::new())).is_none());
    }

    #[test]
    fn finalize_returns_none_on_a_degenerate_entry() {
        // Zero-area entries are unusable for capture and would poison the baseline comparison.
        let acc = acc_with(vec![
            entry(0, 0, 1920, 1080, 96, "P"),
            entry(1920, 0, 0, 1080, 96, "Q"), // zero width
        ]);
        assert!(finalize_enumeration(true, acc).is_none());
    }

    #[test]
    fn finalize_returns_ordered_entries_on_success() {
        // Positional ordering must apply even though the scripted accumulator hands the entries
        // in device order — the projector is the ONLY place ordering happens post-callback.
        let acc = acc_with(vec![
            entry(1920, 0, 2560, 1440, 144, r"\\.\DISPLAY1"),
            entry(0, 0, 1920, 1080, 96, r"\\.\DISPLAY2"),
        ]);
        let ordered = finalize_enumeration(true, acc).expect("Some");
        let devices: Vec<&str> = ordered.iter().map(|e| e.device.as_str()).collect();
        assert_eq!(devices, vec![r"\\.\DISPLAY2", r"\\.\DISPLAY1"]);
    }

    #[test]
    fn a_single_monitor_desktop_is_id_zero_at_the_origin() {
        // The regression case that must never move: one display, id 0, origin (0,0) — which makes
        // the GDI blit `BitBlt(src 0,0)`, byte-for-byte the pre-multimonitor call.
        let ordered = order_entries(vec![entry(0, 0, 1920, 1080, 96, r"\\.\DISPLAY1")]);
        let infos = monitor_infos(&ordered);
        assert_eq!(infos.len(), 1);
        assert_eq!((infos[0].id, infos[0].left, infos[0].top), (0, 0, 0));
        assert!(ordered[0].primary);
    }

    #[test]
    #[ignore = "needs real hardware: a desktop session with TWO OR MORE monitors"]
    fn gdi_captures_each_monitor_and_not_the_primary_every_time() {
        // THE hardware invariant the unit tests above cannot reach. Everything else here is pure id
        // arithmetic; whether `BitBlt` at a non-zero source origin actually reads the *other* panel
        // is a property of the `CreateDCW("DISPLAY")` DC — it holds only if that DC spans the whole
        // virtual desktop rather than just the primary, which is not something the API documents in
        // so many words. If it did not, this tier would return the primary for every id and each
        // frame would still be a perfectly plausible screen.
        //
        // Run it by hand on a multi-monitor box:
        //   cargo test -p rmt-agent-windows --lib -- --ignored gdi_captures_each_monitor
        // `agent_host monitors --all-tiers --capture <dir>` is the richer version of the same check
        // (it dumps PNGs and cross-checks the DXGI and WGC tiers too).
        let mut cap = GdiCapturer::new();
        let mons = cap.monitors().expect("enumerate");
        // The premise, asserted rather than assumed: on a single-monitor box this test proves
        // nothing at all, and passing quietly would be the worst outcome.
        assert!(
            mons.len() >= 2,
            "this test needs 2+ monitors; found {} — it cannot prove per-monitor capture on one \
             display, so it fails rather than passing vacuously",
            mons.len()
        );

        let mut frames = Vec::new();
        for m in &mons {
            let f = cap.capture(m.id).expect("capture monitor");
            assert_eq!(f.monitor_id, m.id, "frame is stamped with the requested id");
            // A capture of the WRONG monitor is caught here whenever the panels differ in size.
            assert_eq!(
                (f.width, f.height),
                (m.width, m.height),
                "monitor {} captured at the wrong size — a different panel was read",
                m.id
            );
            assert_eq!(f.bytes.len(), (f.width * f.height * 4) as usize, "packed BGRA8");
            assert!(
                f.bytes.iter().any(|&b| b != 0),
                "monitor {} captured entirely black",
                m.id
            );
            frames.push(f);
        }

        // …and the size check is weak when the panels match, which is the common case, so also
        // require the CONTENT to differ. Two monitors showing pixel-identical images would make
        // this inconclusive — put different windows on them before running.
        let same_size = frames.windows(2).all(|w| (w[0].width, w[0].height) == (w[1].width, w[1].height));
        let all_identical = frames.windows(2).all(|w| w[0].bytes == w[1].bytes);
        assert!(
            !all_identical,
            "every monitor captured byte-identical pixels{} — this is what a primary-only tier \
             looks like. If the screens genuinely show the same image, put different windows on \
             them and re-run.",
            if same_size { " (and they are the same size, so nothing else would catch it)" } else { "" }
        );
    }

    #[test]
    #[ignore = "needs real hardware"]
    fn enumerate_and_capture_smoke() {
        // TODO(hardware): needs a real display and an interactive session (session 0 has no
        // display). Exercises the full GDI path: enumerate → per-monitor DC → BitBlt → GetDIBits.
        let mut cap = GdiCapturer::new();
        let mons = cap.monitors().expect("enumerate");
        assert!(!mons.is_empty(), "expected at least one monitor");
        let frame = cap.capture(mons[0].id).expect("capture");
        assert_eq!(frame.monitor_id, mons[0].id);
        assert_eq!(frame.width, mons[0].width);
        assert_eq!(frame.height, mons[0].height);
        assert_eq!(
            frame.bytes.len(),
            (frame.width * frame.height * 4) as usize,
            "packed BGRA8 = w*h*4"
        );
        assert!(frame.is_keyframe, "GDI frames are always keyframes");
        // A live desktop is not uniformly zero; guard against an all-black readback.
        assert!(
            frame.bytes.iter().any(|&b| b != 0),
            "captured frame is entirely black"
        );
    }
}
