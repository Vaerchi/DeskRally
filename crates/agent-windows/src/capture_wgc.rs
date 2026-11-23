//! Screen capture via **Windows.Graphics.Capture (WGC)** — the RDP/RDS fallback tier of ADR-005.
//!
//! # Why WGC
//!
//! DXGI Desktop Duplication is the primary tier, but it **returns black frames inside an RDP /
//! RDS session** (the remote display path has no duplicated output). WGC keeps working there,
//! which is exactly what the **session-shadowing** story needs. WGC is also the clean path for
//! per-window capture later. It does *not* read the Winlogon secure desktop (that stays GDI).
//!
//! # Shape
//!
//! WGC is a WinRT API. This tier:
//! 1. builds a D3D11 device and wraps it as an `IDirect3DDevice`
//!    (`CreateDirect3D11DeviceFromDXGIDevice`);
//! 2. gets a `GraphicsCaptureItem` for a monitor via `IGraphicsCaptureItemInterop::CreateForMonitor`
//!    (no consent picker — the picker is only for user-driven capture);
//! 3. creates a **free-threaded** `Direct3D11CaptureFramePool` (so no `DispatcherQueue` is needed
//!    on the capture thread) and a `GraphicsCaptureSession`, disables the yellow capture border
//!    and the cursor where the OS supports it, and starts capture;
//! 4. **pulls** frames with `TryGetNextFrame`, unwraps the `IDirect3DSurface` to an
//!    `ID3D11Texture2D` (`IDirect3DDxgiInterfaceAccess`), and reads it back to packed BGRA8 —
//!    the same output convention as the DXGI and GDI tiers.
//!
//! Output matches the other tiers: tightly packed top-down BGRA8, `is_keyframe = true` (WGC gives
//! no dirty-rect metadata through this path).

use std::time::{Duration, Instant};

use rmt_agent_core::platform::{PlatformError, PlatformResult};
use rmt_agent_core::{CapturedFrame, MonitorInfo, ScreenCapturer};

use windows::core::{Interface, IInspectable};
use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Foundation::POINT;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Graphics::Gdi::{
    MonitorFromPoint, HMONITOR, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY,
};
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;

/// Errors from the WGC capture path.
#[derive(Debug, thiserror::Error)]
pub enum WgcError {
    /// `GraphicsCaptureSession::IsSupported()` is false on this OS/session.
    #[error("Windows.Graphics.Capture is not supported here")]
    Unsupported,
    /// No frame arrived within the poll window (transient — retry).
    #[error("no WGC frame within timeout")]
    Timeout,
    /// The requested monitor id is not the primary (only the primary is wired for now).
    #[error("no such monitor: {0}")]
    NoSuchMonitor(u32),
    /// Underlying WinRT/Win32 failure.
    #[error("wgc error: {0}")]
    Windows(#[from] windows::core::Error),
}

impl From<WgcError> for PlatformError {
    fn from(e: WgcError) -> Self {
        match e {
            WgcError::NoSuchMonitor(id) => PlatformError::UnknownMonitor(id),
            WgcError::Timeout => PlatformError::CaptureUnavailable(e.to_string()),
            WgcError::Unsupported | WgcError::Windows(_) => {
                PlatformError::CaptureUnavailable(e.to_string())
            }
        }
    }
}

/// A live WGC capture of one monitor: the D3D device, the frame pool, and the running session.
struct Live {
    frame_pool: Direct3D11CaptureFramePool,
    _session: GraphicsCaptureSession,
    size: SizeInt32,
    /// The `HMONITOR` this session was created for, as a raw handle value. A capture of a
    /// *different* monitor must tear this down and rebuild — a `GraphicsCaptureItem` is bound to
    /// one monitor for its lifetime, so without this the tier would silently keep streaming the
    /// first monitor it was ever asked for.
    hmon: isize,
}

/// [`ScreenCapturer`] over Windows.Graphics.Capture. Captures any monitor: the public id is
/// resolved to a virtual-desktop rect (GDI enumeration) and the rect to an `HMONITOR`, which is
/// what `CreateForMonitor` takes. Switching monitors rebuilds the item/pool/session.
pub struct WgcCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    rt_device: IDirect3DDevice,
    live: Option<Live>,
    staging: Option<ID3D11Texture2D>,
    staging_dims: (u32, u32),
}

// SAFETY: the `ScreenCapturer` trait requires `Send` so the core can move a capturer to a
// dedicated capture thread. The D3D interfaces are already `Send` in the `windows` crate; the
// WinRT capture objects are created **free-threaded** (`CreateFreeThreaded`), i.e. thread-agile,
// so moving the whole capturer between threads is sound. The capturer is only ever *owned* by one
// thread at a time (never shared), so `Send` — not `Sync` — is all we assert.
unsafe impl Send for WgcCapturer {}

impl WgcCapturer {
    /// Build a WGC capturer (D3D device + WinRT device wrapper). Fails with
    /// [`WgcError::Unsupported`] if WGC is unavailable on this OS/session.
    pub fn new() -> Result<Self, WgcError> {
        if !GraphicsCaptureSession::IsSupported().unwrap_or(false) {
            return Err(WgcError::Unsupported);
        }
        let (device, context) = create_device()?;
        // Wrap the D3D11 device as a WinRT IDirect3DDevice for the frame pool.
        let dxgi: IDXGIDevice = device.cast()?;
        // SAFETY: dxgi is a live COM interface; the returned inspectable is cast to IDirect3DDevice.
        let inspectable: IInspectable =
            unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi)? };
        let rt_device: IDirect3DDevice = inspectable.cast()?;
        Ok(Self {
            device,
            context,
            rt_device,
            live: None,
            staging: None,
            staging_dims: (0, 0),
        })
    }

    /// (Re)build the capture item/pool/session for `hmon`, unless one is already live for it.
    fn ensure_live(&mut self, hmon: HMONITOR) -> Result<(), WgcError> {
        if self.live.as_ref().map(|l| l.hmon) == Some(hmon.0 as isize) {
            return Ok(());
        }
        // A different monitor (or none yet): drop the old session before building the new one.
        self.live = None;

        // GraphicsCaptureItem for the monitor via the interop factory (no consent picker).
        let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
        // SAFETY: hmon is a valid monitor handle; CreateForMonitor returns a GraphicsCaptureItem.
        let item: GraphicsCaptureItem = unsafe { interop.CreateForMonitor(hmon)? };
        let size = item.Size()?;

        let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            &self.rt_device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            2,
            size,
        )?;
        let session = frame_pool.CreateCaptureSession(&item)?;

        // Best-effort: hide the yellow capture border and the cursor (newer OS builds only).
        let _ = session.SetIsBorderRequired(false);
        let _ = session.SetIsCursorCaptureEnabled(false);

        // We poll TryGetNextFrame on the free-threaded pool (no FrameArrived handler needed).
        session.StartCapture()?;

        self.live = Some(Live {
            frame_pool,
            _session: session,
            size,
            hmon: hmon.0 as isize,
        });
        Ok(())
    }

    /// Capture one frame of the monitor with public id `monitor_id` as packed top-down BGRA8.
    ///
    /// The id is resolved through the authoritative GDI enumeration
    /// ([`crate::capture_gdi::enumerate_monitors_ordered`]) to a rect, and the rect to an
    /// `HMONITOR`; an id with no monitor falls back to the primary (a frame, not a stall).
    pub fn capture(&mut self, monitor_id: u32) -> Result<CapturedFrame, WgcError> {
        let hmon = crate::capture_gdi::enumerate_monitors_ordered()
            .get(monitor_id as usize)
            .map(|e| hmonitor_for_rect(e.rect.left, e.rect.top, e.width(), e.height()))
            .unwrap_or_else(primary_hmonitor);
        self.capture_monitor(monitor_id, hmon)
    }

    /// Capture one frame of `hmon`, stamping the frame with `captured_id`.
    ///
    /// Split from [`Self::capture`] so [`crate::capture_loop::CaptureLoop`] — which has already
    /// resolved the id to a rect for the other tiers — does not re-enumerate.
    pub(crate) fn capture_monitor(
        &mut self,
        captured_id: u32,
        hmon: HMONITOR,
    ) -> Result<CapturedFrame, WgcError> {
        self.ensure_live(hmon)?;

        // Poll for a frame (the pool fills asynchronously once capture starts).
        let deadline = Instant::now() + Duration::from_millis(300);
        let frame = loop {
            let pool = &self.live.as_ref().expect("live ensured").frame_pool;
            if let Ok(f) = pool.TryGetNextFrame() {
                break f;
            }
            if Instant::now() >= deadline {
                return Err(WgcError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(8));
        };

        // Unwrap the WinRT surface → ID3D11Texture2D.
        let surface = frame.Surface()?;
        let access: IDirect3DDxgiInterfaceAccess = surface.cast()?;
        // SAFETY: GetInterface returns the underlying D3D texture for this surface.
        let texture: ID3D11Texture2D = unsafe { access.GetInterface::<ID3D11Texture2D>()? };

        let bytes = self.readback(&texture)?;
        let (w, h) = self.staging_dims;

        // Recreate the pool if the monitor size changed (resolution change).
        let live_size = self.live.as_ref().map(|l| l.size).unwrap_or_default();
        if (live_size.Width as u32, live_size.Height as u32) != (w, h) {
            // ContentSize differs from pool size → drop live so the next call rebuilds.
            let _ = self
                .live
                .as_ref()
                .map(|l| l.frame_pool.Recreate(
                    &self.rt_device,
                    DirectXPixelFormat::B8G8R8A8UIntNormalized,
                    2,
                    SizeInt32 { Width: w as i32, Height: h as i32 },
                ));
        }

        Ok(CapturedFrame {
            monitor_id: captured_id,
            width: w,
            height: h,
            bytes,
            is_keyframe: true,
        })
    }

    /// Copy the WGC texture to a CPU-readable staging texture and read out packed BGRA8 rows.
    fn readback(&mut self, texture: &ID3D11Texture2D) -> Result<Vec<u8>, WgcError> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: texture is a live D3D texture.
        unsafe { texture.GetDesc(&mut desc) };
        let (w, h) = (desc.Width, desc.Height);
        self.ensure_staging(&desc)?;
        let staging = self.staging.as_ref().expect("staging ensured").clone();

        // SAFETY: both textures are live and format/size compatible by construction.
        unsafe { self.context.CopyResource(&staging, texture) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: staging is USAGE_STAGING with CPU_ACCESS_READ; subresource 0 exists.
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?
        };

        let stride = (w as usize) * 4;
        let mut bytes = vec![0u8; stride * h as usize];
        // SAFETY: mapped.pData has RowPitch*h readable bytes; copy `stride` per row within bounds.
        unsafe {
            let src = mapped.pData as *const u8;
            for row in 0..h as usize {
                let src_row = src.add(row * mapped.RowPitch as usize);
                let dst = &mut bytes[row * stride..row * stride + stride];
                std::ptr::copy_nonoverlapping(src_row, dst.as_mut_ptr(), stride);
            }
            self.context.Unmap(&staging, 0);
        }
        self.staging_dims = (w, h);
        Ok(bytes)
    }

    fn ensure_staging(&mut self, src: &D3D11_TEXTURE2D_DESC) -> Result<(), WgcError> {
        if self.staging.is_some() && self.staging_dims == (src.Width, src.Height) {
            return Ok(());
        }
        let mut desc = *src;
        desc.Usage = D3D11_USAGE_STAGING;
        desc.BindFlags = 0;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        desc.MiscFlags = 0;
        let mut tex: Option<ID3D11Texture2D> = None;
        // SAFETY: desc is a valid staging descriptor; no initial data.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex))? };
        self.staging = tex;
        self.staging_dims = (src.Width, src.Height);
        Ok(())
    }
}

impl ScreenCapturer for WgcCapturer {
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        // WGC has no enumeration of its own (it captures whatever `HMONITOR` it is handed), so it
        // reports the authoritative GDI list — the same one that assigns the ids
        // `capture_frame` resolves. Reporting a one-entry list here used to be harmless because the
        // tier was primary-only; now that it can capture any monitor, disagreeing with the id space
        // it honours would be a lie.
        Ok(crate::capture_gdi::monitor_infos(
            &crate::capture_gdi::enumerate_monitors_ordered(),
        ))
    }

    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
        Ok(WgcCapturer::capture(self, monitor_id)?)
    }
}

/// The `HMONITOR` covering the CENTRE of a virtual-desktop rect.
///
/// The centre, not the top-left: a monitor's top-left is on the boundary with its neighbour, and
/// `MonitorFromPoint` resolves a boundary point to whichever monitor claims it — an off-by-one that
/// would silently capture the wrong panel. `MONITOR_DEFAULTTONEAREST` means a stale rect (a monitor
/// unplugged between enumeration and capture) still yields a usable monitor instead of null.
pub(crate) fn hmonitor_for_rect(left: i32, top: i32, w: i32, h: i32) -> HMONITOR {
    let pt = POINT {
        x: left + w / 2,
        y: top + h / 2,
    };
    // SAFETY: MonitorFromPoint takes a POINT by value and a flag; it cannot fail with NEAREST.
    unsafe { MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST) }
}

/// The primary monitor's handle — the fallback when an id resolves to nothing.
fn primary_hmonitor() -> HMONITOR {
    // SAFETY: constant point/flag; returns the primary HMONITOR.
    unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) }
}

/// Create a D3D11 device+context (hardware, BGRA support) for WGC.
fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext), WgcError> {
    let levels = [D3D_FEATURE_LEVEL_11_0];
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    // SAFETY: null adapter + HARDWARE driver; out-params are set on success.
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?
    };
    Ok((
        device.expect("device out-param set on success"),
        context.expect("context out-param set on success"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wgc_support_query_is_safe() {
        // Must not panic regardless of whether WGC is supported on the test host/session.
        let _ = GraphicsCaptureSession::IsSupported();
    }

    /// The CONTROL for [`wgc_does_not_leave_the_thread_unable_to_switch_desktops`]: a DXGI capture
    /// on this thread must leave it able to `SetThreadDesktop`.
    ///
    /// Without this, "WGC breaks desktop switching" is only half measured — it could be any D3D11
    /// device, or the graphics runtime in general, and the fix would have to be a much larger one
    /// (moving capture off the injection thread entirely) rather than avoiding one tier. DXGI also
    /// creates a D3D11 device, so it is the closest available control.
    ///
    /// Run it BY HAND and ALONE (it binds the calling thread to a desktop):
    ///   cargo test -p rmt-agent-windows --lib -- --ignored --test-threads=1 dxgi_leaves
    #[test]
    #[ignore = "needs real hardware; binds the calling thread to a desktop"]
    fn dxgi_leaves_the_thread_able_to_switch_desktops() {
        use crate::service::DesktopFollower;

        let mut before = DesktopFollower::new();
        before.poll().expect("control: this thread can bind to the input desktop at all");
        drop(before);

        let mut cap = crate::capture::DxgiCapturer::new().expect("dxgi capturer");
        // A capture, not just construction: the duplication object is the interesting part.
        for _ in 0..30 {
            match cap.capture(0, std::time::Duration::from_millis(120)) {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(std::time::Duration::from_millis(30)),
            }
        }

        let mut after = DesktopFollower::new();
        let result = after.poll();
        assert!(
            result.is_ok(),
            "DXGI also leaves this thread unable to SetThreadDesktop ({:?}) — then the problem is              not the WGC tier and the fix is to move capture off the injection thread entirely",
            result.err()
        );
    }

    /// A WGC capture PERMANENTLY prevents `SetThreadDesktop` on the calling thread.
    ///
    /// This test asserts the defect, not the wish, because the defect is the reason
    /// [`crate::capture_loop::CaptureLoop`] does not use this tier. `SetThreadDesktop` fails with
    /// `ERROR_BUSY` (0x800700AA) when the calling thread has windows or hooks on its desktop, and
    /// something WGC creates counts — dropping the capturer does not release it either.
    ///
    /// Why that matters enough to pin: the streaming capture thread binds itself to the active
    /// input desktop, and the SAME thread is where `SendInput` injects, because both must be. Once
    /// WGC has run on it, every later desktop switch fails — a UAC prompt, a lock screen,
    /// Ctrl+Alt+Del. Capture keeps showing the desktop it was stuck on and every injected click
    /// lands there, which from the technician's chair is "the mouse does not work at the login
    /// screen". And it fired constantly, because DXGI yields only on a screen change, so any idle
    /// desktop fell through to WGC.
    ///
    /// **If this test ever FAILS, that is good news**: the platform behaviour changed and WGC can
    /// go back into the tier chain (it is the better RDP tier). Do not "fix" it by deleting it.
    ///
    /// Run BY HAND and ALONE — it binds the calling thread to a desktop, which is not something to
    /// do to a shared test-harness thread:
    ///   cargo test -p rmt-agent-windows --lib -- --ignored --test-threads=1 wgc_capture_permanently
    #[test]
    #[ignore = "needs real hardware; binds the calling thread to a desktop"]
    fn wgc_capture_permanently_disables_setthreaddesktop_on_that_thread() {
        use crate::service::DesktopFollower;

        // CONTROL, on this same thread: binding works before WGC is involved. Without it a failure
        // below proves nothing — the thread might simply be unable to bind at all (wrong session,
        // wrong privileges), and the test would blame WGC for the environment.
        let mut before = DesktopFollower::new();
        before
            .poll()
            .expect("control: this thread can bind to the input desktop with no WGC involved");
        drop(before);

        let mut cap = match WgcCapturer::new() {
            Ok(c) => c,
            Err(e) => panic!("WGC unavailable on this host, so this test proves nothing: {e}"),
        };
        for _ in 0..30 {
            match cap.capture(0) {
                Ok(_) => break,
                Err(WgcError::Timeout) => continue,
                Err(e) => panic!("wgc capture failed: {e}"),
            }
        }
        // Dropping it does NOT release whatever blocks the switch — measured, and the reason
        // "tear WGC down before following the desktop" is not an available fix.
        drop(cap);

        // A fresh follower's first poll issues exactly the `SetThreadDesktop` call a real desktop
        // SWITCH issues, so this is the live-session behaviour and not a proxy for it.
        let mut after = DesktopFollower::new();
        let err = after
            .poll()
            .err()
            .expect("EXPECTED WGC to have spoiled this thread for SetThreadDesktop — it did not");
        assert!(
            format!("{err:?}").contains("0x800700AA"),
            "expected ERROR_BUSY from SetThreadDesktop after a WGC capture, got {err:?}"
        );
    }

    /// Does a WGC capture change this thread's **DPI AWARENESS CONTEXT**?
    ///
    /// The candidate mechanism for the operator's Finding 1, and the reason it is worth testing on
    /// hardware that cannot show the symptom: a context change is invisible when every monitor is
    /// unscaled, because logical and physical coordinates are then identical. It would explain the
    /// whole shape of his output without WGC damaging anything —
    ///
    /// ```text
    ///   before WGC: process unaware -> DXGI DesktopCoordinates virtualized -> matches the
    ///               virtualized MonitorInfo rect -> dxgi x7, works
    ///   after WGC:  coordinates physical -> the ALREADY-CAPTURED MonitorInfo rect is stale and
    ///               logical -> 1.5x mismatch on the scaled display only -> no match
    ///   unscaled displays match either way, which is exactly what his id=0 and id=2 did
    /// ```
    ///
    /// — and it is an ordinary documented side effect (WinRT graphics interop wants per-monitor
    /// awareness) rather than corruption. `GetThreadDpiAwarenessContext` answers it directly, with
    /// no scaled display required: the CAUSE is observable here even though the SYMPTOM is not.
    ///
    /// Deliberately does NOT call `set_process_dpi_awareness` first — the point is to start from
    /// the configuration the operator's build was in (a test binary has no manifest, so it is
    /// DPI-unaware) and see whether WGC moves it.
    ///
    /// **MEASURED: it does not.** `DPI_AWARENESS(0)` (UNAWARE) before and after, from exactly the
    /// starting state his build was in. So this mechanism is NOT established either, and it is the
    /// fifth candidate for Finding 1 to die. Kept as a regression guard and as a record that the
    /// question was asked and answered rather than left open.
    ///
    /// Run BY HAND and ALONE:
    ///   cargo test -p rmt-agent-windows --lib -- --ignored --test-threads=1 wgc_capture_does_not_change_the_dpi
    #[test]
    #[ignore = "needs real hardware; must run in a process whose DPI awareness nothing else set"]
    fn wgc_capture_does_not_change_the_dpi_awareness_context() {
        use windows::Win32::UI::HiDpi::{
            AreDpiAwarenessContextsEqual, GetAwarenessFromDpiAwarenessContext,
            GetThreadDpiAwarenessContext,
        };

        // SAFETY: both take no arguments / a context handle and have no out-params.
        let before = unsafe { GetThreadDpiAwarenessContext() };
        let before_kind = unsafe { GetAwarenessFromDpiAwarenessContext(before) };

        {
            let mut wgc = match WgcCapturer::new() {
                Ok(c) => c,
                Err(e) => panic!("WGC unavailable on this host, test proves nothing: {e}"),
            };
            for _ in 0..30 {
                match wgc.capture(0) {
                    Ok(_) => break,
                    Err(WgcError::Timeout) => continue,
                    Err(e) => panic!("wgc capture failed: {e}"),
                }
            }
        }

        let after = unsafe { GetThreadDpiAwarenessContext() };
        let after_kind = unsafe { GetAwarenessFromDpiAwarenessContext(after) };
        eprintln!("DPI AWARENESS: before={before_kind:?}  after={after_kind:?}");

        // SAFETY: both handles came from GetThreadDpiAwarenessContext.
        let same = unsafe { AreDpiAwarenessContextsEqual(before, after) }.as_bool();
        assert!(
            same,
            "a WGC capture changed this thread's DPI awareness from {before_kind:?} to              {after_kind:?} — every rect read BEFORE it is now in a different coordinate space              than every rect read after, which is a silent 1.5x mismatch on any scaled display"
        );
    }

    /// Does a WGC capture also break **DXGI output resolution** for a monitor that resolved fine
    /// moments earlier in the same process?
    ///
    /// From an operator's three-display laptop, in ONE run of `agent_host monitors --all-tiers`:
    ///
    /// ```text
    ///   capture probe:   id=1 ... tiers over the burst: dxgi x7   <- DXGI resolved and captured it
    ///   per-tier probe:  id=0 tier=dxgi -> ok
    ///                    id=0 tier=wgc  -> ok      <- first WGC capture in this process
    ///                    id=1 tier=dxgi -> no DXGI output covers this rect
    /// ```
    ///
    /// Same process, same rect, same matcher inputs — seven successful DXGI acquisitions before the
    /// WGC capture and no resolvable output after it. A coordinate-space or DPI explanation cannot
    /// account for that ordering, because it would have failed in the earlier probe too.
    ///
    /// **IT DID NOT REPRODUCE HERE, and that is why this test passes.** Run on a two-output box —
    /// including with a live DXGI duplication held on monitor A when the WGC session is created,
    /// which is the operator's exact sequence — monitor B still resolves afterwards. So WGC is NOT
    /// established as the cause, and the hypothesis should not harden into a belief on the strength
    /// of the ordering alone.
    ///
    /// The one difference this hardware cannot cover: **the display that failed for him is scaled
    /// 150%, and neither monitor here is scaled.** Whatever the cause is, it plausibly needs a
    /// mixed-DPI desktop, which nothing available can produce. Until the probe prints the rects it
    /// compared (it now does), the ordering is suggestive and nothing more.
    ///
    /// Kept as a regression guard: if WGC ever DOES start removing DXGI output resolution, this
    /// fails and says so. It is a documented negative, not a reproduction.
    ///
    /// Needs TWO DXGI outputs. Run BY HAND and ALONE:
    ///   cargo test -p rmt-agent-windows --lib -- --ignored --test-threads=1 wgc_capture_does_not_break_dxgi
    #[test]
    #[ignore = "needs real hardware: two or more DXGI outputs"]
    fn wgc_capture_does_not_break_dxgi_output_resolution() {
        use crate::capture::DxgiCapturer;
        use crate::capture_gdi::enumerate_monitors_ordered;

        let mons = enumerate_monitors_ordered();
        assert!(
            mons.len() >= 2,
            "needs 2+ monitors to show a SECOND monitor failing after WGC touched the first; found {}",
            mons.len()
        );
        let rect_of = |i: usize| {
            let e = &mons[i];
            (e.rect.left, e.rect.top, e.rect.right, e.rect.bottom)
        };
        let (a, b) = (rect_of(0), rect_of(1));

        let mut dxgi = DxgiCapturer::new().expect("dxgi capturer");
        // CONTROL: both monitors resolve to a DXGI output before WGC is involved. Without this a
        // failure below could just mean monitor B never had an output.
        let a_before = dxgi.output_index_for_rect(a).expect("enumerate");
        let b_before = dxgi.output_index_for_rect(b).expect("enumerate");
        assert!(
            a_before.is_some() && b_before.is_some(),
            "control: both monitors must resolve BEFORE any WGC capture (a={a_before:?} b={b_before:?})"
        );

        // Mirror the operator's run EXACTLY, because a first attempt that only *resolved* monitor A
        // before the WGC capture did not reproduce: his diagnostic had a live DXGI DUPLICATION on
        // monitor A (a full capture) when the WGC session was created, and holding one may be what
        // matters.
        for _ in 0..12 {
            match dxgi.capture(a_before.unwrap(), std::time::Duration::from_millis(120)) {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(std::time::Duration::from_millis(30)),
            }
        }

        // Now do what the diagnostic did: a real WGC capture of monitor A.
        {
            let mut wgc = match WgcCapturer::new() {
                Ok(c) => c,
                Err(e) => panic!("WGC unavailable on this host, test proves nothing: {e}"),
            };
            let hmon = hmonitor_for_rect(mons[0].rect.left, mons[0].rect.top, mons[0].width(), mons[0].height());
            for _ in 0..30 {
                match wgc.capture_monitor(0, hmon) {
                    Ok(_) => break,
                    Err(WgcError::Timeout) => continue,
                    Err(e) => panic!("wgc capture failed: {e}"),
                }
            }
        }

        // THE ASSERTION: monitor B must still resolve.
        let b_after = dxgi.output_index_for_rect(b).expect("enumerate after wgc");
        assert_eq!(
            b_after, b_before,
            "after a WGC capture of monitor A, DXGI can no longer resolve monitor B's output              (was {b_before:?}, now {b_after:?}) — the operator's diagnostic reported that display              as an indirect one on exactly this evidence"
        );
    }

    #[test]
    #[ignore = "needs real hardware"]
    fn wgc_capture_smoke() {
        // TODO(hardware): needs a real display + interactive session. Exercises the full WGC
        // path: device → interop CreateForMonitor → free-threaded pool → session → frame → readback.
        let mut cap = WgcCapturer::new().expect("wgc capturer");
        // WGC needs a moment after StartCapture before the first frame lands; retry briefly.
        let mut got = None;
        for _ in 0..30 {
            match cap.capture(0) {
                Ok(f) => {
                    got = Some(f);
                    break;
                }
                Err(WgcError::Timeout) => continue,
                Err(e) => panic!("wgc capture failed: {e}"),
            }
        }
        let frame = got.expect("captured a WGC frame");
        assert_eq!(frame.monitor_id, 0);
        assert!(frame.width > 0 && frame.height > 0);
        assert_eq!(
            frame.bytes.len(),
            (frame.width * frame.height * 4) as usize,
            "packed BGRA8 = w*h*4"
        );
        assert!(
            frame.bytes.iter().any(|&b| b != 0),
            "captured WGC frame is entirely black"
        );
    }
}
