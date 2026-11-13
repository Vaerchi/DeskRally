//! Screen capture via **DXGI Desktop Duplication** (DDA) — the primary capture tier of
//! ADR-005.
//!
//! # Why DDA is the primary tier
//!
//! `AcquireNextFrame` hands back an [`ID3D11Texture2D`] that is *already in VRAM*. That means:
//! * **zero-copy to the hardware encoder** (NVENC / QuickSync / AMF) — no CPU round-trip on
//!   the hot path;
//! * **native dirty rectangles** via `GetFrameDirtyRects` / `GetFrameMoveRects`, which drive
//!   the adaptive-FPS / dirty-rect encoder strategy in ADR-006 — the single biggest bandwidth
//!   win on a mostly-static desktop.
//!
//! The CPU-readback path implemented here (copy to a `STAGING` texture, `Map`, memcpy rows)
//! exists for the software-encoder fallback and for tests. In the fast path the texture goes
//! straight to the encoder and is never mapped.
//!
//! # Fallback tiers (ADR-005) — not yet implemented
//!
//! * **Windows.Graphics.Capture (WGC)** — for RDP sessions (where DDA commonly returns black
//!   frames) and fullscreen-exclusive edge cases. Use
//!   `IGraphicsCaptureItemInterop::CreateForMonitor` to skip the consent picker and set
//!   `IsBorderRequired = false`. No native dirty rects.
//! * **GDI `BitBlt`** — the *only* thing that can capture the Winlogon secure desktop
//!   (login screen, UAC, Ctrl+Alt+Del), which both DDA and WGC refuse. Low FPS is acceptable
//!   there; the design accepts high-FPS DDA on the Default desktop and low-FPS GDI on the
//!   secure desktop.
//!
//! A production [`ScreenCapturer`] selects a tier per desktop; this module implements the DDA
//! tier and documents the seam where the selector chooses.
//!
//! # `DXGI_ERROR_ACCESS_LOST` is normal
//!
//! Desktop switches, resolution changes, DWM mode toggles and GPU resets all invalidate the
//! duplication object and surface as `DXGI_ERROR_ACCESS_LOST`. Per ADR-005 this is a
//! **first-class state, not an error**: we tear the duplication down and recreate it on the
//! next capture call (see [`DxgiCapturer::capture`] and [`CaptureError::AccessLost`]).

use std::time::Duration;

use rmt_agent_core::platform::{PlatformError, PlatformResult};
use rmt_agent_core::{CapturedFrame, MonitorInfo, ScreenCapturer};

use windows::core::Interface;
use windows::Win32::Foundation::{E_ACCESSDENIED, RECT};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0,
    D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_DESC, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTPUT_DESC,
};

/// Default acquire timeout used by the trait-level [`ScreenCapturer::capture_frame`], which has
/// no timeout parameter of its own. Long enough to catch a fresh frame on an active desktop,
/// short enough that an idle desktop surfaces as a retryable "unavailable".
const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_millis(100);

/// Errors from the DXGI capture path.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// The duplication became invalid (desktop switch, resolution/DWM change, GPU reset).
    /// **Expected and routine** — the capturer recreates its duplication on the next call.
    #[error("desktop duplication access lost; recreate required")]
    AccessLost,

    /// No new frame arrived within the requested timeout. Not an error at the call site;
    /// callers should treat it as "reuse the previous frame / emit a heartbeat".
    #[error("no new frame within timeout")]
    Timeout,

    /// The requested monitor id is not present (unplugged, or never existed).
    #[error("no such monitor: {0}")]
    NoSuchMonitor(u32),

    /// Duplication was refused, typically `E_ACCESSDENIED` because the calling thread is not
    /// on the input desktop, or the session is a protected/secure desktop where DDA is
    /// unavailable. This is the signal to fall back to the WGC or GDI tier.
    #[error("duplication unavailable on this desktop (fall back to WGC/GDI): {0}")]
    Unavailable(#[source] windows::core::Error),

    /// Any other Win32/DXGI failure.
    #[error("dxgi/d3d11 error: {0}")]
    Windows(#[from] windows::core::Error),
}

impl CaptureError {
    /// Classify a raw DXGI/D3D11 error into the first-class capture states.
    fn from_dxgi(err: windows::core::Error) -> Self {
        match err.code() {
            code if code == DXGI_ERROR_ACCESS_LOST => CaptureError::AccessLost,
            code if code == DXGI_ERROR_WAIT_TIMEOUT => CaptureError::Timeout,
            code if code == E_ACCESSDENIED => CaptureError::Unavailable(err),
            _ => CaptureError::Windows(err),
        }
    }
}

impl From<CaptureError> for PlatformError {
    fn from(e: CaptureError) -> Self {
        match e {
            // A lost duplication and a timeout are both transient — retry is appropriate.
            CaptureError::AccessLost | CaptureError::Timeout => {
                PlatformError::CaptureUnavailable(e.to_string())
            }
            CaptureError::NoSuchMonitor(id) => PlatformError::UnknownMonitor(id),
            // Access-denied / protected desktop: retryable via a different tier, so map to the
            // transient category rather than a hard error.
            CaptureError::Unavailable(_) => PlatformError::CaptureUnavailable(e.to_string()),
            CaptureError::Windows(_) => PlatformError::Other(e.to_string()),
        }
    }
}

/// A live Desktop Duplication for one output, plus the D3D device that created it.
///
/// The device and the duplication share a lifetime: on `ACCESS_LOST` the duplication is
/// dropped and rebuilt, but the device usually survives (unless the loss was a full GPU
/// reset, in which case device recreation is also required — see [`DxgiCapturer::recreate`]).
struct Duplication {
    #[allow(dead_code)]
    output: IDXGIOutput1,
    dupl: IDXGIOutputDuplication,
    desc: DXGI_OUTDUPL_DESC,
    /// True while we hold an acquired frame that must be released before the next acquire.
    frame_held: bool,
}

impl Drop for Duplication {
    fn drop(&mut self) {
        if self.frame_held {
            // Releasing on drop keeps the duplication usable if it is somehow reused; ignore
            // the result because we are tearing down anyway.
            // SAFETY: `dupl` is a live COM interface; ReleaseFrame is always valid to call.
            let _ = unsafe { self.dupl.ReleaseFrame() };
        }
    }
}

/// [`ScreenCapturer`] over DXGI Desktop Duplication.
///
/// Holds a D3D11 device on the adapter that owns the currently-selected monitor and, lazily,
/// a duplication for that monitor. Selecting a different monitor (or an `ACCESS_LOST`) rebuilds
/// the duplication; a GPU reset rebuilds the device too.
pub struct DxgiCapturer {
    factory: IDXGIFactory1,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    /// The adapter the current `device` was created on.
    adapter: IDXGIAdapter1,
    /// The monitor currently being duplicated, if any.
    active_monitor: Option<u32>,
    dupl: Option<Duplication>,
    /// Cached staging texture reused across frames to avoid per-frame allocation. Rebuilt when
    /// the surface dimensions change.
    staging: Option<ID3D11Texture2D>,
    staging_dims: (u32, u32),
}

impl DxgiCapturer {
    /// Create a capturer, building a D3D11 device on the default hardware adapter.
    ///
    /// The device requests `BGRA_SUPPORT` because the desktop surface is `B8G8R8A8_UNORM`;
    /// this also makes the texture directly usable by Direct2D/DWM interop if needed.
    pub fn new() -> Result<Self, CaptureError> {
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }?;
        // Adapter 0 is the default; a multi-GPU host may need to pick the adapter that owns a
        // given output (see `enumerate_monitors`). For now bind to adapter 0 and rebind on
        // demand when a monitor on another adapter is selected.
        let adapter: IDXGIAdapter1 = unsafe { factory.EnumAdapters1(0) }?;
        let (device, context) = create_device(&adapter)?;
        Ok(Self {
            factory,
            device,
            context,
            adapter,
            active_monitor: None,
            dupl: None,
            staging: None,
            staging_dims: (0, 0),
        })
    }

    /// Rebuild the D3D device (after a GPU reset) and drop any duplication/staging state.
    fn recreate(&mut self) -> Result<(), CaptureError> {
        tracing::debug!("recreating D3D11 device after device loss");
        let (device, context) = create_device(&self.adapter)?;
        self.device = device;
        self.context = context;
        self.dupl = None;
        self.staging = None;
        self.staging_dims = (0, 0);
        Ok(())
    }

    /// (Re)build the duplication for `monitor_id`.
    fn ensure_duplication(&mut self, monitor_id: u32) -> Result<(), CaptureError> {
        if self.active_monitor == Some(monitor_id) && self.dupl.is_some() {
            return Ok(());
        }
        // Drop any stale duplication before creating a new one (a monitor can only be
        // duplicated once per process).
        self.dupl = None;

        let (owner, output) = self.find_output(monitor_id)?;
        // `DuplicateOutput` REQUIRES the D3D device to live on the adapter that owns the output;
        // hand it a device from another adapter and it fails with `E_INVALIDARG`, which names
        // nothing. The device was pinned to adapter 0 while `find_output` walked *every* adapter,
        // so any monitor driven by a second adapter was undupli­catable — the ordinary laptop layout
        // where the built-in panel hangs off the Intel iGPU and the external monitor off the
        // discrete GPU.
        //
        // NOT REPRODUCED, and deliberately recorded as such: the build box has two adapters
        // (RTX 3060 + UHD 750) but DXGI reports both of its outputs on the NVIDIA one, so this path
        // never triggers there. It is fixed from the API contract, not from a failure in hand — the
        // next reader should not take the fix as evidence the configuration was tested.
        //
        // Adapters are compared by LUID, the OS's stable identity for an adapter — `IDXGIAdapter1`
        // pointers are not guaranteed to be reference-identical across `EnumAdapters1` calls.
        if adapter_luid(&owner)? != adapter_luid(&self.adapter)? {
            tracing::debug!(monitor_id, "monitor lives on another adapter — rebinding D3D device");
            let (device, context) = create_device(&owner)?;
            self.device = device;
            self.context = context;
            self.adapter = owner;
            // The staging texture belongs to the old device and cannot be used with the new one.
            self.staging = None;
            self.staging_dims = (0, 0);
        }
        let output1: IDXGIOutput1 = output.cast()?;

        // DuplicateOutput binds the duplication to our D3D device. `E_ACCESSDENIED` here means
        // we are not on the input desktop or the desktop forbids DDA → caller should fall back.
        let dupl = unsafe { output1.DuplicateOutput(&self.device) }
            .map_err(CaptureError::from_dxgi)?;

        // 0.58: `IDXGIOutputDuplication::GetDesc` returns the desc by value.
        let desc = unsafe { dupl.GetDesc() };

        self.dupl = Some(Duplication {
            output: output1,
            dupl,
            desc,
            frame_held: false,
        });
        self.active_monitor = Some(monitor_id);
        Ok(())
    }

    /// Find the `IDXGIOutput` whose index (across all adapters) equals `monitor_id`, **together
    /// with the adapter that owns it**.
    ///
    /// The owner is returned, not discarded, because `DuplicateOutput` only works with a D3D device
    /// created on that same adapter — see [`Self::ensure_duplication`].
    ///
    /// `monitor_id` is the flat enumeration index produced by [`Self::enumerate_monitors`].
    fn find_output(&self, monitor_id: u32) -> Result<(IDXGIAdapter1, IDXGIOutput), CaptureError> {
        let mut flat = 0u32;
        let mut ai = 0u32;
        loop {
            let adapter = match unsafe { self.factory.EnumAdapters1(ai) } {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(e.into()),
            };
            let mut oi = 0u32;
            loop {
                match unsafe { adapter.EnumOutputs(oi) } {
                    Ok(output) => {
                        if flat == monitor_id {
                            return Ok((adapter, output));
                        }
                        flat += 1;
                        oi += 1;
                    }
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(e.into()),
                }
            }
            ai += 1;
        }
        Err(CaptureError::NoSuchMonitor(monitor_id))
    }

    /// Enumerate every attached output across every adapter, in a stable flat order.
    ///
    /// The flat index is the `MonitorInfo::id` used everywhere else in this module.
    pub fn enumerate_monitors(&self) -> Result<Vec<MonitorInfo>, CaptureError> {
        let mut out = Vec::new();
        let mut flat = 0u32;
        let mut ai = 0u32;
        loop {
            let adapter = match unsafe { self.factory.EnumAdapters1(ai) } {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(e.into()),
            };
            let mut oi = 0u32;
            loop {
                match unsafe { adapter.EnumOutputs(oi) } {
                    Ok(output) => {
                        // 0.58: `IDXGIOutput::GetDesc` returns `Result<DXGI_OUTPUT_DESC>`.
                        let desc = unsafe { output.GetDesc() }?;
                        out.push(monitor_info_from_desc(flat, &desc));
                        flat += 1;
                        oi += 1;
                    }
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(e.into()),
                }
            }
            ai += 1;
        }
        Ok(out)
    }

    /// Every attached output's desktop rectangle, in the same flat order as
    /// [`Self::enumerate_monitors`] / [`Self::find_output`]. `(left, top, right, bottom)` in
    /// virtual-desktop coordinates.
    ///
    /// This is how a **public monitor id is translated into a DXGI output**: the id space is owned
    /// by GDI's `EnumDisplayMonitors` (the only enumeration that sees indirect / DisplayLink
    /// displays), so the two orderings cannot be assumed to line up — see
    /// [`crate::capture_loop::CaptureLoop::monitors`]. Rects are the shared language: both APIs
    /// report the same virtual-desktop coordinates for the same panel.
    pub(crate) fn output_rects(&self) -> Result<Vec<(i32, i32, i32, i32)>, CaptureError> {
        Ok(self.outputs()?.into_iter().map(|(_, r)| r).collect())
    }

    /// Every attached output as `(owning adapter's description, desktop rect)`, in flat order.
    ///
    /// The adapter name is carried for the `agent_host monitors` diagnostic: which adapter drives
    /// which panel is the first thing worth knowing when Desktop Duplication misbehaves, because
    /// duplication is adapter-bound (see [`Self::ensure_duplication`]). Derived from the same walk
    /// as [`Self::output_rects`] so the two orderings cannot drift apart.
    pub(crate) fn outputs(&self) -> Result<Vec<(String, (i32, i32, i32, i32))>, CaptureError> {
        let mut out = Vec::new();
        let mut ai = 0u32;
        loop {
            let adapter = match unsafe { self.factory.EnumAdapters1(ai) } {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(e.into()),
            };
            let adesc = unsafe { adapter.GetDesc1() }?;
            let len = adesc
                .Description
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(adesc.Description.len());
            let name = String::from_utf16_lossy(&adesc.Description[..len]);
            let mut oi = 0u32;
            loop {
                match unsafe { adapter.EnumOutputs(oi) } {
                    Ok(output) => {
                        let desc = unsafe { output.GetDesc() }?;
                        let r = desc.DesktopCoordinates;
                        out.push((name.clone(), (r.left, r.top, r.right, r.bottom)));
                        oi += 1;
                    }
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(e.into()),
                }
            }
            ai += 1;
        }
        Ok(out)
    }

    /// The flat output index whose desktop rect is exactly `want`, or `None` when no DXGI output
    /// covers it — the signal that this monitor is an **indirect display** (DisplayLink dock,
    /// Miracast, some virtual displays), which Desktop Duplication cannot see at all, and the
    /// caller must fall through to a tier that can (WGC or GDI).
    pub(crate) fn output_index_for_rect(
        &self,
        want: (i32, i32, i32, i32),
    ) -> Result<Option<u32>, CaptureError> {
        Ok(match_output_rect(&self.output_rects()?, want))
    }

    /// [`ScreenCapturer::capture_frame`] with the error KIND preserved, and one device-loss
    /// rebuild+retry.
    ///
    /// The trait method flattens every failure into `PlatformError::CaptureUnavailable`, which
    /// throws away the one distinction the tier selector needs: **a timeout is not a broken tier.**
    /// DXGI yields a frame only when the screen CHANGES, so an idle desktop times out perpetually —
    /// and a caller that reads that as failure tears the duplication down and rebuilds it on every
    /// single frame of an idle session, which is both expensive and the moment dirty-rect state is
    /// lost. `Ok(None)` and `Err(Timeout)` mean "nothing new, ask again"; everything else means the
    /// duplication should be discarded.
    pub fn capture_frame_typed(
        &mut self,
        monitor_id: u32,
    ) -> Result<Option<CapturedFrame>, CaptureError> {
        let timeout = DEFAULT_CAPTURE_TIMEOUT;
        // Surface a device-loss (as opposed to duplication access-loss) by rebuilding the
        // device and retrying once.
        match DxgiCapturer::capture(self, monitor_id, timeout) {
            Err(CaptureError::Windows(ref e)) if is_device_removed(e) => {
                self.recreate()?;
                DxgiCapturer::capture(self, monitor_id, timeout)
            }
            other => other,
        }
    }

    /// Acquire one frame for `monitor_id`, blocking up to `timeout`.
    ///
    /// Returns:
    /// * `Ok(Some(frame))` — a fresh frame (or an accumulated-metadata-only frame with the
    ///   previous pixels; DDA can report `LastPresentTime == 0` meaning "only the mouse
    ///   moved"). Callers decide whether to re-encode.
    /// * `Ok(None)` — nothing new within `timeout` was distinguishable from an empty frame.
    /// * `Err(Timeout)` — nothing new within `timeout`.
    /// * `Err(AccessLost)` — duplication invalidated; it has already been dropped, so simply
    ///   call again to recreate.
    pub fn capture(
        &mut self,
        monitor_id: u32,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, CaptureError> {
        self.ensure_duplication(monitor_id)?;

        let acquire = self.acquire(monitor_id, timeout);
        match acquire {
            Ok(frame) => Ok(frame),
            Err(CaptureError::AccessLost) => {
                // First-class recreate path: drop the duplication so the *next* call rebuilds
                // it. Surface AccessLost so the caller can, e.g., request a keyframe.
                tracing::debug!(monitor_id, "DXGI_ERROR_ACCESS_LOST — dropping duplication");
                self.dupl = None;
                self.active_monitor = None;
                Err(CaptureError::AccessLost)
            }
            Err(e) => Err(e),
        }
    }

    /// Inner acquire/copy/release, factored out so `capture` can uniformly handle the
    /// `ACCESS_LOST` recreate. Assumes `ensure_duplication` already ran.
    fn acquire(
        &mut self,
        monitor_id: u32,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, CaptureError> {
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;

        // Pull the interfaces we need out of `self.dupl` up front to keep the borrow checker
        // happy while we also touch `self.device`/`self.context` during readback.
        let (dupl, desc) = {
            let d = self
                .dupl
                .as_ref()
                .ok_or(CaptureError::NoSuchMonitor(monitor_id))?;
            (d.dupl.clone(), d.desc)
        };

        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // AcquireNextFrame blocks up to timeout_ms. WAIT_TIMEOUT and ACCESS_LOST are both
        // returned here and classified by `from_dxgi`.
        unsafe { dupl.AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource) }
            .map_err(CaptureError::from_dxgi)?;
        if let Some(d) = self.dupl.as_mut() {
            d.frame_held = true;
        }

        // From here we must ReleaseFrame before returning (guard with a scope + explicit
        // release below), otherwise the next AcquireNextFrame fails.
        let result = (|| -> Result<Option<CapturedFrame>, CaptureError> {
            // `LastPresentTime == 0` means the DESKTOP IMAGE DID NOT CHANGE since the last acquire —
            // the frame carries only pointer movement or accumulated metadata. Reading it out as a
            // picture is wrong twice over:
            //
            //  * the FIRST acquire after `DuplicateOutput` reports it, and the surface handed back
            //    is BLANK. Measured on this build box, reliably: a probe that took the first frame
            //    got a black image every time and the second frame was correct. Delivering that
            //    blank as the monitor's first frame means a technician connecting to an idle machine
            //    sees BLACK until something happens to move on screen — the caller has no way to
            //    tell it apart from a real capture of a dark desktop.
            //  * afterwards it is simply "the mouse moved", and re-encoding an unchanged image
            //    spends bandwidth on a picture the receiver already has.
            //
            // Reporting `Ok(None)` — no new frame — is what the caller already knows how to handle,
            // and on the first acquire it makes the tier selector fall through to a tier that yields
            // a real image immediately.
            // MEASURED on this build box, with the tier histogram of `agent_host monitors` as the
            // read-out: over a 12-frame burst per monitor with the screen actively changing, DXGI
            // reports `LastPresentTime == 0` exactly ONCE per monitor — the first acquire after
            // `DuplicateOutput` — and a real timestamp with `AccumulatedFrames` 2..4 for the rest.
            // So the gate costs one frame per duplication and nothing else: the histogram reads
            // `gdi-fallback x1  dxgi x11`, and on an idle screen `gdi-fallback x1  (no new frame) x11`.
            if frame_info.LastPresentTime == 0 {
                return Ok(None);
            }
            let resource = resource.ok_or_else(|| {
                CaptureError::Windows(windows::core::Error::from(DXGI_ERROR_NOT_FOUND))
            })?;
            let texture: ID3D11Texture2D = resource.cast()?;

            // Collect native dirty/move rects for the encoder's adaptive strategy.
            let dirty = self.dirty_rects(&dupl, &frame_info)?;

            // TODO(hardware): needs a real display to verify — the CPU readback below (staging
            // copy + Map + row memcpy) can only be exercised against a live GPU surface. On the
            // hot path this copy is skipped entirely: `texture` is handed straight to the
            // hardware encoder (ADR-006, zero-copy). We return the CPU pixels here for the
            // software-encoder fallback and for deterministic tests.
            let frame = self.readback(monitor_id, &texture, &desc, dirty, &frame_info)?;
            Ok(Some(frame))
        })();

        // Always release, regardless of readback outcome.
        // SAFETY: we hold exactly one acquired frame on `dupl`.
        let _ = unsafe { dupl.ReleaseFrame() };
        if let Some(d) = self.dupl.as_mut() {
            d.frame_held = false;
        }

        result
    }

    /// Query `GetFrameDirtyRects` into portable rectangles.
    ///
    /// The move rects (`GetFrameMoveRects`) are also available and matter for scroll-heavy
    /// content; wiring them is a follow-up. Returns an empty vec when the frame carried no
    /// dirty metadata (metadata-only / mouse-only updates).
    fn dirty_rects(
        &self,
        dupl: &IDXGIOutputDuplication,
        frame_info: &DXGI_OUTDUPL_FRAME_INFO,
    ) -> Result<Vec<DirtyRect>, CaptureError> {
        if frame_info.TotalMetadataBufferSize == 0 {
            return Ok(Vec::new());
        }
        // TODO(hardware): needs a real display to verify — dirty-rect metadata only appears on
        // a live duplication. The two-call size/fill pattern below is the documented API shape.
        let mut buf: Vec<RECT> = vec![RECT::default(); 64];
        let mut required: u32 = 0;
        let byte_cap = (buf.len() * std::mem::size_of::<RECT>()) as u32;
        let res = unsafe {
            dupl.GetFrameDirtyRects(byte_cap, buf.as_mut_ptr(), &mut required)
        };
        if let Err(e) = res {
            // A too-small buffer returns DXGI_ERROR_MORE_DATA in `required`; on any error we
            // degrade gracefully to "whole frame dirty" rather than failing the capture.
            tracing::trace!(?e, "GetFrameDirtyRects failed; treating frame as fully dirty");
            return Ok(Vec::new());
        }
        let count = (required as usize) / std::mem::size_of::<RECT>();
        Ok(buf
            .into_iter()
            .take(count)
            .map(|r| DirtyRect {
                x: r.left,
                y: r.top,
                width: (r.right - r.left).max(0) as u32,
                height: (r.bottom - r.top).max(0) as u32,
            })
            .collect())
    }

    /// Copy the GPU texture to a CPU-readable staging texture and memcpy the rows out.
    fn readback(
        &mut self,
        monitor_id: u32,
        texture: &ID3D11Texture2D,
        _dupl_desc: &DXGI_OUTDUPL_DESC,
        dirty: Vec<DirtyRect>,
        frame_info: &DXGI_OUTDUPL_FRAME_INFO,
    ) -> Result<CapturedFrame, CaptureError> {
        let mut tex_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut tex_desc) };
        let width = tex_desc.Width;
        let height = tex_desc.Height;

        self.ensure_staging(&tex_desc)?;
        let staging = self.staging.as_ref().expect("staging just ensured").clone();

        // GPU→CPU copy. This is the expensive part we avoid on the hardware-encode path.
        // SAFETY: both resources are live and dimension/format-compatible by construction.
        unsafe { self.context.CopyResource(&staging, texture) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: staging is USAGE_STAGING with CPU_ACCESS_READ; subresource 0 exists.
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }?;

        // TODO(hardware): needs a real display to verify — the row-by-row memcpy below reads
        // mapped VRAM staging memory. `RowPitch` is almost always > width*4 (alignment), so we
        // must copy row by row, not in one shot.
        //
        // NOTE(agent-core reconcile): `CapturedFrame` is `{ monitor_id, width, height, bytes,
        // is_keyframe }` — it has no `stride`/`format`/`dirty_rects` fields. We therefore emit
        // *tightly packed* BGRA8 rows into `bytes` (stride collapsed to width*4 during the
        // copy), and fold the dirty/present metadata into `is_keyframe`. The pixel format
        // (BGRA8, the desktop `B8G8R8A8_UNORM` surface) is documented here rather than carried.
        let stride = (width as usize) * 4; // packed output stride (BGRA8), no padding
        let mut bytes = vec![0u8; stride * height as usize];
        // SAFETY: mapped.pData points to at least RowPitch*height readable bytes; we copy
        // exactly `stride` per row within that bound.
        unsafe {
            let src = mapped.pData as *const u8;
            for row in 0..height as usize {
                let src_row = src.add(row * mapped.RowPitch as usize);
                let dst = &mut bytes[row * stride..row * stride + stride];
                std::ptr::copy_nonoverlapping(src_row, dst.as_mut_ptr(), stride);
            }
            self.context.Unmap(&staging, 0);
        }

        // A frame with no dirty metadata (or a fresh duplication) is treated as a standalone
        // keyframe; a partial update carrying dirty rects is a delta on the previous frame.
        // `LastPresentTime == 0` means "no new desktop image this frame" (mouse-only update).
        let desktop_updated = frame_info.LastPresentTime != 0;
        let is_keyframe = dirty.is_empty();
        tracing::trace!(
            monitor_id,
            width,
            height,
            dirty = dirty.len(),
            desktop_updated,
            "captured frame"
        );

        Ok(CapturedFrame {
            monitor_id,
            width,
            height,
            bytes,
            is_keyframe,
        })
    }

    /// Ensure a staging texture matching `desc` (same format, CPU-readable) exists.
    fn ensure_staging(&mut self, src: &D3D11_TEXTURE2D_DESC) -> Result<(), CaptureError> {
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
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }?;
        self.staging = tex;
        self.staging_dims = (src.Width, src.Height);
        Ok(())
    }
}

/// A portable dirty rectangle in output pixels.
///
/// Fields are captured from the DXGI metadata for the encoder's future dirty-rect strategy
/// (ADR-006); only the *count* is consumed today (to decide keyframe vs delta), so the
/// coordinates are intentionally retained but not yet read.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct DirtyRect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

/// Create a D3D11 device+context on `adapter`.
///
/// Passing an explicit adapter requires `D3D_DRIVER_TYPE_UNKNOWN` (the driver type is implied
/// by the adapter); `HARDWARE` is only valid with a null adapter. We request feature level
/// 11.1 falling back to 11.0, and `BGRA_SUPPORT` for the desktop's `B8G8R8A8_UNORM` surface.
fn create_device(
    adapter: &IDXGIAdapter1,
) -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
    let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;

    // Try the explicit adapter first (UNKNOWN driver type). If that fails, fall back to the
    // default hardware device (null adapter, HARDWARE driver type).
    let attempt = unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    };
    if attempt.is_err() {
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
            )
        }?;
    }

    Ok((
        device.expect("device out-param set on success"),
        context.expect("context out-param set on success"),
    ))
}

/// Build a portable [`MonitorInfo`] from a DXGI output descriptor.
/// The adapter's LUID — the OS's stable identity for a graphics adapter, and the only sound way to
/// ask "is this the same adapter?" (`IDXGIAdapter1` COM pointers are not guaranteed to compare
/// equal across separate `EnumAdapters1` walks).
fn adapter_luid(adapter: &IDXGIAdapter1) -> Result<(u32, i32), CaptureError> {
    // SAFETY: `adapter` is a live COM interface; GetDesc1 fills the descriptor by out-param.
    let desc = unsafe { adapter.GetDesc1() }?;
    Ok((desc.AdapterLuid.LowPart, desc.AdapterLuid.HighPart))
}

/// Find the index of the output rect that exactly equals `want`.
///
/// Exact equality, not overlap or containment: two panels can never share a virtual-desktop rect,
/// and a *detached* DXGI output reports `(0,0,0,0)` — which a real monitor rect can never equal,
/// so detached outputs are excluded without a special case. A near-match would be a mis-identified
/// panel, which is worse than falling through to a tier that captures by rect directly.
///
/// Split out of [`DxgiCapturer::output_index_for_rect`] because the mapping is the part that can be
/// wrong (and the part hardware would hide): it is pure, so it is tested.
pub(crate) fn match_output_rect(
    rects: &[(i32, i32, i32, i32)],
    want: (i32, i32, i32, i32),
) -> Option<u32> {
    rects.iter().position(|r| *r == want).map(|i| i as u32)
}

fn monitor_info_from_desc(id: u32, desc: &DXGI_OUTPUT_DESC) -> MonitorInfo {
    let r = desc.DesktopCoordinates;
    // `left`/`top` are the monitor's origin in the VIRTUAL DESKTOP (can be negative). They are what
    // lets the input remap place a controller's frame-normalized pointer on the correct monitor when
    // more than one exists — without them, injection spreads 0..65535 across the whole virtual desktop
    // and every click on a non-primary monitor lands offset. See the host's input-remap.
    // TODO(hardware): a real DPI scale comes from `GetDpiForMonitor(desc.Monitor, ...)`; DXGI's
    // output desc doesn't carry it, so we report 1.0 (96 DPI) until wired to a live monitor.
    MonitorInfo {
        id,
        width: (r.right - r.left).max(0) as u32,
        height: (r.bottom - r.top).max(0) as u32,
        dpi_scale: 1.0,
        left: r.left,
        top: r.top,
    }
}

impl ScreenCapturer for DxgiCapturer {
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        Ok(self.enumerate_monitors()?)
    }

    /// Pull one frame for `monitor_id`. Adapts the timeout-driven [`DxgiCapturer::capture`]
    /// pull API onto the core's parameterless `capture_frame`: a device-loss triggers one
    /// rebuild+retry, and a "no new frame within the default timeout" surfaces as the
    /// retryable [`PlatformError::CaptureUnavailable`].
    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
        match self.capture_frame_typed(monitor_id)? {
            Some(frame) => Ok(frame),
            None => Err(PlatformError::CaptureUnavailable(
                "no new frame within timeout".to_string(),
            )),
        }
    }
}

/// Whether an error is a D3D device-removed/reset (as distinct from duplication access-loss).
fn is_device_removed(e: &windows::core::Error) -> bool {
    use windows::Win32::Graphics::Dxgi::{DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_DEVICE_RESET};
    let c = e.code();
    c == DXGI_ERROR_DEVICE_REMOVED || c == DXGI_ERROR_DEVICE_RESET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_rect_dimensions_are_non_negative() {
        // Pure conversion sanity: an inverted RECT clamps to zero rather than underflowing.
        let r = RECT { left: 100, top: 50, right: 40, bottom: 20 };
        let w = (r.right - r.left).max(0) as u32;
        let h = (r.bottom - r.top).max(0) as u32;
        assert_eq!((w, h), (0, 0));
    }

    #[test]
    fn monitor_info_maps_dimensions() {
        let mut desc = DXGI_OUTPUT_DESC::default();
        desc.DesktopCoordinates = RECT { left: -1920, top: 0, right: 0, bottom: 1080 };
        let info = monitor_info_from_desc(3, &desc);
        assert_eq!(info.id, 3);
        assert_eq!((info.width, info.height), (1920, 1080));
        assert_eq!(info.dpi_scale, 1.0);
    }

    #[test]
    fn output_rect_match_survives_a_reordered_dxgi_enumeration() {
        // THE trap this whole translation exists for. GDI publishes ids left-to-right; DXGI hands
        // its outputs back in adapter/output order, which here is the REVERSE. If capture selected
        // "the Nth DXGI output" for "the Nth published monitor" it would stream the wrong panel —
        // and every frame would still look like a valid screen, so nothing downstream would notice.
        let dxgi = [
            (1920, 0, 4480, 1440), // DXGI output 0 = the RIGHT panel
            (0, 0, 1920, 1080),    // DXGI output 1 = the primary
        ];
        // Published id 0 is the primary (leftmost) → DXGI output 1, not 0.
        assert_eq!(match_output_rect(&dxgi, (0, 0, 1920, 1080)), Some(1));
        // Published id 1 is the right panel → DXGI output 0.
        assert_eq!(match_output_rect(&dxgi, (1920, 0, 4480, 1440)), Some(0));
    }

    #[test]
    fn an_indirect_display_has_no_dxgi_output() {
        // A DisplayLink/dock panel enumerates in GDI but has no Desktop Duplication output at all;
        // the mapping must say so (None → fall through to a tier that can capture it) rather than
        // pick the closest output.
        let dxgi = [(0, 0, 1920, 1080)];
        assert_eq!(match_output_rect(&dxgi, (1920, 0, 3840, 1080)), None);
        // Not fooled by a same-origin, different-size panel either.
        assert_eq!(match_output_rect(&dxgi, (0, 0, 2560, 1440)), None);
    }

    #[test]
    fn a_detached_output_never_matches_a_real_monitor() {
        // Detached outputs report an empty rect. A real monitor rect is never empty, so they drop
        // out of the match without a special case — but the primary's (0,0,...) origin makes this
        // worth pinning: a sloppy "left/top only" match would pick the detached output.
        let dxgi = [(0, 0, 0, 0), (0, 0, 1920, 1080)];
        assert_eq!(match_output_rect(&dxgi, (0, 0, 1920, 1080)), Some(1));
    }

    #[test]
    fn a_single_monitor_box_still_maps_to_output_zero() {
        // The regression that must not move: one display at the origin → DXGI output 0, exactly
        // the index the pre-multimonitor code hardcoded.
        let dxgi = [(0, 0, 1920, 1080)];
        assert_eq!(match_output_rect(&dxgi, (0, 0, 1920, 1080)), Some(0));
    }

    #[test]
    #[ignore = "needs real hardware"]
    fn enumerate_and_capture_smoke() {
        // TODO(hardware): needs a real display to verify. Exercises the full live path:
        // create device → enumerate → duplicate → acquire → readback.
        let cap = DxgiCapturer::new().expect("create capturer");
        let mons = cap.enumerate_monitors().expect("enumerate");
        assert!(!mons.is_empty(), "expected at least one monitor");
        let mut cap = cap;
        // May legitimately return Timeout on a fully idle desktop; loop briefly.
        let mut got = false;
        for _ in 0..30 {
            match cap.capture(mons[0].id, Duration::from_millis(100)) {
                Ok(Some(frame)) => {
                    assert_eq!(frame.monitor_id, mons[0].id);
                    assert_eq!(frame.bytes.len(), (frame.width * frame.height * 4) as usize);
                    got = true;
                    break;
                }
                Ok(None) | Err(CaptureError::Timeout) | Err(CaptureError::AccessLost) => continue,
                Err(e) => panic!("capture failed: {e}"),
            }
        }
        assert!(got, "never captured a frame");
    }
}
