//! The real Direct3D / DXGI side of the canvas (docs/52): a [`DdaFactory`] that duplicates the
//! output whose desktop rect is exactly a monitor's rect, on the adapter that owns it, and a
//! [`DdaSource`] that does a NON-blocking acquire and reads the image back. Plus the [`GdiReader`]
//! the canvas uses for seeding, self-checks and GDI regions.
//!
//! Everything here runs on the capture thread (the `FollowingCapturer` thread, bound to the input
//! desktop). DDA does not affect that thread's `SetThreadDesktop` (measured:
//! `dxgi_leaves_the_thread_able_to_switch_desktops`), unlike WGC.

use std::collections::HashMap;

use windows::core::Interface;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION_IDENTITY};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_DEVICE_RESET,
    DXGI_ERROR_NOT_FOUND, DXGI_ERROR_UNSUPPORTED, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    DXGI_OUTDUPL_MOVE_RECT,
};
use windows::Win32::Foundation::RECT;

use crate::capture_gdi::GdiCapturer;
use crate::dxgi_canvas::{DdaCreateError, DdaError, DdaFactory, DdaSource, GdiReader, Rect};

/// One adapter's D3D11 device, shared by every duplication of that adapter's outputs.
struct AdapterDevice {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
}

/// Creates duplications by exact rect match; keeps one device per adapter (keyed by LUID).
pub(crate) struct DxgiFactory {
    factory: IDXGIFactory1,
    devices: HashMap<u64, AdapterDevice>,
}

impl DxgiFactory {
    pub(crate) fn new() -> Result<Self, String> {
        // SAFETY: plain factory creation; no arguments to validate.
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(|e| format!("CreateDXGIFactory1: {e}"))?;
        Ok(Self { factory, devices: HashMap::new() })
    }

    /// The output whose desktop rect is exactly `rect`, with its adapter. Exact equality only: a
    /// near-match would be a mis-identified panel (the "blink" was two tiers disagreeing about which
    /// panel an id meant), and a detached output reports (0,0,0,0), which no real rect equals.
    fn find(&self, rect: Rect) -> Result<Option<(IDXGIAdapter1, IDXGIOutput)>, String> {
        let want = (rect.x, rect.y, rect.x + rect.w as i32, rect.y + rect.h as i32);
        let mut ai = 0u32;
        loop {
            // SAFETY: enumeration by index; NOT_FOUND ends the walk.
            let adapter = match unsafe { self.factory.EnumAdapters1(ai) } {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => return Ok(None),
                Err(e) => return Err(format!("EnumAdapters1: {e}")),
            };
            let mut oi = 0u32;
            loop {
                // SAFETY: as above.
                match unsafe { adapter.EnumOutputs(oi) } {
                    Ok(output) => {
                        // SAFETY: GetDesc fills a descriptor for a live output.
                        let d = unsafe { output.GetDesc() }.map_err(|e| format!("output GetDesc: {e}"))?;
                        let r = d.DesktopCoordinates;
                        if (r.left, r.top, r.right, r.bottom) == want {
                            return Ok(Some((adapter, output)));
                        }
                        oi += 1;
                    }
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(format!("EnumOutputs: {e}")),
                }
            }
            ai += 1;
        }
    }

    /// The device on `adapter` itself. NO fallback to another adapter: `DuplicateOutput` needs the
    /// owning adapter's device, and a default-adapter device would fail later with a vague error.
    fn device_for(&mut self, adapter: &IDXGIAdapter1) -> Result<(u64, &AdapterDevice), String> {
        // SAFETY: GetDesc1 fills the descriptor of a live adapter.
        let desc = unsafe { adapter.GetDesc1() }.map_err(|e| format!("adapter GetDesc1: {e}"))?;
        let luid = (u64::from(desc.AdapterLuid.HighPart as u32) << 32) | u64::from(desc.AdapterLuid.LowPart);
        if !self.devices.contains_key(&luid) {
            let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            // SAFETY: explicit adapter with UNKNOWN driver type, as D3D requires; out-params are ours.
            unsafe {
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
            }
            .map_err(|e| format!("D3D11CreateDevice on the owning adapter: {e}"))?;
            let (Some(device), Some(context)) = (device, context) else {
                return Err("D3D11CreateDevice returned no device".into());
            };
            self.devices.insert(luid, AdapterDevice { device, context });
        }
        Ok((luid, &self.devices[&luid]))
    }
}

impl DdaFactory for DxgiFactory {
    fn create(&mut self, rect: Rect) -> Result<(Box<dyn DdaSource>, u64), DdaCreateError> {
        let Some((adapter, output)) = self.find(rect).map_err(DdaCreateError::Failed)? else {
            return Err(DdaCreateError::Unsupported("no DXGI output with this exact rect (indirect display?)".into()));
        };
        let output1: IDXGIOutput1 = output.cast().map_err(|e| DdaCreateError::Failed(format!("IDXGIOutput1: {e}")))?;
        let (luid, dev) = self.device_for(&adapter).map_err(DdaCreateError::Failed)?;
        let (device, context) = (dev.device.clone(), dev.context.clone());
        // SAFETY: the device lives on the adapter that owns this output.
        let dupl = match unsafe { output1.DuplicateOutput(&device) } {
            Ok(d) => d,
            Err(e) if e.code() == DXGI_ERROR_UNSUPPORTED => {
                return Err(DdaCreateError::Unsupported(format!("DuplicateOutput unsupported: {e}")))
            }
            Err(e) => return Err(DdaCreateError::Failed(format!("DuplicateOutput: {e}"))),
        };
        // SAFETY: GetDesc returns the duplication's descriptor by value.
        let desc = unsafe { dupl.GetDesc() };
        // IDENTITY only (docs/52 §4.1): anything else, including UNSPECIFIED, is served by GDI.
        let rot = desc.Rotation;
        if rot != DXGI_MODE_ROTATION_IDENTITY {
            return Err(DdaCreateError::Unsupported(format!("rotated output ({})", rot.0)));
        }
        if desc.ModeDesc.Width != rect.w || desc.ModeDesc.Height != rect.h {
            return Err(DdaCreateError::Unsupported(format!(
                "mode {}x{} differs from the monitor rect {}x{}",
                desc.ModeDesc.Width, desc.ModeDesc.Height, rect.w, rect.h
            )));
        }
        if desc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(DdaCreateError::Unsupported(format!("format {}", desc.ModeDesc.Format.0)));
        }
        Ok((Box::new(DxgiSource { dupl, device, context, staging: None, w: rect.w, h: rect.h }), luid))
    }

    fn reset_adapter(&mut self, adapter: u64) {
        self.devices.remove(&adapter);
    }
}

/// One output's duplication.
struct DxgiSource {
    dupl: IDXGIOutputDuplication,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    staging: Option<ID3D11Texture2D>,
    w: u32,
    h: u32,
}

fn dda_error(e: &windows::core::Error) -> DdaError {
    let c = e.code();
    if c == DXGI_ERROR_ACCESS_LOST {
        DdaError::AccessLost
    } else if c == DXGI_ERROR_DEVICE_REMOVED || c == DXGI_ERROR_DEVICE_RESET {
        DdaError::DeviceLost
    } else {
        DdaError::Other
    }
}

impl DxgiSource {
    /// The areas this frame changed, region-local: dirty rects plus the DESTINATION of every move
    /// rect (the acquired texture is the complete current image, so copying a moved area's destination
    /// from it is exact). `None` = copy everything (no metadata, an API error, or most of the region).
    fn changed_rects(&self, info: &DXGI_OUTDUPL_FRAME_INFO) -> Option<Vec<Rect>> {
        let size = info.TotalMetadataBufferSize as usize;
        if size == 0 {
            return None;
        }
        let mut rects = Vec::new();
        let mut moves = vec![DXGI_OUTDUPL_MOVE_RECT::default(); size / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>() + 1];
        let mut used = 0u32;
        // SAFETY: the buffer holds `moves.len()` entries; `used` receives the bytes written.
        unsafe { self.dupl.GetFrameMoveRects((moves.len() * std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32, moves.as_mut_ptr(), &mut used) }.ok()?;
        for m in &moves[..used as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()] {
            rects.push(m.DestinationRect);
        }
        let mut dirty = vec![RECT::default(); size / std::mem::size_of::<RECT>() + 1];
        // SAFETY: as above.
        unsafe { self.dupl.GetFrameDirtyRects((dirty.len() * std::mem::size_of::<RECT>()) as u32, dirty.as_mut_ptr(), &mut used) }.ok()?;
        rects.extend_from_slice(&dirty[..used as usize / std::mem::size_of::<RECT>()]);
        if rects.is_empty() {
            return None;
        }
        let mut area = 0u64;
        let mut out = Vec::with_capacity(rects.len());
        for r in rects {
            let (l, t) = (r.left.clamp(0, self.w as i32), r.top.clamp(0, self.h as i32));
            let (rr, b) = (r.right.clamp(0, self.w as i32), r.bottom.clamp(0, self.h as i32));
            if rr <= l || b <= t {
                continue;
            }
            area += ((rr - l) as u64) * ((b - t) as u64);
            out.push(Rect { x: l, y: t, w: (rr - l) as u32, h: (b - t) as u32 });
        }
        // Mostly changed (or overlapping heavily): one whole-region copy is cheaper than many.
        if out.is_empty() || area * 2 > u64::from(self.w) * u64::from(self.h) {
            return None;
        }
        Some(out)
    }
}

impl DdaSource for DxgiSource {
    fn acquire(&mut self, out: &mut [u8], timeout_ms: u32) -> Result<Option<Vec<Rect>>, DdaError> {
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // Timeout 0 on every regular call: the producer already paces to the viewers' demand and an
        // idle output must never make a capture call wait (docs/52 §4.2). Only a self-check grace waits.
        // SAFETY: a live duplication; out-params are ours.
        match unsafe { self.dupl.AcquireNextFrame(timeout_ms, &mut info, &mut resource) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) => return Err(dda_error(&e)),
        }
        let result = (|| -> Result<Option<Vec<Rect>>, DdaError> {
            // LastPresentTime == 0: no new desktop image (the blank first frame, or pointer-only).
            if info.LastPresentTime == 0 {
                return Ok(None);
            }
            let changed = self.changed_rects(&info);
            let texture: ID3D11Texture2D = resource.as_ref().ok_or(DdaError::Other)?.cast().map_err(|_| DdaError::Other)?;
            let mut td = D3D11_TEXTURE2D_DESC::default();
            // SAFETY: GetDesc on a live texture.
            unsafe { texture.GetDesc(&mut td) };
            // Every image must still be exactly the region (a mode change can arrive without ACCESS_LOST).
            if td.Width != self.w || td.Height != self.h || td.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
                return Err(DdaError::AccessLost);
            }
            if self.staging.is_none() {
                let mut sd = td;
                sd.Usage = D3D11_USAGE_STAGING;
                sd.BindFlags = 0;
                sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
                sd.MiscFlags = 0;
                let mut tex: Option<ID3D11Texture2D> = None;
                // SAFETY: a valid staging descriptor; no initial data.
                unsafe { self.device.CreateTexture2D(&sd, None, Some(&mut tex)) }.map_err(|e| dda_error(&e))?;
                self.staging = tex;
            }
            let staging = self.staging.as_ref().ok_or(DdaError::Other)?;
            // SAFETY: same size and format by the checks above.
            unsafe { self.context.CopyResource(staging, &texture) };
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            // SAFETY: a CPU-readable staging texture, subresource 0.
            unsafe { self.context.Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }.map_err(|e| dda_error(&e))?;
            let row = self.w as usize * 4;
            let full = [Rect { x: 0, y: 0, w: self.w, h: self.h }];
            let rects: &[Rect] = changed.as_deref().unwrap_or(&full);
            // SAFETY: pData covers RowPitch*height bytes; every rect is clamped to the region, and
            // `out` is the region's tight size (the canvas allocates it so).
            unsafe {
                let src = mapped.pData as *const u8;
                for r in rects {
                    let (x, w) = (r.x as usize * 4, r.w as usize * 4);
                    for y in r.y as usize..(r.y as usize + r.h as usize) {
                        std::ptr::copy_nonoverlapping(src.add(y * mapped.RowPitch as usize + x), out[y * row + x..].as_mut_ptr(), w);
                    }
                }
                self.context.Unmap(staging, 0);
            }
            Ok(Some(rects.to_vec()))
        })();
        // Always release the acquired frame, whatever happened above. A release that reports the
        // duplication lost must be recreated even if the copy succeeded.
        // SAFETY: exactly one frame is held.
        match unsafe { self.dupl.ReleaseFrame() } {
            Err(e) if result.is_ok() => Err(dda_error(&e)),
            _ => result,
        }
    }
}

/// GDI reads for the canvas, through the cached-surface `GdiCapturer` (1.3.10): one capturer per
/// region size, so regions of different sizes do not rebuild each other's surface every read. The
/// whole reader is dropped with the canvas on a desktop switch, so no DC crosses desktops.
pub(crate) struct CanvasGdi {
    by_size: HashMap<(u32, u32), GdiCapturer>,
}

impl CanvasGdi {
    pub(crate) fn new() -> Self {
        Self { by_size: HashMap::new() }
    }
}

impl GdiReader for CanvasGdi {
    fn read(&mut self, rect: Rect, out: &mut [u8]) -> bool {
        let cap = self.by_size.entry((rect.w, rect.h)).or_default();
        match cap.capture_rect(rmt_agent_core::COMPOSITE_MONITOR_ID, rect.x, rect.y, rect.w as i32, rect.h as i32) {
            Ok(f) if f.bytes.len() == out.len() => {
                out.copy_from_slice(&f.bytes);
                true
            }
            _ => false,
        }
    }
}
