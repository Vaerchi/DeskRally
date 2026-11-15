//! Software **VP8** decode (libvpx) — the receiving half of the [`super::vp8`] encoder.
//!
//! It is deliberately NOT on the streaming hot path (browsers and `stream_probe` decode for us);
//! it exists so the codec seam can be exercised end to end off-wire:
//! * the `vp8_roundtrip` verification bin captures a real desktop, encodes it with the *shipping*
//!   [`super::Vp8Encoder`] settings, decodes it here, and writes the result out to be eyeballed;
//! * a decode round-trip test can assert real pixels survive encode→decode, not just that the
//!   BGRA→I420 conversion math is correct in isolation (see `color.rs`).
//!
//! Same libvpx-ABI hazard as the encoder: `env-libvpx-sys` ships bindings for libvpx ≤ 1.13.0 while
//! we link 1.16.0, and `vpx_codec_dec_init_ver` rejects a stale `VPX_DECODER_ABI_VERSION` outright.
//! [`Vp8Decoder::new`] discovers the version the linked library accepts, exactly as
//! `vp8::encoder_abi_version` does for the encoder.

use std::ffi::CStr;
use std::os::raw::{c_int, c_long, c_uint};

use vpx_sys as vpx;

/// A decoded frame, converted back to the tightly packed **BGRA8** the capturers speak (so it can
/// be diffed against the encoder's input or written straight into a bitmap).
pub struct DecodedFrame {
    pub width: usize,
    pub height: usize,
    /// `width * height * 4` bytes, BGRA order, rows top-down and tightly packed.
    pub bgra: Vec<u8>,
}

/// A stateful libvpx VP8 decoder. Not `Send` (raw C context) — own it on one thread, like the
/// encoder.
pub struct Vp8Decoder {
    ctx: Option<Box<vpx::vpx_codec_ctx_t>>,
}

impl Vp8Decoder {
    /// Initialise the VP8 decoder, resolving the decoder ABI version the linked libvpx accepts.
    pub fn new() -> Result<Self, String> {
        // SAFETY: `vpx_codec_vp8_dx` returns a pointer to a static interface descriptor or NULL.
        let iface = unsafe { vpx::vpx_codec_vp8_dx() };
        if iface.is_null() {
            return Err("vpx_codec_vp8_dx returned null".to_string());
        }
        let from_bindings = vpx::VPX_DECODER_ABI_VERSION as c_int;
        let candidates = std::iter::once(from_bindings).chain((1..=80).filter(|v| *v != from_bindings));
        let mut ctx: Box<vpx::vpx_codec_ctx_t> = Box::new(unsafe { std::mem::zeroed() });
        for ver in candidates {
            // SAFETY: a freshly zeroed context each attempt (libvpx inspects `priv`, which must be
            // NULL going in); a NULL `cfg` asks for defaults. On `VPX_CODEC_ABI_MISMATCH` libvpx
            // allocates nothing; on success the context is live and we keep it.
            *ctx = unsafe { std::mem::zeroed() };
            let res = unsafe {
                vpx::vpx_codec_dec_init_ver(ctx.as_mut() as *mut _, iface, std::ptr::null(), 0, ver)
            };
            if res == vpx::VPX_CODEC_OK {
                return Ok(Self { ctx: Some(ctx) });
            }
            if res != vpx::VPX_CODEC_ABI_MISMATCH {
                return Err(format!("vpx_codec_dec_init_ver (decoder ABI {ver}): {}", err_str(res)));
            }
        }
        Err(format!(
            "no VPX_DECODER_ABI_VERSION in 1..=80 was accepted by the linked libvpx \
             (bindings say {from_bindings}); the installed libvpx is incompatible with env-libvpx-sys"
        ))
    }

    /// Decode one compressed VP8 frame. Returns the decoded picture, or `None` if this frame
    /// produced no output image (should not happen for a complete VP8 frame).
    pub fn decode(&mut self, data: &[u8]) -> Result<Option<DecodedFrame>, String> {
        let ctx = self.ctx.as_mut().ok_or("VP8 decoder context missing")?;
        // SAFETY: live context; `data`/len describe a readable slice; NULL user data; `0` deadline
        // means decode to completion (there is no realtime budget on this off-wire path).
        let res = unsafe {
            vpx::vpx_codec_decode(
                ctx.as_mut() as *mut _,
                data.as_ptr(),
                data.len() as c_uint,
                std::ptr::null_mut(),
                0 as c_long,
            )
        };
        if res != vpx::VPX_CODEC_OK {
            return Err(format!("vpx_codec_decode: {}", err_str(res)));
        }
        let mut iter: vpx::vpx_codec_iter_t = std::ptr::null();
        // SAFETY: standard get_frame iteration; `iter` starts NULL and is only handed back here.
        let img = unsafe { vpx::vpx_codec_get_frame(ctx.as_mut() as *mut _, &mut iter) };
        if img.is_null() {
            return Ok(None);
        }
        // SAFETY: libvpx owns `*img` until the next call into the codec; we read it out immediately.
        let img = unsafe { &*img };
        Ok(Some(i420_to_bgra(img)))
    }
}

impl Drop for Vp8Decoder {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.as_mut() {
            // SAFETY: the context is live and owned solely by us; destroyed exactly once.
            unsafe {
                vpx::vpx_codec_destroy(ctx.as_mut() as *mut _);
            }
        }
    }
}

/// Convert a libvpx I420 image to tightly packed BGRA8 using the **BT.601 studio-range** inverse of
/// what `color.rs` encoded — matching the `cs = BT_601, range = STUDIO` the encoder declared, which
/// is also what every VP8 decoder assumes. Integer coefficients (ITU-R BT.601).
fn i420_to_bgra(img: &vpx::vpx_image_t) -> DecodedFrame {
    let w = img.d_w as usize;
    let h = img.d_h as usize;
    let (ys, us, vs) = (img.stride[0] as usize, img.stride[1] as usize, img.stride[2] as usize);
    // SAFETY: the planes describe at least `stride*height` (Y) / `stride*ceil(h/2)` (U,V) bytes.
    let y_plane = unsafe { std::slice::from_raw_parts(img.planes[0], ys * h) };
    let u_plane = unsafe { std::slice::from_raw_parts(img.planes[1], us * h.div_ceil(2)) };
    let v_plane = unsafe { std::slice::from_raw_parts(img.planes[2], vs * h.div_ceil(2)) };

    let mut bgra = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let yy = y_plane[y * ys + x] as i32 - 16;
            let uu = u_plane[(y / 2) * us + (x / 2)] as i32 - 128;
            let vv = v_plane[(y / 2) * vs + (x / 2)] as i32 - 128;
            let c = 298 * yy;
            let r = ((c + 409 * vv + 128) >> 8).clamp(0, 255) as u8;
            let g = ((c - 100 * uu - 208 * vv + 128) >> 8).clamp(0, 255) as u8;
            let b = ((c + 516 * uu + 128) >> 8).clamp(0, 255) as u8;
            let o = (y * w + x) * 4;
            bgra[o] = b;
            bgra[o + 1] = g;
            bgra[o + 2] = r;
            bgra[o + 3] = 0xFF;
        }
    }
    DecodedFrame { width: w, height: h, bgra }
}

/// libvpx's own string for an error code (self-contained twin of `vp8::err_str`).
fn err_str(res: vpx::vpx_codec_err_t) -> String {
    // SAFETY: `vpx_codec_err_to_string` returns a static NUL-terminated string for every input.
    let p = unsafe { vpx::vpx_codec_err_to_string(res) };
    if p.is_null() {
        return format!("{res:?}");
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::{VideoEncoder, Vp8Encoder};

    /// The real end-to-end proof the codec preserves colour: encode actual BGRA through the SHIPPING
    /// encoder, decode it here, and check a flat field comes back within lossy tolerance. `color.rs`
    /// only checks the BGRA→I420 math in isolation; this closes the loop through libvpx both ways.
    #[test]
    fn encode_then_decode_recovers_a_solid_colour() {
        let (w, h) = (128usize, 96usize);
        let (b, g, r) = (40u8, 160u8, 200u8);
        let mut src = vec![0u8; w * h * 4];
        for px in src.chunks_mut(4) {
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 0xFF;
        }
        let mut enc = Vp8Encoder::new(3_000_000).expect("encoder");
        enc.request_keyframe();
        let au = enc.encode_bgra(&src, w, h, 3000).expect("encode");
        assert!(au.keyframe, "forced a keyframe");

        let mut dec = Vp8Decoder::new().expect("decoder");
        let frame = dec.decode(&au.data).expect("decode ok").expect("a decoded image");
        assert_eq!((frame.width, frame.height), (w, h), "dimensions round-trip");

        // A flat field survives VP8 near-exactly; allow a small quantiser/round-trip delta.
        let o = ((h / 2) * w + w / 2) * 4;
        let (db, dg, dr) = (frame.bgra[o] as i32, frame.bgra[o + 1] as i32, frame.bgra[o + 2] as i32);
        assert!((db - b as i32).abs() <= 12, "B {db} vs {b}");
        assert!((dg - g as i32).abs() <= 12, "G {dg} vs {g}");
        assert!((dr - r as i32).abs() <= 12, "R {dr} vs {r}");
        assert_eq!(frame.bgra[o + 3], 0xFF, "opaque alpha");
    }
}
