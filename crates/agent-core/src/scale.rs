//! Integer **box downscale** of a captured BGRA frame (M11 `scale_div`).
//!
//! # Where this runs, and why
//!
//! On the **capture thread**, immediately after capture and *before* the frame crosses into the
//! transport. `VideoFrameSender::send` clones `frame.bytes` — 8.3 MB per frame at 1080p, ~250 MB/s
//! at 30 fps — so downscaling first removes both the pixels and that memcpy. Scaling on the encoder
//! thread instead would pay the full-resolution clone every frame and buy nothing.
//!
//! # Box average, not nearest-neighbour
//!
//! Nearest-neighbour aliases one-pixel-wide text strokes into high-frequency noise, which *costs*
//! more bits at the same target while looking worse — the same trap `transport-webrtc`'s
//! `video/color.rs` already documents for chroma point-sampling. A k×k box average is one read per
//! **source** pixel regardless of `div`, so the cost does not grow with the divisor.
//!
//! # Input mapping is unaffected
//!
//! [`crate::platform::InputEvent::MouseMove`] carries absolute coordinates normalized to
//! `0..=65535` across the monitor, not pixels, so downscaling capture **cannot** desynchronize the
//! remote pointer. This is the first thing a reader will suspect; the codebase is structurally
//! immune.

use std::borrow::Cow;

use crate::platform::CapturedFrame;

/// Exact k×k box-average downscale of a packed BGRA frame, `k = div`.
///
/// * `div <= 1` returns [`Cow::Borrowed`] — **the default path copies nothing and touches no pixel**.
/// * Destination dimensions are `max(2, (src / div) & !1)`: even (so the VP8 encoder's odd-pixel
///   crop never trims a scaled frame) and at least 2 (so a tiny source cannot produce a 0-sized
///   frame the encoder would reject).
/// * A `bytes` buffer whose length is not exactly `width * height * 4` (shorter, or longer because
///   of a padded row pitch) is returned **unscaled** rather than mangled, so a capturer with a
///   padded pitch degrades to "scaling silently does nothing" instead of a sheared picture.
///
/// `is_keyframe` and `monitor_id` are carried through unchanged.
pub fn scale_bgra(frame: Cow<'_, CapturedFrame>, div: u32) -> Cow<'_, CapturedFrame> {
    let (sw, sh) = (frame.width as usize, frame.height as usize);
    let k = div as usize;
    if k <= 1 || sw == 0 || sh == 0 {
        return frame;
    }
    // Packed BGRA is what every ScreenCapturer in this project produces. Verify rather than assume:
    // a short buffer means our stride assumption is wrong, and averaging across a wrong stride
    // shears the image while looking plausible at div == 1.
    // A LONGER buffer is the padded-pitch case (rows are `pitch` bytes wide), and it would pass a
    // `<` check while the loops below read it with stride `sw * 4`, shearing the image.
    match sw.checked_mul(sh).and_then(|p| p.checked_mul(4)) {
        Some(expected) if frame.bytes.len() == expected => {}
        _ => return frame,
    }

    let dw = ((sw / k) & !1).max(2);
    let dh = ((sh / k) & !1).max(2);
    // A source too small to yield a distinct smaller frame: leave it alone rather than upscale.
    if dw >= sw || dh >= sh {
        return frame;
    }

    let src = &frame.bytes;
    let src_stride = sw * 4;
    let mut out = vec![0u8; dw * dh * 4];
    // Source extent of destination column `dx` / row `dy`, as an AREA MAP rather than a fixed
    // `dx * div` offset.
    //
    // This is not a stylistic choice. `dw`/`dh` are floored to even and then raised to a minimum of
    // 2, and that `.max(2)` can push the destination ABOVE `src / div` — a 6x6 frame at div 4
    // floors to 1, is raised to 2, and a fixed `dx * 4` box then reads source column 7 of 6. (That
    // overrun was real; `odd_source_yields_even_dims_at_least_2` caught it.) Deriving the extent
    // from `sw`/`dw` makes every read in bounds by construction, and whenever `dw * div == sw` —
    // which is every real resolution at every supported divisor — it reduces to exactly the k x k
    // box the doc comment promises.
    let span = |d: usize, dn: usize, sn: usize| {
        let a = d * sn / dn;
        let b = ((d + 1) * sn / dn).max(a + 1);
        (a, b.min(sn))
    };
    for dy in 0..dh {
        let (y0, y1) = span(dy, dh, sh);
        for dx in 0..dw {
            let (x0, x1) = span(dx, dw, sw);
            let (mut b, mut g, mut r, mut a) = (0u32, 0u32, 0u32, 0u32);
            for y in y0..y1 {
                let row = y * src_stride;
                for x in x0..x1 {
                    let i = row + x * 4;
                    b += src[i] as u32;
                    g += src[i + 1] as u32;
                    r += src[i + 2] as u32;
                    a += src[i + 3] as u32;
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            let o = (dy * dw + dx) * 4;
            out[o] = (b / n) as u8;
            out[o + 1] = (g / n) as u8;
            out[o + 2] = (r / n) as u8;
            out[o + 3] = (a / n) as u8;
        }
    }

    Cow::Owned(CapturedFrame {
        monitor_id: frame.monitor_id,
        width: dw as u32,
        height: dh as u32,
        bytes: out,
        is_keyframe: frame.is_keyframe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `w`×`h` BGRA where every channel of pixel (x, y) is `f(x, y)`.
    fn frame_with(w: u32, h: u32, f: impl Fn(u32, u32) -> [u8; 4]) -> CapturedFrame {
        let mut bytes = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let px = f(x, y);
                let i = ((y * w + x) * 4) as usize;
                bytes[i..i + 4].copy_from_slice(&px);
            }
        }
        CapturedFrame { monitor_id: 3, width: w, height: h, bytes, is_keyframe: true }
    }

    #[test]
    fn div1_returns_borrowed_and_copies_nothing() {
        // A byte-equality assertion alone would survive "make div 1 go through the scaler" —
        // the identity path must be proven a NO-OP, not merely harmless. Pointer identity is the
        // only assertion that can tell the difference.
        //
        // ODD dimensions are in the table deliberately. With even ones the `dw >= sw` guard
        // catches a broken `k <= 1` check as well (dw would equal sw), so an even-only test passes
        // against a mutation that removed the fast path — measured, by mutating `k <= 1` to
        // `k < 1`. At an odd width the even-flooring makes dw < sw, the frame really would be
        // rescaled, and only these rows notice.
        for (w, h) in [(8u32, 8u32), (15, 9), (1921, 1081)] {
            let f = frame_with(w.min(64), h.min(64), |x, y| [x as u8, y as u8, 7, 255]);
            let src_ptr = f.bytes.as_ptr();
            let out = scale_bgra(Cow::Borrowed(&f), 1);
            assert!(matches!(out, Cow::Borrowed(_)), "{w}x{h}: div 1 must not allocate");
            assert_eq!(out.bytes.as_ptr(), src_ptr, "{w}x{h}: div 1 must not copy a byte");
            assert_eq!((out.width, out.height), (f.width, f.height), "{w}x{h}: dims untouched");
            // div 0 would divide by zero in the kernel; it must take the same no-op path.
            let z = scale_bgra(Cow::Borrowed(&f), 0);
            assert!(matches!(z, Cow::Borrowed(_)), "{w}x{h}: div 0 must not allocate");
            assert_eq!(z.bytes.as_ptr(), src_ptr, "{w}x{h}: div 0 must not copy a byte");
        }
    }

    #[test]
    fn div2_is_an_exact_2x2_average() {
        // A 4x4 checkerboard of 0 and 200: every 2x2 box holds two of each, so every destination
        // pixel must be exactly 100. Nearest-neighbour would produce 0s and 200s.
        let f = frame_with(4, 4, |x, y| {
            let v = if (x + y) % 2 == 0 { 0 } else { 200 };
            [v, v, v, 255]
        });
        let out = scale_bgra(Cow::Borrowed(&f), 2);
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!(out.monitor_id, 3, "monitor id carried through");
        assert!(out.is_keyframe, "keyframe flag carried through");
        for (i, px) in out.bytes.chunks(4).enumerate() {
            assert_eq!(px[0], 100, "pixel {i} blue");
            assert_eq!(px[1], 100, "pixel {i} green");
            assert_eq!(px[2], 100, "pixel {i} red");
            assert_eq!(px[3], 255, "pixel {i} alpha");
        }
    }

    #[test]
    fn div3_and_div4_are_exact_kxk_averages() {
        // A column gradient `10 * (x % 4)` gives each box a known mean, so an off-by-one in the
        // kernel bounds shifts a value detectably rather than merely blurring it. Both sizes below
        // divide EVENLY (12/3 = 4, 16/4 = 4, both even), so the area map is exactly the k x k box.

        // div 3 on a 12-wide source: boxes at x = 0..2, 3..5, 6..8, 9..11.
        //   0,10,20 -> 10 | 30,0,10 -> 13 (40/3) | 20,30,0 -> 16 (50/3) | 10,20,30 -> 20
        let f12 = frame_with(12, 12, |x, _| {
            let v = 10 * (x % 4) as u8;
            [v, v, v, 255]
        });
        let out3 = scale_bgra(Cow::Borrowed(&f12), 3);
        assert_eq!((out3.width, out3.height), (4, 4), "12/3 = 4, already even");
        let row0: Vec<u8> = out3.bytes.chunks(4).take(4).map(|p| p[0]).collect();
        assert_eq!(row0, vec![10, 13, 16, 20], "exact per-box means, not a resample");

        // div 4 on a 16-wide source: every box spans exactly one full x%4 cycle -> 10*(0+1+2+3)/4.
        let f16 = frame_with(16, 16, |x, _| {
            let v = 10 * (x % 4) as u8;
            [v, v, v, 255]
        });
        let out4 = scale_bgra(Cow::Borrowed(&f16), 4);
        assert_eq!((out4.width, out4.height), (4, 4), "16/4 = 4");
        for px in out4.bytes.chunks(4) {
            assert_eq!(px[0], 15, "a 4x4 box over one full x%4 cycle averages 15");
        }
    }

    #[test]
    fn the_real_resolutions_divide_exactly() {
        // The area map degrades gracefully on awkward sizes, but the shipped path must be the exact
        // k x k box — so pin that every supported divisor divides a real desktop evenly into an
        // even destination. If a future MAX_SCALE_DIV broke this, the scaler would still work but
        // would quietly stop being the filter documented above.
        for (w, h) in [(1920u32, 1080u32), (1280, 720), (3840, 2160)] {
            for div in 1..=crate::quality::MAX_SCALE_DIV {
                let (dw, dh) = (w / div, h / div);
                assert_eq!(dw % 2, 0, "{w}x{h} / {div}: width {dw} is odd");
                assert_eq!(dh % 2, 0, "{w}x{h} / {div}: height {dh} is odd");
            }
        }
    }

    #[test]
    fn odd_source_yields_even_dims_at_least_2() {
        // The VP8 encoder crops to even dimensions; producing an odd scaled size would silently
        // trim a column on every frame. And a source small enough to floor to 0 must not.
        let f = frame_with(15, 9, |_, _| [1, 2, 3, 255]);
        let out = scale_bgra(Cow::Borrowed(&f), 2);
        assert_eq!(out.width % 2, 0, "width must be even");
        assert_eq!(out.height % 2, 0, "height must be even");
        assert_eq!((out.width, out.height), (6, 4), "15/2=7 -> 6, 9/2=4");

        let tiny = frame_with(6, 6, |_, _| [9, 9, 9, 255]);
        let out = scale_bgra(Cow::Borrowed(&tiny), 4);
        assert_eq!((out.width, out.height), (2, 2), "floors to 1 -> raised to 2");
        assert!(out.width >= 2 && out.height >= 2);
    }

    #[test]
    fn never_panics_on_a_short_buffer() {
        // A capturer with a padded pitch (or a truncated frame) must degrade to "scaling did
        // nothing", never to an out-of-bounds read or a sheared picture.
        let mut f = frame_with(8, 8, |_, _| [4, 4, 4, 255]);
        f.bytes.truncate(8 * 8 * 4 - 1);
        let out = scale_bgra(Cow::Borrowed(&f), 2);
        assert!(matches!(out, Cow::Borrowed(_)), "short buffer returns the frame untouched");
        assert_eq!((out.width, out.height), (8, 8));

        // Zero-sized frames take the same path.
        let empty = CapturedFrame {
            monitor_id: 0,
            width: 0,
            height: 0,
            bytes: Vec::new(),
            is_keyframe: false,
        };
        let out = scale_bgra(Cow::Borrowed(&empty), 4);
        assert_eq!((out.width, out.height), (0, 0));
    }

    #[test]
    fn refuses_a_padded_pitch_buffer_and_any_length_mismatch() {
        // (1) Padded pitch: 64 extra bytes make the buffer longer than w*h*4. It used to be scaled
        // with the wrong stride into a sheared 8x8 frame.
        let mut padded = frame_with(16, 16, |x, y| [x as u8, y as u8, 5, 255]);
        padded.bytes.extend(std::iter::repeat(9u8).take(64));
        let out = scale_bgra(Cow::Borrowed(&padded), 2);
        assert!(matches!(out, Cow::Borrowed(_)), "padded buffer returns the frame untouched");
        assert_eq!((out.width, out.height), (16, 16));
        assert_eq!(out.bytes, padded.bytes);

        // (2) One byte too long is refused too.
        let mut long = frame_with(16, 16, |_, _| [1, 2, 3, 255]);
        long.bytes.push(0);
        let out = scale_bgra(Cow::Borrowed(&long), 2);
        assert!(matches!(out, Cow::Borrowed(_)), "one extra byte is refused");
        assert_eq!((out.width, out.height), (16, 16));
        assert_eq!(out.bytes.len(), 16 * 16 * 4 + 1);

        // (3) One byte short stays refused (positive control for the old behaviour).
        let mut short = frame_with(16, 16, |_, _| [1, 2, 3, 255]);
        short.bytes.pop();
        let out = scale_bgra(Cow::Borrowed(&short), 2);
        assert!(matches!(out, Cow::Borrowed(_)), "one byte short is refused");
        assert_eq!((out.width, out.height), (16, 16));

        // (4) Exact length still scales (negative control: the guard is not refusing everything).
        let exact = frame_with(16, 16, |_, _| [1, 2, 3, 255]);
        let out = scale_bgra(Cow::Borrowed(&exact), 2);
        assert!(matches!(out, Cow::Owned(_)), "exact-length frame is scaled");
        assert_eq!((out.width, out.height), (8, 8));
        assert_eq!(out.bytes.len(), 8 * 8 * 4);
    }

    #[test]
    fn scaling_shrinks_the_payload_by_the_square_of_the_divisor() {
        // The point of the knob: a quarter of the pixels per axis is a sixteenth of the bytes
        // handed to the encoder AND cloned by VideoFrameSender.
        let f = frame_with(64, 64, |x, y| [x as u8, y as u8, 0, 255]);
        let raw = f.bytes.len();
        for (div, expect) in [(2u32, 32usize), (4, 16)] {
            let out = scale_bgra(Cow::Borrowed(&f), div);
            assert_eq!((out.width, out.height), (expect as u32, expect as u32));
            assert_eq!(out.bytes.len(), expect * expect * 4);
            assert_eq!(out.bytes.len() * (div * div) as usize, raw);
        }
    }
}
