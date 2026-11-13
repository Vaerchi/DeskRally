//! BGRA8 → I420 (planar YUV 4:2:0) colour conversion.
//!
//! The capturers (DXGI/GDI/WGC) hand us BGRA8. OpenH264 accepted that natively; **libvpx does
//! not** — `vpx_codec_encode` only takes `vpx_image_t`, and for VP8 that means `VPX_IMG_FMT_I420`.
//! So the conversion is ours to get right.
//!
//! Matrix: **BT.601, studio ("limited"/"video") range** — Y in 16..=235, Cb/Cr in 16..=240. That is
//! the correct default for WebRTC: VP8's bitstream has no colour-space signalling of its own beyond
//! `vpx_image_t::cs`/`range`, and every browser decoder assumes BT.601 limited range for VP8 unless
//! told otherwise. Feeding full-range luma into a limited-range decode is the classic "washed out /
//! crushed blacks" bug, so we match the decoder rather than the source.
//!
//! The LUMA integer coefficients are libyuv's `ARGBToI420` (the de-facto reference used by
//! Chromium and WebRTC), which is why the unit tests below assert against libyuv's exact outputs.
//! Chroma differs by design — see the rounding note at the averaging step:
//!
//! ```text
//! Y = (( 66*R + 129*G +  25*B + 128) >> 8) +  16
//! U = ((-38*R -  74*G + 112*B + 128) >> 8) + 128
//! V = ((112*R -  94*G -  18*B + 128) >> 8) + 128
//! ```
//!
//! Chroma is **averaged over each 2×2 luma block** (average the RGB, then convert once), not
//! point-sampled from one corner. Point sampling is the other silent-colour-corruption bug: it
//! survives every "did bytes flow?" assertion while visibly mangling fine coloured detail — exactly
//! what a desktop full of 1-pixel-wide coloured text is made of.

/// Where each plane starts inside the packed I420 buffer produced by [`bgra_to_i420_into`].
///
/// The layout is exactly what `vpx_img_wrap(..., VPX_IMG_FMT_I420, w, h, 1, ptr)` expects for even
/// `w`/`h`: a tightly packed Y plane of `w * h`, then U of `cw * ch`, then V of `cw * ch`, with
/// `cw = (w + 1) / 2` and `ch = (h + 1) / 2` and no row padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I420Layout {
    pub width: usize,
    pub height: usize,
    pub chroma_width: usize,
    pub chroma_height: usize,
    /// Byte offset of the U plane (equals `width * height`).
    pub u_offset: usize,
    /// Byte offset of the V plane.
    pub v_offset: usize,
    /// Total buffer length.
    pub len: usize,
}

impl I420Layout {
    /// The layout for a `w`×`h` frame. Odd dimensions round the chroma planes up.
    pub fn new(width: usize, height: usize) -> Self {
        let chroma_width = width.div_ceil(2);
        let chroma_height = height.div_ceil(2);
        let y = width * height;
        let c = chroma_width * chroma_height;
        Self {
            width,
            height,
            chroma_width,
            chroma_height,
            u_offset: y,
            v_offset: y + c,
            len: y + 2 * c,
        }
    }
}

/// The BT.601 neutral chroma value — what U and V both are for any grey pixel, and therefore what
/// [`ChromaMode::Gray`](super::ChromaMode::Gray) fills the chroma planes with. `yuv_of_solid` for
/// black/white/grey collapses to exactly this, which is why grey is representable with constant
/// chroma at all.
const NEUTRAL_CHROMA: u8 = 128;

#[inline]
fn y_of(r: i32, g: i32, b: i32) -> u8 {
    (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8
}

#[inline]
fn u_of(r: i32, g: i32, b: i32) -> u8 {
    (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8
}

#[inline]
fn v_of(r: i32, g: i32, b: i32) -> u8 {
    (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8
}

/// Convert a `w`×`h` BGRA8 image into a packed I420 buffer in `out`.
///
/// `src_stride` is the source row pitch **in bytes** (`w * 4` for a tightly packed frame; capturers
/// sometimes hand back a wider pitch). `out` is resized to [`I420Layout::len`] and fully
/// overwritten, so callers can keep one scratch buffer alive across frames and never allocate in
/// steady state.
///
/// Odd widths/heights are handled: the trailing column/row simply contributes to a 2×1, 1×2 or 1×1
/// chroma average instead of a 2×2 one.
pub fn bgra_to_i420_into(
    bgra: &[u8],
    w: usize,
    h: usize,
    src_stride: usize,
    out: &mut Vec<u8>,
) -> Result<I420Layout, String> {
    bgra_to_i420_into_mode(bgra, w, h, src_stride, super::ChromaMode::Full, out)
}

/// [`bgra_to_i420_into`] with an explicit chroma mode (M11 colour control).
///
/// [`ChromaMode::Full`](super::ChromaMode::Full) takes the **identical** code path as the
/// three-argument form — that equality is pinned by a test, because "the default path changed
/// subtly" is the failure mode a colour feature is most likely to ship.
///
/// [`ChromaMode::Gray`](super::ChromaMode::Gray) leaves luma at full 8-bit depth and fills both
/// chroma planes with exactly 128 (the BT.601 neutral), skipping the whole chroma loop. Two
/// consequences, both intended: constant chroma planes are coded by VP8 as skipped blocks for
/// essentially nothing — a guaranteed bitrate saving rather than a content-dependent one — and not
/// running the averaging loop makes `Gray` **cheaper** in CPU than `Full`, not more expensive.
///
/// Luma is deliberately untouched: in a remote-support session the payload is text, and text
/// legibility is luma. `Gray` throws away colour to keep detail; it is not the bottom of a depth
/// scale.
pub fn bgra_to_i420_into_mode(
    bgra: &[u8],
    w: usize,
    h: usize,
    src_stride: usize,
    mode: super::ChromaMode,
    out: &mut Vec<u8>,
) -> Result<I420Layout, String> {
    if w == 0 || h == 0 {
        return Err(format!("frame too small: {w}x{h}"));
    }
    if src_stride < w * 4 {
        return Err(format!("src_stride {src_stride} < {w}*4"));
    }
    // Only `h-1` full strides plus one row of pixels are actually required.
    let needed = (h - 1) * src_stride + w * 4;
    if bgra.len() < needed {
        return Err(format!("short BGRA buffer: {} < {needed}", bgra.len()));
    }

    let layout = I420Layout::new(w, h);
    out.clear();
    out.resize(layout.len, 0);
    // The same code compiled twice: once for the x86-64 baseline (SSE2) and once with AVX2 enabled,
    // where LLVM vectorises the row loops wider. Integer arithmetic only, so both are bit-identical
    // (pinned by `avx2_and_baseline_agree_bit_for_bit`).
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 was detected on this CPU at runtime, which is the function's only requirement.
        unsafe { convert_planes_avx2(bgra, w, h, src_stride, mode, layout, out) };
        return Ok(layout);
    }
    convert_planes(bgra, w, h, src_stride, mode, layout, out);
    Ok(layout)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn convert_planes_avx2(
    bgra: &[u8],
    w: usize,
    h: usize,
    src_stride: usize,
    mode: super::ChromaMode,
    layout: I420Layout,
    out: &mut [u8],
) {
    convert_planes(bgra, w, h, src_stride, mode, layout, out)
}

/// The conversion proper, on an already validated input and an `out` of exactly `layout.len`.
#[inline(always)]
fn convert_planes(
    bgra: &[u8],
    w: usize,
    h: usize,
    src_stride: usize,
    mode: super::ChromaMode,
    layout: I420Layout,
    out: &mut [u8],
) {
    let (y_plane, chroma) = out.split_at_mut(layout.u_offset);
    let (u_plane, v_plane) = chroma.split_at_mut(layout.chroma_width * layout.chroma_height);

    // Luma: one output byte per source pixel.
    let luma_row = |row: usize, y_plane: &mut [u8]| {
        let src = &bgra[row * src_stride..row * src_stride + w * 4];
        let dst = &mut y_plane[row * w..row * w + w];
        for (px, y) in src.chunks_exact(4).zip(dst.iter_mut()) {
            // BGRA byte order: B, G, R, A.
            *y = y_of(px[2] as i32, px[1] as i32, px[0] as i32);
        }
    };

    // Greyscale (M11): both chroma planes are the BT.601 neutral. Fill and return — the averaging
    // loop below is skipped entirely, so this is strictly less work than Full.
    if matches!(mode, super::ChromaMode::Gray) {
        for row in 0..h {
            luma_row(row, y_plane);
        }
        u_plane.fill(NEUTRAL_CHROMA);
        v_plane.fill(NEUTRAL_CHROMA);
        return;
    }

    // Chroma: average the RGB of each 2x2 block (clamped at odd edges), then convert once.
    //
    // The frame is walked ONCE, a pair of rows at a time: both rows' luma, then the pair's chroma
    // while those rows are still in cache. A 3840x1080 BGRA frame is 16 MB, so a separate chroma
    // pass read it from memory a second time; on the operator's Desktop that pass alone cost ~6.5 ms of a
    // ~10 ms conversion (luma ~3 ms). Single pass: ~5.5 ms; with the AVX2 build: ~3.6 ms
    // (`examples`-style bench, 3840x1080, a different frame each time so nothing is cache-warm).
    //
    // Every WHOLE 2x2 block takes the fast loop: two source rows walked in step, a fixed divisor of
    // 4 as a shift, no per-block edge tests or bounds checks. Only an odd last column or row is left
    // to the general form, which is the rule itself.
    let cw = layout.chroma_width;
    let whole_w = w / 2;
    for cy in 0..h / 2 {
        luma_row(2 * cy, y_plane);
        luma_row(2 * cy + 1, y_plane);
        let r0 = &bgra[2 * cy * src_stride..][..whole_w * 8];
        let r1 = &bgra[(2 * cy + 1) * src_stride..][..whole_w * 8];
        let u_row = &mut u_plane[cy * cw..][..whole_w];
        let v_row = &mut v_plane[cy * cw..][..whole_w];
        for (((a, b), u), v) in r0.chunks_exact(8).zip(r1.chunks_exact(8)).zip(u_row).zip(v_row) {
            // The sums are non-negative, so `+ 2 >> 2` is exactly the general form's rounded `/ 4`.
            let ab = (a[0] as i32 + a[4] as i32 + b[0] as i32 + b[4] as i32 + 2) >> 2;
            let ag = (a[1] as i32 + a[5] as i32 + b[1] as i32 + b[5] as i32 + 2) >> 2;
            let ar = (a[2] as i32 + a[6] as i32 + b[2] as i32 + b[6] as i32 + 2) >> 2;
            *u = u_of(ar, ag, ab);
            *v = v_of(ar, ag, ab);
        }
    }
    // An odd width leaves a last chroma column (every chroma row, the corner included); an odd
    // height leaves a last chroma row (its whole blocks only: the corner is done above).
    if w % 2 == 1 {
        for cy in 0..layout.chroma_height {
            let i = cy * cw + cw - 1;
            (u_plane[i], v_plane[i]) = edge_block_uv(bgra, w, h, src_stride, cw - 1, cy);
        }
    }
    if h % 2 == 1 {
        luma_row(h - 1, y_plane);
        let cy = layout.chroma_height - 1;
        for cx in 0..whole_w {
            let i = cy * cw + cx;
            (u_plane[i], v_plane[i]) = edge_block_uv(bgra, w, h, src_stride, cx, cy);
        }
    }
}

/// The (U, V) of chroma block (`cx`, `cy`) in general form: the rounded average RGB of the 2x2,
/// 2x1, 1x2 or 1x1 source pixels it covers (clamped at an odd edge), converted once.
fn edge_block_uv(bgra: &[u8], w: usize, h: usize, src_stride: usize, cx: usize, cy: usize) -> (u8, u8) {
    let y0 = cy * 2;
    let y1 = (y0 + 1).min(h - 1);
    let x0 = cx * 2;
    let x1 = (x0 + 1).min(w - 1);

    let (mut r, mut g, mut b, mut n) = (0i32, 0i32, 0i32, 0i32);
    for row in y0..=y1 {
        for col in x0..=x1 {
            let o = row * src_stride + col * 4;
            b += bgra[o] as i32;
            g += bgra[o + 1] as i32;
            r += bgra[o + 2] as i32;
            n += 1;
        }
    }
    // Rounded average of the block. NB this deliberately differs from libyuv, whose
    // ARGBToUVRow_C truncates (`(a+b+c+d) >> 2`, no rounding term). At most 1 LSB of
    // chroma on a mixed block, and rounding is the better answer — but do not "fix" a
    // colour bug by diffing against libyuv here and assuming bit-exactness.
    let half = n / 2;
    let (ar, ag, ab) = ((r + half) / n, (g + half) / n, (b + half) / n);
    (u_of(ar, ag, ab), v_of(ar, ag, ab))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: usize, h: usize, b: u8, g: u8, r: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(w * h * 4);
        for _ in 0..w * h {
            v.extend_from_slice(&[b, g, r, 0xFF]);
        }
        v
    }

    /// Convert a solid colour and return the single (Y, U, V) triple it collapses to.
    fn yuv_of_solid(b: u8, g: u8, r: u8) -> (u8, u8, u8) {
        let (w, h) = (8usize, 8usize);
        let src = solid(w, h, b, g, r);
        let mut out = Vec::new();
        let l = bgra_to_i420_into(&src, w, h, w * 4, &mut out).expect("convert");
        let y = out[0];
        let u = out[l.u_offset];
        let v = out[l.v_offset];
        // A solid frame must be uniform in every plane.
        assert!(out[..l.u_offset].iter().all(|&p| p == y), "Y uniform");
        assert!(out[l.u_offset..l.v_offset].iter().all(|&p| p == u), "U uniform");
        assert!(out[l.v_offset..].iter().all(|&p| p == v), "V uniform");
        (y, u, v)
    }

    /// The whole point of these: a swapped U/V plane or a wrong matrix still "works" (bytes flow,
    /// RTP packets arrive, the browser shows a picture) — it is just the WRONG COLOUR. Only known
    /// primaries catch that. Values are BT.601 studio-range, libyuv coefficients.
    #[test]
    fn primaries_convert_to_bt601_studio_range() {
        // BGRA order in the tuple below is (B, G, R).
        assert_eq!(yuv_of_solid(0, 0, 0), (16, 128, 128), "black");
        assert_eq!(yuv_of_solid(255, 255, 255), (235, 128, 128), "white");
        // Red: high V (~240), low U (~90). If U/V were swapped this fails immediately.
        assert_eq!(yuv_of_solid(0, 0, 255), (82, 90, 240), "red");
        // Green: both chroma below 128.
        assert_eq!(yuv_of_solid(0, 255, 0), (144, 54, 34), "green");
        // Blue: high U (~240), low V (~110) — the mirror image of red.
        assert_eq!(yuv_of_solid(255, 0, 0), (41, 240, 110), "blue");
    }

    // --- M11 colour modes -----------------------------------------------------------------

    /// A rich, non-uniform test image: every channel varies per pixel, so a mode that quietly
    /// touched luma or shifted chroma by an LSB shows up.
    fn busy(w: usize, h: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&[
                    (x * 7 + y * 3) as u8,
                    (x * 13 + y * 29) as u8,
                    (x * 31 + y * 5) as u8,
                    0xFF,
                ]);
            }
        }
        v
    }

    /// `Full` must be BYTE-IDENTICAL to the pre-M11 path, not merely "close". The whole colour
    /// feature is safe only if the default costs nothing; a 1-LSB drift here would ship as a
    /// permanent, invisible regression on every session that never touches the new control.
    #[test]
    fn full_is_byte_identical_to_the_unmoded_path() {
        let (w, h) = (17usize, 11usize); // odd both ways: exercises the edge-clamp branches too
        let src = busy(w, h);
        let mut baseline = Vec::new();
        let mut moded = Vec::new();
        let a = bgra_to_i420_into(&src, w, h, w * 4, &mut baseline).expect("baseline");
        let b = bgra_to_i420_into_mode(&src, w, h, w * 4, super::super::ChromaMode::Full, &mut moded)
            .expect("moded");
        assert_eq!(a, b, "layout");
        assert_eq!(baseline, moded, "Full must be the identical code path, byte for byte");
    }

    /// `Gray` fills both chroma planes with exactly 128 and leaves LUMA bit-identical. Writing 127
    /// (or greying the luma too) must fail: the first is not the BT.601 neutral, and the second
    /// would destroy the text legibility the mode exists to preserve.
    #[test]
    fn gray_fills_uv_with_128_and_leaves_y_bit_identical() {
        let (w, h) = (16usize, 8usize);
        let src = busy(w, h);
        let mut full = Vec::new();
        let mut gray = Vec::new();
        let l = bgra_to_i420_into_mode(&src, w, h, w * 4, super::super::ChromaMode::Full, &mut full)
            .expect("full");
        let lg = bgra_to_i420_into_mode(&src, w, h, w * 4, super::super::ChromaMode::Gray, &mut gray)
            .expect("gray");
        assert_eq!(l, lg, "the layout is identical — Gray changes values, not sizes");

        assert_eq!(
            &full[..l.u_offset],
            &gray[..l.u_offset],
            "luma must be bit-identical: Gray discards COLOUR, never detail"
        );
        assert!(
            gray[l.u_offset..].iter().all(|&c| c == 128),
            "every chroma sample must be exactly the BT.601 neutral 128"
        );
        // And the source really did have colour to throw away, or the assertion above is vacuous.
        assert!(
            full[l.u_offset..].iter().any(|&c| c != 128),
            "the test image must carry real chroma, else `Gray` proves nothing"
        );
    }

    /// Luma ordering sanity: green is much brighter than blue, red sits between. Catches a
    /// BGRA↔RGBA channel-order mix-up even if someone "fixed" the expected values above.
    #[test]
    fn luma_ranks_green_over_red_over_blue() {
        let (yg, ..) = yuv_of_solid(0, 255, 0);
        let (yr, ..) = yuv_of_solid(0, 0, 255);
        let (yb, ..) = yuv_of_solid(255, 0, 0);
        assert!(yg > yr && yr > yb, "Y(green)={yg} > Y(red)={yr} > Y(blue)={yb}");
    }

    /// Chroma must AVERAGE the 2x2 block, not point-sample one corner. A red/blue checkerboard
    /// point-sampled at (0,0) yields red's chroma; averaged it yields magenta's.
    #[test]
    fn chroma_averages_the_2x2_block() {
        let (w, h) = (2usize, 2usize);
        // (0,0)=red (0,1)=blue / (1,0)=blue (1,1)=red — B,G,R,A per pixel.
        let src: Vec<u8> = vec![
            0, 0, 255, 255, 255, 0, 0, 255, // row 0: red, blue
            255, 0, 0, 255, 0, 0, 255, 255, // row 1: blue, red
        ];
        let mut out = Vec::new();
        let l = bgra_to_i420_into(&src, w, h, w * 4, &mut out).unwrap();
        assert_eq!((l.chroma_width, l.chroma_height), (1, 1));

        // Averaged block is (B,G,R) = (128, 0, 128) after rounding — i.e. magenta.
        let expect_u = u_of(128, 0, 128);
        let expect_v = v_of(128, 0, 128);
        assert_eq!(out[l.u_offset], expect_u, "U is the block average");
        assert_eq!(out[l.v_offset], expect_v, "V is the block average");

        // And that is NOT what point-sampling the top-left (pure red) would have produced.
        assert_ne!(out[l.u_offset], u_of(255, 0, 0), "not point-sampled");
    }

    /// Odd width/height must not panic and must produce a correctly sized, fully-written buffer.
    #[test]
    fn handles_odd_dimensions() {
        for (w, h) in [(1usize, 1usize), (3, 3), (5, 2), (2, 5), (65, 33)] {
            let src = solid(w, h, 0, 0, 255); // red
            let mut out = Vec::new();
            let l = bgra_to_i420_into(&src, w, h, w * 4, &mut out).expect("odd convert");
            assert_eq!(l.chroma_width, w.div_ceil(2));
            assert_eq!(l.chroma_height, h.div_ceil(2));
            assert_eq!(out.len(), l.len);
            // Every sample is red's, including the edge blocks with fewer contributing pixels.
            assert!(out[..l.u_offset].iter().all(|&p| p == 82), "{w}x{h} Y");
            assert!(out[l.u_offset..l.v_offset].iter().all(|&p| p == 90), "{w}x{h} U");
            assert!(out[l.v_offset..].iter().all(|&p| p == 240), "{w}x{h} V");
        }
    }

    /// A source pitch wider than `w * 4` (padded capture buffers) must be honoured, not assumed.
    #[test]
    fn respects_a_padded_source_stride() {
        let (w, h) = (4usize, 4usize);
        let stride = w * 4 + 12; // 3 pixels of junk padding per row
        let mut src = vec![0xEEu8; stride * h];
        for row in 0..h {
            for col in 0..w {
                let o = row * stride + col * 4;
                src[o] = 0; // B
                src[o + 1] = 255; // G
                src[o + 2] = 0; // R
                src[o + 3] = 255;
            }
        }
        let mut out = Vec::new();
        let l = bgra_to_i420_into(&src, w, h, stride, &mut out).expect("strided convert");
        assert!(out[..l.u_offset].iter().all(|&p| p == 144), "green Y, padding ignored");
        assert!(out[l.u_offset..l.v_offset].iter().all(|&p| p == 54), "green U");
        assert!(out[l.v_offset..].iter().all(|&p| p == 34), "green V");
    }

    /// The buffer must be reusable across frames without leaking stale bytes or reallocating.
    #[test]
    fn reuses_the_output_buffer() {
        let mut out = Vec::new();
        let big = solid(16, 16, 255, 255, 255);
        let l1 = bgra_to_i420_into(&big, 16, 16, 64, &mut out).unwrap();
        assert_eq!(out.len(), l1.len);
        let small = solid(8, 8, 0, 0, 0);
        let l2 = bgra_to_i420_into(&small, 8, 8, 32, &mut out).unwrap();
        assert_eq!(out.len(), l2.len, "resized down, no stale tail");
        assert!(out[..l2.u_offset].iter().all(|&p| p == 16), "black Y, no white left over");
    }

    #[test]
    fn rejects_short_and_degenerate_input() {
        let mut out = Vec::new();
        assert!(bgra_to_i420_into(&[], 0, 0, 0, &mut out).is_err());
        let src = solid(4, 4, 0, 0, 0);
        assert!(bgra_to_i420_into(&src[..16], 4, 4, 16, &mut out).is_err(), "short buffer");
        assert!(bgra_to_i420_into(&src, 4, 4, 8, &mut out).is_err(), "stride < w*4");
    }

    /// The conversion as it was before the single-pass rewrite: luma over the whole frame, then a
    /// general per-block chroma pass. The rewrite must reproduce it bit for bit.
    fn reference(bgra: &[u8], w: usize, h: usize, stride: usize, gray: bool) -> Vec<u8> {
        let l = I420Layout::new(w, h);
        let mut out = vec![0u8; l.len];
        for row in 0..h {
            for col in 0..w {
                let o = row * stride + col * 4;
                out[row * w + col] = y_of(bgra[o + 2] as i32, bgra[o + 1] as i32, bgra[o] as i32);
            }
        }
        for cy in 0..l.chroma_height {
            for cx in 0..l.chroma_width {
                let (mut r, mut g, mut b, mut n) = (0i32, 0i32, 0i32, 0i32);
                for row in [cy * 2, (cy * 2 + 1).min(h - 1)].into_iter().collect::<std::collections::BTreeSet<_>>() {
                    for col in [cx * 2, (cx * 2 + 1).min(w - 1)].into_iter().collect::<std::collections::BTreeSet<_>>() {
                        let o = row * stride + col * 4;
                        b += bgra[o] as i32;
                        g += bgra[o + 1] as i32;
                        r += bgra[o + 2] as i32;
                        n += 1;
                    }
                }
                let (ar, ag, ab) = ((r + n / 2) / n, (g + n / 2) / n, (b + n / 2) / n);
                let i = cy * l.chroma_width + cx;
                out[l.u_offset + i] = if gray { NEUTRAL_CHROMA } else { u_of(ar, ag, ab) };
                out[l.v_offset + i] = if gray { NEUTRAL_CHROMA } else { v_of(ar, ag, ab) };
            }
        }
        out
    }

    /// Deterministic noise (xorshift), so a failure reproduces.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Odd and even sizes, 1-pixel edges, and padded strides (with garbage in the padding, which
    /// must never be read into the picture), in both chroma modes.
    const SHAPES: [(usize, usize); 12] =
        [(1, 1), (1, 2), (2, 1), (2, 2), (3, 3), (3, 2), (2, 3), (5, 7), (16, 9), (17, 11), (64, 33), (127, 64)];

    #[test]
    fn single_pass_matches_the_two_pass_reference_bit_for_bit() {
        for (k, &(w, h)) in SHAPES.iter().enumerate() {
            for pad in [0usize, 4, 12] {
                let stride = w * 4 + pad;
                // Exactly the minimum length the contract allows: no padding after the last row.
                let src = noise((h - 1) * stride + w * 4, 0x9e37_79b9 + k as u64 * 31 + pad as u64);
                for (mode, gray) in [(super::super::ChromaMode::Full, false), (super::super::ChromaMode::Gray, true)] {
                    let mut out = Vec::new();
                    bgra_to_i420_into_mode(&src, w, h, stride, mode, &mut out).expect("convert");
                    assert_eq!(out, reference(&src, w, h, stride, gray), "{w}x{h} pad {pad} gray {gray}");
                }
            }
        }
    }

    /// The AVX2 build and the baseline build of the same code must agree, whichever one this CPU
    /// would pick (the dispatch makes the public function test only one of them).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_and_baseline_agree_bit_for_bit() {
        if !std::arch::is_x86_feature_detected!("avx2") {
            panic!("this test needs an AVX2 CPU to compare the two builds; every dev and CI box has one");
        }
        for (k, &(w, h)) in SHAPES.iter().chain([(1920, 1080), (3840, 1081)].iter()).enumerate() {
            let stride = w * 4 + 8;
            let src = noise(stride * h, 0x1234_5678 + k as u64);
            let l = I420Layout::new(w, h);
            for mode in [super::super::ChromaMode::Full, super::super::ChromaMode::Gray] {
                let mut base = vec![0u8; l.len];
                let mut wide = vec![1u8; l.len];
                convert_planes(&src, w, h, stride, mode, l, &mut base);
                // SAFETY: AVX2 was detected above.
                unsafe { convert_planes_avx2(&src, w, h, stride, mode, l, &mut wide) };
                assert_eq!(base, wide, "{w}x{h} {mode:?}");
            }
        }
    }
}
