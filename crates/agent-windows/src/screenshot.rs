//! Encode a captured desktop frame as a **lossless PNG** for the screenshot feature (docs/01 §2 P1
//! "Screenshot capture").
//!
//! The live video is lossy VP8 and often quality-scaled; a screenshot is the full-resolution, lossless
//! still the technician actually wants to keep. The agent taps the most recent [`CapturedFrame`] the
//! streaming pipeline already produced (native capture resolution, no second capturer to fight the
//! DXGI duplication) and this module turns its packed **BGRA** pixels into an RGB PNG, which is then
//! pushed to the controller over the file-transfer channel and saved like any download.
//!
//! Everything here is pure (no Win32, no I/O): [`bgra_to_rgb`] and [`encode_png`] are unit- and
//! mutation-tested against synthetic frames, and [`screenshot_filename`] takes the clock value as an
//! argument so the name format is pinned by a test.

use rmt_agent_core::CapturedFrame;

/// A reason a frame could not be turned into a screenshot PNG. Surfaced to the controller as a
/// `ControlMessage::Error`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScreenshotError {
    /// No frame has been captured yet this session (the stream has not produced one).
    #[error("no frame has been captured yet")]
    NoFrame,
    /// The frame's byte length is too small for its declared `width * height * 4` (BGRA).
    #[error("frame is {got} bytes but {width}x{height} BGRA needs {need}")]
    ShortFrame {
        /// Bytes actually present.
        got: usize,
        /// Declared width.
        width: u32,
        /// Declared height.
        height: u32,
        /// Bytes required for packed BGRA.
        need: usize,
    },
    /// A degenerate (zero-area) frame — nothing to encode.
    #[error("frame has a zero dimension ({width}x{height})")]
    ZeroArea {
        /// Declared width.
        width: u32,
        /// Declared height.
        height: u32,
    },
    /// The PNG encoder itself failed (should not happen for a well-formed RGB buffer).
    #[error("png encode failed: {0}")]
    Encode(String),
}

/// Convert packed **BGRA** (4 bytes/pixel, the order the Windows capturers produce) to packed **RGB**
/// (3 bytes/pixel), dropping the opaque alpha. Pure so the channel swap — the one thing that is easy to
/// get backwards and would tint a whole screenshot blue-for-red — is pinned by a test.
///
/// Any trailing bytes that do not complete a 4-byte pixel are ignored (`chunks_exact`).
pub fn bgra_to_rgb(bgra: &[u8]) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(bgra.len() / 4 * 3);
    for px in bgra.chunks_exact(4) {
        // BGRA → RGB: red is byte 2, green byte 1, blue byte 0.
        rgb.push(px[2]);
        rgb.push(px[1]);
        rgb.push(px[0]);
    }
    rgb
}

/// Encode a captured BGRA frame as a lossless 8-bit RGB PNG, returning the PNG file bytes.
///
/// Validates the frame is non-empty and large enough for its declared dimensions before touching the
/// encoder, so a truncated/degenerate frame is a typed error rather than a panic or a sheared image.
pub fn encode_png(frame: &CapturedFrame) -> Result<Vec<u8>, ScreenshotError> {
    let (w, h) = (frame.width, frame.height);
    if w == 0 || h == 0 {
        return Err(ScreenshotError::ZeroArea { width: w, height: h });
    }
    let need = (w as usize)
        .checked_mul(h as usize)
        .and_then(|px| px.checked_mul(4))
        .ok_or(ScreenshotError::ZeroArea { width: w, height: h })?;
    if frame.bytes.len() < need {
        return Err(ScreenshotError::ShortFrame {
            got: frame.bytes.len(),
            width: w,
            height: h,
            need,
        });
    }
    // Use exactly the declared pixels (packed BGRA); ignore any trailing slack.
    let rgb = bgra_to_rgb(&frame.bytes[..need]);

    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc
            .write_header()
            .map_err(|e| ScreenshotError::Encode(e.to_string()))?;
        writer
            .write_image_data(&rgb)
            .map_err(|e| ScreenshotError::Encode(e.to_string()))?;
    }
    Ok(out)
}

/// The filename for a screenshot taken at `unix_millis`. Pure so the format is pinned; the caller reads
/// the clock. `screenshot-<unix_millis>.png` — a stable, sortable, collision-resistant name that needs
/// no date-formatting dependency.
pub fn screenshot_filename(unix_millis: u128) -> String {
    format!("screenshot-{unix_millis}.png")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(width: u32, height: u32, bytes: Vec<u8>) -> CapturedFrame {
        CapturedFrame { monitor_id: 0, width, height, bytes, is_keyframe: true }
    }

    #[test]
    fn bgra_to_rgb_swaps_blue_and_red_and_drops_alpha() {
        // One pixel B=1,G=2,R=3,A=4 → R=3,G=2,B=1. If the swap were wrong the whole screenshot would
        // come back with red and blue exchanged — a subtle, ship-it-anyway bug, so it is pinned.
        assert_eq!(bgra_to_rgb(&[1, 2, 3, 4]), vec![3, 2, 1]);
        // Two pixels, and a trailing partial pixel that must be ignored (chunks_exact).
        assert_eq!(
            bgra_to_rgb(&[10, 20, 30, 255, 40, 50, 60, 255, 99]),
            vec![30, 20, 10, 60, 50, 40]
        );
        assert_eq!(bgra_to_rgb(&[]), Vec::<u8>::new());
    }

    #[test]
    fn encode_png_produces_a_valid_png_with_the_frame_dimensions() {
        // A 2x1 BGRA frame → a real PNG: the 8-byte signature, and an IHDR whose width/height match.
        let f = frame(2, 1, vec![1, 2, 3, 255, 4, 5, 6, 255]);
        let png = encode_png(&f).expect("encode");
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'], "PNG signature");
        // IHDR is the first chunk: [len(4)][ "IHDR"(4) ][ width(4 BE) ][ height(4 BE) ]... at offset 8.
        assert_eq!(&png[12..16], b"IHDR");
        let w = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let h = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        assert_eq!((w, h), (2, 1), "IHDR dims must match the frame");
        // Round-trips through the decoder back to the same dimensions and RGB channel count.
        let decoder = png::Decoder::new(&png[..]);
        let reader = decoder.read_info().expect("decode header");
        let info = reader.info();
        assert_eq!((info.width, info.height), (2, 1));
        assert_eq!(info.color_type, png::ColorType::Rgb);
    }

    #[test]
    fn encode_png_rejects_a_short_or_degenerate_frame() {
        // Declares 4x4 (needs 64 bytes) but carries 8 → ShortFrame, not a panic or a sheared image.
        let short = frame(4, 4, vec![0u8; 8]);
        assert!(matches!(encode_png(&short), Err(ScreenshotError::ShortFrame { need: 64, got: 8, .. })));
        // A zero dimension is a distinct, earlier error.
        assert_eq!(
            encode_png(&frame(0, 10, vec![])),
            Err(ScreenshotError::ZeroArea { width: 0, height: 10 })
        );
    }

    #[test]
    fn filename_is_stable_and_sortable() {
        assert_eq!(screenshot_filename(1_700_000_000_000), "screenshot-1700000000000.png");
        // Lexicographic order tracks time order for equal-width values (both 13-digit here).
        assert!(screenshot_filename(1_700_000_000_000) < screenshot_filename(1_700_000_000_001));
    }
}
