//! Software video-encode fallback (ADR-005 / ADR-006): the CPU path used when no hardware encoder
//! (NVENC / QuickSync / AMF) is available — e.g. inside the Hyper-V test VM, or on a headless
//! server GPU with no encode block.
//!
//! It is a deliberately simple, dependency-light **keyframe / delta + DEFLATE** codec rather than a
//! full video codec (the WebRTC media track's VP8 path in `rmt-transport-webrtc::video`):
//! * a **keyframe** DEFLATE-compresses the whole BGRA8 frame;
//! * a **delta** frame XORs the pixels against the previous frame and DEFLATE-compresses the diff.
//!   On a mostly-static desktop the XOR is almost all zeros, so DEFLATE collapses it to a tiny
//!   payload — the single biggest bandwidth win short of a real video codec (ADR-006's
//!   adaptive/dirty-rect strategy is the next step up).
//!
//! The hardware path never runs this: it hands the GPU texture straight to the encoder (zero-copy).
//! This exists for the software fallback and is exercised end-to-end in tests. The encoded payload
//! is what rides on `ChannelId::Video`; [`EncodedFrame::to_bytes`] / [`EncodedFrame::from_bytes`]
//! are its wire form.

use std::io::{Read, Write};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::CapturedFrame;

/// Errors from the software codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodeError {
    /// A DEFLATE compress/decompress step failed.
    #[error("deflate/inflate failed: {0}")]
    Zlib(String),
    /// A delta frame arrived before any keyframe — the decoder has no reference to apply it to.
    #[error("delta frame with no preceding keyframe")]
    NoKeyframe,
    /// A delta's decompressed size doesn't match the reference frame.
    #[error("delta size {got} does not match reference {expected}")]
    SizeMismatch {
        /// Decompressed delta length.
        got: usize,
        /// Reference (previous) frame length.
        expected: usize,
    },
    /// A delta's header dimensions differ from the retained reference frame's.
    #[error("delta frame is {}x{} but the reference is {}x{}", got.0, got.1, expected.0, expected.1)]
    DeltaDimsMismatch {
        /// Width/height declared by the delta header.
        got: (u32, u32),
        /// Width/height of the retained reference frame.
        expected: (u32, u32),
    },
    /// A frame header declared a zero width or height.
    #[error("frame header declares an empty {width}x{height} image")]
    EmptyFrame {
        /// Width declared by the header.
        width: u32,
        /// Height declared by the header.
        height: u32,
    },
    /// The serialized frame was truncated / malformed.
    #[error("truncated encoded frame")]
    Truncated,
    /// The declared (or actual) decompressed size exceeds the permitted bound.
    #[error("decoded frame exceeds the {limit}-byte limit")]
    TooLarge {
        /// The byte limit that was exceeded.
        limit: usize,
    },
    /// A captured frame's buffer length disagrees with its dimensions (or the dimensions are
    /// beyond the permitted bound), so it could not be decoded by [`SoftwareDecoder`].
    #[error("captured frame has {got} bytes, expected {expected} for its dimensions")]
    BadFrame {
        /// Length of the captured buffer.
        got: usize,
        /// Length implied by `width * height * 4` (saturated on overflow).
        expected: usize,
    },
}

/// Largest decoded (BGRA8) frame the decoder will ever inflate: 256 MiB. Header dimensions are
/// attacker-controlled, so this caps memory regardless of what the peer declares.
pub const MAX_DECODED_FRAME_BYTES: usize = 256 * 1024 * 1024;

/// One software-encoded frame. `data` is DEFLATE-compressed: the full BGRA8 pixels for a keyframe,
/// or the byte-wise XOR delta against the previous frame otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Whether this frame is self-contained (keyframe) vs a delta on the previous frame.
    pub is_keyframe: bool,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// DEFLATE-compressed payload (full pixels for a keyframe, XOR delta otherwise).
    pub data: Vec<u8>,
}

impl EncodedFrame {
    /// Header is 9 bytes: `[flags u8][width u32 BE][height u32 BE]`, then the compressed payload.
    const HEADER: usize = 9;

    /// Serialize for the `Video` channel payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER + self.data.len());
        out.push(if self.is_keyframe { 1 } else { 0 });
        out.extend_from_slice(&self.width.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse a payload produced by [`to_bytes`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self, EncodeError> {
        if buf.len() < Self::HEADER {
            return Err(EncodeError::Truncated);
        }
        let is_keyframe = buf[0] != 0;
        let width = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let height = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        Ok(Self {
            is_keyframe,
            width,
            height,
            data: buf[Self::HEADER..].to_vec(),
        })
    }
}

fn deflate(bytes: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).map_err(|e| EncodeError::Zlib(e.to_string()))?;
    enc.finish().map_err(|e| EncodeError::Zlib(e.to_string()))
}

/// Inflate at most `limit` bytes; never buffers more than `limit + 1` bytes of output.
fn inflate(bytes: &[u8], limit: usize) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    ZlibDecoder::new(bytes)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| EncodeError::Zlib(e.to_string()))?;
    if out.len() > limit {
        return Err(EncodeError::TooLarge { limit });
    }
    Ok(out)
}

/// Stateful software encoder. Emits a keyframe when there's no usable reference (first frame, a
/// resolution change, a forced interval, or a capturer-flagged keyframe) and a delta otherwise.
pub struct SoftwareEncoder {
    prev: Option<Vec<u8>>,
    dims: (u32, u32),
    keyframe_interval: u32,
    since_keyframe: u32,
}

impl SoftwareEncoder {
    /// `keyframe_interval` bounds how many deltas may follow a keyframe before another keyframe is
    /// forced (so a joining/lossy viewer recovers). 0 means every frame is a keyframe.
    pub fn new(keyframe_interval: u32) -> Self {
        Self {
            prev: None,
            dims: (0, 0),
            keyframe_interval,
            since_keyframe: 0,
        }
    }

    /// Encode one captured (BGRA8) frame.
    pub fn encode(&mut self, frame: &CapturedFrame) -> Result<EncodedFrame, EncodeError> {
        let raw = &frame.bytes;
        // Validate before touching any state: a rejected frame leaves the encoder unchanged.
        let expected_u64 = (frame.width as u64)
            .checked_mul(frame.height as u64)
            .and_then(|px| px.checked_mul(4))
            .filter(|&b| b <= MAX_DECODED_FRAME_BYTES as u64);
        match expected_u64 {
            Some(b) if b as usize == raw.len() => {}
            other => {
                let expected = match other {
                    Some(b) => b as usize,
                    None => (frame.width as u64)
                        .saturating_mul(frame.height as u64)
                        .saturating_mul(4)
                        .try_into()
                        .unwrap_or(usize::MAX),
                };
                return Err(EncodeError::BadFrame {
                    got: raw.len(),
                    expected,
                });
            }
        }
        let force_key = self.prev.is_none()
            || self.dims != (frame.width, frame.height)
            || self.since_keyframe >= self.keyframe_interval
            || frame.is_keyframe;

        let (is_keyframe, payload) = if force_key {
            self.since_keyframe = 0;
            (true, deflate(raw)?)
        } else {
            self.since_keyframe += 1;
            // Dimensions match (else force_key), so prev has the same length.
            let prev = self.prev.as_ref().expect("prev present when not forcing key");
            let diff: Vec<u8> = raw.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
            (false, deflate(&diff)?)
        };

        self.prev = Some(raw.clone());
        self.dims = (frame.width, frame.height);
        Ok(EncodedFrame {
            is_keyframe,
            width: frame.width,
            height: frame.height,
            data: payload,
        })
    }
}

/// Stateful decoder mirroring [`SoftwareEncoder`]. Reconstructs BGRA8 pixels, applying deltas
/// against the last decoded frame.
#[derive(Default)]
pub struct SoftwareDecoder {
    prev: Option<Vec<u8>>,
    /// Width/height of the retained reference frame; only updated when a frame decodes.
    dims: (u32, u32),
}

impl SoftwareDecoder {
    /// Create a decoder with no reference frame yet (the first frame it decodes must be a keyframe).
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode one encoded frame to BGRA8 pixels.
    ///
    /// A delta whose header width/height differ from the retained reference frame is refused with
    /// [`EncodeError::DeltaDimsMismatch`] (the encoder always sends a keyframe on a dimension
    /// change, so such a delta is corrupt or hostile even if its byte length happens to match).
    /// A frame (keyframe or delta) whose header width or height is 0 is refused with
    /// [`EncodeError::EmptyFrame`] before anything is inflated: the encoder never emits one, and
    /// accepting it would replace the reference frame with an empty image.
    /// Any refused frame leaves the reference frame and its dimensions unchanged.
    pub fn decode(&mut self, enc: &EncodedFrame) -> Result<Vec<u8>, EncodeError> {
        let expected_u64 = (enc.width as u64)
            .checked_mul(enc.height as u64)
            .and_then(|px| px.checked_mul(4))
            .filter(|&b| b <= MAX_DECODED_FRAME_BYTES as u64)
            .ok_or(EncodeError::TooLarge {
                limit: MAX_DECODED_FRAME_BYTES,
            })?;
        if enc.width == 0 || enc.height == 0 {
            return Err(EncodeError::EmptyFrame {
                width: enc.width,
                height: enc.height,
            });
        }
        let expected = expected_u64 as usize;
        let pixels = if enc.is_keyframe {
            let inflated = inflate(&enc.data, expected)?;
            if inflated.len() != expected {
                return Err(EncodeError::SizeMismatch {
                    got: inflated.len(),
                    expected,
                });
            }
            inflated
        } else {
            let prev = self.prev.as_ref().ok_or(EncodeError::NoKeyframe)?;
            if (enc.width, enc.height) != self.dims {
                return Err(EncodeError::DeltaDimsMismatch {
                    got: (enc.width, enc.height),
                    expected: self.dims,
                });
            }
            let inflated = inflate(&enc.data, expected)?;
            if inflated.len() != prev.len() {
                return Err(EncodeError::SizeMismatch {
                    got: inflated.len(),
                    expected: prev.len(),
                });
            }
            let mut out = vec![0u8; inflated.len()];
            for i in 0..inflated.len() {
                out[i] = inflated[i] ^ prev[i];
            }
            out
        };
        self.prev = Some(pixels.clone());
        self.dims = (enc.width, enc.height);
        Ok(pixels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, fill: u8, keyframe: bool) -> CapturedFrame {
        CapturedFrame {
            monitor_id: 0,
            width: w,
            height: h,
            bytes: vec![fill; (w * h * 4) as usize],
            is_keyframe: keyframe,
        }
    }

    #[test]
    fn keyframe_round_trips() {
        let mut enc = SoftwareEncoder::new(30);
        let mut dec = SoftwareDecoder::new();
        let f = frame(16, 16, 0xAB, false);
        let e = enc.encode(&f).unwrap();
        assert!(e.is_keyframe, "first frame must be a keyframe");
        assert_eq!(dec.decode(&e).unwrap(), f.bytes);
    }

    #[test]
    fn delta_round_trips_against_previous() {
        let mut enc = SoftwareEncoder::new(30);
        let mut dec = SoftwareDecoder::new();
        let f1 = frame(32, 32, 0x10, false);
        // f2 differs from f1 in a region.
        let mut f2 = frame(32, 32, 0x10, false);
        for b in f2.bytes.iter_mut().take(100) {
            *b = 0x99;
        }
        let e1 = enc.encode(&f1).unwrap();
        let e2 = enc.encode(&f2).unwrap();
        assert!(e1.is_keyframe && !e2.is_keyframe, "second frame is a delta");
        assert_eq!(dec.decode(&e1).unwrap(), f1.bytes);
        assert_eq!(dec.decode(&e2).unwrap(), f2.bytes, "delta reconstructs exactly");
    }

    #[test]
    fn static_screen_delta_is_tiny() {
        // The whole point of the fallback: an unchanged frame compresses to almost nothing, even
        // when the frame itself has real (incompressible-ish) content.
        let mut enc = SoftwareEncoder::new(1000);
        let mut f = frame(256, 256, 0, false);
        // Varied, poorly-compressible content so the keyframe is genuinely large.
        for (i, b) in f.bytes.iter_mut().enumerate() {
            *b = ((i * 2654435761) >> 13) as u8;
        }
        let key = enc.encode(&f).unwrap();
        let delta = enc.encode(&f).unwrap(); // identical frame → all-zero XOR
        assert!(!delta.is_keyframe);
        let raw_len = f.bytes.len(); // 256*256*4 = 262144
        assert!(
            delta.data.len() < raw_len / 100,
            "unchanged-frame delta {} should be <1/100 of raw {raw_len} (>100:1 compression)",
            delta.data.len()
        );
        // The unchanged delta is dramatically smaller than the content keyframe.
        assert!(
            delta.data.len() * 10 < key.data.len(),
            "delta {} should be <<1/10 of keyframe {}",
            delta.data.len(),
            key.data.len()
        );
    }

    #[test]
    fn forced_keyframe_interval() {
        let mut enc = SoftwareEncoder::new(2); // key, delta, delta, then key again
        let f = frame(8, 8, 1, false);
        assert!(enc.encode(&f).unwrap().is_keyframe); // 1: key
        assert!(!enc.encode(&f).unwrap().is_keyframe); // 2: delta
        assert!(!enc.encode(&f).unwrap().is_keyframe); // 3: delta
        assert!(enc.encode(&f).unwrap().is_keyframe); // 4: interval hit → key
    }

    #[test]
    fn wire_bytes_round_trip() {
        let e = EncodedFrame {
            is_keyframe: true,
            width: 640,
            height: 480,
            data: vec![1, 2, 3, 4, 5],
        };
        let back = EncodedFrame::from_bytes(&e.to_bytes()).unwrap();
        assert_eq!(back, e);
        assert_eq!(EncodedFrame::from_bytes(&[0, 0]), Err(EncodeError::Truncated));
    }

    #[test]
    fn delta_without_keyframe_errors() {
        let mut dec = SoftwareDecoder::new();
        let delta = EncodedFrame {
            is_keyframe: false,
            width: 8,
            height: 8,
            data: deflate(&[0u8; 256]).unwrap(),
        };
        assert_eq!(dec.decode(&delta), Err(EncodeError::NoKeyframe));
    }

    fn key(w: u32, h: u32, data: Vec<u8>) -> EncodedFrame {
        EncodedFrame {
            is_keyframe: true,
            width: w,
            height: h,
            data,
        }
    }

    #[test]
    fn zero_area_round_trip_positive_control() {
        let mut enc = SoftwareEncoder::new(1000);
        let mut dec = SoftwareDecoder::new();
        let f1 = frame(16, 16, 0x21, false);
        let f2 = frame(16, 16, 0x42, false);
        let e1 = enc.encode(&f1).unwrap();
        let e2 = enc.encode(&f2).unwrap();
        assert!(e1.is_keyframe && !e2.is_keyframe);
        assert_eq!(dec.decode(&e1).unwrap(), f1.bytes);
        assert_eq!(dec.decode(&e2).unwrap(), f2.bytes);
    }

    #[test]
    fn decode_refuses_zero_area_keyframe() {
        let empty = deflate(&[]).unwrap();
        assert_eq!(
            SoftwareDecoder::new().decode(&key(16, 0, empty.clone())),
            Err(EncodeError::EmptyFrame { width: 16, height: 0 })
        );
        assert_eq!(
            SoftwareDecoder::new().decode(&key(0, 0, empty.clone())),
            Err(EncodeError::EmptyFrame { width: 0, height: 0 })
        );
        assert_eq!(
            SoftwareDecoder::new().decode(&key(0, 16, empty.clone())),
            Err(EncodeError::EmptyFrame { width: 0, height: 16 })
        );
        // Wire form too: nonzero (0x16) keyframe flag byte, for each zero-area geometry.
        for (w, h) in [(16u32, 0u32), (0, 16), (0, 0)] {
            let mut wire = vec![0x16u8];
            wire.extend_from_slice(&w.to_be_bytes());
            wire.extend_from_slice(&h.to_be_bytes());
            wire.extend_from_slice(&empty);
            let parsed = EncodedFrame::from_bytes(&wire).unwrap();
            assert!(parsed.is_keyframe);
            assert_eq!(
                SoftwareDecoder::new().decode(&parsed),
                Err(EncodeError::EmptyFrame { width: w, height: h })
            );
        }
    }

    #[test]
    fn zero_area_keyframe_does_not_wipe_reference() {
        let mut enc = SoftwareEncoder::new(1000);
        let mut dec = SoftwareDecoder::new();
        let f1 = frame(16, 16, 0x11, false);
        let f2 = frame(16, 16, 0x77, false);
        let e1 = enc.encode(&f1).unwrap();
        let e2 = enc.encode(&f2).unwrap();
        assert_eq!(dec.decode(&e1).unwrap(), f1.bytes);
        assert_eq!(
            dec.decode(&key(0, 0, deflate(&[]).unwrap())),
            Err(EncodeError::EmptyFrame { width: 0, height: 0 })
        );
        assert_eq!(dec.decode(&e2).unwrap(), f2.bytes, "reference frame survived");
    }

    #[test]
    fn zero_width_delta_is_empty_frame_not_dims_mismatch() {
        let mut enc = SoftwareEncoder::new(1000);
        let mut dec = SoftwareDecoder::new();
        dec.decode(&enc.encode(&frame(16, 16, 0x05, false)).unwrap()).unwrap();
        let delta = EncodedFrame {
            is_keyframe: false,
            width: 0,
            height: 16,
            data: deflate(&[]).unwrap(),
        };
        assert_eq!(dec.decode(&delta), Err(EncodeError::EmptyFrame { width: 0, height: 16 }));
        // A zero-dim delta with no reference is also EmptyFrame, not NoKeyframe.
        assert_eq!(
            SoftwareDecoder::new().decode(&delta),
            Err(EncodeError::EmptyFrame { width: 0, height: 16 })
        );
    }

    #[test]
    fn decode_refuses_zlib_bomb() {
        // 64 MiB of zeros deflates to a small payload (hundreds of KB at most, depending
        // on the compression level); the header claims 16x16 (1024 bytes).
        let bomb = deflate(&vec![0u8; 64 * 1024 * 1024]).unwrap();
        assert!(
            bomb.len() < 1024 * 1024,
            "bomb payload is far smaller than its expansion: {}",
            bomb.len()
        );
        let r = SoftwareDecoder::new().decode(&key(16, 16, bomb.clone()));
        assert_eq!(r, Err(EncodeError::TooLarge { limit: 1024 }));
        // Delta path is bounded the same way.
        let mut dec = SoftwareDecoder::new();
        dec.decode(&key(16, 16, deflate(&[0u8; 1024]).unwrap())).unwrap();
        let delta = EncodedFrame {
            is_keyframe: false,
            width: 16,
            height: 16,
            data: bomb,
        };
        assert_eq!(dec.decode(&delta), Err(EncodeError::TooLarge { limit: 1024 }));
    }

    #[test]
    fn inflate_stops_at_limit_plus_one() {
        let out = inflate(&deflate(&[7u8; 4096]).unwrap(), 100);
        assert_eq!(out, Err(EncodeError::TooLarge { limit: 100 }));
        assert_eq!(inflate(&deflate(&[7u8; 100]).unwrap(), 100).unwrap().len(), 100);
    }

    #[test]
    fn keyframe_length_must_match_header_dimensions() {
        let short = key(16, 16, deflate(&[1u8; 1000]).unwrap());
        assert_eq!(
            SoftwareDecoder::new().decode(&short),
            Err(EncodeError::SizeMismatch { got: 1000, expected: 1024 })
        );
        // A refused keyframe must not become the reference for a later delta.
        let mut dec = SoftwareDecoder::new();
        assert!(dec.decode(&short).is_err());
        let delta = EncodedFrame {
            is_keyframe: false,
            width: 16,
            height: 16,
            data: deflate(&[0u8; 1000]).unwrap(),
        };
        assert_eq!(dec.decode(&delta), Err(EncodeError::NoKeyframe));
    }

    #[test]
    fn huge_header_dimensions_are_too_large() {
        let tiny = deflate(&[0u8; 16]).unwrap();
        let limit = MAX_DECODED_FRAME_BYTES;
        assert_eq!(
            SoftwareDecoder::new().decode(&key(u32::MAX, u32::MAX, tiny.clone())),
            Err(EncodeError::TooLarge { limit })
        );
        // 8193 x 8192 x 4 is one row over the limit.
        assert_eq!(
            SoftwareDecoder::new().decode(&key(8193, 8192, tiny.clone())),
            Err(EncodeError::TooLarge { limit })
        );
    }

    #[test]
    fn limit_sized_dimensions_pass_the_bound_check() {
        // 8192 x 8192 x 4 == MAX_DECODED_FRAME_BYTES exactly: not TooLarge from the header; the
        // tiny payload then fails only the exact-length check.
        let r = SoftwareDecoder::new().decode(&key(8192, 8192, deflate(&[0u8; 16]).unwrap()));
        assert_eq!(
            r,
            Err(EncodeError::SizeMismatch { got: 16, expected: MAX_DECODED_FRAME_BYTES })
        );
    }

    #[test]
    fn decode_delta_size_mismatch_returns_error() {
        let mut enc = SoftwareEncoder::new(1000);
        let mut dec = SoftwareDecoder::new();
        // Establish a 16×16 (1024-byte) reference in the decoder.
        let kf = enc.encode(&frame(16, 16, 0xCC, false)).unwrap();
        assert!(kf.is_keyframe);
        dec.decode(&kf).unwrap();
        // Delta decompresses to 64 bytes, not the 1024 the decoder expects.
        let wrong_size_delta = EncodedFrame {
            is_keyframe: false,
            width: 16,
            height: 16,
            data: deflate(&[0u8; 64]).unwrap(),
        };
        assert_eq!(
            dec.decode(&wrong_size_delta),
            Err(EncodeError::SizeMismatch { got: 64, expected: 1024 })
        );
    }

    fn raw_frame(w: u32, h: u32, len: usize, fill: u8) -> CapturedFrame {
        CapturedFrame {
            monitor_id: 0,
            width: w,
            height: h,
            bytes: vec![fill; len],
            is_keyframe: false,
        }
    }

    #[test]
    fn encoder_round_trips_keyframe_and_delta_positive_control() {
        let mut enc = SoftwareEncoder::new(30);
        let mut dec = SoftwareDecoder::new();
        let f1 = frame(16, 16, 0x21, false);
        let mut f2 = frame(16, 16, 0x21, false);
        f2.bytes[5] = 0xEE;
        let e1 = enc.encode(&f1).unwrap();
        let e2 = enc.encode(&f2).unwrap();
        assert!(e1.is_keyframe && !e2.is_keyframe);
        assert_eq!(dec.decode(&e1).unwrap(), f1.bytes);
        assert_eq!(dec.decode(&e2).unwrap(), f2.bytes);
    }

    #[test]
    fn encode_refuses_padded_pitch_buffer() {
        let mut enc = SoftwareEncoder::new(30);
        let padded = raw_frame(16, 16, 16 * 16 * 4 + 64, 1);
        assert_eq!(
            enc.encode(&padded),
            Err(EncodeError::BadFrame { got: 1088, expected: 1024 })
        );
    }

    #[test]
    fn encode_refuses_short_buffer() {
        let mut enc = SoftwareEncoder::new(30);
        assert_eq!(
            enc.encode(&raw_frame(16, 16, 1000, 1)),
            Err(EncodeError::BadFrame { got: 1000, expected: 1024 })
        );
    }

    #[test]
    fn encode_longer_buffer_with_same_dims_errors_instead_of_panicking() {
        let mut enc = SoftwareEncoder::new(30);
        enc.encode(&frame(16, 16, 1, false)).unwrap();
        assert_eq!(
            enc.encode(&raw_frame(16, 16, 1024 + 64, 1)),
            Err(EncodeError::BadFrame { got: 1088, expected: 1024 })
        );
    }

    #[test]
    fn rejected_frame_leaves_encoder_state_unchanged() {
        let mut enc = SoftwareEncoder::new(30);
        let mut dec = SoftwareDecoder::new();
        let f1 = frame(16, 16, 0x40, false);
        let e1 = enc.encode(&f1).unwrap();
        assert_eq!(dec.decode(&e1).unwrap(), f1.bytes);
        // Bad frames: same dims long, and different dims short (must not reset the reference).
        assert!(enc.encode(&raw_frame(16, 16, 2000, 9)).is_err());
        assert!(enc.encode(&raw_frame(8, 8, 10, 9)).is_err());
        let mut f2 = frame(16, 16, 0x40, false);
        f2.bytes[100] = 0x77;
        let e2 = enc.encode(&f2).unwrap();
        assert!(!e2.is_keyframe, "retained reference still yields a delta");
        assert_eq!(dec.decode(&e2).unwrap(), f2.bytes);
    }

    #[test]
    fn rejected_frame_does_not_advance_keyframe_interval() {
        let mut enc = SoftwareEncoder::new(1); // key, delta, key
        let f = frame(8, 8, 3, false);
        assert!(enc.encode(&f).unwrap().is_keyframe);
        for _ in 0..5 {
            assert!(enc.encode(&raw_frame(8, 8, 5, 0)).is_err());
        }
        assert!(!enc.encode(&f).unwrap().is_keyframe);
        assert!(enc.encode(&f).unwrap().is_keyframe);
    }

    #[test]
    fn zero_dimension_with_empty_buffer_is_accepted() {
        // expected == 0, so an empty buffer is consistent and the encoder still accepts it, but
        // the decoder refuses a zero-area frame with EmptyFrame.
        let mut enc = SoftwareEncoder::new(30);
        let mut dec = SoftwareDecoder::new();
        for (w, h) in [(0, 16), (16, 0), (0, 0)] {
            let e = enc.encode(&raw_frame(w, h, 0, 0)).unwrap();
            assert!(e.is_keyframe);
            assert_eq!(
                dec.decode(&e),
                Err(EncodeError::EmptyFrame { width: w, height: h })
            );
        }
        // A non-empty buffer with a zero dimension is refused.
        assert_eq!(
            enc.encode(&raw_frame(0, 16, 4, 0)),
            Err(EncodeError::BadFrame { got: 4, expected: 0 })
        );
    }

    #[test]
    fn oversized_dimensions_are_refused_without_allocating() {
        let mut enc = SoftwareEncoder::new(30);
        // One row over the limit, with an empty buffer: nothing is allocated or deflated.
        assert_eq!(
            enc.encode(&raw_frame(8193, 8192, 0, 0)),
            Err(EncodeError::BadFrame { got: 0, expected: 8193 * 8192 * 4 })
        );
        let r = enc.encode(&raw_frame(u32::MAX, u32::MAX, 0, 0));
        assert!(matches!(r, Err(EncodeError::BadFrame { got: 0, .. })));
        // Exactly at the limit is within bounds, so only the length disagrees.
        assert_eq!(
            enc.encode(&raw_frame(8192, 8192, 0, 0)),
            Err(EncodeError::BadFrame { got: 0, expected: MAX_DECODED_FRAME_BYTES })
        );
    }

    fn delta(w: u32, h: u32, payload: &[u8]) -> EncodedFrame {
        EncodedFrame {
            is_keyframe: false,
            width: w,
            height: h,
            data: deflate(payload).unwrap(),
        }
    }

    fn decoder_with_16x16_reference() -> (SoftwareDecoder, CapturedFrame) {
        let mut enc = SoftwareEncoder::new(1000);
        let mut dec = SoftwareDecoder::new();
        let f = frame(16, 16, 0x33, false);
        dec.decode(&enc.encode(&f).unwrap()).unwrap();
        (dec, f)
    }

    #[test]
    fn same_dim_delta_still_decodes_exactly_positive_control() {
        let (mut dec, f) = decoder_with_16x16_reference();
        let mut xor = vec![0u8; 1024];
        xor[7] = 0x0F;
        let out = dec.decode(&delta(16, 16, &xor)).unwrap();
        let mut expect = f.bytes.clone();
        expect[7] ^= 0x0F;
        assert_eq!(out, expect);
    }

    #[test]
    fn delta_with_different_geometry_is_refused() {
        let (mut dec, _) = decoder_with_16x16_reference();
        for (w, h) in [(8, 32), (32, 8), (17, 16)] {
            // 17x16 inflates to at most 1088 bytes; the 1024-byte payload is valid for all three.
            assert_eq!(
                dec.decode(&delta(w, h, &[0u8; 1024])),
                Err(EncodeError::DeltaDimsMismatch { got: (w, h), expected: (16, 16) })
            );
        }
    }

    #[test]
    fn rejected_delta_leaves_decoder_state_intact() {
        let (mut dec, f) = decoder_with_16x16_reference();
        assert!(dec.decode(&delta(8, 32, &[0xFFu8; 1024])).is_err());
        let mut xor = vec![0u8; 1024];
        xor[100] = 0x5A;
        let out = dec.decode(&delta(16, 16, &xor)).unwrap();
        let mut expect = f.bytes.clone();
        expect[100] ^= 0x5A;
        assert_eq!(out, expect, "reference unchanged by the refused frame");
    }

    #[test]
    fn keyframe_with_new_dims_resets_the_expected_dims() {
        let (mut dec, _) = decoder_with_16x16_reference();
        let k = key(8, 32, deflate(&[0x44u8; 1024]).unwrap());
        assert_eq!(dec.decode(&k).unwrap(), vec![0x44u8; 1024]);
        assert_eq!(
            dec.decode(&delta(16, 16, &[0u8; 1024])),
            Err(EncodeError::DeltaDimsMismatch { got: (16, 16), expected: (8, 32) })
        );
        assert_eq!(dec.decode(&delta(8, 32, &[0u8; 1024])).unwrap(), vec![0x44u8; 1024]);
    }

    #[test]
    fn dims_check_does_not_mask_no_keyframe() {
        let mut dec = SoftwareDecoder::new();
        assert_eq!(dec.decode(&delta(8, 32, &[0u8; 1024])), Err(EncodeError::NoKeyframe));
    }

    #[test]
    fn decode_rejects_corrupt_compressed_data() {
        let frame = EncodedFrame {
            is_keyframe: true,
            width: 4,
            height: 4,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let result = SoftwareDecoder::new().decode(&frame);
        assert!(matches!(result, Err(EncodeError::Zlib(_))));
    }
}
