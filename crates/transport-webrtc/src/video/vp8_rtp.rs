//! Read what a **receiver** can see about a VP8 stream, straight off an RTP payload.
//!
//! # Why this exists
//!
//! Of the four quality knobs, three are verifiable from the wire with simple accounting — bitrate
//! from bytes/sec, frame rate from distinct RTP timestamps, colour from the resulting bitrate. The
//! fourth, **resolution**, is not: under CBR libvpx spends its target regardless of how many pixels
//! it is spending it on, so a `scale_div` change moves no byte counter at all. The only honest
//! receiver-side evidence that the encoder really changed resolution is the dimensions VP8 writes
//! into its keyframe header.
//!
//! Everything here is a pure function over bytes: no peer connection, no encoder, no clock.
//!
//! # The two layers being parsed
//!
//! 1. The **RTP payload descriptor** (RFC 7741 §4.2) that webrtc-rs' VP8 payloader prepends to
//!    every packet. Its `S` bit and partition index identify the first packet of a frame — the only
//!    packet that carries the payload header at all.
//! 2. The **VP8 uncompressed data chunk** (RFC 6386 §9.1) at the start of that first packet: a
//!    3-byte frame tag, and for a keyframe the start code `9d 01 2a` followed by 14-bit width and
//!    height.
//!
//! The byte-level knowledge is the same the `vp8.rs` encoder tests already assert against; this
//! module is the receiver's half of it.

/// What one RTP packet reveals about the VP8 frame it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Vp8PacketInfo {
    /// This packet begins a new frame (descriptor `S` bit set with partition index 0), so its
    /// payload starts with the VP8 frame tag.
    pub frame_start: bool,
    /// The frame is a keyframe. Only meaningful when `frame_start` is set.
    pub keyframe: bool,
    /// Encoded dimensions from the keyframe header, when this packet started a keyframe and the
    /// header was complete. `None` for inter frames, continuation packets, and truncated payloads.
    pub dimensions: Option<(u32, u32)>,
}

/// Inspect one RTP payload (descriptor + VP8 data).
///
/// Total: never panics, never allocates. A malformed, empty or truncated payload yields
/// `Vp8PacketInfo::default()` (i.e. "tells us nothing") rather than an error — this runs on every
/// inbound packet of a live stream, where the correct response to a damaged packet is to learn
/// nothing from it and move on.
pub fn inspect_vp8_payload(payload: &[u8]) -> Vp8PacketInfo {
    let mut info = Vp8PacketInfo::default();
    let Some(&b0) = payload.first() else {
        return info;
    };

    // Mandatory descriptor byte: X R N S R PID(3).
    const X_EXTENDED: u8 = 0x80;
    const S_START_OF_PARTITION: u8 = 0x10;
    const PID_MASK: u8 = 0x07;

    // A frame starts where the first partition starts: S set AND partition index 0. S alone is not
    // enough — later partitions of the SAME frame also set it, and treating one of those as a
    // frame start would read compressed coefficients as a frame tag.
    info.frame_start = (b0 & S_START_OF_PARTITION) != 0 && (b0 & PID_MASK) == 0;

    let mut off = 1usize;
    if (b0 & X_EXTENDED) != 0 {
        let Some(&x) = payload.get(off) else {
            return info;
        };
        off += 1;
        const I_PICTURE_ID: u8 = 0x80;
        const L_TL0PICIDX: u8 = 0x40;
        const T_TID: u8 = 0x20;
        const K_KEYIDX: u8 = 0x10;
        if (x & I_PICTURE_ID) != 0 {
            let Some(&pid0) = payload.get(off) else {
                return info;
            };
            // The M bit says the PictureID is 15 bits over two bytes rather than 7 over one.
            off += if (pid0 & 0x80) != 0 { 2 } else { 1 };
        }
        if (x & L_TL0PICIDX) != 0 {
            off += 1;
        }
        // T and K share one byte, present if EITHER is set — a common off-by-one here would shift
        // the whole payload header by a byte and read garbage dimensions.
        if (x & (T_TID | K_KEYIDX)) != 0 {
            off += 1;
        }
    }

    if !info.frame_start {
        return info;
    }
    let data = &payload[off.min(payload.len())..];
    // Frame tag: 3 bytes little-endian; bit 0 is the frame type, 0 = KEY (RFC 6386 §9.1).
    let Some(&tag0) = data.first() else {
        return info;
    };
    info.keyframe = (tag0 & 0x01) == 0;
    if !info.keyframe {
        return info;
    }
    // Keyframe: 3-byte tag, 3-byte start code, then 2+2 bytes of dimensions = 10 bytes.
    if data.len() < 10 || data[3..6] != [0x9d, 0x01, 0x2a] {
        return info; // not a keyframe header after all, or split before the dimensions
    }
    let w = u16::from_le_bytes([data[6], data[7]]) & 0x3FFF;
    let h = u16::from_le_bytes([data[8], data[9]]) & 0x3FFF;
    info.dimensions = Some((w as u32, h as u32));
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::{VideoEncoder, Vp8Encoder};

    /// The bare (non-extended) descriptor webrtc-rs emits for the first packet of a frame.
    fn first_packet(vp8: &[u8]) -> Vec<u8> {
        let mut v = vec![0x10u8]; // S set, PID 0, no extension
        v.extend_from_slice(vp8);
        v
    }

    /// Round-trip against REAL encoder output at two sizes. Hand-built bytes could agree with a
    /// wrong parser; libvpx's own bitstream cannot.
    #[test]
    fn reads_the_dimensions_real_libvpx_wrote() {
        for (w, h) in [(64usize, 64usize), (128, 96), (320, 240)] {
            let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
            let mut px = vec![0u8; w * h * 4];
            for (i, p) in px.chunks_mut(4).enumerate() {
                p[0] = (i * 7) as u8;
                p[1] = (i * 13) as u8;
                p[2] = (i * 31) as u8;
                p[3] = 0xFF;
            }
            let au = enc.encode_bgra(&px, w, h, 3000).expect("encode");
            assert!(au.keyframe, "first frame is a keyframe");
            let info = inspect_vp8_payload(&first_packet(&au.data));
            assert!(info.frame_start, "S bit + PID 0 is a frame start");
            assert!(info.keyframe, "libvpx said keyframe and so must we");
            assert_eq!(
                info.dimensions,
                Some((w as u32, h as u32)),
                "the keyframe header must report exactly what was encoded"
            );
            // ...and the AU agrees, so the two independent observables cannot silently diverge.
            assert_eq!(info.dimensions, Some((au.width, au.height)));
        }
    }

    #[test]
    fn an_inter_frame_is_not_a_keyframe_and_carries_no_dimensions() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        let px = |t: u8| {
            let mut v = vec![0u8; 64 * 64 * 4];
            for (i, p) in v.chunks_mut(4).enumerate() {
                p[0] = (i as u8).wrapping_add(t);
                p[1] = (i as u8).wrapping_mul(3);
                p[2] = (i as u8).wrapping_mul(5).wrapping_add(t);
                p[3] = 0xFF;
            }
            v
        };
        let _ = enc.encode_bgra(&px(0), 64, 64, 3000).unwrap();
        let inter = enc.encode_bgra(&px(9), 64, 64, 3000).unwrap();
        assert!(!inter.keyframe);
        let info = inspect_vp8_payload(&first_packet(&inter.data));
        assert!(info.frame_start);
        assert!(!info.keyframe, "inter frame");
        assert_eq!(info.dimensions, None, "only a keyframe header carries dimensions");
    }

    /// A later partition of the same frame also sets S. Treating it as a frame start would read
    /// coefficient bytes as a frame tag and could report a keyframe (and dimensions) at random.
    #[test]
    fn a_later_partition_is_not_a_frame_start() {
        let mut body = vec![0x11u8]; // S set, but PID 1
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a, 64, 0, 64, 0]);
        let info = inspect_vp8_payload(&body);
        assert!(!info.frame_start, "PID != 0 is a continuation, not a new frame");
        assert!(!info.keyframe);
        assert_eq!(info.dimensions, None);
    }

    /// The extended descriptor's optional fields must be skipped by exactly the right number of
    /// bytes, or the frame tag is read one byte off and everything after it is wrong.
    #[test]
    fn skips_every_optional_descriptor_field() {
        // A real 64x64 keyframe header to append after each descriptor shape.
        let kf = [0x00u8, 0x00, 0x00, 0x9d, 0x01, 0x2a, 64, 0, 64, 0];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("no extension", vec![0x10]),
            ("X, nothing set", vec![0x90, 0x00]),
            ("X + short PictureID", vec![0x90, 0x80, 0x7F]),
            ("X + long PictureID", vec![0x90, 0x80, 0x80, 0x01]),
            ("X + TL0PICIDX", vec![0x90, 0x40, 0xAB]),
            ("X + TID only", vec![0x90, 0x20, 0xC0]),
            ("X + KEYIDX only", vec![0x90, 0x10, 0x05]),
            ("X + TID and KEYIDX share one byte", vec![0x90, 0x30, 0xC5]),
            (
                "X + everything",
                vec![0x90, 0xF0, 0x80, 0x01, 0xAB, 0xC5],
            ),
        ];
        for (name, desc) in cases {
            let mut pkt = desc.clone();
            pkt.extend_from_slice(&kf);
            let info = inspect_vp8_payload(&pkt);
            assert!(info.frame_start, "{name}: frame start");
            assert!(info.keyframe, "{name}: keyframe");
            assert_eq!(info.dimensions, Some((64, 64)), "{name}: dimensions");
        }
    }

    /// Every truncation point must produce "tells us nothing", never a panic and never a
    /// confidently wrong answer. This runs on live network input.
    #[test]
    fn truncated_and_garbage_payloads_never_panic() {
        let mut full = vec![0x90u8, 0xF0, 0x80, 0x01, 0xAB, 0xC5];
        full.extend_from_slice(&[0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a, 64, 0, 64, 0]);
        for n in 0..full.len() {
            let info = inspect_vp8_payload(&full[..n]);
            // The only claim allowed from a truncated payload is one that cannot be wrong:
            // dimensions require all 10 header bytes.
            if info.dimensions.is_some() {
                assert!(n >= full.len(), "reported dimensions from {n} bytes");
            }
        }
        assert_eq!(inspect_vp8_payload(&[]), Vp8PacketInfo::default());
        // A frame start whose "start code" is wrong must not yield dimensions.
        let mut bogus = vec![0x10u8];
        bogus.extend_from_slice(&[0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 64, 0, 64, 0]);
        let info = inspect_vp8_payload(&bogus);
        assert!(info.keyframe, "the tag really does say keyframe");
        assert_eq!(info.dimensions, None, "but the start code does not match");
    }
}
