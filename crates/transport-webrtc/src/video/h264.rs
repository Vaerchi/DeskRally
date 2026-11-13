//! Software **H.264** encode via the bundled Cisco OpenH264 — the *alternate* implementation of
//! [`VideoEncoder`], behind the off-by-default `h264` cargo feature.
//!
//! This is no longer the shipping codec. H.264 carries MPEG-LA patent-licensing exposure that
//! blocks open-sourcing the project, so [`super::new_video_encoder`] returns VP8 and the default
//! build does not even compile openh264. It is kept because it is what makes the encoder seam
//! *real* rather than decorative: a second, structurally different backend (native BGRA input, no
//! explicit context re-init, Annex-B output instead of a VP8 frame) that the pipeline consumes
//! without knowing the difference. A future hardware encoder (NVENC/QSV/AMF) drops in exactly here.
//!
//! Build/run it with:
//! ```text
//! cargo test -p rmt-transport-webrtc --features h264
//! ```
//!
//! The OpenH264 `Encoder` holds raw C pointers and is not `Send`, same as the VP8 one — own it on
//! a single thread.

use openh264::encoder::{Encoder, EncoderConfig, UsageType};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::OpenH264API;

use super::{EncodedAu, VideoEncoder};

/// A stateful H.264 encoder. Not `Send` (OpenH264 raw pointers) — own it on one thread.
pub struct H264Encoder {
    inner: Encoder,
    dims: (usize, usize),
}

impl H264Encoder {
    /// Build an encoder tuned for desktop capture at the given target bitrate (bits/sec).
    pub fn new(bitrate_bps: u32) -> Result<Self, String> {
        let api = OpenH264API::from_source();
        let config = EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .max_frame_rate(30.0)
            .set_bitrate_bps(bitrate_bps);
        let inner = Encoder::with_api_config(api, config).map_err(|e| e.to_string())?;
        Ok(Self { inner, dims: (0, 0) })
    }
}

impl VideoEncoder for H264Encoder {
    /// Encode one BGRA8 frame (`w*h*4` bytes). H.264 needs even dimensions, so an odd width/height
    /// is cropped by one pixel. Returns the Annex-B bitstream and whether it is a keyframe.
    fn encode_bgra(
        &mut self,
        bgra: &[u8],
        w: usize,
        h: usize,
        duration_90khz: u32,
    ) -> Result<EncodedAu, String> {
        // Crop to even dimensions if needed (repacking rows tightly).
        let ew = w & !1;
        let eh = h & !1;
        if ew == 0 || eh == 0 {
            return Err(format!("frame too small: {w}x{h}"));
        }

        let cropped;
        let (pixels, cw, ch) = if ew == w && eh == h {
            (bgra, w, h)
        } else {
            // Repack the top-left ew*eh region into a tight BGRA buffer.
            let mut out = vec![0u8; ew * eh * 4];
            for row in 0..eh {
                let src = &bgra[row * w * 4..row * w * 4 + ew * 4];
                out[row * ew * 4..row * ew * 4 + ew * 4].copy_from_slice(src);
            }
            cropped = out;
            (cropped.as_slice(), ew, eh)
        };

        if pixels.len() < cw * ch * 4 {
            return Err(format!("short BGRA buffer: {} < {}", pixels.len(), cw * ch * 4));
        }

        self.dims = (cw, ch);
        let yuv = YUVBuffer::from_rgb_source(BgraSliceU8::new(&pixels[..cw * ch * 4], (cw, ch)));
        let bitstream = self.inner.encode(&yuv).map_err(|e| e.to_string())?;

        use openh264::encoder::FrameType;
        let keyframe = matches!(bitstream.frame_type(), FrameType::IDR | FrameType::I);
        Ok(EncodedAu {
            data: bitstream.to_vec(),
            keyframe,
            duration_90khz,
            width: ew as u32,
            height: eh as u32,
        })
    }

    /// OpenH264 can force an IDR on the next `encode` call, so this is a real implementation
    /// rather than a no-op — the seam does not have to paper over anything here.
    fn request_keyframe(&mut self) {
        self.inner.force_intra_frame();
    }

    /// **Not supported**, and it says so rather than accepting the call and ignoring it.
    ///
    /// openh264 0.6's `set_bitrate_bps` is a *consuming builder* method on `EncoderConfig`, applied
    /// only when the encoder is constructed; there is no live setter. A defaulted no-op here would
    /// be exactly the failure this project keeps finding — a defence built and never applied — with
    /// the rate controller reporting success while nothing changed. The transport logs this once
    /// per session and keeps the previous target.
    ///
    /// The backend stays dev-only (`--features h264`), so this is a real limitation of a real
    /// second implementation, which is the point of having one.
    fn set_bitrate(&mut self, _bitrate_bps: u32) -> Result<(), String> {
        Err("openh264 0.6 exposes set_bitrate_bps only on the consuming EncoderConfig builder; \
             this backend cannot retarget a live encoder"
            .to_string())
    }

    /// **Not supported.** This backend hands BGRA to openh264's own `YUVBuffer` converter and never
    /// goes through `video::color`, so there is nowhere to apply the chroma mode.
    fn set_chroma_mode(&mut self, _mode: super::ChromaMode) -> Result<(), String> {
        Err("the h264 backend converts colour via openh264's YUVBuffer, not video::color; \
             chroma modes are unavailable"
            .to_string())
    }

    fn webrtc_mime_type(&self) -> &'static str {
        webrtc::api::media_engine::MIME_TYPE_H264
    }

    fn codec_name(&self) -> &'static str {
        "H.264 (OpenH264)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bgra(w: usize, h: usize, tick: u8) -> Vec<u8> {
        let mut v = vec![0u8; w * h * 4];
        for (i, px) in v.chunks_mut(4).enumerate() {
            px[0] = (i as u8).wrapping_mul(3).wrapping_add(tick);
            px[1] = (i as u8).wrapping_mul(5);
            px[2] = (i as u8).wrapping_mul(7).wrapping_add(tick);
            px[3] = 0xFF;
        }
        v
    }

    #[test]
    fn encodes_bgra_to_annexb_h264() {
        let mut enc = H264Encoder::new(2_000_000).expect("encoder");
        let au = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, 3000).expect("encode");
        assert!(!au.data.is_empty());
        assert!(au.keyframe, "first frame is a keyframe (IDR)");
        assert!(
            au.data.starts_with(&[0, 0, 0, 1]) || au.data.starts_with(&[0, 0, 1]),
            "starts with an H.264 start code: {:02x?}",
            &au.data[..au.data.len().min(4)]
        );
    }

    #[test]
    fn later_frames_are_deltas() {
        let mut enc = H264Encoder::new(2_000_000).expect("encoder");
        let _ = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, 3000).unwrap();
        let p = enc.encode_bgra(&bgra(64, 64, 1), 64, 64, 3000).unwrap();
        assert!(!p.data.is_empty());
        assert!(!p.keyframe, "second frame is a delta (P-frame)");
    }

    #[test]
    fn request_keyframe_forces_an_idr() {
        let mut enc = H264Encoder::new(2_000_000).expect("encoder");
        assert!(enc.encode_bgra(&bgra(64, 64, 0), 64, 64, 3000).unwrap().keyframe);
        assert!(!enc.encode_bgra(&bgra(64, 64, 1), 64, 64, 3000).unwrap().keyframe);
        enc.request_keyframe();
        assert!(enc.encode_bgra(&bgra(64, 64, 2), 64, 64, 3000).unwrap().keyframe);
    }

    #[test]
    fn crops_odd_dimensions() {
        let mut enc = H264Encoder::new(1_000_000).expect("encoder");
        let au = enc.encode_bgra(&bgra(65, 65, 0), 65, 65, 3000).expect("encode odd");
        assert!(!au.data.is_empty());
    }

    #[test]
    fn decodes_back_to_a_frame() {
        use openh264::decoder::Decoder;
        let mut enc = H264Encoder::new(2_000_000).expect("encoder");
        let au = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, 3000).unwrap();
        let mut dec = Decoder::new().expect("decoder");
        let decoded = dec.decode(&au.data).expect("decode ok");
        assert!(decoded.is_some(), "decoder produced a frame from our bitstream");
    }
}
