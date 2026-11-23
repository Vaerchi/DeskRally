//! Pluggable software video encode for the WebRTC video media track (ADR-005/006 fallback path).
//!
//! # The seam
//!
//! [`VideoEncoder`] is the only thing [`crate::WebRtcTransport`]'s video pipeline knows about. It
//! holds a `Box<dyn VideoEncoder>` produced by [`new_video_encoder`], and negotiates whatever
//! [`NEGOTIATED_MIME_TYPE`] says. **Those two items, together, are the entire codec choice** —
//! swapping codecs is a one-line change in each, and the two are cross-checked at construction so
//! they cannot silently drift apart (negotiating VP8 while encoding H.264 produces a black
//! `<video>` and no error anywhere).
//!
//! Implementations:
//! * [`Vp8Encoder`] — **the shipping encoder.** libvpx VP8: royalty-free (BSD-3-Clause with an
//!   explicit patent grant) and mandatory-to-implement for WebRTC browsers.
//! * [`H264Encoder`] — OpenH264, behind the off-by-default `h264` feature. Kept so the seam has a
//!   second, structurally different implementation proving it is real; not shipped, because H.264
//!   patent licensing is what blocks open-sourcing this project.
//!
//! A future hardware encoder (NVENC/QSV/AMF) implements the same trait and drops in the same way.
//!
//! # Threading
//!
//! Both implementations wrap raw C encoder state and are **not `Send`**, so the trait object is
//! deliberately *not* `Box<dyn VideoEncoder + Send>`: the transport owns it on one dedicated OS
//! thread and only moves owned byte buffers across the async boundary. Never capture one in a
//! `tokio::spawn`ed future.

mod color;
pub mod ivf;
pub(crate) mod rate;
mod vp8;
mod vp8_decode;
pub(crate) mod vp8_rtp;

#[cfg(feature = "h264")]
mod h264;

pub use color::{bgra_to_i420_into, bgra_to_i420_into_mode, I420Layout};
pub use vp8::Vp8Encoder;
pub use vp8_decode::{DecodedFrame, Vp8Decoder};
pub use vp8_rtp::Vp8PacketInfo;

#[cfg(feature = "h264")]
pub use h264::H264Encoder;

/// How much colour entropy the encoder is handed (M11). Mirrors `rmt_agent_core::quality::ColorMode`
/// on the encoder side of the seam; the conversion happens once, in the session driver, so this
/// crate keeps its own vocabulary and neither type has to move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChromaMode {
    /// Full colour — the byte-identical pre-M11 path.
    Full,
    /// Both chroma planes forced to the BT.601 neutral; luma untouched.
    Gray,
}

/// The 90 kHz RTP video clock. Frame durations cross the whole pipeline in these units — libvpx's
/// timebase, `EncodedAu::duration_90khz`, and the `Sample::duration` webrtc-rs converts back into
/// an RTP timestamp step all speak it — so there is exactly one place a frame's length is decided.
pub const VIDEO_CLOCK_RATE: u32 = 90_000;

/// One encoded access unit (a whole compressed frame) plus whether it is a keyframe.
///
/// Codec-agnostic on purpose: for H.264 this is an Annex-B access unit, for VP8 a single VP8 frame.
/// Both are exactly what `TrackLocalStaticSample::write_sample` wants, and webrtc-rs picks the
/// right RTP payloader from the negotiated mime type.
pub struct EncodedAu {
    /// The compressed bytes.
    pub data: Vec<u8>,
    /// Whether this access unit is self-contained.
    pub keyframe: bool,
    /// The duration, in 90 kHz ticks, this frame was encoded with — **echoed back**, never
    /// recomputed by the caller.
    ///
    /// The echo is the mechanism, not a convenience: the same number must reach libvpx's rate
    /// controller (as `vpx_codec_encode`'s duration) and the RTP timestamp (via `Sample::duration`),
    /// or the encoder budgets bits for one frame rate while the wire claims another. Recomputing it
    /// downstream would let the two drift silently.
    pub duration_90khz: u32,
    /// Width actually encoded (post even-crop) — what a receiver will read out of a keyframe header.
    pub width: u32,
    /// Height actually encoded.
    pub height: u32,
}

/// One encoded frame offered to a [`RecordingSink`], plus the instant it was handed over.
///
/// Borrowed rather than owned: the tee sits on the encoder thread, and whether to copy is the
/// SINK's decision, not the pipeline's.
pub struct RecordedFrame<'a> {
    /// The compressed bytes — the same buffer about to go to the RTP track.
    pub data: &'a [u8],
    /// Whether this access unit is self-contained.
    pub keyframe: bool,
    /// **The instant the frame was handed to the encoder** — the raw clock reading, deliberately
    /// NOT [`EncodedAu::duration_90khz`].
    ///
    /// This is the single most important field in this struct, and the reason it exists. The
    /// duration that reaches libvpx is clamped to at most one second (`MAX_TICKS`), which is
    /// correct for a rate controller and false for a presentation timeline; and on the DXGI capture
    /// path an idle desktop produces no frame at all rather than a long one. A recorder that summed
    /// durations would write a ten-minute session with five idle minutes as a five-minute file —
    /// wrong about *when* things happened, while looking perfectly well-formed. The sink derives its
    /// own unclamped timeline from these instants.
    pub at: std::time::Instant,
    /// Width actually encoded (post even-crop).
    pub width: u32,
    /// Height actually encoded.
    pub height: u32,
}

/// Somewhere encoded frames are copied to as well as sent (loop 89, session recording).
///
/// # Why this is a trait rather than a recorder living in this crate
///
/// This crate owns the muxer ([`ivf`]) and the tee; it deliberately owns no file handles, no
/// hashing and no filesystem policy. Those need `sha2`, Win32 ACL calls and a disk-space
/// preflight — none of which belong in the crate whose manifest header says it exists "so the heavy
/// webrtc-rs dep tree doesn't touch agent-core/protocol". The same shape as the agent's
/// `ChallengeSigner`, which adapts the agent's `Identity` to this crate's signing seam so the
/// transport needs no key material.
///
/// # The contract, which is a policy decision and not a detail
///
/// [`offer`](Self::offer) is called **on the encoder thread**, in frame order, between the encode
/// and the RTP hand-off. That thread must never block on a disk: a stalled write here is a stalled
/// encoder, which is a stalled capture. So an implementation MUST return promptly — hand the frame
/// to a bounded queue and let another thread write it.
///
/// When that queue is full there are exactly two honest options, and drop-to-latest — what the
/// live video path does one function away, and rightly, because "a stale screen frame has no
/// value" — is not one of them: **a recording with silent holes is worse than no recording, because
/// it looks complete.** The shipped policy is to STOP recording, mark the artifact truncated, and
/// say so. The other defensible choice is to block and let a slow guest disk throttle the live
/// session; this product chose not to, so that a recording can never degrade the support session it
/// is recording.
pub trait RecordingSink: Send + Sync {
    /// Offer one encoded frame. Must not block.
    fn offer(&self, frame: RecordedFrame<'_>);
}

/// A stateful software (or, later, hardware) video encoder driven by the transport's video
/// pipeline.
///
/// Implementations are single-threaded and stateful: frames must be fed in order, and the encoder
/// is responsible for coping with a mid-stream resolution change on its own (the capturers do
/// change size — monitor switches, RDP reconnects, resolution changes).
pub trait VideoEncoder {
    /// Encode one BGRA8 frame. `bgra` is `w * h * 4` bytes, rows tightly packed.
    ///
    /// `duration_90khz` is how long **this** frame lasts, measured between hand-offs, in 90 kHz
    /// ticks. It is not decoration: libvpx derives its rate-control frame rate from the interval
    /// between presentation timestamps, so an encoder told "one 30 fps frame" while the capturer
    /// paces at 5 fps budgets six times too few bits per frame and the wire rate lands nowhere near
    /// the target. Implementations must both use it and echo it back in
    /// [`EncodedAu::duration_90khz`].
    ///
    /// Returns the compressed frame, or an error string for a frame that could not be encoded
    /// (callers log and drop it — a single bad frame must not tear down the session).
    fn encode_bgra(
        &mut self,
        bgra: &[u8],
        w: usize,
        h: usize,
        duration_90khz: u32,
    ) -> Result<EncodedAu, String>;

    /// Ask for the **next** encoded frame to be a keyframe.
    ///
    /// Driven by RTCP PLI/FIR from the receiver ("I cannot decode, send me an intra frame") and by
    /// a viewer joining mid-stream. One-shot: the request is consumed by the next successful
    /// encode.
    fn request_keyframe(&mut self);

    /// Retarget a **live** encoder to a new bitrate (M11).
    ///
    /// Implementations **must not** drop reference frames or force a keyframe. This is the rate
    /// controller's hot path: a keyframe per adjustment would spend, in one 60–150 KB burst, exactly
    /// the bandwidth the adjustment exists to save — and it would arrive at the moment the
    /// controller concluded there was none. That is positive feedback into the collapse.
    ///
    /// `Err` is **non-fatal**: the caller logs it once and keeps the previous target. An encoder
    /// with no live setter says so rather than silently accepting and ignoring the call — a
    /// defaulted no-op is how a defence gets built and never applied.
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), String>;

    /// Set the colour handling for subsequent frames (M11).
    fn set_chroma_mode(&mut self, mode: ChromaMode) -> Result<(), String>;

    /// The WebRTC mime type this encoder's output must be negotiated as, e.g. `video/VP8`.
    /// Used to cross-check the encoder against [`NEGOTIATED_MIME_TYPE`].
    fn webrtc_mime_type(&self) -> &'static str;

    /// Human-readable name for logs.
    fn codec_name(&self) -> &'static str;
}

/// Lowest bitrate any encoder will be configured with, bits/sec. Below this, screen content stops
/// being legible at any resolution and the session is worse than a frozen one.
pub const MIN_BITRATE_BPS: u32 = 100_000;
/// Highest bitrate any encoder will be configured with, bits/sec.
pub const MAX_BITRATE_BPS: u32 = 20_000_000;

/// The mime type the transport negotiates for the video track.
///
/// **Codec selection point (1 of 2)** — keep in step with [`new_video_encoder`].
pub const NEGOTIATED_MIME_TYPE: &str = webrtc::api::media_engine::MIME_TYPE_VP8;

/// Default target bitrate for the video track, in bits/sec.
pub const DEFAULT_BITRATE_BPS: u32 = 3_000_000;

/// Build the encoder the transport will use.
///
/// **Codec selection point (2 of 2)** — keep in step with [`NEGOTIATED_MIME_TYPE`]. `bitrate_bps`
/// is bits/sec (each backend converts to whatever its library wants).
pub fn new_video_encoder(bitrate_bps: u32) -> Result<Box<dyn VideoEncoder>, String> {
    let enc = Vp8Encoder::new(bitrate_bps)?;
    let boxed: Box<dyn VideoEncoder> = Box::new(enc);
    if boxed.webrtc_mime_type() != NEGOTIATED_MIME_TYPE {
        return Err(format!(
            "codec seam mismatch: encoder is {} ({}) but the track negotiates {NEGOTIATED_MIME_TYPE}",
            boxed.codec_name(),
            boxed.webrtc_mime_type()
        ));
    }
    Ok(boxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two halves of the codec choice must agree, or we negotiate one codec and send another —
    /// which shows up as a permanently black `<video>` with no error anywhere in the stack.
    #[test]
    fn the_selected_encoder_matches_the_negotiated_mime_type() {
        let enc = new_video_encoder(DEFAULT_BITRATE_BPS).expect("encoder");
        assert_eq!(enc.webrtc_mime_type(), NEGOTIATED_MIME_TYPE);
        assert_eq!(NEGOTIATED_MIME_TYPE, "video/VP8", "shipping codec is VP8");
    }

    /// Exercise the pipeline purely through `dyn VideoEncoder` — if this compiles and runs, the
    /// transport genuinely does not depend on the concrete encoder type.
    #[test]
    fn drives_the_encoder_through_the_trait_object() {
        fn drive(enc: &mut dyn VideoEncoder) -> (usize, bool, bool, u32) {
            let frame = |t: u8| {
                let mut v = vec![0u8; 64 * 64 * 4];
                for (i, px) in v.chunks_mut(4).enumerate() {
                    px[0] = (i as u8).wrapping_add(t);
                    px[1] = (i as u8).wrapping_mul(3);
                    px[2] = (i as u8).wrapping_mul(5).wrapping_add(t);
                    px[3] = 0xFF;
                }
                v
            };
            let first = enc.encode_bgra(&frame(0), 64, 64, 3000).expect("first");
            let second = enc.encode_bgra(&frame(1), 64, 64, 3000).expect("second");
            enc.request_keyframe();
            let forced = enc.encode_bgra(&frame(2), 64, 64, 3000).expect("forced");
            (
                first.data.len(),
                second.keyframe,
                forced.keyframe,
                forced.duration_90khz,
            )
        }

        let mut vp8 = new_video_encoder(1_000_000).expect("vp8");
        let (len, second_is_kf, forced_is_kf, ticks) = drive(vp8.as_mut());
        assert!(len > 0);
        assert!(!second_is_kf);
        assert!(forced_is_kf);
        assert_eq!(ticks, 3000, "the AU echoes the duration it was given");

        #[cfg(feature = "h264")]
        {
            let mut h264: Box<dyn VideoEncoder> =
                Box::new(H264Encoder::new(1_000_000).expect("h264"));
            let (len, second_is_kf, forced_is_kf, ticks) = drive(h264.as_mut());
            assert!(len > 0);
            assert!(!second_is_kf);
            assert!(forced_is_kf);
            assert_eq!(ticks, 3000);
            assert_ne!(
                h264.webrtc_mime_type(),
                vp8.webrtc_mime_type(),
                "two genuinely different codecs behind one trait"
            );
        }
    }

    /// The two crates' default bitrate constants must agree. `rmt-agent-core` cannot depend on this
    /// crate (that would cycle), so the equality can only be asserted from here — and it must be
    /// asserted somewhere, because `QualitySettings::DEFAULT` claiming "exactly today's behaviour"
    /// is only true while these two numbers match.
    #[test]
    fn the_two_default_bitrate_constants_agree() {
        assert_eq!(
            DEFAULT_BITRATE_BPS,
            rmt_agent_core::quality::DEFAULT_MAX_BITRATE_BPS,
            "video::DEFAULT_BITRATE_BPS and quality::DEFAULT_MAX_BITRATE_BPS have drifted apart"
        );
        // And the shipped default must be a bitrate the encoder will actually accept.
        assert!(MIN_BITRATE_BPS <= DEFAULT_BITRATE_BPS && DEFAULT_BITRATE_BPS <= MAX_BITRATE_BPS);
        // The wire clamp and the encoder clamp must agree at both ends, or a value the controller
        // is told was accepted gets silently re-clamped inside the encoder.
        assert_eq!(MIN_BITRATE_BPS, rmt_agent_core::quality::MIN_MAX_BITRATE_BPS);
        assert_eq!(MAX_BITRATE_BPS, rmt_agent_core::quality::MAX_MAX_BITRATE_BPS);
    }
}
