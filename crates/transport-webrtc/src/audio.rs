//! **Opus** encoding for the WebRTC audio track — the second half of audio passthrough.
//!
//! The first half is [`rmt_agent_windows::audio`], which captures the guest machine's own output
//! (WASAPI loopback) as interleaved `f32`. This module turns that into Opus packets a browser can
//! decode.
//!
//! # Why Opus, and why it needs no seam
//!
//! The video side keeps a `VideoEncoder` trait because the codec choice was contested (VP8 vs
//! H.264, royalty-free vs patent exposure). Audio has no such argument: **Opus is mandatory to
//! implement in WebRTC**, every browser decodes it, and it is royalty-free with an explicit patent
//! grant — the same property that decided VP8. A trait here would be decoration, so there isn't
//! one.
//!
//! # The FFI is hand-declared, and that is deliberate
//!
//! Five functions, plain C signatures, no callbacks and no structs crossing the boundary. A `-sys`
//! crate would add a build script whose CRT choice we do not control, and the agent links `/MT`
//! (`-C target-feature=+crt-static`) — a vendored `/MD` libopus fails with LNK2038 a long way from
//! its cause. See `build.rs`.
//!
//! # Frame size is not a free parameter
//!
//! Opus encodes whole frames of 2.5, 5, 10, 20, 40 or 60 ms. WebRTC's default — and what every
//! browser expects on the wire — is **20 ms**, which at 48 kHz is exactly 960 samples per channel.
//! [`OpusEncoder::encode`] takes a slice of exactly that many samples per channel and says so,
//! rather than silently truncating: a caller that hands over an arbitrary buffer has a framing bug,
//! and swallowing it would turn a loud failure into audio that is subtly wrong forever.

use std::os::raw::{c_char, c_float, c_int, c_uchar};

/// Opaque libopus encoder state.
#[repr(C)]
struct OpusEncoderState {
    _private: [u8; 0],
}

/// Opaque libopus decoder state (tests only — the agent never decodes).
#[cfg(test)]
#[repr(C)]
struct OpusDecoderState {
    _private: [u8; 0],
}

extern "C" {
    fn opus_encoder_create(
        fs: i32,
        channels: c_int,
        application: c_int,
        error: *mut c_int,
    ) -> *mut OpusEncoderState;
    fn opus_encoder_destroy(st: *mut OpusEncoderState);
    fn opus_encode_float(
        st: *mut OpusEncoderState,
        pcm: *const c_float,
        frame_size: c_int,
        data: *mut c_uchar,
        max_data_bytes: i32,
    ) -> i32;
    fn opus_encoder_ctl(st: *mut OpusEncoderState, request: c_int, ...) -> c_int;
    fn opus_strerror(error: c_int) -> *const c_char;
}

// The DECODER, declared only for tests. The agent never decodes audio — the browser does — so in a
// shipping build these three are dead code, and gating them keeps that honest rather than carrying
// three unused imports into every release binary.
#[cfg(test)]
extern "C" {
    fn opus_decoder_create(fs: i32, channels: c_int, error: *mut c_int) -> *mut OpusDecoderState;
    fn opus_decoder_destroy(st: *mut OpusDecoderState);
    fn opus_decode_float(
        st: *mut OpusDecoderState,
        data: *const c_uchar,
        len: i32,
        pcm: *mut c_float,
        frame_size: c_int,
        decode_fec: c_int,
    ) -> c_int;
}

/// `OPUS_APPLICATION_AUDIO` — tuned for general audio rather than speech.
///
/// Not `OPUS_APPLICATION_VOIP`: this stream is a desktop's output — music, video, alert sounds —
/// and VOIP mode applies speech-shaped processing that makes all of that worse. Not
/// `RESTRICTED_LOWDELAY` either: it drops the ~6.5 ms lookahead for a little latency, and a remote
/// desktop's audio is already behind the picture by more than that.
const OPUS_APPLICATION_AUDIO: c_int = 2049;
/// `OPUS_OK`.
const OPUS_OK: c_int = 0;
/// `OPUS_SET_BITRATE_REQUEST`.
const OPUS_SET_BITRATE_REQUEST: c_int = 4002;
/// `OPUS_SET_DTX_REQUEST`.
const OPUS_SET_DTX_REQUEST: c_int = 4016;

/// The sample rate Opus encodes at, and the only one WebRTC negotiates for it.
pub const OPUS_SAMPLE_RATE: u32 = 48_000;
/// Frame duration on the wire. 20 ms is WebRTC's default and what browsers expect.
pub const FRAME_MS: u32 = 20;
/// Samples per channel in one 20 ms frame at 48 kHz.
pub const FRAME_SAMPLES: usize = (OPUS_SAMPLE_RATE as usize * FRAME_MS as usize) / 1000;
/// Default target bitrate. 96 kbps stereo is transparent enough for desktop audio without
/// competing meaningfully with the video track for a constrained uplink.
pub const DEFAULT_BITRATE_BPS: i32 = 96_000;
/// Upper bound on one encoded packet. Opus's own documented maximum is 1275 bytes per frame per
/// channel; 4000 is the size the reference encoder recommends for a single call and leaves room for
/// the worst case without a heap allocation per frame.
const MAX_PACKET_BYTES: usize = 4000;

/// Errors from the Opus encode path.
#[derive(Debug, thiserror::Error)]
pub enum AudioEncodeError {
    /// libopus refused the requested configuration.
    #[error("opus encoder init failed: {0}")]
    Init(String),
    /// libopus refused to encode this frame.
    #[error("opus encode failed: {0}")]
    Encode(String),
    /// The caller handed over a buffer that is not exactly one frame.
    #[error("expected exactly {expected} samples ({FRAME_MS} ms x {channels} ch), got {got}")]
    FrameSize {
        expected: usize,
        got: usize,
        channels: u16,
    },
    /// Only mono and stereo are meaningful for a desktop's output mix.
    #[error("unsupported channel count {0} (expected 1 or 2)")]
    Channels(u16),
}

/// The message libopus gives for an error code.
fn strerror(code: c_int) -> String {
    // SAFETY: opus_strerror returns a static NUL-terminated string for any int.
    let p = unsafe { opus_strerror(code) };
    if p.is_null() {
        return format!("opus error {code}");
    }
    // SAFETY: p is a valid static C string.
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

/// An Opus encoder for one stream.
///
/// Not `Sync`: libopus encoder state is mutable and not internally synchronised. It IS `Send`, so
/// it can live on the capture/encode thread the way the VP8 encoder does.
pub struct OpusEncoder {
    st: *mut OpusEncoderState,
    channels: u16,
    /// Reused so a steady stream costs no allocation per 20 ms frame.
    packet: Vec<u8>,
}

// SAFETY: the encoder state is owned exclusively by this struct and every call goes through `&mut
// self`, so it is never touched from two threads at once. Moving it between threads is sound;
// sharing it is not, hence Send and not Sync.
unsafe impl Send for OpusEncoder {}

impl OpusEncoder {
    /// Create an encoder for `channels` at 48 kHz, targeting [`DEFAULT_BITRATE_BPS`].
    pub fn new(channels: u16) -> Result<Self, AudioEncodeError> {
        Self::with_bitrate(channels, DEFAULT_BITRATE_BPS)
    }

    /// Create an encoder at a specific target bitrate.
    pub fn with_bitrate(channels: u16, bitrate_bps: i32) -> Result<Self, AudioEncodeError> {
        if channels != 1 && channels != 2 {
            return Err(AudioEncodeError::Channels(channels));
        }
        let mut err: c_int = 0;
        // SAFETY: a supported rate/channel/application triple; `err` receives the status.
        let st = unsafe {
            opus_encoder_create(
                OPUS_SAMPLE_RATE as i32,
                channels as c_int,
                OPUS_APPLICATION_AUDIO,
                &mut err,
            )
        };
        if st.is_null() || err != OPUS_OK {
            return Err(AudioEncodeError::Init(strerror(err)));
        }
        let mut enc = Self {
            st,
            channels,
            packet: vec![0u8; MAX_PACKET_BYTES],
        };
        // DTX — discontinuous transmission — is the setting that makes audio passthrough
        // affordable, and it is NOT on by default.
        //
        // Same shape as the idle-screen problem on the video side: the expensive case is not the
        // busy one, it is the boring one that lasts for hours. A remote desktop is silent most of
        // the time, and without DTX it pays the full 96 kbps to say nothing — measured, silence and
        // a 1 kHz tone both encoded to exactly 241 bytes per frame. With DTX a silent frame
        // collapses to ONE byte (400 bps), which the test below pins. Browsers decode DTX packets
        // natively; there is nothing to negotiate and nothing for the viewer to handle.
        //
        // VBR is deliberately NOT set here even though it is wanted: libopus already defaults to
        // it, so the call was pure decoration. Measured rather than assumed — removing it changed
        // no packet size, and a noise frame and a tone frame both encode to 241 B at this bitrate
        // either way. A line of configuration nothing can distinguish from its absence is a line
        // that will one day be read as load-bearing.
        enc.ctl_bool(OPUS_SET_DTX_REQUEST, true)?;
        enc.set_bitrate(bitrate_bps)?;
        Ok(enc)
    }

    /// Set a boolean libopus CTL (`0`/`1`).
    fn ctl_bool(&mut self, request: c_int, on: bool) -> Result<(), AudioEncodeError> {
        // SAFETY: every boolean CTL takes exactly one opus_int32 argument.
        let rc = unsafe { opus_encoder_ctl(self.st, request, if on { 1 } else { 0 } as c_int) };
        if rc != OPUS_OK {
            return Err(AudioEncodeError::Init(strerror(rc)));
        }
        Ok(())
    }

    /// Retarget the encoder's bitrate. Cheap and takes effect on the next frame — no re-init, so
    /// no discontinuity (the same property the VP8 rate controller relies on).
    pub fn set_bitrate(&mut self, bitrate_bps: i32) -> Result<(), AudioEncodeError> {
        // SAFETY: SET_BITRATE takes exactly one opus_int32 argument.
        let rc = unsafe { opus_encoder_ctl(self.st, OPUS_SET_BITRATE_REQUEST, bitrate_bps) };
        if rc != OPUS_OK {
            return Err(AudioEncodeError::Encode(strerror(rc)));
        }
        Ok(())
    }

    /// Channels this encoder was built for.
    pub fn channels(&self) -> u16 {
        self.channels
    }

    /// Samples this encoder expects per [`encode`](Self::encode) call: one 20 ms frame,
    /// interleaved across channels.
    pub fn samples_per_frame(&self) -> usize {
        FRAME_SAMPLES * self.channels as usize
    }

    /// Encode exactly one 20 ms frame of interleaved `f32` samples.
    ///
    /// Returns the encoded packet. A packet can legitimately be very small — Opus signals a silent
    /// frame in a handful of bytes — but never empty.
    pub fn encode(&mut self, pcm: &[f32]) -> Result<&[u8], AudioEncodeError> {
        let expected = self.samples_per_frame();
        if pcm.len() != expected {
            return Err(AudioEncodeError::FrameSize {
                expected,
                got: pcm.len(),
                channels: self.channels,
            });
        }
        // SAFETY: `pcm` holds exactly FRAME_SAMPLES samples per channel, and `packet` has
        // MAX_PACKET_BYTES of capacity, which is what `max_data_bytes` reports.
        let n = unsafe {
            opus_encode_float(
                self.st,
                pcm.as_ptr(),
                FRAME_SAMPLES as c_int,
                self.packet.as_mut_ptr(),
                self.packet.len() as i32,
            )
        };
        if n < 0 {
            return Err(AudioEncodeError::Encode(strerror(n as c_int)));
        }
        Ok(&self.packet[..n as usize])
    }
}

impl Drop for OpusEncoder {
    fn drop(&mut self) {
        // SAFETY: `st` came from opus_encoder_create and is destroyed exactly once.
        unsafe { opus_encoder_destroy(self.st) };
    }
}

/// A decoder, for TESTS only — the agent never decodes audio; the browser does.
///
/// It exists so the encoder's output can be checked for what actually matters (does a browser get
/// the sound back?) rather than for the things that are easy to assert and prove little, like "the
/// packet is non-empty".
#[cfg(test)]
pub(crate) struct OpusDecoder {
    st: *mut OpusDecoderState,
    channels: u16,
}

#[cfg(test)]
impl OpusDecoder {
    pub(crate) fn new(channels: u16) -> Result<Self, AudioEncodeError> {
        let mut err: c_int = 0;
        // SAFETY: supported rate/channels; `err` receives the status.
        let st =
            unsafe { opus_decoder_create(OPUS_SAMPLE_RATE as i32, channels as c_int, &mut err) };
        if st.is_null() || err != OPUS_OK {
            return Err(AudioEncodeError::Init(strerror(err)));
        }
        Ok(Self { st, channels })
    }

    /// Decode one packet into interleaved `f32`.
    pub(crate) fn decode(&mut self, packet: &[u8]) -> Result<Vec<f32>, AudioEncodeError> {
        let mut out = vec![0f32; FRAME_SAMPLES * self.channels as usize];
        // SAFETY: `out` has room for a full frame on every channel.
        let n = unsafe {
            opus_decode_float(
                self.st,
                packet.as_ptr(),
                packet.len() as i32,
                out.as_mut_ptr(),
                FRAME_SAMPLES as c_int,
                0,
            )
        };
        if n < 0 {
            return Err(AudioEncodeError::Encode(strerror(n)));
        }
        out.truncate(n as usize * self.channels as usize);
        Ok(out)
    }
}

#[cfg(test)]
impl Drop for OpusDecoder {
    fn drop(&mut self) {
        // SAFETY: `st` came from opus_decoder_create and is destroyed exactly once.
        unsafe { opus_decoder_destroy(self.st) };
    }
}

/// Buffers arbitrary-length PCM into exactly-one-frame slices.
///
/// Capture and encode do not agree on a block size and never will: WASAPI hands over whatever the
/// endpoint had ready (a few hundred samples, varying), and Opus encodes whole 20 ms frames or
/// nothing. Something has to bridge that, and [`OpusEncoder::encode`] deliberately REFUSES a
/// wrongly-sized buffer rather than truncating — so this is where the joining happens, once, with
/// tests, instead of in every caller.
///
/// The leftover matters more than it looks. A remainder dropped at each block boundary is a click
/// in the audio a few times a second, and it would be inaudible in a test and obvious in a session.
pub struct FrameAccumulator {
    buf: Vec<f32>,
    frame_len: usize,
}

impl FrameAccumulator {
    /// `frame_len` is total samples per frame — [`OpusEncoder::samples_per_frame`], i.e. already
    /// multiplied by the channel count.
    pub fn new(frame_len: usize) -> Self {
        Self {
            // One frame of headroom plus a typical WASAPI block, so a steady stream never grows it.
            buf: Vec::with_capacity(frame_len * 2),
            frame_len,
        }
    }

    /// Append captured samples. Any that do not complete a frame are KEPT for the next call.
    pub fn push(&mut self, pcm: &[f32]) {
        self.buf.extend_from_slice(pcm);
    }

    /// Move the next whole frame into `out` (cleared first), or return false when short.
    pub fn take_frame(&mut self, out: &mut Vec<f32>) -> bool {
        if self.buf.len() < self.frame_len {
            return false;
        }
        out.clear();
        out.extend(self.buf.drain(..self.frame_len));
        true
    }

    /// Samples held back, waiting for the rest of a frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One 20 ms frame of a sine at `hz`, interleaved across `channels`, amplitude 0.5.
    fn tone(hz: f32, channels: u16) -> Vec<f32> {
        let mut v = Vec::with_capacity(FRAME_SAMPLES * channels as usize);
        for i in 0..FRAME_SAMPLES {
            let s = 0.5 * (i as f32 * std::f32::consts::TAU * hz / OPUS_SAMPLE_RATE as f32).sin();
            for _ in 0..channels {
                v.push(s);
            }
        }
        v
    }

    fn rms(samples: &[f32]) -> f32 {
        if samples.is_empty() {
            return 0.0;
        }
        (samples.iter().map(|s| (s * s) as f64).sum::<f64>() / samples.len() as f64).sqrt() as f32
    }

    #[test]
    fn a_tone_survives_encode_and_decode() {
        // THE test that matters: not "a packet came out" but "the sound comes back". Opus is lossy
        // and has ~6.5 ms of lookahead, so the decoded frame is not sample-identical and comparing
        // waveforms would fail for reasons that are not defects — energy is the honest measure.
        let mut enc = OpusEncoder::new(2).expect("encoder");
        let mut dec = OpusDecoder::new(2).expect("decoder");
        let input = tone(440.0, 2);
        let input_rms = rms(&input);

        // Prime: the first frame carries the encoder's lookahead, so its energy is legitimately
        // low. Encoding a couple of frames before measuring is the codec behaving, not a fudge.
        let mut decoded = Vec::new();
        for _ in 0..4 {
            let packet = enc.encode(&input).expect("encode").to_vec();
            assert!(!packet.is_empty(), "opus never emits an empty packet");
            decoded = dec.decode(&packet).expect("decode");
        }

        let out_rms = rms(&decoded);
        assert!(
            (out_rms / input_rms) > 0.7 && (out_rms / input_rms) < 1.3,
            "decoded energy {out_rms:.4} should be close to input {input_rms:.4}"
        );
    }

    #[test]
    fn silence_collapses_to_almost_nothing_once_dtx_engages() {
        // The property that makes audio passthrough affordable next to the video track, and one no
        // "packet is non-empty" test can see. A remote desktop is SILENT most of the time, so the
        // expensive case is the boring one that lasts for hours — the same shape as the idle-screen
        // problem on the video side.
        //
        // It is also the check that VBR and DTX are actually ON. With only a bitrate set, libopus
        // emitted 241 bytes for silence and 241 bytes for a 1 kHz tone: a silent desktop paying
        // full 96 kbps freight for the length of the session.
        //
        // DTX DOES NOT ENGAGE IMMEDIATELY, and that is why this test encodes a RUN of silence
        // rather than one frame. Measured, printing the size of every fifth frame:
        //
        //     frame  0: 241 B   5: 241 B   10: 1 B   15: 1 B   ...   55: 1 B
        //
        // An earlier version of this test measured at frame 5 and concluded DTX was not working at
        // all. One byte per 20 ms frame is 400 bps against 96 kbps — a 240x reduction.
        let mut enc = OpusEncoder::new(2).expect("encoder");
        let silence = vec![0f32; enc.samples_per_frame()];
        let loud = tone(1000.0, 2);
        // Steady state, past the encoder's lookahead.
        for _ in 0..4 {
            let _ = enc.encode(&loud).expect("encode");
        }
        let loud_len = enc.encode(&loud).expect("encode").len();
        // 300 ms of silence — comfortably past the onset measured above, without pinning the exact
        // frame at which libopus decides, which is its business and not a contract.
        for _ in 0..15 {
            let _ = enc.encode(&silence).expect("encode");
        }
        let silent_len = enc.encode(&silence).expect("encode").len();
        assert!(
            silent_len * 10 < loud_len,
            "silence {silent_len} B should be an order of magnitude cheaper than a tone {loud_len} B              — if they are equal, VBR/DTX did not take effect"
        );
    }

    #[test]
    fn a_wrongly_sized_buffer_is_refused_rather_than_truncated() {
        // Opus encodes whole frames. Silently taking the first 960 samples of whatever arrives
        // would turn a caller's framing bug into audio that is subtly wrong forever, at no point
        // failing.
        let mut enc = OpusEncoder::new(2).expect("encoder");
        let short = vec![0f32; enc.samples_per_frame() - 2];
        let long = vec![0f32; enc.samples_per_frame() + 2];
        assert!(matches!(
            enc.encode(&short),
            Err(AudioEncodeError::FrameSize { .. })
        ));
        assert!(matches!(
            enc.encode(&long),
            Err(AudioEncodeError::FrameSize { .. })
        ));
    }

    #[test]
    fn mono_and_stereo_frames_are_different_sizes() {
        // Pins that `samples_per_frame` follows the CHANNEL COUNT rather than being a constant —
        // a mono encoder fed a stereo frame is the mistake this prevents.
        assert_eq!(OpusEncoder::new(1).unwrap().samples_per_frame(), 960);
        assert_eq!(OpusEncoder::new(2).unwrap().samples_per_frame(), 1920);
    }

    #[test]
    fn an_unsupported_channel_count_is_refused_at_construction() {
        assert!(matches!(OpusEncoder::new(0), Err(AudioEncodeError::Channels(0))));
        assert!(matches!(OpusEncoder::new(6), Err(AudioEncodeError::Channels(6))));
    }

    #[test]
    fn the_bitrate_can_be_retargeted_without_reinit() {
        // The audio equivalent of the VP8 rate controller's property: a bitrate change must not
        // require rebuilding the encoder, or every adaptation would be a discontinuity.
        let mut enc = OpusEncoder::new(2).expect("encoder");
        let frame = tone(440.0, 2);
        for _ in 0..4 {
            let _ = enc.encode(&frame).expect("encode");
        }
        let at_default = enc.encode(&frame).expect("encode").len();
        enc.set_bitrate(24_000).expect("retarget");
        for _ in 0..4 {
            let _ = enc.encode(&frame).expect("encode");
        }
        let at_low = enc.encode(&frame).expect("encode").len();
        assert!(
            at_low < at_default,
            "24 kbps frame {at_low} B should be smaller than 96 kbps {at_default} B"
        );
    }

    #[test]
    fn the_accumulator_loses_no_samples_across_ragged_blocks() {
        // THE property. WASAPI blocks do not divide evenly into 20 ms frames, so every boundary
        // leaves a remainder; dropping it would be a click in the audio several times a second —
        // inaudible to a test that only counts frames, obvious in a session.
        let frame = 960usize;
        let mut acc = FrameAccumulator::new(frame);
        let mut out = Vec::new();
        let mut seen: Vec<f32> = Vec::new();
        // Deliberately RAGGED and coprime-ish block sizes, so no boundary lines up with the frame.
        let blocks = [401usize, 137, 999, 48, 1553, 7, 880];
        let mut next = 0f32;
        let mut fed = 0usize;
        for b in blocks {
            let block: Vec<f32> = (0..b)
                .map(|_| {
                    next += 1.0;
                    next
                })
                .collect();
            fed += b;
            acc.push(&block);
            while acc.take_frame(&mut out) {
                assert_eq!(out.len(), frame, "a frame is always exactly one frame");
                seen.extend_from_slice(&out);
            }
        }
        // Everything that came out is the front of what went in, IN ORDER and with nothing skipped.
        let expected: Vec<f32> = (1..=seen.len() as u32).map(|i| i as f32).collect();
        assert_eq!(seen, expected, "samples emerge in order with no gaps");
        assert_eq!(
            seen.len() + acc.pending(),
            fed,
            "every sample fed is either emitted or still pending — none dropped"
        );
        assert!(acc.pending() < frame, "a whole frame is never held back");
    }

    #[test]
    fn the_accumulator_yields_nothing_until_a_whole_frame_exists() {
        // Opus encodes whole frames; emitting a short one would be refused by the encoder, and
        // padding it with silence would insert a click.
        let mut acc = FrameAccumulator::new(960);
        let mut out = Vec::new();
        acc.push(&vec![0.5f32; 959]);
        assert!(!acc.take_frame(&mut out), "959 samples is not a frame");
        assert_eq!(acc.pending(), 959);
        acc.push(&[0.5]);
        assert!(acc.take_frame(&mut out), "the 960th completes it");
        assert_eq!(out.len(), 960);
        assert_eq!(acc.pending(), 0);
    }

    #[test]
    fn one_big_block_yields_several_frames_not_just_one() {
        // A capture that fell behind hands over several frames at once. Emitting one and keeping
        // the rest forever would add latency that never drains.
        let mut acc = FrameAccumulator::new(960);
        let mut out = Vec::new();
        acc.push(&vec![0.1f32; 960 * 3 + 5]);
        let mut n = 0;
        while acc.take_frame(&mut out) {
            n += 1;
        }
        assert_eq!(n, 3);
        assert_eq!(acc.pending(), 5);
    }
}
