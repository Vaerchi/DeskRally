//! Minimal **IVF** container writer for the session recorder (loop 89, docs/01 §5 "Session
//! recording to video").
//!
//! # Why IVF, and why written here rather than taken from a dependency
//!
//! IVF is 44 bytes of format in total — a 32-byte file header and a 12-byte header per frame — and
//! it is the only container this project can write without either a new dependency or a large,
//! self-unverifiable muxer. The alternative considered was minimal WebM/Matroska: 350-600 lines of
//! EBML with no in-tree parser to check the output against, where a subtly wrong file plays in
//! **nothing** and gives no useful error. The trade is deliberate and has a real cost, stated
//! plainly rather than discovered later: **no browser plays IVF.** Converting is a stream copy
//! (`ffmpeg -i seg-0000.ivf -c copy out.webm`) — no transcode, no quality loss, seconds per hour of
//! footage — but it is a step somebody has to take before anyone outside engineering can watch a
//! recording.
//!
//! `webrtc-media`'s own [`IVFWriter`] is already in the dependency tree and is deliberately NOT
//! used, for two reasons that are both disqualifying rather than stylistic:
//!
//! 1. **It is fed from the wrong side.** Its writer trait takes `write_rtp(&rtp::packet::Packet)`
//!    and depacketises internally. The agent hands whole access units to
//!    `TrackLocalStaticSample::write_sample` and webrtc-rs packetises *inside* itself — nothing in
//!    this crate can observe its own outbound RTP. Recording after packetisation would also record
//!    what the network did rather than what the operator did (see [`super::EncodedAu`]).
//! 2. **Its per-frame timestamp is a frame counter**, not a time. That flattens a variable-rate
//!    pipeline to constant-rate, which is precisely the lie this module exists to avoid.
//!
//! Its *reader* is another matter: [`IVFReader`] is reachable with no manifest change (the
//! `webrtc` facade re-exports `media`), and the tests below round-trip through it. A real oracle
//! beats a self-consistent test — a writer checked only against its own reader agrees with itself
//! about a shared misunderstanding.
//!
//! # The timebase, which is the whole point
//!
//! The header declares a rational timebase and every frame carries a `u64` timestamp in it. Written
//! as **1/90000**, matching [`VIDEO_CLOCK_RATE`](super::VIDEO_CLOCK_RATE) — the same 90 kHz clock
//! the encoder, the RTP timestamp and `EncodedAu::duration_90khz` already speak — so there is no
//! rational conversion anywhere in this writer and no rounding drift across a long session. A u64 of
//! 90 kHz ticks overflows after roughly 6.5 million years.
//!
//! **The caller supplies the presentation timestamp and must NOT derive it from
//! `EncodedAu::duration_90khz`.** That field is clamped to at most one second
//! (`MAX_TICKS`) before it reaches libvpx, which is correct for a rate controller and false for a
//! presentation timeline; and on the DXGI capture path an idle desktop produces no frame at all
//! rather than a long one. Summing durations would therefore write a ten-minute session with five
//! idle minutes as a five-minute file — a recording that is wrong about *when* things happened
//! while looking perfectly well-formed. Pass a wall-clock-derived tick count instead.
//!
//! # What this format cannot express
//!
//! `width`/`height` live in the FILE header as `u16` and apply to the whole file. This pipeline
//! genuinely does change resolution mid-session (monitor switches, RDP reconnects, an operator
//! scale change — each re-initialises the encoder), so a dimension change requires starting a NEW
//! file. [`super::EncodedAu`] carries the post-crop `width`/`height` of every frame, which makes
//! that observable at the tee; segmenting is the caller's job and this writer will not do it
//! silently.
//!
//! There is also no codec-private data, no metadata, no chapters and no audio track. Anything a
//! reviewer needs to know about a recording — session identity, the quality settings actually in
//! force, dropped frames, the digest — belongs in a sidecar next to the file, not in here.
//!
//! [`IVFWriter`]: https://docs.rs/webrtc-media
//! [`IVFReader`]: https://docs.rs/webrtc-media

use std::io::{self, Seek, SeekFrom, Write};

/// `DKIF`, the IVF file signature.
const SIGNATURE: &[u8; 4] = b"DKIF";
/// The only IVF version in use.
const VERSION: u16 = 0;
/// Size of the file header, and the value the header itself declares.
const FILE_HEADER_SIZE: u16 = 32;
/// FourCC for a VP8 bitstream.
const FOURCC_VP80: &[u8; 4] = b"VP80";
/// Byte offset of `num_frames` within the file header — patched by [`IvfWriter::finalize`].
const NUM_FRAMES_OFFSET: u64 = 24;

/// Writes a VP8 elementary stream into an IVF container.
///
/// Generic over the sink so the tests can write into a `Cursor<Vec<u8>>` and touch no filesystem;
/// production passes a `BufWriter<File>`. `Seek` is required only by [`finalize`](Self::finalize).
pub struct IvfWriter<W: Write + Seek> {
    inner: W,
    frames: u32,
    /// Total bytes handed to `write_frame`, excluding container overhead. Reported so the caller
    /// can enforce a size budget without a second accounting of the same bytes.
    payload_bytes: u64,
}

impl<W: Write + Seek> IvfWriter<W> {
    /// Start a file, writing the 32-byte header immediately.
    ///
    /// `width`/`height` apply to EVERY frame in this file; see the module docs on segmenting.
    pub fn new(mut inner: W, width: u16, height: u16) -> io::Result<Self> {
        let mut hdr = [0u8; FILE_HEADER_SIZE as usize];
        hdr[0..4].copy_from_slice(SIGNATURE);
        hdr[4..6].copy_from_slice(&VERSION.to_le_bytes());
        hdr[6..8].copy_from_slice(&FILE_HEADER_SIZE.to_le_bytes());
        hdr[8..12].copy_from_slice(FOURCC_VP80);
        hdr[12..14].copy_from_slice(&width.to_le_bytes());
        hdr[14..16].copy_from_slice(&height.to_le_bytes());
        // DENOMINATOR FIRST, then numerator. That order is easy to get backwards and the failure is
        // quiet — a file whose declared timebase is 90000/1 plays 8.1 billion times too fast rather
        // than erroring — so it is asserted byte-for-byte by `header_is_the_documented_32_bytes`.
        hdr[16..20].copy_from_slice(&super::VIDEO_CLOCK_RATE.to_le_bytes());
        hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        // num_frames stays 0 until `finalize` patches it. A recording interrupted by power loss
        // therefore declares 0 frames; ffmpeg and VLC both ignore the field and read to EOF, so such
        // a file still plays. It is patched rather than buffered because the alternative is holding
        // the whole recording in memory to count it first.
        hdr[24..28].copy_from_slice(&0u32.to_le_bytes());
        hdr[28..32].copy_from_slice(&0u32.to_le_bytes());
        inner.write_all(&hdr)?;
        Ok(Self { inner, frames: 0, payload_bytes: 0 })
    }

    /// Append one encoded frame at `pts_90khz`.
    ///
    /// `pts_90khz` is a PRESENTATION timestamp in 90 kHz ticks from the start of this file — read
    /// the module docs before deriving it from anything the encoder returns.
    pub fn write_frame(&mut self, data: &[u8], pts_90khz: u64) -> io::Result<()> {
        // IVF's frame_size is u32. A single VP8 frame that large is not reachable here (the encoder
        // is capped at MAX_BITRATE_BPS), but the cast is checked rather than assumed: a silent
        // truncation would write a length prefix that disagrees with the bytes that follow, which
        // corrupts every frame after it rather than just this one.
        let len = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "IVF frame exceeds u32 bytes")
        })?;
        let mut hdr = [0u8; 12];
        hdr[0..4].copy_from_slice(&len.to_le_bytes());
        hdr[4..12].copy_from_slice(&pts_90khz.to_le_bytes());
        self.inner.write_all(&hdr)?;
        self.inner.write_all(data)?;
        self.frames = self.frames.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(data.len() as u64);
        Ok(())
    }

    /// Frames written so far.
    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// Encoded payload bytes written so far, excluding the 32-byte file header and the 12 bytes per
    /// frame of container overhead.
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Patch `num_frames` into the header, flush, and return the sink.
    ///
    /// Consuming `self` is the point: it makes "I finished the file" a state the type system tracks,
    /// so a recorder cannot keep writing after the count is fixed. Deliberately NOT done in a `Drop`
    /// impl — a `Drop` would have to swallow the io::Result, and a header patch that silently failed
    /// is exactly the kind of quiet wrongness this module is trying to avoid. Dropping an
    /// un-finalized writer is a supported outcome (see the power-loss test), not an error.
    pub fn finalize(mut self) -> io::Result<W> {
        let n = self.frames;
        self.inner.seek(SeekFrom::Start(NUM_FRAMES_OFFSET))?;
        self.inner.write_all(&n.to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// What [`read_back`] found in an IVF byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvfSummary {
    /// Width from the file header.
    pub width: u16,
    /// Height from the file header.
    pub height: u16,
    /// `num_frames` as DECLARED by the header — 0 for a file that was never finalized, which is
    /// different from the number of frames actually present.
    pub declared_frames: u32,
    /// The timebase, as `(numerator, denominator)`.
    pub timebase: (u32, u32),
    /// `(pts, payload_len)` for every frame actually present.
    pub frames: Vec<(u64, usize)>,
}

/// Parse an IVF byte stream using the **vendored `webrtc-media` reader**.
///
/// Exposed so a consumer of this writer — the agent's session recorder — can assert against the
/// same independent oracle the writer's own tests use, without taking a direct dependency on the
/// `webrtc` crate just to read four fields back. A writer checked only against a reader we also
/// wrote would agree with itself about a shared misunderstanding; this one is somebody else's
/// implementation of the spec.
pub fn read_back(bytes: &[u8]) -> Result<IvfSummary, String> {
    use webrtc::media::io::ivf_reader::IVFReader;
    let (mut r, hdr) =
        IVFReader::new(io::Cursor::new(bytes.to_vec())).map_err(|e| format!("ivf header: {e}"))?;
    let mut frames = Vec::new();
    // The reader signals end-of-stream as an error, so a parse failure and a clean EOF are the same
    // return here. That is fine for an oracle over a complete in-memory buffer: a truncated file
    // yields fewer frames, which is exactly what a caller asserting a frame count wants to see.
    while let Ok((payload, fh)) = r.parse_next_frame() {
        frames.push((fh.timestamp, payload.len()));
    }
    Ok(IvfSummary {
        width: hdr.width,
        height: hdr.height,
        declared_frames: hdr.num_frames,
        timebase: (hdr.timebase_numerator, hdr.timebase_denominator),
        frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use webrtc::media::io::ivf_reader::IVFReader;

    /// The 32-byte header, asserted byte-for-byte against the documented layout.
    ///
    /// A round-trip through `IVFReader` alone would NOT catch a swapped timebase pair: the reader
    /// parses whatever order the writer wrote and hands both fields back, so writer and reader would
    /// agree with each other and disagree with every real player. This is the test that pins the
    /// bytes on the wire rather than the agreement between two pieces of our own code.
    #[test]
    fn header_is_the_documented_32_bytes() {
        let w = IvfWriter::new(Cursor::new(Vec::new()), 1280, 720).unwrap();
        let buf = w.finalize().unwrap().into_inner();
        assert_eq!(&buf[0..4], b"DKIF", "signature");
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 0, "version");
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 32, "header_size");
        assert_eq!(&buf[8..12], b"VP80", "fourcc");
        assert_eq!(u16::from_le_bytes([buf[12], buf[13]]), 1280, "width");
        assert_eq!(u16::from_le_bytes([buf[14], buf[15]]), 720, "height");
        // THE ORDER THAT MATTERS: denominator at 16, numerator at 20 — i.e. a timebase of 1/90000
        // second per tick, not 90000/1.
        assert_eq!(
            u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            90_000,
            "timebase DENOMINATOR must be 90000 (a swap here plays the file 8.1e9x too fast)"
        );
        assert_eq!(u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]), 1, "timebase numerator");
        assert_eq!(buf.len(), 32, "an empty recording is exactly the header");
    }

    /// Round trip through the vendored `IVFReader`: payloads and timestamps survive intact.
    #[test]
    fn frames_round_trip_through_the_vendored_reader() {
        let mut w = IvfWriter::new(Cursor::new(Vec::new()), 640, 480).unwrap();
        // Deliberately IRREGULAR gaps: 0, 3000, 3000+7500, ... A constant-rate writer (or one that
        // wrote a frame counter instead of a timestamp, which is exactly what webrtc-media's own
        // IVFWriter does) passes a fixed-interval test and fails this one.
        let frames: Vec<(Vec<u8>, u64)> = vec![
            (vec![0xAA; 10], 0),
            (vec![0xBB; 3], 3_000),
            (vec![0xCC; 128], 10_500),
            (vec![0xDD; 1], 900_000),
        ];
        for (data, pts) in &frames {
            w.write_frame(data, *pts).unwrap();
        }
        assert_eq!(w.frames(), 4);
        assert_eq!(w.payload_bytes(), 10 + 3 + 128 + 1);
        let buf = w.finalize().unwrap().into_inner();

        let (mut r, hdr) = IVFReader::new(Cursor::new(buf)).unwrap();
        assert_eq!(&hdr.signature, b"DKIF");
        assert_eq!(hdr.width, 640);
        assert_eq!(hdr.height, 480);
        assert_eq!(hdr.timebase_denominator, 90_000);
        assert_eq!(hdr.timebase_numerator, 1);
        assert_eq!(hdr.num_frames, 4, "finalize must patch the count");
        for (want_data, want_pts) in &frames {
            let (payload, fh) = r.parse_next_frame().unwrap();
            assert_eq!(&payload[..], &want_data[..], "payload survived");
            assert_eq!(fh.timestamp, *want_pts, "PTS survived — NOT a frame index");
            assert_eq!(fh.frame_size as usize, want_data.len());
        }
        assert!(r.parse_next_frame().is_err(), "exactly four frames, then EOF");
    }

    /// A recording that is never finalized still parses; it just declares zero frames.
    ///
    /// This is the power-loss case, and it is asserted rather than assumed because the recorder's
    /// whole value proposition is that an interrupted recording is still evidence.
    #[test]
    fn an_unfinalized_file_still_parses_and_declares_zero_frames() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = IvfWriter::new(&mut buf, 320, 240).unwrap();
            w.write_frame(&[1, 2, 3], 0).unwrap();
            w.write_frame(&[4, 5, 6], 3_000).unwrap();
            // dropped without finalize
        }
        let bytes = buf.into_inner();
        let (mut r, hdr) = IVFReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(hdr.num_frames, 0, "an interrupted recording declares 0 — players read to EOF");
        // …and the frames are all there regardless, which is the property that matters.
        assert_eq!(&r.parse_next_frame().unwrap().0[..], &[1, 2, 3]);
        assert_eq!(&r.parse_next_frame().unwrap().0[..], &[4, 5, 6]);
    }

    /// The container overhead is exactly 32 + 12n, which is what a size budget must account for.
    #[test]
    fn on_disk_size_is_header_plus_twelve_bytes_per_frame() {
        let mut w = IvfWriter::new(Cursor::new(Vec::new()), 16, 16).unwrap();
        for i in 0..5u64 {
            w.write_frame(&[0u8; 100], i * 3_000).unwrap();
        }
        let payload = w.payload_bytes();
        let buf = w.finalize().unwrap().into_inner();
        assert_eq!(payload, 500);
        assert_eq!(buf.len() as u64, 32 + 5 * 12 + payload);
    }
}
