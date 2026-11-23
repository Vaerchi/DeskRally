//! Frame format for the multiplexed-over-one-stream fallback (TCP/WebSocket, where the
//! transport doesn't give us native streams like QUIC does). Each frame is channel-tagged and
//! length-prefixed so a single ordered byte stream can carry all channels.
//!
//! Layout: `[channel: u8][len: u32 big-endian][payload: len bytes]`.
//!
//! On QUIC/WebRTC each channel gets its own stream/track and this framing isn't needed on the
//! hot path; it exists for the UDP-hostile-network fallback and for tests.

use crate::channel::ChannelId;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A decoded frame: which channel, and its payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: ChannelId,
    pub payload: Bytes,
}

/// Guard against a malicious/corrupt length header allocating unbounded memory. 64 MiB is far
/// above any legitimate single frame (video frames are chunked well below this).
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("unknown channel id {0}")]
    UnknownChannel(u8),
    #[error("frame length {0} exceeds maximum {MAX_FRAME_LEN}")]
    TooLong(usize),
    /// Not enough bytes buffered yet to decode a full frame — read more and retry.
    #[error("incomplete frame: need more bytes")]
    Incomplete,
}

impl Frame {
    pub fn new(channel: ChannelId, payload: impl Into<Bytes>) -> Self {
        Self { channel, payload: payload.into() }
    }

    /// Encode into `dst` (append). Header is 5 bytes + payload.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(5 + self.payload.len());
        dst.put_u8(self.channel as u8);
        dst.put_u32(self.payload.len() as u32);
        dst.put_slice(&self.payload);
    }

    /// Checked encode: appends exactly what [`Frame::encode`] would, but refuses a payload the
    /// decoder (and every peer) would reject. Returns `FrameError::TooLong(len)` when the
    /// payload exceeds [`MAX_FRAME_LEN`], leaving `dst` untouched. Senders must use this so an
    /// oversized frame is refused locally instead of killing the session at the peer.
    pub fn try_encode(&self, dst: &mut BytesMut) -> Result<(), FrameError> {
        let len = self.payload.len();
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLong(len));
        }
        self.encode(dst);
        Ok(())
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut b = BytesMut::new();
        self.encode(&mut b);
        b.freeze()
    }

    /// Try to decode one frame from the front of `src`, consuming it on success. Returns
    /// `Err(Incomplete)` (leaving `src` untouched) when more bytes are needed — the caller
    /// reads more from the socket and retries. This is the standard streaming-decoder contract.
    pub fn decode(src: &mut BytesMut) -> Result<Self, FrameError> {
        if src.len() < 5 {
            return Err(FrameError::Incomplete);
        }
        // Peek the header without consuming, so an incomplete payload leaves src intact.
        let channel_byte = src[0];
        let len = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;

        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLong(len));
        }
        // Validate the channel from the HEADER, BEFORE waiting for the payload. Both facts are
        // known the moment the 5 header bytes are present, and the old order (completeness first)
        // meant an unknown channel paired with a large declared length reported `Incomplete` — a
        // recoverable "read more" — while the caller accumulated toward a payload that was always
        // going to be rejected. That is what turned five bytes into an unbounded receive buffer in
        // docs/25 F02. A hard error must be reported at the earliest moment it is knowable.
        let channel =
            ChannelId::from_u8(channel_byte).ok_or(FrameError::UnknownChannel(channel_byte))?;
        if src.len() < 5 + len {
            return Err(FrameError::Incomplete);
        }

        src.advance(5);
        let payload = src.split_to(len).freeze();
        Ok(Frame { channel, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_single_frame() {
        let f = Frame::new(ChannelId::Input, Bytes::from_static(b"click"));
        let mut buf = BytesMut::new();
        f.encode(&mut buf);
        let decoded = Frame::decode(&mut buf).unwrap();
        assert_eq!(decoded, f);
        assert!(buf.is_empty(), "decode should consume the whole frame");
    }

    #[test]
    fn decodes_multiple_frames_from_one_buffer() {
        let mut buf = BytesMut::new();
        Frame::new(ChannelId::Input, Bytes::from_static(b"a")).encode(&mut buf);
        Frame::new(ChannelId::Video, Bytes::from_static(b"bb")).encode(&mut buf);
        let f1 = Frame::decode(&mut buf).unwrap();
        let f2 = Frame::decode(&mut buf).unwrap();
        assert_eq!(f1.channel, ChannelId::Input);
        assert_eq!(f2.channel, ChannelId::Video);
        assert_eq!(&f2.payload[..], b"bb");
    }

    #[test]
    fn incomplete_frame_leaves_buffer_untouched() {
        let mut full = BytesMut::new();
        Frame::new(ChannelId::Chat, Bytes::from_static(b"hello")).encode(&mut full);
        // Feed only a partial frame (header + 2 of 5 payload bytes).
        let mut partial = BytesMut::from(&full[..7]);
        let before = partial.clone();
        assert_eq!(Frame::decode(&mut partial), Err(FrameError::Incomplete));
        assert_eq!(partial, before, "incomplete decode must not consume");
    }

    #[test]
    fn rejects_oversized_length_header() {
        let mut buf = BytesMut::new();
        buf.put_u8(ChannelId::Video as u8);
        buf.put_u32((MAX_FRAME_LEN + 1) as u32);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::TooLong(MAX_FRAME_LEN + 1)));
    }

    #[test]
    fn try_encode_max_len_payload_round_trips() {
        let f = Frame::new(ChannelId::Video, Bytes::from(vec![0xABu8; MAX_FRAME_LEN]));
        let mut buf = BytesMut::new();
        f.try_encode(&mut buf).expect("a MAX_FRAME_LEN payload is legal");
        assert_eq!(buf.len(), 5 + MAX_FRAME_LEN);
        let decoded = Frame::decode(&mut buf).unwrap();
        assert_eq!(decoded, f);
        assert!(buf.is_empty());
    }

    #[test]
    fn try_encode_refuses_oversized_payload_and_leaves_dst_untouched() {
        let f = Frame::new(ChannelId::Video, Bytes::from(vec![0u8; MAX_FRAME_LEN + 1]));

        let mut empty = BytesMut::new();
        assert_eq!(f.try_encode(&mut empty), Err(FrameError::TooLong(MAX_FRAME_LEN + 1)));
        assert!(empty.is_empty(), "dst must stay empty on error");

        let mut filled = BytesMut::from(&b"prefix"[..]);
        assert_eq!(f.try_encode(&mut filled), Err(FrameError::TooLong(MAX_FRAME_LEN + 1)));
        assert_eq!(&filled[..], b"prefix", "pre-filled dst must be unchanged on error");
    }

    #[test]
    fn try_encode_is_byte_identical_to_encode_for_small_frames() {
        for payload in [&b""[..], &b"x"[..], &b"hello world"[..]] {
            let f = Frame::new(ChannelId::Chat, Bytes::copy_from_slice(payload));
            let mut a = BytesMut::from(&b"pre"[..]);
            let mut b = a.clone();
            f.encode(&mut a);
            f.try_encode(&mut b).unwrap();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn rejects_unknown_channel() {
        let mut buf = BytesMut::new();
        buf.put_u8(99);
        buf.put_u32(0);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::UnknownChannel(99)));
    }

    /// docs/25 F02: an unknown channel byte must be a HARD error the instant the 5-byte
    /// header arrives. Validating it AFTER the completeness check reports `Incomplete` — a
    /// recoverable "read more" — for a frame that can never be accepted, so the receiver
    /// keeps buffering toward a payload it was always going to reject. Do not "tidy" the
    /// order in `decode`: it must stay length, CHANNEL, completeness, in lockstep with the
    /// TypeScript mirror in web/viewer/src/lib/protocol.ts.
    ///
    /// `rejects_unknown_channel` above declares length 0, so it passes under BOTH orderings;
    /// only a large declared length with no payload supplied separates them.
    #[test]
    fn rejects_unknown_channel_before_waiting_for_the_declared_payload() {
        // Large but legal — under the old ordering the receiver waited for 8 MiB it would
        // always reject, and got `Incomplete` ("read more") instead of a hard error.
        let declared_len: u32 = 8 * 1024 * 1024;
        assert!((declared_len as usize) < MAX_FRAME_LEN, "declared length must be legal");

        let mut buf = BytesMut::new();
        buf.put_u8(99); // not a ChannelId
        buf.put_u32(declared_len);
        // Only the 5 header bytes are present: no payload at all.
        let before = buf.clone();

        assert_eq!(Frame::decode(&mut buf), Err(FrameError::UnknownChannel(99)));
        assert_eq!(buf, before, "a rejected frame must not consume the buffer");
    }
}
