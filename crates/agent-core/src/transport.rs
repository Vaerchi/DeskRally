//! The transport seam (ADR-001). Everything above this trait is transport-agnostic: the media
//! and data path is WebRTC in v1 and may become raw QUIC later, but the [`Session`] mux and the
//! channel logic never learn which. A transport moves whole [`Frame`]s — it does **not** see
//! plaintext, because the [`Session`] seals payloads before they ever reach here.
//!
//! [`Session`]: crate::session::Session
//!
//! Concretely a transport is "a thing I can push a [`Frame`] into and pull a [`Frame`] out of,
//! asynchronously". [`LoopbackTransport`] is the in-process implementation used by tests and by
//! wiring bring-up: a bidirectional pair backed by tokio mpsc channels, so two [`Session`]s can
//! talk with zero network involved.

use rmt_protocol::Frame;
use tokio::sync::mpsc;

/// Errors moving frames across a transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The far end hung up (channel closed / connection dropped). Terminal for this transport;
    /// the supervisor reconnects and builds a fresh one.
    #[error("transport closed")]
    Closed,
    /// The underlying transport reported an error; detail preserved as text.
    #[error("transport error: {0}")]
    Other(String),
}

/// Result alias for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Abstraction over the frame-moving layer. `async fn`-in-trait keeps implementations simple;
/// the [`Session`] is generic over `T: Transport`, so no dynamic dispatch is required on the hot
/// path. Implementors are the WebRTC data/media bridge (v1), a future QUIC transport, and the
/// test-only [`LoopbackTransport`].
///
/// [`Session`]: crate::session::Session
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Send one frame to the peer. Resolves once the frame is accepted by the transport (queued
    /// for delivery); it does not imply the peer has received it.
    async fn send_frame(&mut self, frame: Frame) -> TransportResult<()>;

    /// Await the next frame from the peer. Returns [`TransportError::Closed`] when the far end
    /// has gone away and no more frames will arrive.
    async fn recv_frame(&mut self) -> TransportResult<Frame>;
}

/// An in-memory, bidirectional transport: a pair of tokio mpsc channels wired crosswise. Create
/// both ends with [`LoopbackTransport::pair`]; frames sent on one end arrive on the other. Used
/// for tests and local bring-up — no sockets, no encryption *of its own* (the [`Session`] above
/// still end-to-end encrypts payloads).
///
/// [`Session`]: crate::session::Session
pub struct LoopbackTransport {
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
}

impl LoopbackTransport {
    /// Default channel capacity for a loopback pair. Bounded so a stuck reader exerts
    /// backpressure instead of growing memory without limit.
    pub const DEFAULT_CAPACITY: usize = 64;

    /// Create a connected pair of endpoints. Anything sent on the first arrives on the second
    /// and vice-versa. Uses [`DEFAULT_CAPACITY`](Self::DEFAULT_CAPACITY).
    pub fn pair() -> (LoopbackTransport, LoopbackTransport) {
        Self::pair_with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// Create a connected pair with an explicit per-direction channel capacity.
    ///
    /// # Panics
    /// Panics if `capacity` is zero (tokio's bounded channel requires a positive capacity).
    pub fn pair_with_capacity(capacity: usize) -> (LoopbackTransport, LoopbackTransport) {
        let (a_tx, b_rx) = mpsc::channel(capacity);
        let (b_tx, a_rx) = mpsc::channel(capacity);
        (
            LoopbackTransport { tx: a_tx, rx: a_rx },
            LoopbackTransport { tx: b_tx, rx: b_rx },
        )
    }
}

impl Transport for LoopbackTransport {
    async fn send_frame(&mut self, frame: Frame) -> TransportResult<()> {
        self.tx.send(frame).await.map_err(|_| TransportError::Closed)
    }

    async fn recv_frame(&mut self) -> TransportResult<Frame> {
        self.rx.recv().await.ok_or(TransportError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rmt_protocol::ChannelId;

    #[tokio::test]
    async fn loopback_delivers_frames_both_ways() {
        let (mut a, mut b) = LoopbackTransport::pair();

        a.send_frame(Frame::new(ChannelId::Input, Bytes::from_static(b"click")))
            .await
            .unwrap();
        let got = b.recv_frame().await.unwrap();
        assert_eq!(got.channel, ChannelId::Input);
        assert_eq!(&got.payload[..], b"click");

        // ...and the reverse direction is independent.
        b.send_frame(Frame::new(ChannelId::Video, Bytes::from_static(b"px")))
            .await
            .unwrap();
        let got = a.recv_frame().await.unwrap();
        assert_eq!(got.channel, ChannelId::Video);
        assert_eq!(&got.payload[..], b"px");
    }

    #[tokio::test]
    async fn recv_reports_closed_when_peer_dropped() {
        let (a, mut b) = LoopbackTransport::pair();
        drop(a); // peer hangs up
        assert!(matches!(b.recv_frame().await, Err(TransportError::Closed)));
    }

    #[tokio::test]
    async fn send_reports_closed_when_peer_dropped() {
        let (mut a, b) = LoopbackTransport::pair();
        drop(b);
        let err = a
            .send_frame(Frame::new(ChannelId::Chat, Bytes::from_static(b"hi")))
            .await;
        assert!(matches!(err, Err(TransportError::Closed)));
    }

    #[tokio::test]
    async fn frames_preserve_fifo_order_per_direction() {
        let (mut a, mut b) = LoopbackTransport::pair();
        for i in 0..10u8 {
            a.send_frame(Frame::new(ChannelId::Chat, Bytes::copy_from_slice(&[i])))
                .await
                .unwrap();
        }
        for i in 0..10u8 {
            let f = b.recv_frame().await.unwrap();
            assert_eq!(&f.payload[..], &[i]);
        }
    }
}
