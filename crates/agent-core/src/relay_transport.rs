//! A [`Transport`] over a TCP connection to the relay (`server/relay`). This is the real
//! fallback data path (ADR-002): when a direct P2P path can't be established, both peers
//! connect to the relay and present the same [`RelayToken`]; the relay splices them and
//! forwards bytes verbatim, blind to the E2E-encrypted payloads.
//!
//! Wire protocol (must match `server/relay/main.go`):
//!   1. On connect, send the token as a newline-terminated canonical UUID: `"<uuid>\n"`.
//!   2. Thereafter, exchange length-prefixed [`Frame`]s (the [`rmt_protocol::frame`] format).
//!      The relay treats everything after the token as an opaque byte stream.

use bytes::BytesMut;
use rmt_protocol::frame::FrameError;
use rmt_protocol::{Frame, RelayToken};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::transport::{Transport, TransportError, TransportResult};

/// A frame transport over one TCP connection to the relay.
pub struct RelayTransport {
    stream: TcpStream,
    /// Accumulates bytes until a whole [`Frame`] can be decoded (streaming decoder contract).
    rbuf: BytesMut,
}

impl RelayTransport {
    /// Connect to the relay at `addr` and announce `token`. Both peers of a session use the
    /// same token so the relay pairs them.
    pub async fn connect(addr: &str, token: RelayToken) -> TransportResult<Self> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TransportError::Other(format!("connect {addr}: {e}")))?;
        // The relay expects a newline-terminated canonical UUID; `Uuid`'s Display is exactly
        // the 8-4-4-4-12 hex form the relay validates.
        let line = format!("{}\n", token.0);
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|e| TransportError::Other(format!("send token: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| TransportError::Other(format!("flush token: {e}")))?;
        Ok(Self { stream, rbuf: BytesMut::with_capacity(64 * 1024) })
    }
}

impl Transport for RelayTransport {
    async fn send_frame(&mut self, frame: Frame) -> TransportResult<()> {
        // Refuse an oversized frame BEFORE any write: the peer's decoder would reject it and
        // tear the session down, and a >4 GiB length would wrap the u32 header.
        let mut buf = BytesMut::new();
        frame
            .try_encode(&mut buf)
            .map_err(|e| TransportError::Other(e.to_string()))?;
        self.stream
            .write_all(&buf)
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> TransportResult<Frame> {
        loop {
            match Frame::decode(&mut self.rbuf) {
                Ok(frame) => return Ok(frame),
                Err(FrameError::Incomplete) => {
                    let n = self
                        .stream
                        .read_buf(&mut self.rbuf)
                        .await
                        .map_err(|_| TransportError::Closed)?;
                    if n == 0 {
                        return Err(TransportError::Closed);
                    }
                }
                Err(e) => return Err(TransportError::Other(e.to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rmt_protocol::{ChannelId, Frame, RelayToken};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use uuid::Uuid;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    async fn bind_loopback() -> (String, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        (addr, listener)
    }

    /// connect() must send the token as a newline-terminated canonical lowercase UUID.
    /// The relay's bufio.Reader.ReadString('\n') blocks until the '\n' arrives, and its
    /// normalizeToken validates the 8-4-4-4-12 hyphenated lowercase hex form.
    /// Without the '\n', read_line blocks until the relay's 10 s handshake deadline fires;
    /// the timeout here turns that silent hang into a clear test failure.
    #[tokio::test]
    async fn connect_sends_canonical_uuid_with_newline() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let uuid = Uuid::new_v4();
            let token = RelayToken(uuid);

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                line
            });

            let _transport = RelayTransport::connect(&addr, token).await.unwrap();
            let received = server.await.unwrap();

            let expected = format!("{}\n", uuid);
            assert_eq!(received, expected, "token line must match canonical UUID + newline");
            let uuid_part = received.trim_end_matches('\n');
            // 8-4-4-4-12 = 32 hex digits + 4 hyphens = 36 chars, all lowercase.
            assert_eq!(uuid_part.len(), 36);
            assert!(
                uuid_part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "token must be canonical lowercase: {uuid_part}"
            );
        })
        .await
        .expect("connect_sends_canonical_uuid_with_newline timed out — newline likely missing");
    }

    /// send_frame/recv_frame must round-trip a frame through the length-prefix framing.
    /// The echo server reads the token then reflects the raw frame bytes back.
    #[tokio::test]
    async fn send_recv_frame_round_trip() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let token = RelayToken(Uuid::new_v4());

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                // Consume the token line; the relay is opaque to what follows.
                let mut _line = String::new();
                reader.read_line(&mut _line).await.unwrap();
                // Frame: 1 (channel) + 4 (big-endian length) + 4 ("ping") = 9 bytes.
                let mut frame_bytes = [0u8; 9];
                reader.read_exact(&mut frame_bytes).await.unwrap();
                write_half.write_all(&frame_bytes).await.unwrap();
            });

            let mut transport = RelayTransport::connect(&addr, token).await.unwrap();
            let frame = Frame::new(ChannelId::Control, Bytes::from_static(b"ping"));
            transport.send_frame(frame.clone()).await.unwrap();
            let received = transport.recv_frame().await.unwrap();
            assert_eq!(received, frame);
            server.await.unwrap();
        })
        .await
        .expect("send_recv_frame_round_trip timed out");
    }

    /// recv_frame must return TransportError::Other when the peer sends a frame header with an
    /// unknown channel byte. This exercises the Err(e) arm at relay_transport.rs:73 and
    /// distinguishes it from TransportError::Closed; the mutation that swaps Other→Closed fails
    /// because the assertion pattern only matches Other(_).
    #[tokio::test]
    async fn recv_frame_returns_other_on_malformed_frame() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let token = RelayToken(Uuid::new_v4());

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut _line = String::new();
                reader.read_line(&mut _line).await.unwrap();
                // 5-byte frame header: channel=0x99 (invalid), big-endian length=0.
                // Frame::decode sees a complete header, returns FrameError::UnknownChannel(0x99),
                // which relay_transport maps to TransportError::Other via the Err(e) arm.
                let mut stream = reader.into_inner();
                stream.write_all(&[0x99u8, 0x00, 0x00, 0x00, 0x00]).await.unwrap();
                // Keep the connection open so recv_frame has the bytes available.
                tokio::time::sleep(Duration::from_secs(2)).await;
            });

            let mut transport = RelayTransport::connect(&addr, token).await.unwrap();
            let result = transport.recv_frame().await;
            assert!(
                matches!(result, Err(TransportError::Other(_))),
                "expected Other(_) for unknown channel byte, got {result:?}"
            );
            server.abort();
        })
        .await
        .expect("recv_frame_returns_other_on_malformed_frame timed out");
    }

    /// send_frame must return TransportError::Closed when the peer drops the connection before
    /// the write completes. This exercises the .map_err(|_| TransportError::Closed) at
    /// relay_transport.rs:55; the mutation that removes it would change the error type.
    #[tokio::test]
    async fn send_frame_returns_closed_when_peer_disconnects() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let token = RelayToken(Uuid::new_v4());

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut _line = String::new();
                reader.read_line(&mut _line).await.unwrap();
                // SO_LINGER=0 makes the close send RST rather than a graceful FIN, so
                // the peer's next write returns an error immediately rather than being
                // silently buffered and acknowledged before the FIN is processed.
                let inner = reader.into_inner();
                inner.set_linger(Some(Duration::ZERO)).unwrap();
                // Drop inner here — RST is sent.
            });

            // Connect first (the server must accept), then wait until the loopback
            // RST is visible on the client socket before calling send_frame.  A bare
            // yield_now() is not enough: a small write can succeed while the kernel
            // still has buffer space.  peek() returns Ok(0) on graceful FIN or Err on
            // RST — both mean the peer is gone and the next write will fail.
            let mut transport = RelayTransport::connect(&addr, token).await.unwrap();
            server.await.unwrap();
            let mut probe = [0u8; 1];
            loop {
                match transport.stream.peek(&mut probe).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // unexpected data; keep probing
                }
            }
            let frame = Frame::new(ChannelId::Control, Bytes::from_static(b"ping"));
            let result = transport.send_frame(frame).await;
            assert!(
                matches!(result, Err(TransportError::Closed)),
                "expected Closed after peer disconnect, got {result:?}"
            );
        })
        .await
        .expect("send_frame_returns_closed_when_peer_disconnects timed out");
    }

    /// An oversized frame must be refused locally with Other(_), before any byte is written, and
    /// a following legal frame must still arrive intact: the server's first bytes after the token
    /// line must be exactly the small frame, proving nothing of the oversized one was emitted.
    #[tokio::test]
    async fn send_frame_refuses_oversized_payload_without_writing() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let token = RelayToken(Uuid::new_v4());
            let small = Frame::new(ChannelId::Control, Bytes::from_static(b"ping"));
            let expected = small.to_bytes();

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut _line = String::new();
                reader.read_line(&mut _line).await.unwrap();
                let mut got = vec![0u8; 9];
                reader.read_exact(&mut got).await.unwrap();
                got
            });

            let mut transport = RelayTransport::connect(&addr, token).await.unwrap();
            let big = Frame::new(
                ChannelId::Video,
                Bytes::from(vec![0u8; rmt_protocol::frame::MAX_FRAME_LEN + 1]),
            );
            let result = transport.send_frame(big).await;
            assert!(
                matches!(result, Err(TransportError::Other(_))),
                "expected Other(_) for oversized frame, got {result:?}"
            );

            transport.send_frame(small).await.unwrap();
            let got = server.await.unwrap();
            assert_eq!(&got[..], &expected[..], "first bytes after token must be the small frame");
        })
        .await
        .expect("send_frame_refuses_oversized_payload_without_writing timed out");
    }

    /// recv_frame must return TransportError::Closed when the peer closes the connection.
    /// The server JoinHandle is awaited so a peer-task panic is visible rather than silently
    /// masquerading as successful EOF coverage.
    #[tokio::test]
    async fn recv_frame_returns_closed_on_eof() {
        timeout(TEST_TIMEOUT, async {
            let (addr, listener) = bind_loopback().await;
            let token = RelayToken(Uuid::new_v4());

            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut _line = String::new();
                reader.read_line(&mut _line).await.unwrap();
                // Drop stream here; the connection closes and the client sees EOF.
            });

            let mut transport = RelayTransport::connect(&addr, token).await.unwrap();
            assert!(matches!(transport.recv_frame().await, Err(TransportError::Closed)));
            server.await.unwrap();
        })
        .await
        .expect("recv_frame_returns_closed_on_eof timed out");
    }
}
