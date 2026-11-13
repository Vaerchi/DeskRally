//! TURN over TCP and TLS for the agent (docs/50).
//!
//! webrtc-ice gathers relay candidates over UDP only. On a network that blocks UDP the agent had no
//! relay at all, while the browser on the other end used `turns:…:443`. The vendored webrtc-ice
//! (`third_party/webrtc-ice/src/relay_dialer.rs`) now hands every `?transport=tcp` TURN URL to the
//! dialer registered here, and this module turns a TCP or TLS stream to the TURN server into the
//! packet-style [`Conn`] the TURN client already speaks, like Pion's `STUNConn`:
//! - **out:** each `send_to` writes one STUN message or ChannelData frame, padding ChannelData to
//!   a multiple of 4 bytes as RFC 8656 §12.5 requires over a stream;
//! - **in:** frames are delimited by their own headers (STUN: 20 + length; ChannelData: 4 + length,
//!   padded) and delivered one per `recv_from`, with the padding removed.
//!
//! The relayed address the server allocates is still UDP toward the peer. Only the agent-to-TURN
//! leg moves to TCP/TLS, which is exactly what a UDP-blocking firewall needs (RFC 8835 §3.4).
//!
//! TLS trust is [`crate::tls_trust::client_config`], the same roots as every other agent dial.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use webrtc::ice::relay_dialer::{set_relay_stream_dialer, RelayStreamDialer};
use webrtc::ice::url::{ProtoType, SchemeType, Url};
use webrtc::util::{Conn, Error as UtilError};

/// Bound on the TCP connect and, separately, on the TLS handshake. The agent gathers NON-trickle
/// (it sends its SDP once gathering completes), so an unreachable TURN listener that silently drops
/// packets delays the session start by up to this much per stage. Our TURN answers in well under a
/// second wherever it is reachable at all.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// How the frame starting with `head` is laid out: `(bytes on the wire, bytes delivered)`.
/// - STUN (first two bits `00`): a 20-byte header plus the message length, a multiple of 4.
/// - ChannelData (first two bits `01`, channels 0x4000-0x7FFF): 4 + length, padded to 4 over a stream.
/// - Anything else is not a TURN frame; the stream cannot be resynchronised, so it is an error.
pub(crate) fn frame_layout(head: [u8; 4]) -> Result<(usize, usize), String> {
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] >> 6 {
        0b00 if len % 4 == 0 => Ok((20 + len, 20 + len)),
        0b00 => Err(format!("STUN message length {len} is not a multiple of 4")),
        0b01 => Ok((4 + ((len + 3) & !3), 4 + len)),
        _ => Err(format!("first byte {:#04x} is neither STUN nor ChannelData", head[0])),
    }
}

/// Bytes to append when writing `frame` to a stream: ChannelData pads to a multiple of 4.
pub(crate) fn write_padding(frame: &[u8]) -> usize {
    if frame.first().is_some_and(|b| b >> 6 == 0b01) {
        (4 - frame.len() % 4) % 4
    } else {
        0
    }
}

/// Frames queued for the writer task. A full queue drops the frame, as a full UDP send buffer would:
/// the TURN client retransmits its own requests, and media tolerates loss.
const OUTBOUND_FRAMES: usize = 256;
/// Whole frames the reader task may hold for `recv_from`. When full, the reader stops reading, which
/// is TCP backpressure toward the server rather than a drop.
const INBOUND_FRAMES: usize = 256;

type Inbound = Result<Vec<u8>, String>;

/// One TCP or TLS stream to a TURN server, presented as a packet [`Conn`].
///
/// Two tasks own the stream, one per half:
/// - the **writer** writes whole frames from a queue, so no caller can be cancelled halfway through
///   a frame and leave the stream unframed (`write_all` is not cancel-safe);
/// - the **reader** cuts the byte stream into frames and hands them over a channel, so a cancelled
///   `recv_from` loses nothing.
///
/// `close` only signals. Both tasks stop at once, even if the server has stopped reading, and drop
/// their halves, which closes the socket (both halves of a split stream must go before it does).
/// The connection is terminal from then on.
pub struct StreamConn {
    inbound: Mutex<tokio::sync::mpsc::Receiver<Inbound>>,
    out: tokio::sync::mpsc::Sender<Vec<u8>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    local: SocketAddr,
    remote: SocketAddr,
}

impl StreamConn {
    /// Must be called inside a tokio runtime: it spawns the reader and writer tasks.
    pub fn new<S>(stream: S, local: SocketAddr, remote: SocketAddr) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        let (out, out_rx) = tokio::sync::mpsc::channel(OUTBOUND_FRAMES);
        let (in_tx, inbound) = tokio::sync::mpsc::channel(INBOUND_FRAMES);
        let (shutdown, stop) = tokio::sync::watch::channel(false);
        tokio::spawn(write_frames(w, out_rx, stop.clone()));
        tokio::spawn(read_frames(r, in_tx, stop));
        StreamConn { inbound: Mutex::new(inbound), out, shutdown, local, remote }
    }

    fn closed() -> UtilError {
        UtilError::Other("TURN stream closed".into())
    }

    async fn read_frame(&self, buf: &mut [u8]) -> Result<usize, UtilError> {
        let mut stop = self.shutdown.subscribe();
        if *stop.borrow() {
            return Err(Self::closed());
        }
        let mut rx = self.inbound.lock().await;
        // `recv` is cancel-safe: a frame is only taken once it completes.
        let frame = tokio::select! {
            m = rx.recv() => match m {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Err(UtilError::Other(e)),
                None => return Err(Self::closed()),
            },
            _ = stop.wait_for(|closed| *closed) => return Err(Self::closed()),
        };
        if frame.len() > buf.len() {
            return Err(UtilError::ErrBufferShort);
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
    /// Queue one whole frame for the writer task. Never waits, so there is nothing to cancel.
    fn write_frame(&self, frame: &[u8]) -> Result<usize, UtilError> {
        if *self.shutdown.borrow() {
            return Err(Self::closed());
        }
        let pad = write_padding(frame);
        let mut out = Vec::with_capacity(frame.len() + pad);
        out.extend_from_slice(frame);
        out.resize(frame.len() + pad, 0);
        match self.out.try_send(out) {
            Ok(()) => Ok(frame.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("turn: TCP send queue full; frame dropped");
                Ok(frame.len())
            }
            // The writer task ended: a write failed or the connection was closed.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(Self::closed()),
        }
    }
}

/// The reader task: cut the stream into frames (padding removed) until EOF, an error, or `close`.
/// A stream that is not TURN framing cannot be resynchronised: the error is delivered, then it stops.
async fn read_frames<R: AsyncRead + Unpin>(
    mut r: R,
    tx: tokio::sync::mpsc::Sender<Inbound>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        while pending.len() >= 4 {
            let head = [pending[0], pending[1], pending[2], pending[3]];
            let (wire, deliver) = match frame_layout(head) {
                Ok(l) => l,
                Err(e) => {
                    // Deliver the error unless closing; never wait past `close` (the queue may be full).
                    tokio::select! {
                        _ = tx.send(Err(e)) => {}
                        _ = stop.wait_for(|closed| *closed) => {}
                    }
                    return;
                }
            };
            if pending.len() < wire {
                break;
            }
            let frame = pending[..deliver].to_vec();
            pending.drain(..wire);
            tokio::select! {
                sent = tx.send(Ok(frame)) => if sent.is_err() { return },
                _ = stop.wait_for(|closed| *closed) => return,
            }
        }
        let n = tokio::select! {
            res = r.read(&mut chunk) => match res {
                Ok(0) | Err(_) => return, // dropping `tx` ends every later receive
                Ok(n) => n,
            },
            _ = stop.wait_for(|closed| *closed) => return,
        };
        pending.extend_from_slice(&chunk[..n]);
    }
}

/// The writer task: whole frames, in order, until the queue closes, a write fails, or `close`.
async fn write_frames<W: AsyncWrite + Unpin>(
    mut w: W,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let frame = tokio::select! {
            f = rx.recv() => match f { Some(f) => f, None => break },
            _ = stop.wait_for(|closed| *closed) => break,
        };
        let written = tokio::select! {
            r = async { w.write_all(&frame).await?; w.flush().await } => r.is_ok(),
            // Interrupting a write leaves the stream unframed; that is fine, it is closing.
            _ = stop.wait_for(|closed| *closed) => false,
        };
        if !written {
            break;
        }
    }
    // Dropping `rx` here makes later sends fail with Closed; dropping `w` releases the stream.
}

#[async_trait::async_trait]
impl Conn for StreamConn {
    async fn connect(&self, _addr: SocketAddr) -> Result<(), UtilError> {
        Ok(()) // a stream is connected from birth, to exactly one TURN server
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, UtilError> {
        self.read_frame(buf).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), UtilError> {
        Ok((self.read_frame(buf).await?, self.remote))
    }
    async fn send(&self, buf: &[u8]) -> Result<usize, UtilError> {
        self.write_frame(buf)
    }
    /// The target is ignored: everything on this stream goes to its one TURN server, which is the
    /// only address the TURN client ever sends to.
    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> Result<usize, UtilError> {
        self.write_frame(buf)
    }
    fn local_addr(&self) -> Result<SocketAddr, UtilError> {
        Ok(self.local)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }
    /// Signals only, so it returns at once even when the server has stopped reading.
    async fn close(&self) -> Result<(), UtilError> {
        self.shutdown.send_replace(true);
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Dials `turn:…?transport=tcp` over TCP and `turns:…?transport=tcp` over TLS.
pub struct TurnStreamDialer {
    /// `None` when the agent's TLS roots could not be loaded: `turns:` then fails (logged per URL)
    /// and plain `turn:` over TCP still works.
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl TurnStreamDialer {
    pub fn new(tls: Option<Arc<rustls::ClientConfig>>) -> Self {
        TurnStreamDialer { tls }
    }

    async fn dial_inner(&self, url: &Url) -> Result<StreamConn, String> {
        if url.proto != ProtoType::Tcp {
            return Err(format!("not a TCP TURN URL: {url}"));
        }
        let addr = format!("{}:{}", url.host, url.port);
        let tcp = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("TCP connect to {addr} timed out"))?
            .map_err(|e| format!("TCP connect to {addr}: {e}"))?;
        let _ = tcp.set_nodelay(true);
        let local = tcp.local_addr().map_err(|e| e.to_string())?;
        let remote = tcp.peer_addr().map_err(|e| e.to_string())?;
        match url.scheme {
            SchemeType::Turn => Ok(StreamConn::new(tcp, local, remote)),
            SchemeType::Turns => {
                let config = self.tls.clone().ok_or("no TLS trust roots for turns:")?;
                // The certificate is checked against the URL's host, never the resolved address.
                let name = rustls::pki_types::ServerName::try_from(url.host.clone())
                    .map_err(|e| format!("TURN host {:?} is not a valid TLS name: {e}", url.host))?;
                let tls = tokio::time::timeout(DIAL_TIMEOUT, tokio_rustls::TlsConnector::from(config).connect(name, tcp))
                    .await
                    .map_err(|_| format!("TLS handshake with {addr} timed out"))?
                    .map_err(|e| format!("TLS handshake with {addr}: {e}"))?;
                Ok(StreamConn::new(tls, local, remote))
            }
            _ => Err(format!("not a TURN URL: {url}")),
        }
    }
}

#[async_trait::async_trait]
impl RelayStreamDialer for TurnStreamDialer {
    async fn dial(&self, url: &Url) -> Result<Arc<dyn Conn + Send + Sync>, String> {
        Ok(Arc::new(self.dial_inner(url).await?))
    }
}

/// Register the production dialer once per process (later calls are no-ops). Called before any
/// peer connection is built, so the first session can already use TCP/TLS TURN.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let tls = match crate::tls_trust::client_config() {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                tracing::warn!(error = %e, "turn: TLS roots unavailable; turns: relays are disabled, turn: over TCP still works");
                None
            }
        };
        set_relay_stream_dialer(Arc::new(TurnStreamDialer::new(tls)));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_reads_stun_and_padded_channel_data() {
        // STUN binding request header: type 0x0001, length 8.
        assert_eq!(frame_layout([0x00, 0x01, 0x00, 0x08]), Ok((28, 28)));
        // ChannelData 0x4000, length 5: delivered 9 bytes, 12 on the wire.
        assert_eq!(frame_layout([0x40, 0x00, 0x00, 0x05]), Ok((12, 9)));
        assert_eq!(frame_layout([0x7F, 0xFF, 0x00, 0x04]), Ok((8, 8)), "already aligned: no padding");
        assert!(frame_layout([0x00, 0x01, 0x00, 0x07]).is_err(), "STUN length must be a multiple of 4");
        assert!(frame_layout([0x80, 0, 0, 0]).is_err(), "neither STUN nor ChannelData");
        assert!(frame_layout([0xC0, 0, 0, 0]).is_err());
    }

    #[test]
    fn only_channel_data_is_padded_on_write() {
        assert_eq!(write_padding(&[0x40, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5]), 3);
        assert_eq!(write_padding(&[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4]), 0);
        assert_eq!(write_padding(&[0x00, 0x01, 0x00, 0x00]), 0, "STUN is always aligned");
        assert_eq!(write_padding(&[]), 0);
    }

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], p))
    }

    #[tokio::test]
    async fn frames_survive_a_stream_split_into_single_bytes() {
        let (a, mut b) = tokio::io::duplex(64);
        let conn = StreamConn::new(a, addr(1), addr(2));
        let stun = [0x01, 0x01, 0x00, 0x04, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 9, 9, 9, 9];
        let chan = [0x40, 0x01, 0x00, 0x03, 7, 7, 7, 0]; // ChannelData, 3 bytes + 1 pad
        let writer = tokio::spawn(async move {
            for byte in stun.iter().chain(chan.iter()) {
                b.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            b
        });
        let mut buf = [0u8; 100];
        let (n, from) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&stun[..], addr(2)));
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &chan[..7], "padding removed");
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn channel_data_is_padded_on_the_wire_and_garbage_is_an_error() {
        let (a, mut b) = tokio::io::duplex(64);
        let conn = StreamConn::new(a, addr(1), addr(2));
        assert_eq!(conn.send_to(&[0x40, 0x00, 0x00, 0x01, 0xAB], addr(9)).await.unwrap(), 5);
        let mut wire = [0u8; 8];
        b.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, [0x40, 0x00, 0x00, 0x01, 0xAB, 0, 0, 0]);

        b.write_all(&[0xFF, 0, 0, 0]).await.unwrap();
        let mut buf = [0u8; 16];
        assert!(conn.recv_from(&mut buf).await.is_err(), "a non-TURN frame cannot be resynchronised");
    }

    #[tokio::test]
    async fn a_frame_larger_than_the_buffer_is_refused_not_truncated() {
        let (a, mut b) = tokio::io::duplex(64);
        let conn = StreamConn::new(a, addr(1), addr(2));
        b.write_all(&[0x40, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]).await.unwrap();
        let mut small = [0u8; 8];
        assert!(matches!(conn.recv_from(&mut small).await, Err(UtilError::ErrBufferShort)));
    }

    /// Codex round 1: a server that stops reading must not be able to hang `close`, and after close
    /// the connection is terminal in both directions.
    #[tokio::test]
    async fn close_returns_at_once_while_the_server_is_not_reading() {
        let (a, _never_read) = tokio::io::duplex(8);
        let conn = StreamConn::new(a, addr(1), addr(2));
        for _ in 0..50 {
            conn.send_to(&[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4], addr(9)).await.unwrap(); // writer now blocked
        }
        tokio::time::timeout(Duration::from_secs(1), conn.close()).await.expect("close must not wait for the writer").unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await; // let the writer task observe it
        assert!(conn.send_to(&[0x00, 0x01, 0x00, 0x00], addr(9)).await.is_err(), "terminal after close");
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(1), conn.recv_from(&mut buf)).await.expect("no hang");
        assert!(r.is_err());
    }

    /// Codex round 2: close must actually close the SOCKET, even while the StreamConn is still
    /// referenced, so the TURN server sees the connection end and frees the allocation.
    #[tokio::test]
    async fn close_closes_the_socket_while_the_conn_is_still_referenced() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let local = client.local_addr().unwrap();
        let conn = StreamConn::new(client, local, server_addr);
        conn.close().await.unwrap();
        let mut byte = [0u8; 1];
        let seen = tokio::time::timeout(Duration::from_secs(2), server.read(&mut byte)).await;
        assert!(
            matches!(seen, Ok(Ok(0)) | Ok(Err(_))),
            "the server must observe the connection ending; got {seen:?}"
        );
        drop(conn); // still alive until here
    }

    /// Codex 1.3.7 release review v3: a TURN client that fails to construct (or a gather that returns
    /// early) DROPS the StreamConn without calling close. Dropping must close it too: the shutdown
    /// sender's drop wakes both tasks, so the server sees the connection end, even with a writer
    /// blocked on a server that is not reading.
    #[tokio::test]
    async fn dropping_the_conn_without_close_closes_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let local = client.local_addr().unwrap();
        let conn = StreamConn::new(client, local, server_addr);
        conn.send_to(&[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4], addr(9)).await.unwrap();
        drop(conn);
        let mut buf = [0u8; 64];
        let ended = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match server.read(&mut buf).await {
                    Ok(0) | Err(_) => return true,
                    Ok(_) => continue, // the frame queued before the drop may still arrive
                }
            }
        })
        .await;
        assert_eq!(ended.ok(), Some(true), "the server must observe the connection ending after a plain drop");
    }

    /// Codex round 3: with the inbound queue full of undelivered frames and a malformed header
    /// behind them, close must still release the read half (the socket closes, conn still alive).
    #[tokio::test]
    async fn close_closes_the_socket_with_a_full_inbound_queue_and_a_bad_frame_behind_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let local = client.local_addr().unwrap();
        let conn = StreamConn::new(client, local, server_addr);
        // EXACTLY a queue's worth of valid frames: all of them fit, so the reader goes on to the
        // malformed header and blocks delivering THAT error (one more valid frame would block it
        // earlier, on a valid-frame send, and the error path would go untested; Codex round 4).
        for _ in 0..INBOUND_FRAMES {
            server.write_all(&[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4]).await.unwrap();
        }
        server.write_all(&[0xFF, 0, 0, 0]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await; // loopback: the reader has read it all
        conn.close().await.unwrap(); // never drained
        let mut sink = [0u8; 64];
        let seen = tokio::time::timeout(Duration::from_secs(2), server.read(&mut sink)).await;
        assert!(matches!(seen, Ok(Ok(0)) | Ok(Err(_))), "the server must observe the connection ending; got {seen:?}");
        drop(conn);
    }

    #[tokio::test]
    async fn a_pending_receive_ends_on_close() {
        let (a, _b) = tokio::io::duplex(64);
        let conn = Arc::new(StreamConn::new(a, addr(1), addr(2)));
        let c = conn.clone();
        let pending = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            c.recv_from(&mut buf).await.map(|(n, _)| n)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        conn.close().await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(1), pending).await.expect("receive released").unwrap();
        assert!(r.is_err());
    }

    /// Frames reach a slow reader whole and in order (the writer task writes one frame at a time).
    #[tokio::test]
    async fn a_slow_reader_gets_every_frame_whole_and_in_order() {
        let (a, mut b) = tokio::io::duplex(16);
        let conn = StreamConn::new(a, addr(1), addr(2));
        for i in 0..100u8 {
            conn.send_to(&[0x40, 0x00, 0x00, 0x03, i, i, i], addr(9)).await.unwrap();
        }
        for i in 0..100u8 {
            let mut frame = [0u8; 8];
            b.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame, [0x40, 0x00, 0x00, 0x03, i, i, i, 0], "frame {i}");
            if i % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    /// A send never waits: with the server not reading and the queue full, frames are dropped
    /// (as a full UDP buffer drops them) instead of blocking the caller.
    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        let (a, _never_read) = tokio::io::duplex(4);
        let conn = StreamConn::new(a, addr(1), addr(2));
        let sent = tokio::time::timeout(Duration::from_secs(1), async {
            for _ in 0..(OUTBOUND_FRAMES * 4) {
                conn.send_to(&[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4], addr(9)).await.unwrap();
            }
        })
        .await;
        assert!(sent.is_ok(), "sends must not block on a stalled server");
    }

    #[tokio::test]
    async fn a_cancelled_receive_loses_no_bytes() {
        let (a, mut b) = tokio::io::duplex(64);
        let conn = StreamConn::new(a, addr(1), addr(2));
        b.write_all(&[0x40, 0x00, 0x00, 0x04, 1, 2]).await.unwrap(); // half a frame
        let mut buf = [0u8; 16];
        let first = tokio::time::timeout(Duration::from_millis(50), conn.recv_from(&mut buf)).await;
        assert!(first.is_err(), "incomplete frame: the receive is still waiting when cancelled");
        b.write_all(&[3, 4]).await.unwrap();
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x40, 0x00, 0x00, 0x04, 1, 2, 3, 4]);
    }
}
