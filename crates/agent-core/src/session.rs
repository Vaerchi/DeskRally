//! The session mux. A [`Session`] owns one direction-pair of end-to-end [`SessionKeys`] and
//! turns *logical* channel messages into *sealed* [`Frame`]s and back.
//!
//! Send path: `plaintext + ChannelId` → `SessionKeys::seal` (with the channel id bound as AEAD
//! associated data) → wrapped in a [`Frame`] tagged with that same channel. Receive path is the
//! inverse: a [`Frame`] is opened with its channel id as AAD, so a ciphertext captured on one
//! channel cannot be replayed onto another — the AEAD check fails if the tags disagree.
//!
//! The [`Session`] is transport-agnostic. It can produce/consume [`Frame`]s in isolation
//! ([`Session::seal_on`] / [`Session::open`]) or drive a [`Transport`] directly
//! ([`Session::send`] / [`Session::recv`]). Crypto and framing live here; byte-moving lives in
//! [`crate::transport`].

use rmt_crypto::{SealError, SessionKeys};
use rmt_protocol::{ChannelId, Frame, SessionId};

use crate::transport::{Transport, TransportError};

/// Errors from sealing/opening or moving a session frame.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The AEAD layer refused to seal or open (bad tag, wrong channel/AAD, exhausted nonce).
    #[error("session crypto error: {0}")]
    Crypto(#[from] SealError),
    /// The underlying transport failed while sending/receiving a frame.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// One live, end-to-end-encrypted session. Owns the [`SessionKeys`] (which carry the send/recv
/// nonce counters) and multiplexes [`ChannelId`] traffic over a single sealed [`Frame`] stream.
///
/// `&mut self` is required to send *or* receive because sealing and opening each advance a nonce
/// counter inside [`SessionKeys`]; a session is therefore driven from a single owning task.
pub struct Session {
    id: SessionId,
    keys: SessionKeys,
}

impl Session {
    /// Wrap established [`SessionKeys`] (from a completed [`rmt_crypto::Handshake`]) into a
    /// session identified by `id`.
    pub fn new(id: SessionId, keys: SessionKeys) -> Self {
        Self { id, keys }
    }

    /// The session's identifier.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Associated data bound into every sealed payload: the channel id. Binding the channel
    /// means a sealed payload authenticates *which* channel it belongs to, so it cannot be
    /// lifted from (say) [`ChannelId::Input`] and replayed on [`ChannelId::Clipboard`].
    fn channel_aad(channel: ChannelId) -> [u8; 1] {
        [channel as u8]
    }

    /// Seal `plaintext` for `channel` and return the wire-ready [`Frame`] (channel-tagged,
    /// carrying the sealed bytes as its payload). Advances the send nonce counter.
    pub fn seal_on(&mut self, channel: ChannelId, plaintext: &[u8]) -> Result<Frame, SessionError> {
        let aad = Self::channel_aad(channel);
        let sealed = self.keys.seal(plaintext, &aad)?;
        Ok(Frame::new(channel, sealed))
    }

    /// Open a received [`Frame`], returning the decrypted plaintext. The frame's own channel id
    /// is used as AAD, so a frame whose channel tag was altered in flight fails to open.
    /// Advances the receive nonce high-water mark.
    pub fn open(&mut self, frame: &Frame) -> Result<Vec<u8>, SessionError> {
        let aad = Self::channel_aad(frame.channel);
        let plaintext = self.keys.open(&frame.payload, &aad)?;
        Ok(plaintext)
    }

    /// Seal `plaintext` for `channel` and push it across `transport`. Convenience over
    /// [`Session::seal_on`] + [`Transport::send_frame`].
    pub async fn send<T: Transport>(
        &mut self,
        transport: &mut T,
        channel: ChannelId,
        plaintext: &[u8],
    ) -> Result<(), SessionError> {
        let frame = self.seal_on(channel, plaintext)?;
        transport.send_frame(frame).await?;
        Ok(())
    }

    /// Await the next frame from `transport` and open it, returning the channel it arrived on
    /// together with the decrypted plaintext.
    pub async fn recv<T: Transport>(
        &mut self,
        transport: &mut T,
    ) -> Result<(ChannelId, Vec<u8>), SessionError> {
        let frame = transport.recv_frame().await?;
        let plaintext = self.open(&frame)?;
        Ok((frame.channel, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::LoopbackTransport;
    use rmt_crypto::{Handshake, Role};

    /// Run a controller/agent handshake and wrap each side in a [`Session`] sharing one id.
    fn paired_sessions() -> (Session, Session) {
        let id = SessionId::new();
        let controller = Handshake::new(Role::Controller);
        let agent = Handshake::new(Role::Agent);
        let controller_pub = controller.public_bytes();
        let agent_pub = agent.public_bytes();
        let controller_keys = controller.complete(&agent_pub);
        let agent_keys = agent.complete(&controller_pub);
        (
            Session::new(id, controller_keys),
            Session::new(id, agent_keys),
        )
    }

    #[test]
    fn input_frame_round_trips_controller_to_agent() {
        let (mut controller, mut agent) = paired_sessions();

        let frame = controller
            .seal_on(ChannelId::Input, b"mousemove 32768,100")
            .unwrap();
        // The frame on the wire is tagged Input and its payload is *not* the plaintext.
        assert_eq!(frame.channel, ChannelId::Input);
        assert_ne!(&frame.payload[..], b"mousemove 32768,100");

        let opened = agent.open(&frame).unwrap();
        assert_eq!(opened, b"mousemove 32768,100");
    }

    #[test]
    fn both_directions_are_independent() {
        let (mut controller, mut agent) = paired_sessions();

        let up = controller.seal_on(ChannelId::Input, b"key A down").unwrap();
        assert_eq!(agent.open(&up).unwrap(), b"key A down");

        let down = agent.seal_on(ChannelId::Video, b"\x00\x01keyframe").unwrap();
        assert_eq!(controller.open(&down).unwrap(), b"\x00\x01keyframe");
    }

    #[test]
    fn frame_retagged_to_another_channel_fails_to_open() {
        let (mut controller, mut agent) = paired_sessions();
        let frame = controller.seal_on(ChannelId::Input, b"secret").unwrap();

        // Attacker keeps the sealed bytes but claims a different channel → AAD mismatch.
        let forged = Frame::new(ChannelId::Clipboard, frame.payload.clone());
        assert!(matches!(
            agent.open(&forged),
            Err(SessionError::Crypto(SealError::Decrypt))
        ));
        // The honest frame still opens fine.
        assert_eq!(agent.open(&frame).unwrap(), b"secret");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (mut controller, mut agent) = paired_sessions();
        let mut frame = controller.seal_on(ChannelId::Chat, b"hello").unwrap();
        let mut bad = frame.payload.to_vec();
        *bad.last_mut().unwrap() ^= 0xff;
        frame.payload = bad.into();
        assert!(agent.open(&frame).is_err());
    }

    #[tokio::test]
    async fn round_trips_over_a_loopback_transport() {
        let (mut controller, mut agent) = paired_sessions();
        let (mut ctrl_link, mut agent_link) = LoopbackTransport::pair();

        controller
            .send(&mut ctrl_link, ChannelId::Input, b"scroll 0,-3")
            .await
            .unwrap();

        let (channel, plaintext) = agent.recv(&mut agent_link).await.unwrap();
        assert_eq!(channel, ChannelId::Input);
        assert_eq!(plaintext, b"scroll 0,-3");
    }

    #[tokio::test]
    async fn send_returns_transport_error_when_transport_is_closed() {
        let (mut session, _) = paired_sessions();
        let (mut sender, receiver) = LoopbackTransport::pair();
        // Dropping the receiver closes the channel; the next send finds no reader.
        drop(receiver);
        let result = session.send(&mut sender, ChannelId::Input, b"ping").await;
        assert!(matches!(
            result,
            Err(SessionError::Transport(TransportError::Closed))
        ));
    }

    #[tokio::test]
    async fn recv_returns_transport_error_when_transport_is_closed() {
        let (mut session, _) = paired_sessions();
        let (sender, mut receiver) = LoopbackTransport::pair();
        // Dropping the sender closes the channel; recv sees no more senders.
        drop(sender);
        let result = session.recv(&mut receiver).await;
        assert!(matches!(
            result,
            Err(SessionError::Transport(TransportError::Closed))
        ));
    }

    #[test]
    fn session_exposes_its_id() {
        let id = SessionId::new();
        let (controller, _agent) = {
            let c = Handshake::new(Role::Controller);
            let a = Handshake::new(Role::Agent);
            let cp = c.public_bytes();
            let ap = a.public_bytes();
            (Session::new(id, c.complete(&ap)), Session::new(id, a.complete(&cp)))
        };
        assert_eq!(controller.id(), id);
    }
}
