//! End-to-end session crypto (ADR-004).
//!
//! **NOT WIRED INTO ANY SHIPPING BINARY.** `Session::new` is called only from tests; the real data
//! plane in `transport-webrtc` moves length-prefixed frames over the SCTP/DTLS data channel with no
//! app-level sealing. Treat everything below as the intended design of this crate, not as a
//! description of what the product currently does — see docs/02 ADR-004's status note.
//!
//! When it IS wired in, the relay becomes blind in the strong sense: this layer would encrypt
//! session content *inside* whatever transport tunnel is used, so a compromised relay — or a
//! signaling server that substituted DTLS fingerprints — would see only ciphertext.
//!
//! Design:
//!   * Each agent and controller has a long-term **Ed25519 identity** (registered + pinned at
//!     signaling — closes the malicious-server key-swap gap).
//!   * Each session runs an **X25519 ECDH** with ephemeral keys, authenticated by the
//!     long-term identities → forward secrecy, fresh key per session.
//!   * The shared secret is run through **HKDF-SHA256** to derive directional AEAD keys, and
//!     session content is sealed with **ChaCha20-Poly1305**.
//!
//! This crate owns the primitives; higher layers own the handshake choreography over the
//! signaling/Control channel.

use thiserror::Error;

mod identity;
mod session;

pub use identity::{Identity, PublicIdentity, VerifyError};
pub use session::{Handshake, HandshakeError, SessionKeys, SealError, Role};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("seal/open failed: {0}")]
    Seal(#[from] SealError),
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("bad key encoding: {0}")]
    Encoding(String),
}
