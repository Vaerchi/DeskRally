//! Per-session key agreement + authenticated encryption. Ephemeral X25519 ECDH gives forward
//! secrecy; HKDF-SHA256 derives directional keys; ChaCha20-Poly1305 seals each message. The
//! ECDH transcript is signed by the long-term identities at a higher layer for authentication.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Which side of the session we are — decides key direction so the two peers agree on which
/// derived key is send vs receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The connecting controller.
    Controller,
    /// The controlled agent.
    Agent,
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("AEAD encryption failed")]
    Encrypt,
    #[error("AEAD decryption/authentication failed")]
    Decrypt,
    #[error("nonce counter exhausted; rekey required")]
    NonceExhausted,
    #[error("replayed or stale message counter")]
    Replay,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("peer public key is a low-order point; shared secret is not contributory")]
    LowOrderPeerKey,
}

/// One side's ephemeral handshake state. Exchange `public_bytes()` with the peer (over the
/// authenticated Control channel), then `complete()` into [`SessionKeys`].
pub struct Handshake {
    secret: EphemeralSecret,
    public: PublicKey,
    role: Role,
}

impl Handshake {
    pub fn new(role: Role) -> Self {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public, role }
    }

    /// Our ephemeral public key to send to the peer (32 bytes).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Complete the ECDH with the peer's ephemeral public key, deriving directional AEAD keys.
    ///
    /// This does NOT reject low-order peer public keys: such a key yields an all-zero shared
    /// secret that anyone can compute. New code should use [`Handshake::try_complete`].
    pub fn complete(self, peer_public: &[u8; 32]) -> SessionKeys {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        derive_session_keys(self.role, shared.as_bytes())
    }

    /// Like [`Handshake::complete`], but fails closed when the peer's public key is a low-order
    /// point (non-contributory exchange), before any key material is derived.
    pub fn try_complete(self, peer_public: &[u8; 32]) -> Result<SessionKeys, HandshakeError> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(HandshakeError::LowOrderPeerKey);
        }
        Ok(derive_session_keys(self.role, shared.as_bytes()))
    }
}

/// Derive two 32-byte keys from the shared secret. Both sides use the same salt/info so they
/// agree; `Role` selects which is "send" vs "receive".
fn derive_session_keys(role: Role, shared: &[u8; 32]) -> SessionKeys {
    let hk = Hkdf::<Sha256>::new(Some(b"rmt-session-v1"), shared);
    let mut c2a = [0u8; 32]; // controller -> agent
    let mut a2c = [0u8; 32]; // agent -> controller
    hk.expand(b"controller-to-agent", &mut c2a).expect("hkdf len ok");
    hk.expand(b"agent-to-controller", &mut a2c).expect("hkdf len ok");

    let (send, recv) = match role {
        Role::Controller => (c2a, a2c),
        Role::Agent => (a2c, c2a),
    };
    SessionKeys::new(&send, &recv)
}

/// Established per-session keys. `seal` for outbound, `open` for inbound. Nonces are counters,
/// distinct per direction, so the two peers never reuse a (key, nonce) pair.
pub struct SessionKeys {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_ctr: u64,
    replay: ReplayWindow,
}

impl SessionKeys {
    fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        Self {
            send: ChaCha20Poly1305::new(Key::from_slice(send_key)),
            recv: ChaCha20Poly1305::new(Key::from_slice(recv_key)),
            send_ctr: 0,
            replay: ReplayWindow::new(),
        }
    }

    /// Seal an outbound message. Returns `[nonce_counter: u64 be][ciphertext+tag]`. `aad` binds
    /// context (e.g. the channel id) so a frame can't be replayed onto another channel.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
        let ctr = self.send_ctr;
        self.send_ctr = self.send_ctr.checked_add(1).ok_or(SealError::NonceExhausted)?;
        let nonce = counter_nonce(ctr);
        let ct = self
            .send
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| SealError::Encrypt)?;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&ctr.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open an inbound message produced by the peer's `seal`.
    pub fn open(&mut self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < 8 {
            return Err(SealError::Decrypt);
        }
        let ctr = u64::from_be_bytes(sealed[..8].try_into().unwrap());
        // Refuse replays and stale counters BEFORE spending a decrypt on them.
        if self.replay.is_replay(ctr) {
            return Err(SealError::Replay);
        }
        let nonce = counter_nonce(ctr);
        let pt = self
            .recv
            .decrypt(&nonce, Payload { msg: &sealed[8..], aad })
            .map_err(|_| SealError::Decrypt)?;
        // Mark the counter seen only now that the tag verified: a forged frame must not burn a
        // legitimate slot or advance the window.
        self.replay.mark_seen(ctr);
        Ok(pt)
    }
}

/// Width of the anti-replay window: the highest accepted counter plus the 63 below it.
const REPLAY_WINDOW: u64 = 64;

/// Sliding-window replay filter (IPsec/WireGuard style). Bit `i` of `bitmap` records that counter
/// `highest - i` was accepted.
struct ReplayWindow {
    started: bool,
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self { started: false, highest: 0, bitmap: 0 }
    }

    /// True if `ctr` was already accepted or is older than the window.
    fn is_replay(&self, ctr: u64) -> bool {
        if !self.started || ctr > self.highest {
            return false;
        }
        let back = self.highest - ctr;
        back >= REPLAY_WINDOW || (self.bitmap >> back) & 1 == 1
    }

    /// Record `ctr` as accepted. Call only after the AEAD tag has verified.
    fn mark_seen(&mut self, ctr: u64) {
        if !self.started {
            self.started = true;
            self.highest = ctr;
            self.bitmap = 1;
        } else if ctr > self.highest {
            let shift = ctr - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = ctr;
        } else {
            let back = self.highest - ctr;
            if back < REPLAY_WINDOW {
                self.bitmap |= 1u64 << back;
            }
        }
    }
}

/// Build a 96-bit nonce from a 64-bit counter (first 4 bytes zero). Unique per direction key.
fn counter_nonce(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    *Nonce::from_slice(&n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish() -> (SessionKeys, SessionKeys) {
        let ctrl = Handshake::new(Role::Controller);
        let agent = Handshake::new(Role::Agent);
        let ctrl_pub = ctrl.public_bytes();
        let agent_pub = agent.public_bytes();
        (ctrl.complete(&agent_pub), agent.complete(&ctrl_pub))
    }

    #[test]
    fn both_sides_derive_interoperable_keys() {
        let (mut controller, mut agent) = establish();
        // Controller -> agent.
        let sealed = controller.seal(b"move 10,20", b"channel:input").unwrap();
        let opened = agent.open(&sealed, b"channel:input").unwrap();
        assert_eq!(opened, b"move 10,20");
        // Agent -> controller.
        let sealed = agent.seal(b"frame-data", b"channel:video").unwrap();
        let opened = controller.open(&sealed, b"channel:video").unwrap();
        assert_eq!(opened, b"frame-data");
    }

    #[test]
    fn wrong_aad_fails_to_open() {
        let (mut controller, mut agent) = establish();
        let sealed = controller.seal(b"secret", b"channel:input").unwrap();
        assert!(matches!(
            agent.open(&sealed, b"channel:video"),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut controller, mut agent) = establish();
        let mut sealed = controller.seal(b"secret", b"aad").unwrap();
        *sealed.last_mut().unwrap() ^= 0xff;
        assert!(agent.open(&sealed, b"aad").is_err());
    }

    #[test]
    fn a_third_party_key_cannot_decrypt() {
        let (mut controller, _agent) = establish();
        let (_c2, mut eavesdropper) = establish();
        let sealed = controller.seal(b"secret", b"aad").unwrap();
        assert!(eavesdropper.open(&sealed, b"aad").is_err());
    }

    #[test]
    fn seal_returns_nonce_exhausted_at_counter_overflow() {
        let (mut controller, _agent) = establish();
        controller.send_ctr = u64::MAX;
        assert!(matches!(
            controller.seal(b"msg", b"aad"),
            Err(SealError::NonceExhausted)
        ));
    }

    /// Seal at an explicit counter using the sender's key, same wire format as `seal`.
    fn seal_at(keys: &SessionKeys, ctr: u64, pt: &[u8], aad: &[u8]) -> Vec<u8> {
        let ct = keys
            .send
            .encrypt(&counter_nonce(ctr), Payload { msg: pt, aad })
            .unwrap();
        let mut out = ctr.to_be_bytes().to_vec();
        out.extend_from_slice(&ct);
        out
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let (mut controller, mut agent) = establish();
        let sealed = controller.seal(b"key down", b"aad").unwrap();
        assert_eq!(agent.open(&sealed, b"aad").unwrap(), b"key down");
        assert!(matches!(agent.open(&sealed, b"aad"), Err(SealError::Replay)));
    }

    #[test]
    fn failed_auth_does_not_consume_the_slot() {
        let (mut controller, mut agent) = establish();
        let genuine = controller.seal(b"real", b"aad").unwrap();
        let mut forged = genuine.clone();
        *forged.last_mut().unwrap() ^= 0xff;
        assert!(matches!(agent.open(&forged, b"aad"), Err(SealError::Decrypt)));
        assert_eq!(agent.open(&genuine, b"aad").unwrap(), b"real");
    }

    #[test]
    fn in_window_reordering_is_accepted_then_replays_rejected() {
        let (mut controller, mut agent) = establish();
        let f: Vec<Vec<u8>> = (0..3u8).map(|i| controller.seal(&[i], b"aad").unwrap()).collect();
        for i in [2usize, 0, 1] {
            assert_eq!(agent.open(&f[i], b"aad").unwrap(), vec![i as u8]);
        }
        for frame in &f {
            assert!(matches!(agent.open(frame, b"aad"), Err(SealError::Replay)));
        }
    }

    #[test]
    fn counter_just_outside_window_is_stale() {
        let (controller, mut agent) = establish();
        agent.open(&seal_at(&controller, 100, b"x", b"aad"), b"aad").unwrap();
        assert!(matches!(
            agent.open(&seal_at(&controller, 100 - 64, b"x", b"aad"), b"aad"),
            Err(SealError::Replay)
        ));
        assert!(agent.open(&seal_at(&controller, 100 - 63, b"x", b"aad"), b"aad").is_ok());
    }

    #[test]
    fn long_in_order_run_all_opens() {
        let (mut controller, mut agent) = establish();
        for i in 0..1000u32 {
            let sealed = controller.seal(&i.to_be_bytes(), b"aad").unwrap();
            assert_eq!(agent.open(&sealed, b"aad").unwrap(), i.to_be_bytes());
        }
    }

    #[test]
    fn max_counter_opens_once_and_does_not_wrap_window() {
        let (controller, mut agent) = establish();
        let max = seal_at(&controller, u64::MAX, b"x", b"aad");
        assert!(agent.open(&max, b"aad").is_ok());
        assert!(matches!(agent.open(&max, b"aad"), Err(SealError::Replay)));
        assert!(matches!(
            agent.open(&seal_at(&controller, 5, b"x", b"aad"), b"aad"),
            Err(SealError::Replay)
        ));
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn low_order_points() -> Vec<[u8; 32]> {
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut pm1 = [0xffu8; 32];
        pm1[0] = 0xec;
        pm1[31] = 0x7f;
        let mut p = pm1;
        p[0] = 0xed;
        let mut pp1 = pm1;
        pp1[0] = 0xee;
        vec![
            [0u8; 32],
            one,
            hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            pm1,
            p,
            pp1,
        ]
    }

    #[test]
    fn try_complete_honest_peers_interoperate_with_complete() {
        // All four checked/unchecked pairings must interoperate, proving identical derivation.
        for (ctrl_checked, agent_checked) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let ctrl = Handshake::new(Role::Controller);
            let agent = Handshake::new(Role::Agent);
            let ctrl_pub = ctrl.public_bytes();
            let agent_pub = agent.public_bytes();
            let mut c = if ctrl_checked {
                ctrl.try_complete(&agent_pub).unwrap()
            } else {
                ctrl.complete(&agent_pub)
            };
            let mut a = if agent_checked {
                agent.try_complete(&ctrl_pub).unwrap()
            } else {
                agent.complete(&ctrl_pub)
            };
            let sealed = c.seal(b"to agent", b"aad").unwrap();
            assert_eq!(a.open(&sealed, b"aad").unwrap(), b"to agent");
            let sealed = a.seal(b"to controller", b"aad").unwrap();
            assert_eq!(c.open(&sealed, b"aad").unwrap(), b"to controller");
        }
    }

    #[test]
    fn try_complete_refuses_all_zero_peer_key() {
        let hs = Handshake::new(Role::Controller);
        assert!(matches!(
            hs.try_complete(&[0u8; 32]),
            Err(HandshakeError::LowOrderPeerKey)
        ));
    }

    #[test]
    fn try_complete_refuses_known_low_order_points_for_both_roles() {
        for point in low_order_points() {
            for role in [Role::Controller, Role::Agent] {
                let hs = Handshake::new(role);
                assert_eq!(
                    hs.try_complete(&point).err(),
                    Some(HandshakeError::LowOrderPeerKey),
                    "role {role:?}, point {point:02x?}"
                );
            }
        }
    }

    #[test]
    fn handshake_error_message_is_stable() {
        assert_eq!(
            HandshakeError::LowOrderPeerKey.to_string(),
            "peer public key is a low-order point; shared secret is not contributory"
        );
    }

    #[test]
    fn open_returns_decrypt_on_truncated_input() {
        let (_controller, mut agent) = establish();
        assert!(matches!(
            agent.open(&[0u8; 7], b"aad"),
            Err(SealError::Decrypt)
        ));
    }
}
