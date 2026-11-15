//! Long-term Ed25519 identities for agents and controllers. Registered with signaling and
//! **pinned** so a compromised server can't swap keys to MITM (see docs/02-architecture.md
//! ADR-004). Hex-encoded on the wire.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// A private long-term identity. Sign with it; never send the secret anywhere.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    signing: SigningKey,
}

/// The public half — what peers pin and verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    verifying: VerifyingKey,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("signature invalid")]
    BadSignature,
    #[error("public key does not match the pinned identity")]
    Unpinned,
    #[error("malformed key/signature encoding")]
    Encoding,
}

impl Identity {
    /// Generate a fresh identity (at enrollment). Uses the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Self { signing: SigningKey::generate(&mut rng) }
    }

    /// Reconstruct from a stored 32-byte seed (e.g. from the OS keystore / DPAPI on Windows).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(seed) }
    }

    /// The 32-byte seed, for sealed at-rest storage. Handle with care.
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity { verifying: self.signing.verifying_key() }
    }

    pub fn public_hex(&self) -> String {
        self.public().to_hex()
    }

    /// Sign a message (e.g. the session handshake transcript) with the long-term key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

impl PublicIdentity {
    pub fn to_hex(&self) -> String {
        hex::encode(self.verifying.to_bytes())
    }

    /// Parse a hex-encoded 32-byte Ed25519 public key. Rejects (as `Encoding`) anything that is
    /// not valid hex, not exactly 32 bytes, not a decompressible curve point, or a small-order
    /// (weak) point: signatures under such a key are forgeable by anyone, so it can never be a
    /// pinned identity. `verify` itself stays non-strict so existing signatures still verify.
    pub fn from_hex(s: &str) -> Result<Self, VerifyError> {
        let bytes = hex::decode(s).map_err(|_| VerifyError::Encoding)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| VerifyError::Encoding)?;
        let verifying = VerifyingKey::from_bytes(&arr).map_err(|_| VerifyError::Encoding)?;
        if verifying.is_weak() {
            return Err(VerifyError::Encoding);
        }
        Ok(Self { verifying })
    }

    /// Verify a signature made by this identity's private half.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), VerifyError> {
        let signature = Signature::from_bytes(sig);
        self.verifying.verify(msg, &signature).map_err(|_| VerifyError::BadSignature)
    }

    /// Confirm a presented key matches what we pinned. Guards the malicious-rendezvous gap.
    pub fn assert_pinned(&self, pinned_hex: &str) -> Result<(), VerifyError> {
        if self.to_hex() == pinned_hex {
            Ok(())
        } else {
            Err(VerifyError::Unpinned)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let id = Identity::generate();
        let sig = id.sign(b"session-transcript");
        id.public().verify(b"session-transcript", &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let id = Identity::generate();
        let sig = id.sign(b"original");
        assert!(matches!(
            id.public().verify(b"tampered", &sig),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn public_key_hex_round_trips() {
        let id = Identity::generate();
        let hex = id.public_hex();
        let parsed = PublicIdentity::from_hex(&hex).unwrap();
        assert_eq!(parsed, id.public());
    }

    #[test]
    fn seed_reconstructs_the_same_identity() {
        let id = Identity::generate();
        let seed = id.seed();
        let id2 = Identity::from_seed(&seed);
        assert_eq!(id.public_hex(), id2.public_hex());
    }

    #[test]
    fn pinning_rejects_a_swapped_key() {
        let real = Identity::generate();
        let attacker = Identity::generate();
        assert!(real.public().assert_pinned(&real.public_hex()).is_ok());
        assert!(matches!(
            attacker.public().assert_pinned(&real.public_hex()),
            Err(VerifyError::Unpinned)
        ));
    }

    #[test]
    fn from_hex_rejects_non_hex_input() {
        let result = PublicIdentity::from_hex("gg");
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn from_hex_rejects_short_hex() {
        let result = PublicIdentity::from_hex("aabb");
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn from_hex_rejects_long_hex() {
        let result = PublicIdentity::from_hex(&"aa".repeat(33));
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn from_hex_rejects_all_zero_key() {
        let result = PublicIdentity::from_hex(&"00".repeat(32));
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn from_hex_rejects_identity_point() {
        let hex = format!("01{}", "00".repeat(31));
        assert_eq!(hex.len(), 64);
        let result = PublicIdentity::from_hex(&hex);
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn from_hex_rejects_order_8_point() {
        let result = PublicIdentity::from_hex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        );
        assert!(matches!(result, Err(VerifyError::Encoding)));
    }

    #[test]
    fn real_public_hex_parses_and_verifies_own_signature() {
        let id = Identity::generate();
        let parsed = PublicIdentity::from_hex(&id.public_hex()).unwrap();
        let sig = id.sign(b"msg");
        parsed.verify(b"msg", &sig).unwrap();
    }
}
