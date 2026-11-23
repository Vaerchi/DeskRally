//! Session BINDING GRANTS (docs/69 §3.1): the control plane telling this agent which console key may
//! prove itself in one session. Signed with the same pinned issuer key as a session policy or a
//! backstage grant, under its own domain tag (`RMTBINDGv1`).
//!
//! The canonical preimage is a byte-for-byte port of Go's `bindingGrantSigningBytes`
//! (control-plane/binding_grant_mint.go); `tests::verifies_go_minted_binding_grant` pins a grant the Go
//! side minted.

use serde::{Deserialize, Serialize};

use rmt_crypto::PublicIdentity;

use crate::backstage::grant::CLOCK_SKEW_MS;
use crate::session_policy::AccessLevel;

/// `RMTBINDGv1` + two NUL bytes: 12 bytes, like every tag signed by the issuer key.
pub const BINDING_GRANT_DOMAIN_TAG: &[u8; 12] = b"RMTBINDGv1\0\0";

/// Preimage layout version, signed right after the tag.
pub const BINDING_GRANT_VERSION: u8 = 1;

/// The signed claims, exactly as the control plane emits them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingGrantClaims {
    /// The control-plane session id (the one the session ticket carries).
    pub session_id: uuid::Uuid,
    /// The device this grant is for. Must be this agent's own device id.
    pub device_id: uuid::Uuid,
    /// The tenant the session belongs to.
    pub tenant_id: uuid::Uuid,
    /// The technician the control plane admitted.
    pub technician_id: uuid::Uuid,
    /// The access level the control plane admitted.
    pub access: AccessLevel,
    /// The console's ephemeral Ed25519 public key (64 lowercase hex chars).
    pub console_pubkey: String,
    /// Issuance time, Unix ms.
    pub issued_at_ms: i64,
    /// Expiry, Unix ms. Checked when the grant is installed.
    pub expires_at_ms: i64,
}

/// Claims plus the issuer's Ed25519 signature (128 hex chars) over their canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBindingGrant {
    /// The signed claims.
    pub claims: BindingGrantClaims,
    /// Hex Ed25519 signature.
    pub sig: String,
}

/// What a verified grant establishes, from a source signaling cannot forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBindingGrant {
    /// The control-plane session id; the binding transcript signs it.
    pub session_id: uuid::Uuid,
    /// The admitted technician (authoritative over anything signaling reports, docs/69 §3.1).
    pub technician_id: uuid::Uuid,
    /// The tenant.
    pub tenant_id: uuid::Uuid,
    /// The admitted access level.
    pub access: AccessLevel,
    /// The console key the binding proof must verify against.
    pub console_pubkey: [u8; 32],
}

/// Why a grant was refused. Every variant is a refusal; the session cannot be bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingGrantError {
    /// Not decodable as a grant.
    #[error("binding grant is malformed: {0}")]
    Encoding(String),
    /// The signature does not verify under the pinned issuer key.
    #[error("binding grant signature does not verify")]
    BadSignature,
    /// Issued in the future beyond the clock-skew allowance.
    #[error("binding grant is not yet valid")]
    NotYetValid,
    /// Past its expiry.
    #[error("binding grant has expired")]
    Expired,
    /// Minted for a different device.
    #[error("binding grant is for another device")]
    WrongDevice,
}

impl BindingGrantClaims {
    /// `tag(12) || version || session(16) || device(16) || tenant(16) || technician(16) ||
    /// u32be len(access) || access || console_pubkey(32) || i64be issued || i64be expires`.
    /// `None` when the console key is not 32 bytes of hex (the control plane never signs one).
    pub fn signing_bytes(&self) -> Option<Vec<u8>> {
        let key = decode_key(&self.console_pubkey)?;
        let access = self.access.name().as_bytes();
        let mut out = Vec::with_capacity(12 + 1 + 64 + 4 + access.len() + 32 + 16);
        out.extend_from_slice(BINDING_GRANT_DOMAIN_TAG);
        out.push(BINDING_GRANT_VERSION);
        for id in [&self.session_id, &self.device_id, &self.tenant_id, &self.technician_id] {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(access.len() as u32).to_be_bytes());
        out.extend_from_slice(access);
        out.extend_from_slice(&key);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Some(out)
    }
}

fn decode_key(h: &str) -> Option<[u8; 32]> {
    if h.len() != 64 {
        return None;
    }
    hex::decode(h).ok()?.try_into().ok()
}

impl SignedBindingGrant {
    /// Decode the wire JSON the console forwards. Does not verify.
    pub fn from_json(s: &str) -> Result<Self, BindingGrantError> {
        serde_json::from_str(s).map_err(|e| BindingGrantError::Encoding(e.to_string()))
    }

    /// Signature FIRST (nothing self-claimed is trusted before it), then the validity window, then the
    /// device binding — the same order as session-policy verification.
    pub fn verify(
        &self,
        issuer: &PublicIdentity,
        now_ms: i64,
        expected_device: uuid::Uuid,
    ) -> Result<VerifiedBindingGrant, BindingGrantError> {
        let bytes = self
            .claims
            .signing_bytes()
            .ok_or_else(|| BindingGrantError::Encoding("console_pubkey is not a 32-byte hex key".into()))?;
        let sig: [u8; 64] = hex::decode(&self.sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| BindingGrantError::Encoding("signature is not 64 bytes of hex".into()))?;
        issuer.verify(&bytes, &sig).map_err(|_| BindingGrantError::BadSignature)?;
        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(BindingGrantError::NotYetValid);
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(BindingGrantError::Expired);
        }
        if self.claims.device_id != expected_device {
            return Err(BindingGrantError::WrongDevice);
        }
        Ok(VerifiedBindingGrant {
            session_id: self.claims.session_id,
            technician_id: self.claims.technician_id,
            tenant_id: self.claims.tenant_id,
            access: self.claims.access,
            console_pubkey: decode_key(&self.claims.console_pubkey).expect("checked by signing_bytes"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmt_crypto::Identity;

    /// The seed the Go golden fixtures use (control-plane/grant_test.go goldenSeedHex).
    const GOLDEN_SEED: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32,
    ];

    /// Minted by Go (TestBindingGrantGoldenVectorV1 -v). If this stops verifying, the two sides disagree on
    /// the preimage and every real grant would be refused.
    const GO_MINTED: &str = r#"{"claims":{"session_id":"22222222-2222-2222-2222-222222222222","device_id":"33333333-3333-3333-3333-333333333333","tenant_id":"44444444-4444-4444-4444-444444444444","technician_id":"11111111-1111-1111-1111-111111111111","access":"control","console_pubkey":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"dcbe7c5d96ce5e0debfff6c97cb4f1545409329c6f84e5ba6183cc82e1b002b86c5d4a8fcd898127199929a7c593b9c7cc81810fd70d3dd1c6735e7eccd76701"}"#;

    /// Go's goldenBindPreimageHex.
    const GO_PREIMAGE_HEX: &str = "524d5442494e444776310000012222222222222222222222222222222233333333333333333333333333333333444444444444444444444444444444441111111111111111111111111111111100000007636f6e74726f6cd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00000192cc09140000000192cc16cfa0";

    fn device() -> uuid::Uuid {
        "33333333-3333-3333-3333-333333333333".parse().unwrap()
    }

    #[test]
    fn verifies_go_minted_binding_grant() {
        let issuer = Identity::from_seed(&GOLDEN_SEED).public();
        let g = SignedBindingGrant::from_json(GO_MINTED).unwrap();
        assert_eq!(hex::encode(g.claims.signing_bytes().unwrap()), GO_PREIMAGE_HEX);
        let v = g.verify(&issuer, 1_730_000_000_500, device()).unwrap();
        assert_eq!(v.session_id, "22222222-2222-2222-2222-222222222222".parse::<uuid::Uuid>().unwrap());
        assert_eq!(v.access, AccessLevel::Control);
        assert_eq!(hex::encode(v.console_pubkey), g.claims.console_pubkey);
    }

    #[test]
    fn refuses_tampering_wrong_device_and_time() {
        let issuer = Identity::from_seed(&GOLDEN_SEED).public();
        let g = SignedBindingGrant::from_json(GO_MINTED).unwrap();
        let ok_now = 1_730_000_000_500;

        let mut t = g.clone();
        t.claims.console_pubkey = "ab".repeat(32);
        assert_eq!(t.verify(&issuer, ok_now, device()), Err(BindingGrantError::BadSignature));
        let mut t = g.clone();
        t.claims.access = AccessLevel::ViewOnly;
        assert_eq!(t.verify(&issuer, ok_now, device()), Err(BindingGrantError::BadSignature));
        let mut t = g.clone();
        t.claims.technician_id = uuid::Uuid::nil();
        assert_eq!(t.verify(&issuer, ok_now, device()), Err(BindingGrantError::BadSignature));

        let other = Identity::from_seed(&[9; 32]).public();
        assert_eq!(g.verify(&other, ok_now, device()), Err(BindingGrantError::BadSignature));
        assert_eq!(g.verify(&issuer, ok_now, uuid::Uuid::nil()), Err(BindingGrantError::WrongDevice));
        assert_eq!(g.verify(&issuer, 1_730_000_900_000, device()), Err(BindingGrantError::Expired));
        assert_eq!(
            g.verify(&issuer, 1_730_000_000_000 - CLOCK_SKEW_MS - 1, device()),
            Err(BindingGrantError::NotYetValid)
        );

        let mut t = g.clone();
        t.claims.console_pubkey = "short".into();
        assert!(matches!(t.verify(&issuer, ok_now, device()), Err(BindingGrantError::Encoding(_))));
        let mut t = g;
        t.sig = "00".into();
        assert!(matches!(t.verify(&issuer, ok_now, device()), Err(BindingGrantError::Encoding(_))));
    }
}
