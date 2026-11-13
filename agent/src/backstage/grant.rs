//! Cryptographically-signed, capability-scoped, expiring backstage grants (H1).
//!
//! M5 self-issued a full/demo [`Grant`](crate::backstage::rbac::Grant) unconditionally — the
//! biggest security shortcut in the backstage-over-transport path. H1 replaces that with a grant
//! the **control-plane mints and signs** with its long-term Ed25519 identity, scoped to exactly the
//! capabilities the authenticated technician holds for this machine and valid only for a short
//! window. The agent pins the issuer's public key and verifies the signature (and the validity
//! window) before it will construct a [`Dispatcher`](crate::backstage::Dispatcher) — so a
//! compromised or absent control-plane can no longer hand itself full backstage access.
//!
//! # Wire shape
//!
//! Two nested structs, JSON on the wire:
//!
//! * [`GrantClaims`] — the signed payload: the `Grant` itself plus an issued-at / expires-at pair
//!   (Unix milliseconds).
//! * [`SignedGrant`] — the claims plus a hex-encoded 64-byte Ed25519 signature over the claims.
//!
//! ```json
//! {
//!   "claims": {
//!     "grant": { "technician_id": "…", "session_id": "…", "machine_id": "…",
//!                "capabilities": ["system_info_read", "process_list"] },
//!     "issued_at_ms": 1730000000000,
//!     "expires_at_ms": 1730000900000
//!   },
//!   "sig": "<128 hex chars>"
//! }
//! ```
//!
//! # Canonical signing bytes (H1b)
//!
//! The signature covers the **canonical v1** binary encoding of the claims
//! ([`GrantClaims::signing_bytes`]), NOT `serde_json::to_vec`. The canonical form is a
//! language-agnostic, big-endian, length-prefixed concatenation of the claim fields behind a
//! domain-separation tag (see [`crate::backstage::canonical`]) that Rust and Go build byte-for-byte
//! identically — so the Go control-plane can mint grants a Rust agent verifies. The `SignedGrant`
//! *wire shape* is unchanged: the claims still travel as JSON (for transport/readability) and the
//! signature is still a hex string; only the **signed preimage** changed from JSON to canonical
//! bytes. Because JSON formatting no longer feeds the signature, Go's `encoding/json` quirks are
//! irrelevant to verification.
//!
//! Cross-language agreement is proven by shared golden vectors: `tests::golden_vector_v1` here and
//! `TestGoldenVectorV1` in `control-plane/grant_test.go` assert the SAME fixed fixture produces the
//! SAME canonical-bytes hex AND the SAME Ed25519 signature hex, and `tests::verifies_go_minted_grant`
//! feeds a Go-minted `SignedGrant` JSON straight into [`SignedGrant::verify`].

use serde::{Deserialize, Serialize};

use rmt_crypto::{Identity, PublicIdentity};

use crate::backstage::canonical::{capability_name, CanonicalWriter};
use crate::backstage::rbac::Grant;

/// Clock skew tolerated on the not-yet-valid check, so a small issuer/agent clock difference does
/// not spuriously reject a fresh grant. Deliberately one-sided and small (the expiry check is
/// exact — an expired grant is always rejected).
pub const CLOCK_SKEW_MS: i64 = 30_000;

/// The signed payload: the capability [`Grant`] plus its validity window (Unix milliseconds).
///
/// Its [`signing_bytes`](GrantClaims::signing_bytes) are exactly what the issuer signs (see
/// [`crate::backstage::canonical`]). Keep the field set + order stable — changing it changes the
/// signing bytes and breaks the cross-language golden vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantClaims {
    /// The capability grant the agent will enforce once this claim verifies.
    pub grant: Grant,
    /// When the control-plane minted this grant (Unix ms). `now_ms` must be at or after this
    /// (minus [`CLOCK_SKEW_MS`]).
    pub issued_at_ms: i64,
    /// When this grant stops being valid (Unix ms, exclusive). `now_ms` must be strictly before it.
    pub expires_at_ms: i64,
}

impl GrantClaims {
    /// The **canonical v1** signing bytes for these claims: a language-agnostic, big-endian,
    /// length-prefixed encoding behind the [`DOMAIN_TAG`](crate::backstage::canonical::DOMAIN_TAG)
    /// (see [`crate::backstage::canonical`] for the exact layout). This — not the JSON — is what the
    /// issuer signs and the agent verifies, so Rust and Go produce identical signing input for the
    /// same claims. The Go control-plane's `signingBytes` is a byte-for-byte port.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.tag()
            .raw16(self.grant.technician_id.as_bytes())
            .raw16(self.grant.session_id.as_bytes())
            .raw16(self.grant.machine_id.as_bytes())
            .u32(self.grant.capabilities.len() as u32);
        for cap in &self.grant.capabilities {
            w.lp_str(capability_name(*cap));
        }
        w.i64(self.issued_at_ms).i64(self.expires_at_ms);
        w.into_bytes()
    }

    /// Sign these claims with the issuer's long-term identity, producing a [`SignedGrant`].
    ///
    /// The signature is over [`signing_bytes`](Self::signing_bytes) — the canonical v1 preimage,
    /// which Go builds identically, so a Go-minted grant verifies here and vice-versa.
    pub fn sign(&self, issuer: &Identity) -> SignedGrant {
        let sig = issuer.sign(&self.signing_bytes());
        SignedGrant { claims: self.clone(), sig: hex::encode(sig) }
    }
}

/// A [`GrantClaims`] plus the issuer's Ed25519 signature over it (hex-encoded, 128 chars).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    /// The signed claims.
    pub claims: GrantClaims,
    /// Hex-encoded 64-byte Ed25519 signature over the claims' canonical v1
    /// [`signing_bytes`](GrantClaims::signing_bytes).
    pub sig: String,
}

impl SignedGrant {
    /// Encode this signed grant to its JSON wire string (carried opaquely in the Control channel's
    /// `InstallGrant` message so `rmt-agent-core` need not depend on `rmt-agent`).
    pub fn to_json(&self) -> Result<String, GrantError> {
        serde_json::to_string(self).map_err(|e| GrantError::Encoding(e.to_string()))
    }

    /// Decode a signed grant from its JSON wire string. Does **not** verify — call [`verify`].
    pub fn from_json(s: &str) -> Result<Self, GrantError> {
        serde_json::from_str(s).map_err(|e| GrantError::Encoding(e.to_string()))
    }

    /// Verify the signature against the pinned `issuer`, check the validity window against `now_ms`,
    /// and bind the grant to this device by requiring `self.claims.grant.machine_id ==
    /// expected_machine_id`. Returns the enclosed [`Grant`] only if all three pass.
    ///
    /// Order: signature first (a forged/tampered grant is rejected before its self-claimed times or
    /// machine are even trusted), then not-yet-valid (with [`CLOCK_SKEW_MS`] tolerance), then expiry,
    /// then the device binding (H3). The machine check is last so an unsigned/expired grant is
    /// rejected before its machine claim is ever considered — the `machine_id` is already inside the
    /// signed canonical preimage, so this is a check on an authenticated field, not a preimage change.
    pub fn verify(
        &self,
        issuer: &PublicIdentity,
        now_ms: i64,
        expected_machine_id: uuid::Uuid,
    ) -> Result<Grant, GrantError> {
        let bytes = self.claims.signing_bytes();
        let sig_bytes = hex::decode(&self.sig).map_err(|_| GrantError::Encoding("signature is not hex".into()))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| GrantError::Encoding("signature is not 64 bytes".into()))?;

        issuer.verify(&bytes, &sig).map_err(|_| GrantError::BadSignature)?;

        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(GrantError::NotYetValid);
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(GrantError::Expired);
        }
        if self.claims.grant.machine_id != expected_machine_id {
            return Err(GrantError::WrongMachine {
                expected: expected_machine_id,
                found: self.claims.grant.machine_id,
            });
        }
        Ok(self.claims.grant.clone())
    }
}

/// Why a [`SignedGrant`] was rejected. Distinct variants so the agent can log/report precisely and
/// the control-plane can distinguish a clock problem from a key problem.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("grant signature is invalid (wrong issuer key or tampered claims)")]
    BadSignature,
    #[error("grant has expired")]
    Expired,
    #[error("grant is not yet valid")]
    NotYetValid,
    #[error("grant is for a different machine (expected {expected}, grant carries {found})")]
    WrongMachine { expected: uuid::Uuid, found: uuid::Uuid },
    #[error("malformed signed grant: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backstage::rbac::Capability;

    fn claims(now: i64, ttl: i64) -> GrantClaims {
        GrantClaims {
            grant: Grant {
                technician_id: uuid::Uuid::nil(),
                session_id: uuid::Uuid::nil(),
                machine_id: uuid::Uuid::nil(),
                capabilities: vec![Capability::SystemInfoRead, Capability::ProcessList],
            },
            issued_at_ms: now,
            expires_at_ms: now + ttl,
        }
    }

    #[test]
    fn sign_then_verify_round_trip_returns_the_grant() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let signed = claims(now, 60_000).sign(&issuer);
        // Survives a JSON round-trip (as it would crossing the Control channel).
        let json = signed.to_json().unwrap();
        let back = SignedGrant::from_json(&json).unwrap();

        // Bound to the grant's own machine_id (nil here) — device binding must not reject a grant
        // minted for this very device.
        let grant = back
            .verify(&issuer.public(), now + 5_000, uuid::Uuid::nil())
            .expect("valid grant verifies");
        assert!(grant.allows(Capability::SystemInfoRead));
        assert!(grant.allows(Capability::ProcessList));
        assert!(!grant.allows(Capability::RegistryWrite));
    }

    #[test]
    fn wrong_machine_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let machine_x = uuid::Uuid::from_u128(0x0A);
        let machine_y = uuid::Uuid::from_u128(0x0B);
        let mut c = claims(now, 60_000);
        c.grant.machine_id = machine_x;
        let signed = c.sign(&issuer);
        // Signature + window are fine; the grant is minted for machine X but verified for machine Y.
        assert!(matches!(
            signed.verify(&issuer.public(), now + 5_000, machine_y),
            Err(GrantError::WrongMachine { expected, found })
                if expected == machine_y && found == machine_x
        ));
        // And it DOES verify when the expected machine matches.
        assert!(signed.verify(&issuer.public(), now + 5_000, machine_x).is_ok());
    }

    #[test]
    fn tampered_claims_are_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let mut signed = claims(now, 60_000).sign(&issuer);
        // Attacker widens the capability set after signing.
        signed.claims.grant.capabilities.push(Capability::ShellAsSystem);
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::nil()),
            Err(GrantError::BadSignature)
        ));
    }

    #[test]
    fn wrong_issuer_key_is_rejected() {
        let issuer = Identity::generate();
        let attacker = Identity::generate();
        let now = 1_000_000;
        let signed = claims(now, 60_000).sign(&issuer);
        assert!(matches!(
            signed.verify(&attacker.public(), now, uuid::Uuid::nil()),
            Err(GrantError::BadSignature)
        ));
    }

    #[test]
    fn expired_grant_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        let signed = claims(now, 10_000).sign(&issuer);
        // Well past expiry.
        assert!(matches!(
            signed.verify(&issuer.public(), now + 20_000, uuid::Uuid::nil()),
            Err(GrantError::Expired)
        ));
    }

    #[test]
    fn not_yet_valid_grant_is_rejected() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        // Issued far in the future (beyond the skew tolerance).
        let signed = claims(now + 10 * CLOCK_SKEW_MS, 60_000).sign(&issuer);
        assert!(matches!(
            signed.verify(&issuer.public(), now, uuid::Uuid::nil()),
            Err(GrantError::NotYetValid)
        ));
    }

    #[test]
    fn small_clock_skew_is_tolerated_on_issue() {
        let issuer = Identity::generate();
        let now = 1_000_000;
        // Issued a few seconds "ahead" of the verifier's clock — within CLOCK_SKEW_MS, so accepted.
        let signed = claims(now + 5_000, 60_000).sign(&issuer);
        assert!(signed.verify(&issuer.public(), now, uuid::Uuid::nil()).is_ok());
    }

    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE VECTORS (H1b) — the proof Rust and Go agree byte-for-byte.
    //
    // The SAME fixed fixture is hardcoded in control-plane/grant_test.go. If the two languages'
    // canonical encoders or Ed25519 signing ever diverge, one side's hex stops matching these
    // constants. DO NOT change a value here without changing it identically in the Go test.
    //
    //   seed (32 bytes, hex):
    //     0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
    //   issuer public key (hex, derived from the seed):
    //     GOLDEN_PUBKEY_HEX below
    //   technician_id: 11111111-1111-1111-1111-111111111111
    //   session_id:    22222222-2222-2222-2222-222222222222
    //   machine_id:    33333333-3333-3333-3333-333333333333
    //   capabilities:  [system_info_read, process_list, shell_as_system]   (slice order matters)
    //   issued_at_ms:  1730000000000
    //   expires_at_ms: 1730000900000
    //
    //   => canonical signing-bytes hex : GOLDEN_PREIMAGE_HEX
    //   => Ed25519 signature hex       : GOLDEN_SIG_HEX
    // =====================================================================================

    const GOLDEN_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const GOLDEN_PUBKEY_HEX: &str =
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const GOLDEN_PREIMAGE_HEX: &str = "524d544752414e5476310000111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333000000030000001073797374656d5f696e666f5f726561640000000c70726f636573735f6c6973740000000f7368656c6c5f61735f73797374656d00000192cc09140000000192cc16cfa0";
    const GOLDEN_SIG_HEX: &str = "4b299bb9963a14c9f62b8349139ba5eb29c6d3113b583f9e87b5a583548001c6d68679d5039a8dae95ebdfba27925c8808f451ddbf52d416e9a14578ac7d9800";

    fn golden_claims() -> GrantClaims {
        GrantClaims {
            grant: Grant {
                technician_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
                session_id: "22222222-2222-2222-2222-222222222222".parse().unwrap(),
                machine_id: "33333333-3333-3333-3333-333333333333".parse().unwrap(),
                capabilities: vec![
                    Capability::SystemInfoRead,
                    Capability::ProcessList,
                    Capability::ShellAsSystem,
                ],
            },
            issued_at_ms: 1_730_000_000_000,
            expires_at_ms: 1_730_000_900_000,
        }
    }

    #[test]
    fn golden_vector_v1() {
        let issuer = Identity::from_seed(&GOLDEN_SEED);
        let claims = golden_claims();
        let preimage_hex = hex::encode(claims.signing_bytes());
        let signed = claims.sign(&issuer);

        // Printed so the constants can be captured on first run (cargo test -- --nocapture).
        eprintln!("GOLDEN_PUBKEY_HEX   = {}", issuer.public_hex());
        eprintln!("GOLDEN_PREIMAGE_HEX = {preimage_hex}");
        eprintln!("GOLDEN_SIG_HEX      = {}", signed.sig);

        assert_eq!(issuer.public_hex(), GOLDEN_PUBKEY_HEX, "pubkey drift");
        assert_eq!(preimage_hex, GOLDEN_PREIMAGE_HEX, "canonical preimage drift");
        assert_eq!(signed.sig, GOLDEN_SIG_HEX, "signature drift");
    }

    /// Direct Go-mint → Rust-verify interop: a `SignedGrant` JSON produced by the Go `GrantIssuer`
    /// for the golden fixture (pasted verbatim from `control-plane/grant_test.go`'s mint output)
    /// verifies here and yields the expected caps. Proves cross-language mint→verify, not just that
    /// both sides compute the same hex.
    #[test]
    fn verifies_go_minted_grant() {
        const GO_MINTED_JSON: &str = r#"{"claims":{"grant":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","capabilities":["system_info_read","process_list","shell_as_system"]},"issued_at_ms":1730000000000,"expires_at_ms":1730000900000},"sig":"4b299bb9963a14c9f62b8349139ba5eb29c6d3113b583f9e87b5a583548001c6d68679d5039a8dae95ebdfba27925c8808f451ddbf52d416e9a14578ac7d9800"}"#;
        let issuer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedGrant::from_json(GO_MINTED_JSON).expect("Go-minted JSON parses");
        // now_ms inside the fixture's validity window; expected machine is the fixture's machine_id.
        let expected_machine = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let grant = signed
            .verify(&issuer, 1_730_000_100_000, expected_machine)
            .expect("Go-minted grant verifies in Rust");
        assert!(grant.allows(Capability::SystemInfoRead));
        assert!(grant.allows(Capability::ProcessList));
        assert!(grant.allows(Capability::ShellAsSystem));
        assert!(!grant.allows(Capability::RegistryWrite));
    }
}
