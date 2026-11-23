//! Canonical transcript bytes for the `RMTSESSBINDv1` session-binding proofs (docs/69 §3.2).
//!
//! Both ends of a session sign the SAME transcript, differing only in the role byte: the agent with its
//! enrolled device key (role 1), the console with the ephemeral key the control plane bound into the
//! session's `RMTBINDGv1` grant (role 2). Each end fills both certificate fingerprints from ITS OWN live
//! DTLS association, so under a man in the middle the two ends hold different transcripts and neither
//! proof verifies on the other side.
//!
//! The byte layout is a cross-language contract with the viewer (`web/viewer/src/lib/session_binding.ts`).
//! Both pin the same golden vector; changing a value in one place without the other breaks the build.

/// Domain separation tag: ASCII `RMTSESSBINDv1` (13 bytes) + three NUL bytes = 16 bytes. Differs from
/// `RMTAGENTAUTHv1\0\0` at byte 3, so a registration proof can never verify as a binding proof.
pub const SESSION_BIND_DOMAIN_TAG: &[u8; 16] = b"RMTSESSBINDv1\0\0\0";

/// Transcript layout version.
pub const SESSION_BIND_VERSION: u8 = 1;

/// Role byte for the agent's proof.
pub const ROLE_AGENT: u8 = 1;
/// Role byte for the console's proof.
pub const ROLE_CONSOLE: u8 = 2;

/// Length of every binary field after the session id: SHA-256 fingerprints and nonces.
pub const BIND_FIELD_LEN: usize = 32;

/// The transcript inputs. Every field is fixed-length, so the preimage needs no length prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindTranscript {
    /// The control-plane session id as raw UUID bytes (from the verified grant on the agent, from the
    /// session response on the console). Never signaling's own session id.
    pub session_id: [u8; 16],
    /// SHA-256 of the DER certificate the AGENT presented on this association.
    pub agent_cert_sha256: [u8; BIND_FIELD_LEN],
    /// SHA-256 of the DER certificate the CONSOLE presented on this association.
    pub console_cert_sha256: [u8; BIND_FIELD_LEN],
    /// The agent's fresh nonce for this exchange.
    pub agent_nonce: [u8; BIND_FIELD_LEN],
    /// The console's fresh nonce for this exchange.
    pub console_nonce: [u8; BIND_FIELD_LEN],
}

impl BindTranscript {
    /// The canonical bytes signed for `role` ([`ROLE_AGENT`] or [`ROLE_CONSOLE`]):
    /// `tag(16) || version || session(16) || agent_fp(32) || console_fp(32) || agent_nonce(32) ||
    /// console_nonce(32) || role`.
    pub fn signing_bytes(&self, role: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 1 + 16 + 4 * BIND_FIELD_LEN + 1);
        out.extend_from_slice(SESSION_BIND_DOMAIN_TAG);
        out.push(SESSION_BIND_VERSION);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.agent_cert_sha256);
        out.extend_from_slice(&self.console_cert_sha256);
        out.extend_from_slice(&self.agent_nonce);
        out.extend_from_slice(&self.console_nonce);
        out.push(role);
        out
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Binding v2 (docs/69 §6.2): the console COMMITS to its nonce in BindStart and reveals it only in its proof, so
// neither side can pick its contribution after seeing the other's. That is what makes a short comparison code
// sound: v1's nonces let a man in the middle grind a 6-digit code (§6.1).
// ---------------------------------------------------------------------------------------------------------------

/// v2 signing domain: ASCII `RMTSESSBINDv2` + one NUL (14 bytes), as Codex's spec states.
pub const SESSION_BIND_V2_TAG: &[u8; 14] = b"RMTSESSBINDv2\0";
/// Commitment domain: `RMTBIND-COMMIT-v2` + NUL.
pub const BIND_COMMIT_V2_TAG: &[u8; 18] = b"RMTBIND-COMMIT-v2\0";
/// Comparison-code domain: `RMTSASv2` + NUL.
pub const SAS_V2_TAG: &[u8; 9] = b"RMTSASv2\0";
/// v2 layout version byte (the first byte of `common`).
pub const SESSION_BIND_V2_VERSION: u8 = 2;

/// `SHA-256("RMTBIND-COMMIT-v2\0" || console_nonce)`: what the console sends in place of its nonce.
pub fn commit_v2(console_nonce: &[u8; BIND_FIELD_LEN]) -> [u8; BIND_FIELD_LEN] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(BIND_COMMIT_V2_TAG);
    h.update(console_nonce);
    h.finalize().into()
}

/// The v2 exchange's fixed fields. `commitment` replaces v1's console nonce in what the agent signs; the revealed
/// nonce is appended only to the console's proof and to the code input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindTranscriptV2 {
    /// The control-plane session id (raw UUID bytes).
    pub session_id: [u8; 16],
    /// SHA-256 of the agent's DER certificate on this association.
    pub agent_cert_sha256: [u8; BIND_FIELD_LEN],
    /// SHA-256 of the console's DER certificate on this association.
    pub console_cert_sha256: [u8; BIND_FIELD_LEN],
    /// The agent's enrolled Ed25519 public key (raw 32 bytes).
    pub device_pubkey: [u8; BIND_FIELD_LEN],
    /// The console's ephemeral Ed25519 public key from the grant (raw 32 bytes).
    pub console_pubkey: [u8; BIND_FIELD_LEN],
    /// `commit_v2(console_nonce)` as received in BindStartV2.
    pub commitment: [u8; BIND_FIELD_LEN],
    /// The agent's fresh nonce.
    pub agent_nonce: [u8; BIND_FIELD_LEN],
}

impl BindTranscriptV2 {
    /// `u8(2) || session(16) || agent_fp || console_fp || device_pk || console_pk || commitment || agent_nonce`.
    pub fn common(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 16 + 6 * BIND_FIELD_LEN);
        out.push(SESSION_BIND_V2_VERSION);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.agent_cert_sha256);
        out.extend_from_slice(&self.console_cert_sha256);
        out.extend_from_slice(&self.device_pubkey);
        out.extend_from_slice(&self.console_pubkey);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.agent_nonce);
        out
    }

    /// What the agent signs: `tag || common || ROLE_AGENT`.
    pub fn agent_signing_bytes(&self) -> Vec<u8> {
        let mut out = SESSION_BIND_V2_TAG.to_vec();
        out.extend_from_slice(&self.common());
        out.push(ROLE_AGENT);
        out
    }

    /// What the console signs: `tag || common || ROLE_CONSOLE || console_nonce` (the opening is bound).
    pub fn console_signing_bytes(&self, console_nonce: &[u8; BIND_FIELD_LEN]) -> Vec<u8> {
        let mut out = SESSION_BIND_V2_TAG.to_vec();
        out.extend_from_slice(&self.common());
        out.push(ROLE_CONSOLE);
        out.extend_from_slice(console_nonce);
        out
    }

    /// The six-digit comparison code: `u32_be(SHA-256(SAS tag || common || console_nonce)[0..4]) mod 1_000_000`.
    /// Only meaningful once `console_nonce` opens `commitment` (the caller checks that first).
    pub fn comparison_code(&self, console_nonce: &[u8; BIND_FIELD_LEN]) -> u32 {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(SAS_V2_TAG);
        h.update(self.common());
        h.update(console_nonce);
        let d: [u8; 32] = h.finalize().into();
        u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000
    }
}

/// Render a code as `"123 456"` (zero-padded), the form both screens show.
pub fn format_comparison_code(code: u32) -> String {
    let s = format!("{:06}", code % 1_000_000);
    format!("{} {}", &s[..3], &s[3..])
}

/// Decode a 32-byte field from exactly 64 hex characters; `None` for anything else.
pub fn decode_field_hex(s: &str) -> Option<[u8; BIND_FIELD_LEN]> {
    if s.len() != 2 * BIND_FIELD_LEN {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // GOLDEN VECTOR, pinned identically in web/viewer/src/lib/session_binding.test.ts.
    const PREIMAGE_ROLE_AGENT_HEX: &str = concat!(
        "524d545345535342494e44763100000001",
        "22222222222222222222222222222222",
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
        "01",
    );

    pub(crate) fn golden() -> BindTranscript {
        BindTranscript {
            session_id: [0x22; 16],
            agent_cert_sha256: [0xa1; 32],
            console_cert_sha256: [0xb2; 32],
            agent_nonce: [0xc3; 32],
            console_nonce: [0xd4; 32],
        }
    }

    #[test]
    fn golden_vector_v1() {
        let want = PREIMAGE_ROLE_AGENT_HEX;
        assert_eq!(hex::encode(golden().signing_bytes(ROLE_AGENT)), want);
        // The console's preimage differs ONLY in the final role byte.
        let console = golden().signing_bytes(ROLE_CONSOLE);
        assert_eq!(hex::encode(&console[..console.len() - 1]), want[..want.len() - 2]);
        assert_eq!(*console.last().unwrap(), ROLE_CONSOLE);
    }

    #[test]
    fn every_field_changes_the_bytes() {
        let base = golden().signing_bytes(ROLE_AGENT);
        let mut variants = vec![];
        let mut t = golden();
        t.session_id[0] ^= 1;
        variants.push(t);
        let mut t = golden();
        t.agent_cert_sha256[31] ^= 1;
        variants.push(t);
        let mut t = golden();
        t.console_cert_sha256[0] ^= 1;
        variants.push(t);
        let mut t = golden();
        t.agent_nonce[5] ^= 1;
        variants.push(t);
        let mut t = golden();
        t.console_nonce[9] ^= 1;
        variants.push(t);
        for v in variants {
            assert_ne!(v.signing_bytes(ROLE_AGENT), base);
        }
        // Swapping the two fingerprints is a different transcript (the order is part of the contract).
        let mut t = golden();
        std::mem::swap(&mut t.agent_cert_sha256, &mut t.console_cert_sha256);
        assert_ne!(t.signing_bytes(ROLE_AGENT), base);
    }

    #[test]
    fn tag_is_distinct_from_agent_auth() {
        assert_eq!(SESSION_BIND_DOMAIN_TAG.len(), 16);
        assert_ne!(&SESSION_BIND_DOMAIN_TAG[..], &crate::agent_auth::AGENT_AUTH_DOMAIN_TAG[..]);
    }

    const GOLDEN_V2_COMMIT_HEX: &str = "8b105150116754b88aa06c646a02d57c5c63f07aa7d07b885fc4dfd88ef891cd";
    const GOLDEN_V2_CODE: u32 = 697670;

    pub(crate) fn golden_v2() -> BindTranscriptV2 {
        BindTranscriptV2 {
            session_id: [0x22; 16],
            agent_cert_sha256: [0xa1; 32],
            console_cert_sha256: [0xb2; 32],
            device_pubkey: [0xe5; 32],
            console_pubkey: [0xf6; 32],
            commitment: commit_v2(&[0xd4; 32]),
            agent_nonce: [0xc3; 32],
        }
    }

    #[test]
    fn v2_layout_and_domains() {
        let t = golden_v2();
        let common = t.common();
        assert_eq!(common.len(), 1 + 16 + 6 * 32);
        assert_eq!(common[0], 2);
        let a = t.agent_signing_bytes();
        assert!(a.starts_with(SESSION_BIND_V2_TAG) && *a.last().unwrap() == ROLE_AGENT);
        let c = t.console_signing_bytes(&[0xd4; 32]);
        assert_eq!(&c[..SESSION_BIND_V2_TAG.len() + common.len()], &a[..a.len() - 1]);
        assert_eq!(c[SESSION_BIND_V2_TAG.len() + common.len()], ROLE_CONSOLE);
        assert_eq!(&c[c.len() - 32..], &[0xd4; 32]);
        // v2 never verifies as v1 and vice versa: the tags differ from byte 12.
        assert_ne!(&SESSION_BIND_V2_TAG[..], &SESSION_BIND_DOMAIN_TAG[..14]);
    }

    #[test]
    fn v2_golden_vector() {
        // GOLDEN VALUES, pinned identically in web/viewer/src/lib/session_binding.test.ts.
        assert_eq!(hex::encode(commit_v2(&[0xd4; 32])), GOLDEN_V2_COMMIT_HEX);
        assert_eq!(golden_v2().comparison_code(&[0xd4; 32]), GOLDEN_V2_CODE);
        assert_eq!(format_comparison_code(GOLDEN_V2_CODE).len(), 7);
        assert_eq!(format_comparison_code(42), "000 042");
    }

    #[test]
    fn every_v2_field_changes_the_code() {
        let base = golden_v2().comparison_code(&[0xd4; 32]);
        let mut changed = 0;
        for i in 0..7 {
            let mut t = golden_v2();
            match i {
                0 => t.session_id[0] ^= 1,
                1 => t.agent_cert_sha256[0] ^= 1,
                2 => t.console_cert_sha256[0] ^= 1,
                3 => t.device_pubkey[0] ^= 1,
                4 => t.console_pubkey[0] ^= 1,
                5 => t.commitment[0] ^= 1,
                _ => t.agent_nonce[0] ^= 1,
            }
            if t.comparison_code(&[0xd4; 32]) != base {
                changed += 1;
            }
        }
        // A 6-digit projection can collide by chance (1 in 10^6 per field); all 7 changing is the expectation.
        assert_eq!(changed, 7);
        assert_ne!(golden_v2().comparison_code(&[0xd5; 32]), base);
    }

    #[test]
    fn field_hex_is_exactly_32_bytes() {
        assert_eq!(decode_field_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode_field_hex(&"ab".repeat(31)), None);
        assert_eq!(decode_field_hex(&"zz".repeat(32)), None);
        assert_eq!(decode_field_hex(&"ab".repeat(33)), None);
    }
}
