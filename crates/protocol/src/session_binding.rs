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

    #[test]
    fn field_hex_is_exactly_32_bytes() {
        assert_eq!(decode_field_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode_field_hex(&"ab".repeat(31)), None);
        assert_eq!(decode_field_hex(&"zz".repeat(32)), None);
        assert_eq!(decode_field_hex(&"ab".repeat(33)), None);
    }
}
