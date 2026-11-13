//! Canonical signing bytes for the `RMTAGENTAUTHv1` agent-registration proof (M3).
//!
//! `register_agent` on its own is an assertion, not a proof: a device id is an identifier and
//! anyone who learns one could displace the real agent's socket. M3 closes that by making the
//! signaling server issue a random nonce and register the connection only after it verifies an
//! Ed25519 signature over the bytes built here, against the public key the control plane pinned
//! for that device id at enrollment.
//!
//! The byte layout is a **cross-language contract** with `server/signaling/agentauth.go`. Both
//! sides pin the same golden vector (see the test below and `server/signaling/agentauth_test.go`);
//! changing a value in one place without the other is a build-breaking drift, by design.
//!
//! Style matches the project's other domain-tagged preimages (`RMTGRANTv1`, `RMTTICKETv1`): a
//! fixed 16-byte tag, a `u8` version, then big-endian length-prefixed fields.

/// Domain separation tag: ASCII `RMTAGENTAUTHv1` (14 bytes) + two NUL pad bytes = 16 bytes.
/// Distinct from `RMTGRANTv1\0\0` and `RMTTICKETv1\0` at byte 3, so no preimage under one tag can
/// ever verify as another.
pub const AGENT_AUTH_DOMAIN_TAG: &[u8; 16] = b"RMTAGENTAUTHv1\0\0";

/// Preimage layout version. Bump only alongside the Go side and a new golden vector.
pub const AGENT_AUTH_VERSION: u8 = 1;

/// The nonce is exactly 32 bytes. The verifier rejects any other length, so the length prefix in
/// the preimage is a formatting convention, not a degree of freedom.
pub const AGENT_AUTH_NONCE_LEN: usize = 32;

/// Build the canonical bytes an agent signs to prove possession of its enrolled identity.
///
/// `device` and `tenant` are the **server-authoritative** values — the device id the challenge was
/// issued for and the tenant the control plane reports for it — not whatever the client declared in
/// `register_agent`. Binding all three (device, tenant, nonce) means a signature captured for one
/// device or tenant cannot be replayed for another.
///
/// No timestamp is signed: the nonce's server-side TTL is the freshness bound, and a client-chosen
/// timestamp would add a clock-skew failure mode without adding security.
pub fn agent_auth_signing_bytes(
    device: &str,
    tenant: &str,
    nonce: &[u8; AGENT_AUTH_NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(61 + device.len() + tenant.len());
    out.extend_from_slice(AGENT_AUTH_DOMAIN_TAG);
    out.push(AGENT_AUTH_VERSION);
    push_lp(&mut out, device.as_bytes());
    push_lp(&mut out, tenant.as_bytes());
    push_lp(&mut out, nonce);
    out
}

/// Append a `u32` big-endian length prefix followed by the raw field bytes.
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Decode a wire nonce (lowercase hex, 64 chars) into its 32 raw bytes. Returns `None` for
/// non-hex input or any length other than 32 bytes — the same rejection the Go verifier applies,
/// so an agent never signs a preimage the server would not have built.
pub fn decode_nonce_hex(s: &str) -> Option<[u8; AGENT_AUTH_NONCE_LEN]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // GOLDEN VECTOR — pinned identically in `server/signaling/agentauth_test.go`.
    // Do not change a value here without changing it identically there: these constants are the
    // only thing that keeps the Rust signer and the Go verifier building the same bytes.
    const SEED_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const PUBKEY_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const DEVICE_ID: &str = "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7";
    const TENANT_ID: &str = "11111111-2222-3333-4444-555555555555";
    const NONCE_HEX: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const PREIMAGE_HEX: &str = concat!(
        "524d544147454e544155544876310000010000002439663163326333612d3462",
        "35642d346536662d383039312d61326233633464356536663700000024313131",
        "31313131312d323232322d333333332d343434342d3535353535353535353535",
        "3500000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9ba",
        "bbbcbdbebf",
    );
    const SIG_HEX: &str = concat!(
        "b8ba719cba0e4301aba3d1d83b811eead5806461d7cd3633e3f27ae4cd15ecbb",
        "5480493e0eee099eb64234214f1fd874b5dafa95fc6d31ad2267788d2352f601",
    );

    fn golden_nonce() -> [u8; AGENT_AUTH_NONCE_LEN] {
        decode_nonce_hex(NONCE_HEX).expect("golden nonce is 32 hex bytes")
    }

    #[test]
    fn golden_vector_preimage_matches_the_pinned_bytes() {
        let preimage = agent_auth_signing_bytes(DEVICE_ID, TENANT_ID, &golden_nonce());
        assert_eq!(preimage.len(), 133, "preimage is 61 + 36 + 36 bytes");
        assert_eq!(hex::encode(&preimage), PREIMAGE_HEX);
    }

    #[test]
    fn golden_vector_signature_matches_the_pinned_bytes() {
        let seed: [u8; 32] = hex::decode(SEED_HEX).unwrap().try_into().unwrap();
        let id = rmt_crypto::Identity::from_seed(&seed);
        assert_eq!(id.public_hex(), PUBKEY_HEX, "seed must derive the pinned public key");
        let sig = id.sign(&agent_auth_signing_bytes(DEVICE_ID, TENANT_ID, &golden_nonce()));
        assert_eq!(hex::encode(sig), SIG_HEX);
        // And the pinned signature verifies against the pinned public key, which is exactly what
        // the Go signaling server does with these same constants.
        let sig_bytes: [u8; 64] = hex::decode(SIG_HEX).unwrap().try_into().unwrap();
        rmt_crypto::PublicIdentity::from_hex(PUBKEY_HEX)
            .unwrap()
            .verify(
                &agent_auth_signing_bytes(DEVICE_ID, TENANT_ID, &golden_nonce()),
                &sig_bytes,
            )
            .expect("pinned signature must verify");
    }

    #[test]
    fn layout_is_tag_version_then_length_prefixed_fields() {
        let bytes = agent_auth_signing_bytes("dev", "ten", &[7u8; 32]);
        assert_eq!(&bytes[..16], AGENT_AUTH_DOMAIN_TAG);
        assert_eq!(bytes[16], AGENT_AUTH_VERSION);
        assert_eq!(&bytes[17..21], &3u32.to_be_bytes());
        assert_eq!(&bytes[21..24], b"dev");
        assert_eq!(&bytes[24..28], &3u32.to_be_bytes());
        assert_eq!(&bytes[28..31], b"ten");
        assert_eq!(&bytes[31..35], &32u32.to_be_bytes());
        assert_eq!(&bytes[35..], &[7u8; 32]);
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Length prefixes (rather than separators) mean a device/tenant split cannot be shifted:
        // ("ab","c") and ("a","bc") must not collide.
        let a = agent_auth_signing_bytes("ab", "c", &[0u8; 32]);
        let b = agent_auth_signing_bytes("a", "bc", &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn every_bound_field_changes_the_preimage() {
        let base = agent_auth_signing_bytes(DEVICE_ID, TENANT_ID, &golden_nonce());
        assert_ne!(base, agent_auth_signing_bytes("other-device", TENANT_ID, &golden_nonce()));
        assert_ne!(base, agent_auth_signing_bytes(DEVICE_ID, "other-tenant", &golden_nonce()));
        assert_ne!(base, agent_auth_signing_bytes(DEVICE_ID, TENANT_ID, &[0u8; 32]));
    }

    #[test]
    fn domain_tag_cannot_collide_with_the_grant_or_ticket_tags() {
        assert_ne!(&AGENT_AUTH_DOMAIN_TAG[..], b"RMTGRANTv1\0\0\0\0\0\0");
        assert_ne!(&AGENT_AUTH_DOMAIN_TAG[..], b"RMTTICKETv1\0\0\0\0\0");
        assert_eq!(hex::encode(AGENT_AUTH_DOMAIN_TAG), "524d544147454e544155544876310000");
    }

    #[test]
    fn nonce_decoding_rejects_wrong_lengths_and_non_hex() {
        assert!(decode_nonce_hex(NONCE_HEX).is_some());
        assert!(decode_nonce_hex(&NONCE_HEX[..62]).is_none(), "31 bytes must be rejected");
        assert!(decode_nonce_hex(&format!("{NONCE_HEX}ff")).is_none(), "33 bytes must be rejected");
        assert!(decode_nonce_hex("zz").is_none(), "non-hex must be rejected");
        assert!(decode_nonce_hex("").is_none(), "empty must be rejected");
    }

    #[test]
    fn nonce_hex_is_case_insensitive_on_decode() {
        assert_eq!(
            decode_nonce_hex(NONCE_HEX).unwrap(),
            decode_nonce_hex(&NONCE_HEX.to_uppercase()).unwrap()
        );
    }
}
