//! The ONE rustls client configuration every agent HTTPS/WSS dial uses: enrollment, attended-support
//! redeem, the managed-installer bundle download, and the signaling WebSocket.
//!
//! Trust is the **union** of two root sets:
//!
//! * the OS store (`rustls-native-certs`), so a self-hosted deployment whose control plane chains to a
//!   private CA installed in `LocalMachine\Root` keeps working (docs/07, proven on LAB-VM); and
//! * Mozilla's bundled roots (`webpki-roots`), so a public deployment works on a machine whose store
//!   does not (yet) hold the public root.
//!
//! The second set addresses a trust-store gap consistent with the reported fresh-machine failure
//! (MSI-Night, 2026-10-09): enrollment failed before HTTP. Windows ships with a minimal
//! root store and installs further roots (ISRG Root X1, which `main.deskrally.com` chains to) only ON
//! DEMAND, when a CryptoAPI chain build asks for one. rustls never builds a chain through CryptoAPI —
//! `rustls-native-certs` only ENUMERATES the store — so on such a machine the agent saw no ISRG root
//! available to trust that server. The guest's CAPI2 log showed the root arriving 98 s after the
//! failed enrollment. Confirming the complete installer path still requires clean-VM acceptance.
//!
//! Verification is unchanged and fail-closed: rustls' WebPKI verifier checks the chain, validity and
//! the server NAME against this store. There is no "accept invalid" path anywhere. The store is
//! rebuilt on every call (never cached), so a private CA installed while the agent runs is picked up
//! by the next dial, exactly as before.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// Mozilla's bundled roots plus `native`. Native certificates that fail to parse are skipped (and
/// counted in a debug log); they cannot remove the bundled roots.
pub fn root_store_from(native: impl IntoIterator<Item = CertificateDer<'static>>) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let (added, ignored) = store.add_parsable_certificates(native);
    tracing::debug!(native_added = added, native_ignored = ignored, total = store.len(), "tls_trust: root store built");
    store
}

/// A client config trusting [`root_store_from`]`(native)`. Split from [`client_config`] so tests can
/// supply the "OS store" — including an empty one, which is the fresh-machine case.
pub fn config_from_native(
    native: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<ClientConfig, String> {
    Ok(ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls_trust: could not select TLS protocol versions: {e}"))?
        .with_root_certificates(root_store_from(native))
        .with_no_client_auth())
}

/// The production config: this machine's OS store plus the bundled roots.
///
/// A partially unreadable OS store is logged and tolerated rather than fatal — the bundled roots still
/// apply, and any certificate that did load still counts. (tokio-tungstenite's own native-roots loader
/// aborted the whole connect on any store error.)
pub fn client_config() -> Result<ClientConfig, String> {
    let native = rustls_native_certs::load_native_certs();
    // Counts only: an error's text can name a store path or certificate, and neither belongs in a log.
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            loaded = native.certs.len(),
            "tls_trust: some OS trust-store certificates could not be loaded; bundled public roots still apply"
        );
    }
    config_from_native(native.certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{CertificateError, ClientConnection, ServerConfig, ServerConnection};

    /// SHA-256 of ISRG Root X1's SubjectPublicKeyInfo — Let's Encrypt's published key pin
    /// (`C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=`). It was cross-checked on 2026-10-11 against the
    /// copy Windows had installed in `LocalMachine\Root` (thumbprint CABD2A79…A5E8), so it is a
    /// source independent of webpki-roots: the test proves the bundled anchor is THE key
    /// `main.deskrally.com` chains to, not merely something whose name says so.
    const ISRG_ROOT_X1_SPKI_SHA256: [u8; 32] = [
        0x0b, 0x9f, 0xa5, 0xa5, 0x9e, 0xed, 0x71, 0x5c, 0x26, 0xc1, 0x02, 0x0c, 0x71, 0x1b, 0x4f, 0x6e,
        0xc4, 0x2d, 0x58, 0xb0, 0x01, 0x5e, 0x14, 0x33, 0x7a, 0x39, 0xda, 0xd3, 0x01, 0xc5, 0xaf, 0xc3,
    ];

    /// webpki stores an anchor's SPKI as the SEQUENCE's CONTENTS; a pin hashes the whole DER SEQUENCE.
    fn spki_sha256(spki_contents: &[u8]) -> [u8; 32] {
        let n = spki_contents.len();
        let mut der = vec![0x30];
        match n {
            0..=0x7f => der.push(n as u8),
            0x80..=0xff => der.extend([0x81, n as u8]),
            _ => der.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        der.extend_from_slice(spki_contents);
        ring::digest::digest(&ring::digest::SHA256, &der).as_ref().try_into().unwrap()
    }

    fn trusts_isrg_root_x1(store: &RootCertStore) -> bool {
        store.roots.iter().any(|ta| spki_sha256(ta.subject_public_key_info.as_ref()) == ISRG_ROOT_X1_SPKI_SHA256)
    }

    /// A throwaway private CA and a leaf for `dns_name` it signed (the self-hosted deployment case).
    struct PrivatePki {
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        leaf_key: Vec<u8>,
    }

    fn private_pki(dns_name: &str) -> PrivatePki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "DeskRally tls_trust test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![dns_name.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        PrivatePki { ca: ca.der().clone(), leaf: leaf.der().clone(), leaf_key: leaf_key.serialize_der() }
    }

    /// A full in-memory handshake: `client` dials `server_name`; the server presents `pki.leaf`.
    /// Returns the CLIENT's verdict — the side whose trust decision is under test.
    fn handshake(client: ClientConfig, server_name: &str, pki: &PrivatePki) -> Result<(), rustls::Error> {
        let server_cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![pki.leaf.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_key.clone())),
            )
            .unwrap();
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let mut c = ClientConnection::new(Arc::new(client), name)?;
        let mut s = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        for _ in 0..16 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd).unwrap();
            }
            // A server-side error here would only be the client's alert; the client verdict is below.
            let _ = s.process_new_packets();
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                c.read_tls(&mut rd).unwrap();
            }
            c.process_new_packets()?;
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake neither completed nor failed in 16 flights");
    }

    /// THE REGRESSION: a fresh machine's OS store has no ISRG root. The union must still trust it.
    /// Negative control: the empty native set alone (the old behavior's store) does NOT contain it,
    /// so the assertion can fail.
    #[test]
    fn empty_os_store_still_trusts_the_public_root_the_control_plane_chains_to() {
        assert!(!trusts_isrg_root_x1(&RootCertStore::empty()), "control: the probe must be able to say no");
        let store = root_store_from(Vec::new());
        assert!(trusts_isrg_root_x1(&store), "ISRG Root X1's KEY is missing with an empty OS store");
        assert_eq!(store.len(), webpki_roots::TLS_SERVER_ROOTS.len(), "empty OS store adds nothing, removes nothing");
    }

    /// Private-CA support is preserved: a CA present only in the OS store is trusted.
    #[test]
    fn a_private_ca_from_the_os_store_is_trusted() {
        let pki = private_pki("cp.selfhosted.test");
        let store = root_store_from(vec![pki.ca.clone()]);
        assert_eq!(store.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 1);
        handshake(config_from_native(vec![pki.ca.clone()]).unwrap(), "cp.selfhosted.test", &pki)
            .expect("a server chaining to an OS-store CA must be accepted");
    }

    /// Fail-closed: the bundled roots do not make an unknown CA acceptable.
    #[test]
    fn a_ca_in_neither_set_is_rejected() {
        let pki = private_pki("cp.selfhosted.test");
        let err = handshake(config_from_native(Vec::new()).unwrap(), "cp.selfhosted.test", &pki)
            .expect_err("an unknown CA must be rejected");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
            "rejected for the wrong reason: {err:?}"
        );
    }

    /// Fail-closed: a TRUSTED chain for the wrong name is still rejected.
    #[test]
    fn a_trusted_certificate_for_another_name_is_rejected() {
        let pki = private_pki("cp.selfhosted.test");
        let err = handshake(config_from_native(vec![pki.ca.clone()]).unwrap(), "evil.test", &pki)
            .expect_err("a name mismatch must be rejected");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
                )
            ),
            "rejected for the wrong reason: {err:?}"
        );
    }

    /// Unparseable OS-store entries are skipped, never fatal, and never displace the bundled roots.
    #[test]
    fn garbage_in_the_os_store_is_skipped() {
        let store = root_store_from(vec![CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00])]);
        assert!(trusts_isrg_root_x1(&store));
        assert_eq!(store.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    /// The production entry point builds on this machine (real OS store).
    #[test]
    fn client_config_builds_from_the_real_os_store() {
        client_config().expect("production config must build");
    }
}
