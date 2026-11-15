//! `RMTAGENTUPLOADv1` — the signed request the agent presents to the control plane's recording upload
//! API (docs/63 §2a C1, wire contract §5.1). The Rust mirror of `control-plane/recording_sig.go`.
//!
//! The signature is Ed25519 by the agent's enrolled identity over a LENGTH-PREFIXED binary preimage:
//! fifteen elements, each a big-endian `u32` length followed by the bytes. Because every field is its
//! own length-prefixed element, no choice of field values can be re-parsed as a different split, and a
//! field absent from the preimage is absent from the signature. The list below is exhaustive:
//!
//! ```text
//!  1 domain tag                "RMTAGENTUPLOADv1"
//!  2 version                   u32 = 1
//!  3 deployment audience       the control plane's public origin (normalised)
//!  4 operation                 1 byte: 1 create | 2 put | 3 head | 4 finish
//!  5 canonical path            as the CONTROL PLANE sees it (a proxy's /cp prefix is not part of it)
//!  6 tenant id                 16 raw bytes
//!  7 device id                 UTF-8 text
//!  8 enrollment key fingerprint  sha256 of the 32 raw pubkey bytes
//!  9 recording id              16 raw bytes
//! 10 upload generation         u64
//! 11 segment index             u32 (0 for create / finish)
//! 12 offset                    u64 (0 except put)
//! 13 exact body length         u64
//! 14 sha256(body)              32 raw bytes
//! 15 timestamp                 u64 unix milliseconds
//! ```
//!
//! `control-plane/testdata/recording_upload_v1_vectors.json` is the shared golden fixture: the Go tests
//! generate it and the tests below load the SAME file, so a drift on either side fails a build. It carries
//! positive vectors (preimage AND signature must match byte for byte — Ed25519 is deterministic) and
//! negative vectors (each field changed: the base signature must NOT verify the changed preimage).

use rmt_crypto::{Identity, PublicIdentity};
use sha2::{Digest, Sha256};

/// First element of every preimage.
pub const UPLOAD_SIG_DOMAIN: &str = "RMTAGENTUPLOADv1";
const UPLOAD_SIG_VERSION: u32 = 1;
/// Accepted clock skew each way (±5 minutes), inclusive. The server's value; the agent only uses it to
/// reason about a 401 (a skewed clock looks exactly like a bad signature).
pub const UPLOAD_SIG_WINDOW_MS: i64 = 5 * 60 * 1000;

/// The signed operation enum. Mirrors the server's: it is derived from method + route there, and the
/// agent must sign the one its request actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UploadOp {
    Create = 1,
    Put = 2,
    Head = 3,
    Finish = 4,
}

/// Every field of one signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSigFields {
    pub audience: String,
    pub op: UploadOp,
    pub path: String,
    pub tenant_id: [u8; 16],
    pub device_id: String,
    pub key_fp: [u8; 32],
    pub recording_id: [u8; 16],
    pub generation: u64,
    pub segment: u32,
    pub offset: u64,
    pub body_len: u64,
    pub body_sha256: [u8; 32],
    pub timestamp_ms: u64,
}

fn append_lp(dst: &mut Vec<u8>, field: &[u8]) {
    dst.extend_from_slice(&(field.len() as u32).to_be_bytes());
    dst.extend_from_slice(field);
}

impl UploadSigFields {
    /// The exact bytes that are signed.
    pub fn preimage(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(320);
        append_lp(&mut p, UPLOAD_SIG_DOMAIN.as_bytes());
        append_lp(&mut p, &UPLOAD_SIG_VERSION.to_be_bytes());
        append_lp(&mut p, self.audience.as_bytes());
        append_lp(&mut p, &[self.op as u8]);
        append_lp(&mut p, self.path.as_bytes());
        append_lp(&mut p, &self.tenant_id);
        append_lp(&mut p, self.device_id.as_bytes());
        append_lp(&mut p, &self.key_fp);
        append_lp(&mut p, &self.recording_id);
        append_lp(&mut p, &self.generation.to_be_bytes());
        append_lp(&mut p, &self.segment.to_be_bytes());
        append_lp(&mut p, &self.offset.to_be_bytes());
        append_lp(&mut p, &self.body_len.to_be_bytes());
        append_lp(&mut p, &self.body_sha256);
        append_lp(&mut p, &self.timestamp_ms.to_be_bytes());
        p
    }

    /// Sign with the agent's enrolled identity.
    pub fn sign(&self, identity: &Identity) -> [u8; 64] {
        identity.sign(&self.preimage())
    }

    /// Whether `sig` is a valid signature by `public` over this preimage (tests and diagnostics; the
    /// server is the verifier in production).
    pub fn verify(&self, public: &PublicIdentity, sig: &[u8; 64]) -> bool {
        public.verify(&self.preimage(), sig).is_ok()
    }
}

/// sha256 of the raw 32-byte public key: the `X-Rmt-Key-Fp` header and preimage element 8.
pub fn key_fingerprint(public: &PublicIdentity) -> [u8; 32] {
    let raw = hex::decode(public.to_hex()).expect("a PublicIdentity always renders valid hex");
    Sha256::digest(&raw).into()
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The ±5 minute window, inclusive at both edges; zero is never accepted.
pub fn timestamp_ok(now_ms: i64, ts_ms: u64) -> bool {
    if ts_ms == 0 || ts_ms > (1u64 << 62) {
        return false;
    }
    (ts_ms as i64 - now_ms).abs() <= UPLOAD_SIG_WINDOW_MS
}

/// Parse a canonical lower-case hyphenated UUID into its 16 raw bytes. The server accepts ONLY this
/// spelling; so does the agent, so the id it signs is the id it sends.
pub fn parse_canonical_uuid(s: &str) -> Option<[u8; 16]> {
    if s.len() != 36 {
        return None;
    }
    for (i, c) in s.bytes().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return None;
                }
            }
            _ => {
                if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                    return None;
                }
            }
        }
    }
    let h: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    hex::decode_to_slice(h, &mut out).ok()?;
    Some(out)
}

pub fn format_uuid(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// The canonical path for an operation, as the control plane sees it.
pub fn canonical_path(op: UploadOp, recording: &str, segment: u32) -> String {
    match op {
        UploadOp::Create => "/agent/recordings".to_string(),
        UploadOp::Put | UploadOp::Head => format!("/agent/recordings/{recording}/segments/{segment}"),
        UploadOp::Finish => format!("/agent/recordings/{recording}/finish"),
    }
}

/// Canonicalise an origin the way `NormalizeRecordingAudience` (Go) does: lower-case scheme and host,
/// no default port, no path, no userinfo/query/fragment; https only, plain http solely for loopback.
pub fn normalize_audience(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty origin".into());
    }
    let u = reqwest::Url::parse(raw).map_err(|_| "not an absolute URL".to_string())?;
    // `Url` always reports at least "/" as the path of a hierarchical URL.
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || (u.path() != "" && u.path() != "/")
        || u.cannot_be_a_base()
    {
        return Err("must be an origin like https://main.example.com (scheme and host[:port] only)".into());
    }
    let scheme = u.scheme().to_ascii_lowercase();
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    match scheme.as_str() {
        "https" => {}
        "http" => {
            if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
                return Err("plain http is accepted only for a loopback host".into());
            }
        }
        _ => return Err("must be an https origin".into()),
    }
    // `Url::port()` is already None for the scheme's default port (443 / 80).
    Ok(match u.port() {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

/// The audience for a configured control-plane base URL. The base may carry a reverse-proxy prefix
/// (`https://main.deskrally.com/cp`): the AUDIENCE is the bare origin, the prefix is only part of
/// the URL the request is sent to (the proxy strips it, so the signed path is the stripped one).
pub fn audience_from_base(base: &str) -> Result<String, String> {
    let u = reqwest::Url::parse(base.trim()).map_err(|_| "not an absolute URL".to_string())?;
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return Err("control_plane_url must not carry credentials, query or fragment".into());
    }
    let mut origin = u.clone();
    origin.set_path("");
    normalize_audience(origin.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const VECTORS: &str = include_str!("../../../control-plane/testdata/recording_upload_v1_vectors.json");

    #[derive(Deserialize)]
    struct VecFields {
        audience: String,
        op_code: u8,
        path: String,
        tenant_id: String,
        device_id: String,
        key_fingerprint_hex: String,
        recording_id: String,
        generation: u64,
        segment: u32,
        offset: u64,
        body_length: u64,
        body_sha256_hex: String,
        timestamp_ms: u64,
    }
    #[derive(Deserialize)]
    struct Positive {
        name: String,
        fields: VecFields,
        preimage_hex: String,
        signature_hex: String,
    }
    #[derive(Deserialize)]
    struct Negative {
        name: String,
        changed: String,
        fields: VecFields,
        preimage_hex: String,
        signature_hex: String,
        expect_verify: bool,
    }
    #[derive(Deserialize)]
    struct Window {
        now_ms: i64,
        timestamp_ms: u64,
        accept: bool,
    }
    #[derive(Deserialize)]
    struct File {
        seed_hex: String,
        public_hex: String,
        key_fingerprint_hex: String,
        vectors: Vec<Positive>,
        negative_vectors: Vec<Negative>,
        window_ms: i64,
        window_cases: Vec<Window>,
    }

    fn file() -> File {
        serde_json::from_str(VECTORS).expect("the shared vectors file parses")
    }

    fn to_fields(v: &VecFields) -> UploadSigFields {
        let op = match v.op_code {
            1 => UploadOp::Create,
            2 => UploadOp::Put,
            3 => UploadOp::Head,
            4 => UploadOp::Finish,
            // An op code outside the enum: the vector set has none, and the preimage would be
            // undefined. Fail the test loudly rather than invent one.
            n => panic!("unknown op_code {n}"),
        };
        let mut key_fp = [0u8; 32];
        hex::decode_to_slice(&v.key_fingerprint_hex, &mut key_fp).unwrap();
        let mut body = [0u8; 32];
        hex::decode_to_slice(&v.body_sha256_hex, &mut body).unwrap();
        UploadSigFields {
            audience: v.audience.clone(),
            op,
            path: v.path.clone(),
            tenant_id: parse_canonical_uuid(&v.tenant_id).expect("tenant uuid"),
            device_id: v.device_id.clone(),
            key_fp,
            recording_id: parse_canonical_uuid(&v.recording_id).expect("recording uuid"),
            generation: v.generation,
            segment: v.segment,
            offset: v.offset,
            body_len: v.body_length,
            body_sha256: body,
            timestamp_ms: v.timestamp_ms,
        }
    }

    fn identity(f: &File) -> Identity {
        let mut seed = [0u8; 32];
        hex::decode_to_slice(&f.seed_hex, &mut seed).unwrap();
        Identity::from_seed(&seed)
    }

    #[test]
    fn the_vector_file_has_the_shape_these_tests_assume() {
        let f = file();
        assert!(f.vectors.len() >= 5, "create, put, head, finish, utf8 device");
        assert!(f.negative_vectors.len() >= 15, "every field has a negative vector");
        assert!(f.window_cases.len() >= 12);
        assert_eq!(f.window_ms, UPLOAD_SIG_WINDOW_MS);
    }

    #[test]
    fn the_golden_key_matches_the_files_public_key_and_fingerprint() {
        let f = file();
        let id = identity(&f);
        assert_eq!(id.public_hex(), f.public_hex);
        assert_eq!(hex::encode(key_fingerprint(&id.public())), f.key_fingerprint_hex);
    }

    #[test]
    fn every_positive_vector_reproduces_the_preimage_and_the_signature_byte_for_byte() {
        let f = file();
        let id = identity(&f);
        for v in &f.vectors {
            let fields = to_fields(&v.fields);
            assert_eq!(hex::encode(fields.preimage()), v.preimage_hex, "preimage of {}", v.name);
            let sig = fields.sign(&id);
            assert_eq!(hex::encode(sig), v.signature_hex, "signature of {}", v.name);
            assert!(fields.verify(&id.public(), &sig), "{} verifies under the golden key", v.name);
        }
    }

    #[test]
    fn every_negative_vector_fails_verification_under_the_base_signature() {
        let f = file();
        let id = identity(&f);
        for v in &f.negative_vectors {
            assert!(!v.expect_verify, "{}: the file itself says this must fail", v.name);
            let sig_bytes = hex::decode(&v.signature_hex).unwrap();
            // The preimage the Go side recorded must be reproducible from the changed fields where the
            // change is a field (the signature-level negatives keep the base fields).
            let fields = to_fields(&v.fields);
            let pre = hex::decode(&v.preimage_hex).unwrap();
            let verifies = match <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                // A signature of the wrong length can never verify.
                Err(_) => false,
                Ok(sig) => {
                    // Verify the recorded preimage bytes directly (covers domain_tag / version
                    // negatives that are not expressible as a field of UploadSigFields) ...
                    let direct = id.public().verify(&pre, &sig).is_ok();
                    // ... and, for the field negatives, what this implementation would sign.
                    let rebuilt = hex::encode(fields.preimage()) == v.preimage_hex;
                    if matches!(v.changed.as_str(), "domain_tag" | "version") {
                        direct
                    } else {
                        assert!(rebuilt, "{}: Rust rebuilds the Go preimage for changed field {}", v.name, v.changed);
                        direct || fields.verify(&id.public(), &sig)
                    }
                }
            };
            assert!(!verifies, "negative vector {:?} ({}) must NOT verify", v.name, v.changed);
        }
    }

    #[test]
    fn a_signature_by_a_different_key_does_not_verify_the_positive_preimage() {
        let f = file();
        let other = Identity::from_seed(&[9u8; 32]);
        let v = &f.vectors[0];
        let fields = to_fields(&v.fields);
        let sig = fields.sign(&other);
        assert_ne!(hex::encode(sig), v.signature_hex);
        assert!(!fields.verify(&identity(&f).public(), &sig));
    }

    #[test]
    fn changing_any_single_field_changes_the_preimage() {
        let f = file();
        let base = to_fields(&f.vectors.iter().find(|v| v.name == "put-seg2").unwrap().fields);
        let mut variants: Vec<UploadSigFields> = Vec::new();
        let mut v = base.clone();
        v.audience.push('x');
        variants.push(v);
        let mut v = base.clone();
        v.op = UploadOp::Head;
        variants.push(v);
        let mut v = base.clone();
        v.path.push('x');
        variants.push(v);
        let mut v = base.clone();
        v.tenant_id[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.device_id.push('x');
        variants.push(v);
        let mut v = base.clone();
        v.key_fp[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.recording_id[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.generation += 1;
        variants.push(v);
        let mut v = base.clone();
        v.segment += 1;
        variants.push(v);
        let mut v = base.clone();
        v.offset += 1;
        variants.push(v);
        let mut v = base.clone();
        v.body_len += 1;
        variants.push(v);
        let mut v = base.clone();
        v.body_sha256[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.timestamp_ms += 1;
        variants.push(v);
        for (i, var) in variants.iter().enumerate() {
            assert_ne!(var.preimage(), base.preimage(), "variant {i} must change the signed bytes");
        }
    }

    #[test]
    fn the_timestamp_window_matches_every_shared_case() {
        let f = file();
        for c in &f.window_cases {
            assert_eq!(
                timestamp_ok(c.now_ms, c.timestamp_ms),
                c.accept,
                "now={} ts={}",
                c.now_ms,
                c.timestamp_ms
            );
        }
    }

    #[test]
    fn uuids_are_accepted_only_in_the_canonical_spelling() {
        let ok = "f0e1d2c3-b4a5-4968-8776-655443322110";
        let raw = parse_canonical_uuid(ok).unwrap();
        assert_eq!(format_uuid(&raw), ok);
        for bad in [
            "F0E1D2C3-B4A5-4968-8776-655443322110",
            "f0e1d2c3b4a549688776655443322110",
            "../f0e1d2c3-b4a5-4968-8776-65544332",
            "f0e1d2c3-b4a5-4968-8776-65544332211",
            "{f0e1d2c3-b4a5-4968-8776-655443322110}",
            "",
        ] {
            assert!(parse_canonical_uuid(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn canonical_paths_match_the_servers() {
        let id = "f0e1d2c3-b4a5-4968-8776-655443322110";
        assert_eq!(canonical_path(UploadOp::Create, id, 0), "/agent/recordings");
        assert_eq!(canonical_path(UploadOp::Put, id, 2), format!("/agent/recordings/{id}/segments/2"));
        assert_eq!(canonical_path(UploadOp::Head, id, 2), format!("/agent/recordings/{id}/segments/2"));
        assert_eq!(canonical_path(UploadOp::Finish, id, 0), format!("/agent/recordings/{id}/finish"));
        // The vector file's own paths agree.
        let f = file();
        for v in &f.vectors {
            let fields = to_fields(&v.fields);
            let op = fields.op;
            assert_eq!(
                canonical_path(op, &format_uuid(&fields.recording_id), fields.segment),
                fields.path,
                "{}",
                v.name
            );
        }
    }

    #[test]
    fn audience_normalisation_follows_the_servers_rules() {
        let ok = |s: &str| normalize_audience(s).unwrap();
        assert_eq!(ok("https://Main.DeskRally.COM"), "https://main.deskrally.com");
        assert_eq!(ok("https://main.deskrally.com:443/"), "https://main.deskrally.com");
        assert_eq!(ok("https://main.deskrally.com:8443"), "https://main.deskrally.com:8443");
        assert_eq!(ok("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
        assert_eq!(ok("http://localhost:80"), "http://localhost");
        for bad in [
            "",
            "http://main.deskrally.com",
            "ftp://main.deskrally.com",
            "https://main.deskrally.com/cp",
            "https://user@main.deskrally.com",
            "https://main.deskrally.com?x=1",
            "https://main.deskrally.com#f",
            "main.deskrally.com",
        ] {
            assert!(normalize_audience(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_audience_of_a_base_with_a_proxy_prefix_is_the_bare_origin() {
        assert_eq!(audience_from_base("https://main.deskrally.com/cp").unwrap(), "https://main.deskrally.com");
        assert_eq!(audience_from_base("https://main.deskrally.com/cp/").unwrap(), "https://main.deskrally.com");
        assert_eq!(audience_from_base("https://cp.example:8443").unwrap(), "https://cp.example:8443");
        assert!(audience_from_base("http://cp.example/cp").is_err(), "plain http to a remote host");
        assert!(audience_from_base("https://u:p@cp.example/cp").is_err());
    }
}
