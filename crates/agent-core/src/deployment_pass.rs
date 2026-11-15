//! Deployment passes and agent release attestations (docs/48 C, "Formats"): the Rust verifier.
//!
//! One of three implementations of one format. The Go reference is
//! `control-plane/deployment_pass.go`; the C++/CNG one (Setup) comes in slice 5. All three must
//! produce the expected result for every vector in `control-plane/testdata/deployment-pass-vectors.json`,
//! which this crate's tests load directly.
//!
//! A pass binds DeskRally's GENERIC signed Support (and Setup) to one customer server for at most
//! 31 days. The generic Support reads `deployment-pass.json` from beside its exe, verifies it
//! here against the root key compiled into it, and takes the control-plane URL from it. Nothing in
//! this module is a network call or reads a file: it turns bytes and a clock into a verified value
//! or a classified refusal.
//!
//! Check order is part of the contract, so every implementation reports the same [`Kind`]:
//! `key` → `envelope` → `signature` → `body` → `validity`.

use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Domain prefix of a deployment pass (NUL-terminated): a signature for one purpose never
/// verifies as another.
pub const PASS_DOMAIN: &[u8] = b"DRPASS1\0";
/// Domain prefix of an agent release attestation.
pub const RELEASE_DOMAIN: &[u8] = b"DRREL1\0";

/// Largest accepted signed-object file.
pub const MAX_SIGNED_OBJECT_BYTES: usize = 4096;
/// Largest accepted decoded body.
pub const MAX_SIGNED_BODY_BYTES: usize = 2048;
/// The `purpose` of a deployment pass body.
pub const PASS_PURPOSE: &str = "deskrally-deployment-pass";
/// The `purpose` of a release attestation body.
pub const RELEASE_PURPOSE: &str = "deskrally-agent-release";
/// 31 days: revoking a pass means not renewing it.
pub const PASS_MAX_LIFETIME_SECS: i64 = 31 * 24 * 3600;
/// docs/48's "13 months", fixed at 396 days so no implementation needs calendar arithmetic.
pub const RELEASE_MAX_LIFETIME_SECS: i64 = 396 * 24 * 3600;
/// How far before `issued_at` an object is already accepted.
pub const CLOCK_SKEW_SECS: i64 = 5 * 60;
const MAX_MSI_SIZE: i64 = (1 << 31) - 1;

/// Which check refused the input. The vectors pin this, not the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The root public key itself is malformed or not on the curve.
    Key,
    /// The file is not a well-formed `{format, body, sig}` envelope.
    Envelope,
    /// The signature is malformed or does not verify for this purpose.
    Signature,
    /// The signed body breaks a format or field rule.
    Body,
    /// Correctly signed and formed, but not valid at the caller's clock.
    Validity,
}

impl Kind {
    /// The vector file's spelling of this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Key => "key",
            Kind::Envelope => "envelope",
            Kind::Signature => "signature",
            Kind::Body => "body",
            Kind::Validity => "validity",
        }
    }
}

/// A refusal: which check, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassError {
    /// Which check refused.
    pub kind: Kind,
    /// A human-readable reason (never shown to a guest verbatim; for logs).
    pub reason: String,
}

impl std::fmt::Display for PassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.reason)
    }
}

impl std::error::Error for PassError {}

fn err(kind: Kind, reason: impl Into<String>) -> PassError {
    PassError { kind, reason: reason.into() }
}

/// A parsed root public key (SEC1 uncompressed P-256).
#[derive(Clone, Debug)]
pub struct RootKey(VerifyingKey);

impl RootKey {
    /// Parse 130 lowercase hex characters: `04 ‖ x ‖ y`, a point on the curve.
    pub fn from_hex(s: &str) -> Result<Self, PassError> {
        if s.len() != 130 || !is_lower_hex(s) {
            return Err(err(Kind::Key, "root key must be 130 lowercase hex characters (SEC1 uncompressed P-256)"));
        }
        let raw = hex_decode(s);
        if raw[0] != 0x04 {
            return Err(err(Kind::Key, "root key must be an uncompressed point (0x04 prefix)"));
        }
        VerifyingKey::from_sec1_bytes(&raw)
            .map(RootKey)
            .map_err(|_| err(Kind::Key, "root key is not a valid P-256 point"))
    }
}

/// A VERIFIED deployment pass. Only [`verify_pass`] makes one; its fields cannot change afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentPass {
    pass_id: String,
    issued_to: String,
    origin: String,
    grant_issuer_pubkey: String,
    for_setup: bool,
    for_support: bool,
    min_agent_version: String,
    issued_at: i64,
    expires_at: i64,
}

impl DeploymentPass {
    #[must_use]
    /// The verified `pass_id` field.
    pub fn pass_id(&self) -> &str {
        &self.pass_id
    }
    /// Charset-restricted at issuance and re-checked here: safe to show in a consent dialog.
    #[must_use]
    pub fn issued_to(&self) -> &str {
        &self.issued_to
    }
    #[must_use]
    /// The verified `origin` field.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    #[must_use]
    /// The verified `grant_issuer_pubkey` field.
    pub fn grant_issuer_pubkey(&self) -> &str {
        &self.grant_issuer_pubkey
    }
    #[must_use]
    /// The verified `for_setup` field.
    pub fn for_setup(&self) -> bool {
        self.for_setup
    }
    #[must_use]
    /// The verified `for_support` field.
    pub fn for_support(&self) -> bool {
        self.for_support
    }
    #[must_use]
    /// The verified `min_agent_version` field.
    pub fn min_agent_version(&self) -> &str {
        &self.min_agent_version
    }
    #[must_use]
    /// `issued_at` as Unix seconds (UTC).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    #[must_use]
    /// `expires_at` as Unix seconds (UTC).
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// What the consent dialog shows as "Server:".
    #[must_use]
    pub fn host_port(&self) -> &str {
        self.origin.strip_prefix("https://").unwrap_or(&self.origin)
    }
    /// Derived, never carried: origin + "/cp".
    #[must_use]
    pub fn control_plane_url(&self) -> String {
        format!("{}/cp", self.origin)
    }
    /// Derived, never carried: wss://host[:port]/ws.
    #[must_use]
    pub fn signaling_url(&self) -> String {
        format!("wss://{}/ws", self.host_port())
    }
}

/// A VERIFIED agent release attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRelease {
    msi_sha256: String,
    msi_size: i64,
    product_version: String,
    product_code: String,
    upgrade_code: String,
    arch: String,
    issued_at: i64,
    expires_at: i64,
}

impl AgentRelease {
    #[must_use]
    /// The verified `msi_sha256` field.
    pub fn msi_sha256(&self) -> &str {
        &self.msi_sha256
    }
    #[must_use]
    /// The verified `msi_size` field.
    pub fn msi_size(&self) -> i64 {
        self.msi_size
    }
    #[must_use]
    /// The verified `product_version` field.
    pub fn product_version(&self) -> &str {
        &self.product_version
    }
    #[must_use]
    /// The verified `product_code` field.
    pub fn product_code(&self) -> &str {
        &self.product_code
    }
    #[must_use]
    /// The verified `upgrade_code` field.
    pub fn upgrade_code(&self) -> &str {
        &self.upgrade_code
    }
    #[must_use]
    /// The verified `arch` field.
    pub fn arch(&self) -> &str {
        &self.arch
    }
    #[must_use]
    /// `issued_at` as Unix seconds (UTC).
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    #[must_use]
    /// `expires_at` as Unix seconds (UTC).
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Every check on a pass file's bytes, at `now` (Unix seconds, the caller's clock).
pub fn verify_pass(root: &RootKey, raw: &[u8], now: i64) -> Result<DeploymentPass, PassError> {
    let body = open_signed_object(root, PASS_DOMAIN, raw)?;
    let p = parse_pass_body(&body)?;
    check_window("deployment pass", p.issued_at, p.expires_at, now)?;
    Ok(p)
}

/// Every check on a release attestation file's bytes, at `now`.
pub fn verify_release(root: &RootKey, raw: &[u8], now: i64) -> Result<AgentRelease, PassError> {
    let body = open_signed_object(root, RELEASE_DOMAIN, raw)?;
    let r = parse_release_body(&body)?;
    check_window("agent release attestation", r.issued_at, r.expires_at, now)?;
    Ok(r)
}

// -------------------------------------------------------------------------------------------
// Envelope and signature (checks 2 and 3)
// -------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: i64,
    body: String,
    sig: String,
}

fn open_signed_object(root: &RootKey, domain: &[u8], raw: &[u8]) -> Result<Vec<u8>, PassError> {
    if raw.len() > MAX_SIGNED_OBJECT_BYTES {
        return Err(err(Kind::Envelope, format!("signed object is {} bytes, over the {MAX_SIGNED_OBJECT_BYTES}-byte limit", raw.len())));
    }
    if std::str::from_utf8(raw).is_err() {
        return Err(err(Kind::Envelope, "signed object is not valid UTF-8"));
    }
    // serde_json refuses duplicate and unknown keys (deny_unknown_fields + derived Deserialize),
    // missing keys, nulls, wrong types (a "1" string or 1.0 for format), and trailing data.
    let env: Envelope = serde_json::from_slice(raw).map_err(|e| err(Kind::Envelope, format!("envelope JSON: {e}")))?;
    if env.format != 1 {
        return Err(err(Kind::Envelope, format!("format {} is not supported (expected 1)", env.format)));
    }
    if env.body.is_empty() {
        return Err(err(Kind::Envelope, "empty body"));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let body = engine
        .decode(&env.body)
        .ok()
        // The one canonical spelling only: re-encoding must reproduce the text exactly.
        .filter(|b| engine.encode(b) == env.body)
        .ok_or_else(|| err(Kind::Envelope, "body is not canonical standard padded base64"))?;
    if env.sig.len() != 128 || !is_lower_hex(&env.sig) {
        return Err(err(Kind::Envelope, "sig must be 128 lowercase hex characters (r || s)"));
    }
    // from_slice refuses r or s equal to 0 or >= n. No low-S rule: either twin verifies.
    let sig = Signature::from_slice(&hex_decode(&env.sig))
        .map_err(|_| err(Kind::Signature, "r or s is outside [1, n-1]"))?;
    let digest = Sha256::new().chain_update(domain).chain_update(&body).finalize();
    root.0
        .verify_prehash(&digest, &sig)
        .map_err(|_| err(Kind::Signature, "signature does not verify under the root key for this purpose"))?;
    Ok(body)
}

// -------------------------------------------------------------------------------------------
// Bodies (check 4)
// -------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassBody {
    purpose: String,
    v: i64,
    pass_id: String,
    issued_to: String,
    origin: String,
    grant_issuer_pubkey: String,
    uses: Vec<String>,
    min_agent_version: String,
    issued_at: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBody {
    purpose: String,
    v: i64,
    msi_sha256: String,
    msi_size: i64,
    product_version: String,
    product_code: String,
    upgrade_code: String,
    arch: String,
    issued_at: String,
    expires_at: String,
}

/// Size, then no control bytes (so no NUL and no whitespace other than space), then UTF-8.
fn check_body_bytes(body: &[u8]) -> Result<(), PassError> {
    if body.len() > MAX_SIGNED_BODY_BYTES {
        return Err(err(Kind::Body, format!("body is {} bytes, over the {MAX_SIGNED_BODY_BYTES}-byte limit", body.len())));
    }
    if let Some(i) = body.iter().position(|&c| c < 0x20 || c == 0x7f) {
        return Err(err(Kind::Body, format!("control byte 0x{:02x} at {i}", body[i])));
    }
    if std::str::from_utf8(body).is_err() {
        return Err(err(Kind::Body, "body is not valid UTF-8"));
    }
    Ok(())
}

fn field(name: &str, e: impl std::fmt::Display) -> PassError {
    err(Kind::Body, format!("{name}: {e}"))
}

fn parse_pass_body(body: &[u8]) -> Result<DeploymentPass, PassError> {
    check_body_bytes(body)?;
    let b: PassBody = serde_json::from_slice(body).map_err(|e| err(Kind::Body, format!("pass body JSON: {e}")))?;
    if b.purpose != PASS_PURPOSE {
        return Err(field("purpose", format!("{:?} is not {PASS_PURPOSE:?}", b.purpose)));
    }
    if b.v != 1 {
        return Err(field("v", format!("version {} is not supported (expected 1)", b.v)));
    }
    check_uuid(&b.pass_id).map_err(|e| field("pass_id", e))?;
    check_issued_to(&b.issued_to).map_err(|e| field("issued_to", e))?;
    check_origin(&b.origin).map_err(|e| field("origin", e))?;
    if b.grant_issuer_pubkey.len() != 64 || !is_lower_hex(&b.grant_issuer_pubkey) {
        return Err(field("grant_issuer_pubkey", "expected 64 lowercase hex characters"));
    }
    if b.uses.is_empty() {
        return Err(field("uses", "must name at least one of setup, support"));
    }
    let (mut for_setup, mut for_support) = (false, false);
    for u in &b.uses {
        let slot = match u.as_str() {
            "setup" => &mut for_setup,
            "support" => &mut for_support,
            other => return Err(field("uses", format!("{other:?} is not setup or support"))),
        };
        if *slot {
            return Err(field("uses", format!("{u:?} is listed twice")));
        }
        *slot = true;
    }
    check_product_version(&b.min_agent_version).map_err(|e| field("min_agent_version", e))?;
    let issued_at = parse_time(&b.issued_at).map_err(|e| field("issued_at", e))?;
    let expires_at = parse_time(&b.expires_at).map_err(|e| field("expires_at", e))?;
    check_lifetime(issued_at, expires_at, PASS_MAX_LIFETIME_SECS).map_err(|e| field("expires_at", e))?;
    Ok(DeploymentPass {
        pass_id: b.pass_id,
        issued_to: b.issued_to,
        origin: b.origin,
        grant_issuer_pubkey: b.grant_issuer_pubkey,
        for_setup,
        for_support,
        min_agent_version: b.min_agent_version,
        issued_at,
        expires_at,
    })
}

fn parse_release_body(body: &[u8]) -> Result<AgentRelease, PassError> {
    check_body_bytes(body)?;
    let b: ReleaseBody = serde_json::from_slice(body).map_err(|e| err(Kind::Body, format!("release body JSON: {e}")))?;
    if b.purpose != RELEASE_PURPOSE {
        return Err(field("purpose", format!("{:?} is not {RELEASE_PURPOSE:?}", b.purpose)));
    }
    if b.v != 1 {
        return Err(field("v", format!("version {} is not supported (expected 1)", b.v)));
    }
    if b.msi_sha256.len() != 64 || !is_lower_hex(&b.msi_sha256) {
        return Err(field("msi_sha256", "expected 64 lowercase hex characters"));
    }
    if !(1..=MAX_MSI_SIZE).contains(&b.msi_size) {
        return Err(field("msi_size", format!("{} is outside [1, {MAX_MSI_SIZE}]", b.msi_size)));
    }
    check_product_version(&b.product_version).map_err(|e| field("product_version", e))?;
    check_braced_guid(&b.product_code).map_err(|e| field("product_code", e))?;
    check_braced_guid(&b.upgrade_code).map_err(|e| field("upgrade_code", e))?;
    if b.arch != "x64" {
        return Err(field("arch", format!("{:?} is not x64", b.arch)));
    }
    let issued_at = parse_time(&b.issued_at).map_err(|e| field("issued_at", e))?;
    let expires_at = parse_time(&b.expires_at).map_err(|e| field("expires_at", e))?;
    check_lifetime(issued_at, expires_at, RELEASE_MAX_LIFETIME_SECS).map_err(|e| field("expires_at", e))?;
    Ok(AgentRelease {
        msi_sha256: b.msi_sha256,
        msi_size: b.msi_size,
        product_version: b.product_version,
        product_code: b.product_code,
        upgrade_code: b.upgrade_code,
        arch: b.arch,
        issued_at,
        expires_at,
    })
}

// -------------------------------------------------------------------------------------------
// Validity (check 5)
// -------------------------------------------------------------------------------------------

fn check_lifetime(issued: i64, expires: i64, max: i64) -> Result<(), String> {
    if expires <= issued {
        return Err("expires_at must be after issued_at".into());
    }
    if expires - issued > max {
        return Err(format!("lifetime {}s exceeds the {max}s maximum", expires - issued));
    }
    Ok(())
}

fn check_window(what: &str, issued: i64, expires: i64, now: i64) -> Result<(), PassError> {
    if now < issued - CLOCK_SKEW_SECS {
        return Err(err(Kind::Validity, format!("{what} is not valid yet")));
    }
    if now >= expires {
        return Err(err(Kind::Validity, format!("{what} has expired")));
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------
// Field rules (mirroring the Go reference exactly)
// -------------------------------------------------------------------------------------------

/// Exactly `https://<host>[:<port>]`: lowercase ASCII LDH labels (punycode for IDNs), no trailing
/// dot, default port omitted, no path, userinfo, query or fragment.
pub fn check_origin(s: &str) -> Result<(), String> {
    let rest = s.strip_prefix("https://").ok_or("must start with https://")?;
    let (host, port) = match rest.find(':') {
        Some(i) => {
            let port = &rest[i + 1..];
            if port.is_empty() {
                return Err("empty port".into());
            }
            (&rest[..i], Some(port))
        }
        None => (rest, None),
    };
    if host.is_empty() || host.len() > 253 {
        return Err("host must be 1-253 characters".into());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("each host label must be 1-63 characters (no empty labels or trailing dot)".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a host label starts or ends with '-'".into());
        }
        if !label.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return Err("host may contain only a-z, 0-9, '-' and '.'; use punycode and no path, userinfo, query or fragment".into());
        }
    }
    if let Some(port) = port {
        if !port.bytes().all(|c| c.is_ascii_digit()) {
            return Err("port must be decimal digits only, with nothing after it".into());
        }
        if port.starts_with('0') || port.len() > 5 {
            return Err("port must be 1-65535 without leading zeros".into());
        }
        let n: u32 = port.parse().map_err(|_| "port must be 1-65535")?;
        if n > 65535 {
            return Err("port must be 1-65535".into());
        }
        if n == 443 {
            return Err("omit the default port 443".into());
        }
    }
    Ok(())
}

fn check_issued_to(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 {
        return Err("must be 1-64 characters".into());
    }
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || b" .,&'()-".contains(&c)) {
        return Err("only A-Z a-z 0-9 space . , & ' ( ) - are allowed".into());
    }
    Ok(())
}

fn check_uuid(s: &str) -> Result<(), String> {
    if s.len() != 36 {
        return Err("expected a 36-character lowercase UUID".into());
    }
    for (i, c) in s.bytes().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        };
        if !ok {
            return Err("expected a lowercase 8-4-4-4-12 UUID".into());
        }
    }
    Ok(())
}

/// A.B.C within Windows Installer's limits (255.255.65535), no leading zeros, digits only.
fn check_product_version(s: &str) -> Result<(), String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("expected exactly 3 dot-separated fields".into());
    }
    for (p, limit) in parts.iter().zip([255u32, 255, 65535]) {
        if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
            return Err("fields must be decimal digits only".into());
        }
        if p.len() > 1 && p.starts_with('0') {
            return Err("a field has a leading zero".into());
        }
        if p.len() > 5 || p.parse::<u32>().map_or(true, |n| n > limit) {
            return Err("a field exceeds the Windows Installer limit (255.255.65535)".into());
        }
    }
    Ok(())
}

/// {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}, uppercase hex only.
fn check_braced_guid(s: &str) -> Result<(), String> {
    let b = s.as_bytes();
    if b.len() != 38 || b[0] != b'{' || b[37] != b'}' {
        return Err("expected a braced 38-character GUID".into());
    }
    for (i, &c) in b[1..37].iter().enumerate() {
        let ok = match i + 1 {
            9 | 14 | 19 | 24 => c == b'-',
            _ => c.is_ascii_digit() || (b'A'..=b'F').contains(&c),
        };
        if !ok {
            return Err("expected the 8-4-4-4-12 layout in uppercase hex".into());
        }
    }
    Ok(())
}

/// Exactly `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds) as Unix seconds; impossible dates refused.
pub fn parse_time(s: &str) -> Result<i64, String> {
    let b = s.as_bytes();
    let shape_ok = b.len() == 20
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    if !shape_ok {
        return Err(format!("{s:?} is not YYYY-MM-DDTHH:MM:SSZ (UTC, whole seconds)"));
    }
    let n = |a: usize, z: usize| s[a..z].parse::<i64>().unwrap_or(-1);
    let (y, mo, d, h, mi, se) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > dim[(mo - 1) as usize] || h > 23 || mi > 59 || se > 59 {
        return Err(format!("{s:?} is not a valid UTC date and time"));
    }
    Ok(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`parse_time`], for messages and tests.
#[must_use]
pub fn format_time(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // civil_from_days (Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Decode hex already checked by [`is_lower_hex`] with an even length.
fn hex_decode(s: &str) -> Vec<u8> {
    let v = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
    s.as_bytes().chunks(2).map(|p| v(p[0]) << 4 | v(p[1])).collect()
}

#[cfg(test)]
#[path = "deployment_pass_tests.rs"]
mod tests;
