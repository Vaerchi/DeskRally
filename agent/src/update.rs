//! The signed **update manifest**: what the agent is told about an available release, and the
//! verification it performs before believing a word of it (docs/21 §3, step 2 of §8).
//!
//! # Read docs/21 §0 first, because this module inherits its threat model
//!
//! An auto-update channel is, by construction, *remote code execution as SYSTEM on every managed
//! machine, on a schedule, with no human in the loop*. docs/21 opens by calling it the most
//! dangerous feature in the product, and the two consequences it draws from that drive every
//! decision here:
//!
//! * **Whoever can sign an update owns every machine, forever** — not "can start a session", owns.
//! * **A bad update is unrecoverable by the same channel**, because the mechanism you would use to
//!   push the fix is the mechanism that just broke.
//!
//! # What this module deliberately does NOT do
//!
//! This is **step 2 of docs/21 §8, and only step 2**. §8 orders the steps so that work can stop at
//! any point without having built half a dangerous feature, and the line is drawn here:
//!
//! * There is **no download**. Nothing in this module or its callers opens a socket. [`Release::url`](crate::update::Release::url)
//!   is carried, length- and scheme-checked, and otherwise untouched.
//! * There is **no staging, no swap, no service restart**. Nothing writes an executable anywhere.
//! * There is **no fetch path for the manifest itself**. The manifest is a file an operator places
//!   beside `config.json`, inside the directory `crate::agent_root::harden_agent_root` already
//!   restricts to SYSTEM + Administrators. Inventing a fetch would need either an authenticated
//!   HTTP channel to the control plane (the unattended agent has none) or a scheduler (there is
//!   none — `crates/agent-windows/src/service.rs`'s only helper-lifetime loop is a bare stop-file
//!   poll, and every other ticker in the tree is session-scoped). Both are step 3/4 work.
//! * There is **no sha256 computation**, because there is no file to hash. The digest is validated
//!   for SHAPE only; verifying it against real bytes is step 3's job and step 3's alone.
//!
//! The whole point of shipping step 2 alone is that the trust model gets exercised — signed,
//! verified, logged, and visible in `helper.log` — before anything exists that could act on it.
//!
//! # The key is not the grant issuer key, and that is the whole design
//!
//! docs/21 §3 calls this "the most important sentence in this document", and it is the one place
//! this module deliberately contradicts the reasoning its four sibling artifacts share.
//!
//! [`crate::backstage::grant`], [`crate::session_policy`], [`crate::elevation`] and the audit chain
//! are all signed by ONE control-plane key, separated only by their domain tags, and
//! `control-plane/elevation_mint.go` argues explicitly for that: "the agent pins ONE public key
//! (`grant_issuer_pubkey`), so a second key would mean a second thing to provision and rotate."
//! That argument is correct for those four. **It is wrong for this one**, and the two must not be
//! read as contradicting each other, so here is the difference stated once:
//!
//! * **Blast radius.** A leaked `GRANT_ISSUER_SEED` mints backstage grants and elevation grants:
//!   serious, but scoped to sessions, bounded by capabilities, single-use, and audited. A leaked
//!   *update* key is arbitrary code as SYSTEM on every machine, permanently, with no audit trail
//!   that survives — the attacker controls the thing that writes it.
//! * **The control plane is the component most likely to be compromised.** It is the
//!   internet-facing one, and `GRANT_ISSUER_SEED` sits in a `.env` file on it. If the update key
//!   never lives there, compromising the control plane yields the ability to *serve* a manifest but
//!   not to *sign* one — turning "fleet-wide RCE" into "denial of updates", which is a category of
//!   problem a deployment survives.
//!
//! So the update signing key lives offline, at release time, in the same posture as a code-signing
//! certificate; `control-plane/cmd/rmt-update-sign` is the only thing in this repository that
//! signs one, and it is a separate binary from the server. The agent pins the public half as
//! `update_signer_pubkey` (a *second* pinned key, accepted as a cost) and
//! [`UpdateTrust::from_config`](crate::update::UpdateTrust::from_config) **refuses to run at all** if that value equals
//! `grant_issuer_pubkey` — because an operator who pastes one into the other has silently merged
//! the two threat models above, and nothing else in the system would ever tell them.
//!
//! # Where the pin lives: install time, not enrollment
//!
//! docs/21 §3 says the agent "pins `update_signer_pubkey` at enrollment, alongside the grant issuer
//! pubkey it already pins". That is **factually wrong about this codebase** and the doc has been
//! corrected: `crates/agent-windows/src/enroll.rs`'s `apply_enrollment` writes `device_id` and
//! `tenant_id` and clears the token, and `grant_issuer_pubkey` appears nowhere in that file. The
//! key that actually gets pinned is written by the INSTALLER into `config.json`
//! (`install-agent.ps1`, generated by `scripts/build-release.ps1`), so this one is too.
//!
//! # Wire shape
//!
//! Mirrors [`crate::elevation`] and [`crate::session_policy`] exactly, so all three verify paths
//! read the same:
//!
//! ```json
//! {
//!   "claims": {
//!     "release": {
//!       "version": "0.4.0",
//!       "sha256": "e3b0c442…",
//!       "url": "https://updates.example/rmt-agent-0.4.0.exe",
//!       "min_upgradable_from": "0.2.0"
//!     },
//!     "issued_at_ms": 1730000000000,
//!     "expires_at_ms": 1732592000000
//!   },
//!   "sig": "<128 hex chars>"
//! }
//! ```
//!
//! docs/21 §3 sketched a flat object with a `released_at` RFC-3339 string. Two deliberate
//! deviations, both recorded in the doc:
//!
//! * **`issued_at_ms` / `expires_at_ms` as Unix milliseconds**, not an RFC-3339 string. Every other
//!   signed artifact in this system uses `i64` milliseconds in its preimage, and the golden vectors
//!   that keep Rust and Go byte-identical depend on there being exactly one way to encode the
//!   value. A date STRING in a canonical preimage is a cross-language parsing hazard for no gain
//!   (`2026-09-01T00:00:00Z` and `2026-09-01T00:00:00.000Z` are the same instant and different
//!   bytes), and the agent needs an instant, not a rendering.
//! * **An expiry at all**, which the sketch had no equivalent of. A signature with no expiry is
//!   valid forever, so a manifest for a build later found to be broken — exactly the §5 scenario —
//!   stays a valid instruction to install that build for as long as anyone can serve the bytes. The
//!   expiry bounds that window without needing the fleet's cooperation, which is the property §0
//!   says every part of this feature must have. It is not a substitute for §5's kill switch; it is
//!   the floor under it.
//!
//! # Canonical signing bytes (update v1 — big-endian throughout)
//!
//! ```text
//! UPDATE_DOMAIN_TAG                                   // 12 bytes: b"RMTUPDATEv1\x00"
//! || u32be(len(version_utf8))    || version_utf8      // "0.4.0"
//! || u32be(len(sha256_utf8))     || sha256_utf8       // 64 LOWERCASE hex chars
//! || u32be(len(url_utf8))        || url_utf8          // https:// only
//! || u32be(len(min_upg_utf8))    || min_upg_utf8      // "0.2.0"
//! || i64be(issued_at_ms)
//! || i64be(expires_at_ms)
//! ```
//!
//! Every field of [`Release`](crate::update::Release) is in the preimage, and `tests::every_release_field_changes_the_preimage`
//! proves it one field at a time. That test is not decoration: the `url` is the field naming *what
//! gets executed*, and a preimage that omitted it would let anyone holding one genuine manifest
//! redirect the whole fleet to a binary of their choosing while keeping the real signature.
//!
//! The digest is signed as its lowercase hex STRING rather than as 32 raw bytes. That makes the
//! canonicalization rule visible instead of implicit, and [`SignedUpdateManifest::verify`](crate::update::SignedUpdateManifest::verify) enforces
//! it: an uppercase or short digest is REFUSED ([`UpdateManifestError::MalformedSha256`](crate::update::UpdateManifestError::MalformedSha256)) rather
//! than silently normalized into a different-but-equal value. Fail closed, never canonicalize on
//! the reader's behalf.
//!
//! Cross-language agreement with the Go signer is proven by shared golden vectors:
//! `tests::golden_vector_v1` here and `TestUpdateManifestGoldenVectorV1` in
//! `control-plane/update_manifest_test.go` pin the SAME fixture to the SAME canonical-bytes hex AND
//! the SAME signature hex, and `tests::verifies_go_signed_manifest` feeds Go's actual wire bytes
//! through the real decoder.

use std::cmp::Ordering;
use std::path::Path;

use serde::{Deserialize, Serialize};

use rmt_crypto::{Identity, PublicIdentity};

use crate::backstage::canonical::CanonicalWriter;
use crate::backstage::grant::CLOCK_SKEW_MS;

/// The basename of the manifest file the operator places inside the hardened agent root.
///
/// The DIRECTORY is deliberately not configurable and not named here: the Windows agent joins this
/// onto `crate::config::CONFIG_DIR` (`crates/agent-windows/src/config.rs`, pinned to this constant
/// by a test there). A config knob for the location would be a way to point the agent at a
/// directory nobody hardened, which defeats the only integrity control the manifest FILE has —
/// `harden_agent_root` restricting `C:\rmt-agent` to SYSTEM + Administrators. The signature is what
/// makes the manifest trustworthy; the ACL is what stops a local user from swapping in an older
/// signed one, and both are needed.
pub const MANIFEST_FILENAME: &str = "update-manifest.json";

/// Largest manifest file this will read off disk, in bytes.
///
/// A manifest is a few hundred bytes. The bound exists because the file lives on the guest's disk
/// and `serde_json` will happily allocate whatever it is handed: a multi-gigabyte "manifest"
/// planted by anyone who can write the file would be an out-of-memory kill of the SYSTEM helper
/// (i.e. of the agent that is the only way back into the machine) before a single signature was
/// ever checked. Refusing by size costs nothing and happens before any parse.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// Longest accepted `version` / `min_upgradable_from` string. Generous next to a real semver;
/// present so a signed-but-absurd value cannot bloat a log line or a future registry write.
const MAX_VERSION_LEN: usize = 64;

/// Longest accepted download URL. Well above any real one; the point is a bound, not a policy.
const MAX_URL_LEN: usize = 2048;

/// The scheme a release URL must use. `https` only, checked at VERIFY time rather than at download
/// time, deliberately: the check that matters is the one made before the value is trusted, and step
/// 3 (which is the thing that would fetch) must inherit an already-validated URL rather than be
/// trusted to re-derive this rule. `http://` would put the fleet's next binary on the wire in
/// clear, and `file://` would turn a manifest into "run this path", so neither is a scheme this
/// ever accepts even though the signature alone would already be authenticating the bytes.
const REQUIRED_URL_SCHEME: &str = "https://";

// =========================================================================================
// The manifest itself
// =========================================================================================

/// What a release IS: the version, the digest of its binary, where the binary lives, and the oldest
/// build permitted to take this upgrade.
///
/// Field set and order are part of the signed preimage. Changing either changes the signing bytes
/// and breaks the cross-language golden vectors — which is the intended alarm, not an inconvenience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on a field this build does not know. Every field of this artifact is signed and
// load-bearing, so an unrecognised one means "this manifest asserts something I do not understand"
// — which is never a reason to proceed on a value whose worst case is executing someone else's
// binary as SYSTEM. serde IGNORES unknown fields by default, so this attribute is the whole check.
// It costs forward compatibility deliberately: a future manifest carrying a new field is refused by
// today's agents rather than half-understood by them, which is the correct direction for a
// security artifact and is exactly why `min_upgradable_from` exists.
#[serde(deny_unknown_fields)]
pub struct Release {
    /// The version this release publishes, e.g. `"0.4.0"`. Compared against the running agent's
    /// `rmt_agent_core::version::AGENT_VERSION` — see [`Release::availability`] — using
    /// [`compare_versions`], which ignores semver build metadata. Named as a path rather than
    /// linked, because this crate deliberately does not depend on `rmt-agent-core`.
    pub version: String,
    /// Lowercase hex SHA-256 of the release binary, exactly 64 characters.
    ///
    /// **Nothing in step 2 hashes anything.** This is carried and shape-checked so that step 3's
    /// "verify sha256 AND signature before the file moves" (docs/21 §6) has a value it can trust
    /// the provenance of. A digest that arrived unsigned would be worthless.
    pub sha256: String,
    /// Where the release binary can be fetched from. `https://` only, bounded length, no control
    /// characters. **Step 2 never fetches it.**
    pub url: String,
    /// The oldest running version permitted to take this upgrade — docs/21 §7's mechanism for a
    /// build to refuse an upgrade path that was never tested. A running agent older than this
    /// reports [`UpdateAvailability::UpgradePathUnsupported`], which is a *refusal to claim an
    /// update is available*, not an error.
    pub min_upgradable_from: String,
}

/// [`Release`] plus its validity window (Unix milliseconds). Keep the field set + order stable —
/// changing it changes the signing bytes and breaks the cross-language golden vectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on a field this build does not know. Every field of this artifact is signed and
// load-bearing, so an unrecognised one means "this manifest asserts something I do not understand"
// — which is never a reason to proceed on a value whose worst case is executing someone else's
// binary as SYSTEM. serde IGNORES unknown fields by default, so this attribute is the whole check.
// It costs forward compatibility deliberately: a future manifest carrying a new field is refused by
// today's agents rather than half-understood by them, which is the correct direction for a
// Fail closed on an unknown field, for the reason spelled out on [`Release`]. Applied to all three
// structs, not just the outermost, because serde checks it per-struct: a stray key inside `claims`
// would otherwise be ignored while the same key at the top level was refused.
#[serde(deny_unknown_fields)]
pub struct UpdateManifestClaims {
    /// The release these claims describe.
    pub release: Release,
    /// When the release process signed this manifest (Unix ms). `now_ms` must be at or after this,
    /// minus [`CLOCK_SKEW_MS`].
    pub issued_at_ms: i64,
    /// When this manifest stops being believed (Unix ms, exclusive). See the module docs for why an
    /// update manifest has an expiry at all.
    pub expires_at_ms: i64,
}

impl UpdateManifestClaims {
    /// The canonical update-v1 signing bytes (see the module docs for the exact layout). This — not
    /// the JSON — is what the release signer signs and the agent verifies, so Rust and Go produce
    /// identical signing input for the same claims.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.update_tag()
            .lp_str(&self.release.version)
            .lp_str(&self.release.sha256)
            .lp_str(&self.release.url)
            .lp_str(&self.release.min_upgradable_from)
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms);
        w.into_bytes()
    }

    /// Sign these claims.
    ///
    /// **Test and tooling surface only.** No production Rust path calls this: the agent verifies,
    /// it never signs, and the only thing in this repository that produces a real signature is the
    /// offline `control-plane/cmd/rmt-update-sign` binary. It exists here so the golden vectors can
    /// be computed on this side and compared with Go's, which is the only way the two encoders are
    /// held together.
    pub fn sign(&self, signer: &Identity) -> SignedUpdateManifest {
        let sig = signer.sign(&self.signing_bytes());
        SignedUpdateManifest { claims: self.clone(), sig: hex::encode(sig) }
    }
}

/// An [`UpdateManifestClaims`] plus the release signer's Ed25519 signature over its canonical
/// signing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on an unknown field; see [`Release`].
#[serde(deny_unknown_fields)]
pub struct SignedUpdateManifest {
    /// The signed claims.
    pub claims: UpdateManifestClaims,
    /// Hex-encoded 64-byte Ed25519 signature over
    /// [`signing_bytes`](UpdateManifestClaims::signing_bytes).
    pub sig: String,
}

impl SignedUpdateManifest {
    /// Encode to the JSON wire string (the exact bytes that live in `update-manifest.json`).
    pub fn to_json(&self) -> Result<String, UpdateManifestError> {
        serde_json::to_string(self).map_err(|e| UpdateManifestError::Encoding(e.to_string()))
    }

    /// Decode from the JSON wire string. Does **not** verify — call [`verify`](Self::verify).
    pub fn from_json(s: &str) -> Result<Self, UpdateManifestError> {
        serde_json::from_str(s).map_err(|e| UpdateManifestError::Encoding(e.to_string()))
    }

    /// Read the manifest file at `path`.
    ///
    /// `Ok(None)` means **there is no manifest**, which is the normal state of every machine that
    /// has never been given one and is not an error. `Err` means a manifest is present and could
    /// not be believed — a distinction the caller must keep, because "no manifest" and "a manifest
    /// I could not read" want opposite log lines: the first is silence, the second is an alarm.
    ///
    /// Size is checked before the read, not after (see [`MAX_MANIFEST_BYTES`]).
    pub fn from_file(path: &Path) -> Result<Option<Self>, UpdateManifestError> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(UpdateManifestError::Unreadable {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })
            }
        };
        if !meta.is_file() {
            return Err(UpdateManifestError::Unreadable {
                path: path.display().to_string(),
                reason: "not a regular file".into(),
            });
        }
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(UpdateManifestError::Unreadable {
                path: path.display().to_string(),
                reason: format!("{} bytes exceeds the {MAX_MANIFEST_BYTES}-byte cap", meta.len()),
            });
        }
        let text = std::fs::read_to_string(path).map_err(|e| UpdateManifestError::Unreadable {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        Self::from_json(&text).map(Some)
    }

    /// Verify the signature against the pinned release `signer`, then the validity window against
    /// `now_ms`, then the shape of every self-claimed field.
    ///
    /// **Order is the security property, and it is copied deliberately from
    /// [`SignedElevationGrant::verify`](crate::elevation::SignedElevationGrant::verify):**
    ///
    /// 1. **Signature FIRST**, so a forged manifest is rejected before any field it carries is
    ///    trusted, read, logged or compared. Everything below this line is an assertion the
    ///    *signer* made; everything above it is the only reason to believe them. Reversing the
    ///    order would let an attacker choose which error message a forgery produces, and — worse
    ///    here than anywhere else — would put an attacker-chosen URL into the agent's log before
    ///    anything had authenticated it.
    /// 2. **Not-yet-valid**, with [`CLOCK_SKEW_MS`] tolerance (one-sided, as everywhere else).
    /// 3. **Expired**, exact. A stale-but-genuine manifest is refused; see the module docs for why
    ///    an update manifest expires at all.
    /// 4. **Field shapes** — digest, version strings, URL. Last because they are the checks that
    ///    say "this manifest is malformed", not "this manifest is not for us", and reporting the
    ///    most specific true reason keeps the log legible.
    ///
    /// What is deliberately NOT here: any comparison against the running version. That is
    /// [`Release::availability`], kept separate for exactly the reason `SignedElevationGrant::verify`
    /// keeps single-use out of itself — this is a pure predicate pinned by byte-for-byte golden
    /// vectors shared with the Go signer, and folding in a host fact would make those vectors
    /// meaningless.
    pub fn verify(
        &self,
        signer: &PublicIdentity,
        now_ms: i64,
    ) -> Result<Release, UpdateManifestError> {
        let bytes = self.claims.signing_bytes();
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|_| UpdateManifestError::Encoding("signature is not hex".into()))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| UpdateManifestError::Encoding("signature is not 64 bytes".into()))?;

        signer.verify(&bytes, &sig).map_err(|_| UpdateManifestError::BadSignature)?;

        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(UpdateManifestError::NotYetValid {
                issued_at_ms: self.claims.issued_at_ms,
                now_ms,
            });
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(UpdateManifestError::Expired {
                expires_at_ms: self.claims.expires_at_ms,
                now_ms,
            });
        }

        let r = &self.claims.release;
        if let Err(reason) = check_sha256_hex(&r.sha256) {
            return Err(UpdateManifestError::MalformedSha256 { reason });
        }
        if let Err(e) = parse_version(&r.version) {
            return Err(UpdateManifestError::MalformedVersion {
                field: "version",
                value: r.version.clone(),
                reason: e,
            });
        }
        if let Err(e) = parse_version(&r.min_upgradable_from) {
            return Err(UpdateManifestError::MalformedVersion {
                field: "min_upgradable_from",
                value: r.min_upgradable_from.clone(),
                reason: e,
            });
        }
        if let Err(reason) = check_url(&r.url) {
            return Err(UpdateManifestError::MalformedUrl { reason });
        }

        Ok(r.clone())
    }
}

/// The canonical form of the release digest: exactly 64 LOWERCASE hex characters.
///
/// Uppercase is refused rather than folded. The digest is inside the signed preimage as a string,
/// so `"AB…"` and `"ab…"` are two different signed messages; accepting both would mean the agent
/// silently treats a value it was not handed as the value it was handed. That is the shape of bug
/// that turns a signature check into a formality.
fn check_sha256_hex(s: &str) -> Result<(), &'static str> {
    if s.len() != 64 {
        return Err("expected exactly 64 hex characters");
    }
    if !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected lowercase hex only (0-9, a-f)");
    }
    Ok(())
}

/// Shape-check the release URL. See [`REQUIRED_URL_SCHEME`] for why the scheme is pinned here
/// rather than at the (not-yet-existing) download site.
fn check_url(s: &str) -> Result<(), &'static str> {
    if s.len() > MAX_URL_LEN {
        return Err("longer than the accepted maximum");
    }
    if !s.starts_with(REQUIRED_URL_SCHEME) {
        return Err("must be an https:// URL");
    }
    if s.len() == REQUIRED_URL_SCHEME.len() {
        return Err("has a scheme but no host");
    }
    // A control character in a URL is either an encoding accident or an attempt to break whatever
    // renders it (a log line, a future console field). Neither is a URL worth carrying.
    if s.chars().any(|c| c.is_control()) {
        return Err("contains control characters");
    }
    Ok(())
}

/// Why a [`SignedUpdateManifest`] was refused.
///
/// One variant per refusal reason, for the reason `fail-closed-must-say-which-failure` records: a
/// fail-closed control that cannot say WHICH failure closed it produces an outage nobody can
/// diagnose. Here the two that must never be confused are [`BadSignature`](Self::BadSignature)
/// ("someone tampered with this, or the wrong key is pinned") and [`Expired`](Self::Expired) ("the
/// release process has not published in a while") — the first is an attack, the second is a
/// calendar, and an operator seeing one message for both would investigate the wrong thing.
#[derive(Debug, thiserror::Error)]
pub enum UpdateManifestError {
    #[error(
        "update manifest signature is invalid (wrong update_signer_pubkey, or the manifest was \
         tampered with)"
    )]
    BadSignature,
    #[error("update manifest expired at {expires_at_ms} (now {now_ms})")]
    Expired { expires_at_ms: i64, now_ms: i64 },
    #[error("update manifest is not yet valid (issued at {issued_at_ms}, now {now_ms})")]
    NotYetValid { issued_at_ms: i64, now_ms: i64 },
    #[error("update manifest sha256 is malformed: {reason}")]
    MalformedSha256 { reason: &'static str },
    #[error("update manifest {field} {value:?} is not a comparable version: {reason}")]
    MalformedVersion { field: &'static str, value: String, reason: VersionParseError },
    #[error("update manifest url is malformed: {reason}")]
    MalformedUrl { reason: &'static str },
    // The variants from here to `Unreadable` belong to format 2 only (see [`SignedUpdateManifestV2`]).
    #[error("update manifest ring {value:?} is not one of canary, early, general")]
    MalformedRing { value: String },
    #[error("update manifest product_version {value:?} is malformed: {reason}")]
    MalformedProductVersion { value: String, reason: &'static str },
    #[error("update manifest {field} {value:?} is not a braced uppercase GUID: {reason}")]
    MalformedGuid { field: &'static str, value: String, reason: &'static str },
    #[error("update manifest format {found} is not supported here (expected 2)")]
    UnsupportedFormat { found: u32 },
    #[error("update manifest at {path} could not be read: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("malformed signed update manifest: {0}")]
    Encoding(String),
}

// =========================================================================================
// UpdateTrust — the fail-closed pin, with no permissive third state
// =========================================================================================

/// Whether this agent will believe an update manifest at all, and against which key.
///
/// **Two variants, and there will never be a third.** The shape is copied from
/// `crates/agent-windows/src/host.rs`'s `BackstageAuth`, whose comment records what an `Option`
/// cost the first time: under the old `Option`, "no issuer" and "self-issue a grant carrying all 19
/// capabilities" were the SAME value, so the authorization system was switched off by *omission*.
/// The equivalent mistake here would be a variant meaning "no key pinned, so accept the manifest as
/// it stands" — i.e. fleet-wide RCE for anyone who can write a file. There is no such variant, and
/// adding one would need this doc comment deleted first.
///
/// The refusal carries its own reason ([`UpdateRefusalReason`]) rather than being a bare marker,
/// for the reason `fail-closed-must-say-which-failure` records in this repository's history: a
/// restored box refused every login for a day because the control that failed closed could not say
/// which of its inputs it had failed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateTrust {
    /// A well-formed release-signer public key is pinned. A manifest is believed if, and only if,
    /// it verifies against this key.
    VerifyWith(PublicIdentity),
    /// No manifest will be believed, for the stated reason.
    RefuseAllUpdates(UpdateRefusalReason),
}

/// Why [`UpdateTrust::from_config`] refused to pin a key. Each maps to a distinct log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRefusalReason {
    /// `update_signer_pubkey` is absent or blank — the state of every machine installed before this
    /// feature existed, and the correct default. Not an alarm.
    NotConfigured,
    /// `update_signer_pubkey` is present but is not a valid Ed25519 public key in hex. An alarm:
    /// somebody intended updates to work here and they will not.
    Malformed,
    /// `update_signer_pubkey` equals `grant_issuer_pubkey`.
    ///
    /// The loudest refusal, and the reason this whole enum exists. docs/21 §3's central claim is
    /// that a control-plane compromise must not yield the ability to sign an update; if the two
    /// keys are the same key, that claim is simply false and nothing else in the system would
    /// notice. Refusing is the only honest response: an operator who did this either has an offline
    /// key to substitute, or has to accept that this deployment does not do updates. Silently
    /// accepting would give them the reassurance of a signature check whose key is sitting in a
    /// `.env` file on an internet-facing box.
    SameKeyAsGrantIssuer,
}

impl std::fmt::Display for UpdateRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateRefusalReason::NotConfigured => {
                write!(f, "no update_signer_pubkey configured")
            }
            UpdateRefusalReason::Malformed => {
                write!(f, "update_signer_pubkey is not a valid Ed25519 hex public key")
            }
            UpdateRefusalReason::SameKeyAsGrantIssuer => write!(
                f,
                "update_signer_pubkey EQUALS grant_issuer_pubkey — the update signing key must \
                 never be the control plane's key (docs/21 §3); a control-plane compromise would \
                 then be fleet-wide code execution"
            ),
        }
    }
}

impl UpdateTrust {
    /// Decide, once, from config. The single place the decision is made, so a test asserts on the
    /// same code the installed service runs.
    ///
    /// * a well-formed key that differs from the grant issuer's ⇒ [`UpdateTrust::VerifyWith`];
    /// * absent, blank, malformed, or equal to `grant_issuer_pubkey` ⇒
    ///   [`UpdateTrust::RefuseAllUpdates`] naming which.
    ///
    /// Both keys are compared as PARSED [`PublicIdentity`] values, not as strings: hex is
    /// case-insensitive and may carry surrounding whitespace, so a string comparison would miss
    /// `ABC…` against `abc…` — and missing it is precisely the failure the check exists to catch.
    pub fn from_config(
        update_signer_pubkey: Option<&str>,
        grant_issuer_pubkey: Option<&str>,
    ) -> Self {
        let hex = match update_signer_pubkey.map(str::trim) {
            Some(h) if !h.is_empty() => h,
            _ => return UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::NotConfigured),
        };
        let key = match PublicIdentity::from_hex(hex) {
            Ok(k) => k,
            Err(_) => return UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::Malformed),
        };
        // A malformed grant_issuer_pubkey is NOT this function's problem — the backstage path
        // already refuses on it, loudly and separately. What matters here is only whether a
        // WELL-FORMED issuer key is the same key, because that is the case where both checks pass
        // individually and the deployment is nonetheless indefensible.
        if let Some(issuer_hex) = grant_issuer_pubkey.map(str::trim) {
            if let Ok(issuer) = PublicIdentity::from_hex(issuer_hex) {
                if issuer == key {
                    return UpdateTrust::RefuseAllUpdates(
                        UpdateRefusalReason::SameKeyAsGrantIssuer,
                    );
                }
            }
        }
        UpdateTrust::VerifyWith(key)
    }

    /// The pinned key, or `None` when every update is refused. Deliberately not an
    /// `unwrap_or_default()`-shaped helper: there is no default key.
    pub fn key(&self) -> Option<&PublicIdentity> {
        match self {
            UpdateTrust::VerifyWith(k) => Some(k),
            UpdateTrust::RefuseAllUpdates(_) => None,
        }
    }
}

// =========================================================================================
// Version comparison — this tree's first version comparator
// =========================================================================================

/// A parsed `major.minor.patch`, with semver build metadata already discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    /// Breaking-change component.
    pub major: u64,
    /// Feature component.
    pub minor: u64,
    /// Fix component.
    pub patch: u64,
}

/// Why a version string could not be compared.
///
/// A parse FAILURE is a refusal to order, never a guess. Nothing in this module treats an
/// unparseable version as "old" or as "new": [`Release::availability`] propagates the error and the
/// caller reports "cannot tell", because a comparator that guesses is how a fleet gets told an
/// update is available when it is not — or, worse, that it is up to date when it is not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionParseError {
    #[error("empty version string")]
    Empty,
    #[error("longer than the {MAX_VERSION_LEN}-character maximum")]
    TooLong,
    #[error("expected exactly 3 dot-separated components, found {found}")]
    WrongComponentCount { found: usize },
    #[error("component {index} is empty")]
    EmptyComponent { index: usize },
    #[error("component {index} ({value:?}) is not a decimal number")]
    NotNumeric { index: usize, value: String },
    #[error("component {index} ({value:?}) has a leading zero")]
    LeadingZero { index: usize, value: String },
    #[error("component {index} ({value:?}) does not fit in a u64")]
    Overflow { index: usize, value: String },
    #[error("pre-release versions are not comparable here ({value:?})")]
    PreReleaseUnsupported { value: String },
}

/// Parse `<major>.<minor>.<patch>`, discarding semver **build metadata** after the first `+`.
///
/// Build metadata is discarded because [semver §10](https://semver.org/#spec-item-10) says it is
/// "ignored when determining version precedence" — and `crates/agent-core/src/version.rs` builds
/// `AGENT_VERSION` as exactly `<crate version>+<short git sha>` for that reason: two builds of
/// `0.0.1` from different commits are the same *version* and different *builds*. So `0.0.1+abc` and
/// `0.0.1+def` compare EQUAL here, and `tests::build_metadata_is_ignored_for_precedence` pins it.
/// That is not a technicality — it is what makes "a rebuild is not an update" true, and without it
/// every agent would report an update available against every rebuild of its own version forever.
///
/// **Pre-release versions (`1.0.0-rc1`) are REFUSED, not ordered.** Semver's pre-release precedence
/// rules are real and fiddly (dot-separated identifiers, numeric vs alphanumeric, shorter-set-wins),
/// and implementing a subset of them would mean this comparator quietly disagrees with semver on
/// some inputs. Refusing is honest and fails closed: an agent built from a pre-release tag reports
/// "cannot compare versions" rather than a wrong answer. If pre-releases ever ship, implement the
/// full rule and give it its own golden table — do not extend this by intuition.
pub fn parse_version(s: &str) -> Result<SemVer, VersionParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(VersionParseError::Empty);
    }
    if s.len() > MAX_VERSION_LEN {
        return Err(VersionParseError::TooLong);
    }
    // Build metadata: everything from the FIRST '+' onward, discarded. Note the split is on the
    // first '+', not the last — `1.2.3+a+b` has one metadata field containing a '+', which is
    // still metadata and still ignored.
    let core = s.split_once('+').map(|(before, _)| before).unwrap_or(s);
    if core.is_empty() {
        return Err(VersionParseError::Empty);
    }
    if core.contains('-') {
        return Err(VersionParseError::PreReleaseUnsupported { value: s.to_string() });
    }

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(VersionParseError::WrongComponentCount { found: parts.len() });
    }
    let mut out = [0u64; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(VersionParseError::EmptyComponent { index });
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(VersionParseError::NotNumeric { index, value: (*part).to_string() });
        }
        // Semver forbids leading zeroes in numeric identifiers, and this refuses rather than
        // normalizes: `01` and `1` parsing to the same value would make two DIFFERENT signed
        // manifests describe the same release, and a release process that emitted `0.04.0` once
        // would be silently accepted and then silently disagree with every other tool that reads
        // the string.
        if part.len() > 1 && part.starts_with('0') {
            return Err(VersionParseError::LeadingZero { index, value: (*part).to_string() });
        }
        out[index] = part
            .parse::<u64>()
            .map_err(|_| VersionParseError::Overflow { index, value: (*part).to_string() })?;
    }
    Ok(SemVer { major: out[0], minor: out[1], patch: out[2] })
}

/// Order two version strings by semver precedence (build metadata ignored).
///
/// Returns an error if EITHER side is unparseable; see [`VersionParseError`] for why that is a
/// refusal rather than a fallback to string comparison.
pub fn compare_versions(a: &str, b: &str) -> Result<Ordering, VersionParseError> {
    Ok(parse_version(a)?.cmp(&parse_version(b)?))
}

// =========================================================================================
// Availability — the ONLY thing step 2 does with a verified manifest
// =========================================================================================

/// What a verified manifest means for THIS agent.
///
/// Three outcomes, and the important one is that two of them are not errors. A correctly signed
/// manifest describing a version that is not newer is a perfectly good manifest; so is one whose
/// upgrade path this build is too old for. Reporting either as a failure would train an operator to
/// ignore the failure that matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAvailability {
    /// The manifest names a version equal to or older than the running one. The expected steady
    /// state of an up-to-date fleet, and the NEGATIVE CONTROL for every other test in this module:
    /// code that reported "update available" unconditionally would pass everything else.
    NoUpdate { running: String, offered: String },
    /// Newer, and this build is on the manifest's supported upgrade path.
    Available { running: String, offered: String },
    /// Newer, but the running build is older than `min_upgradable_from`, so this release refuses to
    /// be reached from here (docs/21 §7). A machine in this state needs a human, which is exactly
    /// what the field is for.
    UpgradePathUnsupported { running: String, offered: String, min_upgradable_from: String },
}

impl UpdateAvailability {
    /// Is an update both newer AND reachable from here? The one question step 3 would ask.
    pub fn is_available(&self) -> bool {
        matches!(self, UpdateAvailability::Available { .. })
    }
}

impl Release {
    /// Compare this release against the running agent's version.
    ///
    /// `running_version` is `rmt_agent_core::version::AGENT_VERSION` on the real path — passed in
    /// as a `&str` rather than read from a constant so this crate needs no dependency on
    /// `rmt-agent-core` (see `agent/Cargo.toml`: `rmt-agent` deliberately depends on no workspace
    /// crate but `rmt-crypto`) and so a test can name both sides.
    ///
    /// The `min_upgradable_from` check runs only when the release is actually newer, and that
    /// ordering is deliberate: an old manifest left lying around should report
    /// [`NoUpdate`](UpdateAvailability::NoUpdate), not a confusing complaint about an upgrade path
    /// to a version nobody is being offered.
    pub fn availability(
        &self,
        running_version: &str,
    ) -> Result<UpdateAvailability, VersionParseError> {
        availability_of(&self.version, &self.min_upgradable_from, running_version)
    }
}

/// The one decision procedure behind [`Release::availability`] and
/// [`ReleaseV2::availability`], taking the two fields that decide it. Shared so that the two
/// formats can never disagree about what "newer" or "reachable from here" means.
fn availability_of(
    offered: &str,
    min_upgradable_from: &str,
    running_version: &str,
) -> Result<UpdateAvailability, VersionParseError> {
    // Both comparisons go through [`compare_versions`], deliberately, rather than through
    // `SemVer`'s derived `Ord`. There must be exactly ONE place that decides which of two
    // versions is newer: with two paths, a mutation to the public comparator would leave this
    // function — the one that actually decides whether the fleet is told an update exists —
    // untouched, and the tests over the comparator would prove nothing about it.
    if compare_versions(offered, running_version)? != Ordering::Greater {
        return Ok(UpdateAvailability::NoUpdate {
            running: running_version.to_string(),
            offered: offered.to_string(),
        });
    }
    if compare_versions(running_version, min_upgradable_from)? == Ordering::Less {
        return Ok(UpdateAvailability::UpgradePathUnsupported {
            running: running_version.to_string(),
            offered: offered.to_string(),
            min_upgradable_from: min_upgradable_from.to_string(),
        });
    }
    Ok(UpdateAvailability::Available {
        running: running_version.to_string(),
        offered: offered.to_string(),
    })
}

// =========================================================================================
// Format 2 — the MSI-delivering manifest
// =========================================================================================
//
// Format 1 (above) describes a bare agent binary. Format 2 describes a Windows Installer package:
// the same trust model, the same single update key, the same verify order, but a different release
// body (a `ring`, the MSI's digest and URL, and the identifiers Windows Installer itself keys on)
// and a different domain tag. It lives BESIDE v1 rather than replacing it because agents in the
// field only know v1, and `format` is what lets each side refuse the other's JSON instead of
// half-reading it: the v1 structs deny unknown fields (so `"format"` is refused there), and the v2
// struct requires `format` (so v1 JSON is refused here).

/// The only `format` value [`SignedUpdateManifestV2`] accepts.
pub const MANIFEST_FORMAT_V2: u32 = 2;

/// The rollout rings a v2 release may name. Exact, lowercase, closed set: a typo'd ring would
/// otherwise be a signed manifest no ring ever selects, or one a ring selects by accident.
pub const RELEASE_RINGS: [&str; 3] = ["canary", "early", "general"];

/// What a format-2 release IS. Field set and order are the signed preimage order AND the JSON field
/// order; changing either breaks the cross-language golden vectors, which is the intended alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on an unknown field, for the reason spelled out on [`Release`].
#[serde(deny_unknown_fields)]
pub struct ReleaseV2 {
    /// Rollout ring: exactly one of [`RELEASE_RINGS`].
    pub ring: String,
    /// Agent semver, under the same rules as [`Release::version`] (see [`parse_version`]).
    pub version: String,
    /// Lowercase hex SHA-256 of the MSI, exactly 64 characters. Uppercase is refused, never folded.
    pub msi_sha256: String,
    /// Where the MSI is fetched from. `https://` only, bounded, no control characters.
    pub msi_url: String,
    /// The MSI `ProductVersion`: `a.b.c` with a, b <= 255 and c <= 65535 (the Windows Installer
    /// limits). Distinct from `version` because Windows Installer ignores a 4th field and caps the
    /// others, so the agent semver cannot be used as-is.
    pub product_version: String,
    /// The MSI `ProductCode`: a braced UPPERCASE GUID.
    pub product_code: String,
    /// The MSI `UpgradeCode`: a braced UPPERCASE GUID. Stable across releases.
    pub upgrade_code: String,
    /// The oldest running version permitted to take this upgrade, as in v1.
    pub min_upgradable_from: String,
}

/// [`ReleaseV2`] plus its validity window (Unix milliseconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on an unknown field at every level; see [`UpdateManifestClaims`].
#[serde(deny_unknown_fields)]
pub struct UpdateManifestClaimsV2 {
    /// The release these claims describe.
    pub release: ReleaseV2,
    /// When the release process signed this manifest (Unix ms).
    pub issued_at_ms: i64,
    /// When this manifest stops being believed (Unix ms, exclusive).
    pub expires_at_ms: i64,
}

impl UpdateManifestClaimsV2 {
    /// The canonical update-v2 signing bytes: the v2 tag, then every release field as a
    /// length-prefixed string in declaration order, then the two window integers. Mirrored in Go by
    /// `UpdateManifestV2SigningBytes`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let r = &self.release;
        let mut w = CanonicalWriter::new();
        w.update_v2_tag()
            .lp_str(&r.ring)
            .lp_str(&r.version)
            .lp_str(&r.msi_sha256)
            .lp_str(&r.msi_url)
            .lp_str(&r.product_version)
            .lp_str(&r.product_code)
            .lp_str(&r.upgrade_code)
            .lp_str(&r.min_upgradable_from)
            .i64(self.issued_at_ms)
            .i64(self.expires_at_ms);
        w.into_bytes()
    }

    /// Sign these claims. **Test and tooling surface only**, for the reason given on
    /// [`UpdateManifestClaims::sign`]: the agent verifies, and only the offline
    /// `control-plane/cmd/rmt-update-sign` signs for real.
    pub fn sign(&self, signer: &Identity) -> SignedUpdateManifestV2 {
        let sig = signer.sign(&self.signing_bytes());
        SignedUpdateManifestV2 {
            format: MANIFEST_FORMAT_V2,
            claims: self.clone(),
            sig: hex::encode(sig),
        }
    }
}

/// A format-2 manifest as it sits on the wire: `{"format":2,"claims":{...},"sig":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Fail closed on an unknown field; see [`Release`].
#[serde(deny_unknown_fields)]
pub struct SignedUpdateManifestV2 {
    /// Wire discriminator; must equal [`MANIFEST_FORMAT_V2`]. Not part of the preimage (the domain
    /// tag already separates the formats under the signature); it exists so a reader refuses a
    /// manifest of the wrong generation by name instead of by a missing-field accident.
    pub format: u32,
    /// The signed claims.
    pub claims: UpdateManifestClaimsV2,
    /// Hex-encoded 64-byte Ed25519 signature over
    /// [`signing_bytes`](UpdateManifestClaimsV2::signing_bytes).
    pub sig: String,
}

impl SignedUpdateManifestV2 {
    /// Encode to the JSON wire string.
    pub fn to_json(&self) -> Result<String, UpdateManifestError> {
        serde_json::to_string(self).map_err(|e| UpdateManifestError::Encoding(e.to_string()))
    }

    /// Decode from the JSON wire string, refusing any `format` other than 2. Does **not** verify.
    ///
    /// v1 JSON has no `format` key and fails here as a missing field; v2 JSON given to the v1
    /// decoder fails there as an unknown one. Both directions are tested.
    pub fn from_json(s: &str) -> Result<Self, UpdateManifestError> {
        let m: Self =
            serde_json::from_str(s).map_err(|e| UpdateManifestError::Encoding(e.to_string()))?;
        m.check_format()?;
        Ok(m)
    }

    fn check_format(&self) -> Result<(), UpdateManifestError> {
        if self.format != MANIFEST_FORMAT_V2 {
            return Err(UpdateManifestError::UnsupportedFormat { found: self.format });
        }
        Ok(())
    }

    /// Verify exactly as [`SignedUpdateManifest::verify`] does, and in the same order: signature
    /// FIRST, then not-yet-valid (with [`CLOCK_SKEW_MS`]), then expired (exact), then the shape of
    /// every self-claimed field, in field order. See that method for why the order is the security
    /// property; nothing here relaxes it.
    ///
    /// `format` is checked before the signature because it is the wire discriminator, not a claim:
    /// it says which verifier to run at all, and the only attacker-chosen value it can put in an
    /// error is a `u32`.
    pub fn verify(
        &self,
        signer: &PublicIdentity,
        now_ms: i64,
    ) -> Result<ReleaseV2, UpdateManifestError> {
        self.check_format()?;

        let bytes = self.claims.signing_bytes();
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|_| UpdateManifestError::Encoding("signature is not hex".into()))?;
        let sig: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| UpdateManifestError::Encoding("signature is not 64 bytes".into()))?;

        signer.verify(&bytes, &sig).map_err(|_| UpdateManifestError::BadSignature)?;

        if now_ms + CLOCK_SKEW_MS < self.claims.issued_at_ms {
            return Err(UpdateManifestError::NotYetValid {
                issued_at_ms: self.claims.issued_at_ms,
                now_ms,
            });
        }
        if now_ms >= self.claims.expires_at_ms {
            return Err(UpdateManifestError::Expired {
                expires_at_ms: self.claims.expires_at_ms,
                now_ms,
            });
        }

        let r = &self.claims.release;
        if !RELEASE_RINGS.contains(&r.ring.as_str()) {
            return Err(UpdateManifestError::MalformedRing { value: r.ring.clone() });
        }
        if let Err(e) = parse_version(&r.version) {
            return Err(UpdateManifestError::MalformedVersion {
                field: "version",
                value: r.version.clone(),
                reason: e,
            });
        }
        if let Err(reason) = check_sha256_hex(&r.msi_sha256) {
            return Err(UpdateManifestError::MalformedSha256 { reason });
        }
        if let Err(reason) = check_url(&r.msi_url) {
            return Err(UpdateManifestError::MalformedUrl { reason });
        }
        if let Err(reason) = check_product_version(&r.product_version) {
            return Err(UpdateManifestError::MalformedProductVersion {
                value: r.product_version.clone(),
                reason,
            });
        }
        for (field, value) in [("product_code", &r.product_code), ("upgrade_code", &r.upgrade_code)]
        {
            if let Err(reason) = check_braced_guid(value) {
                return Err(UpdateManifestError::MalformedGuid {
                    field,
                    value: value.clone(),
                    reason,
                });
            }
        }
        if let Err(e) = parse_version(&r.min_upgradable_from) {
            return Err(UpdateManifestError::MalformedVersion {
                field: "min_upgradable_from",
                value: r.min_upgradable_from.clone(),
                reason: e,
            });
        }

        Ok(r.clone())
    }
}

impl ReleaseV2 {
    /// Compare this release against the running agent's version, with exactly
    /// [`Release::availability`]'s semantics (the two share one implementation).
    pub fn availability(
        &self,
        running_version: &str,
    ) -> Result<UpdateAvailability, VersionParseError> {
        availability_of(&self.version, &self.min_upgradable_from, running_version)
    }
}

/// Windows Installer's `ProductVersion` limits: `major.minor.build`, 8/8/16 bits.
const PRODUCT_VERSION_LIMITS: [u32; 3] = [255, 255, 65535];

/// Shape-check a `ProductVersion`: exactly three dot-separated decimal fields within Windows
/// Installer's limits, no sign, no whitespace, no leading zeros (except a lone `0`).
///
/// Refused rather than normalised for the same reason as [`parse_version`]'s leading-zero rule:
/// `1.03.0` and `1.3.0` would otherwise be two different signed strings for one installed version,
/// and a field of 256 is truncated or rejected by Windows Installer itself, so a manifest carrying
/// one would describe an upgrade the installer cannot perform.
fn check_product_version(s: &str) -> Result<(), &'static str> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("expected exactly 3 dot-separated fields");
    }
    for (part, limit) in parts.iter().zip(PRODUCT_VERSION_LIMITS) {
        if part.is_empty() {
            return Err("a field is empty");
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err("fields must be decimal digits only");
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err("a field has a leading zero");
        }
        // At most 5 digits can be in range, so capping the length first means the parse cannot
        // overflow.
        if part.len() > 5 || part.parse::<u32>().map_or(true, |n| n > limit) {
            return Err("a field exceeds the Windows Installer limit (255.255.65535)");
        }
    }
    Ok(())
}

/// Shape-check a braced uppercase GUID: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, hex digits 0-9
/// A-F only. Lowercase is refused, never folded: the GUID sits in the preimage as a string, and
/// Windows Installer compares ProductCode case-sensitively.
fn check_braced_guid(s: &str) -> Result<(), &'static str> {
    const LEN: usize = 38;
    // Dashes follow the 8th, 12th, 16th and 20th hex digit; these are offsets into the braced string.
    const DASHES: [usize; 4] = [9, 14, 19, 24];
    let b = s.as_bytes();
    if b.len() != LEN {
        return Err("expected exactly 38 characters");
    }
    if b[0] != b'{' || b[LEN - 1] != b'}' {
        return Err("expected surrounding braces");
    }
    for (i, &c) in b.iter().enumerate().take(LEN - 1).skip(1) {
        if DASHES.contains(&i) {
            if c != b'-' {
                return Err("expected the 8-4-4-4-12 dash layout");
            }
        } else if !(c.is_ascii_digit() || (b'A'..=b'F').contains(&c)) {
            return Err("expected uppercase hex only (0-9, A-F)");
        }
    }
    Ok(())
}

// =========================================================================================
// The one call the agent makes: load, verify, compare, and say what happened
// =========================================================================================

/// Everything step 2 has to report, as one value.
///
/// Deliberately a single enum rather than a `Result<Option<..>>` tangle at the call site: the host
/// has exactly one job with this — turn it into a log line — and every case it must distinguish is
/// a variant here, so a new case cannot be silently swallowed by a `_ =>` arm in `host.rs`.
#[derive(Debug)]
pub enum UpdateCheck {
    /// No `update-manifest.json` on this machine. The normal state; log nothing loud.
    NoManifest,
    /// A manifest exists but this agent refuses every update, and why. Logged as a WARNING even
    /// though the common case ([`UpdateRefusalReason::NotConfigured`]) is benign, because a
    /// manifest that someone bothered to place and the agent will never read is a
    /// misconfiguration worth seeing.
    Refused(UpdateRefusalReason),
    /// A manifest exists and did not verify. The loud case.
    Invalid(UpdateManifestError),
    /// A manifest verified, but its versions could not be compared with the running one.
    Incomparable { running: String, offered: String, reason: VersionParseError },
    /// A manifest verified and was compared.
    Verified { release: Release, availability: UpdateAvailability },
}

/// Load, verify and evaluate the manifest at `path` — the whole of step 2, in one call.
///
/// Note the order once more: the file is read, DECODED, and only then verified; and no field of the
/// decoded manifest is looked at, logged or compared until [`SignedUpdateManifest::verify`] has
/// returned `Ok`. The caller receives already-verified values or an error, and never both.
pub fn check_for_update(
    path: &Path,
    trust: &UpdateTrust,
    running_version: &str,
    now_ms: i64,
) -> UpdateCheck {
    let signed = match SignedUpdateManifest::from_file(path) {
        Ok(None) => return UpdateCheck::NoManifest,
        Ok(Some(m)) => m,
        Err(e) => return UpdateCheck::Invalid(e),
    };
    // The refusal check sits AFTER the file read on purpose. An agent with no pinned key that has a
    // manifest sitting on disk is a misconfiguration an operator wants told about; if the refusal
    // short-circuited first, that machine would look identical to one that simply has no manifest.
    let key = match trust {
        UpdateTrust::VerifyWith(k) => k,
        UpdateTrust::RefuseAllUpdates(reason) => return UpdateCheck::Refused(reason.clone()),
    };
    let release = match signed.verify(key, now_ms) {
        Ok(r) => r,
        Err(e) => return UpdateCheck::Invalid(e),
    };
    match release.availability(running_version) {
        Ok(availability) => UpdateCheck::Verified { release, availability },
        Err(reason) => UpdateCheck::Incomparable {
            running: running_version.to_string(),
            offered: release.version,
            reason,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER_SEED: [u8; 32] = [7u8; 32];
    const RUNNING: &str = "0.3.0+0594362";

    fn release() -> Release {
        Release {
            version: "0.4.0".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            url: "https://updates.deskrally.com/rmt-agent-0.4.0.exe".into(),
            min_upgradable_from: "0.2.0".into(),
        }
    }

    fn claims(now: i64, ttl: i64) -> UpdateManifestClaims {
        UpdateManifestClaims { release: release(), issued_at_ms: now, expires_at_ms: now + ttl }
    }

    fn signer() -> Identity {
        Identity::from_seed(&SIGNER_SEED)
    }

    // -------------------------------------------------------------------------------------
    // verify() — the checks, one at a time
    // -------------------------------------------------------------------------------------

    #[test]
    fn a_genuine_manifest_verifies() {
        let s = signer();
        let now = 1_730_000_000_000;
        let signed = claims(now, 2_592_000_000).sign(&s);
        let r = signed.verify(&s.public(), now + 1_000).expect("a genuine manifest verifies");
        assert_eq!(r, release());
    }

    /// The signature must catch a tampered field BEFORE any shape check does, or a forger picks
    /// which error they see — and, worse here, gets an attacker-chosen URL into the agent's log
    /// before anything authenticated it. The tampered value is deliberately a WELL-FORMED https URL
    /// so the only thing that can refuse it is the signature.
    #[test]
    fn a_tampered_url_fails_the_signature_first() {
        let s = signer();
        let now = 1_730_000_000_000;
        let mut signed = claims(now, 2_592_000_000).sign(&s);
        signed.claims.release.url = "https://evil.example/backdoor.exe".into();
        assert!(matches!(
            signed.verify(&s.public(), now + 1_000),
            Err(UpdateManifestError::BadSignature)
        ));
    }

    /// The same, for the digest — the field step 3 would use to decide a downloaded file is the
    /// right one.
    #[test]
    fn a_tampered_sha256_fails_the_signature() {
        let s = signer();
        let now = 1_730_000_000_000;
        let mut signed = claims(now, 2_592_000_000).sign(&s);
        signed.claims.release.sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(matches!(
            signed.verify(&s.public(), now + 1_000),
            Err(UpdateManifestError::BadSignature)
        ));
    }

    /// THE ORDER, pinned rather than merely documented.
    ///
    /// A manifest that fails TWO checks at once must report the EARLIER one. Without this, the
    /// checks could be reordered freely and every other test in this module would still pass:
    /// each of them fails exactly one check, so each is satisfied by any order.
    ///
    /// Why the order is the security property, not a preference. Everything after the signature is
    /// a field the *manifest* asserts; the signature is the only reason to believe any of them.
    /// Reporting a shape complaint about an unauthenticated manifest means the agent has read,
    /// judged and logged attacker-controlled text — including a URL naming an executable — before
    /// establishing that anyone it trusts wrote it. It also hands a forger a way to choose which
    /// error they see, which is how a verifier gets probed.
    #[test]
    fn the_signature_is_checked_before_anything_the_manifest_claims() {
        let s = signer();
        let attacker = Identity::from_seed(&[9u8; 32]);
        let now = 1_730_000_000_000;

        // Signed by the WRONG key AND malformed in every self-claimed field at once.
        let mut c = claims(now, 2_592_000_000);
        c.release.sha256 = "not-a-digest".into();
        c.release.url = "file:///C:/evil.exe".into();
        c.release.version = "banana".into();
        c.release.min_upgradable_from = String::new();
        let signed = c.sign(&attacker);
        assert!(
            matches!(signed.verify(&s.public(), now + 1_000), Err(UpdateManifestError::BadSignature)),
            "a forged manifest must be refused for its SIGNATURE, before any field it carries"
        );

        // Freshness outranks the field shapes too: an EXPIRED but correctly signed manifest with a
        // malformed digest reports Expired, not MalformedSha256.
        let mut c = claims(now, 2_592_000_000);
        c.release.sha256 = "not-a-digest".into();
        let signed = c.sign(&s);
        assert!(
            matches!(
                signed.verify(&s.public(), now + 2_592_000_000),
                Err(UpdateManifestError::Expired { .. })
            ),
            "expiry must be reported before a field shape"
        );
        // …and the same manifest inside its window DOES reach the shape check, so the assertion
        // above is about ORDER and not about the shape check being unreachable.
        assert!(matches!(
            signed.verify(&s.public(), now + 1_000),
            Err(UpdateManifestError::MalformedSha256 { .. })
        ));
    }

    #[test]
    fn a_manifest_from_another_key_is_refused() {
        let s = signer();
        let attacker = Identity::from_seed(&[9u8; 32]);
        let now = 1_730_000_000_000;
        let signed = claims(now, 2_592_000_000).sign(&attacker);
        assert!(matches!(
            signed.verify(&s.public(), now + 1_000),
            Err(UpdateManifestError::BadSignature)
        ));
    }

    #[test]
    fn the_validity_window_is_enforced_at_both_ends() {
        let s = signer();
        let now = 1_730_000_000_000;
        let ttl = 2_592_000_000;
        let signed = claims(now, ttl).sign(&s);

        // Expiry is EXACT: at expires_at_ms the manifest is already dead.
        assert!(matches!(
            signed.verify(&s.public(), now + ttl),
            Err(UpdateManifestError::Expired { .. })
        ));
        assert!(signed.verify(&s.public(), now + ttl - 1).is_ok());

        // Not-yet-valid tolerates CLOCK_SKEW_MS, one-sided.
        assert!(signed.verify(&s.public(), now - CLOCK_SKEW_MS).is_ok());
        assert!(matches!(
            signed.verify(&s.public(), now - CLOCK_SKEW_MS - 1),
            Err(UpdateManifestError::NotYetValid { .. })
        ));
    }

    /// A malformed digest is refused — but only on a manifest that is otherwise genuine, which is
    /// the only way to reach the check at all. Signing the bad value is the point: it proves the
    /// shape check is a real check and not an accident of the signature covering the field.
    #[test]
    fn a_malformed_sha256_is_refused_even_when_signed() {
        let s = signer();
        let now = 1_730_000_000_000;
        let bad = [
            // Too short.
            "e3b0c442",
            // Too long.
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500",
            // Correct length, UPPERCASE — refused rather than folded (see check_sha256_hex).
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            // Correct length, not hex.
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            // Empty.
            "",
        ];
        for value in bad {
            let mut c = claims(now, 2_592_000_000);
            c.release.sha256 = value.into();
            let signed = c.sign(&s);
            assert!(
                matches!(
                    signed.verify(&s.public(), now + 1_000),
                    Err(UpdateManifestError::MalformedSha256 { .. })
                ),
                "sha256 {value:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_malformed_url_is_refused_even_when_signed() {
        let s = signer();
        let now = 1_730_000_000_000;
        let bad = [
            "http://updates.example/agent.exe",
            "file:///C:/rmt-agent/agent.exe",
            r"\\evil\share\agent.exe",
            "updates.example/agent.exe",
            "https://",
            "https://updates.example/a\nb.exe",
        ];
        for value in bad {
            let mut c = claims(now, 2_592_000_000);
            c.release.url = value.into();
            let signed = c.sign(&s);
            assert!(
                matches!(
                    signed.verify(&s.public(), now + 1_000),
                    Err(UpdateManifestError::MalformedUrl { .. })
                ),
                "url {value:?} should have been refused"
            );
        }
    }

    #[test]
    fn a_malformed_version_is_refused_even_when_signed() {
        let s = signer();
        let now = 1_730_000_000_000;
        for (field, v, m) in [
            ("version", "not-a-version", "0.2.0"),
            ("version", "0.4", "0.2.0"),
            ("version", "", "0.2.0"),
            ("min_upgradable_from", "0.4.0", "banana"),
            ("min_upgradable_from", "0.4.0", "0.2"),
        ] {
            let mut c = claims(now, 2_592_000_000);
            c.release.version = v.into();
            c.release.min_upgradable_from = m.into();
            let signed = c.sign(&s);
            match signed.verify(&s.public(), now + 1_000) {
                Err(UpdateManifestError::MalformedVersion { field: got, .. }) => {
                    assert_eq!(got, field, "wrong field named for ({v:?}, {m:?})")
                }
                other => panic!("({v:?}, {m:?}) should have been refused, got {other:?}"),
            }
        }
    }

    /// A signature that is not hex, or is hex of the wrong length, must be an ENCODING refusal
    /// rather than a panic or a `BadSignature` — the two say different things to an operator.
    #[test]
    fn a_malformed_signature_is_an_encoding_error() {
        let s = signer();
        let now = 1_730_000_000_000;
        for sig in ["", "zz", "abcd", &"ab".repeat(63), &"ab".repeat(65)] {
            let mut signed = claims(now, 2_592_000_000).sign(&s);
            signed.sig = sig.to_string();
            assert!(
                matches!(
                    signed.verify(&s.public(), now + 1_000),
                    Err(UpdateManifestError::Encoding(_))
                ),
                "sig {sig:?} should have been an encoding error"
            );
        }
    }

    /// Malformed JSON, and JSON that is well-formed but not a manifest, must both fail to DECODE
    /// rather than deserialize into something with default fields. serde has no defaults on these
    /// structs, so this is structural — assert it anyway, because a later `#[serde(default)]` added
    /// for "compatibility" would turn a missing `url` into `""` on a path where the whole point is
    /// that every field is signed.
    #[test]
    fn malformed_manifest_json_does_not_decode() {
        let bad = [
            "",
            "{",
            "null",
            "[]",
            r#"{"claims":{},"sig":"ab"}"#,
            // Every field but `url`.
            r#"{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c442","min_upgradable_from":"0.2.0"},"issued_at_ms":1,"expires_at_ms":2},"sig":"ab"}"#,
            // `issued_at_ms` as a string.
            r#"{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c442","url":"https://x/y","min_upgradable_from":"0.2.0"},"issued_at_ms":"1","expires_at_ms":2},"sig":"ab"}"#,
            // No signature at all — the one shape an "unsigned manifest" would arrive as.
            r#"{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c442","url":"https://x/y","min_upgradable_from":"0.2.0"},"issued_at_ms":1,"expires_at_ms":2}}"#,
        ];
        for js in bad {
            assert!(
                SignedUpdateManifest::from_json(js).is_err(),
                "{js:?} should not have decoded"
            );
        }
    }

    /// An unknown field must fail to DECODE at every level of the structure, not just the
    /// outermost. serde checks `deny_unknown_fields` per-struct, so a missing attribute on the
    /// inner types would leave a stray key inside `claims` silently ignored while the same key at
    /// the top level was refused — and "silently ignored" is the wrong direction for an artifact
    /// where every field is signed and load-bearing.
    ///
    /// The positive control is the genuine JSON in the same test: without it, a decoder that
    /// rejected EVERYTHING would pass.
    #[test]
    fn an_unknown_field_does_not_decode_at_any_level() {
        let s = signer();
        let genuine = claims(1_730_000_000_000, 2_592_000_000).sign(&s).to_json().unwrap();
        assert!(SignedUpdateManifest::from_json(&genuine).is_ok(), "positive control");

        for (name, injected) in [
            ("top level", genuine.replacen(r#"{"claims""#, r#"{"rollback":true,"claims""#, 1)),
            ("claims", genuine.replacen(r#""issued_at_ms""#, r#""ring":"canary","issued_at_ms""#, 1)),
            ("release", genuine.replacen(r#""version""#, r#""exec":"cmd.exe","version""#, 1)),
        ] {
            assert_ne!(injected, genuine, "{name}: the fixture did not actually change");
            assert!(
                SignedUpdateManifest::from_json(&injected).is_err(),
                "an unknown field at {name} must be refused"
            );
        }
    }

    /// Every field of `Release` must be inside the preimage. Proven one field at a time against the
    /// unmodified baseline, because a test that changed them all together would pass even if only
    /// one of them were signed. The `url` case is the one that matters most: it names what gets
    /// executed.
    #[test]
    fn every_release_field_changes_the_preimage() {
        let base = claims(1_730_000_000_000, 2_592_000_000);
        let baseline = base.signing_bytes();

        let mutations: [(&str, fn(&mut UpdateManifestClaims)); 6] = [
            ("version", |c| c.release.version = "0.4.1".into()),
            ("sha256", |c| {
                c.release.sha256 =
                    "0000000000000000000000000000000000000000000000000000000000000000".into()
            }),
            ("url", |c| c.release.url = "https://evil.example/backdoor.exe".into()),
            ("min_upgradable_from", |c| c.release.min_upgradable_from = "0.3.0".into()),
            ("issued_at_ms", |c| c.issued_at_ms += 1),
            ("expires_at_ms", |c| c.expires_at_ms += 1),
        ];
        for (name, mutate) in mutations {
            let mut c = base.clone();
            mutate(&mut c);
            assert_ne!(
                c.signing_bytes(),
                baseline,
                "changing {name} did not change the signing bytes — the field is not signed"
            );
        }
        // The premise, established locally rather than assumed: an UNCHANGED clone must produce the
        // SAME bytes. Without this a `signing_bytes` that returned a random nonce would pass every
        // assertion above.
        assert_eq!(base.clone().signing_bytes(), baseline);
    }

    /// The preimage opens with the update tag and nothing else could be mistaken for it. Pairwise
    /// distinctness of the constants is asserted in `backstage::canonical`; this asserts the
    /// ENCODER actually puts the right one at the front, which is the property that would break if
    /// someone copied `signing_bytes` from `elevation.rs` and forgot the one changed line.
    #[test]
    fn the_preimage_is_domain_separated() {
        use crate::backstage::canonical::{ELEVATION_DOMAIN_TAG, UPDATE_DOMAIN_TAG};
        let bytes = claims(1_730_000_000_000, 2_592_000_000).signing_bytes();
        assert_eq!(&bytes[..12], &UPDATE_DOMAIN_TAG);
        assert_ne!(&bytes[..12], &ELEVATION_DOMAIN_TAG);
    }

    // -------------------------------------------------------------------------------------
    // UpdateTrust — fail closed, and say which failure
    // -------------------------------------------------------------------------------------

    #[test]
    fn a_well_formed_distinct_key_is_pinned() {
        let update = Identity::from_seed(&[1u8; 32]).public_hex();
        let issuer = Identity::from_seed(&[2u8; 32]).public_hex();
        match UpdateTrust::from_config(Some(&update), Some(&issuer)) {
            UpdateTrust::VerifyWith(k) => assert_eq!(k.to_hex(), update),
            other => panic!("expected a pinned key, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_or_blank_key_refuses_every_update() {
        for v in [None, Some(""), Some("   ")] {
            assert_eq!(
                UpdateTrust::from_config(v, None),
                UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::NotConfigured),
                "{v:?} must refuse"
            );
        }
    }

    #[test]
    fn a_malformed_key_refuses_every_update() {
        for v in ["nonsense", "ab", &"f".repeat(63), &"f".repeat(65)] {
            assert_eq!(
                UpdateTrust::from_config(Some(v), None),
                UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::Malformed),
                "{v:?} must refuse"
            );
        }
    }

    /// docs/21 §3's central claim, made enforceable. Also asserted through case and whitespace
    /// differences, because a string comparison would pass those through and the whole check would
    /// be defeated by a copy-paste that happened to change the case.
    #[test]
    fn reusing_the_grant_issuer_key_refuses_every_update() {
        let shared = Identity::from_seed(&[3u8; 32]).public_hex();
        for update in [shared.clone(), shared.to_uppercase(), format!("  {shared}  ")] {
            assert_eq!(
                UpdateTrust::from_config(Some(&update), Some(&shared)),
                UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::SameKeyAsGrantIssuer),
                "{update:?} is the issuer key and must refuse"
            );
        }
        // The NEGATIVE control for the check above: a different key with the same length and shape
        // must still be pinned, or the test would pass against a version that refused everything.
        let other = Identity::from_seed(&[4u8; 32]).public_hex();
        assert!(matches!(
            UpdateTrust::from_config(Some(&other), Some(&shared)),
            UpdateTrust::VerifyWith(_)
        ));
    }

    /// There is no variant that accepts an unverifiable manifest, and `key()` is the only way to
    /// get a verifying key out — so a refusal cannot be turned into an acceptance by a caller.
    #[test]
    fn a_refusal_yields_no_key() {
        assert!(UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::NotConfigured).key().is_none());
        assert!(UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::Malformed).key().is_none());
        assert!(UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::SameKeyAsGrantIssuer)
            .key()
            .is_none());
    }

    /// Each refusal must render a DIFFERENT sentence. A fail-closed control whose three causes all
    /// print the same line is the failure `fail-closed-must-say-which-failure` records.
    #[test]
    fn each_refusal_reason_reads_differently() {
        let msgs = [
            UpdateRefusalReason::NotConfigured.to_string(),
            UpdateRefusalReason::Malformed.to_string(),
            UpdateRefusalReason::SameKeyAsGrantIssuer.to_string(),
        ];
        for (i, a) in msgs.iter().enumerate() {
            assert!(!a.is_empty());
            for b in msgs.iter().skip(i + 1) {
                assert_ne!(a, b, "two refusal reasons print the same message");
            }
        }
        assert!(msgs[2].contains("grant_issuer_pubkey"));
    }

    // -------------------------------------------------------------------------------------
    // The version comparator
    // -------------------------------------------------------------------------------------

    /// THE property `crates/agent-core/src/version.rs` documents and nothing implemented until now:
    /// `AGENT_VERSION` is `<semver>+<sha>`, and semver build metadata is ignored for precedence.
    #[test]
    fn build_metadata_is_ignored_for_precedence() {
        assert_eq!(compare_versions("0.0.1+abc", "0.0.1+def"), Ok(Ordering::Equal));
        assert_eq!(compare_versions("0.0.1+abc", "0.0.1"), Ok(Ordering::Equal));
        assert_eq!(compare_versions("0.0.1", "0.0.1+def"), Ok(Ordering::Equal));
        // …and metadata never makes a difference to a comparison that is decided by the core.
        assert_eq!(compare_versions("0.0.2+aaa", "0.0.1+zzz"), Ok(Ordering::Greater));
        assert_eq!(compare_versions("0.0.1+zzz", "0.0.2+aaa"), Ok(Ordering::Less));
    }

    #[test]
    fn components_are_ordered_numerically_not_lexically() {
        // The single most important case: as strings, "0.9.0" > "0.10.0".
        assert_eq!(compare_versions("0.10.0", "0.9.0"), Ok(Ordering::Greater));
        assert_eq!(compare_versions("2.0.0", "10.0.0"), Ok(Ordering::Less));
        assert_eq!(compare_versions("1.0.10", "1.0.9"), Ok(Ordering::Greater));
        // Major outranks minor outranks patch.
        assert_eq!(compare_versions("1.0.0", "0.99.99"), Ok(Ordering::Greater));
        assert_eq!(compare_versions("0.5.0", "0.4.99"), Ok(Ordering::Greater));
        assert_eq!(compare_versions("0.0.0", "0.0.0"), Ok(Ordering::Equal));
    }

    #[test]
    fn unparseable_versions_are_refused_not_guessed() {
        use VersionParseError::*;
        assert_eq!(parse_version(""), Err(Empty));
        assert_eq!(parse_version("   "), Err(Empty));
        assert_eq!(parse_version("+abc"), Err(Empty));
        assert_eq!(parse_version("1.2"), Err(WrongComponentCount { found: 2 }));
        assert_eq!(parse_version("1.2.3.4"), Err(WrongComponentCount { found: 4 }));
        assert_eq!(parse_version("1..3"), Err(EmptyComponent { index: 1 }));
        assert_eq!(
            parse_version("1.2.x"),
            Err(NotNumeric { index: 2, value: "x".into() })
        );
        assert_eq!(
            parse_version("1.02.3"),
            Err(LeadingZero { index: 1, value: "02".into() })
        );
        assert_eq!(
            parse_version("1.0.0-rc1"),
            Err(PreReleaseUnsupported { value: "1.0.0-rc1".into() })
        );
        assert_eq!(parse_version(&"9".repeat(65)), Err(TooLong));
        assert_eq!(
            parse_version("1.2.99999999999999999999"),
            Err(Overflow { index: 2, value: "99999999999999999999".into() })
        );
        // `0` alone is fine; only a LEADING zero on a longer number is refused.
        assert!(parse_version("0.0.0").is_ok());
        // An unparseable side poisons the comparison rather than defaulting it.
        assert!(compare_versions("1.0.0", "banana").is_err());
        assert!(compare_versions("banana", "1.0.0").is_err());
    }

    /// The real `AGENT_VERSION` shape parses. Stated as the shape rather than importing the
    /// constant, because `rmt-agent` deliberately does not depend on `rmt-agent-core`.
    #[test]
    fn the_real_agent_version_shape_parses() {
        assert_eq!(
            parse_version("0.0.1+0594362"),
            Ok(SemVer { major: 0, minor: 0, patch: 1 })
        );
        // Including the degraded build (`build.rs` stamps "unknown" when git is unavailable), which
        // must still compare as an ordinary 0.0.1 rather than becoming uncomparable.
        assert_eq!(
            parse_version("0.0.1+unknown"),
            Ok(SemVer { major: 0, minor: 0, patch: 1 })
        );
    }

    // -------------------------------------------------------------------------------------
    // Availability — including the negative control
    // -------------------------------------------------------------------------------------

    #[test]
    fn a_newer_release_is_available() {
        let a = release().availability(RUNNING).unwrap();
        assert!(a.is_available(), "{a:?}");
    }

    /// THE NEGATIVE CONTROL. A correctly signed manifest for a version that is NOT newer must
    /// report "no update" — not an error, and certainly not "available". Without this test, code
    /// that reported an update unconditionally would pass every other assertion in this module.
    #[test]
    fn a_release_that_is_not_newer_reports_no_update() {
        let mut r = release();
        // Equal.
        r.version = "0.3.0".into();
        assert!(matches!(
            r.availability(RUNNING).unwrap(),
            UpdateAvailability::NoUpdate { .. }
        ));
        // Older.
        r.version = "0.2.0".into();
        assert!(matches!(
            r.availability(RUNNING).unwrap(),
            UpdateAvailability::NoUpdate { .. }
        ));
        // Equal but for build metadata — a rebuild of the running version is NOT an update.
        r.version = "0.3.0".into();
        assert!(matches!(
            r.availability("0.3.0+deadbee").unwrap(),
            UpdateAvailability::NoUpdate { .. }
        ));
    }

    #[test]
    fn a_release_out_of_upgrade_range_is_not_available() {
        let mut r = release();
        r.min_upgradable_from = "0.3.5".into();
        match r.availability(RUNNING).unwrap() {
            UpdateAvailability::UpgradePathUnsupported { min_upgradable_from, .. } => {
                assert_eq!(min_upgradable_from, "0.3.5")
            }
            other => panic!("expected UpgradePathUnsupported, got {other:?}"),
        }
        // The boundary is inclusive: running == min_upgradable_from IS upgradable.
        r.min_upgradable_from = "0.3.0".into();
        assert!(r.availability(RUNNING).unwrap().is_available());
    }

    #[test]
    fn an_uncomparable_running_version_is_an_error_not_an_update() {
        assert!(release().availability("not-a-version").is_err());
    }

    // -------------------------------------------------------------------------------------
    // check_for_update — the whole of step 2 end to end
    // -------------------------------------------------------------------------------------

    fn tmp_manifest(name: &str, body: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt-update-test-{}-{name}.json", std::process::id()));
        std::fs::write(&p, body).expect("write fixture");
        p
    }

    #[test]
    fn an_absent_manifest_is_not_an_error() {
        let mut p = std::env::temp_dir();
        p.push(format!("rmt-update-test-{}-absent.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let s = signer();
        let trust = UpdateTrust::VerifyWith(s.public());
        assert!(matches!(
            check_for_update(&p, &trust, RUNNING, 1_730_000_001_000),
            UpdateCheck::NoManifest
        ));
    }

    #[test]
    fn a_present_but_unverifiable_manifest_is_reported_invalid() {
        let s = signer();
        let attacker = Identity::from_seed(&[9u8; 32]);
        let now = 1_730_000_000_000;
        let signed = claims(now, 2_592_000_000).sign(&attacker);
        let p = tmp_manifest("wrongkey", &signed.to_json().unwrap());
        let trust = UpdateTrust::VerifyWith(s.public());
        match check_for_update(&p, &trust, RUNNING, now + 1_000) {
            UpdateCheck::Invalid(UpdateManifestError::BadSignature) => {}
            other => panic!("expected Invalid(BadSignature), got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_present_but_undecodable_manifest_is_reported_invalid() {
        let p = tmp_manifest("garbage", "this is not json");
        let s = signer();
        let trust = UpdateTrust::VerifyWith(s.public());
        match check_for_update(&p, &trust, RUNNING, 1_730_000_001_000) {
            UpdateCheck::Invalid(UpdateManifestError::Encoding(_)) => {}
            other => panic!("expected Invalid(Encoding), got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    /// A refusal is reported even though the manifest itself is perfectly genuine — and reported
    /// AFTER the file is found, so an operator who placed a manifest on a machine with no pinned
    /// key is told, rather than seeing the same silence as a machine with no manifest.
    #[test]
    fn a_refusing_agent_reports_the_refusal_and_never_the_release() {
        let s = signer();
        let now = 1_730_000_000_000;
        let signed = claims(now, 2_592_000_000).sign(&s);
        let p = tmp_manifest("refused", &signed.to_json().unwrap());
        let trust = UpdateTrust::RefuseAllUpdates(UpdateRefusalReason::SameKeyAsGrantIssuer);
        match check_for_update(&p, &trust, RUNNING, now + 1_000) {
            UpdateCheck::Refused(UpdateRefusalReason::SameKeyAsGrantIssuer) => {}
            other => panic!("expected Refused, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_oversized_manifest_is_refused_before_it_is_parsed() {
        let body = format!("{{\"pad\":\"{}\"}}", "a".repeat(MAX_MANIFEST_BYTES as usize + 1));
        let p = tmp_manifest("oversize", &body);
        let s = signer();
        let trust = UpdateTrust::VerifyWith(s.public());
        match check_for_update(&p, &trust, RUNNING, 1_730_000_001_000) {
            UpdateCheck::Invalid(UpdateManifestError::Unreadable { reason, .. }) => {
                assert!(reason.contains("cap"), "{reason}")
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_happy_path_reports_the_verified_release_and_availability() {
        let s = signer();
        let now = 1_730_000_000_000;
        let signed = claims(now, 2_592_000_000).sign(&s);
        let p = tmp_manifest("happy", &signed.to_json().unwrap());
        let trust = UpdateTrust::VerifyWith(s.public());
        match check_for_update(&p, &trust, RUNNING, now + 1_000) {
            UpdateCheck::Verified { release, availability } => {
                assert_eq!(release.version, "0.4.0");
                assert!(availability.is_available());
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    // =====================================================================================
    // GOLDEN CROSS-LANGUAGE VECTOR (update v1) — the proof Rust and Go agree byte-for-byte.
    //
    // The SAME fixed fixture is hardcoded in control-plane/update_manifest_test.go's
    // TestUpdateManifestGoldenVectorV1. If the two languages' canonical encoders or Ed25519
    // signing ever diverge, one side's hex stops matching. DO NOT change a value here without
    // changing it identically in the Go test.
    //
    // NOTE THE SEED. The grant, session-policy and elevation vectors all deliberately share ONE
    // seed, because for those three the domain tag is the only thing separating the signatures and
    // the vectors exist partly to prove it. This vector uses a DIFFERENT seed on purpose: the
    // update signing key is a different key in reality (docs/21 §3), the fixture should look like
    // reality, and a shared seed here would quietly model the exact configuration
    // `UpdateTrust::from_config` refuses. Domain separation is still asserted, by
    // `the_preimage_is_domain_separated` — which needs no key at all.
    //
    //   seed (32 bytes, hex): 2122…40
    //   version:             0.4.0
    //   sha256:              e3b0c442…b855   (SHA-256 of the empty input — recognisable, valid)
    //   url:                 https://updates.deskrally.com/rmt-agent-0.4.0.exe
    //   min_upgradable_from: 0.2.0
    //   issued_at_ms:        1730000000000
    //   expires_at_ms:       1732592000000   (issued + 30 days)
    // =====================================================================================

    const GOLDEN_SEED: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    const GOLDEN_PUBKEY_HEX: &str =
        "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";
    const GOLDEN_PREIMAGE_HEX: &str = "524d5455504441544576310000000005302e342e3000000040653362306334343239386663316331343961666266346338393936666239323432376165343165343634396239333463613439353939316237383532623835350000003168747470733a2f2f757064617465732e6465736b72616c6c792e636f6d2f726d742d6167656e742d302e342e302e65786500000005302e322e3000000192cc091400000001936687dc00";
    const GOLDEN_SIG_HEX: &str = "eb7c68776b438a8879d948213149fbac431927aba493dc9f823e3349d5ccf481c322e90b85bd32e04aab33dd786b4a0f75bdafe02f4c58c46a878d517149350d";

    fn golden_claims() -> UpdateManifestClaims {
        UpdateManifestClaims {
            release: Release {
                version: "0.4.0".into(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                url: "https://updates.deskrally.com/rmt-agent-0.4.0.exe".into(),
                min_upgradable_from: "0.2.0".into(),
            },
            issued_at_ms: 1_730_000_000_000,
            expires_at_ms: 1_732_592_000_000,
        }
    }

    #[test]
    fn golden_vector_v1() {
        let signer = Identity::from_seed(&GOLDEN_SEED);
        let claims = golden_claims();
        let preimage_hex = hex::encode(claims.signing_bytes());
        let signed = claims.sign(&signer);

        // Printed so the constants can be captured on first run (cargo test -- --nocapture).
        eprintln!("GOLDEN_PUBKEY_HEX   = {}", signer.public_hex());
        eprintln!("GOLDEN_PREIMAGE_HEX = {preimage_hex}");
        eprintln!("GOLDEN_SIG_HEX      = {}", signed.sig);
        eprintln!("GOLDEN_JSON         = {}", signed.to_json().unwrap());

        assert_eq!(signer.public_hex(), GOLDEN_PUBKEY_HEX, "pubkey drift");
        assert_eq!(preimage_hex, GOLDEN_PREIMAGE_HEX, "canonical preimage drift");
        assert_eq!(signed.sig, GOLDEN_SIG_HEX, "signature drift");
    }

    /// Direct Go-sign → Rust-verify interop: a `SignedUpdateManifest` JSON produced by the offline
    /// `control-plane/cmd/rmt-update-sign` signer for the golden fixture (pasted verbatim from
    /// `control-plane/update_manifest_test.go`'s logged output) verifies here.
    ///
    /// This proves more than `golden_vector_v1` does. That test shows both languages compute the
    /// same hex for the same fixture; this one feeds Go's wire bytes — field names, field order,
    /// number formatting and all — through the real decoder and the real verifier. A serde rename
    /// on THIS side passes the hex comparison and fails here.
    ///
    /// Read the direction carefully. This constant is a frozen SNAPSHOT of Go's output, not Go's
    /// live output, so on its own it cannot catch a Go struct-tag rename — Go would happily emit
    /// the new spelling while this test kept verifying the old one. The Go half of the contract is
    /// `goldenUpdateWireJSON` in `control-plane/update_manifest_test.go`, which pins this exact
    /// string from the other side. The pair is the contract; either alone is half of it.
    #[test]
    fn verifies_go_signed_manifest() {
        const GO_SIGNED_JSON: &str = r#"{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","url":"https://updates.deskrally.com/rmt-agent-0.4.0.exe","min_upgradable_from":"0.2.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"eb7c68776b438a8879d948213149fbac431927aba493dc9f823e3349d5ccf481c322e90b85bd32e04aab33dd786b4a0f75bdafe02f4c58c46a878d517149350d"}"#;

        let signer = PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap();
        let signed = SignedUpdateManifest::from_json(GO_SIGNED_JSON).expect("Go JSON decodes");
        let release = signed
            .verify(&signer, 1_730_000_060_000)
            .expect("a Go-signed update manifest verifies in Rust");
        assert_eq!(release, golden_claims().release);
    }
}

// =========================================================================================
// Format 2 tests
// =========================================================================================
#[cfg(test)]
mod tests_v2 {
    use super::*;
    use crate::backstage::canonical::{UPDATE_DOMAIN_TAG, UPDATE_V2_DOMAIN_TAG};

    // The v1 golden seed, reused: the update key is one key whichever format it signs, so the v2
    // fixture should look like that rather than model a second key.
    const GOLDEN_SEED: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    const GOLDEN_PUBKEY_HEX: &str =
        "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";
    const ISSUED: i64 = 1_730_000_000_000;
    const EXPIRES: i64 = 1_732_592_000_000; // issued + 30 days
    const NOW: i64 = ISSUED + 60_000;

    // The GOLDEN VECTOR (update v2). The same fixture, the same preimage hex and the same signature
    // hex are pinned in `control-plane/update_manifest_v2_test.go`; a change here must be made
    // identically there, deliberately, never by regenerating one side from its own output.
    const GOLDEN_PREIMAGE_HEX: &str = "524d545550444154457632000000000663616e61727900000005302e312e3000000040653362306334343239386663316331343961666266346338393936666239323432376165343165343634396239333463613439353939316237383532623835350000004b68747470733a2f2f6d61696e2e6465736b72616c6c792e636f6d2f646f776e6c6f61642f6167656e742f72656c65617365732f302e312e302f4465736b52616c6c794167656e742e6d736900000005312e332e30000000267b31313131313131312d323232322d333333332d343434342d3535353535353535353535357d000000267b37423345394332412d344631442d344538422d394136432d3244354538463141334237437d00000005302e312e3000000192cc091400000001936687dc00";
    const GOLDEN_SIG_HEX: &str = "04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b";

    fn golden_release() -> ReleaseV2 {
        ReleaseV2 {
            ring: "canary".into(),
            version: "0.1.0".into(),
            msi_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            msi_url: "https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi"
                .into(),
            product_version: "1.3.0".into(),
            product_code: "{11111111-2222-3333-4444-555555555555}".into(),
            upgrade_code: "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}".into(),
            min_upgradable_from: "0.1.0".into(),
        }
    }

    fn golden_claims() -> UpdateManifestClaimsV2 {
        UpdateManifestClaimsV2 {
            release: golden_release(),
            issued_at_ms: ISSUED,
            expires_at_ms: EXPIRES,
        }
    }

    fn signer() -> Identity {
        Identity::from_seed(&GOLDEN_SEED)
    }

    fn public() -> PublicIdentity {
        PublicIdentity::from_hex(GOLDEN_PUBKEY_HEX).unwrap()
    }

    /// Sign `mutate(golden)` with the REAL key, so a refusal is the shape check and not the
    /// signature.
    fn verify_mutated(mutate: impl FnOnce(&mut ReleaseV2)) -> Result<ReleaseV2, UpdateManifestError> {
        let mut c = golden_claims();
        mutate(&mut c.release);
        c.sign(&signer()).verify(&public(), NOW)
    }

    #[test]
    fn golden_vector_v2() {
        let signer = signer();
        let claims = golden_claims();
        let preimage_hex = hex::encode(claims.signing_bytes());
        let signed = claims.sign(&signer);

        // Printed so the constants can be captured on first run (cargo test -- --nocapture).
        eprintln!("GOLDEN_PREIMAGE_HEX = {preimage_hex}");
        eprintln!("GOLDEN_SIG_HEX      = {}", signed.sig);
        eprintln!("GOLDEN_JSON         = {}", signed.to_json().unwrap());

        assert_eq!(signer.public_hex(), GOLDEN_PUBKEY_HEX, "pubkey drift");
        assert_eq!(preimage_hex, GOLDEN_PREIMAGE_HEX, "canonical preimage drift");
        assert_eq!(signed.sig, GOLDEN_SIG_HEX, "signature drift");
    }

    /// Go-sign -> Rust-verify for format 2: wire JSON produced by the Go signer for the golden
    /// fixture (pasted verbatim from `control-plane/update_manifest_v2_test.go`'s
    /// `goldenUpdateV2WireJSON`) goes through the real decoder and verifier. Same reasoning as v1's
    /// `verifies_go_signed_manifest`: this is a frozen snapshot, and the pair of constants is the
    /// contract.
    #[test]
    fn verifies_go_signed_manifest_v2() {
        const GO_SIGNED_JSON: &str = r#"{"format":2,"claims":{"release":{"ring":"canary","version":"0.1.0","msi_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","msi_url":"https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi","product_version":"1.3.0","product_code":"{11111111-2222-3333-4444-555555555555}","upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}","min_upgradable_from":"0.1.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b"}"#;
        let signed = SignedUpdateManifestV2::from_json(GO_SIGNED_JSON).expect("Go JSON decodes");
        let release =
            signed.verify(&public(), NOW).expect("a Go-signed v2 manifest verifies in Rust");
        assert_eq!(release, golden_release());
        // And Rust re-encodes it to the same bytes, so field order cannot have drifted either way.
        assert_eq!(signed.to_json().unwrap(), GO_SIGNED_JSON);
    }

    #[test]
    fn a_genuine_v2_manifest_verifies() {
        let signed = golden_claims().sign(&signer());
        assert_eq!(signed.format, 2);
        assert_eq!(signed.verify(&public(), NOW).unwrap(), golden_release());
        // And through the wire.
        let round = SignedUpdateManifestV2::from_json(&signed.to_json().unwrap()).unwrap();
        assert_eq!(round, signed);
        round.verify(&public(), NOW).unwrap();
    }

    #[test]
    fn every_v2_release_field_changes_the_preimage() {
        let base = golden_claims();
        let baseline = base.signing_bytes();

        let mutations: [(&str, fn(&mut UpdateManifestClaimsV2)); 10] = [
            ("ring", |c| c.release.ring = "early".into()),
            ("version", |c| c.release.version = "0.1.1".into()),
            ("msi_sha256", |c| c.release.msi_sha256 = "0".repeat(64)),
            ("msi_url", |c| c.release.msi_url = "https://evil.example/x.msi".into()),
            ("product_version", |c| c.release.product_version = "1.3.1".into()),
            ("product_code", |c| {
                c.release.product_code = "{11111111-2222-3333-4444-555555555556}".into()
            }),
            ("upgrade_code", |c| {
                c.release.upgrade_code = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7D}".into()
            }),
            ("min_upgradable_from", |c| c.release.min_upgradable_from = "0.1.1".into()),
            ("issued_at_ms", |c| c.issued_at_ms += 1),
            ("expires_at_ms", |c| c.expires_at_ms += 1),
        ];
        for (name, mutate) in mutations {
            let mut c = base.clone();
            mutate(&mut c);
            assert_ne!(
                c.signing_bytes(),
                baseline,
                "changing {name} did not change the signing bytes — the field is not signed"
            );
        }
        // The premise, established locally: an unchanged clone yields the same bytes.
        assert_eq!(base.clone().signing_bytes(), baseline);
    }

    /// Swapping two string fields of equal length must change the preimage too: the length prefix
    /// frames each field, but the ORDER is what binds a value to its meaning. product_code and
    /// upgrade_code are the pair an operator could plausibly transpose.
    #[test]
    fn swapping_the_two_guids_changes_the_preimage() {
        let base = golden_claims();
        let mut swapped = base.clone();
        std::mem::swap(&mut swapped.release.product_code, &mut swapped.release.upgrade_code);
        assert_ne!(base.signing_bytes(), swapped.signing_bytes());
    }

    #[test]
    fn the_v2_preimage_is_domain_separated_from_v1() {
        let v2 = golden_claims().signing_bytes();
        assert_eq!(&v2[..12], &UPDATE_V2_DOMAIN_TAG);
        assert_ne!(&v2[..12], &UPDATE_DOMAIN_TAG);

        // Analogous content: the v1 claims built from the v2 release's overlapping fields.
        let r = golden_release();
        let v1 = UpdateManifestClaims {
            release: Release {
                version: r.version.clone(),
                sha256: r.msi_sha256.clone(),
                url: r.msi_url.clone(),
                min_upgradable_from: r.min_upgradable_from.clone(),
            },
            issued_at_ms: ISSUED,
            expires_at_ms: EXPIRES,
        }
        .signing_bytes();
        assert_eq!(&v1[..12], &UPDATE_DOMAIN_TAG);
        assert_ne!(v1, v2);

        // And a v1 signature is useless as a v2 one: re-presenting it under v2 claims is refused.
        let v1_sig = signer().sign(&v1);
        let mut forged = golden_claims().sign(&signer());
        forged.sig = hex::encode(v1_sig);
        assert!(matches!(forged.verify(&public(), NOW), Err(UpdateManifestError::BadSignature)));
    }

    #[test]
    fn a_tampered_v2_signature_or_field_is_refused() {
        let good = golden_claims().sign(&signer());

        let mut flipped = good.clone();
        let mut sig = hex::decode(&flipped.sig).unwrap();
        sig[0] ^= 0x01;
        flipped.sig = hex::encode(sig);
        assert!(matches!(flipped.verify(&public(), NOW), Err(UpdateManifestError::BadSignature)));

        let mut repointed = good.clone();
        repointed.claims.release.msi_url = "https://evil.example/x.msi".into();
        assert!(matches!(
            repointed.verify(&public(), NOW),
            Err(UpdateManifestError::BadSignature)
        ));

        let mut other_ring = good.clone();
        other_ring.claims.release.ring = "general".into();
        assert!(matches!(
            other_ring.verify(&public(), NOW),
            Err(UpdateManifestError::BadSignature)
        ));

        let other_key = Identity::from_seed(&[9u8; 32]).public_hex();
        let other = PublicIdentity::from_hex(&other_key).unwrap();
        assert!(matches!(good.verify(&other, NOW), Err(UpdateManifestError::BadSignature)));

        let mut short = good.clone();
        short.sig = "ab".into();
        assert!(matches!(short.verify(&public(), NOW), Err(UpdateManifestError::Encoding(_))));
        let mut nonhex = good;
        nonhex.sig = "zz".repeat(64);
        assert!(matches!(nonhex.verify(&public(), NOW), Err(UpdateManifestError::Encoding(_))));
    }

    #[test]
    fn the_v2_validity_window_is_enforced_at_both_ends() {
        let signed = golden_claims().sign(&signer());
        let pk = public();
        assert!(signed.verify(&pk, ISSUED + 1000).is_ok());
        // Expiry is exact.
        assert!(matches!(
            signed.verify(&pk, EXPIRES),
            Err(UpdateManifestError::Expired { .. })
        ));
        assert!(signed.verify(&pk, EXPIRES - 1).is_ok());
        // Not-yet-valid tolerates CLOCK_SKEW_MS, one-sided.
        assert!(signed.verify(&pk, ISSUED - CLOCK_SKEW_MS).is_ok());
        assert!(matches!(
            signed.verify(&pk, ISSUED - CLOCK_SKEW_MS - 1),
            Err(UpdateManifestError::NotYetValid { .. })
        ));
    }

    /// The signature is checked before the window and the window before the shapes. One manifest
    /// that fails several checks at once; which error is reported pins the order.
    #[test]
    fn v2_verify_order_is_signature_then_window_then_shapes() {
        // Malformed ring AND expired AND signed by a stranger: BadSignature.
        let mut c = golden_claims();
        c.release.ring = "nightly".into();
        let stranger = Identity::from_seed(&[9u8; 32]);
        assert!(matches!(
            c.sign(&stranger).verify(&public(), EXPIRES + 1),
            Err(UpdateManifestError::BadSignature)
        ));
        // Genuinely signed, malformed ring AND expired: Expired, not MalformedRing.
        assert!(matches!(
            c.sign(&signer()).verify(&public(), EXPIRES + 1),
            Err(UpdateManifestError::Expired { .. })
        ));
        // Same, within the window: now the shape is what is reported.
        assert!(matches!(
            c.sign(&signer()).verify(&public(), NOW),
            Err(UpdateManifestError::MalformedRing { .. })
        ));
    }

    #[test]
    fn v2_malformed_fields_are_refused_even_when_signed() {
        // Positive control: the unmutated fixture verifies, so each refusal below is the mutation.
        assert!(verify_mutated(|_| {}).is_ok());

        let upper_sha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert!(matches!(
            verify_mutated(|r| r.msi_sha256 = upper_sha.into()),
            Err(UpdateManifestError::MalformedSha256 { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.msi_sha256 = "e3b0".into()),
            Err(UpdateManifestError::MalformedSha256 { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.msi_url = "http://main.deskrally.com/a.msi".into()),
            Err(UpdateManifestError::MalformedUrl { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.msi_url = "https://x/a\n.msi".into()),
            Err(UpdateManifestError::MalformedUrl { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.version = "0.1".into()),
            Err(UpdateManifestError::MalformedVersion { field: "version", .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.min_upgradable_from = "banana".into()),
            Err(UpdateManifestError::MalformedVersion { field: "min_upgradable_from", .. })
        ));
        // The golden product_code is all digits, so lowercasing it would be a no-op: the lowercase
        // case runs against the upgrade code, which has letters.
        assert!(matches!(
            verify_mutated(|r| r.upgrade_code = r.upgrade_code.to_lowercase()),
            Err(UpdateManifestError::MalformedGuid { field: "upgrade_code", .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.product_code = "{aaaaaaaa-2222-3333-4444-555555555555}".into()),
            Err(UpdateManifestError::MalformedGuid { field: "product_code", .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.product_code = "{1111111-2222-3333-4444-555555555555}".into()),
            Err(UpdateManifestError::MalformedGuid { field: "product_code", .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.product_version = "256.0.0".into()),
            Err(UpdateManifestError::MalformedProductVersion { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.product_version = "1.3.65536".into()),
            Err(UpdateManifestError::MalformedProductVersion { .. })
        ));
        assert!(matches!(
            verify_mutated(|r| r.product_version = "01.3.0".into()),
            Err(UpdateManifestError::MalformedProductVersion { .. })
        ));
        for ring in ["", "Canary", "CANARY", "nightly", "canary ", "canary,early", "general\0"] {
            assert!(
                matches!(
                    verify_mutated(|r| r.ring = ring.into()),
                    Err(UpdateManifestError::MalformedRing { .. })
                ),
                "ring {ring:?} must be refused"
            );
        }
        for ring in RELEASE_RINGS {
            assert!(verify_mutated(|r| r.ring = ring.into()).is_ok(), "ring {ring:?}");
        }
    }

    #[test]
    fn product_version_table() {
        let good = ["0.0.0", "1.3.0", "255.255.65535", "0.0.1", "10.20.30"];
        for s in good {
            assert!(check_product_version(s).is_ok(), "{s:?} must be accepted");
        }
        let bad = [
            "", "1", "1.2", "1.2.3.4", "1..3", ".1.2", "1.2.", "256.0.0", "0.256.0", "1.3.65536",
            "1.3.99999", "1.3.100000", "1.3.999999999999", "01.3.0", "1.03.0", "1.3.00", "1.3.01",
            "-1.0.0", "+1.0.0", "1.3.0+abc", "1.3.0-rc1", " 1.3.0", "1.3.0 ", "1.3.x", "١.٣.٠",
        ];
        for s in bad {
            assert!(check_product_version(s).is_err(), "{s:?} must be refused");
        }
    }

    #[test]
    fn guid_table() {
        let good = [
            "{11111111-2222-3333-4444-555555555555}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
            "{00000000-0000-0000-0000-000000000000}",
            "{ABCDEF00-ABCD-EF00-ABCD-EF0000000000}",
        ];
        for s in good {
            assert!(check_braced_guid(s).is_ok(), "{s:?} must be accepted");
        }
        let bad = [
            "",
            "11111111-2222-3333-4444-555555555555",
            "{11111111-2222-3333-4444-555555555555",
            "11111111-2222-3333-4444-555555555555}",
            "(11111111-2222-3333-4444-555555555555)",
            "{7b3e9c2a-4f1d-4e8b-9a6c-2d5e8f1a3b7c}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7c}",
            "{7B3E9C2A4F1D4E8B9A6C2D5E8F1A3B7C0000}",
            "{7B3E9C2A-4F1D-4E8B-9A6C2-D5E8F1A3B7C}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7G}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C }",
            " {7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7CC}",
            "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7é}",
        ];
        for s in bad {
            assert!(check_braced_guid(s).is_err(), "{s:?} must be refused");
        }
    }

    #[test]
    fn v2_availability_matches_v1_semantics() {
        let r = golden_release(); // version 0.1.0, min_upgradable_from 0.1.0
        assert!(matches!(
            r.availability("0.1.0+abc").unwrap(),
            UpdateAvailability::NoUpdate { .. }
        ));
        assert!(matches!(
            r.availability("0.2.0").unwrap(),
            UpdateAvailability::NoUpdate { .. }
        ));
        let newer = ReleaseV2 { version: "0.3.0".into(), ..golden_release() };
        assert!(newer.availability("0.2.0").unwrap().is_available());
        assert!(matches!(
            newer.availability("0.0.9").unwrap(),
            UpdateAvailability::UpgradePathUnsupported { .. }
        ));
        assert!(newer.availability("banana").is_err());
        // Same answer as the v1 release with the same three fields, across a table.
        let v1 = Release {
            version: "0.3.0".into(),
            sha256: String::new(),
            url: String::new(),
            min_upgradable_from: "0.1.0".into(),
        };
        for running in ["0.0.9", "0.1.0", "0.2.0", "0.3.0", "0.3.0+x", "0.4.0"] {
            assert_eq!(
                newer.availability(running).unwrap(),
                v1.availability(running).unwrap(),
                "running {running}"
            );
        }
    }

    // ---- the two formats refuse each other's JSON ------------------------------------------

    #[test]
    fn a_v1_parser_refuses_v2_json_and_a_v2_parser_refuses_v1_json() {
        let v2 = golden_claims().sign(&signer()).to_json().unwrap();
        let v1 = UpdateManifestClaims {
            release: Release {
                version: "0.4.0".into(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                url: "https://updates.deskrally.com/rmt-agent-0.4.0.exe".into(),
                min_upgradable_from: "0.2.0".into(),
            },
            issued_at_ms: ISSUED,
            expires_at_ms: EXPIRES,
        }
        .sign(&signer())
        .to_json()
        .unwrap();

        // Positive controls: each parser accepts its own format.
        assert!(SignedUpdateManifest::from_json(&v1).is_ok());
        assert!(SignedUpdateManifestV2::from_json(&v2).is_ok());

        assert!(SignedUpdateManifest::from_json(&v2).is_err(), "v1 parser accepted v2 JSON");
        assert!(SignedUpdateManifestV2::from_json(&v1).is_err(), "v2 parser accepted v1 JSON");

        // Even a v1 manifest with a `format` key bolted on is refused by the v1 parser.
        let v1_with_format = v1.replacen('{', r#"{"format":2,"#, 1);
        assert!(SignedUpdateManifest::from_json(&v1_with_format).is_err());
    }

    #[test]
    fn only_format_2_decodes() {
        let genuine = golden_claims().sign(&signer()).to_json().unwrap();
        assert!(genuine.starts_with(r#"{"format":2,"claims":"#), "wire order: {genuine}");
        for bad in ["0", "1", "3", "4294967295"] {
            let js = genuine.replacen(r#""format":2"#, &format!(r#""format":{bad}"#), 1);
            assert_ne!(js, genuine);
            assert!(
                matches!(
                    SignedUpdateManifestV2::from_json(&js),
                    Err(UpdateManifestError::UnsupportedFormat { .. })
                ),
                "format {bad} must be refused"
            );
        }
        for bad in [r#""format":"2""#, r#""format":2.5"#, r#""format":null"#, r#""format":-2"#] {
            let js = genuine.replacen(r#""format":2"#, bad, 1);
            assert!(SignedUpdateManifestV2::from_json(&js).is_err(), "{bad} must not decode");
        }
        // A programmatically built value with the wrong format is refused at verify too.
        let mut wrong = golden_claims().sign(&signer());
        wrong.format = 1;
        assert!(matches!(
            wrong.verify(&public(), NOW),
            Err(UpdateManifestError::UnsupportedFormat { found: 1 })
        ));
    }

    #[test]
    fn a_v2_unknown_field_does_not_decode_at_any_level() {
        let genuine = golden_claims().sign(&signer()).to_json().unwrap();
        for (name, injected) in [
            ("top level", genuine.replacen(r#"{"format""#, r#"{"rollback":true,"format""#, 1)),
            ("claims", genuine.replacen(r#""issued_at_ms""#, r#""x":1,"issued_at_ms""#, 1)),
            ("release", genuine.replacen(r#""ring""#, r#""exec":"cmd.exe","ring""#, 1)),
        ] {
            assert_ne!(injected, genuine, "{name}: the fixture did not change");
            assert!(
                SignedUpdateManifestV2::from_json(&injected).is_err(),
                "an unknown field at {name} must be refused"
            );
        }
        // A v1-style `sha256`/`url` inside the v2 release is an unknown field, not an alias.
        let aliased = genuine.replacen(r#""msi_sha256""#, r#""sha256""#, 1);
        assert!(SignedUpdateManifestV2::from_json(&aliased).is_err());
    }

    #[test]
    fn malformed_v2_json_does_not_decode() {
        for js in ["", "{", "null", "[]", r#"{"format":2,"claims":{},"sig":"ab"}"#, r#"{"format":2}"#] {
            assert!(SignedUpdateManifestV2::from_json(js).is_err(), "{js:?} should not decode");
        }
        // A release missing one field (`upgrade_code`) never decodes, signed or not.
        let genuine = golden_claims().sign(&signer()).to_json().unwrap();
        let needle = r#""upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}","#;
        assert!(genuine.contains(needle));
        assert!(SignedUpdateManifestV2::from_json(&genuine.replacen(needle, "", 1)).is_err());
    }

    /// The Go side (`wireVariantsV2` in control-plane/update_manifest_v2_decode_test.go) refuses a
    /// list of variants of the golden wire JSON; this runs the same list through serde, so "Go's
    /// verifier said OK" and "an agent will decode it" cannot drift apart. serde refuses case
    /// variants, duplicate fields, nulls, missing fields and trailing data. (Go also refuses invalid
    /// UTF-8 input; a `&str` cannot hold it, so there is no Rust twin of that one case.)
    #[test]
    fn the_rust_decoder_refuses_the_same_wire_variants() {
        let g = golden_claims().sign(&signer()).to_json().unwrap();
        assert!(SignedUpdateManifestV2::from_json(&g).is_ok(), "positive control");
        let rep = |old: &str, new: &str| {
            assert_eq!(g.matches(old).count(), 1, "needle {old:?} must occur exactly once");
            g.replacen(old, new, 1)
        };
        let mut v: Vec<(String, String)> = Vec::new();

        let keys = [
            "format", "claims", "sig", "release", "issued_at_ms", "expires_at_ms", "ring", "version",
            "msi_sha256", "msi_url", "product_version", "product_code", "upgrade_code",
            "min_upgradable_from",
        ];
        for k in keys {
            let mut cap = k.to_string();
            cap[..1].make_ascii_uppercase();
            v.push((format!("case {k}"), rep(&format!("\"{k}\":"), &format!("\"{cap}\":"))));
            v.push((format!("upper {k}"), rep(&format!("\"{k}\":"), &format!("\"{}\":", k.to_uppercase()))));
        }

        v.push(("dup format".into(), rep(r#""format":2,"#, r#""format":2,"format":2,"#)));
        v.push(("dup sig".into(), format!("{},\"sig\":\"{}\"}}", g.trim_end_matches('}'), "00".repeat(64))));
        v.push(("dup issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000,"#, r#""issued_at_ms":1730000000000,"issued_at_ms":1730000000000,"#)));
        v.push(("dup expires_at_ms".into(), rep(r#","expires_at_ms":1732592000000"#, r#","expires_at_ms":1732592000000,"expires_at_ms":1732592000000"#)));
        v.push(("dup ring".into(), rep(r#""ring":"canary","#, r#""ring":"canary","ring":"canary","#)));
        v.push(("dup min_upgradable_from".into(), rep(r#""min_upgradable_from":"0.1.0""#, r#""min_upgradable_from":"0.1.0","min_upgradable_from":"0.1.0""#)));

        v.push(("missing format".into(), rep(r#""format":2,"#, "")));
        v.push(("missing claims".into(), format!("{{\"format\":2,\"sig\":\"{}\"}}", "00".repeat(64))));
        v.push(("missing sig".into(), rep(&format!(",\"sig\":\"{GOLDEN_SIG_HEX}\""), "")));
        v.push(("missing issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000,"#, "")));
        v.push(("missing expires_at_ms".into(), rep(r#","expires_at_ms":1732592000000"#, "")));
        v.push(("missing min_upgradable_from".into(), rep(r#","min_upgradable_from":"0.1.0""#, "")));
        v.push(("null min_upgradable_from".into(), rep(r#""min_upgradable_from":"0.1.0""#, r#""min_upgradable_from":null"#)));
        v.push(("negative zero issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000"#, r#""issued_at_ms":-0"#)));
        v.push(("negative zero expires_at_ms".into(), rep(r#""expires_at_ms":1732592000000"#, r#""expires_at_ms":-0"#)));
        for (k, val) in [
            ("ring", r#""canary""#.to_string()),
            ("version", r#""0.1.0""#.to_string()),
            ("msi_sha256", "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"".to_string()),
            ("msi_url", "\"https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi\"".to_string()),
            ("product_version", r#""1.3.0""#.to_string()),
            ("product_code", r#""{11111111-2222-3333-4444-555555555555}""#.to_string()),
            ("upgrade_code", r#""{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}""#.to_string()),
        ] {
            v.push((format!("missing {k}"), rep(&format!("\"{k}\":{val},"), "")));
            v.push((format!("null {k}"), rep(&format!("\"{k}\":{val}"), &format!("\"{k}\":null"))));
            v.push((format!("number {k}"), rep(&format!("\"{k}\":{val}"), &format!("\"{k}\":1"))));
        }
        v.push(("null format".into(), rep(r#""format":2"#, r#""format":null"#)));
        v.push(("null claims".into(), rep(r#""claims":{"#, r#""claims":null,"x":{"#)));
        v.push(("null release".into(), rep(r#""release":{"ring""#, r#""release":null,"x":{"ring""#)));
        v.push(("null issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000"#, r#""issued_at_ms":null"#)));
        v.push(("null expires_at_ms".into(), rep(r#""expires_at_ms":1732592000000"#, r#""expires_at_ms":null"#)));
        v.push(("null sig".into(), rep(&format!("\"sig\":\"{GOLDEN_SIG_HEX}\""), r#""sig":null"#)));
        v.push(("string issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000"#, r#""issued_at_ms":"1730000000000""#)));
        v.push(("float issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000"#, r#""issued_at_ms":1730000000000.0"#)));
        v.push(("exponent expires_at_ms".into(), rep(r#""expires_at_ms":1732592000000"#, r#""expires_at_ms":1.732592e12"#)));
        v.push(("overflow expires_at_ms".into(), rep(r#""expires_at_ms":1732592000000"#, r#""expires_at_ms":9223372036854775808"#)));
        v.push(("leading zero issued_at_ms".into(), rep(r#""issued_at_ms":1730000000000"#, r#""issued_at_ms":01730000000000"#)));
        v.push(("null document".into(), "null".into()));
        v.push(("array document".into(), "[]".into()));

        for f in ["0", "1", "3", "4294967295", "-2", r#""2""#, "2.0", "2.5", "2e0", "true"] {
            v.push((format!("format {f}"), rep(r#""format":2"#, &format!("\"format\":{f}"))));
        }

        v.push(("unknown top".into(), rep(r#"{"format""#, r#"{"rollback":true,"format""#)));
        v.push(("unknown claims".into(), rep(r#""issued_at_ms""#, r#""x":1,"issued_at_ms""#)));
        v.push(("unknown release".into(), rep(r#""ring""#, r#""exec":"cmd.exe","ring""#)));

        for tail in ["x", "{}", ",", "}", "\n{}", " null", "\0"] {
            v.push((format!("trailing {tail:?}"), format!("{g}{tail}")));
        }

        v.push(("empty".into(), String::new()));
        v.push(("truncated".into(), g[..g.len() - 1].to_string()));
        v.push(("trailing comma".into(), rep(r#""min_upgradable_from":"0.1.0""#, r#""min_upgradable_from":"0.1.0","#)));
        v.push(("bare value".into(), rep(r#""ring":"canary""#, r#""ring":canary"#)));
        v.push(("control char in string".into(), rep(r#""ring":"canary""#, "\"ring\":\"can\nary\"")));
        v.push(("lone surrogate".into(), rep(r#""ring":"canary""#, r#""ring":"can\ud800ary""#)));
        v.push(("lone low surrogate".into(), rep(r#""ring":"canary""#, r#""ring":"can\udc00ary""#)));
        v.push(("bad escape".into(), rep(r#""ring":"canary""#, r#""ring":"can\qary""#)));

        assert!(v.len() >= 100, "only {} variants: the list has lost cases", v.len());
        let mut accepted = Vec::new();
        for (name, js) in &v {
            assert_ne!(js, &g, "{name}: the variant equals the golden JSON");
            if SignedUpdateManifestV2::from_json(js).is_ok() {
                accepted.push(name.clone());
            }
        }
        assert!(accepted.is_empty(), "Rust accepted variants Go refuses: {accepted:?}");

        // Whitespace and escapes are accepted by both sides.
        assert!(SignedUpdateManifestV2::from_json(&format!(" \t\r\n{g}\n \r\t")).is_ok());
        let escaped = g.replacen(r#""canary""#, r#""canary\/""#, 1);
        assert_eq!(SignedUpdateManifestV2::from_json(&escaped).unwrap().claims.release.ring, "canary/");
        let pair = g.replacen(r#""canary""#, r#""😀""#, 1);
        assert_eq!(SignedUpdateManifestV2::from_json(&pair).unwrap().claims.release.ring, "\u{1F600}");
    }
}
