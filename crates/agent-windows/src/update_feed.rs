//! The format-2 (MSI) release feed: fetch and verify a ring manifest, download the package.
//!
//! The feed host is compile-time. A config knob for it would let whoever can edit config redirect
//! the download to a host the signature check cannot speak for. The test feed is a cargo feature
//! with its own host; release packaging refuses a binary built with it (design v3).
//!
//! Format 2 lives under `/download/agent/v2/`, separate from format 1, so agents that only speak
//! format 1 never fetch an MSI manifest at all (they would refuse it anyway: deny_unknown_fields).

#![cfg(windows)]

use std::io::{Read as _, Write as _};

use rmt_agent::update::{ReleaseV2, SignedUpdateManifestV2, UpdateAvailability, UpdateTrust};

/// Build-time feed identity; empty unless explicitly selected by the builder.
#[cfg(not(feature = "update-test-feed"))]
pub const FEED: &str = env!("DESKRALLY_UPDATE_FEED_OVERRIDE");
#[cfg(feature = "update-test-feed")]
pub const FEED: &str = "https://deskrally-update-test.lan";

/// Whether this binary has an update feed. Log the disabled mode once per process.
pub fn configured() -> bool {
    if FEED.is_empty() {
        static LOG_ONCE: std::sync::Once = std::sync::Once::new();
        LOG_ONCE.call_once(|| tracing::info!("auto-update is not configured in this build"));
        false
    } else {
        true
    }
}

fn require_configured() -> Result<(), FeedError> {
    if configured() {
        Ok(())
    } else {
        Err(FeedError::Transient("auto-update is not configured in this build".into()))
    }
}

pub const PACKAGE_NAME: &str = "DeskRallyAgent.msi";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Why a feed step failed, which decides backoff vs. quarantine (design v2 D8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    /// Network, HTTP status, timeouts, a manifest we could not believe: retry with backoff.
    Transient(String),
    /// Correctly-hashed signed bytes that fail Authenticode or identity checks: the release is
    /// broken, quarantine it.
    Verification(String),
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedError::Transient(s) => write!(f, "transient: {s}"),
            FeedError::Verification(s) => write!(f, "verification: {s}"),
        }
    }
}

pub fn manifest_url(ring: &str) -> Result<String, FeedError> {
    require_configured()?;
    Ok(format!("{FEED}/download/agent/v2/{ring}/manifest.json"))
}

pub fn package_url(version: &str) -> Option<String> {
    if !configured() {
        return None;
    }
    package_url_for_feed(FEED, version)
}

fn package_url_for_feed(feed: &str, version: &str) -> Option<String> {
    if feed.is_empty() {
        return None;
    }
    let core = version.split('+').next()?;
    Some(format!("{feed}/download/agent/releases/{core}/{PACKAGE_NAME}"))
}

fn client() -> Result<reqwest::blocking::Client, FeedError> {
    // The shared trust configuration (OS store UNION bundled roots), as enrollment uses: a fresh
    // machine whose store lacks ISRG Root X1 refused the production feed with OS roots alone
    // (acceptance VM, 2026-10-15). The lab feed's CA is in LocalMachine\Root, so it still works.
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(rmt_transport_webrtc::tls_trust::client_config().map_err(FeedError::Transient)?)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| FeedError::Transient(format!("http client: {e}")))
}

/// Every check a verified release must pass beyond its signature, in one place so it is testable
/// without a network (design v3 step 3, v4 version identity).
pub fn check_release(
    release: &ReleaseV2,
    ring: &str,
    installed_version: &str,
    installed_product_version: &str,
) -> Result<bool, String> {
    check_release_mode(release, ring, installed_version, installed_product_version, false)
}

/// [`check_release`] with the docs/65 reinstall rule: when `allow_same` is set, a release that is EXACTLY the installed one (same
/// version, same ProductVersion) is offered too, so a `reinstall` directive can repair the current signed release. Never a
/// downgrade: anything older than what is installed is still refused. Every other check (ring, URL, family, version mapping)
/// is unchanged, and the directive supplies none of them.
pub fn check_release_mode(
    release: &ReleaseV2,
    ring: &str,
    installed_version: &str,
    installed_product_version: &str,
    allow_same: bool,
) -> Result<bool, String> {
    require_configured().map_err(|e| e.to_string())?;
    // Check against the public URL builder as well as the shared identity validator.
    if Some(&release.msi_url) != package_url(&release.version).as_ref() {
        return Err("package URL does not match the signed version".into());
    }
    check_release_for_feed(FEED, release, ring, installed_version, installed_product_version, allow_same)
}

fn check_release_for_feed(
    feed: &str,
    release: &ReleaseV2,
    ring: &str,
    installed_version: &str,
    installed_product_version: &str,
    allow_same: bool,
) -> Result<bool, String> {
    if release.ring != ring {
        return Err("manifest ring differs from local policy".into());
    }
    crate::update_download::validate_version_segment(&release.version).map_err(str::to_string)?;
    if Some(&release.msi_url) != package_url_for_feed(feed, &release.version).as_ref() {
        return Err("package URL does not match the signed version".into());
    }
    if release.upgrade_code != crate::update_msi::UPGRADE_CODE {
        return Err("manifest names another product family".into());
    }
    if crate::update_msi::product_version_for(&release.version).as_deref()
        != Some(release.product_version.as_str())
    {
        return Err("ProductVersion does not map to the agent version".into());
    }
    if allow_same
        && crate::update_msi::product_version_cmp(&release.product_version, installed_product_version)
            == Some(std::cmp::Ordering::Equal)
        && rmt_agent::update::compare_versions(&release.version, installed_version).map_err(|e| e.to_string())?
            == std::cmp::Ordering::Equal
    {
        return Ok(true);
    }
    let newer_msi = crate::update_msi::product_version_cmp(
        &release.product_version,
        installed_product_version,
    ) == Some(std::cmp::Ordering::Greater);
    let available = matches!(
        release.availability(installed_version).map_err(|e| e.to_string())?,
        UpdateAvailability::Available { .. }
    );
    Ok(newer_msi && available)
}

/// Fetch and verify the ring manifest. `Ok(None)`: no manifest (404) or nothing newer.
pub fn fetch_offer(
    update_pin: Option<&str>,
    grant_pin: Option<&str>,
    ring: &str,
    installed_version: &str,
    installed_product_version: &str,
    now_ms: i64,
    allow_same: bool,
) -> Result<Option<ReleaseV2>, FeedError> {
    require_configured()?;
    let key = match UpdateTrust::from_config(update_pin, grant_pin) {
        UpdateTrust::VerifyWith(k) => k,
        UpdateTrust::RefuseAllUpdates(reason) => {
            return Err(FeedError::Transient(format!("no update trust: {reason}")))
        }
    };
    if !matches!(ring, "canary" | "early" | "general") {
        return Err(FeedError::Transient("invalid ring".into()));
    }
    let resp = client()?
        .get(manifest_url(ring)?)
        .send()
        .map_err(|e| FeedError::Transient(format!("manifest fetch: {e}")))?;
    match resp.status().as_u16() {
        404 => return Ok(None),
        200 => {}
        s => return Err(FeedError::Transient(format!("manifest HTTP {s}"))),
    }
    let mut body = Vec::new();
    resp.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| FeedError::Transient(format!("manifest read: {e}")))?;
    if body.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(FeedError::Transient("manifest too large".into()));
    }
    let text = std::str::from_utf8(&body).map_err(|_| FeedError::Transient("manifest not UTF-8".into()))?;
    let signed = SignedUpdateManifestV2::from_json(text)
        .map_err(|e| FeedError::Transient(format!("manifest decode: {e}")))?;
    let release = signed
        .verify(&key, now_ms)
        .map_err(|e| FeedError::Transient(format!("manifest verify: {e}")))?;
    match check_release_mode(&release, ring, installed_version, installed_product_version, allow_same) {
        Ok(true) => Ok(Some(release)),
        Ok(false) => Ok(None),
        Err(e) => Err(FeedError::Transient(format!("manifest rejected: {e}"))),
    }
}

/// Stream the package into `file` (a protected staging child), hashing as it goes. A digest
/// mismatch is Transient (transport corruption); the caller verifies Authenticode and identity.
pub fn download(release: &ReleaseV2, file: &mut std::fs::File) -> Result<(), FeedError> {
    use sha2::Digest;
    require_configured()?;
    let resp = client()?
        .get(&release.msi_url)
        .send()
        .map_err(|e| FeedError::Transient(format!("package fetch: {e}")))?;
    if resp.status().as_u16() != 200 {
        return Err(FeedError::Transient(format!("package HTTP {}", resp.status().as_u16())));
    }
    let mut hash = sha2::Sha256::new();
    let mut reader = resp.take(MAX_PACKAGE_BYTES + 1);
    let mut buf = vec![0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| FeedError::Transient(format!("package read: {e}")))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_PACKAGE_BYTES {
            return Err(FeedError::Transient("package too large".into()));
        }
        file.write_all(&buf[..n])
            .map_err(|e| FeedError::Transient(format!("package write: {e}")))?;
        hash.update(&buf[..n]);
    }
    file.sync_all()
        .map_err(|e| FeedError::Transient(format!("package sync: {e}")))?;
    if hex::encode(hash.finalize()) != release.msi_sha256 {
        return Err(FeedError::Transient("package digest mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercise all release identity rules under a fixed test identity in every build mode.
    const TEST_FEED: &str = "https://updates.example.com";

    fn check_release(r: &ReleaseV2, ring: &str, version: &str, product: &str) -> Result<bool, String> {
        check_release_mode(r, ring, version, product, false)
    }

    fn check_release_mode(r: &ReleaseV2, ring: &str, version: &str, product: &str, same: bool) -> Result<bool, String> {
        check_release_for_feed(TEST_FEED, r, ring, version, product, same)
    }

    fn release() -> ReleaseV2 {
        ReleaseV2 {
            ring: "canary".into(),
            version: "0.1.2".into(),
            msi_sha256: "a".repeat(64),
            msi_url: package_url_for_feed(TEST_FEED, "0.1.2").unwrap(),
            product_version: "1.3.2".into(),
            product_code: "{11111111-2222-3333-4444-555555555555}".into(),
            upgrade_code: crate::update_msi::UPGRADE_CODE.into(),
            min_upgradable_from: "0.1.0".into(),
        }
    }

    #[test]
    fn a_consistent_newer_release_is_offered() {
        assert_eq!(check_release(&release(), "canary", "0.1.1+abc", "1.3.1"), Ok(true));
        assert_eq!(check_release(&release(), "canary", "0.1.2+abc", "1.3.2"), Ok(false));
    }

    #[test]
    fn a_reinstall_may_offer_exactly_the_installed_release_but_never_an_older_one() {
        // docs/65: same version and same ProductVersion is offered only in reinstall mode.
        assert_eq!(check_release_mode(&release(), "canary", "0.1.2+abc", "1.3.2", true), Ok(true));
        assert_eq!(check_release_mode(&release(), "canary", "0.1.2+abc", "1.3.2", false), Ok(false), "an ordinary update never reinstalls");
        // A newer release is still offered, an OLDER one (the machine is ahead of the ring) is not.
        assert_eq!(check_release_mode(&release(), "canary", "0.1.1+abc", "1.3.1", true), Ok(true));
        assert_eq!(check_release_mode(&release(), "canary", "0.1.3+abc", "1.3.3", true), Ok(false));
        // Same ProductVersion but a different agent version string is not "the same release".
        assert_eq!(check_release_mode(&release(), "canary", "0.1.3+abc", "1.3.2", true), Ok(false));
        // Every identity check still applies in reinstall mode.
        let mut r = release();
        r.ring = "general".into();
        assert!(check_release_mode(&r, "canary", "0.1.2+abc", "1.3.2", true).is_err());
        let mut r = release();
        r.upgrade_code = "{00000000-0000-0000-0000-000000000000}".into();
        assert!(check_release_mode(&r, "canary", "0.1.2+abc", "1.3.2", true).is_err());
    }

    #[test]
    fn each_identity_mismatch_is_refused() {
        let mut r = release();
        r.ring = "general".into();
        assert!(check_release(&r, "canary", "0.1.1", "1.3.1").is_err());
        let mut r = release();
        r.msi_url = format!("{FEED}/download/agent/releases/0.1.3/{PACKAGE_NAME}");
        assert!(check_release(&r, "canary", "0.1.1", "1.3.1").is_err());
        let mut r = release();
        r.upgrade_code = "{00000000-0000-0000-0000-000000000000}".into();
        assert!(check_release(&r, "canary", "0.1.1", "1.3.1").is_err());
        let mut r = release();
        r.product_version = "1.3.9".into();
        assert!(check_release(&r, "canary", "0.1.1", "1.3.1").is_err());
        let mut r = release();
        r.version = "0.1.2+UPPER".into();
        assert!(check_release(&r, "canary", "0.1.1", "1.3.1").is_err());
    }

    #[test]
    fn the_bootstrap_from_1_2_7_is_offered_only_from_min_upgradable() {
        // A 1.2.7 machine reports agent 0.0.1+4bd1e5c; min_upgradable_from 0.1.0 refuses it, so
        // the bootstrap itself is a manual install (design: none of the fleet has the updater).
        assert_eq!(check_release(&release(), "canary", "0.0.1+4bd1e5c", "1.2.7"), Ok(false));
    }

    #[test]
    fn feed_matches_the_selected_build_identity() {
        #[cfg(not(feature = "update-test-feed"))]
        assert_eq!(FEED, env!("DESKRALLY_UPDATE_FEED_OVERRIDE"));
        #[cfg(feature = "update-test-feed")]
        assert_eq!(FEED, "https://deskrally-update-test.lan");
        assert_eq!(configured(), !FEED.is_empty());
        assert_eq!(require_configured().is_ok(), configured());
        if configured() {
            assert!(manifest_url("general").unwrap().ends_with("/download/agent/v2/general/manifest.json"));
            let mut r = release();
            r.msi_url = package_url("0.1.2").unwrap();
            assert_eq!(super::check_release(&r, "canary", "0.1.1", "1.3.1"), Ok(true));
        } else {
            assert!(manifest_url("general").is_err());
            assert!(package_url("0.1.2").is_none());
            assert!(super::check_release(&release(), "canary", "0.1.1", "1.3.1").is_err());
        }
    }
    #[test]
    fn unconfigured_manifest_fetch_is_refused_before_trust_or_network() {
        if !configured() {
            let result = fetch_offer(None, None, "general", "0.1.1", "1.3.1", 0, false);
            assert_eq!(result.unwrap_err(), FeedError::Transient("auto-update is not configured in this build".into()));
        }
    }

    #[test]
    fn unconfigured_package_download_is_refused_before_network() {
        if !configured() {
            let path = std::env::temp_dir().join(format!("rmt-unconfigured-update-{}", uuid::Uuid::new_v4()));
            let mut file = std::fs::File::create(&path).unwrap();
            let result = download(&release(), &mut file);
            let len = file.metadata().unwrap().len();
            drop(file);
            std::fs::remove_file(path).unwrap();
            assert_eq!(result.unwrap_err(), FeedError::Transient("auto-update is not configured in this build".into()));
            assert_eq!(len, 0);
        }
    }

}
