//! Pinning the control plane's DIRECTIVE public key (docs/65 D-C3).
//!
//! The key is pinned once, into the ACL-protected `config.json`, from exactly two places:
//!
//! * the enroll response (`directive_pubkey`), at first enrollment;
//! * the MSI property `DIRECTIVE_PUBKEY`, at install or upgrade (`agent_host.exe msi-provision <file> <key>`).
//!
//! Both are SET-IF-BLANK: a different key that is already pinned is preserved and reported, never rotated
//! (rotation is an operator act on the box, like the update signer). Nothing that arrives over signaling, no
//! grant and no manifest can reach this module, which is the point: a compromised grant signer cannot replace
//! the key that guards a fleet wipe. The pin must also be a DEDICATED key: equal to the grant issuer's or the
//! update signer's key it is refused (one compromised seed must not be enough).

use rmt_crypto::PublicIdentity;

use crate::config::HelperConfig;

/// Why a candidate key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// Not 64 hex chars, not a curve point, or a weak (small-order) point.
    Malformed,
    /// Equal to the grant issuer's key.
    SameAsGrantIssuer,
    /// Equal to the update signer's key.
    SameAsUpdateSigner,
    /// The config text is not a JSON object.
    ConfigNotAnObject,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PinError::Malformed => "directive public key is not a usable Ed25519 key",
            PinError::SameAsGrantIssuer => "directive key equals the grant issuer key (it must be dedicated)",
            PinError::SameAsUpdateSigner => "directive key equals the update signer key (it must be dedicated)",
            PinError::ConfigNotAnObject => "config is not a JSON object",
        })
    }
}

/// What a pin attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The key was written.
    Pinned,
    /// The same key was already pinned.
    AlreadyPinned,
    /// A DIFFERENT key is pinned; it was kept (no rotation).
    KeptExisting,
}

/// Normalise (trim, lowercase) and validate a candidate key: 64 hex chars that decode to a non-weak Ed25519 point.
pub fn normalize(candidate: &str) -> Result<String, PinError> {
    let key = candidate.trim().to_ascii_lowercase();
    if key.len() != 64 || PublicIdentity::from_hex(&key).is_err() {
        return Err(PinError::Malformed);
    }
    Ok(key)
}

fn same(a: Option<&str>, key: &str) -> bool {
    a.map(str::trim).is_some_and(|s| !s.is_empty() && s.eq_ignore_ascii_case(key))
}

/// Refuse a key that is also the grant issuer's or the update signer's.
pub fn check_dedicated(key: &str, grant: Option<&str>, update: Option<&str>) -> Result<(), PinError> {
    if same(grant, key) {
        return Err(PinError::SameAsGrantIssuer);
    }
    if same(update, key) {
        return Err(PinError::SameAsUpdateSigner);
    }
    Ok(())
}

/// The pinned directive key of `cfg`, if one is present AND usable (valid, and dedicated). Anything else is "no pinned
/// key": every directive is refused and `directive_v1` is not advertised. Re-validated on every call so a hand-edited
/// config that makes the key equal to another signer's disables directives rather than trusting it.
pub fn pinned(cfg: &HelperConfig) -> Option<String> {
    let raw = cfg.directive_pubkey.as_deref()?;
    let key = normalize(raw).ok()?;
    check_dedicated(&key, cfg.grant_issuer_pubkey.as_deref(), cfg.update_signer_pubkey.as_deref()).ok()?;
    Some(key)
}

/// Set-if-blank in a loaded config (the enroll path). The caller persists.
pub fn pin_into_config(cfg: &mut HelperConfig, candidate: &str) -> Result<PinOutcome, PinError> {
    let key = normalize(candidate)?;
    check_dedicated(&key, cfg.grant_issuer_pubkey.as_deref(), cfg.update_signer_pubkey.as_deref())?;
    match cfg.directive_pubkey.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => {
            cfg.directive_pubkey = Some(key);
            Ok(PinOutcome::Pinned)
        }
        Some(existing) if existing.eq_ignore_ascii_case(&key) => Ok(PinOutcome::AlreadyPinned),
        Some(_) => Ok(PinOutcome::KeptExisting),
    }
}

/// Set-if-blank on the RAW JSON object (the MSI upgrade path: unknown fields must survive). `Ok(None)` when nothing
/// changes; `Ok(Some(text))` is the new document.
pub fn pin_config_json(text: &str, candidate: &str) -> Result<Option<String>, PinError> {
    let key = normalize(candidate)?;
    let mut value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|_| PinError::ConfigNotAnObject)?;
    let obj = value.as_object_mut().ok_or(PinError::ConfigNotAnObject)?;
    let text_of = |o: &serde_json::Map<String, serde_json::Value>, k: &str| -> Option<String> {
        o.get(k).and_then(|v| v.as_str()).map(str::to_owned)
    };
    check_dedicated(
        &key,
        text_of(obj, "grant_issuer_pubkey").as_deref(),
        text_of(obj, "update_signer_pubkey").as_deref(),
    )?;
    let existing = text_of(obj, "directive_pubkey").unwrap_or_default();
    if !existing.trim().is_empty() {
        return Ok(None); // same key, or a different one that is preserved (no rotation)
    }
    obj.insert("directive_pubkey".into(), key.into());
    serde_json::to_string_pretty(&value).map(Some).map_err(|_| PinError::ConfigNotAnObject)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Go golden directive key (control-plane/directive_vectors_test.go): a real Ed25519 point.
    const KEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    const OTHER: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";

    #[test]
    fn malformed_or_weak_keys_are_refused() {
        for bad in ["", "abc", &"zz".repeat(32), &"00".repeat(32), &"ab".repeat(33)] {
            assert_eq!(normalize(bad), Err(PinError::Malformed), "{bad:?}");
        }
        assert_eq!(normalize(&format!("  {}  ", KEY.to_uppercase())).unwrap(), KEY);
    }

    #[test]
    fn a_key_shared_with_another_signer_is_refused() {
        assert_eq!(check_dedicated(KEY, Some(KEY), None), Err(PinError::SameAsGrantIssuer));
        assert_eq!(check_dedicated(KEY, None, Some(&KEY.to_uppercase())), Err(PinError::SameAsUpdateSigner));
        assert_eq!(check_dedicated(KEY, Some(OTHER), Some("")), Ok(()));
        let mut cfg = HelperConfig { grant_issuer_pubkey: Some(KEY.into()), ..Default::default() };
        assert_eq!(pin_into_config(&mut cfg, KEY), Err(PinError::SameAsGrantIssuer));
        assert!(cfg.directive_pubkey.is_none());
    }

    #[test]
    fn pinning_is_set_if_blank_and_never_rotates() {
        let mut cfg = HelperConfig::default();
        assert_eq!(pin_into_config(&mut cfg, KEY), Ok(PinOutcome::Pinned));
        assert_eq!(pin_into_config(&mut cfg, KEY), Ok(PinOutcome::AlreadyPinned));
        assert_eq!(pin_into_config(&mut cfg, OTHER), Ok(PinOutcome::KeptExisting));
        assert_eq!(cfg.directive_pubkey.as_deref(), Some(KEY), "a second, different key must not replace the pin");
        let mut blank = HelperConfig { directive_pubkey: Some("  ".into()), ..Default::default() };
        assert_eq!(pin_into_config(&mut blank, OTHER), Ok(PinOutcome::Pinned));
    }

    #[test]
    fn the_effective_pin_is_revalidated_on_every_read() {
        let mut cfg = HelperConfig { directive_pubkey: Some(KEY.into()), ..Default::default() };
        assert_eq!(pinned(&cfg).as_deref(), Some(KEY));
        // A hand-edit that makes the directive key equal the grant issuer's disables directives.
        cfg.grant_issuer_pubkey = Some(KEY.into());
        assert_eq!(pinned(&cfg), None);
        cfg.grant_issuer_pubkey = None;
        cfg.directive_pubkey = Some("not-a-key".into());
        assert_eq!(pinned(&cfg), None);
        assert_eq!(pinned(&HelperConfig::default()), None);
    }

    #[test]
    fn raw_json_pinning_keeps_unknown_fields_and_never_rotates() {
        let text = r#"{"custom":{"keep":1},"device_id":"d","grant_issuer_pubkey":""}"#;
        let new = pin_config_json(text, KEY).unwrap().expect("pinned");
        let v: serde_json::Value = serde_json::from_str(&new).unwrap();
        assert_eq!(v["directive_pubkey"], KEY);
        assert_eq!(v["custom"]["keep"], 1);
        assert_eq!(v["device_id"], "d");
        // Already pinned (same or different): untouched.
        assert_eq!(pin_config_json(&new, KEY).unwrap(), None);
        assert_eq!(pin_config_json(&new, OTHER).unwrap(), None);
        // A shared key is refused.
        let shared = format!(r#"{{"update_signer_pubkey":"{KEY}"}}"#);
        assert_eq!(pin_config_json(&shared, KEY), Err(PinError::SameAsUpdateSigner));
        assert_eq!(pin_config_json("[1]", KEY), Err(PinError::ConfigNotAnObject));
        assert_eq!(pin_config_json("{}", "nope"), Err(PinError::Malformed));
    }
}
