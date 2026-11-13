//! MSI provisioning boundary. Never invoked by ordinary service startup.
//!
//! The deferred MSI action runs this executable as SYSTEM with only a local file PATH in argv.
//! Existing enrolled config and identity are read-only: repairs/upgrades must not apply defaults,
//! spend another token, or discard unknown settings. Fresh enrollment uses the existing protocol.
//! On install rollback we intentionally retain the protected identity/config: remote token
//! redemption cannot be rolled back, and deleting its key would strand the redeemed device.

use crate::config::{HelperConfig, CONFIG_DIR, CONFIG_FILE, DEFAULT_IDENTITY_FILE};
use std::{fs::File, io::Read, os::windows::fs::OpenOptionsExt, path::Path};

const MAX_BYTES: u64 = 64 * 1024;

// Exit codes are deliberately non-secret; neither JSON/parser errors nor enrollment responses
// are printed. A hostile endpoint may echo the token in its error body.
const INVALID: i32 = 20;
const UNTRUSTED: i32 = 21;
const EXISTING_INVALID: i32 = 22;
const ENROLL_FAILED: i32 = 23;
const IO_FAILED: i32 = 24;

fn configured(cfg: &HelperConfig) -> bool {
    cfg.device_id
        .as_deref()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
        && cfg
            .tenant_id
            .as_deref()
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
}

fn settings_valid(cfg: &HelperConfig) -> bool {
    let Some(cp) = cfg.control_plane_url.as_deref() else {
        return false;
    };
    if crate::enroll::validate_control_plane_url(cp).is_err() {
        return false;
    }
    let Some(ws) = cfg.signaling_url.as_deref() else {
        return false;
    };
    let http = if let Some(tail) = ws.strip_prefix("wss://") {
        format!("https://{tail}")
    } else if let Some(tail) = ws.strip_prefix("ws://") {
        format!("http://{tail}")
    } else {
        return false;
    };
    if crate::enroll::validate_control_plane_url(&http).is_err() {
        return false;
    }
    if cfg
        .identity_path
        .as_deref()
        .is_some_and(|p| p != DEFAULT_IDENTITY_FILE)
    {
        return false;
    }
    let pin = cfg.grant_issuer_pubkey.as_deref().unwrap_or("").trim();
    let update = cfg.update_signer_pubkey.as_deref().unwrap_or("").trim();
    for key in [pin, update] {
        if !key.is_empty() && (key.len() != 64 || hex::decode(key).is_err()) {
            return false;
        }
    }
    if cfg.require_session_policy && pin.is_empty() {
        return false;
    }
    if !update.is_empty() && update.eq_ignore_ascii_case(pin) {
        return false;
    }
    true
}

fn fresh_config(data: &str) -> Result<HelperConfig, i32> {
    let value: serde_json::Value =
        serde_json::from_str(data.trim_start_matches('\u{feff}')).map_err(|_| INVALID)?;
    let obj = value.as_object().ok_or(INVALID)?;
    // Reject typos and identity injection; serde's permissive runtime loader is inappropriate
    // at first installation. Future runtime settings are preserved verbatim on upgrade.
    const KEYS: &[&str] = &[
        "signaling_url",
        "control_plane_url",
        "enrollment_token",
        "stun",
        "transfer_dir",
        "grant_issuer_pubkey",
        "update_signer_pubkey",
        "directive_pubkey",
        "require_session_policy",
        "max_session_secs",
        "quality",
        "clipboard",
    ];
    if obj.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return Err(INVALID);
    }
    let cfg: HelperConfig = serde_json::from_value(value).map_err(|_| INVALID)?;
    // docs/65 D-C3: a supplied directive key must be a usable, DEDICATED key; refuse the install rather than silently run without one.
    if let Some(key) = cfg.directive_pubkey.as_deref().filter(|k| !k.trim().is_empty()) {
        let key = crate::directive_pin::normalize(key).map_err(|_| INVALID)?;
        crate::directive_pin::check_dedicated(&key, cfg.grant_issuer_pubkey.as_deref(), cfg.update_signer_pubkey.as_deref())
            .map_err(|_| INVALID)?;
    }
    if !settings_valid(&cfg)
        || !cfg
            .enrollment_token
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty())
    {
        return Err(INVALID);
    }
    Ok(cfg)
}

/// Only SYSTEM/Administrators may own/access a provisioning file or a pre-existing identity root.
/// Check BEFORE hardening: hardening attacker-planted bytes must not make them trusted.
fn trusted_acl(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{
                Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
                GetAce, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
                ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            },
        },
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut owner = PSID::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            &mut sd,
        )
        .is_err()
        {
            return false;
        }
        let privileged = |sid: PSID| {
            IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
        };
        let ok = (|| {
            if acl.is_null() || !privileged(owner) {
                return false;
            }
            for i in 0..(*acl).AceCount {
                let mut ace = std::ptr::null_mut();
                if GetAce(acl, u32::from(i), &mut ace).is_err() {
                    return false;
                }
                // Accept only ordinary allow ACEs for the two privileged principals. Reject
                // unknown/object/callback ACEs rather than partially interpreting access rules.
                if (*(ace as *const ACE_HEADER)).AceType != 0 {
                    return false;
                }
                let allow = &*(ace as *const ACCESS_ALLOWED_ACE);
                if !privileged(PSID((&allow.SidStart as *const u32).cast_mut().cast())) {
                    return false;
                }
            }
            (*acl).AceCount > 0
        })();
        let _ = LocalFree(HLOCAL(sd.0));
        ok
    }
}

fn local_file(path: &Path) -> Result<String, i32> {
    use rmt_agent::backstage::panels::local_path;
    let text = path.to_str().ok_or(INVALID)?;
    local_path::validate_path_shape(text).map_err(|_| UNTRUSTED)?;
    local_path::refuse_remote_drive(text).map_err(|_| UNTRUSTED)?;
    local_path::refuse_reparse_indirection(text).map_err(|_| UNTRUSTED)?;
    if !trusted_acl(path) || !path.parent().is_some_and(trusted_acl) {
        return Err(UNTRUSTED);
    }
    // No write/delete sharing while reading; bound actual bytes, not just a racy metadata size.
    let file = File::options()
        .read(true)
        .share_mode(0)
        .open(path)
        .map_err(|_| IO_FAILED)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IO_FAILED)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(INVALID);
    }
    String::from_utf8(bytes).map_err(|_| INVALID)
}

/// The MSI property `DIRECTIVE_PUBKEY` (docs/65 D-C3) against an EXISTING config (upgrade/repair): `Ok(Some(text))` is the document to
/// write (set-if-blank on the raw JSON, unknown fields kept), `Ok(None)` means nothing changes (no key given, or a key is already
/// pinned: never rotated). A malformed or shared key is `INVALID`.
fn existing_config_pin(raw: &str, directive_key: Option<&str>) -> Result<Option<String>, i32> {
    let Some(key) = directive_key.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    crate::directive_pin::pin_config_json(raw, key).map_err(|_| INVALID)
}

fn provision(provisioning: Option<&str>, directive_key: Option<&str>) -> Result<(), i32> {
    let root = Path::new(CONFIG_DIR);
    match std::fs::symlink_metadata(root) {
        Ok(md)
            if crate::agent_root::is_reparse_point(&md) || !md.is_dir() || !trusted_acl(root) =>
        {
            return Err(UNTRUSTED)
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(IO_FAILED),
    }
    let config_path = Path::new(CONFIG_FILE);
    let config_exists = match std::fs::symlink_metadata(config_path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(IO_FAILED),
    };
    if config_exists {
        let raw = local_file(config_path)?;
        let cfg: HelperConfig = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .map_err(|_| EXISTING_INVALID)?;
        if !settings_valid(&cfg) || !configured(&cfg) {
            return Err(EXISTING_INVALID);
        }
        // Read through the same local/ACL checks before decoding the private identity.
        let _ = local_file(Path::new(DEFAULT_IDENTITY_FILE))?;
        if crate::enroll::read_identity(DEFAULT_IDENTITY_FILE)
            .map_err(|_| EXISTING_INVALID)?
            .is_none()
        {
            return Err(EXISTING_INVALID);
        }
        // No re-enroll and no default application, even if PROVISIONINGFILE was supplied. The ONE permitted change is the
        // set-if-blank directive key pin (docs/65 D-C3), written atomically through the anchored agent root.
        if let Some(new) = existing_config_pin(&raw, directive_key)? {
            let anchor = crate::anchor::Anchor::open().map_err(|_| IO_FAILED)?;
            anchor.dir().write_atomic("config.json", new.as_bytes()).map_err(|_| IO_FAILED)?;
        }
        return Ok(());
    }
    let path = provisioning.filter(|p| !p.is_empty()).ok_or(INVALID)?;
    let mut cfg = fresh_config(&local_file(Path::new(path))?)?;
    if let Some(key) = directive_key.map(str::trim).filter(|k| !k.is_empty()) {
        crate::directive_pin::pin_into_config(&mut cfg, key).map_err(|_| INVALID)?;
    }
    if std::fs::symlink_metadata(DEFAULT_IDENTITY_FILE).is_ok() {
        // A failed attempt may have created this key. Reuse only protected, valid key material.
        let _ = local_file(Path::new(DEFAULT_IDENTITY_FILE))?;
        crate::enroll::read_identity(DEFAULT_IDENTITY_FILE).map_err(|_| EXISTING_INVALID)?;
    }
    crate::agent_root::harden_agent_root(root).map_err(|_| UNTRUSTED)?;
    // enroll_once writes config only after success, and clears its token. Failure leaves no
    // un-enrolled config that an automatic service could accidentally treat as unmanaged.
    crate::enroll::enroll_once(&mut cfg, CONFIG_FILE, None).map_err(|_| ENROLL_FAILED)?;
    crate::agent_root::harden_agent_root(root).map_err(|_| UNTRUSTED)?;
    Ok(())
}

pub fn command(args: &[String]) -> i32 {
    // msi-provision [<file> [<DIRECTIVE_PUBKEY>]]
    if args.len() > 4 {
        return INVALID;
    }
    match provision(args.get(2).map(String::as_str), args.get(3).map(String::as_str)) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> serde_json::Value {
        serde_json::json!({
            "control_plane_url":"https://cp.example/cp", "signaling_url":"wss://cp.example/ws",
            "enrollment_token":"test-only", "clipboard":"disabled", "max_session_secs":900
        })
    }
    #[test]
    fn msi_fresh_config_rejects_identity_injection_and_typos() {
        for key in ["device_id", "tenant_id", "identity_path", "enrolment_token"] {
            let mut v = input();
            v[key] = "attacker".into();
            assert_eq!(fresh_config(&v.to_string()).unwrap_err(), INVALID);
        }
    }
    #[test]
    fn msi_preserves_requested_settings_and_requires_secure_endpoints() {
        let cfg = fresh_config(&input().to_string()).unwrap();
        assert_eq!(cfg.max_session_secs, Some(900));
        for (key, bad) in [
            ("control_plane_url", "http://remote.example/cp"),
            ("signaling_url", "ws://remote.example/ws"),
            ("control_plane_url", "https://user:pass@cp.example"),
            ("enrollment_token", ""),
        ] {
            let mut v = input();
            v[key] = bad.into();
            assert!(fresh_config(&v.to_string()).is_err());
        }
    }
    #[test]
    fn msi_refuses_unverifiable_policy_and_shared_update_authority() {
        let mut v = input();
        v["require_session_policy"] = true.into();
        assert!(fresh_config(&v.to_string()).is_err());
        v["grant_issuer_pubkey"] = "ab".repeat(32).into();
        assert!(fresh_config(&v.to_string()).is_ok());
        v["update_signer_pubkey"] = "AB".repeat(32).into();
        assert!(fresh_config(&v.to_string()).is_err());
    }
    const DKEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

    #[test]
    fn msi_fresh_config_accepts_a_dedicated_directive_key_and_refuses_a_shared_or_malformed_one() {
        let mut v = input();
        v["directive_pubkey"] = DKEY.into();
        assert!(fresh_config(&v.to_string()).is_ok());
        v["directive_pubkey"] = "nonsense".into();
        assert_eq!(fresh_config(&v.to_string()).unwrap_err(), INVALID);
        v["directive_pubkey"] = DKEY.into();
        v["grant_issuer_pubkey"] = DKEY.to_uppercase().into();
        assert_eq!(fresh_config(&v.to_string()).unwrap_err(), INVALID, "a key shared with the grant issuer");
        v["grant_issuer_pubkey"] = "ab".repeat(32).into();
        v["update_signer_pubkey"] = DKEY.into();
        assert_eq!(fresh_config(&v.to_string()).unwrap_err(), INVALID, "a key shared with the update signer");
    }

    #[test]
    fn msi_upgrade_pins_a_blank_directive_key_once_and_never_rotates() {
        let raw = r#"{"device_id":"d","custom":1}"#;
        assert_eq!(existing_config_pin(raw, None), Ok(None));
        assert_eq!(existing_config_pin(raw, Some("  ")), Ok(None));
        let new = existing_config_pin(raw, Some(DKEY)).unwrap().expect("pinned");
        let v: serde_json::Value = serde_json::from_str(&new).unwrap();
        assert_eq!((v["directive_pubkey"].as_str(), v["custom"].as_i64()), (Some(DKEY), Some(1)));
        let other = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
        assert_eq!(existing_config_pin(&new, Some(other)), Ok(None), "a different key must not rotate the pin");
        assert_eq!(existing_config_pin(raw, Some("zz")), Err(INVALID));
    }

    #[test]
    fn msi_command_takes_at_most_a_file_and_a_key() {
        let a = |n: usize| (0..n).map(|i| i.to_string()).collect::<Vec<_>>();
        assert_eq!(command(&a(5)), INVALID);
    }

    #[test]
    fn msi_enrolled_state_requires_both_server_identifiers() {
        let mut cfg = fresh_config(&input().to_string()).unwrap();
        cfg.device_id = Some(uuid::Uuid::new_v4().to_string());
        assert!(!configured(&cfg));
        cfg.tenant_id = Some(uuid::Uuid::new_v4().to_string());
        assert!(configured(&cfg));
    }
}
