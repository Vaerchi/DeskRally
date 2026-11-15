//! Shared Authenticode publisher verification and update version validation.
//! Format-2 manifest fetching and MSI downloads live in `update_feed`.

#![cfg(windows)]

use std::path::Path;
use crate::update_guard::check_no_reparse_ancestors;

fn require_publisher(publisher: &str) -> Result<(), String> {
    if publisher.is_empty() {
        return Err("this build has no pinned publisher; signed-binary checks are disabled".into());
    }
    Ok(())
}

/// Validate `<major>.<minor>.<patch>` optionally followed by `+<strict-lowercase-hex>`.
///
/// Strict hex: `[0-9a-f]+` only. Uppercase, non-hex characters, and an empty metadata string
/// after `+` are all refused. This matches the build metadata produced by `build.rs`
/// (`<short git sha>` in lowercase hex) and nothing else.
pub(crate) fn validate_version_segment(s: &str) -> Result<(), &'static str> {
    let (core, meta) = s
        .split_once('+')
        .map(|(c, m)| (c, Some(m)))
        .unwrap_or((s, None));

    // Core must be a valid parseable semver triple (no pre-release, no leading zeros).
    rmt_agent::update::parse_version(core).map_err(|_| "not a valid semver core")?;

    if let Some(meta) = meta {
        if meta.is_empty() {
            return Err("build metadata after '+' must not be empty");
        }
        if !meta
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("build metadata must be strict lowercase hex (0-9, a-f)");
        }
    }

    Ok(())
}

// ── Authenticode verification ─────────────────────────────────────────────────

/// Require the trusted timestamped publisher; the short-lived leaf certificate rotates.
pub fn verify_authenticode(path: &Path) -> Result<(), String> {
    require_publisher(env!("DESKRALLY_UPDATE_PUBLISHER"))?;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::*;
    check_no_reparse_ancestors(path).map_err(|e| e.to_string())?;
    if !path.is_absolute() {
        return Err("signature path must be absolute".into());
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let result = if status != 0 {
        Err(format!("untrusted Authenticode signature: {status:#x}"))
    } else if data.hWVTStateData == HANDLE::default() {
        Err("missing verified signature state".into())
    } else {
        unsafe { verified_publisher(data.hWVTStateData) }
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    result
}

// Read only provider-owned data while the WinVerifyTrust state remains open.
unsafe fn verified_publisher(state: windows::Win32::Foundation::HANDLE) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::*;
    use windows::Win32::Security::WinTrust::*;
    let provider = WTHelperProvDataFromStateData(state);
    if provider.is_null() {
        return Err("missing provider".into());
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
    if signer.is_null() {
        return Err("missing signer".into());
    }
    let signer = &*signer;
    if signer.dwError != 0
        || signer.csCounterSigners == 0
        || signer.pasCounterSigners.is_null()
        || (*signer.pasCounterSigners).dwError != 0
    {
        return Err("validated timestamp required".into());
    }
    if signer.csCertChain == 0 || signer.pasCertChain.is_null() {
        return Err("missing signer chain".into());
    }
    let cert = (*signer.pasCertChain).pCert;
    if cert.is_null() || (*cert).pCertInfo.is_null() {
        return Err("missing signer certificate".into());
    }
    let mut text = [0u16; 1024];
    let len = CertNameToStrW(
        X509_ASN_ENCODING,
        &(*(*cert).pCertInfo).Subject,
        CERT_STRING_TYPE(CERT_X500_NAME_STR.0 | CERT_NAME_STR_REVERSE_FLAG),
        Some(&mut text),
    );
    if len < 2 || len as usize > text.len() {
        return Err("invalid publisher subject".into());
    }
    let subject =
        String::from_utf16(&text[..len as usize - 1]).map_err(|_| "invalid subject encoding")?;
    // DeskRally's publisher, or the build kit's own-feed publisher (docs/48 B.3: a subject match, a
    // secondary check; the update key authenticates the package).
    if subject != env!("DESKRALLY_UPDATE_PUBLISHER") {
        return Err("unexpected publisher subject".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_publisher_is_refused_before_path_checks() {
        let expected = "this build has no pinned publisher; signed-binary checks are disabled";
        assert_eq!(require_publisher(""), Err(expected.into()));
        assert!(require_publisher("CN=Example").is_ok());
        if env!("DESKRALLY_UPDATE_PUBLISHER").is_empty() {
            assert_eq!(verify_authenticode(Path::new("relative")), Err(expected.into()));
        }
    }

    #[test]
    fn valid_version_segments() {
        for s in ["0.0.2", "1.2.3", "0.0.2+abc123", "1.2.3+deadbeef"] {
            assert!(validate_version_segment(s).is_ok(), "expected Ok for {s:?}");
        }
    }

    #[test]
    fn invalid_version_segments() {
        for s in [
            "0.0",
            "0.0.2-rc1",
            "0.0.2+UPPER",
            "0.0.2+",
            "0.0.2+abc_",
            "banana",
            "",
        ] {
            assert!(
                validate_version_segment(s).is_err(),
                "expected Err for {s:?}"
            );
        }
    }

    #[test]
    fn unsigned_file_is_rejected_by_windows_trust() {
        let path =
            std::env::temp_dir().join(format!("rmt-update-unsigned-{}.exe", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"not a PE").unwrap();
        assert!(verify_authenticode(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn configured_real_signed_fixture_is_accepted() {
        if !env!("DESKRALLY_UPDATE_PUBLISHER").is_empty() {
            if let Some(path) = std::env::var_os("RMT_UPDATE_SIGNED_FIXTURE") {
                verify_authenticode(Path::new(&path)).unwrap();
            }
        }
    }
}
