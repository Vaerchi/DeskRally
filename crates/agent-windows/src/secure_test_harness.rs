//! Secure-test-harness execution barrier (feature = "secure-test" only).
//!
//! # What this module provides
//!
//! A minimal additive injection seam that lets test callers exercise REAL Ed25519 grant and
//! session-policy verification (the same `SignedGrant::verify` / `SignedSessionPolicy::verify`
//! code the production agent runs) while keeping every Win32 backstage backend structurally
//! absent. The `Dispatcher` type is never constructed; no `ShellExecuteExW`, no SCM call, no
//! registry write ever happens.
//!
//! # What this module does NOT change
//!
//! - Production semantics: every function here is dead code without `--features secure-test`.
//! - Signature verification: `verify_grant_inert` calls the exact same `SignedGrant::verify`
//!   and `SpentGrants::claim_key` as the production `dispatcher_from_signed_grant`.
//! - Session policy admission: `InstallSessionPolicy` handling in `host.rs` is unmodified —
//!   `SignedSessionPolicy::verify` runs identically in both modes.
//! - `BackstageAuth` enum: no new variant added. `SignedBy` is used as-is; only what happens
//!   AFTER successful verification differs when `secure_test_harness: true`.
//!
//! # Security invariants this module must preserve
//!
//! 1. `verify_grant_inert` must call `spent.claim_key` with the VERIFIED signature bytes
//!    (not raw input). A grant that fails `SignedGrant::verify` must not be spent.
//! 2. `inert_extract_setup_zip` must not write any file to the filesystem.
//! 3. `inert_launch_setup_exe` must not call `ShellExecuteExW` or any process-creation API.
//! 4. `check_secure_test_preconditions` must return `Err` when `--grant-issuer` is absent,
//!    when the URL is not loopback, or (on Windows) when `%TEMP%` is not user-owned.

use crate::host::SpentGrants;
use rmt_crypto::PublicIdentity;
use rmt_agent::backstage::grant::SignedGrant;

// ---------------------------------------------------------------------------
// Core verification: same steps as dispatcher_from_signed_grant, no Dispatcher
// ---------------------------------------------------------------------------

/// Verify a signed grant blob exactly as production does, but return `()` instead of
/// constructing a `Dispatcher`. The real executor is never instantiated.
///
/// Steps (identical to `host::dispatcher_from_signed_grant`):
///   1. Decode + parse the JSON blob as `SignedGrant`
///   2. Verify Ed25519 signature, validity window, and machine binding via `SignedGrant::verify`
///   3. Burn the verified signature bytes in `spent` (single-use enforcement)
///
/// Returns `Ok(())` if and only if a production `dispatcher_from_signed_grant` would have
/// returned `Ok(Dispatcher)` — i.e., this is a sound proxy for "a real dispatcher would have
/// been installed".
pub(crate) fn verify_grant_inert(
    blob: &str,
    issuer: &PublicIdentity,
    now_ms: i64,
    expected_machine_id: uuid::Uuid,
    spent: &SpentGrants,
) -> Result<(), String> {
    let signed = SignedGrant::from_json(blob).map_err(|e| e.to_string())?;
    // Real verification — same code path as production.
    let _grant = signed
        .verify(issuer, now_ms, expected_machine_id)
        .map_err(|e| e.to_string())?;
    // Burn the VERIFIED signature bytes, not raw input. A grant that failed verify() above
    // never reaches this line, so a forged/tampered blob cannot pollute the spent ledger.
    let signature: [u8; 64] = hex::decode(&signed.sig)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid signature length".to_string())?;
    if !spent.claim_backstage(signature, signed.claims.expires_at_ms, now_ms) {
        return Err("grant has already been installed (grants are single use)".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inert promote sinks
// ---------------------------------------------------------------------------

/// Validate the promote bundle's ZIP structure without extracting any file to the filesystem.
///
/// Checks the same allowlist as `extract_setup_zip` (drives rejected, traversal rejected,
/// unknown names rejected, required names present) but writes nothing to disk.
/// Returns `Ok(())` if the bundle would pass real extraction, `Err` otherwise.
pub(crate) fn inert_extract_setup_zip(zip_bytes: &[u8]) -> Result<(), String> {
    use std::io::Cursor;
    let cursor = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| format!("secure-test: ZIP parse failed: {e}"))?;
    // Mirror the allowlist from extract_setup_zip.
    const ALLOWED: &[&str] = &["DeskRallySetup.exe", "DeskRallyAgent.msi", "enrollment.token"];
    let mut found = std::collections::HashSet::new();
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| format!("secure-test: ZIP entry {i} read failed: {e}"))?;
        let name = entry.name();
        // Reject traversal and drive-qualified paths.
        if name.contains("..") || name.contains(':') || name.starts_with('/') || name.starts_with('\\') {
            return Err(format!("secure-test: ZIP entry rejected (unsafe name): {name:?}"));
        }
        // Reject unknown entries.
        if !ALLOWED.contains(&name) {
            return Err(format!("secure-test: ZIP entry not on allowlist: {name:?}"));
        }
        found.insert(name.to_string());
    }
    // Require all three entries.
    for required in ALLOWED {
        if !found.contains(*required) {
            return Err(format!("secure-test: ZIP missing required entry: {required:?}"));
        }
    }
    tracing::info!(
        "secure-test-harness: inert_extract_setup_zip: bundle structure valid; \
         no files extracted (execution structurally denied)"
    );
    Ok(())
}

/// No-op setup launcher for secure-test mode. Logs intent and returns `Ok(())` without
/// calling `ShellExecuteExW` or spawning any process.
pub(crate) fn inert_launch_setup_exe() -> Result<(), String> {
    tracing::info!(
        "secure-test-harness: inert_launch_setup_exe: would have launched DeskRallySetup.exe; \
         call suppressed (execution structurally denied)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI precondition checks
// ---------------------------------------------------------------------------

/// Errors returned by `check_secure_test_preconditions`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreconditionError {
    MissingIssuer,
    NonLoopbackUrl(String),
    TempNotUserOwned(String),
}

impl std::fmt::Display for PreconditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreconditionError::MissingIssuer => f.write_str(
                "--secure-test-harness requires --grant-issuer; use a control-plane-issued \
                 Ed25519 public key. InsecureSelfIssued is not permitted in \
                 secure-test-harness mode.",
            ),
            PreconditionError::NonLoopbackUrl(url) => write!(
                f,
                "--secure-test-harness requires a loopback control-plane URL \
                 (http://127.0.0.1/… or http://[::1]/…); got {url:?} — \
                 non-loopback endpoints are forbidden in test-harness mode",
            ),
            PreconditionError::TempNotUserOwned(detail) => write!(
                f,
                "--secure-test-harness: %TEMP% is not owned by this process's user; \
                 harness requires a user-private temp directory for ZIP extraction safety: \
                 {detail}",
            ),
        }
    }
}

/// Validate CLI safety preconditions for `--secure-test-harness`:
///
/// P1. `grant_issuer_hex` must be `Some` (explicit error — no `InsecureSelfIssued` fallback).
/// P2. `control_plane_url` must be a loopback HTTP URL (127.x.x.x or ::1).
/// P3. `%TEMP%` must be owned by the current process's user (Windows only; skipped on
///     non-Windows since the crate compiles to nothing there).
///
/// `check_temp` should be `true` only when promote is enabled (`allow_promote: true`).
pub(crate) fn check_secure_test_preconditions(
    grant_issuer_hex: Option<&str>,
    control_plane_url: &str,
    check_temp: bool,
) -> Result<(), PreconditionError> {
    // P1: issuer required.
    if grant_issuer_hex.map(str::trim).filter(|s| !s.is_empty()).is_none() {
        return Err(PreconditionError::MissingIssuer);
    }
    // P2: loopback URL.
    // validate_control_plane_url returns Ok(true) iff HTTP+loopback, Ok(false) iff HTTPS.
    // --secure-test-harness requires loopback specifically.
    match crate::enroll::validate_control_plane_url(control_plane_url) {
        Ok(true) => {} // HTTP + loopback — required.
        Ok(false) => {
            return Err(PreconditionError::NonLoopbackUrl(control_plane_url.to_string()));
        }
        Err(_) => {
            return Err(PreconditionError::NonLoopbackUrl(control_plane_url.to_string()));
        }
    }
    // P3: temp directory ownership (Windows only, promote only).
    if check_temp {
        #[cfg(windows)]
        check_temp_owner_windows()?;
    }
    Ok(())
}

/// Windows-only: verify that `%TEMP%` is owned by the current process's user SID.
#[cfg(windows)]
fn check_temp_owner_windows() -> Result<(), PreconditionError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PCWSTR;

    // LocalFree is deprecated and absent from the windows 0.58 crate bindings; bind it directly.
    // SAFETY: LocalFree is a stable Win32 ABI exported from kernel32.dll since Windows 3.1.
    extern "system" {
        fn LocalFree(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    let temp = std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .map_err(|_| {
            PreconditionError::TempNotUserOwned("TEMP/TMP environment variable not set".into())
        })?;

    // Open the current process token (TOKEN_QUERY is sufficient for TokenUser).
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a non-owning pseudo-handle; OpenProcessToken returns an
    // owned handle that must be closed.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|e| {
        PreconditionError::TempNotUserOwned(format!("OpenProcessToken failed: {e}"))
    })?;

    // Query the process user SID.
    let mut buf = [0u8; 256];
    let mut ret_len = 0u32;
    // SAFETY: buf is large enough for TOKEN_USER + inline SID; ret_len is an out-param.
    let token_result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as _),
            buf.len() as u32,
            &mut ret_len,
        )
    };
    // SAFETY: token is a real HANDLE that OpenProcessToken opened for us.
    unsafe { let _ = CloseHandle(token); }
    token_result.map_err(|_| {
        PreconditionError::TempNotUserOwned("GetTokenInformation(TokenUser) failed".into())
    })?;

    // SAFETY: GetTokenInformation wrote a valid TOKEN_USER into buf.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let process_sid: PSID = token_user.User.Sid;

    // Query the owner SID of %TEMP%.
    let temp_wide: Vec<u16> = temp.encode_utf16().chain(std::iter::once(0)).collect();
    let mut owner_sid = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: GetNamedSecurityInfoW fills owner_sid and sd; sd must be freed with LocalFree.
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(temp_wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(std::ptr::addr_of_mut!(owner_sid)),
            None,
            None,
            None,
            std::ptr::addr_of_mut!(sd),
        )
    }.ok().map_err(|e| PreconditionError::TempNotUserOwned(format!(
        "GetNamedSecurityInfoW({temp:?}) failed: {e}"
    )))?;

    // SAFETY: both SIDs point into valid memory (process buf and OS-allocated sd).
    // In windows 0.58, EqualSid returns Ok(()) when equal, Err(_) when not.
    let equal = unsafe { EqualSid(owner_sid, process_sid) }.is_ok();
    // Free the security descriptor allocated by GetNamedSecurityInfoW.
    // SAFETY: sd.0 is the pointer returned by GetNamedSecurityInfoW; LocalFree owns it.
    unsafe { LocalFree(sd.0 as *mut _); }

    if !equal {
        return Err(PreconditionError::TempNotUserOwned(format!(
            "owner of {temp:?} does not match this process's user SID"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::host::SpentGrants;

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_millis() as i64
    }

    // Test-only grant minting. In production, grants are minted by the Go control plane.
    // Here we build the exact same canonical preimage in Rust so we can exercise verify().

    fn test_key_pair() -> (rmt_crypto::Identity, rmt_crypto::PublicIdentity) {
        let identity = rmt_crypto::Identity::generate();
        let pk = identity.public();
        (identity, pk)
    }

    fn mint_test_grant(
        identity: &rmt_crypto::Identity,
        machine_id: uuid::Uuid,
        session_id: uuid::Uuid,
        technician_id: uuid::Uuid,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> String {
        use rmt_agent::backstage::grant::GrantClaims;
        use rmt_agent::backstage::rbac::{Capability, Grant};
        let claims = GrantClaims {
            grant: Grant {
                technician_id,
                session_id,
                machine_id,
                capabilities: vec![Capability::ProcessList],
            },
            issued_at_ms,
            expires_at_ms,
        };
        let signed = claims.sign(identity);
        serde_json::to_string(&signed).expect("serialize")
    }

    fn fresh_spent() -> Arc<SpentGrants> {
        Arc::new(SpentGrants::default())
    }

    // -----------------------------------------------------------------------
    // verify_grant_inert
    // -----------------------------------------------------------------------

    #[test]
    fn valid_grant_verify_inert_ok() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        let blob = mint_test_grant(&sk, machine, session, tech, now - 1000, now + 60_000);
        let spent = fresh_spent();
        assert!(verify_grant_inert(&blob, &pk, now, machine, &spent).is_ok());
    }

    #[test]
    fn invalid_grant_bad_sig_rejected() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        let mut blob = mint_test_grant(&sk, machine, session, tech, now - 1000, now + 60_000);
        // Tamper with the sig field.
        blob = blob.replace("\"sig\":\"", "\"sig\":\"ff");
        let spent = fresh_spent();
        assert!(verify_grant_inert(&blob, &pk, now, machine, &spent).is_err());
    }

    #[test]
    fn expired_grant_rejected() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        // Expired 2 minutes ago.
        let blob = mint_test_grant(&sk, machine, session, tech, now - 180_000, now - 120_000);
        let spent = fresh_spent();
        let err = verify_grant_inert(&blob, &pk, now, machine, &spent).unwrap_err();
        assert!(err.contains("expired") || err.contains("validity") || err.contains("window"),
            "unexpected error: {err}");
    }

    #[test]
    fn future_grant_rejected() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        // Issued far in the future.
        let blob = mint_test_grant(&sk, machine, session, tech, now + 3_600_000, now + 7_200_000);
        let spent = fresh_spent();
        assert!(verify_grant_inert(&blob, &pk, now, machine, &spent).is_err());
    }

    #[test]
    fn wrong_machine_grant_rejected() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let other_machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        let blob = mint_test_grant(&sk, machine, session, tech, now - 1000, now + 60_000);
        let spent = fresh_spent();
        // Verify against a different machine_id.
        assert!(verify_grant_inert(&blob, &pk, now, other_machine, &spent).is_err());
    }

    #[test]
    fn double_spend_grant_rejected() {
        let (sk, pk) = test_key_pair();
        let machine = uuid::Uuid::new_v4();
        let session = uuid::Uuid::new_v4();
        let tech = uuid::Uuid::new_v4();
        let now = now_ms();
        let blob = mint_test_grant(&sk, machine, session, tech, now - 1000, now + 60_000);
        let spent = fresh_spent();
        // First install: ok.
        assert!(verify_grant_inert(&blob, &pk, now, machine, &spent).is_ok());
        // Second install: rejected.
        let err = verify_grant_inert(&blob, &pk, now, machine, &spent).unwrap_err();
        assert!(err.contains("already") || err.contains("single use"), "unexpected: {err}");
    }

    // -----------------------------------------------------------------------
    // inert_extract_setup_zip
    // -----------------------------------------------------------------------

    fn build_valid_bundle() -> Vec<u8> {
        use std::io::Write as _;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for name in &["DeskRallySetup.exe", "DeskRallyAgent.msi", "enrollment.token"] {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(b"placeholder").unwrap();
        }
        zw.finish().unwrap();
        buf
    }

    #[test]
    fn inert_extract_zip_no_fs_write() {
        let bundle = build_valid_bundle();
        let result = inert_extract_setup_zip(&bundle);
        assert!(result.is_ok(), "{result:?}");
        // No temp directory should have been created.
        // (We cannot assert the absence of FS side-effects globally, but the function contract
        // is documented: it writes nothing. The code has no FS write calls.)
    }

    #[test]
    fn inert_extract_zip_traversal_rejected() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file("../evil.exe", opts).unwrap();
        zw.write_all(b"bad").unwrap();
        zw.finish().unwrap();
        assert!(inert_extract_setup_zip(&buf).is_err());
    }

    #[test]
    fn inert_extract_zip_unknown_entry_rejected() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        // All three required plus an extra unknown file.
        for name in &["DeskRallySetup.exe", "DeskRallyAgent.msi", "enrollment.token", "extra.dll"] {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(b"x").unwrap();
        }
        zw.finish().unwrap();
        assert!(inert_extract_setup_zip(&buf).is_err());
    }

    #[test]
    fn inert_extract_zip_missing_required_entry_rejected() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        // Missing enrollment.token.
        for name in &["DeskRallySetup.exe", "DeskRallyAgent.msi"] {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(b"x").unwrap();
        }
        zw.finish().unwrap();
        assert!(inert_extract_setup_zip(&buf).is_err());
    }

    #[test]
    fn inert_launch_exe_returns_ok() {
        assert!(inert_launch_setup_exe().is_ok());
    }

    // -----------------------------------------------------------------------
    // check_secure_test_preconditions
    // -----------------------------------------------------------------------

    #[test]
    fn missing_issuer_precondition_error() {
        let err = check_secure_test_preconditions(None, "http://127.0.0.1:8081", false)
            .unwrap_err();
        assert_eq!(err, PreconditionError::MissingIssuer);
        assert!(err.to_string().contains("--grant-issuer"));
        assert!(!err.to_string().contains("InsecureSelfIssued") == false,
            "error must mention InsecureSelfIssued to guide the caller");
    }

    #[test]
    fn empty_issuer_precondition_error() {
        let err = check_secure_test_preconditions(Some(""), "http://127.0.0.1:8081", false)
            .unwrap_err();
        assert_eq!(err, PreconditionError::MissingIssuer);
    }

    #[test]
    fn nonloopback_url_precondition_error() {
        let err = check_secure_test_preconditions(
            Some("aabbcc"),
            "https://example.com",
            false,
        )
        .unwrap_err();
        assert!(matches!(err, PreconditionError::NonLoopbackUrl(_)));
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn loopback_ipv4_precondition_ok() {
        assert!(
            check_secure_test_preconditions(Some("aabbcc"), "http://127.0.0.1:8081", false)
                .is_ok()
        );
    }

    #[test]
    fn loopback_ipv6_precondition_ok() {
        assert!(
            check_secure_test_preconditions(Some("aabbcc"), "http://[::1]:8081", false).is_ok()
        );
    }

    #[test]
    fn localhost_url_precondition_ok() {
        assert!(
            check_secure_test_preconditions(Some("aabbcc"), "http://localhost:8081", false)
                .is_ok()
        );
    }
}
