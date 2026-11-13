//! The scheduled SYSTEM worker (design v3 flow as amended through v10.1).
//!
//! `agent_host.exe auto-update-worker`, run hourly and at boot by the MSI-provisioned task:
//! 1. identity: LocalSystem, running from `<install_location>\agent_host.exe`;
//! 2. the anchor, the worker lock, the EXCLUSIVE session lock (no live session; none can start);
//! 3. recovery of any unresolved attempt BEFORE policy or network (disabling offers must never
//!    disable recovery);
//! 4. policy, pacing, preconditions (a recent authenticated registration on this boot, a console
//!    session), the signed format-2 offer;
//! 5. download into protected staging, digest, Authenticode, package identity;
//! 6. persist Prelaunch, copy this image to staging as the runner, hand the runner the exclusive
//!    lock as its only inherited handle, and exit. The runner (`auto-update-run`) installs.

#![cfg(windows)]

use std::ffi::c_void;
use std::io::{self, Read as _, Write as _};
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use serde::Deserialize;
use sha2::Digest;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    GetHandleInformation, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTUPINFOEXW,
};

use crate::anchor::{Anchor, Dir};
use crate::update_feed::{self as feed, FeedError};
use crate::update_files as files;
use crate::update_msi as msi;
use crate::update_runner as runner;
use crate::update_state::{Attempt, Phase, UpdateState};

const POLICY: &str = "auto-update.json";
const WORKER_LOCK: &str = "update-worker.lock";
pub const SESSION_LOCK: &str = "update-session.lock";
const RUNNER_NAME: &str = "runner.exe";
/// The offer is checked at most daily (design v3 step 2); backoff can only delay further.
const CHECK_INTERVAL_MS: u64 = 24 * 3_600_000;
/// The installed agent must have registered on this boot within this window (design v5 R3).
/// The heartbeat must be this recent. 1.3.1: the helper re-stamps it every 3 minutes, and only
/// while its signaling connection has answered within PONG_DEADLINE, so a heartbeat older than
/// this means no proven-live registration for at least two refresh periods. 8 minutes still covers
/// the boot-time run (5 minutes after a fresh registration).
const HEARTBEAT_FRESH_MS: u64 = 8 * 60_000;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
/// FILE_SHARE_READ: readers (WinVerifyTrust, msiexec, CreateProcess) yes; writers/renamers no.
const SHARE_READ: u32 = 0x1;

/// Authenticode failures that say nothing about the release itself: the file could not be read,
/// or revocation could not be checked right now. These back off and retry; only trust/signature
/// failures quarantine (design v2 D8).
fn authenticode_error_is_transient(error: &str) -> bool {
    const TRANSIENT: [&str; 3] = [
        "0x80092003", // CRYPT_E_FILE_ERROR
        "0x80092013", // CRYPT_E_REVOCATION_OFFLINE
        "0x800b010e", // CERT_E_REVOCATION_FAILURE
    ];
    let lower = error.to_ascii_lowercase();
    TRANSIENT.iter().any(|code| lower.contains(code))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    enabled: bool,
    ring: String,
}

/// The process token is LocalSystem.
pub fn is_local_system() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let ok = if needed == 0 || needed > 65_536 {
            false
        } else {
            let mut buf = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
            GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), needed, &mut needed)
                .is_ok()
                && IsWellKnownSid((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid, WinLocalSystemSid)
                    .as_bool()
        };
        let _ = CloseHandle(token);
        ok
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// The console has a session (design v5 R3: no headless attempts).
fn console_session_present() -> bool {
    unsafe { windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() != u32::MAX }
}

fn hash_file(f: &mut std::fs::File) -> io::Result<String> {
    use std::io::Seek;
    f.seek(io::SeekFrom::Start(0))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Entry point. Returns Ok for every "nothing to do / not now" path; Err only for faults worth
/// logging as failures.
pub fn run() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let install = runner::install_location().map_err(|e| e.to_string())?;
    if !same_path(&exe, &install.join("agent_host.exe")) {
        return Err("worker is not running from the installed location".into());
    }
    let anchor = Anchor::open().map_err(|e| format!("agent root: {e}"))?;
    let root = anchor.dir();
    let _worker_lock = match root.open_exclusive(WORKER_LOCK) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(32) => return Ok(()),
        Err(e) => return Err(format!("worker lock: {e}")),
    };
    let session_lock = match root.open_exclusive(SESSION_LOCK) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(32) => {
            tracing::info!("update: a session (or a running installer) holds the idle barrier");
            return Ok(());
        }
        Err(e) => return Err(format!("session lock: {e}")),
    };
    let mut state = files::load_state(root).map_err(|e| format!("state: {e}"))?;
    let boot = files::boot_id().map_err(|e| format!("boot id: {e}"))?;
    let now = files::now_ms();
    if state.on_boot(&boot, now) {
        files::save_state(root, &state).map_err(|e| e.to_string())?;
    }
    runner::recover(&anchor, &mut state).map_err(|e| format!("recovery: {e}"))?;
    sweep_staging(root, &state);
    if !matches!(state.phase, Phase::Idle) || state.anomaly.is_some() {
        return Ok(());
    }
    // docs/65 D-C5: operations are serialized with auto-update. An update attempt never starts under an unresolved directive
    // REMOVAL (recovery above still runs: disabling offers must never disable recovery). Unreadable records count as in flight.
    match crate::directive::AnchorStore::open(&anchor) {
        Ok(store) if crate::directive::removal_in_flight(&store) => {
            tracing::info!("update: a directive removal is in flight; not starting an update");
            return Ok(());
        }
        Ok(_) => {}
        Err(e) => return Err(format!("directive records: {e}")),
    }
    offer_and_launch(&anchor, &mut state, session_lock, &boot, now)
}

/// Remove staging folders that belong to no unresolved attempt.
fn sweep_staging(root: &Dir, state: &UpdateState) {
    let keep = state.phase.attempt().map(|a| a.attempt_id.clone());
    let Ok(staging) = root.child_dir(files::STAGING, true) else { return };
    for name in staging.list().unwrap_or_default() {
        if Some(&name) != keep.as_ref() {
            if let Err(e) = staging.remove_dir(&name) {
                tracing::debug!(error = %e, name, "update: staging sweep deferred");
            }
        }
    }
}

fn offer_and_launch(
    anchor: &Anchor,
    state: &mut UpdateState,
    session_lock: std::fs::File,
    boot: &str,
    now: u64,
) -> Result<(), String> {
    let root = anchor.dir();
    // docs/65: a signed `reinstall` directive asks for ONE ordinary attempt at the current signed ring release, same version
    // allowed. It bypasses only the opt-in (`enabled`) and the daily pacing; every safety check below still applies, and a refusal
    // is written back to the marker so the directive reports it instead of hanging.
    // E2: a Requested marker whose directive ALREADY has an attempt (in flight or finished) in the update state is reconciled, never
    // offered a second attempt. The association lives in the update state (written with Prelaunch); the marker is only a pointer.
    if let Some(m) = crate::directive_reinstall::read(root).map_err(|e| format!("directive marker: {e}"))? {
        if let Some(reconciled) = crate::directive_reinstall::reconcile(&m, state) {
            crate::directive_reinstall::write(root, &reconciled).map_err(|e| format!("directive marker: {e}"))?;
            return Ok(());
        }
    }
    let marker = crate::directive_reinstall::read(root).ok().flatten().filter(|m| m.is_actionable(now as i64));
    let refuse = |why: &str| -> Result<(), String> {
        if let Some(m) = &marker {
            let _ = crate::directive_reinstall::write(root, &m.refused(why));
        }
        Ok(())
    };
    // Recovery and directive reconciliation above still run without an update identity.
    if !feed::configured() {
        return refuse("auto-update is not configured in this build");
    }
    let policy = root.read(POLICY, 4096).map_err(|e| format!("policy: {e}"))?;
    let Some(policy) = policy else {
        return refuse("auto-update is not provisioned on this machine (no policy, so no ring to repair from)");
    };
    let policy: Policy = serde_json::from_slice(&policy).map_err(|e| format!("policy: {e}"))?;
    if !policy.enabled && marker.is_none() {
        return Ok(());
    }
    if marker.is_none() {
        if let Some(due_in_ms) = paced_for(state.last_check_ms, now) {
            // Said out loud: a silent paced return looked like a stuck worker on the operator's Desktop (11-06,
            // canary 1.3.21 published 2 h after the last check, so nothing happened for ~22 h).
            tracing::info!(
                last_check_ms = state.last_check_ms,
                next_check_in_min = due_in_ms / 60_000,
                "update: checked within the last 24 h; next feed check is due later"
            );
            return Ok(());
        }
    }
    // Preconditions: this boot's agent recently completed an authenticated registration.
    let Some(hb) = files::read_heartbeat(root).map_err(|e| e.to_string())? else {
        tracing::info!("update: no registration heartbeat yet");
        return Ok(());
    };
    if hb.boot_id != boot || now.saturating_sub(hb.at_ms) > HEARTBEAT_FRESH_MS || !console_session_present() {
        tracing::info!("update: preconditions not met (fresh registration on this boot, console session)");
        return Ok(());
    }
    // R4a: never start while a replacement/deletion of our files is queued for the next boot.
    match runner::pending_renames() {
        Ok(false) => {}
        Ok(true) => {
            tracing::info!("update: pending file renames under the agent paths; waiting for a reboot");
            return Ok(());
        }
        Err(e) => return Err(format!("pending renames unreadable: {e}")),
    }
    let family = msi::installed_family().map_err(|e| e.to_string())?;
    let [previous] = family.as_slice() else {
        tracing::warn!(count = family.len(), "update: installed family is not exactly one product");
        return Ok(());
    };
    let previous_version = msi::installed_version(previous).map_err(|e| e.to_string())?;
    let cfg = crate::config::HelperConfig::load().ok_or("installed configuration unavailable")?;

    state.last_check_ms = now;
    files::save_state(root, state).map_err(|e| e.to_string())?;
    let release = match feed::fetch_offer(
        cfg.update_signer_pubkey.as_deref(),
        cfg.grant_issuer_pubkey.as_deref(),
        &policy.ring,
        &msi::effective_installed_version(&hb.version, &previous_version),
        &previous_version,
        now as i64,
        marker.is_some(),
    ) {
        Ok(Some(r)) => r,
        Ok(None) => return refuse(&format!("no signed release is available for ring {} that can be installed here", policy.ring)),
        Err(e) => return Err(e.to_string()),
    };
    if state.accept_offer(&release.msi_sha256) {
        files::save_state(root, state).map_err(|e| e.to_string())?;
    }
    if let Err(why) = state.may_start(&release.msi_sha256, now) {
        tracing::info!(why, version = %release.version, "update: offer not attempted");
        return refuse(&format!("the update chain will not start an attempt: {why}"));
    }

    // Download into a fresh protected staging folder named by the attempt id.
    let attempt_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let staging = root
        .child_dir(files::STAGING, true)
        .and_then(|s| s.child_dir(&attempt_id, true))
        .map_err(|e| format!("staging: {e}"))?;
    {
        let mut download = staging.create_file(feed::PACKAGE_NAME).map_err(|e| e.to_string())?;
        if let Err(e) = feed::download(&release, &mut download) {
            return Err(e.to_string()); // Transient: retried after the daily interval
        }
    }
    // Verify through a READ-ONLY handle that forbids writers: holding the download's write handle
    // made WinVerifyTrust fail to open the file (CRYPT_E_FILE_ERROR, acceptance VM 2026-10-15).
    // Re-hash what is actually on disk now, so the bytes verified are the bytes downloaded.
    let mut package = staging
        .open_file_read(feed::PACKAGE_NAME, SHARE_READ)
        .map_err(|e| e.to_string())?;
    if hash_file(&mut package).map_err(|e| e.to_string())? != release.msi_sha256 {
        return Err("staged package changed after download".into());
    }
    let package_path = crate::anchor::final_path(package.as_raw_handle()).map_err(|e| e.to_string())?;
    let verified = crate::update_download::verify_authenticode(Path::new(&package_path)).and_then(|()| {
        let id = msi::package_identity(Path::new(&package_path)).map_err(|e| e.to_string())?;
        if id.product_code != release.product_code
            || id.product_version != release.product_version
            || id.upgrade_code != msi::UPGRADE_CODE
        {
            return Err("package identity differs from the signed manifest".into());
        }
        Ok(())
    });
    if let Err(e) = verified {
        if authenticode_error_is_transient(&e) {
            return Err(FeedError::Transient(e).to_string());
        }
        // Correctly hashed, signed-manifest bytes that are not what they claim: broken release.
        state.quarantine_release(&release.msi_sha256);
        files::save_state(root, state).map_err(|e| e.to_string())?;
        return Err(FeedError::Verification(e).to_string());
    }

    // Relocate: a verified copy of this image runs the install, so no MSI-owned file is in use.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut source = std::fs::File::open(&exe).map_err(|e| e.to_string())?;
    {
        let mut copy = staging.create_file(RUNNER_NAME).map_err(|e| e.to_string())?;
        io::copy(&mut source, &mut copy).map_err(|e| e.to_string())?;
        copy.flush().and_then(|_| copy.sync_all()).map_err(|e| e.to_string())?;
    }
    let mut runner_file = staging.open_file_read(RUNNER_NAME, SHARE_READ).map_err(|e| e.to_string())?;
    let runner_path = crate::anchor::final_path(runner_file.as_raw_handle()).map_err(|e| e.to_string())?;
    if hash_file(&mut source).map_err(|e| e.to_string())? != hash_file(&mut runner_file).map_err(|e| e.to_string())?
        || crate::update_download::verify_authenticode(Path::new(&runner_path)).is_err()
    {
        return Err("runner copy failed verification".into());
    }

    let attempt = Attempt {
        attempt_id: attempt_id.clone(),
        previous_product_code: previous.clone(),
        previous_product_version: previous_version,
        target_product_code: release.product_code.clone(),
        target_product_version: release.product_version.clone(),
        target_version: release.version.clone(),
        msi_sha256: release.msi_sha256.clone(),
        nonce: files::new_nonce(),
        boot_id: boot.to_owned(),
        previous_version: hb.version.clone(),
        anchor: Some(anchor.identity()),
        directive_id: marker.as_ref().map(|m| m.directive_id.clone()),
    };
    // E5: check-and-reserve under the lock the directive engine also takes around ITS check-and-reserve. Whoever holds it is the
    // only one deciding; the loser sees the winner's durable reservation (Prelaunch here, `executing` there) and stands down.
    {
        let Some(_exclusion) = crate::directive_win::try_exclusion(root).map_err(|e| format!("exclusion lock: {e}"))? else {
            tracing::info!("update: a directive is deciding right now; not starting an update");
            return Ok(());
        };
        match crate::directive::AnchorStore::open(anchor) {
            Ok(store) if crate::directive::removal_in_flight(&store) => {
                tracing::info!("update: a directive removal reserved the machine; not starting an update");
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => return Err(format!("directive records: {e}")),
        }
        state.phase = Phase::Prelaunch { attempt };
        files::save_state(root, state).map_err(|e| e.to_string())?;
    }
    if let Some(m) = &marker {
        // A pointer only (the directive id is already in the Prelaunch state, atomically). A failure is NOT ignored: the attempt
        // is resolved as not started and the error reaches the log and the directive.
        if let Err(e) = crate::directive_reinstall::write(root, &m.launched(&attempt_id)) {
            let _ = runner::finish(root, state, boot);
            return Err(format!("directive marker: {e}"));
        }
    }
    drop(package);
    drop(runner_file);

    if let Err(e) = start_runner(&runner_path, &attempt_id, &session_lock) {
        tracing::error!(error = %e, "update: runner did not start");
        runner::finish(root, state, boot).map_err(|e| e.to_string())?;
        return Err(format!("runner start: {e}"));
    }
    tracing::info!(attempt = %attempt_id, version = %release.version, "update: runner started");
    Ok(())
}

/// Start the runner with the exclusive session lock as its ONLY inherited handle, so the idle
/// barrier is held continuously across the handoff (design v4).
fn start_runner(runner_path: &str, attempt_id: &str, lock: &std::fs::File) -> io::Result<()> {
    let lock_raw = lock.as_raw_handle();
    let h = HANDLE(lock_raw);
    unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)? };
    let result = (|| {
        let mut size = 0usize;
        let _ = unsafe {
            InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()), 1, 0, &mut size)
        };
        let mut attr_buf = vec![0u8; size];
        let attrs = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(attrs, 1, 0, &mut size)? };
        let handles = [lock_raw];
        let r = (|| -> io::Result<()> {
            unsafe {
                UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    Some(handles.as_ptr() as *const c_void),
                    std::mem::size_of_val(&handles),
                    None,
                    None,
                )?;
            }
            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attrs;
            let mut cmd: Vec<u16> = format!(
                "\"{runner_path}\" auto-update-run {attempt_id} {}",
                lock_raw as usize
            )
            .encode_utf16()
            .chain(Some(0))
            .collect();
            let app: Vec<u16> = runner_path.encode_utf16().chain(Some(0)).collect();
            let cwd: Vec<u16> = crate::agent_root::system32_exe("")
                .to_string_lossy()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut pi = PROCESS_INFORMATION::default();
            unsafe {
                CreateProcessW(
                    PCWSTR(app.as_ptr()),
                    PWSTR(cmd.as_mut_ptr()),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    None,
                    PCWSTR(cwd.as_ptr()),
                    &si.StartupInfo,
                    &mut pi,
                )?;
                let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
                let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
            }
            Ok(())
        })();
        unsafe { DeleteProcThreadAttributeList(attrs) };
        r
    })();
    unsafe {
        let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
    }
    result
}

/// The daily pacing: `Some(ms until the next check is due)` while the last check is less than
/// `CHECK_INTERVAL_MS` ago, `None` when a check is due. A last check in the FUTURE (the clock went
/// back) is never pacing: it must not suppress checks until the clock catches up.
fn paced_for(last_check_ms: u64, now: u64) -> Option<u64> {
    if last_check_ms > now {
        return None;
    }
    let since = now - last_check_ms;
    (since < CHECK_INTERVAL_MS).then(|| CHECK_INTERVAL_MS - since)
}

#[cfg(test)]
mod tests {
    use super::authenticode_error_is_transient as transient;
    use super::{paced_for, CHECK_INTERVAL_MS};

    #[test]
    fn pacing_reports_the_time_until_the_next_check() {
        let last = 1_000_000_000;
        assert_eq!(paced_for(last, last), Some(CHECK_INTERVAL_MS));
        assert_eq!(paced_for(last, last + 3_600_000), Some(CHECK_INTERVAL_MS - 3_600_000));
        assert_eq!(paced_for(last, last + CHECK_INTERVAL_MS - 1), Some(1));
        assert_eq!(paced_for(last, last + CHECK_INTERVAL_MS), None, "due exactly at 24 h");
        assert_eq!(paced_for(last, last + 2 * CHECK_INTERVAL_MS), None);
        assert_eq!(paced_for(0, last), None, "never checked");
        assert_eq!(paced_for(last + 5, last), None, "a last check in the future never paces");
    }

    #[test]
    fn only_io_and_revocation_availability_errors_are_transient() {
        assert!(transient("untrusted Authenticode signature: 0x80092003"));
        assert!(transient("untrusted Authenticode signature: 0x80092013"));
        assert!(transient("untrusted Authenticode signature: 0x800B010E"));
        assert!(!transient("untrusted Authenticode signature: 0x800b0100"), "no signature");
        assert!(!transient("untrusted Authenticode signature: 0x80096010"), "bad digest");
        assert!(!transient("unexpected publisher subject"));
        assert!(!transient("package identity differs from the signed manifest"));
    }
}

/// `auto-update-run <attempt_id> <lock handle>`: the relocated runner.
pub fn run_runner(args: &[String]) -> Result<(), String> {
    use windows::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32).map_err(|e| e.to_string())? };
    let [_, _, id, raw] = args else {
        return Err("usage".into());
    };
    if !files::valid_attempt_id(id) {
        return Err("invalid attempt id".into());
    }
    let anchor = Anchor::open().map_err(|e| format!("agent root: {e}"))?;
    let root = anchor.dir();
    // The image must be the staged copy for THIS attempt.
    let staging = root
        .child_dir(files::STAGING, false)
        .and_then(|s| s.child_dir(id, false))
        .map_err(|e| format!("staging: {e}"))?;
    let expected = format!("{}\\{RUNNER_NAME}", staging.final_path().map_err(|e| e.to_string())?);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if !same_path(&exe, Path::new(&expected)) {
        return Err("runner is not the staged copy for this attempt".into());
    }
    // The inherited handle must BE the session lock (identity, not a path claim), then stop
    // being inheritable.
    let raw: usize = raw.parse().map_err(|_| "invalid handle")?;
    let lock = HANDLE(raw as *mut c_void);
    let mut flags = 0u32;
    unsafe { GetHandleInformation(lock, &mut flags).map_err(|e| e.to_string())? };
    let id_of = crate::anchor::file_identity(lock.0).map_err(|e| e.to_string())?;
    let expected_id = root.child_file_id(SESSION_LOCK).map_err(|e| e.to_string())?;
    let path = crate::anchor::final_path(lock.0).map_err(|e| e.to_string())?;
    if id_of.volume != anchor.identity().volume
        || u64::from_le_bytes(id_of.id[..8].try_into().unwrap()) != expected_id
        || !path.eq_ignore_ascii_case(&format!("{}\\{SESSION_LOCK}", crate::anchor::ROOT))
    {
        return Err("inherited handle is not the session lock".into());
    }
    unsafe {
        SetHandleInformation(lock, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).map_err(|e| e.to_string())?;
    }
    let mut state = files::load_state(root).map_err(|e| e.to_string())?;
    match &state.phase {
        Phase::Prelaunch { attempt } if attempt.attempt_id == *id => {}
        _ => return Err("no Prelaunch record for this attempt".into()),
    }
    runner::run_attempt(&anchor, &mut state).map_err(|e| e.to_string())
}
