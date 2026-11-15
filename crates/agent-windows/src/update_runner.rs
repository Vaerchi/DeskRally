//! The install and its recovery (design v10 launch + v10.1 C1, v7 L2').
//!
//! The runner is a verified copy of the agent image in protected staging, so no MSI-owned file is
//! in use while Windows Installer replaces them. It inherits exactly one handle, the exclusive
//! session lock. It persists `Installing` (with its own identity) and then calls
//! `MsiInstallProductW` IN-PROCESS: there is no installer child process to supervise.
//!
//! Measured (LAB-VM, designs/msi-api-probe): if the calling process dies, the install either
//! never reached the Windows Installer service or the service carries the transaction to its own
//! end. So completion is never inferred from the caller's fate or from idle sampling. It is proven
//! by causal, attempt-bound evidence: the call's return code (E-exit), or the package's own
//! commit/rollback custom-action marker (E-txn). With neither, the attempt is Unresolved until a
//! different boot (Codex v10.1).

#![cfg(windows)]

use std::io;
use std::os::windows::io::AsRawHandle;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{FILETIME, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::anchor::{Anchor, Dir};
use crate::update_files as files;
use crate::update_msi as msi;
use crate::update_state::{
    classify, Attempt, Evidence, GateEvidence, InstalledFamily, Outcome, Phase, RunnerIdentity,
    UpdateState,
};

/// How long the runner waits for Windows Installer to be idle after the call returns.
const IDLE_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

fn filetime_u64(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

/// `C:\Program Files\RMT Agent` from the known folder, never from the environment.
pub fn install_location() -> io::Result<std::path::PathBuf> {
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    let p = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None)? };
    let s = unsafe { p.to_string() }.map_err(|_| io::Error::other("program files path"));
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as *const std::ffi::c_void)) };
    Ok(std::path::PathBuf::from(s?).join("RMT Agent"))
}

/// PendingFileRenameOperations entries under install_location or the agent root (E-pfro).
pub fn pending_renames() -> io::Result<bool> {
    use windows::core::w;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_MULTI_SZ};
    let key = w!(r"SYSTEM\CurrentControlSet\Control\Session Manager");
    let name = w!("PendingFileRenameOperations");
    let mut size = 0u32;
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_MULTI_SZ, None, None, Some(&mut size))
    };
    if rc.0 == 2 {
        return Ok(false);
    }
    if rc.is_err() {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let mut buf = vec![0u16; size as usize / 2 + 1];
    let mut size2 = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            name,
            RRF_RT_REG_MULTI_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size2),
        )
    };
    if rc.is_err() {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let install = install_location()?.to_string_lossy().to_lowercase();
    Ok(pending_renames_match(&buf, &install))
}

pub(crate) fn pending_renames_match(multi_sz: &[u16], install_lower: &str) -> bool {
    let root = crate::anchor::ROOT.to_lowercase();
    multi_sz
        .split(|&c| c == 0)
        .map(|e| String::from_utf16_lossy(e).to_lowercase())
        .any(|e| {
            let e = e.trim_start_matches('!').trim_start_matches(r"\??\");
            let under = |base: &str| e.starts_with(base) && e[base.len()..].starts_with('\\');
            under(install_lower) || under(&root)
        })
}

// ─── Runner identity ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Absent,
    Present,
    /// An access or query failure: never read as absence.
    Unknown,
}

pub fn own_identity() -> io::Result<RunnerIdentity> {
    let (mut c, mut x, mut k, mut u) = Default::default();
    unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut x, &mut k, &mut u)? };
    Ok(RunnerIdentity {
        pid: unsafe { GetCurrentProcessId() },
        creation_time: filetime_u64(c),
    })
}

/// Is the runner process with this identity still alive? (pid + creation time; three-valued.)
pub fn runner_presence(id: &RunnerIdentity) -> Presence {
    let h = match unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, false, id.pid)
    } {
        Ok(h) => h,
        Err(e) if e.code().0 as u32 == 0x8007_0057 => return Presence::Absent,
        Err(_) => return Presence::Unknown,
    };
    let (mut c, mut x, mut k, mut u) = Default::default();
    let presence = if unsafe { GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) }.is_err() {
        Presence::Unknown
    } else if filetime_u64(c) != id.creation_time {
        Presence::Absent // the pid now belongs to another process
    } else if unsafe { WaitForSingleObject(h, 0) } == WAIT_OBJECT_0 {
        Presence::Absent // exited
    } else {
        Presence::Present
    };
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
    presence
}

// ─── Evidence + classification ────────────────────────────────────────────────

fn staging_dir(root: &Dir, id: &str) -> io::Result<Dir> {
    root.child_dir(files::STAGING, true)?.child_dir(id, false)
}

/// Assemble every piece of attempt-bound evidence and classify (rules 1-9).
pub fn classify_attempt(root: &Dir, attempt: &Attempt) -> io::Result<Outcome> {
    let id = &attempt.attempt_id;
    let family = msi::installed_family()?;
    let ack_matches = files::read_ack(root, id)?.is_some_and(|a| {
        &a.attempt_id == id && a.nonce == attempt.nonce && a.actual_version == attempt.target_version
    });
    let installed = installed_state(&family, attempt, ack_matches);
    let log = staging_dir(root, id)
        .and_then(|d| d.read("install.log", 32 * 1024 * 1024))
        .ok()
        .flatten()
        .map(|b| msi::log_facts(&b, id))
        .unwrap_or_default();
    let gate = files::read_gate(root, id)?
        .filter(|g| &g.attempt_id == id)
        .map(|g| GateEvidence {
            result: g.result,
            in_use: g.in_use || log.gate_in_use,
            teardown_complete: g.teardown_complete,
        })
        .or_else(|| {
            log.gate_in_use.then_some(GateEvidence {
                result: crate::update_state::GateResult::Mismatch,
                in_use: true,
                teardown_complete: false,
            })
        });
    let evidence = Evidence {
        installed,
        incomplete_rollback: log.incomplete_rollback,
        prelaunch_only: false,
        exit: files::read_exit(root, id)?,
        gate,
        ack_matches,
        candidate_fault: files::candidate_fault_for(root, id, &attempt.target_version, &attempt.boot_id),
        teardown_record: files::teardown_complete_for(root, id, &attempt.boot_id)?,
        pending_renames: pending_renames()?,
        verification_failure: log.verification_failure,
    };
    let outcome = classify(&evidence);
    tracing::info!(attempt = %id, ?evidence, ?outcome, "update: attempt classified");
    Ok(outcome)
}

/// The `MsiInstallProductW` command line for an attempt. A same-product attempt (docs/65 `reinstall`: the target IS the installed
/// product) must say so: Windows Installer treats a package whose ProductCode is already installed as maintenance mode, which
/// without `REINSTALL` does nothing. `REINSTALL=ALL REINSTALLMODE=vamus` repairs every feature from this package: missing or
/// older files are replaced, registry and shortcuts rewritten. An ordinary upgrade keeps its command line byte-for-byte.
pub(crate) fn install_props(attempt: &Attempt, anchor_prop: &str) -> String {
    let mut props = format!(
        "DESKRALLY_AUTOUPDATE=1 DESKRALLY_ATTEMPT={} DESKRALLY_NONCE={} DESKRALLY_EXPECTED={} DESKRALLY_ANCHOR={} REBOOT=ReallySuppress",
        attempt.attempt_id, attempt.nonce, attempt.target_version, anchor_prop
    );
    if attempt.previous_product_code.eq_ignore_ascii_case(&attempt.target_product_code) {
        props.push_str(" REINSTALL=ALL REINSTALLMODE=vamus");
    }
    props
}

/// Which side of the attempt the installed family is on. For an ordinary update the product code says it. A SAME-product attempt
/// (a reinstall) has one code for both sides, so the code cannot say: the HealthGate acknowledgement bound to THIS attempt's
/// nonce and version is what proves the new image is the one running (and its absence reads as "previous", so a failed or
/// rolled-back repair is never counted as Done).
pub(crate) fn installed_state(family: &[String], attempt: &Attempt, ack_matches: bool) -> InstalledFamily {
    match family {
        [one] if one.eq_ignore_ascii_case(&attempt.previous_product_code)
            && one.eq_ignore_ascii_case(&attempt.target_product_code) =>
        {
            if ack_matches { InstalledFamily::Target } else { InstalledFamily::Previous }
        }
        [one] if one.eq_ignore_ascii_case(&attempt.previous_product_code) => InstalledFamily::Previous,
        [one] if one.eq_ignore_ascii_case(&attempt.target_product_code) => InstalledFamily::Target,
        _ => InstalledFamily::Other,
    }
}

/// Classify and persist the result in ONE write, then archive the attempt's evidence (P1). The
/// caller has established the precondition (E-exit/E-txn on this boot, or a different boot); this
/// adds the idle requirement. Returns false if the installer is still busy.
pub fn finish(root: &Dir, state: &mut UpdateState, boot: &str) -> io::Result<bool> {
    let Some(attempt) = state.phase.attempt().cloned() else {
        return Ok(true);
    };
    let outcome = if matches!(state.phase, Phase::Prelaunch { .. }) {
        Outcome::NotStarted
    } else {
        if msi::installer_busy()? {
            return Ok(false);
        }
        classify_attempt(root, &attempt)?
    };
    state.apply_outcome(outcome, boot, files::now_ms());
    files::save_state(root, state)?;
    if let Err(e) = files::archive_attempt(root, &attempt.attempt_id) {
        tracing::warn!(error = %e, "update: evidence archive deferred");
    }
    Ok(true)
}

fn finish_within(root: &Dir, state: &mut UpdateState, boot: &str) -> io::Result<()> {
    let deadline = std::time::Instant::now() + IDLE_WAIT;
    while std::time::Instant::now() < deadline {
        if finish(root, state, boot)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    tracing::warn!("update: installer still busy; a later run will finish the attempt");
    Ok(())
}

/// Recovery for whatever phase the durable state is in (C1). The caller holds the exclusive
/// session lock and has applied `on_boot`. Evidence is read only through the root the attempt
/// was recorded with (v6 A1); a different root fails closed.
pub fn recover(anchor: &Anchor, state: &mut UpdateState) -> io::Result<()> {
    let root = anchor.dir();
    if let Some(attempt) = state.phase.attempt() {
        files::check_anchor(anchor, attempt)?;
    }
    let boot = files::boot_id()?;
    match state.phase.clone() {
        Phase::Prelaunch { .. } => {
            finish(root, state, &boot)?;
        }
        Phase::PostBootVerify { .. } => {
            if let Some(hb) = files::read_heartbeat(root)? {
                if state.on_heartbeat(&hb.registration_id, &hb.boot_id, &hb.version, files::now_ms())
                {
                    files::save_state(root, state)?;
                }
            }
        }
        Phase::Installing { attempt, .. } | Phase::Unresolved { attempt } if attempt.boot_id != boot => {
            // No request survives a reboot; Windows Installer's own reboot-time recovery holds
            // InProgress, which `finish` waits out.
            finish(root, state, &boot)?;
        }
        Phase::Unresolved { .. } => {
            tracing::error!("update: unresolved attempt; launches blocked until a reboot (surfaced)");
        }
        Phase::Installing { attempt, runner } => match runner_presence(&runner) {
            Presence::Present | Presence::Unknown => {
                tracing::warn!("update: runner alive or unknown; attempt stays Installing");
            }
            Presence::Absent => {
                let id = &attempt.attempt_id;
                if files::read_exit(root, id)?.is_some() || files::read_txn(root, id)?.is_some() {
                    finish(root, state, &boot)?;
                } else if state.mark_unresolved() {
                    files::save_state(root, state)?;
                    tracing::error!(
                        attempt = %id,
                        "update: runner died with no result and no transaction record; Unresolved \
                         until a reboot (surfaced)"
                    );
                }
            }
        },
        _ => {}
    }
    Ok(())
}

// ─── Install (runner) ─────────────────────────────────────────────────────────

/// The runner's work: verify the staged package again, persist Installing, install in-process,
/// persist the return code, then wait for idle and classify. The worker persisted Prelaunch.
pub fn run_attempt(anchor: &Anchor, state: &mut UpdateState) -> io::Result<()> {
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiEnableLogW, MsiInstallProductW, MsiSetInternalUI, INSTALLLOGMODE, INSTALLUILEVEL_NONE,
    };
    let root = anchor.dir();
    let Phase::Prelaunch { attempt } = state.phase.clone() else {
        return Err(io::Error::other("runner started without a Prelaunch attempt"));
    };
    let boot = files::boot_id()?;
    files::check_anchor(anchor, &attempt)?;
    if attempt.boot_id != boot {
        return finish(root, state, &boot).map(|_| ());
    }
    let staging = staging_dir(root, &attempt.attempt_id)?;
    // Hold the package shared-read-only for the whole install: nothing can swap it.
    let package = staging.open_file_read(crate::update_feed::PACKAGE_NAME, 0x1)?;
    let package_path = crate::anchor::final_path(package.as_raw_handle())?;
    let digest = {
        use sha2::Digest;
        use std::io::Read;
        let mut h = sha2::Sha256::new();
        let mut f = &package;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        hex::encode(h.finalize())
    };
    let identity = msi::package_identity(std::path::Path::new(&package_path))?;
    if digest != attempt.msi_sha256
        || identity.product_code != attempt.target_product_code
        || identity.product_version != attempt.target_product_version
        || identity.upgrade_code != msi::UPGRADE_CODE
        || crate::update_download::verify_authenticode(std::path::Path::new(&package_path)).is_err()
    {
        tracing::error!("update: staged package changed or failed verification before install");
        state.apply_outcome(Outcome::NotStarted, &boot, files::now_ms());
        return files::save_state(root, state);
    }
    // R4a again, immediately before the installer: a rename queued since the worker checked.
    if pending_renames()? {
        tracing::info!("update: pending file renames appeared; not installing");
        state.apply_outcome(Outcome::NotStarted, &boot, files::now_ms());
        return files::save_state(root, state);
    }
    // Property values are validated shapes (uuid, 32 hex, strict semver): no quoting needed and
    // nothing a value could inject into the command line.
    if !files::valid_attempt_id(&attempt.attempt_id)
        || !files::valid_nonce(&attempt.nonce)
        || crate::update_download::validate_version_segment(&attempt.target_version).is_err()
    {
        return Err(io::Error::other("attempt parameters malformed"));
    }
    files::write_request(
        root,
        &files::Request {
            attempt_id: attempt.attempt_id.clone(),
            nonce: attempt.nonce.clone(),
            expected_version: attempt.target_version.clone(),
        },
    )?;
    let log_path = format!("{}\\install.log", staging.final_path()?);

    // Installing is durable BEFORE the installer can see the request.
    state.phase = Phase::Installing {
        attempt: attempt.clone(),
        runner: own_identity()?,
    };
    files::save_state(root, state)?;

    let anchor_prop = attempt
        .anchor
        .as_ref()
        .map(files::anchor_property)
        .ok_or_else(|| io::Error::other("attempt has no recorded anchor identity"))?;
    let props = install_props(&attempt, &anchor_prop);
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    let (pkg_w, props_w, log_w) = (wide(&package_path), wide(&props), wide(&log_path));
    if files::test_hook(root, "runner-exit-before-install") {
        std::process::exit(91);
    }
    let rc = unsafe {
        MsiSetInternalUI(INSTALLUILEVEL_NONE, None);
        // Verbose, flushed per line so a crash still leaves the log behind.
        MsiEnableLogW(INSTALLLOGMODE(0x3FFF), PCWSTR(log_w.as_ptr()), 0x2);
        MsiInstallProductW(PCWSTR(pkg_w.as_ptr()), PCWSTR(props_w.as_ptr()))
    };
    tracing::info!(attempt = %attempt.attempt_id, rc, "update: installer returned");
    if files::test_hook(root, "runner-exit-after-install") {
        std::process::exit(92);
    }
    files::write_exit(root, &files::ExitRecord { attempt_id: attempt.attempt_id.clone(), code: rc })?;
    drop(package);
    finish_within(root, state, &boot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(prev: &str, target: &str) -> Attempt {
        Attempt {
            attempt_id: "att".into(),
            previous_product_code: prev.into(),
            previous_product_version: "1.3.18".into(),
            target_product_code: target.into(),
            target_product_version: "1.3.18".into(),
            target_version: "0.1.18".into(),
            msi_sha256: "a".repeat(64),
            nonce: "nn".into(),
            boot_id: "b".into(),
            previous_version: "0.1.18+x".into(),
            anchor: None,
            directive_id: None,
        }
    }

    #[test]
    fn only_a_same_product_attempt_asks_the_installer_to_reinstall() {
        let upgrade = install_props(&attempt("{A}", "{B}"), "anc");
        assert_eq!(
            upgrade,
            "DESKRALLY_AUTOUPDATE=1 DESKRALLY_ATTEMPT=att DESKRALLY_NONCE=nn DESKRALLY_EXPECTED=0.1.18 DESKRALLY_ANCHOR=anc REBOOT=ReallySuppress",
            "an ordinary upgrade command line must not change"
        );
        let repair = install_props(&attempt("{A}", "{a}"), "anc");
        assert!(repair.ends_with(" REINSTALL=ALL REINSTALLMODE=vamus"), "{repair}");
    }

    #[test]
    fn a_same_product_attempt_is_target_only_with_its_own_ack_and_never_by_the_code_alone() {
        let a = attempt("{A}", "{A}");
        let fam = vec!["{A}".to_string()];
        assert_eq!(installed_state(&fam, &a, true), InstalledFamily::Target);
        assert_eq!(installed_state(&fam, &a, false), InstalledFamily::Previous, "no ack: a failed or rolled-back repair is not Done");
        assert_eq!(installed_state(&["{Z}".to_string()], &a, true), InstalledFamily::Other);
        assert_eq!(installed_state(&[], &a, true), InstalledFamily::Other);
        // An ordinary update is unchanged: the code decides, the ack does not.
        let up = attempt("{A}", "{B}");
        assert_eq!(installed_state(&["{A}".to_string()], &up, true), InstalledFamily::Previous);
        assert_eq!(installed_state(&["{B}".to_string()], &up, false), InstalledFamily::Target);
    }

    #[test]
    fn pending_rename_entries_match_only_our_paths() {
        let enc = |entries: &[&str]| -> Vec<u16> {
            entries
                .iter()
                .flat_map(|e| e.encode_utf16().chain(Some(0)))
                .chain(Some(0))
                .collect()
        };
        let install = r"c:\program files\rmt agent";
        assert!(pending_renames_match(
            &enc(&[r"\??\C:\Program Files\RMT Agent\agent_host.exe", ""]),
            install
        ));
        assert!(pending_renames_match(&enc(&[r"\??\C:\rmt-agent\x.tmp", ""]), install));
        assert!(!pending_renames_match(
            &enc(&[r"\??\C:\Program Files\RMT Agent Other\x", r"\??\C:\rmt-agentx\y", r"\??\D:\z"]),
            install
        ));
    }

    #[test]
    fn install_location_is_program_files() {
        let p = install_location().unwrap();
        assert!(p.ends_with("RMT Agent"));
        assert!(p.is_absolute());
    }

    #[test]
    fn runner_presence_tells_identity_from_pid() {
        let me = own_identity().unwrap();
        assert_eq!(runner_presence(&me), Presence::Present);
        let reused = RunnerIdentity { creation_time: me.creation_time ^ 1, ..me.clone() };
        assert_eq!(runner_presence(&reused), Presence::Absent, "a reused pid is not presence");
        // A child that has exited is absent.
        let mut child = std::process::Command::new(crate::agent_root::system32_exe("cmd.exe"))
            .args(["/c", "exit", "0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).unwrap() };
        let (mut c, mut x, mut k, mut u) = Default::default();
        unsafe { GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u).unwrap() };
        child.wait().unwrap();
        let gone = RunnerIdentity { pid, creation_time: filetime_u64(c) };
        assert_eq!(runner_presence(&gone), Presence::Absent);
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(h);
        }
    }
}
