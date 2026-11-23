//! `support_main`: the entry point of the public support client `DeskRallySupport.exe`
//! (docs/27 step 11, docs/28).
//!
//! The fixed order of `support_main` is itself the design: stdio sinks first (so no `println!` can
//! panic a GUI-subsystem process), then DPI awareness BEFORE any window, then refuse an elevated
//! run, then single-instance, then a per-run working root with a hardened sweep of its siblings,
//! then the log and panic hook pinned to that root, then the baked origin is validated, then the
//! code prompt drives redeem→consent→stream. Nothing is written under `C:\rmt-agent`; nothing is
//! installed; the disk footprint is one per-run directory the closing receipt names.
//!
//! The pure decisions here — argv classification, the sweep-name predicate, the single-instance and
//! elevation choices — are unit-tested; the Win32 wiring is exercised on the VM (docs/27 step 11).

use std::path::{Path, PathBuf};

/// How the process was invoked.
#[derive(Debug, PartialEq, Eq)]
pub enum SupportArg {
    /// No arguments: run the interactive support flow.
    RunFlow,
    /// `--deployment`: print the baked control-plane origin and exit 0 (for the publish guard).
    PrintDeployment,
    /// `elevated-input --pipe <name> --parent <pid>`, exactly: the elevated input helper an attended
    /// session launches through UAC as this same program (docs/53). It serves only a pipe whose
    /// server is that parent, alive and running this same image, so it is no new door.
    ElevatedInput,
    /// Anything else: exit 2. A public binary has no other command surface — an empty argv surface
    /// is part of the design (docs/27 "Security and honesty first").
    Unknown,
}

/// Classify the argv TAIL (everything after the exe name).
pub fn classify_argv(tail: &[String]) -> SupportArg {
    match tail {
        [] => SupportArg::RunFlow,
        [one] if one == "--deployment" => SupportArg::PrintDeployment,
        [cmd, p, _, q, _] if cmd == "elevated-input" && p == "--pipe" && q == "--parent" => SupportArg::ElevatedInput,
        _ => SupportArg::Unknown,
    }
}

/// Whether a directory name is one of OUR per-run roots: `session-` followed by exactly 32 hex
/// characters, and nothing else.
///
/// The sweep uses this so it can only ever delete a directory shaped like one it created — never a
/// `session-decoy`, a truncated name, or a name with a trailing dot (which Windows would otherwise
/// treat as the un-dotted name). This is the belt to the reparse-point handling in [`sweep_run_root`].
pub fn is_run_dir_name(name: &str) -> bool {
    match name.strip_prefix("session-") {
        Some(hex) => hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

/// A fresh per-run directory name: `session-<32 hex>` from a v4 UUID (random, collision-resistant
/// for a temp-dir name). Always satisfies [`is_run_dir_name`].
pub fn run_dir_name() -> String {
    format!("session-{}", uuid::Uuid::new_v4().simple())
}

/// The parent directory the per-run roots live under: `%TEMP%\DeskRally`. Under the user's own temp,
/// never `C:\rmt-agent` (which belongs to the installed SYSTEM service) and never bare `C:\` (which
/// lets any authenticated user create siblings).
pub fn run_root_parent() -> PathBuf {
    std::env::temp_dir().join("DeskRally")
}

/// The file name of the diagnostic written by the failure paths that run BEFORE the per-run
/// `support.log` can exist.
const STARTUP_LOG_NAME: &str = "support-startup.log";

/// Where a failure that happens before the per-run root exists records itself:
/// `%TEMP%\DeskRally\support-startup.log`.
///
/// [`support_main`] can refuse an elevated run (step 3) or fail to create the run root (step 5)
/// before there is any run root to pin a log to, and BOTH of those then show a **blocking** modal.
/// Step 1 has already bound stderr to `NUL` on a GUI-subsystem launch, so without this file those
/// two failures leave a process that is alive forever with **no written evidence anywhere** —
/// measured on real Windows 2026-09-07, and indistinguishable from the "hang" recorded in
/// docs/28 section 8.3.
///
/// It sits in the run-root PARENT, which is also the directory [`sweep_run_root`] walks — and what
/// keeps it safe there is NOT its name. The sweep only ever removes directories (and reparse points
/// it unlinks without following), so a plain file survives whatever it is called; mutation testing
/// on 2026-09-07 refuted the tidier-sounding claim that [`is_run_dir_name`] is what protects it.
/// `the_sweep_removes_only_directories_so_a_diagnostic_file_survives` pins the real mechanism and
/// `the_startup_log_sits_beside_the_run_roots_not_inside_one` pins the location and the name.
///
/// Pinning the log here is a one-way door (the path cell is first-caller-wins), which is why only
/// paths that are about to RETURN may do it.
pub fn startup_log_path() -> PathBuf {
    run_root_parent().join(STARTUP_LOG_NAME)
}

/// Create this run's working root under [`run_root_parent`], sweeping stale siblings first. Returns
/// the created directory, or an error to surface as [`rmt_agent_core::support_ui::Failure::WorkspaceSetupFailed`].
pub fn make_run_root() -> Result<PathBuf, String> {
    let parent = run_root_parent();
    std::fs::create_dir_all(&parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    // The kept-logs directory is created the same way as the parent. A failure here never stops the
    // client: the sweep then simply keeps no logs.
    let _ = std::fs::create_dir_all(logs_dir(&parent));
    keep_startup_log(&parent, std::time::SystemTime::now());
    sweep_run_root(&parent);
    let root = parent.join(run_dir_name());
    std::fs::create_dir(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    Ok(root)
}

/// The most entries the sweep will look at, so a parent stuffed with junk cannot make startup hang.
const SWEEP_MAX_ENTRIES: usize = 256;

/// Remove stale `session-<32 hex>` siblings, safely.
///
/// Two guards, both load-bearing (this repo has an LPE primitive on record from a delete that
/// followed an attacker-planted junction — see the memory index):
///
/// * **Name predicate.** Only entries matching [`is_run_dir_name`] are touched; a decoy directory is
///   ignored.
/// * **Never recurse through a reparse point.** A matching-named entry that is a REPARSE POINT (a
///   junction/symlink someone planted to point at, say, the user's profile) is removed with
///   `remove_dir` (which unlinks the reparse point itself, following nothing), NOT `remove_dir_all`
///   (which would recurse into and delete the target). Only a real directory is recursed into.
///
/// Best-effort and bounded: failures are logged and skipped, and at most [`SWEEP_MAX_ENTRIES`] are
/// considered.
pub fn sweep_run_root(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    let logs = logs_dir(parent);
    for entry in entries.take(SWEEP_MAX_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_run_dir_name(name) {
            continue;
        }
        let path = entry.path();
        // symlink_metadata does NOT follow the link, so a junction reports its own attributes.
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if is_reparse_point(&meta) {
            // Unlink the reparse point without following it. remove_dir on a junction removes the
            // junction, not its target.
            if let Err(e) = std::fs::remove_dir(&path) {
                tracing::warn!(path = %path.display(), error = %e, "support: could not unlink a planted reparse point");
            }
            continue;
        }
        if meta.is_dir() {
            // Keep the run's log before the directory (and the log with it) is deleted. A failure
            // is logged inside and never stops the sweep.
            let stamp = meta.created().or_else(|_| meta.modified()).unwrap_or(std::time::UNIX_EPOCH);
            preserve_run_log(&path, &logs, stamp);
            if let Err(e) = std::fs::remove_dir_all(&path) {
                tracing::warn!(path = %path.display(), error = %e, "support: could not remove a stale run dir");
            }
        }
    }
    prune_logs(&logs, SUPPORT_LOG_PREFIX);
}

/// How many kept logs of each kind survive in [`logs_dir`].
const KEEP_LOGS: usize = 5;
/// The most bytes of one kept log. A larger log keeps its TAIL: the end of a run is what matters.
const KEEP_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Kept per-run logs are named `support-<UTC stamp>-<id>.log`; kept startup logs `startup-<UTC stamp>.log`.
const SUPPORT_LOG_PREFIX: &str = "support-";
const STARTUP_LOG_PREFIX: &str = "startup-";

/// Where logs of earlier runs are kept: `%TEMP%\DeskRally\logs`. Not a `session-<32 hex>` name, so
/// the sweep never treats it as a target.
pub fn logs_dir(parent: &Path) -> PathBuf {
    parent.join("logs")
}

/// `YYYYMMDDTHHMMSSZ` in UTC: fixed width, so a name sort is a time sort.
pub fn utc_stamp(t: std::time::SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// True when `dir` is an existing plain directory (not a reparse point): the only kind of
/// destination a kept log is ever written into.
///
/// This is a path check followed by a later write, so a swap in between (the directory replaced by
/// a junction after the check) is not excluded. That race is deliberately NOT closed, and the reason
/// is the threat model, not an oversight. The support client refuses to run elevated
/// (`support_main` step 3), so it runs as the customer's own user, and `%TEMP%\DeskRally\logs` and
/// the run dirs are inside that user's own profile. Anyone who can swap them for a junction is that
/// same user (or already an administrator), and can write to or delete the junction's target
/// directly without any help from this code. The race therefore gains them no privilege and crosses
/// no boundary. What the check is for is the NON-racing case: a stale or planted reparse point left
/// from an earlier run is never written through. A cheap hardening that stays inside this file, if
/// it is ever wanted: open the `logs` directory once with `FILE_FLAG_BACKUP_SEMANTICS |
/// FILE_FLAG_OPEN_REPARSE_POINT`, verify it on that handle, and hold the handle for the whole
/// sweep so the directory cannot be replaced while the sweep runs. A handle-relative filesystem
/// layer (NtCreateFile with a RootDirectory) is out of proportion here and is not built.
fn is_plain_dir(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && !is_reparse_point(&m))
}

/// Copy at most the last [`KEEP_LOG_MAX_BYTES`] of the REGULAR file `src` to a NEW file `dest`.
/// The source is opened without following a link and checked on the handle; the destination is
/// `create_new`, so an existing name (or a planted link at it) is never written through.
fn copy_log_tail(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let mut file = open_regular_no_follow(src)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a plain regular file"))?;
    // A hard link is a regular file with a second name: a `support.log` hard-linked to some other
    // file of the user's would otherwise be copied out into the kept logs. This run's own log has
    // exactly one link. Checked on the open handle, like the reparse check, so there is no window.
    if file_link_count(&file) != Some(1) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the log has more than one hard link (or its link count is unknown)",
        ));
    }
    let len = file.metadata()?.len();
    if len > KEEP_LOG_MAX_BYTES {
        file.seek(SeekFrom::Start(len - KEEP_LOG_MAX_BYTES))?;
    }
    let mut buf = Vec::new();
    file.take(KEEP_LOG_MAX_BYTES).read_to_end(&mut buf)?;
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(dest)?;
    out.write_all(&buf)?;
    out.flush()
}

/// The number of hard links to the file behind `file`, read from the open handle. `None` when it
/// cannot be read (which callers treat as a refusal).
fn file_link_count(file: &std::fs::File) -> Option<u32> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is valid for the life of `file`; `info` is a stack struct the call fills in.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .ok()
        .map(|()| info.nNumberOfLinks)
}

/// Keep the stale run dir's `support.log` as `<logs>/support-<stamp>-<short id>.log`, before the
/// sweep deletes the directory. Only a REGULAR file named exactly `support.log`, never through a
/// reparse point; a missing log is normal; any failure is logged and swallowed.
pub fn preserve_run_log(run_dir: &Path, logs: &Path, stamp: std::time::SystemTime) {
    if !is_plain_dir(logs) {
        return;
    }
    let src = run_dir.join("support.log");
    if std::fs::symlink_metadata(&src).is_err() {
        return; // nothing was ever logged
    }
    let id: String = run_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("session-"))
        .map_or_else(String::new, |h| h.chars().take(8).collect());
    let dest = logs.join(format!("{SUPPORT_LOG_PREFIX}{}-{id}.log", utc_stamp(stamp)));
    if let Err(e) = copy_log_tail(&src, &dest) {
        tracing::warn!(path = %src.display(), error = %e, "support: could not keep a stale run's log");
    }
}

/// Keep a leftover `support-startup.log` (written by an earlier failed start) as
/// `<logs>/startup-<stamp>.log` instead of letting a later failure append to it, then remove it.
fn keep_startup_log(parent: &Path, now: std::time::SystemTime) {
    let logs = logs_dir(parent);
    let src = parent.join(STARTUP_LOG_NAME);
    let Ok(meta) = std::fs::symlink_metadata(&src) else { return };
    if !meta.is_file() || is_reparse_point(&meta) || !is_plain_dir(&logs) {
        return;
    }
    let stamp = meta.modified().unwrap_or(now);
    let dest = logs.join(format!("{STARTUP_LOG_PREFIX}{}.log", utc_stamp(stamp)));
    if copy_log_tail(&src, &dest).is_ok() {
        let _ = std::fs::remove_file(&src);
    }
    prune_logs(&logs, STARTUP_LOG_PREFIX);
}

/// Delete all but the newest [`KEEP_LOGS`] plain `<prefix>*.log` files in `logs`. Names carry a
/// fixed-width UTC stamp, so the lexicographic order is the age order. Never touches anything that
/// is not a regular file of that shape.
fn prune_logs(logs: &Path, prefix: &str) {
    if !is_plain_dir(logs) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(logs) else { return };
    let mut names: Vec<String> = entries
        .take(SWEEP_MAX_ENTRIES * 4)
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let meta = std::fs::symlink_metadata(e.path()).ok()?;
            (name.starts_with(prefix) && name.ends_with(".log") && meta.is_file() && !is_reparse_point(&meta)).then_some(name)
        })
        .collect();
    names.sort_unstable_by(|a, b| b.cmp(a));
    for old in names.into_iter().skip(KEEP_LOGS) {
        if let Err(e) = std::fs::remove_file(logs.join(&old)) {
            tracing::warn!(file = %old, error = %e, "support: could not prune an old kept log");
        }
    }
}

/// True if a directory entry is a reparse point (a junction or symlink).
#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Whether this process is running elevated (as administrator).
///
/// The support client refuses to run elevated: it is meant to run as the customer's normal user, and
/// an elevated run is either a mistake or a technician doing something the design does not want on a
/// first-contact call. Nothing on the attended path checks this today.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: opens this process's own token, reads TokenElevation into a stack struct, closes it.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false; // cannot tell -> do not block a legitimate run
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// The entry point proper. Returns a process exit code.
#[cfg(windows)]
pub fn support_main(tail: &[String]) -> i32 {
    // 1. stdio sinks — before ANY println! (a windows-subsystem process has no console).
    crate::stdio::ensure_stdio_sinks();

    // A generic (pass-mode) build runs from a folder the guest extracted a download into, so it
    // loads DLLs from System32 only (docs/48; Setup does the same). Baked builds are unchanged.
    if rmt_agent_core::deployment::is_pass_mode() {
        restrict_dll_search_to_system32();
    }

    // argv: --deployment prints the baked origin (the publish guard reads it); a pass-mode build
    // prints its mode and root key instead, since it has no origin. Unknown args exit 2.
    match classify_argv(tail) {
        SupportArg::PrintDeployment => {
            if rmt_agent_core::deployment::is_pass_mode() {
                println!("MODE=PASS PASS_ROOT_KEY={}", rmt_agent_core::deployment::PASS_ROOT_KEY);
            } else {
                println!("{}", rmt_agent_core::deployment::CONTROL_PLANE_URL);
            }
            return 0;
        }
        SupportArg::Unknown => {
            eprintln!("DeskRallySupport: no arguments are accepted (or use --deployment)");
            return 2;
        }
        SupportArg::ElevatedInput => return crate::elevation_win::run_helper(tail),
        SupportArg::RunFlow => {}
    }

    // 2. DPI awareness BEFORE any window is created (idempotent; already-set is fine).
    let _ = crate::set_process_dpi_awareness();

    // 3. Refuse an elevated run, with a named message.
    //
    // The diagnostics come BEFORE the dialog, and that ordering is the point rather than tidiness:
    // `support_failure_dialog` is a `MessageBoxW` with no timeout, so it does not return until a
    // human clicks it. Anything logged after it is logged only on the runs that already had someone
    // watching — which is never the runs that need explaining.
    if is_elevated() {
        crate::logging::init_at_pinned(startup_log_path());
        tracing::error!("support: refusing to run elevated — showing the dialog, then exiting 2");
        eprintln!("DeskRallySupport: refusing to run elevated");
        crate::host::support_failure_dialog(&rmt_agent_core::support_ui::Failure::ElevatedRun);
        return 2;
    }

    // 4. Single instance (HINT): if a prompt window is already up, focus it and exit. FindWindowW,
    // never a Global\ mutex (a standard user lacks SeCreateGlobalPrivilege).
    if crate::code_prompt::focus_existing_prompt() {
        eprintln!("DeskRallySupport: already running — focused the existing window");
        return 0;
    }

    // 5. Per-run working root + hardened sweep of stale siblings.
    let run_root = match make_run_root() {
        Ok(r) => r,
        Err(e) => {
            // Best-effort: when the PARENT is what could not be created this log cannot be written
            // either. It still covers the ordinary case — the parent exists and the run dir is what
            // failed (an ACL, a full disk, a name collision) — which was previously silent.
            crate::logging::init_at_pinned(startup_log_path());
            tracing::error!(error = %e, "support: could not create the per-run working root");
            eprintln!("DeskRallySupport: {e}");
            crate::host::support_failure_dialog(&rmt_agent_core::support_ui::Failure::WorkspaceSetupFailed);
            return 1;
        }
    };

    // 6. Log pinned to the run root (RMT_LOG_FILE cannot redirect it), then the panic hook.
    crate::logging::init_at_pinned(run_root.join("support.log"));
    crate::panic_hook::install(run_root.clone());

    // Say so. The subscriber opens the log file per EVENT (`logging::EventWriter`), so before this
    // line a perfectly healthy run left `support.log` ABSENT and the run root completely empty —
    // nothing on the happy path emitted an event on the way to the prompt. docs/28 section 8.3 read
    // that empty directory as evidence of a hang; it is what success looks like. An announce here
    // makes the file's PRESENCE the normal case, so its absence means something again.
    tracing::info!(
        run_root = %run_root.display(),
        pid = std::process::id(),
        "support: starting"
    );

    // 7a. A generic build takes its server from the deployment pass beside it, verified against the
    // root key compiled in (docs/48 "Generic Support").
    let mut pass_binding = None;
    let origin = if rmt_agent_core::deployment::is_pass_mode() {
        match load_deployment_pass() {
            Ok(pass) => {
                tracing::info!(pass_id = %pass.pass_id(), origin = %pass.origin(), "support: deployment pass verified");
                pass_binding = Some(crate::host::PassBinding {
                    signaling_url: pass.signaling_url(),
                    grant_issuer_pubkey: pass.grant_issuer_pubkey().to_string(),
                    issued_to: pass.issued_to().to_string(),
                });
                pass.control_plane_url()
            }
            Err(failure) => {
                tracing::error!(failure = ?failure, "support: no usable deployment pass");
                crate::host::support_failure_dialog(&failure);
                return 1;
            }
        }
    } else {
        rmt_agent_core::deployment::CONTROL_PLANE_URL.trim().to_string()
    };

    // 7. Validate the baked origin against the SAME policy the URI path uses.
    if pass_binding.is_none() && rmt_agent_core::deployment::is_unconfigured() {
        tracing::error!("support: this build has no baked control-plane origin");
        eprintln!("DeskRallySupport: this build has no control-plane origin");
        crate::host::support_failure_dialog(&rmt_agent_core::support_ui::Failure::Unconfigured);
        return 1;
    }
    if let Err(e) = crate::enroll::validate_control_plane_url(&origin) {
        tracing::error!(origin = %origin, error = %e, "support: the baked control-plane origin is invalid");
        eprintln!("DeskRallySupport: baked control-plane origin is invalid: {e}");
        crate::host::support_failure_dialog(&rmt_agent_core::support_ui::Failure::Unconfigured);
        return 1;
    }

    // 8. Prompt for the code (redeemed while up), then the shared consent + stream tail.
    let product = product_name();
    // THE line. A modal prompt waiting for a code is a process that is alive, silent and
    // window-owning for as long as the customer takes to find and read out their code — which is
    // indistinguishable from a wedged process when seen from outside. Saying so turns "alive at
    // 151 s with no output" from a symptom into a status.
    tracing::info!(
        origin = %origin,
        "support: showing the code prompt — this process stays alive, waiting for a code, until one is entered or the window is cancelled"
    );
    let params = crate::host::support_attend_params(origin, run_root.clone(), pass_binding);
    let code = crate::host::run_attend_prompted(params, product);
    tracing::info!(exit = code, "support: the code prompt returned");

    // 9. Closing receipt: where the run's files live (nothing is INSTALLED; things are WRITTEN).
    println!("DeskRallySupport: session finished (exit {code}). Working folder: {}", run_root.display());
    println!("DeskRallySupport: nothing was installed. You can delete that folder.");
    code
}

/// The product name shown in the prompt caption. Built-in default; a deployment could override via a
/// baked constant later. Kept a plain constant for now.
fn product_name() -> String {
    "DeskRally".to_string()
}

/// The pass file a session bundle places beside a generic Support.
const PASS_FILE_NAME: &str = "deployment-pass.json";

/// Read `deployment-pass.json` from beside the exe: a regular file (never a link or junction), read
/// through ONE handle, at most [`rmt_agent_core::deployment_pass::MAX_SIGNED_OBJECT_BYTES`]. `None`
/// for a missing, non-regular or oversized file.
pub fn read_pass_file(exe_dir: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = open_regular_no_follow(&exe_dir.join(PASS_FILE_NAME))?;
    let limit = rmt_agent_core::deployment_pass::MAX_SIGNED_OBJECT_BYTES;
    let mut buf = Vec::with_capacity(limit);
    file.take(limit as u64 + 1).read_to_end(&mut buf).ok()?;
    (buf.len() <= limit).then_some(buf)
}

/// Open `path` for reading WITHOUT following a final-component link, and keep it only if the opened
/// object is a plain regular file. All checks run on the one handle that is then read, so there is
/// no check-then-open window: `FILE_FLAG_OPEN_REPARSE_POINT` opens a symlink or junction ITSELF
/// (never its target), and its reparse attribute is then refused. Directories need
/// `FILE_FLAG_BACKUP_SEMANTICS` to open at all, so they fail here too.
fn open_regular_no_follow(path: &Path) -> Option<std::fs::File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let file = std::fs::OpenOptions::new()
        .read(true)
        // Nobody may write or delete it while it is read.
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    let reparse = meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
    (meta.file_type().is_file() && !reparse).then_some(file)
}

/// Load and verify this generic build's deployment pass, mapping every refusal to the failure the
/// guest sees. The pass must cover `support`.
fn load_deployment_pass() -> Result<rmt_agent_core::deployment_pass::DeploymentPass, rmt_agent_core::support_ui::Failure> {
    use rmt_agent_core::deployment_pass::{verify_pass, Kind, RootKey};
    use rmt_agent_core::support_ui::Failure;
    let raw = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .and_then(|dir| read_pass_file(&dir))
        .ok_or(Failure::PassMissing)?;
    let root = RootKey::from_hex(rmt_agent_core::deployment::PASS_ROOT_KEY).map_err(|_| Failure::Unconfigured)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let pass = verify_pass(&root, &raw, now).map_err(|e| match e.kind {
        Kind::Validity => Failure::PassExpired,
        _ => Failure::PassRejected,
    })?;
    if !pass.for_support() {
        return Err(Failure::PassRejected);
    }
    Ok(pass)
}

/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`: later `LoadLibrary` calls search
/// System32 only, never the (download) folder the exe runs from. Best-effort: a failure is logged.
fn restrict_dll_search_to_system32() {
    use windows::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
    // SAFETY: a process-wide loader setting with no pointers; safe to call at any time.
    if let Err(e) = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } {
        eprintln!("DeskRallySupport: could not restrict DLL search to System32: {e}");
    }
}

/// Maximum bytes to read from a `session.code` sidecar. A 13-char Crockford code plus generous
/// whitespace overhead; we do NOT need to read past this to know the code is too long.
const SIDECAR_MAX_BYTES: u64 = 128;

/// Read and validate the optional `session.code` sidecar that a session bundle places alongside
/// the exe. Returns the validated code on success or `None` for missing/invalid/oversized files.
///
/// Security properties:
/// - Uses `symlink_metadata` (not `metadata`) so a junction or symlink is NEVER followed.
/// - Bounds the read to [`SIDECAR_MAX_BYTES`]; even a crafted file larger than that is rejected.
/// - Validates via [`crate::uri::validate_code`], the same allow-list the code-prompt uses.
/// - Any I/O error silently returns `None` — a missing sidecar is the normal case for guests
///   who downloaded the standalone exe.
pub fn read_sidecar_code(exe_dir: &Path) -> Option<String> {
    let path = exe_dir.join("session.code");
    // symlink_metadata does NOT follow the link — a junction or symlink is never traversed.
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > SIDECAR_MAX_BYTES {
        return None;
    }
    let raw = std::fs::read_to_string(&path).ok()?;
    let trimmed = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    crate::uri::validate_code(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_classification() {
        assert_eq!(classify_argv(&[]), SupportArg::RunFlow);
        assert_eq!(classify_argv(&["--deployment".to_string()]), SupportArg::PrintDeployment);
        assert_eq!(classify_argv(&["whatever".to_string()]), SupportArg::Unknown);
        assert_eq!(
            classify_argv(&["--deployment".to_string(), "extra".to_string()]),
            SupportArg::Unknown,
            "trailing junk after --deployment is not accepted"
        );
        assert_eq!(classify_argv(&["--code".to_string(), "X".to_string()]), SupportArg::Unknown);
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(classify_argv(&v(&["elevated-input", "--pipe", r"\\.\pipe\deskrally-elev-x", "--parent", "42"])), SupportArg::ElevatedInput);
        assert_eq!(classify_argv(&v(&["elevated-input", "--parent", "42", "--pipe", "x"])), SupportArg::Unknown, "exact shape only");
        assert_eq!(classify_argv(&v(&["elevated-input"])), SupportArg::Unknown);
        assert_eq!(classify_argv(&v(&["elevated-input", "--pipe", "x", "--parent", "42", "extra"])), SupportArg::Unknown);
    }

    #[test]
    fn the_run_dir_predicate_accepts_only_our_shape() {
        let good = format!("session-{}", "a".repeat(32));
        assert!(is_run_dir_name(&good));
        assert!(is_run_dir_name(&run_dir_name()), "a freshly generated name must pass its own gate");
        // Rejections from docs/27 step 11 verify (b):
        assert!(!is_run_dir_name("session-decoy"));
        assert!(!is_run_dir_name("session-"));
        assert!(!is_run_dir_name(&format!("session-{}", "a".repeat(31))), "31 hex is too short");
        assert!(!is_run_dir_name(&format!("session-{}", "a".repeat(33))), "33 hex is too long");
        assert!(!is_run_dir_name(&format!("session-{}.", "a".repeat(32))), "a trailing dot is rejected");
        assert!(!is_run_dir_name(&format!("session-{}", "g".repeat(32))), "non-hex is rejected");
        assert!(!is_run_dir_name("prefix-session-00000000000000000000000000000000"));
    }

    #[test]
    fn generated_run_dir_names_are_unique_and_valid() {
        let a = run_dir_name();
        let b = run_dir_name();
        assert_ne!(a, b, "two runs must not collide");
        assert!(is_run_dir_name(&a) && is_run_dir_name(&b));
    }

    /// The sweep removes a stale run dir and IGNORES a decoy, without following a planted junction.
    /// (The junction case is covered structurally by is_reparse_point + remove_dir; here we prove
    /// the name predicate on real directories.)
    #[test]
    fn the_sweep_removes_a_stale_run_dir_and_ignores_a_decoy() {
        let tmp = std::env::temp_dir().join(format!("deskrally-sweep-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let stale = tmp.join(format!("session-{}", "a".repeat(32)));
        let decoy = tmp.join("session-decoy");
        let unrelated = tmp.join("important-data");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("f.txt"), b"x").unwrap();
        std::fs::create_dir_all(&decoy).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();

        sweep_run_root(&tmp);

        assert!(!stale.exists(), "a stale session-<32hex> dir must be swept");
        assert!(decoy.exists(), "a decoy name must be left alone");
        assert!(unrelated.exists(), "an unrelated dir must be left alone");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// [`startup_log_path`] must be a sibling of the run roots, never inside one: the run root is
    /// exactly what does not exist on the two paths that write it.
    #[test]
    fn the_startup_log_sits_beside_the_run_roots_not_inside_one() {
        let p = startup_log_path();
        assert_eq!(
            p.parent(),
            Some(run_root_parent().as_path()),
            "the diagnostic must live in the run-root parent"
        );
        // The LITERAL name, not STARTUP_LOG_NAME: comparing the constant with itself would pass
        // against any rename, and this path is one a support engineer is TOLD to go and read.
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("support-startup.log"),
            "the diagnostic's name is support-facing; a rename needs a deliberate change here"
        );
        assert!(
            !is_run_dir_name(STARTUP_LOG_NAME),
            "the diagnostic must not be shaped like a run dir, or the sweep would eat it"
        );
    }

    #[test]
    fn sidecar_code_reads_valid_file() {
        let dir = std::env::temp_dir().join(format!("sidecar-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.code"), b"0123456789ABC").unwrap();
        assert_eq!(read_sidecar_code(&dir), Some("0123456789ABC".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_code_strips_whitespace() {
        let dir = std::env::temp_dir().join(format!("sidecar-ws-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.code"), b"  0123456789ABC\r\n").unwrap();
        assert_eq!(read_sidecar_code(&dir), Some("0123456789ABC".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_code_ignores_missing_file() {
        let dir = std::env::temp_dir().join(format!("sidecar-missing-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_sidecar_code(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_code_ignores_empty_file() {
        let dir = std::env::temp_dir().join(format!("sidecar-empty-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.code"), b"").unwrap();
        assert_eq!(read_sidecar_code(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_code_ignores_file_with_invalid_chars() {
        let dir = std::env::temp_dir().join(format!("sidecar-bad-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        // Contains a '!' which is not in the code_char_is_safe allow-list.
        std::fs::write(dir.join("session.code"), b"0123456789AB!").unwrap();
        assert_eq!(read_sidecar_code(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_code_ignores_file_that_is_too_long() {
        let dir = std::env::temp_dir().join(format!("sidecar-long-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        // 129 bytes — one over SIDECAR_MAX_BYTES.
        std::fs::write(dir.join("session.code"), vec![b'A'; 129]).unwrap();
        assert_eq!(read_sidecar_code(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(windows))]
    #[test]
    fn sidecar_code_ignores_symlink() {
        let dir = std::env::temp_dir().join(format!("sidecar-sym-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.code");
        std::fs::write(&target, b"0123456789ABC").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("session.code")).unwrap();
        // On non-Windows, symlink_metadata sees the symlink's own type (is_symlink), not is_file.
        assert_eq!(read_sidecar_code(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [`sweep_run_root`] walks the run-root PARENT, which is exactly where the pre-log diagnostic
    /// lives — so the sweep must not be able to delete it.
    ///
    /// What protects it is **not** [`is_run_dir_name`]: it is that the sweep only ever removes
    /// DIRECTORIES (and reparse points it unlinks without following). So this pins the
    /// mechanism-level property rather than the names — a plain FILE in the parent survives, *even
    /// one whose name matches the run-dir shape exactly*. That is the property a future "also tidy
    /// away stray files" change would break, taking the diagnostic with it.
    ///
    /// Mutation evidence, 2026-09-07. Renaming `STARTUP_LOG_NAME` into the `session-<32 hex>` shape
    /// and making `is_run_dir_name` match everything BOTH leave this test green — which is why its
    /// name and this comment no longer claim otherwise; the sibling test
    /// `the_startup_log_sits_beside_the_run_roots_not_inside_one` is what catches those. Swapping
    /// the sweep's `remove_dir_all` for a delete that also handles files REDS it, and so does
    /// gutting the sweep entirely (which is what the `stale` assertion below exists to detect).
    #[test]
    fn the_sweep_removes_only_directories_so_a_diagnostic_file_survives() {
        let tmp = std::env::temp_dir()
            .join(format!("deskrally-startuplog-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&tmp).unwrap();
        let diag = tmp.join(STARTUP_LOG_NAME);
        let body = b"support: refusing to run elevated\n";
        std::fs::write(&diag, body).unwrap();
        // A FILE whose name matches the run-dir shape exactly. It must survive too — the name is
        // not what saves the diagnostic, and a sweep that deleted this would delete the diagnostic
        // the day anybody renamed it.
        let file_named_like_a_run_dir = tmp.join(format!("session-{}", "c".repeat(32)));
        std::fs::write(&file_named_like_a_run_dir, b"a file, not a directory").unwrap();
        // A real stale run DIR, so the sweep has actual work to do. Without this the test would
        // also pass against a sweep gutted to do nothing at all.
        let stale = tmp.join(format!("session-{}", "b".repeat(32)));
        std::fs::create_dir_all(&stale).unwrap();

        sweep_run_root(&tmp);

        assert!(
            !stale.exists(),
            "the sweep did not run — this test proves nothing until it does"
        );
        assert!(diag.exists(), "the sweep deleted the pre-log diagnostic");
        assert!(
            file_named_like_a_run_dir.exists(),
            "the sweep deleted a FILE that merely carried a run-dir name"
        );
        assert_eq!(
            std::fs::read(&diag).unwrap(),
            body,
            "the diagnostic survived but was truncated or rewritten"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- kept logs ----

    fn tmp_parent(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("deskrally-keeplog-{tag}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(logs_dir(&p)).unwrap();
        p
    }

    fn stale_run(parent: &Path, hex: char, log: Option<&[u8]>) -> PathBuf {
        let d = parent.join(format!("session-{}", hex.to_string().repeat(32)));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("other.txt"), b"x").unwrap();
        if let Some(b) = log {
            std::fs::write(d.join("support.log"), b).unwrap();
        }
        d
    }

    fn kept(parent: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(logs_dir(parent))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn the_utc_stamp_is_sortable_and_correct() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(utc_stamp(UNIX_EPOCH + Duration::from_secs(1_794_573_296)), "20261113T123456Z");
        assert_eq!(utc_stamp(UNIX_EPOCH + Duration::from_secs(951_782_400)), "20000229T000000Z");
    }

    #[test]
    fn a_stale_runs_log_is_kept_across_the_next_start_and_the_dir_is_still_swept() {
        let tmp = tmp_parent("kept");
        let stale = stale_run(&tmp, 'a', Some(b"redeemed\nconsent\nws closed\n"));
        sweep_run_root(&tmp);
        assert!(!stale.exists(), "the stale dir must still be deleted");
        let k = kept(&tmp);
        assert_eq!(k.len(), 1, "{k:?}");
        assert!(k[0].starts_with("support-2") && k[0].ends_with("-aaaaaaaa.log"), "{k:?}");
        assert_eq!(std::fs::read(logs_dir(&tmp).join(&k[0])).unwrap(), b"redeemed\nconsent\nws closed\n");
        // The next sweep must not treat logs as a target, nor lose the kept log.
        sweep_run_root(&tmp);
        assert_eq!(kept(&tmp), k);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rotation_keeps_only_the_newest_five() {
        use std::time::{Duration, UNIX_EPOCH};
        let tmp = tmp_parent("rot");
        for i in 0..8u64 {
            let d = stale_run(&tmp, char::from(b'a' + i as u8), Some(format!("run {i}").as_bytes()));
            preserve_run_log(&d, &logs_dir(&tmp), UNIX_EPOCH + Duration::from_secs(1_700_000_000 + i * 60));
        }
        prune_logs(&logs_dir(&tmp), SUPPORT_LOG_PREFIX);
        let k = kept(&tmp);
        assert_eq!(k.len(), 5, "{k:?}");
        let bodies: Vec<String> =
            k.iter().map(|n| String::from_utf8(std::fs::read(logs_dir(&tmp).join(n)).unwrap()).unwrap()).collect();
        assert_eq!(bodies, ["run 3", "run 4", "run 5", "run 6", "run 7"], "the OLDEST were dropped");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_oversize_log_keeps_its_tail() {
        let tmp = tmp_parent("tail");
        let mut big = vec![0x01u8; 1024 * 1024];
        big.extend(vec![b'M'; KEEP_LOG_MAX_BYTES as usize - 10]);
        big.extend_from_slice(b"THE-END-OK");
        let stale = stale_run(&tmp, 'b', Some(&big));
        sweep_run_root(&tmp);
        assert!(!stale.exists());
        let k = kept(&tmp);
        let body = std::fs::read(logs_dir(&tmp).join(&k[0])).unwrap();
        assert_eq!(body.len() as u64, KEEP_LOG_MAX_BYTES);
        assert!(body.ends_with(b"THE-END-OK"), "the end of the run must survive");
        assert!(!body.contains(&0x01u8), "the head is what was dropped");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_missing_log_is_fine_and_the_dir_is_still_swept() {
        let tmp = tmp_parent("missing");
        let stale = stale_run(&tmp, 'c', None);
        sweep_run_root(&tmp);
        assert!(!stale.exists());
        assert!(kept(&tmp).is_empty());
        // Even with the logs dir itself absent, the sweep still sweeps.
        let stale2 = stale_run(&tmp, 'd', Some(b"x"));
        std::fs::remove_dir_all(logs_dir(&tmp)).unwrap();
        sweep_run_root(&tmp);
        assert!(!stale2.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_log_that_is_a_link_or_a_directory_is_not_followed_or_kept() {
        let tmp = tmp_parent("link");
        let secret = tmp.join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();
        // support.log as a symlink to a secret (may need Developer Mode: skipped, not faked).
        let a = stale_run(&tmp, 'e', None);
        let linked = std::os::windows::fs::symlink_file(&secret, a.join("support.log")).is_ok();
        // support.log as a junction to a directory (needs no privilege).
        let b = stale_run(&tmp, 'f', None);
        let target = tmp.join("target-dir");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("inside.txt"), b"keep me").unwrap();
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(b.join("support.log"))
            .arg(&target)
            .output()
            .expect("cmd");
        assert!(st.status.success(), "mklink /J failed: {st:?}");
        // support.log as a plain directory.
        let c = stale_run(&tmp, '1', None);
        std::fs::create_dir(c.join("support.log")).unwrap();

        sweep_run_root(&tmp);

        assert!(kept(&tmp).is_empty(), "a link or directory was kept as a log: {:?}", kept(&tmp));
        assert!(!a.exists() && !b.exists() && !c.exists(), "the dirs are still swept");
        assert_eq!(std::fs::read(&secret).unwrap(), b"TOP SECRET");
        assert!(target.join("inside.txt").exists(), "the junction target was followed and deleted");
        if !linked {
            eprintln!("symlink creation unavailable here; symlink case not exercised");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_support_log_that_is_a_hard_link_is_not_kept() {
        let tmp = tmp_parent("hardlink");
        let secret = tmp.join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();
        let stale = stale_run(&tmp, '3', None);
        std::fs::hard_link(&secret, stale.join("support.log")).expect("hard links need no privilege on NTFS");
        // Control: an ordinary single-link log in another run IS kept, so the refusal is the link count.
        let ok = stale_run(&tmp, '4', Some(b"my own log"));

        sweep_run_root(&tmp);

        assert!(!stale.exists() && !ok.exists(), "the dirs are still swept");
        let k = kept(&tmp);
        assert_eq!(k.len(), 1, "only the single-link log is kept: {k:?}");
        assert_eq!(std::fs::read(logs_dir(&tmp).join(&k[0])).unwrap(), b"my own log");
        assert_eq!(std::fs::read(&secret).unwrap(), b"TOP SECRET");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_logs_dir_that_is_a_junction_receives_nothing() {
        let tmp = tmp_parent("logsjunction");
        std::fs::remove_dir_all(logs_dir(&tmp)).unwrap();
        let target = tmp.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(logs_dir(&tmp))
            .arg(&target)
            .output()
            .expect("cmd");
        assert!(st.status.success(), "mklink /J failed: {st:?}");
        let stale = stale_run(&tmp, '2', Some(b"x"));
        sweep_run_root(&tmp);
        assert!(!stale.exists());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "a log was written through a junction");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_leftover_startup_log_is_rotated_not_overwritten() {
        let tmp = tmp_parent("startup");
        let src = tmp.join(STARTUP_LOG_NAME);
        std::fs::write(&src, b"refusing to run elevated").unwrap();
        keep_startup_log(&tmp, std::time::SystemTime::now());
        assert!(!src.exists());
        let k = kept(&tmp);
        assert_eq!(k.len(), 1);
        assert!(k[0].starts_with("startup-2") && k[0].ends_with(".log"), "{k:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- docs/48 C slice 4: the deployment pass beside a generic Support ----

    fn pass_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dr-pass-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_pass_file_is_read_only_as_a_bounded_regular_file() {
        let limit = rmt_agent_core::deployment_pass::MAX_SIGNED_OBJECT_BYTES;
        let d = pass_dir("read");
        assert_eq!(read_pass_file(&d), None, "missing file");
        std::fs::write(d.join(PASS_FILE_NAME), b"{\"format\":1}").unwrap();
        assert_eq!(read_pass_file(&d).as_deref(), Some(&b"{\"format\":1}"[..]));
        std::fs::write(d.join(PASS_FILE_NAME), vec![b' '; limit]).unwrap();
        assert_eq!(read_pass_file(&d).map(|b| b.len()), Some(limit), "exactly at the limit");
        std::fs::write(d.join(PASS_FILE_NAME), vec![b' '; limit + 1]).unwrap();
        assert_eq!(read_pass_file(&d), None, "one byte over the limit");
        std::fs::remove_file(d.join(PASS_FILE_NAME)).unwrap();
        std::fs::create_dir(d.join(PASS_FILE_NAME)).unwrap();
        assert_eq!(read_pass_file(&d), None, "a directory named like the pass");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_linked_pass_file_is_never_followed() {
        let d = pass_dir("link");
        let target = d.join("elsewhere.json");
        std::fs::write(&target, b"{}").unwrap();
        // Creating a symlink may need Developer Mode; a hard-to-create link is skipped, not faked.
        if std::os::windows::fs::symlink_file(&target, d.join(PASS_FILE_NAME)).is_ok() {
            assert_eq!(read_pass_file(&d), None, "a symlinked pass was followed");
            // The open primitive itself, handed a link directly: what a link swapped in after any
            // earlier check would deliver. It must refuse on the handle, not by a prior path check.
            assert!(open_regular_no_follow(&d.join(PASS_FILE_NAME)).is_none(), "the open followed a link");
            assert!(open_regular_no_follow(&target).is_some(), "control: the target itself opens");
        } else {
            eprintln!("symlink creation unavailable here; link refusal not exercised");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_junction_named_like_the_pass_is_refused() {
        let d = pass_dir("junction");
        let real = d.join("realdir");
        std::fs::create_dir(&real).unwrap();
        // mklink /J needs no privilege, so this one always runs.
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(d.join(PASS_FILE_NAME))
            .arg(&real)
            .output()
            .expect("cmd");
        assert!(status.status.success(), "mklink /J failed: {status:?}");
        assert!(open_regular_no_follow(&d.join(PASS_FILE_NAME)).is_none(), "a junction opened");
        assert_eq!(read_pass_file(&d), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
