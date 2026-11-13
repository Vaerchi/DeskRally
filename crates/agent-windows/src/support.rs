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
            if let Err(e) = std::fs::remove_dir_all(&path) {
                tracing::warn!(path = %path.display(), error = %e, "support: could not remove a stale run dir");
            }
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
