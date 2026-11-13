//! The Windows implementations of the directive seams (docs/65 F4): the update-chain trigger, the removal helper's launcher and
//! its machine-touching operations, and the helper's own signaling channel.
//!
//! **Nothing in this module is ever constructed by a test.** `WinActuator` starts the update worker and spawns the removal
//! helper; [`WinRemovalOps`] calls `MsiConfigureProductEx(..., ABSENT)` and deletes the agent root. The decision logic they
//! serve is `directive` (engine) and `directive_removal` (procedure), tested with doubles; the pure pieces defined here
//! (paths, the ack wire message, the answer matcher) are tested on their own. Real end-to-end execution is for a VM.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rmt_crypto::Identity;
use rmt_protocol::directive::{state, SignedAck, DIRECTIVE_FEATURE};
use rmt_protocol::signaling::{ClientToServer, ServerToClient};
use rmt_protocol::DeviceId;

use crate::anchor::{self, Anchor};
use crate::directive::{
    Actuator, OpRecord, ReinstallStatus, RemovalHandoff, RemovalOutcome, RemovalStatus,
};
use crate::directive_reinstall as reinstall;
use crate::directive_removal::{
    self as removal, AckChannel, AckDelivery, ConfigTree, HelperHandoff, RecordingDisposition, RemovalOps, RemovalResult,
};
use crate::update_files as files;
use crate::update_msi as msi;
use crate::update_runner as runner;

/// Where the helper directory is created: the SYSTEM profile's local app data,
/// `%SystemRoot%\System32\config\systemprofile\AppData\Local`. Every ancestor of it is SYSTEM/Administrators(/TrustedInstaller)-only,
/// so no unprivileged user can rename, delete or swap the helper directory. (`%SystemRoot%\Temp` is NOT used: its DACL lets Users
/// create and, on some machines, grants Everyone full control, so a non-admin could remove or replace a child of it.)
pub fn system_temp() -> PathBuf {
    let root = match std::env::var("SystemRoot").ok() {
        Some(v) if !v.trim().is_empty() => v,
        _ => r"C:\Windows".to_string(),
    };
    PathBuf::from(root).join(r"System32\config\systemprofile\AppData\Local")
}

/// The helper directory name for a directive: derived from the (canonical-UUID) directive id, so a second launch for the same
/// directive finds the first one's directory instead of creating a second helper.
pub fn helper_dir_name(directive_id: &str) -> Option<String> {
    uuid::Uuid::parse_str(directive_id)
        .ok()
        .filter(|u| u.hyphenated().to_string() == directive_id)
        .map(|_| format!("DeskRallyRemoval-{directive_id}"))
}

pub const HANDOFF_FILE: &str = "handoff.json";
pub const HELPER_EXE: &str = "helper.exe";
pub const STATUS_FILE: &str = "status.json";
pub const RESULT_FILE: &str = "result.json";
pub const HELPER_LOG: &str = "removal.log";
pub const JOURNAL_FILE: &str = "journal.json";
pub const TASK_XML_FILE: &str = "resume-task.xml";
pub const HELPER_LOCK: &str = "helper.lock";
/// Written right BEFORE the helper is spawned (after the directory is complete and verified): "a launch was attempted at `at_ms`".
pub const LAUNCH_MARKER_FILE: &str = "launching.json";
/// How long a launch marker with no helper status after it is believed (the helper writes its status within moments of starting).
pub const LAUNCH_GRACE_MS: i64 = 120_000;
const SHARE_READ: u32 = 0x1;
const MAX_HANDOFF_BYTES: usize = 32 * 1024;
/// How long the removal waits for pending central recording uploads before explicitly abandoning them (docs/63 R2, docs/65 D-C9).
const RECORDING_DRAIN_BUDGET: Duration = Duration::from_secs(90);

/// What an EXISTING helper directory means for a (re)launch of the removal.
#[derive(Debug)]
pub enum Recovery {
    /// The helper wrote its status or result (it ran, or runs), or a live process holds the helper lock: leave everything alone.
    Live,
    /// Nobody holds the lock yet but a launch was attempted moments ago (the process may still be starting), or the state cannot be
    /// established: do nothing, look again later.
    Starting,
    /// PROOF that no helper is alive: the stable helper lock was acquired by the recovery itself, and under that lock there is no
    /// status/result and no recent launch attempt. The guard is held; the caller may wipe and rebuild the directory, and must drop it
    /// right before spawning the new helper (which takes the same lock).
    Rebuild(Box<dyn std::any::Any>),
}

/// What the launch left behind in the helper directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub status_or_result: bool,
    pub launch_marker_at_ms: Option<i64>,
}

/// Decide what an existing helper directory means. Elapsed time alone NEVER authorizes a wipe: a spawned but suspended or slow helper
/// holds (or is about to hold) the stable helper lock, and recovery may rebuild only when it can take that very lock itself, which proves
/// no live helper, and after re-reading the evidence UNDER the lock. `try_lock`: `Ok(Some(guard))` = acquired, `Ok(None)` = held by
/// someone else, `Err` = cannot tell. Pure over its closures so every case is testable with a fake lock.
pub fn decide_recovery(
    try_lock: &mut dyn FnMut() -> io::Result<Option<Box<dyn std::any::Any>>>,
    evidence: &mut dyn FnMut() -> Result<Evidence, String>,
    now_ms: i64,
) -> Result<Recovery, String> {
    if evidence()?.status_or_result {
        return Ok(Recovery::Live);
    }
    let guard = match try_lock() {
        Ok(Some(g)) => g,
        // A live process holds it (however long ago it was launched), or the lock cannot be examined: never touch the directory.
        Ok(None) | Err(_) => return Ok(Recovery::Live),
    };
    // Under the lock: the helper may have written its status between the two looks.
    let e = evidence()?;
    if e.status_or_result {
        return Ok(Recovery::Live);
    }
    match e.launch_marker_at_ms {
        // The lock is free but the process was spawned moments ago and may not have reached its lock yet.
        Some(at) if now_ms.saturating_sub(at) < LAUNCH_GRACE_MS => Ok(Recovery::Starting),
        _ => Ok(Recovery::Rebuild(guard)),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LaunchMarker {
    at_ms: i64,
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The stable helper lock: a sibling of the helper directory, so it survives a rebuild of the directory. The HELPER takes it (no
/// sharing) before it reads its handoff and holds it for its whole run; recovery takes it to prove no helper is alive.
fn helper_lock_path(dir_name: &str) -> PathBuf {
    system_temp().join(format!("{dir_name}.lock"))
}

/// The launch GENERATION file, beside the stable lock (so it also survives a rebuild of the directory).
fn helper_gen_path(dir_name: &str) -> PathBuf {
    system_temp().join(format!("{dir_name}.gen"))
}

/// The current generation (0 when none was ever written). An unreadable or malformed file is an ERROR, never "0": a generation that
/// cannot be established must not let any helper act.
fn read_generation(path: &Path) -> io::Result<u64> {
    match std::fs::read_to_string(path) {
        Ok(t) => t.trim().parse::<u64>().map_err(|_| io::Error::other("the helper generation file is malformed")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Durably advance the generation and return the new one. The caller holds the stable lock, so nobody else reads or writes it; the new
/// value is on disk (temp file, flushed, renamed) before this returns, and therefore before the replacement helper is spawned. From
/// then on every older generation is superseded: it exits without touching anything (see [`generation_may_run`]).
fn bump_generation(path: &Path) -> io::Result<u64> {
    use std::io::Write;
    let next = read_generation(path)?.checked_add(1).ok_or_else(|| io::Error::other("generation overflow"))?;
    let tmp = path.with_extension("gen.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(next.to_string().as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(next)
}

/// Whether a helper launched as generation `own` may act when the current generation is `current`. A launch with no generation (the
/// scheduled restart task, which always re-runs the CURRENT helper copy against its own handoff) is the current one by construction.
pub fn generation_may_run(own: Option<u64>, current: u64) -> bool {
    own.is_none_or(|g| g == current)
}

fn open_helper_lock(dir_name: &str) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    // share_mode(0): a second open anywhere fails while this handle lives.
    std::fs::OpenOptions::new().write(true).create(true).share_mode(0).open(helper_lock_path(dir_name))
}

/// Read an existing helper directory's launch evidence.
fn read_evidence(dir: &anchor::Dir) -> Result<Evidence, String> {
    let has_result = dir.read(RESULT_FILE, 4096).map_err(|e| e.to_string())?.is_some();
    let has_status = dir.read(STATUS_FILE, 4096).map_err(|e| e.to_string())?.is_some();
    let marker = match dir.read(LAUNCH_MARKER_FILE, 256) {
        Ok(Some(b)) => serde_json::from_slice::<LaunchMarker>(&b).ok().map(|m| m.at_ms),
        Ok(None) => None,
        Err(e) => return Err(e.to_string()),
    };
    Ok(Evidence { status_or_result: has_result || has_status, launch_marker_at_ms: marker })
}

/// Recovery decision for the real helper directory `path` of `dir_name`.
fn recover_dir(path: &Path, dir_name: &str) -> Result<Recovery, String> {
    let mut lock = || -> io::Result<Option<Box<dyn std::any::Any>>> {
        Ok(open_helper_lock(dir_name).ok().map(|f| Box::new(f) as Box<dyn std::any::Any>))
    };
    let mut ev = || -> Result<Evidence, String> {
        let a = Anchor::open_at(path).map_err(|e| format!("cannot inspect the helper directory: {e}"))?;
        read_evidence(a.dir())
    };
    decide_recovery(&mut lock, &mut ev, now_unix_ms())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HelperStatus {
    pid: u32,
    creation_time: u64,
}

fn sha256_hex(f: &mut std::fs::File) -> io::Result<String> {
    use sha2::Digest;
    use std::io::{Read, Seek};
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

// ---------------------------------------------------------------------------------------------------
// The actuator
// ---------------------------------------------------------------------------------------------------

/// Production [`Actuator`]: the update chain via the anchored root, the removal helper via a private temp directory.
pub struct WinActuator;

impl WinActuator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WinActuator {
    fn default() -> Self {
        Self::new()
    }
}

/// The lock the engine and the update worker both hold across their eligibility check + reservation (D-C5). One durable file in the
/// anchored agent root, opened with NO sharing: whoever has it open is the only one deciding. `Ok(None)` ⇒ the other path holds it.
pub const EXCLUSION_LOCK: &str = "directive-update.lock";

pub fn try_exclusion(root: &anchor::Dir) -> io::Result<Option<std::fs::File>> {
    match root.open_exclusive(EXCLUSION_LOCK) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.raw_os_error() == Some(32) => Ok(None), // ERROR_SHARING_VIOLATION: held by the other path
        Err(e) => Err(e),
    }
}

impl Actuator for WinActuator {
    fn acquire_exclusion(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        let anchor = Anchor::open().ok()?;
        let lock = try_exclusion(anchor.dir()).ok().flatten()?;
        Some(Box::new(lock))
    }

    fn update_busy(&mut self) -> bool {
        // Any doubt is "busy": a directive waits, it never races an installer.
        let Ok(anchor) = Anchor::open() else { return true };
        match files::load_state(anchor.dir()) {
            Ok(state) => !matches!(state.phase, crate::update_state::Phase::Idle) || msi::installer_busy().unwrap_or(true),
            Err(_) => true,
        }
    }

    fn start_reinstall(&mut self, rec: &OpRecord, now_ms: i64) -> Result<(), String> {
        let anchor = Anchor::open().map_err(|e| format!("agent root: {e}"))?;
        // Idempotent per directive: a marker for THIS directive (Requested, Launched or Refused) is left exactly as it is, so a
        // retry after a crash can never reset a launched request into a second attempt. The update state, not the marker, is what
        // proves an attempt exists.
        let existing = reinstall::read(anchor.dir()).map_err(|e| format!("could not read the reinstall request: {e}"))?;
        if existing.as_ref().is_none_or(|m| m.directive_id != rec.directive_id) {
            let marker = reinstall::Marker::requested(&rec.directive_id, now_ms, rec.expires_at_ms);
            reinstall::write(anchor.dir(), &marker).map_err(|e| format!("could not write the reinstall request: {e}"))?;
        }
        // Start the scheduled worker now instead of waiting for its next hourly run. Best effort: the hourly trigger still
        // picks the marker up, and the marker expires with the directive.
        let out = std::process::Command::new(crate::agent_root::system32_exe("schtasks.exe"))
            .args(["/Run", "/TN", crate::update_provision::TASK_NAME])
            .output();
        match out {
            Ok(o) if o.status.success() => tracing::info!("directive: started the auto-update task for a reinstall"),
            Ok(o) => tracing::warn!(code = ?o.status.code(), "directive: could not start the auto-update task; the next scheduled run will pick the request up"),
            Err(e) => tracing::warn!(error = %e, "directive: could not start the auto-update task; the next scheduled run will pick the request up"),
        }
        Ok(())
    }

    fn reinstall_status(&mut self, rec: &OpRecord, now_ms: i64) -> ReinstallStatus {
        let read = (|| -> io::Result<(Option<reinstall::Marker>, crate::update_state::UpdateState)> {
            let anchor = Anchor::open()?;
            Ok((reinstall::read(anchor.dir())?, files::load_state(anchor.dir())?))
        })();
        match read {
            Ok((marker, state)) => reinstall::status(marker.as_ref(), &state, &rec.directive_id, rec.expires_at_ms, now_ms),
            // Unreadable right now: keep waiting rather than guess.
            Err(_) => ReinstallStatus::InProgress,
        }
    }

    fn start_uninstall(&mut self, handoff: &RemovalHandoff) -> Result<(), String> {
        let dir_name = helper_dir_name(&handoff.directive_id).ok_or("directive id is not a canonical UUID")?;
        // The helper confirms its final result over HTTPS to the control plane; without a valid origin it could never know the outcome.
        final_ack_url(&handoff.control_plane_url, &handoff.directive_id)
            .map_err(|e| format!("no usable control plane URL for the final report: {e}"))?;
        let temp = system_temp();
        // Idempotent, but a directory is NOT proof of a launch: the service can die between creating it and spawning the helper. An
        // existing directory is judged by its evidence (helper status/result, a recent launch marker); an abandoned preparation
        // is wiped and rebuilt below.
        let existing = temp.join(&dir_name);
        // Held across the wipe and the rebuild; dropped right before the new helper is spawned (the helper takes the same lock).
        let mut recovery_lock: Option<Box<dyn std::any::Any>> = None;
        if std::fs::symlink_metadata(&existing).is_ok() {
            match recover_dir(&existing, &dir_name)? {
                Recovery::Live | Recovery::Starting => return Ok(()),
                Recovery::Rebuild(guard) => {
                    tracing::warn!("directive: no live helper holds the removal lock and none ever reported; rebuilding the helper directory");
                    recovery_lock = Some(guard);
                    let anchor = Anchor::open_at(&existing).map_err(|e| format!("cannot inspect the helper directory: {e}"))?;
                    anchor.dir().remove_tree_contents(&anchor::TreeLimits::default()).map_err(|e| format!("cannot clear the abandoned helper directory: {e}"))?;
                    drop(anchor);
                    std::fs::remove_dir(&existing).map_err(|e| format!("cannot remove the abandoned helper directory: {e}"))?;
                }
            }
        }
        // The stable lock is held from here until just before the spawn (recovery already holds it; a first launch takes it). While
        // it is held the next GENERATION is made durable, so a helper from an earlier launch that was only suspended (and takes the lock
        // later) finds a newer generation and exits without acting.
        let guard = match recovery_lock.take() {
            Some(g) => g,
            None => match open_helper_lock(&dir_name) {
                Ok(f) => Box::new(f) as Box<dyn std::any::Any>,
                Err(_) => return Ok(()), // a live helper (or another launcher) holds it
            },
        };
        recovery_lock = Some(guard);
        let generation = bump_generation(&helper_gen_path(&dir_name)).map_err(|e| format!("could not record the helper generation: {e}"))?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let install = runner::install_location().map_err(|e| e.to_string())?;
        // D-C7 / docs/65 F4: the running image must BE the MSI install location (refuses an attended stub, a promoted
        // download directory, anything else).
        let exe_dir = exe.parent().ok_or("the agent image has no directory")?;
        removal::verify_dir_identity(exe_dir, &install)
            .map_err(|e| format!("this agent is not running from the MSI install location: {e}"))?;
        let family = msi::installed_family().map_err(|e| e.to_string())?;
        let [product_code] = family.as_slice() else {
            return Err("the installed products are not exactly one agent product".into());
        };
        let hh = HelperHandoff {
            base: RemovalHandoff {
                v: handoff.v,
                directive_id: handoff.directive_id.clone(),
                artifact: handoff.artifact.clone(),
                device_id: handoff.device_id.clone(),
                tenant_id: handoff.tenant_id.clone(),
                key_fp: handoff.key_fp.clone(),
                pinned_directive_key: handoff.pinned_directive_key.clone(),
                identity_seed_hex: handoff.identity_seed_hex.clone(),
                accepted_ms: handoff.accepted_ms,
                signaling_url: handoff.signaling_url.clone(),
                control_plane_url: handoff.control_plane_url.clone(),
            },
            product_code: product_code.clone(),
            install_dir: install.to_string_lossy().into_owned(),
            config_dir: crate::config::CONFIG_DIR.to_owned(),
        };
        // The same pre-flight the helper will run: refuse BEFORE a helper exists.
        removal::preflight(&mut WinRemovalOps::new(None), &hh)?;

        let dir = anchor::create_private_dir(&temp, &dir_name).map_err(|e| format!("could not create the helper directory: {e}"))?;
        let launched = (|| -> Result<(), String> {
            let json = serde_json::to_vec(&hh).map_err(|e| e.to_string())?;
            dir.write_atomic(HANDOFF_FILE, &json).map_err(|e| e.to_string())?;
            let mut source = std::fs::File::open(&exe).map_err(|e| e.to_string())?;
            {
                let mut copy = dir.create_file(HELPER_EXE).map_err(|e| e.to_string())?;
                io::copy(&mut source, &mut copy).map_err(|e| e.to_string())?;
                io::Write::flush(&mut copy).and_then(|_| copy.sync_all()).map_err(|e| e.to_string())?;
            }
            let mut copy = dir.open_file_read(HELPER_EXE, SHARE_READ).map_err(|e| e.to_string())?;
            if sha256_hex(&mut source).map_err(|e| e.to_string())? != sha256_hex(&mut copy).map_err(|e| e.to_string())? {
                return Err("the helper copy differs from the installed image".into());
            }
            let helper_path = {
                use std::os::windows::io::AsRawHandle;
                anchor::final_path(copy.as_raw_handle()).map_err(|e| e.to_string())?
            };
            crate::update_download::verify_authenticode(Path::new(&helper_path))
                .map_err(|e| format!("the helper copy failed signature verification: {e}"))?;
            let handoff_path = format!("{}\\{HANDOFF_FILE}", dir.final_path().map_err(|e| e.to_string())?);
            drop(copy);
            let marker = serde_json::to_vec(&LaunchMarker { at_ms: now_unix_ms() }).map_err(|e| e.to_string())?;
            dir.write_atomic(LAUNCH_MARKER_FILE, &marker).map_err(|e| e.to_string())?;
            // The new helper takes the stable lock itself: release ours (if recovery held it) just before it exists.
            drop(recovery_lock.take());
            spawn_detached(&helper_path, &format!("directive-removal \"{handoff_path}\" {generation}"))
        })();
        if let Err(e) = launched {
            // Nothing was touched: clean the directory so a retry can create it again.
            let _ = dir.remove_tree_contents(&anchor::TreeLimits::default());
            drop(dir);
            let _ = std::fs::remove_dir(temp.join(&dir_name));
            return Err(e);
        }
        Ok(())
    }

    fn removal_status(&mut self, rec: &OpRecord) -> RemovalStatus {
        let Some(name) = helper_dir_name(&rec.directive_id) else { return RemovalStatus::Exited(None) };
        let path = system_temp().join(name);
        if std::fs::symlink_metadata(&path).is_err() {
            return RemovalStatus::NotLaunched;
        }
        let Ok(anchor) = Anchor::open_at(&path) else { return RemovalStatus::Running };
        let dir = anchor.dir();
        if let Ok(Some(bytes)) = dir.read(RESULT_FILE, 4096) {
            return RemovalStatus::Exited(serde_json::from_slice::<RemovalOutcome>(&bytes).ok());
        }
        match dir.read(STATUS_FILE, 4096) {
            Ok(Some(bytes)) => match serde_json::from_slice::<HelperStatus>(&bytes) {
                Ok(s) => match runner::runner_presence(&crate::update_state::RunnerIdentity { pid: s.pid, creation_time: s.creation_time }) {
                    runner::Presence::Present | runner::Presence::Unknown => RemovalStatus::Running,
                    runner::Presence::Absent => RemovalStatus::Exited(None),
                },
                Err(_) => RemovalStatus::Exited(None),
            },
            // No status yet: either the helper has just been spawned, or no helper was ever spawned (a crash after the directory was
            // created). The launch marker tells them apart.
            Ok(None) => match recover_dir(&path, &helper_dir_name(&rec.directive_id).unwrap_or_default()) {
                // Rebuild's guard drops here: only start_uninstall (which re-decides under the lock) ever acts on it.
                Ok(Recovery::Rebuild(_guard)) => RemovalStatus::NotLaunched,
                _ => RemovalStatus::Running,
            },
            Err(_) => RemovalStatus::Running,
        }
    }
}

/// `%SystemRoot%\System32\Tasks`: where Task Scheduler keeps task definitions (SYSTEM/Administrators-writable only).
pub fn tasks_root() -> PathBuf {
    let root = match std::env::var("SystemRoot").ok() {
        Some(v) if !v.trim().is_empty() => v,
        _ => r"C:\Windows".to_string(),
    };
    PathBuf::from(root).join(r"System32\Tasks")
}

/// Whether the task `name` (`\Folder\Task`) is registered, from its definition file under `tasks_root`. `Ok(false)` ONLY for NotFound;
/// every other failure (access denied, a sharing violation, a broken path) is an error, never "absent".
pub fn task_presence(tasks_root: &Path, name: &str) -> Result<bool, String> {
    let rel = name.trim_start_matches('\\');
    if rel.is_empty() || rel.split('\\').any(|c| c.is_empty() || c == ".." || c == "." || c.contains(':')) {
        return Err("an unusable task name".into());
    }
    match std::fs::symlink_metadata(tasks_root.join(rel)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot tell whether the task exists: {e}")),
    }
}

/// Remove a task safely: already absent is success; a presence error propagates; a delete failure propagates; and after a successful
/// delete the task must be verifiably GONE.
pub fn remove_task_checked(presence: &dyn Fn() -> Result<bool, String>, delete: &dyn Fn() -> Result<(), String>) -> Result<(), String> {
    if !presence()? {
        return Ok(());
    }
    delete()?;
    if presence()? {
        return Err("the restart task is still registered after /Delete".into());
    }
    Ok(())
}

/// Spawn `exe args` fully DETACHED: it must outlive the process that spawned it, which the removal destroys. Tries to break
/// out of any job first; falls back to a plain detached spawn.
fn spawn_detached(exe: &str, args: &str) -> Result<(), String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
    let app = wide(exe);
    let cwd = wide(&crate::agent_root::system32_exe("").to_string_lossy());
    let cmdline = format!("\"{exe}\" {args}");
    let base = DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    let spawn = |flags: PROCESS_CREATION_FLAGS| -> windows::core::Result<()> {
        let mut cmd = wide(&cmdline);
        let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: both buffers are NUL-terminated and outlive the call; the returned handles are closed exactly once.
        unsafe {
            CreateProcessW(PCWSTR(app.as_ptr()), PWSTR(cmd.as_mut_ptr()), None, None, false, flags, None, PCWSTR(cwd.as_ptr()), &si, &mut pi)?;
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
        }
        Ok(())
    };
    spawn(base | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(base)).map_err(|e| format!("could not start the removal helper: {e}"))
}

// ---------------------------------------------------------------------------------------------------
// The helper's machine-touching operations
// ---------------------------------------------------------------------------------------------------

/// Production [`RemovalOps`]. `helper_dir` is the helper's own directory (for self-cleanup); `None` for the orchestrator's
/// read-only pre-flight, which never reaches `configure_absent` or `delete_config_tree`.
pub struct WinRemovalOps {
    tree: ConfigTree,
    helper_dir: Option<PathBuf>,
    directive_id: Option<String>,
    /// R4: the install chain, held open (no rename/delete sharing on ancestors) through the MSI removal.
    held: Option<anchor::HeldChain>,
}

impl WinRemovalOps {
    pub fn new(helper_dir: Option<PathBuf>) -> Self {
        Self { tree: ConfigTree::new(), helper_dir, directive_id: None, held: None }
    }

    pub fn for_directive(helper_dir: PathBuf, directive_id: &str) -> Self {
        Self { directive_id: Some(directive_id.to_owned()), ..Self::new(Some(helper_dir)) }
    }

    fn task_name(&self) -> Option<String> {
        self.directive_id.as_ref().map(|id| format!("\\DeskRally\\RemovalResume-{id}"))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

impl RemovalOps for WinRemovalOps {
    fn installed_products(&mut self) -> Result<Vec<String>, String> {
        msi::installed_family().map_err(|e| e.to_string())
    }

    fn product_is_per_machine(&mut self, code: &str) -> Result<bool, String> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::System::ApplicationInstallationAndServicing::{MsiGetProductInfoExW, MSIINSTALLCONTEXT_MACHINE};
        let (code, prop) = (wide(code), wide("VersionString"));
        let mut buf = vec![0u16; 64];
        let mut len = buf.len() as u32;
        // With no user SID and the MACHINE context this succeeds only for a per-machine installation.
        let rc = unsafe {
            MsiGetProductInfoExW(PCWSTR(code.as_ptr()), PCWSTR::null(), MSIINSTALLCONTEXT_MACHINE, PCWSTR(prop.as_ptr()), PWSTR(buf.as_mut_ptr()), Some(&mut len))
        };
        match rc {
            0 => Ok(true),
            1605 => Ok(false), // ERROR_UNKNOWN_PRODUCT in the machine context: not a per-machine install
            rc => Err(format!("Windows Installer error {rc}")),
        }
    }

    fn product_install_location(&mut self, code: &str) -> Result<String, String> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::System::ApplicationInstallationAndServicing::MsiGetProductInfoW;
        let (code, prop) = (wide(code), wide("InstallLocation"));
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let rc = unsafe { MsiGetProductInfoW(PCWSTR(code.as_ptr()), PCWSTR(prop.as_ptr()), PWSTR(buf.as_mut_ptr()), Some(&mut len)) };
        if rc != 0 {
            return Err(format!("Windows Installer error {rc}"));
        }
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        Ok(s.trim_end_matches('\\').to_owned())
    }

    fn verify_install_dir(&mut self, claimed: &str, expected: &str) -> Result<(), String> {
        removal::verify_dir_identity(Path::new(claimed), Path::new(expected)).map(|_| ()).map_err(|e| e.to_string())
    }

    fn preflight_config_tree(&mut self, config_dir: &str) -> Result<usize, String> {
        // The agent root is a fixed location: a handoff naming anything else is not ours to delete.
        if !config_dir.eq_ignore_ascii_case(crate::config::CONFIG_DIR) {
            return Err("the handoff names a directory other than the agent root".into());
        }
        self.tree.preflight(Path::new(config_dir))
    }

    fn settle_recordings(&mut self) -> Result<RecordingDisposition, String> {
        // D-C9 (docs/63 R2): finish pending central uploads within a bounded time, then EXPLICITLY abandon whatever could not
        // finish (`finish_or_abandon_pending` never leaves anything pending). Uploaded recordings have already had their local
        // copy deleted by the uploader; what is still on disk afterwards goes with the machine and is counted in the ack.
        // FALLIBLE: anything that could not be settled durably (an incomplete enumeration, an unreadable queue entry, a
        // settlement that could not be saved) returns Err and BLOCKS the removal; only a fully settled queue proceeds.
        let drain = crate::recording_upload_http::finish_or_abandon_pending(RECORDING_DRAIN_BUDGET)?;
        fn count_files(dir: &Path, depth: usize) -> io::Result<usize> {
            if depth > 4 {
                return Ok(0);
            }
            let mut n = 0;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    n += count_files(&entry.path(), depth + 1)?;
                } else if ft.is_file() {
                    n += 1;
                }
            }
            Ok(n)
        }
        let mut local = 0usize;
        for dir in [crate::config::DEFAULT_RECORDING_DIR, crate::recording_broker::DIRECTORY] {
            match count_files(Path::new(dir), 0) {
                Ok(n) => local += n,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(removal::recording_disposition(drain.uploaded as usize, drain.abandoned as usize, local))
    }

    fn configure_absent(&mut self, code: &str) -> u32 {
        use windows::core::PCWSTR;
        use windows::Win32::System::ApplicationInstallationAndServicing::{
            MsiConfigureProductExW, MsiSetInternalUI, INSTALLLEVEL, INSTALLSTATE_ABSENT, INSTALLUILEVEL_NONE,
        };
        let (code, cmd) = (wide(code), wide("REBOOT=ReallySuppress"));
        // INSTALLLEVEL_DEFAULT (0) with the product forced to ABSENT: a full, silent removal that keeps the product's own
        // uninstall custom actions (service removal, safe-boot cleanup, URI handler) in the loop.
        unsafe {
            MsiSetInternalUI(INSTALLUILEVEL_NONE, None);
            MsiConfigureProductExW(PCWSTR(code.as_ptr()), INSTALLLEVEL(0), INSTALLSTATE_ABSENT, PCWSTR(cmd.as_ptr()))
        }
    }

    fn installer_busy(&mut self) -> bool {
        msi::installer_busy().unwrap_or(true)
    }

    fn boot_id(&mut self) -> String {
        files::boot_id().unwrap_or_default()
    }

    fn hold_install_dir(&mut self, install_dir: &str) -> Result<(), String> {
        let leaf = Path::new(install_dir);
        // The floor is the volume root: the rights that matter there are the ones that could remove or rewrite it.
        let mut comps = leaf.components();
        let (Some(std::path::Component::Prefix(p)), Some(std::path::Component::RootDir)) = (comps.next(), comps.next()) else {
            return Err("the install directory is not a drive-letter path".into());
        };
        let floor = PathBuf::from(format!("{}\\", p.as_os_str().to_string_lossy()));
        let chain = anchor::hold_chain(leaf, &floor).map_err(|e| e.to_string())?;
        if !chain.leaf_path().eq_ignore_ascii_case(install_dir.trim_end_matches('\\')) {
            return Err(format!("the held directory is {} not {install_dir}", chain.leaf_path()));
        }
        self.held = Some(chain);
        Ok(())
    }

    fn release_install_dir(&mut self) {
        self.held = None;
    }

    fn install_dir_absent(&mut self, install_dir: &str) -> Result<bool, String> {
        // By name and without following a final reparse point: only "not found" is absence; anything else is not an answer.
        match std::fs::symlink_metadata(install_dir) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    }

    fn install_resume_task(&mut self) -> Result<(), String> {
        let (Some(dir), Some(name)) = (self.helper_dir.clone(), self.task_name()) else {
            return Err("no helper directory".into());
        };
        let helper = dir.join(HELPER_EXE).to_string_lossy().into_owned();
        let handoff = dir.join(HANDOFF_FILE).to_string_lossy().into_owned();
        let xml = removal::resume_task_xml(&helper, &handoff)?;
        // schtasks reads the definition from a file (UTF-16LE with BOM); the file lives in the SYSTEM-only helper directory.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let anchor = Anchor::open_at(&dir).map_err(|e| e.to_string())?;
        anchor.dir().write_atomic(TASK_XML_FILE, &bytes).map_err(|e| e.to_string())?;
        let xml_path = dir.join(TASK_XML_FILE);
        // An argv array: no shell, no composed command line.
        let out = std::process::Command::new(crate::agent_root::system32_exe("schtasks.exe"))
            .args(["/Create", "/TN", name.as_str(), "/XML"])
            .arg(&xml_path)
            .arg("/F")
            .output()
            .map_err(|e| e.to_string())?;
        let _ = anchor.dir().remove(TASK_XML_FILE);
        if out.status.success() { Ok(()) } else { Err(format!("schtasks /Create exited {:?}", out.status.code())) }
    }

    fn remove_resume_task(&mut self) -> Result<(), String> {
        let Some(name) = self.task_name() else { return Ok(()) };
        let schtasks = crate::agent_root::system32_exe("schtasks.exe");
        let root = tasks_root();
        // Presence is judged from the task's definition FILE under System32Tasks (language-independent, unlike schtasks' messages): only
        // NotFound is "absent"; any other failure propagates. After /Delete the task must be verifiably gone.
        remove_task_checked(
            &|| task_presence(&root, &name),
            &|| {
                let out = std::process::Command::new(&schtasks).args(["/Delete", "/TN", name.as_str(), "/F"]).output().map_err(|e| e.to_string())?;
                if out.status.success() { Ok(()) } else { Err(format!("schtasks /Delete exited {:?}", out.status.code())) }
            },
        )
    }

    fn config_root_identity(&mut self) -> Option<anchor::FileIdentity> {
        self.tree.identity()
    }

    fn expect_config_root(&mut self, id: Option<anchor::FileIdentity>) {
        self.tree.expect(id);
    }

    fn delete_helper_secrets(&mut self) -> Result<(), String> {
        let Some(dir) = &self.helper_dir else { return Ok(()) };
        let anchor = match Anchor::open_at(dir) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        // The handoff holds the identity seed. `remove` succeeds when it is already gone.
        anchor.dir().remove(HANDOFF_FILE).map_err(|e| e.to_string())
    }

    fn delete_config_tree_keep_identity(&mut self, config_dir: &str) -> Result<usize, String> {
        if !config_dir.eq_ignore_ascii_case(crate::config::CONFIG_DIR) {
            return Err("the handoff names a directory other than the agent root".into());
        }
        // The root's identity is the journaled pre-flight one (`expect_config_root`), never re-learned here.
        self.tree.delete_except_identity(Path::new(config_dir))
    }

    fn verify_config_clean(&mut self, config_dir: &str) -> Result<(), String> {
        self.tree.verify_only_identity_left(Path::new(config_dir))
    }

    fn delete_identity_and_root(&mut self, config_dir: &str, allow_absent: bool) -> Result<(), String> {
        if !config_dir.eq_ignore_ascii_case(crate::config::CONFIG_DIR) {
            return Err("the handoff names a directory other than the agent root".into());
        }
        self.tree.delete_identity_and_root(Path::new(config_dir), allow_absent)
    }

    fn cleanup_footprint(&mut self) {
        // What the legacy detached-cmd removal did for the URI handler and Safe Mode; the MSI knows neither.
        if let Some(scheme) = crate::service::deployment_scheme_from_config() {
            let _ = crate::uri::unregister_scheme(&scheme);
        }
        crate::reboot::remove_safeboot_registration();
        crate::reboot::clear_safeboot_best_effort();
    }

    fn schedule_self_cleanup(&mut self) {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
        let Some(dir) = &self.helper_dir else { return };
        // Files first, then the directory (the order the reboot-time deletion needs). The running image cannot delete itself.
                for name in [JOURNAL_FILE, STATUS_FILE, LAUNCH_MARKER_FILE, HELPER_LOG, HELPER_EXE] {
            let p = wide(&dir.join(name).to_string_lossy());
            let _ = unsafe { MoveFileExW(PCWSTR(p.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
        }
        let p = wide(&dir.to_string_lossy());
        let _ = unsafe { MoveFileExW(PCWSTR(p.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            for p in [helper_lock_path(name), helper_gen_path(name)] {
                let p = wide(&p.to_string_lossy());
                let _ = unsafe { MoveFileExW(PCWSTR(p.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The helper's signaling channel
// ---------------------------------------------------------------------------------------------------

/// What the control plane answered to an ack (`ServerToClient::DirectiveAckResult.outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckAnswer {
    Applied,
    Refused,
    Unavailable,
}

/// The wire message for a signed ack: the exact fields the control plane's verifier checks, nothing else.
pub fn ack_message(ack: &SignedAck) -> ClientToServer {
    ClientToServer::DirectiveAck {
        directive_id: ack.directive_id.clone(),
        from: ack.from.clone(),
        to: ack.to.clone(),
        ts_ms: ack.ts_ms,
        detail: ack.detail.clone(),
        sig: ack.sig.clone(),
    }
}

/// Read a server message as the answer to EXACTLY `ack`: the directive id and the echoed `from`, `to` and `ts_ms` must all match. An
/// answer without the echo, or echoing a different send, is unattributable and is `None` (never a success).
pub fn answer_to(msg: &ServerToClient, ack: &SignedAck) -> Option<AckAnswer> {
    match msg {
        ServerToClient::DirectiveAckResult { directive_id: id, outcome, from: Some(from), to: Some(to), ts_ms: Some(ts) }
            if *id == ack.directive_id && *from == ack.from && *to == ack.to && *ts == ack.ts_ms =>
        {
            Some(match outcome.as_str() {
            "applied" | "replay" => AckAnswer::Applied,
            "refused" => AckAnswer::Refused,
            _ => AckAnswer::Unavailable,
            })
        }
        _ => None,
    }
}

/// The helper's OWN connection: after the removal the agent that held the real one is gone, and the identity key is still on
/// disk only until the final report is delivered. Failure acks are not sent here: the surviving agent reports a failure from
/// the helper's result file (a second registration for the device would only displace its live connection).
pub struct SignalingAckChannel {
    pub signaling_url: String,
    pub device: uuid::Uuid,
    pub tenant: String,
    pub seed: [u8; 32],
    /// Total patience for one `deliver` call (the helper's journal carries retries across calls and restarts).
    pub budget: Duration,
    /// The product is gone, so no surviving agent will report a failure: this channel must.
    pub agent_gone: bool,
    /// A durable result handoff exists that the surviving agent will read and report (see [`failed_ack_suppressed`]).
    pub result_durable: bool,
}

/// A4: the helper reports a failure itself UNLESS a surviving agent AND a durable result handoff both exist. `agent_gone` comes from
/// the durable journal phase (`run_removal` derives it before any delivery), never from a restarted process's default.
pub fn failed_ack_suppressed(agent_gone: bool, result_durable: bool) -> bool {
    !agent_gone && result_durable
}

impl SignalingAckChannel {
    async fn attempt(&self, ack: &SignedAck) -> Result<AckAnswer, String> {
        use rmt_transport_webrtc::{Role, WebRtcTransport};
        let identity = Identity::from_seed(&self.seed);
        let role = Role::Agent {
            device: DeviceId(self.device),
            pubkey: identity.public_hex(),
            tenant: Some(self.tenant.clone()),
            signer: Some(std::sync::Arc::new(crate::enroll::IdentitySigner::new(identity))),
            os: None,
            require_session_policy: false,
            agent_version: Some(rmt_agent_core::version::AGENT_VERSION.to_string()),
            logged_in_user: None,
            multi_session_capable: None,
            features: vec![DIRECTIVE_FEATURE.to_string()],
        };
        let (sig, mut rx, _features) = tokio::time::timeout(
            Duration::from_secs(30),
            WebRtcTransport::register_for_mux_with_features(&self.signaling_url, &role),
        )
        .await
        .map_err(|_| "registration timed out".to_string())??;
        sig.send(ack_message(ack))?;
        let deadline = Instant::now() + Duration::from_secs(25);
        let outcome = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, rx.recv()).await {
                Ok(Some(msg)) => {
                    if let Some(a) = answer_to(&msg, ack) {
                        break Ok(a);
                    }
                    if let ServerToClient::Rejected { reason } = msg {
                        break Err(format!("rejected: {reason}"));
                    }
                }
                Ok(None) => break Err("connection closed".to_string()),
                Err(_) => break Err("no answer".to_string()),
            }
        };
        sig.cancel();
        outcome
    }
}

impl AckChannel for SignalingAckChannel {
    fn agent_removed(&mut self) {
        self.agent_gone = true;
    }

    fn deliver(&mut self, ack: &SignedAck) -> AckDelivery {
        if failed_ack_suppressed(self.agent_gone, self.result_durable) && ack.to == state::FAILED {
            return AckDelivery::Delivered; // carried by the durable result file; see the type docs
        }
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(_) => return AckDelivery::Undeliverable,
        };
        let deadline = Instant::now() + self.budget;
        let mut wait = Duration::from_secs(2);
        loop {
            match rt.block_on(self.attempt(ack)) {
                Ok(AckAnswer::Applied) => return AckDelivery::Delivered,
                Ok(AckAnswer::Refused) => return AckDelivery::Refused,
                Ok(AckAnswer::Unavailable) | Err(_) => {}
            }
            if Instant::now() + wait >= deadline {
                return AckDelivery::Undeliverable;
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(Duration::from_secs(60));
        }
    }
}

/// Build the process-wide directive hub (docs/65), or `None` with the reason logged. Directives are enabled ONLY when ALL of: a
/// usable, DEDICATED directive key is pinned ([`crate::directive_pin::pinned`]); the agent is enrolled (device id, tenant id and
/// identity key present); and the anchored record store opens. Any one missing and the agent refuses every directive and does
/// not advertise `directive_v1`. The hub is created here and its pump (which is also the crash-resume) is started by the
/// caller on its runtime.
pub fn build_hub(
    cfg: &crate::config::HelperConfig,
    identity: Option<Identity>,
    signaling_url: &str,
) -> Option<std::sync::Arc<crate::directive_hub::DirectiveHub>> {
    use crate::directive::{AnchorStore, Engine, EngineContext};
    let Some(pinned) = crate::directive_pin::pinned(cfg) else {
        tracing::info!("directives disabled: no usable dedicated directive key is pinned");
        return None;
    };
    let (Some(identity), Some(device_id), Some(tenant_id)) = (
        identity,
        cfg.device_id.clone().filter(|s| !s.trim().is_empty()),
        cfg.tenant_id.clone().filter(|s| !s.trim().is_empty()),
    ) else {
        tracing::info!("directives disabled: the agent is not fully enrolled (identity key, device id, tenant id)");
        return None;
    };
    let key_fp = rmt_protocol::directive::key_fingerprint(&identity.public_hex())?;
    let store = match Anchor::open().and_then(|a| AnchorStore::open(&a)) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "directives disabled: the directive record store could not be opened");
            return None;
        }
    };
    let engine = Engine::new(
        EngineContext {
            device_id,
            tenant_id,
            key_fp,
            pinned_key: Some(pinned),
            signaling_url: signaling_url.to_owned(),
            control_plane_url: cfg.control_plane_url.clone().unwrap_or_default(),
        },
        identity,
        Box::new(store),
        Box::new(WinActuator::new()),
    );
    let hub = crate::directive_hub::DirectiveHub::new(engine);
    crate::directive_hub::set_global(hub.clone());
    tracing::info!("directives enabled: directive key pinned, record store open");
    Some(hub)
}

// ---------------------------------------------------------------------------------------------------
// The FINAL ack over HTTPS (docs/65 section 2b)
// ---------------------------------------------------------------------------------------------------

/// The control plane's answer to `POST /agent/directives/{id}/final-ack`, as the helper acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalAckVerdict {
    /// 200 `{"outcome":"applied"|"replay"}`: the ONLY confirmation.
    Confirmed,
    /// 409 (and a 400): the control plane will not take this result. Terminal, NOT confirmed.
    Refused,
    /// 404: every pre-authentication failure looks like this. Not confirmed; the caller retries a few times, then gives up.
    NotFound,
    /// 410: the control plane's window for the result has passed. Terminal, not confirmed.
    Gone,
    /// 429: wait `Retry-After` (clamped) and try again.
    Throttled(Duration),
    /// 5xx, any other status, or a 200 that is not a clear `applied`/`replay`: retry with backoff. Never a confirmation.
    Transient,
}

/// Map an HTTP answer to a verdict. PURE. Confirmation is exactly a 200 whose body says `applied` or `replay`.
pub fn classify_final_ack_response(status: u16, retry_after: Option<&str>, body: &str) -> FinalAckVerdict {
    match status {
        200 => {
            let outcome = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("outcome").and_then(|o| o.as_str().map(str::to_owned)));
            match outcome.as_deref() {
                Some("applied") | Some("replay") => FinalAckVerdict::Confirmed,
                _ => FinalAckVerdict::Transient,
            }
        }
        409 | 400 => FinalAckVerdict::Refused,
        404 => FinalAckVerdict::NotFound,
        410 => FinalAckVerdict::Gone,
        429 => {
            let secs = retry_after.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(60).clamp(1, 300);
            FinalAckVerdict::Throttled(Duration::from_secs(secs))
        }
        _ => FinalAckVerdict::Transient,
    }
}

/// `{origin}/agent/directives/{id}/final-ack`, with the origin validated exactly as enrollment validates it (HTTPS, loopback http
/// only for development) and the id required to be a canonical UUID.
pub fn final_ack_url(origin: &str, directive_id: &str) -> Result<String, String> {
    crate::enroll::validate_control_plane_url(origin)?;
    let id = uuid::Uuid::parse_str(directive_id).map_err(|_| "directive id is not a UUID".to_string())?;
    Ok(format!("{}/agent/directives/{}/final-ack", origin.trim().trim_end_matches('/'), id.hyphenated()))
}

/// The exact JSON body of a final ack: `from`, `to`, `ts_ms`, `detail`, `sig`, and NOTHING else (no device or tenant id: the
/// control plane rejects unknown fields and derives everything from the signed row).
pub fn final_ack_body(ack: &SignedAck) -> String {
    serde_json::json!({
        "from": ack.from,
        "to": ack.to,
        "ts_ms": ack.ts_ms,
        "detail": ack.detail,
        "sig": ack.sig,
    })
    .to_string()
}

/// Delivers the helper's FINAL ack (`complete`, or the post-MSI `failed`) to the control plane over plain HTTPS: no registration, no
/// device id. The caller persists the exact ack before the first call and passes the SAME ack on every retry.
pub struct FinalAckHttp {
    pub origin: String,
    /// Total patience for one `deliver_final` call.
    pub budget: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// First backoff after a transient failure (doubles, capped at 60 s).
    pub backoff: Duration,
}

/// The most of a final-ack response body the helper will read (a real answer is a few dozen bytes).
const MAX_FINAL_ACK_RESPONSE_BYTES: usize = 4096;

/// Read at most `max` bytes of `r`: `max` + 1 are pulled so an oversized body is DETECTED and is an error, never silently truncated into
/// something that parses. A read error is an error too.
fn read_limited(r: impl io::Read, max: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(r, max as u64 + 1), &mut buf).map_err(|e| format!("reading the response: {e}"))?;
    if buf.len() > max {
        return Err(format!("the response body exceeds {max} bytes"));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

impl FinalAckHttp {
    pub fn new(origin: String) -> Self {
        Self { origin, budget: Duration::from_secs(120), timeout: Duration::from_secs(20), backoff: Duration::from_secs(2) }
    }

    fn client(&self) -> Result<reqwest::blocking::Client, String> {
        // The same trust configuration as every other agent call to the control plane (OS store UNION bundled roots).
        reqwest::blocking::Client::builder()
            .use_preconfigured_tls(rmt_transport_webrtc::tls_trust::client_config()?)
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("http client: {e}"))
    }

    /// One request. `Err` is a transport failure (retried).
    fn post_once(&self, client: &reqwest::blocking::Client, url: &str, body: &str) -> Result<(u16, Option<String>, String), String> {
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let retry_after = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_owned);
        // Read THROUGH a byte limit: a hostile or faulty endpoint must not be able to make this SYSTEM process allocate its whole body
        // (the request timeout bounds time, not bytes). No decompression feature is enabled, so these are the wire bytes.
        Ok((status, retry_after, read_limited(resp, MAX_FINAL_ACK_RESPONSE_BYTES)?))
    }

    /// Send `ack` until the control plane answers terminally or the budget is spent. Only a 200 `applied`/`replay` is `Delivered`.
    pub fn deliver_final(&self, ack: &SignedAck) -> AckDelivery {
        let Ok(url) = final_ack_url(&self.origin, &ack.directive_id) else { return AckDelivery::Undeliverable };
        let Ok(client) = self.client() else { return AckDelivery::Undeliverable };
        let body = final_ack_body(ack);
        let deadline = Instant::now() + self.budget;
        let mut wait = self.backoff;
        loop {
            let verdict = match self.post_once(&client, &url, &body) {
                Ok((status, retry_after, text)) => classify_final_ack_response(status, retry_after.as_deref(), &text),
                Err(_) => FinalAckVerdict::Transient,
            };
            let pause = match verdict {
                FinalAckVerdict::Confirmed => return AckDelivery::Delivered,
                FinalAckVerdict::Refused => return AckDelivery::Refused,
                FinalAckVerdict::NotFound => return AckDelivery::NotFound,
                FinalAckVerdict::Gone => return AckDelivery::Gone,
                FinalAckVerdict::Throttled(d) => d,
                FinalAckVerdict::Transient => {
                    let w = wait;
                    wait = (wait * 2).min(Duration::from_secs(60));
                    w
                }
            };
            if Instant::now() + pause >= deadline {
                return AckDelivery::Undeliverable;
            }
            std::thread::sleep(pause);
        }
    }
}

/// The helper's channel: the FINAL ack (`complete`, or the post-MSI `failed`) goes over the final-ack HTTPS route, because a removed
/// device cannot register; the interim `reboot_pending` ack (the device is still registered then) stays on signaling.
pub struct HelperAckChannel {
    pub signaling: SignalingAckChannel,
    pub http: FinalAckHttp,
}

impl AckChannel for HelperAckChannel {
    fn deliver(&mut self, ack: &SignedAck) -> AckDelivery {
        let is_final = ack.to == state::COMPLETE || ack.to == state::FAILED;
        if !is_final {
            return self.signaling.deliver(ack);
        }
        if ack.to == state::FAILED && failed_ack_suppressed(self.signaling.agent_gone, self.signaling.result_durable) {
            return AckDelivery::Delivered; // the surviving agent reports it from the durable result file
        }
        self.http.deliver_final(ack)
    }

    fn agent_removed(&mut self) {
        self.signaling.agent_gone = true;
    }
}

// ---------------------------------------------------------------------------------------------------
// The helper's entry point (`agent_host.exe directive-removal <handoff.json>`)
// ---------------------------------------------------------------------------------------------------

fn log_line(dir: &anchor::Dir, line: &str) {
    // Best effort, bounded: append by rewriting a small file (the helper is short-lived).
    let mut text = dir.read(HELPER_LOG, 64 * 1024).ok().flatten().unwrap_or_default();
    text.extend_from_slice(format!("{} {line}\n", crate::update_files::now_ms()).as_bytes());
    text.truncate(64 * 1024);
    let _ = dir.write_atomic(HELPER_LOG, &text);
}

/// What the engine (when it is still alive to read the result file) should learn. `None` for a deferral: nothing final yet.
fn outcome_of(r: &RemovalResult) -> Option<RemovalOutcome> {
    Some(match r {
        RemovalResult::Complete { .. } => RemovalOutcome::Complete,
        RemovalResult::RebootPending => RemovalOutcome::RebootPending,
        RemovalResult::Failed(why) => RemovalOutcome::Failed(why.clone()),
        RemovalResult::Unreported => RemovalOutcome::Failed("the removal finished but its final report was never confirmed".into()),
        RemovalResult::Deferred { .. } => return None,
    })
}

/// Entry point of the copied helper. Requires LocalSystem and a handoff living next to this very image in the directory the
/// directive id names, so it cannot be steered at an arbitrary handoff file.
pub fn removal_command(args: &[String]) -> i32 {
    use windows::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
    if !crate::update_worker::is_local_system() || !(args.len() == 3 || args.len() == 4) {
        return 13;
    }
    unsafe {
        if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32).is_err() {
            return 13;
        }
    }
    let Ok(exe) = std::env::current_exe() else { return 13 };
    let Some(dir_path) = exe.parent().map(Path::to_path_buf) else { return 13 };
    let Ok(anchor) = Anchor::open_at(&dir_path) else { return 13 };
    let dir = anchor.dir();
    // The handoff must be the one beside this image, and this image must live in <SystemRoot>\Temp\DeskRallyRemoval-<id>.
    let expected_handoff = dir_path.join(HANDOFF_FILE);
    if !args[2].eq_ignore_ascii_case(&expected_handoff.to_string_lossy())
        || dir_path.parent().map(|p| p.to_string_lossy().to_ascii_lowercase()) != Some(system_temp().to_string_lossy().to_ascii_lowercase())
        || exe.file_name().map(|n| n.to_string_lossy().eq_ignore_ascii_case(HELPER_EXE)) != Some(true)
    {
        return 13;
    }
    // The STABLE lock (a sibling of the directory, so it outlives a rebuild of it): taken BEFORE the handoff is read and held for the whole
    // run. Recovery rebuilds the directory only when it can take this same lock, which proves no helper is alive.
    let Some(dir_name) = dir_path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else { return 13 };
    let Ok(_stable_lock) = open_helper_lock(&dir_name) else { return 0 };
    // GENERATION: the lock was just taken, so recovery cannot be writing the generation now. A helper that was suspended before it got
    // here and has since been superseded by a rebuild finds a newer generation and exits having touched nothing. A launch with no
    // generation argument (the restart task) is the current one.
    let own_generation = match args.get(3) {
        Some(a) => match a.parse::<u64>() {
            Ok(g) => Some(g),
            Err(_) => return 13,
        },
        None => None,
    };
    match read_generation(&helper_gen_path(&dir_name)) {
        Ok(current) if generation_may_run(own_generation, current) => {}
        // Superseded, or the current generation cannot be established: act on nothing.
        _ => return 0,
    }
    // R2: ONE helper at a time (the restart task may fire while a previous run is still working).
    let Ok(_instance) = dir.open_exclusive(HELPER_LOCK) else { return 0 };
    let handoff_bytes = match dir.read(HANDOFF_FILE, MAX_HANDOFF_BYTES) {
        Ok(Some(b)) => b,
        // The handoff is already gone (deleted before the task was): the task's FINISHED-ONLY entry point removes the leftovers from the
        // journal alone. The directive id comes from the directory name, validated.
        Ok(None) => {
            let Some(id) = dir_path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_prefix("DeskRallyRemoval-")) else { return 13 };
            if helper_dir_name(id).is_none() {
                return 13;
            }
            let mut ops = WinRemovalOps::for_directive(dir_path.clone(), id);
            let journal = DirJournal { dir };
            let r = removal::run_leftovers_only(&mut ops, &journal);
            log_line(dir, &format!("removal helper (finished-only): {r:?}"));
            return r.exit_code();
        }
        Err(_) => return 13,
    };
    let Ok(h) = serde_json::from_slice::<HelperHandoff>(&handoff_bytes) else { return 13 };
    if helper_dir_name(&h.base.directive_id).as_deref() != dir_path.file_name().and_then(|n| n.to_str()) {
        return 13;
    }
    if let Ok(id) = runner::own_identity() {
        if let Ok(b) = serde_json::to_vec(&HelperStatus { pid: id.pid, creation_time: id.creation_time }) {
            let _ = dir.write_atomic(STATUS_FILE, &b);
        }
    }
    log_line(dir, &format!("removal helper started for directive {}", h.base.directive_id));
    let Ok(seed) = hex::decode(&h.base.identity_seed_hex).map(<[u8; 32]>::try_from) else { return 13 };
    let Ok(seed) = seed else { return 13 };
    let Ok(device) = uuid::Uuid::parse_str(&h.base.device_id) else { return 13 };
    let mut channel = HelperAckChannel {
        signaling: SignalingAckChannel {
            signaling_url: h.base.signaling_url.clone(),
            device,
            tenant: h.base.tenant_id.clone(),
            seed,
            budget: Duration::from_secs(120),
            agent_gone: false,
            result_durable: false,
        },
        http: FinalAckHttp::new(h.base.control_plane_url.clone()),
    };
    let mut ops = WinRemovalOps::for_directive(dir_path.clone(), &h.base.directive_id);
    let mut journal = DirJournal { dir };
    // Deferred work is retried in this process for a while (an unreachable control plane, a busy installer); a reboot wait ends it
    // and the restart task continues after the boot. Whatever is not final is picked up by that task: the journal says where.
    let started = Instant::now();
    let result = loop {
        let r = removal::run_removal(&h, &mut ops, &mut channel, &mut journal, &|| files::now_ms() as i64);
        log_line(dir, &format!("removal helper: {r:?}"));
        match &r {
            RemovalResult::Deferred { in_process: true, .. } if started.elapsed() < Duration::from_secs(30 * 60) => {
                std::thread::sleep(Duration::from_secs(60));
            }
            _ => break r,
        }
    };
    if let Some(outcome) = outcome_of(&result) {
        if let Ok(b) = serde_json::to_vec(&outcome) {
            let _ = dir.write_atomic(RESULT_FILE, &b);
        }
    }
    result.exit_code()
}

/// The helper's journal: `journal.json` in its own SYSTEM-only directory (outside the uninstall target), written atomically.
struct DirJournal<'a> {
    dir: &'a anchor::Dir,
}

impl removal::JournalStore for DirJournal<'_> {
    fn load(&self) -> io::Result<Option<removal::Journal>> {
        match self.dir.read(JOURNAL_FILE, 64 * 1024)? {
            None => Ok(None),
            Some(b) => serde_json::from_slice(&b).map(Some).map_err(|e| io::Error::other(format!("journal: {e}"))),
        }
    }
    fn save(&mut self, j: &removal::Journal) -> io::Result<()> {
        let b = serde_json::to_vec(j).map_err(io::Error::other)?;
        self.dir.write_atomic(JOURNAL_FILE, &b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_body_is_read_through_a_byte_limit() {
        struct Endless(std::rc::Rc<std::cell::Cell<usize>>);
        impl io::Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.set(self.0.get() + buf.len());
                buf.fill(b'x');
                Ok(buf.len())
            }
        }
        let pulled = std::rc::Rc::new(std::cell::Cell::new(0));
        assert!(read_limited(Endless(pulled.clone()), MAX_FINAL_ACK_RESPONSE_BYTES).is_err(), "an endless body is an error, not a truncation");
        assert!(pulled.get() <= MAX_FINAL_ACK_RESPONSE_BYTES + 8192, "pulled {} bytes from an endless body", pulled.get());
        assert_eq!(read_limited(&b"{\"outcome\":\"applied\"}"[..], 4096).unwrap(), "{\"outcome\":\"applied\"}");
        // Exactly the limit is fine; one byte more is an error.
        assert_eq!(read_limited(&vec![b'a'; 100][..], 100).unwrap().len(), 100);
        assert!(read_limited(&vec![b'a'; 101][..], 100).is_err());
    }

    // ---- release re-review A1: recovery rebuilds only under the stable helper lock ---------------------------------------

    use std::cell::Cell;

    const NOW: i64 = 1_800_000_000_000;

    /// A fake stable lock: `held` = a live helper owns it; counts how often recovery asked and whether its guard still lives.
    struct FakeLock {
        held: bool,
        err: bool,
        asked: Cell<u32>,
        guard_alive: std::rc::Rc<Cell<bool>>,
    }
    struct Guard(std::rc::Rc<Cell<bool>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }
    impl FakeLock {
        fn new(held: bool) -> Self {
            Self { held, err: false, asked: Cell::new(0), guard_alive: Default::default() }
        }
        fn try_lock(&self) -> io::Result<Option<Box<dyn std::any::Any>>> {
            self.asked.set(self.asked.get() + 1);
            if self.err {
                return Err(io::Error::other("cannot tell"));
            }
            if self.held {
                return Ok(None);
            }
            self.guard_alive.set(true);
            Ok(Some(Box::new(Guard(self.guard_alive.clone()))))
        }
    }

    fn decide(lock: &FakeLock, ev: &[Evidence], now: i64) -> Recovery {
        let i = Cell::new(0usize);
        let mut evidence = || {
            let e = ev[i.get().min(ev.len() - 1)];
            i.set(i.get() + 1);
            Ok(e)
        };
        decide_recovery(&mut || lock.try_lock(), &mut evidence, now).unwrap()
    }

    fn none() -> Evidence {
        Evidence { status_or_result: false, launch_marker_at_ms: None }
    }

    #[test]
    fn a_held_lock_means_no_wipe_however_old_the_launch_is() {
        let lock = FakeLock::new(true);
        // A spawned but suspended helper: marker 10 minutes old, no status yet, lock held (or about to be) by that process.
        let old = Evidence { status_or_result: false, launch_marker_at_ms: Some(NOW - 10 * 60_000) };
        assert!(matches!(decide(&lock, &[old], NOW), Recovery::Live));
        assert!(matches!(decide(&lock, &[none()], NOW), Recovery::Live), "no marker at all, still held");
        // A lock that cannot be examined is also never a licence to wipe.
        let mut broken = FakeLock::new(false);
        broken.err = true;
        assert!(matches!(decide(&broken, &[none()], NOW), Recovery::Live));
    }

    #[test]
    fn a_free_lock_with_no_status_and_no_recent_launch_rebuilds_and_holds_the_guard() {
        let lock = FakeLock::new(false);
        let r = decide(&lock, &[none()], NOW);
        assert!(matches!(r, Recovery::Rebuild(_)));
        assert!(lock.guard_alive.get(), "the lock stays held while the caller wipes and rebuilds");
        drop(r);
        assert!(!lock.guard_alive.get());
        // A stale marker (crash between the marker and the spawn) rebuilds too.
        let stale = Evidence { status_or_result: false, launch_marker_at_ms: Some(NOW - LAUNCH_GRACE_MS) };
        assert!(matches!(decide(&FakeLock::new(false), &[stale], NOW), Recovery::Rebuild(_)));
    }

    #[test]
    fn evidence_is_rechecked_under_the_lock_and_a_fresh_launch_is_given_time() {
        // The helper wrote its status between the first look and our taking the lock: it ran; do not wipe.
        let lock = FakeLock::new(false);
        let ran = Evidence { status_or_result: true, launch_marker_at_ms: None };
        assert!(matches!(decide(&lock, &[none(), ran], NOW), Recovery::Live));
        assert!(!lock.guard_alive.get(), "the guard is released again");
        // Status present from the start: the lock is not even asked for.
        let lock = FakeLock::new(false);
        assert!(matches!(decide(&lock, &[ran], NOW), Recovery::Live));
        assert_eq!(lock.asked.get(), 0);
        // Lock free but the process was spawned a second ago (may not have reached its lock): starting, no wipe.
        let fresh = Evidence { status_or_result: false, launch_marker_at_ms: Some(NOW - 1_000) };
        assert!(matches!(decide(&FakeLock::new(false), &[fresh], NOW), Recovery::Starting));
        let future = Evidence { status_or_result: false, launch_marker_at_ms: Some(NOW + 5_000) };
        assert!(matches!(decide(&FakeLock::new(false), &[future], NOW), Recovery::Starting), "a clock step back is not abandonment");
    }

    #[test]
    fn a_suspended_old_child_that_takes_the_lock_after_a_rebuild_exits_untouched_and_the_current_child_proceeds() {
        use std::os::windows::fs::OpenOptionsExt;
        let base = std::env::temp_dir().join(format!("rmt-gen-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();
        let (lock, gen) = (base.join("h.lock"), base.join("h.gen"));
        let open = || std::fs::OpenOptions::new().write(true).create(true).share_mode(0).open(&lock);
        // First launch (generation N = 1), under the lock; the spawned child is then SUSPENDED before it ever reaches its lock.
        let launch_guard = open().unwrap();
        let n = bump_generation(&gen).unwrap();
        assert_eq!(n, 1);
        drop(launch_guard);
        // Recovery (after the grace): takes the free lock, rebuilds, records generation N+1 DURABLY while still holding the lock, and only
        // then releases it for the replacement child.
        let recovery_guard = open().unwrap();
        let n1 = bump_generation(&gen).unwrap();
        assert_eq!(n1, 2);
        assert_eq!(read_generation(&gen).unwrap(), 2, "durable before the lock is released");
        drop(recovery_guard);
        // The OLD child wakes up and gets the (free) lock first: its generation is superseded, so it must act on nothing.
        let old_child_lock = open().unwrap();
        assert!(!generation_may_run(Some(n), read_generation(&gen).unwrap()), "superseded: exits untouched");
        drop(old_child_lock);
        // The CURRENT child proceeds; so does a restart-task launch (no generation argument).
        let cur = open().unwrap();
        assert!(generation_may_run(Some(n1), read_generation(&gen).unwrap()));
        assert!(generation_may_run(None, read_generation(&gen).unwrap()));
        drop(cur);
        // An unreadable generation file lets nobody act.
        std::fs::write(&gen, b"garbage").unwrap();
        assert!(read_generation(&gen).is_err());
        assert!(bump_generation(&gen).is_err(), "and nothing can be launched over it either");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_real_stable_lock_excludes_a_second_holder() {
        // A real file lock in a temp directory (not the SYSTEM profile): the same open options the helper and recovery use.
        use std::os::windows::fs::OpenOptionsExt;
        let p = std::env::temp_dir().join(format!("rmt-stable-lock-{}.lock", uuid::Uuid::new_v4()));
        let open = || std::fs::OpenOptions::new().write(true).create(true).share_mode(0).open(&p);
        let first = open().expect("the first holder gets it");
        assert!(open().is_err(), "a second holder is excluded while the first lives");
        drop(first);
        assert!(open().is_ok(), "free again once the holder is gone");
        let _ = std::fs::remove_file(&p);
    }


    #[test]
    fn the_helper_directory_name_comes_only_from_a_canonical_directive_id() {
        let id = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
        assert_eq!(helper_dir_name(id).as_deref(), Some("DeskRallyRemoval-bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"));
        for bad in ["", "..\\..\\x", "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF", "bbbbbbbbcccc4ddd8eeeffffffffffff", "x/../y", "{bbbbbbbb-cccc-4ddd-8eee-ffffffffffff}"] {
            assert_eq!(helper_dir_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_ack_message_carries_exactly_the_signed_fields() {
        let ack = SignedAck {
            directive_id: "d".into(),
            from: "executing".into(),
            to: "complete".into(),
            ts_ms: 9,
            detail: "removed".into(),
            sig: "ab".into(),
        };
        assert_eq!(
            serde_json::to_string(&ack_message(&ack)).unwrap(),
            r#"{"type":"directive_ack","directive_id":"d","from":"executing","to":"complete","ts_ms":9,"detail":"removed","sig":"ab"}"#
        );
    }

    #[test]
    fn answers_are_matched_to_exactly_the_ack_sent_and_mapped() {
        let sent = SignedAck { directive_id: "d".into(), from: "executing".into(), to: "complete".into(), ts_ms: 50, detail: String::new(), sig: "s".into() };
        let r = |id: &str, o: &str, from: Option<&str>, to: Option<&str>, ts: Option<i64>| ServerToClient::DirectiveAckResult {
            directive_id: id.into(),
            outcome: o.into(),
            from: from.map(str::to_owned),
            to: to.map(str::to_owned),
            ts_ms: ts,
        };
        let ok = |o: &str| r("d", o, Some("executing"), Some("complete"), Some(50));
        assert_eq!(answer_to(&ok("applied"), &sent), Some(AckAnswer::Applied));
        assert_eq!(answer_to(&ok("replay"), &sent), Some(AckAnswer::Applied));
        assert_eq!(answer_to(&ok("refused"), &sent), Some(AckAnswer::Refused));
        assert_eq!(answer_to(&ok("unavailable"), &sent), Some(AckAnswer::Unavailable));
        assert_eq!(answer_to(&ok("???"), &sent), Some(AckAnswer::Unavailable), "an unknown answer is retried, never taken as success");
        // Unattributable or about another send: ignored, never a success.
        assert_eq!(answer_to(&r("d", "applied", None, None, None), &sent), None, "no echo");
        assert_eq!(answer_to(&r("d", "applied", Some("executing"), Some("complete"), Some(49)), &sent), None, "another send of the step");
        assert_eq!(answer_to(&r("d", "applied", Some("accepted"), Some("executing"), Some(50)), &sent), None, "another step");
        assert_eq!(answer_to(&r("other", "applied", Some("executing"), Some("complete"), Some(50)), &sent), None, "another directive");
        assert_eq!(answer_to(&ServerToClient::Directive { directive_id: "d".into(), artifact: "{}".into() }, &sent), None);
    }
    #[test]
    fn a_failure_ack_is_not_sent_over_a_second_registration() {
        // The surviving agent reports failures from the result file; registering the device again would displace its
        // live connection. (No network is touched: deliver() returns before any connection for a failed ack.)
        let mut ch = SignalingAckChannel {
            signaling_url: "wss://invalid.invalid/ws".into(),
            device: uuid::Uuid::nil(),
            tenant: "t".into(),
            seed: [1; 32],
            budget: Duration::from_millis(1),
            agent_gone: false,
            result_durable: true,
        };
        let ack = SignedAck { directive_id: "d".into(), from: "executing".into(), to: "failed".into(), ts_ms: 1, detail: "x".into(), sig: "s".into() };
        assert_eq!(ch.deliver(&ack), AckDelivery::Delivered);
    }

    #[test]
    fn every_outcome_the_helper_can_reach_maps_to_an_engine_outcome_and_never_to_a_false_complete() {
        assert_eq!(outcome_of(&RemovalResult::Complete { residue: None }), Some(RemovalOutcome::Complete));
        assert_eq!(outcome_of(&RemovalResult::RebootPending), Some(RemovalOutcome::RebootPending));
        assert!(matches!(outcome_of(&RemovalResult::Failed("x".into())), Some(RemovalOutcome::Failed(_))));
        assert!(matches!(outcome_of(&RemovalResult::Unreported), Some(RemovalOutcome::Failed(_))), "an unreported removal must not read as complete");
        assert_eq!(outcome_of(&RemovalResult::Deferred { reason: "x".into(), in_process: true }), None);
    }
}

#[cfg(test)]
mod location_tests {
    use super::*;

    #[test]
    fn the_helper_directory_lives_under_the_system_profile_not_a_world_writable_temp() {
        let p = system_temp().to_string_lossy().to_ascii_lowercase();
        assert!(p.ends_with(r"\system32\config\systemprofile\appdata\local"), "{p}");
        assert!(!p.ends_with(r"\temp"), "the helper must not live under a Users-writable Temp: {p}");
    }
}

#[cfg(test)]
mod final_ack_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const ID: &str = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

    fn ack() -> SignedAck {
        SignedAck { directive_id: ID.into(), from: "executing".into(), to: "complete".into(), ts_ms: 1_800_000_005_000, detail: "removed".into(), sig: "ab".repeat(64) }
    }

    type Seen = Arc<Mutex<Vec<(String, String, String)>>>; // (request line, content-type, body)

    /// A one-thread HTTP server over loopback: answers each connection with the next scripted response (status, extra header, body),
    /// then keeps repeating the LAST one. Records what it was sent. Never reaches a real control plane.
    fn server(script: Vec<(u16, &'static str, &'static str)>) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen: Seen = Arc::default();
        let s = seen.clone();
        std::thread::spawn(move || {
            let mut n = 0usize;
            for conn in listener.incoming() {
                let Ok(mut c) = conn else { break };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let (head_end, content_len) = loop {
                    let Ok(k) = c.read(&mut tmp) else { break (0, 0) };
                    if k == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&tmp[..k]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                        let cl = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
                        break (p + 4, cl);
                    }
                };
                while head_end > 0 && buf.len() < head_end + content_len {
                    let Ok(k) = c.read(&mut tmp) else { break };
                    if k == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..k]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]).to_string();
                let body = String::from_utf8_lossy(&buf[head_end.min(buf.len())..]).to_string();
                let ct = head.lines().find_map(|l| l.to_lowercase().strip_prefix("content-type:").map(|v| v.trim().to_owned())).unwrap_or_default();
                s.lock().unwrap().push((head.lines().next().unwrap_or("").to_owned(), ct, body));
                let (status, extra, resp_body) = script[n.min(script.len() - 1)];
                n += 1;
                let reply = format!("HTTP/1.1 {status} X\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}", resp_body.len());
                let _ = c.write_all(reply.as_bytes());
            }
        });
        (origin, seen)
    }

    fn http(origin: String) -> FinalAckHttp {
        FinalAckHttp { origin, budget: Duration::from_secs(3), timeout: Duration::from_secs(2), backoff: Duration::from_millis(30) }
    }

    // ---- the pure verdicts ----------------------------------------------------------------------------------------

    #[test]
    fn only_a_200_applied_or_replay_is_a_confirmation() {
        let c = |s, b| classify_final_ack_response(s, None, b);
        assert_eq!(c(200, r#"{"outcome":"applied","state":"complete"}"#), FinalAckVerdict::Confirmed);
        assert_eq!(c(200, r#"{"outcome":"replay","state":"complete"}"#), FinalAckVerdict::Confirmed);
        for not in [r#"{"outcome":"refused"}"#, r#"{"outcome":"unavailable"}"#, "{}", "", "not json", r#"{"state":"complete"}"#] {
            assert_eq!(c(200, not), FinalAckVerdict::Transient, "a 200 whose body is {not:?} is NOT a confirmation");
        }
        for s in [201u16, 202, 204, 301, 302, 401, 403, 408, 500, 502, 503, 504] {
            assert_ne!(c(s, r#"{"outcome":"applied"}"#), FinalAckVerdict::Confirmed, "status {s} must never confirm");
        }
        assert_eq!(c(409, r#"{"outcome":"refused","state":"complete"}"#), FinalAckVerdict::Refused);
        assert_eq!(c(400, "{}"), FinalAckVerdict::Refused);
        assert_eq!(c(404, r#"{"error":"unknown directive"}"#), FinalAckVerdict::NotFound);
        assert_eq!(c(410, "{}"), FinalAckVerdict::Gone);
        assert_eq!(c(500, ""), FinalAckVerdict::Transient);
        assert_eq!(classify_final_ack_response(429, Some("7"), ""), FinalAckVerdict::Throttled(Duration::from_secs(7)));
        assert_eq!(classify_final_ack_response(429, None, ""), FinalAckVerdict::Throttled(Duration::from_secs(60)));
        assert_eq!(classify_final_ack_response(429, Some("999999"), ""), FinalAckVerdict::Throttled(Duration::from_secs(300)), "clamped");
        assert_eq!(classify_final_ack_response(429, Some("0"), ""), FinalAckVerdict::Throttled(Duration::from_secs(1)));
    }

    #[test]
    fn the_url_and_body_have_exactly_the_documented_shape() {
        assert_eq!(final_ack_url("https://cp.example/", ID).unwrap(), format!("https://cp.example/agent/directives/{ID}/final-ack"));
        assert_eq!(final_ack_url("http://127.0.0.1:9", ID).unwrap(), format!("http://127.0.0.1:9/agent/directives/{ID}/final-ack"));
        assert!(final_ack_url("http://remote.example", ID).is_err(), "plaintext http only for loopback");
        assert!(final_ack_url("https://cp.example", "../x").is_err());
        let v: serde_json::Value = serde_json::from_str(&final_ack_body(&ack())).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["detail", "from", "sig", "to", "ts_ms"], "no device id, tenant id or directive id in the body");
        assert_eq!(v["ts_ms"], 1_800_000_005_000i64);
    }

    // ---- over a real HTTP exchange ----------------------------------------------------------------------------------

    #[test]
    fn a_200_applied_or_replay_is_delivered_and_the_request_is_exactly_the_documented_one() {
        for body in [r#"{"outcome":"applied","state":"complete"}"#, r#"{"outcome":"replay","state":"complete"}"#] {
            let (origin, seen) = server(vec![(200, "", body)]);
            assert_eq!(http(origin).deliver_final(&ack()), AckDelivery::Delivered, "{body}");
            let s = seen.lock().unwrap();
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].0, format!("POST /agent/directives/{ID}/final-ack HTTP/1.1"));
            assert!(s[0].1.starts_with("application/json"), "{}", s[0].1);
            assert_eq!(s[0].2, final_ack_body(&ack()));
        }
    }

    #[test]
    fn a_409_is_terminal_and_not_confirmed() {
        let (origin, seen) = server(vec![(409, "", r#"{"outcome":"refused","state":"executing","error":"stale"}"#)]);
        assert_eq!(http(origin).deliver_final(&ack()), AckDelivery::Refused);
        assert_eq!(seen.lock().unwrap().len(), 1, "terminal: not retried");
    }

    #[test]
    fn a_404_and_a_410_are_returned_at_once_for_the_journal_to_judge() {
        let (origin, seen) = server(vec![(404, "", r#"{"error":"unknown directive"}"#)]);
        assert_eq!(http(origin).deliver_final(&ack()), AckDelivery::NotFound);
        assert_eq!(seen.lock().unwrap().len(), 1);
        let (origin, seen) = server(vec![(410, "", r#"{"error":"window passed"}"#)]);
        assert_eq!(http(origin).deliver_final(&ack()), AckDelivery::Gone);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_429_honours_retry_after_then_a_5xx_is_retried_with_the_identical_ack() {
        let (origin, seen) = server(vec![
            (429, "Retry-After: 1\r\n", r#"{"error":"slow down"}"#),
            (503, "", "{}"),
            (200, "", r#"{"outcome":"applied","state":"complete"}"#),
        ]);
        let started = Instant::now();
        let mut h = http(origin);
        h.budget = Duration::from_secs(10);
        assert_eq!(h.deliver_final(&ack()), AckDelivery::Delivered);
        assert!(started.elapsed() >= Duration::from_millis(900), "Retry-After: 1 was honoured ({:?})", started.elapsed());
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|r| r.2 == s[0].2), "every retry carries the IDENTICAL body (the exact persisted ack)");
    }

    #[test]
    fn a_200_that_is_not_a_clear_confirmation_is_retried_and_never_delivered() {
        let (origin, seen) = server(vec![(200, "", r#"{"outcome":"refused"}"#)]);
        let mut h = http(origin);
        h.budget = Duration::from_millis(400);
        assert_eq!(h.deliver_final(&ack()), AckDelivery::Undeliverable);
        assert!(seen.lock().unwrap().len() >= 2, "retried");
    }

    #[test]
    fn a_network_failure_ends_undeliverable_within_the_budget() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        drop(l); // nothing listens
        let mut h = http(origin);
        h.budget = Duration::from_millis(500);
        let t = Instant::now();
        assert_eq!(h.deliver_final(&ack()), AckDelivery::Undeliverable);
        assert!(t.elapsed() < Duration::from_secs(60), "a refused connection must end at the budget, not retry forever");
    }

    #[test]
    fn the_channel_routes_final_acks_over_https_and_the_interim_one_over_signaling() {
        let (origin, seen) = server(vec![(200, "", r#"{"outcome":"applied","state":"complete"}"#)]);
        let mut ch = HelperAckChannel {
            signaling: SignalingAckChannel {
                signaling_url: "wss://invalid.invalid/ws".into(),
                device: uuid::Uuid::nil(),
                tenant: "t".into(),
                seed: [1; 32],
                budget: Duration::from_millis(1),
                agent_gone: false,
                result_durable: false,
            },
            http: http(origin),
        };
        ch.agent_removed();
        assert_eq!(ch.deliver(&ack()), AckDelivery::Delivered);
        assert_eq!(seen.lock().unwrap().len(), 1, "complete went to the final-ack route");
        let mut failed = ack();
        failed.to = "failed".into();
        assert_eq!(ch.deliver(&failed), AckDelivery::Delivered, "the post-MSI failed ack goes there too");
        assert_eq!(seen.lock().unwrap().len(), 2);
        // The interim ack does NOT touch the HTTP route (no registration is possible here, so it is simply undeliverable).
        let mut interim = ack();
        interim.to = "reboot_pending".into();
        assert_eq!(ch.deliver(&interim), AckDelivery::Undeliverable);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}

#[cfg(test)]
mod task_removal_tests {
    use super::*;
    use std::cell::Cell;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmt-tasks-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join("DeskRally")).unwrap();
        d
    }

    #[test]
    fn task_presence_distinguishes_not_found_from_every_other_failure() {
        let root = dir("presence");
        std::fs::write(root.join("DeskRally").join("RemovalResume-x"), b"<Task/>").unwrap();
        assert_eq!(task_presence(&root, r"\DeskRally\RemovalResume-x"), Ok(true));
        assert_eq!(task_presence(&root, r"\DeskRally\RemovalResume-missing"), Ok(false), "NotFound is the ONLY absent");
        assert_eq!(task_presence(&root.join("no-such-tasks-root"), r"\DeskRally\x"), Ok(false));
        // A path that cannot be examined (a file where a directory is expected) is an ERROR, not "absent".
        std::fs::write(root.join("notadir"), b"x").unwrap();
        assert!(task_presence(&root, r"\notadir\x").is_err() || task_presence(&root, r"\notadir\x") == Ok(false));
        // A failure that is NOT "not found" (here: an invalid file name, os error 123) must propagate, never read as "absent".
        assert!(task_presence(&root, r"\DeskRally\bad*name").is_err(), "an unexaminable path is an error");
        for bad in ["", r"\",r"\..\x", r"\DeskRally\..\..\x", r"\a:\b"] {
            assert!(task_presence(&root, bad).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removal_propagates_a_presence_error_a_delete_error_and_verifies_the_task_is_gone() {
        // Absent: success, no delete attempted.
        let deleted = Cell::new(0);
        assert_eq!(remove_task_checked(&|| Ok(false), &|| { deleted.set(deleted.get() + 1); Ok(()) }), Ok(()));
        assert_eq!(deleted.get(), 0);
        // Presence cannot be determined: an error, nothing deleted (an unsuccessful query is NOT "absent").
        assert_eq!(remove_task_checked(&|| Err("access denied".into()), &|| { deleted.set(1); Ok(()) }), Err("access denied".into()));
        assert_eq!(deleted.get(), 0);
        // Present and the delete fails.
        assert_eq!(remove_task_checked(&|| Ok(true), &|| Err("schtasks /Delete exited Some(1)".into())), Err("schtasks /Delete exited Some(1)".into()));
        // Present, delete "succeeds" but the task is still there: an error.
        let calls = Cell::new(0);
        let r = remove_task_checked(&|| { calls.set(calls.get() + 1); Ok(true) }, &|| Ok(()));
        assert!(matches!(&r, Err(e) if e.contains("still registered")), "{r:?}");
        assert_eq!(calls.get(), 2, "presence is checked again after the delete");
        // Present, delete succeeds, task gone afterwards.
        let state = Cell::new(true);
        assert_eq!(remove_task_checked(&|| Ok(state.get()), &|| { state.set(false); Ok(()) }), Ok(()));
        // The verification itself failing is an error too.
        let n = Cell::new(0);
        let r = remove_task_checked(&|| { n.set(n.get() + 1); if n.get() == 1 { Ok(true) } else { Err("cannot tell".into()) } }, &|| Ok(()));
        assert_eq!(r, Err("cannot tell".into()));
    }
}
