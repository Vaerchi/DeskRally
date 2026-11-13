//! Idle barrier for the automatic updater: a per-session shared file handle that blocks the
//! updater worker's exclusive open while any brokered session is live.
//!
//! ## Protocol
//!
//! * Each installed brokered session calls [`SessionFileGuard::open_for_installed_session`] BEFORE
//!   transport startup.  The returned guard holds a `FILE_SHARE_READ`-only handle on
//!   [`UPDATE_SESSION_LOCK_FILE`] for the session's lifetime.  `FILE_SHARE_DELETE` is
//!   intentionally absent: attempting to rename or delete the lock file while any guard is held
//!   will fail with a sharing violation, preventing lock-bypass attacks.
//!
//! * The updater worker opens the same file exclusively, relative to the trusted anchor
//!   (`crate::update_worker`, `crate::anchor::Dir::open_exclusive`). An exclusive open
//!   (share_mode = 0) fails with `ERROR_SHARING_VIOLATION` (OS error 32) while any session guard
//!   is held.  After all guards drop the exclusive open succeeds.
//!
//! * Guard failure is **fail-closed**: the session task calls deregister and returns before
//!   attempting transport startup.  A missing or reparse-point lock file is therefore a hard
//!   block on session establishment, not a soft warning.
//!
//! The attempt-bound ack/heartbeat protocol of the auto-updater lives in `crate::update_helper`
//! (anchor-relative, design v5 R3 / v7 L2'); this module is only the idle barrier.

use std::fs;
use std::io;
use std::os::windows::io::OwnedHandle;
use std::path::Path;

/// Lock file: inside `C:\rmt-agent` (CONFIG_DIR), hardened by `harden_agent_root`.
pub const UPDATE_SESSION_LOCK_FILE: &str = r"C:\rmt-agent\update-session.lock";

/// `FILE_ATTRIBUTE_REPARSE_POINT` (Win32 0x400) — catches junctions, which `is_symlink()` misses.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

// ─── Session guard ────────────────────────────────────────────────────────────

/// Per-session idle barrier guard.
///
/// Holds a `FILE_SHARE_READ`-only handle on [`UPDATE_SESSION_LOCK_FILE`].  `FILE_SHARE_DELETE`
/// is absent: rename/delete of the lock file fails while any guard is live, which prevents
/// an attacker from sidestepping the barrier by renaming the file away.
///
/// `Send + Sync` because `OwnedHandle` is.  Drop (or let the owning task exit) to release.
pub struct SessionFileGuard {
    #[allow(dead_code)] // held for RAII — the OS closes the handle on drop
    handle: OwnedHandle,
}

impl SessionFileGuard {
    /// Opens a guard for an installed brokered session.
    ///
    /// Returns `Ok(None)` when `is_installed` is `false` so that test harnesses and the
    /// `stream`/`attend` subcommands are never affected.  In production `is_installed` comes from
    /// `MultiSessionOpts::recording_dir.is_some()`, which is `Some` only on the installed helper.
    ///
    /// On the installed path an `Err` is returned without fallback: the caller must fail closed
    /// (deregister the session from the mux, then return — never proceed to transport startup).
    pub fn open_for_installed_session(is_installed: bool) -> io::Result<Option<Self>> {
        if !is_installed {
            return Ok(None);
        }
        let path = Path::new(UPDATE_SESSION_LOCK_FILE);
        check_no_reparse_ancestors(path)?;
        let handle = open_shared_handle(path)?;
        Ok(Some(SessionFileGuard { handle }))
    }
}

// ─── Startup helper ───────────────────────────────────────────────────────────

/// Ensures [`UPDATE_SESSION_LOCK_FILE`] exists and is a plain regular file.
///
/// Called once at installed helper startup from `run_helper_stream`, after `harden_agent_root`
/// has already secured `C:\rmt-agent`.  The created file inherits the directory's
/// SYSTEM + Administrators ACL.
///
/// Steps:
/// 1. Ancestor reparse check on the lock path.
/// 2. `create_new` — succeeds only when the file is missing; avoids truncating an existing file.
/// 3. If the file already exists, validate via `symlink_metadata` that it is a plain regular
///    file and not a reparse point.  The existing file is never opened for write.
///
/// Returns `Err` on any reparse ancestor, unexpected IO error, or invalid existing file.
/// Failures are logged by the caller; the lock may remain absent, causing per-session guard
/// opens to fail (fail-closed for sessions).
pub fn ensure_session_lock_exists() -> io::Result<()> {
    ensure_lock_at(Path::new(UPDATE_SESSION_LOCK_FILE))
}

fn ensure_lock_at(path: &Path) -> io::Result<()> {
    check_no_reparse_ancestors(path)?;

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => {
            tracing::debug!("update_guard: created {UPDATE_SESSION_LOCK_FILE}");
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => { /* fall through to validate */ }
        Err(e) => return Err(e),
    }

    // File already exists — validate it without opening for write.
    use std::os::windows::fs::MetadataExt as _;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("session lock file is a reparse point: {}", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "session lock file is not a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

// ─── Exclusive guard (future updater) ────────────────────────────────────────

/// Error returned by [`try_exclusive_guard`].
#[derive(Debug)]
pub enum ExclusiveGuardError {
    /// One or more session guards are currently held — updater must wait.
    SessionsActive,
    /// IO error unrelated to a sharing violation.
    Io(io::Error),
}

impl std::fmt::Display for ExclusiveGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionsActive => write!(f, "active sessions hold the update idle barrier"),
            Self::Io(e) => write!(f, "io error acquiring exclusive update guard: {e}"),
        }
    }
}

/// An exclusive handle on [`UPDATE_SESSION_LOCK_FILE`], held by the updater worker while no
/// session guards are live.  Drop to release.
pub struct ExclusiveGuard {
    #[allow(dead_code)]
    handle: OwnedHandle,
}

/// Attempts to acquire an exclusive handle on the session lock file.
///
/// Performs an ancestor reparse check before opening.  Fails with
/// [`ExclusiveGuardError::SessionsActive`] (OS error 32) if any [`SessionFileGuard`] is
/// currently held.  Intended for the updater worker process only.
pub fn try_exclusive_guard() -> Result<ExclusiveGuard, ExclusiveGuardError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let path = Path::new(UPDATE_SESSION_LOCK_FILE);
    check_no_reparse_ancestors(path).map_err(ExclusiveGuardError::Io)?;
    match fs::OpenOptions::new().read(true).share_mode(0).open(path) {
        Ok(file) => Ok(ExclusiveGuard {
            handle: OwnedHandle::from(file),
        }),
        Err(e) if e.raw_os_error() == Some(32) => Err(ExclusiveGuardError::SessionsActive),
        Err(e) => Err(ExclusiveGuardError::Io(e)),
    }
}

// ─── Reparse ancestor check ───────────────────────────────────────────────────

/// Returns `Err` if any ancestor of `path` (up to the drive root) is a reparse point.
/// Uses `symlink_metadata` so that junctions — which `is_symlink()` misses on Windows — are
/// caught via the `FILE_ATTRIBUTE_REPARSE_POINT` flag.
pub fn check_no_reparse_ancestors(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(meta) => {
                if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "reparse point detected in path ancestry: {}",
                            current.display()
                        ),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => { /* not yet created; keep walking */ }
            Err(e) => return Err(e),
        }
        match current.parent() {
            Some(p) if p != current => current = p,
            _ => break,
        }
    }
    Ok(())
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Opens `path` with `FILE_SHARE_READ` only (no `FILE_SHARE_DELETE`).
///
/// Share mode semantics:
/// * Multiple concurrent shared readers coexist (concurrent session guards).
/// * Rename/delete of the path fails while any handle is open — prevents lock-bypass.
/// * An exclusive open (share_mode = 0) fails with OS error 32 while this handle is live.
fn open_shared_handle(path: &Path) -> io::Result<OwnedHandle> {
    use std::os::windows::fs::OpenOptionsExt as _;
    // FILE_SHARE_READ (0x1) only — no FILE_SHARE_DELETE.
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001)
        .open(path)?;
    Ok(OwnedHandle::from(file))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// ─── Idle release ─────────────────────────────────────────────────────────────
//
// A session left open with nobody at it used to block agent updates forever: one forgotten viewer
// tab held the barrier indefinitely. the operator's decision (2026-10-21): a session with no technician
// activity for 30 minutes stops blocking updates. Its barrier stands down and re-arms on the next
// activity. An update that starts in between restarts the agent and so ends that idle session
// (reported to the control plane as a service stop, docs/49).
//
// "Activity" is what a person at the viewer does: input, file transfer, chat, clipboard, backstage.
// NOT the control channel, which carries the viewer's automatic 10 s lease renewals and would keep
// every open tab "active" forever. A watch-only observer therefore counts as idle after 30 minutes;
// that is the accepted trade.

/// No technician activity for this long and the session stops blocking updates.
pub const SESSION_IDLE_RELEASE: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How often a session checks its idle state (release, or re-arm after activity).
pub const SESSION_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// One session's activity clock. The session loop touches it; the idle barrier reads it.
pub struct SessionActivity {
    epoch: std::time::Instant,
    /// Milliseconds since `epoch` of the last activity.
    last_ms: std::sync::atomic::AtomicU64,
    /// Set while the session's barrier is stood down (idle). The first activity after that re-arms the
    /// barrier SYNCHRONOUSLY, before the activity is processed (see [`Self::touch`]).
    released: std::sync::atomic::AtomicBool,
    /// Re-arms the barrier now. Installed by [`IdleBarrier::link`]; holds only a WEAK reference to the
    /// barrier, since a strong one would be a cycle (barrier -> activity -> barrier) that kept the
    /// session's guard alive after the session ended: the leak 638a311 fixed, again.
    rearm: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl SessionActivity {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(SessionActivity {
            epoch: std::time::Instant::now(),
            last_ms: std::sync::atomic::AtomicU64::new(0),
            released: std::sync::atomic::AtomicBool::new(false),
            rearm: std::sync::OnceLock::new(),
        })
    }

    /// Record activity. If the barrier is stood down, re-take it NOW, on the caller's thread, before
    /// the caller goes on to process the activity: waiting for the next poll (up to 10 s) left a window
    /// where an update could take the lock and restart the agent under a technician who had just come
    /// back (Codex release review of 1.3.7). If an update ALREADY holds the lock, re-arming fails and
    /// the poll retries; that update began while the session was genuinely idle past the limit, which
    /// is the trade the operator chose.
    pub fn touch(&self) {
        let now = self.epoch.elapsed().as_millis() as u64;
        self.last_ms.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        if self.released.load(std::sync::atomic::Ordering::SeqCst) {
            if let Some(rearm) = self.rearm.get() {
                rearm();
            }
        }
    }

    pub fn idle_for(&self) -> std::time::Duration {
        let now = self.epoch.elapsed().as_millis() as u64;
        std::time::Duration::from_millis(now.saturating_sub(self.last_ms.load(std::sync::atomic::Ordering::SeqCst)))
    }

    /// Note a received frame: only technician-driven channels count (see the module note above).
    pub fn note_channel(&self, channel: rmt_protocol::ChannelId) {
        use rmt_protocol::ChannelId::*;
        if matches!(channel, Input | FileTransfer | Chat | Clipboard | Backstage) {
            self.touch();
        }
    }
}

/// What one [`IdleBarrier::poll`] did.
#[derive(Debug)]
pub enum IdlePoll {
    Unchanged,
    /// Idle past the limit: the barrier stood down.
    Released,
    /// Activity resumed: the barrier holds again.
    Rearmed,
    /// Activity resumed but the barrier could not be re-taken (an update is already running, or the
    /// lock file is suspect). Retried on the next poll.
    RearmFailed(io::Error),
}

/// One session's barrier that stands down after `idle` without activity and re-arms on activity.
/// Generic over the guard so the policy is testable without the real lock file.
pub struct IdleBarrier<G> {
    /// `None` while stood down. Never `Some` on a non-installed path (`installed == false`).
    guard: std::sync::Mutex<Option<G>>,
    installed: bool,
    reopen: Box<dyn Fn() -> io::Result<Option<G>> + Send + Sync>,
    activity: std::sync::Arc<SessionActivity>,
    idle: std::time::Duration,
    /// Test seam: runs inside a release, after the poll found the session idle and BEFORE it announces
    /// the release, which is the one interleaving the re-check exists for.
    #[cfg(test)]
    before_release: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl<G> IdleBarrier<G> {
    /// `initial` is the guard the session took at start; `None` means a non-installed path, where
    /// there is no barrier and the poll never does anything.
    pub fn new(
        initial: Option<G>,
        reopen: Box<dyn Fn() -> io::Result<Option<G>> + Send + Sync>,
        activity: std::sync::Arc<SessionActivity>,
        idle: std::time::Duration,
    ) -> Self {
        let installed = initial.is_some();
        IdleBarrier {
            guard: std::sync::Mutex::new(initial),
            installed,
            reopen,
            activity,
            idle,
            #[cfg(test)]
            before_release: std::sync::OnceLock::new(),
        }
    }

    pub fn poll(&self) -> IdlePoll {
        if !self.installed {
            return IdlePoll::Unchanged;
        }
        let mut g = self.guard.lock().unwrap();
        let idle = self.activity.idle_for() >= self.idle;
        match (g.is_some(), idle) {
            (true, true) => {
                #[cfg(test)]
                if let Some(hook) = self.before_release.get() {
                    hook();
                }
                // Announce the release BEFORE dropping the guard, then re-check: an activity racing this
                // poll either sees `released` (and re-arms as soon as this lock is free) or is seen here.
                // Both sides use SeqCst, so one of the two must observe the other.
                self.activity.released.store(true, std::sync::atomic::Ordering::SeqCst);
                if self.activity.idle_for() < self.idle {
                    self.activity.released.store(false, std::sync::atomic::Ordering::SeqCst);
                    return IdlePoll::Unchanged;
                }
                *g = None;
                IdlePoll::Released
            }
            (false, false) => self.rearm_locked(&mut g),
            _ => IdlePoll::Unchanged,
        }
    }

    /// Re-take a stood-down barrier now (the activity hook). A no-op while holding.
    pub fn rearm_now(&self) -> IdlePoll {
        if !self.installed {
            return IdlePoll::Unchanged;
        }
        let mut g = self.guard.lock().unwrap();
        if g.is_some() {
            return IdlePoll::Unchanged;
        }
        self.rearm_locked(&mut g)
    }

    fn rearm_locked(&self, g: &mut Option<G>) -> IdlePoll {
        match (self.reopen)() {
            Ok(Some(new)) => {
                *g = Some(new);
                self.activity.released.store(false, std::sync::atomic::Ordering::SeqCst);
                IdlePoll::Rearmed
            }
            Ok(None) => IdlePoll::RearmFailed(io::Error::other("the guard reopened as not installed")),
            Err(e) => IdlePoll::RearmFailed(e),
        }
    }

    /// Whether the barrier currently holds (for logs and tests).
    pub fn holding(&self) -> bool {
        self.guard.lock().unwrap().is_some()
    }
}

impl<G: Send + 'static> IdleBarrier<G> {
    /// Let the session's activity re-arm this barrier synchronously (see [`SessionActivity::touch`]).
    /// `on_rearm` reports the outcome (logging). The hook holds a `Weak`: once the session drops the
    /// barrier, the hook does nothing and the guard is freed.
    pub fn link(self: &std::sync::Arc<Self>, on_rearm: impl Fn(IdlePoll) + Send + Sync + 'static) {
        let weak = std::sync::Arc::downgrade(self);
        let _ = self.activity.rearm.set(Box::new(move || {
            if let Some(barrier) = weak.upgrade() {
                on_rearm(barrier.rearm_now());
            }
        }));
    }
}

#[cfg(test)]
mod idle_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A fake guard that counts how many are alive, so a release is observable.
    struct Fake(Arc<AtomicUsize>);
    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    fn fake(live: &Arc<AtomicUsize>) -> Fake {
        live.fetch_add(1, Ordering::SeqCst);
        Fake(live.clone())
    }

    #[test]
    fn idle_releases_and_activity_rearms() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let l2 = live.clone();
        let b = IdleBarrier::new(Some(fake(&live)), Box::new(move || Ok(Some(fake(&l2)))), act.clone(), Duration::from_millis(80));
        act.touch();
        assert!(matches!(b.poll(), IdlePoll::Unchanged), "fresh activity: still holding");
        assert_eq!(live.load(Ordering::SeqCst), 1);
        std::thread::sleep(Duration::from_millis(120));
        assert!(matches!(b.poll(), IdlePoll::Released));
        assert_eq!(live.load(Ordering::SeqCst), 0, "the guard really dropped (the lock handle closes)");
        assert!(matches!(b.poll(), IdlePoll::Unchanged), "stays released while idle");
        act.touch();
        assert!(matches!(b.poll(), IdlePoll::Rearmed));
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert!(b.holding());
    }

    #[test]
    fn a_failed_rearm_is_retried_and_never_holds_a_stale_guard() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (l2, f2) = (live.clone(), fail.clone());
        let b = IdleBarrier::new(
            Some(fake(&live)),
            Box::new(move || if f2.load(Ordering::SeqCst) { Err(io::Error::other("sharing violation")) } else { Ok(Some(fake(&l2))) }),
            act.clone(),
            Duration::from_millis(50),
        );
        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(b.poll(), IdlePoll::Released));
        act.touch();
        assert!(matches!(b.poll(), IdlePoll::RearmFailed(_)), "an update holds the lock: re-arm fails");
        assert!(!b.holding());
        fail.store(false, Ordering::SeqCst);
        assert!(matches!(b.poll(), IdlePoll::Rearmed), "retried on the next poll");
    }

    /// Codex 1.3.7 release review: activity after an idle release must re-take the barrier BEFORE the
    /// activity is processed, not at the next poll (an update could take the lock in that window).
    #[test]
    fn a_linked_barrier_rearms_synchronously_on_the_first_activity() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let l2 = live.clone();
        let b = Arc::new(IdleBarrier::new(Some(fake(&live)), Box::new(move || Ok(Some(fake(&l2)))), act.clone(), Duration::from_millis(50)));
        let rearms = Arc::new(AtomicUsize::new(0));
        let r2 = rearms.clone();
        b.link(move |r| if matches!(r, IdlePoll::Rearmed) { r2.fetch_add(1, Ordering::SeqCst); });
        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(b.poll(), IdlePoll::Released));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        // The technician comes back: touch() alone (NO poll) must hold the barrier again.
        act.touch();
        assert!(b.holding(), "re-armed by the activity itself, before any poll");
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert_eq!(rearms.load(Ordering::SeqCst), 1);
        // Further activity while holding does not reopen the lock.
        act.touch();
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert_eq!(rearms.load(Ordering::SeqCst), 1);
    }

    /// If an update already holds the lock, the synchronous re-arm fails and the poll retries.
    #[test]
    fn a_synchronous_rearm_that_fails_is_retried_by_the_poll() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (l2, f2) = (live.clone(), fail.clone());
        let b = Arc::new(IdleBarrier::new(
            Some(fake(&live)),
            Box::new(move || if f2.load(Ordering::SeqCst) { Err(io::Error::other("sharing violation")) } else { Ok(Some(fake(&l2))) }),
            act.clone(),
            Duration::from_millis(50),
        ));
        let failures = Arc::new(AtomicUsize::new(0));
        let f3 = failures.clone();
        b.link(move |r| if matches!(r, IdlePoll::RearmFailed(_)) { f3.fetch_add(1, Ordering::SeqCst); });
        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(b.poll(), IdlePoll::Released));
        act.touch();
        assert!(!b.holding());
        assert_eq!(failures.load(Ordering::SeqCst), 1, "the failure is reported");
        fail.store(false, Ordering::SeqCst);
        assert!(matches!(b.poll(), IdlePoll::Rearmed), "the poll retries while activity is recent");
    }

    /// The hook holds a Weak: dropping the session's barrier frees its guard even though the activity
    /// clock (still referenced by the session loop) carries the hook. A strong reference would be a
    /// cycle that kept the update lock held after the session ended.
    #[test]
    fn the_link_never_keeps_the_barrier_or_its_guard_alive() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let l2 = live.clone();
        let b = Arc::new(IdleBarrier::new(Some(fake(&live)), Box::new(move || Ok(Some(fake(&l2)))), act.clone(), Duration::from_secs(3600)));
        b.link(|_| {});
        assert_eq!(live.load(Ordering::SeqCst), 1);
        drop(b);
        assert_eq!(live.load(Ordering::SeqCst), 0, "the guard is released with the barrier");
        act.touch(); // the hook finds no barrier and does nothing
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// An activity that lands while a poll is deciding to release must not be lost. Deterministic: the
    /// test seam runs the activity at exactly the dangerous point (the poll already judged the session
    /// idle; it has not yet announced the release). The re-check must see it and keep holding. (A
    /// two-thread hammer could not hit this window, so a mutant without the re-check survived it.)
    #[test]
    fn activity_racing_a_release_is_never_lost() {
        let live = Arc::new(AtomicUsize::new(0));
        let act = SessionActivity::new();
        let l2 = live.clone();
        let b = Arc::new(IdleBarrier::new(Some(fake(&live)), Box::new(move || Ok(Some(fake(&l2)))), act.clone(), Duration::from_millis(50)));
        b.link(|_| {});
        let a2 = act.clone();
        let _ = b.before_release.set(Box::new(move || a2.touch()));
        std::thread::sleep(Duration::from_millis(80));
        assert!(matches!(b.poll(), IdlePoll::Unchanged), "the racing activity is seen: no release");
        assert!(b.holding(), "the barrier still holds after an activity that raced the release");
        assert_eq!(live.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_non_installed_session_has_no_barrier_to_release_or_rearm() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let b: IdleBarrier<Fake> = IdleBarrier::new(None, Box::new(move || { c2.fetch_add(1, Ordering::SeqCst); Ok(None) }), SessionActivity::new(), Duration::ZERO);
        assert!(matches!(b.poll(), IdlePoll::Unchanged));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "never tries to open a lock off the installed path");
    }

    #[test]
    fn only_technician_channels_count_as_activity() {
        use rmt_protocol::ChannelId;
        let act = SessionActivity::new();
        std::thread::sleep(Duration::from_millis(60));
        act.note_channel(ChannelId::Control); // lease renewals ride here
        assert!(act.idle_for() >= Duration::from_millis(50), "control traffic must not count");
        for ch in [ChannelId::Input, ChannelId::FileTransfer, ChannelId::Chat, ChannelId::Clipboard, ChannelId::Backstage] {
            std::thread::sleep(Duration::from_millis(30));
            act.note_channel(ch);
            assert!(act.idle_for() < Duration::from_millis(20), "{ch:?} must count");
        }
    }

    #[test]
    fn the_shipped_limit_is_thirty_minutes() {
        assert_eq!(SESSION_IDLE_RELEASE, Duration::from_secs(1800));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::os::windows::fs::OpenOptionsExt as _;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn unique_path(suffix: &str) -> std::path::PathBuf {
        // Use process-id + a per-call counter for uniqueness without pulling uuid into prod deps.
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!("rmt-guard-{}-{}-{}", std::process::id(), n, suffix))
    }

    fn make_lock(path: &std::path::Path) {
        fs::write(path, b"").expect("make_lock: create");
    }

    fn try_exclusive(path: &std::path::Path) -> bool {
        fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .is_ok()
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
    }

    // ── idle barrier tests ────────────────────────────────────────────────────

    #[test]
    fn two_shared_readers_block_exclusive() {
        let path = unique_path("two-shared.lock");
        make_lock(&path);

        let g1 = open_shared_handle(&path).expect("g1");
        let g2 = open_shared_handle(&path).expect("g2");

        assert!(
            !try_exclusive(&path),
            "exclusive must fail while two shared readers held"
        );

        drop(g1);
        // One guard dropped — other still holds.
        assert!(
            !try_exclusive(&path),
            "exclusive must still fail after dropping one of two guards"
        );

        drop(g2);
        assert!(
            try_exclusive(&path),
            "exclusive must succeed after all guards dropped"
        );
        cleanup(&path);
    }

    #[test]
    fn exclusive_blocks_new_shared_guard() {
        let path = unique_path("excl-blocks-shared.lock");
        make_lock(&path);

        let _ex = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("exclusive open");

        // Shared open must fail while exclusive is held.
        let r = open_shared_handle(&path);
        assert!(r.is_err(), "shared open must fail while exclusive held");
        assert_eq!(r.unwrap_err().raw_os_error(), Some(32));

        drop(_ex);
        cleanup(&path);
    }

    #[test]
    fn drop_guard_unblocks_exclusive() {
        let path = unique_path("drop-unblock.lock");
        make_lock(&path);

        let g = open_shared_handle(&path).expect("guard");
        assert!(!try_exclusive(&path));
        drop(g);
        assert!(try_exclusive(&path));
        cleanup(&path);
    }

    #[test]
    fn delete_lock_fails_while_shared_held() {
        // Proves FILE_SHARE_DELETE is absent: the OS rejects deletion while a reader holds the file.
        let path = unique_path("no-delete.lock");
        make_lock(&path);
        let _g = open_shared_handle(&path).expect("guard");
        let del_result = fs::remove_file(&path);
        assert!(
            del_result.is_err(),
            "delete must fail while FILE_SHARE_READ-only handle is held"
        );
        drop(_g);
        cleanup(&path);
    }

    #[test]
    fn rename_lock_fails_while_shared_held() {
        // Proves FILE_SHARE_DELETE is absent: rename requires FILE_SHARE_DELETE on the source.
        let path = unique_path("no-rename-src.lock");
        let dst = unique_path("no-rename-dst.lock");
        make_lock(&path);
        let _g = open_shared_handle(&path).expect("guard");
        let rename_result = fs::rename(&path, &dst);
        assert!(
            rename_result.is_err(),
            "rename must fail while FILE_SHARE_READ-only handle is held"
        );
        drop(_g);
        cleanup(&path);
        cleanup(&dst);
    }

    #[test]
    fn ensure_succeeds_while_guard_held() {
        // ensure_session_lock_exists validates via symlink_metadata (no write open), so an
        // existing file held open by a guard must still pass validation.
        let path = unique_path("ensure-while-held.lock");
        make_lock(&path);
        let _g = open_shared_handle(&path).expect("guard");

        ensure_lock_at(&path).expect("startup validation while a real session guard is held");

        drop(_g);
        cleanup(&path);
    }

    #[test]
    fn open_for_installed_session_returns_none_when_not_installed() {
        assert!(matches!(
            SessionFileGuard::open_for_installed_session(false),
            Ok(None)
        ));
    }

    #[test]
    fn reparse_check_passes_for_plain_dir() {
        // temp_dir is a plain directory with no reparse points on a standard Windows install.
        let path = env::temp_dir().join("rmt-reparse-check-probe.txt");
        assert!(check_no_reparse_ancestors(&path).is_ok());
    }
}
