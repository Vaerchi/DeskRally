//! The agent's `tracing` subscriber → the helper log (+ stderr).
//!
//! Until this module existed there was **no** `tracing_subscriber` anywhere in the workspace, so
//! every `tracing::info!/warn!/error!` in the agent crates was a silent no-op — including
//! `enroll`'s security-relevant *"plaintext http:// … development only"* warning, which no operator
//! had ever been shown (docs/07 loop 6 §2). The helper's only real log was `host::log_line`
//! (`println!` + append to `C:\rmt-agent\helper.log`). [`init`] installs a global subscriber that
//! writes tracing events to that SAME file, so the service-spawned SYSTEM helper — which has no
//! console — has one observable stream for both kinds of logging.
//!
//! Design constraints, all deliberate:
//!
//! * **One append per event; hold no handle.** Each event is buffered whole and written with a
//!   single `write_all` to a freshly opened append handle, which is then closed
//!   ([`EventWriter`]). The service and the helper are different *processes* appending to one
//!   file, and `tracing` emits an event in several `write` calls, so writing straight through
//!   would splice one process's line into the other's. No process holds a handle that would block
//!   inspection or rotation-by-deletion.
//! * **Logging can never fail the caller.** A file that cannot be opened (a non-elevated dev run
//!   against a SYSTEM-owned `C:\rmt-agent`) degrades to stderr-only; a stderr with no reader — or
//!   none at all — is swallowed. Every error in the write path is deliberately dropped.
//! * **stderr, not stdout.** The e2e tests parse this binary's stdout (`INJECTED …`,
//!   `CLIPBOARD-SET …`, `PROBE RESULT …`); tracing output must never interleave with that
//!   contract. stderr is also what makes `enroll`'s warnings visible to an interactive operator.
//!   (`install-agent.ps1` does **not** parse stdout — it reads the written `config.json` — so the
//!   installer is not part of that contract.)
//! * **`log`-crate records are NOT bridged** (the `tracing-log` feature is off in the workspace
//!   manifest): the webrtc/reqwest/tungstenite stacks log via the `log` crate at high volume and
//!   would swamp helper.log. This subscriber carries the workspace's own `tracing` events only.
//! * **INFO by default, `RMT_LOG` overrides** (`error|warn|info|debug|trace|off`). No call site in
//!   the workspace emits info-or-louder per FRAME or per input event — `debug!` is where that noise
//!   lives — so INFO does not scale with stream traffic. It is **not** silent on an idle agent: the
//!   reconnect loop re-registers roughly every 20s and logs one line each time (as `host::log_line`
//!   already did), which is what [`MAX_LOG_BYTES`] exists to bound.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The one helper log file. `host::log_line` appends here too — one file, two writers, both
/// append-per-line, so the two streams interleave rather than clobber each other.
pub const HELPER_LOG_FILE: &str = r"C:\rmt-agent\helper.log";

/// Environment override for the subscriber's max level (`error|warn|info|debug|trace|off`).
const LEVEL_ENV: &str = "RMT_LOG";
/// Environment override for the log FILE. Exists so an automated test can drive the real binary
/// against a temp path and assert the subscriber is actually installed (`tests/host_logging.rs`)
/// instead of writing into the machine-wide `C:\rmt-agent`, and so `stream_probe` and the CLI
/// subcommands can steer their own logs.
///
/// **The override is not unconditional, and this comment used to say it was.** The old justification
/// — that setting this on the installed SYSTEM service already needs admin rights, so honouring it
/// grants an attacker nothing new — is true of that service and FALSE of a GUI binary a member of the
/// public double-clicks in their own session, where setting an environment variable needs no
/// privilege at all. So the redirect is now a policy value ([`EnvRedirect`]) and is honoured only on
/// the [`init`] / [`init_at`] paths ([`EnvRedirect::Allowed`]). The public support client calls
/// [`init_at_pinned`] ([`EnvRedirect::Forbidden`]), which ignores this variable entirely.
const FILE_ENV: &str = "RMT_LOG_FILE";

/// Size at which the helper log is rotated. The agent re-registers roughly every 20s while idle,
/// and BOTH writers (this subscriber and `host::log_line`) emit a line per cycle, so an unattended
/// machine produces a few hundred KB a day — unbounded before this existed. One generation is
/// kept: a support engineer wants the recent past, not a year of it.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// Install the process-global subscriber writing to [`log_path`] (+ stderr). Idempotent: a
/// second call — or a host that already installed its own subscriber — is a silent no-op, never a
/// panic. Call once, first thing, from the binary entry point (`host::host_main`); library code and
/// tests must NOT call this (tests use `tracing::subscriber::with_default` with [`subscriber`]).
///
/// This is the AGENT's entry point, writing to [`HELPER_LOG_FILE`]. A controller-side tool that must
/// not write into the agent's machine-wide directory calls [`init_at`] instead.
pub fn init() {
    init_at(PathBuf::from(HELPER_LOG_FILE));
}

/// [`init`] with the DEFAULT log file chosen by the caller — for a binary that is not the agent.
///
/// `stream_probe` is the case this exists for. It is a CONTROLLER-side verification tool: it runs on
/// whatever machine the operator is driving from, as an ordinary user, so defaulting it into
/// `C:\rmt-agent\helper.log` would be wrong twice over — that directory belongs to the agent's
/// SYSTEM service (an unelevated operator often cannot write it, and the subscriber would silently
/// degrade to stderr-only), and interleaving a controller's events into the log of the machine it is
/// probing would make the agent's own timeline harder to read, not easier.
///
/// Only the DEFAULT moves. `RMT_LOG_FILE` still overrides it, so one variable redirects the log of
/// whichever binary is being run — which is what the tests here rely on.
pub fn init_at(default_file: PathBuf) {
    let _ = init_with(
        log_path_with_default(default_file).to_path_buf(),
        level_from_env(),
    );
}

/// [`init_at`] for a binary a member of the PUBLIC runs, where `RMT_LOG_FILE` must not aim the log.
///
/// Same first-caller-wins cell as [`init_at`], so this has to run before anything resolves the path
/// implicitly — at the very top of `main`, above even argument parsing.
///
/// See [`EnvRedirect::Forbidden`] for why the support client does not get the override that the
/// service, the probe and the CLI subcommands do.
pub fn init_at_pinned(file: PathBuf) {
    let _ = init_with(log_path_pinned(file).to_path_buf(), level_from_env());
}

/// A default log path for a controller-side TOOL: `%TEMP%\rmt-<tool>.log`.
///
/// The temp directory rather than a fixed path because this must be writable by an ordinary user on
/// a machine that may have no agent installed at all — the probe's whole job is to run from
/// somewhere else and point at an agent.
pub fn tool_log_path(tool: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rmt-{tool}.log"))
}

/// The one log path for this process, resolved once. `host::log_line` writes here too, so a run
/// that redirects the log with `RMT_LOG_FILE` gets **both** streams in the redirected file rather
/// than splitting them across two places.
pub(crate) fn log_path() -> &'static Path {
    log_path_with_default(PathBuf::from(HELPER_LOG_FILE))
}

/// [`log_path`] with the fallback supplied. **The FIRST caller in a process wins** — the resolved
/// path is cached, so a later call with a different default gets the first one. That is the point
/// rather than a limitation: `host::log_line` and the subscriber must never disagree about which
/// file they are appending to, and both reach the path through here. It is also why [`init`] /
/// [`init_at`] belong at the very top of `main`, before anything can resolve the path implicitly.
pub(crate) fn log_path_with_default(default_file: PathBuf) -> &'static Path {
    LOG_PATH.get_or_init(|| log_path_from_env(default_file))
}

/// The resolved path for this process. Hoisted out of [`log_path_with_default`] so
/// [`log_path_pinned`] can seed the SAME cell — two `OnceLock`s would let the subscriber and
/// `host::log_line` disagree about the file, which is the one thing this module exists to prevent.
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// May `RMT_LOG_FILE` move this process's log?
///
/// A policy, made an explicit value rather than an implicit branch, because the honest answer
/// depends on WHO runs the binary — and the previous answer was written when only one kind did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EnvRedirect {
    /// The installed service, `stream_probe`, and the CLI subcommands. The variable is how the
    /// tests and the probe steer their own logs, and setting it on the SYSTEM service already
    /// requires administrative rights, so it grants an attacker nothing they do not have.
    Allowed,
    /// A binary a MEMBER OF THE PUBLIC double-clicks in their own session.
    ///
    /// The reasoning that licenses `Allowed` inverts here, and it is worth stating because the
    /// comment justifying the override predates this caller and reads as unconditional. Setting an
    /// environment variable in the user's own session needs no privilege at all — a shortcut, a
    /// `.bat`, or anything already running as that user can do it. So the override would let
    /// someone else choose the path a support client writes to: appending attacker-influenced
    /// content to a file of their choosing, and moving a log that names the control plane, the
    /// session and the technician somewhere they can read it.
    ///
    /// The log is not secret, and this is not the last line of defence. But the redirect buys the
    /// attacker something and buys the guest nothing, and a support client has no reason to let its
    /// environment aim it.
    Forbidden,
}

/// Resolve a log path under an explicit redirect policy.
///
/// Pure, and separate from the cached [`log_path_with_default`], so both arms are testable — the
/// `OnceLock` resolves once per process and cannot be exercised twice from a test.
fn resolve_log_path(default_file: PathBuf, redirect: EnvRedirect) -> PathBuf {
    if redirect == EnvRedirect::Forbidden {
        return default_file;
    }
    match std::env::var(FILE_ENV) {
        Ok(raw) if !raw.trim().is_empty() => PathBuf::from(raw.trim()),
        _ => default_file,
    }
}

/// The log file to write: `RMT_LOG_FILE` if it names one, else `default_file`. An empty or
/// whitespace-only value is treated as absent rather than as "the current directory".
fn log_path_from_env(default_file: PathBuf) -> PathBuf {
    resolve_log_path(default_file, EnvRedirect::Allowed)
}

/// [`log_path_with_default`], with the environment locked out. See [`EnvRedirect::Forbidden`].
pub(crate) fn log_path_pinned(file: PathBuf) -> &'static Path {
    LOG_PATH.get_or_init(|| resolve_log_path(file, EnvRedirect::Forbidden))
}

/// A UTC timestamp for a log line, in the same shape `tracing`'s formatter emits
/// (`2026-08-04T02:53:14.237455Z`), so `host::log_line`'s lines sort and correlate with the
/// subscriber's in the file the two share.
///
/// Hand-formatted from `SystemTime` rather than pulling in a date crate for one line: the agent
/// has no other need for calendar arithmetic, and this is the civil-from-days algorithm, exact for
/// every date this code can see.
pub(crate) fn log_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_unix_micros(now.as_secs(), now.subsec_micros())
}

/// [`log_timestamp`] with the clock injected — the whole implementation, so the unit tests exercise
/// the shipped arithmetic at fixed instants instead of a copy of it.
fn format_unix_micros(unix_secs: u64, micros: u32) -> String {
    let (days, rem) = ((unix_secs / 86_400) as i64, unix_secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 → civil y/m/d (Howard Hinnant's `civil_from_days`).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mth <= 2);

    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}.{micros:06}Z")
}

/// Open the log for append, creating the directory and rotating first if it has outgrown
/// [`MAX_LOG_BYTES`]. `None` ⇒ the log is unwritable (a non-elevated dev run against a
/// SYSTEM-owned `C:\rmt-agent`); every caller degrades rather than failing.
///
/// Both writers go through here so rotation is decided in ONE place — a second writer that only
/// appended would keep the file growing past the cap between the first writer's checks.
pub(crate) fn open_log_append(path: &Path) -> Option<std::fs::File> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    rotate_if_oversized(path, MAX_LOG_BYTES);
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Rename `path` to `<stem>.1.log` when it exceeds `max`, discarding any previous generation.
///
/// **Best-effort by design.** The service (session 0) and the helper (session 1) are separate
/// processes appending to one file, so a rename can fail because the other has it open for the
/// length of a single write. A failed rotation is harmless: the file keeps growing a little and
/// the next write retries. Making it fallible-and-loud would turn a housekeeping detail into a
/// failure mode for the code that merely wanted to log.
///
/// It is also **unsynchronised across processes**, so if both writers cross the threshold at once
/// one can delete the generation the other just rotated. The bound on that is losing the retained
/// generation at an 8 MB boundary — never the live log, which is only ever renamed away after a
/// successor is opened on the next write. A cross-process mutex to close a window that costs old
/// log lines would be a worse trade than the loss it prevents.
fn rotate_if_oversized(path: &Path, max: u64) {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > max => {}
        _ => return, // absent, unreadable, or still small
    }
    let rotated = path.with_extension("1.log");
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, &rotated);
}

/// [`init`]'s body with the path/level injectable. Returns whether THIS call installed the global
/// subscriber (`false` = one was already installed, which callers treat as success).
fn init_with(path: PathBuf, level: LevelFilter) -> bool {
    tracing::subscriber::set_global_default(subscriber(path, level)).is_ok()
}

/// Build the subscriber. Factored from [`init`] so unit tests can install it *scoped* via
/// `tracing::subscriber::with_default` against a temp path instead of claiming the one
/// process-global subscriber slot.
///
/// `pub(crate)` so tests in OTHER modules can do the same — `service.rs` uses it to prove the
/// service's own decisions now reach a subscriber, which is the whole point of retiring its
/// private, gated, unrotated log writer.
pub(crate) fn subscriber(path: PathBuf, level: LevelFilter) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_max_level(level)
        // helper.log is plain text; ANSI escapes would garble `Get-Content` inspection. The `ansi`
        // cargo feature is off in the workspace manifest, so escapes would not be emitted anyway —
        // this states the intent at the one place a future feature change would otherwise flip it.
        .with_ansi(false)
        .with_writer(HelperLogWriter { path })
        .finish()
}

/// Resolve the max level from `RMT_LOG`, defaulting to INFO. A value that does not parse falls
/// back to INFO *loudly* (one stderr line) — the subscriber is not installed yet at that point, so
/// stderr is the only place the complaint can go, and a silent fallback would make a typo'd
/// `RMT_LOG=debgu` look like the agent simply refused to log.
///
/// An **empty or whitespace-only** value is treated as absent, matching [`log_path_from_env`].
/// This is not defensive tidiness: `tracing_core`'s `FromStr for LevelFilter` maps `""` to
/// **ERROR**, so `RMT_LOG=` (a `-e RMT_LOG` with no value, a service env entry with a blank data
/// field, `RMT_LOG=$UNSET_VAR` in a wrapper) would parse Ok and silently suppress every `info!`
/// and `warn!` in the agent — including `enroll`'s plaintext-http warning, i.e. exactly the
/// pre-change symptom this module exists to end, with no diagnostic to explain it.
fn level_from_env() -> LevelFilter {
    match std::env::var(LEVEL_ENV) {
        Ok(raw) if !raw.trim().is_empty() => match raw.trim().parse::<LevelFilter>() {
            Ok(level) => level,
            Err(_) => {
                eprintln!(
                    "agent: {LEVEL_ENV}={raw:?} is not a level (error|warn|info|debug|trace|off) — using info"
                );
                LevelFilter::INFO
            }
        },
        _ => LevelFilter::INFO,
    }
}

/// A [`MakeWriter`] that, per event, appends to the helper log (best-effort) and mirrors to stderr
/// (best-effort). See the module docs for why neither destination may ever fail the caller.
struct HelperLogWriter {
    path: PathBuf,
}

impl<'a> MakeWriter<'a> for HelperLogWriter {
    type Writer = EventWriter<'a>;

    fn make_writer(&'a self) -> EventWriter<'a> {
        // One writer per event. The file is NOT opened here: the whole event is buffered and
        // written in a single append on drop (see `EventWriter`), which is what makes the
        // per-line interleaving in the module docs true rather than merely hoped for.
        EventWriter {
            path: &self.path,
            buf: Vec::with_capacity(256),
        }
    }
}

/// One event's writer. `tracing`'s formatter emits an event in SEVERAL `write` calls (the
/// timestamp, the level, the target, each field, the newline), so writing straight through to the
/// file would let the service's and the helper's lines splice into each other mid-line. Instead the
/// event is accumulated here and flushed as ONE append in [`Drop`] — a single `write_all` to a
/// handle opened with `FILE_APPEND_DATA`, which Windows serialises against other appenders.
///
/// Opening in `drop` rather than in `make_writer` also means the rotation check runs once per
/// event, immediately before the write it applies to.
struct EventWriter<'a> {
    path: &'a Path,
    buf: Vec<u8>,
}

impl io::Write for EventWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        // Always claim success: a logging sink that surfaces errors becomes a fault injector for
        // the code that logs (tracing's fmt layer would print its own complaint per event).
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit();
        Ok(())
    }
}

impl EventWriter<'_> {
    /// Append the buffered event to the log and mirror it to stderr, both best-effort, then clear
    /// the buffer so a `flush()` followed by `drop` cannot write the event twice.
    fn emit(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        // None ⇒ the log is unwritable (non-elevated dev box); stderr still gets the event.
        if let Some(mut f) = open_log_append(self.path) {
            let _ = f.write_all(&self.buf);
        }
        // Best-effort: a service-spawned process may have no reader on stderr, or none at all.
        let _ = io::stderr().write_all(&self.buf);
        self.buf.clear();
    }
}

impl Drop for EventWriter<'_> {
    fn drop(&mut self) {
        self.emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `log_path_from_env` with the agent's own default — the shape every pre-existing assertion
    /// here was written against, before the default became a parameter.
    fn helper_default() -> PathBuf {
        log_path_from_env(PathBuf::from(HELPER_LOG_FILE))
    }

    /// Writer + level filter pinned end to end: a real fmt subscriber writing a real file, scoped
    /// with `with_default` (NOT installed globally, so this test does not fight the rest of the
    /// test binary over the one process-global subscriber slot). Deleting the `.with_writer(…)`
    /// wiring or raising the filter makes this fail — it pins the subscriber actually DELIVERING
    /// events to the file, which is the exact behavior the shipped agent lacked.
    #[test]
    fn info_reaches_the_log_file_and_debug_does_not() {
        let dir = std::env::temp_dir().join(format!("rmt-logging-test-{}", std::process::id()));
        let path = dir.join("helper.log");
        let _ = std::fs::remove_file(&path);

        let sub = subscriber(path.clone(), LevelFilter::INFO);
        tracing::subscriber::with_default(sub, || {
            tracing::info!(marker = "RMT_TEST_SHOULD_APPEAR", "logging test info line");
            tracing::debug!(marker = "RMT_TEST_MUST_NOT_APPEAR", "logging test debug line");
        });

        let text = std::fs::read_to_string(&path)
            .expect("the subscriber created and wrote the log file");
        assert!(
            text.contains("RMT_TEST_SHOULD_APPEAR"),
            "info event reaches the file; got: {text}"
        );
        assert!(
            text.contains("logging test info line"),
            "the formatted message body is present; got: {text}"
        );
        assert!(
            !text.contains("RMT_TEST_MUST_NOT_APPEAR"),
            "debug is filtered at the default INFO level; got: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The non-elevated dev-box case (`C:\rmt-agent` owned by SYSTEM): a log path that cannot be
    /// opened must neither panic nor error the emitting code. The "file" here is a *directory*,
    /// which `open()` refuses on every platform.
    ///
    /// What this pins is exactly **"emitting does not panic or fail"**. It does NOT observe the
    /// stderr fallback — a unit test cannot read this process's own stderr without redirecting a
    /// file descriptor the harness owns — so the stderr half is pinned by
    /// `tests/host_logging.rs::tracing_output_does_not_pollute_stdout`, which runs the real binary
    /// and reads its captured streams.
    #[test]
    fn unwritable_log_path_is_survivable() {
        let dir = std::env::temp_dir(); // exists and is a directory ⇒ open() fails
        let sub = subscriber(dir, LevelFilter::INFO);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("this event has nowhere to go but stderr");
        });
        // Reaching here without a panic IS the assertion.
    }

    /// `init` must be idempotent: whichever call loses the global-slot race is a silent no-op.
    /// (The first call may also "lose" if another test installed a global subscriber first —
    /// only the second call's outcome is deterministic, so that is what is asserted.)
    #[test]
    fn double_init_is_a_noop_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("rmt-logging-init-{}", std::process::id()));
        let _ = init_with(dir.join("first.log"), LevelFilter::INFO);
        assert!(
            !init_with(dir.join("second.log"), LevelFilter::INFO),
            "a second global install must be refused (and swallowed by init())"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotation: a log past the cap is moved aside (one generation kept, the older one discarded)
    /// and the next append starts a fresh file. A log at or under the cap is left ALONE — a
    /// rotation that fired every write would throw away the history it exists to preserve.
    #[test]
    fn an_oversized_log_rotates_and_a_small_one_does_not() {
        let dir = std::env::temp_dir().join(format!("rmt-logging-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("helper.log");
        let rotated = dir.join("helper.1.log");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);

        // Under the cap ⇒ untouched, and the append adds to what is already there.
        std::fs::write(&path, b"first-generation").unwrap();
        rotate_if_oversized(&path, 1024);
        assert!(!rotated.exists(), "a small log must not rotate");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first-generation");

        // Over the cap ⇒ moved aside; the live file is recreated empty by the next append.
        rotate_if_oversized(&path, 4);
        assert!(!path.exists(), "the oversized log was moved aside");
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap(),
            "first-generation",
            "the rotated generation keeps the old contents"
        );
        {
            use std::io::Write as _;
            let mut f = open_log_append(&path).expect("append reopens the log");
            writeln!(f, "second-generation").unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            "second-generation"
        );

        // A second rotation discards the older generation rather than accumulating forever.
        rotate_if_oversized(&path, 4);
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap().trim(),
            "second-generation",
            "only one generation is kept"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pins the **shipped** [`MAX_LOG_BYTES`], which nothing else covers: every other rotation test
    /// passes `max` explicitly, so a change to the constant itself slipped through the whole suite.
    /// Setting it to 0 (or any value an ordinary log exceeds) makes `open_log_append` rotate on
    /// EVERY write, leaving helper.log holding a single line and helper.1.log the one before it —
    /// the agent's log destroyed, with every other test still green. This drives the real
    /// `open_log_append` twice and requires both lines to survive.
    #[test]
    fn the_shipped_cap_keeps_an_ordinary_log_intact() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("rmt-logging-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("helper.log");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(dir.join("helper.1.log"));

        for line in ["first line", "second line"] {
            let mut f = open_log_append(&path).expect("the log opens for append");
            writeln!(f, "{line}").unwrap();
        }

        let text = std::fs::read_to_string(&path).expect("the log still exists");
        assert!(
            text.contains("first line") && text.contains("second line"),
            "consecutive appends must accumulate, not rotate each other away; got: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `log_timestamp` must produce the same shape `tracing`'s formatter does, since the whole
    /// point is that the two writers' lines are comparable in the file they share. Checked against
    /// fixed instants — a formatter tested only against "now" cannot catch an off-by-one in the
    /// civil-date conversion, because every wrong answer still looks like a plausible date.
    #[test]
    fn log_timestamp_matches_the_tracing_shape_and_the_calendar() {
        let ts = log_timestamp();
        assert_eq!(ts.len(), 27, "2026-08-04T02:53:14.237455Z is 27 chars: {ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "shape: {ts}");
        // Same slots the tracing formatter uses, so the two interleave readably.
        assert!(ts[..4].parse::<u32>().unwrap() >= 2026, "year: {ts}");

        // Fixed instants through the SHIPPED formatter — not a copy of its arithmetic, which
        // would test the copy and pin nothing. Epoch, a leap day, and both sides of a year
        // boundary, where an off-by-one in civil_from_days would show up.
        assert_eq!(format_unix_micros(0, 0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(&format_unix_micros(1_709_164_800, 0)[..10], "2024-02-29");
        assert_eq!(&format_unix_micros(1_735_689_599, 0)[..10], "2024-12-31");
        assert_eq!(&format_unix_micros(1_735_689_600, 0)[..10], "2025-01-01");
        // 1_754_269_994 = 1_735_689_600 (2025-01-01T00:00:00Z) + 215 d + 4394 s → 2025-08-04
        // 01:13:14. Derived by hand, not copied from a run of this function.
        assert_eq!(
            format_unix_micros(1_754_269_994, 237_455),
            "2025-08-04T01:13:14.237455Z"
        );
    }

    /// A missing log is not an error condition — `rotate_if_oversized` must simply do nothing
    /// (the very first run of a fresh install takes this path on every write).
    #[test]
    fn rotating_a_missing_log_is_a_noop() {
        let path = std::env::temp_dir().join(format!("rmt-absent-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        rotate_if_oversized(&path, 0);
        assert!(!path.exists());
        assert!(!path.with_extension("1.log").exists());
    }

    /// `RMT_LOG` / `RMT_LOG_FILE` parsing: valid names map to their level, garbage falls back to
    /// INFO *loudly*, and empty/whitespace is treated as absent by BOTH (an empty `RMT_LOG` parses
    /// to ERROR in `tracing_core` and would silence the agent — see `level_from_env`).
    ///
    /// Both variables are exercised in ONE test because each is process-global: two tests that
    /// each set one would still race with any other test reading it, and cargo runs tests in
    /// parallel threads within one process. Keeping every mutation of them here means nothing else
    /// in this binary observes them mid-change.
    #[test]
    fn level_and_file_env_parse_or_fall_back() {
        // SAFETY(std): set_var/remove_var are process-global; confined to this single test.
        // Clear first — a developer or CI with either variable exported would otherwise fail the
        // default-value assertions below with a diagnosis that points at the code, not their env.
        std::env::remove_var(LEVEL_ENV);
        std::env::remove_var(FILE_ENV);
        assert_eq!(level_from_env(), LevelFilter::INFO);
        assert_eq!(helper_default(), PathBuf::from(HELPER_LOG_FILE));

        std::env::set_var(LEVEL_ENV, "debug");
        assert_eq!(level_from_env(), LevelFilter::DEBUG);
        std::env::set_var(LEVEL_ENV, "WARN"); // case-insensitive
        assert_eq!(level_from_env(), LevelFilter::WARN);
        std::env::set_var(LEVEL_ENV, "debgu"); // the typo case — loud fallback, not silence
        assert_eq!(level_from_env(), LevelFilter::INFO);
        // The empty/whitespace cases are the ones that BITE: tracing_core parses "" as ERROR, so
        // without the is_empty guard `RMT_LOG=` would silently suppress every info!/warn! in the
        // agent — the pre-change symptom, with no diagnostic. Removing that guard fails here.
        std::env::set_var(LEVEL_ENV, "");
        assert_eq!(level_from_env(), LevelFilter::INFO, "empty RMT_LOG must not mean ERROR");
        std::env::set_var(LEVEL_ENV, "   ");
        assert_eq!(level_from_env(), LevelFilter::INFO, "blank RMT_LOG must not mean ERROR");
        std::env::remove_var(LEVEL_ENV);
        assert_eq!(level_from_env(), LevelFilter::INFO);

        assert_eq!(helper_default(), PathBuf::from(HELPER_LOG_FILE));
        std::env::set_var(FILE_ENV, r"C:\tmp\rmt-test.log");
        assert_eq!(helper_default(), PathBuf::from(r"C:\tmp\rmt-test.log"));
        // The override beats a TOOL default too — one variable redirects whichever binary runs,
        // which is what tests/probe_logging.rs relies on to keep the probe out of %TEMP%.
        assert_eq!(
            log_path_from_env(tool_log_path("probe")),
            PathBuf::from(r"C:\tmp\rmt-test.log"),
            "RMT_LOG_FILE must win over a caller-supplied default, not just over HELPER_LOG_FILE"
        );
        // Empty/whitespace must NOT become a relative path (which would drop the log into whatever
        // the process's working directory happens to be).
        std::env::set_var(FILE_ENV, "   ");
        assert_eq!(helper_default(), PathBuf::from(HELPER_LOG_FILE));
        std::env::remove_var(FILE_ENV);

        // ---- EnvRedirect::Forbidden: the support client's log cannot be aimed by its caller ----
        //
        // Asserted HERE rather than in a test of its own on purpose: these assertions need
        // RMT_LOG_FILE set, `set_var` is process-global, and cargo runs test functions on separate
        // threads — a second test touching the same variable would race this one and fail in a way
        // that looks like a real defect.
        //
        // The paired negative is what gives this meaning. If only the Forbidden arm were asserted
        // it would pass against a `resolve_log_path` that ignored the environment ALWAYS, which
        // would silently break the probe and every test that steers its own log.
        let attacker = PathBuf::from(r"C:\Users\Public\aimed-by-someone-else.log");
        let ours = PathBuf::from(r"C:\rmt-support\support.log");
        std::env::set_var(FILE_ENV, &attacker);
        assert_eq!(
            resolve_log_path(ours.clone(), EnvRedirect::Forbidden),
            ours,
            "a public-facing binary must write where IT chose; RMT_LOG_FILE needs no privilege to \
             set in the user's own session, so honouring it lets someone else pick the path"
        );
        assert_eq!(
            resolve_log_path(ours.clone(), EnvRedirect::Allowed),
            attacker,
            "the service/probe/CLI arm must still honour RMT_LOG_FILE — probe_logging.rs and the \
             tests above depend on it, and a Forbidden-always resolver would pass the assert \
             directly above this one"
        );
        std::env::remove_var(FILE_ENV);
        // With nothing set, both arms agree — the policy only ever REMOVES a redirect.
        assert_eq!(resolve_log_path(ours.clone(), EnvRedirect::Forbidden), ours);
        assert_eq!(resolve_log_path(ours.clone(), EnvRedirect::Allowed), ours);
        assert_eq!(helper_default(), PathBuf::from(HELPER_LOG_FILE));
        // With no override, a tool default is used VERBATIM (this is what keeps stream_probe out
        // of the agent's SYSTEM-owned directory).
        assert_eq!(log_path_from_env(tool_log_path("probe")), tool_log_path("probe"));
    }
}
