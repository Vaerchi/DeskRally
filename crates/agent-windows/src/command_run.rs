//! The **one-line command bar**: run a single command non-interactively, capture its output, and
//! return it (docs/01 P1 "One-line command bar — fire a command, capture output, no full shell").
//!
//! # What this is, and what it is not
//!
//! This is the *one-shot* sibling of the interactive ConPTY shell backstage panel: the technician
//! types one command, the agent runs it, captures stdout+stderr up to a cap, kills it if it outruns a
//! time budget, and answers with the exit code and the captured text. There is deliberately **no
//! interactivity** (no ConPTY, no live terminal) and **no whitelist** — unlike [`crate::launch`], which
//! resolves a fixed key, this runs an arbitrary command line, exactly like the ConPTY shell already
//! does. The *session itself* is the authorization, at the same trust level as input injection,
//! [`crate::reboot`] and [`crate::launch`] (a controller that can inject input can already type into a
//! shell). The command runs **hidden** (`CREATE_NO_WINDOW`), so nothing pops on the guest's screen — the
//! output is returned over the wire, not shown locally.
//!
//! # As SYSTEM (default) or as the interactive user
//!
//! `as_user == false` runs the command as **whatever this agent process already is** — on the
//! unattended per-session helper that is SYSTEM, the high-value default for remote support (`whoami`
//! → `NT AUTHORITY\SYSTEM`); on the ATTENDED host it is the guest's own user, because that is what
//! `agent_host attend` runs as. There is no SYSTEM mode on the attended path and never was.
//! `as_user == true` runs it as the **interactive user**
//! via their token ([`interactive_user_token`], `WTSQueryUserToken` — the same technique
//! [`crate::launch`] uses). Note the deliberate difference from the tool launcher: this uses the user's
//! **base** token, *not* their linked-elevated token. A launched MMC console needs elevation to be
//! useful, but a non-interactive command must never *silently* elevate — "as the user" means their
//! ordinary rights. SYSTEM is the mode to reach for when you need privilege.
//!
//! # …and, since loop 87, as the interactive user ELEVATED — but only on demand and only with a signature
//!
//! [`RunIdentity::UserElevated`] runs the command with the interactive user's **linked elevated
//! token**: their own full administrator rights, as if they had clicked "Yes" on a UAC prompt. Never
//! SYSTEM. The sentence above stays true, because the word doing the work in it is *silently* — this
//! mode is reachable only through a `Control::ElevatedRun` carrying a control-plane-signed,
//! session-bound, single-use elevation grant (`rmt_agent::elevation`, docs/01 §3), which `host.rs`
//! verifies and burns before it ever calls in here.
//!
//! **Read what that gate is, though, because it is easy to over-read** (corrected in loop 88): on
//! the UNATTENDED host it is an *authorization and audit* control, NOT a privilege boundary.
//! `as_user == false` above already runs arbitrary text as SYSTEM with no grant at all, and SYSTEM
//! holds `SeTcbPrivilege` — which is precisely what [`interactive_user_token`] below needs. A
//! technician who can run one ungated SYSTEM command can mint the guest's elevated token by hand
//! using the two calls this file and [`crate::launch`] already contain. What the grant buys is that
//! the supported path is capability-gated (`CapElevateSession`, Owner+Admin, not API-token-grantable)
//! and produces one audit event per elevated command naming who took the guest's identity and when.
//! See `rmt_agent::elevation`'s module docs for the full argument; do not restate it as a privilege
//! boundary here.
//!
//! Two rules this module enforces itself, so they cannot be forgotten by a caller:
//!
//! * **Only the UNATTENDED host can do it.** [`RunIdentity::UserElevated`] under
//!   [`crate::launch::TokenStrategy::OwnProcess`] is refused with [`CommandError::NotElevatable`]
//!   before any Win32 call. The attended host runs as the guest at medium integrity and Windows will
//!   not let it create a high-integrity process without a UAC consent no remote peer can supply
//!   (loop 84 measured this on LAB-VM). Refusing is a pure decision on a pure field, which is why
//!   it is unit-tested on the gate rather than only on the VM.
//! * **NEVER fall back to the base token.** [`crate::launch`] does exactly that
//!   (`elevated.unwrap_or(base)`) and is right to: a launcher that cannot elevate should still open
//!   Task Manager. Here the same fallback would be a LIE — the technician asked for elevation, the
//!   control plane audited it, a single-use grant was burned, and they would get an unelevated
//!   result they cannot distinguish from an elevated one. A user with no separate elevated token
//!   (a standard user; a UAC-off account) gets [`CommandError::NotElevatable`] instead.
//!
//! # Bounded in size and time (so it can never wedge the session)
//!
//! Output is capped at [`MAX_OUTPUT_BYTES`] per stream (the reader keeps draining past the cap so the
//! child never blocks on a full pipe — it just stops *keeping* bytes, and sets `truncated`). The command
//! is killed after [`DEFAULT_TIMEOUT`] via a **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
//! so a hung command's whole *process tree* dies, not just its top process. The dispatch side
//! (`host.rs`) runs [`CommandRunner::run`] on a blocking task held in a pending slot, so even a
//! full-timeout command never freezes the video/input/telemetry `select!` loop.
//!
//! # Safety in tests
//!
//! [`CommandRunner::new`] takes a `real` flag exactly like [`crate::reboot::Rebooter`] /
//! [`crate::launch::Launcher`]. The `--log-input` / `--synthetic` dev+e2e paths build a **mock** runner
//! that logs and returns a canned result without executing anything, so a gate/e2e that sends
//! `RunCommand` gets a `CommandResult` and the CI box runs no command. The pure [`build_invocation`] and
//! the capping helper are unit- + mutation-tested here; the SYSTEM capture path is exercised by real
//! `cmd /C echo` tests (harmless + fast); the `as_user` token path is VM-tested (a unit test cannot mint
//! a user token without a logged-in interactive session).

use std::time::Duration;

use rmt_agent_core::control::CommandShell;

/// Per-stream capture cap. stdout and stderr are each kept up to this many bytes; beyond it the reader
/// keeps draining (so the child never blocks on a full pipe) but discards, and sets `truncated`.
/// 64 KiB comfortably holds `ipconfig /all`, `systeminfo`, a directory listing — the things a one-line
/// bar is for. A command that produces more belongs in the interactive shell.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// How long a command may run before it (and its whole process tree) is killed. A one-liner is meant to
/// be quick; anything genuinely long-running belongs in the ConPTY shell. The session is NOT frozen
/// while this runs (the dispatch side runs it off the `select!` loop), so this is a safety bound on a
/// runaway command, not a UI latency.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The exit code a killed (timed-out) process reports. `TerminateJobObject` stamps every process in the
/// tree with this, so `GetExitCodeProcess` returns it; as an `i32` it is `-1`. `timed_out` is the
/// authoritative signal that a kill happened — this is just the code that accompanies it.
const KILL_EXIT_CODE: u32 = 0xFFFF_FFFF;

/// The captured result of a finished (or killed) command. Mirrors the wire
/// [`rmt_agent_core::control::ControlMessage::CommandResult`] fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// The process exit code (`KILL_EXIT_CODE` as `i32` = -1 when `timed_out`).
    pub exit_code: i32,
    /// Captured standard output (UTF-8 lossy).
    pub stdout: String,
    /// Captured standard error (UTF-8 lossy).
    pub stderr: String,
    /// stdout and/or stderr hit [`MAX_OUTPUT_BYTES`] and were cut off.
    pub truncated: bool,
    /// The command exceeded [`DEFAULT_TIMEOUT`] and its process tree was killed.
    pub timed_out: bool,
}

/// A reason the command could not be *started* (as opposed to running and failing — that is a
/// [`CommandOutput`] with a non-zero `exit_code`).
///
/// WHICH control message carries it depends on the REQUEST, not on the variant: a `RunCommand` that
/// could not start is a `ControlMessage::Error` ("that command did not run"), while an `ElevatedRun`
/// that could not start — for ANY of these reasons — is a `ControlMessage::ElevationDenied`, because
/// nothing executed AND the elevation did not happen, which is a different fact about whether a
/// privileged action occurred. See the `pending_command` completion arm in `host.rs`.
///
/// Holds `String`s (not `windows::core::Error`) so the whole result is `Send` across the
/// `spawn_blocking` boundary the dispatch uses.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// `as_user` was requested and the interactive user's token could not be obtained.
    ///
    /// The message used to assert "no interactive user is logged in", which was a guess dressed as a
    /// fact: `WTSQueryUserToken` fails that way when nobody is signed in, but it fails the SAME way
    /// with `ERROR_PRIVILEGE_NOT_HELD` when the caller lacks `SeTcbPrivilege` — which was the real
    /// cause on every attended session, with the guest sitting right there logged in. Report the
    /// error and let it name itself.
    #[error("could not obtain the interactive user's token: {0}")]
    NoUser(String),
    /// A Win32 setup step (pipes, job object, environment) failed before the process started.
    #[error("could not prepare the command: {0}")]
    Setup(String),
    /// `CreateProcess[AsUser]W` itself failed (e.g. the shell exe is missing).
    #[error("could not start the command: {0}")]
    Spawn(String),
    /// [`RunIdentity::UserElevated`] was asked for and this agent cannot honour it.
    ///
    /// Its own variant, and NEVER a silent downgrade to the base token. Two situations reach it and
    /// the message says which: the ATTENDED host (it runs as the guest at medium integrity, so a
    /// high-integrity child needs a UAC consent no remote peer can supply), and an interactive user
    /// who has no separate elevated token at all (a standard user, or an account whose base token is
    /// not UAC-filtered). Both mean "the elevated result you asked for does not exist here", and in
    /// both the honest answer is a refusal the technician can read.
    #[error("cannot run elevated: {0}")]
    NotElevatable(String),
}

/// Which identity a one-shot command runs under.
///
/// A named enum rather than two bools, for the reason this codebase keeps relearning
/// (`insecure-default-nobody-chose`): with `as_user` + `elevated` there would be a bit pattern —
/// `as_user == false, elevated == true` — that means "SYSTEM, elevated", which is not a thing, and
/// nothing would stop a caller constructing it. Here the three real identities are the only three
/// values, and the [`Default`] is the one that asks for nothing special.
///
/// This is an AGENT-side type. The wire keeps `RunCommand { as_user: bool }` unchanged and adds a
/// separate `ElevatedRun` message, so an agent already in the field cannot be handed a command whose
/// elevation flag it silently ignores (see `rmt_agent_core::control::ElevatedRun`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunIdentity {
    /// Whatever this agent process already is: SYSTEM on the unattended per-session helper, the
    /// guest's own user on the attended host. The historical `as_user == false`, and the default.
    #[default]
    Host,
    /// The interactive user's **base** (UAC-filtered) token. The historical `as_user == true`.
    User,
    /// The interactive user's **linked elevated** token — full administrator rights as that user,
    /// never SYSTEM. Reachable only via a verified elevation grant, and only on the unattended host.
    UserElevated,
}

impl RunIdentity {
    /// The historical two-state selector, so the unchanged `RunCommand` wire maps onto the enum in
    /// exactly one place instead of at every call site.
    pub fn from_as_user(as_user: bool) -> Self {
        if as_user {
            RunIdentity::User
        } else {
            RunIdentity::Host
        }
    }

    /// Does this identity require a verified elevation grant? Only [`RunIdentity::UserElevated`].
    pub fn needs_grant(self) -> bool {
        matches!(self, RunIdentity::UserElevated)
    }
}

/// Build the `(program, command_line)` pair for a shell + command. Pure, so the exact invocation is
/// pinned by a test. `program` is the absolute exe (`lpApplicationName`); `command_line` is the full
/// line whose first token is that exe (`lpCommandLine`). Both are resolved under `%SystemRoot%` so a
/// hijacked `PATH` cannot redirect the interpreter.
///
/// * [`CommandShell::Cmd`]        → `cmd.exe /C <command>` (built-ins, pipes, redirection).
/// * [`CommandShell::PowerShell`] → `powershell.exe -NoProfile -NonInteractive -Command <command>`.
///
/// `<command>` is appended verbatim: quoting inside it is the technician's business, exactly as if they
/// typed it at a prompt.
pub fn build_invocation(shell: CommandShell, command: &str) -> (String, String) {
    let root = system_root();
    match shell {
        CommandShell::Cmd => {
            let exe = format!(r"{root}\System32\cmd.exe");
            let command_line = format!(r#""{exe}" /C {command}"#);
            (exe, command_line)
        }
        CommandShell::PowerShell => {
            let exe = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
            let command_line =
                format!(r#""{exe}" -NoProfile -NonInteractive -Command {command}"#);
            (exe, command_line)
        }
    }
}

/// Given `already` bytes kept, `n` new bytes just read, and the `cap`, decide how many of the new bytes
/// to keep and whether this batch dropped any (truncation). Pure and shared with the reader loop, so a
/// unit test pins the EXACT boundary the shipped capture runs — an off-by-one here would either lose a
/// byte from a full-but-legal capture or cry truncation on one that fit exactly.
fn keep_count(already: usize, n: usize, cap: usize) -> (usize, bool) {
    if already >= cap {
        // Already full: keep nothing, and it truncated iff there were actually new bytes to drop.
        return (0, n > 0);
    }
    let take = (cap - already).min(n);
    (take, take < n)
}

/// Runs a one-shot command and captures its output, or logs the intent and returns a canned result
/// (the mock). Mirrors [`crate::launch::Launcher`] / [`crate::reboot::Rebooter`]. `Copy` so the dispatch
/// can move it into a `spawn_blocking` closure cheaply.
#[derive(Debug, Clone, Copy)]
pub struct CommandRunner {
    real: bool,
    strategy: crate::launch::TokenStrategy,
}

impl CommandRunner {
    /// `real == true` in production; `false` on the `--log-input` / `--synthetic` dev+e2e paths, where
    /// [`Self::run`] logs + returns a canned [`CommandOutput`] without executing (so the gate runs no
    /// command).
    /// `host_runs_as_interactive_user` mirrors [`crate::host::SessionOptions`]: `true` for the attended
    /// host (this process IS the guest's user), `false` for the SYSTEM per-session helper.
    pub fn new(real: bool, host_runs_as_interactive_user: bool) -> Self {
        Self { real, strategy: crate::launch::token_strategy(host_runs_as_interactive_user) }
    }

    /// Can this host honour [`RunIdentity::UserElevated`] at all?
    ///
    /// A pure predicate on a field the caller stated, so it is decidable without a desktop, a
    /// session or a privilege — and so `host.rs` can refuse an elevated run BEFORE burning the
    /// single-use grant. Burning a grant on a host that could never have honoured it would cost the
    /// technician their authorization for nothing, which is the same ordering argument the backstage
    /// ledger makes ("claim strictly after verification").
    ///
    /// **It answers the HOST axis only, and that is not the whole of "can this run elevate".** The
    /// second axis is the USER: whether the interactive account actually has a linked elevated token
    /// (a standard user has none, and neither does anyone on a UAC-off box). So a `true` here means
    /// "this host is the kind that CAN elevate", not "this run will". When the user axis then fails,
    /// [`elevated_token_or_refuse`] refuses rather than downgrading, the refusal reaches the
    /// technician as `ElevationDenied`, and the grant IS spent. Do not read the paragraph above as
    /// promising otherwise.
    ///
    /// That is a CHOICE, not a limit, and it is worth stating honestly: the user axis could be
    /// probed before the ledger claim with the same two calls the run itself makes
    /// (`interactive_user_token` + `crate::launch::linked_elevated_token`). It is not, because doing
    /// so would fetch the token twice and the answer would still be a TOCTOU — the account's
    /// elevation state can change between the probe and the spawn. Spending the grant and letting
    /// the technician re-mint a 2-minute artifact is the cheaper wrong answer than either a
    /// non-monotonic ledger or a check that can lie.
    ///
    /// False on the ATTENDED host: it runs as the guest at medium integrity, and a medium-integrity
    /// process may not create a high-integrity one without a UAC consent (loop 84, measured on
    /// LAB-VM).
    pub fn can_elevate(&self) -> bool {
        self.strategy == crate::launch::TokenStrategy::FetchInteractiveUser
    }

    /// Run `command` under `shell` as `identity`, and capture the result. Bounded by
    /// [`MAX_OUTPUT_BYTES`] and [`DEFAULT_TIMEOUT`]. `Err` only when the process could not be
    /// *started*; a process that ran and failed is `Ok` with a non-zero `exit_code`.
    ///
    /// The command text is intentionally NOT logged (it can carry credentials); only its shape is.
    /// The IDENTITY *is* logged, on both the real and the mock path — it is the only externally
    /// visible record of which token a command took, and the mock path is the one a headless e2e
    /// can observe.
    pub fn run(
        &self,
        shell: CommandShell,
        command: &str,
        identity: RunIdentity,
    ) -> Result<CommandOutput, CommandError> {
        // Refused BEFORE the mock check, deliberately: a mocked runner that cheerfully "elevated"
        // would make the attended refusal invisible to every headless test, which is exactly how
        // loop 84's token bug survived two VM verifications of the same feature.
        if identity.needs_grant() && !self.can_elevate() {
            return Err(CommandError::NotElevatable(
                "this agent runs as the guest's own user and cannot create a higher-integrity \
                 process without a UAC prompt; elevation is available on unattended (SYSTEM \
                 helper) agents only"
                    .to_string(),
            ));
        }
        if !self.real {
            tracing::warn!(
                ?identity,
                ?shell,
                cmd_len = command.len(),
                "command: MOCK — would run a command (not executing; --log-input/--synthetic path)"
            );
            return Ok(CommandOutput {
                exit_code: 0,
                stdout: format!("<mock: {shell:?} command not executed on this build>\r\n"),
                stderr: String::new(),
                truncated: false,
                timed_out: false,
            });
        }
        let (program, command_line) = build_invocation(shell, command);
        // ALREADY THE USER ⇒ `User` is a no-op, not a token fetch. On the attended host both modes
        // run as the guest, so honouring it by calling WTSQueryUserToken would fail 0x522 and turn a
        // request we can trivially satisfy into an error (which is exactly what it did).
        // `UserElevated` cannot reach here on that host — it was refused above.
        let effective = match identity {
            RunIdentity::User if !self.can_elevate() => RunIdentity::Host,
            other => other,
        };
        let out =
            spawn_and_capture(&program, &command_line, effective, DEFAULT_TIMEOUT, MAX_OUTPUT_BYTES)?;
        tracing::info!(
            ?identity,
            ?shell,
            exit_code = out.exit_code,
            timed_out = out.timed_out,
            truncated = out.truncated,
            "command: ran and captured output"
        );
        Ok(out)
    }
}

/// `%SystemRoot%`, defaulting to `C:\Windows` if unset or empty/whitespace (mirrors
/// [`crate::launch`]'s helper — see its docs for why the empty case matters).
fn system_root() -> String {
    match std::env::var("SystemRoot").ok() {
        Some(v) if !v.trim().is_empty() => v,
        _ => r"C:\Windows".to_string(),
    }
}

/// UTF-16, NUL-terminated (mirrors [`crate::sas::wide`] / [`crate::launch`], kept local).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// --- the Win32 spawn + capture (cfg(windows)) ---------------------------------------------------

/// Spawn `program`/`command_line`, capture stdout+stderr (capped), enforce `timeout` (tree-kill), and
/// return the [`CommandOutput`]. `identity` selects `CreateProcessAsUserW` (the interactive user's
/// base or linked-elevated token) over `CreateProcessW` (the agent's own identity — SYSTEM on the
/// unattended helper). This is the whole Win32 surface of the feature; the token paths are VM-tested
/// and the host path is real-`cmd`-tested.
///
/// The caller has already refused [`RunIdentity::UserElevated`] on a host that cannot elevate, and
/// already collapsed [`RunIdentity::User`] to [`RunIdentity::Host`] where the two are the same
/// person, so this function does no policy — only the Win32.
#[cfg(windows)]
fn spawn_and_capture(
    program: &str,
    command_line: &str,
    identity: RunIdentity,
    timeout: Duration,
    cap: usize,
) -> Result<CommandOutput, CommandError> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, GENERIC_READ,
        WAIT_TIMEOUT,
    };
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject, TerminateJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, INFINITE,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    let setup = |e: windows::core::Error| CommandError::Setup(e.to_string());
    let spawn = |e: windows::core::Error| CommandError::Spawn(e.to_string());

    // Inheritable SECURITY_ATTRIBUTES: the child must inherit the pipe write-ends and the NUL stdin.
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };

    // SAFETY: every handle created below is closed on every return path; out-params are stack locals
    // kept alive across their calls. Raw handle values are moved into reader threads as `isize` (Send)
    // and rebuilt there.
    unsafe {
        // 1. Two output pipes (child writes, we read). Read ends are made NON-inheritable so the child
        //    cannot hold them open and keep us blocked on read after it exits.
        let mut out_r = HANDLE::default();
        let mut out_w = HANDLE::default();
        CreatePipe(&mut out_r, &mut out_w, Some(&sa), 0).map_err(setup)?;
        let mut err_r = HANDLE::default();
        let mut err_w = HANDLE::default();
        if let Err(e) = CreatePipe(&mut err_r, &mut err_w, Some(&sa), 0) {
            let _ = CloseHandle(out_r);
            let _ = CloseHandle(out_w);
            return Err(setup(e));
        }
        let _ = SetHandleInformation(out_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(err_r, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));

        // A guard that closes the handles we own on this side, so early returns cannot leak them.
        let close_pipes = |out_r: HANDLE, out_w: HANDLE, err_r: HANDLE, err_w: HANDLE| {
            let _ = CloseHandle(out_r);
            let _ = CloseHandle(out_w);
            let _ = CloseHandle(err_r);
            let _ = CloseHandle(err_w);
        };

        // 2. NUL for stdin (inheritable), so the command reads instant EOF rather than hanging on input
        //    and never inherits the (invalid) stdin of a SYSTEM service.
        let nul_w = wide(r"\\.\NUL");
        let nul_in = match CreateFileW(
            PCWSTR(nul_w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h) => h,
            Err(e) => {
                close_pipes(out_r, out_w, err_r, err_w);
                return Err(setup(e));
            }
        };

        // 3. Job object with KILL_ON_JOB_CLOSE, so a timeout (TerminateJobObject) — or simply dropping
        //    the job handle — kills the command's WHOLE process tree, not just its top process.
        let job = match CreateJobObjectW(None, PCWSTR::null()) {
            Ok(j) => j,
            Err(e) => {
                close_pipes(out_r, out_w, err_r, err_w);
                let _ = CloseHandle(nul_in);
                return Err(setup(e));
            }
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) {
            close_pipes(out_r, out_w, err_r, err_w);
            let _ = CloseHandle(nul_in);
            let _ = CloseHandle(job);
            return Err(setup(e));
        }

        // 4. The interactive user's token + environment, only when switching identity.
        //
        //    `User`         → their BASE token, exactly as before.
        //    `UserElevated` → their LINKED ELEVATED token. `linked_elevated_token` returns `None`
        //                     for anyone who has no separate elevated token (a standard user, an
        //                     already-full token, a failed query) — and unlike `crate::launch`, we
        //                     do NOT fall back to the base token. A silent downgrade here would
        //                     return an unelevated result the technician cannot tell from an
        //                     elevated one, after a single-use grant was spent to get it.
        let mut token = HANDLE::default();
        let mut base_token = HANDLE::default();
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let switch_identity = identity != RunIdentity::Host;
        if switch_identity {
            match interactive_user_token() {
                Ok(t) => base_token = t,
                Err(e) => {
                    close_pipes(out_r, out_w, err_r, err_w);
                    let _ = CloseHandle(nul_in);
                    let _ = CloseHandle(job);
                    return Err(CommandError::NoUser(e.to_string()));
                }
            }
            token = base_token;
            if identity == RunIdentity::UserElevated {
                match elevated_token_or_refuse(crate::launch::linked_elevated_token(
                    base_token,
                    crate::launch::TokenStrategy::FetchInteractiveUser,
                )) {
                    Ok(elevated) => token = elevated,
                    Err(e) => {
                        close_pipes(out_r, out_w, err_r, err_w);
                        let _ = CloseHandle(nul_in);
                        let _ = CloseHandle(job);
                        let _ = CloseHandle(base_token);
                        return Err(e);
                    }
                }
            }
            if let Err(e) = CreateEnvironmentBlock(&mut env, token, false) {
                close_pipes(out_r, out_w, err_r, err_w);
                let _ = CloseHandle(nul_in);
                let _ = CloseHandle(job);
                if token != base_token {
                    let _ = CloseHandle(token);
                }
                let _ = CloseHandle(base_token);
                return Err(setup(e));
            }
        }

        // 5. STARTUPINFO wiring our three handles, and the process SUSPENDED so we can put it in the job
        //    before it can spawn a child that would escape the tree-kill.
        let mut si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: nul_in,
            hStdOutput: out_w,
            hStdError: err_w,
            ..Default::default()
        };
        let mut desktop_w = wide(r"WinSta0\Default");
        if switch_identity {
            // The user session's interactive desktop, matching crate::launch (harmless for a hidden
            // process, but correct for a token bound to that session).
            si.lpDesktop = PWSTR(desktop_w.as_mut_ptr());
        }
        let program_w = wide(program);
        let mut cmdline_w = wide(command_line);
        let mut pi = PROCESS_INFORMATION::default();
        let base_flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;

        let created = if switch_identity {
            CreateProcessAsUserW(
                token,
                PCWSTR(program_w.as_ptr()),
                PWSTR(cmdline_w.as_mut_ptr()),
                None,
                None,
                true, // inherit handles (the pipe + NUL)
                PROCESS_CREATION_FLAGS(base_flags.0 | CREATE_UNICODE_ENVIRONMENT.0),
                Some(env),
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        } else {
            CreateProcessW(
                PCWSTR(program_w.as_ptr()),
                PWSTR(cmdline_w.as_mut_ptr()),
                None,
                None,
                true, // inherit handles
                base_flags,
                None, // inherit the SYSTEM helper's environment
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        };

        // The token(s) + environment block have done their job the instant CreateProcess returns.
        // `token` and `base_token` are DISTINCT handles when the elevated one was fetched, and both
        // are ours to close; when they are the same handle, close it once.
        if switch_identity {
            if !env.is_null() {
                let _ = DestroyEnvironmentBlock(env);
            }
            if token != base_token {
                let _ = CloseHandle(token);
            }
            let _ = CloseHandle(base_token);
        }
        if let Err(e) = created {
            close_pipes(out_r, out_w, err_r, err_w);
            let _ = CloseHandle(nul_in);
            let _ = CloseHandle(job);
            return Err(spawn(e));
        }

        // 6. Put the (still suspended) process in the job, then let it run. If Assign fails (rare on
        //    Win8+), we proceed without tree-kill rather than fail the command — a top-level kill still
        //    bounds it.
        if let Err(e) = AssignProcessToJobObject(job, pi.hProcess) {
            tracing::warn!(error = %e, "command: could not assign process to job (tree-kill degraded)");
        }
        ResumeThread(pi.hThread);

        // 7. The parent no longer needs the child's ends: close the pipe WRITE ends and the NUL handle
        //    so that when the child exits, our reads hit EOF (a broken pipe). We keep the read ends.
        let _ = CloseHandle(out_w);
        let _ = CloseHandle(err_w);
        let _ = CloseHandle(nul_in);

        // 8. Drain both pipes on threads (so a full pipe never deadlocks against our wait), capped.
        let out_raw = out_r.0 as isize;
        let err_raw = err_r.0 as isize;
        let out_reader = std::thread::spawn(move || read_all_capped(out_raw, cap));
        let err_reader = std::thread::spawn(move || read_all_capped(err_raw, cap));

        // 9. Wait up to the budget; on timeout kill the whole tree, then wait for it to be gone.
        let ms = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        let wait = WaitForSingleObject(pi.hProcess, ms);
        let timed_out = wait == WAIT_TIMEOUT;
        if timed_out {
            let _ = TerminateJobObject(job, KILL_EXIT_CODE);
            let _ = WaitForSingleObject(pi.hProcess, INFINITE);
        }

        // 10. Exit code (after any kill this is KILL_EXIT_CODE), then join the readers (they end at EOF,
        //     which the tree-kill guarantees even if the command spawned children).
        let mut code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut code);
        let (out_bytes, out_trunc) = out_reader.join().unwrap_or_default();
        let (err_bytes, err_trunc) = err_reader.join().unwrap_or_default();

        // 11. Clean up the remaining handles. Closing the job handle (KILL_ON_JOB_CLOSE) also reaps any
        //     straggler the tree-kill missed.
        let _ = CloseHandle(out_r);
        let _ = CloseHandle(err_r);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(job);

        Ok(CommandOutput {
            exit_code: code as i32,
            stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
            truncated: out_trunc || err_trunc,
            timed_out,
        })
    }
}

/// Read a pipe read-end (passed as a raw `isize` so it is `Send` into the reader thread) to EOF, keeping
/// at most `cap` bytes but continuing to drain past it (so the child never blocks on a full pipe) and
/// reporting whether anything was dropped.
#[cfg(windows)]
fn read_all_capped(read_handle_raw: isize, cap: usize) -> (Vec<u8>, bool) {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::ReadFile;

    let handle = HANDLE(read_handle_raw as *mut core::ffi::c_void);
    let mut kept: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        let mut read: u32 = 0;
        // SAFETY: `handle` is a valid pipe read-end owned by the spawning function for this thread's
        // lifetime; `buf`/`read` are stack locals kept alive across the call.
        let ok = unsafe { ReadFile(handle, Some(&mut buf), Some(&mut read), None) };
        if ok.is_err() || read == 0 {
            // A closed write-end yields ERROR_BROKEN_PIPE (an Err) — normal EOF for an anonymous pipe.
            break;
        }
        let n = read as usize;
        let (take, batch_truncated) = keep_count(kept.len(), n, cap);
        if take > 0 {
            kept.extend_from_slice(&buf[..take]);
        }
        if batch_truncated {
            truncated = true;
        }
    }
    (kept, truncated)
}

/// Which token an ELEVATED run must use, given whatever [`crate::launch::linked_elevated_token`]
/// found — or the refusal, when it found nothing.
///
/// Its own function so the `None` arm is reachable from a unit test at all: the real path needs
/// `SeTcbPrivilege` and a live interactive session, so under `cargo test` execution dies at
/// [`interactive_user_token`] several steps earlier (`real::as_user_on_the_system_helper_still_takes
/// _the_token_path` pins exactly that), and the Playwright agents all run mocked. Inline, the
/// "never a silent downgrade" rule in the module docs was provable by nothing.
///
/// **What the unit test does and does not close.** It pins THIS decision: given no linked token,
/// refuse rather than hand one back. It does NOT pin the propagation — the call site in
/// [`spawn_and_capture`] could still discard the `Err` and leave `token` as `base_token`, and no
/// suite would notice. That residual is VM-only (LAB-VM, `whoami /groups`: Medium vs High
/// Mandatory Level). Say so rather than letting the extraction imply more coverage than it bought.
#[cfg(windows)]
fn elevated_token_or_refuse(
    linked: Option<windows::Win32::Foundation::HANDLE>,
) -> Result<windows::Win32::Foundation::HANDLE, CommandError> {
    match linked {
        Some(elevated) => Ok(elevated),
        None => Err(CommandError::NotElevatable(
            "the interactive user has no linked elevated token — a standard user has no \
             administrator rights to take, and this agent will not silently run the command \
             unelevated instead"
                .to_string(),
        )),
    }
}

/// The interactive user's primary token for THIS helper's own session (`WTSQueryUserToken`), for
/// `as_user`. Deliberately the **base** token, not the linked-elevated one [`crate::launch`] uses — a
/// command must not silently elevate (SYSTEM is the mode for privilege). Fails if no user is logged in.
///
/// # Safety
/// Requires `SeTcbPrivilege` (the SYSTEM helper has it). The returned handle is owned by the caller and
/// must be closed.
#[cfg(windows)]
unsafe fn interactive_user_token() -> windows::core::Result<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken};
    use windows::Win32::System::Threading::GetCurrentProcessId;

    // The helper is a per-session process; target ITS session, not the global active console session,
    // so the command runs as the user the technician is actually viewing (mirrors crate::launch).
    let mut session_id: u32 = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)?;
    let mut token = HANDLE::default();
    WTSQueryUserToken(session_id, &mut token)?;
    Ok(token)
}

/// Non-Windows stub so the crate still type-checks off-Windows (it compiles to an empty shell — see the
/// crate docs). Never called; the whole feature is Windows-only.
#[cfg(not(windows))]
fn spawn_and_capture(
    _program: &str,
    _command_line: &str,
    _identity: RunIdentity,
    _timeout: Duration,
    _cap: usize,
) -> Result<CommandOutput, CommandError> {
    Err(CommandError::Setup("command execution is Windows-only".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_invocation_cmd_and_powershell() {
        // Cmd → cmd.exe /C <command>; PowerShell → the non-interactive, no-profile form. The exe is
        // absolute under %SystemRoot% (a relative exe would be PATH-hijackable), and the command is
        // appended verbatim.
        let (exe, line) = build_invocation(CommandShell::Cmd, "whoami");
        assert!(exe.ends_with(r"\System32\cmd.exe"), "cmd exe: {exe}");
        assert!(line.ends_with(r" /C whoami"), "cmd line: {line}");
        assert!(line.starts_with(&format!("\"{exe}\"")), "cmd line names the exe: {line}");

        let (exe, line) = build_invocation(CommandShell::PowerShell, "Get-Date");
        assert!(exe.ends_with(r"\WindowsPowerShell\v1.0\powershell.exe"), "ps exe: {exe}");
        assert!(
            line.ends_with(" -NoProfile -NonInteractive -Command Get-Date"),
            "ps line: {line}"
        );
        // The shell selection actually changes the interpreter — the whole point of the flag.
        let (cmd_exe, _) = build_invocation(CommandShell::Cmd, "x");
        let (ps_exe, _) = build_invocation(CommandShell::PowerShell, "x");
        assert_ne!(cmd_exe, ps_exe);
    }

    #[test]
    fn keep_count_is_exact_at_the_boundary() {
        // The reader loop's shipped keep-decision. Filling exactly to the cap keeps everything and does
        // NOT truncate; one byte past the cap keeps up to the cap and truncates; an already-full buffer
        // keeps nothing and truncates only if there were bytes to drop.
        assert_eq!(keep_count(0, 3, 3), (3, false)); // exactly cap → keep all, no truncation
        assert_eq!(keep_count(0, 4, 3), (3, true)); // one over → keep 3, truncated
        assert_eq!(keep_count(2, 1, 3), (1, false)); // fills to exactly cap → no truncation
        assert_eq!(keep_count(2, 5, 3), (1, true)); // fills then overflows → keep 1, truncated
        assert_eq!(keep_count(3, 1, 3), (0, true)); // already full, more bytes → dropped
        assert_eq!(keep_count(5, 2, 3), (0, true)); // already over (defensive) → dropped
    }

    #[test]
    fn mock_runner_never_executes_but_acks() {
        // A mock runner returns a canned Ok without running anything — so a gate/e2e that sends
        // RunCommand gets a CommandResult and the CI box runs no command.
        let r = CommandRunner::new(false, false);
        let out = r.run(CommandShell::Cmd, "shutdown /r /t 0", RunIdentity::Host).expect("mock ok");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("mock"), "mock stdout: {}", out.stdout);
        assert!(!out.timed_out);
    }

    // --- elevation (loop 87, docs/01 §3) --------------------------------------------------

    #[test]
    fn run_identity_maps_the_unchanged_as_user_wire_field() {
        // The wire still carries `as_user: bool`; the enum is agent-side. This is the ONE place the
        // two vocabularies meet, so it is the one place a mix-up could silently swap SYSTEM for the
        // user (or the reverse) on every command.
        assert_eq!(RunIdentity::from_as_user(false), RunIdentity::Host);
        assert_eq!(RunIdentity::from_as_user(true), RunIdentity::User);
        // …and neither maps to the elevated identity, which no `RunCommand` may ever reach.
        assert_ne!(RunIdentity::from_as_user(true), RunIdentity::UserElevated);
        assert_ne!(RunIdentity::from_as_user(false), RunIdentity::UserElevated);
    }

    /// The "never a silent downgrade" rule, which until loop 88 was asserted in three comments and
    /// tested nowhere — the whole reason [`elevated_token_or_refuse`] exists as its own function.
    ///
    /// The failure it guards against is the quiet one: with the `None` arm deleted the run proceeds
    /// on `base_token`, the technician gets a normal-looking `CommandResult`, and the control plane
    /// has already audited an elevation and burned a single-use grant for it. Nothing anywhere
    /// reports that the command ran unelevated.
    #[cfg(windows)]
    #[test]
    fn an_elevated_run_refuses_rather_than_falling_back_to_the_base_token() {
        use windows::Win32::Foundation::HANDLE;

        // No linked elevated token — a standard user, or any account on a UAC-off box.
        match elevated_token_or_refuse(None) {
            Err(CommandError::NotElevatable(m)) => {
                // The reason has to survive to the technician: this refusal is reported to them and
                // "cannot run elevated" with no cause reads as a broken feature.
                assert!(
                    m.contains("no linked elevated token"),
                    "the refusal does not say WHY: {m}"
                );
            }
            Err(other) => panic!("refused with the wrong error — a caller distinguishes these: {other}"),
            Ok(h) => panic!(
                "SILENT DOWNGRADE: handed back {:?} instead of refusing. The technician would get an \
                 unelevated result after a single-use grant was spent.",
                h.0
            ),
        }

        // PREMISE, declared locally (memory: regression-test-premise-drift): the function is not
        // simply refusing everything. A real linked token comes back UNCHANGED — so the assertion
        // above is about the `None` arm and not about a function that can never succeed.
        let elevated = HANDLE(0x1234_usize as *mut core::ffi::c_void);
        let got = elevated_token_or_refuse(Some(elevated)).expect("a real linked token is accepted");
        assert_eq!(got.0, elevated.0, "the elevated token was not the one passed through");
    }

    #[test]
    fn the_default_identity_asks_for_nothing_special() {
        // A `RunIdentity` that materialised from a Default must not be the privileged one.
        assert_eq!(RunIdentity::default(), RunIdentity::Host);
        assert!(!RunIdentity::default().needs_grant());
        assert!(!RunIdentity::User.needs_grant());
        assert!(RunIdentity::UserElevated.needs_grant());
    }

    #[test]
    fn only_the_unattended_host_can_elevate() {
        // `can_elevate` is what `host.rs` consults BEFORE burning a single-use grant, so its value
        // decides whether a technician's authorization is spent for nothing.
        assert!(
            CommandRunner::new(true, false).can_elevate(),
            "the SYSTEM per-session helper must be able to elevate — it is the only host that can"
        );
        assert!(
            !CommandRunner::new(true, true).can_elevate(),
            "the ATTENDED host runs as the guest at medium integrity; Windows will not let it \
             create a high-integrity process without a UAC consent (loop 84, measured)"
        );
    }

    #[test]
    fn an_attended_host_refuses_an_elevated_run_without_touching_win32() {
        // The refusal is a decision on a pure field, so it is provable HERE rather than only on the
        // VM — and it is checked BEFORE the mock branch, so a mocked runner cannot pretend to have
        // elevated. That ordering is the lesson of loop 84: the gate runs the mocks, so a mock that
        // answers "sure, elevated" makes an attended-path bug invisible to every test in the tree.
        for real in [true, false] {
            let r = CommandRunner::new(real, true);
            match r.run(CommandShell::Cmd, "whoami /groups", RunIdentity::UserElevated) {
                Err(CommandError::NotElevatable(msg)) => {
                    assert!(msg.contains("UAC"), "the refusal must say WHY: {msg}");
                }
                Err(other) => panic!("expected NotElevatable, got {other}"),
                Ok(out) => panic!(
                    "an attended host claimed to run an ELEVATED command (real={real}, stdout {:?}) \
                     — the technician would read an unelevated result as an elevated one",
                    out.stdout
                ),
            }
        }
    }

    #[test]
    fn an_unattended_mock_accepts_an_elevated_run_rather_than_refusing_it() {
        // Renamed in loop 88: the old name ("still honours the identity it was asked for") claimed
        // something this body cannot check. `CommandOutput` carries no identity — the identity is
        // only observable in the tracing line, which is why the E2E asserts `identity=UserElevated`
        // in the agent's log and this test cannot.
        //
        // What it DOES pin is still worth pinning: the elevated identity survives the mock branch
        // instead of being refused by the attended check above it. That refusal is deliberately
        // placed BEFORE the mock so an attended agent's refusal is visible to headless tests; this
        // asserts the other side of that ordering, i.e. that it does not also swallow the
        // UNATTENDED case and blind every e2e to the whole feature.
        let r = CommandRunner::new(false, false);
        let out = r
            .run(CommandShell::Cmd, "whoami", RunIdentity::UserElevated)
            .expect("the unattended mock accepts an elevated run");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("mock"), "mock stdout: {}", out.stdout);
    }

    // The real SYSTEM capture path is exercised against `cmd` directly — harmless, fast, deterministic
    // on Windows (the gate host). The token (`as_user`) path cannot be unit-tested (no logged-in user
    // token without an interactive session) and is VM-verified instead.
    #[cfg(windows)]
    mod real {
        use super::*;

        #[test]
        fn echo_captures_stdout_and_zero_exit() {
            let r = CommandRunner::new(true, false);
            let out = r.run(CommandShell::Cmd, "echo hello-rmt", RunIdentity::Host).expect("run");
            assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
            assert!(out.stdout.contains("hello-rmt"), "stdout: {:?}", out.stdout);
            assert!(!out.timed_out);
            assert!(!out.truncated);
        }

        #[test]
        fn nonzero_exit_is_reported() {
            // `cmd /C exit 3` returns 3 — proving we read the real exit code, not a hard-coded 0.
            let r = CommandRunner::new(true, false);
            let out = r.run(CommandShell::Cmd, "exit 3", RunIdentity::Host).expect("run");
            assert_eq!(out.exit_code, 3);
            assert!(!out.timed_out);
        }

        #[test]
        fn as_user_on_a_host_that_is_already_the_user_runs_instead_of_failing() {
            // THE REGRESSION, and it is runnable HERE — no VM needed — because `cargo test` runs as an
            // interactive user, which is the same relationship the attended host has to the guest.
            //
            // With host_runs_as_interactive_user=true, `as_user` must be satisfied by simply running
            // (we are the user) rather than by fetching somebody's token. Before the fix this call
            // reached WTSQueryUserToken and came back
            // `CommandError::NoUser(ERROR_PRIVILEGE_NOT_HELD)` — 0x80070522 — because SeTcbPrivilege
            // is SYSTEM's, not an administrator's. That is what broke RunCommand{as_user} on every
            // attended session.
            let r = CommandRunner::new(true, true);
            let out = r
                .run(CommandShell::Cmd, "echo as-user-ran", RunIdentity::User)
                .expect("as_user must not need a privileged token fetch when we ARE the user");
            assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
            assert!(out.stdout.contains("as-user-ran"), "stdout: {:?}", out.stdout);
        }

        #[test]
        fn as_user_on_the_system_helper_still_takes_the_token_path() {
            // The complement. As the SYSTEM helper (host_runs_as_interactive_user=false) `as_user`
            // must still go and fetch the user's token — that is the whole point of the mode. Run as
            // an ordinary interactive user in the gate, that fetch is REFUSED, and the refusal is the
            // observable: it proves the branch was taken rather than quietly downgraded to "just run".
            //
            // Asserting the error VARIANT, not its text: the point is which path ran.
            let r = CommandRunner::new(true, false);
            match r.run(CommandShell::Cmd, "echo should-not-run", RunIdentity::User) {
                Err(CommandError::NoUser(_)) => {}
                Err(other) => panic!("expected NoUser from the token fetch, got {other}"),
                Ok(out) => panic!(
                    "the SYSTEM-helper path ran the command without fetching a token                      (stdout {:?}) — as_user has been silently downgraded, so an unattended                      technician's `as_user` command would run as SYSTEM instead",
                    out.stdout
                ),
            }
        }

        #[test]
        fn stderr_is_captured_separately() {
            // Redirect a message to stderr; it must land in stderr, not stdout.
            let r = CommandRunner::new(true, false);
            let out = r.run(CommandShell::Cmd, "echo oops 1>&2", RunIdentity::Host).expect("run");
            assert!(out.stderr.contains("oops"), "stderr: {:?}", out.stderr);
            assert!(!out.stdout.contains("oops"), "stdout leaked stderr: {:?}", out.stdout);
        }

        #[test]
        fn output_over_the_cap_is_truncated_not_hung() {
            // Emit more than a tiny cap and prove: we keep exactly `cap` bytes, flag truncation, and
            // — crucially — DO NOT hang (the reader keeps draining past the cap so the child's pipe
            // writes never block). A 4000-'x' line dwarfs a 100-byte cap.
            let cap = 100;
            let (program, line) = build_invocation(
                CommandShell::PowerShell,
                "$([string]::new('x',4000))",
            );
            let out = spawn_and_capture(&program, &line, RunIdentity::Host, Duration::from_secs(20), cap)
                .expect("run");
            assert!(out.truncated, "expected truncation");
            assert!(out.stdout.len() <= cap, "kept {} > cap {cap}", out.stdout.len());
            assert!(!out.timed_out, "a large-output command must complete, not time out");
        }

        #[test]
        fn a_hung_command_is_killed_at_the_timeout() {
            // A 30-second sleeper against a 400 ms budget must be killed (timed_out) and report the
            // kill code — proving the job-object tree-kill actually fires, fast.
            let (program, line) = build_invocation(CommandShell::PowerShell, "Start-Sleep -Seconds 30");
            let start = std::time::Instant::now();
            let out = spawn_and_capture(&program, &line, RunIdentity::Host, Duration::from_millis(400), MAX_OUTPUT_BYTES)
                .expect("run");
            assert!(out.timed_out, "expected a timeout kill");
            assert_eq!(out.exit_code, -1, "killed process reports the kill code");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "kill did not happen promptly: {:?}",
                start.elapsed()
            );
        }
    }
}
