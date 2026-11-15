//! Launch a built-in Windows admin tool on the guest's INTERACTIVE desktop, so it appears in the
//! technician's live stream (docs/01 P1 "System tool launchers — Registry Editor, Event Viewer,
//! Services, Task Manager, Device Manager").
//!
//! # Why a whitelist, not a command
//!
//! The controller sends a stable KEY (`"task_manager"`, …), never a path or command line. The agent
//! resolves it against the fixed [`TOOLS`] table and can only ever spawn one of those known, signed OS
//! binaries — this can never become an arbitrary-executable surface, unlike a "run this command" bar.
//! [`resolve_tool`] is the whole security boundary and is pure + exhaustively tested.
//!
//! # Where — and as WHOM — the tool runs
//!
//! The tool is launched **as the logged-in user**, never as SYSTEM — but HOW it gets that user's
//! token depends on which host is running, and getting that wrong broke this feature outright on one
//! of them (see "Two hosts" below). This is a deliberate least-privilege choice — a SYSTEM-elevated Registry Editor / Services console left on
//! the desktop would be a **local privilege escalation** for a standard-user guest, who can drive that
//! higher-integrity window with *physical* input (UIPI only blocks synthetic input).
//!
//! **Elevation, without SYSTEM.** Two of the five consoles (Services, Device Manager) require
//! elevation, so launching them with an admin's *UAC-filtered* token fails with
//! `ERROR_ELEVATION_REQUIRED`. When the interactive user is a filtered admin, the launch therefore
//! uses their **linked elevated token** ([`linked_elevated_token`]) — their own full admin rights, exactly what
//! they would get by clicking "Yes" on a UAC prompt, and still NOT SYSTEM. A **standard** user has no
//! elevated linked token, so they get their base token and the elevation-requiring consoles fail —
//! which is correct: a standard user genuinely cannot open them, and we never hand them rights they
//! do not have. If no user is logged in (a machine at the sign-in screen), there is no token at all
//! and the launch fails with an `Error`, since there is no interactive desktop to place a tool on.
//!
//! # Two hosts, and the bug that came of assuming one of them
//!
//! This crate serves TWO hosts, and they stand in a different relationship to the user:
//!
//! * **UNATTENDED** — a per-session helper running as **SYSTEM** in the user's session. It is not the
//!   user, so it must go and FETCH their token: `WTSQueryUserToken`, which needs `SeTcbPrivilege`.
//! * **ATTENDED** — `agent_host attend`, running **as the guest's own user** in their own session. It
//!   already IS the user.
//!
//! The original code did the SYSTEM thing unconditionally, and its own comment said so ("needs
//! SeTcbPrivilege, which the SYSTEM helper has"). On the attended host that call fails with
//! `ERROR_PRIVILEGE_NOT_HELD` (0x522) — administrators do NOT hold `SeTcbPrivilege` — so **every tool
//! launch on every attended session failed**, which is the main remote-support scenario. It went
//! unnoticed for the reason `guest-window-probe.ps1` probes both hosts separately: loops 26/27
//! VM-verified this on the SYSTEM helper, and the gate runs the MOCK launcher, so no test and no
//! verification ever exercised the real token path on the attended host.
//!
//! [`TokenStrategy`] is that choice, made from an explicit flag threaded down from
//! `SessionOptions::host_runs_as_interactive_user` rather than sniffed at the call site — so it is a
//! decision the caller states and a pure function can test, not a privilege probe that fails late.
//!
//! ## What ATTENDED can and cannot do, measured
//!
//! Fixing the token strategy revealed the real boundary, and it is worth stating exactly because the
//! three failures look alike from the outside (a tool that did not appear) and are entirely different:
//!
//! | on the ATTENDED host | outcome (measured on LAB-VM) |
//! |---|---|
//! | `RunCommand`, either mode | works — both run as the guest, because that is what this process is |
//! | Task Manager / Registry Editor / Event Viewer | **launch** on the guest's desktop as the guest |
//! | Services / Device Manager | refused, `ERROR_ELEVATION_REQUIRED` → [`LaunchError::NeedsElevation`] |
//!
//! The last row is **Windows, not us.** Those two consoles need a high-integrity process, and a
//! medium-integrity one may not create it without a UAC consent — that is the local privilege
//! escalation UAC exists to prevent, and an admin guest's *linked elevated token* does not buy a way
//! around it. The unattended host has no such limit because it is SYSTEM. So this is reported as its
//! own error naming the situation, not as a hex code to go debugging.
//!
//! Getting here also exposed a second, unrelated bug that only the attended host could hit:
//! `TokenLinkedToken` returns an **impersonation** token, and `CreateProcessAsUserW` requires a
//! **primary** one. Unduplicated it fails `ERROR_BAD_IMPERSONATION_LEVEL` (0x542). SYSTEM's privileges
//! had been hiding that, so it surfaced the first time an ordinary administrator took this path.
//!
//! # Two deliberate design decisions (not oversights)
//!
//! * **No extra authorization gate.** `LaunchTool` rides the plain Control channel, at the same trust
//!   level as input injection and [`crate::reboot`] — the *session itself* is the authorization. A
//!   controller that can inject input can already open any of these tools via the Start menu, so the
//!   launcher grants no capability beyond what the session already confers. This is intentionally
//!   NOT gated behind a backstage grant (that gate is for privileged ops — file/registry/process —
//!   that a session does not otherwise confer).
//!
//!   **That Start-menu argument is the weaker half, and on its own it is not enough** (noted in loop
//!   88, after a review raised this launcher as an ungated door to the same privilege loop 87's
//!   signed elevation grant gates). Two elevation-requiring consoles here — Services and Device
//!   Manager — need a UAC consent the technician can only answer where the session can drive the
//!   secure desktop. The argument that actually holds is narrower and stronger: the ELEVATED token is
//!   only ever obtained under [`TokenStrategy::FetchInteractiveUser`], i.e. on the unattended
//!   per-session SYSTEM helper, and that session ALREADY confers arbitrary command execution as
//!   SYSTEM through `RunCommand { as_user: false }` — from which the guest's elevated token is two
//!   documented calls away (see `crate::command_run`'s module docs). So this path hands out strictly
//!   less than a sibling path in the same session at the same trust level; it is not a new door.
//!   Blast radius is further bounded by the whitelist — [`resolve_tool`] is the boundary, and it
//!   resolves five signed in-box binaries and nothing else.
//!
//!   On the ATTENDED host the duplication is MEASURED to fail (0x542) and [`linked_elevated_token`]
//!   therefore returns `None` in practice — see its own comment. Stated as measurement, not as an
//!   invariant: the function does not consult [`TokenStrategy`] before querying `TokenLinkedToken`,
//!   so nothing structural guarantees it. If that guarantee is ever wanted, return `None` for
//!   [`TokenStrategy::OwnProcess`] up front.
//! * **Launched tools persist after disconnect.** The tool is not tracked or torn down at session
//!   end; it stays open like any app the technician launched via the Start menu. That is safe here
//!   precisely because it runs **as the user at the user's own rights** (never SYSTEM; only an admin's
//!   own linked-elevated token) — leaving it running hands the guest nothing they could not open
//!   themselves.
//!
//! # Safety in tests
//!
//! [`Launcher::new`] takes a `real` flag exactly like [`crate::reboot::Rebooter`]. The `--log-input`
//! / `--synthetic` dev+e2e paths build a **mock** launcher that resolves + logs + acks but spawns
//! nothing, so a gate run never pops Task Manager on the CI box.
//!
//! The pure [`resolve_tool`] is unit- and mutation-tested here; `CreateProcessAsUserW` is VM-tested.

/// One launchable tool: its wire key, the executable to spawn (relative to `%SystemRoot%`), any
/// arguments (also `%SystemRoot%`-relative, for the MMC snap-ins), and a human label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    /// The stable wire key the controller sends.
    pub key: &'static str,
    /// Executable path relative to `%SystemRoot%` (e.g. `System32\taskmgr.exe`).
    pub exe: &'static str,
    /// Arguments, each also relative to `%SystemRoot%` (the `.msc` path for an MMC snap-in). Empty
    /// for a tool launched directly.
    pub args: &'static [&'static str],
    /// Human label for logs and the controller's status line.
    pub label: &'static str,
}

/// The fixed whitelist. Exactly the five tools docs/01 names. `mmc.exe <snap-in>.msc` for the two MMC
/// consoles; the other three are self-contained executables. Every path is a signed in-box Windows
/// binary, resolved under `%SystemRoot%` so a hijacked `PATH` cannot redirect the launch.
pub const TOOLS: &[ToolSpec] = &[
    ToolSpec { key: "task_manager", exe: r"System32\taskmgr.exe", args: &[], label: "Task Manager" },
    ToolSpec { key: "registry_editor", exe: r"regedit.exe", args: &[], label: "Registry Editor" },
    ToolSpec { key: "event_viewer", exe: r"System32\eventvwr.exe", args: &[], label: "Event Viewer" },
    ToolSpec { key: "services", exe: r"System32\mmc.exe", args: &[r"System32\services.msc"], label: "Services" },
    ToolSpec { key: "device_manager", exe: r"System32\mmc.exe", args: &[r"System32\devmgmt.msc"], label: "Device Manager" },
];

/// Resolve a wire key to its [`ToolSpec`], or `None` for anything not on the whitelist. This is the
/// security boundary: an unknown key, an empty string, or a path-traversal attempt all return `None`
/// and nothing is spawned. Pure so the table is pinned by a test.
pub fn resolve_tool(key: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.key == key)
}

/// Errors from a tool launch. Both are surfaced to the controller as a `ControlMessage::Error`.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// The key was not on the whitelist — nothing was spawned.
    #[error("unknown tool {0:?}")]
    UnknownTool(String),
    /// `CreateProcessW` failed for a whitelisted tool.
    #[error("could not launch {tool}: {source}")]
    Spawn {
        /// The tool label that failed to spawn.
        tool: &'static str,
        /// The underlying Win32 error.
        #[source]
        source: windows::core::Error,
    },
    /// The tool requires ELEVATION that this agent cannot obtain without the guest's consent.
    ///
    /// Its own variant rather than a `Spawn` carrying 0x2E4, because it is not a fault and the operator
    /// should not go looking for one: the two consoles that need elevation (Services, Device Manager)
    /// cannot be opened silently by an ATTENDED agent even when the guest is an administrator, since
    /// spawning a high-integrity process from a medium-integrity one without a UAC consent is precisely
    /// the escalation UAC exists to stop. A standard user reaches the same message for the simpler
    /// reason that they have no elevated rights at all.
    // One line, deliberately: a `\`-continued literal here reached the operator with the source's own
    // indentation embedded in it ("grant itself — have the          person at the machine").
    #[error("{tool} needs administrator elevation, which this session cannot grant itself; the person at the machine must open it (an unattended agent can, being SYSTEM)")]
    NeedsElevation {
        /// The tool label that needs elevation.
        tool: &'static str,
    },
}

/// Launches a whitelisted tool on the interactive desktop, or logs the intent without spawning (mock).
pub struct Launcher {
    real: bool,
    strategy: TokenStrategy,
}

/// How to obtain the token the tool is launched with. The two hosts differ; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStrategy {
    /// We are SYSTEM in the user's session (the unattended per-session helper): fetch the user's token
    /// with `WTSQueryUserToken`, which requires `SeTcbPrivilege`.
    FetchInteractiveUser,
    /// We ARE the interactive user already (the attended host): use our own token. No privileged call,
    /// and nothing to fetch — asking for someone else's token here fails with
    /// `ERROR_PRIVILEGE_NOT_HELD` because an administrator is not `SeTcbPrivilege`.
    OwnProcess,
}

/// The strategy for a host that is (or is not) the interactive user.
///
/// A pure function on purpose: it is the one decision that broke the attended path, and this way the
/// choice is stated by the caller and testable without a desktop, a session, or a privilege.
pub fn token_strategy(host_runs_as_interactive_user: bool) -> TokenStrategy {
    if host_runs_as_interactive_user {
        TokenStrategy::OwnProcess
    } else {
        TokenStrategy::FetchInteractiveUser
    }
}

impl Launcher {
    /// `real == true` in production; `false` on the `--log-input` / `--synthetic` dev+e2e paths, where
    /// [`Self::launch`] resolves + logs + returns Ok without spawning (so the gate never pops a tool).
    ///
    /// `host_runs_as_interactive_user` selects the [`TokenStrategy`]: false for the SYSTEM per-session
    /// helper, true for `agent_host attend`, which runs as the guest themselves.
    pub fn new(real: bool, host_runs_as_interactive_user: bool) -> Self {
        Self { real, strategy: token_strategy(host_runs_as_interactive_user) }
    }

    /// Resolve `key` against the whitelist and launch it. `Err(UnknownTool)` for an unknown key (the
    /// controller sees an `Error`), `Err(Spawn)` if `CreateProcessW` fails. On success returns the
    /// resolved [`ToolSpec`] so the caller can ack with the label/key.
    pub fn launch(&self, key: &str) -> Result<&'static ToolSpec, LaunchError> {
        let spec = resolve_tool(key).ok_or_else(|| LaunchError::UnknownTool(key.to_string()))?;
        if !self.real {
            tracing::warn!(tool = key, "launch: MOCK — would launch {} (not spawning; --log-input/--synthetic path)", spec.label);
            return Ok(spec);
        }
        launch_on_interactive_desktop(spec, self.strategy)?;
        tracing::info!(tool = key, "launch: spawned {} on the interactive desktop", spec.label);
        Ok(spec)
    }
}

/// `CreateProcessAsUserW` the tool onto `WinSta0\Default` **as the interactive user** (see the module
/// docs for why not as SYSTEM). `%SystemRoot%`-relative paths are made absolute so the launch does not
/// depend on the process's `PATH` or working directory.
fn launch_on_interactive_desktop(spec: &ToolSpec, strategy: TokenStrategy) -> Result<(), LaunchError> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_ELEVATION_REQUIRED, FALSE, HANDLE};
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken};
    use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetCurrentProcessId,
        OpenProcessToken, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let root = system_root();
    let exe = format!(r"{root}\{}", spec.exe);
    // Command line: "exe" "arg1" …, each arg also resolved under %SystemRoot%.
    let mut cmdline = format!("\"{exe}\"");
    for a in spec.args {
        cmdline.push_str(&format!(r#" "{root}\{a}""#));
    }
    // ERROR_ELEVATION_REQUIRED (0x2E4) is not a fault to debug — it is Windows declining to elevate
    // silently, and the operator needs to be told which situation they are in rather than shown a
    // hex code. It is REACHABLE on both hosts and for different reasons: a standard user simply has no
    // elevated rights, and an ATTENDED admin has them but cannot take them without a UAC consent this
    // agent has no sanctioned way to trigger (spawning a high-IL process from a medium-IL one without
    // consent is the local privilege escalation UAC exists to prevent).
    let map_err = |e: windows::core::Error| {
        if e.code() == windows::core::HRESULT::from_win32(ERROR_ELEVATION_REQUIRED.0) {
            return LaunchError::NeedsElevation { tool: spec.label };
        }
        LaunchError::Spawn { tool: spec.label, source: e }
    };

    // SAFETY: the helper runs in the interactive session; every out-param below is a stack local we
    // keep alive across its call, and every handle/allocation is released on both exit paths.
    unsafe {
        // Target THIS helper's OWN session, not the machine-global active console session. The helper
        // is a per-session process (spawned `--helper --session <id>`) and streams exactly its own
        // session; `WTSGetActiveConsoleSessionId` can point at a DIFFERENT session (an RDP session, or
        // a fast-user-switch in flight), which would open the tool on an uninvolved user's desktop
        // while the technician sees nothing. `ProcessIdToSessionId(self)` is that streamed session.
        // The user's primary token, obtained the way THIS host can obtain it (see TokenStrategy).
        let mut base = HANDLE::default();
        let own_token = match strategy {
            TokenStrategy::FetchInteractiveUser => {
                // SYSTEM helper: go and fetch the session's user token. Needs SeTcbPrivilege, which
                // SYSTEM has and an administrator does not. Fails if no user is logged in.
                let mut session_id: u32 = 0;
                ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id).map_err(map_err)?;
                WTSQueryUserToken(session_id, &mut base).map_err(map_err)?;
                false
            }
            TokenStrategy::OwnProcess => {
                // We ARE the user, in their session, on their desktop. Our own token is the right one,
                // and no privileged call is involved. TOKEN_QUERY|TOKEN_DUPLICATE is what
                // `linked_elevated_token` and CreateProcessAsUserW's duplication need.
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut base)
                    .map_err(map_err)?;
                true
            }
        };

        // Launch with the user's ELEVATED linked token when they are a UAC-filtered admin (so the
        // elevation-requiring consoles work), otherwise their base token. Never SYSTEM — see docs.
        let elevated = linked_elevated_token(base, strategy);
        let token = elevated.unwrap_or(base);

        // WHICH spawn. Switching identity needs `CreateProcessAsUserW`; running as ourselves does not.
        //
        //   * SYSTEM helper                  -> always AsUser (we are not the user).
        //   * attended + filtered admin      -> AsUser with the LINKED ELEVATED token, so the two
        //                                      elevation-requiring consoles still open.
        //   * attended, no elevated token    -> plain `CreateProcessW`. We are already the right user,
        //                                      in the right session, on the right desktop, with the
        //                                      right environment. Handing our own token back to
        //                                      CreateProcessAsUserW would be a more privileged call
        //                                      (it wants SeAssignPrimaryToken/SeIncreaseQuota) to
        //                                      achieve exactly nothing.
        let switch_identity = elevated.is_some() || !own_token;
        // The instrument. Which of the three routes ran is invisible from the outside — a tool that did
        // not appear could be any of them — and this loop spent two VM round trips distinguishing
        // 0x522 (wrong token strategy) from 0x542 (impersonation token, not primary) from 0x2E4
        // (elevation genuinely refused). One line makes the next one a log read.
        tracing::debug!(
            ?strategy,
            elevated = elevated.is_some(),
            switch_identity,
            tool = spec.key,
            "launch: token route chosen"
        );

        // The user's environment, needed only when we are switching identity: passing NULL to
        // CreateProcessAsUserW would inherit the SYSTEM helper's environment (%TEMP% under
        // systemprofile), running the user's tool with SYSTEM's paths — the opposite of this module's
        // least-privilege intent. A failure is FATAL rather than a silent fallback, for that reason.
        // When we are NOT switching identity our own environment is already the user's, so there is
        // nothing to build and nothing that can fail.
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        if switch_identity {
            if let Err(e) = CreateEnvironmentBlock(&mut env, token, FALSE) {
                if let Some(el) = elevated {
                    let _ = CloseHandle(el);
                }
                let _ = CloseHandle(base);
                return Err(map_err(e));
            }
        }

        let exe_w = wide(&exe);
        let mut cmd_w = wide(&cmdline);
        let mut desktop_w = wide(r"WinSta0\Default");
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = PWSTR(desktop_w.as_mut_ptr());
        let mut pi = PROCESS_INFORMATION::default();

        let res = if switch_identity {
            CreateProcessAsUserW(
                token,
                PCWSTR(exe_w.as_ptr()),
                PWSTR(cmd_w.as_mut_ptr()),
                None,
                None,
                FALSE,
                CREATE_UNICODE_ENVIRONMENT,
                Some(env),
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        } else {
            CreateProcessW(
                PCWSTR(exe_w.as_ptr()),
                PWSTR(cmd_w.as_mut_ptr()),
                None,
                None,
                FALSE,
                Default::default(),
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        };

        if !env.is_null() {
            let _ = DestroyEnvironmentBlock(env);
        }
        // Close the elevated linked token (a distinct handle) AND the base token.
        if let Some(e) = elevated {
            let _ = CloseHandle(e);
        }
        let _ = CloseHandle(base);
        res.map_err(map_err)?;
        // Handles from a successful CreateProcessAsUserW, closed exactly once.
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
    Ok(())
}

/// The interactive user's **full (elevated) linked token, duplicated to a PRIMARY token** when they are
/// a UAC-filtered admin, else `None`. Primary matters: `CreateProcessAsUserW` rejects the impersonation
/// token `TokenLinkedToken` returns. A standard user (or an already-elevated / UAC-off token) has no distinct elevated linked
/// token, so `None` means "use the base token" — never a rights upgrade the user does not already own.
///
/// **What `None` means to the caller is the caller's decision, and the two callers differ.** This
/// module treats it as "use the base token" (a launcher that cannot elevate should still open Task
/// Manager, and the elevation-requiring consoles then fail with the true reason,
/// `ERROR_ELEVATION_REQUIRED`). [`crate::command_run`] treats it as a hard refusal
/// (`CommandError::NotElevatable`), because there a silent downgrade would return an unelevated
/// result the technician cannot distinguish from an elevated one — after a single-use, audited
/// elevation grant was spent to ask for it. Do not "unify" those two readings.
///
/// # Safety
/// `base` must be a valid token handle. The returned handle (if any) is owned by the caller and must
/// be closed.
pub(crate) unsafe fn linked_elevated_token(
    base: windows::Win32::Foundation::HANDLE,
    strategy: TokenStrategy,
) -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::Security::{
        DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevationType,
        TokenElevationTypeLimited, TokenLinkedToken, TokenPrimary, TOKEN_ALL_ACCESS,
        TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN,
    };

    let mut elev = TOKEN_ELEVATION_TYPE::default();
    let mut ret = 0u32;
    GetTokenInformation(
        base,
        TokenElevationType,
        Some(&mut elev as *mut _ as *mut core::ffi::c_void),
        std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
        &mut ret,
    )
    .inspect_err(|e| tracing::debug!(error = %e, "launch: elevation-type query failed"))
    .ok()?;
    // Only a FILTERED admin has a separate elevated token worth fetching. TokenElevationTypeFull
    // (already elevated) and TokenElevationTypeDefault (standard user / UAC off) both mean "the base
    // token is already what this user can run as".
    if elev != TokenElevationTypeLimited {
        tracing::debug!(elevation_type = elev.0, "launch: no separate elevated token for this user");
        return None;
    }
    let mut linked = TOKEN_LINKED_TOKEN::default();
    GetTokenInformation(
        base,
        TokenLinkedToken,
        Some(&mut linked as *mut _ as *mut core::ffi::c_void),
        std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
        &mut ret,
    )
    .inspect_err(|e| tracing::debug!(error = %e, "launch: linked-token query failed"))
    .ok()?;
    // MUST be duplicated to a PRIMARY token. `TokenLinkedToken` hands back an IMPERSONATION token and
    // `CreateProcessAsUserW` requires a primary one, refusing the former with
    // `ERROR_BAD_IMPERSONATION_LEVEL` (0x542). SYSTEM's privileges had been hiding that: the moment the
    // ATTENDED host took this path as an ordinary administrator, every elevated launch failed 0x542.
    //
    // MEASURED OUTCOME on the attended host (LAB-VM, filtered-admin guest): the query above succeeds
    // and this duplication FAILS, so we return None and the caller uses the base token. That is the
    // right answer and not a workaround — an unelevated launch of an elevation-requiring console then
    // fails with ERROR_ELEVATION_REQUIRED, which is Windows declining to let a medium-integrity process
    // create a high-integrity one without consent. Falling back can therefore never grant MORE than the
    // user already has, which is this module's whole invariant.
    let mut primary = windows::Win32::Foundation::HANDLE::default();
    let dup = DuplicateTokenEx(
        linked.LinkedToken,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    );
    // The impersonation handle is ours either way — close it, and fall back to the base token if the
    // duplication failed (a filtered admin then simply gets their unelevated rights, which is the same
    // outcome a standard user gets and never MORE than the user has).
    match dup {
        Ok(()) => {
            let _ = windows::Win32::Foundation::CloseHandle(linked.LinkedToken);
            Some(primary)
        }
        Err(e) => {
            tracing::debug!(error = %e, ?strategy,
                "launch: linked token could not be duplicated to a primary token");
            match strategy {
                // PRESERVE THE PREVIOUSLY-VERIFIED BEHAVIOUR. Loops 26/27 VM-verified elevated tool
                // launches on the SYSTEM helper using this handle UNDUPLICATED — SYSTEM holds the
                // privileges that make `CreateProcessAsUserW` accept it. The duplication above is the
                // documented contract and is tried first, but if it ever fails here the old, proven
                // path is strictly better than losing elevation, so hand back the raw handle.
                TokenStrategy::FetchInteractiveUser => Some(linked.LinkedToken),
                // On the attended host the duplication DOES fail (measured: 0x542), and passing the raw
                // impersonation token on would just fail the same way two calls later — reported as an
                // opaque spawn error instead of the accurate "this needs elevation nobody can grant
                // silently". So give up the elevated token and let the base-token launch produce
                // ERROR_ELEVATION_REQUIRED, which is the true reason.
                TokenStrategy::OwnProcess => {
                    let _ = windows::Win32::Foundation::CloseHandle(linked.LinkedToken);
                    None
                }
            }
        }
    }
}

/// `%SystemRoot%`, defaulting to `C:\Windows` if the variable is unset OR empty/whitespace.
fn system_root() -> String {
    system_root_from(std::env::var("SystemRoot").ok().as_deref())
}

/// [`system_root`] with the raw variable injected, so the empty-string case is unit-tested. The empty
/// check matters: `std::env::var` returns `Ok("")` for an empty variable (not `Err`), and an empty
/// root would yield a drive-relative `\System32\taskmgr.exe` that resolves against the current drive's
/// working directory rather than the Windows install.
fn system_root_from(var: Option<&str>) -> String {
    match var {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => r"C:\Windows".to_string(),
    }
}

/// UTF-16, NUL-terminated (mirrors [`crate::sas::wide`], kept local to avoid a cross-module change).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_whitelist_resolves_exactly_the_five_named_tools() {
        // Each key maps to the right in-box binary. A wrong exe here would launch the wrong tool (or a
        // hijack if the path were relative), so the mapping is pinned exactly.
        assert_eq!(resolve_tool("task_manager").unwrap().exe, r"System32\taskmgr.exe");
        assert_eq!(resolve_tool("registry_editor").unwrap().exe, r"regedit.exe");
        assert_eq!(resolve_tool("event_viewer").unwrap().exe, r"System32\eventvwr.exe");
        // The two MMC consoles launch mmc.exe with their snap-in as the argument.
        let svc = resolve_tool("services").unwrap();
        assert_eq!(svc.exe, r"System32\mmc.exe");
        assert_eq!(svc.args, &[r"System32\services.msc"]);
        let dev = resolve_tool("device_manager").unwrap();
        assert_eq!(dev.exe, r"System32\mmc.exe");
        assert_eq!(dev.args, &[r"System32\devmgmt.msc"]);
        // The whitelist has exactly these five — nothing snuck in.
        assert_eq!(TOOLS.len(), 5);
    }

    #[test]
    fn unknown_keys_resolve_to_nothing() {
        // The security boundary: anything not on the whitelist — empty, a near-miss, a path-traversal
        // or an arbitrary exe — resolves to None and is never spawned.
        assert!(resolve_tool("").is_none());
        assert!(resolve_tool("taskmgr").is_none()); // near-miss, not the real key
        assert!(resolve_tool("cmd").is_none());
        assert!(resolve_tool(r"..\..\Windows\System32\cmd.exe").is_none());
        assert!(resolve_tool("System32\\calc.exe").is_none());
    }

    #[test]
    fn every_whitelist_key_is_unique_and_launchable() {
        // No duplicate keys (a duplicate would make resolve_tool's result order-dependent), and every
        // entry has a non-empty exe + label so a launch can always build a command line.
        let mut keys: Vec<&str> = TOOLS.iter().map(|t| t.key).collect();
        keys.sort_unstable();
        let unique = { let mut k = keys.clone(); k.dedup(); k.len() };
        assert_eq!(keys.len(), unique, "tool keys must be unique");
        for t in TOOLS {
            assert!(!t.exe.is_empty() && !t.label.is_empty(), "{} needs an exe + label", t.key);
        }
    }

    #[test]
    fn system_root_falls_back_on_unset_or_empty() {
        // A real value is used verbatim; unset OR empty/whitespace falls back to C:\Windows. The
        // empty case is the one that bites — env::var returns Ok("") not Err, and an empty root makes
        // the exe path drive-relative (`\System32\taskmgr.exe`), a PATH/cwd-hijackable launch.
        assert_eq!(system_root_from(Some(r"D:\Windows")), r"D:\Windows");
        assert_eq!(system_root_from(None), r"C:\Windows");
        assert_eq!(system_root_from(Some("")), r"C:\Windows");
        assert_eq!(system_root_from(Some("   ")), r"C:\Windows");
    }

    #[test]
    fn mock_launcher_resolves_but_never_spawns() {
        // A mock launcher still enforces the whitelist (unknown → Err) but spawns nothing for a valid
        // key — so a gate/e2e that sends LaunchTool gets its ack and no window opens.
        let l = Launcher::new(false, false);
        assert!(l.launch("task_manager").is_ok());
        assert!(matches!(l.launch("nope"), Err(LaunchError::UnknownTool(_))));
    }

    #[test]
    fn a_host_that_is_the_user_uses_its_own_token() {
        // THE REGRESSION, as a one-line decision. The attended host runs as the guest's own user, so
        // it must not call WTSQueryUserToken: that needs SeTcbPrivilege, an administrator does not
        // hold it, and every LaunchTool / RunCommand{as_user} on every attended session failed
        // ERROR_PRIVILEGE_NOT_HELD (0x522) because the code assumed the SYSTEM helper.
        assert_eq!(token_strategy(true), TokenStrategy::OwnProcess);
    }

    #[test]
    fn the_system_helper_still_fetches_the_users_token() {
        // The complement, and the half that keeps the fix honest: the SYSTEM per-session helper is NOT
        // the user, so it must still fetch their token. A change that made OwnProcess unconditional
        // would run the unattended technician's tools as SYSTEM — a local privilege escalation for the
        // guest, which is the thing this module's whole design exists to avoid.
        assert_eq!(token_strategy(false), TokenStrategy::FetchInteractiveUser);
    }

    #[test]
    fn the_launcher_records_the_strategy_its_host_asked_for() {
        // The flag has to survive the constructor: it is threaded from SessionOptions and read only
        // deep inside the (untestable) spawn, so this pins the one hop in between.
        assert_eq!(Launcher::new(true, true).strategy, TokenStrategy::OwnProcess);
        assert_eq!(Launcher::new(true, false).strategy, TokenStrategy::FetchInteractiveUser);
    }
}
