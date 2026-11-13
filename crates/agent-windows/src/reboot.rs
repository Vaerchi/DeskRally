//! Reboot the guest machine on a technician's command — normal or **Safe Mode with Networking** —
//! and let auto-reconnect bring the session back (docs/01 P1 "Reboot guest (normal and Safe Mode)
//! with auto-reconnect"; docs/01 P1 "Safe Mode remote support").
//!
//! # Why this is a real feature and not one call
//!
//! An ordinary reboot is a single `InitiateSystemShutdownExW`. Safe Mode is the hard half, and it is
//! the one that matters for support (malware / broken-driver repair):
//!
//! 1. **Getting INTO Safe Mode.** The next boot's mode is a BCD element — `safeboot network`. The
//!    agent sets it with `bcdedit` *before* rebooting. Crucially this element is **sticky**: once set,
//!    every subsequent boot is Safe Mode until it is cleared. So a *normal* [`Rebooter::reboot`]
//!    always **clears** it first — a normal reboot is the guaranteed way back out, and this command
//!    can never strand a machine in Safe Mode.
//! 2. **Running the agent IN Safe Mode.** Safe Mode starts almost no services. Unless the service is
//!    registered under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\<service>`, it will not
//!    start, so nothing re-registers and the "with auto-reconnect" promise fails. The `Network`
//!    variant (Safe Mode *with Networking*) is the only one that can reconnect at all — no networking,
//!    no session. [`ensure_safeboot_service_registered`] writes that key idempotently at helper
//!    startup, so an already-installed agent gains it on the next start without a reinstall.
//!
//! # Safety: this must never fire during a test or a dev run
//!
//! [`Rebooter::new`] takes a `real` flag exactly like [`crate::input_block::InputBlocker`]. The
//! `--log-input` dev/e2e paths construct a **mock** rebooter that logs the intent and actuates
//! nothing, so the Playwright console e2e — and a local gate run — can exercise the whole
//! `RebootGuest → RebootScheduled` round-trip without rebooting the developer's box. Only the two
//! production call sites (`run_attend`, `run_helper_stream`) build a real one.
//!
//! # What is tested where
//!
//! The pure decision halves — the `bcdedit` argument vectors ([`safeboot_bcdedit_args`]), the
//! Safe-Mode registration decision ([`safeboot_registration_needed`]), and the `SM_CLEANBOOT`
//! interpretation ([`SafeBootKind::from_clean_boot`]) — are unit- and mutation-tested here with no
//! Win32 involved. The functions that touch the OS (`bcdedit`, the shutdown syscall, the registry)
//! can only be exercised on a live machine — the VM run recorded in docs/07.

use std::process::Command;

/// The SafeBoot registration branch the service is registered under. **Networking**, not Minimal:
/// a Safe-Mode agent with no network cannot reconnect, so a Minimal registration would boot the
/// machine into a mode the technician can never reach. Mirrors what [`safeboot_bcdedit_args`] sets.
const SAFEBOOT_NETWORK_PARENT: &str = r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network";

/// The value written under the per-service SafeBoot key so the SCM starts it in Safe Mode. The
/// documented convention: the key's **default** value is the string `"Service"`.
const SAFEBOOT_SERVICE_VALUE: &str = "Service";

/// The service name whose SafeBoot key this module manages. Kept equal to `host::SERVICE_NAME`
/// (asserted by a test) rather than importing it, so this module has no dependency on `host`'s
/// (large) surface.
const SERVICE_NAME: &str = "RmtAgent";

/// Which boot mode `GetSystemMetrics(SM_CLEANBOOT)` reports we are in. Used only for an observable
/// log line at startup (so a VM run can confirm from the agent's OWN log that it booted into Safe
/// Mode), which is why the mapping is pure and testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeBootKind {
    /// Normal boot (`SM_CLEANBOOT == 0`).
    Normal,
    /// Safe Mode, minimal (`SM_CLEANBOOT == 1`) — no networking; the agent cannot reconnect here.
    Minimal,
    /// Safe Mode with Networking (`SM_CLEANBOOT == 2`) — the mode [`Rebooter::reboot`] targets.
    Network,
}

impl SafeBootKind {
    /// Map the raw `SM_CLEANBOOT` return to a mode. Any unexpected non-`{0,1,2}` value is treated as
    /// [`SafeBootKind::Minimal`] — "some kind of safe mode" is the safe reading of an unknown nonzero,
    /// and it is never `Normal` unless the value is exactly `0`.
    pub fn from_clean_boot(clean_boot: i32) -> Self {
        match clean_boot {
            0 => SafeBootKind::Normal,
            2 => SafeBootKind::Network,
            _ => SafeBootKind::Minimal, // 1, or any unexpected nonzero
        }
    }

    /// `true` for any Safe-Mode variant (i.e. not [`SafeBootKind::Normal`]).
    pub fn is_safe(self) -> bool {
        self != SafeBootKind::Normal
    }
}

/// The `bcdedit` arguments to set (Safe Mode) or clear (normal) the next boot's `safeboot` element.
///
/// Pure so the exact argument vector is pinned by a test — a wrong verb here is a silently
/// wrong-mode reboot, which no runtime check downstream would catch.
///
/// * `safe_mode == true`  → `bcdedit /set {current} safeboot network` (Safe Mode **with Networking**).
/// * `safe_mode == false` → `bcdedit /deletevalue {current} safeboot` (ensure normal — clears any
///   sticky element a prior Safe-Mode reboot left).
pub fn safeboot_bcdedit_args(safe_mode: bool) -> Vec<&'static str> {
    if safe_mode {
        vec!["/set", "{current}", "safeboot", "network"]
    } else {
        vec!["/deletevalue", "{current}", "safeboot"]
    }
}

/// Whether the SafeBoot service registration needs to be (re)written, given the value currently under
/// the key (`None` if the key/value is absent). Pure + idempotent, mirroring
/// [`crate::sas::services_bit_update`]: returns `false` only when the exact `"Service"` value is
/// already present (case-insensitive, since the SCM matches it case-insensitively), so startup does
/// not churn the registry every boot.
pub fn safeboot_registration_needed(current: Option<&str>) -> bool {
    match current {
        Some(v) => !v.eq_ignore_ascii_case(SAFEBOOT_SERVICE_VALUE),
        None => true,
    }
}

/// Errors from the reboot path. Every variant is a reason the reboot did **not** happen, surfaced to
/// the controller as a `ControlMessage::Error` so the operator learns the command was rejected rather
/// than watching for a reboot that never comes.
#[derive(Debug, thiserror::Error)]
pub enum RebootError {
    /// Setting the `safeboot network` BCD element failed, so a Safe-Mode reboot would silently boot
    /// normally. Carries `bcdedit`'s captured output. (Only Safe Mode treats this as fatal; a normal
    /// reboot's *clear* is best-effort — see [`Rebooter::reboot`].)
    #[error("bcdedit failed: {0}")]
    BcdEdit(String),
    /// Enabling `SeShutdownPrivilege` on this process token failed (the privilege is not held, or the
    /// token could not be opened/adjusted).
    #[error("could not enable SeShutdownPrivilege: {0}")]
    Privilege(String),
    /// `InitiateSystemShutdownExW` itself failed.
    #[error("InitiateSystemShutdownExW failed: {0}")]
    Shutdown(#[source] windows::core::Error),
}

/// Grace period, in seconds, between the shutdown call and the actual reboot. Long enough for the
/// `RebootScheduled` ack to flush over the data channel and for the guest window to show its notice,
/// short enough that a support reboot feels immediate.
const REBOOT_GRACE_SECS: u32 = 5;

/// Actuates a guest reboot, or logs the intent without actuating (the mock).
///
/// Mirrors [`crate::input_block::InputBlocker`]: `real == false` is the `--log-input` test/dev path.
pub struct Rebooter {
    real: bool,
    /// Set once [`Self::shutdown`] really initiates a power-off. A power-off makes a later
    /// `InitiateSystemShutdownExW` return `ERROR_SHUTDOWN_IN_PROGRESS` — but, UNLIKE a pending reboot, a
    /// pending power-off does NOT consume the `safeboot` BCD element. So if a safe-mode reboot arrives in
    /// the shutdown's grace window and hits that error, [`Self::reboot`] must ROLL the element BACK (not
    /// preserve it, as it does for the double-reboot race) — otherwise the machine powers off with an
    /// unrequested `safeboot` set. This flag is what lets `reboot` tell the two cases apart.
    shutdown_initiated: std::sync::atomic::AtomicBool,
}

impl Rebooter {
    /// `real == true` in production (`run_attend` / `run_helper_stream`); `false` in the `--log-input`
    /// dev/e2e path, where [`Self::reboot`] logs and returns `Ok(())` without touching the machine.
    pub fn new(real: bool) -> Self {
        Self { real, shutdown_initiated: std::sync::atomic::AtomicBool::new(false) }
    }

    /// Set/clear the boot mode as needed and initiate the reboot. Returns `Ok(())` once the reboot is
    /// **scheduled** (the grace period is running); the caller sends `RebootScheduled` only then.
    ///
    /// Ordering and rollback (real path):
    /// 1. Point the next boot: Safe Mode → set `safeboot network` (**fatal on failure** — booting
    ///    normally when the operator asked for Safe Mode is a silent lie); normal → clear `safeboot`
    ///    (**best-effort** — if it was not set, `bcdedit /deletevalue` "fails" and that is fine).
    /// 2. Enable `SeShutdownPrivilege`.
    /// 3. `InitiateSystemShutdownExW(reboot, force, grace)`. If this fails **after** we set
    ///    `safeboot network`, roll the element back so a later organic reboot is not surprised into
    ///    Safe Mode.
    pub fn reboot(&self, safe_mode: bool) -> Result<(), RebootError> {
        if !self.real {
            tracing::warn!(
                safe_mode,
                "reboot: MOCK — would reboot the guest (not actuating; --log-input/dev path)"
            );
            return Ok(());
        }

        // 1. Point the next boot.
        if safe_mode {
            run_bcdedit(&safeboot_bcdedit_args(true))?; // fatal: wrong-mode reboot otherwise
        } else {
            // Clear any sticky `safeboot` element. When we are NOT in Safe Mode this is best-effort: a
            // machine with no element makes `/deletevalue` return non-zero, which is the desired end
            // state. But when we ARE in Safe Mode, clearing is the ONLY escape hatch, and a genuine
            // failure (BCD store locked, corrupt, access) would reboot the machine straight back into
            // Safe Mode while acking success — breaking this module's guarantee that a normal reboot
            // can never strand a machine there. `/deletevalue`'s exit code cannot tell "already clear"
            // from "failed to clear", so when in Safe Mode we VERIFY by read-back and fail the whole
            // command (the technician then sees an Error, not a false success) rather than reboot.
            let clear = run_bcdedit(&safeboot_bcdedit_args(false));
            if current_safe_boot_kind().is_safe() && safeboot_is_set() {
                let why = clear
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "bcdedit reported success but the element is still present".to_string());
                return Err(RebootError::BcdEdit(format!(
                    "in Safe Mode but the safeboot element could not be cleared (a normal reboot would re-enter Safe Mode): {why}"
                )));
            }
            if let Err(e) = clear {
                tracing::info!(error = %e, "reboot: clearing safeboot was a no-op (not in safe mode) — proceeding");
            }
        }

        // 2 + 3. Privilege, then the syscall — rolling back the Safe-Mode element if the syscall fails,
        // EXCEPT when a shutdown is already pending (rolling back then would clear the element the
        // in-flight reboot depends on — see `initiate_reboot`).
        if let Err(e) = enable_shutdown_privilege() {
            if safe_mode {
                rollback_safeboot();
            }
            return Err(e);
        }
        if let Err(e) = initiate_reboot(safe_mode) {
            let we_shut_down = self.shutdown_initiated.load(std::sync::atomic::Ordering::SeqCst);
            if should_rollback_safeboot(safe_mode, &e, we_shut_down) {
                rollback_safeboot();
            }
            return Err(e);
        }
        tracing::info!(safe_mode, grace_secs = REBOOT_GRACE_SECS, "reboot: scheduled");
        Ok(())
    }

    /// Initiate a forced **SHUTDOWN (power off)** — the remote-support "Shut Down" (docs/01 §2 power
    /// menu, the last of lock / log off / reboot / shut down). Same syscall machinery as [`Self::reboot`]
    /// MINUS the boot-mode management: a shutdown is orthogonal to `safeboot` (the machine is going OFF,
    /// not choosing a next boot mode), so it neither sets nor clears it. Unlike a reboot the agent will
    /// NOT come back on its own — the machine stays off until it is powered on — which is why this is the
    /// most destructive control action.
    ///
    /// `real == false` is the MOCK path: it logs and returns `Ok(())` without powering anything off. It
    /// is the SAME `real` flag [`Self::reboot`] uses, so `SessionOptions::mock_reboot` gates BOTH — a
    /// synthetic/`--log-input` agent (the gate + Playwright e2e run one on the CI box) can round-trip
    /// `ShutDownGuest → ShutDownScheduled` without powering off the operator's own machine.
    pub fn shutdown(&self) -> Result<(), RebootError> {
        if !self.real {
            tracing::warn!("shutdown: MOCK — would power off the guest (not actuating; --log-input/--synthetic path)");
            return Ok(());
        }
        enable_shutdown_privilege()?;
        initiate_shutdown()?;
        // A real power-off is now pending in the grace window — record it so a safe-mode reboot arriving
        // before it fires rolls `safeboot` back instead of leaving it set (see the field docs).
        self.shutdown_initiated.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::info!(grace_secs = REBOOT_GRACE_SECS, "shutdown: scheduled");
        Ok(())
    }
}

/// Best-effort clear of the `safeboot` element after a failed Safe-Mode reboot, so we do not leave a
/// sticky element that would surprise the next organic boot into Safe Mode.
fn rollback_safeboot() {
    if let Err(e) = run_bcdedit(&safeboot_bcdedit_args(false)) {
        tracing::warn!(error = %e, "reboot: could not roll back safeboot after a failed shutdown — the NEXT reboot may enter Safe Mode");
    }
}

/// Best-effort clear of the `safeboot` BCD element, called at UNINSTALL. Removing the agent must not
/// leave a machine that is in agent-set Safe Mode stranded with no agent left to clear the element
/// (a review finding). A no-op when nothing is set (`/deletevalue` returns non-zero, which is fine);
/// logged, never fatal — an uninstall completes regardless.
pub fn clear_safeboot_best_effort() {
    match run_bcdedit(&safeboot_bcdedit_args(false)) {
        Ok(()) => tracing::info!("uninstall: cleared the safeboot BCD element (machine will boot normally)"),
        Err(e) => tracing::info!(error = %e, "uninstall: no safeboot element to clear (or bcdedit unavailable)"),
    }
}

/// Whether the current boot entry has a `safeboot` element, read back from `bcdedit /enum {current}`.
///
/// A read failure returns `true` **conservatively**: if we cannot confirm the element is gone, the
/// normal-reboot escape hatch must refuse rather than risk rebooting straight back into Safe Mode.
fn safeboot_is_set() -> bool {
    let exe = bcdedit_path();
    match Command::new(&exe).args(["/enum", "{current}"]).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .to_ascii_lowercase()
            .contains("safeboot"),
        Err(e) => {
            tracing::warn!(error = %e, "reboot: could not read bcdedit to verify safeboot; assuming still set");
            true
        }
    }
}

/// `true` when `e` is `InitiateSystemShutdownExW` reporting a shutdown is **already pending**
/// (`ERROR_SHUTDOWN_IN_PROGRESS`, 1115). Its `safeboot` element must NOT then be rolled back: another
/// reboot is in flight and depends on it, and clearing it would silently downgrade an in-flight
/// Safe-Mode reboot to a normal one — the double-`RebootGuest` race a review surfaced.
fn is_shutdown_already_pending(e: &RebootError) -> bool {
    match e {
        RebootError::Shutdown(win) => (win.code().0 as u32 & 0xFFFF) == 1115,
        _ => false,
    }
}

/// Whether [`Rebooter::reboot`] should roll the `safeboot` element back after its shutdown syscall
/// FAILED. Pure so the three-way decision is pinned by a test.
///
/// * A **normal** reboot (`safe_mode == false`) set no element → never roll back.
/// * A **safe-mode** reboot that failed with anything other than "shutdown already pending" is a genuine
///   failure → roll back so the machine is not surprised into Safe Mode on a later organic boot.
/// * "Shutdown already pending" (`ERROR_SHUTDOWN_IN_PROGRESS`) is the ambiguous case:
///     - if it is a pending **reboot** (`we_initiated_shutdown == false`), that reboot will CONSUME the
///       `safeboot` element, so preserve it — the double-`RebootGuest` race.
///     - if WE initiated a **shutdown** (`we_initiated_shutdown == true`), the pending power-off does NOT
///       consume `safeboot`, so ROLL IT BACK — otherwise the machine powers off with an unrequested
///       `safeboot` set and boots Safe Mode on next power-on (the loop-42 shutdown-then-safe-reboot race).
pub fn should_rollback_safeboot(safe_mode: bool, err: &RebootError, we_initiated_shutdown: bool) -> bool {
    safe_mode && (!is_shutdown_already_pending(err) || we_initiated_shutdown)
}

/// Run `bcdedit` with `args`, mapping a non-zero exit (or a spawn failure) to [`RebootError::BcdEdit`]
/// with the captured output. Uses the absolute System32 path so it does not depend on the service's
/// `PATH` (and, on x64, is never redirected to SysWOW64).
fn run_bcdedit(args: &[&str]) -> Result<(), RebootError> {
    let exe = bcdedit_path();
    let output = Command::new(&exe)
        .args(args)
        .output()
        .map_err(|e| RebootError::BcdEdit(format!("spawn {exe}: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let mut msg = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let err = String::from_utf8_lossy(&output.stderr);
    if !err.trim().is_empty() {
        msg.push_str(err.trim());
    }
    Err(RebootError::BcdEdit(format!(
        "exit {:?}: {msg}",
        output.status.code()
    )))
}

/// Absolute path to `bcdedit.exe` under System32 (`%SystemRoot%\System32\bcdedit.exe`), falling back
/// to `C:\Windows\System32\...` if `SystemRoot` is somehow unset.
fn bcdedit_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\bcdedit.exe")
}

/// Enable `SeShutdownPrivilege` on the current process token. `InitiateSystemShutdownEx` needs it;
/// a SYSTEM service holds it but it must still be explicitly enabled in the token.
fn enable_shutdown_privilege() -> Result<(), RebootError> {
    use windows::core::w;
    use windows::Win32::Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: every pointer below is a stack local kept alive across its call; the token handle is
    // closed on both exit paths.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| RebootError::Privilege(format!("OpenProcessToken: {e}")))?;

        let mut luid = Default::default();
        let lookup = LookupPrivilegeValueW(None, w!("SeShutdownPrivilege"), &mut luid);
        if let Err(e) = lookup {
            let _ = windows::Win32::Foundation::CloseHandle(token);
            return Err(RebootError::Privilege(format!("LookupPrivilegeValueW: {e}")));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjust = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        // AdjustTokenPrivileges returns Ok even when the privilege was not actually assigned; the
        // real signal is GetLastError == ERROR_NOT_ALL_ASSIGNED.
        let not_assigned = GetLastError() == ERROR_NOT_ALL_ASSIGNED;
        let _ = windows::Win32::Foundation::CloseHandle(token);
        if let Err(e) = adjust {
            return Err(RebootError::Privilege(format!("AdjustTokenPrivileges: {e}")));
        }
        if not_assigned {
            return Err(RebootError::Privilege(
                "SeShutdownPrivilege is not held by this process".to_string(),
            ));
        }
    }
    Ok(())
}

/// Initiate a forced reboot with a short grace period. `bforceappsclosed = TRUE` so a hung app cannot
/// veto a support reboot; `brebootaftershutdown = TRUE` reboots rather than powering off.
fn initiate_reboot(safe_mode: bool) -> Result<(), RebootError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::TRUE;
    use windows::Win32::System::Shutdown::{
        InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_APPLICATION,
        SHTDN_REASON_MINOR_MAINTENANCE, SHUTDOWN_REASON,
    };

    let reason = SHUTDOWN_REASON(
        SHTDN_REASON_MAJOR_APPLICATION.0 | SHTDN_REASON_MINOR_MAINTENANCE.0 | SHTDN_REASON_FLAG_PLANNED.0,
    );
    let message = if safe_mode {
        w!("Remote support: rebooting into Safe Mode with Networking.")
    } else {
        w!("Remote support: rebooting this machine.")
    };
    // SAFETY: `message` is a static NUL-terminated wide literal; no caller memory is retained.
    unsafe {
        InitiateSystemShutdownExW(
            PCWSTR::null(),
            PCWSTR(message.as_ptr()),
            REBOOT_GRACE_SECS,
            TRUE, // bForceAppsClosed
            TRUE, // bRebootAfterShutdown
            reason,
        )
    }
    .map_err(RebootError::Shutdown)
}

/// Initiate a forced **power-off** with a short grace period. Identical to [`initiate_reboot`] except
/// `bRebootAfterShutdown = FALSE` — the machine powers off instead of rebooting.
fn initiate_shutdown() -> Result<(), RebootError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{FALSE, TRUE};
    use windows::Win32::System::Shutdown::{
        InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_APPLICATION,
        SHTDN_REASON_MINOR_MAINTENANCE, SHUTDOWN_REASON,
    };

    let reason = SHUTDOWN_REASON(
        SHTDN_REASON_MAJOR_APPLICATION.0 | SHTDN_REASON_MINOR_MAINTENANCE.0 | SHTDN_REASON_FLAG_PLANNED.0,
    );
    let message = w!("Remote support: shutting down this machine.");
    // SAFETY: `message` is a static NUL-terminated wide literal; no caller memory is retained.
    unsafe {
        InitiateSystemShutdownExW(
            PCWSTR::null(),
            PCWSTR(message.as_ptr()),
            REBOOT_GRACE_SECS,
            TRUE,  // bForceAppsClosed
            FALSE, // bRebootAfterShutdown = FALSE → power off
            reason,
        )
    }
    .map_err(RebootError::Shutdown)
}

/// The current boot mode, from `GetSystemMetrics(SM_CLEANBOOT)`. Logged once at helper startup so a
/// VM run can confirm a Safe-Mode boot from the agent's own log.
pub fn current_safe_boot_kind() -> SafeBootKind {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CLEANBOOT};
    // SAFETY: GetSystemMetrics takes a constant index and touches no caller memory.
    let raw = unsafe { GetSystemMetrics(SM_CLEANBOOT) };
    SafeBootKind::from_clean_boot(raw)
}

/// Ensure the service is registered to start under **Safe Mode with Networking**, so a
/// [`Rebooter::reboot`] into Safe Mode actually reconnects. Idempotent — mirrors
/// [`crate::sas::ensure_software_sas_enabled`]: reads the current value and writes only when it is not
/// already `"Service"`, so it does not churn the registry on every boot. Returns `Ok(true)` when it
/// wrote, `Ok(false)` when the registration was already present.
///
/// Requires write access to `HKLM\SYSTEM\...\SafeBoot\Network`, which SYSTEM has; a non-elevated dev
/// run gets an access-denied error, which the caller logs (Safe-Mode reboots simply will not
/// reconnect for that unusual configuration).
pub fn ensure_safeboot_service_registered() -> Result<bool, RebootError> {
    let current = read_safeboot_registration()?;
    if !safeboot_registration_needed(current.as_deref()) {
        return Ok(false);
    }
    write_safeboot_registration()?;
    Ok(true)
}

/// The full registry subkey for this service's SafeBoot registration.
fn safeboot_service_subkey() -> String {
    format!(r"{SAFEBOOT_NETWORK_PARENT}\{SERVICE_NAME}")
}

/// Read the default value under the SafeBoot service key, or `None` if the key/value is absent.
fn read_safeboot_registration() -> Result<Option<String>, RebootError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

    let subkey = wide(&safeboot_service_subkey());
    // Ask for the size first (data ptr None), then read into a buffer.
    let mut size: u32 = 0;
    // SAFETY: subkey is NUL-terminated UTF-16; a NULL data pointer requests just the size.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR::null(), // the (Default) value
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status.is_err() {
        return Err(RebootError::BcdEdit(format!(
            "RegGetValueW(size) failed: {:#x}",
            status.0
        )));
    }
    let mut buf = vec![0u16; (size as usize / 2).max(1)];
    let mut size2 = size;
    // SAFETY: buf holds `size2` bytes; RegGetValueW writes at most that many.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size2),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status.is_err() {
        return Err(RebootError::BcdEdit(format!(
            "RegGetValueW(read) failed: {:#x}",
            WIN32_ERROR(status.0).0
        )));
    }
    // Trim the trailing NUL(s) the API includes in the count.
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(Some(String::from_utf16_lossy(&buf[..end])))
}

/// Create the SafeBoot service key (creating each missing level) and set its default value to
/// `"Service"`.
fn write_safeboot_registration() -> Result<(), RebootError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let subkey = wide(&safeboot_service_subkey());
    let mut hkey = HKEY::default();
    // SAFETY: subkey is NUL-terminated UTF-16; we receive an owned key handle closed below.
    // RegCreateKeyExW opens the key if it already exists and creates every missing level.
    let create = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if create.is_err() {
        return Err(RebootError::BcdEdit(format!(
            "RegCreateKeyExW failed: {:#x}",
            WIN32_ERROR(create.0).0
        )));
    }

    // REG_SZ default value = "Service" (NUL-terminated wide bytes).
    let value = wide(SAFEBOOT_SERVICE_VALUE);
    let bytes = unsafe {
        std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2)
    };
    // SAFETY: hkey is a valid open key with KEY_SET_VALUE; a NULL value name is the (Default) value;
    // `bytes` describes the wide string including its terminator.
    let set = unsafe { RegSetValueExW(hkey, PCWSTR::null(), 0, REG_SZ, Some(bytes)) };
    // SAFETY: hkey was opened above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set.is_err() {
        return Err(RebootError::BcdEdit(format!(
            "RegSetValueExW failed: {:#x}",
            WIN32_ERROR(set.0).0
        )));
    }
    Ok(())
}

/// Remove the SafeBoot service key (best-effort), so an uninstall leaves nothing behind that would
/// register a now-absent service to start in Safe Mode.
pub fn remove_safeboot_registration() {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegDeleteTreeW, HKEY_LOCAL_MACHINE};
    let subkey = wide(&safeboot_service_subkey());
    // SAFETY: subkey is NUL-terminated UTF-16; deleting an absent key is a harmless error we ignore.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(subkey.as_ptr())) };
    if status.is_ok() {
        tracing::info!(key = %safeboot_service_subkey(), "reboot: removed SafeBoot service registration");
    }
}

/// UTF-16, NUL-terminated (mirrors [`crate::sas::wide`], kept local to avoid a cross-module
/// visibility change).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_mode_sets_network_and_normal_clears() {
        // Safe Mode: /set {current} safeboot network — the exact verb + element. A wrong verb here is
        // a silent wrong-mode reboot no downstream check catches, which is why this is pinned exactly.
        assert_eq!(
            safeboot_bcdedit_args(true),
            vec!["/set", "{current}", "safeboot", "network"]
        );
        // Normal: /deletevalue {current} safeboot — clears any sticky element so a normal reboot is
        // always the way back out of Safe Mode.
        assert_eq!(
            safeboot_bcdedit_args(false),
            vec!["/deletevalue", "{current}", "safeboot"]
        );
    }

    #[test]
    fn registration_needed_only_when_not_already_service() {
        // Absent → must write.
        assert!(safeboot_registration_needed(None));
        // Some other value → must (re)write.
        assert!(safeboot_registration_needed(Some("")));
        assert!(safeboot_registration_needed(Some("Driver")));
        // Already "Service" → no write (idempotence; the SCM matches case-insensitively, so neither
        // does churn the registry every boot).
        assert!(!safeboot_registration_needed(Some("Service")));
        assert!(!safeboot_registration_needed(Some("service")));
        assert!(!safeboot_registration_needed(Some("SERVICE")));
    }

    #[test]
    fn clean_boot_maps_to_the_right_mode() {
        // 0 = normal, 2 = safe-with-network (what we target); 1 and any other nonzero = "some safe
        // mode" (Minimal), never Normal.
        assert_eq!(SafeBootKind::from_clean_boot(0), SafeBootKind::Normal);
        assert_eq!(SafeBootKind::from_clean_boot(1), SafeBootKind::Minimal);
        assert_eq!(SafeBootKind::from_clean_boot(2), SafeBootKind::Network);
        assert_eq!(SafeBootKind::from_clean_boot(7), SafeBootKind::Minimal);
        // is_safe is the boundary the startup log branches on: only Normal is "not safe".
        assert!(!SafeBootKind::from_clean_boot(0).is_safe());
        assert!(SafeBootKind::from_clean_boot(1).is_safe());
        assert!(SafeBootKind::from_clean_boot(2).is_safe());
    }

    #[test]
    fn safeboot_subkey_names_this_service_under_network() {
        // The registration must land under SafeBoot\Network (with-networking), and name THIS service —
        // a Minimal registration or a wrong service name would silently never start in Safe Mode.
        assert_eq!(
            safeboot_service_subkey(),
            r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\RmtAgent"
        );
        // The constant must stay equal to host::SERVICE_NAME (this module hard-codes it to avoid a
        // dependency on host). If host's name ever changes, this catches the drift.
        assert_eq!(SERVICE_NAME, "RmtAgent");
    }

    #[test]
    fn shutdown_already_pending_only_matches_error_1115() {
        use windows::Win32::Foundation::WIN32_ERROR;
        // ERROR_SHUTDOWN_IN_PROGRESS (1115) on the Shutdown variant → true: a reboot is in flight, so
        // its safeboot element must NOT be rolled back (the double-RebootGuest race).
        let pending = RebootError::Shutdown(windows::core::Error::from(WIN32_ERROR(1115)));
        assert!(is_shutdown_already_pending(&pending));
        // A different shutdown error (e.g. access denied 5) is a real failure → rollback IS wanted.
        let other = RebootError::Shutdown(windows::core::Error::from(WIN32_ERROR(5)));
        assert!(!is_shutdown_already_pending(&other));
        // Non-shutdown variants never match — a bcdedit/privilege failure is not a pending shutdown.
        assert!(!is_shutdown_already_pending(&RebootError::BcdEdit("x".into())));
        assert!(!is_shutdown_already_pending(&RebootError::Privilege("x".into())));
    }

    #[test]
    fn rollback_safeboot_decision_distinguishes_pending_reboot_from_our_shutdown() {
        use windows::Win32::Foundation::WIN32_ERROR;
        let pending = RebootError::Shutdown(windows::core::Error::from(WIN32_ERROR(1115)));
        let real_fail = RebootError::Shutdown(windows::core::Error::from(WIN32_ERROR(5)));
        // A NORMAL reboot set no safeboot element — never roll back (nothing to undo).
        assert!(!should_rollback_safeboot(false, &pending, false));
        assert!(!should_rollback_safeboot(false, &pending, true));
        // Safe-mode reboot, "shutdown already pending" from a pending REBOOT (not our shutdown): PRESERVE
        // the element — the in-flight reboot consumes it (the double-RebootGuest race).
        assert!(!should_rollback_safeboot(true, &pending, false));
        // Safe-mode reboot, "shutdown already pending" but WE initiated a power-off (which does NOT consume
        // safeboot): ROLL BACK — the loop-42 shutdown-then-safe-reboot race. This is the whole fix; without
        // the `|| we_initiated_shutdown`, the machine would power off with an unrequested safeboot set.
        assert!(should_rollback_safeboot(true, &pending, true));
        // Safe-mode reboot, a genuine syscall failure (not 1115): always roll back, shutdown or not.
        assert!(should_rollback_safeboot(true, &real_fail, false));
        assert!(should_rollback_safeboot(true, &real_fail, true));
    }

    #[test]
    fn mock_rebooter_never_actuates() {
        // The whole safety story: a mock rebooter returns Ok without touching the machine, so a gate
        // run / e2e that sends RebootGuest gets its RebootScheduled ack and nothing reboots. (A real
        // rebooter cannot be unit-tested — it would reboot the test host.)
        let r = Rebooter::new(false);
        assert!(r.reboot(false).is_ok());
        assert!(r.reboot(true).is_ok());
    }

    #[test]
    fn mock_rebooter_shutdown_never_actuates() {
        // Same safety story for the more destructive shutdown: a mock rebooter acks `ShutDownScheduled`
        // without powering off, so a gate/e2e that sends ShutDownGuest never powers off the CI box. The
        // shared `real` flag means SessionOptions::mock_reboot gates shutdown too.
        assert!(Rebooter::new(false).shutdown().is_ok());
    }
}
