//! Secure Attention Sequence (Ctrl+Alt+Del) generation.
//!
//! Ctrl+Alt+Del is the one keystroke Windows will not let an application forge. `SendInput`'s
//! synthetic key events are dropped by Winlogon for this combination by design — that is the whole
//! point of a *secure* attention sequence — so [`InputEvent::Key`](rmt_agent_core::InputEvent)
//! cannot deliver it. The only supported primitive is `SendSAS` (`sas.dll`), which asks Winlogon to
//! raise the secure desktop itself.
//!
//! # The three preconditions `SendSAS` enforces (and how the agent meets them)
//!
//! 1. **Caller account.** `SendSAS(FALSE)` — "generate SAS as a service" — is only honored for a
//!    process running under **LocalSystem**. Both the service and its per-session helper are SYSTEM.
//! 2. **Caller session.** Verified on LAB-VM (docs/07): `SendSAS(FALSE)` raises the secure desktop
//!    when called from the **session-0 service**, and does *nothing* when called from the session-1
//!    per-session helper — even though that helper is also LocalSystem. `SendSAS(FALSE)` is a
//!    *service* primitive, and services live in session 0. The helper therefore does **not** call it
//!    directly: on a [`InputEvent::Sas`](rmt_agent_core::InputEvent) it signals the session-0 service
//!    ([`request_secure_attention`]), whose responder thread ([`run_sas_responder`]) makes the call
//!    from the context that works.
//! 3. **Machine policy.** Even for a session-0 LocalSystem service the call is silently a no-op unless
//!    the `SoftwareSASGeneration` policy grants software SAS to services. That policy lives at
//!    `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SoftwareSASGeneration`
//!    (a DWORD bitmask: bit `0x1` = **Services**, bit `0x2` = Ease-of-Access apps). Absent or `0`,
//!    nothing happens — which is precisely why the checklist item read "SendSAS appears in no
//!    crate": the plumbing to *enable* it was never there.
//!
//! [`ensure_software_sas_enabled`] sets the Services bit at helper startup (idempotently, and
//! without clobbering an administrator's Ease-of-Access bit), so that by the time a controller
//! presses Ctrl+Alt+Del the policy is already in force.
//!
//! # The session-0 hop
//!
//! The service creates a named auto-reset event ([`SAS_EVENT_NAME`], in the `Global\` namespace so
//! it is visible across sessions) and a [`run_sas_responder`] thread that blocks on it and calls
//! `SendSAS` whenever it is signaled. The helper's [`request_secure_attention`] opens that event and
//! signals it. Both processes are SYSTEM, so the event's default DACL already permits the open. If
//! the event does not exist (e.g. the elevated `stream` dev CLI, which has no companion service),
//! `request_secure_attention` falls back to a direct call — best effort, since that path is not the
//! service context and may itself no-op.
//!
//! The pure bit-twiddling half ([`services_bit_update`]) is unit-tested here with no registry or
//! Win32 involved; the functions that touch the OS can only be exercised on a live machine (the VM
//! run recorded in docs/07).

/// Name of the cross-session event the helper signals to ask the **service** to generate the SAS.
/// `Global\` so a session-1 helper and the session-0 service name the same object.
pub const SAS_EVENT_NAME: &str = r"Global\RmtAgentSasRequest";

/// The `SoftwareSASGeneration` bit that authorizes **services** (a LocalSystem service calling
/// `SendSAS(FALSE)`) to generate a software SAS. Bit `0x2` is the Ease-of-Access bit, which we
/// never touch.
pub const SAS_SERVICES_BIT: u32 = 0x1;

/// Decide how to update the `SoftwareSASGeneration` policy so the **Services** bit is set.
///
/// Pure and total so the policy logic is testable without a registry:
/// * `current` is the DWORD already present (`None` if the value does not exist yet).
/// * Returns `Some(new_value)` if a write is needed, or `None` if the Services bit is already set
///   and nothing should be written.
///
/// Crucially this OR-merges rather than overwriting: if an administrator has enabled the
/// Ease-of-Access bit (`0x2`), we preserve it and add `0x1`, rather than stomping the policy down to
/// a bare `0x1`.
pub fn services_bit_update(current: Option<u32>) -> Option<u32> {
    let existing = current.unwrap_or(0);
    if existing & SAS_SERVICES_BIT != 0 {
        // Services bit already present — nothing to do (whatever else is set, leave it).
        return None;
    }
    Some(existing | SAS_SERVICES_BIT)
}

/// Errors from the SAS policy/generation path. `SendSAS` itself returns `void` and cannot report
/// failure, so the only fallible piece is the registry write.
#[derive(Debug, thiserror::Error)]
pub enum SasError {
    /// A Win32 registry call failed while reading or writing the policy value.
    #[error("SoftwareSASGeneration registry access failed: {0}")]
    Registry(#[source] windows::core::Error),
}

/// Registry location of the software-SAS policy.
const POLICY_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const POLICY_VALUE: &str = "SoftwareSASGeneration";

/// Ensure `SoftwareSASGeneration` grants software SAS to **services**, so a later
/// [`send_secure_attention`] from this LocalSystem helper is honored.
///
/// Reads the current DWORD (via [`read_policy`]), and if the Services bit is missing writes it back
/// OR-merged with whatever was there ([`services_bit_update`]). Idempotent: on the common path where
/// the bit is already set it performs no write and returns `Ok(false)`. Returns `Ok(true)` when it
/// wrote the value.
///
/// Requires write access to `HKLM\...\Policies\System`, which SYSTEM and Administrators have. A
/// non-elevated `stream`-CLI run will get an access-denied [`SasError::Registry`]; that is surfaced
/// (and logged by the caller) rather than hidden, because without the policy SAS silently won't
/// work.
pub fn ensure_software_sas_enabled() -> Result<bool, SasError> {
    let current = read_policy()?;
    match services_bit_update(current) {
        None => Ok(false),
        Some(new_value) => {
            write_policy(new_value)?;
            Ok(true)
        }
    }
}

/// Read the current `SoftwareSASGeneration` DWORD, or `None` if the value does not exist.
///
/// A missing *value* (or missing key) is `Ok(None)`, not an error — a machine that never had the
/// policy is the normal fresh-install case. Only a genuine access failure surfaces as
/// [`SasError::Registry`].
fn read_policy() -> Result<Option<u32>, SasError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, WIN32_ERROR};
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

    let value = wide(POLICY_VALUE);
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `data`/`size` describe one owned 4-byte stack value; RegGetValueW writes at most
    // `size` bytes into it. Both the subkey path and the value name are NUL-terminated UTF-16.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    if status.is_ok() {
        return Ok(Some(data));
    }
    // A value/key that simply isn't there is the fresh-install case, not a failure.
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    Err(SasError::Registry(windows::core::Error::from(WIN32_ERROR(status.0))))
}

/// Write `value` to `SoftwareSASGeneration`, creating the `Policies\System` subkey if absent.
fn write_policy(value: u32) -> Result<(), SasError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    let subkey = wide(POLICY_SUBKEY);
    let value_name = wide(POLICY_VALUE);
    let mut hkey = HKEY::default();
    // SAFETY: `subkey` is NUL-terminated UTF-16; we pass no class/security and receive an owned key
    // handle we close below. RegCreateKeyExW opens the key if it already exists.
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
        return Err(SasError::Registry(windows::core::Error::from(WIN32_ERROR(create.0))));
    }

    let bytes = value.to_ne_bytes();
    // SAFETY: `hkey` is a valid open key with KEY_SET_VALUE; `value_name` is NUL-terminated UTF-16;
    // `bytes` is a 4-byte buffer matching REG_DWORD.
    let set = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            0,
            REG_DWORD,
            Some(&bytes),
        )
    };
    // SAFETY: `hkey` was opened by the RegCreateKeyExW above and is closed exactly once here.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set.is_err() {
        return Err(SasError::Registry(windows::core::Error::from(WIN32_ERROR(set.0))));
    }
    Ok(())
}

/// Generate the Secure Attention Sequence (Ctrl+Alt+Del) via `SendSAS` **from this process**.
///
/// Passes `FALSE` ("as a service"). This only has an effect from the **session-0 LocalSystem
/// service** context (see the module docs) and when [`ensure_software_sas_enabled`] has set the
/// Services policy bit; `SendSAS` returns `void` and cannot report a no-op. The session-1 helper
/// must NOT call this — it routes through [`request_secure_attention`] instead. Public because the
/// service's [`run_sas_responder`] and the dev-CLI fallback both call it.
pub fn send_secure_attention() {
    use windows::Win32::Foundation::FALSE;
    use windows::Win32::Security::Authentication::Identity::SendSAS;
    // SAFETY: `SendSAS` takes a single BOOL by value and touches no caller memory. It is safe to
    // call from any thread; whether it has an effect is governed by process context + policy, not
    // by anything we pass.
    unsafe { SendSAS(FALSE) };
}

/// Ask the session-0 service to generate the SAS by signaling [`SAS_EVENT_NAME`].
///
/// This is what the per-session helper calls on an [`InputEvent::Sas`](rmt_agent_core::InputEvent):
/// the helper is in session 1, where `SendSAS(FALSE)` does nothing, so it hands the request to the
/// service's [`run_sas_responder`] (session 0) instead. If the event cannot be opened — no companion
/// service is running, e.g. the elevated `stream` dev CLI — it falls back to a direct
/// [`send_secure_attention`] as a best effort (that path may itself no-op, but it is better than
/// dropping the request silently, and it is logged by the returned discriminant).
///
/// Returns `true` if the service was signaled, `false` if it fell back to the direct call.
pub fn request_secure_attention() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenEventW, EVENT_MODIFY_STATE};
    use windows::Win32::System::Threading::SetEvent;

    let name = wide(SAS_EVENT_NAME);
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; a failure to open
    // (the service is not running) is an `Err`, not UB.
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(name.as_ptr())) };
    match handle {
        Ok(h) => {
            // SAFETY: `h` is a valid event handle we own; SetEvent signals it, then we close it.
            unsafe {
                let _ = SetEvent(h);
                let _ = CloseHandle(h);
            }
            true
        }
        Err(_) => {
            // No service responder reachable — best-effort direct call (logged by the caller).
            send_secure_attention();
            false
        }
    }
}

/// Service-side (session 0) SAS responder: own the named event and call `SendSAS` on each signal.
///
/// Creates [`SAS_EVENT_NAME`] as an **auto-reset** event (so each signal fires exactly one SAS and a
/// burst coalesces rather than stacking secure-desktop switches), then loops: wait up to 500 ms,
/// generate the SAS on a signal, and otherwise re-check `stop`. Returns when `stop` is set or if the
/// event cannot be created. Intended to run on a dedicated thread spawned by the service main; the
/// call that matters — `SendSAS` — therefore happens in the session-0 service context that LAB-VM
/// proved is the one Windows honors.
pub fn run_sas_responder(stop: &std::sync::atomic::AtomicBool) {
    use std::mem::size_of;
    use std::sync::atomic::Ordering;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, FALSE, HLOCAL, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    // DACL granting ONLY LocalSystem (`SY`) EVENT_ALL_ACCESS (0x1F0003). The sole legitimate signaler
    // is the SYSTEM helper, so locking the event to SYSTEM means no lower-privileged or sibling-
    // service process can open it to force a secure-desktop switch. Together with the
    // ERROR_ALREADY_EXISTS refusal below, this also pins the reset type to OUR auto-reset object,
    // closing the "squatted manual-reset event → SendSAS storm" gap a review raised.
    let sddl = wide("D:(A;;0x1F0003;;;SY)");
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated UTF-16 outliving the call; on success `psd` receives a
    // LocalAlloc'd descriptor that we LocalFree once, after CreateEventW has copied it into the object.
    if let Err(e) = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    } {
        tracing::warn!(error = %e, "sas: could not build responder event ACL; Ctrl+Alt+Del disabled");
        return;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: FALSE,
    };

    let name = wide(SAS_EVENT_NAME);
    // Auto-reset (manual_reset = FALSE), initially unset. Named in Global\ so the helper can open it.
    // SAFETY: `sa`/`psd` outlive the call; `name` is NUL-terminated UTF-16.
    let created = unsafe { CreateEventW(Some(&sa), false, false, PCWSTR(name.as_ptr())) };
    // Read the last error BEFORE any other call: LocalFree below may overwrite it.
    // SAFETY: no arguments.
    let already_existed = created.is_ok() && unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    // The kernel copied the descriptor into the object at creation; free our local copy now.
    // SAFETY: `psd.0` came from ConvertStringSecurityDescriptorToSecurityDescriptorW (LocalAlloc);
    // freed exactly once.
    unsafe {
        let _ = LocalFree(HLOCAL(psd.0));
    }

    let event = match created {
        Ok(h) => {
            // ERROR_ALREADY_EXISTS ⇒ the named object pre-existed, so it is NOT the one we just tried
            // to create: its reset type (and DACL) were fixed by whoever created it first. Refuse to
            // adopt it rather than run the wait loop against an object of unknown provenance.
            if already_existed {
                // SAFETY: `h` is a handle we own; closed exactly once here.
                unsafe {
                    let _ = CloseHandle(h);
                }
                tracing::warn!(
                    event = SAS_EVENT_NAME,
                    "sas: responder event already existed (unexpected) — Ctrl+Alt+Del disabled"
                );
                return;
            }
            h
        }
        Err(e) => {
            tracing::warn!(error = %e, "sas: could not create responder event; Ctrl+Alt+Del disabled");
            return;
        }
    };
    tracing::info!(event = SAS_EVENT_NAME, "sas: responder ready (session-0 SendSAS)");

    while !stop.load(Ordering::SeqCst) {
        // SAFETY: `event` is a live handle we own; the 500 ms bound lets the loop observe `stop`.
        let wait = unsafe { WaitForSingleObject(event, 500) };
        if wait == WAIT_OBJECT_0 {
            tracing::info!("sas: request received — generating secure attention sequence");
            send_secure_attention();
        }
    }
    // SAFETY: `event` owned by this thread, closed exactly once as the loop exits.
    unsafe {
        let _ = CloseHandle(event);
    }
}

/// UTF-16, NUL-terminated (mirrors [`crate::service::wide`], kept local to avoid a cross-module
/// visibility change).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_the_services_bit_when_absent() {
        // Fresh machine: value does not exist → write bare Services bit.
        assert_eq!(services_bit_update(None), Some(SAS_SERVICES_BIT));
        // Value present but zeroed (policy explicitly "None") → write Services bit.
        assert_eq!(services_bit_update(Some(0)), Some(0x1));
    }

    #[test]
    fn preserves_the_ease_of_access_bit() {
        // Admin enabled Ease-of-Access (0x2) only: we must OR in 0x1, NOT overwrite to 0x1 and lose
        // their setting. The regression this guards: a naive `set 1` would disable EoA SAS.
        assert_eq!(services_bit_update(Some(0x2)), Some(0x3));
    }

    #[test]
    fn no_write_when_services_bit_already_set() {
        // Both the bare Services value and the "both" value already satisfy the requirement, so no
        // write is issued (idempotence — the startup call must not churn the registry every boot).
        assert_eq!(services_bit_update(Some(0x1)), None);
        assert_eq!(services_bit_update(Some(0x3)), None);
        // An unexpected high bit that still includes 0x1 is also left untouched.
        assert_eq!(services_bit_update(Some(0x1 | 0x4)), None);
    }
}
