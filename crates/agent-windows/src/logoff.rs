//! Log off the interactive user on the guest — the remote-support "log off" (docs/01 §2 power
//! actions, alongside [`crate::lock`] and [`crate::reboot`]).
//!
//! # Why `WTSLogoffSession`, and which session
//!
//! `ExitWindowsEx(EWX_LOGOFF)` logs off the caller's session but behaves poorly from a service-spawned
//! process; `WTSLogoffSession` logs off a **named** session and is the robust primitive from SYSTEM.
//! The helper resolves ITS OWN session (`ProcessIdToSessionId(GetCurrentProcessId())`) — the exact
//! session it streams — rather than `WTSGetActiveConsoleSessionId`, for the same reason
//! [`crate::launch`] does: the active console session can be a *different* session mid fast-user-switch
//! or an RDP session, and logging that off would end an uninvolved user's session while the technician
//! sees nothing. Logging off the streamed session is precisely "log off the guest the technician is
//! looking at".
//!
//! We pass `bWait = FALSE`: the call returns immediately and the OS tears the session down
//! asynchronously (broadcasting `WM_QUERYENDSESSION`, then terminating), which leaves a window for the
//! `LogOffScheduled` ack to flush before the helper is killed — the same "reply before the session
//! drops" shape [`crate::reboot`] relies on. Once the session ends the streamed session drops and the
//! persistent SYSTEM service re-registers, so auto-reconnect re-establishes at the sign-in screen.
//!
//! # Safety: this must never fire during a test or a dev run
//!
//! Like [`crate::lock::Locker`] and [`crate::reboot::Rebooter`], the syscall is gated by a `real` flag.
//! The gate and Playwright e2e run a REAL agent on the CI box, so a real logoff would log the test
//! operator out mid-gate — [`Logoffer::new`] `false` (the `--synthetic` / `--log-input` paths) acks the
//! request WITHOUT logging anyone off. See `SessionOptions::mock_logoff`.

/// Logs off the guest's interactive session, or no-ops when built as a mock (synthetic / test agent).
#[derive(Debug, Clone, Copy)]
pub struct Logoffer {
    real: bool,
}

impl Logoffer {
    /// `real = true` calls `WTSLogoffSession`; `false` is the mock used by the synthetic/log-input agent.
    pub fn new(real: bool) -> Self {
        Self { real }
    }

    /// Log off the guest's interactive user. A mock logoffer returns `Ok(())` WITHOUT logging anyone
    /// off, so the gate/e2e never logs the operator out of the machine running the agent.
    pub fn logoff(&self) -> Result<(), String> {
        if !self.real {
            return Ok(());
        }
        #[cfg(windows)]
        {
            logoff_current_session()
        }
        #[cfg(not(windows))]
        {
            Err("WTSLogoffSession is Windows-only".to_string())
        }
    }
}

/// Resolve the helper's own streamed session and log it off (`bWait = FALSE`, so the call returns
/// before the session is torn down and the ack can flush). Windows-only.
#[cfg(windows)]
fn logoff_current_session() -> Result<(), String> {
    use windows::Win32::Foundation::FALSE;
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSLogoffSession, WTS_CURRENT_SERVER_HANDLE,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;

    // SAFETY: `session_id` is a stack local kept alive across the call; both APIs touch no caller
    // memory beyond that out-param. Target THIS helper's own streamed session (see module docs), not
    // the machine-global active console session.
    unsafe {
        let mut session_id: u32 = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id)
            .map_err(|e| format!("ProcessIdToSessionId failed: {e}"))?;
        WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, session_id, FALSE)
            .map_err(|e| format!("WTSLogoffSession(session {session_id}) failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_logoffer_never_touches_the_os() {
        // The gate and Playwright e2e run a REAL agent on the CI box; a mock logoffer MUST ack without
        // logging anyone off, or running the tests would end the operator's own session.
        assert!(
            Logoffer::new(false).logoff().is_ok(),
            "a mock logoff must succeed without side effects"
        );
    }
}
