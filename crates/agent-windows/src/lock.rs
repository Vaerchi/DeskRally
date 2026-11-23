//! Lock the guest workstation — the remote-support "lock" (docs/01 §1).
//!
//! `LockWorkStation` locks the session of the CALLING process, so it only has a visible effect from a
//! process in the INTERACTIVE session — which the per-session helper is (the streaming + control
//! dispatch run there). Called from a session-0 service it would lock nothing, the exact reason
//! `scripts/vmlab/guest-lock.ps1` reaches the interactive session via a scheduled task rather than
//! calling `LockWorkStation` from PowerShell Direct (which lands in session 0).
//!
//! Like [`crate::reboot::Rebooter`], the actual syscall is gated by a `real` flag so the synthetic /
//! `--log-input` agent the gate and Playwright e2e run — a REAL agent on the CI box — never locks the
//! test operator's own session: a mock [`Locker`] acks the request without touching the OS.

#[cfg(windows)]
use windows::Win32::System::Shutdown::LockWorkStation;

/// Locks the guest workstation, or no-ops when built as a mock (synthetic / test agent).
#[derive(Debug, Clone, Copy)]
pub struct Locker {
    real: bool,
}

impl Locker {
    /// `real = true` calls `LockWorkStation`; `false` is the mock used by the synthetic/log-input agent.
    pub fn new(real: bool) -> Self {
        Self { real }
    }

    /// Lock the workstation (Win+L). A mock locker returns `Ok(())` WITHOUT locking anything, so the
    /// gate/e2e never locks the machine running it.
    pub fn lock(&self) -> Result<(), String> {
        if !self.real {
            return Ok(());
        }
        // SAFETY: LockWorkStation takes no arguments and is always safe to call; the windows crate
        // wraps its BOOL return as a Result (nonzero = success).
        #[cfg(windows)]
        {
            unsafe { LockWorkStation() }.map_err(|e| format!("LockWorkStation failed: {e}"))
        }
        #[cfg(not(windows))]
        {
            Err("LockWorkStation is Windows-only".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_locker_never_touches_the_os() {
        // The gate and Playwright e2e run a REAL agent on the CI box; a mock locker MUST ack without
        // locking, or running the tests would lock the operator's own session.
        assert!(Locker::new(false).lock().is_ok(), "a mock lock must succeed without side effects");
    }
}
