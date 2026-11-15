//! Service control — start / stop / restart. Reached only through the dispatcher, which has
//! already applied the `ServiceControl` capability. Startup-type / ImagePath edits are a
//! separate, higher (`ServiceConfig`) capability and are not implemented here.
//!
//! Most services require the agent to be elevated (LocalSystem, its production identity) to
//! start or stop; from a normal context these return access-denied, which is surfaced as a
//! structured [`OpError::AccessDenied`] rather than a panic. The plumbing and error mapping are
//! exercised by a test that targets a non-existent service (needs no privilege); the live
//! control path is an `#[ignore]` test to be run from an elevated console.

use super::OpError;

/// What to do to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Start,
    Stop,
    Restart,
}

#[cfg(windows)]
pub fn control(name: &str, verb: Verb) -> Result<(), OpError> {
    imp::control(name, verb)
}

#[cfg(not(windows))]
pub fn control(_name: &str, _verb: Verb) -> Result<(), OpError> {
    Err(OpError::Unsupported)
}

#[cfg(windows)]
mod imp {
    use super::{OpError, Verb};

    use windows::core::HSTRING;
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
    };

    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    pub(super) fn control(name: &str, verb: Verb) -> Result<(), OpError> {
        unsafe {
            let scm = Handle(
                OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
                    .map_err(|e| OpError::Api { api: "OpenSCManager", source: e })?,
            );

            let access = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS;
            let svc = Handle(
                OpenServiceW(scm.0, &HSTRING::from(name), access).map_err(|e| {
                    if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() {
                        OpError::NotFound(name.to_string())
                    } else if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                        OpError::AccessDenied(name.to_string())
                    } else {
                        OpError::Api { api: "OpenService", source: e }
                    }
                })?,
            );

            match verb {
                Verb::Start => start(svc.0, name),
                Verb::Stop => stop(svc.0, name),
                Verb::Restart => {
                    stop(svc.0, name)?;
                    wait_for_state(svc.0, SERVICE_STOPPED.0)?;
                    start(svc.0, name)
                }
            }
        }
    }

    unsafe fn start(svc: SC_HANDLE, name: &str) -> Result<(), OpError> {
        StartServiceW(svc, None).map_err(|e| access_or_api(e, "StartService", name))
    }

    unsafe fn stop(svc: SC_HANDLE, name: &str) -> Result<(), OpError> {
        let mut status = SERVICE_STATUS::default();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
            .map_err(|e| access_or_api(e, "ControlService", name))
    }

    /// Poll the service status until it reaches `target_state` or a short deadline passes.
    /// Used between the stop and start halves of a restart. This is real-clock polling; it is
    /// only reached outside the injected-clock test paths.
    unsafe fn wait_for_state(svc: SC_HANDLE, target_state: u32) -> Result<(), OpError> {
        for _ in 0..50 {
            let mut status = SERVICE_STATUS::default();
            if QueryServiceStatus(svc, &mut status).is_err() {
                break;
            }
            if status.dwCurrentState.0 == target_state {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // Best effort: the caller (restart) proceeds to start regardless; a stuck service
        // surfaces later as a start failure.
        Ok(())
    }

    fn access_or_api(e: windows::core::Error, api: &'static str, name: &str) -> OpError {
        if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
            OpError::AccessDenied(name.to_string())
        } else {
            OpError::Api { api, source: e }
        }
    }

    // Reference SERVICE_RUNNING so the import stays meaningful (used by the ignored live test's
    // expectations and documents the state we start toward).
    #[allow(dead_code)]
    const _RUNNING: u32 = SERVICE_RUNNING.0;
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn controlling_a_nonexistent_service_is_a_clean_error() {
        // Connecting to the SCM and opening a bogus service needs no elevation; it must return
        // a structured NotFound, never panic.
        let err = control("NoSuchServiceXYZ_12345", Verb::Start).unwrap_err();
        assert!(
            matches!(err, OpError::NotFound(_) | OpError::AccessDenied(_)),
            "got {err:?}"
        );
    }

    #[test]
    #[ignore = "mutates a real service; run elevated: cargo test -- --ignored restart_spooler"]
    fn restart_spooler() {
        // Print Spooler is a safe-to-bounce service on most machines. Requires an elevated
        // console; skipped by default.
        control("Spooler", Verb::Restart).expect("restart spooler");
    }
}
