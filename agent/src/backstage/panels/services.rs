//! Service panel — the read-only Windows service list a technician sees, rendered natively in
//! the browser (no remoted pixels), the same way the [`super::process`] panel works.
//!
//! Requires [`crate::backstage::rbac::Capability::ServiceList`]. Start/stop/restart lives
//! behind `ServiceControl`, and startup-type/ImagePath edits behind `ServiceConfig` + the
//! guard rail; this module is list-only.
//!
//! Enumeration is `OpenSCManager` + `EnumServicesStatusExW` (SC_ENUM_PROCESS_INFO), which
//! yields the display name, current state, start type, and — for running services — the host
//! PID. `SC_MANAGER_ENUMERATE_SERVICE` is grantable to non-elevated callers, so this reads
//! without the agent needing to be LocalSystem; the config/PID detail is best-effort and rows
//! carry `Option`s so the UI shows "—" rather than lying.

use serde::{Deserialize, Serialize};

/// One row in the service table. Shaped for direct JSON rendering in the technician UI, and
/// portable (the type is available on every platform even though enumeration is Windows-only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceRow {
    /// The service's registry key name (what `sc`/`Start-Service` take).
    pub name: String,
    /// Human-friendly name shown in services.msc.
    pub display_name: String,
    pub state: ServiceState,
    /// PID of the hosting process when running; `None` when stopped or not readable.
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    /// A state code the OS reported that we don't have a name for.
    Unknown,
}

/// Enumerate Win32 services. Real data on Windows; an empty list on other platforms (this is a
/// Windows-only capability — the type stays portable so the dispatcher/`Response` compile
/// everywhere).
#[cfg(windows)]
pub fn snapshot() -> Vec<ServiceRow> {
    imp::snapshot().unwrap_or_default()
}

#[cfg(not(windows))]
pub fn snapshot() -> Vec<ServiceRow> {
    Vec::new()
}

#[cfg(windows)]
mod imp {
    use super::{ServiceRow, ServiceState};

    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CONTINUE_PENDING,
        SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATE_ALL, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_WIN32,
    };

    /// RAII guard so the SCM handle is always closed, including on the error paths.
    struct ScmHandle(windows::Win32::System::Services::SC_HANDLE);
    impl Drop for ScmHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    pub(super) fn snapshot() -> Option<Vec<ServiceRow>> {
        unsafe {
            // Read-only enumeration right; grantable without full admin.
            let scm = ScmHandle(OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE).ok()?);

            // Two-call idiom: the first call fails with ERROR_MORE_DATA and reports the exact
            // byte count needed, which we then allocate and fill.
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;
            let mut resume: u32 = 0;

            let probe = EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            );
            // Expected to fail asking for buffer space; a genuine empty machine sets needed = 0.
            if probe.is_ok() || needed == 0 {
                return Some(Vec::new());
            }

            let mut buf = vec![0u8; needed as usize];
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(buf.as_mut_slice()),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
            .ok()?;

            // The buffer is an array of ENUM_SERVICE_STATUS_PROCESSW; the name pointers point
            // back into the same buffer (past the struct array).
            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                returned as usize,
            );

            let mut rows: Vec<ServiceRow> = entries
                .iter()
                .map(|e| {
                    let status = &e.ServiceStatusProcess;
                    let pid = status.dwProcessId;
                    ServiceRow {
                        name: pwstr_to_string(e.lpServiceName.0),
                        display_name: pwstr_to_string(e.lpDisplayName.0),
                        state: map_state(status.dwCurrentState),
                        // dwProcessId is 0 for a service that isn't currently running.
                        pid: if pid != 0 { Some(pid) } else { None },
                    }
                })
                .collect();

            // Stable, useful default ordering: running first, then alphabetical by display name.
            rows.sort_by(|a, b| {
                let rank = |s: ServiceState| if s == ServiceState::Running { 0 } else { 1 };
                rank(a.state).cmp(&rank(b.state)).then_with(|| {
                    a.display_name.to_ascii_lowercase().cmp(&b.display_name.to_ascii_lowercase())
                })
            });
            Some(rows)
        }
    }

    fn map_state(state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE) -> ServiceState {
        match state {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_START_PENDING => ServiceState::StartPending,
            SERVICE_STOP_PENDING => ServiceState::StopPending,
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
            SERVICE_PAUSE_PENDING => ServiceState::PausePending,
            SERVICE_PAUSED => ServiceState::Paused,
            _ => ServiceState::Unknown,
        }
    }

    /// Read a null-terminated wide string that the API wrote into our buffer.
    unsafe fn pwstr_to_string(p: *mut u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_lists_real_services() {
        let rows = snapshot();
        assert!(!rows.is_empty(), "a running Windows machine always has services");

        // Every row has both names populated.
        assert!(rows.iter().all(|r| !r.name.is_empty() && !r.display_name.is_empty()));

        // The Service Control Manager's own presence is a given: the RPC endpoint mapper
        // ("RpcSs") is always installed and running on Windows.
        let rpcss = rows
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case("RpcSs"))
            .expect("RpcSs service should always exist");
        assert_eq!(rpcss.state, ServiceState::Running);
        assert!(rpcss.pid.is_some(), "a running service should report a host PID");
    }

    #[test]
    fn running_services_sort_before_stopped() {
        let rows = snapshot();
        let first_stopped = rows.iter().position(|r| r.state != ServiceState::Running);
        if let Some(idx) = first_stopped {
            assert!(
                rows[idx..].iter().all(|r| r.state != ServiceState::Running),
                "all running services must come before the first non-running one"
            );
        }
    }

    #[test]
    fn rows_serialize_to_json_for_the_ui() {
        let rows = snapshot();
        let json = serde_json::to_string(rows.first().unwrap()).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"state\""));
    }
}
