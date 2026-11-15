//! Process termination. Reached only through the dispatcher, which has already applied the
//! `ProcessKill` capability and the protected-process guard rail (`lsass`, `csrss`, the agent
//! itself, …) before this runs.
//!
//! The guard rail matches on an image *name* while the kill targets a *pid*. That was once framed
//! here as an acceptable TOCTOU gap (a recycled pid), which understated it: the `image` field
//! arrives in the REQUEST, so it was never a race that had to be won — a caller could simply name a
//! harmless process and pass any pid it liked, and the protected-process list (`lsass`, `csrss`, the
//! agent itself) would wave it through while the kill went to the real target. The audit event
//! recorded the claimed name, so the trail asserted a process that was never touched.
//!
//! [`image_name_for_pid`] closes it by doing what that note asked for: the dispatcher resolves the
//! image FROM the pid and evaluates the guard on the resolved name, ignoring the caller's claim. The
//! termination operation repeats that check using the same kernel handle used to terminate,
//! so PID recycling between authorization and execution cannot substitute a protected process.

use super::OpError;

/// Resolve the image name actually running under `pid`, for the protected-process guard rail.
///
/// `None` means "cannot say", which the dispatcher treats as DENY — an unresolvable pid must not
/// fall through to a permissive guard. Uses `sysinfo`, the same source the process panel names
/// processes with, so the guard judges the name the technician is looking at.
pub fn image_name_for_pid(pid: u32) -> Option<String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let target = Pid::from_u32(pid);
    let mut sys = System::new();
    // Only this pid, and only its identity — no CPU delta, so no second refresh and no sleep.
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(target).map(|p| p.name().to_string_lossy().into_owned())
}

/// Forcibly terminate a process by pid. `exit_code` is what the terminated process reports.
#[cfg(windows)]
pub fn kill(pid: u32, exit_code: u32) -> Result<(), OpError> {
    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            // A missing pid surfaces as INVALID_PARAMETER; a live-but-forbidden one as ACCESS_DENIED.
            if e.code() == ERROR_INVALID_PARAMETER.to_hresult() {
                OpError::NotFound(format!("pid {pid}"))
            } else if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                OpError::AccessDenied(format!("pid {pid}"))
            } else {
                OpError::Api { api: "OpenProcess", source: e }
            }
        })?;

        // Resolve and authorize the image on the SAME handle that will be terminated.
        // PID reuse between the dispatcher's preview and this operation cannot change the target.
        let result = (|| {
            let mut buffer = vec![0u16; 32768];
            let mut size = buffer.len() as u32;
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size)
                .map_err(|e| OpError::Api { api: "QueryFullProcessImageNameW", source: e })?;
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            let image = std::path::Path::new(&path).file_name().and_then(|s| s.to_str())
                .ok_or_else(|| OpError::AccessDenied("unresolvable process image".into()))?;
            let own = std::env::current_exe().map_err(|e| OpError::Other(e.to_string()))?;
            let own_image = own.file_name().and_then(|s| s.to_str())
                .ok_or_else(|| OpError::AccessDenied("unresolvable agent image".into()))?;
            if !matches!(crate::backstage::rbac::GuardRail::for_process_kill(image, own_image), crate::backstage::rbac::GuardRail::Allow) {
                return Err(OpError::AccessDenied("protected process".into()));
            }
            TerminateProcess(handle, exit_code).map_err(|e| OpError::Api { api: "TerminateProcess", source: e })
        })();
        let _ = CloseHandle(handle);
        result
    }
}

#[cfg(not(windows))]
pub fn kill(_pid: u32, _exit_code: u32) -> Result<(), OpError> {
    Err(OpError::Unsupported)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn kills_a_child_process_by_pid() {
        // Spawn a benign, long-lived child we own, then terminate it through the op.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 30 127.0.0.1 >NUL"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn child");
        let pid = child.id();

        kill(pid, 1).expect("terminating our own child should succeed");

        // The child must now exit (not hang for the full ping duration).
        let status = child.wait().expect("wait on killed child");
        assert!(!status.success(), "a terminated process should not report success");
    }

    #[test]
    fn killing_a_nonexistent_pid_is_a_clean_error() {
        // A pid that is almost certainly not live. Expect a structured error, never a panic.
        let err = kill(0xFFFF_FFF0, 1).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_) | OpError::AccessDenied(_) | OpError::Api { .. }));
    }
}
