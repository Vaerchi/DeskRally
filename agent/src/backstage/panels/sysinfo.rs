//! System-info panel — the "guest system info" summary (hardware, OS, uptime, memory) a
//! technician sees at a glance, rendered natively. Read-only, over the `sysinfo` crate, so it
//! runs on any platform.
//!
//! Requires [`crate::backstage::rbac::Capability::SystemInfoRead`]. This is the fast headline
//! summary; the process/service panels drill down. Fields the host can't report come back as
//! `Option`/empty so the UI shows "—" rather than fabricating a value.

use serde::{Deserialize, Serialize};
use sysinfo::System;

/// A one-shot snapshot of machine identity and resource headline. Shaped for direct JSON
/// rendering in the technician UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    /// OS family, e.g. "Windows".
    pub os_name: Option<String>,
    /// Long OS description, e.g. "Windows 11 Pro".
    pub os_long_version: Option<String>,
    /// Kernel / build version string.
    pub kernel_version: Option<String>,
    /// CPU architecture, e.g. "x86_64".
    pub cpu_arch: String,
    /// CPU model string, e.g. "AMD Ryzen 9 5900X".
    pub cpu_brand: String,
    /// Logical processor count (threads).
    pub logical_cpus: usize,
    /// Physical core count when the OS reports it.
    pub physical_cores: Option<usize>,
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    /// Seconds since boot.
    pub uptime_seconds: u64,
    /// Boot time as a Unix timestamp (seconds).
    pub boot_time_unix: u64,
    /// The user logged into the active console session (`DOMAIN\user`), or `None` when no one is
    /// logged in (e.g. the login screen) or it cannot be resolved. Best-effort — see
    /// [`console_logged_in_user`]. NOT `%USERNAME%`: the backstage helper runs as LocalSystem, so the
    /// environment/`GetUserName` would report SYSTEM rather than the interactive user.
    pub logged_in_user: Option<String>,
}

/// Collect a system-info snapshot. Refreshes only the memory + CPU views it needs (the static
/// identity fields are cheap associated calls), so it's fast enough to call on panel open.
pub fn snapshot() -> SystemInfo {
    let mut sys = System::new();
    sys.refresh_memory();
    // A single CPU refresh is enough for the brand string (we don't report live CPU% here).
    sys.refresh_cpu_all();

    let (cpu_brand, logical_cpus) = match sys.cpus() {
        cpus if !cpus.is_empty() => (cpus[0].brand().trim().to_string(), cpus.len()),
        _ => (String::new(), 0),
    };

    SystemInfo {
        hostname: System::host_name(),
        os_name: System::name(),
        os_long_version: System::long_os_version(),
        kernel_version: System::kernel_version(),
        cpu_arch: System::cpu_arch(),
        cpu_brand,
        logical_cpus,
        physical_cores: sys.physical_core_count(),
        total_memory_bytes: sys.total_memory(),
        used_memory_bytes: sys.used_memory(),
        total_swap_bytes: sys.total_swap(),
        used_swap_bytes: sys.used_swap(),
        uptime_seconds: System::uptime(),
        boot_time_unix: System::boot_time(),
        logged_in_user: console_logged_in_user(),
    }
}

/// The user logged into the ACTIVE CONSOLE session, resolved via WTS. The backstage helper runs as
/// LocalSystem, so `%USERNAME%`/`GetUserName` would report SYSTEM, not the interactive user — the WTS
/// session query is the correct source. Best-effort: `None` when no one is logged in (login screen),
/// no session is attached to the console, or any API call fails. Formatted `DOMAIN\user` when a domain
/// is reported, else the bare user name.
#[cfg(windows)]
fn console_logged_in_user() -> Option<String> {
    use windows::Win32::System::RemoteDesktop::{
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSDomainName,
        WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_INFO_CLASS,
    };

    // Query one WTS string field for `session`; returns an owned copy and frees the WTS buffer.
    // Empty (a session with no user) collapses to `None`.
    unsafe fn query(session: u32, class: WTS_INFO_CLASS) -> Option<String> {
        let mut buf = windows::core::PWSTR::null();
        let mut bytes: u32 = 0;
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, class, &mut buf, &mut bytes)
            .ok()?;
        if buf.is_null() {
            return None;
        }
        let s = buf.to_string().ok();
        WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
        s.filter(|v| !v.is_empty())
    }

    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        if session == 0xFFFF_FFFF {
            return None; // no session is currently attached to the console
        }
        let user = query(session, WTSUserName)?;
        Some(match query(session, WTSDomainName) {
            Some(domain) => format!("{domain}\\{user}"),
            None => user,
        })
    }
}

#[cfg(not(windows))]
fn console_logged_in_user() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_plausible_machine_facts() {
        let info = snapshot();

        // A real machine always has memory and at least one logical CPU.
        assert!(info.total_memory_bytes > 0, "total memory should be non-zero");
        assert!(info.used_memory_bytes <= info.total_memory_bytes, "used <= total memory");
        assert!(info.logical_cpus >= 1, "at least one logical CPU");
        assert!(!info.cpu_arch.is_empty(), "architecture should be known");

        // Boot time is in the past, and uptime is a sane positive duration.
        assert!(info.boot_time_unix > 0, "boot time should be a real timestamp");

        // logged_in_user is best-effort (None on the login screen / Session-0 CI); when present it
        // must be a non-empty name, never an empty string (empty collapses to None by construction).
        assert!(info.logged_in_user.as_deref() != Some(""), "empty console user must be None, not \"\"");
    }

    #[test]
    fn serializes_to_json_for_the_ui() {
        let json = serde_json::to_string(&snapshot()).unwrap();
        assert!(json.contains("\"total_memory_bytes\""));
        assert!(json.contains("\"cpu_arch\""));
        assert!(json.contains("\"logged_in_user\""));
    }
}
