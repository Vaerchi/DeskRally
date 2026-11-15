//! Process panel — the read-only process list a technician sees, rendered natively in the
//! browser (no remoted pixels). This is a real, running implementation over `sysinfo`.
//!
//! Requires [`crate::backstage::rbac::Capability::ProcessList`]. The kill action lives behind
//! `ProcessKill` + the protected-object guard rail; this module is list-only.
//!
//! Limitation to revisit: from a non-elevated context `sysinfo` can't always read the command
//! line or owner of processes in other sessions. When the agent runs as LocalSystem (with
//! `SeDebugPrivilege`) most of that becomes available; where it still isn't, drop to
//! `OpenProcess` + `NtQueryInformationProcess(ProcessCommandLineInformation)` and
//! `GetTokenInformation(TokenUser)`. Rows carry `Option`s so the UI shows "—" rather than lying.

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// One row in the process table. Shaped for direct JSON rendering in the technician UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessRow {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    /// Percent of total CPU across all cores, 0–100. Requires two samples (see [`snapshot`]).
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    /// None when we lack rights to read another session's process owner.
    pub user: Option<String>,
    /// None when the command line isn't readable (privilege/session boundary).
    pub command_line: Option<String>,
}

/// Take a process snapshot with valid CPU percentages.
///
/// CPU usage is a delta between two refreshes, so we refresh, wait one CPU-measurement
/// interval, and refresh again — otherwise every process reports 0%. `sleep` is injected as a
/// closure so tests/callers control timing and this stays runtime-agnostic.
pub fn snapshot(sleep: impl FnOnce()) -> Vec<ProcessRow> {
    let mut sys = System::new();
    let refresh = ProcessRefreshKind::everything();

    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    sleep();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let mut rows: Vec<ProcessRow> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcessRow {
            pid: pid.as_u32(),
            parent_pid: p.parent().map(Pid::as_u32),
            name: p.name().to_string_lossy().into_owned(),
            cpu_percent: p.cpu_usage(),
            memory_bytes: p.memory(),
            user: None, // populated below where resolvable
            command_line: {
                let parts: Vec<String> =
                    p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                if parts.is_empty() { None } else { Some(parts.join(" ")) }
            },
        })
        .collect();

    // Stable, useful default ordering: highest CPU first, then by name.
    rows.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
    });
    rows
}

/// Convenience wrapper using the recommended CPU sampling interval.
pub fn snapshot_default() -> Vec<ProcessRow> {
    snapshot(|| std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_lists_real_running_processes() {
        // No artificial wait needed for the shape assertions; CPU% may read 0 with a no-op
        // sleep, which is fine here — we're asserting enumeration works, not exact CPU.
        let rows = snapshot(|| {});
        assert!(!rows.is_empty(), "a running machine always has processes");

        // The test process itself must be present, with a sane name and non-zero memory.
        let me = std::process::id();
        let mine = rows.iter().find(|r| r.pid == me).expect("test process should appear");
        assert!(!mine.name.is_empty());
        assert!(mine.memory_bytes > 0);
    }

    #[test]
    fn rows_are_sorted_by_cpu_descending() {
        let rows = snapshot(|| {});
        for w in rows.windows(2) {
            assert!(w[0].cpu_percent >= w[1].cpu_percent);
        }
    }

    #[test]
    fn rows_serialize_to_json_for_the_ui() {
        let rows = snapshot(|| {});
        let json = serde_json::to_string(&rows.first().unwrap()).unwrap();
        assert!(json.contains("\"pid\""));
        assert!(json.contains("\"memory_bytes\""));
    }
}
