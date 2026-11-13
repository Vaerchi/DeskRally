//! Capability-based access control for backstage tooling.
//!
//! Every backstage action maps to exactly one [`Capability`]. The relay hands the agent a
//! signed grant listing the capabilities the authenticated technician holds *for this
//! machine* (roles are resolved server-side, scoped to session groups — see
//! `docs/02-architecture.md` ADR and `docs/04-backstage.md`). The agent re-checks every
//! request against that grant and **never** trusts the UI to have hidden a button.
//!
//! Two independent gates protect the dangerous surface:
//!   1. [`Capability`] — does this technician hold the right at all?
//!   2. [`GuardRail`] — even with the right, does this specific target require an extra
//!      typed confirmation, and is it on the hardcoded protected-object denylist?

use serde::{Deserialize, Serialize};

/// A single, indivisible backstage permission. Ordered loosely from least to most dangerous.
///
/// New capabilities MUST be added here (not inferred) so that a capability the server
/// doesn't know about can never be granted implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // --- read-only (Tier 1) ---
    ProcessList,
    ServiceList,
    EventLogRead,
    FileBrowse,
    FileDownload,
    RegistryRead,
    SystemInfoRead,

    // --- operator (Tier 2) ---
    ServiceControl,   // start / stop / restart (config change is Tier 3)
    ProcessKill,      // non-protected processes only; see GuardRail
    FileUpload,
    ShellAsUser,      // interactive shell in the logged-in user's context

    // --- admin (Tier 3) ---
    RegistryWrite,
    RegistryHiveLoad, // RegLoadKey/RegUnLoadKey of an offline user hive
    ServiceConfig,    // change startup type / ImagePath
    FileDelete,
    ShellAsSystem,    // interactive shell as LocalSystem
    ShellAsCredential,// interactive shell under supplied credentials (lateral-movement primitive)
    UninstallProgram,
    LocalUserAdmin,   // create/modify/disable local users & groups
}

impl Capability {
    /// Every [`Capability`] variant, in declaration order. The canonical signing-bytes encoder
    /// ([`crate::backstage::canonical`]) and its cross-language name table are exhaustively tested
    /// against this list, so a newly added variant that is not given a canonical name fails tests.
    pub const ALL: [Capability; 19] = {
        use Capability::*;
        [
            ProcessList, ServiceList, EventLogRead, FileBrowse, FileDownload, RegistryRead,
            SystemInfoRead, ServiceControl, ProcessKill, FileUpload, ShellAsUser, RegistryWrite,
            RegistryHiveLoad, ServiceConfig, FileDelete, ShellAsSystem, ShellAsCredential,
            UninstallProgram, LocalUserAdmin,
        ]
    };

    /// The minimum role tier that may hold this capability. Used for defense-in-depth and
    /// for rendering role presets; the authoritative grant is still per-capability.
    pub fn tier(self) -> Tier {
        use Capability::*;
        match self {
            ProcessList | ServiceList | EventLogRead | FileBrowse | FileDownload
            | RegistryRead | SystemInfoRead => Tier::ReadOnly,

            ServiceControl | ProcessKill | FileUpload | ShellAsUser => Tier::Operator,

            RegistryWrite | RegistryHiveLoad | ServiceConfig | FileDelete | ShellAsSystem
            | ShellAsCredential | UninstallProgram | LocalUserAdmin => Tier::Admin,
        }
    }

    /// Whether an action using this capability always requires a typed confirmation
    /// ("type the machine name") regardless of target. Target-specific escalation is
    /// handled separately by [`GuardRail::evaluate`].
    pub fn always_requires_confirmation(self) -> bool {
        use Capability::*;
        matches!(self, ShellAsCredential | RegistryHiveLoad | UninstallProgram)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    ReadOnly,
    Operator,
    Admin,
}

/// The set of capabilities an authenticated technician holds for one machine, as issued by
/// the relay. Deserialized from the signed session grant; treat as read-only after receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub technician_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub machine_id: uuid::Uuid,
    pub capabilities: Vec<Capability>,
}

impl Grant {
    pub fn allows(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// The single choke point for authorization. Returns `Ok` only if the capability is
    /// granted; the caller must still satisfy any [`GuardRail`] before acting.
    pub fn require(&self, cap: Capability) -> Result<(), Denied> {
        if self.allows(cap) {
            Ok(())
        } else {
            Err(Denied { capability: cap, tier: cap.tier() })
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("capability {capability:?} (tier {tier:?}) not granted for this session")]
pub struct Denied {
    pub capability: Capability,
    pub tier: Tier,
}

/// Outcome of a guard-rail check against a specific target (a process, a service, a
/// registry path, a filesystem path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardRail {
    /// Proceed without extra friction.
    Allow,
    /// Proceed only if the technician has echoed back a confirmation token (the machine
    /// name). `reason` is shown in the confirmation dialog and recorded in the audit log.
    RequireConfirmation { reason: &'static str },
    /// Refuse outright — the agent will not perform this even for a Tier::Admin grant.
    Deny { reason: &'static str },
}

/// Process image names that must never be killable/suspendable via backstage. Killing any of
/// these BSODs or bricks the machine. The agent's own service is added dynamically.
pub const PROTECTED_PROCESSES: &[&str] = &[
    "lsass.exe", "csrss.exe", "wininit.exe", "services.exe", "smss.exe", "winlogon.exe",
    "system", "registry", "memory compression",
];

/// Registry roots where a write is a classic persistence / privilege-escalation vector and
/// therefore always demands confirmation.
pub const SENSITIVE_REG_PREFIXES: &[&str] = &[
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SYSTEM\CurrentControlSet\Control",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
];

impl GuardRail {
    /// Evaluate a process-kill target. `own_service_image` is this agent's own exe name so
    /// it can refuse to terminate itself.
    pub fn for_process_kill(image_name: &str, own_service_image: &str) -> Self {
        let lower = image_name.to_ascii_lowercase();
        if lower == own_service_image.to_ascii_lowercase() {
            return GuardRail::Deny { reason: "cannot terminate the remote-support agent itself" };
        }
        if PROTECTED_PROCESSES.iter().any(|p| *p == lower) {
            return GuardRail::Deny { reason: "terminating a critical system process would crash the machine" };
        }
        GuardRail::Allow
    }

    /// Evaluate a registry write target by its full path (case-insensitive prefix match).
    ///
    /// The path is first CANONICALIZED through the same `split_path` the write itself uses, because
    /// the guard must judge the key that will actually be written. `SENSITIVE_REG_PREFIXES` are all
    /// spelled with the short hive (`HKLM\…`), but the op accepts the long alias too and maps
    /// `HKEY_LOCAL_MACHINE` onto the identical hive handle — so a raw `starts_with` let
    /// `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` through with no
    /// confirmation while `HKLM\…\Run` demanded one, for the very same key. Two spellings, one
    /// registry key, and the guard saw two different things.
    ///
    /// An unparseable hive keeps the old raw comparison: `open_hive` rejects it anyway, so there is
    /// no write to guard, and inventing a denial here would only diverge from the op again.
    pub fn for_registry_write(full_path: &str) -> Self {
        let canonical = match crate::backstage::ops::registry::split_path(full_path) {
            Some((hive, sub)) if !sub.is_empty() => format!("{hive}\\{sub}"),
            Some((hive, _)) => hive.to_string(),
            None => full_path.to_string(),
        };
        let upper = canonical.to_ascii_uppercase();
        let mut parts: Vec<&str> = upper.split('\\').collect();
        // Active and numbered control sets, and the 32-bit Software view, share these guardrails.
        if parts.len() > 2 && parts[0] == "HKLM" && parts[1] == "SYSTEM" {
            if parts[2].strip_prefix("CONTROLSET").is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit())) {
                parts[2] = "CURRENTCONTROLSET";
            }
        }
        if parts.len() > 2 && parts[0] == "HKLM" && parts[1] == "SOFTWARE" && parts[2] == "WOW6432NODE" { parts.remove(2); }
        let upper = parts.join("\\");
        if SENSITIVE_REG_PREFIXES.iter().any(|p| upper.starts_with(&p.to_ascii_uppercase())) {
            return GuardRail::RequireConfirmation {
                reason: "writing under a system/persistence key can render the machine unbootable",
            };
        }
        GuardRail::Allow
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_registry_aliases_cannot_skip_guardrails() {
        for path in [r"HKLM\SYSTEM\ControlSet001\Services", r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"] {
            assert!(matches!(super::GuardRail::for_registry_write(path), super::GuardRail::RequireConfirmation { .. }));
        }
        for path in [r"HKLM\\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", r"HKLM\SOFTWARE\\Microsoft", "HKLM\\Software\0ignored"] {
            assert!(crate::backstage::ops::registry::split_path(path).is_none());
        }
    }

    use super::*;

    /// The sensitive-key confirmation must not depend on how the caller SPELLS the hive.
    ///
    /// PREMISE, declared locally: `ops::registry::split_path` maps `HKEY_LOCAL_MACHINE` and `HKLM`
    /// onto the same hive handle, so both spellings write the identical key. The guard's prefix list
    /// is written with the short form only, so before canonicalization the long form skipped the
    /// typed-confirmation requirement on Run, Winlogon, Services and Control — the persistence and
    /// boot keys the confirmation exists for.
    #[test]
    fn sensitive_registry_guard_is_hive_spelling_independent() {
        let sensitive_short = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let sensitive_long = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        // Negative control FIRST: an ordinary key is still allowed with no confirmation, in BOTH
        // spellings. Without this, a guard that demanded confirmation for everything would pass.
        for benign in [r"HKCU\Software\Acme\Settings", r"HKEY_CURRENT_USER\Software\Acme\Settings"] {
            assert!(
                matches!(GuardRail::for_registry_write(benign), GuardRail::Allow),
                "an ordinary key must not require confirmation: {benign}"
            );
        }

        // Both spellings of the SAME protected key must reach the same verdict.
        for path in [sensitive_short, sensitive_long] {
            assert!(
                matches!(GuardRail::for_registry_write(path), GuardRail::RequireConfirmation { .. }),
                "SECURITY: writing {path} did not require confirmation"
            );
        }

        // And the mixed-case long form, since the op is case-insensitive too.
        assert!(
            matches!(
                GuardRail::for_registry_write(r"hkey_local_machine\system\currentcontrolset\services\foo"),
                GuardRail::RequireConfirmation { .. }
            ),
            "SECURITY: a lower-case long hive name skipped the confirmation"
        );
    }

    #[test]
    fn ungranted_capability_is_denied() {
        let g = Grant {
            technician_id: uuid::Uuid::nil(),
            session_id: uuid::Uuid::nil(),
            machine_id: uuid::Uuid::nil(),
            capabilities: vec![Capability::ProcessList],
        };
        assert!(g.require(Capability::ProcessList).is_ok());
        assert!(g.require(Capability::RegistryWrite).is_err());
    }

    #[test]
    fn critical_processes_cannot_be_killed_even_with_grant() {
        assert_eq!(
            GuardRail::for_process_kill("lsass.exe", "rmt-agent.exe"),
            GuardRail::Deny { reason: "terminating a critical system process would crash the machine" }
        );
    }

    #[test]
    fn agent_refuses_to_kill_itself() {
        assert!(matches!(
            GuardRail::for_process_kill("RMT-Agent.exe", "rmt-agent.exe"),
            GuardRail::Deny { .. }
        ));
    }

    #[test]
    fn service_key_write_needs_confirmation() {
        assert!(matches!(
            GuardRail::for_registry_write(r"HKLM\SYSTEM\CurrentControlSet\Services\Foo\ImagePath"),
            GuardRail::RequireConfirmation { .. }
        ));
        assert_eq!(
            GuardRail::for_registry_write(r"HKCU\Software\Acme\Setting"),
            GuardRail::Allow
        );
    }
}
