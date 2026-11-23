//! MSI provisioning for auto-update (design v3 MSI changes, v2 D2/D7, v5 M1):
//! `agent_host.exe msi-autoupdate provision <txn> <ring> | rollback <txn> | commit <txn> |
//! deprovision`, where `<txn>` is a per-transaction id the package generates (DESKRALLY_TXN), so a
//! rollback only ever restores the snapshot taken by ITS OWN transaction (Codex impl B).
//!
//! * provision: snapshot first, then pin the update signer key if config has none (set-if-blank,
//!   raw JSON so unknown fields survive), create `auto-update.json` if absent (ring from an
//!   allowlist), and register the scheduled task (hourly + at boot, LocalSystem).
//! * rollback (rollback custom action, scheduled BEFORE provision): restore exactly the snapshot.
//! * commit (commit custom action): delete the snapshot. Never fails the install.
//! * deprovision (intentional uninstall only, never during a major upgrade): remove the task, the
//!   policy and the updater state.
//!
//! The pin is a build artifact (`packaging/update-signer-pubkey.hex` via build.rs). An existing
//! DIFFERENT pin is preserved and reported: set-if-blank never rotates a key (design D7/D9).

#![cfg(windows)]

use std::io;

use serde::{Deserialize, Serialize};

use crate::anchor::{Anchor, Dir};

/// The release signer's public key compiled into this build ("" when the build has none).
pub const UPDATE_PIN: &str = env!("DESKRALLY_UPDATE_PIN");
const CONFIG: &str = "config.json";
const POLICY: &str = "auto-update.json";
const SNAPSHOT_PREFIX: &str = "msi-rollback-autoupdate.";
/// One bound for writing AND reading a snapshot, checked before any mutation (Codex impl B).
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

fn snapshot_name(txn: &str) -> String {
    format!("{SNAPSHOT_PREFIX}{txn}.json")
}
const TASK_XML: &str = "autoupdate-task.xml";
pub const TASK_NAME: &str = r"\DeskRally\AutoUpdate";

pub const OK: i32 = 0;
const INVALID: i32 = 30;
const FAILED: i32 = 31;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    config: Option<String>,
    policy: Option<String>,
    task_xml: Option<String>,
}

pub fn command(args: &[String]) -> i32 {
    let verb = args.get(2).map(String::as_str);
    let txn = args.get(3).map(String::as_str).unwrap_or("");
    let txn_ok = crate::update_files::valid_attempt_id(txn);
    let result = match (verb, args.len()) {
        (Some("provision"), 5) => {
            let ring = args[4].as_str();
            if !txn_ok || !matches!(ring, "canary" | "early" | "general") {
                return INVALID;
            }
            provision(txn, ring)
        }
        (Some("rollback"), 4) if txn_ok => rollback(txn),
        (Some("commit"), 4) if txn_ok => commit(txn),
        (Some("deprovision"), 3) => deprovision(),
        _ => return INVALID,
    };
    match result {
        Ok(()) => OK,
        Err(e) => {
            tracing::error!(error = %e, verb, "msi-autoupdate failed");
            // Commit/rollback cleanup must never fail the transaction (a failing commit action
            // starts a rollback); provision and deprovision report.
            if matches!(verb, Some("commit") | Some("rollback")) {
                OK
            } else {
                FAILED
            }
        }
    }
}

fn read_text(dir: &Dir, name: &str) -> io::Result<Option<String>> {
    match dir.read(name, crate::anchor::MAX_STATE_BYTES)? {
        None => Ok(None),
        Some(b) => String::from_utf8(b).map(Some).map_err(|_| io::Error::other("not UTF-8")),
    }
}

fn task_query_xml() -> io::Result<Option<String>> {
    let out = std::process::Command::new(crate::agent_root::system32_exe("schtasks.exe"))
        .args(["/Query", "/TN", TASK_NAME, "/XML"])
        .output()?;
    Ok(out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned()))
}

fn task_create(root: &Dir, xml: &str) -> io::Result<()> {
    // schtasks reads the definition from a file; UTF-16LE with BOM is its native encoding.
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    root.write_atomic(TASK_XML, &bytes)?;
    let path = format!("{}\\{TASK_XML}", crate::anchor::ROOT);
    let status = std::process::Command::new(crate::agent_root::system32_exe("schtasks.exe"))
        .args(["/Create", "/TN", TASK_NAME, "/XML", &path, "/F"])
        .output()?;
    let _ = root.remove(TASK_XML);
    if !status.status.success() {
        return Err(io::Error::other("schtasks /Create failed"));
    }
    Ok(())
}

fn task_delete() -> io::Result<()> {
    let _ = std::process::Command::new(crate::agent_root::system32_exe("schtasks.exe"))
        .args(["/Delete", "/TN", TASK_NAME, "/F"])
        .output()?;
    Ok(())
}

/// The task definition: LocalSystem, at boot (after 5 min) and hourly, one instance at a time.
pub(crate) fn task_xml(agent_exe: &str) -> String {
    let exe = agent_exe
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>DeskRally agent automatic updates</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Delay>PT5M</Delay><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <RandomDelay>PT10M</RandomDelay>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="System"><Exec><Command>"{exe}"</Command><Arguments>auto-update-worker</Arguments></Exec></Actions>
</Task>
"#
    )
}

/// Set-if-blank on the raw JSON object; returns the new text, or None if nothing changes.
pub(crate) fn pin_config(text: &str, pin: &str) -> Result<Option<String>, &'static str> {
    if pin.is_empty() {
        return Ok(None);
    }
    let mut value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|_| "config not JSON")?;
    let obj = value.as_object_mut().ok_or("config not an object")?;
    let existing = obj
        .get("update_signer_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    if !existing.is_empty() {
        if !existing.eq_ignore_ascii_case(pin) {
            tracing::warn!("msi-autoupdate: a different update signer pin is configured; preserved (no rotation)");
        }
        return Ok(None);
    }
    let grant = obj.get("grant_issuer_pubkey").and_then(|v| v.as_str()).unwrap_or("");
    if grant.eq_ignore_ascii_case(pin) {
        return Err("update pin equals the grant issuer key");
    }
    obj.insert("update_signer_pubkey".into(), pin.into());
    serde_json::to_string_pretty(&value).map(Some).map_err(|_| "encode")
}

fn provision(txn: &str, ring: &str) -> io::Result<()> {
    let anchor = Anchor::open()?;
    let root = anchor.dir();
    // This transaction's own snapshot, written and size-checked BEFORE any mutation.
    let snap = Snapshot {
        config: read_text(root, CONFIG)?,
        policy: read_text(root, POLICY)?,
        task_xml: task_query_xml()?,
    };
    let bytes = serde_json::to_vec(&snap).map_err(io::Error::other)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(io::Error::other("rollback snapshot would exceed its bound; refusing to provision"));
    }
    root.write_atomic(&snapshot_name(txn), &bytes)?;
    if let Some(text) = read_text(root, CONFIG)? {
        if let Some(new) = pin_config(&text, UPDATE_PIN).map_err(io::Error::other)? {
            root.write_atomic(CONFIG, new.as_bytes())?;
        }
    }
    if read_text(root, POLICY)?.is_none() {
        let policy = serde_json::json!({ "enabled": true, "ring": ring });
        root.write_atomic(POLICY, policy.to_string().as_bytes())?;
    }
    let exe = crate::update_runner::install_location()?.join("agent_host.exe");
    task_create(root, &task_xml(&exe.to_string_lossy()))
}

fn rollback(txn: &str) -> io::Result<()> {
    let anchor = Anchor::open()?;
    let root = anchor.dir();
    // Only THIS transaction's snapshot: none means this transaction never reached provisioning.
    let Some(raw) = root.read(&snapshot_name(txn), MAX_SNAPSHOT_BYTES)? else {
        return Ok(());
    };
    let snap: Snapshot = serde_json::from_slice(&raw).map_err(io::Error::other)?;
    match &snap.config {
        Some(c) => root.write_atomic(CONFIG, c.as_bytes())?,
        None => {} // config is owned by enrollment; never deleted here
    }
    match &snap.policy {
        Some(p) => root.write_atomic(POLICY, p.as_bytes())?,
        None => root.remove(POLICY)?,
    }
    match &snap.task_xml {
        Some(xml) => task_create(root, xml)?,
        None => task_delete()?,
    }
    root.remove(&snapshot_name(txn))
}

/// Delete this transaction's snapshot, and any left behind by earlier transactions whose own
/// cleanup failed (they can never be selected by a rollback, but they are clutter).
fn commit(_txn: &str) -> io::Result<()> {
    remove_snapshots(Anchor::open()?.dir())
}

fn remove_snapshots(root: &Dir) -> io::Result<()> {
    for name in root.list()? {
        if name.starts_with(SNAPSHOT_PREFIX) && name.ends_with(".json") {
            root.remove(&name)?;
        }
    }
    Ok(())
}

fn deprovision() -> io::Result<()> {
    task_delete()?;
    let anchor = Anchor::open()?;
    let root = anchor.dir();
    for name in [POLICY, crate::update_files::STATE] {
        root.remove(name)?;
    }
    remove_snapshots(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn pin_is_set_only_if_blank_and_unknown_fields_survive() {
        let out = pin_config(r#"{"signaling_url":"wss://x/ws","future":1}"#, PIN).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["update_signer_pubkey"], PIN);
        assert_eq!(v["future"], 1);
        assert_eq!(pin_config(&out, PIN).unwrap(), None, "already pinned: no change");
        let other = r#"{"update_signer_pubkey":"2222222222222222222222222222222222222222222222222222222222222222"}"#;
        assert_eq!(pin_config(other, PIN).unwrap(), None, "a different pin is preserved");
        assert_eq!(pin_config(r#"{"update_signer_pubkey":"  "}"#, "").unwrap(), None, "no build pin");
        assert!(pin_config(&format!(r#"{{"grant_issuer_pubkey":"{PIN}"}}"#), PIN).is_err());
    }

    #[test]
    fn task_definition_runs_the_installed_worker_as_system() {
        let xml = task_xml(r"C:\Program Files\RMT Agent\agent_host.exe");
        assert!(xml.contains(r#"<Command>"C:\Program Files\RMT Agent\agent_host.exe"</Command>"#));
        assert!(xml.contains("<Arguments>auto-update-worker</Arguments>"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        assert!(xml.contains("<Interval>PT1H</Interval>"));
        assert!(xml.contains("IgnoreNew"));
    }

    #[test]
    fn verbs_are_allowlisted() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let txn = "11111111-2222-3333-4444-555555555555";
        assert_eq!(command(&a(&["x", "msi-autoupdate", "provision", txn, "evil"])), INVALID);
        assert_eq!(command(&a(&["x", "msi-autoupdate", "provision", "not-a-txn", "general"])), INVALID);
        assert_eq!(command(&a(&["x", "msi-autoupdate", "rollback"])), INVALID, "rollback needs its txn");
        assert_eq!(snapshot_name(txn), format!("msi-rollback-autoupdate.{txn}.json"));
        assert!(crate::anchor::valid_component(&snapshot_name(txn)));
        assert_eq!(command(&a(&["x", "msi-autoupdate", "explode"])), INVALID);
        assert_eq!(command(&a(&["x", "msi-autoupdate"])), INVALID);
    }

    #[test]
    fn build_pin_is_blank_or_well_formed() {
        assert!(
            UPDATE_PIN.is_empty()
                || (UPDATE_PIN.len() == 64 && UPDATE_PIN.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        );
    }
}
