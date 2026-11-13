//! The updater's durable files under the trusted anchor: the state document and the
//! attempt-bound evidence (design v7 L2'). Every read and write goes through [`crate::anchor`].
//!
//! Evidence files are named `<kind>.<attempt_id>.json`, so a record from one attempt can never be
//! mistaken for another's (Codex v6: a stale marker must not affect a different attempt), and the
//! whole set for an attempt is moved to `update-history` only AFTER its terminal state is durable
//! (P1). Records are bounded, `deny_unknown_fields` JSON: they are written by our own components,
//! so an unknown field means corruption or forgery, not a newer version.

#![cfg(windows)]

use std::io;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::anchor::{Dir, MAX_STATE_BYTES};
use crate::update_state::{GateResult, Phase, UpdateState};

pub const STATE: &str = "update-state.json";
pub const REQUEST: &str = "update-watchdog.json";
pub const HEARTBEAT: &str = "registration-heartbeat.json";
/// Held exclusively (share mode 0) around every heartbeat write and refresh read-check-write, so a
/// refresh by an outgoing helper can never overwrite a newer registration's heartbeat.
pub const HEARTBEAT_LOCK: &str = "registration-heartbeat.lock";
pub const STAGING: &str = "update-staging";
pub const HISTORY: &str = "update-history";
/// Attempts whose evidence is kept in history.
const HISTORY_KEEP: usize = 3;

pub fn ack_name(id: &str) -> String {
    format!("update-watchdog.{id}.ack.json")
}
pub fn gate_name(id: &str) -> String {
    format!("gate.{id}.json")
}
pub fn candidate_fault_name(id: &str) -> String {
    format!("candidate-fault.{id}.json")
}
pub fn teardown_pending_name(id: &str) -> String {
    format!("teardown-pending.{id}.json")
}
pub fn teardown_complete_name(id: &str) -> String {
    format!("teardown-complete.{id}.json")
}
pub fn exit_name(id: &str) -> String {
    format!("exit.{id}.json")
}
/// E-txn (v10.1 C1): written by the package's commit / rollback custom actions.
pub fn txn_name(id: &str) -> String {
    format!("txn.{id}.json")
}

/// Attempt ids are lowercase hyphenated UUIDs: safe as a path component and unambiguous.
pub fn valid_attempt_id(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.hyphenated().to_string() == s)
}

/// 32 lowercase hex (16 random bytes).
pub fn valid_nonce(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn new_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn read_json<T: DeserializeOwned>(dir: &Dir, name: &str) -> io::Result<Option<T>> {
    match dir.read(name, MAX_STATE_BYTES)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::other(format!("{name}: {e}"))),
    }
}

fn write_json<T: Serialize>(dir: &Dir, name: &str, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    dir.write_atomic(name, &bytes)
}

/// A missing state document is a fresh machine; an unreadable one fails closed.
pub fn load_state(dir: &Dir) -> io::Result<UpdateState> {
    Ok(read_json(dir, STATE)?.unwrap_or_default())
}

pub fn save_state(dir: &Dir, state: &UpdateState) -> io::Result<()> {
    write_json(dir, STATE, state)
}

/// The kernel's boot counter (`PrefetchParameters\BootId`). A boot id that cannot be read fails
/// closed: every barrier and post-boot rule depends on telling boots apart.
pub fn boot_id() -> io::Result<String> {
    use windows::core::w;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
    let mut value: u32 = 0;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"),
            w!("BootId"),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut value as *mut u32).cast()),
            Some(&mut size),
        )
    };
    if rc.is_err() {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    Ok(value.to_string())
}

/// Lab-only fault injection for VM acceptance: `test-hook.<name>` under the anchor. Compiled only
/// into `update-test-feed` builds, which release packaging refuses to package.
#[cfg(feature = "update-test-feed")]
pub fn test_hook(dir: &Dir, name: &str) -> bool {
    matches!(dir.read(&format!("test-hook.{name}"), 64), Ok(Some(_)))
}
#[cfg(not(feature = "update-test-feed"))]
#[inline(always)]
pub fn test_hook(_dir: &Dir, _name: &str) -> bool {
    false
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── Records ──────────────────────────────────────────────────────────────────

/// The runner's request to the new helper (one per attempt; replaced only after classification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub attempt_id: String,
    pub nonce: String,
    pub expected_version: String,
}

/// The new helper's ack, written after authenticated registration. `actual_version` is the
/// compile-time constant, never echoed from the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub attempt_id: String,
    pub nonce: String,
    pub actual_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateRecord {
    pub attempt_id: String,
    pub result: GateResult,
    pub observed_version: Option<String>,
    pub ondisk_version: Option<String>,
    pub in_use: bool,
    pub teardown_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateFault {
    pub attempt_id: String,
    pub version: String,
    pub boot_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperIdentity {
    pub pid: u32,
    pub creation_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownRecord {
    pub attempt_id: String,
    pub boot_id: String,
    pub helpers: Vec<HelperIdentity>,
}

/// Written by the helper at every authenticated registration (design v5 R3 precondition, v9 R2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub registration_id: String,
    pub boot_id: String,
    pub version: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitRecord {
    pub attempt_id: String,
    pub code: u32,
}

/// How the installer transaction reached its end, as the package's own custom actions saw it.
/// Evidence that this attempt reached commit or rollback EXECUTION — not the final outcome (a later
/// commit-action failure can still roll back), so it only licenses classification after idle; the
/// installed state decides the outcome (Codex v10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnResult {
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxnRecord {
    pub attempt_id: String,
    pub result: TxnResult,
}

/// `Some` only for a well-formed record naming this attempt; anything else is non-authorizing.
pub fn read_txn(dir: &Dir, id: &str) -> io::Result<Option<TxnResult>> {
    // A malformed, foreign, or untrusted (owner/DACL) record never authorizes anything; at worst
    // the attempt stays Unresolved until a reboot.
    match read_json::<TxnRecord>(dir, &txn_name(id)) {
        Ok(rec) => Ok(rec.filter(|r| r.attempt_id == id).map(|r| r.result)),
        Err(e) => {
            tracing::warn!(error = %e, "update: transaction record ignored");
            Ok(None)
        }
    }
}

pub fn read_request(dir: &Dir) -> io::Result<Option<Request>> {
    let req: Option<Request> = read_json(dir, REQUEST)?;
    match req {
        Some(r) if !valid_attempt_id(&r.attempt_id) || !valid_nonce(&r.nonce) => {
            Err(io::Error::other("malformed update request"))
        }
        other => Ok(other),
    }
}
pub fn write_request(dir: &Dir, r: &Request) -> io::Result<()> {
    write_json(dir, REQUEST, r)
}
pub fn read_ack(dir: &Dir, id: &str) -> io::Result<Option<Ack>> {
    read_json(dir, &ack_name(id))
}
pub fn write_gate(dir: &Dir, g: &GateRecord) -> io::Result<()> {
    write_json(dir, &gate_name(&g.attempt_id), g)
}
pub fn read_gate(dir: &Dir, id: &str) -> io::Result<Option<GateRecord>> {
    read_json(dir, &gate_name(id))
}
pub fn write_candidate_fault(dir: &Dir, c: &CandidateFault) -> io::Result<()> {
    write_json(dir, &candidate_fault_name(&c.attempt_id), c)
}
/// E-cand is affirmative only if the record names THIS attempt, THIS candidate version and THIS
/// boot (Codex impl A round 3). Missing, malformed, untrusted or mismatched records never
/// authorize candidate blame.
pub fn candidate_fault_for(dir: &Dir, id: &str, version: &str, boot: &str) -> bool {
    match read_json::<CandidateFault>(dir, &candidate_fault_name(id)) {
        Ok(rec) => rec.is_some_and(|r| candidate_fault_matches(&r, id, version, boot)),
        Err(e) => {
            tracing::warn!(error = %e, "update: candidate fault record ignored");
            false
        }
    }
}

pub(crate) fn candidate_fault_matches(r: &CandidateFault, id: &str, version: &str, boot: &str) -> bool {
    r.attempt_id == id && r.version == version && r.boot_id == boot
}
pub fn write_teardown(dir: &Dir, complete: bool, t: &TeardownRecord) -> io::Result<()> {
    let name = if complete {
        teardown_complete_name(&t.attempt_id)
    } else {
        teardown_pending_name(&t.attempt_id)
    };
    write_json(dir, &name, t)
}
/// S1': positive evidence only, bound to this attempt AND this boot.
pub fn teardown_complete_for(dir: &Dir, id: &str, boot: &str) -> io::Result<bool> {
    Ok(read_json::<TeardownRecord>(dir, &teardown_complete_name(id))?
        .is_some_and(|t| t.attempt_id == id && t.boot_id == boot))
}
pub fn read_heartbeat(dir: &Dir) -> io::Result<Option<Heartbeat>> {
    read_json(dir, HEARTBEAT)
}
pub fn write_heartbeat(dir: &Dir, h: &Heartbeat) -> io::Result<()> {
    write_json(dir, HEARTBEAT, h)
}

/// The heartbeat to write when re-stamping registration `registration_id` on boot `boot` at `now`,
/// or `None` to write nothing.
///
/// 1.3.0 stamped the heartbeat only at registration. The helper then holds one signaling connection
/// for hours, so the worker's freshness precondition (update_worker HEARTBEAT_FRESH_MS) failed and
/// hourly checks never reached the feed. The helper now re-stamps while that registration's
/// connection is still up. Only `at_ms` changes: the same `registration_id` keeps post-boot
/// verification counting each registration once (UpdateState::on_heartbeat). A file that now names
/// another registration or boot, or none, is left alone, so a refresh can never revive or stand in
/// for a registration it did not make. Time never moves backwards.
pub fn refreshed_heartbeat(
    current: Option<&Heartbeat>,
    registration_id: &str,
    boot: &str,
    now: u64,
) -> Option<Heartbeat> {
    let cur = current?;
    (cur.registration_id == registration_id && cur.boot_id == boot && now > cur.at_ms)
        .then(|| Heartbeat { at_ms: now, ..cur.clone() })
}

/// What a registration writes, if anything: nothing once its liveness proof has expired
/// (`now_instant > proof_expiry`, checked by the caller immediately before writing); otherwise its
/// first heartbeat if not yet published (same `registration_id`), else [`refreshed_heartbeat`].
#[allow(clippy::too_many_arguments)]
pub fn heartbeat_to_write(
    published: bool,
    current: Option<&Heartbeat>,
    registration_id: &str,
    boot: &str,
    version: &str,
    now: u64,
    proof_expiry: std::time::Instant,
    now_instant: std::time::Instant,
) -> Option<Heartbeat> {
    if now_instant > proof_expiry {
        return None;
    }
    if !published {
        return Some(Heartbeat {
            registration_id: registration_id.to_owned(),
            boot_id: boot.to_owned(),
            version: version.to_owned(),
            at_ms: now,
        });
    }
    refreshed_heartbeat(current, registration_id, boot, now)
}
pub fn write_exit(dir: &Dir, e: &ExitRecord) -> io::Result<()> {
    write_json(dir, &exit_name(&e.attempt_id), e)
}
pub fn read_exit(dir: &Dir, id: &str) -> io::Result<Option<u32>> {
    Ok(read_json::<ExitRecord>(dir, &exit_name(id))?
        .filter(|e| e.attempt_id == id)
        .map(|e| e.code))
}

/// The attempt the service/helper should attribute evidence to: an installer launch that may be
/// running on THIS boot (S1' predicate as amended by v10: phase Installing, matching boot).
pub fn active_attempt(anchor: &crate::anchor::Anchor) -> io::Result<Option<crate::update_state::Attempt>> {
    let state = load_state(anchor.dir())?;
    let boot = boot_id()?;
    Ok(match &state.phase {
        Phase::Installing { attempt, .. } if attempt.boot_id == boot => {
            check_anchor(anchor, attempt)?;
            Some(attempt.clone())
        }
        _ => None,
    })
}

/// `<16 hex volume serial>-<32 hex file id>`: the DESKRALLY_ANCHOR property the package's
/// transaction-record writer compares with the root it holds (packaging/msi/actions.cpp).
pub fn anchor_property(id: &crate::anchor::FileIdentity) -> String {
    format!("{:016x}-{}", id.volume, hex::encode(id.id))
}

/// v6 A1: evidence for an attempt is only read or written through the root it was recorded with.
pub fn check_anchor(anchor: &crate::anchor::Anchor, attempt: &crate::update_state::Attempt) -> io::Result<()> {
    match &attempt.anchor {
        Some(recorded) => anchor.expect_identity(recorded),
        None => Err(io::Error::other("attempt has no recorded anchor identity")),
    }
}

/// Move every `*.<id>.json` evidence file (and the request, if it is this attempt's) into
/// `update-history/<ms>-<id>/`, then keep only the newest [`HISTORY_KEEP`] attempts. Called only
/// after the attempt's terminal state is durable; leftovers from a crash are swept by the same
/// call on the next run (P1).
pub fn archive_attempt(root: &Dir, id: &str) -> io::Result<()> {
    let history = root.child_dir(HISTORY, true)?;
    let existing = history.list()?;
    let folder = existing
        .iter()
        .find(|n| n.ends_with(id))
        .cloned()
        .unwrap_or_else(|| format!("{:013}-{id}", now_ms()));
    let dest = history.child_dir(&folder, true)?;
    let suffix = format!(".{id}.json");
    let ack = ack_name(id);
    for name in root.list()? {
        if name.ends_with(&suffix) || name == ack {
            root.move_to(&name, &dest)?;
        }
    }
    if read_request(root).ok().flatten().is_some_and(|r| r.attempt_id == id) {
        root.move_to(REQUEST, &dest)?;
    }
    drop(dest);
    let mut folders = history.list()?;
    folders.sort();
    while folders.len() > HISTORY_KEEP {
        let oldest = folders.remove(0);
        history.remove_dir(&oldest)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_nonces_are_strict() {
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        assert!(valid_attempt_id(&id));
        assert!(!valid_attempt_id(&id.to_uppercase()));
        assert!(!valid_attempt_id(&format!("{{{id}}}")));
        assert!(!valid_attempt_id("../x"));
        assert!(valid_nonce(&new_nonce()));
        assert!(!valid_nonce(&new_nonce().to_uppercase()));
        for name in [
            ack_name(&id),
            gate_name(&id),
            candidate_fault_name(&id),
            teardown_complete_name(&id),
            exit_name(&id),
            txn_name(&id),
        ] {
            assert!(crate::anchor::valid_component(&name), "{name}");
        }
    }

    #[test]
    fn anchor_property_matches_the_custom_action_format() {
        // actions.cpp root_matches: "%016llx-" then 16 bytes "%02x" = 49 lowercase chars.
        let id = crate::anchor::FileIdentity { volume: 0xAB, id: [0xC4; 16] };
        let p = anchor_property(&id);
        assert_eq!(p.len(), 49);
        assert_eq!(&p[..17], "00000000000000ab-");
        assert!(p[17..].bytes().all(|b| b == b'c' || b == b'4'));
    }

    #[test]
    fn refresh_restamps_only_its_own_registration_on_this_boot() {
        let hb = Heartbeat {
            registration_id: "reg-a".into(),
            boot_id: "boot-1".into(),
            version: "0.1.1+abc".into(),
            at_ms: 1_000,
        };
        let r = refreshed_heartbeat(Some(&hb), "reg-a", "boot-1", 5_000).expect("own registration");
        assert_eq!(r, Heartbeat { at_ms: 5_000, ..hb.clone() }, "only at_ms changes");
        assert_eq!(refreshed_heartbeat(Some(&hb), "reg-b", "boot-1", 5_000), None, "another registration");
        assert_eq!(refreshed_heartbeat(Some(&hb), "reg-a", "boot-2", 5_000), None, "another boot");
        assert_eq!(refreshed_heartbeat(None, "reg-a", "boot-1", 5_000), None, "no heartbeat to refresh");
        assert_eq!(refreshed_heartbeat(Some(&hb), "reg-a", "boot-1", 1_000), None, "time must advance");
        assert_eq!(refreshed_heartbeat(Some(&hb), "reg-a", "boot-1", 999), None, "never backwards");
    }

    #[test]
    fn an_unpublished_registration_publishes_its_own_first_heartbeat_on_a_live_tick() {
        let other = Heartbeat {
            registration_id: "reg-old".into(),
            boot_id: "boot-1".into(),
            version: "0.1.0+x".into(),
            at_ms: 1_000,
        };
        let t0 = std::time::Instant::now();
        let live = t0 + std::time::Duration::from_secs(60);
        let w = heartbeat_to_write(false, Some(&other), "reg-new", "boot-1", "0.1.1+y", 5_000, live, t0)
            .expect("publish");
        assert_eq!((w.registration_id.as_str(), w.version.as_str(), w.at_ms), ("reg-new", "0.1.1+y", 5_000));
        assert_eq!(heartbeat_to_write(true, Some(&other), "reg-new", "boot-1", "0.1.1+y", 5_000, live, t0), None,
            "once published, only its own heartbeat is refreshed");
    }

    #[test]
    fn expired_liveness_proof_writes_nothing_for_first_publication_or_refresh() {
        let own = Heartbeat {
            registration_id: "reg".into(),
            boot_id: "boot".into(),
            version: "0.1.1+y".into(),
            at_ms: 1_000,
        };
        let expiry = std::time::Instant::now();
        // A delayed task (registration-time publication or a refresh) runs after the proof expired.
        let late = expiry + std::time::Duration::from_millis(1);
        assert_eq!(heartbeat_to_write(false, None, "reg", "boot", "0.1.1+y", 5_000, expiry, late), None,
            "delayed first publication");
        assert_eq!(heartbeat_to_write(true, Some(&own), "reg", "boot", "0.1.1+y", 5_000, expiry, late), None,
            "delayed refresh");
        assert!(heartbeat_to_write(true, Some(&own), "reg", "boot", "0.1.1+y", 5_000, expiry, expiry).is_some(),
            "at the expiry instant the proof still holds");
    }

    #[test]
    fn boot_id_is_readable_and_stable() {
        let a = boot_id().expect("BootId readable");
        assert_eq!(a, boot_id().unwrap());
    }

    #[test]
    fn txn_record_wire_shape_matches_the_custom_action() {
        // Exactly what packaging/msi/actions.cpp writes.
        let j = r#"{"attempt_id":"11111111-2222-3333-4444-555555555555","result":"rolled_back"}"#;
        let r: TxnRecord = serde_json::from_str(j).unwrap();
        assert_eq!(r.result, TxnResult::RolledBack);
        assert!(serde_json::from_str::<TxnRecord>(r#"{"attempt_id":"x","result":"maybe"}"#).is_err());
    }

    #[test]
    fn candidate_faults_bind_attempt_version_and_boot() {
        let r = CandidateFault {
            attempt_id: "a".into(),
            version: "0.1.1+abc".into(),
            boot_id: "7".into(),
            reason: "x".into(),
        };
        assert!(candidate_fault_matches(&r, "a", "0.1.1+abc", "7"));
        assert!(!candidate_fault_matches(&r, "b", "0.1.1+abc", "7"), "wrong attempt");
        assert!(!candidate_fault_matches(&r, "a", "0.1.0+def", "7"), "wrong version");
        assert!(!candidate_fault_matches(&r, "a", "0.1.1+abc", "6"), "prior boot");
        // A record without boot_id (older shape) is malformed, hence non-authorizing.
        assert!(serde_json::from_str::<CandidateFault>(r#"{"attempt_id":"a","version":"v","reason":"r"}"#).is_err());
    }

    #[test]
    fn records_refuse_unknown_fields() {
        let j = r#"{"attempt_id":"a","nonce":"b","actual_version":"c","extra":1}"#;
        assert!(serde_json::from_str::<Ack>(j).is_err());
    }
}
