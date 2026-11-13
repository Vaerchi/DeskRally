//! The removal helper's procedure (docs/65 D-C6, D-C7, D-C9 and the Codex R/A repairs): ONE function, [`run_removal`].
//!
//! It runs in a COPY of `agent_host.exe` placed outside the uninstall target in a SYSTEM-only directory (the orchestrator is
//! `directive_win`), because the installed binary cannot remove itself and the process that received the directive is destroyed by
//! the removal. Everything it does to the machine goes through [`RemovalOps`], its reports through [`AckChannel`], and its durable
//! progress through [`JournalStore`], so the whole decision procedure (including every crash point) is tested with doubles: no test
//! here can uninstall or delete anything but its own temp directories.
//!
//! # The phases, in order (the contract). Each is persisted BEFORE the next begins.
//!
//! 1. **Fresh**: re-verify the directive against the REAL clock, pre-flight, settle recordings, HOLD the validated install chain,
//!    install the protected restart task, journal `MsiStarting` (with the current BOOT ID), then re-check the clock one last time:
//!    an expired directive is durably `Aborted` and no installer runs.
//! 2. **`MsiStarting` -> `MsiDone`**: `MsiConfigureProductEx(ABSENT)`; return code, reboot requirement, and confirmation that the
//!    product registration is gone. On a RESUME from `MsiStarting` with the product absent the outcome is ambiguous (a reboot may be
//!    owed and the crash lost it), so a LATER boot is required before cleanup.
//! 3. **Interim report** (only when the installer said a reboot is owed): the exact `reboot_pending` ack is persisted before its first
//!    send, resent unchanged, and the server-side state advances ONLY on an applied/replay answer for that exact ack. The local
//!    reboot requirement is tracked separately and is never lost by an undelivered ack.
//! 4. **Cleanup (R1)** -> `CleanupDone`: delete the config tree and recordings EXCEPT `identity.key`, verify nothing else is left.
//! 5. **Final report (R3)** -> `ReportConfirmed`: sign `complete` once, persist that exact ack, deliver it, retrying across restarts.
//! 6. **Identity last** -> `IdentityDeleted`: only after `ReportConfirmed` delete `identity.key` and the emptied root (an
//!    already-absent identity or root is success here: this is finalization recovery).
//! 7. **`Finished`** is written durably FIRST; only then are the restart task and the handoff removed. A re-run in `Finished` just
//!    removes leftovers, and any removal failure is propagated (retried), never swallowed.
//!
//! A failure before the installer ran is durably `Aborted` (then the task and handoff are removed the same way).
//!
//! # R3: which branch applies
//!
//! Signaling answers EVERY refused registration with the same generic reason (`agentAuthRejectionReason`), including a REMOVED
//! device's, so a refusal after a lost final answer is NOT distinguishable from any other refusal. Branch 2 therefore applies: the
//! helper never treats a refusal as confirmation, bounds its retries at the directive's expiry plus 24 h, then deletes identity,
//! config and journal anyway and leaves the control plane showing `removal_unconfirmed`. An Owner "forget this machine" action (docs/65
//! section 8) resolves it. It never reports or assumes `complete` without confirmation.

use std::io;
use std::path::{Path, PathBuf};

use rmt_crypto::Identity;
use rmt_protocol::directive::{self as proto, DirectiveKind, Expectation, SignedAck};
use serde::{Deserialize, Serialize};

use crate::anchor::{Anchor, FileIdentity, TreeLimits};
use crate::directive::{clip, RemovalHandoff};

/// `ERROR_SUCCESS_REBOOT_REQUIRED` / `ERROR_SUCCESS_REBOOT_INITIATED`.
const REBOOT_RCS: [u32; 2] = [3010, 1641];
/// How long after the directive's expiry the helper keeps trying to deliver its reports.
pub const REPORT_GRACE_MS: i64 = 24 * 3_600_000;
/// A stored ack is re-signed (fresh timestamp) once it is older than this: the control plane refuses a NEW transition whose
/// timestamp is more than an hour old, and an unconfirmed ack may never have been applied.
pub const FINAL_ACK_FRESH_MS: i64 = 30 * 60_000;
/// The name of the key file kept until the very end.
pub const IDENTITY_FILE_NAME: &str = "identity.key";
/// How many 404s from the final-ack route are retried before the report is treated as terminal-not-confirmed.
pub const FINAL_ACK_NOTFOUND_LIMIT: u32 = 3;

/// What the orchestrator hands the helper: the engine's handoff plus what the orchestrator resolved and validated.
#[derive(Serialize, Deserialize)]
pub struct HelperHandoff {
    pub base: RemovalHandoff,
    /// The product the removal is for; the helper refuses any other.
    pub product_code: String,
    /// The install location the MSI must report (the known `Program Files\RMT Agent` folder).
    pub install_dir: String,
    /// The agent root to delete.
    pub config_dir: String,
}

impl std::fmt::Debug for HelperHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperHandoff").field("base", &self.base).field("product_code", &self.product_code).finish_non_exhaustive()
    }
}

/// What local recordings meant for the removal (D-C9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordingDisposition {
    /// No local recordings.
    NoneToUpload,
    /// Every pending upload finished.
    Finished(usize),
    /// Pending uploads were EXPLICITLY abandoned; the central report says how many local files were deleted.
    Abandoned(usize),
    /// The real settlement (docs/63 R2): uploads were driven to completion within a bounded time, the ones that could not
    /// finish were explicitly abandoned, and whatever local files remain go with the machine.
    Settled { uploaded: usize, abandoned_uploads: usize, local_files: usize },
}

/// Map what the uploader did (and how many local recording files remain) to the disposition the ack reports.
/// Pure: nothing remaining and nothing abandoned is `NoneToUpload` / `Finished`; anything abandoned or left behind is stated.
pub fn recording_disposition(uploaded: usize, abandoned_uploads: usize, local_files: usize) -> RecordingDisposition {
    match (uploaded, abandoned_uploads, local_files) {
        (0, 0, 0) => RecordingDisposition::NoneToUpload,
        (n, 0, 0) => RecordingDisposition::Finished(n),
        (0, 0, n) => RecordingDisposition::Abandoned(n),
        (uploaded, abandoned_uploads, local_files) => RecordingDisposition::Settled { uploaded, abandoned_uploads, local_files },
    }
}

/// The ack detail for a disposition. The abandoned count is always stated when non-zero.
pub fn recording_note(r: &RecordingDisposition) -> String {
    match r {
        RecordingDisposition::NoneToUpload => "no local recordings".to_owned(),
        RecordingDisposition::Finished(n) => format!("{n} recording upload(s) finished"),
        RecordingDisposition::Abandoned(n) => format!("{n} local recording file(s) abandoned and deleted"),
        RecordingDisposition::Settled { uploaded, abandoned_uploads, local_files } => format!(
            "{uploaded} recording upload(s) finished; {abandoned_uploads} pending upload(s) explicitly abandoned; {local_files} local recording file(s) deleted with the machine"
        ),
    }
}

/// The helper's machine-touching operations.
pub trait RemovalOps {
    /// Product codes of the agent's MSI family installed right now.
    fn installed_products(&mut self) -> Result<Vec<String>, String>;
    /// Windows Installer is executing or recovering a transaction.
    fn installer_busy(&mut self) -> bool;
    /// An identifier of the current boot (changes across a reboot; derived from the boot time).
    fn boot_id(&mut self) -> String;
    fn product_is_per_machine(&mut self, code: &str) -> Result<bool, String>;
    /// The MSI's recorded install location for `code`.
    fn product_install_location(&mut self, code: &str) -> Result<String, String>;
    /// Validate a claimed directory against the expected one (canonical, no reparse points, same place), by name.
    fn verify_install_dir(&mut self, claimed: &str, expected: &str) -> Result<(), String>;
    /// R4: open and HOLD every component of the install directory until [`release_install_dir`](Self::release_install_dir).
    fn hold_install_dir(&mut self, install_dir: &str) -> Result<(), String>;
    fn release_install_dir(&mut self);
    /// Whether the install directory is gone from disk (`Ok(true)`), still there (`Ok(false)`), or could not be told (`Err`).
    fn install_dir_absent(&mut self, install_dir: &str) -> Result<bool, String>;
    /// Read-only pre-flight of the config tree: plain, trusted, bounded.
    fn preflight_config_tree(&mut self, config_dir: &str) -> Result<usize, String>;
    /// The identity of the agent root as pre-flighted (persisted in the journal and re-required on every later open).
    fn config_root_identity(&mut self) -> Option<FileIdentity>;
    /// After a restart: the root identity every later open must match (the journaled pre-flight one).
    fn expect_config_root(&mut self, id: Option<FileIdentity>);
    /// The D-C9 hook: finish or abandon pending recording uploads.
    fn settle_recordings(&mut self) -> Result<RecordingDisposition, String>;
    /// R2: install the protected restart mechanism (a SYSTEM task at boot and on a repeat) that re-runs this helper from its copy.
    fn install_resume_task(&mut self) -> Result<(), String>;
    /// Remove the restart task. Success when it is already gone; a real failure is an error (and is retried by the caller).
    fn remove_resume_task(&mut self) -> Result<(), String>;
    /// `MsiConfigureProductEx(code, ABSENT)`: the Windows Installer return code.
    fn configure_absent(&mut self, code: &str) -> u32;
    /// Registry footprint the product does not own; best effort, idempotent.
    fn cleanup_footprint(&mut self);
    /// R1: delete everything in the agent root EXCEPT `identity.key`, re-validating against the expected root identity.
    fn delete_config_tree_keep_identity(&mut self, config_dir: &str) -> Result<usize, String>;
    /// R1: nothing but `identity.key` is left in the agent root.
    fn verify_config_clean(&mut self, config_dir: &str) -> Result<(), String>;
    /// A6: reopen the root, require the expected identity, require that only `identity.key` remains, delete it through validated
    /// handles, then the emptied root. `allow_absent`: an already-absent identity or root is success (finalization recovery only).
    fn delete_identity_and_root(&mut self, config_dir: &str, allow_absent: bool) -> Result<(), String>;
    /// Delete this helper's secrets (the handoff holds the identity seed). Success when already gone.
    fn delete_helper_secrets(&mut self) -> Result<(), String>;
    /// Schedule the rest of the helper's own copy for deletion (it cannot delete the image it runs from). Best effort.
    fn schedule_self_cleanup(&mut self);
}

/// How an ack delivery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckDelivery {
    /// The control plane answered `applied` or `replay` FOR THIS EXACT ACK.
    Delivered,
    /// The control plane answered `refused`.
    Refused,
    /// 410 on the final-ack route: the control plane's window for this result has passed. Terminal: nothing more can be learned.
    Gone,
    /// 404 on the final-ack route: EVERY pre-authentication failure (unknown id, bad signature, key mismatch) looks like this. Not
    /// confirmed; retried a few times, then terminal.
    NotFound,
    /// No answer (network, 5xx, throttling that outlasted the call, a malformed answer).
    Undeliverable,
}

pub trait AckChannel {
    /// Send `ack` and wait (bounded) for the control plane's answer to it. One attempt budget per call; the caller retries across
    /// restarts.
    fn deliver(&mut self, ack: &SignedAck) -> AckDelivery;
    /// The product is gone: failures must now be reported by this helper (the agent that would have reported them no longer
    /// exists). Called from the DURABLE journal phase on every run, before any delivery.
    fn agent_removed(&mut self) {}
}

/// R2: the helper's durable progress, in its SYSTEM-only directory OUTSIDE the uninstall target.
pub trait JournalStore {
    fn load(&self) -> io::Result<Option<Journal>>;
    /// Durably replace. Must not return Ok before the bytes are flushed.
    fn save(&mut self, j: &Journal) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// MSI removal is about to start (or is running): journaled BEFORE `configure_absent`.
    MsiStarting,
    /// The product is gone.
    MsiDone,
    /// Config and recordings are deleted and VERIFIED (only `identity.key` remains).
    CleanupDone,
    /// The final report is confirmed (`reported`) or the retry window closed / the control plane refused (`!reported`).
    ReportConfirmed { reported: bool },
    /// `identity.key` and the emptied root are gone.
    IdentityDeleted { reported: bool },
    /// Everything is done; only the restart task, the handoff and the helper copy may remain (and are removed next).
    Finished { reported: bool },
    /// Nothing was removed and nothing will be: cancelled or failed BEFORE the installer ran (or after it rolled back).
    Aborted { reason: String },
}

impl Phase {
    /// The product is gone (or was never going to be tracked again): the surviving agent no longer exists to report failures.
    fn agent_is_gone(&self) -> bool {
        matches!(
            self,
            Phase::MsiDone | Phase::CleanupDone | Phase::ReportConfirmed { .. } | Phase::IdentityDeleted { .. } | Phase::Finished { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub v: u32,
    pub phase: Phase,
    /// The boot the installer was started in (persisted BEFORE it ran).
    pub boot_at_msi: String,
    /// A reboot is (or, when ambiguous, may be) owed before the cleanup: the LOCAL requirement, independent of any ack.
    pub reboot_required: bool,
    /// The installer itself said so (3010/1641), as opposed to "possible, because a crash lost the answer".
    pub reboot_known: bool,
    /// The server-side state the control plane last CONFIRMED for this directive (`executing`, or `reboot_pending` after that exact
    /// ack was answered applied/replay): the final ack's `from`.
    pub confirmed_state: String,
    pub recordings_note: String,
    /// The exact interim ack, persisted before its first send and resent verbatim.
    pub reboot_ack: Option<SignedAck>,
    pub reboot_ack_signed_ms: i64,
    /// The interim report is settled: answered, refused, or the window closed. Never set by a mere undelivered attempt.
    pub reboot_ack_settled: bool,
    /// The exact final ack, persisted before its first send and re-sent verbatim across restarts.
    pub final_ack: Option<SignedAck>,
    pub final_ack_signed_ms: i64,
    /// The directive's own expiry (the last moment the removal may START).
    pub expires_at_ms: i64,
    /// When the helper stops retrying its reports and cleans up anyway (directive expiry + 24 h).
    pub deadline_ms: i64,
    pub last_ts_ms: i64,
    pub cleanup_attempts: u32,
    pub last_error: Option<String>,
    /// Set when the removal ended with a cleanup that could not be completed: the (durable) final ack is then a `failed` one, and
    /// the identity and config are left for the operator.
    #[serde(default)]
    pub failure: Option<String>,
    /// How many times the final-ack route answered 404 (an unattributable failure): a few are retried, then terminal.
    #[serde(default)]
    pub final_ack_notfound: u32,
    /// The pre-flighted identity of the agent root: every later open must match it.
    pub root_identity: Option<FileIdentity>,
}

impl Journal {
    fn new(expires_at_ms: i64, recordings_note: String, boot: String, root_identity: Option<FileIdentity>) -> Self {
        Self {
            v: 2,
            phase: Phase::MsiStarting,
            boot_at_msi: boot,
            reboot_required: false,
            reboot_known: false,
            confirmed_state: proto::state::EXECUTING.into(),
            recordings_note,
            reboot_ack: None,
            reboot_ack_signed_ms: 0,
            reboot_ack_settled: false,
            final_ack: None,
            final_ack_signed_ms: 0,
            expires_at_ms,
            deadline_ms: expires_at_ms.saturating_add(REPORT_GRACE_MS),
            last_ts_ms: 0,
            cleanup_attempts: 0,
            last_error: None,
            failure: None,
            final_ack_notfound: 0,
            root_identity,
        }
    }
}

/// What the helper concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalResult {
    /// Removed, cleaned, reported (confirmed), identity deleted.
    Complete { residue: Option<String> },
    /// The installer owes a reboot; the restart task finishes after it.
    RebootPending,
    /// Nothing was removed (or the removal rolled back, or cleanup could not be completed): reported.
    Failed(String),
    /// Removed and cleaned, but the final report was never CONFIRMED within the retry window: identity and config were deleted anyway
    /// (R3 branch 2) and the control plane keeps showing `removal_unconfirmed`.
    Unreported,
    /// Not finished yet; run again. `in_process`: worth retrying in this process after a pause (otherwise wait for the restart task).
    Deferred { reason: String, in_process: bool },
}

impl RemovalResult {
    pub fn exit_code(&self) -> i32 {
        match self {
            RemovalResult::Complete { .. } => 0,
            RemovalResult::Failed(_) => 10,
            RemovalResult::RebootPending => 11,
            RemovalResult::Unreported => 12,
            RemovalResult::Deferred { .. } => 14,
        }
    }

    /// Nothing more will be done by a restart.
    pub fn is_final(&self) -> bool {
        !matches!(self, RemovalResult::Deferred { .. } | RemovalResult::RebootPending)
    }
}

/// The pre-flight both the orchestrator (before launching) and the helper (before touching anything) run. `Err` is the
/// human-readable reason, which becomes the `failed` ack's detail.
pub fn preflight(ops: &mut dyn RemovalOps, h: &HelperHandoff) -> Result<(), String> {
    let products = ops.installed_products().map_err(|e| format!("could not enumerate installed products: {e}"))?;
    match products.as_slice() {
        [one] if one.eq_ignore_ascii_case(&h.product_code) => {}
        [] => return Err("the agent product is not installed".into()),
        _ => return Err("installed products are not exactly the expected agent product".into()),
    }
    if !ops.product_is_per_machine(&h.product_code).map_err(|e| format!("install context unreadable: {e}"))? {
        return Err("the product is not a per-machine install".into());
    }
    let location = ops
        .product_install_location(&h.product_code)
        .map_err(|e| format!("install location unreadable: {e}"))?;
    ops.verify_install_dir(&location, &h.install_dir)
        .map_err(|e| format!("install location rejected: {e}"))?;
    ops.preflight_config_tree(&h.config_dir).map_err(|e| format!("config directory rejected: {e}"))?;
    Ok(())
}

fn deferred(reason: impl Into<String>) -> RemovalResult {
    RemovalResult::Deferred { reason: reason.into(), in_process: true }
}

fn save(journal: &mut dyn JournalStore, j: &Journal) -> Result<(), RemovalResult> {
    journal.save(j).map_err(|e| deferred(format!("the journal could not be written: {e}")))
}

/// Sign an ack from `from` to `to` with a strictly increasing timestamp (the journal remembers the last one used).
fn sign(identity: &Identity, h: &HelperHandoff, j: &mut Journal, from: &str, to: &str, detail: &str, clock: &dyn Fn() -> i64) -> SignedAck {
    let ts = clock().max(j.last_ts_ms + 1);
    j.last_ts_ms = ts;
    proto::sign_ack(
        identity,
        &h.base.tenant_id,
        &h.base.device_id,
        &h.base.directive_id,
        &h.base.key_fp,
        from,
        to,
        ts,
        &clip(detail, proto::MAX_ACK_DETAIL_BYTES),
    )
    // The ids and fingerprint were verified before any phase ran; an unencodable ack cannot occur. Produce a placeholder the control
    // plane will refuse rather than panic in a SYSTEM helper.
    .unwrap_or(SignedAck {
        directive_id: h.base.directive_id.clone(),
        from: from.to_owned(),
        to: to.to_owned(),
        ts_ms: ts,
        detail: String::new(),
        sig: String::new(),
    })
}

/// Remove the agent. See the module docs for the phases, which are the contract. Safe to call again after a crash: the journal
/// says where it was.
pub fn run_removal(
    h: &HelperHandoff,
    ops: &mut dyn RemovalOps,
    acks: &mut dyn AckChannel,
    journal: &mut dyn JournalStore,
    clock: &dyn Fn() -> i64,
) -> RemovalResult {
    let seed: Option<[u8; 32]> = hex::decode(&h.base.identity_seed_hex).ok().and_then(|b| b.try_into().ok());
    let Some(seed) = seed else {
        return RemovalResult::Failed("the captured identity is unusable".into());
    };
    let identity = Identity::from_seed(&seed);
    let existing = match journal.load() {
        Ok(j) => j,
        Err(e) => return deferred(format!("the journal is unreadable: {e}")),
    };

    let mut j = match existing {
        Some(j) => {
            // A4: whether the agent still exists comes from the DURABLE phase, never from a fresh process's defaults.
            if j.phase.agent_is_gone() {
                acks.agent_removed();
            }
            ops.expect_config_root(j.root_identity);
            j
        }
        None => match start_fresh(h, ops, acks, journal, clock) {
            Ok(j) => j,
            Err(result) => return result,
        },
    };

    loop {
        match j.phase.clone() {
            Phase::Aborted { reason } => return finish_aborted(ops, &reason),
            Phase::MsiStarting => {
                // Only reachable on a RESUME (a crash during the removal).
                if ops.installer_busy() {
                    return deferred("Windows Installer is still working");
                }
                match ops.installed_products() {
                    Ok(p) if !p.iter().any(|c| c.eq_ignore_ascii_case(&h.product_code)) => {
                        // The product is gone but the installer's answer was lost. A reboot MAY be owed: require a later boot
                        // before any cleanup (A2).
                        ops.release_install_dir();
                        acks.agent_removed();
                        j.phase = Phase::MsiDone;
                        j.reboot_required = true;
                        j.reboot_known = false;
                        if let Err(r) = save(journal, &j) {
                            return r;
                        }
                    }
                    Ok(_) => {
                        // The removal did not complete and the installer is idle: the product is still installed (rolled back).
                        return abort(ops, journal, &mut j, "the removal was interrupted and the product is still installed".into());
                    }
                    Err(e) => return deferred(format!("cannot enumerate products: {e}")),
                }
            }
            Phase::MsiDone => {
                // A1: the interim report, for a reboot the installer itself announced.
                if j.reboot_required && j.reboot_known && !j.reboot_ack_settled {
                    if let Some(r) = interim_report(h, acks, journal, &mut j, &identity, clock) {
                        return r;
                    }
                }
                // A2: the local reboot requirement is independent of any ack: wait for a LATER boot (bounded by the deadline).
                if j.reboot_required && ops.boot_id() == j.boot_at_msi {
                    if clock() < j.deadline_ms {
                        return if j.reboot_known {
                            RemovalResult::RebootPending
                        } else {
                            RemovalResult::Deferred { reason: "waiting for a reboot (the installer's answer was lost)".into(), in_process: false }
                        };
                    }
                    // The window closed and the required (or possibly required) reboot was NEVER observed: `complete` is never generated
                    // before a later boot satisfies it. Report `failed` (reason: reboot not observed) through the same persisted final-ack
                    // machinery; nothing is cleaned up and the identity and config stay for the operator.
                    let why = "the removal needs a reboot that was not observed before the report deadline".to_owned();
                    let from = j.confirmed_state.clone();
                    let ack = sign(&identity, h, &mut j, &from, proto::state::FAILED, &why, clock);
                    j.failure = Some(why);
                    j.final_ack = Some(ack);
                    j.final_ack_signed_ms = clock();
                    j.phase = Phase::CleanupDone;
                    if let Err(r) = save(journal, &j) {
                        return r;
                    }
                    continue;
                }
                // B1: a reboot-required return means the product may have stayed registered until the reboot. After that reboot the
                // removal is VERIFIED before any cleanup or `complete`: the installer must be idle, the product must be absent from the
                // registration, and the install directory gone. If the reboot-time removal failed or rolled back, the agent is still
                // installed: nothing local is deleted (identity and config stay) and `failed` is reported.
                if j.reboot_required {
                    if ops.installer_busy() {
                        return deferred("Windows Installer is still working after the reboot");
                    }
                    let still = match ops.installed_products() {
                        Err(e) => return deferred(format!("cannot enumerate products after the reboot: {e}")),
                        Ok(p) if p.iter().any(|c| c.eq_ignore_ascii_case(&h.product_code)) => {
                            Some("the product is still installed after the required reboot (the removal did not complete)".to_owned())
                        }
                        Ok(_) => match ops.install_dir_absent(&h.install_dir) {
                            Err(e) => return deferred(format!("cannot inspect the install directory after the reboot: {e}")),
                            Ok(true) => None,
                            Ok(false) => Some("the install directory still exists after the required reboot (the removal did not complete)".to_owned()),
                        },
                    };
                    if let Some(why) = still {
                        let from = j.confirmed_state.clone();
                        let ack = sign(&identity, h, &mut j, &from, proto::state::FAILED, &why, clock);
                        j.failure = Some(why);
                        j.final_ack = Some(ack);
                        j.final_ack_signed_ms = clock();
                        j.phase = Phase::CleanupDone;
                        if let Err(r) = save(journal, &j) {
                            return r;
                        }
                        continue;
                    }
                }
                // R1: delete + VERIFY the config tree and recordings (everything except identity.key) BEFORE any `complete`.
                ops.cleanup_footprint();
                let cleaned = ops
                    .delete_config_tree_keep_identity(&h.config_dir)
                    .and_then(|_| ops.verify_config_clean(&h.config_dir));
                match cleaned {
                    Ok(()) => {
                        j.phase = Phase::CleanupDone;
                        j.last_error = None;
                        if let Err(r) = save(journal, &j) {
                            return r;
                        }
                    }
                    Err(e) => {
                        j.cleanup_attempts += 1;
                        j.last_error = Some(clip(&e, 200));
                        let _ = journal.save(&j);
                        if clock() < j.deadline_ms {
                            return deferred(format!("cleanup incomplete: {e}"));
                        }
                        // The window closed: report TRUTHFULLY that the machine was removed but not cleaned, never `complete`.
                        let why = format!("the product was removed but local cleanup could not be completed: {e}");
                        let from = j.confirmed_state.clone();
                        let ack = sign(&identity, h, &mut j, &from, proto::state::FAILED, &why, clock);
                        // The exact failed ack is persisted and delivered by the SAME machinery as `complete` (the final-ack route).
                        j.failure = Some(why);
                        j.final_ack = Some(ack);
                        j.final_ack_signed_ms = clock();
                        j.phase = Phase::CleanupDone;
                        if let Err(r) = save(journal, &j) {
                            return r;
                        }
                    }
                }
            }
            Phase::CleanupDone => {
                // R3: the exact final ack is persisted before its first send and re-sent verbatim; re-signed only when stale.
                let now = clock();
                let stale = j.final_ack.is_none() || now - j.final_ack_signed_ms > FINAL_ACK_FRESH_MS;
                if stale {
                    let from = j.confirmed_state.clone();
                    let note = j.recordings_note.clone();
                    let (to, detail) = match &j.failure {
                        Some(why) => (proto::state::FAILED, why.clone()),
                        None => (proto::state::COMPLETE, format!("removed ({note})")),
                    };
                    let ack = sign(&identity, h, &mut j, &from, to, &detail, clock);
                    j.final_ack = Some(ack);
                    j.final_ack_signed_ms = now;
                    if let Err(r) = save(journal, &j) {
                        return r;
                    }
                }
                let ack = j.final_ack.clone().expect("just ensured");
                let reported = match acks.deliver(&ack) {
                    AckDelivery::Delivered => true,
                    // The control plane will not track this directive (409), or its window for it has passed (410): nothing more to
                    // learn by retrying. Not confirmed.
                    AckDelivery::Refused | AckDelivery::Gone => false,
                    // 404 is every pre-authentication failure; a few are retried, then terminal-not-confirmed.
                    AckDelivery::NotFound => {
                        j.final_ack_notfound += 1;
                        if j.final_ack_notfound < FINAL_ACK_NOTFOUND_LIMIT {
                            if let Err(r) = save(journal, &j) {
                                return r;
                            }
                            return deferred("the final-ack route did not recognise the report (404); retrying");
                        }
                        false
                    }
                    AckDelivery::Undeliverable if clock() < j.deadline_ms => return deferred("the final report is not confirmed yet"),
                    // R3 branch 2: a refused registration is not distinguishable, so the retries are bounded. Clean up anyway.
                    AckDelivery::Undeliverable => false,
                };
                // A cleanup failure leaves the identity and config for the operator: report it, then finish (no identity deletion).
                if j.failure.is_some() {
                    j.phase = Phase::Finished { reported };
                    if let Err(r) = save(journal, &j) {
                        return r;
                    }
                    continue;
                }
                // A3: durable BEFORE the identity is touched.
                j.phase = Phase::ReportConfirmed { reported };
                if let Err(r) = save(journal, &j) {
                    return r;
                }
            }
            Phase::ReportConfirmed { reported } => {
                // Finalization recovery: an identity or root a previous attempt already deleted is success.
                if let Err(e) = ops.delete_identity_and_root(&h.config_dir, true) {
                    return deferred(format!("could not delete the identity: {e}"));
                }
                j.phase = Phase::IdentityDeleted { reported };
                if let Err(r) = save(journal, &j) {
                    return r;
                }
            }
            Phase::IdentityDeleted { reported } => {
                // Finished is durable BEFORE the task and the handoff go.
                j.phase = Phase::Finished { reported };
                if let Err(r) = save(journal, &j) {
                    return r;
                }
            }
            Phase::Finished { reported } => {
                if let Err(r) = finalize_leftovers(ops) {
                    return r;
                }
                if let Some(why) = j.failure.clone() {
                    return RemovalResult::Failed(why);
                }
                return if reported { RemovalResult::Complete { residue: None } } else { RemovalResult::Unreported };
            }
        }
    }
}

/// Phase `MsiDone` with a reboot the installer announced: persist the exact `reboot_pending` ack, resend it unchanged, and advance
/// the CONFIRMED state only on an applied/replay answer for that exact ack. `Some` ends this run.
fn interim_report(
    h: &HelperHandoff,
    acks: &mut dyn AckChannel,
    journal: &mut dyn JournalStore,
    j: &mut Journal,
    identity: &Identity,
    clock: &dyn Fn() -> i64,
) -> Option<RemovalResult> {
    let now = clock();
    if j.reboot_ack.is_none() || now - j.reboot_ack_signed_ms > FINAL_ACK_FRESH_MS {
        let detail = format!("removed; a reboot is required ({})", j.recordings_note);
        let ack = sign(identity, h, j, proto::state::EXECUTING, proto::state::REBOOT_PENDING, &detail, clock);
        j.reboot_ack = Some(ack);
        j.reboot_ack_signed_ms = now;
        // Persisted BEFORE its first send: a lost answer can never lead to a differently-signed transition.
        if let Err(r) = save(journal, j) {
            return Some(r);
        }
    }
    let ack = j.reboot_ack.clone().expect("just ensured");
    match acks.deliver(&ack) {
        AckDelivery::Delivered => {
            j.confirmed_state = proto::state::REBOOT_PENDING.into();
            j.reboot_ack_settled = true;
        }
        // Refused: the control plane will not take the interim state. The server-side state stays `executing` and the final ack goes
        // from there; the local reboot requirement is untouched.
        AckDelivery::Refused | AckDelivery::Gone | AckDelivery::NotFound => j.reboot_ack_settled = true,
        AckDelivery::Undeliverable if clock() < j.deadline_ms => {
            return Some(deferred("the reboot_pending report is not confirmed yet"));
        }
        // The window closed with no answer: stop trying (the state stays `executing`).
        AckDelivery::Undeliverable => j.reboot_ack_settled = true,
    }
    save(journal, j).err()
}

/// Durably abort (nothing removed), then undo the helper's setup.
fn abort(ops: &mut dyn RemovalOps, journal: &mut dyn JournalStore, j: &mut Journal, reason: String) -> RemovalResult {
    j.phase = Phase::Aborted { reason: reason.clone() };
    if let Err(r) = save(journal, j) {
        return r;
    }
    finish_aborted(ops, &reason)
}

/// The aborted removal's cleanup: release the chain, remove the restart task, delete the secrets. Failures are retried (the journal
/// says `Aborted`), never swallowed.
fn finish_aborted(ops: &mut dyn RemovalOps, reason: &str) -> RemovalResult {
    ops.release_install_dir();
    if let Err(e) = finalize_leftovers(ops) {
        return e;
    }
    RemovalResult::Failed(reason.to_owned())
}

/// The helper's leftovers, in the order that never strands a secret: the handoff (which holds the identity seed and is what the restart
/// task needs) goes FIRST, and the restart task goes LAST. A handoff that cannot be deleted keeps the task (which retries); a crash
/// between the two leaves a task whose Finished-only entry point ([`run_leftovers_only`]) removes it without needing the handoff.
/// Each failure propagates.
fn finalize_leftovers(ops: &mut dyn RemovalOps) -> Result<(), RemovalResult> {
    ops.delete_helper_secrets().map_err(|e| deferred(format!("could not delete the helper's secrets: {e}")))?;
    ops.remove_resume_task().map_err(|e| deferred(format!("could not remove the restart task: {e}")))?;
    ops.schedule_self_cleanup();
    Ok(())
}

/// The restart task's FINISHED-ONLY entry point: invoked when the handoff is already gone. It loads nothing but the journal; if the journal
/// says the removal is `Finished` (or `Aborted`) it removes the leftovers (the task, then the helper copy) and reports the journal's
/// verdict; in any other phase it touches nothing (the removal is not finished and the handoff it needs is missing).
pub fn run_leftovers_only(ops: &mut dyn RemovalOps, journal: &dyn JournalStore) -> RemovalResult {
    let j = match journal.load() {
        Ok(Some(j)) => j,
        Ok(None) => return RemovalResult::Failed("no handoff and no journal: nothing to resume".into()),
        Err(e) => return deferred(format!("the journal is unreadable: {e}")),
    };
    let verdict = match &j.phase {
        Phase::Finished { reported } => match (&j.failure, reported) {
            (Some(why), _) => RemovalResult::Failed(why.clone()),
            (None, true) => RemovalResult::Complete { residue: None },
            (None, false) => RemovalResult::Unreported,
        },
        Phase::Aborted { reason } => RemovalResult::Failed(reason.clone()),
        _ => return RemovalResult::Failed("the handoff is missing but the removal is not finished".into()),
    };
    ops.release_install_dir();
    if let Err(r) = finalize_leftovers(ops) {
        return r;
    }
    verdict
}

/// Phase 1: everything before the first irreversible step. `Err` is a final (or deferred) result: nothing was removed.
fn start_fresh(
    h: &HelperHandoff,
    ops: &mut dyn RemovalOps,
    acks: &mut dyn AckChannel,
    journal: &mut dyn JournalStore,
    clock: &dyn Fn() -> i64,
) -> Result<Journal, RemovalResult> {
    // E4: freshness against the REAL clock, independently of whoever launched us.
    let verified = match proto::verify_directive(
        Some(&h.base.pinned_directive_key),
        &h.base.artifact,
        &Expectation {
            device_id: &h.base.device_id,
            tenant_id: &h.base.tenant_id,
            key_fp: &h.base.key_fp,
            now_ms: clock(),
        },
        &proto::EmptyLedger,
    ) {
        Ok(v) if v.kind == DirectiveKind::Uninstall && v.claims.directive_id == h.base.directive_id.to_ascii_lowercase() => v,
        Ok(_) => return Err(RemovalResult::Failed("the handoff is not this uninstall directive".into())),
        Err(r) => return Err(RemovalResult::Failed(format!("re-verification refused the directive: {}", r.code()))),
    };
    if let Err(why) = preflight(ops, h) {
        return Err(RemovalResult::Failed(why));
    }
    let root_identity = ops.config_root_identity();
    let recordings = match ops.settle_recordings() {
        Ok(r) => r,
        Err(why) => return Err(RemovalResult::Failed(format!("pending recording uploads could not be settled: {why}"))),
    };
    let note = recording_note(&recordings);
    // R4: hold the validated install chain through the removal; an unsafe install is refused BEFORE the installer is invoked.
    if let Err(why) = ops.hold_install_dir(&h.install_dir) {
        return Err(RemovalResult::Failed(format!("the install directory is not safe to remove: {why}")));
    }
    // R2: the protected restart mechanism exists BEFORE the first irreversible step.
    if let Err(why) = ops.install_resume_task() {
        ops.release_install_dir();
        return Err(RemovalResult::Failed(format!("the restart task could not be installed: {why}")));
    }
    // A2: the boot id is durable BEFORE the installer runs.
    let mut j = Journal::new(verified.claims.expires_at_ms, note, ops.boot_id(), root_identity);
    if let Err(e) = journal.save(&j) {
        let _ = ops.remove_resume_task();
        ops.release_install_dir();
        return Err(RemovalResult::Failed(format!("the journal could not be written: {e}")));
    }
    // A5: the clock, one last time, IMMEDIATELY before the irreversible call. An expired directive is durably cancelled: no installer.
    if clock() >= j.expires_at_ms {
        return Err(abort(ops, journal, &mut j, "the directive expired before the installer could start".into()));
    }
    // The MSI removal itself.
    let rc = ops.configure_absent(&h.product_code);
    let reboot = REBOOT_RCS.contains(&rc);
    if rc != 0 && !reboot {
        return Err(abort(ops, journal, &mut j, format!("the installer returned {rc}; the product was not removed")));
    }
    match ops.installed_products() {
        Ok(p) if p.iter().any(|c| c.eq_ignore_ascii_case(&h.product_code)) && !reboot => {
            return Err(abort(ops, journal, &mut j, "the installer reported success but the product is still registered".into()));
        }
        Ok(_) => {}
        Err(e) => {
            // Cannot tell. The journal stays at MsiStarting: the resume reconciles it against the product registration.
            return Err(deferred(format!("could not confirm the product is gone: {e}")));
        }
    }
    ops.release_install_dir();
    acks.agent_removed();
    j.phase = Phase::MsiDone;
    j.reboot_required = reboot;
    j.reboot_known = reboot;
    if let Err(r) = save(journal, &j) {
        return Err(r);
    }
    Ok(j)
}

/// The restart task's definition (R2): SYSTEM, at boot and on a repeat, re-running the helper copy against its own handoff. The
/// command and its argument are separate XML elements (no shell, no command-line string is composed), both are validated to contain
/// nothing that could break out of them, and the task carries an explicit protected security descriptor (SYSTEM and Administrators
/// only) so that nobody else can modify or run it.
pub fn resume_task_xml(helper_exe: &str, handoff_path: &str) -> Result<String, String> {
    for p in [helper_exe, handoff_path] {
        if p.is_empty() || p.chars().any(|c| c == '"' || c.is_control() || c == '%') {
            return Err("a path contains a character that is not allowed in the restart task".into());
        }
    }
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>DeskRally agent removal (resumes an interrupted removal)</Description>
    <SecurityDescriptor>{TASK_SDDL}</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Delay>PT1M</Delay><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Repetition><Interval>PT10M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="System"><Exec><Command>{}</Command><Arguments>directive-removal "{}"</Arguments></Exec></Actions>
</Task>
"#,
        esc(helper_exe),
        esc(handoff_path)
    ))
}

/// Protected DACL: SYSTEM and Administrators full control, nobody else.
pub const TASK_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

// ---------------------------------------------------------------------------------------------------
// Path validation (D-C7)
// ---------------------------------------------------------------------------------------------------

/// Why a claimed directory was not accepted as the expected one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    NotAbsolute,
    /// `.`/`..` components, a UNC / device / verbatim prefix, or an unusable spelling.
    NotCanonical,
    Missing,
    NotADirectory,
    /// A component on the way is a reparse point (junction, symlink, mount point).
    ReparsePoint(PathBuf),
    /// Resolves somewhere other than the expected directory.
    Mismatch { resolved: PathBuf, expected: PathBuf },
    Io(String),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::NotAbsolute => f.write_str("not an absolute path"),
            PathError::NotCanonical => f.write_str("not a canonical drive-letter path"),
            PathError::Missing => f.write_str("does not exist"),
            PathError::NotADirectory => f.write_str("not a directory"),
            PathError::ReparsePoint(p) => write!(f, "{} is a reparse point", p.display()),
            PathError::Mismatch { resolved, expected } => {
                write!(f, "resolves to {} instead of {}", resolved.display(), expected.display())
            }
            PathError::Io(e) => write!(f, "{e}"),
        }
    }
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_reparse(md: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// A plain `X:\a\b` path: a drive prefix, then normal components only.
fn plain_components(p: &Path) -> Result<Vec<std::ffi::OsString>, PathError> {
    use std::path::{Component, Prefix};
    if !p.is_absolute() {
        return Err(PathError::NotAbsolute);
    }
    let mut out = Vec::new();
    let mut comps = p.components();
    match comps.next() {
        Some(Component::Prefix(pre)) if matches!(pre.kind(), Prefix::Disk(_)) => out.push(pre.as_os_str().to_owned()),
        _ => return Err(PathError::NotCanonical),
    }
    match comps.next() {
        Some(Component::RootDir) => {}
        _ => return Err(PathError::NotCanonical),
    }
    for c in comps {
        match c {
            Component::Normal(n) => out.push(n.to_owned()),
            _ => return Err(PathError::NotCanonical),
        }
    }
    Ok(out)
}

fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
}

fn same_place(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().trim_end_matches('\\').eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches('\\'))
}

/// Accept `claimed` only if it is a plain, existing directory path with NO reparse point on any component, whose canonical
/// form is `expected`. This is a by-name check, so it is only the FIRST gate: deletion happens through handles opened and
/// compared afterwards ([`ConfigTree`]), which is what closes the swap window.
pub fn verify_dir_identity(claimed: &Path, expected: &Path) -> Result<PathBuf, PathError> {
    let parts = plain_components(claimed)?;
    plain_components(expected)?;
    // Walk every prefix below the drive root.
    let mut acc = PathBuf::from(format!("{}\\", parts[0].to_string_lossy()));
    for part in &parts[1..] {
        acc.push(part);
        let md = std::fs::symlink_metadata(&acc).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                PathError::Missing
            } else {
                PathError::Io(e.to_string())
            }
        })?;
        if is_reparse(&md) {
            return Err(PathError::ReparsePoint(acc));
        }
    }
    let md = std::fs::symlink_metadata(claimed).map_err(|e| PathError::Io(e.to_string()))?;
    if !md.is_dir() {
        return Err(PathError::NotADirectory);
    }
    let resolved = strip_verbatim(&std::fs::canonicalize(claimed).map_err(|e| PathError::Io(e.to_string()))?);
    let expected_resolved = strip_verbatim(&std::fs::canonicalize(expected).map_err(|e| PathError::Io(e.to_string()))?);
    if !same_place(&resolved, &expected_resolved) || !same_place(&resolved, claimed) {
        return Err(PathError::Mismatch { resolved, expected: expected_resolved });
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------------------------------
// The config tree (D-C7): pre-flight, then delete through handles that are compared to the pre-flight identity
// ---------------------------------------------------------------------------------------------------

/// The agent root to delete. `preflight` opens it through an [`Anchor`] (plain directory, trusted owner/DACL, parent without
/// delete-child for others), walks it read-only, and remembers its identity; `delete` reopens it, REQUIRES the same identity
/// and the same final path, re-walks it, then deletes contents handle-relative (each file re-validated on its own delete
/// handle) and finally the emptied directory.
pub struct ConfigTree {
    limits: TreeLimits,
    identity: Option<FileIdentity>,
}

impl ConfigTree {
    pub fn new() -> Self {
        Self { limits: TreeLimits::default(), identity: None }
    }

    pub fn preflight(&mut self, dir: &Path) -> Result<usize, String> {
        let anchor = Anchor::open_at(dir).map_err(|e| e.to_string())?;
        let n = anchor.dir().validate_tree(&self.limits).map_err(|e| e.to_string())?;
        self.identity = Some(anchor.identity());
        Ok(n)
    }

    /// Reopen the directory and require it to be the very one pre-flighted, at the expected path, and still a valid tree.
    fn reopen(&self, dir: &Path) -> Result<Anchor, String> {
        let want = self.identity.ok_or("config directory was not pre-flighted")?;
        let anchor = Anchor::open_at(dir).map_err(|e| e.to_string())?;
        anchor.expect_identity(&want).map_err(|e| e.to_string())?;
        let opened = strip_verbatim(Path::new(&anchor.dir().final_path().map_err(|e| e.to_string())?));
        if !same_place(&opened, dir) {
            return Err(format!("the opened directory is {} not {}", opened.display(), dir.display()));
        }
        // A fresh walk under the held handle: anything planted since the pre-flight stops the deletion.
        anchor.dir().validate_tree(&self.limits).map_err(|e| e.to_string())?;
        Ok(anchor)
    }

    /// R1: delete every top-level entry EXCEPT `identity.key` (recordings, config, state, directive records), each handle-relative
    /// and re-validated. Idempotent: a second call after a partial failure continues.
    pub fn delete_except_identity(&mut self, dir: &Path) -> Result<usize, String> {
        let anchor = self.reopen(dir)?;
        let mut removed = 0;
        for name in anchor.dir().list().map_err(|e| e.to_string())? {
            if name.eq_ignore_ascii_case(IDENTITY_FILE_NAME) {
                continue;
            }
            anchor.dir().remove_entry(&name, &self.limits).map_err(|e| format!("{name}: {e}"))?;
            removed += 1;
        }
        Ok(removed)
    }

    /// The identity of the agent root as pre-flighted.
    pub fn identity(&self) -> Option<FileIdentity> {
        self.identity
    }

    /// After a restart: the identity every later open must match (the journaled pre-flight one).
    pub fn expect(&mut self, id: Option<FileIdentity>) {
        self.identity = id;
    }

    /// Open the root and require it to be the expected one (no tree walk).
    fn open_expected(&self, dir: &Path) -> Result<Anchor, String> {
        let want = self.identity.ok_or("the agent root's identity is not known")?;
        let anchor = Anchor::open_at(dir).map_err(|e| e.to_string())?;
        anchor.expect_identity(&want).map_err(|e| e.to_string())?;
        Ok(anchor)
    }

    /// R1: VERIFY nothing but `identity.key` is left, in the root that was pre-flighted.
    pub fn verify_only_identity_left(&mut self, dir: &Path) -> Result<(), String> {
        let anchor = self.open_expected(dir)?;
        let left = Self::others(&anchor)?;
        if left.is_empty() {
            Ok(())
        } else {
            Err(format!("{} entr{} remain{} ({})", left.len(), if left.len() == 1 { "y" } else { "ies" }, if left.len() == 1 { "s" } else { "" }, left.join(", ")))
        }
    }

    fn others(anchor: &Anchor) -> Result<Vec<String>, String> {
        Ok(anchor
            .dir()
            .list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|n| !n.eq_ignore_ascii_case(IDENTITY_FILE_NAME))
            .collect())
    }

    /// A6: `identity.key`, then the emptied root. The root is reopened and REQUIRED to be the pre-flighted one; only the identity
    /// entry may remain; the identity goes through a validated handle; `RemoveDirectory` then fails on a non-empty directory and
    /// removes a swapped-in junction as itself, never its target. `allow_absent`: an identity or root that is already gone is success
    /// (finalization recovery: a previous attempt may have deleted it before its journal entry was written).
    pub fn delete_identity_and_root(&mut self, dir: &Path, allow_absent: bool) -> Result<(), String> {
        let absent = |e: &str| e.contains("os error 2") || e.contains("os error 3") || e.to_ascii_lowercase().contains("cannot find");
        {
            let anchor = match self.open_expected(dir) {
                Ok(a) => a,
                Err(e) if allow_absent && absent(&e) => return Ok(()), // the root itself is already gone
                Err(e) => return Err(e),
            };
            let others = Self::others(&anchor)?;
            if !others.is_empty() {
                return Err(format!("unexpected entries remain in the agent root: {}", others.join(", ")));
            }
            if !allow_absent && anchor.dir().entry_kind(IDENTITY_FILE_NAME).is_err() {
                return Err("identity.key is not there".into());
            }
            anchor.dir().remove_validated_file(IDENTITY_FILE_NAME).map_err(|e| e.to_string())?;
            // Verify: nothing at all is left.
            if !anchor.dir().list().map_err(|e| e.to_string())?.is_empty() {
                return Err("the agent root is not empty after deleting the identity".into());
            }
        }
        match std::fs::remove_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if allow_absent && e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("could not remove the emptied directory: {e}")),
        }
    }
}


impl Default for ConfigTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
