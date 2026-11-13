//! The auto-update attempt state machine: one durable document, pure transitions.
//!
//! Design: coordination/designs/agent-auto-update-bootstrap-v3..v10.md (Codex-accepted v10.1). Later
//! amendments supersede earlier text; the section names below (v10 launch, C1, L2', P1, R2, H1', S1') are
//! the design's, so a reviewer can map each rule to its paragraph.
//!
//! Nothing in this module performs I/O. The runner/worker read evidence, call these functions, and
//! persist the returned [`UpdateState`] with ONE atomic write. That is the whole crash-safety
//! argument for the bookkeeping: a transition is either durable in full or not at all, so a crash
//! can never leave "barrier consumed but verification not started", or "outcome counted but not
//! recorded" (Codex v7 P1).
//!
//! The classification ([`classify`]) is a total function over [`Evidence`]: every combination maps
//! to exactly one [`Outcome`], with [`Outcome::Unknown`] as the conservative fallback (rule 9).
//! Quarantine (refusing a release forever) needs AFFIRMATIVE evidence — a candidate fault written by
//! the new binary itself, or a Verification failure. A timeout, an unknown exit code, or missing
//! evidence never quarantines: those are what a signaling outage looks like too (Codex v6 H1).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Transient backoff ladder (design v3 step 2 / v2 D8): 1 h, 4 h, then 24 h forever.
const BACKOFF_MS: [u64; 3] = [3_600_000, 4 * 3_600_000, 24 * 3_600_000];
/// After this many consecutive non-Done outcomes for one release: operational pause (H1').
const PAUSE_AFTER_FAILURES: u32 = 3;
/// Two consecutive reboot-class rollbacks for one release also pause (P1).
const PAUSE_AFTER_REBOOT_ROLLBACKS: u32 = 2;
/// While paused: one attempt per 24 h. Retries never stop permanently (H1').
const PAUSED_RETRY_MS: u64 = 24 * 3_600_000;
/// Idempotent counting window (P1): ids of attempts whose outcome has been counted.
const COUNTED_ATTEMPTS: usize = 8;
/// PostBootVerify: distinct registrations reporting a non-target version before Anomaly (P1/R2).
const VERIFY_MISMATCH_REGISTRATIONS: u32 = 3;
/// PostBootVerify: boots without three registrations before Anomaly (R2).
const VERIFY_MAX_BOOTS: u32 = 5;
/// Quarantined digests kept (bounded so the document stays small).
const MAX_QUARANTINE: usize = 16;

/// What one attempt is trying to do. Persisted at Prelaunch, BEFORE any process exists (L1').
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt_id: String,
    pub previous_product_code: String,
    pub previous_product_version: String,
    pub target_product_code: String,
    pub target_product_version: String,
    pub target_version: String,
    pub msi_sha256: String,
    pub nonce: String,
    pub boot_id: String,
    /// The installed agent's version when the attempt began (from its registration heartbeat).
    /// An ack carrying THIS version means the old binary is still answering: in-use (rule 5).
    #[serde(default)]
    pub previous_version: String,
    /// The agent root's (anchor) identity recorded at Prelaunch; every component that touches
    /// attempt evidence refuses a root with a different identity (v6 A1).
    #[serde(default)]
    pub anchor: Option<crate::anchor::FileIdentity>,
    /// docs/65: the fleet directive this attempt is for (a `reinstall`), persisted ATOMICALLY with the attempt itself (the one
    /// Prelaunch write), so a crash can never leave an attempt that a directive cannot find or a directive that launches a second one.
    #[serde(default)]
    pub directive_id: Option<String>,
}

/// The runner process identity, persisted at Installing (v10 launch). A pid alone is never trusted:
/// recovery compares creation times, because pids are reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerIdentity {
    pub pid: u32,
    pub creation_time: u64,
}

/// Which reboot-class outcome a barrier / post-boot verification belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebootKind {
    DonePendingReboot,
    TargetUnacked,
    RolledBackReboot,
}

/// Attempt phase. Every transition writes the whole [`UpdateState`] atomically.
///
/// ```text
/// Prelaunch -> Installing --(E-exit or E-txn, then idle)--> classify -> {Idle | RebootBarrier | PostBootVerify}
/// Installing --(runner gone, no E-exit, no E-txn, same boot)--> Unresolved
/// {Installing, Unresolved} --(different boot, idle)--> classify
/// RebootBarrier --(new boot)--> PostBootVerify -> Idle      (target kinds)
/// RebootBarrier --(new boot)--> Idle                        (RolledBackReboot)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Idle,
    /// Persisted by the worker before the runner exists. Never classified: nothing reached the
    /// installer, so it resolves as NotStarted.
    Prelaunch {
        attempt: Attempt,
    },
    /// Persisted by the runner BEFORE it calls MsiInstallProductW (v10 launch).
    Installing {
        attempt: Attempt,
        runner: RunnerIdentity,
    },
    /// The runner died with no return code and no transaction marker on this boot. A request it
    /// handed to the installer may still execute, so nothing proves the attempt is over: surfaced,
    /// blocks every launch, resolved only on a different boot (v10.1 C1).
    Unresolved {
        attempt: Attempt,
    },
    RebootBarrier {
        attempt: Attempt,
        kind: RebootKind,
        boot_id: String,
    },
    PostBootVerify {
        attempt: Attempt,
        kind: RebootKind,
        verify_boot_id: String,
        heartbeats_seen: u32,
        last_registration_id: Option<String>,
        boots_elapsed: u32,
    },
}

impl Phase {
    /// The attempt in flight, if any.
    pub fn attempt(&self) -> Option<&Attempt> {
        match self {
            Phase::Idle => None,
            Phase::Prelaunch { attempt }
            | Phase::Installing { attempt, .. }
            | Phase::Unresolved { attempt }
            | Phase::RebootBarrier { attempt, .. }
            | Phase::PostBootVerify { attempt, .. } => Some(attempt),
        }
    }

    /// The ONLY phases classification may run from (v10.1 C1), each under its own precondition
    /// checked by the caller: Installing needs E-exit or E-txn (or a different boot) plus an idle
    /// installer; Unresolved needs a different boot plus an idle installer. Prelaunch is
    /// NotStarted by construction, and barrier/verify/idle are never reclassified, so a crash after
    /// any transition cannot recreate a barrier or count an outcome twice.
    pub fn classifiable(&self) -> Option<&Attempt> {
        match self {
            Phase::Installing { attempt, .. } | Phase::Unresolved { attempt } => Some(attempt),
            _ => None,
        }
    }
}

/// An outcome that the operator must see. New attempts are blocked while one is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anomaly {
    pub attempt_id: Option<String>,
    pub reason: String,
    pub at_ms: u64,
}

/// H1': surfaced, never permanent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalPause {
    pub msi_sha256: String,
    pub since_ms: u64,
    pub reason: String,
}

/// The whole durable updater document (`update-state.json`). Additive-only (design v4): an older
/// runner must still parse what a newer one wrote, so unknown fields are tolerated, not refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    pub format: u32,
    pub phase: Phase,
    #[serde(default)]
    pub last_check_ms: u64,
    /// Earliest time the next attempt may start (Transient backoff / pause).
    #[serde(default)]
    pub next_attempt_ms: u64,
    /// Release the consecutive counters belong to; reset when a different release is attempted.
    #[serde(default)]
    pub counted_release: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub consecutive_reboot_rollbacks: u32,
    #[serde(default)]
    pub counted_attempts: VecDeque<String>,
    #[serde(default)]
    pub quarantined: VecDeque<String>,
    #[serde(default)]
    pub pause: Option<OperationalPause>,
    #[serde(default)]
    pub anomaly: Option<Anomaly>,
    #[serde(default)]
    pub last_outcome: Option<String>,
    /// Outcomes keyed by the attempt that produced them (bounded). `last_outcome` is global and says nothing about WHICH attempt
    /// it belongs to; a directive reads only its own attempt's entry here.
    #[serde(default)]
    pub attempt_outcomes: VecDeque<AttemptOutcome>,
}

/// One attempt's recorded outcome (docs/65).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptOutcome {
    pub attempt_id: String,
    #[serde(default)]
    pub directive_id: Option<String>,
    /// `Done`, `DonePendingReboot`, `RolledBack`, `Anomaly`, or a classification name (`Health`, `Unknown`, ...).
    pub outcome: String,
}

const MAX_ATTEMPT_OUTCOMES: usize = 16;

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            format: 2,
            phase: Phase::Idle,
            last_check_ms: 0,
            next_attempt_ms: 0,
            counted_release: None,
            consecutive_failures: 0,
            consecutive_reboot_rollbacks: 0,
            counted_attempts: VecDeque::new(),
            quarantined: VecDeque::new(),
            pause: None,
            anomaly: None,
            last_outcome: None,
            attempt_outcomes: VecDeque::new(),
        }
    }
}

// ─── Classification (L2') ─────────────────────────────────────────────────────

/// Which installed product of the UpgradeCode family remains after the installer finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledFamily {
    Previous,
    Target,
    /// None, several, or an unrelated product. Never acted on automatically (rule 1).
    Other,
}

/// HealthGate's durable record, `gate.<attempt_id>.json` (E-gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateResult {
    Passed,
    Timeout,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateEvidence {
    pub result: GateResult,
    /// Old binary answered, or the on-disk FileVersion is not the expected one: a deferred
    /// (in-use) replacement.
    pub in_use: bool,
    /// `teardown-complete.<attempt_id>` existed for this boot when the gate looked (S1').
    pub teardown_complete: bool,
}

/// Every piece of durable, attempt-bound evidence classification may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub installed: InstalledFamily,
    /// The installer log reports an incomplete rollback.
    pub incomplete_rollback: bool,
    /// The attempt was still at Prelaunch (the runner never recorded Installing).
    pub prelaunch_only: bool,
    /// msiexec exit code, if the runner persisted one.
    pub exit: Option<u32>,
    pub gate: Option<GateEvidence>,
    /// E-ack: matching attempt ack (nonce + expected version).
    pub ack_matches: bool,
    /// E-cand: an affirmative candidate fault for this attempt, stated by the candidate itself
    /// (an explicit signaling rejection, or unreadable config). The service-observed "three fast
    /// helper deaths" producer named in design v7 is deliberately NOT implemented: the service
    /// cannot positively prove a dead helper never registered (Codex impl A round 2), and dropping
    /// a producer can only turn a quarantine into a backed-off retry, never a wrong outcome.
    pub candidate_fault: bool,
    /// E-teardown: `teardown-complete.<attempt_id>` exists (read by the classifier directly).
    pub teardown_record: bool,
    /// E-pfro: PendingFileRenameOperations entries under install_location or C:\rmt-agent.
    pub pending_renames: bool,
    /// Another custom action recorded a Verification-class failure for this attempt.
    pub verification_failure: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Anomaly,
    NotStarted,
    DonePendingReboot,
    Done,
    TargetUnacked,
    RolledBackReboot,
    Busy,
    Health,
    Verification,
    Unknown,
}

impl Outcome {
    /// Only affirmative evidence quarantines (H1').
    pub fn quarantines(self) -> bool {
        matches!(self, Outcome::Health | Outcome::Verification)
    }
}

const ERROR_SUCCESS_REBOOT_REQUIRED: u32 = 3010;
const ERROR_SUCCESS_REBOOT_INITIATED: u32 = 1641;
const ERROR_INSTALL_ALREADY_RUNNING: u32 = 1618;

fn reboot_exit(exit: Option<u32>) -> bool {
    matches!(
        exit,
        Some(ERROR_SUCCESS_REBOOT_REQUIRED) | Some(ERROR_SUCCESS_REBOOT_INITIATED)
    )
}

/// Rules 1-9 of design v7 L2', first match wins. Total: rule 9 catches everything else.
pub fn classify(e: &Evidence) -> Outcome {
    // 1. An installed state we do not understand is never acted on.
    if e.installed == InstalledFamily::Other || e.incomplete_rollback {
        return Outcome::Anomaly;
    }
    // 2. Never authorized: the kernel killed any process with the job.
    if e.prelaunch_only {
        return Outcome::NotStarted;
    }
    if e.installed == InstalledFamily::Target {
        // 3. Committed, but a reboot is owed before the new files are all in place.
        if reboot_exit(e.exit) || e.pending_renames {
            return Outcome::DonePendingReboot;
        }
        // 4. Committed means the gate passed; the ack is confirmation, not permission.
        return if e.ack_matches {
            Outcome::Done
        } else {
            Outcome::TargetUnacked
        };
    }
    // Installed = previous from here on.
    // 5. Reboot / teardown uncertainty outranks candidate blame: a binary that could not be
    //    replaced, or a helper that might still have been running, is not evidence the candidate
    //    is bad.
    let gate_reboot = e
        .gate
        .is_some_and(|g| g.in_use || !g.teardown_complete);
    if gate_reboot
        || (e.gate.is_none() && !e.teardown_record)
        || e.pending_renames
        || reboot_exit(e.exit)
    {
        return Outcome::RolledBackReboot;
    }
    // 6. Another installation held the installer.
    if e.exit == Some(ERROR_INSTALL_ALREADY_RUNNING) {
        return Outcome::Busy;
    }
    // 7. The new binary itself said it is broken.
    if e.candidate_fault {
        return Outcome::Health;
    }
    // 8. A custom action rejected the package.
    if e.verification_failure {
        return Outcome::Verification;
    }
    // 9. Everything else, including a bare gate timeout.
    Outcome::Unknown
}

// ─── Transitions ──────────────────────────────────────────────────────────────

fn reboot_kind(outcome: Outcome) -> Option<RebootKind> {
    match outcome {
        Outcome::DonePendingReboot => Some(RebootKind::DonePendingReboot),
        Outcome::RolledBackReboot => Some(RebootKind::RolledBackReboot),
        _ => None,
    }
}

impl UpdateState {
    /// A signed offer for a DIFFERENT release than the one the counters, pause and pacing belong
    /// to starts fresh (H1': a newer signed release clears the pause). Returns true if it changed.
    pub fn accept_offer(&mut self, msi_sha256: &str) -> bool {
        let stale = self.counted_release.as_deref().is_some_and(|r| r != msi_sha256)
            || self.pause.as_ref().is_some_and(|p| p.msi_sha256 != msi_sha256);
        if stale {
            self.counted_release = Some(msi_sha256.to_owned());
            self.consecutive_failures = 0;
            self.consecutive_reboot_rollbacks = 0;
            self.pause = None;
            self.next_attempt_ms = 0;
        }
        stale
    }

    /// Whether the next attempt may start now for `msi_sha256`, and if not, why.
    pub fn may_start(&self, msi_sha256: &str, now_ms: u64) -> Result<(), &'static str> {
        if self.anomaly.is_some() {
            return Err("anomaly recorded; admin action required");
        }
        match self.phase {
            Phase::Idle => {}
            Phase::Unresolved { .. } => {
                return Err("unresolved attempt; resolves after a reboot");
            }
            _ => return Err("an attempt is unresolved"),
        }
        if self.quarantined.iter().any(|q| q == msi_sha256) {
            return Err("release quarantined");
        }
        if now_ms < self.next_attempt_ms {
            return Err("backing off");
        }
        Ok(())
    }

    /// Count `attempt`'s outcome at most once (P1). Returns false if already counted.
    fn count_once(&mut self, attempt: &Attempt) -> bool {
        if self.counted_attempts.iter().any(|a| a == &attempt.attempt_id) {
            return false;
        }
        self.counted_attempts.push_back(attempt.attempt_id.clone());
        while self.counted_attempts.len() > COUNTED_ATTEMPTS {
            self.counted_attempts.pop_front();
        }
        if self.counted_release.as_deref() != Some(&attempt.msi_sha256) {
            self.counted_release = Some(attempt.msi_sha256.clone());
            self.consecutive_failures = 0;
            self.consecutive_reboot_rollbacks = 0;
        }
        true
    }

    /// Record `label` as the outcome of `attempt` (replacing an earlier entry for the same attempt).
    fn note_outcome(&mut self, attempt: &Attempt, label: &str) {
        self.attempt_outcomes.retain(|o| o.attempt_id != attempt.attempt_id);
        self.attempt_outcomes.push_back(AttemptOutcome {
            attempt_id: attempt.attempt_id.clone(),
            directive_id: attempt.directive_id.clone(),
            outcome: label.to_owned(),
        });
        while self.attempt_outcomes.len() > MAX_ATTEMPT_OUTCOMES {
            self.attempt_outcomes.pop_front();
        }
    }

    /// The attempt (in flight or finished) that belongs to `directive_id`: its id and, when it has finished, its own outcome.
    pub fn attempt_for_directive(&self, directive_id: &str) -> Option<(String, Option<String>)> {
        if let Some(a) = self.phase.attempt().filter(|a| a.directive_id.as_deref() == Some(directive_id)) {
            let done = self.attempt_outcomes.iter().find(|o| o.attempt_id == a.attempt_id).map(|o| o.outcome.clone());
            return Some((a.attempt_id.clone(), done));
        }
        self.attempt_outcomes
            .iter()
            .rev()
            .find(|o| o.directive_id.as_deref() == Some(directive_id))
            .map(|o| (o.attempt_id.clone(), Some(o.outcome.clone())))
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_reboot_rollbacks = 0;
        self.pause = None;
        self.next_attempt_ms = 0;
    }

    fn record_failure(&mut self, attempt: &Attempt, reboot_rollback: bool, now_ms: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if reboot_rollback {
            self.consecutive_reboot_rollbacks = self.consecutive_reboot_rollbacks.saturating_add(1);
        } else {
            self.consecutive_reboot_rollbacks = 0;
        }
        if self.pause.is_none()
            && (self.consecutive_failures >= PAUSE_AFTER_FAILURES
                || self.consecutive_reboot_rollbacks >= PAUSE_AFTER_REBOOT_ROLLBACKS)
        {
            self.pause = Some(OperationalPause {
                msi_sha256: attempt.msi_sha256.clone(),
                since_ms: now_ms,
                reason: format!(
                    "{} consecutive unsuccessful attempts ({} reboot-class)",
                    self.consecutive_failures, self.consecutive_reboot_rollbacks
                ),
            });
        }
        let step = (self.consecutive_failures.max(1) as usize - 1).min(BACKOFF_MS.len() - 1);
        let wait = if self.pause.is_some() {
            PAUSED_RETRY_MS
        } else {
            BACKOFF_MS[step]
        };
        self.next_attempt_ms = now_ms.saturating_add(wait);
    }

    /// Refuse this release from now on (Health / Verification only, design v6 H1).
    pub fn quarantine_release(&mut self, msi_sha256: &str) {
        if !self.quarantined.iter().any(|q| q == msi_sha256) {
            self.quarantined.push_back(msi_sha256.to_owned());
            while self.quarantined.len() > MAX_QUARANTINE {
                self.quarantined.pop_front();
            }
        }
    }

    /// Apply a classification result for the attempt in a classifiable phase. The caller
    /// persists the returned state with ONE atomic write (R4); evidence files are moved to
    /// history only after that write (P1).
    pub fn apply_outcome(&mut self, outcome: Outcome, current_boot_id: &str, now_ms: u64) {
        let Some(attempt) = self.phase.attempt().cloned() else {
            return;
        };
        let first = self.count_once(&attempt);
        self.last_outcome = Some(format!("{outcome:?} {}", attempt.target_version));
        self.note_outcome(&attempt, &format!("{outcome:?}"));
        match outcome {
            Outcome::Anomaly => {
                self.anomaly = Some(Anomaly {
                    attempt_id: Some(attempt.attempt_id.clone()),
                    reason: "installed state not previous-or-target, or incomplete rollback"
                        .into(),
                    at_ms: now_ms,
                });
                self.phase = Phase::Idle;
            }
            Outcome::Done => {
                if first {
                    self.record_success();
                }
                self.phase = Phase::Idle;
            }
            Outcome::TargetUnacked => {
                // Committed; verify by the registration heartbeat on this boot (P1).
                self.phase = Phase::PostBootVerify {
                    attempt,
                    kind: RebootKind::TargetUnacked,
                    verify_boot_id: current_boot_id.to_owned(),
                    heartbeats_seen: 0,
                    last_registration_id: None,
                    boots_elapsed: 0,
                };
            }
            Outcome::DonePendingReboot | Outcome::RolledBackReboot => {
                if first && outcome == Outcome::RolledBackReboot {
                    self.record_failure(&attempt, true, now_ms);
                }
                self.phase = Phase::RebootBarrier {
                    attempt,
                    kind: reboot_kind(outcome).expect("reboot outcome"),
                    boot_id: current_boot_id.to_owned(),
                };
            }
            Outcome::Health | Outcome::Verification => {
                self.quarantine_release(&attempt.msi_sha256);
                if first {
                    self.record_failure(&attempt, false, now_ms);
                }
                self.phase = Phase::Idle;
            }
            Outcome::NotStarted | Outcome::Busy | Outcome::Unknown => {
                if first {
                    self.record_failure(&attempt, false, now_ms);
                }
                self.phase = Phase::Idle;
            }
        }
    }

    /// Called at the start of every run with the current boot id. Consumes a barrier from an
    /// earlier boot, and re-arms PostBootVerify on a further reboot (R2). Returns true if the
    /// state changed (the caller persists it).
    pub fn on_boot(&mut self, current_boot_id: &str, now_ms: u64) -> bool {
        match &mut self.phase {
            Phase::RebootBarrier {
                attempt,
                kind,
                boot_id,
            } if boot_id != current_boot_id => {
                let attempt = attempt.clone();
                let kind = *kind;
                if kind == RebootKind::RolledBackReboot {
                    // Counted when the barrier was created; eligible again (backoff permitting).
                    self.last_outcome = Some(format!("RolledBack {}", attempt.target_version));
                    self.note_outcome(&attempt, "RolledBack");
                    self.phase = Phase::Idle;
                } else {
                    self.phase = Phase::PostBootVerify {
                        attempt,
                        kind,
                        verify_boot_id: current_boot_id.to_owned(),
                        heartbeats_seen: 0,
                        last_registration_id: None,
                        boots_elapsed: 0,
                    };
                }
                true
            }
            Phase::PostBootVerify {
                attempt,
                verify_boot_id,
                heartbeats_seen,
                last_registration_id,
                boots_elapsed,
                ..
            } if verify_boot_id != current_boot_id => {
                *boots_elapsed += 1;
                if *boots_elapsed >= VERIFY_MAX_BOOTS {
                    let id = attempt.attempt_id.clone();
                    let att = attempt.clone();
                    self.anomaly = Some(Anomaly {
                        attempt_id: Some(id),
                        reason: format!(
                            "{VERIFY_MAX_BOOTS} boots without verifying the installed version"
                        ),
                        at_ms: now_ms,
                    });
                    self.note_outcome(&att, "Anomaly");
                    self.phase = Phase::Idle;
                } else {
                    *verify_boot_id = current_boot_id.to_owned();
                    *heartbeats_seen = 0;
                    *last_registration_id = None;
                }
                true
            }
            _ => false,
        }
    }

    /// Feed the current registration heartbeat (R2). Each registration counts once. Returns true
    /// if the state changed.
    pub fn on_heartbeat(
        &mut self,
        registration_id: &str,
        boot_id: &str,
        version: &str,
        now_ms: u64,
    ) -> bool {
        let Phase::PostBootVerify {
            attempt,
            verify_boot_id,
            heartbeats_seen,
            last_registration_id,
            ..
        } = &mut self.phase
        else {
            return false;
        };
        if boot_id != verify_boot_id || last_registration_id.as_deref() == Some(registration_id) {
            return false;
        }
        let attempt = attempt.clone();
        if version == attempt.target_version {
            // Unconditional (Codex impl A): the attempt was already counted when it entered the
            // barrier/verification, so a count-gated reset would never run. Repeating it is
            // harmless: this same write moves the phase to Idle.
            self.count_once(&attempt);
            self.record_success();
            self.last_outcome = Some(format!("Done {}", attempt.target_version));
            self.note_outcome(&attempt, "Done");
            self.phase = Phase::Idle;
            return true;
        }
        *heartbeats_seen += 1;
        *last_registration_id = Some(registration_id.to_owned());
        if *heartbeats_seen >= VERIFY_MISMATCH_REGISTRATIONS {
            self.anomaly = Some(Anomaly {
                attempt_id: Some(attempt.attempt_id.clone()),
                reason: format!(
                    "committed {} but the agent reports {version}",
                    attempt.target_version
                ),
                at_ms: now_ms,
            });
            self.note_outcome(&attempt, "Anomaly");
            self.phase = Phase::Idle;
        }
        true
    }

    /// C1: the runner is gone, and neither its return code nor a transaction marker exists, on
    /// the attempt's own boot. Returns true if the state changed.
    pub fn mark_unresolved(&mut self) -> bool {
        if let Phase::Installing { attempt, .. } = &self.phase {
            self.phase = Phase::Unresolved {
                attempt: attempt.clone(),
            };
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(id: &str, sha: &str) -> Attempt {
        Attempt {
            attempt_id: id.into(),
            previous_product_code: "{P}".into(),
            previous_product_version: "1.2.7".into(),
            target_product_code: "{T}".into(),
            target_product_version: "1.3.1".into(),
            target_version: "0.1.1".into(),
            msi_sha256: sha.into(),
            nonce: "n".into(),
            boot_id: "b1".into(),
            previous_version: "0.1.0".into(),
            anchor: None,
            directive_id: None,
        }
    }
    fn runner() -> RunnerIdentity {
        RunnerIdentity {
            pid: 10,
            creation_time: 1,
        }
    }
    fn running(id: &str, sha: &str) -> UpdateState {
        UpdateState {
            phase: Phase::Installing {
                attempt: attempt(id, sha),
                runner: runner(),
            },
            ..Default::default()
        }
    }
    fn base() -> Evidence {
        Evidence {
            installed: InstalledFamily::Previous,
            incomplete_rollback: false,
            prelaunch_only: false,
            exit: Some(1603),
            gate: Some(GateEvidence {
                result: GateResult::Timeout,
                in_use: false,
                teardown_complete: true,
            }),
            ack_matches: false,
            candidate_fault: false,
            teardown_record: true,
            pending_renames: false,
            verification_failure: false,
        }
    }

    /// Every combination of evidence, for the property tests.
    fn all_evidence() -> Vec<Evidence> {
        let mut out = Vec::new();
        let gates = [
            None,
            Some((GateResult::Passed, false, true)),
            Some((GateResult::Timeout, false, true)),
            Some((GateResult::Timeout, true, true)),
            Some((GateResult::Timeout, false, false)),
            Some((GateResult::Mismatch, true, false)),
        ];
        let exits = [None, Some(0), Some(1603), Some(1618), Some(3010), Some(1641)];
        for installed in [
            InstalledFamily::Previous,
            InstalledFamily::Target,
            InstalledFamily::Other,
        ] {
            for bits in 0u32..(1 << 7) {
                for exit in exits {
                    for gate in gates {
                        out.push(Evidence {
                            installed,
                            incomplete_rollback: bits & 1 != 0,
                            prelaunch_only: bits & 2 != 0,
                            exit,
                            gate: gate.map(|(result, in_use, teardown_complete)| GateEvidence {
                                result,
                                in_use,
                                teardown_complete,
                            }),
                            ack_matches: bits & 4 != 0,
                            candidate_fault: bits & 8 != 0,
                            teardown_record: bits & 16 != 0,
                            pending_renames: bits & 32 != 0,
                            verification_failure: bits & 64 != 0,
                        });
                    }
                }
            }
        }
        out
    }

    #[test]
    fn each_rule_in_order() {
        let mut e = base();
        e.installed = InstalledFamily::Other;
        assert_eq!(classify(&e), Outcome::Anomaly, "rule 1 installed");
        let mut e = base();
        e.incomplete_rollback = true;
        e.candidate_fault = true;
        assert_eq!(classify(&e), Outcome::Anomaly, "rule 1 outranks Health");
        let mut e = base();
        e.prelaunch_only = true;
        assert_eq!(classify(&e), Outcome::NotStarted, "rule 2");
        let mut e = base();
        e.installed = InstalledFamily::Target;
        e.ack_matches = true;
        e.exit = Some(3010);
        assert_eq!(classify(&e), Outcome::DonePendingReboot, "rule 3 outranks Done");
        e.exit = Some(0);
        assert_eq!(classify(&e), Outcome::Done, "rule 4 ack");
        e.ack_matches = false;
        assert_eq!(classify(&e), Outcome::TargetUnacked, "rule 4 no ack");
        let mut e = base();
        e.candidate_fault = true;
        e.gate = Some(GateEvidence {
            result: GateResult::Timeout,
            in_use: true,
            teardown_complete: true,
        });
        assert_eq!(classify(&e), Outcome::RolledBackReboot, "rule 5 in-use outranks Health");
        let mut e = base();
        e.candidate_fault = true;
        e.gate = Some(GateEvidence {
            result: GateResult::Timeout,
            in_use: false,
            teardown_complete: false,
        });
        assert_eq!(classify(&e), Outcome::RolledBackReboot, "rule 5 teardown uncertainty");
        let mut e = base();
        e.gate = None;
        e.teardown_record = false;
        assert_eq!(classify(&e), Outcome::RolledBackReboot, "rule 5 no gate, no teardown");
        let mut e = base();
        e.gate = None;
        e.exit = Some(1618);
        assert_eq!(classify(&e), Outcome::Busy, "rule 6");
        let mut e = base();
        e.candidate_fault = true;
        assert_eq!(classify(&e), Outcome::Health, "rule 7");
        let mut e = base();
        e.verification_failure = true;
        assert_eq!(classify(&e), Outcome::Verification, "rule 8");
        assert_eq!(classify(&base()), Outcome::Unknown, "rule 9: a bare timeout");
        let mut e = base();
        e.exit = None;
        e.gate = None;
        assert_eq!(classify(&e), Outcome::Unknown, "rule 9: unknown exit, no gate");
    }

    /// Invariants that must hold for EVERY evidence combination (design v7 acceptance).
    #[test]
    fn classification_invariants_hold_for_every_combination() {
        let all = all_evidence();
        assert!(all.len() > 10_000);
        for e in &all {
            let o = classify(e);
            // Quarantine only on affirmative evidence.
            if o == Outcome::Health {
                assert!(e.candidate_fault, "{e:?}");
            }
            if o == Outcome::Verification {
                assert!(e.verification_failure, "{e:?}");
            }
            // Health never when reboot/teardown uncertainty exists.
            if o.quarantines() {
                assert!(!e.pending_renames && !reboot_exit(e.exit), "{e:?}");
                assert!(e.gate.map_or(e.teardown_record, |g| !g.in_use && g.teardown_complete));
            }
            // An unknown installed state is never acted on.
            if e.installed == InstalledFamily::Other || e.incomplete_rollback {
                assert_eq!(o, Outcome::Anomaly);
            }
            // A committed target never quarantines or claims a rollback.
            if e.installed == InstalledFamily::Target && o != Outcome::Anomaly && !e.prelaunch_only
            {
                assert!(matches!(
                    o,
                    Outcome::Done | Outcome::TargetUnacked | Outcome::DonePendingReboot
                ));
            }
            // A bare timeout (no cand, no verification) never quarantines.
            if !e.candidate_fault && !e.verification_failure {
                assert!(!o.quarantines());
            }
        }
    }

    #[test]
    fn health_quarantines_once_and_counts_once() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::Health, "b1", 1000);
        assert_eq!(s.phase, Phase::Idle);
        assert_eq!(s.quarantined, ["sha1"]);
        assert_eq!(s.consecutive_failures, 1);
        assert_eq!(s.may_start("sha1", u64::MAX), Err("release quarantined"));
        assert!(s.may_start("sha2", u64::MAX).is_ok());
        // Replaying the same attempt (a crash before evidence cleanup) never double-counts.
        s.phase = Phase::Installing {
            attempt: attempt("a1", "sha1"),
            runner: runner(),
        };
        s.apply_outcome(Outcome::Health, "b1", 2000);
        assert_eq!(s.consecutive_failures, 1);
        assert_eq!(s.quarantined.len(), 1);
    }

    #[test]
    fn transient_backoff_ladder_then_pause_never_stops() {
        let mut s = UpdateState::default();
        let mut now = 0;
        let mut waits = Vec::new();
        for i in 0..5 {
            s.phase = Phase::Installing {
                attempt: attempt(&format!("a{i}"), "sha1"),
                runner: runner(),
            };
            s.apply_outcome(Outcome::Unknown, "b1", now);
            waits.push(s.next_attempt_ms - now);
            now = s.next_attempt_ms;
            assert!(s.quarantined.is_empty(), "a timeout never quarantines");
        }
        assert_eq!(
            waits,
            [BACKOFF_MS[0], BACKOFF_MS[1], PAUSED_RETRY_MS, PAUSED_RETRY_MS, PAUSED_RETRY_MS]
        );
        assert!(s.pause.is_some(), "third failure pauses");
        assert!(s.may_start("sha1", now).is_ok(), "paused still retries daily");
        // A Done clears the pause and counters.
        s.phase = Phase::Installing {
            attempt: attempt("a9", "sha1"),
            runner: runner(),
        };
        s.apply_outcome(Outcome::Done, "b1", now);
        assert!(s.pause.is_none());
        assert_eq!(s.consecutive_failures, 0);
    }

    #[test]
    fn a_new_release_resets_the_counters() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::Unknown, "b1", 0);
        s.phase = Phase::Installing {
            attempt: attempt("a2", "sha1"),
            runner: runner(),
        };
        s.apply_outcome(Outcome::Unknown, "b1", 0);
        assert_eq!(s.consecutive_failures, 2);
        s.phase = Phase::Installing {
            attempt: attempt("a3", "sha2"),
            runner: runner(),
        };
        s.apply_outcome(Outcome::Unknown, "b1", 0);
        assert_eq!(s.consecutive_failures, 1);
    }

    #[test]
    fn rolled_back_reboot_barrier_then_eligible_and_two_pause() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::RolledBackReboot, "b1", 0);
        assert!(matches!(s.phase, Phase::RebootBarrier { .. }));
        assert_eq!(s.may_start("sha1", u64::MAX), Err("an attempt is unresolved"));
        assert!(!s.on_boot("b1", 0), "same boot keeps the barrier");
        assert!(s.on_boot("b2", 0));
        assert_eq!(s.phase, Phase::Idle);
        // A crash replay of on_boot is a no-op.
        assert!(!s.on_boot("b2", 0));
        s.phase = Phase::Installing {
            attempt: attempt("a2", "sha1"),
            runner: runner(),
        };
        s.apply_outcome(Outcome::RolledBackReboot, "b2", 0);
        assert!(s.pause.is_some(), "two consecutive reboot rollbacks pause");
        assert!(s.quarantined.is_empty());
    }

    #[test]
    fn done_pending_reboot_verifies_across_reboots() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::DonePendingReboot, "b1", 0);
        assert!(s.on_boot("b2", 0));
        let Phase::PostBootVerify { verify_boot_id, .. } = &s.phase else {
            panic!("{:?}", s.phase)
        };
        assert_eq!(verify_boot_id, "b2");
        // A stale heartbeat from the old boot is ignored.
        assert!(!s.on_heartbeat("r0", "b1", "0.1.1", 0));
        // A further reboot re-arms the verification instead of blocking forever.
        assert!(s.on_boot("b3", 0));
        assert!(s.on_heartbeat("r1", "b3", "0.1.1", 0));
        assert_eq!(s.phase, Phase::Idle);
        assert!(s.anomaly.is_none());
    }

    #[test]
    fn one_registration_counts_once_and_three_mismatches_are_anomaly() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::TargetUnacked, "b1", 0);
        for _ in 0..5 {
            s.on_heartbeat("r1", "b1", "0.1.0", 0);
        }
        let Phase::PostBootVerify {
            heartbeats_seen, ..
        } = &s.phase
        else {
            panic!()
        };
        assert_eq!(*heartbeats_seen, 1, "the same registration polled 5 times counts once");
        s.on_heartbeat("r2", "b1", "0.1.0", 0);
        s.on_heartbeat("r3", "b1", "0.1.0", 0);
        assert!(s.anomaly.is_some());
        assert!(s.may_start("sha2", u64::MAX).is_err());
    }

    #[test]
    fn verified_success_after_a_barrier_clears_failure_bookkeeping() {
        for kind in [Outcome::DonePendingReboot, Outcome::TargetUnacked] {
            let mut s = running("a0", "sha1");
            s.apply_outcome(Outcome::Unknown, "b1", 0);
            s.phase = Phase::Installing { attempt: attempt("a1", "sha1"), runner: runner() };
            s.apply_outcome(Outcome::Unknown, "b1", 0);
            s.phase = Phase::Installing { attempt: attempt("a2", "sha1"), runner: runner() };
            s.apply_outcome(Outcome::Unknown, "b1", 0);
            assert!(s.pause.is_some() && s.next_attempt_ms > 0 && s.consecutive_failures == 3);
            s.phase = Phase::Installing { attempt: attempt("a3", "sha1"), runner: runner() };
            s.apply_outcome(kind, "b1", 0);
            if kind == Outcome::DonePendingReboot {
                assert!(s.on_boot("b2", 0));
            }
            let boot = if kind == Outcome::DonePendingReboot { "b2" } else { "b1" };
            assert!(s.on_heartbeat("r1", boot, "0.1.1", 0));
            assert_eq!(s.phase, Phase::Idle, "{kind:?}");
            assert!(s.pause.is_none(), "{kind:?}");
            assert_eq!((s.consecutive_failures, s.next_attempt_ms), (0, 0), "{kind:?}");
        }
    }

    #[test]
    fn a_different_release_clears_the_previous_pause() {
        let mut s = UpdateState::default();
        for i in 0..3 {
            s.phase = Phase::Installing { attempt: attempt(&format!("a{i}"), "sha1"), runner: runner() };
            s.apply_outcome(Outcome::Unknown, "b1", 1000);
        }
        assert!(s.pause.is_some());
        assert!(s.may_start("sha2", 2000).is_err(), "premise: pacing applies before acceptance");
        assert!(!s.accept_offer("sha1"), "the same release keeps its pause");
        assert!(s.accept_offer("sha2"));
        assert!(s.pause.is_none());
        assert!(s.may_start("sha2", 2000).is_ok());
    }

    #[test]
    fn five_boots_without_verification_is_anomaly() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::TargetUnacked, "b0", 0);
        for i in 1..=5 {
            s.on_boot(&format!("b{i}"), 0);
        }
        assert!(s.anomaly.is_some());
    }

    #[test]
    fn unresolved_blocks_launches_and_classifies_later() {
        let mut s = running("a1", "sha1");
        assert!(s.mark_unresolved());
        assert!(!s.mark_unresolved(), "idempotent");
        assert_eq!(
            s.may_start("sha2", u64::MAX),
            Err("unresolved attempt; resolves after a reboot")
        );
        assert!(s.phase.classifiable().is_some(), "resolves by classification on a new boot");
        s.apply_outcome(Outcome::Unknown, "b2", 0);
        assert_eq!(s.phase, Phase::Idle);
        assert!(s.quarantined.is_empty(), "never quarantines without evidence");
    }

    #[test]
    fn only_c1_phases_classify() {
        let a = attempt("a1", "sha1");
        assert!(Phase::Prelaunch { attempt: a.clone() }.classifiable().is_none());
        assert!(Phase::RebootBarrier {
            attempt: a.clone(),
            kind: RebootKind::RolledBackReboot,
            boot_id: "b".into()
        }
        .classifiable()
        .is_none());
        assert!(Phase::Idle.classifiable().is_none());
        assert!(Phase::Installing {
            attempt: a.clone(),
            runner: runner(),
        }
        .classifiable()
        .is_some());
        assert!(Phase::Unresolved { attempt: a }.classifiable().is_some());
    }

    #[test]
    fn state_round_trips_and_tolerates_added_fields() {
        let mut s = running("a1", "sha1");
        s.apply_outcome(Outcome::DonePendingReboot, "b1", 5);
        let text = serde_json::to_string(&s).unwrap();
        let back: UpdateState = serde_json::from_str(&text).unwrap();
        assert_eq!(back, s);
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["future_field"] = 1.into();
        assert!(serde_json::from_value::<UpdateState>(v).is_ok(), "additive-only format");
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    fn att(id: &str, d: Option<&str>) -> Attempt {
        Attempt {
            attempt_id: id.into(), previous_product_code: "{A}".into(), previous_product_version: "1.0.0".into(),
            target_product_code: "{B}".into(), target_product_version: "1.0.1".into(), target_version: "0.1.1".into(),
            msi_sha256: "a".repeat(64), nonce: "n".into(), boot_id: "b".into(), previous_version: "v".into(),
            anchor: None, directive_id: d.map(str::to_owned),
        }
    }

    #[test]
    fn every_ending_of_an_attempt_records_its_own_keyed_outcome() {
        for (outcome, label) in [(Outcome::Done, "Done"), (Outcome::Health, "Health"), (Outcome::Unknown, "Unknown"), (Outcome::NotStarted, "NotStarted")] {
            let mut s = UpdateState::default();
            s.phase = Phase::Prelaunch { attempt: att("a1", Some("d")) };
            s.apply_outcome(outcome, "boot", 1);
            assert_eq!(s.attempt_for_directive("d"), Some(("a1".into(), Some(label.into()))), "{label}");
        }
        // A second attempt (another directive, then none) never overwrites the first's entry.
        let mut s = UpdateState::default();
        s.phase = Phase::Prelaunch { attempt: att("a1", Some("d")) };
        s.apply_outcome(Outcome::Done, "boot", 1);
        s.phase = Phase::Prelaunch { attempt: att("a2", None) };
        s.apply_outcome(Outcome::Health, "boot", 2);
        assert_eq!(s.attempt_for_directive("d"), Some(("a1".into(), Some("Done".into()))));
        assert_eq!(s.attempt_outcomes.len(), 2);
    }

    #[test]
    fn the_outcome_history_is_bounded_and_the_attempt_directive_link_survives_serialization() {
        let mut s = UpdateState::default();
        for i in 0..40 {
            s.phase = Phase::Prelaunch { attempt: att(&format!("a{i}"), Some(&format!("d{i}"))) };
            s.apply_outcome(Outcome::Done, "boot", i);
        }
        assert!(s.attempt_outcomes.len() <= 16);
        let back: UpdateState = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.attempt_for_directive("d39").map(|a| a.0), Some("a39".to_string()));
        assert_eq!(back.attempt_for_directive("d0"), None, "forgotten, not misattributed");
        // An older state document without the new fields still loads.
        let old = r#"{"format":2,"phase":"Idle"}"#;
        assert!(serde_json::from_str::<UpdateState>(old).is_ok());
    }
}
