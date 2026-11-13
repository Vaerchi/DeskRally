//! How a `reinstall` directive reaches the EXISTING update chain and how its progress is read back (docs/65 F4).
//!
//! A reinstall is not a second updater. The agent writes a small request marker into the anchored agent root and starts the
//! scheduled update worker; the worker, which already owns the session lock, the signed ring manifest, the digest and
//! Authenticode checks, HealthGate and rollback, consumes the marker and runs ONE ordinary attempt at the current signed ring
//! release, with "same version" allowed. The directive supplies NO URL, version or file: only the request to repair.
//!
//! Progress is read back from the update state document (never inferred from a process or a timer): the marker names the
//! attempt once the worker launched it, and [`probe`] maps that attempt's place in `UpdateState` to a [`ReinstallStatus`].
//! The mapping is pure, so it is tested without an installer.

use serde::{Deserialize, Serialize};

use crate::directive::ReinstallStatus;
use crate::update_state::UpdateState;

/// File name inside the anchored agent root.
pub const MARKER: &str = "directive-reinstall.json";
const MAX_MARKER_BYTES: usize = 4096;

/// How long after the directive expired a still-unfinished attempt may keep its `InProgress` reading.
pub const GRACE_MS: i64 = 24 * 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkerStatus {
    /// Written by the agent; the worker has not picked it up.
    Requested,
    /// The worker launched an attempt (`attempt_id` is set).
    Launched,
    /// The worker declined (`detail` says why): the update chain's own safety state (quarantine, pause, anomaly), no
    /// provisioned policy, no published release.
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub directive_id: String,
    pub requested_ms: i64,
    pub expires_at_ms: i64,
    pub status: MarkerStatus,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Marker {
    pub fn requested(directive_id: &str, now_ms: i64, expires_at_ms: i64) -> Self {
        Self {
            directive_id: directive_id.to_owned(),
            requested_ms: now_ms,
            expires_at_ms,
            status: MarkerStatus::Requested,
            attempt_id: None,
            detail: None,
        }
    }

    pub fn launched(&self, attempt_id: &str) -> Self {
        Self { status: MarkerStatus::Launched, attempt_id: Some(attempt_id.to_owned()), detail: None, ..self.clone() }
    }

    pub fn refused(&self, why: &str) -> Self {
        Self { status: MarkerStatus::Refused, detail: Some(crate::directive::clip(why, 200)), ..self.clone() }
    }

    /// A request the worker should still act on.
    pub fn is_actionable(&self, now_ms: i64) -> bool {
        self.status == MarkerStatus::Requested && now_ms < self.expires_at_ms
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("marker serialises")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_MARKER_BYTES {
            return None;
        }
        serde_json::from_slice(bytes).ok()
    }
}

/// Read the marker from the anchored agent root. `Ok(None)`: none, or one that cannot be understood (never acted on).
pub fn read(root: &crate::anchor::Dir) -> std::io::Result<Option<Marker>> {
    Ok(root.read(MARKER, MAX_MARKER_BYTES)?.and_then(|b| Marker::decode(&b)))
}

pub fn write(root: &crate::anchor::Dir, marker: &Marker) -> std::io::Result<()> {
    root.write_atomic(MARKER, &marker.encode())
}

/// Map the marker and the update state to how the reinstall is going.
///
/// The update state is AUTHORITATIVE for which attempt belongs to the directive (`Attempt.directive_id`, written atomically with
/// Prelaunch) and for how THAT attempt ended (`attempt_outcomes`, keyed by attempt id). Nothing global is read: another update's
/// success can never be attributed to this directive. The marker only says what was requested and whether the worker declined.
pub fn probe(marker: &Marker, state: &UpdateState, now_ms: i64) -> ReinstallStatus {
    if let Some((_attempt, outcome)) = state.attempt_for_directive(&marker.directive_id) {
        return match outcome.as_deref() {
            None | Some("TargetUnacked") => ReinstallStatus::InProgress,
            Some("Done") => ReinstallStatus::Done,
            Some("DonePendingReboot") => ReinstallStatus::RebootPending,
            Some(other) => ReinstallStatus::Failed(format!("the update chain finished with: {}", crate::directive::clip(other, 120))),
        };
    }
    match marker.status {
        MarkerStatus::Refused => {
            ReinstallStatus::Failed(marker.detail.clone().unwrap_or_else(|| "the update chain declined the request".into()))
        }
        MarkerStatus::Requested => {
            if now_ms >= marker.expires_at_ms {
                ReinstallStatus::Failed("the update worker did not pick the request up before it expired".into())
            } else {
                ReinstallStatus::InProgress
            }
        }
        // The worker launched an attempt but the update state no longer knows it (its bounded outcome history rolled over).
        MarkerStatus::Launched => ReinstallStatus::Failed("the reinstall attempt's outcome is no longer recorded".into()),
    }
}

/// How a directive's reinstall stands, given whatever marker is on disk (`None`, this directive's or another's) and the update state.
pub fn status(marker: Option<&Marker>, state: &UpdateState, directive_id: &str, expires_at_ms: i64, now_ms: i64) -> ReinstallStatus {
    match marker {
        Some(m) if m.directive_id == directive_id => probe(m, state, now_ms),
        // The update state already knows an attempt for this directive (the marker lagged or was lost): it decides.
        _ if state.attempt_for_directive(directive_id).is_some() => {
            probe(&Marker::requested(directive_id, now_ms, expires_at_ms), state, now_ms)
        }
        // Another directive's request that is still live owns the marker: wait, never clobber it.
        Some(other) if other.is_actionable(now_ms) => ReinstallStatus::InProgress,
        // No request exists for THIS directive (a crash after `reinstall_requested` was persisted but before the marker was written):
        // ask for a retry; polling a request that was never made would wait forever.
        _ => ReinstallStatus::NotRequested,
    }
}

/// The worker's reconciliation: a `Requested` marker whose directive already has an attempt in the update state becomes `Launched`
/// for that attempt, and NO second attempt is offered.
pub fn reconcile(marker: &Marker, state: &UpdateState) -> Option<Marker> {
    if marker.status != MarkerStatus::Requested {
        return None;
    }
    state.attempt_for_directive(&marker.directive_id).map(|(id, _)| marker.launched(&id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_state::{Attempt, Phase, RebootKind};

    fn attempt(id: &str, directive: Option<&str>) -> Attempt {
        Attempt {
            attempt_id: id.into(),
            previous_product_code: "{A}".into(),
            previous_product_version: "1.3.18".into(),
            target_product_code: "{A}".into(),
            target_product_version: "1.3.18".into(),
            target_version: "0.1.18".into(),
            msi_sha256: "a".repeat(64),
            nonce: "n".into(),
            boot_id: "b".into(),
            previous_version: "0.1.18+x".into(),
            anchor: None,
            directive_id: directive.map(str::to_owned),
        }
    }

    fn requested() -> Marker {
        Marker::requested("d", 1000, 100_000)
    }

    fn finished(state: &mut UpdateState, id: &str, directive: Option<&str>, outcome: &str) {
        state.attempt_outcomes.push_back(crate::update_state::AttemptOutcome {
            attempt_id: id.into(),
            directive_id: directive.map(str::to_owned),
            outcome: outcome.into(),
        });
    }

    #[test]
    fn a_request_not_yet_picked_up_is_in_progress_until_it_expires() {
        let m = Marker::requested("d", 1000, 5000);
        assert_eq!(probe(&m, &UpdateState::default(), 2000), ReinstallStatus::InProgress);
        assert!(matches!(probe(&m, &UpdateState::default(), 5000), ReinstallStatus::Failed(_)));
        assert!(m.is_actionable(4999) && !m.is_actionable(5000));
    }

    #[test]
    fn a_refusal_by_the_update_chain_is_a_failure_with_its_reason() {
        let m = Marker::requested("d", 0, 9).refused("release quarantined");
        assert_eq!(probe(&m, &UpdateState::default(), 1), ReinstallStatus::Failed("release quarantined".into()));
        assert!(!m.is_actionable(1), "a refused marker is never acted on again");
    }

    #[test]
    fn an_attempt_in_flight_is_in_progress_and_a_pending_reboot_is_reported() {
        let mut s = UpdateState::default();
        s.phase = Phase::Prelaunch { attempt: attempt("att-1", Some("d")) };
        assert_eq!(probe(&requested(), &s, 5), ReinstallStatus::InProgress, "found by the directive id even though the marker never became Launched");
        finished(&mut s, "att-1", Some("d"), "DonePendingReboot");
        s.phase = Phase::RebootBarrier { attempt: attempt("att-1", Some("d")), kind: RebootKind::DonePendingReboot, boot_id: "b".into() };
        assert_eq!(probe(&requested(), &s, 5), ReinstallStatus::RebootPending);
    }

    #[test]
    fn an_attempt_awaiting_post_boot_verification_is_still_in_progress() {
        let mut s = UpdateState::default();
        finished(&mut s, "att-1", Some("d"), "TargetUnacked");
        s.phase = Phase::Prelaunch { attempt: attempt("att-1", Some("d")) };
        assert_eq!(probe(&requested(), &s, 5), ReinstallStatus::InProgress);
    }

    #[test]
    fn only_the_directives_own_attempt_decides_its_outcome() {
        let mut s = UpdateState::default();
        // ANOTHER update (no directive, then another directive's) succeeded: it must not be attributed to "d".
        finished(&mut s, "other-1", None, "Done");
        finished(&mut s, "other-2", Some("someone-else"), "Done");
        s.last_outcome = Some("Done 0.1.18".into());
        assert_eq!(
            probe(&Marker::requested("d", 0, 100_000).launched("att-1"), &s, 5),
            ReinstallStatus::Failed("the reinstall attempt's outcome is no longer recorded".into())
        );
        assert_eq!(probe(&requested(), &s, 5), ReinstallStatus::InProgress, "the global last_outcome is never read");
        // Its own attempt's outcome decides.
        finished(&mut s, "att-1", Some("d"), "Done");
        assert_eq!(probe(&requested(), &s, 5), ReinstallStatus::Done);
        // A different directive's attempt in flight is not ours either.
        let mut s2 = UpdateState::default();
        s2.phase = Phase::Prelaunch { attempt: attempt("att-9", Some("not-d")) };
        s2.last_outcome = Some("Done 0.1.18".into());
        assert_eq!(probe(&requested(), &s2, 5), ReinstallStatus::InProgress);
    }

    #[test]
    fn each_non_success_outcome_of_its_own_attempt_is_a_failure() {
        for bad in ["Health", "Unknown", "Busy", "NotStarted", "Verification", "Anomaly", "RolledBack", "RolledBackReboot"] {
            let mut s = UpdateState::default();
            finished(&mut s, "att-1", Some("d"), bad);
            assert!(matches!(probe(&requested(), &s, 5), ReinstallStatus::Failed(_)), "{bad} is not success");
        }
    }

    #[test]
    fn the_marker_round_trips_and_rejects_garbage_and_extra_fields() {
        let m = requested().launched("att-1");
        assert_eq!(Marker::decode(&m.encode()), Some(m));
        assert_eq!(Marker::decode(b"{not json"), None);
        assert_eq!(Marker::decode(&vec![b' '; 5000]), None);
        let extra = br#"{"directive_id":"d","requested_ms":1,"expires_at_ms":2,"status":"requested","url":"https://evil"}"#;
        assert_eq!(Marker::decode(extra), None, "no field can smuggle a URL: unknown fields are refused");
    }

    #[test]
    fn the_state_finds_the_attempt_by_directive_id_atomically_with_prelaunch() {
        let mut s = UpdateState::default();
        assert_eq!(s.attempt_for_directive("d"), None);
        s.phase = Phase::Prelaunch { attempt: attempt("att-1", Some("d")) };
        assert_eq!(s.attempt_for_directive("d"), Some(("att-1".into(), None)));
        // The association survives a serialization round trip (it IS the persisted state).
        let back: UpdateState = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.attempt_for_directive("d"), Some(("att-1".into(), None)));
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use crate::update_state::{Attempt, Phase};

    fn att(id: &str, d: &str) -> Attempt {
        Attempt {
            attempt_id: id.into(), previous_product_code: "{A}".into(), previous_product_version: "1".into(),
            target_product_code: "{A}".into(), target_product_version: "1".into(), target_version: "0.1.0".into(),
            msi_sha256: "a".repeat(64), nonce: "n".into(), boot_id: "b".into(), previous_version: "v".into(),
            anchor: None, directive_id: Some(d.into()),
        }
    }

    #[test]
    fn no_marker_and_no_attempt_means_the_request_was_never_made_so_it_is_made_again() {
        assert_eq!(status(None, &UpdateState::default(), "d", 100_000, 5), ReinstallStatus::NotRequested);
        // Another directive's EXPIRED / settled marker does not own the slot either.
        let stale = Marker::requested("other", 0, 3).refused("x");
        assert_eq!(status(Some(&stale), &UpdateState::default(), "d", 100_000, 5), ReinstallStatus::NotRequested);
        // But another directive's LIVE request does: wait, never clobber it.
        let live = Marker::requested("other", 0, 100_000);
        assert_eq!(status(Some(&live), &UpdateState::default(), "d", 100_000, 5), ReinstallStatus::InProgress);
    }

    #[test]
    fn a_lost_or_lagging_marker_is_overruled_by_the_update_state() {
        let mut s = UpdateState::default();
        s.phase = Phase::Prelaunch { attempt: att("att-1", "d") };
        assert_eq!(status(None, &s, "d", 100_000, 5), ReinstallStatus::InProgress, "marker lost, attempt exists: never request again");
        let lagging = Marker::requested("d", 0, 100_000);
        assert_eq!(status(Some(&lagging), &s, "d", 100_000, 5), ReinstallStatus::InProgress);
    }

    #[test]
    fn the_worker_reconciles_a_requested_marker_against_its_attempt_instead_of_offering_another() {
        let requested = Marker::requested("d", 0, 100_000);
        assert_eq!(reconcile(&requested, &UpdateState::default()), None, "no attempt yet: the worker may offer one");
        let mut s = UpdateState::default();
        s.phase = Phase::Prelaunch { attempt: att("att-1", "d") };
        let r = reconcile(&requested, &s).expect("an attempt for this directive exists: reconcile");
        assert_eq!((r.status, r.attempt_id.as_deref()), (MarkerStatus::Launched, Some("att-1")));
        // A finished attempt also reconciles (crash after the outcome, before the marker).
        let mut done = UpdateState::default();
        done.attempt_outcomes.push_back(crate::update_state::AttemptOutcome { attempt_id: "att-2".into(), directive_id: Some("d".into()), outcome: "Done".into() });
        assert!(reconcile(&requested, &done).is_some());
        // Only Requested markers are reconciled; another directive's attempt is not ours.
        assert_eq!(reconcile(&r, &s), None);
        let mut other = UpdateState::default();
        other.phase = Phase::Prelaunch { attempt: att("att-3", "someone-else") };
        assert_eq!(reconcile(&requested, &other), None);
    }
}
