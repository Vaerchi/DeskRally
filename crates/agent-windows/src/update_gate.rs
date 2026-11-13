//! HealthGate (design v4, amended v5 M1 / v7 L2'): `agent_host.exe msi-health-gate <attempt>
//! <nonce> <expected_version>`, run by the deferred SYSTEM custom action AFTER StartServices and
//! inside the MSI transaction. Exit 0 lets Windows Installer commit; anything else makes it roll the
//! whole transaction back, restoring the previous product.
//!
//! The custom action has already checked that the installed agent_host.exe carries the expected
//! FileVersion (a deferred, in-use replacement is reported by the custom action itself, because
//! then this subcommand would not even be the new code). This binary therefore IS the candidate.
//!
//! The gate passes only on the new helper's attempt-bound ack (authenticated registration, actual
//! version == expected). It always leaves `gate.<attempt>.json` before returning, so
//! classification never depends on the installer's exit code alone.

#![cfg(windows)]

use std::time::{Duration, Instant};

use crate::anchor::Anchor;
use crate::update_files as files;
use crate::update_state::{GateResult, Phase};

const GATE_TIMEOUT: Duration = Duration::from_secs(180);

/// Exit codes are non-secret and stable for the custom action's log line.
pub const EXIT_PASSED: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_VERIFICATION: i32 = 2;

pub fn command(args: &[String]) -> i32 {
    let [_, _, id, nonce, expected] = args else {
        return EXIT_VERIFICATION;
    };
    if !files::valid_attempt_id(id)
        || !files::valid_nonce(nonce)
        || crate::update_download::validate_version_segment(expected).is_err()
    {
        return EXIT_VERIFICATION;
    }
    match gate(id, nonce, expected) {
        Ok(true) => EXIT_PASSED,
        Ok(false) => EXIT_FAILED,
        Err(e) => {
            tracing::error!(error = %e, "health gate: verification failure");
            EXIT_VERIFICATION
        }
    }
}

fn gate(id: &str, nonce: &str, expected: &str) -> std::io::Result<bool> {
    let anchor = Anchor::open()?;
    let root = anchor.dir();
    let boot = files::boot_id()?;
    // M1: the property only selects the mode; the protected attempt record must agree.
    let state = files::load_state(root)?;
    let previous_version = match &state.phase {
        Phase::Installing { attempt, .. }
            if attempt.attempt_id == id
                && attempt.nonce == nonce
                && attempt.target_version == expected
                && attempt.boot_id == boot =>
        {
            files::check_anchor(&anchor, attempt)?;
            attempt.previous_version.clone()
        }
        _ => return Err(std::io::Error::other("no matching Installing attempt")),
    };
    if rmt_agent_core::version::AGENT_VERSION != expected {
        return Err(std::io::Error::other("gate binary is not the expected version"));
    }
    let deadline = Instant::now() + GATE_TIMEOUT;
    let (result, observed) = loop {
        if let Some(ack) = files::read_ack(root, id)? {
            if ack.attempt_id == id && ack.nonce == nonce {
                let ok = ack.actual_version == expected;
                break (
                    if ok { GateResult::Passed } else { GateResult::Mismatch },
                    Some(ack.actual_version),
                );
            }
        }
        if files::candidate_fault_for(root, id, expected, &boot) || Instant::now() >= deadline {
            break (GateResult::Timeout, None);
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    // The previous build answering the ack means its helper still runs: an in-use replacement
    // (rule 5), never candidate blame.
    let in_use = observed_is_previous(observed.as_deref(), &previous_version);
    let record = files::GateRecord {
        attempt_id: id.to_owned(),
        result,
        observed_version: observed,
        ondisk_version: Some(rmt_agent_core::version::AGENT_VERSION.to_owned()),
        in_use,
        // S1': positive evidence only, read at gate time.
        teardown_complete: files::teardown_complete_for(root, id, &boot)?,
    };
    files::write_gate(root, &record)?;
    tracing::info!(attempt = id, ?result, "health gate: decided");
    Ok(result == GateResult::Passed)
}

pub(crate) fn observed_is_previous(observed: Option<&str>, previous: &str) -> bool {
    !previous.is_empty() && observed == Some(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_version_ack_is_in_use_and_never_health() {
        use crate::update_state::*;
        assert!(observed_is_previous(Some("0.1.0+aaa"), "0.1.0+aaa"));
        assert!(!observed_is_previous(Some("0.1.1+bbb"), "0.1.0+aaa"));
        assert!(!observed_is_previous(None, "0.1.0+aaa"));
        assert!(!observed_is_previous(Some(""), ""), "unknown previous never matches");
        // With positive teardown evidence AND a candidate fault, an old-version ack still
        // classifies as RolledBackReboot (rule 5 before rule 7).
        let e = Evidence {
            installed: InstalledFamily::Previous,
            incomplete_rollback: false,
            prelaunch_only: false,
            exit: Some(1603),
            gate: Some(GateEvidence {
                result: GateResult::Mismatch,
                in_use: observed_is_previous(Some("0.1.0+aaa"), "0.1.0+aaa"),
                teardown_complete: true,
            }),
            ack_matches: false,
            candidate_fault: true,
            teardown_record: true,
            pending_renames: false,
            verification_failure: false,
        };
        assert_eq!(classify(&e), Outcome::RolledBackReboot);
    }

    #[test]
    fn malformed_arguments_are_verification_failures() {
        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        let nonce = files::new_nonce();
        let base = |a: &str, n: &str, v: &str| {
            vec!["agent_host.exe".into(), "msi-health-gate".into(), a.into(), n.into(), v.into()]
        };
        assert_eq!(command(&base("not-a-uuid", &nonce, "0.1.0")), EXIT_VERIFICATION);
        assert_eq!(command(&base(&id, "ABC", "0.1.0")), EXIT_VERIFICATION);
        assert_eq!(command(&base(&id, &nonce, "0.1.0 extra")), EXIT_VERIFICATION);
        assert_eq!(command(&["x".into()]), EXIT_VERIFICATION);
    }
}
