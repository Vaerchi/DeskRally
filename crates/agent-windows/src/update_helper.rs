//! The installed helper's side of the auto-update protocol (design v5 R3, v7 L2', v9 R2):
//!
//! * a registration heartbeat after EVERY authenticated registration (a fresh `registration_id`
//!   per registration, so post-boot verification counts each one once);
//! * the attempt-bound ack, with the compile-time version (never echoed from the request);
//! * an affirmative candidate fault (E-cand), and only when THIS binary is the candidate of the
//!   attempt in flight on this boot. A fault from any other binary would blame the wrong release.
//!
//! Every failure here is logged and swallowed: the session path must never depend on the updater,
//! and a missing heartbeat or ack only ever makes the updater more conservative.

#![cfg(windows)]

use rmt_agent_core::version::AGENT_VERSION;

use crate::anchor::Anchor;
use crate::update_files as files;

/// One authenticated registration's update heartbeat. `published` is false when registration time
/// could not write it (e.g. the lock was briefly held); a later proven-live tick publishes it with
/// the same id and then acks.
#[derive(Debug, Clone)]
pub struct Registration {
    pub id: String,
    pub published: bool,
}

/// After an authenticated registration on the installed path. `proof_expiry` is when the
/// connection's liveness evidence (its handshake/registration, then echoed probes) expires; a
/// delayed call past it publishes nothing and leaves the registration for a proven-live tick.
/// Blocking file I/O: call it off the async runtime (host.rs uses spawn_blocking). Returns the
/// registration for [`refresh_heartbeat`], or `None` when the anchor cannot be opened at all.
pub fn on_registered(proof_expiry: std::time::Instant) -> Option<Registration> {
    let anchor = match Anchor::open() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "update: registration heartbeat/ack not written");
            return None;
        }
    };
    let mut reg = Registration { id: uuid::Uuid::new_v4().hyphenated().to_string(), published: false };
    publish_and_ack(&anchor, &mut reg, proof_expiry);
    Some(reg)
}

/// Publish (if not yet) or re-stamp this registration's heartbeat (1.3.1). Write only while the
/// caller's liveness proof holds: `proof_expiry` is the absolute instant its evidence (the last
/// echoed keepalive probe plus the deadline) expires, re-checked under the lock immediately before
/// writing, so a delayed task cannot publish with obsolete evidence. Never counts as a new
/// registration; acks only on first publication (same as registration time).
pub fn refresh_heartbeat(mut reg: Registration, proof_expiry: std::time::Instant) -> Registration {
    match Anchor::open() {
        Ok(anchor) => publish_and_ack(&anchor, &mut reg, proof_expiry),
        Err(e) => tracing::warn!(error = %e, "update: registration heartbeat not refreshed"),
    }
    reg
}

fn publish_and_ack(anchor: &Anchor, reg: &mut Registration, proof_expiry: std::time::Instant) {
    let first = !reg.published;
    let result = (|| -> std::io::Result<bool> {
        let _lock = heartbeat_lock(anchor)?;
        let dir = anchor.dir();
        let boot = files::boot_id()?;
        let current = files::read_heartbeat(dir)?;
        // The expiry is checked inside heartbeat_to_write, as late as possible before the write.
        let Some(hb) = files::heartbeat_to_write(
            reg.published,
            current.as_ref(),
            &reg.id,
            &boot,
            AGENT_VERSION,
            files::now_ms(),
            proof_expiry,
            std::time::Instant::now(),
        ) else {
            return Ok(false);
        };
        files::write_heartbeat(dir, &hb).map(|()| true)
    })();
    match result {
        Ok(true) => {
            reg.published = true;
            tracing::debug!(first, "update: registration heartbeat written");
            if first {
                if let Err(e) = ack_if_requested(anchor) {
                    tracing::warn!(error = %e, "update: attempt ack not written");
                }
            }
        }
        Ok(false) => tracing::debug!(
            "update: heartbeat not written (another registration or boot, clock did not advance, or proof expired)"
        ),
        Err(e) => tracing::warn!(error = %e, first, "update: registration heartbeat not written"),
    }
}

/// The cross-process heartbeat lock: an exclusive (share-mode 0) handle on HEARTBEAT_LOCK under the
/// validated anchor, held by the returned file until dropped. Briefly retried; a holder only does a
/// small read and an atomic write.
fn heartbeat_lock(anchor: &Anchor) -> std::io::Result<std::fs::File> {
    let mut last = None;
    for _ in 0..20 {
        match anchor.dir().open_exclusive(files::HEARTBEAT_LOCK) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("heartbeat lock unavailable")))
}

fn ack_if_requested(anchor: &Anchor) -> std::io::Result<()> {
    let dir = anchor.dir();
    let Some(req) = files::read_request(dir)? else {
        return Ok(());
    };
    // VM acceptance (test-feed builds only): a candidate that never acks, or that reports itself.
    if files::test_hook(dir, "candidate-fault") {
        report_candidate_fault("test hook");
        return Ok(());
    }
    if files::test_hook(dir, "no-ack") {
        return Ok(());
    }
    // Ack only an attempt that is actually in flight on this boot; a stale request stays unacked.
    let Some(active) = files::active_attempt(anchor)? else {
        return Ok(());
    };
    if active.attempt_id != req.attempt_id || active.nonce != req.nonce {
        return Ok(());
    }
    let ack = files::Ack {
        attempt_id: req.attempt_id.clone(),
        nonce: req.nonce,
        actual_version: AGENT_VERSION.to_owned(),
    };
    dir.write_atomic(
        &files::ack_name(&req.attempt_id),
        &serde_json::to_vec(&ack).map_err(std::io::Error::other)?,
    )?;
    tracing::info!(attempt = %ack.attempt_id, version = AGENT_VERSION, "update: attempt ack written");
    Ok(())
}

/// Record that this binary, as the candidate of the in-flight attempt, cannot work (E-cand).
pub fn report_candidate_fault(reason: &str) {
    match candidate_attempt() {
        Ok(Some((anchor, id, boot))) => {
            let fault = files::CandidateFault {
                attempt_id: id,
                version: AGENT_VERSION.to_owned(),
                boot_id: boot,
                reason: reason.to_owned(),
            };
            match files::write_candidate_fault(anchor.dir(), &fault) {
                Ok(()) => tracing::error!(reason, "update: candidate fault recorded"),
                Err(e) => tracing::warn!(error = %e, "update: candidate fault not written"),
            }
        }
        Ok(None) => {}
        Err(e) => tracing::debug!(error = %e, "update: no candidate attribution"),
    }
}

/// `Some` only when an attempt is in flight on this boot AND its target is this exact build.
pub fn candidate_attempt() -> std::io::Result<Option<(Anchor, String, String)>> {
    let anchor = Anchor::open()?;
    let active = files::active_attempt(&anchor)?;
    Ok(active
        .filter(|a| a.target_version == AGENT_VERSION)
        .map(|a| (anchor, a.attempt_id, a.boot_id)))
}
