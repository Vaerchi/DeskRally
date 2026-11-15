//! ADR-008 regression tests for the file-transfer gate + audit.
//!
//! These sit at the level the adversarial review found gaps: NOT the happy path (`e2e_filetransfer`
//! covers that over real WebRTC), but the paths that produce no interesting reply and therefore hid
//! a missing record — an authorized download that fails, and an upload that is never finalized.
//!
//! Included from `host.rs` via `#[path]` so it can reach that module's private functions.

use super::*;
use rmt_agent::backstage::audit::AuditAction;
use rmt_agent::backstage::rbac::{Capability, Grant};

/// A session chain, as `serve_session_with_ice` builds one: from the SESSION, not from a grant.
/// The ids are the ones signaling would have vouched for on `brokered`.
fn session_chain() -> SharedAuditChain {
    rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::from_u128(0x5e55), // session
        uuid::Uuid::from_u128(0x7ec4), // technician
        uuid::Uuid::from_u128(0x4ac0), // machine
    )
}

/// A dispatcher that JOINS `chain`, the way a real `InstallGrant` now does.
fn dispatcher_on(chain: &SharedAuditChain, caps: Vec<Capability>) -> Dispatcher {
    Dispatcher::with_chain(
        Grant {
            technician_id: uuid::Uuid::nil(),
            session_id: uuid::Uuid::nil(),
            machine_id: uuid::Uuid::nil(),
            capabilities: caps,
        },
        "rmt-agent.exe",
        chain.clone(),
    )
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rmt_ft_audit_{tag}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("create temp transfer dir");
    d
}

/// Pull the audit events out of a reply list.
fn audits(msgs: &[FtMessage]) -> Vec<serde_json::Value> {
    msgs.iter()
        .filter_map(|m| match m {
            FtMessage::Audit { event, .. } => Some(event.clone()),
            _ => None,
        })
        .collect()
}

/// REGRESSION: every post-gate download failure must be audited as `Failed`, not merely answered
/// with an `Error`. `FileDownload` is granted to every holder of `backstage_shell`, so without this
/// an authorized insider could probe the transfer root and attempt traversal and symlink escapes
/// while the tamper-evident chain stayed completely silent.
fn download_failure_is_audited(path: &str, want_reason: &str) {
    let dir = temp_dir("dlfail");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileDownload]);
    let id = uuid::Uuid::new_v4();

    let out = serve_download(&chain, id, path, &dir, Some(&mut disp), 1);

    assert!(
        matches!(out.first(), Some(FtMessage::Error { .. })),
        "expected an Error reply for {path:?}, got {out:?}"
    );
    let evs = audits(&out);
    assert_eq!(evs.len(), 1, "a failed download must produce exactly one audit event: {out:?}");
    let ev = &evs[0];
    assert_eq!(ev["action"]["kind"], "file_transfer");
    assert_eq!(ev["action"]["direction"], "output");
    assert_eq!(ev["outcome"]["result"], "failed", "outcome for {path:?}");
    assert!(
        ev["outcome"]["error"].as_str().unwrap_or_default().contains(want_reason),
        "error {:?} should mention {want_reason:?}",
        ev["outcome"]["error"]
    );
    // The REQUESTED path is what an investigator needs — that is what was attempted.
    assert_eq!(ev["action"]["path"], path);
    // Nothing was read, so no digest may be claimed.
    assert_eq!(ev["action"]["sha256"], "");
    assert_eq!(ev["action"]["bytes"].as_u64(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn download_path_traversal_is_audited_as_failed() {
    download_failure_is_audited(r"..\..\Windows\System32\config\SAM", "traversal");
}

#[test]
fn download_absolute_path_is_audited_as_failed() {
    download_failure_is_audited(r"C:\Windows\System32\config\SAM", "absolute");
}

#[test]
fn download_of_a_missing_file_is_audited_as_failed() {
    download_failure_is_audited("no-such-file.bin", "not found");
}

/// A download the caller is not entitled to is still recorded — as DENIED, distinct from the FAILED
/// above. The trail must separate "refused" from "broke".
#[test]
fn unauthorized_download_is_audited_as_denied_and_reads_nothing() {
    let dir = temp_dir("dldenied");
    std::fs::write(dir.join("secret.bin"), b"top secret").unwrap();
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileBrowse]); // no FileDownload
    let out = serve_download(&chain, uuid::Uuid::new_v4(), "secret.bin", &dir, Some(&mut disp), 1);

    let evs = audits(&out);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["outcome"]["result"], "denied");
    // No Offer/Chunk may be produced — the file must not leave the machine.
    assert!(
        !out.iter().any(|m| matches!(m, FtMessage::Offer(_) | FtMessage::Chunk(_))),
        "an unauthorized download emitted file data: {out:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **THE REGRESSION FOR THE LOOP-91 CHAIN LIFT.** With NO dispatcher (secure mode before a signed
/// grant) the transfer is still refused — and the refusal is now RECORDED.
///
/// The previous version of this test asserted the opposite (`…_and_unaudited`: "no chain exists, so
/// nothing may be recorded") and passed, which is what made the gap look like a design. The chain
/// used to be built inside `Dispatcher::new` from a GRANT, so an entire session without one produced
/// no trail at all and ADR-008's "an authorized transfer always ends in a record" quietly did not
/// apply to it. An investigator reading such a session saw no file-transfer work — indistinguishable
/// from a session where nobody tried. The chain belongs to the SESSION now, so this proves it exists
/// before any grant does.
#[test]
fn download_without_a_grant_is_refused_and_audited_into_the_session_chain() {
    let dir = temp_dir("dlnogrant");
    let chain = session_chain();
    std::fs::write(dir.join("secret.bin"), b"top secret").unwrap();

    let out = serve_download(&chain, uuid::Uuid::new_v4(), "secret.bin", &dir, None, 1);

    assert!(matches!(out.first(), Some(FtMessage::Error { .. })));
    let evs = audits(&out);
    assert_eq!(evs.len(), 1, "the refusal must be recorded even with no grant: {out:?}");
    assert_eq!(evs[0]["outcome"]["result"], "denied");
    assert_eq!(evs[0]["action"]["kind"], "file_transfer");
    assert_eq!(evs[0]["action"]["direction"], "output");
    // It is on the SESSION's chain, carrying the SESSION's identity — not a nil grant's.
    assert_eq!(evs[0]["seq"], 0);
    assert_eq!(evs[0]["prev_hash"], "");
    assert_eq!(evs[0]["session_id"], uuid::Uuid::from_u128(0x5e55).to_string());
    assert_eq!(evs[0]["technician_id"], uuid::Uuid::from_u128(0x7ec4).to_string());
    assert_eq!(evs[0]["machine_id"], uuid::Uuid::from_u128(0x4ac0).to_string());
    // The reason must name the missing GRANT rather than a missing capability: "you hold no grant"
    // and "your grant does not cover this" are different findings about a session.
    let reason = evs[0]["outcome"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("grant"), "denial reason should name the grant, got {reason:?}");
    // And nothing left the machine.
    assert!(!out.iter().any(|m| matches!(m, FtMessage::Offer(_) | FtMessage::Chunk(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The fork this lift also closes.** A grant installed part-way through a session CONTINUES the
/// session's chain; it does not restart it at `seq 0`.
///
/// That fork was live and invisible. `host.rs` replaces `dispatcher` wholesale on every
/// `InstallGrant`, and the old `Dispatcher::new` built a fresh chain each time — so the events after
/// a re-grant came back numbered from 0 again. The console's `AuditForwarder` de-duplicates on
/// `seq`, so every one of them collided with a seq it had already sent and was DISCARDED: the
/// central trail simply stopped mid-session, with no error anywhere. Asserting on `seq` AND
/// `prev_hash` is what makes it visible — `seq` alone would pass on a chain that renumbered but
/// linked to nothing.
#[test]
fn a_grant_installed_mid_session_continues_the_chain_rather_than_forking_it() {
    let dir = temp_dir("regrant");
    let chain = session_chain();
    std::fs::write(dir.join("secret.bin"), b"top secret").unwrap();

    // Before any grant: the refused download seals seq 0.
    let pre = audits(&serve_download(&chain, uuid::Uuid::new_v4(), "secret.bin", &dir, None, 1));
    assert_eq!(pre[0]["seq"], 0);
    let seq0_hash = pre[0]["hash"].as_str().unwrap().to_string();

    // First grant arrives.
    let mut disp = dispatcher_on(&chain, vec![Capability::FileDownload]);
    let one =
        audits(&serve_download(&chain, uuid::Uuid::new_v4(), "secret.bin", &dir, Some(&mut disp), 2));
    assert_eq!(one[0]["seq"], 1, "the first grant must continue at seq 1");
    assert_eq!(one[0]["prev_hash"], seq0_hash, "and link to the pre-grant event");
    let seq1_hash = one[0]["hash"].as_str().unwrap().to_string();

    // A SECOND grant replaces the dispatcher, exactly as `Control::InstallGrant` does.
    let mut disp2 = dispatcher_on(&chain, vec![Capability::FileDownload]);
    let two = audits(&serve_download(
        &chain,
        uuid::Uuid::new_v4(),
        "secret.bin",
        &dir,
        Some(&mut disp2),
        3,
    ));
    assert_eq!(two[0]["seq"], 2, "a re-grant must NOT restart the chain at seq 0");
    assert_eq!(two[0]["prev_hash"], seq1_hash);
    let _ = std::fs::remove_dir_all(&dir);
}



/// An upload the caller is not entitled to is refused BEFORE any filesystem work: no directory, no
/// `.part`, no upload state — and the attempt is recorded as denied.
#[test]
fn unauthorized_upload_is_denied_before_touching_the_disk() {
    let dir = temp_dir("upnoperm").join("nested-not-created");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileDownload]); // no FileUpload
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id = uuid::Uuid::new_v4();

    let out = start_upload(
        &chain,
        Offer { id, name: "payload.exe".into(), size: 4, sha256: "x".into() },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert!(
        matches!(out.first(), Some(FtMessage::Ack { ok: false, .. })),
        "expected a refusing Ack, got {out:?}"
    );
    assert_eq!(audits(&out).len(), 1);
    assert_eq!(audits(&out)[0]["outcome"]["result"], "denied");
    assert!(uploads.is_empty(), "a refused Offer must leave no upload state");
    assert!(!dir.exists(), "a refused Offer must not create the transfer directory");

    // A chunk for that never-started transfer is rejected and still writes nothing.
    let out = append_chunk(&chain, Chunk { id, seq: 0, data: b"evil".to_vec() }, &mut uploads, Some(&mut disp), 1);
    assert!(matches!(out.first(), Some(FtMessage::Error { .. })));
    assert!(audits(&out).is_empty(), "a chunk for a transfer that never started records nothing");
    assert!(!dir.exists());
}

/// A completed upload whose digest does not match is recorded as FAILED (not denied, not ok),
/// carrying the digest that ACTUALLY arrived rather than the one the sender claimed.
#[test]
fn a_digest_mismatch_is_audited_as_failed_with_the_real_digest() {
    let dir = temp_dir("mismatch");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id = uuid::Uuid::new_v4();

    let claimed = "0".repeat(64);
    let mut root = crate::upload_root::LazyRoot::new(dir.clone(), false);
    start_upload(
        &chain,
        Offer { id, name: "a.bin".into(), size: 4, sha256: claimed.clone() },
        &mut uploads,
        &mut root,
        Some(&mut disp),
        1,
    );
    append_chunk(&chain, Chunk { id, seq: 0, data: b"evil".to_vec() }, &mut uploads, Some(&mut disp), 1);
    let out = finish_upload(&chain, id, &mut uploads, root.opened().unwrap(), Some(&mut disp), 2);

    assert!(matches!(out.first(), Some(FtMessage::Ack { ok: false, .. })));
    let evs = audits(&out);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["outcome"]["result"], "failed");
    let recorded = evs[0]["action"]["sha256"].as_str().unwrap_or_default();
    assert_ne!(recorded, claimed, "the CLAIMED digest must not be recorded as fact");
    assert_eq!(recorded, file_transfer::sha256_hex(b"evil"), "record what actually arrived");
    assert_eq!(evs[0]["action"]["bytes"].as_u64(), Some(4));
    assert_eq!(evs[0]["action"]["kind"], "file_transfer");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The AuditAction the dispatcher builds is the FileTransfer variant with the fields the control
/// plane's canonical encoder expects (guards against a silent variant swap).
#[test]
fn recorded_action_is_the_file_transfer_variant() {
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let (ev, allowed) =
        disp.record_file_transfer(Direction::Input, r"C:\t\a.bin", "abc", 7, Outcome::Ok, 1);
    assert!(allowed);
    match ev.action {
        AuditAction::FileTransfer { bytes, .. } => assert_eq!(bytes, 7),
        other => panic!("expected FileTransfer, got {other:?}"),
    }
}


/// **THE GUARD THAT KEEPS THE CHAIN CONTIGUOUS.** With no control-plane session vouched for,
/// `recording_audit` seals NOTHING — and, crucially, does not advance the chain's `seq`.
///
/// The second half is the whole point and is what a `is_none()` assertion alone would miss. The
/// control plane's `verifyLinkage` demands strictly contiguous seq, so an event that is sealed and
/// then not delivered is a permanent HOLE: every later event in the session is rejected forever,
/// and the console swallows flush failures, so nobody finds out. A guard that returned `None` while
/// still consuming a seq would therefore be WORSE than no guard at all — it would look correct here
/// and destroy the trail in production.
///
/// A probe event after the fact is how "did the chain move?" is measured: its `seq` is the chain's
/// next number, so 0 proves nothing was consumed.
#[test]
fn recording_audit_seals_nothing_and_consumes_no_seq_without_a_session() {
    let nil_chain = rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::nil(),
        uuid::Uuid::nil(),
        uuid::Uuid::from_u128(0x4ac0),
    );

    let ev = recording_audit(
        &nil_chain,
        AuditAction::RecordingStarted { started_at_unix_ms: 5, directory: "d".into() },
        7,
    );
    assert!(ev.is_none(), "an unforwardable event must not be sealed: {ev:?}");

    // The chain did not move. If this probe comes back at seq 1 the guard consumed a number that
    // no batch will ever carry, and the session's trail is wedged from its first real event.
    let probe = rmt_agent::backstage::audit::record_shared(
        &nil_chain,
        AuditAction::FileBrowse { path: "p".into() },
        Outcome::Ok,
        8,
    );
    assert_eq!(probe.seq, 0, "the refused seal advanced the chain, leaving a hole");
}

/// The POSITIVE control: with a real session the same call DOES seal, and the event it returns is
/// the recording action, on the session's identity, at the chain's next seq.
///
/// Without this leg, `recording_audit` could return `None` unconditionally and the test above would
/// still pass — an inert feature that measures as a guard.
#[test]
fn recording_audit_seals_and_advances_when_a_session_was_vouched_for() {
    let chain = rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::from_u128(0x5e55),
        uuid::Uuid::from_u128(0x7ec4),
        uuid::Uuid::from_u128(0x4ac0),
    );

    let v = recording_audit(
        &chain,
        AuditAction::RecordingStopped {
            frames: 913,
            payload_bytes: 4_211_337,
            truncated: Some("size_limit".into()),
            dropped_frames: 47,
            segment_sha256: vec!["a".repeat(64), "b".repeat(64)],
            directory: "d".into(),
        },
        9,
    )
    .expect("a vouched-for session must seal the event");

    assert_eq!(v["seq"], 0);
    assert_eq!(v["prev_hash"], "");
    assert_eq!(v["session_id"], uuid::Uuid::from_u128(0x5e55).to_string());
    assert_eq!(v["technician_id"], uuid::Uuid::from_u128(0x7ec4).to_string());
    assert_eq!(v["machine_id"], uuid::Uuid::from_u128(0x4ac0).to_string());
    assert_eq!(v["action"]["kind"], "recording_stopped");
    // The DIGESTS are the audit-valuable part — they are what ties this line to the file somebody
    // later hands over — so assert they survived serialization in order, not merely that a key exists.
    assert_eq!(v["action"]["segment_sha256"][0], "a".repeat(64));
    assert_eq!(v["action"]["segment_sha256"][1], "b".repeat(64));
    assert_eq!(v["action"]["truncated"], "size_limit");
    assert_eq!(v["occurred_at_unix_ms"], 9);

    // And it advanced the chain by exactly one, so the next producer continues rather than collides.
    let probe = rmt_agent::backstage::audit::record_shared(
        &chain,
        AuditAction::FileBrowse { path: "p".into() },
        Outcome::Ok,
        10,
    );
    assert_eq!(probe.seq, 1, "the sealed event must advance the chain by exactly one");
    assert_eq!(probe.prev_hash, v["hash"].as_str().unwrap(), "the chain must link");
}

/// `recording_stopped_message` puts the SAME figures in the control reply and in the sealed event,
/// and reads them from the finished artifact.
///
/// Two numbers describing one recording that can disagree is a defect waiting to happen: the
/// operator reads the reply, the auditor reads the event, and nothing would ever compare them. The
/// digests are the sharpest case — they exist ONLY in the audit event, so a mistake there is
/// invisible from the UI.
#[test]
fn the_stopped_reply_and_its_sealed_event_agree_on_the_artifact() {
    let chain = rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::from_u128(0x5e55),
        uuid::Uuid::from_u128(0x7ec4),
        uuid::Uuid::from_u128(0x4ac0),
    );
    let side = crate::recording::Sidecar {
        kind: crate::recording::SIDECAR_KIND.to_string(),
        device_id: "dev".into(),
        session_id: None,
        started_at_unix_ms: 1,
        ended_at_unix_ms: 2,
        delete_after_unix_ms: 3,
        segments: vec![
            crate::recording::Segment {
                file: "s-0000.ivf".into(),
                width: 640,
                height: 480,
                frames: 10,
                payload_bytes: 100,
                sha256: "a".repeat(64),
            },
            crate::recording::Segment {
                file: "s-0001.ivf".into(),
                width: 800,
                height: 600,
                frames: 5,
                payload_bytes: 50,
                sha256: "b".repeat(64),
            },
        ],
        truncated: Some("size_limit".into()),
        dropped_frames: 3,
        disclaimer: String::new(),
    };

    let msg = recording_stopped_message(&side, std::path::Path::new(r"D:\rec"), &chain);
    let (segments, frames, payload_bytes, truncated, dropped, directory, audit) = match msg {
        ControlMessage::RecordingStopped {
            segments,
            frames,
            payload_bytes,
            truncated,
            dropped_frames_total,
            directory,
            audit,
        } => (segments, frames, payload_bytes, truncated, dropped_frames_total, directory, audit),
        other => panic!("expected RecordingStopped, got {other:?}"),
    };

    // The reply's own figures come from the artifact, summed across segments.
    assert_eq!(segments, 2);
    assert_eq!(frames, 15);
    assert_eq!(payload_bytes, 150);
    assert_eq!(truncated.as_deref(), Some("size_limit"));
    assert_eq!(dropped, 3);

    let a = audit.expect("a vouched-for session seals the stop event");
    assert_eq!(a["action"]["kind"], "recording_stopped");
    assert_eq!(a["action"]["frames"], frames, "the reply and the audit event disagree on frames");
    assert_eq!(a["action"]["payload_bytes"], payload_bytes);
    assert_eq!(a["action"]["dropped_frames"], dropped);
    assert_eq!(a["action"]["truncated"], "size_limit");
    assert_eq!(a["action"]["directory"], directory);
    // The digest list's LENGTH is the segment count, which is why no separate `segments` field
    // exists on the audit action to disagree with it.
    assert_eq!(a["action"]["segment_sha256"].as_array().map(|v| v.len()), Some(segments as usize));
    assert_eq!(a["action"]["segment_sha256"][0], "a".repeat(64));
    assert_eq!(a["action"]["segment_sha256"][1], "b".repeat(64));
}


/// **THE REGRESSION THE FINAL GATE CAUGHT.** A session whose signaling vouched for nothing adopts
/// the installed GRANT's identity, and only then starts sealing.
///
/// Found by `secure_grant.spec.ts` failing with "the console never POSTed /audit/ingest". The lift
/// keyed the chain on what signaling vouched for — and a stack running
/// `-insecure-no-ticket-verification` vouches for NEITHER id, so the chain was built nil/nil. Two
/// independent breakages followed, and only the first was visible: the console's forwarder key did
/// not match, so every event was dropped; and had one got through, `/audit/ingest` compares
/// `technician_id` to the authenticated caller and would have answered 403 to a nil.
///
/// The grant is the right second source, not a weaker one: the control plane mints it as
/// `Grants.Mint(p.UserID, …)`, so it carries the very technician id ingest will compare against.
#[test]
fn an_unidentified_chain_adopts_the_grants_identity_and_only_then_seals() {
    let session = uuid::Uuid::from_u128(0x9005);
    let tech = uuid::Uuid::from_u128(0x7ec4);
    let chain = rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::nil(),
        uuid::Uuid::nil(),
        uuid::Uuid::from_u128(0x4ac0),
    );

    // PREMISE: before any grant the chain is unidentified, and it seals NOTHING. Sealing here would
    // consume a seq for an event nothing can forward — a hole, which is worse than no record.
    assert!(rmt_agent::backstage::audit::try_record_shared(
        &chain,
        AuditAction::FileBrowse { path: "p".into() },
        Outcome::Ok,
        1,
    )
    .is_none());

    let grant = Grant {
        technician_id: tech,
        session_id: session,
        machine_id: uuid::Uuid::nil(),
        capabilities: vec![Capability::FileDownload],
    };
    let _disp = Dispatcher::with_chain(grant, "rmt-agent.exe", chain.clone());

    // Now it seals, under the GRANT's identity, still at seq 0 — nothing was consumed while
    // unidentified, so the console's first event is genuinely the chain's first event.
    let ev = rmt_agent::backstage::audit::try_record_shared(
        &chain,
        AuditAction::FileBrowse { path: "p".into() },
        Outcome::Ok,
        2,
    )
    .expect("an identified chain must seal");
    assert_eq!(ev.seq, 0, "the refused seals must not have advanced the chain");
    assert_eq!(ev.prev_hash, "");
    assert_eq!(ev.session_id, session);
    assert_eq!(ev.technician_id, tech, "ingest compares this to the authenticated caller");
}

/// A chain signaling DID identify keeps its identity: a later grant cannot rename the trail.
///
/// This is the direction that matters for trust. The ticket's ids were verified by signaling
/// (control-plane signature, device binding, single-use burn) before the session existed; a grant
/// arriving later must not be able to re-point an in-flight trail at a different session or person.
#[test]
fn a_ticketed_chain_ignores_a_grant_that_disagrees() {
    let session = uuid::Uuid::from_u128(0x5e55);
    let tech = uuid::Uuid::from_u128(0x7ec4);
    let chain = rmt_agent::backstage::audit::new_shared_chain(session, tech, uuid::Uuid::nil());

    let grant = Grant {
        technician_id: uuid::Uuid::from_u128(0xbad),
        session_id: uuid::Uuid::from_u128(0xbad2),
        machine_id: uuid::Uuid::nil(),
        capabilities: vec![Capability::FileDownload],
    };
    let _disp = Dispatcher::with_chain(grant, "rmt-agent.exe", chain.clone());

    let ev = rmt_agent::backstage::audit::try_record_shared(
        &chain,
        AuditAction::FileBrowse { path: "p".into() },
        Outcome::Ok,
        1,
    )
    .expect("an identified chain seals");
    assert_eq!(ev.session_id, session, "a grant must not rename a ticketed session's trail");
    assert_eq!(ev.technician_id, tech, "a grant must not re-attribute a ticketed session's trail");
}

/// Adoption is refused once the chain has sealed anything, even if it is still unidentified in part.
///
/// The console binds its forwarder to the FIRST event it sees, so an identity that changed after an
/// event existed would put two different `session_id`s in one chain — which the control plane's
/// per-session linkage check rejects, permanently.
#[test]
fn adoption_is_refused_after_the_chain_has_sealed_an_event() {
    let mut c = rmt_agent::backstage::audit::AuditChain::new(
        uuid::Uuid::from_u128(0x5e55),
        uuid::Uuid::nil(), // identified by session but not by technician
        uuid::Uuid::nil(),
    );
    assert!(!c.is_identified(), "a nil technician means unidentified: ingest would 403 it");
    // Force one event onto it through the unconditional recorder, as a Dispatcher would.
    let _ = c.record(AuditAction::FileBrowse { path: "p".into() }, Outcome::Ok, 1);
    assert!(
        !c.adopt_identity(uuid::Uuid::from_u128(0x1), uuid::Uuid::from_u128(0x2)),
        "adopting after an event exists would disagree with what that event already says"
    );

    // And a nil offer is refused even on a virgin chain — adopting nil is not adopting.
    let mut fresh =
        rmt_agent::backstage::audit::AuditChain::new(uuid::Uuid::nil(), uuid::Uuid::nil(), uuid::Uuid::nil());
    assert!(!fresh.adopt_identity(uuid::Uuid::nil(), uuid::Uuid::from_u128(0x2)));
    assert!(!fresh.adopt_identity(uuid::Uuid::from_u128(0x1), uuid::Uuid::nil()));
    assert!(fresh.adopt_identity(uuid::Uuid::from_u128(0x1), uuid::Uuid::from_u128(0x2)));
    assert!(fresh.is_identified());
    // Once identified, a second offer is refused.
    assert!(!fresh.adopt_identity(uuid::Uuid::from_u128(0x9), uuid::Uuid::from_u128(0x9)));
}

/// A grant may FILL IN a missing identity half, but must never REPLACE a ticket-verified
/// `session_id` with one the caller chose.
///
/// `is_identified()` requires both halves, so a chain holding a real session id and a nil technician
/// id reads as "unidentified" and was adoptable wholesale. That half state is ordinary, not exotic:
/// `technician_id` on `brokered` is `#[serde(default)]` and arrived in loop 91, while
/// `control_plane_session` dates from loop 86 — so any signaling server older than the agent sends
/// the session and omits the technician.
///
/// The grant's `session_id` is NOT an equally-trustworthy source in this direction: the console
/// sends a fresh `crypto.randomUUID()`, the control plane takes `req.SessionID` verbatim, and
/// `SignedGrant::verify` binds only `machine_id`. A technician who put a victim's live session id in
/// their own grant request would otherwise have this agent seal `seq 0` under the victim's id,
/// wedging that session's chain with events genuinely signed by a real agent.
#[test]
fn a_grant_cannot_rename_a_ticket_verified_session() {
    let ticketed = uuid::Uuid::from_u128(0x5e55);
    let victim = uuid::Uuid::from_u128(0x1c71);
    let tech = uuid::Uuid::from_u128(0x7ec4);

    // The half state, exactly as host.rs builds it when signaling omits the technician.
    let mut c = rmt_agent::backstage::audit::AuditChain::new(ticketed, uuid::Uuid::nil(), uuid::Uuid::nil());
    assert!(!c.is_identified(), "premise: a nil technician reads as unidentified");
    assert_eq!(c.next_seq(), 0, "premise: nothing sealed yet, so the seq arm cannot be what refuses");

    assert!(
        !c.adopt_identity(victim, tech),
        "a grant naming a DIFFERENT session must not rename a ticket-verified chain"
    );
    assert_eq!(
        c.session_id(),
        ticketed,
        "the ticket-verified session id must survive the refused adoption"
    );
    assert!(!c.is_identified(), "a refused adoption must not half-apply the technician either");

    // The legitimate rolling-upgrade case still works: SAME session, technician filled in.
    let mut c2 = rmt_agent::backstage::audit::AuditChain::new(ticketed, uuid::Uuid::nil(), uuid::Uuid::nil());
    assert!(
        c2.adopt_identity(ticketed, tech),
        "filling in a MISSING half from a grant that agrees about the session must still be allowed"
    );
    assert!(c2.is_identified());
    assert_eq!(c2.session_id(), ticketed);
}

// ---- Authorized uploads that fail before Done (ADR-008) and the temp-name namespace --------------

/// Exactly one Failed audit for an Input transfer, with no digest and the given byte count.
fn assert_one_failed_upload_audit(out: &[FtMessage], want_reason: &str, want_bytes: u64) {
    assert!(matches!(out.first(), Some(FtMessage::Error { .. })), "expected an Error reply: {out:?}");
    let evs = audits(out);
    assert_eq!(evs.len(), 1, "an authorized upload that fails must produce exactly one audit event: {out:?}");
    assert_eq!(evs[0]["action"]["kind"], "file_transfer");
    assert_eq!(evs[0]["action"]["direction"], "input");
    assert_eq!(evs[0]["outcome"]["result"], "failed");
    assert!(
        evs[0]["outcome"]["error"].as_str().unwrap_or_default().contains(want_reason),
        "error {:?} should mention {want_reason:?}",
        evs[0]["outcome"]["error"]
    );
    assert_eq!(evs[0]["action"]["sha256"], "", "nothing verified, so no digest may be claimed");
    assert_eq!(evs[0]["action"]["bytes"].as_u64(), Some(want_bytes));
}

#[test]
fn an_authorized_offer_over_the_size_limit_is_audited_as_failed() {
    let dir = temp_dir("uplimit");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id = uuid::Uuid::new_v4();
    let out = start_upload(
        &chain,
        Offer { id, name: "huge.bin".into(), size: 2 * 1024 * 1024 * 1024, sha256: "0".repeat(64) },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert_one_failed_upload_audit(&out, "size/concurrency limit", 0);
    assert!(uploads.is_empty());
    assert!(!dir.join(UPLOAD_STAGING_DIR).exists(), "a refused Offer stages nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_upload_named_like_the_staging_folder_is_refused_and_audited() {
    let dir = temp_dir("upreserved");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let out = start_upload(
        &chain,
        Offer { id: uuid::Uuid::new_v4(), name: ".RMT-Staging".into(), size: 1, sha256: "0".repeat(64) },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert_one_failed_upload_audit(&out, "reserved", 0);
    assert!(uploads.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_out_of_order_chunk_aborts_audits_and_removes_the_part() {
    let dir = temp_dir("upgap");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id = uuid::Uuid::new_v4();
    let out = start_upload(
        &chain,
        Offer { id, name: "a.bin".into(), size: 8, sha256: "0".repeat(64) },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert!(out.is_empty(), "{out:?}");
    let out = append_chunk(&chain, Chunk { id, seq: 0, data: b"abc".to_vec() }, &mut uploads, Some(&mut disp), 2);
    assert!(out.is_empty(), "{out:?}");
    let part = dir.join(UPLOAD_STAGING_DIR).join(format!("{id}.part"));
    assert!(part.exists());
    // seq 2 after seq 0: a gap.
    let out = append_chunk(&chain, Chunk { id, seq: 2, data: b"de".to_vec() }, &mut uploads, Some(&mut disp), 3);
    assert_one_failed_upload_audit(&out, "out-of-order chunk", 3);
    assert!(uploads.is_empty(), "the aborted upload is dropped");
    assert!(!part.exists(), "the aborted upload's .part is removed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_chunk_past_the_offered_size_aborts_and_is_audited() {
    let dir = temp_dir("upover");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id = uuid::Uuid::new_v4();
    let out = start_upload(
        &chain,
        Offer { id, name: "a.bin".into(), size: 2, sha256: "0".repeat(64) },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert!(out.is_empty(), "{out:?}");
    let out = append_chunk(&chain, Chunk { id, seq: 0, data: b"abc".to_vec() }, &mut uploads, Some(&mut disp), 2);
    assert_one_failed_upload_audit(&out, "limit exceeded", 0);
    assert!(uploads.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Offer + one chunk for an upload that will be finished later (or never).
fn begin_upload(
    chain: &SharedAuditChain,
    disp: &mut Dispatcher,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &mut crate::upload_root::LazyRoot,
    id: Uuid,
    name: &str,
    bytes: &[u8],
) {
    let out = start_upload(
        chain,
        Offer { id, name: name.into(), size: bytes.len() as u64, sha256: file_transfer::sha256_hex(bytes) },
        uploads,
        root,
        Some(&mut *disp),
        1,
    );
    assert!(out.is_empty(), "offer for {name:?} must be accepted: {out:?}");
    let out = append_chunk(chain, Chunk { id, seq: 0, data: bytes.to_vec() }, uploads, Some(&mut *disp), 2);
    assert!(out.is_empty(), "chunk for {name:?} must be accepted: {out:?}");
}

/// REGRESSION: an upload whose NAME equals another in-flight upload's temp file must not touch that
/// temp file. Temp files used to be `<name>.<id>.part` beside the destination, so committing an upload
/// named `a.txt.<idA>.part` deleted A's temp file and renamed itself over it, and A then failed.
#[test]
fn an_upload_named_like_another_uploads_temp_file_cannot_disturb_it() {
    let dir = temp_dir("upcollide");
    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let id_a = uuid::Uuid::new_v4();
    let mut root = crate::upload_root::LazyRoot::new(dir.clone(), false);

    // A is offered and receives its bytes, but has not finished.
    let a_bytes = b"the real file".to_vec();
    begin_upload(&chain, &mut disp, &mut uploads, &mut root, id_a, "a.txt", &a_bytes);

    // B commits under every name an old-style or new-style temp file of A could have had.
    for name in [format!("a.txt.{id_a}.part"), format!("{id_a}.part")] {
        let id_b = uuid::Uuid::new_v4();
        begin_upload(&chain, &mut disp, &mut uploads, &mut root, id_b, &name, b"intruder");
        let out = finish_upload(&chain, id_b, &mut uploads, root.opened().unwrap(), Some(&mut disp), 3);
        assert!(matches!(out.first(), Some(FtMessage::Ack { ok: true, .. })), "B ({name}) commits: {out:?}");
    }

    // A still completes with ITS bytes.
    let out = finish_upload(&chain, id_a, &mut uploads, root.opened().unwrap(), Some(&mut disp), 4);
    assert!(matches!(out.first(), Some(FtMessage::Ack { ok: true, .. })), "A must still commit: {out:?}");
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), a_bytes);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A writer that accepts `accept` bytes, then fails.
struct FailAfter {
    accept: usize,
    got: Vec<u8>,
}
impl std::io::Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = self.accept - self.got.len();
        if room == 0 {
            return Err(std::io::Error::other("disk gone"));
        }
        let n = room.min(buf.len()).min(2); // short writes, so the loop really iterates
        self.got.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_counting_reports_the_bytes_that_landed_before_a_failure() {
    let mut w = FailAfter { accept: 3, got: Vec::new() };
    let (n, res) = write_counting(&mut w, b"abcdef");
    assert_eq!(n, 3, "the partial prefix must be counted");
    assert!(res.is_err());
    assert_eq!(w.got, b"abc");

    let mut w = FailAfter { accept: 10, got: Vec::new() };
    let (n, res) = write_counting(&mut w, b"abcdef");
    assert_eq!((n, res.is_ok()), (6, true));
}

/// A `.rmt-staging` JUNCTION planted in the root must be refused (audited) before SYSTEM writes a
/// byte through it; the junction's target stays untouched.
#[test]
fn a_junction_planted_as_the_staging_folder_is_refused_and_its_target_untouched() {
    let dir = temp_dir("upjunction");
    let target = temp_dir("upjunction_target");
    let link = dir.join(UPLOAD_STAGING_DIR);
    let mk = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link.as_os_str())
        .arg(target.as_os_str())
        .output()
        .expect("cmd runs");
    assert!(mk.status.success(), "mklink /J failed: {}", String::from_utf8_lossy(&mk.stderr));

    let chain = session_chain();
    let mut disp = dispatcher_on(&chain, vec![Capability::FileUpload]);
    let mut uploads: HashMap<Uuid, UploadState> = HashMap::new();
    let out = start_upload(
        &chain,
        Offer { id: uuid::Uuid::new_v4(), name: "a.bin".into(), size: 1, sha256: "0".repeat(64) },
        &mut uploads,
        &mut crate::upload_root::LazyRoot::new(dir.clone(), false),
        Some(&mut disp),
        1,
    );
    assert_one_failed_upload_audit(&out, "junction", 0);
    assert!(uploads.is_empty());
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "nothing may be written through the junction");
    let _ = std::fs::remove_dir(&link); // removes the junction, not its target
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&target);
}
