//! docs/25 F04 regression tests for the `ListDirectory` capability gate + audit record.
//!
//! These sit at the level the finding found the gap: not "does `dir_list` enumerate a folder"
//! (`dir_list`'s own tests cover that, and they passed the whole time this was ungated), but "who is
//! allowed to ask, what happens when they are not, and does the trail say so". Every test here is
//! written so that DELETING the gate makes it fail — a listing that comes back with entries is the
//! observable, not a boolean returned by the thing under test.
//!
//! Included from `host.rs` via `#[path]` so it can reach that module's private functions.

use super::*;
use rmt_agent::backstage::audit::AuditAction;
use rmt_agent::backstage::rbac::{Capability, Grant};

/// A session chain with an IDENTITY, as `serve_session_with_ice` builds one when signaling vouched
/// for a control-plane session. Identity matters here: `audit_file_browse` deliberately seals
/// nothing without it, so a nil-id chain would make every "was it recorded?" assertion vacuous.
fn identified_chain() -> SharedAuditChain {
    rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::from_u128(0x5e55), // session
        uuid::Uuid::from_u128(0x7ec4), // technician
        uuid::Uuid::from_u128(0x4ac0), // machine
    )
}

/// A dispatcher that JOINS `chain`, the way a real `InstallGrant` does.
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

/// A real directory with one recognisable file in it. The tests point the gate at REAL contents so
/// that "nothing was read" is an assertion about the reply rather than about the mock.
fn temp_dir_with_a_file(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rmt_f04_{tag}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("create temp dir");
    std::fs::write(d.join("payroll.xlsx"), b"secret").expect("write file");
    d
}

/// THE REGRESSION FOR F04, no-grant half. In secure mode the dispatcher is `None` until a
/// control-plane-signed grant is installed — the state every session starts in and the state a peer
/// that never got a grant stays in. Before this fix that peer could enumerate the disk.
///
/// The assertion is deliberately NOT "a refusal came back": it is that the refusal carries no file
/// names. A gate that replied `DirectoryListingRefused` while still calling `read_dir` would pass a
/// weaker test and leak exactly what the finding is about.
#[test]
fn a_session_with_no_grant_is_refused_and_reads_nothing() {
    let dir = temp_dir_with_a_file("nogrant");
    let chain = identified_chain();

    let reply = directory_listing_reply(&chain, None, dir.to_string_lossy().into_owned(), 1_000);

    match reply {
        ControlMessage::DirectoryListingRefused { ref reason, ref audit, ref path } => {
            assert_eq!(path, &dir.to_string_lossy().into_owned(), "the refusal echoes the request");
            assert!(
                reason.contains("no backstage grant"),
                "the refusal must name the missing GRANT, not a missing capability: {reason}"
            );
            let ev = audit.as_ref().expect("a refusal on an identified chain must be recorded");
            assert_eq!(ev["action"]["kind"], "file_browse");
            assert_eq!(ev["action"]["path"], dir.to_string_lossy().into_owned());
            assert_eq!(ev["outcome"]["result"], "denied");
        }
        other => panic!("a session with no grant must be refused, got {other:?}"),
    }
    // Belt and braces on the leak: no reply shape carrying entries may be produced at all.
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the gate: an authorized technician whose ROLE does not include file browsing.
/// `FileDownload` is held here on purpose — a neighbouring Tier-1 file capability, so the test fails
/// if the gate is loosened to "any file capability" rather than deleted outright.
#[test]
fn a_grant_without_file_browse_is_refused_and_reads_nothing() {
    let dir = temp_dir_with_a_file("nocap");
    let chain = identified_chain();
    let disp = dispatcher_on(&chain, vec![Capability::FileDownload, Capability::ProcessList]);

    let reply =
        directory_listing_reply(&chain, Some(&disp), dir.to_string_lossy().into_owned(), 2_000);

    match reply {
        ControlMessage::DirectoryListingRefused { ref reason, ref audit, .. } => {
            assert!(
                reason.contains("file_browse"),
                "the refusal must name the missing CAPABILITY, not a missing grant: {reason}"
            );
            let ev = audit.as_ref().expect("a refusal on an identified chain must be recorded");
            assert_eq!(ev["outcome"]["result"], "denied");
            assert!(
                ev["outcome"]["reason"].as_str().unwrap_or_default().contains("file_browse"),
                "the sealed reason must say which capability: {:?}",
                ev["outcome"]
            );
        }
        other => panic!("a grant without file_browse must be refused, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The POSITIVE control. Without this the two tests above would pass against a `ListDirectory` arm
/// that refused unconditionally — a gate that denies everything is not a gate, it is an outage, and
/// it is the mutant a "does it deny?" suite cannot see.
#[test]
fn a_grant_with_file_browse_lists_the_directory_and_records_it() {
    let dir = temp_dir_with_a_file("allowed");
    let chain = identified_chain();
    let disp = dispatcher_on(&chain, vec![Capability::FileBrowse]);

    let reply =
        directory_listing_reply(&chain, Some(&disp), dir.to_string_lossy().into_owned(), 3_000);

    match reply {
        ControlMessage::DirectoryListing { ref entries, truncated, ref audit, .. } => {
            assert!(!truncated);
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, vec!["payroll.xlsx"], "an authorized browse still works");
            let ev = audit.as_ref().expect("an authorized browse must be recorded");
            assert_eq!(ev["action"]["kind"], "file_browse");
            assert_eq!(ev["outcome"]["result"], "ok");
        }
        other => panic!("a grant with file_browse must be allowed, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The path rule, at the dispatch level rather than in `dir_list`'s own unit tests: a UNC path is
/// refused for an authorized technician too, and the refusal is sealed. Capability and destination
/// are independent questions — holding `file_browse` says which machine's operator trusts you, not
/// which machine you may make this one talk to.
#[test]
fn a_unc_path_is_refused_even_with_the_capability_and_the_refusal_is_recorded() {
    let chain = identified_chain();
    let disp = dispatcher_on(&chain, vec![Capability::FileBrowse]);

    let reply = directory_listing_reply(
        &chain,
        Some(&disp),
        r"\\rmt-f04-no-such-host.invalid\share".to_string(),
        4_000,
    );

    match reply {
        ControlMessage::DirectoryListingRefused { ref reason, ref audit, ref path } => {
            assert_eq!(path, r"\\rmt-f04-no-such-host.invalid\share");
            assert!(reason.contains("network (UNC)"), "wrong refusal reason: {reason}");
            let ev = audit.as_ref().expect("a refused UNC browse must be recorded");
            assert_eq!(ev["outcome"]["result"], "denied");
            // The path an investigator needs is the one that was ASKED FOR — the attempt is the
            // finding, and there is no resolved path because nothing was resolved.
            assert_eq!(ev["action"]["path"], r"\\rmt-f04-no-such-host.invalid\share");
        }
        other => panic!("a UNC path must be refused, got {other:?}"),
    }
}

/// A path the filesystem simply cannot read is NOT a refusal and NOT an audit event. The distinction
/// is load-bearing in both directions: `Error` has no field to carry a sealed event, so recording one
/// here would seal something undeliverable — a `seq` hole that wedges the whole session's trail at
/// ingest — and every mistyped folder in a support call would do it.
#[test]
fn a_missing_directory_is_an_error_and_seals_nothing() {
    let chain = identified_chain();
    let disp = dispatcher_on(&chain, vec![Capability::FileBrowse]);
    let missing = std::env::temp_dir().join("rmt-f04-no-such-directory-xyzzy");
    let _ = std::fs::remove_dir_all(&missing);

    let before = chain.lock().unwrap().next_seq();
    let reply =
        directory_listing_reply(&chain, Some(&disp), missing.to_string_lossy().into_owned(), 5_000);
    let after = chain.lock().unwrap().next_seq();

    assert!(
        matches!(reply, ControlMessage::Error { .. }),
        "an unreadable path is an Error, not a refusal: {reply:?}"
    );
    assert_eq!(before, after, "a filesystem error must consume no audit seq");
}

/// The fail-closed direction of the audit rule, proved rather than assumed: on a chain signaling
/// vouched for nothing (dev/LAN, `-insecure-no-ticket-verification`) NOTHING is sealed, because the
/// viewer has no forwarder to deliver it to and an undelivered event is worse than no event. The
/// listing itself still works — the trail is thinner, not the feature.
#[test]
fn an_unidentified_chain_seals_nothing_but_still_lists() {
    let dir = temp_dir_with_a_file("unidentified");
    let chain = rmt_agent::backstage::audit::new_shared_chain(
        uuid::Uuid::nil(),
        uuid::Uuid::nil(),
        uuid::Uuid::from_u128(0x4ac0),
    );
    let disp = dispatcher_on(&chain, vec![Capability::FileBrowse]);

    let reply =
        directory_listing_reply(&chain, Some(&disp), dir.to_string_lossy().into_owned(), 6_000);

    match reply {
        ControlMessage::DirectoryListing { ref entries, ref audit, .. } => {
            assert_eq!(entries.len(), 1, "the listing still works");
            assert!(audit.is_none(), "an unidentified chain must seal nothing: {audit:?}");
        }
        other => panic!("expected a listing, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `file_browse_denial_reason` in isolation, so the three states are pinned even if the reply shape
/// changes: no dispatcher, a dispatcher without the capability, and one with it.
#[test]
fn the_denial_reason_distinguishes_no_grant_from_a_grant_that_lacks_the_capability() {
    let chain = identified_chain();
    let none = file_browse_denial_reason(None).expect("no dispatcher must deny");
    assert!(none.contains("no backstage grant"), "{none}");

    let without = dispatcher_on(&chain, vec![Capability::ProcessList]);
    let lacking = file_browse_denial_reason(Some(&without)).expect("a grant without it must deny");
    assert!(lacking.contains("file_browse"), "{lacking}");
    assert_ne!(none, lacking, "the two denials must be distinguishable in the trail");

    let with = dispatcher_on(&chain, vec![Capability::FileBrowse]);
    assert!(file_browse_denial_reason(Some(&with)).is_none(), "the capability must allow");
}

/// The audit ACTION is the one the backstage channel's browse panel already seals, not a new
/// variant. Pinned because adding one would have been a canonical-signing change across eight places
/// and two languages, and because the console's decoder only knows the names that exist.
#[test]
fn the_sealed_action_is_the_existing_file_browse_variant() {
    let chain = identified_chain();
    let ev = audit_file_browse(&chain, r"C:\Users", Outcome::Ok, 7_000)
        .expect("an identified chain seals");
    let canonical = serde_json::to_value(AuditAction::FileBrowse { path: r"C:\Users".into() })
        .expect("serialize the action");
    assert_eq!(ev["action"], canonical, "the wire action must be the existing FileBrowse shape");
}
