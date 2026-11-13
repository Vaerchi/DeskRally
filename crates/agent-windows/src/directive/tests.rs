//! The directive engine against doubles: every refusal, the persist-before-side-effect order, the state machine, resume
//! after a crash, serialization with the update chain, and the acknowledgement chain. Nothing here actuates the machine.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use rmt_protocol::directive::{self as proto, Refusal};

use super::testkit::*;
use super::*;

fn accepted(rig: &mut Rig, kind: &str, id: &str) {
    match rig.engine.submit(&mint(kind, id), None) {
        SubmitOutcome::Accepted { directive_id, .. } => assert_eq!(directive_id, id),
        other => panic!("expected acceptance, got {other:?}"),
    }
}

// ---- every refusal changes NOTHING ------------------------------------------------------------------

fn assert_refused(rig: &mut Rig, artifact: &str, why: Refusal) {
    assert_eq!(rig.engine.submit(artifact, None), SubmitOutcome::Refused(why));
    assert!(rig.store.records.lock().unwrap().is_empty(), "a refused directive must not be persisted ({why:?})");
    assert!(rig.engine.drive().is_empty());
    assert!(rig.engine.next_ack().is_none(), "a refused directive earns no ack ({why:?})");
    assert!(rig.no_side_effects(), "a refused directive must cause no side effect ({why:?})");
}

#[test]
fn no_pinned_directive_key_refuses_everything() {
    let mut rig = rig_with(None);
    assert_refused(&mut rig, &mint("uninstall", DIRECTIVE_ID), Refusal::NoPinnedKey);
    assert_refused(&mut rig, &mint("reinstall", OTHER_ID), Refusal::NoPinnedKey);
}

#[test]
fn a_directive_signed_by_another_key_is_refused() {
    let mut rig = rig();
    // The grant issuer, say: any key that is not the pinned directive key.
    let forged = sign_with(&Identity::from_seed(&[0x33; 32]), claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW + 600_000));
    assert_refused(&mut rig, &forged, Refusal::Signature);
}

#[test]
fn a_tampered_directive_is_refused() {
    let mut rig = rig();
    let tampered = mint("reinstall", DIRECTIVE_ID).replace("reinstall", "uninstall");
    assert_refused(&mut rig, &tampered, Refusal::Signature);
}

#[test]
fn a_directive_for_another_device_is_refused() {
    let mut rig = rig();
    let mut c = claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW + 600_000);
    c.device_id = "66666666-7777-4888-8999-bbbbbbbbbbbb".into();
    assert_refused(&mut rig, &sign_with(&directive_key(), c), Refusal::DeviceMismatch);
}

#[test]
fn a_directive_for_another_tenant_is_refused() {
    let mut rig = rig();
    let mut c = claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW + 600_000);
    c.tenant_id = "99999999-2222-4333-8444-555555555555".into();
    assert_refused(&mut rig, &sign_with(&directive_key(), c), Refusal::TenantMismatch);
}

#[test]
fn a_directive_for_another_enrollment_generation_is_refused() {
    let mut rig = rig();
    let mut c = claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW + 600_000);
    c.key_fp = "00".repeat(32);
    assert_refused(&mut rig, &sign_with(&directive_key(), c), Refusal::KeyFpMismatch);
}

#[test]
fn a_directive_issued_in_the_future_is_refused_but_two_minutes_of_skew_is_fine() {
    let mut rig = rig();
    let late = sign_with(&directive_key(), claims("uninstall", DIRECTIVE_ID, NOW + 121_000, NOW + 600_000));
    assert_refused(&mut rig, &late, Refusal::NotYetValid);
    let ok = sign_with(&directive_key(), claims("uninstall", OTHER_ID, NOW + 119_000, NOW + 600_000));
    assert!(matches!(rig.engine.submit(&ok, None), SubmitOutcome::Accepted { .. }));
}

#[test]
fn an_expired_directive_is_refused() {
    let mut rig = rig();
    let expired = sign_with(&directive_key(), claims("uninstall", DIRECTIVE_ID, NOW - 7_200_000, NOW - 3_600_000));
    assert_refused(&mut rig, &expired, Refusal::Expired);
}

#[test]
fn a_lifetime_above_the_kind_maximum_is_refused() {
    let mut rig = rig();
    let long_uninstall = sign_with(&directive_key(), claims("uninstall", DIRECTIVE_ID, NOW - 1000, NOW - 1000 + 3_600_001));
    assert_refused(&mut rig, &long_uninstall, Refusal::LifetimeTooLong);
    let long_reinstall = sign_with(&directive_key(), claims("reinstall", OTHER_ID, NOW - 1000, NOW - 1000 + 86_400_001));
    assert_refused(&mut rig, &long_reinstall, Refusal::LifetimeTooLong);
}

#[test]
fn garbage_is_refused_as_malformed() {
    let mut rig = rig();
    assert_refused(&mut rig, "not json", Refusal::Malformed);
    assert_refused(&mut rig, "{}", Refusal::Malformed);
}

#[test]
fn a_replayed_directive_is_refused_even_after_a_restart_and_after_it_finished() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    let art = mint("reinstall", DIRECTIVE_ID);
    // While active (the same id is a replay, not a "busy").
    assert_eq!(rig.engine.submit(&art, None), SubmitOutcome::Refused(Refusal::Replayed));
    // Across a restart: the ledger is the persisted record set.
    rig.restart();
    assert_eq!(rig.engine.submit(&art, None), SubmitOutcome::Refused(Refusal::Replayed));
    // And once it has finished.
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, COMPLETE);
    assert_eq!(rig.engine.submit(&art, None), SubmitOutcome::Refused(Refusal::Replayed));
}

#[test]
fn an_in_session_path_accepts_only_a_signed_uninstall() {
    // D-C2: EndSession{uninstall} carries a directive; a reinstall (or anything else) is not a removal authorization.
    let mut rig = rig();
    assert_eq!(rig.engine.submit(&mint("reinstall", DIRECTIVE_ID), Some(DirectiveKind::Uninstall)), SubmitOutcome::WrongKind);
    assert!(rig.store.records.lock().unwrap().is_empty());
    assert!(matches!(
        rig.engine.submit(&mint("uninstall", OTHER_ID), Some(DirectiveKind::Uninstall)),
        SubmitOutcome::Accepted { .. }
    ));
}

// ---- persist BEFORE side effects ---------------------------------------------------------------------

#[test]
fn acceptance_is_durable_before_anything_runs_and_a_failed_write_accepts_nothing() {
    let mut rig = rig();
    rig.store.fail_saves.store(true, Ordering::SeqCst);
    let out = rig.engine.submit(&mint("uninstall", DIRECTIVE_ID), None);
    assert!(matches!(out, SubmitOutcome::StoreFailed(_)), "{out:?}");
    rig.store.fail_saves.store(false, Ordering::SeqCst);
    assert!(rig.engine.drive().is_empty());
    assert!(rig.act.calls("start_") == 0, "no side effect without a durable record");
}

#[test]
fn an_unreadable_ledger_fails_closed() {
    let mut rig = rig();
    rig.store.fail_loads.store(true, Ordering::SeqCst);
    assert!(matches!(rig.engine.submit(&mint("uninstall", DIRECTIVE_ID), None), SubmitOutcome::StoreFailed(_)));
    assert_eq!(rig.act.calls("start_"), 0);
}

#[test]
fn executing_is_durable_before_the_removal_helper_is_launched() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    let ev = rig.events.lock().unwrap().clone();
    let launch = ev.iter().position(|e| e.starts_with("start_uninstall")).expect("launched");
    let durable = ev
        .iter()
        .position(|e| e == &format!("save:{DIRECTIVE_ID}:executing:removal_launching"))
        .expect("executing/removal_launching saved");
    assert!(durable < launch, "{ev:?}");
}

#[test]
fn executing_is_durable_before_the_update_chain_is_asked_to_reinstall() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    let ev = rig.events.lock().unwrap().clone();
    let start = ev.iter().position(|e| e.starts_with("start_reinstall")).unwrap();
    let durable = ev.iter().position(|e| e == &format!("save:{DIRECTIVE_ID}:executing:reinstall_requested")).unwrap();
    assert!(durable < start, "{ev:?}");
}

#[test]
fn the_removal_handoff_carries_the_identity_captured_before_the_install_is_touched() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    let h = rig.act.handoffs.lock().unwrap().clone();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].1, hex::encode([0x22u8; 32]), "the helper signs the final ack with the captured key");
}

// ---- reinstall state machine --------------------------------------------------------------------------

#[test]
fn a_reinstall_runs_accepted_executing_complete_with_its_acks_in_order() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, ACCEPTED);
    assert_eq!(rig.act.calls("start_"), 0, "acceptance alone runs nothing");
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!((r.state.as_str(), r.step.as_str()), (EXECUTING, step::REINSTALL_REQUESTED));
    assert_eq!(rig.act.calls("start_reinstall"), 1);
    rig.engine.drive(); // still InProgress: no change, no second start
    assert_eq!(rig.act.calls("start_reinstall"), 1);
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, COMPLETE);
    let chain: Vec<_> = r.acks.iter().map(|a| (a.from.as_str(), a.to.as_str())).collect();
    assert_eq!(chain, [("issued", "accepted"), ("accepted", "executing"), ("executing", "complete")]);
    for (from, to) in chain {
        assert!(proto::transition_allowed(from, to), "{from}->{to} must be a transition the control plane accepts");
    }
}

#[test]
fn a_reinstall_the_chain_cannot_start_or_that_fails_is_reported_failed() {
    let mut rig = rig();
    *rig.act.start_reinstall_err.lock().unwrap() = Some("auto-update is not provisioned".into());
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("not provisioned"));

    let mut rig = self::rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Failed("health gate failed; rolled back".into());
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!((r.state.as_str(), r.detail.as_str()), (FAILED, "health gate failed; rolled back"));
}

#[test]
fn a_reinstall_needing_a_reboot_reports_reboot_pending_then_can_still_complete() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::RebootPending;
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, REBOOT_PENDING);
    rig.engine.drive(); // idempotent: no duplicate transition
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().acks.iter().filter(|a| a.to == REBOOT_PENDING).count(), 1);
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, COMPLETE);
    assert!(proto::transition_allowed(REBOOT_PENDING, COMPLETE));
}

// ---- uninstall ----------------------------------------------------------------------------------------

#[test]
fn an_uninstall_launches_the_helper_once_and_then_leaves_the_rest_to_it() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!((r.state.as_str(), r.step.as_str()), (EXECUTING, step::REMOVAL_STARTED));
    rig.engine.drive();
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 1, "the helper is launched exactly once");
}

#[test]
fn a_helper_that_cannot_be_launched_reports_failed_and_changes_nothing_else() {
    let mut rig = rig();
    *rig.act.start_uninstall_err.lock().unwrap() = Some("not the MSI location".into());
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("not the MSI location"));
}

#[test]
fn a_helper_that_died_without_a_result_is_reported_failed_never_complete() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.removal.lock().unwrap() = RemovalStatus::Exited(None);
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("without a result"));
    // Even a helper claiming completion cannot make us say complete while we are still running.
    let mut rig = self::rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.removal.lock().unwrap() = RemovalStatus::Exited(Some(RemovalOutcome::Complete));
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, FAILED);
}

#[test]
fn a_helper_that_reports_reboot_pending_is_adopted() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.removal.lock().unwrap() = RemovalStatus::Exited(Some(RemovalOutcome::RebootPending));
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, REBOOT_PENDING);
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().is_terminal(), "reboot_pending is final for a removal");
}

// ---- crash / resume -----------------------------------------------------------------------------------

#[test]
fn a_crash_after_accepted_resumes_into_executing_exactly_once() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.restart(); // the process died right after the durable accept
    rig.engine.drive();
    rig.restart();
    rig.engine.drive(); // and again: no second start
    assert_eq!(rig.act.calls("start_reinstall"), 1);
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, EXECUTING);
}

#[test]
fn a_crash_between_executing_and_the_helper_launch_relaunches_only_when_no_helper_exists() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    // Hand-write the post-crash state: executing/removal_launching durable, spawn outcome unknown.
    let mut r = rig.store.get(DIRECTIVE_ID).unwrap();
    r.transition(EXECUTING, "", NOW);
    r.step = step::REMOVAL_LAUNCHING.into();
    rig.store.save(&r).unwrap();
    rig.settle_acks();
    rig.restart();
    *rig.act.removal.lock().unwrap() = RemovalStatus::Running; // a helper DID start
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 0, "a running helper is never launched twice");
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().step, step::REMOVAL_STARTED);

    let mut rig = self::rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    let mut r = rig.store.get(DIRECTIVE_ID).unwrap();
    r.transition(EXECUTING, "", NOW);
    r.step = step::REMOVAL_LAUNCHING.into();
    rig.store.save(&r).unwrap();
    rig.settle_acks();
    rig.restart();
    *rig.act.removal.lock().unwrap() = RemovalStatus::NotLaunched; // it never started: safe to launch
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 1);
}

#[test]
fn an_executing_record_with_an_unknown_step_is_failed_not_repeated() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    let mut r = rig.store.get(DIRECTIVE_ID).unwrap();
    r.transition(EXECUTING, "", NOW);
    r.step = "something_new".into();
    rig.store.save(&r).unwrap();
    rig.restart();
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, FAILED);
    assert_eq!(rig.act.calls("start_"), 0);
}

#[test]
fn a_directive_that_expired_while_it_waited_is_failed_not_run() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.advance(3_600_000 + 1_000); // past its 1 h lifetime, before it ever started
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("expired"));
    assert_eq!(rig.act.calls("start_"), 0);
}

// ---- serialization with auto-update -------------------------------------------------------------------

#[test]
fn a_directive_waits_while_an_update_attempt_is_in_flight() {
    let mut rig = rig();
    rig.act.busy.store(true, Ordering::SeqCst);
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, ACCEPTED);
    assert_eq!(rig.act.calls("start_"), 0);
    rig.act.busy.store(false, Ordering::SeqCst);
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 1);
}

#[test]
fn only_one_directive_runs_at_a_time_and_the_second_is_not_persisted() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    let second = mint("uninstall", OTHER_ID);
    assert_eq!(rig.engine.submit(&second, None), SubmitOutcome::Busy);
    assert!(rig.store.get(OTHER_ID).is_none(), "a busy refusal must stay deliverable, so it is not ledgered");
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    rig.engine.drive();
    assert!(matches!(rig.engine.submit(&second, None), SubmitOutcome::Accepted { .. }));
}

#[test]
fn the_update_worker_is_told_a_directive_is_in_flight() {
    let mut rig = rig();
    assert!(!in_flight(&rig.store));
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    assert!(in_flight(&rig.store), "accepted");
    rig.engine.drive();
    assert!(in_flight(&rig.store), "executing");
    *rig.act.removal.lock().unwrap() = RemovalStatus::Exited(None);
    rig.engine.drive();
    assert!(!in_flight(&rig.store), "failed is terminal");
    rig.store.fail_loads.store(true, Ordering::SeqCst);
    assert!(in_flight(&rig.store), "an unreadable ledger counts as in flight: never update under an unresolved removal");
}

// ---- acknowledgements ---------------------------------------------------------------------------------

fn verify(a: &SignedAck, r: &OpRecord) -> bool {
    proto::verify_ack(&device_key().public_hex(), &r.tenant_id, &r.device_id, &r.directive_id, &r.key_fp, a)
}

#[test]
fn acks_are_signed_by_the_device_key_bound_to_the_directive_and_sent_in_order() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    let first = rig.engine.next_ack().expect("issued->accepted owed");
    assert_eq!((first.from.as_str(), first.to.as_str()), ("issued", "accepted"));
    assert!(verify(&first, &r));
    // Until the first is answered the same step is offered again (never skipped ahead).
    let again = rig.engine.next_ack().unwrap();
    assert_eq!((again.from.as_str(), again.to.as_str()), ("issued", "accepted"));
    rig.answer("applied");
    let second = rig.engine.next_ack().unwrap();
    assert_eq!((second.from.as_str(), second.to.as_str()), ("accepted", "executing"));
    assert!(verify(&second, &rig.store.get(DIRECTIVE_ID).unwrap()));
    // A signature never verifies for another directive's tenant/id.
    let mut other = rig.store.get(DIRECTIVE_ID).unwrap();
    other.directive_id = OTHER_ID.into();
    assert!(!verify(&second, &other));
}

#[test]
fn ack_timestamps_strictly_increase_even_with_a_frozen_clock_and_across_restarts() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    let a = rig.engine.next_ack().unwrap();
    let b = rig.engine.next_ack().unwrap();
    assert!(b.ts_ms > a.ts_ms, "the control plane refuses a ts that is not larger than the last accepted");
    rig.restart();
    let c = rig.engine.next_ack().unwrap();
    assert!(c.ts_ms > b.ts_ms, "a restart must not reuse a timestamp");
}

#[test]
fn ack_results_applied_replay_settle_unavailable_retries_refused_ends_the_chain() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.answer("unavailable");
    assert!(!rig.store.get(DIRECTIVE_ID).unwrap().acks[0].delivered);
    rig.answer("replay");
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().acks[0].delivered);
    rig.answer("refused");
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert!(r.acks[1].refused);
    assert!(rig.engine.next_ack().is_none(), "nothing is sent after a terminal refusal");
    assert!(!rig.engine.acks_owed());
    // An unknown id or nonsense outcome changes nothing.
    rig.engine.on_ack_result(&AckKey { directive_id: "00000000-0000-4000-8000-000000000000".into(), from: "issued".into(), to: "accepted".into(), ts_ms: 1 }, "applied");
    rig.answer("bogus");
}

#[test]
fn only_transitions_the_control_plane_accepts_are_ever_signed() {
    // Drive a full reinstall and check every ack in the record against the server's transition table.
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::RebootPending;
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert!(r.acks.len() >= 4);
    for a in &r.acks {
        assert!(proto::transition_allowed(&a.from, &a.to), "{} -> {}", a.from, a.to);
    }
    // Drain: every one is signable.
    let mut sent = 0;
    while let Some(ack) = rig.engine.next_ack() {
        assert!(verify(&ack, &rig.store.get(DIRECTIVE_ID).unwrap()));
        rig.answer("applied");
        sent += 1;
        assert!(sent < 20);
    }
    assert_eq!(sent, r.acks.len());
}

// ---- the on-disk record format ------------------------------------------------------------------------

#[test]
fn records_round_trip_through_the_real_store_and_a_restart_keeps_the_ledger() {
    let fs = FsStore::new("roundtrip");
    let events: Events = Arc::default();
    let act = FakeActuator::new(events);
    let mut engine = Engine::new(ctx(pinned()), device_key(), Box::new(FsStore { dir: fs.dir.clone() }), Box::new(act.clone()))
        .with_clock(|| NOW);
    assert!(matches!(engine.submit(&mint("uninstall", DIRECTIVE_ID), None), SubmitOutcome::Accepted { .. }));
    // A brand new engine over the same directory refuses the same artifact as a replay.
    let mut again = Engine::new(ctx(pinned()), device_key(), Box::new(FsStore { dir: fs.dir.clone() }), Box::new(act))
        .with_clock(|| NOW);
    assert_eq!(again.submit(&mint("uninstall", DIRECTIVE_ID), None), SubmitOutcome::Refused(Refusal::Replayed));
    let recs = again.records().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].state, ACCEPTED);
}

#[test]
fn a_corrupt_or_misnamed_record_fails_closed_instead_of_dropping_its_ledger_entry() {
    let fs = FsStore::new("corrupt");
    let id = DIRECTIVE_ID;
    std::fs::write(fs.dir.join(format!("directive-{id}.json")), b"{ not json").unwrap();
    assert!(fs.load_all().is_err(), "an unreadable record must be an error, not a missing one");
    let mut engine = Engine::new(ctx(pinned()), device_key(), Box::new(FsStore { dir: fs.dir.clone() }), Box::new(FakeActuator::new(Arc::default())))
        .with_clock(|| NOW);
    assert!(matches!(engine.submit(&mint("uninstall", id), None), SubmitOutcome::StoreFailed(_)));

    let fs = FsStore::new("misnamed");
    let mut rig = rig();
    accepted(&mut rig, "uninstall", id);
    let good = rig.store.get(id).unwrap();
    // A valid record stored under a different directive's name.
    std::fs::write(fs.dir.join(format!("directive-{OTHER_ID}.json")), serde_json::to_vec(&good).unwrap()).unwrap();
    assert!(fs.load_all().is_err());
}

#[test]
fn stray_temp_files_and_foreign_names_are_not_records_and_names_never_become_paths() {
    let fs = FsStore::new("stray");
    std::fs::write(fs.dir.join(format!("directive-{DIRECTIVE_ID}.json.tmp-abc")), b"x").unwrap();
    std::fs::write(fs.dir.join("notes.txt"), b"x").unwrap();
    std::fs::write(fs.dir.join("directive-..\\evil.json"), b"x").unwrap_or(());
    assert!(fs.load_all().unwrap().is_empty());
    for bad in ["", "../x", "..\\x", "not-a-uuid", "BBBBBBBB-CCCC-4DDD-8EEE-FFFFFFFFFFFF", "bbbbbbbbccccddddeeeeffffffffffff"] {
        assert!(record_name(bad).is_none(), "{bad:?}");
    }
    assert!(record_name(DIRECTIVE_ID).is_some());
}

#[test]
fn terminal_records_are_pruned_only_after_their_directive_expired_and_their_acks_settled() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, COMPLETE);
    // Acks still owed: kept, even long after expiry.
    rig.advance(10 * 86_400_000);
    rig.engine.drive();
    assert!(rig.store.get(DIRECTIVE_ID).is_some());
    while rig.engine.next_ack().is_some() {
        rig.answer("applied");
    }
    rig.engine.drive();
    assert!(rig.store.get(DIRECTIVE_ID).is_none(), "settled and long expired: pruned");
    // Pruning cannot re-open a replay: the directive is long expired.
    assert_eq!(
        rig.engine.submit(&mint("reinstall", DIRECTIVE_ID), None),
        SubmitOutcome::Refused(Refusal::Expired)
    );
}

// ---- a removal waits for the control plane's chain ---------------------------------------------------

#[test]
fn a_removal_is_not_launched_until_the_control_plane_has_the_chain_up_to_executing() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.engine.drive();
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 0, "no acks delivered yet: the helper's acks would be refused");
    // Only the FIRST of two owed acks delivered: still waiting.
    let first = rig.engine.next_ack().unwrap();
    assert_eq!((first.from.as_str(), first.to.as_str()), ("issued", "accepted"));
    rig.answer("applied");
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 0);
    rig.settle_acks();
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 1);
}

#[test]
fn a_removal_the_control_plane_refused_to_track_is_failed_without_any_side_effect() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.engine.next_ack().unwrap();
    rig.answer("refused"); // e.g. cancelled or expired centrally
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("refused"));
    assert_eq!(rig.act.calls("start_"), 0);
}

#[test]
fn a_removal_still_waiting_for_its_chain_when_it_expires_is_failed() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.advance(3_600_000 + 5_000);
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert_eq!(rig.act.calls("start_"), 0);
}

#[test]
fn the_update_worker_yields_to_a_removal_but_a_reinstall_is_the_update_chain_itself() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    assert!(in_flight(&rig.store), "a reinstall is a directive in flight...");
    assert!(!removal_in_flight(&rig.store), "...but it must not block the worker that performs it");
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();

    let mut rig = self::rig();
    assert!(!removal_in_flight(&rig.store));
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    assert!(removal_in_flight(&rig.store), "accepted removal");
    rig.engine.drive();
    rig.settle_acks();
    rig.engine.drive();
    assert!(removal_in_flight(&rig.store), "executing removal");
    *rig.act.removal.lock().unwrap() = RemovalStatus::Exited(Some(RemovalOutcome::RebootPending));
    rig.engine.drive();
    assert!(!removal_in_flight(&rig.store), "reboot_pending is final for a removal");
    rig.store.fail_loads.store(true, Ordering::SeqCst);
    assert!(removal_in_flight(&rig.store), "unreadable records: never update under an unresolved removal");
}

// ---- P1: canonical identity ---------------------------------------------------------------------------

#[test]
fn a_case_altered_replay_is_refused_across_a_restart_and_records_use_the_canonical_id() {
    let mut rig = rig();
    let original = mint("uninstall", DIRECTIVE_ID);
    let shouty = original.replace(DIRECTIVE_ID, &DIRECTIVE_ID.to_uppercase());
    assert_ne!(original, shouty);
    // The altered artifact FIRST: it is accepted under the canonical id...
    assert!(matches!(rig.engine.submit(&shouty, None), SubmitOutcome::Accepted { ref directive_id, .. } if directive_id == DIRECTIVE_ID));
    assert!(rig.store.get(DIRECTIVE_ID).is_some() && rig.store.get(&DIRECTIVE_ID.to_uppercase()).is_none());
    rig.restart();
    // ...and the genuine text (and the altered one again) are replays, even after a restart.
    assert_eq!(rig.engine.submit(&original, None), SubmitOutcome::Refused(Refusal::Replayed));
    assert_eq!(rig.engine.submit(&shouty, None), SubmitOutcome::Refused(Refusal::Replayed));
    // Acks are produced for the canonical id.
    assert_eq!(rig.engine.next_ack().unwrap().directive_id, DIRECTIVE_ID);
}

// ---- E1: answers are correlated with the exact transition ---------------------------------------------

fn key(rig: &Rig, from: &str, to: &str) -> AckKey {
    let rec = rig.store.get(DIRECTIVE_ID).unwrap();
    let ts = rec.acks.iter().find(|a| a.from == from && a.to == to).and_then(|a| a.sent_ts.last().copied()).unwrap_or(0);
    AckKey { directive_id: DIRECTIVE_ID.into(), from: from.into(), to: to.into(), ts_ms: ts }
}

#[test]
fn a_delayed_duplicate_answer_for_an_earlier_step_cannot_settle_a_later_one() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    // issued->accepted is sent twice (a retry) and BOTH answers are applied/replay: the second is the late duplicate.
    rig.engine.next_ack().unwrap();
    { let k = key(&rig, "issued", "accepted"); rig.engine.on_ack_result(&k, "applied"); }
    let second = rig.engine.next_ack().unwrap();
    assert_eq!((second.from.as_str(), second.to.as_str()), ("accepted", "executing"));
    { let k = key(&rig, "issued", "accepted"); rig.engine.on_ack_result(&k, "replay"); } // the delayed duplicate
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert!(r.acks[0].delivered);
    assert!(!r.acks[1].delivered, "accepted->executing must still be owed: nothing answered it");
    // A late duplicate refusal of the settled step does not end the chain either.
    { let k = key(&rig, "issued", "accepted"); rig.engine.on_ack_result(&k, "refused"); }
    assert!(!rig.store.get(DIRECTIVE_ID).unwrap().acks[0].refused);
    // Only the answer that names the step settles it.
    { let k = key(&rig, "accepted", "executing"); rig.engine.on_ack_result(&k, "applied"); }
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().acks[1].delivered);
}

#[test]
fn an_answer_for_a_step_that_is_not_next_or_not_a_step_changes_nothing() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    { let k = key(&rig, "accepted", "executing"); rig.engine.on_ack_result(&k, "applied"); } // step 1 before step 0
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().acks.iter().all(|a| !a.delivered));
    { let k = key(&rig, "executing", "complete"); rig.engine.on_ack_result(&k, "applied"); } // no such step yet
    { let k = key(&rig, "issued", "accepted"); rig.engine.on_ack_result(&k, "bogus"); }
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().acks.iter().all(|a| !a.delivered && !a.refused));
}

// ---- E4: expiry before the first removal launch; E5: mutual exclusion with the update path ---------------

#[test]
fn a_removal_whose_chain_is_confirmed_but_whose_directive_expired_is_not_launched() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.engine.drive();
    rig.settle_acks(); // every ack delivered: the OLD code launched here regardless of the clock
    rig.advance(3_600_000 + 1_000);
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_uninstall"), 0, "an expired removal must never launch");
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("expired"));
}

#[test]
fn the_engine_does_not_reserve_while_the_other_path_holds_the_exclusion() {
    let mut rig = rig();
    accepted(&mut rig, "uninstall", DIRECTIVE_ID);
    rig.act.exclusion.store(true, Ordering::SeqCst); // the update worker is deciding right now
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, ACCEPTED, "no reservation without the lock");
    rig.act.exclusion.store(false, Ordering::SeqCst);
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, EXECUTING);
    assert!(!rig.act.exclusion.load(Ordering::SeqCst), "the lock is released once the reservation is saved");
}

/// The worker's side of the protocol, exactly as `update_worker` runs it: take the lock, check no removal is in flight, reserve.
fn worker_try_reserve(store: &MemStore, lock: &Arc<std::sync::atomic::AtomicBool>, update_reserved: &Arc<std::sync::atomic::AtomicBool>) -> bool {
    if lock.swap(true, Ordering::SeqCst) {
        return false;
    }
    let ok = !removal_in_flight(store);
    if ok {
        std::thread::yield_now();
        update_reserved.store(true, Ordering::SeqCst);
    }
    lock.store(false, Ordering::SeqCst);
    ok
}

#[test]
fn removal_and_update_are_mutually_exclusive_under_every_interleaving_tried() {
    for round in 0..300 {
        let mut rig = rig();
        accepted(&mut rig, "uninstall", DIRECTIVE_ID);
        // The fake's update_busy reads this flag, as the real one reads the update state's phase: the worker sets it INSIDE its
        // critical section, exactly where it persists Prelaunch.
        let busy = rig.act.busy.clone();
        let update_reserved = busy.clone();
        let lock = rig.act.exclusion.clone();
        let (store, flag) = (rig.store.clone(), update_reserved.clone());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b2 = barrier.clone();
        let worker = std::thread::spawn(move || {
            b2.wait();
            for _ in 0..50 {
                if worker_try_reserve(&store, &lock, &flag) {
                    return;
                }
                std::thread::yield_now();
            }
        });
        barrier.wait();
        for _ in 0..50 {
            rig.engine.drive();
            if rig.store.get(DIRECTIVE_ID).unwrap().state != ACCEPTED {
                break;
            }
            std::thread::yield_now();
        }
        worker.join().unwrap();
        let removal_reserved = rig.store.get(DIRECTIVE_ID).unwrap().state != ACCEPTED;
        assert!(
            !(removal_reserved && update_reserved.load(Ordering::SeqCst)),
            "round {round}: both an update and a removal were allowed to proceed"
        );
    }
}

// ---- E2: a reinstall whose request was never made is requested again -----------------------------------

#[test]
fn a_crash_between_reinstall_requested_and_the_marker_retries_the_request_instead_of_polling_forever() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    // Hand-write the post-crash state: executing/reinstall_requested durable, start_reinstall never wrote its marker.
    let mut r = rig.store.get(DIRECTIVE_ID).unwrap();
    r.transition(EXECUTING, "", NOW);
    r.step = step::REINSTALL_REQUESTED.into();
    rig.store.save(&r).unwrap();
    rig.restart();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::NotRequested;
    rig.engine.drive();
    assert_eq!(rig.act.calls("start_reinstall"), 1, "the request is made again");
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, EXECUTING);
    // Past the directive's expiry the retry is abandoned and reported.
    rig.advance(86_400_000 + 5_000);
    rig.engine.drive();
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert_eq!(r.state, FAILED);
    assert!(r.detail.contains("never made"));
}

// ---- B1 (engine side): only a send the engine itself persisted can be answered -------------------------------

#[test]
fn an_answer_naming_a_timestamp_the_engine_never_sent_settles_nothing() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    let sent = rig.engine.next_ack().unwrap();
    let forged = AckKey { directive_id: DIRECTIVE_ID.into(), from: "issued".into(), to: "accepted".into(), ts_ms: sent.ts_ms + 12345 };
    rig.engine.on_ack_result(&forged, "applied");
    assert!(!rig.store.get(DIRECTIVE_ID).unwrap().acks[0].delivered);
    rig.engine.on_ack_result(&AckKey::of(&sent), "applied");
    assert!(rig.store.get(DIRECTIVE_ID).unwrap().acks[0].delivered);
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().acks[0].sent_ts, vec![sent.ts_ms], "the send was persisted before it could be answered");
}

// ---- release review 1.3.19 ---------------------------------------------------------------------------

fn park_a_reboot_pending_reinstall(rig: &mut Rig) {
    accepted(rig, "reinstall", DIRECTIVE_ID);
    rig.engine.drive();
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::RebootPending;
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, REBOOT_PENDING);
    rig.advance(1_000);
}

#[test]
fn a_parked_reboot_pending_reinstall_does_not_starve_a_newer_accepted_uninstall() {
    let mut rig = rig();
    park_a_reboot_pending_reinstall(&mut rig);
    accepted(&mut rig, "uninstall", OTHER_ID);
    assert!(removal_in_flight(&rig.store), "the accepted uninstall is an unresolved removal");
    rig.engine.drive();
    assert_eq!(
        rig.store.get(OTHER_ID).unwrap().state,
        EXECUTING,
        "the uninstall must be driven even though an older reinstall is still reboot_pending"
    );
}

#[test]
fn a_waiting_accepted_uninstall_still_expires_behind_a_parked_reboot_pending_reinstall() {
    let mut rig = rig();
    park_a_reboot_pending_reinstall(&mut rig);
    accepted(&mut rig, "uninstall", OTHER_ID);
    rig.act.busy.store(true, Ordering::SeqCst); // an update attempt is running: the uninstall waits
    rig.engine.drive();
    assert_eq!(rig.store.get(OTHER_ID).unwrap().state, ACCEPTED);
    rig.advance(2 * 3_600_000);
    rig.engine.drive();
    assert_eq!(rig.store.get(OTHER_ID).unwrap().state, FAILED, "expiry processing must reach it");
    assert!(!removal_in_flight(&rig.store));
}

#[test]
fn a_parked_reboot_pending_reinstall_can_still_resolve_while_an_uninstall_runs() {
    let mut rig = rig();
    park_a_reboot_pending_reinstall(&mut rig);
    accepted(&mut rig, "uninstall", OTHER_ID);
    *rig.act.reinstall.lock().unwrap() = ReinstallStatus::Done;
    rig.engine.drive();
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, COMPLETE);
    assert_eq!(rig.store.get(OTHER_ID).unwrap().state, EXECUTING);
}

#[test]
fn a_refused_ack_settles_the_rest_of_the_chain_so_the_record_can_be_pruned() {
    let mut rig = rig();
    accepted(&mut rig, "reinstall", DIRECTIVE_ID);
    *rig.act.start_reinstall_err.lock().unwrap() = Some("nope".into());
    rig.engine.drive(); // accepted -> executing -> failed: three steps owed
    assert_eq!(rig.store.get(DIRECTIVE_ID).unwrap().state, FAILED);
    rig.answer("refused"); // the very first step is refused: nothing after it is ever sent
    let r = rig.store.get(DIRECTIVE_ID).unwrap();
    assert!(r.acks.len() >= 3 && r.acks[0].refused && !r.acks[1].delivered);
    assert!(r.acks_settled(), "a refused step ends the chain: the steps behind it are abandoned");
    assert!(rig.engine.next_ack().is_none());
    rig.advance(86_400_000 + 24 * 3_600_000 + 10_000);
    rig.engine.drive();
    assert!(rig.store.get(DIRECTIVE_ID).is_none(), "a terminal record whose chain was refused must be pruned");
}
