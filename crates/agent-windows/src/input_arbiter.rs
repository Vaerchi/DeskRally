//! Input-control arbitration between concurrent sessions (docs/61, design Codex-reviewed r1).
//!
//! This module is the STATE MACHINE only: `Unowned -> Transitioning { id } -> Owned`, plus the
//! armed-but-ownerless `Blocked` state, with an arbitration EPOCH that advances on every transition
//! begin so input stamped in an earlier interval can never become effective later (r1 H2). It is
//! deliberately pure — liveness/eligibility arrive through [`Participants`], and the caller performs
//! the fencing/draining work BETWEEN [`InputArbiter::begin_hand`] and [`InputArbiter::commit`]
//! (r1 H1/H3: entering arbitration from `Unowned` fences EVERY participant, and the typist barrier
//! must be awaited OFF the coordinator lock) — so every rule the review pinned is unit-testable
//! without threads:
//!
//! * validation BEFORE any state change; an invalid target never leaves the sender owning anything;
//! * only the current owner hands; from `Unowned`/`Blocked` an eligible sender claims-and-hands in
//!   one serialized decision;
//! * self-hand is rejected without side effects from `Unowned` (free interleave already admits the
//!   sender) but is THE explicit claim from `Blocked` — the only way a lone surviving controller can
//!   recover input once arbitration is armed;
//! * `Transitioning` admits no new presses from anyone; cleanup failure RETAINS `Transitioning`
//!   (callers retry) and never announces success; commit re-checks the transition id AND the
//!   target's liveness, resolving to `Blocked` if the target vanished;
//! * once armed, the owner's teardown moves to `Blocked` (announced, input-dead) — never a silent
//!   return to free interleave (r1 A4);
//! * handles pair with an INCARNATION so a reused counter can never alias a dead session.
//!
//! Injection gating consults [`InputArbiter::injection_verdict`] with the event's stamped epoch;
//! releases are never dropped here — they always reach the coordinator's BOOKKEEPING, which is
//! holder- and epoch-aware (r1 answer 2).

#![cfg_attr(not(windows), allow(dead_code))]

/// A session's identity for arbitration: the coordinator's handle plus an incarnation that is never
/// reused, so a message naming a dead session's recycled handle cannot act on its successor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Member {
    pub handle: u64,
    pub incarnation: u64,
}

/// Liveness/eligibility oracle, answered under the coordinator lock by the real registry.
pub(crate) trait Participants {
    /// The member is registered, its incarnation current, and its transport live.
    fn is_live(&self, m: Member) -> bool;
    /// The member's session admits control-level input at all (an observer is never eligible).
    fn is_control_eligible(&self, m: Member) -> bool;
    /// Every currently-registered member (the fence scope when leaving `Unowned`).
    fn all_members(&self) -> Vec<Member>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// Compatibility mode: no arbitration has ever been armed; input interleaves as it always has.
    Unowned,
    /// A hand is in flight: no new presses from anyone until it commits or resolves.
    Transitioning { id: u64, to: Member },
    /// One member owns input.
    Owned { who: Member },
    /// Armed but ownerless (owner tore down, or a transition's target vanished): input is DEAD until
    /// an eligible controller claims. Never silently returns to `Unowned`.
    Blocked,
}

/// What the caller must fence/drain between `begin_hand` and `commit`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum FenceScope {
    /// Leaving `Unowned`: EVERY participant may hold keys or queued typing (r1 H1).
    AllParticipants(Vec<Member>),
    /// An owner-to-owner hand: the previous owner is the only admitted producer to quiesce.
    Previous(Member),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Transition {
    pub id: u64,
    pub to: Member,
    pub fence: FenceScope,
    /// The epoch all NEW input must carry to survive `injection_verdict` after commit.
    pub epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HandRefusal {
    /// Another member owns input; the refusal names it so the viewer can say who.
    NotOwner { owner: Member },
    /// A transition is already in flight; serialize behind it.
    Busy,
    SenderNotLive,
    SenderNotEligible,
    TargetNotLive,
    TargetNotEligible,
    /// Self-hand from `Unowned`: a no-op by design (free interleave already admits the sender).
    SelfHandMeaningless,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum CommitOutcome {
    /// The hand committed; announce `Owned { who }` to every participant.
    Owned { who: Member, epoch: u64 },
    /// The target vanished during cleanup; arbitration stays armed and input stays dead.
    BlockedTargetGone,
    /// The id does not name the in-flight transition (already resolved, or never begun).
    StaleTransition,
}

/// Per-event verdict at the injection gate. A denied RELEASE still reaches the coordinator's
/// bookkeeping — but only for the CURRENT ownership interval: the hub's dispatch exempts a denied
/// release when its stamped epoch equals the current one, and drops a stale-interval up (whose key
/// the transition fence already freed) so it cannot release a later hold. See
/// [`crate::shared_capture`]'s `InputArbiterHub::dispatch`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum InjectionVerdict {
    Admit,
    /// Drop: wrong owner, stale epoch, transition in flight, or blocked.
    Deny,
}

pub(crate) struct InputArbiter {
    mode: Mode,
    epoch: u64,
    next_transition_id: u64,
}

impl InputArbiter {
    pub fn new() -> Self {
        Self { mode: Mode::Unowned, epoch: 0, next_transition_id: 1 }
    }

    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// The epoch NEW input must be stamped with to be admitted under the current/next owner.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether arbitration has ever been armed (drives the viewer's mode indicator).
    pub fn armed(&self) -> bool {
        !matches!(self.mode, Mode::Unowned)
    }

    /// Validate and BEGIN a hand. On success the mode is `Transitioning`, the epoch has advanced
    /// (new presses die at the gate until commit opens the recipient), and the returned fence tells
    /// the caller exactly what to quiesce before calling [`commit`]. Validation precedes every state
    /// change: a refusal leaves the arbiter exactly as it was.
    /// The validation `begin_hand` performs, without changing anything — so a caller can refuse an
    /// invalid hand BEFORE taking any action on its behalf (cross-stage review: a hand that is already
    /// invalid must not cancel the owner's typing). It reserves nothing; `begin_hand` re-validates.
    pub fn check_hand(&self, sender: Member, target: Member, participants: &impl Participants) -> Result<(), HandRefusal> {
        if matches!(self.mode, Mode::Transitioning { .. }) {
            return Err(HandRefusal::Busy);
        }
        if !participants.is_live(sender) {
            return Err(HandRefusal::SenderNotLive);
        }
        if !participants.is_control_eligible(sender) {
            return Err(HandRefusal::SenderNotEligible);
        }
        match &self.mode {
            Mode::Owned { who } if *who != sender => return Err(HandRefusal::NotOwner { owner: *who }),
            // Free interleave already admits the sender; arming to hand to yourself means nothing.
            Mode::Unowned if sender == target => return Err(HandRefusal::SelfHandMeaningless),
            _ => {}
        }
        if !participants.is_live(target) {
            return Err(HandRefusal::TargetNotLive);
        }
        if !participants.is_control_eligible(target) {
            return Err(HandRefusal::TargetNotEligible);
        }
        Ok(())
    }

    pub fn begin_hand(
        &mut self,
        sender: Member,
        target: Member,
        participants: &impl Participants,
    ) -> Result<Transition, HandRefusal> {
        // Validation precedes every state change. From Blocked, sender == target IS the explicit claim
        // (the only recovery for a lone surviving controller once arbitration is armed); from Unowned
        // it means nothing (free interleave already admits the sender).
        self.check_hand(sender, target, participants)?;

        let fence = match &self.mode {
            Mode::Unowned => FenceScope::AllParticipants(participants.all_members()),
            Mode::Owned { who } => FenceScope::Previous(*who),
            // Cross-stage review: a hand superseded mid-fence (its target left) is abandoned without
            // releasing the previous owner's holds, and their stale-epoch key-ups are dropped. So a
            // claim from Blocked must fence EVERY participant, not assume nothing is held.
            Mode::Blocked => FenceScope::AllParticipants(participants.all_members()),
            Mode::Transitioning { .. } => unreachable!("checked above"),
        };
        let id = self.next_transition_id;
        self.next_transition_id += 1;
        // Advance the epoch FIRST (r1 H2/H3 ordering): everything stamped before this instant is
        // stale at the gate from here on, including input of the sessions being fenced.
        self.epoch += 1;
        self.mode = Mode::Transitioning { id, to: target };
        Ok(Transition { id, to: target, fence, epoch: self.epoch })
    }

    /// Commit a transition AFTER its fence/drain completed. Re-checks the id and the target's
    /// liveness: a vanished target resolves to `Blocked` (never a silent owner, never `Unowned`).
    pub fn commit(&mut self, id: u64, participants: &impl Participants) -> CommitOutcome {
        let to = match &self.mode {
            Mode::Transitioning { id: current, to } if *current == id => *to,
            _ => return CommitOutcome::StaleTransition,
        };
        if !participants.is_live(to) || !participants.is_control_eligible(to) {
            self.mode = Mode::Blocked;
            return CommitOutcome::BlockedTargetGone;
        }
        self.mode = Mode::Owned { who: to };
        CommitOutcome::Owned { who: to, epoch: self.epoch }
    }

    /// A member is gone (clean end and detected crash take the SAME path).
    ///
    /// * owner gone, armed -> `Blocked` (announced input-dead; r1 A4 — never silent interleave);
    /// * transition target gone -> `Blocked` (resolved by the next commit attempt too, but teardown
    ///   must not wait for it);
    /// * transition SENDER gone -> the hand may still commit (the target lives); no change here;
    /// * anything else -> no change.
    ///
    /// Returns true when the mode changed (the caller announces a snapshot to every participant).
    pub fn teardown(&mut self, member: Member) -> bool {
        match &self.mode {
            Mode::Owned { who } if *who == member => {
                self.epoch += 1; // nothing stamped for the dead owner may fire later
                self.mode = Mode::Blocked;
                true
            }
            Mode::Transitioning { to, .. } if *to == member => {
                self.epoch += 1;
                self.mode = Mode::Blocked;
                true
            }
            _ => false,
        }
    }

    /// `member` can no longer control (it became view-only: a policy floor, the toggle, or a lost
    /// guest indicator). An OWNER that loses eligibility is resolved exactly like an owner that left —
    /// `Blocked`, announced, epoch advanced — so input is never held hostage by a session that cannot
    /// type (cross-stage review). A transition TO it resolves the same way. Returns whether the mode
    /// changed.
    pub fn lose_eligibility(&mut self, member: Member) -> bool {
        self.teardown(member)
    }

    /// Every participant has left: return to compatibility mode. Stickiness exists so the indicator
    /// cannot lie to OTHER participants; with none left there is nobody to mislead, and a later lone
    /// technician (or an old viewer with no claim UI) must not start locked out. The epoch advances so
    /// nothing stamped before can matter. Returns whether the mode changed.
    pub fn reset_unarmed(&mut self) -> bool {
        if matches!(self.mode, Mode::Unowned) {
            return false;
        }
        self.epoch += 1;
        self.mode = Mode::Unowned;
        true
    }

    /// The per-event gate (presses, text, moves, wheel — NOT releases, which always reach the
    /// coordinator's holder/epoch-aware bookkeeping instead).
    pub fn injection_verdict(&self, member: Member, stamped_epoch: u64) -> InjectionVerdict {
        verdict_for(&self.mode, self.epoch, member, stamped_epoch)
    }
}

/// The verdict logic itself, shared with the hub's published `(mode, epoch)` snapshot so the
/// capture thread's per-event gate and this state machine can never disagree.
pub(crate) fn verdict_for(
    mode: &Mode,
    epoch: u64,
    member: Member,
    stamped_epoch: u64,
) -> InjectionVerdict {
    match mode {
        Mode::Unowned => InjectionVerdict::Admit,
        Mode::Transitioning { .. } | Mode::Blocked => InjectionVerdict::Deny,
        Mode::Owned { who } => {
            if *who == member && stamped_epoch == epoch {
                InjectionVerdict::Admit
            } else {
                InjectionVerdict::Deny
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        live: Vec<Member>,
        eligible: Vec<Member>,
    }
    impl Fake {
        fn of(members: &[Member]) -> Self {
            Self { live: members.to_vec(), eligible: members.to_vec() }
        }
        fn drop_member(&mut self, m: Member) {
            self.live.retain(|x| *x != m);
            self.eligible.retain(|x| *x != m);
        }
        fn make_observer(&mut self, m: Member) {
            self.eligible.retain(|x| *x != m);
        }
    }
    impl Participants for Fake {
        fn is_live(&self, m: Member) -> bool {
            self.live.contains(&m)
        }
        fn is_control_eligible(&self, m: Member) -> bool {
            self.eligible.contains(&m)
        }
        fn all_members(&self) -> Vec<Member> {
            self.live.clone()
        }
    }

    const A: Member = Member { handle: 1, incarnation: 10 };
    const B: Member = Member { handle: 2, incarnation: 20 };
    const C: Member = Member { handle: 3, incarnation: 30 };

    #[test]
    fn unowned_admits_everyone_and_any_epoch() {
        let arb = InputArbiter::new();
        assert!(!arb.armed());
        assert_eq!(arb.injection_verdict(A, 0), InjectionVerdict::Admit);
        assert_eq!(arb.injection_verdict(B, 999), InjectionVerdict::Admit);
    }

    #[test]
    fn first_hand_from_unowned_fences_every_participant_and_commits_to_target() {
        let p = Fake::of(&[A, B, C]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).expect("valid hand");
        match &t.fence {
            FenceScope::AllParticipants(all) => {
                assert_eq!(all.len(), 3, "leaving Unowned fences EVERYONE, not just the sender");
            }
            other => panic!("expected AllParticipants, got {other:?}"),
        }
        // Mid-transition nobody injects, old epochs are dead.
        assert_eq!(arb.injection_verdict(A, t.epoch), InjectionVerdict::Deny);
        assert_eq!(arb.injection_verdict(B, t.epoch), InjectionVerdict::Deny);
        assert_eq!(arb.commit(t.id, &p), CommitOutcome::Owned { who: B, epoch: t.epoch });
        // Only the owner, only at the current epoch.
        assert_eq!(arb.injection_verdict(B, t.epoch), InjectionVerdict::Admit);
        assert_eq!(arb.injection_verdict(B, t.epoch - 1), InjectionVerdict::Deny, "stale epoch");
        assert_eq!(arb.injection_verdict(A, t.epoch), InjectionVerdict::Deny);
    }

    #[test]
    fn validation_precedes_state_change_and_an_invalid_target_claims_nothing() {
        let mut p = Fake::of(&[A, B]);
        p.drop_member(B);
        let mut arb = InputArbiter::new();
        let before_epoch = arb.epoch();
        assert_eq!(arb.begin_hand(A, B, &p), Err(HandRefusal::TargetNotLive));
        assert_eq!(*arb.mode(), Mode::Unowned, "refusal leaves the arbiter untouched");
        assert_eq!(arb.epoch(), before_epoch);
        assert_eq!(arb.injection_verdict(A, 0), InjectionVerdict::Admit, "still free interleave");
    }

    #[test]
    fn only_the_owner_hands_and_the_refusal_names_the_owner() {
        let p = Fake::of(&[A, B, C]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        arb.commit(t.id, &p);
        assert_eq!(arb.begin_hand(C, A, &p), Err(HandRefusal::NotOwner { owner: B }));
        // The recipient may legitimately hand onward; the fence is now just the previous owner.
        let t2 = arb.begin_hand(B, C, &p).unwrap();
        assert_eq!(t2.fence, FenceScope::Previous(B));
        assert_eq!(arb.commit(t2.id, &p), CommitOutcome::Owned { who: C, epoch: t2.epoch });
    }

    #[test]
    fn concurrent_hands_serialize_and_the_loser_sees_busy_then_judges_against_the_new_owner() {
        let p = Fake::of(&[A, B, C]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        assert_eq!(arb.begin_hand(C, A, &p), Err(HandRefusal::Busy), "transition in flight");
        arb.commit(t.id, &p);
        assert_eq!(arb.begin_hand(C, A, &p), Err(HandRefusal::NotOwner { owner: B }));
    }

    #[test]
    fn observers_are_never_valid_targets_or_senders() {
        let mut p = Fake::of(&[A, B]);
        p.make_observer(B);
        let mut arb = InputArbiter::new();
        assert_eq!(arb.begin_hand(A, B, &p), Err(HandRefusal::TargetNotEligible));
        assert_eq!(arb.begin_hand(B, A, &p), Err(HandRefusal::SenderNotEligible));
    }

    #[test]
    fn self_hand_is_meaningless_from_unowned_but_is_the_claim_from_blocked() {
        let p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        assert_eq!(arb.begin_hand(A, A, &p), Err(HandRefusal::SelfHandMeaningless));

        let t = arb.begin_hand(A, B, &p).unwrap();
        arb.commit(t.id, &p);
        assert!(arb.teardown(B), "owner teardown must change mode");
        assert_eq!(*arb.mode(), Mode::Blocked);
        assert_eq!(arb.injection_verdict(A, arb.epoch()), InjectionVerdict::Deny, "blocked is dead");

        // The lone survivor recovers by claiming. The claim fences EVERY participant: an abandoned
        // earlier fence may have left someone's holds behind (cross-stage review).
        let t2 = arb.begin_hand(A, A, &p).unwrap();
        assert_eq!(t2.fence, FenceScope::AllParticipants(p.all_members()));
        assert_eq!(arb.commit(t2.id, &p), CommitOutcome::Owned { who: A, epoch: t2.epoch });
        assert_eq!(arb.injection_verdict(A, t2.epoch), InjectionVerdict::Admit);
    }

    #[test]
    fn cleanup_failure_retains_transitioning_and_commit_is_idempotent_about_stale_ids() {
        let p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        // The caller's cleanup failed; it simply does not commit. The mode stays Transitioning and
        // nobody injects — never a success announcement.
        assert!(matches!(arb.mode(), Mode::Transitioning { .. }));
        assert_eq!(arb.injection_verdict(B, t.epoch), InjectionVerdict::Deny);
        // A stale/foreign id cannot commit anything.
        assert_eq!(arb.commit(t.id + 7, &p), CommitOutcome::StaleTransition);
        assert!(matches!(arb.mode(), Mode::Transitioning { .. }));
        // The retry then commits the SAME transition.
        assert_eq!(arb.commit(t.id, &p), CommitOutcome::Owned { who: B, epoch: t.epoch });
        // And committing again is stale, not a second announcement.
        assert_eq!(arb.commit(t.id, &p), CommitOutcome::StaleTransition);
    }

    #[test]
    fn a_target_that_vanishes_during_cleanup_resolves_to_blocked_not_a_silent_owner() {
        let mut p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        p.drop_member(B);
        assert_eq!(arb.commit(t.id, &p), CommitOutcome::BlockedTargetGone);
        assert_eq!(*arb.mode(), Mode::Blocked);
        assert_eq!(arb.injection_verdict(A, arb.epoch()), InjectionVerdict::Deny);
    }

    #[test]
    fn owner_teardown_blocks_input_rather_than_resuming_interleave_and_bumps_the_epoch() {
        let p = Fake::of(&[A, B, C]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        arb.commit(t.id, &p);
        let before = arb.epoch();
        assert!(arb.teardown(B));
        assert_eq!(*arb.mode(), Mode::Blocked);
        assert!(arb.epoch() > before, "nothing stamped for the dead owner may fire later");
        assert_eq!(arb.injection_verdict(C, arb.epoch()), InjectionVerdict::Deny);
        // A non-owner's teardown changes nothing.
        let t2 = arb.begin_hand(A, A, &p).unwrap();
        arb.commit(t2.id, &p);
        assert!(!arb.teardown(C));
        assert_eq!(*arb.mode(), Mode::Owned { who: A });
    }

    #[test]
    fn a_recycled_handle_with_a_new_incarnation_never_aliases_the_dead_session() {
        let reborn = Member { handle: B.handle, incarnation: B.incarnation + 1 };
        let p = Fake::of(&[A, reborn]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, reborn, &p).unwrap();
        arb.commit(t.id, &p);
        // The OLD incarnation is not the owner even though the handle matches.
        assert_eq!(arb.injection_verdict(B, t.epoch), InjectionVerdict::Deny);
        assert_eq!(arb.injection_verdict(reborn, t.epoch), InjectionVerdict::Admit);
    }

    #[test]
    fn transition_sender_dying_does_not_kill_the_hand() {
        let mut p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        assert!(!arb.teardown(A), "the sender's death mid-hand does not change the mode");
        p.drop_member(A);
        assert_eq!(arb.commit(t.id, &p), CommitOutcome::Owned { who: B, epoch: t.epoch });
    }

    #[test]
    fn check_hand_validates_without_changing_anything() {
        let p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        assert_eq!(arb.check_hand(A, A, &p), Err(HandRefusal::SelfHandMeaningless));
        assert_eq!(arb.check_hand(A, B, &p), Ok(()));
        assert_eq!(*arb.mode(), Mode::Unowned, "a check must not arm anything");
        assert_eq!(arb.epoch(), 0, "a check must not advance the epoch");
        let t = arb.begin_hand(A, B, &p).unwrap();
        assert_eq!(arb.check_hand(B, A, &p), Err(HandRefusal::Busy));
        arb.commit(t.id, &p);
        assert_eq!(arb.check_hand(A, B, &p), Err(HandRefusal::NotOwner { owner: B }));
    }

    #[test]
    fn an_owner_that_becomes_view_only_releases_input_to_blocked() {
        let p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        let t = arb.begin_hand(A, B, &p).unwrap();
        arb.commit(t.id, &p);
        let before = arb.epoch();
        assert!(!arb.lose_eligibility(A), "a non-owner losing eligibility changes nothing");
        assert!(arb.lose_eligibility(B), "the owner losing eligibility must free input");
        assert_eq!(*arb.mode(), Mode::Blocked);
        assert!(arb.epoch() > before, "nothing the ex-owner stamped may fire later");
    }

    #[test]
    fn with_everyone_gone_the_machine_returns_to_compatibility_mode() {
        let p = Fake::of(&[A, B]);
        let mut arb = InputArbiter::new();
        assert!(!arb.reset_unarmed(), "already unarmed");
        let t = arb.begin_hand(A, B, &p).unwrap();
        arb.commit(t.id, &p);
        arb.teardown(B);
        assert_eq!(*arb.mode(), Mode::Blocked);
        let before = arb.epoch();
        assert!(arb.reset_unarmed());
        assert_eq!(*arb.mode(), Mode::Unowned);
        assert!(arb.epoch() > before);
        assert_eq!(arb.injection_verdict(A, 0), InjectionVerdict::Admit, "compatibility mode admits again");
    }
}
