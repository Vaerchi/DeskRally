//! docs/73 2.2.8 (c), host level: the announce, the routing of every request message into the hub, and the
//! wire / audit mapping of every directive, with the REAL hub, directory, handoff queues and capture thread.
//! Only the transport is absent: [`Host::pump`] drains a session's handoff queue exactly as the session
//! loop does (`wire_of` for a request directive, the audit action as-is for `SealAudit`), so a session's
//! `log` is the sequence of frames it would have put on the wire / sealed into its chain, in order.

use super::*;
use crate::session_directory::{handoff_channel, HandoffOutbound, HandoffRx, SessionIdentity};
use crate::shared_capture::{SessionInputSender, SharedCapture};
use rmt_agent_core::control::{ControlMessage as Cm, InputRequestOutcome as Out};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Sess {
    _input: SessionInputSender,
    handle: u64,
    sid: String,
    observer: bool,
    rx: HandoffRx,
    _reg: crate::shared_capture::DirectoryRegistration,
    /// Everything this session would have sent or sealed so far, in order.
    log: Vec<Wire>,
}

struct Host {
    cap: SharedCapture,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Host {
    fn new() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (cap, thread) = crate::shared_capture::spawn_for_request_tests(Arc::clone(&stop));
        Self { cap, stop, thread: Some(thread) }
    }

    /// A registered, directory-joined session; control-eligible unless an observer.
    fn session(&self, n: u128, observer: bool) -> Sess {
        let input = self.cap.new_session_input();
        let handle = input.handle();
        self.cap.arb.set_control_eligible(handle, !observer);
        let (tx, rx) = handoff_channel();
        let sid = Uuid::from_u128(0x5000 + n).to_string();
        let reg = self.cap.arb.join_directory(
            sid.clone(),
            SessionIdentity {
                handle,
                control_plane_session: Some(Uuid::from_u128(0xc000 + n)),
                technician_id: Some(Uuid::from_u128(0xd000 + n)),
            },
            tx,
        );
        Sess { _input: input, handle, sid, observer, rx, _reg: reg, log: Vec::new() }
    }

    /// Drain `s`''s queue the way the session loop does, appending to its log.
    fn pump(&self, s: &mut Sess) {
        while let Ok(m) = s.rx.try_recv() {
            match m {
                HandoffOutbound::Control(c) => s.log.push(Wire::Control(c)),
                HandoffOutbound::SealAudit(a) => s.log.push(Wire::Seal(a)),
                HandoffOutbound::Request(d) => {
                    if let Some(w) = wire_of(&d, |h| self.cap.arb.signaling_id_of(h)) {
                        s.log.push(w);
                    }
                }
                HandoffOutbound::KeepAwakeChanged | HandoffOutbound::Disconnect(_) => {}
            }
        }
    }

    fn send(&self, s: &Sess, flag: bool, msg: Cm) -> Inbound<()> {
        let ctx = InboundCtx { hub: &self.cap.arb, handle: s.handle, request_v1: flag, observer: s.observer };
        handle_inbound(&ctx, &msg, Instant::now(), || Some(()))
    }

    fn announce(&self, s: &Sess) {
        match self.send(s, true, Cm::InputRequestCapable {}) {
            Inbound::Reply(Cm::InputRequestAvailable { available }) => assert_eq!(available, !s.observer),
            o => panic!("expected the availability reply, got {o:?}"),
        }
    }

    /// `owner` owns input (committed through the real capture thread).
    fn make_owner(&self, owner: &Sess, other: &Sess) {
        let out = self.cap.hand_input_control(other.handle, owner.handle).unwrap();
        assert!(matches!(out, crate::input_arbiter::CommitOutcome::Owned { .. }));
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

const CID: &str = "aaaaaaaa-1111-4222-8333-444444444444";

fn request(cid: &str) -> Cm {
    Cm::RequestInputControl { client_request_id: cid.into(), retry: false }
}

fn pos(log: &[Wire], pred: impl Fn(&Wire) -> bool, what: &str) -> usize {
    log.iter().position(pred).unwrap_or_else(|| panic!("{what} not found in {log:#?}"))
}

fn is_requested_seal(w: &Wire) -> bool {
    matches!(w, Wire::Seal(AuditAction::InputControlRequested { .. }))
}
fn is_closed_seal(w: &Wire, want: InputRequestAuditOutcome) -> bool {
    matches!(w, Wire::Seal(AuditAction::InputControlRequestClosed { outcome, .. }) if *outcome == want)
}
fn is_handed_seal(w: &Wire) -> bool {
    matches!(w, Wire::Seal(AuditAction::InputControlHanded { .. }))
}
fn result_outcome(w: &Wire) -> Option<Out> {
    match w {
        Wire::Control(Cm::InputControlRequestResult { outcome, .. }) => Some(*outcome),
        _ => None,
    }
}

/// announce -> available (false for an observer); only the announced session ever hears of the feature.
#[test]
fn the_announce_is_answered_with_availability() {
    let host = Host::new();
    let viewer = host.session(1, false);
    let observer = host.session(2, true);
    host.announce(&viewer);
    host.announce(&observer);
}

/// Flag off: no advertisement, and every request message is dropped silently, with no state, no reply
/// and no audit; the announce had no effect, so the session stays unsupported afterwards too.
#[test]
fn with_the_flag_off_nothing_is_advertised_and_requests_are_dropped_silently() {
    let host = Host::new();
    let (mut a, mut b) = (host.session(1, false), host.session(2, false));
    host.make_owner(&a, &b);
    assert!(matches!(host.send(&a, false, Cm::InputRequestCapable {}), Inbound::Nothing));
    assert!(matches!(host.send(&b, false, Cm::InputRequestCapable {}), Inbound::Nothing));
    assert!(matches!(host.send(&b, false, request(CID)), Inbound::Nothing));
    host.pump(&mut a);
    host.pump(&mut b);
    let requested_anything = |s: &Sess| s.log.iter().any(|w| matches!(w, Wire::Seal(AuditAction::InputControlRequested { .. })) || matches!(w, Wire::Control(Cm::InputControlRequestPending { .. } | Cm::InputControlRequestResult { .. } | Cm::InputControlRequested { .. })));
    assert!(!requested_anything(&a) && !requested_anything(&b));
    // The announce was ignored, so even with the flag turned on a request from the unannounced session
    // is dropped by the hub: still nothing.
    assert!(matches!(host.send(&b, true, request(CID)), Inbound::Nothing));
    host.pump(&mut b);
    assert!(!requested_anything(&b));
}

/// A session that never announced gets nothing: no reply to its request, and as a holder it is never prompted.
#[test]
fn an_unannounced_session_gets_nothing() {
    let host = Host::new();
    let (mut a, mut b) = (host.session(1, false), host.session(2, false));
    host.make_owner(&a, &b);
    host.announce(&b); // b announces, the OWNER a does not
    assert!(matches!(host.send(&b, true, request(CID)), Inbound::Nothing));
    host.pump(&mut a);
    host.pump(&mut b);
    assert!(!a.log.iter().any(|w| matches!(w, Wire::Control(Cm::InputControlRequested { .. }))), "the unannounced holder is never prompted");
    // b hears an immediate refusal: unsupported_holder, never audited.
    assert!(b.log.iter().any(|w| result_outcome(w) == Some(Out::UnsupportedHolder)), "{:?}", b.log);
    assert!(!b.log.iter().any(is_requested_seal));
    // And an unannounced REQUESTER gets no reply at all.
    let mut c = host.session(3, false);
    assert!(matches!(host.send(&c, true, request("cccccccc-1111-4222-8333-444444444444")), Inbound::Nothing));
    host.pump(&mut c);
    assert!(c.log.iter().all(|w| matches!(w, Wire::Control(Cm::InputControlChanged { .. }))), "{:?}", c.log);
}

/// request -> prompt -> accept -> granted, with the audit ORDER on the requester's chain:
/// requested < handed < closed{granted}; none of the request kinds on the holder's chain.
#[test]
fn request_prompt_accept_granted_with_the_audit_order_on_the_requesters_chain() {
    let host = Host::new();
    let (mut a, mut b) = (host.session(1, false), host.session(2, false));
    host.make_owner(&a, &b);
    host.announce(&a);
    host.announce(&b);

    assert!(matches!(host.send(&b, true, request(CID)), Inbound::Nothing));
    host.pump(&mut b);
    host.pump(&mut a);
    // B: requested, then Pending. A: the prompt, naming B by signaling id.
    let (req_at, pending_at) = (
        pos(&b.log, is_requested_seal, "requested seal"),
        pos(&b.log, |w| matches!(w, Wire::Control(Cm::InputControlRequestPending { .. })), "Pending"),
    );
    assert!(req_at < pending_at, "requested is sealed before Pending is sent");
    let request_id = match a.log.iter().find_map(|w| match w {
        Wire::Control(Cm::InputControlRequested { request_id, from_session, expires_in_ms }) => {
            assert_eq!(from_session, &b.sid);
            assert_eq!(*expires_in_ms, 60_000);
            Some(request_id.clone())
        }
        _ => None,
    }) {
        Some(id) => id,
        None => panic!("no prompt for the holder: {:?}", a.log),
    };

    // The holder shows the prompt, then accepts.
    assert!(matches!(host.send(&a, true, Cm::InputControlPromptShown { request_id: request_id.clone() }), Inbound::Nothing));
    let (id, deadline) = match host.send(&a, true, Cm::AnswerInputControlRequest { request_id: request_id.clone(), accept: true }) {
        Inbound::SpawnHand { request_id, deadline, .. } => (request_id, deadline),
        o => panic!("expected the hand job, got {o:?}"),
    };
    assert_eq!(id.to_string(), request_id);
    assert!(deadline > Instant::now() && deadline <= Instant::now() + Duration::from_secs(10));
    // The job, as the host runs it off the loop.
    let outcome = host.cap.hand_input_control_for_request(a.handle, id, deadline);
    assert!(matches!(outcome, crate::shared_capture::RequestHandOutcome::Granted { .. }), "{outcome:?}");
    assert!(matches!(host.cap.arb.mode(), crate::input_arbiter::Mode::Owned { who } if who.handle == b.handle));

    host.pump(&mut b);
    host.pump(&mut a);
    let handed = pos(&b.log, is_handed_seal, "handed seal");
    let closed = pos(&b.log, |w| is_closed_seal(w, InputRequestAuditOutcome::Granted), "closed{granted} seal");
    assert!(req_at < handed && handed < closed, "requested < handed < closed on B''s chain: {:#?}", b.log);
    let result = pos(&b.log, |w| result_outcome(w) == Some(Out::Granted), "Result{granted}");
    assert!(closed < result, "the Result follows the close");
    // A hears the prompt withdrawn, and its chain carries the hand but NEVER a request kind.
    assert!(a.log.iter().any(|w| matches!(w, Wire::Control(Cm::InputControlRequestWithdrawn { reason: Out::Granted, .. }))));
    assert!(a.log.iter().any(is_handed_seal));
    assert!(!a.log.iter().any(|w| is_requested_seal(w) || matches!(w, Wire::Seal(AuditAction::InputControlRequestClosed { .. }))));
    // Exactly one close.
    assert_eq!(b.log.iter().filter(|w| matches!(w, Wire::Seal(AuditAction::InputControlRequestClosed { .. }))).count(), 1);
}

/// A decline ends the request: the requester gets `declined` and the close; the holder gets Withdrawn.
#[test]
fn a_decline_closes_the_request_declined() {
    let host = Host::new();
    let (mut a, mut b) = (host.session(1, false), host.session(2, false));
    host.make_owner(&a, &b);
    host.announce(&a);
    host.announce(&b);
    host.send(&b, true, request(CID));
    host.pump(&mut a);
    let request_id = a
        .log
        .iter()
        .find_map(|w| match w {
            Wire::Control(Cm::InputControlRequested { request_id, .. }) => Some(request_id.clone()),
            _ => None,
        })
        .expect("a prompt");
    assert!(matches!(
        host.send(&a, true, Cm::AnswerInputControlRequest { request_id: request_id.clone(), accept: false }),
        Inbound::Nothing
    ));
    host.pump(&mut a);
    host.pump(&mut b);
    assert!(b.log.iter().any(|w| result_outcome(w) == Some(Out::Declined)), "{:?}", b.log);
    assert!(b.log.iter().any(|w| is_closed_seal(w, InputRequestAuditOutcome::Declined)));
    assert!(a.log.iter().any(|w| matches!(w, Wire::Control(Cm::InputControlRequestWithdrawn { reason: Out::Declined, .. }))));
    assert!(matches!(host.cap.arb.mode(), crate::input_arbiter::Mode::Owned { who } if who.handle == a.handle), "nothing moved");
}

/// A busy hand slot or machine permit at the accept: the request fails at once, the holder is told.
#[test]
fn an_accept_with_a_busy_slot_fails_the_request_and_tells_the_holder() {
    let host = Host::new();
    let (mut a, mut b) = (host.session(1, false), host.session(2, false));
    host.make_owner(&a, &b);
    host.announce(&a);
    host.announce(&b);
    host.send(&b, true, request(CID));
    host.pump(&mut a);
    let request_id = a
        .log
        .iter()
        .find_map(|w| match w {
            Wire::Control(Cm::InputControlRequested { request_id, .. }) => Some(request_id.clone()),
            _ => None,
        })
        .unwrap();
    let ctx = InboundCtx { hub: &host.cap.arb, handle: a.handle, request_v1: true, observer: false };
    let msg = Cm::AnswerInputControlRequest { request_id, accept: true };
    let out = handle_inbound::<()>(&ctx, &msg, Instant::now(), || None);
    assert!(matches!(out, Inbound::HolderBusy));
    host.pump(&mut b);
    assert!(b.log.iter().any(|w| result_outcome(w) == Some(Out::Failed)), "{:?}", b.log);
    assert!(b.log.iter().any(|w| is_closed_seal(w, InputRequestAuditOutcome::Failed)));
}

/// An observer announces (and is told no) but its request is refused `ineligible`, never audited.
#[test]
fn an_observer_is_refused_ineligible_without_an_audit_record() {
    let host = Host::new();
    let (a, b) = (host.session(1, false), host.session(2, false));
    let mut obs = host.session(3, true);
    host.make_owner(&a, &b);
    host.announce(&a);
    host.announce(&obs);
    host.send(&obs, true, request(CID));
    host.pump(&mut obs);
    assert!(obs.log.iter().any(|w| result_outcome(w) == Some(Out::Ineligible)), "{:?}", obs.log);
    assert!(!obs.log.iter().any(is_requested_seal));
}