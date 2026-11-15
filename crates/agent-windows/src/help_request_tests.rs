//! Tests for the help-request state machine and the tray decision logic. No window, menu, message box or notification is
//! ever created here: the UI is a recording double, the sink records messages, and time is a value the tests move.

use super::*;
use std::cell::{Cell, RefCell};

#[derive(Default)]
struct RecSink {
    sent: Mutex<Vec<ClientToServer>>,
    dead: Mutex<bool>,
}

impl HelpSink for RecSink {
    fn send(&self, msg: ClientToServer) -> bool {
        if *self.dead.lock().unwrap() {
            return false;
        }
        self.sent.lock().unwrap().push(msg);
        true
    }
}

impl RecSink {
    fn take(&self) -> Vec<ClientToServer> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

fn hub_with(advertised: bool, t0: Instant) -> (Arc<HelpHub>, Arc<RecSink>, u64) {
    let hub = HelpHub::new();
    let sink = Arc::new(RecSink::default());
    let generation = hub.attach(sink.clone(), advertised, t0);
    (hub, sink, generation)
}

fn info(id: &str, status: &str) -> HelpRequestInfo {
    HelpRequestInfo { id: id.into(), status: status.into(), note: String::new(), created_at: String::new(), expires_at: String::new() }
}

fn res(op: &str, op_id: &str, outcome: &str, request: Option<HelpRequestInfo>) -> HelpResult {
    HelpResult { op: op.into(), op_id: op_id.into(), outcome: outcome.into(), request, retry_after_seconds: 0, cancel_of: String::new() }
}

fn sent_op_id(m: &ClientToServer) -> String {
    match m {
        ClientToServer::HelpRequest { op_id, .. } => op_id.clone(),
        other => panic!("expected help_request, got {other:?}"),
    }
}

/// Start a request and acknowledge it: the hub is Open with id "r1".
fn open_request(hub: &HelpHub, sink: &RecSink, generation: u64, now: Instant) -> String {
    hub.request("printer is jammed", now).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    hub.on_result(generation, res("help_request", &op, "ok", Some(info("r1", "open"))), now);
    assert_eq!(hub.view(now).phase, ViewPhase::Open);
    op
}

const SEC: Duration = Duration::from_secs(1);

#[test]
fn feature_absent_means_no_menu_and_nothing_is_ever_sent() {
    // A retired machine's restricted connection, an old server and a control plane without the routes all look the same:
    // the Registered message did not list help_request_v1.
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(false, t0);
    let v = hub.view(t0);
    assert!(!v.available && !v.can_request);
    assert_eq!(hub.request("hello", t0), Err(RequestError::NotAvailable));
    assert_eq!(hub.cancel("r1", t0), Err(CancelError::NotAvailable));
    hub.tick(t0 + Duration::from_secs(3600));
    assert!(sink.take().is_empty(), "an unadvertised connection must receive no help message at all");
    assert!(!advertised(&["session_ended_v1".to_string()]));
    assert!(advertised(&["session_ended_v1".to_string(), "help_request_v1".to_string()]));
}

#[test]
fn a_request_goes_out_sanitized_waits_for_the_ack_then_is_open_and_cancellable() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    assert_eq!(sink.take(), vec![ClientToServer::HelpStatus {}], "attach re-queries the device's open request (H-C4)");

    let long = format!("  {}\u{202E}\n{}  ", "a".repeat(150), "b".repeat(150));
    hub.request(&long, t0).unwrap();
    let sent = sink.take();
    assert_eq!(sent.len(), 1);
    let ClientToServer::HelpRequest { op_id, note } = &sent[0] else { panic!("{:?}", sent[0]) };
    assert_eq!(note.chars().count(), MAX_NOTE_CHARS, "the note is capped at 200 characters");
    assert!(!note.contains('\u{202E}') && !note.contains('\n'), "bidi override and newline never reach the wire");
    assert!(!op_id.is_empty() && op_id.len() <= 64 && op_id.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(hub.view(t0).phase, ViewPhase::Sending);
    assert_eq!(status_text(&hub.view(t0)).unwrap(), "Sending your help request\u{2026}");
    assert_eq!(hub.request("again", t0), Err(RequestError::AlreadyOpen), "one request at a time");
    assert_eq!(hub.cancel("r1", t0), Err(CancelError::NothingToCancel), "cannot cancel what the server has not acknowledged");

    hub.on_result(g, res("help_request", op_id, "ok", Some(info("r1", "open"))), t0);
    let v = hub.view(t0);
    assert_eq!(v.phase, ViewPhase::Open);
    assert!(status_text(&v).unwrap().contains("waiting for a technician"));
    assert!(!status_text(&v).unwrap().contains("will connect"), "H-C4: the wording must not promise a connection");

    hub.cancel("r1", t0).unwrap();
    assert_eq!(sink.take(), vec![ClientToServer::HelpCancel { request_id: "r1".into() }], "cancel names the request id");
    assert_eq!(hub.view(t0).phase, ViewPhase::Cancelling);
    assert_eq!(hub.cancel("r1", t0), Err(CancelError::NothingToCancel), "a second cancel while one is in flight is not sent");
    hub.on_result(g, res("help_cancel", "", "ok", Some(info("r1", "cancelled"))), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice), (ViewPhase::Idle, Some(Notice::Cancelled)));
    assert!(v.can_request);
}

#[test]
fn accepted_expired_and_vanished_requests_reset_the_ui_via_the_status_poll() {
    let t0 = Instant::now();
    for (status, notice) in [("accepted", Notice::Accepted), ("expired", Notice::Expired), ("cancelled", Notice::Cancelled)] {
        let (hub, sink, g) = hub_with(true, t0);
        open_request(&hub, &sink, g, t0);
        hub.tick(t0 + STATUS_POLL);
        assert_eq!(sink.take(), vec![ClientToServer::HelpStatus {}], "the 60 s timer re-queries an open request");
        hub.on_result(g, res("help_status", "", "ok", Some(info("r1", status))), t0 + STATUS_POLL);
        let v = hub.view(t0 + STATUS_POLL);
        assert_eq!((v.phase, v.notice), (ViewPhase::Idle, Some(notice)), "status {status}");
    }
    // The server no longer has it at all.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.on_result(g, res("help_status", "", "ok", None), t0 + SEC);
    assert_eq!(hub.view(t0 + SEC).notice, Some(Notice::Expired));
    assert!(status_text(&hub.view(t0 + SEC)).unwrap().contains("expired"));
}

#[test]
fn the_status_timer_does_not_fire_early() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.tick(t0 + STATUS_POLL - SEC);
    assert!(sink.take().is_empty());
    hub.tick(t0 + STATUS_POLL);
    assert_eq!(sink.take().len(), 1);
    hub.tick(t0 + STATUS_POLL + SEC);
    assert!(sink.take().is_empty(), "polled once per period");
}

#[test]
fn an_idle_status_adopts_an_open_request_but_a_stale_closed_one_is_not_news() {
    let t0 = Instant::now();
    let (hub, _sink, g) = hub_with(true, t0);
    // The device's LATEST request, closed hours ago, answers a status while nothing is open: no notice appears.
    hub.on_result(g, res("help_status", "", "ok", Some(info("old", "accepted"))), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice), (ViewPhase::Idle, None));
    // A request made before this helper started IS adopted, and can be cancelled.
    hub.on_result(g, res("help_status", "", "ok", Some(info("r9", "open"))), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Open);
    hub.cancel("r9", t0).unwrap();
}

#[test]
fn answers_from_an_old_connection_or_for_another_op_are_ignored() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    hub.on_result(g, res("help_request", "someone-elses-op", "ok", Some(info("r1", "open"))), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Sending, "an answer naming another op_id settles nothing");
    hub.on_result(g, res("help_request", "", "ok", Some(info("r1", "open"))), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Sending, "an unattributable answer settles nothing");
    // The connection drops and a new one attaches: the old generation's late answer is ignored.
    let sink2 = Arc::new(RecSink::default());
    let g2 = hub.attach(sink2.clone(), true, t0 + SEC);
    assert_ne!(g, g2);
    hub.on_result(g, res("help_request", &op, "ok", Some(info("r1", "open"))), t0 + SEC);
    assert_eq!(hub.view(t0 + SEC).phase, ViewPhase::Sending);
    // ...and the unacknowledged request is re-sent on the new connection with the SAME op_id (server dedup).
    assert_eq!(sink2.take(), vec![ClientToServer::HelpRequest { op_id: op.clone(), note: "x".into() }]);
    hub.on_result(g2, res("help_request", &op, "ok", Some(info("r1", "open"))), t0 + SEC);
    assert_eq!(hub.view(t0 + SEC).phase, ViewPhase::Open);
    // Detaching a superseded generation does not disturb the live one.
    hub.detach(g, t0 + SEC);
    assert!(hub.view(t0 + SEC).available);
    hub.detach(g2, t0 + SEC);
    assert!(!hub.view(t0 + SEC).available);
}

#[test]
fn losing_the_feature_on_reconnect_hides_the_menu_and_stops_sending() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    // The machine was retired meanwhile: the new Registered does not list the feature.
    let sink2 = Arc::new(RecSink::default());
    hub.attach(sink2.clone(), false, t0 + SEC);
    assert!(!hub.view(t0 + SEC).available);
    hub.tick(t0 + Duration::from_secs(600));
    assert!(sink2.take().is_empty());
}

#[test]
fn an_open_request_is_requeried_on_reconnect() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    let sink2 = Arc::new(RecSink::default());
    hub.attach(sink2.clone(), true, t0 + SEC);
    assert_eq!(sink2.take(), vec![ClientToServer::HelpStatus {}]);
    assert_eq!(hub.view(t0 + SEC).phase, ViewPhase::Open, "the request stays open across the reconnect");
}

#[test]
fn an_unacknowledged_request_is_resent_and_after_two_minutes_is_uncertain_never_failed() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    hub.on_result(g, res("help_request", &op, "unavailable", None), t0 + SEC);
    assert_eq!(hub.view(t0 + SEC).phase, ViewPhase::Sending, "'unavailable' keeps trying");
    hub.tick(t0 + RESEND_AFTER - SEC);
    assert!(sink.take().is_empty());
    hub.tick(t0 + RESEND_AFTER);
    assert_eq!(sent_op_id(&sink.take()[0]), op, "the resend carries the SAME op_id");
    hub.tick(t0 + SEND_GIVE_UP);
    let v = hub.view(t0 + SEND_GIVE_UP);
    assert_eq!((v.phase, v.notice, v.can_request), (ViewPhase::Checking, None, false), "uncertain: no failure claim, no new request");
    assert!(status_text(&v).unwrap().contains("Checking"));
    assert!(!status_text(&v).unwrap().contains("could not"), "never claims non-delivery while the outcome is unknown");
    assert_eq!(hub.request("again", t0 + SEND_GIVE_UP), Err(RequestError::AlreadyOpen), "no fresh creation while unknown");
    assert_eq!(hub.cancel("anything", t0 + SEND_GIVE_UP), Err(CancelError::NothingToCancel));
    // It keeps asking, with the SAME op_id, at the slower uncertain cadence, however long it takes...
    sink.take();
    let mut now = t0 + SEND_GIVE_UP;
    for _ in 0..5 {
        hub.tick(now + UNCERTAIN_RESEND - SEC);
        assert!(sink.take().is_empty());
        now += UNCERTAIN_RESEND;
        hub.tick(now);
        assert_eq!(sent_op_id(&sink.take()[0]), op);
        assert_eq!(hub.view(now).phase, ViewPhase::Checking);
    }
    // ...until an authoritative answer: the lost acknowledgement arrives (the request WAS created).
    hub.on_result(g, res("help_request", &op, "ok", Some(info("r1", "open"))), now);
    let v = hub.view(now);
    assert_eq!((v.phase, v.open_id.as_deref()), (ViewPhase::Open, Some("r1")), "the orphan is adopted and can be cancelled");
    hub.cancel("r1", now).unwrap();
}

#[test]
fn an_uncertain_request_that_turns_out_open_is_found_by_status_too() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    sink.take();
    hub.tick(t0 + SEND_GIVE_UP);
    hub.on_result(g, res("help_status", "", "ok", Some(info("r7", "open"))), t0 + SEND_GIVE_UP);
    assert_eq!(hub.view(t0 + SEND_GIVE_UP).open_id.as_deref(), Some("r7"));
}

#[test]
fn a_cancel_names_the_request_the_guest_was_shown() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    // The menu showed r1; meanwhile r1 expired and the guest (or another menu) opened r2.
    hub.on_result(g, res("help_status", "", "ok", Some(info("r1", "expired"))), t0);
    hub.on_result(g, res("help_status", "", "ok", Some(info("r2", "open"))), t0);
    sink.take();
    assert_eq!(hub.cancel("r1", t0), Err(CancelError::NothingToCancel), "a stale menu cannot cancel the newer request");
    assert!(sink.take().is_empty());
    hub.cancel("r2", t0).unwrap();
    assert_eq!(sink.take(), vec![ClientToServer::HelpCancel { request_id: "r2".into() }]);
}

#[test]
fn a_late_cancel_answer_about_an_earlier_request_does_not_disturb_the_current_one() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.on_result(g, res("help_status", "", "ok", Some(info("r2", "open"))), t0); // r1 gone, r2 open
    hub.cancel("r2", t0).unwrap();
    sink.take();
    // A delayed answer for r1's cancel arrives while r2's cancel is outstanding.
    hub.on_result(g, res("help_cancel", "", "ok", Some(info("r1", "cancelled"))), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.open_id.as_deref()), (ViewPhase::Cancelling, Some("r2")), "r2 untouched, its cancel still outstanding");
    // A delayed not_found cannot be attributed: it must not clear r2, it only asks the server what is true.
    hub.on_result(g, res("help_cancel", "", "not_found", None), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.open_id.as_deref()), (ViewPhase::Open, Some("r2")));
    assert_eq!(sink.take(), vec![ClientToServer::HelpStatus {}], "a not_found triggers a status query instead of settling");
    hub.on_result(g, res("help_status", "", "ok", Some(info("r2", "cancelled"))), t0);
    assert_eq!(hub.view(t0).notice, Some(Notice::Cancelled));
}
#[test]
fn refusal_resets_the_ui_and_shows_it() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    hub.on_result(g, res("help_request", &op, "refused", None), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice), (ViewPhase::Idle, Some(Notice::Refused)));
}

#[test]
fn a_lost_cancel_race_shows_the_state_that_won() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    hub.on_result(g, res("help_cancel", "", "conflict", Some(info("r1", "accepted"))), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice), (ViewPhase::Idle, Some(Notice::Accepted)));
    // A cancel answered "unavailable" can be pressed again.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    hub.on_result(g, res("help_cancel", "", "unavailable", None), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Open);
    hub.cancel("r1", t0).unwrap();
}

#[test]
fn an_unanswered_cancel_is_forgotten_after_a_while() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    hub.tick(t0 + CANCEL_PATIENCE - SEC);
    assert_eq!(hub.view(t0 + CANCEL_PATIENCE - SEC).phase, ViewPhase::Cancelling);
    hub.tick(t0 + CANCEL_PATIENCE);
    assert_eq!(hub.view(t0 + CANCEL_PATIENCE).phase, ViewPhase::Open);
}

#[test]
fn creations_are_limited_to_three_an_hour_and_ten_a_day_like_the_server() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    let mut now = t0;
    // Three acknowledged requests, each cancelled, within the hour.
    for n in 0..CREATIONS_PER_HOUR {
        hub.request("x", now).unwrap();
        let op = sent_op_id(sink.take().last().unwrap());
        hub.on_result(g, res("help_request", &op, "ok", Some(info(&format!("r{n}"), "open"))), now);
        hub.cancel(&format!("r{n}"), now).unwrap();
        hub.on_result(g, res("help_cancel", "", "ok", Some(info(&format!("r{n}"), "cancelled"))), now);
        now += 60 * SEC;
    }
    match hub.request("x", now) {
        Err(RequestError::RateLimited(w)) => {
            assert!(w > Duration::from_secs(3000) && w <= Duration::from_secs(3600), "wait until the oldest ages out: {w:?}")
        }
        other => panic!("the 4th request in an hour must be refused client-side: {other:?}"),
    }
    assert!(!hub.view(now).can_request, "the menu item is disabled while limited");
    assert!(status_text(&hub.view(now)).unwrap().contains("try again later"));
    // An hour after the FIRST one, it is allowed again.
    now = t0 + Duration::from_secs(3600);
    hub.request("x", now).expect("the first creation aged out of the hour window");

    // Ten in a day: spread so the hourly limit never trips.
    let (hub, sink, g) = hub_with(true, t0);
    let mut now = t0;
    for n in 0..CREATIONS_PER_DAY {
        hub.request("x", now).unwrap();
        let op = sent_op_id(sink.take().last().unwrap());
        hub.on_result(g, res("help_request", &op, "ok", Some(info(&format!("d{n}"), "open"))), now);
        hub.on_result(g, res("help_status", "", "ok", Some(info(&format!("d{n}"), "expired"))), now);
        now += Duration::from_secs(50 * 60);
    }
    // 10 creations over ~8 hours; the 11th, still inside the day, is refused.
    assert!(matches!(hub.request("x", now), Err(RequestError::RateLimited(w)) if w > Duration::from_secs(3600)));
    now = t0 + Duration::from_secs(24 * 3600);
    hub.request("x", now).expect("a day later the first aged out");
}

#[test]
fn a_server_limit_blocks_requests_for_its_retry_after() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    let mut r = res("help_request", &op, "limited", None);
    r.retry_after_seconds = 900;
    hub.on_result(g, r, t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice, v.can_request), (ViewPhase::Idle, Some(Notice::Limited), false));
    assert!(matches!(hub.request("x", t0 + Duration::from_secs(899)), Err(RequestError::RateLimited(_))));
    hub.request("x", t0 + Duration::from_secs(900)).unwrap();
}

#[test]
fn messages_are_capped_at_twelve_a_minute_like_signalings_window() {
    let t0 = Instant::now();
    let mut l = Limiter::default();
    for n in 0..MESSAGES_PER_MINUTE {
        assert!(l.message_ok(t0 + Duration::from_millis(n as u64)), "message {n} is within the budget");
    }
    assert!(!l.message_ok(t0 + Duration::from_secs(59)), "the 13th inside one minute is refused");
    assert!(l.message_ok(t0 + Duration::from_secs(61)), "the window slid");
    // Through the hub: a flapping connection (an attach per flap) cannot exceed the budget either.
    let hub = HelpHub::new();
    let mut total = 0usize;
    for _ in 0..40 {
        let sink = Arc::new(RecSink::default());
        hub.attach(sink.clone(), true, t0);
        total += sink.take().len();
    }
    assert_eq!(total, MESSAGES_PER_MINUTE, "exactly the per-minute budget leaves, the rest is withheld");
}
#[test]
fn a_dead_connection_fails_the_request_without_changing_state() {
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(true, t0);
    *sink.dead.lock().unwrap() = true;
    assert_eq!(hub.request("x", t0), Err(RequestError::SendFailed));
    assert_eq!(hub.view(t0).phase, ViewPhase::Idle);
}

#[test]
fn notices_lapse() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.on_result(g, res("help_status", "", "ok", Some(info("r1", "expired"))), t0);
    assert_eq!(hub.view(t0 + NOTICE_TTL - SEC).notice, Some(Notice::Expired));
    assert_eq!(hub.view(t0 + NOTICE_TTL).notice, None);
}

#[test]
fn the_tray_is_told_only_when_the_visible_state_changes() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    hub.set_on_change(Arc::new(move || {
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    hub.request("x", t0).unwrap();
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    let op = sent_op_id(sink.take().last().unwrap());
    hub.on_result(g, res("help_request", "stale", "ok", Some(info("r", "open"))), t0);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1, "an ignored answer changes nothing");
    hub.on_result(g, res("help_request", &op, "ok", Some(info("r1", "open"))), t0);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn notes_are_cleaned() {
    assert_eq!(sanitize_note("  hello\tworld\r\nbye  "), "hello world  bye");
    assert_eq!(sanitize_note("a\u{0007}b\u{200B}c\u{202E}d\u{FEFF}"), "abcd");
    assert_eq!(sanitize_note(&"\u{00e9}".repeat(500)).chars().count(), MAX_NOTE_CHARS);
    assert_eq!(sanitize_note("   "), "");
}

#[test]
fn tooltip_follows_the_state() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    let base = "DeskRally \u{2014} Ready for support";
    assert_eq!(tooltip_text(&hub.view(t0), base), base);
    open_request(&hub, &sink, g, t0);
    assert!(tooltip_text(&hub.view(t0), base).ends_with("waiting for a technician"));
}

// ── Tray decision logic ─────────────────────────────────────────────────────────────────────────────────────────────

/// A UI double: scripted answers, and a record of every call, so the tests prove what was (not) shown.
struct FakeUi {
    menu_answer: Cell<(MenuChoice, bool)>,
    dialog_answer: RefCell<(Option<String>, bool)>,
    menus_shown: Cell<u32>,
    dialogs_shown: Cell<u32>,
    abouts_shown: Cell<u32>,
    /// The `available` flag of every view the menu was shown for.
    menu_available: Cell<Option<bool>>,
}

impl FakeUi {
    fn new(menu: (MenuChoice, bool), dialog: (Option<&str>, bool)) -> Self {
        Self {
            menu_answer: Cell::new(menu),
            dialog_answer: RefCell::new((dialog.0.map(str::to_string), dialog.1)),
            menus_shown: Cell::new(0),
            dialogs_shown: Cell::new(0),
            abouts_shown: Cell::new(0),
            menu_available: Cell::new(None),
        }
    }
}

impl HelpUi for FakeUi {
    fn menu(&self, view: &HelpView) -> (MenuChoice, bool) {
        self.menus_shown.set(self.menus_shown.get() + 1);
        self.menu_available.set(Some(view.available));
        self.menu_answer.get()
    }
    fn note_dialog(&self) -> (Option<String>, bool) {
        self.dialogs_shown.set(self.dialogs_shown.get() + 1);
        self.dialog_answer.borrow().clone()
    }
    fn about(&self) {
        self.abouts_shown.set(self.abouts_shown.get() + 1);
    }
}

#[test]
fn without_the_feature_the_menu_offers_only_about_and_nothing_can_be_requested() {
    // Menu wave 11: the icon is never dead, but without `help_request_v1` (an old server, a retired machine, no
    // connection yet) nothing about help can happen, whatever the menu returns.
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(false, t0);
    sink.take();
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (Some("x"), true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::UnavailableDismissed);
    assert_eq!(ui.menus_shown.get(), 1, "the menu opens (it says why help is unavailable)");
    assert_eq!(ui.menu_available.get(), Some(false), "and is built for an unavailable view, so it has no help items");
    assert_eq!(ui.dialogs_shown.get(), 0, "no note dialog");
    assert!(sink.take().is_empty());
    let ui = FakeUi::new((MenuChoice::CancelRequest, true), (None, true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::UnavailableDismissed);
    assert!(sink.take().is_empty());
    // A never-attached hub (no connection yet) likewise.
    let hub = HelpHub::new();
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (Some("x"), true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::UnavailableDismissed);
    assert_eq!(ui.dialogs_shown.get(), 0);
}

#[test]
fn about_opens_from_either_menu_and_never_requests_or_cancels() {
    let t0 = Instant::now();
    for available in [false, true] {
        let (hub, sink, _g) = hub_with(available, t0);
        sink.take();
        // Read-only, so it opens even when the click was not the guest's own (nothing is sent either way).
        for by_guest in [true, false] {
            let ui = FakeUi::new((MenuChoice::About, by_guest), (Some("x"), true));
            assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::About, "available={available} by_guest={by_guest}");
            assert_eq!(ui.abouts_shown.get(), 1);
            assert_eq!(ui.dialogs_shown.get(), 0);
            assert!(sink.take().is_empty());
        }
    }
    // An open request is not touched by About.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    let ui = FakeUi::new((MenuChoice::About, true), (None, true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::About);
    assert!(sink.take().is_empty());
    assert_eq!(hub.view(t0).phase, ViewPhase::Open);
}

#[test]
fn injected_input_cannot_choose_the_menu_item_but_real_input_can() {
    let t0 = Instant::now();
    // Negative: the technician's injected click selects "Request help...".
    let (hub, sink, _g) = hub_with(true, t0);
    sink.take();
    let ui = FakeUi::new((MenuChoice::RequestHelp, false), (Some("x"), true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::InjectedIgnored);
    assert_eq!(ui.dialogs_shown.get(), 0, "no dialog opens for an injected choice");
    assert!(sink.take().is_empty());
    assert_eq!(hub.view(t0).phase, ViewPhase::Idle);
    // Positive control: the same flow with the guest's own input goes through.
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (Some("printer"), true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::Requested);
    assert_eq!(ui.dialogs_shown.get(), 1);
    assert!(matches!(&sink.take()[..], [ClientToServer::HelpRequest { note, .. }] if note == "printer"));
}

#[test]
fn injected_input_cannot_press_send_in_the_dialog() {
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(true, t0);
    sink.take();
    // The guest opens the dialog; an injected click presses Send.
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (Some("from the technician"), false));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::InjectedIgnored);
    assert!(sink.take().is_empty(), "provenance is checked on the Send action, not only on opening the menu (H-C7)");
    assert_eq!(hub.view(t0).phase, ViewPhase::Idle);
    // Cancelling the dialog sends nothing either.
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (None, true));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::DialogCancelled);
    assert!(sink.take().is_empty());
}

#[test]
fn injected_input_cannot_cancel_a_request() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    let ui = FakeUi::new((MenuChoice::CancelRequest, false), (None, false));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::InjectedIgnored);
    assert!(sink.take().is_empty());
    assert_eq!(hub.view(t0).phase, ViewPhase::Open);
    let ui = FakeUi::new((MenuChoice::CancelRequest, true), (None, false));
    assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::CancelSent);
    assert_eq!(sink.take(), vec![ClientToServer::HelpCancel { request_id: "r1".into() }]);
}

#[test]
fn dismissing_the_menu_does_nothing_whoever_pressed() {
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(true, t0);
    sink.take();
    for by_guest in [true, false] {
        let ui = FakeUi::new((MenuChoice::Dismissed, by_guest), (None, false));
        assert_eq!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::Dismissed);
    }
    assert!(sink.take().is_empty());
}

#[test]
fn the_dialog_is_not_offered_while_a_request_is_in_flight_or_limited() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    let ui = FakeUi::new((MenuChoice::RequestHelp, true), (Some("x"), true));
    assert!(matches!(run_tray_menu(&hub, &ui, || t0), TrayOutcome::RequestFailed(RequestError::AlreadyOpen)));
    assert_eq!(ui.dialogs_shown.get(), 0);
}

// ── The dialog's Send is authenticated at the action (complete genuine gestures) ──────────────────────────────────────

const VK_SP: u32 = 0x20;
const VK_EN: u32 = 0x0D;

fn click_on_send(a: &mut SendAuth, t: Instant) {
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t);
}

#[test]
fn a_forged_send_command_after_genuine_typing_is_not_accepted() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    // The guest types a note, a Space among it, with the focus in the note box: not an activation of Send.
    for _ in 0..2 {
        a.note_key_down(VK_SP, false, t0);
        a.note_key_up(VK_SP, false, t0);
    }
    assert!(!a.authorize(t0 + Duration::from_millis(10)), "a posted command is not an activation");
    assert!(!SendAuth::default().authorize(t0), "nor is one with no input at all");
}

#[test]
fn a_genuine_click_on_send_or_enter_or_space_on_the_focused_button_is_accepted_once() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    click_on_send(&mut a, t0);
    assert!(a.authorize(t0 + Duration::from_millis(20)), "positive control: a real click on Send");
    assert!(!a.authorize(t0 + Duration::from_millis(30)), "single-use: a second command finds nothing");
    // Space activates on its key UP: down AND up of the same key.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    assert!(!a.authorize(t0 + Duration::from_millis(50)), "Space is not an activation until it is released");
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, true, t0 + Duration::from_millis(100));
    assert!(a.authorize(t0 + Duration::from_millis(120)), "Space down AND up with Send focused");
}

#[test]
fn dragging_onto_send_with_a_press_elsewhere_is_not_a_click() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    a.note_mouse_down(true, false); // pressed in the note box (or anywhere but Send)
    a.note_mouse_up(true, true, t0); // dragged and released over Send
    assert!(!a.authorize(t0 + Duration::from_millis(5)), "a forged command after the drag-release finds nothing");
    // Pressed on Send but released elsewhere is not a click either.
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, false, t0);
    assert!(!a.authorize(t0));
    // A release with no press seen at all.
    let mut a = SendAuth::default();
    a.note_mouse_up(true, true, t0);
    assert!(!a.authorize(t0));
}

#[test]
fn any_other_genuine_input_clears_a_gesture_or_a_completed_activation() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    // Right / middle button down elsewhere or on Send clears it.
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    a.note_mouse_down(false, true);
    a.note_mouse_up(true, true, t0);
    assert!(!a.authorize(t0));
    // A completed click, then an intervening press elsewhere: cleared before the command lands.
    let mut a = SendAuth::default();
    click_on_send(&mut a, t0);
    a.note_mouse_down(true, false);
    assert!(!a.authorize(t0 + ms(5)));
    // A completed click, then a right-button release.
    let mut a = SendAuth::default();
    click_on_send(&mut a, t0);
    a.note_mouse_up(false, true, t0 + ms(2));
    assert!(!a.authorize(t0 + ms(5)));
    // A completed key activation, then typing.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, true, t0);
    a.note_key_down(0x41, false, t0);
    assert!(!a.authorize(t0 + ms(5)));
    // Mid-gesture: another key between the activation key's down and up, and a different key's release.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_down(0x41, false, t0);
    a.note_key_up(VK_SP, true, t0);
    assert!(!a.authorize(t0 + ms(5)));
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_EN, true, t0);
    assert!(!a.authorize(t0 + ms(5)), "Enter's release does not complete Space's press");
    // A key UP with no down seen (focus moved onto Send by Tab while Space was held, say).
    let mut a = SendAuth::default();
    a.note_key_up(VK_SP, true, t0);
    assert!(!a.authorize(t0));
}

// A quick Enter (down and up within a millisecond) reaches the hooks before the message loop dequeues the DOWN: the release of Enter itself
// must not discard the record, or Enter on a focused Send failed about half the time in the VM (2026-11-04).
#[test]
fn enters_own_release_before_the_message_loop_sees_the_down_does_not_cancel_it() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let ok = keydown_lparam(ENTER_SCAN, false);
    let mut a = recorded(t0, 7);
    a.note_key_up(VK_EN, true, t0 + ms(1)); // the hook's release arrives first
    assert!(a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "the genuine Enter DOWN still authorizes");
    assert!(!a.begin_enter_dispatch(t0 + ms(3), 7, ok, HW), "single use");
    // Any OTHER key's release still clears it, and so does a stale record.
    let mut a = recorded(t0, 7);
    a.note_key_up(0x41, false, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW));
    let mut a = recorded(t0, 7);
    a.note_key_up(VK_EN, true, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ACTIVATION_FRESH + ms(2), 7, ok, HW), "lapses");
    // Not a way to authorize a forgery: a posted look-alike with every field copied is still refused after the release.
    let posted: &dyn Fn() -> bool = &|| false;
    let mut a = recorded(t0, 7);
    a.note_key_up(VK_EN, true, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, posted));
}

#[test]
fn a_stale_gesture_or_any_injected_press_blocks_send() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    click_on_send(&mut a, t0);
    assert!(!a.authorize(t0 + ACTIVATION_FRESH + Duration::from_millis(1)), "a stale activation lapses");
    let mut a = SendAuth::default();
    click_on_send(&mut a, t0);
    a.note_injected(); // a technician's injected press anywhere in the dialog
    assert!(!a.authorize(t0 + Duration::from_millis(10)));
    click_on_send(&mut a, t0 + Duration::from_millis(20));
    assert!(!a.authorize(t0 + Duration::from_millis(30)), "the taint lasts for the whole dialog");
}
// ── cancel_of correlation and the replay window ───────────────────────────────────────────────────────────────────────

fn cancel_res(outcome: &str, cancel_of: &str, request: Option<HelpRequestInfo>) -> HelpResult {
    let mut r = res("help_cancel", "", outcome, request);
    r.cancel_of = cancel_of.into();
    r
}

#[test]
fn with_cancel_of_every_cancel_answer_is_correlated_including_not_found() {
    let t0 = Instant::now();
    // A not_found about ANOTHER request settles nothing of the current one.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.on_result(g, res("help_status", "", "ok", Some(info("r2", "open"))), t0);
    hub.cancel("r2", t0).unwrap();
    sink.take();
    hub.on_result(g, cancel_res("not_found", "r1", None), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.open_id.as_deref()), (ViewPhase::Cancelling, Some("r2")), "a delayed answer about r1 changes nothing");
    assert!(sink.take().is_empty(), "and with cancel_of there is no need to query");
    // A not_found about the CURRENT request settles it (and nothing else).
    hub.on_result(g, cancel_res("not_found", "r2", None), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.notice), (ViewPhase::Idle, Some(Notice::Cancelled)));
    // ok / conflict for the current request, and for another one.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    hub.on_result(g, cancel_res("ok", "rX", Some(info("rX", "cancelled"))), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Cancelling, "an answer about rX is not about r1");
    hub.on_result(g, cancel_res("conflict", "r1", Some(info("r1", "accepted"))), t0);
    assert_eq!(hub.view(t0).notice, Some(Notice::Accepted));
    // unavailable for the current one lets the guest press Cancel again.
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    hub.on_result(g, cancel_res("unavailable", "r1", None), t0);
    assert_eq!(hub.view(t0).phase, ViewPhase::Open);
}

#[test]
fn without_cancel_of_an_older_signaling_falls_back_to_a_status_query_and_settles_nothing() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    open_request(&hub, &sink, g, t0);
    hub.cancel("r1", t0).unwrap();
    sink.take();
    hub.on_result(g, res("help_cancel", "", "not_found", None), t0);
    let v = hub.view(t0);
    assert_eq!((v.phase, v.open_id.as_deref()), (ViewPhase::Open, Some("r1")));
    assert_eq!(sink.take(), vec![ClientToServer::HelpStatus {}]);
}

#[test]
fn replays_of_the_same_op_id_stop_before_the_servers_24_hour_dedup_window() {
    let t0 = Instant::now();
    let (hub, sink, g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    let op = sent_op_id(sink.take().last().unwrap());
    // Uncertain for hours: every replay inside the window is the same-op_id create.
    let mut now = t0;
    let mut creates = 0;
    let mut statuses = 0;
    while now < t0 + Duration::from_secs(23 * 3600) {
        now += UNCERTAIN_RESEND;
        hub.tick(now);
        for m in sink.take() {
            match m {
                ClientToServer::HelpRequest { op_id, .. } => {
                    assert_eq!(op_id, op);
                    assert!(now - t0 < REPLAY_WINDOW, "a create was replayed at {:?}, past the replay window", now - t0);
                    creates += 1;
                }
                ClientToServer::HelpStatus {} => {
                    assert!(now - t0 >= REPLAY_WINDOW, "status-only is for after the window");
                    statuses += 1;
                }
                other => panic!("{other:?}"),
            }
        }
    }
    assert!(creates > 100 && statuses > 10, "replays before the window, status-only after (creates {creates}, statuses {statuses})");
    assert_eq!(hub.view(now).phase, ViewPhase::Checking, "still uncertain: no failure is claimed");
    // A status that finds no open request after the window ends the uncertainty (any request we made closed long ago).
    hub.on_result(g, res("help_status", "", "ok", None), now);
    let v = hub.view(now);
    assert_eq!((v.phase, v.can_request), (ViewPhase::Idle, true));
    assert_eq!(v.notice, Some(Notice::Expired));
}

#[test]
fn past_the_window_a_reconnect_asks_status_not_create_and_an_open_request_is_still_adopted() {
    let t0 = Instant::now();
    let (hub, sink, _g) = hub_with(true, t0);
    hub.request("x", t0).unwrap();
    sink.take();
    let later = t0 + REPLAY_WINDOW + SEC;
    let sink2 = Arc::new(RecSink::default());
    let g2 = hub.attach(sink2.clone(), true, later);
    assert_eq!(sink2.take(), vec![ClientToServer::HelpStatus {}], "no create after the window, even on reconnect");
    hub.on_result(g2, res("help_status", "", "ok", Some(info("r5", "open"))), later);
    assert_eq!(hub.view(later).open_id.as_deref(), Some("r5"));
}
// ── Enter: bound to the genuine key press itself (hook time + scan code), never to a time window ─────────────────────

/// `WM_KEYDOWN` lParam for scan code `scan`, with the repeat flag (bit 30) as given.
fn keydown_lparam(scan: u32, repeat: bool) -> isize {
    ((scan << 16) | 1 | if repeat { 1 << 30 } else { 0 }) as isize
}

const ENTER_SCAN: u32 = 0x1C;

/// Windows says: from the hardware.
const HW: &dyn Fn() -> bool = &|| true;

fn recorded(t0: Instant, time: u32) -> SendAuth {
    let mut a = SendAuth::default();
    a.note_key_down(VK_EN, true, t0);
    a.note_enter_down(t0, time, ENTER_SCAN);
    a
}

#[test]
fn a_genuine_enter_is_matched_by_time_and_scan_code_once() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let mut a = recorded(t0, 5000);
    // The hook alone authorizes NOTHING: a forged WM_COMMAND finds no authorization, however soon it arrives.
    assert!(!a.authorize(t0 + ms(1)));
    assert!(a.begin_enter_dispatch(t0 + ms(2), 5000, keydown_lparam(ENTER_SCAN, false), HW), "the genuine message matches its own hook event");
    assert!(!a.begin_enter_dispatch(t0 + ms(3), 5000, keydown_lparam(ENTER_SCAN, false), HW), "single use");
    // Enter pressed while the NOTE BOX has focus (activating = false) records nothing at the hook.
    let mut a = SendAuth::default();
    a.note_key_down(VK_EN, false, t0);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 5000, keydown_lparam(ENTER_SCAN, false), HW));
    assert!(!SendAuth::default().begin_enter_dispatch(t0, 0, keydown_lparam(ENTER_SCAN, false), HW), "a posted WM_KEYDOWN with no genuine Enter");
}

#[test]
fn a_forged_enter_queued_ahead_of_the_genuine_one_does_not_consume_the_record() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let mut a = recorded(t0, 5000);
    // Forged messages: a different time, a different scan code, a repeat. None consumes, none authorizes.
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 4999, keydown_lparam(ENTER_SCAN, false), HW), "different time");
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 5000, keydown_lparam(0x00, false), HW), "different scan code (a PostMessage with lParam 0)");
    assert!(!a.begin_enter_dispatch(t0 + ms(3), 5000, keydown_lparam(ENTER_SCAN, true), HW), "a repeat");
    // The genuine one, arriving after them, still authorizes.
    assert!(a.begin_enter_dispatch(t0 + ms(4), 5000, keydown_lparam(ENTER_SCAN, false), HW));
}

#[test]
fn an_enter_dispatch_keeps_every_anti_forgery_property() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let ok = keydown_lparam(ENTER_SCAN, false);
    let mut a = recorded(t0, 7);
    a.note_key_down(0x41, false, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "another key clears it");
    let mut a = recorded(t0, 7);
    a.note_mouse_down(true, false);
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "a press elsewhere clears it");
    let mut a = recorded(t0, 7);
    a.note_mouse_up(false, true, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "a release clears it");
    let mut a = recorded(t0, 7);
    a.note_key_up(0x41, false, t0 + ms(1));
    assert!(!a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "a key release clears it");
    let mut a = recorded(t0, 7);
    a.note_injected();
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, ok, HW), "an injected press voids it");
    a.note_key_down(VK_EN, true, t0 + ms(2));
    a.note_enter_down(t0 + ms(2), 8, ENTER_SCAN);
    assert!(!a.begin_enter_dispatch(t0 + ms(3), 8, ok, HW), "the taint lasts for the whole dialog");
    let mut a = recorded(t0, 7);
    assert!(!a.begin_enter_dispatch(t0 + ACTIVATION_FRESH + ms(1), 7, ok, HW), "stale: the message never arrived");
}

#[test]
fn a_posted_enter_with_identical_time_scan_and_repeat_neither_consumes_nor_authorizes() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let lp = keydown_lparam(ENTER_SCAN, false);
    let posted: &dyn Fn() -> bool = &|| false; // IMO_UNAVAILABLE: a PostMessage look-alike
    let mut a = recorded(t0, 5000);
    // The forgery copies everything the message carries and is dequeued BEFORE the genuine one: refused, record untouched.
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 5000, lp, posted));
    assert!(!a.authorize(t0 + ms(2)), "and authorizes nothing");
    // The genuine (IMO_HARDWARE) one then authorizes, once.
    assert!(a.begin_enter_dispatch(t0 + ms(3), 5000, lp, HW));
    assert!(!a.begin_enter_dispatch(t0 + ms(4), 5000, lp, HW));
}

#[test]
fn an_api_failure_fails_closed_for_enter_but_not_for_mouse_or_space() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let broken: &dyn Fn() -> bool = &|| false; // GetCurrentInputMessageSource failed
    let mut a = recorded(t0, 9);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 9, keydown_lparam(ENTER_SCAN, false), broken));
    // The hook-based mouse and Space gestures do not depend on the query.
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0);
    assert!(a.authorize(t0 + ms(1)));
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, true, t0 + ms(1));
    assert!(a.authorize(t0 + ms(2)));
}

#[test]
fn space_and_left_button_releases_to_send_that_are_not_from_the_input_queue_cannot_authorize_send() {
    let real: &dyn Fn() -> bool = &|| true;
    let posted: &dyn Fn() -> bool = &|| false;
    const WM_KEYUP: u32 = 0x0101;
    const WM_SYSKEYUP: u32 = 0x0105;
    const WM_LBUTTONUP: u32 = 0x0202;
    for (m, w) in [(WM_KEYUP, 0x20usize), (WM_SYSKEYUP, 0x20), (WM_LBUTTONUP, 0)] {
        assert!(SendAuth::unvouched_send_release(m, w, true, posted), "message {m:#x} to Send from a posted source is unvouched (Send refused, message still delivered)");
        assert!(!SendAuth::unvouched_send_release(m, w, true, real), "message {m:#x} to Send from the input queue is vouched");
    }
    // Everything else is never touched by this rule, whatever the source says (the query is not even needed).
    for (m, w) in [(WM_KEYUP, 0x41usize), (0x0100, 0x20), (0x0201, 0), (0x0200, 0)] {
        assert!(!SendAuth::unvouched_send_release(m, w, true, posted), "message {m:#x}/{w:#x} is out of scope");
    }
}

// 2026-11-04 (Ed, agent 1.3.19): the provenance rule dropped EVERY left-button release that did not report IMO_HARDWARE, Cancel's included,
// so a guest whose pointer goes through remapping software (IMO_INJECTED) could not dismiss the dialog by clicking.
#[test]
fn a_release_addressed_to_anything_but_send_is_never_filtered_by_provenance() {
    let posted: &dyn Fn() -> bool = &|| false;
    let broken: &dyn Fn() -> bool = &|| false; // the provenance query failed
    const WM_KEYUP: u32 = 0x0101;
    const WM_LBUTTONUP: u32 = 0x0202;
    for src in [posted, broken] {
        assert!(!SendAuth::unvouched_send_release(WM_LBUTTONUP, 0, false, src), "Cancel / note box / caption click release");
        assert!(!SendAuth::unvouched_send_release(WM_KEYUP, 0x20, false, src), "Space released while Cancel has the focus");
    }
    // The positive control: the same message addressed to Send IS unvouched when it is not real input.
    assert!(SendAuth::unvouched_send_release(WM_LBUTTONUP, 0, true, posted));
}

#[test]
fn only_this_products_own_injection_taints_the_dialog_and_a_lower_integrity_one_is_merely_not_the_guests() {
    use crate::input::RMT_INJECTED_TAG;
    assert_eq!(SendAuth::classify_hook_event(RMT_INJECTED_TAG, false), HookEvent::Product, "a technician's session (the product's own tag)");
    assert_eq!(SendAuth::classify_hook_event(RMT_INJECTED_TAG, true), HookEvent::Product, "the tag wins over the integrity flag");
    assert_eq!(SendAuth::classify_hook_event(0, true), HookEvent::LowerIntegrity, "an injection by a lower-integrity process");
    // A guest's remapper, KVM or on-screen keyboard: injected by the OS's account, carries its own (or no) extra info.
    for extra in [0usize, 1, 0xDEAD_BEEF, RMT_INJECTED_TAG + 1, RMT_INJECTED_TAG - 1] {
        assert_eq!(SendAuth::classify_hook_event(extra, false), HookEvent::Guest, "extra info {extra:#x} is third-party software, not a technician");
    }
}

// The end-to-end wiring the hooks do, on SendAuth: a remapped (OS-injected, untagged) click on Send still completes a gesture, while the same
// click after any tagged event does not.
#[test]
fn a_remapped_click_on_send_authorizes_but_a_tagged_one_never_does() {
    use crate::input::RMT_INJECTED_TAG;
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let feed = |a: &mut SendAuth, extra: usize, down: bool, at: Instant| {
        if !a.admit_hook_event(SendAuth::classify_hook_event(extra, false)) {
        } else if down {
            a.note_mouse_down(true, true);
        } else {
            a.note_mouse_up(true, true, at);
        }
    };
    let mut a = SendAuth::default();
    feed(&mut a, 0, true, t0);
    feed(&mut a, 0, false, t0 + ms(30));
    assert!(a.authorize(t0 + ms(40)), "an untagged OS-injected press and release over Send");

    let mut a = SendAuth::default();
    feed(&mut a, RMT_INJECTED_TAG, true, t0);
    feed(&mut a, RMT_INJECTED_TAG, false, t0 + ms(30));
    assert!(!a.authorize(t0 + ms(40)), "the technician's tagged click");
    // And the taint is for the whole dialog: the guest's own click right after it does not send either.
    feed(&mut a, 0, true, t0 + ms(50));
    feed(&mut a, 0, false, t0 + ms(80));
    assert!(!a.authorize(t0 + ms(90)));
}

// Codex release review (1.3.20): the lower-integrity flag names the injector's integrity, not a technician. A guest's own lower-integrity
// remapper or accessibility tool injects anywhere on the desktop, and latching that disabled Send for the dialog's whole life. Such an event
// voids whatever gesture it interrupts (mouse, Space or Enter), and the guest's next genuine gesture still sends.
#[test]
fn a_lower_integrity_injection_voids_the_gesture_it_interrupts_but_the_next_genuine_one_sends() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let low = SendAuth::classify_hook_event(0, true);
    assert_eq!(low, HookEvent::LowerIntegrity);

    // Mouse: between press and release, and between release and command.
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    assert!(!a.admit_hook_event(low), "not recorded as part of a gesture");
    a.note_mouse_up(true, true, t0);
    assert!(!a.authorize(t0 + ms(1)), "the interrupted click does not send");
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0 + ms(2));
    a.admit_hook_event(low);
    assert!(!a.authorize(t0 + ms(3)), "a completed click it follows is void too");
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0 + ms(4));
    assert!(a.authorize(t0 + ms(5)), "the guest's next genuine click sends");

    // Space.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.admit_hook_event(low);
    a.note_key_up(VK_SP, true, t0 + ms(1));
    assert!(!a.authorize(t0 + ms(2)));
    a.note_key_down(VK_SP, true, t0 + ms(3));
    a.note_key_up(VK_SP, true, t0 + ms(4));
    assert!(a.authorize(t0 + ms(5)), "the next genuine Space sends");

    // Enter.
    let ok = keydown_lparam(ENTER_SCAN, false);
    let mut a = recorded(t0, 7);
    a.admit_hook_event(low);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, ok, HW), "the interrupted Enter does not send");
    a.note_key_down(VK_EN, true, t0 + ms(2));
    a.note_enter_down(t0 + ms(2), 8, ENTER_SCAN);
    assert!(a.begin_enter_dispatch(t0 + ms(3), 8, ok, HW), "the next genuine Enter sends");
}

// 2026-11-04 (Ed, agent 1.3.19): the loop dropped a Send-bound release it could not vouch for, so the button kept the mouse capture, looked
// pressed and swallowed every later click. Provenance must never drop anything: only this product's tag does.
#[test]
fn the_loop_drops_only_tagged_input_and_a_release_to_send_is_always_delivered() {
    let real: &dyn Fn() -> bool = &|| true;
    let posted: &dyn Fn() -> bool = &|| false;
    const WM_KEYUP: u32 = 0x0101;
    const WM_LBUTTONDOWN: u32 = 0x0201;
    const WM_LBUTTONUP: u32 = 0x0202;
    const WM_CHAR: u32 = 0x0102;
    for (m, w) in [(WM_LBUTTONUP, 0usize), (WM_KEYUP, 0x20)] {
        assert_eq!(SendAuth::pump_step(m, w, false, true, posted), PumpStep::SendRelease { vouched: false }, "{m:#x} to Send, unvouched");
        assert_eq!(SendAuth::pump_step(m, w, false, true, real), PumpStep::SendRelease { vouched: true }, "{m:#x} to Send, real");
        assert_eq!(SendAuth::pump_step(m, w, false, false, posted), PumpStep::Deliver, "{m:#x} elsewhere");
    }
    // Typing, other keys' releases and presses are never provenance-checked.
    assert_eq!(SendAuth::pump_step(WM_CHAR, 0x61, false, false, posted), PumpStep::Deliver);
    assert_eq!(SendAuth::pump_step(WM_KEYUP, 0x41, false, true, posted), PumpStep::Deliver);
    assert_eq!(SendAuth::pump_step(WM_LBUTTONDOWN, 0, false, true, posted), PumpStep::Deliver);
    // The technician's tagged input is the only thing dropped (the positive control).
    for m in [WM_LBUTTONDOWN, WM_CHAR, WM_KEYUP] {
        assert_eq!(SendAuth::pump_step(m, 0x20, true, true, real), PumpStep::Drop, "tagged {m:#x}");
    }
    // ...except a tagged left-button RELEASE, delivered by design (`guest_window::is_mouse_actuator_message`) so a button lets go of the
    // capture; it cannot send, because the hooks taint the dialog on the tagged press (`authorize` then refuses).
    assert_eq!(SendAuth::pump_step(WM_LBUTTONUP, 0, true, true, real), PumpStep::SendRelease { vouched: true });
}

// Codex (2026-11-04): a WM_LBUTTONUP or WM_COMMAND SENT straight to the window procedure never passes through the loop, so a mouse/Space
// gesture must authorize Send only inside the loop's dispatch of a vouched release, and a command arriving any other way must not even
// consult (or consume) the record.
#[test]
fn a_mouse_or_space_gesture_authorizes_send_only_inside_a_vouched_release_dispatch() {
    let calls = Cell::new(0);
    let mut yes = || {
        calls.set(calls.get() + 1);
        true
    };
    assert!(!SendAuth::send_command_allowed(true, false, false, &mut yes), "a posted or sent command outside any vouched release");
    assert_eq!(calls.get(), 0, "the record is not consulted (or consumed) outside a vouched release dispatch");
    assert!(!SendAuth::send_command_allowed(false, false, true, &mut yes), "not from the Send button");
    assert!(!SendAuth::send_command_allowed(false, true, false, &mut yes), "not from the Send button, even in an Enter dispatch");
    assert_eq!(calls.get(), 0);
    assert!(SendAuth::send_command_allowed(true, true, false, &mut yes), "genuine Enter");
    assert_eq!(calls.get(), 0, "Enter does not need the mouse record");
    assert!(SendAuth::send_command_allowed(true, false, true, &mut yes), "vouched release with a completed genuine gesture");
    assert_eq!(calls.get(), 1);
    let mut no = || false;
    assert!(!SendAuth::send_command_allowed(true, false, true, &mut no), "vouched release but no gesture (or a tainted dialog)");
}

// A posted release dequeued ahead of the guest's real one takes its place (the button lets go of the capture and the real release then
// produces no click), so the completed gesture must not stay usable by a forged WM_COMMAND for the freshness window.
#[test]
fn voiding_after_a_send_release_leaves_no_gesture_a_forged_command_could_use() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0);
    a.void_activation();
    assert!(!a.authorize(t0 + Duration::from_millis(10)));
    // The guest's next genuine click still works.
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0 + Duration::from_millis(500));
    assert!(a.authorize(t0 + Duration::from_millis(510)));
}

// ── Refusal reasons (help_diag): the typed twin of every gate decision ───────────────────────────────────────────

mod refusal_reasons {
    use super::*;
    use crate::help_diag::{EnterRefusal, GestureRefusal, HookInfo, LineContext, Refusal, Via};

    const NO_HW: &dyn Fn() -> bool = &|| false;
    const RMT_TAG: usize = crate::input::RMT_INJECTED_TAG;

    #[test]
    fn authorize_names_why_it_refused() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut a = SendAuth::default();
        assert_eq!(a.authorize_why(t0), Err(GestureRefusal::NoRecord));
        click_on_send(&mut a, t0);
        assert_eq!(a.authorize_why(t0 + ms(10)), Ok(()));
        click_on_send(&mut a, t0);
        assert_eq!(a.authorize_why(t0 + ACTIVATION_FRESH + ms(500)), Err(GestureRefusal::Stale { age_ms: 2500 }));
        let mut a = SendAuth::default();
        click_on_send(&mut a, t0);
        a.note_injected();
        assert_eq!(a.authorize_why(t0 + ms(1)), Err(GestureRefusal::Tainted));
        // Tainted wins even over a fresh completed gesture recorded afterwards.
        click_on_send(&mut a, t0);
        assert_eq!(a.authorize_why(t0 + ms(2)), Err(GestureRefusal::Tainted));
    }

    #[test]
    fn enter_names_which_field_refused() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let lp = keydown_lparam(ENTER_SCAN, false);
        assert_eq!(SendAuth::default().begin_enter_dispatch_why(t0, 5000, lp, HW), Err(EnterRefusal::NoRecord));
        assert_eq!(recorded(t0, 5000).begin_enter_dispatch_why(t0 + ms(1), 5001, lp, HW), Err(EnterRefusal::TimeMismatch { msg: 5001, hook: 5000 }));
        assert_eq!(
            recorded(t0, 5000).begin_enter_dispatch_why(t0 + ms(1), 5000, keydown_lparam(0x00, false), HW),
            Err(EnterRefusal::ScanMismatch)
        );
        assert_eq!(recorded(t0, 5000).begin_enter_dispatch_why(t0 + ms(1), 5000, keydown_lparam(ENTER_SCAN, true), HW), Err(EnterRefusal::Repeat));
        assert_eq!(recorded(t0, 5000).begin_enter_dispatch_why(t0 + ms(1), 5000, lp, NO_HW), Err(EnterRefusal::OriginNotReal));
        assert_eq!(
            recorded(t0, 5000).begin_enter_dispatch_why(t0 + ACTIVATION_FRESH + ms(7), 5000, lp, HW),
            Err(EnterRefusal::Stale { age_ms: 2007 })
        );
        // A record made AFTER the dialog was tainted (a guest-looking Enter once a technician's input was seen).
        let mut a = SendAuth::default();
        a.note_injected();
        a.note_key_down(VK_EN, true, t0);
        a.note_enter_down(t0, 5000, ENTER_SCAN);
        assert_eq!(a.begin_enter_dispatch_why(t0 + ms(1), 5000, lp, HW), Err(EnterRefusal::Tainted));
        // And the success case still consumes exactly once.
        let mut a = recorded(t0, 5000);
        assert_eq!(a.begin_enter_dispatch_why(t0 + ms(1), 5000, lp, HW), Ok(()));
        assert_eq!(a.begin_enter_dispatch_why(t0 + ms(2), 5000, lp, HW), Err(EnterRefusal::NoRecord));
    }

    #[test]
    fn the_command_decision_names_its_failure_and_matches_the_bool() {
        let mut ok = || Ok(());
        let mut no = || Err(GestureRefusal::Stale { age_ms: 9 });
        assert_eq!(SendAuth::send_command_decision(false, true, true, &mut ok), Err(Refusal::CommandNotFromSend));
        assert_eq!(SendAuth::send_command_decision(true, false, false, &mut ok), Err(Refusal::CommandOutsideDispatch));
        assert_eq!(SendAuth::send_command_decision(true, false, true, &mut no), Err(Refusal::Gesture(GestureRefusal::Stale { age_ms: 9 })));
        assert_eq!(SendAuth::send_command_decision(true, true, false, &mut no), Ok(()));
        assert_eq!(SendAuth::send_command_decision(true, false, true, &mut ok), Ok(()));
        // The bool is derived from the decision: every combination agrees.
        for from_button in [false, true] {
            for by_enter in [false, true] {
                for in_release in [false, true] {
                    for grant in [false, true] {
                        let mut yes_no = || if grant { Ok(()) } else { Err(GestureRefusal::NoRecord) };
                        let d = SendAuth::send_command_decision(from_button, by_enter, in_release, &mut yes_no).is_ok();
                        let mut g = || grant;
                        assert_eq!(d, SendAuth::send_command_allowed(from_button, by_enter, in_release, &mut g));
                    }
                }
            }
        }
    }

    // The counters and the void / taint records come from the real hook path, and one refused Send yields exactly one line.
    #[test]
    fn observed_hook_events_reach_the_refusal_line() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut a = SendAuth::default();
        let mv = |m| HookInfo::mouse(m, 0, 0);
        assert!(a.observe_hook_event(SendAuth::classify_hook_event(0, false), mv(0x200), t0));
        a.note_mouse_down(true, true);
        a.note_hit(0x10, 0x10);
        // A lower-integrity injected move between press and release (Razer-style): voids, and the line says so.
        let low = HookInfo::mouse(0x200, 0x2, 0x77);
        assert!(!a.observe_hook_event(SendAuth::classify_hook_event(0x77, true), low, t0 + ms(5)));
        a.note_mouse_up(true, true, t0 + ms(9));
        let why = a.authorize_why(t0 + ms(10)).unwrap_err();
        assert_eq!(why, GestureRefusal::NoRecord);
        let line = a.refusal_line(t0 + ms(30), (Refusal::Gesture(why), Via::Release), &LineContext::default()).unwrap();
        assert!(line.contains("reason=gesture_no_hook_record"), "{line}");
        assert!(line.contains("seen[mouse=2 clicks=1 gate_keys=0 gate_key_downs=0] taints=0 voids=1"), "{line}");
        assert!(line.contains("last_void=mouse msg=0x200 flags=0x2 extra=0x77 void_ago_ms=25"), "{line}");
        // A technician's tagged key taints and is named.
        let tag = HookInfo::key(0x100, 0, RMT_TAG);
        assert!(!a.observe_hook_event(SendAuth::classify_hook_event(RMT_TAG, false), tag, t0 + ms(40)));
        let line = a.refusal_line(t0 + ms(50), (Refusal::Gesture(GestureRefusal::Tainted), Via::Release), &LineContext::default());
        // (one line at a time: the limiter admits the burst)
        let line = line.unwrap();
        assert!(line.contains("tainted=true") && line.contains("taints=1") && line.contains(&format!("first_taint=key msg=0x100 flags=0x0 extra={RMT_TAG:#x}")), "{line}");
        assert!(!line.contains("vk"), "a key's identity is never logged: {line}");
    }
}

// 2026-11-07 (Ed, agent 1.3.21): Windows reported IMO_UNAVAILABLE for every genuine mouse release on Send, so Send could not be clicked. An
// unavailable origin is admitted only when bound to the hook's record; an input-queue origin always is; an unknown origin or a failed query
// never is.
#[test]
fn an_unavailable_origin_is_admitted_only_when_bound_to_the_hooks_release() {
    assert!(InputOrigin::Queue.admits_release(false));
    assert!(InputOrigin::Queue.admits_release(true));
    assert!(InputOrigin::Unavailable.admits_release(true));
    assert!(!InputOrigin::Unavailable.admits_release(false), "an unbound release with no stated origin may be a look-alike");
    assert!(!InputOrigin::Refused.admits_release(true), "a failed query or an unknown origin is refused even when bound");
    // Enter is bound by its own identity check before the origin is asked.
    assert!(InputOrigin::Queue.admits_enter());
    assert!(InputOrigin::Unavailable.admits_enter());
    assert!(!InputOrigin::Refused.admits_enter());
}

// The binding is the hook's time stamp for the release that COMPLETED a genuine gesture on Send: equal time stamps only, single use, and
// cleared by everything that clears the gesture.
#[test]
fn a_release_is_bound_only_by_the_time_stamp_of_the_release_that_completed_the_gesture() {
    let t0 = Instant::now();
    let mouse = |time: u32| {
        let mut a = SendAuth::default();
        a.note_mouse_down(true, true);
        a.note_mouse_up(true, true, t0);
        a.note_release_time(time);
        a
    };
    let a = mouse(4242);
    assert!(a.release_bound_to(4242), "the genuine release itself");
    assert!(!a.release_bound_to(4241), "a message stamped before the hook's event");
    assert_eq!(a.release_bind_delta(4242 + 3), Some(3), "a re-posted release trails by a few ms");
    assert_eq!(a.release_bind_delta(4242 + RELEASE_BIND_SLACK_MS), Some(RELEASE_BIND_SLACK_MS), "the edge of the window");
    assert!(!a.release_bound_to(4242 + RELEASE_BIND_SLACK_MS + 1), "past the window");
    assert!(!a.release_bound_to(4242u32.wrapping_sub(1)), "one before, which is u32::MAX-away modulo 2^32");
    // The tick count wraps after ~49.7 days: a release just before the wrap binds a message just after it.
    let w = mouse(u32::MAX - 5);
    assert_eq!(w.release_bind_delta(10), Some(16));
    assert!(!w.release_bound_to(u32::MAX - 6));
    assert_eq!(a.release_hook_time(), Some(4242));

    // A release that completed nothing leaves no binding: off Send, a press that began elsewhere, the right button.
    for (down_over, up_left, up_over) in [(true, true, false), (false, true, true), (true, false, true)] {
        let mut a = SendAuth::default();
        a.note_mouse_down(true, down_over);
        a.note_mouse_up(up_left, up_over, t0);
        a.note_release_time(7);
        assert!(!a.release_bound_to(7), "down_over={down_over} up_left={up_left} up_over={up_over}");
        assert_eq!(a.release_hook_time(), None);
    }

    // Space completes the same way, with the key's release time stamp.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, true, t0);
    a.note_release_time(99);
    assert!(a.release_bound_to(99));

    // Everything that ends the gesture ends the binding.
    let mut a = mouse(5);
    a.void_activation();
    assert!(!a.release_bound_to(5), "voided after the release dispatch");
    let mut a = mouse(5);
    a.note_disallowed();
    assert!(!a.release_bound_to(5), "a lower-integrity injection");
    let mut a = mouse(5);
    a.note_injected();
    assert!(!a.release_bound_to(5), "a technician's input taints the dialog");
    let mut a = mouse(5);
    a.note_mouse_down(true, true);
    assert!(!a.release_bound_to(5), "a new press");
    let mut a = mouse(5);
    a.note_key_down(0x41, false, t0);
    assert!(!a.release_bound_to(5), "any key");
    let mut a = mouse(5);
    assert!(a.authorize(t0));
    assert!(!a.release_bound_to(5), "consumed by the command it authorized");
}

// End to end through the pump rule, exactly as the dialog composes it: a release with no stated origin is vouched only when bound, and the
// Send command still needs the completed gesture inside that dispatch.
#[test]
fn the_pump_vouches_for_an_unavailable_release_to_send_only_when_bound() {
    const WM_LBUTTONUP: u32 = 0x0202;
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0);
    a.note_release_time(1000);
    for (msg_time, want) in [(1000u32, true), (1004, true), (999, false), (1000 + RELEASE_BIND_SLACK_MS + 1, false)] {
        let check = || InputOrigin::Unavailable.admits_release(a.release_bound_to(msg_time));
        assert_eq!(SendAuth::pump_step(WM_LBUTTONUP, 0, false, true, &check), PumpStep::SendRelease { vouched: want }, "msg time {msg_time}");
    }
    let refused = || InputOrigin::Refused.admits_release(a.release_bound_to(1000));
    assert_eq!(SendAuth::pump_step(WM_LBUTTONUP, 0, false, true, &refused), PumpStep::SendRelease { vouched: false });
    assert!(SendAuth::send_command_allowed(true, false, true, &mut || a.authorize(t0)), "the bound release's command sends");

    // With no gesture at all, an unavailable release is never vouched, whatever its time stamp.
    let none = SendAuth::default();
    let check = || InputOrigin::Unavailable.admits_release(none.release_bound_to(0));
    assert_eq!(SendAuth::pump_step(WM_LBUTTONUP, 0, false, true, &check), PumpStep::SendRelease { vouched: false });
}

// Enter on a focused Send with an unavailable origin: admitted on the time stamp and scan code identity, refused when the identity differs,
// and refused when the origin query failed.
#[test]
fn an_enter_with_an_unavailable_origin_is_admitted_on_its_identity() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let ok = keydown_lparam(ENTER_SCAN, false);
    let unavailable: &dyn Fn() -> bool = &|| InputOrigin::Unavailable.admits_enter();
    let failed: &dyn Fn() -> bool = &|| InputOrigin::Refused.admits_enter();
    let mut a = recorded(t0, 7);
    assert!(a.begin_enter_dispatch(t0 + ms(1), 7, ok, unavailable));
    let mut a = recorded(t0, 7);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 8, ok, unavailable), "another Enter's time stamp");
    let mut a = recorded(t0, 7);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, keydown_lparam(ENTER_SCAN + 1, false), unavailable), "another scan code");
    let mut a = recorded(t0, 7);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, ok, failed), "a failed origin query");
    assert!(a.begin_enter_dispatch(t0 + ms(2), 7, ok, HW), "a refused look-alike does not consume the record");
}

// Review (1.3.22): a technician's input taints the dialog; a LATER genuine gesture still sets a record (only `authorize` refuses a tainted
// dialog), so the binding itself must refuse while tainted, for the mouse and for Space.
#[test]
fn a_tainted_dialog_binds_no_release_even_after_a_later_genuine_gesture() {
    let t0 = Instant::now();
    let mut a = SendAuth::default();
    a.note_injected();
    a.note_mouse_down(true, true);
    a.note_mouse_up(true, true, t0);
    a.note_release_time(5);
    assert!(!a.release_bound_to(5), "mouse");
    let mut a = SendAuth::default();
    a.note_injected();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, true, t0);
    a.note_release_time(6);
    assert!(!a.release_bound_to(6), "Space");
}

// Review (1.3.22): Space end to end through the pump rule, and a different key's release after Space's ends the binding.
#[test]
fn a_space_release_with_no_stated_origin_is_vouched_only_when_bound() {
    const WM_KEYUP: u32 = 0x0101;
    const WM_SYSKEYUP: u32 = 0x0105;
    let t0 = Instant::now();
    let space = || {
        let mut a = SendAuth::default();
        a.note_key_down(VK_SP, true, t0);
        a.note_key_up(VK_SP, true, t0);
        a.note_release_time(2000);
        a
    };
    let a = space();
    for m in [WM_KEYUP, WM_SYSKEYUP] {
        for (msg_time, want) in [(2000u32, true), (2002, true), (1999, false)] {
            let check = || InputOrigin::Unavailable.admits_release(a.release_bound_to(msg_time));
            assert_eq!(SendAuth::pump_step(m, 0x20, false, true, &check), PumpStep::SendRelease { vouched: want }, "{m:#x} at {msg_time}");
        }
    }
    // Shift released after Space (Shift+Space): the gesture, and with it the binding, is gone.
    let mut a = space();
    a.note_key_up(0x10, false, t0);
    a.note_release_time(2001);
    assert!(!a.release_bound_to(2000) && !a.release_bound_to(2001));
    // A Space release while Send does not have the focus completes nothing and binds nothing.
    let mut a = SendAuth::default();
    a.note_key_down(VK_SP, true, t0);
    a.note_key_up(VK_SP, false, t0);
    a.note_release_time(3000);
    assert!(!a.release_bound_to(3000));
}

// Review (1.3.22): Enter with no stated origin after a lower-integrity void or a taint is refused; a refused look-alike does not consume the
// record, so the genuine Enter that follows still sends.
#[test]
fn an_unavailable_enter_after_a_void_or_taint_is_refused_and_a_refused_one_consumes_nothing() {
    let t0 = Instant::now();
    let ms = Duration::from_millis;
    let ok = keydown_lparam(ENTER_SCAN, false);
    let unavailable: &dyn Fn() -> bool = &|| InputOrigin::Unavailable.admits_enter();
    let mut a = recorded(t0, 7);
    a.note_disallowed();
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, ok, unavailable), "after a lower-integrity injection");
    let mut a = recorded(t0, 7);
    a.note_injected();
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 7, ok, unavailable), "after a technician's input");
    // A look-alike with another time stamp is refused first; the genuine Enter, also with no stated origin, still matches.
    let mut a = recorded(t0, 7);
    assert!(!a.begin_enter_dispatch(t0 + ms(1), 9, ok, unavailable));
    assert!(a.begin_enter_dispatch(t0 + ms(2), 7, ok, unavailable));
    assert!(!a.begin_enter_dispatch(t0 + ms(3), 7, ok, unavailable), "single use");
}
