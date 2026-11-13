//! Guest-initiated help requests from an ENROLLED machine's tray (docs/64 H3, the agent half).
//!
//! The helper process owns both the tray icon and the authenticated signaling connection, so there is no new
//! listening surface (H-C7): the tray thread calls into one [`HelpHub`] that lives for the helper's lifetime (across
//! signaling reconnects), and the signaling mux hands it every `help_request_result` and attaches the live connection as
//! its [`HelpSink`].
//!
//! # What this module owns
//!
//! * The request state machine (H-C4): `Idle` -> `Sending` (until the server acks; resent with the SAME `op_id`, which
//!   the control plane dedups for 24 h) -> `Open` (re-queried on every reconnect and every 60 s) -> a terminal notice
//!   (accepted / expired / cancelled / refused / limited) shown until the guest asks again.
//! * Feature gating (D2/D3): the menu exists, and anything is sent, only while the CURRENT connection's `Registered`
//!   listed `help_request_v1`. The server withholds the feature from a RETIRED machine (restricted signaling mode, docs/65
//!   D-C1) and from servers whose control plane lacks the routes, so "retired may not request" and "old server" are both
//!   simply "feature absent" here. Sending anyway would be fatal rather than merely refused: a restricted connection
//!   answers an unknown message with `Rejected`, which ends the mux.
//! * Client-side limits that agree with the server's durable ones (H-C2): at most 3 creations per hour and 10 per day per
//!   device, and a courtesy ceiling of 12 messages per minute (signaling's per-device window). A `limited` answer also
//!   blocks new requests for the server's `retry_after_seconds`. The server remains the authority; these only keep a
//!   well-behaved agent from asking for what it will be refused.
//! * The note: optional, at most [`MAX_NOTE_CHARS`] characters, control and bidi/format characters removed.
//! * [`run_tray_menu`]: the decision logic behind the tray menu, with every OS-visible call behind [`HelpUi`] so tests
//!   never open a window. Both the menu choice AND the dialog's Send are accepted only when the guest's own hardware input
//!   made them (H-C7); the provenance answer comes from the UI layer (`tray_menu_provenance`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmt_protocol::signaling::{ClientToServer, HelpRequestInfo, HELP_NOTE_MAX_CHARS, HELP_REQUEST_FEATURE};
use tokio::sync::Notify;

use crate::help_diag::{EnterRefusal, GestureRefusal, GestureStep, HookInfo, LineContext, Refusal, SendDiag, Stashed};

/// The longest note the guest may send (the server's `helpNoteMaxRunes`).
pub const MAX_NOTE_CHARS: usize = HELP_NOTE_MAX_CHARS;
/// Creations per device per hour / per day the control plane allows (`helpDeviceHourlyLimit`, `helpDeviceDailyLimit`).
pub const CREATIONS_PER_HOUR: usize = 3;
pub const CREATIONS_PER_DAY: usize = 10;
/// Messages per minute per device signaling admits (`helpPeerPerMinute`).
pub const MESSAGES_PER_MINUTE: usize = 12;
/// While `Open`, ask the server for the request's state this often (H-C4).
pub const STATUS_POLL: Duration = Duration::from_secs(60);
/// While `Sending`, resend the (same op_id) request this often until it is acknowledged...
pub const RESEND_AFTER: Duration = Duration::from_secs(20);
/// ...and after this long without an answer the outcome is UNCERTAIN: the request may well have been created with only the
/// acknowledgement lost, so the agent never claims non-delivery, never allows a fresh creation, and keeps asking.
pub const SEND_GIVE_UP: Duration = Duration::from_secs(120);
/// While the outcome is uncertain, replay the SAME op_id this often (the server dedups on it for 24 h, so the answer is
/// authoritative: the original request if it exists, else it is created now).
pub const UNCERTAIN_RESEND: Duration = Duration::from_secs(60);
/// The control plane dedups an op_id for 24 h. Replaying it creates a request if none exists, so replays stop well before the
/// window closes (measured from the FIRST send); afterwards only `help_status` is asked, never a create, so a request that
/// stays uncertain for a long time can never be created a second time.
pub const REPLAY_WINDOW: Duration = Duration::from_secs(20 * 3600);
/// A cancel with no answer is forgotten (the guest may press it again) after this long.
pub const CANCEL_PATIENCE: Duration = Duration::from_secs(30);
/// A terminal notice stays in the menu and tooltip this long.
pub const NOTICE_TTL: Duration = Duration::from_secs(10 * 60);
/// The longest `retry_after_seconds` honoured (a hostile or buggy value must not lock the menu for good).
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the pump wakes by itself.
const PUMP_INTERVAL: Duration = Duration::from_secs(5);

/// Where messages go: the live signaling connection (or a test double).
pub trait HelpSink: Send + Sync {
    /// Queue `msg` for the server; `false` if the connection is gone.
    fn send(&self, msg: ClientToServer) -> bool;
}

/// One `help_request_result` as it arrived (the mux builds this from the wire message).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HelpResult {
    pub op: String,
    pub op_id: String,
    pub outcome: String,
    pub request: Option<HelpRequestInfo>,
    pub retry_after_seconds: u32,
    /// On a help_cancel answer: the request id it is about (empty from an older signaling).
    pub cancel_of: String,
}

/// What the guest last learned about a request that is no longer open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    /// A technician accepted: a session is about to start.
    Accepted,
    Expired,
    Cancelled,
    /// The server refused the request (retired or quarantined machine, bad request, ...).
    Refused,
    /// A limit was hit; new requests are blocked for a while.
    Limited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Idle,
    Sending { op_id: String, note: String, started: Instant, last_sent: Instant, uncertain: bool },
    Open { id: String, last_poll: Instant, cancel_sent: Option<Instant> },
}

/// The coarse state the tray shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewPhase {
    Idle,
    Sending,
    /// No answer for [`SEND_GIVE_UP`]: whether the server holds the request is unknown. Nothing new may be created.
    Checking,
    Open,
    Cancelling,
}

/// A snapshot for the tray: everything needed to build the menu, the status line and the tooltip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpView {
    /// The current connection advertises `help_request_v1`: the menu item exists. False for a retired machine, an old
    /// server, or no connection.
    pub available: bool,
    pub phase: ViewPhase,
    pub notice: Option<Notice>,
    /// The id of the acknowledged open request this view shows (what a Cancel chosen from it names).
    pub open_id: Option<String>,
    /// "Request help..." may be offered (available, nothing in flight, not rate limited).
    pub can_request: bool,
    /// When a request is blocked by a limit, for how much longer.
    pub blocked_for: Option<Duration>,
}

/// The one line of status shown at the top of the menu; `None` when there is nothing to say.
pub fn status_text(v: &HelpView) -> Option<String> {
    let t = match v.phase {
        ViewPhase::Sending => "Sending your help request\u{2026}",
        ViewPhase::Checking => "Checking that your help request was received\u{2026}",
        ViewPhase::Open => "Help requested \u{2014} waiting for a technician",
        ViewPhase::Cancelling => "Cancelling your help request\u{2026}",
        ViewPhase::Idle => match v.notice {
            Some(Notice::Accepted) => "A technician accepted your request \u{2014} connecting",
            // A limit explains why the menu item is greyed out, so it outranks the other notices.
            _ if v.blocked_for.is_some() => "Too many help requests \u{2014} please try again later",
            Some(Notice::Expired) => "Your help request expired",
            Some(Notice::Cancelled) => "Your help request was cancelled",
            Some(Notice::Refused) => "Your help request could not be accepted",
            Some(Notice::Limited) => "Too many help requests \u{2014} please try again later",
            None => return None,
        },
    };
    Some(t.to_string())
}

/// The tray tooltip for a state.
pub fn tooltip_text(v: &HelpView, base: &str) -> String {
    match status_text(v) {
        Some(s) if v.available || v.phase != ViewPhase::Idle => format!("{base} \u{2014} {s}"),
        _ => base.to_string(),
    }
}

/// Why a request was not started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The connection does not advertise the feature (retired machine, old server, offline).
    NotAvailable,
    /// A request is already in flight or open.
    AlreadyOpen,
    /// A client-side limit; try again after this long.
    RateLimited(Duration),
    /// The connection dropped under us.
    SendFailed,
}

/// Why a cancel was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelError {
    NotAvailable,
    /// No acknowledged open request to cancel (nothing open, still sending, or a cancel already in flight).
    NothingToCancel,
    RateLimited,
    SendFailed,
}

/// Remove what a note must not carry: whitespace controls become spaces, every other control and the invisible
/// format/bidi characters are dropped, the result is trimmed and capped at [`MAX_NOTE_CHARS`] characters. The server
/// normalizes again; this keeps what the guest SEES in the dialog equal to what is sent.
pub fn sanitize_note(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            // Zero-width, bidi embedding/override/isolate, word joiner, line/paragraph separators, BOM.
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}'
            | '\u{2028}' | '\u{2029}' | '\u{FEFF}' => {}
            c => out.push(c),
        }
    }
    out.trim().chars().take(MAX_NOTE_CHARS).collect::<String>().trim().to_string()
}

/// Client-side admission, agreeing with the control plane's durable limits and signaling's per-minute window.
#[derive(Default)]
struct Limiter {
    created: VecDeque<Instant>,
    msgs: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl Limiter {
    fn prune(&mut self, now: Instant) {
        while self.created.front().is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(24 * 3600)) {
            self.created.pop_front();
        }
        while self.msgs.front().is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60)) {
            self.msgs.pop_front();
        }
        if self.blocked_until.is_some_and(|t| t <= now) {
            self.blocked_until = None;
        }
    }

    /// How long until a NEW request is allowed; `None` = now.
    fn creation_wait(&mut self, now: Instant) -> Option<Duration> {
        self.prune(now);
        let mut wait = self.blocked_until.map(|t| t.saturating_duration_since(now));
        let mut consider = |limit: usize, window: Duration| {
            let within: Vec<Instant> =
                self.created.iter().copied().filter(|t| now.saturating_duration_since(*t) < window).collect();
            if within.len() >= limit {
                // The (len - limit + 1)th oldest in the window must age out.
                let oldest_blocking = within[within.len() - limit];
                let w = (oldest_blocking + window).saturating_duration_since(now);
                wait = Some(wait.map_or(w, |x| x.max(w)));
            }
        };
        consider(CREATIONS_PER_HOUR, Duration::from_secs(3600));
        consider(CREATIONS_PER_DAY, Duration::from_secs(24 * 3600));
        wait
    }

    fn note_creation(&mut self, now: Instant) {
        self.created.push_back(now);
    }

    /// Spend one message of the per-minute budget.
    fn message_ok(&mut self, now: Instant) -> bool {
        self.prune(now);
        if self.msgs.len() >= MESSAGES_PER_MINUTE {
            return false;
        }
        self.msgs.push_back(now);
        true
    }
}

struct Inner {
    /// Incremented by every attach and detach; answers carry the generation of the connection they arrived on.
    generation: u64,
    sink: Option<Arc<dyn HelpSink>>,
    available: bool,
    phase: Phase,
    notice: Option<(Notice, Instant)>,
    limiter: Limiter,
}

/// The help-request state for one helper lifetime. Cheap to share (`Arc`); every method takes `now` so tests control time.
pub struct HelpHub {
    inner: Mutex<Inner>,
    on_change: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    wake: Notify,
}

impl HelpHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                generation: 0,
                sink: None,
                available: false,
                phase: Phase::Idle,
                notice: None,
                limiter: Limiter::default(),
            }),
            on_change: Mutex::new(None),
            wake: Notify::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register what to call (from any thread) when the view changes. The tray posts a message to its window.
    pub fn set_on_change(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_change.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    /// Run `f` on the state; if the guest-visible view changed, tell the tray (after the lock is released).
    fn mutate<R>(&self, now: Instant, f: impl FnOnce(&mut Inner) -> R) -> R {
        let (r, changed) = {
            let mut g = self.lock();
            let before = view_of(&mut g, now);
            let r = f(&mut g);
            let after = view_of(&mut g, now);
            (r, before != after)
        };
        if changed {
            let cb = self.on_change.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(cb) = cb {
                cb();
            }
        }
        r
    }

    /// A (re)registered connection is live. `advertised`: its `Registered` listed `help_request_v1`. Returns the
    /// connection's generation, which every answer from it must be tagged with.
    ///
    /// Resync (H-C4): a request still `Sending` is re-sent with its SAME op_id (the server dedups); otherwise the
    /// server is asked for the device's open request, which also surfaces one made before this helper started.
    pub fn attach(&self, sink: Arc<dyn HelpSink>, advertised: bool, now: Instant) -> u64 {
        let r = self.mutate(now, |i| {
            i.generation += 1;
            i.sink = Some(sink);
            i.available = advertised;
            if !advertised {
                // Retired, old server, or the feature was withdrawn: nothing can be sent, so nothing is pending.
                i.phase = Phase::Idle;
                return i.generation;
            }
            match i.phase.clone() {
                Phase::Sending { op_id, note, started, .. } => {
                    if send_msg(i, resend_msg(op_id, note, started, now), now) {
                        if let Phase::Sending { last_sent, .. } = &mut i.phase {
                            *last_sent = now;
                        }
                    }
                }
                Phase::Open { .. } | Phase::Idle => {
                    if send_msg(i, ClientToServer::HelpStatus {}, now) {
                        if let Phase::Open { last_poll, cancel_sent, .. } = &mut i.phase {
                            *last_poll = now;
                            *cancel_sent = None;
                        }
                    }
                }
            }
            i.generation
        });
        self.wake.notify_one();
        r
    }

    /// The connection of `generation` is gone. A later attach already superseded it is not disturbed.
    pub fn detach(&self, generation: u64, now: Instant) {
        self.mutate(now, |i| {
            if i.generation == generation {
                i.generation += 1;
                i.sink = None;
                i.available = false;
            }
        });
    }

    /// The guest asked for help. `note` is sanitized and capped here.
    pub fn request(&self, note: &str, now: Instant) -> Result<(), RequestError> {
        self.mutate(now, |i| {
            if !i.available || i.sink.is_none() {
                return Err(RequestError::NotAvailable);
            }
            if !matches!(i.phase, Phase::Idle) {
                return Err(RequestError::AlreadyOpen);
            }
            if let Some(w) = i.limiter.creation_wait(now) {
                return Err(RequestError::RateLimited(w));
            }
            let note = sanitize_note(note);
            let op_id = uuid::Uuid::new_v4().simple().to_string();
            if !i.limiter.message_ok(now) {
                return Err(RequestError::RateLimited(Duration::from_secs(60)));
            }
            let sent = i.sink.as_ref().is_some_and(|s| s.send(ClientToServer::HelpRequest { op_id: op_id.clone(), note: note.clone() }));
            if !sent {
                return Err(RequestError::SendFailed);
            }
            i.notice = None;
            i.phase = Phase::Sending { op_id, note, started: now, last_sent: now, uncertain: false };
            Ok(())
        })
    }

    /// The guest withdrew the request THEY WERE SHOWN (`expected_id`, from the view the menu was built from). If the
    /// request changed since (it expired and a newer one opened), nothing is sent: a stale menu must not cancel a request the
    /// guest never saw.
    pub fn cancel(&self, expected_id: &str, now: Instant) -> Result<(), CancelError> {
        self.mutate(now, |i| {
            if !i.available || i.sink.is_none() {
                return Err(CancelError::NotAvailable);
            }
            let id = match &i.phase {
                Phase::Open { id, cancel_sent: None, .. } if id == expected_id => id.clone(),
                _ => return Err(CancelError::NothingToCancel),
            };
            if !i.limiter.message_ok(now) {
                return Err(CancelError::RateLimited);
            }
            if !i.sink.as_ref().is_some_and(|s| s.send(ClientToServer::HelpCancel { request_id: id })) {
                return Err(CancelError::SendFailed);
            }
            if let Phase::Open { cancel_sent, .. } = &mut i.phase {
                *cancel_sent = Some(now);
            }
            Ok(())
        })
    }

    /// Fold one server answer. Ignored unless `generation` is still the current connection's.
    pub fn on_result(&self, generation: u64, r: HelpResult, now: Instant) {
        self.mutate(now, |i| {
            if i.generation != generation {
                return;
            }
            match r.op.as_str() {
                "help_request" => on_request_result(i, &r, now),
                "help_cancel" => on_cancel_result(i, &r, now),
                "help_status" => on_status_result(i, &r, now),
                other => tracing::debug!(op = other, "help: ignoring a result for an unknown op"),
            }
        });
    }

    /// Timers: resend an unacknowledged request, give up on one that never gets through, re-query an open one (H-C4),
    /// forget a cancel that was never answered.
    pub fn tick(&self, now: Instant) {
        self.mutate(now, |i| {
            if !i.available || i.sink.is_none() {
                return;
            }
            match i.phase.clone() {
                Phase::Sending { op_id, note, started, last_sent, uncertain } => {
                    let uncertain = uncertain || now.saturating_duration_since(started) >= SEND_GIVE_UP;
                    if let Phase::Sending { uncertain: u, .. } = &mut i.phase {
                        *u = uncertain;
                    }
                    let every = if uncertain { UNCERTAIN_RESEND } else { RESEND_AFTER };
                    if now.saturating_duration_since(last_sent) >= every
                        && send_msg(i, resend_msg(op_id, note, started, now), now)
                    {
                        if let Phase::Sending { last_sent, .. } = &mut i.phase {
                            *last_sent = now;
                        }
                    }
                }
                Phase::Open { last_poll, cancel_sent, .. } => {
                    if cancel_sent.is_some_and(|t| now.saturating_duration_since(t) >= CANCEL_PATIENCE) {
                        if let Phase::Open { cancel_sent, .. } = &mut i.phase {
                            *cancel_sent = None;
                        }
                    }
                    if now.saturating_duration_since(last_poll) >= STATUS_POLL && send_msg(i, ClientToServer::HelpStatus {}, now) {
                        if let Phase::Open { last_poll, .. } = &mut i.phase {
                            *last_poll = now;
                        }
                    }
                }
                Phase::Idle => {}
            }
        });
    }

    /// What the tray should show now.
    pub fn view(&self, now: Instant) -> HelpView {
        let mut g = self.lock();
        view_of(&mut g, now)
    }

    /// The pump: wakes every few seconds and on attach, and runs the timers. Spawned once per helper.
    pub async fn run(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(PUMP_INTERVAL) => {},
            }
            self.tick(Instant::now());
        }
    }
}

/// What re-asking about an unacknowledged request sends: the same-op_id create while the server still dedups it, else only
/// a status query.
fn resend_msg(op_id: String, note: String, started: Instant, now: Instant) -> ClientToServer {
    if now.saturating_duration_since(started) < REPLAY_WINDOW {
        ClientToServer::HelpRequest { op_id, note }
    } else {
        ClientToServer::HelpStatus {}
    }
}

/// Spend a message of the per-minute budget and send; false if either refused.
fn send_msg(i: &mut Inner, msg: ClientToServer, now: Instant) -> bool {
    if !i.limiter.message_ok(now) {
        return false;
    }
    i.sink.as_ref().is_some_and(|s| s.send(msg))
}

fn view_of(i: &mut Inner, now: Instant) -> HelpView {
    let blocked_for = i.limiter.creation_wait(now);
    let phase = match &i.phase {
        Phase::Idle => ViewPhase::Idle,
        Phase::Sending { uncertain: true, .. } => ViewPhase::Checking,
        Phase::Sending { .. } => ViewPhase::Sending,
        Phase::Open { cancel_sent: Some(_), .. } => ViewPhase::Cancelling,
        Phase::Open { .. } => ViewPhase::Open,
    };
    let notice = i.notice.filter(|(_, at)| now.saturating_duration_since(*at) < NOTICE_TTL).map(|(n, _)| n);
    HelpView {
        available: i.available,
        phase,
        notice: if phase == ViewPhase::Idle { notice } else { None },
        open_id: match &i.phase {
            Phase::Open { id, .. } => Some(id.clone()),
            _ => None,
        },
        can_request: i.available && phase == ViewPhase::Idle && blocked_for.is_none(),
        blocked_for,
    }
}

fn finish(i: &mut Inner, status: &str, now: Instant) {
    let notice = match status {
        "accepted" => Notice::Accepted,
        "expired" => Notice::Expired,
        "cancelled" => Notice::Cancelled,
        _ => return,
    };
    i.phase = Phase::Idle;
    i.notice = Some((notice, now));
}

fn open_from(i: &mut Inner, info: &HelpRequestInfo, now: Instant) {
    // A request the server still holds open keeps an in-flight cancel for the SAME id.
    let keep_cancel = match &i.phase {
        Phase::Open { id, cancel_sent, .. } if *id == info.id => *cancel_sent,
        _ => None,
    };
    i.phase = Phase::Open { id: info.id.clone(), last_poll: now, cancel_sent: keep_cancel };
    i.notice = None;
}

fn on_request_result(i: &mut Inner, r: &HelpResult, now: Instant) {
    // Only an answer that names the op_id we are waiting on counts; anything else is stale or unattributable.
    let waiting = match &i.phase {
        Phase::Sending { op_id, .. } => op_id.clone(),
        _ => return,
    };
    if r.op_id != waiting {
        return;
    }
    match r.outcome.as_str() {
        "ok" | "conflict" => match &r.request {
            Some(info) if info.status == "open" => {
                if r.outcome == "ok" {
                    i.limiter.note_creation(now);
                }
                open_from(i, info, now);
            }
            Some(info) => {
                i.limiter.note_creation(now);
                finish(i, &info.status, now);
                if matches!(i.phase, Phase::Sending { .. }) {
                    // An unknown terminal status: do not keep a request we cannot name.
                    i.phase = Phase::Idle;
                    i.notice = Some((Notice::Refused, now));
                }
            }
            None => {} // acknowledged without a request: keep Sending, the timer resends.
        },
        "refused" | "not_found" => {
            i.phase = Phase::Idle;
            i.notice = Some((Notice::Refused, now));
        }
        "limited" => {
            let wait = Duration::from_secs(u64::from(r.retry_after_seconds.max(1))).min(MAX_RETRY_AFTER);
            i.limiter.blocked_until = Some(now + wait);
            i.phase = Phase::Idle;
            i.notice = Some((Notice::Limited, now));
        }
        _ => {} // "unavailable" and anything new: still Sending; the timer resends, then gives up.
    }
}

fn on_cancel_result(i: &mut Inner, r: &HelpResult, now: Instant) {
    let id = match &i.phase {
        Phase::Open { id, .. } => id.clone(),
        _ => return,
    };
    let clear_cancel = |i: &mut Inner| {
        if let Phase::Open { cancel_sent, .. } = &mut i.phase {
            *cancel_sent = None;
        }
    };
    // Newer signaling names the request every cancel answer is about, for EVERY outcome: correlate by it. An answer about
    // another request touches nothing of the one open now; one about this request settles it.
    if !r.cancel_of.is_empty() {
        if r.cancel_of != id {
            return;
        }
        match r.outcome.as_str() {
            "ok" | "conflict" => match &r.request {
                Some(info) if info.id == id && info.status != "open" => finish(i, &info.status, now),
                _ => clear_cancel(i),
            },
            // The server does not hold this request for this device any more: it is settled, as cancelled.
            "not_found" => {
                i.phase = Phase::Idle;
                i.notice = Some((Notice::Cancelled, now));
            }
            _ => clear_cancel(i),
        }
        return;
    }
    // An older signaling (no cancel_of) cannot attribute a not_found: fall back to asking, settling nothing.
    match r.outcome.as_str() {
        "ok" | "conflict" => match &r.request {
            // Correlated by the request id the server echoes: an answer about ANOTHER request (a delayed one for an
            // earlier request) touches nothing of the one open now.
            Some(info) if info.id == id && info.status != "open" => finish(i, &info.status, now),
            Some(info) if info.id == id => clear_cancel(i),
            _ => {}
        },
        // A not_found carries no request id and a cancel carries no op_id (server/signaling/helprequest.go), so it cannot
        // be attributed to the request that was open when the cancel was sent: it may be a delayed answer about an earlier
        // one. It therefore settles NOTHING; ask the server what is true instead (the status answer names the request).
        "not_found" => {
            clear_cancel(i);
            let _ = send_msg(i, ClientToServer::HelpStatus {}, now);
        }
        // unavailable / limited / refused carry no id either: they can only mean "the cancel may not have happened", and
        // the open request is unchanged, so the guest may press Cancel again.
        _ => clear_cancel(i),
    }
}

fn on_status_result(i: &mut Inner, r: &HelpResult, now: Instant) {
    if r.outcome != "ok" {
        return;
    }
    // Past the replay window only status is asked, and any request this agent created has long since closed (30 min
    // lifetime): no open request now means the uncertain send is over, not that it failed.
    if let Phase::Sending { started, .. } = &i.phase {
        if now.saturating_duration_since(*started) >= REPLAY_WINDOW && !matches!(&r.request, Some(info) if info.status == "open") {
            i.phase = Phase::Idle;
            i.notice = Some((Notice::Expired, now));
            return;
        }
    }
    match &r.request {
        Some(info) if info.status == "open" => open_from(i, info, now),
        // The server answers with the device's LATEST request when none is open, possibly one closed hours ago: it
        // is news only if it is the very request this agent was holding open.
        Some(info) => {
            if matches!(&i.phase, Phase::Open { id, .. } if *id == info.id) {
                finish(i, &info.status, now);
            }
        }
        None => {
            if matches!(i.phase, Phase::Open { .. }) {
                i.phase = Phase::Idle;
                i.notice = Some((Notice::Expired, now));
            }
        }
    }
}

// ── Authenticating the dialog's Send ──────────────────────────────────────────────────────────────────────────────

/// How recent the genuine activation must be when the dialog's `WM_COMMAND` for Send is processed.
pub const ACTIVATION_FRESH: Duration = Duration::from_secs(2);

/// How far a release message's time stamp may trail the hook's time stamp for the release that completed the gesture, when Windows gives the
/// message no origin. Normally they are equal. A layer that re-posts the release (one hypothesis for the operator's PC, 1.3.21) stamps the post time,
/// a few milliseconds later; exact equality would then refuse every click again. A message stamped BEFORE the hook's event is never bound.
pub const RELEASE_BIND_SLACK_MS: u32 = 250;

/// The Enter key's virtual-key code (`VK_RETURN`).
const VK_ENTER: u32 = 0x0D;

/// Proof that the guest ACTIVATED Send, kept by the dialog from low-level hook events (which only real input and
/// `SendInput` pass through; a posted `WM_COMMAND` / `BM_CLICK` / `WM_LBUTTONUP` never does).
///
/// A `WM_COMMAND` is just a message any same-integrity process can post, so it proves nothing by itself (Codex H3 review).
/// Send is authorized only by a COMPLETE genuine gesture on the Send button: a left-button DOWN on Send followed by the
/// left-button UP with the pointer still over Send, or a Space key DOWN while Send has the focus followed by its UP (Space
/// activates a button on release), or an Enter key DOWN while Send has the focus, which is bound to the dispatch of that very
/// `WM_KEYDOWN(VK_RETURN)` (the dialog manager turns the DOWN itself into the default-button command, before any UP exists) and is never a
/// time-window authorization. Anything else the guest does in between clears it: a press elsewhere (so a drag from outside onto Send
/// never starts one), a right/middle/extra button, any other key, a different key's release, a release off the button. This
/// product's own injected input (a technician's, see [`SendAuth::classify_hook_event`]) taints the whole dialog; an injection by a
/// lower-integrity process voids only the gesture in progress. A completed gesture is single-use and lapses after [`ACTIVATION_FRESH`].
#[derive(Debug, Default)]
pub struct SendAuth {
    tainted: bool,
    /// The press of a gesture still in progress.
    pending: Pending,
    /// A completed gesture waiting for its `WM_COMMAND` (mouse release, Space release). Enter never uses this.
    activated_at: Option<Instant>,
    /// The low-level hook's time stamp (`MSLLHOOKSTRUCT.time` / `KBDLLHOOKSTRUCT.time`) of the release that completed `activated_at`: the
    /// identity a release message is bound to when Windows cannot say where it came from (see [`InputOrigin::admits_release`]).
    release_time: Option<u32>,
    /// A genuine Enter DOWN on the focused Send, seen by the hook and waiting to be matched by the dialog's message loop with the very
    /// `WM_KEYDOWN(VK_RETURN)` it belongs to (see [`SendAuth::begin_enter_dispatch`]). Not an authorization of any later command.
    enter_pending: Option<EnterRecord>,
    /// What the hooks and the loop saw, for the refusal log line (`help_diag`). Consulted by no gate.
    diag: SendDiag,
}

/// The identity of the hook's genuine Enter DOWN.
#[derive(Debug, Clone, Copy)]
struct EnterRecord {
    at: Instant,
    time: u32,
    scan: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Pending {
    #[default]
    None,
    Mouse,
    Key(u32),
}

/// What one low-level hook event is, for the Send authorization (see [`SendAuth::classify_hook_event`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    /// This product's own injected input (a technician's session): taints the dialog for good ([`SendAuth::note_injected`]).
    Product,
    /// Injected by a process of LOWER integrity than this helper: voids the gesture in progress, nothing more ([`SendAuth::note_disallowed`]).
    LowerIntegrity,
    /// The guest's input: hardware, or software injection at the helper's integrity or above (a remapper, a KVM, an on-screen keyboard).
    Guest,
}

/// What Windows says about the origin of the message the dialog is processing (`GetCurrentInputMessageSource`), as the gates use it.
///
/// `Unavailable` is not a verdict. A posted or sent look-alike reports it, but so does the guest's real hardware click on some machines: the operator's
/// PC (agent 1.3.21, 2026-11-07) reported `IMO_UNAVAILABLE` / `IMDT_UNAVAILABLE` for every genuine left-button release on Send (the cause is
/// not established; the lab VM reports hardware), so a strict origin rule left Send unusable with the mouse. Such a message is accepted only when
/// it is bound by identity to the genuine event the low-level hook recorded (see [`InputOrigin::admits_release`] and
/// [`InputOrigin::admits_enter`]). A look-alike bound that way can only stand in for a press the guest really made on Send. It cannot invent
/// one, because every gesture starts from the hook's record, and the hook sees only real input or `SendInput`. The dialog runs as SYSTEM, so
/// User Interface Privilege Isolation already keeps an ordinary desktop process from posting to it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOrigin {
    /// Through the input queue: hardware, `SendInput` that is not this product's own (the hooks vet that), or Windows itself.
    Queue,
    /// `IMO_UNAVAILABLE`: Windows does not say.
    Unavailable,
    /// An origin this code does not know, or the query failed (fail closed).
    Refused,
}

impl InputOrigin {
    /// A Space / left-button release addressed to Send may complete a gesture. `bound`: the message's time stamp is the hook's time stamp for the
    /// release that completed a genuine gesture on Send, or trails it by at most [`RELEASE_BIND_SLACK_MS`] ([`SendAuth::release_bound_to`]).
    pub fn admits_release(self, bound: bool) -> bool {
        match self {
            InputOrigin::Queue => true,
            InputOrigin::Unavailable => bound,
            InputOrigin::Refused => false,
        }
    }

    /// The `WM_KEYDOWN(VK_RETURN)` being dispatched may authorize Send. Called only after [`SendAuth::begin_enter_dispatch_why`] has matched
    /// the message to the hook's genuine Enter DOWN by time stamp, scan code and repeat bit, so `Unavailable` is admitted on that identity.
    pub fn admits_enter(self) -> bool {
        self != InputOrigin::Refused
    }
}

/// What the dialog's message loop does with one dequeued message (see [`SendAuth::pump_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpStep {
    /// This product's own injected keyboard/mouse input (a technician's): never reaches the dialog.
    Drop,
    /// Delivered; not a release that completes a gesture on Send.
    Deliver,
    /// A Space / left-button release addressed to Send, delivered either way (a button that misses its release keeps the mouse capture and
    /// swallows every later click: the operator's 1.3.19 dialog, 2026-11-04). `vouched`: Windows says it came through the input queue; only inside
    /// the dispatch of a VOUCHED release can a mouse/Space gesture authorize Send (see [`SendAuth::send_command_allowed`]).
    SendRelease { vouched: bool },
}

impl SendAuth {
    /// The message loop's decision for one dequeued message. `tagged`: it carries this product's injection tag. Only tagged keyboard/mouse
    /// input is ever dropped; provenance never drops anything, it only decides whether a Send-bound release may complete a gesture.
    pub fn pump_step(message: u32, wparam: usize, tagged: bool, target_is_send: bool, from_real_input: &dyn Fn() -> bool) -> PumpStep {
        if crate::code_prompt::classify_pump_message(message, tagged) == crate::code_prompt::PumpAction::Drop {
            return PumpStep::Drop;
        }
        if !Self::is_send_release(message, wparam, target_is_send) {
            return PumpStep::Deliver;
        }
        PumpStep::SendRelease { vouched: !Self::unvouched_send_release(message, wparam, target_is_send, from_real_input) }
    }

    /// A Space (`WM_KEYUP`/`WM_SYSKEYUP` of `VK_SPACE`) or left-button release addressed to the Send button.
    fn is_send_release(message: u32, wparam: usize, target_is_send: bool) -> bool {
        const WM_KEYUP: u32 = 0x0101;
        const WM_SYSKEYUP: u32 = 0x0105;
        const WM_LBUTTONUP: u32 = 0x0202;
        const VK_SPACE: usize = 0x20;
        target_is_send && (((message == WM_KEYUP || message == WM_SYSKEYUP) && wparam == VK_SPACE) || message == WM_LBUTTONUP)
    }

    /// Whether Send's `WM_COMMAND` is honoured. `from_button`: it names the Send button as its sender. Enter: only synchronously inside the
    /// dispatch of the genuine Enter DOWN (`by_enter`). Mouse and Space: only synchronously inside the loop's dispatch of a VOUCHED release to
    /// Send (`in_vouched_release`), and then only with a completed genuine gesture (`authorize`, which consumes it). A command that arrives
    /// any other way (posted, or SENT straight to the window procedure, which never passes through the loop) finds neither and is refused
    /// without consulting the record.
    pub fn send_command_allowed(from_button: bool, by_enter: bool, in_vouched_release: bool, authorize: &mut dyn FnMut() -> bool) -> bool {
        Self::send_command_decision(from_button, by_enter, in_vouched_release, &mut || {
            if authorize() {
                Ok(())
            } else {
                Err(GestureRefusal::NoRecord)
            }
        })
        .is_ok()
    }

    /// [`SendAuth::send_command_allowed`] with the reason it refused (the decision itself is this one; the bool is derived from it).
    pub fn send_command_decision(
        from_button: bool,
        by_enter: bool,
        in_vouched_release: bool,
        authorize: &mut dyn FnMut() -> Result<(), GestureRefusal>,
    ) -> Result<(), Refusal> {
        if !from_button {
            Err(Refusal::CommandNotFromSend)
        } else if by_enter {
            Ok(())
        } else if in_vouched_release {
            authorize().map_err(Refusal::Gesture)
        } else {
            Err(Refusal::CommandOutsideDispatch)
        }
    }

    /// Clears any completed or in-progress mouse/Space gesture. Called before an UNVOUCHED Send-bound release is dispatched (a look-alike
    /// dequeued ahead of the guest's real release takes its place; the guest sees the hint and clicks again) and after EVERY Send-bound
    /// release dispatch, so a gesture is usable only by the release that completed it and a stranded record (a release that produced no
    /// click) never outlives it.
    pub fn void_activation(&mut self) {
        self.pending = Pending::None;
        self.activated_at = None;
        self.release_time = None;
    }

    /// The hook's time stamp for the release it just handed to [`note_mouse_up`](Self::note_mouse_up) or
    /// [`note_key_up`](Self::note_key_up). Kept only if that release completed a gesture.
    pub fn note_release_time(&mut self, time: u32) {
        self.release_time = self.activated_at.map(|_| time);
    }

    /// Whether a release message with time stamp `msg_time` is the very release that completed the pending genuine gesture on Send (the
    /// identity [`InputOrigin::admits_release`] binds an `Unavailable` origin to). It decides nothing about the command: that is still
    /// [`authorize`](Self::authorize), inside the dispatch.
    pub fn release_bound_to(&self, msg_time: u32) -> bool {
        self.release_bind_delta(msg_time).is_some()
    }

    /// The gap in milliseconds from the hook's release time stamp to `msg_time` when the message is bound: stamped at or after the hook's
    /// event, by at most [`RELEASE_BIND_SLACK_MS`] (the tick count wraps, so the difference is taken modulo 2^32).
    pub fn release_bind_delta(&self, msg_time: u32) -> Option<u32> {
        if self.tainted || self.activated_at.is_none() {
            return None;
        }
        let delta = msg_time.wrapping_sub(self.release_time?);
        (delta <= RELEASE_BIND_SLACK_MS).then_some(delta)
    }

    /// A Send-bound release with no stated origin was admitted on the hook binding, `delta_ms` after the hook's event (closing line only).
    pub fn note_unavailable_admitted(&mut self, delta_ms: u32) {
        self.diag.note_unavailable_admitted(delta_ms);
    }

    /// The recorded release time stamp, for the refusal log.
    pub fn release_hook_time(&self) -> Option<u32> {
        self.release_time
    }

    /// This product's own injected input was seen ([`HookEvent::Product`]): a technician is driving this desktop, so nothing in this dialog
    /// is the guest's any more.
    pub fn note_injected(&mut self) {
        self.tainted = true;
        self.note_disallowed();
    }

    /// An event that may not take part in a gesture was seen ([`HookEvent::LowerIntegrity`]): whatever was in progress or completed is void,
    /// but the dialog is not tainted, so the guest's next genuine gesture still authorizes Send. A guest's own lower-integrity remapper or
    /// accessibility tool injects such events anywhere on the desktop; latching them disabled Send for the dialog's whole life (Codex
    /// release review, 1.3.20).
    pub fn note_disallowed(&mut self) {
        self.pending = Pending::None;
        self.activated_at = None;
        self.release_time = None;
        self.enter_pending = None;
    }

    /// A genuine mouse button went DOWN. Only the left button with the pointer over Send begins a gesture; every other
    /// press (elsewhere, another button) ends whatever was in progress.
    pub fn note_mouse_down(&mut self, left: bool, over_send: bool) {
        self.diag.note_step(GestureStep::MouseDown { left, over: over_send });
        self.activated_at = None;
        self.release_time = None;
        self.enter_pending = None;
        self.pending = if left && over_send { Pending::Mouse } else { Pending::None };
    }

    /// A genuine mouse button went UP. Completes the gesture only if it is the left button, over Send, and a left press on
    /// Send began it.
    pub fn note_mouse_up(&mut self, left: bool, over_send: bool, at: Instant) {
        let complete = left && over_send && self.pending == Pending::Mouse;
        self.diag.note_step(GestureStep::MouseUp { left, over: over_send, press_on_send: self.pending == Pending::Mouse });
        self.pending = Pending::None;
        self.enter_pending = None;
        self.activated_at = complete.then_some(at);
        self.release_time = None;
    }

    /// A genuine key went DOWN at `at`. `activates_send`: it is Enter or Space and Send has the focus. Any other key ends a
    /// gesture in progress (an auto-repeat of the activation key just restarts it).
    ///
    /// The two keys activate a focused button at different moments, and the authorization follows the OS:
    /// * **Space** activates on its key UP (the button's own handling), so the gesture is DOWN then UP of the same key.
    /// * **Enter** is not delivered to the button at all: `IsDialogMessageW` turns the key DOWN into the default-button `WM_COMMAND`
    ///   and sends it synchronously, before the key UP exists. A genuine Enter DOWN is therefore only RECORDED here; it authorizes nothing
    ///   by itself and by no time window: the dialog's message loop matches it with the one `WM_KEYDOWN(VK_RETURN)` it dispatches and
    ///   accepts Send's command only synchronously inside that dispatch ([`SendAuth::begin_enter_dispatch`]). A forged `WM_COMMAND` can
    ///   therefore never consume it. Cleared by any other input; voided by any injected press.
    pub fn note_key_down(&mut self, vk: u32, activates_send: bool, at: Instant) {
        self.diag.note_step(GestureStep::KeyDown { activating: activates_send });
        self.pending = Pending::None;
        self.activated_at = None;
        self.release_time = None;
        self.enter_pending = None;
        if !activates_send {
            return;
        }
        if vk == VK_ENTER {
            // Enter is recorded separately, with the hook event's identity, by `note_enter_down`.
        } else {
            self.pending = Pending::Key(vk);
        }
    }

    /// The dialog's message loop is about to hand a `WM_KEYDOWN(VK_RETURN)` to `IsDialogMessageW`. `true` iff the hook recorded a genuine
    /// (never injected, Send focused) Enter DOWN that is still fresh, and consumes it: the caller then accepts Send's command ONLY while
    /// that one dispatch is running (a thread-local flag set around the call and cleared right after). Any other message, or an Enter
    /// the hook did not vouch for (a posted `WM_KEYDOWN`), gets `false`.
    ///
    /// The message is matched to the hook's event by IDENTITY, not by "an Enter while a record exists": `msg_time` (`MSG.time`) must equal
    /// the recorded `KBDLLHOOKSTRUCT.time`, `lparam`'s scan code (bits 16-23) must equal the recorded one, and the repeat flag (bit 30)
    /// must be clear. A message that does not match (a posted `WM_KEYDOWN(VK_RETURN)` queued ahead of the real one, say) neither
    /// consumes the record nor authorizes anything; the genuine message still can.
    pub fn begin_enter_dispatch(&mut self, now: Instant, msg_time: u32, lparam: isize, from_real_input: &dyn Fn() -> bool) -> bool {
        self.begin_enter_dispatch_why(now, msg_time, lparam, from_real_input).is_ok()
    }

    /// [`SendAuth::begin_enter_dispatch`] with the reason it refused (the decision itself is this one; the bool is derived from it).
    pub fn begin_enter_dispatch_why(
        &mut self,
        now: Instant,
        msg_time: u32,
        lparam: isize,
        from_real_input: &dyn Fn() -> bool,
    ) -> Result<(), EnterRefusal> {
        let Some(rec) = self.enter_pending else { return Err(EnterRefusal::NoRecord) };
        let scan = ((lparam >> 16) & 0xff) as u32;
        let repeat = (lparam >> 30) & 1 != 0;
        let age = now.saturating_duration_since(rec.at);
        if self.tainted {
            self.enter_pending = None;
            return Err(EnterRefusal::Tainted);
        }
        if age > ACTIVATION_FRESH {
            self.enter_pending = None;
            return Err(EnterRefusal::Stale { age_ms: age.as_millis() as u64 });
        }
        if msg_time != rec.time {
            return Err(EnterRefusal::TimeMismatch { msg: msg_time, hook: rec.time });
        }
        if scan != rec.scan {
            return Err(EnterRefusal::ScanMismatch);
        }
        if repeat {
            return Err(EnterRefusal::Repeat);
        }
        // Windows' own provenance for the message being processed (the dialog passes `InputOrigin::admits_enter`): an unknown origin or a
        // failed query refuses (fail closed). IMO_UNAVAILABLE is admitted on the identity matched above, because some real keyboards and mice
        // report it (see `InputOrigin`). Checked BEFORE the record is consumed, so a refused message neither consumes nor authorizes.
        if !from_real_input() {
            return Err(EnterRefusal::OriginNotReal);
        }
        self.enter_pending = None;
        Ok(())
    }

    /// Whether a release message that completes a Space or mouse gesture ON THE SEND BUTTON (`WM_KEYUP`/`WM_SYSKEYUP` of Space,
    /// `WM_LBUTTONUP`) is NOT vouched for. `from_real_input` is the dialog's [`InputOrigin::admits_release`]: an input-queue origin, or
    /// `IMO_UNAVAILABLE` bound by time stamp to the hook's genuine release ([`SendAuth::release_bound_to`]); anything else may be a posted or
    /// sent look-alike.
    /// `target_is_send`: the message's window is the Send button (the button holds the mouse capture, so its release is addressed to it
    /// wherever the pointer is).
    ///
    /// The message is still DELIVERED (the button must see its release, or it keeps the mouse capture and looks pressed while every later
    /// click goes to it: the operator's 1.3.19 dialog, 2026-11-04); the dialog only refuses the Send command that dispatch produces. This rule is ONLY
    /// about Send. A release addressed to anything else (Cancel, the note box, the caption) is never classified here, whatever its source:
    /// Cancel, Escape, closing, typing and focus changes must not depend on provenance. `true` = refuse Send for this dispatch. An API
    /// failure counts as unvouched (fail closed).
    pub fn unvouched_send_release(message: u32, wparam: usize, target_is_send: bool, from_real_input: &dyn Fn() -> bool) -> bool {
        const WM_KEYUP: u32 = 0x0101;
        const WM_SYSKEYUP: u32 = 0x0105;
        const WM_LBUTTONUP: u32 = 0x0202;
        const VK_SPACE: usize = 0x20;
        let release = ((message == WM_KEYUP || message == WM_SYSKEYUP) && wparam == VK_SPACE) || message == WM_LBUTTONUP;
        release && target_is_send && !from_real_input()
    }

    /// What a low-level hook event is. THIS PRODUCT's own input (`dwExtraInfo == RMT_INJECTED_TAG`, a technician's session) taints the whole
    /// dialog ([`SendAuth::note_injected`]). An injection by a LOWER-integrity process only voids the gesture in progress
    /// ([`SendAuth::note_disallowed`]): the flag names the injector's integrity, not who it works for, and a guest's own remapper or
    /// accessibility tool can raise it anywhere on the desktop (Codex release review, 1.3.20). Input that merely carries the OS "injected"
    /// flag is the guest's: that is what a guest's own remapper, macro or remote-control software (a KVM, Parsec, an on-screen keyboard)
    /// produces for every click of the guest's real mouse, and refusing it left such a guest unable to press Send (2026-11-04). The tag is
    /// not a security boundary (any process can set `dwExtraInfo`): the decision and its residual risk are written down in docs/64 (H-C7).
    pub fn classify_hook_event(extra_info: usize, lower_integrity_injected: bool) -> HookEvent {
        if extra_info == crate::input::RMT_INJECTED_TAG {
            HookEvent::Product
        } else if lower_integrity_injected {
            HookEvent::LowerIntegrity
        } else {
            HookEvent::Guest
        }
    }

    /// Applies a hook event's classification: [`HookEvent::Product`] taints, [`HookEvent::LowerIntegrity`] voids. `true` = the event is
    /// the guest's and the caller goes on to record it as part of a gesture.
    pub fn admit_hook_event(&mut self, event: HookEvent) -> bool {
        match event {
            HookEvent::Product => {
                self.note_injected();
                false
            }
            HookEvent::LowerIntegrity => {
                self.note_disallowed();
                false
            }
            HookEvent::Guest => true,
        }
    }

    /// The hook saw a genuine (never injected) Enter DOWN while Send has the focus: its time stamp and scan code identify it (see
    /// [`begin_enter_dispatch`](Self::begin_enter_dispatch)). Call after [`note_key_down`](Self::note_key_down) for the same event.
    pub fn note_enter_down(&mut self, at: Instant, time: u32, scan: u32) {
        self.enter_pending = Some(EnterRecord { at, time, scan });
    }

    /// A genuine key went UP. Completes the gesture only for the key that began it, with Send still focused.
    ///
    /// Enter's OWN release does not clear the Enter record. The low-level hook runs when the input happens, the message loop dequeues the
    /// `WM_KEYDOWN` later, so a quick press (a macro, a remapper, the Hyper-V console's key tap: down and up within a millisecond) delivers
    /// BOTH hook events before the loop sees the DOWN, and clearing on the release made Enter on a focused Send fail about half the time (VM,
    /// 2026-11-04). The record stays single-use, bound to the DOWN's time and scan code, vetted by `GetCurrentInputMessageSource`, and
    /// lapses after [`ACTIVATION_FRESH`]; any OTHER input still clears it.
    pub fn note_key_up(&mut self, vk: u32, activates_send: bool, at: Instant) {
        let complete = activates_send && self.pending == Pending::Key(vk);
        self.diag.note_step(GestureStep::KeyUp { activating: activates_send, completed: complete });
        self.pending = Pending::None;
        if vk != VK_ENTER {
            self.enter_pending = None;
        }
        self.activated_at = complete.then_some(at);
        self.release_time = None;
    }

    /// Whether the Send command being processed at `now` is backed by a completed genuine gesture. Consumes it.
    pub fn authorize(&mut self, now: Instant) -> bool {
        self.authorize_why(now).is_ok()
    }

    /// [`SendAuth::authorize`] with the reason it refused (the decision itself is this one; the bool is derived from it).
    pub fn authorize_why(&mut self, now: Instant) -> Result<(), GestureRefusal> {
        let at = self.activated_at.take();
        self.release_time = None;
        self.pending = Pending::None;
        if self.tainted {
            return Err(GestureRefusal::Tainted);
        }
        match at {
            None => Err(GestureRefusal::NoRecord),
            Some(t) => {
                let age = now.saturating_duration_since(t);
                if age <= ACTIVATION_FRESH {
                    Ok(())
                } else {
                    Err(GestureRefusal::Stale { age_ms: age.as_millis() as u64 })
                }
            }
        }
    }

    /// A hook event, judged ([`SendAuth::admit_hook_event`]) and also counted for the refusal log. `true` = the guest's.
    pub fn observe_hook_event(&mut self, event: HookEvent, info: HookInfo, now: Instant) -> bool {
        self.diag.count_event(info);
        match event {
            HookEvent::Product => self.diag.note_product(info, now),
            HookEvent::LowerIntegrity => self.diag.note_lower(info, now),
            HookEvent::Guest => {}
        }
        self.admit_hook_event(event)
    }

    /// Where the pointer was at the last press / release (for the refusal log only).
    pub fn note_hit(&mut self, under_pointer: isize, send: isize) {
        self.diag.note_hit(under_pointer, send);
    }

    /// A Send-bound release was dispatched and produced no command.
    pub fn note_release_without_command(&mut self) {
        self.diag.note_release_without_command();
    }

    pub fn diag(&self) -> &SendDiag {
        &self.diag
    }

    /// The single log line for a refusal (`None` = rate limited). Never contains note text.
    pub fn refusal_line(&mut self, now: Instant, r: Stashed, ctx: &LineContext) -> Option<String> {
        let tainted = self.tainted;
        self.diag.refusal_line(now, tainted, r, ctx)
    }
}
// ── Tray decision logic (no OS calls) ─────────────────────────────────────────────────────────────────────────────

/// An item the guest can choose from the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuChoice {
    Dismissed,
    RequestHelp,
    CancelRequest,
    /// "About DeskRally": what this icon is, and the agent's version. Read-only, so it needs no provenance.
    About,
}

/// Everything the tray does that the guest can SEE or that reads their input. The Win32 implementation lives in
/// `tray.rs`; tests use a double, so no window, menu or message box is ever opened by a test.
pub trait HelpUi {
    /// Show the menu for `view`. Returns the choice and whether the guest's OWN hardware input made it. When
    /// `view.available` is false the menu offers no help items, only a greyed line saying why and "About DeskRally"
    /// (menu wave 11: the icon is never dead).
    fn menu(&self, view: &HelpView) -> (MenuChoice, bool);
    /// Show the note dialog. Returns the note (`None` = cancelled) and whether the guest's OWN hardware input pressed Send.
    fn note_dialog(&self) -> (Option<String>, bool);
    /// Show the "About DeskRally" box.
    fn about(&self);
}

/// The greyed first line of the menu when help requests are not available on this connection.
pub const HELP_UNAVAILABLE_LINE: &str = "Help requests aren\u{2019}t available right now";

/// What a tray click did (for the log and the tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayOutcome {
    /// The feature is not available on this connection: the menu offered only the reason and "About DeskRally", and
    /// the guest dismissed it.
    UnavailableDismissed,
    /// The guest opened "About DeskRally".
    About,
    Dismissed,
    /// The choice or the Send was not the guest's own hardware input: nothing happened.
    InjectedIgnored,
    Requested,
    CancelSent,
    /// The guest cancelled the dialog or left the note box.
    DialogCancelled,
    RequestFailed(RequestError),
    CancelFailed(CancelError),
}

/// A left- or right-click on the tray icon.
pub fn run_tray_menu(hub: &HelpHub, ui: &dyn HelpUi, now: impl Fn() -> Instant) -> TrayOutcome {
    let view = hub.view(now());
    let (choice, by_guest) = ui.menu(&view);
    if choice == MenuChoice::About {
        ui.about();
        return TrayOutcome::About;
    }
    if !view.available {
        // Without the feature the menu has no help items; whatever else came back, nothing is requested or cancelled.
        return TrayOutcome::UnavailableDismissed;
    }
    if choice == MenuChoice::Dismissed {
        return TrayOutcome::Dismissed;
    }
    if !by_guest {
        tracing::warn!("help: tray menu choice ignored (not the guest's own input)");
        return TrayOutcome::InjectedIgnored;
    }
    match choice {
        MenuChoice::Dismissed | MenuChoice::About => TrayOutcome::Dismissed,
        MenuChoice::CancelRequest => match view.open_id.as_deref().map(|id| hub.cancel(id, now())).unwrap_or(Err(CancelError::NothingToCancel)) {
            Ok(()) => TrayOutcome::CancelSent,
            Err(e) => TrayOutcome::CancelFailed(e),
        },
        MenuChoice::RequestHelp => {
            // Offering the dialog is refused here too, not only by the menu item being greyed out.
            if !view.can_request {
                // The reason comes from the view: asking the hub to request would SEND if the state changed meanwhile.
                return TrayOutcome::RequestFailed(if !view.available {
                    RequestError::NotAvailable
                } else if view.phase != ViewPhase::Idle {
                    RequestError::AlreadyOpen
                } else {
                    RequestError::RateLimited(view.blocked_for.unwrap_or_default())
                });
            }
            let (note, by_guest) = ui.note_dialog();
            let Some(note) = note else { return TrayOutcome::DialogCancelled };
            if !by_guest {
                tracing::warn!("help: Send ignored (not the guest's own input)");
                return TrayOutcome::InjectedIgnored;
            }
            match hub.request(&note, now()) {
                Ok(()) => TrayOutcome::Requested,
                Err(e) => TrayOutcome::RequestFailed(e),
            }
        }
    }
}

/// Whether the connection's `Registered` listed the feature.
pub fn advertised(features: &[String]) -> bool {
    features.iter().any(|f| f == HELP_REQUEST_FEATURE)
}

#[cfg(test)]
#[path = "help_request_tests.rs"]
mod tests;
