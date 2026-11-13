//! Why a Send in the tray's help dialog was refused (docs/64 H-C7 diagnostics).
//!
//! The gate in `help_request::SendAuth` answers yes/no. On a real PC (1.3.20, the operator's machine) every Send was refused and the log said only "ignored",
//! so the failing condition could not be told apart (a voided gesture, a tainted dialog, an input origin outside the accepted set, a hook that
//! never fired...). This module holds the pure half of the answer: the typed refusal reasons, the counters the hooks keep, a bounded line
//! limiter and the formatting of the one log line per refusal. It decides nothing: no gate consults it, so it cannot weaken one.
//!
//! Privacy: a line carries counts, flags, extra-info values and message ids ONLY. No note text, no key identity (no virtual-key code, no
//! scan code), no typing rhythm (keys are counted only while they act on the Send button, so typing in the note box leaves no count), no
//! pointer coordinates.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    Mouse,
    Key,
}

/// What one low-level hook event looked like (never which key it was).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookInfo {
    pub kind: HookKind,
    pub message: u32,
    pub flags: u32,
    pub extra: usize,
}

impl HookInfo {
    pub fn mouse(message: u32, flags: u32, extra: usize) -> Self {
        Self { kind: HookKind::Mouse, message, flags, extra }
    }
    pub fn key(message: u32, flags: u32, extra: usize) -> Self {
        Self { kind: HookKind::Key, message, flags, extra }
    }
    fn fmt(&self, out: &mut String) {
        let k = if self.kind == HookKind::Mouse { "mouse" } else { "key" };
        let _ = write!(out, "{k} msg={:#x} flags={:#x} extra={:#x}", self.message, self.flags, self.extra);
    }
}

/// The last thing the gesture bookkeeping did with a genuine event (it explains a "no record" refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GestureStep {
    MouseDown { left: bool, over: bool },
    MouseUp { left: bool, over: bool, press_on_send: bool },
    /// `activating`: Enter or Space with Send focused (the only keys the log counts). Which key it was is never recorded.
    KeyDown { activating: bool },
    KeyUp { activating: bool, completed: bool },
    /// A product-tagged or lower-integrity event voided / tainted it.
    Voided(HookKind),
}

impl GestureStep {
    fn fmt(&self, out: &mut String) {
        let _ = match *self {
            GestureStep::MouseDown { left, over } => write!(out, "mouse_down(left={left} over_send={over})"),
            GestureStep::MouseUp { left, over, press_on_send } => {
                write!(out, "mouse_up(left={left} over_send={over} press_began_on_send={press_on_send})")
            }
            GestureStep::KeyDown { activating } => write!(out, "key_down(send_focused={activating})"),
            GestureStep::KeyUp { activating, completed } => {
                write!(out, "key_up(send_focused={activating} completed={completed})")
            }
            GestureStep::Voided(HookKind::Mouse) => write!(out, "voided_by_mouse_event"),
            GestureStep::Voided(HookKind::Key) => write!(out, "voided_by_key_event"),
        };
    }
}

/// Windows' answer to "where did the message being processed come from" (`GetCurrentInputMessageSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginProbe {
    pub origin: i32,
    pub device: i32,
    /// The HRESULT when the query failed.
    pub error: Option<i32>,
    /// Whether the gate accepted it (`help_dialog::origin_is_real_input`).
    pub real: bool,
}

/// The label suffix for a probe: empty for the gate's own answer to the refused message, `_at_log` for a fresh query made while logging (the
/// message has been dispatched by then, so it can differ from what the gate saw). The two must never be confused in the log.
pub fn probe_suffix(fresh_at_log: bool) -> &'static str {
    if fresh_at_log {
        "_at_log"
    } else {
        ""
    }
}

impl OriginProbe {
    fn fmt(&self, out: &mut String, sfx: &str) {
        match self.error {
            Some(e) => {
                let _ = write!(out, "origin{sfx}=query_failed({:#x})", e as u32);
            }
            None => {
                let name = match self.origin {
                    0 => "unavailable",
                    1 => "hardware",
                    2 => "injected",
                    4 => "system",
                    _ => "unknown",
                };
                let _ = write!(out, "origin{sfx}={}({name}) device{sfx}={} accepted{sfx}={}", self.origin, self.device, self.real);
            }
        }
    }
}

/// Which field of the Enter identity check disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterRefusal {
    /// The hook recorded no Enter on a focused Send (the hook never fired, Send was not focused when it did, or another event cleared it).
    NoRecord,
    Tainted,
    Stale { age_ms: u64 },
    TimeMismatch { msg: u32, hook: u32 },
    /// The message's scan code differs from the recorded one (the values are a key identity and are never logged).
    ScanMismatch,
    Repeat,
    /// Windows did not report hardware / injected / system origin for the message (the probe says what it did report).
    OriginNotReal,
}

/// Why a completed mouse / Space gesture was not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GestureRefusal {
    Tainted,
    NoRecord,
    Stale { age_ms: u64 },
}

/// Every way a Send can be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The `WM_COMMAND` did not name the Send button as its sender.
    CommandNotFromSend,
    /// A command that arrived outside the dispatch of an Enter / release the loop vouched for (posted or sent straight to the window).
    CommandOutsideDispatch,
    /// A Space / left-button release addressed to Send whose input-queue origin was not accepted.
    ReleaseUnvouched,
    Gesture(GestureRefusal),
    Enter(EnterRefusal),
}

impl Refusal {
    /// The stable code the operator greps for.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::CommandNotFromSend => "command_not_from_send_button",
            Refusal::CommandOutsideDispatch => "command_outside_vouched_dispatch",
            Refusal::ReleaseUnvouched => "release_origin_not_accepted",
            Refusal::Gesture(GestureRefusal::Tainted) => "gesture_dialog_tainted",
            Refusal::Gesture(GestureRefusal::NoRecord) => "gesture_no_hook_record",
            Refusal::Gesture(GestureRefusal::Stale { .. }) => "gesture_record_stale",
            Refusal::Enter(EnterRefusal::NoRecord) => "enter_no_hook_record",
            Refusal::Enter(EnterRefusal::Tainted) => "enter_dialog_tainted",
            Refusal::Enter(EnterRefusal::Stale { .. }) => "enter_record_stale",
            Refusal::Enter(EnterRefusal::TimeMismatch { .. }) => "enter_time_mismatch",
            Refusal::Enter(EnterRefusal::ScanMismatch) => "enter_scan_mismatch",
            Refusal::Enter(EnterRefusal::Repeat) => "enter_is_autorepeat",
            Refusal::Enter(EnterRefusal::OriginNotReal) => "enter_origin_not_accepted",
        }
    }
    fn detail(&self, out: &mut String) {
        let _ = match *self {
            Refusal::Gesture(GestureRefusal::Stale { age_ms }) | Refusal::Enter(EnterRefusal::Stale { age_ms }) => write!(out, " age_ms={age_ms}"),
            Refusal::Enter(EnterRefusal::TimeMismatch { msg, hook }) => write!(out, " message={msg:#x} hook={hook:#x}"),
            _ => Ok(()),
        };
    }
}

/// Which path produced the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Command,
    Enter,
    Release,
}

/// A refusal the message loop noticed BEFORE the command arrived (or in place of one).
pub type Stashed = (Refusal, Via);

/// Combines the command's own verdict with what the loop noticed before dispatching. A command outside any vouched dispatch is where the
/// loop's earlier finding (an Enter without a record, an unvouched release) is the real reason; every other verdict stands as it is.
pub fn reconcile(decision: Refusal, in_vouched_release: bool, stash: Option<Stashed>) -> Stashed {
    match (decision, stash) {
        (Refusal::CommandOutsideDispatch, Some(s)) => s,
        (d, _) => (d, if in_vouched_release { Via::Release } else { Via::Command }),
    }
}

/// Whether a refusal the loop noticed, but that no command picked up, deserves a line. A plain Enter in the note box or on Cancel is an
/// expected non-event (it only matters with the focus on Send); logging it would spend the burst budget and could suppress a real refusal.
pub fn undelivered_worth_logging(via: Via, focus_on_send: bool) -> bool {
    via != Via::Enter || focus_on_send
}

/// What the dialog observed around the refusal (all optional: a value it could not read is simply absent).
#[derive(Debug, Clone, Copy, Default)]
pub struct LineContext {
    pub probe: Option<OriginProbe>,
    /// `probe` was queried while logging, not by the gate for the refused message (see [`probe_suffix`]).
    pub probe_fresh_at_log: bool,
    pub focus_on_send: Option<bool>,
    pub foreground_is_dialog: Option<bool>,
    /// For a release refusal: the message's time stamp and the hook's time stamp of the release that completed a gesture (`None`: no gesture
    /// was completed). An `IMO_UNAVAILABLE` release is admitted only when the message is stamped at, or at most `RELEASE_BIND_SLACK_MS` (250)
    /// after, the hook's time stamp (modulo the tick wrap), so a gap outside that window here is the reason.
    pub release_times: Option<(u32, Option<u32>)>,
}

/// Counters since the dialog opened.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub mouse_events: u32,
    pub mouse_clicks: u32,
    pub key_events: u32,
    pub key_downs: u32,
    pub product_events: u32,
    pub lower_il_events: u32,
    pub releases_without_command: u32,
    /// Send-bound releases with no stated origin (`IMO_UNAVAILABLE`) that were admitted on the hook binding, and the largest gap between the
    /// message's time stamp and the hook's that one of them had (what the binding window is measured against on a real machine).
    pub unavailable_admitted: u32,
    pub max_bind_delta_ms: u32,
}

fn bump(c: &mut u32) {
    *c = c.saturating_add(1);
}

/// At most [`BURST_LINES`] lines at once, then one per [`SPACING`], and never more than [`MAX_LINES`] for the dialog's life: a stuck key
/// cannot flood the log. Suppressed refusals are counted and reported on the next line that gets through.
#[derive(Debug, Default)]
pub struct LineLimit {
    emitted: u32,
    suppressed_since: u32,
    pub suppressed_total: u32,
    last: Option<Instant>,
}

pub const BURST_LINES: u32 = 6;
pub const MAX_LINES: u32 = 30;
pub const SPACING: Duration = Duration::from_secs(3);

impl LineLimit {
    /// `Some(n)` = log it, `n` refusals were suppressed since the previous line; `None` = suppressed.
    pub fn admit(&mut self, now: Instant) -> Option<u32> {
        let spaced = self.last.is_none_or(|t| now.saturating_duration_since(t) >= SPACING);
        if self.emitted >= MAX_LINES || (self.emitted >= BURST_LINES && !spaced) {
            bump(&mut self.suppressed_since);
            bump(&mut self.suppressed_total);
            return None;
        }
        self.emitted += 1;
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed_since))
    }
    pub fn emitted(&self) -> u32 {
        self.emitted
    }
}

/// Everything the hooks and the loop saw, kept for the dialog's life.
#[derive(Debug, Default)]
pub struct SendDiag {
    pub counters: Counters,
    first_product: Option<(HookInfo, Instant)>,
    last_lower: Option<(HookInfo, Instant)>,
    last_step: Option<GestureStep>,
    /// `(window under the pointer, the Send button)` at the last mouse press / release.
    last_hit: Option<(isize, isize)>,
    limit: LineLimit,
}

impl SendDiag {
    pub fn count_event(&mut self, info: HookInfo) {
        // Keys are NOT counted here: only a key that acts on Send is (see `note_step`). A count of every key, or of Space, would reveal the
        // length of the typed note.
        if info.kind == HookKind::Mouse {
            bump(&mut self.counters.mouse_events);
        }
    }
    pub fn note_product(&mut self, info: HookInfo, now: Instant) {
        bump(&mut self.counters.product_events);
        self.first_product.get_or_insert((info, now));
        self.last_step = Some(GestureStep::Voided(info.kind));
    }
    pub fn note_lower(&mut self, info: HookInfo, now: Instant) {
        bump(&mut self.counters.lower_il_events);
        self.last_lower = Some((info, now));
        self.last_step = Some(GestureStep::Voided(info.kind));
    }
    pub fn note_step(&mut self, step: GestureStep) {
        match step {
            GestureStep::MouseDown { .. } => bump(&mut self.counters.mouse_clicks),
            GestureStep::KeyDown { activating: true } => {
                bump(&mut self.counters.key_events);
                bump(&mut self.counters.key_downs);
            }
            GestureStep::KeyUp { activating: true, .. } => bump(&mut self.counters.key_events),
            _ => {}
        }
        self.last_step = Some(step);
    }
    pub fn note_hit(&mut self, under_pointer: isize, send: isize) {
        self.last_hit = Some((under_pointer, send));
    }
    pub fn note_release_without_command(&mut self) {
        bump(&mut self.counters.releases_without_command);
    }
    pub fn note_unavailable_admitted(&mut self, delta_ms: u32) {
        bump(&mut self.counters.unavailable_admitted);
        self.counters.max_bind_delta_ms = self.counters.max_bind_delta_ms.max(delta_ms);
    }
    pub fn suppressed_total(&self) -> u32 {
        self.limit.suppressed_total
    }
    pub fn lines_emitted(&self) -> u32 {
        self.limit.emitted()
    }

    /// The one line for a refusal, or `None` when the limiter holds it back.
    pub fn refusal_line(&mut self, now: Instant, tainted: bool, r: Stashed, ctx: &LineContext) -> Option<String> {
        let suppressed = self.limit.admit(now)?;
        let (refusal, via) = r;
        let mut s = String::with_capacity(320);
        let via = match via {
            Via::Command => "command",
            Via::Enter => "enter",
            Via::Release => "release",
        };
        let _ = write!(s, "help: Send refused #{}: reason={}", self.limit.emitted(), refusal.code());
        refusal.detail(&mut s);
        let _ = write!(s, " via={via} tainted={tainted}");
        if let Some(f) = ctx.focus_on_send {
            let _ = write!(s, " send_focused={f}");
        }
        if let Some(f) = ctx.foreground_is_dialog {
            let _ = write!(s, " dialog_foreground={f}");
        }
        if let Some(p) = &ctx.probe {
            s.push(' ');
            p.fmt(&mut s, probe_suffix(ctx.probe_fresh_at_log));
        }
        if let Some((msg, hook)) = ctx.release_times {
            match hook {
                Some(h) => {
                    let _ = write!(s, " msg_time={msg} hook_release_time={h}");
                }
                None => {
                    let _ = write!(s, " msg_time={msg} hook_release_time=none");
                }
            }
        }
        if let Some(step) = &self.last_step {
            s.push_str(" last_step=");
            step.fmt(&mut s);
        }
        if let Some((hit, send)) = self.last_hit {
            let _ = write!(s, " last_hit_window={hit:#x} send_button={send:#x}");
        }
        let c = &self.counters;
        let _ = write!(
            s,
            " seen[mouse={} clicks={} gate_keys={} gate_key_downs={}] taints={} voids={}",
            c.mouse_events, c.mouse_clicks, c.key_events, c.key_downs, c.product_events, c.lower_il_events
        );
        if let Some((info, at)) = &self.first_product {
            s.push_str(" first_taint=");
            info.fmt(&mut s);
            let _ = write!(s, " taint_ago_ms={}", now.saturating_duration_since(*at).as_millis());
        }
        if let Some((info, at)) = &self.last_lower {
            s.push_str(" last_void=");
            info.fmt(&mut s);
            let _ = write!(s, " void_ago_ms={}", now.saturating_duration_since(*at).as_millis());
        }
        if suppressed > 0 {
            let _ = write!(s, " (+{suppressed} suppressed)");
        }
        Some(s)
    }

    /// The line logged when the dialog closes, with what start-up could not log (see [`Startup`]).
    pub fn summary_line(&self, startup: &Startup, outcome: &str, open_ms: u128) -> String {
        let c = &self.counters;
        let mut s = format!(
            "help: dialog closed outcome={outcome} open_ms={open_ms} seen[mouse={} clicks={} gate_keys={} gate_key_downs={}] taints={} voids={} releases_without_command={} unavailable_admitted={} max_bind_delta_ms={} refusal_lines={} suppressed={}",
            c.mouse_events,
            c.mouse_clicks,
            c.key_events,
            c.key_downs,
            c.product_events,
            c.lower_il_events,
            c.releases_without_command,
            c.unavailable_admitted,
            c.max_bind_delta_ms,
            self.limit.emitted(),
            self.limit.suppressed_total
        );
        startup.fmt(&mut s);
        s
    }
}

/// The mandatory-integrity RID as a word.
pub fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000..=0x0FFF => "untrusted",
        0x1000..=0x1FFF => "low",
        0x2000..=0x2FFF => "medium",
        0x3000..=0x3FFF => "high",
        0x4000..=0x4FFF => "system",
        _ => "other",
    }
}

/// What the dialog's start-up did while the low-level hooks were live. A hooked thread that is not pumping stalls every process's input
/// until `LowLevelHooksTimeout`, so none of it is logged then: it is reported in the closing line instead.
#[derive(Debug, Clone, Copy)]
pub struct Startup {
    pub mouse_hook: Result<(), i32>,
    pub kbd_hook: Result<(), i32>,
    /// `None` = the dialog was never shown, so no foreground was requested.
    pub foreground_granted: Option<bool>,
}

impl Startup {
    fn fmt(&self, out: &mut String) {
        fn hook(r: Result<(), i32>) -> String {
            match r {
                Ok(()) => "ok".to_string(),
                Err(e) => format!("failed({:#x})", e as u32),
            }
        }
        let fg = self.foreground_granted.map_or("not_requested".to_string(), |g| g.to_string());
        let _ = write!(out, " hooks[mouse={} keyboard={}] foreground_granted={fg}", hook(self.mouse_hook), hook(self.kbd_hook));
    }
}

/// The line logged BEFORE the hooks are installed: who this process is. (The hook results follow in the closing line.)
pub fn open_line(integrity_rid: Option<u32>, session: Option<u32>) -> String {
    let il = integrity_rid.map_or("unknown".to_string(), |r| format!("{r:#x}({})", integrity_name(r)));
    let sess = session.map_or("unknown".to_string(), |s| s.to_string());
    format!("help: dialog opening process_integrity={il} session={sess}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> LineContext {
        LineContext {
            probe: Some(OriginProbe { origin: 2, device: 1, error: None, real: true }),
            probe_fresh_at_log: false,
            focus_on_send: Some(true),
            foreground_is_dialog: Some(true),
            release_times: None,
        }
    }

    #[test]
    fn no_key_identity_reaches_the_log() {
        let mut d = SendDiag::default();
        d.note_lower(HookInfo::key(0x100, 2, 7), Instant::now());
        d.note_step(GestureStep::KeyDown { activating: true });
        let down = d.refusal_line(Instant::now(), false, (Refusal::Gesture(GestureRefusal::NoRecord), Via::Release), &LineContext::default()).unwrap();
        assert!(down.contains("last_step=key_down(send_focused=true)"), "{down}");
        assert!(!down.contains("vk"), "no virtual-key code may be logged: {down}");
        d.note_step(GestureStep::KeyUp { activating: true, completed: true });
        let line = d.refusal_line(Instant::now(), false, (Refusal::Gesture(GestureRefusal::NoRecord), Via::Release), &LineContext::default()).unwrap();
        assert!(line.contains("last_void=key msg=0x100 flags=0x2 extra=0x7"), "{line}");
        assert!(line.contains("last_step=key_up(send_focused=true completed=true)"), "{line}");
        assert!(!line.contains("vk"), "no virtual-key code may be logged: {line}");
    }

    #[test]
    fn a_line_names_the_reason_the_counters_and_the_void() {
        let t0 = Instant::now();
        let mut d = SendDiag::default();
        for _ in 0..14 {
            d.count_event(HookInfo::mouse(0x200, 0, 0));
        }
        d.note_step(GestureStep::MouseDown { left: true, over: true });
        d.note_hit(0x3a05c, 0x4023e);
        d.note_lower(HookInfo::mouse(0x200, 0x2, 0xff), t0);
        d.note_step(GestureStep::MouseUp { left: true, over: false, press_on_send: false });
        let l = d.refusal_line(t0 + Duration::from_millis(40), false, (Refusal::Gesture(GestureRefusal::NoRecord), Via::Release), &ctx()).unwrap();
        for needle in [
            "reason=gesture_no_hook_record",
            "via=release",
            "tainted=false",
            "send_focused=true",
            "origin=2(injected) device=1 accepted=true",
            "last_step=mouse_up(left=true over_send=false press_began_on_send=false)",
            "last_hit_window=0x3a05c send_button=0x4023e",
            "seen[mouse=14 clicks=1 gate_keys=0 gate_key_downs=0]",
            "voids=1",
            "last_void=mouse msg=0x200 flags=0x2 extra=0xff void_ago_ms=40",
        ] {
            assert!(l.contains(needle), "missing {needle:?} in {l}");
        }
        assert!(!l.contains('\n'), "one line");
    }

    // One test per reason: each must produce its own code, and the details the operator needs.
    #[test]
    fn every_reason_has_a_distinct_code_and_its_details() {
        let all = [
            (Refusal::CommandNotFromSend, "command_not_from_send_button", ""),
            (Refusal::CommandOutsideDispatch, "command_outside_vouched_dispatch", ""),
            (Refusal::ReleaseUnvouched, "release_origin_not_accepted", ""),
            (Refusal::Gesture(GestureRefusal::Tainted), "gesture_dialog_tainted", ""),
            (Refusal::Gesture(GestureRefusal::NoRecord), "gesture_no_hook_record", ""),
            (Refusal::Gesture(GestureRefusal::Stale { age_ms: 2500 }), "gesture_record_stale", "age_ms=2500"),
            (Refusal::Enter(EnterRefusal::NoRecord), "enter_no_hook_record", ""),
            (Refusal::Enter(EnterRefusal::Tainted), "enter_dialog_tainted", ""),
            (Refusal::Enter(EnterRefusal::Stale { age_ms: 2100 }), "enter_record_stale", "age_ms=2100"),
            (Refusal::Enter(EnterRefusal::TimeMismatch { msg: 0x1389, hook: 0x1388 }), "enter_time_mismatch", "message=0x1389 hook=0x1388"),
            (Refusal::Enter(EnterRefusal::ScanMismatch), "enter_scan_mismatch", ""),
            (Refusal::Enter(EnterRefusal::Repeat), "enter_is_autorepeat", ""),
            (Refusal::Enter(EnterRefusal::OriginNotReal), "enter_origin_not_accepted", ""),
        ];
        let mut codes: Vec<&str> = all.iter().map(|(r, _, _)| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "codes must be distinct");
        for (r, code, detail) in all {
            let l = SendDiag::default().refusal_line(Instant::now(), false, (r, Via::Command), &LineContext::default()).unwrap();
            assert!(l.contains(&format!("reason={code}")), "{l}");
            assert!(detail.is_empty() || l.contains(detail), "{detail} in {l}");
            assert!(!l.contains("scan") || code == "enter_scan_mismatch", "{l}");
            if code == "enter_scan_mismatch" {
                assert!(!l.contains("hook=") && !l.contains("message="), "a scan code is a key identity and is not logged: {l}");
            }
        }
    }

    // The closing line counts releases admitted on the hook binding and the widest gap seen, so a canary run measures the window.
    #[test]
    fn the_closing_line_reports_releases_admitted_on_the_binding() {
        let su = Startup { mouse_hook: Ok(()), kbd_hook: Ok(()), foreground_granted: Some(true) };
        let mut d = SendDiag::default();
        assert!(d.summary_line(&su, "cancel", 1).contains(" unavailable_admitted=0 max_bind_delta_ms=0 "));
        d.note_unavailable_admitted(3);
        d.note_unavailable_admitted(0);
        let l = d.summary_line(&su, "send", 1);
        assert!(l.contains(" unavailable_admitted=2 max_bind_delta_ms=3 "), "{l}");
    }

    // A refused release says which time stamps the binding compared (1.3.22: an IMO_UNAVAILABLE release is admitted only within 0-250 ms after the hook's).
    #[test]
    fn a_release_refusal_shows_the_compared_time_stamps() {
        let line = |times| {
            let ctx = LineContext { release_times: times, ..Default::default() };
            SendDiag::default().refusal_line(Instant::now(), false, (Refusal::ReleaseUnvouched, Via::Release), &ctx).unwrap()
        };
        let l = line(Some((1000, Some(999))));
        assert!(l.contains(" msg_time=1000 hook_release_time=999"), "{l}");
        let l = line(Some((1000, None)));
        assert!(l.contains(" msg_time=1000 hook_release_time=none"), "{l}");
        let l = line(None);
        assert!(!l.contains("msg_time="), "absent for a non-release refusal: {l}");
    }

    #[test]
    fn a_tainted_dialog_names_the_event_that_tainted_it_and_the_origin_failure_is_shown() {
        let t0 = Instant::now();
        let mut d = SendDiag::default();
        d.note_product(HookInfo::key(0x100, 0, 0x5244_4d52), t0);
        d.note_product(HookInfo::mouse(0x201, 0, 0x5244_4d52), t0 + Duration::from_secs(1));
        let c = LineContext { probe: Some(OriginProbe { origin: -1, device: -1, error: Some(0x80070005u32 as i32), real: false }), ..Default::default() };
        let l = d.refusal_line(t0 + Duration::from_secs(2), true, (Refusal::Gesture(GestureRefusal::Tainted), Via::Release), &c).unwrap();
        assert!(l.contains("tainted=true") && l.contains("taints=2"), "{l}");
        assert!(l.contains("first_taint=key msg=0x100 flags=0x0 extra=0x52444d52 taint_ago_ms=2000"), "{l}");
        assert!(!l.contains("vk"), "{l}");
        assert!(l.contains("origin=query_failed(0x80070005)"), "{l}");
    }

    #[test]
    fn a_stuck_key_cannot_flood_the_log() {
        let t0 = Instant::now();
        let mut lim = LineLimit::default();
        let ms = Duration::from_millis;
        // A burst of BURST_LINES, then nothing within SPACING.
        for i in 0..BURST_LINES {
            assert_eq!(lim.admit(t0 + ms(u64::from(i))), Some(0));
        }
        for i in 0..1000 {
            assert_eq!(lim.admit(t0 + ms(100 + i)), None, "suppressed inside the spacing window");
        }
        // After the spacing one gets through and reports how many were held back.
        assert_eq!(lim.admit(t0 + SPACING + ms(10)), Some(1000));
        // Never more than MAX_LINES, however slowly.
        let mut n = BURST_LINES + 1;
        let mut t = t0 + SPACING + ms(10);
        for _ in 0..200 {
            t += SPACING;
            if lim.admit(t).is_some() {
                n += 1;
            }
        }
        assert_eq!(n, MAX_LINES);
        assert_eq!(lim.emitted(), MAX_LINES);
        assert!(lim.suppressed_total > 1000);
    }

    #[test]
    fn the_limiter_state_shows_in_the_line_and_the_summary() {
        let t0 = Instant::now();
        let mut d = SendDiag::default();
        let r = (Refusal::CommandOutsideDispatch, Via::Command);
        for i in 0..BURST_LINES {
            assert!(d.refusal_line(t0 + Duration::from_millis(u64::from(i)), false, r, &LineContext::default()).is_some());
        }
        assert!(d.refusal_line(t0 + Duration::from_millis(50), false, r, &LineContext::default()).is_none());
        let l = d.refusal_line(t0 + SPACING + Duration::from_millis(60), false, r, &LineContext::default()).unwrap();
        assert!(l.ends_with("(+1 suppressed)"), "{l}");
        let s = d.summary_line(&Startup { mouse_hook: Ok(()), kbd_hook: Ok(()), foreground_granted: Some(true) }, "cancel", 4321);
        assert!(s.contains("outcome=cancel open_ms=4321") && s.contains("refusal_lines=7 suppressed=1"), "{s}");
    }

    #[test]
    fn the_loops_earlier_finding_is_the_reason_only_for_an_unvouched_command() {
        let enter = (Refusal::Enter(EnterRefusal::NoRecord), Via::Enter);
        assert_eq!(reconcile(Refusal::CommandOutsideDispatch, false, Some(enter)), enter);
        assert_eq!(reconcile(Refusal::CommandOutsideDispatch, false, None), (Refusal::CommandOutsideDispatch, Via::Command));
        // A verdict of its own (the gesture, the sender) is never replaced by a stash.
        let g = Refusal::Gesture(GestureRefusal::NoRecord);
        assert_eq!(reconcile(g, true, Some(enter)), (g, Via::Release));
        assert_eq!(reconcile(Refusal::CommandNotFromSend, false, Some(enter)), (Refusal::CommandNotFromSend, Via::Command));
    }

    #[test]
    fn the_open_line_is_about_the_process_and_the_closing_line_carries_the_start_up_facts() {
        assert_eq!(open_line(Some(0x4000), Some(1)), "help: dialog opening process_integrity=0x4000(system) session=1");
        assert!(open_line(None, None).ends_with("process_integrity=unknown session=unknown"));
        assert!(!open_line(Some(0x2000), Some(1)).contains("hooks"), "the hooks are not installed yet when this is logged");
        assert_eq!(integrity_name(0x2000), "medium");
        assert_eq!(integrity_name(0x3000), "high");
        let su = Startup { mouse_hook: Ok(()), kbd_hook: Err(0x5), foreground_granted: Some(false) };
        let l = SendDiag::default().summary_line(&su, "closed", 12);
        assert!(l.ends_with(" hooks[mouse=ok keyboard=failed(0x5)] foreground_granted=false"), "{l}");
        let shown = Startup { mouse_hook: Ok(()), kbd_hook: Ok(()), foreground_granted: None };
        assert!(SendDiag::default().summary_line(&shown, "cancel", 1).ends_with("hooks[mouse=ok keyboard=ok] foreground_granted=not_requested"));
    }

    #[test]
    fn a_fresh_probe_at_log_time_is_labelled_apart_from_the_gates_own() {
        let mut p = OriginProbe { origin: 1, device: 2, error: None, real: true };
        let own = LineContext { probe: Some(p), ..Default::default() };
        let l = SendDiag::default().refusal_line(Instant::now(), false, (Refusal::CommandOutsideDispatch, Via::Command), &own).unwrap();
        assert!(l.contains(" origin=1(hardware) device=2 accepted=true") && !l.contains("_at_log"), "{l}");
        let late = LineContext { probe: Some(p), probe_fresh_at_log: true, ..Default::default() };
        let l = SendDiag::default().refusal_line(Instant::now(), false, (Refusal::CommandOutsideDispatch, Via::Command), &late).unwrap();
        assert!(l.contains(" origin_at_log=1(hardware) device_at_log=2 accepted_at_log=true"), "{l}");
        assert!(!l.contains(" origin="), "{l}");
        p = OriginProbe { origin: -1, device: -1, error: Some(5), real: false };
        let late = LineContext { probe: Some(p), probe_fresh_at_log: true, ..Default::default() };
        let l = SendDiag::default().refusal_line(Instant::now(), false, (Refusal::CommandOutsideDispatch, Via::Command), &late).unwrap();
        assert!(l.contains("origin_at_log=query_failed(0x5)"), "{l}");
    }

    #[test]
    fn only_keys_acting_on_send_are_counted_never_the_typing() {
        let mut d = SendDiag::default();
        // Typing in the note box, Space included (a Space count would approximate the word count): hook events and steps with Send NOT focused.
        for _ in 0..50 {
            d.count_event(HookInfo::key(0x100, 0, 0));
            d.note_step(GestureStep::KeyDown { activating: false });
            d.count_event(HookInfo::key(0x101, 0, 0));
            d.note_step(GestureStep::KeyUp { activating: false, completed: false });
        }
        assert_eq!((d.counters.key_events, d.counters.key_downs), (0, 0), "typing leaves no count (note length / word count must not leak)");
        let line = d.refusal_line(Instant::now(), false, (Refusal::CommandOutsideDispatch, Via::Command), &LineContext::default()).unwrap();
        assert!(line.contains("gate_keys=0 gate_key_downs=0"), "{line}");
        // Enter / Space with Send focused is counted.
        d.count_event(HookInfo::key(0x100, 0, 0));
        d.note_step(GestureStep::KeyDown { activating: true });
        d.note_step(GestureStep::KeyUp { activating: true, completed: true });
        assert_eq!((d.counters.key_events, d.counters.key_downs), (2, 1));
    }

    #[test]
    fn a_click_is_counted_once_not_for_its_release_too() {
        let mut d = SendDiag::default();
        d.note_step(GestureStep::MouseDown { left: true, over: true });
        d.note_step(GestureStep::MouseUp { left: true, over: true, press_on_send: true });
        assert_eq!(d.counters.mouse_clicks, 1);
    }

    #[test]
    fn an_enter_that_no_command_took_is_logged_only_with_the_focus_on_send() {
        // Plain Enter in the note box / on Cancel is an expected non-event: no line, no burst budget spent.
        assert!(!undelivered_worth_logging(Via::Enter, false));
        assert!(undelivered_worth_logging(Via::Enter, true));
        // A release that clicked nothing is worth a line wherever the focus is.
        assert!(undelivered_worth_logging(Via::Release, false));
        assert!(undelivered_worth_logging(Via::Command, false));
    }
}
