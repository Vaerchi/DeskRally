//! The **guest-facing window**: what the person sitting at the controlled machine sees and types.
//!
//! This is the pure model. It owns no window, no thread and no clock — the Win32 shell in
//! `rmt_agent_windows::guest_window` draws whatever this says and feeds it events. Everything worth
//! arguing about (what the banner claims, when a line is shown, what a guest is allowed to type,
//! whether a message may still be sent) is decided here, where it is testable without a desktop.
//!
//! # One window, two checklist lines
//!
//! docs/01 §5 wants an on-screen "session active" indicator; docs/01 §7 wants guest-side chat. They
//! are deliberately the same window, because they are the same conversation: *something is
//! happening to your computer, here is who is doing it, here is how you talk to them.* Two windows
//! would mean two message pumps, two teardowns, and a "session active" badge the guest can move
//! away from the chat that explains it.
//!
//! # Why the guest's own line is not shown until the transcript posts it
//!
//! [`GuestEvent::Submit`] returns [`GuestCommand::SendChat`] and appends **nothing**. The line
//! appears when it comes back as [`GuestEvent::Posted`], carrying the sequence number and timestamp
//! the agent's [`crate::chat::Transcript`] assigned it. This is the same rule the browser controller
//! follows (`ChatClient.send` adds nothing locally), and for the same reason: the transcript is the
//! single ordering authority, so a local optimistic append is a second, unnumbered copy that
//! duplicates or reorders the moment the real one lands.
//!
//! # Why the technician's text is sanitized here
//!
//! A chat body is written by the remote party and drawn on the guest's screen. Without
//! [`crate::text::sanitize_display`] a single `U+202E` in a technician's message reverses the
//! rendering of the window — including the banner naming who is in control. See [`crate::text`].

use std::collections::VecDeque;

use crate::chat::{ChatFrom, MAX_BODY_CHARS};
use crate::text::sanitize_display;

/// How many chat lines the window keeps on screen.
///
/// Smaller than [`crate::chat::MAX_TRANSCRIPT`] (500) on purpose: the agent's transcript is the
/// durable record that survives reconnects, while this is a scrollback the guest reads during one
/// session. The window is small and nobody scrolls back 500 lines in it.
pub const MAX_VISIBLE_LINES: usize = 200;

/// Longest banner field (host, reason) the window renders.
///
/// The banner is one or two lines in a small window; past this the text that matters — *who has
/// control of this machine* — is pushed out of view, which is the failure the cap exists to stop.
pub const MAX_BANNER_CHARS: usize = 120;

/// What the window is currently telling the guest.
///
/// [`SessionPhase::Ended`] is [`Default`] deliberately. A default-constructed presenter must claim
/// the *least* — a window that defaults to "ACTIVE" would assert a remote party has control of the
/// machine when nothing has said so, and this repo has already shipped one permissive `Default`
/// (the `Option` whose `None` granted all 19 backstage capabilities, docs/07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPhase {
    /// A technician is connected right now.
    Active,
    /// The session is over. Nothing more can be sent.
    #[default]
    Ended,
}

/// One line as the guest sees it. Already sanitized and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLine {
    /// Who wrote it.
    pub from: ChatFrom,
    /// The text, sanitized for display and capped at [`MAX_BODY_CHARS`].
    pub body: String,
    /// Unix milliseconds the agent's transcript recorded it at.
    pub at_unix_ms: i64,
}

/// Everything the window needs to say *who* is doing this.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionInfo {
    /// Host (with port) of the control plane that brokered this session, for display.
    ///
    /// Empty is legal and is rendered as "unknown", never omitted — see [`GuestPresenter::detail`].
    pub control_plane_host: String,
    /// The reason the technician gave, if any. Attacker-controlled; sanitized on the way in.
    pub reason: String,
}

/// Something that happened, folded into the presenter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestEvent {
    /// The agent's transcript recorded a line — from either side. This is the ONLY way a line ever
    /// reaches the window, including the guest's own (see the module doc).
    Posted {
        /// Who wrote it, as the transcript decided.
        from: ChatFrom,
        /// The recorded body.
        body: String,
        /// The recorded timestamp.
        at_unix_ms: i64,
    },
    /// The guest typed a character into the compose box.
    Typed(char),
    /// The guest pressed Backspace.
    Backspace,
    /// The guest pressed Enter (without Shift).
    Submit,
    /// A line replayed from the persisted transcript as the window opened.
    ///
    /// Shown exactly like [`GuestEvent::Posted`] but **never counted as unread**. A badge claims
    /// something arrived while the guest was not looking; text that predates the window is text the
    /// guest cannot have missed, so a machine with a long support history would otherwise open
    /// announcing "47 unread" for last week's conversation.
    Seeded {
        /// Who wrote it.
        from: ChatFrom,
        /// The recorded body.
        body: String,
        /// The recorded timestamp.
        at_unix_ms: i64,
    },
    /// The window came to the foreground, or the guest clicked into it.
    Focused,
    /// The window lost the foreground.
    ///
    /// Without this the unread counter is dead for the rest of the session after the guest's first
    /// click: `focused` latches true and every later message counts as already-read.
    Blurred,
    /// The guest clicked the window's **End session** button.
    ///
    /// This is the guest exercising control over their own machine — docs/12 §5 asks for it, and
    /// before it existed the only affordance was closing the window, which did NOT stop the session.
    /// Distinct from [`GuestEvent::Ended`], which is the session reporting that it is *already* over.
    EndClicked,
    /// The session ended — the technician disconnected, or the agent tore the session down.
    Ended,
    /// The controller toggled view-only for this session (loops 30–32): `true` ⇒ the technician is
    /// now WATCHING only (their injected input is dropped by the agent), `false` ⇒ they are
    /// CONTROLLING again. Folded so the guest's headline can tell the two apart — the on-screen
    /// consent signal that a view-only session is not a control session. A change repaints; a no-op
    /// (the same state re-asserted) does not.
    ViewOnly(bool),
    /// The session started (`true`) or stopped (`false`) **recording the screen to a file** (loop
    /// 89). Folded so the guest's headline and the window caption say so while it runs.
    ///
    /// This is not a courtesy. A recording is the one thing a support session does that outlives
    /// it, and the guest cannot infer it from anything else on screen — the stream looks identical.
    /// docs/01 §9 has asked for a *"being recorded"* indicator since loop 18 and could not have one
    /// because recording did not exist.
    ///
    /// **Ending the session does not clear it.** Once a recording has been made, the ENDED headline
    /// says a file was left behind, because that is the fact the guest most needs after the
    /// technician has gone. See [`GuestPresenter::recorded_ever`].
    Recording(bool),
    /// Clipboard text actually CROSSED the session boundary — `to_technician == true` when the
    /// guest's clipboard was sent to the technician, `false` when the technician wrote into the
    /// guest's clipboard.
    ///
    /// Folded as two LATCHING facts, not a live mode, because the clipboard is not a state the guest
    /// can watch — it is a series of events that leave no trace. Nothing on screen changes when a
    /// copy is forwarded, so unlike view-only and recording there is no moment at which the guest
    /// could notice it happening. Reporting "clipboard sharing is enabled" would also be the wrong
    /// claim: it is true of nearly every session and says nothing about whether anything moved.
    ///
    /// The two directions are separate because they are different disclosures. Outbound answers
    /// *what you copied was read* — the exfiltration a screen-watching threat model misses, since
    /// the clipboard holds what was COPIED rather than what is DISPLAYED, routinely a password
    /// manager's contents. Inbound answers *something you did not copy is in your clipboard now*,
    /// which matters because the next thing the guest pastes may not be the thing they think it is.
    ///
    /// Like [`GuestEvent::Recording`]'s latch, ending the session does not clear these: after the
    /// technician has gone, "they have your clipboard contents" is exactly the fact that is still
    /// actionable.
    ClipboardShared {
        /// `true` ⇒ guest's clipboard went OUT to the technician; `false` ⇒ technician's text came IN.
        to_technician: bool,
    },
}

/// What the host must do as a result of an event.
///
/// A single value, not a `Vec`, matching this repo's other fold-to-effect state machine
/// (`ServiceState::on_session_change -> HelperAction`). Redraw is **not** a command: almost every
/// event needs one, so it would drown the interesting variant. Ask [`GuestPresenter::take_dirty`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestCommand {
    /// Nothing to do.
    None,
    /// Deliver this text to the technician as a chat line **from the guest**.
    ///
    /// The role is deliberately NOT carried in this value. The agent decides it at the send site,
    /// exactly as it does for inbound frames (`host.rs`: "this transport has two peers, so anything
    /// arriving over it is the technician's by construction"). A presenter that handed out a
    /// [`ChatFrom`] the caller trusted would re-open that hole from the other end the moment
    /// anything remote could reach this window.
    SendChat(String),
    /// The guest asked to end the session; the host must tear it down.
    ///
    /// The window does not close itself on this — it asks the session to stop, and the session's own
    /// teardown then closes the surface. One authority for "the session is over", the same reason the
    /// phase is driven by [`GuestEvent::Ended`] rather than set locally on the click.
    EndSession,
}

/// A message from the guest's window to the session that owns it. One channel, not two: the window
/// has a single pump and a single outbound path.
///
/// The role of a chat line is deliberately NOT carried (see [`GuestCommand::SendChat`]) — `Chat` is
/// a bare body and the session stamps [`ChatFrom::Guest`] at the receive site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestToHost {
    /// A line the guest typed. The session assigns the author.
    Chat(String),
    /// The guest pressed the window's End button — tear the session down.
    End,
    /// Whether the session's on-screen indicator is visible. `false` (it could not be placed on a
    /// display after a display change) holds the session view-only until it is visible again.
    IndicatorVisible(bool),
}

/// The seam between a session and whatever draws the guest's window.
///
/// A factory rather than a surface, because the surface needs the session's chat channel, which
/// only exists once the session is running — the same reason the clipboard worker is spawned inside
/// the session rather than handed in ready-made. The banner text ([`SessionInfo`]) is captured by
/// the implementation at construction, so each host supplies its own without threading it through
/// the session signature.
pub trait GuestUi: Send {
    /// Open the surface. `to_host` carries messages the guest generates — chat lines they type and
    /// an End request from the window's button — as [`GuestToHost`].
    ///
    /// A chat message carries only the body, **not** a `(ChatFrom, String)`. The role is decided at
    /// the receiving end — see [`GuestCommand::SendChat`].
    fn open(
        &self,
        to_host: tokio::sync::mpsc::UnboundedSender<GuestToHost>,
    ) -> Result<Box<dyn GuestSurface>, String>;
}

/// A live guest window. Every method is called from the session task and must not block on it.
pub trait GuestSurface: Send {
    /// A line was recorded by the transcript **during this session** — show it, and count it as
    /// unread if the guest is not looking. Called for both roles.
    fn posted(&self, from: ChatFrom, body: &str, at_unix_ms: i64);
    /// A line replayed from the persisted transcript as the window opened. Shown, never unread.
    fn seed(&self, from: ChatFrom, body: &str, at_unix_ms: i64);
    /// The session ended; the banner should say so and nothing more can be sent.
    fn ended(&self);
    /// The controller toggled view-only (loops 30–32): `view_only == true` ⇒ the technician is now
    /// WATCHING only (their input is dropped by the agent), `false` ⇒ CONTROLLING. The surface
    /// reflects it live — headline + window caption — so the guest can tell watching from control.
    fn set_view_only(&self, view_only: bool);
    /// The session started or stopped RECORDING the screen to a file on this machine (loop 89).
    /// The surface reflects it live — headline + window caption — and, once it has been true, the
    /// ended banner keeps saying a recording was left behind. See [`GuestEvent::Recording`].
    fn set_recording(&self, recording: bool);
    /// Clipboard text CROSSED the session boundary: `to_technician == true` when the guest's
    /// clipboard was sent out to the technician, `false` when the technician's text was written into
    /// the guest's clipboard.
    ///
    /// Called on every crossing; the presenter latches and only repaints on the first of each
    /// direction. Deliberately has no default implementation — a surface that shows the guest what
    /// is happening to their machine must decide about this one, not inherit silence.
    /// See [`GuestEvent::ClipboardShared`].
    fn clipboard_shared(&self, to_technician: bool);
    /// Tear the surface down and wait for it to be gone.
    fn close(&mut self);
}

/// The guest window's whole model.
///
/// Mutate-and-return, like [`crate::chat::Transcript`] and [`crate::reconnect::Backoff`]: fold an
/// event with [`GuestPresenter::on`], then read the accessors to paint.
#[derive(Debug)]
pub struct GuestPresenter {
    phase: SessionPhase,
    info: SessionInfo,
    lines: VecDeque<GuestLine>,
    compose: String,
    unread: u32,
    focused: bool,
    /// `true` ⇒ the technician is WATCHING only (view-only — the agent drops their injected input,
    /// loops 30–32); `false` ⇒ they are CONTROLLING. This is the consent distinction the guest could
    /// not previously see: a view-only session and a control session looked identical on screen.
    ///
    /// It starts **false (controlling)**, which is both the real initial state (a session opens in
    /// full control; view-only is opt-in) and the safe claim: under-stating control — telling the
    /// guest "only watching" while the technician can type — is the one error a consent indicator
    /// must never make, so the honest default is the more alarming one.
    view_only: bool,
    /// `true` ⇒ the screen is being written to a file on this machine RIGHT NOW (loop 89).
    ///
    /// Starts false, like [`Self::view_only`], and for the same reason: a session opens without a
    /// recording and one is started explicitly. The safe direction here is the opposite of
    /// view-only's, though — under-stating CONTROL is the dangerous error there, and over-stating a
    /// RECORDING would be the dangerous error here, because a guest told they are being recorded
    /// when they are not learns to distrust the indicator.
    recording: bool,
    /// `true` once [`Self::recording`] has been true at any point this session.
    ///
    /// Separate from `recording` because the two answer different questions and the second outlives
    /// the first: *is it running* drives the live banner, *did it ever run* drives what the ENDED
    /// banner says. A guest who steps away during a recorded session and comes back after it ended
    /// would otherwise find a window that says only "no longer shared", with nothing anywhere on
    /// their screen indicating that a video of it is sitting on their disk.
    recorded_ever: bool,
    /// `true` once the guest's clipboard has been sent to the technician at least once.
    ///
    /// Latching for the same reason as [`Self::recorded_ever`], and with the same safe direction:
    /// over-stating it would teach the guest to distrust the notice, so it is set only when text
    /// genuinely crossed the boundary — never when the channel merely exists. A session where the
    /// guest copies nothing says nothing.
    clipboard_out_ever: bool,
    /// `true` once the technician has written into the guest's clipboard at least once.
    clipboard_in_ever: bool,
    dirty: bool,
}

impl GuestPresenter {
    /// A presenter for a session that is starting now.
    ///
    /// `info`'s strings are sanitized here so no caller can forget: they come from a control-plane
    /// URL and an attacker-supplied `reason`, and they are about to be drawn on a stranger's screen.
    pub fn new(info: SessionInfo) -> Self {
        Self {
            phase: SessionPhase::Active,
            info: SessionInfo {
                control_plane_host: sanitize_display(&info.control_plane_host, MAX_BANNER_CHARS),
                reason: sanitize_display(&info.reason, MAX_BANNER_CHARS),
            },
            lines: VecDeque::new(),
            compose: String::new(),
            unread: 0,
            // A window that has just appeared has not been read, so a first message must count as
            // unread even though nothing has stolen focus yet.
            focused: false,
            // A session opens in full control; view-only is toggled on afterward (and never
            // under-claimed — see the field doc).
            view_only: false,
            // Nothing is being recorded until a controller asks for it.
            recording: false,
            recorded_ever: false,
            clipboard_out_ever: false,
            clipboard_in_ever: false,
            dirty: true,
        }
    }

    /// Fold one event, returning what the host must do.
    pub fn on(&mut self, event: GuestEvent) -> GuestCommand {
        match event {
            GuestEvent::Posted { from, body, at_unix_ms } => {
                let unread = from == ChatFrom::Technician && !self.focused;
                self.append(from, body, at_unix_ms, unread)
            }
            // Same rendering, never unread — see the variant's doc.
            GuestEvent::Seeded { from, body, at_unix_ms } => {
                self.append(from, body, at_unix_ms, false)
            }
            GuestEvent::Typed(c) => {
                // Refuse what would rewrite the window rather than silently accepting and stripping
                // it later: the guest must see exactly what they will send.
                if crate::text::is_display_hostile(c) {
                    return GuestCommand::None;
                }
                // The cap is the WIRE limit, so the box can never hold text the transcript would
                // then truncate — the guest would otherwise read back a message they did not send.
                if self.compose.chars().count() >= MAX_BODY_CHARS {
                    return GuestCommand::None;
                }
                self.compose.push(c);
                self.dirty = true;
                GuestCommand::None
            }
            GuestEvent::Backspace => {
                // By CHARACTER, not byte: popping a byte off a multi-byte character leaves an
                // invalid string, and `String::pop` is the only correct primitive here.
                if self.compose.pop().is_some() {
                    self.dirty = true;
                }
                GuestCommand::None
            }
            GuestEvent::Submit => {
                let body = self.compose.trim().to_string();
                // Nothing to send: an empty or whitespace-only line would occupy a numbered slot in
                // a persisted support transcript and tell the technician nothing.
                if body.is_empty() {
                    // Still clear whitespace so the box does not look occupied.
                    if !self.compose.is_empty() {
                        self.compose.clear();
                        self.dirty = true;
                    }
                    return GuestCommand::None;
                }
                // After the session ends the transport is gone. Returning `SendChat` here would ask
                // the host to write into a closed channel, and the guest would watch their message
                // sit in a window that will never post it.
                if self.phase == SessionPhase::Ended {
                    return GuestCommand::None;
                }
                self.compose.clear();
                self.dirty = true;
                GuestCommand::SendChat(body)
            }
            GuestEvent::Focused => {
                if !self.focused || self.unread != 0 {
                    self.dirty = true;
                }
                self.focused = true;
                self.unread = 0;
                GuestCommand::None
            }
            GuestEvent::Blurred => {
                if self.focused {
                    self.focused = false;
                    // Nothing on screen changes when focus leaves, so this is not a repaint.
                }
                GuestCommand::None
            }
            GuestEvent::EndClicked => {
                // Only while a session is actually running. A click that races the session's own
                // teardown (the Ended event already folded) is a no-op, not a second teardown — the
                // button is not drawn once ended, but an event can still sit queued behind Ended.
                if self.phase == SessionPhase::Active {
                    GuestCommand::EndSession
                } else {
                    GuestCommand::None
                }
            }
            GuestEvent::Ended => {
                if self.phase != SessionPhase::Ended {
                    self.phase = SessionPhase::Ended;
                    self.dirty = true;
                }
                GuestCommand::None
            }
            GuestEvent::ViewOnly(view_only) => {
                // Edge-triggered like the other folds: re-asserting the same state changes nothing on
                // screen, so it must not repaint an idle window on a CPU already busy encoding.
                if self.view_only != view_only {
                    self.view_only = view_only;
                    self.dirty = true;
                }
                GuestCommand::None
            }
            GuestEvent::Recording(recording) => {
                // Edge-triggered like its siblings. `recorded_ever` LATCHES and is deliberately not
                // part of the edge test: it is set on the way up and never cleared, so that the
                // ended banner can still say a file was left on this machine.
                if self.recording != recording {
                    self.recording = recording;
                    self.recorded_ever |= recording;
                    self.dirty = true;
                }
                GuestCommand::None
            }
            GuestEvent::ClipboardShared { to_technician } => {
                // Edge-triggered on the LATCH, not on an event count: the second copy of the session
                // tells the guest nothing the first did not, and a repaint per clipboard change
                // would redraw the window every 300ms poll for anyone doing ordinary copy-paste
                // work. `dirty` is set only when a latch actually flips.
                let flag =
                    if to_technician { &mut self.clipboard_out_ever } else { &mut self.clipboard_in_ever };
                if !*flag {
                    *flag = true;
                    self.dirty = true;
                }
                GuestCommand::None
            }
        }
    }

    /// Whether the window should draw (and hit-test) the **End session** button.
    ///
    /// Only while the session is active: once it has ended there is nothing to end, and a live
    /// button on a dead session would send an `End` the host has no session to act on.
    pub fn end_button_visible(&self) -> bool {
        self.phase == SessionPhase::Active
    }

    /// Append one line, shared by [`GuestEvent::Posted`] and [`GuestEvent::Seeded`] so the two can
    /// differ in exactly one respect — whether it counts as unread — and in no other.
    fn append(&mut self, from: ChatFrom, body: String, at_unix_ms: i64, unread: bool) -> GuestCommand {
        let body = sanitize_display(&body, MAX_BODY_CHARS);
        // A body that sanitizes away to nothing is dropped rather than shown as a blank line: a run
        // of empty rows is a way to push the banner off a small window.
        if body.is_empty() {
            return GuestCommand::None;
        }
        if unread {
            self.unread = self.unread.saturating_add(1);
        }
        self.lines.push_back(GuestLine { from, body, at_unix_ms });
        while self.lines.len() > MAX_VISIBLE_LINES {
            self.lines.pop_front();
        }
        self.dirty = true;
        GuestCommand::None
    }

    /// The headline the window shows, in the guest's own terms.
    ///
    /// Deliberately blunt and in the second person. This is the line that has to work when someone
    /// glances at a screen they did not expect to be shared. While active it also states WHICH kind
    /// of access is in force — being watched is materially different from being controlled, and the
    /// guest is entitled to know which. The control-case wording is unchanged from loop 18.
    /// While a recording runs, RECORDED leads: of the two facts on the line it is the one that
    /// outlives the session, so it is stated before the access mode rather than appended to it.
    /// The ENDED wording tells a guest who was away what was left behind, which is the only moment
    /// that information is actionable for them.
    pub fn headline(&self) -> &'static str {
        match self.phase {
            SessionPhase::Active if self.recording && self.view_only => {
                "Remote support session ACTIVE — your screen is being RECORDED to a file on this computer, and VIEWED (view only, no control)"
            }
            SessionPhase::Active if self.recording => {
                "Remote support session ACTIVE — your screen is being RECORDED to a file on this computer, and shared"
            }
            SessionPhase::Active if self.view_only => {
                "Remote support session ACTIVE — your screen is being VIEWED (view only, no control)"
            }
            SessionPhase::Active => "Remote support session ACTIVE — your screen is being shared",
            SessionPhase::Ended if self.recorded_ever => {
                "Remote support session ENDED — your screen is no longer shared. A RECORDING of it was saved on this computer."
            }
            SessionPhase::Ended => "Remote support session ENDED — your screen is no longer shared",
        }
    }

    /// Whether the technician is currently WATCHING only (view-only) rather than controlling. Drives
    /// the headline and the window title so the guest can tell the two apart.
    pub fn view_only(&self) -> bool {
        self.view_only
    }

    /// The window CAPTION (title-bar text). Distinct from [`Self::headline`] (owner-drawn GDI pixels,
    /// unreadable by an automated check): the caption is plain `SetWindowTextW` text that a probe can
    /// `GetWindowTextW`, so mirroring the control state here makes it programmatically verifiable
    /// (guest-window-probe.ps1 already reads it). Reflects both session phase and control mode.
    pub fn window_title(&self) -> &'static str {
        match self.phase {
            SessionPhase::Ended if self.recorded_ever => {
                "Remote support session — ended (RECORDING SAVED)"
            }
            SessionPhase::Ended => "Remote support session — ended",
            SessionPhase::Active if self.recording && self.view_only => {
                "Remote support session — RECORDING · VIEW ONLY"
            }
            SessionPhase::Active if self.recording => {
                "Remote support session — RECORDING · controlling"
            }
            SessionPhase::Active if self.view_only => "Remote support session — VIEW ONLY",
            SessionPhase::Active => "Remote support session — controlling",
        }
    }

    /// Whether the screen is being written to a file on this machine right now (loop 89). Drives
    /// the headline and the window caption.
    pub fn recording(&self) -> bool {
        self.recording
    }

    /// Whether a recording was made at any point this session — including one already stopped.
    /// This is what keeps the ENDED banner honest about the file left on the guest's disk.
    pub fn recorded_ever(&self) -> bool {
        self.recorded_ever
    }

    /// The detail line: who brokered this, and why they said they were here.
    ///
    /// An unknown host is **stated as unknown, never omitted**. The same rule governs the consent
    /// dialog (`attend::consent_prompt_text`): a missing line reads as "no third party involved",
    /// which is the opposite of the truth.
    pub fn detail(&self) -> String {
        let host = if self.info.control_plane_host.is_empty() {
            "an unknown server"
        } else {
            &self.info.control_plane_host
        };
        let mut out = match self.phase {
            SessionPhase::Active => format!("Connected via {host}"),
            SessionPhase::Ended => format!("Was connected via {host}"),
        };
        if !self.info.reason.is_empty() {
            out.push_str(" · Reason: ");
            out.push_str(&self.info.reason);
        }
        // CLIPBOARD DISCLOSURE. Deliberately on the detail line rather than in the headline or the
        // caption: both of those are exhaustive `match`es over `&'static str`, and a third
        // independent dimension would multiply them into a dozen near-identical strings for a fact
        // that is secondary to "what is happening to my screen". The detail line is already the
        // dynamic one, and it already carries the other things-you-should-know-about-this-connection.
        //
        // Stated in the past tense and only once something has actually moved, so the notice always
        // refers to a real event the guest can act on.
        if let Some(clip) = self.clipboard_notice() {
            out.push_str(" · ");
            out.push_str(clip);
        }
        out
    }

    /// The clipboard disclosure, or `None` when no clipboard text has crossed this session.
    ///
    /// Split out from [`Self::detail`] so a test can assert the exact wording without reconstructing
    /// the rest of the line, and so a future surface can place it somewhere else.
    pub fn clipboard_notice(&self) -> Option<&'static str> {
        match (self.clipboard_out_ever, self.clipboard_in_ever) {
            (true, true) => Some(
                "CLIPBOARD SHARED: what you copied was sent to the technician, and they have put text in your clipboard",
            ),
            (true, false) => Some("CLIPBOARD SHARED: what you copied was sent to the technician"),
            (false, true) => Some("CLIPBOARD: the technician has put text in your clipboard"),
            (false, false) => None,
        }
    }

    /// Whether the guest's clipboard has been sent to the technician at any point this session.
    pub fn clipboard_out_ever(&self) -> bool {
        self.clipboard_out_ever
    }

    /// Whether the technician has written into the guest's clipboard at any point this session.
    pub fn clipboard_in_ever(&self) -> bool {
        self.clipboard_in_ever
    }

    /// Current phase.
    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    /// The lines to paint, oldest first.
    pub fn lines(&self) -> &VecDeque<GuestLine> {
        &self.lines
    }

    /// What the guest has typed so far.
    pub fn compose(&self) -> &str {
        &self.compose
    }

    /// Technician lines that have arrived since the guest last looked.
    pub fn unread(&self) -> u32 {
        self.unread
    }

    /// Whether the window needs repainting, **clearing the flag**.
    ///
    /// Edge-triggered on purpose: a shell that repaints on every pump iteration burns a core
    /// redrawing an idle window, and this window sits on a machine whose CPU is already being spent
    /// capturing and encoding the screen.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::replace(&mut self.dirty, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A presenter mid-session, with the banner fields a real attended session supplies.
    fn active() -> GuestPresenter {
        GuestPresenter::new(SessionInfo {
            control_plane_host: "support.example.com:8443".to_string(),
            reason: "Printer not working".to_string(),
        })
    }

    /// Type a whole string, returning the last command (all but the last are `None`).
    fn type_str(p: &mut GuestPresenter, s: &str) {
        for c in s.chars() {
            p.on(GuestEvent::Typed(c));
        }
    }

    // --- sending ------------------------------------------------------------------------------

    #[test]
    fn submit_sends_the_composed_text_and_clears_the_box() {
        let mut p = active();
        type_str(&mut p, "my printer is offline");
        assert_eq!(p.compose(), "my printer is offline");
        assert_eq!(
            p.on(GuestEvent::Submit),
            GuestCommand::SendChat("my printer is offline".to_string())
        );
        assert_eq!(p.compose(), "", "a box that is not cleared sends the same line twice");
    }

    #[test]
    fn the_guests_own_line_is_not_shown_until_the_transcript_posts_it() {
        // The mutation this defeats is the obvious one: append locally on Submit. The line would
        // then appear TWICE — once optimistically, once when the transcript's copy arrives — and
        // the two would carry different timestamps.
        let mut p = active();
        type_str(&mut p, "hello");
        p.on(GuestEvent::Submit);
        assert!(p.lines().is_empty(), "nothing may appear before the transcript numbers it");

        p.on(GuestEvent::Posted {
            from: ChatFrom::Guest,
            body: "hello".to_string(),
            at_unix_ms: 1_700_000_000_000,
        });
        assert_eq!(p.lines().len(), 1, "exactly one copy, the transcript's");
        assert_eq!(p.lines()[0].from, ChatFrom::Guest);
    }

    #[test]
    fn an_empty_or_whitespace_only_line_is_never_sent() {
        let mut p = active();
        assert_eq!(p.on(GuestEvent::Submit), GuestCommand::None, "empty box");
        type_str(&mut p, "   \t  ");
        assert_eq!(p.on(GuestEvent::Submit), GuestCommand::None, "whitespace only");
        assert_eq!(p.compose(), "", "but the box is still cleared");
    }

    // --- ending the session (docs/12 §5) ------------------------------------------------------

    #[test]
    fn clicking_end_asks_the_host_to_tear_the_session_down() {
        let mut p = active();
        assert_eq!(p.on(GuestEvent::EndClicked), GuestCommand::EndSession);
        // The presenter does NOT flip its own phase — the session's `Ended` event is the one
        // authority for "the session is over", the same rule the phase already follows.
        assert_eq!(p.phase(), SessionPhase::Active, "the click asks; it does not decide");
    }

    #[test]
    fn end_is_a_no_op_once_the_session_has_already_ended() {
        let mut p = active();
        p.on(GuestEvent::Ended);
        assert_eq!(
            p.on(GuestEvent::EndClicked),
            GuestCommand::None,
            "a click racing the session's own teardown must not ask for a second one"
        );
    }

    #[test]
    fn the_end_button_is_shown_only_while_the_session_is_active() {
        let mut p = active();
        assert!(p.end_button_visible(), "an active session can be ended");
        p.on(GuestEvent::Ended);
        assert!(!p.end_button_visible(), "nothing to end once the session is over");
    }

    #[test]
    fn after_the_session_ends_nothing_more_can_be_sent() {
        let mut p = active();
        p.on(GuestEvent::Ended);
        type_str(&mut p, "are you still there?");
        assert_eq!(
            p.on(GuestEvent::Submit),
            GuestCommand::None,
            "the transport is gone; asking the host to send would drop the text silently"
        );
        assert_eq!(p.compose(), "are you still there?", "and the text is NOT thrown away");
    }

    // --- what may be typed --------------------------------------------------------------------

    #[test]
    fn the_compose_box_cannot_exceed_the_wire_limit() {
        // Without this cap the transcript truncates at MAX_BODY_CHARS and the guest reads back a
        // message that is not the one they composed.
        let mut p = active();
        for _ in 0..(MAX_BODY_CHARS + 50) {
            p.on(GuestEvent::Typed('x'));
        }
        assert_eq!(p.compose().chars().count(), MAX_BODY_CHARS);
    }

    #[test]
    fn characters_that_would_rewrite_the_window_are_refused_as_they_are_typed() {
        let mut p = active();
        type_str(&mut p, "a\u{202E}b");
        assert_eq!(p.compose(), "ab", "the bidi override never enters the box");
    }

    #[test]
    fn backspace_removes_a_whole_character_and_is_harmless_on_an_empty_box() {
        let mut p = active();
        p.on(GuestEvent::Backspace); // must not panic or underflow
        assert_eq!(p.compose(), "");
        type_str(&mut p, "hi🙂");
        p.on(GuestEvent::Backspace);
        assert_eq!(p.compose(), "hi", "popping bytes would leave an invalid string");
    }

    // --- what is shown ------------------------------------------------------------------------

    #[test]
    fn a_technicians_line_is_sanitized_before_it_reaches_the_screen() {
        // The remote party controls this text and it is drawn on the guest's machine.
        let mut p = active();
        p.on(GuestEvent::Posted {
            from: ChatFrom::Technician,
            body: "visit \u{202E}moc.live.troppus\nnow".to_string(),
            at_unix_ms: 1,
        });
        assert_eq!(p.lines()[0].body, "visit moc.live.troppusnow");
    }

    #[test]
    fn a_line_that_sanitizes_away_to_nothing_is_dropped_rather_than_shown_blank() {
        let mut p = active();
        p.on(GuestEvent::Posted {
            from: ChatFrom::Technician,
            body: "\u{202E}\u{200B}".to_string(),
            at_unix_ms: 1,
        });
        assert!(p.lines().is_empty(), "blank rows are a way to push the banner out of view");
    }

    #[test]
    fn the_visible_log_is_bounded_and_drops_the_oldest() {
        let mut p = active();
        for i in 0..(MAX_VISIBLE_LINES + 25) {
            p.on(GuestEvent::Posted {
                from: ChatFrom::Technician,
                body: format!("line {i}"),
                at_unix_ms: i as i64,
            });
        }
        assert_eq!(p.lines().len(), MAX_VISIBLE_LINES, "memory is bounded");
        assert_eq!(p.lines()[0].body, "line 25", "the oldest were evicted, not the newest");
    }

    // --- unread -------------------------------------------------------------------------------

    #[test]
    fn unread_counts_only_the_technicians_lines_and_only_while_unfocused() {
        let mut p = active();
        p.on(GuestEvent::Posted { from: ChatFrom::Technician, body: "a".into(), at_unix_ms: 1 });
        p.on(GuestEvent::Posted { from: ChatFrom::Guest, body: "b".into(), at_unix_ms: 2 });
        assert_eq!(p.unread(), 1, "the guest's own line is not news to the guest");

        p.on(GuestEvent::Focused);
        assert_eq!(p.unread(), 0, "looking at the window clears it");

        p.on(GuestEvent::Posted { from: ChatFrom::Technician, body: "c".into(), at_unix_ms: 3 });
        assert_eq!(p.unread(), 0, "a line that arrives while the guest is looking is already read");
    }

    #[test]
    fn replayed_history_is_shown_but_never_counted_as_unread() {
        // The defect this pins: the session replays the persisted transcript into the window when
        // it opens. Routing that through `Posted` made every historical technician line unread, so
        // a machine with a support history opened announcing dozens of "new" messages from days ago
        // — a badge for text the guest could not possibly have missed.
        let mut p = active();
        for i in 0..7 {
            p.on(GuestEvent::Seeded {
                from: ChatFrom::Technician,
                body: format!("last week {i}"),
                at_unix_ms: i,
            });
        }
        assert_eq!(p.lines().len(), 7, "history is still SHOWN");
        assert_eq!(p.unread(), 0, "…but none of it is news");

        // And a line that genuinely arrives now still counts.
        p.on(GuestEvent::Posted { from: ChatFrom::Technician, body: "hello".into(), at_unix_ms: 8 });
        assert_eq!(p.unread(), 1);
    }

    #[test]
    fn losing_focus_re_arms_the_unread_counter() {
        // Without a Blurred event `focused` latches true at the guest's first click and the badge is
        // dead for the rest of the session — every later message silently counts as already read,
        // which is the exact opposite of what the counter is for.
        let mut p = active();
        p.on(GuestEvent::Focused);
        p.on(GuestEvent::Posted { from: ChatFrom::Technician, body: "a".into(), at_unix_ms: 1 });
        assert_eq!(p.unread(), 0, "read, because the guest was looking");

        p.on(GuestEvent::Blurred);
        p.on(GuestEvent::Posted { from: ChatFrom::Technician, body: "b".into(), at_unix_ms: 2 });
        assert_eq!(p.unread(), 1, "the guest looked away, so this one is news again");
    }

    // --- banner -------------------------------------------------------------------------------

    #[test]
    fn the_banner_states_an_unknown_host_rather_than_omitting_it() {
        // A missing "connected via" line reads as "no third party is involved", which is the exact
        // opposite of the truth. Same rule as the consent dialog.
        let p = GuestPresenter::new(SessionInfo::default());
        assert!(p.detail().contains("unknown"), "got: {}", p.detail());
        assert!(!p.detail().is_empty());
    }

    #[test]
    fn the_banner_fields_are_sanitized_and_capped_at_construction() {
        let p = GuestPresenter::new(SessionInfo {
            control_plane_host: "evil\u{202E}moc.example".to_string(),
            reason: "r".repeat(500),
        });
        assert!(p.detail().contains("evilmoc.example"));
        assert!(!p.detail().contains('\u{202E}'));
        // reason capped: MAX_BANNER_CHARS incl. the ellipsis.
        assert!(p.detail().ends_with('…'));
    }

    #[test]
    fn the_headline_changes_when_the_session_ends_and_says_which_way() {
        let mut p = active();
        let live = p.headline();
        assert!(live.contains("ACTIVE"));
        p.on(GuestEvent::Ended);
        assert!(p.headline().contains("ENDED"));
        assert_ne!(live, p.headline());
        assert!(p.detail().starts_with("Was connected"), "got: {}", p.detail());
    }

    #[test]
    fn a_default_phase_claims_the_least() {
        // A permissive default is this repo's known bug class. "ACTIVE" would assert that a remote
        // party has control of the machine when nothing has said so.
        assert_eq!(SessionPhase::default(), SessionPhase::Ended);
    }

    // --- clipboard disclosure -------------------------------------------------------------------

    #[test]
    fn a_session_that_moved_no_clipboard_makes_no_clipboard_claim() {
        // THE NEGATIVE CONTROL for every assertion below. A notice that appears on a session where
        // nothing was copied is a notice the guest learns to ignore — the same reasoning that keeps
        // `recorded_ever` off until a recording really ran.
        let p = active();
        assert!(!p.clipboard_out_ever());
        assert!(!p.clipboard_in_ever());
        assert_eq!(p.clipboard_notice(), None);
        assert!(
            !p.detail().contains("CLIPBOARD"),
            "a session with no clipboard activity must not mention the clipboard: {}",
            p.detail(),
        );
    }

    #[test]
    fn the_guest_is_told_when_their_clipboard_goes_to_the_technician() {
        let mut p = active();
        let quiet = p.detail();
        p.on(GuestEvent::ClipboardShared { to_technician: true });

        assert!(p.clipboard_out_ever());
        assert!(!p.clipboard_in_ever(), "an outbound copy must not claim the technician wrote to us");
        let notice = p.clipboard_notice().expect("outbound crossing must be disclosed");
        assert!(notice.contains("what you copied was sent"), "notice: {notice}");
        assert_ne!(p.detail(), quiet, "the detail line must change once the clipboard has moved");
        assert!(p.detail().contains(notice));
    }

    #[test]
    fn the_guest_is_told_when_the_technician_writes_into_their_clipboard() {
        // A distinct disclosure from the outbound one, because it answers a different question:
        // the next thing the guest pastes may not be the thing they think they copied.
        let mut p = active();
        p.on(GuestEvent::ClipboardShared { to_technician: false });

        assert!(p.clipboard_in_ever());
        assert!(!p.clipboard_out_ever());
        let notice = p.clipboard_notice().expect("inbound crossing must be disclosed");
        assert!(notice.contains("put text in your clipboard"), "notice: {notice}");
        assert!(
            !notice.contains("what you copied was sent"),
            "an inbound-only session must not claim the guest's clipboard was read: {notice}",
        );
    }

    #[test]
    fn the_two_directions_are_disclosed_separately_and_together() {
        // All four states must be distinguishable, or the notice cannot be trusted to mean what it
        // says. This is the pairwise-distinct check the recording/view-only captions also make.
        let none = active();

        let mut out_only = active();
        out_only.on(GuestEvent::ClipboardShared { to_technician: true });

        let mut in_only = active();
        in_only.on(GuestEvent::ClipboardShared { to_technician: false });

        let mut both = active();
        both.on(GuestEvent::ClipboardShared { to_technician: true });
        both.on(GuestEvent::ClipboardShared { to_technician: false });

        let notices = [
            none.clipboard_notice(),
            out_only.clipboard_notice(),
            in_only.clipboard_notice(),
            both.clipboard_notice(),
        ];
        for i in 0..notices.len() {
            for j in (i + 1)..notices.len() {
                assert_ne!(notices[i], notices[j], "clipboard notices {i} and {j} are identical");
            }
        }
        let both_notice = both.clipboard_notice().unwrap();
        assert!(both_notice.contains("what you copied was sent"));
        assert!(both_notice.contains("put text in your clipboard"));
    }

    #[test]
    fn a_clipboard_that_moved_is_still_disclosed_after_the_session_ends() {
        // The latch, and the reason for it: after the technician has gone, "they have what you
        // copied" is precisely the fact that is still actionable. Mirrors `recorded_ever`.
        let mut p = active();
        p.on(GuestEvent::ClipboardShared { to_technician: true });
        p.on(GuestEvent::Ended);

        assert!(p.clipboard_out_ever(), "ending a session does not un-share a clipboard");
        assert!(p.detail().contains("CLIPBOARD SHARED"), "ended detail: {}", p.detail());

        // Second, independent presenter that ends having moved nothing: it must make no claim.
        let mut never = active();
        never.on(GuestEvent::Ended);
        assert_eq!(
            never.clipboard_notice(),
            None,
            "a session that shared no clipboard must not say one was shared after it ends",
        );
    }

    #[test]
    fn repeated_clipboard_crossings_repaint_only_on_the_first_of_each_direction() {
        // Ordinary copy-paste work fires this on a 300ms poll. Repainting per crossing would redraw
        // the window continuously for a fact that has not changed. Same shape as
        // `toggling_recording_repaints_only_on_a_real_change`.
        let mut p = active();
        p.take_dirty();

        p.on(GuestEvent::ClipboardShared { to_technician: true });
        assert!(p.take_dirty(), "the first outbound crossing must repaint");

        p.on(GuestEvent::ClipboardShared { to_technician: true });
        assert!(!p.take_dirty(), "a second outbound crossing tells the guest nothing new");

        p.on(GuestEvent::ClipboardShared { to_technician: false });
        assert!(p.take_dirty(), "the first INBOUND crossing is a new fact and must repaint");

        p.on(GuestEvent::ClipboardShared { to_technician: false });
        assert!(!p.take_dirty(), "a second inbound crossing does not");
    }

    // --- view-only / control indicator (docs/01 §1/§5) ----------------------------------------

    #[test]
    fn a_new_session_is_controlling_not_view_only() {
        // The honest default: a session opens in full control, and under-claiming control (telling
        // the guest "only watching" while the technician can type) is the one error the consent
        // indicator must never make. So a fresh presenter reports controlling.
        let p = active();
        assert!(!p.view_only(), "a session starts controlling; view-only is opt-in");
        assert!(p.headline().contains("being shared"), "control headline: {}", p.headline());
        assert!(!p.headline().contains("VIEWED"));
    }

    #[test]
    fn view_only_changes_the_headline_to_say_watching_not_controlling() {
        let mut p = active();
        let controlling = p.headline();
        p.on(GuestEvent::ViewOnly(true));
        assert!(p.view_only());
        let watching = p.headline();
        assert_ne!(controlling, watching, "the guest must be able to tell watching from controlling");
        assert!(watching.contains("VIEWED"), "view-only headline: {watching}");
        assert!(watching.contains("view only"), "view-only headline must say so: {watching}");
        assert!(watching.contains("ACTIVE"), "still an active session");
    }

    #[test]
    fn returning_to_control_restores_the_control_headline() {
        let mut p = active();
        let controlling = p.headline();
        p.on(GuestEvent::ViewOnly(true));
        p.on(GuestEvent::ViewOnly(false));
        assert!(!p.view_only());
        assert_eq!(p.headline(), controlling, "back in control ⇒ back to the control headline");
    }

    #[test]
    fn the_window_title_encodes_the_control_state_for_an_automated_probe() {
        // The headline is owner-drawn GDI (unreadable by a check); the caption is SetWindowTextW text
        // a probe reads. So the caption must carry the distinction the VM proof asserts: a
        // controlling session and a view-only one produce DIFFERENT titles, each naming its mode.
        let mut p = active();
        let controlling = p.window_title();
        assert!(controlling.contains("controlling"), "control title: {controlling}");
        p.on(GuestEvent::ViewOnly(true));
        let viewing = p.window_title();
        assert!(viewing.contains("VIEW ONLY"), "view-only title: {viewing}");
        assert_ne!(controlling, viewing, "the probe must see the caption change on the toggle");
        // Ended is its own title, distinct from both active states.
        p.on(GuestEvent::Ended);
        let ended = p.window_title();
        assert!(ended.contains("ended"), "ended title: {ended}");
        assert_ne!(ended, controlling);
        assert_ne!(ended, viewing);
    }

    #[test]
    fn a_recording_says_so_in_both_the_headline_and_the_caption() {
        // docs/01 §9's "being recorded" indicator (loop 89). The caption is the half a VM probe can
        // read (`GetWindowTextW`); the headline is the half the guest reads.
        let mut p = active();
        let (quiet_head, quiet_cap) = (p.headline(), p.window_title());
        assert!(!quiet_head.contains("RECORD"), "nothing is recording yet: {quiet_head}");
        assert!(!quiet_cap.contains("RECORD"), "nothing is recording yet: {quiet_cap}");
        p.on(GuestEvent::Recording(true));
        assert!(p.recording());
        let (head, cap) = (p.headline(), p.window_title());
        assert!(head.contains("RECORDED"), "recording headline: {head}");
        assert!(head.contains("ACTIVE"), "still an active session: {head}");
        assert!(cap.contains("RECORDING"), "recording caption: {cap}");
        assert_ne!(quiet_head, head, "the guest must be able to see it start");
        assert_ne!(quiet_cap, cap, "the probe must see the caption change");
    }

    #[test]
    fn a_recording_and_view_only_are_both_stated_at_once() {
        // The two facts are independent, and a session can be both. Neither may hide the other:
        // collapsing them would let "view only" reassure a guest whose screen is being written to
        // disk. Four active captions, all distinct, is the invariant.
        let mut p = active();
        let plain = p.window_title();
        p.on(GuestEvent::ViewOnly(true));
        let vo = p.window_title();
        p.on(GuestEvent::Recording(true));
        let both = p.window_title();
        p.on(GuestEvent::ViewOnly(false));
        let rec = p.window_title();
        let all = [plain, vo, both, rec];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "every active caption must be distinguishable: {all:?}");
            }
        }
        assert!(both.contains("RECORDING") && both.contains("VIEW ONLY"), "both: {both}");
        let head = {
            p.on(GuestEvent::ViewOnly(true));
            p.headline()
        };
        assert!(head.contains("RECORDED"), "headline states the recording: {head}");
        assert!(head.contains("view only"), "headline still states view-only: {head}");
    }

    #[test]
    fn a_recording_that_stopped_is_still_disclosed_after_the_session_ends() {
        // The latch. A guest who was away from their desk learns, from the window still on their
        // screen, that a video of their machine is on their disk — the one moment that fact is
        // actionable for them. Ending a session that recorded NOTHING must not claim otherwise.
        let mut p = active();
        p.on(GuestEvent::Recording(true));
        p.on(GuestEvent::Recording(false));
        assert!(!p.recording(), "it stopped");
        assert!(p.recorded_ever(), "but it happened");
        let live = p.headline();
        assert!(!live.contains("RECORDED to a file"), "not recording any more: {live}");
        p.on(GuestEvent::Ended);
        let (head, cap) = (p.headline(), p.window_title());
        assert!(head.contains("RECORDING"), "ended headline discloses the file: {head}");
        assert!(cap.contains("RECORDING SAVED"), "ended caption discloses it: {cap}");

        let mut never = active();
        never.on(GuestEvent::Ended);
        assert!(!never.recorded_ever());
        assert!(
            !never.headline().contains("RECORDING") && !never.window_title().contains("RECORDING"),
            "a session that recorded nothing must not claim a file exists"
        );
    }

    #[test]
    fn toggling_recording_repaints_only_on_a_real_change() {
        let mut p = active();
        p.take_dirty();
        p.on(GuestEvent::Recording(false));
        assert!(!p.take_dirty(), "re-asserting 'not recording' must not repaint");
        p.on(GuestEvent::Recording(true));
        assert!(p.take_dirty(), "starting must repaint");
        p.on(GuestEvent::Recording(true));
        assert!(!p.take_dirty(), "re-asserting 'recording' must not repaint");
    }

    #[test]
    fn a_fresh_presenter_claims_no_recording() {
        // The same rule as `SessionPhase::Ended` being `Default`: a default-constructed presenter
        // must claim the least. Over-claiming here teaches the guest to distrust the indicator.
        let p = GuestPresenter::new(SessionInfo::default());
        assert!(!p.recording());
        assert!(!p.recorded_ever());
    }

    #[test]
    fn toggling_view_only_repaints_only_on_a_real_change() {
        // Edge-triggered like every other fold: re-asserting the same state must not repaint an idle
        // window on a machine already spending its CPU capturing and encoding the screen. The
        // mutation this defeats is setting dirty unconditionally in the ViewOnly arm.
        let mut p = active();
        p.take_dirty(); // clear the initial paint
        p.on(GuestEvent::ViewOnly(false)); // already controlling — no change
        assert!(!p.take_dirty(), "re-asserting the current control state changed nothing");
        p.on(GuestEvent::ViewOnly(true)); // controlling → watching
        assert!(p.take_dirty(), "a real transition must repaint");
        p.on(GuestEvent::ViewOnly(true)); // still watching — no change
        assert!(!p.take_dirty(), "re-asserting view-only changed nothing");
    }

    // --- redraw -------------------------------------------------------------------------------

    #[test]
    fn take_dirty_is_edge_triggered() {
        let mut p = active();
        assert!(p.take_dirty(), "a freshly opened window must paint once");
        assert!(!p.take_dirty(), "and not again until something changes");
        p.on(GuestEvent::Typed('x'));
        assert!(p.take_dirty());
        assert!(!p.take_dirty());
    }

    #[test]
    fn an_event_that_changes_nothing_does_not_request_a_repaint() {
        // The mutation: set `dirty = true` unconditionally in `on`. The window would then repaint
        // on every rejected keystroke and every no-op focus, on a machine already spending its CPU
        // capturing and encoding the screen.
        let mut p = active();
        p.take_dirty();
        p.on(GuestEvent::Typed('\u{202E}')); // refused
        assert!(!p.take_dirty(), "a refused keystroke changed nothing on screen");
        p.on(GuestEvent::Backspace); // empty box
        assert!(!p.take_dirty(), "backspace on an empty box changed nothing on screen");
        p.on(GuestEvent::Focused);
        p.take_dirty();
        p.on(GuestEvent::Focused); // already focused, nothing unread
        assert!(!p.take_dirty(), "focusing an already-focused window changed nothing");
    }
}
