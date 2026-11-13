//! Canonical wire codec for the **session control channel** (M10 multi-monitor).
//!
//! Like [`crate::input_codec`], [`crate::file_transfer`] and [`crate::clipboard`], this is the
//! **one** encoding both ends of a session agree on: the Rust agent decodes/encodes control frames
//! with [`decode`]/[`encode`], and the browser controller (`web/viewer/src/lib/control.ts`) produces
//! byte-identical frames. Messages ride as the payload of a [`Frame`](rmt_protocol::Frame) tagged
//! [`rmt_protocol::ChannelId::Control`]; the transport frames them.
//!
//! # Purpose (M10)
//!
//! The controller enumerates the agent's monitors and picks which one to stream. The exchange is:
//!
//! 1. controller → agent: [`ControlMessage::RequestMonitors`]
//! 2. agent → controller: [`ControlMessage::MonitorList`] (the attached monitors)
//! 3. controller → agent: [`ControlMessage::SelectMonitor`] (choose which to stream)
//! 4. agent → controller: [`ControlMessage::Error`] *only* when a selection names an unknown id
//!    (a successful select is silent — the video simply switches to the chosen monitor).
//!
//! # Wire shape
//!
//! JSON, **adjacently tagged** (`{"t":<variant>,"c":<content>}`) exactly like the sibling codecs.
//! A unit variant carries no content, so it serializes as just `{"t":<variant>}`:
//!
//! * `RequestMonitors`                     → `{"t":"RequestMonitors"}`
//! * `MonitorList { monitors }`            → `{"t":"MonitorList","c":{"monitors":[…]}}`
//! * `SelectMonitor { id }`                → `{"t":"SelectMonitor","c":{"id":1}}`
//! * `Error { message }`                   → `{"t":"Error","c":{"message":"…"}}`
//!
//! Each [`MonitorDesc`] is `{"id":…,"width":…,"height":…,"primary":…}` (serde struct field order).
//!
//! # Quality control (M11)
//!
//! The same channel carries the operator's quality selection and the agent's telemetry:
//!
//! 1. controller → agent: [`ControlMessage::RequestQuality`] (also **arms** the session — see below)
//! 2. agent → controller: [`ControlMessage::QualityApplied`] (the *clamped* settings in force)
//! 3. controller → agent: [`ControlMessage::SetQuality`], answered with another `QualityApplied`
//! 4. agent → controller: [`ControlMessage::QualityStats`] at 1 Hz, **only once armed**
//!
//! ## The arming rule
//!
//! The agent sends **no** `QualityApplied` or `QualityStats` until this session has received a
//! `RequestQuality` or `SetQuality`. An older controller never sends one, so its traffic is
//! byte-for-byte what it is today. This matters more than it looks: the TypeScript
//! `decodeControl` *throws* on an unknown variant, and it is called inside a loop over the frames
//! coalesced into one SCTP message — so one unknown variant would discard its innocent siblings.
//! (The browser client also catches that throw now, but the agent not speaking first is the
//! defence that does not depend on the controller being new.)

use serde::{Deserialize, Serialize};

use crate::quality::QualitySettings;

/// A single monitor as advertised to the controller. Deliberately the wire-facing subset of
/// [`crate::platform::MonitorInfo`] (no `dpi_scale`, plus a `primary` flag): the controller needs
/// enough to label + size a picker entry and to know which is the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorDesc {
    /// Stable-within-a-session id used in [`ControlMessage::SelectMonitor`] (matches
    /// [`crate::platform::MonitorInfo::id`], the capturer's monitor index).
    pub id: u32,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// Whether this is the primary monitor (the one streamed by default, id `0`).
    pub primary: bool,
}

/// A display rectangle within a fixed, full virtual-desktop video canvas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanvasMonitor {
    pub id: u32,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Pixel coordinates refer to the native canvas; encoder scaling preserves its aspect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorCanvas {
    pub width: u32,
    pub height: u32,
    pub monitors: Vec<CanvasMonitor>,
}

/// A single entry in a [`ControlMessage::DirectoryListing`]: a file or subdirectory of the listed
/// path. The wire-facing subset the controller needs to render and navigate a file browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// The entry's base name (no path), e.g. `"Windows"` or `"config.json"`.
    pub name: String,
    /// `true` for a directory (navigable), `false` for a file.
    pub is_dir: bool,
    /// File size in bytes. `0` for a directory (a directory's own size is not meaningful here).
    pub size: u64,
    /// Last-modified time as whole seconds since the Unix epoch, or `0` if unavailable.
    pub modified_unix: i64,
}

/// Which interpreter runs a [`ControlMessage::RunCommand`]. A unit-only enum, so — exactly like
/// [`crate::quality::ColorMode`] — it serializes as a **bare string** (`"Cmd"` / `"PowerShell"`),
/// never an object. The controller's `web/viewer/src/lib/control.ts` pins the identical strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandShell {
    /// `cmd.exe /C <command>` — the classic command interpreter (built-ins, pipes, redirection).
    Cmd,
    /// `powershell.exe -NoProfile -NonInteractive -Command <command>`.
    PowerShell,
}

/// Deserialize an `Option<String>` field that MUST be present on the wire — `null` for `None`.
///
/// **serde's default for a missing `Option` field is `None`, and here that default is a lie.** With
/// a plain `Option<String>`, a `RecordingStopped` that omits `truncated` decodes as "the recording
/// ran to completion" — the single misreading that message exists to prevent, since a truncated
/// file ends exactly like a complete one and nothing else on the wire distinguishes them. Every
/// other field on this wire is required and a missing one is an error; this makes the one field
/// whose type would silently opt out behave the same.
///
/// It also keeps Rust and TypeScript honest with each other: `control.ts`'s decoder rejects an
/// absent `truncated` explicitly, and without this the two codecs would disagree about a message
/// they are supposed to be byte-compatible on — the divergence caught by
/// `a_recording_stopped_without_truncated_is_rejected_rather_than_read_as_complete`, which failed
/// against the plain `Option` this replaced.
fn required_option_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d)
}

/// A single decoded control message. Adjacently-tagged as `{"t":…,"c":…}` on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
pub enum ControlMessage {
    /// controller → agent: "tell me your monitors". Answered with [`ControlMessage::MonitorList`].
    RequestMonitors,
    /// Controller crop interest; null means every display.
    WatchedMonitors { monitors: Option<Vec<u32>> },
    /// agent → controller: the currently-attached monitors.
    MonitorList {
        /// The attached monitors (at least one; `monitors[0]` / `primary` is the default stream).
        monitors: Vec<MonitorDesc>,
    },
    /// controller → agent: stream the monitor with this id from now on. Silent on success; an
    /// [`ControlMessage::Error`] comes back if the id is not in the last-advertised list. The
    /// reserved id [`crate::platform::COMPOSITE_MONITOR_ID`] requests a **composite "view all"** of
    /// every monitor at once and is always accepted (even with a single monitor).
    SelectMonitor {
        /// The chosen monitor id (a [`MonitorDesc::id`] from a prior `MonitorList`, or
        /// [`crate::platform::COMPOSITE_MONITOR_ID`] for view-all).
        id: u32,
    },
    /// agent → controller: a [`ControlMessage::SelectMonitor`] was accepted (single-session path
    /// only). In multi-session pinned-display mode the agent does NOT send this message; instead it
    /// sends [`ControlMessage::MonitorPinned`] once when the pin is established.
    ///
    /// Carries the monotonic `selection_gen` epoch the agent assigned to this transition.  The
    /// controller SHOULD send [`ControlMessage::FrameDisplayed`] with the same `selection_gen` on
    /// the `requestVideoFrameCallback` tick after the new monitor's frame is composited on screen.
    SelectMonitorAccepted {
        /// The monotonic selection-generation epoch assigned to this `SelectMonitor` transition.
        selection_gen: u64,
    },
    /// controller → agent: the controller has rendered a frame that belongs to generation
    /// `selection_gen`.  Not processed in multi-session pinned-display mode (the agent never sends
    /// [`ControlMessage::SelectMonitorAccepted`] on that path, so no ack is expected).
    FrameDisplayed {
        /// Must match a prior [`ControlMessage::SelectMonitorAccepted::selection_gen`]; mismatches
        /// are silently ignored.
        selection_gen: u64,
    },
    /// agent → controller: in multi-session (shared-capture) mode, one monitor has been pinned for
    /// the entire helper lifetime.  Sent once on the first [`ControlMessage::SelectMonitor`] that
    /// establishes the pin.  A subsequent `SelectMonitor` with the **same** id is a silent no-op
    /// (this message is NOT repeated).  Any `SelectMonitor` naming a **different** id or
    /// [`crate::platform::COMPOSITE_MONITOR_ID`] is rejected with [`ControlMessage::Error`].
    ///
    /// Old controllers that do not recognise this variant silently discard it and may still attempt
    /// a different `SelectMonitor`; the agent rejects it with `Error`.  Dynamic monitor switching
    /// in multi-session mode is deferred — do not claim the feature complete.
    /// A fixed full-desktop stream. Updated viewers select a local viewport independently.
    /// Legacy viewers continue to receive MonitorPinned(COMPOSITE_MONITOR_ID).
    MonitorCanvas(MonitorCanvas),
    MonitorPinned {
        /// The monitor id pinned for the helper lifetime.  Matches the id in the most-recently
        /// advertised [`ControlMessage::MonitorList`].
        monitor_id: u32,
    },
    /// agent → controller: something the controller asked for could not be done (today: a
    /// `SelectMonitor` for an unknown id, a pinned-mode `SelectMonitor` for a different monitor,
    /// or an `InstallGrant` that failed to verify). Advisory; the stream keeps running unchanged.
    Error {
        /// Human-readable reason.
        message: String,
    },
    /// controller → agent (H1): install a control-plane-signed backstage grant. `signed_grant` is
    /// the **opaque JSON wire form** of a `rmt_agent::backstage::grant::SignedGrant` — kept as a
    /// plain string here so `rmt-agent-core` does not depend on `rmt-agent` (that would cycle). The
    /// agent decodes + verifies it against its pinned issuer key before granting any backstage
    /// access; on success it answers [`ControlMessage::GrantInstalled`], on failure
    /// [`ControlMessage::Error`].
    InstallGrant {
        /// The `SignedGrant` JSON blob (see `rmt_agent::backstage::grant`). Opaque to this crate.
        /// [`decode`] refuses one longer than [`MAX_SIGNED_BLOB_BYTES`] (64 KiB).
        signed_grant: String,
    },
    /// agent → controller (H1): a prior [`ControlMessage::InstallGrant`] verified and the backstage
    /// dispatcher is now armed with the granted capabilities. Backstage requests will be authorized
    /// against that grant from here on.
    GrantInstalled,
    /// controller → agent (docs/58 §2): "which Backstage features do you understand?". Answered with
    /// [`ControlMessage::BackstageFeatures`]. The controller ASKS, the agent never volunteers: an
    /// older controller's `decodeControl` throws on an unknown variant (see the module docs on the
    /// arming rule), so the agent must not speak first. An older agent drops this as undecodable, so
    /// the controller simply never learns of any feature and offers none.
    RequestBackstageFeatures,
    /// agent → controller (docs/58 §2): the answer to [`ControlMessage::RequestBackstageFeatures`].
    /// The console offers a feature only after seeing it here, so an older agent (which never sends
    /// this) is never sent a request it would drop.
    /// Known values: `confirm` (a `needs_confirmation` reply carries a token the retry echoes) and
    /// `file_manage` (CreateDirectory / RenamePath / DeletePath).
    BackstageFeatures {
        /// Feature names; unknown ones are ignored by the console.
        features: Vec<String>,
    },
    /// controller → agent (loop 79): install a control-plane-signed **session access policy** —
    /// what the ORGANISATION says this session may do, as opposed to what the controller asks for.
    /// `signed_policy` is the **opaque JSON wire form** of a
    /// `rmt_agent::session_policy::SignedSessionPolicy`, kept as a plain string here for the same
    /// reason [`ControlMessage::InstallGrant`] is (no `rmt-agent-core` → `rmt-agent` dependency
    /// cycle). The agent verifies it against the SAME pinned issuer key it uses for grants — the
    /// two are told apart by a domain-separation tag in the signed bytes, not by a second key — and
    /// answers [`ControlMessage::SessionPolicyInstalled`] on success or [`ControlMessage::Error`]
    /// on failure.
    ///
    /// A verified policy can only ever RESTRICT the session (the agent keeps the most restrictive
    /// level it has verified and refuses a later, more permissive one). That ratchet is what makes
    /// the message safe to accept more than once.
    ///
    /// Replay of a captured policy from an EARLIER session is closed separately, and since loop 86
    /// it is closed properly: the policy is BOUND to a control-plane session id, and the agent does
    /// know its own — signaling reports it on `Brokered`, but only for a ticket whose control-plane
    /// signature it verified and burned single-use. A policy naming another session is refused, and
    /// refused terminally. (An earlier version of this paragraph said the agent "cannot check
    /// freshness itself"; that has been false since loop 86 and an implementer must not build
    /// against it.)
    InstallSessionPolicy {
        /// The `SignedSessionPolicy` JSON blob. Opaque to this crate. [`decode`] refuses one
        /// longer than [`MAX_SIGNED_BLOB_BYTES`] (64 KiB).
        signed_policy: String,
    },
    /// agent → controller (loop 79): a prior [`ControlMessage::InstallSessionPolicy`] verified and
    /// is now in force.
    ///
    /// `access` is the level the POLICY carried; `view_only` is the session's EFFECTIVE input state
    /// afterwards, which is not always the same thing — the ratchet may hold a stricter level from
    /// an earlier policy, and the controller's own [`ControlMessage::SetViewOnly`] toggle also
    /// counts. A controller should drive its indicator from `view_only` and use `access` only to
    /// explain WHY (policy-enforced vs self-selected).
    SessionPolicyInstalled {
        /// The access level the verified policy carried: `"view_only"` or `"control"`. A plain
        /// string, not an enum, so an older controller renders an unfamiliar future level instead
        /// of failing to decode the whole message.
        access: String,
        /// Whether the agent is dropping the controller's injected input now that the policy is in
        /// force.
        view_only: bool,
        /// Whether the verified policy permits recording for this session. An older viewer that does
        /// not recognise this field keeps its existing allow-by-default behaviour, which is safe.
        #[serde(default = "crate::control::default_true")]
        allow_recording: bool,
        /// Whether the verified policy requires recording for this session. When `true` the viewer
        /// must auto-start recording and the agent will reject `StopRecording`. Defaults to `false`
        /// so an older agent that does not know this field keeps the optional-recording baseline.
        #[serde(default)]
        require_recording: bool,
    },
    /// agent → controller (docs/25 F03): **this session runs on a control-plane LEASE, and the
    /// controller must keep renewing it or the session ends.**
    ///
    /// Sent unprompted as soon as the session loop starts, and re-sent on every lease tick for as
    /// long as the agent holds no lease — so a controller that missed the first one still gets the
    /// message, and a dropped frame costs nobody their session.
    ///
    /// The controller answers by calling `POST /sessions/{id}/policy` on the control plane and
    /// forwarding the returned blob in an [`ControlMessage::InstallSessionPolicy`], repeatedly, for
    /// as long as it wants the session. The control plane refuses to mint once the session has been
    /// ended, the principal disabled, the tenant suspended or the machine quarantined — which is
    /// what makes an administrator's "End session" reach an unattended desktop at all.
    ///
    /// **Why the AGENT announces this instead of the console just knowing.** The console cannot tell
    /// whether a given agent is able to verify a signed policy: `grant_issuer_pubkey` is optional in
    /// `config.json` and an agent without one fails CLOSED on any policy it is sent, dropping to
    /// view-only for the rest of the session. A console that renewed unconditionally would therefore
    /// take remote control away from every agent in the fleet that never pinned the key. The one
    /// party that knows is the agent, so the agent is the one that asks.
    ///
    /// Ignoring this message is not a bypass — it is how a controller ends its own session.
    SessionLeaseRequired {
        /// How much longer the agent will wait for the FIRST lease before tearing the session down.
        /// It counts DOWN across re-announcements, because the deadline is absolute from the start
        /// of the session and is never extended.
        ///
        /// Advisory: the deadline is the agent's and is enforced whether or not this message was
        /// received or understood. It is here so a controller can log a useful warning — and so a
        /// future console can show "renewing" rather than a mysterious disconnect.
        renew_within_ms: u64,
    },
    /// controller → agent (M11): report the quality settings in force. Answered with
    /// [`ControlMessage::QualityApplied`], and it **arms** the session for `QualityStats` (see the
    /// module docs). A controller sends this on connect to discover whether the agent speaks
    /// quality at all — no reply within a couple of seconds means an older agent.
    RequestQuality,
    /// controller → agent (M11): apply these settings. Always answered with a
    /// [`ControlMessage::QualityApplied`] carrying the values that were actually accepted, so the
    /// controller learns about clamping instead of silently believing its own request.
    SetQuality {
        /// The requested settings. The agent clamps them ([`QualitySettings::clamped`]) and then
        /// applies its own machine policy ceiling before anything reads a field.
        quality: QualitySettings,
    },
    /// controller → agent: the window showing this session went to the background (`true`: the
    /// tab or window is hidden or minimised) or came back (`false`). In the background the agent
    /// sends this session about one frame a second and no keep-alive frames, and the shared capture
    /// slows with it when no other viewer wants more; the operator's [`QualitySettings`] are not
    /// touched and are back in force on `false`. Not acknowledged.
    ///
    /// A separate variant rather than a `QualitySettings` field: that struct is deliberately
    /// complete (see [`crate::quality`]), and an older agent simply drops a variant it does not
    /// know, so a newer viewer can send this to any agent.
    SetBackground {
        /// `true` while the viewer is hidden.
        background: bool,
    },
    /// agent → controller (M11): the settings actually in force after clamping.
    QualityApplied {
        /// What the agent applied.
        quality: QualitySettings,
        /// The encoder's target bitrate at this instant. Equal to `quality.max_bitrate_bps` here;
        /// it diverges afterwards when the adaptive controller lowers it.
        encoder_bitrate_bps: u32,
        /// `true` when the **machine's** configured ceiling, not the wire clamp, reduced the ask —
        /// so the operator can tell "I asked for too much" from "this machine is administratively
        /// capped".
        capped_by_policy: bool,
    },
    /// agent → controller (M11): 1 Hz streaming telemetry, sent **only after arming**.
    QualityStats {
        /// What libvpx was last successfully told (written after `set_bitrate` returned `Ok`, so it
        /// reports the encoder's state and not our intention).
        encoder_bitrate_bps: u32,
        /// Encoded access-unit bytes over the last window × 8. This is **encoder output**: it
        /// excludes RTP/SRTP headers and NACK retransmits, which makes it directly comparable with
        /// a receiver's payload accounting.
        measured_bitrate_bps: u32,
        /// RFC 3550 `fraction lost` from the newest report the rate controller acted on, in 1/256
        /// units (0..=255).
        fraction_lost_256: u32,
        /// Round-trip time in milliseconds derived from that report's LSR/DLSR. `0` = not yet
        /// measurable.
        rtt_ms: u32,
        /// Width the encoder actually encoded (post-scale, post-even-crop).
        width: u32,
        /// Height the encoder actually encoded.
        height: u32,
        /// SSRC-matched RTCP report blocks the rate controller has **consumed** this session. The
        /// anti-"my stimulus never arrived" counter: no measurement that depends on feedback should
        /// be believed until this number is moving.
        feedback_reports: u64,
        /// **Achieved** encoded frame rate over the window, in hundredths of a frame per second.
        ///
        /// The operator sets a frame rate; this is the one they are getting. They were previously
        /// never told the difference — the count existed inside the transport and was dropped on
        /// the floor at this send site. The two diverge for reasons that are not the operator's
        /// mistake and that nothing else reports: a capturer that cannot sustain the rate (the lab
        /// VM really captures at ~14 fps when commanded 30), and the encoder superseding stale
        /// frames under load (see `dropped_frames_total`).
        ///
        /// Sent as a RATE derived from the **measured** window rather than a raw count, so the
        /// receiver never has to assume the 1 Hz telemetry timer did not slip. `0` = not yet
        /// measurable, which a renderer must distinguish from a genuine zero.
        fps_x100: u32,
        /// Frames the encoder superseded via drain-to-latest, session-total.
        ///
        /// The *cause* when `fps_x100` sits below the commanded rate: capture is outrunning encode
        /// and the newest frame is winning. Monotone and session-scoped (like `feedback_reports`),
        /// so it needs no window to interpret.
        ///
        /// Wire key is `"dropped_frames"` (retained for deployed-agent compatibility; the Rust
        /// field name `dropped_frames_total` documents the semantics internally).
        #[serde(rename = "dropped_frames")]
        dropped_frames_total: u64,
    },
    /// controller → agent (privacy): block or unblock the guest's own physical keyboard & mouse for
    /// the duration of the session, so a bystander at the machine cannot interfere while the
    /// technician works. Always answered with [`ControlMessage::InputBlockApplied`] carrying the
    /// state actually in force (blocking can fail to arm — e.g. no interactive desktop — and is
    /// force-released on teardown), so the controller reflects reality rather than its own request.
    SetInputBlocked {
        /// `true` to block the guest's physical input, `false` to release it.
        blocked: bool,
    },
    /// agent → controller (privacy): the input-block state actually in force, sent in reply to every
    /// [`ControlMessage::SetInputBlocked`]. The block is also force-released when the session tears
    /// down, but no ack is sent then (the peer is usually already gone); a controller clears its own
    /// indicator when the connection drops, so it never shows a stale "blocked".
    InputBlockApplied {
        /// Whether the guest's physical input is blocked right now.
        blocked: bool,
    },
    /// controller → agent (privacy): blank or unblank the guest's screens for the duration of the
    /// session, so a bystander at the machine cannot see what the technician is doing. A solid black
    /// overlay window covers all monitors while blanked. Complementary to
    /// [`ControlMessage::SetInputBlocked`] (which freezes the guest's keyboard/mouse); either may be
    /// used independently. Always answered with [`ControlMessage::MonitorBlankedApplied`] carrying the
    /// state actually in force (blanking can fail to arm — e.g. no interactive desktop — and is
    /// force-released on teardown), so the controller reflects reality rather than its own request.
    SetMonitorBlanked {
        /// `true` to blank the guest's monitors, `false` to restore them.
        blanked: bool,
    },
    /// agent → controller (privacy): the monitor-blank state actually in force, sent in reply to
    /// every [`ControlMessage::SetMonitorBlanked`]. The overlay is also removed unconditionally when
    /// the session tears down (no ack is sent then — the peer is usually already gone); a controller
    /// clears its own indicator when the connection drops, so it never shows a stale "blanked".
    MonitorBlankedApplied {
        /// Whether the guest's screens are blanked right now.
        blanked: bool,
    },
    /// controller → agent (view-only / presentation mode): put this session into **view-only** mode, in
    /// which the agent **refuses to inject** the controller's keyboard/mouse input — the technician
    /// watches without controlling. Enforced at the AGENT (not merely the controller's "capture input"
    /// toggle, which is the controller declining to *send*): even input that reaches the agent is
    /// dropped. Answered with [`ControlMessage::ViewOnlyApplied`] carrying the state in force. Distinct
    /// from [`ControlMessage::SetInputBlocked`], which blocks the GUEST's own physical input — this is
    /// the mirror, dropping the CONTROLLER's injected input.
    SetViewOnly {
        /// `true` ⇒ enter view-only (drop injected input); `false` ⇒ resume control.
        enabled: bool,
    },
    /// agent → controller (view-only / presentation mode): the view-only state actually in force, sent
    /// in reply to every [`ControlMessage::SetViewOnly`]. View-only is also cleared when the session
    /// tears down (no ack is sent then; a controller clears its own indicator on disconnect).
    ViewOnlyApplied {
        /// Whether the agent is dropping the controller's injected input right now.
        enabled: bool,
    },
    /// controller → agent (remote support): reboot the guest machine, optionally into **Safe Mode
    /// with Networking**. The agent replies with [`ControlMessage::RebootScheduled`] immediately
    /// before it initiates the reboot, or with [`ControlMessage::Error`] if it could not arm it
    /// (insufficient privilege, a `bcdedit`/registry failure). The reboot is deliberately the LAST
    /// thing a session does — auto-reconnect on the controller side re-establishes it once the guest
    /// is back, because the persistent SYSTEM service re-registers on boot (and, for `safe_mode`, is
    /// registered to start under Safe Mode with Networking).
    RebootGuest {
        /// `true` ⇒ reboot into **Safe Mode with Networking**: the agent sets the BCD `safeboot
        /// network` element first, so the *next* boot is safe mode. `false` ⇒ an ordinary reboot,
        /// which also **clears** any safeboot element — so a normal reboot is always the way back out
        /// of Safe Mode, and a machine can never be stranded there by this command.
        safe_mode: bool,
    },
    /// agent → controller (remote support): a [`ControlMessage::RebootGuest`] was accepted and the
    /// reboot is now scheduled — the session is about to drop and the agent will re-register when the
    /// guest returns. Carries `safe_mode` so the controller can tell the operator whether to expect a
    /// normal or Safe-Mode boot. A reboot that could not be armed answers with
    /// [`ControlMessage::Error`] instead and does NOT drop the session.
    RebootScheduled {
        /// Whether the scheduled reboot is into Safe Mode with Networking.
        safe_mode: bool,
    },
    /// controller → agent (remote support): **lock the guest workstation** (the Win+L equivalent), so
    /// the machine returns to its sign-in screen and a bystander cannot use the session the technician
    /// leaves behind. The agent calls `LockWorkStation` in the interactive session and answers with
    /// [`ControlMessage::WorkstationLocked`] on success or [`ControlMessage::Error`] (e.g. when a
    /// view-only session refuses it, or the OS call fails). Locking is a control action on the guest
    /// machine, so a view-only session refuses it exactly as it refuses reboot/tool/command.
    LockWorkstation,
    /// agent → controller (remote support): a [`ControlMessage::LockWorkstation`] was carried out — the
    /// guest is now at its lock screen. Advisory; the stream keeps running (the lock shade renders on
    /// the Default desktop until a keypress switches to Winlogon).
    WorkstationLocked,
    /// controller → agent (remote support): **log off the interactive user** on the guest — ending
    /// their session and closing their apps, so the machine returns to the sign-in screen with no user
    /// logged in (distinct from [`ControlMessage::LockWorkstation`], which leaves the user logged in
    /// behind a lock shade). The agent logs off ITS OWN streamed session (`WTSLogoffSession`) and
    /// answers with [`ControlMessage::LogOffScheduled`] on success or [`ControlMessage::Error`] (e.g.
    /// when a view-only session refuses it, or the OS call fails). Logging off is a control action on
    /// the guest, so a view-only session refuses it exactly as it refuses reboot/tool/command/lock.
    LogOffGuest,
    /// agent → controller (remote support): a [`ControlMessage::LogOffGuest`] was accepted and the
    /// user's session is being torn down — the streamed session is about to drop, and auto-reconnect
    /// re-establishes at the sign-in screen once the SYSTEM service re-registers (like a reboot's
    /// return, but the machine never went down). A logoff that could not be initiated answers with
    /// [`ControlMessage::Error`] instead and does NOT drop the session.
    LogOffScheduled,
    /// controller → agent (remote support): **shut the guest machine down** (power off) — the last of
    /// the power-menu actions (lock / log off / reboot / shut down). The agent forces a shutdown via
    /// `InitiateSystemShutdownExW` (bRebootAfterShutdown = FALSE) and answers with
    /// [`ControlMessage::ShutDownScheduled`] on success or [`ControlMessage::Error`] (e.g. a view-only
    /// session refuses it, or insufficient privilege). Unlike a reboot the agent will NOT come back on
    /// its own — the machine stays off until something powers it on — so this is deliberately the most
    /// destructive control action, refused by a view-only session like reboot/lock/logoff.
    ShutDownGuest,
    /// agent → controller (remote support): a [`ControlMessage::ShutDownGuest`] was accepted and the
    /// power-off is scheduled — the session is about to drop and, unlike a reboot, will NOT re-establish
    /// until the machine is powered back on. A shutdown that could not be armed answers with
    /// [`ControlMessage::Error`] instead and does NOT drop the session.
    ShutDownScheduled,
    /// controller → agent (remote support): launch a built-in Windows admin tool on the guest's
    /// **interactive desktop**, so it appears in the technician's live stream. `tool` is a stable KEY
    /// (`"task_manager"`, `"registry_editor"`, `"event_viewer"`, `"services"`, `"device_manager"`),
    /// NOT a path or command line — the agent resolves it against a fixed whitelist and answers with
    /// [`ControlMessage::ToolLaunched`] on success or [`ControlMessage::Error`] for an unknown key or a
    /// spawn failure. The whitelist is the security boundary: this can never launch an arbitrary
    /// executable, only one of the known signed OS tools. [`decode`] refuses a `tool` key that
    /// contains any control character (`char::is_control`) or is longer than
    /// [`MAX_LAUNCH_TOOL_KEY_BYTES`] (64) bytes, so it can never forge or flood the agent's logs.
    LaunchTool {
        /// The whitelisted tool key (see the variant docs). Unknown keys are rejected, never run.
        tool: String,
    },
    /// agent → controller (remote support): a [`ControlMessage::LaunchTool`] resolved and the tool was
    /// spawned on the interactive desktop. Echoes the `tool` key so the controller can confirm which
    /// one. A launch that could not be resolved or spawned answers with [`ControlMessage::Error`].
    ToolLaunched {
        /// The tool key that was launched.
        tool: String,
    },
    /// controller → agent (remote support): the **one-line command bar** — run a single command
    /// non-interactively, capture its output, and return it. Deliberately NOT a full shell (that is the
    /// separate ConPTY backstage panel): the command runs, its stdout/stderr are captured up to a cap,
    /// it is killed if it outruns a time budget, and the agent answers with [`ControlMessage::CommandResult`]
    /// (or a [`ControlMessage::Error`] if the process could not even be started). Unlike
    /// [`ControlMessage::LaunchTool`] there is **no whitelist** — this is arbitrary execution, exactly
    /// like the ConPTY shell, and the *session itself* is the authorization (the same trust level as
    /// input injection / reboot / tool-launch). The command runs hidden (`CREATE_NO_WINDOW`), so nothing
    /// pops on the guest's screen.
    RunCommand {
        /// The command line to run (a single line). Interpreted by `shell`. [`decode`] refuses one
        /// longer than [`MAX_COMMAND_LINE_UTF16`] (32767 UTF-16 units, the `CreateProcess` limit).
        command: String,
        /// Which interpreter runs `command`.
        shell: CommandShell,
        /// `true` ⇒ run as the **interactive user** (their base token — a command is not silently
        /// elevated, unlike a launched MMC console); `false` ⇒ run as the **SYSTEM** helper, which is
        /// the high-value default for remote support (`whoami` → `NT AUTHORITY\SYSTEM`).
        ///
        /// Running with the user's *elevated* token is deliberately NOT reachable from here — the
        /// word doing the work above is *silently*. It has its own message,
        /// [`ControlMessage::ElevatedRun`], which carries a control-plane signature authorizing it.
        as_user: bool,
    },
    /// controller → agent (loop 87, docs/01 §3 "Elevate client to admin mid-session"): run ONE
    /// command with the interactive user's **linked elevated token** — their own full administrator
    /// rights, never SYSTEM — authorized by a control-plane-signed, session-bound, single-use
    /// **elevation grant**.
    ///
    /// A separate variant rather than a fourth field on [`ControlMessage::RunCommand`], for a reason
    /// that is about deployed agents and not tidiness. Nothing in this codec is
    /// `deny_unknown_fields`, so an OLDER agent handed a `RunCommand` with a new `elevated` flag
    /// would silently ignore it and run the command UNELEVATED while the technician believed
    /// otherwise — the worst possible failure for a privilege feature. And this codec rejects a
    /// MISSING field rather than defaulting it, so renaming `as_user` would make every command from
    /// a current viewer fail against every agent already in the field. A new variant has neither
    /// failure mode: an older agent simply logs and drops it.
    ///
    /// `signed_elevation` is the **opaque JSON wire form** of a
    /// `rmt_agent::elevation::SignedElevationGrant`, kept as a plain string here for the same reason
    /// [`ControlMessage::InstallGrant`] and [`ControlMessage::InstallSessionPolicy`] are (no
    /// `rmt-agent-core` → `rmt-agent` dependency cycle). The agent verifies it against the SAME
    /// pinned issuer key it uses for grants and policies — the three are told apart by a
    /// domain-separation tag in the signed bytes, not by separate keys — additionally requires it to
    /// name the LIVE control-plane session, and BURNS it, so one grant runs exactly one command.
    ///
    /// There is deliberately no `as_user` here: an elevated run is *by definition* the interactive
    /// user's linked token, so no combination of fields can ask for "SYSTEM, but signed". SYSTEM is
    /// already reachable, ungated, through `RunCommand { as_user: false }` and needs no grant.
    ///
    /// Answered with the ordinary [`ControlMessage::CommandResult`] on success, or
    /// [`ControlMessage::ElevationDenied`] whenever the elevated run was refused and NOTHING was
    /// started — deliberately stated as a rule rather than a list, because the list has grown twice
    /// and a stale enumeration reads as a guarantee. Today's causes: the session is view-only or
    /// already running a command, the grant does not verify (signature, window, machine, session),
    /// it has already been used, this host cannot elevate at all, the agent has no pinned issuer
    /// key, or the run could not start (no linked elevated token, nobody signed in, a Win32 fault).
    /// See the `ElevatedRun` arm and the `pending_command` completion arm in the agent's `host.rs`.
    ElevatedRun {
        /// The `SignedElevationGrant` JSON blob (see `rmt_agent::elevation`). Opaque to this crate.
        /// [`decode`] refuses one longer than [`MAX_SIGNED_BLOB_BYTES`] (64 KiB).
        signed_elevation: String,
        /// The command line to run (a single line). Interpreted by `shell`. [`decode`] refuses one
        /// longer than [`MAX_COMMAND_LINE_UTF16`] (32767 UTF-16 units, the `CreateProcess` limit).
        command: String,
        /// Which interpreter runs `command`.
        shell: CommandShell,
    },
    /// agent → controller (loop 87): an [`ControlMessage::ElevatedRun`] was refused, and nothing ran.
    ///
    /// Its own variant rather than a plain [`ControlMessage::Error`] because the two are not the
    /// same event and the controller must not conflate them: an `Error` after a run request reads as
    /// "the command failed", whereas this means the command was never started and the technician's
    /// elevation request was declined. Conflating them would leave a viewer unable to say whether a
    /// privileged action happened.
    ElevationDenied {
        /// Human-readable reason (the verification failure, "already used", or "this host cannot
        /// elevate"). Safe to show: it never echoes the command text.
        reason: String,
    },
    /// controller → agent (remote support): capture a **still screenshot** of the monitor currently
    /// being streamed, at its native capture resolution, and send it back as a lossless PNG. Unlike the
    /// live video (lossy VP8, quality-scaled), this is a full-resolution, lossless grab. The agent
    /// answers by **pushing the PNG over [`rmt_protocol::ChannelId::FileTransfer`]** (an `Offer` +
    /// `Chunk`s + `Done`, named `screenshot-<ts>.png`) — which the controller receives and saves like any
    /// download — or with a [`ControlMessage::Error`] if no frame has been captured yet or the encode
    /// failed. Session-authorized (same trust as the live stream it mirrors); it grants nothing the
    /// technician cannot already see streaming, so it is not separately gated.
    RequestScreenshot,
    /// controller → agent (remote support): **list a directory** on the guest, for the file browser
    /// (docs/01 §3 "File Manager — browse remote filesystem"). An empty `path` lists the drive roots
    /// (`C:\`, `D:\`, …); any other path is enumerated. The agent answers with
    /// [`ControlMessage::DirectoryListing`], [`ControlMessage::DirectoryListingRefused`] if it will
    /// not reach that path at all, or a [`ControlMessage::Error`] if the path simply cannot be read.
    ///
    /// **Gated on the `file_browse` capability and audited (docs/25 F04).** It used to be neither,
    /// on the stated grounds that a listing "grants nothing beyond what the technician can already
    /// see streaming" — which was not true, and the untruth was load-bearing: a directory listing
    /// names files that are nowhere on the screen, and `read_dir` reaches UNC paths, mapped network
    /// drives and reparse points off the volume, so the same message could make a LocalSystem,
    /// domain-joined agent authenticate to an attacker's share. The identical operation on the
    /// backstage channel (`Request::BrowseDirectory`) had required `Capability::FileBrowse` and
    /// produced an audit record since it was written; this one is now held to that same rule.
    ///
    /// Still honored under view-only, and now for a reason that survives inspection: view-only
    /// decides what may be DRIVEN on the machine (input, reboot, lock, log off, shut down), while
    /// what may be READ is decided by the grant's capabilities — which is exactly how the far more
    /// disclosing `FileTransfer` download has always worked.
    ListDirectory {
        /// The directory to list. Empty ⇒ the drive roots.
        ///
        /// [`decode`] refuses a request whose path contains any control character
        /// (`char::is_control`) or is longer than [`MAX_LIST_DIRECTORY_PATH_UTF16`] UTF-16 units, so
        /// a hostile controller cannot inject lines or bulk into the agent's audit chain and logs.
        /// UNC and `\\?\` paths still decode; the listing code owns refusing those.
        path: String,
    },
    /// agent → controller (remote support): the entries of a [`ControlMessage::ListDirectory`] path.
    /// `entries` is sorted directories-first then case-insensitively by name, and is CAPPED — a
    /// pathological directory is truncated rather than returned in full (any ordinary folder comes
    /// back complete).
    DirectoryListing {
        /// The path that was listed, echoed so a late reply is matched to its request; empty ⇒ roots.
        path: String,
        /// The directory's entries (files + subdirectories), possibly capped (see `truncated`).
        entries: Vec<DirEntry>,
        /// `true` ⇒ the directory held more than the agent's cap and `entries` is a truncated prefix
        /// (so the controller can say "showing the first N" rather than silently under-reporting).
        truncated: bool,
        /// The SEALED audit event this listing produced, as JSON (docs/25 F04).
        ///
        /// Carried on the reply for the reason spelled out at [`ControlMessage::RecordingStarted`]'s
        /// field: an event sealed into the chain but never DELIVERED leaves a `seq` hole, and the
        /// control plane's `verifyLinkage` requires strict contiguity, so one undelivered event
        /// wedges the whole session's trail at ingest permanently. Attaching it here makes "sealed"
        /// and "delivered" the same act — which is also why the agent seals this only on the path
        /// that actually produces this message.
        ///
        /// `null` when signaling vouched for no session (dev/LAN): the viewer has no forwarder then
        /// either, so there is nothing the event could be delivered to.
        #[serde(default)]
        audit: Option<serde_json::Value>,
    },
    /// agent → controller (docs/25 F04): a [`ControlMessage::ListDirectory`] was REFUSED and nothing
    /// was read — the session holds no `file_browse` capability, or the path names somewhere this
    /// agent will not reach (a UNC path, a device-namespace path, an extended-length `\\?\` path, a
    /// mapped network drive, or a link off the local disk).
    ///
    /// Its own variant rather than a plain [`ControlMessage::Error`], for two reasons that both come
    /// down to not conflating distinct events. The first is [`ControlMessage::ElevationDenied`]'s: a
    /// refusal and a failure are different things and the operator has to be able to tell "this
    /// session may not browse" from "that folder could not be read". The second is structural — a
    /// refusal is an AUDITABLE event and `Error` has nowhere to put one, so routing refusals through
    /// `Error` would have meant either sealing an event with no delivery vehicle (a `seq` hole, see
    /// `DirectoryListing::audit`) or silently not recording the attempts most worth recording.
    ///
    /// A path that merely cannot be READ (missing, not a directory, access denied by the filesystem)
    /// is still a plain `Error`: that is the OS declining, it happens constantly, and it is not a
    /// decision this agent made about anybody.
    DirectoryListingRefused {
        /// The path that was asked for, echoed so the controller can match it to its request exactly
        /// as it matches a [`ControlMessage::DirectoryListing`]; empty ⇒ the drive roots.
        path: String,
        /// Why it was refused, for the operator. Safe to show: it names the rule, never the contents
        /// of anything, and the path it echoes is the one the caller already sent.
        reason: String,
        /// The SEALED audit event for the refusal, as JSON. Same delivery contract as
        /// [`ControlMessage::DirectoryListing`]'s field. `null` when the chain has no identity.
        #[serde(default)]
        audit: Option<serde_json::Value>,
    },
    /// agent → controller (remote support): the captured result of a [`ControlMessage::RunCommand`].
    /// A process that could not be *started* (bad shell path, no interactive user for `as_user`) answers
    /// with [`ControlMessage::Error`] instead; this message means the process ran (or was killed).
    CommandResult {
        /// The process exit code. A command killed for exceeding the time budget reports the kill
        /// code (with `timed_out` set), never an absent value — every finished/killed Windows process
        /// has a code, so this is a plain `i32` and not an `Option` (no absent-means-default on this wire).
        exit_code: i32,
        /// Captured standard output (UTF-8 lossy; capped — see `truncated`).
        stdout: String,
        /// Captured standard error (UTF-8 lossy; capped — see `truncated`).
        stderr: String,
        /// `true` ⇒ stdout and/or stderr exceeded the capture cap and were cut off.
        truncated: bool,
        /// `true` ⇒ the command exceeded its time budget and was killed (its whole process tree).
        timed_out: bool,
    },
    /// controller → agent (loop 89, docs/01 §5): **start recording this session to video** on the
    /// guest's own disk. The agent tees the VP8 it is already encoding into IVF files next to a JSON
    /// sidecar (see `rmt_agent_windows::recording`), answers [`ControlMessage::RecordingStarted`],
    /// and shows the guest's window a **"being RECORDED"** banner for as long as it runs.
    ///
    /// A [`ControlMessage::Error`] comes back when the host has no recording location configured,
    /// the directory's DACL cannot be restricted, free disk is below the floor, or a recording is
    /// already running (this is not a toggle — a second start is an error, not a silent no-op,
    /// because the operator's mental model of which file their session is in must stay right).
    ///
    /// **Honored under view-only.** Recording captures exactly what the technician is already
    /// watching, so refusing it would not protect the guest — it would push the technician to a
    /// local screen recorder, where there is no guest indicator, no retention limit and no digest.
    /// What makes that acceptable is the indicator, which is why it is not optional.
    StartRecording,
    /// agent → controller (loop 89): a [`ControlMessage::StartRecording`] took effect; frames are
    /// being written from now on.
    RecordingStarted {
        /// Wall-clock start, Unix milliseconds — the epoch the recording's own timeline counts from.
        started_at_unix_ms: i64,
        /// The SEALED audit event this start produced, as JSON (loop 91).
        ///
        /// Carried on the ack rather than sent separately for a hard reason: an event that is sealed
        /// into the chain but never DELIVERED leaves a `seq` hole, and the control plane's
        /// `verifyLinkage` requires strict contiguity — so one undelivered event wedges the whole
        /// session's trail at ingest, permanently. Attaching it to the reply makes "sealed" and
        /// "delivered" the same act. The corollary is deliberate and stated where the code is: the
        /// FAILURE paths (`Error`) seal nothing, because they have no delivery vehicle.
        ///
        /// `null` when signaling vouched for no session (dev/LAN) — the viewer has no forwarder then
        /// either. Opaque `Value`, so `agent-core` does not depend on the backstage audit types; the
        /// file-transfer channel carries its events the same way.
        #[serde(default)]
        audit: Option<serde_json::Value>,
    },
    /// controller → agent (loop 89): **stop recording** and finalize the files. The agent answers
    /// [`ControlMessage::RecordingStopped`], or a [`ControlMessage::Error`] if nothing was running.
    ///
    /// A session that ends while recording stops it the same way — the recorder is finalized in the
    /// session teardown — but no `RecordingStopped` can be delivered over a transport that is
    /// already gone, so the sidecar on disk, not this message, is the record of what happened.
    StopRecording,
    /// agent → controller (loop 89): recording stopped and every file is finalized. The figures are
    /// read back from the finished artifact, not accumulated optimistically as frames were offered.
    RecordingStopped {
        /// IVF files written. More than one means the encoded resolution changed mid-session (IVF
        /// puts width/height in the file header), not that anything went wrong.
        segments: u32,
        /// Frames that reached a file.
        frames: u64,
        /// Encoded payload bytes across every segment (excludes container overhead).
        payload_bytes: u64,
        /// Why it stopped early (`"queue_full"`, `"size_limit"`, `"disk_low"`, `"io_error"`), or
        /// `None` if it ran to completion. **A truncated recording says so** — a file that merely
        /// ends looks identical to one that finished, so this is the only way the operator learns.
        ///
        /// `deserialize_with` and not a plain `Option`: see [`required_option_string`]. Absent must
        /// not mean complete.
        #[serde(deserialize_with = "required_option_string")]
        truncated: Option<String>,
        /// Frames the tee offered that never reached a file. Non-zero only alongside `truncated`.
        /// Wire key is `"dropped_frames"` — same rationale as `QualityStats::dropped_frames_total`.
        #[serde(rename = "dropped_frames")]
        dropped_frames_total: u64,
        /// The recording directory on the guest, for the operator to retrieve the files from over
        /// the file browser / file transfer. Not a URL and not a promise of durability — see the
        /// disclaimer in the sidecar.
        directory: String,
        /// The SEALED audit event this stop produced, as JSON (loop 91). Same delivery contract as
        /// [`ControlMessage::RecordingStarted`]'s field — see it for why sealing and delivering must
        /// be one act. This is the audit-valuable half: it carries the artifact's per-segment
        /// SHA-256 digests, which is what ties the audit line to the file somebody later hands over.
        #[serde(default)]
        audit: Option<serde_json::Value>,
    },
    /// controller → agent (remote support): **configurable session-end behavior** — end this session,
    /// optionally UNINSTALLING the agent afterward ("remove client"). The agent acks with
    /// [`ControlMessage::SessionEnding`] carrying the same `uninstall`, *then* tears the session down.
    ///
    /// * `uninstall == false` → a clean end. For an unattended (installed) agent this is
    ///   indistinguishable from the operator disconnecting — the agent stays installed and re-registers
    ///   ("leave installed" / "end"). For the ephemeral attended client it simply exits.
    /// * `uninstall == true` → "remove client": after acking, the unattended agent **self-uninstalls**
    ///   (removes its service, `rmt://` handler, Safe-Mode registration, and its own binary + state
    ///   directories via a detached orchestrator that outlives the process tree it kills). The attended
    ///   client has nothing installed, so it just ends.
    ///
    /// Session-authorized (same trust level as reboot / input): a controller that can reboot the machine
    /// can already render it unavailable, so removing the agent is no greater a power.
    ///
    /// **docs/65 D-C2 (supersedes the paragraph above for new agents): ONE authorization path for every removal.** An
    /// agent with a pinned directive key IGNORES `uninstall: true` unless `directive` carries a valid control-plane-signed
    /// `uninstall` directive for THIS device (`RMTDIRECTIVEv1`, issued through the removal gates: retired machine, fresh
    /// step-up, typed confirmation, cancel window, optional second approver). A bare flag ends the session and removes
    /// nothing. The removal itself is the directive engine's MSI-based, verified, reported removal, never a detached
    /// `cmd.exe`. Old agents still honour the bare flag.
    EndSession {
        /// `true` ⇒ request removal (honoured only with a valid `directive`); `false` ⇒ just end it.
        uninstall: bool,
        /// The signed uninstall directive artifact authorizing the removal (docs/65 D-C2). Absent on the wire when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        directive: Option<String>,
    },
    /// agent → controller (remote support): a [`ControlMessage::EndSession`] was accepted; the session
    /// is about to drop. Echoes `uninstall` so the controller can tell the operator whether the agent is
    /// merely disconnecting or removing itself. Sent BEFORE teardown (and, for `uninstall`, before the
    /// self-uninstall is spawned), so it reliably reaches the controller.
    SessionEnding {
        /// Whether the agent is uninstalling itself after this session ("remove client").
        uninstall: bool,
    },
    /// agent → controller (remote support): the guest revoked access at the controlled machine.
    /// Sent before teardown so the controller stops automatic session recovery.
    SessionEndedByGuest,
    /// agent → controller: the agent's configured file-transfer root, advertised once at session
    /// start alongside the initial [`ControlMessage::MonitorList`]. The viewer uses this path to
    /// determine which file-browser entries are inside the transfer root (and therefore downloadable).
    /// Mirrors [`crate::config::HelperConfig::transfer_dir_or_default`]: the `transfer_dir` key in
    /// `config.json`, or `C:\rmt-agent\transfers` when absent.
    TransferDir {
        /// Absolute Windows path of the agent's configured transfer root, e.g. `C:\rmt-agent\transfers`.
        path: String,
    },
    /// agent → controller (docs/53): whether this session can ask the guest for admin rights, sent
    /// once at session start. An agent that never sends it cannot, so the viewer shows no button.
    /// `reason` says why not (e.g. "the signed-in user is not an administrator").
    AdminRightsAvailable {
        /// Whether the button may be offered.
        available: bool,
        /// Why not, when not.
        #[serde(default)]
        reason: Option<String>,
    },
    /// controller → agent (docs/53): ask the guest for admin rights. A controlling technician in an
    /// attended session only; refused from observers and on unattended hosts.
    RequestAdminRights,
    /// agent → controller (docs/53): where a request stands. `Granted` means the guest approved UAC
    /// and the elevated input helper connected and passed its handshake, nothing more.
    AdminRightsResult {
        /// The new state.
        state: AdminRightsState,
        /// A reason to show, for `Unavailable` (and optionally others).
        #[serde(default)]
        reason: Option<String>,
    },
    /// agent → controller (docs/61): whether this agent supports in-session INPUT HAND-OFF between
    /// concurrent technicians, sent once at session start. An agent that never sends it cannot, so the
    /// viewer offers no hand-control action (affirmative capability; a timeout is not capability).
    InputHandoffAvailable {
        /// Whether the hand-control action may be offered.
        available: bool,
    },
    /// controller → agent (docs/61): hand this session's input control to another technician in the
    /// same session, named by their signaling session id. Honored only when the sender currently owns
    /// input or input is unowned; refused from observers and for an unknown/departed target (Error).
    HandInputControl {
        /// The target technician's signaling session id.
        to_session: String,
    },
    /// agent → controller (docs/61): the AUTHORITATIVE input-ownership snapshot for the whole session,
    /// sent to every participant on any change and to a session at join/reconnect. The viewer renders
    /// only this acked state (it never infers a hand succeeded). `owner_session`/`owner_name` are set
    /// only for `Owned`.
    InputControlChanged {
        /// Who owns input now, as a signaling session id — `None` for `Shared`/`Blocked`.
        #[serde(default)]
        owner_session: Option<String>,
        /// The owner's display name, for the in-page banner — `None` for `Shared`/`Blocked`.
        #[serde(default)]
        owner_name: Option<String>,
        /// The machine-wide input-arbitration mode.
        mode: InputControlMode,
    },
}

/// The machine-wide input-arbitration mode, as the viewer shows it (docs/61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputControlMode {
    /// Compatibility mode: no hand-off has been armed; input interleaves as it always has.
    Shared,
    /// One technician owns input.
    Owned,
    /// Armed but ownerless (the owner left): input is locked until an eligible technician claims it.
    Blocked,
}

/// The states of a docs/53 admin-rights request, as the viewer shows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRightsState {
    /// Waiting for the guest (our dialog, then Windows' prompt).
    Pending,
    /// The helper is connected; input reaches elevated windows.
    Granted,
    /// The guest said no, in our dialog or Windows'.
    Declined,
    /// It could not happen (see `reason`); input stays as it was.
    Unavailable,
    /// A grant ended (helper gone, revoked, or the session ending); input is local again.
    Ended,
}

/// Error decoding a control message off the wire (malformed JSON or an unknown variant/shape).
pub type ControlCodecError = serde_json::Error;

/// Encode one [`ControlMessage`] to its canonical JSON wire bytes.
///
/// Serde default helper — returns `true`. Used for `#[serde(default)]` fields whose absent-means-
/// permissive baseline is `true`, so older senders that omit the field keep the allow behaviour.
pub fn default_true() -> bool { true }

/// Infallible in practice; on the impossible serialize error it yields an empty vec, keeping the
/// send path total (matches the sibling codecs).
pub fn encode(msg: &ControlMessage) -> Vec<u8> {
    serde_json::to_vec(msg).unwrap_or_default()
}

/// Largest control frame [`decode`] will parse, in bytes: a quarter of the transport `Frame`'s
/// 64 MiB cap, and well above the largest legal frame (a 4096-entry `DirectoryListing` at about
/// 7 MB worst-case escaped, or a `CommandResult` with 2x64 KiB streams at about 0.8 MB). Anything
/// larger is refused before parsing, so a peer cannot force a multi-megabyte parse/allocation.
pub const MAX_CONTROL_WIRE_LEN: usize = 16 * 1024 * 1024;

/// Decode one [`ControlMessage`] from canonical JSON wire bytes.
///
/// Input longer than [`MAX_CONTROL_WIRE_LEN`] is refused before parsing.
pub fn decode(bytes: &[u8]) -> Result<ControlMessage, ControlCodecError> {
    if bytes.len() > MAX_CONTROL_WIRE_LEN {
        return Err(<ControlCodecError as serde::de::Error>::custom(format!(
            "control frame of {} bytes exceeds the {} byte limit",
            bytes.len(),
            MAX_CONTROL_WIRE_LEN
        )));
    }
    let msg: ControlMessage = serde_json::from_slice(bytes)?;
    if let ControlMessage::ListDirectory { path } = &msg {
        if !is_valid_list_path(path) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "list directory path contains control characters or exceeds {} UTF-16 units, got {} bytes",
                MAX_LIST_DIRECTORY_PATH_UTF16,
                path.len()
            )));
        }
    }
    if let ControlMessage::LaunchTool { tool } = &msg {
        if !is_valid_tool_key(tool) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "launch tool key contains control characters or exceeds {} bytes, got {} bytes",
                MAX_LAUNCH_TOOL_KEY_BYTES,
                tool.len()
            )));
        }
    }
    if let ControlMessage::HandInputControl { to_session } = &msg {
        if !is_valid_session_id(to_session) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "hand-input-control target id contains control characters or exceeds {} bytes, got {} bytes",
                MAX_SESSION_ID_BYTES,
                to_session.len()
            )));
        }
    }
    let command = match &msg {
        ControlMessage::RunCommand { command, .. } | ControlMessage::ElevatedRun { command, .. } => {
            Some(command)
        }
        _ => None,
    };
    if let Some(command) = command {
        if !is_valid_command_line(command) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "command line exceeds {} UTF-16 units, got {} bytes",
                MAX_COMMAND_LINE_UTF16,
                command.len()
            )));
        }
    }
    let signed_blob = match &msg {
        ControlMessage::InstallGrant { signed_grant } => Some(signed_grant),
        ControlMessage::InstallSessionPolicy { signed_policy } => Some(signed_policy),
        ControlMessage::ElevatedRun { signed_elevation, .. } => Some(signed_elevation),
        _ => None,
    };
    if let Some(blob) = signed_blob {
        if !is_valid_signed_blob(blob) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "signed blob exceeds {} bytes, got {} bytes",
                MAX_SIGNED_BLOB_BYTES,
                blob.len()
            )));
        }
    }
    Ok(msg)
}

/// Longest controller-supplied signed blob (`InstallGrant.signed_grant`,
/// `InstallSessionPolicy.signed_policy`, `ElevatedRun.signed_elevation`) [`decode`] accepts, in
/// bytes. Real signed blobs are a few hundred bytes to a few KiB.
pub const MAX_SIGNED_BLOB_BYTES: usize = 64 * 1024;

/// `true` when a signed blob fits [`MAX_SIGNED_BLOB_BYTES`]. Content is not inspected: the blob
/// stays opaque JSON that the agent verifies.
fn is_valid_signed_blob(blob: &str) -> bool {
    blob.len() <= MAX_SIGNED_BLOB_BYTES
}

/// Longest `LaunchTool` key [`decode`] accepts, in bytes. Real keys are short lowercase identifiers.
pub const MAX_LAUNCH_TOOL_KEY_BYTES: usize = 64;

/// `true` when a tool key holds no control character and fits [`MAX_LAUNCH_TOOL_KEY_BYTES`]. The
/// character set is otherwise unrestricted: unknown clean keys still reach the agent's whitelist.
fn is_valid_tool_key(key: &str) -> bool {
    !key.chars().any(char::is_control) && key.len() <= MAX_LAUNCH_TOOL_KEY_BYTES
}

/// Longest `HandInputControl` target id [`decode`] accepts, in bytes. A signaling session id is a
/// uuid (36 chars); the cap is generous but bounds a hostile frame before the agent resolves it.
pub const MAX_SESSION_ID_BYTES: usize = 128;

/// `true` when a `to_session` id holds no control character and fits [`MAX_SESSION_ID_BYTES`].
fn is_valid_session_id(id: &str) -> bool {
    !id.chars().any(char::is_control) && id.len() <= MAX_SESSION_ID_BYTES
}

/// Longest `ListDirectory` path [`decode`] accepts, in UTF-16 code units: the Windows extended
/// path limit.
pub const MAX_LIST_DIRECTORY_PATH_UTF16: usize = 32767;

/// Longest `RunCommand`/`ElevatedRun` command [`decode`] accepts, in UTF-16 code units: the Windows
/// `CreateProcess` command-line limit.
pub const MAX_COMMAND_LINE_UTF16: usize = 32767;

/// `true` when a command fits the Windows command-line limit. Content is not inspected: multi-line
/// and tab-containing commands, and the empty command, stay decodable.
fn is_valid_command_line(command: &str) -> bool {
    command.encode_utf16().count() <= MAX_COMMAND_LINE_UTF16
}

/// `true` when a requested listing path holds no control character and fits the Windows limit.
/// No real Windows path can violate either, so this refuses only hostile input.
fn is_valid_list_path(path: &str) -> bool {
    !path.chars().any(crate::file_transfer::is_windows_forbidden_control)
        && path.encode_utf16().count() <= MAX_LIST_DIRECTORY_PATH_UTF16
}

/// What an OBSERVER session (observer design v2: a technician watching, view-only from the first
/// frame) may do with an inbound control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverRule {
    /// Read-only, or affects only the observer's own stream (its monitor, its encoder quality), or
    /// can only TIGHTEN its own session (a signed policy, the view-only toggle).
    Allow,
    /// Actuating, and its handler already refuses it, with a proper reply, whenever the session is
    /// view-only. An observer session is always view-only, so the handler's own gate applies. These
    /// are listed separately (not `Refuse`) so the observer keeps the handler's specific reply.
    ViewOnlyGated,
    /// Refused for an observer at dispatch, before any handler runs: actuating with no view-only gate
    /// of its own (recording control), or a message only the agent should ever send.
    Refuse,
}

/// Classify a decoded control message for an observer session.
///
/// **Exhaustive on purpose, with no wildcard arm:** a new `ControlMessage` variant does not compile
/// until someone decides here what an observer may do with it. A default would be a decision nobody
/// made (design v2: "a new control message is denied for observers until someone adds it").
pub fn observer_rule(msg: &ControlMessage) -> ObserverRule {
    use ObserverRule::*;
    match msg {
        // Read-only, or scoped to the observer's own capture/encoder.
        ControlMessage::RequestMonitors
        | ControlMessage::SelectMonitor { .. }
        | ControlMessage::FrameDisplayed { .. }
        | ControlMessage::RequestQuality
        | ControlMessage::SetQuality { .. }
        | ControlMessage::SetBackground { .. }
        | ControlMessage::WatchedMonitors { .. }
        | ControlMessage::RequestScreenshot
        | ControlMessage::RequestBackstageFeatures
        | ControlMessage::ListDirectory { .. } => Allow,
        // Can only tighten the observer's own session: a signed policy ratchets toward view-only, the
        // toggle cannot clear the observer floor, and backstage WRITE ops are refused on the backstage
        // channel itself for observers (so a grant only ever serves reads).
        ControlMessage::InstallGrant { .. }
        | ControlMessage::InstallSessionPolicy { .. }
        | ControlMessage::SetViewOnly { .. } => Allow,
        // Actuating; each handler refuses under view-only with its own reply (EndSession: the session
        // still ends, an uninstall is dropped).
        ControlMessage::SetInputBlocked { .. }
        | ControlMessage::SetMonitorBlanked { .. }
        | ControlMessage::RebootGuest { .. }
        | ControlMessage::LockWorkstation
        | ControlMessage::LogOffGuest
        | ControlMessage::ShutDownGuest
        | ControlMessage::LaunchTool { .. }
        | ControlMessage::RunCommand { .. }
        | ControlMessage::ElevatedRun { .. }
        | ControlMessage::EndSession { .. } => ViewOnlyGated,
        // Shared recording state belongs to the controlling technician (design v2).
        ControlMessage::StartRecording { .. } | ControlMessage::StopRecording { .. } => Refuse,
        // docs/61: an observer never hands input control (it has none to hand); refused at dispatch.
        ControlMessage::HandInputControl { .. } => Refuse,
        // agent -> controller messages: never meaningful from a controller.
        ControlMessage::MonitorList { .. }
        | ControlMessage::SelectMonitorAccepted { .. }
        | ControlMessage::MonitorCanvas(_)
        | ControlMessage::MonitorPinned { .. }
        | ControlMessage::Error { .. }
        | ControlMessage::GrantInstalled
        | ControlMessage::BackstageFeatures { .. }
        | ControlMessage::SessionPolicyInstalled { .. }
        | ControlMessage::SessionLeaseRequired { .. }
        | ControlMessage::QualityApplied { .. }
        | ControlMessage::QualityStats { .. }
        | ControlMessage::InputBlockApplied { .. }
        | ControlMessage::MonitorBlankedApplied { .. }
        | ControlMessage::ViewOnlyApplied { .. }
        | ControlMessage::RebootScheduled { .. }
        | ControlMessage::WorkstationLocked
        | ControlMessage::LogOffScheduled
        | ControlMessage::ShutDownScheduled
        | ControlMessage::ToolLaunched { .. }
        | ControlMessage::ElevationDenied { .. }
        | ControlMessage::DirectoryListing { .. }
        | ControlMessage::DirectoryListingRefused { .. }
        | ControlMessage::CommandResult { .. }
        | ControlMessage::RecordingStarted { .. }
        | ControlMessage::RecordingStopped { .. }
        | ControlMessage::SessionEnding { .. }
        | ControlMessage::SessionEndedByGuest
        | ControlMessage::TransferDir { .. }
        | ControlMessage::AdminRightsAvailable { .. }
        | ControlMessage::AdminRightsResult { .. }
        | ControlMessage::InputHandoffAvailable { .. }
        | ControlMessage::InputControlChanged { .. } => Refuse,
        // docs/53: an observer never raises a UAC prompt on the guest's screen.
        ControlMessage::RequestAdminRights => Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_rule_allows_read_only_and_restricting_messages() {
        let messages = [
            ControlMessage::RequestMonitors,
            ControlMessage::SelectMonitor { id: 0 },
            ControlMessage::FrameDisplayed { selection_gen: 0 },
            ControlMessage::RequestQuality,
            ControlMessage::RequestScreenshot,
            ControlMessage::WatchedMonitors { monitors: Some(vec![0]) },
            ControlMessage::ListDirectory { path: String::new() },
            ControlMessage::InstallGrant { signed_grant: "{}".into() },
            ControlMessage::InstallSessionPolicy { signed_policy: "{}".into() },
            ControlMessage::SetViewOnly { enabled: false },
            ControlMessage::SetViewOnly { enabled: true },
        ];
        for msg in messages {
            assert!(matches!(observer_rule(&msg), ObserverRule::Allow), "{msg:?}");
        }
    }

    #[test]
    fn observer_rule_preserves_view_only_gates() {
        let messages = [
            ControlMessage::SetInputBlocked { blocked: true },
            ControlMessage::SetMonitorBlanked { blanked: true },
            ControlMessage::RebootGuest { safe_mode: false },
            ControlMessage::LockWorkstation,
            ControlMessage::LogOffGuest,
            ControlMessage::ShutDownGuest,
            ControlMessage::LaunchTool { tool: "task_manager".into() },
            ControlMessage::EndSession { uninstall: false, directive: None },
            ControlMessage::EndSession { uninstall: true, directive: None },
        ];
        for msg in messages {
            assert!(matches!(observer_rule(&msg), ObserverRule::ViewOnlyGated), "{msg:?}");
        }
    }

    #[test]
    fn observer_rule_refuses_recording_control() {
        for msg in [ControlMessage::StartRecording, ControlMessage::StopRecording] {
            assert!(matches!(observer_rule(&msg), ObserverRule::Refuse), "{msg:?}");
        }
    }

    #[test]
    fn observer_rule_refuses_agent_to_controller_messages() {
        let messages = [
            ControlMessage::SelectMonitorAccepted { selection_gen: 0 },
            ControlMessage::MonitorPinned { monitor_id: 0 },
            ControlMessage::Error { message: "refused".into() },
            ControlMessage::GrantInstalled,
            ControlMessage::BackstageFeatures { features: vec!["confirm".into()] },
            ControlMessage::ViewOnlyApplied { enabled: true },
            ControlMessage::SessionEndedByGuest,
        ];
        for msg in messages {
            assert!(matches!(observer_rule(&msg), ObserverRule::Refuse), "{msg:?}");
        }
    }

    /// Round-trip a message and assert its exact canonical JSON, so the shape is pinned and the
    /// TypeScript controller can be tested against the same strings.
    fn round_trip(msg: ControlMessage, expect_json: &str) {
        let bytes = encode(&msg);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            expect_json,
            "canonical JSON for {msg:?}"
        );
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, msg, "round-trip for {msg:?}");
    }

    /// A valid `Error` frame padded with trailing JSON whitespace to exactly `len` bytes.
    fn padded_error_frame(len: usize) -> Vec<u8> {
        let mut bytes = encode(&ControlMessage::Error { message: "x".into() });
        assert!(bytes.len() <= len);
        bytes.resize(len, b' ');
        bytes
    }

    #[test]
    fn decode_accepts_frame_at_exactly_the_limit() {
        let bytes = padded_error_frame(MAX_CONTROL_WIRE_LEN);
        assert_eq!(bytes.len(), MAX_CONTROL_WIRE_LEN);
        assert_eq!(
            decode(&bytes).expect("frame at the limit decodes"),
            ControlMessage::Error { message: "x".into() }
        );
    }

    #[test]
    fn decode_refuses_valid_json_one_byte_over_the_limit() {
        let bytes = padded_error_frame(MAX_CONTROL_WIRE_LEN + 1);
        let err = decode(&bytes).expect_err("over-limit frame is refused");
        let msg = err.to_string();
        assert!(msg.contains(&(MAX_CONTROL_WIRE_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_CONTROL_WIRE_LEN.to_string()), "{msg}");
    }

    /// One frame per command-carrying variant, each carrying `command`.
    fn command_frames(command: &str) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (
                "RunCommand",
                encode(&ControlMessage::RunCommand {
                    command: command.into(),
                    shell: CommandShell::Cmd,
                    as_user: false,
                }),
            ),
            (
                "ElevatedRun",
                encode(&ControlMessage::ElevatedRun {
                    signed_elevation: "{}".into(),
                    command: command.into(),
                    shell: CommandShell::Cmd,
                }),
            ),
        ]
    }

    #[test]
    fn command_line_realistic_multiline_tabbed_quoted_and_empty_decode() {
        for command in ["echo \"a b\"\tc\r\nwhoami\n", ""] {
            for (name, bytes) in command_frames(command) {
                let msg = decode(&bytes).unwrap_or_else(|e| panic!("{name} {command:?}: {e}"));
                match msg {
                    ControlMessage::RunCommand { command: got, .. }
                    | ControlMessage::ElevatedRun { command: got, .. } => assert_eq!(got, command),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    #[test]
    fn command_line_ascii_boundary_is_exact_for_both_variants() {
        for (name, bytes) in command_frames(&"a".repeat(MAX_COMMAND_LINE_UTF16)) {
            assert!(decode(&bytes).is_ok(), "{name} at the limit decodes");
        }
        for (name, bytes) in command_frames(&"a".repeat(MAX_COMMAND_LINE_UTF16 + 1)) {
            assert!(decode(&bytes).is_err(), "{name} one over the limit is refused");
        }
    }

    #[test]
    fn command_line_is_measured_in_utf16_units_not_chars() {
        // U+1F600 is one char but two UTF-16 units.
        for (name, bytes) in command_frames(&"\u{1F600}".repeat(16383)) {
            assert!(decode(&bytes).is_ok(), "{name}: 32766 units decodes");
        }
        let over = "\u{1F600}".repeat(16384);
        assert_eq!(over.chars().count(), 16384);
        assert_eq!(over.encode_utf16().count(), 32768);
        for (name, bytes) in command_frames(&over) {
            assert!(decode(&bytes).is_err(), "{name}: 32768 units is refused");
        }
    }

    #[test]
    fn command_line_one_mib_is_refused_and_names_the_limit() {
        for (name, bytes) in command_frames(&"a".repeat(1024 * 1024)) {
            let msg = decode(&bytes).expect_err(name).to_string();
            assert!(msg.contains(&MAX_COMMAND_LINE_UTF16.to_string()), "{name}: {msg}");
        }
    }

    #[test]
    fn command_line_cap_does_not_apply_to_command_result_output() {
        let bytes = encode(&ControlMessage::CommandResult {
            exit_code: 0,
            stdout: "o".repeat(MAX_COMMAND_LINE_UTF16 * 4),
            stderr: "e".repeat(MAX_COMMAND_LINE_UTF16 * 4),
            truncated: false,
            timed_out: false,
        });
        assert!(matches!(decode(&bytes), Ok(ControlMessage::CommandResult { .. })));
    }

    /// One frame per signed-blob variant, each carrying `blob`.
    fn signed_blob_frames(blob: &str) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("InstallGrant", encode(&ControlMessage::InstallGrant { signed_grant: blob.into() })),
            (
                "InstallSessionPolicy",
                encode(&ControlMessage::InstallSessionPolicy { signed_policy: blob.into() }),
            ),
            (
                "ElevatedRun",
                encode(&ControlMessage::ElevatedRun {
                    signed_elevation: blob.into(),
                    command: "whoami".into(),
                    shell: CommandShell::Cmd,
                }),
            ),
        ]
    }

    /// An opaque JSON-looking blob of exactly `len` bytes.
    fn blob_of_len(len: usize) -> String {
        let prefix = r#"{"claims":{"p":""#;
        let suffix = r#""},"sig":"ab"}"#;
        assert!(len >= prefix.len() + suffix.len());
        format!("{prefix}{}{suffix}", "a".repeat(len - prefix.len() - suffix.len()))
    }

    #[test]
    fn signed_blob_realistic_size_decodes_for_each_variant() {
        let blob = blob_of_len(2048);
        for (name, bytes) in signed_blob_frames(&blob) {
            assert!(decode(&bytes).is_ok(), "{name} with a 2 KiB blob must decode");
        }
    }

    #[test]
    fn signed_blob_cap_is_64_kib_and_boundary_is_exact() {
        assert_eq!(MAX_SIGNED_BLOB_BYTES, 65536);
        let at = blob_of_len(MAX_SIGNED_BLOB_BYTES);
        assert_eq!(at.len(), 65536);
        for (name, bytes) in signed_blob_frames(&at) {
            assert!(decode(&bytes).is_ok(), "{name} with exactly 65536 bytes must decode");
        }
        let over = blob_of_len(MAX_SIGNED_BLOB_BYTES + 1);
        for (name, bytes) in signed_blob_frames(&over) {
            assert!(decode(&bytes).is_err(), "{name} with 65537 bytes must be refused");
        }
    }

    #[test]
    fn signed_blob_one_mebibyte_is_refused_and_message_names_the_limit() {
        let blob = blob_of_len(1024 * 1024);
        for (name, bytes) in signed_blob_frames(&blob) {
            let msg = decode(&bytes).expect_err(name).to_string();
            assert!(msg.contains("65536"), "{name}: {msg}");
            assert!(msg.contains(&(1024 * 1024).to_string()), "{name}: {msg}");
        }
    }

    #[test]
    fn large_error_message_still_decodes_despite_signed_blob_cap() {
        let big = "e".repeat(MAX_SIGNED_BLOB_BYTES * 4);
        let msg = ControlMessage::Error { message: big };
        assert_eq!(decode(&encode(&msg)).expect("large Error decodes"), msg);
    }

    fn list_frame(path: &str) -> Vec<u8> {
        encode(&ControlMessage::ListDirectory { path: path.into() })
    }

    #[test]
    fn list_directory_accepts_ordinary_empty_unicode_unc_and_extended_paths() {
        for p in ["", r"C:\Users\Zoë", r"\\host\share", r"\\?\C:\x", r"C:\"] {
            assert_eq!(
                decode(&list_frame(p)).expect(p),
                ControlMessage::ListDirectory { path: p.into() }
            );
        }
    }

    #[test]
    fn list_directory_refuses_control_characters() {
        for p in [
            "C:\\a\n",
            "C:\\a\r\nFORGED audit line",
            "C:\\a\u{0}b",
            "C:\\a\u{1f}",
        ] {
            let err = decode(&list_frame(p)).expect_err("control char refused");
            let msg = err.to_string();
            assert!(msg.contains("32767"), "{msg}");
            assert!(msg.contains("control characters"), "{msg}");
        }
    }

    /// DEL and C1 are LEGAL in Windows file names (only C0 and NUL are not), so a folder whose name
    /// carries one must stay listable.
    #[test]
    fn list_directory_accepts_del_and_c1_which_windows_allows() {
        for p in ["C:\\a\u{7f}", "C:\\a\u{85}", "C:\\a\u{9f}b"] {
            assert_eq!(decode(&list_frame(p)).unwrap(), ControlMessage::ListDirectory { path: p.into() }, "{p:?}");
        }
    }

    #[test]
    fn list_directory_length_limit_is_32767_ascii_chars() {
        assert!(decode(&list_frame(&"a".repeat(MAX_LIST_DIRECTORY_PATH_UTF16))).is_ok());
        assert!(decode(&list_frame(&"a".repeat(MAX_LIST_DIRECTORY_PATH_UTF16 + 1))).is_err());
    }

    #[test]
    fn list_directory_limit_is_measured_in_utf16_units() {
        // U+1F600 is one char but two UTF-16 units.
        assert!(decode(&list_frame(&"\u{1F600}".repeat(16383))).is_ok());
        assert!(decode(&list_frame(&"\u{1F600}".repeat(16384))).is_err());
    }

    #[test]
    fn directory_replies_with_control_characters_are_not_refused() {
        let listing = ControlMessage::DirectoryListing {
            path: "C:\\a\nb\u{0}".into(),
            entries: vec![],
            truncated: false,
            audit: None,
        };
        assert_eq!(decode(&encode(&listing)).expect("listing"), listing);
        let refused = ControlMessage::DirectoryListingRefused {
            path: "C:\\a\r\nb".into(),
            reason: "no".into(),
            audit: None,
        };
        assert_eq!(decode(&encode(&refused)).expect("refused"), refused);
    }

    fn launch_frame(tool: &str) -> Vec<u8> {
        encode(&ControlMessage::LaunchTool { tool: tool.into() })
    }

    #[test]
    fn launch_tool_accepts_all_whitelisted_keys() {
        for k in ["task_manager", "registry_editor", "event_viewer", "services", "device_manager"] {
            assert_eq!(
                decode(&launch_frame(k)).expect(k),
                ControlMessage::LaunchTool { tool: k.into() }
            );
        }
    }

    #[test]
    fn launch_tool_refuses_control_characters() {
        for k in [
            "task_manager\n",
            "task_manager\r\nFORGED log line",
            "task\u{0}manager",
            "task_manager\u{7f}",
            "task_manager\u{85}",
        ] {
            let err = decode(&launch_frame(k)).expect_err("control char refused");
            let msg = err.to_string();
            assert!(msg.contains("64 bytes"), "{msg}");
            assert!(msg.contains("control characters"), "{msg}");
        }
    }

    #[test]
    fn launch_tool_length_limit_is_64_bytes() {
        assert!(decode(&launch_frame(&"a".repeat(MAX_LAUNCH_TOOL_KEY_BYTES))).is_ok());
        assert!(decode(&launch_frame(&"a".repeat(MAX_LAUNCH_TOOL_KEY_BYTES + 1))).is_err());
    }

    #[test]
    fn launch_tool_refuses_a_1_mib_key() {
        assert!(decode(&launch_frame(&"a".repeat(1024 * 1024))).is_err());
    }

    #[test]
    fn launch_tool_unknown_clean_and_empty_keys_still_decode() {
        for k in ["not_a_tool", ""] {
            assert_eq!(
                decode(&launch_frame(k)).expect(k),
                ControlMessage::LaunchTool { tool: k.into() }
            );
        }
    }

    #[test]
    fn tool_launched_echo_with_control_characters_is_not_refused() {
        let echo = ControlMessage::ToolLaunched { tool: "a\r\nb\u{0}".into() };
        assert_eq!(decode(&encode(&echo)).expect("echo"), echo);
    }

    #[test]
    fn decode_refuses_a_32_mib_valid_frame() {
        let bytes = padded_error_frame(32 * 1024 * 1024);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn decode_small_malformed_json_still_errors_via_serde() {
        let err = decode(b"{not json").expect_err("malformed");
        assert!(!err.to_string().contains("exceeds the"), "{err}");
        assert!(decode(b"").is_err());
    }

    #[test]
    fn request_monitors_is_a_bare_tag() {
        // A unit variant carries no `c` under adjacent tagging.
        round_trip(ControlMessage::RequestMonitors, r#"{"t":"RequestMonitors"}"#);
    }

    #[test]
    fn monitor_list_round_trips() {
        round_trip(
            ControlMessage::MonitorList {
                monitors: vec![
                    MonitorDesc { id: 0, width: 1920, height: 1080, primary: true },
                    MonitorDesc { id: 1, width: 1280, height: 1024, primary: false },
                ],
            },
            r#"{"t":"MonitorList","c":{"monitors":[{"id":0,"width":1920,"height":1080,"primary":true},{"id":1,"width":1280,"height":1024,"primary":false}]}}"#,
        );
    }

    #[test]
    fn empty_monitor_list_round_trips() {
        round_trip(
            ControlMessage::MonitorList { monitors: vec![] },
            r#"{"t":"MonitorList","c":{"monitors":[]}}"#,
        );
    }

    #[test]
    fn select_monitor_round_trips() {
        round_trip(
            ControlMessage::SelectMonitor { id: 2 },
            r#"{"t":"SelectMonitor","c":{"id":2}}"#,
        );
    }

    #[test]
    fn select_composite_monitor_round_trips() {
        // The reserved view-all id is just a u32 on the wire (u32::MAX = 4294967295); the TS mirror
        // (control.test.ts) pins the identical string.
        round_trip(
            ControlMessage::SelectMonitor { id: crate::platform::COMPOSITE_MONITOR_ID },
            r#"{"t":"SelectMonitor","c":{"id":4294967295}}"#,
        );
    }

    #[test]
    fn monitor_pinned_round_trips() {
        round_trip(
            ControlMessage::MonitorPinned { monitor_id: 2 },
            r#"{"t":"MonitorPinned","c":{"monitor_id":2}}"#,
        );
    }

    #[test]
    fn error_round_trips() {
        round_trip(
            ControlMessage::Error { message: "unknown monitor id 7".into() },
            r#"{"t":"Error","c":{"message":"unknown monitor id 7"}}"#,
        );
    }

    #[test]
    fn install_grant_round_trips() {
        // The signed grant rides as an opaque JSON string; the codec neither parses nor validates it.
        round_trip(
            ControlMessage::InstallGrant { signed_grant: r#"{"claims":{},"sig":"ab"}"#.into() },
            r#"{"t":"InstallGrant","c":{"signed_grant":"{\"claims\":{},\"sig\":\"ab\"}"}}"#,
        );
    }

    #[test]
    fn grant_installed_is_a_bare_tag() {
        // Unit variant → no `c` under adjacent tagging (like RequestMonitors).
        round_trip(ControlMessage::GrantInstalled, r#"{"t":"GrantInstalled"}"#);
    }

    #[test]
    fn request_backstage_features_is_a_bare_tag() {
        round_trip(ControlMessage::RequestBackstageFeatures, r#"{"t":"RequestBackstageFeatures"}"#);
        assert!(matches!(
            observer_rule(&ControlMessage::RequestBackstageFeatures),
            ObserverRule::Allow
        ));
    }

    #[test]
    fn backstage_features_round_trips() {
        round_trip(
            ControlMessage::BackstageFeatures { features: vec!["confirm".into(), "file_manage".into()] },
            r#"{"t":"BackstageFeatures","c":{"features":["confirm","file_manage"]}}"#,
        );
    }

    #[test]
    fn install_session_policy_round_trips() {
        // Like InstallGrant, the signed policy rides as an opaque JSON string — this crate neither
        // parses nor validates it (that is `rmt-agent`'s job, and depending on it would cycle).
        round_trip(
            ControlMessage::InstallSessionPolicy {
                signed_policy: r#"{"claims":{},"sig":"ab"}"#.into(),
            },
            r#"{"t":"InstallSessionPolicy","c":{"signed_policy":"{\"claims\":{},\"sig\":\"ab\"}"}}"#,
        );
    }

    /// docs/25 F03. The wire form is pinned because a viewer in another language decodes it, and an
    /// agent whose announcement the console cannot read is an agent whose sessions all die at the
    /// grace deadline.
    #[test]
    fn session_lease_required_round_trips() {
        round_trip(
            ControlMessage::SessionLeaseRequired { renew_within_ms: 15_000 },
            r#"{"t":"SessionLeaseRequired","c":{"renew_within_ms":15000}}"#,
        );
    }

    #[test]
    fn session_policy_installed_round_trips() {
        round_trip(
            ControlMessage::SessionPolicyInstalled {
                access: "view_only".into(),
                view_only: true,
                allow_recording: true,
                require_recording: false,
            },
            r#"{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":false}}"#,
        );
        // `access` and `view_only` are independent on the wire: a `control` policy can still leave
        // the session view-only (the controller's own toggle, or a stricter earlier policy the
        // ratchet is holding). Encoding them as one field would lose that distinction.
        round_trip(
            ControlMessage::SessionPolicyInstalled {
                access: "control".into(),
                view_only: true,
                allow_recording: false,
                require_recording: false,
            },
            r#"{"t":"SessionPolicyInstalled","c":{"access":"control","view_only":true,"allow_recording":false,"require_recording":false}}"#,
        );
        // require_recording=true: the viewer must auto-start recording and the agent rejects StopRecording.
        round_trip(
            ControlMessage::SessionPolicyInstalled {
                access: "view_only".into(),
                view_only: true,
                allow_recording: true,
                require_recording: true,
            },
            r#"{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":true}}"#,
        );
    }

    /// `access` is a plain string, deliberately: a future third level must render on an older
    /// controller rather than making the whole message undecodable. Pinned because switching it to
    /// an enum would look like a tidy-up and would silently break forward compatibility.
    ///
    /// An ABSENT `allow_recording` defaults to `true` (record-allowed) — backward-compatible: old
    /// senders that do not know this field keep the permissive baseline.
    #[test]
    fn session_policy_installed_accepts_an_unfamiliar_access_level() {
        let decoded = decode(
            br#"{"t":"SessionPolicyInstalled","c":{"access":"future_level","view_only":false}}"#,
        )
        .expect("an unknown access level must still decode");
        match decoded {
            ControlMessage::SessionPolicyInstalled { access, view_only, allow_recording, require_recording } => {
                assert_eq!(access, "future_level");
                assert!(!view_only);
                assert!(allow_recording, "absent allow_recording must default to true");
                assert!(!require_recording, "absent require_recording must default to false");
            }
            other => panic!("decoded to the wrong variant: {other:?}"),
        }
    }

    #[test]
    fn install_session_policy_requires_its_field() {
        assert!(decode(br#"{"t":"InstallSessionPolicy","c":{}}"#).is_err());
    }

    #[test]
    fn rejects_garbage_and_unknown_variants() {
        assert!(decode(b"not json").is_err());
        assert!(decode(br#"{"t":"Nope"}"#).is_err());
    }

    // --- M11 quality control ---------------------------------------------------------------
    //
    // These six literals are the cross-language contract. `web/viewer/src/lib/control.test.ts`
    // pins the SAME strings byte-for-byte; each file names the other in a comment. Reordering a
    // struct field here silently changes the bytes, and only these assertions would catch it.

    use crate::quality::{ColorMode, QualitySettings};

    #[test]
    fn request_quality_is_a_bare_tag() {
        round_trip(ControlMessage::RequestQuality, r#"{"t":"RequestQuality"}"#);
    }

    #[test]
    fn set_quality_round_trips_at_the_defaults() {
        round_trip(
            ControlMessage::SetQuality { quality: QualitySettings::DEFAULT },
            r#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true}}}"#,
        );
    }

    /// The background signal's wire form is pinned; a missing flag is rejected, not defaulted.
    #[test]
    fn set_background_round_trips_and_requires_its_flag() {
        round_trip(ControlMessage::SetBackground { background: true }, r#"{"t":"SetBackground","c":{"background":true}}"#);
        round_trip(ControlMessage::SetBackground { background: false }, r#"{"t":"SetBackground","c":{"background":false}}"#);
        assert!(decode(br#"{"t":"SetBackground","c":{}}"#).is_err());
        assert_eq!(observer_rule(&ControlMessage::SetBackground { background: true }), ObserverRule::Allow);
    }

    #[test]
    fn set_quality_round_trips_at_the_slow_link_end() {
        // A unit-only enum serializes as a bare string, so `color` is `"Gray"` and not an object.
        round_trip(
            ControlMessage::SetQuality {
                quality: QualitySettings {
                    scale_div: 2,
                    fps: 5,
                    color: ColorMode::Gray,
                    max_bitrate_bps: 400_000,
                    adaptive: false,
                },
            },
            r#"{"t":"SetQuality","c":{"quality":{"scale_div":2,"fps":5,"color":"Gray","max_bitrate_bps":400000,"adaptive":false}}}"#,
        );
    }

    #[test]
    fn quality_applied_round_trips() {
        round_trip(
            ControlMessage::QualityApplied {
                quality: QualitySettings {
                    scale_div: 4,
                    fps: 1,
                    color: ColorMode::Gray,
                    max_bitrate_bps: 100_000,
                    adaptive: true,
                },
                encoder_bitrate_bps: 100_000,
                capped_by_policy: true,
            },
            r#"{"t":"QualityApplied","c":{"quality":{"scale_div":4,"fps":1,"color":"Gray","max_bitrate_bps":100000,"adaptive":true},"encoder_bitrate_bps":100000,"capped_by_policy":true}}"#,
        );
        round_trip(
            ControlMessage::QualityApplied {
                quality: QualitySettings::DEFAULT,
                encoder_bitrate_bps: 3_000_000,
                capped_by_policy: false,
            },
            r#"{"t":"QualityApplied","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true},"encoder_bitrate_bps":3000000,"capped_by_policy":false}}"#,
        );
    }

    #[test]
    fn quality_stats_round_trips() {
        round_trip(
            ControlMessage::QualityStats {
                encoder_bitrate_bps: 742_000,
                measured_bitrate_bps: 731_520,
                fraction_lost_256: 13,
                rtt_ms: 24,
                width: 960,
                height: 540,
                feedback_reports: 42,
                fps_x100: 1_437,
                dropped_frames_total: 118,
            },
            // Wire key is "dropped_frames" (not "dropped_frames_total") — see field annotation.
            r#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}"#,
        );
    }

    /// `fps_x100` and `dropped_frames_total` are REQUIRED, like every other field on this wire.
    ///
    /// Stated as its own test because these two are the newest and the most tempting to make
    /// optional "for compatibility": a tolerant decoder would render a missing achieved frame rate
    /// as `0`, i.e. as a total stall, which is a worse lie than refusing the message. The
    /// absent-means-default rule is what shipped the `Option` whose `None` granted every
    /// capability.
    #[test]
    fn the_new_telemetry_fields_are_not_optional() {
        // Wire key is "dropped_frames"; a message with the correct wire format minus fps_x100 must be rejected.
        assert!(
            decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"dropped_frames":0}}"#).is_err(),
            "a missing fps_x100 must be rejected, not read as a stalled stream"
        );
        assert!(
            decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"fps_x100":0}}"#).is_err(),
            "a missing dropped_frames (wire key) must be rejected"
        );
    }

    /// Both deployed and current agents emit `"dropped_frames"` — the canonical wire key.
    /// `"dropped_frames_total"` was the short-lived rename from the rejected commit 6a79bb3 and is
    /// immediately reverted here. This test pins the revert: if a future change accidentally
    /// restores the rename, a new agent would silently deliver zero to an old viewer (the old
    /// viewer would read the unknown key as absent and decode the field as 0 with no error).
    /// Hard-rejecting `"dropped_frames_total"` surfaces that regression as a decode failure
    /// rather than as a silent zero on the operator's readout.
    #[test]
    fn dropped_frames_wire_key_compatibility() {
        // Old-agent / current-viewer: wire key "dropped_frames" — this is the canonical wire format.
        assert!(
            decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}"#).is_ok(),
            "QualityStats with wire key dropped_frames must be accepted"
        );
        assert!(
            decode(br#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#).is_ok(),
            "RecordingStopped with wire key dropped_frames must be accepted"
        );
        // Rejected-rename format "dropped_frames_total" must be rejected (not silently aliased).
        assert!(
            decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames_total":118}}"#).is_err(),
            "QualityStats with rejected wire key dropped_frames_total must be rejected"
        );
        assert!(
            decode(br#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames_total":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#).is_err(),
            "RecordingStopped with rejected wire key dropped_frames_total must be rejected"
        );
    }

    #[test]
    fn the_schema_owns_the_quality_constraint() {
        // The codec rejects a shape it cannot represent; it does NOT silently substitute a default.
        // A tolerant decoder here would mean an unparseable colour arrives as `Full` and the
        // operator's greyscale selection quietly does nothing.
        assert!(
            decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Sepia","max_bitrate_bps":3000000,"adaptive":true}}}"#).is_err(),
            "an unknown ColorMode must be rejected, not defaulted"
        );
        assert!(
            decode(br#"{"t":"SetQuality","c":{}}"#).is_err(),
            "a missing `quality` must be rejected — there is no partial update on this wire"
        );
        assert!(
            decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000}}}"#).is_err(),
            "a missing field must be rejected: an absent-means-default rule is what shipped the \
             Option whose None granted every capability"
        );
        // Out-of-RANGE is a different thing from out-of-SHAPE: the codec accepts it and the agent's
        // clamp is what tames it, so a hostile controller gets a working session at legal values
        // rather than a dropped frame.
        assert!(
            decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":0,"fps":0,"color":"Full","max_bitrate_bps":0,"adaptive":true}}}"#).is_ok(),
            "range is the clamp's job, not the codec's"
        );
    }

    // --- input block (privacy) -----------------------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn set_input_blocked_round_trips() {
        round_trip(
            ControlMessage::SetInputBlocked { blocked: true },
            r#"{"t":"SetInputBlocked","c":{"blocked":true}}"#,
        );
        round_trip(
            ControlMessage::SetInputBlocked { blocked: false },
            r#"{"t":"SetInputBlocked","c":{"blocked":false}}"#,
        );
    }

    #[test]
    fn input_block_applied_round_trips() {
        round_trip(
            ControlMessage::InputBlockApplied { blocked: true },
            r#"{"t":"InputBlockApplied","c":{"blocked":true}}"#,
        );
        round_trip(
            ControlMessage::InputBlockApplied { blocked: false },
            r#"{"t":"InputBlockApplied","c":{"blocked":false}}"#,
        );
    }

    #[test]
    fn input_block_requires_the_blocked_field() {
        // No partial shape on this wire (the recurring lesson): a missing `blocked` is rejected, not
        // read as some default.
        assert!(
            decode(br#"{"t":"SetInputBlocked","c":{}}"#).is_err(),
            "a missing `blocked` must be rejected"
        );
    }

    // --- monitor blank (privacy) ---------------------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn set_monitor_blanked_round_trips() {
        round_trip(
            ControlMessage::SetMonitorBlanked { blanked: true },
            r#"{"t":"SetMonitorBlanked","c":{"blanked":true}}"#,
        );
        round_trip(
            ControlMessage::SetMonitorBlanked { blanked: false },
            r#"{"t":"SetMonitorBlanked","c":{"blanked":false}}"#,
        );
    }

    #[test]
    fn monitor_blanked_applied_round_trips() {
        round_trip(
            ControlMessage::MonitorBlankedApplied { blanked: true },
            r#"{"t":"MonitorBlankedApplied","c":{"blanked":true}}"#,
        );
        round_trip(
            ControlMessage::MonitorBlankedApplied { blanked: false },
            r#"{"t":"MonitorBlankedApplied","c":{"blanked":false}}"#,
        );
    }

    #[test]
    fn monitor_blank_requires_the_blanked_field() {
        assert!(
            decode(br#"{"t":"SetMonitorBlanked","c":{}}"#).is_err(),
            "a missing `blanked` must be rejected"
        );
    }

    // --- view-only / presentation mode ---------------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn set_view_only_round_trips() {
        round_trip(
            ControlMessage::SetViewOnly { enabled: true },
            r#"{"t":"SetViewOnly","c":{"enabled":true}}"#,
        );
        round_trip(
            ControlMessage::SetViewOnly { enabled: false },
            r#"{"t":"SetViewOnly","c":{"enabled":false}}"#,
        );
    }

    #[test]
    fn view_only_applied_round_trips() {
        round_trip(
            ControlMessage::ViewOnlyApplied { enabled: true },
            r#"{"t":"ViewOnlyApplied","c":{"enabled":true}}"#,
        );
        round_trip(
            ControlMessage::ViewOnlyApplied { enabled: false },
            r#"{"t":"ViewOnlyApplied","c":{"enabled":false}}"#,
        );
    }

    #[test]
    fn set_view_only_requires_the_enabled_field() {
        assert!(
            decode(br#"{"t":"SetViewOnly","c":{}}"#).is_err(),
            "a missing `enabled` must be rejected"
        );
    }

    // --- reboot guest (remote support) ---------------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn reboot_guest_round_trips() {
        round_trip(
            ControlMessage::RebootGuest { safe_mode: true },
            r#"{"t":"RebootGuest","c":{"safe_mode":true}}"#,
        );
        round_trip(
            ControlMessage::RebootGuest { safe_mode: false },
            r#"{"t":"RebootGuest","c":{"safe_mode":false}}"#,
        );
    }

    #[test]
    fn reboot_scheduled_round_trips() {
        round_trip(
            ControlMessage::RebootScheduled { safe_mode: true },
            r#"{"t":"RebootScheduled","c":{"safe_mode":true}}"#,
        );
        round_trip(
            ControlMessage::RebootScheduled { safe_mode: false },
            r#"{"t":"RebootScheduled","c":{"safe_mode":false}}"#,
        );
    }

    // --- lock workstation (remote support) -----------------------------------------------------
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn lock_workstation_round_trips_as_bare_tags() {
        // Both directions carry no content, so they serialize as just `{"t":…}` (like RequestScreenshot).
        round_trip(ControlMessage::LockWorkstation, r#"{"t":"LockWorkstation"}"#);
        round_trip(ControlMessage::WorkstationLocked, r#"{"t":"WorkstationLocked"}"#);
    }

    // --- log off the guest (remote support) ----------------------------------------------------
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn log_off_round_trips_as_bare_tags() {
        // Both directions carry no content (like lock), so they serialize as just `{"t":…}`.
        round_trip(ControlMessage::LogOffGuest, r#"{"t":"LogOffGuest"}"#);
        round_trip(ControlMessage::LogOffScheduled, r#"{"t":"LogOffScheduled"}"#);
    }

    // --- shut down the guest (remote support) --------------------------------------------------
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn shut_down_round_trips_as_bare_tags() {
        // Both directions carry no content (like lock/logoff), so they serialize as just `{"t":…}`.
        round_trip(ControlMessage::ShutDownGuest, r#"{"t":"ShutDownGuest"}"#);
        round_trip(ControlMessage::ShutDownScheduled, r#"{"t":"ShutDownScheduled"}"#);
    }

    #[test]
    fn reboot_guest_requires_the_safe_mode_field() {
        // Same no-partial-shape rule as the input block: a missing `safe_mode` must be rejected, not
        // silently read as `false`. A reboot command is the last thing you want defaulting.
        assert!(
            decode(br#"{"t":"RebootGuest","c":{}}"#).is_err(),
            "a missing `safe_mode` must be rejected"
        );
    }

    // --- system tool launchers (remote support) ------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn launch_tool_round_trips() {
        round_trip(
            ControlMessage::LaunchTool { tool: "task_manager".into() },
            r#"{"t":"LaunchTool","c":{"tool":"task_manager"}}"#,
        );
        round_trip(
            ControlMessage::LaunchTool { tool: "registry_editor".into() },
            r#"{"t":"LaunchTool","c":{"tool":"registry_editor"}}"#,
        );
    }

    #[test]
    fn tool_launched_round_trips() {
        round_trip(
            ControlMessage::ToolLaunched { tool: "services".into() },
            r#"{"t":"ToolLaunched","c":{"tool":"services"}}"#,
        );
    }

    #[test]
    fn launch_tool_requires_the_tool_field() {
        // No partial shape: a missing `tool` is rejected, not read as an empty string (which the
        // agent's whitelist would reject anyway, but the codec must not invent the field).
        assert!(
            decode(br#"{"t":"LaunchTool","c":{}}"#).is_err(),
            "a missing `tool` must be rejected"
        );
    }

    // --- one-line command bar (remote support) -------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn run_command_round_trips() {
        // A unit-only CommandShell serializes as a BARE STRING ("Cmd"/"PowerShell"), not an object —
        // same rule as ColorMode. Field order is command, shell, as_user (declaration order).
        round_trip(
            ControlMessage::RunCommand {
                command: "whoami".into(),
                shell: CommandShell::Cmd,
                as_user: false,
            },
            r#"{"t":"RunCommand","c":{"command":"whoami","shell":"Cmd","as_user":false}}"#,
        );
        round_trip(
            ControlMessage::RunCommand {
                command: "Get-Date".into(),
                shell: CommandShell::PowerShell,
                as_user: true,
            },
            r#"{"t":"RunCommand","c":{"command":"Get-Date","shell":"PowerShell","as_user":true}}"#,
        );
    }

    #[test]
    fn list_directory_round_trips() {
        // Field order: path (the sole field). A drive path round-trips (note the escaped backslash).
        round_trip(
            ControlMessage::ListDirectory { path: r"C:\".into() },
            r#"{"t":"ListDirectory","c":{"path":"C:\\"}}"#,
        );
        // An empty path means "list the drive roots".
        round_trip(
            ControlMessage::ListDirectory { path: String::new() },
            r#"{"t":"ListDirectory","c":{"path":""}}"#,
        );
    }

    #[test]
    fn directory_listing_round_trips() {
        // A DirEntry serializes as {"name","is_dir","size","modified_unix"} (serde field order);
        // DirectoryListing is {"path","entries","truncated","audit"}. Directories-first ordering is a
        // property of the AGENT (dir_list.rs), not the wire, so the vector here is written in that
        // order deliberately.
        round_trip(
            ControlMessage::DirectoryListing {
                path: r"C:\".into(),
                entries: vec![
                    DirEntry { name: "Windows".into(), is_dir: true, size: 0, modified_unix: 1_700_000_000 },
                    DirEntry { name: "readme.txt".into(), is_dir: false, size: 42, modified_unix: 1_700_000_001 },
                ],
                truncated: false,
                audit: None,
            },
            r#"{"t":"DirectoryListing","c":{"path":"C:\\","entries":[{"name":"Windows","is_dir":true,"size":0,"modified_unix":1700000000},{"name":"readme.txt","is_dir":false,"size":42,"modified_unix":1700000001}],"truncated":false,"audit":null}}"#,
        );
        // An empty listing (an existing but empty directory) is a valid, non-error answer, and a
        // capped one sets `truncated`.
        round_trip(
            ControlMessage::DirectoryListing {
                path: String::new(),
                entries: vec![],
                truncated: true,
                audit: None,
            },
            r#"{"t":"DirectoryListing","c":{"path":"","entries":[],"truncated":true,"audit":null}}"#,
        );
    }

    /// docs/25 F04. A refusal is its own message because it is a different EVENT from a failure —
    /// and because it has to carry an audit record, which `Error` has nowhere to put.
    #[test]
    fn directory_listing_refused_round_trips() {
        round_trip(
            ControlMessage::DirectoryListingRefused {
                path: r"\\attacker\share".into(),
                reason: "network (UNC) paths are not browsable".into(),
                audit: None,
            },
            r#"{"t":"DirectoryListingRefused","c":{"path":"\\\\attacker\\share","reason":"network (UNC) paths are not browsable","audit":null}}"#,
        );
    }

    /// The same guarantee `a_sealed_audit_event_rides_the_recording_ack_unmodified` makes for
    /// recording, for the two file-browser replies: the control plane recomputes the event's
    /// canonical preimage at `/audit/ingest` and treats any field-level difference as tampering, so
    /// a codec that "helpfully" reshaped the event would present to an operator as the agent forging
    /// its own audit trail.
    #[test]
    fn a_sealed_audit_event_rides_a_directory_reply_unmodified() {
        let ev = serde_json::json!({
            "seq": 3,
            "action": {"kind": "file_browse", "path": r"C:\Users"},
            "outcome": {"result": "ok"},
            "hash": "b8f1",
        });
        let listing = ControlMessage::DirectoryListing {
            path: r"C:\Users".into(),
            entries: vec![],
            truncated: false,
            audit: Some(ev.clone()),
        };
        let back = decode(&encode(&listing)).expect("round trip");
        match back {
            ControlMessage::DirectoryListing { audit: Some(got), .. } => {
                assert_eq!(got, ev, "the sealed event must survive the codec byte for byte");
            }
            other => panic!("expected a DirectoryListing carrying an audit event, got {other:?}"),
        }

        let refused = ControlMessage::DirectoryListingRefused {
            path: r"\\attacker\share".into(),
            reason: "network (UNC) paths are not browsable".into(),
            audit: Some(ev.clone()),
        };
        let back = decode(&encode(&refused)).expect("round trip");
        match back {
            ControlMessage::DirectoryListingRefused { audit: Some(got), .. } => {
                assert_eq!(got, ev, "a refusal's event must survive the codec too");
            }
            other => panic!("expected a DirectoryListingRefused carrying an audit event, got {other:?}"),
        }
    }

    #[test]
    fn directory_messages_reject_missing_fields() {
        // Same strict-wire rule as everywhere else: no field has an absent-means-default.
        assert!(
            decode(br#"{"t":"ListDirectory","c":{}}"#).is_err(),
            "a missing `path` must be rejected"
        );
        assert!(
            decode(br#"{"t":"DirectoryListing","c":{"path":"C:\\","entries":[]}}"#).is_err(),
            "a missing `truncated` must be rejected"
        );
        assert!(
            decode(br#"{"t":"DirectoryListing","c":{"path":"C:\\","truncated":false}}"#).is_err(),
            "a missing `entries` must be rejected"
        );
        assert!(
            decode(br#"{"t":"DirectoryListing","c":{"path":"","entries":[{"name":"x","is_dir":true,"size":0}],"truncated":false}}"#).is_err(),
            "a DirEntry missing `modified_unix` must be rejected"
        );
        assert!(
            decode(br#"{"t":"DirectoryListingRefused","c":{"path":"C:\\"}}"#).is_err(),
            "a refusal missing `reason` must be rejected"
        );
        // `audit` is the one exception on these two messages, and deliberately so: an agent that
        // predates docs/25 F04 sends no `audit` key, and a reply that decoded as an error there
        // would break the file browser to protect a record that agent never sealed. An absent key is
        // `None` — the trail is thinner, but nothing false is asserted.
        assert!(
            matches!(
                decode(br#"{"t":"DirectoryListing","c":{"path":"","entries":[],"truncated":false}}"#),
                Ok(ControlMessage::DirectoryListing { audit: None, .. })
            ),
            "an absent `audit` key must decode as no event"
        );
        assert!(
            matches!(
                decode(br#"{"t":"DirectoryListingRefused","c":{"path":"","reason":"no"}}"#),
                Ok(ControlMessage::DirectoryListingRefused { audit: None, .. })
            ),
            "an absent `audit` key must decode as no event"
        );
    }

    #[test]
    fn command_result_round_trips() {
        // A clean success: the exit code, both captured streams, and the two flags.
        round_trip(
            ControlMessage::CommandResult {
                exit_code: 0,
                stdout: "nt authority\\system\r\n".into(),
                stderr: String::new(),
                truncated: false,
                timed_out: false,
            },
            r#"{"t":"CommandResult","c":{"exit_code":0,"stdout":"nt authority\\system\r\n","stderr":"","truncated":false,"timed_out":false}}"#,
        );
        // A killed-on-timeout, truncated result: exit_code is the kill code (a real value, not null),
        // and both flags are set. A negative exit code round-trips as a signed integer.
        round_trip(
            ControlMessage::CommandResult {
                exit_code: -1,
                stdout: "partial".into(),
                stderr: "boom".into(),
                truncated: true,
                timed_out: true,
            },
            r#"{"t":"CommandResult","c":{"exit_code":-1,"stdout":"partial","stderr":"boom","truncated":true,"timed_out":true}}"#,
        );
    }

    #[test]
    fn run_command_rejects_a_missing_field_or_unknown_shell() {
        // No partial shape on this wire: every field is required.
        assert!(
            decode(br#"{"t":"RunCommand","c":{"command":"whoami","as_user":false}}"#).is_err(),
            "a missing `shell` must be rejected"
        );
        assert!(
            decode(br#"{"t":"RunCommand","c":{"shell":"Cmd","as_user":false}}"#).is_err(),
            "a missing `command` must be rejected"
        );
        // `as_user` is a bool with no default — a missing one is rejected, not read as false. Running a
        // command as SYSTEM vs the user is exactly the kind of thing that must never silently default.
        assert!(
            decode(br#"{"t":"RunCommand","c":{"command":"whoami","shell":"Cmd"}}"#).is_err(),
            "a missing `as_user` must be rejected"
        );
        // An unknown shell is rejected, not defaulted to Cmd (which would run a PowerShell script line
        // through the wrong interpreter).
        assert!(
            decode(br#"{"t":"RunCommand","c":{"command":"x","shell":"Bash","as_user":false}}"#).is_err(),
            "an unknown CommandShell must be rejected"
        );
    }

    // --- elevated run (loop 87, docs/01 §3) ---------------------------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn elevated_run_round_trips() {
        // The signed elevation rides as an opaque JSON string, exactly like InstallGrant and
        // InstallSessionPolicy; this crate neither parses nor validates it.
        // Field order is declaration order: signed_elevation, command, shell.
        round_trip(
            ControlMessage::ElevatedRun {
                signed_elevation: r#"{"claims":{},"sig":"ab"}"#.into(),
                command: "whoami /groups".into(),
                shell: CommandShell::Cmd,
            },
            r#"{"t":"ElevatedRun","c":{"signed_elevation":"{\"claims\":{},\"sig\":\"ab\"}","command":"whoami /groups","shell":"Cmd"}}"#,
        );
        round_trip(
            ControlMessage::ElevatedRun {
                signed_elevation: "{}".into(),
                command: "Get-Date".into(),
                shell: CommandShell::PowerShell,
            },
            r#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"Get-Date","shell":"PowerShell"}}"#,
        );
    }

    #[test]
    fn elevation_denied_round_trips() {
        round_trip(
            ControlMessage::ElevationDenied {
                reason: "elevation grant is for a different session".into(),
            },
            r#"{"t":"ElevationDenied","c":{"reason":"elevation grant is for a different session"}}"#,
        );
    }

    #[test]
    fn elevated_run_rejects_a_missing_field_or_unknown_shell() {
        // No partial shape here either — and the stakes are higher than on RunCommand. A missing
        // `signed_elevation` that decoded as "" would hand the agent an unauthorized elevated run
        // request and rely entirely on the verifier to notice; a missing field must never get that
        // far.
        assert!(
            decode(br#"{"t":"ElevatedRun","c":{"command":"whoami","shell":"Cmd"}}"#).is_err(),
            "a missing `signed_elevation` must be rejected"
        );
        assert!(
            decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","shell":"Cmd"}}"#).is_err(),
            "a missing `command` must be rejected"
        );
        assert!(
            decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x"}}"#).is_err(),
            "a missing `shell` must be rejected"
        );
        assert!(
            decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Bash"}}"#)
                .is_err(),
            "an unknown CommandShell must be rejected"
        );
        assert!(
            decode(br#"{"t":"ElevationDenied","c":{}}"#).is_err(),
            "a missing `reason` must be rejected"
        );
        // The full shape DOES decode, so the assertions above are not passing because the variant
        // itself is unknown to the codec.
        assert!(decode(
            br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Cmd"}}"#
        )
        .is_ok());
    }

    // --- configurable session-end behavior (remote support) -----------------------------------
    //
    // Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

    #[test]
    fn end_session_round_trips() {
        round_trip(
            ControlMessage::EndSession { uninstall: false, directive: None },
            r#"{"t":"EndSession","c":{"uninstall":false}}"#,
        );
        round_trip(
            ControlMessage::EndSession { uninstall: true, directive: None },
            r#"{"t":"EndSession","c":{"uninstall":true}}"#,
        );
    }

    #[test]
    fn session_ending_round_trips() {
        round_trip(
            ControlMessage::SessionEnding { uninstall: true },
            r#"{"t":"SessionEnding","c":{"uninstall":true}}"#,
        );
        round_trip(
            ControlMessage::SessionEnding { uninstall: false },
            r#"{"t":"SessionEnding","c":{"uninstall":false}}"#,
        );
    }

    #[test]
    fn session_ended_by_guest_is_a_bare_tag() {
        round_trip(ControlMessage::SessionEndedByGuest, r#"{"t":"SessionEndedByGuest"}"#);
    }

    #[test]
    fn admin_rights_messages_have_pinned_shapes() {
        round_trip(ControlMessage::RequestAdminRights, r#"{"t":"RequestAdminRights"}"#);
        round_trip(
            ControlMessage::AdminRightsAvailable { available: false, reason: Some("the signed-in user is not an administrator".into()) },
            r#"{"t":"AdminRightsAvailable","c":{"available":false,"reason":"the signed-in user is not an administrator"}}"#,
        );
        round_trip(
            ControlMessage::AdminRightsResult { state: AdminRightsState::Granted, reason: None },
            r#"{"t":"AdminRightsResult","c":{"state":"granted","reason":null}}"#,
        );
        // An older or terser sender may omit the reason.
        assert_eq!(
            decode(br#"{"t":"AdminRightsResult","c":{"state":"declined"}}"#).unwrap(),
            ControlMessage::AdminRightsResult { state: AdminRightsState::Declined, reason: None }
        );
    }

    #[test]
    fn input_handoff_messages_have_pinned_shapes() {
        round_trip(
            ControlMessage::InputHandoffAvailable { available: true },
            r#"{"t":"InputHandoffAvailable","c":{"available":true}}"#,
        );
        round_trip(
            ControlMessage::HandInputControl { to_session: "11111111-2222-3333-4444-555555555555".into() },
            r#"{"t":"HandInputControl","c":{"to_session":"11111111-2222-3333-4444-555555555555"}}"#,
        );
        round_trip(
            ControlMessage::InputControlChanged {
                owner_session: Some("11111111-2222-3333-4444-555555555555".into()),
                owner_name: Some("Jordan".into()),
                mode: InputControlMode::Owned,
            },
            r#"{"t":"InputControlChanged","c":{"owner_session":"11111111-2222-3333-4444-555555555555","owner_name":"Jordan","mode":"owned"}}"#,
        );
        round_trip(
            ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Shared },
            r#"{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"shared"}}"#,
        );
        round_trip(
            ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Blocked },
            r#"{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"blocked"}}"#,
        );
        // A terser sender may omit the owner fields on a Shared/Blocked snapshot.
        assert_eq!(
            decode(br#"{"t":"InputControlChanged","c":{"mode":"shared"}}"#).unwrap(),
            ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Shared }
        );
        // A control character or an over-long target id is refused before the agent resolves it.
        assert!(decode(br#"{"t":"HandInputControl","c":{"to_session":"ok-id"}}"#).is_ok());
        assert!(decode(b"{\"t\":\"HandInputControl\",\"c\":{\"to_session\":\"bad\\u0007id\"}}").is_err());
        let long = "a".repeat(MAX_SESSION_ID_BYTES + 1);
        let frame = format!("{{\"t\":\"HandInputControl\",\"c\":{{\"to_session\":\"{long}\"}}}}");
        assert!(decode(frame.as_bytes()).is_err());
    }

    #[test]
    fn observers_cannot_request_admin_rights() {
        assert!(matches!(observer_rule(&ControlMessage::RequestAdminRights), ObserverRule::Refuse));
    }

    #[test]
    fn end_session_can_carry_the_signed_uninstall_directive_and_omits_it_when_absent() {
        // docs/65 D-C2: the directive rides inside EndSession; an old controller's frame (no field) still decodes, and an
        // absent directive stays off the wire (the pre-D-C2 shape is byte-identical).
        assert_eq!(
            decode(br#"{"t":"EndSession","c":{"uninstall":true}}"#).unwrap(),
            ControlMessage::EndSession { uninstall: true, directive: None }
        );
        let with = ControlMessage::EndSession { uninstall: true, directive: Some("{\"claims\":{}}".into()) };
        let wire = encode(&with);
        assert_eq!(decode(&wire).unwrap(), with);
        assert!(std::str::from_utf8(&wire).unwrap().contains("\"directive\""));
    }

    #[test]
    fn end_session_requires_the_uninstall_field() {
        // No partial shape: a missing `uninstall` must be rejected, not read as `false`. "remove
        // client" is exactly the kind of destructive choice that must never silently default.
        assert!(
            decode(br#"{"t":"EndSession","c":{}}"#).is_err(),
            "a missing `uninstall` must be rejected"
        );
    }

    #[test]
    fn transfer_dir_round_trips() {
        // Pins the exact wire shape so control.test.ts can assert the same literal.
        round_trip(
            ControlMessage::TransferDir { path: r"C:\rmt-agent\transfers".to_string() },
            r#"{"t":"TransferDir","c":{"path":"C:\\rmt-agent\\transfers"}}"#,
        );
    }

    #[test]
    fn request_screenshot_is_a_bare_tag() {
        // A unit variant → no `c` under adjacent tagging (like RequestMonitors). The TS mirror
        // (control.test.ts) pins the identical string. Success comes back as a PNG on the FileTransfer
        // channel, not a Control reply, so there is no paired response variant here.
        round_trip(ControlMessage::RequestScreenshot, r#"{"t":"RequestScreenshot"}"#);
    }

    #[test]
    fn recording_start_and_stop_are_bare_tags() {
        // Unit variants both ways (like RequestScreenshot). The TS mirror pins the same strings.
        round_trip(ControlMessage::StartRecording, r#"{"t":"StartRecording"}"#);
        round_trip(ControlMessage::StopRecording, r#"{"t":"StopRecording"}"#);
    }

    #[test]
    fn recording_replies_round_trip() {
        round_trip(
            ControlMessage::RecordingStarted {
                started_at_unix_ms: 1_764_000_000_123,
                audit: None,
            },
            r#"{"t":"RecordingStarted","c":{"started_at_unix_ms":1764000000123,"audit":null}}"#,
        );
        round_trip(
            ControlMessage::RecordingStopped {
                segments: 2,
                frames: 913,
                payload_bytes: 4_211_337,
                truncated: None,
                dropped_frames_total: 0,
                directory: r"C:\rmt-agent\recordings".to_string(),
                audit: None,
            },
            // Wire key is "dropped_frames" (retained for deployed-agent compatibility).
            r#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#,
        );
        round_trip(
            ControlMessage::RecordingStopped {
                segments: 1,
                frames: 12,
                payload_bytes: 900,
                truncated: Some("queue_full".to_string()),
                dropped_frames_total: 47,
                directory: String::new(),
                audit: None,
            },
            r#"{"t":"RecordingStopped","c":{"segments":1,"frames":12,"payload_bytes":900,"truncated":"queue_full","dropped_frames":47,"directory":"","audit":null}}"#,
        );
    }

    /// The sealed event rides on the ack, and survives the round trip byte-identically.
    ///
    /// A round trip and not merely an encode, deliberately: the console re-posts this event VERBATIM
    /// to `POST /audit/ingest`, which recomputes its canonical preimage and rejects any field-level
    /// difference as tampering. A codec that reordered, re-typed or dropped one key here would
    /// present to an operator as "the control plane thinks the agent forged its own audit trail" —
    /// and because the chain is strictly sequential, the rejection would wedge every later event in
    /// the session, not just this one.
    #[test]
    fn a_sealed_audit_event_rides_the_recording_ack_unmodified() {
        let ev = serde_json::json!({
            "id": "44444444-4444-4444-4444-444444444444",
            "seq": 0,
            "session_id": "11111111-1111-1111-1111-111111111111",
            "technician_id": "22222222-2222-2222-2222-222222222222",
            "machine_id": "33333333-3333-3333-3333-333333333333",
            "occurred_at_unix_ms": 1_730_000_000_000i64,
            "action": { "kind": "recording_started", "started_at_unix_ms": 1_730_000_000_000i64,
                        "directory": "D:/rec" },
            "outcome": { "result": "ok" },
            "prev_hash": "",
            "hash": "9f9ad6566756dd1bac7537dada03baf3e6b0ec799180e6be19c126163d9c63e4",
        });
        let msg = ControlMessage::RecordingStarted {
            started_at_unix_ms: 1_730_000_000_000,
            audit: Some(ev.clone()),
        };
        match decode(&encode(&msg)).expect("the ack decodes") {
            ControlMessage::RecordingStarted { audit: Some(got), .. } => {
                assert_eq!(got, ev, "the sealed event must survive the codec byte-for-byte");
            }
            other => panic!("expected RecordingStarted carrying an audit event, got {other:?}"),
        }
    }

    /// An ack from an agent that sealed nothing (no control-plane session was vouched for) must
    /// still decode: `audit` is `#[serde(default)]`, so an ABSENT key is `None` rather than a decode
    /// failure. Unlike `truncated` two tests up, absence here carries no dangerous second reading —
    /// no event is no event — which is exactly why the two fields are treated differently.
    #[test]
    fn a_recording_ack_without_an_audit_key_decodes_as_no_event() {
        let m = decode(br#"{"t":"RecordingStarted","c":{"started_at_unix_ms":7}}"#)
            .expect("an ack with no audit key must decode");
        assert!(matches!(
            m,
            ControlMessage::RecordingStarted { started_at_unix_ms: 7, audit: None }
        ));
    }
    #[test]
    fn a_recording_stopped_without_truncated_is_rejected_rather_than_read_as_complete() {
        // THE misreading this message exists to prevent. `truncated: null` is the "ran to
        // completion" value and is on the wire explicitly; an ABSENT key must not decode to it,
        // because the difference between the two is the difference between a complete recording and
        // one that silently stops partway — and the file looks identical either way.
        assert!(
            decode(
                // Wire key is "dropped_frames" (not "dropped_frames_total").
                br#"{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"dropped_frames":0,"directory":""}}"#
            )
            .is_err(),
            "a missing `truncated` must be rejected, not read as 'completed'"
        );
        // And the explicit null IS accepted, so the assertion above is about absence and not about
        // null — the two would be indistinguishable with only the negative case.
        assert!(decode(
            br#"{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"truncated":null,"dropped_frames":0,"directory":""}}"#
        )
        .is_ok());
        assert!(
            decode(br#"{"t":"RecordingStarted","c":{}}"#).is_err(),
            "a missing `started_at_unix_ms` must be rejected, not read as the epoch"
        );
    }

    #[test]
    fn command_result_requires_all_fields() {
        // `exit_code` is a plain i32, so a missing one is rejected by serde rather than defaulting to 0
        // — the trap the fps_x100/dropped_frames test also guards: a tolerant decoder would render a
        // command that never ran as one that exited cleanly.
        assert!(
            decode(br#"{"t":"CommandResult","c":{"stdout":"","stderr":"","truncated":false,"timed_out":false}}"#).is_err(),
            "a missing `exit_code` must be rejected, not read as 0"
        );
        assert!(
            decode(br#"{"t":"CommandResult","c":{"exit_code":0,"stdout":"","stderr":"","timed_out":false}}"#).is_err(),
            "a missing `truncated` must be rejected"
        );
    }
}

#[cfg(test)]
mod watched_tests {
    use super::*;
    #[test]
    fn watched_round_trip() {
        for (monitors, wire) in [(None, r#"{"t":"WatchedMonitors","c":{"monitors":null}}"#),
            (Some(vec![1, 3]), r#"{"t":"WatchedMonitors","c":{"monitors":[1,3]}}"#)] {
            let msg = ControlMessage::WatchedMonitors { monitors };
            assert_eq!(encode(&msg), wire.as_bytes());
            assert_eq!(decode(wire.as_bytes()).unwrap(), msg);
        }
    }
}
