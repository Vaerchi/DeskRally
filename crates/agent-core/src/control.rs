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
    /// controller → agent (docs/69 §3.2, step 1): start binding this session. `grant` is the
    /// control plane's `RMTBINDGv1` JSON (opaque here, size-bounded like other signed blobs);
    /// `console_nonce` is 64 hex chars. Answered with [`ControlMessage::BindAgentProof`], or
    /// [`ControlMessage::BindResult`] with `ok: false` when the grant does not verify.
    BindStart {
        /// The signed binding grant JSON.
        grant: String,
        /// The console's fresh nonce, hex.
        console_nonce: String,
    },
    /// agent → controller (step 2): the agent's nonce and its device-key signature over the
    /// `RMTSESSBINDv1` transcript with role 1.
    BindAgentProof {
        /// The agent's fresh nonce, hex.
        agent_nonce: String,
        /// Ed25519 signature, hex (128 chars).
        sig: String,
    },
    /// controller → agent (step 3): the console-key signature over the transcript with role 2.
    BindConsoleProof {
        /// Ed25519 signature, hex (128 chars).
        sig: String,
    },
    /// agent → controller (step 4): the binding outcome. Only after `ok: true` does an enforcing
    /// agent send a picture or accept input.
    BindResult {
        /// Whether the console's proof verified.
        ok: bool,
        /// A short machine-readable reason when `ok` is false.
        #[serde(default)]
        reason: Option<String>,
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
        ControlMessage::BindStart { grant, .. } => Some(grant),
        _ => None,
    };
    // docs/69: binding fields are fixed-length hex; refuse anything else at the codec.
    let bind_fields: &[(&str, usize)] = match &msg {
        ControlMessage::BindStart { console_nonce, .. } => &[(console_nonce.as_str(), 64)],
        ControlMessage::BindAgentProof { agent_nonce, sig } => &[(agent_nonce.as_str(), 64), (sig.as_str(), 128)],
        ControlMessage::BindConsoleProof { sig } => &[(sig.as_str(), 128)],
        _ => &[],
    };
    for (field, len) in bind_fields {
        if field.len() != *len || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(<ControlCodecError as serde::de::Error>::custom(format!(
                "binding field must be {len} hex characters"
            )));
        }
    }
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
        // docs/69: an observer's connection is bound like any other (its own grant, its own key).
        ControlMessage::BindStart { .. } | ControlMessage::BindConsoleProof { .. } => Allow,
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
        | ControlMessage::InputControlChanged { .. }
        | ControlMessage::BindAgentProof { .. }
        | ControlMessage::BindResult { .. } => Refuse,
        // docs/53: an observer never raises a UAC prompt on the guest's screen.
        ControlMessage::RequestAdminRights => Refuse,
    }
}

#[cfg(test)]
mod tests;

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
