import type { MonitorCanvas } from "./monitor_canvas";
/**
 * Canonical session-control codec + minimal client (browser side, M10 multi-monitor).
 *
 * Byte-for-byte mirror of the Rust `crates/agent-core/src/control.rs`. Messages ride as the payload
 * of a `Frame` tagged `ChannelId.Control` on the single "frames" data channel (see transport.ts).
 * The wire shape is **adjacently-tagged** JSON — `{"t":<variant>,"c":<content>}` — exactly like
 * input.ts / clipboard.ts. A unit variant (`RequestMonitors`) carries no content, so it serializes
 * as just `{"t":"RequestMonitors"}`.
 *
 * Keep this in lockstep with the Rust unit tests: the exact JSON strings here are the same literals
 * the Rust `round_trip` asserts.
 *
 * ## Flow (M10)
 *
 * 1. controller → agent: `RequestMonitors`
 * 2. agent → controller: `MonitorList { monitors }`
 * 3. controller → agent: `SelectMonitor { id }`  (silent on success — the video simply switches)
 * 4. agent → controller: `Error { message }`     (only when a `SelectMonitor` names an unknown id)
 *
 * Wiring this into `Viewer.tsx` (a monitor picker UI) is out of scope for M10 — this is the client
 * seam + codec.
 *
 * ## Flow (M11 quality control)
 *
 * 1. controller → agent: `RequestQuality` — also **arms** the session for telemetry
 * 2. agent → controller: `QualityApplied { quality, encoder_bitrate_bps, capped_by_policy }`
 * 3. controller → agent: `SetQuality { quality }`, answered with another `QualityApplied`
 * 4. agent → controller: `QualityStats { … }` at 1 Hz, **only once armed**
 *
 * The agent stays silent about quality until it is armed, so an agent talking to an older controller
 * emits byte-for-byte the traffic it always did. That is the compatibility direction; the other
 * direction — a NEW controller against an OLD agent — has no handshake to lean on, so the controller
 * discovers support by *absence*: no `QualityApplied` within a couple of seconds of `RequestQuality`
 * means the agent does not speak M11 (see `App.tsx`), and the UI says so rather than offering
 * controls that do nothing.
 */

import { ChannelId } from "./protocol";

/** One monitor as advertised by the agent. Mirror of the Rust `MonitorDesc` (serde field order). */
export interface MonitorDesc {
  id: number;
  width: number;
  height: number;
  primary: boolean;
}

/**
 * Pre-encode colour reduction. Mirror of the Rust `quality::ColorMode`, which is a unit-only enum and
 * therefore serializes as a **bare string** (`"Full"` / `"Gray"`), not an object.
 *
 * `Gray` is not a codec bit depth — VP8 is always 8-bit YUV 4:2:0 — it forces U = V = 128 so both
 * chroma planes are constant and code as skipped blocks. It is the one tier that saves bits by
 * construction rather than content-dependently.
 */
export type ColorMode = "Full" | "Gray";

/**
 * Which interpreter runs a `RunCommand`. Mirror of the Rust `control::CommandShell`, a unit-only enum,
 * so it serializes as a **bare string** (`"Cmd"` / `"PowerShell"`), not an object.
 */
export type CommandShell = "Cmd" | "PowerShell";

/** The content of an agent → controller `CommandResult`: a finished (or killed) command's capture. */
export interface CommandResult {
  /** The process exit code (`-1` when `timed_out` — the kill code). */
  exit_code: number;
  /** Captured standard output (UTF-8 lossy, capped — see `truncated`). */
  stdout: string;
  /** Captured standard error (UTF-8 lossy, capped — see `truncated`). */
  stderr: string;
  /** stdout and/or stderr hit the capture cap and were cut off. */
  truncated: boolean;
  /** The command exceeded its time budget and its process tree was killed. */
  timed_out: boolean;
}

/** One entry of a `DirectoryListing`. Mirror of the Rust `control::DirEntry` (serde field order). */
export interface DirEntry {
  /** The entry's base name (no path), e.g. `"Windows"` or `"config.json"`. */
  name: string;
  /** `true` for a directory (navigable), `false` for a file. */
  is_dir: boolean;
  /** File size in bytes (`0` for a directory). */
  size: number;
  /** Last-modified time as whole seconds since the Unix epoch (`0` if unavailable). */
  modified_unix: number;
}

/** The content of an agent → controller `DirectoryListing`: one listed directory's entries. */
export interface DirectoryListing {
  /** The path that was listed (echoed from the request); empty ⇒ the drive roots. */
  path: string;
  /** The entries, sorted directories-first then case-insensitively by name (possibly capped). */
  entries: DirEntry[];
  /** `true` ⇒ the directory held more than the agent's cap and `entries` is a truncated prefix. */
  truncated: boolean;
  /**
   * The SEALED audit event this listing produced (docs/25 F04), or null when the agent sealed none.
   *
   * It rides the reply for the reason given on `RecordingResult`'s field: an event sealed into the
   * chain but never delivered is a `seq` hole, and a hole wedges every later event in the session at
   * ingest. Hand it to the forwarder VERBATIM — the control plane recomputes its canonical preimage
   * and treats any field-level difference as tampering.
   */
  audit: SealedAuditEvent;
}

/**
 * The content of an agent → controller `DirectoryListingRefused` (docs/25 F04): the file browser was
 * told no, and nothing was read.
 *
 * Distinct from `Error` because a refusal and a failure are different events — "this session may not
 * browse" is not "that folder could not be read" — and because a refusal carries an audit record,
 * which `Error` has nowhere to put.
 */
export interface DirectoryListingRefusal {
  /** The path that was asked for (echoed from the request); empty ⇒ the drive roots. */
  path: string;
  /** Why it was refused, safe to show the operator: it names the rule, never any file. */
  reason: string;
  /** The SEALED audit event for the refusal, or null. Same delivery contract as a listing's. */
  audit: SealedAuditEvent;
}

/**
 * The SEALED audit event a recording ack carries (loop 91), or `null` when the agent sealed none.
 *
 * Deliberately opaque here. It is forwarded to `POST /audit/ingest` VERBATIM, and the control plane
 * recomputes its canonical preimage and rejects any field-level difference as tampering — so this
 * layer must not normalize, reorder or re-type a single key of it. `AuditForwarder` owns the shape
 * that is actually read (`lib/audit_forward.ts`); everything between here and the POST is a pipe.
 *
 * `null` is the honest reading of "no chain": signaling vouched for no control-plane session, so the
 * agent sealed nothing rather than sealing an event it could never deliver — an undelivered event
 * would be a `seq` hole, and a hole wedges every later event in the session at ingest.
 */
export type SealedAuditEvent = Record<string, unknown> | null;

/**
 * Decode the `audit` key off a recording ack. An absent key, an explicit null, and anything that is
 * not a JSON object all read as "no event" rather than throwing.
 *
 * Lenient on purpose, and the asymmetry with `truncated` two fields over is the point: a missing
 * `truncated` would silently turn a truncated recording into a clean one, so it is rejected, whereas
 * a missing `audit` can only mean the trail is thinner — never that a false statement gets made. And
 * the whole message is the operator's confirmation that a video of somebody's screen is being
 * written; throwing it away over an audit key the agent may legitimately omit would break the
 * feature to protect the trail.
 */
function decodeSealedAudit(v: unknown): SealedAuditEvent {
  if (v === null || v === undefined) return null;
  if (typeof v !== "object" || Array.isArray(v)) return null;
  return v as Record<string, unknown>;
}

/**
 * The content of an agent → controller `RecordingStopped`: what the finished recording actually is
 * (loop 89). Every figure is read back from the artifact on disk, not accumulated as frames went by.
 */
export interface RecordingResult {
  /** IVF files written. >1 means the encoded resolution changed mid-session, not that anything failed. */
  segments: number;
  /** Frames that reached a file. */
  frames: number;
  /** Encoded payload bytes across every segment (excludes container overhead). */
  payload_bytes: number;
  /**
   * Why it stopped early (`"queue_full"` / `"size_limit"` / `"disk_low"` / `"io_error"`), or `null`
   * if it ran to completion. **A UI that drops this is worse than one that never showed the
   * recording at all** — a truncated file ends exactly like a complete one.
   */
  truncated: string | null;
  /** Frames offered to the recorder that never reached a file. Cumulative session total; non-zero only alongside `truncated`. */
  dropped_frames_total: number;
  /** The directory on the GUEST where the local files are. Not a URL; a central copy, if the tenant stores them, is uploaded later. */
  directory: string;
}

/**
 * One **complete** quality request. Mirror of the Rust `quality::QualitySettings` (serde field order:
 * scale_div, fps, color, max_bitrate_bps, adaptive).
 *
 * Every field is required and none is optional, deliberately: a controller changing one knob does
 * read-modify-write against the last `QualityApplied` it received. There is no partial update on this
 * wire, so there is no absent-means-default rule to get wrong — the shape that once shipped an
 * `Option` whose `None` granted all 19 backstage capabilities (docs/07).
 */
export interface QualitySettings {
  /** Integer capture downscale divisor, 1..=4 (1 = 100 %, 2 = 50 %, 3 = 33 %, 4 = 25 %). */
  scale_div: number;
  /** Capture pacing target in frames/sec, 1..=60. */
  fps: number;
  /** Pre-encode colour reduction. */
  color: ColorMode;
  /** The operator's bitrate **ceiling** in bits/sec, 100_000..=20_000_000. */
  max_bitrate_bps: number;
  /** Whether the agent's loss-based controller may lower the encoder bitrate below the ceiling. */
  adaptive: boolean;
}

/** The content of an agent → controller `QualityApplied`: the settings actually in force. */
export interface QualityApplied {
  /** What the agent applied, after its clamp and its machine policy ceiling. */
  quality: QualitySettings;
  /** The encoder's target bitrate at this instant (diverges downward once the controller adapts). */
  encoder_bitrate_bps: number;
  /**
   * `true` when the **machine's** configured ceiling, not the wire clamp, reduced the ask — so the
   * operator can tell "I asked for too much" from "this machine is administratively capped".
   */
  capped_by_policy: boolean;
}

/**
 * The content of an agent → controller `QualityStats`: 1 Hz streaming telemetry.
 *
 * `feedback_reports` and `dropped_frames_total` are `u64` in Rust and `number` here. That is safe
 * rather than lucky: the first counts SSRC-matched RTCP report blocks *consumed* (~1 Hz) and the
 * second counts superseded frames (bounded by the capture rate), so reaching
 * `Number.MAX_SAFE_INTEGER` would take longer than the age of the universe. The other fields are
 * all `u32`.
 */
export interface QualityStats {
  /** What libvpx was last successfully told (written after `set_bitrate` returned `Ok`). */
  encoder_bitrate_bps: number;
  /**
   * Encoded access-unit bytes over the last window × 8. This is **encoder output**: it excludes
   * RTP/SRTP headers and NACK retransmits, so it is directly comparable with a receiver's payload
   * accounting — and is NOT the same number as a link-rate measurement.
   */
  measured_bitrate_bps: number;
  /** RFC 3550 `fraction lost` from the newest report acted on, in 1/256 units (0..=255). */
  fraction_lost_256: number;
  /** RTT in milliseconds derived from that report's LSR/DLSR. `0` = not yet measurable. */
  rtt_ms: number;
  /** Width the encoder actually encoded (post-scale, post-even-crop). */
  width: number;
  /** Height the encoder actually encoded. */
  height: number;
  /**
   * SSRC-matched RTCP report blocks the rate controller has **consumed** this session. The
   * anti-"my stimulus never arrived" counter: no field above that depends on feedback should be
   * believed until this number is moving, which is why the readout says so in words.
   */
  feedback_reports: number;
  /**
   * **Achieved** encoded frame rate over the agent's measured window, in hundredths of a frame/sec.
   *
   * The operator sets a frame rate; this is the one they are getting, and the two diverge for
   * reasons that are not the operator's mistake: a capturer that cannot sustain the rate (the lab
   * VM really captures at ~14 fps when commanded 30), and the encoder superseding stale frames
   * under load (see `dropped_frames_total`). It is a RATE over the agent's ACTUAL measured window rather
   * than a raw count, so this side never has to assume the 1 Hz telemetry timer did not slip.
   *
   * `0` = **not yet measurable**, which a renderer must distinguish from a genuine zero — see
   * `formatQualityReadout` in `quality.ts`, which prints an em dash for it exactly as it does for
   * `rtt_ms`.
   */
  fps_x100: number;
  /**
   * Frames the encoder superseded via drain-to-latest, session-total.
   *
   * The *cause* when `fps_x100` sits below the commanded rate: capture is outrunning encode and the
   * newest frame is winning. Monotone and session-scoped (like `feedback_reports`), so it needs no
   * window to interpret.
   */
  dropped_frames_total: number;
}

/** A single control message. Mirror of the Rust `ControlMessage` enum (adjacently tagged). */
export type ControlMessage =
  | { t: "RequestMonitors" }
  | { t: "MonitorList"; c: { monitors: MonitorDesc[] } }
  | { t: "SelectMonitor"; c: { id: number } }
  // agent → controller: SelectMonitor was accepted (single-session path only).
  // In multi-session pinned-display mode the agent sends MonitorPinned instead.
  | { t: "SelectMonitorAccepted"; c: { selection_gen: number } }
  // controller → agent: the controller has rendered a frame for `selection_gen`.
  // Not processed in multi-session pinned-display mode.
  | { t: "FrameDisplayed"; c: { selection_gen: number } }
  // agent → controller: in multi-session mode, one monitor is pinned for the helper lifetime.
  // Sent once on the first SelectMonitor that establishes the pin. A subsequent SelectMonitor
  // with the same id is a silent no-op (not repeated). Any SelectMonitor naming a different id
  // or COMPOSITE_MONITOR_ID is rejected with Error. Dynamic switching is deferred.
  | { t: "MonitorPinned"; c: { monitor_id: number } }
  | { t: "WatchedMonitors"; c: { monitors: number[] | null } }
  | { t: "MonitorCanvas"; c: MonitorCanvas }
  | { t: "Error"; c: { message: string } }
  // H1: install a control-plane-signed backstage grant. `signed_grant` is the opaque JSON wire form
  // of the Rust `SignedGrant` (the agent decodes + verifies it). Answered with `GrantInstalled` on
  // success or `Error` on failure.
  | { t: "InstallGrant"; c: { signed_grant: string } }
  // H1: agent → controller ack that a prior `InstallGrant` verified; backstage is now authorized.
  | { t: "GrantInstalled" }
  // docs/58 §2: controller → agent "which Backstage features do you understand?" (sent after
  // GrantInstalled), answered by `BackstageFeatures`. An older agent drops the question, so the
  // console never learns of, and never offers, a feature it lacks.
  | { t: "RequestBackstageFeatures" }
  | { t: "BackstageFeatures"; c: { features: string[] } }
  // Loops 79/80: install a control-plane-signed SESSION ACCESS POLICY — what the ORGANISATION says this
  // session may do, as opposed to what the technician asks for. `signed_policy` is the opaque JSON wire
  // form of the Rust `SignedSessionPolicy`; the agent verifies it against the SAME pinned issuer key it
  // uses for backstage grants (they are told apart by a domain tag inside the signed bytes, not a second
  // key). Answered with `SessionPolicyInstalled`, or `Error` if it does not verify.
  | { t: "InstallSessionPolicy"; c: { signed_policy: string } }
  // Loops 79/80: agent → controller ack. `access` is the level the POLICY carried; `view_only` is the
  // session's EFFECTIVE input state afterwards, which can differ — the agent applies a policy as a
  // one-way RATCHET, so a stricter policy already in force (or the technician's own toggle) still wins.
  // Drive the indicator from `view_only`; use `access` only to explain WHY.
  // `allow_recording` (loop 93): whether the group policy permits recording; absent in messages from
  // older agents, in which case it defaults to true (permissive baseline — a ban is the restriction).
  // `require_recording` (loop 89/0044): whether recording is mandatory; absent in messages from older
  // agents, defaults to false (optional baseline — mandatory is the restriction).
  // `max_session_duration_seconds` (loop 90/0045): hard time limit in seconds; 0 = unlimited; absent
  // in messages from older agents, defaults to 0 (unlimited — a cap is the restriction).
  | { t: "SessionPolicyInstalled"; c: { access: string; view_only: boolean; allow_recording: boolean; require_recording: boolean; max_session_duration_seconds: number } }
  // docs/25 F03: agent -> controller, "this session runs on a control-plane LEASE and you must keep
  // renewing it or it ends". Sent as soon as the session loop starts and re-sent every couple of
  // seconds until a lease verifies, so one dropped frame costs nobody their session.
  //
  // The AGENT announces this rather than the console assuming it, because only the agent knows
  // whether it can verify a signed policy at all: `grant_issuer_pubkey` is optional in the agent's
  // config, and an agent without one fails CLOSED on any policy it is sent — dropping to view-only
  // for the rest of the session. A console that renewed unconditionally would take remote control
  // away from every agent in the fleet that never pinned the key.
  //
  // `renew_within_ms` counts DOWN across re-announcements; the deadline is absolute from the start of
  // the session and is never extended. It is advisory — the agent enforces it whether or not this
  // message was received.
  | { t: "SessionLeaseRequired"; c: { renew_within_ms: number } }
  // M11: controller → agent "report the quality in force" — also arms the session for QualityStats.
  | { t: "RequestQuality" }
  // M11: controller → agent "apply these settings". Always answered with a `QualityApplied` carrying
  // the values actually accepted, so the controller learns about clamping instead of believing itself.
  | { t: "SetQuality"; c: { quality: QualitySettings } }
  // controller → agent: every window showing this session is hidden (`true`) or one is shown again
  // (`false`); see lib/background.ts. Not acknowledged; an older agent drops it.
  | { t: "SetBackground"; c: { background: boolean } }
  // M11: agent → controller, the settings actually in force after clamping + machine policy.
  | { t: "QualityApplied"; c: QualityApplied }
  // M11: agent → controller, 1 Hz telemetry (only after arming).
  | { t: "QualityStats"; c: QualityStats }
  // Privacy: controller → agent "block/unblock the guest's own keyboard & mouse". Answered with
  // `InputBlockApplied` carrying the state actually in force.
  | { t: "SetInputBlocked"; c: { blocked: boolean } }
  // Privacy: agent → controller, the input-block state in force (reply to `SetInputBlocked`).
  | { t: "InputBlockApplied"; c: { blocked: boolean } }
  // Privacy: controller → agent "blank/unblank the guest's monitors" — a solid black overlay
  // covers all displays so a bystander cannot see what the technician is doing. Answered with
  // `MonitorBlankedApplied` carrying the state actually in force.
  | { t: "SetMonitorBlanked"; c: { blanked: boolean } }
  // Privacy: agent → controller, the monitor-blank state in force (reply to `SetMonitorBlanked`).
  | { t: "MonitorBlankedApplied"; c: { blanked: boolean } }
  // View-only: controller → agent "watch without controlling" — the agent DROPS injected input.
  // Answered with `ViewOnlyApplied` carrying the state in force.
  | { t: "SetViewOnly"; c: { enabled: boolean } }
  // View-only: agent → controller, the view-only state in force (reply to `SetViewOnly`).
  | { t: "ViewOnlyApplied"; c: { enabled: boolean } }
  // Remote support: controller → agent "reboot the guest" (safe_mode = Safe Mode with Networking).
  // Answered with `RebootScheduled` if armed, else `Error` (and the session keeps running).
  | { t: "RebootGuest"; c: { safe_mode: boolean } }
  // Remote support: agent → controller, the reboot is scheduled and the session is about to drop.
  | { t: "RebootScheduled"; c: { safe_mode: boolean } }
  // Remote support: controller → agent "lock the guest workstation" (Win+L). Answered with
  // `WorkstationLocked`, or `Error` (e.g. a view-only session refuses it). No content.
  | { t: "LockWorkstation" }
  // Remote support: agent → controller, the guest is now at its lock screen. No content.
  | { t: "WorkstationLocked" }
  // Remote support: controller → agent "log off the guest's interactive user" (ends their session,
  // unlike lock). Answered with `LogOffScheduled`, or `Error` (e.g. a view-only session refuses it).
  | { t: "LogOffGuest" }
  // Remote support: agent → controller, the user is being logged off and the session is about to drop.
  | { t: "LogOffScheduled" }
  // Remote support: controller → agent "shut the guest machine down" (power off). Answered with
  // `ShutDownScheduled`, or `Error` (e.g. a view-only session refuses it). The agent does NOT come back.
  | { t: "ShutDownGuest" }
  // Remote support: agent → controller, the power-off is scheduled and the session is about to drop.
  | { t: "ShutDownScheduled" }
  // Remote support: controller → agent "launch this whitelisted admin tool on the guest desktop".
  // `tool` is a stable key; the agent resolves it and answers `ToolLaunched` or `Error`.
  | { t: "LaunchTool"; c: { tool: string } }
  // Remote support: agent → controller, the tool was spawned on the interactive desktop.
  | { t: "ToolLaunched"; c: { tool: string } }
  // Remote support: controller → agent "run this one-line command, capture output" (`as_user` picks
  // SYSTEM vs the interactive user). Answered with `CommandResult`, or `Error` if it could not start.
  | { t: "RunCommand"; c: { command: string; shell: CommandShell; as_user: boolean } }
  // Remote support: agent → controller, the captured result of a `RunCommand` OR an `ElevatedRun`.
  | { t: "CommandResult"; c: CommandResult }
  // Remote support (loop 87, docs/01 §3): controller → agent "run this ONE command with the guest's
  // LINKED ELEVATED token", authorized by a control-plane-signed, session-bound, single-use elevation
  // grant carried opaquely as JSON. Answered with `CommandResult` on success, or `ElevationDenied`
  // (NOT a plain `Error`) if the grant does not verify, has been used, or this host cannot elevate.
  //
  // A separate message rather than a flag on `RunCommand`, deliberately: an agent already in the
  // field would silently IGNORE an unknown extra field and run the command unelevated while the
  // technician believed otherwise. It drops an unknown message instead, which is honest.
  | { t: "ElevatedRun"; c: { signed_elevation: string; command: string; shell: CommandShell } }
  // Remote support: agent → controller, an `ElevatedRun` was refused and NOTHING ran. Distinct from
  // `Error` on purpose — "the command failed" and "the command never started" must not be conflated
  // when the difference is whether a privileged action happened.
  | { t: "ElevationDenied"; c: { reason: string } }
  // Remote support: controller → agent, list a directory for the file browser (empty path = drives).
  | { t: "ListDirectory"; c: { path: string } }
  // Remote support: agent → controller, the entries of a `ListDirectory` path.
  | { t: "DirectoryListing"; c: DirectoryListing }
  // Remote support: agent → controller, a `ListDirectory` was REFUSED and nothing was read (docs/25
  // F04) — no `file_browse` capability, or a path this agent will not reach (UNC, device namespace,
  // `\\?\`, a mapped network drive, a link off the local disk).
  | { t: "DirectoryListingRefused"; c: DirectoryListingRefusal }
  // Remote support: controller → agent "take a full-res lossless screenshot". No Control reply — the
  // agent PUSHES the PNG over the FileTransfer channel (received + saved like any download), or sends
  // `Error` if no frame has been captured yet.
  | { t: "RequestScreenshot" }
  // Session recording (loop 89): controller → agent "record this session to a file on the guest's
  // disk". Answered with `RecordingStarted`, or `Error` (no location configured, no disk, DACL
  // refused, or one is already running — a second start is an error, not a silent no-op).
  | { t: "StartRecording" }
  // Session recording: agent → controller, frames are being written from now on.
  | { t: "RecordingStarted"; c: { started_at_unix_ms: number; audit: SealedAuditEvent } }
  // Session recording: controller → agent "stop and finalize". `Error` if nothing was running.
  | { t: "StopRecording" }
  // Session recording: agent → controller, everything is finalized. The figures come from the
  // finished artifact, and `truncated` is the only way the operator learns a recording stopped early
  // — a file that merely ends looks identical to one that finished.
  | {
      t: "RecordingStopped";
      c: {
        segments: number;
        frames: number;
        payload_bytes: number;
        truncated: string | null;
        dropped_frames_total: number;
        directory: string;
        audit: SealedAuditEvent;
      };
    }
  // Remote support: controller → agent "end this session" — with `uninstall`, "remove client" (the
  // unattended agent self-uninstalls after acking). Answered with `SessionEnding` just before the drop.
  | { t: "EndSession"; c: { uninstall: boolean } }
  // Remote support: agent → controller, the session is ending (echoes `uninstall`). Sent before teardown.
  | { t: "SessionEnding"; c: { uninstall: boolean } }
  // agent → controller: the guest revoked access; stop automatic session recovery before teardown.
  | { t: "SessionEndedByGuest" }
  // agent → controller: the agent's configured file-transfer root, sent once at session start
  // alongside the initial `MonitorList`. The viewer uses this to determine which file-browser
  // entries are downloadable (path must be inside the root). Mirrors `config.json` `transfer_dir`,
  // or `C:\rmt-agent\transfers` when absent.
  | { t: "TransferDir"; c: { path: string } }
  // docs/53, agent → controller: whether this attended session can ask the guest for admin rights,
  // sent once at session start. An agent that never sends it cannot; the viewer offers no button.
  | { t: "AdminRightsAvailable"; c: { available: boolean; reason: string | null } }
  // docs/53, controller → agent: ask the guest for admin rights (a controlling technician only).
  | { t: "RequestAdminRights" }
  // docs/53, agent → controller: where a request stands.
  | { t: "AdminRightsResult"; c: { state: AdminRightsState; reason: string | null } }
  // docs/61, agent → controller: whether this agent supports in-session INPUT HAND-OFF between
  // concurrent technicians, sent once at session start. An agent that never sends it cannot, so the
  // viewer offers no hand-control action (affirmative capability; a timeout is not capability).
  | { t: "InputHandoffAvailable"; c: { available: boolean } }
  // docs/61, controller → agent: hand this session's input control to another technician named by
  // their signaling session id. Refused from observers and for an unknown/departed target (Error).
  | { t: "HandInputControl"; c: { to_session: string } }
  // docs/61, agent → controller: the AUTHORITATIVE input-ownership snapshot for the whole session,
  // sent to every participant on any change and at join/reconnect. The viewer renders only this
  // acked state. owner_session/owner_name are set only for "owned".
  | { t: "InputControlChanged"; c: { owner_session: string | null; owner_name: string | null; mode: InputControlMode } };

/** docs/53: the states of an admin-rights request. */
export type AdminRightsState = "pending" | "granted" | "declined" | "unavailable" | "ended";
const ADMIN_RIGHTS_STATES: readonly AdminRightsState[] = ["pending", "granted", "declined", "unavailable", "ended"];

/** docs/61: the machine-wide input-arbitration mode, as the viewer shows it. */
export type InputControlMode = "shared" | "owned" | "blocked";
const INPUT_CONTROL_MODES: readonly InputControlMode[] = ["shared", "owned", "blocked"];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * The nested `quality` object literal, rebuilt in serde declaration order.
 *
 * `JSON.stringify` emits string keys in insertion order, so the ONLY thing keeping our bytes equal to
 * serde's is the order the properties are written here. Two messages carry a `QualitySettings`
 * (`SetQuality` and `QualityApplied`), and duplicating the literal would mean a field reorder could be
 * fixed in one and missed in the other — so the order lives here, once, and both arms call it.
 */
function qualityJson(q: QualitySettings) {
  return {
    scale_div: q.scale_div,
    fps: q.fps,
    color: q.color,
    max_bitrate_bps: q.max_bitrate_bps,
    adaptive: q.adaptive,
  };
}

/**
 * Encode one {@link ControlMessage} to its canonical JSON wire bytes (UTF-8), byte-compatible with
 * Rust `control::decode`. The unit variant `RequestMonitors` is emitted as a bare `{"t":…}` (no `c`),
 * matching serde's adjacent tagging; the others emit `{"t":…,"c":…}`. Field order is pinned to
 * serde's output so the bytes are identical to Rust.
 */
export function encodeControl(msg: ControlMessage): Uint8Array {
  let obj: unknown;
  switch (msg.t) {
    case "RequestMonitors":
      obj = { t: msg.t };
      break;
    case "MonitorList":
      // Rebuild each MonitorDesc in serde field order (id, width, height, primary).
      obj = {
        t: msg.t,
        c: {
          monitors: msg.c.monitors.map((m) => ({
            id: m.id,
            width: m.width,
            height: m.height,
            primary: m.primary,
          })),
        },
      };
      break;
    case "SelectMonitor":
      obj = { t: msg.t, c: { id: msg.c.id } };
      break;
    case "SelectMonitorAccepted":
      obj = { t: msg.t, c: { selection_gen: msg.c.selection_gen } };
      break;
    case "FrameDisplayed":
      obj = { t: msg.t, c: { selection_gen: msg.c.selection_gen } };
      break;
    case "WatchedMonitors":
      obj = { t: msg.t, c: { monitors: msg.c.monitors } };
      break;
    case "MonitorCanvas":
      obj = { t: msg.t, c: msg.c };
      break;
    case "MonitorPinned":
      obj = { t: msg.t, c: { monitor_id: msg.c.monitor_id } };
      break;
    case "Error":
      obj = { t: msg.t, c: { message: msg.c.message } };
      break;
    case "InstallGrant":
      obj = { t: msg.t, c: { signed_grant: msg.c.signed_grant } };
      break;
    case "GrantInstalled":
    case "SessionEndedByGuest":
    case "RequestAdminRights":
    case "RequestBackstageFeatures":
      obj = { t: msg.t };
      break;
    case "BackstageFeatures":
      obj = { t: msg.t, c: { features: [...msg.c.features] } };
      break;
    case "InstallSessionPolicy":
      obj = { t: msg.t, c: { signed_policy: msg.c.signed_policy } };
      break;
    case "SessionPolicyInstalled":
      obj = { t: msg.t, c: { access: msg.c.access, view_only: msg.c.view_only, allow_recording: msg.c.allow_recording, require_recording: msg.c.require_recording, max_session_duration_seconds: msg.c.max_session_duration_seconds } };
      break;
    case "SessionLeaseRequired":
      obj = { t: msg.t, c: { renew_within_ms: msg.c.renew_within_ms } };
      break;
    case "RequestQuality":
      obj = { t: msg.t };
      break;
    case "SetQuality":
      obj = { t: msg.t, c: { quality: qualityJson(msg.c.quality) } };
      break;
    case "SetBackground":
      obj = { t: msg.t, c: { background: msg.c.background } };
      break;
    case "QualityApplied":
      obj = {
        t: msg.t,
        c: {
          quality: qualityJson(msg.c.quality),
          encoder_bitrate_bps: msg.c.encoder_bitrate_bps,
          capped_by_policy: msg.c.capped_by_policy,
        },
      };
      break;
    case "QualityStats":
      // Rebuilt in serde field order; the controller never sends this, but pinning the encoder keeps
      // the golden vectors symmetric with Rust's own round-trip test.
      obj = {
        t: msg.t,
        c: {
          encoder_bitrate_bps: msg.c.encoder_bitrate_bps,
          measured_bitrate_bps: msg.c.measured_bitrate_bps,
          fraction_lost_256: msg.c.fraction_lost_256,
          rtt_ms: msg.c.rtt_ms,
          width: msg.c.width,
          height: msg.c.height,
          feedback_reports: msg.c.feedback_reports,
          fps_x100: msg.c.fps_x100,
          // Wire key is "dropped_frames" (retained for deployed-agent compatibility).
          dropped_frames: msg.c.dropped_frames_total,
        },
      };
      break;
    case "SetInputBlocked":
      obj = { t: msg.t, c: { blocked: msg.c.blocked } };
      break;
    case "InputBlockApplied":
      obj = { t: msg.t, c: { blocked: msg.c.blocked } };
      break;
    case "SetMonitorBlanked":
      obj = { t: msg.t, c: { blanked: msg.c.blanked } };
      break;
    case "MonitorBlankedApplied":
      obj = { t: msg.t, c: { blanked: msg.c.blanked } };
      break;
    case "SetViewOnly":
      obj = { t: msg.t, c: { enabled: msg.c.enabled } };
      break;
    case "ViewOnlyApplied":
      obj = { t: msg.t, c: { enabled: msg.c.enabled } };
      break;
    case "RebootGuest":
      obj = { t: msg.t, c: { safe_mode: msg.c.safe_mode } };
      break;
    case "RebootScheduled":
      obj = { t: msg.t, c: { safe_mode: msg.c.safe_mode } };
      break;
    case "LockWorkstation":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "WorkstationLocked":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "LogOffGuest":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "LogOffScheduled":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "ShutDownGuest":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "ShutDownScheduled":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "LaunchTool":
      obj = { t: msg.t, c: { tool: msg.c.tool } };
      break;
    case "ToolLaunched":
      obj = { t: msg.t, c: { tool: msg.c.tool } };
      break;
    case "RunCommand":
      // serde field order: command, shell, as_user.
      obj = {
        t: msg.t,
        c: { command: msg.c.command, shell: msg.c.shell, as_user: msg.c.as_user },
      };
      break;
    case "ElevatedRun":
      // serde field order: signed_elevation, command, shell.
      obj = {
        t: msg.t,
        c: {
          signed_elevation: msg.c.signed_elevation,
          command: msg.c.command,
          shell: msg.c.shell,
        },
      };
      break;
    case "ElevationDenied":
      obj = { t: msg.t, c: { reason: msg.c.reason } };
      break;
    case "CommandResult":
      // serde field order: exit_code, stdout, stderr, truncated, timed_out.
      obj = {
        t: msg.t,
        c: {
          exit_code: msg.c.exit_code,
          stdout: msg.c.stdout,
          stderr: msg.c.stderr,
          truncated: msg.c.truncated,
          timed_out: msg.c.timed_out,
        },
      };
      break;
    case "RequestScreenshot":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "ListDirectory":
      obj = { t: msg.t, c: { path: msg.c.path } };
      break;
    case "DirectoryListing":
      // serde field order: path, entries (each name, is_dir, size, modified_unix), truncated, audit.
      obj = {
        t: msg.t,
        c: {
          path: msg.c.path,
          entries: msg.c.entries.map((e) => ({
            name: e.name,
            is_dir: e.is_dir,
            size: e.size,
            modified_unix: e.modified_unix,
          })),
          truncated: msg.c.truncated,
          audit: msg.c.audit,
        },
      };
      break;
    case "DirectoryListingRefused":
      // serde field order: path, reason, audit.
      obj = { t: msg.t, c: { path: msg.c.path, reason: msg.c.reason, audit: msg.c.audit } };
      break;
    case "StartRecording":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "StopRecording":
      obj = { t: msg.t }; // unit variant → bare tag, no content
      break;
    case "RecordingStarted":
      obj = { t: msg.t, c: { started_at_unix_ms: msg.c.started_at_unix_ms, audit: msg.c.audit } };
      break;
    case "RecordingStopped":
      // serde field order: segments, frames, payload_bytes, truncated, dropped_frames, directory,
      // audit. Wire key is "dropped_frames" (retained for deployed-agent compatibility).
      obj = {
        t: msg.t,
        c: {
          segments: msg.c.segments,
          frames: msg.c.frames,
          payload_bytes: msg.c.payload_bytes,
          truncated: msg.c.truncated,
          dropped_frames: msg.c.dropped_frames_total,
          directory: msg.c.directory,
          audit: msg.c.audit,
        },
      };
      break;
    case "EndSession":
      obj = { t: msg.t, c: { uninstall: msg.c.uninstall } };
      break;
    case "SessionEnding":
      obj = { t: msg.t, c: { uninstall: msg.c.uninstall } };
      break;
    case "TransferDir":
      obj = { t: msg.t, c: { path: msg.c.path } };
      break;
    case "AdminRightsAvailable":
      obj = { t: msg.t, c: { available: msg.c.available, reason: msg.c.reason } };
      break;
    case "AdminRightsResult":
      obj = { t: msg.t, c: { state: msg.c.state, reason: msg.c.reason } };
      break;
    case "InputHandoffAvailable":
      obj = { t: msg.t, c: { available: msg.c.available } };
      break;
    case "HandInputControl":
      obj = { t: msg.t, c: { to_session: msg.c.to_session } };
      break;
    case "InputControlChanged":
      // serde field order: owner_session, owner_name, mode.
      obj = { t: msg.t, c: { owner_session: msg.c.owner_session, owner_name: msg.c.owner_name, mode: msg.c.mode } };
      break;
  }
  return encoder.encode(JSON.stringify(obj));
}

/**
 * Validate + rebuild a nested `quality` object. Throws on any missing or wrongly-typed field.
 *
 * Strict on purpose, and `color` most of all: substituting a default for an unparseable colour would
 * mean the operator's greyscale selection quietly does nothing on a link chosen precisely because it
 * cannot afford chroma. Out-of-RANGE is a different matter and is deliberately NOT checked here — the
 * agent's clamp owns range (see `quality.ts`), so a hostile controller gets a working session at legal
 * values instead of a dropped frame.
 */
function decodeQuality(v: unknown): QualitySettings {
  const q = v as Partial<QualitySettings> | undefined;
  if (
    !q ||
    typeof q.scale_div !== "number" ||
    typeof q.fps !== "number" ||
    (q.color !== "Full" && q.color !== "Gray") ||
    typeof q.max_bitrate_bps !== "number" ||
    typeof q.adaptive !== "boolean"
  ) {
    throw new Error("malformed QualitySettings");
  }
  return {
    scale_div: q.scale_div,
    fps: q.fps,
    color: q.color,
    max_bitrate_bps: q.max_bitrate_bps,
    adaptive: q.adaptive,
  };
}

/** Decode one {@link ControlMessage} from canonical JSON wire bytes. Throws on a malformed shape. */
export function decodeControl(bytes: Uint8Array): ControlMessage {
  if (bytes.length === 0) throw new Error("empty control payload");
  const obj = JSON.parse(decoder.decode(bytes)) as { t?: string; c?: unknown };
  switch (obj.t) {
    case "RequestMonitors":
      return { t: "RequestMonitors" };
    case "MonitorList": {
      const c = obj.c as { monitors?: unknown } | undefined;
      if (!c || !Array.isArray(c.monitors)) throw new Error("malformed MonitorList");
      const monitors = c.monitors.map((m) => {
        const d = m as Partial<MonitorDesc>;
        if (
          typeof d.id !== "number" ||
          typeof d.width !== "number" ||
          typeof d.height !== "number" ||
          typeof d.primary !== "boolean"
        ) {
          throw new Error("malformed MonitorDesc");
        }
        return { id: d.id, width: d.width, height: d.height, primary: d.primary };
      });
      return { t: "MonitorList", c: { monitors } };
    }
    case "SelectMonitor": {
      const c = obj.c as { id?: unknown } | undefined;
      if (!c || typeof c.id !== "number") throw new Error("malformed SelectMonitor");
      return { t: "SelectMonitor", c: { id: c.id } };
    }
    case "SelectMonitorAccepted": {
      const c = obj.c as { selection_gen?: unknown } | undefined;
      if (!c || typeof c.selection_gen !== "number") throw new Error("malformed SelectMonitorAccepted");
      return { t: "SelectMonitorAccepted", c: { selection_gen: c.selection_gen } };
    }
    case "WatchedMonitors": {
      const c = obj.c as { monitors?: unknown } | undefined;
      if (!c || (c.monitors !== null && (!Array.isArray(c.monitors) ||
        !c.monitors.every((id: unknown) => typeof id === "number" && Number.isInteger(id) && id >= 0 && id <= 0xffffffff))))
        throw new Error("malformed WatchedMonitors");
      return { t: "WatchedMonitors", c: { monitors: c.monitors as number[] | null } };
    }
    case "MonitorCanvas": {
      const c = obj.c as MonitorCanvas | undefined;
      const integer = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
      if (!c || !integer(c.width) || !integer(c.height) || !c.width || !c.height ||
          c.width > 16383 || c.height > 16383 || !Array.isArray(c.monitors) ||
          c.monitors.length === 0 || c.monitors.length > 64) throw new Error("malformed MonitorCanvas");
      const ids = new Set<number>();
      for (const m of c.monitors) {
        if (!m || !integer(m.id) || m.id >= 0xffffffff || ids.has(m.id) ||
            !integer(m.x) || !integer(m.y) || !integer(m.width) || !integer(m.height) ||
            !m.width || !m.height || m.x + m.width > c.width || m.y + m.height > c.height)
          throw new Error("malformed MonitorCanvas rectangle");
        ids.add(m.id);
      }
      return { t: "MonitorCanvas", c: { width:c.width, height:c.height,
        monitors:c.monitors.map(m => ({id:m.id,x:m.x,y:m.y,width:m.width,height:m.height})) } };
    }
    case "MonitorPinned": {
      const c = obj.c as { monitor_id?: unknown } | undefined;
      if (!c || typeof c.monitor_id !== "number") throw new Error("malformed MonitorPinned");
      return { t: "MonitorPinned", c: { monitor_id: c.monitor_id } };
    }
    case "Error": {
      const c = obj.c as { message?: unknown } | undefined;
      if (!c || typeof c.message !== "string") throw new Error("malformed Error");
      return { t: "Error", c: { message: c.message } };
    }
    case "InstallGrant": {
      const c = obj.c as { signed_grant?: unknown } | undefined;
      if (!c || typeof c.signed_grant !== "string") throw new Error("malformed InstallGrant");
      return { t: "InstallGrant", c: { signed_grant: c.signed_grant } };
    }
    case "GrantInstalled":
      return { t: "GrantInstalled" };
    case "RequestBackstageFeatures":
      return { t: "RequestBackstageFeatures" };
    case "BackstageFeatures": {
      const c = obj.c as { features?: unknown } | undefined;
      if (!c || !Array.isArray(c.features) || !c.features.every((f) => typeof f === "string")) {
        throw new Error("malformed BackstageFeatures");
      }
      return { t: "BackstageFeatures", c: { features: [...(c.features as string[])] } };
    }
    case "SessionEndedByGuest":
      return { t: "SessionEndedByGuest" };
    case "InstallSessionPolicy": {
      const c = obj.c as { signed_policy?: unknown } | undefined;
      if (!c || typeof c.signed_policy !== "string") throw new Error("malformed InstallSessionPolicy");
      return { t: "InstallSessionPolicy", c: { signed_policy: c.signed_policy } };
    }
    case "SessionPolicyInstalled": {
      const c = obj.c as { access?: unknown; view_only?: unknown; allow_recording?: unknown; require_recording?: unknown; max_session_duration_seconds?: unknown } | undefined;
      // `access` stays a plain string on purpose: a future third level must RENDER on an older console
      // rather than making the whole message undecodable.
      if (!c || typeof c.access !== "string" || typeof c.view_only !== "boolean") {
        throw new Error("malformed SessionPolicyInstalled");
      }
      // `allow_recording` absent (old agent) → true; the ban is the restriction, not the baseline.
      const allow_recording = c.allow_recording === false ? false : true;
      // `require_recording` absent (old agent) → false; mandatory recording is the restriction.
      const require_recording = c.require_recording === true ? true : false;
      // `max_session_duration_seconds` absent (old agent) → 0; a cap is the restriction.
      const max_session_duration_seconds = typeof c.max_session_duration_seconds === "number" ? c.max_session_duration_seconds : 0;
      return { t: "SessionPolicyInstalled", c: { access: c.access, view_only: c.view_only, allow_recording, require_recording, max_session_duration_seconds } };
    }
    case "SessionLeaseRequired": {
      const c = obj.c as { renew_within_ms?: unknown } | undefined;
      if (!c || typeof c.renew_within_ms !== "number") {
        throw new Error("malformed SessionLeaseRequired");
      }
      return { t: "SessionLeaseRequired", c: { renew_within_ms: c.renew_within_ms } };
    }
    case "RequestQuality":
      return { t: "RequestQuality" };
    case "SetQuality": {
      const c = obj.c as { quality?: unknown } | undefined;
      if (!c) throw new Error("malformed SetQuality");
      return { t: "SetQuality", c: { quality: decodeQuality(c.quality) } };
    }
    case "SetBackground": {
      const c = obj.c as { background?: unknown } | undefined;
      if (!c || typeof c.background !== "boolean") throw new Error("malformed SetBackground");
      return { t: "SetBackground", c: { background: c.background } };
    }
    case "QualityApplied": {
      const c = obj.c as Partial<QualityApplied> | undefined;
      if (
        !c ||
        typeof c.encoder_bitrate_bps !== "number" ||
        typeof c.capped_by_policy !== "boolean"
      ) {
        throw new Error("malformed QualityApplied");
      }
      return {
        t: "QualityApplied",
        c: {
          quality: decodeQuality(c.quality),
          encoder_bitrate_bps: c.encoder_bitrate_bps,
          capped_by_policy: c.capped_by_policy,
        },
      };
    }
    case "QualityStats": {
      const c = obj.c as
        | {
            encoder_bitrate_bps?: unknown;
            measured_bitrate_bps?: unknown;
            fraction_lost_256?: unknown;
            rtt_ms?: unknown;
            width?: unknown;
            height?: unknown;
            feedback_reports?: unknown;
            fps_x100?: unknown;
            // Wire key is "dropped_frames" (retained for deployed-agent compatibility).
            dropped_frames?: unknown;
          }
        | undefined;
      if (
        !c ||
        typeof c.encoder_bitrate_bps !== "number" ||
        typeof c.measured_bitrate_bps !== "number" ||
        typeof c.fraction_lost_256 !== "number" ||
        typeof c.rtt_ms !== "number" ||
        typeof c.width !== "number" ||
        typeof c.height !== "number" ||
        typeof c.feedback_reports !== "number" ||
        // Required, like every other field on this wire. Substituting 0 for an absent `fps_x100`
        // would render as "not yet measurable" forever — an agent whose stream had genuinely
        // stalled and one that simply predates the field would look identical to the operator.
        typeof c.fps_x100 !== "number" ||
        typeof c.dropped_frames !== "number"
      ) {
        throw new Error("malformed QualityStats");
      }
      return {
        t: "QualityStats",
        c: {
          encoder_bitrate_bps: c.encoder_bitrate_bps,
          measured_bitrate_bps: c.measured_bitrate_bps,
          fraction_lost_256: c.fraction_lost_256,
          rtt_ms: c.rtt_ms,
          width: c.width,
          height: c.height,
          feedback_reports: c.feedback_reports,
          fps_x100: c.fps_x100,
          dropped_frames_total: c.dropped_frames,
        },
      };
    }
    case "SetInputBlocked": {
      const c = obj.c as { blocked?: unknown } | undefined;
      if (!c || typeof c.blocked !== "boolean") throw new Error("malformed SetInputBlocked");
      return { t: "SetInputBlocked", c: { blocked: c.blocked } };
    }
    case "InputBlockApplied": {
      const c = obj.c as { blocked?: unknown } | undefined;
      if (!c || typeof c.blocked !== "boolean") throw new Error("malformed InputBlockApplied");
      return { t: "InputBlockApplied", c: { blocked: c.blocked } };
    }
    case "SetMonitorBlanked": {
      const c = obj.c as { blanked?: unknown } | undefined;
      if (!c || typeof c.blanked !== "boolean") throw new Error("malformed SetMonitorBlanked");
      return { t: "SetMonitorBlanked", c: { blanked: c.blanked } };
    }
    case "MonitorBlankedApplied": {
      const c = obj.c as { blanked?: unknown } | undefined;
      if (!c || typeof c.blanked !== "boolean") throw new Error("malformed MonitorBlankedApplied");
      return { t: "MonitorBlankedApplied", c: { blanked: c.blanked } };
    }
    case "SetViewOnly": {
      const c = obj.c as { enabled?: unknown } | undefined;
      if (!c || typeof c.enabled !== "boolean") throw new Error("malformed SetViewOnly");
      return { t: "SetViewOnly", c: { enabled: c.enabled } };
    }
    case "ViewOnlyApplied": {
      const c = obj.c as { enabled?: unknown } | undefined;
      if (!c || typeof c.enabled !== "boolean") throw new Error("malformed ViewOnlyApplied");
      return { t: "ViewOnlyApplied", c: { enabled: c.enabled } };
    }
    case "RebootGuest": {
      const c = obj.c as { safe_mode?: unknown } | undefined;
      if (!c || typeof c.safe_mode !== "boolean") throw new Error("malformed RebootGuest");
      return { t: "RebootGuest", c: { safe_mode: c.safe_mode } };
    }
    case "RebootScheduled": {
      const c = obj.c as { safe_mode?: unknown } | undefined;
      if (!c || typeof c.safe_mode !== "boolean") throw new Error("malformed RebootScheduled");
      return { t: "RebootScheduled", c: { safe_mode: c.safe_mode } };
    }
    case "LaunchTool": {
      const c = obj.c as { tool?: unknown } | undefined;
      if (!c || typeof c.tool !== "string") throw new Error("malformed LaunchTool");
      return { t: "LaunchTool", c: { tool: c.tool } };
    }
    case "ToolLaunched": {
      const c = obj.c as { tool?: unknown } | undefined;
      if (!c || typeof c.tool !== "string") throw new Error("malformed ToolLaunched");
      return { t: "ToolLaunched", c: { tool: c.tool } };
    }
    case "RunCommand": {
      const c = obj.c as { command?: unknown; shell?: unknown; as_user?: unknown } | undefined;
      // Strict: every field required, and `shell` must be one of the two known values — an unknown
      // shell is rejected, not defaulted to Cmd (which would run a PS line through the wrong interpreter).
      if (
        !c ||
        typeof c.command !== "string" ||
        (c.shell !== "Cmd" && c.shell !== "PowerShell") ||
        typeof c.as_user !== "boolean"
      ) {
        throw new Error("malformed RunCommand");
      }
      return { t: "RunCommand", c: { command: c.command, shell: c.shell, as_user: c.as_user } };
    }
    case "ElevatedRun": {
      const c = obj.c as
        | { signed_elevation?: unknown; command?: unknown; shell?: unknown }
        | undefined;
      // Strict, and the stakes are higher than on `RunCommand`: a `signed_elevation` that decoded to
      // "" would forward an unauthorized elevated run and lean entirely on the agent's verifier to
      // notice. A missing field must never get that far.
      if (
        !c ||
        typeof c.signed_elevation !== "string" ||
        typeof c.command !== "string" ||
        (c.shell !== "Cmd" && c.shell !== "PowerShell")
      ) {
        throw new Error("malformed ElevatedRun");
      }
      return {
        t: "ElevatedRun",
        c: { signed_elevation: c.signed_elevation, command: c.command, shell: c.shell },
      };
    }
    case "ElevationDenied": {
      const c = obj.c as { reason?: unknown } | undefined;
      if (!c || typeof c.reason !== "string") throw new Error("malformed ElevationDenied");
      return { t: "ElevationDenied", c: { reason: c.reason } };
    }
    case "CommandResult": {
      const c = obj.c as Partial<CommandResult> | undefined;
      // Strict, like every message on this wire: `exit_code` is required, NOT defaulted to 0 — a
      // tolerant decoder would render a command that never ran as one that exited cleanly.
      if (
        !c ||
        typeof c.exit_code !== "number" ||
        typeof c.stdout !== "string" ||
        typeof c.stderr !== "string" ||
        typeof c.truncated !== "boolean" ||
        typeof c.timed_out !== "boolean"
      ) {
        throw new Error("malformed CommandResult");
      }
      return {
        t: "CommandResult",
        c: {
          exit_code: c.exit_code,
          stdout: c.stdout,
          stderr: c.stderr,
          truncated: c.truncated,
          timed_out: c.timed_out,
        },
      };
    }
    case "RequestScreenshot":
      return { t: "RequestScreenshot" };
    case "ListDirectory": {
      const c = obj.c as { path?: unknown } | undefined;
      if (!c || typeof c.path !== "string") throw new Error("malformed ListDirectory");
      return { t: "ListDirectory", c: { path: c.path } };
    }
    case "DirectoryListing": {
      const c = obj.c as Partial<DirectoryListing> | undefined;
      // Strict, like every message on this wire: path, entries (an array), and truncated are all
      // required. Each DirEntry is validated field-by-field so a malformed row cannot slip through
      // as a half-populated object the UI would render with `undefined` cells.
      if (!c || typeof c.path !== "string" || !Array.isArray(c.entries) || typeof c.truncated !== "boolean") {
        throw new Error("malformed DirectoryListing");
      }
      const entries: DirEntry[] = c.entries.map((e) => {
        const d = e as Partial<DirEntry>;
        if (
          typeof d.name !== "string" ||
          typeof d.is_dir !== "boolean" ||
          typeof d.size !== "number" ||
          typeof d.modified_unix !== "number"
        ) {
          throw new Error("malformed DirEntry");
        }
        return { name: d.name, is_dir: d.is_dir, size: d.size, modified_unix: d.modified_unix };
      });
      // `audit` is decoded leniently (an absent key, a null, or a non-object all read as "no
      // event") while every other field stays strict. The asymmetry is the same one `RecordingResult`
      // makes: an agent predating docs/25 F04 sends no `audit` key, and throwing the whole listing
      // away over it would break the file browser to protect a record that agent never sealed.
      return {
        t: "DirectoryListing",
        c: {
          path: c.path,
          entries,
          truncated: c.truncated,
          audit: decodeSealedAudit((obj.c as { audit?: unknown }).audit),
        },
      };
    }
    case "DirectoryListingRefused": {
      const c = obj.c as { path?: unknown; reason?: unknown; audit?: unknown } | undefined;
      if (!c || typeof c.path !== "string" || typeof c.reason !== "string") {
        throw new Error("malformed DirectoryListingRefused");
      }
      return {
        t: "DirectoryListingRefused",
        c: { path: c.path, reason: c.reason, audit: decodeSealedAudit(c.audit) },
      };
    }
    case "LockWorkstation":
      return { t: "LockWorkstation" };
    case "WorkstationLocked":
      return { t: "WorkstationLocked" };
    case "LogOffGuest":
      return { t: "LogOffGuest" };
    case "LogOffScheduled":
      return { t: "LogOffScheduled" };
    case "ShutDownGuest":
      return { t: "ShutDownGuest" };
    case "ShutDownScheduled":
      return { t: "ShutDownScheduled" };
    case "StartRecording":
      return { t: "StartRecording" };
    case "StopRecording":
      return { t: "StopRecording" };
    case "RecordingStarted": {
      const c = obj.c as { started_at_unix_ms?: unknown; audit?: unknown } | undefined;
      if (!c || typeof c.started_at_unix_ms !== "number") {
        throw new Error("malformed RecordingStarted");
      }
      return {
        t: "RecordingStarted",
        c: { started_at_unix_ms: c.started_at_unix_ms, audit: decodeSealedAudit(c.audit) },
      };
    }
    case "RecordingStopped": {
      const c = obj.c as
        | {
            segments?: unknown;
            frames?: unknown;
            payload_bytes?: unknown;
            truncated?: unknown;
            // Wire key is "dropped_frames" (retained for deployed-agent compatibility).
            dropped_frames?: unknown;
            directory?: unknown;
            audit?: unknown;
          }
        | undefined;
      // `truncated` is `Option<String>` in Rust, so `null` is the LEGAL "ran to completion" value —
      // the one field on this wire where absence is meaningful rather than malformed. Every other
      // field is required, `truncated` must be a string or exactly null, and `undefined` is
      // rejected: a missing key would decode as "completed" and turn a truncated recording into a
      // clean one, which is the single misreading this message exists to prevent.
      if (
        !c ||
        typeof c.segments !== "number" ||
        typeof c.frames !== "number" ||
        typeof c.payload_bytes !== "number" ||
        typeof c.dropped_frames !== "number" ||
        typeof c.directory !== "string" ||
        !(c.truncated === null || typeof c.truncated === "string")
      ) {
        throw new Error("malformed RecordingStopped");
      }
      return {
        t: "RecordingStopped",
        c: {
          segments: c.segments,
          frames: c.frames,
          payload_bytes: c.payload_bytes,
          truncated: c.truncated,
          dropped_frames_total: c.dropped_frames,
          directory: c.directory,
          audit: decodeSealedAudit(c.audit),
        },
      };
    }
    case "EndSession": {
      const c = obj.c as { uninstall?: unknown } | undefined;
      if (!c || typeof c.uninstall !== "boolean") throw new Error("malformed EndSession");
      return { t: "EndSession", c: { uninstall: c.uninstall } };
    }
    case "SessionEnding": {
      const c = obj.c as { uninstall?: unknown } | undefined;
      if (!c || typeof c.uninstall !== "boolean") throw new Error("malformed SessionEnding");
      return { t: "SessionEnding", c: { uninstall: c.uninstall } };
    }
    case "TransferDir": {
      const c = obj.c as { path?: unknown } | undefined;
      if (!c || typeof c.path !== "string") throw new Error("malformed TransferDir");
      return { t: "TransferDir", c: { path: c.path } };
    }
    case "RequestAdminRights":
      return { t: "RequestAdminRights" };
    case "AdminRightsAvailable": {
      const c = obj.c as { available?: unknown; reason?: unknown } | undefined;
      if (!c || typeof c.available !== "boolean") throw new Error("malformed AdminRightsAvailable");
      if (c.reason != null && typeof c.reason !== "string") throw new Error("malformed AdminRightsAvailable");
      return { t: "AdminRightsAvailable", c: { available: c.available, reason: (c.reason as string | null | undefined) ?? null } };
    }
    case "AdminRightsResult": {
      const c = obj.c as { state?: unknown; reason?: unknown } | undefined;
      if (!c || !ADMIN_RIGHTS_STATES.includes(c.state as AdminRightsState)) throw new Error("malformed AdminRightsResult");
      if (c.reason != null && typeof c.reason !== "string") throw new Error("malformed AdminRightsResult");
      return { t: "AdminRightsResult", c: { state: c.state as AdminRightsState, reason: (c.reason as string | null | undefined) ?? null } };
    }
    case "InputHandoffAvailable": {
      const c = obj.c as { available?: unknown } | undefined;
      if (!c || typeof c.available !== "boolean") throw new Error("malformed InputHandoffAvailable");
      return { t: "InputHandoffAvailable", c: { available: c.available } };
    }
    case "HandInputControl": {
      const c = obj.c as { to_session?: unknown } | undefined;
      if (!c || typeof c.to_session !== "string") throw new Error("malformed HandInputControl");
      return { t: "HandInputControl", c: { to_session: c.to_session } };
    }
    case "InputControlChanged": {
      const c = obj.c as { owner_session?: unknown; owner_name?: unknown; mode?: unknown } | undefined;
      if (!c || !INPUT_CONTROL_MODES.includes(c.mode as InputControlMode)) throw new Error("malformed InputControlChanged");
      if (c.owner_session != null && typeof c.owner_session !== "string") throw new Error("malformed InputControlChanged");
      if (c.owner_name != null && typeof c.owner_name !== "string") throw new Error("malformed InputControlChanged");
      return {
        t: "InputControlChanged",
        c: {
          owner_session: (c.owner_session as string | null | undefined) ?? null,
          owner_name: (c.owner_name as string | null | undefined) ?? null,
          mode: c.mode as InputControlMode,
        },
      };
    }
    default:
      throw new Error(`unknown control variant ${String(obj.t)}`);
  }
}

// Convenience constructors — keep call sites terse and the tag/content shape in one place.

/** Ask the agent for its monitors. */
export const requestMonitors = (): ControlMessage => ({ t: "RequestMonitors" });

/** Choose which monitor the agent should stream. */
export const selectMonitor = (id: number): ControlMessage => ({ t: "SelectMonitor", c: { id } });

/**
 * Reserved monitor id meaning **"view all"** — the agent streams a single composite frame of every
 * monitor stitched together rather than one physical display. Mirror of the Rust
 * `platform::COMPOSITE_MONITOR_ID` (`u32::MAX`); `SelectMonitor { id: COMPOSITE_MONITOR_ID }` is
 * always accepted by the agent. (Wiring a "View all" entry into the monitor picker UI is part of the
 * still-unbuilt picker in `Viewer.tsx`.)
 */
export const COMPOSITE_MONITOR_ID = 0xffffffff;

/** Ask the agent to stream a composite "view all" of every monitor. */
export const selectAllMonitors = (): ControlMessage => selectMonitor(COMPOSITE_MONITOR_ID);

/** Install a control-plane-signed backstage grant (H1). `signedGrant` is the `SignedGrant` JSON. */
export const installGrant = (signedGrant: string): ControlMessage => ({
  t: "InstallGrant",
  c: { signed_grant: signedGrant },
});

/** Install a control-plane-signed session access policy (loops 79/80). `signedPolicy` is the
 *  `SignedSessionPolicy` JSON exactly as `POST /sessions` returned it — forwarded verbatim, never
 *  re-serialized, because the signature covers the claims and the agent re-derives them from these bytes. */
export const installSessionPolicy = (signedPolicy: string): ControlMessage => ({
  t: "InstallSessionPolicy",
  c: { signed_policy: signedPolicy },
});

/** Ask the agent to report the quality in force (M11), arming the session for `QualityStats`. */
export const requestQuality = (): ControlMessage => ({ t: "RequestQuality" });

/** Ask the agent to apply `quality` (M11). Answered with a `QualityApplied` carrying what it took. */
export const setQuality = (quality: QualitySettings): ControlMessage => ({
  t: "SetQuality",
  c: { quality },
});

/** Tell the agent every window showing the session is hidden (`true`) or one is shown (`false`). */
export const setBackground = (background: boolean): ControlMessage => ({
  t: "SetBackground",
  c: { background },
});

/** Block/unblock the guest's own keyboard & mouse. Answered with `InputBlockApplied` (state in force). */
export const setInputBlocked = (blocked: boolean): ControlMessage => ({
  t: "SetInputBlocked",
  c: { blocked },
});

/** Blank/unblank the guest's monitors (privacy mode). Answered with `MonitorBlankedApplied`. */
export const setMonitorBlanked = (blanked: boolean): ControlMessage => ({
  t: "SetMonitorBlanked",
  c: { blanked },
});

/** Enter/leave view-only (the agent drops injected input). Answered with `ViewOnlyApplied` (state in force). */
export const setViewOnly = (enabled: boolean): ControlMessage => ({
  t: "SetViewOnly",
  c: { enabled },
});

/**
 * Reboot the guest (remote support). `safeMode` requests **Safe Mode with Networking**. Answered
 * with `RebootScheduled` (the session then drops and auto-reconnect brings it back) or `Error`.
 */
export const rebootGuest = (safeMode: boolean): ControlMessage => ({
  t: "RebootGuest",
  c: { safe_mode: safeMode },
});

/** Launch a whitelisted admin tool on the guest desktop (`tool` = a stable key like `task_manager`). */
export const launchTool = (tool: string): ControlMessage => ({
  t: "LaunchTool",
  c: { tool },
});

/**
 * Run a one-line command on the guest and capture its output (remote support). `asUser` runs it as the
 * interactive user; otherwise as SYSTEM. Answered with `CommandResult` (→ `onCommandResult`) or `Error`.
 */
export const runCommand = (
  command: string,
  shell: CommandShell,
  asUser: boolean,
): ControlMessage => ({ t: "RunCommand", c: { command, shell, as_user: asUser } });

/**
 * Run ONE command on the guest with the interactive user's LINKED ELEVATED token (loop 87, docs/01
 * §3). `signedElevation` is the opaque JSON blob from `POST /sessions/{id}/elevation` — forwarded
 * VERBATIM, because the signature covers the claims and the agent re-derives the canonical preimage
 * from exactly these bytes. Answered with `CommandResult` (→ `onCommandResult`) or `ElevationDenied`
 * (→ `onElevationDenied`).
 *
 * There is no `asUser` here: an elevated run is by definition the interactive user's token, so no
 * combination of arguments can ask for "SYSTEM, but signed".
 */
export const elevatedRun = (
  signedElevation: string,
  command: string,
  shell: CommandShell,
): ControlMessage => ({
  t: "ElevatedRun",
  c: { signed_elevation: signedElevation, command, shell },
});

/** The shells the console offers, in menu order. The `key` MUST match the Rust `control::CommandShell`. */
export const COMMAND_SHELLS: ReadonlyArray<{ key: CommandShell; label: string }> = [
  { key: "Cmd", label: "Command Prompt" },
  { key: "PowerShell", label: "PowerShell" },
];

/**
 * Ask the agent for a full-resolution lossless screenshot of the current view. There is no Control
 * reply — the agent pushes the PNG over the FileTransfer channel, received and saved like any download.
 */
export const requestScreenshot = (): ControlMessage => ({ t: "RequestScreenshot" });

/**
 * Start recording this session to a file on the GUEST's disk (loop 89, docs/01 §5). The agent
 * answers `RecordingStarted` (→ `onRecordingStarted`) or `Error` (→ `onError`).
 *
 * The recording is written on the recorded machine, not here and not on the relay: nothing is streamed to
 * the browser during the session. If the tenant turned on central storage (docs/63) the agent uploads the
 * finished file afterwards, outside any live session. The guest's own window says so while it runs.
 */
export const startRecording = (): ControlMessage => ({ t: "StartRecording" });

/**
 * Stop recording and finalize the files (loop 89). Answered with `RecordingStopped`
 * (→ `onRecordingStopped`), or `Error` if nothing was running.
 */
export const stopRecording = (): ControlMessage => ({ t: "StopRecording" });

/**
 * Ask the agent to list `path` for the file browser (docs/01 §3). An empty `path` lists the drive
 * roots. Answered with a `DirectoryListing` (→ `onDirectoryListing`), a `DirectoryListingRefused`
 * (→ `onDirectoryListingRefused`) if the session may not browse or the path is not on the guest's
 * local disk, or an `Error` (→ `onError`) if the path simply cannot be read.
 */
export const listDirectory = (path: string): ControlMessage => ({ t: "ListDirectory", c: { path } });

/**
 * Lock the guest workstation (remote support, Win+L). The agent answers with `WorkstationLocked`, or
 * an `Error` if it refuses (e.g. a view-only session) or the OS call fails.
 */
export const lockWorkstation = (): ControlMessage => ({ t: "LockWorkstation" });

/**
 * Log off the guest's interactive user (remote support). Ends their session and returns the machine to
 * the sign-in screen with no user logged in — distinct from {@link lockWorkstation}, which leaves them
 * logged in behind a lock shade. The agent answers with `LogOffScheduled` (the session then drops and
 * auto-reconnect re-establishes at the sign-in screen), or an `Error` if it refuses (view-only) / fails.
 */
export const logOffGuest = (): ControlMessage => ({ t: "LogOffGuest" });

/**
 * Shut the guest machine DOWN (power off) — the last power-menu action (remote support). The agent
 * answers with `ShutDownScheduled` (the session then drops and, unlike a reboot, does NOT re-establish
 * until the machine is powered back on), or an `Error` if it refuses (view-only) / cannot arm it.
 */
export const shutDownGuest = (): ControlMessage => ({ t: "ShutDownGuest" });

/**
 * The one-line summary of a finished recording, as the operator reads it (loop 89).
 *
 * A pure function and not JSX, deliberately. `web/viewer/vite.config.ts` globs only
 * `src/**\/*.{test,spec}.ts`, so **nothing in a `.tsx` file has unit coverage** — and the branch
 * that matters most here is the one an e2e cannot easily stage: a TRUNCATED recording needs a full
 * queue, an exhausted disk or a blown size budget to produce. Left inline in `Viewer.tsx` that
 * branch would be reachable by no test in the repo, which for this particular string is the worst
 * possible place to have a gap: a recording that stopped early and is reported as "Recorded 43
 * frames" is a file the operator will hand over believing it is complete.
 *
 * The truncation is stated FIRST and in capitals for the same reason. The frame count is the
 * reassuring half and the reader's eye stops there.
 */
export function recordingSummary(r: RecordingResult): string {
  const what = r.truncated
    ? `Recording TRUNCATED (${r.truncated}) after ${r.frames} frames`
    : `Recorded ${r.frames} frames`;
  const lost = r.dropped_frames_total > 0 ? `, ${r.dropped_frames_total} frames lost` : "";
  return `${what}${lost} → ${r.directory} (on the guest)`;
}

/**
 * The naming convention the agent uses for a pushed screenshot: `screenshot-<unix_millis>.png` (see
 * `crate::screenshot::screenshot_filename`). The controller uses this to tell an agent-initiated
 * screenshot push apart from an ordinary Files-panel download, so it can save it inline.
 */
export const isScreenshotName = (name: string): boolean =>
  name.startsWith("screenshot-") && name.endsWith(".png");

/**
 * End the session (remote support). `uninstall` requests "remove client" — the unattended agent
 * self-uninstalls after acking. Answered with `SessionEnding` (→ `onSessionEnding`) just before the drop.
 */
export const endSession = (uninstall: boolean): ControlMessage => ({
  t: "EndSession",
  c: { uninstall },
});

/**
 * The tools the console offers, in menu order. The `key` MUST match the agent's whitelist
 * (`crates/agent-windows/src/launch.rs`); the `label` is what the operator sees.
 */
export const SYSTEM_TOOLS: ReadonlyArray<{ key: string; label: string }> = [
  { key: "task_manager", label: "Task Manager" },
  { key: "registry_editor", label: "Registry Editor" },
  { key: "event_viewer", label: "Event Viewer" },
  { key: "services", label: "Services" },
  { key: "device_manager", label: "Device Manager" },
];

// --- minimal client ----------------------------------------------------------------------------

/**
 * Minimal session-control client over the session data channel.
 *
 * Construct with a `send` bound to `transport.send(ChannelId.Control, …)`. Call {@link requestList}
 * to ask the agent to enumerate its monitors and {@link select} to switch which one is streamed;
 * {@link requestQuality} / {@link setQuality} drive the M11 quality knobs. Feed every inbound
 * `ChannelId.Control` payload to {@link handleMessage}, which records an inbound `MonitorList`
 * (readable via {@link monitors}), surfaces `Error`s, and fans quality replies out to
 * `onQualityApplied` / `onQualityStats`.
 */
export class ControlClient {
  private readonly send: (payload: Uint8Array) => void;
  /** The monitors most recently advertised by the agent (empty until a `MonitorList` arrives). */
  private lastMonitors: MonitorDesc[] = [];
  /** Optional callback fired when a fresh `MonitorList` is received. */
  private readonly onMonitors?: (monitors: MonitorDesc[]) => void;
  /** Optional callback fired when the agent reports an `Error`. */
  private readonly onError?: (message: string) => void;
  /** Optional callback fired when the agent acks an `InstallGrant` (H1). */
  private readonly onGrantInstalled?: () => void;
  /** docs/58 §2: the Backstage features the agent reported. */
  private readonly onBackstageFeatures?: (features: string[]) => void;
  /** Optional callback fired when the agent reports the quality in force (M11). */
  private readonly onQualityApplied?: (applied: QualityApplied) => void;
  /** Optional callback fired for each 1 Hz `QualityStats` sample (M11). */
  private readonly onQualityStats?: (stats: QualityStats) => void;
  /** Optional callback fired when the agent reports the input-block state in force (privacy). */
  private readonly onInputBlockApplied?: (blocked: boolean) => void;
  /** Optional callback fired when the agent reports the monitor-blank state in force (privacy). */
  private readonly onMonitorBlankedApplied?: (blanked: boolean) => void;
  /** Optional callback fired when the agent reports the view-only state in force. */
  private readonly onViewOnlyApplied?: (enabled: boolean) => void;
  /** Optional callback fired when the agent acks a `RebootGuest` (`safeMode` = Safe Mode boot). */
  private readonly onRebootScheduled?: (safeMode: boolean) => void;
  /** Optional callback fired when the agent acks a `LockWorkstation` (the guest is now at its lock screen). */
  private readonly onWorkstationLocked?: () => void;
  /** Optional callback fired when the agent acks a `LogOffGuest` (the user is being logged off; session drops). */
  private readonly onLogOffScheduled?: () => void;
  /** Optional callback fired when the agent acks a `ShutDownGuest` (the machine is powering off; it will not return). */
  private readonly onShutDownScheduled?: () => void;
  /** Optional callback fired when the agent acks a `LaunchTool` (`tool` = the whitelist key). */
  private readonly onToolLaunched?: (tool: string) => void;
  /** Optional callback fired when the agent returns a `CommandResult` (one-line command bar, or an
   *  `elevatedRun`). */
  private readonly onCommandResult?: (result: CommandResult) => void;
  /** Optional callback fired when the agent REFUSES an `elevatedRun` (loop 87). Nothing ran — this is
   *  deliberately not routed through `onError`, which means "a command failed". */
  private readonly onElevationDenied?: (reason: string) => void;
  /** Optional callback fired when the agent returns a `DirectoryListing` (file browser). The
   *  listing carries the SEALED audit event for the browse (docs/25 F04), which must reach the audit
   *  forwarder VERBATIM — see `DirectoryListing.audit`. */
  private readonly onDirectoryListing?: (listing: DirectoryListing) => void;
  /** Optional callback fired when the agent REFUSES a `listDirectory` (docs/25 F04). Nothing was
   *  read. Deliberately not routed through `onError`, which means "that folder could not be read":
   *  this means "this session may not browse it", and it carries the refusal's audit event. */
  private readonly onDirectoryListingRefused?: (refusal: DirectoryListingRefusal) => void;
  /** Optional callback fired when the agent acks a `StartRecording` (loop 89). The second argument
   *  is the SEALED audit event the agent chained for this start (loop 91), or null if it sealed
   *  none; it must be handed to the audit forwarder VERBATIM. */
  private readonly onRecordingStarted?: (startedAtUnixMs: number, audit: SealedAuditEvent) => void;
  /** Optional callback fired when a recording is finalized (loop 89) — by `StopRecording`. Carries
   *  the figures read back from the artifact, including `truncated`, plus the sealed audit event
   *  (loop 91), which is the one carrying the artifact's per-segment digests. */
  private readonly onRecordingStopped?: (result: RecordingResult, audit: SealedAuditEvent) => void;
  /** Optional callback fired when the agent acks an `EndSession` (`uninstall` = "remove client"). */
  private readonly onSessionEnding?: (uninstall: boolean) => void;
  /** Optional callback fired when the guest revokes access at the controlled machine. */
  private readonly onSessionEndedByGuest?: () => void;
  /** Optional callback fired when the agent advertises its file-transfer root at session start
   *  (alongside `MonitorList`). The path mirrors the agent's `config.json` `transfer_dir`, or the
   *  default `C:\rmt-agent\transfers` when absent. */
  private readonly onTransferDir?: (path: string) => void;
  /** docs/53: the agent says whether this session can ask the guest for admin rights. */
  private readonly onAdminRightsAvailable?: (available: boolean, reason: string | null) => void;
  /** docs/53: where an admin-rights request stands. */
  private readonly onAdminRightsResult?: (state: AdminRightsState, reason: string | null) => void;
  /** docs/61: the agent says whether technicians in this session can hand input control. */
  private readonly onInputHandoffAvailable?: (available: boolean) => void;
  /** docs/61: the authoritative snapshot of who owns input (sent on every change and at join). */
  private readonly onInputControlChanged?: (ownerSession: string | null, mode: InputControlMode) => void;
  /**
   * Optional callback fired when the agent accepts a `SelectMonitor` and reports the monotonic
   * epoch (`selection_gen`) assigned to this transition.  The controller MUST register a
   * `requestVideoFrameCallback` on the video element and send `FrameDisplayed { selection_gen }`
   * when the callback fires — that is the signal that the new monitor's frame is actually visible.
   *
   * NOTE: `requestVideoFrameCallback` fires on the next composited video frame after registration.
   * Without per-frame RTP epoch metadata the controller cannot verify this frame belongs to the
   * new selection; the ack is best-effort for single-session transitions only.  The agent rejects
   * `SelectMonitor` when multiple sessions are active, so this callback only fires in that case.
   */
  private readonly onSelectMonitorAccepted?: (selectionGen: number) => void;
  /**
   * Optional callback fired when the agent pins a monitor for the helper lifetime
   * (multi-session pinned-display mode).  Sent once on the first `SelectMonitor` that
   * establishes the pin.  The viewer should display this limitation and disable or
   * annotate the monitor picker.  `SelectMonitor` for a different id returns `Error`.
   */
  private readonly onMonitorPinned?: (monitorId: number) => void;
  private readonly onMonitorCanvas?: (canvas: MonitorCanvas) => void;
  /** Optional callback fired when the agent accepts a session ACCESS policy (loops 79/80). `access` is
   *  the level the policy carried; `viewOnly` is the session's EFFECTIVE input state afterwards.
   *  `allowRecording` (loop 93) is whether the group policy permits recording; default true when absent.
   *  `requireRecording` (loop 89/0044) is whether recording is mandatory; default false when absent.
   *  `maxSessionDurationSeconds` (loop 90/0045) is the hard time limit; 0 = unlimited; default 0 when absent. */
  private readonly onSessionPolicyInstalled?: (access: string, viewOnly: boolean, allowRecording: boolean, requireRecording: boolean, maxSessionDurationSeconds: number) => void;
  /** Optional callback fired when the agent says this session runs on a control-plane LEASE that the
   *  console must keep renewing (docs/25 F03). `renewWithinMs` is how long the agent will still wait
   *  for the FIRST lease; it counts down across re-announcements and is never extended.
   *
   *  IGNORING THIS ENDS THE SESSION. The agent tears the session down when its lease lapses, whether
   *  or not this console understood the message — which is exactly what makes an administrator's
   *  "End session" reach an unattended desktop, and equally what a stale cached console bundle looks
   *  like from the technician's side. */
  private readonly onSessionLeaseRequired?: (renewWithinMs: number) => void;
  /** Where an undecodable inbound frame goes. See {@link handleMessage}. */
  private readonly onUnknown: (err: Error) => void;

  constructor(
    send: (payload: Uint8Array) => void,
    handlers: {
      onMonitors?: (monitors: MonitorDesc[]) => void;
      onError?: (message: string) => void;
      onGrantInstalled?: () => void;
      onBackstageFeatures?: (features: string[]) => void;
      onQualityApplied?: (applied: QualityApplied) => void;
      onQualityStats?: (stats: QualityStats) => void;
      onInputBlockApplied?: (blocked: boolean) => void;
      onMonitorBlankedApplied?: (blanked: boolean) => void;
      onViewOnlyApplied?: (enabled: boolean) => void;
      onRebootScheduled?: (safeMode: boolean) => void;
      onWorkstationLocked?: () => void;
      onLogOffScheduled?: () => void;
      onShutDownScheduled?: () => void;
      onToolLaunched?: (tool: string) => void;
      onCommandResult?: (result: CommandResult) => void;
      onElevationDenied?: (reason: string) => void;
      onDirectoryListing?: (listing: DirectoryListing) => void;
      onDirectoryListingRefused?: (refusal: DirectoryListingRefusal) => void;
      onRecordingStarted?: (startedAtUnixMs: number, audit: SealedAuditEvent) => void;
      onRecordingStopped?: (result: RecordingResult, audit: SealedAuditEvent) => void;
      onSessionEnding?: (uninstall: boolean) => void;
      onSessionEndedByGuest?: () => void;
      onSessionPolicyInstalled?: (access: string, viewOnly: boolean, allowRecording: boolean, requireRecording: boolean, maxSessionDurationSeconds: number) => void;
      onSessionLeaseRequired?: (renewWithinMs: number) => void;
      onTransferDir?: (path: string) => void;
      onAdminRightsAvailable?: (available: boolean, reason: string | null) => void;
      onAdminRightsResult?: (state: AdminRightsState, reason: string | null) => void;
      onInputHandoffAvailable?: (available: boolean) => void;
      onInputControlChanged?: (ownerSession: string | null, mode: InputControlMode) => void;
      onSelectMonitorAccepted?: (selectionGen: number) => void;
      onMonitorPinned?: (monitorId: number) => void;
      onMonitorCanvas?: (canvas: MonitorCanvas) => void;
      onUnknown?: (err: Error) => void;
    } = {},
  ) {
    this.send = send;
    this.onMonitors = handlers.onMonitors;
    this.onError = handlers.onError;
    this.onGrantInstalled = handlers.onGrantInstalled;
    this.onBackstageFeatures = handlers.onBackstageFeatures;
    this.onSessionPolicyInstalled = handlers.onSessionPolicyInstalled;
    this.onSessionLeaseRequired = handlers.onSessionLeaseRequired;
    this.onQualityApplied = handlers.onQualityApplied;
    this.onQualityStats = handlers.onQualityStats;
    this.onInputBlockApplied = handlers.onInputBlockApplied;
    this.onMonitorBlankedApplied = handlers.onMonitorBlankedApplied;
    this.onViewOnlyApplied = handlers.onViewOnlyApplied;
    this.onRebootScheduled = handlers.onRebootScheduled;
    this.onWorkstationLocked = handlers.onWorkstationLocked;
    this.onLogOffScheduled = handlers.onLogOffScheduled;
    this.onShutDownScheduled = handlers.onShutDownScheduled;
    this.onToolLaunched = handlers.onToolLaunched;
    this.onCommandResult = handlers.onCommandResult;
    this.onElevationDenied = handlers.onElevationDenied;
    this.onDirectoryListing = handlers.onDirectoryListing;
    this.onDirectoryListingRefused = handlers.onDirectoryListingRefused;
    this.onRecordingStarted = handlers.onRecordingStarted;
    this.onRecordingStopped = handlers.onRecordingStopped;
    this.onSessionEnding = handlers.onSessionEnding;
    this.onSessionEndedByGuest = handlers.onSessionEndedByGuest;
    this.onTransferDir = handlers.onTransferDir;
    this.onAdminRightsAvailable = handlers.onAdminRightsAvailable;
    this.onAdminRightsResult = handlers.onAdminRightsResult;
    this.onInputHandoffAvailable = handlers.onInputHandoffAvailable;
    this.onInputControlChanged = handlers.onInputControlChanged;
    this.onSelectMonitorAccepted = handlers.onSelectMonitorAccepted;
    this.onMonitorPinned = handlers.onMonitorPinned;
    this.onMonitorCanvas = handlers.onMonitorCanvas;
    // Default to `console.debug`, not `console.warn`: a frame from a newer agent is an expected
    // condition on a mixed-version fleet, not an operator-visible fault.
    this.onUnknown =
      handlers.onUnknown ??
      ((err) => console.debug("control: dropping undecodable frame:", err.message));
  }

  /** Install a control-plane-signed backstage grant (H1). The agent acks via `onGrantInstalled`. */
  installGrant(signedGrant: string): void {
    this.send(encodeControl(installGrant(signedGrant)));
  }

  /** docs/58 §2: ask which Backstage features the agent understands; answered via
   *  `onBackstageFeatures` (or never, by an agent too old to know the question). */
  requestBackstageFeatures(): void {
    this.send(encodeControl({ t: "RequestBackstageFeatures" }));
  }

  /** Install a control-plane-signed session access policy (loops 79/80). The agent acks via
   *  `onSessionPolicyInstalled`, or replies `Error` if it does not verify. */
  installSessionPolicy(signedPolicy: string): void {
    this.send(encodeControl(installSessionPolicy(signedPolicy)));
  }

  /** Ask the agent to enumerate its monitors. The reply arrives via {@link handleMessage}. */
  requestList(): void {
    this.send(encodeControl(requestMonitors()));
  }

  /** Ask the agent to stream the monitor with `id`. Silent on success; an `Error` on an unknown id. */
  watchedMonitors(monitors: number[] | null): void {
    this.send(encodeControl({ t: "WatchedMonitors", c: { monitors } }));
  }

  select(id: number): void {
    this.send(encodeControl(selectMonitor(id)));
  }

  /** Ask the agent to stream a composite "view all" of every monitor (reserved id, always accepted). */
  selectAll(): void {
    this.select(COMPOSITE_MONITOR_ID);
  }

  /**
   * Notify the agent that the viewer has composited a frame for `selectionGen`.  The agent uses
   * this to restore input-injection readiness for this session exactly when the new monitor is
   * visible on the viewer's display (single-session only; multi-session transitions are rejected
   * before the epoch is issued, so this is never called in that case).
   */
  sendFrameDisplayed(selectionGen: number): void {
    this.send(encodeControl({ t: "FrameDisplayed", c: { selection_gen: selectionGen } }));
  }

  /**
   * Ask the agent to report the quality settings in force (M11).
   *
   * Also **arms** the session: the agent sends no `QualityApplied` or `QualityStats` until it has
   * seen this (or a `SetQuality`). The reply — or its absence — is how the controller discovers
   * whether the agent speaks M11 at all; see `App.tsx`'s probe timer.
   */
  requestQuality(): void {
    this.send(encodeControl(requestQuality()));
  }

  /**
   * Ask the agent to apply `q` (M11). The agent answers with a `QualityApplied` carrying the values it
   * actually took, which may differ: it clamps to legal range and then applies its own machine policy
   * ceiling. Treat `onQualityApplied` — never this argument — as the truth about what is in force.
   */
  setQuality(q: QualitySettings): void {
    this.send(encodeControl(setQuality(q)));
  }

  /**
   * Background mode (lib/background.ts): `true` when every window showing this session is hidden, so
   * the agent drops it to about one frame a second; `false` restores the operator's settings at once.
   */
  setBackground(hidden: boolean): void {
    this.send(encodeControl(setBackground(hidden)));
  }

  /**
   * Block or unblock the guest's own physical keyboard & mouse (privacy). The agent answers with an
   * `InputBlockApplied` carrying the state ACTUALLY in force (blocking can fail to arm), routed to
   * `onInputBlockApplied` — treat that, never this argument, as the truth about what is blocked.
   */
  setInputBlocked(blocked: boolean): void {
    this.send(encodeControl(setInputBlocked(blocked)));
  }

  /**
   * Blank or unblank the guest's monitors (privacy mode). A solid black overlay covers all
   * displays while blanked. The agent answers with `MonitorBlankedApplied` carrying the state
   * ACTUALLY in force (window creation can fail), routed to `onMonitorBlankedApplied` — treat
   * that, never this argument, as the truth about whether the screen is blanked.
   */
  setMonitorBlanked(blanked: boolean): void {
    this.send(encodeControl(setMonitorBlanked(blanked)));
  }

  /**
   * Enter/leave view-only mode (the agent drops the controller's injected input). The agent answers
   * with a `ViewOnlyApplied` carrying the state ACTUALLY in force, routed to `onViewOnlyApplied` —
   * treat that, never this argument, as the truth about whether input is being dropped.
   */
  setViewOnly(enabled: boolean): void {
    this.send(encodeControl(setViewOnly(enabled)));
  }

  /**
   * Reboot the guest (remote support). `safeMode` requests **Safe Mode with Networking**. The agent
   * answers with a `RebootScheduled` (routed to `onRebootScheduled`) just before it drops the
   * session, or an `Error` if it could not arm the reboot — in which case the session keeps running.
   */
  reboot(safeMode: boolean): void {
    this.send(encodeControl(rebootGuest(safeMode)));
  }

  /**
   * Launch a whitelisted admin tool on the guest's interactive desktop (remote support). `tool` is a
   * stable key from {@link SYSTEM_TOOLS}. The agent answers with `ToolLaunched` (→ `onToolLaunched`)
   * on success or an `Error` for an unknown key / spawn failure.
   */
  launchTool(tool: string): void {
    this.send(encodeControl(launchTool(tool)));
  }

  /**
   * Run a one-line command on the guest and capture its output (remote support). `asUser` runs it as
   * the interactive user; otherwise as SYSTEM. The result arrives via `onCommandResult`, or an `Error`
   * (→ `onError`) if the process could not be started. One command at a time — a second sent while one
   * is still running is refused by the agent with an `Error`.
   */
  runCommand(command: string, shell: CommandShell, asUser: boolean): void {
    this.send(encodeControl(runCommand(command, shell, asUser)));
  }

  /**
   * Run ONE command on the guest with the interactive user's ELEVATED token (loop 87, docs/01 §3).
   * `signedElevation` is a single-use grant from `POST /sessions/{id}/elevation`: the caller mints
   * one per elevated command, which is what makes every elevated command its own audited event.
   * The result arrives via `onCommandResult`; a refusal via `onElevationDenied`.
   */
  elevatedRun(signedElevation: string, command: string, shell: CommandShell): void {
    this.send(encodeControl(elevatedRun(signedElevation, command, shell)));
  }

  /**
   * Ask the agent for a full-resolution lossless screenshot of the current view (remote support). No
   * Control reply: the agent pushes the PNG over the FileTransfer channel, which the file-transfer
   * client receives and saves like any download. An `Error` (→ `onError`) comes back only if no frame
   * has been captured yet.
   */
  requestScreenshot(): void {
    this.send(encodeControl(requestScreenshot()));
  }

  /**
   * List a directory on the guest for the file browser (docs/01 §3). An empty `path` lists the drive
   * roots. The listing arrives via `onDirectoryListing`; a refusal via `onDirectoryListingRefused`;
   * an unreadable path via `onError`.
   *
   * Requires the `file_browse` capability on the session's grant, and every listing is recorded in
   * the session's audit chain (docs/25 F04) — it is read-only, but a directory listing names files
   * that are nowhere on the screen, so "the technician can already see it" was never true of it.
   * Still honored in view-only mode: view-only governs what may be DRIVEN, the grant governs what
   * may be READ.
   */
  listDirectory(path: string): void {
    this.send(encodeControl(listDirectory(path)));
  }

  /**
   * Start recording this session to a file on the GUEST's disk (loop 89, docs/01 §5). Acked via
   * `onRecordingStarted`, or refused via `onError`. Honored under view-only — see the Rust dispatch
   * arm for why, and note that the guest's window announces it either way.
   */
  startRecording(): void {
    this.send(encodeControl(startRecording()));
  }

  /** Stop recording and finalize (loop 89). Result via `onRecordingStopped`, or `onError`. */
  stopRecording(): void {
    this.send(encodeControl(stopRecording()));
  }

  /**
   * Lock the guest workstation (remote support, Win+L). The agent answers with `WorkstationLocked`
   * (→ `onWorkstationLocked`) on success, or an `Error` (→ `onError`) if it refuses (view-only) or the
   * OS call fails.
   */
  lock(): void {
    this.send(encodeControl(lockWorkstation()));
  }

  /**
   * Log off the guest's interactive user (remote support). Ends their session (closing their apps),
   * unlike {@link lock}. The agent answers with `LogOffScheduled` (→ `onLogOffScheduled`) as the
   * session drops, or an `Error` (→ `onError`) if it refuses (view-only) or the OS call fails.
   */
  logOff(): void {
    this.send(encodeControl(logOffGuest()));
  }

  /**
   * Shut the guest machine DOWN (power off) — the last power-menu action (remote support). The agent
   * answers with `ShutDownScheduled` (→ `onShutDownScheduled`) as the session drops and, unlike a
   * reboot, does NOT return until the machine is powered on; or an `Error` (→ `onError`) if it refuses
   * (view-only) or cannot arm it.
   */
  shutDown(): void {
    this.send(encodeControl(shutDownGuest()));
  }

  /**
   * End the session (remote support). `uninstall` requests "remove client" (the unattended agent
   * self-uninstalls after acking). The agent answers with `SessionEnding` (→ `onSessionEnding`) just
   * before it drops the session.
   */
  endSession(uninstall: boolean): void {
    this.send(encodeControl(endSession(uninstall)));
  }

  /** docs/53: ask the guest for admin rights. Answered by `AdminRightsResult` (→ `onAdminRightsResult`). */
  requestAdminRights(): void {
    this.send(encodeControl({ t: "RequestAdminRights" }));
  }

  /**
   * docs/61: hand this session's input control to the technician whose SIGNALING session id is
   * `toSession` (handing to our own id claims locked input). There is no reply on success: the
   * `InputControlChanged` snapshot every participant receives is the answer; a refusal is an `Error`
   * starting with `input control: `.
   */
  handInputControl(toSession: string): void {
    this.send(encodeControl({ t: "HandInputControl", c: { to_session: toSession } }));
  }

  /** The monitors most recently advertised by the agent. */
  get monitors(): readonly MonitorDesc[] {
    return this.lastMonitors;
  }

  /**
   * Route one inbound `ChannelId.Control` payload (a `MonitorList`, an `Error`, a quality reply…).
   *
   * TOLERANT BY DESIGN, unlike {@link decodeControl}. This is called with no try/catch of its own from
   * `App.tsx`'s `onMessage`, which runs inside `transport.ts`'s `for (const f of frames)` loop over
   * every frame coalesced into a single SCTP message. A throw escaping here therefore abandons that
   * loop and discards the INNOCENT SIBLING frames behind the bad one — an unknown variant from a
   * newer agent could silently cost the operator a monitor list or a grant ack that decoded fine.
   *
   * So the split is: the codec stays strict (it must never invent a value it could not parse — see
   * `decodeQuality`), and the client absorbs the failure, reporting it to `onUnknown` and moving on to
   * the next frame. Forward compatibility is the client's job; correctness is the codec's.
   */
  handleMessage(payload: Uint8Array): void {
    let msg: ControlMessage;
    try {
      msg = decodeControl(payload);
    } catch (err) {
      this.onUnknown(err as Error);
      return;
    }
    switch (msg.t) {
      case "MonitorList":
        this.lastMonitors = msg.c.monitors;
        this.onMonitors?.(msg.c.monitors);
        break;
      case "Error":
        this.onError?.(msg.c.message);
        break;
      case "GrantInstalled":
        this.onGrantInstalled?.();
        break;
      case "BackstageFeatures":
        this.onBackstageFeatures?.(msg.c.features);
        break;
      case "SessionPolicyInstalled":
        this.onSessionPolicyInstalled?.(msg.c.access, msg.c.view_only, msg.c.allow_recording, msg.c.require_recording, msg.c.max_session_duration_seconds);
        break;
      case "SessionLeaseRequired":
        this.onSessionLeaseRequired?.(msg.c.renew_within_ms);
        break;
      case "QualityApplied":
        this.onQualityApplied?.(msg.c);
        break;
      case "QualityStats":
        this.onQualityStats?.(msg.c);
        break;
      case "InputBlockApplied":
        this.onInputBlockApplied?.(msg.c.blocked);
        break;
      case "MonitorBlankedApplied":
        this.onMonitorBlankedApplied?.(msg.c.blanked);
        break;
      case "ViewOnlyApplied":
        this.onViewOnlyApplied?.(msg.c.enabled);
        break;
      case "RebootScheduled":
        this.onRebootScheduled?.(msg.c.safe_mode);
        break;
      case "WorkstationLocked":
        this.onWorkstationLocked?.();
        break;
      case "LogOffScheduled":
        this.onLogOffScheduled?.();
        break;
      case "ShutDownScheduled":
        this.onShutDownScheduled?.();
        break;
      case "ToolLaunched":
        this.onToolLaunched?.(msg.c.tool);
        break;
      case "CommandResult":
        this.onCommandResult?.(msg.c);
        break;
      case "ElevationDenied":
        this.onElevationDenied?.(msg.c.reason);
        break;
      case "DirectoryListing":
        this.onDirectoryListing?.(msg.c);
        break;
      case "DirectoryListingRefused":
        this.onDirectoryListingRefused?.(msg.c);
        break;
      case "RecordingStarted":
        this.onRecordingStarted?.(msg.c.started_at_unix_ms, msg.c.audit);
        break;
      case "RecordingStopped":
        this.onRecordingStopped?.(msg.c, msg.c.audit);
        break;
      case "SessionEnding":
        this.onSessionEnding?.(msg.c.uninstall);
        break;
      case "SessionEndedByGuest":
        this.onSessionEndedByGuest?.();
        break;
      case "TransferDir":
        this.onTransferDir?.(msg.c.path);
        break;
      case "AdminRightsAvailable":
        this.onAdminRightsAvailable?.(msg.c.available, msg.c.reason);
        break;
      case "AdminRightsResult":
        this.onAdminRightsResult?.(msg.c.state, msg.c.reason);
        break;
      case "InputHandoffAvailable":
        this.onInputHandoffAvailable?.(msg.c.available);
        break;
      case "InputControlChanged":
        this.onInputControlChanged?.(msg.c.owner_session, msg.c.mode);
        break;
      case "SelectMonitorAccepted":
        this.onSelectMonitorAccepted?.(msg.c.selection_gen);
        break;
      case "MonitorCanvas":
        this.onMonitorCanvas?.(msg.c);
        break;
      case "MonitorPinned":
        this.onMonitorPinned?.(msg.c.monitor_id);
        break;
      // RequestMonitors / SelectMonitor / FrameDisplayed / InstallGrant / RequestQuality /
      // SetQuality / SetInputBlocked / SetMonitorBlanked / SetViewOnly / RebootGuest / LaunchTool /
      // RunCommand / ElevatedRun / RequestScreenshot / StartRecording / StopRecording / EndSession /
      // RequestAdminRights are controller→agent; never received here.
      default:
        break;
    }
  }
}

/** The `ChannelId` this client's frames ride on (re-exported for callers wiring the transport). */
export const CONTROL_CHANNEL = ChannelId.Control;
