import { contentRect } from "../lib/viewport";
import type { RecoveryNotice } from "../lib/session_recovery";
import type { ToolboxItem } from "../lib/console_api";
import type { ReactNode } from "react";
/**
 * The remote screen surface. Renders the agent's video track into a <video> element,
 * captures mouse + keyboard, and emits Input-channel frames with coordinates normalized to
 * the 0..65535 absolute space the agent's `SendInput` path expects (ADR-005: absolute,
 * virtual-desktop coordinates computed in a PerMonitorV2 DPI-aware process).
 *
 * Wired to a `Transport` if one is provided; otherwise it runs in a self-contained preview
 * mode (input events are logged) so the UI is usable before a live agent exists.
 *
 * V1: input is encoded via the canonical `input.ts` / `dom_input.ts` codec (the exact bytes the
 * Rust agent's `input_codec` decodes), sent as `transport.send(ChannelId.Input, encodeInput(ev))`.
 * The old local `InputOp` binary layout (which the agent did NOT decode) has been removed. Monitors
 * come from the Control channel (see App.tsx); switching one calls back to `onSelectMonitor`.
 */

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import { MenuSection, ToolbarDock } from "./ToolbarMenu";
import { tabMonitorButtons } from "../lib/session_chrome";
import { shouldUseMobileFullscreenBar } from "../lib/mobile_fullscreen";
import { ViewerSurface } from "./ViewerSurface";
import { openPopout } from "../lib/popout";
import { watchVisibility } from "../lib/background";
import { PopoutControls } from "./PopoutControls";
import {
  COLOR_CHOICES,
  ChannelId,
  COMPOSITE_MONITOR_ID,
  DEFAULT_QUALITY,
  FPS_CHOICES,
  QUALITY_PRESETS,
  SCALE_CHOICES,
  SYSTEM_TOOLS,
  COMMAND_SHELLS,
  bitrateChoicesKbps,
  clampQuality,
  encodeInput,
  buttonEvent,
  formatQualityReadout,
  keyEvent,
  liveKeyEvent,
  moveEvent,
  NAV_KEYS,
  STRIP_MODIFIERS,
  codeForTypedChar,
  singleTypedChar,
  TYPING_SENTINEL,
  navKeyEvents,
  shouldReseed,
  typingEdit,
  typingFieldKey,
  oskKeyEvents,
  presetIdFor,
  qualityFromPreset,
  qualityTone,
  toggleLatch,
  wheelToScroll,
  wheelPixels,
  mapPointerToAbs,
  panBy,
  zoomAtPoint,
  zoomToCenter,
  INITIAL_GESTURE_STATE,
  reduceGesture,
  type GestureAction,
  type GestureEvent,
  type GesturePoint,
  type GestureState,
  zoomByWheel,
  actualZoom,
  displayScalePct,
  isPannable,
  clampPan,
  IDENTITY_VIEW,
  MIN_ZOOM,
  ZOOM_STEP,
  type ViewTransform,
  type Dims,
  SPECIAL_KEYS,
  type ColorMode,
  type NavKey,
  type QualityPresetId,
  type QualitySettings,
  type QualityStats,
  type SpecialKey,
  type InputEvent,
  type Transport,
  type ConnectionState,
  type CommandShell,
  type CommandResult,
  type DirectoryListing,
  recordingSummary,
  type RecordingResult,
} from "../lib";
import {
  INITIAL_TRACKPAD_STATE,
  SENSITIVITIES,
  cursorMapPoint,
  cursorSurfacePoint,
  isTouchEchoMouse,
  isTouchEchoMouseUp,
  readTrackpadPrefs,
  reduceTrackpad,
  revealDelta,
  writeTrackpadPrefs,
  type Pt as PadPoint,
  type Sensitivity,
  type TrackpadAction,
  type TrackpadEvent,
  type TrackpadState,
} from "../lib/trackpad";
import { NO_OWNERS, acquire, clickAllowed, release as releaseOwner, releaseAll, type Owner, type Owners } from "../lib/button_owners";
import { PAD_SEND_INTERVAL_MS, createPadSender } from "../lib/pad_sender";
import { NO_PRESS, clickArrived, pressAbandoned, pressBegan, pressEnded, type PressActivation } from "../lib/press_activation";
import { TypeClipboard } from "./TypeClipboard";
import { FileManagerPanel, type BrowseUploadRow } from "./FileManagerPanel";
import {
  monitorCrop,
  cropStyles as computeCropStyles,
  remapCroppedPointer,
  type MonitorCanvas,
} from "../lib/monitor_canvas";

export interface MonitorInfo {
  id: number;
  label: string;
  width: number;
  height: number;
  primary?: boolean;
}

/** One entry in the monitor picker `<select>`. */
export interface MonitorOption {
  value: number;
  label: string;
}

/**
 * The picker's option list: one entry per advertised monitor, plus a **"View all"** composite entry
 * (value {@link COMPOSITE_MONITOR_ID}) when the agent advertises more than one monitor — selecting it
 * streams a stitched view of every display. Pure + exported so it can be unit-tested without rendering.
 */
export function viewerMonitorOptions(monitors: MonitorInfo[]): MonitorOption[] {
  const opts: MonitorOption[] = monitors.map((m) => ({
    value: m.id,
    label: `${m.label}${m.width > 0 ? ` (${m.width}×${m.height})` : ""}${m.primary ? " ★" : ""}`,
  }));
  if (monitors.length > 1) {
    opts.push({ value: COMPOSITE_MONITOR_ID, label: "View all (composite)" });
  }
  return opts;
}

/**
 * Whether `id` is a valid current selection given the advertised monitors: a real monitor id, or the
 * composite id but only when more than one monitor is present. Used to keep the picker's selection
 * valid as the advertised list changes.
 */
export function isValidMonitorSelection(id: number, monitors: MonitorInfo[]): boolean {
  return monitors.some((m) => m.id === id) || (monitors.length > 1 && id === COMPOSITE_MONITOR_ID);
}

/**
 * Which monitor the picker should start on: the **primary**, falling back to the first advertised.
 *
 * Not simply `monitors[0]`. Monitor ids are POSITIONAL — the agent orders them left-to-right across
 * the virtual desktop so that "Display 1" is the leftmost panel and the composite "view all" stitch
 * comes out in the right order. On a desk where the second screen sits to the *left* of the main
 * one, id 0 is therefore not the primary, and opening the session on it would land the technician
 * on the wrong screen. The agent seeds its own capture selection the same way, from the same
 * `primary` flag, so the two agree without an extra negotiation.
 */
export function defaultMonitorSelection(monitors: MonitorInfo[]): number {
  return (monitors.find((m) => m.primary) ?? monitors[0])?.id ?? 0;
}

/**
 * Tooltip for the speaker control: why it is off, or how to turn it off.
 *
 * Three states, not two. "Disabled" and "off" look alike and mean opposite things — one is *this
 * machine is sending no audio*, the other is *you have not asked to hear it* — and an operator who
 * cannot tell them apart reports the feature as broken when it is working exactly as asked.
 * Pure and exported so the wording is testable without rendering.
 */
export function audioToggleTitle(available: boolean, on: boolean): string {
  if (!available) {
    return "This machine is not sending audio (no audio device, or an agent without audio support)";
  }
  return on ? "Mute the remote machine's audio" : "Hear the remote machine's audio";
}

/**
 * Why a control is unavailable, said on screen (menu redesign wave 7c). A `title` tooltip never shows on a phone,
 * so a disabled control carries a visible line beside it, tied to it by aria-describedby.
 */
export function ControlReason({ id, testId, text }: { id: string; testId: string; text: string | null }) {
  if (!text) return null;
  return <span id={id} className="viewer__reason" data-testid={testId}>{text}</span>;
}

/** The visible reasons (short; the tooltips keep the long form). Null when the control is available. */
export function controlReasons(s: {
  audioAvailable: boolean; qualityDisabled: boolean; pannable: boolean; viewOnlyEnforced: boolean;
  typingEnabled: boolean; viewOnly: boolean; panning: boolean; recordingLocked: boolean;
}) {
  return {
    audio: s.audioAvailable ? null : "This computer is not sending sound.",
    quality: s.qualityDisabled ? "This agent cannot change quality. Update the agent." : null,
    pan: s.pannable ? null : "Zoom in first: the whole screen is already showing.",
    viewOnly: s.viewOnlyEnforced ? "Your organization requires view only for this computer." : null,
    typing: s.typingEnabled ? null
      : s.viewOnly ? "This session is view only."
        : s.panning ? "Turn off Pan to type."
          : "Turn on Capture input to type.",
    record: s.recordingLocked ? "Your organization requires this recording; it cannot be stopped." : null,
  };
}

/** One entry in the quality preset `<select>`. */
export interface QualityOption {
  value: QualityPresetId | "custom";
  label: string;
}

/**
 * The quality picker's option list: the four named presets, plus a **"Custom"** entry when the
 * settings in force match none of them (an advanced-panel tweak, or a machine policy that capped the
 * bitrate to a value no preset uses).
 *
 * Appending "Custom" only when it applies keeps the control from listing a mode the operator cannot
 * meaningfully pick; showing it when it applies keeps the `<select>` from mislabelling the live
 * settings as whichever preset happens to sort first. Pure + exported so it is unit-testable without
 * rendering, like {@link viewerMonitorOptions}.
 */
export function viewerQualityOptions(q: QualitySettings): QualityOption[] {
  const opts: QualityOption[] = QUALITY_PRESETS.map((p) => ({ value: p.id, label: p.label }));
  if (presetIdFor(q) === "custom") opts.push({ value: "custom", label: "Custom" });
  return opts;
}

/** Whether the quality controls are interactive, and the tooltip explaining it when they are not. */
export interface QualityControlState {
  disabled: boolean;
  title: string;
}

/**
 * Enable/disable state for the quality controls.
 *
 * Disabled ONLY on an explicit `false` — the agent answered nothing within the probe window, so it
 * predates M11 and a `SetQuality` would be dropped by its decoder. `undefined` (still probing, or no
 * probe at all in preview mode) stays enabled: an old agent ignoring a setting is a smaller harm than
 * a new agent's controls being dead for the first seconds of every session.
 *
 * The `title` carries the reason in both states. A control that is greyed out with no explanation is
 * the worst outcome for an operator — they cannot tell "broken" from "not supported here" and will
 * spend the session wondering, or reconnecting.
 */
/** What the control plane's signed policy did to this session, as the viewer knows it. */
export type SessionPolicyState = {
  /** The agent reports it is holding a view-only floor the technician cannot lift. */
  enforced: boolean;
  /** Whether the agent VERIFIED the policy. False ⇒ it was refused; see `sessionPolicyBanner`. */
  applied: boolean;
  /** The agent's own words: the level in force, or why the policy was refused. */
  note?: string;
  /** Whether the group policy permits recording; undefined until first policy installs (defaults to
   *  allow). The Viewer hides the record button when this is explicitly false. */
  allowRecording?: boolean;
  /** Whether the group policy requires recording; undefined until first policy installs (defaults to
   *  false). When true the Viewer auto-starts recording and the stop button shows "Required". */
  requireRecording?: boolean;
};

/**
 * The banner text for a session policy that could NOT be applied, or `null` when there is nothing the
 * operator needs told.
 *
 * WHY THIS EXISTS. When the agent REFUSES a policy (bad signature, expired, no pinned issuer) it fails
 * closed and floors the session — and that floor is terminal, because `reject_unverified` raises it in a
 * way no later policy can release. But the refusal arrives as a plain `Error`, so the viewer recorded
 * `enforced: false`, which left the view-only button ENABLED and reading normally. The operator was
 * shown a session they appeared to control, could click "resume control" all day, and was told nothing.
 * The refusal text was captured into state that had exactly one consumer — `enforced` — and was never
 * rendered anywhere.
 *
 * `applied` is what makes the two cases distinguishable at all: a VERIFIED `control` policy also reports
 * `enforced: false`, and that one is genuinely nothing to report.
 */
export function sessionPolicyBanner(state?: SessionPolicyState): string | null {
  if (!state || state.applied) return null;
  const why = state.note?.trim();
  // The organisation decided something about this session and the agent could not check it, so it
  // refused. Name the consequence (terminal, not transient) rather than only the error.
  return why
    ? `Session policy could not be applied: ${why}. This session stays view-only — start a new one once the cause is fixed.`
    : "Session policy could not be applied. This session stays view-only — start a new one once the cause is fixed.";
}

export function qualityControlState(qualitySupported?: boolean): QualityControlState {
  return qualitySupported === false
    ? {
        disabled: true,
        title:
          "This agent does not support quality selection (it did not answer the quality request). Update the agent to change resolution, frame rate, colour or bitrate.",
      }
    : {
        disabled: false,
        title: "Streaming quality: resolution, frame rate, colour and the bitrate ceiling.",
      };
}

/**
 * The CSS `transform` that renders a {@link ViewTransform} onto the base (`object-fit: contain`)
 * `<video>` layer. Origin is the surface top-left `(0,0)` so the transform matches `lib/viewport`'s
 * math exactly — the SAME numbers drive both this render and the pointer→desktop mapping, so a click
 * always lands where the pixels are (see `lib/viewport` for the derivation). Translate is applied
 * before scale in CSS space; with a `0 0` origin that is the `p*zoom + pan` the mapping inverts.
 */
export function videoTransform(view: ViewTransform): string {
  return `translate(${view.panX}px, ${view.panY}px) scale(${view.zoom})`;
}

/**
 * Primary label for the machine in the viewer status bar.
 * When an alias is present it is shown; the hostname is relegated to a tooltip (see `machineDisplayTitle`).
 */
export function machineDisplayLabel(machineName: string, machineAlias?: string): string {
  return machineAlias ?? machineName;
}

/**
 * Tooltip text for the machine label. Only returns the hostname when it differs from the displayed label
 * (i.e., when an alias is shown). Returns `undefined` when the label already IS the hostname.
 */
export function machineDisplayTitle(machineName: string, machineAlias?: string): string | undefined {
  return machineAlias ? machineName : undefined;
}

/**
 * The view to apply when the operator has expressed a zoom preference and the monitor switches.
 *
 * On a monitor change the viewer always resets to `IDENTITY_VIEW` first (the old zoom/pan was
 * framed for the old desktop) and then, once real content dimensions arrive via `loadedmetadata`,
 * re-applies this function. `"fit"` leaves the reset in place; `"actual"` zooms to native pixels
 * (one surface pixel per desktop pixel) from the centre of the new desktop, clamped so that when
 * the monitor is SMALLER than the viewer window the view stays at the fit rather than shrinking
 * further below `MIN_ZOOM`.
 */
export function preferredViewForMonitorSwitch(pref: "fit" | "actual", dims: Dims): ViewTransform {
  if (pref === "actual") {
    const z = actualZoom(dims);
    return z > MIN_ZOOM ? zoomToCenter(dims, IDENTITY_VIEW, z) : IDENTITY_VIEW;
  }
  return IDENTITY_VIEW;
}

export interface ViewerProps {
  hostWindow?: Window;
  initialMonitorId?: number;
  disablePopout?: boolean;
  toolbarHost?: HTMLElement | null;
  toolbarMenuOpen?: boolean;
  toolbarEndHost?: HTMLElement | null;
  /**
   * The collapsed session tab's monitor slot (lib/session_chrome.ts). When set, the main-window viewer
   * docks one-click monitor buttons there, so switching displays stays available while the rest of the
   * bar is hidden. Ignored in pop-out windows and in fullscreen (those keep their inline toolbar).
   */
  tabHost?: HTMLElement | null;
  additionalControls?: ReactNode;
  /** Rendered at the top of the Input menu (the clipboard's quick controls). */
  inputPanelExtras?: ReactNode;
  disconnectLabel?: string;
  popoutControls?: ReactNode;
  onPopoutChange?: (open: boolean) => void;
  /** Live transport. If omitted, the viewer runs in local preview mode. */
  transport?: Transport;
  /** Remote video, once negotiated (from `WebRTCTransport.onVideoTrack`). */
  stream?: MediaStream | null;
  /** Current connection state, for the status bar. */
  connectionState?: ConnectionState;
  recoveryNotice?: RecoveryNotice | null;
  onReconnect?: () => void;
  /** Monitors advertised by the agent (Control channel). Empty ⇒ single-display fallback. */
  /** Whether the agent is actually sending an audio track — gates the speaker control. */
  audioAvailable?: boolean;
  monitors?: MonitorInfo[];
  /** Called when the operator picks a different monitor (→ Control `SelectMonitor`). */
  onSelectMonitor?: (id: number) => void;
  /**
   * When set, the agent is in multi-session pinned-display mode: the monitor with this id is
   * fixed for the helper lifetime.  The picker is disabled and a limitation notice is shown.
   * Absent (undefined) means single-session mode where dynamic switching is supported.
   */
  pinnedMonitorId?: number;
  /**
   * The quality settings the controls should display and read-modify-write against: the operator's
   * own pending ask while one is in flight, otherwise the settings the agent reports are IN FORCE
   * (its last `QualityApplied` — the agent clamps and applies a machine policy, so the two differ).
   * `App.tsx` resolves that with `effectiveQuality`; see `lib/quality.ts` for why both are needed.
   * Undefined before the first reply, where the shipped default is the right thing to show.
   */
  quality?: QualitySettings;
  /** Newest 1 Hz `QualityStats` sample, or null before the first one arrives. */
  qualityStats?: QualityStats | null;
  /** `false` once the agent has been shown not to speak M11; `undefined` while that is still unknown. */
  qualitySupported?: boolean;
  /** Called when the operator changes any quality control (→ Control `SetQuality`). */
  onSetQuality?: (q: QualitySettings) => void;
  /**
   * Whether the guest's own physical keyboard/mouse are blocked right now (privacy). Sourced from the
   * agent's `InputBlockApplied` ack — the state ACTUALLY in force, not the operator's last request.
   */
  inputBlocked?: boolean;
  /** Called when the operator toggles the guest-input block (→ Control `SetInputBlocked`). */
  onToggleInputBlock?: (blocked: boolean) => void;
  /**
   * Whether the guest's monitors are blanked right now (privacy). Sourced from the agent's
   * `MonitorBlankedApplied` ack — the state ACTUALLY in force, not the operator's last request.
   */
  monitorBlanked?: boolean;
  /** Called when the operator toggles the monitor blank (→ Control `SetMonitorBlanked`). Absent ⇒ button hidden. */
  onToggleMonitorBlank?: (blanked: boolean) => void;
  /**
   * Whether the session is in **view-only** mode right now (the agent drops the controller's injected
   * input). Sourced from the agent's `ViewOnlyApplied` ack — the state actually in force.
   */
  viewOnly?: boolean;
  /** Called when the operator toggles view-only (→ Control `SetViewOnly`). Absent ⇒ the toggle hidden. */
  onToggleViewOnly?: (enabled: boolean) => void;
  /**
   * True when view-only is held by a control-plane-signed SESSION POLICY rather than chosen by the
   * technician (docs/01 §5, loops 79/80). The agent enforces it as a one-way ratchet, so the toggle
   * genuinely cannot lift it — the button is therefore disabled and says WHY.
   *
   * Distinct from `viewOnly` on purpose: the technician needs to tell "I chose this and can undo it"
   * apart from "my organisation decided this". Without the distinction the button looks broken.
   */
  viewOnlyEnforced?: boolean;
  /** The signed-policy state, so a policy the agent REFUSED is visible instead of silently dropped. */
  sessionPolicy?: SessionPolicyState;
  /**
   * Called when the operator confirms a guest reboot (→ Control `RebootGuest`). `safeMode` requests
   * **Safe Mode with Networking**. Absent ⇒ the Reboot control is not shown.
   */
  onReboot?: (safeMode: boolean) => void;
  /**
   * A transient status line for an in-progress reboot ("Rebooting… reconnecting"), sourced from the
   * agent's `RebootScheduled` ack and cleared on reconnect. `undefined` ⇒ nothing to show.
   */
  rebootStatus?: string;
  /** Called when the operator locks the guest (→ Control `LockWorkstation`). Absent ⇒ button hidden. */
  onLock?: () => void;
  /** A transient confirmation ("Guest locked") from the agent's `WorkstationLocked` ack, else undefined. */
  lockStatus?: string;
  /** Called when the operator logs off the guest's user (→ Control `LogOffGuest`). Absent ⇒ button hidden. */
  onLogOff?: () => void;
  /** A transient status ("Logging the guest off…") from the agent's `LogOffScheduled` ack, else undefined. */
  logoffStatus?: string;
  /** Called when the operator shuts the guest down (→ Control `ShutDownGuest`), after a confirm. Absent ⇒ hidden. */
  onShutDown?: () => void;
  /** A transient status ("Shutting the guest down…") from the agent's `ShutDownScheduled` ack, else undefined. */
  shutdownStatus?: string;
  /**
   * Called when the operator picks a system tool to launch on the guest (→ Control `LaunchTool`).
   * `tool` is a whitelist key from `SYSTEM_TOOLS`. Absent ⇒ the Tools menu is not shown.
   */
  onLaunchTool?: (tool: string) => void;
  /**
   * A transient status line confirming the last launched tool ("Launched Task Manager"), from the
   * agent's `ToolLaunched` ack. `undefined` ⇒ nothing to show.
   */
  toolStatus?: string;
  /**
   * Called when the operator fires a one-line command (→ Control `RunCommand`). `asUser` runs it as
   * the interactive user; unchecked runs as whatever the agent process already is — SYSTEM on an
   * unattended agent, the guest's own user on an attended one. Absent ⇒ the Command bar is not shown.
   */
  onRunCommand?: (command: string, shell: CommandShell, asUser: boolean) => void;
  /**
   * Called when the operator fires a command with the guest's ELEVATED token (docs/01 §3, loop 87).
   * Distinct from `onRunCommand` because it is a distinct ACT, not a flag: the caller first mints a
   * single-use, control-plane-signed elevation grant (which authorizes and audits it) and only then
   * sends the command, so there is one audited event per elevated command.
   *
   * `undefined` ⇒ this connection cannot elevate and the button is not rendered at all — the
   * direct-connect and ATTENDED paths, neither of which has a control-plane session record to mint
   * against (and an attended agent could not honour a grant anyway: it runs at the guest's own
   * integrity level). Hiding it beats showing a control that always fails.
   *
   * Note there is no `asUser` argument: an elevated run is BY DEFINITION the interactive user's
   * token, so there is no combination of inputs that means "SYSTEM, but signed".
   */
  onElevatedRun?: (command: string, shell: CommandShell) => void;
  /**
   * Shared Toolbox (docs/design-shared-toolbox.md): the caller's saved scripts, offered in the command
   * panel. `onRunToolboxItem` asks the control plane to authorize + audit the run, then sends the exact
   * command it returns; the result lands in the same output area as the command bar's. `undefined` ⇒
   * no toolbox row (no control-plane session record to run against, e.g. direct connect or attended).
   */
  toolboxItems?: readonly ToolboxItem[];
  /** Reload saved scripts without clearing the current listing while the request is pending. */
  onRefreshToolbox?: () => void;
  onRunToolboxItem?: (item: ToolboxItem) => void;
  /** Why the last toolbox run was refused (control plane) — nothing ran. */
  toolboxError?: string;
  /** Why the toolbox could not be listed (shown instead of an empty toolbox). */
  toolboxListError?: string;
  /**
   * Why the last elevation attempt failed — the control plane's reason (no capability, session
   * ended, attended, group mandated view-only) or the agent's (`ElevationDenied`: grant did not
   * verify, already used, this host cannot elevate). Rendered in the command panel.
   *
   * Its own field rather than folding into the generic error banner: "nothing ran, the elevation was
   * declined" is a different fact from "the command failed", and the operator has to be able to tell
   * whether a privileged action happened.
   */
  elevationError?: string;
  /**
   * The captured result of the last command (from the agent's `CommandResult`), or `undefined` if
   * none has returned this session. Rendered in the command panel's output area.
   */
  commandResult?: CommandResult;
  /**
   * `true` while a command is in flight (sent, no result yet). Disables the Run button so only one
   * command runs at a time — the agent refuses a second concurrent one anyway.
   */
  commandPending?: boolean;
  /**
   * Called when the operator asks for a full-res screenshot (→ Control `RequestScreenshot`). The PNG
   * arrives over the file-transfer channel and `App` saves it. Absent ⇒ the Screenshot button hidden.
   */
  onScreenshot?: () => void;
  /**
   * A transient status line for the screenshot ("Capturing…" then "Saved screenshot-….png"), from
   * `App`. `undefined` ⇒ nothing to show.
   */
  screenshotStatus?: string;
  /**
   * Session recording (loop 89, docs/01 §5). When provided, a Record toggle appears; calling it
   * starts or stops recording depending on {@link recording}. Absent ⇒ the control is hidden.
   */
  onToggleRecording?: () => void;
  /**
   * `true` while the AGENT says a recording is running. Sourced from its ack, never from the click —
   * this drives a label that claims a video of someone's screen is being written to their disk.
   */
  recording?: boolean;
  /** `true` between the ask and the agent's answer; disables the toggle so a double-click cannot
   *  send a start the agent will refuse as "already recording". */
  recordingPending?: boolean;
  /** `true` when the group policy REQUIRES recording. The stop button is disabled and labelled
   *  "Required by policy" so the operator knows they cannot turn it off. */
  recordingRequired?: boolean;
  /** The last finished recording, from `RecordingStopped`. `undefined` ⇒ nothing to summarize. */
  recordingResult?: RecordingResult;
  /**
   * Called when the operator saves a note for this session. Only present for brokered sessions
   * (which have a control-plane session record); absent on attended and direct-connect paths where
   * there is no record to annotate. Absent ⇒ the Note button is hidden.
   */
  onSaveNote?: (note: string) => Promise<void>;
  /**
   * Remote file browser (docs/01 §3). When provided, a "Files" toggle appears; clicking a folder
   * calls this with the path to list (empty ⇒ drive roots). Read-only, honored even in view-only.
   */
  onBrowseDir?: (path: string) => void;
  /** The latest `DirectoryListing` from the agent (from `App`), or undefined before the first reply. */
  dirListing?: DirectoryListing;
  /** A directory listing is in flight. */
  dirLoading?: boolean;
  /** The agent refused the last navigation (denied/absent path). */
  dirError?: string;
  /** "Get access" offered by the file browser when the agent refused for lack of a backstage grant (FileManagerPanel). */
  onGetFileAccess?: () => void;
  /** The agent acknowledged an installed backstage grant (re-lists a folder refused before it). */
  fileGrantInstalled?: boolean;
  /**
   * Called with an absolute remote path when the operator clicks a file's download button in the
   * file browser. Only passed when the session has FileDownload capability. Absent ⇒ no download
   * buttons appear in the file browser. See `FileManagerPanel` for path and transfer-dir semantics.
   */
  onDownloadFile?: (absolutePath: string) => void;
  /** Relative paths (relative to the transfer root) of browse-downloaded files this session; forwarded to `FileManagerPanel`. */
  completedDownloadFiles?: ReadonlySet<string>;
  /** Upload files into the transfer root from the file browser; forwarded to `FileManagerPanel` (see there). */
  onUploadFiles?: (files: File[]) => void;
  /** Uploads started from the file browser this session; forwarded to `FileManagerPanel`. */
  browseUploads?: readonly BrowseUploadRow[];
  /**
   * The agent-advertised file-transfer root (`TransferDir` control message). When `undefined` (older
   * agent that has not sent this message), `FileManagerPanel` disables the Transfers shortcut and
   * suppresses all download affordances — there is no safe root to fall back to.
   */
  transferDirPath?: string;
  /**
   * Called when the operator ends the session from the agent side (→ Control `EndSession`). `uninstall`
   * requests "remove client" (the agent self-uninstalls). Absent ⇒ the End-session control is hidden.
   */
  /**
   * A transient status line once the agent acks `SessionEnding` ("Ending session…" / "Removing
   * client…"), from `App`. `undefined` ⇒ nothing to show.
   */
  endSessionStatus?: string;
  /** Human label for the machine being controlled. */
  machineName?: string;
  /**
   * Operator-chosen friendly alias for the machine. When set, shown as the primary label in the
   * status bar; `machineName` (the hostname) becomes a tooltip. Absent for attended or manual
   * connections where no alias is known.
   */
  machineAlias?: string;
  onDisconnect?: () => void;
  /** Called with the <video> element whenever it mounts or unmounts (null on unmount).
   *  Used by App to register requestVideoFrameCallback for per-session ack epoch. */
  onVideoElement?: (el: HTMLVideoElement | null) => void;
  /**
   * Background mode: called with this viewer's own token and whether the window it is shown in
   * (its pop-out when popped out) is hidden, on every change, and with `null` on unmount. Several
   * viewers can show one session (monitor windows), so the caller aggregates (lib/background.ts).
   */
  onVisibilityChange?: (viewer: object, hidden: boolean | null) => void;
  /**
   * When provided, the encoder is streaming the FULL virtual-desktop canvas and the viewer
   * performs a LOCAL crop to the selected monitor instead of sending `SelectMonitor` to the agent.
   *
   * Each viewer independently picks any sub-region; the stream is shared, untouched. The parent
   * validates this capability before supplying the prop (codec must be confirmed to carry the full
   * canvas). Without this prop the viewer falls back to the old `onSelectMonitor` path.
   *
   * Constraints:
   * - `onSelectMonitor` is NEVER called in canvas mode (not even for the initial auto-primary).
   * - The `pinnedMonitorId` UI notice is suppressed (pin flag has no effect on local crop).
   * - "View all" (COMPOSITE_MONITOR_ID / -1) shows the full canvas with no crop applied.
   */
  monitorCanvas?: MonitorCanvas;
  onCropMonitorChange?: (id: number | null) => void;
  onWatchedMonitors?: (ids: number[] | null) => void;
}

// --- Helpers ---------------------------------------------------------------

/** Minimum panel width — must match .viewer__menupanel min-width in index.css. */
const PANEL_MIN_W = 200;

/** Minimum usable panel height. If below-trigger space is less than this, flip above. */
const PANEL_MIN_USEFUL_H = 80;

/** Position for an overlay panel, anchored either below or above the trigger.
 *  Exactly one of `top`/`bottom` is set; the other is undefined. Both are in .viewer coordinates
 *  (pixels from the containing block's respective edge). */
interface PanelPos {
  top?: number;
  bottom?: number;
  left: number;
  maxHeight: number;
  maxWidth: number;
}

/**
 * Compute a position for an overlay panel that is clamped to visible bounds.
 *
 * left: left-aligns to the trigger but caps so the minimum-width panel fits inside the viewer.
 * maxWidth: remaining horizontal space to the viewer's right edge so expanded content cannot push
 *   the panel past the viewer's right boundary. Always at least PANEL_MIN_W.
 * Vertical placement: below the trigger when enough room exists (PANEL_MIN_USEFUL_H or more),
 *   otherwise flipped above the trigger so controls remain reachable near the bottom of the
 *   viewer. A near-bottom trigger opening a zero-height panel is treated as a flip, not a fit.
 *
 * All coordinates are relative to .viewer (position:relative), which is the containing block for
 * .viewer__menupanel {position:absolute}.
 */
function panelPos(triggerEl: Element, viewerEl: Element): PanelPos {
  const t = triggerEl.getBoundingClientRect();
  const v = viewerEl.getBoundingClientRect();
  const left = Math.max(0, Math.min(t.left - v.left, v.width - PANEL_MIN_W));
  const maxWidth = Math.max(PANEL_MIN_W, v.width - left);
  const floor = Math.min(v.bottom, viewerEl.ownerDocument.defaultView?.innerHeight ?? v.bottom);
  const belowHeight = Math.max(0, floor - t.bottom - 16);

  // How much room exists above the trigger in the viewport. The panel is allowed to overflow the
  // viewer upward into viewport space, so aboveHeight is not clamped to the space inside .viewer.
  const aboveHeight = Math.max(0, t.top - 16);

  // Flip above only when there is genuinely more room above than below.
  if (belowHeight >= PANEL_MIN_USEFUL_H || belowHeight >= aboveHeight) {
    return { top: t.bottom - v.top, left, maxHeight: belowHeight, maxWidth };
  }

  // Flip above the trigger. bottom (CSS) = distance from .viewer's bottom to panel's bottom edge.
  // We want panel.bottom_viewport = t.top - 16, so:
  //   v.bottom - bottom_css = t.top - 16  →  bottom_css = v.bottom - t.top + 16
  const bottomCss = v.bottom - t.top + 16;
  return { bottom: bottomCss, left, maxHeight: aboveHeight, maxWidth };
}

// --- Component -------------------------------------------------------------

export function Viewer({
  hostWindow,
  initialMonitorId,
  disablePopout = false,
  additionalControls,
  inputPanelExtras,
  toolbarHost,
  toolbarMenuOpen = false,
  toolbarEndHost,
  tabHost,
  disconnectLabel = "Disconnect",
  popoutControls,
  onPopoutChange,
  transport,
  stream,
  connectionState = "idle",
  recoveryNotice,
  onReconnect,
  audioAvailable = false,
  monitors = [],
  onSelectMonitor,
  quality,
  qualityStats,
  qualitySupported,
  onSetQuality,
  inputBlocked = false,
  onToggleInputBlock,
  monitorBlanked = false,
  onToggleMonitorBlank,
  viewOnly = false,
  onToggleViewOnly,
  viewOnlyEnforced = false,
  sessionPolicy,
  onReboot,
  rebootStatus,
  onLock,
  lockStatus,
  onLogOff,
  logoffStatus,
  onShutDown,
  shutdownStatus,
  onLaunchTool,
  toolStatus,
  onRunCommand,
  onElevatedRun,
  toolboxItems,
  onRefreshToolbox,
  onRunToolboxItem,
  toolboxError,
  toolboxListError,
  elevationError,
  commandResult,
  commandPending = false,
  onScreenshot,
  screenshotStatus,
  onToggleRecording,
  recording = false,
  recordingPending = false,
  recordingRequired = false,
  recordingResult,
  onSaveNote,
  onBrowseDir,
  dirListing,
  dirLoading,
  dirError,
  onGetFileAccess,
  fileGrantInstalled,
  onDownloadFile,
  completedDownloadFiles,
  onUploadFiles,
  browseUploads,
  transferDirPath,
  endSessionStatus,
  machineName = "unknown-agent",
  machineAlias,
  onDisconnect,
  onVideoElement,
  onVisibilityChange,
  pinnedMonitorId,
  monitorCanvas,
  onCropMonitorChange,
}: ViewerProps) {
  const ownerWindow = hostWindow ?? window;
  const ownerDocument = ownerWindow.document;
  // Audio starts MUTED and needs a click, for two independent reasons that happen to agree.
  //
  // Browsers refuse to autoplay audible media without a user gesture; a <video muted> plays, an
  // unmuted one may be blocked with nothing but a rejected promise to show for it. Un-muting in
  // response to the operator's own click IS that gesture, so this path always works.
  //
  // And it is the behaviour to want anyway: a technician connecting to a machine in an open-plan
  // office should not have the guest's music come out of their laptop unannounced.
  const [audioOn, setAudioOn] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);
  /**
   * Bumped whenever the surface or video ELEMENT changes identity, which happens when the desktop is
   * moved into (or back out of) a pop-out window and the browser builds new nodes for it.
   *
   * Four effects below bind to these elements — `srcObject`, the intrinsic-size listener, the
   * ResizeObserver and the non-passive wheel listener — and three of them had dependency lists that
   * could not see an element swap (`[]`, `[stream]`). Without this they would stay attached to
   * detached nodes: the popped-out desktop would render black, never re-clamp its pan, and ignore the
   * scroll wheel, all while every one of them looked correctly written.
   */
  const [elEpoch, setElEpoch] = useState(0);
  const onSurfaceEl = useCallback((el: HTMLDivElement | null, previous: HTMLDivElement | null) => {
    if (!el && surfaceRef.current !== previous) return;
    surfaceRef.current = el;
    if (el) setElEpoch((n) => n + 1);
  }, []);
  const onVideoEl = useCallback((el: HTMLVideoElement | null, previous: HTMLVideoElement | null) => {
    if (!el && videoRef.current !== previous) return;
    videoRef.current = el;
    if (el) setElEpoch((n) => n + 1);
    onVideoElement?.(el);
  }, [onVideoElement]);
  // The whole viewer (toolbar + surface) is what goes fullscreen, so the controls stay reachable on a
  // phone/tablet rather than dropping the operator into a chrome-less video they can't disconnect from.
  const viewerRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeMonitor, setActiveMonitor] = useState(0);
  const [captureInput, setCaptureInput] = useState(true);
  // Reboot is destructive, so the button opens an inline confirm with the two modes rather than
  // firing on one click (and no native `confirm()`, which blocks the pump and is hard to drive in
  // the e2e). Closed by choosing a mode or Cancel.
  const [rebootMenuOpen, setRebootMenuOpen] = useState(false);
  // Shut Down is the most destructive control action (the agent cannot bring the machine back), so it
  // is two-step: the first click ARMS a confirm, the second actually sends `ShutDownGuest`.
  const [shutdownArmed, setShutdownArmed] = useState(false);
  // Menu redesign wave 9: Log off closes the signed-in user's apps (unsaved work is lost), so it is two-step too.
  const [logoffArmed, setLogoffArmed] = useState(false);
  // The system-tool launcher menu (Task Manager, Registry Editor, …). A dropdown rather than five
  // toolbar buttons; picking one sends `LaunchTool` and closes.
  const [toolsMenuOpen, setToolsMenuOpen] = useState(false);
  // The one-line command bar. A toggle opens a panel with an input, a shell picker, an "as user"
  // toggle, and the captured output. Local UI state; the command itself and its result flow through
  // `onRunCommand` / `commandResult`.
  const [commandOpen, setCommandOpen] = useState(false);
  const [filesOpen, setFilesOpen] = useState(false);
  const [commandText, setCommandText] = useState("");
  const [commandShell, setCommandShell] = useState<CommandShell>("Cmd");
  const [commandAsUser, setCommandAsUser] = useState(false);
  const [noteOpen, setNoteOpen] = useState(false);
  const [noteDraft, setNoteDraft] = useState("");
  const [notePending, setNotePending] = useState(false);
  const [noteSavedMsg, setNoteSavedMsg] = useState<string | null>(null);
  const [viewPanelOpen, setViewPanelOpen] = useState(false);
  const [inputPanelOpen, setInputPanelOpen] = useState(false);
  const [toolsPanelOpen, setToolsPanelOpen] = useState(false);
  const [showKeys, setShowKeys] = useState(false);
  const [viewPanelPos, setViewPanelPos] = useState<PanelPos>({ top: 40, left: 0, maxHeight: 400, maxWidth: 400 });
  const [inputPanelPos, setInputPanelPos] = useState<PanelPos>({ top: 40, left: 0, maxHeight: 400, maxWidth: 400 });
  const [toolsPanelPos, setToolsPanelPos] = useState<PanelPos>({ top: 40, left: 0, maxHeight: 400, maxWidth: 400 });
  // End-session confirm (destructive, especially "remove client"), a two-step inline menu like reboot.
  // Zoom & pan of the remote image. `IDENTITY_VIEW` is scale-to-fit (the whole desktop, letterboxed).
  // The pointer→desktop mapping is derived from this same state (lib/viewport), so it is correct at
  // any zoom — retiring the old "input paused in 1:1" limitation.
  const [view, setView] = useState<ViewTransform>(IDENTITY_VIEW);
  /**
   * The current transform, mirrored onto a ref for the TOUCH path.
   *
   * One touch event can produce several actions — a pinch that also clicks, a drag whose pan
   * preceded it — and those are applied with functional `setView` updates, so React state has not
   * caught up by the time a later action in the same batch needs to map a point to the desktop.
   * Reading `view` from the closure there would map against the pre-gesture transform and land the
   * click in the wrong place on the customer's machine. The mouse path does not need this because a
   * mouse event yields exactly one action.
   */
  const viewRef = useRef<ViewTransform>(IDENTITY_VIEW);
  viewRef.current = view;
  // The operator's last explicit zoom choice: "fit" (reset to scale-to-fit) or "actual" (1:1
  // native pixels). A ref rather than state because a monitor change reads it inside a callback
  // and it never needs to drive a render on its own.
  const scalePrefRef = useRef<"fit" | "actual">("fit");
  // Set by onMonitorChange when scalePref is "actual"; cleared once the new monitor's real
  // content dimensions arrive and the 1:1 snap is applied.
  const pendingActualSnapRef = useRef(false);
  // Pan mode: while on, pointer drags PAN the image and are NOT sent to the remote (a view-only
  // navigation mode, like the old 1:1 view but with a live indicator). Off ⇒ every pointer event
  // controls the remote, correctly mapped.
  const [panning, setPanning] = useState(false);
  // Intrinsic size of the streamed desktop image (video `videoWidth`/`videoHeight`); 0 until known,
  // where the surface size stands in (correct for the aspect-matched preview).
  const [contentSize, setContentSize] = useState<{ w: number; h: number }>({ w: 0, h: 0 });
  // Mirror contentSize to a ref so onMonitorChange (a stable useCallback) can read the current
  // value without contentSize in its deps — which would recreate the callback on every resize.
  const contentSizeRef = useRef<{ w: number; h: number }>({ w: 0, h: 0 });
  contentSizeRef.current = contentSize;
  // Incremented on every monitor switch so the snap effect re-runs even for same-resolution
  // switches where contentSize itself doesn't change (the track keeps its intrinsic dims).
  const [monitorSwitchSeq, setMonitorSwitchSeq] = useState(0);
  const [lastEvent, setLastEvent] = useState<string>("");
  const [showAdvancedQuality, setShowAdvancedQuality] = useState(false);
  // Modifiers armed on the key strip above the phone's keyboard. Purely local: nothing is pressed on
  // the guest until the next key, and that key releases them again (see `oskKeyEvents`). Mirrored in
  // a ref so the typing handler reads the current latch without re-subscribing.
  const [latched, setLatched] = useState<readonly string[]>([]);
  const latchedRef = useRef<readonly string[]>([]);
  latchedRef.current = latched;
  // The phone-typing bar: a real text field so the device's OWN keyboard opens, diffed into input
  // events on every edit (see `phone_typing.ts`). `typedRef` is the field's CONTENT (sentinel
  // stripped) as of the last diff — what the guest holds before its caret; `composingRef` holds an
  // IME composition open so the field is never reset under it; `typingSuppressRef` silences the
  // input handler while a reset force-commits a composition.
  const [showTyping, setShowTyping] = useState(false);
  const typingRef = useRef<HTMLTextAreaElement | null>(null);
  const typingBarRef = useRef<HTMLDivElement | null>(null);
  const typedRef = useRef<string>("");
  const composingRef = useRef(false);
  const typingSuppressRef = useRef(false);
  // Live pan-drag anchor: pointer position + view pan at drag start (a ref so a move doesn't rerender
  // per pixel). Null when no drag is in progress.
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  // DOM button codes currently pressed on the REMOTE via this surface. Tracked so every button-down
  // is guaranteed a matching button-up even if the pointer is released over the letterbox or off the
  // surface entirely — otherwise a button could stick pressed on the customer's machine.
  // Who holds each remote mouse button (lib/button_owners.ts): the physical mouse, the trackpad and
  // direct touch can all press the same button, and only the LAST owner letting go releases it.
  const ownersRef = useRef<Owners>(NO_OWNERS);
  // Trackpad pointer mode (lib/trackpad.ts): the operator's per-device choice, the pure reducer's
  // state (mirrored to a ref so a burst of touch events composes) and the collapsed flag of its bar.
  const [trackpadOn, setTrackpadOn] = useState(() => readTrackpadPrefs().enabled);
  const [tp, setTp] = useState<TrackpadState>(() => ({
    ...INITIAL_TRACKPAD_STATE,
    sensitivity: readTrackpadPrefs().sensitivity,
  }));
  const tpRef = useRef<TrackpadState>(tp);
  const [tpCollapsed, setTpCollapsed] = useState(false);
  const lastTouchAtRef = useRef(0);
  const leftPressRef = useRef<PressActivation>(NO_PRESS);
  // Key codes sent down to the remote that have not yet received a matching keyup. Flushed as keyup
  // events whenever keyboard listeners are removed (menu open, input disabled, unmount) so nothing
  // stays stuck pressed on the customer's machine.
  const pressedKeysRef = useRef<Map<string, { code: string; keyCode: number }>>(new Map());
  // Latest wheel-handler closure, dispatched to by a stable NON-PASSIVE native listener (see below).
  const wheelHandlerRef = useRef<(e: WheelEvent) => void>(() => {});
  const viewTriggerRef = useRef<HTMLButtonElement>(null);
  const inputTriggerRef = useRef<HTMLButtonElement>(null);
  const toolsTriggerRef = useRef<HTMLButtonElement>(null);
  const viewPanelRef = useRef<HTMLDivElement>(null);
  const inputPanelRef = useRef<HTMLDivElement>(null);
  const toolsPanelRef = useRef<HTMLDivElement>(null);
  // Mirrors of the panel-open state as refs so the Escape handler can read the CURRENT value without
  // adding the state variables to its dep array (which would re-subscribe every toggle).
  const viewPanelOpenRef = useRef(false);
  const inputPanelOpenRef = useRef(false);
  const toolsPanelOpenRef = useRef(false);

  // Pan mode is view-only navigation, so NO input reaches the remote there — pointer, keyboard, and
  // the key toolbars alike. That keeps the "pan mode — input not sent" indicator literally true; a
  // review caught keyboard leaking through in pan mode while the banner claimed input was off.
  // `inputActive` gates keyboard + the special-key/OSK toolbars (keys carry no coordinates, so they
  // are correct at any *zoom* — a merely-zoomed, not-panning view still sends them).
  const inputActive = captureInput && !panning && !recoveryNotice;
  // A pointer event actuates the remote only when capturing AND not in pan-navigation mode.
  const pointerToRemote = captureInput && !panning;
  // Trackpad mode drives the remote only where direct touch would: capturing and not panning. Outside
  // that (pan mode, capture off) the ordinary touch gestures apply, which is what navigates the view.
  const padActive = trackpadOn && pointerToRemote;

  // Current surface + desktop-image dimensions for the transform. Read live from the DOM (the surface
  // can resize) and combined with the last-known intrinsic video size. Defined before the effects
  // that consume it.
  const activeCrop = useMemo(() => monitorCanvas ? monitorCrop(monitorCanvas, activeMonitor) : null,
    [monitorCanvas, activeMonitor]);
  useEffect(() => { onCropMonitorChange?.(activeCrop ? activeMonitor : null); },
    [activeCrop, activeMonitor, onCropMonitorChange]);
  const readDims = useCallback((): { rect: DOMRect; dims: Dims } | null => {
    const surface = surfaceRef.current;
    if (!surface) return null;
    const rect = surface.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return null;
    return {
      rect,
      dims: { surfaceW: rect.width, surfaceH: rect.height, contentW: contentSize.w * (activeCrop?.width ?? 1), contentH: contentSize.h * (activeCrop?.height ?? 1) },
    };
  }, [contentSize, activeCrop]);

  const activeCropStyles = (() => {
    if (!activeCrop) return null;
    const info = readDims();
    const rect = info && contentRect(info.dims, view);
    if (!rect) return null;
    const styles = computeCropStyles(activeCrop, true);
    styles.wrapperStyle = { ...styles.wrapperStyle,
      left:`${rect.ox}px`, top:`${rect.oy}px`, width:`${rect.cw}px`, height:`${rect.ch}px` };
    return styles;
  })();

  // Fall back to a single "Display 1" when the agent advertised no monitor list.
  const monitorList = useMemo<MonitorInfo[]>(
    () =>
      monitors.length > 0
        ? monitors
        : [{ id: 0, label: "Display 1", width: 0, height: 0, primary: true }],
    [monitors],
  );
  // Mirror monitorList to a ref so onMonitorChange (a stable useCallback) can read the current
  // monitor list without monitorList in its deps — which would recreate the callback on every change.
  const monitorListRef = useRef<MonitorInfo[]>([]);
  monitorListRef.current = monitorList;

  // Land on the PRIMARY when the agent's real monitor list first arrives, and thereafter keep the
  // selection valid as that list changes (the composite "view all" id stays valid as long as more
  // than one monitor is present).
  //
  // The first-list step exists because id 0 is the LEFTMOST monitor, not the primary (ids are
  // positional — see `defaultMonitorSelection`). Without it the picker would sit on "Display 1"
  // while the agent streamed the primary, and the label would name a different screen than the one
  // on-screen. The selection is pushed to the agent rather than only set locally: both sides derive
  // the same answer from the same `primary` flag, but sending it makes the two provably agree
  // instead of relying on them staying in step.
  const monitorDefaultApplied = useRef(false);
  useEffect(() => {
    if (monitors.length > 0 && !monitorDefaultApplied.current) {
      monitorDefaultApplied.current = true;
      const initial = initialMonitorId !== undefined && isValidMonitorSelection(initialMonitorId, monitorList)
        ? initialMonitorId : defaultMonitorSelection(monitorList);
      if (initial !== activeMonitor) {
        setActiveMonitor(initial);
        // In canvas mode the crop is local — NEVER call onSelectMonitor; the agent keeps
        // streaming the full canvas and knows nothing about our local crop choice.
        if (!monitorCanvas) onSelectMonitor?.(initial);
      }
      return;
    }
    if (!isValidMonitorSelection(activeMonitor, monitorList)) {
      const next = defaultMonitorSelection(monitorList);
      setActiveMonitor(next);
      // monitors=[] means pre-discovery (fallback Display1 is local only); only send the
      // replacement request when a real list is present so the agent never sees a synthetic id.
      if (monitors.length > 0 && !monitorCanvas) onSelectMonitor?.(next);
    }
  }, [monitors, monitorList, activeMonitor, onSelectMonitor, monitorCanvas, initialMonitorId]);

  // Audio going away (agent restarted, endpoint unplugged) must not leave the control reading ON
  // for a stream that no longer exists — an indicator that lies is worse than one that is absent.
  useEffect(() => {
    if (!audioAvailable) setAudioOn(false);
  }, [audioAvailable]);

  // Attach the remote media stream to the <video> element.
  useEffect(() => {
    const el = videoRef.current;
    if (el && stream) {
      el.srcObject = stream;
    }
  }, [stream, elEpoch]);

  // Track the streamed desktop's intrinsic size so the transform letterboxes to the RIGHT aspect
  // ratio. `resize` fires when the agent changes resolution mid-session (a quality or monitor switch).
  useEffect(() => {
    const el = videoRef.current;
    if (!el) return;
    const update = () => setContentSize({ w: el.videoWidth, h: el.videoHeight });
    update();
    el.addEventListener("loadedmetadata", update);
    el.addEventListener("resize", update);
    return () => {
      el.removeEventListener("loadedmetadata", update);
      el.removeEventListener("resize", update);
    };
  }, [stream, elEpoch]);

  // Keep the pan valid when the geometry changes: the surface resizing (window resize, a panel
  // toggling open) OR the streamed resolution/aspect changing on the SAME monitor (a quality switch).
  // Either could turn a previously-legal pan into a black gap. `readDims` closes over `contentSize`,
  // so this effect also re-runs — and re-clamps — when the intrinsic video size changes.
  useEffect(() => {
    const surface = surfaceRef.current;
    if (!surface || typeof ResizeObserver === "undefined") return;
    const reclamp = () => {
      const info = readDims();
      if (info) setView((v) => clampPan(info.dims, v));
    };
    reclamp();
    const ro = new ResizeObserver(reclamp);
    ro.observe(surface);
    return () => ro.disconnect();
  }, [readDims, elEpoch]);

  // After a monitor switch where the operator prefers 1:1, re-apply the native-pixel view once the
  // new stream's real dimensions are known. The flag is read by ref (no dep) and cleared on the
  // first real-dimension fire to prevent re-firing.
  //
  // Two triggers:
  //   contentSize — fires for different-resolution switches once loadedmetadata/resize supplies
  //                 the new track dims (onMonitorChange cleared contentSize to zero for these).
  //   monitorSwitchSeq — fires for same-resolution switches where the track's intrinsic size is
  //                      unchanged so neither loadedmetadata nor resize re-fires; onMonitorChange
  //                      skips the contentSize clear and increments this counter instead.
  useEffect(() => {
    if (!pendingActualSnapRef.current) return;
    const w = contentSize.w * (activeCrop?.width ?? 1);
    const h = contentSize.h * (activeCrop?.height ?? 1);
    if (w === 0 || h === 0) return;
    pendingActualSnapRef.current = false;
    const surface = surfaceRef.current;
    if (!surface) return;
    const rect = surface.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    setView(preferredViewForMonitorSwitch("actual", { surfaceW: rect.width, surfaceH: rect.height, contentW: w, contentH: h }));
  }, [contentSize, monitorSwitchSeq, activeCrop]);

  // Forget the phone-typing field's history: empty content, sentinel back. Required whenever the
  // guest's caret may have moved behind the bar's back (see the contract in `phone_typing.ts`), or a later Backspace or
  // autocorrect would delete text the operator never meant. A live composition is force-committed by
  // a blur first — rewriting the value under it would garble the word — with the input handler
  // silenced, because what it commits was already sent live as the composition grew.
  const resetTyping = useCallback((refocus: boolean) => {
    const el = typingRef.current;
    if (!el) return;
    const wasFocused = el.ownerDocument.activeElement === el;
    if (composingRef.current && wasFocused) {
      typingSuppressRef.current = true;
      try {
        el.blur();
      } finally {
        typingSuppressRef.current = false;
      }
    }
    composingRef.current = false;
    el.value = TYPING_SENTINEL;
    typedRef.current = "";
    if (refocus && el.ownerDocument.activeElement !== el) el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
  }, []);

  const sendEvent = useCallback(
    (ev: InputEvent, label: string) => {
      setLastEvent(label);
      // A click or tap on the guest moves its caret or focus: the typing bar's history is now stale
      // (on a phone the tap need not even take focus from the field, so onFocus cannot catch it).
      if (ev.t === "MouseButton") resetTyping(false);
      // Canonical codec: frame the encoded InputEvent onto ChannelId.Input over the one
      // "frames" channel — the exact bytes the Rust agent's input_codec decodes + injects.
      transport?.send(ChannelId.Input, encodeInput(ev));
    },
    [transport, resetTyping],
  );

  /** Take ownership of a button; the DOWN goes out only if nobody else already holds it. */
  const pressButton = useCallback(
    (button: number, owner: Owner, label: string) => {
      const ev = buttonEvent(button, true);
      if (!ev) return;
      const r = acquire(ownersRef.current, button, owner);
      ownersRef.current = r.owners;
      if (r.send) sendEvent(ev, label);
    },
    [sendEvent],
  );
  /** Let go as one owner; the UP goes out only when that was the last owner. Never gated. */
  const releaseButton = useCallback(
    (button: number, owner: Owner, label: string) => {
      const r = releaseOwner(ownersRef.current, button, owner);
      ownersRef.current = r.owners;
      const ev = r.send ? buttonEvent(button, false) : null;
      if (ev) sendEvent(ev, label);
    },
    [sendEvent],
  );
  /** Every owner lets go at once (capture off, monitor change): one UP per held button. */
  const releaseEverything = useCallback(
    (label: string) => {
      const r = releaseAll(ownersRef.current);
      ownersRef.current = r.owners;
      for (const b of r.ups) {
        const ev = buttonEvent(b, false);
        if (ev) sendEvent(ev, label);
      }
    },
    [sendEvent],
  );

  /**
   * Map a surface-local pointer position to absolute agent coordinates (0..65535).
   *
   * In CANVAS mode the viewport mapping operates on the cropped surface, yielding a fraction
   * within the crop. We then remap that fraction through `activeCrop` to get the full-canvas
   * fraction before calling `toAbs`. This ensures the agent — which always uses the full
   * virtual-desktop coordinate space — receives the right coordinate regardless of crop.
   *
   * In UNCROPPED mode this is identical to `mapPointerToAbs` from lib/viewport.
   */
  const mapPointer = useCallback(
    (px: number, py: number, dims: ReturnType<typeof readDims>): { xAbs: number; yAbs: number } | null => {
      if (!dims) return null;
      const pos = mapPointerToAbs(px, py, dims.dims, viewRef.current);
      if (!pos) return null;
      if (!activeCrop) return pos; // uncropped path — coordinates are already full-canvas
      // pos.xAbs / 65535 gives the fraction within the crop; remap to full canvas fraction.
      const remapped = remapCroppedPointer(pos.xAbs / 65535, pos.yAbs / 65535, activeCrop);
      if (!remapped) return null;
      // toAbs expects a [0,1] fraction and scales to 0..65535.
      // We inline the same scaling here to avoid importing toAbs separately.
      return {
        xAbs: Math.round(remapped.nx * 65535),
        yAbs: Math.round(remapped.ny * 65535),
      };
    },
    [activeCrop, readDims],
  );

  // THE ONE GATE for every key-only send — the special-key toolbar and the on-screen keyboard both
  // go through here, and nothing else may send keys.
  //
  // Gated on `inputActive` (= captureInput && !panning): the operator's master "send my input"
  // switch AND the pan-navigation mode. Unchecking capture stops the buttons too, not just the
  // pointer/keyboard; and pan mode sends NOTHING, so the "input not sent" banner cannot lie. Keys are
  // still correct at any zoom (a zoomed-but-not-panning view has inputActive true) — the console e2e
  // pins that keys fire while zoomed and stay silent while panning.
  //
  // Sharing one helper is the point. A loop-14 review found `sendSpecial` bypassing the master
  // switch entirely — two send paths had drifted apart, and only one of them was gated. A second
  // sender copying the check would be the same defect waiting to happen, so there is only one.
  //
  // `fromTyping` marks the phone-typing bar's own sends. Every OTHER key sent here (a special-key
  // chord like Alt+Tab or Win, an on-screen-keyboard cap) can move the guest's caret or focus while
  // the typing field keeps focus, so it forgets the bar's history first.
  const sendKeyEvents = useCallback(
    (events: InputEvent[], label: string, fromTyping = false) => {
      if (!inputActive || events.length === 0) return;
      if (!fromTyping) resetTyping(false);
      for (const ev of events) {
        transport?.send(ChannelId.Input, encodeInput(ev));
      }
      setLastEvent(label);
    },
    [transport, inputActive, resetTyping],
  );

  const sendSpecial = useCallback(
    (sk: SpecialKey) => sendKeyEvents(sk.build(), `special ${sk.label}`),
    [sendKeyEvents],
  );

  // A modifier on the key strip: latch or unlatch it locally (nothing is sent yet).
  const onStripModifier = useCallback((code: string) => {
    setLatched((l) => toggleLatch(l, code));
  }, []);

  // Typing reaches the guest only while input is live AND the session is not view-only (the agent
  // drops view-only input, so an edit "sent" then would be history the guest never received).
  const typingEnabled = inputActive && !viewOnly;

  // "Type clipboard" sends over seconds, so it reads the CURRENT gate and sender on every batch
  // through a ref: going view-only or pausing input mid-way stops it at the next batch.
  const typeClipboardSend = useRef<(events: InputEvent[]) => boolean>(() => false);
  typeClipboardSend.current = (events) => {
    if (!typingEnabled) return false;
    sendKeyEvents(events, "type clipboard");
    return true;
  };


  // Every edit to the phone-typing field: replay the diff on the guest, then put the sentinel back
  // when it is safe to (never mid-composition). Goes through `sendKeyEvents`, so the master input
  // switch and pan mode gate it like every other key path.
  const onTypingInput = useCallback(
    (inputType?: string) => {
      const el = typingRef.current;
      if (!el || typingSuppressRef.current) return;
      if (!typingEnabled) {
        // Nothing may be recorded as sent while it cannot be — reset instead of advancing history.
        resetTyping(false);
        return;
      }
      const edit = typingEdit(typedRef.current, el.value, inputType);
      if (edit.overflow) {
        setLastEvent("typing: edit too large — not sent");
        resetTyping(true);
        return;
      }
      // A latched strip modifier applies to the next typed letter or digit: Ctrl, then "c" on the
      // phone keyboard, sends Ctrl+C rather than the text "c". The field is reset, because the
      // character went as a key combination, not as text the guest now holds.
      const held = latchedRef.current;
      if (held.length) {
        setLatched([]);
        const ch = singleTypedChar(edit.events);
        const code = ch === null ? null : codeForTypedChar(ch);
        if (code) {
          sendKeyEvents(oskKeyEvents(held, code), `typed ${held.join("+")}+${ch}`, true);
          resetTyping(true);
          return;
        }
      }
      typedRef.current = edit.content;
      sendKeyEvents(edit.events, "typed", true);
      if (shouldReseed(el.value, composingRef.current)) {
        el.value = TYPING_SENTINEL;
        typedRef.current = "";
      }
    },
    [sendKeyEvents, typingEnabled, resetTyping],
  );

  // Losing input (capture off, pan, view-only) or getting it back invalidates the history either way.
  useEffect(() => {
    resetTyping(false);
  }, [typingEnabled, resetTyping]);

  // A nav key (button or hardware) moves the guest caret: reset FIRST, then send.
  const sendTypingNav = useCallback(
    (events: InputEvent[], label: string) => {
      resetTyping(true);
      sendKeyEvents(events, label, true);
    },
    [resetTyping, sendKeyEvents],
  );

  // A strip key (Esc, arrows, …) carries any latched modifier with it, then clears the latch.
  const sendStripKey = useCallback(
    (k: NavKey) => {
      const held = latchedRef.current;
      setLatched([]);
      sendTypingNav(held.length ? oskKeyEvents(held, k.code) : navKeyEvents(k), `strip ${held.join("+")}${held.length ? "+" : ""}${k.label}`);
    },
    [sendTypingNav],
  );

  // On a touch device the typing bar is docked to the bottom of what the user can SEE (index.css), so
  // its special-key line sits right on top of the phone's own keyboard. Android Chrome overlays the
  // keyboard on the page instead of resizing it, so a plain `bottom: 0` would sit behind the keyboard:
  // follow the visual viewport and publish how much of the window the keyboard covers.
  //
  // The bar and the keyboard then lie OVER the bottom of the remote screen, and with a wide screen
  // fitted to a portrait phone what stayed visible was mostly the black letterbox above the picture
  // (Ed, 2026-10-27). So the surface also gives up the covered strip (--typing-cover, a bottom
  // margin): the fit, the pan clamp and the touch mapping all read the surface's rect, so the picture
  // re-fits into the part of the screen still visible above the bar.
  useEffect(() => {
    if (!showTyping) return;
    const bar = typingBarRef.current;
    const win = bar?.ownerDocument.defaultView;
    const vv = win?.visualViewport;
    if (!bar || !win || !vv) return;
    let lifted: HTMLDivElement | null = null;
    const update = () => {
      const covered = Math.max(0, win.innerHeight - (vv.height + vv.offsetTop));
      bar.style.setProperty("--keyboard-inset", `${Math.round(covered)}px`);
      const surface = surfaceRef.current;
      if (!surface) return;
      if (lifted && lifted !== surface) lifted.style.removeProperty("--typing-cover");
      lifted = surface;
      // Measure against where the surface would end WITHOUT the margin, or the margin would feed back.
      const current = parseFloat(surface.style.getPropertyValue("--typing-cover")) || 0;
      const bottom = surface.getBoundingClientRect().bottom + current;
      // The bar sits `covered` px up from the layout bottom; read it after the inset has applied.
      const cover = Math.max(0, Math.round(bottom - bar.getBoundingClientRect().top));
      if (cover !== current) surface.style.setProperty("--typing-cover", `${cover}px`);
    };
    update();
    vv.addEventListener("resize", update);
    vv.addEventListener("scroll", update);
    win.addEventListener("resize", update);
    // The bar grows when the field wraps a long line, and the surface moves when panels toggle.
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(update);
    ro?.observe(bar);
    return () => {
      vv.removeEventListener("resize", update);
      vv.removeEventListener("scroll", update);
      win.removeEventListener("resize", update);
      ro?.disconnect();
      lifted?.style.removeProperty("--typing-cover");
    };
  }, [showTyping]);

  const openTyping = useCallback(() => {
    if (showTyping) {
      setShowTyping(false);
      setLatched([]);
      return;
    }
    // Focus has to happen INSIDE the tap's handler or Android will not raise its keyboard, so the
    // field is rendered synchronously first rather than focused from an effect after the render.
    flushSync(() => setShowTyping(true));
    resetTyping(true);
  }, [showTyping, resetTyping]);

  // Apply a new view, dropping pan mode once back at the fit (zoom ≤ 1, where the letterboxed content
  // can never overflow the surface) so the operator is never stranded in a mode that does nothing.
  // Any explicit zoom choice (Fit, 1:1, In, Out, gesture) also cancels a pending monitor-switch snap:
  // if the operator zooms before the new stream's dims arrive, their choice wins over the deferred snap.
  const applyView = useCallback((next: ViewTransform) => {
    pendingActualSnapRef.current = false;
    setView(next);
    if (next.zoom <= 1) {
      setPanning(false);
      dragRef.current = null;
    }
  }, []);

  const onMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const drag = dragRef.current;
      if (drag) {
        // A pan drag in progress: translate the view by how far the pointer moved since drag start.
        const info = readDims();
        if (!info) return;
        setView(
          panBy(info.dims, { zoom: view.zoom, panX: drag.panX, panY: drag.panY },
            e.clientX - drag.x, e.clientY - drag.y),
        );
        return;
      }
      if (!pointerToRemote) return;
      const info = readDims();
      if (!info) return;
      const pos = mapPointer(e.clientX - info.rect.left, e.clientY - info.rect.top, info);
      if (!pos) return; // pointer is over the letterbox / off the desktop → send nothing
      sendEvent(moveEvent(pos.xAbs, pos.yAbs), `move ${pos.xAbs},${pos.yAbs}`);
    },
    [pointerToRemote, readDims, view, sendEvent, mapPointer],
  );

  // Only a button-DOWN is handled on the surface; the matching UP is delivered by a window-level
  // listener (below) so it fires wherever the release happens — over the letterbox or off-surface.
  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (panning) {
        // In pan mode the left button drives the pan drag; nothing reaches the remote.
        e.preventDefault();
        if (e.button === 0) dragRef.current = { x: e.clientX, y: e.clientY, panX: view.panX, panY: view.panY };
        return;
      }
      if (!pointerToRemote) return;
      const info = readDims();
      if (!info) return;
      // Only PRESS a button where the pointer maps onto the desktop — a press in the letterbox is
      // dropped (matching the move behaviour) so a click never lands at a clamped edge coordinate. The
      // release is NOT gated this way (a button-up carries no coordinate, and must always be sent).
      const pos = mapPointer(e.clientX - info.rect.left, e.clientY - info.rect.top, info);
      if (!pos) return;
      e.preventDefault();
      // DOM: 0=left, 1=middle, 2=right, 3=back, 4=forward (dom_input maps to InputButton).
      if (!buttonEvent(e.button, true)) return;
      // preventDefault suppresses the browser's normal focus transfer. Reclaim it explicitly
      // after a real desktop click, otherwise a previously selected console field keeps swallowing
      // keys through the editable-target guard. currentTarget also belongs to the pop-out document.
      (e.currentTarget as HTMLElement).focus({ preventScroll: true });
      // A local viewport switch can occur under a stationary pointer (keyboard menu).
      // Position the remote cursor explicitly before pressing in the newly visible monitor.
      if (monitorCanvas) sendEvent(moveEvent(pos.xAbs, pos.yAbs), `move ${pos.xAbs},${pos.yAbs}`);
      pressButton(e.button, "mouse", `btn ${e.button} down`);
    },
    [panning, pointerToRemote, readDims, view, sendEvent, mapPointer, monitorCanvas, pressButton],
  );

  // The wheel handler lives on a NON-PASSIVE native listener (attached in an effect below) because
  // React 18 registers its delegated `onWheel` as passive, making `preventDefault()` a no-op — a
  // Ctrl+wheel would then ALSO page-zoom the whole console. We keep the latest closure on a ref so the
  // stable native listener always sees current state without re-subscribing each frame.
  wheelHandlerRef.current = (e: WheelEvent) => {
    // Ctrl+wheel ZOOMS toward the cursor in any mode (view-only, so it works even with capture off).
    // Plain wheel is a remote scroll when controlling the remote, or a vertical pan while navigating.
    const info = readDims();
    if (e.ctrlKey) {
      if (!info) return;
      e.preventDefault();
      const dyPx = wheelPixels(e.deltaY, e.deltaMode);
      applyView(zoomByWheel(info.dims, view, e.clientX - info.rect.left, e.clientY - info.rect.top, dyPx));
      return;
    }
    if (panning) {
      if (!info) return;
      e.preventDefault();
      setView(panBy(info.dims, view, 0, -wheelPixels(e.deltaY, e.deltaMode)));
      return;
    }
    if (!pointerToRemote) return;
    // dom_input flips the sign (DOM down → agent down) and scales to wheel notches.
    sendEvent(
      wheelToScroll({ deltaX: e.deltaX, deltaY: e.deltaY, deltaMode: e.deltaMode }),
      `wheel ${e.deltaX},${e.deltaY}`,
    );
  };

  // --- Touch ------------------------------------------------------------------------------------
  //
  // The canvas was mouse-only, so on a phone it was undrivable: no pinch, no pan, no right click,
  // no drag, and a tap arrived only as the UA's synthetic delayed click. `lib/touch_gestures.ts`
  // decides what a finger MEANT; everything here does is turn that into the same calls the mouse
  // and wheel paths already make, so touch gains no privileges of its own.
  //
  // NOTE ON preventDefault: React registers touchstart/touchmove as PASSIVE at the root, exactly as
  // it does `wheel` (see the native wheel listener above and its comment). So `e.preventDefault()`
  // in these handlers is a silent no-op. It is not needed either — `touch-action: none` on
  // `.viewer__surface` is what stops the browser claiming the gesture, and CSS cannot be defeated by
  // a passive registration. Do not "fix" this by reaching for a native listener.
  const gestureRef = useRef<GestureState>(INITIAL_GESTURE_STATE);
  const longPressTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  /** Turn one recognised gesture action into the existing view/input calls. */
  const applyGestureAction = useCallback(
    (a: GestureAction) => {
      const info = readDims();
      if (!info) return;
      const { dims } = info;

      // Functional updates throughout: a single touch event can yield several actions, and reading
      // `view` from the closure would apply every one of them to the same stale transform.
      switch (a.kind) {
        case "pan":
          setView((prev) => panBy(dims, prev, a.dx, a.dy));
          return;
        case "zoom":
          // The recogniser reports a per-move RATIO, so it composes with whatever zoom we are at
          // and stays inside clampZoom rather than jumping to an absolute scale.
          // Cancel any pending monitor-switch snap so the operator's gesture wins (same contract
          // as the toolbar zoom buttons via applyView — see the applyView comment).
          pendingActualSnapRef.current = false;
          setView((prev) => zoomAtPoint(dims, prev, a.cx, a.cy, prev.zoom * a.scale));
          return;
        case "scroll":
          if (!pointerToRemote) {
            // View-only or pan mode: two fingers navigate, matching what a plain wheel does there.
            setView((prev) => panBy(dims, prev, a.dx, a.dy));
            return;
          }
          // Sign flip so it feels like grabbing the page: fingers moving DOWN pull the content
          // down, which is a wheel scrolling UP. `wheelToScroll` then applies its own DOM→agent
          // convention, so this is the only place the touch direction is decided.
          sendEvent(
            wheelToScroll({ deltaX: -a.dx, deltaY: -a.dy, deltaMode: 0 }),
            `touch scroll ${Math.round(a.dx)},${Math.round(a.dy)}`,
          );
          return;
        default:
          break;
      }

      // Everything below reaches the guest, so it is gated exactly like the mouse path.
      if (!pointerToRemote) return;
      // In canvas mode, remap through the active crop before sending to the agent.
      const at = (x: number, y: number) => mapPointer(x, y, info);

      switch (a.kind) {
        case "click": {
          const pos = at(a.x, a.y);
          if (!pos) return; // in the letterbox, off the desktop — send nothing, as the mouse does
          const dom = a.button === "right" ? 2 : 0;
          const down = buttonEvent(dom, true);
          const up = buttonEvent(dom, false);
          if (!down || !up) return;
          sendEvent(moveEvent(pos.xAbs, pos.yAbs), `touch move ${pos.xAbs},${pos.yAbs}`);
          sendEvent(down, `touch ${a.button} down`);
          sendEvent(up, `touch ${a.button} up`);
          return;
        }
        case "doubleClick": {
          const pos = at(a.x, a.y);
          if (!pos) return;
          const down = buttonEvent(0, true);
          const up = buttonEvent(0, false);
          if (!down || !up) return;
          sendEvent(moveEvent(pos.xAbs, pos.yAbs), `touch move ${pos.xAbs},${pos.yAbs}`);
          // Two down/up pairs rather than a "double click" event: the wire protocol has no such
          // event, and the guest's own double-click interval is what decides it — which is correct,
          // because that is the setting the customer configured.
          sendEvent(down, "touch left down");
          sendEvent(up, "touch left up");
          sendEvent(down, "touch left down");
          sendEvent(up, "touch left up");
          return;
        }
        case "dragStart": {
          const pos = at(a.x, a.y);
          if (!pos) return;
          const down = buttonEvent(0, true);
          if (!down) return;
          sendEvent(moveEvent(pos.xAbs, pos.yAbs), `touch move ${pos.xAbs},${pos.yAbs}`);
          pressButton(0, "touch", "touch drag down");
          return;
        }
        case "dragMove": {
          const pos = at(a.x, a.y);
          if (!pos) return;
          sendEvent(moveEvent(pos.xAbs, pos.yAbs), `touch drag ${pos.xAbs},${pos.yAbs}`);
          return;
        }
        case "dragEnd": {
          const up = buttonEvent(0, false);
          if (!up) return;
          // Released unconditionally, and the pressed-set is cleared: a button-UP must never be
          // dropped for a button that went down, whatever the coordinate says.
          releaseButton(0, "touch", "touch drag up");
          return;
        }
        default:
          return;
      }
    },
    [readDims, pointerToRemote, sendEvent, mapPointer, pressButton, releaseButton],
  );

  /** Feed one event through the recogniser, apply what it produced, re-arm the long-press timer. */
  const feedGesture = useCallback(
    (e: GestureEvent) => {
      const r = reduceGesture(gestureRef.current, e);
      gestureRef.current = r.state;
      for (const a of r.actions) applyGestureAction(a);

      if (longPressTimer.current !== null) {
        clearTimeout(longPressTimer.current);
        longPressTimer.current = null;
      }
      if (r.longPressDeadline !== undefined) {
        // The reducer cannot fire its own timer, so it hands back a deadline and we schedule the
        // one tick that turns a held finger into a right click.
        const delay = Math.max(0, r.longPressDeadline - performance.now());
        longPressTimer.current = setTimeout(() => {
          longPressTimer.current = null;
          feedGesture({ type: "tick", t: performance.now() });
        }, delay);
      }
    },
    [applyGestureAction],
  );

  // Clear the pending timer on unmount, or a tick can fire against a torn-down session.
  useEffect(
    () => () => {
      if (longPressTimer.current !== null) clearTimeout(longPressTimer.current);
    },
    [],
  );

  /** React TouchList → surface-relative points. `e.touches` is already the ACTIVE set. */
  const touchPoints = useCallback(
    (list: React.TouchList): GesturePoint[] => {
      const info = readDims();
      if (!info) return [];
      const out: GesturePoint[] = [];
      for (let i = 0; i < list.length; i++) {
        const t = list[i];
        out.push({ id: t.identifier, x: t.clientX - info.rect.left, y: t.clientY - info.rect.top });
      }
      return out;
    },
    [readDims],
  );

  // --- Trackpad mode -------------------------------------------------------------------------
  //
  // lib/trackpad.ts decides what a finger or a control MEANT; here it becomes the same calls the
  // mouse and wheel paths make (mapPointer / moveEvent / buttonEvent / wheelToScroll). The cursor is
  // kept as a fraction of the displayed desktop, so it is converted to a surface point and sent
  // through mapPointer: crops and multi-monitor canvases need no second mapping.
  //
  // THE GATE. Remote actions need `pointerToRemote` (as direct touch) AND a ready session: connected
  // and not paused for recovery. While it is closed the reducer is not even fed (see padEvent), so it
  // can never record a press that was not sent; `release` always gets through.
  const padGeom = useCallback(() => {
    const info = readDims();
    const r = info ? contentRect(info.dims, viewRef.current) : null;
    return { info, r, geom: { cw: r?.cw ?? 0, ch: r?.ch ?? 0 } };
  }, [readDims]);
  const canPadSend = pointerToRemote && connectionState === "connected" && !recoveryNotice;
  const canPadSendRef = useRef(canPadSend);
  canPadSendRef.current = canPadSend;

  // Moves and wheel are coalesced to a fixed cadence (lib/pad_sender.ts): the latest position once per
  // tick, wheel notches summed, everything flushed before any button event. The sinks read the
  // CURRENT cursor/view/gate through a ref, so a tick never acts on a stale closure.
  const padSinkRef = useRef({ move: () => {}, wheel: (_dx: number, _dy: number) => {} });
  padSinkRef.current = {
    move: () => {
      if (!canPadSendRef.current) return;
      const { info, r } = padGeom();
      if (!info || !r) return;
      const at = cursorMapPoint(r, tpRef.current.cursor);
      const pos = mapPointer(at.x, at.y, info);
      if (pos) sendEvent(moveEvent(pos.xAbs, pos.yAbs), `trackpad move ${pos.xAbs},${pos.yAbs}`);
    },
    wheel: (dx, dy) => {
      if (!canPadSendRef.current) return;
      sendEvent(wheelToScroll({ deltaX: dx * 100, deltaY: dy * 100, deltaMode: 0 }), `trackpad scroll ${dx},${dy}`);
    },
  };
  const padSender = useMemo(
    () =>
      createPadSender({
        schedule: (cb) => {
          const id = ownerWindow.setTimeout(cb, PAD_SEND_INTERVAL_MS);
          return () => ownerWindow.clearTimeout(id);
        },
        sendMove: () => padSinkRef.current.move(),
        sendWheel: (dx, dy) => padSinkRef.current.wheel(dx, dy),
      }),
    [ownerWindow],
  );

  /** Returns false when a button-DOWN could not be sent, so the reducer can be told. */
  const applyPadAction = useCallback(
    (a: TrackpadAction): boolean => {
      if (a.kind === "buttonUp") {
        // A release is never gated or dropped, and only lets go of what the pad itself pressed.
        padSender.flush();
        releaseButton(0, "pad", "trackpad left up");
        return true;
      }
      if (a.kind === "zoom") {
        const { info } = padGeom();
        if (!info) return true;
        pendingActualSnapRef.current = false;
        const { dims } = info;
        setView((prev) => zoomAtPoint(dims, prev, a.cx, a.cy, prev.zoom * a.scale));
        return true;
      }
      // Rejected BEFORE anything is recorded: nothing below may touch ownership while paused.
      if (!canPadSendRef.current) return a.kind !== "buttonDown";
      if (a.kind === "move") {
        padSender.move();
        return true;
      }
      if (a.kind === "wheel") {
        padSender.wheel(a.dx, a.dy);
        return true;
      }
      // A button event: anything still pending goes first, so it lands at the newest position.
      padSender.flush();
      const { info, r } = padGeom();
      if (!info || !r) return a.kind !== "buttonDown";
      const at = cursorMapPoint(r, a);
      const pos = mapPointer(at.x, at.y, info);
      if (!pos) return a.kind !== "buttonDown";
      const dom = a.kind === "click" && a.button === "right" ? 2 : 0;
      if (!buttonEvent(dom, true)) return a.kind !== "buttonDown";
      if (a.kind === "buttonDown") {
        sendEvent(moveEvent(pos.xAbs, pos.yAbs), `trackpad move ${pos.xAbs},${pos.yAbs}`);
        pressButton(0, "pad", "trackpad left down");
        return true;
      }
      // A synthesised click on a button somebody else is holding (a physical mouse mid-drag, direct
      // touch) is SUPPRESSED: a down/up pair inside their drag would release it. See button_owners.ts.
      if (!clickAllowed(ownersRef.current, dom)) return true;
      sendEvent(moveEvent(pos.xAbs, pos.yAbs), `trackpad move ${pos.xAbs},${pos.yAbs}`);
      const down = buttonEvent(dom, true);
      const up = buttonEvent(dom, false);
      if (down && up) {
        sendEvent(down, `trackpad ${a.button} down`);
        sendEvent(up, `trackpad ${a.button} up`);
      }
      return true;
    },
    [padGeom, padSender, mapPointer, sendEvent, pressButton, releaseButton],
  );
  // The reducer's actions are applied through a ref so the stable dispatcher below never sees a
  // stale closure (the view, the gate and the transport all change under it).
  const applyPadActionRef = useRef(applyPadAction);
  applyPadActionRef.current = applyPadAction;
  const geomRef = useRef(padGeom);
  geomRef.current = padGeom;

  const padEvent = useCallback(
    (ev: TrackpadEvent) => {
      // Paused or disconnected: refuse everything that could act on the guest BEFORE the reducer
      // mutates (a Hold latched now would be a press that was never sent). Release always runs.
      if (!canPadSendRef.current && ev.type !== "release" && ev.type !== "sensitivity") return;
      if (ev.type === "release") padSender.flush();
      const r = reduceTrackpad(tpRef.current, ev, geomRef.current().geom);
      tpRef.current = r.state;
      setTp(r.state);
      let rejectedDown = false;
      for (const a of r.actions) if (!applyPadActionRef.current(a)) rejectedDown = true;
      // A press that could not be sent (cursor unmappable, gate closed mid-way) must not leave the
      // reducer believing it is held: resync it to "nothing held".
      if (rejectedDown) {
        const rr = reduceTrackpad(tpRef.current, { type: "release" }, geomRef.current().geom);
        tpRef.current = rr.state;
        setTp(rr.state);
        for (const a of rr.actions) applyPadActionRef.current(a);
      }
    },
    [padSender],
  );

  /** Touches that started on the surface itself — not on the trackpad's own controls drawn over it. */
  const padPoints = useCallback(
    (list: React.TouchList): PadPoint[] => {
      const info = readDims();
      const surface = surfaceRef.current;
      if (!info || !surface) return [];
      const out: PadPoint[] = [];
      for (let i = 0; i < list.length; i++) {
        const t = list[i];
        const target = t.target as Element | null;
        if (!target || !surface.contains(target) || target.closest?.("[data-trackpad-ui]")) continue;
        out.push({ id: t.identifier, x: t.clientX - info.rect.left, y: t.clientY - info.rect.top });
      }
      return out;
    },
    [readDims],
  );

  const onTouchStart = useCallback(
    (e: React.TouchEvent) => {
      if (padActive) {
        lastTouchAtRef.current = performance.now();
        padEvent({ type: "start", points: padPoints(e.touches), t: performance.now() });
        return;
      }
      feedGesture({ type: "start", points: touchPoints(e.touches), t: performance.now() });
    },
    [padActive, padEvent, padPoints, feedGesture, touchPoints],
  );
  const onTouchMove = useCallback(
    (e: React.TouchEvent) => {
      if (padActive) {
        lastTouchAtRef.current = performance.now();
        padEvent({ type: "move", points: padPoints(e.touches), t: performance.now() });
        return;
      }
      feedGesture({ type: "move", points: touchPoints(e.touches), t: performance.now() });
    },
    [padActive, padEvent, padPoints, feedGesture, touchPoints],
  );
  const onTouchEnd = useCallback(
    (e: React.TouchEvent) => {
      if (padActive) {
        lastTouchAtRef.current = performance.now();
        padEvent({ type: "end", points: padPoints(e.touches), t: performance.now() });
        return;
      }
      feedGesture({ type: "end", points: touchPoints(e.touches), t: performance.now() });
    },
    [padActive, padEvent, padPoints, feedGesture, touchPoints],
  );
  const onTouchCancel = useCallback(() => {
    if (padActive) {
      lastTouchAtRef.current = performance.now();
      padEvent({ type: "cancel" });
      return;
    }
    feedGesture({ type: "cancel", t: performance.now() });
  }, [padActive, padEvent, feedGesture]);

  // A tap also makes the browser fire compatibility mouse events, which here would click UNDER the
  // finger. Drop those (and only those) while the trackpad is on; a real mouse still works.
  const isTouchEcho = (e: React.MouseEvent): boolean =>
    padActive &&
    isTouchEchoMouse(
      lastTouchAtRef.current,
      performance.now(),
      (e.nativeEvent as unknown as { sourceCapabilities?: { firesTouchEvents?: boolean } }).sourceCapabilities
        ?.firesTouchEvents,
    );
  const surfaceMouseMove = (e: React.MouseEvent) => {
    if (!isTouchEcho(e)) onMouseMove(e);
  };
  const surfaceMouseDown = (e: React.MouseEvent) => {
    if (!isTouchEcho(e)) onMouseDown(e);
  };

  // Let go of everything the trackpad holds whenever it can no longer be trusted to see the release:
  // the mode or the gate turning off, the session dropping, input pausing for recovery, the page
  // being hidden or losing focus, a monitor switch (onMonitorChange), unmount.
  const releasePad = useCallback(() => padEvent({ type: "release" }), [padEvent]);
  useEffect(() => {
    if (!padActive || !canPadSend) releasePad();
  }, [padActive, canPadSend, releasePad]);
  useEffect(() => {
    const doc = ownerDocument;
    const onVis = () => {
      if (doc.visibilityState === "hidden") releasePad();
    };
    doc.addEventListener("visibilitychange", onVis);
    ownerWindow.addEventListener("blur", releasePad);
    ownerWindow.addEventListener("pagehide", releasePad);
    return () => {
      doc.removeEventListener("visibilitychange", onVis);
      ownerWindow.removeEventListener("blur", releasePad);
      ownerWindow.removeEventListener("pagehide", releasePad);
      releasePad();
    };
  }, [ownerDocument, ownerWindow, releasePad]);

  const setTrackpad = useCallback(
    (on: boolean) => {
      setTrackpadOn(on);
      if (!on) padEvent({ type: "release" });
      writeTrackpadPrefs({ enabled: on, sensitivity: tpRef.current.sensitivity });
    },
    [padEvent],
  );
  const setSensitivity = useCallback(
    (value: Sensitivity) => {
      padEvent({ type: "sensitivity", value });
      writeTrackpadPrefs({ enabled: trackpadOn, sensitivity: value });
    },
    [padEvent, trackpadOn],
  );

  // Keep the cursor in view: a pinch, a pan clamp, a resize or the cursor reaching the edge of a
  // zoomed picture pans just enough to show it. A no-op pan is skipped or this would loop at an edge.
  useEffect(() => {
    if (!padActive) return;
    const { info, r } = padGeom();
    if (!info || !r) return;
    const pt = cursorSurfacePoint(r, tp.cursor);
    const d = revealDelta(pt, info.dims.surfaceW, info.dims.surfaceH);
    if (d.dx === 0 && d.dy === 0) return;
    const next = panBy(info.dims, viewRef.current, d.dx, d.dy);
    if (next.panX !== viewRef.current.panX || next.panY !== viewRef.current.panY) setView(next);
  }, [padActive, tp.cursor, view, contentSize, padGeom]);

  // Reset note panel when the session is no longer connected: clears any draft or status that
  // belongs to the previous session before the next one appears. Also close all overlay panels and
  // clear destructive confirmation state so they never carry over into a reconnected session.
  useEffect(() => {
    if (connectionState !== "connected") {
      setNoteOpen(false);
      setNoteDraft("");
      setNoteSavedMsg(null);
      setViewPanelOpen(false);
      setInputPanelOpen(false);
      setToolsPanelOpen(false);
      setToolsMenuOpen(false);
      setRebootMenuOpen(false);
      setShutdownArmed(false);
      setLogoffArmed(false);
    }
  }, [connectionState]);

  // Clear destructive confirmation state whenever the Tools panel is closed. An outside-click or
  // Escape that closes the panel without a choice should not leave Reboot / Shut Down half-armed the
  // next time the panel opens.
  useEffect(() => {
    if (!toolsPanelOpen) {
      setShutdownArmed(false);
      setRebootMenuOpen(false);
      setLogoffArmed(false);
    }
  }, [toolsPanelOpen]);

  const submitNote = useCallback(async () => {
    if (!onSaveNote || !noteDraft.trim()) return;
    setNotePending(true);
    setNoteSavedMsg(null);
    try {
      await onSaveNote(noteDraft.trim());
      setNoteSavedMsg("Note saved");
      setNoteDraft("");
      setNoteOpen(false);
    } catch {
      setNoteSavedMsg("Failed to save — try again");
    } finally {
      setNotePending(false);
    }
  }, [onSaveNote, noteDraft]);

  // Zoom controls (view-only, so not gated on capture). Buttons zoom about the surface centre; Fit
  // and 1:1 jump to the fit and to native pixels respectively.
  const zoomIn = useCallback(() => {
    const info = readDims();
    if (info) applyView(zoomToCenter(info.dims, view, view.zoom * ZOOM_STEP));
  }, [readDims, view, applyView]);
  const zoomOut = useCallback(() => {
    const info = readDims();
    if (info) applyView(zoomToCenter(info.dims, view, view.zoom / ZOOM_STEP));
  }, [readDims, view, applyView]);
  const zoomFit = useCallback(() => {
    scalePrefRef.current = "fit";
    applyView(IDENTITY_VIEW);
  }, [applyView]);
  const zoomActual = useCallback(() => {
    scalePrefRef.current = "actual";
    const info = readDims();
    if (info) applyView(zoomToCenter(info.dims, view, actualZoom(info.dims)));
  }, [readDims, view, applyView]);

  // Fullscreen. Track the browser's own state (the user can exit with Esc or a system gesture, not
  // just our button) so the label stays truthful. `requestFullscreen` can reject (permission, an
  // unsupported context) — swallow it rather than throwing into a click handler.
  useEffect(() => {
    const doc = surfaceRef.current?.ownerDocument ?? ownerDocument;
    const onFsChange = () => setIsFullscreen(doc.fullscreenElement != null);
    onFsChange();
    doc.addEventListener("fullscreenchange", onFsChange);
    return () => doc.removeEventListener("fullscreenchange", onFsChange);
  }, [elEpoch]);
  const toggleFullscreen = useCallback(() => {
    const doc = surfaceRef.current?.ownerDocument ?? ownerDocument;
    if (doc.fullscreenElement) {
      void doc.exitFullscreen().catch(() => {});
    } else {
      const target = doc === ownerDocument ? viewerRef.current : doc.documentElement;
      void target?.requestFullscreen?.().catch(() => {});
    }
  }, []);

  // MUST stay above the pop-out effect and both <ViewerSurface> uses: a const read before its
  // declaration is a ReferenceError (see Viewer.test.ts, which pins the order).
  // The trackpad's cursor and controls, drawn inside the surface (so they are clipped to it, sit
  // above the video, and stay above a docked phone keyboard: the surface already gives up that strip).
  // Its controls stop their own touch/mouse events so nothing they do reaches the surface handlers,
  // and keep focus where it is (mousedown preventDefault) so the phone keyboard stays up.
  const padOverlay = (() => {
    if (!padActive) return null;
    const { r } = padGeom();
    const pt = r ? cursorSurfacePoint(r, tp.cursor) : null;
    const stop = (e: React.SyntheticEvent) => e.stopPropagation();
    const noteTouch = (e: React.PointerEvent) => {
      if (e.pointerType !== "mouse") lastTouchAtRef.current = performance.now();
    };
    const ui = {
      "data-trackpad-ui": "",
      onTouchStart: stop,
      onTouchMove: stop,
      onTouchEnd: stop,
      onTouchCancel: stop,
      onMouseMove: stop,
      onMouseDown: (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
      },
      onPointerDownCapture: noteTouch,
      onPointerUpCapture: noteTouch,
      onContextMenu: (e: React.MouseEvent) => e.preventDefault(),
    };
    // [Left] can be pressed by a pointer, by the keyboard (Space/Enter held) or by assistive tech that
    // sends only a click. Every route must end in a release: pointer cancel / capture loss, key up,
    // BLUR (Tab away while Space is held, so the keyup lands elsewhere) and unmount (releasePad).
    const leftHandlers = {
      onPointerDown: (e: React.PointerEvent<HTMLButtonElement>) => {
        if (e.button !== 0) return;
        leftPressRef.current = pressBegan(e.pointerId);
        e.currentTarget.setPointerCapture?.(e.pointerId);
        padEvent({ type: "leftDown" });
      },
      onPointerUp: () => {
        leftPressRef.current = pressEnded(leftPressRef.current, performance.now());
        padEvent({ type: "leftUp" });
      },
      onPointerCancel: () => {
        // A cancelled press generates no click: forget it so it cannot be matched to a later one.
        leftPressRef.current = pressAbandoned();
        padEvent({ type: "leftUp" });
      },
      onLostPointerCapture: () => padEvent({ type: "leftUp" }),
      onKeyDown: (e: React.KeyboardEvent) => {
        // The keyboard path does its own down/up and suppresses the native activation click with
        // preventDefault (keydown and keyup), so it never sets a pending press.
        // preventDefault on EVERY Space/Enter keydown, repeats included: a held Enter auto-repeats, and
        // each unprevented repeat would fire a native click that releases the held press early.
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (!e.repeat) padEvent({ type: "leftDown" });
        }
      },
      onKeyUp: (e: React.KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          padEvent({ type: "leftUp" });
        }
      },
      onBlur: () => {
        leftPressRef.current = pressAbandoned();
        padEvent({ type: "leftUp" });
      },
      // Only the click a POINTER press on this button generated (detail > 0, same pointer) is
      // suppressed. A click with detail 0 (a screen reader's "activate", or any synthetic click) is
      // always an independent full click, down then up (lib/press_activation.ts).
      onClick: (e: React.MouseEvent) => {
        const c = clickArrived(leftPressRef.current, performance.now(), {
          detail: e.detail,
          pointerId: (e.nativeEvent as { pointerId?: number }).pointerId,
        });
        leftPressRef.current = c.state;
        if (!c.activate) return;
        padEvent({ type: "leftDown" });
        padEvent({ type: "leftUp" });
      },
    };
    const stripY = (e: React.PointerEvent<HTMLDivElement>) => e.clientY - e.currentTarget.getBoundingClientRect().top;
    const stepStrip = (dir: -1 | 1) => {
      padEvent({ type: "stripStart", y: dir < 0 ? 0 : 2, h: 2 });
      padEvent({ type: "stripEnd", y: dir < 0 ? 0 : 2 });
    };
    return (
      <>
        {pt && (
          <div
            className={`viewer__tpcursor${viewOnly ? " viewer__tpcursor--dim" : ""}`}
            data-testid="trackpad-cursor"
            data-fx={tp.cursor.fx.toFixed(4)}
            data-fy={tp.cursor.fy.toFixed(4)}
            style={{ transform: `translate(${pt.x}px, ${pt.y}px)` }}
            aria-hidden="true"
          >
            <svg width="22" height="30" viewBox="0 0 22 30" focusable="false">
              <path d="M1 1 L1 22 L6.5 17 L10.5 27 L14.5 25.3 L10.5 15.6 L18 15.6 Z" fill="#fff" stroke="#000" strokeWidth="1.6" strokeLinejoin="round" />
            </svg>
          </div>
        )}
        {tpCollapsed ? (
          <div className="viewer__tpbar viewer__tpbar--collapsed" {...ui} data-testid="trackpad-bar">
            <button
              type="button"
              className="viewer__tpbtn"
              data-testid="trackpad-expand"
              aria-expanded="false"
              aria-label="Show trackpad controls"
              onClick={() => setTpCollapsed(false)}
            >
              ▲
            </button>
          </div>
        ) : (
          <>
            <div className="viewer__tpbar" role="toolbar" aria-label="Trackpad controls" {...ui} data-testid="trackpad-bar">
              <button
                type="button"
                className="viewer__tpbtn viewer__tpbtn--small"
                data-testid="trackpad-collapse"
                aria-expanded="true"
                aria-label="Hide trackpad controls"
                onClick={() => setTpCollapsed(true)}
              >
                ▼
              </button>
              <button
                type="button"
                className={`viewer__tpbtn${tp.padButton ? " viewer__tpbtn--on" : ""}`}
                data-testid="trackpad-left"
                aria-label="Left click. Press and hold to drag."
                title="Left click at the cursor; press and hold to drag"
                {...leftHandlers}
              >
                Left
              </button>
              <button
                type="button"
                className={`viewer__tpbtn${tp.held ? " viewer__tpbtn--on" : ""}`}
                data-testid="trackpad-hold"
                aria-pressed={tp.held}
                aria-label="Hold left button (drag lock)"
                title="Keep the left button down so a one-finger drag drags; tap again to release"
                onClick={() => padEvent({ type: "holdToggle" })}
              >
                Hold
              </button>
              <button
                type="button"
                className="viewer__tpbtn"
                data-testid="trackpad-right"
                aria-label="Right click"
                title="Right click at the cursor"
                onClick={() => padEvent({ type: "rightClick" })}
              >
                Right
              </button>
            </div>
            <div
              className="viewer__tpstrip"
              role="group"
              tabIndex={0}
              aria-label="Scroll strip. Drag up or down to scroll, or tap the top or bottom for one step."
              data-testid="trackpad-scroll"
              {...ui}
              onPointerDown={(e) => {
                e.currentTarget.setPointerCapture?.(e.pointerId);
                padEvent({ type: "stripStart", y: stripY(e), h: e.currentTarget.getBoundingClientRect().height });
              }}
              onPointerMove={(e) => padEvent({ type: "stripMove", y: stripY(e) })}
              onPointerUp={(e) => padEvent({ type: "stripEnd", y: stripY(e) })}
              onPointerCancel={() => padEvent({ type: "stripCancel" })}
              onLostPointerCapture={() => padEvent({ type: "stripCancel" })}
              onKeyDown={(e) => {
                if (e.key === "ArrowUp") {
                  e.preventDefault();
                  stepStrip(-1);
                } else if (e.key === "ArrowDown") {
                  e.preventDefault();
                  stepStrip(1);
                }
              }}
            >
              <span className="viewer__tpstrip-grip" aria-hidden="true">▲<br />⋮<br />▼</span>
            </div>
          </>
        )}
      </>
    );
  })();

  // --- Pop the desktop into its own window (two monitors: desktop on one, console on the other) ---
  //
  // The child window gets its OWN React root rather than a `createPortal`. React binds its event
  // listeners to a tree's root container, and a portal's nodes live in the child document, so native
  // events there would never reach this document's container: the desktop would render and then
  // ignore every click. A root created against a container in the child listens where the events are.
  const popoutRef = useRef<{ win: Window; root: Root } | null>(null);
  const [poppedOut, setPoppedOut] = useState(false);
  // Full screen on a phone: one compact floating bar instead of the whole toolbar (Ed, 11-06: "a full
  // screen version that just has the monitor selector, trackpad selector and keyboard selector for
  // mobile"). "Mobile" is read live from the OWNER window (the viewer can live in another window):
  // a coarse primary pointer, or a phone-width viewport. The old chrome is hidden by CSS, not
  // unmounted, so the video and the peer connection are untouched by the switch.
  const [coarsePointer, setCoarsePointer] = useState(() => !!ownerWindow.matchMedia?.("(pointer: coarse)").matches);
  const [winWidth, setWinWidth] = useState(() => ownerWindow.innerWidth);
  useEffect(() => {
    const mq = ownerWindow.matchMedia?.("(pointer: coarse)");
    const onMq = () => setCoarsePointer(!!mq?.matches);
    const onResize = () => setWinWidth(ownerWindow.innerWidth);
    onMq();
    onResize();
    mq?.addEventListener?.("change", onMq);
    ownerWindow.addEventListener("resize", onResize);
    return () => {
      mq?.removeEventListener?.("change", onMq);
      ownerWindow.removeEventListener("resize", onResize);
    };
  }, [ownerWindow]);
  const mobileFs = shouldUseMobileFullscreenBar({
    isFullscreen,
    coarsePointer,
    width: winWidth,
    poppedOut: poppedOut || !!hostWindow,
  });
  // The View/Input/Tools panels belong to the chrome this mode hides; close them on the way in so
  // none is left floating over the video with no button to dismiss it.
  useEffect(() => {
    if (!mobileFs) return;
    setViewPanelOpen(false);
    setInputPanelOpen(false);
    setToolsPanelOpen(false);
  }, [mobileFs]);
  const [popoutError, setPopoutError] = useState<string | null>(null);

  const closePopout = useCallback(() => {
    const p = popoutRef.current;
    popoutRef.current = null;
    setPoppedOut(false);
    onPopoutChange?.(false);
    if (!p) return;
    // Unmount BEFORE closing the window. React has to detach listeners and run cleanups while that
    // document still exists; closing first leaves it unmounting against a dead document.
    try {
      p.root.unmount();
    } catch {
      /* the window may already be gone — the state above is what matters */
    }
    try {
      p.win.close();
    } catch {
      /* closing a window we did not open can throw; nothing here depends on it */
    }
  }, [onPopoutChange]);

  const popOut = useCallback(async () => {
    setPopoutError(null);
    const opened = await openPopout(`${machineDisplayLabel(machineName, machineAlias) || "Remote desktop"} — DeskRally`);
    if (!opened) {
      // Say so. A button that silently does nothing reads as a broken product, and a blocked popup
      // is the overwhelmingly common reason this fails.
      setPopoutError("The browser blocked the pop-out window — allow pop-ups for this site, then retry.");
      return;
    }
    popoutRef.current = { win: opened.win, root: createRoot(opened.container) };
    setPoppedOut(true);
    onPopoutChange?.(true);
    // The operator can close that window directly, and then the console must stop claiming the
    // desktop lives elsewhere. `pagehide` covers the normal close.
    opened.win.addEventListener("pagehide", closePopout);
  }, [machineName, machineAlias, closePopout, onPopoutChange]);

  // Keep the popped-out surface in sync. Deliberately NO dependency array: it must re-render for
  // every parent render, because the surface's props include the live view transform, the pan state
  // and the stream — a missed dependency here is a desktop frozen mid-pan in another window, which is
  // both easy to do and hard to spot.
  useEffect(() => {
    const p = popoutRef.current;
    if (!poppedOut || !p) return;
    p.root.render(
      <>
      <PopoutControls win={p.win} onReturn={closePopout} onFit={zoomFit} onActual={zoomActual}
        onZoomIn={zoomIn} onZoomOut={zoomOut} monitors={viewerMonitorOptions(monitorList)}
        activeMonitor={activeMonitor} onMonitorChange={onMonitorChange}
        monitorLocked={pinnedMonitorId !== undefined && !monitorCanvas}>{popoutControls}</PopoutControls>
      <ViewerSurface
        onSurfaceEl={onSurfaceEl}
        onVideoEl={onVideoEl}
        panning={panning}
        cropStyles={activeCropStyles}
        transform={videoTransform(view)}
        audioOn={audioOn}
        hasStream={!!stream}
        live={!!transport}
        recoveryNotice={recoveryNotice}
        onReconnect={onReconnect}
        onMouseMove={surfaceMouseMove}
        onMouseDown={surfaceMouseDown}
        overlay={padOverlay}
        onTouchStart={onTouchStart}
        onTouchMove={onTouchMove}
        onTouchEnd={onTouchEnd}
        onTouchCancel={onTouchCancel}
      />
      </>,
    );
  });

  // A window closed by the OS, a crashed tab, or a browser that does not fire `pagehide` on
  // `window.close()` would otherwise leave the console insisting the desktop is popped out with
  // nowhere to bring it back from. Polling `closed` is the only reliable cross-browser signal.
  useEffect(() => {
    if (!poppedOut) return;
    const t = setInterval(() => {
      if (popoutRef.current?.win.closed) closePopout();
    }, 1000);
    return () => clearInterval(t);
  }, [poppedOut, closePopout]);

  // A pop-out must not outlive the session. Without this, disconnecting leaves an orphaned window
  // showing a frozen last frame of someone's desktop.
  useEffect(() => () => closePopout(), [closePopout]);

  /**
   * Every window whose keyboard and mouse belong to this session.
   *
   * Two effects below listen at WINDOW level rather than on the surface — keystrokes, and the
   * button-UP that must arrive even when the release happens off the surface. Once the desktop is in
   * its own window those events fire THERE, and a listener bound only to the opener would never see
   * them: typing would reach no guest at all, and a drag released in the pop-out would leave the
   * button STUCK DOWN on the customer's machine — the precise failure the mouse-up effect was written
   * to prevent, reintroduced by moving the desktop.
   */
  const inputWindows = useCallback((): Window[] => {
    const wins: Window[] = [ownerWindow];
    const pop = popoutRef.current?.win;
    if (poppedOut && pop && !pop.closed) wins.push(pop);
    return wins;
  }, [poppedOut, ownerWindow]);

  // Background mode: report whether the window this desktop is shown in is hidden. That is the
  // pop-out while popped out (the console tab behind it may be hidden while the operator works in
  // the pop-out), the hosting window otherwise; re-bound whenever the desktop moves.
  const visibilityToken = useRef({});
  useEffect(() => {
    if (!onVisibilityChange) return;
    const pop = popoutRef.current?.win;
    const shownIn = poppedOut && pop && !pop.closed ? pop : ownerWindow;
    const token = visibilityToken.current;
    return watchVisibility(shownIn.document, (hidden) => onVisibilityChange(token, hidden));
  }, [poppedOut, ownerWindow, onVisibilityChange]);
  useEffect(() => {
    const token = visibilityToken.current;
    return () => onVisibilityChange?.(token, null);
  }, [onVisibilityChange]);

  const zoomPct = (() => {
    const info = readDims();
    return info ? displayScalePct(info.dims, view) : Math.round(view.zoom * 100);
  })();
  const pannable = (() => {
    const info = readDims();
    return info ? isPannable(info.dims, view) : false;
  })();

  const keyboardMenuOpen = toolbarMenuOpen || viewPanelOpen || inputPanelOpen || toolsPanelOpen || toolsMenuOpen;
  const anyMenuOpen = viewPanelOpen || inputPanelOpen || toolsPanelOpen || toolsMenuOpen;

  // Keep refs in sync so the Escape handler can identify the active trigger without extra deps.
  viewPanelOpenRef.current = viewPanelOpen;
  inputPanelOpenRef.current = inputPanelOpen;
  toolsPanelOpenRef.current = toolsPanelOpen;

  const openViewPanel = useCallback(() => {
    const triggerEl = viewTriggerRef.current;
    const viewerEl = viewerRef.current;
    if (!triggerEl || !viewerEl) return;
    setViewPanelPos(panelPos(triggerEl, viewerEl));
    setViewPanelOpen((o) => !o);
    setInputPanelOpen(false);
    setToolsPanelOpen(false);
    setToolsMenuOpen(false);
  }, []);

  const openInputPanel = useCallback(() => {
    const triggerEl = inputTriggerRef.current;
    const viewerEl = viewerRef.current;
    if (!triggerEl || !viewerEl) return;
    setInputPanelPos(panelPos(triggerEl, viewerEl));
    setInputPanelOpen((o) => !o);
    setViewPanelOpen(false);
    setToolsPanelOpen(false);
    setToolsMenuOpen(false);
  }, []);

  const openToolsPanel = useCallback(() => {
    const triggerEl = toolsTriggerRef.current;
    const viewerEl = viewerRef.current;
    if (!triggerEl || !viewerEl) return;
    setToolsPanelPos(panelPos(triggerEl, viewerEl));
    setToolsPanelOpen((o) => !o);
    setViewPanelOpen(false);
    setInputPanelOpen(false);
  }, []);

  useEffect(() => {
    if (!anyMenuOpen) return;
    const closeAll = () => {
      setViewPanelOpen(false);
      setInputPanelOpen(false);
      setToolsPanelOpen(false);
      setToolsMenuOpen(false);
      setRebootMenuOpen(false);
      setShutdownArmed(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        // Restore focus to whichever trigger opened the panel so keyboard navigation continues.
        const activeTrigger = viewPanelOpenRef.current ? viewTriggerRef.current
          : inputPanelOpenRef.current ? inputTriggerRef.current
          : toolsPanelOpenRef.current ? toolsTriggerRef.current
          : null;
        closeAll();
        activeTrigger?.focus();
      }
    };
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      const inPanel =
        viewPanelRef.current?.contains(target) ||
        inputPanelRef.current?.contains(target) ||
        toolsPanelRef.current?.contains(target);
      const onTrigger =
        viewTriggerRef.current?.contains(target) ||
        inputTriggerRef.current?.contains(target) ||
        toolsTriggerRef.current?.contains(target);
      if (!inPanel && !onTrigger) closeAll();
    };
    ownerDocument.addEventListener("keydown", onKey);
    ownerDocument.addEventListener("pointerdown", onPointerDown, true);
    // Also listen for Escape in the popout so the operator can dismiss the menu from there.
    const popWin = popoutRef.current?.win;
    if (poppedOut && popWin && !popWin.closed) {
      popWin.document.addEventListener("keydown", onKey);
    }
    return () => {
      ownerDocument.removeEventListener("keydown", onKey);
      ownerDocument.removeEventListener("pointerdown", onPointerDown, true);
      const pop = popoutRef.current?.win;
      if (pop) {
        try { pop.document.removeEventListener("keydown", onKey); } catch { /* closed */ }
      }
    };
  }, [anyMenuOpen, poppedOut, ownerDocument]);

  // Close all panels and reset resize-dependent positions when the window resizes.
  useEffect(() => {
    if (!anyMenuOpen) return;
    const onResize = () => {
      setViewPanelOpen(false);
      setInputPanelOpen(false);
      setToolsPanelOpen(false);
      setToolsMenuOpen(false);
      setRebootMenuOpen(false);
      setShutdownArmed(false);
    };
    ownerWindow.addEventListener("resize", onResize);
    return () => ownerWindow.removeEventListener("resize", onResize);
  }, [anyMenuOpen, ownerWindow]);

  // Keyboard is captured at the window level while input capture is on.
  //
  // When a menu is open in the main window, the effect attaches to the POPOUT ONLY — the main
  // window's keystrokes go to the menu. This ensures a menu open in the console does not also
  // disable keyboard input from an open popout window.
  useLayoutEffect(() => {
    if (!inputActive) return;
    const onKey = (down: boolean) => (e: KeyboardEvent) => {
      // Don't hijack typing into the console's OWN form fields (the command bar's input, a shell
      // picker, …). This window-level capture is for keystrokes meant for the remote desktop; a
      // keystroke landing in an editable element is the operator typing into the UI, and sending it to
      // the guest — while `preventDefault` also stops it reaching the field — would be doubly wrong.
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable)
      ) {
        return;
      }
      // Let the browser keep a couple of escape hatches so the tech can't trap themselves.
      if (e.key === "F11" || (e.ctrlKey && e.shiftKey && e.key === "Escape")) return;
      // code is a Windows virtual-key code (agent injects VIRTUAL_KEY(code)); see dom_input.
      // A release of a key we PRESSED on the guest always goes out, with the mapping it was pressed
      // with — even if this keyup is flagged as composing / 229, which would otherwise filter it and
      // leave the key (a modifier, say) held down on the guest.
      const held = down ? undefined : pressedKeysRef.current.get(e.code);
      if (held) {
        e.preventDefault();
        pressedKeysRef.current.delete(e.code);
        setLastEvent(`key ${e.code} up`);
        transport?.send(ChannelId.Input, encodeInput(keyEvent(held, false)));
        return;
      }
      // A key pressed while focus is on one of the trackpad's own controls belongs to that control
      // (Space/Enter operate [Left], Tab moves focus on). Forwarding it would type a space on the guest
      // and, because it is preventDefault-ed below, trap Tab so keyboard focus could never leave the
      // control (a Space-held [Left] could then never be released by tabbing away).
      if (target?.closest?.("[data-trackpad-ui]")) return;
      // `null` = an IME placeholder (keyCode 229) or an unmapped key: nothing real to inject.
      const info = { code: e.code, keyCode: e.keyCode };
      const ev = liveKeyEvent({ ...info, isComposing: e.isComposing }, down);
      if (!ev) return;
      e.preventDefault();
      if (down) {
        pressedKeysRef.current.set(e.code, info);
        resetTyping(false);
      }
      setLastEvent(`key ${e.code} ${down ? "down" : "up"}`);
      transport?.send(ChannelId.Input, encodeInput(ev));
    };
    const kd = onKey(true);
    const ku = onKey(false);
    // When the menu is open in the main window, attach only to the popout (if any) so popout
    // typing still reaches the remote while the main window's keyboard feeds the menu.
    const wins = keyboardMenuOpen
      ? inputWindows().filter((w) => w !== ownerWindow)
      : inputWindows();
    for (const w of wins) {
      w.addEventListener("keydown", kd);
      w.addEventListener("keyup", ku);
    }
    return () => {
      // Flush any keys still held on the remote before we stop listening. Without this, a modifier
      // held on open → menu click → modifier release (in menu) never delivers a keyup.
      const held = pressedKeysRef.current;
      for (const [code, info] of held) {
        transport?.send(ChannelId.Input, encodeInput(keyEvent(info, false)));
        setLastEvent(`key ${code} up`);
      }
      held.clear();
      for (const w of wins) {
        // A pop-out the operator closed is already gone by the time this cleanup runs, and touching
        // a closed window can throw. Detaching from the others still has to happen, so this cannot
        // be one unguarded loop.
        try {
          w.removeEventListener("keydown", kd);
          w.removeEventListener("keyup", ku);
        } catch {
          /* window already closed */
        }
      }
    };
  }, [inputActive, keyboardMenuOpen, transport, inputWindows, resetTyping]);

  // Deliver every button-UP at the WINDOW level (not the surface), and end any pan drag. A release
  // over the letterbox or outside the surface must still reach the remote — otherwise a button pressed
  // during a drag-to-the-edge would stay stuck down on the customer's machine.
  useEffect(() => {
    const onUp = (e: MouseEvent) => {
      dragRef.current = null;
      // Releases only the "mouse" owner's press, so a compatibility mouseup after a touch tap cannot
      // release Hold or a touch drag. But when a PHYSICAL button is held and a touch then taps, that
      // echo would release the recorded mouse owner: so a mouseup the browser positively says a touch
      // generated is ignored. Unknown capabilities still release (a stuck button is worse than an
      // early-ended drag); see isTouchEchoMouseUp.
      if (isTouchEchoMouseUp((e as unknown as { sourceCapabilities?: { firesTouchEvents?: boolean } }).sourceCapabilities?.firesTouchEvents)) return;
      releaseButton(e.button, "mouse", `btn ${e.button} up`);
    };
    const wins = inputWindows();
    for (const w of wins) w.addEventListener("mouseup", onUp);
    return () => {
      for (const w of wins) {
        try {
          w.removeEventListener("mouseup", onUp);
        } catch {
          /* window already closed */
        }
      }
    };
  }, [releaseButton, inputWindows]);

  // Safety net: if capture is turned off or pan mode is entered while a button is held, release it so
  // nothing sticks (the physical mouseup would otherwise be the only release, and it may never come
  // through this surface once the state changed).
  useEffect(() => {
    if (pointerToRemote) return;
    releaseEverything("capture off: release button");
  }, [pointerToRemote, releaseEverything]);

  // Attach the wheel handler as a NON-PASSIVE native listener (see wheelHandlerRef above for why the
  // React onWheel prop cannot be used). The listener is stable and dispatches through the ref, so it
  // never needs re-subscribing as the view changes.
  useEffect(() => {
    const el = surfaceRef.current;
    if (!el) return;
    const listener = (e: WheelEvent) => wheelHandlerRef.current(e);
    el.addEventListener("wheel", listener, { passive: false });
    return () => el.removeEventListener("wheel", listener);
  }, [elEpoch]);

  const status = useMemo(() => STATUS_META[connectionState], [connectionState]);

  const onMonitorChange = useCallback(
    (id: number) => {
      releaseEverything("monitor change: release button");
      padEvent({ type: "release" });
      gestureRef.current = INITIAL_GESTURE_STATE;
      if (longPressTimer.current !== null) clearTimeout(longPressTimer.current);
      longPressTimer.current = null;
      setActiveMonitor(id);
      // A different monitor is a different desktop (size/aspect); reset to fit so no stale zoom/pan
      // carries over while the new stream loads. If the operator chose 1:1, the snap effect below
      // will re-apply it once real content dimensions arrive.
      setView(IDENTITY_VIEW);
      const cs = contentSizeRef.current;
      const ml = monitorListRef.current;
      // Use the TARGET monitor's ADVERTISED dims to classify this switch. el.videoWidth at switch
      // time still reflects the OLD monitor's stream — comparing it to contentSize (which was also
      // derived from the old stream) is always true and cannot identify a different-resolution target.
      // COMPOSITE_MONITOR_ID and monitors with unknown dims (width=0) are treated as different-res.
      const target = id !== COMPOSITE_MONITOR_ID ? ml.find((m) => m.id === id) : undefined;
      const sameRes = target !== undefined && target.width > 0
        && target.width === cs.w && target.height === cs.h;
      if (!sameRes && !monitorCanvas) {
        setContentSize({ w: 0, h: 0 }); // clear stale dims; snap effect waits for new dims
      }
      pendingActualSnapRef.current = scalePrefRef.current === "actual"; // always assign, never just set true
      setMonitorSwitchSeq((s) => s + 1); // triggers snap even when contentSize is unchanged (same-res)
      setPanning(false);
      // In canvas mode the crop is local — NEVER send SelectMonitor to the agent.
      if (!monitorCanvas) onSelectMonitor?.(id);
    },
    [onSelectMonitor, monitorCanvas, sendEvent, padEvent, releaseEverything],
  );

  // The settings the controls display. Sourced from the agent's last `QualityApplied` rather than
  // from local state ON PURPOSE: a control that snaps back to what the agent actually applied is the
  // only way the operator learns that an ask was clamped or policy-capped. Optimistic local state
  // would show them a setting that is not in force.
  const activeQuality = quality ?? DEFAULT_QUALITY;
  const qualityControls = qualityControlState(qualitySupported);
  const reasonBase = useId();
  const rid = (key: string) => `${reasonBase}-${key}`;
  const reasons = controlReasons({
    audioAvailable, qualityDisabled: qualityControls.disabled, pannable, viewOnlyEnforced: !!viewOnlyEnforced,
    typingEnabled, viewOnly: !!viewOnly, panning, recordingLocked: !!(recordingRequired && recording),
  });
  const statsTone = qualityTone(qualityStats);

  // Clamp on the way out so the request we send is one the agent can accept whole. Its own clamp is
  // the authoritative one (see lib/quality.ts) — this is about the UI and the wire agreeing.
  const commitQuality = useCallback(
    (next: QualitySettings) => {
      onSetQuality?.(clampQuality(next));
    },
    [onSetQuality],
  );

  const onPresetChange = useCallback(
    (id: string) => {
      // "custom" is a readout of the current state, not a destination — selecting it would have no
      // settings to apply, so it is ignored rather than mapped to some arbitrary preset.
      if (id === "custom") return;
      commitQuality(qualityFromPreset(id as QualityPresetId));
    },
    [commitQuality],
  );

  // Each advanced control is a read-modify-write against the settings in force: the wire has no
  // partial update (see control.ts), so one knob moving still sends all five fields.
  const onQualityField = useCallback(
    (patch: Partial<QualitySettings>) => {
      commitQuality({ ...activeQuality, ...patch });
    },
    [commitQuality, activeQuality],
  );

  return (
    <div className={`viewer${mobileFs ? " viewer--mobilefs" : ""}`} ref={viewerRef}>
      {/* One-click monitor switching in the collapsed session tab (main window only; fullscreen and
          pop-outs keep the inline bar, which carries the full Monitor select). */}
      {tabHost && !hostWindow && !isFullscreen && (
        <ToolbarDock target={tabHost}>
          {/* Connection state stays visible while the bar is collapsed. */}
          <span className="session-tab__dot" data-tone={status.tone} title={status.label} aria-label={status.label}
            role="status" data-testid="session-tab-status" />
          {/* Facts the technician must not lose behind the collapsed bar. */}
          {recording && (
            <span className="session-tab__badge session-tab__badge--rec" role="status" data-testid="session-tab-recording"
              title={recordingRequired ? "Recording required by policy" : "Recording"}>⏺ REC</span>
          )}
          {panning && (
            <span className="session-tab__badge" role="status" data-testid="session-tab-pan"
              title="Pan mode: clicks are not sent to the remote">✋ Pan</span>
          )}
          {tabMonitorButtons(viewerMonitorOptions(monitorList), activeMonitor, COMPOSITE_MONITOR_ID).map((b) => (
            <button
              key={b.value}
              type="button"
              className={`session-tab__monitor${b.active ? " session-tab__monitor--on" : ""}`}
              aria-pressed={b.active}
              aria-label={`Show ${b.title}`}
              title={b.title}
              disabled={pinnedMonitorId !== undefined && !monitorCanvas}
              onClick={() => onMonitorChange(b.value)}
              data-testid={`session-tab-monitor-${b.text}`}
            >
              {b.text}
            </button>
          ))}
          {/* Full screen is one click from the tab, not behind ▾ (Ed, 10-29: "i do not see an option
              to make it full screen"). In full screen the inline bar carries Exit; Esc also leaves. */}
          <button
            type="button"
            className="session-tab__fullscreen"
            aria-label="Full screen"
            title="Full screen (Esc to leave)"
            onClick={toggleFullscreen}
            data-testid="session-tab-fullscreen"
          >
            ⤢
          </button>
        </ToolbarDock>
      )}
      {mobileFs && (() => {
        // Same stop-the-touch rules as the trackpad's own controls: nothing here reaches the surface
        // handlers, and a button never takes focus from the typing field (so the phone keyboard stays up).
        const stop = (e: React.SyntheticEvent) => e.stopPropagation();
        const noteTouch = (e: React.PointerEvent) => {
          if (e.pointerType !== "mouse") lastTouchAtRef.current = performance.now();
        };
        const ui = {
          "data-trackpad-ui": "",
          onTouchStart: stop,
          onTouchMove: stop,
          onTouchEnd: stop,
          onTouchCancel: stop,
          onMouseMove: stop,
          onMouseDown: (e: React.MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
          },
          onPointerDownCapture: noteTouch,
          onPointerUpCapture: noteTouch,
          onContextMenu: (e: React.MouseEvent) => e.preventDefault(),
        };
        return (
          <div className="viewer__mfsbar" role="toolbar" aria-label="Full screen controls" data-testid="viewer-mfs-bar" {...ui}>
            {/* The safety facts the session tab keeps visible when collapsed stay visible here too. */}
            <span className="session-tab__dot" data-tone={status.tone} title={status.label} aria-label={status.label}
              role="status" data-testid="viewer-mfs-status" />
            {recording && (
              <span className="session-tab__badge session-tab__badge--rec" role="status" data-testid="viewer-mfs-recording"
                title={recordingRequired ? "Recording required by policy" : "Recording"}>⏺ REC</span>
            )}
            {/* Pan has no other switch in this mode, and while it is on Keyboard and the trackpad are
                dead, so the badge itself turns it off (deployment review, 11-06). */}
            {panning && (
              <button type="button" className="session-tab__badge viewer__mfspan" data-testid="viewer-mfs-pan"
                aria-label="Pan mode is on: clicks are not sent. Tap to turn Pan off"
                title="Pan mode: clicks are not sent to the remote. Tap to turn Pan off"
                onClick={() => setPanning(false)}>✋ Pan ✕</button>
            )}
            {/* The statusbar is hidden in this mode, so say WHY Keyboard is dead and the trackpad shows no
                cursor: touch has no tooltips (review, 11-06). */}
            {!typingEnabled && (
              <span className="session-tab__badge" role="status" data-testid="viewer-mfs-inputoff"
                title="Typing and pointer input are not being sent">{viewOnly ? "👁 View only" : "Input paused"}</span>
            )}
            {tabMonitorButtons(viewerMonitorOptions(monitorList), activeMonitor, COMPOSITE_MONITOR_ID).map((b) => (
              <button
                key={b.value}
                type="button"
                className={`viewer__mfsbtn${b.active ? " viewer__mfsbtn--on" : ""}`}
                aria-pressed={b.active}
                aria-label={`Show ${b.title}`}
                title={b.title}
                disabled={pinnedMonitorId !== undefined && !monitorCanvas}
                onClick={() => onMonitorChange(b.value)}
                data-testid={`viewer-mfs-monitor-${b.text}`}
              >
                {b.text}
              </button>
            ))}
            <button
              type="button"
              className={`viewer__mfsbtn${trackpadOn ? " viewer__mfsbtn--on" : ""}`}
              data-testid="viewer-mfs-trackpad"
              aria-pressed={trackpadOn}
              aria-label={`Trackpad ${trackpadOn ? "on" : "off"}`}
              title={trackpadOn ? "Trackpad mode is on. Tap to return to direct touch." : "Use the screen like a laptop trackpad"}
              onClick={() => setTrackpad(!trackpadOn)}
            >
              🖱<span className="viewer__mfslbl"> Trackpad {trackpadOn ? "on" : "off"}</span>
            </button>
            <button
              type="button"
              className={`viewer__mfsbtn${showTyping ? " viewer__mfsbtn--on" : ""}`}
              data-testid="viewer-mfs-keyboard"
              aria-expanded={showTyping}
              aria-label="Keyboard"
              disabled={!typingEnabled}
              title={typingEnabled ? "Type with this device's own keyboard" : "Typing is unavailable (view-only, Pan or input capture off)"}
              // Focus must happen INSIDE the tap or Android will not raise its keyboard (see openTyping).
              onClick={openTyping}
            >
              ⌨<span className="viewer__mfslbl"> Keyboard</span>
            </button>
            <button
              type="button"
              className="viewer__mfsbtn"
              aria-label="Exit full screen"
              title="Exit full screen"
              data-testid="viewer-mfs-exit"
              onClick={toggleFullscreen}
            >
              ⤡
            </button>
          </div>
        );
      })()}
      <ToolbarDock target={!isFullscreen ? toolbarHost : null} inline={!!hostWindow || !toolbarHost}>
      <div className="viewer__statusbar">
        <span className="viewer__status" data-tone={status.tone}>
          <span className="viewer__dot" />
          {status.label}
        </span>
        <span
          className="viewer__machine"
          title={machineDisplayTitle(machineName, machineAlias)}
          data-testid="viewer-machine-label"
        >
          {machineDisplayLabel(machineName, machineAlias)}
        </span>

        <label className="viewer__monitor">
          <span className="viewer__lbl">Monitor</span>
          <select
            data-testid="viewer-monitor"
            value={activeMonitor}
            disabled={pinnedMonitorId !== undefined && !monitorCanvas}
            onChange={(e) => onMonitorChange(Number(e.target.value))}
          >
            {viewerMonitorOptions(monitorList).map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          {pinnedMonitorId !== undefined && !monitorCanvas && (
            <span
              className="viewer__monitor-pinned"
              data-testid="viewer-monitor-pinned"
              title="Multi-session mode: monitor selection is fixed for the lifetime of this helper. Dynamic switching is not yet supported."
            >
              Pinned to display {pinnedMonitorId}
            </span>
          )}
        </label>

        <span className="viewer__sep" aria-hidden="true" />

        <button
          ref={viewTriggerRef}
          type="button"
          className={`viewer__zoombtn${viewPanelOpen ? " viewer__zoombtn--on" : ""}`}
          data-testid="viewer-view-menu"
          aria-expanded={viewPanelOpen}
          aria-haspopup="dialog"
          onClick={openViewPanel}
          title="Audio, video quality, and advanced quality settings"
        >
          View ▾
        </button>

        <button
          ref={inputTriggerRef}
          type="button"
          className={`viewer__zoombtn${inputPanelOpen ? " viewer__zoombtn--on" : ""}`}
          data-testid="viewer-input-menu"
          aria-expanded={inputPanelOpen}
          aria-haspopup="dialog"
          onClick={openInputPanel}
          title="Input capture, guest input controls, and special key bar"
        >
          Input ▾
        </button>

        <button
          ref={toolsTriggerRef}
          type="button"
          className={`viewer__zoombtn${toolsPanelOpen ? " viewer__zoombtn--on" : ""}`}
          data-testid="viewer-tools-menu"
          aria-expanded={toolsPanelOpen}
          aria-haspopup="dialog"
          onClick={openToolsPanel}
          title="Screenshot, note, command, files, system tools, and guest power options"
        >
          Tools ▾
        </button>

        {/* The last input event: a diagnostic the input e2e reads. Always mounted (the "More" menu that held it
            is gone, and the View panel is drawn only while open), never shown. */}
        <span className="viewer__lastevent" data-testid="viewer-last-event" title="last input event" hidden>{lastEvent || "—"}</span>
        {/* A monitor window's own controls (its clipboard) stay in its row; in the main window the extra
            controls are the "open one window per monitor" buttons, which belong with View. */}
        {hostWindow && additionalControls}
        <span className="viewer__spacer" />
        {sessionPolicyBanner(sessionPolicy) && (
          <span className="viewer__policynote" role="status" data-testid="viewer-policy-note">
            {sessionPolicyBanner(sessionPolicy)}
          </span>
        )}
        {rebootStatus && (
          <span className="viewer__reboot-status" data-testid="viewer-reboot-status">
            {rebootStatus}
          </span>
        )}
        {lockStatus && (
          <span className="viewer__lock-status" data-testid="viewer-lock-status">
            {lockStatus}
          </span>
        )}
        {logoffStatus && (
          <span className="viewer__logoff-status" data-testid="viewer-logoff-status">
            {logoffStatus}
          </span>
        )}
        {shutdownStatus && (
          <span className="viewer__shutdown-status" data-testid="viewer-shutdown-status">
            {shutdownStatus}
          </span>
        )}
        {toolStatus && (
          <span className="viewer__reboot-status" data-testid="viewer-tool-status">
            {toolStatus}
          </span>
        )}
        {endSessionStatus && (
          <span className="viewer__reboot-status" data-testid="viewer-endsession-status" role="status">
            {endSessionStatus}
          </span>
        )}
        {noteSavedMsg && (
          <span className="viewer__reboot-status" data-testid="viewer-note-saved" role="status">
            {noteSavedMsg}
          </span>
        )}
        {screenshotStatus && (
          <span className="viewer__reboot-status" data-testid="viewer-screenshot-status">
            {screenshotStatus}
          </span>
        )}
        {inputBlocked && (
          <span className="viewer__reboot-status" role="status">
            🚫 Guest input blocked
          </span>
        )}
        {monitorBlanked && (
          <span className="viewer__reboot-status" role="status">
            ⬛ Screen blanked
          </span>
        )}
        {panning && (
          <span
            className="viewer__inputpaused"
            data-testid="viewer-pan-active"
            title="Dragging pans the view; clicks are not sent to the remote. Turn off Pan to control the machine."
          >
            pan mode — input not sent
          </span>
        )}
        {popoutError && (
          <span className="viewer__inputpaused" role="alert" data-testid="viewer-popout-error">
            {popoutError}
          </span>
        )}

        <ToolbarDock target={!isFullscreen ? toolbarEndHost : null} inline={!!hostWindow || !toolbarHost}>
          {recording && <span className="viewer__recording-indicator" data-testid="viewer-recording-indicator" role="status" title={recordingRequired ? "Recording required by policy" : "Recording"}>⏺<span className="viewer__lbl"> Recording{recordingRequired ? " (required)" : ""}</span></span>}
          <button className="viewer__disconnect" onClick={onDisconnect}>{disconnectLabel}</button>
        </ToolbarDock>
      </div>
      </ToolbarDock>

      {viewPanelOpen && (
        <div
          ref={viewPanelRef}
          className="viewer__menupanel"
          style={{ top: viewPanelPos.top, bottom: viewPanelPos.bottom, left: viewPanelPos.left, maxHeight: viewPanelPos.maxHeight, maxWidth: viewPanelPos.maxWidth }}
          role="dialog"
          aria-label="View settings"
        >
          <button
            type="button"
            className="viewer__audio"
            data-testid="viewer-audio"
            onClick={() => setAudioOn((on) => !on)}
            disabled={!audioAvailable}
            aria-pressed={audioOn}
            aria-describedby={reasons.audio ? rid("audio") : undefined}
            title={audioToggleTitle(audioAvailable, audioOn)}
          >
            {audioAvailable && audioOn ? "\u{1F50A} Sound on" : "\u{1F507} Sound off"}
          </button>
          <ControlReason id={rid("audio")} testId="viewer-audio-reason" text={reasons.audio} />

          <label className="viewer__quality viewer__menupanel-field" title={qualityControls.title}>
            <span className="viewer__menupanel-label">Quality</span>
            <select
              data-testid="viewer-quality"
              value={presetIdFor(activeQuality)}
              disabled={qualityControls.disabled}
              aria-describedby={reasons.quality ? rid("quality") : undefined}
              onChange={(e) => onPresetChange(e.target.value)}
            >
              {viewerQualityOptions(activeQuality).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <span
            className="viewer__quality-readout"
            data-testid="viewer-quality-readout"
            data-tone={statsTone}
            title={
              qualityControls.disabled
                ? qualityControls.title
                : "Live encoder telemetry: encoded size, encoder output bitrate, RFC 3550 fraction lost and RTT"
            }
          >
            {qualityControls.disabled
              ? "telemetry unsupported"
              : formatQualityReadout(qualityStats, activeQuality.fps)}
          </span>

          <ControlReason id={rid("quality")} testId="viewer-quality-reason" text={reasons.quality} />

          <button
            className="viewer__quality-advanced"
            data-testid="viewer-quality-advanced"
            type="button"
            aria-expanded={showAdvancedQuality}
            disabled={qualityControls.disabled}
            title={
              qualityControls.disabled
                ? qualityControls.title
                : "Show the individual resolution / frame rate / colour / bitrate controls"
            }
            onClick={() => setShowAdvancedQuality((v) => !v)}
          >
            {showAdvancedQuality ? "Advanced ▲" : "Advanced ▼"}
          </button>

          {showAdvancedQuality && !qualityControls.disabled && (
            <div
              className="viewer__qualitypanel viewer__qualitypanel--inline"
              data-testid="viewer-quality-panel"
              role="group"
              aria-label="Advanced quality"
            >
              <label className="viewer__qualityfield">
                Resolution
                <select
                  data-testid="quality-scale"
                  value={activeQuality.scale_div}
                  onChange={(e) => onQualityField({ scale_div: Number(e.target.value) })}
                >
                  {SCALE_CHOICES.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="viewer__qualityfield">
                Frame rate
                <select
                  data-testid="quality-fps"
                  value={activeQuality.fps}
                  onChange={(e) => onQualityField({ fps: Number(e.target.value) })}
                >
                  {FPS_CHOICES.map((f) => (
                    <option key={f} value={f}>
                      {f} fps
                    </option>
                  ))}
                </select>
              </label>

              <label className="viewer__qualityfield">
                Colour
                <select
                  data-testid="quality-color"
                  value={activeQuality.color}
                  onChange={(e) => onQualityField({ color: e.target.value as ColorMode })}
                >
                  {COLOR_CHOICES.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="viewer__qualityfield">
                Bitrate cap
                <select
                  data-testid="quality-kbps"
                  value={Math.round(activeQuality.max_bitrate_bps / 1000)}
                  onChange={(e) => onQualityField({ max_bitrate_bps: Number(e.target.value) * 1000 })}
                >
                  {bitrateChoicesKbps(activeQuality.max_bitrate_bps).map((k) => (
                    <option key={k} value={k}>
                      {k >= 1000 ? `${k / 1000} Mbps` : `${k} kbps`}
                    </option>
                  ))}
                </select>
              </label>

              <label className="viewer__qualityfield viewer__qualityfield--check">
                <input
                  type="checkbox"
                  data-testid="quality-auto"
                  checked={activeQuality.adaptive}
                  onChange={(e) => onQualityField({ adaptive: e.target.checked })}
                />
                Adapt to loss
              </label>

              <span className="viewer__qualityhint">
                The cap is a ceiling; with "Adapt to loss" on, the agent may encode below it.
              </span>
            </div>
          )}
          {/* Menu redesign wave 7b: zoom, pan, full screen, pop out and monitor windows (were under "More"). */}
          <MenuSection title="Size and window" testId="viewer-view-window">
          <span className="viewer__zoom" role="group" aria-label="Zoom">
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-zoom-out"
              onClick={zoomOut}
              title="Zoom out"
              aria-label="Zoom out"
            >
              −
            </button>
            <span className="viewer__zoomreadout" data-testid="viewer-zoom-readout" title="On-screen size relative to the remote desktop's native pixels (100% = actual size)">
              {zoomPct}%
            </span>
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-zoom-in"
              onClick={zoomIn}
              title="Zoom in"
              aria-label="Zoom in"
            >
              +
            </button>
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-zoom-fit"
              onClick={zoomFit}
              title="Scale the whole desktop to fit the window"
            >
              Fit
            </button>
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-zoom-actual"
              onClick={zoomActual}
              title="Show the desktop at 1:1 native pixels"
            >
              1:1
            </button>
            <button
              type="button"
              className={`viewer__zoombtn${panning ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-pan"
              aria-pressed={panning}
              disabled={!pannable}
              aria-describedby={reasons.pan ? rid("pan") : undefined}
              onClick={() => { if (!panning) setViewPanelOpen(false); setPanning((v) => !v); }}
              title={
                pannable
                  ? "Pan mode: drag to move the view (pointer input is NOT sent to the remote while on)"
                  : "Zoom in first — the whole desktop is already visible"
              }
            >
              ✋<span className="viewer__lbl"> Pan</span>
            </button>
            <button
              type="button"
              className={`viewer__zoombtn${isFullscreen ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-fullscreen"
              aria-pressed={isFullscreen}
              onClick={toggleFullscreen}
              title={
                isFullscreen
                  ? "Exit full screen"
                  : "Full screen — fills the display (good for phone/tablet)"
              }
            >
              ⤢<span className="viewer__lbl">{isFullscreen ? " Exit" : " Full screen"}</span>
            </button>
            {!poppedOut && !disablePopout && (
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="viewer-popout"
                onClick={() => { setViewPanelOpen(false); void popOut(); }}
                title="Open the remote desktop in its own window — drag it to a second monitor and keep the console on this one"
              >
                ⧉<span className="viewer__lbl"> Pop out</span>
              </button>
            )}
          </span>

          <ControlReason id={rid("pan")} testId="viewer-pan-reason" text={reasons.pan} />
          {!hostWindow && additionalControls}
          </MenuSection>
        </div>
      )}

      {inputPanelOpen && (
        <div
          ref={inputPanelRef}
          className="viewer__menupanel"
          style={{ top: inputPanelPos.top, bottom: inputPanelPos.bottom, left: inputPanelPos.left, maxHeight: inputPanelPos.maxHeight, maxWidth: inputPanelPos.maxWidth }}
          role="dialog"
          aria-label="Input settings"
        >
          {inputPanelExtras}
          <TypeClipboard enabled={typingEnabled} send={(events) => typeClipboardSend.current(events)} />
          <label className="viewer__toggle viewer__menupanel-field">
            <input
              type="checkbox"
              data-testid="viewer-capture-input"
              checked={captureInput}
              onChange={(e) => setCaptureInput(e.target.checked)}
            />
            <span className="viewer__menupanel-label">Capture input</span>
          </label>

          {onToggleInputBlock && (
            <button
              type="button"
              className={`viewer__zoombtn${inputBlocked ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-block-input"
              aria-pressed={inputBlocked}
              onClick={() => onToggleInputBlock(!inputBlocked)}
              title={
                inputBlocked
                  ? "The guest's keyboard & mouse are blocked — click to release"
                  : "Block the guest's own keyboard & mouse (your input still works)"
              }
            >
              {inputBlocked ? "🚫 Guest input blocked" : "Block guest input"}
            </button>
          )}

          {onToggleMonitorBlank && (
            <button
              type="button"
              className={`viewer__zoombtn${monitorBlanked ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-blank-monitor"
              aria-pressed={monitorBlanked}
              onClick={() => onToggleMonitorBlank(!monitorBlanked)}
              title={
                monitorBlanked
                  ? "Guest's screen is blanked — click to restore"
                  : "Blank the guest's screen (bystanders cannot see what you are doing)"
              }
            >
              {monitorBlanked ? "⬛ Screen blanked" : "Blank guest screen"}
            </button>
          )}

          {onToggleViewOnly && (
            <button
              type="button"
              className={`viewer__zoombtn${viewOnly ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-view-only"
              aria-pressed={viewOnly}
              disabled={viewOnlyEnforced}
              aria-describedby={reasons.viewOnly ? rid("viewonly") : undefined}
              onClick={() => onToggleViewOnly(!viewOnly)}
              title={
                viewOnlyEnforced
                  ? "View-only is required for this machine group by your organisation's session policy — the agent enforces it and it cannot be turned off here"
                  : viewOnly
                    ? "View-only: the agent is dropping your input — click to resume control"
                    : "View only: watch without controlling (the agent refuses your keyboard/mouse)"
              }
            >
              {viewOnlyEnforced ? "🔒 View only (policy)" : viewOnly ? "👁 View only" : "View only"}
            </button>
          )}
          {onToggleViewOnly && <ControlReason id={rid("viewonly")} testId="viewer-view-only-reason" text={reasons.viewOnly} />}

          <button
            type="button"
            className={`viewer__zoombtn${trackpadOn ? " viewer__zoombtn--on" : ""}`}
            data-testid="viewer-trackpad-toggle"
            aria-pressed={trackpadOn}
            onClick={() => {
              setTrackpad(!trackpadOn);
              // Turning it on: get the menu out of the way so the cursor and controls are usable.
              if (!trackpadOn) setInputPanelOpen(false);
            }}
            title={
              trackpadOn
                ? "Trackpad mode is on: drag moves a cursor, tap clicks at the cursor. Click to return to direct touch."
                : "Use the screen like a laptop trackpad: a visible cursor, relative movement, Left/Right/Hold buttons and a scroll strip"
            }
          >
            {trackpadOn ? "🖱 Trackpad mode ✓" : "🖱 Trackpad mode"}
          </button>
          {trackpadOn && (
            <span className="viewer__tpsens" role="group" aria-label="Trackpad sensitivity">
              {SENSITIVITIES.map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`viewer__zoombtn${tp.sensitivity === v ? " viewer__zoombtn--on" : ""}`}
                  data-testid={`viewer-trackpad-sens-${v}`}
                  aria-pressed={tp.sensitivity === v}
                  title={`Cursor speed: ${v}`}
                  onClick={() => setSensitivity(v)}
                >
                  {v === "low" ? "Slow" : v === "normal" ? "Normal" : "Fast"}
                </button>
              ))}
            </span>
          )}

          <span className="viewer__menusep" aria-hidden="true" />

          <button
            type="button"
            className={`viewer__zoombtn${showKeys ? " viewer__zoombtn--on" : ""}`}
            data-testid="viewer-special-keys-toggle"
            aria-pressed={showKeys}
            onClick={() => setShowKeys((v) => !v)}
            title="Show the special-key bar (Ctrl+Alt+Del, function keys, …)"
          >
            Special keys {showKeys ? "▲" : "▼"}
          </button>

          <button
            type="button"
            className={`viewer__zoombtn${showTyping ? " viewer__zoombtn--on" : ""}`}
            data-testid="viewer-typing-toggle"
            aria-expanded={showTyping}
            disabled={!typingEnabled}
            aria-describedby={reasons.typing ? rid("typing") : undefined}
            title={
              typingEnabled
                ? "Type with this device's own keyboard, with a row of special keys above it"
                : viewOnly
                  ? "This session is view-only"
                  : panning
                    ? "Turn off Pan to send input"
                    : "Enable 'Capture input' to send keys"
            }
            onMouseDown={(e) => e.preventDefault()}
            // Opens the field and focuses it INSIDE this tap, which is what makes a phone raise its
            // own keyboard (see openTyping).
            onClick={openTyping}
          >
            {showTyping ? "⌨ Keyboard ▲" : "⌨ Keyboard ▼"}
          </button>
          <ControlReason id={rid("typing")} testId="viewer-typing-reason" text={reasons.typing} />
        </div>
      )}

      {toolsPanelOpen && (
        <div
          ref={toolsPanelRef}
          className="viewer__menupanel"
          style={{ top: toolsPanelPos.top, bottom: toolsPanelPos.bottom, left: toolsPanelPos.left, maxHeight: toolsPanelPos.maxHeight, maxWidth: toolsPanelPos.maxWidth }}
          role="dialog"
          aria-label="Tools"
        >
          {/* Menu redesign wave 7b: recording (was under "More"). */}
          <MenuSection title="Recording" testId="viewer-tools-recording">
          {onToggleRecording && (
            <span className="viewer__record" role="group" aria-label="Session recording">
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="viewer-record"
                aria-pressed={recording}
                disabled={recordingPending || (recordingRequired && recording)}
                aria-describedby={reasons.record ? rid("record") : undefined}
                onClick={onToggleRecording}
                title={
                  recordingRequired && recording
                    ? "Recording is required by group policy and cannot be stopped"
                    : recording
                      ? "Stop recording and finalize the file"
                      : "Record this session to a file on the GUEST's machine. The guest's window says so while it runs. Nothing is uploaded unless your organization has turned on central recording storage; then the finished file is sent to the server after the session."
                }
              >
                ⏺<span className="viewer__lbl">{recordingRequired && recording ? " Recording (Required)" : recording ? " Stop recording" : " Record"}</span>
              </button>
              <ControlReason id={rid("record")} testId="viewer-record-reason" text={reasons.record} />
              {recording && (
                <span className="viewer__reboot-status" data-testid="viewer-record-live">
                  Recording — the guest is being told
                </span>
              )}
              {!recording && recordingResult && (
                <span className="viewer__reboot-status" data-testid="viewer-record-result">
                  {recordingSummary(recordingResult)}
                </span>
              )}
            </span>
          )}
          </MenuSection>
          <MenuSection title="Tools" testId="viewer-tools-actions">
          {onScreenshot && (
            <span className="viewer__shot" role="group" aria-label="Screenshot">
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="viewer-screenshot"
                onClick={() => { setToolsPanelOpen(false); onScreenshot(); }}
                title="Save a full-resolution lossless screenshot of the current view"
              >
                📷<span className="viewer__lbl"> Screenshot</span>
              </button>
            </span>
          )}

          {onSaveNote && (
            <button
              type="button"
              className={`viewer__zoombtn${noteOpen ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-note-toggle"
              aria-expanded={noteOpen}
              onClick={() => { setNoteOpen((o) => !o); setToolsPanelOpen(false); }}
              title="Add a note to this session record"
            >
              📝<span className="viewer__lbl"> Note</span>
            </button>
          )}

          {onRunCommand && (
            <button
              type="button"
              className={`viewer__zoombtn${commandOpen ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-command-toggle"
              aria-expanded={commandOpen}
              onClick={() => { setCommandOpen((o) => !o); setToolsPanelOpen(false); }}
              title="Run a one-line command on the guest and capture its output"
            >
              ⌨<span className="viewer__lbl"> Command</span>
            </button>
          )}

          {onBrowseDir && (
            <button
              type="button"
              className={`viewer__zoombtn${filesOpen ? " viewer__zoombtn--on" : ""}`}
              data-testid="viewer-files-toggle"
              aria-expanded={filesOpen}
              onClick={() => { setFilesOpen((o) => !o); setToolsPanelOpen(false); }}
              title="Browse the guest's files"
            >
              🗂<span className="viewer__lbl"> Files</span>
            </button>
          )}

          {onLaunchTool && (
            <span className="viewer__tools" role="group" aria-label="Windows desktop tools">
              <button
                type="button"
                className={`viewer__zoombtn${toolsMenuOpen ? " viewer__zoombtn--on" : ""}`}
                data-testid="viewer-tools"
                aria-expanded={toolsMenuOpen}
                onClick={() => setToolsMenuOpen((o) => !o)}
                title="Open a system tool on the guest (Task Manager, Registry Editor, …)"
              >
                🛠<span className="viewer__lbl"> Windows desktop tools ▾</span>
              </button>
              {toolsMenuOpen && (
                <span className="viewer__tools-menu" role="menu">
                  {SYSTEM_TOOLS.map((t) => (
                    <button
                      key={t.key}
                      type="button"
                      role="menuitem"
                      className="viewer__zoombtn"
                      data-testid={`viewer-tool-${t.key}`}
                      onClick={() => {
                        setToolsMenuOpen(false);
                        setToolsPanelOpen(false);
                        onLaunchTool(t.key);
                      }}
                      title={`Launch ${t.label} on the guest desktop`}
                    >
                      {t.label}
                    </button>
                  ))}
                </span>
              )}
            </span>
          )}

          </MenuSection>

          {/* An observer gets none of these controls: no empty "Power" box for them. */}
          {((onLock && !lockStatus) || (onLogOff && !logoffStatus) || (onReboot && !rebootStatus) || (onShutDown && !shutdownStatus)) && (
          <fieldset className="viewer__power" data-testid="viewer-power"><legend>Power and user session</legend>
          {onLock && !lockStatus && (
            <span className="viewer__lock" role="group" aria-label="Lock guest">
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="viewer-lock"
                onClick={() => { setToolsPanelOpen(false); onLock(); }}
                title="Lock the guest workstation (returns it to the sign-in screen)"
              >
                🔒<span className="viewer__lbl"> Lock</span>
              </button>
            </span>
          )}

          {onLogOff && !logoffStatus && (
            <span className="viewer__logoff" role="group" aria-label="Log off guest">
              {logoffArmed ? (
                <>
                  <span className="viewer__reboot-label" data-testid="viewer-logoff-question">
                    Log off the signed-in user{machineName ? ` on ${machineAlias || machineName}` : ""}? Their open apps
                    close and unsaved work is lost.
                  </span>
                  <button
                    type="button"
                    className="viewer__zoombtn viewer__zoombtn--danger"
                    data-testid="viewer-logoff-confirm"
                    onClick={() => { setLogoffArmed(false); setToolsPanelOpen(false); onLogOff(); }}
                  >
                    Confirm log off
                  </button>
                  <button
                    type="button"
                    className="viewer__zoombtn"
                    data-testid="viewer-logoff-cancel"
                    onClick={() => setLogoffArmed(false)}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="viewer__zoombtn"
                  data-testid="viewer-logoff"
                  onClick={() => setLogoffArmed(true)}
                  title="Log off the guest's user (ends their session and closes their apps)"
                >
                  ⎋<span className="viewer__lbl"> Log off</span>
                </button>
              )}
            </span>
          )}

          {onReboot && !rebootStatus && (
            <span className="viewer__reboot" role="group" aria-label="Reboot guest">
              {rebootMenuOpen ? (
                <>
                  <span className="viewer__reboot-label">Restart the computer?</span>
                  <button
                    type="button"
                    className="viewer__zoombtn"
                    data-testid="viewer-reboot-normal"
                    onClick={() => {
                      setRebootMenuOpen(false);
                      setToolsPanelOpen(false);
                      onReboot(false);
                    }}
                    title="Reboot the guest normally (auto-reconnects when it comes back)"
                  >
                    Normal
                  </button>
                  <button
                    type="button"
                    className="viewer__zoombtn"
                    data-testid="viewer-reboot-safe"
                    onClick={() => {
                      setRebootMenuOpen(false);
                      setToolsPanelOpen(false);
                      onReboot(true);
                    }}
                    title="Reboot into Safe Mode with Networking (for driver/malware repair)"
                  >
                    Safe Mode with Networking
                  </button>
                  <button
                    type="button"
                    className="viewer__zoombtn"
                    data-testid="viewer-reboot-cancel"
                    onClick={() => setRebootMenuOpen(false)}
                    title="Cancel"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="viewer__zoombtn"
                  data-testid="viewer-reboot"
                  onClick={() => setRebootMenuOpen(true)}
                  title="Restart the computer (normally, or into Safe Mode with Networking)"
                >
                  ⟳<span className="viewer__lbl"> Restart</span>
                </button>
              )}
            </span>
          )}

          {onShutDown && !shutdownStatus && (
            <span className="viewer__shutdown" role="group" aria-label="Shut down guest">
              {shutdownArmed ? (
                <>
                  <button
                    type="button"
                    className="viewer__zoombtn viewer__zoombtn--danger"
                    data-testid="viewer-shutdown-confirm"
                    onClick={() => {
                      setShutdownArmed(false);
                      setToolsPanelOpen(false);
                      onShutDown();
                    }}
                    title="Power the machine OFF — it will not come back until powered on again"
                  >
                    Confirm shut down
                  </button>
                  <button
                    type="button"
                    className="viewer__zoombtn"
                    data-testid="viewer-shutdown-cancel"
                    onClick={() => setShutdownArmed(false)}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="viewer__zoombtn"
                  data-testid="viewer-shutdown"
                  onClick={() => setShutdownArmed(true)}
                  title="Shut the guest machine down (power off)"
                >
                  ⏻<span className="viewer__lbl"> Shut down</span>
                </button>
              )}
            </span>
          )}
          </fieldset>
          )}
        </div>
      )}

      <div
        className="viewer__keys"
        style={showKeys ? {} : { display: "none" }}
        data-testid="viewer-special-keys"
        role="toolbar"
        aria-label="Special keys"
      >
        <span className="viewer__keys-label">Send keys</span>
        {SPECIAL_KEYS.map((sk) => (
          <button
            key={sk.id}
            type="button"
            className={`viewer__key${sk.id === "cad" ? " viewer__key--cad" : ""}`}
            data-testid={`special-${sk.id}`}
            title={inputActive ? sk.title : panning ? "Turn off Pan to send input" : "Enable 'Capture input' to send keys"}
            disabled={!inputActive}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => sendSpecial(sk)}
          >
            {sk.label}
          </button>
        ))}

        <span className="viewer__spacer" />
        <button
          type="button"
          className="viewer__key"
          aria-expanded={showTyping}
          disabled={!typingEnabled}
          title="Type with this device's own keyboard, with a row of special keys above it"
          onMouseDown={(e) => e.preventDefault()}
          onClick={openTyping}
        >
          {showTyping ? "⌨ Keyboard ▲" : "⌨ Keyboard ▼"}
        </button>
      </div>

      {showTyping && (
        <div className="viewer__typing" data-testid="viewer-typing" ref={typingBarRef}>
          <textarea
            ref={typingRef}
            className="viewer__typing-field"
            data-testid="viewer-typing-field"
            aria-label="Type to send to the remote machine"
            placeholder="Type here — sent as you type"
            rows={1}
            disabled={!typingEnabled}
            // Autocorrect and predictions still work (the diff replays their corrections), but
            // auto-capitalisation would capitalise against our sentinel, not the guest's text.
            autoCapitalize="off"
            autoComplete="off"
            spellCheck={false}
            enterKeyHint="enter"
            onInput={(e) => onTypingInput((e.nativeEvent as globalThis.InputEvent).inputType)}
            // Focus coming BACK to the field means the operator was elsewhere — typically tapping
            // the remote screen, which moves the guest caret. Start a fresh history.
            onFocus={() => resetTyping(false)}
            onCompositionStart={() => {
              composingRef.current = true;
            }}
            onCompositionEnd={() => {
              composingRef.current = false;
              // Some keyboards commit the composition with no trailing `input` event; diff now so
              // the commit and any pending reset are not left waiting for the next keystroke.
              onTypingInput();
            }}
            onKeyDown={(e) => {
              const evs = typingFieldKey({
                key: e.key,
                code: e.code,
                keyCode: e.keyCode,
                isComposing: e.nativeEvent.isComposing,
              });
              if (evs) {
                e.preventDefault();
                sendTypingNav(evs, `typed ${e.key}`);
              }
            }}
          />
          <div className="viewer__typing-nav" role="toolbar" aria-label="Special keys">
            {STRIP_MODIFIERS.map((k) => (
              <button
                key={k.code}
                type="button"
                className={`viewer__key${latched.includes(k.code) ? " viewer__key--latched" : ""}`}
                data-testid={`nav-${k.code}`}
                aria-pressed={latched.includes(k.code)}
                title={k.title}
                disabled={!typingEnabled}
                // Keep focus in the field so the device keyboard stays up between taps.
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => onStripModifier(k.code)}
              >
                {k.label}
              </button>
            ))}
            {NAV_KEYS.map((k) => (
              <button
                key={k.code}
                type="button"
                className="viewer__key"
                data-testid={`nav-${k.code}`}
                title={k.title}
                disabled={!typingEnabled}
                // Keep focus in the field so the device keyboard stays up between taps.
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => sendStripKey(k)}
              >
                {k.label}
              </button>
            ))}
          </div>
        </div>
      )}


      {onBrowseDir && filesOpen && (
        <FileManagerPanel
          listing={dirListing}
          loading={dirLoading ?? false}
          error={dirError}
          onNavigate={onBrowseDir}
          onDownloadFile={onDownloadFile}
          completedFiles={completedDownloadFiles}
          transferDirPath={transferDirPath}
          onUploadFiles={onUploadFiles}
          uploads={browseUploads}
          onGetAccess={onGetFileAccess}
          grantInstalled={fileGrantInstalled}
        />
      )}

      {onRunCommand && commandOpen && (
        <div className="viewer__command" data-testid="viewer-command-panel">
          <div className="viewer__command-row">
            <input
              type="text"
              className="viewer__command-input"
              data-testid="viewer-command-input"
              placeholder="e.g. whoami"
              value={commandText}
              onChange={(e) => setCommandText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && commandText.trim() && !commandPending) {
                  onRunCommand(commandText, commandShell, commandAsUser);
                }
              }}
            />
            <select
              className="viewer__command-shell"
              data-testid="viewer-command-shell"
              value={commandShell}
              onChange={(e) => setCommandShell(e.target.value as CommandShell)}
              title="Which interpreter runs the command"
            >
              {COMMAND_SHELLS.map((s) => (
                <option key={s.key} value={s.key}>
                  {s.label}
                </option>
              ))}
            </select>
            <label
              className="viewer__command-asuser"
              title="Run as the signed-in user. On an unattended agent the unchecked default runs as SYSTEM; on an attended session the agent is already the user, so both run as them."
            >
              <input
                type="checkbox"
                data-testid="viewer-command-asuser"
                checked={commandAsUser}
                onChange={(e) => setCommandAsUser(e.target.checked)}
              />
              As user
            </label>
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-command-run"
              disabled={commandPending || commandText.trim().length === 0}
              onClick={() => onRunCommand(commandText, commandShell, commandAsUser)}
              title="Run the command on the guest and capture its output"
            >
              {commandPending ? "Running…" : "Run"}
            </button>
            {onElevatedRun && (
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="viewer-command-elevate"
                disabled={commandPending || commandText.trim().length === 0 || viewOnly}
                onClick={() => onElevatedRun(commandText, commandShell)}
                title={
                  viewOnly
                    ? "This session is view-only, so an elevated command cannot run. Take control first."
                    : "Run this one command with the signed-in user's full administrator rights (their own elevated token, never SYSTEM). Each elevated command is separately authorized and recorded in the audit trail."
                }
              >
                Run as admin
              </button>
            )}
          </div>
          {onRunToolboxItem && (
            <ToolboxRunRow
              items={toolboxItems}
              onRefresh={onRefreshToolbox}
              listError={toolboxListError}
              pending={!!commandPending}
              viewOnly={!!viewOnly}
              onRun={onRunToolboxItem}
            />
          )}
          {toolboxError && (
            <p className="viewer__command-elevation-error" data-testid="viewer-toolbox-error">
              Toolbox: {toolboxError}
            </p>
          )}
          {elevationError && (
            <p className="viewer__command-elevation-error" data-testid="viewer-command-elevation-error">
              Elevation refused: {elevationError}
            </p>
          )}
          {commandResult && (
            <pre className="viewer__command-output" data-testid="viewer-command-output">
              {`exit ${commandResult.exit_code}` +
                (commandResult.timed_out ? " (timed out)" : "") +
                (commandResult.truncated ? " (truncated)" : "") +
                "\n" +
                commandResult.stdout +
                (commandResult.stderr ? `\n[stderr]\n${commandResult.stderr}` : "")}
            </pre>
          )}
        </div>
      )}

      {onSaveNote && noteOpen && (
        <div className="viewer__command" data-testid="viewer-note-panel">
          <div className="viewer__command-row">
            <textarea
              className="viewer__note-input"
              data-testid="viewer-note-input"
              placeholder="Add a note about this session…"
              rows={3}
              maxLength={4000}
              value={noteDraft}
              onChange={(e) => {
                setNoteDraft(e.target.value);
                setNoteSavedMsg(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && noteDraft.trim() && !notePending) {
                  e.preventDefault();
                  void submitNote();
                }
              }}
            />
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="viewer-note-save"
              disabled={notePending || noteDraft.trim().length === 0}
              onClick={() => void submitNote()}
              title="Save note to the session record (Ctrl+Enter)"
            >
              {notePending ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      )}

      {poppedOut ? (
        <div className="viewer__popped" data-testid="viewer-popped-placeholder">
          <p>The remote desktop is in its own window.</p>
          <p className="viewer__hint">
            {recoveryNotice ? recoveryNotice.message : "The session is in that window — its connection status appears there."}
          </p>
          <button type="button" className="viewer__zoombtn" data-testid="viewer-popin" onClick={closePopout}>
            ⧉<span className="viewer__lbl"> Bring it back</span>
          </button>
        </div>
      ) : (
        <ViewerSurface
          onSurfaceEl={onSurfaceEl}
          onVideoEl={onVideoEl}
          panning={panning}
          cropStyles={activeCropStyles}
        transform={videoTransform(view)}
          audioOn={audioOn}
          hasStream={!!stream}
          live={!!transport}
          recoveryNotice={recoveryNotice}
          onReconnect={onReconnect}
          onMouseMove={surfaceMouseMove}
          onMouseDown={surfaceMouseDown}
          overlay={padOverlay}
          onTouchStart={onTouchStart}
          onTouchMove={onTouchMove}
          onTouchEnd={onTouchEnd}
          onTouchCancel={onTouchCancel}
        />
      )}
    </div>
  );
}

const STATUS_META: Record<ConnectionState, { label: string; tone: string }> = {
  idle: { label: "Idle", tone: "neutral" },
  signaling: { label: "Signaling…", tone: "pending" },
  connecting: { label: "Connecting…", tone: "pending" },
  connected: { label: "Connected", tone: "good" },
  disconnected: { label: "Disconnected", tone: "neutral" },
  failed: { label: "Failed", tone: "bad" },
};

/** The command panel's Toolbox row: pick a saved script, see what it is, run it on this machine. */
function ToolboxRunRow({
  items,
  onRefresh,
  listError,
  pending,
  viewOnly,
  onRun,
}: {
  items: readonly ToolboxItem[] | undefined;
  onRefresh?: () => void;
  listError?: string;
  pending: boolean;
  viewOnly: boolean;
  onRun: (item: ToolboxItem) => void;
}) {
  const [selectedId, setSelectedId] = useState("");
  const selected = items?.find((it) => it.id === selectedId);
  useEffect(() => {
    if (!items?.some((it) => it.id === selectedId)) setSelectedId("");
  }, [items, selectedId]);
  const refreshButton = onRefresh && (
    <button
      type="button"
      className="viewer__zoombtn"
      data-testid="viewer-toolbox-refresh"
      aria-label="Refresh toolbox"
      title="Reload the saved scripts"
      onClick={onRefresh}
    >
      ↻
    </button>
  );
  if (listError) {
    return (
      <p className="viewer__command-toolbox-empty" data-testid="viewer-toolbox-unavailable">
        Toolbox unavailable: {listError} {refreshButton}
      </p>
    );
  }
  if (items === undefined) {
    return (
      <p className="viewer__command-toolbox-empty" data-testid="viewer-toolbox-loading">
        Toolbox: loading…
      </p>
    );
  }
  if (items.length === 0) {
    return (
      <p className="viewer__command-toolbox-empty" data-testid="viewer-toolbox-empty">
        Toolbox: no saved scripts yet. Add them in the Toolbox area. {refreshButton}
      </p>
    );
  }
  return (
    <div className="viewer__command-row" data-testid="viewer-toolbox-row">
      <select
        className="viewer__command-shell"
        data-testid="viewer-toolbox-select"
        aria-label="Toolbox item"
        value={selected?.id ?? ""}
        onChange={(e) => setSelectedId(e.target.value)}
      >
        <option value="">Toolbox…</option>
        {items.map((it) => (
          <option key={it.id} value={it.id}>
            {it.name}
            {it.scope === "personal" ? " (mine)" : ""}
          </option>
        ))}
      </select>
      {refreshButton}
      {selected && (
        <span className="viewer__command-toolbox-preview" data-testid="viewer-toolbox-preview">
          {selected.shell === "powershell" ? "PowerShell" : "cmd"}, as {selected.run_as === "user" ? "the signed-in user" : "SYSTEM"}
          {selected.description ? ` — ${selected.description}` : ""}
        </span>
      )}
      <button
        type="button"
        className="viewer__zoombtn"
        data-testid="viewer-toolbox-run"
        disabled={!selected || pending || viewOnly}
        onClick={() => selected && onRun(selected)}
        title={viewOnly ? "This session is view-only, so a script cannot run." : "Run this saved script on the guest (recorded in the audit trail)"}
      >
        Run script
      </button>
    </div>
  );
}
