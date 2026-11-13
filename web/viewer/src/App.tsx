import { RallyMark, RallyWelcome } from "./components/RallyIdentity";
import { SessionViewer } from "./components/SessionViewer";
import { ConnectionDiagnostics } from "./components/ConnectionDiagnostics";
import { BackgroundTracker } from "./lib/background";
import { desktopLink, desktopMinVersion, isDesktopClient, defaultDesktopPreference, attendedLaunchId, DESKTOP_PREFERENCE_KEY, type DesktopTarget } from "./lib/desktop_launch";
import type { MonitorCanvas } from "./lib/monitor_canvas";
/**
 * Top-level shell: the access panel on the left, the remote viewer on the right.
 *
 * V1: this wires a REAL session end-to-end. Connecting opens a `SignalingClient`, registers a
 * controller identity, constructs a `WebRTCTransport`, runs the signaling/ICE handshake against a
 * live agent, and feeds the negotiated `MediaStream` + connection state into `<Viewer>`. Monitors
 * are fetched over the Control channel via `ControlClient`; input flows from the Viewer over the
 * Input channel using the canonical codec.
 */

import { MenuSection, ToolbarMenu } from "./components/ToolbarMenu";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  AccessPanel,
  DEFAULT_SIGNALING_URL,
  machinesFromRecords,
  type Machine as AccessMachine,
} from "./components/AccessPanel";
import { type MonitorInfo, type SessionPolicyState } from "./components/Viewer";
import { BackstagePanels } from "./components/BackstagePanels";
import { FileTransferPanel, saveBytesAsFile, type CompletedDownload } from "./components/FileTransferPanel";
import { IncomingDownloadPrompt } from "./components/IncomingDownloadPrompt";
import { RelayNotice } from "./components/RelayNotice";
import type { PendingDownloadMeta } from "./lib/file_transfer";
import { ChatPanel } from "./components/ChatPanel";
import { ClipboardControl } from "./components/ClipboardControl";
import { BackstageClient } from "./backstage/client";
import { ChannelBackstageTransport } from "./backstage/channel";
import { JoinPage } from "./components/JoinPage";
import { LoginForm } from "./components/LoginForm";
import { SsoTotpForm } from "./components/SsoTotpForm";
import { MachinesPanel } from "./components/MachinesPanel";
import { SessionsPanel } from "./components/SessionsPanel";
import { AuditPanel } from "./components/AuditPanel";
import { NotificationBell } from "./components/NotificationBell";
import { useAuditNotifications } from "./lib/use_audit_notifications";
import { chromeMode, parseSessionChrome, SESSION_CHROME_KEY, type SessionChromePref } from "./lib/session_chrome";
import { ReportsPanel } from "./components/ReportsPanel";
import { RecordingsPanel } from "./components/RecordingsPanel";
import { PlatformPanel } from "./components/PlatformPanel";
import { ToolboxPanel } from "./components/ToolboxPanel";
import { BrokeredSessionCore } from "./lib/brokered_session_core";
import { runToolboxScript } from "./lib/toolbox_run";
import { TenantSecurityPanel } from "./components/TenantSecurityPanel";
import { DynamicGroupsPanel } from "./components/DynamicGroupsPanel";
import { SitesPanel } from "./components/SitesPanel";
import { MachineGroupsPanel } from "./components/MachineGroupsPanel";
import { APITokensPanel } from "./components/APITokensPanel";
import { EnrollmentTokensPanel } from "./components/EnrollmentTokensPanel";
import { WebhooksPanel } from "./components/WebhooksPanel";
import { AppearancePanel } from "./components/AppearancePanel";
import { UsersPanel } from "./components/UsersPanel";
import { RolesPanel } from "./components/RolesPanel";
import { MyAccountPanel } from "./components/MyAccountPanel";
import { HelpPanel } from "./components/HelpPanel";
import { isSamePath, shouldAdoptListing } from "./lib/filepath";
import type { BrowseUploadRow } from "./components/FileManagerPanel";
import { parseGrantCapabilities } from "./lib/grant";
import { GrantOpGuard, resumeGrant } from "./lib/grant_resume";
import { downloadFileFromBrowse, gateDownloadOnCapability, gateUploadOnCapability } from "./lib/download_callbacks";
import { onceAtATime } from "./lib/once_at_a_time";
import { AuthSession } from "./lib/auth_session";
import { AUTH_CHECK_TIMEOUT_MS, boundedAuthCheck } from "./lib/auth_observation";
import { SessionLeaseRenewer } from "./lib/session_lease";
import { releaseSessionOnTerminalTransport } from "./lib/session_lifecycle";
import { SessionRecovery, RecoveryRefused, withDeadline, type RecoveryNotice } from "./lib/session_recovery";
import { withRelayLimitCause } from "./lib/relay_notice";
import { isDisplayLayoutEnd, LayoutReconnectBudget, LAYOUT_RECONNECT_DELAY_MS } from "./lib/layout_reconnect";
import { isRefusal } from "./lib/session_lease";
import {
  effectivePaneMode,
  paneModeFor,
  parsePaneModePreference,
  shouldForceDrawerClosed,
  PANE_MODE_PREF_KEY,
  SPLIT_WIDE_MIN_WIDTH,
  type PaneModePreference,
} from "./lib/layout_breakpoints";
import { AttendedPanel } from "./components/AttendedPanel";
import { parseMachineUrlParams } from "./lib/machine_url_params";
import { SessionInvite } from "./components/SessionInvite";
import { AdminRightsControl } from "./components/AdminRightsControl";
import {
  NO_ADMIN_RIGHTS,
  adminRightsAdvertised,
  adminRightsRequested,
  adminRightsResult,
  type AdminRightsModel,
} from "./lib/admin_rights";
import { InputControlBadge, InputHandoffControl } from "./components/InputHandoffControl";
import {
  HAND_PENDING_TIMEOUT_MS,
  NO_INPUT_HANDOFF,
  handRefused,
  handRequested,
  handTimedOut,
  handoffAdvertised,
  inputControlChanged,
  isInputControlError,
  type InputHandoffModel,
} from "./lib/input_handoff";
import type { SessionParticipantEntry } from "./lib/protocol";
import { ClipboardClient, type ClipboardApi, type ClipboardNotice } from "./lib/clipboard";
import type { HelpRequest, SessionTransfer } from "./lib/console_api";
import { AcceptKeys, HelpAcceptController, helpBellView, HelpRequestPoller, type HelpAcceptState } from "./lib/help_requests";
import { HelpRequestsBell } from "./components/HelpRequestsBell";
import { acceptAndWait, IncomingTransferPoller, senderTransferredMessage } from "./lib/session_transfer";
import { TransferDialog } from "./components/TransferDialog";
import { IncomingTransfers } from "./components/IncomingTransfers";
import { ClipboardQuick } from "./components/ClipboardQuick";
import {
  AuditForwarder,
  ChannelId,
  ChatClient,
  ConsoleApiClient,
  ConsoleApiError,
  isHexColor,
  isLogoDataUri,
  ControlClient,
  ControlPlaneClient,
  ControlPlaneError,
  FileTransferClient,
  SignalingClient,
  WebRTCTransport,
  OBSERVE_UNSUPPORTED,
  acquireBrokeredSession,
  isDeviceAccessDenied,
  asDeviceId,
  effectiveQuality,
  initialQualityIntent,
  qualityIntentReducer,
  releaseBrokeredSession,
  SYSTEM_TOOLS,
  attendedHandoff,
  type AuditEvent,
  type BrokeredSession,
  type ChatEntry,
  type CommandResult,
  type CommandShell,
  type ConnectionState,
  type DeviceId,
  type DirectoryListing,
  type RecordingResult,
  type SealedAuditEvent,
  type TenantBranding,
  type ToolboxItem,
  type MonitorDesc,
  type QualitySettings,
  type QualityStats,
  type ConnectedAttendedSession,
} from "./lib";

interface ActiveSession {
  device: DeviceId;
  name: string;
}

/**
 * How often a live session's buffered audit events are shipped to the control plane (H2, ADR-008).
 *
 * Periodic rather than per-event because the chain is verified as an ORDERED batch server-side, and
 * because a technician running a burst of backstage commands should not produce a POST per
 * keystroke. Short enough that a browser crashing mid-session loses seconds of trail, not the whole
 * session: the agent keeps its own copy either way, but the whole point of central storage is that
 * it survives the endpoint.
 */
const AUDIT_FLUSH_INTERVAL_MS = 10_000;

/**
 * How long to wait for a `QualityApplied` after the connect-time `RequestQuality` before concluding
 * the agent does not speak M11 (docs: the arming rule in `crates/agent-core/src/control.rs`).
 *
 * There is no version handshake on this channel, so absence IS the signal — an agent that predates
 * M11 fails to decode `RequestQuality` and answers nothing at all. Two seconds is chosen against the
 * two things that delay a legitimate reply: the data channel opening (the send is buffered until
 * then) and one data-channel round trip, both of which are well under a second even on a slow WAN.
 * Guessing short only costs a disabled control that re-enables on the next connect; guessing long
 * leaves live controls that silently do nothing, which is the failure worth avoiding.
 */
const QUALITY_PROBE_TIMEOUT_MS = 2_000;

/**
 * Build the audit forwarder for one brokered session, wired to the authenticated console client.
 *
 * `null` when the connection was never brokered through the control plane — the direct-connect/dev
 * path, where there is no authenticated console to POST through at all. The agent still chains its
 * own trail in that case; it just is not shipped centrally.
 *
 * When it IS brokered, the forwarder is created with a `null` id and BINDS to whatever the agent's
 * first event says its chain is (loop 91). The console genuinely cannot know that id in advance: the
 * agent chains under the session id signaling vouched for, and a deployment that verifies no session
 * tickets vouches for nothing, so the agent falls back to the id inside the installed grant. Passing
 * the brokered id as a hard key looked obviously right and silently discarded the entire trail on
 * every unticketed stack — including this repo's own e2e, which is where it was caught.
 *
 * Flush failures are SWALLOWED, deliberately. Forwarding is a durability measure, not an
 * authorization one: the events stay buffered for the next flush, and a control plane that is
 * briefly unreachable must not tear down a live remote-support session or surface an error over the
 * technician's screen. What is not acceptable is losing them silently, which is why the teardown
 * path flushes one last time before the forwarder is dropped.
 */
/**
 * Hand a sealed audit event from a recording ack to the session's forwarder (loop 91).
 *
 * Exported and free-standing so it can be unit-tested: `App.tsx` is a `.tsx`, which the vitest
 * config does not collect, and the last time an audit hop lived only inside a component nothing
 * covered it. `forwarder` is passed rather than read from the ref for the same reason.
 *
 * A `null` event is a no-op, not an error: the agent seals nothing when signaling vouched for no
 * session, and on that path there is no forwarder either.
 */
import { auditSessionIdFor, makeAuditForwarder } from "./lib/session_audit";
// Re-exported for the existing wiring tests (audit_wiring.test.ts), which import them from App.
export { auditSessionIdFor, makeAuditForwarder };

export function enqueueSealedAuditInto(
  forwarder: AuditForwarder | null,
  audit: SealedAuditEvent,
): void {
  // The `!audit` half is a documented EQUIVALENT MUTANT: `AuditForwarder.enqueue` opens with its own
  // `if (events == null) return`, so removing this check changes no observable behaviour and no test
  // can kill it. Kept anyway, because it states the contract WHERE THE CALLER READS IT — the agent
  // seals nothing when signaling vouched for no session, and that is a fact about this hop, not a
  // detail of the forwarder's internals for this function to depend on.
  if (!forwarder || !audit) return;
  // Cast, never reshape. The control plane re-hashes this event's canonical preimage and rejects a
  // field-level difference as tampering, so anything the browser "fixed" on the way through would
  // present as the agent having forged its own trail — and would wedge the rest of the session's
  // chain, because a rejected batch can never be skipped.
  forwarder.enqueue(audit as unknown as AuditEvent);
}

type ConsoleView = "screen" | "backstage" | "files" | "chat";

/**
 * M3: top-level console area. "live" is the original session workspace (connect/view/backstage);
 * the rest are the management panels over the control plane's data-plane endpoints. "attended"
 * is the on-demand session flow (docs/12 §9).
 */
// How long to wait for a `DirectoryListing`/`Error` before concluding the guest will not answer a
// `ListDirectory` (an agent predating this feature silently drops the unknown variant, per control.ts'
// forward-compat design). Mirrors the M11 quality probe timeout. A local listing is milliseconds, so
// 8 s is generous while still recovering the panel from a permanent no-answer.
const DIR_REPLY_TIMEOUT_MS = 8000;

// How long to wait for an `ElevatedRun`'s verdict — a `CommandResult` OR an `ElevationDenied` —
// before concluding the guest will not answer (docs/01 §3, loop 87). An agent predating loop 87
// silently DROPS the unknown variant, exactly as it drops `ListDirectory`, so without this the
// command bar would stay disabled for the rest of the session with nothing on screen explaining
// why — and the control plane would have already spent an audit event on the grant.
//
// Longer than the directory timeout because an elevated command genuinely runs: the agent's own
// budget is 30 s (`command_run::DEFAULT_TIMEOUT`), so this must outlast a command that is killed at
// its timeout and still answers.
//
// 60 s, not 35 (loop 88). 35 left five seconds for the mint round trip, the transport, the agent's
// output capture and the reply — so a command that used its full 30 s budget could plausibly answer
// AFTER the deadline had already told the operator it was refused. That is the worst possible thing
// for this particular timer to be wrong about: the command may have run with administrator rights.
// Being slow to give up costs a disabled Run button; being early costs a false account of whether a
// privileged action happened. Sixty is still far short of "stuck forever", which is the only failure
// this deadline exists to prevent.
const ELEVATION_REPLY_TIMEOUT_MS = 60_000;

type ConsoleArea =
  | "live"
  | "attended"
  | "machines"
  | "sessions"
  | "audit"
  | "recordings"
  | "reports"
  | "platform"
  | "toolbox"
  | "security"
  | "sites"
  | "groups"
  | "machinegroups"
  | "apitokens"
  | "enrollment"
  | "webhooks"
  | "appearance"
  | "users"
  | "roles"
  | "account"
  | "help";

/**
 * The menu's groups, in display order (menu redesign wave 4, the operator's structure of 2026-11-07: Machines | Support | History |
 * Manage | Admin, then the account). Wave 10 turns the same groups into the visible top bar.
 */
type ConsoleAreaGroup = "Machines" | "Support" | "History" | "Manage" | "Admin" | "Account" | "Platform";
const CONSOLE_AREA_GROUPS: readonly ConsoleAreaGroup[] = ["Machines", "Support", "History", "Manage", "Admin", "Account", "Platform"];

const CONSOLE_AREAS: { id: ConsoleArea; label: string; group: ConsoleAreaGroup }[] = [
  { id: "live", label: "Live", group: "Machines" },
  { id: "machines", label: "Machines", group: "Machines" },
  { id: "attended", label: "Support", group: "Support" },
  { id: "sessions", label: "Sessions", group: "History" },
  // Shown only to a principal the server lets list recordings (view_recordings); see `visibleAreas`.
  { id: "recordings", label: "Recordings", group: "History" },
  { id: "audit", label: "Audit", group: "History" },
  { id: "reports", label: "Reports", group: "History" },
  // Internal ids are unchanged; only the labels were clarified. "sites" reads/writes the existing
  // machine `site` property; "machinegroups" are the static RBAC/policy groups.
  { id: "enrollment", label: "Install DeskRally", group: "Manage" },
  { id: "machinegroups", label: "Machine groups", group: "Manage" },
  { id: "groups", label: "Smart groups", group: "Manage" },
  { id: "sites", label: "Sites", group: "Manage" },
  { id: "toolbox", label: "Toolbox", group: "Manage" },
  { id: "users", label: "Users", group: "Admin" },
  { id: "roles", label: "Roles", group: "Admin" },
  { id: "security", label: "Security", group: "Admin" },
  { id: "apitokens", label: "API tokens", group: "Admin" },
  { id: "webhooks", label: "Webhooks", group: "Admin" },
  { id: "appearance", label: "Appearance", group: "Admin" },
  { id: "account", label: "My account", group: "Account" },
  { id: "help", label: "Help", group: "Account" },
  // Shown only to the platform operator (GET /platform/me); see `visibleAreas`.
  { id: "platform", label: "Platform", group: "Platform" },
];

/**
 * A safe `navigator.clipboard` for the `ClipboardClient`: in an insecure context (or a browser that
 * withholds the API) `navigator.clipboard` is `undefined`, so we substitute a shim whose reads/writes
 * reject — the `ClipboardClient` already treats a rejected read/write as a best-effort no-op.
 */
function clipboardApi(): ClipboardApi {
  const nav = navigator as Navigator & { clipboard?: ClipboardApi };
  return (
    nav.clipboard ?? {
      readText: () => Promise.reject(new Error("clipboard API unavailable (insecure context)")),
      writeText: () => Promise.reject(new Error("clipboard API unavailable (insecure context)")),
    }
  );
}

import { iceServersFor } from "./lib/ice_servers";
import { formatExpiry } from "./lib/user_access";
import { type AccessWindow, windowLabel } from "./lib/access_window";
import { areaVisible, heldCapabilities } from "./lib/area_visibility";
import { areaBarItems, areaSubtabs } from "./lib/area_nav";

/** Present the agent's `MonitorDesc` list to the Viewer's picker (adds a human label). */
function toMonitorInfo(list: MonitorDesc[]): MonitorInfo[] {
  return list.map((m, i) => ({
    id: m.id,
    label: `Display ${i + 1}`,
    width: m.width,
    height: m.height,
    primary: m.primary,
  }));
}

export default function App() {
  const desktopClient = isDesktopClient(navigator.userAgent);
  const [preferDesktop, setPreferDesktop] = useState(() => {
    try { return defaultDesktopPreference(localStorage.getItem(DESKTOP_PREFERENCE_KEY) ?? (import.meta.env.DEV ? "browser" : null), navigator.userAgent, window.location.origin); }
    catch { return defaultDesktopPreference(import.meta.env.DEV ? "browser" : null, navigator.userAgent, window.location.origin); }
  });
  const [desktopRequest, setDesktopRequest] = useState<{ target: DesktopTarget; uri: string; name: string; signalingUrl: string; epoch: number } | null>(null);
  const attendedUrlAttempted = useRef(false);
  const [session, setSession] = useState<ActiveSession | null>(null);
  const [machineAlias, setMachineAlias] = useState<string | undefined>(undefined);
  // Holds the alias set by handleConnectFromList before connectImpl runs, so connectImpl can
  // pick it up without changing the connectImpl/handleConnect signature.
  const pendingMachineAliasRef = useRef<string | undefined>(undefined);
  const [state, setState] = useState<ConnectionState>("idle");
  const [view, setView] = useState<ConsoleView>("screen");
  // M3: which console area is showing — the live session workspace or a management panel.
  const [area, setArea] = useState<ConsoleArea>(() =>
    window.location.pathname === "/console/account" ? "account" :
    window.location.pathname === "/console/security" ? "security" :
    window.location.pathname === "/console/help" ? "help" : "live",
  );
  const installRequested = useRef(new URLSearchParams(window.location.search).get("area") === "enrollment");
  const [stream, setStream] = useState<MediaStream | null>(null);
  // What the control plane's signed policy did to this session: `enforced` = the agent is holding a
  // view-only FLOOR the technician cannot lift; `note` explains a policy that could not be applied.
  // `applied` distinguishes "the agent VERIFIED this policy" from "the agent REFUSED it". Both can
  // report enforced:false — a verified `control` policy does, and so does a rejection — and only the
  // second one is something the operator must be told (see Viewer's sessionPolicyBanner).
  const [sessionPolicyState, setSessionPolicyState] = useState<SessionPolicyState | null>(null);
  const [monitors, setMonitors] = useState<MonitorDesc[]>([]);
  const [pinnedMonitorId, setPinnedMonitorId] = useState<number | undefined>(undefined);
  const [monitorCanvas, setMonitorCanvas] = useState<MonitorCanvas | undefined>(undefined);
  const monitorCanvasRef = useRef<MonitorCanvas | undefined>(undefined);
  // Whether the agent is sending audio at all. Set by `onAudioTrack` and cleared with the session,
  // so a machine WITH audio does not leave the control enabled for the next machine without it.
  const [audioAvailable, setAudioAvailable] = useState(false);
  // M11: the quality the agent reports is IN FORCE (its `QualityApplied`) *plus* the operator's
  // not-yet-answered ask. Both are needed — the advanced panel read-modify-writes all five fields
  // (there is no partial update on this wire), so reading only the acknowledged value made two quick
  // edits on a high-RTT link revert each other. `lib/quality.ts` holds the reducer and the reasoning.
  const [qualityIntent, dispatchQuality] = useReducer(
    qualityIntentReducer,
    undefined,
    initialQualityIntent,
  );
  const [qualityStats, setQualityStats] = useState<QualityStats | null>(null);
  // `undefined` = still probing, `true` = the agent answered, `false` = it did not within the window
  // and therefore predates M11. Three states, not two: a `false` default would flash "unsupported"
  // over the controls at the start of every session with a perfectly capable agent.
  const [qualitySupported, setQualitySupported] = useState<boolean | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  // The live backstage client for the current session — held in state so switching to the Backstage
  // view re-renders `<BackstagePanels client={…} />` with a client backed by the WebRTC transport.
  const [backstageClient, setBackstageClient] = useState<BackstageClient | null>(null);
  // V3: live file-transfer + clipboard clients for the current session, in state so the Files tab
  // and the clipboard control re-render with clients backed by the live WebRTC transport.
  const [fileTransferClient, setFileTransferClient] = useState<FileTransferClient | null>(null);
  const [clipboardClient, setClipboardClient] = useState<ClipboardClient | null>(null);
  // Session transfer (docs/51). Sender: the dialog and this session's live offer (its recipient names the
  // "Session transferred to Bob" message). Receiver: offers polled every 10 s, and the one being accepted.
  const [transferDialogOpen, setTransferDialogOpen] = useState(false);
  const [outgoingTransfer, setOutgoingTransfer] = useState<SessionTransfer | null>(null);
  const outgoingTransferRef = useRef<SessionTransfer | null>(null);
  outgoingTransferRef.current = outgoingTransfer;
  const [incomingOffers, setIncomingOffers] = useState<SessionTransfer[]>([]);
  const [dismissedOffers, setDismissedOffers] = useState<ReadonlySet<string>>(() => new Set());
  const [acceptingTransfer, setAcceptingTransfer] = useState<{ id: string; status: string } | null>(null);
  const [incomingTransferError, setIncomingTransferError] = useState<string | null>(null);
  const incomingPollerRef = useRef<IncomingTransferPoller | null>(null);
  // Guest help requests (docs/64): the open queue this user may act on, polled while signed in; the one being
  // accepted; and the last accept failure, shown with the server's own words.
  const [helpRequests, setHelpRequests] = useState<HelpRequest[]>([]);
  // The accept in progress, its terminal failure, and an UNRESOLVED accept (outcome unknown: a lost response)
  // are held by the controller, independently of the queue, which stops listing a request once it is accepted.
  const [helpAccept, setHelpAccept] = useState<HelpAcceptState>({ accepting: null, error: null, unresolved: null });
  const helpPollerRef = useRef<HelpRequestPoller | null>(null);
  const helpAcceptRef = useRef<HelpAcceptController | null>(null);
  const [viewerPoppedOut, setViewerPoppedOut] = useState(false);
  // docs/25 F08: latest own-status notice from the clipboard client (byte counts + result kinds
  // only, never remote content). Held here so it is reset alongside the client on teardown.
  const [clipboardNotice, setClipboardNotice] = useState<ClipboardNotice | null>(null);
  // M12: in-session chat. The client is held in state so the Chat tab re-renders with one backed by
  // the live WebRTC transport; the transcript and the truncation flag are held here (not read off
  // the client) because the client is not a React store — its `onMessages` push is what tells React
  // the agent posted something, exactly as `monitors` and `download` are handled above.
  const [chatClient, setChatClient] = useState<ChatClient | null>(null);
  const [chatMessages, setChatMessages] = useState<readonly ChatEntry[]>([]);
  const [chatTruncated, setChatTruncated] = useState(false);
  // The most recently completed inbound download (fed to the Files panel to trigger a browser save).
  const [download, setDownload] = useState<CompletedDownload | null>(null);
  // Relative paths (from transfer root) of all files downloaded this session — shown as "✓ saved"
  // in the file browser rows. Accumulated across multiple downloads; cleared on teardown.
  // Using rel paths (not basenames) prevents false badges: "subdir/report.pdf" ≠ "report.pdf".
  const [completedBrowseRelPaths, setCompletedBrowseRelPaths] = useState<ReadonlySet<string>>(new Set());
  // Uploads started from the file browser this session (newest first), for its status list. Cleared on
  // teardown with the rest of the per-session file state.
  const [browseUploads, setBrowseUploads] = useState<readonly BrowseUploadRow[]>([]);
  const browseUploadSeq = useRef(0);
  // F06 explicit approval: metadata only for unsolicited downloads awaiting the operator's Save.
  // The BYTES stay inside the FileTransferClient under the same F07 lease. React only sees names,
  // sizes, and ids — approval buttons round-trip through the current client, so a click after the
  // client was replaced / disposed silently no-ops.
  const [pendingDownloads, setPendingDownloads] = useState<readonly PendingDownloadMeta[]>([]);
  // Set true once the operator confirms a control-plane-signed grant was installed (H1); flips the
  // "denied — no grant" affordance back off.
  const [grantInstalled, setGrantInstalled] = useState(false);
  // The technician held a backstage grant (the agent acked one) in the session being recovered. Only
  // the FACT survives a recovery (teardown(true) keeps it; any other teardown clears it): the grant
  // itself is never kept, a resumed session re-mints for its NEW session id (lib/grant_resume.ts).
  const grantHeldRef = useRef(false);
  // The single in-flight grant operation (automatic resume OR manual Get access) for the session.
  const grantOpRef = useRef(new GrantOpGuard());
  // Shown in the backstage panel's grant-denied state when the automatic resume could not restore access.
  const [grantResumeNotice, setGrantResumeNotice] = useState<string | null>(null);
  // docs/58 §2: the Backstage features THIS session's agent reported (asked for after GrantInstalled).
  // Empty until it answers; an agent too old to know the question never does.
  const [backstageFeatures, setBackstageFeatures] = useState<ReadonlySet<string>>(new Set());
  // docs/58 §3: the session client may send a confirmed retry only once this session's agent has
  // advertised `confirm`. A new session builds a new client, which starts without it.
  useEffect(() => {
    if (backstageFeatures.has("confirm")) backstageClient?.allowConfirmation();
  }, [backstageFeatures, backstageClient]);
  // Capabilities extracted from the last viewer-minted grant. `null` means no grant has been minted
  // by the viewer yet (dev agents self-issue grants; UI defaults remain visible). A non-null Set that
  // lacks "file_download" suppresses the download affordance when the session explicitly omits it.
  const [grantCapabilities, setGrantCapabilities] = useState<ReadonlySet<string> | null>(null);
  // Task 4: the agent-advertised file-transfer root (`TransferDir` control message). Cleared on
  // teardown so a stale path from a previous machine never silently affects the next session. The
  // ref provides the current value to `downloadFromBrowse` without re-creating the callback.
  const agentTransferDirRef = useRef<string | undefined>(undefined);
  const [agentTransferDir, setAgentTransferDir] = useState<string | undefined>(undefined);
  // docs/53: what the agent said about asking the guest for admin rights, and the latest request.
  // Per session: reset on teardown with the transfer root.
  const [adminRights, setAdminRights] = useState<AdminRightsModel>(NO_ADMIN_RIGHTS);
  // docs/61: input hand-off between technicians on this machine (agent-arbitrated; see input_handoff.ts).
  const [inputHandoff, setInputHandoff] = useState<InputHandoffModel>(NO_INPUT_HANDOFF);
  // The other controllers on this machine, and our own SIGNALING session id: hand targets are named by
  // signaling id (what the agent keys its directory on), and our own id is how we tell ourselves apart.
  const [participants, setParticipants] = useState<SessionParticipantEntry[]>([]);
  const [ownSignalingId, setOwnSignalingId] = useState<string | null>(null);
  // A hand the agent never answers must not disable the action forever (the agent ignores repeats
  // while one is pending, so a retry after this is safe).
  useEffect(() => {
    if (!inputHandoff.pending) return;
    const t = setTimeout(() => setInputHandoff((m) => handTimedOut(m)), HAND_PENDING_TIMEOUT_MS);
    return () => clearTimeout(t);
  }, [inputHandoff.pending]);
  // In-flight browse downloads: requestId → rel path. Each browse request gets a UUID from
  // FileTransferClient.request(); on completion, the UUID in onDownload resolves the exact rel path
  // without any basename heuristic — correct even for concurrent downloads of same-named files.
  // Entries are removed on: onDownload (success) or onDownloadError with an id: a peer abort after
  // the Offer, a refusal before any Offer, or a request that expired unanswered. Anything else
  // remains until session teardown (clear()). The map is bounded by maxPendingRequests (32).
  const pendingBrowseRelsRef = useRef<Map<string, string>>(new Map());
  // Privacy: whether the guest's own keyboard/mouse are blocked. Sourced from the agent's
  // `InputBlockApplied` ack (the state actually in force), NOT optimistically from the request — the
  // block can fail to arm, and this must reflect reality.
  const [inputBlocked, setInputBlocked] = useState(false);
  // Privacy: whether the guest's monitors are blanked. Sourced from the agent's
  // `MonitorBlankedApplied` ack (the state actually in force), NOT optimistically from the request —
  // window creation can fail and this must reflect reality.
  const [monitorBlanked, setMonitorBlanked] = useState(false);
  // View-only / presentation mode: whether the agent is dropping our injected input. Sourced from the
  // agent's `ViewOnlyApplied` ack (the state actually in force), never optimistically from the request.
  const [viewOnly, setViewOnly] = useState(false);
  const [observing, setObserving] = useState(false);
  const observingRef = useRef(false);
  // Remote support: a transient status line while a reboot the operator requested is in flight.
  // Set from the agent's `RebootScheduled` ack (so it only shows once the reboot is genuinely
  // scheduled, not on the click), and cleared when the session reconnects — see the effect below.
  const [rebootStatus, setRebootStatus] = useState<string | undefined>(undefined);
  const [lockStatus, setLockStatus] = useState<string | undefined>(undefined);
  // Remote support: a transient status for an in-progress log off, set from the agent's
  // `LogOffScheduled` ack (so it only shows once logoff is genuinely initiated, not on the click) and
  // cleared when the session reconnects — like rebootStatus, because logoff also drops the session.
  const [logoffStatus, setLogoffStatus] = useState<string | undefined>(undefined);
  // Remote support: a transient status for an in-progress SHUT DOWN, set from the agent's
  // `ShutDownScheduled` ack. Unlike reboot/logoff the machine does NOT come back on its own, so the
  // status says so; cleared on reconnect (if the machine is later powered on and re-registers).
  const [shutdownStatus, setShutdownStatus] = useState<string | undefined>(undefined);
  // Remote support: a transient confirmation of the last tool launched ("Launched Task Manager"),
  // set from the agent's `ToolLaunched` ack and cleared on disconnect.
  const [toolStatus, setToolStatus] = useState<string | undefined>(undefined);
  // Session recording (loop 89, docs/01 §5): whether a recording is running RIGHT NOW, and the
  // finished result of the last one.
  //
  // `recording` is sourced from the agent's `RecordingStarted` / `RecordingStopped` acks and NEVER
  // optimistically from the click — the same rule as `viewOnly`, and for a stronger reason here. The
  // button's label is a claim about whether a video of somebody's screen is being written to their
  // disk; a click that the agent refuses (no location configured, disk full, DACL) must not leave
  // this saying "Recording". `pending` disables the button between the ask and the answer so a
  // double-click cannot send a start the agent will refuse as "already recording".
  const [recording, setRecording] = useState(false);
  const [recordingPending, setRecordingPending] = useState(false);
  const [recordingResult, setRecordingResult] = useState<RecordingResult | undefined>(undefined);
  // Remote support (one-line command bar): the captured result of the last command, set from the
  // agent's `CommandResult`, and whether a command is currently in flight (one at a time). `pending`
  // is set on send and cleared on the result OR an error, so the Run button re-enables either way.
  const [commandResult, setCommandResult] = useState<CommandResult | undefined>(undefined);
  const [commandPending, setCommandPending] = useState(false);
  // Remote support (elevate to admin, docs/01 §3): whether THIS connection can even ask for an
  // elevation grant, and the reason the last request was refused.
  //
  // `canElevate` is STATE and not a read of `brokeredSessionRef`, because a ref cannot re-render:
  // the control that depends on it has to appear and disappear with the connection. It is false on
  // the DIRECT-CONNECT and ATTENDED paths, which hold no control-plane session record of their own
  // — there is nothing to POST an elevation request against, and an attended agent could not honour
  // one anyway (it runs at the guest's integrity level).
  const [canElevate, setCanElevate] = useState(false);
  const [elevationError, setElevationError] = useState<string | undefined>(undefined);
  // Shared Toolbox in the session (docs/design-shared-toolbox.md): the caller's saved scripts, loaded
  // when a brokered session connects, and why the last run request was refused.
  const [toolboxItems, setToolboxItems] = useState<readonly ToolboxItem[] | undefined>(undefined);
  const [toolboxRefreshSeq, setToolboxRefreshSeq] = useState(0);
  const refreshToolbox = useCallback(() => setToolboxRefreshSeq((seq) => seq + 1), []);
  const [toolboxError, setToolboxError] = useState<string | undefined>(undefined);
  // Why the toolbox could not be listed for this session (distinct from an empty toolbox).
  const [toolboxListError, setToolboxListError] = useState<string | undefined>(undefined);
  // The command panel's current operation: bumped by every command, elevated run and toolbox run, so
  // a toolbox request that completes after a newer one started leaves the UI alone.
  const commandOpSeq = useRef(0);
  // Remote support (file browser): the latest directory listing from the agent, whether one is in
  // flight, and the last navigation error. `dirPendingRef` lets the SHARED onError attribute a
  // failure to the browser (vs another action) without a stale-closure read of the loading state.
  const [dirListing, setDirListing] = useState<DirectoryListing | undefined>(undefined);
  const [dirLoading, setDirLoading] = useState(false);
  const [dirError, setDirError] = useState<string | undefined>(undefined);
  // The path the browser is waiting on (null = idle). It correlates replies (dropping a stale
  // out-of-order answer to a superseded navigation) and lets the shared onError attribute a failure
  // to the browser. `dirTimeoutRef` bounds the wait so an agent that never answers — e.g. one
  // predating this feature, which silently drops the unknown ListDirectory — cannot leave the panel
  // stuck on "Loading…" (the same forward-compat trap the M11 quality probe timeout closes).
  const dirPendingPathRef = useRef<string | null>(null);
  const dirTimeoutRef = useRef<number | null>(null);
  // Remote support (screenshot): a transient "Saved screenshot-….png" line, set when the agent's
  // pushed PNG finishes saving, cleared on disconnect.
  const [screenshotStatus, setScreenshotStatus] = useState<string | undefined>(undefined);
  // Remote support (end session): a transient status once the agent acks `SessionEnding`, cleared on
  // disconnect. Follows the ack (not the click), so "Removing client…" only shows once the agent agrees.
  const [endSessionStatus, setEndSessionStatus] = useState<string | undefined>(undefined);
  // Multi-Tech: the number of CO-PARTICIPANTS (other technicians, self excluded) in the current
  // session, sourced from session_participants messages. 0 = no message received yet, or no
  // co-techs present. Shows a badge when > 0 (i.e. at least one peer is present).
  const [sessionParticipantCount, setSessionParticipantCount] = useState<number>(0);
  const [sessionObserverCount, setSessionObserverCount] = useState(0);

  /**
   * Responsive shell state (see `lib/layout_breakpoints.ts`).
   *
   * `navOpen` drives the machine-list drawer in the stacked (phone / folded-foldable) layout, and
   * the wider layouts simply ignore it — the list is a permanent pane there, by CSS.
   *
   * `viewportWidth` exists ONLY to compute a `data-pane-mode` attribute and to decide whether an
   * open drawer should be forced shut. **It must never gate what is RENDERED.** Unfolding a
   * foldable is a live resize of a page that is mid-session; a `{wide ? <A/> : <B/>}` branch would
   * unmount a subtree on that resize, and unmounting the session pane destroys the `<video>`, the
   * peer connection and the zoom/pan state — i.e. opening the phone would drop the call.
   */
  const [toolbarEndHost, setToolbarEndHost] = useState<HTMLDivElement | null>(null);
  const [appMenuOpen, setAppMenuOpen] = useState(false);
  // The Help button at the right end of the top bar opens Help as a side panel OVER the current
  // view instead of switching area: the remote screen only exists while the Live area is shown, so
  // navigating away mid-session would tear the session down, and the desktop app does not allow
  // opening a second window to read it. The full Help area stays in the DeskRally menu.
  const [helpOpen, setHelpOpen] = useState(false);
  useEffect(() => {
    if (!helpOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setHelpOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [helpOpen]);
  const [sessionMenuOpen, setSessionMenuOpen] = useState(false);
  const [toolbarHost, setToolbarHost] = useState<HTMLDivElement | null>(null);
  // Session chrome (lib/session_chrome.ts): during a live session the top bar collapses behind a
  // small tab on the top edge (Chrome Remote Desktop style) unless the operator pins it. The pin is a
  // per-browser convenience; storage can be unavailable, so every access is guarded.
  const [sessionChrome, setSessionChrome] = useState<SessionChromePref>(() => {
    try { return parseSessionChrome(localStorage.getItem(SESSION_CHROME_KEY)); } catch { return "minimal"; }
  });
  const [chromeOpen, setChromeOpen] = useState(false);
  const [tabHost, setTabHost] = useState<HTMLDivElement | null>(null);
  const setChromePref = useCallback((pref: SessionChromePref) => {
    setSessionChrome(pref);
    setChromeOpen(false);
    try { localStorage.setItem(SESSION_CHROME_KEY, pref); } catch { /* preference optional */ }
  }, []);
  const [navOpen, setNavOpen] = useState(false);
  const [viewportWidth, setViewportWidth] = useState(() =>
    typeof window === "undefined" ? SPLIT_WIDE_MIN_WIDTH : window.innerWidth,
  );
  /**
   * The operator's layout choice, remembered per browser.
   *
   * Asked for directly: they reported the compact menu bar missing on their foldable, and it was
   * behaving as designed — the unfolded inner screen is around 700 px, which is `split-narrow`, so
   * it kept two panes and the full bar. A width threshold cannot know that someone at 700 px, or on
   * a desktop, would rather have the screen back and reach the machine list from a drawer. So it is
   * a preference rather than an inference.
   *
   * Every `localStorage` access is wrapped: it throws outright in some privacy modes, and a console
   * that cannot start because it could not read a layout preference would be a ridiculous failure.
   * An unreadable or unrecognised value degrades to "follow the viewport".
   */
  const [layoutPref, setLayoutPref] = useState<PaneModePreference>(() => {
    try {
      return parsePaneModePreference(window.localStorage.getItem(PANE_MODE_PREF_KEY));
    } catch {
      return "auto";
    }
  });
  useEffect(() => {
    const onResize = () => setViewportWidth(window.innerWidth);
    window.addEventListener("resize", onResize);
    // Foldables also report a posture change as an orientation change, and some report it ONLY that
    // way; both funnel to the same width read, so subscribing to both costs nothing and misses less.
    window.addEventListener("orientationchange", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("orientationchange", onResize);
    };
  }, []);
  const paneMode = effectivePaneMode(viewportWidth, layoutPref);
  useEffect(() => {
    // A drawer left open while the layout widens would strand a backdrop over a two-pane view. The
    // helper returns false when there is nothing to do, so an ordinary resize does not set state.
    // It takes the EFFECTIVE mode, so an operator who forced compact on a wide screen keeps their
    // drawer instead of having it slammed shut on every resize event.
    if (shouldForceDrawerClosed(paneMode, navOpen)) setNavOpen(false);
  }, [paneMode, navOpen]);

  /** Set the layout preference and remember it. */
  const applyLayoutPref = useCallback((next: PaneModePreference) => {
    setLayoutPref(next);
    try {
      window.localStorage.setItem(PANE_MODE_PREF_KEY, next);
    } catch {
      // Unwritable storage (private mode, blocked site data) costs persistence, not the feature:
      // the choice still applies for this session.
    }
  }, []);
  /** Flip between following the viewport and forcing the compact layout. */
  const toggleCompactLayout = useCallback(() => {
    applyLayoutPref(layoutPref === "compact" ? "auto" : "compact");
  }, [applyLayoutPref, layoutPref]);
  /**
   * The ☰ button. Where the list is a permanent pane it COLLAPSES it (compact), giving the session the
   * whole window; where the list is a drawer it opens and closes the drawer.
   *
   * Asked for on 2026-10-22: on an unfolded phone (tablet mode) the list was a permanent pane with no
   * visible way to hide it. The Compact toggle existed but sat inside the DeskRally menu, and the ☰
   * button was hidden in exactly the two-pane layouts where the list needs a close control.
   */
  const onNavToggle = useCallback(() => {
    if (paneMode !== "stacked") {
      applyLayoutPref("compact");
      return;
    }
    setNavOpen((v) => !v);
  }, [paneMode, applyLayoutPref]);
  /** "Keep list open": undo a collapse, back to following the window size (a pane where it fits). */
  const pinMachineList = useCallback(() => {
    setNavOpen(false);
    applyLayoutPref("auto");
  }, [applyLayoutPref]);

  // V4: the control-plane HTTP client (grant mint + issuer pubkey + prod login). Its base URL
  // defaults to the Vite dev proxy prefix `/cp` (same-origin, no CORS) — see lib/controlplane.ts and
  // the proxy in vite.config.ts. Stable across renders.
  const logoutPendingRef = useRef<Promise<void> | null>(null);
  const authExpiredHandlerRef = useRef<() => void>(() => {});
  const authSessionRef = useRef<AuthSession | null>(null);
  if (authSessionRef.current === null) {
    authSessionRef.current = new AuthSession(() => authExpiredHandlerRef.current());
  }
  const authSession = authSessionRef.current;
  const controlPlaneRef = useRef<ControlPlaneClient>(new ControlPlaneClient({ fetch: authSession.fetch }));

  // M3: the management-console API client (machines/sessions/audit/tenants). Same `/cp` proxy
  // base + session-cookie auth as the grant client; stable across renders so the panels'
  // load-on-mount effects don't refire.
  const consoleApiRef = useRef<ConsoleApiClient>(new ConsoleApiClient({ fetch: authSession.fetch }));

  // The access panel's REAL fleet, from `GET /machines` with live presence (control-plane
  // migrations/0017). `undefined` means "not loaded" — the panel then falls back to its own
  // placeholder list, which is what keeps a control-plane-less dev shell renderable. A failed load
  // is deliberately NOT surfaced as a page error: the manual connect-by-device-id form inside the
  // panel is the path the operator (and the e2e) use to reach an agent directly, and it must keep
  // working when the control plane is absent or the caller is not logged in.
  const [fleet, setFleet] = useState<AccessMachine[] | undefined>(undefined);

  /**
   * Whether the console may show anything at all.
   *
   *   "checking" — the first probe is in flight; render nothing rather than a flash of empty panels.
   *   "required" — the control plane answered 401. Show ONLY the login screen.
   *   "open"     — either authenticated, or there is no control plane to authenticate against.
   *
   * WHY THIS EXISTS. The 401 used to be swallowed by the `catch` below, with the comment
   * "leave the panel on its fallback". The result on a real deployment was a console that rendered
   * its full navigation over an empty machine list, with no error, no login form, and no way to
   * reach one — `loginRequired` was set from exactly one place, a 401 from `mintGrant`, which
   * cannot be reached without a session in the first place. The product could not be logged into.
   *
   * "open" deliberately covers BOTH authenticated and no-control-plane. A network failure is not a
   * 401: the direct-connect/dev path has no control plane at all and must keep working, and every
   * e2e runs against StubAuthenticator, which answers 200 and never sees this gate.
   */
  const [authGate, setAuthGate] = useState<"checking" | "required" | "open">("checking");
  useEffect(() => {
    if (authGate === "open" && installRequested.current) {
      installRequested.current = false;
      const url = new URL(window.location.href);
      url.searchParams.delete("area");
      window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
      setArea("enrollment");
    }
  }, [authGate]);
  const [fleetEpoch, setFleetEpoch] = useState(0);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const epoch = authSession.epoch;
    void (async () => {
      try {
        // Fetch the machine listing and open sessions in parallel. The session fetch is best-effort:
        // a missing CapViewSessions grant (or any network error) degrades to no session badges,
        // never to a failed fleet load. Known limitation: listLiveSessions fetches all sessions and
        // filters client-side; on a high-volume tenant the server's 200-row default window could
        // truncate before reaching very old live sessions. Acceptable for the current deployment
        // size; a server-side ?live=true filter would close this gap if needed.
        // The group list is best-effort too (docs/62): it only turns the machine headings into path labels
        // ("Acme › Site A") so two groups with one name stay apart. Without it the headings stay the joined name.
        const [listing, liveSessions, groupList] = await Promise.all([
          consoleApiRef.current.listMachinesWithPresence(),
          consoleApiRef.current.listLiveSessions().catch(() => []),
          consoleApiRef.current.listMachineGroups().catch(() => []),
        ]);
        if (!cancelled && authSession.isCurrent(epoch)) {
          // Last-writer-wins when two live sessions share a machine_device_id (policy-permitted
          // concurrent sessions, or a racy close). The badge is advisory — "someone is active" —
          // not authoritative, so showing one is better than showing none.
          const liveByDevice = new Map(
            liveSessions.map((s) => [
              s.machine_device_id,
              { sessionId: s.id, startedAt: s.started_at, technicianId: s.technician_id },
            ]),
          );
          setFleet(machinesFromRecords(listing, liveByDevice, groupList));
          setAuthGate("open");
        }
      } catch (e) {
        if (cancelled || !authSession.isCurrent(epoch)) return;
        // A 401 is the ONE case that means "ask for credentials". Everything else — no control
        // plane, offline, a 500 — leaves the console usable for direct connect, as before.
        const unauth =
          (e instanceof ConsoleApiError && e.kind === "unauthenticated") ||
          (e instanceof ControlPlaneError && e.status === 401);
        setAuthGate(unauth ? "required" : "open");
      }
    })();
    return () => {
      cancelled = true;
    };
    // fleetEpoch re-runs this after a successful login. Without it the effect's [] deps left the
    // machine list empty until a full page reload — you could log in and still see nothing.
  }, [fleetEpoch, authSession]);

  // Per-tenant branding / white-label (docs/01 §9): apply the tenant's product name to the document
  // title and its accent to the `--accent` CSS variable (the whole console reads that variable). An
  // empty/invalid value falls back to the built-in CSS default. Stable so the load effect + the
  // Appearance panel's onSaved can both call it.
  const applyBranding = useCallback((b: TenantBranding) => {
    // The fallback must match index.html's <title>, or an unbranded tenant sees the tab change
    // from one to the other the moment branding resolves.
    document.title = b.product_name.trim() !== "" ? b.product_name.trim() : "DeskRally";
    const root = document.documentElement;
    if (isHexColor(b.accent_color)) {
      root.style.setProperty("--accent", b.accent_color);
    } else {
      root.style.removeProperty("--accent"); // back to the :root default in index.css
    }
    // The logo renders in the console header (React state, not a DOM mutation). Guard with the client
    // mirror so only a plain raster data: URI is ever handed to <img src> — never a value the server
    // would reject (the server is the authority; this never renders what it would not have stored).
    setBrandLogo(isLogoDataUri(b.logo_data_uri) ? b.logo_data_uri : "");
  }, []);
  const [brandLogo, setBrandLogo] = useState("");
  // The Platform area is offered only to the platform operator. Every platform request is authorized by
  // the server regardless; this only keeps the tab away from everyone else.
  const [platformOperator, setPlatformOperator] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const epoch = authSession.epoch;
      let operator = false;
      try {
        operator = (await consoleApiRef.current.platformWhoami()).operator;
      } catch {
        // Unauthenticated / older control plane — no Platform area.
      }
      if (!cancelled && authSession.isCurrent(epoch)) setPlatformOperator(operator);
    })();
    return () => {
      cancelled = true;
    };
  }, [fleetEpoch, authSession]);
  useEffect(() => {
    if (!platformOperator && area === "platform") setArea("live");
  }, [platformOperator, area]);
  // The Recordings area (docs/63 D6) is offered only when the server lets this principal list recordings: a 403 (no
  // view_recordings) or 404 (central recording not deployed) leaves it out. The console holds no capability list, so the
  // probe IS the gate; every recordings request is authorized again by the server.
  const [recordingsAllowed, setRecordingsAllowed] = useState(false);
  // Menu redesign wave 5: the capabilities GET /me reported, or null while unknown (not answered yet, or an older server
  // without the list). Unknown hides nothing; see lib/area_visibility.ts.
  const [heldCaps, setHeldCaps] = useState<ReadonlySet<string> | null>(null);
  // A recording opened from a session-history row (the Recordings area plays it on arrival).
  const [openRecordingId, setOpenRecordingId] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const epoch = authSession.epoch;
      let allowed = false;
      try {
        await consoleApiRef.current.listRecordings({ limit: 1 });
        allowed = true;
      } catch {
        // Not permitted, not deployed, or signed out: no Recordings area.
      }
      if (!cancelled && authSession.isCurrent(epoch)) setRecordingsAllowed(allowed);
    })();
    return () => {
      cancelled = true;
    };
  }, [fleetEpoch, authSession]);
  useEffect(() => {
    if (!recordingsAllowed && area === "recordings") setArea("live");
  }, [recordingsAllowed, area]);
  // An area the user's capabilities rule out (a deep link, or capabilities that changed) falls back to Live, like the
  // platform and recordings probes above.
  useEffect(() => {
    if (!areaVisible(area, heldCaps)) setArea("live");
  }, [heldCaps, area]);
  const visibleAreas = useMemo(
    () => CONSOLE_AREAS.filter((a) => (a.id !== "platform" || platformOperator) && (a.id !== "recordings" || recordingsAllowed)
      && areaVisible(a.id, heldCaps)),
    [platformOperator, recordingsAllowed, heldCaps],
  );
  // Menu redesign wave 10: the active page's siblings, drawn as tabs above it (History: Sessions | Audit ...).
  const areaSubtabsHere = useMemo(() => areaSubtabs(visibleAreas, area), [visibleAreas, area]);
  // "Signed in as" in the app menu, next to Sign out.
  const [signedInAs, setSignedInAs] = useState<string | null>(null);
  // docs/56: the signed-in user's access has expired (they can sign in but may do nothing), with when.
  const [accessEnded, setAccessEnded] = useState<{ at: string | null } | null>(null);
  // docs/57: the signed-in user is outside their access hours right now (window null = varying hours).
  const [outsideHours, setOutsideHours] = useState<{ window: AccessWindow | null } | null>(null);
  // Operator notifications (docs/01 §7 P1): poll the audit trail while signed in and surface notable
  // events in the topbar bell. Best-effort; see use_audit_notifications.ts.
  const notifications = useAuditNotifications(consoleApiRef.current, signedInAs);
  useEffect(() => {
    let cancelled = false;
    const epoch = authSession.epoch;
    consoleApiRef.current.me().then(
      (me) => {
        if (!cancelled && authSession.isCurrent(epoch)) {
          setSignedInAs(me.email);
          setHeldCaps(heldCapabilities(me.capabilities));
          setAccessEnded(me.accessExpired ? { at: me.accessExpiresAt } : null);
          setOutsideHours(!me.accessExpired && me.accessOutsideWindow ? { window: me.accessWindow } : null);
        }
      },
      () => { if (!cancelled) { setSignedInAs(null); setHeldCaps(null); setAccessEnded(null); setOutsideHours(null); } },
    );
    return () => {
      cancelled = true;
    };
  }, [fleetEpoch, authSession]);
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const epoch = authSession.epoch;
        const b = await consoleApiRef.current.getTenantBranding();
        if (!cancelled && authSession.isCurrent(epoch)) applyBranding(b);
      } catch {
        // Unauthenticated / no control plane — keep the built-in defaults.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [applyBranding, fleetEpoch, authSession]);

  // Privacy: the guest-input block and monitor blank live only while connected. The agent
  // force-releases both on its side the instant the session tears down, so a dropped/failed
  // connection must clear the indicators here too — otherwise buttons would keep asserting
  // "blocked"/"blanked" for a machine that is no longer reachable.
  useEffect(() => {
    if (state !== "connected") {
      setInputBlocked(false);
      // Monitor blank is per-session (the agent removes the overlay on teardown); must not persist.
      setMonitorBlanked(false);
      // View-only is per-session (the agent clears it on teardown); the indicator must not persist.
      setViewOnly(false);
      // NOT `observing`: it is the user's choice for THIS connect, set by connectImpl while the state
      // may still read idle, and cleared by teardown/disconnect. Clearing it here undid it.
      // A "Launched X" notice is meaningless once the session is gone.
      setToolStatus(undefined);
      // A stale command output / a stuck "running" would mislead on the next connect.
      setCommandResult(undefined);
      setCommandPending(false);
      // Elevation is per-SESSION: a grant names one control-plane session id and no other. Carrying
      // "you may elevate" (or a stale refusal) into the next connection would offer a control that
      // cannot work — and `<Viewer/>` is rendered with no `key`, so its own state survives a
      // reconnect to a DIFFERENT machine unless this clears here.
      setCanElevate(false);
      setElevationError(undefined);
      if (elevationTimeoutRef.current !== null) {
        clearTimeout(elevationTimeoutRef.current);
        elevationTimeoutRef.current = null;
      }
      // (the ENABLE side lives at the bottom of this effect — see the note there)
      // A stale "screenshot saved" line is meaningless once the session is gone.
      setScreenshotStatus(undefined);
      // Recording is per-SESSION and the agent finalizes it in its own teardown, so the console must
      // stop claiming one is running the moment the session drops — a badge that says "Recording"
      // for a machine we can no longer reach is a false statement about somebody's screen. The
      // RESULT is deliberately kept: it is the operator's only record of where the files landed, and
      // a session that dropped mid-recording is exactly when they need to read it. It clears on the
      // next connect (below), where it would otherwise describe the wrong machine.
      setRecording(false);
      setRecordingPending(false);
      // Likewise a stale "ending session…" once we're disconnected.
      setEndSessionStatus(undefined);
      // File-browser state is per-session — the paths belong to the machine we just left.
      agentTransferDirRef.current = undefined;
      setAgentTransferDir(undefined);
      setAdminRights(NO_ADMIN_RIGHTS);
      setInputHandoff(NO_INPUT_HANDOFF);
      setDirListing(undefined);
      setDirLoading(false);
      setDirError(undefined);
      dirPendingPathRef.current = null;
      if (dirTimeoutRef.current !== null) {
        clearTimeout(dirTimeoutRef.current);
        dirTimeoutRef.current = null;
      }
      return;
    }
    // CONNECTED. Elevation needs a control-plane session record to mint an elevation grant against,
    // which the attended path (`preAcquired`) and the direct-connect fallback do not have.
    //
    // Derived HERE and not in `connect()`, and this is the whole reason the note exists: `connect()`
    // sets `brokeredSessionRef` while the state is still "signaling", and every later transition
    // that is not "connected" re-runs this effect and clears the flag. Setting it there meant it was
    // switched on once and switched off again a moment later by "connecting" — so the "Run as admin"
    // button never rendered and the entire feature was inert in the viewer while every other layer
    // worked. (Loop 80 shipped exactly this shape once before; the adversarial review caught it both
    // times.) The enable and the reset now live in ONE place, keyed on ONE condition.
    setCanElevate(brokeredSessionRef.current !== null);
  }, [state]);

  // Live objects for the current session; refs so callbacks and teardown reach them without
  // re-rendering churn.
  const transportRef = useRef<WebRTCTransport | null>(null);
  // Stable callback for ConnectionDiagnostics — wraps the ref so identity never changes.
  const getTransportStats = useCallback(() => transportRef.current?.getStats() ?? Promise.resolve(undefined), []);
  const sessionGeneration = useRef(0);
  const [recoveryNotice, setRecoveryNotice] = useState<RecoveryNotice | null>(null);
  // Signaling brokered this session WITHOUT a relay credential (the account is at its cap on outstanding
  // ones), so only a direct connection can succeed. `relayNotice` is what the CURRENT transport reported,
  // set from its `onRelayNotice` and reset with it; the banner shows it (components/RelayNotice.tsx).
  // The dismissal is the technician's and is about the MACHINE they are looking at, not about a transport:
  // every reconnect builds a new transport that reports the same cap, and none of them may resurrect a banner
  // they closed. Reconnects reach `connectImpl` by more than one road and only recovery is `teardown(true)`:
  // a display-layout end reconnects by itself through `reconnectManually`, a fresh connect like the Reconnect
  // button, whose teardown cannot tell it from a click on the machine list. So the dismissal is keyed by the
  // device it was made for and ends only with a disconnect or a connect to ANOTHER machine, never with a
  // transport. Dismissing hides the banner only; a failure still names the cause.
  const [relayNotice, setRelayNotice] = useState<string | null>(null);
  const [relayNoticeDismissedFor, setRelayNoticeDismissedFor] = useState<DeviceId | null>(null);
  const retryConnection = useRef<(isCurrent: () => boolean) => Promise<void>>(async () => {});
  const recovery = useRef<SessionRecovery | null>(null);
  const layoutReconnectBudget = useRef(new LayoutReconnectBudget());
  const reconnectManuallyRef = useRef<() => void>(() => {});
  const recoveryStoppedRef = useRef<() => void>(() => {});
  if (!recovery.current) recovery.current = new SessionRecovery((isCurrent) => retryConnection.current(isCurrent), setRecoveryNotice,
    () => recoveryStoppedRef.current());
  const recoveryTarget = useRef<{ device: DeviceId; name: string; url: string; attended: boolean; observe?: boolean } | null>(null);
  const signalingRef = useRef<SignalingClient | null>(null);
  const controlRef = useRef<ControlClient | null>(null);
  // Which windows showing the session are hidden (background mode, see `onViewerVisibility`).
  const backgroundTracker = useRef(new BackgroundTracker());
  // Loops 79/80 — the session ACCESS policy. `policyPendingRef` marks an InstallSessionPolicy awaiting its
  // reply so a rejection (which arrives as a plain `Error`) can be told apart from a command failure.
  const policyPendingRef = useRef(false);
  // 0044 — tracks whether we have already auto-sent StartRecording for a require_recording=true policy.
  // Prevents double-send when the lease renews (each renewal delivers a fresh SessionPolicyInstalled).
  const requireRecordingPendingRef = useRef(false);
  // docs/25 F03 — the session LEASE. One renewer for the console's life; `start` switches it to the
  // live session and `stop` (from teardown) ends it. The loop itself lives in `lib/session_lease.ts`
  // rather than in this closure, so it is reachable by a test — the "feature inert at its untested
  // layer" shape this file has shipped once already, with loop 80's session policy.
  const leaseRenewerRef = useRef<SessionLeaseRenewer | null>(null);
  const leaseTransportStateRef = useRef<ConnectionState>("idle");
  // Latched once the agent asks for a lease on a connection that has no control-plane session record
  // to renew against (direct connect). Stops the agent's re-announcements re-raising the banner.
  const leaseUnrenewableRef = useRef(false);
  const backstageRef = useRef<ChannelBackstageTransport | null>(null);
  const fileTransferRef = useRef<FileTransferClient | null>(null);
  const clipboardRef = useRef<ClipboardClient | null>(null);
  const chatRef = useRef<ChatClient | null>(null);
  // Monotonic id bumped per completed download so the Files panel saves each one exactly once.
  const downloadSeq = useRef(0);
  // M2: the control-plane session record backing the current brokered connection (null on the
  // direct-connect fallback). Ended best-effort on teardown.
  const brokeredSessionRef = useRef<string | null>(null);
  // Loop 87: the deadline armed on an in-flight `ElevatedRun`, so an agent that never answers cannot
  // leave the command bar disabled forever. Cleared by either verdict and by disconnect.
  const elevationTimeoutRef = useRef<number | null>(null);
  // H2/ADR-008: the audit forwarder for the current session, plus its flush timer. One per
  // brokered session — the forwarder is keyed on a session id and drops events from any other, so
  // reusing one across connections would silently discard the new session's trail.
  const auditForwarderRef = useRef<AuditForwarder | null>(null);
  const auditFlushTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // The session id the CURRENT forwarder is keyed on: the CONTROL-PLANE session id, since loop 91.
  const auditSessionIdRef = useRef<string | null>(null);
  // M11: the "did the agent ever answer RequestQuality?" timer. In a ref so the ControlClient's
  // handler (built once per connect) can cancel it, and so teardown can clear a pending one — a
  // stray fire after disconnect would mark the NEXT agent unsupported before it had answered.
  const qualityProbeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  /**
   * Open the audit forwarder for a brokered SESSION, and start flushing it.
   *
   * **The id is the CONTROL-PLANE session id, since loop 91** — one forwarder per connection, opened
   * as soon as the session record exists and before any grant.
   *
   * It used to be per GRANT, which was correct for the code as it stood: the agent built its
   * `AuditChain` inside `Dispatcher::new` from `grant.session_id`, and an install replaced the
   * dispatcher, so each install genuinely started a new chain at seq 0. Two consequences followed,
   * and loop 91 removed the cause of both by lifting the chain to the session:
   *
   *  * a session with NO grant produced no chain at all, so a session recording and a REFUSED file
   *    transfer had nowhere to record — the whole reason for the lift; and
   *  * a second "Get access" (reachable on any denial whose message matches /grant/i) forked the
   *    trail, and this forwarder's seq-keyed dedupe then silently discarded the fork.
   *
   * The agent now stamps every event with the control-plane session id signaling vouched for, and
   * `enqueue` DROPS events whose `session_id` differs from the forwarder's — so keying on anything
   * else here would discard the entire trail rather than part of it. The two ids must be one value.
   *
   * `null` when there is no control-plane session (direct-connect / dev): `makeAuditForwarder`
   * returns null, nothing is forwarded, and the agent seals nothing either — the same fail-closed
   * reading on both sides of the wire, which is what keeps the chain contiguous.
   */
  const openSessionAuditForwarder = useCallback((sessionId: string | null) => {
    if (auditFlushTimer.current !== null) {
      clearInterval(auditFlushTimer.current);
      auditFlushTimer.current = null;
    }
    void auditForwarderRef.current?.flush().catch(() => setError("Audit forwarding failed; the audit trail may be incomplete."));

    auditSessionIdRef.current = sessionId;
    auditForwarderRef.current = makeAuditForwarder(consoleApiRef.current, sessionId, (e) => setError(e.message));
    if (auditForwarderRef.current) {
      auditFlushTimer.current = setInterval(() => {
        void auditForwarderRef.current?.flush().catch(() => setError("Audit forwarding failed; the audit trail may be incomplete."));
      }, AUDIT_FLUSH_INTERVAL_MS);
    }
  }, []);

  /** Buffer a recording ack's sealed audit event into the live session forwarder. */
  const enqueueSealedAudit = useCallback((audit: SealedAuditEvent) => {
    enqueueSealedAuditInto(auditForwarderRef.current, audit);
  }, []);

  /**
   * Stop renewing the live session's lease (docs/25 F03). Idempotent; safe with a request in flight
   * (the renewer re-checks which session it is renewing after every await).
   */
  const stopRenewingLease = useCallback(() => {
    leaseRenewerRef.current?.stop();
    leaseUnrenewableRef.current = false;
  }, []);

  // Recovery stopped for good (refused, or its 2-minute window ran out). While it ran it kept the session record so
  // a retry could check the original was still authorized; now nothing will reconnect, so end the record NOW, while
  // this page's sign-in is still valid. Production 2026-11-09: the last retry's record (4c1f4541) was minted, its
  // connect failed, recovery gave up from that failed retry (no transport event, so the terminal-transport release
  // below never ran), and the record waited 2 h for a teardown whose /end then got a 401: a leaked live row.
  // Not while the transport is still connected (a guest shutting down, an agent ending the session): that path
  // releases the record itself when the connection drops, and ending it early would cut the lease under the user.
  recoveryStoppedRef.current = () => {
    if (leaseTransportStateRef.current === "connected") return;
    stopRenewingLease();
    releaseBrokeredSession(consoleApiRef.current, brokeredSessionRef.current);
    brokeredSessionRef.current = null;
  };

  /**
   * The transport changed state — and a TERMINAL state must RELEASE the session, not merely
   * repaint a status line.
   *
   * `onStateChange` used to be `setState` alone, so a dead transport was a label in the corner and
   * nothing more. That is the zombie session (docs/25 F03; observed in production 2026-09-02): the
   * agent is gone, but the console keeps renewing the lease every 10 s against a control plane that
   * has no idea, so the session record stays alive with nothing on the other end — and the NEXT
   * connect to that machine hangs on "connecting" behind a session that will never end. The
   * operator's own captured renewals showed exactly this: two more 200s AFTER the picture died.
   *
   * `failed` releases immediately. A leased session gets a 60-second recovery window after
   * `disconnected`; reconnecting cancels it. Do not depend on browsers eventually emitting failed.
   */
  const handleTransportState = useCallback(
    // `lostMessage` overrides the generic "Connection lost" when the caller knows WHY (an offline agent).
    // `relayCause` is set only by the transport itself, for a connection that never came up while signaling
    // had withheld its relay credential (WebRTCTransport.relayLimitCause): the technician is then told the
    // relay limit is the likely cause, not left with a bare "Connection lost" for what is usually a
    // restrictive network. Callers that know the reason (offline, a refused lease) pass none.
    (s: ConnectionState, lostMessage?: string, relayCause: string | null = null) => {
      leaseTransportStateRef.current = s;
      setState(s);
      if (s === "disconnected") leaseRenewerRef.current?.notifyTransportDisconnected();
      if (s === "connected") leaseRenewerRef.current?.notifyTransportConnected();
      if(s === "connected") recovery.current?.connected();
      const lost = withRelayLimitCause("Connection lost", relayCause);
      if(s === "disconnected" || s === "failed") recovery.current?.lost(lostMessage ??
        (recoveryTarget.current?.attended ? `${lost}. Return to Support to reconnect with guest consent` : lost));
      if(s === "failed") stopRenewingLease();
      // Keep the old record until recovery checks that it is STILL authorized. A fresh
      // session must not undo an administrator ending the original one.
      const released = !recovery.current?.enabled && releaseSessionOnTerminalTransport(s, {
        stopRenewing: stopRenewingLease,
        release: () => {
          releaseBrokeredSession(consoleApiRef.current, brokeredSessionRef.current);
          brokeredSessionRef.current = null;
        },
      });
      // Keep any more specific message that already explained the failure.
      if (released) {
        setError(
          (prev) =>
            prev ??
            `${withRelayLimitCause("the connection to this machine was lost", relayCause)} — the session has been released; reconnect to continue`,
        );
      }
    },
    [stopRenewingLease],
  );

  /**
   * Start renewing the lease for `sessionId`, and keep renewing until teardown (docs/25 F03).
   *
   * Driven by the AGENT's `SessionLeaseRequired`, never assumed. The console cannot tell whether a
   * given agent is able to verify a signed policy — `grant_issuer_pubkey` is optional in agent
   * config and an agent without one fails CLOSED on any policy it is sent — so a console that
   * renewed unconditionally would drop every such agent in the fleet to view-only. The agent is the
   * only party that knows, so the agent asks and this responds.
   *
   * **If this stops, the session ends.** That is the point of the mechanism: the control plane
   * refuses to mint once an administrator has ended the session, so a technician who has been cut
   * off cannot keep the desktop by ignoring the console.
   */
  const startRenewingLease = useCallback((sessionId: string) => {
    if (leaseRenewerRef.current === null) {
      leaseRenewerRef.current = new SessionLeaseRenewer({
        renew: (id, signal) => consoleApiRef.current.renewSessionPolicy(id, signal),
        install: (signed) => {
          // Marked pending so the agent's answer is ATTRIBUTED to the policy rather than reported as
          // a generic agent error — the same single-pending attribution the initial install uses.
          policyPendingRef.current = true;
          // Forwarded VERBATIM: the signature covers the claims and the agent re-derives the
          // canonical preimage from exactly these bytes, so re-serializing here would break every
          // lease in a way that looks like a crypto bug.
          controlRef.current?.installSessionPolicy(signed);
        },
        onRefused: (message) => {
          const transient = message === "transport disconnected";
          // Handed to a colleague (docs/51): say so and to whom, rather than "the session has ended".
          const live = outgoingTransferRef.current;
          const transferred = transient ? null
            : senderTransferredMessage(message, live?.accepted_by_name || live?.to_name);
          if (transferred) {
            recovery.current?.refuse(transferred);
            setOutgoingTransfer(null);
            handleTransportState("failed");
            transportRef.current?.close();
            signalingRef.current?.close();
            setError(transferred);
            return;
          }
          if (!transient) recovery.current?.refuse(`Session ended: ${message}. Reconnect manually if permitted.`);
          // Stop the actual transport and release the record, not just the renewal timer.
          handleTransportState("failed");
          transportRef.current?.close();
          signalingRef.current?.close();
          setError(transient ? "Connection interrupted — attempting to reconnect" :
            `This session has ended (${message}) — reconnect manually if permitted`);
        },
      });
    }
    leaseRenewerRef.current.start(sessionId);
    // A queued agent announcement may arrive after the disconnect state notification.
    if (leaseTransportStateRef.current === "disconnected") {
      leaseRenewerRef.current.notifyTransportDisconnected();
    }
  }, [handleTransportState]);

  const teardown = useCallback((preserveRecovery = false) => {
    sessionGeneration.current++;
    // A hand-off offer belongs to the session being torn down (docs/51): it ends with it.
    setOutgoingTransfer(null);
    setTransferDialogOpen(false);
    if (!preserveRecovery) { recovery.current?.cancel(); recoveryTarget.current=null; grantHeldRef.current = false; }
    grantOpRef.current.reset(); // any in-flight grant operation loses ownership with its session
    setGrantResumeNotice(null);
    // Flush BEFORE ending the session record: the last commands of a session are the ones most
    // worth having centrally, and they are still buffered at this point. Fire-and-forget, because
    // teardown also runs from an unmount (see the effect below) and must not await anything.
    if (auditFlushTimer.current !== null) {
      clearInterval(auditFlushTimer.current);
      auditFlushTimer.current = null;
    }
    // keepaliveFirstBatch: teardown also runs from `pagehide`, where an ordinary fetch is abandoned.
    void auditForwarderRef.current?.flush({ keepaliveFirstBatch: true }).catch(() => setError("Audit forwarding failed; the audit trail may be incomplete."));
    auditForwarderRef.current = null;
    auditSessionIdRef.current = null;

    if (qualityProbeTimer.current !== null) {
      clearTimeout(qualityProbeTimer.current);
      qualityProbeTimer.current = null;
    }
    // Stop renewing (docs/25 F03). Clearing `leaseSessionRef` as well as the timer is what makes the
    // stop reliable: a renewal already in flight resolves AFTER this runs, and its continuation
    // checks the id before installing anything or rescheduling itself.
    stopRenewingLease();

    releaseBrokeredSession(consoleApiRef.current, brokeredSessionRef.current);
    brokeredSessionRef.current = null;
    backstageRef.current?.close(); // reject any in-flight backstage correlation
    transportRef.current?.close();
    signalingRef.current?.close();
    transportRef.current = null;
    signalingRef.current = null;
    controlRef.current = null;
    backstageRef.current = null;
    // Dispose BEFORE clearing the ref so an in-flight digest cannot deliver into a stale app: the
    // client latches disposed, drops receiving buffers, and resolves any pending upload ack.
    fileTransferRef.current?.dispose();
    fileTransferRef.current = null;
    // docs/25 F08: dispose BEFORE clearing the ref. Dispose latches the client into a state that
    // drops any late inbound frames and refuses async sends after the reader has already resolved,
    // so a slow readText that arrives during teardown cannot push through a stale transport.
    clipboardRef.current?.dispose();
    clipboardRef.current = null;
    chatRef.current = null;
    setBackstageClient(null);
    setFileTransferClient(null);
    setClipboardClient(null);
    setClipboardNotice(null);
    // The relay notice describes how THIS transport was brokered; the next one reports its own. Its dismissal
    // is deliberately NOT reset here: it belongs to the machine, not to the transport, and teardown runs for
    // every reconnect (see where it is declared).
    setRelayNotice(null);
    // M12: the transcript belongs to the MACHINE, not to the console. Carrying one session's
    // conversation into the next would show the operator another customer's messages, and the
    // sequence numbers — which are per machine — would collide with the next agent's.
    setChatClient(null);
    setChatMessages([]);
    setChatTruncated(false);
    setDownload(null);
    pendingBrowseRelsRef.current.clear();
    setCompletedBrowseRelPaths(new Set());
    setBrowseUploads([]);
    setPendingDownloads([]);
    setGrantInstalled(false);
    setBackstageFeatures(new Set());
    setGrantCapabilities(null);
    agentTransferDirRef.current = undefined;
    setAgentTransferDir(undefined);
    setAdminRights(NO_ADMIN_RIGHTS);
    setInputHandoff(NO_INPUT_HANDOFF);
    pendingMachineAliasRef.current = undefined;
    setMachineAlias(undefined);
    // The session ACCESS policy is per-SESSION, so it must not survive teardown. Left set, the next
    // connection inherits the previous machine's "policy enforced" lock: the view-only toggle renders
    // disabled with an organisation-mandate tooltip for a group that mandated nothing. It cannot go the
    // other way (a policy always re-asserts itself on install), but a console that claims a mandate that
    // does not exist is still lying to the operator — and on the attended path, which installs no policy
    // at all, nothing would ever correct it.
    setSessionPolicyState(null);
    policyPendingRef.current = false;
    requireRecordingPendingRef.current = false;
    // The block and the monitor blank are properties of the AGENT's session and are force-released
    // on the agent when the session ends; clear the indicators so a console kept open across sessions
    // never shows a stale "blocked"/"blanked" for the next machine.
    setInputBlocked(false);
    setMonitorBlanked(false);
    setViewOnly(false);
    observingRef.current = false;
    setObserving(false);
    // Clear any in-flight reboot notice: a fresh connect means either the reboot completed (the agent
    // is back) or we moved to a different machine. Either way the "Rebooting…" line is now stale.
    setRebootStatus(undefined);
    // Same as the reboot notice: a fresh connect means the logoff completed (we're back at the sign-in
    // screen, or a new user is on) or we moved machines — either way "Logging off…" is now stale.
    setLogoffStatus(undefined);
    // A fresh connect means the machine was powered back on and re-registered — the "shutting down" line
    // is now stale.
    setShutdownStatus(undefined);
    setToolStatus(undefined);
    // A recording summary names a directory on the machine we just left; carrying it into the next
    // session would point the operator at a path that does not exist on this host.
    setRecording(false);
    setRecordingPending(false);
    setRecordingResult(undefined);
    // Quality is a property of the AGENT, not of the console: carrying the last machine's applied
    // settings, telemetry or support verdict into the next session would describe the wrong host.
    // The reset also drops any outstanding-reply count — the next agent will not answer this one's.
    dispatchQuality({ type: "reset" });
    setQualityStats(null);
    setQualitySupported(undefined);
    // Multi-Tech: participant count belongs to the session; clear so a stale "2 techs" badge
    // never carries into the idle state or the next machine's session.
    setSessionParticipantCount(0);
    setSessionObserverCount(0);
    setParticipants([]);
    setOwnSignalingId(null);
  }, [stopRenewingLease]);

  const disconnectSession = useCallback(() => {
    teardown();
    setSession(null);
    // The technician is leaving the machine: connecting to it again is a new session and brings the relay
    // notice back if the account is still at its cap.
    setRelayNoticeDismissedFor(null);
    setState("idle");
    setView("screen");
    setStream(null);
    setMonitors([]);
    setPinnedMonitorId(undefined);
    setMonitorCanvas(undefined);
    monitorCanvasRef.current = undefined;
    setError(null);
  }, [teardown]);

  // The connect body. NOT called directly — `handleConnect` below wraps it in the re-entrancy
  // guard, and every caller must go through that. See `onceAtATime` for what happens without it.
  const connectImpl = useCallback(
    async (device: DeviceId, name: string, signalingUrl: string, preAcquired?: BrokeredSession, recovering = false, observe = false) => {
      const authEpoch = authSession.epoch;
      if (!authSession.isCurrent(authEpoch)) return;
      // Capture BEFORE teardown — teardown clears pendingMachineAliasRef as a safety measure
      // (prevents a stale alias from surviving into unrelated teardown paths such as unmount).
      const pendingAlias = pendingMachineAliasRef.current;
      // Drop any prior session before starting a new one.
      teardown(recovering);
      // A relay notice the technician dismissed stays dismissed for a reconnect to the SAME machine (recovery, a
      // display-layout reconnect, the Reconnect button) and ends with a connect to another one.
      setRelayNoticeDismissedFor((kept) => (kept === device ? kept : null));
      if (observe) preAcquired = undefined;
      // A pre-acquired session is the ATTENDED hand-off (its record is not ours to renew or end) unless it
      // is marked owned: a session transfer's S2, which is an ordinary session in every respect (docs/51).
      const attendedPath = !!preAcquired && !preAcquired.owned;
      observingRef.current = observe;
      setObserving(observe);
      if(!recovering) recoveryTarget.current={device,name,url:signalingUrl,attended:attendedPath,...(observe ? {observe:true} : {})};
      const generation=sessionGeneration.current;
      const isCurrent=()=> authSession.isCurrent(authEpoch) && sessionGeneration.current === generation;
      setSession({ device, name });
      setMachineAlias(pendingAlias);
      setView("screen");
      setStream(null);
      setMonitors([]);
    setPinnedMonitorId(undefined);
    setMonitorCanvas(undefined);
    monitorCanvasRef.current = undefined;
      setAudioAvailable(false);
      setError(null);
      setState("signaling");

      // M2 brokered path: start a control-plane session FIRST; when it succeeds we dial the
      // RETURNED signaling URL and present the signed session ticket in connect_request. When
      // the control plane is unreachable (dev flow / e2e without one) this resolves null and we
      // keep the direct-connect behavior against the operator-entered URL.
      //
      // The ATTENDED path arrives with `preAcquired` — its ticket was already minted by the
      // consent gate (POST /attended-sessions/{id}/connect), so we must not POST /sessions for
      // the ephemeral device, and teardown must NOT end it as a session record (attended
      // sessions end via their own endpoint/panel), so brokeredSessionRef stays null.
      let brokered: BrokeredSession | null;
      try {
        const request = observe
          ? acquireBrokeredSession(consoleApiRef.current, device, undefined, {access:"view_only"})
          : preAcquired ? Promise.resolve(preAcquired) : recovering
          ? consoleApiRef.current.startBrokeredSession(device).then(started => {
              if(!started.signaling) throw new RecoveryRefused("No authorized signaling endpoint is available");
              return {sessionId:started.session.id, signaling:started.signaling, sessionPolicy:started.session_policy};
            })
          : acquireBrokeredSession(consoleApiRef.current,device);
        brokered=preAcquired ?? await withDeadline(request,15000,late=> {
          releaseBrokeredSession(consoleApiRef.current,late?.sessionId);
        });
      } catch(error) {
        if(!isCurrent()) return;
        setState("failed");
        if(recovering) throw isRefusal(error) ? new RecoveryRefused(`Reconnect refused: ${(error as Error).message}`) : error;
        // 403 from POST /sessions: authenticated but not authorized for this device.
        // Show a visible device-refusal error — do NOT fall through to direct-connect.
        // On a production signaling server the ticketless fallback would also fail, but the
        // viewer must fail-closed and surface the reason immediately rather than silently
        // opening a socket that signaling will reject.
        if (isDeviceAccessDenied(error)) {
          setError(observe ? "Not authorized to observe this machine" : "Not authorized to connect to this device. Contact your administrator.");
          return;
        }
        if (observe && error instanceof Error && "status" in error && error.status === 409) {
          setError(error.message);
          return;
        }
        recovery.current?.lost("Unable to establish the session. Try reconnecting");
        return;
      }
      if (!isCurrent()) {
        if (!attendedPath) releaseBrokeredSession(consoleApiRef.current, brokered?.sessionId);
        return;
      }
      recovery.current!.enabled=!!brokered && !attendedPath;
      brokeredSessionRef.current = attendedPath ? null : (brokered?.sessionId ?? null);
      // NOTE: `canElevate` is NOT set here. It is derived from this ref in the `[state]` effect
      // above, when the connection reaches "connected" — see the comment there for why setting it
      // at this point was a bug that made the whole feature inert.

      // H2/ADR-008: open the forwarder NOW, on the control-plane session id, before any grant.
      // Since loop 91 the agent's chain is the SESSION's — it exists from the moment the session is
      // brokered, and its first event can be a refused file transfer or a recording, neither of
      // which needs a grant. Waiting for `GrantInstalled` would drop exactly those.
      //
      // From `brokered`, NOT from `brokeredSessionRef` — the two differ on the ATTENDED path and
      // getting that wrong loses the whole trail. `brokeredSessionRef` is deliberately null for an
      // attended session so that TEARDOWN does not end its session record (attended sessions end
      // through their own endpoint), which is a statement about ownership, not about identity. The
      // attended ticket is minted by the consent gate and carries a real control-plane session id,
      // signaling verifies it, and the agent seals every event under it — so keying the forwarder
      // off the ref would leave the agent chaining a trail nothing ever forwards.
      openSessionAuditForwarder(auditSessionIdFor(brokered));

      const signaling = new SignalingClient(brokered?.signaling.url ?? signalingUrl);
      signalingRef.current = signaling;
      try {
        await signaling.open();
        if (!isCurrent()) { signaling.close(); return; }
        // Register a controller identity BEFORE connect_request: the broker echoes the requester's
        // DeviceId to the agent as `Brokered.peer_device`; an unregistered controller sends an empty
        // id the Rust agent cannot decode (it would silently drop the broker and hang).
        signaling.send({
          type: "register_agent",
          device: asDeviceId(crypto.randomUUID()),
          pubkey: "ed25519:browser-controller",
          nat: "unknown",
          enrollment_token: null,
        });
        // Multi-Tech: subscribe to participant-list pushes BEFORE transport.connect() fires
        // connect_request, so the first session_participants message (which arrives right after
        // brokered + relay_assignment) is never missed. The SignalingClient clears all handlers
        // on close(), so no explicit unsubscribe is needed — teardown() calls signaling.close().
        //
        // ownSignalingSessionId captures the session id the signaling server assigns to this
        // controller in the "brokered" message (broker.go newUUID at lines 197–202). This is
        // DISTINCT from brokered?.sessionId, which is the control-plane RECORD id returned by
        // POST /sessions. session_participants entries use the signaling session id (s.Id), so
        // self-filtering must use the same id — not the CP record id.
        let ownSignalingSessionId: string | null = null;
        signaling.onMessage((msg) => {
          if (!isCurrent()) return;
          if (msg.type === "brokered") {
            if (observingRef.current && (msg.access !== "view_only" || msg.access_version !== 1)) {
              disconnectSession();
              setError(OBSERVE_UNSUPPORTED);
              return;
            }
            // Capture our signaling-level session id the moment the server assigns it. Participant
            // entries will use this exact id, so we record it before any participant push arrives.
            ownSignalingSessionId = msg.session;
            setOwnSignalingId(msg.session);
            return;
          }
          if (msg.type === "session_participants") {
            // Guard: only update for the machine we connected to. The signaling server may push
            // participant lists for multiple devices on the same connection (future multiplexing).
            if (msg.device_id !== device) return;
            // Filter ourselves out using the SIGNALING session id (not the CP record id). When
            // no signaling session id is known yet (direct-connect path or brokered arrives after
            // first push) include all participants — a transient over-count is safer than a
            // permanent under-count.
            const peers = ownSignalingSessionId
              ? msg.participants.filter((p) => p.session_id !== ownSignalingSessionId)
              : msg.participants;
            setSessionParticipantCount(peers.length);
            setSessionObserverCount(peers.filter(p => p.access === "view_only").length);
            // docs/61: the full list (including us) — the hand-off view filters itself and observers out.
            setParticipants(msg.participants);
          }
        });
      } catch (e) {
        if (!isCurrent()) return;
        setError(`signaling failed: ${(e as Error).message}`);
        handleTransportState("failed");
        if(recovering) throw e;
        return;
      }

      // Control client: monitor enumeration/selection over ChannelId.Control. Its `send` frames onto
      // the transport we are about to build (closure captures the ref).
      const control = new ControlClient(
        (payload) => transportRef.current?.send(ChannelId.Control, payload),
        {
          onMonitors: (list) => setMonitors([...list]),
          onMonitorPinned: (monitorId) => setPinnedMonitorId(monitorId),
          onMonitorCanvas: (canvas) => { monitorCanvasRef.current = canvas; setMonitorCanvas(canvas); },
          // The agent verified the policy and reported the state in force. `viewOnly` is EFFECTIVE, not
          // simply the level the policy carried — the agent applies a policy as a one-way ratchet, so a
          // stricter one already in force still wins.
          onSessionPolicyInstalled: (access, viewOnly, allowRecording, requireRecording) => {
            policyPendingRef.current = false;
            // The agent VERIFIED a control-plane-signed policy, so it is lease-capable: start (or keep)
            // renewing now instead of relying only on its SessionLeaseRequired announcement. That
            // announcement goes out once, at the agent's first loop iteration, and stops as soon as
            // the console's initial policy is installed (~15 ms later). When it raced ahead of this
            // client's frame handling it was lost, nothing renewed, and the session died at the lease
            // expiry (~30 s) — measured 3 of 4 runs for observers, and in production 2026-10-19. An
            // agent that cannot verify never sends SessionPolicyInstalled, so this cannot drop such a
            // fleet to view-only. Idempotent: start() ignores the session it is already renewing.
            const leaseSession = brokeredSessionRef.current;
            if (leaseSession) startRenewingLease(leaseSession);
            setSessionPolicyState({ enforced: viewOnly, applied: true, note: `policy: ${access}`, allowRecording, requireRecording });
            if (viewOnly) setViewOnly(true);
            // Auto-start recording when the group policy requires it. Guard with the pending ref so
            // lease renewals (each of which fires this callback) don't send a second StartRecording
            // while the first one is still in flight or after recording is already running.
            if (requireRecording && !requireRecordingPendingRef.current) {
              requireRecordingPendingRef.current = true;
              controlRef.current?.startRecording();
            }
          },
          // docs/25 F03 — the agent says this session runs on a control-plane LEASE. Start renewing,
          // and keep renewing until teardown; if we stop, the agent ends the session, which is
          // exactly how an administrator's "End session" reaches an unattended desktop.
          //
          // Only a BROKERED session can be renewed: `POST /sessions/{id}/policy` addresses a
          // `session_record`, which only the brokered path creates. An agent that asks on a
          // direct-connect session is telling us something we cannot act on, so say so once rather
          // than starting a renewal loop that would 404 forever.
          onSessionLeaseRequired: () => {
            const sessionId = brokeredSessionRef.current;
            if (!sessionId) {
              if (!leaseUnrenewableRef.current) {
                leaseUnrenewableRef.current = true;
                setError(
                  "this machine requires a control-plane session lease, but this connection was " +
                    "not brokered by the control plane — it will end shortly",
                );
              }
              return;
            }
            startRenewingLease(sessionId);
          },
          // Loop 87: the agent REFUSED an elevated run — nothing executed. Deliberately its own
          // callback and not `onError`, because "the command failed" and "the command never started
          // and the elevation was declined" are different facts about whether a privileged action
          // happened. It also has to clear `commandPending`, or the Run button stays disabled.
          onElevationDenied: (reason) => {
            if (elevationTimeoutRef.current !== null) {
              clearTimeout(elevationTimeoutRef.current);
              elevationTimeoutRef.current = null;
            }
            setCommandPending(false);
            setElevationError(reason);
            // The mirror of `onCommandResult`'s clear: a refusal means NOTHING ran, so a previous
            // command's output must not sit under "Elevation refused" as if it were this attempt's.
            setCommandResult(undefined);
          },
          onError: (message) => {
            if(!isCurrent()) return;
            // docs/61: a hand refusal (stable "input control: " prefix) belongs to the pending hand. It
            // changes no ownership state and is not a session error.
            if(isInputControlError(message)) {
              setInputHandoff((m) => handRefused(m, message));
              return;
            }
            // Agent host.rs lease-lapse errors use this exact prefix. Other policy
            // failures can mean a view-only floor or a recoverable expired renewal;
            // they must not be mistaken for a session termination.
            if(message.startsWith("session ended:")) {
              const reconnectLayout = isDisplayLayoutEnd(message) && layoutReconnectBudget.current.take(Date.now());
              if(reconnectLayout) {
                recovery.current?.cancel();
                setError(`${message} — reconnecting automatically…`);
              } else {
                setError(message);
              }
              handleTransportState("failed");
              transportRef.current?.close(); signalingRef.current?.close();
              if(reconnectLayout) {
                const gen = sessionGeneration.current;
                setTimeout(() => {
                  if (sessionGeneration.current === gen) reconnectManuallyRef.current();
                }, LAYOUT_RECONNECT_DELAY_MS);
              }
              return;
            }
            // A session-policy rejection is not a command failure — attribute it to the install that is
            // in flight and report it as a POLICY state instead of the generic agent-error banner. It
            // matters which one it is: "the organisation's policy could not be applied" is a security
            // fact the operator should read differently from "that command did not run".
            if (policyPendingRef.current) {
              policyPendingRef.current = false;
              // applied:false — the agent could not verify it and has floored the session for good.
              // This is the case that used to vanish: the note was stored and never rendered.
              setSessionPolicyState({ enforced: false, applied: false, note: message });
              return;
            }
            setError(`agent: ${message}`);
            // An elevated command that verified and then failed to start answers `Error` for a Win32
            // fault (a failed environment block, a spawn failure) — with ONE carve-out added in loop
            // 88: a failure at the TOKEN step (`CommandError::NotElevatable` — the interactive user
            // has no linked elevated token at all) answers `ElevationDenied` instead, because
            // nothing ran and the elevation was declined, which is exactly what that channel is for.
            // The grant is spent either way; see the `pending_command` completion arm in host.rs.
            // Disarm the deadline here too, since an `Error` is still a verdict.
            if (elevationTimeoutRef.current !== null) {
              clearTimeout(elevationTimeoutRef.current);
              elevationTimeoutRef.current = null;
            }
            // A command that could not start (or was refused as one-already-running) comes back as an
            // Error, not a CommandResult — so re-enable the Run button here too, else it stays disabled.
            setCommandPending(false);
            // Likewise a screenshot that could not be taken (no frame yet) — clear the "Capturing…".
            setScreenshotStatus(undefined);
            // A recording that could not START (no location configured, disk below the floor, DACL
            // refused) or could not STOP (nothing running) answers Error, not RecordingStopped — so
            // clear the pending flag here too, or the Record button stays disabled for the rest of
            // the session. `recording` itself is deliberately NOT touched: an Error while a
            // recording is genuinely running (a refused second start) must not make the UI claim it
            // stopped, and the agent's own `RecordingStopped` is the only thing that says it did.
            setRecordingPending(false);
            // If require_recording is mandated but the start was refused (host has no recording
            // dir, disk full, DACL), reset the pending guard so the next policy lease renewal can
            // retry. Use setRecording's functional updater to read the CURRENT value without
            // stale-closure risk — we return `prev` unchanged so the recording indicator is not
            // disturbed.
            setRecording(prev => {
              if (!prev && requireRecordingPendingRef.current) {
                requireRecordingPendingRef.current = false;
              }
              return prev;
            });
            // A directory listing that could not be read comes back as an Error — attribute it to the
            // file browser ONLY when one was in flight, so it shows inline and stops the "Loading…".
            // Navigation is disabled while loading (FileManagerPanel), so at most one ListDirectory is
            // in flight, which is what makes this single-pending attribution correct.
            if (dirPendingPathRef.current !== null) {
              dirPendingPathRef.current = null;
              if (dirTimeoutRef.current !== null) {
                clearTimeout(dirTimeoutRef.current);
                dirTimeoutRef.current = null;
              }
              setDirError(message);
              setDirLoading(false);
            }
          },
          // H1: agent acked a control-plane-signed grant — clear the "no grant" affordance.
          //
          // It no longer touches the forwarder. Before loop 91 this had to swap it, because the
          // install started a fresh chain; the dispatcher now JOINS the session's chain, so the
          // forwarder opened at connect is already the right one, and re-keying here would throw
          // away every event sealed before the grant arrived.
          onGrantInstalled: () => {
            grantHeldRef.current = true;
            setGrantResumeNotice(null);
            setGrantInstalled(true);
            // docs/58 §2: ask what this agent's Backstage understands; offer nothing new until it says.
            controlRef.current?.requestBackstageFeatures();
          },
          onBackstageFeatures: (features) => setBackstageFeatures(new Set(features)),
          // M11: the agent answered, so it speaks quality — cancel the probe timer and adopt the
          // settings it reports are in force (which may be a clamped or policy-capped version of
          // what was asked for; this reply is the only truth about that).
          onQualityApplied: (applied) => {
            if (qualityProbeTimer.current !== null) {
              clearTimeout(qualityProbeTimer.current);
              qualityProbeTimer.current = null;
            }
            setQualitySupported(true);
            dispatchQuality({ type: "applied", quality: applied.quality });
          },
          onQualityStats: (stats) => setQualityStats(stats),
          // Privacy: adopt the input-block state the agent reports is in force (which may be `false`
          // even after a `true` request, if the block could not arm).
          onInputBlockApplied: (blocked) => setInputBlocked(blocked),
          // Privacy: adopt the monitor-blank state the agent reports is in force (which may be `false`
          // even after a `true` request, if window creation failed — e.g. no interactive desktop).
          onMonitorBlankedApplied: (blanked) => setMonitorBlanked(blanked),
          // View-only: adopt the state the agent reports is in force (the enforcement is agent-side).
          onViewOnlyApplied: (enabled) => setViewOnly(enabled),
          // Remote support: the agent accepted the reboot and is about to drop — show a status line
          // until the session reconnects (cleared on the next connect). The ack carries the mode it
          // actually scheduled, so a Safe-Mode reboot says so even if the request was ambiguous.
          onRebootScheduled: (safeMode) =>
            setRebootStatus(
              safeMode
                ? "Rebooting into Safe Mode with Networking… reconnecting when it returns"
                : "Rebooting the guest… reconnecting when it returns",
            ),
          // Remote support: the agent locked the guest — it is now at its sign-in screen.
          onWorkstationLocked: () => setLockStatus("Guest locked"),
          // Remote support: the agent is logging the guest's user off — the session is about to drop
          // and reconnect at the sign-in screen (this notice is cleared on the next connect).
          onLogOffScheduled: () =>
            setLogoffStatus("Logging the guest off… reconnecting when it returns"),
          // Remote support: the agent is powering the guest OFF — the session drops and will NOT return
          // until the machine is powered back on (no auto-reconnect, unlike reboot/logoff).
          onShutDownScheduled: () => {
            recovery.current?.refuse("The guest is shutting down. Reconnect when it is powered on.");
            setShutdownStatus("Shutting the guest down… it will not reconnect until powered on");
          },
          // Remote support: confirm the launched tool by its human label (the agent echoes the key).
          onToolLaunched: (tool) => {
            const label = SYSTEM_TOOLS.find((t) => t.key === tool)?.label ?? tool;
            setToolStatus(`Launched ${label}`);
          },
          // Remote support (one-line command bar): the command finished — show its captured output and
          // re-enable the Run button.
          onCommandResult: (result) => {
            // Answers BOTH `RunCommand` and `ElevatedRun`, so it disarms the elevation deadline too.
            if (elevationTimeoutRef.current !== null) {
              clearTimeout(elevationTimeoutRef.current);
              elevationTimeoutRef.current = null;
            }
            // A VERDICT CLEARS THE OTHER CHANNEL. The two are mutually exclusive answers to one
            // request, but they live in separate state, so without this a late `CommandResult`
            // renders the command's own output directly beneath "Elevation refused: the guest did
            // not answer" — the deadline having fired first. Whichever verdict arrives is the truth.
            setElevationError(undefined);
            setCommandResult(result);
            setCommandPending(false);
          },
          // Remote support (file browser): the agent returned a listing. Drop a stale out-of-order
          // answer to a superseded navigation (so the panel never flips to a folder the operator has
          // already left); otherwise adopt it and clear the pending path + timeout.
          onDirectoryListing: (listing) => {
            // docs/25 F04: buffer the browse's SEALED audit event FIRST, and unconditionally —
            // before the staleness check, which drops the listing itself. The event is not part of
            // the UI's story: the agent has already consumed a `seq` for it, so a viewer that
            // discards it leaves a hole that wedges the rest of the session's trail at ingest. What
            // the operator is looking at and what the record says happened are different questions.
            enqueueSealedAudit(listing.audit);
            if (!shouldAdoptListing(dirPendingPathRef.current, listing.path)) return;
            dirPendingPathRef.current = null;
            if (dirTimeoutRef.current !== null) {
              clearTimeout(dirTimeoutRef.current);
              dirTimeoutRef.current = null;
            }
            setDirListing(listing);
            setDirLoading(false);
            setDirError(undefined);
          },
          // Remote support (file browser): the agent REFUSED the navigation (docs/25 F04) — this
          // session holds no `file_browse` capability, or the path is not on the guest's local disk.
          // Nothing was read, so there is no listing to adopt; the reason goes where an unreadable
          // path's message goes, because to the operator both mean "this folder did not open" and
          // only the text differs. Its audit event is buffered on the same terms as a listing's.
          onDirectoryListingRefused: (refusal) => {
            enqueueSealedAudit(refusal.audit);
            if (!shouldAdoptListing(dirPendingPathRef.current, refusal.path)) return;
            dirPendingPathRef.current = null;
            if (dirTimeoutRef.current !== null) {
              clearTimeout(dirTimeoutRef.current);
              dirTimeoutRef.current = null;
            }
            setDirError(refusal.reason);
            setDirLoading(false);
          },
          // Session recording (loop 89): the agent is now writing this session to the guest's disk.
          // The state comes from the ACK, never the click — see the `recording` declaration.
          onRecordingStarted: (_startedAt, audit) => {
            // The organisational record that this happened (loop 91). Forwarded VERBATIM: the
            // control plane recomputes the event's canonical preimage and treats any field-level
            // difference as tampering, so the browser must not normalize a single key of it. It is
            // buffered, not posted — the flush timer opened with the session owns delivery, and a
            // control plane that is briefly unreachable must not disturb a live support session.
            enqueueSealedAudit(audit);
            setRecordingPending(false);
            setRecording(true);
            // A new recording supersedes the last one's summary; leaving it on screen beside a live
            // "Recording" badge reads as a description of the recording in progress.
            setRecordingResult(undefined);
          },
          // Session recording: finalized. The result carries `truncated`, which is the only signal
          // that a recording stopped early — a file that merely ends looks complete.
          onRecordingStopped: (result, audit) => {
            // The audit-valuable half: this event carries the artifact's per-segment SHA-256
            // digests, which is what ties the trail to the file somebody later hands over.
            enqueueSealedAudit(audit);
            setRecordingPending(false);
            setRecording(false);
            setRecordingResult(result);
          },
          // Remote support (end session): the agent accepted and is about to drop. Show what it agreed
          // to (a plain end vs a "remove client" uninstall); the session then tears down on its own.
          onSessionEnding: (uninstall) => {
            recovery.current?.refuse("The remote session was ended");
            setEndSessionStatus(
              uninstall
                ? "Removing client… the agent is uninstalling itself"
                : "Ending session…",
            );
          },
          onSessionEndedByGuest: () => {
            recovery.current?.refuse("The guest ended the session. Reconnect manually if they allow it.");
            setEndSessionStatus("The guest ended the session");
          },
          // Task 4: the agent tells us its configured transfer root at session start. Store in both
          // state (so the file-browser shortcut button navigates to the right path) and a ref (so
          // `downloadFromBrowse` reads the current value without needing to re-create the callback).
          onTransferDir: (path) => {
            agentTransferDirRef.current = path;
            setAgentTransferDir(path);
          },
          // docs/53: an attended agent says once whether this session can ask for admin rights,
          // then reports each request.
          onAdminRightsAvailable: (available, reason) => setAdminRights((m) => adminRightsAdvertised(m, available, reason)),
          onAdminRightsResult: (state, reason) => setAdminRights((m) => adminRightsResult(m, state, reason)),
          // docs/61: the agent says once whether hand-off is possible, then sends the authoritative
          // snapshot of who owns input on every change — the only thing that says a hand worked.
          // A superseded session's late frames never reach these: the transport's onMessage drops them
          // (isCurrent) before routing, which input_handoff.spec.ts pins.
          onInputHandoffAvailable: (available) => setInputHandoff((m) => handoffAdvertised(m, available)),
          onInputControlChanged: (owner, mode) => setInputHandoff((m) => inputControlChanged(m, owner, mode)),
        },
      );
      controlRef.current = control;


      // V2: backstage tooling over the live session. The transport adapts the request/response
      // BackstageClient seam onto `transport.send(ChannelId.Backstage, …)` + inbound Backstage frames
      // (fed below in onMessage). `transport.send` buffers until the channel opens, so a request
      // issued before the Backstage channel is ready simply waits for its reply frame.
      //
      // The second argument is the AUDIT TAP (H2): every inbound envelope carries the agent's
      // hash-chained record of the action it answers, and buffering it here — at the one point all
      // backstage traffic passes through — is what finally makes `POST /audit/ingest` receive
      // anything. Before this, the agent chained events, the envelope delivered them, and the
      // console dropped them on the floor.
      const backstage = new ChannelBackstageTransport(
        (payload) => transportRef.current?.send(ChannelId.Backstage, payload),
        (env) => auditForwarderRef.current?.enqueueEnvelope(env as { ok: boolean; audit?: AuditEvent | null }),
      );
      backstageRef.current = backstage;
      setBackstageClient(new BackstageClient(backstage.asBackstageTransport(), { sessionChannel: true }));

      // V3: file transfer over ChannelId.FileTransfer. `send` frames onto the transport we are about
      // to build (via the ref closure); `send` buffers until the channel opens, so an upload started
      // right after connect just waits for the channel. A completed inbound download surfaces via
      // `onDownload`, which we hand to the Files panel (bumping a seq so it saves each once).
      // The third argument is the file-transfer half of the SAME chain (ADR-008): the agent records
      // uploads and downloads — including refusals — as events on the session's existing backstage
      // chain, so they must reach the same forwarder or the chain arrives at the control plane with
      // gaps in its sequence and fails linkage verification.
      const fileTransfer = new FileTransferClient(
        (payload) => transportRef.current?.send(ChannelId.FileTransfer, payload),
        (file) => {
          // F06 routing is by the file's OWN provenance, not by name-shape heuristics:
          //   'requested' → a viewer.request(path) the peer echoed; goes to the Files panel's save
          //   flow exactly as before (unchanged CompletedDownload seq bump).
          //   'approved'  → an unsolicited push the operator explicitly clicked Save on; save it
          //   directly here so the gesture works from the Video/tab/popout surface without the
          //   Files panel being mounted. The status line is deliberately generic — we do NOT claim
          //   a trusted screenshot correlation from a name prefix.
          if (file.source === "approved") {
            saveBytesAsFile(file.name, file.bytes);
            setScreenshotStatus(
              `Saved ${file.name} (${Math.round(file.bytes.length / 1024)} KB)${
                file.verified ? "" : " — checksum mismatch"
              }`,
            );
          } else {
            // Save the file immediately regardless of which tab is active (Bug 1 fix).
            saveBytesAsFile(file.name, file.bytes);
            // Update download state for status display in FileTransferPanel (when it's mounted).
            setDownload({
              name: file.name,
              bytes: file.bytes,
              sha256: file.sha256,
              verified: file.verified,
              seq: ++downloadSeq.current,
            });
            // Resolve which browse-requested rel path this completion belongs to using the
            // request UUID (file.id). UUID-based lookup is exact — no basename heuristic, no
            // ambiguity for same-named files in different subdirectories.
            const completedRel = file.id ? (pendingBrowseRelsRef.current.get(file.id) ?? null) : null;
            if (completedRel !== null) {
              pendingBrowseRelsRef.current.delete(file.id);
              setCompletedBrowseRelPaths((prev) => new Set([...prev, completedRel]));
            }
          }
        },
        (event) => auditForwarderRef.current?.enqueue(event as AuditEvent),
        {
          // F06/F07: surface rejected/aborted inbound transfers through the top-of-page banner.
          // The reason string is bounded and own — the client never echoes peer bytes here.
          // Also removes the stale map entry so a later same-basename manual download never
          // inherits a badge that belonged to the failed browse request.
          onDownloadError: ({ id, name, reason }) => {
            const label = name ? `Download ${name}` : "Download";
            setError(`${label} rejected: ${reason}`);
            if (id) pendingBrowseRelsRef.current.delete(id);
          },
          // F06 explicit-approval observer: an unsolicited Offer will be admitted under the F07
          // bounds, hash-verified, held INSIDE the client, and its metadata surfaced here — the
          // operator sees a Save/Dismiss prompt on the session UI regardless of tab. Absent this,
          // an unsolicited Offer is refused before reserving anything.
          onPendingDownloadsChanged: (snapshot) => setPendingDownloads(snapshot),
        },
      );
      fileTransferRef.current = fileTransfer;
      setFileTransferClient(fileTransfer);

      // V3 + docs/25 F08: clipboard sync over ChannelId.Clipboard. Outbound (operator → agent) is
      // gesture-driven by the ClipboardControl; inbound (agent → operator) is DEFAULT OFF — the
      // operator opts this session in with the Receive checkbox and the client drops all frames
      // until they do, without ever calling `writeText` or retaining remote text.
      const clipboard = new ClipboardClient(
        (payload) => transportRef.current?.send(ChannelId.Clipboard, payload),
        clipboardApi(),
        { onNotice: (n) => setClipboardNotice(n) },
      );
      clipboardRef.current = clipboard;
      setClipboardClient(clipboard);

      // M12: in-session chat over ChannelId.Chat. The AGENT owns the transcript — it assigns each
      // message's sequence and timestamp and echoes the recorded entry back — so everything the
      // panel renders arrives through `onMessages`; nothing is posted locally on send.
      const chat = new ChatClient((payload) => transportRef.current?.send(ChannelId.Chat, payload), {
        // Copy rather than storing the client's own array (the same defence `onMonitors` uses
        // above): React decides whether to re-render by IDENTITY, so state that aliases another
        // object's internal array would stop updating the instant that owner appended in place
        // instead of replacing — a message that arrives and never appears.
        onMessages: (m) => setChatMessages([...m]),
        onTruncated: () => setChatTruncated(true),
      });
      chatRef.current = chat;
      setChatClient(chat);

      const transport = new WebRTCTransport(
        // ICE policy keys off the EFFECTIVE rendezvous (the brokered URL when present).
        { signaling, iceServers: iceServersFor(brokered?.signaling.url ?? signalingUrl), requireViewOnlyBrokered: observe },
        {
          // A `failed` that follows a connection which never came up while signaling had withheld its relay
          // credential carries the relay limit as its likely cause (see handleTransportState).
          onStateChange: (s) => { if (isCurrent()) handleTransportState(s, undefined, s === "failed" ? transport.relayLimitCause() : null); },
          // Signaling brokered this session without a relay credential: tell the technician up front.
          onRelayNotice: (notice) => { if (isCurrent()) setRelayNotice(notice); },
          onVideoTrack: (s) => { if (isCurrent()) setStream(s); },
          // Both tracks arrive in the SAME MediaStream, so the <video> element already has the
          // audio; this only records that there IS some, which is what gates the speaker control.
          onAudioTrack: (s) => {
            if (!isCurrent()) return;
            setStream(s);
            setAudioAvailable(true);
          },
          onError: (err) => {
            if(!isCurrent()) return;
            setError(err.message);
            // The machine's agent is not registered with signaling: offline, rebooting, or between
            // re-registrations. Signaling sends nothing else for this attempt, so without this the
            // view only failed later, through the transport's timeout, as a generic "Connection
            // lost". Say it is offline now and let recovery retry with backoff: it connects as soon
            // as the agent is back, and each retry releases the previous record.
            if(/device .+ is not registered or offline$/.test(err.message)) {
              const offline = `${name} is offline: its DeskRally agent is not connected`;
              setError(offline);
              handleTransportState("failed", offline);
              transportRef.current?.close();
              signalingRef.current?.close();
              return;
            }
            // A signaling rejection is authoritative; do not create sessions in a loop.
            if(err.message.startsWith("connect rejected:") && !(
              err.message === "connect rejected: peer became unreachable" ||
              err.message === "connect rejected: internal error allocating session"
            )) recovery.current?.refuse(err.message);
          },
          onMessage: (channel, payload) => {
            if (!isCurrent()) return;
            // Route each inbound frame by channel. Control drives the monitor client (and grant
            // acks); Backstage resolves the next in-flight tool request (FIFO); FileTransfer feeds the
            // transfer client (Acks + inbound download Offer/Chunk/Done); Clipboard applies the
            // agent's text locally ONLY when the operator has opted this session in via the Receive
            // checkbox (docs/25 F08), otherwise the client drops the frame without decoding; Chat
            // merges the agent's Posted/History into the
            // transcript. Distinct channels, so none steals another's frames.
            if (channel === ChannelId.Control) control.handleMessage(payload);
            else if (channel === ChannelId.Backstage) backstage.handleMessage(payload);
            else if (channel === ChannelId.FileTransfer) fileTransfer.handleMessage(payload);
            else if (channel === ChannelId.Clipboard) void clipboard.handleMessage(payload);
            else if (channel === ChannelId.Chat) chat.handleMessage(payload);
          },
        },
      );
      transportRef.current = transport;

      // Dev/e2e seam: expose the live transport's stats + state so the Playwright console test can
      // assert real inbound media (getStats) without the app shipping a debug handle to production.
      if (import.meta.env.DEV) {
        (
          window as unknown as {
            __rmt?: { stats(): Promise<RTCStatsReport | undefined>; state: string };
          }
        ).__rmt = {
          stats: () => transport.getStats(),
          get state() {
            return transport.state;
          },
        };
        // Backstage debug seam: lets the Playwright backstage test drive a raw request over the live
        // ChannelId.Backstage and inspect the exact envelope (or error) the agent returned, isolating
        // the transport round-trip from the panel UI.
        (window as unknown as { __backstage?: BackstageClient }).__backstage = new BackstageClient(
          backstage.asBackstageTransport(),
        );
      }

      try {
        await transport.connect(device, brokered?.signaling.ticket);
        if (!isCurrent()) { transport.close(); signaling.close(); return; }
        // connect() creates the data channel; sends can now queue until it opens.
        // Install the signed access policy before monitor/quality requests. Sending it
        // before connect() throws because no frames channel exists yet.
        if (brokered?.sessionPolicy) {
          policyPendingRef.current = true;
          control.installSessionPolicy(brokered.sessionPolicy.signed);
        }
        // `send` buffers until the "frames" channel opens, so requesting the monitor list right
        // after connect is safe — the MonitorList reply routes back via onMessage → control.
        control.requestList();
        // M12: pull the conversation this machine already has, so opening a session shows what was
        // said rather than an empty box — a second technician (or the same one after a reconnect)
        // needs the context. This client is fresh, so its cursor is 0 and the agent replays its
        // whole retained window; within a session a later call asks only for the gap.
        chat.requestHistory();
        // M11: the same buffered send arms the session for quality telemetry and asks what is in
        // force. An agent that predates M11 cannot decode it and answers nothing, so the ABSENCE of
        // a reply is the discovery mechanism — hence the timer.
        //
        // Counted in the intent state because it is answered with a `QualityApplied` just like a
        // `SetQuality` is: an uncounted reply would be consumed as the answer to whatever the
        // operator did next, snapping the panel back to the pre-edit settings.
        control.requestQuality();
        dispatchQuality({ type: "requested" });
        // docs/58 §2: ask which Backstage features this agent understands. An older agent drops the
        // question, so the console simply never offers what it cannot do.
        control.requestBackstageFeatures();
        if (backgroundTracker.current.background) {
          control.setBackground(true);
          transport.setBackground(true);
        }
        // A RESUMED session starts with no grant on the agent: re-mint for the new session id and
        // install it, but only if the technician had one. 403/429 never loop (see resumeGrant).
        const resumeSessionId = auditSessionIdFor(brokered);
        const resumeToken = recovering && grantHeldRef.current && resumeSessionId
          ? grantOpRef.current.begin("auto", resumeSessionId)
          : null;
        if (resumeToken !== null && resumeSessionId) {
          const grantControlPlane = controlPlaneRef.current;
          const guard = grantOpRef.current;
          const owns = () => isCurrent() && controlRef.current === control && guard.owns(resumeToken);
          void resumeGrant({
            hadGrant: true,
            sessionId: resumeSessionId,
            mint: (sessionId) => grantControlPlane.mintGrant(device, { sessionId }),
            install: (signedGrant) => {
              setGrantCapabilities(parseGrantCapabilities(signedGrant));
              control.installGrant(signedGrant);
            },
            isCurrent: owns,
            // Same handling as Get access: a 401 returns the shared auth boundary to sign-in. (The
            // auth-aware fetch has usually expired the session already; expire() is idempotent.)
            onUnauthorized: () => { if (owns()) authSession.expire(); },
          }).then((outcome) => {
            // A 401/403 means the technician is not (or no longer) authorized: forget the fact, so a
            // LATER recovery does not mint again; only an explicit Get access tries after this.
            if (outcome === "denied" && owns()) grantHeldRef.current = false;
            if (owns() && (outcome === "denied" || outcome === "gave-up")) {
              setGrantResumeNotice(
                "Under the Hood access could not be restored automatically after the reconnect. Use Get access to try again.",
              );
            }
          }).finally(() => guard.end(resumeToken));
        }
        qualityProbeTimer.current = setTimeout(() => {
          qualityProbeTimer.current = null;
          // `s ?? false` rather than a bare `false`: a `QualityApplied` racing the timeout must win,
          // or a slow-but-capable agent would be marked unsupported a moment after proving it is not.
          setQualitySupported((s) => s ?? false);
        }, QUALITY_PROBE_TIMEOUT_MS);
      } catch (e) {
        if (!isCurrent()) return;
        setError(`connect failed: ${(e as Error).message}`);
        handleTransportState("failed");
        if(recovering) throw e;
      }
    },
    [teardown, disconnectSession, openSessionAuditForwarder, startRenewingLease, handleTransportState, authSession],
  );

  /**
   * Connect, guarded against re-entry.
   *
   * `connectImpl` awaits a POST /sessions round trip before it assigns `signalingRef` and
   * `transportRef`. A second Connect during that window runs its `teardown()` while those refs are
   * still the PREVIOUS session's, so neither call closes the other's transport: two agents stay
   * live, and every audit event from both funnels into the one `AuditForwarder` installed last —
   * which binds to the first event it sees and silently discards the other session's entire trail.
   *
   * The guard lives here rather than on the button because the race is between two async bodies,
   * not two renders; `disabled` would only narrow the window. AccessPanel deliberately never
   * disables Connect.
   */
  // The in-flight bit lives in a ref, NOT in the wrapper's closure: `useMemo` rebuilds the wrapper
  // whenever `connectImpl` changes identity, and a rebuilt wrapper with a closure flag would start
  // unguarded mid-connection. `connectImpl` is stable today only because both its dependencies are
  // `useCallback(…, [])` — one added dependency would silently undo the guard with nothing failing.
  const connectGate = useRef({ running: false });
  // Tracks whether a URL-param auto-connect has already been attempted this page load so we
  // do not re-trigger it on every fleet refresh (fleetEpoch changes, branding reload, etc.).
  const urlParamConnectAttempted = useRef(false);

  const handleConnect = useMemo(
    () =>
      onceAtATime(connectImpl, (device, name) => {
        // Named, because the operator clicked a machine and will not get it. Silent would leave
        // them re-clicking a button that looks like it does nothing.
        console.warn(
          `connect to ${name} (${device}) ignored: a connection is already being established`,
        );
      }, connectGate.current),
    [connectImpl],
  );

  retryConnection.current = async (recoveryIsCurrent) => {
    const target=recoveryTarget.current;
    const generation=sessionGeneration.current;
    const authEpoch=authSession.epoch;
    if(!target || target.attended || !authSession.isCurrent(authEpoch)) throw new RecoveryRefused("Reconnect from Support or sign in again");
    if(connectGate.current.running) throw new Error("A connection is already being established");
    // Verify the ORIGINAL session before ending it or acquiring a fresh ticket.
    // Deliberately use the authoritative renewal endpoint (includes revocation,
    // quarantine and duration policy), not a cached status/listing. This lease is
    // an authorization check, not installed on the failed transport.
    const id=brokeredSessionRef.current;
    if(id) {
      const abort=new AbortController();
      try {await withDeadline(consoleApiRef.current.renewSessionPolicy(id,abort.signal),8000);}
      catch(error) {
        if(isRefusal(error)) {
          if(recoveryIsCurrent() && sessionGeneration.current === generation) {
            recovery.current?.refuse(senderTransferredMessage((error as Error).message,
              outgoingTransferRef.current?.accepted_by_name || outgoingTransferRef.current?.to_name)
              ?? `Session ended: ${(error as Error).message}`);
            stopRenewingLease();
            transportRef.current?.close(); signalingRef.current?.close();
          }
          throw new RecoveryRefused(`Session ended: ${(error as Error).message}`);
        }
        throw error;
      } finally {abort.abort();}
    }
    if(!recoveryIsCurrent() || sessionGeneration.current !== generation || !authSession.isCurrent(authEpoch) || recoveryTarget.current !== target) return;
    await handleConnect(target.device,target.name,target.url,undefined,true,target.observe ?? false);
  };

  const reconnectManually=useCallback(()=> {
    const target=recoveryTarget.current;
    if(!target) return;
    if(target.attended) {setArea("attended");return;}
    void handleConnect(target.device,target.name,target.url,undefined,false,target.observe ?? false);
  },[handleConnect]);
  reconnectManuallyRef.current = reconnectManually;

  // Multi-machine: if the page was opened with ?device=<uuid>&name=<name>&signaling=<url>
  // (e.g. via the "Open in new tab" affordance), auto-connect once the auth gate opens.
  // Runs at most once per page load (urlParamConnectAttempted ref) so fleet refreshes do not
  // re-trigger a connect that the technician may have manually disconnected.
  //
  // The link is attacker-craftable and its `name` used to be shown as-is, so a link could open a
  // session on one machine titled as another ("Prod-DC01") — security audit 2026-10-18. The label now
  // never comes from the link: the machine list's own name when the list has this device, else the
  // neutral id-derived one. Connecting itself is unchanged (dev/direct-connect setups have no list,
  // and the control plane still decides whether this technician may reach the device at all).
  useEffect(() => {
    if (authGate !== "open" || urlParamConnectAttempted.current) return;
    urlParamConnectAttempted.current = true;
    const parsed = parseMachineUrlParams(window.location.search, window.location);
    if (!parsed) return;
    setArea("live");
    const machine = fleet?.find((m) => m.device.toLowerCase() === parsed.device.toLowerCase());
    pendingMachineAliasRef.current = machine?.alias;
    // An invite to watch (`observe=1`) joins view-only; the control plane still checks this technician's access.
    void handleConnect(asDeviceId(parsed.device), machine?.name ?? `agent ${parsed.device.slice(0, 8)}`, parsed.signalingUrl, undefined, false, parsed.observe);
    // `fleet` is read once, at the moment the gate opens; a later list refresh must not re-connect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authGate, handleConnect]);

  // Update the browser tab title to show the connected machine name so multiple open tabs are
  // easily distinguishable. Restores the default on disconnect; branding overrides it on reload.
  useEffect(() => {
    if (!session) return;
    const label = machineAlias ?? session.name;
    document.title = `${label} — DeskRally`;
    return () => {
      document.title = "DeskRally";
    };
  }, [session, machineAlias]);

  /**
   * Picking a machine from the drawer should also CLOSE the drawer.
   *
   * In the stacked layout the list covers the session it is about to open, so leaving it up would
   * hide the thing the operator just asked for. `setNavOpen(false)` unconditionally rather than
   * only when stacked: the flag is meaningless in the split layouts, so there is nothing to guard
   * and one less width-dependent branch in the tree.
   */
  const requestDesktop = useCallback((target: DesktopTarget, name = "Support session", signalingUrl = "") => {
    const uri = desktopLink(target, window.location.origin);
    if (!uri) { setError("This connection cannot open in the desktop app. Choose Browser to connect from this website."); return; }
    setDesktopRequest({ target, uri, name, signalingUrl, epoch: authSession.epoch });
    // No session or credentials are minted in the browser. The app authenticates and authorizes itself.
    window.location.assign(uri);
  }, [authSession]);
  const handleConnectFromList = useCallback(
    (device: DeviceId, name: string, signalingUrl: string, alias?: string, observe = false) => {
      setNavOpen(false);
      if (!observe && ((!desktopClient && preferDesktop) || (desktopClient && session && state !== "failed" && state !== "idle"))) {
        requestDesktop({ kind: "connect", id: device }, alias ?? name, signalingUrl);
        return;
      }
      setArea("live");
      pendingMachineAliasRef.current = alias;
      handleConnect(device, name, signalingUrl, undefined, false, observe);
    },
    [handleConnect, desktopClient, preferDesktop, session, state, requestDesktop],
  );

  // End a session from the machine list. Ends the session via the control plane and bumps
  // fleetEpoch so the listing re-fetches and the badge disappears. Authorization (CapEndSession)
  // is enforced by the control plane; a 403 propagates to AccessPanel's in-flight guard which
  // re-enables the button and leaves the badge in place.
  const handleEndFleetSession = useCallback(async (sessionId: string) => {
    await consoleApiRef.current.endSession(sessionId);
    setFleetEpoch((n) => n + 1);
  }, []);

  // Session transfer, SENDER (docs/51): follow this session's live offer, so the banner shows who
  // accepted and the final message can name them. The sender's read never finalizes anything.
  const outgoingTransferId = outgoingTransfer?.id;
  const outgoingTransferState = outgoingTransfer?.state;
  useEffect(() => {
    if (!outgoingTransferId || (outgoingTransferState !== "pending" && outgoingTransferState !== "releasing")) return;
    let live = true;
    const timer = window.setInterval(() => {
      consoleApiRef.current.getSessionTransfer(outgoingTransferId).then(
        (next) => { if (live) setOutgoingTransfer((cur) => (cur?.id === next.id ? next : cur)); },
        () => { /* retried on the next tick */ },
      );
    }, 3000);
    return () => { live = false; window.clearInterval(timer); };
  }, [outgoingTransferId, outgoingTransferState]);
  const cancelOutgoingTransfer = useCallback(async () => {
    const t = outgoingTransferRef.current;
    if (!t) return;
    try {
      await consoleApiRef.current.cancelSessionTransfer(t.id);
      setOutgoingTransfer(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  }, []);

  // Session transfer, RECEIVER: poll for offers while signed in (no push channel; 10 s, docs/51 §5).
  useEffect(() => {
    if (authGate !== "open") return;
    const poller = new IncomingTransferPoller(consoleApiRef.current, setIncomingOffers);
    incomingPollerRef.current = poller;
    poller.start();
    return () => {
      poller.stop();
      incomingPollerRef.current = null;
      setIncomingOffers([]);
    };
  }, [authGate]);
  const acceptIncomingTransfer = useCallback(async (offer: SessionTransfer) => {
    const authEpoch = authSession.epoch;
    const sender = offer.from_name || "the sender";
    setIncomingTransferError(null);
    setAcceptingTransfer({ id: offer.id, status: "Accepting…" });
    try {
      const got = await acceptAndWait(consoleApiRef.current, offer.id, {
        onState: (t) => setAcceptingTransfer({
          id: offer.id,
          status: t.state === "accepted" ? "Connecting…" : `Waiting for ${sender}'s session to close…`,
        }),
      });
      if (!authSession.isCurrent(authEpoch)) return;
      setArea("live");
      void handleConnect(asDeviceId(got.deviceId), offer.machine_name || "Transferred session", got.signalingUrl, got.brokered);
    } catch (failure) {
      if (authSession.isCurrent(authEpoch)) {
        setIncomingTransferError(failure instanceof Error ? failure.message : String(failure));
      }
    } finally {
      setAcceptingTransfer(null);
      incomingPollerRef.current?.refresh();
    }
  }, [authSession, handleConnect]);
  const visibleOffers = incomingOffers.filter((t) => !dismissedOffers.has(t.id));

  // Guest help requests: poll while signed in (15 s; no push channel). Accept creates the session on the
  // server, bound to the request, then this connects to THAT session as an owned, ordinary one.
  useEffect(() => {
    if (authGate !== "open") return;
    const poller = new HelpRequestPoller(consoleApiRef.current, setHelpRequests);
    helpPollerRef.current = poller;
    // A fresh controller (and fresh idempotency keys) per sign-in: nothing unresolved survives a sign-out.
    const accept = new HelpAcceptController(consoleApiRef.current, new AcceptKeys(), setHelpAccept);
    helpAcceptRef.current = accept;
    poller.start();
    return () => {
      poller.stop();
      accept.reset();
      helpPollerRef.current = null;
      helpAcceptRef.current = null;
      setHelpRequests([]);
    };
  }, [authGate]);
  // First accept and Retry both go through the controller: same request id, same idempotency key.
  const runHelpAccept = useCallback(async (request: HelpRequest | null) => {
    const controller = helpAcceptRef.current;
    if (!controller) return;
    const authEpoch = authSession.epoch;
    try {
      const got = request ? await controller.attempt(request) : await controller.retry();
      if (got && authSession.isCurrent(authEpoch)) {
        const label = request?.machine_alias || request?.machine_name || "Help request";
        setArea("live");
        void handleConnect(asDeviceId(got.deviceId), label, got.signalingUrl, got.brokered);
      }
    } finally {
      helpPollerRef.current?.refresh();
    }
  }, [authSession, handleConnect]);
  const acceptHelpRequest = useCallback((request: HelpRequest) => runHelpAccept(request), [runHelpAccept]);
  const retryHelpAccept = useCallback(() => {
    const u = helpAcceptRef.current?.snapshot().unresolved;
    return runHelpAccept(u ? u.request : null);
  }, [runHelpAccept]);

  // Attended connect (docs/12 §9): the consent gate already minted the ticket + coordinates, so
  // we jump straight into the live workspace with them — same machinery, pre-acquired envelope.
  const renderedAuthEpoch = authSession.epoch;
  const handleAttendedConnect = useCallback(
    (connected: ConnectedAttendedSession) => {
      if (!authSession.isCurrent(renderedAuthEpoch)) return;
      setArea("live");
      // The whole response is mapped by `attendedHandoff` (lib/console_panels), which is where the
      // signed policy is carried into the pre-acquired envelope exactly as the unattended path does.
      // It lives there rather than inline because this callback cannot be unit-tested and the
      // mapping's failure mode is SILENT: drop the policy and the session runs unrestricted while
      // the console still shows the group as view-only.
      const handoff = attendedHandoff(connected);
      void handleConnect(
        asDeviceId(handoff.deviceId),
        handoff.label,
        handoff.signalingUrl,
        handoff.preAcquired,
      );
    },
    [handleConnect, authSession, renderedAuthEpoch],
  );

  const connectAttendedHere = useCallback(async (id: string) => {
    const epoch = authSession.epoch;
    try {
      const connected = await consoleApiRef.current.connectAttendedSession(id);
      if (authSession.isCurrent(epoch)) handleAttendedConnect(connected);
    } catch (e) {
      if (authSession.isCurrent(epoch)) setError(e instanceof Error ? e.message : "Could not connect to this support session.");
    }
  }, [authSession, handleAttendedConnect]);
  useEffect(() => {
    if (authGate !== "open" || attendedUrlAttempted.current) return;
    attendedUrlAttempted.current = true;
    const id = attendedLaunchId(window.location.search);
    // A launch identifies either a machine or an attended session, never both.
    if (id && !new URLSearchParams(window.location.search).has("device")) void connectAttendedHere(id);
  }, [authGate, connectAttendedHere]);
  useEffect(() => {
    if (authGate !== "open") setDesktopRequest(null);
  }, [authGate]);

  // Tear the live session down when the console itself goes away. Without this, `teardown` ran only
  // from Disconnect and from the start of the NEXT connect — so an unmount left the audit flush
  // interval running against a dead transport, dropped whatever was still buffered, and never
  // released the brokered session record.
  //
  // Tab closure is handled separately below. Final audit flushing remains best-effort;
  // the agent retains its own chained copy.
  useEffect(() => () => teardown(), [teardown]);

  const handleDisconnect = disconnectSession;

  useEffect(() => {
    // React does not unmount on tab closure. endSession uses a small keepalive fetch with
    // the normal CSRF header; sendBeacon cannot carry that header. Treat BFCache navigation
    // as leaving the remote session too, so Back never revives an unattended controller.
    window.addEventListener("pagehide", handleDisconnect);
    return () => window.removeEventListener("pagehide", handleDisconnect);
  }, [handleDisconnect]);

  const selectMonitor = useCallback((id: number) => {
    if (!monitorCanvasRef.current) controlRef.current?.select(id);
  }, []);

  // Privacy: ask the agent to block/unblock the guest's own keyboard & mouse. The indicator does not
  // move here — it follows the agent's `InputBlockApplied` ack (onInputBlockApplied), which is the
  // only truth about whether the block actually armed.
  const toggleInputBlock = useCallback((blocked: boolean) => {
    controlRef.current?.setInputBlocked(blocked);
  }, []);

  // Privacy: ask the agent to blank/unblank the guest's monitors. The indicator follows the agent's
  // `MonitorBlankedApplied` ack (onMonitorBlankedApplied), not the click — the overlay is created on
  // the agent side and may fail (e.g. no interactive desktop).
  const toggleMonitorBlank = useCallback((blanked: boolean) => {
    controlRef.current?.setMonitorBlanked(blanked);
  }, []);

  // View-only: ask the agent to drop / resume our injected input. The indicator follows the agent's
  // `ViewOnlyApplied` ack (onViewOnlyApplied), never the click — the enforcement lives at the agent.
  const toggleViewOnly = useCallback((enabled: boolean) => {
    controlRef.current?.setViewOnly(enabled);
  }, []);

  // Remote support: ask the agent to reboot (normal or Safe Mode with Networking). The status line
  // does not move here — it follows the agent's `RebootScheduled` ack (onRebootScheduled), so a
  // reboot that could not be armed surfaces as an `Error` instead of a false "Rebooting…".
  const rebootGuest = useCallback((safeMode: boolean) => {
    controlRef.current?.reboot(safeMode);
  }, []);

  // Remote support: launch a whitelisted admin tool on the guest. The status line follows the agent's
  // `ToolLaunched` ack (onToolLaunched), not the click, so an unknown key or spawn failure surfaces as
  // an `Error` rather than a false "Launched".
  const launchTool = useCallback((tool: string) => {
    // Clear any prior "Launched X" first, so a failed or repeated launch never shows a stale success:
    // the status re-appears only when THIS launch's `ToolLaunched` ack arrives (or an `Error` shows).
    setToolStatus(undefined);
    controlRef.current?.launchTool(tool);
  }, []);

  // Remote support (one-line command bar): fire a command and mark it pending. The output does not
  // move here — it follows the agent's `CommandResult` (onCommandResult), so a command that could not
  // start surfaces as an `Error` rather than a false result. `pending` disables the Run button until
  // either the result or an error arrives (both clear it).
  // Remote support (file browser): ask the agent to list `path` (empty = drive roots). The result
  // follows the agent's `DirectoryListing` (onDirectoryListing) or an `Error` (onError). Read-only,
  // so it works even in view-only mode. Mark pending so onError can attribute a failure here.
  const browseDir = useCallback((path: string) => {
    dirPendingPathRef.current = path;
    setDirLoading(true);
    setDirError(undefined);
    if (dirTimeoutRef.current !== null) clearTimeout(dirTimeoutRef.current);
    dirTimeoutRef.current = window.setTimeout(() => {
      dirTimeoutRef.current = null;
      // Still waiting after the budget: the guest never answered. Surface it and stop "Loading…".
      if (dirPendingPathRef.current !== null) {
        dirPendingPathRef.current = null;
        setDirLoading(false);
        setDirError("The guest did not respond — it may be an older agent that cannot browse files.");
      }
    }, DIR_REPLY_TIMEOUT_MS);
    controlRef.current?.listDirectory(path);
  }, []);

  // File browser download: delegates to downloadFileFromBrowse() which enforces the no-fallback
  // safety contract — if the agent has not sent a TransferDir message the call is a no-op.
  const downloadFromBrowse = useCallback((absolutePath: string) => {
    const result = downloadFileFromBrowse(absolutePath, agentTransferDirRef.current, fileTransferRef.current);
    if (result !== null) {
      pendingBrowseRelsRef.current.set(result.requestId, result.rel);
    }
  }, []);

  // File browser upload: the files land in the agent's transfer root (the browser only offers this
  // while it is AT that root). Sequential, one Ack at a time, through the client captured when the
  // batch started — a client replaced mid-batch belongs to a different session, so nothing further is
  // sent and no row of the new session is touched. Afterwards the root is re-listed so the new files
  // appear, unless the operator has navigated away or another listing is already in flight.
  const dirListingRef = useRef(dirListing);
  dirListingRef.current = dirListing;
  const uploadFromBrowse = useCallback(
    async (files: File[]) => {
      const client = fileTransferRef.current;
      const root = agentTransferDirRef.current;
      if (!client || root === undefined) return;
      const current = () => fileTransferRef.current === client;
      for (const file of files) {
        if (!current()) return;
        const id = ++browseUploadSeq.current;
        const settle = (phase: BrowseUploadRow["phase"], message: string) => {
          if (current()) setBrowseUploads((prev) => prev.map((r) => (r.id === id ? { ...r, phase, message } : r)));
        };
        setBrowseUploads((prev) => [{ id, name: file.name, phase: "uploading", message: "Uploading…" }, ...prev]);
        try {
          const bytes = new Uint8Array(await file.arrayBuffer());
          if (!current()) return;
          const ack = await client.upload(file.name, bytes);
          settle(ack.ok ? "ok" : "error", ack.ok ? "Uploaded" : ack.message || "Rejected by the remote machine");
        } catch (e) {
          settle("error", e instanceof Error ? e.message : String(e));
        }
      }
      const listing = dirListingRef.current;
      if (current() && dirPendingPathRef.current === null && listing && isSamePath(listing.path, root)) {
        browseDir(listing.path);
      }
    },
    [browseDir],
  );

  const runCommand = useCallback((command: string, shell: CommandShell, asUser: boolean) => {
    commandOpSeq.current++;
    setCommandResult(undefined);
    setCommandPending(true);
    setElevationError(undefined);
    controlRef.current?.runCommand(command, shell, asUser);
  }, []);

  /**
   * Run ONE command with the guest's ELEVATED token (docs/01 §3, loop 87).
   *
   * Two hops, in this order and no other: mint a single-use grant from the control plane (which
   * authorizes and AUDITS it), then forward that grant with the command. A grant per command is the
   * design, not an inefficiency — it is what puts every elevated command in the audit trail.
   *
   * A mint failure never sends anything, so the technician sees the control plane's own reason (403
   * without the capability, 409 for an attended or view-only-mandated session) rather than an
   * unexplained agent refusal.
   */
  const elevatedRun = useCallback(
    async (command: string, shell: CommandShell) => {
      const sessionId = brokeredSessionRef.current;
      if (!sessionId) {
        setElevationError("This session has no control-plane record, so it cannot be elevated.");
        return;
      }
      commandOpSeq.current++; // supersedes any toolbox run still waiting on the control plane
      setCommandResult(undefined);
      setElevationError(undefined);
      setCommandPending(true);
      try {
        const grant = await consoleApiRef.current.mintSessionElevation(sessionId);
        // RE-CHECK the session AFTER the await. The mint is a network round trip, and the operator
        // can disconnect (or connect somewhere else) while it is in flight — at which point
        // `controlRef` points at a DIFFERENT machine's agent. Sending then would hand another
        // machine the grant and the command text. The grant is useless there (it names this
        // session), but the command line is not, and it can carry credentials.
        if (brokeredSessionRef.current !== sessionId) {
          setCommandPending(false);
          setElevationError("The session changed while the elevation was being authorized; nothing ran.");
          return;
        }
        controlRef.current?.elevatedRun(grant.signed, command, shell);
        // An agent predating loop 87 drops the unknown `ElevatedRun` variant and answers NOTHING, so
        // arm a deadline: without it the command bar stays disabled for the rest of the session with
        // no explanation. Cleared by whichever verdict arrives first (see the `[state]` effect and
        // the two handlers), and by disconnect.
        if (elevationTimeoutRef.current !== null) clearTimeout(elevationTimeoutRef.current);
        elevationTimeoutRef.current = window.setTimeout(() => {
          elevationTimeoutRef.current = null;
          setCommandPending(false);
          setElevationError(
            "The guest did not answer — it may be an older agent that cannot run elevated commands.",
          );
        }, ELEVATION_REPLY_TIMEOUT_MS);
      } catch (e) {
        // The grant never left the control plane, so nothing ran and nothing is pending.
        setCommandPending(false);
        setElevationError(e instanceof Error ? e.message : String(e));
      }
    },
    [],
  );

  // The toolbox is offered exactly when "Run as admin" is: a connected session with a control-plane
  // record to authorize and audit the run against. Cleanup rejects earlier sessions and superseded
  // listings. Leaving Toolbox management reloads the list; refreshes keep the previous items visible.
  const inToolboxArea = area === "toolbox";
  useEffect(() => {
    setToolboxError(undefined);
    if (!canElevate) {
      setToolboxItems(undefined);
      setToolboxListError(undefined);
      return;
    }
    if (inToolboxArea) return;
    let cancelled = false;
    void (async () => {
      try {
        const listing = await consoleApiRef.current.listToolbox();
        if (!cancelled) {
          setToolboxItems(listing.items);
          setToolboxListError(undefined);
        }
      } catch (e) {
        if (!cancelled) {
          setToolboxItems(undefined);
          setToolboxListError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [canElevate, toolboxRefreshSeq, inToolboxArea]);

  /**
   * Run a saved script on the connected machine. Two hops, like an elevated run: the control plane
   * authorizes the run against the held session and commits the audit record FIRST, and returns the
   * exact command; only then is it sent as an ordinary RunCommand. A refusal sends nothing.
   */
  const runToolboxItem = useCallback(async (item: ToolboxItem) => {
    const op = ++commandOpSeq.current;
    const sessionAtStart = brokeredSessionRef.current;
    setCommandResult(undefined);
    setToolboxError(undefined);
    setElevationError(undefined);
    setCommandPending(true);
    const outcome = await runToolboxScript(item, {
      api: consoleApiRef.current,
      currentSessionId: () => brokeredSessionRef.current,
      sendRunCommand: (command, shell, asUser) => controlRef.current?.runCommand(command, shell, asUser),
      isCurrent: () => commandOpSeq.current === op && brokeredSessionRef.current === sessionAtStart,
    });
    if (!outcome.sent && !outcome.stale) {
      setCommandPending(false);
      setToolboxError(outcome.error);
    }
  }, []);

  // Remote support: ask the agent for a full-res screenshot. The PNG arrives over the file-transfer
  // channel and is saved by `onDownload` above (which also sets the status line); nothing happens here
  // but the request, so an agent that has captured no frame yet surfaces an `Error` instead.
  const requestScreenshot = useCallback(() => {
    // The PNG arrives as an unsolicited file-transfer Offer (the agent's screenshot path does not
    // echo a viewer-issued request id), so the operator will see an explicit Save prompt on the
    // session UI once the bytes are verified. We do NOT promise silent auto-save here.
    setScreenshotStatus("Capturing… you will confirm Save when the file arrives.");
    controlRef.current?.requestScreenshot();
  }, []);

  // Session note: save a free-text operator note to the control-plane session record.
  // `brokeredSessionRef.current` is null on the attended path (App deliberately does not own that
  // session record, so teardown must not end it). Attended sessions therefore cannot annotate in
  // real time via this path. The callback is gated on `canElevate` (≡ brokeredSessionRef ≠ null)
  // so the Note button is hidden on attended and direct-connect sessions.
  const saveSessionNote = useCallback(async (note: string) => {
    const id = brokeredSessionRef.current;
    if (!id) return;
    await consoleApiRef.current.setSessionNote(id, note);
  }, []);

  // Session recording (loop 89): toggle recording of this session to a file on the GUEST's disk.
  //
  // ONE callback for both directions, keyed off the state the AGENT last reported. The alternative —
  // two buttons, or a local "intent" flag — would let the console's idea of whether a recording is
  // running drift from the machine's, and this is the control where that drift matters most: the
  // operator's belief about whether a video exists has to match the disk.
  const toggleRecording = useCallback(() => {
    setRecordingPending(true);
    if (recording) {
      controlRef.current?.stopRecording();
    } else {
      controlRef.current?.startRecording();
    }
  }, [recording]);

  // Remote support: lock the guest workstation (Win+L). The confirmation follows the agent's
  // `WorkstationLocked` ack (onWorkstationLocked), not the click, so a view-only refusal surfaces as an
  // `Error` in the app-error banner rather than a false "Guest locked".
  const lockGuest = useCallback(() => {
    setLockStatus(undefined);
    controlRef.current?.lock();
  }, []);

  // Remote support: log off the guest's interactive user. Like reboot, the status line follows the
  // agent's `LogOffScheduled` ack (onLogOffScheduled), not the click — so a view-only refusal surfaces
  // as an `Error` in the app-error banner rather than a false "Logging off…".
  const logOffGuest = useCallback(() => {
    setLogoffStatus(undefined);
    controlRef.current?.logOff();
  }, []);

  // Remote support: shut the guest machine down (power off). The status follows the agent's
  // `ShutDownScheduled` ack (onShutDownScheduled), not the click, so a view-only refusal surfaces as an
  // `Error` banner rather than a false "Shutting down…". The Viewer gates this behind a two-step confirm
  // (the most destructive action — the agent cannot bring the machine back).
  const shutDownGuest = useCallback(() => {
    setShutdownStatus(undefined);
    controlRef.current?.shutDown();
  }, []);

  // M11: send the operator's choice and record it as PENDING — not as acknowledged. `acknowledged`
  // still moves only when the agent answers with what it actually applied (see onQualityApplied), so
  // a clamped or policy-capped ask is never shown as if it were in force; the pending copy exists
  // only so the operator's NEXT edit composes with this one instead of reverting it.
  const applyQuality = useCallback((q: QualitySettings) => {
    dispatchQuality({ type: "asked", quality: q });
    controlRef.current?.setQuality(q);
  }, []);

  // Background mode (lib/background.ts): the session drops to ~1 fps on the agent while every
  // window showing it is hidden. Only transitions are sent; a reconnect re-sends a background state
  // (see the connect hook), since a new agent session starts in the foreground.
  const onViewerVisibility = useCallback((viewer: object, hidden: boolean | null) => {
    const changed = backgroundTracker.current.update(viewer, hidden);
    if (changed !== undefined) {
      controlRef.current?.setBackground(changed);
      // The stall check must not demand frames the agent no longer owes (lib/transport.ts setBackground).
      transportRef.current?.setBackground(changed);
    }
  }, []);

  // V4 secure-mode "Get access": mint a control-plane-signed grant for the connected machine and
  // install it over the Control channel. The agent verifies the signature against its pinned issuer
  // and acks `GrantInstalled` → `onGrantInstalled` sets `grantInstalled`, which retries the denied
  // backstage tab (see BackstagePanels). A 401 means the (prod) control plane needs a login first, so
  // the shared auth boundary returns to sign-in. Other failures
  // (e.g. 403 not authorized) propagate to the panel's inline error.
  const handleFetchGrant = useCallback(async () => {
    if (!session) throw new Error("no active session");
    const epoch = authSession.epoch;
    const grantSessionId = auditSessionIdRef.current;
    const control = controlRef.current;
    if (!grantSessionId) throw new Error("Under the Hood requires a brokered session");
    // A manual request supersedes an in-flight automatic resume (and vice versa never happens).
    const guard = grantOpRef.current;
    const token = guard.begin("manual", grantSessionId)!;
    try {
      const signedGrant = await controlPlaneRef.current.mintGrant(session.device, {
        sessionId: grantSessionId,
      });
      if (authSession.isCurrent(epoch) && control === controlRef.current && guard.owns(token)) {
        setGrantCapabilities(parseGrantCapabilities(signedGrant));
        control?.installGrant(signedGrant);
      }
    } finally {
      guard.end(token);
    }
  }, [session, authSession]);

  // V4 prod mode: log in to the control plane (sets an httpOnly session cookie server-side), then
  // return to the console after reloading the fleet. DEV mode uses stub auth.
  const handleLogin = useCallback(
    async (tenant: string, email: string, password: string, totp?: string, rememberDevice = false) => {
      // A late logout response clears cookies; finish it before issuing a new one.
      await logoutPendingRef.current;
      await controlPlaneRef.current.login(tenant, email, password, totp, rememberDevice);
    },
    [],
  );

  /**
   * Sign out: disconnect and re-gate immediately, then clear the server session.
   *
   * The console had NO logout at all — `POST /auth/logout` was mounted, tested server-side and
   * unreachable from the UI, so the only way to end a session was to close the browser and hope.
   * That is a poor property for a tool whose session authorizes remote control of other people's
   * machines.
   *
   * The gate is closed even if the request fails: locally forgetting the session is the safer half,
   * and leaving someone looking at a logged-in console after they clicked Sign out would be worse
   * than a stale server-side session that the idle timeout will reap anyway.
   */
  const handleLogout = useCallback(async () => {
    authSession.expire();
    setAuthNotice("You have signed out.");
    const pending = controlPlaneRef.current.logout().catch(() => {
      // Already expired or unreachable: the local gate remains closed.
    });
    logoutPendingRef.current = pending;
    await pending;
    if (logoutPendingRef.current === pending) logoutPendingRef.current = null;
  }, [authSession]);

  const handleLoginSuccess = useCallback(() => {
    authSession.signedIn();
    handleDisconnect();
    setAuthNotice(null);
    // A login prompted on a protected callback path must return to that panel.
    if (window.location.pathname === "/console/account") setArea("account");
    if (window.location.pathname === "/console/security") setArea("security");
    if (window.location.pathname === "/console/help") setArea("help");
    setAuthGate("checking");
    setFleetEpoch((n) => n + 1);
  }, [authSession, handleDisconnect]);

  authExpiredHandlerRef.current = () => {
    handleDisconnect();
    setFleet(undefined);
    setArea("live");
    setAuthNotice(authGate === "open" ? "Your sign-in has expired. Sign in again to continue." : null);
    setAuthGate("required");
  };

  useEffect(() => {
    if (authGate !== "open") return;
    const abort = new AbortController();
    let pending = false;
    const check = async () => {
      // Keep checking when the main tab is hidden: its pop-out may still be in use.
      if (pending) return;
      pending = true;
      try {
        await boundedAuthCheck(
          `${controlPlaneRef.current.base}/auth/session`,
          abort.signal,
          AUTH_CHECK_TIMEOUT_MS,
          authSession.fetch,
        );
      } finally {
        pending = false;
      }
    };
    const timer = window.setInterval(() => { void check(); }, 30_000);
    const resume = () => { void check(); };
    window.addEventListener("focus", resume);
    document.addEventListener("visibilitychange", resume);
    return () => {
      abort.abort();
      window.clearInterval(timer);
      window.removeEventListener("focus", resume);
      document.removeEventListener("visibilitychange", resume);
    };
  }, [authGate, authSession]);

  // A new session (or none) starts with the bar collapsed behind the tab; an opened overlay does not
  // carry over from the previous machine.
  const sessionDevice = session?.device;
  useEffect(() => { setChromeOpen(false); }, [sessionDevice]);

  // Session chrome mode. An app error forces the bar open: the error banner lives in it and must never
  // be hidden behind the collapsed tab.
  const chrome = chromeMode(area === "live" && !!session, sessionChrome, chromeOpen || !!error);
  const minimalChrome = chrome === "collapsed" || chrome === "overlay";
  // Menu redesign wave 10b: outside a live session, on anything wider than a phone, the page bar is drawn and the
  // help-request and activity bells and an Account menu sit at its right end. Otherwise (a live session, or a phone,
  // where the bar is hidden by the same 600px rule in index.css) they stay inside the DeskRally menu. Each control is
  // rendered in exactly ONE place, so its test id is never duplicated.
  const barChrome = chrome === "normal" && viewportWidth > 600;
  const bells = signedInAs ? <>
    <HelpRequestsBell requests={helpRequests} accepting={helpAccept.accepting} error={helpAccept.error}
      unresolved={helpAccept.unresolved} onRetry={() => void retryHelpAccept()}
      onAccept={acceptHelpRequest} onClearError={() => helpAcceptRef.current?.clearError()}
      onOpen={() => helpPollerRef.current?.refresh()} />
    <NotificationBell state={notifications.state} onOpen={notifications.markSeen} onDismiss={notifications.dismiss} />
  </> : null;
  const whoami = signedInAs ? (
    <span className="app__whoami" data-testid="app-whoami" title={`Signed in as ${signedInAs}`}>
      Signed in as {signedInAs}
    </span>
  ) : null;
  const signOutButton = (
    <button type="button" className="app__signout" data-testid="app-signout" onClick={() => void handleLogout()}>
      Sign out
    </button>
  );

  // Keyboard focus across chrome transitions: the button just pressed disappears (▾ hides when the bar
  // drops, ▴ and Pin hide when it collapses or pins), so move focus to where the user now is rather
  // than dropping it on <body>. Only after a user-initiated transition (the intent ref) — a session
  // starting must never steal focus from the remote screen.
  const focusAfterChrome = useRef<"collapse" | "toggle" | "help" | null>(null);
  const toggleBtnRef = useRef<HTMLButtonElement>(null);
  const collapseBtnRef = useRef<HTMLButtonElement>(null);
  const helpBtnRef = useRef<HTMLButtonElement>(null);
  // Whether keyboard focus is currently inside the top bar or the tab. Tracked with focusin because a
  // focused element that is REMOVED fires no further focus event — so after a mode change this still
  // says "focus was in the chrome" even though the element is gone and focus fell to <body>.
  const focusInChrome = useRef(false);
  useEffect(() => {
    const inChrome = (e: Event) => !!(e.target as Element | null)?.closest?.(".app__topbar, .session-tab");
    const onFocusIn = (e: FocusEvent) => { focusInChrome.current = inChrome(e); };
    // A pointer press elsewhere (e.g. on the remote screen, which may not take focus itself) means the
    // operator has left the chrome: forget it, so a later mode change never pulls focus back to the bar.
    const onPointerDown = (e: PointerEvent) => { if (!inChrome(e)) focusInChrome.current = false; };
    document.addEventListener("focusin", onFocusIn);
    document.addEventListener("pointerdown", onPointerDown, true);
    return () => {
      document.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("pointerdown", onPointerDown, true);
    };
  }, []);
  useEffect(() => {
    // 1. A user-initiated transition: land exactly where they are now.
    const want = focusAfterChrome.current;
    focusAfterChrome.current = null;
    if (want) {
      if (want === "collapse" && chrome === "overlay") collapseBtnRef.current?.focus();
      else if (want === "toggle" && chrome === "collapsed") toggleBtnRef.current?.focus();
      else if (want === "help" && chrome === "pinned") helpBtnRef.current?.focus();
      return;
    }
    // 2. Any OTHER transition (the session ended, an error-forced overlay closed as the error
    //    cleared, a control in the bar removed itself): restore focus only if it was IN the chrome and
    //    the change dropped it — never pull focus away from the remote screen or a field elsewhere.
    if (!focusInChrome.current) return;
    const active = document.activeElement;
    if (active && active !== document.body && active.isConnected) return;
    if (chrome === "collapsed") toggleBtnRef.current?.focus();
    else if (chrome === "overlay") collapseBtnRef.current?.focus();
    else helpBtnRef.current?.focus();
  }, [chrome]);

  // THE GATE. Nothing below this renders until the control plane says who you are.
  //
  // Deliberately an early return rather than an overlay: an overlay still mounts the panels behind
  // it, and every one of them fires its own authenticated fetch. Returning here means an
  // unauthenticated browser makes exactly one request — the probe that produced the 401 — and shows
  // no fleet, no session list and no audit trail, which is the actual requirement.
  if (authGate === "checking") {
    return <div className="app app--gate" data-testid="app-auth-checking" />;
  }
  // The callback route must bypass JoinPage even when an existing session opens the gate.
  if (window.location.pathname === "/console/sso-totp") {
    return <div className="app app--gate app--signin">
      <SsoTotpForm api={consoleApiRef.current} onSuccess={handleLoginSuccess} />
    </div>;
  }
  if (authGate === "required" && !authNotice &&
      window.location.pathname !== "/console" && window.location.pathname !== "/login" &&
      window.location.pathname !== "/console/account" && window.location.pathname !== "/console/security" &&
      window.location.pathname !== "/console/help") {
    return <JoinPage code={window.location.hash.replace(/^#/, "")}
      productName={import.meta.env.VITE_PRODUCT_NAME}
      defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN}
      download={{url: import.meta.env.VITE_SUPPORT_DOWNLOAD_URL,
                 sha256: import.meta.env.VITE_SUPPORT_DOWNLOAD_SHA256}} />;
  }
  if (authGate === "required") {
    // The full-screen sign-in carries the DeskRally identity (docs/28 section 4): scoped to
    // `app--signin` so its palette and hero remain separate from the console.
    return (
      <div className="app app--gate app--signin">
        <header className="app__topbar app__topbar--signin">
          <span className="app__brand"><RallyMark />DeskRally</span>
          <span className="app__brandby">Remote support</span>
          <a className="join__downloads" href="/downloads">Downloads</a>
          <a className="join__downloads" href="/docs">Documentation</a>
        </header>
        <div className="app__signin-body">
          <aside className="app__signin-hero" aria-label="Welcome to DeskRally"><RallyWelcome technician /></aside>
          <div className="app__login-overlay" data-testid="app-login-gate">
            {authNotice && <p role="status">{authNotice}</p>}
            <LoginForm api={consoleApiRef.current} onLogin={handleLogin} onSuccess={handleLoginSuccess} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app" data-nav-open={navOpen ? "true" : "false"} data-pane-mode={paneMode}
      data-natural-pane-mode={paneModeFor(viewportWidth)} data-chrome={chrome}>
      {minimalChrome && (
        <div className="session-tab" data-testid="session-tab" data-state={chrome} role="toolbar" aria-label="Session">
          <div className="session-tab__slot" ref={setTabHost} />
          <button
            type="button"
            className="session-tab__toggle"
            data-testid="session-tab-toggle"
            aria-expanded={chrome === "overlay"}
            aria-label="Show session controls"
            title="Show session controls"
            onClick={() => { focusAfterChrome.current = "collapse"; setChromeOpen(true); }}
            ref={toggleBtnRef}
          >
            ▾
          </button>
        </div>
      )}
      <header className={`app__topbar${chrome === "collapsed" ? " app__topbar--collapsed" : ""}${chrome === "overlay" ? " app__topbar--overlay" : ""}`}>
        {/* The drawer toggle is in the DOM at EVERY width and hidden by CSS where the machine list
            is a permanent pane. Rendering it conditionally on width would unmount part of the shell
            on a fold/unfold, and this tree must survive a live resize mid-session. */}
        <button
          type="button"
          className="app__navtoggle"
          data-testid="app-nav-toggle"
          aria-label={paneMode !== "stacked" ? "Hide machine list" : navOpen ? "Hide machines" : "Show machines"}
          title={paneMode !== "stacked" ? "Hide the machine list and give the session the whole window" : undefined}
          aria-expanded={paneMode !== "stacked" || navOpen}
          aria-controls="access-panel"
          onClick={onNavToggle}
        >
          ☰
        </button>
        {brandLogo && (
          <img
            className="app__brandlogo"
            src={brandLogo}
            alt=""
            data-testid="app-brand-logo"
            style={{ height: "1.75rem", verticalAlign: "middle", marginRight: "0.5rem" }}
          />
        )}
        <ToolbarMenu label="DeskRally" onOpenChange={setAppMenuOpen} badge={signedInAs && !barChrome ? helpBellView(helpRequests, helpAccept.unresolved ? 1 : 0).badge : null} badgeNoun="help requests waiting">
        <span className="app__brand"><RallyMark />DeskRally</span>
        {!barChrome && <a href="/downloads" target="_blank" rel="noopener noreferrer">Downloads</a>}
        {!desktopClient && <label>Connect in <select aria-label="Connect in" value={preferDesktop ? "desktop" : "browser"}
          onChange={e => { const desktop = e.target.value === "desktop"; setPreferDesktop(desktop);
            try { localStorage.setItem(DESKTOP_PREFERENCE_KEY, desktop ? "desktop" : "browser"); } catch { /* preference optional */ }
          }}><option value="desktop">Desktop app</option><option value="browser">Browser</option></select></label>}
        {/* Console areas stay available in the app menu without taking a second row. */}
        <nav className="app__viewswitch app__consolenav" aria-label="Console area">
          {CONSOLE_AREA_GROUPS.map((g) => {
            const inGroup = visibleAreas.filter((a) => a.group === g);
            if (inGroup.length === 0) return null;
            return (
              <div key={g} className="app__navgroup" role="tablist" aria-label={g} data-testid={`nav-group-${g.toLowerCase()}`}>
                <span className="app__navgroup-title" aria-hidden="true">{g}</span>
                {inGroup.map((a) => (
                  <button
                    key={a.id}
                    role="tab"
                    aria-selected={area === a.id}
                    data-active={area === a.id}
                    onClick={() => setArea(a.id)}
                  >
                    {a.label}
                  </button>
                ))}
              </div>
            );
          })}
        </nav>
        {/* Compact-layout toggle. Available at EVERY width, which is the point: the automatic band
            is right for a phone and still not what someone on a 700px foldable — or a wide desktop
            who wants the screen back — necessarily wants. `aria-pressed` rather than a checkbox,
            because it toggles the surrounding layout rather than submitting a value. */}
        <button
          type="button"
          className={`app__compact${layoutPref === "compact" ? " app__compact--on" : ""}`}
          data-testid="app-compact-toggle"
          aria-pressed={layoutPref === "compact"}
          title={
            layoutPref === "compact"
              ? "Compact layout is ON — the machine list is a drawer. Click to follow the window size instead."
              : "Compact layout: hide the machine list behind a menu button and give the session the whole window."
          }
          onClick={toggleCompactLayout}
        >
          {layoutPref === "compact" ? "Compact ✓" : "Compact"}
        </button>
        {!barChrome && bells}
        {!barChrome && whoami}
        {!barChrome && signOutButton}
        </ToolbarMenu>
        {/* Menu redesign wave 10: outside a live session the console's pages are a VISIBLE bar (Ed, 2026-11-07),
            built from the same groups as the menu above. In a live session (chrome other than "normal") it is not
            drawn, so the CRD-style tab row gains nothing; on a phone CSS hides it and the menu sheet is the drawer. */}
        {chrome === "normal" && (
          <nav className="app__areabar" aria-label="Console" data-testid="area-bar">
            {areaBarItems(visibleAreas, area).map((it) => it.kind === "direct" ? (
              <button key={it.group} type="button" className="app__areabtn" data-testid={`area-bar-${it.group.toLowerCase()}`}
                aria-current={it.current ? "page" : undefined}
                onClick={() => { if (!it.current) setArea(it.target.id as ConsoleArea); }}>
                {it.group}
              </button>
            ) : (
              <ToolbarMenu key={it.group} label={it.group} triggerTestId={`area-bar-${it.group.toLowerCase()}`}
                triggerClassName={`app__areabtn${it.current ? " app__areabtn--current" : ""}`} closeOnAction>
                {it.items.map((a) => (
                  <button key={a.id} type="button" className="app__areaitem" data-testid={`area-bar-item-${a.id}`}
                    aria-current={area === a.id ? "page" : undefined} onClick={() => setArea(a.id)}>
                    {a.label}
                  </button>
                ))}
              </ToolbarMenu>
            ))}
          </nav>
        )}
        {/* Wave 10b: the right end of the bar. A sibling of the nav, never inside it: the nav scrolls sideways
            (overflow-x), which would clip the bells' drop-down panels. */}
        {barChrome && (
          <div className="app__barend" data-testid="area-bar-end">
            {bells}
            <ToolbarMenu label="Account" triggerTestId="area-bar-account" triggerClassName="app__areabtn" closeOnAction>
              {whoami}
              {visibleAreas.filter((a) => a.group === "Account").map((a) => (
                <button key={a.id} type="button" className="app__areaitem" data-testid={`area-bar-item-${a.id}`}
                  aria-current={area === a.id ? "page" : undefined} onClick={() => setArea(a.id)}>
                  {a.label}
                </button>
              ))}
              <a className="app__areaitem" href="/downloads" target="_blank" rel="noopener noreferrer">Downloads</a>
              {signOutButton}
            </ToolbarMenu>
          </div>
        )}
        {accessEnded && (
          <div className="app__error" role="alert" data-testid="access-expired">
            <span>
              Your access to this organization {accessEnded.at ? `ended ${formatExpiry(new Date(accessEnded.at))}` : "has ended"}.
              Ask an administrator to extend it.
            </span>
          </div>
        )}
        {outsideHours && (
          <div className="app__error" role="alert" data-testid="access-outside-hours">
            <span>
              {outsideHours.window
                ? `Your access is limited to ${windowLabel(outsideHours.window)}; it is outside those hours now.`
                : "Your access is limited to set hours, and it is outside them now."}
            </span>
          </div>
        )}
        {error && (
          <div className="app__error" role="alert" data-testid="app-error">
            <span>{error}</span>
            <button type="button" onClick={() => setError(null)} aria-label="Dismiss message">Dismiss</button>
          </div>
        )}
        {area === "live" && session && <>
          <select className="app__session-select" aria-label="Session view" value={view}
            onChange={event => setView(event.target.value as typeof view)}>
            <option value="screen">Screen</option><option value="backstage">Under the Hood</option>
            <option value="files">Files</option><option value="chat">Chat</option>
          </select>
          <ToolbarMenu label="Session" onOpenChange={setSessionMenuOpen}>
            {/* Menu redesign wave 7: the machine and connection state first, then labelled sections. */}
            <span className="menu-section__identity" data-testid="session-menu-identity">{session.name} · {state}</span>
            <MenuSection title="Clipboard" testId="session-menu-clipboard">
            {!viewerPoppedOut && <ClipboardControl client={observing ? undefined : clipboardClient ?? undefined} notice={clipboardNotice} />}
            </MenuSection>
            <MenuSection title="Collaboration" testId="session-menu-collaboration">
            {/* docs/51: hand this control session to a colleague. Needs a control-plane session (canElevate
                is exactly "connected with one"); the server enforces the rest (holder, agent version). */}
            {canElevate && !observing && !outgoingTransfer && (
              <button type="button" className="panel__action" data-testid="session-transfer"
                title="Give this session to a colleague: they take it over and you leave"
                onClick={() => setTransferDialogOpen(true)}>Hand over session…</button>
            )}
            {/* Invite a colleague: a link to this machine, not a credential (an attended session's
                ephemeral machine cannot be reached by link, hence the same control-plane condition). */}
            {(canElevate || observing) && <SessionInvite device={session.device} allowControl={!observing} />}
            {/* docs/53: only an attended agent advertises this; the guest answers a dialog and UAC. */}
            <AdminRightsControl model={adminRights} observing={observing}
              onRequest={() => {
                setAdminRights((m) => adminRightsRequested(m));
                controlRef.current?.requestAdminRights();
              }} />
            {/* docs/61: hand keyboard/mouse control to another technician on this machine (or take it when
                its owner left). Only on the agent's affirmative capability; never for an observer. */}
            {/* A view-only session (policy floor, toggle, lost indicator) cannot hand or hold input either:
                the agent refuses it, so the action is not offered (the badge still shows who has it). */}
            <InputHandoffControl model={inputHandoff} observing={observing || viewOnly} ownSessionId={ownSignalingId}
              participants={participants}
              onHand={(to) => {
                setInputHandoff((m) => handRequested(m));
                controlRef.current?.handInputControl(to);
              }}
              onClaim={() => {
                if (!ownSignalingId) return;
                setInputHandoff((m) => handRequested(m));
                controlRef.current?.handInputControl(ownSignalingId);
              }} />
            </MenuSection>
            <MenuSection title="Connection" testId="session-menu-connection">
            {/* Pinned bar → back to the collapsed tab. Lives in this menu, not the row: the row is full. */}
            {chrome === "pinned" && (
              <button type="button" className="panel__action" data-testid="session-chrome-unpin"
                title="Hide the toolbar behind a small tab at the top edge"
                onClick={() => { focusAfterChrome.current = "toggle"; setChromePref("minimal"); }}>
                Hide toolbar
              </button>
            )}
              {view === "screen" && (
                <ConnectionDiagnostics
                  key={sessionGeneration.current}
                  sessionKey={String(sessionGeneration.current)}
                  getStats={getTransportStats}
                  connectionState={state}
                  stream={stream}
                />
              )}
            </MenuSection>
          </ToolbarMenu>
            {sessionParticipantCount > 0 && <span className="app__participants" title="Other technicians connected to this machine" data-testid="session-participants">
              {sessionParticipantCount} co-tech{sessionParticipantCount !== 1 ? "s" : ""}{sessionObserverCount > 0 && ` · ${sessionObserverCount} observing`}
            </span>}
            {observing && <span data-testid="observing-badge">Observing · view only</span>}
            <InputControlBadge model={inputHandoff} observing={observing} ownSessionId={ownSignalingId}
              participants={participants} />
        </>}
        <div className="app__toolbar-host" ref={setToolbarHost} />
        <div className="app__toolbar-end" ref={setToolbarEndHost} />
        {/* ▴ and Pin HANG below the dropped bar (absolute, top: 100%) rather than sitting in the row:
            the row is already full at phone widths, and anything added to it overflows the page. */}
        {chrome === "overlay" && (
          <div className="app__chrome-hang">
            <button type="button" className="app__chrome-btn" data-testid="session-chrome-pin"
              title="Keep the session toolbar always visible"
              onClick={() => { focusAfterChrome.current = "help"; setChromePref("pinned"); }}>
              📌 Pin
            </button>
            <button ref={collapseBtnRef} type="button" className="app__chrome-btn" data-testid="session-chrome-collapse"
              aria-label="Hide session controls" title="Hide session controls"
              onClick={() => { focusAfterChrome.current = "toggle"; setChromeOpen(false); setError(null); }}>
              ▴
            </button>
          </div>
        )}
        <button
          ref={helpBtnRef}
          type="button"
          className="app__help"
          data-testid="app-help"
          aria-label="Help"
          aria-expanded={helpOpen}
          title="Help"
          onClick={() => setHelpOpen((v) => !v)}
        >
          <span aria-hidden="true">?</span>
          <span className="app__help-label">Help</span>
        </button>
      </header>
      {helpOpen && (
        <aside className="app__helpdrawer" role="dialog" aria-label="Help" data-testid="help-drawer">
          <button type="button" className="app__helpdrawer-close" data-testid="help-drawer-close"
            onClick={() => setHelpOpen(false)} aria-label="Close help">
            ✕ Close
          </button>
          <HelpPanel />
        </aside>
      )}

      <div className="app__body">
        {/* Backdrop for the stacked-layout drawer. Also always present; CSS shows it only while the
            drawer is open in the stacked band. */}
        <div
          className="app__navbackdrop"
          data-testid="app-nav-backdrop"
          aria-hidden="true"
          onClick={() => setNavOpen(false)}
        />
        <AccessPanel
          machines={fleet}
          onConnect={handleConnectFromList}
          onObserve={(!desktopClient && preferDesktop) || (desktopClient && session && state !== "failed" && state !== "idle") ? undefined : (device, name, url, alias) => handleConnectFromList(device, name, url, alias, true)}
          activeDevice={session?.device ?? null}
          onEndSession={handleEndFleetSession}
          onPin={layoutPref === "compact" ? pinMachineList : undefined}
        />

        <main className="app__main">
          {chrome === "normal" && areaSubtabsHere && (
            <nav className="app__subtabs" aria-label={`${areaSubtabsHere.group} pages`} data-testid="area-subtabs">
              {areaSubtabsHere.pages.map((a) => (
                <button key={a.id} type="button" className="app__subtab" data-testid={`area-subtab-${a.id}`}
                  aria-current={area === a.id ? "page" : undefined} onClick={() => setArea(a.id)}>
                  {a.label}
                </button>
              ))}
            </nav>
          )}
          <IncomingTransfers offers={visibleOffers} accepting={acceptingTransfer} error={incomingTransferError}
            onAccept={(t) => void acceptIncomingTransfer(t)}
            onDismiss={(t) => setDismissedOffers((prev) => new Set(prev).add(t.id))}
            onClearError={() => setIncomingTransferError(null)} />
          {desktopRequest && authSession.isCurrent(desktopRequest.epoch) && <div role="status" className="panel__hint" data-testid="desktop-launch-notice">
            {desktopClient
              ? "Opening another DeskRally window. If it does not appear, retry or connect in this window instead."
              : "Opening DeskRally. Your browser may ask permission to open the app. If no app window appears, retry or connect in this browser instead."}
            {desktopMinVersion(window.location.origin) && ` This organization requires DeskRally ${desktopMinVersion(window.location.origin)} or newer.`}
            {" "}<a href={desktopRequest.uri}>Open app again</a>{" "}
            <button type="button" onClick={() => {
              const request = desktopRequest; setDesktopRequest(null);
              if (!authSession.isCurrent(request.epoch)) return;
              if (request.target.kind === "attended") void connectAttendedHere(request.target.id);
              else void handleConnect(asDeviceId(request.target.id), request.name, request.signalingUrl);
            }}>{desktopClient ? "Connect in this window instead" : "Connect in browser instead"}</button>
            <button type="button" onClick={() => setDesktopRequest(null)}>Dismiss</button>
          </div>}
          {area === "attended" && (
            <AttendedPanel api={consoleApiRef.current} onConnect={handleAttendedConnect}
              onOpenInApp={(id) => {
                if ((!desktopClient && preferDesktop) || (desktopClient && session && state !== "failed" && state !== "idle")) {
                  requestDesktop({ kind: "attended", id }); return true;
                }
                return false;
              }} />
          )}
          {area === "machines" && <MachinesPanel api={consoleApiRef.current}
            onConnect={(machine) => handleConnectFromList(asDeviceId(machine.device_id), machine.name || machine.device_id, DEFAULT_SIGNALING_URL, machine.alias || undefined)} />}
          {area === "sessions" && <SessionsPanel api={consoleApiRef.current} onOpenRecording={recordingsAllowed ? (id) => { setOpenRecordingId(id); setArea("recordings"); } : undefined} />}
          {area === "audit" && <AuditPanel api={consoleApiRef.current} />}
          {area === "recordings" && recordingsAllowed && <RecordingsPanel api={consoleApiRef.current} initialRecordingId={openRecordingId} />}
          {area === "reports" && <ReportsPanel api={consoleApiRef.current} />}
          {area === "platform" && platformOperator && <PlatformPanel api={consoleApiRef.current} />}
          {area === "toolbox" && <ToolboxPanel api={consoleApiRef.current} openBulkCore={(label, bulkId) => (device, signal) => BrokeredSessionCore.open(device, {
            api: consoleApiRef.current,
            authSession,
          }, { signal, note: `Bulk run ${bulkId}: ${label}` })} />}
          {area === "security" && <TenantSecurityPanel api={consoleApiRef.current} />}
          {area === "sites" && <SitesPanel api={consoleApiRef.current} />}
          {area === "groups" && <DynamicGroupsPanel api={consoleApiRef.current} />}
          {area === "machinegroups" && <MachineGroupsPanel api={consoleApiRef.current} />}
          {area === "apitokens" && <APITokensPanel api={consoleApiRef.current} />}
          {area === "enrollment" && <EnrollmentTokensPanel api={consoleApiRef.current} />}
          {area === "webhooks" && <WebhooksPanel api={consoleApiRef.current} />}
          {area === "appearance" && (
            <AppearancePanel api={consoleApiRef.current} onSaved={applyBranding} />
          )}
          {area === "users" && <UsersPanel api={consoleApiRef.current} />}
          {area === "roles" && <RolesPanel api={consoleApiRef.current} />}
          {area === "account" && <MyAccountPanel api={consoleApiRef.current} />}
          {area === "help" && <HelpPanel />}
          {area === "live" && session && (
            <div className="app__session">
              {transferDialogOpen && brokeredSessionRef.current && (
                <TransferDialog api={consoleApiRef.current} sessionId={brokeredSessionRef.current}
                  machineName={machineAlias ?? session.name}
                  onOffered={setOutgoingTransfer} onClose={() => setTransferDialogOpen(false)} />
              )}
              {outgoingTransfer && (
                <p role="status" className="panel__hint" data-testid="transfer-banner">
                  {outgoingTransfer.state === "pending" && <>
                    Waiting for {outgoingTransfer.to_name || "anyone in the group"} to accept{" "}
                    <button type="button" className="panel__action" data-testid="transfer-banner-cancel"
                      onClick={() => void cancelOutgoingTransfer()}>Cancel hand-off</button>
                  </>}
                  {outgoingTransfer.state === "releasing" &&
                    `${outgoingTransfer.accepted_by_name || "Your colleague"} accepted · handing the session over…`}
                  {outgoingTransfer.state !== "pending" && outgoingTransfer.state !== "releasing" && <>
                    {outgoingTransfer.state === "expired" ? "Nobody accepted the hand-off in time."
                      : outgoingTransfer.state === "failed" ? `The hand-off did not complete: ${outgoingTransfer.failure_reason ?? ""}`
                      : `The hand-off is ${outgoingTransfer.state}.`}{" "}
                    <button type="button" className="panel__action" onClick={() => setOutgoingTransfer(null)}>OK</button>
                  </>}
                </p>
              )}
              {/* F06 explicit approval: any unsolicited (verified) download surfaces here so the
                  operator can Save or Dismiss from any tab. The prompt calls approve/dismiss on
                  the CURRENT client — a stale click after the client was replaced is a no-op. */}
              <IncomingDownloadPrompt
                client={fileTransferClient ?? undefined}
                pending={pendingDownloads}
              />
              {view === "screen" && (
                <SessionViewer
                  toolbarHost={toolbarHost}
                  toolbarMenuOpen={appMenuOpen || sessionMenuOpen}
                  toolbarEndHost={toolbarEndHost}
                  tabHost={minimalChrome ? tabHost : null}
                  onPopoutChange={setViewerPoppedOut}
                  onVisibilityChange={onViewerVisibility}
                  popoutControls={<ClipboardControl client={observing ? undefined : clipboardClient ?? undefined} notice={clipboardNotice} />}
                  inputPanelExtras={<ClipboardQuick client={observing ? undefined : clipboardClient ?? undefined} />}
                  transport={transportRef.current ?? undefined}
                  stream={stream}
                  machineName={session.name}
                  machineAlias={machineAlias}
                  connectionState={state}
                  recoveryNotice={recoveryNotice}
                  onReconnect={reconnectManually}
                  audioAvailable={audioAvailable}
                  monitors={toMonitorInfo(monitors)}
                  onSelectMonitor={selectMonitor}
                  quality={effectiveQuality(qualityIntent)}
                  qualityStats={qualityStats}
                  qualitySupported={qualitySupported}
                  onSetQuality={applyQuality}
                  inputBlocked={inputBlocked}
                  onToggleInputBlock={observing ? undefined : toggleInputBlock}
                  monitorBlanked={monitorBlanked}
                  onToggleMonitorBlank={observing ? undefined : toggleMonitorBlank}
                  viewOnly={viewOnly}
                  onToggleViewOnly={toggleViewOnly}
                  viewOnlyEnforced={sessionPolicyState?.enforced ?? false}
                  sessionPolicy={sessionPolicyState ?? undefined}
                  onReboot={observing ? undefined : rebootGuest}
                  rebootStatus={rebootStatus}
                  onLock={observing ? undefined : lockGuest}
                  lockStatus={lockStatus}
                  onLogOff={observing ? undefined : logOffGuest}
                  logoffStatus={logoffStatus}
                  onShutDown={observing ? undefined : shutDownGuest}
                  shutdownStatus={shutdownStatus}
                  onLaunchTool={observing ? undefined : launchTool}
                  toolStatus={toolStatus}
                  onRunCommand={observing ? undefined : runCommand}
                  onElevatedRun={!observing && canElevate ? elevatedRun : undefined}
                  toolboxItems={toolboxItems}
                  onRefreshToolbox={!observing && canElevate ? refreshToolbox : undefined}
                  onRunToolboxItem={!observing && canElevate ? (it) => void runToolboxItem(it) : undefined}
                  toolboxError={toolboxError}
                  toolboxListError={toolboxListError}
                  elevationError={elevationError}
                  commandResult={commandResult}
                  commandPending={commandPending}
                  onScreenshot={requestScreenshot}
                  screenshotStatus={screenshotStatus}
                  onToggleRecording={observing || sessionPolicyState?.allowRecording === false ? undefined : toggleRecording}
                  recordingRequired={sessionPolicyState?.requireRecording === true}
                  recording={recording}
                  recordingPending={recordingPending}
                  recordingResult={recordingResult}
                  onSaveNote={!observing && canElevate ? saveSessionNote : undefined}
                  onBrowseDir={browseDir}
                  dirListing={dirListing}
                  dirLoading={dirLoading}
                  dirError={dirError}
                  onGetFileAccess={() => void handleFetchGrant().catch((e: unknown) => setError(`Get access failed: ${e instanceof Error ? e.message : String(e)}`))}
                  fileGrantInstalled={grantInstalled}
                  onDownloadFile={gateDownloadOnCapability(grantCapabilities, agentTransferDir, downloadFromBrowse)}
                  completedDownloadFiles={completedBrowseRelPaths}
                  onUploadFiles={observing ? undefined : gateUploadOnCapability(grantCapabilities, agentTransferDir, (files) => void uploadFromBrowse(files))}
                  browseUploads={browseUploads}
                  transferDirPath={agentTransferDir}
                  endSessionStatus={endSessionStatus}
                  onDisconnect={handleDisconnect}
                  pinnedMonitorId={pinnedMonitorId}
                  monitorCanvas={monitorCanvas}
                  onWatchedMonitors={ids => controlRef.current?.watchedMonitors(ids)}
                />
              )}
              {view === "backstage" && (
                <BackstagePanels
                  machineName={session.name}
                  client={backstageClient ?? undefined}
                  // H1 secure-mode hook: when a backstage request is denied for lack of a grant, the
                  // panel surfaces a paste-a-SignedGrant affordance and calls this to install it over
                  // the Control channel. Dev/synthetic agents self-issue a demo grant, so this never
                  // fires there. V3 replaces the pasted grant with a `POST /grant/mint` fetch.
                  onInstallGrant={(signedGrant) => {
                    setGrantCapabilities(parseGrantCapabilities(signedGrant));
                    controlRef.current?.installGrant(signedGrant);
                  }}
                  // V4 primary path: one-click "Get access" mints a grant from the control plane and
                  // installs it. Paste (onInstallGrant) stays as a manual fallback.
                  onFetchGrant={handleFetchGrant}
                  grantInstalled={grantInstalled}
                  grantNotice={grantResumeNotice}
                  fileManage={
                    !observing &&
                    // The AGENT advertises file_manage only when the grant it verified holds
                    // file_delete (docs/58 §2); a grant the console minted must agree.
                    backstageFeatures.has("file_manage") &&
                    grantCapabilities?.has("file_delete") !== false
                  }
                  // docs/58 §12: "Upload here" only when the agent says it can place uploads.
                  uploadToAgent={
                    !observing && backstageFeatures.has("file_place") && fileTransferClient
                      ? async (file: File) =>
                          fileTransferClient.uploadWithId(file.name, new Uint8Array(await file.arrayBuffer()))
                      : undefined
                  }
                />
              )}
              {view === "files" && (
                <FileTransferPanel client={fileTransferClient ?? undefined} download={download} />
              )}
              {view === "chat" && (
                <ChatPanel
                  client={chatClient ?? undefined}
                  messages={chatMessages}
                  truncated={chatTruncated}
                />
              )}
              {/* Signaling brokered this session without a relay credential (the account is at its cap). A strip
                  BELOW the remote picture, in the session area with the other session banners: never in the top
                  row, which is a CRD-style tab with no room for it, and clear of the collapsed tab that sits over
                  the top-centre of the window. Hiding it does not hide the cause from a failure message. */}
              {relayNotice && relayNoticeDismissedFor !== session.device && (
                <RelayNotice notice={relayNotice} onDismiss={() => setRelayNoticeDismissedFor(session.device)} />
              )}
            </div>
          )}
          {area === "live" && !session && (
            <div className="app__empty">
              <h1>Select a machine to control</h1>
              <p>Pick an online agent from the list, or enter a Device ID to connect.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
