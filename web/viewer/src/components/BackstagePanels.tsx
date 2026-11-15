/**
 * Backstage console: the tabbed container that fetches structured tool data through the
 * `BackstageClient` and renders the native panels (docs/04-backstage.md Part 1). It owns the
 * request lifecycle — tab selection, loading/error state, file-path navigation, the audit strip,
 * and the type-to-confirm retry for dangerous actions — while the panels stay presentational.
 *
 * The client is injectable (`client` prop) so this mounts against a live agent in production and a
 * mock transport in tests. Effects drive the fetches, so `renderToStaticMarkup` shows the initial
 * loading state without any network access.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  BackstageClient,
  auditActionLabel,
  auditOutcomeLabel,
  type AuditEvent,
  type BackstageError,
  type Envelope,
  type Request,
  type Response,
  type ServiceVerb,
} from "../backstage/client";
import type { ProcessRow, ServiceRow } from "../backstage/panels";
import { ProcessPanel } from "./ProcessPanel";
import { ServicesPanel } from "./ServicesPanel";
import { FileBrowserPanel, joinPath } from "./FileBrowserPanel";
import { SystemInfoPanel } from "./SystemInfoPanel";
import { EventLogPanel } from "./EventLogPanel";

type TabId = "processes" | "services" | "files" | "eventlog" | "sysinfo";

const TABS: { id: TabId; label: string }[] = [
  { id: "processes", label: "Processes" },
  { id: "services", label: "Services" },
  { id: "files", label: "Files" },
  { id: "eventlog", label: "Event Log" },
  { id: "sysinfo", label: "System" },
];

export interface BackstagePanelsProps {
  /** Machine name under control — the operator re-types this to confirm dangerous actions. */
  machineName: string;
  /** Injectable client (default talks to `/backstage/exec` via fetch). */
  client?: BackstageClient;
  /** Event-log channel to query for the Event Log tab (default "System"). */
  eventChannel?: string;
  /**
   * Secure-mode hook (H1): install a control-plane-signed `SignedGrant` (JSON) over the Control
   * channel. When provided, a "denied — no grant" error surfaces a paste-and-install affordance
   * (manual fallback). Dev/synthetic agents self-issue a demo grant, so this never fires there.
   */
  onInstallGrant?: (signedGrant: string) => void;
  /**
   * Secure-mode primary action (V4): fetch a signed grant from the control plane
   * (`POST /grant/mint`) and install it — the one-click "Get access" flow. Rejects (with a
   * human-readable message) on a mint/auth failure, which the panel surfaces. When provided, the
   * "denied — no grant" state shows a "Get access" button; the paste box remains as a fallback.
   */
  onFetchGrant?: () => Promise<void>;
  /** Set true once the agent acks a prior grant install; clears the affordance + retries the tab. */
  grantInstalled?: boolean;
  /** Why the automatic post-reconnect grant restore did not succeed (shown with the Get access state). */
  grantNotice?: string | null;
  /**
   * docs/58: offer New folder / Rename / Delete in the Files tab. The container sets it only when
   * the installed grant holds `file_delete` AND the agent advertised `file_manage`; the agent
   * enforces both regardless.
   */
  fileManage?: boolean;
  /**
   * docs/58 §12: upload a file to this machine's transfer folder and report its transfer id and the
   * name it landed under. Given only when the agent advertised `file_place`; enables "Upload here".
   */
  uploadToAgent?: (file: File) => Promise<{ ok: boolean; message: string; id: string }>;
}

/** One "Upload here" file and where it is in its two steps. */
export interface Placement {
  key: string;
  name: string;
  /** The folder it is being placed in, frozen when the upload started. */
  dest: string;
  phase: "uploading" | "placing" | "placed" | "failed" | "discarded";
  message: string;
  transferId?: string;
}

/**
 * docs/58 §12: placement works only onto the drive that holds the agent's transfer folder (C:). Said
 * BEFORE anything is uploaded, rather than after a file has crossed the network for nothing.
 */
export function placeableDestination(dest: string): string | null {
  return /^c:\\/i.test(dest) ? null : "Files can only be placed on drive C: in this version.";
}

/**
 * What the confirmation dialog says for a pending file operation: the agent's reason and the
 * RESOLVED path(s) it reported in the needs_confirmation record (docs/58 §7), so the operator
 * confirms the object the agent will actually touch, not the text they typed.
 */
export function describePendingFileOp(pending: Envelope, fallback: string): string {
  const action = (pending.audit as { action?: Record<string, unknown> } | undefined)?.action;
  const reason = (pending.error?.message ?? "").replace(/^action requires confirmation:\s*/, "");
  let target = fallback;
  if (action && typeof action.path === "string") target = action.path;
  else if (action && typeof action.from === "string" && typeof action.to === "string") target = `${action.from} → ${action.to}`;
  return reason ? `${target} (${reason})` : target;
}

/**
 * Does a `denied` error read like the agent has no backstage grant installed (secure mode)? The
 * dispatcher's denial message mentions the grant; we key off that so an ordinary policy denial
 * (which the operator cannot fix by installing a grant) does not offer the install affordance.
 */
function isNoGrantDenial(error: BackstageError | null): boolean {
  return !!error && error.kind === "denied" && /grant/i.test(error.message);
}

interface PendingConfirm {
  description: string;
  resolve: (proceed: boolean) => void;
}

/**
 * Confirmations are QUEUED: several can be pending at once (each file of a multi-file "Upload here",
 * or two quick clicks), and the dialog shows the oldest. Answering removes exactly the one answered;
 * a stale second answer for it (a double click) changes nothing.
 */
export function dequeueConfirm<T>(queue: readonly T[], answered: T): T[] {
  return queue[0] === answered ? queue.slice(1) : [...queue];
}

/** Map a tab to the read request that populates it. */
function requestForTab(tab: TabId, path: string, eventChannel: string): Request {
  switch (tab) {
    case "processes":
      return { type: "ListProcesses" };
    case "services":
      return { type: "ListServices" };
    case "files":
      return { type: "BrowseDirectory", data: { path } };
    case "eventlog":
      return { type: "ReadEventLog", data: { channel: eventChannel, max: 50 } };
    case "sysinfo":
      return { type: "GetSystemInfo" };
  }
}

export function BackstagePanels({
  machineName,
  client,
  eventChannel = "System",
  onInstallGrant,
  onFetchGrant,
  grantInstalled,
  grantNotice,
  fileManage,
  uploadToAgent,
}: BackstagePanelsProps) {
  // Keep a single client instance across renders when none is injected.
  const clientRef = useRef<BackstageClient | null>(client ?? null);
  if (client && clientRef.current !== client) clientRef.current = client;
  if (!clientRef.current) clientRef.current = new BackstageClient();
  const active = clientRef.current;

  const [tab, setTab] = useState<TabId>("processes");
  const [path, setPath] = useState(""); // "" = drive roots
  const [response, setResponse] = useState<Response | null>(null);
  const [error, setError] = useState<BackstageError | null>(null);
  const [audit, setAudit] = useState<AuditEvent | null>(null);
  const [loading, setLoading] = useState(false);
  const [confirmQueue, setConfirmQueue] = useState<PendingConfirm[]>([]);
  const pendingConfirm = confirmQueue[0] ?? null;
  const [confirmText, setConfirmText] = useState("");
  // H1: pasted `SignedGrant` JSON for the secure-mode install affordance (manual fallback).
  const [grantText, setGrantText] = useState("");
  // V4: in-flight state + error for the one-click "Get access" (control-plane mint) flow.
  const [fetchingGrant, setFetchingGrant] = useState(false);
  const [fetchGrantError, setFetchGrantError] = useState<string | null>(null);

  // Guard against out-of-order responses when the operator switches tabs quickly.
  const loadSeq = useRef(0);

  // What is on screen RIGHT NOW. A kill/service action awaits the agent (and maybe a confirm dialog),
  // so its completion must re-list the tab/folder the operator is looking at when it finishes, not
  // the one it started from. Assigned on every render so the refs never lag the state.
  const tabRef = useRef(tab);
  const pathRef = useRef(path);
  tabRef.current = tab;
  pathRef.current = path;

  const load = useCallback(
    async (which: TabId, atPath: string) => {
      const seq = ++loadSeq.current;
      setLoading(true);
      setError(null);
      try {
        const env = await active.exec(requestForTab(which, atPath, eventChannel));
        if (seq !== loadSeq.current) return; // superseded
        setAudit(env.audit ?? null);
        if (env.ok) {
          setResponse(env.response ?? null);
          setError(null);
        } else {
          setResponse(null);
          setError(env.error ?? { kind: "exec_failed", message: "unknown error" });
        }
      } catch (e) {
        if (seq !== loadSeq.current) return;
        setResponse(null);
        setAudit(null);
        setError({ kind: "exec_failed", message: e instanceof Error ? e.message : String(e) });
      } finally {
        if (seq === loadSeq.current) setLoading(false);
      }
    },
    [active, eventChannel],
  );

  useEffect(() => {
    void load(tab, path);
  }, [load, tab, path]);

  // H1: once the agent acks the installed grant, clear the paste box and retry the current tab —
  // the request that was `denied` for lack of a grant should now succeed.
  useEffect(() => {
    if (grantInstalled) {
      setGrantText("");
      void load(tab, path);
    }
    // Intentionally keyed only on `grantInstalled` so this fires on the ack, not on every tab change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [grantInstalled]);

  // --- Confirm dialog plumbing ---------------------------------------------

  const requestConfirm = useCallback((description: string): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      setConfirmQueue((q) => [...q, { description, resolve }]);
    });
  }, []);

  const resolveConfirm = useCallback(
    (proceed: boolean) => {
      if (!pendingConfirm) return;
      pendingConfirm.resolve(proceed);
      setConfirmQueue((q) => dequeueConfirm(q, pendingConfirm));
      setConfirmText("");
    },
    [pendingConfirm],
  );

  // Apply an action's result: surface audit + error, and refresh the list on success.
  const applyAction = useCallback(
    (env: Envelope) => {
      setAudit(env.audit ?? null);
      if (env.ok) {
        setError(null);
        // Read the refs, not the closure: the operator may have switched tab/folder since the action began.
        void load(tabRef.current, pathRef.current);
      } else {
        setError(env.error ?? { kind: "exec_failed", message: "unknown error" });
      }
    },
    [load],
  );

  const handleKill = useCallback(
    async (row: ProcessRow) => {
      const env = await active.killProcess(
        { pid: row.pid, image: row.name, owner: row.user ?? "" },
        () => requestConfirm(`Kill ${row.name} (PID ${row.pid}) on ${machineName}?`),
      );
      applyAction(env);
    },
    [active, requestConfirm, machineName, applyAction],
  );

  const handleControl = useCallback(
    async (row: ServiceRow, verb: ServiceVerb) => {
      const env = await active.controlService(
        { service: row.name, verb },
        () => requestConfirm(`${verbLabel(verb)} "${row.display_name}" on ${machineName}?`),
      );
      applyAction(env);
    },
    [active, requestConfirm, machineName, applyAction],
  );

  const handleNavigate = useCallback((next: string) => setPath(next), []);

  // docs/58 file management. Each change is one request through the confirm flow; the folder that
  // was on screen when it STARTED is the one it acts in (a later navigation does not retarget it),
  // and the listing re-reads whatever is on screen when it settles (applyAction).
  const [fileBusy, setFileBusy] = useState(false);
  const runFileOp = useCallback(
    async (op: (confirm: (pending: Envelope) => Promise<boolean>) => Promise<Envelope>, label: string) => {
      setFileBusy(true);
      try {
        const env = await op((pending) =>
          requestConfirm(`${label} on ${machineName}: ${describePendingFileOp(pending, label)}?`),
        );
        applyAction(env);
      } catch (e) {
        // The transport closed (a missed reply or a failed send). The change may or may not have
        // happened; it is never retried automatically.
        setError({ kind: "exec_failed", message: e instanceof Error ? e.message : String(e) });
      } finally {
        setFileBusy(false);
      }
    },
    [requestConfirm, machineName, applyAction],
  );
  const handleNewFolder = useCallback(
    (name: string) => {
      const target = joinPath(path, name);
      void runFileOp((c) => active.createDirectory(target, c), `Create folder ${target}`);
    },
    [active, path, runFileOp],
  );
  const handleRename = useCallback(
    (from: string, to: string) => {
      const a = joinPath(path, from);
      const b = joinPath(path, to);
      void runFileOp((c) => active.renamePath(a, b, c), `Rename ${a} to ${to}`);
    },
    [active, path, runFileOp],
  );
  // docs/58 §12 "Upload here": each file is uploaded to the transfer folder, then placed by its
  // transfer id in the folder that was on screen when the upload STARTED (navigating away does not
  // move it). Two steps, reported separately; a failed placement offers Discard.
  const [placements, setPlacements] = useState<Placement[]>([]);
  const updatePlacement = useCallback((key: string, patch: Partial<Placement>) => {
    setPlacements((ps) => ps.map((p) => (p.key === key ? { ...p, ...patch } : p)));
  }, []);
  const handleUploadHere = useCallback(
    (files: File[]) => {
      if (!uploadToAgent) return;
      const dest = path;
      const refused = placeableDestination(dest);
      for (const file of files) {
        const key = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        setPlacements((ps) => [
          ...ps,
          { key, name: file.name, dest, phase: refused ? "failed" : "uploading", message: refused ?? "Uploading…" },
        ]);
        if (refused) continue;
        void (async () => {
          try {
            const up = await uploadToAgent(file);
            if (!up.ok) {
              updatePlacement(key, { phase: "failed", message: `Upload failed: ${up.message || "rejected by the agent"}` });
              return;
            }
            updatePlacement(key, { phase: "placing", transferId: up.id, message: `Uploaded${up.message && up.message !== file.name ? ` as ${up.message}` : ""}; placing…` });
            const env = await active.placeUpload(up.id, dest, (pending) =>
              requestConfirm(`Place ${file.name} on ${machineName}: ${describePendingFileOp(pending, dest)}?`),
            );
            if (env.ok) {
              updatePlacement(key, { phase: "placed", message: `Placed in ${dest}` });
              if (pathRef.current === dest) void load(tabRef.current, pathRef.current);
            } else {
              updatePlacement(key, {
                phase: "failed",
                message: `Uploaded, but not placed: ${env.error?.message ?? "refused"}. It is in the agent's transfer folder.`,
              });
            }
          } catch (e) {
            // A closed transport: the outcome is unknown and nothing is retried automatically.
            updatePlacement(key, { phase: "failed", message: e instanceof Error ? e.message : String(e) });
          }
        })();
      }
    },
    [uploadToAgent, path, active, requestConfirm, machineName, updatePlacement, load],
  );
  const handleDiscard = useCallback(
    async (p: Placement) => {
      if (!p.transferId) return;
      try {
        const env = await active.discardUpload(p.transferId, () => Promise.resolve(true));
        updatePlacement(p.key, env.ok ? { phase: "discarded", message: "Discarded from the transfer folder" } : { message: env.error?.message ?? "discard refused" });
      } catch (e) {
        updatePlacement(p.key, { message: e instanceof Error ? e.message : String(e) });
      }
    },
    [active, updatePlacement],
  );

  const handleDelete = useCallback(
    (name: string) => {
      const target = joinPath(path, name);
      void runFileOp((c) => active.deletePath(target, c), `Delete ${target}`);
    },
    [active, path, runFileOp],
  );

  const refresh = useCallback(() => void load(tab, path), [load, tab, path]);

  const handleInstallGrant = useCallback(() => {
    const grant = grantText.trim();
    if (grant && onInstallGrant) onInstallGrant(grant);
  }, [grantText, onInstallGrant]);

  // V4: one-click "Get access" — ask App to mint a grant from the control plane + install it. On
  // success the agent acks `GrantInstalled`, which flips `grantInstalled` and retries the tab (the
  // effect above). On failure surface the mint/auth error inline (e.g. 401 → log in, 403 → denied).
  const handleFetchGrant = useCallback(async () => {
    if (!onFetchGrant) return;
    setFetchingGrant(true);
    setFetchGrantError(null);
    try {
      await onFetchGrant();
    } catch (e) {
      setFetchGrantError(e instanceof Error ? e.message : String(e));
    } finally {
      setFetchingGrant(false);
    }
  }, [onFetchGrant]);

  // Clear any prior fetch error once a grant is installed (the affordance is about to disappear).
  useEffect(() => {
    if (grantInstalled) setFetchGrantError(null);
  }, [grantInstalled]);

  const showGrantAffordance = (!!onInstallGrant || !!onFetchGrant) && isNoGrantDenial(error);

  return (
    <div className="backstage">
      <div className="backstage__bar">
        <div className="backstage__tabs" role="tablist">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              className="backstage__tab"
              data-active={tab === t.id}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
        <span className="backstage__spacer" />
        {loading && <span className="backstage__loading">Loading…</span>}
        <button className="backstage__refresh" onClick={refresh}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="backstage__error" data-kind={error.kind} role="alert">
          <strong>{errorHeadline(error.kind)}</strong> {error.message}
        </div>
      )}

      {showGrantAffordance && (
        <div className="backstage__grant" data-testid="backstage-grant">
          <p className="backstage__grant-desc">
            This machine is in secure mode and requires a signed backstage grant. Fetch one from the
            control plane to authorize these tools, or paste a <code>SignedGrant</code> JSON manually.
          </p>

          {onFetchGrant && (
            <div className="backstage__grant-actions">
              <button
                data-testid="backstage-grant-fetch"
                disabled={fetchingGrant}
                onClick={() => void handleFetchGrant()}
              >
                {fetchingGrant ? "Getting access…" : "Get access (fetch grant from control plane)"}
              </button>
            </div>
          )}

          {grantNotice && !fetchGrantError && (
            <div className="backstage__grant-fetch-error" data-testid="backstage-grant-resume-notice" role="alert">
              {grantNotice}
            </div>
          )}

          {fetchGrantError && (
            <div className="backstage__grant-fetch-error" data-testid="backstage-grant-fetch-error" role="alert">
              {fetchGrantError}
            </div>
          )}

          {onInstallGrant && (
            <>
              <p className="backstage__grant-fallback">Or paste a grant manually:</p>
              <textarea
                className="backstage__grant-input"
                data-testid="backstage-grant-input"
                placeholder='{"claims":…,"sig":…}'
                value={grantText}
                onChange={(e) => setGrantText(e.target.value)}
                rows={3}
              />
              <div className="backstage__grant-actions">
                <button
                  data-testid="backstage-grant-install"
                  disabled={grantText.trim() === ""}
                  onClick={handleInstallGrant}
                >
                  Install grant
                </button>
              </div>
            </>
          )}
        </div>
      )}

      <div className="backstage__body">{renderBody()}</div>

      {placements.length > 0 && (
        <ul className="backstage__placements" data-testid="files-placements">
          {placements.map((p) => (
            <li key={p.key} data-phase={p.phase} data-testid={`files-placement-${p.name}`}>
              <strong>{p.name}</strong> → <code>{p.dest}</code>: {p.message}{" "}
              {p.phase === "failed" && p.transferId && (
                <button type="button" className="panel__action" onClick={() => void handleDiscard(p)} data-testid={`files-placement-discard-${p.name}`}>
                  Discard upload
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <AuditStrip audit={audit} />

      {pendingConfirm && (
        <div className="backstage__confirm-backdrop" role="dialog" aria-modal="true">
          <div className="backstage__confirm">
            <p className="backstage__confirm-desc">{pendingConfirm.description}</p>
            {confirmQueue.length > 1 && (
              <p className="backstage__confirm-hint" data-testid="backstage-confirm-more">
                {confirmQueue.length - 1} more waiting for confirmation after this one.
              </p>
            )}
            <p className="backstage__confirm-hint">
              Type the machine name <code>{machineName}</code> to confirm this action.
            </p>
            <input
              className="backstage__confirm-input"
              autoFocus
              value={confirmText}
              placeholder={machineName}
              onChange={(e) => setConfirmText(e.target.value)}
            />
            <div className="backstage__confirm-actions">
              <button onClick={() => resolveConfirm(false)}>Cancel</button>
              <button
                className="panel__action--danger"
                disabled={confirmText !== machineName}
                onClick={() => resolveConfirm(true)}
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  function renderBody() {
    switch (tab) {
      case "processes":
        if (response?.type === "ProcessList")
          return <ProcessPanel rows={response.data} onKill={handleKill} />;
        break;
      case "services":
        if (response?.type === "ServiceList")
          return <ServicesPanel rows={response.data} onControl={handleControl} />;
        break;
      case "files":
        if (response?.type === "DirectoryListing")
          return (
            <FileBrowserPanel
              listing={response.data}
              onNavigate={handleNavigate}
              manage={
                fileManage
                  ? {
                      onNewFolder: handleNewFolder,
                      onRename: handleRename,
                      onDelete: handleDelete,
                      busy: fileBusy,
                      onUploadHere: uploadToAgent ? handleUploadHere : undefined,
                    }
                  : undefined
              }
            />
          );
        break;
      case "eventlog":
        if (response?.type === "EventLog") return <EventLogPanel rows={response.data} />;
        break;
      case "sysinfo":
        if (response?.type === "SystemInfo") return <SystemInfoPanel info={response.data} />;
        break;
    }
    if (loading) return <p className="backstage__status">Loading…</p>;
    if (!error) return <p className="backstage__status">No data.</p>;
    return null; // error banner is already shown above
  }
}

function AuditStrip({ audit }: { audit: AuditEvent | null }) {
  if (!audit) return null;
  // The live agent serializes outcome/action as Rust-enum objects; coerce to display strings so a
  // React child is never an object (which would throw). `hash` is always a hex string.
  const outcome = auditOutcomeLabel(audit);
  const action = auditActionLabel(audit);
  return (
    <div className="backstage__audit" title="tamper-evident audit record">
      <span className="backstage__audit-label">audit</span>
      <span className="backstage__audit-outcome" data-outcome={outcome}>
        {outcome}
      </span>
      {action && <span className="backstage__audit-action">{action}</span>}
      <code className="backstage__audit-hash" data-testid="backstage-audit-hash">
        {shortHash(audit.hash)}
      </code>
    </div>
  );
}

function shortHash(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-8)}` : hash;
}

function verbLabel(verb: ServiceVerb): string {
  return verb.charAt(0).toUpperCase() + verb.slice(1);
}

function errorHeadline(kind: BackstageError["kind"]): string {
  switch (kind) {
    case "denied":
      return "Denied.";
    case "needs_confirmation":
      return "Confirmation required.";
    case "refused":
      return "Refused.";
    case "exec_failed":
      return "Failed.";
  }
}
