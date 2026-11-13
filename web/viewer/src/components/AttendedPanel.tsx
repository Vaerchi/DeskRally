/**
 * Attended (on-demand) support sessions — the console side of docs/12 §9.
 *
 * Start mints a one-time code + join link (`POST /attended-sessions`; the code is shown ONCE —
 * only its hash is stored). The panel then polls `GET /attended-sessions/{id}` while the user
 * redeems the code and answers the consent prompt; Connect stays disabled until the polled state
 * reaches `consented` (the SERVER refuses the ticket before consent — the button is a mirror of
 * the gate, not the gate). Connect (`POST …/connect`) hands the returned signaling envelope to
 * App's connect path, which drives the SAME WebRTC machinery as a machine-list connect. Promote
 * (`POST …/promote`) stashes an enrollment token the guest picks up to become permanent; End
 * closes the session and reaps the ephemeral machine.
 *
 * All non-render logic lives in `lib/console_panels.ts` (startAttendedFlow, connectAttendedFlow,
 * canConnectAttended, …) where it is unit-tested DOM-less.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { groupOptions, groupPaths, pathLabelFor } from "../lib/group_tree";
import { ManagedInstallDownload } from "./ManagedInstallDownload";
import type {
  AttendedSessionRecord,
  ConnectedAttendedSession,
  ConsoleApi,
  CreatedAttendedSession,
  MachineGroup,
} from "../lib/console_api";
import {
  ATTENDED_POLL_MS,
  attendedPollDone,
  attendedStateHint,
  attendedTone,
  canConnectAttended,
  connectAttendedFlow,
  pollAttendedSession,
  promoteResultMessage,
  startAttendedFlow,
} from "../lib/console_panels";

export interface AttendedPanelProps {
  api: ConsoleApi;
  onOpenInApp?: (sessionId: string) => boolean;
  /** Hand a consent-gated connect's signaling envelope to the live-session machinery. */
  /**
   * Hand the live session to the workspace.
   *
   * Takes the WHOLE connect response rather than spreading it into positional arguments. The signed
   * ACCESS policy it carries (present when the session's group enforces view-only) must be forwarded,
   * not dropped — an attended machine is ephemeral but NOT group-less, since redemption enrols it
   * into the invite's group, so a per-group mandate applies here exactly as it does to an ordinary
   * session. Passing one value means a field nobody destructures cannot be forgotten; `attendedHandoff`
   * does the mapping and is tested.
   */
  onConnect: (connected: ConnectedAttendedSession) => void;
}

export function AttendedPanel({ api, onConnect, onOpenInApp }: AttendedPanelProps) {
  const epoch = useRef(0);
  const revision = useRef(0);
  const [rows, setRows] = useState<AttendedSessionRecord[]>([]);
  const [nextOffset, setNextOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const listRequest = useRef(0);
  const [groupId, setGroupId] = useState("");
  const [groups, setGroups] = useState<MachineGroup[]>([]);
  // Path labels in tree order from the shared helper (docs/62), so equal group names never merge.
  const groupPathMap = useMemo(() => groupPaths(groups), [groups]);
  const groupPickerOptions = useMemo(() => groupOptions(groups), [groups]);
  const [loadingGroups, setLoadingGroups] = useState(true);
  const [groupError, setGroupError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [created, setCreated] = useState<CreatedAttendedSession | null>(null);
  const [session, setSession] = useState<AttendedSessionRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [promoted, setPromoted] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState<{ id: string; message: string } | null>(null);
  const copyRequest = useRef(0);
  const [error, setError] = useState<string | null>(null);
  // The id the poll loop watches; a ref so the interval closure always sees the latest.
  const watchIdRef = useRef<string | null>(null);

  const loadSessions = useCallback(async (offset = 0) => {
    const generation = epoch.current;
    const request = ++listRequest.current;
    setListBusy(true); setListError(null);
    try {
      const page = await api.listAttendedSessions(offset);
      if (epoch.current !== generation || listRequest.current !== request) return;
      setRows(previous => offset === 0 ? page.sessions : [...previous, ...page.sessions.filter(s => !previous.some(p => p.id === s.id))]);
      setHasMore(page.has_more); setNextOffset(offset + page.sessions.length);
    } catch {
      if (epoch.current === generation && listRequest.current === request) setListError("Could not load support sessions. Try Refresh.");
    } finally {
      if (epoch.current === generation && listRequest.current === request) setListBusy(false);
    }
  }, [api]);

  useEffect(() => {
    epoch.current++; revision.current++;
    copyRequest.current++; setCopyFeedback(null);
    setReason(""); setCreated(null); setSession(null); watchIdRef.current = null;
    setRows([]); setHasMore(false); setBusy(false); setConnecting(false); setPromoted(false); setError(null);
    void loadSessions();
    return () => { epoch.current++; revision.current++; copyRequest.current++; watchIdRef.current = null; };
  }, [api, loadSessions]);

  useEffect(() => {
    let active = true;
    setLoadingGroups(true);
    setGroups([]);
    setGroupId("");
    setGroupError(null);
    void api.listMachineGroups().then((items) => {
      if (!active) return;
      setGroups(items);
      // A sole group needs no configuration. Never invent a group ID for a real tenant.
      setGroupId(items.length === 1 ? items[0].id : "");
    }, () => {
      if (active) setGroupError("Could not load machine groups. Reopen this panel to try again.");
    }).finally(() => {
      if (active) setLoadingGroups(false);
    });
    return () => { active = false; };
  }, [api]);

  const handleStart = useCallback(async () => {
    const generation = epoch.current; revision.current++;
    copyRequest.current++; setCopyFeedback(null);
    setBusy(true);
    setError(null);
    setPromoted(false);
    const outcome = await startAttendedFlow(api, groupId, reason);
    if (epoch.current !== generation) return;
    setBusy(false);
    if (!outcome.ok) {
      setError(outcome.message);
      return;
    }
    setCreated(outcome.created);
    setSession(outcome.created.session);
    watchIdRef.current = outcome.created.session.id;
    void loadSessions();
  }, [api, groupId, reason, loadSessions]);

  // Consent watch: while a session is live and non-terminal, refresh its state every couple of
  // seconds. A failed poll is silently retried (transient network); terminal states stop it.
  useEffect(() => {
    if (!session || busy || connecting || attendedPollDone(session.state)) return;
    let active = true;
    const generation = epoch.current;
    const timer = setInterval(() => {
      const id = watchIdRef.current;
      if (!id) return;
      const version = revision.current;
      void pollAttendedSession(api, id).then((latest) => {
        if (active && epoch.current === generation && revision.current === version && latest && watchIdRef.current === latest.id) {
          setSession(latest);
          setRows(previous => previous.map(row => row.id === latest.id ? latest : row));
          // If the guest cancelled the install consent dialog (not a hard failure), re-enable
          // the promote button so the technician can request it again. A hard failure or
          // success leaves `promoted` true — the technician reads the result message instead.
          const pr = latest.promote_result;
          if (pr && !pr.success) {
            const err = pr.error ?? "";
            if (err.includes("declined") || err.includes("cancelled") || err.includes("UAC")) {
              setPromoted(false);
            }
          }
        }
      });
    }, ATTENDED_POLL_MS);
    return () => { active = false; clearInterval(timer); };
  }, [api, session, busy, connecting]);

  const handleConnect = useCallback(async () => {
    if (!session) return;
    if (onOpenInApp?.(session.id)) return;
    const generation = epoch.current; revision.current++;
    setConnecting(true);
    setError(null);
    const outcome = await connectAttendedFlow(api, session.id);
    if (epoch.current !== generation) return;
    setConnecting(false);
    if (!outcome.ok) {
      setError(outcome.awaitingConsent ? "The user has not consented yet." : outcome.message);
      return;
    }
    setSession(outcome.connected.session);
    onConnect(outcome.connected);
  }, [api, session, onConnect, onOpenInApp]);

  const handlePromote = useCallback(async () => {
    if (!session) return;
    const generation = epoch.current; revision.current++;
    setBusy(true);
    setError(null);
    try {
      await api.promoteAttendedSession(session.id);
      if (epoch.current === generation) setPromoted(true);
    } catch (e) {
      if (epoch.current === generation) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (epoch.current === generation) setBusy(false);
    }
  }, [api, session]);

  const handleEnd = useCallback(async () => {
    if (!session) return;
    const generation = epoch.current; revision.current++;
    setBusy(true);
    setError(null);
    try {
      const ended = await api.endAttendedSession(session.id);
      if (epoch.current !== generation) return;
      setSession(ended);
      setRows(previous => previous.map(row => row.id === ended.id ? ended : row));
    } catch (e) {
      if (epoch.current === generation) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (epoch.current === generation) setBusy(false);
    }
  }, [api, session]);

  async function copyInvitation(value: string, label: string) {
    if (!session) return;
    const id = session.id;
    const request = ++copyRequest.current;
    setCopyFeedback(null);
    try {
      await navigator.clipboard.writeText(value);
      if (copyRequest.current === request) setCopyFeedback({ id, message: `${label} copied.` });
    } catch {
      if (copyRequest.current === request) setCopyFeedback({ id, message: "Could not copy. Select and copy the code or link above." });
    }
  }

  const state = session?.state;
  const invitation = created?.session.id === session?.id ? created : null;
  function selectSession(row: AttendedSessionRecord) {
    copyRequest.current++; setCopyFeedback(null);
    revision.current++;
    watchIdRef.current = row.id;
    setSession(row); setPromoted(!!row.promote_result); setError(null);
  }

  return (
    <div className="panel panel--attended">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Support session</span>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="attended-error">
            {error}
          </span>
        )}
      </div>

      <div className="panel__form">
        <label className="panel__toolbar-field">
          Machine group
          <select
            data-testid="attended-group"
            value={groupId}
            onChange={(e) => setGroupId(e.target.value)}
            disabled={loadingGroups || busy || groups.length === 0}
          >
            <option value="" disabled>
              {loadingGroups ? "Loading groups…" : groups.length ? "Select a group…" : "No groups available"}
            </option>
            {groupPickerOptions.map((group) => <option key={group.id} value={group.id}>{group.label}</option>)}
          </select>
        </label>
        <label className="panel__toolbar-field">
          Reason (shown to the user)
          <input
            data-testid="attended-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. printer support"
          />
        </label>
        <button
          className="panel__action"
          data-testid="attended-start"
          onClick={() => void handleStart()}
          disabled={busy || connecting || loadingGroups || !groups.some((group) => group.id === groupId)}
        >
          {busy && !created ? "Starting…" : "Start support session"}
        </button>
      </div>
      {groupError && <p role="alert">{groupError}</p>}
      {!loadingGroups && !groupError && groups.length === 0 && (
        <p>Create a machine group under Machine groups, or ask your administrator for access to one.</p>
      )}

      <section aria-label="Shared support sessions" className="panel__detail">
        <h3>Support sessions</h3>
        <p>Sessions shared with your account and authorized colleagues. Select one to view its status and controls.</p>
        <button className="panel__action" onClick={() => void loadSessions()} disabled={listBusy}>Refresh</button>
        {listError && <p role="alert">{listError}</p>}
        {!listBusy && !listError && rows.length === 0 && <p>No support sessions found.</p>}
        <ul>{rows.map(row => <li key={row.id}>
          <button className="panel__action" aria-pressed={session?.id === row.id}
            disabled={busy || connecting} onClick={() => selectSession(row)}>
            {row.reason || "Support session"} — {pathLabelFor(groupPathMap, row.group_id)} — {row.state} — {new Date(row.created_at).toLocaleString()}
          </button>
        </li>)}</ul>
        {listBusy && <p role="status">Loading sessions…</p>}
        {hasMore && <button className="panel__action" disabled={listBusy} onClick={() => void loadSessions(nextOffset)}>Load more</button>}
      </section>

      {session && (
        <div className="panel__detail">
          {invitation && <>
          <p>
            Share this code or join link with the person you are helping. Keep this page open; the invitation cannot be retrieved after you leave.
          </p>
          {/* data-code carries the RAW code for the e2e harness; the text shows the grouped form. */}
          <p
            className="panel__mono panel__code"
            data-testid="attended-code"
            data-code={invitation.join_code}
          >
            {invitation.code}
          </p>
          <p>
            Join link:{" "}
            <a data-testid="attended-join-url" href={invitation.join_url}>
              {invitation.join_url}
            </a>
          </p>
          <div className="panel__actions-row">
            <button type="button" className="panel__action" data-testid="attended-copy-code" onClick={() => void copyInvitation(invitation.code, "Code")}>Copy code</button>
            <button type="button" className="panel__action" data-testid="attended-copy-link" onClick={() => void copyInvitation(new URL(invitation.join_url, window.location.href).href, "Link")}>Copy link</button>
            <span role="status">{copyFeedback?.id === session.id ? copyFeedback.message : ""}</span>
          </div>
          </>}
          <p>Invitation expires: <time dateTime={session.expires_at}>{new Date(session.expires_at).toLocaleString()}</time></p>
          {!invitation && session.state === "pending" && <p>The invitation code was shown only when this session was created. If it was lost, end this invitation and start a new support session.</p>}
          <p>Saved status does not confirm the guest is online. If the guest connection has ended, start a new support session with the guest.</p>
          <p>
            <span
              className="panel__badge"
              data-tone={attendedTone(session.state)}
              data-testid="attended-state"
            >
              {session.state}
            </span>{" "}
            <span data-testid="attended-hint">{attendedStateHint(session.state)}</span>
            {session.consent_user && <> Consented by: {session.consent_user}.</>}
          </p>
          <div className="panel__actions-row">
            <button
              className="panel__action"
              data-testid="attended-connect"
              onClick={() => void handleConnect()}
              disabled={!state || !canConnectAttended(state) || connecting || busy}
            >
              {connecting ? "Connecting…" : "Connect"}
            </button>
            <button
              className="panel__action"
              data-testid="attended-promote"
              onClick={() => void handlePromote()}
              disabled={!state || !canConnectAttended(state) || busy || connecting || promoted}
            >
              {promoted ? "Installation requested…" : "Enable unattended access"}
            </button>
            <button
              className="panel__action panel__action--danger"
              data-testid="attended-end"
              onClick={() => void handleEnd()}
              disabled={!state || attendedPollDone(state) || busy || connecting}
            >
              End
            </button>
          </div>
          {(() => {
            const msg = promoteResultMessage(promoted, session.promote_result);
            if (msg.pending) {
              return (
                <p className="panel__hint" data-testid="attended-promote-pending">
                  Waiting for guest to approve the Windows administrator prompt…
                </p>
              );
            }
            if (msg.text) {
              return (
                <p
                  className="panel__hint"
                  data-testid="attended-promote-result"
                  data-success={String(session.promote_result?.success ?? false)}
                >
                  {msg.text}
                </p>
              );
            }
            return null;
          })()}
          <p className="panel__hint">
            When unattended access is enabled, the guest must approve a Windows administrator
            prompt. A compatible Support client (attend CLI) triggers this automatically.
          </p>
          <ManagedInstallDownload api={api} groupId={session.group_id} />
        </div>
      )}
    </div>
  );
}
