/**
 * Management-console sessions view (Milestone M3): the tenant's remote-support sessions from
 * `GET /sessions`, newest first, with a live/ended badge and an "End" action on live rows
 * (`POST /sessions/{id}/end` then refresh — the `endSessionAndRefresh` flow in
 * `lib/console_panels.ts`, where the logic lives and is tested).
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { ConsoleApi, SessionRecord, SessionReportFilter } from "../lib/console_api";
import {
  capsSummary,
  datetimeLocalToUtcRfc3339,
  endSessionAndRefresh,
  filterSessionsByText,
  formatDurationSeconds,
  machineDisplayText,
  machineDisplayTooltip,
  sessionDurationSeconds,
  sessionStatus,
  sessionTone,
  setSessionNoteAndRefresh,
  sortSessionsNewestFirst,
} from "../lib/console_panels";
import { sessionsToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";

export interface SessionsPanelProps {
  api: ConsoleApi;
  /** Open a session's central recording (docs/63). The link shows only for rows the server gave a `recording_id`. */
  onOpenRecording?: (recordingId: string) => void;
}

/** A successful listing together with the exact applied date filter that produced it. */
export interface LoadedSessions {
  rows: readonly SessionRecord[];
  applied: SessionReportFilter | undefined;
}

/**
 * The rows that may be shown (and exported) for the CURRENT applied filter: only a listing fetched for exactly
 * this filter. Rows from any other query are never returned, so a response for an earlier date window cannot be
 * displayed or exported under the current one.
 */
export function sessionRowsForQuery(
  loaded: LoadedSessions | null,
  applied: SessionReportFilter | undefined,
): readonly SessionRecord[] {
  if (loaded === null || loaded.applied !== applied) return [];
  return loaded.rows;
}

export function SessionsPanel({ api, onOpenRecording }: SessionsPanelProps) {
  const [loaded, setLoaded] = useState<LoadedSessions | null>(null);
  // Bumped per request (refresh / End / note save) and on unmount: only the newest request may apply its outcome.
  const requestSeq = useRef(0);
  const [busy, setBusy] = useState(false);
  // The session id an End is in flight for (disables just that row's button).
  const [ending, setEnding] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Listing freshness, tracked apart from `error` (which any action, e.g. starting a note edit, may clear): set by
  // a newest request that failed, cleared only by a newest request that successfully re-listed.
  const [listingStale, setListingStale] = useState(false);
  // The session id whose note is being edited (null = none), its draft text, and the id a save is
  // in flight for. Only one note edits at a time.
  const [editingNote, setEditingNote] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [savingNote, setSavingNote] = useState<string | null>(null);
  // A since/until window on the session start (docs/01 §5), read as UTC — the applied filter drives the fetch.
  const [filterSince, setFilterSince] = useState("");
  const [filterUntil, setFilterUntil] = useState("");
  const [applied, setApplied] = useState<SessionReportFilter | undefined>(undefined);
  const [textQuery, setTextQuery] = useState("");

  const refresh = useCallback(async () => {
    const id = ++requestSeq.current;
    setBusy(true);
    setError(null);
    try {
      const listed = sortSessionsNewestFirst(await api.listSessions(applied));
      if (id !== requestSeq.current) return; // superseded by a newer request
      setLoaded({ rows: listed, applied });
      setListingStale(false);
    } catch (e) {
      if (id !== requestSeq.current) return;
      setListingStale(true);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (id === requestSeq.current) setBusy(false);
    }
  }, [api, applied]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Invalidate any in-flight request on unmount.
  useEffect(
    () => () => {
      requestSeq.current++;
    },
    [],
  );

  const rows = useMemo(() => sessionRowsForQuery(loaded, applied), [loaded, applied]);
  // Rows are kept across a failed refresh of the SAME query, but labelled; they are not exportable then.
  const staleRows = listingStale && rows.length > 0;

  const handleFilter = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      const since = datetimeLocalToUtcRfc3339(filterSince);
      const until = datetimeLocalToUtcRfc3339(filterUntil);
      const f: SessionReportFilter = {};
      if (since !== "") f.since = since;
      if (until !== "") f.until = until;
      setApplied(Object.keys(f).length > 0 ? f : undefined);
    },
    [filterSince, filterUntil],
  );

  const handleClear = useCallback(() => {
    setFilterSince("");
    setFilterUntil("");
    setApplied(undefined);
  }, []);

  const handleEnd = useCallback(
    async (id: string) => {
      const seq = ++requestSeq.current;
      setEnding(id);
      setBusy(true);
      setError(null);
      try {
        // Re-list with the applied date filter so ending a session does not revert a filtered view to all-time.
        const listed = await endSessionAndRefresh(api, id, applied);
        if (seq === requestSeq.current) {
          setLoaded({ rows: listed, applied });
          setListingStale(false);
        }
      } catch (e) {
        if (seq === requestSeq.current) {
          setListingStale(true);
          setError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        setEnding(null);
        if (seq === requestSeq.current) setBusy(false);
      }
    },
    [api, applied],
  );

  const startEditNote = useCallback((s: SessionRecord) => {
    setEditingNote(s.id);
    setNoteDraft(s.note);
    setError(null);
  }, []);

  const cancelEditNote = useCallback(() => {
    setEditingNote(null);
    setNoteDraft("");
  }, []);

  const handleSaveNote = useCallback(
    async (id: string) => {
      const seq = ++requestSeq.current;
      setSavingNote(id);
      setBusy(true);
      setError(null);
      try {
        // Re-list with the applied date filter so saving a note does not revert a filtered view to all-time.
        const listed = await setSessionNoteAndRefresh(api, id, noteDraft, applied);
        if (seq === requestSeq.current) {
          setLoaded({ rows: listed, applied });
          setListingStale(false);
          setEditingNote(null);
          setNoteDraft("");
        }
      } catch (e) {
        if (seq === requestSeq.current) {
          setListingStale(true);
          setError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        setSavingNote(null);
        if (seq === requestSeq.current) setBusy(false);
      }
    },
    [api, noteDraft, applied],
  );

  const filteredRows = useMemo(() => filterSessionsByText(rows, textQuery), [rows, textQuery]);

  const handleExport = useCallback(() => {
    // Export the sessions CURRENTLY SHOWN (honoring both the date filter and the text search) as a
    // CSV the browser saves — a pure serialization, no extra fetch. `filteredRows` derives only from rows
    // fetched for the current applied filter (see sessionRowsForQuery).
    saveBytesAsFile("sessions.csv", new TextEncoder().encode(sessionsToCsv(filteredRows)));
  }, [filteredRows]);

  return (
    <div className="panel panel--sessions">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Sessions</span>
        <input
          type="search"
          className="panel__search"
          placeholder="Search machine name, alias, device ID, technician, note…"
          aria-label="Search sessions"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="sessions-search"
        />
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={rows.length === 0 || staleRows || busy}
          title="Download the shown sessions as a CSV (honoring current search and date filter)"
          data-testid="sessions-export"
        >
          Export CSV
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="sessions-error">
            {error}
          </span>
        )}
        {staleRows && (
          <span className="panel__toolbar-error" data-testid="sessions-stale">
            Refresh failed — these rows are from the last successful load and may be out of date.
          </span>
        )}
      </div>
      <form className="panel__form" onSubmit={handleFilter}>
        <span className="panel__toolbar-title">Filter by date</span>
        <label className="panel__toolbar-field">
          Since (UTC)
          <input
            type="datetime-local"
            value={filterSince}
            onChange={(e) => setFilterSince(e.target.value)}
            data-testid="sessions-since"
          />
        </label>
        <label className="panel__toolbar-field">
          Until (UTC)
          <input
            type="datetime-local"
            value={filterUntil}
            onChange={(e) => setFilterUntil(e.target.value)}
            data-testid="sessions-until"
          />
        </label>
        {/* Not disabled while loading: a newer query supersedes the in-flight one (see requestSeq). */}
        <button className="panel__action" type="submit" data-testid="sessions-apply">
          Apply
        </button>
        {applied && (
          <button className="panel__action" type="button" onClick={handleClear} data-testid="sessions-clear">
            Clear
          </button>
        )}
      </form>
      <table className="panel__table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Machine</th>
            <th>Device ID</th>
            <th>Technician</th>
            <th>Started (UTC)</th>
            <th>Ended (UTC)</th>
            <th>Duration</th>
            <th>Under the Hood tools</th>
            <th>Note</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredRows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={10} data-testid="sessions-empty">
                {busy
                  ? "Loading…"
                  : error !== null
                    ? "Sessions could not be loaded for the current filter."
                    : textQuery.trim()
                      ? "No sessions match this search."
                      : "No sessions."}
              </td>
            </tr>
          )}
          {filteredRows.map((s) => (
            <tr key={s.id}>
              <td>
                <span className="panel__badge" data-tone={sessionTone(s)}>
                  {sessionStatus(s)}
                </span>
              </td>
              <td className="panel__name" title={machineDisplayTooltip(s.machine_alias, s.machine_name)}>
                {machineDisplayText(s.machine_alias, s.machine_name)}
              </td>
              <td className="panel__mono">{s.machine_device_id}</td>
              <td className="panel__mono">{s.technician_id}</td>
              <td className="panel__mono">{formatIsoUtc(s.started_at)}</td>
              <td className="panel__mono">{formatIsoUtc(s.ended_at)}</td>
              <td
                className="panel__mono"
                data-testid={`session-duration-${s.id}`}
                title={sessionStatus(s) === "live" ? "Duration since session started (as of last refresh)" : undefined}
              >
                {formatDurationSeconds(sessionDurationSeconds(s))}
              </td>
              <td className="panel__ellipsis" title={capsSummary(s.granted_caps)}>
                {capsSummary(s.granted_caps)}
              </td>
              <td data-testid={`session-note-${s.id}`}>
                {editingNote === s.id ? (
                  <div className="panel__note-edit">
                    <textarea
                      className="panel__note-input"
                      value={noteDraft}
                      onChange={(e) => setNoteDraft(e.target.value)}
                      rows={2}
                      data-testid={`session-note-input-${s.id}`}
                    />
                    <button
                      className="panel__action"
                      onClick={() => void handleSaveNote(s.id)}
                      disabled={savingNote !== null}
                      data-testid={`session-note-save-${s.id}`}
                    >
                      {savingNote === s.id ? "Saving…" : "Save"}
                    </button>
                    <button
                      className="panel__action"
                      onClick={cancelEditNote}
                      disabled={savingNote !== null}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="panel__note-view">
                    <span className="panel__ellipsis" title={s.note}>
                      {s.note || "—"}
                    </span>
                    <button
                      className="panel__action"
                      onClick={() => startEditNote(s)}
                      disabled={editingNote !== null}
                      data-testid={`session-note-edit-${s.id}`}
                    >
                      {s.note ? "Edit" : "Add"}
                    </button>
                  </div>
                )}
              </td>
              <td className="panel__col--action">
                {sessionStatus(s) === "live" && (
                  <button
                    className="panel__action panel__action--danger"
                    onClick={() => void handleEnd(s.id)}
                    disabled={ending !== null}
                  >
                    {ending === s.id ? "Ending…" : "End"}
                  </button>
                )}
                {s.recording_id && onOpenRecording && (
                  <button
                    className="panel__action"
                    type="button"
                    onClick={() => onOpenRecording(s.recording_id as string)}
                    data-testid={`session-recording-${s.id}`}
                    title="Open this session's stored recording"
                  >
                    Recording
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
