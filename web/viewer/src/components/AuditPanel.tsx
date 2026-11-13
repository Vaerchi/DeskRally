/**
 * Management-console audit view (Milestone M3): the tenant's management-plane audit trail from
 * `GET /audit?limit=N` (who did what in the console — machine enrolled, session started, tenant
 * created), newest first as the server returns it. A limit selector re-fetches on change; the
 * actor/target/metadata cells render via the pure helpers in `lib/console_panels.ts`.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { AuditListFilter, ConsoleApi, MgmtAuditEvent } from "../lib/console_api";
import {
  AUDIT_LIMIT_CHOICES,
  DEFAULT_AUDIT_LIMIT,
  datetimeLocalToUtcRfc3339,
  filterAuditEventsByText,
  formatActor,
  formatAuditTarget,
  metadataSummary,
} from "../lib/console_panels";
import { auditEventsToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";

export interface AuditPanelProps {
  api: ConsoleApi;
}

/** A successful listing together with the exact query (limit + applied filter) that produced it. */
export interface LoadedAudit {
  rows: readonly MgmtAuditEvent[];
  limit: number;
  applied: AuditListFilter | undefined;
}

/**
 * The rows that may be shown (and exported) as the result of the CURRENT controls: only a listing fetched
 * for exactly this limit and applied filter. Rows from any other query are never returned, so a response
 * for an earlier filter cannot be displayed or exported under the current one.
 */
export function auditRowsForQuery(
  loaded: LoadedAudit | null,
  limit: number,
  applied: AuditListFilter | undefined,
): readonly MgmtAuditEvent[] {
  if (loaded === null || loaded.limit !== limit || loaded.applied !== applied) return [];
  return loaded.rows;
}

export function AuditPanel({ api }: AuditPanelProps) {
  const [loaded, setLoaded] = useState<LoadedAudit | null>(null);
  // Bumped per request (and on unmount): only the newest request may apply its outcome.
  const requestSeq = useRef(0);
  const [limit, setLimit] = useState(DEFAULT_AUDIT_LIMIT);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The audit-search form, and the filter currently APPLIED to the listing (undefined = all).
  const [filterAction, setFilterAction] = useState("");
  const [filterKind, setFilterKind] = useState("");
  const [filterActor, setFilterActor] = useState("");
  const [filterSince, setFilterSince] = useState("");
  const [filterUntil, setFilterUntil] = useState("");
  const [applied, setApplied] = useState<AuditListFilter | undefined>(undefined);
  const [textQuery, setTextQuery] = useState("");

  const refresh = useCallback(async () => {
    const id = ++requestSeq.current;
    setBusy(true);
    setError(null);
    try {
      const events = await api.listAudit(limit, applied);
      if (id !== requestSeq.current) return; // superseded by a newer request
      setLoaded({ rows: events, limit, applied });
    } catch (e) {
      if (id !== requestSeq.current) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (id === requestSeq.current) setBusy(false);
    }
  }, [api, limit, applied]);

  // Load on mount and whenever the limit or the applied filter changes.
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

  const rows = useMemo(() => auditRowsForQuery(loaded, limit, applied), [loaded, limit, applied]);
  // Rows are kept across a failed refresh of the SAME query, but labelled; they are not exportable then.
  const staleRows = error !== null && rows.length > 0;

  const handleFilter = useCallback((e: FormEvent) => {
    e.preventDefault();
    const action = filterAction.trim();
    const targetKind = filterKind.trim();
    const actor = filterActor.trim();
    // The datetime-local inputs are read as UTC (the panel displays UTC), so an entry like
    // "2026-08-17T12:00" becomes the RFC3339 instant "2026-08-17T12:00:00Z" the server expects.
    const since = datetimeLocalToUtcRfc3339(filterSince);
    const until = datetimeLocalToUtcRfc3339(filterUntil);
    const anySet = action !== "" || targetKind !== "" || actor !== "" || since !== "" || until !== "";
    setApplied(anySet ? { action, targetKind, actor, since, until } : undefined);
  }, [filterAction, filterKind, filterActor, filterSince, filterUntil]);

  const handleClear = useCallback(() => {
    setFilterAction("");
    setFilterKind("");
    setFilterActor("");
    setFilterSince("");
    setFilterUntil("");
    setApplied(undefined);
  }, []);

  const filteredRows = useMemo(() => filterAuditEventsByText(rows, textQuery), [rows, textQuery]);

  const handleExport = useCallback(() => {
    // Export events CURRENTLY shown (honoring both the server-side filter and the text search) as CSV.
    // `filteredRows` derives only from rows fetched for the current limit/filter (see auditRowsForQuery).
    saveBytesAsFile("audit-events.csv", new TextEncoder().encode(auditEventsToCsv(filteredRows)));
  }, [filteredRows]);

  return (
    <div className="panel panel--audit">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Audit</span>
        <label className="panel__toolbar-field">
          Show
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            aria-label="Audit event limit"
          >
            {AUDIT_LIMIT_CHOICES.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <input
          type="search"
          className="panel__search"
          placeholder="Search action, actor, target, IP, details…"
          aria-label="Search audit events"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="audit-search"
        />
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={busy || staleRows || filteredRows.length === 0}
          title="Download the shown audit events as a CSV (honoring current search and server-side filter)"
          data-testid="audit-export"
        >
          Export CSV
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="audit-error">
            {error}
          </span>
        )}
        {staleRows && (
          <span className="panel__toolbar-error" data-testid="audit-stale">
            Refresh failed — these rows are from the last successful load and may be out of date.
          </span>
        )}
      </div>
      <form className="panel__form" onSubmit={handleFilter}>
        <span className="panel__toolbar-title">Search</span>
        <label className="panel__toolbar-field">
          Action
          <input
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            placeholder="machine.enroll"
            data-testid="audit-filter-action"
          />
        </label>
        <label className="panel__toolbar-field">
          Target
          <input
            value={filterKind}
            onChange={(e) => setFilterKind(e.target.value)}
            placeholder="machine"
            data-testid="audit-filter-kind"
          />
        </label>
        <label className="panel__toolbar-field">
          Actor
          <input
            value={filterActor}
            onChange={(e) => setFilterActor(e.target.value)}
            placeholder="user or token id"
            data-testid="audit-filter-actor"
          />
        </label>
        <label className="panel__toolbar-field">
          Since (UTC)
          <input
            type="datetime-local"
            value={filterSince}
            onChange={(e) => setFilterSince(e.target.value)}
            data-testid="audit-filter-since"
          />
        </label>
        <label className="panel__toolbar-field">
          Until (UTC)
          <input
            type="datetime-local"
            value={filterUntil}
            onChange={(e) => setFilterUntil(e.target.value)}
            data-testid="audit-filter-until"
          />
        </label>
        {/* Not disabled while loading: a newer query supersedes the in-flight one (see requestSeq). */}
        <button className="panel__action" type="submit" data-testid="audit-filter-apply">
          Filter
        </button>
        {applied && (
          <button
            className="panel__action"
            type="button"
            onClick={handleClear}
            data-testid="audit-filter-clear"
          >
            Clear
          </button>
        )}
      </form>
      <table className="panel__table">
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Target</th>
            <th>Source IP</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {filteredRows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={6} data-testid="audit-empty">
                {busy
                  ? "Loading…"
                  : error !== null
                    ? "Audit events could not be loaded for the current filter."
                    : textQuery.trim() && applied
                    ? "No audit events match this search and filter."
                    : textQuery.trim()
                      ? "No audit events match this search."
                      : applied
                        ? "No audit events match this filter."
                        : "No audit events."}
              </td>
            </tr>
          )}
          {filteredRows.map((e) => (
            <tr key={e.id}>
              <td className="panel__mono">{formatIsoUtc(e.occurred_at)}</td>
              <td className="panel__name">{e.action}</td>
              <td className="panel__mono">{formatActor(e)}</td>
              <td className="panel__mono panel__ellipsis" title={formatAuditTarget(e)}>
                {formatAuditTarget(e)}
              </td>
              <td className="panel__mono" data-testid="audit-source-ip">
                {e.source_ip ?? ""}
              </td>
              <td className="panel__mono panel__ellipsis" title={metadataSummary(e.metadata)}>
                {metadataSummary(e.metadata)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
