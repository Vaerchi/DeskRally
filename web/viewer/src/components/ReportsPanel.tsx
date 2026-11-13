/**
 * Reports (docs/01 §5). Two aggregations of the tenant's activity, selectable by report type:
 *   • "Events by action" — a per-ACTION aggregation of the management-plane audit trail from
 *     `GET /audit/summary` (CapViewAudit), optionally within a UTC time window.
 *   • "Sessions by machine" — a per-MACHINE count of remote-support sessions from
 *     `GET /reports/sessions-by-machine` (CapViewSessions, group-scoped like the session list).
 * The server enforces each report's capability; the panel stays thin like the other console panels.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type {
  AuditActionCount,
  AuditListFilter,
  ConsoleApi,
  MachineSessionCount,
  SessionReportFilter,
  TechnicianSessionCount,
  UserSummary,
} from "../lib/console_api";
import {
  datetimeLocalToUtcRfc3339,
  formatDurationSeconds,
  reportChartRows,
  technicianLabel,
} from "../lib/console_panels";
import { barChart } from "../lib/report_chart";
import { ReportBarChart } from "./ReportBarChart";
import { saveBytesAsFile } from "./FileTransferPanel";
import { auditSummaryToCsv, machineSessionsToCsv, technicianSessionsToCsv } from "../lib/report_csv";

export interface ReportsPanelProps {
  api: ConsoleApi;
}

export type ReportType = "actions" | "sessions" | "technicians";

/** The row type each report type loads. */
interface ReportRowMap {
  actions: AuditActionCount;
  sessions: MachineSessionCount;
  technicians: TechnicianSessionCount;
}

/** The applied filter a report was fetched with: the audit filter (actions) or the date window (sessions/technicians). */
export type ReportApplied = AuditListFilter | SessionReportFilter | undefined;

/** A successful report load together with the exact report type and applied filter that produced it. */
export interface LoadedReport {
  rows: readonly ReportRowMap[ReportType][];
  reportType: ReportType;
  applied: ReportApplied;
}

/**
 * The rows that may be shown, charted, totalled and exported for the CURRENT report type + applied filter: only a
 * load fetched for exactly this query. Rows from any other report type or filter are never returned, so a response
 * for an earlier query cannot be presented as the current report.
 */
export function reportRowsForQuery<T extends ReportType>(
  loaded: LoadedReport | null,
  query: { reportType: T; applied: ReportApplied },
): readonly ReportRowMap[T][] {
  if (loaded === null || loaded.reportType !== query.reportType || loaded.applied !== query.applied) return [];
  return loaded.rows as readonly ReportRowMap[T][];
}

/** The print header's one-line provenance: report name, every applied filter, and the totals. Pure
 *  so its wording is pinned by tests — a report printed to PDF must say exactly what it covers. */
export function reportPrintSubtitle(
  reportType: ReportType,
  applied: ReportApplied,
  rowCount: number,
  total: number,
): string {
  const name =
    reportType === "sessions"
      ? "Sessions by machine"
      : reportType === "technicians"
        ? "Sessions by technician"
        : "Events by action";
  const parts: string[] = [];
  if (applied) {
    const a = applied as AuditListFilter & SessionReportFilter;
    if (a.action) parts.push(`action=${a.action}`);
    if (a.targetKind) parts.push(`target=${a.targetKind}`);
    if (a.actor) parts.push(`actor=${a.actor}`);
    if (a.since) parts.push(`since ${a.since}`);
    if (a.until) parts.push(`until ${a.until}`);
  }
  const filters = parts.length > 0 ? parts.join(", ") : "no filter";
  return `${name} — ${filters} — ${rowCount} rows, total ${total}`;
}

export function ReportsPanel({ api }: ReportsPanelProps) {
  const [reportType, setReportType] = useState<ReportType>("actions");
  // Whether the report is shown as a bar chart (in ADDITION to the table).
  const [showChart, setShowChart] = useState(false);
  const [loaded, setLoaded] = useState<LoadedReport | null>(null);
  // Bumped per request and on unmount: only the newest request may apply its outcome.
  const requestSeq = useRef(0);
  // Set by a newest request that failed, cleared only by a newest request that succeeded.
  const [listingStale, setListingStale] = useState(false);
  const [users, setUsers] = useState<readonly UserSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterSince, setFilterSince] = useState("");
  const [filterUntil, setFilterUntil] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterTargetKind, setFilterTargetKind] = useState("");
  const [filterActor, setFilterActor] = useState("");
  const [applied, setApplied] = useState<AuditListFilter | undefined>(undefined);
  // The SESSION reports (sessions/technicians) have their OWN since/until window, kept separate from the
  // audit filter above so switching report types never carries a stale date across.
  const [sessionSince, setSessionSince] = useState("");
  const [sessionUntil, setSessionUntil] = useState("");
  const [sessionApplied, setSessionApplied] = useState<SessionReportFilter | undefined>(undefined);
  // Print/PDF export: the timestamp is set FIRST so the print-only header renders it, then the
  // effect calls window.print() (the browser's own PDF path — no PDF dependency).
  const [printedAt, setPrintedAt] = useState<string | null>(null);
  useEffect(() => {
    if (printedAt !== null) window.print();
  }, [printedAt]);

  // The query the panel is CURRENTLY showing: the report type plus the filter that type uses.
  const currentApplied: ReportApplied = reportType === "actions" ? applied : sessionApplied;

  const refresh = useCallback(async () => {
    const id = ++requestSeq.current;
    setBusy(true);
    setError(null);
    try {
      let result: LoadedReport;
      if (reportType === "sessions") {
        result = { reportType, applied: sessionApplied, rows: await api.sessionsByMachine(sessionApplied) };
      } else if (reportType === "technicians") {
        result = { reportType, applied: sessionApplied, rows: await api.sessionsByTechnician(sessionApplied) };
      } else {
        result = { reportType, applied, rows: await api.auditSummary(applied) };
      }
      if (id !== requestSeq.current) return; // superseded by a newer request
      setLoaded(result);
      setListingStale(false);
    } catch (e) {
      if (id !== requestSeq.current) return;
      setListingStale(true);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (id === requestSeq.current) setBusy(false);
    }
  }, [api, applied, reportType, sessionApplied]);

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

  // Only rows fetched for exactly the current report type + filter are displayed, charted, totalled or exported.
  const rows = useMemo(
    () => reportRowsForQuery(loaded, { reportType: "actions", applied: currentApplied }),
    [loaded, currentApplied],
  );
  const sessionRows = useMemo(
    () => reportRowsForQuery(loaded, { reportType: "sessions", applied: currentApplied }),
    [loaded, currentApplied],
  );
  const technicianRows = useMemo(
    () => reportRowsForQuery(loaded, { reportType: "technicians", applied: currentApplied }),
    [loaded, currentApplied],
  );

  // Load the tenant's users once so technician ids resolve to emails (best-effort — a failure just shows
  // the raw id, and a caller who can view sessions but not users still gets a usable report).
  useEffect(() => {
    void api.listUsers().then(setUsers).catch(() => {});
  }, [api]);

  // The technician rows with their id resolved to a display label — the single source both the table and
  // the CSV export render from, so they never diverge.
  const labeledTechRows = useMemo(
    () =>
      technicianRows.map((r) => ({
        technician_id: r.technician_id,
        technician: technicianLabel(users, r.technician_id),
        count: r.count,
        total_seconds: r.total_seconds,
      })),
    [technicianRows, users],
  );

  const total = useMemo(
    () =>
      reportType === "sessions"
        ? sessionRows.reduce((sum, r) => sum + r.count, 0)
        : reportType === "technicians"
          ? technicianRows.reduce((sum, r) => sum + r.count, 0)
          : rows.reduce((sum, r) => sum + r.count, 0),
    [reportType, rows, sessionRows, technicianRows],
  );

  // The CURRENT report's rows as {key, label, value} — the single source the bar chart draws from. Keyed on
  // the stable UNIQUE id (machine_id / technician_id / action) the table uses, NOT the display label, so
  // same-named rows do not collide in the chart's React keys / data-testids (reportChartRows enforces this).
  const bars = useMemo(
    () => barChart(reportChartRows(reportType, rows, sessionRows, labeledTechRows)),
    [reportType, rows, sessionRows, labeledTechRows],
  );

  const handleFilter = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      // datetime-local read as UTC (the panel labels UTC), matching the Audit tab. Every field is
      // optional; only non-empty ones enter the filter, and an all-empty form clears it (undefined).
      const f: AuditListFilter = {};
      const action = filterAction.trim();
      const targetKind = filterTargetKind.trim();
      const actor = filterActor.trim();
      const since = datetimeLocalToUtcRfc3339(filterSince);
      const until = datetimeLocalToUtcRfc3339(filterUntil);
      if (action !== "") f.action = action;
      if (targetKind !== "") f.targetKind = targetKind;
      if (actor !== "") f.actor = actor;
      if (since !== "") f.since = since;
      if (until !== "") f.until = until;
      setApplied(Object.keys(f).length > 0 ? f : undefined);
    },
    [filterAction, filterTargetKind, filterActor, filterSince, filterUntil],
  );

  const handleClear = useCallback(() => {
    setFilterSince("");
    setFilterUntil("");
    setFilterAction("");
    setFilterTargetKind("");
    setFilterActor("");
    setApplied(undefined);
  }, []);

  const handleSessionFilter = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      // datetime-local read as UTC (matching the audit filter); only non-empty bounds enter the window,
      // and an all-empty form clears it (undefined = all-time).
      const since = datetimeLocalToUtcRfc3339(sessionSince);
      const until = datetimeLocalToUtcRfc3339(sessionUntil);
      const f: SessionReportFilter = {};
      if (since !== "") f.since = since;
      if (until !== "") f.until = until;
      setSessionApplied(Object.keys(f).length > 0 ? f : undefined);
    },
    [sessionSince, sessionUntil],
  );

  const handleSessionClear = useCallback(() => {
    setSessionSince("");
    setSessionUntil("");
    setSessionApplied(undefined);
  }, []);

  const handleExport = useCallback(() => {
    // Never export a listing whose latest refresh failed: it may be out of date.
    if (listingStale) return;
    // Export the report CURRENTLY shown as a CSV file the browser saves.
    const [name, csv] =
      reportType === "sessions"
        ? ["sessions-by-machine.csv", machineSessionsToCsv(sessionRows)]
        : reportType === "technicians"
          ? ["sessions-by-technician.csv", technicianSessionsToCsv(labeledTechRows)]
          : ["audit-report.csv", auditSummaryToCsv(rows)];
    saveBytesAsFile(name, new TextEncoder().encode(csv));
  }, [listingStale, reportType, rows, sessionRows, labeledTechRows]);

  const rowCount =
    reportType === "sessions"
      ? sessionRows.length
      : reportType === "technicians"
        ? technicianRows.length
        : rows.length;
  // Rows are kept across a failed refresh of the SAME query, but labelled; they are not exportable then.
  const staleRows = listingStale && rowCount > 0;
  const emptyText = (fallback: string) =>
    busy ? "Loading…" : error !== null ? "The report could not be loaded for the current filter." : fallback;

  return (
    <section className="panel panel--reports" data-testid="reports">
      <div className="report-print-header" data-testid="report-print-header">
        <strong>{document.title}</strong>
        <div>{reportPrintSubtitle(reportType, currentApplied, rowCount, total)}</div>
        {printedAt !== null && <div>Generated {printedAt}</div>}
      </div>
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">
          {reportType === "sessions"
            ? "Reports — sessions by machine"
            : reportType === "technicians"
              ? "Reports — sessions by technician"
              : "Reports — events by action"}
        </span>
        <label className="panel__toolbar-field">
          Report
          <select
            value={reportType}
            onChange={(e) => {
              // Mark busy synchronously so the switch renders "Loading…" — without this the empty cell
              // would flash the wrong report's empty text ("No sessions recorded.") for one paint before
              // the effect-driven refresh sets busy. The effect below re-fetches for the new type.
              setBusy(true);
              setReportType(e.target.value as ReportType);
            }}
            data-testid="report-type"
          >
            <option value="actions">Events by action</option>
            <option value="sessions">Sessions by machine</option>
            <option value="technicians">Sessions by technician</option>
          </select>
        </label>
        <button className="panel__action" onClick={() => void refresh()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={busy || rowCount === 0 || listingStale}
          data-testid="report-export"
        >
          Export CSV
        </button>
        <button
          className="panel__action"
          onClick={() => setPrintedAt(new Date().toLocaleString())}
          disabled={busy || rowCount === 0 || listingStale}
          data-testid="report-print"
          title="Opens the browser's print dialog; choose 'Save as PDF' there."
        >
          Print / PDF
        </button>
        <button
          className="panel__action"
          onClick={() => setShowChart((v) => !v)}
          disabled={rowCount === 0}
          aria-pressed={showChart}
          data-testid="report-chart-toggle"
        >
          {showChart ? "Hide chart" : "Show chart"}
        </button>
        <span className="panel__toolbar-title" data-testid="report-total">
          {`Total: ${total}`}
        </span>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="report-error">
            {error}
          </span>
        )}
        {staleRows && (
          <span className="panel__toolbar-error" data-testid="report-stale">
            Refresh failed — these rows are from the last successful load and may be out of date.
          </span>
        )}
      </div>
      {reportType === "actions" && (
      <form className="panel__form" onSubmit={handleFilter}>
        <span className="panel__toolbar-title">Filter</span>
        <label className="panel__toolbar-field">
          Action
          <input
            type="text"
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            placeholder="e.g. session.start"
            data-testid="report-action"
          />
        </label>
        <label className="panel__toolbar-field">
          Target kind
          <input
            type="text"
            value={filterTargetKind}
            onChange={(e) => setFilterTargetKind(e.target.value)}
            placeholder="e.g. machine"
            data-testid="report-target-kind"
          />
        </label>
        <label className="panel__toolbar-field">
          Actor (user/token id)
          <input
            type="text"
            value={filterActor}
            onChange={(e) => setFilterActor(e.target.value)}
            placeholder="user or token id"
            data-testid="report-actor"
          />
        </label>
        <label className="panel__toolbar-field">
          Since (UTC)
          <input
            type="datetime-local"
            value={filterSince}
            onChange={(e) => setFilterSince(e.target.value)}
            data-testid="report-since"
          />
        </label>
        <label className="panel__toolbar-field">
          Until (UTC)
          <input
            type="datetime-local"
            value={filterUntil}
            onChange={(e) => setFilterUntil(e.target.value)}
            data-testid="report-until"
          />
        </label>
        <button className="panel__action" type="submit" disabled={busy} data-testid="report-apply">
          Apply
        </button>
        {applied && (
          <button className="panel__action" type="button" onClick={handleClear} data-testid="report-clear">
            Clear
          </button>
        )}
      </form>
      )}
      {(reportType === "sessions" || reportType === "technicians") && (
        <form className="panel__form" onSubmit={handleSessionFilter}>
          <span className="panel__toolbar-title">Filter by date</span>
          <label className="panel__toolbar-field">
            Since (UTC)
            <input
              type="datetime-local"
              value={sessionSince}
              onChange={(e) => setSessionSince(e.target.value)}
              data-testid="session-report-since"
            />
          </label>
          <label className="panel__toolbar-field">
            Until (UTC)
            <input
              type="datetime-local"
              value={sessionUntil}
              onChange={(e) => setSessionUntil(e.target.value)}
              data-testid="session-report-until"
            />
          </label>
          <button className="panel__action" type="submit" disabled={busy} data-testid="session-report-apply">
            Apply
          </button>
          {sessionApplied && (
            <button
              className="panel__action"
              type="button"
              onClick={handleSessionClear}
              data-testid="session-report-clear"
            >
              Clear
            </button>
          )}
        </form>
      )}
      {showChart && bars.length > 0 && (
        <div className="panel__chart" style={{ overflowX: "auto", padding: "8px 0" }}>
          <ReportBarChart bars={bars} />
        </div>
      )}
      {reportType === "sessions" ? (
        <table className="panel__table">
          <thead>
            <tr>
              <th>Machine</th>
              <th>Sessions</th>
              <th>Total time</th>
            </tr>
          </thead>
          <tbody>
            {sessionRows.length === 0 && (
              <tr>
                <td className="panel__empty" colSpan={3} data-testid="reports-empty">
                  {emptyText("No sessions recorded.")}
                </td>
              </tr>
            )}
            {sessionRows.map((r) => (
              <tr key={r.machine_id} data-testid={`session-report-row-${r.machine_id}`}>
                <td className="panel__name">{r.machine_name}</td>
                <td className="panel__mono" data-testid={`session-report-count-${r.machine_id}`}>
                  {r.count}
                </td>
                <td className="panel__mono" data-testid={`session-report-time-${r.machine_id}`}>
                  {formatDurationSeconds(r.total_seconds)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : reportType === "technicians" ? (
        <table className="panel__table">
          <thead>
            <tr>
              <th>Technician</th>
              <th>Sessions</th>
              <th>Total time</th>
            </tr>
          </thead>
          <tbody>
            {labeledTechRows.length === 0 && (
              <tr>
                <td className="panel__empty" colSpan={3} data-testid="reports-empty">
                  {emptyText("No sessions recorded.")}
                </td>
              </tr>
            )}
            {labeledTechRows.map((r) => (
              <tr key={r.technician_id} data-testid={`tech-report-row-${r.technician_id}`}>
                <td className="panel__name" data-testid={`tech-report-label-${r.technician_id}`}>
                  {r.technician}
                </td>
                <td className="panel__mono" data-testid={`tech-report-count-${r.technician_id}`}>
                  {r.count}
                </td>
                <td className="panel__mono" data-testid={`tech-report-time-${r.technician_id}`}>
                  {formatDurationSeconds(r.total_seconds)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <table className="panel__table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td className="panel__empty" colSpan={2} data-testid="reports-empty">
                  {emptyText(applied ? "No events in this window." : "No audit events.")}
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.action} data-testid={`report-row-${r.action}`}>
                <td className="panel__name">{r.action}</td>
                <td className="panel__mono" data-testid={`report-count-${r.action}`}>
                  {r.count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
