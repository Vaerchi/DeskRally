/**
 * ReportsPanel response-association tests: rows may be shown, charted, totalled and exported only for the exact
 * report type + applied filter that produced them (the overlap behaviour itself is covered by
 * e2e/supervisor_reports_filter_integrity).
 */

import { describe, it, expect } from "vitest";
import { reportPrintSubtitle, reportRowsForQuery, type LoadedReport } from "./ReportsPanel";
import type { AuditActionCount, AuditListFilter, MachineSessionCount, SessionReportFilter } from "../lib/console_api";

const ACTIONS = [{ action: "session.start", count: 3 }] as unknown as readonly AuditActionCount[];
const MACHINES = [{ machine_id: "m-1", machine_name: "alpha", count: 2 }] as unknown as readonly MachineSessionCount[];
const AUDIT_FILTER: AuditListFilter = { action: "session.start" };
const WINDOW: SessionReportFilter = { since: "2026-08-01T00:00:00Z" };

describe("reportRowsForQuery", () => {
  it("returns nothing before any successful load", () => {
    expect(reportRowsForQuery(null, { reportType: "actions", applied: undefined })).toEqual([]);
    expect(reportRowsForQuery(null, { reportType: "sessions", applied: WINDOW })).toEqual([]);
  });

  it("returns the rows for the report type and filter that produced them", () => {
    const audit: LoadedReport = { rows: ACTIONS, reportType: "actions", applied: AUDIT_FILTER };
    expect(reportRowsForQuery(audit, { reportType: "actions", applied: AUDIT_FILTER })).toBe(ACTIONS);
    const unfiltered: LoadedReport = { rows: MACHINES, reportType: "sessions", applied: undefined };
    expect(reportRowsForQuery(unfiltered, { reportType: "sessions", applied: undefined })).toBe(MACHINES);
  });

  it("never returns rows fetched under a different filter", () => {
    const audit: LoadedReport = { rows: ACTIONS, reportType: "actions", applied: AUDIT_FILTER };
    expect(reportRowsForQuery(audit, { reportType: "actions", applied: undefined })).toEqual([]);
    expect(reportRowsForQuery(audit, { reportType: "actions", applied: { ...AUDIT_FILTER } })).toEqual([]);
    expect(reportRowsForQuery(audit, { reportType: "actions", applied: { action: "other" } })).toEqual([]);
    const windowed: LoadedReport = { rows: MACHINES, reportType: "sessions", applied: WINDOW };
    expect(reportRowsForQuery(windowed, { reportType: "sessions", applied: undefined })).toEqual([]);
    expect(reportRowsForQuery(windowed, { reportType: "sessions", applied: { until: "2026-08-31T23:59:59Z" } })).toEqual([]);
  });

  it("never returns rows fetched for a different report type, even with the same filter", () => {
    const sessions: LoadedReport = { rows: MACHINES, reportType: "sessions", applied: WINDOW };
    expect(reportRowsForQuery(sessions, { reportType: "technicians", applied: WINDOW })).toEqual([]);
    expect(reportRowsForQuery(sessions, { reportType: "actions", applied: WINDOW })).toEqual([]);
    const audit: LoadedReport = { rows: ACTIONS, reportType: "actions", applied: undefined };
    expect(reportRowsForQuery(audit, { reportType: "sessions", applied: undefined })).toEqual([]);
  });
});

describe("reportPrintSubtitle", () => {
  it("names the report, every applied filter, and the totals", () => {
    expect(
      reportPrintSubtitle("actions", { action: "machine.enroll", actor: "u1", since: "2026-10-01T00:00:00Z" }, 4, 17),
    ).toBe("Events by action — action=machine.enroll, actor=u1, since 2026-10-01T00:00:00Z — 4 rows, total 17");
  });
  it("says 'no filter' rather than implying an unfiltered report was filtered", () => {
    expect(reportPrintSubtitle("sessions", undefined, 2, 9)).toBe("Sessions by machine — no filter — 2 rows, total 9");
    expect(reportPrintSubtitle("sessions", {}, 2, 9)).toBe("Sessions by machine — no filter — 2 rows, total 9");
  });
  it("covers the session window bounds", () => {
    expect(reportPrintSubtitle("technicians", { since: "A", until: "B" }, 1, 1)).toBe(
      "Sessions by technician — since A, until B — 1 rows, total 1",
    );
  });
});
