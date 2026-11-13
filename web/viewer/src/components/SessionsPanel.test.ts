/**
 * SessionsPanel response-association tests: rows may be shown/exported only for the exact applied filter that
 * produced them (the overlap behaviour itself is covered by e2e/supervisor_sessions_filter_integrity).
 */

import { describe, it, expect } from "vitest";
import { sessionRowsForQuery, type LoadedSessions } from "./SessionsPanel";
import type { SessionRecord, SessionReportFilter } from "../lib/console_api";

const ROWS = [{ id: "s-1", machine_name: "alpha" }] as unknown as readonly SessionRecord[];
const FILTER: SessionReportFilter = { since: "2026-08-01T00:00:00Z" };

describe("sessionRowsForQuery", () => {
  it("returns nothing before any successful load", () => {
    expect(sessionRowsForQuery(null, undefined)).toEqual([]);
    expect(sessionRowsForQuery(null, FILTER)).toEqual([]);
  });

  it("returns the rows for the filter that produced them", () => {
    const loaded: LoadedSessions = { rows: ROWS, applied: FILTER };
    expect(sessionRowsForQuery(loaded, FILTER)).toBe(ROWS);
    const unfiltered: LoadedSessions = { rows: ROWS, applied: undefined };
    expect(sessionRowsForQuery(unfiltered, undefined)).toBe(ROWS);
  });

  it("never returns rows fetched under a different filter", () => {
    const loaded: LoadedSessions = { rows: ROWS, applied: FILTER };
    expect(sessionRowsForQuery(loaded, undefined)).toEqual([]);
    expect(sessionRowsForQuery(loaded, { ...FILTER })).toEqual([]);
    expect(sessionRowsForQuery(loaded, { until: "2026-08-31T23:59:59Z" })).toEqual([]);
    const unfiltered: LoadedSessions = { rows: ROWS, applied: undefined };
    expect(sessionRowsForQuery(unfiltered, FILTER)).toEqual([]);
  });
});
