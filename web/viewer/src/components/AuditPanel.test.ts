/**
 * AuditPanel response-association tests: rows may be shown/exported only for the exact limit + applied
 * filter that produced them (the overlap behaviour itself is covered by e2e/supervisor_audit_filter_integrity).
 */

import { describe, it, expect } from "vitest";
import { auditRowsForQuery, type LoadedAudit } from "./AuditPanel";
import type { AuditListFilter, MgmtAuditEvent } from "../lib/console_api";

const ROWS = [{ id: "e-1", action: "machine.enroll" }] as unknown as readonly MgmtAuditEvent[];
const FILTER: AuditListFilter = { action: "machine.enroll", targetKind: "", actor: "", since: "", until: "" };

describe("auditRowsForQuery", () => {
  it("returns nothing before any successful load", () => {
    expect(auditRowsForQuery(null, 50, undefined)).toEqual([]);
  });

  it("returns the rows for the query that produced them", () => {
    const loaded: LoadedAudit = { rows: ROWS, limit: 50, applied: FILTER };
    expect(auditRowsForQuery(loaded, 50, FILTER)).toBe(ROWS);
    const unfiltered: LoadedAudit = { rows: ROWS, limit: 50, applied: undefined };
    expect(auditRowsForQuery(unfiltered, 50, undefined)).toBe(ROWS);
  });

  it("never returns rows fetched under a different filter", () => {
    const loaded: LoadedAudit = { rows: ROWS, limit: 50, applied: FILTER };
    expect(auditRowsForQuery(loaded, 50, undefined)).toEqual([]);
    expect(auditRowsForQuery(loaded, 50, { ...FILTER })).toEqual([]);
    const unfiltered: LoadedAudit = { rows: ROWS, limit: 50, applied: undefined };
    expect(auditRowsForQuery(unfiltered, 50, FILTER)).toEqual([]);
  });

  it("never returns rows fetched under a different limit", () => {
    const loaded: LoadedAudit = { rows: ROWS, limit: 50, applied: undefined };
    expect(auditRowsForQuery(loaded, 100, undefined)).toEqual([]);
  });
});
