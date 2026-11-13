/**
 * F17 regression tests — CSV formula-injection hardening.
 *
 * Policy under test: untrusted TEXT fields (machine names, aliases, OS, group names, technician
 * labels, audit action/actor/target/metadata) are prefixed with the visible literal "[text] "
 * when the cell value begins with a formula-trigger pattern:
 *   - ASCII operators = + - @ or their fullwidth equivalents ＝ ＋ － ＠, possibly after leading
 *     whitespace / BOM / C0 control characters.
 *   - A bare leading tab, CR, LF, BOM, or other C0/DEL control character even with no subsequent
 *     operator.
 * Empty strings are not altered. Number-typed fields (count, total_seconds) bypass hardening.
 * The prefix is prepended BEFORE the entire original string; original bytes are preserved after it.
 * After prefixing, RFC 4180 quoting is applied normally.
 *
 * These tests MUST FAIL if:
 *   - Neutralization is removed (formula char reaches cell start unmodified).
 *   - RFC 4180 quoting is removed from prefixed values (delimiter in original leaks cell boundary).
 *   - Numeric fields are accidentally prefixed (breaks spreadsheet SUM/pivot).
 *   - Empty strings are altered.
 *   - The prefix is applied invisibly (apostrophe/tab escape instead of "[text] ").
 */

import { describe, it, expect } from "vitest";
import {
  auditEventsToCsv,
  auditSummaryToCsv,
  machineSessionsToCsv,
  machinesToCsv,
  technicianSessionsToCsv,
} from "./report_csv";
import type { MachineRecord, MgmtAuditEvent } from "./console_api";

// ---------------------------------------------------------------------------
// Minimal RFC 4180 parser — used to assert cell boundaries independently of
// the serializer's own quoting logic. Handles embedded newlines in quoted
// fields and doubled-quote escaping.
// ---------------------------------------------------------------------------
function parseRfc4180(csv: string): string[][] {
  const rows: string[][] = [];
  let i = 0;
  const n = csv.length;

  while (i < n) {
    const row: string[] = [];

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (i >= n) {
        row.push("");
        break;
      }

      if (csv[i] === '"') {
        // Quoted field
        let field = "";
        i++; // skip opening quote
        while (i < n) {
          if (csv[i] === '"') {
            if (i + 1 < n && csv[i + 1] === '"') {
              field += '"';
              i += 2;
            } else {
              i++; // skip closing quote
              break;
            }
          } else {
            field += csv[i++];
          }
        }
        row.push(field);
        if (i < n && csv[i] === ",") {
          i++;
        } else if (i < n && csv[i] === "\r" && i + 1 < n && csv[i + 1] === "\n") {
          i += 2;
          break;
        } else {
          break;
        }
      } else {
        // Unquoted field — reads until comma, CRLF, or end
        let field = "";
        while (i < n && csv[i] !== "," && !(csv[i] === "\r" && i + 1 < n && csv[i + 1] === "\n")) {
          field += csv[i++];
        }
        row.push(field);
        if (i < n && csv[i] === ",") {
          i++;
        } else if (i < n && csv[i] === "\r" && i + 1 < n && csv[i + 1] === "\n") {
          i += 2;
          break;
        } else {
          break;
        }
      }
    }

    rows.push(row);
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const machineRow = (over: Partial<MachineRecord> = {}): MachineRecord => ({
  id: "pk-1",
  tenant_id: "t-1",
  device_id: "dev-1",
  group_id: "g-1",
  name: "HOST-1",
  ...over,
});

const machineSessionRow = (machine_name: string, count = 1, total_seconds = 0) => ({
  machine_id: "m-1",
  machine_name,
  machine_group_id: "g-1",
  count,
  total_seconds,
});

const auditEvent = (over: Partial<MgmtAuditEvent> = {}): MgmtAuditEvent => ({
  id: "e-1",
  tenant_id: "t-1",
  action: "machine.enroll",
  occurred_at: "2026-09-14T00:00:00Z",
  ...over,
});

// ---------------------------------------------------------------------------
// auditSummaryToCsv — action column is untrusted; count is numeric
// ---------------------------------------------------------------------------
describe("auditSummaryToCsv formula-injection hardening", () => {
  it("prefixes a leading = in action", () => {
    const csv = auditSummaryToCsv([{ action: "=MALICIOUS()", count: 5 }]);
    const rows = parseRfc4180(csv);
    expect(rows[1][0]).toBe("[text] =MALICIOUS()");
    expect(rows[1][1]).toBe("5");
  });

  it("prefixes a leading + in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "+cmd", count: 1 }]));
    expect(rows[1][0]).toBe("[text] +cmd");
  });

  it("prefixes a leading - in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "-1+1", count: 1 }]));
    expect(rows[1][0]).toBe("[text] -1+1");
  });

  it("prefixes a leading @ in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "@SUM(A1)", count: 1 }]));
    expect(rows[1][0]).toBe("[text] @SUM(A1)");
  });

  it("prefixes fullwidth ＝ in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "＝EVIL", count: 1 }]));
    expect(rows[1][0]).toBe("[text] ＝EVIL");
  });

  it("prefixes fullwidth ＋ in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "＋EVIL", count: 1 }]));
    expect(rows[1][0]).toBe("[text] ＋EVIL");
  });

  it("prefixes fullwidth － in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "－EVIL", count: 1 }]));
    expect(rows[1][0]).toBe("[text] －EVIL");
  });

  it("prefixes fullwidth ＠ in action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "＠EVIL", count: 1 }]));
    expect(rows[1][0]).toBe("[text] ＠EVIL");
  });

  it("prefixes = after leading space", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: " =cmd", count: 1 }]));
    expect(rows[1][0]).toBe("[text]  =cmd");
  });

  it("prefixes = after tab (bare tab also risky)", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\t=cmd", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \t=cmd");
  });

  it("prefixes = after BOM", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\uFEFF=cmd", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \uFEFF=cmd");
  });

  it("prefixes a bare leading tab with no operator", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\thello", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \thello");
  });

  it("prefixes a bare leading CR", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\rfoo", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \rfoo");
  });

  it("prefixes a bare leading LF", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\nfoo", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \nfoo");
  });

  it("prefixes a bare BOM with no operator", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\uFEFFnormal", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \uFEFFnormal");
  });

  it("prefixes a bare C0 control (0x01) with no operator", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "\x01payload", count: 1 }]));
    expect(rows[1][0]).toBe("[text] \x01payload");
  });

  it("does not prefix an ordinary dotted action", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "machine.enroll", count: 9 }]));
    expect(rows[1][0]).toBe("machine.enroll");
  });

  it("does not prefix an empty action (empty cell unchanged)", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "", count: 0 }]));
    expect(rows[1][0]).toBe("");
  });

  it("does not prefix internal = (only leading position is risky)", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "ok=inner", count: 1 }]));
    expect(rows[1][0]).toBe("ok=inner");
  });

  it("does not prefix an @ that is not leading (email-like action label)", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "user@example.com", count: 1 }]));
    expect(rows[1][0]).toBe("user@example.com");
  });

  it("does not prefix a - that is not leading", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "foo-bar", count: 1 }]));
    expect(rows[1][0]).toBe("foo-bar");
  });

  // Numeric column must never be prefixed
  it("count: negative number is NOT prefixed (numeric field)", () => {
    const csv = auditSummaryToCsv([{ action: "ok", count: -5 }]);
    const rows = parseRfc4180(csv);
    expect(rows[1][1]).toBe("-5");
    expect(rows[1][1]).not.toContain("[text]");
  });

  it("count: zero is NOT prefixed", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "ok", count: 0 }]));
    expect(rows[1][1]).toBe("0");
  });

  // Risky value that ALSO contains a comma — must be RFC4180-quoted AND prefixed
  it("RFC4180 quotes a prefixed action that contains a comma", () => {
    const csv = auditSummaryToCsv([{ action: "=HYPERLINK(A1,B1)", count: 1 }]);
    expect(csv).toContain('"[text] =HYPERLINK(A1,B1)"');
    const rows = parseRfc4180(csv);
    // After parsing, must be exactly two data cells (action, count) — not three
    expect(rows[1]).toHaveLength(2);
    expect(rows[1][0]).toBe("[text] =HYPERLINK(A1,B1)");
  });

  it("RFC4180 quotes a prefixed action that contains a double quote", () => {
    // action: ="evil"  → prefix → [text] ="evil"  → RFC4180 → "[text] =""evil"""
    const csv = auditSummaryToCsv([{ action: '="evil"', count: 1 }]);
    expect(csv).toContain('"[text] =""evil"""');
    const rows = parseRfc4180(csv);
    expect(rows[1][0]).toBe('[text] ="evil"');
  });

  it("raw: RFC4180 correctly doubles quotes inside prefixed value", () => {
    // =a"b  → prefix → [text] =a"b  → RFC4180 → "[text] =a""b"
    const csv = auditSummaryToCsv([{ action: '=a"b', count: 1 }]);
    expect(csv).toContain('"[text] =a""b"');
    const rows = parseRfc4180(csv);
    expect(rows[1][0]).toBe('[text] =a"b');
  });

  it("preserves original bytes after the prefix (no destructive trim)", () => {
    const original = "=  leading spaces inside";
    const rows = parseRfc4180(auditSummaryToCsv([{ action: original, count: 1 }]));
    expect(rows[1][0]).toBe(`[text] ${original}`);
  });
});

// ---------------------------------------------------------------------------
// machineSessionsToCsv — machine_name is untrusted; count and total_seconds numeric
// ---------------------------------------------------------------------------
describe("machineSessionsToCsv formula-injection hardening", () => {
  it("prefixes = in machine_name", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("=EVIL()")]));
    expect(rows[1][0]).toBe("[text] =EVIL()");
  });

  it("prefixes @ in machine_name", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("@SUM(A:A)")]));
    expect(rows[1][0]).toBe("[text] @SUM(A:A)");
  });

  it("prefixes + in machine_name", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("+cmd")]));
    expect(rows[1][0]).toBe("[text] +cmd");
  });

  it("prefixes - in machine_name", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("-bad")]));
    expect(rows[1][0]).toBe("[text] -bad");
  });

  it("prefixes BOM-prefixed machine name", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("\uFEFF=cmd")]));
    expect(rows[1][0]).toBe("[text] \uFEFF=cmd");
  });

  it("does not prefix a normal hostname", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("WORKSTATION-42")]));
    expect(rows[1][0]).toBe("WORKSTATION-42");
  });

  it("count: negative NOT prefixed", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", -3)]));
    expect(rows[1][1]).toBe("-3");
    expect(rows[1][1]).not.toContain("[text]");
  });

  it("total_seconds: negative NOT prefixed", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", 1, -99)]));
    expect(rows[1][2]).toBe("-99");
    expect(rows[1][2]).not.toContain("[text]");
  });

  it("total_seconds: large positive NOT prefixed", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", 1, 999999)]));
    expect(rows[1][2]).toBe("999999");
  });

  it("row has exactly 3 cells even when machine name contains a malicious comma", () => {
    const csv = machineSessionsToCsv([machineSessionRow("=HYPERLINK(\"http://x\",\"y\")", 2, 10)]);
    const rows = parseRfc4180(csv);
    expect(rows[1]).toHaveLength(3);
    expect(rows[1][1]).toBe("2");
    expect(rows[1][2]).toBe("10");
  });

  it("Unicode machine name is not prefixed", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("サーバー-01")]));
    expect(rows[1][0]).toBe("サーバー-01");
  });
});

// ---------------------------------------------------------------------------
// machinesToCsv — every string column shares the text policy, including identifiers and timestamps.
// ---------------------------------------------------------------------------
describe("machinesToCsv formula-injection hardening", () => {
  it("prefixes = in machine name", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "=MALICIOUS()" })]));
    expect(rows[1][0]).toBe("[text] =MALICIOUS()");
  });

  it("prefixes + in alias", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ alias: "+evil" })]));
    expect(rows[1][1]).toBe("[text] +evil");
  });

  it("prefixes - in os string", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ os: "-=BAD" })]));
    expect(rows[1][5]).toBe("[text] -=BAD");
  });

  it("prefixes @ in group_name", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ group_name: "@GROUP" })]));
    expect(rows[1][3]).toBe("[text] @GROUP");
  });

  it("prefixes = in status (arbitrary string from old server)", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ status: "=active" })]));
    expect(rows[1][4]).toBe("[text] =active");
  });

  it("prefixes fullwidth ＝ in name", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "＝evil" })]));
    expect(rows[1][0]).toBe("[text] ＝evil");
  });

  it("prefixes BOM-prefixed alias", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ alias: "\uFEFF=x" })]));
    expect(rows[1][1]).toBe("[text] \uFEFF=x");
  });

  it("prefixes tab-only name", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "\t" })]));
    expect(rows[1][0]).toBe("[text] \t");
  });

  it("empty alias is not altered", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ alias: "" })]));
    expect(rows[1][1]).toBe("");
  });

  it("device_id (UUID) is NOT prefixed even if it began with a letter followed by hex digits", () => {
    // UUIDs never start with = + - @ but verify the field is untouched
    const rows = parseRfc4180(machinesToCsv([machineRow({ device_id: "abc-123" })]));
    expect(rows[1][2]).toBe("abc-123");
  });

  it("id (UUID) is NOT prefixed", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ id: "pk-99" })]));
    expect(rows[1][8]).toBe("pk-99");
  });

  it("last_seen timestamp is NOT prefixed (system timestamp, not user-controlled)", () => {
    const ts = "2026-09-14T12:00:00Z";
    const rows = parseRfc4180(machinesToCsv([machineRow({ last_seen: ts })]));
    expect(rows[1][7]).toBe(ts);
  });

  it("online literal 'online' is NOT prefixed", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ online: true })]));
    expect(rows[1][6]).toBe("online");
  });

  it("row always has 9 columns even when name contains malicious comma payload", () => {
    const csv = machinesToCsv([machineRow({ name: "=HYPERLINK(A1,B1)" })]);
    const rows = parseRfc4180(csv);
    expect(rows[1]).toHaveLength(9);
  });

  it("normal ASCII hostname unchanged", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "DESKTOP-ABC123" })]));
    expect(rows[1][0]).toBe("DESKTOP-ABC123");
  });

  it("Unicode machine name unchanged", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "サーバー" })]));
    expect(rows[1][0]).toBe("サーバー");
  });
});

// ---------------------------------------------------------------------------
// technicianSessionsToCsv — technician is untrusted; count/total_seconds numeric
// ---------------------------------------------------------------------------
describe("technicianSessionsToCsv formula-injection hardening", () => {
  const row = (technician: string, count = 1, total_seconds = 0) => ({ technician, count, total_seconds });

  it("prefixes = in technician label", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("=EVIL")]));
    expect(rows[1][0]).toBe("[text] =EVIL");
  });

  it("prefixes @ in technician label (leading @ is a formula trigger)", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("@domain.com")]));
    expect(rows[1][0]).toBe("[text] @domain.com");
  });

  it("prefixes - in technician label", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("-admin")]));
    expect(rows[1][0]).toBe("[text] -admin");
  });

  it("does not prefix email address (@ is not leading)", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("alice@example.com")]));
    expect(rows[1][0]).toBe("alice@example.com");
  });

  it("does not prefix normal display label", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("Alice Smith")]));
    expect(rows[1][0]).toBe("Alice Smith");
  });

  it("count: negative NOT prefixed", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("ok", -1)]));
    expect(rows[1][1]).toBe("-1");
    expect(rows[1][1]).not.toContain("[text]");
  });

  it("total_seconds: zero NOT prefixed", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([row("ok", 0, 0)]));
    expect(rows[1][2]).toBe("0");
  });

  it("row has exactly 3 columns when technician carries a comma injection", () => {
    const csv = technicianSessionsToCsv([row("=HYPERLINK(\"x\",\"click\")", 5, 120)]);
    const rows = parseRfc4180(csv);
    expect(rows[1]).toHaveLength(3);
    expect(rows[1][1]).toBe("5");
    expect(rows[1][2]).toBe("120");
  });
});

// ---------------------------------------------------------------------------
// auditEventsToCsv — action, actor_user_id, target_kind, target_id, metadata are
// untrusted text; occurred_at is a system timestamp (not hardened)
// ---------------------------------------------------------------------------
describe("auditEventsToCsv formula-injection hardening", () => {
  it("prefixes = in action", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ action: "=EVAL(A1)" })]));
    expect(rows[1][1]).toBe("[text] =EVAL(A1)");
  });

  it("prefixes + in actor_user_id", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ actor_user_id: "+malicious" })]));
    expect(rows[1][2]).toBe("[text] +malicious");
  });

  it("prefixes - in target_kind", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ target_kind: "-injection" })]));
    expect(rows[1][3]).toBe("[text] -injection");
  });

  it("prefixes @ in target_id", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ target_id: "@evil" })]));
    expect(rows[1][4]).toBe("[text] @evil");
  });

  it("prefixes fullwidth ＝ in action", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ action: "＝danger" })]));
    expect(rows[1][1]).toBe("[text] ＝danger");
  });

  it("prefixes space+= in actor_user_id", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ actor_user_id: " =cmd" })]));
    expect(rows[1][2]).toBe("[text]  =cmd");
  });

  it("occurred_at timestamp is NOT prefixed (system-generated, starts with digit)", () => {
    const ts = "2026-09-14T00:00:00Z";
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ occurred_at: ts })]));
    expect(rows[1][0]).toBe(ts);
    expect(rows[1][0]).not.toContain("[text]");
  });

  it("empty actor_user_id is not altered", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent()]));
    expect(rows[1][2]).toBe("");
  });

  it("metadata JSON (starts with '{') is not prefixed", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ metadata: { key: "value" } })]));
    // JSON starts with { which is not a formula trigger
    expect(rows[1][5]).toBe('{"key":"value"}');
    expect(rows[1][5]).not.toContain("[text]");
  });

  it("null metadata is empty cell unchanged", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ metadata: null })]));
    expect(rows[1][5]).toBe("");
  });

  it("row always has 7 columns (source_ip last) even with formula payload in action containing comma", () => {
    const csv = auditEventsToCsv([auditEvent({ action: "=HYPERLINK(A1,B1)", target_id: "x" })]);
    const rows = parseRfc4180(csv);
    expect(rows[0]).toHaveLength(7);
    expect(rows[1]).toHaveLength(7);
  });

  it("a formula payload in source_ip is neutralised like any other cell", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ source_ip: "=cmd|' /C calc'!A0" })]));
    expect(rows[1][6]).not.toMatch(/^[=+\-@]/);
  });

  it("normal dotted action unchanged", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ action: "user.login" })]));
    expect(rows[1][1]).toBe("user.login");
  });

  it("actor UUID unchanged (UUIDs start with hex, never a formula char)", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ actor_user_id: uuid })]));
    expect(rows[1][2]).toBe(uuid);
  });
});

// ---------------------------------------------------------------------------
// Cross-serializer: numeric fields must never be prefixed regardless of value
// ---------------------------------------------------------------------------
describe("numeric field preservation across all serializers", () => {
  it("auditSummaryToCsv: count=0 is bare '0'", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "x", count: 0 }]));
    expect(rows[1][1]).toBe("0");
  });

  it("auditSummaryToCsv: large count is bare numeric string", () => {
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "x", count: 1000000 }]));
    expect(rows[1][1]).toBe("1000000");
  });

  it("machineSessionsToCsv: count=-1 stays '-1'", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", -1)]));
    expect(rows[1][1]).toBe("-1");
  });

  it("machineSessionsToCsv: total_seconds=0 stays '0'", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", 1, 0)]));
    expect(rows[1][2]).toBe("0");
  });

  it("machineSessionsToCsv: total_seconds=-3600 stays '-3600'", () => {
    const rows = parseRfc4180(machineSessionsToCsv([machineSessionRow("ok", 1, -3600)]));
    expect(rows[1][2]).toBe("-3600");
  });

  it("technicianSessionsToCsv: count=-99 stays '-99'", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([{ technician: "ok", count: -99, total_seconds: 0 }]));
    expect(rows[1][1]).toBe("-99");
  });

  it("technicianSessionsToCsv: total_seconds large positive is bare numeric", () => {
    const rows = parseRfc4180(
      technicianSessionsToCsv([{ technician: "ok", count: 1, total_seconds: 86400 }]),
    );
    expect(rows[1][2]).toBe("86400");
  });
});

// ---------------------------------------------------------------------------
// Prefix visibility: must use "[text] " literal, not an invisible apostrophe or tab
// ---------------------------------------------------------------------------
describe("prefix is visible '[text] ' literal", () => {
  it("prefix starts with '[text] ' in auditSummaryToCsv (not an apostrophe or invisible byte)", () => {
    const csv = auditSummaryToCsv([{ action: "=EVIL", count: 1 }]);
    const rows = parseRfc4180(csv);
    expect(rows[1][0].startsWith("[text] ")).toBe(true);
  });

  it("prefix starts with '[text] ' in machinesToCsv name column", () => {
    const rows = parseRfc4180(machinesToCsv([machineRow({ name: "@attacker" })]));
    expect(rows[1][0].startsWith("[text] ")).toBe(true);
  });

  it("prefix starts with '[text] ' in technicianSessionsToCsv", () => {
    const rows = parseRfc4180(technicianSessionsToCsv([{ technician: "+evil", count: 1, total_seconds: 0 }]));
    expect(rows[1][0].startsWith("[text] ")).toBe(true);
  });

  it("prefix starts with '[text] ' in auditEventsToCsv action column", () => {
    const rows = parseRfc4180(auditEventsToCsv([auditEvent({ action: "-dangerous" })]));
    expect(rows[1][1].startsWith("[text] ")).toBe(true);
  });

  it("prefix '[' itself is not a formula trigger (no double-prefix)", () => {
    // A prefixed cell "[text] =EVIL" starts with '[' which is safe
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "=EVIL", count: 1 }]));
    const cell = rows[1][0];
    expect(cell).not.toMatch(/^\[text\] \[text\]/);
    expect(cell).toMatch(/^\[text\] /);
  });
});

// ---------------------------------------------------------------------------
// RFC4180 cell boundary: malicious comma/quote/newline payloads stay in one cell
// ---------------------------------------------------------------------------
describe("RFC4180 cell boundary — malicious delimiter payloads", () => {
  it("machine name with comma injection: still one cell, correct neighbour fields", () => {
    const csv = machineSessionsToCsv([machineSessionRow("=HYPERLINK(\"x\",click)", 3, 60)]);
    const rows = parseRfc4180(csv);
    expect(rows).toHaveLength(2); // header + 1 data row
    expect(rows[1]).toHaveLength(3);
    expect(rows[1][0]).toBe('[text] =HYPERLINK("x",click)');
    expect(rows[1][1]).toBe("3");
    expect(rows[1][2]).toBe("60");
  });

  it("machine name with embedded CRLF: still parsed as one cell", () => {
    const csv = machineSessionsToCsv([machineSessionRow("=evil\r\nnextrow", 1, 0)]);
    const rows = parseRfc4180(csv);
    // Header + 1 data row (embedded CRLF lives inside the quoted field)
    expect(rows).toHaveLength(2);
    expect(rows[1][0]).toBe("[text] =evil\r\nnextrow");
  });

  it("technician with quote injection: double-quote correctly escaped, one cell", () => {
    const csv = technicianSessionsToCsv([
      { technician: '="INJECT""MORE"', count: 1, total_seconds: 0 },
    ]);
    const rows = parseRfc4180(csv);
    expect(rows[1]).toHaveLength(3);
    expect(rows[1][0]).toBe('[text] ="INJECT""MORE"');
  });

  it("audit action with semicolon: semicolon is preserved literally (not a CSV delimiter)", () => {
    // RFC4180 uses comma; semicolon is not special and must NOT alter the cell
    const rows = parseRfc4180(auditSummaryToCsv([{ action: "=a;b;c", count: 1 }]));
    expect(rows[1][0]).toBe("[text] =a;b;c");
  });

  it("alias with embedded newline and leading formula char: contained in one cell", () => {
    const csv = machinesToCsv([machineRow({ alias: "=evil\nmore" })]);
    const rows = parseRfc4180(csv);
    expect(rows[1]).toHaveLength(9);
    expect(rows[1][1]).toBe("[text] =evil\nmore");
  });
});
