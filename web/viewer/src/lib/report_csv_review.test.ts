import { describe, expect, it } from "vitest";
import { auditEventsToCsv, auditSummaryToCsv, machinesToCsv, machineSessionsToCsv, technicianSessionsToCsv } from "./report_csv";

describe("independent CSV export boundary checks", () => {
  it.each([" =1+1", "\uFEFF\t=1+1", " \u0000text", "\u007ftext", "\u00a0＠SUM(A1)"])(
    "puts an explicit text marker before the complete original prefix %j", (value) => {
      expect(auditSummaryToCsv([{ action: value, count: 2 }])).toBe(
        `action,count\r\n"[text] ${value}",2\r\n`,
      );
    },
  );

  it("contains formula, quote, delimiter and fake next-row text in one quoted field", () => {
    const value = '=1+1",5\r\n=2+2;"';
    expect(technicianSessionsToCsv([{ technician: value, count: 7, total_seconds: 9 }])).toBe(
      'technician,sessions,total_seconds\r\n"[text] =1+1"",5\r\n=2+2;""",7,9\r\n',
    );
  });

  it("separates textual minus signs from numeric count and duration columns", () => {
    expect(machineSessionsToCsv([{
      machine_id: "m", machine_group_id: "g", machine_name: "-42", count: -2, total_seconds: -3,
    }])).toBe('machine,sessions,total_seconds\r\n"[text] -42",-2,-3\r\n');
    expect(auditSummaryToCsv([{ action: "normal", count: 1e21 }])).toBe("action,count\r\nnormal,1e+21\r\n");
  });

  it("treats JSON scalar metadata as exported text while leaving nested JSON contained", () => {
    const base = { id: "i", tenant_id: "t", occurred_at: "now", action: "event" };
    expect(auditEventsToCsv([{ ...base, metadata: -42 }])).toBe(
      'occurred_at,action,actor,target_kind,target_id,metadata,source_ip\r\nnow,event,,,,"[text] -42",\r\n',
    );
    expect(auditEventsToCsv([{ ...base, metadata: { note: "=1+1" } }])).toBe(
      'occurred_at,action,actor,target_kind,target_id,metadata,source_ip\r\nnow,event,,,,"{""note"":""=1+1""}",\r\n',
    );
  });

  it("applies the same text contract to every string column rather than trusting identifier names", () => {
    const label = "=label";
    expect(machinesToCsv([{
      id: label, tenant_id: "unused", group_id: "unused", device_id: label, name: label,
      alias: label, group_name: label, status: label, os: label, last_seen: label, online: true,
    }])).toBe(
      'name,alias,device_id,group,status,os,online,last_seen,id\r\n' +
      '"[text] =label","[text] =label","[text] =label","[text] =label","[text] =label","[text] =label",online,"[text] =label","[text] =label"\r\n',
    );
    expect(auditEventsToCsv([{
      id: "unused", tenant_id: "unused", occurred_at: label, action: label,
      actor_user_id: label, target_kind: label, target_id: label,
    }])).toBe(
      'occurred_at,action,actor,target_kind,target_id,metadata,source_ip\r\n' +
      '"[text] =label","[text] =label","[text] =label","[text] =label","[text] =label",,\r\n',
    );
  });
});
