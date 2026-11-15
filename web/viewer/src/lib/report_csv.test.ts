/** Unit tests for the §5 Reports CSV serializers — RFC 4180 header, rows, escaping. */
import { describe, it, expect } from "vitest";
import {
  apiTokensToCsv,
  auditEventsToCsv,
  auditSummaryToCsv,
  bulkResultsToCsv,
  csvTextField,
  enrollmentTokensToCsv,
  machineGroupsToCsv,
  machineSessionsToCsv,
  machinesToCsv,
  sitesToCsv,
  sessionsToCsv,
  technicianSessionsToCsv,
  tenantsToCsv,
  usersToCsv,
  webhooksToCsv,
} from "./report_csv";
import type { APIToken, EnrollmentToken, MachineGroup, MachineRecord, MgmtAuditEvent, SessionRecord, Tenant, TenantWebhook, UserSummary } from "./console_api";
import type { SiteRow, SiteState } from "./sites";

describe("sitesToCsv", () => {
  const HEADER = "site,site_state,name,alias,device_id,group,status,online,id";
  const row = (site: SiteState, over: Partial<MachineRecord> = {}): SiteRow => ({
    machine: { id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "HOST-1", ...over },
    site,
  });

  it("emits the header alone for an empty list", () => {
    expect(sitesToCsv([])).toBe(HEADER + "\r\n");
  });

  it("keeps the given order, defaults status to active and renders online/offline/unknown", () => {
    expect(
      sitesToCsv([
        row({ kind: "set", value: "Oslo" }, { id: "pk-2", name: "B", device_id: "d2", online: false, alias: "Rcpt", group_name: "Front", status: "quarantined" }),
        row({ kind: "set", value: "Bergen" }, { online: true }),
        row({ kind: "set", value: "Rome" }),
      ]),
    ).toBe(
      HEADER +
        "\r\nOslo,set,B,Rcpt,d2,Front,quarantined,offline,pk-2" +
        "\r\nBergen,set,HOST-1,,dev-1,,active,online,pk-1" +
        "\r\nRome,set,HOST-1,,dev-1,,active,unknown,pk-1\r\n",
    );
  });

  it("distinguishes set, none and unknown; none/unknown never carry a site value", () => {
    expect(
      sitesToCsv([
        row({ kind: "set", value: "Oslo" }),
        row({ kind: "none" }),
        row({ kind: "unknown", error: "boom, \"bad\"" }),
      ]),
    ).toBe(
      HEADER +
        "\r\nOslo,set,HOST-1,,dev-1,,active,unknown,pk-1" +
        "\r\n,none,HOST-1,,dev-1,,active,unknown,pk-1" +
        "\r\n,unknown,HOST-1,,dev-1,,active,unknown,pk-1\r\n",
    );
  });

  it("an empty stored value is still `set` with an empty cell", () => {
    expect(sitesToCsv([row({ kind: "set", value: "" })])).toBe(HEADER + "\r\n,set,HOST-1,,dev-1,,active,unknown,pk-1\r\n");
  });

  it("RFC 4180-escapes comma, quote and newline", () => {
    expect(sitesToCsv([row({ kind: "set", value: 'A, "B"\nC' }, { name: "x,y", alias: 'q"q' })])).toBe(
      HEADER + '\r\n"A, ""B""\nC",set,"x,y","q""q",dev-1,,active,unknown,pk-1\r\n',
    );
  });

  it("prefixes a formula-leading site with [text] ", () => {
    expect(sitesToCsv([row({ kind: "set", value: '=HYPERLINK("http://x","y")' })])).toBe(
      HEADER + '\r\n"[text] =HYPERLINK(""http://x"",""y"")",set,HOST-1,,dev-1,,active,unknown,pk-1\r\n',
    );
  });

  it("preserves multibyte text", () => {
    expect(sitesToCsv([row({ kind: "set", value: "Tromsø 東京" }, { name: "ホスト", alias: "Ünï" })])).toBe(
      HEADER + "\r\nTromsø 東京,set,ホスト,Ünï,dev-1,,active,unknown,pk-1\r\n",
    );
  });

  it("leaves machinesToCsv output unchanged", () => {
    const m: MachineRecord = { id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "H" };
    expect(machinesToCsv([m, { ...m, online: true }, { ...m, online: false }])).toBe(
      "name,alias,device_id,group,status,os,online,last_seen,id" +
        "\r\nH,,dev-1,,active,,unknown,,pk-1" +
        "\r\nH,,dev-1,,active,,online,,pk-1" +
        "\r\nH,,dev-1,,active,,offline,,pk-1\r\n",
    );
  });
});

describe("bulkResultsToCsv", () => {
  const header = "device_id,machine,alias,state,exit_code,reason,output_head,agent_truncated,console_truncated\r\n";

  it("emits the header alone for an empty report (trailing CRLF)", () => {
    expect(bulkResultsToCsv([])).toBe(header);
  });

  it("preserves order, empty optional cells, numeric exit codes and both truncation flags", () => {
    expect(bulkResultsToCsv([
      { deviceId: "d1", machineName: "alpha", state: "done", outcome: {
        exitCode: -1, agentTruncated: true, consoleTruncated: false,
      } },
      { deviceId: "d2", machineName: "bravo", alias: "desk", state: "queued" },
      { deviceId: "d3", machineName: "charlie", state: "done", outcome: {
        exitCode: 0, agentTruncated: false, consoleTruncated: true,
      } },
    ])).toBe(header +
      "d1,alpha,,done,-1,,,true,false\r\n" +
      "d2,bravo,desk,queued,,,,,\r\n" +
      "d3,charlie,,done,0,,,false,true\r\n");
  });

  it("quotes commas, doubles quotes and preserves output line breaks", () => {
    expect(bulkResultsToCsv([{
      deviceId: "d", machineName: "PC, Reception", alias: 'a"b', state: "failed",
      outcome: { reason: 'error, "detail"', outputHead: "first\r\nsecond" },
    }])).toBe(header + 'd,"PC, Reception","a""b",failed,,"error, ""detail""","first\r\nsecond",,\r\n');
  });

  it("neutralizes every untrusted text column with each risky leading pattern", () => {
    for (const value of ["=1", "+1", "-1", "@sum", "\tplain", "\rplain", "\nplain", "\uFEFFplain", "\x00plain", "\x7Fplain", "  =1", " \tplain", "＝1", "＋1", "－1", "＠sum"]) {
      const cell = `"[text] ${value}"`;
      expect(bulkResultsToCsv([{
        deviceId: value, machineName: value, alias: value, state: "unknown",
        outcome: { reason: value, outputHead: value },
      }])).toBe(header + `${cell},${cell},${cell},unknown,,${cell},${cell},,\r\n`);
    }
  });

  it("exports the shared neutralizer and preserves the entire original text after its marker", () => {
    expect(csvTextField(' ="a,b"')).toBe('"[text]  =""a,b"""');
    expect(csvTextField("ordinary")).toBe("ordinary");
    expect(csvTextField("")).toBe("");
  });
});

describe("auditSummaryToCsv", () => {
  it("emits the header alone for an empty summary (trailing CRLF)", () => {
    expect(auditSummaryToCsv([])).toBe("action,count\r\n");
  });

  it("emits one CRLF-terminated row per entry, in order, count stringified", () => {
    expect(
      auditSummaryToCsv([
        { action: "machine.enroll", count: 3 },
        { action: "session.start", count: 1 },
      ]),
    ).toBe("action,count\r\nmachine.enroll,3\r\nsession.start,1\r\n");
  });

  it("quotes a field containing a comma", () => {
    expect(auditSummaryToCsv([{ action: "a,b", count: 2 }])).toBe('action,count\r\n"a,b",2\r\n');
  });

  it("quotes a field containing a double quote, doubling the quote", () => {
    expect(auditSummaryToCsv([{ action: 'a"b', count: 1 }])).toBe('action,count\r\n"a""b",1\r\n');
  });

  it("quotes a field containing a newline", () => {
    expect(auditSummaryToCsv([{ action: "a\nb", count: 1 }])).toBe('action,count\r\n"a\nb",1\r\n');
  });

  it("leaves an ordinary dotted action unquoted", () => {
    expect(auditSummaryToCsv([{ action: "user.role_set", count: 9 }])).toBe(
      "action,count\r\nuser.role_set,9\r\n",
    );
  });
});

describe("machineSessionsToCsv", () => {
  const row = (machine_name: string, count: number, total_seconds = 0, i = 0) => ({
    machine_id: `m-${i}`,
    machine_name,
    machine_group_id: "g-1",
    count,
    total_seconds,
  });

  it("emits the header alone for an empty report (trailing CRLF)", () => {
    expect(machineSessionsToCsv([])).toBe("machine,sessions,total_seconds\r\n");
  });

  it("emits one CRLF-terminated row per machine, in order, count + seconds stringified", () => {
    expect(machineSessionsToCsv([row("alpha", 3, 90, 0), row("bravo", 1, 0, 1)])).toBe(
      "machine,sessions,total_seconds\r\nalpha,3,90\r\nbravo,1,0\r\n",
    );
  });

  it("quotes a machine name containing a comma (hostnames are arbitrary text)", () => {
    expect(machineSessionsToCsv([row("PC, Reception", 2, 45)])).toBe(
      'machine,sessions,total_seconds\r\n"PC, Reception",2,45\r\n',
    );
  });

  it("quotes a machine name containing a double quote, doubling the quote", () => {
    expect(machineSessionsToCsv([row('a"b', 1, 7)])).toBe('machine,sessions,total_seconds\r\n"a""b",1,7\r\n');
  });

  it("serializes name, count, and RAW total_seconds — never the id or group", () => {
    expect(machineSessionsToCsv([row("host-7", 4, 3661, 99)])).toBe(
      "machine,sessions,total_seconds\r\nhost-7,4,3661\r\n",
    );
  });
});

describe("technicianSessionsToCsv", () => {
  const row = (technician: string, count: number, total_seconds = 0) => ({ technician, count, total_seconds });

  it("emits the header alone for an empty report (trailing CRLF)", () => {
    expect(technicianSessionsToCsv([])).toBe("technician,sessions,total_seconds\r\n");
  });

  it("emits one CRLF-terminated row per technician, in order, count + RAW seconds stringified", () => {
    expect(technicianSessionsToCsv([row("a@x.test", 5, 900), row("b@x.test", 1, 0)])).toBe(
      "technician,sessions,total_seconds\r\na@x.test,5,900\r\nb@x.test,1,0\r\n",
    );
  });

  it("RFC 4180-escapes a technician label carrying a comma or quote (an email is arbitrary text)", () => {
    expect(technicianSessionsToCsv([row('a,"b"@x.test', 2, 45)])).toBe(
      'technician,sessions,total_seconds\r\n"a,""b""@x.test",2,45\r\n',
    );
  });
});

describe("machinesToCsv", () => {
  const HEADER = "name,alias,device_id,group,status,os,online,last_seen,id";
  const m = (over: Partial<MachineRecord> = {}): MachineRecord => ({
    id: "pk-1",
    tenant_id: "t-1",
    device_id: "dev-1",
    group_id: "g-1",
    name: "HOST-1",
    ...over,
  });

  it("emits the header alone for an empty fleet (trailing CRLF)", () => {
    expect(machinesToCsv([])).toBe(HEADER + "\r\n");
  });

  it("emits all nine columns in order; absent optionals default (status→active, online→unknown, rest empty)", () => {
    expect(machinesToCsv([m()])).toBe(HEADER + "\r\nHOST-1,,dev-1,,active,,unknown,,pk-1\r\n");
  });

  it("renders present fields incl. the alias and the online tri-state (true→online, false→offline)", () => {
    expect(
      machinesToCsv([
        m({ alias: "Reception", group_name: "Front Office", status: "quarantined", os: "Win11", online: true, last_seen: "2026-08-01T00:00:00Z" }),
        m({ id: "pk-2", device_id: "dev-2", name: "HOST-2", online: false }),
      ]),
    ).toBe(
      HEADER +
        "\r\nHOST-1,Reception,dev-1,Front Office,quarantined,Win11,online,2026-08-01T00:00:00Z,pk-1" +
        "\r\nHOST-2,,dev-2,,active,,offline,,pk-2\r\n",
    );
  });

  it("RFC 4180-escapes a hostname/alias carrying a comma or quote", () => {
    expect(machinesToCsv([m({ name: "PC, Reception", alias: 'a"b' })])).toBe(
      HEADER + '\r\n"PC, Reception","a""b",dev-1,,active,,unknown,,pk-1\r\n',
    );
  });
});

describe("auditEventsToCsv", () => {
  const HEADER = "occurred_at,action,actor,target_kind,target_id,metadata,source_ip";
  const ev = (over: Partial<MgmtAuditEvent> = {}): MgmtAuditEvent => ({
    id: "e-1",
    tenant_id: "t-1",
    action: "machine.enroll",
    occurred_at: "2026-08-01T12:00:00Z",
    ...over,
  });

  it("emits the header alone for no events (trailing CRLF)", () => {
    expect(auditEventsToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders absent optional fields (actor/target/metadata) as empty cells", () => {
    expect(auditEventsToCsv([ev()])).toBe(HEADER + "\r\n2026-08-01T12:00:00Z,machine.enroll,,,,,\r\n");
  });

  it("emits all seven columns in order when present", () => {
    expect(
      auditEventsToCsv([ev({ actor_user_id: "u-1", target_kind: "machine", target_id: "m-1" })]),
    ).toBe(HEADER + "\r\n2026-08-01T12:00:00Z,machine.enroll,u-1,machine,m-1,,\r\n");
  });

  it("JSON-stringifies metadata into ONE escaped cell (its commas + quotes are doubled/quoted)", () => {
    expect(auditEventsToCsv([ev({ metadata: { machine_id: "m-1", n: 2 } })])).toBe(
      HEADER + '\r\n2026-08-01T12:00:00Z,machine.enroll,,,,"{""machine_id"":""m-1"",""n"":2}",\r\n',
    );
  });

  it("treats null and undefined metadata alike as an empty cell", () => {
    expect(auditEventsToCsv([ev({ metadata: null }), ev({ metadata: undefined })])).toBe(
      HEADER + "\r\n2026-08-01T12:00:00Z,machine.enroll,,,,,\r\n2026-08-01T12:00:00Z,machine.enroll,,,,,\r\n",
    );
  });

  it("escapes an action / target that itself contains a comma or quote", () => {
    expect(auditEventsToCsv([ev({ action: "a,b", target_id: 'x"y' })])).toBe(
      HEADER + '\r\n2026-08-01T12:00:00Z,"a,b",,,"x""y",,\r\n',
    );
  });

  it("appends source_ip as the LAST column (existing positions unchanged); IPv6 is one plain cell, absent is empty", () => {
    expect(auditEventsToCsv([ev({ source_ip: "198.51.100.7" }), ev({ source_ip: "2001:db8::1" }), ev()])).toBe(
      HEADER +
        "\r\n2026-08-01T12:00:00Z,machine.enroll,,,,,198.51.100.7\r\n" +
        "2026-08-01T12:00:00Z,machine.enroll,,,,,2001:db8::1\r\n" +
        "2026-08-01T12:00:00Z,machine.enroll,,,,,\r\n",
    );
  });
});

describe("sessionsToCsv", () => {
  const HEADER =
    "status,started_at,ended_at,duration_seconds,machine,machine_alias,device_id,technician_id,note,id";

  const s = (over: Partial<SessionRecord> = {}): SessionRecord => ({
    id: "sess-1",
    tenant_id: "t-1",
    machine_id: "m-1",
    technician_id: "tech-1",
    started_at: "2026-09-01T10:00:00Z",
    consent_policy: "none",
    granted_caps: null,
    machine_group_id: "g-1",
    machine_device_id: "dev-1",
    machine_name: "HOST-1",
    machine_alias: "",
    note: "",
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(sessionsToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders an ended session: all ten columns, ended_at present, duration from timestamps", () => {
    const row = s({ ended_at: "2026-09-01T10:01:30Z" });
    expect(sessionsToCsv([row])).toBe(
      HEADER + "\r\nended,2026-09-01T10:00:00Z,2026-09-01T10:01:30Z,90,HOST-1,,dev-1,tech-1,,sess-1\r\n",
    );
  });

  it("renders a live session: status=live, ended_at empty, duration from the now parameter", () => {
    const started = new Date("2026-09-01T10:00:00Z").getTime();
    const now = started + 45_000; // 45 s after start
    const row = s(); // no ended_at
    expect(sessionsToCsv([row], now)).toBe(
      HEADER + "\r\nlive,2026-09-01T10:00:00Z,,45,HOST-1,,dev-1,tech-1,,sess-1\r\n",
    );
  });

  it("renders duration_seconds as a bare integer (not quoted, not formula-hardened)", () => {
    const row = s({ ended_at: "2026-09-01T11:40:00Z" }); // 6000 s
    const csv = sessionsToCsv([row]);
    // The duration column (4th) must be the raw number with no surrounding quotes or [text] prefix.
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[3]).toBe("6000");
  });

  it("includes machine_alias when set, pinning its column position in a full-row match", () => {
    const row = s({ machine_alias: "Reception PC", ended_at: "2026-09-01T10:00:10Z" });
    expect(sessionsToCsv([row])).toBe(
      HEADER + "\r\nended,2026-09-01T10:00:00Z,2026-09-01T10:00:10Z,10,HOST-1,Reception PC,dev-1,tech-1,,sess-1\r\n",
    );
  });

  it("RFC 4180-escapes machine_name and note containing commas or quotes", () => {
    const row = s({ machine_name: "PC, Lab", note: 'printer "offline"', ended_at: "2026-09-01T10:00:10Z" });
    const csv = sessionsToCsv([row]);
    expect(csv).toContain('"PC, Lab"');
    expect(csv).toContain('"printer ""offline"""');
  });

  it("applies F17 formula-injection hardening to a note starting with '='", () => {
    const row = s({ note: "=SUM(A1)", ended_at: "2026-09-01T10:00:10Z" });
    const csv = sessionsToCsv([row]);
    // The note cell must be prefixed with [text] and quoted.
    expect(csv).toContain('"[text] =SUM(A1)"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [
      s({ id: "sess-1", ended_at: "2026-09-01T10:00:10Z" }),
      s({ id: "sess-2", ended_at: "2026-09-01T11:00:10Z" }),
    ];
    const csv = sessionsToCsv(rows);
    const lines = csv.split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("sess-1");
    expect(lines[2]).toContain("sess-2");
  });
});

describe("usersToCsv", () => {
  const HEADER = "email,display_name,roles,status,id";

  const u = (over: Partial<UserSummary> = {}): UserSummary => ({
    id: "user-1",
    email: "alice@example.com",
    display_name: "Alice",
    disabled: false,
    roles: ["technician"],
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(usersToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders an active user: all five columns in order with correct values", () => {
    expect(usersToCsv([u()])).toBe(HEADER + "\r\nalice@example.com,Alice,technician,active,user-1\r\n");
  });

  it("renders a disabled user with status=disabled", () => {
    expect(usersToCsv([u({ disabled: true })])).toBe(
      HEADER + "\r\nalice@example.com,Alice,technician,disabled,user-1\r\n",
    );
  });

  it("joins multiple roles with | separating them", () => {
    const csv = usersToCsv([u({ roles: ["owner", "admin"] })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[2]).toBe("owner|admin");
  });

  it("renders an empty roles cell when roles array is empty", () => {
    const csv = usersToCsv([u({ roles: [] })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[2]).toBe("");
  });

  it("RFC 4180-escapes a display_name containing a comma", () => {
    const csv = usersToCsv([u({ display_name: "Smith, Alice" })]);
    expect(csv).toContain('"Smith, Alice"');
  });

  it("applies F17 formula-injection hardening to a display_name starting with '='", () => {
    const csv = usersToCsv([u({ display_name: "=CMD()" })]);
    expect(csv).toContain('"[text] =CMD()"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [u({ id: "user-1", email: "a@x.com" }), u({ id: "user-2", email: "b@x.com" })];
    const lines = usersToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("user-1");
    expect(lines[2]).toContain("user-2");
  });
});

describe("tenantsToCsv", () => {
  const HEADER = "status,slug,name,mode,created_at,id";

  const t = (over: Partial<Tenant> = {}): Tenant => ({
    id: "tid-1",
    slug: "acme",
    name: "Acme Corp",
    deployment_mode: "saas",
    created_at: "2026-01-01T00:00:00Z",
    disabled: false,
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(tenantsToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders an active tenant: all six columns in order with correct values", () => {
    expect(tenantsToCsv([t()])).toBe(
      HEADER + "\r\nactive,acme,Acme Corp,saas,2026-01-01T00:00:00Z,tid-1\r\n",
    );
  });

  it("renders status=disabled for a disabled tenant", () => {
    expect(tenantsToCsv([t({ disabled: true })])).toBe(
      HEADER + "\r\ndisabled,acme,Acme Corp,saas,2026-01-01T00:00:00Z,tid-1\r\n",
    );
  });

  it("renders the deployment_mode column (mode) correctly for self_hosted", () => {
    const cols = tenantsToCsv([t({ deployment_mode: "self_hosted" })]).split("\r\n")[1]!.split(",");
    expect(cols[3]).toBe("self_hosted");
  });

  it("RFC 4180-escapes a name containing a comma", () => {
    const csv = tenantsToCsv([t({ name: "Acme, Inc." })]);
    expect(csv).toContain('"Acme, Inc."');
  });

  it("applies F17 formula-injection hardening to a name starting with '='", () => {
    const csv = tenantsToCsv([t({ name: "=DANGER()" })]);
    expect(csv).toContain('"[text] =DANGER()"');
  });

  it("applies F17 formula-injection hardening to a slug starting with '+'", () => {
    const csv = tenantsToCsv([t({ slug: "+malicious" })]);
    expect(csv).toContain('"[text] +malicious"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [t({ id: "tid-1", slug: "alpha" }), t({ id: "tid-2", slug: "beta" })];
    const lines = tenantsToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("tid-1");
    expect(lines[2]).toContain("tid-2");
  });
});

describe("enrollmentTokensToCsv", () => {
  const HEADER = "group_id,expires_at,uses,max_uses,status,created_at,created_by,id";

  const tok = (over: Partial<EnrollmentToken> = {}): EnrollmentToken => ({
    id: "tok-aaa",
    tenant_id: "tid-1",
    group_id: "grp-111",
    created_by: "user@example.com",
    created_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-02-01T00:00:00Z",
    max_uses: 5,
    uses: 2,
    revoked: false,
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(enrollmentTokensToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders an active token: all eight columns in order with correct values", () => {
    expect(enrollmentTokensToCsv([tok()])).toBe(
      HEADER + "\r\ngrp-111,2026-02-01T00:00:00Z,2,5,active,2026-01-01T00:00:00Z,user@example.com,tok-aaa\r\n",
    );
  });

  it("renders status=revoked for a revoked token", () => {
    const csv = enrollmentTokensToCsv([tok({ revoked: true })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[4]).toBe("revoked");
  });

  it("renders status=active for a non-revoked token", () => {
    const csv = enrollmentTokensToCsv([tok({ revoked: false })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[4]).toBe("active");
  });

  it("emits uses and max_uses as bare numbers (no quoting)", () => {
    const csv = enrollmentTokensToCsv([tok({ uses: 3, max_uses: 10 })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[2]).toBe("3");
    expect(cols[3]).toBe("10");
  });

  it("emits empty string for absent created_by", () => {
    const csv = enrollmentTokensToCsv([tok({ created_by: undefined })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[6]).toBe("");
  });

  it("emits empty string for an empty expires_at", () => {
    const csv = enrollmentTokensToCsv([tok({ expires_at: "" })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[1]).toBe("");
  });

  it("RFC 4180-escapes a group_id containing a comma", () => {
    const csv = enrollmentTokensToCsv([tok({ group_id: "grp,odd" })]);
    expect(csv).toContain('"grp,odd"');
  });

  it("applies F17 formula-injection hardening to a created_by starting with '='", () => {
    const csv = enrollmentTokensToCsv([tok({ created_by: "=DANGER()" })]);
    expect(csv).toContain('"[text] =DANGER()"');
  });

  it("applies F17 formula-injection hardening to a group_id starting with '+'", () => {
    const csv = enrollmentTokensToCsv([tok({ group_id: "+malicious" })]);
    expect(csv).toContain('"[text] +malicious"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [tok({ id: "tok-1" }), tok({ id: "tok-2" })];
    const lines = enrollmentTokensToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("tok-1");
    expect(lines[2]).toContain("tok-2");
  });
});

describe("apiTokensToCsv", () => {
  const HEADER = "name,id,capabilities,expires_at,status,created_at";

  const tok = (over: Partial<APIToken> = {}): APIToken => ({
    id: "tok-aaa",
    name: "ci-bot",
    capabilities: ["view_machines", "view_sessions"],
    created_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-06-01T00:00:00Z",
    revoked_at: null,
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(apiTokensToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders an active token: all six columns in order with correct values", () => {
    expect(apiTokensToCsv([tok()])).toBe(
      HEADER +
        "\r\nci-bot,tok-aaa,view_machines|view_sessions,2026-06-01T00:00:00Z,active,2026-01-01T00:00:00Z\r\n",
    );
  });

  it("renders status=revoked for a token with a revoked_at timestamp", () => {
    const csv = apiTokensToCsv([tok({ revoked_at: "2026-02-01T00:00:00Z" })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[4]).toBe("revoked");
  });

  it("renders status=active for a token with null revoked_at", () => {
    const csv = apiTokensToCsv([tok({ revoked_at: null })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[4]).toBe("active");
  });

  it("joins capabilities with '|'", () => {
    const csv = apiTokensToCsv([tok({ capabilities: ["view_machines", "manage_machines"] })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[2]).toBe("view_machines|manage_machines");
  });

  it("emits empty string for a null expires_at", () => {
    const csv = apiTokensToCsv([tok({ expires_at: null })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[3]).toBe("");
  });

  it("RFC 4180-escapes a name containing a comma", () => {
    const csv = apiTokensToCsv([tok({ name: "ci,bot" })]);
    expect(csv).toContain('"ci,bot"');
  });

  it("applies F17 formula-injection hardening to a name starting with '='", () => {
    const csv = apiTokensToCsv([tok({ name: "=DANGER()" })]);
    expect(csv).toContain('"[text] =DANGER()"');
  });

  it("applies F17 formula-injection hardening to a name starting with '+'", () => {
    const csv = apiTokensToCsv([tok({ name: "+malicious" })]);
    expect(csv).toContain('"[text] +malicious"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [tok({ id: "tok-1" }), tok({ id: "tok-2" })];
    const lines = apiTokensToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("tok-1");
    expect(lines[2]).toContain("tok-2");
  });
});

describe("machineGroupsToCsv", () => {
  const HEADER = "name,id";
  function grp(overrides?: Partial<MachineGroup>): MachineGroup {
    return { id: "gid-abc123", name: "Front Office", ...overrides };
  }

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(machineGroupsToCsv([])).toBe(HEADER + "\r\n");
  });

  it("emits one CRLF-terminated data row with name then id", () => {
    expect(machineGroupsToCsv([grp()])).toBe(`${HEADER}\r\nFront Office,gid-abc123\r\n`);
  });

  it("pins the id column position — id is the second field", () => {
    const csv = machineGroupsToCsv([grp({ id: "explicit-id" })]);
    const dataRow = csv.split("\r\n")[1];
    expect(dataRow?.split(",")[1]).toBe("explicit-id");
  });

  it("applies F17 formula-injection hardening to a name starting with '='", () => {
    const csv = machineGroupsToCsv([grp({ name: "=DANGER()" })]);
    expect(csv).toContain('"[text] =DANGER()"');
  });

  it("applies F17 formula-injection hardening to a name starting with '+'", () => {
    const csv = machineGroupsToCsv([grp({ name: "+malicious" })]);
    expect(csv).toContain('"[text] +malicious"');
  });

  it("RFC 4180 double-quote-escapes a name containing a comma", () => {
    const csv = machineGroupsToCsv([grp({ name: "Sales, West" })]);
    expect(csv).toContain('"Sales, West"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [grp({ id: "g1", name: "Alpha" }), grp({ id: "g2", name: "Beta" })];
    const lines = machineGroupsToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("g1");
    expect(lines[2]).toContain("g2");
  });
});

describe("webhooksToCsv", () => {
  const HEADER = "id,url,events,created_at";

  const wh = (over: Partial<TenantWebhook> = {}): TenantWebhook => ({
    id: "wh-aaa",
    url: "https://example.com/hook",
    events: ["session.start", "machine.enroll"],
    created_at: "2026-09-27T00:00:00Z",
    ...over,
  });

  it("emits the header alone for an empty list (trailing CRLF)", () => {
    expect(webhooksToCsv([])).toBe(HEADER + "\r\n");
  });

  it("renders a webhook with specific events: events pipe-joined in third column", () => {
    expect(webhooksToCsv([wh()])).toBe(
      HEADER + "\r\nwh-aaa,https://example.com/hook,session.start|machine.enroll,2026-09-27T00:00:00Z\r\n",
    );
  });

  it("renders 'all' for a webhook with an empty events array", () => {
    const csv = webhooksToCsv([wh({ events: [] })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[2]).toBe("all");
  });

  it("pins column order: id first, url second, events third, created_at fourth", () => {
    const csv = webhooksToCsv([wh({ id: "explicit-id", events: ["session.start"] })]);
    const cols = csv.split("\r\n")[1]!.split(",");
    expect(cols[0]).toBe("explicit-id");
    expect(cols[1]).toBe("https://example.com/hook");
    expect(cols[2]).toBe("session.start");
    expect(cols[3]).toBe("2026-09-27T00:00:00Z");
  });

  it("applies F17 formula-injection hardening to a URL starting with '='", () => {
    const csv = webhooksToCsv([wh({ url: "=DANGER()" })]);
    expect(csv).toContain('"[text] =DANGER()"');
  });

  it("RFC 4180-escapes a URL containing a comma", () => {
    const csv = webhooksToCsv([wh({ url: "https://example.com/hook,extra" })]);
    expect(csv).toContain('"https://example.com/hook,extra"');
  });

  it("emits multiple rows in the order given, each CRLF-terminated", () => {
    const rows = [wh({ id: "wh-1" }), wh({ id: "wh-2" })];
    const lines = webhooksToCsv(rows).split("\r\n").filter((l) => l !== "");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(lines[1]).toContain("wh-1");
    expect(lines[2]).toContain("wh-2");
  });
});
