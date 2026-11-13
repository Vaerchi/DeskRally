import { describe, expect, it } from "vitest";
import type { MachineProperty, MachinePropertyFilter, MachineRecord } from "./console_api";
import {
  MAX_SITE_LEN,
  SITE_LIMIT_HINT,
  SITE_PROPERTY_KEY,
  SITE_STATE_FILTERS,
  SiteSync,
  applyOverrides,
  applySiteFilters,
  filterSiteRowsByState,
  parseSiteStateFilter,
  clearMachineSite,
  filterSiteRows,
  groupBySite,
  loadMachineSites,
  saveMachineSite,
  siteNames,
  utf8ByteLength,
  validateSite,
  type SiteRow,
} from "./sites";

function machine(id: string, name = id): MachineRecord {
  return { id, tenant_id: "t", device_id: `dev-${id}`, group_id: "g", name };
}

/** Fake API: `props` per machine; a machine id in `failProps` rejects its property read. */
function fakeApi(opts: {
  machines: MachineRecord[];
  props: Record<string, MachineProperty[]>;
  failProps?: Set<string>;
  failFilter?: boolean;
  failList?: boolean;
}) {
  const propCalls: string[] = [];
  const listCalls: (MachinePropertyFilter | undefined)[] = [];
  return {
    propCalls,
    listCalls,
    async listMachines(filter?: MachinePropertyFilter) {
      listCalls.push(filter);
      if (!filter) {
        if (opts.failList) throw new Error("list down");
        return opts.machines;
      }
      if (opts.failFilter) throw new Error("filter down");
      return opts.machines.filter((m) => (opts.props[m.id] ?? []).some((p) => p.key === filter.propertyKey));
    },
    async listMachineProperties(id: string) {
      propCalls.push(id);
      if (opts.failProps?.has(id)) throw new Error(`props down for ${id}`);
      return opts.props[id] ?? [];
    },
  };
}

const siteOf = (rows: SiteRow[], id: string) => rows.find((r) => r.machine.id === id)?.site;

describe("loadMachineSites", () => {
  it("reads sites only for machines the site filter returns; the rest are definitively 'none'", async () => {
    const api = fakeApi({
      machines: [machine("a"), machine("b"), machine("c")],
      props: { a: [{ key: "rack", value: "R1" }, { key: "site", value: "HQ" }], b: [{ key: "rack", value: "R2" }] },
    });
    const { rows, filterError } = await loadMachineSites(api);
    expect(filterError).toBeNull();
    expect(siteOf(rows, "a")).toEqual({ kind: "set", value: "HQ" });
    expect(siteOf(rows, "b")).toEqual({ kind: "none" });
    expect(siteOf(rows, "c")).toEqual({ kind: "none" });
    expect(api.propCalls).toEqual(["a"]);
    expect(api.listCalls).toEqual([undefined, { propertyKey: SITE_PROPERTY_KEY }]);
  });

  it("a failed property read is UNKNOWN with the error, never 'No site'", async () => {
    const api = fakeApi({
      machines: [machine("a"), machine("b")],
      props: { a: [{ key: "site", value: "HQ" }], b: [{ key: "site", value: "Branch" }] },
      failProps: new Set(["b"]),
    });
    const { rows } = await loadMachineSites(api);
    expect(siteOf(rows, "a")).toEqual({ kind: "set", value: "HQ" });
    expect(siteOf(rows, "b")).toEqual({ kind: "unknown", error: "props down for b" });
  });

  it("when the site filter fails, every machine is read individually instead of guessing 'none'", async () => {
    const api = fakeApi({
      machines: [machine("a"), machine("b"), machine("c")],
      props: { a: [{ key: "site", value: "HQ" }] },
      failFilter: true,
      failProps: new Set(["c"]),
    });
    const { rows, filterError } = await loadMachineSites(api, 2);
    expect(filterError).toBe("filter down");
    expect([...api.propCalls].sort()).toEqual(["a", "b", "c"]);
    expect(siteOf(rows, "a")).toEqual({ kind: "set", value: "HQ" });
    expect(siteOf(rows, "b")).toEqual({ kind: "none" });
    expect(siteOf(rows, "c")?.kind).toBe("unknown");
    expect(rows.map((r) => r.machine.id)).toEqual(["a", "b", "c"]); // input order preserved
  });

  it("rejects when the machine listing itself fails (nothing to show)", async () => {
    const api = fakeApi({ machines: [], props: {}, failList: true });
    await expect(loadMachineSites(api)).rejects.toThrow("list down");
  });
});

describe("validateSite", () => {
  it("trims and accepts a name", () => {
    expect(validateSite("  HQ ")).toEqual({ ok: true, value: "HQ" });
  });
  it("rejects blank (clearing is a separate, explicit action)", () => {
    expect(validateSite("   ").ok).toBe(false);
  });
  it("rejects a value over the server cap and accepts one at it", () => {
    expect(validateSite("x".repeat(MAX_SITE_LEN)).ok).toBe(true);
    expect(validateSite("x".repeat(MAX_SITE_LEN + 1)).ok).toBe(false);
  });
  it("counts UTF-8 bytes: 2-byte characters hit the cap at half the character count", () => {
    const atCap = "é".repeat(MAX_SITE_LEN / 2); // 2048 UTF-16 units, 4096 bytes
    expect(utf8ByteLength(atCap)).toBe(MAX_SITE_LEN);
    expect(validateSite(atCap)).toEqual({ ok: true, value: atCap });
    const over = validateSite(atCap + "x"); // 2049 units but 4097 bytes
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.message).toContain("4097 bytes");
  });
  it("counts 3-byte and 4-byte (surrogate pair) characters by bytes", () => {
    const three = "世".repeat(1365); // 4095 bytes
    expect(validateSite(three).ok).toBe(true);
    expect(validateSite(three + "x").ok).toBe(true); // exactly 4096
    expect(validateSite(three + "xx").ok).toBe(false); // 4097
    const four = "😀".repeat(1024); // 2048 UTF-16 units, 4096 bytes
    expect(validateSite(four).ok).toBe(true);
    expect(validateSite(four + "x").ok).toBe(false);
  });
  it("measures the trimmed value and never truncates", () => {
    const atCap = "é".repeat(MAX_SITE_LEN / 2);
    expect(validateSite(`  ${atCap}\t`)).toEqual({ ok: true, value: atCap });
    const tooLong = "😀".repeat(1025);
    const r = validateSite(tooLong);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).not.toContain(tooLong);
  });
  it("states the limit in bytes", () => {
    expect(SITE_LIMIT_HINT).toContain("4096 bytes");
  });
});

describe("saveMachineSite / clearMachineSite", () => {
  it("writes ONLY the site key (other properties untouched) and resolves on an exact echo", async () => {
    const calls: [string, string, string][] = [];
    const api = {
      async setMachineProperty(id: string, key: string, value: string) {
        calls.push([id, key, value]);
        return { key, value };
      },
    };
    await expect(saveMachineSite(api, "m1", "HQ")).resolves.toEqual({ kind: "set", value: "HQ" });
    expect(calls).toEqual([["m1", "site", "HQ"]]);
  });

  it("does not report success when the server echoes a different value", async () => {
    const api = { setMachineProperty: async () => ({ key: "site", value: "Other" }) };
    await expect(saveMachineSite(api, "m1", "HQ")).rejects.toThrow(/did not confirm/);
  });

  it("propagates a failed write", async () => {
    const api = {
      setMachineProperty: async (): Promise<MachineProperty> => {
        throw new Error("403 forbidden");
      },
    };
    await expect(saveMachineSite(api, "m1", "HQ")).rejects.toThrow("403 forbidden");
  });

  it("clear deletes only the site key and propagates failure", async () => {
    const deleted: [string, string][] = [];
    const ok = { deleteMachineProperty: async (id: string, key: string) => void deleted.push([id, key]) };
    await expect(clearMachineSite(ok, "m1")).resolves.toEqual({ kind: "none" });
    expect(deleted).toEqual([["m1", "site"]]);
    const bad = {
      deleteMachineProperty: async () => {
        throw new Error("404 unknown property");
      },
    };
    await expect(clearMachineSite(bad, "m1")).rejects.toThrow("404 unknown property");
  });
});

describe("SiteSync (stale refresh vs confirmed save)", () => {
  const stale: SiteRow[] = [{ machine: machine("a"), site: { kind: "none" } }];

  it("a refresh that started BEFORE a confirmed save does not overwrite it", () => {
    const sync = new SiteSync();
    const ticket = sync.beginLoad(); // load reads the server...
    sync.confirm("a", { kind: "set", value: "HQ" }); // ...save confirmed meanwhile
    expect(sync.finishLoad(ticket, stale)).toEqual([{ machine: machine("a"), site: { kind: "set", value: "HQ" } }]);
  });

  it("a refresh that started AFTER the save trusts the server's answer again", () => {
    const sync = new SiteSync();
    const t1 = sync.beginLoad();
    sync.confirm("a", { kind: "set", value: "HQ" });
    sync.finishLoad(t1, stale); // still holds the override
    const t2 = sync.beginLoad(); // started after the save
    const fresh: SiteRow[] = [{ machine: machine("a"), site: { kind: "set", value: "HQ" } }];
    expect(sync.finishLoad(t2, fresh)).toEqual(fresh);
    // and once pruned, a later server change (e.g. by another operator) is shown, not masked
    const t3 = sync.beginLoad();
    const changed: SiteRow[] = [{ machine: machine("a"), site: { kind: "set", value: "Branch" } }];
    expect(sync.finishLoad(t3, changed)).toEqual(changed);
  });

  it("a superseded load publishes nothing", () => {
    const sync = new SiteSync();
    const older = sync.beginLoad();
    const newer = sync.beginLoad();
    expect(sync.finishLoad(older, stale)).toBeNull();
    expect(sync.isCurrent(older)).toBe(false);
    expect(sync.finishLoad(newer, stale)).toEqual(stale);
  });

  it("applyOverrides ignores changes at or before the load's start sequence", () => {
    const overrides = new Map([["a", { site: { kind: "set" as const, value: "HQ" }, seq: 3 }]]);
    expect(applyOverrides(stale, overrides, 3)).toEqual(stale);
    expect(applyOverrides(stale, overrides, 2)[0].site).toEqual({ kind: "set", value: "HQ" });
  });
});

describe("filterSiteRows", () => {
  const rows: SiteRow[] = [
    { machine: { ...machine("1", "HQ-DESK-01"), alias: "Front Desk" }, site: { kind: "set", value: "Head Office" } },
    { machine: machine("2", "branch-pc"), site: { kind: "none" } },
    { machine: machine("3", "lab-box"), site: { kind: "unknown", error: "boom" } },
  ];
  const ids = (r: SiteRow[]) => r.map((x) => x.machine.id);

  it("returns every row for a blank or whitespace query", () => {
    expect(ids(filterSiteRows(rows, ""))).toEqual(["1", "2", "3"]);
    expect(ids(filterSiteRows(rows, "   "))).toEqual(["1", "2", "3"]);
  });

  it("matches site name, alias and hostname case-insensitively, trimmed", () => {
    expect(ids(filterSiteRows(rows, " head OFFICE "))).toEqual(["1"]);
    expect(ids(filterSiteRows(rows, "front"))).toEqual(["1"]);
    expect(ids(filterSiteRows(rows, "hq-desk"))).toEqual(["1"]);
    expect(ids(filterSiteRows(rows, "BRANCH"))).toEqual(["2"]);
  });

  it("returns nothing on no match, and never matches no-site/unknown by a site label", () => {
    expect(filterSiteRows(rows, "zzz")).toEqual([]);
    expect(filterSiteRows(rows, "no site")).toEqual([]);
    expect(filterSiteRows(rows, "unknown")).toEqual([]);
    expect(filterSiteRows(rows, "boom")).toEqual([]);
  });

  it("keeps row identity and site state untouched", () => {
    const out = filterSiteRows(rows, "lab");
    expect(out).toHaveLength(1);
    expect(out[0]).toBe(rows[2]);
    expect(out[0].site).toEqual({ kind: "unknown", error: "boom" });
  });
});

describe("filterSiteRowsByState / applySiteFilters", () => {
  const rows: SiteRow[] = [
    { machine: { ...machine("1", "HQ-DESK-01"), alias: "Front Desk" }, site: { kind: "set", value: "Head Office" } },
    { machine: machine("2", "branch-pc"), site: { kind: "none" } },
    { machine: machine("3", "lab-box"), site: { kind: "unknown", error: "boom" } },
    { machine: machine("4", "empty-site-box"), site: { kind: "set", value: "" } },
    { machine: machine("5", "branch-two"), site: { kind: "unknown", error: "down" } },
  ];
  const ids = (r: SiteRow[]) => r.map((x) => x.machine.id);

  it("offers the four statuses in order", () => {
    expect(SITE_STATE_FILTERS.map((f) => [f.value, f.label])).toEqual([
      ["all", "All machines"],
      ["assigned", "Assigned site"],
      ["none", "No site"],
      ["unknown", "Site unavailable"],
    ]);
  });

  it("all returns every row, as a copy", () => {
    const out = filterSiteRowsByState(rows, "all");
    expect(ids(out)).toEqual(["1", "2", "3", "4", "5"]);
    expect(out).not.toBe(rows);
  });

  it("assigned includes an empty stored value", () => {
    expect(ids(filterSiteRowsByState(rows, "assigned"))).toEqual(["1", "4"]);
  });

  it("none is only confirmed absence; unknown rows are never counted as none", () => {
    expect(ids(filterSiteRowsByState(rows, "none"))).toEqual(["2"]);
  });

  it("unknown returns only unreadable rows, never none or empty-set", () => {
    expect(ids(filterSiteRowsByState(rows, "unknown"))).toEqual(["3", "5"]);
  });

  it("each row lands in exactly one non-all status", () => {
    const total = (["assigned", "none", "unknown"] as const).flatMap((s) => ids(filterSiteRowsByState(rows, s)));
    expect(total.sort()).toEqual(["1", "2", "3", "4", "5"]);
  });

  it("combines with text search (AND), trimmed and case-insensitive", () => {
    expect(ids(applySiteFilters(rows, " BRANCH ", "all"))).toEqual(["2", "5"]);
    expect(ids(applySiteFilters(rows, "branch", "none"))).toEqual(["2"]);
    expect(ids(applySiteFilters(rows, "branch", "unknown"))).toEqual(["5"]);
    expect(ids(applySiteFilters(rows, "branch", "assigned"))).toEqual([]);
    expect(ids(applySiteFilters(rows, "head office", "assigned"))).toEqual(["1"]);
    expect(ids(applySiteFilters(rows, "head office", "none"))).toEqual([]);
    expect(ids(applySiteFilters(rows, "", "unknown"))).toEqual(["3", "5"]);
  });

  it("does not mutate its input and keeps row identity", () => {
    const before = [...rows];
    const out = applySiteFilters(rows, "lab", "unknown");
    expect(rows).toEqual(before);
    expect(out[0]).toBe(rows[2]);
  });

  it("parseSiteStateFilter falls back to all for unrecognised input", () => {
    expect(parseSiteStateFilter("none")).toBe("none");
    expect(parseSiteStateFilter("assigned")).toBe("assigned");
    expect(parseSiteStateFilter("bogus")).toBe("all");
    expect(parseSiteStateFilter("")).toBe("all");
  });
});

describe("groupBySite / siteNames", () => {
  it("orders named sites A→Z, then No site, then Unknown, machines by display name", () => {
    const rows: SiteRow[] = [
      { machine: machine("1", "zeta"), site: { kind: "set", value: "HQ" } },
      { machine: machine("2", "alpha"), site: { kind: "unknown", error: "x" } },
      { machine: machine("3", "beta"), site: { kind: "none" } },
      { machine: machine("4", "alpha"), site: { kind: "set", value: "Branch" } },
      { machine: machine("5", "gamma"), site: { kind: "set", value: "HQ" } },
    ];
    const buckets = groupBySite(rows);
    expect(buckets.map((b) => [b.kind, b.site, b.rows.map((r) => r.machine.name)])).toEqual([
      ["set", "Branch", ["alpha"]],
      ["set", "HQ", ["gamma", "zeta"]],
      ["none", null, ["beta"]],
      ["unknown", null, ["alpha"]],
    ]);
    expect(siteNames(rows)).toEqual(["Branch", "HQ"]);
  });
});
