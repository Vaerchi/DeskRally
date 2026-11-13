import { describe, expect, it } from "vitest";
import type { MachineProperty, MachineRecord } from "./console_api";
import { MAX_SITE_LEN, type SiteRow } from "./sites";
import {
  BULK_SELECTION_CAP,
  apiContextKey,
  planBulkAssign,
  pruneSelection,
  runBulkAssign,
  selectVisible,
  selectionAfterBatch,
  summarizeBulk,
  toggleSelected,
  type BulkTarget,
} from "./sites_bulk";

function row(id: string, alias?: string): SiteRow {
  const machine: MachineRecord = { id, tenant_id: "t", device_id: `dev-${id}`, group_id: "g", name: `name-${id}`, alias };
  return { machine, site: { kind: "none" } };
}

const rowsOf = (n: number) => Array.from({ length: n }, (_, i) => row(`m${i}`));
const ids = (s: ReadonlySet<string>) => [...s];

describe("apiContextKey", () => {
  it("is stable for one api object and different for a replaced one (forces a fresh panel context)", () => {
    const a = {};
    const b = {};
    expect(apiContextKey(a)).toBe(apiContextKey(a));
    expect(apiContextKey(b)).not.toBe(apiContextKey(a));
  });
});

describe("selection", () => {
  it("pruneSelection drops hidden ids and keeps identity when nothing changes", () => {
    const visible = [row("a"), row("b")];
    const same = new Set(["a"]);
    expect(pruneSelection(same, visible)).toBe(same);
    expect(ids(pruneSelection(new Set(["a", "gone"]), visible))).toEqual(["a"]);
  });

  it("toggleSelected never adds a hidden id", () => {
    const r = toggleSelected(new Set(), [row("a")], "hidden", true);
    expect(r.selected.size).toBe(0);
  });

  it("toggleSelected prunes stale ids before adding", () => {
    const r = toggleSelected(new Set(["gone"]), [row("a")], "a", true);
    expect(ids(r.selected)).toEqual(["a"]);
  });

  it("toggleSelected refuses the 51st machine and says so, but still allows deselect", () => {
    const visible = rowsOf(BULK_SELECTION_CAP + 1);
    const full = selectVisible(new Set(), visible).selected;
    expect(full.size).toBe(BULK_SELECTION_CAP);
    const refused = toggleSelected(full, visible, `m${BULK_SELECTION_CAP}`, true);
    expect(refused.capped).toBe(true);
    expect(refused.selected.size).toBe(BULK_SELECTION_CAP);
    expect(toggleSelected(full, visible, "m0", false).selected.size).toBe(BULK_SELECTION_CAP - 1);
  });

  it("selectVisible takes the first 50 in display order and reports truncation", () => {
    const visible = rowsOf(60);
    const r = selectVisible(new Set(), visible);
    expect(r.capped).toBe(true);
    expect(ids(r.selected)).toEqual(visible.slice(0, BULK_SELECTION_CAP).map((x) => x.machine.id));
    expect(selectVisible(new Set(), rowsOf(3)).capped).toBe(false);
  });

  it("selectVisible ignores previously selected hidden ids", () => {
    const r = selectVisible(new Set(["gone"]), [row("a")]);
    expect(ids(r.selected)).toEqual(["a"]);
  });
});

describe("planBulkAssign", () => {
  it("targets only selected AND visible rows, in display order, with labels", () => {
    const visible = [row("a", "Alpha"), row("b"), row("c")];
    const plan = planBulkAssign(new Set(["c", "a", "hidden"]), visible, "  HQ  ");
    expect(plan).toEqual({
      ok: true,
      value: "HQ",
      targets: [
        { id: "a", label: "Alpha" },
        { id: "c", label: "name-c" },
      ],
    });
  });

  it("uses validateSite: blank and over-long UTF-8 are refused", () => {
    const visible = [row("a")];
    expect(planBulkAssign(new Set(["a"]), visible, "   ").ok).toBe(false);
    // 1366 three-byte characters = 4098 bytes > 4096 although only 1366 UTF-16 units.
    const tooLong = "€".repeat(Math.floor(MAX_SITE_LEN / 3) + 1);
    const p = planBulkAssign(new Set(["a"]), visible, tooLong);
    expect(p.ok).toBe(false);
    expect(!p.ok && p.message).toContain("bytes");
    expect(planBulkAssign(new Set(["a"]), visible, "€".repeat(Math.floor(MAX_SITE_LEN / 3))).ok).toBe(true);
  });

  it("refuses an empty target set", () => {
    const p = planBulkAssign(new Set(["hidden"]), [row("a")], "HQ");
    expect(p).toEqual({ ok: false, message: "select at least one machine" });
  });

  it("refuses more than the cap", () => {
    const visible = rowsOf(BULK_SELECTION_CAP + 1);
    const p = planBulkAssign(new Set(visible.map((r) => r.machine.id)), visible, "HQ");
    expect(p.ok).toBe(false);
  });
});

/** Fake API recording every write; behaviour per machine id. */
function fakeApi(behave: Record<string, "ok" | "403" | "wrongValue" | "wrongKey" | "empty">) {
  const calls: { id: string; key: string; value: string }[] = [];
  let inFlight = 0;
  let maxInFlight = 0;
  return {
    calls,
    get maxInFlight() {
      return maxInFlight;
    },
    async setMachineProperty(id: string, key: string, value: string): Promise<MachineProperty> {
      calls.push({ id, key, value });
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await Promise.resolve();
      inFlight--;
      switch (behave[id] ?? "ok") {
        case "403":
          throw new Error("403 forbidden");
        case "wrongValue":
          return { key, value: `${value}-other` } as MachineProperty;
        case "wrongKey":
          return { key: "rack", value } as MachineProperty;
        case "empty":
          return undefined as unknown as MachineProperty;
        default:
          return { key, value } as MachineProperty;
      }
    },
  };
}

const targets = (...idList: string[]): BulkTarget[] => idList.map((id) => ({ id, label: `L-${id}` }));

describe("runBulkAssign", () => {
  it("writes only the site key, only to the targets, one at a time", async () => {
    const api = fakeApi({});
    const run = await runBulkAssign(api, targets("a", "b", "c"), "HQ", { shouldContinue: () => true });
    expect(api.calls).toEqual([
      { id: "a", key: "site", value: "HQ" },
      { id: "b", key: "site", value: "HQ" },
      { id: "c", key: "site", value: "HQ" },
    ]);
    expect(api.maxInFlight).toBe(1);
    expect(run.outcomes.every((o) => o.status === "saved")).toBe(true);
    expect(run.stopped).toBe(false);
  });

  it("mixed success, 403 and bad echoes: only exact echoes count as saved", async () => {
    const api = fakeApi({ b: "403", c: "wrongValue", d: "wrongKey", e: "empty" });
    const confirmed: string[] = [];
    const run = await runBulkAssign(api, targets("a", "b", "c", "d", "e"), "HQ", {
      shouldContinue: () => true,
      onOutcome: (o) => {
        if (o.status === "saved") confirmed.push(o.id);
      },
    });
    expect(run.outcomes.map((o) => `${o.id}:${o.status}`)).toEqual(["a:saved", "b:failed", "c:failed", "d:failed", "e:failed"]);
    expect(confirmed).toEqual(["a"]);
    const failed = run.outcomes.find((o) => o.id === "c");
    expect(failed?.status === "failed" && failed.error).toContain("did not confirm");
    const s = summarizeBulk(run.outcomes, "HQ");
    expect(s).toMatchObject({ saved: 1, failed: 4, skipped: 0, total: 5, allSaved: false });
    expect(s.message).toContain("1 of 5");
    expect(s.message).not.toMatch(/all saved/i);
  });

  it("a snapshot is taken: mutating the input array mid-run changes nothing", async () => {
    const api = fakeApi({});
    const list = targets("a", "b");
    const run = await runBulkAssign(api, list, "HQ", {
      shouldContinue: () => true,
      onOutcome: () => {
        list.push({ id: "z", label: "z" });
      },
    });
    expect(api.calls.map((c) => c.id)).toEqual(["a", "b"]);
    expect(run.outcomes).toHaveLength(2);
  });

  it("stops issuing requests once shouldContinue is false and reports the rest as not attempted", async () => {
    const api = fakeApi({});
    let go = true;
    const published: string[] = [];
    const run = await runBulkAssign(api, targets("a", "b", "c"), "HQ", {
      shouldContinue: () => go,
      onOutcome: (o) => {
        published.push(o.id);
        go = false; // e.g. the api identity changed after the first machine
      },
    });
    expect(api.calls.map((c) => c.id)).toEqual(["a"]);
    expect(published).toEqual(["a"]);
    expect(run.stopped).toBe(true);
    expect(run.outcomes.map((o) => o.status)).toEqual(["saved", "skipped", "skipped"]);
  });

  it("a response landing after the context changed is not published", async () => {
    const api = fakeApi({});
    let go = true;
    const orig = api.setMachineProperty.bind(api);
    api.setMachineProperty = async (id, key, value) => {
      const r = await orig(id, key, value);
      go = false; // context changed while the request was in flight
      return r;
    };
    const published: string[] = [];
    const run = await runBulkAssign(api, targets("a", "b"), "HQ", {
      shouldContinue: () => go,
      onOutcome: (o) => published.push(o.id),
    });
    expect(published).toEqual([]);
    expect(api.calls).toHaveLength(1);
    expect(run.outcomes.map((o) => o.status)).toEqual(["skipped", "skipped"]);
  });

  it("zero requests when never allowed to start", async () => {
    const api = fakeApi({});
    const run = await runBulkAssign(api, targets("a"), "HQ", { shouldContinue: () => false });
    expect(api.calls).toHaveLength(0);
    expect(run.stopped).toBe(true);
  });
});

describe("summary and retry selection", () => {
  it("all saved reports exact counts; retry set is empty", async () => {
    const api = fakeApi({});
    const { outcomes } = await runBulkAssign(api, targets("a", "b"), "HQ", { shouldContinue: () => true });
    const s = summarizeBulk(outcomes, "HQ");
    expect(s.allSaved).toBe(true);
    expect(s.message).toBe('Site "HQ" set on 2 of 2 machines.');
    expect(selectionAfterBatch(new Set(["a", "b"]), outcomes).size).toBe(0);
  });

  it("failed rows stay selected and a retry targets only them", async () => {
    const api = fakeApi({ b: "403" });
    const visible = [row("a"), row("b"), row("c")];
    const first = await runBulkAssign(api, targets("a", "b", "c"), "HQ", { shouldContinue: () => true });
    const next = selectionAfterBatch(new Set(["a", "b", "c"]), first.outcomes);
    expect(ids(next)).toEqual(["b"]);
    const plan = planBulkAssign(next, visible, "HQ");
    expect(plan.ok && plan.targets.map((t) => t.id)).toEqual(["b"]);
    const retryApi = fakeApi({});
    await runBulkAssign(retryApi, plan.ok ? plan.targets : [], "HQ", { shouldContinue: () => true });
    expect(retryApi.calls.map((c) => c.id)).toEqual(["b"]);
  });

  it("not-attempted machines stay selected and are counted separately", () => {
    const outcomes = [
      { status: "saved" as const, id: "a", label: "a", site: { kind: "set" as const, value: "HQ" } },
      { status: "skipped" as const, id: "b", label: "b" },
    ];
    expect(ids(selectionAfterBatch(new Set(["a", "b"]), outcomes))).toEqual(["b"]);
    expect(summarizeBulk(outcomes, "HQ").message).toContain("1 not attempted");
  });

  it("an empty outcome list is never 'all saved'", () => {
    expect(summarizeBulk([], "HQ").allSaved).toBe(false);
  });
});
