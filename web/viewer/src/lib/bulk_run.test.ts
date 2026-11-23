import { describe, expect, it, vi } from "vitest";
import type { ToolboxItem } from "./console_api";
import type { RunOutcome } from "./brokered_session_core";
import { composeRunLine, runBulk } from "./bulk_run";
import type { BulkCore, BulkRun, BulkTask, OpenBulkCore } from "./bulk_run";

const ITEM: ToolboxItem = {
  id: "script", name: "Script", description: "", scope: "shared", shell: "cmd",
  run_as: "system", body: "echo hello", body_sha256: "hash", version: 7,
  updated_at: "2026-10-17T00:00:00Z", mine: false,
};
const TASK: BulkTask = { kind: "toolbox", item: ITEM };
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const done = (stdout = "", stderr = ""): RunOutcome => ({
  kind: "done", exitCode: 0, stdout, stderr, agentTruncated: false, consoleTruncated: false,
});
const tick = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function core(result: RunOutcome = done()): BulkCore {
  return { run: vi.fn().mockResolvedValue(result), close: vi.fn().mockResolvedValue(undefined) };
}

describe("runBulk", () => {
  it("holds at most three sessions, including cleanup, and opens FIFO without retries", async () => {
    const gates = Array.from({ length: 7 }, () => deferred<void>());
    const opened: string[] = [];
    let live = 0;
    let maximum = 0;
    const cores: BulkCore[] = [];
    const open: OpenBulkCore = async (device) => {
      const index = Number(device);
      opened.push(device);
      maximum = Math.max(maximum, ++live);
      const session: BulkCore = {
        run: vi.fn().mockResolvedValue(done()),
        close: vi.fn(async () => { await gates[index].promise; live--; }),
      };
      cores.push(session);
      return session;
    };
    const bulk = runBulk(["0", "1", "2", "3", "4", "5", "6"], TASK, open);
    await tick();
    expect(opened).toEqual(["0", "1", "2"]);
    gates[1].resolve();
    await tick();
    expect(opened).toEqual(["0", "1", "2", "3"]);
    for (const gate of gates) gate.resolve();
    const rows = await bulk.done;
    expect(opened).toEqual(["0", "1", "2", "3", "4", "5", "6"]);
    expect(maximum).toBe(3);
    expect(live).toBe(0);
    expect(rows.every((row) => row.state === "done")).toBe(true);
    for (const session of cores) {
      expect(session.run).toHaveBeenCalledTimes(1);
      expect(session.close).toHaveBeenCalledTimes(1);
    }
  });

  it("rejects 26 unique devices synchronously before opening anything", () => {
    const open = vi.fn();
    expect(() => runBulk(Array.from({ length: 26 }, (_, i) => String(i)), TASK, open)).toThrow(/25/);
    expect(open).not.toHaveBeenCalled();
  });

  it("deduplicates before enforcing the limit and preserves first-seen order", async () => {
    const open = vi.fn(async () => core());
    const bulk = runBulk(["b", "a", ...Array<string>(30).fill("b")], TASK, open);
    expect((await bulk.done).map((row) => row.deviceId)).toEqual(["b", "a"]);
    expect(open.mock.calls).toHaveLength(2);
  });

  it("cancels queued, connecting, and authorizing rows but waits for dispatched results", async () => {
    const acquisition = deferred<BulkCore>();
    const authorization = deferred<RunOutcome>();
    const result = deferred<RunOutcome>();
    const dispatched = core();
    dispatched.run = vi.fn(() => result.promise);
    const authorizing = core();
    authorizing.run = vi.fn((_item, isCancelled) => authorization.promise.then(() =>
      isCancelled() ? { kind: "not_run" as const, reason: "Cancelled before dispatch" } : done()));
    const late = core();
    const signals: AbortSignal[] = [];
    const open = vi.fn((device: string, signal: AbortSignal): Promise<BulkCore> => {
      signals.push(signal);
      return device === "connecting" ? acquisition.promise : Promise.resolve(device === "sent" ? dispatched : authorizing);
    });
    const bulk = runBulk(["sent", "authorizing", "connecting", "queued"], TASK, open);
    await tick();
    bulk.cancel();
    bulk.cancel();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    expect(bulk.rows[3].state).toBe("cancelled");
    expect(dispatched.close).not.toHaveBeenCalled();
    acquisition.resolve(late);
    authorization.resolve(done());
    await tick();
    expect(late.run).not.toHaveBeenCalled();
    expect(late.close).toHaveBeenCalledTimes(1);
    expect(authorizing.close).toHaveBeenCalledTimes(1);
    expect(dispatched.close).not.toHaveBeenCalled();
    result.resolve(done("finished"));
    expect((await bulk.done).map((row) => row.state)).toEqual(["done", "cancelled", "cancelled", "cancelled"]);
    expect(dispatched.close).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledTimes(3);
  });

  it("forwards abort to a pending acquisition and opens nothing after cancellation", async () => {
    const open = vi.fn((_device: string, signal: AbortSignal) => new Promise<BulkCore>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    }));
    const bulk = runBulk(["a", "b", "c", "d"], TASK, open);
    await tick();
    bulk.cancel();
    expect((await bulk.done).every((row) => row.state === "cancelled")).toBe(true);
    expect(open).toHaveBeenCalledTimes(3);
  });

  it("allows cancellation before the first open", async () => {
    const open = vi.fn(async () => core());
    const bulk = runBulk(["a"], TASK, open);
    bulk.cancel();
    expect((await bulk.done)[0].state).toBe("cancelled");
    expect(open).not.toHaveBeenCalled();
  });

  it("retains UTF-8 heads within the aggregate budget and preserves both flags", async () => {
    const first = deferred<RunOutcome>();
    const second = deferred<RunOutcome>();
    const a = core();
    const b = core();
    a.run = vi.fn(() => first.promise);
    b.run = vi.fn(() => second.promise);
    const bulk = runBulk(["a", "b"], TASK, async (id) => id === "a" ? a : b, { aggregateBudgetBytes: 7 });
    await tick();
    first.resolve({ ...done("😀", "é"), agentTruncated: true, consoleTruncated: true } as RunOutcome);
    await tick();
    second.resolve(done("ab", "tail"));
    const rows = await bulk.done;
    expect(rows[0].outcome).toEqual({ exitCode: 0, outputHead: "😀é", agentTruncated: true, consoleTruncated: true });
    expect(rows[1].outcome).toEqual({ exitCode: 0, outputHead: "a", agentTruncated: false, consoleTruncated: true });
    expect(rows.reduce((sum, row) => sum + new TextEncoder().encode(row.outcome?.outputHead ?? "").length, 0)).toBe(7);
  });

  it("enforces the per-row byte cap even for injected cores and supports a zero budget", async () => {
    const rows = await runBulk(["a"], TASK, async () => core(done("x".repeat(65535) + "😀", "stderr"))).done;
    expect(rows[0].outcome?.outputHead).toBe("x".repeat(65535) + "s");
    expect(rows[0].outcome?.consoleTruncated).toBe(true);
    const empty = await runBulk(["a"], TASK, async () => core(done("x")), { aggregateBudgetBytes: 0 }).done;
    expect(empty[0].outcome?.outputHead).toBe("");
    expect(empty[0].outcome?.consoleTruncated).toBe(true);
  });

  it("isolates acquisition, run, and cleanup failures and preserves terminal outcomes", async () => {
    const rejected = core();
    rejected.run = vi.fn().mockRejectedValue(new Error("send may have occurred"));
    const refused = core({ kind: "not_run", reason: "policy" });
    const unknown = core({ kind: "unknown", reason: "disconnected" });
    const success = core(done());
    success.close = vi.fn().mockRejectedValue(new Error("cleanup"));
    const open = vi.fn(async (id: string) => {
      if (id === "acquire") throw new Error("denied");
      return id === "throw" ? rejected : id === "refused" ? refused : id === "unknown" ? unknown : success;
    });
    const rows = await runBulk(["acquire", "throw", "refused", "unknown", "success"], TASK, open).done;
    expect(rows.map((row) => row.state)).toEqual(["failed", "unknown", "failed", "unknown", "done"]);
    expect(rows.map((row) => row.outcome?.reason)).toEqual(["denied", "send may have occurred", "policy", "disconnected", undefined]);
    for (const session of [rejected, refused, unknown, success]) expect(session.close).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledTimes(5);
  });

  it("isolates observers and snapshots, and emits each terminal state exactly once", async () => {
    const states: string[] = [];
    const bulk = runBulk(["a"], TASK, async () => core(), {
      onChange(rows) {
        states.push(rows[0].state);
        (rows[0] as { state: string }).state = "corrupted";
        throw new Error("observer");
      },
    });
    expect((await bulk.done)[0].state).toBe("done");
    expect(states).toEqual(["queued", "connecting", "running", "done"]);
    const snapshot = bulk.rows;
    snapshot[0].outcome!.reason = "changed";
    expect(bulk.rows[0].outcome?.reason).toBeUndefined();
  });

  it("handles cancellation reentered from a running notification without calling run", async () => {
    const session = core();
    let bulk!: BulkRun;
    bulk = runBulk(["a"], TASK, async () => session, {
      onChange(rows) { if (rows[0].state === "running") bulk.cancel(); },
    });
    expect((await bulk.done)[0].state).toBe("cancelled");
    expect(session.run).not.toHaveBeenCalled();
    expect(session.close).toHaveBeenCalledTimes(1);
  });

  it("handles an empty selection and rejects invalid budgets", async () => {
    const open = vi.fn(async () => core());
    expect(await runBulk([], TASK, open).done).toEqual([]);
    expect(open).not.toHaveBeenCalled();
    for (const budget of [-1, 0.5, Infinity, NaN]) {
      expect(() => runBulk([], TASK, open, { aggregateBudgetBytes: budget })).toThrow(/budget/);
    }
  });
});

describe("composeRunLine (push-and-run, docs/60 2a)", () => {
  const DIR = "C:\\rmt-agent\\transfers";

  it("builds the PowerShell line from the landed name (dedup suffix, spaces) and trims args", () => {
    const out = composeRunLine(DIR, "my setup (2).exe", "  /S /NORESTART ");
    expect(out).toEqual({ ok: true, line: "& 'C:\\rmt-agent\\transfers\\my setup (2).exe' /S /NORESTART; exit $LASTEXITCODE" });
  });

  it("omits the argument gap when args are empty", () => {
    const out = composeRunLine(DIR, "tool.exe", "");
    expect(out).toEqual({ ok: true, line: "& 'C:\\rmt-agent\\transfers\\tool.exe'; exit $LASTEXITCODE" });
  });

  it("refuses when the agent advertised no transfer folder", () => {
    expect(composeRunLine(undefined, "tool.exe", "").ok).toBe(false);
  });

  it("refuses an unquotable landed name instead of escaping it", () => {
    for (const landed of [
      "a'b.exe", // the PS literal delimiter
      "a%PATH%.exe",
      "a!b.exe",
      'a"b.exe',
      "a&b.exe",
      "a;b.exe",
      "a`b.exe",
      "a$b.exe",
      "a|b.exe",
      "a<b.exe",
      "sub\\tool.exe", // a separator: the name must be ONE component
      "c:tool.exe",
      "..",
      ". .",
      "",
    ]) {
      const out = composeRunLine(DIR, landed, "");
      expect(out.ok, `landed ${JSON.stringify(landed)} must be refused`).toBe(false);
    }
  });

  it("refuses a transfer folder that is relative, trailing-slashed, or has an unsafe segment", () => {
    for (const dir of ["transfers", "C:\\", "C:\\x\\", "C:\\a%b\\c", "C:\\a\\..", "\\\\server\\share"]) {
      expect(composeRunLine(dir, "tool.exe", "").ok, `dir ${JSON.stringify(dir)} must be refused`).toBe(false);
    }
  });

  it("refuses multi-line args but passes PowerShell-syntax args through verbatim", () => {
    expect(composeRunLine(DIR, "t.exe", "a\nb").ok).toBe(false);
    const out = composeRunLine(DIR, "t.exe", "-ArgumentList 'x'");
    expect(out.ok && out.line.includes("-ArgumentList 'x'")).toBe(true);
  });
});
