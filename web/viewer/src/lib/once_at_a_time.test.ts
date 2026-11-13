import { describe, expect, it, vi } from "vitest";

import { onceAtATime } from "./once_at_a_time";

/** A promise plus the handle to settle it, so a test controls exactly when an action finishes. */
function deferred(): { promise: Promise<void>; resolve: () => void; reject: (e: Error) => void } {
  let resolve!: () => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("onceAtATime", () => {
  it("drops a call made while the first is still in flight", async () => {
    const first = deferred();
    const calls: string[] = [];
    const guarded = onceAtATime(async (who: string) => {
      calls.push(who);
      await first.promise;
    });

    // A starts and parks on its await — the state `handleConnect` is in during POST /sessions.
    const a = guarded("A");
    // B arrives before A has finished. It must not run at all: by the time its body would reach
    // teardown(), A has not yet assigned the refs that teardown closes.
    await guarded("B");

    expect(calls).toEqual(["A"]);

    first.resolve();
    await a;
  });

  it("allows the next call once the first has finished", async () => {
    const first = deferred();
    const calls: string[] = [];
    const guarded = onceAtATime(async (who: string) => {
      calls.push(who);
      if (who === "A") await first.promise;
    });

    const a = guarded("A");
    first.resolve();
    await a;

    // Switching machines after a connection settles is the ordinary flow and must still work. A
    // guard that latched permanently would pass the test above and break the product.
    await guarded("B");
    expect(calls).toEqual(["A", "B"]);
  });

  it("reopens after the action REJECTS, so a failed connect does not wedge Connect shut", async () => {
    const first = deferred();
    const calls: string[] = [];
    const guarded = onceAtATime(async (who: string) => {
      calls.push(who);
      if (who === "A") await first.promise;
    });

    const a = guarded("A");
    first.reject(new Error("control plane unreachable"));
    await expect(a).rejects.toThrow("control plane unreachable");

    await guarded("B");
    expect(calls).toEqual(["A", "B"]);
  });

  it("reports the dropped call so the drop is not silent", async () => {
    const first = deferred();
    const dropped = vi.fn();
    const guarded = onceAtATime(async (_who: string) => {
      await first.promise;
    }, dropped);

    const a = guarded("A");
    await guarded("B");

    // The arguments matter: a log saying only "a connect was dropped" cannot tell an operator which
    // machine they clicked and did not get.
    expect(dropped).toHaveBeenCalledTimes(1);
    expect(dropped).toHaveBeenCalledWith("B");

    first.resolve();
    await a;
  });

  it("keeps guarding across a REBUILT wrapper when the gate is caller-owned", async () => {
    const first = deferred();
    const calls: string[] = [];
    const gate = { running: false };
    const body = async (who: string) => {
      calls.push(who);
      if (who === "A") await first.promise;
    };

    // App.tsx builds the wrapper in a useMemo keyed on `connectImpl`. If a dependency ever changes
    // identity mid-connection the wrapper is rebuilt — and with the flag in the wrapper's closure
    // the new one starts unguarded, which is a silent regression no other test would catch.
    const a = onceAtATime(body, undefined, gate)("A");
    const rebuilt = onceAtATime(body, undefined, gate);
    await rebuilt("B");

    expect(calls).toEqual(["A"]);

    first.resolve();
    await a;

    // And it must still open again afterwards.
    await rebuilt("C");
    expect(calls).toEqual(["A", "C"]);
  });

  it("with the DEFAULT gate a rebuilt wrapper does NOT guard — which is why App.tsx owns one", async () => {
    const first = deferred();
    const calls: string[] = [];
    const body = async (who: string) => {
      calls.push(who);
      if (who === "A") await first.promise;
    };

    // The negative control for the test above. Stated as an expectation rather than left implicit
    // so that the reason App.tsx passes a ref is recorded, not folklore.
    const a = onceAtATime(body)("A");
    await onceAtATime(body)("B");
    expect(calls).toEqual(["A", "B"]);

    first.resolve();
    await a;
  });

  it("does not serialize calls that never overlap", async () => {
    const calls: string[] = [];
    const guarded = onceAtATime(async (who: string) => {
      calls.push(who);
    });

    for (const who of ["A", "B", "C"]) await guarded(who);
    expect(calls).toEqual(["A", "B", "C"]);
  });
});
