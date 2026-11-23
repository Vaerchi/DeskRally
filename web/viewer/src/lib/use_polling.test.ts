import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startPolling } from "./use_polling";

// The vitest environment is node: stand in for the document with an EventTarget.
class FakeDocument extends EventTarget {
  hidden = false;
  setHidden(h: boolean) {
    this.hidden = h;
    this.dispatchEvent(new Event("visibilitychange"));
  }
}

let doc: FakeDocument;
beforeEach(() => {
  vi.useFakeTimers();
  doc = new FakeDocument();
  vi.stubGlobal("document", doc);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("startPolling", () => {
  it("ticks immediately, then on the interval", async () => {
    const fn = vi.fn(async () => {});
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(fn).toHaveBeenCalledTimes(4);
    stop();
  });

  it("pauses while the document is hidden and resumes with an immediate tick", async () => {
    const fn = vi.fn(async () => {});
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(0);
    doc.setHidden(true);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fn).toHaveBeenCalledTimes(1);
    doc.setHidden(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(2); // immediate, not after a full interval
    await vi.advanceTimersByTimeAsync(1000);
    expect(fn).toHaveBeenCalledTimes(3);
    stop();
  });

  it("does not start while hidden, and starts on becoming visible", async () => {
    doc.hidden = true;
    const fn = vi.fn(async () => {});
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fn).not.toHaveBeenCalled();
    doc.setHidden(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);
    stop();
  });

  it("never overlaps requests, including across a hide/show during a slow read", async () => {
    let release!: () => void;
    let running = 0;
    let maxRunning = 0;
    const fn = vi.fn(() => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      return new Promise<void>((r) => { release = () => { running--; r(); }; });
    });
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fn).toHaveBeenCalledTimes(1); // still in flight: no second call
    doc.setHidden(true);
    doc.setHidden(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(fn).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(1000);
    expect(fn).toHaveBeenCalledTimes(2);
    expect(maxRunning).toBe(1);
    release();
    stop();
  });

  it("keeps polling after fn throws", async () => {
    const fn = vi.fn(async () => { throw new Error("boom"); });
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(2500);
    expect(fn).toHaveBeenCalledTimes(3);
    stop();
  });

  it("stops for good, including visibility changes", async () => {
    const fn = vi.fn(async () => {});
    const stop = startPolling(fn, 1000);
    await vi.advanceTimersByTimeAsync(0);
    stop();
    await vi.advanceTimersByTimeAsync(5000);
    doc.setHidden(true);
    doc.setHidden(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("immediate:false waits one interval", async () => {
    const fn = vi.fn(async () => {});
    const stop = startPolling(fn, 1000, { immediate: false });
    await vi.advanceTimersByTimeAsync(999);
    expect(fn).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(fn).toHaveBeenCalledTimes(1);
    stop();
  });
});
