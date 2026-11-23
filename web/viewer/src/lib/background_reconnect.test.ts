import { afterEach, describe, expect, it, vi } from "vitest";
import { isRecoverableAgentEnd } from "./agent_error";
import { watchBackgroundReturn } from "./background_reconnect";
import { LayoutReconnectBudget } from "./layout_reconnect";
import { SessionRecovery } from "./session_recovery";

class TestDocument extends EventTarget {
  visibilityState: DocumentVisibilityState = "visible";

  setVisibility(state: DocumentVisibilityState) {
    this.visibilityState = state;
    this.dispatchEvent(new Event("visibilitychange"));
  }
}

function setup(maxAttempts = 3) {
  vi.useFakeTimers();
  const doc = new TestDocument();
  const win = new EventTarget();
  const retry = vi.fn(async () => {});
  const notify = vi.fn();
  const recovery = new SessionRecovery(retry, notify, undefined, () => doc.visibilityState === "hidden");
  recovery.enabled = true;
  const budget = new LayoutReconnectBudget(maxAttempts);
  const session = { generation: 1, wasLive: true, frames: 10, failed: false };
  const transport = { failed: false, signalingDropped: false };
  const stop = watchBackgroundReturn(doc, win, () => ({
    ...session,
    failed: transport.failed || transport.signalingDropped || !!notify.mock.lastCall?.[0],
  }), (isCurrent) => recovery.afterBackground(budget, isCurrent));
  function hideFor(ms: number) {
    doc.setVisibility("hidden");
    vi.advanceTimersByTime(ms);
  }
  function showFromCache() {
    doc.visibilityState = "visible";
    win.dispatchEvent(Object.assign(new Event("pageshow"), { persisted: true }));
  }
  return { doc, retry, notify, recovery, session, transport, hideFor, showFromCache, stop };
}

afterEach(() => vi.useRealTimers());

describe("background-return recovery", () => {
  it("ignores a short hide and a session that never connected", async () => {
    const f = setup();
    f.transport.failed = true;
    f.hideFor(1999);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(6000);
    f.session.wasLive = false;
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(6000);
    expect(f.retry).not.toHaveBeenCalled();
  });

  it("replaces the ordinary loss timer with one retry after 1 second", async () => {
    const f = setup();
    f.doc.setVisibility("hidden");
    f.transport.failed = true;
    f.recovery.lost();
    await vi.advanceTimersByTimeAsync(3000);
    expect(f.retry).not.toHaveBeenCalled();
    f.doc.setVisibility("visible");
    f.showFromCache();
    expect(f.notify).toHaveBeenLastCalledWith({
      message: "Reconnecting after the app was in the background…", retrying: true,
    });
    await vi.advanceTimersByTimeAsync(999);
    expect(f.retry).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(f.retry).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10000);
    expect(f.retry).toHaveBeenCalledTimes(1);
  });

  it("reconnects on persisted pageshow when a recovery notice is already visible", async () => {
    const f = setup();
    f.hideFor(2000);
    f.recovery.lost("ICE failed");
    f.showFromCache();
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.retry).toHaveBeenCalledTimes(1);
  });

  it("reconnects when signaling dropped even if WebRTC still reports connected", async () => {
    const f = setup();
    f.hideFor(2000);
    f.transport.signalingDropped = true;
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.retry).toHaveBeenCalledTimes(1);
  });

  it("waits five seconds for fresh frames on a connected transport", async () => {
    const f = setup();
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(4999);
    expect(f.notify).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(f.notify).toHaveBeenLastCalledWith(expect.objectContaining({ retrying: true }));
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.retry).toHaveBeenCalledTimes(1);
  });

  it("leaves a connection alone if fresh frames arrive", async () => {
    const f = setup();
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(4000);
    f.session.frames++;
    await vi.advanceTimersByTimeAsync(3000);
    expect(f.retry).not.toHaveBeenCalled();
    expect(f.notify).not.toHaveBeenCalled();
  });

  it.each(["Guest ended the session", "Administrator ended the session", "Maximum duration reached",
    "Machine quarantined", "Binding failed", "Sign-in expired"])("does not revive a refusal: %s", async (reason) => {
    const f = setup();
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    f.recovery.refuse(reason);
    await vi.advanceTimersByTimeAsync(6000);
    expect(f.retry).not.toHaveBeenCalled();
    expect(f.notify).toHaveBeenLastCalledWith({ message: reason, retrying: false });
  });

  it("leaves the manual recovery notice after exhausting the separate budget", async () => {
    const f = setup(1);
    f.transport.failed = true;
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(1000);
    f.recovery.cancel();
    f.session.generation++;
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.retry).toHaveBeenCalledTimes(1);
    expect(f.notify).toHaveBeenLastCalledWith({
      message: "Connection unavailable. Reconnect to start a new session.", retrying: false,
    });
  });

  it.each(["hidden", "watching frames", "waiting to reconnect"])("cancels on generation change while %s", async (stage) => {
    const f = setup();
    f.transport.failed = stage === "waiting to reconnect";
    f.hideFor(2000);
    if (stage !== "hidden") f.doc.setVisibility("visible");
    f.session.generation++;
    if (stage === "hidden") f.doc.setVisibility("visible");
    await vi.advanceTimersByTimeAsync(7000);
    expect(f.retry).not.toHaveBeenCalled();
  });

  it("cancels an armed reconnect on End or navigation", async () => {
    const f = setup();
    f.transport.failed = true;
    f.hideFor(2000);
    f.doc.setVisibility("visible");
    f.stop();
    f.recovery.cancel();
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.retry).not.toHaveBeenCalled();
  });

  it("classifies the agent lease lapse without including deliberate agent ends", () => {
    expect(isRecoverableAgentEnd("session ended: the control-plane session lease expired and was not renewed")).toBe(true);
    expect(isRecoverableAgentEnd("session ended: the lease lapsed")).toBe(true);
    expect(isRecoverableAgentEnd("session ended: idle timeout reached")).toBe(false);
    expect(isRecoverableAgentEnd("session ended: maximum duration reached")).toBe(false);
  });
});
