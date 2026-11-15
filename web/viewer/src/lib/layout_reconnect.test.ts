import { describe, expect, it } from "vitest";
import { isDisplayLayoutEnd, LayoutReconnectBudget } from "./layout_reconnect";

 describe("layout reconnect", () => {
  it("matches only the agent's display-layout end prefix", () => {
    expect(isDisplayLayoutEnd("session ended: the display layout on this machine changed (a monitor was connected, disconnected or woke up, or the resolution changed); reconnect to continue")).toBe(true);
    expect(isDisplayLayoutEnd("session ended: idle timeout reached")).toBe(false);
    expect(isDisplayLayoutEnd("session ended: the control-plane session lease expired and was not renewed")).toBe(false);
    expect(isDisplayLayoutEnd("Session ended: session has ended")).toBe(false);
  });

  it("allows three attempts per ten minutes and expires the oldest attempt", () => {
    const budget = new LayoutReconnectBudget();
    expect(budget.take(0)).toBe(true);
    expect(budget.take(1000)).toBe(true);
    expect(budget.take(2000)).toBe(true);
    expect(budget.take(3000)).toBe(false);
    expect(budget.take(599_999)).toBe(false);
    expect(budget.take(600_000)).toBe(true);
    expect(budget.take(600_001)).toBe(false);
  });

  it("does not consume budget when an attempt is refused", () => {
    const budget = new LayoutReconnectBudget(1, 100);
    expect(budget.take(0)).toBe(true);
    expect(budget.take(50)).toBe(false);
    expect(budget.take(99)).toBe(false);
    expect(budget.take(100)).toBe(true);
    expect(budget.take(150)).toBe(false);
    expect(budget.take(200)).toBe(true);
  });
});
