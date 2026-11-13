/** Unit tests for the latest-wins generation guard used to drop stale reads. */
import { describe, it, expect } from "vitest";
import { createLatestWins } from "./latest_wins";

describe("createLatestWins", () => {
  it("a fresh token is current", () => {
    const lw = createLatestWins();
    expect(lw.isCurrent(lw.begin())).toBe(true);
  });

  it("the latest begin wins and earlier tokens go stale", () => {
    const lw = createLatestWins();
    const a = lw.begin();
    const b = lw.begin();
    const c = lw.begin();
    expect(lw.isCurrent(a)).toBe(false);
    expect(lw.isCurrent(b)).toBe(false);
    expect(lw.isCurrent(c)).toBe(true);
  });

  it("invalidate makes every outstanding token stale", () => {
    const lw = createLatestWins();
    const a = lw.begin();
    const b = lw.begin();
    lw.invalidate();
    expect(lw.isCurrent(a)).toBe(false);
    expect(lw.isCurrent(b)).toBe(false);
  });

  it("a token begun after invalidate is current, and repeated invalidate stays stale", () => {
    const lw = createLatestWins();
    const old = lw.begin();
    lw.invalidate();
    lw.invalidate();
    const fresh = lw.begin();
    expect(lw.isCurrent(old)).toBe(false);
    expect(lw.isCurrent(fresh)).toBe(true);
    lw.invalidate();
    expect(lw.isCurrent(fresh)).toBe(false);
  });

  it("independent instances do not interfere", () => {
    const x = createLatestWins();
    const y = createLatestWins();
    const tx = x.begin();
    const ty = y.begin();
    y.begin();
    y.invalidate();
    expect(x.isCurrent(tx)).toBe(true);
    expect(y.isCurrent(ty)).toBe(false);
    x.invalidate();
    const ty2 = y.begin();
    expect(x.isCurrent(tx)).toBe(false);
    expect(y.isCurrent(ty2)).toBe(true);
  });

  it("a token never begun by this instance is not current", () => {
    const lw = createLatestWins();
    lw.begin();
    expect(lw.isCurrent(0)).toBe(false);
    expect(lw.isCurrent(99)).toBe(false);
  });
});
