/** Boundary tests for the session-policy form validator (mirrors server NormalizeSessionPolicy). */
import { describe, it, expect } from "vitest";
import { defaultIdleMinutes, parseDefaultIdleMinutes, parseSessionPolicyInput } from "./session_policy_input";

function err(limit: string, age: string): string {
  const r = parseSessionPolicyInput(limit, age);
  if (r.ok) throw new Error(`expected rejection for ${JSON.stringify([limit, age])}`);
  return r.error;
}

describe("default idle timeout minutes", () => {
  it.each([0, 1, 90, 300, 3599, 3600])("round-trips %d API seconds", (seconds) => {
    expect(parseDefaultIdleMinutes(defaultIdleMinutes(seconds))).toBe(seconds);
  });

  it("displays minutes and converts edited minutes to seconds", () => {
    expect(defaultIdleMinutes(300)).toBe("5");
    expect(parseDefaultIdleMinutes(" 7.5 ")).toBe(450);
  });

  it.each(["", " ", "-1", "60.01", "61", "0.001", "1e1", "NaN", "Infinity"])("rejects %j", (text) => {
    expect(parseDefaultIdleMinutes(text)).toBeNull();
  });
});

describe("parseSessionPolicyInput", () => {
  it("accepts 0/0 (no limits)", () => {
    expect(parseSessionPolicyInput("0", "0")).toEqual({
      ok: true,
      value: { max_concurrent_sessions: 0, max_session_seconds: 0 },
    });
  });

  it("trims whitespace around valid values", () => {
    expect(parseSessionPolicyInput(" 5 ", " 60 ")).toEqual({
      ok: true,
      value: { max_concurrent_sessions: 5, max_session_seconds: 60 },
    });
  });

  it("concurrency bounds: 0, 1, 100000 ok; -1, 100001 rejected naming the field and range", () => {
    expect(parseSessionPolicyInput("0", "0").ok).toBe(true);
    expect(parseSessionPolicyInput("1", "60").ok).toBe(true);
    expect(parseSessionPolicyInput("100000", "60").ok).toBe(true);
    for (const bad of ["-1", "100001"]) {
      const e = err(bad, "60");
      expect(e).toContain("max_concurrent_sessions");
      expect(e).toContain("100000");
    }
  });

  it("duration bounds: 0, 60, 2592000 ok; 59, 2592001 rejected naming the field and range", () => {
    expect(parseSessionPolicyInput("0", "0").ok).toBe(true);
    expect(parseSessionPolicyInput("0", "60").ok).toBe(true);
    expect(parseSessionPolicyInput("0", "2592000").ok).toBe(true);
    for (const bad of ["59", "2592001", "-1"]) {
      const e = err("0", bad);
      expect(e).toContain("max_session_seconds");
      expect(e).toContain("60");
      expect(e).toContain("2592000");
    }
  });

  it("never coerces empty or malformed input to 0", () => {
    for (const bad of ["", " ", "1e3", "9007199254740993", "abc", "1.5", "+1", "١٢"]) {
      expect(err(bad, "0")).toContain("max_concurrent_sessions");
      expect(err("0", bad)).toContain("max_session_seconds");
    }
  });

  it("rejects a concurrency cap with no duration", () => {
    const e = err("1", "0");
    expect(e).toContain("max_session_seconds");
  });
});
