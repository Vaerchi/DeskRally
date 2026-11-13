import { describe, it, expect } from "vitest";
import { parseEnvelope } from "./client";

describe("parseEnvelope", () => {
  it("accepts valid envelopes without validating tool-specific data", () => {
    const value = {
      ok: true,
      response: { type: "RegistryValue", data: { arbitrary: true } },
      audit: {
        hash: "abc",
        outcome: { result: "ok", reason: "authorized" },
        prev_hash: null,
        time: "2026-10-18T00:00:00Z",
        action: { kind: "read_registry" },
        actor: "operator",
      },
    };
    expect(parseEnvelope(JSON.stringify(value))).toEqual(value);
    const failure = { ok: false, error: { kind: "denied", message: "blocked" } };
    expect(parseEnvelope(JSON.stringify(failure))).toEqual(failure);
    expect(parseEnvelope('{"ok":true,"audit":{"hash":"abc","outcome":"authorized"}}').ok).toBe(true);
  });

  it.each([
    { ok: true, audit: {} },
    { ok: true, audit: { hash: 123, outcome: "ok" } },
    { ok: false, error: { kind: 123, message: "blocked" } },
    { ok: false, error: { kind: "denied", message: 123 } },
    { ok: false, error: null },
    { ok: true, audit: [] },
    { ok: true, audit: { hash: "abc", outcome: "ok", time: 123 } },
    { ok: true, audit: { hash: "abc", outcome: "ok", actor: false } },
    { ok: true, audit: { hash: "abc", outcome: "ok", prev_hash: 123 } },
    { ok: true, audit: { hash: "abc", outcome: { result: 123 } } },
    { ok: true, audit: { hash: "abc", outcome: { reason: false } } },
    { ok: true, audit: { hash: "abc", outcome: "ok", action: { kind: 123 } } },
  ])("rejects malformed nested fields: %j", (value) => {
    expect(() => parseEnvelope(JSON.stringify(value))).toThrowError("malformed Under the Hood reply:");
  });
});
