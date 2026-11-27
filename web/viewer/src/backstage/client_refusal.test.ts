import { describe, it, expect } from "vitest";
import { explainAgentRefusal, parseEnvelope } from "./client";

describe("explainAgentRefusal", () => {
  it("tells the operator an old agent needs updating for a large Get", () => {
    const raw = "action refused: files over 64 MiB cannot be downloaded yet";
    const out = explainAgentRefusal(raw);
    expect(out.startsWith(raw)).toBe(true);
    expect(out).toContain("agent 1.3.39 or later");
    expect(explainAgentRefusal(out)).toBe(out); // idempotent
  });

  it("leaves every other message alone", () => {
    expect(explainAgentRefusal("action refused: path is outside the allowed roots")).toBe(
      "action refused: path is outside the allowed roots",
    );
  });

  it("is applied when an agent envelope is parsed", () => {
    const env = parseEnvelope(
      JSON.stringify({ ok: false, error: { kind: "refused", message: "action refused: files over 64 MiB cannot be downloaded yet" } }),
    );
    expect(env.error?.message).toContain("agent 1.3.39 or later");
  });
});
