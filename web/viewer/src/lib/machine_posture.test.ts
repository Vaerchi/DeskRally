import { describe, expect, it } from "vitest";
import { policyPosture, policyPostureBadge } from "./machine_posture";

describe("policyPosture: all combinations", () => {
  const T = true, F = false, U = undefined;
  const cases: Array<[boolean | undefined, boolean | undefined, string]> = [
    [T, T, "enforced"],
    [T, F, "not_enforced"], // key alone is not mandatory policy
    [F, T, "not_enforced"],
    [F, F, "not_enforced"],
    [F, U, "not_enforced"],
    [U, F, "not_enforced"],
    [T, U, "unknown"],
    [U, T, "unknown"],
    [U, U, "unknown"],
  ];
  for (const [pinned, required, want] of cases) {
    it(`pinned=${pinned} required=${required} -> ${want}`, () => {
      expect(policyPosture({ grant_key_pinned: pinned, session_policy_required: required })).toBe(want);
    });
  }
  it("unknown is labelled, neutral and self-reported wording is present on enforced", () => {
    expect(policyPostureBadge({}).label).toBe("policy unknown");
    expect(policyPostureBadge({ grant_key_pinned: true, session_policy_required: true }).title).toMatch(/Self-reported/);
  });
});
