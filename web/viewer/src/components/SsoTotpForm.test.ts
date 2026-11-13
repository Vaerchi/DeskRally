import { describe, expect, it } from "vitest";
import { ssoTotpReason } from "./SsoTotpForm";

describe("ssoTotpReason", () => {
  it("explains only the three control-plane reasons", () => {
    expect(ssoTotpReason("trust_off")).toMatch(/not set DeskRally to accept/);
    expect(ssoTotpReason("no_amr")).toMatch(/did not report how you signed in/);
    expect(ssoTotpReason("no_mfa")).toMatch(/did not use MFA/);
  });

  // Codex UX review v1: inherited keys must not resolve (an object would crash React's render).
  it("ignores inherited keys, unknown values and absence", () => {
    for (const why of ["__proto__", "constructor", "toString", "hasOwnProperty", "required", "", "<b>x</b>"]) {
      expect(ssoTotpReason(why)).toBeNull();
    }
    expect(ssoTotpReason(null)).toBeNull();
  });
});
