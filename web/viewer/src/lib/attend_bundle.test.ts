import { describe, expect, it } from "vitest";
import { attendBundleEndpointUrl, attendSupportModeUrl, parseSupportMode, validAttendCodeForBundle } from "./attend_bundle";

describe("validAttendCodeForBundle", () => {
  it("accepts short codes and rejects near misses", () => {
    expect(validAttendCodeForBundle("7K3M9R2T")).toBe(true);
    for (const bad of ["1234567", "123456789", "7K3M-9R2T", "7k3m9r2t", "1234567I", "1234567U"]) expect(validAttendCodeForBundle(bad)).toBe(false);
  });
  it("accepts a valid 13-char Crockford code", () => {
    expect(validAttendCodeForBundle("0123456789ABC")).toBe(true);
  });

  it("accepts all valid Crockford characters", () => {
    // 32 chars in Crockford alphabet; pick a 13-char subset
    expect(validAttendCodeForBundle("ABCDEFGHJKMN0")).toBe(true);
    expect(validAttendCodeForBundle("PQRSTVWXYZ012")).toBe(true);
  });

  it("rejects codes that are too short", () => {
    expect(validAttendCodeForBundle("0123456789AB")).toBe(false);
    expect(validAttendCodeForBundle("")).toBe(false);
  });

  it("rejects codes that are too long", () => {
    expect(validAttendCodeForBundle("0123456789ABCD")).toBe(false);
  });

  it("rejects lowercase letters", () => {
    expect(validAttendCodeForBundle("0123456789abc")).toBe(false);
    expect(validAttendCodeForBundle("0123456789ABc")).toBe(false);
  });

  it("rejects I, L, O, U (excluded from Crockford)", () => {
    expect(validAttendCodeForBundle("0123456789ABI")).toBe(false);
    expect(validAttendCodeForBundle("0123456789ABL")).toBe(false);
    expect(validAttendCodeForBundle("0123456789ABO")).toBe(false);
    expect(validAttendCodeForBundle("0123456789ABU")).toBe(false);
  });

  it("rejects punctuation and spaces", () => {
    expect(validAttendCodeForBundle("0123456789AB!")).toBe(false);
    expect(validAttendCodeForBundle("0123456789AB ")).toBe(false);
    expect(validAttendCodeForBundle("0123456789AB-")).toBe(false);
  });
});

describe("attendBundleEndpointUrl", () => {
  it("builds the expected URL from a bare origin", () => {
    expect(attendBundleEndpointUrl("https://support.example")).toBe(
      "https://support.example/cp/attended-sessions/support-bundle"
    );
  });

  it("strips trailing slashes from the origin", () => {
    expect(attendBundleEndpointUrl("https://support.example/")).toBe(
      "https://support.example/cp/attended-sessions/support-bundle"
    );
    expect(attendBundleEndpointUrl("https://support.example///")).toBe(
      "https://support.example/cp/attended-sessions/support-bundle"
    );
  });

  it("preserves ports in the origin", () => {
    expect(attendBundleEndpointUrl("https://localhost:8443")).toBe(
      "https://localhost:8443/cp/attended-sessions/support-bundle"
    );
  });
});

describe("support mode (docs/48 C pass mode)", () => {
  it("asks the public endpoint under /cp", () => {
    expect(attendSupportModeUrl("https://support.example/")).toBe("https://support.example/cp/attended-sessions/support-mode");
  });
  it("is bundle-only only for an explicit true", () => {
    expect(parseSupportMode({ bundle_only: true })).toBe(true);
    for (const body of [{ bundle_only: false }, { bundle_only: "true" }, { bundle_only: 1 }, {}, null, undefined, "x"]) {
      expect(parseSupportMode(body)).toBe(false);
    }
  });
});
