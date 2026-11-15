import { describe, expect, it } from "vitest";
import { parseGrantCapabilities } from "./grant";

function makeGrant(capabilities: unknown): string {
  return JSON.stringify({
    claims: {
      grant: { machine_id: "m1", capabilities, machine_group_id: null },
      issued_at_ms: 1_000_000,
      expires_at_ms: 2_000_000,
    },
    sig: "deadbeef".repeat(16),
  });
}

describe("parseGrantCapabilities", () => {
  it("returns all capability strings from a well-formed grant", () => {
    const caps = parseGrantCapabilities(makeGrant(["file_download", "process_list"]));
    expect(caps.has("file_download")).toBe(true);
    expect(caps.has("process_list")).toBe(true);
    expect(caps.size).toBe(2);
  });

  it("returns an empty set when the capabilities array is empty", () => {
    const caps = parseGrantCapabilities(makeGrant([]));
    expect(caps.size).toBe(0);
    expect(caps.has("file_download")).toBe(false);
  });

  it("returns false for file_download when it is absent from the grant", () => {
    const caps = parseGrantCapabilities(makeGrant(["process_list", "system_info_read"]));
    expect(caps.has("file_download")).toBe(false);
    expect(caps.has("process_list")).toBe(true);
  });

  it("returns an empty set on malformed JSON", () => {
    expect(parseGrantCapabilities("not json").size).toBe(0);
  });

  it("returns an empty set when claims is absent", () => {
    expect(parseGrantCapabilities(JSON.stringify({ sig: "abc" })).size).toBe(0);
  });

  it("returns an empty set when grant is absent from claims", () => {
    expect(
      parseGrantCapabilities(
        JSON.stringify({ claims: { issued_at_ms: 0, expires_at_ms: 0 }, sig: "abc" }),
      ).size,
    ).toBe(0);
  });

  it("returns an empty set when capabilities is not an array", () => {
    expect(parseGrantCapabilities(makeGrant("not_an_array")).size).toBe(0);
    expect(parseGrantCapabilities(makeGrant(null)).size).toBe(0);
  });

  it("silently skips non-string entries in the capabilities array", () => {
    const caps = parseGrantCapabilities(makeGrant(["file_download", 42, null, "process_list"]));
    expect(caps.has("file_download")).toBe(true);
    expect(caps.has("process_list")).toBe(true);
    expect(caps.size).toBe(2);
  });
});
