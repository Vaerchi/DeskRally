import { describe, expect, it } from "vitest";
import type { DynamicGroup, DynamicGroupCondition } from "./console_api";
import { summarizeDynamicGroup, validateDynamicGroup } from "./dynamic_groups";

const legacy: DynamicGroup = { id: "group-1", name: "HQ", property_key: "site", property_value: "HQ" };
const site: DynamicGroupCondition = { field: "property:site", op: "equals", value: "HQ" };
const os: DynamicGroupCondition = { field: "os", op: "contains", value: "11" };

describe("summarizeDynamicGroup", () => {
  it("joins conditions using the group's match mode", () => {
    const group = { ...legacy, conditions: [site, os] };
    expect(summarizeDynamicGroup({ ...group, match: "all" })).toBe("site = HQ AND os contains 11");
    expect(summarizeDynamicGroup({ ...group, match: "any" })).toBe("site = HQ OR os contains 11");
  });

  it("renders legacy conditions and distinguishes empty values from existence", () => {
    expect(summarizeDynamicGroup(legacy)).toBe("site = HQ");
    expect(summarizeDynamicGroup({ ...legacy, property_value: "" })).toBe("site exists");
    expect(summarizeDynamicGroup({ ...legacy, conditions: [{ ...site, value: "" }] })).toBe('site = ""');
    expect(summarizeDynamicGroup({
      ...legacy,
      conditions: [{ ...site, op: "not_exists", value: "" }],
    })).toBe("site does not exist");
  });
});

describe("validateDynamicGroup", () => {
  it("accepts compound, existence, online and version conditions", () => {
    expect(validateDynamicGroup("HQ", "any", [
      site, os, { field: "property:retired", op: "not_exists", value: "" },
      { field: "online", op: "equals", value: "false" },
      { field: "agent_version", op: "version_at_least", value: "0.1.34+abc" },
    ])).toBeNull();
  });

  it("enforces row and byte limits", () => {
    expect(validateDynamicGroup("HQ", "all", Array.from({ length: 10 }, () => site))).toBeNull();
    expect(validateDynamicGroup("HQ", "all", Array.from({ length: 11 }, () => site))).toContain("1 to 10");
    expect(validateDynamicGroup("HQ", "all", [])).toContain("1 to 10");
    expect(validateDynamicGroup("HQ", "all", [{ ...site, value: "é".repeat(2049) }])).toContain("4096 bytes");
  });

  it("reports invalid fields, operators and values by row", () => {
    expect(validateDynamicGroup("HQ", "any", [site, { ...os, field: "machine" }])).toContain("Condition 2: unknown field");
    expect(validateDynamicGroup("HQ", "all", [{ ...site, field: "property:" }])).toContain("property key");
    expect(validateDynamicGroup("HQ", "all", [{ ...os, field: "online" }])).toContain("invalid operator");
    expect(validateDynamicGroup("HQ", "all", [{ field: "online", op: "equals", value: "up" }])).toContain("true or false");
    expect(validateDynamicGroup("HQ", "all", [{ ...site, op: "exists" }])).toContain("leave the value empty");
    expect(validateDynamicGroup("HQ", "all", [
      { field: "agent_version", op: "version_at_least", value: "1.3.9-rc" },
    ])).toContain("dotted numeric version");
  });
});
