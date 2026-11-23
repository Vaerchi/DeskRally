import { describe, expect, it } from "vitest";
import type { MachineGroup } from "./console_api";
import { scopeLabel, toggleGroup } from "./user_scope";

const GROUPS: MachineGroup[] = [
  { id: "g1", name: "HQ" },
  { id: "g2", name: "Branch" },
];

describe("scopeLabel", () => {
  it("renders an empty or absent scope as all groups", () => {
    expect(scopeLabel([], GROUPS)).toBe("All groups");
    expect(scopeLabel(undefined, GROUPS)).toBe("All groups");
  });

  it("resolves ids to group names with the subgroups suffix, sorted", () => {
    expect(scopeLabel(["g2", "g1"], GROUPS)).toBe("Branch (and subgroups), HQ (and subgroups)");
    expect(scopeLabel(["g1"], GROUPS)).toBe("HQ (and subgroups)");
  });

  it("falls back to the raw id, with NO suffix, for a since-deleted group (covers nothing, still shown)", () => {
    // Sorted case-insensitively by localeCompare: "gone" precedes "HQ (and subgroups)".
    expect(scopeLabel(["g1", "gone"], GROUPS)).toBe("gone, HQ (and subgroups)");
  });

  it("uses the PATH for a nested group, so equal names are distinguishable", () => {
    const nested: MachineGroup[] = [
      { id: "p", name: "Acme", parent_id: null },
      { id: "c", name: "Site A", parent_id: "p" },
      { id: "s", name: "Site A", parent_id: "q" },
      { id: "q", name: "Other", parent_id: null },
    ];
    expect(scopeLabel(["c"], nested)).toBe("Acme › Site A (and subgroups)");
    expect(scopeLabel(["s"], nested)).toBe("Other › Site A (and subgroups)");
    // A scope on a child whose parent the caller cannot see renders from the child.
    expect(scopeLabel(["c"], [{ id: "c", name: "Site A", parent_id: "p" }])).toBe("Site A (and subgroups)");
  });
});

describe("toggleGroup", () => {
  it("adds when absent, removes when present, and is immutable", () => {
    const start: string[] = ["a"];
    expect(toggleGroup(start, "b")).toEqual(["a", "b"]);
    expect(toggleGroup(start, "a")).toEqual([]);
    expect(start).toEqual(["a"]); // unchanged
  });
});
