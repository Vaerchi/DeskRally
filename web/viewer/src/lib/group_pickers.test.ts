/**
 * docs/62 §4 — every group picker and group label goes through the ONE tree helper, so equal names never
 * merge. The viewer's unit convention has no DOM, so this pins (a) the pure label/bucket functions the
 * pickers are built from, and (b) with a source guard that each picker panel really uses the helper and
 * does not render a bare `group.name` option any more. The browser behaviour is e2e/subgroups.spec.ts.
 */
import { describe, expect, it } from "vitest";
import type { MachineGroup, MachineListing, MachineRecord } from "./console_api";
import { groupLabel, groupNameFor } from "./console_panels";
import { bucketMachinesByGroup, machineFromRecord, machinesFromRecords } from "../components/AccessPanel";
import { groupOptions } from "./group_tree";
import machinesPanel from "../components/MachinesPanel.tsx?raw";
import enrollmentPanel from "../components/EnrollmentTokensPanel.tsx?raw";
import attendedPanel from "../components/AttendedPanel.tsx?raw";
import usersPanel from "../components/UsersPanel.tsx?raw";
import groupsPanel from "../components/MachineGroupsPanel.tsx?raw";

const g = (id: string, name: string, parent_id: string | null = null): MachineGroup => ({ id, name, parent_id });

// Two groups called "Lab" under DIFFERENT parents, one distinct group, asymmetric on purpose.
const GROUPS = [g("east", "East"), g("west", "West"), g("lab-e", "Lab", "east"), g("lab-w", "Lab", "west"), g("solo", "Solo")];

describe("labels shown in tables use the path, not the bare name", () => {
  it("groupNameFor (enrollment tokens) and groupLabel (machine cell) disambiguate equal names", () => {
    expect(groupNameFor(GROUPS, "lab-e")).toBe("East › Lab");
    expect(groupNameFor(GROUPS, "lab-w")).toBe("West › Lab");
    expect(groupLabel(GROUPS, "lab-w", "Lab")).toBe("West › Lab");
    // A group outside the visible list still falls back to the server's joined name, then the id.
    expect(groupLabel(GROUPS, "hidden", "Joined")).toBe("Joined");
    expect(groupNameFor(GROUPS, "hidden")).toBe("hidden");
  });

  it("a picker built from the groups offers two distinct, path-labelled Lab options", () => {
    const labs = groupOptions(GROUPS).filter((o) => o.label.endsWith("Lab"));
    expect(labs.map((o) => [o.id, o.label])).toEqual([
      ["lab-e", "East › Lab"],
      ["lab-w", "West › Lab"],
    ]);
  });
});

describe("AccessPanel buckets by group ID / path, never by name", () => {
  const rec = (id: string, group_id: string, group_name: string): MachineRecord => ({
    id,
    tenant_id: "t",
    device_id: `${id}-dev`,
    group_id,
    name: id.toUpperCase(),
    os: "Windows",
    group_name,
    online: true,
  });
  const listing: MachineListing = {
    presenceKnown: true,
    machines: [rec("m1", "lab-e", "Lab"), rec("m2", "lab-w", "Lab"), rec("m3", "lab-e", "Lab")],
  };

  it("maps the heading to the path when the group list is available", () => {
    const ms = machinesFromRecords(listing, undefined, GROUPS);
    expect(ms.map((m) => m.group)).toEqual(["East › Lab", "West › Lab", "East › Lab"]);
    expect(ms.map((m) => m.groupId)).toEqual(["lab-e", "lab-w", "lab-e"]);
  });

  it("without a group list the heading stays the joined name (older server / failed group read)", () => {
    expect(machinesFromRecords(listing).map((m) => m.group)).toEqual(["Lab", "Lab", "Lab"]);
    expect(machineFromRecord(rec("m1", "lab-e", "Lab"), true).group).toBe("Lab");
  });

  it("two groups sharing a NAME stay two sections", () => {
    // Even with the bare joined name as the heading (no group list), the sections must not merge.
    const sections = bucketMachinesByGroup(machinesFromRecords(listing));
    expect(sections).toHaveLength(2);
    expect(sections.map(([, , list]) => list.length).sort()).toEqual([1, 2]);
    // With paths the headings differ too.
    const withPaths = bucketMachinesByGroup(machinesFromRecords(listing, undefined, GROUPS));
    expect(withPaths.map(([, heading]) => heading)).toEqual(["East › Lab", "West › Lab"]);
  });

  it("a hand-built machine with no groupId still buckets by its heading", () => {
    const base = machineFromRecord(rec("m1", "x", "Same"), true);
    const a = { ...base, groupId: undefined };
    const b = { ...base, groupId: undefined, name: "OTHER" };
    expect(bucketMachinesByGroup([a, b])).toHaveLength(1);
  });
});

describe("every picker panel uses the shared tree helper", () => {
  // Needles are assembled so this file can never satisfy its own search.
  const HELPER = "group" + "Options(";
  const BARE_NAME_OPTION = /<option[^>]*>\s*\{(?:g|group)\.name\}/;

  for (const [name, src] of [
    ["MachinesPanel (move + bulk move)", machinesPanel],
    ["EnrollmentTokensPanel", enrollmentPanel],
    ["AttendedPanel", attendedPanel],
    ["UsersPanel (scope picker)", usersPanel],
    ["MachineGroupsPanel (parent + move pickers)", groupsPanel],
  ] as const) {
    it(`${name} builds its options from the tree helper and renders no bare group.name option`, () => {
      expect(src.includes(HELPER) || src.includes("moveTarget" + "Rows(")).toBe(true);
      expect(BARE_NAME_OPTION.test(src)).toBe(false);
    });
  }
});
