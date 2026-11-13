import { describe, expect, it } from "vitest";
import type { MachineGroup } from "./console_api";
import {
  filterGroupTree,
  groupOptions,
  groupPaths,
  groupTree,
  moveTargetRows,
  optionsFromRows,
  pathLabelFor,
  subtreeIds,
} from "./group_tree";

const g = (id: string, name: string, parent_id?: string | null): MachineGroup =>
  parent_id === undefined ? { id, name } : { id, name, parent_id };

// ASYMMETRIC fixture on purpose (no symmetric shape that passes with swapped wiring):
//   Acme (P)
//     Site A (C)
//       Lab (GC)
//     Site B (S, sibling of C)
//   Beta (R2)
const P = g("p", "Acme", null);
const C = g("c", "Site A", "p");
const GC = g("gc", "Lab", "c");
const S = g("s", "Site B", "p");
const R2 = g("r2", "Beta", null);
// Deliberately shuffled input order: the tree must not depend on it.
const ALL = [GC, R2, S, P, C];

describe("groupTree", () => {
  it("is depth-first and name-sorted, with indent level and path", () => {
    const rows = groupTree(ALL);
    expect(rows.map((r) => r.group.id)).toEqual(["p", "c", "gc", "s", "r2"]);
    expect(rows.map((r) => r.depth)).toEqual([0, 1, 2, 1, 0]);
    expect(rows.map((r) => r.path)).toEqual(["Acme", "Acme › Site A", "Acme › Site A › Lab", "Acme › Site B", "Beta"]);
    expect(rows.map((r) => r.parentId)).toEqual([null, "p", "c", "p", null]);
    expect(rows.map((r) => r.hasChildren)).toEqual([true, true, false, false, false]);
    expect(rows[2].ancestorIds).toEqual(["p", "c"]);
  });

  it("treats a group whose parent is NOT in the list as top level (a hidden ancestor never leaks)", () => {
    // A technician scoped to Site A sees Site A and Lab; the server sends parent_id null for Site A, but even if
    // an older/other response still carried "p", the path must not invent the missing ancestor.
    const rows = groupTree([g("c", "Site A", "p"), GC]);
    expect(rows.map((r) => [r.group.id, r.depth, r.path])).toEqual([
      ["c", 0, "Site A"],
      ["gc", 1, "Site A › Lab"],
    ]);
    expect(rows[0].parentId).toBeNull();
  });

  it("sorts a hidden-parent group among the roots by NAME (not rescued last as an orphan)", () => {
    const rows = groupTree([g("z", "Zeta", null), g("h", "Aardvark", "not-visible"), g("m", "Mid", null)]);
    expect(rows.map((r) => r.group.name)).toEqual(["Aardvark", "Mid", "Zeta"]);
    expect(rows.every((r) => r.depth === 0 && r.parentId === null)).toBe(true);
  });

  it("works on an older server's flat list (parent_id absent)", () => {
    const rows = groupTree([g("b", "Beta"), g("a", "Alpha")]);
    expect(rows.map((r) => [r.group.name, r.depth, r.path])).toEqual([
      ["Alpha", 0, "Alpha"],
      ["Beta", 0, "Beta"],
    ]);
  });

  it("is cycle-safe on bad data: every group appears exactly once and nothing loops", () => {
    // A <-> B cycle, a self-parent, and a descendant hanging off the cycle.
    const bad = [g("a", "A", "b"), g("b", "B", "a"), g("self", "Self", "self"), g("d", "D", "b")];
    const rows = groupTree(bad);
    expect(rows.map((r) => r.group.id).sort()).toEqual(["a", "b", "d", "self"]);
    expect(new Set(rows.map((r) => r.group.id)).size).toBe(4);
    // The self-parent is a root; the cycle is broken at its alphabetically-first member.
    expect(rows.find((r) => r.group.id === "self")!.depth).toBe(0);
    expect(rows.find((r) => r.group.id === "a")!.depth).toBe(0);
  });

  it("sorts a self-parent group among the roots by NAME (the self-parent guard, not the cycle rescue)", () => {
    const rows = groupTree([g("z", "Zeta", null), g("self", "Aardvark", "self"), g("m", "Mid", null)]);
    expect(rows.map((r) => r.group.name)).toEqual(["Aardvark", "Mid", "Zeta"]);
  });

  it("keeps the first of a duplicated id", () => {
    const rows = groupTree([g("x", "First"), g("x", "Second")]);
    expect(rows).toHaveLength(1);
    expect(rows[0].group.name).toBe("First");
  });

  it("survives a very deep chain without recursion limits", () => {
    const chain: MachineGroup[] = [];
    for (let i = 0; i < 5000; i++) chain.push(g(`n${i}`, `N${i}`, i === 0 ? null : `n${i - 1}`));
    const rows = groupTree(chain);
    expect(rows).toHaveLength(5000);
    expect(rows[4999].depth).toBe(4999);
  });
});

describe("groupPaths / pathLabelFor", () => {
  it("never merges equal names: same name under different parents gets different paths", () => {
    const groups = [g("p1", "East", null), g("p2", "West", null), g("l1", "Lab", "p1"), g("l2", "Lab", "p2")];
    const paths = groupPaths(groups);
    expect(paths.get("l1")).toBe("East › Lab");
    expect(paths.get("l2")).toBe("West › Lab");
  });

  it("adds a short id suffix only when two groups would carry the SAME path", () => {
    const groups = [
      g("11111111-aaaa", "Lab", null),
      g("22222222-bbbb", "Lab", null),
      g("33333333-cccc", "Unique", null),
    ];
    const paths = groupPaths(groups);
    expect(paths.get("11111111-aaaa")).toBe("Lab [11111111]");
    expect(paths.get("22222222-bbbb")).toBe("Lab [22222222]");
    expect(paths.get("33333333-cccc")).toBe("Unique");
  });

  it("falls back to the joined name, then the raw id, for a group outside the list", () => {
    const paths = groupPaths([P]);
    expect(pathLabelFor(paths, "p")).toBe("Acme");
    expect(pathLabelFor(paths, "gone", "Joined Name")).toBe("Joined Name");
    expect(pathLabelFor(paths, "gone")).toBe("gone");
  });
});

describe("groupOptions (the picker model)", () => {
  it("lists path labels in tree order with depth", () => {
    expect(groupOptions(ALL).map((o) => [o.id, o.label, o.depth])).toEqual([
      ["p", "Acme", 0],
      ["c", "Acme › Site A", 1],
      ["gc", "Acme › Site A › Lab", 2],
      ["s", "Acme › Site B", 1],
      ["r2", "Beta", 0],
    ]);
  });
});

describe("subtreeIds / moveTargetRows (the Move… parent picker)", () => {
  it("subtree is the group plus every descendant, never a sibling or ancestor", () => {
    expect([...subtreeIds(ALL, "c")].sort()).toEqual(["c", "gc"]);
    expect([...subtreeIds(ALL, "p")].sort()).toEqual(["c", "gc", "p", "s"]);
    expect([...subtreeIds(ALL, "s")]).toEqual(["s"]);
    expect([...subtreeIds(ALL, "unknown")]).toEqual(["unknown"]);
  });

  it("excludes the group's own subtree and keeps its ancestors, siblings and unrelated groups", () => {
    expect(moveTargetRows(ALL, "c").map((r) => r.group.id)).toEqual(["p", "s", "r2"]);
    expect(moveTargetRows(ALL, "p").map((r) => r.group.id)).toEqual(["r2"]);
    expect(moveTargetRows(ALL, "gc").map((r) => r.group.id)).toEqual(["p", "c", "s", "r2"]);
  });

  it("keeps path labels computed against the full tree after pruning", () => {
    const labels = optionsFromRows(moveTargetRows(ALL, "c")).map((o) => o.label);
    expect(labels).toEqual(["Acme", "Acme › Site B", "Beta"]);
  });

  it("is cycle-safe on bad data", () => {
    const bad = [g("a", "A", "b"), g("b", "B", "a")];
    expect(subtreeIds(bad, "a").has("a")).toBe(true);
    expect(moveTargetRows(bad, "a").every((r) => r.group.id !== "a")).toBe(true);
  });
});

describe("filterGroupTree (keeps ancestors of matches)", () => {
  const rows = groupTree(ALL);

  it("returns every row, matched, for an empty or blank query", () => {
    expect(filterGroupTree(rows, "").map((r) => r.group.id)).toEqual(["p", "c", "gc", "s", "r2"]);
    expect(filterGroupTree(rows, "   ").every((r) => r.matched)).toBe(true);
  });

  it("keeps the ancestors of a deep match, flagged as not matched themselves", () => {
    const out = filterGroupTree(rows, "lab");
    expect(out.map((r) => [r.group.id, r.matched])).toEqual([
      ["p", false],
      ["c", false],
      ["gc", true],
    ]);
  });

  it("does not drag in siblings or descendants of a mid-tree match", () => {
    const out = filterGroupTree(rows, "site b");
    expect(out.map((r) => r.group.id)).toEqual(["p", "s"]);
    // A match on a parent does not keep its (non-matching) children.
    expect(filterGroupTree(rows, "site a").map((r) => r.group.id)).toEqual(["p", "c"]);
  });

  it("matches the group id too, and returns nothing for no match", () => {
    expect(filterGroupTree(rows, "R2").map((r) => r.group.id)).toEqual(["r2"]);
    expect(filterGroupTree(rows, "zzz")).toEqual([]);
  });

  it("keeps a hidden-ancestor root as the top of its own subtree", () => {
    const partial = groupTree([C, GC]);
    expect(filterGroupTree(partial, "lab").map((r) => r.group.id)).toEqual(["c", "gc"]);
  });
});
