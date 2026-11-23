/**
 * The ONE shared tree helper for nested machine groups (docs/62 §4). Every place that lists or picks a
 * group — the Groups panel, machine move / bulk move, enrollment, attended, the users scope picker, the
 * session-policy editor, the machine list's headings — goes through here, so a name that appears twice
 * can never merge two groups and every picker orders and labels groups the same way.
 *
 * Built ONLY from the groups the caller was given (docs/62 D6/R9): a technician scoped to a child does
 * not see the ancestors, and the server returns `parent_id: null` for a parent the caller cannot see. A
 * group whose `parent_id` names a group that is not in the list is therefore a ROOT here, never an
 * orphan, and its path starts at its own name. Nothing in this file asks the server for a hidden group.
 *
 * Pure and defensive about its input: the data crosses a network boundary and a bad row (a self-parent,
 * a two-group cycle, a duplicated id) must never hang the console in a loop or drop a group from view.
 */

import type { MachineGroup } from "./console_api";

/** Separator in a path label: "Acme › Site A › Lab". */
export const PATH_SEPARATOR = " › ";

/** One group in depth-first order, with what a renderer needs to draw it as a tree row. */
export interface GroupTreeRow {
  group: MachineGroup;
  /** Indent level: 0 for a root (or a group whose parent is not visible), 1 for its child, ... */
  depth: number;
  /** The VISIBLE parent's id, or null for a root. May differ from `group.parent_id` (hidden parent, bad data). */
  parentId: string | null;
  /** Full path label built from visible ancestors only: "A › B › C". */
  path: string;
  /** Names of the visible ancestors from the root down to (not including) this group. */
  ancestors: readonly string[];
  /** Ids of the visible ancestors from the root down to (not including) this group. */
  ancestorIds: readonly string[];
  /** Whether at least one visible group is a child of this one. */
  hasChildren: boolean;
}

const byNameThenId = (a: MachineGroup, b: MachineGroup): number =>
  a.name.localeCompare(b.name) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/**
 * Depth-first, name-sorted tree rows for `groups`.
 *
 * - Siblings sort by name (then id, so two equal names have a stable order).
 * - A group whose parent is absent from the list, is itself, or sits in a cycle renders as a root.
 * - A duplicated id keeps its FIRST occurrence (a row key can only be unique once).
 * - Every group in the input appears exactly once in the output, whatever the data looks like.
 */
export function groupTree(groups: readonly MachineGroup[]): GroupTreeRow[] {
  const byId = new Map<string, MachineGroup>();
  for (const g of groups) if (!byId.has(g.id)) byId.set(g.id, g);

  const visibleParent = (g: MachineGroup): string | null => {
    const p = g.parent_id;
    return typeof p === "string" && p !== g.id && byId.has(p) ? p : null;
  };

  const children = new Map<string, MachineGroup[]>();
  const roots: MachineGroup[] = [];
  for (const g of byId.values()) {
    const p = visibleParent(g);
    if (p === null) roots.push(g);
    else (children.get(p) ?? children.set(p, []).get(p)!).push(g);
  }

  const rows: GroupTreeRow[] = [];
  const seen = new Set<string>();

  const walk = (root: MachineGroup, rootParent: string | null): void => {
    // Iterative so a pathological (deep) chain cannot overflow the stack; `seen` makes a cycle terminate.
    const stack: { g: MachineGroup; depth: number; names: string[]; ids: string[]; parentId: string | null }[] = [
      { g: root, depth: 0, names: [], ids: [], parentId: rootParent },
    ];
    while (stack.length > 0) {
      const { g, depth, names, ids, parentId } = stack.pop()!;
      if (seen.has(g.id)) continue;
      seen.add(g.id);
      const kids = (children.get(g.id) ?? []).filter((k) => !seen.has(k.id)).sort(byNameThenId);
      rows.push({
        group: g,
        depth,
        parentId,
        path: [...names, g.name].join(PATH_SEPARATOR),
        ancestors: names,
        ancestorIds: ids,
        hasChildren: kids.length > 0,
      });
      // Push in reverse so the alphabetically-first child is popped (rendered) first.
      for (let i = kids.length - 1; i >= 0; i--) {
        stack.push({ g: kids[i], depth: depth + 1, names: [...names, g.name], ids: [...ids, g.id], parentId: g.id });
      }
    }
  };

  for (const r of roots.sort(byNameThenId)) walk(r, null);
  // Whatever is left is only reachable through a cycle (A -> B -> A): no root leads to it. Break the cycle
  // deterministically by treating the first leftover (in name order) as a root, then continue.
  for (const g of [...byId.values()].sort(byNameThenId)) {
    if (!seen.has(g.id)) walk(g, null);
  }
  return rows;
}

/**
 * Path label per group id, e.g. `Map { id -> "Acme › Site A › Lab" }`. When two groups would carry the
 * SAME label (equal names under the same parent, or two roots with one name) the label gets a short id
 * suffix — "Lab [1a2b3c4d]" — so a picker never shows two indistinguishable options.
 */
export function groupPaths(groups: readonly MachineGroup[]): Map<string, string> {
  return pathsFromRows(groupTree(groups));
}

/** {@link groupPaths} for rows already built. */
export function pathsFromRows(rows: readonly GroupTreeRow[]): Map<string, string> {
  const count = new Map<string, number>();
  for (const r of rows) count.set(r.path, (count.get(r.path) ?? 0) + 1);
  const out = new Map<string, string>();
  for (const r of rows) {
    out.set(r.group.id, (count.get(r.path) ?? 0) > 1 ? `${r.path} [${r.group.id.slice(0, 8)}]` : r.path);
  }
  return out;
}

/**
 * The label for one group id: its path, else the server's joined name, else the raw id. The fallbacks are
 * for a group outside the caller's visible list (a machine record names it, the list does not), so a cell
 * is never blank.
 */
export function pathLabelFor(paths: ReadonlyMap<string, string>, id: string, joinedName?: string): string {
  return paths.get(id) || joinedName || id;
}

/** One entry of a group picker: value, display label (the path) and indent level. */
export interface GroupOption {
  id: string;
  /** Path label, disambiguated. The text of an `<option>` or a checkbox label. */
  label: string;
  depth: number;
}

/** Picker entries for `groups` in tree order. */
export function groupOptions(groups: readonly MachineGroup[]): GroupOption[] {
  return optionsFromRows(groupTree(groups));
}

/** {@link groupOptions} for rows already built (and possibly pruned, see {@link moveTargetRows}). */
export function optionsFromRows(rows: readonly GroupTreeRow[]): GroupOption[] {
  const paths = pathsFromRows(rows);
  return rows.map((r) => ({ id: r.group.id, label: paths.get(r.group.id) ?? r.path, depth: r.depth }));
}

/** `id` and every visible descendant of it. Cycle-safe; unknown id yields just `{id}`. */
export function subtreeIds(groups: readonly MachineGroup[], id: string): Set<string> {
  const rows = groupTree(groups);
  const out = new Set<string>([id]);
  // Rows are depth-first, so one pass in order sees an ancestor before its descendants.
  for (const r of rows) {
    if (r.group.id === id || r.ancestorIds.includes(id)) out.add(r.group.id);
  }
  return out;
}

/**
 * The legal new parents for `groupId` in the Move picker: every visible group EXCEPT the group itself and
 * its own subtree (moving a group under itself or a descendant is a cycle). The caller adds the
 * "Top level" choice. The server stays the authority (cycle, depth cap, authorization -> 409/403).
 */
export function moveTargetRows(groups: readonly MachineGroup[], groupId: string): GroupTreeRow[] {
  const banned = subtreeIds(groups, groupId);
  return groupTree(groups).filter((r) => !banned.has(r.group.id));
}

/** A tree row plus whether it matched the filter itself (false = shown only as the ancestor of a match). */
export interface FilteredGroupRow extends GroupTreeRow {
  matched: boolean;
}

/**
 * Text filter for the tree that KEEPS THE ANCESTORS of every match, so a hit is never shown floating
 * without its parents. Matches name or id, case-insensitive. An empty query returns every row, matched.
 */
export function filterGroupTree(rows: readonly GroupTreeRow[], query: string): FilteredGroupRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows.map((r) => ({ ...r, matched: true }));
  const match = (r: GroupTreeRow) => r.group.name.toLowerCase().includes(q) || r.group.id.toLowerCase().includes(q);
  const keep = new Set<string>();
  const matched = new Set<string>();
  for (const r of rows) {
    if (!match(r)) continue;
    matched.add(r.group.id);
    keep.add(r.group.id);
    for (const a of r.ancestorIds) keep.add(a);
  }
  return rows.filter((r) => keep.has(r.group.id)).map((r) => ({ ...r, matched: matched.has(r.group.id) }));
}
