import type { MachineGroup } from "./console_api";
import { groupPaths } from "./group_tree";

/**
 * Display + encoding helpers for a user's machine-group scope (docs/55 Phase 2). Pure, so the
 * UsersPanel's scope display and invite encoding are unit-tested without rendering (the viewer's
 * component-test convention — no @testing-library).
 */

/** Suffix on every group named in a scope: a scope on a group covers its subgroups too (docs/62 D3). */
export const SUBGROUPS_SUFFIX = " (and subgroups)";

/**
 * A human label for a user's effective group scope. An empty/absent scope is tenant-wide, shown as
 * "All groups". A non-empty scope lists the group PATHS ("Acme › Site A", from the groups list, so two
 * groups with one name stay distinct), each followed by "(and subgroups)" because access is inherited
 * downward. A group that no longer exists (a since-deleted group a membership still names — a safe
 * dangling deny, shown so the operator can see it) falls back to the raw id with NO suffix, since it covers
 * nothing. Sorted and comma-joined.
 */
export function scopeLabel(scopedGroupIDs: readonly string[] | undefined, groups: readonly MachineGroup[]): string {
  const ids = scopedGroupIDs ?? [];
  if (ids.length === 0) return "All groups";
  const paths = groupPaths(groups);
  return ids
    .map((id) => {
      const p = paths.get(id);
      return p === undefined ? id : `${p}${SUBGROUPS_SUFFIX}`;
    })
    .sort((a, b) => a.localeCompare(b))
    .join(", ");
}

/**
 * Toggle a group id in a selection (for the invite form's multi-select), returning a new array. Kept
 * pure and order-stable (append on add, filter on remove) so the control is a plain controlled input.
 */
export function toggleGroup(selected: readonly string[], id: string): string[] {
  return selected.includes(id) ? selected.filter((g) => g !== id) : [...selected, id];
}
