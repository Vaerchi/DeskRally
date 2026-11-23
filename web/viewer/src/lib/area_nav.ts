/**
 * Menu redesign wave 10 (the operator's decision of 2026-11-07): outside a live session the console shows a VISIBLE top bar,
 * Machines | Support | History | Manage ▾ | Admin ▾ (and Platform for an operator), built from the same groups the
 * DeskRally menu uses. This is the pure model of that bar; App.tsx draws it.
 *
 * - A DIRECT group is one button. It opens the group's first page, and when the group has more than one page, the
 *   pages are shown as a row of sibling tabs above the content (History: Sessions | Recordings | Audit | Reports).
 * - A MENU group (Manage, Admin) is a dropdown listing its pages.
 * - Groups not listed here (Account: My account, Help) are not page buttons: App.tsx puts them in the Account menu at
 *   the bar's right end (wave 10b), and they stay in the DeskRally menu too.
 *
 * Only the areas passed in are used, so a page the role cannot use (wave 5) is never offered, and a group with no
 * visible page is left out entirely.
 */
export const BAR_GROUPS = [
  { group: "Machines", kind: "direct" },
  { group: "Support", kind: "direct" },
  { group: "History", kind: "direct" },
  { group: "Manage", kind: "menu" },
  { group: "Admin", kind: "menu" },
  { group: "Platform", kind: "direct" },
] as const;

export interface AreaLike {
  id: string;
  label: string;
  group: string;
}

export type BarItem<A extends AreaLike> =
  | { kind: "direct"; group: string; target: A; current: boolean }
  | { kind: "menu"; group: string; items: A[]; current: boolean };

export function areaBarItems<A extends AreaLike>(areas: readonly A[], active: string): BarItem<A>[] {
  const out: BarItem<A>[] = [];
  for (const { group, kind } of BAR_GROUPS) {
    const inGroup = areas.filter((a) => a.group === group);
    if (inGroup.length === 0) continue;
    const current = inGroup.some((a) => a.id === active);
    out.push(kind === "direct" ? { kind, group, target: inGroup[0], current } : { kind, group, items: inGroup, current });
  }
  return out;
}

/**
 * The sibling pages to show as tabs for the active page: its group's pages, when the group is a direct one with more
 * than one page. Null otherwise (a menu group's pages are in its dropdown; a one-page group needs no tabs).
 */
export function areaSubtabs<A extends AreaLike>(areas: readonly A[], active: string): { group: string; pages: A[] } | null {
  const here = areas.find((a) => a.id === active);
  if (!here) return null;
  const spec = BAR_GROUPS.find((g) => g.group === here.group);
  if (!spec || spec.kind !== "direct") return null;
  const pages = areas.filter((a) => a.group === here.group);
  return pages.length > 1 ? { group: here.group, pages } : null;
}
