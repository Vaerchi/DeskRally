// Toolbox folders (decision 2026-11-24): a name's text before its last "/" is its folder ("Maintenance/Clear temp",
// "Network/DNS/Flush cache"). A display grouping only: no schema change, and the full name stays the item's identity
// (unique per scope, as today). A name without "/" sits at the top, outside any folder.

import type { ToolboxItem } from "./console_api";

export type ToolboxName = { folder: string; leaf: string };

/** Split at the LAST "/", trimming each side. An empty side (leading/trailing "/") means no folder. */
export function splitToolboxName(name: string): ToolboxName {
  const at = name.lastIndexOf("/");
  if (at < 0) return { folder: "", leaf: name.trim() };
  const folder = name.slice(0, at).split("/").map((s) => s.trim()).filter((s) => s !== "").join("/");
  const leaf = name.slice(at + 1).trim();
  if (folder === "" || leaf === "") return { folder: "", leaf: name.trim() };
  return { folder, leaf };
}

export type ToolboxFolder<T extends Pick<ToolboxItem, "name">> = { folder: string; items: T[] };

/** Unfiled items first, then folders A-Z; items A-Z by their leaf name within each group. Folder names are
 *  case-insensitive ("Zeta" and "zeta" are one folder, shown with the spelling that sorts first). */
export function groupToolboxItems<T extends Pick<ToolboxItem, "name">>(items: readonly T[]): ToolboxFolder<T>[] {
  const byFolder = new Map<string, { label: string; items: T[] }>();
  for (const it of items) {
    const { folder } = splitToolboxName(it.name);
    const key = folder.toLowerCase();
    const group = byFolder.get(key) ?? { label: folder, items: [] };
    if (folder < group.label) group.label = folder;
    group.items.push(it);
    byFolder.set(key, group);
  }
  const cmp = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" }) || (a < b ? -1 : a > b ? 1 : 0);
  return [...byFolder.entries()]
    .sort(([a], [b]) => (a === "" ? -1 : b === "" ? 1 : cmp(a, b)))
    .map(([, g]) => ({
      folder: g.label,
      items: [...g.items].sort((x, y) => cmp(splitToolboxName(x.name).leaf, splitToolboxName(y.name).leaf)),
    }));
}
