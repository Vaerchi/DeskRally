import { test, expect } from "@playwright/test";
import { openAppMenu } from "./nav";

// Menu redesign wave 4 (the operator's structure, 2026-11-07): the DeskRally menu lists the console areas in labelled groups, in the order
// Machines, Support, History, Manage, Admin, Account. It was one flat 21-item grid. Each group is its own tablist, named for the
// group, so a screen reader announces where a page lives.
const EXPECTED: [string, string[]][] = [
  ["machines", ["Live", "Machines"]],
  ["support", ["Support"]],
  ["history", ["Sessions", "Audit", "Reports"]],
  ["manage", ["Install DeskRally", "Machine groups", "Smart groups", "Sites", "Toolbox"]],
  ["admin", ["Users", "Roles", "Security", "API tokens", "Webhooks", "Appearance"]],
  ["account", ["My account", "Help"]],
];

test("the DeskRally menu groups its pages: Machines, Support, History, Manage, Admin, Account", async ({ page }) => {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/");
  await openAppMenu(page);

  const groups = page.locator(".app__navgroup");
  // The groups in order (Platform is operator-only and Recordings needs a permission; neither applies here).
  await expect(groups).toHaveCount(EXPECTED.length);
  for (const [i, [key, tabs]] of EXPECTED.entries()) {
    const g = groups.nth(i);
    await expect(g).toHaveAttribute("data-testid", `nav-group-${key}`);
    await expect(g.getByRole("tab")).toHaveText(tabs);
  }
  // Each group is a named tablist, and its heading is not itself a tab.
  await expect(page.getByRole("tablist", { name: "Admin" }).getByRole("tab", { name: "Users", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Admin", exact: true })).toHaveCount(0);
});
