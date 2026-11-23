import { test, expect, type Page } from "@playwright/test";
import { openAppMenu } from "./nav";

// Menu redesign wave 5: the DeskRally menu offers only the areas the user's capabilities allow (lib/area_visibility.ts). A
// technician was shown Users, Roles, API tokens, Webhooks, Security, Appearance and Install DeskRally, which all answered 403.
// Unknown capabilities (an older server without the list) hide nothing.
const all = (c: string) => ({ capability: c, all_groups: true, group_ids: [] });

async function mount(page: Page, capabilities: unknown) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") return route.fulfill({ json: { email: "tech@example.test", user_id: "u1", capabilities } });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/");
  await openAppMenu(page);
}

test("a technician's menu leaves out administration and keeps the work", async ({ page }) => {
  await mount(page, ["view_machines", "start_session", "view_sessions", "transfer_files"].map(all));
  // Wait until /me has applied (the menu shows everything while capabilities are unknown).
  await expect(page.getByRole("tab", { name: "Users", exact: true })).toHaveCount(0);
  for (const name of ["Roles", "Security", "API tokens", "Webhooks", "Install DeskRally", "Audit"]) {
    await expect(page.getByRole("tab", { name, exact: true }), name).toHaveCount(0);
  }
  // The Admin group keeps only the read-only Appearance page for them.
  await expect(page.getByTestId("nav-group-admin").getByRole("tab")).toHaveText(["Appearance"]);
  // Appearance stays: every member reads the branding, read-only (tenant_public_join.spec "a member sees the section read-only").
  for (const name of ["Live", "Machines", "Support", "Sessions", "Reports", "Toolbox", "Appearance", "My account", "Help"]) {
    await expect(page.getByRole("tab", { name, exact: true }), name).toBeVisible();
  }
});

test("an owner's menu has every area, and a server without the capability list hides nothing", async ({ page }) => {
  await mount(page, ["view_machines", "start_session", "view_sessions", "view_audit", "manage_users", "manage_roles",
    "manage_tenant", "manage_enrollment", "manage_toolbox"].map(all));
  for (const name of ["Users", "Roles", "Security", "API tokens", "Webhooks", "Appearance", "Install DeskRally", "Audit"]) {
    await expect(page.getByRole("tab", { name, exact: true }), name).toBeVisible();
  }
});

test("an older server that sends no capability list hides nothing", async ({ page }) => {
  await mount(page, undefined);
  for (const name of ["Users", "Roles", "Security", "Install DeskRally"]) {
    await expect(page.getByRole("tab", { name, exact: true }), name).toBeVisible();
  }
});
