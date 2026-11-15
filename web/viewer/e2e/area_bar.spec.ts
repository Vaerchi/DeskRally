import { test, expect, type Page } from "@playwright/test";
import { openAppMenu } from "./nav";

// Menu redesign wave 10 (Ed, 2026-11-07): outside a live session the console's pages are a VISIBLE bar,
// Machines | Support | History | Manage ▾ | Admin ▾, built from the DeskRally menu's groups (lib/area_nav.ts). Machines and
// History show their pages as tabs above the content. On a phone the bar is not drawn; the menu sheet holds the groups.
// In a session the bar is not drawn at all (single_row_chrome.spec.ts asserts it), so the tab row gains nothing.
const all = (c: string) => ({ capability: c, all_groups: true, group_ids: [] });

async function mount(page: Page, capabilities?: unknown) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me" && capabilities) return route.fulfill({ json: { email: "tech@example.test", user_id: "u1", capabilities } });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/");
}

const bar = (page: Page) => page.getByTestId("area-bar");
const current = (page: Page) => bar(page).locator('[aria-current="page"], .app__areabtn--current');

test("the bar lists Machines, Support, History, Manage and Admin, and Machines is where the console opens", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await mount(page);
  await expect(bar(page).locator(".app__areabtn")).toHaveText(["Machines", "Support", "History", "Manage ▾", "Admin ▾"]);
  await expect(current(page)).toHaveText(["Machines"]);
  await expect(page.getByTestId("area-subtabs").locator("button")).toHaveText(["Live", "Machines"]);
  await expect(page.getByTestId("area-subtab-live")).toHaveAttribute("aria-current", "page");
  // The bar is plain buttons: the menu's tabs (and every test that finds a page by its tab) stay unique.
  await expect(bar(page).getByRole("tab")).toHaveCount(0);
  await expect(page.getByTestId("area-subtabs").getByRole("tab")).toHaveCount(0);
  // One row: the bar scrolls rather than wrapping, and the page never scrolls sideways.
  expect((await bar(page).boundingBox())!.height).toBeLessThanOrEqual(40);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("a direct group opens its first page and shows its pages as tabs", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await mount(page);
  await page.getByTestId("area-bar-history").click();
  await expect(current(page)).toHaveText(["History"]);
  const tabs = page.getByTestId("area-subtabs");
  await expect(tabs).toHaveAttribute("aria-label", "History pages");
  await expect(tabs.locator("button")).toHaveText(["Sessions", "Audit", "Reports"]);
  await expect(page.getByTestId("area-subtab-sessions")).toHaveAttribute("aria-current", "page");
  await page.getByTestId("area-subtab-audit").click();
  await expect(page.getByTestId("area-subtab-audit")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("area-subtab-sessions")).not.toHaveAttribute("aria-current", "page");
  // Clicking the group you are in keeps the page you are on.
  await page.getByTestId("area-bar-history").click();
  await expect(page.getByTestId("area-subtab-audit")).toHaveAttribute("aria-current", "page");
  // A one-page group has no tabs.
  await page.getByTestId("area-bar-support").click();
  await expect(current(page)).toHaveText(["Support"]);
  await expect(page.getByTestId("area-subtabs")).toHaveCount(0);
});

test("Manage and Admin are dropdowns; choosing a page closes it and marks the group", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await mount(page);
  const manage = page.getByTestId("area-bar-manage");
  await manage.click();
  const panel = page.getByRole("dialog", { name: "Manage", exact: true });
  await expect(panel.locator(".app__areaitem")).toHaveText(["Install DeskRally", "Machine groups", "Smart groups", "Sites", "Toolbox"]);
  await panel.getByTestId("area-bar-item-toolbox").click();
  await expect(panel).toBeHidden();
  await expect(manage).toHaveAttribute("aria-expanded", "false");
  await expect(current(page)).toHaveText(["Manage ▾"]);
  await expect(page.getByTestId("area-subtabs")).toHaveCount(0);
  await manage.click();
  await expect(panel.getByTestId("area-bar-item-toolbox")).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Escape");
  await page.getByTestId("area-bar-admin").click();
  await expect(page.getByRole("dialog", { name: "Admin", exact: true }).locator(".app__areaitem"))
    .toHaveText(["Users", "Roles", "Security", "API tokens", "Webhooks", "Appearance"]);
});

test("a technician's bar offers only the pages their role can use", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await mount(page, ["view_machines", "start_session", "view_sessions", "transfer_files"].map(all));
  // Wave 5's rules apply to the bar too: it is built from the same visible areas as the menu.
  await page.getByTestId("area-bar-admin").click();
  await expect(page.getByRole("dialog", { name: "Admin", exact: true }).locator(".app__areaitem")).toHaveText(["Appearance"]);
  await page.keyboard.press("Escape");
  await page.getByTestId("area-bar-manage").click();
  await expect(page.getByRole("dialog", { name: "Manage", exact: true }).getByTestId("area-bar-item-enrollment")).toHaveCount(0);
});

// Wave 10b: the bar's right end holds the bells and an Account menu, so the DeskRally menu no longer carries them here.
test("Account at the bar's right end holds who you are, My account, Help, Downloads and Sign out", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await mount(page, ["view_machines", "start_session"].map(all));
  const end = page.getByTestId("area-bar-end");
  await expect(end.getByTestId("notifications-bell")).toBeVisible();
  const account = page.getByTestId("area-bar-account");
  await expect(account).toHaveText("Account ▾");
  await account.click();
  const panel = page.getByRole("dialog", { name: "Account", exact: true });
  await expect(panel.getByTestId("app-whoami")).toHaveText("Signed in as tech@example.test");
  await expect(panel.locator(".app__areaitem")).toHaveText(["My account", "Help", "Downloads"]);
  await expect(panel.getByRole("link", { name: "Downloads", exact: true })).toHaveAttribute("href", "/downloads");
  await expect(panel.getByTestId("app-signout")).toBeVisible();
  await panel.getByTestId("area-bar-item-account").click();
  await expect(panel).toBeHidden();
  await expect(current(page)).toHaveCount(0); // My account is not a bar page: no group is marked
  // Nothing is drawn twice: the DeskRally menu holds the pages, not the account controls or the bells.
  await openAppMenu(page);
  const menu = page.getByRole("dialog", { name: "DeskRally", exact: true });
  await expect(menu.getByTestId("app-signout")).toHaveCount(0);
  await expect(menu.getByTestId("notifications-bell")).toHaveCount(0);
  await expect(menu.getByRole("link", { name: "Downloads", exact: true })).toHaveCount(0);
  await expect(page.getByTestId("app-signout")).toHaveCount(1);
  // still one row of the same height
  expect((await page.locator(".app__topbar").boundingBox())!.height).toBe(46);
});

test("on a phone the bar is not drawn and the DeskRally menu holds the same groups", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mount(page);
  await expect(bar(page)).toBeHidden();
  await expect(page.getByTestId("area-bar-end")).toHaveCount(0);
  await openAppMenu(page);
  await expect(page.getByTestId("nav-group-history")).toBeVisible();
  // ...and Sign out, which sits in the Account menu at the bar's end on a wider screen
  await expect(page.getByTestId("app-signout")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
