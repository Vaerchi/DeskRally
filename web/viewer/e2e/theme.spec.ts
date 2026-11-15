/**
 * Light theme and reduced motion (lib/theme.ts, the token blocks at the top of src/index.css).
 *
 * Behaviour specs: the preference control, persistence, "System" following the OS, the remote
 * picture surround staying black, the guest pages staying paper, reduced motion. Plus a screenshot
 * matrix (light and dark, desktop and phone) that is written ONLY when LT_SHOTS names a directory,
 * so the ordinary gate never produces files.
 */
import { test, expect, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { connect } from "./fake_session";
import { openAppMenu } from "./nav";

const DEVICE = "2b948dba-5566-4778-8990-aabbccddeeff";
const MACHINES = [
  { id: "pk-1", tenant_id: "t-1", device_id: DEVICE, group_id: "g-1", group_name: "Home Computers", name: "Front Desk PC", os: "Windows 11", online: true, multi_session_capable: true },
  { id: "pk-2", tenant_id: "t-1", device_id: "3c948dba-5566-4778-8990-aabbccddeeff", group_id: "g-1", group_name: "Home Computers", name: "Back Office Laptop", os: "Windows 10", online: false, multi_session_capable: false },
  { id: "pk-3", tenant_id: "t-1", device_id: "4d948dba-5566-4778-8990-aabbccddeeff", group_id: "g-2", group_name: "Workshop", name: "Lathe Controller", os: "Windows 11", online: true, multi_session_capable: false },
];
const LIVE = { id: "live-1", tenant_id: "t-1", machine_id: "pk-1", machine_device_id: DEVICE, technician_id: "ed@example.test", started_at: "2026-10-19T10:00:00Z" };

async function routeCp(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") await route.fulfill({ status: 204 });
    else if (path === "/cp/machines") await route.fulfill({ json: { machines: MACHINES, presence_known: true } });
    else if (path === "/cp/sessions") await route.fulfill({ json: { sessions: [LIVE] } });
    else await route.fulfill({ json: {} });
  });
}
const bg = (page: Page, sel = "body") => page.locator(sel).first().evaluate((el) => getComputedStyle(el).backgroundColor);
const LIGHT_BG = "rgb(246, 248, 250)";
const DARK_BG = "rgb(14, 17, 22)";

test.describe("theme preference", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("System by default follows the OS, and an explicit choice overrides it and persists", async ({ page }) => {
    await routeCp(page);
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto("/");
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);
    expect(await bg(page)).toBe(LIGHT_BG);
    await page.emulateMedia({ colorScheme: "dark" });
    expect(await bg(page)).toBe(DARK_BG);

    await openAppMenu(page);
    const select = page.getByTestId("app-theme-select");
    await expect(select).toHaveValue("system");
    await select.selectOption("light");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    expect(await bg(page)).toBe(LIGHT_BG); // OS says dark, the choice wins
    expect(await page.evaluate(() => localStorage.getItem("deskrally.theme"))).toBe("light");
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe("light");

    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await openAppMenu(page);
    await expect(page.getByTestId("app-theme-select")).toHaveValue("light");

    await page.getByTestId("app-theme-select").selectOption("dark");
    expect(await bg(page)).toBe(DARK_BG);
    await page.getByTestId("app-theme-select").selectOption("system");
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);
    expect(await page.evaluate(() => localStorage.getItem("deskrally.theme"))).toBeNull();
  });

  test("a stored choice is on the document before the app script runs", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("deskrally.theme", "light"));
    await page.route("**/src/main.tsx*", (r) => r.abort()); // the app never starts: only theme-init.js can have set it
    await page.goto("/");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("the remote picture surround is black in both themes", async ({ page }) => {
    await connect(page);
    for (const theme of ["light", "dark"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      expect(await bg(page, ".viewer__surface"), theme).toBe("rgb(0, 0, 0)");
    }
  });

  test("the guest join page is paper in both themes", async ({ page }) => {
    await page.route("**/cp/**", (r) => r.fulfill({ json: {} }));
    for (const theme of ["light", "dark"]) {
      await page.goto("/join#ABCD2345");
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      expect(await bg(page, ".join"), theme).toBe("rgb(243, 240, 232)");
    }
  });
});

test.describe("reduced motion", () => {
  test.use({ storageState: { cookies: [], origins: [] }, viewport: { width: 412, height: 900 } });
  const duration = (page: Page) => page.locator(".access").evaluate((el) => getComputedStyle(el).transitionDuration);
  test("the machine-list drawer slides normally and snaps under prefers-reduced-motion", async ({ page }) => {
    await routeCp(page);
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.goto("/");
    await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked");
    expect(await duration(page)).toBe("0.16s");
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(parseFloat(await duration(page))).toBeLessThan(0.001);
  });
});

// ---- Screenshot matrix (opt-in) ------------------------------------------------------------------
// Set LT_SHOTS=<dir> to write the light/dark screenshot matrix. Without it these tests are not registered at all
// (rather than skipped): the verification gate counts every skip as a failure.
const SHOTS = process.env.LT_SHOTS;
if (SHOTS) test.describe("screenshots", () => {
  test.use({ storageState: { cookies: [], origins: [] } });
  const sizes = { desktop: { width: 1366, height: 800 }, phone: { width: 412, height: 860 } } as const;
  for (const theme of ["light", "dark"] as const) {
    for (const [sizeName, size] of Object.entries(sizes)) {
      const tag = `${theme}-${sizeName}`;
      const shot = (page: Page, name: string) => page.screenshot({ path: `${SHOTS}/${tag}-${name}.png` });
      test(`console, menu and machine list, ${tag}`, async ({ page }) => {
        mkdirSync(SHOTS!, { recursive: true });
        await page.setViewportSize(size);
        await page.addInitScript((t) => localStorage.setItem("deskrally.theme", t), theme);
        await routeCp(page);
        await page.goto("/");
        await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", /.+/);
        if (sizeName === "phone") await page.getByTestId("app-nav-toggle").click();
        await expect(page.getByTestId(`connect-${DEVICE}`)).toBeVisible();
        await page.waitForTimeout(400); // let the drawer finish sliding
        await shot(page, "1-machines");
        if (sizeName === "phone") await page.locator(".app__navbackdrop").click({ position: { x: 390, y: 400 } });
        await page.waitForTimeout(300);
        await openAppMenu(page);
        await page.waitForTimeout(300);
        await shot(page, "2-menu");
        if (sizeName === "phone") {
          await page.locator(".toolbar-menu__panel:visible").first().evaluate((el) => { el.scrollTop = el.scrollHeight; });
          await shot(page, "2b-menu-bottom");
        }
        for (const [area, file] of [["Sessions", "3-sessions"], ["Appearance", "4-appearance"], ["Users", "5-users"]] as const) {
          await page.getByRole("tab", { name: area, exact: true }).click();
          await page.waitForTimeout(250);
          await shot(page, file);
          await openAppMenu(page);
        }
      });
      test(`live session with a fake peer, ${tag}`, async ({ page }) => {
        mkdirSync(SHOTS!, { recursive: true });
        await page.setViewportSize(size);
        await page.addInitScript((t) => localStorage.setItem("deskrally.theme", t), theme);
        await page.addInitScript(() => localStorage.setItem("deskrally.sessionChrome", "pinned"));
        await connect(page);
        await page.waitForTimeout(400);
        await shot(page, "6-session");
      });
      test(`guest and public pages, ${tag}`, async ({ page }) => {
        mkdirSync(SHOTS!, { recursive: true });
        await page.setViewportSize(size);
        await page.addInitScript((t) => localStorage.setItem("deskrally.theme", t), theme);
        await page.route("**/cp/**", (r) => r.fulfill({ json: {} }));
        await page.goto("/join#ABCD2345");
        await page.waitForTimeout(400);
        await shot(page, "7-join");
        await page.goto("/docs");
        await page.waitForTimeout(600);
        await shot(page, "8-docs");
      });
    }
  }
});
