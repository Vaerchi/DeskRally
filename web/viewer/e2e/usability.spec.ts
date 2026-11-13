import { test, expect, type Page } from "@playwright/test";
import { consoleTab, setConnectIn } from "./nav";

const devices = [
  { id: "m1", tenant_id: "t1", device_id: "11111111-1111-4111-8111-111111111111", name: "Office PC", alias: "Front desk", group_id: "g1", group_name: "Office", online: true, status: "active", os: "Windows" },
  { id: "m2", tenant_id: "t1", device_id: "22222222-2222-4222-8222-222222222222", name: "Laptop", group_id: "g1", group_name: "Office", online: false, status: "active" },
];

async function mountMachines(page: Page) {
  await page.route("**/cp/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: devices, presence_known: true } });
    if (path === "/cp/machine-groups") return route.fulfill({ json: { machine_groups: [{ id: "g1", name: "Office" }] } });
    if (path === "/cp/sessions" && route.request().method() === "POST") {
      return route.fulfill({ status: 403, json: { error: "session ended: the display layout changed; reconnect to continue" } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("/");
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("machine-name-m1")).toBeVisible();
}

test("bulk status needs an explicit choice and cancelling never writes", async ({ page }) => {
  let writes = 0;
  page.on("request", req => { if (req.method() === "POST" && req.url().includes("status")) writes++; });
  await mountMachines(page);
  await page.getByTestId("bulk-check-m1").check();
  await expect(page.getByTestId("bulk-status-select")).toHaveValue("");
  await expect(page.getByTestId("bulk-apply")).toBeDisabled();
  await page.getByTestId("bulk-status-select").selectOption("quarantined");
  page.once("dialog", async dialog => { expect(dialog.message()).toContain("1 selected machines"); await dialog.dismiss(); });
  await page.getByTestId("bulk-apply").click();
  page.once("dialog", async dialog => { expect(dialog.message()).toContain("Front desk"); await dialog.dismiss(); });
  await page.getByTestId("machine-status-select-m1").selectOption("retired");
  expect(writes).toBe(0);
  await expect(page.getByTestId("machine-status-m1")).toHaveText("active");
});

test("device search prunes selection and row Connect respects availability", async ({ page }) => {
  await mountMachines(page);
  await page.getByTestId("bulk-check-m1").check();
  await page.getByTestId("machines-text-search").fill("22222222");
  await expect(page.getByTestId("bulk-selected-count")).toHaveText("0 selected");
  // The one connect rule (wave 3): a machine that LOOKED offline keeps Connect, with the reason; only out of service disables it.
  await expect(page.getByTestId("machine-connect-m2")).toBeEnabled();
  await expect(page.getByTestId("machine-connect-m2")).toHaveAttribute("title", /looked offline/);
  await expect(page.getByTestId("machine-connect-m1")).toHaveCount(0);
  if (!await page.locator(".access__search").isVisible()) await page.getByTestId("app-nav-toggle").click();
  await page.locator(".access").getByRole("searchbox", { name: "Search machines", exact: true }).fill("1111-4111");
  await expect(page.locator(".access__machine")).toHaveCount(1);
  await expect(page.locator(".access__machine")).toContainText("Front desk");
});

test("row Connect uses the device identity and leaves the full failure visible", async ({ page }) => {
  await mountMachines(page);
  await setConnectIn(page, "browser");
  const started = page.waitForRequest(req => req.method() === "POST" && new URL(req.url()).pathname === "/cp/sessions");
  await page.getByTestId("machine-connect-m1").click();
  expect((await started).postDataJSON().machine_id).toBe(devices[0].device_id);
  await expect(page.locator(".panel--machines")).toHaveCount(0);
  const error = page.getByTestId("app-error");
  await expect(error).toBeVisible();
  await expect(error.locator("span")).toBeVisible();
  await expect(error.locator("span")).toContainText("Not authorized to connect to this device. Contact your administrator.");
  await page.screenshot({ path: test.info().outputPath("connect-error.png") });
  await error.getByRole("button", { name: "Dismiss message" }).click();
  await expect(error).toHaveCount(0);
});

test("invitations copy code and link with expiry and honest failure feedback", async ({ page }) => {
  const session = { id: "s1", tenant_id: "tenant", group_id: "group", technician_id: "alice", state: "pending", reason: "Printer support", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 600000).toISOString() };
  await page.addInitScript(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: {
    writeText: async (value: string) => { if ((window as unknown as { failCopy: boolean }).failCopy) throw new Error("denied"); (window as unknown as { copied: string }).copied = value; },
  } }));
  await page.route("**/fixture/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/machine-groups")) return route.fulfill({ json: { machine_groups: [{ id: "group", name: "Support" }] } });
    if (path.endsWith("/attended-sessions") && route.request().method() === "POST") return route.fulfill({ json: { session, code: "ABCD-EFGH", join_code: "ABCDEFGH", join_url: "/join#ABCDEFGH" } });
    if (path.endsWith("/attended-sessions")) return route.fulfill({ json: { sessions: [], has_more: false } });
    return route.fulfill({ json: { session } });
  });
  await page.goto("/e2e/attended_shared.html");
  await page.getByTestId("attended-start").click();
  await page.getByTestId("attended-copy-code").click();
  await expect(page.getByText("Code copied.", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe("ABCD-EFGH");
  await expect(page.locator("time")).toHaveAttribute("datetime", session.expires_at);
  await page.screenshot({ path: test.info().outputPath("invitation.png") });
  await page.getByTestId("attended-copy-link").click();
  await expect(page.getByText("Link copied.", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { copied: string }).copied)).toBe(new URL("/join#ABCDEFGH", page.url()).href);
  await page.evaluate(() => { (window as unknown as { failCopy: boolean }).failCopy = true; });
  await page.getByTestId("attended-copy-link").click();
  await expect(page.getByText("Could not copy. Select and copy the code or link above.")).toBeVisible();
  await page.evaluate(() => (window as unknown as { __account: (account: string) => void }).__account("bob"));
  await expect(page.getByText("Could not copy. Select and copy the code or link above.")).toHaveCount(0);
});

test("phone Tools menu keeps power labels readable without page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 412, height: 900 });
  await page.goto("/e2e/viewer_chrome.html");
  await page.getByTestId("viewer-tools-menu").click();
  const label = page.getByTestId("viewer-lock").locator(".viewer__lbl");
  await expect(label).toBeVisible();
  expect((await label.boundingBox())!.width).toBeGreaterThan(24);
  await expect(page.getByRole("group", { name: "Power and user session", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("tools-phone.png") });
});
