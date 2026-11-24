/**
 * A machine installed while the console is open appears in the machine list without a reload (2026-11-23: "i
 * installed another computer and the machines list on the app did not update"). The list used to load once, at
 * sign-in; it now refreshes every 30 s while the console is visible, and at once when it becomes visible again.
 *
 * Mutation evidence: removing the fleetTick effect in App.tsx leaves the second machine absent after the clock
 * advance, so the first test fails.
 */
import { test, expect, type Page } from "@playwright/test";

const FIRST = "11111111-2222-4333-8444-555555555555";
const SECOND = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const machine = (device: string, name: string) => ({
  id: `pk-${device.slice(0, 4)}`, tenant_id: "t-1", device_id: device, group_id: "g-1", group_name: "Home Computers",
  name, os: "Windows 11", online: true, multi_session_capable: true,
});

async function fixture(page: Page) {
  const state = { machines: [machine(FIRST, "Office PC")], listings: 0 };
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") {
      state.listings++;
      return route.fulfill({ json: { machines: state.machines, presence_known: true } });
    }
    if (path === "/cp/sessions") return route.fulfill({ json: { sessions: [] } });
    return route.fulfill({ json: {} });
  });
  await page.clock.install();
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await expect(page.getByTestId(`connect-${FIRST}`)).toBeVisible();
  return state;
}

test("a newly installed machine appears within the refresh interval, without a reload", async ({ page }) => {
  const state = await fixture(page);
  // The new computer finishes installing while the console is open.
  state.machines = [...state.machines, machine(SECOND, "New Laptop")];
  await expect(page.getByTestId(`connect-${SECOND}`)).toHaveCount(0);
  const before = state.listings;
  await page.clock.fastForward(31_000);
  await expect(page.getByTestId(`connect-${SECOND}`)).toBeVisible();
  expect(state.listings).toBeGreaterThan(before);
  await expect(page.getByTestId(`connect-${FIRST}`)).toBeVisible();
});

test("a hidden console does not poll; returning to it refreshes at once", async ({ page }) => {
  const state = await fixture(page);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  const hiddenAt = state.listings;
  state.machines = [...state.machines, machine(SECOND, "New Laptop")];
  await page.clock.fastForward(95_000);
  expect(state.listings, "no polling while hidden").toBe(hiddenAt);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.getByTestId(`connect-${SECOND}`)).toBeVisible();
});
