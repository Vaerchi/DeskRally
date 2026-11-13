/**
 * Sites — local search over the loaded rows, mocked-API browser test (loopback only).
 *
 *   1. A query by site name, machine alias or hostname narrows rows and shows "Showing X of Y".
 *   2. No match shows a reset; clearing restores every row.
 *   3. A filtered row can be edited and saved; other properties/requests are untouched, and a draft in a
 *      row hidden by the filter survives.
 *   4. Searching sends no extra /cp/ requests.
 *   5. At 390px the search and rows stay inside the viewport.
 *
 * Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const M1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const M2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const M3 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const MACHINES = [
  { id: M1, tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "HQ-DESK-01", alias: "Front Desk" },
  { id: M2, tenant_id: "t-1", device_id: "dev-2", group_id: "g-1", name: "branch-pc" },
  { id: M3, tenant_id: "t-1", device_id: "dev-3", group_id: "g-1", name: "lab-box" },
];

async function mount(page: Page, puts: { path: string; value: string }[], cpGets: string[]) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/machines" && method === "GET") {
      cpGets.push(url.pathname + url.search);
      const filtered = url.searchParams.has("property_key");
      await route.fulfill({ json: { machines: filtered ? [MACHINES[0]] : MACHINES } });
    } else if (url.pathname === `/cp/machines/${M1}/properties` && method === "GET") {
      cpGets.push(url.pathname);
      await route.fulfill({ json: { properties: [{ key: "site", value: "Head Office" }] } });
    } else if (url.pathname.endsWith("/properties/site") && method === "PUT") {
      const { value } = route.request().postDataJSON() as { value: string };
      puts.push({ path: url.pathname, value });
      await route.fulfill({ json: { property: { key: "site", value } } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${M3}`)).toBeVisible({ timeout: 15_000 });
}

test("sites search: match, no-match reset, clear, and editing a filtered result", async ({ page }) => {
  const puts: { path: string; value: string }[] = [];
  const cpGets: string[] = [];
  await mount(page, puts, cpGets);

  const search = page.getByTestId("sites-search");
  const summary = page.getByTestId("sites-summary");
  await expect(summary).toHaveText("1 site, 3 machines");

  const getsBefore = cpGets.length;

  // Match by site name.
  await search.fill("head off");
  await expect(summary).toHaveText("Showing 1 of 3 machines, 1 site");
  await expect(page.getByTestId(`site-row-${M1}`)).toBeVisible();
  await expect(page.getByTestId(`site-row-${M2}`)).toHaveCount(0);

  // Match by alias, then hostname (the unknown/no-site rows stay distinct, found by machine only).
  await search.fill("front");
  await expect(page.getByTestId(`site-row-${M1}`)).toBeVisible();
  await search.fill("BRANCH");
  await expect(summary).toHaveText("Showing 1 of 3 machines, 0 sites");
  await expect(page.getByTestId(`site-value-${M2}`)).toHaveText("No site");

  // No match -> message + reset.
  await search.fill("nothing-here");
  await expect(page.getByTestId("sites-no-match")).toBeVisible();
  await expect(summary).toHaveText("Showing 0 of 3 machines, 0 sites");
  await page.getByTestId("sites-no-match-reset").click();
  await expect(search).toHaveValue("");
  await expect(summary).toHaveText("1 site, 3 machines");
  for (const id of [M1, M2, M3]) await expect(page.getByTestId(`site-row-${id}`)).toBeVisible();

  // Edit a filtered result; a draft in a row the filter hides survives.
  await page.getByTestId(`site-input-${M3}`).fill("draft-site");
  await search.fill("branch-pc");
  await expect(page.getByTestId(`site-row-${M3}`)).toHaveCount(0);
  await page.getByTestId(`site-input-${M2}`).fill("Warehouse");
  await page.getByTestId(`site-save-${M2}`).click();
  await expect(page.getByTestId(`site-value-${M2}`)).toHaveText("Warehouse");
  expect(puts).toEqual([{ path: `/cp/machines/${M2}/properties/site`, value: "Warehouse" }]);

  await page.getByTestId("sites-search-clear").click();
  await expect(page.getByTestId(`site-input-${M3}`)).toHaveValue("draft-site");

  // Searching itself made no new reads.
  expect(cpGets.length).toBe(getsBefore);
});

test("sites search stays usable at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await mount(page, [], []);
  const search = page.getByTestId("sites-search");
  await search.fill("lab");
  await expect(page.getByTestId(`site-row-${M3}`)).toBeVisible();
  const box = await search.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
