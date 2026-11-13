/**
 * Sites — assignment-status filter over the loaded rows, mocked-API browser test (loopback only).
 *
 *   1. All machines / Assigned site / No site / Site unavailable narrow the rows; an empty stored site
 *      is "assigned" and an unreadable lookup is "unavailable", never "No site".
 *   2. It combines with text search; shown/total counts stay honest; no-match offers clear-all.
 *   3. Drafts and row errors survive a row being hidden and restored.
 *   4. Filtering sends no requests at all.
 *   5. At 390px the filter and rows stay inside the viewport.
 *
 * Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const M1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const M2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const M3 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const M4 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ALL = [M1, M2, M3, M4];
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const MACHINES = [
  { id: M1, tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "HQ-DESK-01", alias: "Front Desk" },
  { id: M2, tenant_id: "t-1", device_id: "dev-2", group_id: "g-1", name: "branch-pc" },
  { id: M3, tenant_id: "t-1", device_id: "dev-3", group_id: "g-1", name: "branch-lab" },
  { id: M4, tenant_id: "t-1", device_id: "dev-4", group_id: "g-1", name: "empty-site-box" },
];

/** M1 "Head Office", M4 stored empty, M2 confirmed absent, M3 listed as having a site but unreadable. */
async function mount(page: Page, requests: string[]) {
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
      requests.push(`${method} ${url.pathname}${url.search}`);
      const filtered = url.searchParams.has("property_key");
      await route.fulfill({ json: { machines: filtered ? [MACHINES[0], MACHINES[2], MACHINES[3]] : MACHINES } });
    } else if (url.pathname === `/cp/machines/${M1}/properties` && method === "GET") {
      requests.push(`${method} ${url.pathname}`);
      await route.fulfill({ json: { properties: [{ key: "site", value: "Head Office" }] } });
    } else if (url.pathname === `/cp/machines/${M4}/properties` && method === "GET") {
      requests.push(`${method} ${url.pathname}`);
      await route.fulfill({ json: { properties: [{ key: "site", value: "" }] } });
    } else if (url.pathname === `/cp/machines/${M3}/properties` && method === "GET") {
      requests.push(`${method} ${url.pathname}`);
      await route.fulfill({ status: 500, json: { error: "boom" } });
    } else if (url.pathname.startsWith("/cp/")) {
      requests.push(`${method} ${url.pathname}`);
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${M4}`)).toBeVisible({ timeout: 15_000 });
}

async function expectRows(page: Page, visible: string[]) {
  for (const id of ALL) {
    await expect(page.getByTestId(`site-row-${id}`)).toHaveCount(visible.includes(id) ? 1 : 0);
  }
}

test("sites assignment filter: statuses, combined search, reset, drafts and no requests", async ({ page }) => {
  const requests: string[] = [];
  await mount(page, requests);

  const filter = page.getByLabel("Assignment");
  const search = page.getByTestId("sites-search");
  const summary = page.getByTestId("sites-summary");
  await expect(summary).toHaveText("2 sites, 4 machines");
  await expect(page.getByTestId(`site-value-${M4}`)).toHaveText("(empty)");
  await expect(page.getByTestId(`site-value-${M2}`)).toHaveText("No site");
  await expect(page.getByTestId(`site-value-${M3}`)).toHaveText("Unknown");

  // Drafts and a row error entered BEFORE any filtering.
  await page.getByTestId(`site-input-${M3}`).fill("draft-site");
  await page.getByTestId(`site-save-${M2}`).click(); // blank draft -> local validation error, no request
  await expect(page.getByTestId(`site-error-${M2}`)).toBeVisible();

  const before = requests.length;

  await filter.selectOption("assigned");
  await expectRows(page, [M1, M4]); // an empty stored value is assigned
  await expect(summary).toHaveText("Showing 2 of 4 machines, 2 sites");

  await filter.selectOption("none");
  await expectRows(page, [M2]); // the unreadable machine is NOT "No site"
  await expect(summary).toHaveText("Showing 1 of 4 machines, 0 sites");
  await expect(page.getByTestId(`site-error-${M2}`)).toBeVisible();

  await filter.selectOption("unknown");
  await expectRows(page, [M3]);
  await expect(summary).toHaveText("Showing 1 of 4 machines, 0 sites");
  await expect(page.getByTestId(`site-input-${M3}`)).toHaveValue("draft-site");

  // Combined with text search.
  await search.fill("branch");
  await expectRows(page, [M3]);
  await filter.selectOption("none");
  await expectRows(page, [M2]);
  await filter.selectOption("assigned");
  await expectRows(page, []);
  await expect(summary).toHaveText("Showing 0 of 4 machines, 0 sites");
  await expect(page.getByTestId("sites-no-match")).toBeVisible();

  // Clear-all resets both controls.
  await page.getByTestId("sites-no-match-reset").click();
  await expect(search).toHaveValue("");
  await expect(filter).toHaveValue("all");
  await expectRows(page, ALL);
  await expect(summary).toHaveText("2 sites, 4 machines");
  await expect(page.getByTestId(`site-input-${M3}`)).toHaveValue("draft-site");
  await expect(page.getByTestId(`site-error-${M2}`)).toBeVisible();

  // Status alone (no query) is a filter too: the summary reports shown/total.
  await filter.selectOption("none");
  await expect(summary).toHaveText("Showing 1 of 4 machines, 0 sites");
  await filter.selectOption("all");
  await expect(summary).toHaveText("2 sites, 4 machines");

  // Filtering and clearing made no requests of any kind.
  expect(requests.length).toBe(before);
  expect(requests.filter((r) => !r.startsWith("GET "))).toEqual([]);
});

test("sites assignment filter stays usable at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await mount(page, []);
  const filter = page.getByLabel("Assignment");
  await filter.selectOption("unknown");
  await expect(page.getByTestId(`site-row-${M3}`)).toBeVisible();
  const box = await filter.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
