/**
 * Sites — bulk SET of one site on explicitly selected machines, mocked-API browser test (loopback only).
 *
 *   1. Only the selected machines are written; Cancel sends zero requests; the confirmation shows the
 *      count, the target site and every machine name.
 *   2. Mixed 200 / 403 / mismatched echo: only exact echoes count as saved, the aggregate is honest, failed
 *      rows stay selected and a retry sends ONLY them.
 *   3. Filters prune the selection immediately; a hidden machine is never targeted.
 *   4. "Select all visible" stops at the cap of 50 and the 51st row cannot be selected.
 *   5. A duplicate confirm sends one batch, one request at a time, and every control is locked meanwhile.
 *   6. A blank / over-long (UTF-8 bytes) site is refused with no request.
 *   7. At 390px the bulk controls and confirmation stay inside the viewport.
 *
 * Every /cp/ call is answered here and non-loopback origins are aborted: no production traffic.
 * Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const idN = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const M1 = idN(1);
const M2 = idN(2);
const M3 = idN(3);
const M4 = idN(4);

type Machine = { id: string; tenant_id: string; device_id: string; group_id: string; name: string; alias?: string };
type Behave = "ok" | "403" | "wrong";

const FOUR: Machine[] = [
  { id: M1, tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "pc-one", alias: "Front Desk" },
  { id: M2, tenant_id: "t-1", device_id: "dev-2", group_id: "g-1", name: "pc-two" },
  { id: M3, tenant_id: "t-1", device_id: "dev-3", group_id: "g-1", name: "pc-three" },
  { id: M4, tenant_id: "t-1", device_id: "dev-4", group_id: "g-1", name: "pc-four" },
];

interface Mock {
  puts: { id: string; value: string }[];
  gets: string[];
  behave: Record<string, Behave>;
  /** When set, every PUT waits for it before answering. */
  gate: { wait: Promise<void> | null };
}

async function mount(page: Page, machines: Machine[], siteOf: Record<string, string> = {}): Promise<Mock> {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  const mock: Mock = { puts: [], gets: [], behave: {}, gate: { wait: null } };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const put = /^\/cp\/machines\/([^/]+)\/properties\/site$/.exec(url.pathname);
    const props = /^\/cp\/machines\/([^/]+)\/properties$/.exec(url.pathname);
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/machines" && method === "GET") {
      mock.gets.push(url.pathname);
      const filtered = url.searchParams.has("property_key");
      await route.fulfill({ json: { machines: filtered ? machines.filter((m) => m.id in siteOf) : machines } });
    } else if (props && method === "GET") {
      const site = siteOf[props[1]];
      await route.fulfill({ json: { properties: site === undefined ? [] : [{ key: "site", value: site }] } });
    } else if (put && method === "PUT") {
      const { value } = route.request().postDataJSON() as { value: string };
      const id = put[1];
      mock.puts.push({ id, value });
      if (mock.gate.wait) await mock.gate.wait;
      const b = mock.behave[id] ?? "ok";
      if (b === "403") await route.fulfill({ status: 403, json: { error: "forbidden" } });
      else await route.fulfill({ json: { property: { key: "site", value: b === "wrong" ? `${value}-x` : value } } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${machines[0].id}`)).toBeVisible({ timeout: 15_000 });
  return mock;
}

const pick = (page: Page, id: string) => page.getByTestId(`site-select-${id}`);

async function selectAndReview(page: Page, ids: string[], site: string) {
  for (const id of ids) await pick(page, id).check();
  await page.getByTestId("sites-bulk-site").fill(site);
  await page.getByTestId("sites-bulk-review").click();
}

test("bulk assign: explicit targets, cancel sends nothing, mixed results, retry only failures", async ({ page }) => {
  const mock = await mount(page, FOUR);
  await selectAndReview(page, [M1, M2, M3], "  Branch 7  ");

  const confirm = page.getByTestId("sites-bulk-confirm");
  await expect(confirm).toBeVisible();
  await expect(page.getByTestId("sites-bulk-confirm-title")).toHaveText('Set site "Branch 7" on 3 machines?');
  const list = page.getByTestId("sites-bulk-confirm-list");
  await expect(list).toContainText("Front Desk");
  await expect(list).toContainText("pc-two");
  await expect(list).toContainText("pc-three");
  await expect(list).not.toContainText("pc-four");

  // Cancel: zero requests, selection kept, controls usable again.
  await page.getByTestId("sites-bulk-confirm-cancel").click();
  await expect(confirm).toHaveCount(0);
  expect(mock.puts).toEqual([]);
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("3 selected (max 50)");

  // Confirm with one success, one 403 and one mismatched echo.
  mock.behave[M2] = "403";
  mock.behave[M3] = "wrong";
  await page.getByTestId("sites-bulk-review").click();
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-result")).toBeVisible();
  const summary = page.getByTestId("sites-bulk-summary");
  await expect(summary).toContainText('Site "Branch 7" set on 1 of 3 machines; 2 failed');
  await expect(summary).toHaveAttribute("role", "alert");
  await expect(summary).not.toContainText(/all saved/i);
  await expect(page.getByTestId(`sites-bulk-result-${M1}`)).toHaveAttribute("data-status", "saved");
  await expect(page.getByTestId(`sites-bulk-result-${M2}`)).toHaveAttribute("data-status", "failed");
  await expect(page.getByTestId(`sites-bulk-result-${M3}`)).toHaveAttribute("data-status", "failed");

  // Exactly the three targets, in display order (Front Desk, pc-three, pc-two); M4 was never touched.
  expect(mock.puts).toEqual([
    { id: M1, value: "Branch 7" },
    { id: M3, value: "Branch 7" },
    { id: M2, value: "Branch 7" },
  ]);
  await expect(page.getByTestId(`site-value-${M1}`)).toHaveText("Branch 7");
  await expect(page.getByTestId(`site-value-${M2}`)).toHaveText("No site");
  await expect(page.getByTestId(`site-value-${M3}`)).toHaveText("No site");
  await expect(page.getByTestId(`site-value-${M4}`)).toHaveText("No site");

  // Success left the selection; failures stayed.
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("2 selected (max 50)");
  await expect(pick(page, M1)).not.toBeChecked();
  await expect(pick(page, M2)).toBeChecked();
  await expect(pick(page, M3)).toBeChecked();

  // Retry: only the failed machines are sent.
  mock.behave[M2] = "ok";
  mock.behave[M3] = "ok";
  await page.getByTestId("sites-bulk-review").click();
  await expect(page.getByTestId("sites-bulk-confirm-title")).toHaveText('Set site "Branch 7" on 2 machines?');
  await expect(list).not.toContainText("Front Desk");
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "Branch 7" set on 2 of 2 machines.');
  expect(mock.puts.slice(3)).toEqual([
    { id: M3, value: "Branch 7" },
    { id: M2, value: "Branch 7" },
  ]);
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("0 selected (max 50)");
  await expect(page.getByTestId(`site-value-${M4}`)).toHaveText("No site");
});

test("bulk assign: filters prune the selection immediately, hidden rows are never targeted", async ({ page }) => {
  const mock = await mount(page, FOUR, { [M1]: "Old HQ" });
  for (const id of [M1, M2, M3]) await pick(page, id).check();
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("3 selected (max 50)");

  // Status filter hides M1 (assigned): it leaves the selection at once.
  await page.getByTestId("sites-state-filter").selectOption("none");
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("2 selected (max 50)");

  // Text filter hides M3.
  await page.getByTestId("sites-search").fill("two");
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("1 selected (max 50)");

  // Clearing the filters does not resurrect the pruned selection.
  await page.getByTestId("sites-search").fill("");
  await page.getByTestId("sites-state-filter").selectOption("all");
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("1 selected (max 50)");
  await expect(pick(page, M1)).not.toBeChecked();
  await expect(pick(page, M3)).not.toBeChecked();
  await expect(pick(page, M2)).toBeChecked();

  await page.getByTestId("sites-bulk-site").fill("Only Two");
  await page.getByTestId("sites-bulk-review").click();
  await expect(page.getByTestId("sites-bulk-confirm-list").locator("li")).toHaveCount(1);
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "Only Two" set on 1 of 1 machine.');
  expect(mock.puts).toEqual([{ id: M2, value: "Only Two" }]);
});

test("bulk assign: select-all-visible stops at 50 and the 51st cannot be selected", async ({ page }) => {
  const many: Machine[] = Array.from({ length: 55 }, (_, i) => ({
    id: idN(100 + i),
    tenant_id: "t-1",
    device_id: `dev-${i}`,
    group_id: "g-1",
    name: `bulk-${String(i).padStart(2, "0")}`,
  }));
  const mock = await mount(page, many);
  await page.getByTestId("sites-bulk-select-all").click();
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("50 selected (max 50)");
  await expect(page.getByTestId("sites-bulk-cap")).toBeVisible();
  await expect(page.locator('[data-testid^="site-select-"]:checked')).toHaveCount(50);
  await expect(pick(page, idN(154))).toBeDisabled();
  await expect(pick(page, idN(100))).toBeEnabled(); // a selected row can still be unticked

  await page.getByTestId("sites-bulk-site").fill("Cap Site");
  await page.getByTestId("sites-bulk-review").click();
  await expect(page.getByTestId("sites-bulk-confirm-title")).toHaveText('Set site "Cap Site" on 50 machines?');
  await expect(page.getByTestId("sites-bulk-confirm-list").locator("li")).toHaveCount(50);
  await page.getByTestId("sites-bulk-confirm-cancel").click();
  expect(mock.puts).toEqual([]);
});

test("bulk assign: duplicate confirm sends one batch, one request at a time, all controls locked", async ({ page }) => {
  const mock = await mount(page, FOUR);
  let release!: () => void;
  mock.gate.wait = new Promise<void>((r) => (release = r));
  await selectAndReview(page, [M1, M2], "Locked Site");

  // Two synchronous clicks before React can re-render: the second must be dropped.
  await page.getByTestId("sites-bulk-confirm-yes").evaluate((el) => {
    (el as HTMLButtonElement).click();
    (el as HTMLButtonElement).click();
  });
  await expect(page.getByTestId("sites-bulk-progress")).toBeVisible();
  await expect.poll(() => mock.puts.length).toBe(1);
  await page.waitForTimeout(250);
  expect(mock.puts).toEqual([{ id: M1, value: "Locked Site" }]); // M2 waits for M1's answer

  await expect(page.getByTestId("sites-refresh")).toBeDisabled();
  await expect(page.getByTestId("sites-search")).toBeDisabled();
  await expect(page.getByTestId("sites-state-filter")).toBeDisabled();
  await expect(pick(page, M3)).toBeDisabled();
  await expect(page.getByTestId("sites-bulk-review")).toBeDisabled();
  await expect(page.getByTestId("sites-bulk-select-all")).toBeDisabled();
  await expect(page.getByTestId(`site-save-${M4}`)).toBeDisabled();
  await expect(page.getByTestId(`site-input-${M4}`)).toBeDisabled();

  release();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "Locked Site" set on 2 of 2 machines.');
  expect(mock.puts).toEqual([
    { id: M1, value: "Locked Site" },
    { id: M2, value: "Locked Site" },
  ]);
  await expect(page.getByTestId("sites-refresh")).toBeEnabled();
  await expect(page.getByTestId(`site-save-${M4}`)).toBeEnabled();
});

test("bulk assign: Cancel then Confirm before a re-render sends zero requests", async ({ page }) => {
  const mock = await mount(page, FOUR);
  await selectAndReview(page, [M1, M2], "Cancelled Site");
  await expect(page.getByTestId("sites-bulk-confirm")).toBeVisible();

  // Both clicks run in one synchronous script, so the Confirm button is still mounted and its (stale)
  // handler runs after Cancel has already invalidated the confirmation.
  await page.evaluate(() => {
    (document.querySelector('[data-testid="sites-bulk-confirm-cancel"]') as HTMLButtonElement).click();
    (document.querySelector('[data-testid="sites-bulk-confirm-yes"]') as HTMLButtonElement).click();
  });
  await expect(page.getByTestId("sites-bulk-confirm")).toHaveCount(0);
  await page.waitForTimeout(300);
  expect(mock.puts).toEqual([]);
  await expect(page.getByTestId("sites-bulk-result")).toHaveCount(0);
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("2 selected (max 50)");
  await expect(page.getByTestId(`site-value-${M1}`)).toHaveText("No site");

  // The panel is not wedged: a fresh review + confirm still works.
  await page.getByTestId("sites-bulk-review").click();
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "Cancelled Site" set on 2 of 2 machines.');
  expect(mock.puts.length).toBe(2);
});

test("bulk assign: invalid site is refused locally, and existing row drafts survive a batch", async ({ page }) => {
  const mock = await mount(page, FOUR);
  await page.getByTestId(`site-input-${M1}`).fill("my draft"); // a draft on a machine that IS a target
  await pick(page, M1).check();

  await page.getByTestId("sites-bulk-review").click(); // blank site
  await expect(page.getByTestId("sites-bulk-error")).toBeVisible();
  await expect(page.getByTestId("sites-bulk-confirm")).toHaveCount(0);

  // 1367 three-byte characters = 4101 bytes > 4096 although only 1367 UTF-16 units.
  await page.getByTestId("sites-bulk-site").fill("€".repeat(1367));
  await page.getByTestId("sites-bulk-review").click();
  await expect(page.getByTestId("sites-bulk-error")).toContainText("bytes");
  await expect(page.getByTestId("sites-bulk-confirm")).toHaveCount(0);
  expect(mock.puts).toEqual([]);

  await page.getByTestId("sites-bulk-site").fill("Valid");
  await page.getByTestId("sites-bulk-review").click();
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toContainText("1 of 1 machine");
  await expect(page.getByTestId(`site-input-${M1}`)).toHaveValue("my draft");
  await expect(page.getByTestId(`site-value-${M1}`)).toHaveText("Valid");
  expect(mock.puts).toEqual([{ id: M1, value: "Valid" }]);
});

test("bulk assign: an outstanding write on an UNSELECTED row blocks review; no overlapping request", async ({ page }) => {
  const mock = await mount(page, FOUR);
  let release!: () => void;
  mock.gate.wait = new Promise<void>((r) => (release = r));

  await page.getByTestId(`site-input-${M4}`).fill("Solo");
  await pick(page, M1).check();
  await page.getByTestId("sites-bulk-site").fill("Bulk");

  // One synchronous script: React cannot re-render (so nothing is disabled yet) between the row Save and the
  // Review click, which therefore reaches the handler and must be refused by the synchronous in-flight guard.
  await page.evaluate(
    ([save, review]) => {
      (document.querySelector(`[data-testid="${save}"]`) as HTMLButtonElement).click();
      (document.querySelector(`[data-testid="${review}"]`) as HTMLButtonElement).click();
    },
    [`site-save-${M4}`, "sites-bulk-review"],
  );
  await expect.poll(() => mock.puts.length).toBe(1);
  await expect(page.getByTestId("sites-bulk-confirm")).toHaveCount(0);
  await expect(page.getByTestId("sites-bulk-error")).toContainText("Wait for the current save");
  await expect(page.getByTestId("sites-bulk-review")).toBeDisabled();
  await page.waitForTimeout(250);
  expect(mock.puts).toEqual([{ id: M4, value: "Solo" }]);

  release();
  await expect(page.getByTestId(`site-value-${M4}`)).toHaveText("Solo");
  await expect(page.getByTestId("sites-bulk-review")).toBeEnabled();
  mock.gate.wait = null;
  await page.getByTestId("sites-bulk-review").click();
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "Bulk" set on 1 of 1 machine.');
  expect(mock.puts).toEqual([
    { id: M4, value: "Solo" },
    { id: M1, value: "Bulk" },
  ]);
});

test("bulk assign: leaving Sites mid-batch (unmount) stops further requests and publishes nothing", async ({ page }) => {
  const mock = await mount(page, FOUR);
  let release!: () => void;
  mock.gate.wait = new Promise<void>((r) => (release = r));
  await selectAndReview(page, [M1, M2, M3], "Gone Site");
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect.poll(() => mock.puts.length).toBe(1);

  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("sites")).toHaveCount(0);
  release();
  mock.gate.wait = null;
  await page.waitForTimeout(400);
  expect(mock.puts).toEqual([{ id: M1, value: "Gone Site" }]); // M2/M3 were never requested

  // Coming back is a brand-new context: nothing selected, no result carried over, nothing confirmed locally.
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${M1}`)).toBeVisible();
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("0 selected (max 50)");
  await expect(page.getByTestId("sites-bulk-result")).toHaveCount(0);
  await expect(page.getByTestId("sites-bulk-confirm")).toHaveCount(0);
  await expect(page.getByTestId(`site-value-${M1}`)).toHaveText("No site"); // the mock server never stored it
});

test("bulk assign: leaving Sites during an individual write drops the late answer", async ({ page }) => {
  const mock = await mount(page, FOUR);
  let release!: () => void;
  mock.gate.wait = new Promise<void>((r) => (release = r));
  await page.getByTestId(`site-input-${M2}`).fill("Late");
  await page.getByTestId(`site-save-${M2}`).click();
  await expect.poll(() => mock.puts.length).toBe(1);
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  release();
  mock.gate.wait = null;
  await page.waitForTimeout(300);
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${M2}`)).toBeVisible();
  await expect(page.getByTestId(`site-value-${M2}`)).toHaveText("No site"); // fresh load, no stale confirmation
  await expect(page.getByTestId(`site-input-${M2}`)).toHaveValue("");
  expect(mock.puts).toEqual([{ id: M2, value: "Late" }]);
});

test("bulk assign: a refresh that removes an authorized row prunes it from the selection for good", async ({ page }) => {
  const machines = [...FOUR];
  const mock = await mount(page, machines);
  for (const id of [M1, M2, M3]) await pick(page, id).check();
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("3 selected (max 50)");

  const m2 = machines.splice(1, 1)[0]; // access to M2 is gone server-side
  await page.getByTestId("sites-refresh").click();
  await expect(page.getByTestId(`site-row-${M2}`)).toHaveCount(0);
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("2 selected (max 50)");

  machines.splice(1, 0, m2); // access returns: the row reappears but is NOT re-selected
  await page.getByTestId("sites-refresh").click();
  await expect(page.getByTestId(`site-row-${M2}`)).toBeVisible();
  await expect(pick(page, M2)).not.toBeChecked();
  await expect(page.getByTestId("sites-bulk-count")).toHaveText("2 selected (max 50)");

  await page.getByTestId("sites-bulk-site").fill("After Refresh");
  await page.getByTestId("sites-bulk-review").click();
  await expect(page.getByTestId("sites-bulk-confirm-list").locator("li")).toHaveCount(2);
  await expect(page.getByTestId("sites-bulk-confirm-list")).not.toContainText("pc-two");
  await page.getByTestId("sites-bulk-confirm-yes").click();
  await expect(page.getByTestId("sites-bulk-summary")).toHaveText('Site "After Refresh" set on 2 of 2 machines.');
  expect(mock.puts.map((p) => p.id)).toEqual([M1, M3]);
});

test("bulk assign stays usable at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await mount(page, FOUR);
  await selectAndReview(page, [M1, M2], "Phone Site");
  await expect(page.getByTestId("sites-bulk-confirm")).toBeVisible();

  const inside = async (testId: string) => {
    const box = await page.getByTestId(testId).boundingBox();
    expect(box, testId).not.toBeNull();
    expect(box!.x, `${testId} left`).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width, `${testId} right`).toBeLessThanOrEqual(390);
  };
  for (const t of [
    "sites-bulk-site",
    "sites-bulk-review",
    "sites-bulk-select-all",
    "sites-bulk-deselect",
    "sites-bulk-confirm",
    "sites-bulk-confirm-yes",
    "sites-bulk-confirm-cancel",
    `site-select-${M1}`,
  ]) {
    await inside(t);
  }
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});
