/**
 * docs/68 stage 5, with the API mocked: the platform Reach tab and the tenant Owner's Adoption card.
 *
 *   1. Reach renders the seeded per-artifact table: request counts under "Download requests" (never a column or
 *      cell labelled just "Downloads"), the approximate completed figure, the unique-ish figure with a "partial"
 *      marker and a dash when flagged, updates in their own table, a sparkline per row, and the section 3 caveats.
 *   2. The 7/30/90 window buttons cut the same rows.
 *   3. An operator whose second factor lapsed (403, mfa_ok false) is asked for a code on the tab, and the report
 *      loads after it.
 *   4. Adoption renders the Owner's counts; a 403 renders nothing; at 412 px the page does not scroll sideways.
 *
 * Mocked API, loopback only; named supervisor_* so the mocked profile runs it.
 */
import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { mountPlatform } from "./platform_mock";

const day = (ago: number): string => new Date(Date.now() - ago * 86_400_000).toISOString().slice(0, 10);

const ROWS = [
  { day: day(1), artifact: "DeskRallySupport.exe", class: "human", requests: 40, completed_approx: 30, unique_ish_clients: 12, bytes: 1, unique_ish_partial: false },
  { day: day(2), artifact: "DeskRallySupport.exe", class: "human", requests: 10, completed_approx: 8, unique_ish_clients: 5, bytes: 1, unique_ish_partial: true },
  { day: day(45), artifact: "DeskRallySupport.exe", class: "human", requests: 100, completed_approx: 90, unique_ish_clients: 20, bytes: 1, unique_ish_partial: false },
  { day: day(1), artifact: "server/deskrally-server.tar.gz", class: "human", requests: 3, completed_approx: null, unique_ish_clients: null, bytes: 1, unique_ish_partial: false },
  { day: day(1), artifact: "agent-manifest", class: "update", requests: 500, completed_approx: null, unique_ish_clients: null, bytes: 1, unique_ish_partial: false },
  { day: day(1), artifact: "sidecar", class: "other", requests: 77, completed_approx: null, unique_ish_clients: null, bytes: 1, unique_ish_partial: false },
  { day: day(1), artifact: "-", class: "noise", requests: 999, completed_approx: null, unique_ish_clients: null, bytes: 1, unique_ish_partial: false },
];

const CAVEATS = [
  "Requests are not downloads: the human-artifact request count includes bots, retries and previews.",
  "Update traffic (manifests and payloads) is machine traffic and never counts as a download.",
];

async function openReach(page: Page, onReach: () => { status: number; json: unknown }) {
  const mock = await mountPlatform(page, async (url, method, route) => {
    if (url.pathname === "/cp/platform/reach" && method === "GET") {
      const a = onReach();
      await route.fulfill({ status: a.status, json: a.json });
      return true;
    }
    return false;
  });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-row-acme")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("platform-tab-reach").click();
  return mock;
}

const ok = () => ({ status: 200, json: { from: day(89), to: day(0), rows: ROWS, caveats: CAVEATS } });

test("Reach shows requests, completed, unique-ish with a partial marker, updates apart, sparklines and the caveats", async ({ page }) => {
  await openReach(page, ok);
  const human = page.getByTestId("reach-human");
  await expect(human).toBeVisible();

  const exe = page.getByTestId("reach-row-DeskRallySupport.exe");
  await expect(exe.getByTestId("reach-requests")).toHaveText("50");
  await expect(exe.getByTestId("reach-completed")).toHaveText("38");
  await expect(exe.getByTestId("reach-unique")).toContainText("12");
  await expect(exe.getByTestId("reach-partial")).toHaveText("partial");
  await expect(exe.getByTestId("reach-spark")).toBeVisible();

  const tar = page.getByTestId("reach-row-server/deskrally-server.tar.gz");
  await expect(tar.getByTestId("reach-completed")).toHaveText("—");
  await expect(tar.getByTestId("reach-unique")).toContainText("—");
  await expect(tar.getByTestId("reach-partial")).toBeVisible();

  // Updates are their own table, and other/noise buckets are not shown as artifacts.
  const updates = page.getByTestId("reach-updates");
  await expect(updates.getByTestId("reach-row-agent-manifest").getByTestId("reach-requests")).toHaveText("500");
  await expect(human.getByTestId("reach-row-agent-manifest")).toHaveCount(0);
  await expect(page.getByTestId("platform-reach")).not.toContainText("sidecar");

  // The caveats are printed.
  const caveats = page.getByTestId("reach-caveats");
  await expect(caveats).toContainText("Requests are not downloads");
  await expect(caveats).toContainText("machine traffic and never counts as a download");

  // A raw request count is never labelled "downloads", and the page never says users or installs.
  const headers = await page.getByTestId("platform-reach").locator("th").allTextContents();
  // The exact header list, so a relabel is a deliberate change: person-facing table, then updates table.
  expect(headers.map((h) => h.trim())).toEqual([
    "Artifact", "Download requests", "Completed (approx.)", "Unique-ish clients / day (mean)", "30 days",
    "Artifact", "Requests", "30 days",
  ]);
  // No header says "download" except the one that qualifies it as requests.
  for (const h of headers) if (h.trim() !== "Download requests") expect(h.toLowerCase()).not.toContain("download");
  const text = (await page.getByTestId("platform-reach").innerText()).toLowerCase();
  expect(text).not.toMatch(/\busers?\b|\binstalls?\b/);
  expect(text).not.toMatch(/\bdownloads\b\s*\d|\d+\s+downloads\b/);
});

test("the 7, 30 and 90 day windows cut the same rows", async ({ page }) => {
  await openReach(page, ok);
  const requests = page.getByTestId("reach-row-DeskRallySupport.exe").getByTestId("reach-requests");
  await expect(requests).toHaveText("50"); // 30 days (default)
  await page.getByTestId("reach-window-7").click();
  await expect(requests).toHaveText("50");
  await page.getByTestId("reach-window-90").click();
  await expect(requests).toHaveText("150");
  await page.getByTestId("reach-window-30").click();
  await expect(requests).toHaveText("50");
});

test("a lapsed second factor asks for a code on the tab, then loads the report", async ({ page }) => {
  let verified = false;
  const mock = await openReach(page, () => (verified ? ok() : { status: 403, json: { error: "forbidden" } }));
  // The panel's own /platform/me answer decides what the 403 means.
  mock.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByTestId("reach-window-7").click();
  await page.getByRole("button", { name: "Refresh" }).last().click();
  await expect(page.getByTestId("reach-stepup")).toBeVisible();
  verified = true;
  await page.getByTestId("reach-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByTestId("reach-row-DeskRallySupport.exe")).toBeVisible();
  expect(mock.stepUps).toEqual(["123456"]);
});

test("a factor that lapsed BEFORE the tab opens still shows the tab's own code prompt, and the fallback caveats print", async ({ page }) => {
  let verified = false;
  const mock = await openReach(page, () => (verified ? { status: 200, json: { from: day(89), to: day(0), rows: ROWS, caveats: [] } } : { status: 403, json: { error: "forbidden" } }));
  // openReach is on the Reach tab with a fresh factor. Go back to Tenants, lapse the factor and refresh there: the
  // panel's cached /platform/me becomes the lapsed one and opens ITS prompt; cancelling it leaves who lapsed with
  // no prompt open, which is when the Reach tab is enabled again and must not render an empty pane.
  await page.getByTestId("platform-tab-tenants").click();
  mock.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await page.getByTestId("platform-tab-reach").click();
  await expect(page.getByTestId("reach-stepup")).toBeVisible();
  verified = true;
  await page.getByTestId("reach-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByTestId("reach-row-DeskRallySupport.exe")).toBeVisible();
  // The server sent no caveats: the console's own copy prints, including the registrations line.
  await expect(page.getByTestId("reach-caveats")).toContainText("Registrations are the real adoption signal");
  await expect(page.getByTestId("reach-caveats")).toContainText("Completed is approximate");
});

test("the Reach tab does not scroll the page sideways at phone width", async ({ page }) => {
  await page.setViewportSize({ width: 412, height: 900 });
  await openReach(page, ok);
  await expect(page.getByTestId("reach-human")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("Adoption shows the Owner's counts, and a 403 renders nothing", async ({ page }) => {
  let mode: "ok" | "forbidden" = "ok";
  const mount = async () => {
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== new URL(test.info().project.use.baseURL ?? "http://127.0.0.1:5173").origin) return route.abort();
      if (url.pathname === "/cp/auth/session") return route.fulfill({ status: 204 });
      if (url.pathname === "/cp/adoption") {
        if (mode === "forbidden") return route.fulfill({ status: 403, json: { error: "forbidden" } });
        return route.fulfill({
          json: {
            from: "2026-10-07", to: "2026-11-05", active_devices_30d: 7,
            new_devices_per_week: [{ week: "2026-10-26", count: 2 }, { week: "2026-11-02", count: 4 }],
            attended_funnel: { issued: 8, redeemed: 4, consented: 2, active: 1 },
            agent_versions: [{ version: "1.3.18", count: 5 }, { version: "unknown", count: 1 }],
          },
        });
      }
      if (url.pathname.startsWith("/cp/")) return route.fulfill({ json: {} });
      return route.continue();
    });
    await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
    await (await consoleTab(page, { name: "Security" })).click();
    await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
  };

  await page.setViewportSize({ width: 412, height: 900 });
  await mount();
  const card = page.getByTestId("adoption");
  await expect(card).toBeVisible();
  await expect(page.getByTestId("adoption-active")).toHaveText("7");
  // last_seen is kept by the server's presence sweep (0079); the tooltip says older days may undercount.
  await expect(page.getByText("devices online in the last 30 days")).toBeVisible();
  await expect(page.getByTestId("adoption-weeks")).toContainText("2026-11-02");
  await expect(page.getByTestId("adoption-funnel")).toContainText("Codes issued");
  await expect(page.getByTestId("adoption-funnel")).toContainText("50%");
  await expect(page.getByTestId("adoption-versions")).toContainText("1.3.18");
  await expect(page.getByTestId("adoption-versions")).toContainText("not reported");
  // No sideways page scroll at phone width.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  const text = (await card.innerText()).toLowerCase();
  expect(text).not.toMatch(/\bdownloads?\b|\binstalls?\b/);

  // Not an Owner: the section is not rendered at all.
  mode = "forbidden";
  await page.reload();
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("adoption")).toHaveCount(0);
});
