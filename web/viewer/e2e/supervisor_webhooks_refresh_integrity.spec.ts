/**
 * Webhooks panel — overlapping listings, mocked-API browser regressions.
 *
 *   1. A slow OLDER listing (taken before a delete) landing after the newer post-delete re-list cannot
 *      make the just-deleted webhook (an HMAC-signed outbound endpoint) reappear as active.
 *   2. Busy ("Loading…") stays on while the NEWEST listing is pending even after an older one finishes,
 *      and clears only when the newest listing completes.
 *   3. When the NEWER re-list fails, the older listing (arriving afterwards) is not applied: the failure
 *      stays shown and the prior rows are kept.
 *
 * The panel has no Refresh control, so the older listing is the re-list that follows registering a
 * webhook (it observes the pre-delete state); the newer one follows deleting the seeded "wh-a".
 *
 * Every /cp/ call is routed here. The webhooks handler is keyed by BEHAVIOR (which gates are armed +
 * the server-side state the request observed), never by GET counters, so React StrictMode's replayed
 * mount effect cannot skew it. A released response is confirmed delivered to the browser, then the page
 * is flushed, before any stale-result assertion — no fixed sleeps. Loopback only. Named supervisor_* so
 * the mocked headless profile runs it.
 */

import { test, expect, type Page, type Request } from "@playwright/test";
import { consoleTab } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** A request held by the mock until released. */
class Hold {
  armed = false;
  arrived = false;
  request: Request | null = null;
  private resolve!: () => void;
  readonly gate = new Promise<void>((r) => (this.resolve = r));
  release() {
    this.resolve();
  }
}

async function mount(page: Page) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const server = { aDeleted: false, bCreated: false };
  const older = new Hold(); // applies to listings that observe the PRE-delete state
  const newer = new Hold(); // applies to listings that observe the POST-delete state
  const failNewer = { armed: false };

  const hook = (id: string) => ({
    id,
    url: `https://example.test/${id}`,
    events: [] as string[],
    created_at: "2026-01-01T00:00:00Z",
  });
  const rows = (aDeleted: boolean, bCreated: boolean) => [
    ...(aDeleted ? [] : [hook("wh-a")]),
    ...(bCreated ? [hook("wh-b")] : []),
  ];

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/tenant/webhooks" && method === "GET") {
      const observedDeleted = server.aDeleted; // the state this request sees, fixed at arrival
      const observedCreated = server.bCreated;
      const hold = observedDeleted ? newer : older;
      if (hold.armed) {
        hold.armed = false; // only the first matching request is held
        hold.request = route.request();
        hold.arrived = true;
        await hold.gate;
        await route.fulfill({ json: { webhooks: rows(observedDeleted, observedCreated) } });
      } else if (observedDeleted && failNewer.armed) {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        await route.fulfill({ json: { webhooks: rows(observedDeleted, observedCreated) } });
      }
    } else if (url.pathname === "/cp/tenant/webhooks" && method === "POST") {
      server.bCreated = true;
      await route.fulfill({ json: { webhook: { ...hook("wh-b"), secret: "secret-value" } } });
    } else if (url.pathname === "/cp/tenant/webhooks/wh-a" && method === "DELETE") {
      server.aDeleted = true;
      await route.fulfill({ json: {} });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // machines, sessions, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Webhooks", exact: true })).click();
  await expect(page.getByTestId("webhooks")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("webhook-row-wh-a")).toBeVisible({ timeout: 15_000 });
  return { older, newer, failNewer };
}

/** Release a held request, wait until the browser has received its response, then let React flush. */
async function releaseAndSettle(page: Page, hold: Hold) {
  expect(hold.request).not.toBeNull();
  hold.release();
  const response = await hold.request!.response();
  expect(response).not.toBeNull();
  await response!.finished();
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(resolve, 0))),
      ),
  );
}

/** Register a webhook: its post-write re-list is the (older) listing. */
async function register(page: Page) {
  await page.getByTestId("webhook-url").fill("https://example.test/wh-b");
  await page.getByTestId("webhook-create").click();
}

/**
 * Deliveries harness: wh-a and wh-b are both seeded. Delivery requests are keyed by webhook id: each id
 * has a plan of Holds consumed in order (a hold's label is the event name it returns); with no plan left
 * the response is immediate and labelled "<id>-immediate". DELETE of wh-a can be held via `del`.
 */
async function mountDeliveries(page: Page) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const state = { aDeleted: false };
  const plan: Record<string, { hold: Hold; label: string }[]> = { "wh-a": [], "wh-b": [] };
  const del = new Hold();
  const hook = (id: string) => ({
    id,
    url: `https://example.test/${id}`,
    events: [] as string[],
    created_at: "2026-01-01T00:00:00Z",
  });
  const record = (id: string, event: string) => ({
    webhook_id: id,
    event,
    attempted_at: "2026-01-01T00:00:00Z",
    attempt: 1,
    success: true,
    status_code: 200,
    duration_ms: 5,
    error: "",
  });

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const deliveries = /^\/cp\/tenant\/webhooks\/([^/]+)\/deliveries$/.exec(url.pathname);
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/tenant/webhooks" && method === "GET") {
      await route.fulfill({
        json: { webhooks: [...(state.aDeleted ? [] : [hook("wh-a")]), hook("wh-b")] },
      });
    } else if (deliveries && method === "GET") {
      const id = decodeURIComponent(deliveries[1]!);
      const next = plan[id]?.shift();
      if (next) {
        next.hold.request = route.request();
        next.hold.arrived = true;
        await next.hold.gate;
        await route.fulfill({ json: { deliveries: [record(id, next.label)] } });
      } else {
        await route.fulfill({ json: { deliveries: [record(id, `${id}-immediate`)] } });
      }
    } else if (url.pathname === "/cp/tenant/webhooks/wh-a" && method === "DELETE") {
      if (del.armed) {
        del.armed = false;
        del.request = route.request();
        del.arrived = true;
        await del.gate;
      }
      state.aDeleted = true;
      await route.fulfill({ json: {} });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Webhooks", exact: true })).click();
  await expect(page.getByTestId("webhooks")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("webhook-row-wh-a")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("webhook-row-wh-b")).toBeVisible();
  return { plan, del };
}

test("Show A, Hide, Show A: the first slower deliveries response cannot overwrite the second", async ({
  page,
}) => {
  const m = await mountDeliveries(page);
  const first = new Hold();
  const second = new Hold();
  m.plan["wh-a"]!.push({ hold: first, label: "first-old" }, { hold: second, label: "second-new" });

  await page.getByTestId("webhook-deliveries-btn-wh-a").click();
  await expect.poll(() => first.arrived).toBe(true);
  await page.getByTestId("webhook-deliveries-btn-wh-a").click(); // Hide
  await expect(page.getByTestId("webhook-deliveries-panel")).toHaveCount(0);
  await page.getByTestId("webhook-deliveries-btn-wh-a").click(); // Show again
  await expect.poll(() => second.arrived).toBe(true);

  await releaseAndSettle(page, second);
  await expect(page.getByTestId("webhook-deliveries-table")).toContainText("second-new");

  await releaseAndSettle(page, first);
  await expect(page.getByTestId("webhook-deliveries-table")).toContainText("second-new");
  await expect(page.getByTestId("webhook-deliveries-table")).not.toContainText("first-old");
});

test("deleting A while B's history was selected during the DELETE leaves B's history intact", async ({
  page,
}) => {
  const m = await mountDeliveries(page);
  await page.getByTestId("webhook-deliveries-btn-wh-a").click();
  await expect(page.getByTestId("webhook-deliveries-table")).toContainText("wh-a-immediate");

  m.del.armed = true;
  await page.getByTestId("webhook-delete-wh-a").click();
  await expect.poll(() => m.del.arrived).toBe(true);
  await page.getByTestId("webhook-deliveries-btn-wh-b").click();
  await expect(page.getByTestId("webhook-deliveries-table")).toContainText("wh-b-immediate");

  await releaseAndSettle(page, m.del);
  await expect(page.getByTestId("webhook-row-wh-a")).toHaveCount(0);
  await expect(page.getByTestId("webhook-deliveries-panel")).toBeVisible();
  await expect(page.getByTestId("webhook-deliveries-table")).toContainText("wh-b-immediate");
});

test("showing A while its DELETE is in flight: the late history cannot reopen the deleted webhook's panel", async ({
  page,
}) => {
  const m = await mountDeliveries(page);
  const late = new Hold();
  m.plan["wh-a"]!.push({ hold: late, label: "late-a" });

  m.del.armed = true;
  await page.getByTestId("webhook-delete-wh-a").click();
  await expect.poll(() => m.del.arrived).toBe(true);
  await page.getByTestId("webhook-deliveries-btn-wh-a").click(); // history of A requested, held
  await expect.poll(() => late.arrived).toBe(true);

  await releaseAndSettle(page, m.del);
  await expect(page.getByTestId("webhook-row-wh-a")).toHaveCount(0);
  await expect(page.getByTestId("webhook-deliveries-panel")).toHaveCount(0);

  await releaseAndSettle(page, late);
  await expect(page.getByTestId("webhook-deliveries-panel")).toHaveCount(0);
  await expect(page.getByTestId("webhook-deliveries-table")).toHaveCount(0);
});

test("a slow older listing cannot make a deleted webhook reappear as active", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;

  // Older listing: observes the pre-delete state (wh-a present) and is held.
  await register(page);
  await expect.poll(() => m.older.arrived).toBe(true);

  // Delete → post-delete re-list observes the deletion and completes while the older one is held.
  await page.getByTestId("webhook-delete-wh-a").click();
  await expect(page.getByTestId("webhook-row-wh-a")).toHaveCount(0);
  await expect(page.getByTestId("webhook-row-wh-b")).toBeVisible();

  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("webhook-row-wh-a")).toHaveCount(0);
  await expect(page.getByTestId("webhook-row-wh-b")).toBeVisible();
  await expect(page.getByTestId("webhooks-empty")).toHaveCount(0);
  await expect(page.getByTestId("webhook-error")).toHaveCount(0);
  // The show-once secret from the registration is unaffected by the refresh ordering.
  await expect(page.getByTestId("webhook-secret-value")).toHaveText("secret-value");
});

test("an older listing finishing does not clear busy while the newest is still loading", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;
  m.newer.armed = true;
  // A search nothing matches turns the empty-state row into the only busy indicator.
  await page.getByTestId("webhooks-search").fill("zzz-no-match");
  await expect(page.getByTestId("webhooks-empty")).toHaveText("No webhooks match this search.");

  await register(page);
  await expect.poll(() => m.older.arrived).toBe(true);
  await page.getByTestId("webhooks-search").fill("");
  await page.getByTestId("webhook-delete-wh-a").click();
  await expect.poll(() => m.newer.arrived).toBe(true);
  await page.getByTestId("webhooks-search").fill("zzz-no-match");
  await expect(page.getByTestId("webhooks-empty")).toHaveText("Loading…");

  // The older one lands first: it must neither apply its rows nor clear busy.
  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("webhooks-empty")).toHaveText("Loading…");

  // The newest lands: its rows apply and busy clears.
  await releaseAndSettle(page, m.newer);
  await expect(page.getByTestId("webhooks-empty")).toHaveText("No webhooks match this search.");
  await page.getByTestId("webhooks-search").fill("");
  await expect(page.getByTestId("webhook-row-wh-a")).toHaveCount(0);
  await expect(page.getByTestId("webhook-row-wh-b")).toBeVisible();
  await expect(page.getByTestId("webhook-error")).toHaveCount(0);
});

test("when the newer re-list fails, the older listing is not applied and the failure stays shown", async ({
  page,
}) => {
  const m = await mount(page);
  m.older.armed = true;
  m.failNewer.armed = true;

  await register(page);
  await expect.poll(() => m.older.arrived).toBe(true);

  // Newer re-list (post-delete) fails; the prior rows are kept.
  await page.getByTestId("webhook-delete-wh-a").click();
  await expect(page.getByTestId("webhook-error")).toBeVisible();
  await expect(page.getByTestId("webhook-row-wh-a")).toBeVisible();

  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("webhook-error")).toBeVisible();
  await expect(page.getByTestId("webhook-row-wh-a")).toBeVisible();
  await expect(page.getByTestId("webhook-row-wh-b")).toHaveCount(0);
});
