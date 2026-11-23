/**
 * Platform area — who sees it, the second-factor step-up, and the suspend confirmation.
 *
 *   1. A non-operator (and an older control plane with no /platform/me) gets no Platform tab, and the
 *      console never asks for the platform listing.
 *   2. An operator whose session's second factor is older than 12 hours is asked for a code before the
 *      listing is requested; after a successful step-up the listing loads.
 *   3. Suspending names the effect, warns when the tenant has machines without session leases, and stays
 *      disabled until the slug is typed exactly and a reason is given; the request carries both.
 *   4. A change attempted after the 15-minute window lapsed asks for the code first and then sends the
 *      change exactly once.
 *
 * Mocked API, loopback only; named supervisor_* so the mocked profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab, openAppMenu } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const MAIN = {
  id: "t-main",
  slug: "main",
  name: "Platform",
  deployment_mode: "saas",
  created_at: "2026-01-01T00:00:00Z",
  user_count: 1,
  unleased_machines: false,
};
const ACME = {
  id: "t-acme",
  slug: "acme",
  name: "Acme Corp",
  deployment_mode: "saas",
  created_at: "2026-10-12T00:00:00Z",
  user_count: 4,
  unleased_machines: true,
};

interface Server {
  /** The /platform/me body; null = an older control plane (404). */
  me: Record<string, unknown> | null;
  suspended: Set<string>;
  listRequests: number;
  stepUps: string[];
  suspendBodies: unknown[];
  createBodies: unknown[];
  /** Resolves once the console's /platform/me request has been answered. */
  meAnswered: Promise<unknown>;
  /** When set, the next step-up request waits for `release()` before it is answered. */
  stepUpHold: { arrived: boolean; release: () => void; gate: Promise<void> } | null;
  /** How the FIRST suspend request is refused: "lapse" = 403 and the 15-minute window lapses (as if it
   *  expired between the panel's check and the request); "plain" = 403 with the window still fresh. */
  firstSuspend403: "lapse" | "plain" | null;
  /** When set, the next /platform/me request waits for `release()`; it is answered with `me` as it is
   *  THEN (so a step-up that lands meanwhile is reflected). */
  meHold: ReturnType<typeof hold> | null;
  /** When true, /platform/me fails with 500 (a failed lookup, not a non-operator answer). */
  meFail: boolean;
  /** When set, the next suspend request waits for `release()`. */
  suspendHold: ReturnType<typeof hold> | null;
  /** When set, the next listing request waits for `release()`; it is answered with the rows as they are THEN. */
  listHold: ReturnType<typeof hold> | null;
}

function hold(): { arrived: boolean; release: () => void; gate: Promise<void>; answer?: Record<string, unknown> } {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  return { arrived: false, release, gate };
}

async function mount(page: Page, me: Server["me"]): Promise<Server> {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  const server: Server = {
    me,
    suspended: new Set(),
    listRequests: 0,
    stepUps: [],
    suspendBodies: [],
    createBodies: [],
    meAnswered: page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/me"),
    stepUpHold: null,
    firstSuspend403: null,
    meHold: null,
    meFail: false,
    suspendHold: null,
    listHold: null,
  };
  const rows = () =>
    [MAIN, ACME].map((t) => (server.suspended.has(t.id) ? { ...t, disabled_at: "2026-10-16T00:00:00Z" } : t));

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/platform/me") {
      const held = server.meHold;
      if (held) {
        server.meHold = null;
        held.arrived = true;
        await held.gate;
      }
      if (held?.answer) await route.fulfill({ json: held.answer }); // a held read answered as of when it was SENT
      else if (server.meFail) await route.fulfill({ status: 500, json: { error: "boom" } });
      else if (server.me === null) await route.fulfill({ status: 404, json: { error: "not found" } });
      else await route.fulfill({ json: server.me });
    } else if (url.pathname === "/cp/platform/tenants" && method === "GET") {
      server.listRequests++;
      const heldList = server.listHold;
      if (heldList) {
        server.listHold = null;
        heldList.arrived = true;
        await heldList.gate;
      }
      await route.fulfill({ json: { tenants: rows() } });
    } else if (url.pathname === "/cp/platform/tenants" && method === "POST") {
      server.createBodies.push(route.request().postDataJSON());
      await route.fulfill({ status: 201, json: { tenant: { ...ACME, id: "t-new", slug: "new" } } });
    } else if (url.pathname === "/cp/platform/tenants/t-acme/suspend" && method === "POST") {
      server.suspendBodies.push(route.request().postDataJSON());
      const heldSuspend = server.suspendHold;
      if (heldSuspend) {
        server.suspendHold = null;
        heldSuspend.arrived = true;
        await heldSuspend.gate;
      }
      const refusal = server.suspendBodies.length === 1 ? server.firstSuspend403 : null;
      if (refusal) {
        if (refusal === "lapse") server.me = { operator: true, mfa_ok: true, mfa_fresh: false };
        await route.fulfill({ status: 403, json: { error: "platform operator access denied" } });
        return;
      }
      server.suspended.add("t-acme");
      await route.fulfill({ json: { tenant: { ...ACME, disabled: true } } });
    } else if (url.pathname === "/cp/auth/step-up" && method === "POST") {
      const code = (route.request().postDataJSON() as { code: string }).code;
      server.stepUps.push(code);
      const held = server.stepUpHold;
      if (held) {
        server.stepUpHold = null;
        held.arrived = true;
        await held.gate;
      }
      if (code === "123456") {
        server.me = { operator: true, mfa_ok: true, mfa_fresh: true };
        await route.fulfill({ status: 204 });
      } else {
        // The control plane answers a wrong code 403 (auth_stepup.go): a 401 would sign the console out.
        await route.fulfill({ status: 403, json: { error: "invalid credentials" } });
      }
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  return server;
}

const cell = (page: Page, text: string) => page.getByRole("cell", { name: text, exact: true });

for (const [label, me] of [
  ["a non-operator", { operator: false, mfa_ok: true, mfa_fresh: true }],
  ["an older control plane", null],
] as const) {
  test(`${label} gets no Platform tab and no platform listing request`, async ({ page }) => {
    const server = await mount(page, me);
    // The tab is absent before the answer too; assert only after the console has heard it.
    await server.meAnswered;
    await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
    await openAppMenu(page);
    await expect(page.getByRole("tab", { name: "Machines", exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tab", { name: "Platform", exact: true })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: "Tenants", exact: true })).toHaveCount(0);
    expect(server.listRequests).toBe(0);
  });
}

test("an operator without a recent second factor is asked for a code before the listing loads", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 });
  expect(server.listRequests).toBe(0);

  await page.getByTestId("platform-stepup-code").fill("000000");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-stepup-error")).toBeVisible();
  expect(server.listRequests).toBe(0);

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(cell(page, "acme")).toBeVisible();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  expect(server.stepUps).toEqual(["000000", "123456"]);
});

test("suspending requires the exact slug and a reason, and warns about machines without leases", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(cell(page, "acme")).toBeVisible({ timeout: 15_000 });

  await page.getByTestId("platform-row-acme").getByRole("button", { name: "Suspend…" }).click();
  await expect(page.getByTestId("platform-confirm-effect")).toContainText("4 user(s)");
  await expect(page.getByTestId("platform-unleased-warning")).toBeVisible();
  const submit = page.getByTestId("platform-confirm-submit");
  await expect(submit).toBeDisabled();

  await page.getByTestId("platform-confirm-slug").fill("Acme");
  await page.getByTestId("platform-confirm-reason").fill("unpaid invoice");
  await expect(submit).toBeDisabled(); // case matters: the slug must match exactly
  await page.getByTestId("platform-confirm-slug").fill("acme");
  await page.getByTestId("platform-confirm-reason").fill("   ");
  await expect(submit).toBeDisabled(); // a blank reason is not a reason
  await page.getByTestId("platform-confirm-reason").fill("unpaid invoice");
  await expect(submit).toBeEnabled();
  await submit.click();

  await expect(page.getByTestId("platform-confirm")).toHaveCount(0);
  await expect(page.getByTestId("platform-row-acme").getByText("suspended", { exact: true })).toBeVisible();
  expect(server.suspendBodies).toEqual([{ confirm_slug: "acme", reason: "unpaid invoice" }]);
});

test("the platform tenant's own row offers no unleased warning", async ({ page }) => {
  await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(cell(page, "main")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("platform-row-main").getByRole("button", { name: "Suspend…" }).click();
  await expect(page.getByTestId("platform-confirm-effect")).toBeVisible();
  await expect(page.getByTestId("platform-unleased-warning")).toHaveCount(0);
});

test("a change after the 15-minute window asks for the code, then is sent exactly once", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(cell(page, "acme")).toBeVisible({ timeout: 15_000 });

  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  expect(server.createBodies).toHaveLength(0);

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect.poll(() => server.createBodies.length).toBe(1);
  expect(server.createBodies[0]).toEqual({ slug: "new", name: "New Org", deployment_mode: "saas" });
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
});

// --- Overlap, cancellation, the 403 retry and double submission (Codex slice C review) -------------

async function openPlatform(page: Page) {
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(cell(page, "acme")).toBeVisible({ timeout: 15_000 });
}

async function fillSuspendAcme(page: Page) {
  await page.getByTestId("platform-row-acme").getByRole("button", { name: "Suspend…" }).click();
  await page.getByTestId("platform-confirm-slug").fill("acme");
  await page.getByTestId("platform-confirm-reason").fill("unpaid invoice");
}

/** Let every queued response and React update land before a negative assertion. */
async function settle(page: Page) {
  await page.evaluate(
    () => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(r, 50)))),
  );
}

test("one change at a time: a second change waits, refresh keeps the first, cancel releases it", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);

  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // The panel is frozen while the create waits for its code: no row action, no create field.
  await expect(page.getByTestId("platform-row-acme").getByRole("button", { name: "Suspend…" })).toBeDisabled();
  await expect(page.getByTestId("tenant-slug")).toBeDisabled();
  await expect(page.getByTestId("tenant-name")).toBeDisabled();

  // Refresh neither drops the waiting create nor releases its busy state.
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByRole("button", { name: "Creating…", exact: true })).toBeDisabled();

  // Cancel abandons the create and unfreezes the panel.
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  await fillSuspendAcme(page);
  await expect(page.getByTestId("platform-confirm-submit")).toBeEnabled();

  // The suspension now runs on its own, after its own code; the abandoned create is never sent.
  await page.getByTestId("platform-confirm-submit").click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => server.suspendBodies.length).toBe(1);
  await settle(page);
  expect(server.createBodies).toHaveLength(0);
  expect(server.suspendBodies).toHaveLength(1);
});

test("a verification that lands after Cancel runs nothing, not even a change queued afterwards", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);

  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  const held = hold();
  server.stepUpHold = held;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => held.arrived).toBe(true);
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);

  // A new change starts and waits for its own code (the mock still says the window lapsed).
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // The cancelled verification now succeeds server-side. It must not close the new prompt or run
  // either change.
  held.release();
  await expect.poll(() => server.stepUps.length).toBe(1);
  await settle(page);
  await settle(page);
  expect(server.createBodies).toHaveLength(0);
  expect(server.suspendBodies).toHaveLength(0);
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
});

test("a 403 because the window lapsed asks for a code and resends exactly once", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  server.firstSuspend403 = "lapse";
  await openPlatform(page);
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  expect(server.suspendBodies).toHaveLength(1);

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-row-acme").getByText("suspended", { exact: true })).toBeVisible();
  await settle(page);
  expect(server.suspendBodies).toHaveLength(2);
});

test("a 403 with a fresh window is reported, not retried", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  server.firstSuspend403 = "plain";
  await openPlatform(page);
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect(page.getByTestId("platform-confirm-error")).toContainText("access denied");
  await settle(page);
  expect(server.suspendBodies).toHaveLength(1);
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect(page.getByTestId("platform-confirm-submit")).toBeEnabled();
});

test("the confirm handler itself refuses a wrong slug, and a double submit sends once", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);
  await page.getByTestId("platform-row-acme").getByRole("button", { name: "Suspend…" }).click();
  await page.getByTestId("platform-confirm-slug").fill("acm");
  await page.getByTestId("platform-confirm-reason").fill("unpaid invoice");
  // requestSubmit() submits regardless of the disabled button: the handler must refuse on its own.
  await page.getByTestId("platform-confirm").evaluate((f) => (f as HTMLFormElement).requestSubmit());
  await expect(page.getByTestId("platform-confirm-error")).toContainText("slug exactly");
  await settle(page);
  expect(server.suspendBodies).toHaveLength(0);

  await page.getByTestId("platform-confirm-slug").fill("acme");
  // Two submits in the same task, before React can re-render the button disabled.
  await page.getByTestId("platform-confirm").evaluate((f) => {
    (f as HTMLFormElement).requestSubmit();
    (f as HTMLFormElement).requestSubmit();
  });
  await expect(page.getByTestId("platform-row-acme").getByText("suspended", { exact: true })).toBeVisible();
  await settle(page);
  expect(server.suspendBodies).toHaveLength(1);
});

test("refresh while the listing itself needs a code keeps a waiting change", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click(); // dismiss the listing prompt

  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByRole("button", { name: "Creating…", exact: true })).toBeDisabled();

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => server.createBodies.length).toBe(1);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  await settle(page);
  expect(server.createBodies).toHaveLength(1);
});

test("a double-submitted code is verified once", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByTestId("platform-stepup").evaluate((f) => {
    (f as HTMLFormElement).requestSubmit();
    (f as HTMLFormElement).requestSubmit();
  });
  await expect(cell(page, "acme")).toBeVisible();
  await settle(page);
  expect(server.stepUps).toEqual(["123456"]);
});

test("a second change submitted around the disabled button cannot displace a waiting one", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);
  await fillSuspendAcme(page); // opened and filled first, so it is on screen when the create starts
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByTestId("platform-confirm-slug")).toBeDisabled();

  await page.getByTestId("platform-confirm").evaluate((f) => (f as HTMLFormElement).requestSubmit());
  await settle(page);

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => server.createBodies.length).toBe(1);
  await settle(page);
  expect(server.suspendBodies).toHaveLength(0);
});

// --- Phases (Codex slice C re-review) ----------------------------------------------------------------

test("a listing verification landing while a new change checks freshness does not send it twice", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 });

  // The LISTING prompt's verification is held at the server.
  const verify = hold();
  server.stepUpHold = verify;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => verify.arrived).toBe(true);

  // A create starts meanwhile; its own freshness read is held too.
  const meRead = hold();
  server.meHold = meRead;
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => meRead.arrived).toBe(true);

  // The verification lands first (the server now says fresh), then the create's freshness read.
  verify.release();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await settle(page);
  expect(server.createBodies).toHaveLength(0); // a verification never sends by itself
  meRead.release();
  await expect.poll(() => server.createBodies.length).toBe(1);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  await settle(page);
  expect(server.createBodies).toHaveLength(1);
});

test("a listing verification during a change that is already sent does not resend it", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);

  const sent = hold();
  server.suspendHold = sent;
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect.poll(() => sent.arrived).toBe(true);

  // While the suspend is in flight, a refresh finds the 12-hour window gone and asks for a code.
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await settle(page);
  expect(server.suspendBodies).toHaveLength(1);

  sent.release();
  await expect(page.getByTestId("platform-confirm")).toHaveCount(0);
  await settle(page);
  expect(server.suspendBodies).toHaveLength(1);
});

test("a failed freshness lookup ends the change with a visible error", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);
  server.meFail = true;
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("tenant-form-error")).toContainText("Could not check your platform access");
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect(page.getByTestId("platform-not-operator")).toHaveCount(0); // a failure is not "not an operator"
  expect(server.createBodies).toHaveLength(0);
});

test("a change whose freshness read says non-operator ends, and nothing is left waiting", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);
  server.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-not-operator")).toBeVisible();
  await settle(page);
  expect(server.createBodies).toHaveLength(0);
});

test("a refresh that finds the operator grant gone abandons a change waiting for its code", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  server.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId("platform-not-operator")).toBeVisible();

  // Even if the grant comes back, the abandoned create is never sent.
  server.me = { operator: true, mfa_ok: true, mfa_fresh: true };
  await settle(page);
  expect(server.createBodies).toHaveLength(0);
});

test("a stale non-operator answer from an abandoned change cannot hide a newer change's prompt", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 }); // listing prompt

  // Change 1: its freshness read is held at the server.
  const stale = hold();
  server.meHold = stale;
  await page.getByTestId("tenant-slug").fill("one");
  await page.getByTestId("tenant-name").fill("One");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => stale.arrived).toBe(true);

  // Cancel on the (listing) prompt abandons change 1 while its read is still out.
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click();
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();

  // Change 2 reaches "awaiting a code".
  await page.getByTestId("tenant-slug").fill("two");
  await page.getByTestId("tenant-name").fill("Two");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // Change 1's read now lands, saying "not an operator". It is stale and must change nothing.
  server.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/me");
  stale.release();
  await landed;
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await settle(page);
  await expect(page.getByTestId("platform-not-operator")).toHaveCount(0);
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByRole("button", { name: "Creating…", exact: true })).toBeDisabled();

  // Change 2 completes normally after its code; change 1 is never sent.
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => server.createBodies.length).toBe(1);
  expect(server.createBodies[0]).toEqual({ slug: "two", name: "Two", deployment_mode: "saas" });
  await settle(page);
  expect(server.createBodies).toHaveLength(1);
});

test("a held listing lookup that lands 'non-operator' after a newer change's lookup changes nothing", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);

  // A refresh's lookup is held at the server.
  const stale = hold();
  server.meHold = stale;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => stale.arrived).toBe(true);

  // A change starts afterwards; its own (newer) lookup is answered and it waits for a code.
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // The older refresh lookup now lands, saying "not an operator".
  server.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/me");
  stale.release();
  await landed;
  server.me = { operator: true, mfa_ok: true, mfa_fresh: false };
  await settle(page);
  await expect(page.getByTestId("platform-not-operator")).toHaveCount(0);
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => server.createBodies.length).toBe(1);
  await settle(page);
  expect(server.createBodies).toHaveLength(1);
});

test("Cancel on a prompt opened during a running change does not free the panel for another", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);

  await page.getByTestId("tenant-slug").fill("new"); // typed before the suspend starts
  await page.getByTestId("tenant-name").fill("New Org");
  const sent = hold();
  server.suspendHold = sent;
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect.poll(() => sent.arrived).toBe(true);

  // A refresh opens the listing prompt mid-request; the operator cancels it.
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);

  // The suspend is still in flight: no other change may start, so its completion cannot land on one.
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
  await expect(page.getByTestId("tenant-slug")).toBeDisabled();
  await page.getByRole("form", { name: "New tenant" }).evaluate((f) => (f as HTMLFormElement).requestSubmit());
  await settle(page);
  expect(server.createBodies).toHaveLength(0);

  server.me = { operator: true, mfa_ok: true, mfa_fresh: true };
  sent.release();
  await expect(page.getByTestId("platform-confirm")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  // The new form was not cleared by the old change's completion.
  await expect(page.getByTestId("tenant-slug")).toHaveValue("new");
  expect(server.suspendBodies).toHaveLength(1);
});

// --- Stale UI paths (Codex slice C fifth review) -------------------------------------------------------

test("a listing in flight when access is lost does not repopulate the rows", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);

  const list = hold();
  server.listHold = list;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => list.arrived).toBe(true);

  // A change's newer lookup finds the 12-hour window gone: listing access is lost.
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(cell(page, "acme")).toHaveCount(0);

  // The older listing lands with rows: they must not come back.
  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/tenants");
  list.release();
  await landed;
  await settle(page);
  await expect(cell(page, "acme")).toHaveCount(0);
});

test("a refresh sent before Cancel does not reopen the cancelled prompt", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 });

  const me = hold();
  server.meHold = me;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => me.arrived).toBe(true);
  await page.getByRole("button", { name: "Cancel", exact: true }).first().click();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);

  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/me");
  me.release(); // still "no second factor within 12 h"
  await landed;
  await settle(page);
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
});

test("a change completing after the panel is closed starts nothing", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);
  const sent = hold();
  server.suspendHold = sent;
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect.poll(() => sent.arrived).toBe(true);

  await (await consoleTab(page, { name: "Machines", exact: true })).click(); // unmounts the panel
  await expect(page.getByTestId("platform-confirm")).toHaveCount(0);
  const before = server.listRequests;
  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/tenants/t-acme/suspend");
  sent.release();
  await landed;
  await settle(page);
  await settle(page);
  expect(server.listRequests).toBe(before); // no refresh from an unmounted panel
  expect(server.suspendBodies).toHaveLength(1);
});

test("a verification that lands while a change checks access is not undone by the change's older answer", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: false, mfa_fresh: false });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible({ timeout: 15_000 }); // listing prompt

  // The verification is held at the server.
  const verify = hold();
  server.stepUpHold = verify;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => verify.arrived).toBe(true);

  // A create starts; its access read is held and will answer as of BEFORE the verification.
  const opRead = hold();
  opRead.answer = { operator: true, mfa_ok: true, mfa_fresh: false };
  server.meHold = opRead;
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => opRead.arrived).toBe(true);

  // The verification lands; the refresh it starts is held too.
  const refreshRead = hold();
  server.meHold = refreshRead;
  verify.release();
  await expect.poll(() => refreshRead.arrived).toBe(true);

  // The change's older "not fresh" answer lands first, then the refresh's.
  opRead.release();
  await expect.poll(() => server.createBodies.length).toBe(1);
  refreshRead.release();
  await settle(page);
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  expect(server.createBodies).toHaveLength(1);
  expect(server.stepUps).toEqual(["123456"]);
});

test("a verification that lands during a 403's access check is not undone by that check's older answer", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  server.firstSuspend403 = "lapse";
  await openPlatform(page);

  // The suspend is held at the server, then refused 403.
  const sent = hold();
  server.suspendHold = sent;
  await fillSuspendAcme(page);
  await page.getByTestId("platform-confirm-submit").click();
  await expect.poll(() => sent.arrived).toBe(true);

  // Meanwhile a refresh opens the listing prompt and its verification is held.
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  const verify = hold();
  server.stepUpHold = verify;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => verify.arrived).toBe(true);

  // The 403 lands; its recovery read is held and will answer as of BEFORE the verification.
  const recovery = hold();
  recovery.answer = { operator: true, mfa_ok: true, mfa_fresh: false };
  server.meHold = recovery;
  sent.release();
  await expect.poll(() => recovery.arrived).toBe(true);

  // The verification lands; the refresh it starts is held.
  const refreshRead = hold();
  server.meHold = refreshRead;
  verify.release();
  await expect.poll(() => refreshRead.arrived).toBe(true);

  // The recovery's older "not fresh" answer lands first: the change is retried (once), not re-prompted.
  recovery.release();
  await expect.poll(() => server.suspendBodies.length).toBe(2);
  refreshRead.release();
  await expect(page.getByTestId("platform-row-acme").getByText("suspended", { exact: true })).toBeVisible();
  await settle(page);
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  expect(server.suspendBodies).toHaveLength(2);
  expect(server.stepUps).toEqual(["123456"]);
});

test("a listing's pre-verification 'no second factor' answer never clears the rows after a verification", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: false });
  await openPlatform(page);

  // A create waits for a code (its access read is the older one).
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // THEN a refresh's access read goes out (the newest read so far) and is held; it will answer as of
  // before the verification below.
  const listingRead = hold();
  listingRead.answer = { operator: true, mfa_ok: false, mfa_fresh: false };
  server.meHold = listingRead;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => listingRead.arrived).toBe(true);

  // The code is verified; the create's post-verification read is held, so the verification's
  // follow-up refresh has not started and the listing above is still current.
  const checkRead = hold();
  server.meHold = checkRead;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => checkRead.arrived).toBe(true);
  await expect(cell(page, "acme")).toBeVisible();

  // The listing's old answer lands while the check is still out: discarded unapplied (and replaced by
  // a new read), so the rows never disappear and no prompt opens.
  const landed = page.waitForResponse((r) => new URL(r.url()).pathname === "/cp/platform/me");
  listingRead.release();
  await landed;
  await settle(page);
  await expect(cell(page, "acme")).toBeVisible();

  checkRead.release();
  await expect.poll(() => server.createBodies.length).toBe(1);
  await settle(page);
  await expect(cell(page, "acme")).toBeVisible();
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  expect(server.createBodies).toHaveLength(1);
});

test("an overtaken cached 'no second factor' answer cannot decide a change after a verification", async ({ page }) => {
  const server = await mount(page, { operator: true, mfa_ok: true, mfa_fresh: true });
  await openPlatform(page);

  // A create's access read is held; it will answer "fresh".
  const opRead = hold();
  opRead.answer = { operator: true, mfa_ok: true, mfa_fresh: true };
  server.meHold = opRead;
  await page.getByTestId("tenant-slug").fill("new");
  await page.getByTestId("tenant-name").fill("New Org");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => opRead.arrived).toBe(true);

  // Access lapses; a later refresh applies "no second factor" and opens the prompt.
  server.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();

  // The code is verified; the follow-up refresh read is held, so the negative stays the newest applied.
  const refreshRead = hold();
  server.meHold = refreshRead;
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect.poll(() => refreshRead.arrived).toBe(true);

  // The create's older "fresh" answer lands; the newer applied answer it defers to was overtaken by the
  // verification, so it is read again instead of reopening the prompt.
  opRead.release();
  await expect.poll(() => server.createBodies.length).toBe(1);
  refreshRead.release();
  await settle(page);
  await expect(page.getByTestId("platform-stepup")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  expect(server.createBodies).toHaveLength(1);
  expect(server.stepUps).toEqual(["123456"]);
});
