/**
 * Platform operator: a tenant's hostnames (docs/66 2a.10, 2k), with the API mocked.
 *
 *   1. The history shows each assignment's state: pending, active, and "quarantined until <date>" for a released
 *      host still held back; a row offers only the actions the server will accept.
 *   2. Assign, activate, release and reactivate each ask for confirmation in plain words saying what they do to
 *      guests, and send exactly the body the server takes. Release needs a reason.
 *   3. Look-alike warnings (409) turn the assign confirmation into an acknowledge-every-code-and-give-a-reason form.
 *
 * Mocked API, loopback only; named supervisor_* so the mocked profile runs it.
 */
import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { mountPlatform, ACME } from "./platform_mock";

interface Row {
  id: string;
  host: string;
  tenant_id: string;
  kind: string;
  state: "pending" | "active" | "released";
  created_by: string;
  created_at: string;
  activated_at?: string;
  released_at?: string;
  released_by?: string;
  quarantined_until?: string;
}

const row = (over: Partial<Row>): Row => ({
  id: "a1",
  host: "acme.example.test",
  tenant_id: ACME.id,
  kind: "subdomain",
  state: "active",
  created_by: "op",
  created_at: "2026-10-01T00:00:00Z",
  ...over,
});

// A quarantine that is still running whenever this spec runs.
const FAR_FUTURE = "2099-01-15T00:00:00Z";

interface State {
  rows: Row[];
  /** Look-alike warnings the next assign without acknowledgements is refused with. */
  warnings: Array<{ code: string; message: string }> | null;
  assignBodies: unknown[];
  activated: string[];
  releaseBodies: Array<{ id: string; body: unknown }>;
  reactivateBodies: Array<{ id: string; body: unknown }>;
  /** When set, a history read that arrives while it is set waits for it. */
  gate: Promise<void> | null;
}

const fresh = (rows: Row[]): State => ({ rows, warnings: null, assignBodies: [], activated: [], releaseBodies: [], reactivateBodies: [], gate: null });

async function open(page: Page, st: State) {
  const mock = await mountPlatform(page, async (url, method, route) => {
    const p = url.pathname;
    if (p === `/cp/platform/tenants/${ACME.id}/hostnames` && method === "GET") {
      const gate = st.gate;
      if (gate) await gate;
      await route.fulfill({ json: { hostnames: st.rows } });
      return true;
    }
    if (p === `/cp/platform/tenants/${ACME.id}/hostnames` && method === "POST") {
      const body = route.request().postDataJSON() as { host: string; acknowledge: string[]; override_reason: string };
      st.assignBodies.push(body);
      if (st.warnings && body.acknowledge.length === 0) {
        await route.fulfill({ status: 409, json: { error: "label has lookalike warnings", warnings: st.warnings } });
        return true;
      }
      const created = row({ id: "new1", host: body.host, state: "pending", created_at: "2026-11-05T00:00:00Z" });
      st.rows.push(created);
      await route.fulfill({ status: 201, json: { hostname: created } });
      return true;
    }
    const m = /^\/cp\/platform\/hostnames\/([^/]+)\/(activate|release|reactivate)$/.exec(p);
    if (m && method === "POST") {
      const [, id, verb] = m;
      const body = route.request().postDataJSON();
      const r = st.rows.find((x) => x.id === id)!;
      if (verb === "activate") {
        st.activated.push(id);
        r.state = "active";
        r.activated_at = "2026-11-05T01:00:00Z";
        await route.fulfill({ json: { hostname: r } });
      } else if (verb === "release") {
        st.releaseBodies.push({ id, body });
        r.state = "released";
        r.released_at = "2026-11-05T02:00:00Z";
        r.quarantined_until = FAR_FUTURE;
        await route.fulfill({ json: { hostname: r } });
      } else {
        st.reactivateBodies.push({ id, body });
        const created = row({ id: "re1", host: r.host, state: (body as { activate: boolean }).activate ? "active" : "pending", created_at: "2026-11-05T03:00:00Z" });
        st.rows.push(created);
        await route.fulfill({ status: 201, json: { hostname: created } });
      }
      return true;
    }
    return false;
  });
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(page.getByTestId("platform-row-acme")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("platform-hostnames-acme").click();
  await expect(page.getByTestId("hostnames-root")).toBeVisible();
  return mock;
}

test("the history shows pending, active and quarantined states and only the actions that apply", async ({ page }) => {
  await open(
    page,
    fresh([
      row({ id: "old", host: "legacy.example.test", state: "released", released_at: "2026-09-01T00:00:00Z", quarantined_until: FAR_FUTURE }),
      row({ id: "live", host: "acme.example.test", state: "active", activated_at: "2026-10-02T00:00:00Z" }),
    ]),
  );
  await expect(page.getByTestId("hostname-status-live")).toHaveText("active");
  await expect(page.getByTestId("hostname-status-old")).toHaveText("quarantined until 2099-01-15");
  await expect(page.getByTestId("hostname-act-release-live")).toBeVisible();
  await expect(page.getByTestId("hostname-act-activate-live")).toHaveCount(0);
  // The tenant already holds a live host, so the released one cannot come back (the server would answer 409).
  await expect(page.getByTestId("hostname-act-reactivate-old")).toHaveCount(0);
});

test("assign asks in plain words, then sends the host and shows the pending row", async ({ page }) => {
  const st = fresh([]);
  await open(page, st);
  await page.getByTestId("hostname-assign-host").fill("acme-it.example.test");
  await page.getByTestId("hostname-assign-open").click();
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("PENDING assignment of acme-it.example.test");
  expect(st.assignBodies).toHaveLength(0);
  await page.getByTestId("hostname-confirm-submit").click();
  await expect(page.getByTestId("hostname-notice")).toContainText("Assigned acme-it.example.test (pending)");
  expect(st.assignBodies).toEqual([{ host: "acme-it.example.test", acknowledge: [], override_reason: "" }]);
  await expect(page.getByTestId("hostname-status-new1")).toHaveText("pending");
  await expect(page.getByTestId("hostname-confirm")).toHaveCount(0);
});

test("look-alike warnings must each be acknowledged with a reason before the assign is sent again", async ({ page }) => {
  const st = fresh([]);
  st.warnings = [
    { code: "idn_label", message: "label is an IDN" },
    { code: "skeleton_collision", message: "label is confusable with acme" },
  ];
  await open(page, st);
  await page.getByTestId("hostname-assign-host").fill("xn--acme.example.test");
  await page.getByTestId("hostname-assign-open").click();
  await page.getByTestId("hostname-confirm-submit").click();
  await expect(page.getByTestId("hostname-warnings")).toContainText("skeleton_collision");
  const submit = page.getByTestId("hostname-confirm-submit");
  await expect(submit).toBeDisabled();
  await page.getByTestId("hostname-warn-ack-idn_label").check();
  await page.getByTestId("hostname-confirm-reason").fill("verified with the customer");
  await expect(submit).toBeDisabled(); // one warning is still unacknowledged
  await page.getByTestId("hostname-warn-ack-skeleton_collision").check();
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(page.getByTestId("hostname-notice")).toContainText("Assigned");
  expect(st.assignBodies[1]).toEqual({ host: "xn--acme.example.test", acknowledge: ["idn_label", "skeleton_collision"], override_reason: "verified with the customer" });
});

test("activate says what it makes live, then activates the same row", async ({ page }) => {
  const st = fresh([row({ id: "p1", state: "pending" })]);
  await open(page, st);
  await page.getByTestId("hostname-act-activate-p1").click();
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("Makes acme.example.test live");
  expect(st.activated).toEqual([]);
  await page.getByTestId("hostname-confirm-submit").click();
  await expect(page.getByTestId("hostname-status-p1")).toHaveText("active");
  expect(st.activated).toEqual(["p1"]);
});

test("release needs a reason, says what it does to guests, and leaves the host quarantined", async ({ page }) => {
  const st = fresh([row({ id: "live", state: "active" })]);
  await open(page, st);
  await page.getByTestId("hostname-act-release-live").click();
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("neutral DeskRally page");
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("30 days");
  const submit = page.getByTestId("hostname-confirm-submit");
  await expect(submit).toBeDisabled();
  await page.getByTestId("hostname-confirm-reason").fill("   ");
  await expect(submit).toBeDisabled();
  await page.getByTestId("hostname-confirm-reason").fill("customer left");
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(page.getByTestId("hostname-status-live")).toHaveText("quarantined until 2099-01-15");
  expect(st.releaseBodies).toEqual([{ id: "live", body: { reason: "customer left" } }]);
  // Once released, the host can be brought back.
  await expect(page.getByTestId("hostname-act-reactivate-live")).toBeVisible();
});

test("reactivate says the approval is lost, and sends whether to activate at once", async ({ page }) => {
  const st = fresh([row({ id: "old", state: "released", released_at: "2026-09-01T00:00:00Z", quarantined_until: FAR_FUTURE })]);
  await open(page, st);
  await page.getByTestId("hostname-act-reactivate-old").click();
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("NEW assignment");
  await expect(page.getByTestId("hostname-confirm-effect")).toContainText("approved again");
  await page.getByTestId("hostname-confirm-activate").check();
  await page.getByTestId("hostname-confirm-submit").click();
  await expect(page.getByTestId("hostname-notice")).toContainText("new active assignment");
  expect(st.reactivateBodies).toEqual([{ id: "old", body: { activate: true } }]);
  await expect(page.getByTestId("hostname-status-re1")).toHaveText("active");
});

test("cancelling a confirmation sends nothing", async ({ page }) => {
  const st = fresh([row({ id: "p1", state: "pending" })]);
  await open(page, st);
  await page.getByTestId("hostname-act-release-p1").click();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByTestId("hostname-confirm")).toHaveCount(0);
  expect(st.releaseBodies).toHaveLength(0);
});

test("access that expires while the history is open removes it, and a read still in flight cannot bring it back", async ({ page }) => {
  const st = fresh([row({ id: "live", host: "acme.example.test", state: "active", activated_at: "2026-10-02T00:00:00Z" })]);
  const mock = await open(page, st);
  await expect(page.getByTestId("hostname-status-live")).toHaveText("active");
  // The history's own refresh is parked on the server.
  let release!: () => void;
  st.gate = new Promise<void>((r) => (release = r));
  await page.getByTestId("hostnames-root").getByRole("button", { name: "Refresh", exact: true }).click();
  // The read window expires (operator still, second factor older than 12 h); the panel's refresh finds out.
  mock.me = { operator: true, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).last().click();
  await expect(page.getByTestId("platform-stepup")).toBeVisible();
  await expect(page.getByTestId("hostnames-root")).toHaveCount(0);
  await expect(page.getByTestId("platform-row-acme")).toHaveCount(0);
  // The parked read now lands: nothing comes back.
  st.gate = null;
  release();
  await page.waitForTimeout(300);
  await expect(page.getByTestId("hostnames-root")).toHaveCount(0);
  await expect(page.getByTestId("hostname-row-live")).toHaveCount(0);
  // A step-up restores the LISTING only; the history is opened again on purpose.
  await page.getByTestId("platform-stepup-code").fill("123456");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("platform-row-acme")).toBeVisible();
  await expect(page.getByTestId("hostnames-root")).toHaveCount(0);
});

test("access that is revoked while the history is open removes it", async ({ page }) => {
  const mock = await open(page, fresh([row({ id: "live", state: "active" })]));
  mock.me = { operator: false, mfa_ok: false, mfa_fresh: false };
  await page.getByRole("button", { name: "Refresh", exact: true }).last().click();
  await expect(page.getByTestId("platform-not-operator")).toBeVisible();
  await expect(page.getByTestId("hostnames-root")).toHaveCount(0);
});
