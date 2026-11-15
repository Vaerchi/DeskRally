/**
 * Backstage panels — an action that finishes after the operator switched tab, mocked-API browser
 * regressions.
 *
 * A kill/service-control awaits the agent (and possibly a confirm dialog) before its completion
 * handler re-lists the panel. If the operator switches tab meanwhile, that re-list must load the tab
 * now on screen. Reloading the tab the action started from takes the newest load sequence, supersedes
 * the current tab's listing, and leaves the old tab's response under the new tab's renderer.
 *
 *   1. A kill that succeeds after a switch to Services re-lists SERVICES: the post-action request is
 *      ListServices, the service rows stay visible, and no process rows appear.
 *   2. A kill that FAILS after the switch triggers no re-list at all; the error is shown and the
 *      service rows stay.
 *
 * The page mounts the real BackstagePanels with its default client (POST /backstage/exec on this
 * origin, see backstage_panels.tsx). Every request is answered here; KillProcess is held until the
 * test releases it. A released response is confirmed delivered, then the page is flushed, before any
 * assertion about what followed it — no fixed sleeps. Loopback only.
 * Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const PROCESSES = [
  { pid: 4242, parent_pid: null, name: "proc-alpha.exe", cpu_percent: 0, memory_bytes: 1024, user: "u", command_line: null },
  { pid: 4343, parent_pid: null, name: "proc-beta.exe", cpu_percent: 0, memory_bytes: 2048, user: "u", command_line: null },
];
const SERVICES = [
  { name: "Spooler", display_name: "Print Spooler", state: "running", pid: 2140 },
  { name: "Dnscache", display_name: "DNS Client", state: "running", pid: 1284 },
];

/** A request held by the mock until released. */
class Hold {
  arrived = false;
  private resolve!: () => void;
  readonly gate = new Promise<void>((r) => (this.resolve = r));
  release() {
    this.resolve();
  }
}

async function mount(page: Page, killOutcome: "ok" | "fail") {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const kill = new Hold();
  const seen: string[] = []; // backstage request types, in arrival order
  let killDelivered = false;

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== baseUrl.origin) {
      await route.abort();
      return;
    }
    if (url.pathname !== "/backstage/exec") {
      await route.continue();
      return;
    }
    const type = (JSON.parse(route.request().postData() ?? "{}") as { type?: string }).type ?? "?";
    seen.push(type);
    const reply = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (type === "ListProcesses") await reply({ ok: true, response: { type: "ProcessList", data: PROCESSES } });
    else if (type === "ListServices") await reply({ ok: true, response: { type: "ServiceList", data: SERVICES } });
    else if (type === "KillProcess") {
      kill.arrived = true;
      await kill.gate;
      await reply(
        killOutcome === "ok"
          ? { ok: true, response: { type: "Ack" } }
          : { ok: false, error: { kind: "refused", message: "access denied by test" } },
      );
      killDelivered = true;
    } else await reply({ ok: false, error: { kind: "exec_failed", message: `unexpected ${type}` } });
  });

  await page.goto(new URL("/e2e/backstage_panels.html", baseUrl).toString());
  return { kill, seen, killDelivered: () => killDelivered };
}

/** Start a kill on proc-alpha, then switch to Services while the kill is held. */
async function killThenSwitch(page: Page, m: Awaited<ReturnType<typeof mount>>) {
  const alpha = page.locator("tr", { has: page.locator("td.panel__name", { hasText: "proc-alpha.exe" }) });
  await expect(alpha).toBeVisible();
  await alpha.locator("button.panel__action--danger").click();
  await expect.poll(() => m.kill.arrived).toBe(true);

  await page.getByRole("tab", { name: "Services" }).click();
  await expect(page.locator("td.panel__name", { hasText: "Print Spooler" })).toBeVisible();
  return m.seen.length; // requests issued before the kill completes
}

/** Flush the page's task queue so any work scheduled by a delivered response has run. */
async function flush(page: Page) {
  await page.evaluate(() => new Promise((r) => setTimeout(r, 0)));
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))));
}

test("a kill that succeeds after a tab switch re-lists the CURRENT tab", async ({ page }) => {
  const m = await mount(page, "ok");
  const before = await killThenSwitch(page, m);

  m.kill.release();
  await expect.poll(m.killDelivered).toBe(true);
  await expect.poll(() => m.seen.length).toBeGreaterThan(before);
  await flush(page);

  expect(m.seen.slice(before)).toEqual(["ListServices"]);
  await expect(page.getByRole("tab", { name: "Services" })).toHaveAttribute("aria-selected", "true");
  await expect(page.locator("td.panel__name", { hasText: "Print Spooler" })).toBeVisible();
  await expect(page.locator("td.panel__name", { hasText: "proc-alpha.exe" })).toHaveCount(0);
});

test("a kill that fails after a tab switch does not re-list and keeps the current tab", async ({ page }) => {
  const m = await mount(page, "fail");
  const before = await killThenSwitch(page, m);

  m.kill.release();
  await expect.poll(m.killDelivered).toBe(true);
  await expect(page.getByRole("alert")).toContainText("access denied by test");
  await flush(page);

  expect(m.seen.slice(before)).toEqual([]);
  await expect(page.locator("td.panel__name", { hasText: "Print Spooler" })).toBeVisible();
  await expect(page.locator("td.panel__name", { hasText: "proc-alpha.exe" })).toHaveCount(0);
});
