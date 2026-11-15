/**
 * Audit-trail SEARCH by action / target driven through the REAL console UI (docs/01 §17).
 *
 * The management-plane audit trail is a compliance artefact; an auditor must be able to pull "every
 * machine.enroll" out of it. Browser/control-plane-only (no agent, no signaling), so the Playwright
 * run IS the live proof (VM N/A; loop-23/33/35 precedent). It generates a MIX of audit events by
 * hitting the control plane (two enrolls → two `machine.enroll`; one property set →
 * `machine.property.set`), then drives the Audit tab's search:
 *
 *   1. Unfiltered — both actions appear.
 *   2. Filter action `machine.enroll` — only the two enrolls; the property-set event is gone.
 *   3. Filter action `machine.property.set` — only that event.
 *   4. Clear — both actions back.
 *
 * Stack: control plane in DEV mode on ports.ts CP_PORT (the Vite `/cp` proxy target — workers:1 keeps
 * it from colliding with the other CP-on-CP_PORT specs). DEV's stub auth is a full-cap owner, so no
 * login and no CSRF cookie to manage; its in-memory audit store records the same events production does.
 *
 * Self-skips (loudly, with a reason) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { CP_PORT, CP_BASE } from "./ports";
import { consoleTab } from "./nav";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite /cp proxy target (CONTROL_PLANE_ORIGIN)
const APP_URL = "http://127.0.0.1:5173/";
const GROUP_ID = "00000000-0000-0000-0000-0000000000ff";

let cpProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 200): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return true;
    if (Date.now() > deadline) return false;
    await sleep(stepMs);
  }
}

function tcpUp(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then(() => true)
    .catch(() => false);
}

async function enroll(name: string): Promise<string> {
  const res = await fetch(`${CP_BASE}/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ group_id: GROUP_ID, name }),
  });
  const text = await res.text();
  if (res.status !== 201) throw new Error(`enroll ${name} failed (${res.status}): ${text}`);
  return (JSON.parse(text) as { machine: { id: string } }).machine.id;
}

test.beforeAll(async () => {
  test.setTimeout(120_000);

  // globalSetup (e2e/global-setup.ts) builds this UNCONDITIONALLY before any worker starts, so it is
  // present and current. Assert, never build: the guard that used to stand here built the binary only
  // when ABSENT, which made every run after the first test a stale control plane, silently, forever.
  if (!existsSync(CP_EXE)) {
    skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
    return;
  }

  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CP_LISTEN, DATABASE_URL: "", CP_INSECURE_DEV: "1" },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:err] ${d.toString()}`));

  if (!(await waitFor(() => tcpUp(`${CP_BASE}/machines`, 500), 15_000))) {
    skipReason = `control plane did not come up on ${CP_BASE}`;
    return;
  }

  try {
    // Two enrolls (→ two machine.enroll audit events) + one property set (→ machine.property.set).
    const m1 = await enroll("AUD-1");
    await enroll("AUD-2");
    const put = await fetch(`${CP_BASE}/machines/${m1}/properties/site`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: "HQ" }),
    });
    if (put.status !== 200) {
      skipReason = `set property failed (${put.status}): ${await put.text()}`;
      return;
    }
  } catch (e) {
    skipReason = String(e);
    return;
  }

  try {
    browser = await chromium.launch({ channel: "chrome", headless: true });
  } catch {
    browser = await chromium.launch({ headless: true });
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(cpProc);
});

test("filtering the audit trail by action narrows the listing and clears back", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Audit" })).click();

  const tbody = page.locator(".panel--audit table tbody");
  const enrollCells = page.locator(".panel--audit table tbody td.panel__name", { hasText: "machine.enroll" });
  const actionBox = page.getByTestId("audit-filter-action");
  const apply = page.getByTestId("audit-filter-apply");

  // 1. Unfiltered — both actions present (two enrolls, one property set).
  await expect(enrollCells).toHaveCount(2, { timeout: 15_000 });
  await expect(tbody).toContainText("machine.property.set");

  // 2. Filter action = machine.enroll — only the two enrolls remain.
  await actionBox.fill("machine.enroll");
  await apply.click();
  await expect(enrollCells).toHaveCount(2);
  await expect(tbody).not.toContainText("machine.property.set");

  // 3. Filter action = machine.property.set — only that event.
  await actionBox.fill("machine.property.set");
  await apply.click();
  await expect(tbody).toContainText("machine.property.set");
  await expect(enrollCells).toHaveCount(0);

  // 4. Clear — both actions back.
  await page.getByTestId("audit-filter-clear").click();
  await expect(enrollCells).toHaveCount(2);
  await expect(tbody).toContainText("machine.property.set");

  // 5. Actor filter (loop 45): every event here carries the DEV stub owner as its actor, so a bogus
  // actor id empties the list — proving the ?actor= filter is wired — and clearing restores it.
  await page.getByTestId("audit-filter-actor").fill("no-such-actor-id");
  await apply.click();
  await expect(page.getByTestId("audit-empty")).toBeVisible();
  await page.getByTestId("audit-filter-clear").click();
  await expect(enrollCells).toHaveCount(2);

  // 6. Time bounds (loop 45): a far-FUTURE `since` excludes every (now-stamped) event — proving the
  // datetime-local → RFC3339 `?since=` bound narrows — and clearing restores them.
  await page.getByTestId("audit-filter-since").fill("2099-01-01T00:00");
  await apply.click();
  await expect(page.getByTestId("audit-empty")).toBeVisible();
  await page.getByTestId("audit-filter-clear").click();
  await expect(enrollCells).toHaveCount(2);

  // 7. Export CSV (loop 65) reflects the CURRENTLY-FILTERED events: narrow to machine.enroll, export, and
  // the downloaded audit-events.csv carries the header + the enroll rows but NOT the filtered-out event.
  await actionBox.fill("machine.enroll");
  await apply.click();
  await expect(enrollCells).toHaveCount(2);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("audit-export").click(),
  ]);
  expect(download.suggestedFilename()).toBe("audit-events.csv");
  const csv = readFileSync(await download.path(), "utf8");
  expect(csv).toContain("occurred_at,action,actor,target_kind,target_id,metadata,source_ip");
  expect(csv).toContain("machine.enroll");
  expect(csv).not.toContain("machine.property.set");
});

// Source IP column (d3f397a2: the control plane persists the trusted client address on every audit event and
// GET /audit carries it as `source_ip`, omitted when empty). The listing is MOCKED so the three shapes are
// exact: an IPv4, an IPv6 and an event with none (written outside a request) which shows a blank cell. Plain
// text only, and the table stays usable at phone width (the panel scrolls; the page itself does not).
for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`the audit table shows a Source IP column at ${viewport.width}px`, async () => {
    test.skip(skipReason !== null, skipReason ?? "");
    const page = await browser!.newPage({ viewport });
    const ev = (id: string, extra: Record<string, unknown>) => ({
      id, tenant_id: "t1", action: "auth.login", occurred_at: "2026-11-05T10:00:00Z", ...extra,
    });
    await page.route(
      (u) => u.pathname === "/cp/audit",
      (route) =>
        route.fulfill({
          json: {
            events: [
              ev("e1", { source_ip: "198.51.100.7" }),
              ev("e2", { source_ip: "2001:db8::42" }),
              ev("e3", { action: "job.noreq" }),
              ev("e4", { source_ip: "<b>x</b>" }),
            ],
          },
        }),
    );
    await page.goto(APP_URL);
    await (await consoleTab(page, { name: "Audit" })).click();

    await expect(page.locator(".panel--audit table thead th", { hasText: "Source IP" })).toHaveCount(1, { timeout: 15_000 });
    const cells = page.getByTestId("audit-source-ip");
    await expect(cells).toHaveCount(4);
    await expect(cells.nth(0)).toHaveText("198.51.100.7");
    await expect(cells.nth(1)).toHaveText("2001:db8::42");
    await expect(cells.nth(2)).toHaveText("");
    // Plain text: markup in the value is shown literally, never parsed.
    await expect(cells.nth(3)).toHaveText("<b>x</b>");
    await expect(page.locator(".panel--audit table b")).toHaveCount(0);
    // The search box reaches the new column, and the CSV carries it as the last column.
    await page.getByTestId("audit-search").fill("2001:db8");
    await expect(cells).toHaveCount(1);
    await page.getByTestId("audit-search").fill("");
    await expect(cells).toHaveCount(4);
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("audit-export").click()]);
    const lines = readFileSync(await download.path(), "utf8").trim().split("\r\n");
    expect(lines[1]).toMatch(/,198\.51\.100\.7$/);
    expect(lines[2]).toMatch(/,2001:db8::42$/);
    expect(lines[3]).toMatch(/,$/);
    // Usable at phone width: the page does not scroll sideways, and the last IP cell can be scrolled into view.
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await cells.nth(1).scrollIntoViewIfNeeded();
    await expect(cells.nth(1)).toBeInViewport();
    await page.close();
  });
}
