/**
 * Fleet SEARCH/FILTER by custom property, driven through the REAL console UI (docs/01 §4).
 *
 * Loop 33 gave machines custom properties; loop 35 lets an operator find machines BY one. This is a
 * browser/control-plane-only feature (no agent, no signaling), so the Playwright run IS the live proof
 * (VM N/A; loop-23 precedent). It enrolls TWO machines, tags ONE with `site=HQ`, then drives the
 * Machines tab's property search and asserts the listing NARROWS to the tagged machine and back:
 *
 *   1. Unfiltered — BOTH machines are listed.
 *   2. Filter key `site` (any value) — only the tagged machine remains.
 *   3. Filter `site` = `HQ` — still only the tagged machine.
 *   4. Filter `site` = a value nobody has — the empty state says "no machines match".
 *   5. Clear — BOTH machines are back.
 *
 * Stack: control plane in DEV mode on ports.ts CP_PORT (the Vite `/cp` proxy target — workers:1 keeps
 * it from colliding with the other CP-on-CP_PORT specs). DEV's stub auth is a full-cap owner, so no
 * login and no CSRF cookie to manage.
 *
 * Self-skips (loudly, with a reason) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
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
const GROUP_ID = "00000000-0000-0000-0000-0000000000ee";

let cpProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let hqMachine = ""; // tagged site=HQ
let drMachine = ""; // untagged

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
    hqMachine = await enroll("HQ-BOX");
    drMachine = await enroll("DR-BOX");
    // Tag ONLY the HQ machine with site=HQ (PUT /machines/{id}/properties/{key} body {value}).
    const put = await fetch(`${CP_BASE}/machines/${hqMachine}/properties/site`, {
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

test("filtering the fleet by a custom property narrows the listing and clears back", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Machines" })).click();

  const hqRow = page.getByTestId(`machine-props-${hqMachine}`);
  const drRow = page.getByTestId(`machine-props-${drMachine}`);
  const keyBox = page.getByTestId("machine-filter-key");
  const valBox = page.getByTestId("machine-filter-value");
  const apply = page.getByTestId("machine-filter-apply");

  // 1. Unfiltered — both machines listed.
  await expect(hqRow).toBeVisible({ timeout: 15_000 });
  await expect(drRow).toBeVisible();

  // 2. Filter by key `site` (any value) — only the tagged machine remains.
  await keyBox.fill("site");
  await apply.click();
  await expect(hqRow).toBeVisible();
  await expect(drRow).toHaveCount(0);
  await expect(page.getByTestId("machine-filter-active")).toBeVisible();

  // 3. Filter `site` = `HQ` — still only the tagged machine.
  await valBox.fill("HQ");
  await apply.click();
  await expect(hqRow).toBeVisible();
  await expect(drRow).toHaveCount(0);

  // 4. A value nobody has — the empty state says so, and neither machine is listed.
  await valBox.fill("NOWHERE");
  await apply.click();
  await expect(page.getByTestId("machines-empty")).toHaveText(/no machines match/i);
  await expect(hqRow).toHaveCount(0);
  await expect(drRow).toHaveCount(0);

  // 5. Clear — both machines are back.
  await page.getByTestId("machine-filter-clear").click();
  await expect(hqRow).toBeVisible();
  await expect(drRow).toBeVisible();
});

test("a bulk selection is CONFINED to the visible rows — filtering away a selected machine deselects it", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-props-${hqMachine}`)).toBeVisible({ timeout: 15_000 });

  // Select BOTH machines (unfiltered) → the toolbar reports two selected.
  await page.getByTestId(`bulk-check-${hqMachine}`).check();
  await page.getByTestId(`bulk-check-${drMachine}`).check();
  await expect(page.getByTestId("bulk-selected-count")).toHaveText("2 selected");

  // Filter by `site` so ONLY the HQ machine remains visible — the DR machine drops off screen AND out of
  // the selection (the review-caught safety fix): the count falls to one, so a bulk apply cannot silently
  // hit the now-hidden DR machine.
  await page.getByTestId("machine-filter-key").fill("site");
  await page.getByTestId("machine-filter-apply").click();
  await expect(page.getByTestId(`machine-props-${drMachine}`)).toHaveCount(0);
  await expect(page.getByTestId("bulk-selected-count")).toHaveText("1 selected");
  await expect(page.getByTestId(`bulk-check-${hqMachine}`)).toBeChecked();
});
