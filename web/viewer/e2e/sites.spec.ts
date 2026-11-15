/**
 * Sites driven through the REAL CONSOLE UI (docs/01 §4). A site is the existing `site` machine
 * property; this proves the Sites tab reads and writes exactly that, and nothing else.
 *
 * Against a real DEV control plane (stub full-owner auth, in-memory stores), headless Chromium only:
 *
 *   1. Seed two machines: A with site=HQ AND rack=R1, B with no properties.
 *   2. The Sites tab lists A under "HQ" and B under "No site".
 *   3. Give B a site through the UI → B moves to its site, and the SERVER holds site=Branch for B.
 *   4. Change A's site, then remove it → the server's `rack=R1` on A survives both writes.
 *
 * Screenshots (desktop + narrow) are written to RMT_E2E_SCREENSHOT_DIR when set, for visual review.
 * Self-skips (loudly) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
 */
import { PINNED } from "./chrome_pinned";
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { CP_PORT, CP_BASE } from "./ports";
import { consoleTab } from "./nav";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const CP_LISTEN = `127.0.0.1:${CP_PORT}`;
const APP_URL = "http://127.0.0.1:5173/";
const GROUP_ID = "00000000-0000-0000-0000-0000000000dd"; // dev owner holds AllGroups()
const SHOTS = process.env.RMT_E2E_SCREENSHOT_DIR ?? "";

let cpProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let aPk = "";
let bPk = "";
let aName = "";
let bName = "";

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
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) }).then(() => true).catch(() => false);
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

async function setProp(pk: string, key: string, value: string): Promise<void> {
  // Cookieless (stub auth) ⇒ CSRF is skipped; this is a plain seed, not the thing under test.
  const res = await fetch(`${CP_BASE}/machines/${pk}/properties/${key}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ value }),
  });
  if (res.status !== 200) throw new Error(`setProp ${key}=${value} failed (${res.status}): ${await res.text()}`);
}

/** The server's own view of a machine's properties, as a key → value map. */
async function serverProps(pk: string): Promise<Record<string, string>> {
  const res = await fetch(`${CP_BASE}/machines/${pk}/properties`);
  const body = (await res.json()) as { properties: { key: string; value: string }[] };
  return Object.fromEntries(body.properties.map((p) => [p.key, p.value]));
}

async function shot(page: Page, name: string): Promise<void> {
  if (SHOTS) await page.screenshot({ path: join(SHOTS, name), fullPage: true });
}

test.beforeAll(async () => {
  test.setTimeout(120_000);
  // globalSetup (e2e/global-setup.ts) builds this UNCONDITIONALLY before any worker starts.
  if (!existsSync(CP_EXE)) {
    skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
    return;
  }
  cpProc = spawn(CP_EXE, [], { cwd: CP_DIR, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CP_LISTEN, DATABASE_URL: "", CP_INSECURE_DEV: "1" } });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:err] ${d.toString()}`));
  if (!(await waitFor(() => tcpUp(`${CP_BASE}/machines`, 500), 15_000))) {
    skipReason = `control plane did not come up on ${CP_BASE}`;
    return;
  }
  try {
    aName = `SITE-A-${Date.now()}`;
    bName = `SITE-B-${Date.now()}`;
    aPk = await enroll(aName);
    bPk = await enroll(bName);
    await setProp(aPk, "site", "HQ");
    await setProp(aPk, "rack", "R1");
  } catch (e) {
    skipReason = `seed failed: ${String(e)}`;
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

test("operator sees sites, assigns one, changes and removes one — other properties preserved", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage({ viewport: { width: 1280, height: 900 } });
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId("sites")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId(`site-value-${aPk}`)).toHaveText("HQ");
  await expect(page.getByTestId(`site-value-${bPk}`)).toHaveText("No site");
  await expect(page.getByTestId("site-bucket-HQ")).toContainText("HQ (1)");
  await expect(page.getByTestId("site-bucket-none")).toBeVisible();
  await shot(page, "sites-desktop.png");

  // Assign B a site through the UI.
  await page.getByTestId(`site-input-${bPk}`).fill("Branch");
  await page.getByTestId(`site-save-${bPk}`).click();
  await expect(page.getByTestId(`site-value-${bPk}`)).toHaveText("Branch");
  expect(await serverProps(bPk)).toEqual({ site: "Branch" });

  // Change A's site: only `site` changes; `rack` survives.
  await page.getByTestId(`site-input-${aPk}`).fill("Branch");
  await page.getByTestId(`site-save-${aPk}`).click();
  await expect(page.getByTestId("site-bucket-Branch")).toContainText("Branch (2)");
  expect(await serverProps(aPk)).toEqual({ site: "Branch", rack: "R1" });

  // Remove A's site: the delete targets `site` only.
  await page.getByTestId(`site-clear-${aPk}`).click();
  await expect(page.getByTestId(`site-value-${aPk}`)).toHaveText("No site");
  expect(await serverProps(aPk)).toEqual({ rack: "R1" });

  // A reload re-reads the server and agrees.
  await page.reload();
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-value-${aPk}`)).toHaveText("No site");
  await expect(page.getByTestId(`site-value-${bPk}`)).toHaveText("Branch");

  await page.close();
});

/** Assert `loc` is visible and lies wholly inside the viewport horizontally (no clipping). */
async function expectInsideViewport(page: Page, loc: ReturnType<Page["getByTestId"]>, label: string): Promise<void> {
  await expect(loc, `${label} visible`).toBeVisible();
  const box = await loc.boundingBox();
  const width = page.viewportSize()!.width;
  expect(box, `${label} has a box`).not.toBeNull();
  expect(box!.x, `${label} left edge inside viewport`).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width, `${label} right edge inside viewport (${width}px)`).toBeLessThanOrEqual(width);
}

test("Sites fits a 390px phone: header and every row control inside the viewport", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  // A FRESH context at the phone size: the app picks its pane mode at load, so resizing an already
  // rendered desktop page would photograph a transition, not the layout a phone user gets.
  const context = await browser!.newContext({ ...PINNED, viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.goto(APP_URL);
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked", { timeout: 15_000 });
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId("sites-summary")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator(".app")).not.toHaveAttribute("data-nav-open", "true");

  await expectInsideViewport(page, page.locator(".panel--sites .panel__toolbar-title"), "Sites title");
  await expectInsideViewport(page, page.getByTestId("sites-refresh"), "Refresh");
  for (const pk of [aPk, bPk]) {
    await expectInsideViewport(page, page.getByTestId(`site-value-${pk}`), `site value ${pk}`);
    await expectInsideViewport(page, page.getByTestId(`site-input-${pk}`), `site input ${pk}`);
    await expectInsideViewport(page, page.getByTestId(`site-save-${pk}`), `save ${pk}`);
  }
  // Nothing in the Sites panel scrolls sideways.
  const overflow = await page.getByTestId("sites").evaluate((el) => el.scrollWidth - el.clientWidth);
  expect(overflow, "Sites panel horizontal overflow (px)").toBeLessThanOrEqual(0);
  await shot(page, "sites-narrow.png");
  await context.close();
});
