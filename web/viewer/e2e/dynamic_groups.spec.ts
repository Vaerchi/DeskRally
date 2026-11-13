/**
 * Dynamic machine groups driven through the REAL CONSOLE UI (docs/01 §4).
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof (VM
 * N/A; loop 23 precedent). Against a real DEV control plane (stub full-owner auth, in-memory stores):
 *
 *   1. Seed two machines (POST /enroll) and tag ONE with site=HQ (PUT .../properties/site).
 *   2. In the Groups tab, create a dynamic group keyed on site=HQ.
 *   3. Resolve its members and assert it contains ONLY the tagged machine — the live predicate.
 *   4. Delete the group and assert it is gone.
 *
 * Self-skips (loudly) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
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
const CP_LISTEN = `127.0.0.1:${CP_PORT}`;
const APP_URL = "http://127.0.0.1:5173/";
const GROUP_ID = "00000000-0000-0000-0000-0000000000dd"; // dev owner holds AllGroups()

let cpProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let hqName = "";
let otherName = "";

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

test.beforeAll(async () => {
  test.setTimeout(120_000);
  // globalSetup (e2e/global-setup.ts) builds this UNCONDITIONALLY before any worker starts, so it is
  // present and current. Assert, never build: the guard that used to stand here built the binary only
  // when ABSENT, which made every run after the first test a stale control plane, silently, forever.
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
    // Two machines; tag ONLY the first with site=HQ (unique names so the members list is unambiguous).
    hqName = `HQ-BOX-${Date.now()}`;
    otherName = `OTHER-BOX-${Date.now()}`;
    const hqPk = await enroll(hqName);
    await enroll(otherName);
    await setProp(hqPk, "site", "HQ");
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

test("operator creates a dynamic group and resolves its live members", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Smart groups", exact: true })).click();
  await expect(page.getByTestId("dynamic-groups")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("groups-empty")).toHaveText(/no dynamic groups/i);

  // Create a group keyed on site=HQ.
  await page.getByTestId("group-name").fill("HQ machines");
  await page.getByTestId("group-key").fill("site");
  await page.getByTestId("group-value").fill("HQ");
  await page.getByTestId("group-add").click();
  await expect(page.getByTestId("group-row-HQ machines")).toBeVisible();

  // A duplicate name is refused inline (409 surfaced as the panel error).
  await page.getByTestId("group-name").fill("HQ machines");
  await page.getByTestId("group-key").fill("x");
  await page.getByTestId("group-add").click();
  await expect(page.getByTestId("group-error")).toContainText(/already exists/i);

  // Resolve members: ONLY the tagged machine appears (the live predicate, narrowed to visible).
  await page.getByTestId("group-resolve-HQ machines").click();
  const members = page.getByTestId("group-members");
  await expect(members).toContainText("Members (1)");
  await expect(members).toContainText(hqName);
  await expect(members).not.toContainText(otherName);

  // Delete the group → back to empty, and a reload proves it is durable server-side.
  await page.getByTestId("group-delete-HQ machines").click();
  await expect(page.getByTestId("groups-empty")).toBeVisible();
  await page.reload();
  await (await consoleTab(page, { name: "Smart groups", exact: true })).click();
  await expect(page.getByTestId("groups-empty")).toHaveText(/no dynamic groups/i);
});
