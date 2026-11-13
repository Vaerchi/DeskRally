/**
 * Tenant 2FA requirement policy driven through the REAL CONSOLE UI (docs/01 §10, marathon R71).
 *
 * This is a BROWSER + control-plane feature — no agent, no signaling — so the Playwright run IS the
 * live proof. It drives the operator flow end to end against a real control plane in DEV mode.
 *
 * DEV mode seeds a stub owner with TOTPConfirmed=false, which means the anti-lockout guard on
 * PUT /tenant/security-policy fires immediately when require_2fa=true is requested. The three
 * things this spec proves:
 *
 *   1. On load: the 2FA checkbox is present and unchecked (default policy = not required).
 *   2. Anti-lockout guard: toggling the checkbox to "on" when the caller has no TOTP enrolled
 *      produces a visible inline error ("you must have TOTP enrolled …") and the checkbox rolls
 *      back to unchecked — the server refused the change and the UI state is coherent.
 *   3. Durability sanity: a page reload still shows the checkbox unchecked, confirming the server
 *      never persisted the rejected change.
 *
 * Mutation evidence:
 *   M1: remove setError2fa(err…) in handleToggle2fa → 2fa-policy-error never rendered → test 2 fails
 *   M2: remove anti-lockout check in http_tenant_security.go → no 400 → checkbox stays checked after
 *       toggle → test 2/3 fail (require_2fa would actually be saved as true)
 *   M3: if setRequire2fa were called on the error path → checkbox checked after error → test 2/3 fail
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

test.beforeAll(async () => {
  test.setTimeout(120_000);

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
    browser = await chromium.launch({ channel: "chrome", headless: true });
  } catch {
    browser = await chromium.launch({ headless: true });
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(cpProc);
});

test("2FA checkbox is unchecked by default (policy not required on a fresh tenant)", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });

  const checkbox = page.getByTestId("require-2fa-checkbox");
  await expect(checkbox).toBeVisible();
  await expect(checkbox).not.toBeChecked();
});

test("anti-lockout guard: enabling require_2fa without TOTP enrolled shows an error and rolls back the checkbox", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });

  const checkbox = page.getByTestId("require-2fa-checkbox");
  await expect(checkbox).not.toBeChecked();

  // Toggle on — DEV stub owner has TOTPConfirmed=false, so the server returns 400.
  await checkbox.click();

  // The anti-lockout error must appear.
  await expect(page.getByTestId("2fa-policy-error")).toContainText(/totp enrolled/i);

  // The checkbox must be rolled back to unchecked (setRequire2fa is only called on success).
  await expect(checkbox).not.toBeChecked();
});

test("require_2fa rejected change is not persisted: checkbox stays unchecked after reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });

  // Attempt the rejected toggle.
  await page.getByTestId("require-2fa-checkbox").click();
  await expect(page.getByTestId("2fa-policy-error")).toContainText(/totp enrolled/i);

  // Reload and confirm the server never committed the change.
  await page.reload();
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("require-2fa-checkbox")).not.toBeChecked();
});
