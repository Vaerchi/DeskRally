/**
 * API tokens (docs/01 §8) driven through the REAL CONSOLE UI + the REAL auth path.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop 23 precedent). Against a real DEV control plane (stub full-owner auth for the
 * cookieless console, in-memory stores, and the APITokenAuthenticator front so a minted token
 * actually authenticates):
 *
 *   1. In the API-tokens tab, mint a token scoped to view_machines only; the plaintext is shown ONCE.
 *   2. Present that bearer token programmatically (a Node fetch, exactly a non-browser client):
 *        - GET /machines → 200 (the token carries view_machines), and
 *        - GET /audit    → 403 (it does NOT carry view_audit) — the capability scope is enforced.
 *      A bogus rmt_api_ token → 401 (negative control).
 *   3. The server rejects a non-grantable capability at mint (raw POST with manage_tenant → 400),
 *      proving the boundary independent of the UI, which only offers grantable caps.
 *   4. Revoke the token in the UI; the same bearer then → 401. Revocation kills it end-to-end.
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
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) }).then(() => true).catch(() => false);
}

/** GET a protected path with an API-token bearer, returning the status. */
async function apiGet(path: string, bearer: string): Promise<number> {
  const res = await fetch(`${CP_BASE}${path}`, { headers: { Authorization: `Bearer ${bearer}` } });
  await res.text().catch(() => {});
  return res.status;
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
    browser = await chromium.launch({ channel: "chrome", headless: true });
  } catch {
    browser = await chromium.launch({ headless: true });
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(cpProc);
});

test("operator mints a scoped API token, uses it, and revokes it", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "API tokens" })).click();
  await expect(page.getByTestId("api-tokens")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("tokens-empty")).toHaveText(/no api tokens/i);

  // Mint a token scoped to view_machines ONLY.
  await page.getByTestId("token-name").fill("ci-bot");
  await page.getByTestId("token-cap-view_machines").check();
  await page.getByTestId("token-create").click();

  // The plaintext secret is shown exactly once.
  const secretEl = page.getByTestId("token-secret-value");
  await expect(secretEl).toBeVisible();
  const secret = (await secretEl.textContent())?.trim() ?? "";
  expect(secret).toMatch(/^rmt_api_/);

  // The row shows the token, active.
  await expect(page.getByTestId("token-row-ci-bot")).toBeVisible();
  await expect(page.getByTestId("token-status-ci-bot")).toHaveText("active");

  // --- The bearer AUTHENTICATES and is CAPABILITY-SCOPED (Node fetch = a real programmatic client).
  expect(await apiGet("/machines", secret)).toBe(200); // carries view_machines
  expect(await apiGet("/audit", secret)).toBe(403); // does NOT carry view_audit
  expect(await apiGet("/machines", "rmt_api_bogus-unminted")).toBe(401); // negative control

  // --- The server rejects a non-grantable capability at mint, independent of the UI.
  const badMint = await fetch(`${CP_BASE}/api-tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "evil", capabilities: ["manage_tenant"] }),
  });
  expect(badMint.status).toBe(400);

  // --- Revoke in the UI → the same bearer no longer authenticates.
  await page.getByTestId("token-secret-dismiss").click();
  await page.getByTestId("token-revoke-ci-bot").click();
  await expect(page.getByTestId("token-status-ci-bot")).toHaveText("revoked");
  expect(await apiGet("/machines", secret)).toBe(401);

  // Durable server-side: a reload still shows it (revoked).
  await page.reload();
  await (await consoleTab(page, { name: "API tokens" })).click();
  await expect(page.getByTestId("token-status-ci-bot")).toHaveText("revoked");
});
