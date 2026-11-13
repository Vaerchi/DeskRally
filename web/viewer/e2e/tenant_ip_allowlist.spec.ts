/**
 * Per-tenant IP allow-list driven through the REAL CONSOLE UI (docs/01 §10).
 *
 * This is a BROWSER + control-plane feature — no agent, no signaling, no WebRTC — so the Playwright run
 * IS the live proof (VM is N/A; loop 23 precedent). It drives the operator flow end to end against a
 * real control plane in DEV mode (stub full-owner auth = holds CapManageTenant, no login/CSRF to manage):
 *
 *   1. Open the Security tab: the list is empty ("No restriction") and the panel shows the caller's
 *      current source IP (as the control plane sees it).
 *   2. Try to add a CIDR that EXCLUDES the caller (203.0.113.0/24, TEST-NET-3) — the server's
 *      anti-lockout safeguard refuses it (400 "lock you out") and the list stays empty. This is the
 *      whole point: an admin cannot fence themselves out of the API that manages the list.
 *   3. Add the caller's OWN IP (read from the panel) — it is accepted and rendered as a row.
 *   4. Remove it — back to the open state — and a reload proves the change is durable server-side.
 *
 * The enforcement 403 (a request from a NON-covered source) cannot be exercised from a browser (it
 * cannot spoof its own source IP / X-Forwarded-For), so that path is proven in Go
 * (control-plane/http_tenantipallow_test.go::TestTenantIPAllowlistEnforcement); this spec proves the
 * CRUD + anti-lockout UI.
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
const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite /cp proxy target
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

  // globalSetup (e2e/global-setup.ts) builds this UNCONDITIONALLY before any worker starts, so it is
  // present and current. Assert, never build: the guard that used to stand here built the binary only
  // when ABSENT, which made every run after the first test a stale control plane, silently, forever.
  if (!existsSync(CP_EXE)) {
    skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
    return;
  }

  // DEV mode (DATABASE_URL="" → stub full-owner auth, in-memory per-tenant allow-list store).
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
    browser = await chromium.launch({ headless: true }); // bundled chromium fallback
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(cpProc);
});

test("operator manages the per-tenant IP allow-list and the anti-lockout guard refuses a self-lockout", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
  // Empty list = the API is open; the panel shows the caller's current source IP.
  await expect(page.getByTestId("allowlist-empty")).toHaveText(/no restriction/i);
  await expect(page.getByTestId("allowlist-your-ip")).toContainText(/your current ip/i);

  const cidr = page.getByTestId("allowlist-cidr");
  const add = page.getByTestId("allowlist-add");

  // (1) Anti-lockout: adding a CIDR that excludes the caller (TEST-NET-3) is refused, and NO row is
  //     added — the safeguard, surfaced as the inline server error.
  await cidr.fill("203.0.113.0/24");
  await add.click();
  await expect(page.getByTestId("allowlist-error")).toContainText(/lock you out/i);
  await expect(page.getByTestId("allowlist-empty")).toBeVisible();

  // (2) Add the caller's OWN IP (read from the panel, so this is robust to how the browser reaches the
  //     control plane). It is accepted and rendered as a row; the empty-state disappears.
  const note = await page.getByTestId("allowlist-your-ip").innerText();
  const yourIp = note.replace(/^[^:]*:\s*/, "").trim();
  expect(yourIp.length).toBeGreaterThan(0);
  await cidr.fill(yourIp);
  await add.click();
  await expect(page.getByTestId("allowlist-empty")).toHaveCount(0);
  // Exactly one row now exists, and it renders the caller's IP as a normalized CIDR (e.g. .../32).
  const rows = page.locator('[data-testid^="allowlist-row-"]');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(yourIp);

  // (3) Remove the only entry (locate it by its testid prefix — the row testid embeds the normalized
  //     CIDR) → back to the open state.
  await page.locator('[data-testid^="allowlist-remove-"]').first().click();
  await expect(page.getByTestId("allowlist-empty")).toHaveText(/no restriction/i);

  // (4) A reload proves the change is DURABLE server-side (the list is genuinely empty again, not just
  //     local component state).
  await page.reload();
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("allowlist-empty")).toHaveText(/no restriction/i);
});

test("operator sets the tenant's concurrent-session limit and it persists (docs/01 §5 seat metering)", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
  // Default: no policy row → unlimited concurrency, no session time limit.
  await expect(page.getByTestId("session-limit-current")).toHaveText(/unlimited/i);
  await expect(page.getByTestId("session-maxage-current")).toHaveText(/no session time limit/i);

  // Set a concurrency cap of 3 AND a max session age of 7200s → both notes reflect the save.
  await page.getByTestId("session-limit-input").fill("3");
  await page.getByTestId("session-maxage-input").fill("7200");
  await page.getByTestId("session-limit-save").click();
  await expect(page.getByTestId("session-limit-current")).toHaveText(/limited to 3/i);
  await expect(page.getByTestId("session-maxage-current")).toHaveText(/after 7200s/i);

  // A reload proves both are DURABLE server-side, not local component state.
  await page.reload();
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("session-limit-current")).toHaveText(/limited to 3/i);
  await expect(page.getByTestId("session-limit-input")).toHaveValue("3");
  await expect(page.getByTestId("session-maxage-current")).toHaveText(/after 7200s/i);
  await expect(page.getByTestId("session-maxage-input")).toHaveValue("7200");

  // A too-short max age (< 60s, not 0) is refused by the server → an inline error, no change persisted.
  await page.getByTestId("session-maxage-input").fill("5");
  await page.getByTestId("session-limit-save").click();
  await expect(page.getByTestId("session-limit-error")).toContainText(/max_session_seconds/i);

  // Back to no limits (0/0) — cleanup + proves the toggle both ways.
  await page.getByTestId("session-limit-input").fill("0");
  await page.getByTestId("session-maxage-input").fill("0");
  await page.getByTestId("session-limit-save").click();
  await expect(page.getByTestId("session-limit-current")).toHaveText(/unlimited/i);
  await expect(page.getByTestId("session-maxage-current")).toHaveText(/no session time limit/i);
});
