/**
 * Enrollment tokens (docs/01 §4/§6) driven through the REAL CONSOLE UI — minting the group-scoped
 * secrets an installer redeems to deploy a NEW agent.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop 23 precedent). Against a real DEV control plane (stub full-owner auth, in-memory
 * enrollment-token store):
 *
 *   1. In the Deploy tab, mint a token for a machine group with an expiry + a use cap.
 *   2. The plaintext secret is shown ONCE (handed to the agent installer out of band).
 *   3. The token appears in the list — active, uses 0 / cap — and survives a reload (durable server-side).
 *   4. Revoke it in the UI → the row flips to "revoked".
 *
 * (Redemption — an installer consuming the token to enroll — is the agent's flow, covered by the Go
 * enrollment tests; this proves the console mint/list/revoke surface.)
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
// In DEV the stub owner holds AllGroups(), so any group it creates is authorized; the in-memory
// enrollment store does not FK-check the group id (the pg store does — that boundary is Go-tested).

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

test("operator mints, inspects, and revokes an enrollment token", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  // A token is minted FOR a machine group, so create one first — the Deploy picker lists the tenant's
  // groups (no more pasting a uuid).
  const GROUP_NAME = "Deploy Group";
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("mgroup-name").fill(GROUP_NAME);
  await page.getByTestId("mgroup-create").click();
  await expect(page.getByTestId("machine-groups").locator('[data-testid^="mgroup-row-"]').getByText(GROUP_NAME)).toBeVisible();

  await (await consoleTab(page, { name: "Install DeskRally" })).click();
  await expect(page.getByTestId("enrollment-tokens")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("enroll-tokens-empty")).toHaveText(/no enrollment tokens/i);

  // Pick the group by NAME from the dropdown (enabled once the group list loads), 7 days, usable 3 times.
  await expect(page.getByTestId("enroll-group")).toBeEnabled({ timeout: 15_000 });
  await page.getByTestId("enroll-group").selectOption({ label: GROUP_NAME });
  await page.getByText("Advanced: enrollment tokens", { exact: true }).click();
  await page.getByTestId("enroll-expires").fill("7");
  await page.getByTestId("enroll-max-uses").fill("3");
  await page.getByTestId("enroll-create").click();

  // The plaintext secret is shown exactly once, with the install command carrying it.
  const secretEl = page.getByTestId("enroll-secret-value");
  await expect(secretEl).toBeVisible();
  const secret = (await secretEl.textContent())?.trim() ?? "";
  expect(secret.length).toBeGreaterThan(20);

  // The token appears in the list — active, uses 0 / 3. Grab its id from the row testid.
  const rowTestId = await page
    .getByTestId("enrollment-tokens")
    .locator("tbody tr[data-testid^='enroll-token-row-']")
    .first()
    .getAttribute("data-testid");
  const id = (rowTestId ?? "").replace("enroll-token-row-", "");
  expect(id).not.toBe("");
  await expect(page.getByTestId(`enroll-status-${id}`)).toHaveText("active");
  await expect(page.getByTestId(`enroll-token-row-${id}`)).toContainText("0 / 3");
  // The row labels the group by NAME (not a raw uuid).
  await expect(page.getByTestId(`enroll-group-name-${id}`)).toHaveText(GROUP_NAME);

  // A reload re-fetches from the server — the token is still there (durable), still active.
  await page.getByTestId("enroll-secret-dismiss").click();
  await page.reload();
  await (await consoleTab(page, { name: "Install DeskRally" })).click();
  await page.getByText("Advanced: enrollment tokens", { exact: true }).click();
  await expect(page.getByTestId(`enroll-status-${id}`)).toHaveText("active");

  // Revoke → the row flips to revoked.
  await page.getByTestId(`enroll-revoke-${id}`).click();
  await expect(page.getByTestId(`enroll-status-${id}`)).toHaveText("revoked");
});
