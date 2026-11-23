/**
 * Credential-setup / first-password link (docs/01 §5) driven through the REAL console UI and the
 * self-service /set-password page — the last mile of invite → provision → login.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop 23 precedent). Against a DEV control plane (stub full-owner auth; in-memory user +
 * credential-token stores). The DEV owner is seeded with a KNOWN password (DEV_OWNER_PASSWORD) so the
 * mint STEP-UP — which re-verifies the caller's OWN password before minting an account-takeover link —
 * can succeed; the technician is credential-less, so its first link is a FIRST-provision.
 *
 * We prove:
 *   1. In Users, mint a setup link for the credential-less technician (step-up with the owner password).
 *      The link + token are shown once and flagged first-password.
 *   2. Open that link (/set-password#<token>) and set a password → success.
 *   3. Revoke: mint again, revoke it, then opening the revoked link fails to set a password.
 *
 * DEV-mode caveat (stated, not hidden): the stub authenticator ignores credentials, so this cannot prove
 * the subsequent LOGIN in the browser — the Go pg tests (credential_token*_test.go, auth_password_reset)
 * prove redeem → login. A SKIP IS NOT A PASS.
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

// Must match cmd/controlplane/main.go's dev seed and the Default password policy (12+ runes, 3 classes,
// no identity tokens like "tech"/"technician").
const DEV_OWNER_PASSWORD = "dev-owner-password";
const NEW_PASSWORD = "Sup3r-Secret-Pass!";
const TECH_EMAIL = "tech@dev.local";

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

// Open the Users tab, mint a setup link for the technician (with the owner-password step-up), and return
// the shown link URL.
async function mintSetupLink(page: import("@playwright/test").Page): Promise<string> {
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Users", exact: true })).click();
  await expect(page.getByTestId("users")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId(`user-row-${TECH_EMAIL}`)).toBeVisible();

  await page.getByTestId(`user-setup-${TECH_EMAIL}`).click();
  await expect(page.getByTestId("setup-panel")).toBeVisible();
  await expect(page.getByTestId("setup-target")).toHaveText(TECH_EMAIL);
  // With a panel open, EVERY other row's "Setup link" button is disabled — you cannot switch targets
  // mid-mint, which is what prevents one user's one-time link rendering under another user's header.
  await expect(page.getByTestId("user-setup-owner@dev.local")).toBeDisabled();

  await page.getByTestId("setup-stepup-password").fill(DEV_OWNER_PASSWORD);
  await page.getByTestId("setup-issue-submit").click();

  const urlEl = page.getByTestId("setup-link-url");
  await expect(urlEl).toBeVisible({ timeout: 15_000 });
  const link = (await urlEl.textContent())?.trim() ?? "";
  expect(link).toContain("/set-password#");
  return link;
}

test("mint a first-password setup link and redeem it to set the password", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  const link = await mintSetupLink(page);
  // The technician had no password → this is flagged as a first-password link.
  await expect(page.getByTestId("setup-link-note")).toContainText(/first-password/i);

  // Open the link and set a password.
  await page.goto(link);
  await expect(page.getByTestId("set-password-page")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("set-password-input").fill(NEW_PASSWORD);
  // With the confirmation still empty the submit button is DISABLED (not enabled-but-a-no-op).
  await expect(page.getByTestId("set-password-submit")).toBeDisabled();
  await page.getByTestId("set-password-confirm").fill(NEW_PASSWORD);
  await expect(page.getByTestId("set-password-submit")).toBeEnabled();
  await page.getByTestId("set-password-submit").click();

  await expect(page.getByTestId("set-password-success")).toBeVisible({ timeout: 15_000 });
  await page.close();
});

test("revoke a setup link so it can no longer be redeemed", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  const link = await mintSetupLink(page);
  // Revoke it in the console — the setup panel closes.
  await page.getByTestId("setup-revoke").click();
  await expect(page.getByTestId("setup-panel")).toBeHidden({ timeout: 15_000 });

  // The revoked link no longer sets a password: redeem fails with a clean error, not a success.
  await page.goto(link);
  await expect(page.getByTestId("set-password-page")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("set-password-input").fill(NEW_PASSWORD);
  await page.getByTestId("set-password-confirm").fill(NEW_PASSWORD);
  await page.getByTestId("set-password-submit").click();

  await expect(page.getByTestId("set-password-error")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("set-password-success")).toHaveCount(0);
  await page.close();
});
