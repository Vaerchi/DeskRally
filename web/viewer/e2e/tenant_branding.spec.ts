/**
 * Per-tenant branding / white-label (docs/01 §9) driven through the REAL console UI.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop-23/33/35/37 precedent). Against a real DEV control plane (stub full-owner auth,
 * in-memory branding store):
 *
 *   1. In the Appearance tab, set a product name + accent colour and Save.
 *   2. The theme applies immediately: document.title becomes the product name and the `--accent` CSS
 *      variable becomes the chosen colour (the whole console reads that variable).
 *   3. A RELOAD re-fetches the branding and re-applies it (proving it persisted server-side), even
 *      without re-opening the Appearance tab.
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

async function accentVar(page: import("@playwright/test").Page): Promise<string> {
  return (
    await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--accent"))
  ).trim();
}

test("setting branding themes the console and persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  // Baseline: the built-in accent from index.css (#3b82f6), before any tenant branding.
  await expect.poll(() => accentVar(page)).toBe("#3b82f6");

  await (await consoleTab(page, { name: "Appearance" })).click();
  await expect(page.getByTestId("appearance")).toBeVisible({ timeout: 15_000 });

  // Set a product name + accent and save.
  await page.getByTestId("appearance-name").fill("Acme Remote");
  await page.getByTestId("appearance-accent").fill("#ff0000");
  await page.getByTestId("appearance-save").click();
  await expect(page.getByTestId("appearance-saved")).toBeVisible();

  // The theme applied immediately: title + the --accent CSS variable.
  await expect(page).toHaveTitle("Acme Remote");
  await expect.poll(() => accentVar(page)).toBe("#ff0000");

  // A reload re-fetches + re-applies the branding (it persisted server-side), even though the
  // Appearance tab is not re-opened.
  await page.reload();
  await expect(page).toHaveTitle("Acme Remote");
  await expect.poll(() => accentVar(page)).toBe("#ff0000");
});

test("uploading a logo shows it in the header and persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Appearance" })).click();
  await expect(page.getByTestId("appearance")).toBeVisible({ timeout: 15_000 });

  // A real 1×1 PNG (valid magic bytes AND decodable, so the <img> has non-zero size and is visible).
  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC",
    "base64",
  );
  await page.getByTestId("appearance-logo").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: png });
  await expect(page.getByTestId("appearance-logo-preview")).toBeVisible();
  await page.getByTestId("appearance-save").click();
  await expect(page.getByTestId("appearance-saved")).toBeVisible();

  // The header shows the logo immediately (onSaved re-applies branding).
  const headerLogo = page.getByTestId("app-brand-logo");
  await expect(headerLogo).toBeVisible();
  expect((await headerLogo.getAttribute("src"))?.startsWith("data:image/png;base64,")).toBe(true);

  // It persisted server-side: a reload re-fetches and re-renders it without re-opening Appearance.
  await page.reload();
  await expect(page.getByTestId("app-brand-logo")).toBeVisible();

  // And it can be removed.
  await (await consoleTab(page, { name: "Appearance" })).click();
  await page.getByTestId("appearance-logo-clear").click();
  await page.getByTestId("appearance-save").click();
  await expect(page.getByTestId("appearance-saved")).toBeVisible();
  await expect(page.getByTestId("app-brand-logo")).toHaveCount(0);
});
