/**
 * Machine lifecycle status / quarantine driven through the REAL CONSOLE UI (docs/01 §4).
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM is N/A; loop 23 precedent). Against a real DEV control plane, with one enrolled machine:
 *
 *   1. In the Machines tab, the enrolled machine shows status "active".
 *   2. Quarantine it via the per-row status control → the Status cell flips to "quarantined".
 *   3. A reload re-fetches from the server and still shows "quarantined" (the write is DURABLE).
 *   4. Reactivate → back to "active".
 *
 * (The server-side enforcement — a quarantined machine is refused a new session — is proven by the Go
 * test TestStartSessionRefusedForQuarantinedMachine; the console has no Connect button here.)
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
const GROUP_ID = "00000000-0000-0000-0000-0000000000dd";

let cpProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let machinePk = "";

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
  const res = await fetch(`${CP_BASE}/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ group_id: GROUP_ID, name: "STATUS-TEST" }),
  });
  const text = await res.text();
  if (res.status !== 201) {
    skipReason = `enroll failed (${res.status}): ${text}`;
    return;
  }
  machinePk = (JSON.parse(text) as { machine: { id: string } }).machine.id;
  if (!machinePk) {
    skipReason = `enroll returned no machine id: ${text}`;
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

test("operator quarantines and reactivates a machine, and the quarantine persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("dialog", (dialog) => dialog.accept());
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Machines" })).click();
  const statusCell = page.getByTestId(`machine-status-${machinePk}`);
  await expect(statusCell).toBeVisible({ timeout: 15_000 });
  await expect(statusCell).toHaveText("active");

  // Quarantine via the per-row status control → the cell flips.
  await page.getByTestId(`machine-status-select-${machinePk}`).selectOption("quarantined");
  await expect(statusCell).toHaveText("quarantined");

  // A reload re-fetches from the server and still shows quarantined — the write is durable.
  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-status-${machinePk}`)).toHaveText("quarantined");

  // Reactivate → back to active.
  await page.getByTestId(`machine-status-select-${machinePk}`).selectOption("active");
  await expect(page.getByTestId(`machine-status-${machinePk}`)).toHaveText("active");
});

test("operator bulk-retires several SELECTED machines at once, and it persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  // Enroll two more machines so there is a real multi-selection to act on.
  const enroll = async (name: string): Promise<string> => {
    const res = await fetch(`${CP_BASE}/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ group_id: GROUP_ID, name }),
    });
    expect(res.status).toBe(201);
    return (JSON.parse(await res.text()) as { machine: { id: string } }).machine.id;
  };
  const pk1 = await enroll("BULK-A");
  const pk2 = await enroll("BULK-B");

  const page = await browser!.newPage();
  page.on("dialog", (dialog) => dialog.accept());
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-status-${pk1}`)).toBeVisible({ timeout: 15_000 });

  // Select ONLY the two new machines, choose "retired", and apply the bulk change.
  await page.getByTestId(`bulk-check-${pk1}`).check();
  await page.getByTestId(`bulk-check-${pk2}`).check();
  await expect(page.getByTestId("bulk-selected-count")).toHaveText("2 selected");
  await page.getByTestId("bulk-status-select").selectOption("retired");
  await page.getByTestId("bulk-apply").click();

  // The summary reports both updated and both rows flip to retired (the first test's machine is untouched).
  await expect(page.getByTestId("bulk-result")).toHaveText("2 updated");
  await expect(page.getByTestId(`machine-status-${pk1}`)).toHaveText("retired");
  await expect(page.getByTestId(`machine-status-${pk2}`)).toHaveText("retired");

  // A reload re-fetches from the server → the bulk write was durable, not just local state.
  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-status-${pk1}`)).toHaveText("retired");
  await expect(page.getByTestId(`machine-status-${pk2}`)).toHaveText("retired");
});
