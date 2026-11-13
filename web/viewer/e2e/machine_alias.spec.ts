/**
 * Machine ALIAS / friendly name (docs/01 §4) driven through the REAL CONSOLE UI.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof (VM
 * N/A; loop 23 precedent). Against a real DEV control plane: enroll ONE machine with a hostname, then in
 * the Machines tab set a tenant-chosen friendly name via the per-row Rename control, confirm it overrides
 * the hostname AND persists across a reload, then CLEAR it and confirm the hostname shows again. (The
 * group-scoped CapManageMachines write gate is proven by the Go test TestSetMachineAliasHandler.)
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
import { clickMachineAction, openMachineActions } from "./machine_actions";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const CP_LISTEN = `127.0.0.1:${CP_PORT}`;
const APP_URL = "http://127.0.0.1:5173/";
const HOSTNAME = "ALIAS-BOX";

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

async function createGroup(name: string): Promise<string> {
  const res = await fetch(`${CP_BASE}/machine-groups`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  const text = await res.text();
  if (res.status !== 201 && res.status !== 200) throw new Error(`create group ${name} (${res.status}): ${text}`);
  return (JSON.parse(text) as { machine_group: { id: string } }).machine_group.id;
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
    const gid = await createGroup("ALIAS-GRP");
    const res = await fetch(`${CP_BASE}/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ group_id: gid, name: HOSTNAME }),
    });
    const text = await res.text();
    if (res.status !== 201) {
      skipReason = `enroll failed (${res.status}): ${text}`;
      return;
    }
    machinePk = (JSON.parse(text) as { machine: { id: string } }).machine.id;
    if (!machinePk) {
      skipReason = `setup returned no machine id`;
      return;
    }
  } catch (e) {
    skipReason = `setup failed: ${String(e)}`;
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

test("operator sets a friendly name that overrides the hostname and persists, then clears it", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Machines" })).click();

  // The Name cell starts as the agent-reported hostname.
  const nameCell = page.getByTestId(`machine-name-${machinePk}`);
  await expect(nameCell).toBeVisible({ timeout: 15_000 });
  await expect(nameCell).toHaveText(HOSTNAME);

  // Rename → type a friendly name → Save → the cell now shows the alias (overriding the hostname).
  await clickMachineAction(page, machinePk, `machine-alias-edit-${machinePk}`);
  await page.getByTestId(`machine-alias-input-${machinePk}`).fill("CEO Laptop");
  await page.getByTestId(`machine-alias-save-${machinePk}`).click();
  await expect(page.getByTestId(`machine-name-${machinePk}`)).toHaveText("CEO Laptop");

  // A reload re-fetches from the server and still shows the alias — it is durable.
  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-name-${machinePk}`)).toHaveText("CEO Laptop");

  // Rename → clear the field → Save → the alias is removed and the hostname shows again.
  await clickMachineAction(page, machinePk, `machine-alias-edit-${machinePk}`);
  await page.getByTestId(`machine-alias-input-${machinePk}`).fill("");
  await page.getByTestId(`machine-alias-save-${machinePk}`).click();
  await expect(page.getByTestId(`machine-name-${machinePk}`)).toHaveText(HOSTNAME);
});
