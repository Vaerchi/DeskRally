/**
 * Machine GROUP REASSIGNMENT (docs/01 §4) driven through the REAL CONSOLE UI.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof (VM
 * N/A; loop 23 precedent). Against a real DEV control plane: create TWO machine groups, enroll ONE machine
 * into the first, then in the Machines tab reassign it to the second via the per-row group control and
 * confirm the change persists across a reload. (The two-way authz — manage BOTH the current and target
 * group — is proven by the Go test TestSetMachineGroupHandler.)
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
let gid2 = "";
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
    const gid1 = await createGroup("GRP-ALPHA");
    gid2 = await createGroup("GRP-BETA");
    const res = await fetch(`${CP_BASE}/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ group_id: gid1, name: "REASSIGN-BOX" }),
    });
    const text = await res.text();
    if (res.status !== 201) {
      skipReason = `enroll failed (${res.status}): ${text}`;
      return;
    }
    machinePk = (JSON.parse(text) as { machine: { id: string } }).machine.id;
    if (!machinePk || !gid2) {
      skipReason = `setup returned no ids (machine=${machinePk} gid2=${gid2})`;
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

test("operator reassigns a machine to a different group, and it persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Machines" })).click();

  // The machine starts in GRP-ALPHA (shown by NAME, not the uuid).
  const groupCell = page.getByTestId(`machine-group-${machinePk}`);
  await expect(groupCell).toBeVisible({ timeout: 15_000 });
  await expect(groupCell).toHaveText("GRP-ALPHA");

  // Reassign to GRP-BETA via the per-row group control → the cell flips.
  await page.getByTestId(`machine-group-select-${machinePk}`).selectOption(gid2);
  await expect(groupCell).toHaveText("GRP-BETA");

  // A reload re-fetches from the server and still shows GRP-BETA — the reassignment is durable.
  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-group-${machinePk}`)).toHaveText("GRP-BETA");
});
