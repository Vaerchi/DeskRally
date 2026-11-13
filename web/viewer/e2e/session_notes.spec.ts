/**
 * Session notes (docs/01 §7) — the Sessions console tab's inline note editor, driven through the REAL
 * console UI against a DEV control plane.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof (VM
 * N/A; loop 23 precedent). Seed one session via a plain POST /sessions (DEV stub auth → no login/CSRF),
 * then in the Sessions tab: add a note → save → it shows → Refresh (re-fetch from the server) → the note
 * PERSISTS, proving the PATCH /sessions/{id}/note round-trip.
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

test("Sessions tab: add a note, save, and it persists across a refresh", async () => {
  test.skip(skipReason !== null, skipReason ?? "");

  // Seed one session directly (DEV stub auth → no login/CSRF) and capture its id for the row testids.
  const res = await fetch(`${CP_BASE}/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ machine_id: "dev-note-host" }),
  });
  expect(res.ok).toBe(true);
  const sid = (await res.json()).session.id as string;
  expect(sid).toBeTruthy();

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Sessions", exact: true })).click();
  await expect(page.getByTestId(`session-note-${sid}`)).toBeVisible({ timeout: 15_000 });

  // The fresh session has no note → the affordance reads "Add". Open the editor, type, save.
  await page.getByTestId(`session-note-edit-${sid}`).click();
  await page.getByTestId(`session-note-input-${sid}`).fill("e2e handoff note");
  await page.getByTestId(`session-note-save-${sid}`).click();

  // The saved note is shown in the row (the editor closed back to the view).
  await expect(page.getByTestId(`session-note-${sid}`)).toContainText("e2e handoff note");
  await expect(page.getByTestId(`session-note-input-${sid}`)).toHaveCount(0);

  // Re-fetch from the server (Refresh) → the note PERSISTED (proves the PATCH round-trip, not just local state).
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByTestId(`session-note-${sid}`)).toContainText("e2e handoff note");

  // DATE FILTER: the seeded session is ~now, so a window starting in the FAR FUTURE excludes it → its row
  // disappears from the list. Clearing the filter brings it back. Proves the ?since=/?until= filter is wired
  // end to end on the Sessions list.
  await page.getByTestId("sessions-since").fill("2099-01-01T00:00");
  await page.getByTestId("sessions-apply").click();
  await expect(page.getByTestId(`session-note-${sid}`)).toHaveCount(0);
  await page.getByTestId("sessions-clear").click();
  await expect(page.getByTestId(`session-note-${sid}`)).toBeVisible();
});
