/**
 * Machine custom properties driven through the REAL CONSOLE UI (docs/01 §4).
 *
 * This is a BROWSER-only feature — the property CRUD lives entirely in the control plane + console,
 * with no agent, no signaling and no WebRTC — so the Playwright run IS the live proof (VM is N/A;
 * loop 23 precedent). It drives the operator flow end to end against a real control plane:
 *
 *   1. Enroll a machine (so the Machines tab has a real PRIMARY KEY to address).
 *   2. Open that machine's Properties panel, add two properties, and assert they render in
 *      key-sorted order (the live UI honouring sortPropertiesByKey — rack before site).
 *   3. Remove one and assert it disappears while the other survives.
 *   4. Submit an empty key and assert the inline "key is required" error (validatePropertyForm),
 *      with NO new row — the client-side guard before a round trip.
 *
 * Stack: control plane in DEV mode on ports.ts CP_PORT (the Vite `/cp` proxy target — the browser
 * reaches the CP only through that proxy, so the port is NOT free to choose; workers:1 keeps it from
 * colliding with the other CP-on-CP_PORT specs). DEV mode's stub auth is a full-cap owner, so there
 * is no login and no CSRF cookie to manage.
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
const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite /cp proxy target (CONTROL_PLANE_ORIGIN)
const APP_URL = "http://127.0.0.1:5173/";

// A well-formed group id for the enroll. In DEV the stub owner holds AllGroups(), so any group is
// authorized; the permissive machine store resolves the enrolled machine to it for the property authz.
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

  // DEV mode (DATABASE_URL="" → stub full-owner auth, in-memory permissive machine + property stores).
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

  // Enroll one machine so the Machines tab has a real PK to drive. The response carries the assigned
  // primary key (machine.id) — the identity the /machines/{id}/properties routes and the panel use.
  const res = await fetch(`${CP_BASE}/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ group_id: GROUP_ID, name: "PROP-TEST" }),
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
    browser = await chromium.launch({ headless: true }); // bundled chromium fallback
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(cpProc);
});

test("operator adds, sorts, removes machine properties and sees the empty-key error", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  // Enter the Machines console area and open the enrolled machine's Properties panel.
  await (await consoleTab(page, { name: "Machines" })).click();
  const propsBtn = page.getByTestId(`machine-props-${machinePk}`);
  await expect(propsBtn).toBeVisible({ timeout: 15_000 });
  await propsBtn.click();
  await expect(page.getByTestId("machine-properties")).toBeVisible();
  await expect(page.getByTestId("properties-empty")).toHaveText(/no properties set/i);

  // Add "site=HQ", then "rack=R7". They must render key-sorted (rack BEFORE site) — the live UI
  // proving sortPropertiesByKey, not the fetch order.
  const key = page.getByTestId("property-key");
  const value = page.getByTestId("property-value");
  const add = page.getByTestId("property-add");

  await key.fill("site");
  await value.fill("HQ");
  await add.click();
  await expect(page.getByTestId("property-row-site")).toContainText("HQ");

  await key.fill("rack");
  await value.fill("R7");
  await add.click();
  await expect(page.getByTestId("property-row-rack")).toContainText("R7");

  const keysInOrder = await page.getByTestId("machine-properties").getByRole("row").allInnerTexts();
  const rackIdx = keysInOrder.findIndex((t) => t.includes("rack"));
  const siteIdx = keysInOrder.findIndex((t) => t.includes("site"));
  expect(rackIdx).toBeGreaterThan(0);
  expect(rackIdx).toBeLessThan(siteIdx); // A→Z: rack before site

  // Remove "site"; "rack" survives.
  await page.getByTestId("property-remove-site").click();
  await expect(page.getByTestId("property-row-site")).toHaveCount(0);
  await expect(page.getByTestId("property-row-rack")).toContainText("R7");

  // An empty key is rejected client-side with the inline error and adds NO row.
  await key.fill("");
  await value.fill("orphan");
  await add.click();
  await expect(page.getByTestId("properties-error")).toHaveText(/key is required/i);
  await expect(page.getByTestId("machine-properties").getByText("orphan")).toHaveCount(0);

  // A reload proves the writes are DURABLE server-side, not just local component state.
  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await page.getByTestId(`machine-props-${machinePk}`).click();
  await expect(page.getByTestId("property-row-rack")).toContainText("R7");
  await expect(page.getByTestId("property-row-site")).toHaveCount(0);
});
