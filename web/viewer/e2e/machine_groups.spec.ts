/**
 * Static machine groups (docs/01 §4) driven through the REAL CONSOLE UI — creating the machine_group
 * rows that are the RBAC scope unit and the container new agents enroll into.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop 23 precedent). Against a real DEV control plane (stub full-owner auth, in-memory
 * machine-group store):
 *
 *   1. The Machine groups tab starts empty.
 *   2. Create a group by name → the row appears with a real uuid id (the value to paste into Deploy).
 *   3. A reload re-fetches from the server — the group is still there (durable).
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
import { openGroupPolicy, saveGroupPolicy } from "./group_policy";

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

test("operator creates a machine group and it persists across a reload", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("mgroups-empty")).toHaveText(/no machine groups/i);

  // Create a group by name.
  await page.getByTestId("mgroup-name").fill("Front Office");
  await page.getByTestId("mgroup-create").click();

  // The row appears with the name + a real uuid id. Grab the id from the row testid.
  const row = page.getByTestId("machine-groups").locator("tbody tr[data-testid^='mgroup-row-']").first();
  await expect(row).toContainText("Front Office");
  const rowTestId = await row.getAttribute("data-testid");
  const id = (rowTestId ?? "").replace("mgroup-row-", "");
  expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  await expect(page.getByTestId(`mgroup-id-${id}`)).toHaveText(id);

  // A reload re-fetches from the server — the group is still there (durable).
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId(`mgroup-row-${id}`)).toContainText("Front Office");

  // RENAME it inline → the row shows the new name, and it survives a reload (durable).
  await page.getByTestId(`mgroup-rename-${id}`).click();
  await page.getByTestId(`mgroup-edit-name-${id}`).fill("Head Office");
  await page.getByTestId(`mgroup-save-${id}`).click();
  await expect(page.getByTestId(`mgroup-row-${id}`)).toContainText("Head Office");
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId(`mgroup-row-${id}`)).toContainText("Head Office");

  // Set a per-group concurrent-session CAP (docs/01 §5, loop 78) → it persists across a reload (the
  // input is re-seeded from the server's stored cap).
  await openGroupPolicy(page, id);
  await page.getByTestId(`mgroup-cap-${id}`).fill("2");
  // The server REQUIRES a stated max duration whenever a cap is set (http_group_session_policy.go: the
  // reaper needs one), so a cap-only PUT is a 400. This spec predates that rule and used to reload
  // without looking at the response, which read as "the cap did not persist".
  await page.getByTestId(`mgroup-maxduration-${id}`).fill("3600");
  // Wait for the PUT to COMPLETE before reloading (a reload mid-request can abort it), and confirm the
  // server stored the cap — so a failure below distinguishes "not persisted" from "not re-seeded".
  const capPut = page.waitForResponse(
    (r) => r.url().includes(`/machine-groups/${id}/session-policy`) && r.request().method() === "PUT",
  );
  await page.getByTestId(`mgroup-cap-save-${id}`).click();
  const capRes = await capPut;
  expect(capRes.status(), `cap PUT failed: ${await capRes.text()}`).toBe(200);
  const stored = (await (await fetch(`${CP_BASE}/machine-groups/session-policies`)).json()) as {
    policies: { group_id: string; max_concurrent_sessions: number; max_session_duration_seconds: number }[];
  };
  const storedPolicy = stored.policies.find((p) => p.group_id === id);
  expect(storedPolicy?.max_concurrent_sessions).toBe(2);
  expect(storedPolicy?.max_session_duration_seconds).toBe(3600);
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await openGroupPolicy(page, id);
  await expect(page.getByTestId(`mgroup-cap-${id}`)).toHaveValue("2");

  // Force VIEW-ONLY for the group (docs/01 §5, loops 79/80) → it persists across a reload. This is the
  // ADMIN CONTROL that drives the signed session policy: from here on every session started on a machine
  // in this group is minted a view_only policy the agent enforces and the technician cannot lift. The
  // enforcement itself is agent-side and is VM-verified; what the browser can prove is that the mandate is
  // stored and read back.
  await page.getByTestId(`mgroup-viewonly-${id}`).check();
  await saveGroupPolicy(page, id);
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await openGroupPolicy(page, id);
  await expect(page.getByTestId(`mgroup-viewonly-${id}`)).toBeChecked();
  // …and the CAP set above survived being saved alongside it. The PUT is a full overwrite, so a console
  // that sent only the checkbox would silently clear the cap — the exact coupling bug this asserts against.
  await expect(page.getByTestId(`mgroup-cap-${id}`)).toHaveValue("2");
  // The BACKSTAGE OPT-OUT (migration 0040) defaults to OFF, and that default is load-bearing: with it off,
  // a view-only group also refuses backstage grants, so the column above means watch-only full stop. It was
  // never touched, and saving the two settings that WERE touched must not have turned it on.
  await expect(page.getByTestId(`mgroup-allowbackstage-${id}`)).not.toBeChecked();

  // Turn the opt-out ON — the deliberate unattended-maintenance exception — and prove all THREE settings
  // survive one save together. This is the coupling assertion extended to three: the PUT is a full
  // overwrite, so a console that submitted any two of them would silently reset the third, and each of the
  // three below is a different one of those bugs.
  await page.getByTestId(`mgroup-allowbackstage-${id}`).check();
  await saveGroupPolicy(page, id);
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await openGroupPolicy(page, id);
  await expect(page.getByTestId(`mgroup-allowbackstage-${id}`)).toBeChecked();
  await expect(page.getByTestId(`mgroup-viewonly-${id}`)).toBeChecked();
  await expect(page.getByTestId(`mgroup-cap-${id}`)).toHaveValue("2");

  // Turning it back OFF must also persist. A security exception you cannot revoke is a worse bug than one
  // you cannot grant, and this is the direction an operator reaches for in an incident.
  await page.getByTestId(`mgroup-allowbackstage-${id}`).uncheck();
  await saveGroupPolicy(page, id);
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await openGroupPolicy(page, id);
  await expect(page.getByTestId(`mgroup-allowbackstage-${id}`)).not.toBeChecked();
  await expect(page.getByTestId(`mgroup-viewonly-${id}`)).toBeChecked();
  await expect(page.getByTestId(`mgroup-cap-${id}`)).toHaveValue("2");

  // Turning the MANDATE back OFF must also persist — a mandate you cannot lift is its own kind of bug, and
  // the store deletes the row only when EVERY setting is default, so this exercises the non-delete path.
  await page.getByTestId(`mgroup-viewonly-${id}`).uncheck();
  await saveGroupPolicy(page, id);
  await page.reload();
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await openGroupPolicy(page, id);
  await expect(page.getByTestId(`mgroup-viewonly-${id}`)).not.toBeChecked();
  await expect(page.getByTestId(`mgroup-allowbackstage-${id}`)).not.toBeChecked();
  await expect(page.getByTestId(`mgroup-cap-${id}`)).toHaveValue("2");

  // DELETE it (no machines reference it in DEV) → the row is gone and the empty-state returns.
  await page.getByTestId(`mgroup-delete-${id}`).click();
  await expect(page.getByTestId(`mgroup-row-${id}`)).toHaveCount(0);
  await expect(page.getByTestId("mgroups-empty")).toHaveText(/no machine groups/i);
});
