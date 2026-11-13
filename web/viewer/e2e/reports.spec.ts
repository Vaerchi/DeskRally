/**
 * Reports — the §5 audit-summary aggregation — driven through the REAL CONSOLE UI.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof (VM
 * N/A; loop 23 precedent). Against a real DEV control plane (in-memory mgmt-audit store): generate audit
 * events by doing a recorded console action (create two machine groups → two `machine_group.created`
 * events), then the Reports tab shows that action with a count of 2.
 *
 * Self-skips (loudly) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, readFileSync } from "node:fs";
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

test("Reports aggregates the audit trail by action", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  // Generate two recorded actions: create two machine groups → two machine_group.created audit events.
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
  for (const name of ["Alpha", "Beta"]) {
    await page.getByTestId("mgroup-name").fill(name);
    await page.getByTestId("mgroup-create").click();
    await expect(page.getByTestId("machine-groups").locator('[data-testid^="mgroup-row-"]').getByText(name)).toBeVisible();
  }

  // Reports tab → the summary counts the two machine_group.created events.
  await (await consoleTab(page, { name: "Reports", exact: true })).click();
  await expect(page.getByTestId("reports")).toBeVisible();
  await expect(page.getByTestId("report-count-machine_group.created")).toHaveText("2");
  // The total reflects at least those two events.
  await expect(page.getByTestId("report-total")).toContainText("Total:");

  // CHART: toggling "Show chart" renders a self-contained inline-SVG bar chart with a bar for the
  // machine_group.created action; toggling off removes it.
  await page.getByTestId("report-chart-toggle").click();
  await expect(page.getByTestId("report-chart")).toBeVisible();
  await expect(page.getByTestId("chart-rect-machine_group.created")).toBeVisible();
  await page.getByTestId("report-chart-toggle").click();
  await expect(page.getByTestId("report-chart")).toHaveCount(0);

  // FILTER by action: narrowing to machine_group.created still shows its count; a non-matching action
  // empties the table (the filter is applied server-side via GET /audit/summary?action=).
  await page.getByTestId("report-action").fill("machine_group.created");
  await page.getByTestId("report-apply").click();
  await expect(page.getByTestId("report-count-machine_group.created")).toHaveText("2");
  await page.getByTestId("report-action").fill("no.such.action");
  await page.getByTestId("report-apply").click();
  await expect(page.getByTestId("reports-empty")).toBeVisible();

  // EXPORT CSV: back to the machine_group.created slice, then export → the browser saves a CSV whose
  // content carries that action and its count.
  await page.getByTestId("report-action").fill("machine_group.created");
  await page.getByTestId("report-apply").click();
  await expect(page.getByTestId("report-count-machine_group.created")).toHaveText("2");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("report-export").click(),
  ]);
  expect(download.suggestedFilename()).toBe("audit-report.csv");
  const csvPath = await download.path();
  const csv = readFileSync(csvPath, "utf8");
  expect(csv).toContain("action,count");
  expect(csv).toContain("machine_group.created,2");
});

test("Reports — sessions by machine (report-type toggle + CSV)", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  // Seed session records directly against the DEV control plane (stub auth → no login/CSRF): three
  // starts create three session_record rows (+ three session.start audit events). DEV's permissive
  // machine store resolves the device id to a synthetic (unenrolled) machine with no PK/name, so all
  // three collapse to ONE report row — the per-machine grouping with real names + RLS is proven by the
  // Go test TestPgSessionSummaryByMachineUnderRLS; this spec proves the console UI wiring end to end.
  let firstId = "";
  for (let i = 0; i < 3; i++) {
    const res = await fetch(`${CP_BASE}/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ machine_id: "dev-report-host" }),
    });
    expect(res.ok).toBe(true);
    if (i === 0) firstId = (await res.json()).session.id as string;
  }
  // END one session after a >1s gap so its completed duration floors to at least 1 second — this makes
  // the usage-hours (Total time) metric NON-ZERO end to end. The other two stay open (0s each).
  await sleep(1200);
  expect((await fetch(`${CP_BASE}/sessions/${firstId}/end`, { method: "POST" })).ok).toBe(true);

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Reports", exact: true })).click();
  await expect(page.getByTestId("reports")).toBeVisible({ timeout: 15_000 });

  // Default view (events by action) shows the three session.start events we just generated — a
  // cross-check that the seeding worked and the actions report still renders.
  await expect(page.getByTestId("report-count-session.start")).toHaveText("3");

  // Switch the report type → the sessions-by-machine view: its title, its Machine/Sessions/Total time
  // headers, a non-empty table, and a total of 3 (the three seeded sessions).
  await page.getByTestId("report-type").selectOption("sessions");
  await expect(page.getByText("Reports — sessions by machine")).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Machine" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Sessions" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Total time" })).toBeVisible();
  await expect(page.getByTestId("reports-empty")).toBeHidden();
  await expect(page.getByTestId("report-total")).toContainText("Total: 3");
  // The action-filter form belongs to the audit report only — it must not show in the sessions view.
  await expect(page.getByTestId("report-action")).toHaveCount(0);

  // EXPORT CSV in the sessions view → a sessions-by-machine.csv whose new header is present and whose
  // one machine row carries count 3 and a NON-ZERO raw total_seconds (the ended session's duration).
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("report-export").click(),
  ]);
  expect(download.suggestedFilename()).toBe("sessions-by-machine.csv");
  const csv = readFileSync(await download.path(), "utf8");
  expect(csv).toContain("machine,sessions,total_seconds");
  expect(csv).toMatch(/,3,[1-9]\d*\r\n/);

  // DATE FILTER: the three sessions are ~now, so a window starting in the FAR FUTURE excludes them all →
  // the report empties (Total: 0). Clearing the filter restores the all-time Total: 3. This proves the
  // ?since=/?until= session-report filter is wired end to end.
  await page.getByTestId("session-report-since").fill("2099-01-01T00:00");
  await page.getByTestId("session-report-apply").click();
  await expect(page.getByTestId("report-total")).toContainText("Total: 0");
  await expect(page.getByTestId("reports-empty")).toBeVisible();
  await page.getByTestId("session-report-clear").click();
  await expect(page.getByTestId("report-total")).toContainText("Total: 3");

  // Switch to the sessions-by-technician view: the SAME three sessions were all run by the DEV owner, so
  // they collapse into ONE technician row whose id resolves to owner@dev.local (proving technicianLabel +
  // the users fetch), with a total of 3. Its CSV carries the RESOLVED email, not a raw uuid, and a
  // NON-ZERO raw total_seconds (the ended session's duration).
  await page.getByTestId("report-type").selectOption("technicians");
  await expect(page.getByText("Reports — sessions by technician")).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Technician" })).toBeVisible();
  await expect(page.getByTestId("reports-empty")).toBeHidden();
  await expect(page.getByTestId("report-total")).toContainText("Total: 3");
  // In the report table, not the app menu's "Signed in as owner@dev.local" (added 2026-10-17).
  await expect(page.locator("td", { hasText: "owner@dev.local" })).toBeVisible();
  const [techDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("report-export").click(),
  ]);
  expect(techDownload.suggestedFilename()).toBe("sessions-by-technician.csv");
  const techCsv = readFileSync(await techDownload.path(), "utf8");
  expect(techCsv).toContain("technician,sessions,total_seconds");
  expect(techCsv).toContain("owner@dev.local");
  expect(techCsv).toMatch(/,3,[1-9]\d*\r\n/);

  // Toggle BACK to events-by-action → the audit table returns (the switch is bidirectional).
  await page.getByTestId("report-type").selectOption("actions");
  await expect(page.getByText("Reports — events by action")).toBeVisible();
  await expect(page.getByTestId("report-count-session.start")).toHaveText("3");
});

test("Print/PDF export: provenance header, print-only layout, and the stale/empty guard", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  // Stub the native dialog: the test asserts the panel CALLS it and what the printed page shows.
  await page.addInitScript(() => {
    (window as any).printCalls = 0;
    window.print = () => { (window as any).printCalls++; };
  });
  await page.goto(APP_URL);

  // Seed one recorded action so the report has rows.
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("mgroup-name").fill("PrintSeed");
  await page.getByTestId("mgroup-create").click();
  await expect(page.getByTestId("machine-groups").locator('[data-testid^="mgroup-row-"]').getByText("PrintSeed")).toBeVisible();

  await (await consoleTab(page, { name: "Reports", exact: true })).click();
  await expect(page.getByTestId("reports")).toBeVisible();
  await expect(page.getByTestId("report-count-machine_group.created")).toBeVisible();

  // On screen the print header is hidden; the button is enabled once rows exist.
  await expect(page.getByTestId("report-print-header")).toBeHidden();
  await page.getByTestId("report-print").click();
  await expect.poll(() => page.evaluate(() => (window as any).printCalls)).toBe(1);

  // Under print media: only the reports panel is visible, interactive controls collapse, and the
  // provenance header leads with the title, the filter line and the generated-at stamp.
  await page.emulateMedia({ media: "print" });
  const header = page.getByTestId("report-print-header");
  await expect(header).toBeVisible();
  await expect(header).toContainText("Events by action");
  await expect(header).toContainText("no filter");
  await expect(header).toContainText("Generated ");
  await expect(page.getByTestId("report-print")).toBeHidden();
  await expect(page.getByTestId("app-nav-toggle")).toBeHidden();
  await page.emulateMedia({ media: null });

  // The guard matches the CSV export: a filter that empties the report disables printing.
  await page.getByTestId("report-action").fill("no.such.action");
  await page.getByTestId("report-apply").click();
  await expect(page.getByTestId("report-print")).toBeDisabled();
});
