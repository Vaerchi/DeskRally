/**
 * User management (docs/01 §5) driven through the REAL console UI.
 *
 * A BROWSER + control-plane feature (no agent, no WebRTC), so the Playwright run IS the live proof
 * (VM N/A; loop-23/33/35/37/45/46 precedent). Against a real DEV control plane, whose stub owner is
 * seeded as the all-zeros user beside a demo technician:
 *
 *   1. In the Users tab, both seeded users are listed; the technician is active and shows "technician".
 *   2. Disable the technician → the row flips to "disabled"; enable → back to "active".
 *   3. Assign the technician a new role (→ readonly, then → admin) via the role picker → the Role
 *      column reflects each change (role assignment + no-escalation, owner→lower, end to end).
 *   4. INVITE a new user via the Add-user form (email + role) → the new row appears with its role
 *      (create/invite end to end).
 *   5. The owner IS the caller (the all-zeros stub principal), so BOTH disabling it and changing its
 *      own role are refused server-side (self-lockout) and surface as an inline error — proving the
 *      self-disable and self-role-change guards end to end.
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

test("an admin lists users, disables + re-enables + re-roles + invites one, and cannot act on themselves", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  await (await consoleTab(page, { name: "Users" })).click();
  await expect(page.getByTestId("users")).toBeVisible({ timeout: 15_000 });

  // Both seeded users are listed; the technician starts active and holds the technician role.
  await expect(page.getByTestId("user-row-owner@dev.local")).toBeVisible();
  await expect(page.getByTestId("user-row-tech@dev.local")).toBeVisible();
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("active");
  await expect(page.getByTestId("user-role-tech@dev.local")).toHaveText("technician");

  // Disable the technician → the row flips to disabled.
  await page.getByTestId("user-toggle-tech@dev.local").click();
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("disabled");

  // Enable → back to active.
  await page.getByTestId("user-toggle-tech@dev.local").click();
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("active");

  // Re-role the technician via the picker: → readonly, then → admin. The Role column reflects each
  // change (the owner outranks both, so no-escalation permits it).
  await page.getByTestId("user-role-select-tech@dev.local").selectOption("readonly");
  await expect(page.getByTestId("user-role-tech@dev.local")).toHaveText("readonly");
  await page.getByTestId("user-role-select-tech@dev.local").selectOption("admin");
  await expect(page.getByTestId("user-role-tech@dev.local")).toHaveText("admin");

  // Invite a new user via the Add-user form → the new row appears with its chosen role.
  await page.getByTestId("user-create-email").fill("invitee@dev.local");
  await page.getByTestId("user-create-name").fill("Invitee");
  await page.getByTestId("user-create-role").selectOption("readonly");
  await page.getByTestId("user-create-submit").click();
  await expect(page.getByTestId("user-row-invitee@dev.local")).toBeVisible();
  await expect(page.getByTestId("user-role-invitee@dev.local")).toHaveText("readonly");

  // The owner IS the caller (the all-zeros stub principal), so disabling it is refused server-side
  // and shows inline — the self-disable guard, end to end. The owner stays active.
  await page.getByTestId("user-toggle-owner@dev.local").click();
  await expect(page.getByTestId("users-error")).toBeVisible();
  await expect(page.getByTestId("user-status-owner@dev.local")).toHaveText("active");

  // Changing your OWN role is refused too (self-lockout / self-escalation): the owner stays "owner".
  await page.getByTestId("user-role-select-owner@dev.local").selectOption("admin");
  await expect(page.getByTestId("users-error")).toBeVisible();
  await expect(page.getByTestId("user-role-owner@dev.local")).toHaveText("owner");
});

test("an admin can sign a user out of all sessions, and the control is disabled for a disabled user", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Users" })).click();
  await expect(page.getByTestId("user-row-tech@dev.local")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("active");

  // Active user → Sign out is enabled; signing them out succeeds (no error) and does NOT disable them
  // (unlike Disable, sign-out only revokes sessions — the status stays active).
  const signOut = page.getByTestId("user-signout-tech@dev.local");
  await expect(signOut).toBeEnabled();
  await signOut.click();
  await expect(page.getByTestId("users-error")).toBeHidden();
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("active");

  // Disable the user → Sign out becomes DISABLED (a disabled account has no live sessions to revoke).
  await page.getByTestId("user-toggle-tech@dev.local").click();
  await expect(page.getByTestId("user-status-tech@dev.local")).toHaveText("disabled");
  await expect(page.getByTestId("user-signout-tech@dev.local")).toBeDisabled();

  // Re-enable → Sign out enabled again (leave the fixture as we found it).
  await page.getByTestId("user-toggle-tech@dev.local").click();
  await expect(page.getByTestId("user-signout-tech@dev.local")).toBeEnabled();
});

// docs/56 expiring access, end to end: an admin gives a user access until a date, sees it in the
// Access column, a later role change keeps it, Never clears it, and an invite can carry one too.
test("an admin sets, keeps across a role change, and clears a user's access expiry", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Users" })).click();
  await expect(page.getByTestId("user-row-tech@dev.local")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("user-access-tech@dev.local")).toContainText("Never");

  // A date a few days out, as the datetime-local control wants it (local time, minutes).
  const d = new Date(Date.now() + 3 * 24 * 3600 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  const local = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

  await page.getByTestId("user-access-edit-tech@dev.local").click();
  await expect(page.getByTestId("access-panel")).toBeVisible();
  await page.getByTestId("access-ends").fill(local);
  await expect(page.getByTestId("access-never")).not.toBeChecked();
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("access-panel")).toBeHidden();
  await expect(page.getByTestId("user-access-tech@dev.local")).toContainText(`Expires`);
  await expect(page.getByTestId("user-access-tech@dev.local")).toContainText(String(d.getFullYear()));

  // A role change that does not touch expiry keeps it (the server preserves an omitted expiry).
  await page.getByTestId("user-role-select-tech@dev.local").selectOption("readonly");
  await expect(page.getByTestId("user-role-tech@dev.local")).toHaveText("readonly");
  await expect(page.getByTestId("user-access-tech@dev.local")).toContainText("Expires");

  // Re-open and Save WITHOUT changing anything: nothing is sent (an unchanged expiry is never re-sent
  // through the minute-only input, so a past or to-the-second value cannot be rejected or rounded).
  const rolePosts: string[] = [];
  page.on("request", (r) => {
    if (r.method() === "POST" && /\/users\/[^/]+\/role$/.test(r.url())) rolePosts.push(r.postData() ?? "");
  });
  await page.getByTestId("user-access-edit-tech@dev.local").click();
  await expect(page.getByTestId("access-ends")).toHaveValue(local);
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("access-panel")).toBeHidden();
  expect(rolePosts, "an unchanged Save must send nothing").toHaveLength(0);

  // Re-open: the editor is pre-filled with the stored value; Never clears it (and that IS sent).
  await page.getByTestId("user-access-edit-tech@dev.local").click();
  await expect(page.getByTestId("access-ends")).toHaveValue(local);
  await page.getByTestId("access-never").check();
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("user-access-tech@dev.local")).toContainText("Never");
  expect(rolePosts.map((b) => JSON.parse(b).expires_at)).toEqual([null]);

  // An invite whose role is switched to Owner AFTER a date was typed drops the date (Owner access cannot
  // expire) and succeeds, instead of submitting a hidden expiry the server must refuse.
  await page.getByTestId("user-create-email").fill("second-owner@dev.local");
  await page.getByTestId("user-create-role").selectOption("technician");
  await page.getByTestId("user-create-expiry").fill(local);
  await page.getByTestId("user-create-role").selectOption("owner");
  await expect(page.getByTestId("user-create-expiry")).toHaveValue("");
  await page.getByTestId("user-create-submit").click();
  await expect(page.getByTestId("user-access-second-owner@dev.local")).toContainText("Never");

  // An invite can carry an expiry from the start.
  await page.getByTestId("user-create-email").fill("contractor@dev.local");
  await page.getByTestId("user-create-role").selectOption("technician");
  await page.getByTestId("user-create-expiry").fill(local);
  await page.getByTestId("user-create-submit").click();
  await expect(page.getByTestId("user-access-contractor@dev.local")).toContainText("Expires");
});

// docs/57 scheduled access windows, end to end: an invite carries hours from the start, the Access
// column shows them, a role change keeps them, an unchanged Save sends nothing, end-of-day round-trips,
// and unticking clears them.
test("an admin invites a user with set hours, keeps them across a role change, and clears them", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await (await consoleTab(page, { name: "Users" })).click();
  await expect(page.getByTestId("user-row-tech@dev.local")).toBeVisible({ timeout: 15_000 });

  // Invite with Mon-Fri (the default) 09:00-17:00 UTC.
  await page.getByTestId("user-create-email").fill("shift@dev.local");
  await page.getByTestId("user-create-role").selectOption("technician");
  await page.getByTestId("user-create-window-enabled").check();
  await page.getByTestId("user-create-window-start").fill("09:00");
  await page.getByTestId("user-create-window-end").fill("17:00");
  await page.getByTestId("user-create-window-zone").selectOption("UTC");
  await page.getByTestId("user-create-submit").click();
  await expect(page.getByTestId("user-window-shift@dev.local")).toHaveText("Mon–Fri 09:00–17:00 (UTC)");
  // The invite form resets to "any time" for the next user.
  await expect(page.getByTestId("user-create-window-enabled")).not.toBeChecked();

  // A role change that does not mention hours keeps them.
  await page.getByTestId("user-role-select-shift@dev.local").selectOption("readonly");
  await expect(page.getByTestId("user-role-shift@dev.local")).toHaveText("readonly");
  await expect(page.getByTestId("user-window-shift@dev.local")).toHaveText("Mon–Fri 09:00–17:00 (UTC)");

  const rolePosts: string[] = [];
  page.on("request", (r) => {
    if (r.method() === "POST" && /\/users\/[^/]+\/role$/.test(r.url())) rolePosts.push(r.postData() ?? "");
  });
  // Re-open: pre-filled; an unchanged Save sends nothing.
  await page.getByTestId("user-access-edit-shift@dev.local").click();
  await expect(page.getByTestId("access-window-enabled")).toBeChecked();
  await expect(page.getByTestId("access-window-start")).toHaveValue("09:00");
  await expect(page.getByTestId("access-window-end")).toHaveValue("17:00");
  await expect(page.getByTestId("access-window-zone")).toHaveValue("UTC");
  await expect(page.getByTestId("access-window-day-mon")).toBeChecked();
  await expect(page.getByTestId("access-window-day-sat")).not.toBeChecked();
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("access-panel")).toBeHidden();
  expect(rolePosts, "an unchanged Save must send nothing").toHaveLength(0);

  // Weekend overnight to end of day: Sat + Sun only, 22:00 to 24:00. Only the window is sent (the
  // expiry was not touched, so it is omitted and preserved).
  await page.getByTestId("user-access-edit-shift@dev.local").click();
  for (const d of ["mon", "tue", "wed", "thu", "fri"]) await page.getByTestId(`access-window-day-${d}`).uncheck();
  await page.getByTestId("access-window-day-sat").check();
  await page.getByTestId("access-window-day-sun").check();
  await page.getByTestId("access-window-start").fill("22:00");
  await page.getByTestId("access-window-end-of-day").check();
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("access-panel")).toBeHidden();
  await expect(page.getByTestId("user-window-shift@dev.local")).toHaveText("Sat, Sun 22:00–24:00 (UTC)");
  expect(rolePosts).toHaveLength(1);
  const sent = JSON.parse(rolePosts[0]);
  expect(sent.access_window).toEqual({ days: ["sat", "sun"], start: "22:00", end: "24:00", time_zone: "UTC" });
  expect("expires_at" in sent).toBe(false);

  // 24:00 comes back as "end of day" ticked.
  await page.getByTestId("user-access-edit-shift@dev.local").click();
  await expect(page.getByTestId("access-window-end-of-day")).toBeChecked();
  // Untick: any time again (null is sent).
  await page.getByTestId("access-window-enabled").uncheck();
  await page.getByTestId("access-save").click();
  await expect(page.getByTestId("access-panel")).toBeHidden();
  await expect(page.getByTestId("user-window-shift@dev.local")).toHaveCount(0);
  expect(JSON.parse(rolePosts[1]).access_window).toBeNull();

  // An Owner has no hours section in the invite form.
  await page.getByTestId("user-create-role").selectOption("owner");
  await expect(page.getByTestId("user-create-window")).toHaveCount(0);
});
