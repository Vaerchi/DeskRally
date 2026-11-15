/**
 * docs/58 — Under the Hood file management end to end, against a REAL agent over the session.
 *
 * Its own spec (and so its own signaling + agent process) because the dev agent serves one session:
 * a second test in backstage.spec.ts would wait on an agent that has already served the first.
 * Drives New folder, Rename and Delete (the delete through the type-the-machine-name dialog, which
 * completes only because the confirmation token travels over the session channel) and checks the
 * disk after each. Self-skips (with a reason) when a prerequisite is absent.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const AGENT_BIN = resolve(REPO, "target", "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
import { SIGNALING_WS, SIG_PORT } from "./ports";
import { selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";

const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;

function wsReachable(url: string, timeoutMs: number): Promise<boolean> {
  return new Promise((res) => {
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      res(ok);
    };
    const ws = new WebSocket(url);
    ws.onopen = () => finish(true);
    ws.onerror = () => finish(false);
    setTimeout(() => finish(false), timeoutMs);
  });
}

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 300): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

test.beforeAll(async () => {
  if (!existsSync(AGENT_BIN)) {
    skipReason = `agent binary not found at ${AGENT_BIN} (run: cargo build -p rmt-agent-windows --bin agent_host)`;
    return;
  }

  if (!(await wsReachable(SIGNALING_WS, 800))) {
    // globalSetup (e2e/global-setup.ts) builds this unconditionally before any worker starts. Assert,
    // never build: a build-if-absent guard here is what made the suite run a stale binary on every run
    // after the first.
    if (!existsSync(SIGNALING_EXE)) {
      skipReason = `${SIGNALING_EXE} is missing — globalSetup should have built it`;
      return;
    }
    // The signaling server refuses to start without SIGNALING_TICKET_PUBKEY (unverified brokering
    // would let any WS client reach any agent). This local harness has no control plane to take the
    // key from, so it opts out explicitly — the same flag a developer uses by hand.
    signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"], { cwd: SIGNALING_DIR, stdio: "ignore" });
    const up = await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000);
    if (!up) {
      skipReason = `signaling server did not come up on :${SIG_PORT}`;
      return;
    }
  }

  // Rust streaming agent: synthetic capture + dev-mode backstage (self-issued demo grant).
  agentProc = spawn(AGENT_BIN, ["stream", "--synthetic", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30"], {
    cwd: REPO,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let agentStarted = false;
  agentProc.stdout?.on("data", (d: Buffer) => {
    const s = d.toString();
    process.stdout.write(`[agent] ${s}`);
    if (s.includes("agent device=")) agentStarted = true;
  });
  agentProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agent:err] ${d.toString()}`));
  agentProc.on("exit", (code) => process.stdout.write(`[agent] exited code=${code}\n`));

  await waitFor(async () => agentStarted, 8_000);
  await new Promise((r) => setTimeout(r, 1_000)); // settle so RegisterAgent lands

  const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
  try {
    browser = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
    browserChannel = "chrome(system)";
  } catch {
    try {
      browser = await chromium.launch({ headless: true, args: launchArgs });
      browserChannel = "chromium(bundled)";
    } catch (e) {
      skipReason = `no usable browser: ${String(e)}`;
    }
  }
});

test.afterAll(async () => {
  await browser?.close().catch(() => {});
  await stopProc(agentProc);
  await stopProc(signalingProc);
});

// docs/58: Under the Hood file management against the REAL agent. The test works in a folder of its
// own at the top of C: (the temp folder can exceed the browse entry limit) and checks the disk after
// each change: New folder, Rename, then Delete through the type-the-machine-name dialog, which
// completes only because the confirmation token now travels over the session channel.
test("Under the Hood creates, renames and deletes a folder, delete confirmed by the machine name", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  const { mkdirSync, rmSync } = await import("node:fs");
  const workName = `rmt-e2e-${randomUUID().slice(0, 8)}`;
  // Paths are built from the backslash's code: an escaped backslash in this file was halved once.
  const BS = String.fromCharCode(92);
  const at = (...parts: string[]) => parts.join(BS);
  const work = at("C:", workName);
  mkdirSync(at(work, "inside"), { recursive: true });
  try {
    const page = await browser!.newPage();
    page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
    await page.goto(APP_URL);
    await openManualConnect(page);
    await page.getByTestId("signaling-url").fill(SIGNALING_WS);
    await page.getByTestId("manual-device").fill(deviceId);
    await page.getByTestId("manual-connect").click();
    await page.waitForFunction(
      () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
      undefined,
      { timeout: 30_000 },
    );
    await selectSessionView(page, "Under the Hood");
    await page.getByRole("tab", { name: "Files", exact: true }).click();

    // Drives -> C:\ -> the work folder -> inside (a folder two levels down: no top-of-drive prompt).
    await page.getByRole("button", { name: `C:${BS}` }).first().click();
    // Each folder row now also has Rename/Delete buttons whose labels contain its name: click the
    // folder LINK itself.
    await page.locator(".panel__filelink", { hasText: workName }).click();
    await page.locator(".panel__filelink", { hasText: "inside" }).click();
    await expect(page.getByTestId("files-new-folder")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("files-silent-note")).toBeVisible();

    // New folder.
    await page.getByTestId("files-new-folder").click();
    await page.getByTestId("files-new-folder-name").fill("alpha");
    await page.getByTestId("files-new-folder-create").click();
    await expect(page.getByTestId("files-rename-alpha")).toBeVisible({ timeout: 15_000 });
    expect(existsSync(at(work, "inside", "alpha"))).toBe(true);

    // Rename.
    await page.getByTestId("files-rename-alpha").click();
    await page.getByTestId("files-rename-name-alpha").fill("beta");
    await page.getByTestId("files-rename-save-alpha").click();
    await expect(page.getByTestId("files-rename-beta")).toBeVisible({ timeout: 15_000 });
    expect(existsSync(at(work, "inside", "alpha"))).toBe(false);
    expect(existsSync(at(work, "inside", "beta"))).toBe(true);

    // Delete: always confirmed. The dialog names the RESOLVED path and wants the machine name.
    await page.getByTestId("files-delete-beta").click();
    const dialog = page.locator(".backstage__confirm");
    await expect(dialog).toBeVisible({ timeout: 15_000 });
    await expect(dialog).toContainText("beta");
    const machine = ((await dialog.locator(".backstage__confirm-hint code").textContent()) ?? "").trim();
    await dialog.locator(".backstage__confirm-input").fill(machine);
    await dialog.getByRole("button", { name: "Confirm" }).click();
    await expect(page.getByTestId("files-rename-beta")).toHaveCount(0, { timeout: 15_000 });
    expect(existsSync(at(work, "inside", "beta"))).toBe(false);
    await page.close();
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
