// Its own spec (and so its own signaling + agent process): the dev agent serves ONE session, so a second test in
// backstage.spec.ts waited on an agent that had already served the first and only passed on a retry.
/**
 * Milestone V2 — backstage-console end-to-end test.
 *
 * Drives the REAL App UI (`http://127.0.0.1:5173/`) exactly as an operator would: types a target
 * DeviceId + signaling URL into the manual-connect inputs (reusing V1's flow), clicks Connect, waits
 * for the live `WebRTCTransport` to connect, then switches to the **Backstage** view and asserts the
 * console renders REAL agent data over the session's `ChannelId.Backstage`:
 *
 *   (a) the **System** tab shows a non-empty Hostname + OS (from the agent's `GetSystemInfo`), and an
 *       **audit hash** appears in the audit strip — proving a tamper-evident dispatch round-tripped;
 *   (b) the **Processes** tab renders a non-empty process list (from `ListProcesses`).
 *
 * The agent runs `stream --synthetic` in dev mode: with no grant issuer configured it self-issues a
 * demo grant, so backstage is authorized with no grant install needed (secure-mode grant install is
 * the H1 hook, verified elsewhere). Self-skips (green, with a reason) when a prerequisite is absent.
 * Run: `npm run test:e2e`.
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
import { clickInMenu, openMenu, selectSessionView } from "./nav";
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
    signalingProc = spawn(SIGNALING_EXE, ["-addr", `127.0.0.1:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"], { cwd: SIGNALING_DIR, stdio: "ignore" });
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


// 2026-11-24: Under the Hood from the Session menu, in its own window, with the screen left in the console tab.
test("Under the Hood opens in its own window from the Session menu and the console keeps the screen", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await browser!.newPage();
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

  const popupPromise = page.context().waitForEvent("page");
  await clickInMenu(page, "Session", page.getByTestId("session-uth-window"));
  const popup = await popupPromise;
  // The tools live in the new window...
  await popup.getByRole("tab", { name: "Processes", exact: true }).click();
  const procRows = popup.locator(".panel--process tbody tr .panel__name");
  await expect(procRows.first()).not.toHaveText("", { timeout: 15_000 });
  // ...while the console tab keeps the screen.
  await expect(page.getByRole("combobox", { name: "Session view", exact: true })).toHaveValue("screen");

  // Closing the window returns the console to its normal state.
  await popup.close();
  await openMenu(page, "Session");
  await expect(page.getByTestId("session-uth-window")).toHaveText("Open Under the Hood in a new window", { timeout: 5_000 });
  await page.close();
});
