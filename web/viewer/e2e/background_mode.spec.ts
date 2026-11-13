/**
 * Background mode end-to-end: when the console's window is hidden (as Chrome reports a minimised or
 * background tab), the real console must send `SetBackground { background: true }` to a real
 * `agent_host`, and `false` when it is shown again. The agent's own debug line is the observable, so
 * this proves the whole path: Viewer visibility -> BackgroundTracker -> ControlClient -> the agent's
 * decode and state. Setup is copied from type_clipboard.spec.ts (signaling + synthetic agent +
 * browser).
 */
import { PINNED } from "./chrome_pinned";
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
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
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";

const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
/** Accumulated agent stdout AND stderr (tracing writes the debug line to stderr). */
let agentLog = "";

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

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 200): Promise<boolean> {
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
    if (!existsSync(SIGNALING_EXE)) {
      skipReason = `${SIGNALING_EXE} is missing — globalSetup should have built it`;
      return;
    }
    signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"], { cwd: SIGNALING_DIR, stdio: "ignore" });
    if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000))) {
      skipReason = `signaling server did not come up on :${SIG_PORT}`;
      return;
    }
  }
  agentProc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30"],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RMT_LOG: "debug" } },
  );
  let agentStarted = false;
  const take = (d: Buffer) => {
    const s = d.toString();
    agentLog += s;
    if (s.includes("agent device=")) agentStarted = true;
  };
  agentProc.stdout?.on("data", take);
  agentProc.stderr?.on("data", take);
  agentProc.on("exit", (code) => process.stdout.write(`[agent] exited code=${code}\n`));
  await waitFor(async () => agentStarted, 8_000);
  await new Promise((r) => setTimeout(r, 1_000)); // settle so RegisterAgent lands

  const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
  try {
    browser = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
  } catch {
    try {
      browser = await chromium.launch({ headless: true, args: launchArgs });
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

/** What Chrome does on minimise / background tab: report `hidden` and fire `visibilitychange`. */
async function setVisibility(page: Page, state: "hidden" | "visible") {
  await page.evaluate((s) => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => s });
    document.dispatchEvent(new Event("visibilitychange"));
  }, state);
}

test("a hidden console puts the session in the background on the agent, and showing it brings it back", async () => {
  test.setTimeout(90_000);
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const context = await browser!.newContext({ ...PINNED });
  const page = await context.newPage();
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
  // The screen view is mounted and visible: nothing has been sent yet.
  await new Promise((r) => setTimeout(r, 1_500));
  const stateLines = () => agentLog.split(/\r?\n/).filter((l) => l.includes("viewer background state"));
  expect(stateLines(), "a visible console must not report background").toEqual([]);

  await setVisibility(page, "hidden");
  expect(await waitFor(async () => stateLines().some((l) => /background=true/.test(l)), 10_000), "hidden: no background=true on the agent").toBe(true);
  expect(stateLines().at(-1)).toMatch(/fps=1\b/);

  await setVisibility(page, "visible");
  expect(await waitFor(async () => stateLines().some((l) => /background=false/.test(l)), 10_000), "shown again: no background=false").toBe(true);
  expect(stateLines().at(-1)).toMatch(/fps=30\b/);

  await context.close();
});
