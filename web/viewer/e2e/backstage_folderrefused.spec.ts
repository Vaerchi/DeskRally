/**
 * docs/58 §12 — "Upload here" end to end against a REAL agent: the file is uploaded over the session's
 * file-transfer channel, then placed by its transfer id in the folder being browsed, and the disk is
 * checked. The test agent is not LocalSystem, so it is started with RMT_TEST_UPLOADS_ANCHORED=1, which
 * only a test-harness build honours, to treat its (temporary) transfer folder as the anchored one and
 * offer placement. Its own spec, so its own agent process (the dev agent serves one session).
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";

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
// The agent's transfer folder for this run (never the installed agent's C:\rmt-agent).
const TRANSFER_DIR = resolve(tmpdir(), `rmt-e2e-refused-transfers-${deviceId.slice(0, 8)}`);

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
  agentProc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30", "--transfer-dir", TRANSFER_DIR],
    {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, RMT_TEST_UPLOADS_ANCHORED: "1" },
    },
  );
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

// Live bug 2026-11-25: "Choose a folder" raised NotAllowedError ("The request is not allowed by the user agent or the
// platform in the current context") and the raw message was all the technician saw. A window that refuses folder
// access must fall back to the file picker, with a plain reason.
const REFUSING_PICKER = `
window.showDirectoryPicker = async () => {
  throw new DOMException("The request is not allowed by the user agent or the platform in the current context.", "NotAllowedError");
};
`;

test("a window that refuses folder access falls back to Choose files with a plain reason", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  const page = await browser!.newPage();
  await page.addInitScript(REFUSING_PICKER);
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
  await page.getByTestId("local-choose").click();
  await expect(page.getByTestId("local-no-folder-access")).toContainText("not allowed to open a folder", { timeout: 10_000 });
  // On the drive list there is no remote folder to send into: Send is replaced by a hint (2026-11-25 "-> :" fix).
  await expect(page.getByTestId("local-send-hint")).toContainText("Open a folder on the remote machine");
  await expect(page.getByTestId("local-pick-files")).toHaveCount(0);
  await expect(page.getByText("The request is not allowed by the user agent")).toHaveCount(0);
  await page.close();
});