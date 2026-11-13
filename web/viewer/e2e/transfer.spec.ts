/**
 * Milestone V3 — file-transfer + clipboard operator-console end-to-end test.
 *
 * Drives the REAL App UI (`http://127.0.0.1:5173/`) exactly as an operator would (reusing V1's
 * manual-connect flow), then over ONE live `WebRTCTransport` session verifies both new V3 paths:
 *
 *   (a) **File upload** — switch to the Files tab, pick a known small file in the upload control,
 *       and assert the agent (launched with `--transfer-dir <tmp>`) wrote the exact bytes to that
 *       directory (byte-equal + SHA-256 match).
 *   (b) **Clipboard push** — grant the browser clipboard permissions, set a known string on the
 *       local clipboard, click "Send clipboard → agent", and assert the agent (launched with
 *       `--log-clipboard`) printed `CLIPBOARD-SET <that string>` on stdout.
 *
 * The agent's `stream` subcommand serves exactly one session per launch, so both checks run over the
 * same connection in one test. Self-skips (green, with a reason) when a prerequisite is absent.
 * Run: `npm run test:e2e`.
 */
import { PINNED } from "./chrome_pinned";
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const AGENT_BIN = resolve(REPO, "target", "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
import { SIGNALING_WS, SIG_PORT } from "./ports";
import { closeMenu, openMenu, selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";
const APP_ORIGIN = "http://127.0.0.1:5173";

const deviceId = randomUUID();
const transferDir = mkdtempSync(join(tmpdir(), "rmt-transfer-"));

// Known upload payload + its sha, and a unique clipboard string, computed up front.
const UPLOAD_NAME = "v3-upload.txt";
const UPLOAD_BYTES = Buffer.from(
  "hello from the V3 operator console — file transfer over WebRTC 🦀\nline two\n",
  "utf8",
);
const UPLOAD_SHA = createHash("sha256").update(UPLOAD_BYTES).digest("hex");
const CLIP_STRING = `clipboard-v3-${randomUUID()}`;

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;
/** Accumulated agent stdout, so the clipboard assertion can scan for its `CLIPBOARD-SET` line. */
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

  // Rust streaming agent: synthetic capture (headless) + `--transfer-dir` for uploads and
  // `--log-clipboard` (prints `CLIPBOARD-SET <text>`, never touches the real OS clipboard).
  agentProc = spawn(
    AGENT_BIN,
    [
      "stream",
      "--synthetic",
      "--signaling",
      SIGNALING_WS,
      "--device",
      deviceId,
      "--fps",
      "30",
      "--transfer-dir",
      transferDir,
      "--log-clipboard",
    ],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let agentStarted = false;
  agentProc.stdout?.on("data", (d: Buffer) => {
    const s = d.toString();
    agentLog += s;
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

test("operator console uploads a file and pushes the clipboard to the agent over one session", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  // A context that already holds clipboard permissions for the app origin, so `navigator.clipboard`
  // read/write is not gated by a prompt in headless Chromium (localhost is a secure context).
  const context = await browser!.newContext({ ...PINNED });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: APP_ORIGIN });
  const page = await context.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  await page.goto(APP_URL);

  // --- Manual-connect UI (reused from V1): signaling URL + DeviceId, then Connect. ---
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill(SIGNALING_WS);
  await page.getByTestId("manual-device").fill(deviceId);
  await page.getByTestId("manual-connect").click();

  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 30_000 },
  );
  // The status pill, not the diagnostics panel's "Connected" (both render; strict mode refuses the pair).
  await expect(page.locator(".viewer__status").getByText("Connected", { exact: true })).toBeVisible();

  // --- (a) File upload: switch to the Files tab and pick a known file. ---
  await selectSessionView(page, "Files");
  await expect(page.getByTestId("file-transfer-panel")).toBeVisible();

  await page.getByTestId("ft-file-input").setInputFiles({
    name: UPLOAD_NAME,
    mimeType: "text/plain",
    buffer: UPLOAD_BYTES,
  });

  // The panel resolves the agent's Ack into "Committed on agent" on success.
  await expect(page.getByTestId("ft-upload-status")).toContainText("Committed on agent", {
    timeout: 20_000,
  });

  // Assert the agent wrote the exact bytes to its transfer dir (byte-equal + sha match).
  const landed = join(transferDir, UPLOAD_NAME);
  const sawFile = await waitFor(async () => existsSync(landed), 10_000, 300);
  expect(sawFile, `uploaded file did not appear at ${landed}`).toBe(true);
  const gotBytes = readFileSync(landed);
  const gotSha = createHash("sha256").update(gotBytes).digest("hex");
  console.log(
    `[e2e] transfer channel=${browserChannel} upload → ${landed} bytes=${gotBytes.length} sha256=${gotSha}`,
  );
  expect(gotBytes.equals(UPLOAD_BYTES), "uploaded bytes must match").toBe(true);
  expect(gotSha, "uploaded sha256 must match").toBe(UPLOAD_SHA);

  // --- (b) Clipboard push: set a known local clipboard string, click Send, assert CLIPBOARD-SET. ---
  await page.bringToFront();
  await page.evaluate((s) => navigator.clipboard.writeText(s), CLIP_STRING);

  const beforeLen = agentLog.length;
  await openMenu(page, "Session");
  await page.getByTestId("clipboard-send").click();
  await expect(page.getByTestId("clipboard-status")).toContainText("Sent", { timeout: 10_000 });
  await closeMenu(page, "Session");

  const expectedLine = `CLIPBOARD-SET ${CLIP_STRING}`;
  const sawClip = await waitFor(async () => agentLog.includes(expectedLine), 10_000, 250);
  const clipLine =
    agentLog
      .slice(beforeLen)
      .split(/\r?\n/)
      .find((l) => l.startsWith("CLIPBOARD-SET ")) ?? "(none)";
  console.log(`[e2e] transfer clipboard → agent stdout line: ${clipLine}`);
  expect(sawClip, `agent did not print "${expectedLine}"`).toBe(true);

  await context.close();
});
