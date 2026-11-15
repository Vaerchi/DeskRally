/**
 * "Type clipboard" end-to-end (Ed, 2026-10-23: paste by typing): the technician's clipboard is typed
 * into the guest through the real console against a real `agent_host --log-input`, whose
 * `INJECTED <json>` lines must be EXACTLY the events lib/type_text promises: text in chunks, Enter and
 * Tab as key presses, control characters dropped. View-only must disable it. Setup is copied from
 * phone_typing.spec.ts (same signaling + synthetic agent + browser).
 */
import { PINNED } from "./chrome_pinned";
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
import { clickInMenu, closeMenu, openMenu } from "./nav";
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";

const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;
/** Accumulated agent stdout, so the input assertion can scan for its `INJECTED <json>` lines. */
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

  // Rust streaming agent: synthetic capture (headless, deterministic) + LoggingSink that prints
  // `INJECTED <json>` per decoded input event and does NOT call real SendInput.
  agentProc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30"],
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



test("type clipboard: the clipboard reaches the agent as text chunks with Enter and Tab as key presses", async () => {
  test.setTimeout(90_000);
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const context = await browser!.newContext({ ...PINNED, permissions: ["clipboard-read", "clipboard-write"] });
  const page = await context.newPage();
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

  const injectedSince = (from: number) =>
    agentLog
      .slice(from)
      .split(/\r?\n/)
      .filter((l) => l.startsWith('INJECTED {"t":"Key"') || l.startsWith('INJECTED {"t":"Text"'));
  const textLine = (s: string) => `INJECTED ${JSON.stringify({ t: "Text", c: s })}`;
  const tapLines = (vk: number) => [
    `INJECTED {"t":"Key","c":{"code":${vk},"down":true}}`,
    `INJECTED {"t":"Key","c":{"code":${vk},"down":false}}`,
  ];

  // One event per character (a burst garbles Windows 11 Notepad; see lib/type_text).
  const line1 = "Pässwörd-0123456789-abcdefghijklmnopqrst";
  expect([...line1]).toHaveLength(40);
  await page.evaluate((s) => navigator.clipboard.writeText(s), `${line1}\r\nuser\tname\u001b!`);

  await page.getByTestId("viewer-input-menu").click();
  const start = page.getByTestId("type-clipboard-start");
  await expect(start).toBeEnabled();
  const from = agentLog.length;
  await start.click();
  const last = textLine("!");
  // 51 characters + 2 keys at 60 ms apart: about 3.2 s. Wait for the final "!" AFTER "name".
  expect(await waitFor(async () => injectedSince(from).length >= 40 + 2 + 4 + 2 + 5, 15_000, 200), "typing did not reach the agent").toBe(true);
  expect(injectedSince(from), "one Text per character, Enter, Tab, ESC dropped — in order and nothing else").toEqual([
    ...[...line1].map(textLine),
    ...tapLines(13),
    ...[..."user"].map(textLine),
    ...tapLines(9),
    ...[..."name!"].map(textLine),
  ]);
  await expect(page.getByTestId("type-clipboard-status")).toHaveText("Typed 51 characters.");

  // View-only: the action is disabled, and nothing is typed.
  await page.getByTestId("viewer-view-only").click();
  await expect(page.getByTestId("viewer-view-only")).toHaveAttribute("aria-pressed", "true");
  if (!(await start.isVisible())) await page.getByTestId("viewer-input-menu").click();
  await expect(page.getByTestId("type-clipboard-start")).toBeDisabled();

  await context.close();
});
