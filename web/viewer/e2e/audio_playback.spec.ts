/**
 * Audio passthrough end-to-end, at the layer nothing had asserted: a real browser DECODES and PLAYS
 * the agent's sound. The Rust e2e proves the Opus track flows and the console spec proves Chrome
 * negotiates the audio m-line, but neither ever looked at decoded samples, so a console that
 * negotiated the track and never played it would pass both.
 *
 * The agent runs `stream --synthetic --synthetic-tone`: its audio track carries a steady 440 Hz tone
 * (never the machine's own output). A tone, not silence, because with DTX a silent frame is one byte
 * and a silence-fed test would pass on a stream carrying no sound at all. Setup is copied from
 * background_mode.spec.ts (signaling + synthetic agent + browser).
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
    ["stream", "--synthetic", "--synthetic-tone", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "15"],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
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

/** The `<video>` element that carries the session's stream (the audio plays through it). */
const PLAYER = `[data-testid="viewer-surface"] video`;

type AudioInbound = { totalSamplesReceived: number; totalAudioEnergy: number; audioLevel: number } | null;

async function audioInbound(page: Page): Promise<AudioInbound> {
  return page.evaluate(async () => {
    const r = (window as unknown as { __rmt: { stats(): Promise<RTCStatsReport | undefined> } }).__rmt;
    const report = await r.stats();
    let found: AudioInbound = null;
    report?.forEach((s) => {
      const x = s as unknown as Record<string, unknown>;
      if (x.type === "inbound-rtp" && x.kind === "audio") {
        found = {
          totalSamplesReceived: Number(x.totalSamplesReceived ?? 0),
          totalAudioEnergy: Number(x.totalAudioEnergy ?? 0),
          audioLevel: Number(x.audioLevel ?? 0),
        };
      }
    });
    return found;
  });
}

/** RMS and dominant frequency of the stream's audio track, measured in the page with WebAudio. */
async function analyse(page: Page): Promise<{ rms: number; peakHz: number }> {
  return page.evaluate(async (sel) => {
    const players = [...document.querySelectorAll(sel)] as HTMLVideoElement[];
    const el = players.find((v) => v.srcObject instanceof MediaStream && v.srcObject.getAudioTracks().length > 0);
    if (!el) throw new Error("no video element carries an audio track");
    const track = (el.srcObject as MediaStream).getAudioTracks()[0];
    const ctx = new AudioContext();
    await ctx.resume();
    const src = ctx.createMediaStreamSource(new MediaStream([track]));
    const an = ctx.createAnalyser();
    an.fftSize = 4096;
    src.connect(an);
    await new Promise((r) => setTimeout(r, 1_000));
    const time = new Float32Array(an.fftSize);
    an.getFloatTimeDomainData(time);
    const rms = Math.sqrt(time.reduce((a, v) => a + v * v, 0) / time.length);
    const freq = new Float32Array(an.frequencyBinCount);
    an.getFloatFrequencyData(freq);
    let peak = 0;
    for (let i = 1; i < freq.length; i++) if (freq[i] > freq[peak]) peak = i;
    const peakHz = (peak * ctx.sampleRate) / an.fftSize;
    await ctx.close();
    return { rms, peakHz };
  }, PLAYER);
}

test("the console decodes and plays the agent's sound once the operator turns it on", async () => {
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
  expect(await waitFor(async () => agentLog.includes("synthetic 440 Hz test tone"), 5_000), "the agent did not start the test tone").toBe(true);

  // Sound starts OFF (browser autoplay rules and an open-plan office agree), and the player is muted.
  const players = page.locator(PLAYER);
  await expect.poll(async () => players.evaluateAll((els) => els.some((e) => (e as HTMLVideoElement).srcObject !== null))).toBe(true);
  expect(await players.evaluateAll((els) => els.every((e) => (e as HTMLVideoElement).muted)), "sound must start off").toBe(true);

  // The operator turns it on in the View menu.
  if (!(await page.getByTestId("viewer-audio").isVisible())) await page.getByTestId("viewer-view-menu").click();
  const toggle = page.getByTestId("viewer-audio");
  await expect(toggle, "the agent's audio track never reached the console").toBeEnabled({ timeout: 10_000 });
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect.poll(
    async () => players.evaluateAll((els) => els.some((e) => {
      const v = e as HTMLVideoElement;
      return !v.muted && !v.paused && v.srcObject instanceof MediaStream && v.srcObject.getAudioTracks().length > 0;
    })),
    { message: "no unmuted, playing element carries the audio track" },
  ).toBe(true);

  // Chrome's own receiver counters: decoded samples, with real energy (a silent stream has ~0).
  let first: AudioInbound = null;
  expect(await waitFor(async () => {
    first = await audioInbound(page);
    return !!first && first.totalSamplesReceived > 0 && first.totalAudioEnergy > 0;
  }, 10_000), "no decoded audio samples with energy in inbound-rtp").toBe(true);
  await new Promise((r) => setTimeout(r, 1_000));
  const later = (await audioInbound(page))!;
  expect(later.totalSamplesReceived, "decoded samples stopped growing").toBeGreaterThan(first!.totalSamplesReceived);
  expect(later.audioLevel, "the decoded level is silence").toBeGreaterThan(0.05);

  // And the signal in the page is the agent's tone: loud enough, and at 440 Hz.
  const { rms, peakHz } = await analyse(page);
  console.log(`[e2e] audio: inbound ${JSON.stringify(later)} analyser rms=${rms.toFixed(3)} peak=${peakHz.toFixed(0)} Hz`);
  expect(rms, "the decoded track is silent").toBeGreaterThan(0.05);
  expect(Math.abs(peakHz - 440), "the decoded track is not the 440 Hz test tone").toBeLessThan(25);

  await context.close();
});
