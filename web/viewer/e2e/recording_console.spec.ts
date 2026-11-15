/**
 * Loop 89 — SESSION RECORDING through the real console UI, and the files it leaves on disk.
 *
 * WHY THIS SPEC EXISTS.
 *
 * The recorder itself is covered from below: `recording.rs` has sixteen unit tests, `video/ivf.rs`
 * round-trips through an independent reader, and `e2e_recording.rs` drives the whole agent path
 * over a real WebRTC transport. None of that touches a browser. `web/viewer/vite.config.ts` globs
 * only `src/**\/*.{test,spec}.ts`, so `.tsx` has NO unit coverage — which is exactly how loop 87
 * shipped an elevation button that never rendered while every suite stayed green (loop 88 §1). A
 * recording toggle that never renders, or that lights up on the click instead of on the agent's
 * answer, would fail in precisely the same silent way.
 *
 * WHAT THE TWO TESTS PROVE, and why the second one is not optional:
 *
 *   1. THE POSITIVE. Click Record in the real console → the agent starts recording → the live badge
 *      appears → click again → the summary names real figures → and the IVF file and its sidecar
 *      are on disk, with the frame count in the UI matching the frame count in the artifact.
 *
 *   2. THE NEGATIVE CONTROL, against an agent started WITHOUT `--recording-dir`. Clicking Record
 *      must surface the agent's refusal and leave the badge dark. Without this, test 1 passes just
 *      as happily against a `toggleRecording` that optimistically sets `recording = true` on the
 *      click — i.e. against a console that claims a video of someone's screen is being written when
 *      nothing is. That is the difference between pinning a constant and testing a predicate
 *      (docs/07 `inert-feature-caught-by-render-test`), and this control is the only thing in the
 *      repo that can tell them apart.
 *
 * WHAT IT DELIBERATELY CANNOT PROVE: that the DACL was applied as intended on a real multi-user
 * machine, or that the guest's WINDOW displays the banner. The first is `recording.rs`'s
 * `a_recording_file_does_not_inherit_a_permissive_parent_ace`; the second is a Win32 fact — the
 * agent here runs `--synthetic` with no guest window at all, and `e2e_recording.rs` asserts the
 * SURFACE is told through a fake. Do not read a green run here as covering either.
 *
 * Run: `npm run test:e2e` (from web/viewer). Vite is started by playwright.config.ts's webServer.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { SIGNALING_WS, SIG_PORT } from "./ports";
import { openViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const AGENT_BIN = resolve(REPO, "target", "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const APP_URL = "http://127.0.0.1:5173/";

/** The agent that CAN record, and the scratch directory it records into. */
const recordingDevice = randomUUID();
let recordingDir = "";
/** The agent that cannot — no `--recording-dir`, which is the attended host's configuration. */
const noRecordingDevice = randomUUID();

let signalingProc: ChildProcess | null = null;
let recordingAgent: ChildProcess | null = null;
let plainAgent: ChildProcess | null = null;
let browser: Browser | null = null;
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

/** Spawn one `agent_host stream --synthetic` and resolve once it has announced itself. */
async function spawnAgent(device: string, extra: string[]): Promise<ChildProcess> {
  const proc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", device, "--fps", "30", ...extra],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let started = false;
  proc.stdout?.on("data", (d: Buffer) => {
    const s = d.toString();
    process.stdout.write(`[agent ${device.slice(0, 8)}] ${s}`);
    if (s.includes("agent device=")) started = true;
  });
  proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agent:err] ${d.toString()}`));
  await waitFor(async () => started, 8_000);
  return proc;
}

/** Connect the real console UI to `device` through the manual-connect form. */
async function connectConsole(device: string) {
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill(SIGNALING_WS);
  await page.getByTestId("manual-device").fill(device);
  await page.getByTestId("manual-connect").click();
  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 30_000 },
  );
  return page;
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
    signalingProc = spawn(
      SIGNALING_EXE,
      ["-addr", `:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"],
      { cwd: SIGNALING_DIR, stdio: "ignore" },
    );
    if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000))) {
      skipReason = `signaling server did not come up on :${SIG_PORT}`;
      return;
    }
  }

  // A scratch directory, NOT `C:\rmt-agent\recordings`. `--recording-dir` exists for exactly this:
  // the production path is a fixed location under the agent's root, and a test must not write video
  // there (nor rely on it being writable). Everything downstream of the path is the real code —
  // real IVF, real DACL, real digests.
  recordingDir = mkdtempSync(join(tmpdir(), "rmt-rec-e2e-"));

  recordingAgent = await spawnAgent(recordingDevice, ["--recording-dir", recordingDir]);
  plainAgent = await spawnAgent(noRecordingDevice, []);
  await new Promise((r) => setTimeout(r, 1_000)); // settle so both RegisterAgents land

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
  await stopProc(recordingAgent);
  await stopProc(plainAgent);
  await stopProc(signalingProc);
  if (recordingDir) rmSync(recordingDir, { recursive: true, force: true });
});

test("the console records a session, and the file it names is really there", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await connectConsole(recordingDevice);
  await openViewerPanel(page, "tools");

  const record = page.getByTestId("viewer-record");
  await expect(record, "the Record control must render for a connected session").toBeVisible();
  await expect(record, "nothing is recording yet").toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("viewer-record-live")).toHaveCount(0);

  // ---- start ---------------------------------------------------------------------------------
  await record.click();
  // The badge tracks the AGENT's ack, so waiting for it is waiting for a real round trip.
  await expect(page.getByTestId("viewer-record-live")).toBeVisible({ timeout: 15_000 });
  await expect(record).toHaveAttribute("aria-pressed", "true");
  await expect(record).toHaveText(/Stop recording/);
  // A fixture mistake must fail loudly rather than "proving" that a button exists: if the agent had
  // refused, the app-error banner would be the thing on screen instead of the badge.
  await expect(page.getByTestId("app-error")).toHaveCount(0);

  // Let the encoder actually produce frames for the tee.
  await page.waitForTimeout(2_000);

  // ---- stop ----------------------------------------------------------------------------------
  await record.click();
  const result = page.getByTestId("viewer-record-result");
  await expect(result).toBeVisible({ timeout: 15_000 });
  await expect(record).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("viewer-record-live")).toHaveCount(0);

  const summary = (await result.textContent()) ?? "";
  console.log(`[e2e] recording summary: ${summary}`);
  expect(summary, "a clean stop must not be reported as truncated").not.toMatch(/TRUNCATED/);
  expect(summary, "the operator is told where the files are, on the GUEST").toContain(recordingDir);
  const framesInUi = Number(/Recorded (\d+) frames/.exec(summary)?.[1] ?? "0");
  expect(framesInUi, `no frame count in the summary: ${summary}`).toBeGreaterThan(4);

  // ---- and now the disk, which is the only thing that makes the summary a fact ----------------
  const files = readdirSync(recordingDir);
  const sidecarName = files.find((f) => f.endsWith(".json"));
  const ivfName = files.find((f) => f.endsWith(".ivf"));
  expect(sidecarName, `no sidecar in ${recordingDir}: ${files.join(", ")}`).toBeTruthy();
  expect(ivfName, `no IVF file in ${recordingDir}: ${files.join(", ")}`).toBeTruthy();

  const sidecar = JSON.parse(readFileSync(join(recordingDir, sidecarName!), "utf8")) as {
    kind: string;
    truncated: string | null;
    disclaimer: string;
    segments: Array<{ file: string; frames: number; width: number; height: number; sha256: string }>;
  };
  expect(sidecar.kind).toBe("rmt.session-recording.v1");
  expect(sidecar.truncated).toBeNull();
  expect(sidecar.disclaimer, "the artifact carries its own honesty").toContain("local");
  expect(sidecar.segments).toHaveLength(1);
  expect(
    sidecar.segments[0].frames,
    "the number the operator read must be the number in the artifact",
  ).toBe(framesInUi);

  const bytes = readFileSync(join(recordingDir, sidecar.segments[0].file));
  expect(bytes.subarray(0, 4).toString("latin1"), "IVF signature").toBe("DKIF");
  expect(bytes.subarray(8, 12).toString("latin1"), "VP8 fourcc").toBe("VP80");
  expect(
    bytes.readUInt32LE(24),
    "finalize must patch the header's frame count — an abandoned writer leaves it at 0",
  ).toBe(framesInUi);

  await page.close();
});

test("a console cannot claim a recording an agent refused to start", async () => {
  // THE NEGATIVE CONTROL. See the header: without it the positive test above passes against a UI
  // that lights its badge on the click rather than on the agent's answer.
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await connectConsole(noRecordingDevice);
  await openViewerPanel(page, "tools");

  const record = page.getByTestId("viewer-record");
  await expect(record).toBeVisible();
  await record.click();

  // The refusal must reach the operator…
  await expect(page.getByTestId("app-error")).toContainText(/recording is not available/i, {
    timeout: 15_000,
  });
  // …and the console must not be claiming a recording is running.
  await expect(page.getByTestId("viewer-record-live")).toHaveCount(0);
  await expect(record).toHaveAttribute("aria-pressed", "false");
  await expect(record).toHaveText(/^⏺ Record$/);
  // The button must also be usable again — a refusal that leaves `recordingPending` set would
  // disable the control for the rest of the session.
  await expect(record).toBeEnabled();

  await page.close();
});
