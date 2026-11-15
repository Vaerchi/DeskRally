/**
 * Milestone V1 — operator-console end-to-end test.
 *
 * Unlike `browser-agent.spec.ts` (which drives the transport directly via `harness.html`), this test
 * drives the REAL App UI (`http://127.0.0.1:5173/`) exactly as an operator would: it types a target
 * DeviceId + signaling URL into the manual-connect inputs, clicks Connect, and then:
 *
 *   (a) asserts inbound WebRTC video via `getStats()` (bytesReceived > 0 && packetsReceived > 0) —
 *       proving the App's own `WebRTCTransport` negotiated media, and
 *   (b) performs a real mouse move + click + keypress on the video surface and asserts the agent's
 *       stdout shows the matching `INJECTED {"t":"MouseMove"…}` / `"MouseButton"` / `"Key"` lines —
 *       proving the REAL console's input reaches the agent decoded correctly (canonical codec).
 *
 * Self-skips (green, with a reason) only when a prerequisite is genuinely absent. Run:
 * `npm run test:e2e` (Vite is started by playwright.config.ts's webServer).
 */
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
import { clickInViewerPanel, closeViewerPanel, openViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";

async function openPanel(page: Page, which: "view" | "input" | "tools") {
  const control = page.getByTestId({
    view: "viewer-quality-advanced",
    input: "viewer-capture-input",
    tools: "viewer-tools",
  }[which]);
  if (!(await control.isVisible())) {
    await page.getByTestId(`viewer-${which}-menu`).click();
  }
  await expect(control).toBeVisible();
}

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

test("operator console connects, receives video, and its input reaches the agent", async () => {
  test.setTimeout(120_000); // many interactive steps; 90s base too tight after screenshot Save prompt
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  // Record every SetBackground the console sends on a data channel (step c.7b). The synthetic agent
  // built from this tree may predate the message, so the console's own send is what is asserted.
  await page.addInitScript(() => {
    const w = window as unknown as { __bgSent: boolean[] };
    w.__bgSent = [];
    const send = RTCDataChannel.prototype.send;
    RTCDataChannel.prototype.send = function (this: RTCDataChannel, data: never) {
      try {
        const text = typeof data === "string" ? data
          : new TextDecoder().decode(data instanceof ArrayBuffer ? new Uint8Array(data) : (data as ArrayBufferView));
        const m = /"t":"SetBackground","c":\{"background":(true|false)\}/.exec(text);
        if (m) w.__bgSent.push(m[1] === "true");
      } catch { /* a Blob or an undecodable payload is not a control message */ }
      return send.call(this, data);
    };
  });

  await page.goto(APP_URL);

  // --- Drive the REAL manual-connect UI: type the signaling URL + DeviceId, click Connect. ---
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill(SIGNALING_WS);
  await page.getByTestId("manual-device").fill(deviceId);
  await page.getByTestId("manual-connect").click();

  // Wait for the App's own WebRTCTransport to reach "connected" (via the DEV stats seam).
  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 30_000 },
  );

  // The Viewer status bar should reflect the live connection too.
  // The status pill, not the diagnostics panel's "Connected" (both render; strict mode refuses the pair).
  await expect(page.locator(".viewer__status").getByText("Connected", { exact: true })).toBeVisible();

  // (a) Inbound WebRTC video — poll getStats up to ~12s for real bytes/packets. ---------------
  type Inbound = {
    bytesReceived?: number;
    packetsReceived?: number;
    framesDecoded?: number;
    codec?: string;
  } | null;

  let inbound: Inbound = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (window as unknown as {
          __rmt: { stats(): Promise<RTCStatsReport | undefined> };
        }).__rmt;
        const report = await r.stats();
        const all: Array<Record<string, unknown>> = [];
        report?.forEach((s) => all.push(s as unknown as Record<string, unknown>));
        const rtp = all.find((s) => s.type === "inbound-rtp" && (s as { kind?: string }).kind === "video");
        if (!rtp) return null;
        const codecEntry = all.find((s) => s.type === "codec" && s.id === (rtp as { codecId?: string }).codecId);
        return {
          bytesReceived: rtp.bytesReceived as number | undefined,
          packetsReceived: rtp.packetsReceived as number | undefined,
          framesDecoded: rtp.framesDecoded as number | undefined,
          codec: codecEntry ? (codecEntry.mimeType as string) : undefined,
        };
      });
      return !!inbound && (inbound.bytesReceived ?? 0) > 0 && (inbound.packetsReceived ?? 0) > 0;
    },
    12_000,
    500,
  );

  console.log(`[e2e] console channel=${browserChannel} inbound-rtp video: ${JSON.stringify(inbound)}`);
  expect(inbound, "no inbound-rtp video stats — no media reached the console").not.toBeNull();
  const got = inbound!;
  expect(got.bytesReceived ?? 0, "inbound video bytesReceived").toBeGreaterThan(0);
  expect(got.packetsReceived ?? 0, "inbound video packetsReceived").toBeGreaterThan(0);

  // (b) Real input from the console surface → agent INJECTED lines. ----------------------------
  const surface = page.getByTestId("viewer-surface");
  const box = await surface.boundingBox();
  expect(box, "viewer surface should be laid out").not.toBeNull();
  const b = box!;
  const cx = b.x + b.width / 2;
  const cy = b.y + b.height / 2;

  const beforeLen = agentLog.length;

  // Mouse move across the surface (React onMouseMove → MouseMove with normalized abs coords).
  await page.mouse.move(b.x + b.width * 0.25, b.y + b.height * 0.25);
  await page.mouse.move(cx, cy, { steps: 4 });
  // Left click (mousedown + mouseup → MouseButton Left down/up).
  await page.mouse.click(cx, cy);
  // Keypress 'a' (KeyboardEvent.code "KeyA" → VK 65 → Key down/up).
  await page.keyboard.press("a");

  const MOUSEMOVE_RE = /INJECTED \{"t":"MouseMove","c":\{"x":\d+,"y":\d+\}\}/;
  const BTN_DOWN = 'INJECTED {"t":"MouseButton","c":{"button":"Left","down":true}}';
  const BTN_UP = 'INJECTED {"t":"MouseButton","c":{"button":"Left","down":false}}';
  const KEY_DOWN = 'INJECTED {"t":"Key","c":{"code":65,"down":true}}';

  const sawInput = await waitFor(
    async () =>
      MOUSEMOVE_RE.test(agentLog.slice(beforeLen)) &&
      agentLog.includes(BTN_DOWN) &&
      agentLog.includes(BTN_UP) &&
      agentLog.includes(KEY_DOWN),
    12_000,
    250,
  );

  const injectedLines = agentLog
    .slice(beforeLen)
    .split(/\r?\n/)
    .filter((l) => l.startsWith("INJECTED "));
  console.log(`[e2e] agent INJECTED lines from the real console UI:\n${injectedLines.join("\n")}`);

  expect(sawInput, "agent did not report the console's mouse-move / click / keypress via INJECTED").toBe(true);
  // The canonical-codec proof: a MouseMove, a Left button-down, and Key VK 65 all decoded.
  expect(injectedLines.some((l) => MOUSEMOVE_RE.test(l)), "MouseMove INJECTED").toBe(true);
  expect(injectedLines).toContain(BTN_DOWN);
  // The button-UP must arrive too — it is delivered by a window-level listener so a release over the
  // letterbox or off-surface still reaches the remote (else a drag could leave a button stuck down).
  expect(injectedLines).toContain(BTN_UP);
  expect(injectedLines).toContain(KEY_DOWN);

  // (c) Special-key toolbar → agent INJECTED lines. -------------------------------------------
  // Ctrl+Alt+Del is the secure-desktop / UAC-unlock surface and rides InputEvent::Sas
  // (`{"t":"Sas"}`) — NOT raw Ctrl/Alt/Del key events, which Windows drops — so a break in the
  // render → onClick → sendSpecial → build() → transport.send wiring is otherwise silent. This
  // clicks the real toolbar buttons and checks the agent decoded them.
  const SAS_LINE = 'INJECTED {"t":"Sas"}';
  const beforeSas = agentLog.length;
  // The special-key bar is opened from the Input menu since the compact toolbar (e311d06).
  await page.getByTestId("viewer-input-menu").click();
  await page.getByTestId("viewer-special-keys-toggle").click();
  await page.keyboard.press("Escape");
  await page.getByTestId("special-cad").click();
  const sawSas = await waitFor(async () => agentLog.slice(beforeSas).includes(SAS_LINE), 8_000, 200);
  expect(sawSas, 'Ctrl+Alt+Del button did not reach the agent as INJECTED {"t":"Sas"}').toBe(true);

  // A multi-event chord (Win+D) must send its four Key events in order — this locks the
  // `for (const ev of sk.build())` send-each loop and the press/release nesting. VK 91 = LWIN, 68 = D.
  const beforeChord = agentLog.length;
  await page.getByTestId("special-win-d").click();
  const WIN_DOWN = 'INJECTED {"t":"Key","c":{"code":91,"down":true}}';
  const D_DOWN = 'INJECTED {"t":"Key","c":{"code":68,"down":true}}';
  const D_UP = 'INJECTED {"t":"Key","c":{"code":68,"down":false}}';
  const WIN_UP = 'INJECTED {"t":"Key","c":{"code":91,"down":false}}';
  const sawChord = await waitFor(
    async () => {
      const s = agentLog.slice(beforeChord);
      return s.includes(WIN_DOWN) && s.includes(D_DOWN) && s.includes(D_UP) && s.includes(WIN_UP);
    },
    8_000,
    200,
  );
  expect(sawChord, "Win+D chord did not reach the agent as four Key events").toBe(true);
  const chordKeyLines = agentLog
    .slice(beforeChord)
    .split(/\r?\n/)
    .filter((l) => l.startsWith('INJECTED {"t":"Key"'));
  expect(chordKeyLines, "Win+D chord must arrive as Win↓ D↓ D↑ Win↑ in order").toEqual([
    WIN_DOWN,
    D_DOWN,
    D_UP,
    WIN_UP,
  ]);

  // (c.1) Zoom & pan (M-ZP). Three properties the feature must hold, exercised against a live agent:
  //   • pointer input works at ANY zoom (retiring the old "input paused in 1:1" limitation),
  //   • special keys stay view-independent (a zoomed-in tech must still send Ctrl+Alt+Del), and
  //   • PAN MODE is view-only: a drag pans and reaches the remote as NOTHING.
  // Zoom in several steps so the image overflows the surface and Pan becomes available.
  await openViewerPanel(page, "view");
  for (let i = 0; i < 3; i++) await page.getByTestId("viewer-zoom-in").click();
  await closeViewerPanel(page, "view");

  // Special keys are view-independent — regressing this would silently disable the unlock surface
  // exactly when a tech zooms in.
  const beforeSas2 = agentLog.length;
  await page.getByTestId("special-cad").click();
  const sawSas2 = await waitFor(async () => agentLog.slice(beforeSas2).includes(SAS_LINE), 8_000, 200);
  expect(sawSas2, "Ctrl+Alt+Del stopped working while zoomed — special keys must be view-independent").toBe(true);

  // Pointer input now reaches the agent while zoomed in (this was PAUSED before the zoom/pan feature).
  const zbox = (await surface.boundingBox())!;
  const zcx = zbox.x + zbox.width / 2;
  const zcy = zbox.y + zbox.height / 2;
  const beforeZoomInput = agentLog.length;
  await page.mouse.move(zcx, zcy, { steps: 3 });
  await page.mouse.click(zcx, zcy);
  const sawZoomedInput = await waitFor(
    async () =>
      MOUSEMOVE_RE.test(agentLog.slice(beforeZoomInput)) && agentLog.slice(beforeZoomInput).includes(BTN_DOWN),
    8_000,
    250,
  );
  expect(sawZoomedInput, "pointer input did not reach the agent while zoomed — the mapping must work at any zoom").toBe(true);

  // Pan mode swallows ALL input: enable it, drag across the surface AND press a key, and assert
  // NOTHING new was injected. This is the safety half of the mode — the "pan mode — input not sent"
  // banner must be literally true, so neither a stray click nor a keystroke may reach the customer's
  // machine (a review caught keyboard leaking through while the banner claimed input was off).
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-pan"));
  await expect(page.getByTestId("viewer-pan-active")).toBeVisible();
  await openViewerPanel(page, "view");
  await expect(page.getByTestId("viewer-pan")).toHaveAttribute("aria-pressed", "true");
  await closeViewerPanel(page, "view");
  const beforePan = agentLog.length;
  await page.mouse.move(zbox.x + zbox.width * 0.6, zbox.y + zbox.height * 0.6);
  await page.mouse.down();
  await page.mouse.move(zbox.x + zbox.width * 0.4, zbox.y + zbox.height * 0.4, { steps: 4 });
  await page.mouse.up();
  await page.keyboard.press("z"); // must NOT reach the agent while panning
  await new Promise((r) => setTimeout(r, 500));
  const injectedDuringPan = agentLog
    .slice(beforePan)
    .split(/\r?\n/)
    .filter((l) => l.startsWith("INJECTED "));
  expect(injectedDuringPan, "pan mode leaked pointer or keyboard input to the remote").toEqual([]);

  // Turn Pan back off so the remainder of the run controls the remote again (still zoomed in).
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-pan"));
  await expect(page.getByTestId("viewer-pan-active")).toHaveCount(0);

  // (c.2) Block guest input (privacy). The button reflects the AGENT's `InputBlockApplied` ack, NOT
  // the click, so a toggle that flips the pressed state proves the whole viewer→agent→viewer round
  // trip: SetInputBlocked encodes on the Control channel, the agent dispatches it and answers with
  // the state in force, and the client routes that back to the UI. (The e2e agent runs --log-input,
  // so the block is mocked and installs no real OS hooks — it never freezes the test machine.)
  await openPanel(page, "input");
  const blockBtn = page.getByTestId("viewer-block-input");
  await expect(blockBtn).toHaveAttribute("aria-pressed", "false");
  await blockBtn.click();
  await expect(blockBtn, "the agent did not ack InputBlockApplied{true}").toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await blockBtn.click();
  await expect(blockBtn, "the agent did not ack the release").toHaveAttribute("aria-pressed", "false");

  // (c.2b) View-only / presentation mode. Like the input-block toggle, the pressed state follows the
  // AGENT's `ViewOnlyApplied` ack, so flipping it proves the whole SetViewOnly→ViewOnlyApplied round
  // trip (the agent-side enforcement itself — that injected input is DROPPED — is VM-verified, since
  // this browser agent injects nothing).
  await openPanel(page, "input");
  const viewOnlyBtn = page.getByTestId("viewer-view-only");
  await expect(viewOnlyBtn).toHaveAttribute("aria-pressed", "false");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn, "the agent did not ack ViewOnlyApplied{true}").toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn, "the agent did not ack resuming control").toHaveAttribute("aria-pressed", "false");

  // (c.2c) Blank guest monitor (privacy mode). Like the input-block toggle, the pressed state
  // follows the AGENT's `MonitorBlankedApplied` ack, so flipping it proves the whole
  // SetMonitorBlanked→MonitorBlankedApplied round trip. The e2e agent runs --log-input, so the
  // overlay is MOCKED (ScreenBlanker::new(false)): the agent tracks the requested state and
  // answers honestly but creates no real OS window — the build machine's screen is never blacked out.
  await openPanel(page, "input");
  const blankBtn = page.getByTestId("viewer-blank-monitor");
  await expect(blankBtn).toHaveAttribute("aria-pressed", "false");
  await blankBtn.click();
  await expect(blankBtn, "the agent did not ack MonitorBlankedApplied{true}").toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await blankBtn.click();
  await expect(blankBtn, "the agent did not ack the unblank").toHaveAttribute("aria-pressed", "false");

  // (c.3) Reboot guest (remote support). The status line follows the AGENT's `RebootScheduled` ack,
  // not the click, so its appearance proves the whole RebootGuest→RebootScheduled round trip: the
  // control encodes on the Control channel, the agent dispatches it, and its ack routes back to the
  // UI. Asserting the SAFE-MODE text also pins that the `safe_mode` boolean survives the wire (a mock
  // that always acked normal would show a different message). The e2e agent runs --log-input, so the
  // reboot is MOCKED (logged, not actuated) — the test machine never reboots. The inline confirm
  // (Reboot → Safe Mode) is a deliberate two-step, since a reboot is destructive.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-reboot").click();
  await openPanel(page, "tools");
  await page.getByTestId("viewer-reboot-safe").click();
  await expect(
    page.getByTestId("viewer-reboot-status"),
    "the agent did not ack RebootScheduled{safe_mode:true}",
  ).toContainText("Safe Mode");

  // (c.4) System tool launcher (remote support). The status line follows the AGENT's `ToolLaunched`
  // ack, so its appearance proves the whole LaunchTool→ToolLaunched round trip: the control encodes on
  // the Control channel, the agent resolves the whitelist key and (mocked, --log-input) acks without
  // spawning — the gate log shows `launch: MOCK — would launch Task Manager`, so nothing pops on CI.
  // Asserting the LABEL also pins that the key survived the wire and was resolved to the right tool.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-tools").click();
  await openPanel(page, "tools");
  await page.getByTestId("viewer-tool-task_manager").click();
  await expect(
    page.getByTestId("viewer-tool-status"),
    "the agent did not ack ToolLaunched{task_manager}",
  ).toContainText("Task Manager");

  // (c.5) One-line command bar (remote support). The output area follows the AGENT's `CommandResult`,
  // so its appearance proves the whole RunCommand→CommandResult round trip: the control encodes on the
  // Control channel, the agent runs it (mocked — the e2e agent is `--synthetic`, so nothing executes
  // and the gate log shows `command: MOCK`) and its captured result routes back to the UI. The mock
  // returns a canned result whose stdout mentions "mock"; asserting `exit 0` + that text pins that the
  // whole shape survived the wire. The viewer is still zoomed in here, which also pins that typing into
  // the command input does NOT leak to the remote (the window-level key capture ignores form fields).
  await openPanel(page, "tools");
  await page.getByTestId("viewer-command-toggle").click();
  await page.getByTestId("viewer-command-input").fill("whoami");
  await page.getByTestId("viewer-command-run").click();
  await expect(
    page.getByTestId("viewer-command-output"),
    "the agent did not return a CommandResult",
  ).toContainText("exit 0");
  await expect(page.getByTestId("viewer-command-output")).toContainText("mock");

  // (c.5a) ELEVATE TO ADMIN (loop 87, docs/01 §3) — THE NEGATIVE HALF. The positive half lives in
  // `elevate_console.spec.ts`; this is the assertion that stops it meaning "the button is always on".
  //
  // Loop 87 asserted here that "Run as admin" IS visible. That was wrong, and instructively so:
  // THIS SPEC STARTS NO CONTROL PLANE (see the file header — signaling + an agent only), so
  // `acquireBrokeredSession` resolves null, there is no session record an elevation grant could name,
  // and the viewer hides a control that could only ever fail. The assertion failed for a true reason.
  //
  // Inverted, it is exactly the right test to run here — and the pair pins the PREDICATE rather than
  // a constant: elevation is offered for a brokered session (elevate_console.spec.ts) and withheld
  // without one (here). Neither test alone can tell `canElevate = true` from
  // `canElevate = brokeredSessionRef.current !== null`.
  await expect(
    page.getByTestId("viewer-command-elevate"),
    "a session with NO control-plane record must not offer elevation — the grant would name nothing",
  ).toHaveCount(0);

  // (c.4b) FILE BROWSER (loop 44, docs/01 §3). Open Files → the agent lists the drive roots → open a
  // drive → it lists real folders → Up returns to the roots. READ-ONLY: it needs no mock (listing a
  // directory has no side effect) and the REAL agent lists the CI box's real filesystem, so C:\ and
  // its Windows folder are the whole observable. Proves the ListDirectory ↔ DirectoryListing round
  // trip and the browser's navigation end to end.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-loc")).toHaveText("This PC");
  // The drive roots arrived from the agent; open C:\ (the system drive on any Windows box).
  await expect(page.getByTestId("file-entry-C:\\")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("file-entry-C:\\").click();
  await expect(page.getByTestId("file-loc")).toHaveText("C:\\");
  // A real drive lists real folders — Windows exists on every Windows install.
  await expect(page.getByTestId("file-entry-Windows")).toBeVisible({ timeout: 15_000 });
  // Up returns to the drive roots.
  await page.getByTestId("file-up").click();
  await expect(page.getByTestId("file-loc")).toHaveText("This PC");
  // Close the Files panel so it does not overlap the later view-only checks.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();

  // (c.5b) View-only REFUSES control actions (loop 32). A read-only session drops input AND refuses the
  // write-actions (reboot/tool-launch/command-run). With view-only ON, re-running the same command must
  // come back as an agent Error (surfaced in the app error banner), NOT a CommandResult — proving the
  // agent-side action gate, not just the input gate. Toggle it back off so later steps still work.
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn, "view-only did not arm").toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("viewer-command-run").click();
  await expect(
    page.getByTestId("app-error"),
    "the agent did not refuse the command under view-only",
  ).toContainText("view-only mode: running a command is not allowed");
  // (c.5c) View-only ALSO refuses the LOCK (loop 38) — same agent-side gate as reboot/tool/command. The
  // Lock button stays (no `WorkstationLocked` ack sets a status), and the refusal surfaces in the banner.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-lock").click();
  await expect(
    page.getByTestId("app-error"),
    "the agent did not refuse the lock under view-only",
  ).toContainText("view-only mode: locking the workstation is not allowed");
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn).toHaveAttribute("aria-pressed", "false");

  // (c.6) Lock the guest (loop 38). With view-only OFF the agent locks and acks `WorkstationLocked`, whose
  // "Guest locked" confirmation follows the ACK (not the click) — proving the whole
  // LockWorkstation→WorkstationLocked round trip: encode on the Control channel, agent gate + dispatch, ack
  // routed back to the UI. MOCKED here: the `--synthetic`/`--log-input` agent acks WITHOUT calling
  // `LockWorkStation`, so the CI box's own session is never locked (see SessionOptions::mock_lock).
  await openPanel(page, "tools");
  await page.getByTestId("viewer-lock").click();
  await expect(
    page.getByTestId("viewer-lock-status"),
    "the agent did not ack WorkstationLocked",
  ).toContainText("Guest locked");

  // (c.5d) View-only ALSO refuses LOG OFF (loop 39) — the same agent-side gate as lock/reboot/tool/
  // command. Re-arm view-only, click Log Off, and the refusal surfaces in the app-error banner; the
  // button stays (no `LogOffScheduled` ack sets a status). Then disarm so the success check can run.
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn, "view-only did not re-arm for the logoff check").toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await openPanel(page, "tools");
  await page.getByTestId("viewer-logoff").click();
  await expect(page.getByTestId("viewer-logoff-question")).toContainText("unsaved work is lost");
  await page.getByTestId("viewer-logoff-confirm").click();
  await expect(
    page.getByTestId("app-error"),
    "the agent did not refuse the logoff under view-only",
  ).toContainText("view-only mode: logging off the guest is not allowed");
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn).toHaveAttribute("aria-pressed", "false");

  // (c.7) Log off the guest (loop 39). With view-only OFF the agent acks `LogOffScheduled`, whose
  // "Logging the guest off…" status follows the ACK (not the click) — proving the whole
  // LogOffGuest→LogOffScheduled round trip: encode on the Control channel, agent view-only gate +
  // dispatch, ack routed back to the UI. MOCKED here: the `--synthetic` agent acks WITHOUT calling
  // `WTSLogoffSession`, so the CI operator is never logged out (see SessionOptions::mock_logoff).
  await openPanel(page, "tools");
  await page.getByTestId("viewer-logoff").click();
  await expect(page.getByTestId("viewer-logoff-question")).toContainText("unsaved work is lost");
  await page.getByTestId("viewer-logoff-confirm").click();
  await expect(
    page.getByTestId("viewer-logoff-status"),
    "the agent did not ack LogOffScheduled",
  ).toContainText("Logging the guest off");

  // (c.5e) View-only ALSO refuses SHUT DOWN (loop 42) — the same agent-side gate. Shut Down is two-step
  // (arm → confirm), the most destructive action. Re-arm view-only, arm+confirm the shutdown, and the
  // refusal surfaces in the app-error banner; then disarm view-only for the success check.
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn, "view-only did not re-arm for the shutdown check").toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await openPanel(page, "tools");
  await page.getByTestId("viewer-shutdown").click();
  await openPanel(page, "tools");
  await page.getByTestId("viewer-shutdown-confirm").click();
  await expect(
    page.getByTestId("app-error"),
    "the agent did not refuse the shutdown under view-only",
  ).toContainText("view-only mode: shutting down the guest is not allowed");
  await openPanel(page, "input");
  await viewOnlyBtn.click();
  await expect(viewOnlyBtn).toHaveAttribute("aria-pressed", "false");

  // (c.6) Screenshot capture (remote support). The status line follows the whole round trip: the
  // control sends RequestScreenshot, the agent encodes the newest (synthetic) captured frame as a PNG
  // and PUSHES it over the FileTransfer channel, App receives it as an unsolicited file-transfer
  // offer (IncomingDownloadPrompt), the operator clicks Save to approve it, and `screenshotStatus`
  // is set to "Saved screenshot-…". (The e2e agent is --synthetic, so the frame is synthetic.)
  await openPanel(page, "tools");
  await page.getByTestId("viewer-screenshot").click();
  // The PNG arrives as an unsolicited push — operator must approve it in the download prompt.
  await expect(
    page.getByTestId("incoming-download-save"),
    "the agent did not push a screenshot PNG (no Save button appeared)",
  ).toBeVisible();
  await page.getByTestId("incoming-download-save").click();
  await expect(
    page.getByTestId("viewer-screenshot-status"),
    "screenshot status did not update after Save",
  ).toContainText("Saved screenshot-");

  // (d) The keyboard's special-key strip → agent INJECTED lines. -------------------------------
  // Input > Keyboard opens the device-keyboard field with ONE row of special keys above it (Ed,
  // 2026-10-25: no full on-screen keyboard, just a line of the keys a phone lacks). What matters is
  // that a latched modifier and the next strip key arrive at the guest as a properly nested chord.
  // The viewer is still ZOOMED IN here, which also pins that the strip is gated on "Capture input"
  // alone and not on the view (keys carry no coordinates).
  await openPanel(page, "input");
  await page.getByTestId("viewer-typing-toggle").click();
  await expect(page.getByTestId("viewer-typing")).toBeVisible();
  await expect(page.getByTestId("viewer-osk-toggle"), "the full on-screen keyboard is gone").toHaveCount(0);

  const CTRL_DOWN = 'INJECTED {"t":"Key","c":{"code":162,"down":true}}'; // VK_LCONTROL
  const ESC_DOWN = 'INJECTED {"t":"Key","c":{"code":27,"down":true}}';
  const ESC_UP = 'INJECTED {"t":"Key","c":{"code":27,"down":false}}';
  const CTRL_UP = 'INJECTED {"t":"Key","c":{"code":162,"down":false}}';

  const beforeStrip = agentLog.length;
  await page.getByTestId("nav-ControlLeft").click(); // latches locally — must inject NOTHING yet
  await expect(page.getByTestId("nav-ControlLeft")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("nav-Escape").click();
  const sawStrip = await waitFor(
    async () => agentLog.slice(beforeStrip).includes(CTRL_UP),
    8_000,
    200,
  );
  expect(sawStrip, "strip Ctrl+Esc did not reach the agent").toBe(true);
  const stripLines = agentLog
    .slice(beforeStrip)
    .split(/\r?\n/)
    .filter((l) => l.startsWith('INJECTED {"t":"Key"'));
  // Exactly four events, perfectly nested. The count is load-bearing: a latch that PRESSED Ctrl on
  // tap would produce a fifth event and, worse, leave Ctrl held on the guest if the technician then
  // disconnected — the failure the auto-release design exists to prevent (see lib/osk.ts).
  expect(stripLines, "strip Ctrl+Esc must arrive as Ctrl↓ Esc↓ Esc↑ Ctrl↑ and nothing else").toEqual([
    CTRL_DOWN,
    ESC_DOWN,
    ESC_UP,
    CTRL_UP,
  ]);
  await expect(page.getByTestId("nav-ControlLeft"), "the latch clears after one key").toHaveAttribute("aria-pressed", "false");

  // Ctrl latched, then a letter typed on the device keyboard: Ctrl+C on the guest, NOT the text "c".
  const C_DOWN = 'INJECTED {"t":"Key","c":{"code":67,"down":true}}';
  const C_UP = 'INJECTED {"t":"Key","c":{"code":67,"down":false}}';
  const beforeCtrlC = agentLog.length;
  await page.getByTestId("nav-ControlLeft").click();
  await page.getByTestId("viewer-typing-field").focus();
  await page.keyboard.insertText("c");
  expect(
    await waitFor(async () => agentLog.slice(beforeCtrlC).includes(CTRL_UP), 8_000, 200),
    "Ctrl then a typed c did not reach the agent",
  ).toBe(true);
  const ctrlCLines = agentLog
    .slice(beforeCtrlC)
    .split(/\r?\n/)
    .filter((l) => l.startsWith('INJECTED {"t":"Key"') || l.startsWith('INJECTED {"t":"Text"'));
  expect(ctrlCLines, "Ctrl + typed c must arrive as Ctrl↓ C↓ C↑ Ctrl↑, with no Text").toEqual([
    CTRL_DOWN,
    C_DOWN,
    C_UP,
    CTRL_UP,
  ]);
  await expect(page.getByTestId("nav-ControlLeft")).toHaveAttribute("aria-pressed", "false");

  // The master switch gates the strip too: a second key sender that forgot the gate is the loop-14
  // finding's exact shape, so it is asserted on this sender, not assumed from another.
  await openPanel(page, "input");
  await page.getByTestId("viewer-capture-input").uncheck();
  const beforeGated = agentLog.length;
  await expect(page.getByTestId("nav-Escape")).toBeDisabled();
  await page.getByTestId("nav-Escape").click({ force: true });
  await new Promise((r) => setTimeout(r, 750));
  expect(
    agentLog.slice(beforeGated).includes(ESC_DOWN),
    "a strip key sent input with 'Capture input' unchecked",
  ).toBe(false);
  await openPanel(page, "input");
  await page.getByTestId("viewer-capture-input").check();

  // (e) Quality controls end-to-end. -------------------------------------------------------------
  // Nothing in this suite drove a quality control before. Two things are asserted: that the advanced
  // panel's read-modify-write COMPOSES successive edits, and that the telemetry readout reports the
  // achieved frame rate beside the commanded one.
  await openPanel(page, "view");
  await page.getByTestId("viewer-quality-advanced").click();
  await expect(page.getByTestId("viewer-quality-panel")).toBeVisible();

  // Two edits, back to back, with no wait for the first `QualityApplied` in between. Under the old
  // acknowledged-only read the second message was built from the pre-fps settings and the frame rate
  // reverted to 30. NOTE the honest limitation: on loopback the ack returns in microseconds, so this
  // is a COMPOSITION net rather than a reproduction of the high-RTT race — the deterministic proof of
  // the ordering is the `qualityIntentReducer` unit test, which drives the messages by hand.
  await page.getByTestId("quality-fps").selectOption("15");
  await page.getByTestId("quality-color").selectOption("Gray");

  // Both must be in force once the agent has answered. The agent echoes what it APPLIED, so this is
  // an assertion about the agent's state and not just about local UI state.
  await expect(page.getByTestId("quality-fps")).toHaveValue("15", { timeout: 8_000 });
  await expect(page.getByTestId("quality-color")).toHaveValue("Gray", { timeout: 8_000 });
  // The preset picker follows the same settings into "Custom" (15 fps + Gray is no preset).
  await expect(page.getByTestId("viewer-quality")).toHaveValue("custom");

  // The readout must name the ACHIEVED rate against the commanded one. `—/15 fps` is legitimate for
  // a sample the agent could not yet measure; a readout with no rate term at all is the regression.
  await openViewerPanel(page, "view");
  const readout = page.getByTestId("viewer-quality-readout");
  await expect(readout).toHaveText(/(\d+\.\d|—)\/15 fps/, { timeout: 8_000 });
  console.log(`[e2e] quality readout: ${await readout.textContent()}`);

  // (c.7b) Background mode when the desktop is not shown at all: switching the session to another
  // tab (Files) unmounts the desktop, and nobody can see the picture, so the console must ask the
  // agent for background pacing; coming back to Screen must end it at once.
  // The dev server renders under React StrictMode, which mounts every effect twice, so remounting the
  // desktop sends a brief extra true/false pair there; what each switch must leave is the LAST value.
  const bgSent = () => page.evaluate(() => (window as unknown as { __bgSent: boolean[] }).__bgSent.slice());
  const bgLast = async () => (await bgSent()).at(-1);
  expect(await bgSent(), "the visible console sent SetBackground before any tab switch").toEqual([]);
  const sessionView = page.getByLabel("Session view");
  await sessionView.selectOption("files");
  await expect.poll(bgLast, { message: "no SetBackground(true) after switching to Files", timeout: 5_000 }).toBe(true);
  await sessionView.selectOption("screen");
  await expect.poll(bgLast, { message: "no SetBackground(false) after returning to Screen", timeout: 5_000 }).toBe(false);
  console.log(`[e2e] SetBackground sent across Files and back: ${JSON.stringify(await bgSent())}`);
  await expect(page.getByTestId("viewer-surface")).toBeVisible();

  // (c.8) runs LAST: since onShutDownScheduled refuses recovery ("The guest is shutting down…"), the
  // console deliberately stops sending input after a confirmed shutdown, so every input-driven step
  // (OSK, capture toggle) must come before it.
  // (c.8) Shut down the guest (loop 42). With view-only OFF the agent acks `ShutDownScheduled`, whose
  // "Shutting the guest down…" status follows the ACK — proving the whole ShutDownGuest→ShutDownScheduled
  // round trip. MOCKED here: the `--synthetic` agent's rebooter is a mock (mock_reboot gates shutdown
  // too), so it acks WITHOUT calling InitiateSystemShutdownEx — the CI box is never powered off.
  await openPanel(page, "tools");
  await page.getByTestId("viewer-shutdown").click();
  await openPanel(page, "tools");
  await page.getByTestId("viewer-shutdown-confirm").click();
  await expect(
    page.getByTestId("viewer-shutdown-status"),
    "the agent did not ack ShutDownScheduled",
  ).toContainText("Shutting the guest down");

  // (e) REMOVED 2026-09-05 with the viewer's "End session" control. This step drove
  // `viewer-endsession` → `viewer-endsession-end` and asserted the `SessionEnding` ack, and it was
  // the only place that exercised the viewer UI → EndSession wiring. That wiring no longer exists:
  // the operator leaves with `Disconnect` (which already fires `POST /sessions/{id}/end`) and a
  // session is ended centrally from the Sessions panel.
  //
  // THE PROTOCOL PATH IS STILL COVERED, and better, in `crates/agent-windows/tests/e2e_view_only.rs`
  // — it asserts the round trip AND that `SessionEnding` reports the uninstall flag *actually in
  // force* rather than the one requested, which this step never checked. The viewer keeps only the
  // INCOMING half (`viewer-endsession-status`), because the guest's own End button can still make
  // the agent announce a teardown.
  //
  // GAP, stated rather than papered over: that remaining status display is now UNTESTED at the UI
  // layer. There is no Viewer render test in this repo at all, so deleting this step took the last
  // assertion that `viewer-endsession-status` ever appears. The agent-side test proves the ack is
  // SENT; nothing proves the console still SHOWS it. That is the shape of a feature going inert at
  // its untested layer, and it wants a render test with a negative control (status absent → nothing
  // rendered) when someone next touches this component.
});
