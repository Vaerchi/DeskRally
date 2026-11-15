/**
 * Phone typing bar end-to-end: the device's OWN keyboard (modelled by `insertText`, which fires an
 * `input` event with no keydown — what Chrome on Android delivers) drives the real console against a
 * real `agent_host --log-input`, and the agent's `INJECTED <json>` lines must be EXACTLY the events
 * the guest needs. Setup (signaling + synthetic agent + browser) is the same as `console.spec.ts`.
 *
 * Covers the Codex v1 review's findings as observable behaviour: a nav key resets the bar's history;
 * the sentinel never costs a guest Backspace on select-all replace; losing input resets history.
 * NOT covered: a real Android IME (composition, autocorrect, focus raising the keyboard) — that needs
 * the device. The diff rules for those are unit-tested in `src/lib/phone_typing.test.ts`.
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


test("phone typing bar: the device keyboard's edits reach the agent as exactly the right events", async () => {
  test.setTimeout(90_000);
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  // hasTouch: step 4b taps the remote screen with a real touch, the way a phone does.
  const context = await browser!.newContext({ ...PINNED, hasTouch: true });
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

  /** The INJECTED key/text lines the agent logged since `from` (pointer moves filtered out). */
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
  const ENTER = tapLines(13);
  const BKSP = tapLines(8);
  const LEFT = tapLines(37);
  /** Wait until the agent has logged `last`, then return everything injected since `from`. */
  const settle = async (from: number, last: string, what: string) => {
    expect(await waitFor(async () => agentLog.slice(from).includes(last), 8_000, 200), `${what} did not reach the agent`).toBe(
      true,
    );
    return injectedSince(from);
  };

  // Open the bar from the Input panel. The tap itself must focus the field — Android raises its
  // keyboard only for a focus() made inside the user gesture.
  await page.getByTestId("viewer-input-menu").click();
  await page.getByTestId("viewer-typing-toggle").click();
  const field = page.getByTestId("viewer-typing-field");
  await expect(field).toBeFocused();

  // 0. The docked bar, and the keyboard under it, must not hide the remote screen: the surface gives
  //    up the strip they cover, so the fitted picture sits above the bar (Ed, 2026-10-27: he saw only
  //    letterbox). Android overlays its keyboard on the page, which is modelled here by shrinking the
  //    visual viewport and firing its resize, exactly what the Viewer listens to.
  const geometry = () =>
    page.evaluate(() => {
      const r = (sel: string) => document.querySelector(sel)?.getBoundingClientRect() ?? null;
      const bar = r(".viewer__typing");
      return { surface: r(".viewer__surface"), video: r(".viewer__video"), bar, innerHeight: window.innerHeight };
    });
  expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches), "premise: the touch context docks the bar").toBe(true);
  const KEYBOARD = 300;
  const fullHeight = (await geometry()).surface!.height;
  await page.evaluate((kb) => {
    const vv = window.visualViewport!;
    const h = window.innerHeight - kb;
    Object.defineProperty(vv, "height", { configurable: true, get: () => h });
    vv.dispatchEvent(new Event("resize"));
  }, KEYBOARD);
  const lifted = await geometry();
  expect(Math.round(lifted.bar!.bottom), "the bar sits on top of the keyboard").toBe(lifted.innerHeight - KEYBOARD);
  expect(lifted.surface!.bottom, "the surface ends where the bar begins").toBeLessThanOrEqual(lifted.bar!.top + 1);
  expect(lifted.surface!.bottom, "and gives up no more than that").toBeGreaterThanOrEqual(lifted.bar!.top - 1);
  expect(lifted.video!.bottom, "the picture is above the bar").toBeLessThanOrEqual(lifted.bar!.top + 1);
  // The keyboard goes away: the surface takes back all but the bar.
  await page.evaluate(() => {
    const vv = window.visualViewport!;
    delete (vv as unknown as { height?: number }).height;
    vv.dispatchEvent(new Event("resize"));
  });
  const down = await geometry();
  expect(Math.round(down.bar!.bottom), "keyboard closed: the bar is back at the bottom").toBe(down.innerHeight);
  expect(down.surface!.bottom, "the surface follows the bar back down").toBeGreaterThanOrEqual(down.bar!.top - 1);
  expect(down.surface!.bottom).toBeLessThanOrEqual(down.bar!.top + 1);
  await expect(field).toBeFocused();
  // 1. Text, Enter, a Backspace on the (reset) "empty" field, and a nav key.
  let from = agentLog.length;
  await page.keyboard.insertText("hi there");
  await page.keyboard.press("Enter");
  await page.keyboard.press("Backspace");
  await page.getByTestId("nav-ArrowLeft").click();
  expect(await settle(from, LEFT[1], "typing"), "Text, Enter, Backspace, ← in order and nothing else").toEqual([
    textLine("hi there"),
    ...ENTER,
    ...BKSP,
    ...LEFT,
  ]);
  await expect(field, "a nav key tap must leave focus in the field").toBeFocused();

  // 2. Codex v1 HIGH: a nav key moves the guest caret, so the bar must FORGET what it typed. Type
  //    "abc", ←, Backspace: ONE Backspace on the guest, and the next text is fresh.
  from = agentLog.length;
  await page.keyboard.insertText("abc");
  await page.getByTestId("nav-ArrowLeft").click();
  await page.keyboard.press("Backspace");
  await page.keyboard.insertText("Z");
  expect(await settle(from, textLine("Z"), "typing after a nav key"), "nav must reset the bar's history").toEqual([
    textLine("abc"),
    ...LEFT,
    ...BKSP,
    textLine("Z"),
  ]);

  // 3. Codex v1 HIGH: the sentinel is not guest text. Select-all + replace of "Zxy" must send one
  //    Backspace per character the bar SENT (3), never a fourth for the sentinel.
  from = agentLog.length;
  await page.keyboard.insertText("xy");
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.insertText("q");
  expect(await settle(from, textLine("q"), "select-all replace"), "select-all replace must not over-delete").toEqual([
    textLine("xy"),
    ...BKSP,
    ...BKSP,
    ...BKSP,
    textLine("q"),
  ]);

  // 3b. Codex v2 HIGH: another key sender that KEEPS the field focused (special-key buttons prevent
  //     the focus move) can switch the guest's app. Type "abc", tap ⊞ Win, then select-all replace:
  //     the guest must get NO Backspaces — "abc" is in another app now.
  await page.getByTestId("viewer-input-menu").click();
  await page.getByTestId("viewer-special-keys-toggle").click();
  await page.getByTestId("viewer-input-menu").click(); // close the panel again
  await expect(page.getByTestId("special-win")).toBeVisible();
  await field.focus();
  from = agentLog.length;
  await page.keyboard.insertText("abc");
  await page.getByTestId("special-win").click();
  await expect(field, "the special key must not take focus from the field").toBeFocused();
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.insertText("q");
  expect(await settle(from, textLine("q"), "typing after a special key"), "a special key must reset the bar's history").toEqual([
    textLine("abc"),
    ...tapLines(91), // VK_LWIN
    textLine("q"),
  ]);

  // 3c. Codex v2 HIGH: a pasted TAB moves guest focus. After "a<Tab>b", a select-all replace must not
  //     send Backspaces into the control that only received "b".
  from = agentLog.length;
  await page.keyboard.insertText("a\tb");
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.insertText("r");
  expect(await settle(from, textLine("r"), "typing after a pasted tab"), "a tab must reset the bar's history").toEqual([
    textLine("a"),
    ...tapLines(9), // VK_TAB
    textLine("b"),
    textLine("r"),
  ]);

  // 4. Codex v1 MEDIUM: losing input resets the history. Give the field real history first — the
  //    select-all above took the sentinel with it, so the field has already reset itself to empty.
  //    Then turn capture off and back on: "w" must be forgotten.
  from = agentLog.length;
  await page.keyboard.insertText("w");
  await settle(from, textLine("w"), "typing before the capture toggle");
  await expect(field).toHaveValue(" w");
  if (!(await page.getByTestId("viewer-capture-input").isVisible())) {
    await page.getByTestId("viewer-input-menu").click();
  }
  await page.getByTestId("viewer-capture-input").uncheck();
  await expect(field).toBeDisabled();
  await expect(page.getByTestId("nav-ArrowLeft")).toBeDisabled();
  await expect(page.getByTestId("viewer-typing-toggle")).toBeDisabled();
  await page.getByTestId("viewer-capture-input").check();
  await expect(field).toBeEnabled();
  // Close the Input panel. Left open, it covers the middle of the remote screen, and step 4b's tap
  // landed on the panel instead of the picture (the old "touch tap did not reach the agent" flake,
  // 2 runs in 4: whether the panel was still open here depended on an instant isVisible() above).
  await page.getByTestId("viewer-input-menu").click();
  await expect(page.getByTestId("viewer-capture-input")).toBeHidden();
  // Appending would look identical either way, so assert the reset itself: content gone, sentinel
  // back (a mutation that dropped this reset passed an append-only check).
  await expect(field, "toggling input must reset the field's history").toHaveValue(" ");
  await field.focus();
  from = agentLog.length;
  await page.keyboard.insertText("k");
  expect(await settle(from, textLine("k"), "typing after re-enable"), "re-enabled input must start a fresh history").toEqual([
    textLine("k"),
  ]);
  await expect(field).toHaveValue(" k");

  // 4b. A TAP on the remote screen (a real touch, as on a phone) moves the guest caret. MEASURED: the
  //     surface is focusable and takes focus on the tap, so the field blurs and its onFocus reset
  //     fires on return. (`sendEvent` also resets on every MouseButton, as a backstop for a tap that
  //     leaves the field focused; no path in this harness produces one, so that backstop is NOT
  //     pinned here — a mutation removing it survives this spec.)
  from = agentLog.length;
  await page.keyboard.insertText("abc");
  await settle(from, textLine("abc"), "typing before a touch tap");
  // A tap maps through the picture's geometry, and the viewer DROPS a tap while it does not know the
  // video's size yet. Premise, so a failure names its cause: the picture exists and nothing covers the
  // spot the tap lands on.
  await page.waitForFunction(() => (document.querySelector(".viewer__video") as HTMLVideoElement | null)?.videoWidth, undefined, {
    timeout: 20_000,
  });
  const box = (await page.getByTestId("viewer-surface").boundingBox())!;
  expect(
    await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.className, [box.x + box.width / 2, box.y + box.height / 2]),
    "premise: the tap lands on the remote picture, not on a panel over it",
  ).toBe("viewer__video");
  await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
  await settle(from, '"t":"MouseButton"', "the touch tap");
  await expect(field, "measured: a tap on the surface takes focus from the field").not.toBeFocused();
  await field.focus();
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.insertText("q");
  expect(await settle(from, textLine("q"), "typing after a touch tap"), "a tap on the guest must reset the bar's history").toEqual([
    textLine("abc"),
    textLine("q"),
  ]);

  // A click on the remote screen moves the guest caret; coming back to the field starts fresh.
  await page.getByTestId("viewer-surface").click();
  await expect(field).not.toBeFocused();
  await field.focus();
  await expect(field, "refocusing the field must reset its history").toHaveValue(" ");

  // 5. An oversized paste is refused whole: nothing injected, field reset.
  from = agentLog.length;
  await page.keyboard.insertText("x".repeat(1001));
  await page.keyboard.insertText("ok");
  expect(await settle(from, textLine("ok"), "typing after an oversized paste"), "an oversized edit must send nothing").toEqual([
    textLine("ok"),
  ]);

  // Closing the bar removes it.
  if (!(await page.getByTestId("viewer-typing-toggle").isVisible())) {
    await page.getByTestId("viewer-input-menu").click();
  }
  await page.getByTestId("viewer-typing-toggle").click();
  await expect(page.getByTestId("viewer-typing")).toHaveCount(0);

  // 6. Codex v1 MEDIUM, window-level path: a key PRESSED on the guest is released even when its keyup
  //    arrives flagged as composing (which the IME filter would otherwise drop, leaving Shift held).
  //    `keyCode` cannot be set on a synthetic KeyboardEvent, but `isComposing` can.
  // Close the Input menu with its own button first: the open panel overlays the middle of the remote
  // screen, so clicking the screen to dismiss it hit the panel instead whenever the layout put it there
  // (an intermittent 90 s timeout). Then click the screen, which detaches main-window capture.
  if (await page.getByTestId("viewer-typing-toggle").isVisible()) await page.getByTestId("viewer-input-menu").click();
  await page.getByTestId("viewer-surface").click();
  from = agentLog.length;
  await page.evaluate(() => {
    window.dispatchEvent(new KeyboardEvent("keydown", { code: "ShiftLeft", key: "Shift", bubbles: true }));
    window.dispatchEvent(new KeyboardEvent("keyup", { code: "ShiftLeft", key: "Shift", isComposing: true, bubbles: true }));
  });
  const SHIFT = tapLines(160); // VK_LSHIFT
  expect(await settle(from, SHIFT[1], "the composing-flagged Shift release"), "a held key must always be released").toEqual(SHIFT);
});
