/**
 * Milestone M3 — automated headless-browser ↔ Rust-agent end-to-end test.
 *
 * Proves the real product path with no human at a browser: the Go signaling server runs, a Rust
 * streaming agent connects as `Role::Agent` and emits VP8 video (synthetic capture, so it does
 * not depend on a display or the screen changing), and a headless Chromium loads the viewer's REAL
 * `WebRTCTransport` (via `e2e/harness.html`), reaches the agent through signaling, and asserts the
 * browser actually receives the agent's video media via `getStats()`.
 *
 * PRIMARY assertions: inbound-rtp video `bytesReceived > 0` && `packetsReceived > 0` (SDP
 * negotiation + RTP arrival at the browser), the negotiated codec is `video/VP8`, and
 * `framesDecoded > 0` — the browser must DECODE the stream, not merely receive it. The last two
 * are hard requirements rather than the logged bonus they were under H.264, which is the whole
 * point of the codec move: this is the only test in the repo that proves a real browser can
 * render the agent's video.
 *
 * Browser channel: system Chrome (`channel: "chrome"`) is still preferred, but since the codec
 * moved from H.264 to **VP8** the decoder is no longer the reason — VP8 is royalty-free and
 * Playwright's bundled Chromium decodes it too, so the fallback path should now also decode.
 * The byte/packet primary check is kept because it is the assertion that proves negotiation + RTP.
 *
 * Self-skips (green, with a clear reason) only when a prerequisite is genuinely absent: no agent
 * binary, no signaling server + unbuildable, or no usable browser. A real media-flow failure FAILS.
 *
 * Run: `npm run test:e2e` (from web/viewer). Vite is started by playwright.config.ts's webServer.
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
const REPO = resolve(HERE, "..", "..", ".."); // repo root (viewer/source)
// CARGO_TARGET_DIR is set by the harness to redirect build output outside the source tree.
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
import { SIGNALING_WS, SIG_PORT } from "./ports";
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;
/** Accumulated agent stdout, so the input assertion can scan for its `INJECTED <json>` lines. */
let agentLog = "";

/** Resolve true if a WebSocket upgrade to `url` succeeds within `timeoutMs`. */
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
  // --- Prerequisite: the Rust agent binary must be built. ---
  if (!existsSync(AGENT_BIN)) {
    skipReason = `agent binary not found at ${AGENT_BIN} (run: cargo build -p rmt-agent-windows --bin agent_host)`;
    return;
  }

  // --- Signaling server: reuse if already up, else spawn signaling.exe (build it if missing). ---
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
      // The executable exists (checked above) but did not start — a real regression, not a
      // missing prerequisite. Throw so the suite FAILs rather than silently skipping.
      throw new Error(
        `signaling server at ${SIGNALING_EXE} exists but did not come up on :${SIG_PORT} — ` +
        "check process stderr for the root cause",
      );
    }
  }

  // --- Rust streaming agent: synthetic capture so it emits frames headlessly & deterministically.
  // `--log-input` installs a LoggingSink that prints `INJECTED <json>` per decoded input event and
  // does NOT call real SendInput — the observable proof for the browser→agent input assertion. ---
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

  // Wait until the agent has registered with signaling before the browser asks to be brokered.
  await waitFor(async () => agentStarted, 8_000);
  await new Promise((r) => setTimeout(r, 1_000)); // small settle so RegisterAgent lands

  // --- Browser: prefer system Chrome; fall back to bundled Chromium (both decode VP8). ---
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

test("browser receives the agent's WebRTC video media", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  const target = `${HARNESS_BASE}?url=${encodeURIComponent(SIGNALING_WS)}&device=${deviceId}`;
  await page.goto(target);

  // Wait for the real WebRTCTransport to reach "connected" (or surface a fatal harness error).
  await page.waitForFunction(
    () => {
      const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
      return !!r && (r.state === "connected" || r.state === "failed" || r.error !== null);
    },
    undefined,
    { timeout: 30_000 },
  );

  const status = await page.evaluate(() => {
    const r = (window as unknown as { rmt: { state: string; error: string | null } }).rmt;
    return { state: r.state, error: r.error };
  });
  console.log(`[e2e] browser channel=${browserChannel} state=${status.state} error=${status.error ?? "none"}`);
  expect(status.error, "harness reported a fatal error").toBeNull();
  expect(status.state, "peer connection should be connected").toBe("connected");

  // Poll getStats up to ~12s for inbound-rtp video with real bytes/packets.
  type Inbound = {
    bytesReceived?: number;
    packetsReceived?: number;
    framesDecoded?: number;
    framesReceived?: number;
    codec?: string;
  } | null;

  let inbound: Inbound = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (window as unknown as {
          rmt: { stats(): Promise<Array<Record<string, unknown>>> };
        }).rmt;
        const all = await r.stats();
        const rtp = all.find((s) => s.type === "inbound-rtp" && (s as { kind?: string }).kind === "video");
        if (!rtp) return null;
        const codecEntry = all.find((s) => s.type === "codec" && s.id === (rtp as { codecId?: string }).codecId);
        return {
          bytesReceived: rtp.bytesReceived as number | undefined,
          packetsReceived: rtp.packetsReceived as number | undefined,
          framesDecoded: rtp.framesDecoded as number | undefined,
          framesReceived: rtp.framesReceived as number | undefined,
          codec: codecEntry ? (codecEntry.mimeType as string) : undefined,
        };
      });
      return (
        !!inbound &&
        (inbound.bytesReceived ?? 0) > 0 &&
        (inbound.packetsReceived ?? 0) > 0 &&
        // Wait for DECODED frames, not merely received bytes — see the assertions below.
        (inbound.framesDecoded ?? 0) > 0
      );
    },
    15_000,
    500,
  ).catch(() => {
    // Fall through: the explicit expectations below produce a far more readable failure than a
    // bare polling timeout, and `inbound` still holds the last stats we saw.
  });

  console.log(`[e2e] inbound-rtp video: ${JSON.stringify(inbound)}`);
  const gotTrack = await page.evaluate(
    () => (window as unknown as { rmt: { gotVideoTrack: boolean } }).rmt.gotVideoTrack,
  );
  console.log(`[e2e] onVideoTrack fired=${gotTrack}`);

  // PRIMARY: RTP media actually arrived at the browser (negotiation + transport proven).
  expect(inbound, "no inbound-rtp video stats — no media reached the browser").not.toBeNull();
  const got = inbound!;
  expect(got.bytesReceived ?? 0, "inbound video bytesReceived").toBeGreaterThan(0);
  expect(got.packetsReceived ?? 0, "inbound video packetsReceived").toBeGreaterThan(0);

  // THE CODEC PROOF. Assert the mime the BROWSER negotiated, not what the agent believes it sent:
  // this is the only check in the suite that would fail if the encode path silently reverted to
  // H.264, so "bytes arrived" is deliberately not enough.
  expect(got.codec, "video codec negotiated at the browser").toBe("video/VP8");

  // And the browser must actually DECODE it. Under H.264 this had to stay a soft log, because
  // Playwright's bundled Chromium frequently ships without an H.264 decoder — RTP would arrive and
  // framesDecoded would sit at 0, which is a black <video> for a real user. Removing exactly that
  // caveat is the point of moving to VP8 (every Chromium build decodes it), so it is now an
  // assertion: royalty-free is only worth anything if the picture actually appears.
  const decoded = got.framesDecoded ?? 0;
  expect(
    decoded,
    `browser (${browserChannel}) received VP8 RTP but decoded no frames — a black video for a real user`,
  ).toBeGreaterThan(0);
  console.log(`[e2e] browser DECODED VP8 — framesDecoded=${decoded} (codec ${got.codec})`);

  // ---------------------------------------------------------------------------
  // M4: browser → agent INPUT over the unified "frames" data channel.
  //
  // Drive two input events from the browser's REAL WebRTCTransport (send(ChannelId.Input, …) →
  // one framed Frame on the single "frames" channel) and assert the agent decoded + "injected"
  // them, in order, via its LoggingSink `INJECTED <json>` stdout. This closes M2's control path
  // from a real browser: browser → WebRTC data channel → agent Frame::decode → input_codec → sink.
  // ---------------------------------------------------------------------------
  //
  // The MouseMove is NOT logged with the coordinates the browser sent. Since c7600af the agent
  // remaps a MouseMove out of frame-normalized 0..=65535 (across the selected monitor) into
  // virtual-desktop-normalized 0..=65535 before injection, and the LoggingSink prints the event
  // AFTER that remap — so the logged pair is a function of the AGENT HOST's display metrics, which
  // this browser cannot compute and CI must not hardcode. The remap's exact VALUE is pinned in
  // crates/agent-windows/tests/e2e_input.rs, which runs in-process and can read the same virtual
  // rect the agent does. What is invariant here, and what this test therefore asserts, is the
  // transport contract: exactly the two events arrive, in order, decoded into the right variants,
  // the Key one byte-exact, and the MouseMove carrying a well-formed absolute coordinate pair.
  const EXPECT_KEY = 'INJECTED {"t":"Key","c":{"code":65,"down":true}}';
  /** The absolute coordinate range Windows' MOUSEEVENTF_ABSOLUTE uses; the remap's output space. */
  const ABS_MAX = 65535;

  const beforeLen = agentLog.length;
  await page.evaluate(() => {
    const r = (window as unknown as { rmt: { sendInput(ev: unknown): void } }).rmt;
    // Adjacently-tagged InputEvent shapes (mirror src/lib/input.ts). Order matters for the assert.
    r.sendInput({ t: "MouseMove", c: { x: 12345, y: 6789 } });
    r.sendInput({ t: "Key", c: { code: 65, down: true } });
  });

  /** The `INJECTED …` lines the agent printed since just before the browser sent its two events. */
  const injectedSince = () =>
    agentLog
      .slice(beforeLen)
      .split(/\r?\n/)
      .filter((l) => l.startsWith("INJECTED "));

  // The data channel is reliable+ordered, so the two INJECTED lines must appear, in order. Wait on
  // the COUNT (the MouseMove line is no longer a literal to match on) plus the byte-exact Key line.
  const sawInput = await waitFor(
    async () => {
      const lines = injectedSince();
      return lines.length >= 2 && lines[1] === EXPECT_KEY;
    },
    12_000,
    250,
  );

  const injectedLines = injectedSince();
  console.log(`[e2e] agent INJECTED lines after browser input:\n${injectedLines.join("\n")}`);

  expect(sawInput, "agent did not report both browser-sent input events via INJECTED").toBe(true);
  // Exactly the two events the browser sent — no drops, no duplicates, nothing invented.
  expect(injectedLines, "agent INJECTED lines for the two browser-sent events").toHaveLength(2);
  // Order: MouseMove was sent first, so its INJECTED line must precede the Key one. The Key event
  // is untouched by the remap, so it stays a byte-exact match — losing that would mean the codec
  // or the channel changed, not the pointer geometry.
  expect(injectedLines[1]).toBe(EXPECT_KEY);

  // Line 1 is the remapped MouseMove: assert its SHAPE, since its value is host-dependent (above).
  const mousePayload = injectedLines[0].slice("INJECTED ".length);
  const mouse = JSON.parse(mousePayload) as { t?: string; c?: { x?: unknown; y?: unknown } };
  expect(mouse.t, `first INJECTED line should decode as a MouseMove: ${injectedLines[0]}`).toBe(
    "MouseMove",
  );
  for (const axis of ["x", "y"] as const) {
    const v = mouse.c?.[axis];
    expect(typeof v, `MouseMove.${axis} type in ${mousePayload}`).toBe("number");
    expect(Number.isInteger(v), `MouseMove.${axis} must be an integer: ${mousePayload}`).toBe(true);
    expect(v as number, `MouseMove.${axis} must be a valid absolute coordinate`).toBeGreaterThanOrEqual(0);
    expect(v as number, `MouseMove.${axis} must be a valid absolute coordinate`).toBeLessThanOrEqual(ABS_MAX);
  }
  console.log(`[e2e] agent injected remapped MouseMove ${mousePayload} (value pinned by the Rust e2e_input test)`);
});

// ---------------------------------------------------------------------------
// Transport-level two-session isolation.
//
// Verifies WebRTC transport isolation between two concurrent harness sessions, each connected to
// its own agent. This is TRANSPORT coverage (real WebRTCTransport, real data channel, real
// LoggingSink), NOT full-App coverage — the harness bypasses App auth, CP brokering, URL
// routing, and the Viewer's keyboard-capture stack. Full-App input isolation is separately
// covered by the "App-level two-machine session isolation" test below.
//
//   - harness pageA connects to agentA via real WebRTCTransport + real signaling + real agent.
//   - harness pageB connects to agentB (separate device ID, separate agent process).
//   - Input dispatched from pageA via window.rmt.sendInput reaches agentA only (INJECTED log).
//   - Closing pageB does not affect pageA: agentA's framesDecoded ADVANCES (not merely stays >0).
// ---------------------------------------------------------------------------

test("transport-level two-session isolation: harness A's input reaches only agentA; closing B does not degrade A", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const deviceIdA = randomUUID();
  const deviceIdB = randomUUID();

  let agentLogA = "";
  let agentLogB = "";
  let agentProcA: ChildProcess | null = null;
  let agentProcB: ChildProcess | null = null;

  try {
    // Start agent A (fresh device, so no state from the first test's agent).
    agentProcA = spawn(
      AGENT_BIN,
      ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceIdA, "--fps", "30"],
      { cwd: resolve(REPO), stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentAStarted = false;
    agentProcA.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLogA += s;
      process.stdout.write(`[agentA] ${s}`);
      if (s.includes("agent device=")) agentAStarted = true;
    });
    agentProcA.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agentA:err] ${d.toString()}`));

    // Start agent B (separate device).
    agentProcB = spawn(
      AGENT_BIN,
      ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceIdB, "--fps", "30"],
      { cwd: resolve(REPO), stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentBStarted = false;
    agentProcB.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLogB += s;
      process.stdout.write(`[agentB] ${s}`);
      if (s.includes("agent device=")) agentBStarted = true;
    });
    agentProcB.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agentB:err] ${d.toString()}`));

    // Wait for both agents to register with the signaling server.
    // Prerequisites (binary, signaling) are confirmed above; if registration doesn't arrive this
    // is a real startup failure, not a missing prerequisite — report it as an error, not a skip.
    const bothStarted = await waitFor(async () => agentAStarted && agentBStarted, 10_000);
    if (!bothStarted) {
      throw new Error(
        "agentA or agentB did not log 'agent device=' within 10 s — real startup failure " +
        "(binary confirmed present; check stderr above for the root cause)",
      );
    }
    await new Promise((r) => setTimeout(r, 1_000));

    // Open two harness pages (real WebRTCTransport, each connected to its own agent).
    const pageA = await browser!.newPage();
    const pageB = await browser!.newPage();
    pageA.on("console", (m) => process.stdout.write(`[pageA:${m.type()}] ${m.text()}\n`));
    pageB.on("console", (m) => process.stdout.write(`[pageB:${m.type()}] ${m.text()}\n`));

    await pageA.goto(`${HARNESS_BASE}?url=${encodeURIComponent(SIGNALING_WS)}&device=${deviceIdA}`);
    await pageB.goto(`${HARNESS_BASE}?url=${encodeURIComponent(SIGNALING_WS)}&device=${deviceIdB}`);

    const waitConnected = (p: typeof pageA) =>
      p.waitForFunction(
        () => {
          const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
          return !!r && (r.state === "connected" || r.state === "failed" || r.error !== null);
        },
        undefined,
        { timeout: 30_000 },
      );

    await Promise.all([waitConnected(pageA), waitConnected(pageB)]);

    const stateA = await pageA.evaluate(() =>
      (window as unknown as { rmt: { state: string; error: string | null } }).rmt,
    );
    const stateB = await pageB.evaluate(() =>
      (window as unknown as { rmt: { state: string; error: string | null } }).rmt,
    );
    expect(stateA.error, "session A connected without error").toBeNull();
    expect(stateA.state, "session A peer state").toBe("connected");
    expect(stateB.error, "session B connected without error").toBeNull();
    expect(stateB.state, "session B peer state").toBe("connected");

    // Send a Key event from page A. Record log lengths before sending.
    const logABefore = agentLogA.length;
    const logBBefore = agentLogB.length;

    await pageA.evaluate(() => {
      const r = (window as unknown as { rmt: { sendInput(ev: unknown): void } }).rmt;
      // Use a distinctive key code so agentB cannot be confused with any other log line.
      r.sendInput({ t: "Key", c: { code: 200, down: true } });
    });

    // Wait for agent A to inject the event.
    const sawA = await waitFor(async () => {
      const lines = agentLogA.slice(logABefore).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
      return lines.some((l) => l.includes('"code":200'));
    }, 10_000, 250);

    const injectedA = agentLogA.slice(logABefore).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:isolation] agentA INJECTED lines: ${JSON.stringify(injectedA)}`);
    expect(sawA, "agent A received the input from session A").toBe(true);

    // Agent B must have no new INJECTED lines — input travels over A's data channel only.
    const injectedBFromA = agentLogB.slice(logBBefore).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:isolation] agentB INJECTED lines from pageA: ${JSON.stringify(injectedBFromA)}`);
    expect(injectedBFromA, "agent B received no input from session A").toHaveLength(0);

    // Snapshot framesDecoded on session A BEFORE closing B. The check after is for ADVANCEMENT
    // (framesDecoded must increase), not merely for >0 cumulative — the latter would pass even
    // with a frozen video stream.
    const getFramesA = async () =>
      pageA.evaluate(async () => {
        const r = (window as unknown as { rmt: { stats(): Promise<Array<Record<string, unknown>>> } }).rmt;
        const all = await r.stats();
        const rtp = all.find((s) => s.type === "inbound-rtp" && (s as { kind?: string }).kind === "video");
        return rtp ? (rtp.framesDecoded as number | undefined) ?? 0 : 0;
      });
    const framesBeforeB = await getFramesA();
    console.log(`[e2e:isolation] session A framesDecoded before closing B: ${framesBeforeB}`);

    // Close session B and verify session A continues receiving frames and input.
    await pageB.close();

    // Page A must still be connected.
    const stateAAfter = await pageA.evaluate(() =>
      (window as unknown as { rmt: { state: string } }).rmt.state,
    );
    expect(stateAAfter, "session A stays connected after session B closes").toBe("connected");

    // Session A can still send input and agent A receives it after B is gone.
    const logAAfterDisconnect = agentLogA.length;
    await pageA.evaluate(() => {
      const r = (window as unknown as { rmt: { sendInput(ev: unknown): void } }).rmt;
      r.sendInput({ t: "Key", c: { code: 201, down: true } });
    });

    const sawAAfter = await waitFor(async () => {
      const lines = agentLogA.slice(logAAfterDisconnect).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
      return lines.some((l) => l.includes('"code":201'));
    }, 10_000, 250);

    const injectedAAfter = agentLogA.slice(logAAfterDisconnect).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:isolation] agentA INJECTED after B disconnect: ${JSON.stringify(injectedAAfter)}`);
    expect(sawAAfter, "agent A still receives input after session B disconnected").toBe(true);

    // Verify session A framesDecoded has ADVANCED since before B closed (not merely cumulative >0).
    const framesAdvanced = await waitFor(async () => (await getFramesA()) > framesBeforeB, 8_000, 300);
    const framesAfter = await getFramesA();
    console.log(`[e2e:isolation] session A framesDecoded after B disconnect: ${framesAfter} (was ${framesBeforeB})`);
    expect(framesAdvanced, "session A framesDecoded increased after session B closed (video still flowing)").toBe(true);

    await pageA.close();
  } finally {
    await stopProc(agentProcA);
    await stopProc(agentProcB);
  }
});

// ---------------------------------------------------------------------------
// App-level two-machine session isolation (real App + real transports).
//
// This is the FULL-APP coverage that the transport-level harness test cannot provide: it drives
// the REAL App.tsx — URL-param auto-connect, CP brokering (mocked to 201 with authenticated
// broker coordinates), SignalingClient, WebRTCTransport wired through the App's own event
// handlers, and the Viewer's DOM keyboard-capture stack — not window.rmt.sendInput from outside.
//
// Both sessions share a single browser context (shared auth — same tenant) and each receives a
// distinct brokered session ID from the mock CP. The App uses the broker-provided signaling URL
// (SIGNALING_WS at the test port), bypassing URL-param host validation entirely.
//
// Proof chain:
//   - Mock CP returns authenticated broker coordinates: { session: { id: sessionIdA }, signaling:
//     { url: SIGNALING_WS, device_id: deviceIdA, session_id: sessionIdA } } (201) for App A;
//     equivalent for App B with distinct sessionIdB.
//   - acquireBrokeredSession resolves the BrokeredSession → App dials SIGNALING_WS directly.
//   - Both reach window.__rmt.state === "connected" (App's own DEV stats seam, App.tsx).
//   - Playwright clicks App A's viewer-surface (Viewer's keyboard-capture DOM target) and
//     dispatches a key. The Viewer's handler calls transport.send(ChannelId.Input, …) over the
//     real data channel. agentA logs INJECTED; agentB logs NOTHING.
//   - Snapshot agent log lengths BEFORE click/key to avoid false baselines.
//   - Snapshot framesDecoded on App A before closing B. After closing B wait for advancement.
//   - Send a second key on App A: agentA still receives it (session is independent).
//   - Distinct session IDs (sessionIdA ≠ sessionIdB) are asserted as the "lease isolation" proof.
//
// Self-skips (green) only when prerequisites are genuinely absent (agent binary or signaling
// server unreachable). A startup that succeeds then stalls on __rmt.state FAILs, not skips.
// ---------------------------------------------------------------------------

const APP_BASE = "http://127.0.0.1:5173";

/**
 * Mount a brokered CP mock on a browser context (shared across all pages in the context).
 * Returns authenticated broker coordinates at SIGNALING_WS for each known device → sessionId pair.
 * The signaling server runs with -insecure-no-ticket-verification so no real ticket is needed.
 */
function mountBrokeredCpMock(
  ctx: import("@playwright/test").BrowserContext,
  sessions: Map<string, string>, // deviceId → sessionId
): void {
  void ctx.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 }); return;
    }
    if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: [], presence_known: true } }); return;
    }
    if (path === "/cp/auth/login") {
      await route.fulfill({ status: 200, json: {} }); return;
    }
    if (path === "/cp/sessions" && req.method() === "POST") {
      const bodyText = await req.postData();
      const body = bodyText ? (JSON.parse(bodyText) as { machine_id?: string }) : {};
      const devId = body.machine_id ?? "";
      const sessId = sessions.get(devId) ?? randomUUID();
      await route.fulfill({
        status: 201,
        json: {
          session: {
            id: sessId, tenant_id: "t1", machine_id: "m1", technician_id: "u1",
            started_at: new Date().toISOString(), ended_at: null,
            consent_policy: "none", granted_caps: null,
            machine_group_id: "g1", machine_device_id: devId,
            machine_name: "test-machine", machine_alias: "", note: "",
          },
          signaling: { url: SIGNALING_WS, device_id: devId, session_id: sessId },
        },
      }); return;
    }
    await route.fulfill({ status: 200, json: {} });
  });
}

/** Build the App auto-connect URL for `deviceId`. Signaling URL comes from the broker, not URL params. */
function appConnectUrl(deviceId: string, name: string): string {
  return `${APP_BASE}/?device=${deviceId}&name=${encodeURIComponent(name)}`;
}

/** Read framesDecoded from the App's DEV stats seam (window.__rmt). */
async function appFramesDecoded(page: import("@playwright/test").Page): Promise<number> {
  return page.evaluate(async () => {
    type Rmt = { stats(): Promise<RTCStatsReport | undefined> };
    const rmt = (window as unknown as { __rmt?: Rmt }).__rmt;
    if (!rmt) return 0;
    const report = await rmt.stats();
    let decoded = 0;
    report?.forEach((s) => {
      const entry = s as Record<string, unknown>;
      if (entry.type === "inbound-rtp" && (entry as { kind?: string }).kind === "video") {
        decoded = (entry.framesDecoded as number | undefined) ?? 0;
      }
    });
    return decoded;
  });
}

test("App-level two-machine session isolation: keyboard input reaches only agentA; closing App B does not degrade App A", async () => {
  test.setTimeout(180_000); // two real WebRTC sessions + ICE negotiation each
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const deviceIdA = randomUUID();
  const deviceIdB = randomUUID();
  // Distinct brokered session IDs — the "lease isolation" proof: each App session carries its
  // own CP record and the two are not conflated at the signaling or transport layer.
  const sessionIdA = randomUUID();
  const sessionIdB = randomUUID();
  expect(sessionIdA, "session IDs must be distinct (lease isolation)").not.toBe(sessionIdB);
  console.log(`[e2e:app] session IDs: A=${sessionIdA}, B=${sessionIdB}`);

  let agentLogA = "";
  let agentLogB = "";
  let agentProcA: ChildProcess | null = null;
  let agentProcB: ChildProcess | null = null;

  // Single shared context — both App pages run as the same authenticated tech session (shared
  // cookies/auth state). The context-level CP mock routes sessions by device ID in the POST body.
  const ctx = await browser!.newContext({ ...PINNED });

  try {
    // Start agentA.
    agentProcA = spawn(
      AGENT_BIN,
      ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceIdA, "--fps", "30"],
      { cwd: resolve(REPO), stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentAStarted = false;
    agentProcA.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLogA += s;
      process.stdout.write(`[appA-agent] ${s}`);
      if (s.includes("agent device=")) agentAStarted = true;
    });
    agentProcA.stderr?.on("data", (d: Buffer) => process.stderr.write(`[appA-agent:err] ${d.toString()}`));

    // Start agentB.
    agentProcB = spawn(
      AGENT_BIN,
      ["stream", "--synthetic", "--log-input", "--signaling", SIGNALING_WS, "--device", deviceIdB, "--fps", "30"],
      { cwd: resolve(REPO), stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentBStarted = false;
    agentProcB.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLogB += s;
      process.stdout.write(`[appB-agent] ${s}`);
      if (s.includes("agent device=")) agentBStarted = true;
    });
    agentProcB.stderr?.on("data", (d: Buffer) => process.stderr.write(`[appB-agent:err] ${d.toString()}`));

    // Mount the brokered CP mock at context level (covers all pages in the shared auth context).
    mountBrokeredCpMock(ctx, new Map([[deviceIdA, sessionIdA], [deviceIdB, sessionIdB]]));

    // Prerequisites confirmed (binary exists, signaling running from beforeAll). If agents don't
    // register, this is a real failure — not a missing prerequisite.
    const bothUp = await waitFor(async () => agentAStarted && agentBStarted, 10_000);
    if (!bothUp) {
      throw new Error(
        "App-level test: agentA or agentB did not log 'agent device=' within 10 s " +
        "(binary and signaling confirmed present — real startup failure)",
      );
    }
    await new Promise((r) => setTimeout(r, 1_000)); // let RegisterAgent land on signaling

    // Open App pages in the shared context. The broker provides SIGNALING_WS directly, so the
    // App's URL-param signaling validation is bypassed — the correct port is used regardless.
    const pageA = await ctx.newPage();
    const pageB = await ctx.newPage();
    pageA.on("console", (m) => process.stdout.write(`[appA:${m.type()}] ${m.text()}\n`));
    pageB.on("console", (m) => process.stdout.write(`[appB:${m.type()}] ${m.text()}\n`));

    await pageA.goto(appConnectUrl(deviceIdA, "App-Machine-A"));
    await pageB.goto(appConnectUrl(deviceIdB, "App-Machine-B"));

    // Wait for the App's real WebRTCTransport to reach "connected" on each page.
    // window.__rmt is the DEV stats seam exposed by App.tsx when import.meta.env.DEV is true.
    const waitRmtConnected = (p: typeof pageA) =>
      p.waitForFunction(
        () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
        undefined,
        { timeout: 60_000 },
      );

    await Promise.all([waitRmtConnected(pageA), waitRmtConnected(pageB)]);
    console.log("[e2e:app] both App sessions reached WebRTC connected state");

    // Poll until App A is decoding video frames (data channel is open — prerequisite for input).
    const appADecoding = await waitFor(async () => (await appFramesDecoded(pageA)) > 0, 20_000, 500);
    if (!appADecoding) {
      const fd = await appFramesDecoded(pageA);
      throw new Error(`App A WebRTC connected but framesDecoded stayed at ${fd} after 20 s`);
    }

    // Snapshot BOTH agent log lengths BEFORE any input so the positive (A received) and negative
    // (B did not receive) assertions cover the full operation window. Capturing after the send
    // would discard events that arrived before the snapshot, masking both false failures (A) and
    // false passes (B misrouting arrived before snapshot but counted as "before").
    const EXPECT_KEY_APP = '"code":65';
    const logABeforeKey = agentLogA.length;
    const logBBeforeKey = agentLogB.length;

    // Drive real Viewer keyboard input via Playwright: click the viewer-surface DOM target so
    // the Viewer's capture listener acquires focus, then press a key. The Viewer dispatches
    // it through the App's transport to agentA's data channel → LoggingSink INJECTED.
    await pageA.getByTestId("viewer-surface").click();
    await pageA.keyboard.press("a"); // KeyA → code 65

    const sawAppA = await waitFor(async () => {
      const lines = agentLogA.slice(logABeforeKey).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
      return lines.some((l) => l.includes(EXPECT_KEY_APP));
    }, 15_000, 250);

    const injectedAppA = agentLogA.slice(logABeforeKey).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:app] agentA INJECTED from App A keyboard: ${JSON.stringify(injectedAppA)}`);
    expect(sawAppA, "agentA received the KeyA from App A's viewer keyboard capture").toBe(true);

    // agentB must have received NO new INJECTED lines — App A's input is isolated to A's channel.
    // Allow 300 ms for any spurious misrouting to arrive before asserting absence.
    await pageA.waitForTimeout(300);
    const injectedAppB = agentLogB.slice(logBBeforeKey).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:app] agentB INJECTED from App A keyboard: ${JSON.stringify(injectedAppB)}`);
    expect(injectedAppB, "agentB received no input from App A's keyboard").toHaveLength(0);

    // Snapshot framesDecoded on App A BEFORE closing App B.
    const framesBeforeCloseB = await appFramesDecoded(pageA);
    console.log(`[e2e:app] App A framesDecoded before closing App B: ${framesBeforeCloseB}`);

    // Close App B and verify App A's session continues independently.
    await pageB.close();

    // App A must still have WebRTC connected.
    const rmtStateAfter = await pageA.evaluate(
      () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state,
    );
    expect(rmtStateAfter, "App A WebRTC state after App B closed").toBe("connected");

    // framesDecoded on App A must ADVANCE (not merely remain at its cumulative value).
    const framesAdvancedApp = await waitFor(
      async () => (await appFramesDecoded(pageA)) > framesBeforeCloseB,
      10_000,
      300,
    );
    const framesAfterCloseB = await appFramesDecoded(pageA);
    console.log(`[e2e:app] App A framesDecoded after closing App B: ${framesAfterCloseB} (was ${framesBeforeCloseB})`);
    expect(framesAdvancedApp, "App A framesDecoded advanced after App B closed — video still live").toBe(true);

    // Send a second key on App A and verify agentA still receives it (session ID unchanged).
    const logAAfterB = agentLogA.length;
    await pageA.getByTestId("viewer-surface").click();
    await pageA.keyboard.press("b"); // KeyB → code 66
    const EXPECT_KEY2_APP = '"code":66';
    const sawAppA2 = await waitFor(async () => {
      const lines = agentLogA.slice(logAAfterB).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
      return lines.some((l) => l.includes(EXPECT_KEY2_APP));
    }, 15_000, 250);

    const injectedAppA2 = agentLogA.slice(logAAfterB).split(/\r?\n/).filter((l) => l.startsWith("INJECTED "));
    console.log(`[e2e:app] agentA INJECTED (second key, after B closed): ${JSON.stringify(injectedAppA2)}`);
    expect(sawAppA2, "agentA still receives KeyB from App A after App B session closed").toBe(true);

    await pageA.close();
  } finally {
    await ctx.close().catch(() => {});
    await stopProc(agentProcA);
    await stopProc(agentProcB);
  }
});
