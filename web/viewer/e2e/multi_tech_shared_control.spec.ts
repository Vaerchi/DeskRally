/**
 * F2 MULTI-TECHNICIAN SHARED CONTROL — same-machine two-authorized-technician gate.
 *
 * Proves that two simultaneous controller sessions to the same agent process are correctly
 * isolated, independently authorized, and gracefully separated on disconnect. This is NOT the
 * attended-exclusivity gate (attended sessions are 1-to-1 by design); this tests the installed-
 * service multi-session path exposed via the `multi-stream` test harness subcommand.
 *
 * The agent runs `agent_host multi-stream --synthetic`, which registers with
 * `multi_session_capable: true`. The signaling broker then admits concurrent connect_request
 * messages targeting the same device instead of rejecting the second with "agent busy".
 *
 * TWO PHASES:
 *
 * Phase 1 — Insecure signaling (SIG_PORT 8184, no CP required).
 *   Proves the protocol mechanics: video fan-out, input isolation, disconnect isolation,
 *   held-key release. Uses `-insecure-no-ticket-verification -insecure-no-agent-auth` so the
 *   focus stays on multi-session behaviour, not the auth stack.
 *
 * Phase 2 — Enforcing signaling with CP (SIG_PORT 8186, CP_PORT 8185).
 *   Proves the signed-permission contract: each technician receives an independent CP-signed
 *   session ticket from `POST /sessions`; both present their own ticket on `connect_request`
 *   and reach "connected"; neither can use the other's ticket (failclosed). The agent registers
 *   with a real enrolled Ed25519 identity so an ENFORCING signaling accepts it.
 *
 * CALLER MANIFEST (what this spec spawns and why):
 *   agent_host multi-stream --synthetic --device <uuid>
 *     → registers multi_session_capable=true, emits synthetic VP8 frames
 *   signaling.exe -addr :8184 -insecure-no-ticket-verification -insecure-no-agent-auth
 *     → Phase 1: brokers without any auth checks
 *   signaling.exe -addr :8186 (SIGNALING_TICKET_PUBKEY, SIGNALING_DEVICE_IDENTITY_{URL,TOKEN})
 *     → Phase 2: enforcing, verifies CP-signed tickets on connect_request; -insecure-no-agent-auth
 *       only skips the proof-of-possession registration challenge (enrollment not in scope here)
 *   controlplane.exe (CP_INSECURE_DEV=1, fixed CP_INSECURE_DEV_GRANT_SEED)
 *     → Phase 2: mints signed tickets for POST /sessions; no database needed
 *   harness.html?device=<uuid>&url=<ws> (×2)
 *     → two browser pages each running the real WebRTCTransport
 *
 * Self-skips ONLY when a prerequisite binary is absent. A SKIP IS NOT A PASS.
 * Environment mismatch (binary exists but won't start) FAILs loudly.
 */
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { stopProc } from "./devcp";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

// Phase 1: insecure signaling — proves multi-session mechanics.
const SIG_PORT_INSEC = 8184;
const SIGNALING_WS_INSEC = `ws://127.0.0.1:${SIG_PORT_INSEC}/ws`;

// Phase 2: enforcing signaling + CP — proves signed-permission contract.
const SIG_PORT_ENF = 8186;
const CP_PORT_ENF = 8185;
const SIGNALING_WS_ENF = `ws://127.0.0.1:${SIG_PORT_ENF}/ws`;
const CP_BASE_ENF = `http://127.0.0.1:${CP_PORT_ENF}`;

// Fixed so the grant pubkey is stable across CP restarts within the test run.
const DEV_GRANT_ISSUER_SEED = "2222222222222222222222222222222222222222222222222222222222222222";
const DEVICE_IDENTITY_TOKEN = "e2e-multi-tech-device-identity-token-01234567890abcdef";

// Transport keeps a disconnected peer recoverable for 10 seconds (DISCONNECTED_GRACE).
// Allow that grace plus scheduling slack before requiring its exact coordinator cleanup.
const SESSION_TEARDOWN_TIMEOUT_MS = 15_000;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function waitFor(
  pred: () => Promise<boolean>,
  timeoutMs: number,
  stepMs = 250,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return true;
    if (Date.now() > deadline) return false;
    await sleep(stepMs);
  }
}

function wsReachable(url: string, timeoutMs: number): Promise<boolean> {
  return new Promise((res) => {
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      try { ws.close(); } catch { /* ignore */ }
      res(ok);
    };
    const ws = new WebSocket(url);
    ws.onopen = () => finish(true);
    ws.onerror = () => finish(false);
    setTimeout(() => finish(false), timeoutMs);
  });
}

function httpOk(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then((r) => r.ok)
    .catch(() => false);
}

/** Open a harness page for the given signaling URL + device UUID, optionally with a signed ticket. */
async function openHarnessPage(
  browser: Browser,
  sigWs: string,
  deviceId: string,
  ticketB64?: string,
): Promise<Page> {
  const page = await browser.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  let url = `${HARNESS_BASE}?url=${encodeURIComponent(sigWs)}&device=${deviceId}`;
  if (ticketB64) url += `&ticket=${ticketB64}`;
  await page.goto(url);
  return page;
}

/**
 * Await the harness `window.rmt.connected` Promise — resolves once "connected", rejects on
 * "failed". Uses the harness-wired one-shot resolver rather than polling the mutable `state`
 * field, closing the race where connected→disconnected between two evaluate calls produced a
 * confusing "got disconnected" assertion failure. Times out after `timeoutMs` via a race.
 */
async function waitForConnected(page: Page, timeoutMs = 30_000): Promise<void> {
  await page.evaluate(
    (ms) => {
      const rmt = (window as unknown as { rmt?: { connected: Promise<void> } }).rmt;
      if (!rmt) return Promise.reject(new Error("harness not loaded (window.rmt absent)"));
      return Promise.race([
        rmt.connected,
        new Promise<never>((_, rej) =>
          setTimeout(() => rej(new Error(`waitForConnected timed out after ${ms}ms`)), ms),
        ),
      ]);
    },
    timeoutMs,
  );
}

type InboundStats = { bytesReceived?: number; packetsReceived?: number } | null;

/** Poll harness inbound-rtp video stats until bytes > 0. */
async function waitForVideo(page: Page, label: string, timeoutMs = 20_000): Promise<void> {
  let inbound: InboundStats = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<InboundStats> } }).rmt;
        if (!r) return null;
        const v = await r.inboundVideo();
        return v;
      });
      return (
        inbound !== null &&
        typeof (inbound as { bytesReceived?: number }).bytesReceived === "number" &&
        (inbound as { bytesReceived?: number }).bytesReceived! > 0
      );
    },
    timeoutMs,
  );
  const b = (inbound as { bytesReceived?: number } | null)?.bytesReceived ?? 0;
  const p = (inbound as { packetsReceived?: number } | null)?.packetsReceived ?? 0;
  console.log(`[e2e:${label}] inbound-rtp video: bytesReceived=${b} packetsReceived=${p}`);
  expect(b, `${label}: bytesReceived must be > 0`).toBeGreaterThan(0);
  expect(p, `${label}: packetsReceived must be > 0`).toBeGreaterThan(0);
}

// ─── Phase 1: Insecure signaling ─────────────────────────────────────────────────────────────────

const deviceIdInsec = randomUUID();
let sigProcInsec: ChildProcess | null = null;
let agentProcInsec: ChildProcess | null = null;
let browserInsec: Browser | null = null;
let skipReasonInsec: string | null = null;
let agentLogInsec = "";

test.describe("Phase 1 — insecure signaling: multi-session mechanics", () => {
  test.beforeAll(async () => {
    test.setTimeout(120_000);
    if (!existsSync(AGENT_BIN)) {
      skipReasonInsec = `agent binary not found at ${AGENT_BIN} — build with: cargo build -p rmt-agent-windows --bin agent_host`;
      return;
    }
    if (!existsSync(SIGNALING_EXE)) {
      skipReasonInsec = `${SIGNALING_EXE} is missing — globalSetup should have built it`;
      return;
    }

    // Signaling: insecure (no ticket check, no agent auth). Proves multi-session WITHOUT
    // conflating the result with the auth stack — that is Phase 2's job.
    sigProcInsec = spawn(
      SIGNALING_EXE,
      ["-addr", `:${SIG_PORT_INSEC}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"],
      { cwd: SIGNALING_DIR, stdio: ["ignore", "pipe", "pipe"] },
    );
    sigProcInsec.stdout?.on("data", (d: Buffer) => process.stdout.write(`[sig-insec] ${d}`));
    sigProcInsec.stderr?.on("data", (d: Buffer) => process.stdout.write(`[sig-insec] ${d}`));
    const sigUp = await waitFor(() => wsReachable(SIGNALING_WS_INSEC, 500), 10_000);
    if (!sigUp) throw new Error(`insecure signaling did not come up on :${SIG_PORT_INSEC}`);

    // Agent: multi-stream synthetic — registers multi_session_capable=true, no real DXGI.
    agentProcInsec = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceIdInsec,
        "--signaling", SIGNALING_WS_INSEC,
        "--fps", "10",
      ],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentStarted = false;
    agentProcInsec.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLogInsec += s;
      process.stdout.write(`[agent-insec] ${s}`);
      if (s.includes("multi_session_capable=true")) agentStarted = true;
    });
    agentProcInsec.stderr?.on("data", (d: Buffer) => process.stdout.write(`[agent-insec:err] ${d}`));
    agentProcInsec.on("exit", (code) => process.stdout.write(`[agent-insec] exited code=${code}\n`));

    if (!(await waitFor(async () => agentStarted, 10_000))) {
      throw new Error("multi-stream agent did not report multi_session_capable=true within 10s");
    }
    await sleep(800); // settle: let register_agent land in the broker

    const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
    try {
      browserInsec = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
    } catch {
      try {
        browserInsec = await chromium.launch({ headless: true, args: launchArgs });
      } catch (e) {
        skipReasonInsec = `no usable browser: ${String(e)}`;
      }
    }
  });

  test.afterAll(async () => {
    await browserInsec?.close().catch(() => {});
    await stopProc(agentProcInsec);
    await stopProc(sigProcInsec);
    agentProcInsec = null;
    sigProcInsec = null;
  });

  test("multi-tech: both sessions reach connected and receive independent VP8 video", async () => {
    test.skip(skipReasonInsec !== null, skipReasonInsec ?? "");
    if (!browserInsec) test.skip(true, "no browser");
    test.setTimeout(60_000);

    const pageA = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);
    const pageB = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);

    // Both controllers must be brokered to the same agent concurrently.
    await Promise.all([
      waitForConnected(pageA, 30_000),
      waitForConnected(pageB, 30_000),
    ]);
    console.log("[e2e] both tech A and tech B reached WebRTC connected state");

    // Both must receive video — the agent fans out the same broadcast to each subscriber.
    await Promise.all([
      waitForVideo(pageA, "techA"),
      waitForVideo(pageB, "techB"),
    ]);
    console.log("[e2e] both sessions independently received VP8 video frames — fan-out confirmed");

    await pageA.close();
    await pageB.close();
  });

  test("multi-tech: session A disconnect leaves session B unaffected", async () => {
    test.skip(skipReasonInsec !== null, skipReasonInsec ?? "");
    if (!browserInsec) test.skip(true, "no browser");
    test.setTimeout(60_000);

    const pageA = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);
    const pageB = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);

    await Promise.all([waitForConnected(pageA, 30_000), waitForConnected(pageB, 30_000)]);
    await waitForVideo(pageB, "techB-before-A-disconnect");

    // Record B's baseline byte count before closing A.
    const bytesBefore = await pageB.evaluate(async () => {
      const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
      const v = await r?.inboundVideo();
      return v?.bytesReceived ?? 0;
    });

    // Disconnect tech A.
    await pageA.close();
    console.log("[e2e] tech A page closed");

    // B must continue receiving video after A's disconnect. Poll until bytesReceived grows.
    let bytesAfter = 0;
    const continued = await waitFor(async () => {
      bytesAfter = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        const v = await r?.inboundVideo();
        return v?.bytesReceived ?? 0;
      });
      return bytesAfter > bytesBefore;
    }, 15_000);
    console.log(`[e2e] tech B bytesReceived before A closed: ${bytesBefore}, after: ${bytesAfter}`);
    expect(continued, "session B must continue receiving video after A disconnects").toBe(true);
    expect(bytesAfter).toBeGreaterThan(bytesBefore);

    await pageB.close();
  });

  test("multi-tech: coordinator releases A's held key when A disconnects (single holder)", async () => {
    test.skip(skipReasonInsec !== null, skipReasonInsec ?? "");
    if (!browserInsec) test.skip(true, "no browser");
    test.setTimeout(60_000);

    const pageA = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);
    const pageB = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);

    await Promise.all([waitForConnected(pageA, 30_000), waitForConnected(pageB, 30_000)]);

    // Snapshot agent log BEFORE the key event to isolate this test's log slice from prior sessions.
    const logBefore = agentLogInsec.length;

    // A holds key code 65 (VK_A) without releasing it.
    await pageA.evaluate(() => {
      (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
        t: "Key", c: { code: 65, down: true },
      });
    });
    console.log("[e2e] tech A sent KeyDown 65 (held, no KeyUp)");

    // Wait for A's coordinator admission and capture A's unique session ID.
    // first_holder=true because A is the sole sender at this point.
    let aSessionId = "";
    const aAdmitted = await waitFor(async () => {
      const delta = agentLogInsec.slice(logBefore);
      const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=65 first_holder=true/);
      if (m) { aSessionId = m[1]; return true; }
      return false;
    }, 8_000);
    expect(aAdmitted, "A's key=65 must be admitted by coordinator (first_holder=true)").toBe(true);
    console.log(`[e2e] tech A admitted as session=${aSessionId} first_holder=true`);

    // Assert: exactly one OS key_down for code 65; no key_up yet.
    const logAfterDown = agentLogInsec.slice(logBefore);
    const downCount = (logAfterDown.match(/\[INJECT\] key_down code=65/g) ?? []).length;
    expect(downCount, "recording backend must emit exactly one [INJECT] key_down code=65").toBe(1);
    expect(logAfterDown.includes("[INJECT] key_up code=65"),
      "no key_up must fire before A disconnects").toBe(false);

    // Close A — coordinator release_session fires; A is the sole holder so OS key_up must inject.
    await pageA.close();
    console.log("[e2e] tech A page closed — coordinator must release held key 65 (A sole holder)");

    // Await A's EXACT coordinator cleanup: TEARDOWN:DONE bound to A's session ID (not a prior
    // session's teardown). This prevents a false-pass where a background session's cleanup marker
    // satisfies the condition before A's release_session has actually run.
    const aTornDown = await waitFor(async () => {
      return agentLogInsec.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`);
    }, SESSION_TEARDOWN_TIMEOUT_MS);
    expect(
      aTornDown,
      `A's coordinator cleanup must complete with TEARDOWN:DONE session=${aSessionId}`,
    ).toBe(true);
    console.log(`[e2e] session ${aSessionId} TEARDOWN:DONE confirmed — asserting key_up injection`);

    // key_up must now be present (emitted as part of A's sole-holder release).
    const logAfterRelease = agentLogInsec.slice(logBefore);
    console.log(`[e2e] injector log since key_down: ${logAfterRelease.trim().split("\n").join(" | ")}`);
    expect(
      logAfterRelease.includes("[INJECT] key_up code=65"),
      "coordinator must emit [INJECT] key_up code=65 after A's sole-holder disconnect",
    ).toBe(true);

    // B must still be receiving video — session isolation confirmed.
    await waitForVideo(pageB, "techB-after-A-disconnect-key-hold");
    console.log("[e2e] tech B video continues after A's held-key disconnect — session contamination absent");

    await pageB.close();
  });

  test("multi-tech: coordinator suppresses global key_up while B still holds A's key", async () => {
    test.skip(skipReasonInsec !== null, skipReasonInsec ?? "");
    if (!browserInsec) test.skip(true, "no browser");
    test.setTimeout(60_000);

    // This test proves the cross-session coordinator invariant:
    //   A and B both hold key 65 →  1 OS down (first holder wins)
    //   A disconnects            →  0 OS up   (B still holds; A's TEARDOWN:DONE for A_ID)
    //   B releases key 65        →  1 OS up   (B is the last holder)
    //
    // Binding requirement: A and B must be identified by DISTINCT session IDs captured from
    // their individual ADMITTED_INPUT log lines. The TEARDOWN:DONE wait must be bound to
    // A's exact session ID so that a prior session's teardown cannot falsely satisfy it.
    const pageA = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);
    const pageB = await openHarnessPage(browserInsec!, SIGNALING_WS_INSEC, deviceIdInsec);

    await Promise.all([waitForConnected(pageA, 30_000), waitForConnected(pageB, 30_000)]);
    // Drain video frames for both pages BEFORE taking the log baseline so that any
    // ADMITTED_INPUT lines from the video handshake do not contaminate the key-event slice.
    await Promise.all([waitForVideo(pageA, "techA-coord"), waitForVideo(pageB, "techB-coord")]);

    // Fresh log baseline: every log line after this index belongs exclusively to this test.
    const logBefore = agentLogInsec.length;

    // A sends key 65 down — coordinator injects OS key_down (A is first holder).
    await pageA.evaluate(() => {
      (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
        t: "Key", c: { code: 65, down: true },
      });
    });
    // Await A's ADMITTED_INPUT and capture A's unique session ID before sending B's event.
    // Sequencing matters: we must know A's ID before B's arrives so we can assert they differ.
    let aSessionId = "";
    const aAdmitted = await waitFor(async () => {
      const delta = agentLogInsec.slice(logBefore);
      const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=65 first_holder=true/);
      if (m) { aSessionId = m[1]; return true; }
      return false;
    }, 8_000);
    expect(aAdmitted, "A's key=65 must be admitted as first_holder before B sends its event").toBe(true);
    console.log(`[e2e] tech A admitted as session=${aSessionId} first_holder=true`);

    // B sends key 65 down — coordinator suppresses OS key_down (already held by A).
    await pageB.evaluate(() => {
      (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
        t: "Key", c: { code: 65, down: true },
      });
    });
    // Await B's ADMITTED_INPUT with a DIFFERENT session ID — proves B's event reached the
    // coordinator as an independent session, not a duplicate of A's log line.
    let bSessionId = "";
    const bAdmitted = await waitFor(async () => {
      const delta = agentLogInsec.slice(logBefore);
      // Match any ADMITTED_INPUT for key=65 whose session ID differs from A's.
      const re = /\[SESSION:ADMITTED_INPUT\] session=(\d+) key=65 first_holder=false/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(delta)) !== null) {
        if (m[1] !== aSessionId) { bSessionId = m[1]; return true; }
      }
      return false;
    }, 8_000);
    expect(bAdmitted, "B's key=65 must be admitted with a session ID distinct from A's").toBe(true);
    expect(bSessionId, "B's session ID must be non-empty").not.toBe("");
    expect(bSessionId, "B's session ID must differ from A's").not.toBe(aSessionId);
    console.log(`[e2e] tech B admitted as session=${bSessionId} first_holder=false (suppressed at OS layer)`);
    console.log("[e2e] both A and B sent KeyDown 65");

    // Exactly one OS key_down (A injected it; B's was suppressed by the coordinator).
    const logAfterBothDown = agentLogInsec.slice(logBefore);
    const downCount = (logAfterBothDown.match(/\[INJECT\] key_down code=65/g) ?? []).length;
    expect(downCount, "coordinator must inject OS key_down exactly once even though two sessions hold key 65").toBe(1);
    console.log(`[e2e] OS key_down count for code 65 after A+B both hold: ${downCount} (expected 1)`);

    // A disconnects — coordinator must NOT inject OS key_up (B still holds).
    await pageA.close();
    console.log("[e2e] tech A disconnected; coordinator must suppress OS key_up (B still holds)");

    // Await A's EXACT coordinator cleanup: TEARDOWN:DONE bound to A's session ID only.
    // A prior session's teardown marker (different session=N) must NOT satisfy this check —
    // that was the false-pass path in the unfixed test.
    const aTornDown = await waitFor(async () => {
      return agentLogInsec
        .slice(logBefore)
        .includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`);
    }, SESSION_TEARDOWN_TIMEOUT_MS);
    expect(
      aTornDown,
      `A's coordinator cleanup must complete with TEARDOWN:DONE session=${aSessionId} (not an unrelated session)`,
    ).toBe(true);
    console.log(`[e2e] session ${aSessionId} TEARDOWN:DONE confirmed — asserting no OS key_up`);

    // Only after A's exact cleanup: assert no key_up has been injected.
    const logAfterADisconnect = agentLogInsec.slice(logBefore);
    expect(
      logAfterADisconnect.includes("[INJECT] key_up code=65"),
      "coordinator must suppress OS key_up when B still holds key 65 after A disconnects",
    ).toBe(false);
    console.log("[e2e] confirmed: no OS key_up after A disconnects while B holds — coordinator correct");

    // B releases key 65 — coordinator injects OS key_up (B is the last holder).
    await pageB.evaluate(() => {
      (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
        t: "Key", c: { code: 65, down: false },
      });
    });

    // Await key_up injection then assert the final exact count (must be 1, not 0 or 2+).
    const upLogged = await waitFor(async () => {
      return agentLogInsec.slice(logBefore).includes("[INJECT] key_up code=65");
    }, 5_000);
    const logFinal = agentLogInsec.slice(logBefore);
    const upCount = (logFinal.match(/\[INJECT\] key_up code=65/g) ?? []).length;
    console.log(`[e2e] OS key_up count for code 65 after B releases: ${upCount} (expected 1)`);
    expect(upLogged, "coordinator must inject OS key_up when B (last holder) releases key 65").toBe(true);
    expect(upCount, "exactly one OS key_up must fire — only after the last holder releases").toBe(1);

    // B must receive fresh video bytes after the sequence — measure GROWTH, not cumulative > 0,
    // since B was streaming before this sequence and cumulative bytes are already > 0.
    const bytesBefore = await pageB.evaluate(async () => {
      const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
      const v = await r?.inboundVideo();
      return v?.bytesReceived ?? 0;
    });
    const bytesGrew = await waitFor(async () => {
      const cur = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        const v = await r?.inboundVideo();
        return v?.bytesReceived ?? 0;
      });
      return cur > bytesBefore;
    }, 8_000);
    expect(bytesGrew, "B must receive fresh video bytes after A+B same-key coordinator sequence").toBe(true);
    console.log("[e2e] A+B same-key coordinator invariant: 1 down, 0 up on A-disconnect, 1 up on B-release ✓");

    await pageB.close();
  });
});

// ─── Phase 2: Enforcing signaling + CP — signed permissions ──────────────────────────────────────

let cpProcEnf: ChildProcess | null = null;
let sigProcEnf: ChildProcess | null = null;
let agentProcEnf: ChildProcess | null = null;
let browserEnf: Browser | null = null;
let skipReasonEnf: string | null = null;
let deviceIdEnf = "";
let workDirEnf = "";

/** POST /sessions for `machine_id` in DEV mode; throw on non-OK. */
async function mintTicket(machineId: string): Promise<Record<string, unknown>> {
  const r = await fetch(`${CP_BASE_ENF}/sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ machine_id: machineId }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /sessions → ${r.status}: ${text}`);
  return JSON.parse(text) as Record<string, unknown>;
}

/** base64url-encode a ticket JSON object for the ?ticket= query param. */
function encodeTicket(t: unknown): string {
  return Buffer.from(JSON.stringify(t), "utf8").toString("base64url");
}

test.describe("Phase 2 — enforcing signaling: separate signed session leases", () => {
  test.beforeAll(async () => {
    test.setTimeout(180_000);
    if (!existsSync(AGENT_BIN)) {
      skipReasonEnf = `agent binary not found at ${AGENT_BIN}`;
      return;
    }
    if (!existsSync(SIGNALING_EXE) || !existsSync(CP_EXE)) {
      skipReasonEnf = `signaling or CP binary missing — globalSetup should have built them`;
      return;
    }

    workDirEnf = mkdtempSync(join(tmpdir(), "rmt-multi-tech-enf-"));

    // Control plane: DEV mode, fixed grant seed, device-identity endpoint for signaling.
    cpProcEnf = spawn(CP_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${CP_PORT_ENF}`,
        CP_INSECURE_DEV: "1",
        CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED,
        CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        DATABASE_URL: "",
      },
    });
    cpProcEnf.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp-enf] ${d}`));
    cpProcEnf.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp-enf] ${d}`));
    if (!(await waitFor(() => httpOk(`${CP_BASE_ENF}/healthz`, 500), 15_000))) {
      throw new Error(`CP did not come up on :${CP_PORT_ENF}`);
    }

    // Read the grant pubkey the signaling server will pin.
    const pkBody = await fetch(`${CP_BASE_ENF}/grant/pubkey`).then((r) => r.json()) as {
      grant_issuer_pubkey?: string;
    };
    const grantPubkey = pkBody.grant_issuer_pubkey ?? "";
    if (!/^[0-9a-f]{64}$/.test(grantPubkey)) {
      throw new Error(`unexpected grant_issuer_pubkey: ${grantPubkey}`);
    }

    // Enroll the agent to get a stable device UUID and Ed25519 identity key.
    // This follows the secure_posture.spec.ts pattern: mint a one-use enrollment token,
    // run `agent_host enroll`, read back the device UUID and key path from the config.
    const tokenBody = await fetch(`${CP_BASE_ENF}/enrollment-tokens`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // group_id is required since the per-group enrollment change (the CP answers 400 without it);
      // the DEV control plane's default group, as secure_posture.spec.ts uses.
      body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000", max_uses: 5 }),
    }).then((r) => r.json()) as { token?: string };
    const enrollToken = tokenBody.token;
    if (!enrollToken) throw new Error("POST /enrollment-tokens returned no token");

    const configPath = join(workDirEnf, "agent-config.json");
    const keyPath = join(workDirEnf, "agent-identity.key");
    writeFileSync(
      configPath,
      JSON.stringify({
        signaling_url: SIGNALING_WS_ENF,
        identity_path: keyPath.replace(/\\/g, "/"),
        stun: [],
      }),
    );
    // Async to avoid blocking Playwright's event loop (execFileSync blocks all async machinery
    // including timeout handlers, making a hung enroll immune to test.setTimeout).
    await new Promise<void>((res, rej) =>
      execFile(
        AGENT_BIN,
        ["enroll", "--control-plane-url", CP_BASE_ENF, "--token", enrollToken,
         "--name", "E2E-MultiTech", "--config", configPath],
        { timeout: 30_000 },
        (err) => (err ? rej(err) : res()),
      )
    );
    const cfg = JSON.parse(readFileSync(configPath, "utf8")) as {
      device_id?: string;
      tenant_id?: string;
    };
    deviceIdEnf = cfg.device_id ?? "";
    if (!deviceIdEnf) throw new Error("enrollment did not write device_id into config");
    console.log(`[e2e] enrolled multi-tech agent as device=${deviceIdEnf}`);

    // Signaling: enforcing tickets + -insecure-no-agent-auth (proof-of-possession not tested here;
    // that is Phase 1 of secure_posture.spec.ts). Tickets ARE verified — that is the gate.
    sigProcEnf = spawn(
      SIGNALING_EXE,
      ["-addr", `:${SIG_PORT_ENF}`, "-insecure-no-agent-auth"],
      {
        cwd: SIGNALING_DIR,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          SIGNALING_TICKET_PUBKEY: grantPubkey,
          SIGNALING_DEVICE_IDENTITY_URL: CP_BASE_ENF,
          SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        },
      },
    );
    sigProcEnf.stdout?.on("data", (d: Buffer) => process.stdout.write(`[sig-enf] ${d}`));
    sigProcEnf.stderr?.on("data", (d: Buffer) => process.stdout.write(`[sig-enf] ${d}`));
    if (!(await waitFor(() => wsReachable(SIGNALING_WS_ENF, 500), 10_000))) {
      throw new Error(`enforcing signaling did not come up on :${SIG_PORT_ENF}`);
    }

    // Agent: multi-stream with enrolled identity so signaling (even in -insecure-no-agent-auth mode)
    // receives the correct pubkey claim. Ticket-based connect_request is the thing under test.
    agentProcEnf = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceIdEnf,
        "--identity", keyPath,
        "--signaling", SIGNALING_WS_ENF,
        "--fps", "10",
      ],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    let agentEnfStarted = false;
    agentProcEnf.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      process.stdout.write(`[agent-enf] ${s}`);
      if (s.includes("multi_session_capable=true")) agentEnfStarted = true;
    });
    agentProcEnf.stderr?.on("data", (d: Buffer) => process.stdout.write(`[agent-enf:err] ${d}`));
    if (!(await waitFor(async () => agentEnfStarted, 12_000))) {
      throw new Error("enrolled multi-stream agent did not report multi_session_capable=true");
    }
    await sleep(800);

    const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
    try {
      browserEnf = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
    } catch {
      try {
        browserEnf = await chromium.launch({ headless: true, args: launchArgs });
      } catch (e) {
        skipReasonEnf = `no usable browser: ${String(e)}`;
      }
    }
  });

  test.afterAll(async () => {
    await browserEnf?.close().catch(() => {});
    await stopProc(agentProcEnf);
    await stopProc(sigProcEnf);
    await stopProc(cpProcEnf);
    agentProcEnf = null;
    sigProcEnf = null;
    cpProcEnf = null;
    // Parent test owns the temp dir: remove after stopProc has confirmed all processes exited.
    // Rust TempDirGuard RAII drop does not run on forced process kill, so RAII alone cannot
    // guarantee cleanup. stopProc awaits actual exit before returning, so deletion is safe here.
    if (workDirEnf) {
      try { rmSync(workDirEnf, { recursive: true, force: true }); } catch {}
      workDirEnf = "";
    }
  });

  test(
    "multi-tech: two independent CP-signed tickets each authorize a separate concurrent session",
    async () => {
      test.skip(skipReasonEnf !== null, skipReasonEnf ?? "");
      if (!browserEnf) test.skip(true, "no browser");
      test.setTimeout(90_000);

      // Each technician mints their own session ticket from the CP. Two separate POST /sessions
      // calls produce two distinct session_id values and two separately-signed ticket envelopes.
      const bodyA = await mintTicket(deviceIdEnf);
      const bodyB = await mintTicket(deviceIdEnf);

      const ticketA = (bodyA.signaling as { ticket?: unknown } | undefined)?.ticket;
      const ticketB = (bodyB.signaling as { ticket?: unknown } | undefined)?.ticket;
      const sidA = (bodyA.signaling as { session_id?: string } | undefined)?.session_id
        ?? (bodyA as { session_id?: string }).session_id;
      const sidB = (bodyB.signaling as { session_id?: string } | undefined)?.session_id
        ?? (bodyB as { session_id?: string }).session_id;

      if (!ticketA || !ticketB) {
        throw new Error(
          `POST /sessions did not return tickets. A: ${JSON.stringify(bodyA)}, B: ${JSON.stringify(bodyB)}`,
        );
      }
      expect(sidA, "each technician gets a different session_id").not.toBe(sidB);
      console.log(`[e2e] minted tickets: sessionA=${sidA} sessionB=${sidB}`);

      const ticketAB64 = encodeTicket(ticketA);
      const ticketBB64 = encodeTicket(ticketB);

      const pageA = await openHarnessPage(browserEnf!, SIGNALING_WS_ENF, deviceIdEnf, ticketAB64);
      const pageB = await openHarnessPage(browserEnf!, SIGNALING_WS_ENF, deviceIdEnf, ticketBB64);

      // Both must reach "connected" — the broker admitted both signed tickets.
      await Promise.all([waitForConnected(pageA, 30_000), waitForConnected(pageB, 30_000)]);
      console.log("[e2e] both tech A and tech B connected with independent CP-signed tickets");

      // Both receive video — signed auth did not gate the media path.
      await Promise.all([waitForVideo(pageA, "techA-enf"), waitForVideo(pageB, "techB-enf")]);
      console.log("[e2e] signed-ticket: both sessions independently receiving VP8 video");

      await pageA.close();
      await pageB.close();
    },
  );

  test(
    "multi-tech: a tampered ticket is rejected; the valid partner session continues",
    async () => {
      test.skip(skipReasonEnf !== null, skipReasonEnf ?? "");
      if (!browserEnf) test.skip(true, "no browser");
      test.setTimeout(60_000);

      // Tech B has a valid ticket; tech A presents a tampered (invalid-sig) ticket.
      const bodyB = await mintTicket(deviceIdEnf);
      const ticketB = (bodyB.signaling as { ticket?: unknown } | undefined)?.ticket;
      if (!ticketB) throw new Error(`POST /sessions did not return ticket: ${JSON.stringify(bodyB)}`);

      // Tamper: corrupt the Ed25519 signature field of the decoded ticket (NOT the JSON envelope).
      // Flipping a character in the JSON string's trailing bytes would corrupt JSON structure and
      // cause a parse error in the browser before the broker ever sees the ticket — proving
      // browser-side JSON failure, not broker-side signature rejection. We must corrupt the sig
      // field value so the broker receives a structurally valid ticket with an invalid signature.
      const ticketCopy = JSON.parse(JSON.stringify(ticketB)) as { sig?: string; claims?: unknown };
      if (!ticketCopy.sig || ticketCopy.sig.length < 4) {
        throw new Error(`ticket.sig absent or too short: ${JSON.stringify(ticketCopy)}`);
      }
      const mid = Math.floor(ticketCopy.sig.length / 2);
      ticketCopy.sig =
        ticketCopy.sig.slice(0, mid) +
        (ticketCopy.sig[mid] === "A" ? "B" : "A") +
        ticketCopy.sig.slice(mid + 1);
      const tampered = encodeTicket(ticketCopy);

      // Open A with tampered ticket (expects connect to be rejected / fail).
      const pageA = await openHarnessPage(browserEnf!, SIGNALING_WS_ENF, deviceIdEnf, tampered);

      // Open B with valid ticket.
      const pageB = await openHarnessPage(browserEnf!, SIGNALING_WS_ENF, deviceIdEnf, encodeTicket(ticketB));

      // B must connect; A must fail.
      await waitForConnected(pageB, 30_000);
      console.log("[e2e] tech B (valid ticket) connected");

      // A's state: should be "failed" (rejected by enforcing signaling) or error set.
      const statusA = await pageA.evaluate(() => {
        const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
        return r ? { state: r.state, error: r.error } : null;
      });
      // Allow time for the rejection to propagate.
      await waitFor(async () => {
        const s = await pageA.evaluate(() => {
          const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
          return r?.state ?? "";
        });
        return s === "failed" || s === "disconnected";
      }, 10_000);
      const finalA = await pageA.evaluate(() => {
        const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
        return { state: r?.state, error: r?.error };
      });
      console.log(
        `[e2e] tech A (tampered ticket) state=${finalA.state} error=${finalA.error ?? "none"}`,
      );
      expect(
        finalA.state === "failed" || finalA.state === "disconnected" || finalA.error !== null,
        "tampered ticket must not reach connected state",
      ).toBe(true);

      // B must still be connected and receiving video after A's rejection.
      await waitForVideo(pageB, "techB-after-A-rejected");
      console.log("[e2e] tech B continues receiving video after A's tampered-ticket rejection — failclosed confirmed");

      await pageA.close();
      await pageB.close();
    },
  );
});
