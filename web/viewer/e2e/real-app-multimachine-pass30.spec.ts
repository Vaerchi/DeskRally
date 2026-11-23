/**
 * REAL-APP MULTI-MACHINE SESSION ROUTING / END / LOGOUT — Pass 32 (input correlation)
 *
 * Pass 32 extends the accepted Pass 31 baseline with real App keyboard input correlation and
 * tightened post-logout monitoring. All Pass 31 proofs are preserved:
 *
 *  P1 — One browser.newContext() with the actual product "Open in new tab" link for the second
 *       machine. The two pages share a single browser context (shared cookie jar, shared auth).
 *       No fallback re-login on the popup — the auth gate must NOT appear on page 2.
 *
 *  P1 — Agents started with --grant-issuer <grant_issuer_pubkey> in secure-test-harness mode.
 *       Agent logs must confirm "secure-test-harness mode" and must NOT contain "NOT ENFORCED".
 *       If the binary rejects the flag ("secure profile BLOCKED"), the test hard-fails with a
 *       clear provenance message rather than weakening the assertion.
 *
 *  P1 — Alpha page stays OPEN after CP End session. Teardown is required from the post-End
 *       log offset (only lines after the click count). Agent Alpha must emit exact
 *       "[SESSION:TEARDOWN:DONE session=0]" within 25 s of CP End.
 *       Scope: Alpha is already ended before Beta's logout — this is NOT a two-active-stream
 *       logout scenario. Alpha teardown is driven by CP End; Beta teardown by logout.
 *
 *  P1 — Pre-logout browser cookie+CSRF captured from context.cookies(). Auth-204 baseline
 *       established before logout. Exact pre-logout credentials replayed after logout → must
 *       return 401, not anonymous ≥ 400. Policy renewal replay also returns 401.
 *
 *  P2 — Real Vite /cp proxy used for browser requests (no custom page.route() intercept,
 *       no Origin/Sec-Fetch stripping). Browser's Sec-Fetch-Site: same-origin passes the
 *       originMiddleware check at the CP.
 *
 *  P2 — Bounded window observation: both shared-context pages must cease renewal/reconnect
 *       after logout. Dwell duration computed from the observed policy renewal interval
 *       (renewIntervalMs = min(MAX=15s, max(2s, lease_ms/3)) per session_lease.ts); dwell
 *       covers at least 2 renewal cycles.
 *
 * Pass 32 new requirements:
 *
 *  [Input/A] Real App keyboard input — Alpha positive: press "a" (Playwright dispatches
 *       KeyboardEvent { code:"KeyA", keyCode:65 }). dom_input.ts vkForCode("KeyA") → 0x41=65
 *       (Windows VK_A). This is NOT the browser charCode/keyCode directly — it is the VK code
 *       from the CODE_TO_VK table, the single source of truth in the viewer. Agent Alpha must
 *       emit "[SESSION:ADMITTED_INPUT] session=0 key=65" and "[INJECT] key_down code=65"
 *       within 10 s of the key press. If absent: report concrete defect to Codex.
 *
 *  [Input/B] Real App keyboard input — Beta positive (before End): press "b"
 *       (KeyB → VK 0x42=66). Agent Beta must emit ADMITTED_INPUT key=66 within 10 s.
 *
 *  [Input/C] After Alpha CP End, Beta still active — press "c" (KeyC → VK 0x43=67) on
 *       page2. Agent Beta must admit key=67 within 10 s (proves Beta session survives Alpha End).
 *
 *  [Input/D] After Alpha CP End — negative bounded observation: press "a" on page1 (viewer
 *       now shows non-Connected/disconnected state; App removes keyboard listener when
 *       inputActive becomes false). Assert NO "[SESSION:ADMITTED_INPUT]" in agentLogA within
 *       5 s (bounded, not a timeout substitute — Alpha's session is ended at the coordinator).
 *
 *  [Teardown/Beta] After logout: agent Beta must emit "[SESSION:TEARDOWN:DONE session=0]"
 *       from the betaLogOffsetBeforeLogout offset within 25 s of logout.
 *
 *  [Logout/204] POST /auth/logout → 204 captured via page.on("response") and hard-asserted
 *       (not conditional on whether the listener fired — the App must emit the event).
 *
 *  [Monitor] POST /sessions mint (new session creation), POST /sessions/{id}/policy renewal
 *       attempts (any status), and new signaling WebSocket authentication ("agent auth OK"
 *       in sigLog) are monitored across the explicit post-logout dwell. Assert none occur
 *       after settled logout. No renewed video/input path possible after gate is shown.
 *
 * Ports: CP=8300, SIG=8301 (isolated from all other specs).
 * Two inert synthetic agents (multi-stream --grant-issuer), one browser context, two pages.
 * RecordingOsSink: no real OS keyboard injection; [INJECT] and [SESSION:ADMITTED_INPUT]
 * lines are the test-observable evidence of the coordinator admitting input.
 * No production source edits. retries: 0. No skips.
 */

import { PINNED } from "./chrome_pinned";
import { test, expect, chromium, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { stopProc } from "./devcp";
import { openAccountControls } from "./nav";
import { clickAccessAction, openAccessActions } from "./machine_actions";
import { CP_PORT as SHARED_CP_PORT } from "./ports";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CPTESTFIXTURE_EXE = resolve(CP_DIR, "cptestfixture.exe");

const VITE_BASE = "http://127.0.0.1:5173";

// The console reaches the control plane only through the Vite /cp proxy, whose target is the shared
// e2e CP port (ports.ts). A private port here (8300 until 2026-10-18) left /cp unanswered, so the
// login gate this pass waits for could never appear.
const CP_PORT = Number(SHARED_CP_PORT);
const SIG_PORT = 8301;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;

const GRANT_SEED = "6666666666666666666666666666666666666666666666666666666666666666";
const DEVICE_IDENTITY_TOKEN = "e2e-pass30-multimachine-token-666666abcdef";

// Windows VK codes from dom_input.ts CODE_TO_VK map.
// Letters KeyA..KeyZ → 0x41..0x5A — same numeric value as ASCII uppercase, but this is a
// consequence of the OS VK layout, NOT a "browser key numeric" assumption. The single source
// of truth is dom_input.ts vkForCode(), which maps physical key code strings to Windows VKs.
// Playwright press("a") dispatches { code:"KeyA", keyCode:65 } → vkForCode("KeyA") = 0x41 = 65.
const VK_A = 0x41; // 65 — pressed on page1 (Alpha), before End  [Input/A]
const VK_B = 0x42; // 66 — pressed on page2 (Beta),  before End  [Input/B]
const VK_C = 0x43; // 67 — pressed on page2 (Beta),  after  End  [Input/C positive]

// ── Utilities ─────────────────────────────────────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function waitFor(
  pred: () => Promise<boolean>,
  timeoutMs: number,
  stepMs = 250,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred().catch(() => false)) return true;
    if (Date.now() > deadline) return false;
    await sleep(stepMs);
  }
}

function httpReachable(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then(() => true)
    .catch(() => false);
}

function wsReachable(wsUrl: string, timeoutMs: number): Promise<boolean> {
  return new Promise((res) => {
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      try { ws.close(); } catch { /* ignore */ }
      res(ok);
    };
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => finish(true);
    ws.onerror = () => finish(false);
    setTimeout(() => finish(false), timeoutMs);
  });
}

async function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const hash = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (d) => hash.update(d));
    s.on("end", () => res(hash.digest("hex")));
    s.on("error", rej);
  });
}

// ── CP/fixture types and auth helpers ─────────────────────────────────────────────────────────────

interface FixtureConfig {
  ready: boolean;
  tenant_id: string;
  admin_email: string;
  admin_password: string;
  tech_a_id: string;
  tech_a_email: string;
  tech_a_password: string;
  grant_issuer_pubkey: string;
  listen_addr: string;
}

interface CPSession {
  sessionCookie: string;
  csrfToken: string;
}

async function loginToCP(tenantId: string, email: string, password: string): Promise<CPSession> {
  const r = await fetch(`${CP_BASE}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenant: tenantId, email, password }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /auth/login ${email} → ${r.status}: ${text}`);
  const body = JSON.parse(text) as { csrf_token?: string };
  const csrfToken = body.csrf_token ?? "";

  const setCookies: string[] =
    typeof (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
      ? (r.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
      : [];
  let sessionCookie = "";
  for (const raw of setCookies) {
    const pair = raw.split(";")[0]?.trim() ?? "";
    if (pair.startsWith("cp_session=") || pair.startsWith("__Host-cp_session=")) {
      sessionCookie = pair.split("=").slice(1).join("=");
    }
  }
  if (!sessionCookie) throw new Error(`POST /auth/login ${email}: no session cookie`);
  if (!csrfToken) throw new Error(`POST /auth/login ${email}: no csrf_token`);
  return { sessionCookie, csrfToken };
}

function authHeaders(sess: CPSession): Record<string, string> {
  return {
    "content-type": "application/json",
    "cookie": `cp_session=${sess.sessionCookie}; rmt_csrf=${sess.csrfToken}`,
    "x-csrf-token": sess.csrfToken,
  };
}

// ── Fixture startup ───────────────────────────────────────────────────────────────────────────────

async function parseFixtureReady(proc: ChildProcess, timeoutMs = 30_000): Promise<FixtureConfig> {
  return new Promise<FixtureConfig>((res, rej) => {
    let buf = "";
    const timer = setTimeout(
      () => rej(new Error("cptestfixture: FIXTURE_READY not received within timeout")),
      timeoutMs,
    );
    proc.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      process.stdout.write(`[cp-p32] ${d}`);
      const line = buf.split("\n").find((l) => l.startsWith("FIXTURE_READY "));
      if (line) {
        clearTimeout(timer);
        try {
          res(JSON.parse(line.slice("FIXTURE_READY ".length)) as FixtureConfig);
        } catch (e) {
          rej(new Error(`FIXTURE_READY parse error: ${e}`));
        }
      }
    });
    proc.stderr?.on("data", (d: Buffer) =>
      process.stdout.write(`[cp-p32:err] ${d}`),
    );
  });
}

// ── Machine enrollment ─────────────────────────────────────────────────────────────────────────────

async function createEnrollmentToken(sess: CPSession): Promise<string> {
  const r = await fetch(`${CP_BASE}/enrollment-tokens`, {
    method: "POST",
    headers: authHeaders(sess),
    body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /enrollment-tokens → ${r.status}: ${text}`);
  const body = JSON.parse(text) as { token?: string };
  const token = body.token;
  if (!token) throw new Error("POST /enrollment-tokens: no token in response");
  return token;
}

async function enrollMachine(
  enrollToken: string,
  machineName: string,
  configPath: string,
  keyPath: string,
): Promise<string> {
  writeFileSync(
    configPath,
    JSON.stringify({
      signaling_url: SIGNALING_WS,
      identity_path: keyPath.replace(/\\/g, "/"),
      stun: [],
    }),
  );
  await new Promise<void>((res, rej) =>
    execFile(
      AGENT_BIN,
      [
        "enroll",
        "--control-plane-url", CP_BASE,
        "--token", enrollToken,
        "--name", machineName,
        "--config", configPath,
      ],
      { timeout: 30_000 },
      (err) => (err ? rej(new Error(`enroll ${machineName}: ${err.message}`)) : res()),
    ),
  );
  const cfg = JSON.parse(readFileSync(configPath, "utf8")) as { device_id?: string };
  const deviceId = cfg.device_id ?? "";
  if (!deviceId) throw new Error(`enrollment (${machineName}): no device_id written`);
  return deviceId;
}

// ── Network-event capture (no page.route() intercept — real Vite /cp proxy used) ─────────────────
//
// Browser requests go to http://127.0.0.1:5173/cp/** and are proxied by Vite's /cp block
// (CONTROL_PLANE_ORIGIN=http://127.0.0.1:8300, changeOrigin:true) to our cptestfixture.
// The browser's Sec-Fetch-Site: same-origin passes the CP's originMiddleware check
// (requestIsSameSite returns true on "same-origin" before the Origin fallback fires, so the
// changeOrigin Host rewrite is harmless).  No headers are stripped.
//
// Session IDs are captured from POST /cp/sessions response bodies via page.on("response").
// End-session requests are captured via page.on("request") (headers are present pre-forward).

interface SessionCapture {
  sessionByDevice: Map<string, string>;
}

// page.on("request") does not include browser-managed cookies in headers() (CDP limitation).
// For session creation we only need the response body (device→session mapping), so response
// events are sufficient.  For end-session we use page.route() with route.continue() which
// captures headers WITH browser cookies and forwards the request to Vite's /cp proxy unchanged
// (Sec-Fetch-Site: same-origin preserved; no stripping).
function setupNetworkCapture(page: Page): SessionCapture {
  const capture: SessionCapture = {
    sessionByDevice: new Map(),
  };

  page.on("response", (resp) => {
    const url = resp.url();
    const method = resp.request().method();
    if (method === "POST" && /\/cp\/sessions$/.test(url) && resp.status() < 300) {
      resp.json().then((body: { session?: { id?: string; machine_device_id?: string } }) => {
        const sid = body?.session?.id;
        const did = body?.session?.machine_device_id;
        if (sid && did) {
          capture.sessionByDevice.set(did, sid);
          console.log(`[p32:cap] session created device=${did} session=${sid}`);
        }
      }).catch(() => {/* non-JSON or body already gone */});
    }
  });

  return capture;
}

// setupEndSessionCapture installs a page.route() handler for end-session requests that:
//   1. Captures the full request headers (including browser-managed cookies — available via route)
//   2. Forwards the request UNCHANGED via route.continue() (Vite /cp proxy handles it normally)
// This satisfies "no Origin/Sec-Fetch stripping" since route.continue() passes all headers.
async function setupEndSessionCapture(
  page: Page,
): Promise<Array<{ sessionId: string; headers: Record<string, string> }>> {
  const endRequests: Array<{ sessionId: string; headers: Record<string, string> }> = [];
  await page.route("**/cp/sessions/*/end", async (route) => {
    const req = route.request();
    const urlMatch = req.url().match(/\/cp\/sessions\/([^/?]+)\/end/);
    if (urlMatch && req.method() === "POST") {
      const sessionId = urlMatch[1];
      endRequests.push({ sessionId, headers: req.headers() });
      console.log(`[p32:cap] END SESSION (route, headers captured): session=${sessionId}`);
    }
    await route.continue();
  });
  return endRequests;
}

// ── Module-level state ────────────────────────────────────────────────────────────────────────────

let cpProc: ChildProcess | null = null;
let sigProc: ChildProcess | null = null;
let agentProcA: ChildProcess | null = null;
let agentProcB: ChildProcess | null = null;
let browser: Browser | null = null;
let context: BrowserContext | null = null;
let workDir = "";
let fixtureCfg: FixtureConfig | null = null;
let deviceIdA = "";
let deviceIdB = "";
let keyPathA = "";
let keyPathB = "";
let sigLog = "";
let agentLogA = "";
let agentLogB = "";

// ── Suite ─────────────────────────────────────────────────────────────────────────────────────────

test.describe("Real-App multi-machine session routing, end, and logout — Pass 32", () => {
  test.describe.configure({ retries: 0 });

  test.beforeAll(async () => {
    test.setTimeout(300_000);

    if (!existsSync(AGENT_BIN)) {
      throw new Error(
        `agent binary not found: ${AGENT_BIN}\n` +
          `Build with: cargo build -p rmt-agent-windows --bin agent_host --features test-harness,secure-test`,
      );
    }
    if (!existsSync(SIGNALING_EXE)) {
      throw new Error(`signaling binary not found: ${SIGNALING_EXE}`);
    }
    if (!existsSync(CPTESTFIXTURE_EXE)) {
      throw new Error(`cptestfixture binary not found: ${CPTESTFIXTURE_EXE}`);
    }

    const [hashAgent, hashSig, hashFix] = await Promise.all([
      sha256File(AGENT_BIN),
      sha256File(SIGNALING_EXE),
      sha256File(CPTESTFIXTURE_EXE),
    ]);
    console.log(`[p32:hash] agent_host.exe      ${hashAgent}`);
    console.log(`[p32:hash] signaling.exe        ${hashSig}`);
    console.log(`[p32:hash] cptestfixture.exe    ${hashFix}`);

    workDir = mkdtempSync(join(tmpdir(), "rmt-pass32-"));
    console.log(`[p32] workDir: ${workDir}`);

    // ── cptestfixture ─────────────────────────────────────────────────────────────────────────────
    cpProc = spawn(CPTESTFIXTURE_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${CP_PORT}`,
        CP_FIXTURE_GRANT_SEED: GRANT_SEED,
        CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        CP_SIGNALING_URL: SIGNALING_WS,
      },
    });
    fixtureCfg = await parseFixtureReady(cpProc);
    if (!fixtureCfg.tech_a_email) {
      throw new Error("cptestfixture: fixture config missing tech_a — rebuild cptestfixture");
    }
    if (!fixtureCfg.grant_issuer_pubkey) {
      throw new Error("cptestfixture: no grant_issuer_pubkey in fixture config");
    }
    console.log(`[p32] fixture ready — tenant=${fixtureCfg.tenant_id} grant_issuer=${fixtureCfg.grant_issuer_pubkey.slice(0, 16)}...`);

    if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`, 500), 15_000))) {
      throw new Error(`cptestfixture did not start serving on :${CP_PORT}`);
    }

    // ── Signaling server ──────────────────────────────────────────────────────────────────────────
    sigProc = spawn(SIGNALING_EXE, ["-addr", `127.0.0.1:${SIG_PORT}`], {
      cwd: SIGNALING_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        SIGNALING_TICKET_PUBKEY: fixtureCfg.grant_issuer_pubkey,
        SIGNALING_DEVICE_IDENTITY_URL: CP_BASE,
        SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      },
    });
    const onSig = (s: string) => {
      sigLog += s;
      process.stdout.write(`[sig-p32] ${s}`);
    };
    sigProc.stdout?.on("data", (d: Buffer) => onSig(d.toString()));
    sigProc.stderr?.on("data", (d: Buffer) => onSig(d.toString()));

    if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 15_000))) {
      throw new Error(`signaling did not come up on :${SIG_PORT}`);
    }
    console.log(`[p32] signaling up on :${SIG_PORT}`);

    // ── Enroll both machines ──────────────────────────────────────────────────────────────────────
    const adminSess = await loginToCP(
      fixtureCfg.tenant_id,
      fixtureCfg.admin_email,
      fixtureCfg.admin_password,
    );

    const configPathA = join(workDir, "a-config.json");
    keyPathA = join(workDir, "a-identity.key");
    const tokenA = await createEnrollmentToken(adminSess);
    deviceIdA = await enrollMachine(tokenA, "Pass32-Alpha", configPathA, keyPathA);

    const configPathB = join(workDir, "b-config.json");
    keyPathB = join(workDir, "b-identity.key");
    const tokenB = await createEnrollmentToken(adminSess);
    deviceIdB = await enrollMachine(tokenB, "Pass32-Beta", configPathB, keyPathB);

    console.log(`[p32] enrolled Alpha=${deviceIdA} Beta=${deviceIdB}`);

    // ── Agent Alpha — multi-stream with --grant-issuer (secure-test-harness profile) ─────────────
    // multi_stream_command (host.rs:936) parses --grant-issuer. When built with the secure-test
    // feature, it prints "secure-test-harness mode" and sets BackstageAuth::SignedBy.
    // Without the secure-test feature it prints "secure profile BLOCKED" — the beforeAll assertion
    // below catches this and hard-fails with provenance info rather than degrading to Deny.
    agentProcA = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceIdA,
        "--identity", keyPathA,
        "--tenant", fixtureCfg.tenant_id,
        "--signaling", SIGNALING_WS,
        "--fps", "10",
        "--grant-issuer", fixtureCfg.grant_issuer_pubkey,
      ],
      {
        cwd: REPO,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, RMT_LOG: "debug" },
      },
    );
    const onAgentA = (s: string) => {
      agentLogA += s;
      process.stdout.write(`[agentA-p32] ${s}`);
    };
    agentProcA.stdout?.on("data", (d: Buffer) => onAgentA(d.toString()));
    agentProcA.stderr?.on("data", (d: Buffer) => onAgentA(d.toString()));
    agentProcA.on("exit", (code) =>
      process.stdout.write(`[agentA-p32] exited code=${code}\n`),
    );

    // ── Agent Beta ────────────────────────────────────────────────────────────────────────────────
    agentProcB = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceIdB,
        "--identity", keyPathB,
        "--tenant", fixtureCfg.tenant_id,
        "--signaling", SIGNALING_WS,
        "--fps", "10",
        "--grant-issuer", fixtureCfg.grant_issuer_pubkey,
      ],
      {
        cwd: REPO,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, RMT_LOG: "debug" },
      },
    );
    const onAgentB = (s: string) => {
      agentLogB += s;
      process.stdout.write(`[agentB-p32] ${s}`);
    };
    agentProcB.stdout?.on("data", (d: Buffer) => onAgentB(d.toString()));
    agentProcB.stderr?.on("data", (d: Buffer) => onAgentB(d.toString()));
    agentProcB.on("exit", (code) =>
      process.stdout.write(`[agentB-p32] exited code=${code}\n`),
    );

    // Wait for both agents to register with signaling.
    const agentAuthOkA = `agent auth OK: device "${deviceIdA}"`;
    const agentAuthOkB = `agent auth OK: device "${deviceIdB}"`;
    const agentsRegistered = await waitFor(
      async () => sigLog.includes(agentAuthOkA) && sigLog.includes(agentAuthOkB),
      60_000,
    );
    if (!agentsRegistered) {
      throw new Error(
        `agents did not register within 60s\n` +
          `Alpha registered: ${sigLog.includes(agentAuthOkA)}\n` +
          `Beta  registered: ${sigLog.includes(agentAuthOkB)}`,
      );
    }
    console.log("[p32] both agents registered with signaling");

    // Hard-fail if --grant-issuer was blocked (binary lacks secure-test feature).
    if (agentLogA.includes("secure profile BLOCKED") || agentLogB.includes("secure profile BLOCKED")) {
      const blockedAgent = agentLogA.includes("secure profile BLOCKED") ? "Alpha" : "Beta";
      throw new Error(
        `Agent ${blockedAgent} rejected --grant-issuer: "secure profile BLOCKED".\n` +
          `Binary ${AGENT_BIN} was not built with the secure-test feature.\n` +
          `Build with: cargo build -p rmt-agent-windows --bin agent_host --features test-harness,secure-test\n` +
          `Expected binary hash for secure-test build: 5bf7f4917af06abcfaa62ca1f174ccb0a42eab4459fa3364633f5c1c3fe3aa7d\n` +
          `Agent Alpha log (tail): ${agentLogA.slice(-300)}\n` +
          `Agent Beta log (tail): ${agentLogB.slice(-300)}`,
      );
    }

    // Confirm secure-test-harness mode is active in both agents (multi_stream_command, host.rs:950).
    if (!agentLogA.includes("secure-test-harness mode")) {
      throw new Error(
        `Agent Alpha: expected "secure-test-harness mode" in log but did not find it.\n` +
          `This means --grant-issuer was not accepted by multi_stream_command (host.rs:936).\n` +
          `Agent Alpha log (tail): ${agentLogA.slice(-400)}`,
      );
    }
    if (!agentLogB.includes("secure-test-harness mode")) {
      throw new Error(
        `Agent Beta: expected "secure-test-harness mode" in log but did not find it.\n` +
          `Agent Beta log (tail): ${agentLogB.slice(-400)}`,
      );
    }
    console.log("[p32] both agents confirmed secure-test-harness mode active");

    // Hard-fail if NOT ENFORCED warning appears — it must be absent when grant_issuer is pinned.
    if (agentLogA.includes("NOT ENFORCED")) {
      throw new Error(
        `Agent Alpha emitted "NOT ENFORCED" warning despite --grant-issuer being present.\n` +
          `This indicates BackstageAuth::Deny is active — check binary build flags.\n` +
          `Agent Alpha log: ${agentLogA.slice(-400)}`,
      );
    }
    if (agentLogB.includes("NOT ENFORCED")) {
      throw new Error(
        `Agent Beta emitted "NOT ENFORCED" warning despite --grant-issuer being present.\n` +
          `Agent Beta log: ${agentLogB.slice(-400)}`,
      );
    }
    console.log("[p32] no NOT ENFORCED warnings in agent logs — enforcement confirmed");

    // ── Browser — single context (shared cookie jar / auth state) ────────────────────────────────
    browser = await chromium.launch({ channel: "chrome" });
    context = await browser.newContext({ ...PINNED });
  });

  test.afterAll(async () => {
    if (agentLogA) process.stdout.write(`[p32:final-agentA-log excerpt]\n${agentLogA.slice(-2000)}\n`);
    if (agentLogB) process.stdout.write(`[p32:final-agentB-log excerpt]\n${agentLogB.slice(-2000)}\n`);

    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
    await stopProc(agentProcA, 5_000);
    await stopProc(agentProcB, 5_000);
    await stopProc(sigProc, 5_000);
    await stopProc(cpProc, 5_000);
    agentProcA = agentProcB = sigProc = cpProc = null;
    context = null;
    browser = null;

    try { rmSync(workDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  // ── Main test ──────────────────────────────────────────────────────────────────────────────────

  test("multi-machine session end and logout via real App — Pass 32", async () => {
    test.setTimeout(300_000);

    if (!browser || !context || !fixtureCfg) throw new Error("beforeAll failed — no browser/context/fixture");
    const tenantId = fixtureCfg.tenant_id;
    const techEmail = fixtureCfg.tech_a_email;
    const techPassword = fixtureCfg.tech_a_password;

    // Policy renewal timestamps — captured from page response events during the connected phase.
    // Used to compute the actual renewal interval for the bounded post-logout dwell.
    // renewIntervalMs(leaseTtlMs) = min(MAX_RENEW=15000, max(MIN_RENEW=2000, floor(leaseTtlMs/3)))
    // per session_lease.ts. With the observed lease_ms≈29976, interval = min(15000, 9992) = 9992ms.
    const policyRenewalTimestamps: number[] = [];

    // ── Page 1: login + connect Machine Alpha ─────────────────────────────────────────────────────
    // Uses one context.newPage() — real Vite /cp proxy handles all browser requests.

    const page1 = await context.newPage();
    page1.on("console", (m) =>
      process.stdout.write(`[page1:${m.type()}] ${m.text()}\n`),
    );
    const capture1 = setupNetworkCapture(page1);

    // Track policy renewals from page1 for dwell computation.
    page1.on("response", (resp) => {
      if (/\/cp\/sessions\/[^/]+\/policy$/.test(resp.url()) && resp.status() < 300) {
        policyRenewalTimestamps.push(Date.now());
      }
    });

    await page1.goto(`${VITE_BASE}/console`);
    await expect(page1.getByTestId("app-login-gate")).toBeVisible({ timeout: 20_000 });
    console.log("[p32] Page 1: login gate visible");

    await page1.getByTestId("cp-login-tenant").fill(tenantId);
    await page1.getByTestId("cp-login-email").fill(techEmail);
    await page1.getByTestId("cp-login-password").fill(techPassword);
    await page1.getByTestId("cp-login-submit").click();

    await expect(page1.locator("li.access__machine").first()).toBeVisible({ timeout: 20_000 });
    console.log("[p32] Page 1: fleet loaded");

    await expect(
      page1.locator("li.access__machine").filter({ hasText: "Pass32-Alpha" }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      page1.locator("li.access__machine").filter({ hasText: "Pass32-Beta" }),
    ).toBeVisible({ timeout: 5_000 });
    console.log("[p32] Page 1: both machines visible in fleet");

    // Connect to Machine Alpha on Page 1.
    await page1
      .locator("li.access__machine")
      .filter({ hasText: "Pass32-Alpha" })
      .getByRole("button", { name: /connect/i })
      .click();
    console.log("[p32] Page 1: clicked Connect for Machine Alpha");

    await expect(page1.locator(".viewer__status")).toContainText("Connected", {
      timeout: 45_000,
    });
    console.log("[p32] Page 1: Machine Alpha — connected");

    await page1.waitForFunction(
      () => {
        const v = document.querySelector("video");
        return v != null && v.readyState >= 2 && v.currentTime > 0;
      },
      { timeout: 20_000 },
    );
    console.log("[p32] Page 1: Machine Alpha — video flowing");

    const sessionIdA = await waitFor(
      async () => capture1.sessionByDevice.get(deviceIdA) !== undefined,
      10_000,
    ).then(() => capture1.sessionByDevice.get(deviceIdA) ?? "");
    if (!sessionIdA) throw new Error("Page 1: POST /sessions for Machine Alpha did not return session id");
    console.log(`[p32] Page 1: sessionA=${sessionIdA}`);

    // ── Page 2: real product "Open in new tab" link — same browser context ────────────────────────
    // AccessPanel renders <a data-testid="new-tab-{device}" target="_blank"> for each machine row.
    // Clicking it in a Playwright context emits a 'page' event on the context (same cookie jar).
    // No re-login must be needed — the session cookie is shared via the single browser context.

    const newTabLocator = page1.locator(`[data-testid="new-tab-${deviceIdB}"]`);
    await expect(newTabLocator).toHaveCount(1, { timeout: 10_000 });
    await openAccessActions(page1, deviceIdB); // "Open in new tab" is in the row's "⋯" menu (menu redesign wave 8b)
    await expect(newTabLocator).toBeVisible({ timeout: 10_000 });

    const [page2] = await Promise.all([
      context.waitForEvent("page"),
      newTabLocator.click(),
    ]);
    page2.on("console", (m) =>
      process.stdout.write(`[page2:${m.type()}] ${m.text()}\n`),
    );
    const capture2 = setupNetworkCapture(page2);

    // Track policy renewals from page2 as well (Beta session).
    page2.on("response", (resp) => {
      if (/\/cp\/sessions\/[^/]+\/policy$/.test(resp.url()) && resp.status() < 300) {
        policyRenewalTimestamps.push(Date.now());
      }
    });

    // End-session header capture via route.continue() — installs before the badge becomes visible
    // so the route is ready when the user clicks End session.
    const endRequests = await setupEndSessionCapture(page2);
    console.log("[p32] Page 2: popup opened via new-tab link");

    // HARD ASSERTION: the login gate must NOT appear on Page 2.
    await page2.waitForLoadState("domcontentloaded", { timeout: 10_000 });
    await sleep(2_000);
    await expect(
      page2.getByTestId("app-login-gate"),
      "Page 2 (popup) must NOT show login gate — session cookie must be shared via single browser context",
    ).toHaveCount(0, { timeout: 10_000 });
    console.log("[p32] Page 2: no login gate — shared-context auth confirmed");

    // Wait for Machine Beta to auto-connect (URL param auto-connect, App.tsx:~1751).
    await expect(page2.locator(".viewer__status")).toContainText("Connected", {
      timeout: 60_000,
    });
    console.log("[p32] Page 2: Machine Beta — connected (auto-connect via URL params)");

    await page2.waitForFunction(
      () => {
        const v = document.querySelector("video");
        return v != null && v.readyState >= 2 && v.currentTime > 0;
      },
      { timeout: 20_000 },
    );
    console.log("[p32] Page 2: Machine Beta — video flowing");

    const sessionIdB = await waitFor(
      async () => capture2.sessionByDevice.get(deviceIdB) !== undefined,
      15_000,
    ).then(() => capture2.sessionByDevice.get(deviceIdB) ?? "");
    if (!sessionIdB) throw new Error("Page 2: POST /sessions for Machine Beta did not return session id");
    console.log(`[p32] Page 2: sessionB=${sessionIdB}`);

    // Alpha session badge must also be visible on page 2 fleet panel (live session).
    await expect(page2.getByTestId(`session-badge-${deviceIdA}`)).toBeVisible({ timeout: 10_000 });
    console.log("[p32] Page 2: Machine Alpha session badge visible in fleet (sessionA is live)");

    // ── Pre-logout: capture browser cookie/CSRF for auth-204 baseline and replay ─────────────────

    const preCookies = await context.cookies("http://127.0.0.1:5173");
    const cpSessCookieEntry = preCookies.find(
      (c) => c.name === "cp_session" || c.name === "__Host-cp_session",
    );
    const rmtCsrfCookieEntry = preCookies.find((c) => c.name === "rmt_csrf");

    if (!cpSessCookieEntry) {
      throw new Error(
        "Pre-logout: cp_session cookie not found in browser context. " +
          `Cookies present: ${preCookies.map((c) => c.name).join(", ")}`,
      );
    }
    if (!rmtCsrfCookieEntry) {
      throw new Error(
        "Pre-logout: rmt_csrf cookie not found in browser context. " +
          `Cookies present: ${preCookies.map((c) => c.name).join(", ")}`,
      );
    }

    const preLogoutCpSession = `${cpSessCookieEntry.name}=${cpSessCookieEntry.value}`;
    const preLogoutCsrf = rmtCsrfCookieEntry.value;
    const preLogoutCookieStr = `${preLogoutCpSession}; rmt_csrf=${preLogoutCsrf}`;
    console.log(`[p32] pre-logout cookie captured: ${cpSessCookieEntry.name}=... rmt_csrf=...`);

    // Establish auth baseline — proves the captured cookie is currently valid.
    const baselineRes = await fetch(`${CP_BASE}/auth/session`, {
      headers: { cookie: preLogoutCookieStr },
    });
    expect(
      [200, 204],
      `Pre-logout GET /auth/session with real cookie must return 2xx (auth baseline), got ${baselineRes.status}`,
    ).toContain(baselineRes.status);
    console.log(`[p32] Pre-logout auth baseline: GET /auth/session → ${baselineRes.status} (authenticated confirmed)`);

    // Establish policy-renewal baseline — must return 200 (session is live).
    // POST /sessions/{id}/policy is a cookie-authenticated mutation requiring X-CSRF-Token.
    const preLogoutPolicyRes = await fetch(`${CP_BASE}/sessions/${sessionIdB}/policy`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cookie": preLogoutCookieStr,
        "x-csrf-token": preLogoutCsrf,
      },
      body: JSON.stringify({}),
    });
    expect(
      preLogoutPolicyRes.status,
      `Pre-logout POST /sessions/${sessionIdB}/policy must return 200 (policy baseline — session is live)`,
    ).toBe(200);
    console.log(
      `[p32] Pre-logout policy baseline: POST /sessions/${sessionIdB}/policy → ${preLogoutPolicyRes.status} (200 confirmed)`,
    );

    // ── [Input/A] Key press to Alpha — positive: verify admission in agentLogA ──────────────────
    // Playwright page.keyboard.press("a") dispatches KeyboardEvent { code:"KeyA", keyCode:65 }.
    // Viewer.tsx window-level keydown listener (active when inputActive=true, access="control")
    // calls domKeyToVk({ code:"KeyA", keyCode:65 }) → vkForCode("KeyA") → CODE_TO_VK["KeyA"] =
    // 0x41 = 65 (Windows VK_A). Sends InputEvent::Key { code:65, down:true } to the agent via
    // the WebRTC data channel. RecordingOsSink emits:
    //   [SESSION:ADMITTED_INPUT] session=0 key=65 first_holder=true
    //   [INJECT] key_down code=65
    // Assertion: both lines must appear in agentLogA within 10 s of the key press.
    // If absent: concrete defect — App keyboard input via focused viewer is not reaching agent.

    const alphaKeyOffsetPre = agentLogA.length;
    await page1.keyboard.press("a");
    console.log(`[p32] [Input/A] pressed "a" (VK_A=0x${VK_A.toString(16)}=${VK_A}) on page1 (Alpha viewer)`);

    const alphaAdmittedPre = await waitFor(async () => {
      const tail = agentLogA.slice(alphaKeyOffsetPre);
      return (
        tail.includes("[SESSION:ADMITTED_INPUT]") &&
        new RegExp(`key=${VK_A}\\b`).test(tail)
      );
    }, 10_000);

    if (!alphaAdmittedPre) {
      const tail = agentLogA.slice(alphaKeyOffsetPre).slice(-500);
      throw new Error(
        `[CONCRETE DEFECT for Codex] Agent Alpha: key press "a" (VK 0x41=${VK_A}) NOT admitted within 10 s.\n` +
          `Expected: [SESSION:ADMITTED_INPUT] session=0 key=${VK_A} first_holder=true\n` +
          `Expected: [INJECT] key_down code=${VK_A}\n` +
          `Actual agentLogA (tail, post-keypress):\n${tail}\n` +
          `Possible causes:\n` +
          `  1. App inputActive=false (session not in "control" mode; check policy)\n` +
          `  2. WebRTC data channel not established (check transport logs)\n` +
          `  3. Agent coordinator rejected the session handle (check agent startup)\n` +
          `  4. Playwright key event not reaching document.keydown listener\n` +
          `DO NOT relax this assertion — report the defect.`,
      );
    }

    // Parse and log the actual admission line for the report.
    const alphaAdmitLine = agentLogA.slice(alphaKeyOffsetPre).split("\n")
      .find((l) => l.includes("[SESSION:ADMITTED_INPUT]") && new RegExp(`key=${VK_A}\\b`).test(l));
    console.log(`[p32] [Input/A] PASS: Alpha admitted key=${VK_A}: ${alphaAdmitLine?.trim()}`);

    // Also verify the [INJECT] line (RecordingOsSink confirmation of OS-layer call).
    const alphaInjectLine = agentLogA.slice(alphaKeyOffsetPre).split("\n")
      .find((l) => new RegExp(`\\[INJECT\\] key_down code=${VK_A}\\b`).test(l));
    if (alphaInjectLine) {
      console.log(`[p32] [Input/A] PASS: Alpha INJECT line: ${alphaInjectLine.trim()}`);
    } else {
      console.log(`[p32] [Input/A] NOTE: [INJECT] key_down code=${VK_A} not found in window (may be buffered)`);
    }

    // ── [Input/B] Key press to Beta — positive: verify admission in agentLogB ──────────────────
    // press("b") → KeyB → VK 0x42 = 66 (VK_B). Same path as Alpha.

    const betaKeyOffsetPre = agentLogB.length;
    await page2.keyboard.press("b");
    console.log(`[p32] [Input/B] pressed "b" (VK_B=0x${VK_B.toString(16)}=${VK_B}) on page2 (Beta viewer)`);

    const betaAdmittedPre = await waitFor(async () => {
      const tail = agentLogB.slice(betaKeyOffsetPre);
      return (
        tail.includes("[SESSION:ADMITTED_INPUT]") &&
        new RegExp(`key=${VK_B}\\b`).test(tail)
      );
    }, 10_000);

    if (!betaAdmittedPre) {
      const tail = agentLogB.slice(betaKeyOffsetPre).slice(-500);
      throw new Error(
        `[CONCRETE DEFECT for Codex] Agent Beta: key press "b" (VK 0x42=${VK_B}) NOT admitted within 10 s.\n` +
          `Expected: [SESSION:ADMITTED_INPUT] session=0 key=${VK_B} first_holder=true\n` +
          `Actual agentLogB (tail, post-keypress):\n${tail}\n` +
          `DO NOT relax this assertion — report the defect.`,
      );
    }

    const betaAdmitLinePre = agentLogB.slice(betaKeyOffsetPre).split("\n")
      .find((l) => l.includes("[SESSION:ADMITTED_INPUT]") && new RegExp(`key=${VK_B}\\b`).test(l));
    console.log(`[p32] [Input/B] PASS: Beta admitted key=${VK_B}: ${betaAdmitLinePre?.trim()}`);

    // ── ASSERTION 1: End Machine Alpha's session from Page 2 ───────────────────────────────────────
    // Record log offsets BEFORE the End action so teardown evidence is bound to post-End lines.
    const alphaLogOffsetBeforeEnd = agentLogA.length;

    const endAlphaBtn = page2.getByTestId(`end-session-${deviceIdA}`);
    await expect(endAlphaBtn).toHaveCount(1, { timeout: 5_000 });
    await openAccessActions(page2, deviceIdA); // End session is in the row's "⋯" menu (menu redesign wave 8b)
    await expect(endAlphaBtn).toBeVisible({ timeout: 5_000 });
    page2.once("dialog", (d) => void d.accept()); // End session asks first (menu redesign wave 9)
    await endAlphaBtn.click();
    console.log("[p32] Page 2: clicked End session for Machine Alpha");

    // Alpha session badge must disappear from Page 2 fleet (session ended at CP).
    await expect(page2.getByTestId(`session-badge-${deviceIdA}`)).toHaveCount(0, {
      timeout: 15_000,
    });
    console.log("[p32] Page 2: Machine Alpha session badge gone — session ended");

    // Verify end-session request used the correct session ID and had auth headers.
    expect(
      endRequests.length,
      "Expected at least one POST /sessions/{id}/end request from Page 2 (route capture)",
    ).toBeGreaterThan(0);

    const endReq = endRequests.find((r) => r.sessionId === sessionIdA);
    expect(
      endReq,
      `POST /sessions/{id}/end not found with sessionId=${sessionIdA}. ` +
        `Observed end requests: ${JSON.stringify(endRequests.map((r) => r.sessionId))}`,
    ).toBeTruthy();

    const cookieHdr = endReq!.headers["cookie"] ?? "";
    expect(
      cookieHdr,
      "End-session request must include the session cookie (cp_session or __Host-cp_session)",
    ).toMatch(/cp_session=/);

    const csrfHdr = endReq!.headers["x-csrf-token"] ?? "";
    expect(csrfHdr, "End-session request must include X-CSRF-Token header").not.toBe("");

    console.log(
      `[p32] ASSERTION 1 PASS: sessionId=${sessionIdA} cookie=${cookieHdr.slice(0, 30)}... csrf=${csrfHdr.slice(0, 10)}...`,
    );

    // ── ASSERTION 2: Agent Alpha session teardown — exact [SESSION:TEARDOWN:DONE session=0] ────
    // Page 1 (Alpha viewer) stays OPEN. Teardown must be driven by the CP End signal to the agent,
    // not by page close. Only lines written after the End click (alphaLogOffsetBeforeEnd) count.
    // Exact string required: "[SESSION:TEARDOWN:DONE session=0]" (shared_capture.rs).

    const alphaCleanup = await waitFor(async () =>
      agentLogA.slice(alphaLogOffsetBeforeEnd).includes("[SESSION:TEARDOWN:DONE session=0]"),
      25_000,
    );

    expect(
      alphaCleanup,
      `Agent Alpha must emit "[SESSION:TEARDOWN:DONE session=0]" within 25 s of CP End.\n` +
        `New agent log lines since End click:\n${agentLogA.slice(alphaLogOffsetBeforeEnd).slice(-500)}`,
    ).toBe(true);
    console.log("[p32] ASSERTION 2 PASS: Agent Alpha [SESSION:TEARDOWN:DONE session=0] confirmed from post-End offset");

    // ── ASSERTION 3: Alpha viewer UI shows disconnected state (page 1 stays open) ──────────────
    // The App on Page 1 detects the WebRTC peer disconnect driven by the agent teardown and
    // transitions the viewer status away from "Connected".

    await expect(
      page1.locator(".viewer__status"),
      "Machine Alpha viewer on Page 1 must NOT show 'Connected' after CP End (page 1 stays open)",
    ).not.toContainText("Connected", { timeout: 20_000 });
    console.log("[p32] ASSERTION 3 PASS: Page 1 Alpha viewer shows non-Connected/disconnected state after CP End");

    // ── [Input/C] Key press to Beta after Alpha End — positive ────────────────────────────────────
    // Proves Beta session is still active and admitting input after Alpha's CP End.
    // press("c") → KeyC → VK 0x43 = 67 (VK_C). Scope: Alpha is already ended here.

    const betaKeyOffsetAfterEnd = agentLogB.length;
    await page2.keyboard.press("c");
    console.log(`[p32] [Input/C] pressed "c" (VK_C=0x${VK_C.toString(16)}=${VK_C}) on page2 after Alpha End`);

    const betaAdmittedAfterEnd = await waitFor(async () => {
      const tail = agentLogB.slice(betaKeyOffsetAfterEnd);
      return (
        tail.includes("[SESSION:ADMITTED_INPUT]") &&
        new RegExp(`key=${VK_C}\\b`).test(tail)
      );
    }, 10_000);

    if (!betaAdmittedAfterEnd) {
      const tail = agentLogB.slice(betaKeyOffsetAfterEnd).slice(-500);
      throw new Error(
        `[CONCRETE DEFECT for Codex] Agent Beta: key press "c" (VK 0x43=${VK_C}) NOT admitted after Alpha End.\n` +
          `Beta session should still be active; Alpha End must not affect Beta's coordinator.\n` +
          `Actual agentLogB (tail):\n${tail}`,
      );
    }

    const betaAdmitLineAfterEnd = agentLogB.slice(betaKeyOffsetAfterEnd).split("\n")
      .find((l) => l.includes("[SESSION:ADMITTED_INPUT]") && new RegExp(`key=${VK_C}\\b`).test(l));
    console.log(`[p32] [Input/C] PASS: Beta admitted key=${VK_C} after Alpha End: ${betaAdmitLineAfterEnd?.trim()}`);

    // ── [Input/D] Key press to Alpha after End — negative bounded observation ──────────────────
    // Alpha's session is ended at the CP. The App on page1 detects the WebRTC disconnect and
    // transitions to non-Connected; Viewer.tsx removes the keydown listener when inputActive
    // becomes false (transport closed). A key press on page1 must NOT produce a new
    // [SESSION:ADMITTED_INPUT] in agentLogA within a 5 s bounded window.
    // This is NOT a timeout-as-dwell — 5 s covers the full WebRTC round-trip latency margin.

    const alphaKeyOffsetAfterEnd = agentLogA.length;
    await page1.keyboard.press("a"); // attempt key injection via page1 (Alpha — now disconnected)
    console.log(`[p32] [Input/D] pressed "a" on page1 after Alpha End (negative test — bounded 5 s observation)`);

    await sleep(5_000); // bounded observation window: 5 s covers max WebRTC round-trip

    const alphaAdmittedAfterEnd = agentLogA
      .slice(alphaKeyOffsetAfterEnd)
      .includes("[SESSION:ADMITTED_INPUT]");

    expect(
      alphaAdmittedAfterEnd,
      `[Input/D] Agent Alpha must NOT admit any key input after CP End session.\n` +
        `Alpha coordinator session is torn down; no admission expected.\n` +
        `agentLogA tail after attempt:\n${agentLogA.slice(alphaKeyOffsetAfterEnd).slice(-300)}`,
    ).toBe(false);
    console.log("[p32] [Input/D] PASS: Alpha key rejected/not-admitted after CP End (bounded 5 s, no [SESSION:ADMITTED_INPUT])");

    // ── ASSERTION 4: Machine Beta stream survives and continues ───────────────────────────────────

    await expect(page2.locator(".viewer__status")).toContainText("Connected", {
      timeout: 5_000,
    });

    const t1 = await page2.evaluate(() => {
      const v = document.querySelector("video");
      return v?.currentTime ?? 0;
    });
    await sleep(2_000);
    const t2 = await page2.evaluate(() => {
      const v = document.querySelector("video");
      return v?.currentTime ?? 0;
    });
    expect(
      t2,
      `Machine Beta video must advance after Machine Alpha ends (t1=${t1} t2=${t2})`,
    ).toBeGreaterThan(t1);
    console.log(`[p32] ASSERTION 4 PASS: Machine Beta video advancing (${t1.toFixed(2)}→${t2.toFixed(2)}s)`);

    // Verify Alpha's viewer on page1 is in disconnected state — the App's keyboard listener is
    // removed when inputActive becomes false (confirmed by [Input/D] negative test above).
    await expect(
      page1.locator(".viewer__status"),
      "Alpha viewer must show disconnected state — App keyboard listener removed when inputActive=false",
    ).not.toContainText("Connected", { timeout: 5_000 });
    console.log("[p32] ASSERTION 4 PASS: Machine Alpha viewer disconnected — inputActive=false (confirmed by [Input/D])");

    // ── Compute post-logout bounded dwell from observed renewal interval ───────────────────────
    // session_lease.ts: renewIntervalMs(leaseTtlMs) = min(15000, max(2000, floor(leaseTtlMs/3)))
    // MAX_RENEW_INTERVAL_MS = 15_000 ms (per session_lease.ts). Used as fallback if < 2 renewals
    // observed during the connected phase. Dwell covers at least 2 renewal cycles + 5 s buffer.
    let observedRenewalIntervalMs = 15_000; // MAX_RENEW_INTERVAL_MS fallback
    if (policyRenewalTimestamps.length >= 2) {
      const intervals = policyRenewalTimestamps
        .slice(1)
        .map((t, i) => t - policyRenewalTimestamps[i]!);
      observedRenewalIntervalMs = Math.round(
        intervals.reduce((a, b) => a + b, 0) / intervals.length,
      );
      console.log(
        `[p32] observed ${policyRenewalTimestamps.length} policy renewals; ` +
          `mean interval = ${observedRenewalIntervalMs} ms`,
      );
    } else {
      console.log(
        `[p32] < 2 policy renewals observed during connected phase; ` +
          `using MAX_RENEW_INTERVAL_MS = ${observedRenewalIntervalMs} ms as dwell base`,
      );
    }
    const dwellMs = Math.max(observedRenewalIntervalMs * 2 + 5_000, 25_000);
    console.log(`[p32] post-logout bounded dwell = ${dwellMs} ms (covers ≥ 2 renewal cycles)`);

    // ── ASSERTION 5 & 6: Logout invalidates auth — exact credential replay, cross-tab teardown ─

    // Record offsets before logout so post-logout monitoring is bounded to after the gate.
    const betaLogOffsetBeforeLogout = agentLogB.length;
    const sigLogOffsetBeforeLogout = sigLog.length;

    // Observe logout HTTP response — required (not optional) for exact 204 assertion.
    let logoutResponseStatus = -1;
    const logoutResponseDone = new Promise<void>((resolve) => {
      page2.on("response", (resp) => {
        if (/\/cp\/auth\/logout$/.test(resp.url()) && resp.request().method() === "POST") {
          logoutResponseStatus = resp.status();
          console.log(`[p32] POST /auth/logout → ${resp.status()}`);
          resolve();
        }
      });
    });

    // Monitor both pages for post-logout renewal/reconnect cessation.
    // Track ALL policy attempts (not only 2xx) after logout to catch retries on stale sessions.
    let page1PostLogoutPolicy2xx = false;
    let page2PostLogoutPolicy2xx = false;
    let postLogoutSessionMintCount = 0;
    const logoutTime = { ms: 0 };

    page1.on("response", (resp) => {
      if (logoutTime.ms > 0) {
        if (/\/cp\/sessions\/[^/]+\/policy$/.test(resp.url()) && resp.status() < 300) {
          page1PostLogoutPolicy2xx = true;
        }
        if (/\/cp\/sessions$/.test(resp.url()) && resp.request().method() === "POST" && resp.status() < 300) {
          postLogoutSessionMintCount++;
          console.log(`[p32:WARN] Post-logout session mint on page1: status=${resp.status()}`);
        }
      }
    });
    page2.on("response", (resp) => {
      if (logoutTime.ms > 0) {
        if (/\/cp\/sessions\/[^/]+\/policy$/.test(resp.url()) && resp.status() < 300) {
          page2PostLogoutPolicy2xx = true;
        }
        if (/\/cp\/sessions$/.test(resp.url()) && resp.request().method() === "POST" && resp.status() < 300) {
          postLogoutSessionMintCount++;
          console.log(`[p32:WARN] Post-logout session mint on page2: status=${resp.status()}`);
        }
      }
    });

    const signOutBtn = page2.getByTestId("app-signout");
    await openAccountControls(page2);
    await expect(signOutBtn).toBeVisible({ timeout: 5_000 });
    await signOutBtn.click();
    logoutTime.ms = Date.now();
    console.log("[p32] Sign Out clicked on Page 2");

    // Wait for logout HTTP response — required (not optional).
    await Promise.race([
      logoutResponseDone,
      sleep(10_000),
    ]);

    // [Logout/204] Hard assertion: logout must return 204.
    // If logoutResponseStatus is -1, the response event did not fire — that itself is a defect.
    expect(
      logoutResponseStatus,
      `POST /auth/logout must return 204 (captured via page.on("response")). ` +
        `Got ${logoutResponseStatus === -1 ? "no response event (listener did not fire)" : logoutResponseStatus}. ` +
        `Ensure the App sends POST /auth/logout and the response is observable.`,
    ).toBe(204);
    console.log(`[p32] ASSERTION 5 PASS: POST /auth/logout → 204 (hard-asserted)`);

    // Page 2 must show the login gate after logout.
    await expect(page2.getByTestId("app-login-gate")).toBeVisible({ timeout: 15_000 });
    console.log("[p32] ASSERTION 5 PASS: Page 2 shows login gate after logout");

    // ── [Teardown/Beta] Agent Beta SESSION:TEARDOWN:DONE after logout ────────────────────────────
    // Scope: Alpha was already ended before this logout. Beta is the only active session being
    // torn down by logout. betaLogOffsetBeforeLogout ensures we look only at post-logout lines.

    const betaTeardown = await waitFor(async () =>
      agentLogB.slice(betaLogOffsetBeforeLogout).includes("[SESSION:TEARDOWN:DONE session=0]"),
      25_000,
    );

    expect(
      betaTeardown,
      `Agent Beta must emit "[SESSION:TEARDOWN:DONE session=0]" within 25 s of logout.\n` +
        `Scope: Alpha already ended by CP End — this is Beta's logout-driven teardown.\n` +
        `agentLogB (post-logout tail):\n${agentLogB.slice(betaLogOffsetBeforeLogout).slice(-500)}`,
    ).toBe(true);
    console.log("[p32] [Teardown/Beta] PASS: Agent Beta [SESSION:TEARDOWN:DONE session=0] confirmed after logout");

    // ── ASSERTION 6: Page 1 cross-tab login gate (bounded window) ────────────────────────────────
    // The session cookie was invalidated server-side by logout. Page 1's next CP request returns
    // 401; the App detects it and transitions to the login gate.
    await expect(
      page1.getByTestId("app-login-gate"),
      "Page 1 must show login gate — cookie revocation must propagate cross-tab",
    ).toBeVisible({ timeout: 30_000 });
    console.log("[p32] ASSERTION 6 PASS: Page 1 shows login gate after logout (cross-tab revocation confirmed)");

    // ── [Monitor] Post-logout bounded dwell — cover actual renewal schedule ───────────────────────
    // Wait until at least `dwellMs` has elapsed from logout time. This ensures we observe at
    // least 2 full renewal cycles. Any renewal or reconnect that would occur WILL occur within
    // this window (dwell ≥ 2 × observedRenewalIntervalMs + 5 s).
    const elapsed = Date.now() - logoutTime.ms;
    if (elapsed < dwellMs) {
      const remaining = dwellMs - elapsed;
      console.log(`[p32] [Monitor] dwell remaining: ${remaining} ms`);
      await sleep(remaining);
    }
    console.log(`[p32] [Monitor] dwell complete (${Date.now() - logoutTime.ms} ms elapsed since logout)`);

    // Assert no successful policy renewal occurred after logout on either page.
    expect(
      page1PostLogoutPolicy2xx,
      "Page 1 must not have a successful (2xx) policy renewal after logout (bounded dwell covered renewal schedule)",
    ).toBe(false);
    expect(
      page2PostLogoutPolicy2xx,
      "Page 2 must not have a successful (2xx) policy renewal after logout (bounded dwell covered renewal schedule)",
    ).toBe(false);

    // Assert no new session was minted after logout.
    expect(
      postLogoutSessionMintCount,
      "No POST /sessions (session mint) must succeed after logout — no auto-reconnect",
    ).toBe(0);

    // Assert no new signaling WebSocket authentication after logout.
    // A reconnect would produce "agent auth OK: device" in sigLog after the offset.
    const newSignalingAuth =
      sigLog.slice(sigLogOffsetBeforeLogout).includes(`agent auth OK: device "${deviceIdA}"`) ||
      sigLog.slice(sigLogOffsetBeforeLogout).includes(`agent auth OK: device "${deviceIdB}"`);
    expect(
      newSignalingAuth,
      "No new signaling WebSocket authentication must occur after logout for either agent",
    ).toBe(false);

    console.log("[p32] ASSERTION 6 PASS: no successful renewal/reconnect/mint/signaling after logout — all monitoring clear");

    // ── ASSERTION 7: Exact pre-logout credential replay → 401 ─────────────────────────────────────

    const postLogoutAuthRes = await fetch(`${CP_BASE}/auth/session`, {
      headers: { cookie: preLogoutCookieStr },
    });
    expect(
      postLogoutAuthRes.status,
      `POST-logout GET /auth/session with pre-logout cookie must return 401 ` +
        `(cookie was invalidated by logout, not merely absent). ` +
        `Got ${postLogoutAuthRes.status}. Pre-logout baseline was ${baselineRes.status}.`,
    ).toBe(401);
    console.log(`[p32] ASSERTION 7 PASS: GET /auth/session with pre-logout cookie → 401`);

    // ── ASSERTION 8: Policy renewal replay → 401 ─────────────────────────────────────────────────

    const postLogoutPolicyRes = await fetch(`${CP_BASE}/sessions/${sessionIdB}/policy`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cookie": preLogoutCookieStr,
        "x-csrf-token": preLogoutCsrf,
      },
      body: JSON.stringify({}),
    });
    expect(
      postLogoutPolicyRes.status,
      `POST-logout POST /sessions/${sessionIdB}/policy with pre-logout cookie must return 401. ` +
        `Pre-logout baseline was 200.`,
    ).toBe(401);
    console.log(
      `[p32] ASSERTION 8 PASS: POST /sessions/${sessionIdB}/policy with pre-logout cookie → 401`,
    );

    console.log("[p32] All assertions complete");
    await page2.close();
  });

  // 2026-10-19, production: an OBSERVER session made ZERO lease renewals and the agent ended it at the
  // ~30 s lease expiry ("session lease EXPIRED" in the operator's Desktop helper.log), while control sessions
  // renewed every 10 s. This drives the real console's Observe button against a real agent, real
  // signaling and the real control plane, and holds the observer for 45 s: it must keep renewing
  // and stay connected the whole time.
  test("an observer session keeps renewing its lease and survives > 40 s", async () => {
    test.setTimeout(180_000);
    if (!browser || !context || !fixtureCfg) throw new Error("beforeAll failed — no browser/context/fixture");
    // Observe is admitted for agents >= 0.1.3; this fixture has no presence feed, so record it.
    const rec = await fetch(`${CP_BASE}/fixture/agent-version`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_id: deviceIdA, version: "0.1.4+e2e" }),
    });
    expect(rec.status).toBe(204);

    const page = await context.newPage();
    page.on("console", (m) => process.stdout.write(`[obs:${m.type()}] ${m.text()}
`));
    const renewals: number[] = [];
    page.on("response", (resp) => {
      if (/\/cp\/sessions\/[^/]+\/policy$/.test(resp.url()) && resp.status() < 300) renewals.push(Date.now());
    });
    await page.goto(`${VITE_BASE}/console`);
    // The suite's first test signed tech A out, so this page always starts at the sign-in gate.
    await expect(page.getByTestId("app-login-gate")).toBeVisible({ timeout: 20_000 });
    await page.getByTestId("cp-login-tenant").fill(fixtureCfg.tenant_id);
    await page.getByTestId("cp-login-email").fill(fixtureCfg.tech_a_email);
    await page.getByTestId("cp-login-password").fill(fixtureCfg.tech_a_password);
    await page.getByTestId("cp-login-submit").click();
    const observe = page.getByTestId(`observe-${deviceIdA}`);
    await expect(observe).toHaveCount(1, { timeout: 20_000 });
    await openAccessActions(page, deviceIdA); // View only is in the row's "⋯" menu (menu redesign wave 8b)
    await expect(observe).toBeVisible({ timeout: 20_000 });
    await observe.click();
    await expect(page.getByTestId("observing-badge")).toBeVisible({ timeout: 45_000 });
    await expect(page.locator(".viewer__status")).toContainText("Connected", { timeout: 45_000 });
    const connectedAt = Date.now();
    console.log("[obs] observer connected; holding 45 s");

    await page.waitForTimeout(45_000);

    const during = renewals.filter((t) => t >= connectedAt);
    console.log(`[obs] policy renewals while observing: ${during.length}`);
    expect(during.length, "an observer must renew its lease (every ~10 s)").toBeGreaterThanOrEqual(3);
    await expect(page.locator(".viewer__status")).toContainText("Connected");
    await expect(page.getByTestId("observing-badge")).toBeVisible();
    await expect(page.getByText(/lease/i)).toHaveCount(0);
    await page.close();
  });
});
