/**
 * DEFAULT TTL LIVE VALIDATION — Pass 23.
 *
 * Validates that the signaling server's DEFAULT heartbeat TTL (30 s) is sufficient for end/logout
 * lease-expiry isolation. The 300 s --heartbeat-ttl override used in pass16 is NOT passed here.
 *
 * Protocol:
 *   1. cptestfixture + signaling start without --heartbeat-ttl override (server default: 30 s).
 *      Read timeout = 2 × 30 s = 60 s.
 *   2. Agent enrolled, started with RMT_LOG=debug so heartbeat sends appear in agent log.
 *   3. After agentStarted (multi_session_capable=true), wait 32 s (> 1× TTL boundary).
 *   4. Count "heartbeat sent" debug lines from the agent during the 32 s window.
 *   5. Assert ≥ 3 heartbeats were received (interval = 10 s; 32 s → at least 3 fires expected).
 *   6. Log registration epoch and post-boundary join timestamps as identity evidence.
 *   7. A and B join and connect successfully after the boundary (registration still live).
 *   8. pass20-end:    Admin END A → A renewal 409 → bounded A lease expiry → B isolated.
 *   9. pass20-logout: A logout → A mint/renew 401 → bounded A lease expiry → B isolated.
 *
 * Assertions retained verbatim: signed leases, [SESSION:TEARDOWN:DONE session=X] exact correlation,
 * A RTP frozen, B media+recording input (key=206/210) admitted in 5 s window.
 *
 * Ports: CP=8198, SIG=8199 (isolated from all other specs in the suite).
 * No production source changes. No retries.
 */

import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
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
const CPTESTFIXTURE_EXE = resolve(CP_DIR, "cptestfixture.exe");
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

// Isolated ports — no overlap with any other spec.
const CP_PORT = 8198;
const SIG_PORT = 8199;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;

// Separate grant-seed from pass16/18/20 (4444…).
const FIXTURE_GRANT_SEED = "4444444444444444444444444444444444444444444444444444444444444444";
const DEVICE_IDENTITY_TOKEN = "e2e-default-ttl-pass23-device-identity-token-4444abcdef";

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

function httpReachable(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then(() => true)
    .catch(() => false);
}

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

async function waitForVideo(page: Page, label: string, timeoutMs = 20_000): Promise<void> {
  let inbound: InboundStats = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<InboundStats> } }).rmt;
        if (!r) return null;
        return await r.inboundVideo();
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

// ── Auth helpers ─────────────────────────────────────────────────────────────────────────────────

interface CPSession {
  sessionCookie: string;
  csrfToken: string;
  userID: string;
}

async function loginToCP(tenantID: string, email: string, password: string): Promise<CPSession> {
  const r = await fetch(`${CP_BASE}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenant: tenantID, email, password }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /auth/login ${email} → ${r.status}: ${text}`);

  const body = JSON.parse(text) as { user_id?: string; csrf_token?: string };
  const csrfToken = body.csrf_token ?? "";
  const userID = body.user_id ?? "";

  const setCookies: string[] = typeof (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
    ? (r.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
    : [];

  let sessionCookie = "";
  for (const raw of setCookies) {
    const pair = raw.split(";")[0]?.trim() ?? "";
    if (pair.startsWith("cp_session=") || pair.startsWith("__Host-cp_session=")) {
      sessionCookie = pair.split("=").slice(1).join("=");
    }
  }

  if (!sessionCookie) throw new Error(`POST /auth/login ${email}: no session cookie in response`);
  if (!csrfToken) throw new Error(`POST /auth/login ${email}: no csrf_token in response body`);

  return { sessionCookie, csrfToken, userID };
}

function authHeaders(sess: CPSession): Record<string, string> {
  return {
    "content-type": "application/json",
    "cookie": `cp_session=${sess.sessionCookie}; rmt_csrf=${sess.csrfToken}`,
    "x-csrf-token": sess.csrfToken,
  };
}

async function mintTicket(sess: CPSession, machineId: string): Promise<Record<string, unknown>> {
  const r = await fetch(`${CP_BASE}/sessions`, {
    method: "POST",
    headers: authHeaders(sess),
    body: JSON.stringify({ machine_id: machineId }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /sessions → ${r.status}: ${text}`);
  return JSON.parse(text) as Record<string, unknown>;
}

function encodeTicket(t: unknown): string {
  return Buffer.from(JSON.stringify(t), "utf8").toString("base64url");
}

function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const hash = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (d) => hash.update(d));
    s.on("end", () => res(hash.digest("hex")));
    s.on("error", rej);
  });
}

async function waitForNewControlMsgOfType(
  page: Page,
  msgType: string,
  prevCount: number,
  timeoutMs = 15_000,
): Promise<boolean> {
  return waitFor(async () => {
    const n = await countControlMsgsByType(page, msgType);
    return n > prevCount;
  }, timeoutMs);
}

async function countControlMsgsByType(page: Page, msgType: string): Promise<number> {
  return page.evaluate((t) => {
    const r = (window as unknown as { rmt?: { controlReceived?: { t: string }[] } }).rmt;
    return (r?.controlReceived ?? []).filter((m) => m.t === t).length;
  }, msgType);
}

// ── Session-policy lease helpers ─────────────────────────────────────────────────────────────────

interface SessionLease {
  access: string;
  signed: string;
  lease_ttl_ms: number;
  expires_at_ms: number;
}

async function fetchSessionPolicy(sess: CPSession, sessionId: string): Promise<SessionLease> {
  const r = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sessionId)}/policy`, {
    method: "POST",
    headers: authHeaders(sess),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /sessions/${sessionId}/policy → ${r.status}: ${text}`);
  const body = JSON.parse(text) as { session_policy?: SessionLease };
  const sp = body.session_policy;
  if (!sp || !sp.signed || !sp.lease_ttl_ms || !sp.expires_at_ms) {
    throw new Error(`POST /sessions/${sessionId}/policy: malformed response: ${text}`);
  }
  return sp;
}

async function fetchSessionPolicyRaw(sess: CPSession, sessionId: string): Promise<{ status: number; body: string }> {
  const r = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sessionId)}/policy`, {
    method: "POST",
    headers: authHeaders(sess),
  });
  const body = await r.text();
  return { status: r.status, body };
}

async function adminEndSession(adminSess: CPSession, sessionId: string): Promise<{ status: number; body: string }> {
  const r = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sessionId)}/end`, {
    method: "POST",
    headers: authHeaders(adminSess),
  });
  const body = await r.text();
  return { status: r.status, body };
}

async function logoutFromCP(sess: CPSession): Promise<number> {
  const r = await fetch(`${CP_BASE}/auth/logout`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cookie": `cp_session=${sess.sessionCookie}; rmt_csrf=${sess.csrfToken}`,
      "x-csrf-token": sess.csrfToken,
    },
  });
  return r.status;
}

// ── Fixture config ───────────────────────────────────────────────────────────────────────────────

interface FixtureConfig {
  ready: boolean;
  tenant_id: string;
  admin_email: string;
  admin_password: string;
  tech_a_id: string;
  tech_a_email: string;
  tech_a_password: string;
  tech_b_id: string;
  tech_b_email: string;
  tech_b_password: string;
  grant_issuer_pubkey: string;
  listen_addr: string;
}

// ── Suite state ──────────────────────────────────────────────────────────────────────────────────

let cpProc: ChildProcess | null = null;
let sigProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let deviceId = "";
let tenantId = "";
let keyPath = "";
let workDir = "";
let agentLog = "";
let agentPid = 0;
let grantPubkey = "";
let fixtureCfg: FixtureConfig | null = null;

// Heartbeat TTL validation evidence — captured during the 32 s post-registration wait.
let registrationEpochMs = 0;    // wall-clock when agentStarted=true first fired
let ttlBoundaryPassedMs = 0;    // wall-clock after the 32 s wait completed
let heartbeatsSentDuringWait = 0; // count of "heartbeat sent" debug lines in the 32 s window

test.describe("Default TTL live validation — pass23 (end+logout, no --heartbeat-ttl override)", () => {
  test.beforeAll(async () => {
    test.setTimeout(300_000);

    if (!existsSync(AGENT_BIN)) {
      skipReason = `agent binary not found at ${AGENT_BIN} — build with: cargo build -p rmt-agent-windows --bin agent_host --features test-harness,secure-test`;
      return;
    }
    if (!existsSync(SIGNALING_EXE)) {
      skipReason = `signaling binary missing at ${SIGNALING_EXE} — run globalSetup or build manually`;
      return;
    }
    if (!existsSync(CPTESTFIXTURE_EXE)) {
      skipReason = `cptestfixture binary not found at ${CPTESTFIXTURE_EXE}`;
      return;
    }

    workDir = mkdtempSync(join(tmpdir(), "rmt-default-ttl-p23-"));

    // ── cptestfixture ────────────────────────────────────────────────────────────────────────────
    cpProc = spawn(CPTESTFIXTURE_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${CP_PORT}`,
        CP_FIXTURE_GRANT_SEED: FIXTURE_GRANT_SEED,
        CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        CP_SIGNALING_URL: SIGNALING_WS,
      },
    });

    await new Promise<void>((res, rej) => {
      let buf = "";
      const timeout = setTimeout(() => rej(new Error("cptestfixture did not print FIXTURE_READY within 30s")), 30_000);
      cpProc!.stdout?.on("data", (d: Buffer) => {
        buf += d.toString();
        process.stdout.write(`[cp-p23] ${d}`);
        const line = buf.split("\n").find((l) => l.startsWith("FIXTURE_READY "));
        if (line) {
          clearTimeout(timeout);
          try {
            fixtureCfg = JSON.parse(line.slice("FIXTURE_READY ".length)) as FixtureConfig;
            res();
          } catch (e) {
            rej(new Error(`FIXTURE_READY JSON parse failed: ${e}`));
          }
        }
      });
      cpProc!.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp-p23:err] ${d}`));
    });

    if (!fixtureCfg) throw new Error("cptestfixture: no fixture config parsed");
    grantPubkey = fixtureCfg.grant_issuer_pubkey;
    tenantId = fixtureCfg.tenant_id;
    console.log(`[p23] fixture ready — tenant=${tenantId} grant_issuer_pubkey=${grantPubkey}`);

    if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`, 500), 15_000))) {
      throw new Error(`cptestfixture did not start serving on :${CP_PORT}`);
    }

    const adminSess = await loginToCP(tenantId, fixtureCfg.admin_email, fixtureCfg.admin_password);

    // Enrollment token (admin-authenticated).
    const tokenBody = await fetch(`${CP_BASE}/enrollment-tokens`, {
      method: "POST",
      headers: authHeaders(adminSess),
      body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
    }).then((r) => r.json()) as { token?: string };
    const enrollToken = tokenBody.token;
    if (!enrollToken) throw new Error("POST /enrollment-tokens returned no token");
    console.log(`[p23] enrollment token minted`);

    // Enroll the agent.
    const configPath = join(workDir, "agent-config.json");
    keyPath = join(workDir, "agent-identity.key");
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
        ["enroll", "--control-plane-url", CP_BASE, "--token", enrollToken,
         "--name", "E2E-DefaultTTL-P23", "--config", configPath],
        { timeout: 30_000 },
        (err) => (err ? rej(err) : res()),
      )
    );
    const cfg = JSON.parse(readFileSync(configPath, "utf8")) as {
      device_id?: string;
      tenant_id?: string;
    };
    deviceId = cfg.device_id ?? "";
    if (!deviceId) throw new Error("enrollment did not write device_id into config");
    console.log(`[p23] enrolled device=${deviceId} tenant=${tenantId}`);

    // ── Signaling — NO --heartbeat-ttl override → server default 30 s ───────────────────────────
    // Default: read timeout = 2 × 30 s = 60 s.
    // The agent heartbeats every 10 s, so it will send ≥ 3 heartbeats in the 32 s boundary window.
    sigProc = spawn(
      SIGNALING_EXE,
      ["-addr", `127.0.0.1:${SIG_PORT}`],
      // NOTE: --heartbeat-ttl is deliberately NOT passed.
      {
        cwd: SIGNALING_DIR,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          SIGNALING_TICKET_PUBKEY: grantPubkey,
          SIGNALING_DEVICE_IDENTITY_URL: CP_BASE,
          SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        },
      },
    );
    sigProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[sig-p23] ${d}`));
    sigProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[sig-p23:err] ${d}`));
    if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000))) {
      throw new Error(`signaling did not come up on :${SIG_PORT}`);
    }
    console.log(`[p23] signaling up — default TTL=30s (no override), read timeout=60s`);

    // ── Agent — RMT_LOG=debug to capture "heartbeat sent" debug messages ─────────────────────────
    let secureTestActive = false;
    let secureProfileBlocked = false;
    let agentStarted = false;
    let agentLogOffsetAtStart = 0;

    agentProc = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceId,
        "--identity", keyPath,
        ...(tenantId ? ["--tenant", tenantId] : []),
        "--signaling", SIGNALING_WS,
        "--grant-issuer", grantPubkey,
        "--fps", "10",
      ],
      {
        cwd: REPO,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          // Enable debug logging to capture heartbeat send evidence in agent log.
          RMT_LOG: "debug",
        },
      },
    );
    agentPid = agentProc.pid ?? 0;

    agentProc.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLog += s;
      process.stdout.write(`[agent-p23] ${s}`);
      if (s.includes("multi_session_capable=true")) agentStarted = true;
      if (s.includes("secure-test-harness mode")) secureTestActive = true;
      if (s.includes("secure profile BLOCKED")) secureProfileBlocked = true;
    });
    agentProc.stderr?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLog += s;
      process.stdout.write(`[agent-p23:err] ${s}`);
      if (s.includes("multi_session_capable=true")) agentStarted = true;
      if (s.includes("secure-test-harness mode")) secureTestActive = true;
      if (s.includes("secure profile BLOCKED")) secureProfileBlocked = true;
    });
    agentProc.on("exit", (code) => process.stdout.write(`[agent-p23] exited code=${code}\n`));

    if (!(await waitFor(async () => agentStarted || secureProfileBlocked, 12_000))) {
      throw new Error("agent did not report multi_session_capable=true or blocked within 12s");
    }

    if (secureProfileBlocked) {
      skipReason = "agent binary lacks secure-test feature — build with --features test-harness,secure-test";
      return;
    }
    if (!secureTestActive) {
      skipReason = "agent did not confirm secure-test-harness mode — check --grant-issuer handling";
      return;
    }

    // ── TTL BOUNDARY WAIT ────────────────────────────────────────────────────────────────────────
    //
    // Record the epoch when the agent first confirmed registration (multi_session_capable=true).
    // Then wait 32 s (> 1 × default TTL = 30 s). During this window the agent must heartbeat
    // at least 3 times (10 s interval) to keep its registry entry alive.
    //
    // This window is the core of the Pass23 validation: if --heartbeat-ttl 300 s were still set,
    // no heartbeats would be needed within 30 s. With the default 30 s TTL, the agent's 10 s
    // heartbeat is what keeps the registration alive. Counting the debug messages proves the
    // mechanism is active, and A/B successfully joining after this boundary proves the registry
    // entry is still live.
    registrationEpochMs = Date.now();
    agentLogOffsetAtStart = agentLog.length;
    console.log(`[p23] REGISTRATION EPOCH: ${registrationEpochMs} ms — entering 32 s TTL boundary wait`);
    console.log(`[p23] server heartbeat-TTL=30s  agent HEARTBEAT_INTERVAL=10s  read-timeout=60s`);
    console.log(`[p23] expect ≥ 3 "heartbeat sent" debug lines during the 32 s window`);

    await sleep(32_000);

    ttlBoundaryPassedMs = Date.now();
    const elapsed = ttlBoundaryPassedMs - registrationEpochMs;

    // Count heartbeat evidence in the agent log slice.
    const logSlice = agentLog.slice(agentLogOffsetAtStart);
    // The debug log line is: `signaling_mux: heartbeat sent device=...`
    const hbMatches = logSlice.match(/signaling_mux: heartbeat sent/g) ?? [];
    heartbeatsSentDuringWait = hbMatches.length;

    console.log(`[p23] TTL BOUNDARY PASSED: elapsed=${elapsed}ms`);
    console.log(`[p23] heartbeats sent during boundary window: ${heartbeatsSentDuringWait}`);
    console.log(`[p23] registration identity: device=${deviceId} tenant=${tenantId}`);

    // Hard assertion: at 10 s HEARTBEAT_INTERVAL, 32 s must produce ≥ 3 fires.
    // This makes the test genuinely falsify the heartbeat-mechanism claim rather than relying
    // solely on A/B join success as a proxy. If RMT_LOG=debug does not route to the captured
    // stream, this assertion catches the gap rather than silently producing vacuous evidence.
    // This is a HARD FAILURE — a skip would allow the test to pass with zero heartbeat evidence,
    // which is vacuous. Missing binary/browser failures are caught earlier as prerequisite skips.
    if (heartbeatsSentDuringWait < 3) {
      throw new Error(
        `heartbeat assertion FAILED: only ${heartbeatsSentDuringWait} "heartbeat sent" debug lines observed in 32 s window — expected ≥ 3 at 10 s interval. ` +
        `Check RMT_LOG=debug routing to agent stderr/stdout. ` +
        `The heartbeat mechanism is a release requirement; this is not a skip.`
      );
    }

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
    await stopProc(sigProc);
    await stopProc(cpProc);
    agentProc = null;
    sigProc = null;
    cpProc = null;
    if (workDir) {
      try { rmSync(workDir, { recursive: true, force: true }); } catch {}
      workDir = "";
    }
  });

  // ── pass23-end ───────────────────────────────────────────────────────────────────────────────
  //
  // Same as pass20-end from secure_live_transport_gate.spec.ts, with default TTL already validated
  // by the 32 s boundary wait in beforeAll.
  // Key codes: 203 (A pre-bind), 204 (B pre-bind), 205 (A post-end attempt), 206 (B positive).
  test(
    "pass23-end: default-TTL validated — Admin END A → A renewal 409, bounded A lease expiry, B continuous media+input",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(240_000);

      // Evidence header for this test.
      const agentBinHashEnd = await sha256File(AGENT_BIN);
      const sigBinHashEnd = await sha256File(SIGNALING_EXE);
      console.log(`\n[pass23-end] === DEFAULT TTL LIVE EVIDENCE ===`);
      console.log(`[pass23-end] agent_host.exe SHA-256:   ${agentBinHashEnd}`);
      console.log(`[pass23-end] signaling.exe SHA-256:    ${sigBinHashEnd}`);
      console.log(`[pass23-end] agent PID:                ${agentPid}`);
      console.log(`[pass23-end] device_id:                ${deviceId}`);
      console.log(`[pass23-end] registration epoch:       ${registrationEpochMs} ms`);
      console.log(`[pass23-end] TTL boundary passed:      ${ttlBoundaryPassedMs} ms (+${ttlBoundaryPassedMs - registrationEpochMs} ms elapsed)`);
      console.log(`[pass23-end] heartbeats sent in window:${heartbeatsSentDuringWait} (≥1 expected with RMT_LOG=debug)`);
      console.log(`[pass23-end] first A/B join timestamp: ${Date.now()} ms (>${ttlBoundaryPassedMs - registrationEpochMs}ms after registration)`);

      // ── Fresh sessions ────────────────────────────────────────────────────────────────────────
      const techASess = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);
      const adminSess = await loginToCP(tenantId, fixtureCfg!.admin_email, fixtureCfg!.admin_password);

      const bodyA = await mintTicket(techASess, deviceId);
      const bodyB = await mintTicket(techBSess, deviceId);

      const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessArec = (bodyA.session as { id?: string } | undefined);
      const sessBrec = (bodyB.session as { id?: string } | undefined);

      const ticketA = sigA?.ticket;
      const ticketB = sigB?.ticket;
      const sidA = sigA?.session_id ?? sessArec?.id ?? "";
      const sidB = sigB?.session_id ?? sessBrec?.id ?? "";

      if (!ticketA || !ticketB) throw new Error(`pass23-end: no tickets. A=${JSON.stringify(bodyA)} B=${JSON.stringify(bodyB)}`);
      if (!sidA || !sidB) throw new Error(`pass23-end: no session IDs. A=${sidA} B=${sidB}`);
      expect(sidA, "pass23-end: sidA must differ from sidB").not.toBe(sidB);

      console.log(`[pass23-end] sidA=${sidA} sidB=${sidB}`);

      // ── Open pages and wait for connected + video ─────────────────────────────────────────────
      // A/B join AFTER the 32 s TTL boundary — definitive proof that heartbeats kept registration alive.
      const joinTimestampMs = Date.now();
      console.log(`[pass23-end] A/B join at ${joinTimestampMs} ms, ${joinTimestampMs - registrationEpochMs} ms after registration epoch`);

      const pageA = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA));
      const pageB = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB));

      await Promise.all([
        waitForConnected(pageA, 30_000),
        waitForConnected(pageB, 30_000),
      ]);
      console.log("[pass23-end] A and B reached WebRTC connected — registration survived 32 s TTL boundary");

      await Promise.all([
        waitForVideo(pageA, "p23-end-techA"),
        waitForVideo(pageB, "p23-end-techB"),
      ]);
      console.log("[pass23-end] A and B independently receiving VP8 video — default-TTL heartbeat confirmed live");

      // ── Phase 1: Install initial signed leases ────────────────────────────────────────────────
      const leaseA1 = await fetchSessionPolicy(techASess, sidA);
      console.log(`[pass23-end] A: initial policy — expires_at_ms=${leaseA1.expires_at_ms}`);
      const aAck0 = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
      await pageA.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA1.signed);
      const aAckOk = await waitForNewControlMsgOfType(pageA, "SessionPolicyInstalled", aAck0, 15_000);
      expect(aAckOk, "pass23-end A: initial SessionPolicyInstalled ack must arrive").toBe(true);
      let aAckCount = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
      console.log(`[pass23-end] A: SessionPolicyInstalled ack confirmed (count=${aAckCount})`);

      const leaseB1 = await fetchSessionPolicy(techBSess, sidB);
      const bAck0 = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
      await pageB.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB1.signed);
      const bAckOk = await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bAck0, 15_000);
      expect(bAckOk, "pass23-end B: initial SessionPolicyInstalled ack must arrive").toBe(true);
      let bAckCount = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
      console.log(`[pass23-end] B: SessionPolicyInstalled ack confirmed (count=${bAckCount})`);

      // ── Phase 2: Pre-bind coordinator session IDs ─────────────────────────────────────────────
      const logBefore = agentLog.length;

      await pageA.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 203, down: true },
        });
      });
      let aSessionId = "";
      const aAdmitted = await waitFor(async () => {
        const delta = agentLog.slice(logBefore);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=203 first_holder=true/);
        if (m) { aSessionId = m[1]; return true; }
        return false;
      }, 8_000);
      expect(aAdmitted, "pass23-end A: key=203 must be admitted (first_holder=true)").toBe(true);
      console.log(`[pass23-end] A: pre-bind confirmed session=${aSessionId} key=203`);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 204, down: true },
        });
      });
      let bSessionId = "";
      const bAdmitted = await waitFor(async () => {
        const delta = agentLog.slice(logBefore);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=204 first_holder=true/);
        if (m) { bSessionId = m[1]; return true; }
        return false;
      }, 8_000);
      expect(bAdmitted, "pass23-end B: key=204 must be admitted (first_holder=true)").toBe(true);
      expect(bSessionId, "pass23-end: coordinator session IDs must be distinct").not.toBe(aSessionId);
      console.log(`[pass23-end] A session=${aSessionId} B session=${bSessionId} — DISTINCT`);

      await pageA.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 203, down: false },
        });
      });
      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 204, down: false },
        });
      });

      // ── Phase 3: Admin END A ──────────────────────────────────────────────────────────────────
      const endResult = await adminEndSession(adminSess, sidA);
      expect(endResult.status, "pass23-end: Admin POST /sessions/{sidA}/end must return 200").toBe(200);
      console.log(`[pass23-end] Admin END A: POST /sessions/${sidA}/end → ${endResult.status} 200 CONFIRMED`);

      // ── Phase 4: Verify A renewal → 409 ──────────────────────────────────────────────────────
      const renewAfterEnd = await fetchSessionPolicyRaw(techASess, sidA);
      expect(renewAfterEnd.status, `pass23-end: A renewal after admin END must return 409`).toBe(409);
      console.log(`[pass23-end] A renewal after admin END: ${renewAfterEnd.status} 409 CONFIRMED`);

      // ── Phase 5: Wait for A's lease expiry + 8 s allowance; keep B alive ─────────────────────
      const expiresAtMsA = leaseA1.expires_at_ms;
      const waitUntilMs = expiresAtMsA + 8_000;
      let bCurrentExpiry = leaseB1.expires_at_ms;

      console.log(`[pass23-end] A lease expires: ${expiresAtMsA} (now=${Date.now()}); waiting until ${waitUntilMs} (+8 s)`);

      while (Date.now() < waitUntilMs) {
        const msLeft = waitUntilMs - Date.now();
        const sleepMs = Math.min(10_000, msLeft > 1_000 ? msLeft : 1_000);
        await sleep(sleepMs);
        if (Date.now() >= waitUntilMs) break;
        if (bCurrentExpiry - Date.now() < 20_000 || waitUntilMs - Date.now() < 15_000) {
          const leaseBN = await fetchSessionPolicy(techBSess, sidB);
          await pageB.evaluate((sp) => {
            const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
            if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
            rmt.installSessionPolicy(sp);
          }, leaseBN.signed);
          const bRenewOk = await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bAckCount, 15_000);
          expect(bRenewOk, "pass23-end B: mid-wait renewal ack must arrive").toBe(true);
          bAckCount = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
          bCurrentExpiry = leaseBN.expires_at_ms;
          console.log(`[pass23-end] B: renewal OK — count=${bAckCount} expires_at_ms=${bCurrentExpiry}`);
        }
      }

      // ── Phase 6: Assert A teardown ────────────────────────────────────────────────────────────
      const aTornDown = await waitFor(async () => {
        return agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`);
      }, 20_000);
      expect(
        aTornDown,
        `pass23-end: agent log must contain [SESSION:TEARDOWN:DONE session=${aSessionId}] from offset`,
      ).toBe(true);
      console.log(`[pass23-end] [SESSION:TEARDOWN:DONE session=${aSessionId}] confirmed from offset (definitive)`);

      expect(
        agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
        `pass23-end: B session=${bSessionId} must NOT be torn down during A lease expiry window`,
      ).toBe(false);
      console.log(`[pass23-end] B session=${bSessionId} teardown absent — correct isolation`);

      const logAfterTeardown = agentLog.length;

      // Supplementary: A RTP frozen.
      await sleep(3_000);
      const rtpA_s1 = await pageA.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpA_s2 = await pageA.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpA_s2, `pass23-end A: RTP bytes must be frozen after teardown`).toBeLessThanOrEqual(rtpA_s1 + 5_000);
      console.log(`[pass23-end] A: RTP frozen snap1=${rtpA_s1} snap2=${rtpA_s2} (supplementary)`);

      // ── Phase 7: Assert B alive ───────────────────────────────────────────────────────────────
      const stateB = await pageB.evaluate(() =>
        (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
      );
      expect(stateB, `pass23-end B: must still be "connected" after A expired`).toBe("connected");

      const rtpB_s1 = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpB_s2 = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpB_s2, `pass23-end B: NEW inbound-RTP bytes must arrive after A teardown`).toBeGreaterThan(rtpB_s1);
      console.log(`[pass23-end] B: NEW video bytes confirmed (${rtpB_s1} → ${rtpB_s2})`);

      // ── Phase 8: Input isolation ──────────────────────────────────────────────────────────────
      const aPostEndSend = await pageA.evaluate(() => {
        try {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 205, down: true },
          });
          return "sent";
        } catch (e) {
          return `closed:${String(e)}`;
        }
      }).catch((e: unknown) => `eval-err:${String(e)}`);
      console.log(`[pass23-end] A post-end send outcome: ${aPostEndSend}`);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 206, down: true },
        });
      });

      const inputObs = Date.now() + 5_000;
      let bKey206Admitted = false;
      let aKey205AdmittedPostEnd = false;
      while (Date.now() < inputObs) {
        const delta = agentLog.slice(logAfterTeardown);
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${aSessionId} key=205`)) {
          aKey205AdmittedPostEnd = true;
        }
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${bSessionId} key=206`)) {
          bKey206Admitted = true;
        }
        await sleep(50);
      }
      expect(aKey205AdmittedPostEnd, `pass23-end A: key=205 must NOT be admitted after teardown`).toBe(false);
      expect(bKey206Admitted, `pass23-end B: key=206 must be admitted in same bounded window`).toBe(true);
      console.log(`[pass23-end] A: no ADMITTED_INPUT for key=205 after teardown — isolation confirmed`);
      console.log(`[pass23-end] B: ADMITTED_INPUT for key=206 confirmed — B session live`);

      expect(
        agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
        `pass23-end: B must NOT be torn down after input observation window`,
      ).toBe(false);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 206, down: false },
        });
      });

      // ── Summary ───────────────────────────────────────────────────────────────────────────────
      console.log("\n[pass23-end] PASS — default-TTL Admin END isolation evidence:");
      console.log(`  agent_host.exe SHA-256: ${agentBinHashEnd}`);
      console.log(`  signaling.exe SHA-256:  ${sigBinHashEnd}`);
      console.log(`  heartbeat-ttl flag:     NOT PASSED (server default 30 s)`);
      console.log(`  heartbeats in 32 s win: ${heartbeatsSentDuringWait}`);
      console.log(`  registration epoch:     ${registrationEpochMs} ms`);
      console.log(`  TTL boundary:           ${ttlBoundaryPassedMs} ms (+${ttlBoundaryPassedMs - registrationEpochMs} ms elapsed)`);
      console.log(`  first join at:          ${joinTimestampMs} ms (post-boundary)`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  sidA:                   ${sidA}`);
      console.log(`  sidB:                   ${sidB}`);
      console.log(`  A coordinator session:  ${aSessionId}  (key=203)`);
      console.log(`  B coordinator session:  ${bSessionId}  (key=204, distinct)`);
      console.log(`  A lease expires_at_ms:  ${expiresAtMsA}`);
      console.log(`  Admin END result:       200 CONFIRMED`);
      console.log(`  A renewal after END:    409 CONFIRMED`);
      console.log(`  A: TEARDOWN:DONE:       session=${aSessionId} confirmed from offset`);
      console.log(`  A: RTP frozen:          snap1=${rtpA_s1} snap2=${rtpA_s2}`);
      console.log(`  A: input isolation:     key=205 NOT admitted; send outcome=${aPostEndSend}`);
      console.log(`  B: state after A ends:  ${stateB}`);
      console.log(`  B: RTP bytes:           ${rtpB_s1} → ${rtpB_s2} (growing)`);
      console.log(`  B: input admitted:      key=206 ADMITTED_INPUT in full 5 s window\n`);

      await pageA.close();
      await pageB.close();
    },
  );

  // ── pass23-logout ────────────────────────────────────────────────────────────────────────────
  //
  // Identical to pass20-logout from secure_live_transport_gate.spec.ts, run here with the
  // default 30 s TTL. Key codes: 207 (A pre-bind), 208 (B pre-bind), 209 (A post-logout), 210 (B).
  test(
    "pass23-logout: default-TTL validated — A logout → A mint/renew 401, bounded A lease expiry, B independent media+input",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(240_000);

      // ── Fresh sessions ────────────────────────────────────────────────────────────────────────
      const techASess = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);

      const bodyA = await mintTicket(techASess, deviceId);
      const bodyB = await mintTicket(techBSess, deviceId);

      const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessArec = (bodyA.session as { id?: string } | undefined);
      const sessBrec = (bodyB.session as { id?: string } | undefined);

      const ticketA = sigA?.ticket;
      const ticketB = sigB?.ticket;
      const sidA = sigA?.session_id ?? sessArec?.id ?? "";
      const sidB = sigB?.session_id ?? sessBrec?.id ?? "";

      if (!ticketA || !ticketB) throw new Error(`pass23-logout: no tickets. A=${JSON.stringify(bodyA)} B=${JSON.stringify(bodyB)}`);
      if (!sidA || !sidB) throw new Error(`pass23-logout: no session IDs. A=${sidA} B=${sidB}`);
      expect(sidA, "pass23-logout: sidA must differ from sidB").not.toBe(sidB);

      console.log(`[pass23-logout] sidA=${sidA} sidB=${sidB}`);

      // ── Open pages and wait for connected + video ─────────────────────────────────────────────
      const pageA = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA));
      const pageB = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB));

      await Promise.all([
        waitForConnected(pageA, 30_000),
        waitForConnected(pageB, 30_000),
      ]);
      console.log("[pass23-logout] A and B reached WebRTC connected");

      await Promise.all([
        waitForVideo(pageA, "p23-logout-techA"),
        waitForVideo(pageB, "p23-logout-techB"),
      ]);
      console.log("[pass23-logout] A and B independently receiving VP8 video");

      // ── Phase 1: Install initial signed leases ────────────────────────────────────────────────
      const leaseA1 = await fetchSessionPolicy(techASess, sidA);
      console.log(`[pass23-logout] A: initial policy — expires_at_ms=${leaseA1.expires_at_ms}`);
      const aAck0 = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
      await pageA.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA1.signed);
      const aAckOk = await waitForNewControlMsgOfType(pageA, "SessionPolicyInstalled", aAck0, 15_000);
      expect(aAckOk, "pass23-logout A: initial SessionPolicyInstalled ack must arrive").toBe(true);
      const aAckCount = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
      console.log(`[pass23-logout] A: ack confirmed (count=${aAckCount})`);

      const leaseB1 = await fetchSessionPolicy(techBSess, sidB);
      const bAck0 = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
      await pageB.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB1.signed);
      const bAckOk = await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bAck0, 15_000);
      expect(bAckOk, "pass23-logout B: initial SessionPolicyInstalled ack must arrive").toBe(true);
      let bAckCount = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
      console.log(`[pass23-logout] B: ack confirmed (count=${bAckCount})`);

      // ── Phase 2: Pre-bind coordinator session IDs ─────────────────────────────────────────────
      const logBefore = agentLog.length;

      await pageA.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 207, down: true },
        });
      });
      let aSessionId = "";
      const aAdmitted = await waitFor(async () => {
        const delta = agentLog.slice(logBefore);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=207 first_holder=true/);
        if (m) { aSessionId = m[1]; return true; }
        return false;
      }, 8_000);
      expect(aAdmitted, "pass23-logout A: key=207 must be admitted (first_holder=true)").toBe(true);
      console.log(`[pass23-logout] A: pre-bind confirmed session=${aSessionId} key=207`);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 208, down: true },
        });
      });
      let bSessionId = "";
      const bAdmitted = await waitFor(async () => {
        const delta = agentLog.slice(logBefore);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=208 first_holder=true/);
        if (m) { bSessionId = m[1]; return true; }
        return false;
      }, 8_000);
      expect(bAdmitted, "pass23-logout B: key=208 must be admitted (first_holder=true)").toBe(true);
      expect(bSessionId, "pass23-logout: coordinator session IDs must be distinct").not.toBe(aSessionId);
      console.log(`[pass23-logout] A session=${aSessionId} B session=${bSessionId} — DISTINCT`);

      await pageA.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 207, down: false },
        });
      });
      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 208, down: false },
        });
      });

      // ── Phase 3: A logs out ───────────────────────────────────────────────────────────────────
      const logoutStatus = await logoutFromCP(techASess);
      expect(logoutStatus, "pass23-logout: POST /auth/logout must return 204").toBe(204);
      console.log(`[pass23-logout] A logout: ${logoutStatus} 204 CONFIRMED`);

      // ── Phase 4: Verify A mint → 401, A renewal → 401 ────────────────────────────────────────
      const mintAfterLogout = await fetch(`${CP_BASE}/sessions`, {
        method: "POST",
        headers: authHeaders(techASess),
        body: JSON.stringify({ machine_id: deviceId }),
      });
      expect(mintAfterLogout.status, "pass23-logout: A mint after logout must return 401").toBe(401);
      console.log(`[pass23-logout] A mint after logout: ${mintAfterLogout.status} 401 CONFIRMED`);

      const renewAfterLogout = await fetchSessionPolicyRaw(techASess, sidA);
      expect(renewAfterLogout.status, "pass23-logout: A renewal after logout must return 401").toBe(401);
      console.log(`[pass23-logout] A renewal after logout: ${renewAfterLogout.status} 401 CONFIRMED`);

      // ── Phase 5: Wait for A's lease expiry + 8 s; keep B alive ───────────────────────────────
      const expiresAtMsA = leaseA1.expires_at_ms;
      const waitUntilMs = expiresAtMsA + 8_000;
      let bCurrentExpiry = leaseB1.expires_at_ms;

      console.log(`[pass23-logout] A lease expires: ${expiresAtMsA}; waiting until ${waitUntilMs} (+8 s)`);

      while (Date.now() < waitUntilMs) {
        const msLeft = waitUntilMs - Date.now();
        const sleepMs = Math.min(10_000, msLeft > 1_000 ? msLeft : 1_000);
        await sleep(sleepMs);
        if (Date.now() >= waitUntilMs) break;
        if (bCurrentExpiry - Date.now() < 20_000 || waitUntilMs - Date.now() < 15_000) {
          const leaseBN = await fetchSessionPolicy(techBSess, sidB);
          await pageB.evaluate((sp) => {
            const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
            if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
            rmt.installSessionPolicy(sp);
          }, leaseBN.signed);
          const bRenewOk = await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bAckCount, 15_000);
          expect(bRenewOk, "pass23-logout B: mid-wait renewal ack must arrive").toBe(true);
          bAckCount = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
          bCurrentExpiry = leaseBN.expires_at_ms;
          console.log(`[pass23-logout] B: renewal OK — count=${bAckCount} expires_at_ms=${bCurrentExpiry}`);
        }
      }

      // ── Phase 6: Assert A teardown ────────────────────────────────────────────────────────────
      const aTornDown = await waitFor(async () => {
        return agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`);
      }, 20_000);
      expect(
        aTornDown,
        `pass23-logout: agent log must contain [SESSION:TEARDOWN:DONE session=${aSessionId}] from offset`,
      ).toBe(true);
      console.log(`[pass23-logout] [SESSION:TEARDOWN:DONE session=${aSessionId}] confirmed from offset`);

      expect(
        agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
        `pass23-logout: B session=${bSessionId} must NOT be torn down during A expiry window`,
      ).toBe(false);
      console.log(`[pass23-logout] B session=${bSessionId} teardown absent — correct isolation`);

      const logAfterTeardown = agentLog.length;

      // Supplementary: A RTP frozen.
      await sleep(3_000);
      const rtpA_s1 = await pageA.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpA_s2 = await pageA.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpA_s2, `pass23-logout A: RTP bytes must be frozen after teardown`).toBeLessThanOrEqual(rtpA_s1 + 5_000);
      console.log(`[pass23-logout] A: RTP frozen snap1=${rtpA_s1} snap2=${rtpA_s2} (supplementary)`);

      // ── Phase 7: Assert B alive ───────────────────────────────────────────────────────────────
      const stateB = await pageB.evaluate(() =>
        (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
      );
      expect(stateB, `pass23-logout B: must still be "connected" after A expired`).toBe("connected");

      const rtpB_s1 = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpB_s2 = await pageB.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpB_s2, `pass23-logout B: NEW inbound-RTP bytes must arrive after A teardown`).toBeGreaterThan(rtpB_s1);
      console.log(`[pass23-logout] B: NEW video bytes confirmed (${rtpB_s1} → ${rtpB_s2})`);

      // ── Phase 8: Input isolation ──────────────────────────────────────────────────────────────
      const aPostLogoutSend = await pageA.evaluate(() => {
        try {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 209, down: true },
          });
          return "sent";
        } catch (e) {
          return `closed:${String(e)}`;
        }
      }).catch((e: unknown) => `eval-err:${String(e)}`);
      console.log(`[pass23-logout] A post-logout send outcome: ${aPostLogoutSend}`);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 210, down: true },
        });
      });

      const inputObs = Date.now() + 5_000;
      let bKey210Admitted = false;
      let aKey209AdmittedPostLogout = false;
      while (Date.now() < inputObs) {
        const delta = agentLog.slice(logAfterTeardown);
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${aSessionId} key=209`)) {
          aKey209AdmittedPostLogout = true;
        }
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${bSessionId} key=210`)) {
          bKey210Admitted = true;
        }
        await sleep(50);
      }
      expect(aKey209AdmittedPostLogout, `pass23-logout A: key=209 must NOT be admitted after teardown`).toBe(false);
      expect(bKey210Admitted, `pass23-logout B: key=210 must be admitted in same bounded window`).toBe(true);
      console.log(`[pass23-logout] A: no ADMITTED_INPUT for key=209 — isolation confirmed`);
      console.log(`[pass23-logout] B: ADMITTED_INPUT for key=210 — B session live`);

      expect(
        agentLog.slice(logBefore).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
        `pass23-logout: B must NOT be torn down after input observation window`,
      ).toBe(false);

      await pageB.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 210, down: false },
        });
      });

      // ── Summary ───────────────────────────────────────────────────────────────────────────────
      const agentBinHashL = await sha256File(AGENT_BIN);
      const sigBinHashL = await sha256File(SIGNALING_EXE);
      console.log("\n[pass23-logout] PASS — default-TTL logout isolation evidence:");
      console.log(`  agent_host.exe SHA-256: ${agentBinHashL}`);
      console.log(`  signaling.exe SHA-256:  ${sigBinHashL}`);
      console.log(`  heartbeat-ttl flag:     NOT PASSED (server default 30 s)`);
      console.log(`  heartbeats in 32 s win: ${heartbeatsSentDuringWait}`);
      console.log(`  registration epoch:     ${registrationEpochMs} ms`);
      console.log(`  TTL boundary:           ${ttlBoundaryPassedMs} ms (+${ttlBoundaryPassedMs - registrationEpochMs} ms elapsed)`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  sidA:                   ${sidA}`);
      console.log(`  sidB:                   ${sidB}`);
      console.log(`  A coordinator session:  ${aSessionId}  (key=207)`);
      console.log(`  B coordinator session:  ${bSessionId}  (key=208, distinct)`);
      console.log(`  A lease expires_at_ms:  ${expiresAtMsA}`);
      console.log(`  A logout result:        204 CONFIRMED`);
      console.log(`  A mint after logout:    401 CONFIRMED`);
      console.log(`  A renewal after logout: 401 CONFIRMED`);
      console.log(`  A: TEARDOWN:DONE:       session=${aSessionId} confirmed from offset`);
      console.log(`  A: RTP frozen:          snap1=${rtpA_s1} snap2=${rtpA_s2}`);
      console.log(`  A: input isolation:     key=209 NOT admitted; send outcome=${aPostLogoutSend}`);
      console.log(`  B: state after A ends:  ${stateB}`);
      console.log(`  B: RTP bytes:           ${rtpB_s1} → ${rtpB_s2} (growing)`);
      console.log(`  B: input admitted:      key=210 ADMITTED_INPUT in full 5 s window\n`);

      await pageA.close();
      await pageB.close();
    },
  );
});
