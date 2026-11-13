/**
 * STRICT REPLAY GATE — pass34 live end-to-end test.
 *
 * Proves the full cross-instance replay-refusal chain with a shared real CP ledger:
 *
 *   - cptestfixture (real SessionAuthenticator + InMemoryTicketRedemptionStore)
 *   - Two independent signaling instances (SIG1:8193, SIG2:8194), both in
 *     SIGNALING_STRICT_TICKET_REDEMPTION=1 (fail-closed posture)
 *   - One enrolled device; two agent processes sharing the same identity, each
 *     connecting to its own signaling instance.
 *   - A thin HTTP proxy (port 8195) sits between signaling and CP for the
 *     redemption endpoint only — records CP response codes and can simulate outage.
 *   - Tickets are minted via real login + POST /sessions (no local fabrication for
 *     the primary flow).
 *
 * Test scenarios (serial, shared state):
 *
 *   T1: first CP-signed ticket admits at SIG1, VP8 video flows.
 *   T2: replay same ticket at SIG2 → proxy records CP 409, SIG1 stream keeps growing.
 *   T3: fresh CP-signed ticket at SIG2 → admitted, VP8 video flows (per-ticket ledger).
 *   T4: proxy outage (503 for redemption) → strict SIG1 refuses new admission,
 *       logs ERROR (not WARNING), no fail-open.
 *
 * Architecture note — same-device dual registration:
 *   Two agent_host processes share one enrolled identity (same device_id + key file)
 *   connecting to two separate signaling instances.  Each instance has its own in-memory
 *   registry; the CP identity store is read-only after enrollment and is shared via the
 *   proxy.  If the agent binary prohibits two simultaneous instances (singleton lock or
 *   OS-level exclusion), beforeAll throws a descriptive error naming the exact seam rather
 *   than bypassing auth.
 *
 * Ports (isolated from all other specs):
 *   CP=8192  SIG1=8193  SIG2=8194  Proxy=8195
 *
 * No production edits.  No skips — missing prerequisites hard-fail.
 */

import {
  test,
  expect,
  chromium,
  type Browser,
  type Page,
} from "@playwright/test";
import {
  spawn,
  execFile,
  type ChildProcess,
} from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  rmSync,
  createReadStream,
} from "node:fs";
import * as http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID, createHash } from "node:crypto";
import { stopProc } from "./devcp";

// ── Path resolution ────────────────────────────────────────────────────────────

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

// ── Ports (no overlap with any other spec) ─────────────────────────────────────

const CP_PORT = 8192;
const SIG1_PORT = 8193;
const SIG2_PORT = 8194;
const PROXY_PORT = 8195;

const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const PROXY_BASE = `http://127.0.0.1:${PROXY_PORT}`;
const SIG1_WS = `ws://127.0.0.1:${SIG1_PORT}/ws`;
const SIG2_WS = `ws://127.0.0.1:${SIG2_PORT}/ws`;

// Fixed grant-issuer seed — unique to pass34, not used by any other spec.
const FIXTURE_GRANT_SEED =
  "4444444444444444444444444444444444444444444444444444444444444444";
const DEVICE_IDENTITY_TOKEN =
  "e2e-strict-replay-pass34-device-identity-token-4444abcdef";

// ── Small utilities ────────────────────────────────────────────────────────────

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

function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const hash = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (d) => hash.update(d));
    s.on("end", () => res(hash.digest("hex")));
    s.on("error", rej);
  });
}

function encodeTicket(t: unknown): string {
  return Buffer.from(JSON.stringify(t), "utf8").toString("base64url");
}

// ── Redemption proxy ───────────────────────────────────────────────────────────

interface RedemptionProxy {
  /** Ordered list of HTTP status codes the CP returned for redemption calls. */
  readonly redemptionStatuses: number[];
  /**
   * When true, redemption calls return 503 immediately without forwarding.
   * Identity and all other endpoints are always forwarded.
   */
  setOutage(v: boolean): void;
  stop(): Promise<void>;
}

/**
 * Start a thin HTTP proxy on proxyPort that forwards everything to CP at cpPort.
 * The redemption endpoint (POST /internal/session-tickets/redeem) is interceptable:
 *   - In normal mode: forwarded; CP response status is recorded in redemptionStatuses.
 *   - In outage mode: returns 503 immediately; other paths still forward normally.
 */
async function startRedemptionProxy(
  cpPort: number,
  proxyPort: number,
): Promise<RedemptionProxy> {
  let outage = false;
  const redemptionStatuses: number[] = [];

  const server = http.createServer((req, res) => {
    const isRedemption =
      req.method === "POST" &&
      req.url === "/internal/session-tickets/redeem";

    if (isRedemption && outage) {
      redemptionStatuses.push(503);
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("redemption outage simulated by pass34 proxy");
      return;
    }

    // Forward headers, replacing host so the CP sees the correct value.
    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.toLowerCase() !== "host") {
        headers[k] = v as string | string[];
      }
    }

    const proxyReq = http.request(
      {
        hostname: "127.0.0.1",
        port: cpPort,
        path: req.url ?? "/",
        method: req.method ?? "GET",
        headers,
      },
      (proxyRes) => {
        if (isRedemption) {
          const status = proxyRes.statusCode ?? 0;
          redemptionStatuses.push(status);
          process.stdout.write(
            `[proxy-p34] redemption → CP ${status}\n`,
          );
        }
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      },
    );

    proxyReq.on("error", (err) => {
      process.stderr.write(`[proxy-p34] upstream error: ${err.message}\n`);
      if (!res.headersSent) res.writeHead(502);
      res.end(`upstream error: ${err.message}`);
    });

    req.pipe(proxyReq);
  });

  await new Promise<void>((res, rej) => {
    server.listen(proxyPort, "127.0.0.1", () => res());
    server.on("error", rej);
  });

  return {
    redemptionStatuses,
    setOutage: (v) => { outage = v; },
    stop: () =>
      new Promise<void>((res) =>
        server.close(() => res()),
      ),
  };
}

// ── Control-plane auth helpers ─────────────────────────────────────────────────

interface CPSession {
  sessionCookie: string;
  csrfToken: string;
  userID: string;
}

async function loginToCP(
  tenantID: string,
  email: string,
  password: string,
): Promise<CPSession> {
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

  const setCookies: string[] =
    typeof (r.headers as unknown as { getSetCookie?: () => string[] })
      .getSetCookie === "function"
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
  return { sessionCookie, csrfToken, userID };
}

function authHeaders(sess: CPSession): Record<string, string> {
  return {
    "content-type": "application/json",
    "cookie": `cp_session=${sess.sessionCookie}; rmt_csrf=${sess.csrfToken}`,
    "x-csrf-token": sess.csrfToken,
  };
}

async function mintTicket(
  sess: CPSession,
  machineId: string,
): Promise<Record<string, unknown>> {
  const r = await fetch(`${CP_BASE}/sessions`, {
    method: "POST",
    headers: authHeaders(sess),
    body: JSON.stringify({ machine_id: machineId }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /sessions → ${r.status}: ${text}`);
  return JSON.parse(text) as Record<string, unknown>;
}

// ── Browser / harness helpers ──────────────────────────────────────────────────

type InboundStats = { bytesReceived?: number; packetsReceived?: number } | null;

async function openHarnessPage(
  browser: Browser,
  sigWs: string,
  deviceId: string,
  ticketB64?: string,
): Promise<Page> {
  const page = await browser.newPage();
  page.on("console", (m) =>
    process.stdout.write(`[page:${m.type()}] ${m.text()}\n`),
  );
  let url = `${HARNESS_BASE}?url=${encodeURIComponent(sigWs)}&device=${deviceId}`;
  if (ticketB64) url += `&ticket=${ticketB64}`;
  await page.goto(url);
  return page;
}

async function waitForConnected(page: Page, timeoutMs = 30_000): Promise<void> {
  await page.evaluate(
    (ms) => {
      const rmt = (
        window as unknown as { rmt?: { connected: Promise<void> } }
      ).rmt;
      if (!rmt)
        return Promise.reject(new Error("harness not loaded (window.rmt absent)"));
      return Promise.race([
        rmt.connected,
        new Promise<never>((_, rej) =>
          setTimeout(
            () => rej(new Error(`waitForConnected timed out after ${ms}ms`)),
            ms,
          ),
        ),
      ]);
    },
    timeoutMs,
  );
}

async function waitForVideo(
  page: Page,
  label: string,
  timeoutMs = 25_000,
): Promise<void> {
  let inbound: InboundStats = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (
          window as unknown as {
            rmt?: { inboundVideo: () => Promise<InboundStats> };
          }
        ).rmt;
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
  console.log(
    `[p34:${label}] inbound-rtp video: bytesReceived=${b} packetsReceived=${p}`,
  );
  expect(b, `${label}: bytesReceived must be > 0`).toBeGreaterThan(0);
  expect(p, `${label}: packetsReceived must be > 0`).toBeGreaterThan(0);
}

/** Read instantaneous inbound video bytes from a harness page (0 if unavailable). */
async function getInboundBytes(page: Page): Promise<number> {
  return page.evaluate(async () => {
    const r = (
      window as unknown as {
        rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> };
      }
    ).rmt;
    if (!r) return 0;
    const s = await r.inboundVideo();
    return s?.bytesReceived ?? 0;
  });
}

// ── Raw WebSocket probe (Node.js-side, not browser-side) ──────────────────────

interface WsProbe {
  send(msg: unknown): void;
  /** Resolve once a message of `type` arrives, or null after timeoutMs. */
  await(type: string, timeoutMs?: number): Promise<Record<string, unknown> | null>;
  close(): void;
}

async function probeWS(url: string): Promise<WsProbe> {
  const ws = new WebSocket(url);
  const msgs: Record<string, unknown>[] = [];
  let closed = false;
  ws.onmessage = (e) =>
    msgs.push(JSON.parse(String(e.data)) as Record<string, unknown>);
  ws.onclose = () => { closed = true; };
  await new Promise<void>((res, rej) => {
    ws.onopen = () => res();
    ws.onerror = () =>
      rej(new Error(`probeWS: failed to open WebSocket to ${url}`));
  });
  const find = (type: string) => msgs.find((m) => m.type === type);
  return {
    send: (m) => ws.send(JSON.stringify(m)),
    await: async (type, timeoutMs = 8_000) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline && !closed) {
        const found = find(type);
        if (found) return found;
        await sleep(50);
      }
      return find(type) ?? null;
    },
    close: () => ws.close(),
  };
}

// ── Fixture config ─────────────────────────────────────────────────────────────

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

// ── Suite state ────────────────────────────────────────────────────────────────

let cpProc: ChildProcess | null = null;
let sig1Proc: ChildProcess | null = null;
let sig2Proc: ChildProcess | null = null;
let agent1Proc: ChildProcess | null = null;
let agent2Proc: ChildProcess | null = null;
let browser: Browser | null = null;
let proxy: RedemptionProxy | null = null;

let fixtureCfg: FixtureConfig | null = null;
let device = "";
let keyPath = "";
let tenantId = "";
let grantPubkey = "";
let techASess: CPSession | null = null;

let sig1Log = "";
let sig2Log = "";
let agentLog1 = "";
let agentLog2 = "";
let workDir = "";

/** Evidence lines accumulated for the final report. */
const evidence: string[] = [];

/** The ticket minted in T1, replayed in T2. Set by T1, read by T2. */
let firstTicket: unknown = null;
/** The harness page from T1 (SIG1 session). Checked in T2 for stream continuity. */
let pageA: Page | null = null;

// ── Test suite ─────────────────────────────────────────────────────────────────

test.describe("Strict replay gate — pass34 live", () => {
  // Serial: each test shares state set by the previous one.
  test.describe.configure({ mode: "serial" });

  // ── Setup ────────────────────────────────────────────────────────────────────

  test.beforeAll(async () => {
    test.setTimeout(300_000);

    // Hard-fail on missing binaries: a missing binary is a build defect, not a skip.
    for (const [label, path] of [
      ["agent_host.exe", AGENT_BIN],
      ["signaling.exe", SIGNALING_EXE],
      ["cptestfixture.exe", CPTESTFIXTURE_EXE],
    ] as const) {
      if (!existsSync(path)) {
        throw new Error(
          `[p34] prerequisite missing: ${label} not found at ${path}. ` +
            `Build instructions: cargo build --features test-harness,secure-test (agent); ` +
            `go build (signaling, cptestfixture). A missing binary is a test failure, not a skip.`,
        );
      }
    }

    workDir = mkdtempSync(join(tmpdir(), "rmt-replay-p34-"));

    // ── 1. Start cptestfixture ───────────────────────────────────────────────

    cpProc = spawn(CPTESTFIXTURE_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${CP_PORT}`,
        CP_FIXTURE_GRANT_SEED: FIXTURE_GRANT_SEED,
        CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        CP_SIGNALING_URL: SIG1_WS,
      },
    });

    await new Promise<void>((res, rej) => {
      let buf = "";
      const timeout = setTimeout(
        () => rej(new Error("[p34] cptestfixture did not emit FIXTURE_READY within 30s")),
        30_000,
      );
      cpProc!.stdout?.on("data", (d: Buffer) => {
        buf += d.toString();
        process.stdout.write(`[cp-p34] ${d}`);
        const line = buf.split("\n").find((l) => l.startsWith("FIXTURE_READY "));
        if (line) {
          clearTimeout(timeout);
          try {
            fixtureCfg = JSON.parse(
              line.slice("FIXTURE_READY ".length),
            ) as FixtureConfig;
            res();
          } catch (e) {
            rej(new Error(`[p34] FIXTURE_READY JSON parse failed: ${e}`));
          }
        }
      });
      cpProc!.stderr?.on("data", (d: Buffer) =>
        process.stdout.write(`[cp-p34:err] ${d}`),
      );
    });

    if (!fixtureCfg) throw new Error("[p34] no fixture config after FIXTURE_READY");
    grantPubkey = fixtureCfg.grant_issuer_pubkey;
    tenantId = fixtureCfg.tenant_id;
    console.log(
      `[p34] fixture ready — tenant=${tenantId} pubkey=${grantPubkey}`,
    );

    if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`, 500), 15_000))) {
      throw new Error(`[p34] cptestfixture not reachable on :${CP_PORT}`);
    }

    // ── 2. Start redemption proxy ────────────────────────────────────────────

    proxy = await startRedemptionProxy(CP_PORT, PROXY_PORT);
    console.log(`[p34] redemption proxy listening on :${PROXY_PORT} → CP :${CP_PORT}`);

    // ── 3. Start SIG1 (strict mode, via proxy) ───────────────────────────────

    const sigEnv = {
      ...process.env,
      SIGNALING_TICKET_PUBKEY: grantPubkey,
      SIGNALING_DEVICE_IDENTITY_URL: PROXY_BASE,
      SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      SIGNALING_STRICT_TICKET_REDEMPTION: "1",
    };

    sig1Proc = spawn(
      SIGNALING_EXE,
      ["-addr", `127.0.0.1:${SIG1_PORT}`, "--heartbeat-ttl", "300s"],
      { cwd: SIGNALING_DIR, stdio: ["ignore", "pipe", "pipe"], env: sigEnv },
    );
    const capSig = (tag: string, store: { val: string }) => (d: Buffer) => {
      const s = d.toString();
      store.val += s;
      process.stdout.write(`[${tag}] ${s}`);
    };
    const sig1Store = { val: "" };
    sig1Proc.stdout?.on("data", capSig("sig1-p34", sig1Store));
    sig1Proc.stderr?.on("data", capSig("sig1-p34:err", sig1Store));

    sig2Proc = spawn(
      SIGNALING_EXE,
      ["-addr", `127.0.0.1:${SIG2_PORT}`, "--heartbeat-ttl", "300s"],
      { cwd: SIGNALING_DIR, stdio: ["ignore", "pipe", "pipe"], env: sigEnv },
    );
    const sig2Store = { val: "" };
    sig2Proc.stdout?.on("data", capSig("sig2-p34", sig2Store));
    sig2Proc.stderr?.on("data", capSig("sig2-p34:err", sig2Store));

    if (!(await waitFor(() => wsReachable(SIG1_WS, 500), 12_000))) {
      throw new Error(`[p34] SIG1 did not come up on :${SIG1_PORT}`);
    }
    if (!(await waitFor(() => wsReachable(SIG2_WS, 500), 12_000))) {
      throw new Error(`[p34] SIG2 did not come up on :${SIG2_PORT}`);
    }

    // Capture log references via closure-captured stores (updated live).
    Object.defineProperty(
      { get sig1Log() { return sig1Store.val; } },
      "sig1Log",
      { get: () => sig1Store.val },
    );
    // Use module-level vars for log access in tests via a periodic sync.
    // Simpler: sync the stores into module vars before each assertion.
    const syncLogs = () => {
      sig1Log = sig1Store.val;
      sig2Log = sig2Store.val;
    };
    // Store syncer so tests can call it.
    (globalThis as unknown as Record<string, unknown>)["__p34SyncLogs"] = syncLogs;

    // Verify strict mode markers (no insecure warnings).
    await sleep(500); // let startup messages flush
    syncLogs();
    if (sig1Log.includes("WARNING: -insecure")) {
      throw new Error("[p34] SIG1 started with insecure flag — strict mode not active");
    }
    if (sig2Log.includes("WARNING: -insecure")) {
      throw new Error("[p34] SIG2 started with insecure flag — strict mode not active");
    }

    // ── 4. Admin login + enrollment token ────────────────────────────────────

    const adminSess = await loginToCP(
      tenantId,
      fixtureCfg.admin_email,
      fixtureCfg.admin_password,
    );
    const tokenBody = (await fetch(`${CP_BASE}/enrollment-tokens`, {
      method: "POST",
      headers: authHeaders(adminSess),
      body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
    }).then((r) => r.json())) as { token?: string };
    const enrollToken = tokenBody.token;
    if (!enrollToken)
      throw new Error("[p34] POST /enrollment-tokens returned no token");

    // ── 5. Enroll one device ─────────────────────────────────────────────────

    const configPath = join(workDir, "agent-config.json");
    keyPath = join(workDir, "agent-identity.key");
    writeFileSync(
      configPath,
      JSON.stringify({
        signaling_url: SIG1_WS,
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
          "--name", "E2E-StrictReplay-P34",
          "--config", configPath,
        ],
        { timeout: 30_000 },
        (err) => (err ? rej(err) : res()),
      ),
    );
    const cfg = JSON.parse(readFileSync(configPath, "utf8")) as {
      device_id?: string;
      tenant_id?: string;
    };
    device = cfg.device_id ?? "";
    if (!device) throw new Error("[p34] enrollment did not write device_id");
    console.log(`[p34] enrolled device=${device} tenant=${tenantId}`);

    // ── 6. Start Agent1 (same identity → SIG1) ───────────────────────────────

    const agentArgs = (sigWs: string) => [
      "multi-stream",
      "--synthetic",
      "--device", device,
      "--identity", keyPath,
      "--signaling", sigWs,
      "--grant-issuer", grantPubkey,
      "--fps", "10",
      ...(tenantId ? ["--tenant", tenantId] : []),
    ];

    let agent1Started = false;
    let agent1Blocked = false;
    agent1Proc = spawn(AGENT_BIN, agentArgs(SIG1_WS), {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const capAgent =
      (
        tag: string,
        store: { val: string },
        started: { val: boolean },
        blocked: { val: boolean },
      ) =>
      (d: Buffer) => {
        const s = d.toString();
        store.val += s;
        process.stdout.write(`[${tag}] ${s}`);
        if (s.includes("multi_session_capable=true")) started.val = true;
        if (s.includes("secure profile BLOCKED")) blocked.val = true;
      };
    const a1Log = { val: "" };
    const a1Started = { val: false };
    const a1Blocked = { val: false };
    agent1Proc.stdout?.on("data", capAgent("agent1-p34", a1Log, a1Started, a1Blocked));
    agent1Proc.stderr?.on(
      "data",
      capAgent("agent1-p34:err", a1Log, a1Started, a1Blocked),
    );
    agent1Proc.on("exit", (code) =>
      process.stdout.write(`[agent1-p34] exited code=${code}\n`),
    );

    if (!(await waitFor(async () => a1Started.val || a1Blocked.val, 12_000))) {
      throw new Error(
        "[p34] agent1 did not register at SIG1 within 12s " +
          "(checked for 'multi_session_capable=true' in log)",
      );
    }
    if (a1Blocked.val) {
      throw new Error(
        "[p34] agent1: secure-test feature not compiled into agent binary. " +
          "Build with: cargo build -p rmt-agent-windows --bin agent_host " +
          "--features test-harness,secure-test",
      );
    }
    agentLog1 = a1Log.val;

    // ── 7. Start Agent2 (same identity → SIG2) — dual-registration ──────────
    //
    // Concrete seam: if the agent binary enforces a singleton lock or OS-level
    // exclusion for the identity file, agent2 will fail to start or fail to
    // register.  The error below names this seam precisely rather than
    // bypassing auth.

    let agent2Blocked = false;
    agent2Proc = spawn(AGENT_BIN, agentArgs(SIG2_WS), {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const a2Log = { val: "" };
    const a2Started = { val: false };
    const a2Blocked = { val: false };
    agent2Proc.stdout?.on("data", capAgent("agent2-p34", a2Log, a2Started, a2Blocked));
    agent2Proc.stderr?.on(
      "data",
      capAgent("agent2-p34:err", a2Log, a2Started, a2Blocked),
    );
    agent2Proc.on("exit", (code) =>
      process.stdout.write(`[agent2-p34] exited code=${code}\n`),
    );

    if (!(await waitFor(async () => a2Started.val || a2Blocked.val, 14_000))) {
      agentLog2 = a2Log.val;
      throw new Error(
        "[p34] ARCHITECTURAL SEAM: agent2 did not register at SIG2 within 14s. " +
          "The agent binary may enforce a singleton lock on the identity key file, " +
          "or it may reject a second simultaneous connect from the same device identity. " +
          "Exact seam: two agent_host multi-stream processes sharing the same " +
          "--device / --identity connecting to separate signaling instances. " +
          "The dual-broker shared-ledger replay test requires two enrolled registrations " +
          "simultaneously active. Possible fix: enroll a second device, ensuring both " +
          "have the same device_id in the CP's InMemoryTicketRedemptionStore " +
          "(which is keyed by tenant_id + session_id, not device_id).",
      );
    }
    agent2Blocked = a2Blocked.val;
    if (agent2Blocked) {
      throw new Error(
        "[p34] agent2: secure-test feature not compiled — same as agent1 issue",
      );
    }
    agentLog2 = a2Log.val;

    await sleep(800); // settle registration

    // ── 8. TechA login for ticket minting ────────────────────────────────────

    techASess = await loginToCP(
      tenantId,
      fixtureCfg.tech_a_email,
      fixtureCfg.tech_a_password,
    );
    if (techASess.userID !== fixtureCfg.tech_a_id) {
      throw new Error(
        `[p34] TechA userID mismatch: got ${techASess.userID}, want ${fixtureCfg.tech_a_id}`,
      );
    }
    console.log(`[p34] TechA login OK — user_id=${techASess.userID}`);

    // ── 9. Browser ────────────────────────────────────────────────────────────

    const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
    try {
      browser = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
    } catch {
      try {
        browser = await chromium.launch({ headless: true, args: launchArgs });
      } catch (e) {
        throw new Error(`[p34] no usable browser: ${String(e)}`);
      }
    }

    // ── 10. Hash binaries for evidence ────────────────────────────────────────

    const [agentHash, sigHash, cpHash] = await Promise.all([
      sha256File(AGENT_BIN),
      sha256File(SIGNALING_EXE),
      sha256File(CPTESTFIXTURE_EXE),
    ]);
    evidence.push(`agent_host.exe SHA-256: ${agentHash}`);
    evidence.push(`signaling.exe SHA-256: ${sigHash}`);
    evidence.push(`cptestfixture.exe SHA-256: ${cpHash}`);
    evidence.push(`device_id: ${device}`);
    evidence.push(`tenant_id: ${tenantId}`);
    evidence.push(`grant_issuer_pubkey: ${grantPubkey}`);
    evidence.push(`SIG1 WS: ${SIG1_WS}`);
    evidence.push(`SIG2 WS: ${SIG2_WS}`);
    evidence.push(`proxy port: ${PROXY_PORT} → CP :${CP_PORT}`);
  });

  // ── Teardown ─────────────────────────────────────────────────────────────────

  test.afterAll(async () => {
    // Sync log stores before writing.
    const syncLogs =
      (globalThis as unknown as Record<string, unknown>)["__p34SyncLogs"];
    if (typeof syncLogs === "function") (syncLogs as () => void)();

    // Write report.
    const reportLines = [
      "# Strict Replay Gate — Pass34 Live Report",
      "",
      `Executed: ${new Date().toISOString()}`,
      "",
      "## Binaries and identifiers",
      ...evidence.map((e) => `- ${e}`),
      "",
      "## Scope",
      "- Real-auth cptestfixture (SessionAuthenticator, InMemoryTicketRedemptionStore)",
      "- Two signaling instances (SIG1:8193, SIG2:8194), both SIGNALING_STRICT_TICKET_REDEMPTION=1",
      "- One enrolled device; two agent processes (same identity, separate signaling connections)",
      "- Proxy (port 8195) records redemption response codes from CP and can simulate 503 outage",
      "- Tickets minted via authenticated POST /sessions (no local fabrication for primary flow)",
      "- T1: first CP-signed ticket admits at SIG1, VP8 video flows",
      "- T2: replay same ticket at SIG2 → proxy records CP 409, SIG1 stream still grows",
      "- T3: fresh CP-signed ticket at SIG2 → admitted, VP8 video flows (per-ticket not per-device)",
      "- T4: proxy outage → strict SIG1 refuses, logs ERROR (not WARNING), no fail-open",
      "",
      "## Proxy redemption log",
      `CP response codes for POST /internal/session-tickets/redeem: ${JSON.stringify(proxy?.redemptionStatuses ?? [])}`,
      "",
      "## SIG1 ERROR/WARNING lines",
      ...sig1Log
        .split("\n")
        .filter((l) => l.includes("ERROR") || l.includes("WARNING"))
        .map((l) => `  ${l}`),
      "",
      "## SIG2 ERROR/WARNING lines",
      ...sig2Log
        .split("\n")
        .filter((l) => l.includes("ERROR") || l.includes("WARNING"))
        .map((l) => `  ${l}`),
    ];

    try {
      writeFileSync(
        join(REPO, "strict-replay-pass34.md"),
        reportLines.join("\n"),
      );
      writeFileSync(
        join(REPO, "strict-replay-pass34-live.log"),
        [
          "=== SIG1 ===\n" + sig1Log,
          "=== SIG2 ===\n" + sig2Log,
          "=== agent1 ===\n" + agentLog1,
          "=== agent2 ===\n" + agentLog2,
        ].join("\n\n--- SEGMENT ---\n\n"),
      );
      console.log("[p34] report written: strict-replay-pass34.md + strict-replay-pass34-live.log");
    } catch (e) {
      console.error(`[p34] failed to write report: ${e}`);
    }

    // Close browser and pages.
    await browser?.close().catch(() => {});

    // Stop agent processes first (they hold SIG connections).
    await Promise.all([stopProc(agent2Proc), stopProc(agent1Proc)]);
    agent2Proc = null;
    agent1Proc = null;

    // Stop signaling.
    await Promise.all([stopProc(sig2Proc), stopProc(sig1Proc)]);
    sig2Proc = null;
    sig1Proc = null;

    // Stop proxy.
    await proxy?.stop().catch(() => {});
    proxy = null;

    // Stop CP last.
    await stopProc(cpProc);
    cpProc = null;

    // Cleanup temp dir.
    if (workDir) {
      try { rmSync(workDir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  // ── T1: first ticket admits and video flows at SIG1 ──────────────────────────

  test("P34-T1: first CP-signed ticket admits at SIG1, VP8 video flows", async () => {
    test.setTimeout(120_000);

    // Mint via real login + POST /sessions — no local ticket fabrication.
    const body = await mintTicket(techASess!, device);
    const sig = body.signaling as { ticket?: unknown; session_id?: string } | undefined;
    firstTicket = sig?.ticket;
    if (!firstTicket) {
      throw new Error(
        `[p34-T1] POST /sessions returned no ticket: ${JSON.stringify(body)}`,
      );
    }
    const sidA = sig?.session_id ?? "";
    console.log(`[p34-T1] ticket minted via TechA login: session_id=${sidA}`);
    evidence.push(`T1 session_id: ${sidA}`);

    const redemptionsBefore = proxy!.redemptionStatuses.length;

    pageA = await openHarnessPage(browser!, SIG1_WS, device, encodeTicket(firstTicket));
    await waitForConnected(pageA, 30_000);
    console.log("[p34-T1] WebRTC connected at SIG1");

    await waitForVideo(pageA, "T1-SIG1");
    console.log("[p34-T1] VP8 video flowing at SIG1 — first ticket admitted (CP 200)");

    // Proxy must have recorded exactly one new redemption call returning 200.
    const newStatuses = proxy!.redemptionStatuses.slice(redemptionsBefore);
    expect(
      newStatuses.length,
      "proxy must record exactly one redemption call for the first ticket",
    ).toBe(1);
    expect(
      newStatuses[0],
      "CP must return 200 (first use) for the first ticket",
    ).toBe(200);

    evidence.push(`T1 proxy status: ${newStatuses[0]} (200 = first use, expected)`);
    console.log("[p34-T1] proxy recorded CP 200 — first-use confirmed in shared ledger");
  });

  // ── T2: replay same ticket at SIG2 → CP 409, SIG1 stream grows ──────────────

  test(
    "P34-T2: replay same ticket at SIG2 → proxy records CP 409, SIG1 stream grows",
    async () => {
      test.setTimeout(60_000);

      // Record video bytes before the replay attempt (stream must grow while replay is pending).
      const bytesBefore = await getInboundBytes(pageA!);
      console.log(`[p34-T2] SIG1 inbound bytes before replay: ${bytesBefore}`);
      expect(bytesBefore, "T1 must have established a live stream before T2").toBeGreaterThan(0);

      const redemptionsBefore = proxy!.redemptionStatuses.length;

      // Probe SIG2: register as a controller (random UUID, no agent key), then replay ticket_A.
      // The controller's register_agent triggers a challenge in enforced mode; we do not answer
      // it — that is fine because connect_request is dispatched before authentication completes.
      const p2 = await probeWS(SIG2_WS);
      p2.send({
        type: "register_agent",
        device: randomUUID(),
        pubkey: "ed25519:p34-replay-controller",
        nat: "unknown",
        enrollment_token: null,
      });
      await sleep(300); // let register_agent reach dispatch
      p2.send({ type: "connect_request", target: device, ticket: firstTicket });

      const rej = await p2.await("rejected", 8_000);
      p2.close();

      // Replay must be rejected.
      expect(rej, "SIG2 must receive a rejected message for the replayed ticket").not.toBeNull();
      expect(
        rej!.reason,
        "replay rejection must be the generic opaque reason (not device-offline or busy)",
      ).toBe("connect request not authorized");

      // Causal proof: proxy must have recorded a 409 from CP.
      const newStatuses = proxy!.redemptionStatuses.slice(redemptionsBefore);
      expect(
        newStatuses.length,
        "proxy must record a redemption call for the replay attempt",
      ).toBeGreaterThanOrEqual(1);
      const replayStatus = newStatuses[newStatuses.length - 1];
      expect(
        replayStatus,
        "CP must return 409 for the replayed ticket — shared-ledger single-use enforcement",
      ).toBe(409);
      console.log(
        "[p34-T2] proxy recorded CP 409 — replay refused by shared ledger (causal 409 confirmed)",
      );

      // Wait for video to accumulate (agent streams at 10 FPS; stats update ~1/s).
      await sleep(2_500);

      // First stream must have grown during the replay attempt.
      const bytesAfter = await getInboundBytes(pageA!);
      console.log(
        `[p34-T2] SIG1 inbound bytes after replay: ${bytesAfter} (before=${bytesBefore})`,
      );
      expect(
        bytesAfter,
        "SIG1 stream must continue growing while replay is rejected at SIG2",
      ).toBeGreaterThan(bytesBefore);

      evidence.push(
        `T2 proxy statuses after replay: ${JSON.stringify(proxy!.redemptionStatuses)}`,
      );
      evidence.push(`T2 SIG1 stream growth: ${bytesBefore} → ${bytesAfter} bytes`);
      console.log("[p34-T2] SIG1 stream continuity confirmed — first session unaffected");
    },
  );

  // ── T3: fresh ticket at SIG2 → admits and video ──────────────────────────────

  test(
    "P34-T3: fresh CP-signed ticket at SIG2 → admitted and VP8 video flows",
    async () => {
      test.setTimeout(90_000);

      const redemptionsBefore = proxy!.redemptionStatuses.length;

      // Fresh ticket — new session_id, same device, same TechA.
      const body = await mintTicket(techASess!, device);
      const sig = body.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const freshTicket = sig?.ticket;
      if (!freshTicket) {
        throw new Error(
          `[p34-T3] POST /sessions (fresh) returned no ticket: ${JSON.stringify(body)}`,
        );
      }
      const sidB = sig?.session_id ?? "";
      console.log(`[p34-T3] fresh ticket minted: session_id=${sidB}`);
      evidence.push(`T3 fresh session_id: ${sidB}`);

      const pageB = await openHarnessPage(
        browser!,
        SIG2_WS,
        device,
        encodeTicket(freshTicket),
      );
      await waitForConnected(pageB, 30_000);
      console.log("[p34-T3] WebRTC connected at SIG2 with fresh ticket");

      await waitForVideo(pageB, "T3-SIG2");
      console.log("[p34-T3] VP8 video flowing at SIG2 — ledger is per-ticket, not per-device");

      // Proxy must have recorded 200 for the fresh ticket (not 409).
      const newStatuses = proxy!.redemptionStatuses.slice(redemptionsBefore);
      expect(
        newStatuses.length,
        "proxy must record a redemption call for the fresh ticket",
      ).toBeGreaterThanOrEqual(1);
      const freshStatus = newStatuses[newStatuses.length - 1];
      expect(
        freshStatus,
        "CP must return 200 for the fresh ticket (new session_id = new ledger entry)",
      ).toBe(200);
      console.log("[p34-T3] proxy recorded CP 200 — per-ticket ledger confirmed");

      evidence.push(`T3 proxy status for fresh ticket: ${freshStatus}`);

      await pageB.close().catch(() => {});
    },
  );

  // ── T4: strict mode + proxy outage → fail closed ─────────────────────────────

  test(
    "P34-T4: redemption proxy outage → strict SIG1 refuses (fail-closed), ERROR logged",
    async () => {
      test.setTimeout(60_000);

      // Mint a valid fresh ticket before simulating the outage.
      const body = await mintTicket(techASess!, device);
      const sig = body.signaling as { ticket?: unknown } | undefined;
      const outageTicket = sig?.ticket;
      if (!outageTicket) {
        throw new Error(
          `[p34-T4] POST /sessions (outage) returned no ticket: ${JSON.stringify(body)}`,
        );
      }
      console.log("[p34-T4] fresh ticket minted; activating proxy outage mode");

      // Sync logs before measuring the before-offset.
      const syncLogs =
        (globalThis as unknown as Record<string, unknown>)["__p34SyncLogs"];
      if (typeof syncLogs === "function") (syncLogs as () => void)();
      const logOffsetBefore = sig1Log.length;

      // Activate outage: redemption calls return 503; identity and all other endpoints still forward.
      proxy!.setOutage(true);

      try {
        // Probe SIG1 with the outage ticket.
        const pOut = await probeWS(SIG1_WS);
        pOut.send({
          type: "register_agent",
          device: randomUUID(),
          pubkey: "ed25519:p34-outage-controller",
          nat: "unknown",
          enrollment_token: null,
        });
        await sleep(300);
        pOut.send({ type: "connect_request", target: device, ticket: outageTicket });

        const outageRej = await pOut.await("rejected", 8_000);
        pOut.close();

        // Must be refused (fail-closed).
        expect(
          outageRej,
          "redemption outage must cause strict-mode rejection",
        ).not.toBeNull();
        expect(
          outageRej!.reason,
          "outage rejection must be the generic opaque reason",
        ).toBe("connect request not authorized");
        console.log("[p34-T4] connect_request rejected — fail-closed confirmed");

        // Allow the log line to flush to the capture buffer.
        await sleep(800);
        if (typeof syncLogs === "function") (syncLogs as () => void)();
        const newSig1Log = sig1Log.slice(logOffsetBefore);

        // Strict mode logs ERROR for an unavailable ledger (never WARNING).
        expect(
          newSig1Log,
          "strict mode must log ERROR when the ledger returns 503",
        ).toContain("ERROR: session-ticket ledger unavailable");
        expect(
          newSig1Log,
          "strict mode must NOT emit a fail-open WARNING",
        ).not.toContain("WARNING: session-ticket ledger");

        console.log(
          "[p34-T4] SIG1 ERROR log confirmed; no fail-open WARNING — strict mode gate verified",
        );
        evidence.push("T4: fail-closed confirmed (ERROR log present, no WARNING)");
        evidence.push(
          `T4 proxy statuses at end: ${JSON.stringify(proxy!.redemptionStatuses)}`,
        );
      } finally {
        // Restore proxy to normal operation for clean shutdown.
        proxy!.setOutage(false);
      }
    },
  );
});
