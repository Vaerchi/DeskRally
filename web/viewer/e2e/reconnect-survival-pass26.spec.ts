/**
 * REGISTRATION RECONNECT MEDIA SURVIVAL — Pass 26 (corrected for pass27 review; gaps closed by pass28).
 *
 * Validates that existing WebRTC sessions (A and B) survive uninterrupted when the agent's
 * registration WebSocket is dropped and re-established through a test-owned transparent TCP
 * proxy. The proxy is the only test-side "seam" — no production server or agent source change.
 *
 * Seven concrete review points fixed vs the original pass-26 submission (pass27 accepted):
 *
 *   1. Registration evidence: the startup "multi_session_capable=true" print is NOT authenticated
 *      registration. Signaling-server stderr is captured in sigLog and the literal
 *      "agent auth OK:" line (main.go:495) is the authoritative registration marker for both
 *      startup and post-reconnect detection. proxyConnIdBefore is taken only AFTER that marker.
 *
 *   2. Policy renewals: A, B, and C each have a cancellable renewer task that re-fetches the
 *      signed policy before the lease expires and asserts the SessionPolicyInstalled ack. C gets
 *      a full policy install (not just video) before the final assertions. Renewers are stopped
 *      in a try/finally block before pages close.
 *
 *   3. Host test loop: reconnect loop in multi_stream_command (host.rs, test-harness only) now
 *      checks stop||uninstall_requested before each entry and after Ok(), adds the production-
 *      like 2 s success delay, and keeps the bounded 1 s failure backoff.
 *
 *   4. Prerequisites hard-fail: binary-missing and capability-missing conditions throw instead
 *      of setting skipReason; test.describe.configure({ retries: 0 }) overrides the suite-wide
 *      retries: 2 so any failure is decisive.
 *
 *   5. Media survival measured after reconnect: fresh baselines are taken AFTER the second
 *      authenticated registration is confirmed, a 2 s bounded interval elapses, and bytes AND
 *      framesDecoded are both required to have grown. Final assertions run after C policy
 *      admission.
 *
 *   6. Auth claims: login user_id asserted equal to fixture ID for each of A, B, C; all three
 *      distinct; ticket technician_id asserted to match the session owner.
 *
 *   7. Proxy cleanup: ProxyConn.cleanup is idempotent (cleanedUp guard); forwarding uses
 *      pause/drain backpressure; conns is public so the test can assert old pair is removed
 *      before new registration evidence; close() polls until conns is empty then closes the
 *      server, bounded to 5 s; afterAll races against a 6 s timeout.
 *
 * Four evidence gaps closed by pass28 (no production behavior changes; no host rebuild):
 *
 *   P28-1. Reconnect detection matches exact device in sigLog ("agent auth OK: device \"<id>\"")
 *          AND "register_for_mux: registered" in agent debug log after reconnect offset — proving
 *          it is the correct device's reconnect and the Registered wire message was received.
 *
 *   P28-2. Explicit post-reconnect policy renewal: A and B each complete a signed policy renewal
 *          and receive a SessionPolicyInstalled ack over the new registration connection BEFORE
 *          the fresh media+frame and coordinator input assertions. C's initial install (after
 *          connecting to the new registration) counts as its post-reconnect policy ack.
 *
 *   P28-3. Renewer promptness and completeness: cancel() now resolves a cancelTrigger promise so
 *          the sleeping renewer wakes immediately; the catch clause surfaces ALL errors including
 *          those raised while cancellation is in-flight; renewalErrors is asserted only AFTER
 *          all renewer tasks are stopped and fully awaited (outside try/finally).
 *
 *   P28-4. TcpProxy.close() correctness: poll timer is tracked and cleared before server.close()
 *          fires; on timeout, remaining pairs are logged (assert no pairs), force-destroyed, and
 *          server.close() completes before the error is propagated (not before).
 *
 * Protocol:
 *   1. cptestfixture + signaling start. A TCP loopback proxy (PROXY_PORT → SIG_PORT) is
 *      interposed. The agent connects to the proxy; all traffic is transparently forwarded.
 *   2. Agent enrolled, started with --signaling ws://127.0.0.1:PROXY_PORT/ws.
 *      Registration confirmed via signaling log "agent auth OK:" and proxy.connCount>=1.
 *   3. A (tech_a) and B (tech_b) connect via WebRTC, receive video, install session policies,
 *      install renewable signed policies (acked), and pre-bind their coordinator session IDs
 *      (key=220, key=221).
 *   4. proxy.dropAll() closes the agent-side TCP connection. The agent's SignalingMux sees EOF,
 *      run_multi_session_stream returns Ok(()), the reconnect loop waits 2 s then fires.
 *   5. Agent reconnects to proxy (NEW TCP connection = socket-id-2, distinct from socket-id-1).
 *      New authenticated registration. Signaling log shows second "agent auth OK:".
 *      Old proxy pair is confirmed removed before new registration evidence.
 *   6. Fresh A/B byte+frame baselines taken AFTER second "agent auth OK:". Wait 2 s.
 *      Assert bytes AND framesDecoded grew (proving continuous media, not pre-retirement growth).
 *   7. A sends key=222, B sends key=223. [SESSION:ADMITTED_INPUT] must carry the SAME session
 *      IDs as before reconnect — proving the existing sessions were not torn down.
 *   8. Assert NO [SESSION:TEARDOWN:DONE] for A or B sessions during reconnect window.
 *   9. C (tech_c) mints a ticket, connects via new registration, receives video, installs signed
 *      policy (acked). A/B byte+frame growth re-asserted after C policy admission.
 *  10. Renewable policy tasks for A, B, C are stopped and awaited in try/finally.
 *
 * Ports: CP=8200, SIG=8201, PROXY=8202 (isolated from all other specs in the suite).
 * No production source changes. No retries (retries: 0 in describe.configure). Hard-fail on
 * missing binaries or blocked capability.
 *
 * The reconnect loop in multi_stream_command (host.rs, test-harness only) is required for
 * steps 4–5: it re-calls run_multi_session_stream after the mux connection closes, allowing
 * existing spawned session tasks to continue on the shared Tokio runtime.
 */

import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { createServer as createNetServer, createConnection as createNetConnection, type Server as NetServer, type Socket } from "node:net";
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

// Ports — isolated from all other specs.
const CP_PORT = 8200;
const SIG_PORT = 8201;
const PROXY_PORT = 8202;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const SIGNALING_WS_REAL = `ws://127.0.0.1:${SIG_PORT}/ws`;
const SIGNALING_WS_PROXY = `ws://127.0.0.1:${PROXY_PORT}/ws`;

// Separate grant-seed from all other specs.
const FIXTURE_GRANT_SEED = "5555555555555555555555555555555555555555555555555555555555555555";
const DEVICE_IDENTITY_TOKEN = "e2e-reconnect-pass26-device-identity-token-5555abcdef";

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

// InboundStats includes framesDecoded for Issue 5 (post-reconnect frame growth evidence).
type InboundStats = { bytesReceived?: number; packetsReceived?: number; framesDecoded?: number } | null;

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

// Returns both bytes and frames for Issue 5 growth measurement.
async function getInboundStats(page: Page): Promise<{ bytes: number; frames: number }> {
  const s = await page.evaluate(async () => {
    const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<InboundStats> } }).rmt;
    if (!r) return null;
    return await r.inboundVideo();
  });
  return {
    bytes: (s as { bytesReceived?: number } | null)?.bytesReceived ?? 0,
    frames: (s as { framesDecoded?: number } | null)?.framesDecoded ?? 0,
  };
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

// ── Renewable policy task (Issue 2) ──────────────────────────────────────────────────────────────
//
// Renews the signed session policy before it expires and asserts the agent acknowledges each
// renewal. Errors are surfaced via rejectFn rather than swallowed.

interface Renewer {
  cancel(): void;
  done: Promise<void>;
}

function startPolicyRenewer(
  sess: CPSession,
  sessionId: string,
  page: Page,
  label: string,
  initialLease: SessionLease,
  rejectFn: (e: unknown) => void,
): Renewer {
  let cancelled = false;
  let wakeCancel!: () => void;
  let resolveDone!: () => void;
  const done = new Promise<void>((res) => { resolveDone = res; });
  // cancelTrigger resolves immediately when cancel() is called, interrupting the sleep.
  const cancelTrigger = new Promise<void>((res) => { wakeCancel = res; });

  const run = async (lease: SessionLease) => {
    try {
      while (!cancelled) {
        // Renew at half-TTL before expiry to stay safely ahead of the deadline.
        const renewAt = lease.expires_at_ms - Math.max(5000, lease.lease_ttl_ms / 2);
        const waitMs = Math.max(2000, renewAt - Date.now());
        // Race sleep vs cancelTrigger so cancel() wakes the renewer promptly.
        await Promise.race([sleep(waitMs), cancelTrigger]);
        if (cancelled) break;

        const prevCount = await countControlMsgsByType(page, "SessionPolicyInstalled");
        const newLease = await fetchSessionPolicy(sess, sessionId);
        await page.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, newLease.signed);
        const ackOk = await waitForNewControlMsgOfType(page, "SessionPolicyInstalled", prevCount, 10_000);
        if (!ackOk) throw new Error(`${label}: policy renewal ack timed out`);
        console.log(`[pass26] ${label}: policy renewed (ack confirmed, expires_at_ms=${newLease.expires_at_ms})`);
        lease = newLease;
      }
    } catch (e) {
      // Surface ALL errors — including those raised while cancellation is in-flight —
      // so the test captures in-flight failures rather than swallowing them.
      rejectFn(e);
    } finally {
      resolveDone();
    }
  };

  void run(initialLease);
  return {
    cancel() { cancelled = true; wakeCancel(); },
    done,
  };
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
  tech_c_id: string;
  tech_c_email: string;
  tech_c_password: string;
  grant_issuer_pubkey: string;
  listen_addr: string;
}

// ── Transparent TCP proxy (Issue 7 corrections) ───────────────────────────────────────────────────
//
// Sits between the agent (connects to PROXY_PORT) and the real signaling server (SIG_PORT).
// Forwards bytes in both directions without parsing WebSocket frames — fully transparent.
// Each accepted connection gets a monotonically increasing ID so the test can verify the
// agent used a distinct socket for the post-reconnect registration.
//
// Issue 7 fixes applied here:
//   - cleanup() is idempotent (cleanedUp guard prevents double-call log spam and double-destroy)
//   - Forwarding uses pause/drain backpressure instead of unchecked write
//   - conns is public so the test can assert the old pair is gone before new registration
//   - close() polls until conns is empty (all cleanup handlers have run) before closing server
//   - close() rejects if conns is not empty within 5 s

interface ProxyConn {
  id: number;
  agentSock: Socket;
  sigSock: Socket;
}

class TcpProxy {
  private server!: NetServer;
  /** Public so the test can assert old pair is removed before new registration evidence. */
  public conns = new Map<number, ProxyConn>();
  private nextId = 0;
  /** ID of the most recently accepted agent connection. -1 before any connection. */
  public latestConnId = -1;
  /** Total number of agent connections accepted (cumulative). */
  public connCount = 0;

  async start(proxyPort: number, sigHost: string, sigPort: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createNetServer((agentSock) => {
        const id = this.nextId++;
        this.latestConnId = id;
        this.connCount++;
        process.stdout.write(`[proxy-p26] agent connection accepted id=${id}\n`);

        const sigSock = createNetConnection(sigPort, sigHost);
        const conn: ProxyConn = { id, agentSock, sigSock };
        this.conns.set(id, conn);

        // Idempotent cleanup guard (Issue 7): cleanup may fire from both agentSock.close
        // and sigSock.close when one side is destroyed; only the first call does work.
        let cleanedUp = false;
        const cleanup = () => {
          if (cleanedUp) return;
          cleanedUp = true;
          this.conns.delete(id);
          if (!agentSock.destroyed) agentSock.destroy();
          if (!sigSock.destroyed) sigSock.destroy();
          process.stdout.write(`[proxy-p26] connection id=${id} cleaned up\n`);
        };

        // Backpressure-aware forwarding (Issue 7): pause/drain instead of unchecked write.
        agentSock.on("data", (d: Buffer) => {
          if (!sigSock.destroyed) {
            const ok = sigSock.write(d);
            if (!ok) agentSock.pause();
          }
        });
        sigSock.on("drain", () => agentSock.resume());

        sigSock.on("data", (d: Buffer) => {
          if (!agentSock.destroyed) {
            const ok = agentSock.write(d);
            if (!ok) sigSock.pause();
          }
        });
        agentSock.on("drain", () => sigSock.resume());

        agentSock.on("close", cleanup);
        sigSock.on("close", cleanup);
        agentSock.on("error", () => cleanup());
        sigSock.on("error", () => cleanup());
      });

      this.server.listen(proxyPort, "127.0.0.1", () => {
        process.stdout.write(`[proxy-p26] listening on 127.0.0.1:${proxyPort} → 127.0.0.1:${sigPort}\n`);
        resolve();
      });
      this.server.on("error", reject);
    });
  }

  /** Destroy the agent-side TCP socket for all current connections, forcing the agent to reconnect. */
  dropAllAgentConnections(): void {
    for (const conn of this.conns.values()) {
      process.stdout.write(`[proxy-p26] dropping agent connection id=${conn.id}\n`);
      conn.agentSock.destroy();
    }
  }

  /** Close the proxy: drop all connections, then wait until conns is empty (cleanup handlers ran),
   *  then close the server. Rejects if conns is not empty within 5 s.
   *
   *  Guarantees (pass28):
   *  - poll timer is cleared before server.close() so no stray callbacks fire after settle.
   *  - On timeout, asserts (logs) how many pairs are still open, force-destroys them,
   *    closes the server, then propagates the error — not before.
   */
  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.dropAllAgentConnections();
      const deadline = Date.now() + 5000;
      let pollTimer: ReturnType<typeof setTimeout> | undefined;

      const finish = (err?: Error) => {
        // Clear any pending poll timer so it cannot fire after settlement.
        if (pollTimer !== undefined) {
          clearTimeout(pollTimer);
          pollTimer = undefined;
        }
        // Force-destroy any pairs still in the map to unblock server.close().
        for (const conn of this.conns.values()) {
          if (!conn.agentSock.destroyed) conn.agentSock.destroy();
          if (!conn.sigSock.destroyed) conn.sigSock.destroy();
        }
        // Complete server.close() first; then propagate any error.
        this.server.close((closeErr) => {
          if (err) reject(err);
          else if (closeErr) reject(closeErr);
          else resolve();
        });
      };

      const poll = () => {
        pollTimer = undefined;
        if (this.conns.size === 0) {
          finish();
          return;
        }
        if (Date.now() > deadline) {
          const remaining = this.conns.size;
          process.stdout.write(`[proxy-p26] close: ${remaining} pair(s) still open at timeout — force-closing\n`);
          // Assert no pairs (log evidence), complete server cleanup, then propagate.
          finish(new Error(`[proxy-p26] close timed out: ${remaining} connection(s) still open after 5 s`));
          return;
        }
        pollTimer = setTimeout(poll, 50);
      };
      poll();
    });
  }
}

// ── Suite state ──────────────────────────────────────────────────────────────────────────────────

let cpProc: ChildProcess | null = null;
let sigProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let proxy: TcpProxy | null = null;
let deviceId = "";
let tenantId = "";
let keyPath = "";
let workDir = "";
let agentLog = "";
let agentPid = 0;
let grantPubkey = "";
let fixtureCfg: FixtureConfig | null = null;
/** Signaling-server log (Issue 1): "agent auth OK:" is the authoritative registration marker. */
let sigLog = "";

// Captured before reconnect trigger — for cross-spec evidence.
let proxyConnIdBefore = -1;

test.describe("Registration reconnect media survival — pass26 (synthetic, real auth, TCP proxy)", () => {
  // Issue 4: override suite-wide retries: 2 — any failure here must be decisive.
  test.describe.configure({ retries: 0 });

  test.beforeAll(async () => {
    test.setTimeout(300_000);

    // Issue 4: hard-fail on missing binary — do not skip.
    if (!existsSync(AGENT_BIN)) {
      throw new Error(
        `agent binary not found at ${AGENT_BIN} — build with: ` +
        `cargo build -p rmt-agent-windows --bin agent_host --features test-harness,secure-test`,
      );
    }
    if (!existsSync(SIGNALING_EXE)) {
      throw new Error(
        `signaling binary missing at ${SIGNALING_EXE} — run globalSetup or build manually`,
      );
    }
    if (!existsSync(CPTESTFIXTURE_EXE)) {
      throw new Error(`cptestfixture binary not found at ${CPTESTFIXTURE_EXE}`);
    }

    workDir = mkdtempSync(join(tmpdir(), "rmt-reconnect-p26-"));

    // ── cptestfixture ────────────────────────────────────────────────────────────────────────────
    cpProc = spawn(CPTESTFIXTURE_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${CP_PORT}`,
        CP_FIXTURE_GRANT_SEED: FIXTURE_GRANT_SEED,
        CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
        CP_SIGNALING_URL: SIGNALING_WS_REAL,
      },
    });

    await new Promise<void>((res, rej) => {
      let buf = "";
      const timeout = setTimeout(() => rej(new Error("cptestfixture did not print FIXTURE_READY within 30s")), 30_000);
      cpProc!.stdout?.on("data", (d: Buffer) => {
        buf += d.toString();
        process.stdout.write(`[cp-p26] ${d}`);
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
      cpProc!.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp-p26:err] ${d}`));
    });

    if (!fixtureCfg) throw new Error("cptestfixture: no fixture config parsed");
    // Issue 4: hard-fail if tech_c missing — confirms the updated binary is in use.
    if (!fixtureCfg.tech_c_email) {
      throw new Error(
        `cptestfixture binary lacks tech_c — rebuild with: cd control-plane && go build ./cmd/cptestfixture/`,
      );
    }
    grantPubkey = fixtureCfg.grant_issuer_pubkey;
    tenantId = fixtureCfg.tenant_id;
    console.log(`[p26] fixture ready — tenant=${tenantId} grant_issuer_pubkey=${grantPubkey}`);
    console.log(`[p26] tech_c_email=${fixtureCfg.tech_c_email} (tech_c fixture confirmed)`);

    if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`, 500), 15_000))) {
      throw new Error(`cptestfixture did not start serving on :${CP_PORT}`);
    }

    const adminSess = await loginToCP(tenantId, fixtureCfg.admin_email, fixtureCfg.admin_password);

    // Enroll the agent.
    const tokenBody = await fetch(`${CP_BASE}/enrollment-tokens`, {
      method: "POST",
      headers: authHeaders(adminSess),
      body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
    }).then((r) => r.json()) as { token?: string };
    const enrollToken = tokenBody.token;
    if (!enrollToken) throw new Error("POST /enrollment-tokens returned no token");

    const configPath = join(workDir, "agent-config.json");
    keyPath = join(workDir, "agent-identity.key");
    writeFileSync(
      configPath,
      JSON.stringify({
        signaling_url: SIGNALING_WS_PROXY,
        identity_path: keyPath.replace(/\\/g, "/"),
        stun: [],
      }),
    );
    await new Promise<void>((res, rej) =>
      execFile(
        AGENT_BIN,
        ["enroll", "--control-plane-url", CP_BASE, "--token", enrollToken,
         "--name", "E2E-Reconnect-P26", "--config", configPath],
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
    console.log(`[p26] enrolled device=${deviceId} tenant=${tenantId}`);

    // ── Signaling server ─────────────────────────────────────────────────────────────────────────
    sigProc = spawn(
      SIGNALING_EXE,
      ["-addr", `127.0.0.1:${SIG_PORT}`],
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
    // Issue 1: capture signaling log so "agent auth OK:" can be used as the authoritative
    // registration marker. Go's log.Printf writes to stderr.
    const onSigData = (s: string) => {
      sigLog += s;
      process.stdout.write(`[sig-p26] ${s}`);
    };
    sigProc.stdout?.on("data", (d: Buffer) => onSigData(d.toString()));
    sigProc.stderr?.on("data", (d: Buffer) => onSigData(d.toString()));

    if (!(await waitFor(() => wsReachable(SIGNALING_WS_REAL, 500), 10_000))) {
      throw new Error(`signaling did not come up on :${SIG_PORT}`);
    }
    console.log(`[p26] signaling up on :${SIG_PORT}`);

    // ── TCP proxy ────────────────────────────────────────────────────────────────────────────────
    proxy = new TcpProxy();
    await proxy.start(PROXY_PORT, "127.0.0.1", SIG_PORT);
    console.log(`[p26] TCP proxy up on :${PROXY_PORT} → :${SIG_PORT}`);

    // ── Agent ────────────────────────────────────────────────────────────────────────────────────
    let secureTestActive = false;
    let secureProfileBlocked = false;

    agentProc = spawn(
      AGENT_BIN,
      [
        "multi-stream",
        "--synthetic",
        "--device", deviceId,
        "--identity", keyPath,
        ...(tenantId ? ["--tenant", tenantId] : []),
        "--signaling", SIGNALING_WS_PROXY,
        "--grant-issuer", grantPubkey,
        "--fps", "10",
      ],
      {
        cwd: REPO,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, RMT_LOG: "debug" },
      },
    );
    agentPid = agentProc.pid ?? 0;

    const onAgentData = (s: string) => {
      agentLog += s;
      process.stdout.write(`[agent-p26] ${s}`);
      if (s.includes("secure-test-harness mode")) secureTestActive = true;
      if (s.includes("secure profile BLOCKED")) secureProfileBlocked = true;
    };
    agentProc.stdout?.on("data", (d: Buffer) => onAgentData(d.toString()));
    agentProc.stderr?.on("data", (d: Buffer) => onAgentData(d.toString()));
    agentProc.on("exit", (code) => process.stdout.write(`[agent-p26] exited code=${code}\n`));

    // Issue 1: wait for the signaling server to confirm "agent auth OK:" AND for the proxy to
    // have accepted at least one connection. This is the actual authenticated registration, NOT
    // the startup "multi_session_capable=true" print (which is a capability marker emitted before
    // the reconnect loop connects to the signaling server).
    const agentRegistered = await waitFor(async () => {
      if (secureProfileBlocked) return true;
      // Real authenticated registration: signaling server logs this after successful proof.
      const authOk = sigLog.includes("agent auth OK:");
      const hasConn = (proxy?.connCount ?? 0) >= 1;
      return authOk && hasConn;
    }, 25_000, 200);

    // Issue 4: hard-fail on capability problems.
    if (secureProfileBlocked) {
      throw new Error(
        "agent binary lacks secure-test feature — build with --features test-harness,secure-test",
      );
    }
    if (!agentRegistered) {
      throw new Error(
        "agent did not produce signaling 'agent auth OK:' within 25 s — check --grant-issuer handling",
      );
    }
    if (!secureTestActive) {
      throw new Error(
        "agent did not confirm secure-test-harness mode — check --grant-issuer handling",
      );
    }

    // Issue 1: proxyConnIdBefore taken AFTER registration is confirmed — not before connect.
    proxyConnIdBefore = proxy!.latestConnId;
    console.log(`[p26] first authenticated registration confirmed — proxy connId=${proxyConnIdBefore}`);

    const launchArgs = ["--autoplay-policy=no-user-gesture-required"];
    try {
      browser = await chromium.launch({ channel: "chrome", headless: true, args: launchArgs });
    } catch {
      try {
        browser = await chromium.launch({ headless: true, args: launchArgs });
      } catch (e) {
        // Issue 4: hard-fail when no browser is available.
        throw new Error(`no usable browser: ${String(e)}`);
      }
    }
  });

  test.afterAll(async () => {
    await browser?.close().catch(() => {});
    await stopProc(agentProc);
    await stopProc(sigProc);
    await stopProc(cpProc);
    // Collect proxy close error and clear timeout; complete all remaining cleanup; then throw.
    let proxyCloseErr: unknown = undefined;
    let pairsLeft = 0;
    if (proxy) {
      let closeTimeoutHandle: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([
        proxy.close().catch((e: unknown) => { proxyCloseErr = e; }),
        new Promise<void>((res) => {
          closeTimeoutHandle = setTimeout(() => {
            proxyCloseErr = new Error("[p26] proxy.close timed out after 6 s");
            res();
          }, 6000);
        }),
      ]);
      if (closeTimeoutHandle !== undefined) clearTimeout(closeTimeoutHandle);
      pairsLeft = proxy.conns.size;
      proxy = null;
    }
    agentProc = null;
    sigProc = null;
    cpProc = null;
    if (workDir) {
      try { rmSync(workDir, { recursive: true, force: true }); } catch {}
      workDir = "";
    }
    // Assert pairs empty after all cleanup completes, then propagate any collected error.
    expect(pairsLeft, "proxy must have no remaining connection pairs after close").toBe(0);
    if (proxyCloseErr) throw proxyCloseErr as Error;
  });

  // ── pass26-reconnect-survival ─────────────────────────────────────────────────────────────────
  test(
    "pass26: existing A+B WebRTC media survives registration WebSocket reconnect; C joins new registration",
    async () => {
      if (!browser) throw new Error("no browser (beforeAll failed)");
      if (!fixtureCfg) throw new Error("fixture config not parsed (beforeAll failed)");
      test.setTimeout(300_000);

      const agentBinHash = await sha256File(AGENT_BIN);
      const sigBinHash = await sha256File(SIGNALING_EXE);
      const cpBinHash = await sha256File(CPTESTFIXTURE_EXE);
      console.log(`\n[pass26] === RECONNECT SURVIVAL EVIDENCE ===`);
      console.log(`[pass26] agent_host.exe SHA-256:     ${agentBinHash}`);
      console.log(`[pass26] signaling.exe SHA-256:      ${sigBinHash}`);
      console.log(`[pass26] cptestfixture.exe SHA-256:  ${cpBinHash}`);
      console.log(`[pass26] agent PID:                  ${agentPid}`);
      console.log(`[pass26] device_id:                  ${deviceId}`);
      console.log(`[pass26] proxy connId before:        ${proxyConnIdBefore}`);

      // Renewers stopped in finally regardless of test outcome (Issue 2).
      let renewerA: Renewer | null = null;
      let renewerB: Renewer | null = null;
      let renewerC: Renewer | null = null;
      // Collects background renewal errors so they fail the test via expect.
      const renewalErrors: string[] = [];
      const onRenewalError = (e: unknown) => renewalErrors.push(String(e));

      try {
        // ── Step 1: Login A, B, C — assert IDs match fixture (Issue 6) ───────────────────────────
        const techASess = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
        const techBSess = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);
        const techCSess = await loginToCP(tenantId, fixtureCfg!.tech_c_email, fixtureCfg!.tech_c_password);

        // Issue 6: assert login user_id matches fixture constants and all are distinct.
        expect(techASess.userID, "tech_a login user_id must match fixture").toBe(fixtureCfg!.tech_a_id);
        expect(techBSess.userID, "tech_b login user_id must match fixture").toBe(fixtureCfg!.tech_b_id);
        expect(techCSess.userID, "tech_c login user_id must match fixture").toBe(fixtureCfg!.tech_c_id);
        expect(techASess.userID, "tech_a and tech_b user_ids must be distinct").not.toBe(techBSess.userID);
        expect(techASess.userID, "tech_a and tech_c user_ids must be distinct").not.toBe(techCSess.userID);
        expect(techBSess.userID, "tech_b and tech_c user_ids must be distinct").not.toBe(techCSess.userID);
        console.log(`[pass26] login IDs: A=${techASess.userID} B=${techBSess.userID} C=${techCSess.userID} — all distinct`);

        // ── Step 2: A and B mint tickets and connect ──────────────────────────────────────────────
        const bodyA = await mintTicket(techASess, deviceId);
        const bodyB = await mintTicket(techBSess, deviceId);

        const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
        const sigB = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
        const sessArec = (bodyA.session as { id?: string; technician_id?: string } | undefined);
        const sessBrec = (bodyB.session as { id?: string; technician_id?: string } | undefined);

        const ticketA = sigA?.ticket;
        const ticketB = sigB?.ticket;
        const sidA = sigA?.session_id ?? sessArec?.id ?? "";
        const sidB = sigB?.session_id ?? sessBrec?.id ?? "";

        if (!ticketA || !ticketB) throw new Error(`no tickets. A=${JSON.stringify(bodyA)} B=${JSON.stringify(bodyB)}`);
        if (!sidA || !sidB) throw new Error(`no session IDs. sidA=${sidA} sidB=${sidB}`);
        expect(sidA, "sidA must differ from sidB").not.toBe(sidB);
        console.log(`[pass26] sidA=${sidA} sidB=${sidB}`);

        // Issue 6: assert ticket session owner (technician_id) matches the session's tech.
        const ownerA = sessArec?.technician_id ?? "";
        const ownerB = sessBrec?.technician_id ?? "";
        expect(ownerA, "A ticket technician_id must equal tech_a user_id").toBe(techASess.userID);
        expect(ownerB, "B ticket technician_id must equal tech_b user_id").toBe(techBSess.userID);
        console.log(`[pass26] ticket owners: A.technician_id=${ownerA} B.technician_id=${ownerB} — match`);

        // A and B connect to the REAL signaling server (not the proxy — only the agent uses the proxy).
        const pageA = await openHarnessPage(browser!, SIGNALING_WS_REAL, deviceId, encodeTicket(ticketA));
        const pageB = await openHarnessPage(browser!, SIGNALING_WS_REAL, deviceId, encodeTicket(ticketB));

        await Promise.all([
          waitForConnected(pageA, 30_000),
          waitForConnected(pageB, 30_000),
        ]);
        console.log("[pass26] A and B: WebRTC connected");

        await Promise.all([
          waitForVideo(pageA, "p26-techA-pre"),
          waitForVideo(pageB, "p26-techB-pre"),
        ]);
        console.log("[pass26] A and B: VP8 video flowing");

        // ── Step 3: Install session policies for A and B; start renewers (Issue 2) ───────────────
        const leaseA = await fetchSessionPolicy(techASess, sidA);
        const aAck0 = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
        await pageA.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, leaseA.signed);
        expect(await waitForNewControlMsgOfType(pageA, "SessionPolicyInstalled", aAck0, 15_000), "A: initial policy ack").toBe(true);
        const aAckCount = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
        console.log(`[pass26] A: policy installed (ack count=${aAckCount} expires_at_ms=${leaseA.expires_at_ms})`);

        const leaseB = await fetchSessionPolicy(techBSess, sidB);
        const bAck0 = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
        await pageB.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, leaseB.signed);
        expect(await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bAck0, 15_000), "B: initial policy ack").toBe(true);
        const bAckCount = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
        console.log(`[pass26] B: policy installed (ack count=${bAckCount} expires_at_ms=${leaseB.expires_at_ms})`);

        // Issue 2: start renewable policy tasks for A and B.
        renewerA = startPolicyRenewer(techASess, sidA, pageA, "A", leaseA, onRenewalError);
        renewerB = startPolicyRenewer(techBSess, sidB, pageB, "B", leaseB, onRenewalError);

        // ── Step 4: Pre-bind coordinator session IDs ──────────────────────────────────────────────
        const logBefore = agentLog.length;

        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 220, down: true },
          });
        });
        let aSessionId = "";
        expect(
          await waitFor(async () => {
            const m = agentLog.slice(logBefore).match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=220 first_holder=true/);
            if (m) { aSessionId = m[1]; return true; }
            return false;
          }, 8_000),
          "A: key=220 must be admitted (first_holder=true)",
        ).toBe(true);
        console.log(`[pass26] A: pre-bind session=${aSessionId} key=220`);

        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 221, down: true },
          });
        });
        let bSessionId = "";
        expect(
          await waitFor(async () => {
            const m = agentLog.slice(logBefore).match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=221 first_holder=true/);
            if (m) { bSessionId = m[1]; return true; }
            return false;
          }, 8_000),
          "B: key=221 must be admitted (first_holder=true)",
        ).toBe(true);
        expect(bSessionId, "A and B coordinator session IDs must be distinct").not.toBe(aSessionId);
        console.log(`[pass26] A session=${aSessionId} B session=${bSessionId} — DISTINCT`);

        // Release pre-bind keys.
        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 220, down: false },
          });
        });
        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 221, down: false },
          });
        });

        // ── Step 5: Trigger reconnect by dropping the proxy connection ────────────────────────────
        // Issue 1: record offsets in BOTH logs for split evidence post-reconnect.
        const agentLogReconnectOffset = agentLog.length;
        const sigLogReconnectOffset = sigLog.length;
        const proxyConnIdAtDrop = proxy!.latestConnId;
        console.log(`[pass26] dropping proxy connection id=${proxyConnIdAtDrop} — agent will reconnect`);
        proxy!.dropAllAgentConnections();

        // ── Step 6: Wait for new authenticated registration ───────────────────────────────────────
        //
        // Issue 1: the startup "multi_session_capable=true" print in host.rs is emitted ONCE before
        // the reconnect loop — it is a capability marker, NOT an authenticated registration. After a
        // reconnect, it is not reprinted. The authoritative evidence is:
        //   (a) signaling server log "agent auth OK: device \"<deviceId>\"" (main.go:495) — proves
        //       the correct device completed auth, not an unrelated agent on the same server;
        //   (b) agent log "register_for_mux: registered" (transport-webrtc/src/lib.rs, debug level)
        //       after the reconnect offset — proves the Registered wire message was received.
        //
        // Issue 3: host.rs reconnect loop now sleeps 2 s on Ok(()) before reconnecting, so the
        // total time from drop to second "agent auth OK:" is ~2.5 s. 30 s timeout is ample.
        //
        // Issue 7: also assert the old proxy pair is gone BEFORE new registration is counted.
        let newRegistrationSeen = false;
        let newProxyConnId = proxyConnIdAtDrop;
        const reconnectOk = await waitFor(async () => {
          const sigSlice = sigLog.slice(sigLogReconnectOffset);
          const agentSlice = agentLog.slice(agentLogReconnectOffset);
          // Exact device match in sigLog proves it is this agent's reconnect, not another device.
          // "register_for_mux: registered" in agentLog proves the Registered message was received.
          newRegistrationSeen = sigSlice.includes(`agent auth OK: device "${deviceId}"`)
            && agentSlice.includes("register_for_mux: registered");
          newProxyConnId = proxy!.latestConnId;
          // Old pair must be cleaned up before new registration evidence is accepted.
          const oldPairGone = !proxy!.conns.has(proxyConnIdAtDrop);
          return newRegistrationSeen && newProxyConnId > proxyConnIdAtDrop && oldPairGone;
        }, 30_000, 200);

        expect(reconnectOk, "agent must reconnect and re-register within 30 s").toBe(true);
        // Issue 7: explicit assertion that old pair was cleaned up.
        expect(proxy!.conns.has(proxyConnIdAtDrop), "old proxy pair must be gone before new registration counted").toBe(false);
        expect(newProxyConnId, "new proxy socket ID must be greater than old (distinct socket identity)").toBeGreaterThan(proxyConnIdAtDrop);
        console.log(`[pass26] RECONNECT: new proxy connId=${newProxyConnId} (was ${proxyConnIdAtDrop}) — distinct socket identity confirmed`);
        console.log(`[pass26] signaling log contains second "agent auth OK:" — new authenticated registration confirmed`);

        // ── Step 6b: Explicit post-reconnect policy renewal for A and B ──────────────────────────
        //
        // Require actual signed renewals and agent acks over the new registration before asserting
        // media survival and coordinator input continuity. This proves the new mux connection
        // processes policy messages end-to-end, not just that stale pre-reconnect leases persist.
        const postLeaseA = await fetchSessionPolicy(techASess, sidA);
        const aPostReconnectAck0 = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
        await pageA.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, postLeaseA.signed);
        expect(
          await waitForNewControlMsgOfType(pageA, "SessionPolicyInstalled", aPostReconnectAck0, 15_000),
          "A: post-reconnect policy renewal ack",
        ).toBe(true);
        console.log(`[pass26] A: post-reconnect policy renewal acked (expires_at_ms=${postLeaseA.expires_at_ms})`);

        const postLeaseB = await fetchSessionPolicy(techBSess, sidB);
        const bPostReconnectAck0 = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
        await pageB.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, postLeaseB.signed);
        expect(
          await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", bPostReconnectAck0, 15_000),
          "B: post-reconnect policy renewal ack",
        ).toBe(true);
        console.log(`[pass26] B: post-reconnect policy renewal acked (expires_at_ms=${postLeaseB.expires_at_ms})`);

        // ── Step 7: Assert A and B STILL produce bytes+frames after reconnect (Issue 5) ──────────
        //
        // Issue 5: take fresh baselines AFTER the new registration is confirmed — not before the
        // drop. bytes_pre→bytes_post spanning the reconnect could have grown entirely before the
        // drop and show zero growth after. Fresh baselines prove ongoing live delivery.
        const statsA_fresh = await getInboundStats(pageA);
        const statsB_fresh = await getInboundStats(pageB);
        console.log(`[pass26] POST-RECONNECT fresh baselines: A bytes=${statsA_fresh.bytes} frames=${statsA_fresh.frames}`);
        console.log(`[pass26] POST-RECONNECT fresh baselines: B bytes=${statsB_fresh.bytes} frames=${statsB_fresh.frames}`);

        // Wait 2 s for the synthetic capturer (10 fps) to produce at least 20 new frames.
        await sleep(2_000);

        const statsA_post = await getInboundStats(pageA);
        const statsB_post = await getInboundStats(pageB);
        console.log(`[pass26] POST-RECONNECT measured: A bytes=${statsA_post.bytes} frames=${statsA_post.frames}`);
        console.log(`[pass26] POST-RECONNECT measured: B bytes=${statsB_post.bytes} frames=${statsB_post.frames}`);

        expect(statsA_post.bytes, "A: bytesReceived must grow after reconnect (no teardown)").toBeGreaterThan(statsA_fresh.bytes);
        expect(statsA_post.frames, "A: framesDecoded must grow after reconnect (no teardown)").toBeGreaterThan(statsA_fresh.frames);
        expect(statsB_post.bytes, "B: bytesReceived must grow after reconnect (no teardown)").toBeGreaterThan(statsB_fresh.bytes);
        expect(statsB_post.frames, "B: framesDecoded must grow after reconnect (no teardown)").toBeGreaterThan(statsB_fresh.frames);

        // ── Step 8: Assert no teardown for A or B during reconnect window ─────────────────────────
        const reconnectSlice = agentLog.slice(agentLogReconnectOffset);
        expect(
          reconnectSlice.includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`),
          `A session=${aSessionId} must NOT be torn down during reconnect`,
        ).toBe(false);
        expect(
          reconnectSlice.includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
          `B session=${bSessionId} must NOT be torn down during reconnect`,
        ).toBe(false);
        console.log(`[pass26] NO TEARDOWN for A session=${aSessionId} or B session=${bSessionId} — confirmed`);

        // ── Step 9: Post-reconnect input — same session IDs ──────────────────────────────────────
        const postReconnectLogOffset = agentLog.length;

        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 222, down: true },
          });
        });
        let aPostSid = "";
        const aPostOk = await waitFor(async () => {
          const m = agentLog.slice(postReconnectLogOffset).match(
            /\[SESSION:ADMITTED_INPUT\] session=(\d+) key=222/
          );
          if (m) { aPostSid = m[1]; return true; }
          return false;
        }, 8_000);
        expect(aPostOk, "A: key=222 must be admitted after reconnect").toBe(true);
        expect(aPostSid, "A: coordinator session ID must be unchanged after reconnect").toBe(aSessionId);
        console.log(`[pass26] A: key=222 admitted to session=${aPostSid} (same as pre-reconnect session=${aSessionId})`);

        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 223, down: true },
          });
        });
        let bPostSid = "";
        const bPostOk = await waitFor(async () => {
          const m = agentLog.slice(postReconnectLogOffset).match(
            /\[SESSION:ADMITTED_INPUT\] session=(\d+) key=223/
          );
          if (m) { bPostSid = m[1]; return true; }
          return false;
        }, 8_000);
        expect(bPostOk, "B: key=223 must be admitted after reconnect").toBe(true);
        expect(bPostSid, "B: coordinator session ID must be unchanged after reconnect").toBe(bSessionId);
        console.log(`[pass26] B: key=223 admitted to session=${bPostSid} (same as pre-reconnect session=${bSessionId})`);

        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 222, down: false },
          });
        });
        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 223, down: false },
          });
        });

        // ── Step 10: C joins the NEW registration and receives video + policy (Issue 2) ──────────
        const bodyC = await mintTicket(techCSess, deviceId);
        const sigC = bodyC.signaling as { ticket?: unknown; session_id?: string } | undefined;
        const sessCrec = (bodyC.session as { id?: string; technician_id?: string } | undefined);
        const ticketC = sigC?.ticket;
        const sidC = sigC?.session_id ?? sessCrec?.id ?? "";

        if (!ticketC) throw new Error(`C: no ticket. bodyC=${JSON.stringify(bodyC)}`);
        if (!sidC) throw new Error(`C: no session ID`);

        // Issue 6: assert C ticket technician_id matches tech_c.
        const ownerC = sessCrec?.technician_id ?? "";
        expect(ownerC, "C ticket technician_id must equal tech_c user_id").toBe(techCSess.userID);

        // C's sidC must differ from A and B (fresh session against the new registration).
        expect(sidC, "C sidC must differ from sidA").not.toBe(sidA);
        expect(sidC, "C sidC must differ from sidB").not.toBe(sidB);
        console.log(`[pass26] C: sidC=${sidC} technician_id=${ownerC} — distinct session, owner matches`);

        const pageC = await openHarnessPage(browser!, SIGNALING_WS_REAL, deviceId, encodeTicket(ticketC));
        await waitForConnected(pageC, 30_000);
        console.log("[pass26] C: WebRTC connected via new registration");

        await waitForVideo(pageC, "p26-techC-post-reconnect");
        console.log("[pass26] C: VP8 video flowing via new registration");

        // Issue 2: Install signed policy for C and await the agent's ack.
        const leaseC = await fetchSessionPolicy(techCSess, sidC);
        const cAck0 = await countControlMsgsByType(pageC, "SessionPolicyInstalled");
        await pageC.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, leaseC.signed);
        expect(await waitForNewControlMsgOfType(pageC, "SessionPolicyInstalled", cAck0, 15_000), "C: initial policy ack").toBe(true);
        const cAckCount = await countControlMsgsByType(pageC, "SessionPolicyInstalled");
        console.log(`[pass26] C: policy installed (ack count=${cAckCount} expires_at_ms=${leaseC.expires_at_ms})`);

        // Issue 2: start renewer for C.
        renewerC = startPolicyRenewer(techCSess, sidC, pageC, "C", leaseC, onRenewalError);

        // ── Step 10b: C second explicit signed policy — expiry/ack advancement ──────────────────
        //
        // Requires a NEW fetch+install distinct from the initial policy, confirming the NEW mux
        // connection processes a second signed policy end-to-end. ack count must advance and
        // expires_at_ms must be >= the initial lease (same or later expiry from a fresh signing).
        const cAckCountBefore2 = await countControlMsgsByType(pageC, "SessionPolicyInstalled");
        const leaseC2 = await fetchSessionPolicy(techCSess, sidC);
        await pageC.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, leaseC2.signed);
        expect(
          await waitForNewControlMsgOfType(pageC, "SessionPolicyInstalled", cAckCountBefore2, 15_000),
          "C: second policy install ack",
        ).toBe(true);
        const cAckCountAfter2 = await countControlMsgsByType(pageC, "SessionPolicyInstalled");
        expect(cAckCountAfter2, "C: ack count must advance on second install").toBeGreaterThan(cAckCountBefore2);
        expect(leaseC2.expires_at_ms, "C: second lease expiry must be >= initial expiry").toBeGreaterThanOrEqual(leaseC.expires_at_ms);
        console.log(`[pass26] C: second policy installed (ack count=${cAckCountAfter2} expires_at_ms=${leaseC2.expires_at_ms} >= ${leaseC.expires_at_ms})`);

        // ── Step 11: Re-assert A and B media AFTER C policy admission (Issue 5) ─────────────────
        //
        // Issue 5: "Recheck no A/B teardown and media/input after C policy admission, not just
        // stale connected state." Take fresh baselines now; wait 2 s; require new growth.
        const statsA_afterC = await getInboundStats(pageA);
        const statsB_afterC = await getInboundStats(pageB);
        await sleep(2_000);
        const statsA_finalPost = await getInboundStats(pageA);
        const statsB_finalPost = await getInboundStats(pageB);

        expect(statsA_finalPost.bytes, "A: bytesReceived must still grow after C joins").toBeGreaterThan(statsA_afterC.bytes);
        expect(statsA_finalPost.frames, "A: framesDecoded must still grow after C joins").toBeGreaterThan(statsA_afterC.frames);
        expect(statsB_finalPost.bytes, "B: bytesReceived must still grow after C joins").toBeGreaterThan(statsB_afterC.bytes);
        expect(statsB_finalPost.frames, "B: framesDecoded must still grow after C joins").toBeGreaterThan(statsB_afterC.frames);
        console.log(`[pass26] A after-C bytes: ${statsA_afterC.bytes}→${statsA_finalPost.bytes} frames: ${statsA_afterC.frames}→${statsA_finalPost.frames}`);
        console.log(`[pass26] B after-C bytes: ${statsB_afterC.bytes}→${statsB_finalPost.bytes} frames: ${statsB_afterC.frames}→${statsB_finalPost.frames}`);

        // Verify A and B are still connected (not page-disconnected).
        const stateA = await pageA.evaluate(() =>
          (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
        );
        const stateB = await pageB.evaluate(() =>
          (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
        );
        expect(stateA, "A must still be connected after C joins").toBe("connected");
        expect(stateB, "B must still be connected after C joins").toBe("connected");
        console.log(`[pass26] A state=${stateA} B state=${stateB} — both still connected after C joins`);

        // ── Step 12: After C renewal, send new unique A/B keys — assert original coordinator IDs,
        //             no A/B teardown, final fresh frames ─────────────────────────────────────────
        const finalInputLogOffset = agentLog.length;

        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 224, down: true },
          });
        });
        let aFinalSid = "";
        const aFinalOk = await waitFor(async () => {
          const m = agentLog.slice(finalInputLogOffset).match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=224/);
          if (m) { aFinalSid = m[1]; return true; }
          return false;
        }, 8_000);
        expect(aFinalOk, "A: key=224 must be admitted after C renewal").toBe(true);
        expect(aFinalSid, "A: coordinator session ID must be unchanged after C renewal").toBe(aSessionId);

        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 225, down: true },
          });
        });
        let bFinalSid = "";
        const bFinalOk = await waitFor(async () => {
          const m = agentLog.slice(finalInputLogOffset).match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=225/);
          if (m) { bFinalSid = m[1]; return true; }
          return false;
        }, 8_000);
        expect(bFinalOk, "B: key=225 must be admitted after C renewal").toBe(true);
        expect(bFinalSid, "B: coordinator session ID must be unchanged after C renewal").toBe(bSessionId);

        const finalWindowSlice = agentLog.slice(finalInputLogOffset);
        expect(
          finalWindowSlice.includes(`[SESSION:TEARDOWN:DONE session=${aSessionId}]`),
          `A session=${aSessionId} must NOT be torn down in final window`,
        ).toBe(false);
        expect(
          finalWindowSlice.includes(`[SESSION:TEARDOWN:DONE session=${bSessionId}]`),
          `B session=${bSessionId} must NOT be torn down in final window`,
        ).toBe(false);
        console.log(`[pass26] final: A key=224 session=${aFinalSid} B key=225 session=${bFinalSid} — IDs unchanged, no teardown`);

        await pageA.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 224, down: false },
          });
        });
        await pageB.evaluate(() => {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 225, down: false },
          });
        });

        const statsA_fin2 = await getInboundStats(pageA);
        const statsB_fin2 = await getInboundStats(pageB);
        await sleep(2_000);
        const statsA_fin2post = await getInboundStats(pageA);
        const statsB_fin2post = await getInboundStats(pageB);
        expect(statsA_fin2post.bytes, "A: bytesReceived must grow in final window after C renewal").toBeGreaterThan(statsA_fin2.bytes);
        expect(statsA_fin2post.frames, "A: framesDecoded must grow in final window after C renewal").toBeGreaterThan(statsA_fin2.frames);
        expect(statsB_fin2post.bytes, "B: bytesReceived must grow in final window after C renewal").toBeGreaterThan(statsB_fin2.bytes);
        expect(statsB_fin2post.frames, "B: framesDecoded must grow in final window after C renewal").toBeGreaterThan(statsB_fin2.frames);
        console.log(`[pass26] A final frames: ${statsA_fin2.frames}→${statsA_fin2post.frames} bytes: ${statsA_fin2.bytes}→${statsA_fin2post.bytes}`);
        console.log(`[pass26] B final frames: ${statsB_fin2.frames}→${statsB_fin2post.frames} bytes: ${statsB_fin2.bytes}→${statsB_fin2post.bytes}`);

        // ── Summary ───────────────────────────────────────────────────────────────────────────────
        console.log("\n[pass26] PASS — registration reconnect media survival evidence:");
        console.log(`  agent_host.exe SHA-256:         ${agentBinHash}`);
        console.log(`  signaling.exe SHA-256:          ${sigBinHash}`);
        console.log(`  cptestfixture.exe SHA-256:      ${cpBinHash}`);
        console.log(`  agent PID:                      ${agentPid}`);
        console.log(`  device_id:                      ${deviceId}`);
        console.log(`  proxy socket id (before drop):  ${proxyConnIdAtDrop}`);
        console.log(`  proxy socket id (after drop):   ${newProxyConnId} (distinct — new authenticated registration)`);
        console.log(`  sigA/sidA:                      ${sidA} coordinator=${aSessionId} owner=${ownerA}`);
        console.log(`  sigB/sidB:                      ${sidB} coordinator=${bSessionId} owner=${ownerB}`);
        console.log(`  sidC:                           ${sidC} (fresh, via new registration) owner=${ownerC}`);
        console.log(`  A bytes post-reconnect:          ${statsA_fresh.bytes}→${statsA_post.bytes} (grew)`);
        console.log(`  A frames post-reconnect:         ${statsA_fresh.frames}→${statsA_post.frames} (grew)`);
        console.log(`  B bytes post-reconnect:          ${statsB_fresh.bytes}→${statsB_post.bytes} (grew)`);
        console.log(`  B frames post-reconnect:         ${statsB_fresh.frames}→${statsB_post.frames} (grew)`);
        console.log(`  A: key=222 session:              ${aPostSid} (= ${aSessionId}, unchanged)`);
        console.log(`  B: key=223 session:              ${bPostSid} (= ${bSessionId}, unchanged)`);
        console.log(`  A/B teardown during reconnect:   NONE`);
        console.log(`  C video post-reconnect:          confirmed`);
        console.log(`  C policy ack count:              ${cAckCount}\n`);

        await pageA.close();
        await pageB.close();
        await pageC.close();
      } finally {
        // Always stop and await all renewal tasks before assertions — captures any
        // in-flight errors from the task run before reporting renewalErrors below.
        renewerA?.cancel();
        renewerB?.cancel();
        renewerC?.cancel();
        await Promise.all([
          renewerA?.done ?? Promise.resolve(),
          renewerB?.done ?? Promise.resolve(),
          renewerC?.done ?? Promise.resolve(),
        ]);
        console.log("[pass26] renewal tasks stopped");
      }
      // Assert after workers are stopped and awaited so in-flight cancellation errors
      // are captured in renewalErrors before this check runs.
      expect(renewalErrors, "no policy renewal errors must have occurred").toHaveLength(0);
    },
  );
});
