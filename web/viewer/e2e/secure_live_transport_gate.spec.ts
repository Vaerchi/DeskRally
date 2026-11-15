/**
 * SECURE LIVE TRANSPORT GATE — pass16 live end-to-end test.
 *
 * Pass16 correction: replaces the CP_INSECURE_DEV=1 / StubAuthenticator path from pass15 with
 * a TEST-ONLY cptestfixture binary that enforces real login → session-cookie → CSRF-token
 * authentication (SessionAuthenticator + AuthService). TechA and TechB are genuinely distinct
 * authenticated identities whose returned session.technician_id values differ and match their
 * respective user IDs.
 *
 * Proves the full enforcing signaling + CP grant verification + backstage denial chain:
 *
 *   1. cptestfixture starts: real SessionAuthenticator, distinct TechA + TechB users.
 *   2. Anonymous POST /sessions → 401 (no cookie, no StubAuth bypass).
 *   3. TechA and TechB each log in with distinct passwords → distinct session cookies.
 *   4. One enrolled agent runs `multi-stream --synthetic --grant-issuer <cp-pubkey>`
 *      (requires --features test-harness,secure-test).
 *   5. A and B obtain independent CP-signed session tickets via POST /sessions (each with
 *      their own authenticated session); returned technician_id values DIFFER and match
 *      their respective user IDs.
 *   6. Agent auth verified end-to-end: `RMTAGENTAUTHv1` preimage includes `tenant_id`.
 *   7. Both A and B independently receive VP8 video (enforcing admission confirmed).
 *   8. Tech A mints a CP grant (`POST /grant/mint`), installs it via the Control channel
 *      (InstallGrant), receives a `GrantInstalled` ack.
 *   9. Agent log confirms `verify_grant_inert` ran: grant Ed25519-verified, no Dispatcher.
 *  10. Tech A sends a backstage RPC after grant → denied (structural, no Dispatcher).
 *  11. Tech B sends a backstage RPC without any grant → denied (no-grant path, fail-closed).
 *  12. SHA-256 of the agent binary, PIDs, and session IDs captured as evidence.
 *
 * LIMITS (stated):
 *   - In-memory CP stores (no Postgres). PG matrix separately validated.
 *   - No attend/promotion/real input injection.
 *   - secure-test feature required; test self-skips (not fails) if binary lacks it.
 *
 * Ports: CP=8188, SIG=8189 (isolated from all other specs).
 */

import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID, createHash } from "node:crypto";
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
// Test-only fixture binary — NOT the production controlplane.exe.
const CPTESTFIXTURE_EXE = resolve(CP_DIR, "cptestfixture.exe");
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

// Isolated ports — no overlap with any other spec.
const CP_PORT = 8188;
const SIG_PORT = 8189;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;

// Fixed grant-issuer seed — different from 1111… (secure_posture/secure_grant), 2222… (multi_tech).
// Passed to cptestfixture as CP_FIXTURE_GRANT_SEED.
const FIXTURE_GRANT_SEED = "3333333333333333333333333333333333333333333333333333333333333333";
const DEVICE_IDENTITY_TOKEN = "e2e-secure-live-gate-device-identity-token-3333abcdef";

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

// Returns true as long as the server responds with ANY HTTP status (not just 2xx).
// Used as a startup probe for cptestfixture which has no /healthz route.
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

// ── Real-auth session helpers ────────────────────────────────────────────────────────────────────

interface CPSession {
  /** Raw value of the cp_session cookie. */
  sessionCookie: string;
  /** Raw value of the rmt_csrf cookie (also used as X-CSRF-Token header). */
  csrfToken: string;
  /** The user_id returned in the login response body. */
  userID: string;
}

/**
 * Log in to the CP fixture as the given user. Returns a CPSession carrying the session cookie
 * and CSRF token for subsequent authenticated requests. Throws on any non-200 response.
 *
 * NOTE: Node.js fetch does NOT automatically store/send cookies. We extract them manually from
 * Set-Cookie response headers and include them explicitly in subsequent requests.
 */
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

  // Extract Set-Cookie headers. Node 18+ exposes getSetCookie() on the Headers object.
  const setCookies: string[] = typeof (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
    ? (r.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
    : [];

  let sessionCookie = "";
  for (const raw of setCookies) {
    // Cookie format: "name=value; Path=/; HttpOnly; ..." — take the first segment.
    const pair = raw.split(";")[0]?.trim() ?? "";
    if (pair.startsWith("cp_session=") || pair.startsWith("__Host-cp_session=")) {
      sessionCookie = pair.split("=").slice(1).join("=");
    }
  }

  if (!sessionCookie) throw new Error(`POST /auth/login ${email}: no session cookie in response`);
  if (!csrfToken) throw new Error(`POST /auth/login ${email}: no csrf_token in response body`);

  return { sessionCookie, csrfToken, userID };
}

/**
 * Build the Cookie + X-CSRF-Token headers for an authenticated request.
 * The csrfMiddleware checks BOTH the rmt_csrf cookie value AND the X-CSRF-Token header.
 */
function authHeaders(sess: CPSession): Record<string, string> {
  return {
    "content-type": "application/json",
    // Send both session and CSRF cookies; rmt_csrf value must match X-CSRF-Token header.
    "cookie": `cp_session=${sess.sessionCookie}; rmt_csrf=${sess.csrfToken}`,
    "x-csrf-token": sess.csrfToken,
  };
}

/**
 * POST /sessions as an authenticated technician. Returns the raw response body parsed as JSON.
 * Throws on non-201.
 */
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

/**
 * POST /grant/mint as an authenticated technician for machineId + sessionId.
 * Returns the raw SignedGrant JSON string the agent's `SignedGrant::from_json` will deserialize.
 */
async function mintGrant(sess: CPSession, machineId: string, sessionId: string): Promise<string> {
  const r = await fetch(`${CP_BASE}/grant/mint`, {
    method: "POST",
    headers: authHeaders(sess),
    body: JSON.stringify({ machine_id: machineId, session_id: sessionId }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST /grant/mint → ${r.status}: ${text}`);
  return text; // raw SignedGrant JSON
}

/** SHA-256 hex digest of a file. */
function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const hash = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (d) => hash.update(d));
    s.on("end", () => res(hash.digest("hex")));
    s.on("error", rej);
  });
}

/** Wait for a specific control message type to appear in controlReceived. */
async function waitForControlMsg(page: Page, msgType: string, timeoutMs = 10_000): Promise<void> {
  const found = await waitFor(async () => {
    return page.evaluate((t) => {
      const r = (window as unknown as { rmt?: { controlReceived?: { t: string }[] } }).rmt;
      return (r?.controlReceived ?? []).some((m) => m.t === t);
    }, msgType);
  }, timeoutMs);
  expect(found, `ControlMessage ${msgType} must arrive within ${timeoutMs}ms`).toBe(true);
}

/** Poll agentLog (from offset) until substring appears or timeout. Avoids stdio-buffer races. */
async function waitForAgentLogSlice(
  fromOffset: number,
  substring: string,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (agentLog.slice(fromOffset).includes(substring)) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

/** Wait for at least one backstage response to arrive. */
async function waitForBackstageResponse(page: Page, timeoutMs = 10_000): Promise<string> {
  let resp = "";
  const found = await waitFor(async () => {
    resp = await page.evaluate(() => {
      const r = (window as unknown as { rmt?: { backstageResponses?: string[] } }).rmt;
      return (r?.backstageResponses ?? [])[0] ?? "";
    });
    return resp.length > 0;
  }, timeoutMs);
  expect(found, "backstage response must arrive within timeout").toBe(true);
  return resp;
}

// ── Session-policy lease helpers (pass18) ────────────────────────────────────────────────────────

/**
 * One renewal response from POST /sessions/{id}/policy.
 * `signed` is the opaque JSON blob forwarded verbatim to the agent via InstallSessionPolicy.
 */
interface SessionLease {
  access: string;
  signed: string;
  lease_ttl_ms: number;
  expires_at_ms: number;
}

/**
 * POST /sessions/{id}/policy as the authenticated holder. Returns the signed lease blob and
 * its expiry. Throws on non-200 or a malformed response.
 */
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

/**
 * POST /sessions/{id}/policy without throwing on failure.
 * Returns { status, body } so callers can assert specific error codes (409 on admin END, 401 on logout).
 */
async function fetchSessionPolicyRaw(sess: CPSession, sessionId: string): Promise<{ status: number; body: string }> {
  const r = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sessionId)}/policy`, {
    method: "POST",
    headers: authHeaders(sess),
  });
  const body = await r.text();
  return { status: r.status, body };
}

/**
 * POST /sessions/{id}/end as an authenticated admin.
 * Returns { status, body }; 200 on success.
 */
async function adminEndSession(adminSess: CPSession, sessionId: string): Promise<{ status: number; body: string }> {
  const r = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sessionId)}/end`, {
    method: "POST",
    headers: authHeaders(adminSess),
  });
  const body = await r.text();
  return { status: r.status, body };
}

/**
 * POST /auth/logout using the caller's own cookie + CSRF.
 * Returns 204 on success (always, per implementation — stale tokens are silently accepted).
 */
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

/** Count how many control messages of a given type have arrived on a page so far. */
async function countControlMsgsByType(page: Page, msgType: string): Promise<number> {
  return page.evaluate((t) => {
    const r = (window as unknown as { rmt?: { controlReceived?: { t: string }[] } }).rmt;
    return (r?.controlReceived ?? []).filter((m) => m.t === t).length;
  }, msgType);
}

/**
 * Wait until the count of control messages of `msgType` exceeds `prevCount`.
 * Returns true if the condition is met within the timeout, false otherwise.
 */
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

// ── Fixture config parsed from cptestfixture stdout ──────────────────────────────────────────────

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

// ── Test suite ──────────────────────────────────────────────────────────────────────────────────

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
// cptestfixture stdout: FIXTURE_SESSION_END lines record each agent end report (docs/49).
let cpLog = "";
let agentPid = 0;
let grantPubkey = "";
let fixtureCfg: FixtureConfig | null = null;

test.describe("Secure live transport gate (pass16 — real-auth fixture)", () => {
  test.beforeAll(async () => {
    test.setTimeout(240_000);

    if (!existsSync(AGENT_BIN)) {
      skipReason = `agent binary not found at ${AGENT_BIN} — build with: cargo build -p rmt-agent-windows --bin agent_host --features test-harness,secure-test`;
      return;
    }
    if (!existsSync(SIGNALING_EXE)) {
      skipReason = `signaling binary missing — globalSetup should have built it`;
      return;
    }
    if (!existsSync(CPTESTFIXTURE_EXE)) {
      skipReason = `cptestfixture binary not found at ${CPTESTFIXTURE_EXE} — build with: go build -o cptestfixture.exe ./cmd/cptestfixture (in control-plane/)`;
      return;
    }

    workDir = mkdtempSync(join(tmpdir(), "rmt-secure-live-gate-"));

    // ── Start cptestfixture — real SessionAuthenticator, NO StubAuthenticator/CP_INSECURE_DEV ──
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

    // Parse the FIXTURE_READY JSON line the fixture prints on startup.
    await new Promise<void>((res, rej) => {
      let buf = "";
      const timeout = setTimeout(() => rej(new Error("cptestfixture did not print FIXTURE_READY within 30s")), 30_000);
      cpProc!.stdout?.on("data", (d: Buffer) => {
        buf += d.toString();
        cpLog += d.toString();
        process.stdout.write(`[cp-gate] ${d}`);
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
      cpProc!.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp-gate:err] ${d}`));
    });

    if (!fixtureCfg) throw new Error("cptestfixture: no fixture config parsed");
    grantPubkey = fixtureCfg.grant_issuer_pubkey;
    tenantId = fixtureCfg.tenant_id;
    console.log(`[e2e] fixture ready — tenant=${tenantId} grant_issuer_pubkey=${grantPubkey}`);

    // Wait for the CP to accept HTTP requests. cptestfixture has no /healthz route (that lives
    // only in cmd/controlplane/main.go); probe with GET /grant/pubkey which returns 401 (any
    // HTTP response means the server is up — httpReachable accepts non-2xx).
    if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`, 500), 15_000))) {
      throw new Error(`cptestfixture did not start serving on :${CP_PORT}`);
    }

    // ── Smoke: anonymous POST /sessions must return 401 ─────────────────────────────────
    // This is the KEY CHECK that was false in pass15: in StubAuth mode this returns 200;
    // with real SessionAuthenticator it must return 401.
    const anonResp = await fetch(`${CP_BASE}/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ machine_id: "any-id" }),
    });
    if (anonResp.status !== 401) {
      throw new Error(
        `FIXTURE FAIL: anonymous POST /sessions returned ${anonResp.status}, want 401. ` +
        `StubAuthenticator or CP_INSECURE_DEV may still be in effect.`,
      );
    }
    console.log(`[e2e] anonymous POST /sessions → ${anonResp.status} 401 CONFIRMED (no StubAuth bypass)`);

    // ── Smoke: anonymous GET /grant/pubkey must return 401 ───────────────────────────────
    const anonGrantResp = await fetch(`${CP_BASE}/grant/pubkey`);
    if (anonGrantResp.status !== 401) {
      throw new Error(
        `FIXTURE FAIL: anonymous GET /grant/pubkey returned ${anonGrantResp.status}, want 401. ` +
        `SessionAuthenticator may not be enforcing on GET endpoints.`,
      );
    }
    console.log(`[e2e] anonymous GET /grant/pubkey → ${anonGrantResp.status} 401 CONFIRMED`);

    // ── Login as Admin to mint the enrollment token ───────────────────────────────────────
    const adminSess = await loginToCP(tenantId, fixtureCfg.admin_email, fixtureCfg.admin_password);
    console.log(`[e2e] admin login OK — user_id=${adminSess.userID}`);

    // ── Read grant pubkey (authenticated) ─────────────────────────────────────────────────
    const pkBody = await fetch(`${CP_BASE}/grant/pubkey`, {
      headers: authHeaders(adminSess),
    }).then((r) => r.json()) as { grant_issuer_pubkey?: string };
    if (pkBody.grant_issuer_pubkey !== grantPubkey) {
      throw new Error(`grant_issuer_pubkey mismatch: fixture says ${grantPubkey}, GET returns ${pkBody.grant_issuer_pubkey}`);
    }
    console.log(`[e2e] grant_issuer_pubkey=${grantPubkey} (verified via authenticated GET)`);

    // ── Wrong-CSRF probe — session cookie present + wrong X-CSRF-Token must 403 ──────────
    // csrfMiddleware: expected = csrfTokenFor(sessionToken); mismatch on header or rmt_csrf cookie → 403.
    const wrongCsrfResp = await fetch(`${CP_BASE}/sessions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cookie": `cp_session=${adminSess.sessionCookie}; rmt_csrf=wrong-csrf-value`,
        "x-csrf-token": "wrong-csrf-value",
      },
      body: JSON.stringify({ machine_id: "any-id" }),
    });
    if (wrongCsrfResp.status !== 403) {
      throw new Error(
        `FIXTURE FAIL: wrong-CSRF POST /sessions returned ${wrongCsrfResp.status}, want 403. ` +
        `CSRF middleware may be absent or bypassed.`,
      );
    }
    console.log(`[e2e] wrong-CSRF POST /sessions → ${wrongCsrfResp.status} 403 CONFIRMED`);

    // ── Pre-agent A/B login — verify exact fixture IDs before agent launch ───────────────
    // Per codex-fixture-pass16-review §3: assert userIDs equal the fixture's fixed IDs (not just differ).
    // Fails early if fixture wiring is wrong, before the agent is launched.
    const earlyTechASess = await loginToCP(tenantId, fixtureCfg.tech_a_email, fixtureCfg.tech_a_password);
    const earlyTechBSess = await loginToCP(tenantId, fixtureCfg.tech_b_email, fixtureCfg.tech_b_password);
    if (earlyTechASess.userID !== fixtureCfg.tech_a_id) {
      throw new Error(`FIXTURE FAIL: TechA login returned userID=${earlyTechASess.userID}, want fixture tech_a_id=${fixtureCfg.tech_a_id}`);
    }
    if (earlyTechBSess.userID !== fixtureCfg.tech_b_id) {
      throw new Error(`FIXTURE FAIL: TechB login returned userID=${earlyTechBSess.userID}, want fixture tech_b_id=${fixtureCfg.tech_b_id}`);
    }
    if (earlyTechASess.userID === earlyTechBSess.userID) {
      throw new Error(`FIXTURE FAIL: TechA and TechB share the same userID=${earlyTechASess.userID} — must be distinct`);
    }
    console.log(`[e2e] pre-agent A/B login OK — TechA=${earlyTechASess.userID} TechB=${earlyTechBSess.userID} DISTINCT, both match fixture IDs`);

    // ── Mint enrollment token (admin-authenticated) ───────────────────────────────────────
    const tokenBody = await fetch(`${CP_BASE}/enrollment-tokens`, {
      method: "POST",
      headers: authHeaders(adminSess),
      body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
    }).then((r) => r.json()) as { token?: string };
    const enrollToken = tokenBody.token;
    if (!enrollToken) throw new Error("POST /enrollment-tokens returned no token");
    console.log(`[e2e] enrollment token minted (admin-authenticated)`);

    // ── Enroll the agent ──────────────────────────────────────────────────────────────────
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
         "--name", "E2E-SecureLiveGate-P16", "--config", configPath],
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
    console.log(`[e2e] enrolled device=${deviceId} tenant=${tenantId}`);

    // ── Signaling ────────────────────────────────────────────────────────────────────────
    sigProc = spawn(
      SIGNALING_EXE,
      ["-addr", `127.0.0.1:${SIG_PORT}`, "--heartbeat-ttl", "300s"],
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
    sigProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[sig-gate] ${d}`));
    sigProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[sig-gate:err] ${d}`));
    if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000))) {
      throw new Error(`enforcing signaling did not come up on :${SIG_PORT}`);
    }

    // ── Agent ─────────────────────────────────────────────────────────────────────────────
    let secureTestActive = false;
    let secureProfileBlocked = false;
    let agentStarted = false;

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
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    agentPid = agentProc.pid ?? 0;

    agentProc.stdout?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLog += s;
      process.stdout.write(`[agent-gate] ${s}`);
      if (s.includes("multi_session_capable=true")) agentStarted = true;
      if (s.includes("secure-test-harness mode")) secureTestActive = true;
      if (s.includes("secure profile BLOCKED")) secureProfileBlocked = true;
    });
    agentProc.stderr?.on("data", (d: Buffer) => {
      const s = d.toString();
      agentLog += s;
      process.stdout.write(`[agent-gate:err] ${s}`);
      if (s.includes("multi_session_capable=true")) agentStarted = true;
      if (s.includes("secure-test-harness mode")) secureTestActive = true;
      if (s.includes("secure profile BLOCKED")) secureProfileBlocked = true;
    });
    agentProc.on("exit", (code) => process.stdout.write(`[agent-gate] exited code=${code}\n`));

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
    await sleep(800);

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

  test(
    "live transport gate: A/B independently authenticated, technician_id verified, grant denied on both (structural)",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(120_000);

      // ── Evidence capture ──────────────────────────────────────────────────────────────
      const agentBinHash = await sha256File(AGENT_BIN);
      console.log(`[e2e] agent_host.exe SHA-256: ${agentBinHash}`);
      console.log(`[e2e] agent PID: ${agentPid}`);
      console.log(`[e2e] grant_issuer_pubkey: ${grantPubkey}`);

      // ── Log in as TechA and TechB with distinct credentials ───────────────────────────
      const techASess = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);

      expect(techASess.userID, "TechA user_id must be non-empty").not.toBe("");
      expect(techBSess.userID, "TechB user_id must be non-empty").not.toBe("");
      expect(techASess.userID, "TechA and TechB must be distinct users").not.toBe(techBSess.userID);
      // Per codex-fixture-pass16-review §3: assert exact fixture IDs, not just non-empty/differ.
      expect(techASess.userID, "TechA user_id must equal fixed fixture tech_a_id").toBe(fixtureCfg!.tech_a_id);
      expect(techBSess.userID, "TechB user_id must equal fixed fixture tech_b_id").toBe(fixtureCfg!.tech_b_id);
      console.log(`[e2e] TechA user_id=${techASess.userID}`);
      console.log(`[e2e] TechB user_id=${techBSess.userID}`);

      // ── Mint independent tickets — each authenticated as a different user ─────────────
      const bodyA = await mintTicket(techASess, deviceId);
      const bodyB = await mintTicket(techBSess, deviceId);

      const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessionA = (bodyA.session as { technician_id?: string; id?: string } | undefined);
      const sessionB = (bodyB.session as { technician_id?: string; id?: string } | undefined);

      const ticketA = sigA?.ticket;
      const ticketB = sigB?.ticket;
      const sidA = sigA?.session_id ?? sessionA?.id ?? "";
      const sidB = sigB?.session_id ?? sessionB?.id ?? "";
      const techIdA = sessionA?.technician_id ?? "";
      const techIdB = sessionB?.technician_id ?? "";

      if (!ticketA || !ticketB) {
        throw new Error(
          `POST /sessions did not return tickets. A=${JSON.stringify(bodyA)}, B=${JSON.stringify(bodyB)}`,
        );
      }

      // ── Core auth assertion: technician_id matches authenticated user ─────────────────
      expect(techIdA, "session A technician_id must equal TechA user_id").toBe(techASess.userID);
      expect(techIdB, "session B technician_id must equal TechB user_id").toBe(techBSess.userID);
      expect(techIdA, "session A and B technician_id must differ (distinct users)").not.toBe(techIdB);
      expect(sidA, "each technician gets a distinct session_id").not.toBe(sidB);
      expect(sidA, "sidA must be non-empty").not.toBe("");
      expect(sidB, "sidB must be non-empty").not.toBe("");

      console.log(`[e2e] TechA session: session_id=${sidA} technician_id=${techIdA}`);
      console.log(`[e2e] TechB session: session_id=${sidB} technician_id=${techIdB}`);
      console.log(`[e2e] technician_id assertion: A=${techIdA} B=${techIdB} — DISTINCT and correct`);

      const pageA = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA));
      const pageB = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB));

      // ── Both reach connected + receive video ──────────────────────────────────────────
      await Promise.all([
        waitForConnected(pageA, 30_000),
        waitForConnected(pageB, 30_000),
      ]);
      console.log("[e2e] A and B reached WebRTC connected with independent CP-signed tickets");

      await Promise.all([
        waitForVideo(pageA, "techA"),
        waitForVideo(pageB, "techB"),
      ]);
      console.log("[e2e] A and B independently receiving VP8 video — enforcing admission confirmed");

      // ── Phase: Tech A installs a valid grant ──────────────────────────────────────────
      const logBeforeGrant = agentLog.length;

      const signedGrantJson = await mintGrant(techASess, deviceId, sidA);
      console.log(`[e2e] minted grant for session=${sidA} (${signedGrantJson.length} bytes)`);

      await pageA.evaluate((grantJson) => {
        const rmt = (window as unknown as { rmt?: { installGrant?: (g: string) => void } }).rmt;
        if (!rmt?.installGrant) throw new Error("harness: installGrant not available");
        rmt.installGrant(grantJson);
      }, signedGrantJson);
      console.log("[e2e] InstallGrant sent on Control channel (tech A)");

      await waitForControlMsg(pageA, "GrantInstalled", 12_000);
      console.log("[e2e] GrantInstalled ack received on tech A Control channel");

      const grantLogFound = await waitForAgentLogSlice(
        logBeforeGrant,
        "signed grant verified; execution is structurally denied",
        2_000,
      );
      expect(
        grantLogFound,
        "agent log must confirm verify_grant_inert path (structural denial, no Dispatcher)",
      ).toBe(true);
      console.log("[e2e] agent log confirms: verify_grant_inert ran, no Dispatcher constructed");

      // ── Phase: Tech A backstage RPC after grant — must be denied ─────────────────────
      const logBeforeBackstageA = agentLog.length;

      await pageA.evaluate(() => {
        const rmt = (window as unknown as { rmt?: { sendBackstageRequest?: (j: string) => void } }).rmt;
        if (!rmt?.sendBackstageRequest) throw new Error("harness: sendBackstageRequest not available");
        rmt.sendBackstageRequest('{"type":"GetSystemInfo"}');
      });
      console.log("[e2e] GetSystemInfo backstage request sent (tech A, post-grant)");

      const backstageRespA = await waitForBackstageResponse(pageA, 10_000);
      console.log(`[e2e] tech A backstage response: ${backstageRespA}`);

      expect(backstageRespA, "post-grant backstage response must be denial JSON").toContain('"ok":false');
      expect(backstageRespA).toContain('"kind":"denied"');
      console.log("[e2e] tech A backstage denial confirmed — no Dispatcher means execution is impossible");

      const backstageLogAFound = await waitForAgentLogSlice(
        logBeforeBackstageA,
        "secure-test-harness: backstage request received after grant verification",
        2_000,
      );
      expect(
        backstageLogAFound,
        "agent log must confirm the post-grant backstage denial path",
      ).toBe(true);
      console.log("[e2e] agent log confirms: post-grant backstage path triggered");

      // ── Phase: Tech B backstage RPC without grant — also denied ──────────────────────
      const logBeforeBackstageB = agentLog.length;

      await pageB.evaluate(() => {
        const rmt = (window as unknown as { rmt?: { sendBackstageRequest?: (j: string) => void } }).rmt;
        if (!rmt?.sendBackstageRequest) throw new Error("harness: sendBackstageRequest not available");
        rmt.sendBackstageRequest('{"type":"GetSystemInfo"}');
      });
      console.log("[e2e] GetSystemInfo backstage request sent (tech B, no grant)");

      const backstageRespB = await waitForBackstageResponse(pageB, 10_000);
      console.log(`[e2e] tech B backstage response: ${backstageRespB}`);

      expect(backstageRespB, "no-grant backstage response must be denial JSON").toContain('"ok":false');
      expect(backstageRespB).toContain('"kind":"denied"');
      console.log("[e2e] tech B (no grant) backstage denial confirmed — fail-closed on both paths");

      const needlesB = ["no valid grant installed", "no grant installed", "backstage request with no grant"];
      let backstageLogBFound = false;
      {
        const deadline = Date.now() + 2_000;
        for (;;) {
          const slice = agentLog.slice(logBeforeBackstageB);
          if (needlesB.some((n) => slice.includes(n))) { backstageLogBFound = true; break; }
          if (Date.now() >= deadline) break;
          await sleep(50);
        }
      }
      expect(
        backstageLogBFound,
        "agent log must confirm the no-grant denial path for tech B",
      ).toBe(true);
      console.log("[e2e] agent log confirms: no-grant backstage denial path for tech B");

      // ── Summary evidence ──────────────────────────────────────────────────────────────
      console.log(`\n[e2e] PASS — secure live transport gate evidence (pass16 real-auth):`);
      console.log(`  agent_host.exe SHA-256: ${agentBinHash}`);
      console.log(`  agent PID:              ${agentPid}`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  tenant_id:              ${tenantId}`);
      console.log(`  grant_issuer_pubkey:    ${grantPubkey}`);
      console.log(`  TechA user_id:          ${techASess.userID}`);
      console.log(`  TechB user_id:          ${techBSess.userID}`);
      console.log(`  session A (tech A):     ${sidA}  technician_id=${techIdA}`);
      console.log(`  session B (tech B):     ${sidB}  technician_id=${techIdB}`);
      console.log(`  technician_ids DIFFER:  ${techIdA !== techIdB}`);
      console.log(`  grant response (bytes): ${signedGrantJson.length}`);
      console.log(`  GrantInstalled ack:     YES`);
      console.log(`  A post-grant denial:    ${backstageRespA.slice(0, 120)}`);
      console.log(`  B no-grant denial:      ${backstageRespB.slice(0, 120)}`);
      console.log(`  Auth method:            real SessionAuthenticator (no StubAuth, no CP_INSECURE_DEV)\n`);

      await pageA.close();
      await pageB.close();
    },
  );

  // ── Pass18: signed session-policy lease isolation ───────────────────────────────────────────────
  //
  // Extends the pass17 real-auth baseline with:
  //   1. POST /sessions/{id}/policy (each owner's own auth) → signed blob forwarded byte-exact via
  //      InstallSessionPolicy control channel → SessionPolicyInstalled ack per page.
  //   2. B renews with a fresh POST + InstallSessionPolicy; new ack arrives at a count > install #1.
  //   3. A stops renewal; wait through A's actual signed expiry_at_ms plus 8 s scheduling allowance.
  //   4. Assert A session teardown is correlated: exact [SESSION:TEARDOWN:DONE session=A] from offset; inbound RTP frozen (media plane, supplementary).
  //   5. Assert input isolation: key=200 NOT admitted after A teardown; B key=202 IS admitted in same window (positive control).
  //   6. Assert B has new inbound-RTP bytes after A ends; B's recorded input admitted via coordinator.
  //   7. Negative controls:
  //      a. Cross-user renewal (HTTP): B POST /sessions/{sidA}/policy → 403 Forbidden.
  //      b. Cross-session policy (agent): A's valid signed blob sent to B's agent → agent rejects
  //         (session_id mismatch), Error control msg received, no new SessionPolicyInstalled on B.
  //   Both pages stay open until all assertions complete.
  test(
    "pass18: signed session-policy install, A lease expires while B renews — bounded expiry isolation",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(180_000);

      // ── Fresh sessions for this test ──────────────────────────────────────────────────────────
      const techASess = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);

      const bodyA = await mintTicket(techASess, deviceId);
      const bodyB = await mintTicket(techBSess, deviceId);

      const sigA18 = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB18 = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessA18 = (bodyA.session as { id?: string } | undefined);
      const sessB18 = (bodyB.session as { id?: string } | undefined);

      const ticketA18 = sigA18?.ticket;
      const ticketB18 = sigB18?.ticket;
      const sidA18 = sigA18?.session_id ?? sessA18?.id ?? "";
      const sidB18 = sigB18?.session_id ?? sessB18?.id ?? "";

      if (!ticketA18 || !ticketB18) throw new Error(`pass18: no tickets from POST /sessions. A=${JSON.stringify(bodyA)} B=${JSON.stringify(bodyB)}`);
      if (!sidA18 || !sidB18) throw new Error(`pass18: no session IDs. A=${sidA18} B=${sidB18}`);
      expect(sidA18, "pass18: sidA must differ from sidB").not.toBe(sidB18);

      console.log(`[pass18] sidA=${sidA18} sidB=${sidB18}`);

      // ── Open pages and wait for connected + video ─────────────────────────────────────────────
      const pageA18 = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA18));
      const pageB18 = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB18));

      await Promise.all([
        waitForConnected(pageA18, 30_000),
        waitForConnected(pageB18, 30_000),
      ]);
      console.log("[pass18] A and B reached WebRTC connected");

      await Promise.all([
        waitForVideo(pageA18, "p18-techA"),
        waitForVideo(pageB18, "p18-techB"),
      ]);
      console.log("[pass18] A and B independently receiving VP8 video — confirmed before policy install");

      // ── Phase 1: Install signed session policies for A and B ─────────────────────────────────
      // Each policy is fetched from the CP using the owner's own authenticated session. The signed
      // blob is forwarded byte-exact over the Control channel — no re-encoding or modification.

      const leaseA1 = await fetchSessionPolicy(techASess, sidA18);
      console.log(`[pass18] A: fetched initial policy — access=${leaseA1.access} expires_at_ms=${leaseA1.expires_at_ms} lease_ttl_ms=${leaseA1.lease_ttl_ms}`);

      const aAckCount0 = await countControlMsgsByType(pageA18, "SessionPolicyInstalled");
      await pageA18.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA1.signed);
      console.log("[pass18] A: InstallSessionPolicy sent over Control channel");

      const aAckOk = await waitForNewControlMsgOfType(pageA18, "SessionPolicyInstalled", aAckCount0, 15_000);
      expect(aAckOk, "pass18 A: SessionPolicyInstalled ack must arrive within 15 s of install").toBe(true);
      const aAckCount1 = await countControlMsgsByType(pageA18, "SessionPolicyInstalled");
      console.log(`[pass18] A: SessionPolicyInstalled ack confirmed (ack count=${aAckCount1})`);

      const leaseB1 = await fetchSessionPolicy(techBSess, sidB18);
      console.log(`[pass18] B: fetched initial policy — access=${leaseB1.access} expires_at_ms=${leaseB1.expires_at_ms} lease_ttl_ms=${leaseB1.lease_ttl_ms}`);

      const bAckCount0 = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");
      await pageB18.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB1.signed);
      console.log("[pass18] B: InstallSessionPolicy sent over Control channel");

      const bAckOk = await waitForNewControlMsgOfType(pageB18, "SessionPolicyInstalled", bAckCount0, 15_000);
      expect(bAckOk, "pass18 B: SessionPolicyInstalled ack must arrive within 15 s of install").toBe(true);
      const bAckCount1 = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");
      console.log(`[pass18] B: SessionPolicyInstalled ack confirmed (ack count=${bAckCount1})`);

      // ── Phase 2: B renews — offset-correlated ack ─────────────────────────────────────────────
      // Send a second POST /sessions/{sidB}/policy → fresh signed blob → new ack on B at
      // count > bAckCount1. This proves the renewal path works and produces a fresh credential
      // with its own expiry, correlated by the count offset.
      await sleep(1_000); // ensure distinct issued_at_ms

      const leaseB2 = await fetchSessionPolicy(techBSess, sidB18);
      console.log(`[pass18] B: fetched renewal policy — expires_at_ms=${leaseB2.expires_at_ms}`);

      await pageB18.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB2.signed);
      console.log("[pass18] B: renewal InstallSessionPolicy sent");

      const bRenewOk = await waitForNewControlMsgOfType(pageB18, "SessionPolicyInstalled", bAckCount1, 15_000);
      expect(bRenewOk, "pass18 B: renewed SessionPolicyInstalled must arrive at count > initial install").toBe(true);
      const bAckCount2 = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");
      expect(bAckCount2, "B renewal ack count must be strictly greater than install ack count").toBeGreaterThan(bAckCount1);
      console.log(`[pass18] B: renewal ack confirmed — count increased from ${bAckCount1} → ${bAckCount2} (offset-correlated)`);

      // ── Phase 3: Negative control — cross-user HTTP renewal ───────────────────────────────────
      // B attempts POST /sessions/{sidA}/policy using B's own auth (different user_id than A's
      // session's technician_id). CP must refuse with 403 ("only the technician holding this
      // session may renew it"). This is a pure HTTP check with no side-effect on either session.
      const crossUserResp = await fetch(`${CP_BASE}/sessions/${encodeURIComponent(sidA18)}/policy`, {
        method: "POST",
        headers: authHeaders(techBSess),
      });
      expect(
        crossUserResp.status,
        "cross-user renewal: B POST /sessions/{sidA}/policy must be rejected with 403",
      ).toBe(403);
      console.log(`[pass18] cross-user renewal: B tried POST /sessions/${sidA18}/policy → ${crossUserResp.status} 403 CONFIRMED`);

      // ── Phase 4 preamble: pre-admission key events to bind coordinator session IDs ─────────────
      // Send distinct valid Key events while A is still live to establish coordinator-session
      // bindings. Key codes 200 (A) and 201 (B) are distinct from any other test in this suite.
      // The [SESSION:ADMITTED_INPUT] log lines assign coordinator IDs used to validate teardown
      // isolation below. Log offset is captured here so prior sessions (from test 1) cannot
      // falsely satisfy the teardown or input assertions.
      const logBefore18 = agentLog.length;

      await pageA18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 200, down: true },
        });
      });

      let aSessionId18 = "";
      const aAdmitted18 = await waitFor(async () => {
        const delta = agentLog.slice(logBefore18);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=200 first_holder=true/);
        if (m) { aSessionId18 = m[1]; return true; }
        return false;
      }, 8_000);
      expect(aAdmitted18, "pass18 A: key=200 must be admitted by coordinator (first_holder=true) before expiry").toBe(true);
      console.log(`[pass18] A: pre-admission confirmed session=${aSessionId18} key=200`);

      await pageB18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 201, down: true },
        });
      });

      let bSessionId18 = "";
      const bAdmitted18 = await waitFor(async () => {
        const delta = agentLog.slice(logBefore18);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=201 first_holder=true/);
        if (m) { bSessionId18 = m[1]; return true; }
        return false;
      }, 8_000);
      expect(bAdmitted18, "pass18 B: key=201 must be admitted by coordinator (first_holder=true)").toBe(true);
      expect(bSessionId18, "pass18 B/A: coordinator session IDs must be distinct").not.toBe(aSessionId18);
      console.log(`[pass18] B: pre-admission confirmed session=${bSessionId18} key=201`);
      console.log(`[pass18] A session=${aSessionId18} B session=${bSessionId18} — DISTINCT coordinator IDs`);

      // Release held keys before the expiry wait (clean coordinator state).
      await pageA18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 200, down: false },
        });
      });
      await pageB18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 201, down: false },
        });
      });
      console.log("[pass18] pre-admission keys released — entering A-expiry wait");

      // ── Phase 4: Keep B alive while A's lease runs out ────────────────────────────────────────
      // A's policy expires at leaseA1.expires_at_ms. We wait until expires_at_ms + 8 s (scheduling
      // allowance — enough for the agent's 2 s LEASE_TICK to fire at least 4 times past expiry).
      // During this window we keep renewing B so it does not also expire.
      const expiresAtMsA = leaseA1.expires_at_ms;
      const waitUntilMs = expiresAtMsA + 8_000;
      let bCurrentAckCount = bAckCount2;
      let bCurrentExpiry = leaseB2.expires_at_ms;

      console.log(`[pass18] A's signed expiry: ${expiresAtMsA} (now=${Date.now()}); waiting until ${waitUntilMs} (+8 s allowance)`);
      console.log(`[pass18] STOP renewing A; keep renewing B every 10 s`);

      // Renewal loop: renew B every 10 s until A's expiry+8 s has passed.
      while (Date.now() < waitUntilMs) {
        const msLeft = waitUntilMs - Date.now();
        const sleepMs = Math.min(10_000, msLeft > 1_000 ? msLeft : 1_000);
        await sleep(sleepMs);

        if (Date.now() >= waitUntilMs) break;

        // Renew B if its lease has less than 12 s remaining, or always if we're near the deadline.
        if (bCurrentExpiry - Date.now() < 20_000 || waitUntilMs - Date.now() < 15_000) {
          const leaseBN = await fetchSessionPolicy(techBSess, sidB18);
          await pageB18.evaluate((sp) => {
            const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
            if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
            rmt.installSessionPolicy(sp);
          }, leaseBN.signed);
          const bNewAckOk = await waitForNewControlMsgOfType(pageB18, "SessionPolicyInstalled", bCurrentAckCount, 15_000);
          expect(bNewAckOk, "pass18 B: mid-wait renewal SessionPolicyInstalled ack must arrive — renewal failure is a test failure").toBe(true);
          bCurrentAckCount = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");
          bCurrentExpiry = leaseBN.expires_at_ms;
          console.log(`[pass18] B: mid-wait renewal OK — ack count=${bCurrentAckCount} expires_at_ms=${bCurrentExpiry}`);
        }
      }

      console.log(`[pass18] Past A's expiry (${expiresAtMsA}) + 8 s allowance — asserting A teardown`);

      // ── Phase 5: Assert A session teardown ────────────────────────────────────────────────────
      //
      // DEFINITIVE EVIDENCE: the agent log. When the lease lapses the agent prints
      // "session lease EXPIRED" and "[SESSION:TEARDOWN:DONE]" — that IS the correlated teardown.
      // The browser-side WebRTC ICE state may lag the agent-side close by up to 5–30 s (ICE
      // keepalive timeout), so we poll for it separately but do not require it to confirm teardown.

      // 5a. Agent log — definitive teardown evidence.
      // Poll from the pre-admission offset so prior sessions (test 1 cleanup) cannot satisfy this.
      // The exact marker [SESSION:TEARDOWN:DONE session=<aSessionId18>] proves A's coordinator was
      // cleaned up after its specific lease expiry, not any other session's teardown.
      const aTornDown18 = await waitFor(async () => {
        return agentLog.slice(logBefore18).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId18}]`);
      }, 20_000);
      expect(
        aTornDown18,
        `pass18: agent log must contain [SESSION:TEARDOWN:DONE session=${aSessionId18}] from offset — exact correlation`,
      ).toBe(true);
      console.log(`[pass18] [SESSION:TEARDOWN:DONE session=${aSessionId18}] confirmed from offset (definitive)`);

      // B must NOT have been torn down — its session must remain live.
      expect(
        agentLog.slice(logBefore18).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId18}]`),
        `pass18: B session=${bSessionId18} must NOT be torn down while A expires`,
      ).toBe(false);
      console.log(`[pass18] B session=${bSessionId18} teardown absent — correct isolation`);

      const logAfterTeardown18 = agentLog.length;

      // 5b. RTP bytes frozen (media plane, supplementary — input isolation is proven separately via ADMITTED_INPUT below).
      // Wait an additional 3 s for any in-flight WebRTC packets to drain, then take two snapshots
      // 3 s apart. If the agent stopped sending to A, bytesReceived must not grow.
      await sleep(3_000);
      const rtpA_snap1 = await pageA18.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        if (!r) return 0;
        return (await r.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpA_snap2 = await pageA18.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        if (!r) return 0;
        return (await r.inboundVideo())?.bytesReceived ?? 0;
      });
      // After agent-side teardown, no new RTP packets should arrive.
      // Allow a small epsilon for WebRTC RTCP/keepalive overhead that is not video payload.
      expect(
        rtpA_snap2,
        `pass18 A: inbound RTP bytes must be frozen after agent teardown (snap1=${rtpA_snap1} snap2=${rtpA_snap2})`,
      ).toBeLessThanOrEqual(rtpA_snap1 + 5_000);
      console.log(`[pass18] A: inbound RTP bytes frozen: snap1=${rtpA_snap1} snap2=${rtpA_snap2} (supplementary; input isolation proven separately)`);

      // 5c. Browser state (supplementary, polled up to 15 s more — ICE detection lag).
      let stateA = await pageA18.evaluate(() => (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown");
      if (stateA === "connected") {
        // Give the browser time to detect the remote close via ICE timeout.
        await waitFor(async () => {
          stateA = await pageA18.evaluate(() => (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown");
          return stateA !== "connected";
        }, 15_000);
      }
      // Log the final observed state without hard-failing on it: the agent log and frozen RTP are
      // the reliable evidence; the browser ICE state is supplementary and timing-dependent.
      console.log(`[pass18] A: browser connection state = "${stateA}" (supplementary; agent log is definitive)`);

      // ── Phase 6: Assert B alive after A ends ──────────────────────────────────────────────────
      // B's session must still be connected and receiving video. Snapshot RTP bytes, sleep 2 s,
      // confirm bytes increased — proving the agent is still streaming to B after A's teardown.
      const stateB = await pageB18.evaluate(() => {
        return (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown";
      });
      expect(stateB, `pass18 B: state must still be "connected" after A expired (got "${stateB}")`).toBe("connected");
      console.log(`[pass18] B: connection state = "${stateB}" — still alive after A expired`);

      // NEW video bytes on B AFTER A's teardown window: take two snapshots 3 s apart.
      const rtpB_snap1 = await pageB18.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        if (!r) return 0;
        return (await r.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpB_snap2 = await pageB18.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        if (!r) return 0;
        return (await r.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(
        rtpB_snap2,
        `pass18 B: NEW inbound-RTP bytes must arrive after A ends (snap1=${rtpB_snap1} snap2=${rtpB_snap2})`,
      ).toBeGreaterThan(rtpB_snap1);
      console.log(`[pass18] B: NEW video bytes confirmed after A teardown (${rtpB_snap1} → ${rtpB_snap2})`);

      // ── Input isolation: A must not be admitted after teardown; B must be admitted ──────────────
      // A post-expiry send uses honest outcome capture (transport may be closed — DataChannel.send
      // throws on a closed channel). Whether it throws or silently fails, no new ADMITTED_INPUT
      // for A's coordinator session must appear in a bounded window.
      const aPostExpirySendOutcome = await pageA18.evaluate(() => {
        try {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 200, down: true },
          });
          return "sent";
        } catch (e) {
          return `closed:${String(e)}`;
        }
      }).catch((e: unknown) => `eval-err:${String(e)}`);
      console.log(`[pass18] A post-expiry send outcome: ${aPostExpirySendOutcome} (honest; channel may be closed)`);

      // B sends a valid Key event with correct wire format — must be admitted in same bounded window.
      await pageB18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 202, down: true },
        });
      });
      console.log("[pass18] B: sent key=202 down (valid wire format {t,c}, live session)");

      // Observe ADMITTED_INPUT within 5 s: A's key=200 must NOT appear for aSessionId18;
      // B's key=202 MUST appear for bSessionId18 as positive control.
      const inputObsDeadline = Date.now() + 5_000;
      let bKey202Admitted = false;
      let aKey200AdmittedPostExpiry = false;
      while (Date.now() < inputObsDeadline) {
        const delta = agentLog.slice(logAfterTeardown18);
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${aSessionId18} key=200`)) {
          aKey200AdmittedPostExpiry = true;
        }
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${bSessionId18} key=202`)) {
          bKey202Admitted = true;
        }
        await sleep(50);
      }
      expect(
        aKey200AdmittedPostExpiry,
        `pass18 A: key=200 must NOT be admitted after session=${aSessionId18} teardown — session is dead`,
      ).toBe(false);
      expect(
        bKey202Admitted,
        `pass18 B: key=202 must be admitted for session=${bSessionId18} in same bounded window — B session live`,
      ).toBe(true);
      console.log(`[pass18] A: no ADMITTED_INPUT for key=200 after teardown — input isolation confirmed`);
      console.log(`[pass18] B: ADMITTED_INPUT for key=202 confirmed in same window — B session live`);

      // Release B's held key 202.
      await pageB18.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 202, down: false },
        });
      });
      console.log("[pass18] B: key=202 released");

      // ── Phase 7a: Negative control — cross-session policy at agent ────────────────────────────
      // Mint a fresh (non-expired) signed policy for ANOTHER live CP session of tech A. Its
      // session_id does NOT match B's binding (sidB18), so the agent must reject it with
      // SessionPolicyError::InvalidBinding and send an Error control message. A new
      // SessionPolicyInstalled must NOT appear on B.
      //
      // Not sidA18 any more: since docs/49 the agent reports A's lease lapse and the control plane
      // ENDS A's row, so a policy for sidA18 is refused (409). A second, never-connected session
      // row is still open and yields the same fresh, differently-bound policy.
      //
      // Using a FRESH policy (not the stale leaseA1) ensures the rejection is a session-binding
      // mismatch, not an expiry. The terminal rejection path (reject_unverified) is still exercised.
      const crossBody = await mintTicket(techASess, deviceId);
      const sidCross = (crossBody.signaling as { session_id?: string } | undefined)?.session_id
        ?? (crossBody.session as { id?: string } | undefined)?.id ?? "";
      if (!sidCross) throw new Error(`pass18 cross-session: no session id minted: ${JSON.stringify(crossBody)}`);
      expect(sidCross, "pass18 cross-session: a distinct session").not.toBe(sidB18);
      const leaseA_cross = await fetchSessionPolicy(techASess, sidCross);
      console.log(`[pass18] cross-session: minted fresh policy for a second A session ${sidCross} (expires_at_ms=${leaseA_cross.expires_at_ms}) — session_id≠sidB18`);

      const bErrorCount0 = await countControlMsgsByType(pageB18, "Error");
      const bSpiCount_before = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");

      await pageB18.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA_cross.signed); // a fresh signed policy bound to sidCross, not sidB18
      console.log("[pass18] cross-session: sent A's fresh signed policy to B's agent — expecting Error (session binding mismatch), no SessionPolicyInstalled");

      // Wait for Error control message.
      const crossErrFound = await waitFor(async () => {
        const n = await countControlMsgsByType(pageB18, "Error");
        return n > bErrorCount0;
      }, 10_000);
      expect(
        crossErrFound,
        "pass18 cross-session: agent must send an Error control message when policy session_id mismatches",
      ).toBe(true);

      const bSpiCount_after = await countControlMsgsByType(pageB18, "SessionPolicyInstalled");
      expect(
        bSpiCount_after,
        "pass18 cross-session: cross-session policy must NOT produce a new SessionPolicyInstalled on B",
      ).toBe(bSpiCount_before);
      console.log("[pass18] cross-session policy rejection confirmed (Error arrived, SessionPolicyInstalled count unchanged)");

      // ── Summary ───────────────────────────────────────────────────────────────────────────────
      const agentBinHash18 = await sha256File(AGENT_BIN);
      console.log("\n[pass18] PASS — signed session-policy lease isolation evidence:");
      console.log(`  agent_host.exe SHA-256: ${agentBinHash18}`);
      console.log(`  agent PID:              ${agentPid}`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  tenant_id:              ${tenantId}`);
      console.log(`  grant_issuer_pubkey:    ${grantPubkey}`);
      console.log(`  sidA:                   ${sidA18}`);
      console.log(`  sidB:                   ${sidB18}`);
      console.log(`  A coordinator session:  ${aSessionId18}  (from pre-expiry ADMITTED_INPUT key=200)`);
      console.log(`  B coordinator session:  ${bSessionId18}  (from pre-expiry ADMITTED_INPUT key=201, distinct)`);
      console.log(`  A: expires_at_ms:       ${expiresAtMsA}  (actual signed expiry)`);
      console.log(`  A: TEARDOWN:DONE:       session=${aSessionId18} confirmed from offset (exact correlation)`);
      console.log(`  B: ack count at end:    ${bCurrentAckCount}  (includes initial install + renewals)`);
      console.log(`  A: browser state:       ${stateA}  (agent TEARDOWN:DONE is definitive; ICE may lag)`);
      console.log(`  A: inbound RTP frozen:  snap1=${rtpA_snap1} snap2=${rtpA_snap2}  (media plane, supplementary)`);
      console.log(`  A: input isolation:     key=200 NOT admitted after teardown; send outcome=${aPostExpirySendOutcome}`);
      console.log(`  B: state after A ends:  ${stateB}  (still "connected")`);
      console.log(`  B: RTP bytes:           ${rtpB_snap1} → ${rtpB_snap2}  (growing)`);
      console.log(`  B: input admitted:      key=202 ADMITTED_INPUT in same window as A's no-admission`);
      console.log(`  Cross-user renewal:     HTTP 403 CONFIRMED`);
      console.log(`  Cross-session policy:   agent Error CONFIRMED (session_id mismatch), no new SessionPolicyInstalled\n`);

      await pageA18.close();
      await pageB18.close();
    },
  );

  // ── pass20-end ───────────────────────────────────────────────────────────────────────────────
  //
  // Authenticated Admin END A via POST /sessions/{sidA}/end → 200.
  //
  // What this proves:
  //   1. Admin END stamps ended_at on the session record (CP side only — no push to agent).
  //   2. Subsequent POST /sessions/{sidA}/policy → 409 ("session has ended").
  //   3. A's page stays open; the currently installed lease remains valid on the agent until it
  //      expires naturally. Admin END is not immediate remote termination.
  //   4. Once A's lease lapses, the agent tears down session A and logs [SESSION:TEARDOWN:DONE].
  //   5. A receives no input admission after teardown; B is admitted (positive control).
  //   6. B keeps renewing throughout and remains media + recording-input positive.
  //   7. B is never torn down during A's expiry window or the 5 s observation window.
  //
  // Key codes: 203 (A pre-bind), 204 (B pre-bind), 205 (A post-end attempt), 206 (B positive).
  test(
    "pass20-end: authenticated Admin END A → A renewal 409, bounded A lease expiry, B continuous media+input",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(180_000);

      // ── Fresh sessions for this test ──────────────────────────────────────────────────────────
      const techASess20 = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess20 = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);
      const adminSess20 = await loginToCP(tenantId, fixtureCfg!.admin_email, fixtureCfg!.admin_password);

      const bodyA20 = await mintTicket(techASess20, deviceId);
      const bodyB20 = await mintTicket(techBSess20, deviceId);

      const sigA20 = bodyA20.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB20 = bodyB20.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessA20rec = (bodyA20.session as { id?: string } | undefined);
      const sessB20rec = (bodyB20.session as { id?: string } | undefined);

      const ticketA20 = sigA20?.ticket;
      const ticketB20 = sigB20?.ticket;
      const sidA20 = sigA20?.session_id ?? sessA20rec?.id ?? "";
      const sidB20 = sigB20?.session_id ?? sessB20rec?.id ?? "";

      if (!ticketA20 || !ticketB20) throw new Error(`pass20-end: no tickets. A=${JSON.stringify(bodyA20)} B=${JSON.stringify(bodyB20)}`);
      if (!sidA20 || !sidB20) throw new Error(`pass20-end: no session IDs. A=${sidA20} B=${sidB20}`);
      expect(sidA20, "pass20-end: sidA must differ from sidB").not.toBe(sidB20);

      console.log(`[pass20-end] sidA=${sidA20} sidB=${sidB20}`);

      // ── Open pages and wait for connected + video ─────────────────────────────────────────────
      const pageA20 = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA20));
      const pageB20 = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB20));

      await Promise.all([
        waitForConnected(pageA20, 30_000),
        waitForConnected(pageB20, 30_000),
      ]);
      console.log("[pass20-end] A and B reached WebRTC connected");

      await Promise.all([
        waitForVideo(pageA20, "p20-end-techA"),
        waitForVideo(pageB20, "p20-end-techB"),
      ]);
      console.log("[pass20-end] A and B independently receiving VP8 video — confirmed before policy install");

      // ── Phase 1: Install initial signed leases for A and B ───────────────────────────────────
      const leaseA20_1 = await fetchSessionPolicy(techASess20, sidA20);
      console.log(`[pass20-end] A: initial policy — access=${leaseA20_1.access} expires_at_ms=${leaseA20_1.expires_at_ms}`);
      const aAck20_0 = await countControlMsgsByType(pageA20, "SessionPolicyInstalled");
      await pageA20.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA20_1.signed);
      const aAckOk20 = await waitForNewControlMsgOfType(pageA20, "SessionPolicyInstalled", aAck20_0, 15_000);
      expect(aAckOk20, "pass20-end A: initial SessionPolicyInstalled ack must arrive").toBe(true);
      const aAckCount20 = await countControlMsgsByType(pageA20, "SessionPolicyInstalled");
      console.log(`[pass20-end] A: SessionPolicyInstalled ack confirmed (count=${aAckCount20})`);

      const leaseB20_1 = await fetchSessionPolicy(techBSess20, sidB20);
      console.log(`[pass20-end] B: initial policy — access=${leaseB20_1.access} expires_at_ms=${leaseB20_1.expires_at_ms}`);
      const bAck20_0 = await countControlMsgsByType(pageB20, "SessionPolicyInstalled");
      await pageB20.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB20_1.signed);
      const bAckOk20 = await waitForNewControlMsgOfType(pageB20, "SessionPolicyInstalled", bAck20_0, 15_000);
      expect(bAckOk20, "pass20-end B: initial SessionPolicyInstalled ack must arrive").toBe(true);
      let bAckCount20 = await countControlMsgsByType(pageB20, "SessionPolicyInstalled");
      console.log(`[pass20-end] B: SessionPolicyInstalled ack confirmed (count=${bAckCount20})`);

      // ── Phase 2: Pre-bind coordinator session IDs (key=203 A, key=204 B) ────────────────────
      const logBefore20 = agentLog.length;

      await pageA20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 203, down: true },
        });
      });
      let aSessionId20 = "";
      const aAdmitted20 = await waitFor(async () => {
        const delta = agentLog.slice(logBefore20);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=203 first_holder=true/);
        if (m) { aSessionId20 = m[1]; return true; }
        return false;
      }, 8_000);
      expect(aAdmitted20, "pass20-end A: key=203 must be admitted (first_holder=true) before admin END").toBe(true);
      console.log(`[pass20-end] A: pre-bind confirmed session=${aSessionId20} key=203`);

      await pageB20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 204, down: true },
        });
      });
      let bSessionId20 = "";
      const bAdmitted20 = await waitFor(async () => {
        const delta = agentLog.slice(logBefore20);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=204 first_holder=true/);
        if (m) { bSessionId20 = m[1]; return true; }
        return false;
      }, 8_000);
      expect(bAdmitted20, "pass20-end B: key=204 must be admitted (first_holder=true)").toBe(true);
      expect(bSessionId20, "pass20-end: coordinator session IDs must be distinct").not.toBe(aSessionId20);
      console.log(`[pass20-end] B: pre-bind confirmed session=${bSessionId20} key=204`);
      console.log(`[pass20-end] A session=${aSessionId20} B session=${bSessionId20} — DISTINCT`);

      // Release held keys.
      await pageA20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 203, down: false },
        });
      });
      await pageB20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 204, down: false },
        });
      });

      // ── Phase 3: Admin END A ─────────────────────────────────────────────────────────────────
      // POST /sessions/{sidA}/end stamps ended_at on the session record. No push to the agent —
      // A's installed lease remains valid until it expires. Admin END is NOT immediate termination.
      const endResult20 = await adminEndSession(adminSess20, sidA20);
      expect(endResult20.status, "pass20-end: Admin POST /sessions/{sidA}/end must return 200").toBe(200);
      console.log(`[pass20-end] Admin END A: POST /sessions/${sidA20}/end → ${endResult20.status} 200 CONFIRMED`);

      // ── Phase 4: Verify A renewal → 409 (session has ended) ──────────────────────────────────
      const renewAfterEnd20 = await fetchSessionPolicyRaw(techASess20, sidA20);
      expect(
        renewAfterEnd20.status,
        `pass20-end: POST /sessions/${sidA20}/policy after admin END must return 409 (session has ended)`,
      ).toBe(409);
      console.log(`[pass20-end] A renewal after admin END: ${renewAfterEnd20.status} 409 CONFIRMED (session has ended)`);

      // A's page remains open. The current installed lease is still valid on the agent.
      // The agent will tear down when the lease lapses — not at the moment of admin END.
      console.log(`[pass20-end] A page open — current lease valid until ${leaseA20_1.expires_at_ms}; awaiting natural expiry`);

      // ── Phase 5: Keep A page open; renew B; wait for A's lease to expire ─────────────────────
      const expiresAtMsA20 = leaseA20_1.expires_at_ms;
      const waitUntilMs20 = expiresAtMsA20 + 8_000;
      let bCurrentExpiry20 = leaseB20_1.expires_at_ms;

      console.log(`[pass20-end] A lease expires: ${expiresAtMsA20} (now=${Date.now()}); waiting until ${waitUntilMs20} (+8 s allowance)`);
      console.log(`[pass20-end] Stop renewing A (admin END → 409); keep renewing B every 10 s`);

      while (Date.now() < waitUntilMs20) {
        const msLeft = waitUntilMs20 - Date.now();
        const sleepMs = Math.min(10_000, msLeft > 1_000 ? msLeft : 1_000);
        await sleep(sleepMs);

        if (Date.now() >= waitUntilMs20) break;

        if (bCurrentExpiry20 - Date.now() < 20_000 || waitUntilMs20 - Date.now() < 15_000) {
          const leaseBN = await fetchSessionPolicy(techBSess20, sidB20);
          await pageB20.evaluate((sp) => {
            const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
            if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
            rmt.installSessionPolicy(sp);
          }, leaseBN.signed);
          const bRenewOk20 = await waitForNewControlMsgOfType(pageB20, "SessionPolicyInstalled", bAckCount20, 15_000);
          expect(bRenewOk20, "pass20-end B: mid-wait renewal ack must arrive — renewal failure is a test failure").toBe(true);
          bAckCount20 = await countControlMsgsByType(pageB20, "SessionPolicyInstalled");
          bCurrentExpiry20 = leaseBN.expires_at_ms;
          console.log(`[pass20-end] B: renewal OK — ack count=${bAckCount20} expires_at_ms=${bCurrentExpiry20}`);
        }
      }

      // ── Phase 6: Assert A teardown ────────────────────────────────────────────────────────────
      const aTornDown20 = await waitFor(async () => {
        return agentLog.slice(logBefore20).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId20}]`);
      }, 20_000);
      expect(
        aTornDown20,
        `pass20-end: agent log must contain [SESSION:TEARDOWN:DONE session=${aSessionId20}] from offset`,
      ).toBe(true);
      console.log(`[pass20-end] [SESSION:TEARDOWN:DONE session=${aSessionId20}] confirmed from offset (definitive)`);

      expect(
        agentLog.slice(logBefore20).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId20}]`),
        `pass20-end: B session=${bSessionId20} must NOT be torn down during A lease expiry window`,
      ).toBe(false);
      console.log(`[pass20-end] B session=${bSessionId20} teardown absent — correct isolation`);

      const logAfterTeardown20 = agentLog.length;

      // Supplementary: A RTP frozen.
      await sleep(3_000);
      const rtpA20_s1 = await pageA20.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpA20_s2 = await pageA20.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpA20_s2, `pass20-end A: RTP bytes must be frozen after teardown`).toBeLessThanOrEqual(rtpA20_s1 + 5_000);
      console.log(`[pass20-end] A: inbound RTP frozen snap1=${rtpA20_s1} snap2=${rtpA20_s2} (supplementary)`);

      // ── Phase 7: Assert B alive after A ends ──────────────────────────────────────────────────
      const stateB20 = await pageB20.evaluate(() =>
        (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
      );
      expect(stateB20, `pass20-end B: must still be "connected" after A expired`).toBe("connected");
      console.log(`[pass20-end] B: connection state = "${stateB20}" — still alive`);

      const rtpB20_s1 = await pageB20.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpB20_s2 = await pageB20.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpB20_s2, `pass20-end B: NEW inbound-RTP bytes must arrive after A teardown`).toBeGreaterThan(rtpB20_s1);
      console.log(`[pass20-end] B: NEW video bytes confirmed after A teardown (${rtpB20_s1} → ${rtpB20_s2})`);

      // ── Phase 8: Input isolation — full 5 s observation window ───────────────────────────────
      // A post-end send: honest outcome capture. No break on B admission — observe the full window.
      const aPost20SendOutcome = await pageA20.evaluate(() => {
        try {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 205, down: true },
          });
          return "sent";
        } catch (e) {
          return `closed:${String(e)}`;
        }
      }).catch((e: unknown) => `eval-err:${String(e)}`);
      console.log(`[pass20-end] A post-end send outcome: ${aPost20SendOutcome} (honest; attempted send returned normally; no admission expected)`);

      await pageB20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 206, down: true },
        });
      });
      console.log("[pass20-end] B: sent key=206 down");

      const inputObs20 = Date.now() + 5_000;
      let bKey206Admitted = false;
      let aKey205AdmittedPostEnd = false;
      while (Date.now() < inputObs20) {
        const delta = agentLog.slice(logAfterTeardown20);
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${aSessionId20} key=205`)) {
          aKey205AdmittedPostEnd = true;
        }
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${bSessionId20} key=206`)) {
          bKey206Admitted = true;
        }
        await sleep(50);
      }
      expect(
        aKey205AdmittedPostEnd,
        `pass20-end A: key=205 must NOT be admitted after session=${aSessionId20} teardown (admin END + lease expiry)`,
      ).toBe(false);
      expect(
        bKey206Admitted,
        `pass20-end B: key=206 must be admitted for session=${bSessionId20} in same bounded window`,
      ).toBe(true);
      console.log(`[pass20-end] A: no ADMITTED_INPUT for key=205 after teardown — input isolation confirmed`);
      console.log(`[pass20-end] B: ADMITTED_INPUT for key=206 confirmed — B session live`);

      // B must still not be torn down after the full observation window.
      expect(
        agentLog.slice(logBefore20).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId20}]`),
        `pass20-end: B session=${bSessionId20} must NOT be torn down after input observation window`,
      ).toBe(false);
      console.log(`[pass20-end] B teardown still absent after full observation window — correct`);

      // Release B's key.
      await pageB20.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 206, down: false },
        });
      });

      // ── Summary ───────────────────────────────────────────────────────────────────────────────
      const agentBinHash20 = await sha256File(AGENT_BIN);
      console.log("\n[pass20-end] PASS — Admin END isolation evidence:");
      console.log(`  agent_host.exe SHA-256: ${agentBinHash20}`);
      console.log(`  agent PID:              ${agentPid}`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  tenant_id:              ${tenantId}`);
      console.log(`  grant_issuer_pubkey:    ${grantPubkey}`);
      console.log(`  sidA:                   ${sidA20}`);
      console.log(`  sidB:                   ${sidB20}`);
      console.log(`  A coordinator session:  ${aSessionId20}  (from pre-bind key=203)`);
      console.log(`  B coordinator session:  ${bSessionId20}  (from pre-bind key=204, distinct)`);
      console.log(`  A lease expires_at_ms:  ${expiresAtMsA20}`);
      console.log(`  Admin END result:       200 CONFIRMED (ended_at stamped)`);
      console.log(`  A renewal after END:    409 CONFIRMED (session has ended)`);
      console.log(`  A: TEARDOWN:DONE:       session=${aSessionId20} confirmed from offset (after natural lease expiry)`);
      console.log(`  B: ack count at end:    ${bAckCount20}`);
      console.log(`  A: RTP frozen:          snap1=${rtpA20_s1} snap2=${rtpA20_s2} (supplementary)`);
      console.log(`  A: input isolation:     key=205 NOT admitted after teardown; send outcome=${aPost20SendOutcome}`);
      console.log(`  B: state after A ends:  ${stateB20}`);
      console.log(`  B: RTP bytes:           ${rtpB20_s1} → ${rtpB20_s2} (growing)`);
      console.log(`  B: input admitted:      key=206 ADMITTED_INPUT in full 5 s window\n`);

      await pageA20.close();
      await pageB20.close();
    },
  );

  // ── pass20-logout ─────────────────────────────────────────────────────────────────────────────
  //
  // Technician A authenticated logout via POST /auth/logout → 204.
  //
  // What this proves:
  //   1. Logout revokes A's server-side session cookie; subsequent authenticated requests return 401.
  //   2. POST /sessions (mint new ticket) → 401 after logout (no valid auth).
  //   3. POST /sessions/{sidA}/policy (renewal) → 401 after logout (no valid auth).
  //   4. HTTP logout is NOT immediate remote termination. A's page stays open; the installed lease
  //      on the agent remains valid and the WebRTC session continues until the lease expires.
  //   5. After A's lease lapses the agent tears down session A ([SESSION:TEARDOWN:DONE]).
  //   6. A receives no input admission after teardown; B is admitted (positive control).
  //   7. B keeps renewing (with its own independent session cookie) and remains media + input positive.
  //   8. B is never torn down during or after A's expiry window.
  //
  // Key codes: 207 (A pre-bind), 208 (B pre-bind), 209 (A post-logout attempt), 210 (B positive).
  test(
    "pass20-logout: A authenticated logout → A mint/renew 401, bounded A lease expiry, B independent media+input",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(180_000);

      // ── Fresh sessions ────────────────────────────────────────────────────────────────────────
      const techASess20L = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const techBSess20L = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);

      const bodyA20L = await mintTicket(techASess20L, deviceId);
      const bodyB20L = await mintTicket(techBSess20L, deviceId);

      const sigA20L = bodyA20L.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB20L = bodyB20L.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sessA20Lrec = (bodyA20L.session as { id?: string } | undefined);
      const sessB20Lrec = (bodyB20L.session as { id?: string } | undefined);

      const ticketA20L = sigA20L?.ticket;
      const ticketB20L = sigB20L?.ticket;
      const sidA20L = sigA20L?.session_id ?? sessA20Lrec?.id ?? "";
      const sidB20L = sigB20L?.session_id ?? sessB20Lrec?.id ?? "";

      if (!ticketA20L || !ticketB20L) throw new Error(`pass20-logout: no tickets. A=${JSON.stringify(bodyA20L)} B=${JSON.stringify(bodyB20L)}`);
      if (!sidA20L || !sidB20L) throw new Error(`pass20-logout: no session IDs. A=${sidA20L} B=${sidB20L}`);
      expect(sidA20L, "pass20-logout: sidA must differ from sidB").not.toBe(sidB20L);

      console.log(`[pass20-logout] sidA=${sidA20L} sidB=${sidB20L}`);

      // ── Open pages and wait for connected + video ─────────────────────────────────────────────
      const pageA20L = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketA20L));
      const pageB20L = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(ticketB20L));

      await Promise.all([
        waitForConnected(pageA20L, 30_000),
        waitForConnected(pageB20L, 30_000),
      ]);
      console.log("[pass20-logout] A and B reached WebRTC connected");

      await Promise.all([
        waitForVideo(pageA20L, "p20-logout-techA"),
        waitForVideo(pageB20L, "p20-logout-techB"),
      ]);
      console.log("[pass20-logout] A and B independently receiving VP8 video — confirmed before policy install");

      // ── Phase 1: Install initial signed leases for A and B ───────────────────────────────────
      const leaseA20L_1 = await fetchSessionPolicy(techASess20L, sidA20L);
      console.log(`[pass20-logout] A: initial policy — access=${leaseA20L_1.access} expires_at_ms=${leaseA20L_1.expires_at_ms}`);
      const aAck20L_0 = await countControlMsgsByType(pageA20L, "SessionPolicyInstalled");
      await pageA20L.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseA20L_1.signed);
      const aAckOk20L = await waitForNewControlMsgOfType(pageA20L, "SessionPolicyInstalled", aAck20L_0, 15_000);
      expect(aAckOk20L, "pass20-logout A: initial SessionPolicyInstalled ack must arrive").toBe(true);
      const aAckCount20L = await countControlMsgsByType(pageA20L, "SessionPolicyInstalled");
      console.log(`[pass20-logout] A: SessionPolicyInstalled ack confirmed (count=${aAckCount20L})`);

      const leaseB20L_1 = await fetchSessionPolicy(techBSess20L, sidB20L);
      console.log(`[pass20-logout] B: initial policy — access=${leaseB20L_1.access} expires_at_ms=${leaseB20L_1.expires_at_ms}`);
      const bAck20L_0 = await countControlMsgsByType(pageB20L, "SessionPolicyInstalled");
      await pageB20L.evaluate((sp) => {
        const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
        if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
        rmt.installSessionPolicy(sp);
      }, leaseB20L_1.signed);
      const bAckOk20L = await waitForNewControlMsgOfType(pageB20L, "SessionPolicyInstalled", bAck20L_0, 15_000);
      expect(bAckOk20L, "pass20-logout B: initial SessionPolicyInstalled ack must arrive").toBe(true);
      let bAckCount20L = await countControlMsgsByType(pageB20L, "SessionPolicyInstalled");
      console.log(`[pass20-logout] B: SessionPolicyInstalled ack confirmed (count=${bAckCount20L})`);

      // ── Phase 2: Pre-bind coordinator session IDs (key=207 A, key=208 B) ────────────────────
      const logBefore20L = agentLog.length;

      await pageA20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 207, down: true },
        });
      });
      let aSessionId20L = "";
      const aAdmitted20L = await waitFor(async () => {
        const delta = agentLog.slice(logBefore20L);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=207 first_holder=true/);
        if (m) { aSessionId20L = m[1]; return true; }
        return false;
      }, 8_000);
      expect(aAdmitted20L, "pass20-logout A: key=207 must be admitted (first_holder=true) before logout").toBe(true);
      console.log(`[pass20-logout] A: pre-bind confirmed session=${aSessionId20L} key=207`);

      await pageB20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 208, down: true },
        });
      });
      let bSessionId20L = "";
      const bAdmitted20L = await waitFor(async () => {
        const delta = agentLog.slice(logBefore20L);
        const m = delta.match(/\[SESSION:ADMITTED_INPUT\] session=(\d+) key=208 first_holder=true/);
        if (m) { bSessionId20L = m[1]; return true; }
        return false;
      }, 8_000);
      expect(bAdmitted20L, "pass20-logout B: key=208 must be admitted (first_holder=true)").toBe(true);
      expect(bSessionId20L, "pass20-logout: coordinator session IDs must be distinct").not.toBe(aSessionId20L);
      console.log(`[pass20-logout] B: pre-bind confirmed session=${bSessionId20L} key=208`);
      console.log(`[pass20-logout] A session=${aSessionId20L} B session=${bSessionId20L} — DISTINCT`);

      // Release held keys.
      await pageA20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 207, down: false },
        });
      });
      await pageB20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 208, down: false },
        });
      });

      // ── Phase 3: A logs out ───────────────────────────────────────────────────────────────────
      // POST /auth/logout revokes A's server-side session cookie. Returns 204 (always, per spec).
      const logoutStatus20L = await logoutFromCP(techASess20L);
      expect(logoutStatus20L, "pass20-logout: POST /auth/logout must return 204").toBe(204);
      console.log(`[pass20-logout] A logout: POST /auth/logout → ${logoutStatus20L} 204 CONFIRMED`);

      // ── Phase 4: Verify A mint → 401 and A renewal → 401 ─────────────────────────────────────
      // Cookie is now revoked; every authenticated request from techASess20L must return 401.
      const mintAfterLogout20L = await fetch(`${CP_BASE}/sessions`, {
        method: "POST",
        headers: authHeaders(techASess20L),
        body: JSON.stringify({ machine_id: deviceId }),
      });
      expect(
        mintAfterLogout20L.status,
        "pass20-logout: POST /sessions with revoked cookie must return 401",
      ).toBe(401);
      console.log(`[pass20-logout] A mint after logout: POST /sessions → ${mintAfterLogout20L.status} 401 CONFIRMED`);

      const renewAfterLogout20L = await fetchSessionPolicyRaw(techASess20L, sidA20L);
      expect(
        renewAfterLogout20L.status,
        `pass20-logout: POST /sessions/${sidA20L}/policy with revoked cookie must return 401`,
      ).toBe(401);
      console.log(`[pass20-logout] A renewal after logout: ${renewAfterLogout20L.status} 401 CONFIRMED`);

      // ── CRITICAL NOTE: HTTP logout ≠ immediate remote termination ─────────────────────────────
      // A's WebRTC session and installed lease on the agent are still live. The agent has no
      // notification channel from the CP; it only learns the session is over when the current
      // lease expires and it cannot renew. A's page stays open until the lease lapses.
      console.log(`[pass20-logout] NOTE: A page still open — current lease valid until ${leaseA20L_1.expires_at_ms}`);
      console.log(`[pass20-logout] HTTP logout revoked A's cookie but did NOT immediately terminate the remote session`);

      // ── Phase 5: Keep A page open; renew B; wait for A's lease to expire ─────────────────────
      const expiresAtMsA20L = leaseA20L_1.expires_at_ms;
      const waitUntilMs20L = expiresAtMsA20L + 8_000;
      let bCurrentExpiry20L = leaseB20L_1.expires_at_ms;

      console.log(`[pass20-logout] A lease expires: ${expiresAtMsA20L} (now=${Date.now()}); waiting until ${waitUntilMs20L} (+8 s)`);
      console.log(`[pass20-logout] Stop renewing A (logout → 401); keep renewing B (B's cookie is independent)`);

      while (Date.now() < waitUntilMs20L) {
        const msLeft = waitUntilMs20L - Date.now();
        const sleepMs = Math.min(10_000, msLeft > 1_000 ? msLeft : 1_000);
        await sleep(sleepMs);

        if (Date.now() >= waitUntilMs20L) break;

        if (bCurrentExpiry20L - Date.now() < 20_000 || waitUntilMs20L - Date.now() < 15_000) {
          const leaseBN = await fetchSessionPolicy(techBSess20L, sidB20L);
          await pageB20L.evaluate((sp) => {
            const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
            if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
            rmt.installSessionPolicy(sp);
          }, leaseBN.signed);
          const bRenewOk20L = await waitForNewControlMsgOfType(pageB20L, "SessionPolicyInstalled", bAckCount20L, 15_000);
          expect(bRenewOk20L, "pass20-logout B: mid-wait renewal ack must arrive — renewal failure is a test failure").toBe(true);
          bAckCount20L = await countControlMsgsByType(pageB20L, "SessionPolicyInstalled");
          bCurrentExpiry20L = leaseBN.expires_at_ms;
          console.log(`[pass20-logout] B: renewal OK — ack count=${bAckCount20L} expires_at_ms=${bCurrentExpiry20L}`);
        }
      }

      // ── Phase 6: Assert A teardown ────────────────────────────────────────────────────────────
      const aTornDown20L = await waitFor(async () => {
        return agentLog.slice(logBefore20L).includes(`[SESSION:TEARDOWN:DONE session=${aSessionId20L}]`);
      }, 20_000);
      expect(
        aTornDown20L,
        `pass20-logout: agent log must contain [SESSION:TEARDOWN:DONE session=${aSessionId20L}] from offset`,
      ).toBe(true);
      console.log(`[pass20-logout] [SESSION:TEARDOWN:DONE session=${aSessionId20L}] confirmed from offset (definitive)`);

      expect(
        agentLog.slice(logBefore20L).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId20L}]`),
        `pass20-logout: B session=${bSessionId20L} must NOT be torn down during A lease expiry window`,
      ).toBe(false);
      console.log(`[pass20-logout] B session=${bSessionId20L} teardown absent — correct isolation`);

      const logAfterTeardown20L = agentLog.length;

      // Supplementary: A RTP frozen.
      await sleep(3_000);
      const rtpA20L_s1 = await pageA20L.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpA20L_s2 = await pageA20L.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpA20L_s2, `pass20-logout A: RTP bytes must be frozen after teardown`).toBeLessThanOrEqual(rtpA20L_s1 + 5_000);
      console.log(`[pass20-logout] A: inbound RTP frozen snap1=${rtpA20L_s1} snap2=${rtpA20L_s2} (supplementary)`);

      // ── Phase 7: Assert B alive after A ends ──────────────────────────────────────────────────
      const stateB20L = await pageB20L.evaluate(() =>
        (window as unknown as { rmt?: { state?: string } }).rmt?.state ?? "unknown",
      );
      expect(stateB20L, `pass20-logout B: must still be "connected" after A expired`).toBe("connected");
      console.log(`[pass20-logout] B: connection state = "${stateB20L}" — still alive`);

      const rtpB20L_s1 = await pageB20L.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      await sleep(3_000);
      const rtpB20L_s2 = await pageB20L.evaluate(async () => {
        const r = (window as unknown as { rmt?: { inboundVideo: () => Promise<{ bytesReceived?: number } | null> } }).rmt;
        return (await r?.inboundVideo())?.bytesReceived ?? 0;
      });
      expect(rtpB20L_s2, `pass20-logout B: NEW inbound-RTP bytes must arrive after A teardown`).toBeGreaterThan(rtpB20L_s1);
      console.log(`[pass20-logout] B: NEW video bytes confirmed after A teardown (${rtpB20L_s1} → ${rtpB20L_s2})`);

      // ── Phase 8: Input isolation — full 5 s observation window ───────────────────────────────
      const aPost20LSendOutcome = await pageA20L.evaluate(() => {
        try {
          (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
            t: "Key", c: { code: 209, down: true },
          });
          return "sent";
        } catch (e) {
          return `closed:${String(e)}`;
        }
      }).catch((e: unknown) => `eval-err:${String(e)}`);
      console.log(`[pass20-logout] A post-logout send outcome: ${aPost20LSendOutcome} (honest; attempted send returned normally; no admission expected)`);

      await pageB20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 210, down: true },
        });
      });
      console.log("[pass20-logout] B: sent key=210 down");

      const inputObs20L = Date.now() + 5_000;
      let bKey210Admitted = false;
      let aKey209AdmittedPostLogout = false;
      while (Date.now() < inputObs20L) {
        const delta = agentLog.slice(logAfterTeardown20L);
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${aSessionId20L} key=209`)) {
          aKey209AdmittedPostLogout = true;
        }
        if (delta.includes(`[SESSION:ADMITTED_INPUT] session=${bSessionId20L} key=210`)) {
          bKey210Admitted = true;
        }
        await sleep(50);
      }
      expect(
        aKey209AdmittedPostLogout,
        `pass20-logout A: key=209 must NOT be admitted after session=${aSessionId20L} teardown (logout + lease expiry)`,
      ).toBe(false);
      expect(
        bKey210Admitted,
        `pass20-logout B: key=210 must be admitted for session=${bSessionId20L} in same bounded window`,
      ).toBe(true);
      console.log(`[pass20-logout] A: no ADMITTED_INPUT for key=209 after teardown — input isolation confirmed`);
      console.log(`[pass20-logout] B: ADMITTED_INPUT for key=210 confirmed — B session live`);

      // B must still not be torn down after the full observation window.
      expect(
        agentLog.slice(logBefore20L).includes(`[SESSION:TEARDOWN:DONE session=${bSessionId20L}]`),
        `pass20-logout: B session=${bSessionId20L} must NOT be torn down after input observation window`,
      ).toBe(false);
      console.log(`[pass20-logout] B teardown still absent after full observation window — correct`);

      // Release B's key.
      await pageB20L.evaluate(() => {
        (window as unknown as { rmt: { sendInput: (ev: unknown) => void } }).rmt.sendInput({
          t: "Key", c: { code: 210, down: false },
        });
      });

      // ── Summary ───────────────────────────────────────────────────────────────────────────────
      const agentBinHash20L = await sha256File(AGENT_BIN);
      console.log("\n[pass20-logout] PASS — Authenticated logout isolation evidence:");
      console.log(`  agent_host.exe SHA-256: ${agentBinHash20L}`);
      console.log(`  agent PID:              ${agentPid}`);
      console.log(`  device_id:              ${deviceId}`);
      console.log(`  tenant_id:              ${tenantId}`);
      console.log(`  grant_issuer_pubkey:    ${grantPubkey}`);
      console.log(`  sidA:                   ${sidA20L}`);
      console.log(`  sidB:                   ${sidB20L}`);
      console.log(`  A coordinator session:  ${aSessionId20L}  (from pre-bind key=207)`);
      console.log(`  B coordinator session:  ${bSessionId20L}  (from pre-bind key=208, distinct)`);
      console.log(`  A lease expires_at_ms:  ${expiresAtMsA20L}`);
      console.log(`  A logout result:        204 CONFIRMED (session cookie revoked)`);
      console.log(`  A mint after logout:    401 CONFIRMED (revoked cookie)`);
      console.log(`  A renewal after logout: 401 CONFIRMED (revoked cookie)`);
      console.log(`  HTTP logout ≠ immediate termination: A session ran until lease expired`);
      console.log(`  A: TEARDOWN:DONE:       session=${aSessionId20L} confirmed from offset (after natural lease expiry)`);
      console.log(`  B: ack count at end:    ${bAckCount20L}  (B's cookie independent from A's logout)`);
      console.log(`  A: RTP frozen:          snap1=${rtpA20L_s1} snap2=${rtpA20L_s2} (supplementary)`);
      console.log(`  A: input isolation:     key=209 NOT admitted after teardown; send outcome=${aPost20LSendOutcome}`);
      console.log(`  B: state after A ends:  ${stateB20L}`);
      console.log(`  B: RTP bytes:           ${rtpB20L_s1} → ${rtpB20L_s2} (growing)`);
      console.log(`  B: input admitted:      key=210 ADMITTED_INPUT in full 5 s window\n`);

      await pageA20L.close();
      await pageB20L.close();
    },
  );
  // docs/49: the agent reports EVERY end of a signaling-vouched session with its reason, and the
  // control plane closes exactly that row. Two sessions on one agent:
  //   - A never installs a session policy, so the agent's lease grace (15 s) lapses → lease_lapsed;
  //   - B installs one and stays live while A ends (its row must remain open), then its viewer
  //     page closes → viewer_left.
  // The fixture prints one FIXTURE_SESSION_END line per report it receives through signaling.
  test(
    "docs49-end-report: lease lapse and viewer leaving each close only their own row, with the reason",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(150_000);

      const sessA = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const sessB = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);
      const bodyA = await mintTicket(sessA, deviceId);
      const bodyB = await mintTicket(sessB, deviceId);
      const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sigB = bodyB.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sidA = sigA?.session_id ?? (bodyA.session as { id?: string } | undefined)?.id ?? "";
      const sidB = sigB?.session_id ?? (bodyB.session as { id?: string } | undefined)?.id ?? "";
      if (!sigA?.ticket || !sigB?.ticket || !sidA || !sidB) {
        throw new Error(`docs49: tickets/ids missing A=${JSON.stringify(bodyA)} B=${JSON.stringify(bodyB)}`);
      }
      const endLine = (sid: string) =>
        new RegExp(`FIXTURE_SESSION_END session=${sid} device=${deviceId} reason=(\\w+) queue_age_ms=(\\d+|none) outcome=(\\w+)`);
      const cpLogStart = cpLog.length;
      const logged = (sid: string) => cpLog.slice(cpLogStart).match(endLine(sid));

      const pageA = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(sigA.ticket));
      const pageB = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(sigB.ticket));
      await Promise.all([waitForConnected(pageA, 30_000), waitForConnected(pageB, 30_000)]);
      await Promise.all([waitForVideo(pageA, "d49-A"), waitForVideo(pageB, "d49-B")]);

      // B installs a lease (renewed below); A deliberately never does.
      const installB = async () => {
        const lease = await fetchSessionPolicy(sessB, sidB);
        const before = await countControlMsgsByType(pageB, "SessionPolicyInstalled");
        await pageB.evaluate((sp) => {
          const rmt = (window as unknown as { rmt?: { installSessionPolicy?: (s: string) => void } }).rmt;
          if (!rmt?.installSessionPolicy) throw new Error("harness: installSessionPolicy not available");
          rmt.installSessionPolicy(sp);
        }, lease.signed);
        expect(await waitForNewControlMsgOfType(pageB, "SessionPolicyInstalled", before, 15_000),
          "docs49 B: SessionPolicyInstalled ack").toBe(true);
      };
      await installB();

      // ── A: the lease never arrives → the agent ends A and reports lease_lapsed ──────────────
      expect(await waitFor(async () => logged(sidA) !== null, 45_000),
        `docs49 A: no FIXTURE_SESSION_END for ${sidA} within 45 s`).toBe(true);
      const mA = logged(sidA)!;
      expect(mA[1], "docs49 A: reason").toBe("lease_lapsed");
      expect(mA[3], "docs49 A: outcome").toBe("ended");
      expect(mA[2], "docs49 A: the agent sends its queue age").not.toBe("none");
      expect((await fetchSessionPolicyRaw(sessA, sidA)).status, "docs49 A: renewal after the report → 409").toBe(409);
      // The report names ONE row: B is untouched and still renews.
      expect(logged(sidB), "docs49 B: must not be reported while live").toBeNull();
      await installB();
      expect((await fetchSessionPolicyRaw(sessB, sidB)).status, "docs49 B: still renewable").toBe(200);

      // ── B: the viewer leaves → viewer_left ─────────────────────────────────────────────────
      await pageB.close();
      expect(await waitFor(async () => logged(sidB) !== null, 45_000),
        `docs49 B: no FIXTURE_SESSION_END for ${sidB} within 45 s of closing the page`).toBe(true);
      const mB = logged(sidB)!;
      expect(mB[1], "docs49 B: reason").toBe("viewer_left");
      expect(mB[3], "docs49 B: outcome").toBe("ended");
      expect((await fetchSessionPolicyRaw(sessB, sidB)).status, "docs49 B: renewal after the report → 409").toBe(409);
      // Exactly one report per session (the agent fence + first-cause-wins).
      const count = (sid: string) => (cpLog.slice(cpLogStart).match(new RegExp(`FIXTURE_SESSION_END session=${sid} `, "g")) ?? []).length;
      expect(count(sidA), "docs49 A: one report").toBe(1);
      expect(count(sidB), "docs49 B: one report").toBe(1);
      console.log(`[docs49] A ${sidA}: ${mA[0]}`);
      console.log(`[docs49] B ${sidB}: ${mB[0]}`);
      await pageA.close();
    },
  );
  // docs/51 session transfer, LIVE: tech A hands a live control session on a real agent to tech B. B's
  // new session is admitted only after the AGENT reports A's session ended (docs/51 §8), then B connects
  // with the transfer ticket and receives video. Exercises the CP routes, signaling's end-report relay
  // and the agent together; the console UI on top is covered by the mocked session_transfer.spec.ts.
  test(
    "docs51-transfer: A hands a live session to B; B is admitted only after the agent reports A gone",
    async () => {
      test.skip(skipReason !== null, skipReason ?? "");
      if (!browser) test.skip(true, "no browser");
      if (!fixtureCfg) test.skip(true, "fixture config not parsed");
      test.setTimeout(180_000);
      const cpJson = async (sess: CPSession, method: string, path: string, body?: unknown) => {
        const r = await fetch(`${CP_BASE}${path}`, {
          method, headers: authHeaders(sess), ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        const text = await r.text();
        let json: Record<string, unknown> | null = null;
        try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* not JSON */ }
        return { status: r.status, json, text };
      };
      // The fixture has no presence feed; record the agent's version as signaling does in production
      // (transfers need a docs/49-reporting agent, 0.1.6+).
      const ver = await fetch(`${CP_BASE}/fixture/agent-version`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, version: "0.1.6" }),
      });
      expect(ver.status, "fixture agent-version").toBe(204);

      const sessA = await loginToCP(tenantId, fixtureCfg!.tech_a_email, fixtureCfg!.tech_a_password);
      const sessB = await loginToCP(tenantId, fixtureCfg!.tech_b_email, fixtureCfg!.tech_b_password);
      const bodyA = await mintTicket(sessA, deviceId);
      const sigA = bodyA.signaling as { ticket?: unknown; session_id?: string } | undefined;
      const sidA = sigA?.session_id ?? (bodyA.session as { id?: string } | undefined)?.id ?? "";
      if (!sigA?.ticket || !sidA) throw new Error(`docs51: ticket/id missing ${JSON.stringify(bodyA)}`);
      const cpLogStart = cpLog.length;
      const endOf = (sid: string) => cpLog.slice(cpLogStart).match(
        new RegExp(`FIXTURE_SESSION_END session=${sid} device=${deviceId} reason=(\\w+) queue_age_ms=(\\d+|none) outcome=(\\w+)`));

      const pageA = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(sigA.ticket));
      await waitForConnected(pageA, 30_000);
      await waitForVideo(pageA, "d51-A");
      const leaseA = await fetchSessionPolicy(sessA, sidA);
      const beforeA = await countControlMsgsByType(pageA, "SessionPolicyInstalled");
      await pageA.evaluate((sp) => {
        (window as unknown as { rmt: { installSessionPolicy: (s: string) => void } }).rmt.installSessionPolicy(sp);
      }, leaseA.signed);
      expect(await waitForNewControlMsgOfType(pageA, "SessionPolicyInstalled", beforeA, 15_000),
        "docs51 A: SessionPolicyInstalled ack").toBe(true);

      // ── Offer: A names B (B is a candidate; B cannot offer A's session) ──────────────────────
      const cands = await cpJson(sessA, "GET", `/sessions/${sidA}/transfer-candidates`);
      expect(cands.status, `candidates: ${cands.text}`).toBe(200);
      expect(JSON.stringify(cands.json), "docs51: B is a candidate").toContain(fixtureCfg!.tech_b_id);
      expect((await cpJson(sessB, "POST", `/sessions/${sidA}/transfer`, { to_user_id: fixtureCfg!.tech_a_id })).status,
        "docs51: only the holder can offer").not.toBe(201);
      const offer = await cpJson(sessA, "POST", `/sessions/${sidA}/transfer`, { to_user_id: fixtureCfg!.tech_b_id, note: "e2e hand-off" });
      expect(offer.status, `offer: ${offer.text}`).toBe(201);
      const tid = (offer.json!.transfer as { id: string }).id;
      const incoming = await cpJson(sessB, "GET", "/session-transfers/incoming");
      expect(JSON.stringify(incoming.json), "docs51: B sees the offer").toContain(tid);
      expect((await cpJson(sessA, "POST", `/session-transfers/${tid}/accept`)).status, "docs51: the sender cannot accept").toBe(403);

      // ── Accept: releasing. A's renewals refuse with the reason; NO S2 while A's session lives ──
      const accepted = await cpJson(sessB, "POST", `/session-transfers/${tid}/accept`);
      expect(accepted.status, `accept: ${accepted.text}`).toBe(200);
      expect((accepted.json!.transfer as { state: string }).state).toBe("releasing");
      const renewA = await fetchSessionPolicyRaw(sessA, sidA);
      expect(renewA.status, "docs51 A: renewal after accept -> 409").toBe(409);
      expect(renewA.body, "docs51 A: the reason").toContain("session transferred");
      const early = await cpJson(sessB, "GET", `/session-transfers/${tid}`);
      expect((early.json!.transfer as { state: string }).state, "docs51: S2 is not admitted while A's session lives").toBe("releasing");
      expect((await cpJson(sessB, "POST", `/session-transfers/${tid}/ticket`)).status, "docs51: no ticket before finalize").toBe(409);

      // ── A's viewer leaves (as the real console does on that 409); the agent reports it ────────
      const tClose = Date.now();
      await pageA.close();
      expect(await waitFor(async () => endOf(sidA) !== null, 45_000), `docs51 A: no FIXTURE_SESSION_END for ${sidA}`).toBe(true);
      const mA = endOf(sidA)!;
      expect(["viewer_left", "lease_lapsed"], `docs51 A: reason ${mA[1]}`).toContain(mA[1]);
      let s2 = "";
      expect(await waitFor(async () => {
        const st = await cpJson(sessB, "GET", `/session-transfers/${tid}`);
        const t = st.json?.transfer as { state?: string; new_session_id?: string } | undefined;
        if (t?.state === "accepted" && t.new_session_id) { s2 = t.new_session_id; return true; }
        return false;
      }, 30_000), "docs51: the transfer finalizes after the end report").toBe(true);
      console.log(`[docs51] A ${sidA} ended (${mA[1]}) ${Date.now() - tClose} ms after its page closed; S2=${s2}`);
      expect(s2).not.toBe(sidA);

      // ── B connects to S2 with the transfer ticket and gets video; a second fetch is refused ─────
      const ticket = await cpJson(sessB, "POST", `/session-transfers/${tid}/ticket`);
      expect(ticket.status, `ticket: ${ticket.text}`).toBe(200);
      const sigB = ticket.json!.signaling as { ticket?: unknown; session_id?: string; device_id?: string };
      expect(sigB.session_id, "docs51: the ticket is for S2").toBe(s2);
      expect(sigB.device_id, "docs51: same machine").toBe(deviceId);
      const pageB = await openHarnessPage(browser!, SIGNALING_WS, deviceId, encodeTicket(sigB.ticket));
      await waitForConnected(pageB, 30_000);
      await waitForVideo(pageB, "d51-B");
      expect((await fetchSessionPolicyRaw(sessB, s2)).status, "docs51 B: S2 renews").toBe(200);
      expect((await fetchSessionPolicyRaw(sessA, s2)).status, "docs51: A cannot renew B's session").not.toBe(200);
      expect(await waitFor(async () => (await cpJson(sessB, "POST", `/session-transfers/${tid}/ticket`)).status === 409, 10_000),
        "docs51: after redemption the ticket endpoint answers 409 (reconnect via POST /sessions)").toBe(true);
      await pageB.close();
    },
  );
});
