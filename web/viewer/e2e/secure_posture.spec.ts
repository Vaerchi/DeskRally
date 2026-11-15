/**
 * SECURE-POSTURE end-to-end test (M2 tickets + M3 agent identity).
 *
 * Every other spec in this directory spawns signaling with `-insecure-no-ticket-verification`
 * (and, since M3, `-insecure-no-agent-auth`), so until this file existed the two authorization
 * gates the product actually ships with had never been exercised outside unit tests. This spec
 * stands the whole stack up in its ENFORCING configuration and drives the real path through it:
 *
 *   control-plane (DEV mode, no DATABASE_URL, FIXED CP_INSECURE_DEV_GRANT_SEED so the issuer key is stable)
 *     ├─ GET  /grant/pubkey                        → the key signaling verifies tickets against
 *     ├─ POST /enrollment-tokens                   → a one-shot enrollment secret
 *     ├─ POST /enroll/redeem  (via `agent_host enroll`) → SERVER-MINTED device id, pinned pubkey
 *     ├─ GET  /internal/devices/{id}/identity      → what signaling resolves the pinned key with
 *     └─ POST /sessions                            → the signed session ticket the browser presents
 *
 *   signaling  started with NEITHER insecure flag, SIGNALING_TICKET_PUBKEY set, and
 *              SIGNALING_DEVICE_IDENTITY_{URL,TOKEN} pointed at the control plane
 *   agent      the REAL Rust agent, registering with the enrolled Ed25519 key
 *   browser    headless Chromium/Chrome running the REAL viewer transport via e2e/harness.html
 *
 * It asserts the positives (the agent registers only after proving possession; a ticketed
 * connect_request brokers; RTP media reaches the browser) AND the negatives that are the entire
 * point of the change (an unproven or wrongly-signed register_agent is refused and does NOT
 * displace the healthy agent; a connect_request with no / tampered / wrong-device / replayed
 * ticket is refused).
 *
 * Ports are deliberately 8180/8181, not 8080/8081, so this can run alongside a developer's
 * dev-mode stack and alongside the other specs.
 *
 * Self-skips (loudly, with a reason) only when a prerequisite is genuinely absent: no agent
 * binary, unbuildable Go servers, or no usable browser. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess, execFileSync } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, generateKeyPairSync, sign as edSign } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
/** The controller half of the loop-86 floor test. verify-all.ps1 builds it explicitly. */
const PROBE_BIN = resolve(TARGET_DIR, "debug", "stream_probe.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");

const SIG_PORT = 8180;
const CP_PORT = 8181;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

/** Fixed so GET /grant/pubkey is stable across restarts — signaling pins it at startup. */
const DEV_GRANT_ISSUER_SEED = "1111111111111111111111111111111111111111111111111111111111111111";
/** 32+ chars, or the control plane refuses to mount the device-identity route (contract §4.1). */
const DEVICE_IDENTITY_TOKEN = "e2e-secure-posture-device-identity-token-0123456789";
/**
 * 32+ chars, or signaling refuses to mount GET /internal/presence at all. Wiring the presence feed
 * here is what makes the loop-86 test below possible: `machine.require_session_policy` is refreshed
 * from that feed, so without it the control plane never learns what the agent announced.
 */
const PRESENCE_TOKEN = "e2e-secure-posture-presence-service-token-0123456789";

/** The one reason string signaling reports for EVERY agent-auth failure (contract §2.4). */
const AGENT_AUTH_REJECTION = "registration not authorized";
/** The one reason string the broker reports for every ticket failure (ticket.go errTicketInvalid). */
const TICKET_REJECTION = "connect request not authorized";

interface SignedTicket {
  claims: {
    v: number;
    session_id: string;
    technician_id: string;
    tenant_id: string;
    device_id: string;
    iat_ms: number;
    exp_ms: number;
  };
  sig: string;
}

let cpProc: ChildProcess | null = null;
let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;

/** The enrolled agent this spec drives (server-minted identity from POST /enroll/redeem). */
let device = "";
let tenant = "";
let identityPath = "";
/** A SECOND enrolled machine, used only to prove a ticket is bound to its device id. */
let otherDevice = "";
let agentLog = "";
let workDir = "";

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 250): Promise<boolean> {
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

async function cpFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${CP_BASE}${path}`, init);
}

async function cpPost(path: string, body: unknown): Promise<Record<string, unknown>> {
  const r = await cpFetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST ${path} → ${r.status}: ${text}`);
  return JSON.parse(text) as Record<string, unknown>;
}

/** POST /sessions for a device and return the signed ticket envelope it hands back. */
async function mintTicket(target: string): Promise<SignedTicket> {
  const body = (await cpPost("/sessions", { machine_id: target })) as {
    signaling?: { ticket?: SignedTicket };
  };
  const ticket = body.signaling?.ticket;
  if (!ticket) throw new Error(`POST /sessions returned no ticket: ${JSON.stringify(body)}`);
  return ticket;
}

/** A raw signaling client: collects every server message, and records whether it was closed. */
interface Probe {
  ws: WebSocket;
  msgs: Array<Record<string, unknown>>;
  closed: boolean;
  send(msg: unknown): void;
  types(): string[];
  first(type: string): Record<string, unknown> | undefined;
  /** Resolve once a message of `type` arrives, or null after `timeoutMs`. */
  await(type: string, timeoutMs?: number): Promise<Record<string, unknown> | null>;
}

async function probe(): Promise<Probe> {
  const ws = new WebSocket(SIGNALING_WS);
  const p: Probe = {
    ws,
    msgs: [],
    closed: false,
    send: (msg) => ws.send(JSON.stringify(msg)),
    types: () => p.msgs.map((m) => String(m.type)),
    first: (type) => p.msgs.find((m) => m.type === type),
    await: async (type, timeoutMs = 4000) => {
      await waitFor(async () => p.first(type) !== undefined || p.closed, timeoutMs, 50);
      return p.first(type) ?? null;
    },
  };
  ws.onmessage = (e) => p.msgs.push(JSON.parse(String(e.data)) as Record<string, unknown>);
  ws.onclose = () => {
    p.closed = true;
  };
  await new Promise<void>((res, rej) => {
    ws.onopen = () => res();
    ws.onerror = () => rej(new Error("probe: signaling websocket failed to open"));
  });
  return p;
}

/**
 * Ask signaling to broker `target`, optionally presenting `ticket`, and report what came back.
 * The probe registers a controller identity first, exactly as the viewer does.
 */
async function tryConnect(target: string, ticket?: SignedTicket | null): Promise<Probe> {
  const p = await probe();
  p.send({
    type: "register_agent",
    device: randomUUID(),
    pubkey: "ed25519:controller",
    nat: "unknown",
    enrollment_token: null,
  });
  await sleep(200);
  p.send(ticket ? { type: "connect_request", target, ticket } : { type: "connect_request", target });
  await waitFor(async () => p.first("brokered") !== undefined || p.first("rejected") !== undefined, 4000, 50);
  return p;
}

/** base64url so the ticket survives a query string. */
function encodeTicket(t: SignedTicket): string {
  return Buffer.from(JSON.stringify(t), "utf8").toString("base64url");
}

/** Redeem `token` into a fresh machine via `agent_host enroll`; returns its config + key paths. */
function enrollAgent(tag: string, token: string): { device: string; tenant: string; identityPath: string } {
  const configPath = join(workDir, `${tag}-config.json`);
  const keyPath = join(workDir, `${tag}-identity.key`);
  // identity_path keeps the generated private key inside the test's temp dir instead of the
  // installed agent's C:\rmt-agent — this spec must never disturb a real installation.
  writeFileSync(
    configPath,
    JSON.stringify({ signaling_url: SIGNALING_WS, identity_path: keyPath.replace(/\\/g, "/"), stun: [] }),
  );
  execFileSync(
    AGENT_BIN,
    ["enroll", "--control-plane-url", CP_BASE, "--token", token, "--name", `E2E-${tag}`, "--config", configPath],
    { stdio: "inherit" },
  );
  const cfg = JSON.parse(readFileSync(configPath, "utf8")) as {
    device_id?: string;
    tenant_id?: string;
    enrollment_token?: string | null;
  };
  if (!cfg.device_id || !cfg.tenant_id) {
    throw new Error(`enroll did not persist an identity: ${JSON.stringify(cfg)}`);
  }
  // The token is single-use-ish and must not linger on disk (contract §5.1 step 4).
  expect(cfg.enrollment_token ?? null, "enroll must clear the spent enrollment token").toBeNull();
  return { device: cfg.device_id, tenant: cfg.tenant_id, identityPath: keyPath };
}

// ---------------------------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------------------------

test.beforeAll(async () => {
  test.setTimeout(180_000);

  if (!existsSync(AGENT_BIN)) {
    skipReason = `agent binary not found at ${AGENT_BIN} (run: cargo build -p rmt-agent-windows --bin agent_host)`;
    return;
  }
  for (const [exe, dir, target] of [
    [SIGNALING_EXE, SIGNALING_DIR, "."],
    [CP_EXE, CP_DIR, "./cmd/controlplane"],
  ] as const) {
    // Assert, never build — globalSetup (e2e/global-setup.ts) owns building these, unconditionally,
    // before any worker starts. A build-if-absent guard here is how the suite came to test a stale
    // control plane on every run after the first.
    void dir;
    void target;
    if (!existsSync(exe)) {
      skipReason = `${exe} is missing — globalSetup should have built it`;
      return;
    }
  }

  workDir = mkdtempSync(join(tmpdir(), "rmt-secure-e2e-"));

  // --- Control plane: DEV mode (no DATABASE_URL) but with the two secrets the secure posture
  // needs — a FIXED issuer seed (stable /grant/pubkey) and the device-identity service token. ---
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      CP_LISTEN: `:${CP_PORT}`,
      CP_SIGNALING_URL: SIGNALING_WS,
      CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED,
      CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      // The presence feed, so GET /machines reflects what agents announce on register_agent —
      // including require_session_policy (migrations/0037).
      CP_PRESENCE_URL: `http://127.0.0.1:${SIG_PORT}/internal/presence`,
      CP_PRESENCE_TOKEN: PRESENCE_TOKEN,
      DATABASE_URL: "", CP_INSECURE_DEV: "1",
    },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  const cpUp = await waitFor(async () => {
    try {
      return (await cpFetch("/healthz")).ok;
    } catch {
      return false;
    }
  }, 15_000);
  if (!cpUp) {
    skipReason = `control plane did not come up on :${CP_PORT}`;
    return;
  }

  const pubkeyBody = (await (await cpFetch("/grant/pubkey")).json()) as { grant_issuer_pubkey: string };
  const issuerPubkey = pubkeyBody.grant_issuer_pubkey;
  expect(issuerPubkey, "control plane must expose a hex grant-issuer pubkey").toMatch(/^[0-9a-f]{64}$/);

  // --- Signaling: ENFORCING. No -insecure-no-ticket-verification, no -insecure-no-agent-auth.
  // Both gates are live, and signaling would log.Fatalf here if either env pair were missing. ---
  signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`], {
    cwd: SIGNALING_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SIGNALING_TICKET_PUBKEY: issuerPubkey,
      SIGNALING_DEVICE_IDENTITY_URL: CP_BASE,
      SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      SIGNALING_PRESENCE_TOKEN: PRESENCE_TOKEN,
    },
  });
  let signalingLog = "";
  const capture = (d: Buffer) => {
    signalingLog += d.toString();
    process.stdout.write(`[signaling] ${d.toString()}`);
  };
  signalingProc.stdout?.on("data", capture);
  signalingProc.stderr?.on("data", capture);
  if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 15_000))) {
    skipReason = `signaling did not come up on :${SIG_PORT}`;
    return;
  }
  // Guard against a future default flip silently downgrading this whole spec to dev mode.
  expect(signalingLog, "signaling must NOT be running with an insecure opt-out").not.toContain("WARNING: -insecure");

  // --- Enrollment: mint a token, then let the REAL agent binary redeem it. The device id and the
  // tenant are minted SERVER-SIDE; the agent only supplies its own public key. ---
  const minted = (await cpPost("/enrollment-tokens", {
    group_id: "00000000-0000-0000-0000-000000000000",
    max_uses: 5,
  })) as { token: string };
  const enrolled = enrollAgent("agent", minted.token);
  device = enrolled.device;
  tenant = enrolled.tenant;
  identityPath = enrolled.identityPath;
  otherDevice = enrollAgent("other", minted.token).device;
  console.log(`[e2e] enrolled device=${device} tenant=${tenant} (second machine ${otherDevice})`);

  // The pinned key must actually be resolvable by the service token signaling holds; without this
  // the whole handshake would fail for a configuration reason and look like an auth failure.
  const identityResp = await cpFetch(`/internal/devices/${device}/identity`, {
    headers: { authorization: `Bearer ${DEVICE_IDENTITY_TOKEN}` },
  });
  expect(identityResp.status, "control plane must resolve the enrolled device's identity").toBe(200);

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
  await stopProc(signalingProc);
  await stopProc(cpProc);
});

/** Start the real Rust agent with its ENROLLED identity and wait until it announces itself. */
async function startAgent(): Promise<void> {
  agentProc = spawn(
    AGENT_BIN,
    [
      "stream",
      "--synthetic",
      "--log-input",
      "--signaling",
      SIGNALING_WS,
      "--device",
      device,
      "--identity",
      identityPath,
      "--tenant",
      tenant,
      "--fps",
      "30",
    ],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  agentProc.stdout?.on("data", (d: Buffer) => {
    agentLog += d.toString();
    process.stdout.write(`[agent] ${d.toString()}`);
  });
  agentProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agent:err] ${d.toString()}`));
  await waitFor(async () => agentLog.includes("agent device="), 10_000);
  await sleep(800); // settle: register_agent → challenge → proof → registered
}

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

test("enforcing signaling: proof-of-possession registration, unproven registrations do not displace, ticketed browser session works", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  test.setTimeout(150_000);

  await startAgent();

  // --- NEGATIVE 1: register_agent for the enrolled device with NO proof. -------------------
  // It must get a challenge (register_agent is not a device-existence oracle), must NOT be told
  // it is registered, and — the whole point — must NOT close the incumbent's socket. Per the
  // contract a missing answer does not even close the squatter's own connection.
  const squatter = await probe();
  squatter.send({
    type: "register_agent",
    device,
    pubkey: "ed25519:whatever",
    nat: "unknown",
    enrollment_token: null,
  });
  expect(await squatter.await("agent_auth_challenge"), "an unproven register_agent must be challenged").not.toBeNull();
  await sleep(600);
  expect(squatter.types(), "an unanswered challenge must never yield `registered`").not.toContain("registered");
  expect(squatter.closed, "a merely unanswered challenge must not close the connection").toBe(false);

  // --- NEGATIVE 2: answer the challenge with a signature from the WRONG key. ---------------
  // The signature is deliberately made over the raw nonce with a throwaway key rather than over
  // the canonical RMTAGENTAUTHv1 preimage: a wrong key is a wrong proof whatever it signed, and
  // rebuilding the preimage here would create a THIRD copy of canonical bytes that the contract
  // pins in exactly two places (crates/protocol/src/agent_auth.rs, server/signaling/agentauth.go).
  const forger = await probe();
  forger.send({
    type: "register_agent",
    device,
    pubkey: "ed25519:whatever",
    nat: "unknown",
    enrollment_token: null,
  });
  const challenge = await forger.await("agent_auth_challenge");
  expect(challenge, "forger must receive a challenge").not.toBeNull();
  const nonce = String(challenge!.nonce);
  expect(nonce, "nonce is 32 bytes of hex").toMatch(/^[0-9a-f]{64}$/);
  const { privateKey } = generateKeyPairSync("ed25519");
  forger.send({
    type: "agent_auth_response",
    device,
    nonce,
    sig: edSign(null, Buffer.from(nonce, "hex"), privateKey).toString("hex"),
  });
  const forgerRejected = await forger.await("rejected");
  expect(forgerRejected, "a bad proof must be rejected").not.toBeNull();
  expect(
    forgerRejected!.reason,
    "every agent-auth failure reports the SAME generic reason — a prober must learn nothing",
  ).toBe(AGENT_AUTH_REJECTION);
  expect(forger.types(), "a bad proof must never register").not.toContain("registered");
  expect(await waitFor(async () => forger.closed, 3000), "a bad proof must close the connection").toBe(true);

  // Neither attempt may have touched the incumbent. Displacement closes the incumbent's SOCKET
  // (registry.go "last registration wins"), and this agent has no reconnect loop in `stream` mode,
  // so a closed socket means a dead process.
  expect(agentProc?.exitCode ?? null, "the real agent must still be running after both attacks").toBeNull();

  // --- POSITIVE: the technician's real path. POST /sessions → ticket → browser → brokered. ---
  // This is the load-bearing non-displacement assertion: it can only succeed if the agent is still
  // the live registry entry for `device`. Had either attempt displaced it, the broker would answer
  // "device … is not registered or offline" instead.
  const ticket = await mintTicket(device);
  expect(ticket.claims.device_id, "the ticket must be bound to the enrolled device").toBe(device);
  expect(ticket.claims.tenant_id, "the ticket must be minted in the machine's tenant").toBe(tenant);

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(
    `${HARNESS_BASE}?url=${encodeURIComponent(SIGNALING_WS)}&device=${device}&ticket=${encodeTicket(ticket)}`,
  );
  await page.waitForFunction(
    () => {
      const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
      return !!r && (r.state === "connected" || r.state === "failed" || r.error !== null);
    },
    undefined,
    { timeout: 45_000 },
  );
  const status = await page.evaluate(() => {
    const r = (window as unknown as { rmt: { state: string; error: string | null } }).rmt;
    return { state: r.state, error: r.error };
  });
  console.log(`[e2e] secure posture: state=${status.state} error=${status.error ?? "none"}`);
  expect(status.error, "harness reported a fatal error").toBeNull();
  expect(status.state, "the ticketed connect_request must broker and connect").toBe("connected");

  type Inbound = { bytesReceived?: number; packetsReceived?: number } | null;
  let inbound: Inbound = null;
  await waitFor(
    async () => {
      inbound = await page.evaluate(async () => {
        const r = (window as unknown as { rmt: { stats(): Promise<Array<Record<string, unknown>>> } }).rmt;
        const all = await r.stats();
        const rtp = all.find((s) => s.type === "inbound-rtp" && (s as { kind?: string }).kind === "video");
        if (!rtp) return null;
        return {
          bytesReceived: rtp.bytesReceived as number | undefined,
          packetsReceived: rtp.packetsReceived as number | undefined,
        };
      });
      return !!inbound && (inbound.bytesReceived ?? 0) > 0 && (inbound.packetsReceived ?? 0) > 0;
    },
    15_000,
    500,
  );
  console.log(`[e2e] inbound-rtp video over the SECURE path: ${JSON.stringify(inbound)}`);
  expect(inbound, "no inbound-rtp video — no media reached the browser over the secure path").not.toBeNull();
  expect(inbound!.bytesReceived ?? 0, "inbound video bytesReceived").toBeGreaterThan(0);
  expect(inbound!.packetsReceived ?? 0, "inbound video packetsReceived").toBeGreaterThan(0);

  // --- NEGATIVE 3: replay the ticket the browser just spent. A verified ticket brokers exactly
  // one session; the second presentation must be refused even though everything about it verifies.
  const replay = await tryConnect(device, ticket);
  expect(replay.types(), "a spent ticket must not broker a second session").not.toContain("brokered");
  expect(replay.first("rejected")?.reason, "a replayed ticket is refused with the generic reason").toBe(
    TICKET_REJECTION,
  );

  await page.close();
});

test("enforcing signaling: connect_request without a valid ticket is refused", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(90_000);

  // No ticket at all — the pre-M2 wire shape.
  const none = await tryConnect(device, null);
  expect(none.types(), "a ticketless connect_request must not broker").not.toContain("brokered");
  expect(none.first("rejected")?.reason).toBe(TICKET_REJECTION);

  // A ticket whose claims were edited after signing (here: its expiry pushed an hour out). The
  // signature no longer covers the claims, so it must fail exactly like an unsigned one.
  const tampered = await mintTicket(device);
  tampered.claims.exp_ms = Date.now() + 3_600_000;
  const edited = await tryConnect(device, tampered);
  expect(edited.types(), "edited claims must not broker").not.toContain("brokered");
  expect(edited.first("rejected")?.reason).toBe(TICKET_REJECTION);

  // NOT covered here, deliberately: an otherwise-perfect ticket whose exp_ms has simply passed.
  // POST /sessions mints a 2-minute TTL and only the control plane can sign, so back-dating one
  // from this process is impossible and waiting out the clock does not belong in an e2e. Expiry
  // (and "at expiry still valid") is asserted against a properly signed ticket in
  // server/signaling/ticket_test.go's TestVerifyTicketChecks.

  // A perfectly valid, unspent, unexpired ticket — for a DIFFERENT machine. The device binding is
  // what stops one authorized session from being redirected at another tenant's agent.
  const wrongDevice = await mintTicket(otherDevice);
  expect(wrongDevice.claims.device_id).toBe(otherDevice);
  const crossed = await tryConnect(device, wrongDevice);
  expect(crossed.types(), "a ticket for another device must not broker this one").not.toContain("brokered");
  expect(crossed.first("rejected")?.reason).toBe(TICKET_REJECTION);
});

test("signaling fails closed at startup when the enforcing configuration is incomplete", async () => {
  test.skip(skipReason !== null, skipReason ?? "");

  // Neither insecure flag, and no device-identity endpoint: starting anyway would mean ANY
  // WebSocket client could displace ANY agent, so the process must refuse to run at all.
  const proc = spawn(SIGNALING_EXE, ["-addr", ":8199"], {
    cwd: SIGNALING_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SIGNALING_TICKET_PUBKEY: "1".repeat(64),
      SIGNALING_DEVICE_IDENTITY_URL: "",
      SIGNALING_DEVICE_IDENTITY_TOKEN: "",
    },
  });
  let out = "";
  proc.stdout?.on("data", (d: Buffer) => (out += d.toString()));
  proc.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  const code = await new Promise<number | null>((res) => {
    proc.on("exit", (c) => res(c));
    setTimeout(() => {
      proc.kill();
      res(null);
    }, 10_000);
  });
  console.log(`[e2e] fail-closed startup: exit=${code} log=${out.trim()}`);
  expect(code, "signaling must EXIT rather than run unauthenticated").not.toBe(0);
  expect(out).toContain("SIGNALING_DEVICE_IDENTITY_URL/SIGNALING_DEVICE_IDENTITY_TOKEN are not set");
});

// ---------------------------------------------------------------------------------------------
// LOOP 86 — the UNATTENDED view-only floor, end to end
// ---------------------------------------------------------------------------------------------

/** One enrolled machine that floors itself, shared by the two arms below. */
interface FlooredMachine {
  device: string;
  tenant: string;
  identityPath: string;
  issuerPubkey: string;
}

/**
 * Run `body` against a freshly-spawned agent that opens under the PROVISIONAL view-only floor, and
 * return everything that agent logged.
 *
 * A fresh process per arm, deliberately: `agent_host stream` serves exactly ONE session and exits
 * when the peer goes away (the same one-session-per-process shape the attended guest has), so the
 * second arm would otherwise find nothing to connect to and fail for a reason that has nothing to
 * do with what it is testing.
 */
async function withFlooredAgent(
  m: FlooredMachine,
  body: (log: () => string) => Promise<void>,
  opts: { requireSessionPolicy?: boolean; simulateUnattendedHost?: boolean; pinIssuer?: boolean } = {},
): Promise<void> {
  const requirePolicy = opts.requireSessionPolicy ?? true;
  const pinIssuer = opts.pinIssuer ?? true;
  let log = "";
  const proc = spawn(
    AGENT_BIN,
    [
      "stream",
      "--synthetic",
      "--log-input",
      "--signaling",
      SIGNALING_WS,
      "--device",
      m.device,
      "--identity",
      m.identityPath,
      "--tenant",
      m.tenant,
      "--fps",
      "10",
      // The two halves of an enforcing agent, exactly as HelperConfig's own doc describes them:
      // the floor, and the key that can lift it. The ELEVATION test (loop 87) drops the FLOOR but
      // keeps the KEY: elevation is orthogonal to view-only, and a floored session refuses every
      // command outright, so it could never reach the elevation gate at all.
      ...(requirePolicy ? ["--require-session-policy"] : []),
      // ELEVATION only exists on the UNATTENDED (SYSTEM per-session helper) host, and `agent_host
      // stream` is by nature run BY the interactive user — so without this the elevate path is
      // unreachable from any test and an inert implementation would look identical to a working
      // one. The flag is gated on `--synthetic`/`--log-input` in the agent, so it can only ever
      // change the AUTHORIZATION posture: the command runner here is mocked either way.
      ...(opts.simulateUnattendedHost ? ["--simulate-unattended-host"] : []),
      // Omitting the issuer leaves `BackstageAuth` non-`SignedBy`, which is the agent's FAIL-CLOSED
      // default for every signed artifact. It is a posture no other arm can reach, and until loop 88
      // nothing exercised it for elevation — see the "no pinned issuer" arm.
      ...(pinIssuer ? ["--grant-issuer", m.issuerPubkey] : []),
    ],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  const capture = (d: Buffer) => {
    log += d.toString();
    process.stdout.write(`[floor-agent] ${d.toString()}`);
  };
  proc.stdout?.on("data", capture);
  proc.stderr?.on("data", capture);
  try {
    expect(
      await waitFor(async () => log.includes("agent device="), 20_000),
      `the floored agent never announced itself. log:\n${log}`,
    ).toBe(true);
    await sleep(1200); // register_agent -> challenge -> proof -> registered
    await body(() => log);
  } finally {
    await stopProc(proc);
    await sleep(500); // let signaling drop the registration before the next arm registers the same id
  }
}

/** Drive `stream_probe` as the controller for one session, running `script` against the agent. */
async function driveProbe(ticketPath: string, script: string, secs = 8): Promise<string> {
  const probe = spawn(
    PROBE_BIN,
    [
      "--signaling",
      SIGNALING_WS,
      "--device",
      device,
      "--secs",
      String(secs),
      "--ticket",
      ticketPath,
      "--script",
      script,
    ],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let out = "";
  probe.stdout?.on("data", (d: Buffer) => (out += d.toString()));
  probe.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  return await new Promise<string>((done) => {
    probe.on("exit", () => done(out));
    setTimeout(() => done(out), 45_000);
  });
}

/**
 * The whole loop-86 chain against the real stack, because every link in it is a hop that unit tests
 * on either side structurally cannot see:
 *
 *   agent `--require-session-policy` -> register_agent -> signaling registry -> GET /internal/presence
 *     -> the control plane's machine.require_session_policy -> POST /sessions mints `control`
 *     -> the viewer's channel (stream_probe) installs it -> the agent VERIFIES and lifts its floor
 *
 * and then the attack the whole design turns on:
 *
 *   a policy minted for session A, replayed into session B at the SAME machine, inside its TTL
 *     -> REFUSED, because `SessionPolicy::verify` binds the session id signaling reported from the
 *        ticket it verified.
 *
 * Before loop 86 the negative arm could not even be constructed: `handleStartSession` hard-coded
 * `access = view_only` for permanent machines precisely so no replayable `control` policy existed.
 * Migration 0037 spends that containment and this test is what pays for it — so if it is ever
 * deleted or weakened, the mint condition has to go back with it.
 */
test("unattended: a self-floored agent's control policy is bound to its session, and a REPLAY is refused", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.skip(!existsSync(PROBE_BIN), `stream_probe not built at ${PROBE_BIN}`);
  test.setTimeout(240_000);

  const pubkeyBody = (await (await cpFetch("/grant/pubkey")).json()) as { grant_issuer_pubkey: string };
  const machine: FlooredMachine = {
    device,
    tenant,
    identityPath,
    issuerPubkey: pubkeyBody.grant_issuer_pubkey,
  };

  // ---- ARM 1: the replay is refused --------------------------------------------------------
  await withFlooredAgent(machine, async (log) => {
    // HOP 1: the agent's announcement reached machine.require_session_policy. This is the link that
    // unstrands agents ALREADY IN THE FIELD — enrollment ran once, long ago, from a config that did
    // not carry the flag — and no unit test on either side can see it, because it spans three
    // processes. GET /machines is what DRIVES the refresh, so polling it is the mechanism, not a hack.
    expect(
      await waitFor(async () => {
        const rows = (await (await cpFetch("/machines")).json()) as {
          machines?: Array<{ device_id?: string; require_session_policy?: boolean }>;
        };
        return (rows.machines ?? []).some(
          (mm) => mm.device_id === device && mm.require_session_policy === true,
        );
      }, 25_000),
      "the agent's require_session_policy never reached the control plane's machine row — the " +
        "register_agent -> presence -> RecordRequireSessionPolicy hop is broken",
    ).toBe(true);

    // HOP 2: because the machine is flagged, POST /sessions mints — and mints `control`, since this
    // machine's group enforces nothing. A `view_only` mint here would be no fix at all: the agent is
    // ALREADY view-only, and only `control` discharges a provisional floor.
    const startA = (await cpPost("/sessions", { machine_id: device })) as {
      session?: { id?: string };
      session_policy?: { access?: string; signed?: string };
      signaling?: { ticket?: SignedTicket };
    };
    expect(
      startA.session_policy?.access,
      "a flagged machine in a non-enforcing group must be minted a CONTROL policy — anything else " +
        "leaves it stranded view-only, which is the bug loop 86 exists to fix",
    ).toBe("control");

    // A SECOND session at the same machine, so session A's policy is a genuine, correctly-signed,
    // unexpired `control` policy for this very device that differs from session B's in exactly one
    // field: session_id. That is a replay, and nothing weaker is one — tampering with A's JSON would
    // only re-prove the signature check that loop 79 already pins.
    const startB = (await cpPost("/sessions", { machine_id: device })) as {
      session?: { id?: string };
      signaling?: { ticket?: SignedTicket };
    };
    expect(
      startB.session?.id,
      "premise not met: the two sessions share an id, so there is no replay to attempt",
    ).not.toBe(startA.session?.id);

    const policyA = join(workDir, "floor-policy-a.json");
    writeFileSync(policyA, startA.session_policy!.signed!, "utf8");
    const ticketB = join(workDir, "floor-ticket-b.json");
    writeFileSync(ticketB, JSON.stringify(startB.signaling!.ticket!), "utf8");

    const probeLog = await driveProbe(ticketB, `wait:1200;install-policy:${policyA}`);
    expect(
      await waitFor(async () => log().includes("rejected InstallSessionPolicy"), 20_000),
      "the agent ACCEPTED a policy minted for a DIFFERENT session — the session binding is not in " +
        "force, so every captured control policy is replayable at this machine for its whole TTL.\n" +
        `agent log:\n${log()}\nprobe log:\n${probeLog}`,
    ).toBe(true);
    // …and it must say WHY. Without this, a future refactor could satisfy the assertion above by
    // rejecting for an unrelated reason (clock skew, a device mismatch) while the binding lapsed.
    expect(
      log(),
      "the refusal was not the SESSION binding — this arm would then prove nothing about loop 86",
    ).toContain("different session");

    // Worth knowing what the agent does next: `reject_unverified` makes a rejection TERMINAL for the
    // session, so the attacker's own connection stays floored for good. The attempt costs them the
    // session rather than winning them one, which is why BINDING and not merely detecting is the fix.
  });

  // ---- ARM 2: the genuine article is still accepted, and lifts the floor -------------------
  // Arm 1 alone would pass on an agent that rejected every policy — which would break the feature
  // outright while looking maximally secure. This is its control.
  await withFlooredAgent(machine, async (log) => {
    const start = (await cpPost("/sessions", { machine_id: device })) as {
      session_policy?: { access?: string; signed?: string };
      signaling?: { ticket?: SignedTicket };
    };
    expect(start.session_policy?.access).toBe("control");
    const policy = join(workDir, "floor-policy-c.json");
    writeFileSync(policy, start.session_policy!.signed!, "utf8");
    const ticket = join(workDir, "floor-ticket-c.json");
    writeFileSync(ticket, JSON.stringify(start.signaling!.ticket!), "utf8");

    // ASK TO LEAVE VIEW-ONLY *BEFORE* INSTALLING, and only then install. That first step is what
    // makes this arm mean "discharged" rather than "never floored". An agent whose provisional
    // floor was never applied simply GRANTS `view-control` and logs nothing; a floored one refuses
    // and logs `awaiting_policy=true` (host.rs, the SetViewOnly handler). Without that observation
    // both assertions below are satisfied byte-identically by a session that had no floor at all —
    // the adversarial review caught exactly this, and named the mutation that exploits it:
    // `SessionAccessState::new(false)` at host.rs:2163 deletes the whole anti-tamper measure while
    // leaving every other test in the tree green.
    const probeLog = await driveProbe(ticket, `wait:1200;view-control;wait:600;install-policy:${policy}`);
    expect(
      await waitFor(async () => log().includes("awaiting_policy=true"), 20_000),
      "the agent did NOT open under the provisional floor — `--require-session-policy` never reached " +
        `SessionAccessState, so nothing below would prove a floor was discharged.\nagent log:\n${log()}\n` +
        `probe log:\n${probeLog}`,
    ).toBe(true);
    expect(
      await waitFor(async () => log().includes("session policy verified and in force"), 20_000),
      `the agent rejected its OWN session's policy. agent log:\n${log()}\nprobe log:\n${probeLog}`,
    ).toBe(true);
    // And the floor is DISCHARGED — which now means something, because the line above proved it was up.
    expect(
      log(),
      "the policy verified but the provisional floor did not lift — the agent is still stranded",
    ).toContain('access="control" view_only=false');
  });
});

// ---------------------------------------------------------------------------------------------
// LOOP 87 — ELEVATE TO ADMIN, end to end (docs/01 §3, the trust-model arc's last box)
// ---------------------------------------------------------------------------------------------

/**
 * The whole elevation chain against the real stack, because every link is a hop that unit tests on
 * either side structurally cannot see:
 *
 *   POST /sessions/{id}/elevation mints + AUDITS a signed grant -> the viewer's channel
 *     (stream_probe) sends it inside `ElevatedRun` -> the agent verifies it against the pinned
 *     issuer, binds it to the session id signaling took from the VERIFIED ticket, BURNS it, and only
 *     then runs the command with `RunIdentity::UserElevated`
 *
 * and the two attacks the design turns on:
 *
 *   a grant minted for session A, replayed into session B at the SAME machine, inside its TTL
 *     -> REFUSED on the session binding;
 *   the SAME grant presented twice inside ONE session
 *     -> the second is REFUSED by the single-use ledger.
 *
 * WHAT THIS TEST CANNOT PROVE, stated so nobody mistakes it for coverage: both agents here run
 * `--synthetic --log-input`, which sets `mock_command`, so no Win32 token is ever fetched. This
 * proves the AUTHORIZATION chain end to end. That the elevated token is really the guest's admin
 * token is a VM fact and is verified on LAB-VM with `whoami /groups` (Medium vs High Mandatory
 * Level) — see docs/07.
 */
test("unattended: an elevated command needs a session-bound, single-use grant — and both replays are refused", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.skip(!existsSync(PROBE_BIN), `stream_probe not built at ${PROBE_BIN}`);
  test.setTimeout(240_000);

  const pubkeyBody = (await (await cpFetch("/grant/pubkey")).json()) as { grant_issuer_pubkey: string };
  const machine: FlooredMachine = { device, tenant, identityPath, issuerPubkey: pubkeyBody.grant_issuer_pubkey };
  const noFloor = { requireSessionPolicy: false, simulateUnattendedHost: true };

  /** `POST /sessions/{id}/elevation` → the signed grant blob, written to `file` for the probe. */
  const mintElevation = async (sessionId: string, file: string): Promise<string> => {
    const body = (await cpPost(`/sessions/${sessionId}/elevation`, {})) as {
      elevation?: { signed?: string; token?: string; elevation_id?: string };
    };
    expect(
      body.elevation?.token,
      "the control plane must mint the LINKED ELEVATED token — anything else authorizes nothing",
    ).toBe("linked_elevated");
    const path = join(workDir, file);
    writeFileSync(path, body.elevation!.signed!, "utf8");
    return path;
  };

  // ---- ARM 1: absent first, then granted, then refused as spent ----------------------------
  await withFlooredAgent(
    machine,
    async (log) => {
      const start = (await cpPost("/sessions", { machine_id: device })) as {
        session?: { id?: string };
        signaling?: { ticket?: SignedTicket };
      };
      const ticket = join(workDir, "elev-ticket-a.json");
      writeFileSync(ticket, JSON.stringify(start.signaling!.ticket!), "utf8");
      const grant = await mintElevation(start.session!.id!, "elev-grant-a.json");

      // A SECOND, independent grant for the SAME session. Without it this arm cannot tell a
      // per-GRANT ledger from a per-SESSION one: an agent that allowed exactly one elevation per
      // session would satisfy every other assertion here, and would break the feature (a technician
      // gets one elevated command and then silently none) while looking correct.
      const grantB = await mintElevation(start.session!.id!, "elev-grant-b.json");

      // A grant that CANNOT verify: the genuine one with one signature character flipped. It keeps
      // the same `elevation_id`, which is the point — if the ledger were claimed BEFORE
      // verification, this forgery would burn the real grant's id and the real grant would then be
      // refused as spent. That ordering rule is asserted in three comments and, until this, was
      // tested nowhere for elevation.
      const tampered = join(workDir, "elev-grant-tampered.json");
      const genuine = readFileSync(grant, "utf8");
      writeFileSync(
        tampered,
        genuine.replace(/"sig":"(.)/, (_m, c: string) => '"sig":"' + (c === "a" ? "b" : "a")),
        "utf8",
      );
      expect(readFileSync(tampered, "utf8"), "the tamper did not change the blob").not.toBe(genuine);

      // ASK FOR AN ORDINARY `as_user` RUN FIRST, and only then the elevated one. That first step is
      // what makes this arm mean "elevated" rather than "ran a command". An agent that elevated
      // EVERY command would satisfy every assertion below byte-identically — this is loop 86's
      // lesson (assert the privilege was ABSENT before asserting it was granted) applied to the
      // thing that GRANTS rather than the thing that restricts. The mutation it kills is
      // `RunIdentity::from_as_user` returning `UserElevated`, or the `RunCommand` arm passing
      // `UserElevated` outright.
      //
      // Then, in order: the view-only gate refuses one (and must NOT spend it), the tampered blob is
      // refused (and must NOT spend it either), the genuine grant is ACCEPTED, presenting it again
      // is refused as spent, and a DIFFERENT grant still works.
      const probeLog = await driveProbe(
        ticket,
        [
          "wait:1200",
          "run-user:cmd:whoami", // ABSENT FIRST
          "wait:600",
          "view-only", // floor the session with the technician's own toggle
          "elevate:" + grant + ":cmd:whoami", // refused: view-only. MUST NOT burn the grant.
          "wait:400",
          "view-control",
          "elevate:" + tampered + ":cmd:whoami", // refused: bad signature. MUST NOT burn the id.
          "wait:400",
          "elevate:" + grant + ":cmd:whoami", // ACCEPTED — which proves both non-burns above
          "wait:600",
          "elevate:" + grant + ":cmd:whoami", // refused: already used
          "wait:400",
          "elevate:" + grantB + ":cmd:whoami", // ACCEPTED — single use is per GRANT, not per session
        ].join(";"),
        20,
      );
      const ctx = () => `agent log:\n${log()}\nprobe log:\n${probeLog}`;

      // 1. ABSENT FIRST — the plain command ran with the USER's base token, not an elevated one.
      //    The trailing ` shell=` matters: `identity=User` is a prefix of `identity=UserElevated`.
      expect(
        await waitFor(async () => log().includes("identity=User shell="), 20_000),
        `the ordinary as_user command never reached the runner. ${ctx()}`,
      ).toBe(true);

      // 2. THE VIEW-ONLY GATE. An elevation grant authorizes a TOKEN, never an action a floored
      //    session may not take. Deleting this gate would let a read-only session run commands as
      //    the guest's administrator — the single worst outcome this feature could have.
      expect(
        await waitFor(
          async () => log().includes("elevated command refused: session is view-only"),
          20_000,
        ),
        `a VIEW-ONLY session accepted an elevated command. ${ctx()}`,
      ).toBe(true);

      // 3. THE TAMPERED BLOB is refused, and refused ON THE SIGNATURE — not by some later check
      //    that happened to fire first.
      expect(
        await waitFor(async () => log().includes("signature is invalid"), 20_000),
        `a grant with a corrupted signature was not refused on the signature. ${ctx()}`,
      ).toBe(true);

      // 4. GRANTED — the control plane's grant verified against the pinned issuer AND the live
      //    session id, and the runner received the ELEVATED identity. This ALSO proves the two
      //    refusals above did not burn it: if either had, this would read "already been used".
      expect(
        await waitFor(async () => log().includes("elevation grant verified"), 20_000),
        `the agent rejected its OWN session's grant — or a refused attempt burned it. ${ctx()}`,
      ).toBe(true);
      expect(
        log(),
        `the grant verified but the runner did not get the elevated identity — the authorization is
         decorative. ${ctx()}`,
      ).toContain("identity=UserElevated");

      // 5. SINGLE USE — the SAME grant presented again is refused. Without this a captured grant is
      //    reusable for its whole TTL by whoever holds it.
      expect(
        await waitFor(async () => log().includes("already been used"), 20_000),
        `the same elevation grant was accepted TWICE. ${ctx()}`,
      ).toBe(true);

      // 6. …but a DIFFERENT grant for the SAME session still works, so single use is per GRANT.
      //    Counted rather than matched: exactly TWO verifications (grant, then grantB), which also
      //    pins that the tampered blob and the view-only attempt verified NEITHER.
      expect(
        await waitFor(
          async () => (log().match(/elevation grant verified/g) ?? []).length === 2,
          20_000,
        ),
        `expected exactly 2 verified grants (the genuine one, then a second independent one); got ` +
          `${(log().match(/elevation grant verified/g) ?? []).length}. A per-SESSION ledger shows 1 ` +
          `and would silently give a technician ONE elevated command per session. ${ctx()}`,
      ).toBe(true);
    },
    noFloor,
  );

  // ---- ARM 2: the REPLAY across sessions is refused ------------------------------------------
  // Arm 1 alone would pass on an agent that accepted any signed grant regardless of session. This is
  // the attack the session binding exists for, and it is a REAL grant — correctly signed, unexpired,
  // same machine — differing in exactly one field. Tampering with the JSON would only re-prove the
  // signature check.
  await withFlooredAgent(
    machine,
    async (log) => {
      const startA = (await cpPost("/sessions", { machine_id: device })) as { session?: { id?: string } };
      const startB = (await cpPost("/sessions", { machine_id: device })) as {
        session?: { id?: string };
        signaling?: { ticket?: SignedTicket };
      };
      expect(
        startB.session?.id,
        "premise not met: the two sessions share an id, so there is no replay to attempt",
      ).not.toBe(startA.session?.id);

      const grantA = await mintElevation(startA.session!.id!, "elev-grant-replay.json");
      const ticketB = join(workDir, "elev-ticket-b.json");
      writeFileSync(ticketB, JSON.stringify(startB.signaling!.ticket!), "utf8");

      const probeLog = await driveProbe(ticketB, `wait:1200;elevate:${grantA}:cmd:whoami`, 16);
      const ctx = () => `agent log:\n${log()}\nprobe log:\n${probeLog}`;
      expect(
        await waitFor(async () => log().includes("rejected ElevatedRun"), 20_000),
        `the agent ACCEPTED an elevation grant minted for a DIFFERENT session — every captured grant
         is then replayable at this machine for its whole TTL. ${ctx()}`,
      ).toBe(true);
      // …and it must say WHY. Without this a future refactor could satisfy the assertion above by
      // refusing for an unrelated reason (clock skew, a device mismatch) while the binding lapsed.
      expect(
        log(),
        `the refusal was not the SESSION binding — this arm would then prove nothing. ${ctx()}`,
      ).toContain("different session");
      // NOTHING RAN. The refusal happens before the runner is ever reached, so no elevated identity
      // may appear in this arm's log at all.
      expect(
        log(),
        `a refused elevation still reached the command runner. ${ctx()}`,
      ).not.toContain("identity=UserElevated");
    },
    noFloor,
  );

  // ---- ARM 3: the ATTENDED host refuses — BEFORE the burn ------------------------------------
  // The `can_elevate()` gate in the ElevatedRun dispatch had no test at all: every other arm runs
  // with `--simulate-unattended-host`, so the gate was always FALSE-y and deleting it left the whole
  // tree green. It exists because an attended agent runs at the guest's own medium integrity and
  // Windows will not let it create a high-integrity process without a UAC consent no remote peer can
  // supply (loop 84, measured on LAB-VM).
  //
  // The interesting half is not the refusal, it is its POSITION — and the gate has a neighbour on
  // EACH side, so this arm pins both:
  //
  //   * BEFORE the burn, because a host that could never have honoured a grant must not spend the
  //     technician's only authorization. Invisible to a single presentation, so the arm presents the
  //     SAME grant TWICE and requires the second answer to be the UAC refusal again, never "already
  //     been used". Move the burn ahead of the gate and this goes red while every other arm stays
  //     green.
  //   * AFTER verification, so an unverifiable blob learns nothing about the host. Pinned by
  //     presenting a TAMPERED blob first and requiring the SIGNATURE refusal — hoist the host gate
  //     out of the `BackstageAuth::SignedBy` arm and the tampered blob would answer "cannot elevate"
  //     instead, telling an attacker which host they are talking to before proving anything.
  //     (Without this step the comment claimed an ordering the assertions did not check.)
  await withFlooredAgent(
    machine,
    async (log) => {
      const start = (await cpPost("/sessions", { machine_id: device })) as {
        session?: { id?: string };
        signaling?: { ticket?: SignedTicket };
      };
      const ticket = join(workDir, "elev-ticket-attended.json");
      writeFileSync(ticket, JSON.stringify(start.signaling!.ticket!), "utf8");
      const grant = await mintElevation(start.session!.id!, "elev-grant-attended.json");
      // The same one-character signature flip arm 1 uses. Presented FIRST, so the ordering claim
      // above is checked rather than asserted.
      const tampered = join(workDir, "elev-grant-attended-tampered.json");
      const genuine = readFileSync(grant, "utf8");
      writeFileSync(
        tampered,
        genuine.replace(/"sig":"(.)/, (_m, c: string) => '"sig":"' + (c === "a" ? "b" : "a")),
        "utf8",
      );
      expect(readFileSync(tampered, "utf8"), "the tamper did not change the blob").not.toBe(genuine);

      const probeLog = await driveProbe(
        ticket,
        [
          "wait:1200",
          "elevate:" + tampered + ":cmd:whoami", // refused: SIGNATURE — before the host is consulted
          "wait:600",
          "elevate:" + grant + ":cmd:whoami", // refused: this host cannot elevate
          "wait:600",
          "elevate:" + grant + ":cmd:whoami", // SAME grant — must get the SAME refusal, not "spent"
        ].join(";"),
        20,
      );
      const ctx = () => `agent log:\n${log()}\nprobe log:\n${probeLog}`;

      // ORDERING, half one: verification runs BEFORE the host gate. A tampered blob must be refused
      // on the signature and must NOT be told anything about this host's ability to elevate.
      expect(
        await waitFor(async () => log().includes("signature is invalid"), 20_000),
        `a tampered grant was not refused on the signature. ${ctx()}`,
      ).toBe(true);

      expect(
        await waitFor(async () => log().includes("cannot elevate without a UAC prompt"), 20_000),
        `an ATTENDED agent accepted an elevated command. ${ctx()}`,
      ).toBe(true);
      expect(
        log(),
        `an attended host reached the command runner with the elevated identity. ${ctx()}`,
      ).not.toContain("identity=UserElevated");

      // THE ORDERING ASSERTION. Both presentations must be refused for the HOST reason; a burn
      // ahead of the gate would make the second one "already been used" and would have silently
      // cost the technician a grant on a host that could never use it.
      expect(
        await waitFor(
          async () => (log().match(/cannot elevate without a UAC prompt/g) ?? []).length === 2,
          20_000,
        ),
        `expected the SAME host refusal twice; got ` +
          `${(log().match(/cannot elevate without a UAC prompt/g) ?? []).length}. ${ctx()}`,
      ).toBe(true);
      expect(
        log(),
        `the grant was BURNED by a host that could never honour it — the gate ran after the ledger
         claim, not before it. ${ctx()}`,
      ).not.toContain("already been used");
    },
    { requireSessionPolicy: false, simulateUnattendedHost: false },
  );

  // ---- ARM 4: no pinned issuer ⇒ elevation is refused outright --------------------------------
  // The fail-closed default for an agent that cannot verify ANY signature. Nothing tested it, and
  // replacing the refusal with `None` left every suite green while making the agent elevate on an
  // UNSIGNED request.
  //
  // Be precise about WHICH posture this is, because the two that share the refusal are not equally
  // alarming. Omitting `--grant-issuer` yields `BackstageAuth::InsecureSelfIssued` — the DEV posture,
  // which already self-issues a full demo grant and says so loudly at startup. An INSTALLED service
  // with no `grant_issuer_pubkey` in its config lands on `BackstageAuth::Deny` instead. They reach
  // the same refusal only because `host.rs` matches them in ONE arm, so this exercises the arm for
  // both — but it exercises the DEV variant, and a future split of that match would leave `Deny`
  // uncovered here.
  await withFlooredAgent(
    machine,
    async (log) => {
      const start = (await cpPost("/sessions", { machine_id: device })) as {
        session?: { id?: string };
        signaling?: { ticket?: SignedTicket };
      };
      const ticket = join(workDir, "elev-ticket-unpinned.json");
      writeFileSync(ticket, JSON.stringify(start.signaling!.ticket!), "utf8");
      // A GENUINE grant, correctly signed by the real issuer for this very session. The point is
      // that the agent has no key to check it with — not that the artifact is bad.
      const grant = await mintElevation(start.session!.id!, "elev-grant-unpinned.json");

      const probeLog = await driveProbe(ticket, `wait:1200;elevate:${grant}:cmd:whoami`, 16);
      const ctx = () => `agent log:\n${log()}\nprobe log:\n${probeLog}`;

      expect(
        await waitFor(async () => log().includes("rejected ElevatedRun"), 20_000),
        `an agent with NO pinned issuer key accepted an elevated command. ${ctx()}`,
      ).toBe(true);
      // The ELEVATION wording specifically. `host.rs` has a second "no pinned issuer key" refusal
      // for session-policy installs, and matching the shared prefix would let this arm pass on a
      // refusal that has nothing to do with elevation.
      expect(
        log(),
        `the refusal was not the missing-issuer one, so this arm proves nothing. ${ctx()}`,
      ).toContain("no pinned issuer key, so an elevation grant");
      expect(
        log(),
        `an unverifiable elevation still reached the command runner. ${ctx()}`,
      ).not.toContain("identity=UserElevated");
    },
    { requireSessionPolicy: false, simulateUnattendedHost: true, pinIssuer: false },
  );
});
