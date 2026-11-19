/**
 * docs/69 session binding, LIVE: a real control plane (cptestfixture, grants wired), real signaling (ticket
 * verification + agent auth), a really ENROLLED agent run with `--session-binding enforce`, and the real console.
 *
 *  1. The honest console binds: the status mark reads Verified, video flows, and the agent logs the binding.
 *  2. A console without binding material (the start response's `device_binding` stripped in the browser) cannot
 *     bind: the enforcing agent sends NO picture and ends the session at its deadline.
 *
 * The two-leg man in the middle (substituted DTLS fingerprints) is proven at the transcript level by the Rust and
 * TypeScript unit tests (agent/src/session_binding.rs, web/viewer/src/lib/session_binding.test.ts) and the live
 * fingerprint agreement by crates/transport-webrtc/tests/e2e_binding_fingerprints.rs.
 *
 * Needs the secure-test agent build (verify-all builds it) and cptestfixture.exe.
 */

import { PINNED } from "./chrome_pinned";
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stopProc } from "./devcp";
import { CP_PORT as SHARED_CP_PORT } from "./ports";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CPTESTFIXTURE_EXE = resolve(CP_DIR, "cptestfixture.exe");
const VITE_BASE = "http://127.0.0.1:5173";
const CP_PORT = Number(SHARED_CP_PORT);
const SIG_PORT = 8311;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;
const GRANT_SEED = "6969696969696969696969696969696969696969696969696969696969696969";
const DEVICE_IDENTITY_TOKEN = "e2e-binding-live-token-696969abcdef";
const MACHINE = "Binding-Live";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
async function waitFor(pred: () => Promise<boolean> | boolean, timeoutMs: number, stepMs = 250): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await Promise.resolve(pred()).catch(() => false)) return true;
    if (Date.now() > deadline) return false;
    await sleep(stepMs);
  }
}
const httpReachable = (url: string) => fetch(url, { signal: AbortSignal.timeout(500) }).then(() => true).catch(() => false);
function wsReachable(url: string): Promise<boolean> {
  return new Promise((res) => {
    const ws = new WebSocket(url);
    const done = (ok: boolean) => { try { ws.close(); } catch { /* ignore */ } res(ok); };
    ws.onopen = () => done(true);
    ws.onerror = () => done(false);
    setTimeout(() => done(false), 500);
  });
}

interface FixtureConfig {
  tenant_id: string; admin_email: string; admin_password: string;
  tech_a_email: string; tech_a_password: string; grant_issuer_pubkey: string;
}

function fixtureReady(proc: ChildProcess): Promise<FixtureConfig> {
  return new Promise((res, rej) => {
    let buf = "";
    const timer = setTimeout(() => rej(new Error("cptestfixture: FIXTURE_READY not received")), 30_000);
    proc.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      const line = buf.split("\n").find((l) => l.startsWith("FIXTURE_READY "));
      if (line) { clearTimeout(timer); res(JSON.parse(line.slice("FIXTURE_READY ".length)) as FixtureConfig); }
    });
  });
}

async function adminCookie(cfg: FixtureConfig): Promise<{ cookie: string; csrf: string }> {
  const r = await fetch(`${CP_BASE}/auth/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenant: cfg.tenant_id, email: cfg.admin_email, password: cfg.admin_password }),
  });
  if (!r.ok) throw new Error(`admin login ${r.status}`);
  const csrf = ((await r.json()) as { csrf_token: string }).csrf_token;
  const set = (r.headers as unknown as { getSetCookie: () => string[] }).getSetCookie();
  const pair = set.map((s) => s.split(";")[0]).find((p) => p.startsWith("cp_session=") || p.startsWith("__Host-cp_session="))!;
  return { cookie: `cp_session=${pair.split("=").slice(1).join("=")}; rmt_csrf=${csrf}`, csrf };
}

let cpProc: ChildProcess | null = null;
let sigProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let cfg: FixtureConfig;
let agentLog = "";
let workDir = "";
let deviceId = "";

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(180_000);
  for (const p of [AGENT_BIN, SIGNALING_EXE, CPTESTFIXTURE_EXE]) if (!existsSync(p)) throw new Error(`missing ${p}`);
  workDir = mkdtempSync(join(tmpdir(), "rmt-binding-live-"));
  cpProc = spawn(CPTESTFIXTURE_EXE, [], {
    cwd: CP_DIR, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CP_LISTEN: `127.0.0.1:${CP_PORT}`, CP_FIXTURE_GRANT_SEED: GRANT_SEED,
      CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN, CP_SIGNALING_URL: SIGNALING_WS },
  });
  cfg = await fixtureReady(cpProc);
  if (!(await waitFor(() => httpReachable(`${CP_BASE}/grant/pubkey`), 15_000))) throw new Error("CP not serving");

  let sigLog = "";
  sigProc = spawn(SIGNALING_EXE, ["-addr", `127.0.0.1:${SIG_PORT}`], {
    cwd: SIGNALING_DIR, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SIGNALING_TICKET_PUBKEY: cfg.grant_issuer_pubkey, SIGNALING_DEVICE_IDENTITY_URL: CP_BASE,
      SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN, SIGNALING_ALLOWED_ORIGINS: "*" },
  });
  sigProc.stdout?.on("data", (d: Buffer) => { sigLog += d.toString(); });
  sigProc.stderr?.on("data", (d: Buffer) => { sigLog += d.toString(); });
  if (!(await waitFor(() => wsReachable(SIGNALING_WS), 15_000))) throw new Error("signaling not up");

  // Enroll a real machine: the control plane stores the agent's real Ed25519 key (the binding's device key).
  const admin = await adminCookie(cfg);
  const tok = await fetch(`${CP_BASE}/enrollment-tokens`, {
    method: "POST", headers: { "content-type": "application/json", cookie: admin.cookie, "x-csrf-token": admin.csrf },
    body: JSON.stringify({ group_id: "00000000-0000-0000-0000-000000000000" }),
  }).then(async (r) => ((await r.json()) as { token: string }).token);
  const configPath = join(workDir, "config.json");
  const keyPath = join(workDir, "identity.key");
  writeFileSync(configPath, JSON.stringify({ signaling_url: SIGNALING_WS, identity_path: keyPath.replace(/\\/g, "/"), stun: [] }));
  await new Promise<void>((res, rej) => execFile(AGENT_BIN,
    ["enroll", "--control-plane-url", CP_BASE, "--token", tok, "--name", MACHINE, "--config", configPath],
    { timeout: 30_000 }, (err) => (err ? rej(err) : res())));
  const enrolled = JSON.parse(readFileSync(configPath, "utf8")) as { device_id: string; grant_issuer_pubkey?: string };
  deviceId = enrolled.device_id;
  // docs/69 §3.7: enrollment pinned the control plane's grant key.
  expect(enrolled.grant_issuer_pubkey).toBe(cfg.grant_issuer_pubkey);

  agentProc = spawn(AGENT_BIN, [
    "multi-stream", "--synthetic", "--device", enrolled.device_id, "--identity", keyPath, "--tenant", cfg.tenant_id,
    "--signaling", SIGNALING_WS, "--fps", "10", "--grant-issuer", cfg.grant_issuer_pubkey, "--session-binding", "enforce",
  ], { cwd: REPO, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RMT_LOG: "debug" } });
  agentProc.stdout?.on("data", (d: Buffer) => { agentLog += d.toString(); });
  agentProc.stderr?.on("data", (d: Buffer) => { agentLog += d.toString(); });
  if (!(await waitFor(() => sigLog.includes(`agent auth OK: device "${enrolled.device_id}"`), 60_000))) {
    throw new Error(`agent did not register\n${agentLog.slice(-1500)}`);
  }
  if (!agentLog.includes("secure-test-harness mode")) throw new Error(`agent lacks the secure-test build\n${agentLog.slice(-800)}`);
  browser = await chromium.launch({ channel: "chrome" });
});

test.afterAll(async () => {
  process.stdout.write(`[binding-live agent log tail]\n${agentLog.slice(-3000)}\n`);
  await browser?.close().catch(() => {});
  await stopProc(agentProc, 5_000);
  await stopProc(sigProc, 5_000);
  await stopProc(cpProc, 5_000);
  try { rmSync(workDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

async function loginAndConnect(page: Page): Promise<void> {
  await page.goto(`${VITE_BASE}/console`);
  await expect(page.getByTestId("app-login-gate")).toBeVisible({ timeout: 20_000 });
  await page.getByTestId("cp-login-tenant").fill(cfg.tenant_id);
  await page.getByTestId("cp-login-email").fill(cfg.tech_a_email);
  await page.getByTestId("cp-login-password").fill(cfg.tech_a_password);
  await page.getByTestId("cp-login-submit").click();
  const row = page.locator("li.access__machine").filter({ hasText: MACHINE });
  await expect(row).toBeVisible({ timeout: 20_000 });
  await row.getByRole("button", { name: /connect/i }).click();
}


test("an honest console binds to an enforcing agent: Verified, and the picture flows", async () => {
  test.setTimeout(120_000);
  const context = await browser!.newContext({ ...PINNED });
  const page = await context.newPage();
  const before = agentLog.length;
  await loginAndConnect(page);
  await expect(page.getByTestId("session-binding-status")).toHaveAttribute("data-state", "verified", { timeout: 45_000 });
  await page.waitForFunction(() => { const v = document.querySelector("video"); return !!v && v.readyState >= 2 && v.currentTime > 0; }, undefined, { timeout: 30_000 });
  expect(agentLog.slice(before)).toContain("console verified; the session is bound");
  await context.close();
});

test("a console that cannot bind gets no picture, and the enforcing agent ends the session", async () => {
  test.setTimeout(120_000);
  const context = await browser!.newContext({ ...PINNED });
  const page = await context.newPage();
  // Strip the binding material from the start response: this console never sends BindStart.
  await page.route("**/cp/sessions", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const resp = await route.fetch();
    const body = (await resp.json()) as Record<string, unknown>;
    delete body.device_binding;
    await route.fulfill({ response: resp, json: body });
  });
  const before = agentLog.length;
  await loginAndConnect(page);
  // With no binding material the console shows no mark at all (exactly as before binding was rolled out).
  await expect(page.locator(".viewer__status")).toBeVisible({ timeout: 45_000 });
  await expect(page.getByTestId("session-binding-status")).toHaveCount(0);
  // The enforcing agent ends the session at its 10 s deadline, having sent nothing.
  // The console sent no BindStart at all (its material was stripped), so the agent says the server sent no grant.
  expect(await waitFor(() => {
    const log = agentLog.slice(before);
    return log.includes("the console was not verified; ending the session") && log.includes("no_grant_received");
  }, 30_000)).toBe(true);
  // The AGENT's own count is the evidence: a <video> clock can tick on a live stream with no frame at all (the
  // gate saw currentTime 0.03 s with frames=0), so the picture check is "no decoded frame" plus the agent count.
  expect(await waitFor(() => /serve_session: finished frames=0 forwarded=0/.test(agentLog.slice(before)), 15_000)).toBe(true);
  // No REAL picture either: Chrome shows a 2x2 black placeholder for a remote track that never carried a frame (the
  // gate saw videoWidth 2 with frames=0); the synthetic screen is hundreds of pixels wide.
  expect(await page.evaluate(() => document.querySelector("video")?.videoWidth ?? 0)).toBeLessThan(16);
  expect(agentLog.slice(before)).not.toContain("console verified; the session is bound");
  await context.close();
});

// docs/69 6.2: an agent the server knows to speak binding v2 (0.1.33+) binds over the committed-nonce exchange, and the
// console offers the 6-digit comparison code. Last, because it changes the machine's recorded version.
test("binding v2: Verified with a comparison code the technician can open", async () => {
  test.setTimeout(120_000);
  const r = await fetch(`${CP_BASE}/fixture/agent-version`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, version: "0.1.33+e2e" }),
  });
  expect(r.status).toBe(204);
  const context = await browser!.newContext({ ...PINNED });
  const page = await context.newPage();
  const before = agentLog.length;
  await loginAndConnect(page);
  const mark = page.getByTestId("session-binding-status");
  await expect(mark).toHaveAttribute("data-state", "verified", { timeout: 45_000 });
  await expect(mark).toHaveAttribute("data-has-code", "");
  await mark.click();
  await expect(page.getByTestId("session-binding-code")).toContainText(/\d{3} \d{3}/);
  expect(agentLog.slice(before)).toContain("console verified; the session is bound");
  await context.close();
});

// Codex sas-impl r6 follow-up: with remote keyboard capture ON (the default), the comparison panel is reachable and
// operable from the keyboard alone: Enter opens it, Tab reaches "Codes differ", and Enter there ends the session for
// good (no recovery reconnect) with the technician's own explanation on screen.
test("binding v2: the keyboard alone reaches and operates Codes differ while input is captured", async () => {
  test.setTimeout(120_000);
  const r = await fetch(`${CP_BASE}/fixture/agent-version`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, version: "0.1.33+e2e" }),
  });
  expect(r.status).toBe(204);
  const context = await browser!.newContext({ ...PINNED });
  const page = await context.newPage();
  await loginAndConnect(page);
  const mark = page.getByTestId("session-binding-status");
  await expect(mark).toHaveAttribute("data-state", "verified", { timeout: 45_000 });
  await expect(mark).toHaveAttribute("data-has-code", "");
  await mark.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("session-binding-code")).toContainText(/\d{3} \d{3}/);
  const differ = page.getByTestId("session-binding-codes-differ");
  await page.keyboard.press("Tab");
  await expect(differ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText("You reported that the codes differ, so the session was ended.")).toBeVisible({ timeout: 15_000 });
  await expect(mark).toHaveCount(0);
  // Terminal: no recovery brings the session back.
  await page.waitForTimeout(8_000);
  await expect(page.getByTestId("session-binding-status")).toHaveCount(0);
  await context.close();
});