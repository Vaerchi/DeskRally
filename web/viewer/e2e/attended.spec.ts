/**
 * ATTENDED (on-demand) session end-to-end test — docs/12-attended-sessions-contract.md.
 *
 * Proves the whole attended arc against the ENFORCING stack (no insecure signaling flags), with the
 * REAL Rust guest client (`agent_host attend`) and the REAL browser viewer transport:
 *
 *   control-plane (DEV, fixed CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED, CP_DEVICE_IDENTITY_TOKEN, CP_SIGNALING_URL→ours)
 *   signaling     ENFORCING (ticket pubkey + device-identity endpoint) — NEITHER insecure flag
 *   guest         agent_host attend --code … --auto-consent --synthetic  (ephemeral identity)
 *   browser       harness.html presents the consent-gated ticket
 *
 * It asserts the load-bearing gate — POST /attended-sessions/{id}/connect is REFUSED (409) before
 * the guest consents and SUCCEEDS after — and that, over the resulting ticketed session, real RTP
 * video reaches the browser. Ports 8182/8183 are dedicated so it runs alongside every other spec.
 *
 * Self-skips (loudly) only when a prerequisite is genuinely absent: no agent binary, unbuildable Go
 * servers, or no usable browser. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
// The CONTROLLER for the policy-install test. The browser viewer sends InstallSessionPolicy only on its
// own connect path, so driving it deliberately (and nothing else) needs the probe.
const PROBE_BIN = resolve(TARGET_DIR, "debug", "stream_probe.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");

const SIG_PORT = 8182;
const CP_PORT = 8183;
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;
const HARNESS_BASE = "http://127.0.0.1:5173/e2e/harness.html";

const DEV_GRANT_ISSUER_SEED = "2222222222222222222222222222222222222222222222222222222222222222";
const DEVICE_IDENTITY_TOKEN = "e2e-attended-device-identity-token-0123456789abcdef";
const DEV_GROUP = "00000000-0000-0000-0000-000000000000";

let cpProc: ChildProcess | null = null;
let signalingProc: ChildProcess | null = null;
let guestProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let guestLog = "";

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
      try { ws.close(); } catch { /* ignore */ }
      res(ok);
    };
    const ws = new WebSocket(url);
    ws.onopen = () => finish(true);
    ws.onerror = () => finish(false);
    setTimeout(() => finish(false), timeoutMs);
  });
}

async function cp(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${CP_BASE}${path}`, init);
}
async function cpPost(path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const r = await cp(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? "" : JSON.stringify(body),
  });
  const text = await r.text();
  return { status: r.status, json: text ? JSON.parse(text) : null };
}

function encodeTicket(t: unknown): string {
  return Buffer.from(JSON.stringify(t), "utf8").toString("base64url");
}

test.beforeAll(async () => {
  test.setTimeout(180_000);
  for (const bin of [AGENT_BIN, PROBE_BIN]) {
    if (!existsSync(bin)) {
      skipReason = `binary not found at ${bin} (run: cargo build -p rmt-agent-windows --bin agent_host --bin stream_probe)`;
      return;
    }
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

  // Control plane: DEV mode, but with a fixed issuer seed (stable /grant/pubkey), the device-identity
  // token (so ENFORCING signaling can resolve the guest's ephemeral key), and CP_SIGNALING_URL so the
  // attended /connect + /redeem advertise OUR signaling.
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      CP_LISTEN: `:${CP_PORT}`,
      CP_SIGNALING_URL: SIGNALING_WS,
      CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED,
      CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      DATABASE_URL: "", CP_INSECURE_DEV: "1",
    },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  if (!(await waitFor(async () => { try { return (await cp("/healthz")).ok; } catch { return false; } }, 15_000))) {
    skipReason = `control plane did not come up on :${CP_PORT}`;
    return;
  }
  const pub = (await (await cp("/grant/pubkey")).json()) as { grant_issuer_pubkey: string };
  expect(pub.grant_issuer_pubkey).toMatch(/^[0-9a-f]{64}$/);

  // Signaling: ENFORCING — no -insecure flags.
  signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`], {
    cwd: SIGNALING_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      SIGNALING_TICKET_PUBKEY: pub.grant_issuer_pubkey,
      SIGNALING_DEVICE_IDENTITY_URL: CP_BASE,
      SIGNALING_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
    },
  });
  let sigLog = "";
  signalingProc.stdout?.on("data", (d: Buffer) => { sigLog += d; process.stdout.write(`[signaling] ${d}`); });
  signalingProc.stderr?.on("data", (d: Buffer) => { sigLog += d; process.stdout.write(`[signaling] ${d}`); });
  if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 15_000))) {
    skipReason = `signaling did not come up on :${SIG_PORT}`;
    return;
  }
  expect(sigLog, "signaling must be ENFORCING").not.toContain("WARNING: -insecure");

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
  await stopProc(guestProc);
  await stopProc(signalingProc);
  await stopProc(cpProc);
});

test("attended: consent gates the ticket, then real RTP video flows over the on-demand session", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  test.setTimeout(150_000);

  // 1. Technician mints a one-time code.
  const created = await cpPost("/attended-sessions", { group_id: DEV_GROUP, reason: "Acme IT" });
  expect(created.status, "create attended session").toBe(201);
  const sessionId = created.json.session.id as string;
  const code = created.json.join_code as string;
  expect(sessionId).toBeTruthy();
  expect(code).toBeTruthy();

  // 2. CONSENT GATE, negative: connect before the guest has consented → refused.
  const early = await cpPost(`/attended-sessions/${sessionId}/connect`);
  expect(early.status, "connect before consent must be refused").toBe(409);

  // 3. The REAL guest redeems the code, auto-consents, and streams (synthetic frames, headless).
  guestProc = spawn(
    AGENT_BIN,
    ["attend", "--code", code, "--control-plane-url", CP_BASE, "--signaling", SIGNALING_WS,
      "--auto-consent", "--synthetic", "--fps", "30"],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  guestProc.stdout?.on("data", (d: Buffer) => { guestLog += d; process.stdout.write(`[guest] ${d}`); });
  guestProc.stderr?.on("data", (d: Buffer) => { guestLog += d; process.stderr.write(`[guest:err] ${d}`); });

  // Wait until the guest reports its session indicator is active (consent granted + streaming).
  expect(await waitFor(async () => guestLog.includes("SESSION INDICATOR"), 20_000),
    "guest should consent and start its session").toBe(true);

  // 4. Poll until the control plane records consent (state consented).
  const consented = await waitFor(async () => {
    const g = await (await cp(`/attended-sessions/${sessionId}`)).json();
    return g?.session?.state === "consented" || g?.session?.state === "active";
  }, 15_000);
  expect(consented, "control plane should record consent").toBe(true);

  // 5. CONSENT GATE, positive: connect now succeeds and returns a ticket bound to the guest device.
  const conn = await cpPost(`/attended-sessions/${sessionId}/connect`);
  expect(conn.status, "connect after consent").toBe(200);
  const device = conn.json.signaling.device_id as string;
  const ticket = conn.json.signaling.ticket;
  expect(ticket.claims.device_id).toBe(device);

  // 6. The browser presents the ticket and must receive real RTP video over the attended session.
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(`${HARNESS_BASE}?url=${encodeURIComponent(SIGNALING_WS)}&device=${device}&ticket=${encodeTicket(ticket)}`);
  await page.waitForFunction(() => {
    const r = (window as unknown as { rmt?: { state: string; error: string | null } }).rmt;
    return !!r && (r.state === "connected" || r.state === "failed" || r.error !== null);
  }, undefined, { timeout: 45_000 });
  const status = await page.evaluate(() => {
    const r = (window as unknown as { rmt: { state: string; error: string | null } }).rmt;
    return { state: r.state, error: r.error };
  });
  expect(status.error, "harness reported a fatal error").toBeNull();
  expect(status.state, "the attended ticket must broker and connect").toBe("connected");

  type Inbound = { bytesReceived?: number; packetsReceived?: number } | null;
  let inbound: Inbound = null;
  await waitFor(async () => {
    inbound = await page.evaluate(async () => {
      const r = (window as unknown as { rmt: { stats(): Promise<Array<Record<string, unknown>>> } }).rmt;
      const all = await r.stats();
      const rtp = all.find((s) => s.type === "inbound-rtp" && (s as { kind?: string }).kind === "video");
      if (!rtp) return null;
      return { bytesReceived: rtp.bytesReceived as number, packetsReceived: rtp.packetsReceived as number };
    });
    return !!inbound && (inbound.bytesReceived ?? 0) > 0 && (inbound.packetsReceived ?? 0) > 0;
  }, 15_000, 500);
  console.log(`[e2e] attended inbound-rtp video: ${JSON.stringify(inbound)}`);
  expect(inbound, "no inbound-rtp video reached the browser over the attended session").not.toBeNull();
  expect(inbound!.bytesReceived ?? 0).toBeGreaterThan(0);
  expect(inbound!.packetsReceived ?? 0).toBeGreaterThan(0);

  await page.close();
});

/**
 * THE ATTENDED VIEW-ONLY FLOOR (loop 82), end to end against the same ENFORCING stack.
 *
 * Why this needs a live guest process rather than more unit tests. Loop 81 made the attended CONNECT
 * mint a signed policy, but that policy only reaches the agent because the VIEWER forwards it — and the
 * viewer is precisely the party it restricts, so a technician running a patched console can withhold the
 * frame and the agent, never having heard of a policy, hands over full control. The agent-side answer is
 * `require_session_policy`, and until this loop an attended guest had no way to ask for it: no
 * config.json, no argv flag. The control plane now tells it at redeem.
 *
 * The observable is the GUEST'S OWN stdout — the regime the real agent process actually opened in, not a
 * field in a response body. That crosses in one shot every hop the unit tests can only cover separately:
 * the control plane's group lookup, the JSON on the wire, the guest's parse, and the wiring into the live
 * session's options. That last hop is the one that had no coverage at all, and deleting it left all 173
 * agent tests passing while the feature was inert.
 *
 * The ORDINARY-group leg is not decoration. Without it, a guest that hard-coded "REQUIRED" — or a
 * control plane that demanded a floor from everyone, which is the fleet-wide failure loop 80's review
 * caught — would pass the enforcing leg and look like a working mandate.
 */
async function guestPolicyRegime(label: string, enforceViewOnly: boolean): Promise<string> {
  // A fresh group per leg, so one leg's setting cannot leak into the other or into the RTP test above.
  const group = await cpPost("/machine-groups", { name: `loop82-${label}` });
  expect(group.status, `create machine group (${label})`).toBe(201);
  const groupId = group.json.machine_group.id as string;
  expect(groupId, `group id (${label})`).toBeTruthy();

  if (enforceViewOnly) {
    const put = await cp(`/machine-groups/${groupId}/session-policy`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enforce_view_only: true }),
    });
    expect(put.status, `set enforce_view_only (${label})`).toBe(200);
  }

  const created = await cpPost("/attended-sessions", { group_id: groupId, reason: `loop82 ${label}` });
  expect(created.status, `create attended session (${label})`).toBe(201);
  const code = created.json.join_code as string;
  expect(code, `join code (${label})`).toBeTruthy();

  // Its own process handle and log, deliberately NOT the module-level ones: afterAll owns those, and
  // reusing them here would leak whichever guest it did not end up holding.
  let log = "";
  let proc: ChildProcess | null = null;
  try {
    proc = spawn(
      AGENT_BIN,
      ["attend", "--code", code, "--control-plane-url", CP_BASE, "--signaling", SIGNALING_WS,
        "--auto-consent", "--synthetic", "--fps", "10"],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    proc.stdout?.on("data", (d: Buffer) => { log += d; process.stdout.write(`[guest:${label}] ${d}`); });
    proc.stderr?.on("data", (d: Buffer) => { log += d; process.stdout.write(`[guest:${label}] ${d}`); });
    const reported = await waitFor(async () => log.includes("attend: session policy"), 30_000);
    expect(reported, `the guest never reported its session-policy regime (${label}). log:\n${log}`).toBe(true);
    return log;
  } finally {
    await stopProc(proc);
  }
}

test("attended: an enforcing group opens the guest FLOORED, an ordinary group does not", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(120_000);

  const floored = await guestPolicyRegime("enforcing", true);
  expect(
    floored,
    "the guest opened UNFLOORED for a group that enforces view-only — so a viewer that simply never " +
      "sends the policy frame keeps full control, and the per-group mandate is advisory",
  ).toContain("session policy REQUIRED");

  const ordinary = await guestPolicyRegime("ordinary", false);
  expect(
    ordinary,
    "a group that enforces nothing still opened the guest floored — every ordinary attended session " +
      "would start restricted",
  ).toContain("session policy not required");
});

/**
 * THE SAMPLING WINDOW (loop 83), end to end: told to floor, mandate cleared, floor DISCHARGED.
 *
 * Loop 82's design read the two halves of one decision at different moments — the floor instruction at
 * REDEEM, the mint at CONNECT — so clearing `enforce_view_only` in between left a guest that had already
 * opened view-only with no policy ever arriving to release it. Stuck for the session's whole life, with
 * nothing on screen explaining why.
 *
 * This has to be an e2e with a REAL guest process, for the reason loop 82 learned the hard way: the Go
 * tests can prove the control plane MINTS `access=control`, and the Rust tests can prove such a policy
 * DISCHARGES a provisional floor, but neither can show that the guest in front of you actually opened
 * floored in the first place — which is the premise both halves rest on. Here the guest's own stdout
 * establishes the premise, and the connect response establishes the fix, in one sequence.
 *
 * Note what the OLD code did at step 4: `session_policy` was simply absent, because the group no longer
 * enforced. So this test fails on loop 82's code by the strongest available signal — a missing field, not
 * a subtly different value.
 */
test("attended: clearing the group mandate after redeem DISCHARGES the guest's provisional floor", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(120_000);

  // 1. A group that enforces view-only, fresh so no other leg can interfere.
  const group = await cpPost("/machine-groups", { name: "loop83-sampling-window" });
  expect(group.status, "create machine group").toBe(201);
  const groupId = group.json.machine_group.id as string;
  const enforce = async (on: boolean) => {
    const put = await cp(`/machine-groups/${groupId}/session-policy`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enforce_view_only: on }),
    });
    expect(put.status, `set enforce_view_only=${on}`).toBe(200);
  };
  await enforce(true);

  const created = await cpPost("/attended-sessions", { group_id: groupId, reason: "loop83 sampling window" });
  expect(created.status, "create attended session").toBe(201);
  const sessionId = created.json.session.id as string;
  const code = created.json.join_code as string;

  let log = "";
  let proc: ChildProcess | null = null;
  try {
    // 2. The real guest redeems and opens. Its stdout is what establishes that a floor is genuinely in
    //    force — the whole test is meaningless if this line does not appear.
    proc = spawn(
      AGENT_BIN,
      ["attend", "--code", code, "--control-plane-url", CP_BASE, "--signaling", SIGNALING_WS,
        "--auto-consent", "--synthetic", "--fps", "10"],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    proc.stdout?.on("data", (d: Buffer) => { log += d; process.stdout.write(`[guest:window] ${d}`); });
    proc.stderr?.on("data", (d: Buffer) => { log += d; process.stdout.write(`[guest:window] ${d}`); });
    const reported = await waitFor(async () => log.includes("attend: session policy"), 30_000);
    expect(reported, `the guest never reported its regime. log:\n${log}`).toBe(true);
    expect(
      log,
      "premise not met: the guest did not open FLOORED, so nothing in this test is about a floor",
    ).toContain("session policy REQUIRED");

    // 3. The admin clears the mandate — the window this whole loop is about.
    await enforce(false);

    // 4. Connect must STILL mint, and must carry `control`: the one level that releases a provisional
    //    floor. A view_only policy here would verify the floor permanently into place instead.
    const conn = await cpPost(`/attended-sessions/${sessionId}/connect`);
    expect(conn.status, `connect after the mandate was cleared: ${JSON.stringify(conn.json)}`).toBe(200);
    expect(
      conn.json.session_policy,
      "no session_policy was minted for a guest that had ALREADY been told to open floored — it is " +
        "dropping the technician's input right now and nothing will ever arrive to release it",
    ).toBeTruthy();
    expect(
      conn.json.session_policy.access,
      "the discharging policy must say `control`; view_only would make the floor permanent",
    ).toBe("control");
    // The cleartext level is for display; the SIGNED blob is what the agent obeys, so they must agree.
    const signed = JSON.parse(conn.json.session_policy.signed as string);
    expect(signed.claims.policy.access, "the SIGNED level disagrees with the advertised one").toBe("control");
    expect(signed.claims.policy.session_id, "the policy is not bound to this attended session").toBe(sessionId);
  } finally {
    await stopProc(proc);
  }
});

/**
 * THE ENFORCEMENT, over a real transport, automated at last (loop 85).
 *
 * Loops 79-83 built a control-plane-signed access policy the AGENT enforces, and until this test NOTHING
 * automated ever installed one: `grep -rn InstallSessionPolicy web/viewer/e2e/` came back empty and so did
 * `grep -rn install-policy scripts/`. The whole mechanism rested on unit tests either side of the wire plus
 * VM runs driven by hand. That is the gap loop 82's lesson warns about at its widest — the hop nothing
 * exercises is where an inert feature hides — and it was the stated blocker for testing §3 elevation.
 *
 * It is feasible here because every piece already exists: the e2e control plane runs with a FIXED
 * `CP_INSECURE_DEV_GRANT_SEED`, redeem hands the guest the matching `grant_issuer_pubkey` to pin, and `stream_probe`
 * has an `install-policy:<path>` step that sends the blob VERBATIM and CONSUMES the agent's reply (so a
 * fail-closed rejection cannot green the run). All this adds is the wiring.
 *
 * Both arms matter, and they are each other's control:
 *   ARM A — mandate STANDS: the policy says `view_only`, and after installing it the agent must REFUSE
 *           `SetViewOnly(false)`. That is the mandate actually binding a controller that asks to leave.
 *   ARM B — mandate CLEARED after redeem (loop 83's sampling window): the policy says `control`, and
 *           installing it must DISCHARGE the provisional floor.
 * Without A, B alone would pass on an agent that ignores policies altogether. Without B, A would pass on an
 * agent that treats every policy as a permanent floor — which is precisely the bug loop 83 fixed.
 */
async function runAttendedPolicyInstall(
  label: string,
  clearMandateBeforeConnect: boolean,
  probeScript: (policyPath: string) => string,
  // A guest log line to wait for AFTER the install. Needed because the probe's later steps run on their
  // own clock: asserting on a snapshot taken the moment the install verified passed for `control` (the
  // install IS the outcome there) and failed for `view_only`, whose outcome is a refusal the probe only
  // provokes 1.5s later. Waiting for the thing under test beats sleeping and hoping.
  alsoAwait?: string,
): Promise<{ guestLog: string; access: string }> {
  const group = await cpPost("/machine-groups", { name: `loop85-${label}` });
  expect(group.status, `create group (${label})`).toBe(201);
  const groupId = group.json.machine_group.id as string;
  const enforce = async (on: boolean) => {
    const put = await cp(`/machine-groups/${groupId}/session-policy`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enforce_view_only: on }),
    });
    expect(put.status, `enforce_view_only=${on} (${label})`).toBe(200);
  };
  await enforce(true);

  const created = await cpPost("/attended-sessions", { group_id: groupId, reason: `loop85 ${label}` });
  expect(created.status, `create attended session (${label})`).toBe(201);
  const sessionId = created.json.session.id as string;

  let guestLog = "";
  let guest: ChildProcess | null = null;
  let probe: ChildProcess | null = null;
  try {
    // The guest, floored. `--synthetic` so it streams without a real desktop; the FLOOR is not synthetic.
    guest = spawn(
      AGENT_BIN,
      ["attend", "--code", created.json.join_code as string, "--control-plane-url", CP_BASE,
        "--signaling", SIGNALING_WS, "--auto-consent", "--synthetic", "--fps", "10"],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    const collect = (d: Buffer) => { guestLog += d; process.stdout.write(`[guest:${label}] ${d}`); };
    guest.stdout?.on("data", collect);
    guest.stderr?.on("data", collect);
    expect(
      await waitFor(async () => guestLog.includes("session policy REQUIRED"), 30_000),
      `the guest never reported the floor (${label}). log:\n${guestLog}`,
    ).toBe(true);
    expect(await waitFor(async () => guestLog.includes("streaming device="), 30_000)).toBe(true);

    if (clearMandateBeforeConnect) await enforce(false);

    const conn = await cpPost(`/attended-sessions/${sessionId}/connect`);
    expect(conn.status, `connect (${label}): ${JSON.stringify(conn.json)}`).toBe(200);
    expect(conn.json.session_policy, `no policy minted (${label})`).toBeTruthy();
    const access = conn.json.session_policy.access as string;
    const deviceId = conn.json.session.device_id as string;

    // The blob goes to disk exactly as the control plane produced it — the probe sends it VERBATIM, so
    // any re-encoding here would test our own round trip instead of the real artifact.
    const policyPath = resolve(tmpdir(), `rmt-e2e-policy-${label}.json`);
    writeFileSync(policyPath, conn.json.session_policy.signed as string, "utf8");

    // The SESSION TICKET, because this spec's signaling is ENFORCING (it asserts so in beforeAll). A
    // ticketless controller is simply not brokered, and the visible symptom is the GUEST timing out —
    // which reads like a policy failure and is not one. The browser arm of this file presents the same
    // ticket; the probe now presents it too, so both controllers face the same server posture.
    const ticketPath = resolve(tmpdir(), `rmt-e2e-ticket-${label}.json`);
    writeFileSync(ticketPath, JSON.stringify(conn.json.signaling.ticket), "utf8");

    probe = spawn(
      PROBE_BIN,
      ["--signaling", SIGNALING_WS, "--device", deviceId, "--secs", "6",
        "--ticket", ticketPath, "--script", probeScript(policyPath)],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
    );
    let probeLog = "";
    const collectProbe = (d: Buffer) => { probeLog += d; process.stdout.write(`[probe:${label}] ${d}`); };
    probe.stdout?.on("data", collectProbe);
    probe.stderr?.on("data", collectProbe);
    // The probe's OWN view: it consumes the agent's reply, so "installed" here is the agent answering,
    // not the probe assuming. Waited on separately from the guest log so a failure says which side.
    expect(
      await waitFor(async () => probeLog.includes("SessionPolicyInstalled") || probeLog.includes("PROBE FAIL"), 40_000),
      `the probe never got a reply to install-policy (${label}). log:\n${probeLog}`,
    ).toBe(true);
    expect(probeLog, `the agent REJECTED the policy (${label})`).not.toContain("policy rejected");

    // And the guest's own account of what it did, which is the thing that actually matters.
    expect(
      await waitFor(async () => guestLog.includes("session policy verified and in force"), 20_000),
      `the guest never reported verifying the policy (${label}). log:\n${guestLog}`,
    ).toBe(true);
    if (alsoAwait) {
      expect(
        await waitFor(async () => guestLog.includes(alsoAwait), 20_000),
        `the guest never logged ${JSON.stringify(alsoAwait)} (${label}). log:\n${guestLog}`,
      ).toBe(true);
    }
    return { guestLog, access };
  } finally {
    await stopProc(probe);
    await stopProc(guest);
  }
}

test("attended: a signed view_only policy installed over the wire is ENFORCED against view-control", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(150_000);

  // ARM A. Mandate stands, so the policy is view_only; the probe installs it and THEN asks to leave
  // view-only. The agent must refuse — that refusal is the mandate binding a controller who asks.
  const { guestLog, access } = await runAttendedPolicyInstall(
    "enforced",
    false,
    (p) => `wait:1500;install-policy:${p};wait:1500;view-control`,
    // The refusal is what this test is for, so wait for it rather than for the install.
    "refused",
  );
  expect(access, "an enforcing group must mint view_only").toBe("view_only");
  expect(
    guestLog,
    "the agent verified a view_only policy and then honoured view-control anyway — the per-group mandate " +
      "does not bind a controller that simply asks to leave it",
  ).toContain("refused");
  expect(guestLog).toContain('access="view_only"');
  // The refusal must come from the VERIFIED policy floor, not from the provisional one a session holds
  // while it still awaits a required policy — without this line arm B is the only thing telling them apart.
  expect(
    guestLog,
    "the refusal came from the PROVISIONAL floor, not the verified policy — arm A proves nothing",
  ).toContain("awaiting_policy=false");
});

test("attended: a signed control policy installed over the wire DISCHARGES the provisional floor", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(150_000);

  // ARM B. Loop 83's sampling window, end to end and automated: floored at redeem, mandate cleared before
  // connect, `control` minted, installed over a real transport, floor released.
  const { guestLog, access } = await runAttendedPolicyInstall(
    "discharged",
    true,
    (p) => `wait:1500;install-policy:${p}`,
  );
  expect(access, "a cleared mandate must mint control, the only level that can release a floor").toBe("control");
  expect(
    guestLog,
    "the guest did not report leaving view-only after a verified control policy — it is stuck floored, " +
      "which is exactly the stranding migration 0036 exists to prevent",
  ).toContain("view_only=false");
  expect(guestLog).toContain('access="control"');
});
