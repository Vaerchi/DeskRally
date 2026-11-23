/**
 * Milestone V4 — secure-mode backstage grant, end-to-end.
 *
 * Proves the DENIED→GRANTED transition over REAL WebRTC + a REAL control-plane mint. Orchestrates
 * every moving part:
 *   (a) the Go control plane in DEV mode with a FIXED `CP_INSECURE_DEV_GRANT_SEED` (stub auth ⇒ no login);
 *   (b) reads its `GET /grant/pubkey` (the issuer key the agent must pin);
 *   (c) the Go signaling server;
 *   (d) the Rust agent `stream --synthetic --grant-issuer <that pubkey>` — SECURE mode: it starts
 *       with NO backstage dispatcher and denies backstage until a signed grant is installed;
 *   (e) the console in system Chrome (Vite dev server, which proxies `/cp` → the control plane).
 *
 * Then, as an operator: connect (reusing V1 manual-connect), open Backstage → System, assert it is
 * DENIED (no grant yet). Click "Get access" → the console mints a grant from the control plane
 * (`POST /grant/mint` via the `/cp` proxy) and installs it over the Control channel; the agent
 * verifies it against the pinned issuer and acks `GrantInstalled`, which retries the tab. Assert
 * System now renders REAL data (hostname + OS) and an audit hash.
 *
 * Self-skips (green, with a reason) when a prerequisite binary/browser is absent. Run:
 * `npm run test:e2e`.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
import { SIGNALING_WS, SIG_PORT, CP_PORT, CP_BASE } from "./ports";
import { selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";
const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite `/cp` proxy target (CONTROL_PLANE_ORIGIN)
const APP_URL = "http://127.0.0.1:5173/";

// A FIXED 32-byte Ed25519 seed (64 hex) so the issuer public key is stable across restarts — the
// agent is launched pinned to the key this seed produces.
const DEV_GRANT_ISSUER_SEED = "0011223344556677889900112233445566778899001122334455667788990011";

const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let cpProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;
let issuerPubkey = "";

function tcpUp(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then((r) => r.ok)
    .catch(() => false);
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

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 300): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

test.beforeAll(async () => {
  if (!existsSync(AGENT_BIN)) {
    skipReason = `agent binary not found at ${AGENT_BIN} (run: cargo build -p rmt-agent-windows --bin agent_host)`;
    return;
  }

  // --- (a) control plane (DEV mode, fixed issuer seed) on :8081 ---
  // globalSetup (e2e/global-setup.ts) builds this unconditionally before any worker starts. Assert,
  // never build — see global-setup.ts for the stale-binary defect that guard caused.
  if (!existsSync(CP_EXE)) {
    skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
    return;
  }
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    // CP_SIGNALING_URL so the brokered POST /sessions advertises OUR signaling port; without it the
    // control plane returns DefaultSignalingURL (:8080) and the browser (App.tsx uses
    // brokered.signaling.url over the manual input) would dial the wrong port.
    env: { ...process.env, CP_LISTEN, CP_SIGNALING_URL: SIGNALING_WS, CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED, DATABASE_URL: "", CP_INSECURE_DEV: "1" },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:err] ${d.toString()}`));
  cpProc.on("exit", (code) => process.stdout.write(`[cp] exited code=${code}\n`));

  if (!(await waitFor(() => tcpUp(`${CP_BASE}/healthz`, 500), 10_000))) {
    skipReason = `control-plane did not come up on :${CP_PORT}`;
    return;
  }
  // Verify the Vite /cp proxy reaches the CP before committing test time. A stale Vite with the
  // wrong CONTROL_PLANE_ORIGIN causes __rmt.connected to never fire (broker 500s) and the test to
  // time out at the waitForFunction — not with a clear proxy error.
  // FAIL (not skip) on mismatch: a wrong CONTROL_PLANE_ORIGIN is a known harness misconfiguration.
  if (!(await tcpUp(`http://127.0.0.1:5173/cp/healthz`, 3_000))) {
    throw new Error(
      `Vite /cp proxy did not return 200 OK for /cp/healthz — CONTROL_PLANE_ORIGIN is misconfigured or Vite is stale. ` +
      `Expected proxy target: http://127.0.0.1:${CP_PORT}. ` +
      `Set CONTROL_PLANE_ORIGIN=http://127.0.0.1:${CP_PORT} before starting Vite.`
    );
  }

  // --- (b) read the issuer public key the agent must pin ---
  try {
    const res = await fetch(`${CP_BASE}/grant/pubkey`);
    const body = (await res.json()) as { grant_issuer_pubkey?: string };
    issuerPubkey = body.grant_issuer_pubkey ?? "";
  } catch (e) {
    skipReason = `could not read /grant/pubkey: ${String(e)}`;
    return;
  }
  if (!/^[0-9a-f]{64}$/.test(issuerPubkey)) {
    skipReason = `unexpected grant_issuer_pubkey: ${issuerPubkey}`;
    return;
  }
  process.stdout.write(`[e2e] issuer pubkey = ${issuerPubkey}\n`);

  // B8 requires a VERIFIED session and technician: never reuse an ambient dev broker.
  if (await wsReachable(SIGNALING_WS, 800)) {
    throw new Error(`port ${SIG_PORT} is occupied; this test needs its own enforcing broker`);
  }
  if (!existsSync(SIGNALING_EXE)) throw new Error("globalSetup did not build signaling");
  signalingProc = spawn(SIGNALING_EXE, ["-addr", `127.0.0.1:${SIG_PORT}`, "-insecure-no-agent-auth"], {
    cwd: SIGNALING_DIR, stdio: "ignore", windowsHide: true,
    env: { ...process.env, SIGNALING_TICKET_PUBKEY: issuerPubkey },
  });
  if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000))) {
    throw new Error("ticket-enforcing signaling did not start");
  }

  // --- (d) Rust agent in SECURE mode: pinned to the control plane's issuer key ---
  agentProc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30", "--grant-issuer", issuerPubkey],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let agentStarted = false;
  agentProc.stdout?.on("data", (d: Buffer) => {
    const s = d.toString();
    process.stdout.write(`[agent] ${s}`);
    if (s.includes("agent device=")) agentStarted = true;
  });
  agentProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[agent:err] ${d.toString()}`));
  agentProc.on("exit", (code) => process.stdout.write(`[agent] exited code=${code}\n`));

  await waitFor(async () => agentStarted, 8_000);
  await new Promise((r) => setTimeout(r, 1_000)); // settle so RegisterAgent lands

  // --- (e) browser (system Chrome preferred; VP8 decodes on bundled Chromium too) ---
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
  await stopProc(cpProc);
});

test("secure mode: backstage is DENIED until 'Get access' mints + installs a control-plane grant", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  // H2 / ADR-008: watch for the console FORWARDING the agent's audit chain to the control plane.
  // Registered before any navigation so no flush can be missed. This is the assertion that the
  // trail actually leaves the browser — until the forwarder was wired, the agent chained events,
  // the envelope delivered them, and the console dropped every one.
  const ingests: { status: number; body: string }[] = [];
  page.on("response", (res) => {
    if (!res.url().includes("/audit/ingest")) return;
    void res
      .text()
      .then((body) => ingests.push({ status: res.status(), body }))
      .catch(() => ingests.push({ status: res.status(), body: "" }));
  });

  await page.goto(APP_URL);

  // --- Manual-connect UI (reused from V1): signaling URL + DeviceId, then Connect. ---
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill(SIGNALING_WS);
  await page.getByTestId("manual-device").fill(deviceId);
  await page.getByTestId("manual-connect").click();

  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 30_000 },
  );

  // --- Backstage → System: SECURE agent has no grant yet, so this is DENIED. ---
  await selectSessionView(page, "Under the Hood");
  await page.getByRole("tab", { name: "System", exact: true }).click();

  // The denial surfaces the "Get access" affordance (a no-grant denial mentions the grant).
  const getAccess = page.getByTestId("backstage-grant-fetch");
  await expect(getAccess, "secure agent should DENY backstage until a grant is installed").toBeVisible({
    timeout: 15_000,
  });
  const deniedText = (await page.locator(".backstage__error").textContent())?.trim() ?? "";
  console.log(`[e2e] channel=${browserChannel} DENIED banner: "${deniedText}"`);
  expect(deniedText.toLowerCase()).toContain("grant");

  // Hostname must NOT be showing real data yet (the panel is denied).
  const sysValue = (label: string) =>
    page
      .locator(".sysinfo__row")
      .filter({ has: page.getByText(label, { exact: true }) })
      .locator(".sysinfo__value");
  expect(await sysValue("Hostname").count(), "no System data while denied").toBe(0);

  // --- Click "Get access": mint from the control plane (/cp/grant/mint) + install over Control. ---
  await getAccess.click();

  // On the agent's GrantInstalled ack the tab auto-retries; System now renders REAL data.
  const hostnameValue = sysValue("Hostname");
  await expect(hostnameValue, "System should render after the grant is installed").toBeVisible({
    timeout: 20_000,
  });
  await waitFor(async () => {
    const t = (await hostnameValue.textContent())?.trim() ?? "";
    return t !== "" && t !== "—";
  }, 15_000, 400);

  const hostname = (await hostnameValue.textContent())?.trim() ?? "";
  const os = (await sysValue("OS").textContent())?.trim() ?? "";
  console.log(`[e2e] GRANTED → System hostname="${hostname}" os="${os}"`);
  expect(hostname, "hostname should be real data after the grant").not.toBe("");
  expect(hostname).not.toBe("—");

  // The grant affordance is gone (grant installed), and a tamper-evident audit hash appears.
  await expect(page.getByTestId("backstage-grant-fetch")).toHaveCount(0);
  const auditHash = page.getByTestId("backstage-audit-hash");
  await expect(auditHash).toBeVisible({ timeout: 10_000 });
  const auditText = (await auditHash.textContent())?.trim() ?? "";
  console.log(`[e2e] audit hash="${auditText}"`);
  expect(auditText.length, "audit hash should be non-empty").toBeGreaterThan(0);

  // --- H2 / ADR-008: the chain must REACH the control plane, not merely exist agent-side. ---
  //
  // A 200 here is a strong claim, not a delivery receipt: handleIngestAudit re-derives every
  // event's hash in Go and verifies its linkage against the stored tail, so accepting the batch
  // means the Rust-produced chain verified byte-for-byte on the server. The wait covers the
  // forwarder's flush interval.
  const forwarded = await waitFor(async () => ingests.length > 0, 25_000, 500);
  expect(
    forwarded,
    "the console never POSTed /audit/ingest — the agent's audit chain is not reaching the control plane",
  ).toBe(true);

  const rejected = ingests.filter((i) => i.status !== 200);
  expect(rejected, `control plane refused a forwarded audit batch: ${JSON.stringify(rejected)}`).toEqual([]);

  const first = JSON.parse(ingests[0].body) as { accepted: number; tail_seq: number; tail_hash: string };
  console.log(
    `[e2e] AUDIT FORWARDED: ${ingests.length} batch(es), first accepted=${first.accepted} ` +
      `tail_seq=${first.tail_seq} tail_hash=${first.tail_hash}`,
  );
  expect(first.accepted, "an accepted batch must contain at least one event").toBeGreaterThan(0);
  expect(first.tail_hash, "the stored tail must be a real chain hash").toMatch(/^[0-9a-f]{16,}$/);

  // --- docs/01 §5: the stored chain must be READABLE BACK OUT, not merely accepted. ---
  //
  // Until GET /audit/backstage/export existed, `POST /audit/ingest` was the only route that
  // touched the backstage trail: what a technician did on a customer's machine went in and could
  // only come out through a psql prompt. A 200 on ingest proves the control plane VERIFIED the
  // chain; only this proves it can hand it back to an auditor.
  //
  // SCOPE, stated precisely: this spec runs the control plane in DEV mode (no DATABASE_URL), so
  // the store here is InMemoryAuditStore — the run covers agent → WebRTC → console → ingest →
  // export, NOT Postgres persistence. The pg half (the ingest_seq column, its ordering, RLS, and
  // the append-only privileges) is pinned by TestPgBackstageAuditExportUnderRLS against a real
  // database. Neither test alone covers the feature.
  const exportRes = await fetch(`${CP_BASE}/audit/backstage/export`);
  expect(exportRes.status, "the backstage audit export must be reachable").toBe(200);
  expect(exportRes.headers.get("content-type")).toBe("application/x-ndjson");

  // The resume cursor rides in a header, not in the event bodies, so the NDJSON lines stay
  // byte-identical to what the agent hashed. A collector with no cursor cannot tail the trail.
  const cursor = exportRes.headers.get("x-rmt-next-after-ingest-seq");
  expect(cursor, "the export must return a resume cursor").toMatch(/^-?\d+$/);

  const exported = (await exportRes.text())
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as { seq: number; session_id: string; prev_hash: string; hash: string });
  expect(exported.length, "the export returned no events although a batch was accepted").toBeGreaterThan(0);

  // The exact tail the ingest reported must be among the exported events — i.e. what came back
  // out is the same chain that went in, not merely some rows.
  const tail = exported.find((e) => e.hash === first.tail_hash);
  expect(
    tail,
    `the ingested tail ${first.tail_hash} is absent from the export (${exported.length} event(s) returned)`,
  ).toBeTruthy();

  // Chain shape survives the round trip: seq 0 carries the genesis prev_hash, and within a
  // session each event's prev_hash is its predecessor's hash. A collector re-verifies exactly
  // this, so an export that broke it would be worse than no export at all.
  const chain = exported.filter((e) => e.session_id === tail!.session_id).sort((a, b) => a.seq - b.seq);
  expect(chain[0].seq, "an exported chain must start at seq 0").toBe(0);
  expect(chain[0].prev_hash, "seq 0 must carry the genesis prev_hash").toBe("");
  for (let i = 1; i < chain.length; i++) {
    expect(chain[i].seq, "exported seqs must be contiguous").toBe(chain[i - 1].seq + 1);
    expect(chain[i].prev_hash, "exported prev_hash must point at the predecessor").toBe(chain[i - 1].hash);
  }
  // Resuming from the cursor the server just handed back must return nothing — the collector is
  // caught up. (That it also returns everything NEW after a later append is pinned by
  // TestPgBackstageAuditExportUnderRLS against a real database; here we only prove the round trip
  // terminates rather than looping on the same page forever.)
  const resumed = await fetch(`${CP_BASE}/audit/backstage/export?after_ingest_seq=${cursor}`);
  expect(resumed.status).toBe(200);
  expect((await resumed.text()).trim(), "resuming from the returned cursor must be caught up").toBe("");

  console.log(
    `[e2e] AUDIT EXPORTED: ${exported.length} event(s) as NDJSON; session ${tail!.session_id} ` +
      `chain seq 0..${chain[chain.length - 1].seq} verified, tail_hash=${tail!.hash}, ` +
      `next cursor=${cursor} (resume returned 0 events)`,
  );
});
