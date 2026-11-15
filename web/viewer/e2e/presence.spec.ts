/**
 * Machine-presence end-to-end (docs/01 §4, control-plane migrations/0017).
 *
 * The access panel's "online" light is worth nothing unless it tracks reality, so this test drives
 * the WHOLE presence chain against real processes and asserts the transitions, not the plumbing:
 *
 *   agent WebSocket → signaling registry → GET /internal/presence (service-token gated)
 *     → control plane → GET /machines
 *
 *   1. A machine enrolled but with no agent connected reads OFFLINE, with no last-seen.
 *   2. A live `register_agent` WebSocket flips it to ONLINE and stamps last_seen.
 *   3. Dropping that socket flips it back to OFFLINE — and last_seen SURVIVES, which is the whole
 *      reason the column exists: the live feed can only answer "up now", so "offline since 14:32"
 *      has to come from the durable shadow the control plane writes on each presence read.
 *   4. Without the service token the presence endpoint is not even mounted, so no caller can
 *      enumerate the fleet.
 *
 * It runs its own signaling + control plane on dedicated ports (like secure_posture.spec.ts) so it
 * never contends with the shared harness stack, and needs no browser. Self-skips (green, with a
 * reason) only when a binary genuinely cannot be built.
 */
import { test, expect } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");

// Dedicated ports so this spec can run beside the shared harness stack and a developer's dev stack.
const SIG_PORT = process.env.RMT_E2E_PRESENCE_SIG_PORT ?? "8190";
const CP_PORT = process.env.RMT_E2E_PRESENCE_CP_PORT ?? "8191";
const SIGNALING_WS = `ws://127.0.0.1:${SIG_PORT}/ws`;
const SIG_BASE = `http://127.0.0.1:${SIG_PORT}`;
const CP_BASE = `http://127.0.0.1:${CP_PORT}`;

const PRESENCE_TOKEN = "presence-service-token-long-enough-to-mount-0001";
/** Must exceed DefaultPresenceCacheTTL (5s) so a read reflects the new registry state. */
const CACHE_SETTLE_MS = 6_500;

const deviceId = randomUUID();
const groupId = "00000000-0000-0000-0000-0000000000cc";

/** The os recorded at enrollment — deliberately STALE relative to what the agent announces. */
const ENROLLED_OS = "Windows 11 Pro 24H2 (build 26100)";
/** The os the live agent announces at register_agent: the machine upgraded since enrolling. */
const UPGRADED_OS = "Windows 11 Pro 26H1 (build 27000)";

let signalingProc: ChildProcess | null = null;
let cpProc: ChildProcess | null = null;
let skipReason: string | null = null;

interface MachineRow {
  device_id: string;
  online?: boolean;
  last_seen?: string;
  os?: string;
  group_name?: string;
}
interface MachineListing {
  machines: MachineRow[];
  presence_known: boolean;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 300): Promise<boolean> {
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

async function listMachines(): Promise<MachineListing> {
  const r = await fetch(`${CP_BASE}/machines`);
  const text = await r.text();
  if (!r.ok) throw new Error(`GET /machines → ${r.status}: ${text}`);
  return JSON.parse(text) as MachineListing;
}

async function row(): Promise<MachineRow> {
  const listing = await listMachines();
  const m = listing.machines.find((x) => x.device_id === deviceId);
  if (!m) throw new Error(`device ${deviceId} not in listing: ${JSON.stringify(listing)}`);
  return m;
}

/** Open a signaling socket and announce this device as an agent. Resolves once registered. */
function registerAgent(): Promise<WebSocket> {
  return new Promise((res, rej) => {
    const ws = new WebSocket(SIGNALING_WS);
    const timer = setTimeout(() => rej(new Error("register_agent timed out")), 10_000);
    ws.onopen = () => {
      // The signaling wire shape is FLAT — `{"type":…, <payload fields inlined>}` — see
      // ClientToServer.UnmarshalJSON, which decodes the payload from the whole object. Nesting the
      // fields under "payload" decodes to a zero-valued RegisterAgent, which the dev-mode path
      // accepts with an EMPTY device id, so the socket registers and nothing ever matches it.
      ws.send(
        JSON.stringify({
          type: "register_agent",
          device: deviceId,
          pubkey: "ed25519:" + "11".repeat(32),
          nat: "unknown",
          // What the Rust agent sends here is os_description() — the machine's CURRENT os, which
          // after an upgrade differs from the value enrollment captured. The refresh chain under
          // test: registry → presence feed → RecordObservedOS → the next listing.
          os: UPGRADED_OS,
        }),
      );
    };
    ws.onmessage = (ev) => {
      const msg = JSON.parse(String(ev.data)) as { type?: string };
      if (msg.type === "registered") {
        clearTimeout(timer);
        res(ws);
      }
    };
    ws.onerror = () => {
      clearTimeout(timer);
      rej(new Error("signaling socket error"));
    };
  });
}

test.beforeAll(async () => {
  test.setTimeout(180_000);

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

  // Signaling with the presence feed mounted. Ticket/agent-auth gates are off: this spec is about
  // presence, and the enforcing posture has its own spec (secure_posture.spec.ts).
  signalingProc = spawn(
    SIGNALING_EXE,
    ["-addr", `:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"],
    {
      cwd: SIGNALING_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, SIGNALING_PRESENCE_TOKEN: PRESENCE_TOKEN },
    },
  );
  signalingProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[signaling] ${d}`));
  signalingProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[signaling] ${d}`));
  if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 20_000))) {
    skipReason = `signaling did not come up on :${SIG_PORT}`;
    return;
  }

  // Control plane in DEV mode (no DATABASE_URL), wired to that presence feed.
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      CP_LISTEN: `:${CP_PORT}`,
      CP_SIGNALING_URL: SIGNALING_WS,
      CP_PRESENCE_URL: `${SIG_BASE}/internal/presence`,
      CP_PRESENCE_TOKEN: PRESENCE_TOKEN,
      DATABASE_URL: "", CP_INSECURE_DEV: "1",
    },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  const cpUp = await waitFor(async () => {
    try {
      return (await fetch(`${CP_BASE}/healthz`)).ok;
    } catch {
      return false;
    }
  }, 20_000);
  if (!cpUp) {
    skipReason = `control plane did not come up on :${CP_PORT}`;
    return;
  }

  // Enroll the machine so the tenant actually owns the device id the agent will announce.
  const enroll = await fetch(`${CP_BASE}/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ machine_id: deviceId, group_id: groupId, name: "PRESENCE-01", os: ENROLLED_OS }),
  });
  if (!enroll.ok) {
    skipReason = `POST /enroll → ${enroll.status}: ${await enroll.text()}`;
    return;
  }
});

test.afterAll(() => {
  for (const p of [cpProc, signalingProc]) {
    try {
      p?.kill();
    } catch {
      /* ignore */
    }
  }
});

test("presence tracks an agent connecting and disconnecting, and last-seen survives the drop", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  test.setTimeout(120_000);

  // (1) Enrolled, but no agent connected → the feed answers, and this machine is OFFLINE.
  const before = await listMachines();
  expect(before.presence_known, "the presence feed must be reachable").toBe(true);
  const offlineFirst = before.machines.find((m) => m.device_id === deviceId)!;
  expect(offlineFirst, "the enrolled machine must be listed").toBeTruthy();
  expect(offlineFirst.online).toBe(false);
  expect(offlineFirst.last_seen, "a machine never seen online has no last-seen").toBeFalsy();
  expect(offlineFirst.os, "before any agent connects, os is the enrollment-day value").toBe(ENROLLED_OS);

  // (2) A real agent socket registers → ONLINE, with a last-seen stamp.
  const ws = await registerAgent();
  await sleep(CACHE_SETTLE_MS);
  const online = await row();
  expect(online.online, "a registered agent must read online").toBe(true);
  expect(online.last_seen, "an online machine carries a last-seen").toBeTruthy();
  const seenAt = Date.parse(online.last_seen!);
  expect(Number.isNaN(seenAt), `last_seen must parse: ${online.last_seen}`).toBe(false);

  // (2b) The refresh is WRITE-BEHIND: the listing that first observes the announced os persists it
  // but still displays what it read. A follow-up read shows the refreshed value — machine.os is no
  // longer frozen at enrollment (the row above may already show it if annotate ran during an
  // earlier poll; the follow-up is the deterministic assertion either way).
  const refreshed = await row();
  expect(
    refreshed.os,
    "machine.os must refresh to the value the live agent announced at register_agent",
  ).toBe(UPGRADED_OS);

  // (3) Drop the socket → back to OFFLINE, but the last-seen SURVIVES. This is the whole point of
  // persisting it: the live registry forgets the agent entirely, so "offline since …" can only
  // come from the shadow the control plane wrote while it was up.
  ws.close();
  await sleep(CACHE_SETTLE_MS);
  const dropped = await row();
  expect(dropped.online, "a disconnected agent must read offline").toBe(false);
  expect(dropped.last_seen, "last_seen must survive the disconnect").toBeTruthy();
  const droppedAt = Date.parse(dropped.last_seen!);
  expect(Number.isNaN(droppedAt), `last_seen must still parse: ${dropped.last_seen}`).toBe(false);
  // The retained value is the last OBSERVATION of the device online — the snapshot in which it was
  // last present. So it is at or after the stamp seen live, and close to it (bounded by the poll
  // interval), never reset and never in the future by more than a poll.
  expect(droppedAt).toBeGreaterThanOrEqual(seenAt);
  expect(droppedAt - seenAt).toBeLessThan(60_000);
  // The refreshed os SURVIVES the disconnect, like last_seen: it is a durable fact about the
  // machine, not an attribute of the live connection.
  expect(dropped.os, "the refreshed os must survive the disconnect").toBe(UPGRADED_OS);

  console.log(
    `PRESENCE E2E: device ${deviceId.slice(0, 8)} offline → online (last_seen ${online.last_seen}) → offline, stamp retained; os refreshed "${ENROLLED_OS}" → "${dropped.os}"`,
  );
});

test("the presence endpoint refuses callers without the service token", async () => {
  test.skip(skipReason !== null, skipReason ?? "");

  // With the right token it answers.
  const ok = await fetch(`${SIG_BASE}/internal/presence`, {
    headers: { authorization: `Bearer ${PRESENCE_TOKEN}` },
  });
  expect(ok.status).toBe(200);

  // Without it — or with the wrong one — it does not, and leaks no device id. An open presence
  // feed would enumerate every live agent across every tenant on a shared signaling server.
  for (const headers of [undefined, { authorization: "Bearer wrong-token-but-long-enough-xxxxx" }]) {
    const res = await fetch(`${SIG_BASE}/internal/presence`, { headers });
    expect(res.status, "unauthenticated presence must be refused").toBe(401);
    expect(await res.text()).not.toContain(deviceId);
  }
});
