/**
 * Loop 88 — the VIEWER's elevate-to-admin path, end to end through the real console UI.
 *
 * WHY THIS SPEC EXISTS, because it is the whole point of it.
 *
 * Loop 87 shipped elevate-to-admin (docs/01 §3) and every layer was tested except the last one: the
 * Rust verifier had 17 unit tests, the Go mint had a refusal ladder and golden vectors, and
 * `secure_posture.spec.ts` drove the entire authorization chain over a real transport — but through
 * `stream_probe`, NOT through the browser. `web/viewer/vite.config.ts` globs only
 * `src/**\/*.{test,spec}.ts`, so `.tsx` has no unit coverage at all, and no e2e touched the viewer's
 * elevation UI. Loop 87's own adversarial review then found the consequence: `setCanElevate(true)`
 * ran in `connect()` while the connection was still `"signaling"`, and the `[state]` effect cleared
 * it on the very next transition — so `onElevatedRun` was always `undefined`, the "Run as admin"
 * button never rendered, and **the feature was inert in production while every suite stayed green.**
 * That was the third time in the arc a feature was correct in every layer and dead at the last one.
 *
 * The fix (App.tsx — `setCanElevate` now lives at the bottom of the `[state]` effect's connected
 * branch, keyed on one condition) was argued from reading and proven by nothing. This spec is the
 * proof. Revert that line back into `connect()` and the `viewer-command-elevate` assertion below
 * fails.
 *
 * A PREMISE CORRECTION worth recording, because docs/07 §5 and the note in `console.spec.ts` both
 * got it wrong: this does NOT need a "console-driven connect rather than manual-connect". Those are
 * the same function — `AccessPanel`'s manual form and its per-machine row button both call
 * `handleConnect`, which always brokers unless handed a pre-acquired attended envelope. The one
 * thing loop 87's reverted test was missing is that `console.spec.ts` starts NO CONTROL PLANE, so
 * `acquireBrokeredSession` catches the proxy error, returns null, and the viewer correctly hides a
 * control that could only ever fail. Manual-connect + a real control plane is all it takes.
 *
 * WHAT THIS PROVES, and what it deliberately cannot:
 *
 *   PROVES — the button renders only for a session with a control-plane record; clicking it mints a
 *   real signed grant at `POST /sessions/{id}/elevation`; the control plane AUDITS that mint; the
 *   grant crosses a real WebRTC transport inside `ElevatedRun`; and the agent verifies it against
 *   the pinned issuer, matches the device AND session bindings, burns it single-use, and hands its
 *   command runner `RunIdentity::UserElevated`.
 *
 *   CANNOT PROVE — that any Win32 token was fetched. These agents run `--log-input`, so
 *   `CommandRunner` is mocked and `linked_elevated_token` / `CreateProcessAsUserW` / the Medium→High
 *   integrity flip are all downstream of `if !self.real`. That half is a VM fact, verified on
 *   LAB-VM (docs/07 loop 87 §3: the same account reporting `nt authority\system`, then
 *   `Medium Mandatory Level` with `BUILTIN\Administrators` *deny only*, then `High Mandatory Level`
 *   with it *"Enabled group, Group owner"*). Do not read a green run here as covering that.
 *
 * THREE FIXTURE FACTS THAT ARE LOAD-BEARING, each of which silently disables elevation if dropped —
 * the button still renders, the mint still succeeds, and only the refusal banner tells you:
 *
 *   1. Signaling must VERIFY TICKETS. `broker.go` reports no `control_plane_session` unless it has a
 *      ticket pubkey, the agent maps that absence to `SessionBinding::Unknown`, and
 *      `SignedElevationGrant::verify` then refuses EVERY grant (fail-closed, by design). Under
 *      `-insecure-no-ticket-verification` this feature cannot work at all.
 *   2. The agent must take the UNATTENDED posture (`--simulate-unattended-host`). Otherwise
 *      `can_elevate()` is false and `host.rs` refuses before the burn. The flag is itself gated on
 *      `--synthetic`/`--log-input`, so it can only ever change the authorization posture, never the
 *      token path.
 *   3. The agent must PIN the issuer (`--grant-issuer`). Without it `BackstageAuth` is not
 *      `SignedBy`, and the arm refuses with "no pinned issuer key".
 *
 * Which is why the spec asserts `viewer-command-elevation-error` has count 0 rather than just
 * asserting the button is visible: a fixture mistake must fail loudly instead of "proving" that a
 * button exists.
 *
 * Run: `npm run test:e2e`. One connect only — the session ticket is single-use and this signaling
 * server burns it, so a reconnect would fail for an unrelated reason.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync, mkdtempSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { SIGNALING_WS, SIG_PORT, CP_PORT, CP_BASE } from "./ports";
import { openManualConnect } from "./manual_connect";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const AGENT_BIN = resolve(REPO, "target", "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite `/cp` proxy target (CONTROL_PLANE_ORIGIN)
const APP_URL = "http://127.0.0.1:5173/";

// A FIXED 32-byte Ed25519 seed (64 hex) so the issuer public key is stable — the agent pins it and
// signaling verifies tickets against it. Same value the sibling secure specs use.
const DEV_GRANT_ISSUER_SEED = "0011223344556677889900112233445566778899001122334455667788990011";

// A REAL uuid, not a readable name: `elevationSigningBytes` parses technician/session/machine/
// elevation ids as hyphenated uuids, so a non-uuid device id 400s the mint with a message that
// looks nothing like the cause.
const deviceId = randomUUID();

let signalingProc: ChildProcess | null = null;
let cpProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let skipReason: string | null = null;
let issuerPubkey = "";

/**
 * Everything the agent wrote to stdout AND stderr.
 *
 * Stderr is the half that matters: `logging.rs` mirrors every `tracing` event to stderr, and every
 * observable this spec needs — `elevation grant verified`, `identity=UserElevated`, `rejected
 * ElevatedRun` — is a `tracing` event. Several sibling specs (secure_grant, console, transfer,
 * backstage, browser-agent) forward stderr to the terminal but never accumulate it, so their agent
 * logs are unassertable; `secure_posture.spec.ts` and `attended.spec.ts` DO accumulate both streams,
 * and this follows them. Asserting against the shared `RMT_LOG_FILE` instead would be worse than
 * useless: `playwright.config.ts` gives every agent in the whole run the same file, so another
 * spec's agent could satisfy the assertion.
 */
let agentLog = "";

function tcpUp(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then(() => true)
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
  // Assert, never build. `e2e/global-setup.ts` builds the Go binaries unconditionally before any
  // worker starts; a build-if-absent guard in a spec is what once made the suite silently test a
  // stale control plane on every run after the first.
  for (const [what, path] of [
    ["agent", AGENT_BIN],
    ["control plane", CP_EXE],
    ["signaling", SIGNALING_EXE],
  ] as const) {
    if (!existsSync(path)) {
      skipReason = `${what} binary missing at ${path} — globalSetup should have built it`;
      return;
    }
  }

  // --- (a) control plane, DEV mode, fixed issuer seed. -------------------------------------------
  // The SAME discipline the signaling spawn applies below, and for the same reason: this fixture's
  // control-plane configuration is load-bearing (CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED, CP_SIGNALING_URL, and DEV mode's
  // StubAuthenticator giving every cookieless request an Owner grant). Adopting an ambient control
  // plane on this port would silently substitute someone else's configuration for ours, and the
  // failure would surface as "the button did not render".
  if (await tcpUp(`${CP_BASE}/healthz`, 500)) {
    skipReason =
      `something is already answering on :${CP_PORT}; this spec needs its OWN DEV control plane ` +
      `(stop the dev stack — see docs/07 on stopping the vmlab stack before gating)`;
    return;
  }
  // DEV mode is what makes this spec possible at all: StubAuthenticator makes every cookieless
  // request an Owner (so the principal holds CapElevateSession), and the permissive machine store
  // fabricates an ACTIVE, non-ephemeral machine for any device uuid — so no enrollment is needed and
  // every gate in handleMintElevation passes for the technician who started the session.
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    // CP_SIGNALING_URL so the brokered POST /sessions advertises OUR signaling port — App.tsx
    // prefers `brokered.signaling.url` over the manual input, so without it the browser dials :8080.
    env: { ...process.env, CP_LISTEN, CP_SIGNALING_URL: SIGNALING_WS, CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED, DATABASE_URL: "", CP_INSECURE_DEV: "1" },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:err] ${d.toString()}`));
  cpProc.on("exit", (code) => process.stdout.write(`[cp] exited code=${code}\n`));

  if (!(await waitFor(() => tcpUp(`${CP_BASE}/healthz`, 500), 15_000))) {
    skipReason = `control-plane did not come up on :${CP_PORT}`;
    return;
  }

  // --- (b) the issuer key: signaling verifies tickets with it, the agent pins it. -----------------
  try {
    const body = (await (await fetch(`${CP_BASE}/grant/pubkey`)).json()) as { grant_issuer_pubkey?: string };
    issuerPubkey = body.grant_issuer_pubkey ?? "";
  } catch (e) {
    skipReason = `could not read /grant/pubkey: ${String(e)}`;
    return;
  }
  if (!/^[0-9a-f]{64}$/.test(issuerPubkey)) {
    // Asserted rather than assumed: with no issuer wired, POST /sessions returns no `signaling`
    // envelope, acquireBrokeredSession returns null, and the button is correctly ABSENT — the test
    // would then fail with "the button did not render", which points at the product instead of here.
    skipReason = `unexpected grant_issuer_pubkey: ${issuerPubkey}`;
    return;
  }

  // --- (c) signaling, ENFORCING TICKETS. ---------------------------------------------------------
  // Spawned unconditionally and NEVER reused: an ambient signaling server on this port is almost
  // certainly a developer's dev stack running `-insecure-no-ticket-verification`, under which this
  // whole feature fails closed and this spec would fail for a reason that has nothing to do with the
  // viewer. Specs run serially (`workers: 1`) and tear down with `stopProc`, so the port is ours.
  if (await wsReachable(SIGNALING_WS, 800)) {
    skipReason =
      `something is already listening on :${SIG_PORT}; this spec needs its OWN ticket-ENFORCING ` +
      `signaling server (stop the dev stack — see docs/07 §"the vmlab stack must be STOPPED")`;
    return;
  }
  // `-insecure-no-agent-auth` stays: it lets an unenrolled agent register with no tenant, and
  // signaling's tenant check short-circuits on an empty agent tenant. It gates a DIFFERENT half from
  // ticket verification, which is exactly why the two flags are not coupled.
  signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`, "-insecure-no-agent-auth"], {
    cwd: SIGNALING_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SIGNALING_TICKET_PUBKEY: issuerPubkey },
  });
  let sigLog = "";
  signalingProc.stdout?.on("data", (d: Buffer) => {
    sigLog += d;
    process.stdout.write(`[signaling] ${d}`);
  });
  signalingProc.stderr?.on("data", (d: Buffer) => {
    sigLog += d;
    process.stdout.write(`[signaling] ${d}`);
  });
  if (!(await waitFor(() => wsReachable(SIGNALING_WS, 500), 15_000))) {
    skipReason = `signaling did not come up on :${SIG_PORT}`;
    return;
  }
  // A guard against a future default change in signaling, NOT against an ambient server — the flag
  // is hardcoded absent two statements above and SIGNALING_TICKET_PUBKEY is already validated, so
  // this process cannot emit that warning today. Kept because the day it can, every elevation in
  // this spec would fail closed and the failure would point at the viewer.
  expect(sigLog, "signaling must be ENFORCING TICKETS or every elevation fails closed").not.toContain(
    "WARNING: -insecure-no-ticket-verification",
  );
  // The one that CAN fire: our child lost the bind race and something else is serving this port.
  if (signalingProc.exitCode !== null) {
    skipReason = `our signaling child exited (code ${signalingProc.exitCode}) — the port is not ours`;
    return;
  }

  // --- (d) the agent: UNATTENDED posture, issuer pinned, command runner MOCKED. ------------------
  agentProc = spawn(
    AGENT_BIN,
    [
      "stream",
      "--synthetic",
      "--log-input",
      // The whole reason the elevation path is reachable from a test at all: `stream` is BY NATURE
      // run by the interactive user, and elevation exists only on the unattended (SYSTEM helper)
      // host. Gated on --synthetic/--log-input, so the runner stays mocked.
      "--simulate-unattended-host",
      "--signaling",
      SIGNALING_WS,
      "--device",
      deviceId,
      "--fps",
      "30",
      "--grant-issuer",
      issuerPubkey,
    ],
    {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      // Its OWN log file: playwright.config.ts points every agent in the run at one shared path.
      env: { ...process.env, RMT_LOG_FILE: join(mkdtempSync(join(tmpdir(), "rmt-elev-")), "agent.log") },
    },
  );
  let agentStarted = false;
  const capture = (d: Buffer) => {
    const s = d.toString();
    agentLog += s;
    if (s.includes("agent device=")) agentStarted = true;
    process.stdout.write(`[agent] ${s}`);
  };
  agentProc.stdout?.on("data", capture);
  agentProc.stderr?.on("data", capture);
  agentProc.on("exit", (code) => process.stdout.write(`[agent] exited code=${code}\n`));

  if (!(await waitFor(async () => agentStarted, 15_000))) {
    skipReason = "agent did not report a device id";
    return;
  }
  await new Promise((r) => setTimeout(r, 1_000)); // settle so register_agent lands

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
  // Reverse order, each AWAITING exit. A bare `proc.kill()` returns immediately and leaves a dying
  // process holding the port — and this spec's signaling runs in a DIFFERENT mode from its
  // neighbours, so a leak here would make the next spec's ticketless connect fail mysteriously.
  await browser?.close().catch(() => {});
  await stopProc(agentProc);
  await stopProc(signalingProc);
  await stopProc(cpProc);
});

test("console: 'Run as admin' mints a signed grant and the agent runs the command elevated", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  // The viewer waits up to 35 s for an ElevatedRun verdict; the default 90 s spec timeout leaves too
  // little room around it, and "the agent refused" must not surface as a harness timeout.
  test.setTimeout(180_000);

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));

  await page.goto(APP_URL);
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill(SIGNALING_WS);
  await page.getByTestId("manual-device").fill(deviceId);
  await page.getByTestId("manual-connect").click();
  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 30_000 },
  );

  // The command toggle lives in the Tools menu since the compact toolbar (e311d06): open it first.
  await page.getByTestId("viewer-tools-menu").click();
  await page.getByTestId("viewer-command-toggle").click();
  await expect(page.getByTestId("viewer-command-panel")).toBeVisible();

  // === THE ASSERTION THIS SPEC EXISTS FOR ======================================================
  // `onElevatedRun` is `canElevate ? elevatedRun : undefined`, and the button is rendered only when
  // that prop is defined. Moving `setCanElevate` back into `connect()` — where loop 87 first put it,
  // at connection state "signaling", to be cleared by the very next transition — makes this element
  // never exist. Nothing else in the repo fails when that happens.
  const elevate = page.getByTestId("viewer-command-elevate");
  await expect(
    elevate,
    "the 'Run as admin' button did not render: canElevate never became true for a session that HAS a " +
      "control-plane record. This is the inert-feature shape — check the [state] effect in App.tsx.",
  ).toBeVisible({ timeout: 15_000 });

  // === A: an ORDINARY run first, so "elevated" means something ==================================
  // Without this leg an agent that elevated EVERY command would satisfy every assertion below
  // byte-identically. "As user" is left unchecked, so this is RunIdentity::Host.
  await page.getByTestId("viewer-command-input").fill("whoami");
  await page.getByTestId("viewer-command-run").click();
  await expect(page.getByTestId("viewer-command-output")).toContainText("mock", { timeout: 30_000 });
  expect(
    await waitFor(async () => agentLog.includes("identity=Host"), 15_000),
    "the baseline command did not reach the runner as Host",
  ).toBe(true);
  // The FULL string, not `identity=User`, which is a PREFIX of `identity=UserElevated` and so would
  // be satisfied by the very thing this rules out.
  expect(agentLog, "nothing may have run elevated before any grant existed").not.toContain(
    "identity=UserElevated",
  );

  // === B: the ELEVATED run =====================================================================
  const beforeLen = agentLog.length;
  await page.getByTestId("viewer-command-input").fill("whoami /groups");
  await elevate.click();

  // WAIT FOR A VERDICT BEFORE ASSERTING THERE WAS NO REFUSAL. Order matters here and the first draft
  // of this spec got it wrong: `toHaveCount(0)` is satisfied the instant it is FIRST evaluated, so
  // asserting it straight after the click passes vacuously — milliseconds in, neither a refusal nor
  // a result has arrived, and a fixture in which every elevation is refused would sail through it.
  // (Two review lenses caught that independently. The header sentence calling this the loud-failure
  // check was only true once the wait below came first.)
  //
  // The agent's own account is the verdict, sliced from the offset taken before the click so leg A's
  // output cannot satisfy leg B — which is also why there is no `toContainText("mock")` assertion on
  // the output element here: leg A's result is still displayed and would satisfy it unchanged.
  const elevatedRan = await waitFor(
    async () => agentLog.slice(beforeLen).includes("identity=UserElevated"),
    40_000,
  );

  // NOW the refusal guard means something: a verdict was reached, and this says it was not a
  // refusal. A mint failure or an agent refusal lands here and NOWHERE else, so this is what turns a
  // broken fixture into a loud failure instead of a green "the button exists".
  await expect(
    page.getByTestId("viewer-command-elevation-error"),
    "the elevated run was REFUSED — read the agent log above: 'did not report a control-plane " +
      "session id' means signaling is not verifying tickets; 'cannot elevate without a UAC prompt' " +
      "means --simulate-unattended-host is missing; 'no pinned issuer key' means --grant-issuer is.",
  ).toHaveCount(0);
  expect(
    elevatedRan,
    "the grant verified but the runner never received RunIdentity::UserElevated",
  ).toBe(true);
  const elevatedTail = agentLog.slice(beforeLen);
  // `token=\"linked_elevated\"` — tracing quotes a String-valued field. Matching the unquoted form
  // fails against a working agent, which is how this assertion was first written.
  expect(elevatedTail, "the agent did not report a VERIFIED grant").toContain(
    'token="linked_elevated"',
  );
  expect(elevatedTail, "the agent did not log the grant it burned").toContain("elevation_id=");
  expect(elevatedTail, "the agent rejected the ElevatedRun").not.toContain("rejected ElevatedRun");

  // === C: the control plane AUDITED the mint ===================================================
  // One audited event per elevated command is the entire justification for minting per command
  // rather than granting a session-wide "elevated mode" — so it is worth asserting, not assuming.
  const audit = (await (
    await fetch(`${CP_BASE}/audit?action=session.elevation_minted`)
  ).json()) as { events?: { action?: string; metadata?: Record<string, unknown> }[] };
  const minted = (audit.events ?? []).filter((e) => e.action === "session.elevation_minted");
  expect(minted.length, "the elevation was not recorded in the audit trail").toBe(1);
  expect(minted[0].metadata?.token, "the audit trail does not say WHICH token was authorized").toBe(
    "linked_elevated",
  );
  expect(String(minted[0].metadata?.device_id), "the audit event names a different machine").toBe(deviceId);
});
