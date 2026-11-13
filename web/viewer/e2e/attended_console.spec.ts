/**
 * ATTENDED sessions driven through the REAL CONSOLE UI — the docs/12 §9 web-viewer scope.
 *
 * attended.spec.ts proves the protocol over raw API calls; THIS spec proves the operator-facing
 * flow: the technician uses the Attended panel to mint a code, the panel's consent watch keeps
 * Connect disabled until the REAL guest (`agent_host attend --auto-consent --synthetic`) redeems
 * and consents, then one click Connects — the consent-gated ticket feeds the SAME WebRTC
 * machinery as a machine-list connect, and real RTP video must reach the browser. Also proves the
 * /join guest landing page renders the fragment code + run command.
 *
 * Stack: control plane in DEV mode on ports.ts CP_PORT (the Vite `/cp` proxy target — the browser
 * can only reach the CP through the proxy, so this port is NOT free to choose), ENFORCING
 * signaling on SIG_PORT (ticket pubkey + device-identity endpoint, NEITHER insecure flag).
 *
 * Self-skips (loudly) only when a prerequisite is genuinely absent. A SKIP IS NOT A PASS.
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { SIGNALING_WS, SIG_PORT, CP_PORT, CP_BASE } from "./ports";
import { consoleTab } from "./nav";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(REPO, "target");
const AGENT_BIN = resolve(TARGET_DIR, "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");

const CP_LISTEN = `127.0.0.1:${CP_PORT}`; // MUST match the Vite `/cp` proxy target (CONTROL_PLANE_ORIGIN)
const APP_URL = "http://127.0.0.1:5173/";

const DEV_GRANT_ISSUER_SEED = "3333333333333333333333333333333333333333333333333333333333333333";
const DEVICE_IDENTITY_TOKEN = "e2e-attended-console-device-identity-0123456789abcdef";

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

function tcpUp(url: string, timeoutMs: number): Promise<boolean> {
  return fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    .then((r) => r.ok)
    .catch(() => false);
}

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

  // Control plane on the proxy target port: DEV mode (stub auth — no login/CSRF needed), fixed
  // issuer seed, device-identity token for the ENFORCING signaling, CP_SIGNALING_URL → ours.
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      CP_LISTEN,
      CP_SIGNALING_URL: SIGNALING_WS,
      CP_INSECURE_DEV_GRANT_SEED: DEV_GRANT_ISSUER_SEED,
      CP_DEVICE_IDENTITY_TOKEN: DEVICE_IDENTITY_TOKEN,
      DATABASE_URL: "", CP_INSECURE_DEV: "1",
    },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d}`));
  if (!(await waitFor(() => tcpUp(`${CP_BASE}/healthz`, 500), 15_000))) {
    skipReason = `control plane did not come up on :${CP_PORT}`;
    return;
  }
  // Verify the Vite /cp proxy forwards to the correct CP before committing 150 s of test time.
  // A stale Vite with the wrong CONTROL_PLANE_ORIGIN causes ECONNREFUSED on every browser request
  // and surfaces as "attended-start disabled" (machine groups fail to load) — not as a proxy error.
  // FAIL (not skip) on mismatch: a wrong CONTROL_PLANE_ORIGIN is a known harness misconfiguration,
  // not an absent optional binary. Silently skipping masked the Port 9 incident in Pass 1.
  if (!(await tcpUp(`http://127.0.0.1:5173/cp/healthz`, 3_000))) {
    throw new Error(
      `Vite /cp proxy did not return 200 OK for /cp/healthz — CONTROL_PLANE_ORIGIN is misconfigured or Vite is stale. ` +
      `Expected proxy target: http://127.0.0.1:${CP_PORT}. ` +
      `Set CONTROL_PLANE_ORIGIN=http://127.0.0.1:${CP_PORT} before starting Vite.`
    );
  }
  const pub = (await (await fetch(`${CP_BASE}/grant/pubkey`)).json()) as {
    grant_issuer_pubkey: string;
  };
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

test("console UI: start attended → code shown → Connect gated on consent → live video", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  test.setTimeout(150_000);

  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
  await page.goto(APP_URL);

  // 1. A fresh DEV server has no saved groups. Create a real group; the sole group is selected
  // by name in the panel, just as in an initialized tenant (never an invented zero UUID).
  const groupResponse = await fetch(`${CP_BASE}/machine-groups`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Support test computers" }),
  });
  expect(groupResponse.ok).toBe(true);
  // Open the Attended panel and start a session.
  await (await consoleTab(page, { name: "Support", exact: true })).click();
  await page.getByTestId("attended-reason").fill("Acme IT — printer support");
  await page.getByTestId("attended-start").click();

  // 2. The one-time code + join link render; Connect is disabled while consent is pending.
  const codeEl = page.getByTestId("attended-code");
  await expect(codeEl).toBeVisible({ timeout: 10_000 });
  const code = (await codeEl.getAttribute("data-code")) ?? "";
  expect(code, "the raw one-time code must be exposed for the guest").toMatch(/^[0-9A-Z]{8,}$/i);
  const joinUrl = (await page.getByTestId("attended-join-url").textContent())?.trim() ?? "";
  expect(joinUrl).toBe(`/join#${code}`);
  const connectBtn = page.getByTestId("attended-connect");
  await expect(connectBtn, "Connect must be disabled before consent").toBeDisabled();

  // 3. The REAL guest redeems the code and auto-consents (synthetic frames, headless-safe).
  guestProc = spawn(
    AGENT_BIN,
    ["attend", "--code", code, "--control-plane-url", CP_BASE, "--signaling", SIGNALING_WS,
      "--auto-consent", "--synthetic", "--fps", "30"],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  guestProc.stdout?.on("data", (d: Buffer) => { guestLog += d; process.stdout.write(`[guest] ${d}`); });
  guestProc.stderr?.on("data", (d: Buffer) => { guestLog += d; process.stderr.write(`[guest:err] ${d}`); });
  expect(await waitFor(async () => guestLog.includes("SESSION INDICATOR"), 20_000),
    "guest should consent and start its session").toBe(true);

  // 4. The panel's consent watch flips the state badge and enables Connect — no manual refresh.
  await expect(page.getByTestId("attended-state")).toHaveText(/consented|active/, {
    timeout: 15_000,
  });
  await expect(connectBtn).toBeEnabled();

  // 5. One click connects: the consent-gated ticket drives the standard WebRTC path.
  await connectBtn.click();
  await page.waitForFunction(
    () => (window as unknown as { __rmt?: { state: string } }).__rmt?.state === "connected",
    undefined,
    { timeout: 45_000 },
  );

  // 6. Real RTP video over the attended session (same assertion as the console spec).
  type Inbound = { bytesReceived?: number; packetsReceived?: number } | null;
  let inbound: Inbound = null;
  await waitFor(async () => {
    inbound = await page.evaluate(async () => {
      const r = (window as unknown as {
        __rmt: { stats(): Promise<RTCStatsReport | undefined> };
      }).__rmt;
      const all = await r.stats();
      if (!all) return null;
      let rtp: Record<string, unknown> | null = null;
      all.forEach((s) => {
        const rec = s as unknown as Record<string, unknown>;
        if (rec.type === "inbound-rtp" && rec.kind === "video") rtp = rec;
      });
      if (!rtp) return null;
      return {
        bytesReceived: (rtp as Record<string, unknown>).bytesReceived as number,
        packetsReceived: (rtp as Record<string, unknown>).packetsReceived as number,
      };
    });
    return !!inbound && (inbound.bytesReceived ?? 0) > 0 && (inbound.packetsReceived ?? 0) > 0;
  }, 20_000, 500);
  console.log(`[e2e] attended-console inbound-rtp video: ${JSON.stringify(inbound)}`);
  expect(inbound, "no inbound-rtp video over the console-driven attended session").not.toBeNull();
  expect(inbound!.bytesReceived ?? 0).toBeGreaterThan(0);
  expect(inbound!.packetsReceived ?? 0).toBeGreaterThan(0);

  await page.close();
});

test("the /join landing page renders the fragment code and the run command", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");

  const page = await browser!.newPage();
  await page.goto(`${APP_URL}join#TESTC0DE12345`);
  await expect(page.getByTestId("join-page")).toBeVisible({ timeout: 10_000 });
  // Grouped display of the raw fragment code…
  await expect(page.getByTestId("join-code")).toHaveText("TEST-C0DE-1234-5");

  // Three numbered steps (docs/27 step 17).
  await expect(page.locator(".join__stephead")).toHaveCount(3);

  // The default (unconfigured) build offers NO download block — VITE_SUPPORT_DOWNLOAD_URL is unset,
  // so the page must not hand a guest a download it cannot verify (docs/28 §4).
  await expect(page.getByTestId("join-download")).toHaveCount(0);

  // The copy-paste command is DEMOTED into a collapsed <details>, never deleted. It is present in
  // the DOM (so textContent reads it) but not visible until the guest expands "Advanced".
  await expect(page.getByTestId("join-advanced")).toBeVisible();
  await expect(page.getByTestId("join-command")).not.toBeVisible();
  const cmd = (await page.getByTestId("join-command").textContent()) ?? "";
  expect(cmd).toContain("agent_host attend --code TESTC0DE12345");
  expect(cmd).toContain("--control-plane-url http://127.0.0.1:5173/cp");
  // Expanding Advanced reveals it.
  await page.getByTestId("join-advanced").locator("summary").click();
  await expect(page.getByTestId("join-command")).toBeVisible();

  // A bare /join (no fragment) explains itself instead of showing an empty code, in a live region.
  await page.goto(`${APP_URL}join`);
  await expect(page.getByTestId("join-no-code")).toBeVisible();
  await page.close();
});

test("console UI: Promote button sends the promote request and the guest agent detects the token", async () => {
  // Closes the docs/01 §4 [~] P1 gap: "no e2e clicks Promote."
  // Asserts the full UI→CP→agent round-trip for the attended-to-unattended promotion flow:
  //   1. Technician clicks "Enable unattended access" → CP mints + stashes an enrollment token.
  //   2. Button reflects the post-promote state ("Installation requested", disabled).
  //   3. Guest agent polls /status, detects the token, and begins run_attend_promote.
  // Service install is not asserted: it requires admin elevation and is not feasible in the test
  // environment. The guest log captures "PROMOTE requested" immediately before enroll_once, which
  // is the observable boundary this test exercises.
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  test.setTimeout(120_000);

  let promoteGuestProc: ChildProcess | null = null;
  let promoteGuestLog = "";
  const page = await browser!.newPage();
  page.on("console", (m) => process.stdout.write(`[promote-page:${m.type()}] ${m.text()}\n`));

  try {
    // 1. Open the Attended tab and start a new session (fresh page → fresh panel state).
    // Ensure the CP has exactly one machine group for the panel's auto-select to work.
    // In a normal run, test 1 has already created one. On retry, beforeAll re-runs so the CP
    // is fresh with no groups — adding a second would break auto-select, so we only create one
    // when the list is empty.
    const grpListRes = await fetch(`${CP_BASE}/machine-groups`);
    const grpBody = (await grpListRes.json()) as { groups?: { id: string }[] };
    if ((grpBody.groups ?? []).length === 0) {
      const cr = await fetch(`${CP_BASE}/machine-groups`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Promote test group" }),
      });
      expect(cr.ok, "machine group creation for promote test failed").toBe(true);
    }
    await page.goto(APP_URL);
    await (await consoleTab(page, { name: "Support", exact: true })).click();
    // Wait for groups to load, then explicitly select the first one. Auto-select only fires when
    // exactly one group exists; when a prior test run left a group in the shared CP instance the
    // panel may have two groups and keeps groupId="" — the select gives us a stable way to pick
    // one regardless of how many groups are present, without relying on the auto-select heuristic.
    const groupSelect = page.getByTestId("attended-group");
    await expect(groupSelect).toBeEnabled({ timeout: 15_000 });
    await groupSelect.selectOption({ index: 1 });
    await page.getByTestId("attended-reason").fill("Promote test — attended-to-unattended conversion");
    await page.getByTestId("attended-start").click();

    // 2. Code renders; record it for the guest agent.
    const codeEl = page.getByTestId("attended-code");
    await expect(codeEl).toBeVisible({ timeout: 10_000 });
    const code = (await codeEl.getAttribute("data-code")) ?? "";
    expect(code, "attended code must be non-empty").toMatch(/^[0-9A-Z]{8,}$/i);

    // 3. Connect the real guest agent: redeem code, auto-consent, send synthetic frames.
    promoteGuestProc = spawn(
      AGENT_BIN,
      [
        "attend",
        "--code", code,
        "--control-plane-url", CP_BASE,
        "--signaling", SIGNALING_WS,
        "--auto-consent",
        "--synthetic",
        "--fps", "5",
      ],
      { cwd: REPO, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RUST_LOG: "info" } },
    );
    promoteGuestProc.stdout?.on("data", (d: Buffer) => {
      promoteGuestLog += d;
      process.stdout.write(`[promote-guest] ${d}`);
    });
    promoteGuestProc.stderr?.on("data", (d: Buffer) => {
      promoteGuestLog += d;
      process.stderr.write(`[promote-guest:err] ${d}`);
    });

    // 4. Guest consents: "SESSION INDICATOR" is logged when the on-screen window appears.
    expect(
      await waitFor(async () => promoteGuestLog.includes("SESSION INDICATOR"), 20_000),
      "guest must consent and show the session indicator before Promote is meaningful",
    ).toBe(true);

    // 5. Panel transitions to consented/active; Promote button is enabled.
    await expect(page.getByTestId("attended-state")).toHaveText(/consented|active/, {
      timeout: 15_000,
    });
    const promoteBtn = page.getByTestId("attended-promote");
    await expect(promoteBtn).toBeEnabled({ timeout: 5_000 });
    await expect(promoteBtn).toHaveText("Enable unattended access");

    // 6. Click Promote — sends POST /attended-sessions/{id}/promote to the CP.
    //    M1: removing this click leaves the button in its initial state; step 7 fails.
    await promoteBtn.click();

    // 7. Button reflects the post-promote state immediately: caption changes and button disables.
    //    M2: removing or no-op-ing the CP handler makes the request fail; the caption never changes.
    // Use a regex prefix match: the UI shows "Installation requested…" during the in-flight POST
    // and may settle to "Installation requested" once the response lands. Both are correct product
    // behaviour; asserting the settled text exactly would fail during the loading animation.
    await expect(promoteBtn).toHaveText(/^Installation requested/, { timeout: 10_000 });
    await expect(promoteBtn).toBeDisabled();

    // 8. Guest polls /status, picks up the enrollment token, and logs "PROMOTE requested" before
    //    calling enroll_once (host.rs::run_attend_promote). Service install will likely fail without
    //    admin elevation — this is documented and expected; it is not asserted here.
    //    M3: removing the promote token from the status-poll response means the guest never logs this.
    //    M4: removing run_attend_promote entirely also kills this assertion.
    expect(
      await waitFor(async () => promoteGuestLog.includes("PROMOTE requested"), 20_000),
      "guest agent must detect the promote token via status poll and begin the promote flow",
    ).toBe(true);
  } finally {
    // Use stopProc so the port and file handles are released before the next spec's beforeAll.
    await stopProc(promoteGuestProc);
    await page.close();
  }
});
