/**
 * docs/58 §12 — "Upload here" end to end against a REAL agent: the file is uploaded over the session's
 * file-transfer channel, then placed by its transfer id in the folder being browsed, and the disk is
 * checked. The test agent is not LocalSystem, so it is started with RMT_TEST_UPLOADS_ANCHORED=1, which
 * only a test-harness build honours, to treat its (temporary) transfer folder as the anchored one and
 * offer placement. Its own spec, so its own agent process (the dev agent serves one session).
 */
import { test, expect, chromium, type Browser } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url)); // web/viewer/e2e
const REPO = resolve(HERE, "..", "..", ".."); // repo root
const AGENT_BIN = resolve(REPO, "target", "debug", "agent_host.exe");
const SIGNALING_DIR = resolve(REPO, "server", "signaling");
const SIGNALING_EXE = resolve(SIGNALING_DIR, "signaling.exe");
import { SIGNALING_WS, SIG_PORT } from "./ports";
import { selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";
const APP_URL = "http://127.0.0.1:5173/";

const deviceId = randomUUID();
// The agent's transfer folder for this run (never the installed agent's C:\rmt-agent).
const TRANSFER_DIR = resolve(tmpdir(), `rmt-e2e-place-transfers-${deviceId.slice(0, 8)}`);

let signalingProc: ChildProcess | null = null;
let agentProc: ChildProcess | null = null;
let browser: Browser | null = null;
let browserChannel = "chromium(bundled)";
let skipReason: string | null = null;

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

  if (!(await wsReachable(SIGNALING_WS, 800))) {
    // globalSetup (e2e/global-setup.ts) builds this unconditionally before any worker starts. Assert,
    // never build: a build-if-absent guard here is what made the suite run a stale binary on every run
    // after the first.
    if (!existsSync(SIGNALING_EXE)) {
      skipReason = `${SIGNALING_EXE} is missing — globalSetup should have built it`;
      return;
    }
    // The signaling server refuses to start without SIGNALING_TICKET_PUBKEY (unverified brokering
    // would let any WS client reach any agent). This local harness has no control plane to take the
    // key from, so it opts out explicitly — the same flag a developer uses by hand.
    signalingProc = spawn(SIGNALING_EXE, ["-addr", `:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"], { cwd: SIGNALING_DIR, stdio: "ignore" });
    const up = await waitFor(() => wsReachable(SIGNALING_WS, 500), 10_000);
    if (!up) {
      skipReason = `signaling server did not come up on :${SIG_PORT}`;
      return;
    }
  }

  // Rust streaming agent: synthetic capture + dev-mode backstage (self-issued demo grant).
  agentProc = spawn(
    AGENT_BIN,
    ["stream", "--synthetic", "--signaling", SIGNALING_WS, "--device", deviceId, "--fps", "30", "--transfer-dir", TRANSFER_DIR],
    {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, RMT_TEST_UPLOADS_ANCHORED: "1" },
    },
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
});

// docs/58: Under the Hood file management against the REAL agent. The test works in a folder of its
// own at the top of C: (the temp folder can exceed the browse entry limit) and checks the disk after
// each change: New folder, Rename, then Delete through the type-the-machine-name dialog, which
// completes only because the confirmation token now travels over the session channel.
test("Upload here: a file is uploaded, placed in the browsed folder, and a collision offers Discard", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  const { mkdirSync, rmSync, writeFileSync, readFileSync, readdirSync } = await import("node:fs");
  const BS = String.fromCharCode(92);
  const at = (...parts: string[]) => parts.join(BS);
  const workName = `rmt-e2e-${randomUUID().slice(0, 8)}`;
  const work = at("C:", workName);
  mkdirSync(at(work, "inside"), { recursive: true });
  writeFileSync(at(work, "inside", "taken.txt"), "already here");
  try {
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
    await selectSessionView(page, "Under the Hood");
    await page.getByRole("tab", { name: "Files", exact: true }).click();
    await page.getByRole("button", { name: `C:${BS}` }).first().click();
    await page.locator(".panel__filelink", { hasText: workName }).click();
    await page.locator(".panel__filelink", { hasText: "inside" }).click();
    await expect(page.getByTestId("files-upload-here")).toBeVisible({ timeout: 15_000 });

    // 1. A new name: uploaded, then placed here.
    await page.getByTestId("files-upload-here-input").setInputFiles({
      name: "tool.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("placed bytes"),
    });
    await expect(page.getByTestId("files-placement-tool.txt")).toContainText("Placed in", { timeout: 30_000 });
    expect(readFileSync(at(work, "inside", "tool.txt"), "utf8")).toBe("placed bytes");
    expect(readdirSync(TRANSFER_DIR).filter((n) => n === "tool.txt")).toHaveLength(0);
    await expect(page.getByTestId("files-rename-tool.txt")).toBeVisible({ timeout: 15_000 });

    // 2. A name already in the folder: uploaded, NOT placed (never replaces), Discard removes it.
    await page.getByTestId("files-upload-here-input").setInputFiles({
      name: "taken.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("new bytes"),
    });
    await expect(page.getByTestId("files-placement-taken.txt")).toContainText("not placed", { timeout: 30_000 });
    expect(readFileSync(at(work, "inside", "taken.txt"), "utf8")).toBe("already here");
    expect(readdirSync(TRANSFER_DIR)).toContain("taken.txt");
    await page.getByTestId("files-placement-discard-taken.txt").click();
    await expect(page.getByTestId("files-placement-taken.txt")).toContainText("Discarded", { timeout: 15_000 });
    expect(readdirSync(TRANSFER_DIR)).not.toContain("taken.txt");

    // 3. Several files into a folder that needs confirmation (Codex phase B review): the prompts
    //    queue, one per file, and every placement reaches its own end. Each is DECLINED, so nothing
    //    is ever written into Program Files; both stay in the transfer folder and offer Discard.
    await page.getByRole("button", { name: `C:${BS}` }).first().click();
    await page.locator(".panel__filelink", { hasText: /Program Files$/ }).click();
    await expect(page.getByTestId("files-upload-here")).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("files-upload-here-input").setInputFiles([
      { name: "one.txt", mimeType: "text/plain", buffer: Buffer.from("one") },
      { name: "two.txt", mimeType: "text/plain", buffer: Buffer.from("two") },
    ]);
    const dialog = page.locator(".backstage__confirm");
    await expect(page.getByTestId("backstage-confirm-more")).toContainText("1 more", { timeout: 30_000 });
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("backstage-confirm-more")).toHaveCount(0);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    for (const name of ["one.txt", "two.txt"]) {
      await expect(page.getByTestId(`files-placement-${name}`)).toContainText("not placed", { timeout: 15_000 });
      await expect(page.getByTestId(`files-placement-discard-${name}`)).toBeVisible();
    }
    expect(readdirSync(TRANSFER_DIR)).toEqual(expect.arrayContaining(["one.txt", "two.txt"]));
    await page.close();
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(TRANSFER_DIR, { recursive: true, force: true });
  }
});
