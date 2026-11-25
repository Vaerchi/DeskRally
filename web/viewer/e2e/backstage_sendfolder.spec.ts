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
const TRANSFER_DIR = resolve(tmpdir(), `rmt-e2e-sendfolder-transfers-${deviceId.slice(0, 8)}`);

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
    signalingProc = spawn(SIGNALING_EXE, ["-addr", `127.0.0.1:${SIG_PORT}`, "-insecure-no-ticket-verification", "-insecure-no-agent-auth"], { cwd: SIGNALING_DIR, stdio: "ignore" });
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

// docs/77 phase 2: Get folder against the REAL agent. Headless Chromium cannot drive the folder picker, so the page's
// showDirectoryPicker is replaced by an in-memory folder (window.__fakeRoot); everything else (listing the remote tree,
// staging each file, the verified download, creating local folders, writing files) is the real path.
const FAKE_PICKER = `
(() => {
  function dir(name) {
    const d = { kind: "directory", name, dirs: new Map(), files: new Map() };
    d.entries = async function* () {
      for (const [n, c] of d.dirs) yield [n, c];
      for (const n of d.files.keys()) yield [n, fileHandle(d, n)];
    };
    d.getDirectoryHandle = async (n, o) => {
      if (!d.dirs.has(n)) { if (!(o && o.create)) throw new DOMException("nf", "NotFoundError"); d.dirs.set(n, dir(n)); }
      return d.dirs.get(n);
    };
    d.getFileHandle = async (n, o) => {
      if (!d.files.has(n)) { if (!(o && o.create)) throw new DOMException("nf", "NotFoundError"); d.files.set(n, new Uint8Array()); }
      return fileHandle(d, n);
    };
    return d;
  }
  function fileHandle(d, n) {
    return {
      kind: "file", name: n,
      getFile: async () => new File([d.files.get(n)], n),
      createWritable: async () => {
        let buf = new Uint8Array();
        return {
          write: async (data) => { buf = new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : (data.buffer ? data : data)); },
          close: async () => { d.files.set(n, buf); },
          abort: async () => {},
        };
      },
    };
  }
  window.__fakeRoot = dir("Picked");
  window.showDirectoryPicker = async () => window.__fakeRoot;
  window.__fakeTree = () => {
    const out = {};
    const walk = (d, p) => {
      for (const [n, b] of d.files) out[p + n] = new TextDecoder().decode(b);
      for (const [n, c] of d.dirs) walk(c, p + n + "/");
    };
    walk(window.__fakeRoot, "");
    return out;
  };
})();
`;

test("Send folder: a local tree is created under the remote folder with its bytes", async () => {
  test.skip(skipReason !== null, skipReason ?? "");
  if (!browser) test.skip(true, "no browser");
  const { mkdirSync, rmSync, readFileSync, existsSync: exists } = await import("node:fs");
  const BS = String.fromCharCode(92);
  const workName = `rmt-e2e-sendfolder-${randomUUID().slice(0, 8)}`;
  const work = ["C:", workName, "dest"].join(BS);
  mkdirSync(work, { recursive: true });
  try {
    const page = await browser!.newPage();
    await page.addInitScript(FAKE_PICKER);
    page.on("console", (m) => process.stdout.write(`[page:${m.type()}] ${m.text()}\n`));
    await page.goto(APP_URL);
    // The local tree: Picked\proj\{a.txt, sub\b.txt}
    await page.evaluate(async () => {
      type W = { write(d: Uint8Array): Promise<void>; close(): Promise<void> };
      type D = { getDirectoryHandle(n: string, o?: { create?: boolean }): Promise<D>; getFileHandle(n: string, o?: { create?: boolean }): Promise<{ createWritable(): Promise<W> }> };
      const root = (window as unknown as { __fakeRoot: D }).__fakeRoot;
      const put = async (d: D, n: string, s: string) => {
        const w = await (await d.getFileHandle(n, { create: true })).createWritable();
        await w.write(new TextEncoder().encode(s));
        await w.close();
      };
      const proj = await root.getDirectoryHandle("proj", { create: true });
      await put(proj, "a.txt", "alpha");
      await put(await proj.getDirectoryHandle("sub", { create: true }), "b.txt", "bravo");
    });
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
    await page.getByTestId("local-choose").click();
    await expect(page.getByTestId("local-send-folder-proj")).toBeVisible({ timeout: 10_000 }).catch(() => undefined);
    // Remote: C:\<work>\dest (two levels down: no top-of-drive confirmation).
    await page.getByRole("button", { name: `C:${BS}` }).first().click();
    await page.locator(".panel__filelink", { hasText: workName }).click();
    await page.locator(".panel__filelink", { hasText: "dest" }).click();
    await page.getByTestId("local-send-folder-proj").click();
    await expect(page.locator(".backstage__placements")).toContainText("Sent 2 of 2 files", { timeout: 30_000 });
    expect(readFileSync([work, "proj", "a.txt"].join(BS), "utf8")).toBe("alpha");
    expect(readFileSync([work, "proj", "sub", "b.txt"].join(BS), "utf8")).toBe("bravo");
    expect(exists([work, "proj", "sub"].join(BS))).toBe(true);
    await page.close();
  } finally {
    rmSync(["C:", workName].join(BS), { recursive: true, force: true });
  }
});