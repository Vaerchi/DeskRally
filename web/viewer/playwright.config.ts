import { defineConfig, devices } from "@playwright/test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PINNED_STORAGE } from "./e2e/chrome_pinned";

/**
 * Playwright runner for the M3 browser↔agent e2e test. Kept entirely separate from the vitest
 * unit suite (which runs `src/**\/*.{test,spec}.ts`); this runner only picks up `e2e/**\/*.spec.ts`.
 *
 * The `webServer` block starts the real Vite dev server so the harness page can import the actual
 * `src/lib` transport. The spec itself orchestrates the Go signaling server, the Rust streaming
 * agent, and browser launch (system Chrome preferred; the video codec is VP8).
 */

// Every spec here spawns the real `agent_host`, which since the tracing subscriber landed writes
// its log to `C:\rmt-agent\helper.log` — the SAME file an agent actually installed on this machine
// uses. Without this redirect a test run would interleave into a production log and, at the 8 MB
// cap, rotate it away. Set on `process.env` (not per-spawn) so it reaches the agent however each
// spec spawns it: Playwright re-evaluates this config in every worker process, and the specs
// inherit the worker's environment.
process.env.RMT_LOG_FILE ??= join(tmpdir(), "rmt-e2e-agent.log");

export default defineConfig({
  // Build the Go server binaries the specs spawn, ONCE, before any worker starts. Read
  // e2e/global-setup.ts for why this is not a per-spec `if (!existsSync(exe))` build: that guard made
  // every run after the first reuse a stale control plane, silently, forever.
  globalSetup: "./e2e/global-setup.ts",
  testDir: "./e2e",
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  // The specs run serially and share CP_PORT/SIG_PORT (the Vite /cp proxy target is fixed), and the
  // live specs drive real WebRTC media over loopback whose timing varies under full-suite load. Both
  // produce a DIFFERENT intermittently-flaky spec per run (all pass in isolation) — see e2e/devcp.ts.
  // stopProc (awaiting process exit in afterAll) removes the port race at its root; these bounded
  // retries are the safety net for residual timing variance, so a single transient hiccup does not
  // fail the whole no-skip gate. A retry that RUNS the test still satisfies SKIP=FAILURE; a genuine
  // (deterministic) failure still fails all attempts. TRADE-OFF: a test that fails once then passes on
  // retry is counted a PASS by the gate — so retries can mask a genuinely INTERMITTENT bug. That is an
  // accepted risk here (the observed flakes are harness-only: the shared-port race + WebRTC-media
  // timing, not product races) BUT the list reporter prints "N flaky" whenever a retry was used, so a
  // spec that keeps flaking is VISIBLE in the gate log and must be investigated, not ignored.
  retries: 2,
  reporter: [["list"]],
  // Projects exist ONLY to give the mobile specs a touch-capable device profile. The existing specs
  // are deliberately unchanged: they each call `chromium.launch()` themselves, which bypasses a
  // project's `use` entirely, so putting them under a device profile would look like emulation and
  // be none. A `*.mobile.spec.ts` uses the `page` FIXTURE instead, which is what makes `hasTouch`
  // and the viewport actually apply.
  //
  // `testIgnore`/`testMatch` keep the suite the same SIZE as before rather than running every spec
  // once per project — the run is serial (workers: 1) and doubling it would double the gate.
  // The dev server below serves here. Specs that navigate relative to it (`page.goto('/console')`,
  // `test.info().project.use.baseURL!`) silently failed at their first `goto` without this: eight specs
  // never ran (found 2026-10-18 while adding the observer spec).
  // storageState pins the session toolbar (e2e/chrome_pinned.ts): the pre-existing specs drive the
  // always-visible bar; session_chrome.spec.ts covers the collapsed default separately.
  use: { baseURL: "http://127.0.0.1:5173", storageState: PINNED_STORAGE },
  projects: [
    {
      name: "desktop",
      testIgnore: /.*\.mobile\.spec\.ts$/,
    },
    {
      // An ordinary Android phone. Pixel 7 reports 412 CSS px, which is inside the console's
      // "stacked" band (lib/layout_breakpoints) and representative of the 360-430 range.
      name: "mobile-phone",
      testMatch: /.*\.mobile\.spec\.ts$/,
      use: { ...devices["Pixel 7"] },
    },
    {
      // An UNFOLDED large foldable. There is no Playwright descriptor for one and no emulator
      // profile is a real Galaxy Z Fold 7, so this is an explicit viewport rather than a claim about
      // a specific device.
      //
      // It used to be described as sitting "in the middle of the split-narrow band". Since
      // 2026-09-05 that is the opposite of true and deliberately so: the operator reported the menu
      // taking most of this screen, STACKED_MAX_WIDTH went to 767, and 700 now STACKS. Keeping the
      // viewport here is the point — it asserts the fix on the device that prompted it. Split-narrow
      // still gets touch coverage inside these specs, which resize to 800 explicitly.
      name: "mobile-foldable",
      testMatch: /.*\.mobile\.spec\.ts$/,
      use: {
        ...devices["Pixel 7"],
        viewport: { width: 700, height: 900 },
        hasTouch: true,
        isMobile: true,
      },
    },
  ],
  webServer: {
    command: "npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5173/e2e/harness.html",
    // Never reuse a server from a previous run: its CONTROL_PLANE_ORIGIN may target a dead port
    // from that run's disposable CP, and changing the shell variable does not update a live process.
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      // Forward the test-harness CP port into Vite so its /cp proxy targets the same disposable CP
      // the specs spawn. Without this, a stale CONTROL_PLANE_ORIGIN in the inherited environment
      // (or the default :8081 when RMT_E2E_CP_PORT is absent) stays in the server that proxy calls hit.
      CONTROL_PLANE_ORIGIN: `http://127.0.0.1:${process.env.RMT_E2E_CP_PORT ?? "8081"}`,
      // docs/66 2i: a tenant-branded join page renders only with the default host's origin (its attribution links to
      // <origin>/docs); without it the page is the neutral one. A fixed lab value, asserted by the join_brand specs.
      VITE_DEFAULT_ORIGIN: "https://default.example.test",
      // Propagate CARGO_TARGET_DIR so Vite's process.env is consistent with the specs, which read
      // this to locate agent/probe binaries in integration/target rather than source/target.
      ...(process.env.CARGO_TARGET_DIR ? { CARGO_TARGET_DIR: process.env.CARGO_TARGET_DIR } : {}),
    },
  },
});
