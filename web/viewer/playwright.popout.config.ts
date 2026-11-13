/**
 * Focused Playwright config for the popout-clipboard feature (pass 52).
 *
 * Intentionally OMITS globalSetup: no Go/Rust binaries are built or spawned.
 * Covers clipboard_popout.spec.ts (popup wiring) and clipboard_consent.spec.ts
 * (existing consent-gate scenarios that exercise the same ClipboardClient + ClipboardControl).
 *
 * retries is 0 — a clean pass on the first run is required; any flake must be investigated.
 *
 * Run with:
 *   npx playwright test --config=playwright.popout.config.ts
 */
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: /(clipboard_popout|clipboard_consent)\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  retries: 0,
  reporter: [["list"]],
  projects: [{ name: "desktop" }],
  webServer: {
    command: "npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5173/e2e/clipboard_popout.html",
    reuseExistingServer: process.env.CI !== "true",
    timeout: 60_000,
    env: {
      CONTROL_PLANE_ORIGIN: "http://127.0.0.1:8081",
    },
  },
});
