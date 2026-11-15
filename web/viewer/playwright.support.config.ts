import { defineConfig } from "@playwright/test";

// Local, mocked browser acceptance for the guest entry and authenticated-session regressions.
// The specs spawn the real signaling server, which fails CLOSED without a browser-origin policy; the lab opts out explicitly.
process.env.SIGNALING_ALLOWED_ORIGINS ??= "*";

export default defineConfig({
  testDir: "./e2e",
  testMatch: [
    "auth_expiry.spec.ts",
    "supervisor_*.spec.ts",
    "fleet_end_session.spec.ts",
    "download_wiring.spec.ts",
    "download_delivery.spec.ts",
    "zoom_race.spec.ts",
  ],
  metadata: { supportDownloadExpected: true },
  workers: 1,
  retries: 0,
  timeout: 60_000,
  use: { baseURL: "http://127.0.0.1:5220", channel: "chrome" },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5220 --strictPort",
    url: "http://127.0.0.1:5220",
    reuseExistingServer: false,
    env: {
      VITE_SUPPORT_DOWNLOAD_URL: "/download/DeskRallySupport.exe",
      VITE_SUPPORT_DOWNLOAD_SHA256: "a".repeat(64),
    },
  },
});
