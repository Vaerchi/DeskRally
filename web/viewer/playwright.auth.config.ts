import { defineConfig } from "@playwright/test";

// UI-only tests: all control-plane responses are intercepted, no live service is contacted.
// The specs spawn the real signaling server, which fails CLOSED without a browser-origin policy; the lab opts out explicitly.
process.env.SIGNALING_ALLOWED_ORIGINS ??= "*";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "auth_expiry.spec.ts",
  workers: 1,
  retries: 0,
  use: { baseURL: "http://127.0.0.1:5187", channel: "chrome" },
  webServer: {
    command: "npm run dev -- --port 5187 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5187",
    reuseExistingServer: false,
  },
});
