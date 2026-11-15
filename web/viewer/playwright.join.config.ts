import { defineConfig, devices } from "@playwright/test";

// Local, mocked browser acceptance for the guest /join page: no Go control plane, no agent, no globalSetup.
// Specs that need the real control plane (join_brand_host, tenant_public_join) are not here.
export default defineConfig({
  testDir: "./e2e",
  testMatch: ["join_flow*.spec.ts", "join_pass_mode.spec.ts", "join_brand.spec.ts", "join_brand.mobile.spec.ts", "support_flow.spec.ts"],
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:5173" },
  projects: [
    { name: "desktop", testIgnore: /.*\.mobile\.spec\.ts$/ },
    { name: "mobile-phone", testMatch: /join_brand\.mobile\.spec\.ts$/, use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: "npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5173/e2e/join_flow.html",
    reuseExistingServer: false,
    timeout: 60_000,
    env: { VITE_DEFAULT_ORIGIN: "https://default.example.test" },
  },
});
