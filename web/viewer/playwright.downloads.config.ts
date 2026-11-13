import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e", testMatch: ["downloads_page.spec.ts", "supervisor_support_home.spec.ts", "auth_expiry.spec.ts"],
  workers: 1, retries: 0, timeout: 30000, reporter: "list",
  use: { baseURL: "http://127.0.0.1:5173" },
  webServer: { command: "npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5173", reuseExistingServer: false,
    env: { VITE_SUPPORT_DOWNLOAD_URL: "/download/DeskRallySupport.exe" } },
});
