import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',testMatch:/connection_diagnostics\.spec\.ts$/,workers:1,retries:0,timeout:30000,reporter:'list',webServer:{command:'npm run dev -- --port 5173 --strictPort --host 127.0.0.1',url:'http://127.0.0.1:5173',reuseExistingServer:!process.env.CI}});
