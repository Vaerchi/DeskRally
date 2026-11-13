import { defineConfig, devices } from "@playwright/test";
export default defineConfig({testDir:"./e2e",testMatch:/attended_shared\.spec\.ts$/,workers:1,retries:0,
 timeout:30000,reporter:[["list"]],outputDir:"test-results/attended-shared",
 projects:[{name:"desktop",use:{viewport:{width:1280,height:900}}},{name:"mobile",use:{...devices["Pixel 7"]}}],
 webServer:{command:"npm run dev -- --port 5178 --strictPort --host 127.0.0.1",url:"http://127.0.0.1:5178/e2e/attended_shared.html",reuseExistingServer:false,timeout:60000}});
