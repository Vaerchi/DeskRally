import { defineConfig, devices } from "@playwright/test";
export default defineConfig({testDir:"./e2e",testMatch:/monitor_canvas\.spec\.ts$/,workers:1,retries:0,
  timeout:30000,reporter:[["list"]],outputDir:"test-results/monitor-canvas",
  projects:[{name:"desktop",use:{viewport:{width:1280,height:900}}},
    {name:"mobile",use:{...devices["Pixel 7"]}}],
  webServer:{command:"npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url:"http://127.0.0.1:5173/e2e/monitor_canvas.html",reuseExistingServer:false,timeout:60000,
    env:{CONTROL_PLANE_ORIGIN:"http://127.0.0.1:8081"}}});
