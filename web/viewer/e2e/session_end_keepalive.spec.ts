import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

test("session end keeps its CSRF header and reaches the server after navigation", async ({ page }) => {
  const received: { path?: string; csrf?: string; method?: string }[] = [];
  const server = createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:5173");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "X-CSRF-Token, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    if (req.method === "OPTIONS") { res.writeHead(204).end(); return; }
    received.push({ path: req.url, csrf: req.headers["x-csrf-token"] as string, method: req.method });
    // The old page leaves before the response, as happens during a real close request.
    setTimeout(() => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ session: { id: "fixture-session", ended_at: "2026-09-15T00:00:00Z" } }));
    }, 200);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const port = (server.address() as AddressInfo).port;
    await page.goto("http://127.0.0.1:5173/e2e/harness.html");
    await page.evaluate(async (baseUrl) => {
      const { ConsoleApiClient } = await import("/src/lib/console_api.ts");
      const api = new ConsoleApiClient({ baseUrl, cookies: () => "rmt_csrf=fixture-csrf" });
      window.addEventListener("pagehide", () => {
        void api.endSession("fixture-session").catch(() => {});
      }, { once: true });
    }, `http://127.0.0.1:${port}`);
    await page.goto("about:blank");
    await expect.poll(() => received).toEqual([
      { path: "/sessions/fixture-session/end", csrf: "fixture-csrf", method: "POST" },
    ]);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
