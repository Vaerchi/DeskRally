// First-load bundle budget (outside review, 2026-11-23: the console is used on phones, and App.tsx statically
// imported every page). Runs after `vite build` (npm run build, so every release build): sums the JavaScript a
// browser must fetch before the console can render (the entry script plus its modulepreloads, as named by
// dist/index.html) and fails the build if it grows past the budget. Pages loaded on demand (React.lazy in
// App.tsx) are not counted. Raise the budget deliberately, in review, never to make a build pass.
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BUDGET_GZIP_KB = 215; // measured 200.8 kB on 2026-11-23 after lazy pages (was 280 kB)
const BUDGET_RAW_KB = 720; // measured 667.5 kB (was 935 kB)

const dist = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "..", "dist"));
const html = readFileSync(join(dist, "index.html"), "utf8");
const refs = new Set();
for (const m of html.matchAll(/<script[^>]*type="module"[^>]*src="([^"]+)"/g)) refs.add(m[1]);
for (const m of html.matchAll(/<link[^>]*rel="modulepreload"[^>]*href="([^"]+)"/g)) refs.add(m[1]);
if (refs.size === 0) {
  console.error(`bundle budget: no entry script found in ${join(dist, "index.html")}`);
  process.exit(1);
}
let raw = 0;
let gz = 0;
for (const ref of refs) {
  const bytes = readFileSync(join(dist, ref.replace(/^\//, "")));
  raw += bytes.length;
  gz += gzipSync(bytes, { level: 9 }).length;
  console.log(`bundle budget: ${ref} ${(bytes.length / 1024).toFixed(1)} kB`);
}
const rawKb = raw / 1024;
const gzKb = gz / 1024;
console.log(`bundle budget: first load ${rawKb.toFixed(1)} kB raw / ${gzKb.toFixed(1)} kB gzip ` +
  `(budget ${BUDGET_RAW_KB} / ${BUDGET_GZIP_KB} kB)`);
if (rawKb > BUDGET_RAW_KB || gzKb > BUDGET_GZIP_KB) {
  console.error("bundle budget: EXCEEDED. Load the new code on demand (React.lazy) instead of growing the first load.");
  process.exit(1);
}
