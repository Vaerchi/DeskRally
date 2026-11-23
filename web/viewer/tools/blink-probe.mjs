/**
 * blink-probe — measure the "flashing" symptom against a LIVE deployment, from the receiver.
 *
 *   cd web/viewer && node tools/blink-probe.mjs
 *   SECONDS=30 MACHINE="Work" node tools/blink-probe.mjs
 *
 * THIS IS THE TOOL THAT DIAGNOSED THE BLINK (2026-09-04), after five theories had died guessing at
 * it. Two things about it are the reason it worked, and both are worth preserving:
 *
 *  1. IT SAMPLES THE PIXELS, not just the stats. Receiver stats were always clean — ~24 fps, no
 *     stalls, no resolution change — so "the frames arrive" was never the question. What oscillated
 *     was what got PAINTED, and no stats page shows that.
 *  2. IT SAMPLES AT 10 Hz, faster than the frame rate. The oscillation is 2-3 Hz and is therefore
 *     invisible to a 1 Hz sampler, which is every stats page and every earlier capture attempt.
 *
 * The verdict it produced: the two states were grossly different PICTURES (per-block mean difference
 * 140 of 255, chroma differing 4x) while the console's monitor selection never moved — i.e. the agent
 * was intermittently delivering a DIFFERENT MONITOR under the same id. The operator has two panels at
 * an identical 2560x1080, so frame size never changed and every size-based check was blind.
 *
 * Credentials are read from DESKRALLY_PROBE_LOGIN_FILE and are NEVER printed. It refuses to
 * report numbers from a session that produced no frame, because zeros from a dead session read
 * exactly like a healthy still picture.
 */
import { chromium } from "playwright";
import { readFileSync } from "node:fs";

const SECRETS = process.env.DESKRALLY_PROBE_LOGIN_FILE;
if (!SECRETS?.trim()) {
  throw new Error("Set DESKRALLY_PROBE_LOGIN_FILE to your probe login file.");
}
const SECONDS = Number(process.env.SECONDS ?? 20);
const MACHINE = process.env.MACHINE ?? "Work";

function creds() {
  const txt = readFileSync(SECRETS, "utf8");
  const find = (...names) => {
    for (const line of txt.split(/\r?\n/)) {
      const m = /^\s*([A-Za-z][A-Za-z ]*?)\s{2,}(\S.*?)\s*$/.exec(line);
      if (!m) continue;
      const k = m[1].trim().toLowerCase();
      if (names.some((n) => k === n)) return m[2].trim();
    }
    return "";
  };
  return { url: find("url"), tenant: find("tenant", "slug"), email: find("email", "user", "login"), password: find("password", "pass") };
}

const c = creds();
const browser = await chromium.launch({ headless: true });
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.goto(c.url, { waitUntil: "domcontentloaded" });

if (
  await page.getByTestId("cp-login").waitFor({ state: "visible", timeout: 20_000 }).then(() => true).catch(() => false)
) {
  await page.getByTestId("cp-login-tenant").fill(c.tenant);
  await page.getByTestId("cp-login-email").fill(c.email);
  await page.getByTestId("cp-login-password").fill(c.password);
  await page.getByTestId("cp-login-submit").click();
}

await page.waitForSelector(".access__machine", { timeout: 30_000 });
const names = await page.locator(".access__machine .access__name").allInnerTexts();
const idx = Math.max(0, names.findIndex((n) => n.toLowerCase().includes(MACHINE.toLowerCase())));
console.log(`connecting to ${JSON.stringify(names[idx])}`);
await page.locator(".access__machine").nth(idx).locator("button.access__connect").click();

const gotPicture = await page
  .waitForFunction(
    () => {
      const v = document.querySelector("video.viewer__video");
      return !!v && v.readyState >= 2 && v.videoWidth > 0;
    },
    { timeout: 75_000 },
  )
  .then(() => true)
  .catch(() => false);

if (!gotPicture) {
  // Say so plainly rather than reporting zeros as data. A dead session is itself a finding.
  const err = await page.getByTestId("app-error").textContent().catch(() => null);
  console.log(`NO PICTURE within 75s. console error = ${JSON.stringify(err)}`);
  console.log("Not reporting numbers from a session that never delivered a frame.");
  await browser.close();
  process.exit(3);
}

// Which monitor does the console believe it is showing? If this flips, the answer is immediate.
const monitorLabel = async () =>
  page
    .locator(".viewer__monitor select")
    .inputValue()
    .catch(() => "(no monitor selector)");
console.log(`monitor selection at start: ${await monitorLabel()}`);

const series = await page.evaluate(async (seconds) => {
  const v = document.querySelector("video.viewer__video");
  const cv = document.createElement("canvas");
  cv.width = 64;
  cv.height = 36;
  const cx = cv.getContext("2d", { willReadFrequently: true });
  const out = [];
  const t0 = performance.now();
  while (performance.now() - t0 < seconds * 1000) {
    cx.drawImage(v, 0, 0, cv.width, cv.height);
    const d = cx.getImageData(0, 0, cv.width, cv.height).data;
    let lum = 0;
    let chroma = 0;
    for (let i = 0; i < d.length; i += 4) {
      lum += (d[i] * 299 + d[i + 1] * 587 + d[i + 2] * 114) / 1000;
      chroma += (Math.abs(d[i] - d[i + 1]) + Math.abs(d[i + 1] - d[i + 2]) + Math.abs(d[i] - d[i + 2])) / 3;
    }
    const px = d.length / 4;
    const bw = cv.width / 4;
    const bh = cv.height / 4;
    const blocks = [];
    for (let by = 0; by < 4; by++) {
      for (let bx = 0; bx < 4; bx++) {
        let s = 0;
        let n = 0;
        for (let y = by * bh; y < (by + 1) * bh; y++) {
          for (let x = bx * bw; x < (bx + 1) * bw; x++) {
            const i = (y * cv.width + x) * 4;
            s += (d[i] * 299 + d[i + 1] * 587 + d[i + 2] * 114) / 1000;
            n++;
          }
        }
        blocks.push(Math.round(s / n));
      }
    }
    out.push({ t: Math.round(performance.now() - t0), lum: lum / px, chroma: chroma / px, blocks });
    await new Promise((r) => setTimeout(r, 100));
  }
  return out;
}, SECONDS);

console.log(`monitor selection at end:   ${await monitorLabel()}`);

// Cluster by block signature and report the two most common.
const key = (b) => b.map((x) => Math.round(x / 8)).join(",");
const counts = new Map();
for (const s of series) counts.set(key(s.blocks), (counts.get(key(s.blocks)) ?? 0) + 1);
const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 2);

const groupOf = (k) => series.filter((s) => key(s.blocks) === k);
const avg = (a, f) => a.reduce((x, y) => x + f(y), 0) / a.length;

console.log(`\nsamples=${series.length}  distinct coarse pictures=${counts.size}`);
for (const [k, n] of top) {
  const g = groupOf(k);
  console.log(
    `  state n=${String(n).padStart(3)}  lum=${avg(g, (s) => s.lum).toFixed(1)}  chroma=${avg(g, (s) => s.chroma).toFixed(2)}  blocks=[${g[0].blocks.join(" ")}]`,
  );
}

if (top.length === 2) {
  const A = groupOf(top[0][0])[0].blocks;
  const B = groupOf(top[1][0])[0].blocks;
  const diffs = A.map((a, i) => Math.abs(a - B[i]));
  const maxDiff = Math.max(...diffs);
  const meanDiff = diffs.reduce((a, b) => a + b, 0) / diffs.length;
  const cA = avg(groupOf(top[0][0]), (s) => s.chroma);
  const cB = avg(groupOf(top[1][0]), (s) => s.chroma);
  console.log(`\nper-block |A-B|: mean=${meanDiff.toFixed(1)} max=${maxDiff}  (0-255 scale)`);
  console.log(`chroma A=${cA.toFixed(2)}  B=${cB.toFixed(2)}`);
  if (maxDiff > 40 || meanDiff > 15) {
    console.log(">>> THE TWO STATES ARE DIFFERENT PICTURES. Consistent with alternating MONITORS,");
    console.log("    not with one monitor at two quality levels.");
  } else if (cB < 1.5 && cA > cB * 3) {
    console.log(">>> STATE B IS EFFECTIVELY GRAYSCALE — gray-mode toggling, i.e. the rate controller.");
  } else {
    console.log(">>> The two states are the SAME picture rendered slightly differently — a quality");
    console.log("    tier oscillation, not a monitor swap.");
  }
}

await browser.close();
