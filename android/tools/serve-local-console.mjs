#!/usr/bin/env node
// Serves the BUILT console (web/viewer/dist) over HTTPS with a throwaway self-signed certificate,
// mimicking how deploy/Caddyfile serves it, so the Android app's Trusted Web Activity can be
// verified on an emulator WITHOUT touching production:
//
//   cd web/viewer && npm run build
//   node android/tools/serve-local-console.mjs            # assetlinks.json served as JSON
//   node android/tools/serve-local-console.mjs --spa-assetlinks
//       # NEGATIVE CONTROL: answers /.well-known/assetlinks.json with the SPA's index.html, which
//       # is exactly what production does until the file is deployed. Verification must FAIL.
//
// The emulator reaches this server through Chrome flags, not DNS (see android/README.md):
//   --host-resolver-rules="MAP main.deskrally.com 10.0.2.2:8443" --ignore-certificate-errors
//
// There is no control plane behind it: the login page renders but sign-in cannot succeed.
// Needs `openssl` on PATH (Git for Windows ships one). Node only; no dependencies.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:https";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "../../web/viewer/dist");
const port = Number(process.env.PORT ?? 8443);
const spaAssetlinks = process.argv.includes("--spa-assetlinks");
const certDir = process.env.CERT_DIR ?? resolve(here, "../build/local-cert");

if (!existsSync(join(dist, "index.html"))) {
  console.error(`No build at ${dist}. Run: cd web/viewer && npm run build`);
  process.exit(1);
}

mkdirSync(certDir, { recursive: true });
const key = join(certDir, "key.pem");
const crt = join(certDir, "cert.pem");
if (!existsSync(crt)) {
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
    "-keyout", key, "-out", crt, "-subj", "/CN=main.deskrally.com",
    "-addext", "subjectAltName=DNS:main.deskrally.com,DNS:console.test",
  ], { stdio: "ignore" });
}

const types = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css",
  ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg",
  ".webmanifest": "application/manifest+json", ".svg": "image/svg+xml",
};

createServer({ key: readFileSync(key), cert: readFileSync(crt) }, (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "https://x").pathname);
  console.log(new Date().toISOString(), req.method, path);
  const file = normalize(join(dist, path));
  const isAssetlinks = path === "/.well-known/assetlinks.json";
  const serveFile = (f, status = 200) => {
    res.writeHead(status, {
      "Content-Type": types[extname(f)] ?? "application/octet-stream",
      "Cache-Control": "no-cache",
    });
    res.end(readFileSync(f));
  };
  if (isAssetlinks && spaAssetlinks) return serveFile(join(dist, "index.html"));
  if (file.startsWith(dist + sep) && existsSync(file) && statSync(file).isFile()) return serveFile(file);
  // SPA catch-all, as in the Caddyfile's try_files.
  return serveFile(join(dist, "index.html"));
}).listen(port, "0.0.0.0", () => {
  console.log(`serving ${dist} on https://0.0.0.0:${port} (spa-assetlinks=${spaAssetlinks})`);
});
