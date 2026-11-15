/**
 * Installable-console assets: the web app manifest and the Digital Asset Links file the Android
 * technician app (a Trusted Web Activity, android/) needs to run the console with no URL bar.
 *
 * These are static files, so the failure modes are all silent: a manifest that is not linked is
 * ignored, an icon path that 404s drops the install prompt, and an assetlinks.json that the SPA
 * fallback answers with HTML makes Chrome quietly fall back to a Custom Tab (URL bar visible).
 * Each test reads the REAL shipped file rather than a copy of its expected shape.
 */

import { describe, expect, it } from "vitest";

import manifestRaw from "../public/manifest.webmanifest?raw";
import assetlinksRaw from "../public/.well-known/assetlinks.json?raw";
import indexHtml from "../index.html?raw";
import caddyfile from "../../../deploy/Caddyfile?raw";
import androidGradle from "../../../android/app/build.gradle.kts?raw";
import androidColors from "../../../android/app/src/main/res/values/colors.xml?raw";
import icon192 from "../public/icons/icon-192.png?inline";
import icon512 from "../public/icons/icon-512.png?inline";
import iconMaskable from "../public/icons/icon-maskable-512.png?inline";

const manifest = JSON.parse(manifestRaw);
const assetlinks = JSON.parse(assetlinksRaw);

// Vite inlines a PNG as a base64 data: URI; decode it and read the IHDR chunk.
const ICONS: Record<string, string> = {
  "/icons/icon-192.png": icon192,
  "/icons/icon-512.png": icon512,
  "/icons/icon-maskable-512.png": iconMaskable,
};

function pngSize(dataUri: string): { w: number; h: number } {
  const bin = atob(dataUri.slice(dataUri.indexOf(",") + 1));
  const u8 = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const dv = new DataView(u8.buffer);
  // PNG signature, then IHDR: width and height are big-endian u32 at offsets 16 and 20.
  expect(Array.from(u8.slice(0, 8))).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return { w: dv.getUint32(16), h: dv.getUint32(20) };
}

describe("web app manifest", () => {
  it("is linked from index.html at the path the file is served from", () => {
    expect(indexHtml).toMatch(/<link\s+rel="manifest"\s+href="\/manifest\.webmanifest"\s*\/?>/);
  });

  it("names the app and scopes it to the whole origin", () => {
    expect(manifest.name).toBe("DeskRally");
    expect(manifest.short_name).toBe("DeskRally");
    expect(manifest.start_url).toBe("/");
    expect(manifest.scope).toBe("/");
    expect(manifest.display).toBe("standalone");
  });

  it("uses the console's own background colour for theme and background", () => {
    // Mirrors `--bg` in src/index.css (vitest does not load CSS, so it cannot be read from there).
    // The Android app's colors.xml carries the same value; change all three together.
    const bg = "#0e1116";
    expect(manifest.theme_color.toLowerCase()).toBe(bg);
    expect(manifest.background_color.toLowerCase()).toBe(bg);
    expect(indexHtml.toLowerCase()).toContain(`name="theme-color" content="${bg}"`);
  });

  it("ships real 192 and 512 icons plus a maskable one, at the sizes it declares", () => {
    const purposes = new Set<string>();
    const sizes = new Set<string>();
    for (const icon of manifest.icons) {
      expect(icon.src.startsWith("/")).toBe(true);
      const uri = ICONS[icon.src];
      expect(uri, `no test import for ${icon.src}`).toBeTruthy();
      const { w, h } = pngSize(uri);
      expect(`${w}x${h}`).toBe(icon.sizes);
      purposes.add(icon.purpose);
      sizes.add(icon.sizes);
    }
    expect(sizes.has("192x192")).toBe(true);
    expect(sizes.has("512x512")).toBe(true);
    expect(purposes.has("maskable")).toBe(true);
  });
});

describe("Digital Asset Links", () => {
  const stmt = assetlinks[0];

  it("binds com.deskrally.technician to at least one SHA-256 fingerprint", () => {
    expect(assetlinks).toHaveLength(1);
    expect(stmt.relation).toEqual(["delegate_permission/common.handle_all_urls"]);
    expect(stmt.target.namespace).toBe("android_app");
    expect(stmt.target.package_name).toBe("com.deskrally.technician");
    expect(stmt.target.sha256_cert_fingerprints.length).toBeGreaterThan(0);
    for (const fp of stmt.target.sha256_cert_fingerprints) {
      // 32 colon-separated upper-case hex bytes, the exact shape `keytool -list` prints.
      expect(fp).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    }
  });

  it("is served by an exact-path Caddy handler ahead of the SPA catch-all, as JSON", () => {
    const block = /@assetlinks path \/\.well-known\/assetlinks\.json\s+handle @assetlinks \{([^}]*)\}/.exec(
      caddyfile,
    );
    expect(block).not.toBeNull();
    expect(block![1]).toContain('header Content-Type "application/json"');
    expect(block![1]).toContain("root * /srv/viewer");
    const at = caddyfile.indexOf("handle @assetlinks");
    const spa = caddyfile.indexOf("try_files {path} {path}/ /index.html");
    expect(at).toBeGreaterThan(-1);
    expect(spa).toBeGreaterThan(at);
  });

  it("does not widen the match to all of /.well-known/ (Caddy owns ACME challenges there)", () => {
    expect(caddyfile).not.toMatch(/@\w+ path \/\.well-known\/\*/);
  });
});

describe("Android technician app stays in step with the web assets", () => {
  it("assetlinks.json names the applicationId the Gradle project builds", () => {
    const id = /applicationId\s*=\s*"([^"]+)"/.exec(androidGradle)?.[1];
    expect(id).toBe(assetlinks[0].target.package_name);
  });

  it("uses the console background for the status and navigation bars", () => {
    const bg = /name="console_bg">(#[0-9A-Fa-f]{6})</.exec(androidColors)?.[1];
    expect(bg?.toLowerCase()).toBe(manifest.theme_color.toLowerCase());
  });
});
