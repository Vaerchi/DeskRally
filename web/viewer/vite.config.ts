import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { defaultOrigin } from "./src/lib/default_docs";

/**
 * docs/66 2i: a tenant-branded join page is shown only together with its attribution link to the default host's
 * /docs, built from `VITE_DEFAULT_ORIGIN` (an https origin, nothing else). Unset or `none` builds a viewer whose join
 * page is always neutral; a PRODUCTION build refuses a value that is set but invalid (a typo would otherwise silently
 * turn branding off). Enabling tenant branding (docs/66 2g) requires setting it. Dev server and tests are not checked.
 */
export function checkDefaultOriginForBuild(value: string | undefined): void {
  const v = (value ?? "").trim();
  // Unset is allowed (Codex r9: a routine build must not depend on a theming setting while theming is off); the page
  // is then neutral at runtime, exactly like `none`. Only a value that is SET and invalid is refused, since that is a typo.
  if (v === "" || v === "none") return;
  if (defaultOrigin(v) === null) {
    throw new Error(`VITE_DEFAULT_ORIGIN is invalid: ${JSON.stringify(v)}. It must be an https origin only (e.g. https://main.deskrally.com): a dotted DNS host and an optional port, no path, query, fragment or userinfo; or \"none\" for no tenant branding (docs/66 2i).`);
  }
}

// https://vite.dev/config/
// Control-plane origin the dev proxy forwards `/cp/*` to. Overridable so the same proxy can point
// at a remote control plane; defaults to the local dev control plane on :8081.
const CONTROL_PLANE_ORIGIN = process.env.CONTROL_PLANE_ORIGIN ?? "http://127.0.0.1:8081";

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  if (command === "build" && mode === "production") {
    checkDefaultOriginForBuild(loadEnv(mode, process.cwd(), "VITE_").VITE_DEFAULT_ORIGIN);
  }
  return {
  plugins: [react()],
  server: {
    port: 5173,
    // V4: proxy the control-plane HTTP API so the browser reaches it SAME-ORIGIN (no CORS). The
    // console's `ControlPlaneClient` defaults its base URL to this `/cp` prefix; `/cp/grant/mint`
    // → `http://127.0.0.1:8081/grant/mint`, etc. (`GET /grant/pubkey`, `POST /grant/mint`,
    // `POST /auth/login`). See `src/lib/controlplane.ts`.
    proxy: {
      "/cp": {
        target: CONTROL_PLANE_ORIGIN,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/cp/, ""),
      },
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
  };
});
