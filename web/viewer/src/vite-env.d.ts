/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL / path prefix for the control-plane HTTP API (V4). Defaults to the Vite dev proxy
   * prefix `/cp` (same-origin, no CORS). Set to an absolute origin (e.g. `http://127.0.0.1:8081`)
   * to hit a control plane directly when it serves permissive CORS.
   */
  readonly VITE_CONTROL_PLANE_URL?: string;

  /**
   * Public product name shown on the guest `/join` page (docs/28 section 4). The page is
   * unauthenticated and cannot read `GET /tenant/branding`, so the deployment's name is baked at
   * build time. Defaults to "DeskRally" when unset.
   */
  readonly VITE_PRODUCT_NAME?: string;
  readonly VITE_DEFAULT_ORIGIN?: string;

  /**
   * SAME-ORIGIN absolute path to the signed Windows support client (e.g.
   * `/download/DeskRallySupport.exe`). The `/join` download block renders ONLY when this is set AND
   * validated same-origin (see `lib/support_download.ts`). Stays UNSET until
   * `scripts/verify-download.ps1` has passed for the deployment (docs/27 step 18) -- so a default
   * build offers no download.
   */
  readonly VITE_SUPPORT_DOWNLOAD_URL?: string;

  /**
   * SHA-256 of the served support client, baked from the artifact `publish-support-client.ps1`
   * copied. Shown for read-back only when present; the page never displays a hash it cannot stand
   * behind.
   */
  readonly VITE_SUPPORT_DOWNLOAD_SHA256?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
