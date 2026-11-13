/**
 * Control-plane HTTP client (Milestone V4, secure-mode grant fetch).
 *
 * A small typed wrapper over the Go control-plane's HTTP API (`control-plane/http.go`,
 * `control-plane/grant.go`). The console uses it to obtain a control-plane-signed backstage
 * `SignedGrant` that it forwards to a **secure-mode** agent over the Control channel
 * (`ControlClient.installGrant`), plus a `login` for production (Postgres) auth.
 *
 * ## Endpoints
 *  - `GET  /grant/pubkey` → `{ "grant_issuer_pubkey": <hex> }` (the agent pins this key).
 *  - `POST /grant/mint`   body `{ machine_id, machine_group_id?, session_id? }`
 *                         → the `SignedGrant` JSON (exactly what the agent verifies).
 *  - `POST /auth/login`   body `{ tenant, email, password, totp_code? }` (prod mode; dev mode
 *    ignores auth). The key names are the Go `loginRequest` tags VERBATIM — they were once
 *    `{ username, password, totp }`, which no test caught because every e2e runs the DEV stub
 *    authenticator (`DATABASE_URL: ""`) and never posts this body at all. Both sides had unit tests
 *    against their own assumption and nothing tested the contract between them.
 *
 * ## Auth
 * In DEV mode (no `DATABASE_URL`) the control plane's `StubAuthenticator` treats every request as a
 * full-capability owner — no login needed, which is what the V4 e2e exercises. In PROD mode the
 * session cookie set by `/auth/login` is httpOnly + server-side, so we always send
 * `credentials: "include"` and store nothing here; a 401 from `mintGrant` means "log in first".
 *
 * ## CORS / base URL
 * The Vite dev server (origin `http://localhost:5173`) fetching the control plane (`:8081`) is
 * cross-origin. We avoid CORS entirely with a **Vite dev proxy**: `vite.config.ts` proxies `/cp/*`
 * → `http://127.0.0.1:8081/*`, so from the browser every request is same-origin. Hence the default
 * base URL is the proxy prefix `/cp` (overridable via `VITE_CONTROL_PLANE_URL`, e.g. to hit a
 * control plane directly when it serves permissive CORS).
 */

/** The default base URL: the Vite dev proxy prefix (`/cp` → control plane), overridable via env. */
import { CSRF_HEADER_NAME, csrfTokenFrom } from "./console_api";

export const DEFAULT_CONTROL_PLANE_URL =
  (import.meta.env?.VITE_CONTROL_PLANE_URL as string | undefined) ?? "/cp";

/** An HTTP error from the control plane, carrying the status so callers can branch (e.g. 401). */
export class ControlPlaneError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ControlPlaneError";
    this.status = status;
  }
}

/** Options for {@link ControlPlaneClient.mintGrant}. `machineGroupId`/`sessionId` are optional. */
export interface MintOptions {
  machineGroupId?: string;
  sessionId?: string;
}

/** The minimal `fetch` shape this client needs (so tests can inject a fake). */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ControlPlaneClientOptions {
  /** Base URL / path prefix for the control plane. Default {@link DEFAULT_CONTROL_PLANE_URL}. */
  baseUrl?: string;
  /** Injectable fetch (defaults to the global `fetch`); the unit tests pass a fake. */
  fetch?: FetchLike;
}

/**
 * Typed client for the control-plane grant + auth endpoints. All methods send
 * `credentials: "include"` so a prod session cookie flows; dev mode ignores auth entirely.
 */
export class ControlPlaneClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(opts: ControlPlaneClientOptions = {}) {
    // Strip a trailing slash so `${baseUrl}/grant/mint` never doubles up.
    this.baseUrl = (opts.baseUrl ?? DEFAULT_CONTROL_PLANE_URL).replace(/\/+$/, "");
    this.fetchImpl =
      opts.fetch ??
      ((input, init) => fetch(input, init));
  }

  /** The resolved base URL (for diagnostics/tests). */
  get base(): string {
    return this.baseUrl;
  }

  /**
   * `GET /grant/pubkey` → the issuer's Ed25519 public key (hex). This is the value provisioned into
   * the agent as its pinned `grant_issuer` (the console does not need it for the mint flow, but it
   * lets a UI display/verify which issuer a machine trusts).
   */
  async getIssuerPubkey(): Promise<string> {
    const res = await this.fetchImpl(`${this.baseUrl}/grant/pubkey`, {
      method: "GET",
      credentials: "include",
    });
    if (!res.ok) throw await this.toError(res, "fetch grant issuer pubkey");
    const body = (await res.json()) as { grant_issuer_pubkey?: unknown };
    if (typeof body.grant_issuer_pubkey !== "string") {
      throw new ControlPlaneError(res.status, "malformed /grant/pubkey response");
    }
    return body.grant_issuer_pubkey;
  }

  /**
   * `POST /grant/mint` for `machineId` → the `SignedGrant` **JSON string** to hand straight to
   * {@link ControlClient.installGrant}. Returned as text (not re-parsed) so the exact wire bytes the
   * control plane signed reach the agent unchanged. Throws {@link ControlPlaneError} (with `.status`)
   * on failure — notably 401 (log in first) and 403 (technician lacks backstage authorization).
   */
  /**
   * Headers for a MUTATING request: JSON plus the double-submit CSRF token.
   *
   * WITHOUT THIS, EVERY MUTATION 403s ON A REAL DEPLOYMENT. `csrfMiddleware` (control-plane/csrf.go)
   * rejects any non-GET request that carries a `cp_session` cookie and no matching `X-CSRF-Token`,
   * BEFORE authentication runs. So `mintGrant` — the whole backstage entry point — failed 403 for
   * every user of every Postgres-backed deployment, permanently, with retrying no help.
   *
   * No test caught it because `csrfMiddleware` short-circuits when there is no session cookie, and
   * every e2e runs `StubAuthenticator`, where no cookie ever exists. The sibling client
   * (`ConsoleApiClient`) has always done this correctly; this one was simply never updated when CSRF
   * landed, and its own doc still described CSRF as something the server "is gaining".
   *
   * The token is absent in DEV (no cookie, no middleware), and omitting the header there is correct.
   */
  private mutatingHeaders(): Record<string, string> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const token = csrfTokenFrom(typeof document === "undefined" ? "" : document.cookie);
    if (token) headers[CSRF_HEADER_NAME] = token;
    return headers;
  }

  /** `POST /auth/logout` — clears the server-side session and the cookie. */
  async logout(): Promise<void> {
    const res = await this.fetchImpl(`${this.baseUrl}/auth/logout`, {
      method: "POST",
      credentials: "include",
      headers: this.mutatingHeaders(),
    });
    if (!res.ok) throw await this.toError(res, "log out");
  }

  async mintGrant(machineId: string, opts: MintOptions = {}): Promise<string> {
    const body: Record<string, string> = { machine_id: machineId };
    if (opts.machineGroupId) body.machine_group_id = opts.machineGroupId;
    if (opts.sessionId) body.session_id = opts.sessionId;

    const res = await this.fetchImpl(`${this.baseUrl}/grant/mint`, {
      method: "POST",
      credentials: "include",
      headers: this.mutatingHeaders(),
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await this.toError(res, "get Under the Hood access");
    // The response body IS the SignedGrant JSON the agent deserializes + verifies. Return it as-is.
    return await res.text();
  }

  /**
   * `POST /auth/login` (prod mode). On success the control plane sets an httpOnly session cookie;
   * there is nothing to store client-side, so this resolves `void`. Dev mode has no `/auth/login`
   * route (stub auth) — this is only reached once a prod control plane is configured.
   */
  async login(tenant: string, email: string, password: string, totp?: string, rememberDevice = false): Promise<void> {
    // Field names must match control-plane/auth.go's `loginRequest` json tags exactly. A mismatch
    // does not error anywhere — Go's decoder simply leaves the unmatched fields zero, and the login
    // fails as "invalid credentials", which is indistinguishable from a wrong password.
    const body: Record<string, string | boolean> = { tenant, email, password };
    if (totp) body.totp_code = totp;
    if (rememberDevice) body.remember_device = true;
    const res = await this.fetchImpl(`${this.baseUrl}/auth/login`, {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await this.toError(res, "log in");
  }

  /** Build a {@link ControlPlaneError} from a non-2xx response, preferring the body's `error` field. */
  private async toError(res: Response, action: string): Promise<ControlPlaneError> {
    let detail = "";
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body.error === "string") detail = body.error;
    } catch {
      /* non-JSON body — fall back to the status text */
    }
    const suffix = detail || res.statusText || `HTTP ${res.status}`;
    return new ControlPlaneError(res.status, `could not ${action}: ${suffix}`);
  }
}
