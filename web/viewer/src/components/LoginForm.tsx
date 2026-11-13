/**
 * Control-plane login form (Milestone V4, PROD mode only).
 *
 * Shown when a control-plane base URL is configured AND a `POST /grant/mint` comes back 401 — i.e.
 * a Postgres-backed control plane needs an authenticated session before it will mint a backstage
 * grant. On submit it calls `ControlPlaneClient.login(tenant, email, password, totp?)`, which sets
 * an httpOnly session cookie server-side; nothing is stored client-side here. After a successful
 * login the caller retries the mint.
 *
 * THE TENANT FIELD IS NOT OPTIONAL. Login is tenant-scoped — the server resolves the slug via
 * `cp_resolve_tenant_by_slug` before it looks at any credential. This form used to collect
 * "Username" and no tenant at all, and posted key names the server does not decode, so a
 * Postgres-backed console could not log in AT ALL. Nothing caught it because every e2e spawns the
 * control plane with `DATABASE_URL: ""` — the `StubAuthenticator` that treats every request as a
 * full-capability owner and never sees this form.
 *
 * The slug is PREFILLED from the hostname (see `tenantFromHostname`) because a deployment gives each
 * tenant its own subdomain, so it is already on screen. It stays editable on purpose: a wrong guess
 * must not lock anyone out, and login failures return a deliberately generic 401 that would make a
 * hidden mismatch nearly undebuggable.
 */

import { useCallback, useEffect, useState } from "react";
import { ConsoleApiClient, type ConsoleApi } from "../lib/console_api";

const loginSSOApi = new ConsoleApiClient();

import { tenantFromHostname } from "../lib/tenant_from_host";
import { desktopClientLacksSso, isDesktopClient } from "../lib/desktop_launch";

export interface LoginFormProps {
  /** Perform the login (typically `controlPlane.login`). Rejects with a message on failure. */
  onLogin: (tenant: string, email: string, password: string, totp?: string, rememberDevice?: boolean) => Promise<void>;
  /** Called after a successful login so the caller can retry the pending mint. */
  onSuccess?: () => void;
  /** Dismiss the form without logging in. */
  onCancel?: () => void;
  /** Hostname to derive the tenant from. Injected for tests; defaults to the live location. */
  hostname?: string;
  api?: Pick<ConsoleApi, "ssoInfo">;
}

export function LoginForm({ onLogin, onSuccess, onCancel, hostname, api = loginSSOApi }: LoginFormProps) {
  // Derived ONCE as the initial value, not on every render, so a keystroke in the field is never
  // overwritten by the derivation.
  const [tenant, setTenant] = useState(() =>
    tenantFromHostname(hostname ?? (typeof window === "undefined" ? "" : window.location.hostname)),
  );
  const [ssoTenant, setSsoTenant] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    const slug = tenant.trim();
    setSsoTenant(null);
    if (slug) {
      void api.ssoInfo(slug).then(info => {
        if (!cancelled && info.providers.some(p => p.id === "entra")) setSsoTenant(slug);
      }).catch(() => { /* Discovery is optional; password sign-in must remain available. */ });
    }
    return () => { cancelled = true; };
  }, [api, tenant]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  // Presentation hint only: the server still verifies credentials and owns expiry.
  // Native code adds this marker only after startup Windows Hello verification.
  const userAgent = typeof navigator === "undefined" ? "" : navigator.userAgent;
  const desktop = isDesktopClient(userAgent);
  const helloUnlocked = desktop && /(?:^|\s)DeskRallyHello\/1(?:\s|$)/.test(userAgent);
  const [rememberDevice, setRememberDevice] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setBusy(true);
      setError(null);
      try {
        if (helloUnlocked && rememberDevice) {
          await onLogin(tenant.trim(), email.trim(), password, totp.trim() || undefined, true);
        } else {
          await onLogin(tenant.trim(), email.trim(), password, totp.trim() || undefined);
        }
        onSuccess?.();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [onLogin, onSuccess, tenant, email, password, totp, helloUnlocked, rememberDevice],
  );

  return (
    <div className="login" data-testid="cp-login">
      <form className="login__form" onSubmit={submit}>
        <h2 className="login__title">Sign in to DeskRally</h2>
        <p className="login__hint">
          Sign in with your organisation account to access your machines and support sessions.
        </p>

        {error && (
          <div className="login__error" data-testid="cp-login-error" role="alert">
            {error}
          </div>
        )}

        <label className="login__label">
          Organisation
          <input
            data-testid="cp-login-tenant"
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            autoComplete="organization"
          />
        </label>
        <label className="login__label">
          Email
          <input
            data-testid="cp-login-email"
            autoFocus
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="login__label">
          Password
          <input
            data-testid="cp-login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        <label className="login__label">
          Verification code (if enabled)
          <input
            data-testid="cp-login-totp"
            inputMode="numeric"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            placeholder="123456"
            autoComplete="one-time-code"
          />
        </label>

        {helloUnlocked && <label className="login__label">
          <span><input type="checkbox" data-testid="cp-login-remember"
            checked={rememberDevice} disabled={busy}
            onChange={e => setRememberDevice(e.target.checked)} /> Remember this app for 30 days</span>
          <span className="login__hint">Expires after 7 days without use. Windows Hello verifies each app launch.
            Your DeskRally password is not saved. Sign out to end this sign-in.</span>
        </label>}
        {desktop && !helloUnlocked && <p className="login__hint" data-testid="cp-login-hello-hint">
          To remember this app, enable Windows Hello in the app’s Security menu,
          then close and reopen this window. Desktop 0.4.0 or newer is required.
        </p>}
        {/* Not in the desktop app: it cancels navigation to Microsoft's pages, so the button would
            bounce straight back to this form. */}
        {ssoTenant === tenant.trim() && !desktopClientLacksSso(userAgent) && (
          <button type="button" data-testid="sso-microsoft" disabled={busy}
            onClick={() => {
              const path = window.location.pathname + window.location.search + window.location.hash;
              // A document navigation lets the CP bind the attempt to its HttpOnly browser cookie. The
              // "Remember this app" box applies to Microsoft sign-in too (migrations/0080): the CP keeps the
              // choice on the attempt and honours it only for the Hello-unlocked desktop app.
              const remember = helloUnlocked && rememberDevice ? "&remember=1" : "";
              window.location.assign(`/cp/auth/oidc/start?return=${encodeURIComponent(path)}${remember}`);
            }}>
            Sign in with Microsoft
          </button>
        )}
        <div className="login__actions">
          {onCancel && (
            <button type="button" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
          )}
          <button
            type="submit"
            data-testid="cp-login-submit"
            disabled={busy || tenant.trim() === "" || email.trim() === "" || password === ""}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </div>
      </form>
    </div>
  );
}
