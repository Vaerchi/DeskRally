import { RallyMark } from "./RallyIdentity";
/**
 * Self-service password-setup page (docs/01 §5): the destination of a credential-setup link an
 * administrator minted in the Users panel. The user opens `<origin>/set-password#<token>`, sets a
 * password, and can then sign in. Nothing here is authenticated — the token in the fragment IS the
 * authorization — so this page only ever calls the PUBLIC POST /auth/password/redeem, never a protected
 * console endpoint (same rule as JoinPage).
 *
 * The token rides the URL FRAGMENT so it stays out of server logs and the Referer header; this page
 * reads it client-side only (see setup_link.ts). Redemption sets the password but issues NO session —
 * the user logs in afterward through the one path that enforces TOTP.
 */

import { type FormEvent, useCallback, useMemo, useState } from "react";
import { type ConsoleApi, ConsoleApiClient } from "../lib/console_api";
import { newPasswordsReady, showPasswordMismatch } from "../lib/setup_link";

export interface SetPasswordPageProps {
  /** The raw setup token recovered from the URL fragment ("" when the link was opened bare). */
  token: string;
  /** Console API (defaults to a client at the `/cp` proxy); injectable for tests. */
  api?: ConsoleApi;
}

export function SetPasswordPage({ token, api }: SetPasswordPageProps) {
  const client = useMemo(() => api ?? new ConsoleApiClient(), [api]);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const mismatch = showPasswordMismatch(password, confirm);
  const ready = newPasswordsReady(password, confirm);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (busy || !newPasswordsReady(password, confirm)) return;
      setBusy(true);
      setError(null);
      try {
        await client.redeemPasswordReset(token, password);
        setDone(true);
        setPassword("");
        setConfirm("");
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [client, token, password, confirm, busy],
  );

  return (
    <div className="join">
      <header className="app__topbar">
        <span className="app__brand"><RallyMark />DeskRally</span>
      </header>
      <main className="join__main" data-testid="set-password-page">
        <h1>Set your password</h1>
        {!token ? (
          <p data-testid="set-password-no-token">
            This link carries no setup token. Ask your administrator for the full setup link.
          </p>
        ) : done ? (
          <>
            <p data-testid="set-password-success">
              Your password is set. You can now sign in.
            </p>
            <p>
              <a className="panel__action" href="/" data-testid="set-password-signin">
                Go to sign in
              </a>
            </p>
          </>
        ) : (
          <form className="panel__setup-form" onSubmit={handleSubmit}>
            <p>Choose a password for your account.</p>
            <input
              type="password"
              className="panel__input"
              placeholder="New password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              aria-label="New password"
              autoComplete="new-password"
              data-testid="set-password-input"
            />
            <input
              type="password"
              className="panel__input"
              placeholder="Confirm password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
              aria-label="Confirm password"
              autoComplete="new-password"
              data-testid="set-password-confirm"
            />
            {mismatch && (
              <p className="panel__note" role="alert" data-testid="set-password-mismatch">
                The passwords do not match.
              </p>
            )}
            {error && (
              <p className="panel__note" role="alert" data-testid="set-password-error">
                {error}
              </p>
            )}
            <button
              type="submit"
              className="panel__action"
              disabled={busy || !ready}
              data-testid="set-password-submit"
            >
              {busy ? "Setting…" : "Set password"}
            </button>
          </form>
        )}
      </main>
    </div>
  );
}
