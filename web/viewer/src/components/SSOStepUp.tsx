import { useEffect, useRef, useState, type ReactNode } from "react";
import { ConsoleApiError, type ConsoleApi } from "../lib/console_api";

export interface SSOStepUpProps {
  api: ConsoleApi;
  action: (live: () => boolean) => Promise<void>;
  onCancel: () => void;
  onDone: () => void;
  onForbidden?: () => void;
  children?: ReactNode;
}

/** Keep verification and the sensitive action in one operation; an abandoned prompt cannot send it. */
export function SSOStepUp({ api, action, onCancel, onDone, onForbidden, children }: SSOStepUpProps) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const flight = useRef(false);
  const generation = useRef(0);
  // While a code given in the last few minutes is still fresh, run the action without asking again
  // (production 2026-10-17: Save then Test asked for two codes, and reusing the first one failed as a
  // replay). The server re-checks freshness on the action itself; a 428 there falls back to the form.
  const [checking, setChecking] = useState(true);
  useEffect(() => {
    const mine = generation.current;
    const live = () => generation.current === mine;
    flight.current = true;
    void (async () => {
      let ranAction = false;
      try {
        if (!(await api.ssoStepUpFresh()) || !live()) return;
        ranAction = true;
        await action(live);
        if (live()) onDone();
      } catch (err) {
        if (!live()) return;
        // A 403 means access itself was refused, from the probe or the action: hide, never prompt.
        if (err instanceof ConsoleApiError && err.status === 403 && onForbidden) { onForbidden(); return; }
        // Any other probe failure just falls back to asking for a code.
        if (!ranAction) return;
        if (!(err instanceof ConsoleApiError && err.status === 428)) setError(actionFailure(err));
      } finally {
        if (live()) { flight.current = false; setChecking(false); }
      }
    })();
    return () => { generation.current++; };
    // Runs once per prompt: the parent keys a new SSOStepUp per operation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <form className="panel__form" aria-label="Verify it's you" data-testid="sso-stepup-form"
    onSubmit={e => {
      e.preventDefault();
      if (flight.current || !code.trim()) return;
      flight.current = true;
      const mine = generation.current;
      const live = () => generation.current === mine;
      const submittedCode = code.trim();
      setCode("");
      setBusy(true);
      setError(null);
      void (async () => {
        let verified = false;
        try {
          await api.stepUp(submittedCode);
          if (!live()) return;
          verified = true;
          await action(live);
          if (live()) onDone();
        } catch (err) {
          if (!live()) return;
          if (verified && err instanceof ConsoleApiError && err.status === 403 && onForbidden) {
            onForbidden();
            return;
          }
          setError(verified ? actionFailure(err) : codeFailure(err));
        } finally {
          if (live()) { flight.current = false; setBusy(false); }
        }
      })();
    }}>
    <span className="panel__toolbar-title">Verify it's you</span>
    {checking && <p className="panel__note" role="status">Checking your recent verification…</p>}
    {children}
    <label className="panel__toolbar-field">DeskRally authenticator code
      <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric"
        autoComplete="one-time-code" autoFocus required disabled={busy || checking} data-testid="sso-stepup-code" />
    </label>
    <button type="submit" className="panel__action" disabled={busy || checking || !code.trim()} data-testid="sso-stepup-submit">
      {busy ? "Working…" : "Verify and continue"}
    </button>
    <button type="button" className="panel__action" disabled={busy} onClick={onCancel}>Cancel</button>
    {error && <span className="panel__toolbar-error" role="alert">{error}</span>}
  </form>;
}

// Do not reflect provider responses or submitted credentials into the page. A 400/404/409/428 from a
// signed-in SSO route carries a fixed control-plane message (oidcAPIStatus), safe to show.
function actionFailure(err: unknown): string {
  if (err instanceof ConsoleApiError && [400, 404, 409, 428].includes(err.status)) return err.message;
  return "The Microsoft sign-in action failed. Try again.";
}

// The step-up endpoint answers every refused code the same way (wrong, replayed or missing), so say the
// two things a user can act on: codes are single-use, and a lockout is a wait, not a typo.
function codeFailure(err: unknown): string {
  if (err instanceof ConsoleApiError && err.kind === "conflict") return "Your session or second factor changed. Sign in again.";
  if (err instanceof ConsoleApiError && err.status === 429) {
    return "Too many code attempts. Wait a few minutes, then try again with a new code.";
  }
  return "That code was not accepted. Each code works only once, so if you just used it, wait for the next one in your authenticator app.";
}
