import { useRef, useState, type FormEvent } from "react";
import type { ConsoleApi } from "../lib/console_api";

export function safeSSOReturnPath(value: string): string {
  // Backslashes and escaped separators can be normalized into an external URL by browsers.
  if (!value.startsWith("/") || value.startsWith("//") || /[\\\r\n\u0000]/.test(value)) return "/console";
  try {
    const decoded = decodeURIComponent(value.split(/[?#]/, 1)[0]);
    if (decoded.startsWith("//") || /[\\\r\n\u0000]/.test(decoded)) return "/console";
    if (new URL(value, window.location.origin).origin !== window.location.origin) return "/console";
  } catch { return "/console"; }
  return value;
}

// Why the control plane still wants the DeskRally code after Microsoft sign-in (a fixed enum from
// oidcTOTPReason; anything else shows no explanation rather than reflecting the URL).
const TOTP_REASONS: Readonly<Record<string, string>> = {
  trust_off: "Your organization has not set DeskRally to accept Microsoft's MFA, so DeskRally asks for its own code.",
  no_amr: "Microsoft did not report how you signed in (no MFA information in the sign-in), so DeskRally asks for its own code.",
  no_mfa: "Microsoft reported that this sign-in did not use MFA, so DeskRally asks for its own code.",
};

/** The explanation for a `why` value, or null. Own keys only: `?why=__proto__` must not resolve. */
export function ssoTotpReason(why: string | null): string | null {
  return why !== null && Object.prototype.hasOwnProperty.call(TOTP_REASONS, why) ? TOTP_REASONS[why] : null;
}

export interface SsoTotpFormProps {
  api: Pick<ConsoleApi, "completeSSOTotp">;
  onSuccess: () => void;
}

export function SsoTotpForm({ api, onSuccess }: SsoTotpFormProps) {
  const [pendingId] = useState(() => new URLSearchParams(window.location.search).get("p") ?? "");
  const [why] = useState(() => ssoTotpReason(new URLSearchParams(window.location.search).get("why")));
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (inFlight.current || !pendingId || !code.trim()) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await api.completeSSOTotp(pendingId, code.trim());
      const path = safeSSOReturnPath(result.return_path);
      // Use the password-login gate transition before navigating; the destination reload also
      // probes the session, so neither route can open the console based only on a POST response.
      onSuccess();
      window.location.replace(path);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCode("");
      inFlight.current = false;
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="login__form" data-testid="sso-totp-form" onSubmit={e => void submit(e)}>
        <h2 className="login__title">Complete Microsoft sign-in</h2>
        <p className="login__hint" data-testid="sso-totp-explain">Microsoft sign-in succeeded. Enter your
          <strong> DeskRally</strong> authenticator code (the one you use at the DeskRally login) to finish.</p>
        {why && <p className="login__hint" data-testid="sso-totp-why">{why}</p>}
        <label className="login__label">DeskRally authenticator code
          <input data-testid="sso-totp-code" inputMode="numeric" autoComplete="one-time-code"
            autoFocus value={code} disabled={busy} onChange={e => setCode(e.target.value)} />
        </label>
        {(!pendingId || error) && <p className="login__error" role="alert">
          {error ?? "This sign-in is missing its pending ID. Please start again."}
        </p>}
        <button data-testid="sso-totp-submit" type="submit" disabled={busy || !pendingId || !code.trim()}>
          {busy ? "Verifying…" : "Verify"}
        </button>
        <p className="login__hint">If verification fails, start Microsoft sign-in again.</p>
        <a href="/console">Return to sign-in</a>
      </form>
    </div>
  );
}
