import { useEffect, useRef, useState } from "react";
import { ConsoleApiError, type ConsoleApi, type SSOSettings, type SSOSettingsInput } from "../lib/console_api";
import { SSOStepUp } from "./SSOStepUp";
import { desktopClientLacksSso } from "../lib/desktop_launch";

export function TenantSSOSection({ api }: { api: ConsoleApi }) {
  const [settings, setSettings] = useState<SSOSettings | null>(null);
  const [draft, setDraft] = useState<SSOSettingsInput | null>(null);
  const [secret, setSecret] = useState("");
  const [hidden, setHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get("sso") === "test-ok"
      ? "Microsoft test sign-in succeeded." : null);
  const [operation, setOperation] = useState<{ kind: "save"; body: SSOSettingsInput } | { kind: "test" } | null>(null);
  const operationRef = useRef(false);
  // The desktop app only navigates within the tenant's own origin, so Microsoft's pages are cancelled
  // and the button would bounce back silently (production 2026-10-17). Say so instead.
  const desktopClient = desktopClientLacksSso(navigator.userAgent);
  const [load, setLoad] = useState(0);

  const accept = (s: SSOSettings) => {
    setSettings(s);
    // Project editable fields explicitly: no response field can seed the secret input.
    setDraft({ entra_tenant_id: s.entra_tenant_id, client_id: s.client_id,
      enabled: s.enabled, trust_entra_mfa: s.trust_entra_mfa });
  };
  useEffect(() => {
    let cancelled = false;
    setError(null);
    void api.getSSO().then(s => { if (!cancelled) accept(s); }, err => {
      if (cancelled) return;
      if (err instanceof ConsoleApiError && err.status === 403) setHidden(true);
      else setError("Could not load Microsoft sign-in settings.");
    });
    return () => { cancelled = true; };
  }, [api, load]);

  const finish = () => { operationRef.current = false; setOperation(null); };
  const deny = () => { setHidden(true); setSecret(""); finish(); };
  if (hidden) return null;

  return <section className="panel__form" aria-label="Single sign-on (Microsoft Entra ID)" data-testid="tenant-sso-section">
    <span className="panel__toolbar-title">Single sign-on (Microsoft Entra ID)</span>
    {notice && <p role="status" data-testid="sso-notice">{notice}</p>}
    {error && <p className="panel__toolbar-error" role="alert">{error}
      <button type="button" className="panel__action" onClick={() => setLoad(n => n + 1)}>Retry</button>
    </p>}
    {!settings && !error && <p>Loading…</p>}
    {settings && draft && <>
      <label className="panel__toolbar-field">Redirect URI
        <input readOnly value={settings.redirect_uri} onFocus={e => e.currentTarget.select()} data-testid="sso-redirect-uri" />
      </label>
      <button type="button" className="panel__action" onClick={() => {
        void (async () => {
          try {
            if (!navigator.clipboard) throw new Error("unavailable");
            await navigator.clipboard.writeText(settings.redirect_uri);
            setNotice("Redirect URI copied.");
          } catch { setNotice("Select the redirect URI and copy it manually."); }
        })();
      }}>Copy redirect URI</button>
      <p data-testid="sso-has-secret">Client secret: {settings.has_secret ? "Configured" : "Not configured"}</p>
      <p data-testid="sso-version">Version: {settings.version}</p>
      <p data-testid="sso-last-test">Last test: {settings.last_test
        ? `${settings.last_test.at} (version ${settings.last_test.version})` : "Never"}</p>
      <form data-testid="sso-settings-form" onSubmit={e => {
        e.preventDefault();
        if (operationRef.current) return;
        operationRef.current = true;
        // Portal copies often carry whitespace; the server also normalises, this keeps the form honest.
        const body: SSOSettingsInput = { ...draft,
          entra_tenant_id: draft.entra_tenant_id.trim(), client_id: draft.client_id.trim() };
        // A whitespace-only secret is still sent (as "") so the server refuses it visibly; omitting it would
        // silently keep the old secret.
        if (secret !== "") body.client_secret = secret.trim();
        // Clear the visible input at submission; only the pending operation retains its payload.
        setSecret("");
        setNotice(null);
        setOperation({ kind: "save", body });
      }}>
        <fieldset disabled={operation !== null}>
          <label className="panel__toolbar-field">Entra tenant ID
            <input required value={draft.entra_tenant_id} data-testid="sso-entra-tenant-id"
              onChange={e => setDraft({ ...draft, entra_tenant_id: e.target.value })} />
          </label>
          <label className="panel__toolbar-field">Client ID
            <input required value={draft.client_id} data-testid="sso-client-id"
              onChange={e => setDraft({ ...draft, client_id: e.target.value })} />
          </label>
          <label className="panel__toolbar-field">New client secret (leave blank to keep existing)
            <input type="password" value={secret} autoComplete="new-password" data-testid="sso-client-secret"
              onChange={e => setSecret(e.target.value)} />
          </label>
          <label><input type="checkbox" checked={draft.enabled} data-testid="sso-enabled"
            onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />Enabled</label>
          <label><input type="checkbox" checked={draft.trust_entra_mfa} data-testid="sso-trust-entra-mfa"
            aria-describedby="sso-amr-help"
            onChange={e => setDraft({ ...draft, trust_entra_mfa: e.target.checked })} />Trust Entra MFA</label>
          <p id="sso-amr-help" className="panel__note">Requires the 'amr' optional claim in the app registration</p>
          <button type="submit" className="panel__action" data-testid="sso-save">Save</button>
          {desktopClient && <p className="panel__note" data-testid="sso-desktop-note">Test sign-in opens
            Microsoft's sign-in pages, which the desktop app does not allow yet. Use the console in a web
            browser to test.</p>}
          <button type="button" className="panel__action" disabled={!settings.enabled || desktopClient} data-testid="sso-test"
            onClick={() => {
              if (operationRef.current) return;
              operationRef.current = true;
              setSecret("");
              setNotice(null);
              setOperation({ kind: "test" });
            }}>Test sign-in</button>
        </fieldset>
      </form>
    </>}
    {operation && <SSOStepUp key={operation.kind} api={api} onCancel={finish} onDone={finish} onForbidden={deny}
      action={async live => {
        if (operation.kind === "save") {
          // Remove the transient secret from the pending operation even when the request fails.
          const rotating = operation.body.client_secret !== undefined;
          const pendingSecret = operation.body.client_secret;
          const request = api.putSSO(operation.body);
          delete operation.body.client_secret;
          let saved;
          try {
            saved = await request;
          } catch (error) {
            // 428 = the verification went stale before the save ran; nothing was stored and the prompt
            // now asks for a code, so keep the secret for the retry. Cancel or completion drops it.
            if (error instanceof ConsoleApiError && error.status === 428) {
              if (rotating) operation.body.client_secret = pendingSecret;
              throw error;
            }
            // A failed save that carried a NEW secret must not be retried from this form: the pending
            // body no longer holds the secret, so a "successful" retry would silently keep the old one
            // (Codex impl review C v1). End the operation and ask for the secret again.
            if (rotating) {
              if (live()) {
                finish();
                // Only the fixed validation/conflict messages are worth repeating here (oidcAPIStatus).
                const reason = error instanceof ConsoleApiError && [400, 409].includes(error.status) ? ` ${error.message}.` : "";
                setNotice(`Saving failed and the new client secret was not stored.${reason} Enter the secret again and save.`);
              }
              return;
            }
            throw error;
          }
          if (live()) { accept(saved); setNotice("Microsoft sign-in settings saved."); }
        } else {
          const result = await api.startSSOTest();
          if (live()) window.location.assign(result.url);
        }
      }}>
      <p className="panel__note">{operation.kind === "save" ? "Saving settings" : "Testing sign-in"} requires your DeskRally authenticator code (one code covers the next few minutes).</p>
    </SSOStepUp>}
  </section>;
}
