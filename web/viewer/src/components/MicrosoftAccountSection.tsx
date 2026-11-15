import { useState } from "react";
import type { ConsoleApi } from "../lib/console_api";
import { SSOStepUp } from "./SSOStepUp";
import { desktopClientLacksSso } from "../lib/desktop_launch";

export function MicrosoftAccountSection({ api }: { api: ConsoleApi }) {
  const [action, setAction] = useState<"link" | "unlink" | null>(null);
  const [notice, setNotice] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get("sso") === "linked"
      ? "Microsoft account linked successfully." : null);
  // The desktop app only navigates within the tenant's own origin, so Microsoft's pages are cancelled
  // and the button would bounce back silently (production 2026-10-17). Say so instead.
  const desktopClient = desktopClientLacksSso(navigator.userAgent);

  return <section className="panel__form" aria-label="Microsoft sign-in" data-testid="account-sso-section">
    <span className="panel__toolbar-title">Microsoft sign-in</span>
    {notice && <p role="status" data-testid="account-sso-notice">{notice}</p>}
    {desktopClient && <p className="panel__note" data-testid="account-sso-desktop-note">Linking opens
      Microsoft's sign-in pages, which the desktop app does not allow yet. Use the console in a web
      browser to link.</p>}
    <button type="button" className="panel__action" disabled={action !== null || desktopClient}
      data-testid="sso-link" onClick={() => { setNotice(null); setAction("link"); }}>Link Microsoft account</button>
    <button type="button" className="panel__action panel__action--danger" disabled={action !== null}
      data-testid="sso-unlink" onClick={() => { setNotice(null); setAction("unlink"); }}>Unlink</button>
    {action && <SSOStepUp key={action} api={api} onCancel={() => setAction(null)}
      onDone={() => setAction(null)} action={async live => {
        if (action === "link") {
          const result = await api.startSSOLink();
          if (live()) window.location.assign(result.url);
        } else {
          await api.unlinkSSO();
          if (live()) setNotice("Microsoft account unlinked.");
        }
      }}>
      <p className="panel__note">{action === "link" ? "Linking" : "Unlinking"} your Microsoft account requires your DeskRally authenticator code.</p>
    </SSOStepUp>}
  </section>;
}
