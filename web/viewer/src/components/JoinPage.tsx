/**
 * Guest landing page for attended sessions (docs/12 section 9, docs/27, docs/28): the technician
 * sends `/join#<code>`; this page shows the code and how to run the support client with it.
 *
 * The code rides the URL FRAGMENT (never a query param) so it stays out of server logs, referrers
 * and proxies; `main.tsx` reads it client-side only. The page is guest-facing and UNAUTHENTICATED --
 * it must never call a protected console endpoint, so it never reads `GET /tenant/branding` (which needs
 * a session).
 *
 * # Branding (docs/66 stage 2)
 *
 * The brand comes from the PUBLIC route `GET /cp/public/branding`, which the control plane answers for the
 * HOST the guest opened (`<slug>.deskrally.com`), never for the code: a tenant host shows that tenant's
 * operator-approved name, accent, logo, message and contact; every other host shows the page exactly as the
 * deployment ships it. `useHostBranding` asks once, with a short timeout, and any failure leaves the neutral
 * page in place, which is also what renders while the answer is pending, so a guest never sees a half-applied
 * brand. The deployment's build-time name (`productName`, `VITE_PRODUCT_NAME`) stays the fallback for
 * self-hosted single-tenant builds. The frame and everything a brand can touch is `JoinBrand`.
 *
 * # Honest copy is a security control here (docs/27 "what the page may NOT claim")
 *
 * Every sentence below is written against that list. In particular: nothing is called verified,
 * trusted, or safe; signing and publisher details depend on the deployed download, so the page
 * tells guests to check warnings with their technician rather than assume a publisher; there is
 * no promise the warning can always be clicked through, because on Smart App Control / AppLocker /
 * WDAC / an ASR rule there is no bypass; and the one sentence that does the most work -- only run
 * this if YOU called your IT provider, at a number you looked up yourself -- is always present.
 *
 * The download block renders ONLY when a same-origin URL is configured at build time and the guard
 * in `scripts/verify-download.ps1` has passed for the deployment (step 18). By default it is absent,
 * so the shipped page offers no download and points at the command-line path a technician walks the
 * customer through.
 */

import { useCallback, useEffect, useState } from "react";
import { RallyWelcome } from "./RallyIdentity";
import { BrandName, JoinBrand, brandDisplayName, effectiveBrand } from "./JoinBrand";
import { groupAttendCode } from "../lib/console_panels";
import { attendLaunchUri, validatedAttendCode } from "../lib/attend_link";
import { attendBundleEndpointUrl, attendSupportModeUrl, parseSupportMode, validAttendCodeForBundle } from "../lib/attend_bundle";
import { publicBrandingLogoUrl } from "../lib/host_branding";
import { useBrandDocumentTitle, useHostBranding } from "../lib/use_host_branding";
import {
  detectPlatform,
  resolveSupportDownload,
  type Platform,
  type SupportDownloadConfig,
} from "../lib/support_download";

export interface JoinPageProps {
  /** The raw attend code from the URL fragment ("" when the link was opened bare). */
  code: string;
  /** Origin override for tests; defaults to this page's origin. */
  origin?: string;
  /**
   * The deployment's build-time product name (`VITE_PRODUCT_NAME`), from `main.tsx`: the fallback when the
   * host publishes no brand of its own.
   */
  productName?: string;
  /** The default host's origin (`VITE_DEFAULT_ORIGIN`); the brand attribution links to its /docs. Unset or invalid = the neutral page. */
  defaultOrigin?: string;
  /** Build-time download config (`import.meta.env`), injected by `main.tsx`. */
  download?: SupportDownloadConfig;
  /** Platform override for tests; defaults to the live user agent. */
  platform?: Platform;
  /**
   * When true, show the session-bundle download (labelled "Download support client") for guests with a valid code.
   * Gated by `VITE_SUPPORT_BUNDLE_ENABLED` in `main.tsx` so deployments without the
   * support exe loaded on the server never surface the button.
   */
  bundleEnabled?: boolean;
}

export function JoinPage({ code: rawCode, origin, productName, defaultOrigin, download, platform, bundleEnabled }: JoinPageProps) {
  const [enteredCode, setEnteredCode] = useState(() => validatedAttendCode(rawCode));
  const [codeError, setCodeError] = useState("");
  const [code, setCode] = useState(() => validatedAttendCode(rawCode));
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [bundleState, setBundleState] = useState<"idle" | "downloading" | "failed" | "unavailable">("idle");
  const [openHelp, setOpenHelp] = useState(false);
  const cpOrigin = origin ?? window.location.origin;
  const hostBranding = useHostBranding(cpOrigin);
  const brand = effectiveBrand(hostBranding.brand, defaultOrigin);
  useBrandDocumentTitle(brand.name);
  const name = brandDisplayName(brand, productName);
  const command = `agent_host attend --code ${code || "<CODE>"} --control-plane-url ${cpOrigin}/cp`;
  const launchUri = attendLaunchUri(code, cpOrigin);

  const ua =
    platform ?? detectPlatform(typeof navigator === "undefined" ? undefined : navigator.userAgent);
  const dl = resolveSupportDownload(download ?? {}, ua);

  // Deployment-pass mode (docs/48 C): the standalone exe is generic and only works from inside the
  // session bundle, so the server says so and the plain download is not offered. While the answer
  // is PENDING the plain download is withheld too (a pass deployment must never show an unusable
  // exe, even briefly); a failure or any answer but an explicit true then restores today's page.
  const [supportMode, setSupportMode] = useState<"pending" | "bundle" | "legacy">(bundleEnabled ? "pending" : "legacy");
  useEffect(() => {
    if (!bundleEnabled) { setSupportMode("legacy"); return; }
    let active = true;
    setSupportMode("pending");
    const settle = (bundle: boolean) => { if (active) setSupportMode(bundle ? "bundle" : "legacy"); };
    void fetch(attendSupportModeUrl(cpOrigin), { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((body: unknown) => settle(parseSupportMode(body)), () => settle(false));
    return () => { active = false; };
  }, [bundleEnabled, cpOrigin]);
  const bundleOnly = supportMode === "bundle";
  const showStandalone = supportMode === "legacy";
  // The session bundle carries the code, so a guest who uses it has nothing to type: the steps say so.
  const bundleOffered = dl.kind === "ready" && !!bundleEnabled && !!code && bundleState !== "unavailable";

  const handleCopy = useCallback(() => {
    if (!code) return;
    void navigator.clipboard?.writeText(command).then(
      () => setCopyState("copied"),
      () => setCopyState("failed"),
    );
    // No clipboard API at all (old browser, insecure context) -> tell the guest, don't fail silent.
    if (!navigator.clipboard) setCopyState("failed");
  }, [command, code]);

  const handleBundleDownload = useCallback(() => {
    if (!code || !validAttendCodeForBundle(code)) return;
    setBundleState("downloading");
    void fetch(attendBundleEndpointUrl(cpOrigin), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }).then(async (res) => {
      if (res.status === 503) { setBundleState("unavailable"); return; }
      if (!res.ok) { setBundleState("failed"); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "DeskRally-Support.zip";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setBundleState("idle");
    }).catch(() => setBundleState("failed"));
  }, [code, cpOrigin]);

  return (
    <JoinBrand
      brand={brand}
      fallbackName={productName}
      defaultOrigin={defaultOrigin}
      logoSrc={publicBrandingLogoUrl(cpOrigin, brand.logoRev)}
      loading={!hostBranding.settled}
      nav={
        <>
          <a className="join__downloads" href="/downloads">Downloads</a>
          <a className="join__downloads" href="/docs">Documentation</a>
          <a className="join__signin" href="/console">Technician sign in</a>
        </>
      }
      welcome={<RallyWelcome />}
    >
        {/* ---- Step 1: get the client ---- */}
        <section className="join__step" aria-labelledby="join-step1">
          <h2 id="join-step1" className="join__stephead">
            <span className="join__stepnum">1</span> Get the <BrandName text={name} /> support client
          </h2>

          {dl.kind === "ready" && (
            <div className="join__download" data-testid="join-download">
              {bundleOffered && (
                <div className="join__bundle" data-testid="join-bundle">
                  <p>
                    <button
                      className="join__downloadbtn"
                      data-testid="join-bundle-btn"
                      onClick={handleBundleDownload}
                      disabled={bundleState === "downloading"}
                    >
                      {bundleState === "downloading" ? "Preparing…" : "Download support client"}
                    </button>
                  </p>
                  <p className="join__fineprint">
                    A ZIP with the support client and your session code already inside: extract it
                    and double-click DeskRallySupport.exe. No code to type.
                  </p>
                  {bundleState === "failed" && (
                    <p className="join__fineprint" role="alert" data-testid="join-bundle-error">
                      {bundleOnly
                        ? "Download failed. Try again in a moment, or ask your technician for a new link."
                        : "Download failed. Use the individual download below and enter your code manually."}
                    </p>
                  )}
                </div>
              )}
              {bundleEnabled && code && bundleState === "unavailable" && (
                <p className="join__fineprint" data-testid="join-bundle-unavailable">
                  {bundleOnly
                    ? "The session bundle is not available right now. Ask your technician for help or a new link."
                    : "The session bundle is not available for this deployment. Use the download below and enter your code manually when the client opens."}
                </p>
              )}
              {bundleOnly && !code && (
                <p className="join__fineprint" data-testid="join-bundle-needs-code">
                  Enter your session code below to get the download.
                </p>
              )}
              {showStandalone && (
                <>
                  <p>
                    <a
                      className={bundleOffered ? "join__downloadlink" : "join__downloadbtn"}
                      data-testid="join-download-link"
                      href={dl.url}
                      download
                    >
                      {bundleOffered ? "Or download the client on its own (you type your code)" : "Download support client"}
                    </a>
                  </p>
                  <p className="join__fineprint">
                    It's a single program for Windows. Nothing is installed and no permanent access is
                    left behind -- it runs once and you can delete it afterwards. It will not work over
                    Remote Desktop; run it on the computer that needs help.
                  </p>
                </>
              )}

              {showStandalone && dl.sha256 && (
                <p className="join__fineprint" data-testid="join-sha256">
                  So your technician can confirm you have the genuine file, read this code to them:{" "}
                  <span className="join__mono join__hash">{dl.sha256}</span>. This confirms the file
                  wasn't changed in transit -- it does not, on its own, prove where the file came
                  from.
                </p>
              )}

              <details className="join__details">
                <summary>If Windows or your browser gets in the way</summary>
                <ul className="join__helplist">
                  <li>
                    <strong>Your browser may block the download.</strong> If you see a warning or
                    the file never reaches your Downloads folder, stop and read the message to your
                    technician. Do not bypass a security warning to get the file.
                  </li>
                  <li>
                    <strong>Check any Windows warning before you run the client.</strong> Even a
                    signed download may show a warning. Ask your technician which publisher to
                    expect. If Windows shows an unknown or unexpected publisher, or reports a
                    signature problem, stop and read the exact message to your technician. A
                    publisher name alone does not prove a support request is legitimate.
                  </li>
                  <li>
                    <strong>Some computers block it with no way through.</strong> On a managed
                    machine (Smart App Control, AppLocker, WDAC, or an antivirus rule) Windows may
                    say it's blocked by your organisation and give you no "Run anyway". If so, read
                    exactly what it says to your technician and stop. We can't and won't tell you to
                    bypass it.
                  </li>
                  <li>
                    <strong>We will never ask you to turn off your antivirus</strong> or add an
                    exclusion. If your antivirus removes this file, tell your technician and stop.
                  </li>
                </ul>
              </details>
            </div>
          )}

          {dl.kind === "unsupported-platform" && (
            <p data-testid="join-unsupported">
              The <BrandName text={name} /> support client is for Windows. Open this page on the Windows computer that
              needs help, or ask your technician about other options.
            </p>
          )}

          {dl.kind === "unavailable" && (
            <p data-testid="join-download-unavailable">
              A downloadable client isn't offered for this support address yet. Your technician can
              guide you through starting it from a command line -- see "Advanced" below.
            </p>
          )}
        </section>

        {/* The code is redeemed BEFORE the separate sharing-consent dialog. */}
        <section className="join__step" aria-labelledby="join-step2">
          <h2 id="join-step2" className="join__stephead">
            <span className="join__stepnum">2</span> {bundleOffered ? "Open the client" : "Open the client and enter your code"}
          </h2>
          {bundleOffered && (
            <p data-testid="join-bundle-step">
              If you used the download above, your code is already inside: just open DeskRallySupport.exe. With
              the client on its own, enter the code below when it asks.
            </p>
          )}
          <form className="join__session-form" onSubmit={(event) => {
            event.preventDefault();
            const validated = validatedAttendCode(enteredCode.trim().replace(/[- ]/g, ""));
            if (!validated) {
              setCodeError("Enter the 8-character session code from your technician (older 13-character codes also work).");
              return;
            }
            // Keep the validated code out of requests, referrers and server logs.
            window.history.replaceState(null, "", `/join#${validated}`);
            setCode(validated); setEnteredCode(validated); setCopyState("idle");
          }}>
            <label htmlFor="support-session-code">Session code</label>
            <div className="join__session-fields">
              <input id="support-session-code" value={enteredCode} maxLength={40}
                autoComplete="off" spellCheck={false} autoCapitalize="characters"
                placeholder="Code from your technician"
                aria-invalid={!!codeError} aria-describedby={codeError ? "support-code-error" : undefined}
                onChange={(event) => { setEnteredCode(event.target.value); setCodeError(""); }} />
              {/* It only checks the code and shows it; joining happens in the client. */}
              <button className="join__action" type="submit">Continue</button>
            </div>
            {codeError && <p id="support-code-error" role="alert">{codeError}</p>}
          </form>
          {code ? <>
            <p>Your session code:</p>
            <p className="join__mono join__code" data-testid="join-code" data-code={code}>
              {groupAttendCode(code)}
            </p>
            <p>Enter this code in the support client when it asks. If it has expired, ask your technician for a new one.</p>
          </> : <p data-testid="join-no-code">Ask your technician for a session code or support link.</p>}
          {launchUri && (
            <>
              <p>
                <a className="join__action" data-testid="join-launch" href={launchUri}>
                  Open the <BrandName text={name} /> support client
                </a>
              </p>
              <p className="join__fineprint" data-testid="join-launch-note">
                Only if it is already on this computer. Nothing happens otherwise, and the browser can't tell
                whether it opened: use the download above instead.
              </p>
            </>
          )}
        </section>

        <section className="join__step" aria-labelledby="join-step3">
          <h2 id="join-step3" className="join__stephead">
            <span className="join__stepnum">3</span> Approve screen sharing
          </h2>
          <p>
            Click Connect in the client, check the support address in the permission prompt, and
            choose <strong>Yes</strong> only when you are ready to share your screen and allow control.
            Entering a code contacts the support service to prepare the session; it does not approve
            screen sharing. An indicator stays visible during support, and you can end the session.
          </p>
        </section>

        {/* ---- Advanced: the command-line path (kept verbatim, demoted, never deleted) ---- */}
        <details
          className="join__advanced"
          data-testid="join-advanced"
          open={openHelp}
          onToggle={(e) => setOpenHelp((e.target as HTMLDetailsElement).open)}
        >
          <summary>Advanced: start from a command line</summary>
          <p>
            Run the client from a command line on the computer that needs help (it still asks for
            your consent and shows an indicator):
          </p>
          <p className="join__mono join__code" data-testid="join-command">
            {command}
          </p>
          <button className="join__action" data-testid="join-copy" onClick={handleCopy} disabled={!code}>
            {copyState === "copied" ? "Copied" : "Copy command"}
          </button>
          <p className="join__fineprint" role="status" data-testid="join-copy-status">
            {copyState === "copied" && "Command copied to the clipboard."}
            {copyState === "failed" &&
              "Couldn't copy automatically -- select the command above and copy it manually."}
          </p>
        </details>
    </JoinBrand>
  );
}
