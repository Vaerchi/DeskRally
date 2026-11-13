/**
 * "Public join page" section of the Appearance panel (docs/66 2.7, 2j): what guests see on the tenant's own hostname.
 *
 * This is NOT the console appearance above it. Console appearance themes the team's own console at once (`PUT
 * /tenant/branding`). The public join page is saved as an immutable REVISION (`POST /tenant/branding/revisions`) and shown
 * to guests only after a platform operator approves it, so this section says so, shows the approval state, and previews
 * the draft with the real join-page component before anything is submitted.
 *
 * The inline checks (lib/brand_text.ts, lib/brand_contrast.ts) mirror the server's; the server is the authority and its
 * own refusal text is shown whenever it disagrees. Only an Owner (`manage_tenant`) may edit; members see it read-only.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ConsoleApiError, type ConsoleApi, type TenantBranding } from "../lib/console_api";
import { publicJoinControlsDisabled, canManageTenant } from "../lib/branding_view";
import {
  buildRevisionInput,
  describeBrandingStatus,
  describeSubmitFailure,
  prefillBrandForm,
  type BrandingRevisionsView,
  type LogoState,
  type PrefillSource,
} from "../lib/brand_revisions";
import { checkBrandForm, supportTextCounts, type BrandFormValues } from "../lib/brand_text";
import {
  CONTRAST_LABEL_MIN,
  CONTRAST_SURFACE_MIN,
  checkAccentContrast,
  floor2,
} from "../lib/brand_contrast";
import { LOGO_PICK_TYPES, LogoPrepareError, downscaleLogoToPng } from "../lib/brand_logo";
import { PREVIEW_ORIGIN_NOTICE, draftToHostBrand, previewLogoSrc, previewOriginUsable } from "../lib/brand_preview";
import { BRAND_NAME_MAX, BRAND_TEXT_MAX, BRAND_TEXT_MAX_LINES, type BrandContactKind } from "../lib/host_branding";
import { JoinPreview, type PreviewWidth } from "./JoinPreview";
import "./PublicJoinSection.css";

const DEFAULT_ACCENT = "#35654a"; // shown in the colour picker when no accent is set (the join page's own forest green)
const MAX_PICKED_FILE_BYTES = 8 * 1024 * 1024; // a photo is fine to pick: it is downscaled before upload

// The server names its refusals by JSON field; the form has one place for each.
const FIELD_FOR_SERVER: Record<string, FieldKey> = {
  product_name: "productName",
  accent_color: "accent",
  support_text: "supportText",
  support_contact: "contact",
  logo: "logo",
};
type FieldKey = "productName" | "accent" | "supportText" | "contact" | "logo";

export interface PublicJoinSectionProps {
  api: ConsoleApi;
  /** The deployment's default origin (`import.meta.env.VITE_DEFAULT_ORIGIN`); the preview passes it to JoinBrand unchanged. */
  defaultOrigin?: string;
}

export function PublicJoinSection({ api, defaultOrigin }: PublicJoinSectionProps) {
  const [view, setView] = useState<BrandingRevisionsView | null>(null);
  const [isOwner, setIsOwner] = useState(false);
  // Bumped by each successful LOAD (not by a submit): the form is filled from the server once per load.
  const [loadToken, setLoadToken] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [values, setValues] = useState<BrandFormValues>({ productName: "", accent: "", supportText: "", contactKind: "", contactValue: "" });
  const [logo, setLogo] = useState<LogoState>({ kind: "none" });
  const [source, setSource] = useState<PrefillSource | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<{ field: FieldKey | ""; message: string } | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [refreshNote, setRefreshNote] = useState<string | null>(null);
  const [logoNotice, setLogoNotice] = useState<string | null>(null);
  const [width, setWidth] = useState<PreviewWidth>("phone");
  const [neutral, setNeutral] = useState(false);
  const epochRef = useRef(0);
  // A picked logo is downscaled before it can be sent. `selectionRef` numbers the selections (and a removal): only the newest
  // one's result is used, and while it is pending `preparing` keeps Submit from sending the logo state of BEFORE the pick.
  const selectionRef = useRef(0);
  const [preparing, setPreparing] = useState(false);
  // The console appearance as the load saw it: the last-resort starting point (null when it could not be read).
  const consoleRef = useRef<TenantBranding | null>(null);

  useEffect(() => {
    let cancelled = false;
    setView(null);
    setLoadError(null);
    setBusy(false);
    setOutcome(null);
    setProblem(null);
    selectionRef.current += 1; // a pick still converting belongs to the previous load
    setPreparing(false);
    void (async () => {
      try {
        const [v, owner, consoleB] = await Promise.all([
          api.getBrandingRevisions(),
          // A failed capability read is "not an Owner": the section stays read-only rather than inviting a refused submit.
          api.me().then((m) => canManageTenant(m.capabilities), () => false),
          api.getTenantBranding().catch(() => null),
        ]);
        if (!cancelled) {
          consoleRef.current = consoleB;
          setView(v);
          setIsOwner(owner);
          setLoadToken((t) => t + 1);
        }
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
      epochRef.current += 1;
    };
  }, [api]);

  // Fill the form once per load, from the draft, else the published revision, else the console appearance.
  const filledFor = useRef(0);
  useEffect(() => {
    if (view === null || loadToken === 0 || filledFor.current === loadToken) return;
    filledFor.current = loadToken;
    const p = prefillBrandForm(view, consoleRef.current);
    setValues(p.values);
    setLogo(p.logo);
    setSource(p.source);
    setNote(p.note);
  }, [view, loadToken]);

  // A logo copied from the console appearance is downscaled before it can be submitted (the console one may be large or a WebP).
  const consoleLogoUri = logo.kind === "console" ? logo.dataUri : null;
  useEffect(() => {
    if (consoleLogoUri === null) return;
    let cancelled = false;
    downscaleLogoToPng(consoleLogoUri).then(
      (uri) => {
        if (!cancelled) setLogo({ kind: "new", dataUri: uri });
      },
      (e) => {
        if (cancelled) return;
        setLogo({ kind: "none" });
        setLogoNotice(`The console logo could not be copied: ${e instanceof LogoPrepareError ? e.message : "it could not be read"}.`);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [consoleLogoUri]);

  const logoSupported = view?.logoUploadSupported ?? false;
  const ready = view !== null && source !== null && filledFor.current === loadToken;
  const disabled = publicJoinControlsDisabled(ready, busy, isOwner);

  const check = useMemo(() => checkBrandForm(values), [values]);
  const counts = useMemo(() => supportTextCounts(values.supportText), [values.supportText]);
  const accentCheck = useMemo(() => checkAccentContrast(values.accent.trim().toLowerCase()), [values.accent]);
  const previewBrand = useMemo(() => draftToHostBrand(check), [check]);
  const status = useMemo(() => (view === null ? null : describeBrandingStatus(view)), [view]);

  const edit = useCallback((patch: Partial<BrandFormValues>) => {
    setValues((v) => ({ ...v, ...patch }));
    setOutcome(null);
    setProblem(null);
  }, []);

  const pickLogo = useCallback(async (file: File) => {
    const selection = ++selectionRef.current; // any earlier pick still converting is now superseded
    setOutcome(null);
    setProblem(null);
    setLogoNotice(null);
    if (!LOGO_PICK_TYPES.includes(file.type)) {
      setPreparing(false);
      setLogoNotice("The logo must be a PNG, JPEG, GIF or WebP image.");
      return;
    }
    if (file.size > MAX_PICKED_FILE_BYTES) {
      setPreparing(false);
      setLogoNotice("That image file is too large; choose one under 8 MiB.");
      return;
    }
    const epoch = epochRef.current;
    setPreparing(true);
    try {
      const uri = await downscaleLogoToPng(file);
      if (epochRef.current === epoch && selectionRef.current === selection) {
        setLogo({ kind: "new", dataUri: uri });
        setPreparing(false);
      }
    } catch (e) {
      if (epochRef.current === epoch && selectionRef.current === selection) {
        setLogoNotice(e instanceof LogoPrepareError ? `${e.message}.` : "That image could not be read.");
        setPreparing(false);
      }
    }
  }, []);

  const removeLogo = useCallback(() => {
    selectionRef.current += 1; // a conversion still running must not bring the logo back
    setPreparing(false);
    setLogo({ kind: "none" });
  }, []);

  const submit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (preparing) {
        setProblem({ field: "logo", message: "The logo you chose is still being prepared; try again in a moment." });
        return;
      }
      const input = buildRevisionInput(values, check, logo, logoSupported);
      if (input === null) {
        setProblem({ field: "logo", message: "The logo copied from the console is still being prepared; try again in a moment." });
        return;
      }
      const epoch = epochRef.current;
      setBusy(true);
      setProblem(null);
      setOutcome(null);
      setRefreshNote(null);
      try {
        const result = await api.createBrandingRevision(input);
        if (epochRef.current !== epoch) return;
        selectionRef.current += 1; // nothing picked before this answer may overwrite the logo state it reports
        // The revision exists now: report that first, whatever the status refresh does.
        setLogo(result.revision.hasLogo ? { kind: "kept", sha256: result.revision.logoSha256 } : { kind: "none" });
        setOutcome(
          result.created
            ? "Submitted. Your platform operator must approve it before guests see it; until then the live page keeps showing the last approved version (or the neutral page)."
            : "No change: this is the same as your current draft, so nothing new was submitted.",
        );
        try {
          const fresh = await api.getBrandingRevisions();
          if (epochRef.current !== epoch) return;
          // The status row follows the server; the form keeps what the Owner typed (the draft they just submitted).
          setView(fresh);
        } catch {
          if (epochRef.current !== epoch) return;
          setRefreshNote("Submitted, but the status row could not be refreshed. Reload the page to see it.");
        }
      } catch (err) {
        if (epochRef.current !== epoch) return;
        if (err instanceof ConsoleApiError) {
          const p = describeSubmitFailure(err.status, err.code !== "" ? err.code : err.message, err.field);
          setProblem({ field: FIELD_FOR_SERVER[p.field] ?? "", message: p.message });
        } else {
          setProblem({ field: "", message: err instanceof Error ? err.message : String(err) });
        }
      } finally {
        if (epochRef.current === epoch) setBusy(false);
      }
    },
    [api, values, check, logo, logoSupported, preparing],
  );

  const errId = (key: FieldKey) => `pub-err-${key}`;
  const fieldError = (key: FieldKey, local: string | undefined) => {
    const server = problem !== null && problem.field === key ? problem.message : null;
    if (server !== null) {
      return (
        <span className="pubjoin__error" role="alert" id={errId(key)} data-testid={`pub-error-${key}`} data-from="server">
          The server says: {server}
        </span>
      );
    }
    return local ? (
      <span className="pubjoin__error" id={errId(key)} data-testid={`pub-error-${key}`} data-from="local">
        {local}
      </span>
    ) : null;
  };

  const contactKind = values.contactKind;
  const logoSrc = previewLogoSrc(logo);

  return (
    <section className="pubjoin" data-testid="public-join" aria-labelledby="pubjoin-title">
      <h3 className="pubjoin__title" id="pubjoin-title">
        Public join page
      </h3>
      <p className="pubjoin__lede">
        What guests see when they open your own join address. This is separate from the console appearance above: it is saved
        as a revision and shown to guests only after your platform operator approves it.
      </p>

      {loadError !== null && (
        <span className="pubjoin__error" role="alert" data-testid="pub-load-error">
          {loadError}
        </span>
      )}

      {status !== null && (
        <dl className="pubjoin__status" data-testid="pub-status">
          <dt>Public hostname</dt>
          <dd data-testid="pub-status-hostname" data-assigned={view?.assignment ? "true" : "false"}>
            {status.hostname}
            {status.hostnameState !== "" && <span data-testid="pub-status-host-state"> ({status.hostnameState})</span>}
          </dd>
          <dt>Approval</dt>
          <dd data-testid="pub-status-approval">{status.approval}</dd>
          <dt>Live page shows the published revision</dt>
          <dd data-testid="pub-status-live" data-live={view?.live ? "true" : "false"}>
            {status.live}
          </dd>
        </dl>
      )}

      {ready && !isOwner && (
        <p className="pubjoin__readonly" data-testid="pub-readonly">
          Only an Owner can edit and submit the public join page. You can see what is drafted and the preview.
        </p>
      )}

      {ready && (
        <div className="pubjoin__body">
          <form className="pubjoin__form" onSubmit={(e) => void submit(e)} data-testid="pub-form">
            <p className="pubjoin__note" data-testid="pub-prefill-note" data-source={source ?? ""}>
              {note}
            </p>

            <div className="pubjoin__field">
              <label htmlFor="pub-name-input">Product name</label>
              <input
                id="pub-name-input"
                aria-describedby={`pub-name-hint ${errId("productName")}`}
                value={values.productName}
                onChange={(e) => edit({ productName: e.target.value })}
                disabled={disabled}
                placeholder="Acme Support"
                aria-invalid={check.errors.productName !== undefined}
                data-testid="pub-name"
              />
              <span className="pubjoin__hint" id="pub-name-hint">3 to {BRAND_NAME_MAX} characters, one line.</span>
              {fieldError("productName", check.errors.productName)}
            </div>

            <fieldset className="pubjoin__field pubjoin__accent">
              <legend>Accent colour</legend>
              <span className="pubjoin__row">
                <input
                  type="color"
                  value={/^#[0-9a-fA-F]{6}$/.test(values.accent) ? values.accent.toLowerCase() : DEFAULT_ACCENT}
                  onChange={(e) => edit({ accent: e.target.value })}
                  disabled={disabled}
                  data-testid="pub-accent"
                />
                <input
                  value={values.accent}
                  onChange={(e) => edit({ accent: e.target.value })}
                  disabled={disabled}
                  placeholder="#35654a (empty = the page's own green)"
                  aria-label="Accent colour as #rrggbb"
                  aria-describedby={`pub-contrast ${errId("accent")}`}
                  aria-invalid={check.errors.accent !== undefined}
                  data-testid="pub-accent-text"
                />
                <button type="button" className="panel__action" disabled={disabled} onClick={() => edit({ accent: "" })} data-testid="pub-accent-clear">
                  Use default accent
                </button>
              </span>
              <span className="pubjoin__hint" id="pub-contrast" data-testid="pub-contrast" data-state={accentCheck.failure !== null ? "fail" : accentCheck.labelRatio === null ? "none" : "ok"}>
                {accentCheck.labelRatio === null || accentCheck.surfaceRatio === null
                  ? "The page's own accent is used. Pick a colour to see its contrast."
                  : `White button label ${floor2(accentCheck.labelRatio)}:1 (needs ${CONTRAST_LABEL_MIN}:1) · page surface ${floor2(accentCheck.surfaceRatio)}:1 (needs ${CONTRAST_SURFACE_MIN}:1)${accentCheck.failure !== null ? " — too light" : " — passes"}`}
              </span>
              {fieldError("accent", check.errors.accent)}
            </fieldset>

            <div className="pubjoin__field">
              <label htmlFor="pub-text-input">Support text</label>
              <textarea
                id="pub-text-input"
                aria-describedby={`pub-text-counter ${errId("supportText")}`}
                value={values.supportText}
                onChange={(e) => edit({ supportText: e.target.value })}
                disabled={disabled}
                rows={4}
                aria-invalid={check.errors.supportText !== undefined}
                data-testid="pub-text"
              />
              <span
                className="pubjoin__hint"
                id="pub-text-counter"
                data-testid="pub-text-counter"
                data-over={counts.runes > BRAND_TEXT_MAX || counts.lines > BRAND_TEXT_MAX_LINES ? "true" : "false"}
              >
                {counts.runes}/{BRAND_TEXT_MAX} characters · {counts.lines}/{BRAND_TEXT_MAX_LINES} lines
              </span>
              {fieldError("supportText", check.errors.supportText)}
            </div>

            <fieldset className="pubjoin__field pubjoin__contact" disabled={disabled}>
              <legend>Support contact</legend>
              <span className="pubjoin__row">
                <select
                  value={contactKind}
                  onChange={(e) => edit({ contactKind: e.target.value as BrandContactKind | "" })}
                  aria-label="Support contact kind"
                  data-testid="pub-contact-kind"
                >
                  <option value="">None</option>
                  <option value="phone">Phone</option>
                  <option value="email">Email</option>
                  <option value="url">Website (https)</option>
                </select>
                <input
                  value={values.contactValue}
                  onChange={(e) => edit({ contactValue: e.target.value })}
                  placeholder={contactKind === "phone" ? "+1 555 010 0199" : contactKind === "email" ? "help@example.com" : contactKind === "url" ? "https://support.example.com" : ""}
                  aria-label="Support contact value"
                  aria-describedby={errId("contact")}
                  aria-invalid={check.errors.contact !== undefined}
                  data-testid="pub-contact-value"
                />
              </span>
              {fieldError("contact", check.errors.contact)}
            </fieldset>

            {logoSupported && (
              <div className="pubjoin__field" data-testid="pub-logo-field">
                <label>
                  Logo
                  <input
                    type="file"
                    accept={LOGO_PICK_TYPES.join(",")}
                    disabled={disabled}
                    data-testid="pub-logo"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      e.target.value = ""; // allow re-picking the same file
                      if (file) void pickLogo(file);
                    }}
                  />
                </label>
                <span className="pubjoin__hint" data-testid="pub-logo-state" data-state={logo.kind} data-preparing={preparing ? "true" : "false"}>
                  {preparing
                    ? "Preparing the logo you chose…"
                    : logo.kind === "new"
                    ? "New logo ready (resized to fit 512 by 256 before upload)."
                    : logo.kind === "kept"
                      ? "Your current logo is kept. Choose a file to replace it; the console cannot display the stored logo."
                      : logo.kind === "console"
                        ? "Preparing the logo copied from your console appearance…"
                        : "No logo. The join page shows the DeskRally mark."}
                </span>
                {(logo.kind === "new" || logo.kind === "kept" || preparing) && (
                  <button type="button" className="panel__action" disabled={disabled} onClick={removeLogo} data-testid="pub-logo-clear">
                    Remove logo
                  </button>
                )}
                {logoNotice !== null && (
                  <span className="pubjoin__error" role="alert" data-testid="pub-logo-notice">
                    {logoNotice}
                  </span>
                )}
                {fieldError("logo", undefined)}
              </div>
            )}

            {isOwner && (
              <div className="pubjoin__actions">
                <button className="panel__action" type="submit" disabled={disabled || preparing} data-testid="pub-submit">
                  {busy ? "Submitting…" : "Submit for approval"}
                </button>
              </div>
            )}
            {outcome !== null && (
              <span className="pubjoin__outcome" role="status" data-testid="pub-outcome">
                {outcome}
              </span>
            )}
            {refreshNote !== null && (
              <span className="pubjoin__note" role="status" data-testid="pub-refresh-note">
                {refreshNote}
              </span>
            )}
            {problem !== null && problem.field === "" && (
              <span className="pubjoin__error" role="alert" data-testid="pub-error">
                {problem.message}
              </span>
            )}
          </form>

          <div className="pubjoin__preview" data-testid="pub-preview-pane">
            <div className="pubjoin__previewbar">
              <span className="pubjoin__previewtitle">Preview (your draft, before it is submitted)</span>
              <label>
                <input type="radio" name="pub-width" checked={width === "phone"} onChange={() => setWidth("phone")} data-testid="pub-width-phone" /> Phone
              </label>
              <label>
                <input type="radio" name="pub-width" checked={width === "desktop"} onChange={() => setWidth("desktop")} data-testid="pub-width-desktop" /> Desktop
              </label>
              <label>
                <input type="checkbox" checked={neutral} onChange={(e) => setNeutral(e.target.checked)} data-testid="pub-neutral" /> Show as neutral default
              </label>
            </div>
            {!previewOriginUsable(defaultOrigin) && (
              <p className="pubjoin__error" role="status" data-testid="pub-origin-notice">
                {PREVIEW_ORIGIN_NOTICE}
              </p>
            )}
            {logo.kind === "kept" && (
              <p className="pubjoin__hint" data-testid="pub-preview-logo-note">
                The preview shows the DeskRally mark where your kept logo goes; the stored logo is not sent back to the console.
              </p>
            )}
            <JoinPreview brand={previewBrand} logoSrc={logoSrc} defaultOrigin={defaultOrigin} fallbackName={import.meta.env.VITE_PRODUCT_NAME} width={width} neutral={neutral} testId="pub-preview" />
          </div>
        </div>
      )}
    </section>
  );
}
