/**
 * Per-tenant branding / white-label (docs/01 §9): edit the product name (console title/header) and
 * the accent colour (the `--accent` CSS variable). Owner-only to save (the server gates PUT on
 * CapManageTenant). On save, `onSaved` lets App re-apply the theme immediately without a reload.
 *
 * Below it, `PublicJoinSection` (docs/66 2j) edits the PUBLIC join page: a separate thing, saved as a revision that guests
 * see only after platform-operator approval.
 */

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { brandingControlsDisabled } from "../lib/branding_view";
import { isHexColor, isLogoDataUri, MAX_LOGO_BYTES, type ConsoleApi, type TenantBranding } from "../lib/console_api";
import { PublicJoinSection } from "./PublicJoinSection";

const LOGO_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];

const DEFAULT_ACCENT = "#3b82f6"; // the CSS `:root { --accent }` default, shown when none is set

export interface AppearancePanelProps {
  api: ConsoleApi;
  /** Called after a successful save so the app re-applies the theme immediately. */
  onSaved?: (branding: TenantBranding) => void;
}

export function AppearancePanel({ api, onSaved }: AppearancePanelProps) {
  const [productName, setProductName] = useState("");
  const [accent, setAccent] = useState(""); // "" = use the default accent
  const [logo, setLogo] = useState(""); // "" = no logo; else a validated raster data: URI
  const logoInput = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  // Save is gated on a SUCCESSFUL initial load: the form starts blank and only fills from the server,
  // so saving before (or after a FAILED) load would PUT empty strings and silently erase the tenant's
  // existing branding. `loaded` stays false on a load error, keeping Save disabled until a reload.
  const [loaded, setLoaded] = useState(false);

  // Bumped on unmount and whenever `api` changes; an in-flight save compares it to drop a stale result.
  const epochRef = useRef(0);

  useEffect(() => {
    let cancelled = false;
    // A new api means a different tenant: reset so the form refills from its own load.
    setLoaded(false);
    setBusy(false);
    setSaved(false);
    setError(null);
    void (async () => {
      try {
        const b = await api.getTenantBranding();
        if (!cancelled) {
          setProductName(b.product_name);
          setAccent(b.accent_color);
          setLogo(b.logo_data_uri);
          setLoaded(true);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
      epochRef.current += 1;
    };
  }, [api]);

  const handleSave = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const a = accent.trim();
      if (a !== "" && !isHexColor(a)) {
        setError("accent must be a #rrggbb hex colour, or empty for the default");
        return;
      }
      const epoch = epochRef.current;
      setBusy(true);
      setError(null);
      setSaved(false);
      try {
        const result = await api.setTenantBranding({ product_name: productName.trim(), accent_color: a, logo_data_uri: logo });
        // Drop a late result if the panel unmounted or `api` changed: never re-theme for a stale tenant.
        if (epochRef.current !== epoch) return;
        setProductName(result.product_name);
        setAccent(result.accent_color);
        setLogo(result.logo_data_uri);
        setSaved(true);
        onSaved?.(result);
      } catch (err) {
        if (epochRef.current !== epoch) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (epochRef.current === epoch) setBusy(false);
      }
    },
    [api, productName, accent, logo, onSaved],
  );

  // Read a picked image into a validated raster data: URI. The size cap is checked on the raw file
  // (its decoded bytes), and the type against the four allowed raster types; the server re-validates
  // both plus the magic bytes. SVG is not an accepted type, so a script-bearing SVG never gets here.
  const pickLogo = useCallback((file: File) => {
    setSaved(false);
    if (!LOGO_TYPES.includes(file.type)) {
      setError("logo must be a PNG, JPEG, GIF or WebP image");
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setError(`logo must be at most ${Math.floor(MAX_LOGO_BYTES / 1024)} KiB`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const uri = typeof reader.result === "string" ? reader.result : "";
      if (!isLogoDataUri(uri)) {
        setError("that image could not be read as a logo");
        return;
      }
      setError(null);
      setLogo(uri);
    };
    reader.onerror = () => setError("that image could not be read");
    reader.readAsDataURL(file);
  }, []);

  const controlsDisabled = brandingControlsDisabled(loaded, busy);

  return (
    <section className="panel panel--appearance" data-testid="appearance">
      <form className="panel__form" onSubmit={(e) => void handleSave(e)}>
        <span className="panel__toolbar-title">Console appearance</span>
        <span className="panel__toolbar-title" data-testid="appearance-console-note">
          Themes your team's console as soon as you save.
        </span>
        <label className="panel__toolbar-field">
          Product name
          <input
            value={productName}
            onChange={(e) => {
              setProductName(e.target.value);
              setSaved(false);
            }}
            placeholder="DeskRally"
            maxLength={100}
            disabled={controlsDisabled}
            data-testid="appearance-name"
          />
        </label>
        <label className="panel__toolbar-field">
          Accent colour
          <input
            type="color"
            value={isHexColor(accent) ? accent : DEFAULT_ACCENT}
            onChange={(e) => {
              setAccent(e.target.value);
              setSaved(false);
            }}
            disabled={controlsDisabled}
            data-testid="appearance-accent"
          />
        </label>
        <button
          type="button"
          className="panel__action"
          disabled={controlsDisabled}
          onClick={() => {
            setAccent("");
            setSaved(false);
          }}
          data-testid="appearance-accent-clear"
        >
          Use default accent
        </button>
        <label className="panel__toolbar-field">
          Logo
          <input
            ref={logoInput}
            type="file"
            accept={LOGO_TYPES.join(",")}
            disabled={controlsDisabled}
            data-testid="appearance-logo"
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = ""; // allow re-picking the same file
              if (file) pickLogo(file);
            }}
          />
        </label>
        {logo && (
          <img
            src={logo}
            alt="Current logo"
            data-testid="appearance-logo-preview"
            style={{ height: "2rem", verticalAlign: "middle" }}
          />
        )}
        {logo && (
          <button
            type="button"
            className="panel__action"
            disabled={controlsDisabled}
            onClick={() => {
              setLogo("");
              setSaved(false);
            }}
            data-testid="appearance-logo-clear"
          >
            Remove logo
          </button>
        )}
        <button className="panel__action" type="submit" disabled={controlsDisabled} data-testid="appearance-save">
          {busy ? "Saving…" : "Save"}
        </button>
        {saved && (
          <span className="panel__toolbar-title" data-testid="appearance-saved">
            Saved
          </span>
        )}
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="appearance-error">
            {error}
          </span>
        )}
      </form>
      <PublicJoinSection api={api} defaultOrigin={import.meta.env.VITE_DEFAULT_ORIGIN} />
    </section>
  );
}
