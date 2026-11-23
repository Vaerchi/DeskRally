/**
 * Per-tenant IP allow-list (docs/01 §10): list + add + remove the source CIDRs this tenant permits on
 * the authenticated API, over GET/POST/DELETE /tenant/ip-allowlist. When the list is empty the API is
 * open (no restriction); a non-empty list refuses any source not covered.
 *
 * The panel shows the caller's CURRENT source IP (from the GET) so an admin can see whether an entry
 * they are about to add or remove covers them — and the server's anti-lockout safeguard refuses any
 * change that would fence the acting admin out, surfaced here as an inline error rather than a silent
 * self-lockout. Thin like the other console panels: it owns only load/refresh/in-flight state and
 * rendering; the server is the authority on CIDR validity and lockout.
 */

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import type { ConsoleApi } from "../lib/console_api";
import { TenantSSOSection } from "./TenantSSOSection";
import { AdoptionSection } from "./AdoptionSection";
import { RecordingPolicySection } from "./RecordingPolicySection";
import { allowlistEmptyStateText } from "../lib/console_panels";
import { createLatestWins } from "../lib/latest_wins";
import { defaultIdleMinutes, MAX_DEFAULT_IDLE_MINUTES, parseDefaultIdleMinutes, parseSessionPolicyInput } from "../lib/session_policy_input";
import { sessionLimitControlsDisabled, twoFactorControlState } from "../lib/tenant_security_view";

export interface TenantSecurityPanelProps {
  api: ConsoleApi;
}

export function TenantSecurityPanel({ api }: TenantSecurityPanelProps) {
  const [cidrs, setCidrs] = useState<readonly string[]>([]);
  const [yourIp, setYourIp] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cidr, setCidr] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  // Session policy: the concurrency cap, max session age, and default idle timeout are saved together.
  // saved* are the stored values; *Input are the editable fields. limitError is separate from the
  // allow-list error so each section reports its own.
  const [savedLimit, setSavedLimit] = useState<number | null>(null);
  const [limitInput, setLimitInput] = useState("");
  const [savedMaxAge, setSavedMaxAge] = useState<number | null>(null);
  const [maxAgeInput, setMaxAgeInput] = useState("");
  const [idleInput, setIdleInput] = useState("");
  const [savingLimit, setSavingLimit] = useState(false);
  const [limitError, setLimitError] = useState<string | null>(null);
  // Tri-state: null = not yet read (or the read failed); only a successful read/save makes it a boolean.
  // docs/69 step 4: the tenant's session verification policy (null until loaded).
  const [sessionBinding, setSessionBinding] = useState<"warn" | "require" | null>(null);
  const [savingBinding, setSavingBinding] = useState(false);
  const [require2fa, setRequire2fa] = useState<boolean | null>(null);
  const [saving2fa, setSaving2fa] = useState(false);
  const [error2fa, setError2fa] = useState<string | null>(null);

  // Latest-wins guards, one per section: a read applies its result only if no newer read began and no
  // write was submitted for that section since, so an older in-flight GET can never overwrite a newer
  // (e.g. confirmed-PUT) value. refreshGen separately tracks the newest refresh() so only it clears busy.
  const allowlistWins = useRef(createLatestWins());
  const policyWins = useRef(createLatestWins());
  const twoFactorWins = useRef(createLatestWins());
  const refreshGen = useRef(0);

  const refresh = useCallback(async () => {
    const myRefresh = ++refreshGen.current;
    // All three section tokens are taken synchronously here and held for the whole refresh, so a
    // superseded refresh resuming later can neither begin() (and invalidate a newer refresh's tokens)
    // nor clear a newer error: its own tokens are already stale.
    const token = allowlistWins.current.begin();
    const policyToken = policyWins.current.begin();
    const twoFactorToken = twoFactorWins.current.begin();
    setBusy(true);
    setError(null);
    setLimitError(null);
    setError2fa(null);
    // Load the sections INDEPENDENTLY: a single Promise.all would reject on either failure, discarding
    // the other section's successful result and misfiling its error. Each load routes its own failure to
    // its own error slot, so one section being unavailable never blanks the other. A stale read's
    // result AND error are dropped, and a superseded refresh launches no further reads (the newer
    // refresh performs them).
    try {
      try {
        const list = await api.getTenantIPAllowlist();
        if (allowlistWins.current.isCurrent(token)) {
          setCidrs(list.cidrs);
          setYourIp(list.yourIp);
        }
      } catch (e) {
        if (allowlistWins.current.isCurrent(token)) setError(e instanceof Error ? e.message : String(e));
      }
      if (refreshGen.current !== myRefresh) return;
      try {
        const policy = await api.getSessionPolicy();
        if (policyWins.current.isCurrent(policyToken)) {
          setSavedLimit(policy.max_concurrent_sessions);
          setLimitInput(String(policy.max_concurrent_sessions));
          setSavedMaxAge(policy.max_session_seconds);
          setMaxAgeInput(String(policy.max_session_seconds));
          setIdleInput(defaultIdleMinutes(policy.default_max_idle_seconds ?? 0));
          setSessionBinding(policy.session_binding ?? "warn");
        }
      } catch (e) {
        if (policyWins.current.isCurrent(policyToken)) setLimitError(e instanceof Error ? e.message : String(e));
      }
      if (refreshGen.current !== myRefresh) return;
      try {
        const secPolicy = await api.getTenantSecurityPolicy();
        if (twoFactorWins.current.isCurrent(twoFactorToken)) setRequire2fa(secPolicy.require_2fa);
      } catch (e) {
        if (twoFactorWins.current.isCurrent(twoFactorToken)) setError2fa(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (refreshGen.current === myRefresh) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleAdd = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const trimmed = cidr.trim();
      if (trimmed === "") {
        setError("enter an IP or CIDR (e.g. 203.0.113.0/24 or 198.51.100.7)");
        return;
      }
      setSaving(true);
      setError(null);
      allowlistWins.current.invalidate();
      try {
        await api.addTenantIPAllowlistEntry(trimmed);
        setCidr("");
        await refresh();
      } catch (err) {
        // Surfaces the server's anti-lockout 400 ("this would lock you out …") and CIDR-parse errors.
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, cidr, refresh],
  );

  const handleSaveLimit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      // Mirrors the server's bounds so an out-of-range value gets a field-specific message before the
      // round-trip; the server remains the authority.
      const parsed = parseSessionPolicyInput(limitInput, maxAgeInput);
      if (!parsed.ok) {
        setLimitError(parsed.error);
        return;
      }
      const idleSeconds = parseDefaultIdleMinutes(idleInput);
      if (idleSeconds === null) {
        setLimitError("Enter 0 to 60 minutes in increments of one second.");
        return;
      }
      setSavingLimit(true);
      setLimitError(null);
      policyWins.current.invalidate();
      try {
        const saved = await api.setSessionPolicy({ ...parsed.value, default_max_idle_seconds: idleSeconds });
        // Apply the confirmed echo under a fresh token: any read begun while the PUT was in flight is stale.
        policyWins.current.begin();
        setSavedLimit(saved.max_concurrent_sessions);
        setLimitInput(String(saved.max_concurrent_sessions));
        setSavedMaxAge(saved.max_session_seconds);
        setMaxAgeInput(String(saved.max_session_seconds));
        setIdleInput(defaultIdleMinutes(saved.default_max_idle_seconds ?? 0));
        setSessionBinding(saved.session_binding ?? "warn");
      } catch (err) {
        setLimitError(err instanceof Error ? err.message : String(err));
      } finally {
        setSavingLimit(false);
      }
    },
    [api, limitInput, maxAgeInput, idleInput],
  );

  // Sends the SAVED limits with the mode: the PUT replaces the whole policy, so the toggle must not reset them.
  const handleToggleBinding = useCallback(
    async (require: boolean) => {
      if (savedLimit === null || savedMaxAge === null) return;
      setSavingBinding(true);
      setLimitError(null);
      policyWins.current.invalidate();
      try {
        const saved = await api.setSessionPolicy({
          max_concurrent_sessions: savedLimit,
          max_session_seconds: savedMaxAge,
          session_binding: require ? "require" : "warn",
        });
        policyWins.current.begin();
        setSavedLimit(saved.max_concurrent_sessions);
        setLimitInput(String(saved.max_concurrent_sessions));
        setSavedMaxAge(saved.max_session_seconds);
        setMaxAgeInput(String(saved.max_session_seconds));
        setIdleInput(defaultIdleMinutes(saved.default_max_idle_seconds ?? 0));
        setSessionBinding(saved.session_binding ?? "warn");
      } catch (err) {
        setLimitError(err instanceof Error ? err.message : String(err));
      } finally {
        setSavingBinding(false);
      }
    },
    [api, savedLimit, savedMaxAge],
  );

  const handleToggle2fa = useCallback(
    async (checked: boolean) => {
      setSaving2fa(true);
      setError2fa(null);
      twoFactorWins.current.invalidate();
      try {
        const saved = await api.setTenantSecurityPolicy({ require_2fa: checked });
        // Confirmed echo under a fresh token: a read begun while the PUT was in flight is now stale.
        twoFactorWins.current.begin();
        setRequire2fa(saved.require_2fa);
      } catch (err) {
        // Surfaces the server's anti-lockout 400 ("you must have TOTP enrolled …").
        setError2fa(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving2fa(false);
      }
    },
    [api],
  );

  const handleRemove = useCallback(
    async (c: string) => {
      setRemoving(c);
      setError(null);
      allowlistWins.current.invalidate();
      try {
        await api.deleteTenantIPAllowlistEntry(c);
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRemoving(null);
      }
    },
    [api, refresh],
  );

  const twoFactor = twoFactorControlState(require2fa, busy, saving2fa);
  // Both forms PUT the whole policy, so neither may start while the other is saving (Codex bindmode r1).
  const limitControlsDisabled = sessionLimitControlsDisabled(savedLimit, savedMaxAge, savingLimit) || savingBinding;

  return (
    <section className="panel panel--security" data-testid="tenant-security">
      <TenantSSOSection api={api} />
      <RecordingPolicySection api={api} />
      <AdoptionSection api={api} />
      <form className="panel__form" onSubmit={(e) => void handleSaveLimit(e)} data-testid="session-limit-form">
        <span className="panel__toolbar-title">Concurrent sessions</span>
        <label className="panel__toolbar-field">
          Max open sessions (0 = unlimited)
          <input
            type="number"
            min={0}
            value={limitInput}
            onChange={(e) => setLimitInput(e.target.value)}
            placeholder="0"
            disabled={limitControlsDisabled}
            data-testid="session-limit-input"
          />
        </label>
        <label className="panel__toolbar-field">
          Max session duration (seconds, 0 = no maximum)
          <input
            type="number"
            min={0}
            value={maxAgeInput}
            onChange={(e) => setMaxAgeInput(e.target.value)}
            placeholder="0"
            disabled={limitControlsDisabled}
            data-testid="session-maxage-input"
          />
        </label>
        <label className="panel__toolbar-field">
          Default idle timeout (minutes, 0 = off)
          <input
            type="number"
            min={0}
            max={MAX_DEFAULT_IDLE_MINUTES}
            step="any"
            required
            value={idleInput}
            onChange={(e) => setIdleInput(e.target.value)}
            disabled={limitControlsDisabled}
            aria-describedby="session-default-idle-help"
            data-testid="session-default-idle-input"
          />
        </label>
        <span className="panel__toolbar-note" id="session-default-idle-help">
          Ends a session after this many minutes with no keyboard or mouse input from the technician. Applies to every machine group that has no idle timeout of its own.
        </span>
        <button className="panel__action" type="submit" disabled={limitControlsDisabled} data-testid="session-limit-save">
          {savingLimit ? "Saving…" : "Save"}
        </button>
        {savedLimit !== null && (
          <span className="panel__toolbar-note" data-testid="session-limit-current">
            {savedLimit === 0 ? "Currently unlimited" : `Currently limited to ${savedLimit}`}
          </span>
        )}
        {savedMaxAge !== null && (
          <span className="panel__toolbar-note" data-testid="session-maxage-current">
            {savedMaxAge === 0 ? "No session time limit" : `Sessions end after ${savedMaxAge}s`}
          </span>
        )}
        {limitError && (
          <span className="panel__toolbar-error" role="alert" data-testid="session-limit-error">
            {limitError}
          </span>
        )}
      </form>

      <div className="panel__form" data-testid="session-binding-section">
        <span className="panel__toolbar-title">Session verification</span>
        <label className="panel__toolbar-field panel__toolbar-field--inline">
          <input
            type="checkbox"
            checked={sessionBinding === "require"}
            disabled={sessionBinding === null || busy || savingBinding || limitControlsDisabled}
            onChange={(e) => void handleToggleBinding(e.target.checked)}
            data-testid="require-session-binding-checkbox"
          />
          Require verified sessions
        </label>
        <span className="panel__toolbar-note">
          {sessionBinding === "require"
            ? "A session whose machine cannot prove it is the enrolled machine is refused."
            : "Sessions that cannot be verified still connect, marked \u201cNot verified\u201d. Turn this on once every machine runs agent 1.3.31 or later."}
        </span>
      </div>

      <div className="panel__form" data-testid="2fa-policy-section">
        <span className="panel__toolbar-title">Two-factor authentication</span>
        <label className="panel__toolbar-field panel__toolbar-field--inline">
          <input
            type="checkbox"
            checked={twoFactor.checked}
            disabled={twoFactor.disabled}
            onChange={(e) => void handleToggle2fa(e.target.checked)}
            data-testid="require-2fa-checkbox"
          />
          Require TOTP 2FA for all tenant members
        </label>
        {twoFactor.note && (
          <span className="panel__toolbar-note" data-testid="2fa-policy-unknown">
            {twoFactor.note}
          </span>
        )}
        <span className="panel__toolbar-note">
          You must have TOTP enrolled yourself before enabling this requirement (anti-lockout).
        </span>
        {error2fa && (
          <span className="panel__toolbar-error" role="alert" data-testid="2fa-policy-error">
            {error2fa}
          </span>
        )}
      </div>

      <form className="panel__form" onSubmit={(e) => void handleAdd(e)}>
        <span className="panel__toolbar-title">IP allow-list</span>
        <label className="panel__toolbar-field">
          IP or CIDR
          <input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="203.0.113.0/24"
            data-testid="allowlist-cidr"
          />
        </label>
        <button className="panel__action" type="submit" disabled={saving} data-testid="allowlist-add">
          {saving ? "Adding…" : "Add"}
        </button>
        {yourIp && (
          <span className="panel__toolbar-note" data-testid="allowlist-your-ip">
            Your current IP: {yourIp}
          </span>
        )}
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="allowlist-error">
            {error}
          </span>
        )}
      </form>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Allowed source (CIDR)</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {cidrs.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={2} data-testid="allowlist-empty">
                {allowlistEmptyStateText(busy, error !== null)}
              </td>
            </tr>
          )}
          {cidrs.map((c) => (
            <tr key={c} data-testid={`allowlist-row-${c}`}>
              <td className="panel__mono">{c}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRemove(c)}
                  disabled={removing !== null}
                  data-testid={`allowlist-remove-${c}`}
                >
                  {removing === c ? "Removing…" : "Remove"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
