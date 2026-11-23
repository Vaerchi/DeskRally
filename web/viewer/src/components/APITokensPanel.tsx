/**
 * API tokens (docs/01 §8): mint + list + revoke tenant-admin bearer credentials for programmatic
 * access, over GET/POST/DELETE /api-tokens. Owner-only (the server gates on CapManageTenant).
 *
 * A token carries an explicit capability SUBSET, chosen with the checkboxes below. The offered set
 * MIRRORS apiTokenGrantableCaps in control-plane/apitoken.go — fleet management + reporting only;
 * the server rejects anything outside it, so this list can never silently over-grant. The plaintext
 * secret is shown exactly ONCE, right after minting; there is no way to recover it afterward.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { APIToken, ConsoleApi } from "../lib/console_api";
import { filterAPITokensByText } from "../lib/console_panels";
import { createLatestWins } from "../lib/latest_wins";
import { apiTokensToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";

// The capabilities an API token may carry — mirrors control-plane/apitoken.go's apiTokenGrantableCaps.
const GRANTABLE_CAPS: readonly { key: string; label: string }[] = [
  { key: "view_machines", label: "View machines" },
  { key: "manage_machines", label: "Manage machines" },
  { key: "manage_groups", label: "Manage groups" },
  { key: "view_sessions", label: "View sessions" },
  { key: "view_audit", label: "View audit trail" },
];

export interface APITokensPanelProps {
  api: ConsoleApi;
}

export function APITokensPanel({ api }: APITokensPanelProps) {
  const [tokens, setTokens] = useState<readonly APIToken[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [caps, setCaps] = useState<readonly string[]>([]);
  const [expiresInDays, setExpiresInDays] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  // The just-minted secret, shown ONCE. Null once dismissed.
  const [secret, setSecret] = useState<{ name: string; token: string } | null>(null);
  const [textQuery, setTextQuery] = useState("");

  // Latest-wins guard: only the newest listing may touch tokens/error/busy, so a slower older list landing
  // after a post-revoke re-list cannot make a revoked credential look active. Invalidated on unmount.
  const listGuard = useRef(createLatestWins());
  useEffect(() => {
    const guard = listGuard.current;
    return () => guard.invalidate();
  }, []);

  const refresh = useCallback(async () => {
    const token = listGuard.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = await api.listAPITokens();
      if (!listGuard.current.isCurrent(token)) return; // superseded: a newer listing owns the state
      setTokens(list);
    } catch (e) {
      if (!listGuard.current.isCurrent(token)) return; // a superseded failure must not show
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      // Only the newest listing clears busy (an older one finishing must not hide a newer load).
      if (listGuard.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const toggleCap = useCallback((key: string) => {
    setCaps((prev) => (prev.includes(key) ? prev.filter((c) => c !== key) : [...prev, key]));
  }, []);

  const handleCreate = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const n = name.trim();
      if (n === "") {
        setError("a token needs a name");
        return;
      }
      if (caps.length === 0) {
        setError("select at least one capability");
        return;
      }
      const days = expiresInDays.trim() === "" ? undefined : Number(expiresInDays);
      if (days !== undefined && (!Number.isInteger(days) || days < 0)) {
        setError("expiry must be a whole number of days (blank = never)");
        return;
      }
      setSaving(true);
      setError(null);
      try {
        const created = await api.createAPIToken({ name: n, capabilities: [...caps], expiresInDays: days });
        setSecret({ name: created.apiToken.name, token: created.token });
        setName("");
        setCaps([]);
        setExpiresInDays("");
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, name, caps, expiresInDays, refresh],
  );

  const filteredTokens = useMemo(
    () => filterAPITokensByText(tokens, textQuery),
    [tokens, textQuery],
  );

  const handleExport = useCallback(() => {
    saveBytesAsFile(
      "api-tokens.csv",
      new TextEncoder().encode(apiTokensToCsv(filteredTokens)),
    );
  }, [filteredTokens]);

  const handleRevoke = useCallback(
    async (t: APIToken) => {
      setRemoving(t.id);
      setError(null);
      try {
        await api.revokeAPIToken(t.id);
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRemoving(null);
      }
    },
    [api, refresh],
  );

  return (
    <section className="panel panel--apitokens" data-testid="api-tokens">
      <form className="panel__form" onSubmit={(e) => void handleCreate(e)}>
        <span className="panel__toolbar-title">API tokens</span>
        <label className="panel__toolbar-field">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-bot" data-testid="token-name" />
        </label>
        <fieldset className="panel__toolbar-field panel__caps" data-testid="token-caps">
          <legend>Capabilities</legend>
          {GRANTABLE_CAPS.map((c) => (
            <label key={c.key} className="panel__cap">
              <input
                type="checkbox"
                checked={caps.includes(c.key)}
                onChange={() => toggleCap(c.key)}
                data-testid={`token-cap-${c.key}`}
              />
              {c.label}
            </label>
          ))}
        </fieldset>
        <label className="panel__toolbar-field">
          Expires in days (blank = never)
          <input
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
            placeholder="90"
            inputMode="numeric"
            data-testid="token-expires"
          />
        </label>
        <button className="panel__action" type="submit" disabled={saving} data-testid="token-create">
          {saving ? "Minting…" : "Mint token"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="token-error">
            {error}
          </span>
        )}
      </form>

      {secret && (
        <div className="panel__secret" role="alert" data-testid="token-secret">
          <span className="panel__toolbar-title">
            Copy this token now — it will not be shown again ({secret.name})
          </span>
          <code className="panel__mono" data-testid="token-secret-value">
            {secret.token}
          </code>
          <button className="panel__action" onClick={() => setSecret(null)} data-testid="token-secret-dismiss">
            Done
          </button>
        </div>
      )}

      <div className="panel__toolbar">
        <input
          type="search"
          className="panel__search"
          placeholder="Search name, ID, capability, status…"
          aria-label="Search API tokens"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="api-tokens-search"
        />
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={filteredTokens.length === 0}
          data-testid="api-tokens-export"
        >
          Export CSV
        </button>
      </div>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Capabilities</th>
            <th>Expires</th>
            <th>Status</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredTokens.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={5} data-testid="tokens-empty">
                {busy
                  ? "Loading…"
                  : textQuery.trim()
                    ? "No tokens match this search."
                    : "No API tokens yet."}
              </td>
            </tr>
          )}
          {filteredTokens.map((t) => (
            <tr key={t.id} data-testid={`token-row-${t.name}`}>
              <td className="panel__name">{t.name}</td>
              <td className="panel__mono">{t.capabilities.join(", ")}</td>
              <td className="panel__mono">{t.expires_at ? t.expires_at.slice(0, 10) : "never"}</td>
              <td data-testid={`token-status-${t.name}`}>{t.revoked_at ? "revoked" : "active"}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRevoke(t)}
                  disabled={removing !== null || t.revoked_at != null}
                  data-testid={`token-revoke-${t.name}`}
                >
                  {removing === t.id ? "Revoking…" : "Revoke"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
