/**
 * Enrollment tokens (docs/01 §4/§6): mint + list + revoke the group-scoped bearer secrets an installer
 * redeems to enroll a NEW agent into the tenant, over GET/POST /enrollment-tokens and
 * POST /enrollment-tokens/{id}/revoke. The server gates on CapManageEnrollment for the target group.
 *
 * A token is minted FOR a machine group (the group new agents land in) with an optional expiry and a
 * redemption cap. The plaintext secret is shown exactly ONCE, right after minting, and cannot be
 * recovered afterward — the operator hands it to the agent installer (install-agent.ps1, docs/10).
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { ConsoleApi, EnrollmentToken, MachineGroup } from "../lib/console_api";
import { filterEnrollmentTokensByText } from "../lib/console_panels";
import { groupOptions, groupPaths, pathLabelFor } from "../lib/group_tree";
import { createLatestWins } from "../lib/latest_wins";
import { enrollmentTokensToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";
import { ManagedInstallDownload } from "./ManagedInstallDownload";

const SECONDS_PER_DAY = 86_400;

export interface EnrollmentTokensPanelProps {
  api: ConsoleApi;
}

export function EnrollmentTokensPanel({ api }: EnrollmentTokensPanelProps) {
  const [tokens, setTokens] = useState<readonly EnrollmentToken[]>([]);
  const [groups, setGroups] = useState<readonly MachineGroup[]>([]);
  // One tree helper for every group picker/label (docs/62): path labels, tree order, equal names never merge.
  const groupPathMap = useMemo(() => groupPaths(groups), [groups]);
  const groupPickerOptions = useMemo(() => groupOptions(groups), [groups]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [textQuery, setTextQuery] = useState("");
  const [groupId, setGroupId] = useState("");
  const [expiresInDays, setExpiresInDays] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  // The just-minted secret, shown ONCE. Null once dismissed.
  const [secret, setSecret] = useState<{ groupId: string; token: string } | null>(null);

  // Latest-wins guard: only the newest refresh may touch tokens/groups/error/busy, so a slower older
  // listing landing after a post-revoke re-list cannot make a revoked enrollment secret look active.
  // Invalidated on unmount.
  const listGuard = useRef(createLatestWins());
  useEffect(() => {
    const guard = listGuard.current;
    return () => guard.invalidate();
  }, []);

  const refresh = useCallback(async () => {
    const guard = listGuard.current;
    const token = guard.begin();
    setBusy(true);
    setError(null);
    try {
      // Load tokens and groups INDEPENDENTLY — a groups-load failure must not discard a successful token
      // load (or vice versa). Groups feed the mint PICKER and the by-name labels; tokens are the table.
      try {
        const list = await api.listEnrollmentTokens();
        if (!guard.isCurrent(token)) return; // superseded: a newer refresh owns the state
        setTokens(list);
      } catch (e) {
        if (!guard.isCurrent(token)) return; // a superseded failure must not show
        setError(e instanceof Error ? e.message : String(e));
      }
      try {
        const items = await api.listMachineGroups();
        if (!guard.isCurrent(token)) return;
        setGroups(items);
        setGroupId((current) => items.some((g) => g.id === current) ? current : items.length === 1 ? items[0].id : "");
      } catch (e) {
        if (!guard.isCurrent(token)) return;
        // Keep any token-load error; only surface the groups error if nothing failed yet.
        setError((prev) => prev ?? (e instanceof Error ? e.message : String(e)));
      }
    } finally {
      // Only the newest refresh clears busy (an older one finishing must not hide a newer load).
      if (guard.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleCreate = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const g = groupId.trim();
      if (g === "") {
        setError("select a machine group (create one under Machine groups if the list is empty)");
        return;
      }
      let ttlSeconds: number | undefined;
      if (expiresInDays.trim() !== "") {
        const days = Number(expiresInDays);
        if (!Number.isInteger(days) || days <= 0) {
          setError("expiry must be a positive whole number of days (blank = server default)");
          return;
        }
        ttlSeconds = days * SECONDS_PER_DAY;
      }
      let uses: number | undefined;
      if (maxUses.trim() !== "") {
        const n = Number(maxUses);
        if (!Number.isInteger(n) || n <= 0) {
          setError("max uses must be a positive whole number (blank = server default)");
          return;
        }
        uses = n;
      }
      setSaving(true);
      setError(null);
      try {
        const created = await api.createEnrollmentToken({ groupId: g, ttlSeconds, maxUses: uses });
        setSecret({ groupId: created.enrollmentToken.group_id, token: created.token });
        setGroupId("");
        setExpiresInDays("");
        setMaxUses("");
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, groupId, expiresInDays, maxUses, refresh],
  );

  const handleRevoke = useCallback(
    async (t: EnrollmentToken) => {
      setRemoving(t.id);
      setError(null);
      try {
        await api.revokeEnrollmentToken(t.id);
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRemoving(null);
      }
    },
    [api, refresh],
  );

  const filteredTokens = useMemo(
    () => filterEnrollmentTokensByText(tokens, textQuery),
    [tokens, textQuery],
  );

  const handleExport = useCallback(() => {
    saveBytesAsFile(
      "enrollment-tokens.csv",
      new TextEncoder().encode(enrollmentTokensToCsv(filteredTokens)),
    );
  }, [filteredTokens]);

  return (
    <section className="panel panel--enrollment" data-testid="enrollment-tokens">
      <div className="panel__form">
        <span className="panel__toolbar-title">Install a computer</span>
        <label className="panel__toolbar-field">
          Machine group
          <select
            value={groupId}
            onChange={(e) => setGroupId(e.target.value)}
            disabled={groups.length === 0}
            data-testid="enroll-group"
          >
            <option value="" disabled>
              {groups.length === 0 ? "No machine groups — create one first" : "Select a group…"}
            </option>
            {groupPickerOptions.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <ManagedInstallDownload api={api} groupId={groupId} />
      {error && <p className="panel__toolbar-error" role="alert" data-testid="enroll-error">{error}</p>}
      <details>
        <summary>Advanced: enrollment tokens</summary>
      <form className="panel__form" onSubmit={(e) => void handleCreate(e)}>
        <label className="panel__toolbar-field">
          Expires in days (blank = default)
          <input
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
            placeholder="7"
            inputMode="numeric"
            data-testid="enroll-expires"
          />
        </label>
        <label className="panel__toolbar-field">
          Max uses (blank = default)
          <input
            value={maxUses}
            onChange={(e) => setMaxUses(e.target.value)}
            placeholder="1"
            inputMode="numeric"
            data-testid="enroll-max-uses"
          />
        </label>
        <button className="panel__action" type="submit" disabled={saving} data-testid="enroll-create">
          {saving ? "Minting…" : "Mint token"}
        </button>
      </form>

      {secret && (
        <div className="panel__secret" role="alert" data-testid="enroll-secret">
          <span className="panel__toolbar-title">
            Copy this token now — it will not be shown again (group {pathLabelFor(groupPathMap, secret.groupId)})
          </span>
          <code className="panel__mono" data-testid="enroll-secret-value">
            {secret.token}
          </code>
          <span className="panel__toolbar-title">
            Put it in an MSI provisioning file for a silent install (Help → "Install agents silently").
          </span>
          <button className="panel__action" onClick={() => setSecret(null)} data-testid="enroll-secret-dismiss">
            Done
          </button>
        </div>
      )}

      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Tokens</span>
        <input
          type="search"
          className="panel__search"
          placeholder="Search group, status, ID…"
          aria-label="Search enrollment tokens"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="enrollment-tokens-search"
        />
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={filteredTokens.length === 0}
          data-testid="enrollment-tokens-export"
        >
          Export CSV
        </button>
      </div>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Group</th>
            <th>Expires</th>
            <th>Uses</th>
            <th>Status</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredTokens.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={5} data-testid="enroll-tokens-empty">
                {busy
                  ? "Loading…"
                  : textQuery.trim()
                    ? "No tokens match this search."
                    : "No enrollment tokens yet."}
              </td>
            </tr>
          )}
          {filteredTokens.map((t) => (
            <tr key={t.id} data-testid={`enroll-token-row-${t.id}`}>
              <td data-testid={`enroll-group-name-${t.id}`}>{pathLabelFor(groupPathMap, t.group_id)}</td>
              <td className="panel__mono">{t.expires_at ? t.expires_at.slice(0, 10) : "—"}</td>
              <td className="panel__mono">{`${t.uses} / ${t.max_uses}`}</td>
              <td data-testid={`enroll-status-${t.id}`}>{t.revoked ? "revoked" : "active"}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleRevoke(t)}
                  disabled={removing !== null || t.revoked}
                  data-testid={`enroll-revoke-${t.id}`}
                >
                  {removing === t.id ? "Revoking…" : "Revoke"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </details>
    </section>
  );
}
