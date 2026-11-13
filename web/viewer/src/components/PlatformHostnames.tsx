/**
 * Platform operator: a tenant's hostnames (docs/66 2a.10, 2h, 2k): the assignment HISTORY with each row's state
 * (pending, active, released, quarantined until <date>), and assign, activate, release and reactivate, each
 * confirmed in plain words that say what it does to guests.
 *
 * Changes go through the Platform panel's single-flight operation (`start`): the second-factor check and the one
 * retry after a lapsed window are the panel's, as for suspend and resume. The server decides everything (look-alike
 * warnings, quarantine, one live host per tenant); this screen only offers what it will accept and shows its
 * refusals. A 409 with look-alike warnings turns the confirmation into an acknowledge-and-give-a-reason form.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { ConsoleApi, HostnameAssignment, PlatformFinding } from "../lib/console_api";
import { assignWarnings, hostnameActionEffect, hostnameActions, hostnameStatusLabel, reasonOk, type HostnameAction } from "../lib/platform_branding";

export interface PlatformHostnamesProps {
  api: ConsoleApi;
  tenant: { id: string; slug: string; name: string };
  frozen: boolean;
  start: (run: (live: () => boolean) => Promise<void>, fail: (e: unknown) => void) => boolean;
  onClose: () => void;
}

interface Pending {
  kind: HostnameAction | "assign";
  /** The row acted on (not for assign). */
  row?: HostnameAssignment;
  /** The host typed for an assign. */
  host: string;
}

export function PlatformHostnames({ api, tenant, frozen, start, onClose }: PlatformHostnamesProps) {
  const [rows, setRows] = useState<readonly HostnameAssignment[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [newHost, setNewHost] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [reason, setReason] = useState(""); // a release reason, or the look-alike override reason
  const [activateNow, setActivateNow] = useState(false);
  const [warnings, setWarnings] = useState<readonly PlatformFinding[] | null>(null);
  const [acked, setAcked] = useState<ReadonlySet<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const mounted = useRef(true);
  const loadSeq = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    setLoadError(null);
    try {
      const list = await api.listTenantHostnames(tenant.id);
      if (!mounted.current || seq !== loadSeq.current) return;
      setRows(list);
    } catch (e) {
      if (!mounted.current || seq !== loadSeq.current) return;
      setLoadError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mounted.current && seq === loadSeq.current) setLoading(false);
    }
  }, [api, tenant.id]);

  useEffect(() => {
    void load();
  }, [load]);

  const open = (p: Pending) => {
    if (frozen) return;
    setPending(p);
    setReason("");
    setActivateNow(false);
    setWarnings(null);
    setAcked(new Set());
    setError(null);
    setNotice(null);
  };

  const needsReason = pending?.kind === "release" || (warnings !== null && warnings.length > 0);
  const allAcked = warnings === null || warnings.every((w) => acked.has(w.code));
  const confirmOk = pending !== null && !frozen && (!needsReason || reasonOk(reason)) && allAcked;

  const confirm = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pending || !confirmOk) return; // enforced here, not only by the disabled button
    const p = pending;
    const why = reason.trim();
    const codes = warnings ? warnings.map((w) => w.code) : [];
    const wasActivate = activateNow;
    setError(null);
    start(
      async (live) => {
        let done: string;
        if (p.kind === "assign") {
          await api.assignHostname(tenant.id, p.host, codes, codes.length > 0 ? why : "");
          done = `Assigned ${p.host} (pending). Activate it when the tenant is ready.`;
        } else if (p.kind === "activate") {
          await api.activateHostname(p.row!.id);
          done = `${p.row!.host} is active.`;
        } else if (p.kind === "release") {
          await api.releaseHostname(p.row!.id, why);
          done = `Released ${p.row!.host}; it is quarantined.`;
        } else {
          await api.reactivateHostname(p.row!.id, wasActivate);
          done = `Created a new ${wasActivate ? "active" : "pending"} assignment of ${p.row!.host}. Approve its branding again.`;
        }
        if (!live()) return;
        setPending(null);
        setWarnings(null);
        if (p.kind === "assign") setNewHost("");
        setNotice(done);
        await load();
      },
      (err) => {
        if (!mounted.current) return;
        const w = p.kind === "assign" ? assignWarnings(err) : null;
        if (w) {
          setWarnings(w);
          setAcked(new Set());
          setError("The name looks like another name. Acknowledge every warning and give a reason to assign it anyway.");
        } else {
          setError(err instanceof Error ? err.message : String(err));
        }
      },
    );
  };

  const now = new Date();
  const list = rows ?? [];

  return (
    <section className="panel__form platform-hostnames" aria-label={`Hostnames: ${tenant.name}`} data-testid="hostnames-root">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">
          Hostnames: {tenant.name} ({tenant.slug})
        </span>
        <button className="panel__action" onClick={() => void load()} disabled={loading || frozen}>
          {loading ? "Loading…" : "Refresh"}
        </button>
        <button className="panel__action" onClick={onClose} disabled={frozen} data-testid="hostnames-close">
          Close
        </button>
        {loadError && (
          <span className="panel__toolbar-error" role="alert" data-testid="hostnames-load-error">
            {loadError}
          </span>
        )}
      </div>

      <form
        className="panel__form"
        aria-label="Assign a hostname"
        onSubmit={(e) => {
          e.preventDefault();
          const host = newHost.trim();
          if (host !== "") open({ kind: "assign", host });
        }}
      >
        <label className="panel__toolbar-field">
          New hostname
          <input
            value={newHost}
            onChange={(e) => setNewHost(e.target.value)}
            placeholder="acme.example.com"
            autoComplete="off"
            spellCheck={false}
            disabled={frozen}
            data-testid="hostname-assign-host"
          />
        </label>
        <button className="panel__action" type="submit" disabled={frozen || newHost.trim() === ""} data-testid="hostname-assign-open">
          Assign…
        </button>
      </form>

      {pending && (
        <form className="panel__form" onSubmit={confirm} aria-label="Confirm hostname change" data-testid="hostname-confirm">
          <span className="panel__toolbar-title">
            {pending.kind === "assign" ? "Assign" : pending.kind === "activate" ? "Activate" : pending.kind === "release" ? "Release" : "Reactivate"}{" "}
            <code dir="ltr">{pending.row?.host ?? pending.host}</code>
          </span>
          <span data-testid="hostname-confirm-effect">{hostnameActionEffect(pending.kind, pending.row?.host ?? pending.host, tenant.name)}</span>
          {pending.kind === "reactivate" && (
            <label>
              <input type="checkbox" checked={activateNow} onChange={(e) => setActivateNow(e.target.checked)} disabled={frozen} data-testid="hostname-confirm-activate" />{" "}
              Make it active immediately (otherwise it is pending until activated)
            </label>
          )}
          {warnings && warnings.length > 0 && (
            <fieldset data-testid="hostname-warnings">
              <legend>Look-alike warnings</legend>
              {warnings.map((w) => (
                <label key={w.code} className="platform-review__finding">
                  <input
                    type="checkbox"
                    checked={acked.has(w.code)}
                    disabled={frozen}
                    onChange={(e) =>
                      setAcked((cur) => {
                        const next = new Set(cur);
                        if (e.target.checked) next.add(w.code);
                        else next.delete(w.code);
                        return next;
                      })
                    }
                    data-testid={`hostname-warn-ack-${w.code}`}
                  />{" "}
                  <strong>{w.code}</strong>: {w.message}
                </label>
              ))}
            </fieldset>
          )}
          {needsReason && (
            <label className="panel__toolbar-field">
              {pending.kind === "release" ? "Reason" : "Override reason (recorded in the audit log)"}
              <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} disabled={frozen} data-testid="hostname-confirm-reason" />
            </label>
          )}
          <button className="panel__action" type="submit" disabled={!confirmOk} data-testid="hostname-confirm-submit">
            {pending.kind === "assign" ? "Assign hostname" : pending.kind === "activate" ? "Activate hostname" : pending.kind === "release" ? "Release hostname" : "Reactivate hostname"}
          </button>
          <button className="panel__action" type="button" onClick={() => setPending(null)} disabled={frozen}>
            Cancel
          </button>
        </form>
      )}

      {error && (
        <span className="panel__toolbar-error" role="alert" data-testid="hostname-error">
          {error}
        </span>
      )}
      {notice && (
        <span role="status" data-testid="hostname-notice">
          {notice}
        </span>
      )}

      <table className="panel__table" aria-label="Hostname history">
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Status</th>
            <th>Created (UTC)</th>
            <th>Activated (UTC)</th>
            <th>Released (UTC)</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {list.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={6}>
                {loading ? "Loading…" : "No hostname has been assigned to this tenant."}
              </td>
            </tr>
          )}
          {list.map((a) => (
            <tr key={a.id} data-testid={`hostname-row-${a.id}`}>
              <td className="panel__mono">{a.host}</td>
              <td>
                <span className="panel__badge" data-tone={a.state === "active" ? "good" : a.state === "pending" ? "pending" : "bad"} data-testid={`hostname-status-${a.id}`}>
                  {hostnameStatusLabel(a, now)}
                </span>
              </td>
              <td className="panel__mono">{formatIsoUtc(a.created_at)}</td>
              <td className="panel__mono">{formatIsoUtc(a.activated_at)}</td>
              <td className="panel__mono">{formatIsoUtc(a.released_at)}</td>
              <td>
                {hostnameActions(a, list).map((act) => (
                  <button
                    key={act}
                    className="panel__action"
                    onClick={() => open({ kind: act, row: a, host: a.host })}
                    disabled={frozen}
                    data-testid={`hostname-act-${act}-${a.id}`}
                  >
                    {act === "activate" ? "Activate…" : act === "release" ? "Release…" : "Reactivate…"}
                  </button>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
