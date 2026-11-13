/**
 * Tenant webhooks (docs/01 §8): register + list + delete HMAC-signed HTTP endpoints that receive
 * a POST for each management-plane audit event. Owner-only (the server gates on CapManageTenant).
 *
 * The webhook secret is generated server-side and returned ONCE in the creation response; there is
 * no way to retrieve it afterward. An empty events list means "subscribe to all events".
 *
 * The "Deliveries" button per row loads the last 50 delivery records (in-memory on the server,
 * ephemeral — cleared on restart) for that webhook, newest-first.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { ConsoleApi, TenantWebhook, WebhookDeliveryRecord } from "../lib/console_api";
import { createLatestWins, type LatestWins } from "../lib/latest_wins";
import { filterWebhooksByText, formatDeliveryTime } from "../lib/console_panels";
import { webhooksToCsv } from "../lib/report_csv";
import { saveBytesAsFile } from "./FileTransferPanel";

export interface WebhooksPanelProps {
  api: ConsoleApi;
}

export function WebhooksPanel({ api }: WebhooksPanelProps) {
  const [webhooks, setWebhooks] = useState<readonly TenantWebhook[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [eventsInput, setEventsInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  // The just-created secret, shown ONCE. Null once dismissed.
  const [secret, setSecret] = useState<{ url: string; secret: string } | null>(null);
  const [textQuery, setTextQuery] = useState("");
  // Delivery history: id of the webhook whose deliveries are currently visible; null = none.
  const [deliveriesFor, setDeliveriesFor] = useState<string | null>(null);
  // Null = still loading; [] = loaded (possibly empty); set on close or error.
  const [deliveries, setDeliveries] = useState<readonly WebhookDeliveryRecord[] | null>(null);
  const [deliveriesError, setDeliveriesError] = useState<string | null>(null);

  // Latest-wins ordering for the list: a slower OLDER listing (e.g. taken before a delete) must never
  // overwrite a newer one and resurrect a deleted endpoint. Deliveries have their own sequence.
  const listLatest = useRef<LatestWins>(createLatestWins());
  const deliveriesLatest = useRef<LatestWins>(createLatestWins());
  // Synchronous mirror of deliveriesFor so async continuations see the CURRENT selection, not a stale closure.
  const deliveriesForRef = useRef<string | null>(null);

  const closeDeliveries = useCallback(() => {
    deliveriesLatest.current.invalidate();
    deliveriesForRef.current = null;
    setDeliveriesFor(null);
    setDeliveries(null);
    setDeliveriesError(null);
  }, []);

  const refresh = useCallback(async () => {
    const token = listLatest.current.begin();
    setBusy(true);
    setError(null);
    try {
      const list = await api.listWebhooks();
      if (!listLatest.current.isCurrent(token)) return; // superseded: drop the outcome
      setWebhooks(list);
    } catch (e) {
      if (!listLatest.current.isCurrent(token)) return; // superseded: drop the error
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      // Only the newest request owns the loading indicator.
      if (listLatest.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const list = listLatest.current;
    const deliveriesSeq = deliveriesLatest.current;
    return () => {
      list.invalidate();
      deliveriesSeq.invalidate();
    };
  }, []);

  const handleCreate = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const u = url.trim();
      if (u === "") {
        setError("a URL is required");
        return;
      }
      if (!u.startsWith("https://")) {
        setError("webhook URL must start with https://");
        return;
      }
      // Parse comma-separated event names; empty input = subscribe to all events.
      const events = eventsInput
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      setSaving(true);
      setError(null);
      setSecret(null); // dismiss any prior secret so the new one replaces it without confusion
      try {
        const created = await api.createWebhook({ url: u, events });
        setSecret({ url: created.url, secret: created.secret });
        setUrl("");
        setEventsInput("");
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [api, url, eventsInput, refresh],
  );

  const filteredWebhooks = useMemo(
    () => filterWebhooksByText(webhooks, textQuery),
    [webhooks, textQuery],
  );

  const handleExport = useCallback(() => {
    saveBytesAsFile(
      "webhooks.csv",
      new TextEncoder().encode(webhooksToCsv(filteredWebhooks)),
    );
  }, [filteredWebhooks]);

  const handleDelete = useCallback(
    async (w: TenantWebhook) => {
      if (removing !== null) return;
      setRemoving(w.id);
      setError(null);
      try {
        await api.deleteWebhook(w.id);
        // Read the CURRENT selection (not the one captured at click time): only close the history if it
        // still belongs to the deleted webhook, so a selection made while the DELETE was in flight is
        // either closed (same id) or left untouched (another id).
        if (deliveriesForRef.current === w.id) closeDeliveries();
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRemoving(null);
      }
    },
    [api, refresh, removing, closeDeliveries],
  );

  const handleShowDeliveries = useCallback(
    async (webhookId: string) => {
      // Toggle: clicking the same webhook's button again closes the panel.
      if (deliveriesForRef.current === webhookId) {
        closeDeliveries();
        return;
      }
      const token = deliveriesLatest.current.begin();
      deliveriesForRef.current = webhookId;
      setDeliveriesFor(webhookId);
      setDeliveries(null);
      setDeliveriesError(null);
      try {
        const recs = await api.listWebhookDeliveries(webhookId);
        // Drop the outcome if a toggle, another webhook, a delete or unmount superseded this request.
        if (!deliveriesLatest.current.isCurrent(token)) return;
        setDeliveries(recs);
      } catch (e) {
        if (!deliveriesLatest.current.isCurrent(token)) return;
        setDeliveriesError(e instanceof Error ? e.message : String(e));
        setDeliveries([]);
      }
    },
    [api, closeDeliveries],
  );

  return (
    <section className="panel panel--webhooks" data-testid="webhooks">
      <form className="panel__form" onSubmit={(e) => void handleCreate(e)}>
        <span className="panel__toolbar-title">Webhooks</span>
        <label className="panel__toolbar-field">
          URL (https://)
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/hook"
            data-testid="webhook-url"
          />
        </label>
        <label className="panel__toolbar-field">
          Events (comma-separated, blank = all)
          <input
            value={eventsInput}
            onChange={(e) => setEventsInput(e.target.value)}
            placeholder="session.start, machine.enroll"
            data-testid="webhook-events"
          />
        </label>
        <button className="panel__action" type="submit" disabled={saving} data-testid="webhook-create">
          {saving ? "Registering…" : "Register"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="webhook-error">
            {error}
          </span>
        )}
      </form>

      {secret && (
        <div className="panel__secret" role="alert" data-testid="webhook-secret">
          <span className="panel__toolbar-title">
            Copy this secret now — it will not be shown again ({secret.url})
          </span>
          <code className="panel__mono" data-testid="webhook-secret-value">
            {secret.secret}
          </code>
          <button className="panel__action" onClick={() => setSecret(null)} data-testid="webhook-secret-dismiss">
            Done
          </button>
        </div>
      )}

      <div className="panel__toolbar">
        <input
          type="search"
          className="panel__search"
          placeholder="Search URL, ID, event…"
          aria-label="Search webhooks"
          value={textQuery}
          onChange={(e) => setTextQuery(e.target.value)}
          data-testid="webhooks-search"
        />
        <button
          className="panel__action"
          onClick={handleExport}
          disabled={filteredWebhooks.length === 0}
          data-testid="webhooks-export"
        >
          Export CSV
        </button>
      </div>

      <table className="panel__table">
        <thead>
          <tr>
            <th>URL</th>
            <th>Events</th>
            <th>Registered</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {filteredWebhooks.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={4} data-testid="webhooks-empty">
                {busy
                  ? "Loading…"
                  : textQuery.trim()
                    ? "No webhooks match this search."
                    : "No webhooks registered."}
              </td>
            </tr>
          )}
          {filteredWebhooks.map((w) => (
            <tr key={w.id} data-testid={`webhook-row-${w.id}`}>
              <td className="panel__mono">{w.url}</td>
              <td>{w.events.length === 0 ? "all events" : w.events.join(", ")}</td>
              <td className="panel__mono">{w.created_at.slice(0, 10)}</td>
              <td className="panel__col--action">
                <button
                  className="panel__action"
                  onClick={() => void handleShowDeliveries(w.id)}
                  data-testid={`webhook-deliveries-btn-${w.id}`}
                >
                  {deliveriesFor === w.id ? "Hide" : "Deliveries"}
                </button>
                <button
                  className="panel__action panel__action--danger"
                  onClick={() => void handleDelete(w)}
                  disabled={removing !== null}
                  data-testid={`webhook-delete-${w.id}`}
                >
                  {removing === w.id ? "Deleting…" : "Delete"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {deliveriesFor && (
        <div className="panel__deliveries" data-testid="webhook-deliveries-panel">
          <span className="panel__toolbar-title">
            Recent deliveries — {deliveriesFor.slice(0, 8)}…
          </span>
          {deliveries === null && !deliveriesError && (
            <span data-testid="webhook-deliveries-loading">Loading…</span>
          )}
          {deliveriesError && (
            <span className="panel__toolbar-error" role="alert" data-testid="webhook-deliveries-error">
              {deliveriesError}
            </span>
          )}
          {deliveries !== null && deliveries.length === 0 && (
            <span data-testid="webhook-deliveries-empty">No deliveries recorded yet (records are cleared on server restart).</span>
          )}
          {deliveries !== null && deliveries.length > 0 && (
            <table className="panel__table" data-testid="webhook-deliveries-table">
              <thead>
                <tr>
                  <th>Time (UTC)</th>
                  <th>Event</th>
                  <th>Attempt</th>
                  <th>Result</th>
                  <th>Status</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.map((d, i) => (
                  <tr key={i} data-testid={`delivery-row-${i}`}>
                    <td className="panel__mono">{formatDeliveryTime(d.attempted_at)}</td>
                    <td>{d.event}</td>
                    <td>{d.attempt}</td>
                    <td data-testid={`delivery-result-${i}`}>
                      {d.success ? "OK" : d.error || "failed"}
                    </td>
                    <td>{d.status_code > 0 ? d.status_code : "—"}</td>
                    <td>{d.duration_ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}
