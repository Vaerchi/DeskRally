import { useState } from "react";
import type { HelpRequest } from "../lib/console_api";
import { blockedByUnresolvedMessage, helpBellView, type UnresolvedAccept } from "../lib/help_requests";

/**
 * The "Help requests" control (docs/64): a badge + list of OPEN guest help requests this user may act on.
 * It is deliberately NOT the audit bell: the bell is a tenant-wide, best-effort history; this is a queue of
 * work that expires and can be taken by one technician. Display rules live in the pure
 * {@link helpBellView} (unit-tested); this component only renders them.
 *
 * The note is the guest machine's own text: a React text node, never HTML, always under its label.
 * An offline machine shows no Accept button. A refusal (409: someone else took it, it expired, the
 * machine is offline, a seat cap...) is shown with the server's own words.
 */

export interface HelpRequestsBellProps {
  requests: HelpRequest[];
  /** The request being accepted, and what is happening to it. */
  accepting: { id: string; status: string } | null;
  /** The last accept failure for a request, verbatim from the server. */
  error: { id: string; message: string } | null;
  /** An accept whose outcome is unknown (lost response / transient failure): shown with Retry. */
  unresolved?: UnresolvedAccept | null;
  /** Retry the unresolved accept with its retained request id and idempotency key. */
  onRetry?: () => void;
  onAccept: (request: HelpRequest) => void;
  onClearError: () => void;
  /** Called when the list is opened, so the caller can refresh it straight away. */
  onOpen?: () => void;
}

export function HelpRequestsBell({ requests, accepting, error, unresolved = null, onRetry, onAccept, onClearError, onOpen }: HelpRequestsBellProps) {
  const [open, setOpen] = useState(false);
  const view = helpBellView(requests, unresolved ? 1 : 0);
  // A failure keeps the control visible even when the queue just emptied (someone else took it): the
  // technician must see WHY their click did nothing.
  if (view.empty && !open && !error && !accepting && !unresolved) return null;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) onOpen?.();
  };

  return (
    <div className="app__notifications app__helprequests" data-testid="help-requests">
      <button
        type="button"
        className="app__notifications-bell"
        data-testid="help-requests-button"
        aria-label={view.label}
        aria-expanded={open}
        onClick={toggle}
      >
        <span aria-hidden="true">🙋</span>
        {view.badge && (
          <span className="app__notifications-badge" data-testid="help-requests-badge">{view.badge}</span>
        )}
      </button>
      {open && (
        <div className="app__notifications-panel" role="region" aria-label="Help requests" data-testid="help-requests-panel">
          {error && (
            <p role="alert" className="panel__toolbar-error" data-testid="help-requests-error">
              {error.message} <button type="button" className="panel__action" onClick={onClearError}>OK</button>
            </p>
          )}
          {accepting && <p role="status" aria-live="polite" data-testid="help-requests-status">{accepting.status}</p>}
          {unresolved && (
            <p role="alert" className="panel__toolbar-error" data-testid="help-requests-unresolved">
              Not confirmed: accepting {unresolved.request.machine_alias || unresolved.request.machine_name}. {unresolved.message}{" "}
              <button type="button" className="panel__action" data-testid="help-requests-retry" disabled={accepting !== null} onClick={() => onRetry?.()}>
                Retry
              </button>
            </p>
          )}
          {unresolved && view.rows.some((r) => r.id !== unresolved.request.id) && (
            <p className="panel__hint" data-testid="help-requests-blocked">
              Other requests wait until the pending accept above is retried and resolved.
            </p>
          )}
          {view.empty ? (
            <p className="app__notifications-empty" data-testid="help-requests-empty">No one is asking for help right now.</p>
          ) : (
            <ul className="app__notifications-list">
              {view.rows.map((row) => (
                <li key={row.id} className="app__notifications-item" data-testid={`help-request-${row.id}`}>
                  <span className="app__notifications-item-title">
                    {row.title}
                    {row.subtitle && <span className="panel__hint"> ({row.subtitle})</span>}
                  </span>
                  {row.note && (
                    <span className="app__notifications-item-target" data-testid={`help-request-note-${row.id}`}>
                      <span className="panel__hint">{row.noteLabel}: </span>
                      <q>{row.note}</q>
                    </span>
                  )}
                  <time className="app__notifications-item-time" dateTime={row.createdAt}>{row.createdAt}</time>
                  {row.offline ? (
                    <span className="panel__hint" data-testid={`help-request-offline-${row.id}`}>Offline: nothing to connect to</span>
                  ) : (
                    <button
                      type="button"
                      className="panel__action"
                      data-testid={`help-request-accept-${row.id}`}
                      disabled={accepting !== null || !row.canAccept || (unresolved !== null && unresolved.request.id !== row.id)}
                      title={unresolved && unresolved.request.id !== row.id ? blockedByUnresolvedMessage(unresolved) : undefined}
                      onClick={() => { const r = requests.find((q) => q.id === row.id); if (r) onAccept(r); }}
                    >
                      Accept
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
