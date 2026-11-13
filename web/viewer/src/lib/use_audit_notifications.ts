import { useCallback, useEffect, useRef, useState } from "react";
import type { ConsoleApi } from "./console_api";
import {
  type NotificationState,
  dismissNotification,
  emptyNotificationState,
  ingestAuditEvents,
  markAllSeen,
  newestInstantMs,
  primeNotificationState,
  unseenCount,
} from "./audit_notifications";

/**
 * Polls the management audit trail and maintains the operator-notification state (docs/01 §7 P1).
 * Thin glue: every rule lives in the pure {@link audit_notifications} model (unit-tested); this hook
 * schedules the fetch and threads the result through prime/ingest.
 *
 * BEST-EFFORT by design. This badge is a convenience that tells an operator "something notable
 * happened while you were on another panel"; the COMPLETE, authoritative record is the Audit panel
 * and the out-of-band webhooks. So each poll fetches a single most-recent page since the cursor: in
 * normal operation notable management-audit events are sparse and arrive well under one page per
 * interval, and in the rare event that more than a page occurs between two polls, the older ones are
 * not badged (they remain in the Audit trail). We do NOT page the whole gap, because the server orders
 * audit by an internal `seq` that the event payload does not expose, so a client cursor on occurred_at
 * cannot be made provably lossless — and a badge must not pretend to a completeness it cannot keep.
 *
 * Lifecycle (a review drove these): the effect is keyed on the signed-in IDENTITY, and a generation
 * token ({@link https://react.dev}) makes a superseded poll's late response a no-op, so one user's
 * notifications never leak into another's session and a reset cannot be raced by an in-flight fetch.
 * A failed poll is swallowed and retried next tick (like presence), and polls never overlap.
 */

export const DEFAULT_POLL_MS = 20_000;
/** Each poll fetches at most this many most-recent events since the cursor. */
export const AUDIT_FETCH_LIMIT = 50;

export interface AuditNotifications {
  state: NotificationState;
  /** Derived unseen count, for the badge. */
  unseen: number;
  /** Clear the unseen count (operator opened the panel). */
  markSeen: () => void;
  /** Remove one notification. */
  dismiss: (id: string) => void;
}

/**
 * The notification data bound to the identity it belongs to. Ownership lives INSIDE the state so every
 * functional update can check it atomically: a late poll from a previous identity, resolving after the
 * identity changed, finds `prev.identity` no longer its own and returns `prev` unchanged. A generation
 * check before enqueueing cannot bind an update to its owner — only this can — so this is what actually
 * prevents one user's events from landing in another user's (reset) state.
 */
interface OwnedState {
  identity: string | null;
  data: NotificationState;
}

/**
 * @param api      the authenticated console client (stable; may be null before it exists).
 * @param identity the signed-in user identity (e.g. email), or null when signed out. Polling runs
 *                 only while non-null, and a CHANGE of identity resets the state — so a re-login as a
 *                 different user starts from a clean baseline on the same console.
 */
export function useAuditNotifications(
  api: ConsoleApi | null,
  identity: string | null,
  pollMs: number = DEFAULT_POLL_MS,
): AuditNotifications {
  const [owned, setOwned] = useState<OwnedState>(() => ({ identity, data: emptyNotificationState() }));
  const genRef = useRef(0);

  // Reset DURING render when the identity changes, so a previous user's notifications are never
  // rendered — not even for a single frame — under a new identity. React discards this render pass and
  // re-runs with the empty, rebound state. Guarded by the inequality so it cannot loop.
  if (owned.identity !== identity) {
    setOwned({ identity, data: emptyNotificationState() });
  }

  useEffect(() => {
    if (!api || identity == null) return;
    const gen = ++genRef.current; // this effect generation's token
    const owner = identity; // the identity this generation's polls belong to
    let primed = false; // generation-local fetch strategy
    let cursorMs = 0;
    let inFlight = false;

    const tick = async () => {
      if (inFlight) return; // never overlap polls within a generation
      inFlight = true;
      try {
        const sinceIso = primed && cursorMs > 0 ? new Date(cursorMs).toISOString() : undefined;
        const events = await api.listAudit(AUDIT_FETCH_LIMIT, sinceIso ? { since: sinceIso } : undefined);
        if (genRef.current !== gen) return; // superseded generation: drop the response
        cursorMs = Math.max(cursorMs, newestInstantMs(events));
        primed = true;
        setOwned((prev) => {
          // Authoritative, race-free ownership check: atomic with the state transition. If the identity
          // changed between this poll's start and now, the data is not ours — leave it untouched.
          if (prev.identity !== owner) return prev;
          const data = prev.data.primed ? ingestAuditEvents(prev.data, events) : primeNotificationState(prev.data, events);
          return { identity: prev.identity, data };
        });
      } catch {
        // Best-effort: ignore and retry next tick.
      } finally {
        inFlight = false;
      }
    };

    void tick();
    const timer = window.setInterval(() => void tick(), pollMs);
    return () => {
      genRef.current++; // invalidate any in-flight poll from this generation
      window.clearInterval(timer);
    };
  }, [api, identity, pollMs]);

  const markSeen = useCallback(() => setOwned((prev) => ({ identity: prev.identity, data: markAllSeen(prev.data) })), []);
  const dismiss = useCallback((id: string) => setOwned((prev) => ({ identity: prev.identity, data: dismissNotification(prev.data, id) })), []);
  return { state: owned.data, unseen: unseenCount(owned.data), markSeen, dismiss };
}
