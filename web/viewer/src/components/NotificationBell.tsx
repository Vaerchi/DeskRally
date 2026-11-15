import { useState } from "react";
import { type AuditNotification, type NotificationSeverity, type NotificationState, unseenCount } from "../lib/audit_notifications";

/**
 * The console notification bell (docs/01 §7 P1 operator notifications). It renders from the pure
 * {@link NotificationState} the polling hook maintains. All display logic lives in the exported pure
 * helpers below so it is unit-tested without rendering, matching this codebase's component-test style
 * (see AuditPanel.test.ts).
 */

/** A human phrase for a notable audit action; falls back to the raw action for anything unmapped. */
export function notificationTitle(action: string): string {
  switch (action) {
    case "session.start": return "Session started";
    case "attended.create": return "Support session created";
    case "attended.connect": return "Technician joined a support session";
    case "machine.enroll": return "Machine enrolled";
    case "help.requested": return "A machine asked for help";
    case "help.accepted": return "A help request was taken";
    case "api_token.mint": return "API token created";
    case "enrollment_token.mint": return "Enrollment token created";
    case "grant.mint": return "Under the Hood access granted";
    case "session.elevation_minted": return "Admin elevation granted";
    case "tenant.security_policy.set": return "Security policy changed";
    case "tenant.session_policy.set": return "Session policy changed";
    case "machine_group.session_policy.set": return "Group session policy changed";
    case "tenant.ip_allowlist.add": return "IP allow-list entry added";
    case "tenant.ip_allowlist.remove": return "IP allow-list entry removed";
    case "tenant.sso_update": return "SSO configuration changed";
    default: return action;
  }
}

/** The badge text: null when nothing is unseen, the count up to 99, then "99+". */
export function notificationBadge(unseen: number): string | null {
  if (unseen <= 0) return null;
  return unseen > 99 ? "99+" : String(unseen);
}

export interface NotificationItemView {
  id: string;
  title: string;
  severity: NotificationSeverity;
  occurredAt: string;
  /** "target_kind target_id" when both are present, else whichever exists, else "". */
  target: string;
}

export interface NotificationBellView {
  /** Badge text, or null to hide the badge. */
  badge: string | null;
  /** Accessible button label describing the unseen count. */
  label: string;
  /** True when there is no history to show in the panel. */
  empty: boolean;
  items: NotificationItemView[];
}

function itemView(n: AuditNotification): NotificationItemView {
  const target = [n.targetKind, n.targetId].filter((s) => s && s.trim() !== "").join(" ");
  return { id: n.id, title: notificationTitle(n.action), severity: n.severity, occurredAt: n.occurredAt, target };
}

/** Pure view model for the bell — everything the component needs to render, derived from state. */
export function notificationBellView(state: NotificationState): NotificationBellView {
  const unseen = unseenCount(state);
  const badge = notificationBadge(unseen);
  const label = unseen <= 0 ? "Notifications" : `Notifications, ${unseen} unread`;
  return { badge, label, empty: state.items.length === 0, items: state.items.map(itemView) };
}

export interface NotificationBellProps {
  state: NotificationState;
  /** Called when the panel is opened, so the hook can clear the unseen count. */
  onOpen: () => void;
  /** Called when the operator dismisses one notification. */
  onDismiss: (id: string) => void;
}

export function NotificationBell({ state, onOpen, onDismiss }: NotificationBellProps) {
  const [open, setOpen] = useState(false);
  const view = notificationBellView(state);

  // Side effect (mark-seen) stays OUT of the state updater: the updater must be pure, and calling
  // onOpen inside it would fire twice under React StrictMode's double-invoke.
  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) onOpen();
  };

  return (
    <div className="app__notifications" data-testid="notifications">
      <button
        type="button"
        className="app__notifications-bell"
        data-testid="notifications-bell"
        aria-label={view.label}
        aria-expanded={open}
        onClick={toggle}
      >
        <span aria-hidden="true">🔔</span>
        {view.badge && (
          <span className="app__notifications-badge" data-testid="notifications-badge">{view.badge}</span>
        )}
      </button>
      {open && (
        <div className="app__notifications-panel" role="region" aria-label="Notifications" data-testid="notifications-panel">
          {view.empty ? (
            <p className="app__notifications-empty" data-testid="notifications-empty">No recent activity.</p>
          ) : (
            <ul className="app__notifications-list">
              {view.items.map((it) => (
                <li key={it.id} className="app__notifications-item" data-severity={it.severity} data-testid="notifications-item">
                  <span className="app__notifications-item-title">{it.title}</span>
                  {it.target && <span className="app__notifications-item-target">{it.target}</span>}
                  <time className="app__notifications-item-time" dateTime={it.occurredAt}>{it.occurredAt}</time>
                  <button
                    type="button"
                    className="app__notifications-dismiss"
                    aria-label={`Dismiss ${it.title}`}
                    onClick={() => onDismiss(it.id)}
                  >
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
