/**
 * One connect rule for every machine list (menu redesign wave 3, Codex menu review 2026-11-07). The sidebar and the Machines page
 * used to disagree:
 *   - the sidebar never disabled Connect for a believed-offline machine (deliberately: presence is a cached, possibly wrong
 *     estimate, and the session attempt itself is the authoritative test), while the Machines page disabled it;
 *   - the Machines page refused an out-of-service machine, while the sidebar offered Connect on it;
 *   - one said "Active" on the button, the other "active" on a badge, and the view-only action was "Observe".
 *
 * The rule now:
 *   - Connect is disabled ONLY for a machine that is out of service (status other than "active"; an absent status is active).
 *     The server refuses those anyway, and saying so up front is honest. Presence never disables it: an offline or unknown
 *     machine keeps Connect, with the reason shown.
 *   - The machine this console is already viewing says "Return to session".
 *   - A machine with an open session carries an "In session" badge.
 *   - The view-only action is "View only".
 */

export interface ConnectInput {
  /** `undefined` = presence unknown (not offline). */
  online: boolean | undefined;
  /** Machine status from the control plane ("active", "quarantined", "retired", "removed"); absent = active. */
  status?: string;
  /** This console is already viewing this machine. */
  current: boolean;
}

export interface ConnectState {
  enabled: boolean;
  label: string;
  /** Tooltip and, where the surface has room, the visible reason line. */
  hint: string;
}

export const IN_SESSION_LABEL = "In session";
export const VIEW_ONLY_LABEL = "View only";

/** Whether the machine is in service: an absent status is active. */
export function inService(status?: string): boolean {
  return (status ?? "active") === "active";
}

export function connectState(m: ConnectInput): ConnectState {
  if (!inService(m.status)) {
    return { enabled: false, label: "Connect", hint: `Out of service (${m.status}): new remote sessions are refused` };
  }
  if (m.current) return { enabled: true, label: "Return to session", hint: "You are viewing this machine" };
  if (m.online === undefined) return { enabled: true, label: "Connect", hint: "Presence is unavailable — connecting will try anyway" };
  if (m.online) return { enabled: true, label: "Connect", hint: "Connect to this machine" };
  return { enabled: true, label: "Connect", hint: "This machine looked offline at the last check — connecting will try anyway" };
}
