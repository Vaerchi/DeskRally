/**
 * docs/53: "Request admin rights" in an attended session, as the viewer models it.
 *
 * The agent advertises once whether the session can ask (`AdminRightsAvailable`), and reports each
 * request's progress (`AdminRightsResult`). This module is the pure state and the view rules; the
 * component (`AdminRightsControl`) only renders them, and `App.tsx` only wires the control channel.
 */
import type { AdminRightsState } from "./control";

export interface AdminRightsModel {
  /** `null` until the agent advertises (an older agent never does: no button). */
  available: boolean | null;
  /** Why not, when the agent said it cannot. */
  unavailableReason: string | null;
  /** The latest request's state, `null` before any request. */
  state: AdminRightsState | null;
  /** The latest result's reason (for `unavailable`). */
  detail: string | null;
}

export const NO_ADMIN_RIGHTS: AdminRightsModel = { available: null, unavailableReason: null, state: null, detail: null };

export function adminRightsAdvertised(m: AdminRightsModel, available: boolean, reason: string | null): AdminRightsModel {
  return { ...m, available, unavailableReason: available ? null : reason };
}

export function adminRightsResult(m: AdminRightsModel, state: AdminRightsState, reason: string | null): AdminRightsModel {
  return { ...m, state, detail: reason };
}

/** The click, before the agent's `pending` arrives: blocks a second click at once. */
export function adminRightsRequested(m: AdminRightsModel): AdminRightsModel {
  return { ...m, state: "pending", detail: null };
}

export interface AdminRightsView {
  /** Render the control at all. */
  show: boolean;
  /** The button is enabled. */
  canRequest: boolean;
  /** Why the button is disabled, for its tooltip. */
  disabledReason: string | null;
  /** The status line, or `null` for none. */
  status: string | null;
  /** The standing hint about Windows' own prompts. */
  hint: string | null;
}

const HINT = "Windows security prompts appear only on the guest's screen; ask the guest to answer them.";

function statusText(state: AdminRightsState | null, detail: string | null): string | null {
  switch (state) {
    case null:
      return null;
    case "pending":
      return "Waiting for the guest to approve…";
    case "granted":
      return "Admin rights granted";
    case "declined":
      return "The guest declined";
    case "unavailable":
      if (detail === "expired") return "Request expired; if Windows is still asking, the guest can click No.";
      return detail ? `Admin rights unavailable: ${detail}` : "Admin rights unavailable";
    case "ended":
      return "Admin rights ended";
  }
}

/**
 * The view rules (docs/53 §5): only a controlling technician, only once the agent advertised, never
 * for an observer. While a request waits or a grant lives, the button is disabled and the hint shows.
 */
export function adminRightsView(m: AdminRightsModel, observing: boolean): AdminRightsView {
  if (observing || m.available === null) {
    return { show: false, canRequest: false, disabledReason: null, status: null, hint: null };
  }
  const busy = m.state === "pending" || m.state === "granted";
  const disabledReason = !m.available
    ? (m.unavailableReason ?? "Not available in this session")
    : m.state === "pending"
      ? "Waiting for the guest"
      : m.state === "granted"
        ? "Admin rights are already granted"
        : null;
  return {
    show: true,
    canRequest: m.available && !busy,
    disabledReason,
    status: statusText(m.state, m.detail),
    hint: busy ? HINT : null,
  };
}
