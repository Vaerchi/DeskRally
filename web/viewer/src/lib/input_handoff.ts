/**
 * docs/61: handing input control between technicians connected to the same machine, as the viewer
 * models it.
 *
 * The agent arbitrates; the viewer only reports. It advertises once whether hand-off is possible
 * (`InputHandoffAvailable`) and, on every change, sends the authoritative snapshot of who owns input
 * (`InputControlChanged`). This module is the pure state and the view rules: the component
 * (`InputHandoffControl`) only renders them and `App.tsx` only wires the control channel. The viewer
 * NEVER infers that a hand succeeded — only an `owned` snapshot naming the new owner says so.
 */
import type { InputControlMode } from "./control";
import type { SessionParticipantEntry } from "./protocol";

/**
 * Every hand refusal from the agent starts with this (host.rs `INPUT_CONTROL_ERROR_PREFIX`), which is how
 * an `Error` is attributed to the pending hand rather than to whatever else the session is doing. Change
 * both or neither.
 */
export const INPUT_CONTROL_ERROR_PREFIX = "input control: ";

/**
 * How long a hand may stay unanswered before the UI stops waiting (the agent's answer may still come).
 * Above the agent's worst case — a key waiting behind typing (`KEY_WAIT_LIMIT`, 15 s) plus the typist
 * barrier (5 s) — so a slow but successful hand is not reported as unknown (cross-stage review).
 */
export const HAND_PENDING_TIMEOUT_MS = 25_000;

export interface InputHandoffModel {
  /** `null` until the agent advertises (an older agent never does: no action is offered). */
  available: boolean | null;
  /** The last snapshot's mode; `shared` (compatibility mode) until the agent says otherwise. */
  mode: InputControlMode;
  /** Who owns input, by signaling session id — only for `owned`. */
  ownerSession: string | null;
  /**
   * A hand (or claim) is in flight. The agent IGNORES further requests from this session meanwhile, so
   * the action is disabled until the outcome: an `owned` snapshot, or an `input control:` error.
   */
  pending: boolean;
  /** The last refusal, without its prefix. */
  error: string | null;
}

export const NO_INPUT_HANDOFF: InputHandoffModel = {
  available: null,
  mode: "shared",
  ownerSession: null,
  pending: false,
  error: null,
};

export function handoffAdvertised(m: InputHandoffModel, available: boolean): InputHandoffModel {
  return { ...m, available };
}

/** An authoritative snapshot: replaces the mode and owner, and ends any wait (the outcome is in). */
export function inputControlChanged(
  m: InputHandoffModel,
  ownerSession: string | null,
  mode: InputControlMode,
): InputHandoffModel {
  return { ...m, mode, ownerSession: mode === "owned" ? ownerSession : null, pending: false, error: null };
}

/** The click, before any answer: blocks a second request at once (the agent would ignore it anyway). */
export function handRequested(m: InputHandoffModel): InputHandoffModel {
  return { ...m, pending: true, error: null };
}

/** Whether an agent `Error` is a hand refusal (and so belongs to the pending hand). */
export function isInputControlError(message: string): boolean {
  return message.startsWith(INPUT_CONTROL_ERROR_PREFIX);
}

/** A refusal: the hand did not happen. It changes NO ownership state — only the snapshot does that. */
export function handRefused(m: InputHandoffModel, message: string): InputHandoffModel {
  const text = isInputControlError(message) ? message.slice(INPUT_CONTROL_ERROR_PREFIX.length) : message;
  return { ...m, pending: false, error: text };
}

/** Nothing came back in time: stop waiting so the technician can retry. */
export function handTimedOut(m: InputHandoffModel): InputHandoffModel {
  if (!m.pending) return m;
  return {
    ...m,
    pending: false,
    error: "No answer from the agent yet, so the result is unknown. Check who has input control before trying again.",
  };
}

/** Someone this session may hand input control to. */
export interface HandTarget {
  sessionId: string;
  label: string;
}

export interface InputHandoffView {
  /** Render the Session-menu control at all. */
  show: boolean;
  /** The status line in the menu, or `null`. */
  status: string | null;
  /** The short always-visible indicator — only once arbitration is armed, and for observers too. */
  badge: string | null;
  /** This session owns input. */
  youHaveControl: boolean;
  /** Whom this session may hand to: other controlling technicians (never an observer, never itself). */
  targets: HandTarget[];
  canHand: boolean;
  /** Input is locked (its owner left): this session may take it. */
  canClaim: boolean;
  /** Why the hand action is disabled, for its tooltip. */
  disabledReason: string | null;
  /** The last refusal to show. */
  error: string | null;
}

/**
 * A target's label. Signaling carries no display names (docs/61 §7b), so it is built from ids that
 * belong to THIS session and never shift: no ordinal (ordinals renumber as people join and leave), and
 * the session id is included because one technician can have several sessions (Codex 3d review).
 */
export function handTargetLabel(p: SessionParticipantEntry): string {
  const session = `session ${p.session_id.slice(0, 8)}`;
  return p.technician_id ? `Technician ${p.technician_id.slice(0, 8)} · ${session}` : `Technician · ${session}`;
}

/** Others who can take control, in a stable order. */
function handTargets(own: string, participants: readonly SessionParticipantEntry[]): HandTarget[] {
  return participants
    .filter((p) => p.session_id !== own && p.access !== "view_only")
    .slice()
    .sort((a, b) => a.session_id.localeCompare(b.session_id))
    .map((p) => ({ sessionId: p.session_id, label: handTargetLabel(p) }));
}

/**
 * Whom a click hands to (Codex 3d review: never silently substitute someone the technician did not
 * choose). An explicit pick wins while it is still a target; once that technician leaves the pick is
 * VOID — even if exactly one other target remains — and the technician must choose again. Only when
 * nothing was ever picked does a lone target stand in, and then the button names it.
 */
export function resolveHandTarget(targets: readonly HandTarget[], picked: string): string | null {
  if (picked !== "") return targets.some((t) => t.sessionId === picked) ? picked : null;
  return targets.length === 1 ? targets[0].sessionId : null;
}

/**
 * The view rules (docs/61 D12): the action is offered only on the agent's AFFIRMATIVE capability, only
 * with our own signaling id known (it is how we tell ourselves apart), and never to an observer — who
 * still sees the badge. A hand is possible from shared mode or by the current owner; a claim only once
 * input is locked.
 */
export function inputHandoffView(
  m: InputHandoffModel,
  observing: boolean,
  ownSessionId: string | null,
  participants: readonly SessionParticipantEntry[],
): InputHandoffView {
  const youHaveControl = m.mode === "owned" && ownSessionId !== null && m.ownerSession === ownSessionId;
  // Without our own id we cannot tell "us" from "them": say neither (Codex 3d review).
  const badge =
    m.mode === "owned"
      ? ownSessionId === null
        ? "One technician has input control"
        : youHaveControl
          ? "You have input control"
          : "Another technician has input control"
      : m.mode === "blocked"
        ? "Input locked"
        : null;
  const show = m.available === true && !observing && ownSessionId !== null;
  if (!show) {
    return { show: false, status: null, badge, youHaveControl, targets: [], canHand: false, canClaim: false, disabledReason: null, error: null };
  }
  const targets = handTargets(ownSessionId, participants);
  const status =
    m.mode === "shared"
      ? "Input is shared: every controlling technician can type."
      : m.mode === "blocked"
        ? "Input is locked: the technician who had control left. Take control to continue."
        : youHaveControl
          ? "You have input control."
          : "Another technician has input control.";
  const mayHandNow = m.mode === "shared" || youHaveControl;
  const disabledReason = m.pending
    ? "Waiting for the agent…"
    : !mayHandNow
      ? m.mode === "blocked"
        ? "Input is locked; take control first"
        : "Another technician has input control; only they can hand it on"
      : targets.length === 0
        ? "No other controlling technician is connected"
        : null;
  return {
    show: true,
    status,
    badge,
    youHaveControl,
    targets,
    canHand: !m.pending && mayHandNow && targets.length > 0,
    canClaim: !m.pending && m.mode === "blocked",
    disabledReason,
    error: m.error,
  };
}
