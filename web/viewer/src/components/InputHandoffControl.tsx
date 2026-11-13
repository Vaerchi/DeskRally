import { useState } from "react";
import { inputHandoffView, resolveHandTarget, type InputHandoffModel } from "../lib/input_handoff";
import type { SessionParticipantEntry } from "../lib/protocol";

/**
 * docs/61: hand keyboard and mouse control to another technician on the same machine, from the Session
 * menu. The rules (who sees it, when it is enabled, what each state says) are `inputHandoffView`'s; this
 * only renders them. Nothing here claims a hand worked — the agent's snapshot is the only answer.
 */
export function InputHandoffControl({
  model,
  observing,
  ownSessionId,
  participants,
  onHand,
  onClaim,
}: {
  model: InputHandoffModel;
  observing: boolean;
  ownSessionId: string | null;
  participants: readonly SessionParticipantEntry[];
  onHand: (toSession: string) => void;
  onClaim: () => void;
}) {
  const v = inputHandoffView(model, observing, ownSessionId, participants);
  const [picked, setPicked] = useState("");
  if (!v.show) return null;
  // A pick survives participant pushes only while that technician is still a target; otherwise the
  // technician must choose again (resolveHandTarget never substitutes someone else).
  const target = resolveHandTarget(v.targets, picked);
  return (
    <div className="input-handoff" data-testid="input-handoff">
      {v.status && <span role="status" data-testid="input-handoff-status">{v.status}</span>}
      {v.canClaim ? (
        <button type="button" className="panel__action" data-testid="input-handoff-claim"
          title="Take keyboard and mouse control of this machine" onClick={onClaim}>
          Take input control
        </button>
      ) : (
        <>
          {/* A voided pick keeps the picker up even with one target left: choose again, explicitly. */}
          {(v.targets.length > 1 || (picked !== "" && target === null && v.targets.length > 0)) && (
            <select aria-label="Hand input control to" data-testid="input-handoff-target" value={target ?? ""}
              disabled={!v.canHand} onChange={(e) => setPicked(e.target.value)}>
              <option value="" disabled>Choose a technician…</option>
              {v.targets.map((t) => <option key={t.sessionId} value={t.sessionId}>{t.label}</option>)}
            </select>
          )}
          <button type="button" className="panel__action" data-testid="input-handoff-hand" disabled={!v.canHand || target === null}
            title={v.disabledReason ?? (target === null ? "Choose who to hand control to" : "Give keyboard and mouse control to this technician. Your input stops until control is handed back.")}
            onClick={() => { if (target !== null) onHand(target); }}>
            {v.targets.length === 1 && target !== null ? `Hand input control to ${v.targets[0].label}` : "Hand input control"}
          </button>
        </>
      )}
      {v.error && <span className="input-handoff__error" role="alert" data-testid="input-handoff-error">{v.error}</span>}
    </div>
  );
}

/**
 * docs/61: the always-visible indicator of who owns input — shown once arbitration is armed, to
 * observers too (they cannot hand control, but they should know who is typing).
 */
export function InputControlBadge({
  model,
  observing,
  ownSessionId,
  participants,
}: {
  model: InputHandoffModel;
  observing: boolean;
  ownSessionId: string | null;
  participants: readonly SessionParticipantEntry[];
}) {
  const badge = inputHandoffView(model, observing, ownSessionId, participants).badge;
  // A refusal must be visible even with the Session menu closed (Codex 3d review).
  return (
    <>
      {badge && <span className="app__input-control" role="status" data-testid="input-control-badge">{badge}</span>}
      {model.error && <span className="app__input-control-error" role="alert" data-testid="input-control-error">{model.error}</span>}
    </>
  );
}
