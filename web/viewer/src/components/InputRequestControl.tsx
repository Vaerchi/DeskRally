import { useEffect, useSyncExternalStore } from "react";
import type { InputHandoffModel } from "../lib/input_handoff";
import {
  holderPromptLabel,
  inputRequestView,
  type InputRequestController,
  type InputRequestSnapshot,
} from "../lib/input_request";
import type { SessionParticipantEntry } from "../lib/protocol";

/** The controller's current snapshot, re-rendering on every change. */
export function useInputRequestSnapshot(controller: InputRequestController): InputRequestSnapshot {
  return useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
}

/**
 * docs/73 §2.2 (requester): "Request input control" in the Session menu. The rules (when it shows, what each
 * state and outcome says) are `inputRequestView`'s; this only renders them. Nothing here claims a request
 * worked: the agent's Result and the docs/61 snapshot are the only answers.
 */
export function InputRequestControl({
  snapshot,
  handoff,
  observing,
  ownSessionId,
  onRequest,
  onWithdraw,
}: {
  snapshot: InputRequestSnapshot;
  handoff: InputHandoffModel;
  observing: boolean;
  ownSessionId: string | null;
  onRequest: () => void;
  onWithdraw: () => void;
}) {
  const v = inputRequestView(snapshot, handoff, observing, ownSessionId);
  if (!v.show) return null;
  return (
    <div className="input-handoff" data-testid="input-request">
      {v.status && <span role="status" data-testid="input-request-status">{v.status}</span>}
      {v.canRequest && (
        <button type="button" className="panel__action" data-testid="input-request-ask"
          title="Ask the technician who has keyboard and mouse control to hand it to you" onClick={onRequest}>
          Request input control
        </button>
      )}
      {v.canWithdraw && (
        <button type="button" className="panel__action" data-testid="input-request-withdraw"
          title="Cancel the request" onClick={onWithdraw}>
          Withdraw
        </button>
      )}
    </div>
  );
}

/**
 * docs/73 §2.2 (holder): the NON-MODAL prompt, shown whether or not any menu is open. Rendered inside the
 * viewer element so it also shows in full screen. The requester is named from the participant list; the
 * session id itself is never displayed, and every string is rendered as text.
 */
export function InputControlPrompts({
  controller,
  participants,
  fixed = false,
}: {
  controller: InputRequestController;
  participants: readonly SessionParticipantEntry[];
  /** Anchor to the window instead of the viewer element (for views that have no viewer). */
  fixed?: boolean;
}) {
  const { prompts } = useInputRequestSnapshot(controller);
  // Tell the agent each prompt was rendered (once per id: the controller dedups, also across two windows).
  useEffect(() => {
    for (const p of prompts) controller.promptRendered(p.requestId);
  }, [prompts, controller]);
  if (prompts.length === 0) return null;
  return (
    <div className={fixed ? "input-prompts input-prompts--fixed" : "input-prompts"} data-testid="input-control-prompts">
      {prompts.map((p) => (
        <div key={p.requestId} className="input-prompt" role="alert" data-testid="input-control-prompt">
          <span className="input-prompt__text" data-testid="input-control-prompt-text">
            {holderPromptLabel(p.fromSession, participants)} asks for keyboard and mouse control
          </span>
          <button type="button" className="panel__action" data-testid="input-control-prompt-allow"
            onClick={() => controller.answer(p.requestId, true)}>Allow</button>
          <button type="button" className="panel__action" data-testid="input-control-prompt-decline"
            onClick={() => controller.answer(p.requestId, false)}>Decline</button>
        </div>
      ))}
    </div>
  );
}
