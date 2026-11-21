import type { InputHandoffModel } from "../lib/input_handoff";
import { handTargetLabel } from "../lib/input_handoff";
import type { SessionParticipantEntry } from "../lib/protocol";

export function SessionParticipants({ participants, ownSessionId, input }: {
  participants: readonly SessionParticipantEntry[];
  ownSessionId: string | null;
  input: InputHandoffModel;
}) {
  if (participants.length === 0) return null;

  return <ul className="session-participant-list">
    {participants.slice().sort((a, b) => a.session_id.localeCompare(b.session_id)).map(p => (
      <li key={p.session_id}>
        <span>{handTargetLabel(p, participants)}{p.session_id === ownSessionId ? " (you)" : ""}</span>
        <div>Session access {p.access === "view_only" ? "observing" : "control"}
          {input.mode === "owned" && input.ownerSession === p.session_id && " · has input"}
        </div>
      </li>
    ))}
  </ul>;
}
