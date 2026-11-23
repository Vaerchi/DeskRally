import type { ServerToClient } from "./protocol";

type ParticipantSnapshot = Extract<ServerToClient, { type: "session_participants" }>;

export function acceptParticipantSnapshot(
  snapshot: ParticipantSnapshot,
  ownSessionId: string | null,
  lastRevision: number | undefined,
): boolean {
  if (snapshot.revision !== undefined && lastRevision !== undefined && snapshot.revision < lastRevision) {
    return false;
  }
  return !snapshot.participants.some(p => p.display_name) ||
    (ownSessionId !== null && snapshot.participants.some(p => p.session_id === ownSessionId));
}
