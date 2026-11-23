import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { inputControlChanged, inputHandoffView, NO_INPUT_HANDOFF } from "../lib/input_handoff";
import { acceptParticipantSnapshot } from "../lib/participants";
import type { ServerToClient } from "../lib/protocol";
import { SessionParticipants } from "./SessionParticipants";

const participants = [
  { session_id: "11111111-self", display_name: "Ada" },
  { session_id: "22222222-observer", display_name: "Ada", access: "view_only" },
  { session_id: "33333333-control", technician_id: "abcdef12-tech" },
  { session_id: "44444444-control", display_name: "Pat" },
];
const ownSessionId = participants[0].session_id;

describe("participant snapshots", () => {
  const snapshot: Extract<ServerToClient, { type: "session_participants" }> = {
    type: "session_participants", device_id: "machine", revision: 4, participants,
  };

  it("requires the receiver's signaling id in snapshots that carry names", () => {
    expect(acceptParticipantSnapshot(snapshot, null, undefined)).toBe(false);
    expect(acceptParticipantSnapshot(snapshot, "some-other-session", undefined)).toBe(false);
    expect(acceptParticipantSnapshot(snapshot, ownSessionId, undefined)).toBe(true);
  });

  it("drops older revisions and accepts legacy unnamed pushes", () => {
    expect(acceptParticipantSnapshot(snapshot, ownSessionId, 5)).toBe(false);
    expect(acceptParticipantSnapshot(snapshot, ownSessionId, 4)).toBe(true);
    const legacy = { ...snapshot, participants: [{ session_id: ownSessionId }], revision: undefined };
    expect(acceptParticipantSnapshot(legacy, null, 5)).toBe(true);
  });
});

describe("Session participants", () => {
  it("renders per-session labels and marks ownership only from the agent snapshot", () => {
    const render = (input = NO_INPUT_HANDOFF) => renderToStaticMarkup(
      <SessionParticipants participants={participants} ownSessionId={ownSessionId} input={input} />,
    );
    const initial = render();
    expect(initial.match(/<li>/g)).toHaveLength(4);
    expect(initial).toContain("Ada · session 11111111 (you)");
    expect(initial).toContain("Ada · session 22222222");
    expect(initial).toContain("Session access observing");
    expect(initial).toContain("Technician abcdef12 · session 33333333");
    expect(initial).toContain("Session access control");
    expect(initial).not.toContain("has input");

    const owned = inputControlChanged(NO_INPUT_HANDOFF, participants[3].session_id, "owned");
    expect(render(owned)).toContain("<span>Pat</span><div>Session access control · has input</div>");
    const view = inputHandoffView({ ...owned, available: true }, false, ownSessionId, participants);
    expect(view.badge).toBe("Pat has input control");
    expect(view.targets.map(t => t.label)).toContain("Pat");
  });
});
