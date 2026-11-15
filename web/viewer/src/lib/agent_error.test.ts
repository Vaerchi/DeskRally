import { describe, expect, it } from "vitest";
import { routeAgentError } from "./agent_error";
import { INPUT_CONTROL_ERROR_PREFIX } from "./input_handoff";
import { DISPLAY_LAYOUT_END_PREFIX } from "./layout_reconnect";

describe("routeAgentError", () => {
  it("routes a hand refusal to the input hand-off, even while a policy install is pending", () => {
    expect(routeAgentError(`${INPUT_CONTROL_ERROR_PREFIX}someone else has the hand`, false)).toEqual({ kind: "input-control" });
    expect(routeAgentError(`${INPUT_CONTROL_ERROR_PREFIX}someone else has the hand`, true)).toEqual({ kind: "input-control" });
  });

  it("routes a session end, marking only the display-layout end as a layout change", () => {
    expect(routeAgentError("session ended: the lease lapsed", false)).toEqual({ kind: "session-ended", layoutChange: false });
    expect(routeAgentError(`${DISPLAY_LAYOUT_END_PREFIX}; reconnect`, false)).toEqual({ kind: "session-ended", layoutChange: true });
  });

  it("does not let a pending policy install claim a session end", () => {
    expect(routeAgentError("session ended: the lease lapsed", true)).toEqual({ kind: "session-ended", layoutChange: false });
  });

  it("attributes any other error to the pending policy install, else to the outstanding command", () => {
    expect(routeAgentError("policy signature did not verify", true)).toEqual({ kind: "policy-rejected" });
    expect(routeAgentError("no frame captured yet", false)).toEqual({ kind: "command" });
  });

  it("matches the prefixes exactly, not anywhere in the text", () => {
    expect(routeAgentError("command failed: session ended: no", false)).toEqual({ kind: "command" });
    expect(routeAgentError("Session ended: capitalised", false)).toEqual({ kind: "command" });
  });
});
