import { describe, expect, it } from "vitest";
import { isMonitorPinRefusal, routeAgentError } from "./agent_error";
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

describe("multi-session monitor pin refusals (2026-11-27)", () => {
  it("are recognised (old and new wording) and never become a command error or a policy verdict", () => {
    const raw = "monitor selection is locked to display 4294967295 for this session group; dynamic switching is not supported in multi-session mode";
    expect(isMonitorPinRefusal(raw)).toBe(true);
    expect(isMonitorPinRefusal("monitor selection is locked to all displays for this session group; switching is not supported")).toBe(true);
    expect(routeAgentError(raw, false)).toEqual({ kind: "monitor-pinned" });
    expect(routeAgentError(raw, true)).toEqual({ kind: "monitor-pinned" });
    expect(isMonitorPinRefusal("unknown monitor id 7")).toBe(false);
    expect(routeAgentError("unknown monitor id 7", false)).toEqual({ kind: "command" });
  });
});
