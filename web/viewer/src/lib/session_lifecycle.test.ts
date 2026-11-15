import { describe, expect, it, vi } from "vitest";

import type { ConnectionState } from "./transport";
import {
  isTerminalConnectionState,
  releaseSessionOnTerminalTransport,
} from "./session_lifecycle";

function actions() {
  return { stopRenewing: vi.fn(), release: vi.fn() };
}

describe("releaseSessionOnTerminalTransport", () => {
  it("releases the session when the transport FAILS", () => {
    const a = actions();
    expect(releaseSessionOnTerminalTransport("failed", a)).toBe(true);
    expect(a.stopRenewing).toHaveBeenCalledOnce();
    expect(a.release).toHaveBeenCalledOnce();
  });

  // THE NEGATIVE CONTROL, and the one that matters most. `disconnected` is WebRTC's transient
  // state: ICE recovers from it when a laptop changes network or a link blips. A version of this
  // that treated it as terminal would pass the test above and end live sessions in the field, so
  // asserting the positive case alone would pin a constant rather than the behaviour.
  it("does NOT release on `disconnected` — ICE recovers from that", () => {
    const a = actions();
    expect(releaseSessionOnTerminalTransport("disconnected", a)).toBe(false);
    expect(a.stopRenewing).not.toHaveBeenCalled();
    expect(a.release).not.toHaveBeenCalled();
  });

  it.each<ConnectionState>(["idle", "signaling", "connecting", "connected"])(
    "does not release while the session is alive or still being set up (%s)",
    (state) => {
      const a = actions();
      expect(releaseSessionOnTerminalTransport(state, a)).toBe(false);
      expect(a.stopRenewing).not.toHaveBeenCalled();
      expect(a.release).not.toHaveBeenCalled();
    },
  );

  // Stated as its own assertion so that adding a state to `ConnectionState` without deciding what
  // it means for the session is a visible choice rather than a silent default.
  it("treats exactly one state as terminal", () => {
    const all: ConnectionState[] = [
      "idle",
      "signaling",
      "connecting",
      "connected",
      "disconnected",
      "failed",
    ];
    expect(all.filter(isTerminalConnectionState)).toEqual(["failed"]);
  });
});
