import { describe, expect, it, vi } from "vitest";
import { AuthSession } from "./auth_session";
import { guardedTransportError } from "./transport_error_guard";

describe("guardedTransportError", () => {
  it("suppresses a handler whose epoch matches the post-expire generation while the session is still expired", () => {
    const session = new AuthSession(vi.fn());
    const setError = vi.fn();

    // expire() increments generation to 1 and sets expired=true.
    session.expire();

    // Handler created at epoch=1 — numerically equal to the current generation.
    const staleHandler = guardedTransportError(session, session.epoch, setError);

    // Must NOT fire: expired=true means isCurrent() is false even though epoch===generation.
    staleHandler(new Error("stale"));
    expect(setError).not.toHaveBeenCalled();

    // signedIn() increments generation to 2 and clears expired.
    session.signedIn();

    // Handler at the new epoch must fire normally.
    const liveHandler = guardedTransportError(session, session.epoch, setError);
    liveHandler(new Error("live"));
    expect(setError).toHaveBeenCalledOnce();
    expect(setError).toHaveBeenCalledWith("live");
  });

  it("delivers errors while current, then suppresses the same handler after epoch advances", () => {
    const session = new AuthSession(vi.fn());
    const setError = vi.fn();

    // Handler created while the session is live (epoch 0).
    const firstHandler = guardedTransportError(session, session.epoch, setError);

    // Must deliver errors while still current.
    firstHandler(new Error("early ICE failure"));
    expect(setError).toHaveBeenCalledOnce();
    expect(setError).toHaveBeenCalledWith("early ICE failure");
    setError.mockClear();

    // Session expires, then the user signs back in — epoch advances twice.
    session.expire();
    session.signedIn();

    // New transport gets a handler for the current epoch.
    const currentHandler = guardedTransportError(session, session.epoch, setError);

    // The old handler fires late — must be suppressed (epoch no longer matches).
    firstHandler(new Error("stale ICE failure"));
    expect(setError).not.toHaveBeenCalled();

    // The current handler fires — must reach the UI.
    currentHandler(new Error("live DTLS failure"));
    expect(setError).toHaveBeenCalledOnce();
    expect(setError).toHaveBeenCalledWith("live DTLS failure");
  });
});
