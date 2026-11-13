import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionTransfer, StartedSession } from "./console_api";
import {
  acceptAndWait,
  IncomingTransferPoller,
  senderTransferredMessage,
  transferFailureMessage,
} from "./session_transfer";

afterEach(() => vi.useRealTimers());

const offer = (state: SessionTransfer["state"], extra: Partial<SessionTransfer> = {}): SessionTransfer => ({
  id: "t1", session_id: "s1", machine_id: "m1", from_user_id: "alice", note: "", state,
  created_at: "", expires_at: "", ...extra,
});
const started: StartedSession = {
  session: { id: "s2" } as StartedSession["session"],
  signaling: { url: "wss://sig", device_id: "dev-1", session_id: "s2", ticket: {} as never },
  session_policy: { access: "control", signed: "sig" },
};

function fakeApi(states: SessionTransfer["state"][], ticket: StartedSession = started) {
  const reads = [...states];
  const first = reads.shift()!;
  return {
    acceptSessionTransfer: vi.fn(async () => offer(first, { failure_reason: "nope" })),
    getSessionTransfer: vi.fn(async () => offer(reads.shift() ?? "releasing", { failure_reason: "group changed" })),
    sessionTransferTicket: vi.fn(async () => ticket),
  };
}
const noSleep = async () => {};

describe("acceptAndWait", () => {
  it("polls a releasing offer until accepted, then connects to S2 as an OWNED session", async () => {
    const api = fakeApi(["releasing", "releasing", "accepted"]);
    const seen: string[] = [];
    const got = await acceptAndWait(api, "t1", { sleep: noSleep, onState: (t) => seen.push(t.state) });
    expect(seen).toEqual(["releasing", "releasing", "accepted"]);
    expect(api.getSessionTransfer).toHaveBeenCalledTimes(2);
    expect(api.sessionTransferTicket).toHaveBeenCalledOnce();
    expect(got.deviceId).toBe("dev-1");
    expect(got.signalingUrl).toBe("wss://sig");
    expect(got.brokered).toEqual({
      sessionId: "s2", signaling: started.signaling, sessionPolicy: started.session_policy, owned: true,
    });
  });

  it("never fetches a ticket when the hand-off fails, and says why", async () => {
    const api = fakeApi(["releasing", "failed"]);
    await expect(acceptAndWait(api, "t1", { sleep: noSleep })).rejects.toThrow("group changed");
    expect(api.sessionTransferTicket).not.toHaveBeenCalled();
  });

  it("refuses a withdrawn offer at accept", async () => {
    const api = fakeApi(["cancelled"]);
    await expect(acceptAndWait(api, "t1", { sleep: noSleep })).rejects.toThrow("cancelled");
    expect(api.getSessionTransfer).not.toHaveBeenCalled();
  });

  it("gives up after the timeout without a ticket", async () => {
    const api = fakeApi(["releasing"]);
    let t = 0;
    await expect(acceptAndWait(api, "t1", {
      sleep: async (ms) => { t += ms; }, now: () => t, pollMs: 2000, timeoutMs: 10_000,
    })).rejects.toThrow("did not confirm");
    expect(api.getSessionTransfer.mock.calls.length).toBe(5);
    expect(api.sessionTransferTicket).not.toHaveBeenCalled();
  });

  it("rejects a ticket without signaling instead of connecting blind", async () => {
    const api = fakeApi(["accepted"], { session: started.session });
    await expect(acceptAndWait(api, "t1", { sleep: noSleep })).rejects.toThrow("no signaling");
  });
});

describe("messages", () => {
  it("names the recipient for a transferred session, and words the failed hand-off", () => {
    expect(senderTransferredMessage("could not renew session lease: session transferred", "Bob"))
      .toBe("Session transferred to Bob.");
    expect(senderTransferredMessage("could not renew session lease: session transferred")).toBe("Session transferred.");
    expect(senderTransferredMessage("could not renew session lease: session handed off; the transfer did not complete", "Bob"))
      .toContain("did not complete");
    expect(senderTransferredMessage("could not renew session lease: session has ended", "Bob")).toBeNull();
  });
  it("explains each terminal state", () => {
    expect(transferFailureMessage(offer("expired"))).toContain("expired");
    expect(transferFailureMessage(offer("superseded"))).toContain("newer");
    expect(transferFailureMessage(offer("failed", { failure_reason: "machine gone" }))).toContain("machine gone");
  });
});

describe("IncomingTransferPoller", () => {
  it("polls on an interval, shows only pending offers, survives errors, and stops", async () => {
    vi.useFakeTimers();
    const list = vi.fn()
      .mockResolvedValueOnce([offer("pending"), offer("releasing", { id: "t2" })])
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValue([]);
    const seen: string[][] = [];
    const poller = new IncomingTransferPoller({ listIncomingTransfers: list }, (o) => seen.push(o.map((t) => t.id)), 10_000);
    poller.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(seen).toEqual([["t1"]]);
    await vi.advanceTimersByTimeAsync(10_000); // the error: nothing reported, polling continues
    expect(seen).toEqual([["t1"]]);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(seen).toEqual([["t1"], []]);
    poller.stop();
    const calls = list.mock.calls.length;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(list.mock.calls.length).toBe(calls);
  });

  it("a stale in-flight poll cannot report after stop", async () => {
    vi.useFakeTimers();
    let resolve!: (v: SessionTransfer[]) => void;
    const list = vi.fn(() => new Promise<SessionTransfer[]>((r) => { resolve = r; }));
    const onChange = vi.fn();
    const poller = new IncomingTransferPoller({ listIncomingTransfers: list }, onChange);
    poller.start();
    poller.stop();
    resolve([offer("pending")]);
    await vi.advanceTimersByTimeAsync(0);
    expect(onChange).not.toHaveBeenCalled();
  });
});
