import appSource from "../App.tsx?raw";
import coreSource from "./brokered_session_core.ts?raw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InputRequestAgentMessage, InputRequestOutcome } from "./control";
import { handoffAdvertised, inputControlChanged, NO_INPUT_HANDOFF } from "./input_handoff";
import {
  CLOSED_IDS_KEPT,
  GENERIC_HOLDER_LABEL,
  HANDING_OVER_TEXT,
  holderPromptLabel,
  InputRequestController,
  inputRequestView,
  NO_INPUT_REQUEST,
  OUTCOME_TEXT,
  PROMPT_GRACE_MS,
  REQUEST_RETRY_MS,
  UNCONFIRMED_TEXT,
  WAITING_TEXT,
  type InputRequestSender,
} from "./input_request";

const ME = "me-session";
const PEER = "peer-session";
const CID = "aaaaaaaa-1111-4222-8333-444444444444";
const CID2 = "aaaaaaaa-1111-4222-8333-555555555555";
const RID = "bbbbbbbb-5555-4666-8777-888888888888";
const RID2 = "bbbbbbbb-5555-4666-8777-999999999999";

function fixture(ids: string[] = [CID, CID2]) {
  const calls: string[] = [];
  const sender: InputRequestSender = {
    requestInputControl: (id, retry) => { calls.push(`request ${id} retry=${retry ?? false}`); },
    withdrawInputControlRequest: (id) => { calls.push(`withdraw ${id}`); },
    inputControlPromptShown: (id) => { calls.push(`shown ${id}`); },
    answerInputControlRequest: (id, accept) => { calls.push(`answer ${id} ${accept}`); },
  };
  const queue = [...ids];
  const c = new InputRequestController(() => sender, { newId: () => queue.shift()! });
  const avail = (available = true) => c.handleMessage({ t: "InputRequestAvailable", c: { available } });
  const pending = (state: "pending_delivery" | "shown" | "accepted_in_flight", cid = CID) =>
    c.handleMessage({ t: "InputControlRequestPending", c: { client_request_id: cid, request_id: RID, state } });
  const result = (outcome: InputRequestOutcome, cid = CID) =>
    c.handleMessage({ t: "InputControlRequestResult", c: {
      client_request_id: cid, outcome,
      request_id: ["no_holder", "busy", "rate_limited", "capacity", "unsupported_holder", "unknown"].includes(outcome) ? null : RID,
    } } as InputRequestAgentMessage);
  const requested = (id = RID, from = PEER, ms = 30_000) =>
    c.handleMessage({ t: "InputControlRequested", c: { request_id: id, from_session: from, expires_in_ms: ms } });
  const withdrawn = (id = RID, reason: InputRequestOutcome = "cancelled") =>
    c.handleMessage({ t: "InputControlRequestWithdrawn", c: { request_id: id, reason } });
  return { c, calls, avail, pending, result, requested, withdrawn };
}

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(1_000_000); });
afterEach(() => { vi.useRealTimers(); });

describe("request-for-control view rules (requester)", () => {
  const avail = { ...NO_INPUT_REQUEST, available: true };
  const owned = (owner: string | null) => inputControlChanged(handoffAdvertised(NO_INPUT_HANDOFF, true), owner, "owned");

  it("is hidden until the agent says available, and while input is not owned by another session", () => {
    expect(inputRequestView(NO_INPUT_REQUEST, owned(PEER), false, ME).show).toBe(false);
    expect(inputRequestView(avail, owned(PEER), false, ME)).toMatchObject({ show: true, canRequest: true });
    expect(inputRequestView(avail, NO_INPUT_HANDOFF, false, ME).show).toBe(false); // shared
    expect(inputRequestView(avail, inputControlChanged(NO_INPUT_HANDOFF, null, "blocked"), false, ME).show).toBe(false);
    expect(inputRequestView(avail, owned(ME), false, ME).show).toBe(false); // we own it ourselves
    expect(inputRequestView(avail, owned(null), false, ME).show).toBe(false);
  });

  it("is never offered to an observer or view-only session, nor before our own id is known", () => {
    expect(inputRequestView(avail, owned(PEER), true, ME).show).toBe(false);
    expect(inputRequestView(avail, owned(PEER), false, null).show).toBe(false);
  });

  it("keeps the sticky outcome visible after the snapshot changes (a grant makes us the owner)", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.result("granted");
    const v = inputRequestView(f.c.getSnapshot(), owned(ME), false, ME);
    expect(v).toMatchObject({ show: true, canRequest: false, canWithdraw: false, status: OUTCOME_TEXT.granted });
  });
});

describe("InputRequestController requester", () => {
  it("does nothing until the agent says available", () => {
    const f = fixture();
    f.c.request();
    expect(f.calls).toEqual([]);
    f.avail(false);
    f.c.request();
    expect(f.calls).toEqual([]);
    expect(f.c.getSnapshot().request).toBeNull();
  });

  it("request -> pending -> shown -> accepted_in_flight -> granted, with the right status lines", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    expect(f.calls).toEqual([`request ${CID} retry=false`]);
    const status = () => inputRequestView(f.c.getSnapshot(), inputControlChanged(NO_INPUT_HANDOFF, PEER, "owned"), false, ME);
    expect(status().status).toBe(WAITING_TEXT);
    f.pending("pending_delivery");
    expect(status().status).toBe(WAITING_TEXT);
    f.pending("shown");
    expect(status()).toMatchObject({ status: WAITING_TEXT, canWithdraw: true, canRequest: false });
    f.pending("accepted_in_flight");
    expect(status()).toMatchObject({ status: HANDING_OVER_TEXT, canWithdraw: false });
    f.result("granted");
    expect(f.c.getSnapshot().request).toMatchObject({ phase: "done", outcome: "granted" });
    expect(status().canRequest).toBe(true); // a fresh request may follow
  });

  it("every outcome and refusal has its own plain sentence, and busy says the pinned text", () => {
    const all: InputRequestOutcome[] = [
      "granted", "declined", "expired", "undelivered", "cancelled", "replaced", "holder_changed", "already_satisfied",
      "failed", "ineligible", "no_holder", "busy", "rate_limited", "capacity", "unsupported_holder", "unknown",
    ];
    const seen = new Set<string>();
    for (const outcome of all) {
      const f = fixture();
      f.avail();
      f.c.request();
      f.result(outcome);
      const text = inputRequestView(f.c.getSnapshot(), inputControlChanged(NO_INPUT_HANDOFF, PEER, "owned"), false, ME).status;
      expect(text, outcome).toBe(OUTCOME_TEXT[outcome]);
      expect(text, outcome).toMatch(/^[A-Z][^.\n]{8,}$/);
      seen.add(text!);
    }
    expect(seen.size).toBe(all.length);
    expect(OUTCOME_TEXT.busy).toBe("Input is recovering, try again shortly");
    expect(OUTCOME_TEXT.unsupported_holder).toBe("The other technician's console cannot receive requests");
    expect(OUTCOME_TEXT.capacity).toMatch(/another session of yours already has a request open/i);
  });

  it("re-sends the SAME id with retry:true after 3 s, at most 3 times, then says it could not confirm", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    vi.advanceTimersByTime(REQUEST_RETRY_MS - 1);
    expect(f.calls).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(f.calls).toEqual([`request ${CID} retry=false`, `request ${CID} retry=true`]);
    vi.advanceTimersByTime(REQUEST_RETRY_MS * 2);
    expect(f.calls).toHaveLength(4);
    expect(f.calls.slice(1).every((c) => c === `request ${CID} retry=true`)).toBe(true);
    expect(f.c.getSnapshot().request?.phase).toBe("sending");
    vi.advanceTimersByTime(REQUEST_RETRY_MS);
    expect(f.calls).toHaveLength(4); // no fourth re-send
    expect(f.c.getSnapshot().request?.phase).toBe("unconfirmed");
    const v = inputRequestView(f.c.getSnapshot(), inputControlChanged(NO_INPUT_HANDOFF, PEER, "owned"), false, ME);
    expect(v).toMatchObject({ status: UNCONFIRMED_TEXT, canRequest: true });
    f.c.request(); // a FRESH id
    expect(f.calls[4]).toBe(`request ${CID2} retry=false`);
  });

  it("a reply stops the re-sends", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    vi.advanceTimersByTime(REQUEST_RETRY_MS);
    f.pending("pending_delivery");
    vi.advanceTimersByTime(REQUEST_RETRY_MS * 5);
    expect(f.calls).toHaveLength(2);
    expect(f.c.getSnapshot().request?.phase).toBe("pending_delivery");
  });

  it("a terminal result is sticky per client_request_id: later Pending or another Result never overwrite it", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.result("declined");
    f.pending("shown");
    f.result("granted");
    expect(f.c.getSnapshot().request).toMatchObject({ phase: "done", outcome: "declined" });
    f.result("declined"); // idempotent repeat
    expect(f.c.getSnapshot().request).toMatchObject({ phase: "done", outcome: "declined" });
  });

  it("ignores replies for another id (a previous request's late reply)", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.result("expired");
    f.c.request();
    f.result("granted", CID); // the old id
    f.pending("shown", CID);
    expect(f.c.getSnapshot().request).toMatchObject({ clientRequestId: CID2, phase: "sending" });
  });

  it("withdraw sends only while the holder has not accepted, and changes nothing until the reply", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.c.withdraw();
    expect(f.calls[f.calls.length - 1]).toBe(`withdraw ${CID}`);
    expect(f.c.getSnapshot().request?.phase).toBe("sending");
    f.pending("accepted_in_flight");
    f.c.withdraw();
    expect(f.calls.filter((c) => c.startsWith("withdraw"))).toHaveLength(1);
    f.result("granted");
    f.c.withdraw();
    expect(f.calls.filter((c) => c.startsWith("withdraw"))).toHaveLength(1);
  });

  it("a second click while a request is in flight does not start another", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.c.request();
    expect(f.calls).toEqual([`request ${CID} retry=false`]);
  });

  it("reset (session end or reconnect) discards the request, the prompts and availability; no re-send happens", () => {
    const f = fixture();
    f.avail();
    f.c.request();
    f.requested();
    f.c.reset();
    expect(f.c.getSnapshot()).toEqual(NO_INPUT_REQUEST);
    vi.advanceTimersByTime(REQUEST_RETRY_MS * 5);
    expect(f.calls).toEqual([`request ${CID} retry=false`]);
  });

  it("a sender that throws (transport gone) does not break the controller", () => {
    const c = new InputRequestController(() => { throw new Error("Transport unavailable"); }, { newId: () => CID });
    c.handleMessage({ t: "InputRequestAvailable", c: { available: true } });
    expect(() => c.request()).not.toThrow();
    expect(c.getSnapshot().request?.phase).toBe("sending");
  });

  it("notifies subscribers and keeps the snapshot stable between changes", () => {
    const f = fixture();
    const fn = vi.fn();
    const off = f.c.subscribe(fn);
    const a = f.c.getSnapshot();
    expect(f.c.getSnapshot()).toBe(a);
    f.avail();
    expect(fn).toHaveBeenCalledTimes(1);
    off();
    f.avail(false);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe("InputRequestController holder", () => {
  it("shows a prompt, sends PromptShown once, and Allow/Decline send the answer and remove it", () => {
    const f = fixture();
    f.requested();
    expect(f.c.getSnapshot().prompts).toEqual([{ requestId: RID, fromSession: PEER }]);
    f.c.promptRendered(RID);
    f.c.promptRendered(RID); // a re-render or a second window
    expect(f.calls).toEqual([`shown ${RID}`]);
    f.c.answer(RID, true);
    expect(f.calls[f.calls.length - 1]).toBe(`answer ${RID} true`);
    expect(f.c.getSnapshot().prompts).toEqual([]);
    f.c.answer(RID, false); // already gone: nothing is sent
    expect(f.calls.filter((c) => c.startsWith("answer"))).toHaveLength(1);

    f.requested(RID2);
    f.c.answer(RID2, false);
    expect(f.calls[f.calls.length - 1]).toBe(`answer ${RID2} false`);
  });

  it("does not send PromptShown for a prompt that is not showing", () => {
    const f = fixture();
    f.c.promptRendered(RID);
    expect(f.calls).toEqual([]);
  });

  it("is withdrawn by InputControlRequestWithdrawn", () => {
    const f = fixture();
    f.requested();
    f.withdrawn(RID, "cancelled");
    expect(f.c.getSnapshot().prompts).toEqual([]);
  });

  it("suppresses a delayed prompt whose id was already withdrawn (even if never shown), or already answered", () => {
    const f = fixture();
    f.withdrawn(RID, "requester_left");
    f.requested(RID);
    expect(f.c.getSnapshot().prompts).toEqual([]);
    f.requested(RID2);
    f.c.answer(RID2, true);
    f.requested(RID2); // a re-delivery after our answer
    expect(f.c.getSnapshot().prompts).toEqual([]);
  });

  it("forgets a closed id after 5 minutes, and keeps only the last 32", () => {
    const f = fixture();
    f.withdrawn(RID);
    vi.advanceTimersByTime(5 * 60_000 + 1);
    f.requested(RID);
    expect(f.c.getSnapshot().prompts).toHaveLength(1);
    f.c.reset();
    const uuid = (n: number) => `cccccccc-0000-4000-8000-${String(n).padStart(12, "0")}`;
    for (let i = 0; i < CLOSED_IDS_KEPT + 1; i++) f.withdrawn(uuid(i));
    f.requested(uuid(0)); // the oldest fell out
    f.requested(uuid(CLOSED_IDS_KEPT)); // the newest is still remembered
    expect(f.c.getSnapshot().prompts.map((p) => p.requestId)).toEqual([uuid(0)]);
  });

  it("drops a prompt locally at expires_in_ms + 5 s, sending nothing", () => {
    const f = fixture();
    f.requested(RID, PEER, 10_000);
    vi.advanceTimersByTime(10_000 + PROMPT_GRACE_MS - 1);
    expect(f.c.getSnapshot().prompts).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(f.c.getSnapshot().prompts).toEqual([]);
    expect(f.calls).toEqual([]);
    f.requested(RID, PEER, 10_000); // a duplicate delivery of the expired prompt stays suppressed
    expect(f.c.getSnapshot().prompts).toEqual([]);
  });

  it("an answered prompt's expiry timer is cancelled", () => {
    const f = fixture();
    f.requested(RID, PEER, 1000);
    f.c.answer(RID, true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("holder prompt naming", () => {
  it("uses a known participant's display name, else the generic label; the session id is never shown", () => {
    const participants = [{ session_id: PEER, display_name: "Pat" }, { session_id: "other" }];
    expect(holderPromptLabel(PEER, participants)).toBe("Pat");
    expect(holderPromptLabel("other", participants)).toBe(GENERIC_HOLDER_LABEL);
    expect(holderPromptLabel("<img src=x onerror=alert(1)>", participants)).toBe("Another technician");
  });
});

describe("announcement wiring", () => {
  // The vitest env is node with no DOM, so (like m3_wiring.test.ts) the interactive session's wiring is pinned by source.

  it("only the interactive session announces, once, right after it asks for its other capabilities", () => {
    const app = appSource;
    expect(app.match(/announceInputRequestCapable\(\)/g)).toHaveLength(1);
    expect(app).toMatch(/control\.requestBackstageFeatures\(\);[\s\S]{0,700}control\.announceInputRequestCapable\(\);/);
    expect(app).toContain("onInputRequestMessage");
  });

  it("the bulk-run core neither announces nor installs a request handler", () => {
    const core = coreSource;
    expect(core).not.toMatch(/announceInputRequestCapable|onInputRequestMessage|InputRequestCapable/);
  });
});
