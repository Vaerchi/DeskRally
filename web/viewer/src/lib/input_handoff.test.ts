import { describe, it, expect } from "vitest";
import {
  NO_INPUT_HANDOFF,
  INPUT_CONTROL_ERROR_PREFIX,
  handoffAdvertised,
  handRefused,
  handRequested,
  handTimedOut,
  handTargetLabel,
  resolveHandTarget,
  inputControlChanged,
  inputHandoffView,
  isInputControlError,
} from "./input_handoff";

const ME = "aaaaaaaa-0000-0000-0000-000000000001";
const PEER = "bbbbbbbb-0000-0000-0000-000000000002";
const OBSERVER = "cccccccc-0000-0000-0000-000000000003";
const participants = [
  { session_id: ME, technician_id: "11111111-tech", access: "control" },
  { session_id: PEER, technician_id: "22222222-tech", access: "control" },
  { session_id: OBSERVER, technician_id: "33333333-tech", access: "view_only" },
];
const advertised = handoffAdvertised(NO_INPUT_HANDOFF, true);

describe("input hand-off model (docs/61)", () => {
  it("offers nothing until the agent advertises affirmatively (an old agent never does)", () => {
    const v = inputHandoffView(NO_INPUT_HANDOFF, false, ME, participants);
    expect(v.show).toBe(false);
    expect(v.badge).toBeNull();
    expect(inputHandoffView(handoffAdvertised(NO_INPUT_HANDOFF, false), false, ME, participants).show).toBe(false);
  });

  it("never offers the action to an observer, who still sees who has control", () => {
    const owned = inputControlChanged(advertised, PEER, "owned");
    const v = inputHandoffView(owned, true, ME, participants);
    expect(v.show).toBe(false);
    expect(v.canHand).toBe(false);
    expect(v.badge).toBe("Another technician has input control");
  });

  it("does not offer the action before our own signaling id is known", () => {
    expect(inputHandoffView(advertised, false, null, participants).show).toBe(false);
  });

  it("targets other CONTROLLING technicians only — never itself, never an observer", () => {
    const v = inputHandoffView(advertised, false, ME, participants);
    expect(v.targets.map((t) => t.sessionId)).toEqual([PEER]);
    expect(v.canHand).toBe(true);
    expect(v.status).toMatch(/shared/);
    expect(v.badge).toBeNull(); // compatibility mode shows no indicator
  });

  it("only the owner can hand on; everyone else sees who has it", () => {
    const mine = inputHandoffView(inputControlChanged(advertised, ME, "owned"), false, ME, participants);
    expect(mine.youHaveControl).toBe(true);
    expect(mine.canHand).toBe(true);
    expect(mine.badge).toBe("You have input control");
    const theirs = inputHandoffView(inputControlChanged(advertised, PEER, "owned"), false, ME, participants);
    expect(theirs.canHand).toBe(false);
    expect(theirs.disabledReason).toMatch(/only they can hand it on/);
  });

  it("a locked machine can be claimed, not handed", () => {
    const v = inputHandoffView(inputControlChanged(advertised, null, "blocked"), false, ME, participants);
    expect(v.canClaim).toBe(true);
    expect(v.canHand).toBe(false);
    expect(v.badge).toBe("Input locked");
  });

  it("a pending hand disables both actions until an outcome arrives", () => {
    const pending = handRequested(advertised);
    const v = inputHandoffView(pending, false, ME, participants);
    expect(v.canHand).toBe(false);
    expect(v.disabledReason).toMatch(/Waiting/);
    // The snapshot is the outcome: it ends the wait.
    expect(inputControlChanged(pending, PEER, "owned").pending).toBe(false);
  });

  it("attributes only prefixed agent errors to the hand, and a refusal changes no ownership", () => {
    expect(isInputControlError(`${INPUT_CONTROL_ERROR_PREFIX}that technician is no longer in this session`)).toBe(true);
    expect(isInputControlError("session ended: lease lapsed")).toBe(false);
    const owned = handRequested(inputControlChanged(advertised, ME, "owned"));
    const refused = handRefused(owned, `${INPUT_CONTROL_ERROR_PREFIX}a hand-off is already in progress`);
    expect(refused.pending).toBe(false);
    expect(refused.error).toBe("a hand-off is already in progress");
    expect(refused.mode).toBe("owned");
    expect(refused.ownerSession).toBe(ME);
  });

  it("an unanswered hand times out so the technician can retry; a settled one is untouched", () => {
    const pending = handRequested(advertised);
    expect(handTimedOut(pending).pending).toBe(false);
    expect(handTimedOut(pending).error).toMatch(/result is unknown/);
    expect(handTimedOut(advertised)).toBe(advertised);
  });

  it("owner is dropped for non-owned snapshots", () => {
    const m = inputControlChanged(advertised, PEER, "blocked");
    expect(m.ownerSession).toBeNull();
  });

  it("never substitutes another technician for a pick that left (Codex 3d review)", () => {
    const two = [{ sessionId: "s-1", label: "a" }, { sessionId: "s-2", label: "b" }];
    expect(resolveHandTarget(two, "")).toBeNull(); // several targets: an explicit pick is required
    expect(resolveHandTarget(two, "s-2")).toBe("s-2");
    expect(resolveHandTarget(two, "s-gone")).toBeNull(); // the pick left: choose again
    // A pick that left is void even when one target remains: no substitution, choose again.
    expect(resolveHandTarget([two[1]], "s-gone")).toBeNull();
    expect(resolveHandTarget([two[1]], "")).toBe("s-2"); // never picked: the lone target is named on the button
    expect(resolveHandTarget([], "s-1")).toBeNull();
  });

  it("labels carry no ordinal and include the session id (one technician can have several)", () => {
    expect(handTargetLabel({ session_id: "bbbbbbbb-1", technician_id: "22222222-x", access: "control" }))
      .toBe("Technician 22222222 · session bbbbbbbb");
    expect(handTargetLabel({ session_id: "cccccccc-1" })).toBe("Technician · session cccccccc");
  });

  it("says neither 'you' nor 'another' before our own id is known", () => {
    const v = inputHandoffView(inputControlChanged(advertised, PEER, "owned"), false, null, participants);
    expect(v.badge).toBe("One technician has input control");
  });

  it("labels targets stably regardless of push order", () => {
    const reversed = [...participants].reverse();
    const a = inputHandoffView(advertised, false, OBSERVER, participants).targets;
    const b = inputHandoffView(advertised, false, OBSERVER, reversed).targets;
    expect(a).toEqual(b);
  });
});
