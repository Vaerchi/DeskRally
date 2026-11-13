import { describe, expect, it } from "vitest";
import {
  DIRECTIVE_STATE_INFO,
  canApproveDirective,
  canCancelDirective,
  canForgetFromRemoval,
  canOfferForget,
  canOfferReinstall,
  canOfferRemove,
  cancelWindow,
  directiveUiState,
  forgetDialogCopy,
  forgetOutcomeNote,
  formatCountdown,
  friendlyDirectiveError,
  isActiveDirective,
  holdsCapabilityAnywhere,
  holdsCapabilityForGroup,
  isRequester,
  POLL_FAST_MS,
  POLL_SLOW_MS,
  pollIntervalMs,
  staleNotice,
  readMeCapabilities,
  isStepUpRequired,
  removalConfirmationMatches,
  type AgentDirective,
} from "./fleet_directives";

const T0 = Date.parse("2026-10-31T10:00:00Z");
const dir = (over: Partial<AgentDirective> = {}): AgentDirective => ({
  id: "d1", machine_id: "m1", kind: "uninstall", state: "requested", requested_by: "u-req",
  requested_at: "2026-10-31T10:00:00Z", not_before: "2026-10-31T10:15:00Z", request_expires_at: "2026-10-31T11:00:00Z",
  require_approval: false, ...over,
});

describe("state model", () => {
  it("separates awaiting approval from requested, and delivered from issued", () => {
    expect(directiveUiState(dir())).toBe("requested");
    expect(directiveUiState(dir({ require_approval: true }))).toBe("awaiting_approval");
    expect(directiveUiState(dir({ require_approval: true, approved_by: "u2", approved_at: "2026-10-31T10:01:00Z" }))).toBe("requested");
    expect(directiveUiState(dir({ state: "issued" }))).toBe("issued");
    expect(directiveUiState(dir({ state: "issued", delivered_at: "2026-10-31T10:20:00Z" }))).toBe("delivered");
  });
  it("has a label and explanation for every state the server can send", () => {
    for (const s of ["requested", "issued", "accepted", "executing", "reboot_pending", "complete", "failed", "removal_unconfirmed", "cancelled", "expired", "forgotten"] as const) {
      const ui = directiveUiState(dir({ state: s }));
      expect(DIRECTIVE_STATE_INFO[ui].label.length).toBeGreaterThan(0);
      expect(DIRECTIVE_STATE_INFO[ui].explain.length).toBeGreaterThan(0);
    }
    expect(DIRECTIVE_STATE_INFO.removal_unconfirmed.explain).toBe(
      "The agent has not reported back; the machine stays retired and locked until it does, or until an owner forgets it.",
    );
  });
  it("removal_unconfirmed stays active (the machine remains guarded); terminals do not", () => {
    expect(isActiveDirective(dir({ state: "removal_unconfirmed" }))).toBe(true);
    expect(isActiveDirective(dir({ state: "executing" }))).toBe(true);
    for (const s of ["complete", "failed", "cancelled", "expired", "forgotten"] as const) expect(isActiveDirective(dir({ state: s }))).toBe(false);
  });
  it("a forgotten directive is the control plane's own terminal state: it says the agent never confirmed, and offers nothing", () => {
    const f = dir({ state: "forgotten" });
    expect(directiveUiState(f)).toBe("forgotten");
    expect(DIRECTIVE_STATE_INFO.forgotten.label).toBe("Forgotten");
    expect(DIRECTIVE_STATE_INFO.forgotten.explain).toMatch(/never confirmed/);
    expect(DIRECTIVE_STATE_INFO.forgotten.terminal).toBe(true);
    expect(canCancelDirective(f)).toBe(false);
    expect(canApproveDirective(f, "u-me")).toBe(false);
    expect(cancelWindow(f, T0).kind).toBe("none");
  });
  it("only a requested directive can be cancelled", () => {
    expect(canCancelDirective(dir())).toBe(true);
    expect(canCancelDirective(dir({ state: "issued" }))).toBe(false);
    expect(canCancelDirective(dir({ state: "executing" }))).toBe(false);
  });
});

describe("what is offered", () => {
  it("Remove only for retired machines and only with remove_agent", () => {
    expect(canOfferRemove({ status: "retired" }, true)).toBe(true);
    expect(canOfferRemove({ status: "retired" }, false)).toBe(false);
    for (const s of ["active", "quarantined", "removed", undefined]) expect(canOfferRemove({ status: s }, true)).toBe(false);
  });
  it("Reinstall only for active machines (absent status is active) and only with remove_agent", () => {
    expect(canOfferReinstall({}, true)).toBe(true);
    expect(canOfferReinstall({ status: "active" }, true)).toBe(true);
    expect(canOfferReinstall({ status: "active" }, false)).toBe(false);
    for (const s of ["retired", "quarantined", "removed"]) expect(canOfferReinstall({ status: s }, true)).toBe(false);
  });
  it("Approve is never offered to the requester (by /me user_id); an unknown own id leaves it to the server", () => {
    const d = dir({ require_approval: true });
    expect(canApproveDirective(d, "u-me")).toBe(true);
    expect(canApproveDirective(d, "u-req")).toBe(false);
    expect(isRequester(d, "someone-else")).toBe(false);
    expect(isRequester(d, null)).toBe(false);
    expect(canApproveDirective(d, null)).toBe(true);
    // Only a request awaiting approval can be approved.
    expect(canApproveDirective(dir(), "u-me")).toBe(false);
    expect(canApproveDirective(dir({ require_approval: true, approved_by: "u2", approved_at: "2026-10-31T10:01:00Z" }), "u-me")).toBe(false);
    expect(canApproveDirective(dir({ require_approval: true, state: "cancelled" }), "u-me")).toBe(false);
  });
});

describe("forget this machine (docs/65 sec. 8)", () => {
  it("is offered on RETIRED machines only (retire first, then forget) and only to a holder of remove_agent", () => {
    expect(canOfferForget({ status: "retired" }, true)).toBe(true);
    expect(canOfferForget({ status: "retired" }, false)).toBe(false);
    // Active and quarantined machines are still in service; a removed one has nothing left to forget; an absent status is active.
    for (const s of ["active", "quarantined", "removed", undefined]) expect(canOfferForget({ status: s }, true)).toBe(false);
  });
  it("is offered next to Remove for exactly the machines Remove is offered for (same status, same capability)", () => {
    for (const s of ["active", "quarantined", "retired", "removed", undefined]) {
      for (const holds of [true, false]) expect(canOfferForget({ status: s }, holds)).toBe(canOfferRemove({ status: s }, holds));
    }
  });
  it("the pending row offers it for an UNCONFIRMED removal on a machine that is still retired, and for nothing else", () => {
    const row = { kind: "uninstall" as const, state: "removal_unconfirmed" as const, machine_status: "retired" };
    expect(canForgetFromRemoval(row)).toBe(true);
    for (const state of ["requested", "issued", "accepted", "executing", "reboot_pending", "complete", "failed", "cancelled", "expired", "forgotten"] as const) {
      expect(canForgetFromRemoval({ ...row, state })).toBe(false);
    }
    expect(canForgetFromRemoval({ ...row, kind: "reinstall" })).toBe(false);
    for (const machine_status of ["active", "quarantined", "removed"]) expect(canForgetFromRemoval({ ...row, machine_status })).toBe(false);
  });
  it("the dialog says, in plain words, what it does, when to use it and that it uninstalls nothing", () => {
    const c = forgetDialogCopy({ name: "FRONT-DESK-7" });
    expect(c.title).toBe("Forget FRONT-DESK-7");
    expect(c.effect).toBe(
      "This permanently removes FRONT-DESK-7 from DeskRally. The machine can never reconnect with its current identity, and this cannot be undone. " +
        "Reinstalling the agent on it enrolls it as a new machine.",
    );
    expect(c.when).toBe("Use this when the machine is gone, or when its removal will never be confirmed by the agent.");
    expect(c.notice).toBe("It does not uninstall anything on the machine itself.");
  });
  it("names the machine by its friendly name when it has one (the typed name may be either)", () => {
    const c = forgetDialogCopy({ name: "FRONT-DESK-7", alias: "Reception PC" });
    expect(c.title).toBe("Forget Reception PC");
    expect(c.effect).toContain("permanently removes Reception PC from DeskRally");
    expect(c.effect).not.toContain("FRONT-DESK-7");
  });
  it("says what happened afterwards, and never that the agent confirmed anything", () => {
    expect(forgetOutcomeNote("forgotten", { name: "FRONT-DESK-7" })).toBe(
      "FRONT-DESK-7 was forgotten. It can no longer connect; reinstalling the agent on it enrolls it as a new machine.",
    );
    expect(forgetOutcomeNote("already_removed", { name: "FRONT-DESK-7", alias: "Reception PC" })).toBe("Reception PC was already removed. Nothing changed.");
    for (const o of ["forgotten", "already_removed"] as const) expect(forgetOutcomeNote(o, { name: "X" })).not.toMatch(/confirm/i);
  });
  it("the typed-name rule is the removal's (hostname or alias, exact), so the two dialogs cannot disagree", () => {
    const m = { name: "FRONT-DESK-7", alias: "Reception PC" };
    expect(removalConfirmationMatches("FRONT-DESK-7", m)).toBe(true);
    expect(removalConfirmationMatches(" Reception PC ", m)).toBe(true);
    expect(removalConfirmationMatches("front-desk-7", m)).toBe(false);
    expect(removalConfirmationMatches("", m)).toBe(false);
  });
  it("shows the server's refusals in friendly words", () => {
    const e = (status: number, detail: string, code?: string) => ({ status, message: `could not forget the machine: ${detail}`, code });
    expect(friendlyDirectiveError(e(403, "a recent second-factor verification is required", "step_up_required"), "forget")).toMatch(/authenticator code/);
    expect(friendlyDirectiveError(e(409, "a machine can only be forgotten after it is retired"), "forget")).toBe(
      "Retire the machine first: a machine can only be forgotten once it is retired.",
    );
    expect(friendlyDirectiveError(e(409, "machine changed since it was authorized; retry"), "forget")).toMatch(/changed while you were working/);
    expect(friendlyDirectiveError(e(422, "type the machine's name to confirm that it is forgotten"), "forget")).toBe("Type the machine's name exactly to confirm.");
    expect(friendlyDirectiveError(e(404, "unknown machine"), "forget")).toMatch(/no longer exists/);
    expect(friendlyDirectiveError(e(403, "forbidden: requires remove_agent"), "forget")).toBe("Not allowed: forbidden: requires remove_agent");
  });
});

describe("capabilities from /me", () => {
  const caps = readMeCapabilities([
    { capability: "view_machines", all_groups: true, group_ids: [] },
    { capability: "remove_agent", all_groups: false, group_ids: ["g1", "g1-child"] },
    { capability: 7 },
    null,
    { capability: "manage_users", all_groups: "yes", group_ids: "g1" },
  ]);
  it("drops malformed entries and treats a non-true all_groups as scoped", () => {
    expect(caps.map((c) => c.capability)).toEqual(["view_machines", "remove_agent", "manage_users"]);
    expect(caps[2]).toEqual({ capability: "manage_users", all_groups: false, group_ids: [] });
    expect(readMeCapabilities(undefined)).toEqual([]);
  });
  it("answers per machine group like the server (all groups, or the group is covered)", () => {
    expect(holdsCapabilityForGroup(caps, "view_machines", "anything")).toBe(true);
    expect(holdsCapabilityForGroup(caps, "remove_agent", "g1")).toBe(true);
    expect(holdsCapabilityForGroup(caps, "remove_agent", "g1-child")).toBe(true);
    expect(holdsCapabilityForGroup(caps, "remove_agent", "g2")).toBe(false);
    expect(holdsCapabilityForGroup(caps, "manage_machines", "g1")).toBe(false);
    expect(holdsCapabilityAnywhere(caps, "remove_agent")).toBe(true);
    expect(holdsCapabilityAnywhere(caps, "manage_machines")).toBe(false);
  });
});

describe("typed confirmation guard", () => {
  const m = { name: "FRONT-DESK-7", alias: "Reception PC" };
  it("accepts the exact hostname or alias (surrounding spaces trimmed, as the server does)", () => {
    expect(removalConfirmationMatches("FRONT-DESK-7", m)).toBe(true);
    expect(removalConfirmationMatches("  FRONT-DESK-7 ", m)).toBe(true);
    expect(removalConfirmationMatches("Reception PC", m)).toBe(true);
  });
  it("refuses empty, partial, wrong-case and a blank alias matching a blank entry", () => {
    expect(removalConfirmationMatches("", m)).toBe(false);
    expect(removalConfirmationMatches("   ", m)).toBe(false);
    expect(removalConfirmationMatches("front-desk-7", m)).toBe(false);
    expect(removalConfirmationMatches("FRONT-DESK", m)).toBe(false);
    expect(removalConfirmationMatches("", { name: "X", alias: "" })).toBe(false);
    expect(removalConfirmationMatches("anything", { name: "X" })).toBe(false);
  });
});

describe("cancel-window countdown", () => {
  it("counts down to not_before for a requested directive", () => {
    expect(cancelWindow(dir(), T0)).toEqual({ kind: "counting", msLeft: 15 * 60_000 });
    expect(cancelWindow(dir(), T0 + 14 * 60_000 + 59_000)).toEqual({ kind: "counting", msLeft: 1000 });
    expect(cancelWindow(dir(), T0 + 15 * 60_000).kind).toBe("ended");
    expect(cancelWindow(dir(), T0 + 16 * 60_000).kind).toBe("ended");
  });
  it("does not run while awaiting approval, and approval restarts it (the new not_before)", () => {
    expect(cancelWindow(dir({ require_approval: true }), T0).kind).toBe("needs_approval");
    const approved = dir({ require_approval: true, approved_by: "u2", approved_at: "2026-10-31T10:30:00Z", not_before: "2026-10-31T10:45:00Z" });
    expect(cancelWindow(approved, Date.parse("2026-10-31T10:30:00Z"))).toEqual({ kind: "counting", msLeft: 15 * 60_000 });
  });
  it("there is nothing to cancel once issued or cancelled", () => {
    expect(cancelWindow(dir({ state: "issued" }), T0).kind).toBe("none");
    expect(cancelWindow(dir({ state: "cancelled" }), T0).kind).toBe("none");
    expect(cancelWindow(dir({ not_before: "garbage" }), T0).kind).toBe("none");
  });
  it("formats m:ss and rounds up so it never reads 0:00 while still cancellable", () => {
    expect(formatCountdown(15 * 60_000)).toBe("15:00");
    expect(formatCountdown(61_000)).toBe("1:01");
    expect(formatCountdown(9_000)).toBe("0:09");
    expect(formatCountdown(1)).toBe("0:01");
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(-5)).toBe("0:00");
  });
});

describe("friendly errors", () => {
  const e = (status: number, detail: string, code?: string) => ({ status, message: `could not do it: ${detail}`, code });
  it("recognizes the step-up refusal by code or by its message", () => {
    expect(isStepUpRequired(e(403, "a recent second-factor verification is required", "step_up_required"))).toBe(true);
    expect(isStepUpRequired(e(403, "a recent second-factor verification is required"))).toBe(true);
    expect(isStepUpRequired(e(403, "forbidden"))).toBe(false);
    expect(isStepUpRequired(e(409, "a recent second-factor verification is required"))).toBe(false);
    expect(friendlyDirectiveError(e(403, "x", "step_up_required"), "uninstall")).toMatch(/authenticator code/);
  });
  it("409 keeps the server's reason and rewrites the known ones", () => {
    expect(friendlyDirectiveError(e(409, "machine already has an active directive"), "uninstall")).toMatch(/already has an agent action in progress/);
    expect(friendlyDirectiveError(e(409, "an agent on a retired machine can only be removed, not reinstalled"), "reinstall")).toMatch(/can only be removed, not reinstalled/);
    expect(friendlyDirectiveError(e(409, "an agent can only be removed from a retired machine"), "uninstall")).toMatch(/Retire the machine first/);
    expect(friendlyDirectiveError(e(409, "something new"), "approve")).toBe("Conflict: something new");
  });
  it("410, 429 (per action) and self-approval", () => {
    expect(friendlyDirectiveError(e(410, "directive expired"), "approve")).toMatch(/expired \(requests last 1 hour\)/);
    expect(friendlyDirectiveError(e(429, "directive quota exceeded"), "reinstall")).toMatch(/20 reinstalls per hour/);
    expect(friendlyDirectiveError(e(429, "directive quota exceeded"), "uninstall")).toMatch(/10 removals per hour/);
    expect(friendlyDirectiveError(e(403, "the requester cannot approve their own directive"), "approve")).toMatch(/different person/);
    expect(friendlyDirectiveError(e(403, "forbidden: needs remove_agent"), "cancel")).toBe("Not allowed: forbidden: needs remove_agent");
  });
});

describe("keeping the pending list fresh", () => {
  it("polls fast while a removal is in (or just past) its cancel window, slowly otherwise", () => {
    expect(pollIntervalMs([], T0)).toBe(POLL_SLOW_MS);
    expect(pollIntervalMs([dir()], T0)).toBe(POLL_FAST_MS); // 15 minutes left
    expect(pollIntervalMs([dir()], T0 + 16 * 60_000)).toBe(POLL_FAST_MS); // ended: being issued
    expect(pollIntervalMs([dir({ state: "issued" })], T0)).toBe(POLL_SLOW_MS);
    expect(pollIntervalMs([dir({ require_approval: true })], T0)).toBe(POLL_SLOW_MS); // awaiting approval: no window yet
    expect(pollIntervalMs([dir({ state: "issued" }), dir({ id: "d2" })], T0)).toBe(POLL_FAST_MS);
    expect(POLL_FAST_MS).toBeLessThan(POLL_SLOW_MS);
  });
  it("shows a stale notice only after a failed refresh, with the last good time", () => {
    expect(staleNotice(false, T0)).toBeNull();
    expect(staleNotice(false, null)).toBeNull();
    expect(staleNotice(true, null)).toMatch(/Could not refresh/);
    const at = new Date(2026, 9, 31, 9, 5, 7).getTime();
    expect(staleNotice(true, at)).toBe("Could not refresh — last updated 09:05:07");
  });
});
