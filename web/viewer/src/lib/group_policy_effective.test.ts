import { describe, expect, it } from "vitest";
import type { GroupSessionCap, MachineGroup } from "./console_api";
import { effectivePolicyChips, effectivePolicyFor, effectivePolicyFromServer, policyConflictMessage } from "./group_policy_effective";

const g = (id: string, name: string, parent_id: string | null = null): MachineGroup => ({ id, name, parent_id });
const pol = (group_id: string, over: Partial<GroupSessionCap> = {}): GroupSessionCap => ({
  group_id,
  max_concurrent_sessions: 0,
  enforce_view_only: false,
  allow_backstage_under_view_only: false,
  prohibit_recording: false,
  require_recording: false,
  max_session_duration_seconds: 0,
  max_idle_seconds: 0,
  ...over,
});

// P (Acme) > C (Site A) > GC (Lab); S (Site B) is C's sibling.
const GROUPS = [g("p", "Acme"), g("c", "Site A", "p"), g("gc", "Lab", "c"), g("s", "Site B", "p")];

describe("effectivePolicyFor", () => {
  it("returns null for a group that is not in the list", () => {
    expect(effectivePolicyFor(GROUPS, [], "nope")).toBeNull();
  });

  it("an all-default tree has no restrictions", () => {
    const e = effectivePolicyFor(GROUPS, [], "gc")!;
    expect(effectivePolicyChips(e)).toEqual([]);
    expect(e.conflict).toBe(false);
  });

  it("a parent's require-recording reaches the child, marked inherited, and not the parent's sibling's row", () => {
    const pols = [pol("p", { require_recording: true })];
    const c = effectivePolicyFor(GROUPS, pols, "c")!;
    expect(c.requireRecording).toBe(true);
    expect(c.inherited).toContain("requireRecording");
    expect(effectivePolicyChips(c)).toEqual([{ text: "Recording required", inherited: true }]);
    // The parent itself sets it: not "inherited".
    const p = effectivePolicyFor(GROUPS, pols, "p")!;
    expect(effectivePolicyChips(p)).toEqual([{ text: "Recording required", inherited: false }]);
  });

  it("policy flows DOWN only: a child's setting never shows on its parent or sibling", () => {
    const pols = [pol("c", { enforce_view_only: true })];
    expect(effectivePolicyFor(GROUPS, pols, "p")!.viewOnly).toBe(false);
    expect(effectivePolicyFor(GROUPS, pols, "s")!.viewOnly).toBe(false);
    expect(effectivePolicyFor(GROUPS, pols, "gc")!.viewOnly).toBe(true);
  });

  it("a child cannot clear the parent's view-only (its own row says false, the effective is true)", () => {
    const pols = [pol("p", { enforce_view_only: true }), pol("c", { enforce_view_only: false })];
    expect(effectivePolicyFor(GROUPS, pols, "c")!.viewOnly).toBe(true);
  });

  it("durations are the smallest non-zero; 0 (unlimited) never wins", () => {
    const pols = [
      pol("p", { max_session_duration_seconds: 7200, max_idle_seconds: 600 }),
      pol("c", { max_session_duration_seconds: 3600, max_idle_seconds: 0 }),
      pol("gc", { max_session_duration_seconds: 0 }),
    ];
    const e = effectivePolicyFor(GROUPS, pols, "gc")!;
    expect(e.maxDurationSeconds).toBe(3600);
    expect(e.maxIdleSeconds).toBe(600);
    expect(e.inherited).toEqual(expect.arrayContaining(["maxDuration", "maxIdle"]));
  });

  it("seat cap is the minimum POSITIVE value, 0 = unlimited", () => {
    const pols = [pol("p", { max_concurrent_sessions: 5 }), pol("c", { max_concurrent_sessions: 0 }), pol("gc", { max_concurrent_sessions: 2 })];
    expect(effectivePolicyFor(GROUPS, pols, "gc")!.maxConcurrentSessions).toBe(2);
    expect(effectivePolicyFor(GROUPS, pols, "c")!.maxConcurrentSessions).toBe(5);
    expect(effectivePolicyFor(GROUPS, [pol("c", { max_concurrent_sessions: 0 })], "c")!.maxConcurrentSessions).toBe(0);
  });

  it("backstage opt-out is true only when EVERY view-only level allows it (a child cannot widen it)", () => {
    const strict = [
      pol("p", { enforce_view_only: true, allow_backstage_under_view_only: false }),
      pol("c", { enforce_view_only: true, allow_backstage_under_view_only: true }),
    ];
    const e = effectivePolicyFor(GROUPS, strict, "c")!;
    expect(e.allowBackstageUnderViewOnly).toBe(false);
    expect(e.inherited).toContain("backstageOptOut");
    const allowed = [
      pol("p", { enforce_view_only: true, allow_backstage_under_view_only: true }),
      pol("c", { enforce_view_only: true, allow_backstage_under_view_only: true }),
    ];
    expect(effectivePolicyFor(GROUPS, allowed, "c")!.allowBackstageUnderViewOnly).toBe(true);
  });

  it("a dormant opt-out value on a row that is not view-only never becomes a restriction", () => {
    // P allows the opt-out but is not view-only; C is view-only with the opt-out false. P's dormant value is
    // irrelevant; the only enforcing level is C, and it says false.
    const pols = [pol("p", { enforce_view_only: false, allow_backstage_under_view_only: true }), pol("c", { enforce_view_only: true })];
    expect(effectivePolicyFor(GROUPS, pols, "c")!.allowBackstageUnderViewOnly).toBe(false);
    // And a dormant FALSE on a non-view-only parent does not veto a view-only child that allows it.
    const pols2 = [pol("p", { enforce_view_only: false, allow_backstage_under_view_only: false }), pol("c", { enforce_view_only: true, allow_backstage_under_view_only: true })];
    expect(effectivePolicyFor(GROUPS, pols2, "c")!.allowBackstageUnderViewOnly).toBe(true);
  });

  it("require on the parent + prohibit on the child is a CONFLICT with an explicit message naming both sides", () => {
    const pols = [pol("p", { require_recording: true }), pol("c", { prohibit_recording: true })];
    const e = effectivePolicyFor(GROUPS, pols, "gc")!;
    expect(e.conflict).toBe(true);
    const msg = policyConflictMessage(e)!;
    expect(msg).toContain("required (Acme)");
    expect(msg).toContain("blocked (Acme › Site A)");
    expect(msg).toMatch(/refused/);
    // The parent alone is NOT in conflict, and neither is the sibling.
    expect(effectivePolicyFor(GROUPS, pols, "p")!.conflict).toBe(false);
    expect(effectivePolicyFor(GROUPS, pols, "s")!.conflict).toBe(false);
    expect(policyConflictMessage(effectivePolicyFor(GROUPS, pols, "s")!)).toBeNull();
  });

  it("a hidden ancestor contributes nothing (built only from visible groups)", () => {
    // Only C and GC are visible; C's parent "p" is not in the list, so P's policy cannot be applied here.
    const visible = [g("c", "Site A", "p"), g("gc", "Lab", "c")];
    const e = effectivePolicyFor(visible, [pol("p", { enforce_view_only: true }), pol("c", { max_concurrent_sessions: 3 })], "gc")!;
    expect(e.viewOnly).toBe(false);
    expect(e.maxConcurrentSessions).toBe(3);
  });
});

describe("effectivePolicyFromServer", () => {
  it("shows a restriction only the server knew about (the hidden ancestor's row is absent) as inherited", () => {
    // A {c}-scoped admin: the browser merge sees no rows at all and says "no restrictions".
    expect(effectivePolicyChips(effectivePolicyFor([g("c", "Site A"), g("gc", "Lab", "c")], [], "c")!)).toEqual([]);
    const e = effectivePolicyFromServer({ enforce_view_only: true, max_concurrent_sessions: 5 }, undefined);
    expect(effectivePolicyChips(e)).toEqual([
      { text: "View only", inherited: true },
      { text: "Under the Hood refused", inherited: false },
      { text: "5 sessions", inherited: true },
    ]);
  });

  it("does not mark a value inherited when the group's own row sets it", () => {
    const e = effectivePolicyFromServer({ prohibit_recording: true }, pol("c", { prohibit_recording: true }));
    expect(effectivePolicyChips(e)).toEqual([{ text: "Recording blocked", inherited: false }]);
  });

  it("carries the server's conflict reason into the warning", () => {
    const e = effectivePolicyFromServer({ require_recording: true, prohibit_recording: true, conflict: "needs a fix" }, undefined);
    expect(e.conflict).toBe(true);
    expect(policyConflictMessage(e)).toBe("Conflict: needs a fix.");
  });

  it("an empty server entry is no restriction", () => {
    expect(effectivePolicyChips(effectivePolicyFromServer({}, undefined))).toEqual([]);
  });
});
