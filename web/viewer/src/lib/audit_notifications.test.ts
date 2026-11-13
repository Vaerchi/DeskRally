import { describe, expect, it } from "vitest";
import type { MgmtAuditEvent } from "./console_api";
import {
  MAX_KNOWN_IDS,
  MAX_NOTIFICATIONS,
  dismissNotification,
  emptyNotificationState,
  ingestAuditEvents,
  isNotableAction,
  markAllSeen,
  newestInstantMs,
  notableActions,
  notableSeverity,
  primeNotificationState,
  unseenCount,
} from "./audit_notifications";

/**
 * The management-audit actions the server actually records (the Go `recordMgmtAudit` literals). Mirrored
 * so the notable set cannot reference an action no code path emits — a notification wired to a typo
 * would never fire, silently.
 */
const SERVER_ACTIONS = new Set<string>([
  "api_token.mint", "api_token.revoke", "attended.connect", "attended.create", "attended.end",
  "attended.promote", "enrollment_token.mint", "enrollment_token.revoke", "grant.mint",
  "group.create", "group.delete", "help.accepted", "help.cancelled", "help.expired", "help.reopened",
  "help.requested", "machine.alias_set", "machine.enroll", "machine.group_changed",
  "machine.note_set", "machine.property.delete", "machine.property.set", "machine.status_set",
  "machine_group.created", "machine_group.deleted", "machine_group.renamed",
  "machine_group.session_policy.set", "managed_install.download", "session.elevation_minted",
  "session.end", "session.note_set", "session.reaped", "session.start", "tenant.branding.set",
  "tenant.ip_allowlist.add", "tenant.ip_allowlist.remove", "tenant.security_policy.set",
  "tenant.session_policy.set", "tenant.sso_update", "webhook.create", "webhook.delete",
]);

function ev(id: string, action: string, occurredAt: string, extra: Partial<MgmtAuditEvent> = {}): MgmtAuditEvent {
  return { id, tenant_id: "t1", action, occurred_at: occurredAt, ...extra };
}

describe("notable classifier", () => {
  it("every notable action is a real server action", () => {
    for (const a of notableActions()) {
      expect(SERVER_ACTIONS.has(a), `notable action ${a} is not emitted by any server path`).toBe(true);
    }
  });

  it("includes credential REVOCATIONS and attended promote (review additions)", () => {
    expect(notableSeverity("api_token.revoke")).toBe("security");
    expect(notableSeverity("enrollment_token.revoke")).toBe("security");
    expect(notableSeverity("attended.promote")).toBe("info");
  });

  it("classifies session starts as info and credential changes as security", () => {
    expect(notableSeverity("session.start")).toBe("info");
    expect(notableSeverity("api_token.mint")).toBe("security");
    expect(notableSeverity("grant.mint")).toBe("security");
  });

  it("surfaces exactly two help-request transitions (docs/64): requested and accepted", () => {
    expect(notableSeverity("help.requested")).toBe("info");
    expect(notableSeverity("help.accepted")).toBe("info");
    // Cancel / expire / reopen are bookkeeping, not something a tenant-wide auditor needs badged.
    for (const a of ["help.cancelled", "help.expired", "help.reopened"]) expect(isNotableAction(a)).toBe(false);
  });

  it("treats routine actions as not notable", () => {
    for (const a of ["machine.note_set", "machine.alias_set", "session.note_set", "managed_install.download", "session.reaped", "session.end"]) {
      expect(isNotableAction(a), a).toBe(false);
    }
    expect(isNotableAction("totally.unknown")).toBe(false);
  });
});

describe("newestInstantMs (poll cursor)", () => {
  it("is the max parsed instant, 0 for empty, and handles fractional seconds", () => {
    expect(newestInstantMs([])).toBe(0);
    expect(
      newestInstantMs([ev("a", "session.start", "2026-10-29T10:00:00Z"), ev("b", "grant.mint", "2026-10-29T10:00:00.5Z")]),
    ).toBe(Date.parse("2026-10-29T10:00:00.5Z"));
  });
});

describe("priming the baseline", () => {
  it("sets primed and the cursor, remembers ids, and raises no unseen", () => {
    const primed = primeNotificationState(emptyNotificationState(), [
      ev("a", "session.start", "2026-10-29T10:00:00Z"),
      ev("b", "machine.note_set", "2026-10-29T10:05:00Z"),
    ]);
    expect(primed.primed).toBe(true);
    expect(unseenCount(primed)).toBe(0);
    expect(primed.items).toHaveLength(0);
    expect(primed.highWaterMs).toBe(Date.parse("2026-10-29T10:05:00Z"));
    expect(primed.knownIds).toEqual(["a", "b"]);
  });

  it("does NOT resurface the inclusive-since boundary event after priming", () => {
    // The boundary event existed before the console opened; a later poll re-returns it (since is
    // inclusive). Because prime remembered its id, ingest must not surface it as unread.
    const primed = primeNotificationState(emptyNotificationState(), [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    const after = ingestAuditEvents(primed, [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    expect(after.items).toHaveLength(0);
    expect(unseenCount(after)).toBe(0);
  });

  it("only moves the cursor forward", () => {
    const start = { ...emptyNotificationState(), highWaterMs: Date.parse("2026-10-29T12:00:00Z") };
    const primed = primeNotificationState(start, [ev("a", "session.start", "2026-10-29T09:00:00Z")]);
    expect(primed.highWaterMs).toBe(Date.parse("2026-10-29T12:00:00Z"));
  });
});

describe("ingesting new events", () => {
  it("surfaces only notable, unknown events and counts them unseen", () => {
    const s = ingestAuditEvents(emptyNotificationState(), [
      ev("a", "session.start", "2026-10-29T10:00:00Z"),
      ev("b", "machine.note_set", "2026-10-29T10:01:00Z"), // not notable
      ev("c", "api_token.mint", "2026-10-29T10:02:00Z"),
    ]);
    expect(s.items.map((n) => n.id)).toEqual(["c", "a"]); // newest first
    expect(unseenCount(s)).toBe(2);
    expect(s.highWaterMs).toBe(Date.parse("2026-10-29T10:02:00Z")); // advanced past the non-notable event
    expect(new Set(s.knownIds)).toEqual(new Set(["a", "b", "c"]));
  });

  it("orders by PARSED instant, not lexically (fractional seconds)", () => {
    // Lexically "…00Z" > "…00.5Z" ('Z' > '.'), but 00.000 is earlier than 00.5.
    const s = ingestAuditEvents(emptyNotificationState(), [
      ev("whole", "session.start", "2026-10-29T10:00:00Z"),
      ev("frac", "grant.mint", "2026-10-29T10:00:00.5Z"),
    ]);
    expect(s.items.map((n) => n.id)).toEqual(["frac", "whole"]); // frac is newer
    expect(s.highWaterMs).toBe(Date.parse("2026-10-29T10:00:00.5Z"));
  });

  it("dedupes an event already surfaced", () => {
    let s = ingestAuditEvents(emptyNotificationState(), [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    s = ingestAuditEvents(s, [ev("a", "session.start", "2026-10-29T10:00:00Z"), ev("b", "grant.mint", "2026-10-29T10:03:00Z")]);
    expect(s.items.map((n) => n.id)).toEqual(["b", "a"]);
    expect(unseenCount(s)).toBe(2);
  });

  it("does NOT resurrect a DISMISSED event on a boundary re-fetch", () => {
    let s = ingestAuditEvents(emptyNotificationState(), [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    s = dismissNotification(s, "a");
    s = ingestAuditEvents(s, [ev("a", "session.start", "2026-10-29T10:00:00Z")]); // re-returned by inclusive since
    expect(s.items).toHaveLength(0);
  });

  it("advances the cursor even when a batch is all non-notable", () => {
    const s = ingestAuditEvents(emptyNotificationState(), [
      ev("x", "machine.note_set", "2026-10-29T11:00:00Z"),
      ev("y", "session.reaped", "2026-10-29T11:01:00Z"),
    ]);
    expect(s.items).toHaveLength(0);
    expect(s.highWaterMs).toBe(Date.parse("2026-10-29T11:01:00Z"));
  });

  it("caps the visible list but REMEMBERS the capped-out ids so they never re-add", () => {
    const batch: MgmtAuditEvent[] = [];
    for (let i = 0; i < MAX_NOTIFICATIONS + 10; i++) {
      batch.push(ev(`id-${String(i).padStart(3, "0")}`, "session.start", `2026-10-29T10:${String(i).padStart(2, "0")}:00Z`));
    }
    let s = ingestAuditEvents(emptyNotificationState(), batch);
    expect(s.items).toHaveLength(MAX_NOTIFICATIONS);
    expect(s.items[0].id).toBe("id-059"); // newest kept
    expect(s.knownIds).toContain("id-000"); // a capped-out id is still remembered
    // Re-ingesting a capped-out id must not resurrect it.
    s = ingestAuditEvents(s, [ev("id-000", "session.start", "2026-10-29T10:00:00Z")]);
    expect(s.items.some((n) => n.id === "id-000")).toBe(false);
  });

  it("bounds the known-id memory", () => {
    const batch: MgmtAuditEvent[] = [];
    for (let i = 0; i < MAX_KNOWN_IDS + 50; i++) batch.push(ev(`e-${i}`, "machine.note_set", "2026-10-29T10:00:00Z"));
    const s = ingestAuditEvents(emptyNotificationState(), batch);
    expect(s.knownIds.length).toBe(MAX_KNOWN_IDS);
  });
});

describe("seen / dismiss (derived unseen)", () => {
  it("markAllSeen clears the count but keeps the history", () => {
    let s = ingestAuditEvents(emptyNotificationState(), [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    s = markAllSeen(s);
    expect(unseenCount(s)).toBe(0);
    expect(s.items).toHaveLength(1);
  });

  it("dismissing the only UNSEEN item leaves unseen at 0 (the aggregate-counter bug)", () => {
    // old item, already seen; then one genuinely new item arrives.
    let s = ingestAuditEvents(emptyNotificationState(), [ev("old", "session.start", "2026-10-29T10:00:00Z")]);
    s = markAllSeen(s);
    s = ingestAuditEvents(s, [ev("new", "grant.mint", "2026-10-29T10:05:00Z")]);
    expect(unseenCount(s)).toBe(1);
    s = dismissNotification(s, "new");
    expect(s.items.map((n) => n.id)).toEqual(["old"]);
    expect(unseenCount(s)).toBe(0); // NOT 1
  });

  it("dismiss of a missing id is a no-op (same reference)", () => {
    const s = ingestAuditEvents(emptyNotificationState(), [ev("a", "session.start", "2026-10-29T10:00:00Z")]);
    expect(dismissNotification(s, "missing")).toBe(s);
  });
});
