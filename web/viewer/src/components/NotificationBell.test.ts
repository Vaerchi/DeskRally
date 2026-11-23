import { describe, expect, it } from "vitest";
import type { AuditNotification, NotificationState } from "../lib/audit_notifications";
import { notificationBadge, notificationBellView, notificationTitle } from "./NotificationBell";

function note(partial: Partial<AuditNotification> & Pick<AuditNotification, "id">): AuditNotification {
  return { action: "session.start", severity: "info", occurredAt: "2026-10-29T10:00:00Z", seen: false, ...partial };
}

function state(items: AuditNotification[]): NotificationState {
  return { items, knownIds: items.map((n) => n.id), highWaterMs: 0, primed: true };
}

describe("notificationBadge", () => {
  it("hides at zero, shows the count, and saturates at 99+", () => {
    expect(notificationBadge(0)).toBeNull();
    expect(notificationBadge(-1)).toBeNull();
    expect(notificationBadge(1)).toBe("1");
    expect(notificationBadge(99)).toBe("99");
    expect(notificationBadge(100)).toBe("99+");
  });
});

describe("notificationTitle", () => {
  it("maps known actions to human phrases", () => {
    expect(notificationTitle("session.start")).toBe("Session started");
    expect(notificationTitle("api_token.mint")).toBe("API token created");
    expect(notificationTitle("session.elevation_minted")).toBe("Admin elevation granted");
    expect(notificationTitle("help.requested")).toBe("A machine asked for help");
    expect(notificationTitle("help.accepted")).toBe("A help request was taken");
  });

  it("falls back to the raw action for anything unmapped", () => {
    expect(notificationTitle("some.future.action")).toBe("some.future.action");
  });
});

describe("notificationBellView", () => {
  it("describes an empty, all-seen state", () => {
    const v = notificationBellView(state([]));
    expect(v.badge).toBeNull();
    expect(v.label).toBe("Notifications");
    expect(v.empty).toBe(true);
    expect(v.items).toEqual([]);
  });

  it("derives the badge/label from UNSEEN items and composes the target", () => {
    const v = notificationBellView(
      state([
        note({ id: "a", action: "session.start", severity: "info", targetKind: "machine", targetId: "m-1" }),
        note({ id: "b", action: "api_token.mint", severity: "security", occurredAt: "2026-10-29T09:00:00Z" }),
      ]),
    );
    expect(v.badge).toBe("2");
    expect(v.label).toBe("Notifications, 2 unread");
    expect(v.empty).toBe(false);
    expect(v.items[0]).toMatchObject({ id: "a", title: "Session started", severity: "info", target: "machine m-1" });
    expect(v.items[1]).toMatchObject({ id: "b", title: "API token created", severity: "security", target: "" });
  });

  it("shows history with no badge once everything is seen", () => {
    const v = notificationBellView(state([note({ id: "a", action: "grant.mint", severity: "security", seen: true })]));
    expect(v.badge).toBeNull();
    expect(v.empty).toBe(false);
    expect(v.items).toHaveLength(1);
  });

  it("counts only unseen items in a mixed list", () => {
    const v = notificationBellView(state([note({ id: "a", seen: true }), note({ id: "b", seen: false })]));
    expect(v.badge).toBe("1");
    expect(v.label).toBe("Notifications, 1 unread");
  });
});
