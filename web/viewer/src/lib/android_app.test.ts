import { describe, expect, it } from "vitest";
import { AppSessionLink, appBridge, notificationName, sessionMessage, type AppBridge } from "./android_app";

class FakeBridge implements AppBridge {
  sent: string[] = [];
  onmessage: ((event: { data: unknown }) => void) | null = null;
  postMessage(m: string) { this.sent.push(m); }
}

describe("Android app bridge (docs/78)", () => {
  it("is absent in a browser", () => {
    expect(appBridge({})).toBeNull();
    expect(appBridge({ DeskRallyApp: { postMessage: "no" } })).toBeNull();
    const b = new FakeBridge();
    expect(appBridge({ DeskRallyApp: b })).toBe(b);
  });

  it("names the machine safely for the notification", () => {
    expect(notificationName("FRONT-DESK-01")).toBe("FRONT-DESK-01");
    expect(notificationName("a\u0000b\nc‮d")).toBe("a b c d");
    expect(notificationName("")).toBe("a machine");
    expect(notificationName("x".repeat(100)).length).toBe(60);
    expect(sessionMessage(true, "PC1")).toBe("session:on:PC1");
    expect(sessionMessage(false)).toBe("session:off");
  });

  it("reports only changes, ends the session on the app's request, and says off on dispose", () => {
    const b = new FakeBridge();
    let ended = 0;
    const link = new AppSessionLink(b, () => { ended++; });
    link.report(true, "PC1");
    link.report(true, "PC1");
    link.report(false);
    expect(b.sent).toEqual(["session:on:PC1", "session:off"]);
    b.onmessage?.({ data: "end" });
    b.onmessage?.({ data: "something else" });
    expect(ended).toBe(1);
    link.report(true, "PC2");
    link.dispose();
    expect(b.sent.slice(-2)).toEqual(["session:on:PC2", "session:off"]);
    expect(b.onmessage).toBeNull();
  });

  it("does nothing without a bridge", () => {
    const link = new AppSessionLink(null, () => {});
    expect(() => { link.report(true, "x"); link.dispose(); }).not.toThrow();
  });
});
