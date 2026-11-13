import { describe, expect, it } from "vitest";
import { chromeMode, parseSessionChrome, tabMonitorButtons } from "./session_chrome";

const COMPOSITE = -1;

describe("parseSessionChrome", () => {
  it("defaults to minimal for absent or unknown values", () => {
    expect(parseSessionChrome(null)).toBe("minimal");
    expect(parseSessionChrome(undefined)).toBe("minimal");
    expect(parseSessionChrome("garbage")).toBe("minimal");
    expect(parseSessionChrome("minimal")).toBe("minimal");
  });
  it("honours pinned", () => {
    expect(parseSessionChrome("pinned")).toBe("pinned");
  });
});

describe("chromeMode", () => {
  it("is normal without a live session, whatever the preference", () => {
    expect(chromeMode(false, "minimal", false)).toBe("normal");
    expect(chromeMode(false, "minimal", true)).toBe("normal");
    expect(chromeMode(false, "pinned", false)).toBe("normal");
  });
  it("keeps today's layout when pinned", () => {
    expect(chromeMode(true, "pinned", false)).toBe("pinned");
    expect(chromeMode(true, "pinned", true)).toBe("pinned");
  });
  it("collapses behind the tab when minimal, overlays when opened", () => {
    expect(chromeMode(true, "minimal", false)).toBe("collapsed");
    expect(chromeMode(true, "minimal", true)).toBe("overlay");
  });
});

describe("tabMonitorButtons", () => {
  const two = [
    { value: 0, label: "Display 1 (1920×1080) ★" },
    { value: 1, label: "Display 2 (2560×1440)" },
    { value: COMPOSITE, label: "View all (composite)" },
  ];

  it("shows nothing for a single monitor", () => {
    expect(tabMonitorButtons([{ value: 0, label: "Display 1" }], 0, COMPOSITE)).toEqual([]);
  });

  it("numbers real monitors and labels the composite All, marking the active one", () => {
    expect(tabMonitorButtons(two, 1, COMPOSITE)).toEqual([
      { value: 0, text: "1", title: "Display 1 (1920×1080) ★", active: false },
      { value: 1, text: "2", title: "Display 2 (2560×1440)", active: true },
      { value: COMPOSITE, text: "All", title: "View all (composite)", active: false },
    ]);
  });

  it("numbers by position, not by monitor id", () => {
    const sparse = [
      { value: 7, label: "Left" },
      { value: 3, label: "Right" },
    ];
    expect(tabMonitorButtons(sparse, 3, COMPOSITE).map((b) => b.text)).toEqual(["1", "2"]);
  });
});
