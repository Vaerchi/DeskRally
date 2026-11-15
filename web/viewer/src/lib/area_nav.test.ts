import { describe, expect, it } from "vitest";
import { areaBarItems, areaSubtabs } from "./area_nav";

const AREAS = [
  { id: "live", label: "Live", group: "Machines" },
  { id: "machines", label: "Machines", group: "Machines" },
  { id: "attended", label: "Support", group: "Support" },
  { id: "sessions", label: "Sessions", group: "History" },
  { id: "audit", label: "Audit", group: "History" },
  { id: "enrollment", label: "Install DeskRally", group: "Manage" },
  { id: "toolbox", label: "Toolbox", group: "Manage" },
  { id: "users", label: "Users", group: "Admin" },
  { id: "account", label: "My account", group: "Account" },
  { id: "help", label: "Help", group: "Account" },
];

describe("areaBarItems", () => {
  it("lists Machines | Support | History | Manage | Admin in order, direct or menu, and leaves Account out", () => {
    const items = areaBarItems(AREAS, "live");
    expect(items.map((i) => `${i.group}:${i.kind}`)).toEqual([
      "Machines:direct", "Support:direct", "History:direct", "Manage:menu", "Admin:menu",
    ]);
  });

  it("a direct group opens its first page; a menu group lists its pages", () => {
    const items = areaBarItems(AREAS, "live");
    const history = items.find((i) => i.group === "History");
    expect(history?.kind === "direct" && history.target.id).toBe("sessions");
    const manage = items.find((i) => i.group === "Manage");
    expect(manage?.kind === "menu" && manage.items.map((a) => a.id)).toEqual(["enrollment", "toolbox"]);
  });

  it("marks the group of the active page as current, and only that one", () => {
    expect(areaBarItems(AREAS, "audit").filter((i) => i.current).map((i) => i.group)).toEqual(["History"]);
    expect(areaBarItems(AREAS, "users").filter((i) => i.current).map((i) => i.group)).toEqual(["Admin"]);
    // A page that is not in the bar (My account) leaves every group unmarked.
    expect(areaBarItems(AREAS, "account").filter((i) => i.current)).toEqual([]);
  });

  it("leaves out a group with no page the role may use (wave 5 hid them all)", () => {
    const noAdmin = AREAS.filter((a) => a.group !== "Admin");
    expect(areaBarItems(noAdmin, "live").map((i) => i.group)).not.toContain("Admin");
  });

  it("shows Platform only when its page is passed in (the operator)", () => {
    expect(areaBarItems(AREAS, "live").map((i) => i.group)).not.toContain("Platform");
    const op = [...AREAS, { id: "platform", label: "Platform", group: "Platform" }];
    const groups = areaBarItems(op, "live").map((i) => i.group);
    expect(groups[groups.length - 1]).toBe("Platform");
  });
});

describe("areaSubtabs", () => {
  it("shows a direct group's pages as tabs when it has more than one", () => {
    expect(areaSubtabs(AREAS, "audit")?.pages.map((a) => a.id)).toEqual(["sessions", "audit"]);
    expect(areaSubtabs(AREAS, "live")?.pages.map((a) => a.id)).toEqual(["live", "machines"]);
  });

  it("shows none for a one-page group, a menu group, Account or an unknown page", () => {
    expect(areaSubtabs(AREAS, "attended")).toBeNull();
    expect(areaSubtabs(AREAS, "toolbox")).toBeNull();
    expect(areaSubtabs(AREAS, "account")).toBeNull();
    expect(areaSubtabs(AREAS, "nope")).toBeNull();
  });

  it("a History with only Sessions left (no audit/recordings for this role) needs no tabs", () => {
    const only = AREAS.filter((a) => a.id !== "audit");
    expect(areaSubtabs(only, "sessions")).toBeNull();
  });
});
