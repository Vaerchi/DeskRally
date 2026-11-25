import { describe, expect, it } from "vitest";
import { groupToolboxItems, splitToolboxName } from "./toolbox_folders";

describe("toolbox folders (name prefix)", () => {
  it("splits at the last slash and trims", () => {
    expect(splitToolboxName("Maintenance/Clear temp")).toEqual({ folder: "Maintenance", leaf: "Clear temp" });
    expect(splitToolboxName(" Network / DNS / Flush cache ")).toEqual({ folder: "Network/DNS", leaf: "Flush cache" });
    expect(splitToolboxName("Disk usage")).toEqual({ folder: "", leaf: "Disk usage" });
    // A slash with nothing on one side is not a folder.
    expect(splitToolboxName("/Root")).toEqual({ folder: "", leaf: "/Root" });
    expect(splitToolboxName("Trailing/")).toEqual({ folder: "", leaf: "Trailing/" });
  });

  it("groups unfiled first, then folders A-Z, items A-Z within", () => {
    const names = ["zeta/b", "Zeta/a", "Alpha/x", "loose", "Another", "Alpha/A"];
    const groups = groupToolboxItems(names.map((name) => ({ name })));
    expect(groups.map((g) => [g.folder, g.items.map((i) => i.name)])).toEqual([
      ["", ["Another", "loose"]],
      ["Alpha", ["Alpha/A", "Alpha/x"]],
      ["Zeta", ["Zeta/a", "zeta/b"]],
    ]);
  });
});
