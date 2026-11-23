import { expect, it } from "vitest";
import { machinePropertyKeys, togglePropertyColumn } from "./machine_property_columns";

it("collects the sorted union of own property keys across loaded rows", () => {
  expect(machinePropertyKeys([
    { properties: { site: "HQ", rack: "" } },
    {},
    { properties: { site: "Branch", constructor: "custom" } },
  ])).toEqual(["constructor", "rack", "site"]);
  expect(machinePropertyKeys([])).toEqual([]);
});

it("toggles property columns without mutating the selection and preserves column order", () => {
  const initial = ["site", "rack"];
  const added = togglePropertyColumn(initial, "owner");
  expect(added).toEqual(["site", "rack", "owner"]);
  expect(togglePropertyColumn(added, "rack")).toEqual(["site", "owner"]);
  expect(initial).toEqual(["site", "rack"]);
});
