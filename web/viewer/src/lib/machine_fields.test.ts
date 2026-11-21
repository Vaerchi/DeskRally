import { describe, expect, it, vi } from "vitest";
import { ConsoleApiClient, type MachineField, type MachineRecord } from "./console_api";
import { canonicalFieldValue, compareFieldValues, fieldFilterOperand, storedFieldValue } from "./machine_fields";
import { machinesToCsv } from "./report_csv";

const numberField: MachineField = { id: "id", position: 0, version: 1, key: "score", label: "=Score, \"Q\"", type: "number", choices: null };

describe("field input matches the server", () => {
  it.each([
    [" 007.05000000 ", "7.05"], ["-000.100", "-0.1"], ["999999999999999.999999", "999999999999999.999999"],
    ["-0", undefined], ["-00.000", undefined], ["1e2", undefined], ["+1", undefined], ["1,2", undefined],
    ["1000000000000000", undefined], ["0.0000001", undefined], [" ".repeat(64) + "1", undefined],
    ["1\u0000", undefined], ["\t1", undefined], ["1\u2028", undefined], ["", undefined],
  ])("canonicalizes number %j to %j", (input, expected) => {
    expect(canonicalFieldValue(numberField, input)).toBe(expected);
  });

  it("validates dates, text, booleans and byte-exact choices", () => {
    const field = (type: MachineField["type"], choices: string[] | null = null) => ({ type, choices });
    expect(canonicalFieldValue(field("date"), " 2000-02-29 ")).toBe("2000-02-29");
    for (const date of ["1900-02-29", "2024-04-31", "1899-12-31", "3000-01-01", "2024-2-01"]) {
      expect(canonicalFieldValue(field("date"), date)).toBeUndefined();
    }
    expect(canonicalFieldValue(field("text"), "")).toBe("");
    expect(canonicalFieldValue(field("text"), " a ")).toBe(" a ");
    expect(canonicalFieldValue(field("boolean"), " false ")).toBe("false");
    expect(canonicalFieldValue(field("boolean"), "False")).toBeUndefined();
    expect(canonicalFieldValue(field("choice", ["É"]), " É ")).toBe("É");
    expect(canonicalFieldValue(field("choice", ["É"]), "é")).toBeUndefined();
    expect(canonicalFieldValue(field("choice", ["x"]), "x\u0085")).toBeUndefined();
  });

  it("sends canonical equality or the original raw legacy operand through the same API", async () => {
    const fetch = vi.fn(async (url: string) => {
      const operand = new URL(url, "https://example.test").searchParams.get("property_value");
      return Response.json({ machines: operand === "1.00" ? [{ id: "legacy" }] : [] });
    });
    const api = new ConsoleApiClient({ baseUrl: "/cp", fetch });
    const typed = { propertyKey: "score", propertyValue: fieldFilterOperand(numberField, "1.00") };
    const raw = { propertyKey: "score", propertyValue: fieldFilterOperand(undefined, "1.00") };
    expect(await api.listMachines(typed)).toEqual([]);
    expect(await api.listMachines(raw)).toMatchObject([{ id: "legacy" }]);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      "/cp/machines?property_key=score&property_value=1",
      "/cp/machines?property_key=score&property_value=1.00",
    ]);
  });
});

it("sorts exact decimal values, then unset, then raw nonconforming values in both directions, and exports that order", () => {
  const machine = (name: string, value?: string) =>
    ({ id: name, name, device_id: name, properties: value === undefined ? {} : { score: value } }) as MachineRecord;
  const rows = [
    machine("legacy", "=1+1"), machine("unset"), machine("higher", "999999999999999.000002"),
    machine("negative close", "-999999999999999.000001"), machine("lower", "999999999999999.000001"),
    machine("negative far", "-999999999999999.000002"), machine("zero", "0"),
  ];
  const sorted = (descending: boolean) => [...rows].sort((a, b) =>
    compareFieldValues(numberField, storedFieldValue(a, "score"), storedFieldValue(b, "score"), descending));
  const ascending = ["negative far", "negative close", "zero", "lower", "higher", "unset", "legacy"];
  const descending = ["higher", "lower", "zero", "negative close", "negative far", "unset", "legacy"];
  expect(sorted(false).map((row) => row.name)).toEqual(ascending);
  expect(sorted(true).map((row) => row.name)).toEqual(descending);
  const [header, ...csvRows] = machinesToCsv(sorted(true), ["score"], new Map([["score", numberField.label]])).trimEnd().split("\r\n");
  expect(header).toContain(`,"[text] =Score, ""Q"""`);
  expect(csvRows.map((row) => row.split(",")[0])).toEqual(descending);
  expect(csvRows[csvRows.length - 1]).toContain(',"[text] =1+1"');
});

it("sorts dates lexically, false before true, choices in definition order and stored empty text before unset", () => {
  expect(compareFieldValues({ type: "date", choices: null }, "1999-12-31", "2000-01-01", false)).toBeLessThan(0);
  expect(compareFieldValues({ type: "boolean", choices: null }, "false", "true", false)).toBeLessThan(0);
  expect(compareFieldValues({ type: "choice", choices: ["Z", "A"] }, "Z", "A", false)).toBeLessThan(0);
  expect(compareFieldValues({ type: "text", choices: null }, "", undefined, true)).toBeLessThan(0);
});

