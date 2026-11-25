import { describe, expect, it } from "vitest";
import { MAX_PARAM_VALUE_BYTES, paramValue, paramsForRun, paramsProblem, parseToolboxParams } from "./toolbox_params";

describe("parseToolboxParams (docs/75)", () => {
  it("reads names, Mandatory, types and literal defaults from a leading param block", () => {
    const body = `[CmdletBinding()]
param(
  # the account to reset
  [Parameter(Mandatory)][string]$User,
  [Parameter(Mandatory = $true)] [string] $NewPassword,
  [int]$Newest = 20,
  [string]$LogName = 'System',
  $Plain
)
Get-EventLog -LogName $LogName -Newest $Newest`;
    const { params, unsupported } = parseToolboxParams("powershell", body);
    expect(unsupported).toBe(false);
    expect(params.map((p) => [p.name, p.mandatory, p.type, p.defaultText])).toEqual([
      ["User", true, "string", ""],
      ["NewPassword", true, "string", ""],
      ["Newest", false, "int", "20"],
      ["LogName", false, "string", "System"],
      ["Plain", false, "", ""],
    ]);
    expect(params.find((p) => p.name === "NewPassword")?.secretLooking).toBe(true);
    expect(params.find((p) => p.name === "User")?.secretLooking).toBe(false);
  });

  it("has no parameters for cmd items, scripts without a block, or a param() that is not first", () => {
    expect(parseToolboxParams("cmd", "param($X)").params).toEqual([]);
    expect(parseToolboxParams("powershell", "Get-Date").params).toEqual([]);
    expect(parseToolboxParams("powershell", "Get-Date\nparam($X)").params).toEqual([]);
  });

  it("ignores parentheses and commas inside comments, strings and validation attributes", () => {
    const body = `<# block, comment ( with ) parens #>
param(
  [ValidateSet('a,b', 'c')][string]$Mode = 'x (y)',
  [ValidateRange(1, 5)][int]$Level
)`;
    expect(parseToolboxParams("powershell", body).params.map((p) => [p.name, p.type, p.defaultText])).toEqual([
      ["Mode", "string", "x (y)"],
      ["Level", "int", ""],
    ]);
  });

  it("marks credential parameters unsupported (docs/75 D9)", () => {
    const r = parseToolboxParams("powershell", "param([securestring]$Pw, [pscredential]$Cred, [string]$Ok)");
    expect(r.unsupported).toBe(true);
    expect(r.params.filter((p) => p.unsupported).map((p) => p.name)).toEqual(["Pw", "Cred"]);
  });
});

describe("paramsProblem / paramsForRun", () => {
  const parse = parseToolboxParams("powershell", "param([Parameter(Mandatory)]$User, $Opt = 'd')");

  it("requires mandatory values and sends only filled fields", () => {
    expect(paramsProblem({}, parse)).toBe("User is required.");
    expect(paramsProblem({ User: "alice" }, parse)).toBeNull();
    expect(paramsForRun({ User: "alice", Opt: "" }, parse.params)).toEqual({ User: "alice" });
  });

  it("refuses NUL and over-long values", () => {
    expect(paramsProblem({ User: "a\0b" }, parse)).toMatch(/NUL/);
    expect(paramsProblem({ User: "x".repeat(MAX_PARAM_VALUE_BYTES + 1) }, parse)).toMatch(/too long/);
  });

  it("refuses unsupported parameter kinds", () => {
    expect(paramsProblem({}, parseToolboxParams("powershell", "param([pscredential]$C)"))).toMatch(/cannot be filled/);
  });
});

describe("security review fixes (2026-11-24)", () => {
  it("a parameter named after an Object.prototype member reads as empty, not a function (SEC-005)", () => {
    const parse = parseToolboxParams("powershell", "param([Parameter(Mandatory)]$constructor, $toString)");
    expect(paramsProblem({}, parse)).toBe("constructor is required.");
    expect(paramsForRun({}, parse.params)).toEqual({});
    expect(paramValue({}, "constructor")).toBe("");
    expect(paramsForRun({ constructor: "x" }, parse.params)).toEqual({ constructor: "x" });
  });

  it("PowerShell common parameters are marked unsupported (SEC-002)", () => {
    const parse = parseToolboxParams("powershell", "param($ErrorAction, $OV, $Ok)");
    expect(parse.params.filter((p) => p.unsupported).map((p) => p.name)).toEqual(["ErrorAction", "OV"]);
  });

  it("masks key and pwd names", () => {
    const parse = parseToolboxParams("powershell", "param($ApiKey, $Pwd, $User)");
    expect(parse.params.map((p) => p.secretLooking)).toEqual([true, true, false]);
  });
});
