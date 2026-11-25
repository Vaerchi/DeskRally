import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ProcessPanel } from "./ProcessPanel";
import type { ProcessRow } from "../backstage/panels";

const row = (cpu: number): ProcessRow => ({
  pid: 1, parent_pid: null, name: "busy.exe", cpu_percent: cpu, memory_bytes: 0, user: null, command_line: null,
});

describe("ProcessPanel CPU column (2026-11-25)", () => {
  it("shows CPU as a share of the whole machine once the processor count is known", () => {
    expect(renderToStaticMarkup(<ProcessPanel rows={[row(400)]} logicalCpus={8} />)).toContain("50.0%");
  });
  it("never shows more than 100%", () => {
    expect(renderToStaticMarkup(<ProcessPanel rows={[row(900)]} logicalCpus={8} />)).toContain("100.0%");
  });
  it("shows the raw value until the count is known", () => {
    expect(renderToStaticMarkup(<ProcessPanel rows={[row(12.5)]} />)).toContain("12.5%");
  });
});