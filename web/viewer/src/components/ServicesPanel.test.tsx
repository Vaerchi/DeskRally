import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ServicesPanel } from "./ServicesPanel";
import type { ServiceRow } from "../backstage/panels";

const rows: ServiceRow[] = [
  { name: "Spooler", display_name: "Print Spooler", state: "running", pid: 1234, start_type: "auto" },
  { name: "disk", display_name: "Disk Driver", state: "running", pid: null, start_type: "boot" },
  { name: "Old", display_name: "Old Agent Row", state: "stopped", pid: null },
];

describe("ServicesPanel startup type (1.3.38)", () => {
  it("shows the startup type as text when the agent cannot change it", () => {
    const html = renderToStaticMarkup(<ServicesPanel rows={rows} />);
    expect(html).toContain("Startup type");
    expect(html).toContain("Automatic");
    expect(html).not.toContain("<select");
  });

  it("offers a choice only for the four settable types, never for drivers or unknown rows", () => {
    const html = renderToStaticMarkup(<ServicesPanel rows={rows} onSetStartType={vi.fn()} />);
    expect(html).toContain('data-testid="svc-start-type-Spooler"');
    expect(html).not.toContain('data-testid="svc-start-type-disk"');
    expect(html).not.toContain('data-testid="svc-start-type-Old"');
    expect(html).toContain("Automatic (delayed start)");
    expect(html).toContain("Boot");
  });

  it("every row has exactly as many cells as the header (a merge once duplicated a row's cells)", () => {
    for (const props of [{}, { onControl: vi.fn() }, { onControl: vi.fn(), onSetStartType: vi.fn() }]) {
      const html = renderToStaticMarkup(<ServicesPanel rows={rows} {...props} />);
      const headers = (html.match(/<th[ >]/g) ?? []).length;
      const bodyRows = html.split("<tbody>")[1].split("</tr>").filter((r) => r.includes("<td"));
      expect(bodyRows).toHaveLength(rows.length);
      for (const r of bodyRows) expect((r.match(/<td[ >]/g) ?? []).length).toBe(headers);
    }
  });
});
