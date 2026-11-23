import { expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ConsoleApiClient } from "../lib/console_api";
import { RunHistoryRows } from "./RunHistory";

it("renders server snapshots, including ad-hoc and deleted items, and preserves result text", () => {
  const base = {
    request_id: "1", requested_at: "2026-11-20T10:00:00Z", technician_name: "Technician A",
    item_name: "Inventory", item_version: 3, item_deleted: true, run_as: "system", result: "exit 17",
  };
  const html = renderToStaticMarkup(<RunHistoryRows runs={[
    base,
    { ...base, request_id: "2", item_name: "ad-hoc command", item_version: undefined, item_deleted: false, result: "no result reported" },
  ]} />);
  for (const value of ["2026-11-20", "Technician A", "Inventory@3 (deleted)", "system", "exit 17", "ad-hoc command", "no result reported"]) {
    expect(html).toContain(value);
  }
});

it.each([200, 403])("hides empty or forbidden history (HTTP %s)", async (status) => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ runs: [] }), { status })));
  const api = new ConsoleApiClient({ baseUrl: "/cp", fetch });
  for (const scope of ["machines", "toolbox"] as const) {
    const page = await api.listRunHistory(scope, "id/1");
    expect(fetch).toHaveBeenLastCalledWith(expect.stringContaining(`/cp/${scope}/id%2F1/runs`), expect.objectContaining({ method: "GET" }));
    expect(renderToStaticMarkup(<RunHistoryRows runs={page?.runs ?? []} />)).toBe("");
  }
});
