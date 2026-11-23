import { afterEach, expect, it, vi } from "vitest";
import { Children, isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { FieldsPanel } from "./FieldsPanel";
import { BulkPropertyResults } from "./MachinesPanel";
import { DefinedProperty, MachinePropertiesPanel } from "./MachinePropertiesPanel";
import { ConsoleApiError, type ConsoleApi, type MachineField } from "../lib/console_api";
import { areaVisible } from "../lib/area_visibility";
import { CONSOLE_AREAS } from "../lib/console_areas";
import appSource from "../App.tsx?raw";

// The suite uses the Node environment. Drive effects and event handlers directly for the
// async panel flows, and use React's server renderer to check the resulting markup.
const harness = vi.hoisted(() => ({
  active: false,
  slots: [] as { value: unknown }[],
  index: 0,
  effects: [] as (() => void)[],
  mounted: false,
}));

vi.mock("react", async (importOriginal) => {
  const react = await importOriginal<typeof import("react")>();
  const state = (initial: unknown) => {
    const slot = harness.index++;
    const stored = harness.slots[slot] ??= { value: typeof initial === "function" ? initial() : initial };
    return [stored.value, (value: unknown) => {
      stored.value = typeof value === "function" ? value(stored.value) : value;
    }];
  };
  return {
    ...react,
    useState: (initial?: unknown) => harness.active ? state(initial) : react.useState(initial),
    useRef: (initial: unknown) => harness.active ? state({ current: initial })[0] : react.useRef(initial),
    useCallback: (fn: () => unknown, deps: []) => harness.active ? fn : react.useCallback(fn, deps),
    useEffect: (fn: () => void, deps: []) => {
      if (!harness.active) react.useEffect(fn, deps);
      else if (!harness.mounted) harness.effects.push(fn);
    },
  };
});

function renderPanel(render: () => ReactElement) {
  harness.active = true;
  harness.index = 0;
  try {
    const result = render();
    harness.mounted = true;
    return result;
  } finally {
    harness.active = false;
  }
}

async function runMountEffects() {
  for (const effect of harness.effects.splice(0)) effect();
  // Each mock response resolves immediately. Drain the effect promise chains.
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

function findAction(node: ReactNode, label: string): (() => void) | undefined {
  if (!isValidElement<{ "aria-label"?: string; children?: ReactNode; onClick?: () => void }>(node)) return undefined;
  if (node.props["aria-label"] === label) return node.props.onClick;
  return Children.toArray(node.props.children).map((child) => findAction(child, label)).find(Boolean);
}

afterEach(() => {
  harness.slots = [];
  harness.effects = [];
  harness.mounted = false;
});

const field: MachineField = { key: "flag", id: "a", version: 1, position: 0, label: "Flag", type: "boolean", choices: null };
const second = { ...field, id: "b", key: "score", label: "Score", type: "number" as const, position: 1 };

it("requires an all-groups manage_tenant grant and places Fields under Admin outside the session header", () => {
  const manage = { capability: "manage_tenant", all_groups: false, group_ids: ["g"] };
  const view = { capability: "view_machines", all_groups: true, group_ids: [] };
  const held = new Set(["manage_tenant", "view_machines"]);
  expect(areaVisible("fields", null)).toBe(false);
  expect(areaVisible("fields", held, [manage, view])).toBe(false);
  expect(areaVisible("fields", held, [{ ...manage, all_groups: true }, { ...view, all_groups: false }])).toBe(true);
  expect(CONSOLE_AREAS.find(({ id }) => id === "fields")).toMatchObject({ group: "Admin", label: "Fields" });
  const header = appSource.match(/<header className=\{`app__topbar[\s\S]*?<\/header>/)?.[0];
  expect(header).toBeTruthy();
  expect(header).not.toMatch(/FieldsPanel|machine-fields|machine-field-order/);
});

it("reloads after a stale reorder and shows report unavailable without querying it", async () => {
  const listMachineFields = vi.fn()
    .mockResolvedValueOnce({ fields: [field, second], order_revision: 7 })
    .mockResolvedValueOnce({ fields: [field], order_revision: 8 });
  const reorderMachineFields = vi.fn().mockRejectedValue(new ConsoleApiError(409, "machine field changed, retry"));
  const reportMachineField = vi.fn();
  const api = { listMachineFields, reorderMachineFields, reportMachineField } as unknown as ConsoleApi;
  const render = () => renderPanel(() => FieldsPanel({ api, canViewMachines: false }));
  render();
  await runMountEffects();
  const loaded = render();
  expect(renderToStaticMarkup(loaded)).toContain("Unavailable");
  expect(reportMachineField).not.toHaveBeenCalled();
  const move = findAction(loaded, "Move Flag down");
  expect(move).toBeDefined();
  move?.();
  expect(reorderMachineFields).toHaveBeenCalledWith(["score", "flag"], 7);
  await vi.waitFor(() => {
    const html = renderToStaticMarkup(render());
    expect(html).toContain("Fields changed. The list was reloaded.");
    expect(html).toContain("Move Flag up");
    expect(html).not.toContain("Move Score");
  });
  expect(listMachineFields).toHaveBeenCalledTimes(2);
});

it("keeps the free-form property editor and stored rows when definitions fail to load", async () => {
  const api = {
    listMachineFields: vi.fn().mockRejectedValue(new ConsoleApiError(404, "unknown route")),
    listMachineProperties: vi.fn().mockResolvedValue([{ key: "score", value: "1.00" }]),
  } as unknown as ConsoleApi;
  const render = () => renderPanel(() => MachinePropertiesPanel({ api, machineId: "m1" }));
  render();
  await runMountEffects();
  const html = renderToStaticMarkup(render());
  expect(html).toContain("Field definitions could not be loaded");
  expect(html).toContain('data-testid="property-add"');
  expect(html).toContain('data-testid="property-row-score"');
  expect(html).toContain("1.00");
});

it("renders typed editors and distinct unset, empty, false and nonconforming values", () => {
  const props = { disabled: false, onSave: async () => true, onClear: () => {} };
  const html = renderToStaticMarkup(<>
    <DefinedProperty {...props} field={field} stored={undefined} />
    <DefinedProperty {...props} field={field} stored="false" />
    <DefinedProperty {...props} field={second} stored="1.00" />
    <DefinedProperty {...props} field={{ ...field, type: "text" }} stored="" />
    <DefinedProperty {...props} field={{ ...field, type: "date" }} stored="2024-02-29" />
    <DefinedProperty {...props} field={{ ...field, type: "choice", choices: ["One", "Two"] }} stored="One" />
  </>);
  expect(html).toContain('aria-checked="mixed"');
  expect(html).toContain(">Unset<");
  expect(html).toContain(">Empty text<");
  expect(html).toContain(">false<");
  expect(html).toContain("Nonconforming value");
  expect(html).toContain("1.00");
  expect(html).toContain('inputMode="decimal"');
  expect(html).toContain('type="date"');
  expect(html).toContain('value="One" selected=""');
});

it("throws away invalid edits before saving and keeps the original draft for the server", async () => {
  const onSave = vi.fn().mockResolvedValue(true);
  const props = { disabled: false, onSave, onClear: () => {}, field: second, stored: undefined };
  const render = () => renderPanel(() => DefinedProperty(props));
  const change = (form: ReactElement, value: string) => {
    const label = Children.toArray(form.props.children)[0] as ReactElement;
    const input = Children.toArray(label.props.children)[1] as ReactElement;
    input.props.onChange(value);
  };
  change(render(), "1e2");
  const invalid = render();
  expect(renderToStaticMarkup(invalid)).toContain("Invalid value for field Score");
  invalid.props.onSubmit({ preventDefault() {} });
  expect(onSave).not.toHaveBeenCalled();
  change(render(), " 007.050 ");
  render().props.onSubmit({ preventDefault() {} });
  expect(onSave).toHaveBeenCalledWith(" 007.050 ");
  await Promise.resolve();
});

it("renders mixed property outcomes for each machine", () => {
  const html = renderToStaticMarkup(<BulkPropertyResults results={[
    { machine_id: "m1", ok: true },
    { machine_id: "m2", ok: false, error: "denied" },
    { machine_id: "m3", ok: false, error: "not set" },
  ]} />);
  expect(html).toContain("1 updated, 2 failed");
  expect(html).toContain("m1 — Updated");
  expect(html).toContain("m2 — denied");
  expect(html).toContain("m3 — not set");
});

