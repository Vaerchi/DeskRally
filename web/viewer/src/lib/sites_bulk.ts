/**
 * Sites bulk SET (docs/01 §4): assign ONE site to several explicitly selected, currently visible machines.
 * There is no bulk endpoint — each machine is written through the existing per-machine property route
 * (`saveMachineSite`, a single-key upsert that only resolves on an exact server echo), one at a time.
 * Removing a site is deliberately NOT part of a bulk operation.
 *
 * This module owns the pure parts: selection rules (visible-only, capped), the batch plan (validated
 * site + snapshot of targets) and the sequential runner with honest per-machine outcomes. The panel owns
 * state, the synchronous in-flight guard and publishing.
 */

import type { ConsoleApi } from "./console_api";
import { machineLabel, saveMachineSite, validateSite, type SiteRow, type SiteState } from "./sites";

/** The most machines one batch may target. Shown to the operator; never silently exceeded. */
export const BULK_SELECTION_CAP = 50;

export const BULK_CAP_HINT = `Select up to ${BULK_SELECTION_CAP} machines at a time.`;

const contextKeys = new WeakMap<object, number>();
let nextContextKey = 0;

/** A stable key per api object: a different api identity yields a different key (a fresh context). */
export function apiContextKey(api: object): number {
  let key = contextKeys.get(api);
  if (key === undefined) {
    key = ++nextContextKey;
    contextKeys.set(api, key);
  }
  return key;
}

/** Keep only selected ids that are in `visible`. Returns the SAME set when nothing was dropped. */
export function pruneSelection(selected: ReadonlySet<string>, visible: readonly SiteRow[]): ReadonlySet<string> {
  const shown = new Set(visible.map((r) => r.machine.id));
  let drop = false;
  for (const id of selected) if (!shown.has(id)) drop = true;
  if (!drop) return selected;
  return new Set([...selected].filter((id) => shown.has(id)));
}

export interface SelectionChange {
  selected: ReadonlySet<string>;
  /** True when the change was refused or truncated because of the cap. */
  capped: boolean;
}

/** Select/deselect one VISIBLE machine. A hidden id is never added; a new id beyond the cap is refused. */
export function toggleSelected(
  selected: ReadonlySet<string>,
  visible: readonly SiteRow[],
  id: string,
  on: boolean,
): SelectionChange {
  const base = pruneSelection(selected, visible);
  if (!on) {
    if (!base.has(id)) return { selected: base, capped: false };
    const next = new Set(base);
    next.delete(id);
    return { selected: next, capped: false };
  }
  if (base.has(id)) return { selected: base, capped: false };
  if (!visible.some((r) => r.machine.id === id)) return { selected: base, capped: false };
  if (base.size >= BULK_SELECTION_CAP) return { selected: base, capped: true };
  return { selected: new Set([...base, id]), capped: false };
}

/** Add visible machines in display order until the cap; `capped` when some visible rows were left out. */
export function selectVisible(selected: ReadonlySet<string>, visible: readonly SiteRow[]): SelectionChange {
  const next = new Set(pruneSelection(selected, visible));
  let capped = false;
  for (const r of visible) {
    if (next.has(r.machine.id)) continue;
    if (next.size >= BULK_SELECTION_CAP) {
      capped = true;
      break;
    }
    next.add(r.machine.id);
  }
  return { selected: next, capped };
}

export interface BulkTarget {
  readonly id: string;
  readonly label: string;
}

export type BulkPlan =
  | { ok: true; value: string; targets: readonly BulkTarget[] }
  | { ok: false; message: string };

/**
 * Snapshot a batch: the site validated by the existing `validateSite` (trimmed, UTF-8 byte cap) and the
 * selected machines that are visible RIGHT NOW, in display order. Hidden selected ids are never targets.
 */
export function planBulkAssign(selected: ReadonlySet<string>, visible: readonly SiteRow[], rawSite: string): BulkPlan {
  const v = validateSite(rawSite);
  if (!v.ok) return { ok: false, message: v.message };
  const targets = visible
    .filter((r) => selected.has(r.machine.id))
    .map((r): BulkTarget => Object.freeze({ id: r.machine.id, label: machineLabel(r.machine) }));
  if (targets.length === 0) return { ok: false, message: "select at least one machine" };
  if (targets.length > BULK_SELECTION_CAP) {
    return { ok: false, message: `too many machines selected: ${targets.length}, max ${BULK_SELECTION_CAP}` };
  }
  return { ok: true, value: v.value, targets: Object.freeze(targets) };
}

export type BulkOutcome =
  | { status: "saved"; id: string; label: string; site: SiteState }
  | { status: "failed"; id: string; label: string; error: string }
  | { status: "skipped"; id: string; label: string };

export interface BulkRun {
  outcomes: BulkOutcome[];
  /** True when `shouldContinue` turned false before every target was written. */
  stopped: boolean;
}

export interface BulkHooks {
  /** Checked before every request and again after every response (unmount / api change => false). */
  shouldContinue: () => boolean;
  /** Called for each machine that was attempted while still allowed to continue. */
  onOutcome?: (outcome: BulkOutcome) => void;
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Write `value` to each target's `site`, strictly one request at a time. A machine counts as saved only
 * when `saveMachineSite` resolved (exact key/value echo); a 403, any error or a mismatched echo is
 * "failed". Once `shouldContinue` is false no further request is issued and nothing more is reported
 * through `onOutcome` (a response that lands after a context change is dropped, not published).
 */
export async function runBulkAssign(
  api: Pick<ConsoleApi, "setMachineProperty">,
  targets: readonly BulkTarget[],
  value: string,
  hooks: BulkHooks,
): Promise<BulkRun> {
  const snapshot = [...targets];
  const outcomes: BulkOutcome[] = [];
  let stopped = false;
  for (const t of snapshot) {
    if (stopped || !hooks.shouldContinue()) {
      stopped = true;
      outcomes.push({ status: "skipped", id: t.id, label: t.label });
      continue;
    }
    let outcome: BulkOutcome;
    try {
      const site = await saveMachineSite(api, t.id, value);
      outcome = { status: "saved", id: t.id, label: t.label, site };
    } catch (e) {
      outcome = { status: "failed", id: t.id, label: t.label, error: errorText(e) };
    }
    if (!hooks.shouldContinue()) {
      stopped = true;
      outcomes.push({ status: "skipped", id: t.id, label: t.label });
      continue;
    }
    outcomes.push(outcome);
    hooks.onOutcome?.(outcome);
  }
  return { outcomes, stopped };
}

export interface BulkSummary {
  saved: number;
  failed: number;
  skipped: number;
  total: number;
  /** True only when every target was saved. */
  allSaved: boolean;
  message: string;
}

const machines = (n: number) => (n === 1 ? "machine" : "machines");

export function summarizeBulk(outcomes: readonly BulkOutcome[], site: string): BulkSummary {
  const saved = outcomes.filter((o) => o.status === "saved").length;
  const failed = outcomes.filter((o) => o.status === "failed").length;
  const skipped = outcomes.filter((o) => o.status === "skipped").length;
  const total = outcomes.length;
  const allSaved = total > 0 && saved === total;
  let message: string;
  if (allSaved) {
    message = `Site "${site}" set on ${saved} of ${total} ${machines(total)}.`;
  } else {
    const parts = [`${failed} failed`];
    if (skipped > 0) parts.push(`${skipped} not attempted`);
    message = `Site "${site}" set on ${saved} of ${total} ${machines(total)}; ${parts.join(", ")}. Failed machines stay selected so you can retry them.`;
  }
  return { saved, failed, skipped, total, allSaved, message };
}

/** Selection after a batch: saved machines leave it; failed and not-attempted ones stay for a retry. */
export function selectionAfterBatch(selected: ReadonlySet<string>, outcomes: readonly BulkOutcome[]): ReadonlySet<string> {
  const done = new Set(outcomes.filter((o) => o.status === "saved").map((o) => o.id));
  return new Set([...selected].filter((id) => !done.has(id)));
}
