/**
 * The "Only at certain times" fields (docs/57), shared by the Access editor and the invite form. A
 * controlled component over a {@link WindowDraft}; the parent owns the draft and whether it changed.
 */

import { useMemo } from "react";
import { crossesMidnight, timeZoneOptions, toggleDay, WINDOW_DAYS, type WindowDraft } from "../lib/access_window";

export interface AccessWindowFieldsProps {
  draft: WindowDraft;
  onChange: (d: WindowDraft) => void;
  disabled?: boolean;
  /** data-testid prefix, e.g. "access-window" or "user-create-window". */
  testId: string;
  /** The stored zone, always offered even if the browser's list lacks it. */
  storedZone?: string | null;
}

const DAY_NAMES: Record<string, string> = { mon: "Mon", tue: "Tue", wed: "Wed", thu: "Thu", fri: "Fri", sat: "Sat", sun: "Sun" };

export function AccessWindowFields({ draft, onChange, disabled, testId, storedZone }: AccessWindowFieldsProps) {
  const zones = useMemo(() => timeZoneOptions(storedZone, draft.zone), [storedZone, draft.zone]);
  const set = (patch: Partial<WindowDraft>) => onChange({ ...draft, ...patch });
  return (
    <fieldset className="panel__window" data-testid={testId}>
      <label className="panel__scope-group">
        <input
          type="checkbox"
          checked={draft.enabled}
          onChange={(e) => set({ enabled: e.target.checked })}
          disabled={disabled}
          data-testid={`${testId}-enabled`}
        />
        Only at certain times
      </label>
      {draft.enabled && (
        <>
          <div className="panel__window-days" role="group" aria-label="Days">
            {WINDOW_DAYS.map((d) => (
              <label key={d} className="panel__scope-group">
                <input
                  type="checkbox"
                  checked={draft.days.includes(d)}
                  onChange={() => set({ days: toggleDay(draft.days, d) })}
                  disabled={disabled}
                  data-testid={`${testId}-day-${d}`}
                />
                {DAY_NAMES[d]}
              </label>
            ))}
          </div>
          <div className="panel__window-times">
            <label>
              From{" "}
              <input
                type="time"
                className="panel__input"
                value={draft.start}
                onChange={(e) => set({ start: e.target.value })}
                disabled={disabled}
                data-testid={`${testId}-start`}
              />
            </label>
            <label>
              Until{" "}
              <input
                type="time"
                className="panel__input"
                value={draft.endOfDay ? "" : draft.end}
                onChange={(e) => set({ end: e.target.value })}
                disabled={disabled || draft.endOfDay}
                data-testid={`${testId}-end`}
              />
            </label>
            <label className="panel__scope-group">
              <input
                type="checkbox"
                checked={draft.endOfDay}
                onChange={(e) => set({ endOfDay: e.target.checked })}
                disabled={disabled}
                data-testid={`${testId}-end-of-day`}
              />
              end of day
            </label>
            <select
              className="panel__select"
              value={draft.zone}
              onChange={(e) => set({ zone: e.target.value })}
              disabled={disabled}
              aria-label="Time zone"
              data-testid={`${testId}-zone`}
            >
              {zones.map((z) => (
                <option key={z} value={z}>
                  {z}
                </option>
              ))}
            </select>
          </div>
          <p className="panel__note">
            Days are the day the window starts
            {!draft.endOfDay && draft.end !== "" && crossesMidnight(draft.start, draft.end)
              ? "; this window runs past midnight into the next day"
              : "; an Until earlier than From runs past midnight"}
            . Follows local time, including daylight-saving changes.
          </p>
        </>
      )}
    </fieldset>
  );
}
