/**
 * Scheduled access windows (docs/57): the API shape, its display, and the editor's draft. Pure, so the
 * UsersPanel's Access column, its editor and the invite form are unit-tested without rendering.
 *
 * A window is days + [start, end) wall-clock times in an IANA time zone. A day names the day the window
 * STARTS; an end at or before the start runs past midnight into the next day. "24:00" ends at midnight.
 */

export interface AccessWindow {
  days: string[]; // "sun".."sat", any order
  start: string; // "HH:MM"
  end: string; // "HH:MM", "24:00" allowed
  time_zone: string;
}

/** The editor order (Mon first) and labels. */
export const WINDOW_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const DAY_LABELS: Record<string, string> = { mon: "Mon", tue: "Tue", wed: "Wed", thu: "Thu", fri: "Fri", sat: "Sat", sun: "Sun" };

/** "Mon–Fri", "Mon, Wed", "Sat, Sun", "Every day". Runs follow the Mon-first order and do not wrap. */
export function daysLabel(days: readonly string[]): string {
  const on = WINDOW_DAYS.map((d) => days.includes(d));
  if (on.every(Boolean)) return "Every day";
  const parts: string[] = [];
  for (let i = 0; i < 7; ) {
    if (!on[i]) {
      i++;
      continue;
    }
    let j = i;
    while (j + 1 < 7 && on[j + 1]) j++;
    const a = DAY_LABELS[WINDOW_DAYS[i]];
    const b = DAY_LABELS[WINDOW_DAYS[j]];
    if (j - i >= 2) parts.push(`${a}–${b}`);
    else if (j === i) parts.push(a);
    else parts.push(a, b);
    i = j + 1;
  }
  return parts.join(", ");
}

/** "Mon–Fri 08:00–18:00 (Europe/London)". */
export function windowLabel(w: AccessWindow): string {
  return `${daysLabel(w.days)} ${w.start}–${w.end} (${w.time_zone})`;
}

/** Whether a window runs past midnight (its end is at or before its start). */
export function crossesMidnight(start: string, end: string): boolean {
  return end !== "24:00" && end <= start;
}

/** A defensive read of the server's `access_window` (null for anything malformed or absent). */
export function readWindow(v: unknown): AccessWindow | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  if (!Array.isArray(o.days) || !o.days.every((d) => typeof d === "string")) return null;
  if (typeof o.start !== "string" || typeof o.end !== "string" || typeof o.time_zone !== "string") return null;
  return { days: o.days as string[], start: o.start, end: o.end, time_zone: o.time_zone };
}

/** The editor's state for one window. `enabled` false = any time. */
export interface WindowDraft {
  enabled: boolean;
  days: string[];
  start: string;
  end: string; // "HH:MM" from the time input; ignored when endOfDay
  endOfDay: boolean;
  zone: string;
}

/** The browser's zone, or UTC when it cannot say. */
export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** A draft pre-filled from a stored window, or the defaults (weekdays 08:00–18:00, browser zone). */
export function draftFromWindow(w: AccessWindow | null, defaultZone: string): WindowDraft {
  if (!w) {
    return { enabled: false, days: ["mon", "tue", "wed", "thu", "fri"], start: "08:00", end: "18:00", endOfDay: false, zone: defaultZone };
  }
  const endOfDay = w.end === "24:00";
  return { enabled: true, days: [...w.days], start: w.start, end: endOfDay ? "" : w.end, endOfDay, zone: w.time_zone };
}

const CLOCK = /^([01]\d|2[0-3]):[0-5]\d$/;

/** The API value for a draft: null for "any time", a window, or an error to show. */
export function draftToWindow(d: WindowDraft): { window: AccessWindow | null } | { error: string } {
  if (!d.enabled) return { window: null };
  const days = WINDOW_DAYS.filter((x) => d.days.includes(x));
  if (days.length === 0) return { error: "Choose at least one day." };
  if (!CLOCK.test(d.start)) return { error: "Enter a start time." };
  const end = d.endOfDay ? "24:00" : d.end;
  if (!d.endOfDay && !CLOCK.test(end)) return { error: "Enter an end time, or choose end of day." };
  if (end === d.start) return { error: "The start and end times must differ." };
  if (d.zone.trim() === "") return { error: "Choose a time zone." };
  return { window: { days: [...days], start: d.start, end, time_zone: d.zone.trim() } };
}

/** Toggle one day in a list (keeps no duplicates). */
export function toggleDay(days: readonly string[], day: string): string[] {
  return days.includes(day) ? days.filter((d) => d !== day) : [...days, day];
}

/**
 * The zone choices: the browser's IANA list when it has one, PLUS "UTC" and the stored/selected zone
 * (so an existing window always displays as stored, alias or not). Sorted, de-duplicated.
 */
export function timeZoneOptions(...extra: (string | null | undefined)[]): string[] {
  let list: string[] = [];
  try {
    const sv = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
    if (typeof sv === "function") list = sv("timeZone");
  } catch {
    list = [];
  }
  const all = new Set<string>([...list, "UTC"]);
  for (const z of extra) if (z) all.add(z);
  return [...all].sort((a, b) => a.localeCompare(b));
}
