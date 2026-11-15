/**
 * Display + encoding helpers for expiring access (docs/56). Pure, so the UsersPanel's "Access" column,
 * its editor and the invite form's date are unit-tested without rendering (the viewer's convention).
 *
 * The server stores and returns UTC (RFC 3339); the operator thinks in local time, so the editor uses a
 * `datetime-local` input and these helpers convert at the boundary.
 */

export interface AccessFields {
  access_expires_at?: string | null;
  access_expired?: boolean;
}

/** "Never", "Expired", or "Expires <local date and time>". An older server sends neither field: Never. */
export function accessLabel(u: AccessFields, locale?: string): string {
  if (u.access_expired) return "Expired";
  if (!u.access_expires_at) return "Never";
  const at = new Date(u.access_expires_at);
  if (Number.isNaN(at.getTime())) return "Never";
  return `Expires ${formatExpiry(at, locale)}`;
}

/** A short, unambiguous local rendering: "5 Nov 2026, 17:00". */
export function formatExpiry(at: Date, locale?: string): string {
  return at.toLocaleString(locale, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

/**
 * A `datetime-local` value ("2026-11-05T17:00") → UTC RFC 3339 for the API ("2026-11-05T22:00:00Z"
 * in UTC-5). Empty or invalid → null. Seconds are dropped (the input has none), so the value is stable.
 */
export function localInputToISO(value: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi] = m.slice(1).map(Number);
  const at = new Date(y, mo - 1, d, h, mi); // LOCAL time
  if (Number.isNaN(at.getTime())) return null;
  // Reject anything the Date constructor NORMALIZED: an impossible calendar date (31 Feb) or a local
  // time that does not exist because the clocks sprang forward over it (a DST gap). Silently moving the
  // deadline by an hour is worse than asking again. An AMBIGUOUS fall-back time (it occurs twice) keeps
  // the browser's choice, the earlier instant: access ending sooner is the safe side.
  if (at.getFullYear() !== y || at.getMonth() !== mo - 1 || at.getDate() !== d || at.getHours() !== h || at.getMinutes() !== mi) {
    return null;
  }
  return at.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** The inverse, to pre-fill the editor: an RFC 3339 instant → its LOCAL `datetime-local` value. */
export function isoToLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}
