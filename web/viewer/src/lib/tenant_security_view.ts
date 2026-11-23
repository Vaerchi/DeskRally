/**
 * Pure presentation decisions for TenantSecurityPanel's read-gated controls. A setting that has not been
 * read from the server is UNKNOWN, never a default: the 2FA flag is tri-state (null = unknown) and the
 * session-limit form is only editable once the stored policy has been read, so an admin can neither see an
 * invented "off" nor save blank/default inputs over a policy they could not read.
 */

export interface TwoFactorControlState {
  /** Checked only when the server said true; unknown renders unchecked. */
  checked: boolean;
  disabled: boolean;
  /** Short note shown while the value is unknown; null once known. */
  note: string | null;
}

/** `value` is null until getTenantSecurityPolicy has succeeded; `busy` = a refresh is in flight. */
export function twoFactorControlState(value: boolean | null, busy: boolean, saving: boolean): TwoFactorControlState {
  if (value === null) {
    return {
      checked: false,
      disabled: true,
      note: busy ? "Loading current setting…" : "Current setting unknown (could not be read)",
    };
  }
  return { checked: value, disabled: saving, note: null };
}

/** The session-limit inputs and Save stay disabled until BOTH stored values are known (non-null). */
export function sessionLimitControlsDisabled(
  savedLimit: number | null,
  savedMaxAge: number | null,
  saving: boolean,
): boolean {
  return saving || savedLimit === null || savedMaxAge === null;
}
