/**
 * Appearance form gating. The inputs may only be edited once the initial branding read succeeded
 * (`loaded`) and never while a save is in flight (`busy`), so neither server response can overwrite
 * an edit the administrator made while it was pending.
 */
export function brandingControlsDisabled(loaded: boolean, busy: boolean): boolean {
  return !loaded || busy;
}

/**
 * The PUBLIC join-page section (docs/66 2j) has the same rule plus one: only an Owner (`manage_tenant`) may edit and
 * submit. A member sees the same fields read-only, and so does everyone until the state read AND the capability read
 * have both succeeded (an unreadable capability is "not an Owner": the server would refuse the submit anyway).
 */
export function publicJoinControlsDisabled(loaded: boolean, busy: boolean, isOwner: boolean): boolean {
  return brandingControlsDisabled(loaded, busy) || !isOwner;
}

/** Does the signed-in user hold `manage_tenant`? (`GET /me` capabilities; an older server sends none.) */
export function canManageTenant(capabilities: readonly { capability: string }[]): boolean {
  return capabilities.some((c) => c.capability === "manage_tenant");
}
