/**
 * Which console areas a user can use at all (menu redesign wave 5, Codex menu review 2026-11-07). Ordinary technicians were shown
 * Users, Roles, API tokens, Webhooks, Security and Install DeskRally, all of which answered them with a 403. Appearance is NOT gated:
 * every member reads the branding (GET /tenant/branding and /revisions need no capability) and the page shows them a read-only view.
 *
 * ONE table: each gated area lists the capabilities (any of them) whose holder can use it, taken from the server route each
 * area's page reads or writes (GET /users needs manage_users, and so on). It is informational only: every route still authorizes
 * for itself; this only decides what the menu offers.
 *
 * Unknown means visible: until GET /me has answered, or when it carries no capability list (an older server), nothing is hidden.
 * A page must never vanish because the console does not know yet.
 */

export const AREA_CAPABILITIES: Readonly<Record<string, readonly string[]>> = {
  machines: ["view_machines"],
  machinegroups: ["view_machines"],
  groups: ["view_machines"],
  sites: ["view_machines"],
  attended: ["view_sessions", "start_session"],
  sessions: ["view_sessions"],
  reports: ["view_sessions"],
  audit: ["view_audit"],
  enrollment: ["manage_enrollment", "deploy_agent"],
  toolbox: ["start_session", "manage_toolbox"],
  users: ["manage_users"],
  roles: ["manage_roles"],
  security: ["manage_tenant"],
  apitokens: ["manage_tenant"],
  webhooks: ["manage_tenant"],
};

/** `held`: the capabilities from GET /me, or null when unknown (not answered yet, or an older server without the list). */
export function areaVisible(area: string, held: ReadonlySet<string> | null): boolean {
  if (held === null) return true;
  const needs = AREA_CAPABILITIES[area];
  if (!needs) return true; // live, account, help: always; recordings and platform have their own probes
  return needs.some((c) => held.has(c));
}

/** The capability set from GET /me's list, or null when it is empty (an older server sends none). */
export function heldCapabilities(caps: readonly { capability: string }[] | undefined): ReadonlySet<string> | null {
  if (!caps || caps.length === 0) return null;
  return new Set(caps.map((c) => c.capability));
}
