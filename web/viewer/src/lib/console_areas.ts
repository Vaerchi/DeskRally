// The console's areas (pages) and the groups the menu and the top bar show them in. Moved out of App.tsx unchanged.

/**
 * M3: top-level console area. "live" is the original session workspace (connect/view/backstage);
 * the rest are the management panels over the control plane's data-plane endpoints. "attended"
 * is the on-demand session flow (docs/12 §9).
 */
export type ConsoleArea =
  | "live"
  | "attended"
  | "machines"
  | "sessions"
  | "audit"
  | "recordings"
  | "reports"
  | "platform"
  | "toolbox"
  | "security"
  | "sites"
  | "groups"
  | "machinegroups"
  | "apitokens"
  | "enrollment"
  | "webhooks"
  | "appearance"
  | "users"
  | "roles"
  | "account"
  | "help";

/**
 * The menu's groups, in display order (menu redesign wave 4, the operator's structure of 2026-11-07: Machines | Support | History |
 * Manage | Admin, then the account). Wave 10 turns the same groups into the visible top bar.
 */
export type ConsoleAreaGroup = "Machines" | "Support" | "History" | "Manage" | "Admin" | "Account" | "Platform";
export const CONSOLE_AREA_GROUPS: readonly ConsoleAreaGroup[] = ["Machines", "Support", "History", "Manage", "Admin", "Account", "Platform"];

export interface ConsoleAreaDef {
  id: ConsoleArea;
  label: string;
  group: ConsoleAreaGroup;
}

export const CONSOLE_AREAS: ConsoleAreaDef[] = [
  { id: "live", label: "Live", group: "Machines" },
  { id: "machines", label: "Machines", group: "Machines" },
  { id: "attended", label: "Support", group: "Support" },
  { id: "sessions", label: "Sessions", group: "History" },
  // Shown only to a principal the server lets list recordings (view_recordings); see `visibleAreas`.
  { id: "recordings", label: "Recordings", group: "History" },
  { id: "audit", label: "Audit", group: "History" },
  { id: "reports", label: "Reports", group: "History" },
  // Internal ids are unchanged; only the labels were clarified. "sites" reads/writes the existing
  // machine `site` property; "machinegroups" are the static RBAC/policy groups.
  { id: "enrollment", label: "Install DeskRally", group: "Manage" },
  { id: "machinegroups", label: "Machine groups", group: "Manage" },
  { id: "groups", label: "Smart groups", group: "Manage" },
  { id: "sites", label: "Sites", group: "Manage" },
  { id: "toolbox", label: "Toolbox", group: "Manage" },
  { id: "users", label: "Users", group: "Admin" },
  { id: "roles", label: "Roles", group: "Admin" },
  { id: "security", label: "Security", group: "Admin" },
  { id: "apitokens", label: "API tokens", group: "Admin" },
  { id: "webhooks", label: "Webhooks", group: "Admin" },
  { id: "appearance", label: "Appearance", group: "Admin" },
  { id: "account", label: "My account", group: "Account" },
  { id: "help", label: "Help", group: "Account" },
  // Shown only to the platform operator (GET /platform/me); see `visibleAreas`.
  { id: "platform", label: "Platform", group: "Platform" },
];
