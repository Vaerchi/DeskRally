/**
 * Management-console API client (Milestone M3).
 *
 * A typed wrapper over the Go control plane's data-plane endpoints (`control-plane/http.go`):
 *
 *  - `GET  /machines`          → `{ "machines": [MachineRecord] }`
 *  - `GET  /sessions`          → `{ "sessions": [SessionRecord] }`
 *  - `POST /sessions`          body `{ machine_id }` (the DEVICE id) → 201 `{ "session": SessionRecord }`
 *  - `POST /sessions/{id}/end` → 200 `{ "session": SessionRecord }`
 *  - `GET  /audit?limit=N`     → `{ "events": [MgmtAuditEvent] }`
 *  - `GET  /tenants`           → `{ "tenants": [Tenant] }`
 *  - `POST /tenants`           body `{ slug, name, deployment_mode? }` → 201 `{ "tenant": Tenant }`
 *
 * The row interfaces mirror the Go structs' JSON tags EXACTLY (`machine.go`, `session_record.go`,
 * `mgmtaudit.go`, `tenant.go`) — snake_case names, the same optionality. Keep them in lockstep.
 *
 * ## Auth + errors
 * Every request sends `credentials: "include"` (the httpOnly session cookie from `/auth/login`;
 * DEV-mode stub auth needs nothing). Non-2xx responses become {@link ConsoleApiError}: the body's
 * `{"error": …}` message plus a {@link ConsoleApiErrorKind} so callers can branch — `401 →
 * "unauthenticated"` (log in first), `403 → "forbidden"` (capability denied), `409 → "conflict"`
 * (e.g. tenant slug taken).
 *
 * ## CSRF
 * The control plane is gaining double-submit CSRF: it will set a NON-httpOnly `rmt_csrf` cookie and
 * expect its value echoed in an `X-CSRF-Token` header on mutating requests. Mutations here already
 * echo the cookie when present (and send nothing when absent), so this client works both before and
 * after that lands.
 *
 * Base URL / CORS follows `controlplane.ts`: default is the Vite dev proxy prefix `/cp`.
 */

import { type AccessWindow, readWindow } from "./access_window";
import { DEFAULT_CONTROL_PLANE_URL, type FetchLike } from "./controlplane";
import type { ActiveDirective, ActiveDirectiveList, AgentDirective, DirectiveKind, DirectivePolicy, ForgetMachineResult, MeCapability } from "./fleet_directives";
import { readMeCapabilities } from "./fleet_directives";
import { parseBrandingRevisions, parseBrandRevisionResult, type BrandingRevisionsView, type BrandRevisionInput, type BrandRevisionResult } from "./brand_revisions";
import type { SignedSessionTicket } from "./protocol";
import { parseAdoption, parseReachReport, type Adoption, type ReachReport } from "./reach";
import {
  parseRecordingDetail,
  parseRecordingPage,
  parseRecordingPlaylist,
  parseRecordingPolicy,
  type RecordingDetail,
  type RecordingPage,
  type RecordingPlaylist,
  type RecordingPolicy,
  type RecordingPolicyBody,
} from "./recordings";

// ---------------------------------------------------------------------------
// Row shapes (mirrors of the Go structs' JSON output)
// ---------------------------------------------------------------------------

/**
 * One enrolled machine (Go `Machine`, machine.go). `id` is the DATABASE PRIMARY KEY; `device_id`
 * is the STABLE AGENT IDENTITY — the value session start and the viewer's connect path carry.
 * Never conflate the two.
 */
export interface MachineRecord {
  id: string;
  tenant_id: string;
  device_id: string;
  group_id: string;
  name: string;

  // --- console enrichment (control-plane migrations/0017) ---------------------------------
  // Display data only; group scoping still keys on `group_id`, never `group_name`.

  /** Free-text OS label captured at enrollment. Absent when the agent did not report one. */
  os?: string;
  /** `machine_group.name` for `group_id`, joined server-side so the UI need not resolve uuids. */
  group_name?: string;
  /**
   * TRI-STATE, matching Go's `*bool`: `true` (signaling has it connected), `false` (signaling
   * answered and it was absent), or **absent = UNKNOWN** (the presence feed could not be
   * consulted). Treat absent as unknown, never as offline — see `presence_known` on the listing.
   */
  online?: boolean;
  /** ISO timestamp of the last time the presence feed saw this device. Absent = never seen. */
  last_seen?: string;
  /**
   * Lifecycle status — 'active' | 'quarantined' | 'retired' (machine.status), plus the terminal 'removed'
   * (a confirmed agent removal, or a machine an Owner forgot: docs/65), which is never settable. A
   * quarantined/retired/removed machine is refused a new session server-side. Absent from very old
   * servers; treat absent as active.
   */
  status?: string;
  /**
   * Tenant-chosen FRIENDLY NAME (machine.alias) that overrides the agent-reported `name` (hostname)
   * for display when non-empty. Display-only; nothing authorizes on it. Absent/empty = show `name`.
   * Set via `setMachineAlias`.
   */
  alias?: string;
  /**
   * Free-text operator NOTE (machine.note) — unstructured context/handoff prose, distinct from the short
   * `alias` and from key/value properties. Display-only. Absent/empty = no note. Set via `setMachineNote`.
   */
  note?: string;
  /**
   * The agent's self-reported BUILD IDENTITY, `<semver>+<short git sha>` (control-plane
   * migrations/0039). Absent/empty = this machine has never reported one: a pre-0039 agent, or one
   * that has not reconnected since the column existed. Render that as "unknown", NEVER as
   * up-to-date — an unreported version is the one case where guessing is actively dangerous,
   * because a fleet that looks current is a rollout nobody checks.
   *
   * DISPLAY ONLY, and agent-asserted: it arrives before proof of possession, so nothing may branch
   * on it to grant authority. It is bounded server-side (64 bytes) at both signaling and the store.
   */
  agent_version?: string;
  /**
   * When the CURRENT `agent_version` was FIRST observed — not a heartbeat. Only moves when the
   * version actually changes, so it answers "when did this build land here". For liveness use
   * `last_seen`. Absent = no version has ever been reported.
   */
  agent_version_seen_at?: string;
  /**
   * Windows interactive-session username at the time of last agent registration, in
   * `DOMAIN\user` or plain `user` form. Absent/empty = agent did not report one (pre-R65
   * agent, non-Windows, or no interactive session). Display-only; nothing authorizes on it.
   * Bounded server-side (64 bytes) at both signaling and the store.
   */
  logged_in_user?: string;
  /**
   * Whether this machine can take an additional (observer) session. DERIVED by the control plane
   * from the agent version, with the same gate POST /sessions enforces for access=view_only
   * (control-plane/machine.go stampDerived); never stored.
   * TRI-STATE, matching Go's *bool: true = explicitly advertised, false = explicitly declined,
   * absent = not reported (older agent). NEVER gate authorization on this — it is agent-asserted
   * inventory, not a proof. Absent from very old control-plane versions; treat absent as unknown.
   */
  multi_session_capable?: boolean;
  /**
   * Agent-REPORTED, live-only (never stored): false = no pinned grant issuer key, so the view-only
   * mandate, session lease and signed grants are advisory on this machine. Absent = offline or an agent
   * that does not report posture (unknown). Display only; nothing authorizes on it.
   */
  grant_key_pinned?: boolean;
  /** Agent-reported, live-only: require_session_policy is on. "Enforced" needs this AND grant_key_pinned. */
  session_policy_required?: boolean;
}

/**
 * The machine lifecycle statuses the console may set (docs/01 §4). Mirrors the Go
 * MachineStatus* constants; the server re-validates every write (IsValidMachineStatus).
 */
export const MACHINE_STATUSES = ["active", "quarantined", "retired"] as const;

/** One machine's outcome in a BULK status change (docs/01 §4). `error` is a short reason when `ok` is false. */
export interface BulkStatusResult {
  machine_id: string;
  ok: boolean;
  error?: string;
}
/** One of the settable machine statuses. */
export type MachineStatus = (typeof MACHINE_STATUSES)[number];

/**
 * `GET /machines` envelope. `presence_known` is false when the control plane could not consult the
 * signaling presence feed, in which case every record's `online` is absent and the UI should say
 * "status unavailable" rather than rendering the whole fleet as offline.
 */
export interface MachineListing {
  machines: MachineRecord[];
  presenceKnown: boolean;
}

/**
 * One operator-set custom property on a machine (Go `MachineProperty`, control-plane
 * migrations/0024). Display/automation metadata only — nothing authorizes on it (RBAC scopes on the
 * machine's group). The machine PRIMARY KEY (`MachineRecord.id`), never the device id, addresses the
 * `/machines/{id}/properties` routes these come from. Mirror the Go struct's JSON tags exactly.
 */
export interface MachineProperty {
  key: string;
  value: string;
}

/**
 * A fleet search/filter by custom property (docs/01 §4). `propertyKey` restricts the machine listing
 * to machines carrying that property; `propertyValue`, when non-empty, restricts further to that exact
 * value (empty = any value). An empty/whitespace `propertyKey` means "no filter" (list everything).
 */
export interface MachinePropertyFilter {
  propertyKey: string;
  propertyValue?: string;
}

/**
 * The per-tenant IP allow-list (docs/01 §10): the source CIDRs this tenant permits on the
 * authenticated API, plus the caller's CURRENT source IP as the server sees it — the signal an admin
 * needs to avoid locking themselves out. An empty `cidrs` means no restriction (open).
 */
export interface TenantIPAllowlist {
  cidrs: string[];
  yourIp: string;
}

/**
 * Per-tenant white-label branding (docs/01 §9): the product name shown in the console title/header
 * and the accent colour applied to the `--accent` CSS variable. Empty fields mean "use the default".
 * Mirrors the Go `Branding`.
 */
export interface TenantBranding {
  product_name: string;
  accent_color: string;
  /** Empty, or a validated raster-image data URI the console header shows in an <img>. */
  logo_data_uri: string;
}

/**
 * A tenant's session policy (docs/01 §5 seat metering). `max_concurrent_sessions` caps how many
 * remote-support sessions the tenant may hold OPEN at once (0 = unlimited); `max_session_seconds` caps how
 * long a session may stay open before it is reaped (0 = no maximum). Both default to 0.
 */
export interface SessionPolicy {
  max_concurrent_sessions: number;
  max_session_seconds: number;
}

export interface TenantSecurityPolicy {
  require_2fa: boolean;
}

export interface SSOInfo {
  providers: { id: string; label: string }[];
}

export interface SSOSettings {
  profile: "entra";
  entra_tenant_id: string;
  client_id: string;
  enabled: boolean;
  trust_entra_mfa: boolean;
  has_secret: boolean;
  version: number;
  last_test: { version: number; at: string } | null;
  redirect_uri: string;
}

export interface SSOSettingsInput {
  entra_tenant_id: string;
  client_id: string;
  client_secret?: string;
  enabled: boolean;
  trust_entra_mfa: boolean;
}

export interface SSOTotpResult {
  user_id: string;
  tenant_id: string;
  expires_at: string;
  csrf_token: string;
  return_path: string;
}

function ssoSettingsFrom(body: unknown): SSOSettings {
  const r = body as Partial<SSOSettings> | null;
  if (!r || r.profile !== "entra" ||
      typeof r.entra_tenant_id !== "string" || typeof r.client_id !== "string" ||
      typeof r.enabled !== "boolean" || typeof r.trust_entra_mfa !== "boolean" ||
      typeof r.has_secret !== "boolean" || !Number.isSafeInteger(r.version) ||
      typeof r.version !== "number" || r.version < 0 || typeof r.redirect_uri !== "string" ||
      !(r.last_test === null || (r.last_test && Number.isSafeInteger(r.last_test.version) &&
        typeof r.last_test.at === "string"))) {
    throw new ConsoleApiError(200, "could not read SSO settings: malformed response", "server");
  }
  // Explicit projection keeps unexpected server fields, including secrets, out of the UI.
  return {
    profile: r.profile, entra_tenant_id: r.entra_tenant_id, client_id: r.client_id,
    enabled: r.enabled, trust_entra_mfa: r.trust_entra_mfa, has_secret: r.has_secret,
    version: r.version, last_test: r.last_test, redirect_uri: r.redirect_uri,
  };
}

/**
 * The operator-configured expected agent version (docs/01 §6 "Agent auto-update").
 * Returned by GET /agent-version. When `configured` is false, the operator has not
 * set AGENT_PUBLISHED_VERSION and the console should suppress outdated badges.
 */
export interface AgentVersionInfo {
  /** The expected build string, e.g. "0.0.1+abc1234". Absent when not configured. */
  version?: string;
  /** Whether the operator has configured a published version to compare against. */
  configured: boolean;
}

/** Whether `v` is a finite non-negative number. */
function isNonNegNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

/**
 * Parse a `/tenant/session-policy` response STRICTLY. A missing/mistyped field would otherwise read as 0,
 * which the console shows (and lets an admin save) as "unlimited" — so a malformed body is an error instead.
 */
function sessionPolicyFrom(body: unknown, action: string): SessionPolicy {
  const obj = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (!obj || !isNonNegNum(obj.max_concurrent_sessions) || !isNonNegNum(obj.max_session_seconds)) {
    throw new ConsoleApiError(200, `could not ${action}: malformed response (bad session policy)`, "server");
  }
  return {
    max_concurrent_sessions: obj.max_concurrent_sessions,
    max_session_seconds: obj.max_session_seconds,
  };
}

/** Parse a `/tenant/security-policy` response STRICTLY: `require_2fa` must be a boolean, never coerced. */
function tenantSecurityPolicyFrom(body: unknown, action: string): TenantSecurityPolicy {
  const obj = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (!obj || typeof obj.require_2fa !== "boolean") {
    throw new ConsoleApiError(200, `could not ${action}: malformed response (bad "require_2fa")`, "server");
  }
  return { require_2fa: obj.require_2fa };
}

/** Whether `s` is a `#rrggbb` hex colour. Mirrors the Go `IsHexColor`; empty is NOT a hex colour. */
export function isHexColor(s: string): boolean {
  return /^#[0-9a-fA-F]{6}$/.test(s);
}

/** Largest DECODED logo image, mirroring the Go `MaxLogoBytes`. */
export const MAX_LOGO_BYTES = 128 * 1024;

/**
 * Whether `s` is an acceptable logo: empty, or a base64 raster-image data URI of an allowed type
 * (PNG/JPEG/GIF/WebP — SVG is excluded). A structural mirror of the Go `logoDataURIRe` guard; the
 * server re-validates magic bytes + the decoded size cap. Used so the console never renders — and
 * never submits — a value the server would reject or that is not a plain data: image URI.
 */
export function isLogoDataUri(s: string): boolean {
  return s === "" || /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(s);
}

/**
 * The management view of a user for the console user list (docs/01 §5): identity, the disabled flag,
 * and the DISTINCT sorted keys of the roles the user holds. Mirrors the Go `UserSummary` (`roles` is
 * always an array server-side — never null).
 */
export interface UserSummary {
  id: string;
  email: string;
  display_name: string;
  disabled: boolean;
  roles: string[];
  /**
   * The user's effective machine-group scope (docs/55): an EMPTY array means tenant-wide ("all
   * groups"), a non-empty array is the group ids their memberships are scoped to. Optional so an
   * older server that doesn't send it reads as undefined (the console renders that as "all groups").
   */
  scoped_group_ids?: string[];
  /**
   * docs/56 expiring access: when the user's access ends (RFC 3339, UTC), null when it never does;
   * access_expired when every membership has expired (they can sign in but may do nothing). Optional
   * so an older server reads as "never".
   */
  access_expires_at?: string | null;
  access_expired?: boolean;
  /**
   * docs/57 scheduled access windows: the window when every membership carries the same one, else
   * null; access_window_varies when the memberships do not all carry the same window (a windowed +
   * unrestricted mix included), so null + !varies is genuinely "any time"; access_outside_window when
   * the user holds nothing right now because every unexpired membership is outside its hours.
   */
  access_window?: AccessWindow | null;
  access_window_varies?: boolean;
  access_outside_window?: boolean;
}

/** The signed-in user (`GET /me`): email plus docs/56/57 access state for the console banner. */
export interface MeInfo {
  email: string;
  /** The signed-in user's id (GET /me user_id); null from an older server. */
  userId: string | null;
  /** What the caller holds and where (GET /me capabilities); empty from an older server. See holdsCapabilityForGroup. */
  capabilities: MeCapability[];
  accessExpired: boolean;
  accessExpiresAt: string | null;
  accessWindow: AccessWindow | null;
  accessWindowVaries: boolean;
  accessOutsideWindow: boolean;
}

/**
 * One row of the §5 ROLES REFERENCE (`GET /roles`): a preset role and the capability KEYS it grants (e.g.
 * `manage_users`, `view_machines`). Read-only reference data sourced from the server's rbac vocabulary, so it
 * cannot drift from what is enforced. Mirrors the Go `roleCatalogEntry`.
 */
export interface RoleCatalogEntry {
  role: string;
  capabilities: string[];
}

/**
 * The preset roles the console may assign (docs/01 §5 role assignment), highest authority first.
 * Mirrors the Go `AssignableRoles()`. This list only shapes the picker — the SERVER re-validates every
 * assignment (`IsAssignableRole`) and additionally enforces the no-escalation rule (you can neither
 * act on someone more privileged than you nor grant a role beyond your own).
 */
export const ASSIGNABLE_ROLES = ["owner", "admin", "technician", "readonly", "auditor"] as const;
/** One of the assignable preset role keys. */
export type AssignableRole = (typeof ASSIGNABLE_ROLES)[number];

/** Optional parts of a role set (docs/55-57); undefined = preserve the stored value. */
export interface SetUserRoleOptions {
  expiresAt?: string | null;
  accessWindow?: AccessWindow | null;
  scopedGroupIds?: string[];
}

/**
 * The body of {@link ConsoleApi.createUser} — the console INVITE (docs/01 §5). `role` is one of
 * {@link ASSIGNABLE_ROLES}; `displayName` may be empty. The created account has no credential yet
 * (provisioned separately), and the server 409s a duplicate email.
 */
export interface CreateUserInput {
  email: string;
  displayName: string;
  role: string;
  /**
   * Optional machine-group scope for the new user (docs/55). Omitted/empty invites a tenant-wide
   * user; a non-empty set scopes the membership to those groups. A group-scoped admin can only invite
   * within their own groups (the server's no-escalation check), else the create is 403.
   */
  scopedGroupIds?: string[];
  /** docs/56: when the new user's access ends (RFC 3339); omitted/null = never. */
  expiresAt?: string | null;
  /** docs/57: the hours the new user may act; omitted/null = any time. Sent with the invite itself. */
  accessWindow?: AccessWindow | null;
}

/**
 * A credential-setup token (migration 0020) as returned by the mint endpoint. Only its metadata — the
 * PLAINTEXT secret rides {@link IssuedSetupLink.token} and is shown once. `expires_at` bounds the link's
 * life; the store supersedes any prior outstanding token for the same user on each new mint.
 */
export interface CredentialToken {
  id: string;
  tenant_id: string;
  user_id: string;
  created_by?: string;
  created_at: string;
  expires_at: string;
  consumed: boolean;
  revoked: boolean;
}

/**
 * The result of {@link ConsoleApi.issuePasswordReset}: the single-use plaintext `token` (shown ONCE —
 * only its hash is stored), the token metadata, and `firstProvision` = true when this account had no
 * password yet (a brand-new invite) vs. a reset of a live credential. Build the user-facing link with
 * {@link setupLinkUrl}.
 */
export interface IssuedSetupLink {
  token: string;
  credentialToken: CredentialToken;
  firstProvision: boolean;
}

/** The result of {@link ConsoleApi.redeemPasswordReset}: the password was set; prior sessions revoked. */
export interface RedeemSetupResult {
  changed: boolean;
  sessions_revoked: number;
}

/** Parse a `/tenant/branding` response defensively — a missing/mistyped field is an empty default. */
function brandingFrom(body: unknown): TenantBranding {
  const obj = body as Record<string, unknown> | null;
  return {
    product_name: typeof obj?.product_name === "string" ? obj.product_name : "",
    accent_color: typeof obj?.accent_color === "string" ? obj.accent_color : "",
    logo_data_uri: typeof obj?.logo_data_uri === "string" ? obj.logo_data_uri : "",
  };
}

/**
 * A dynamic machine group (docs/01 §4): a saved, named machine-property predicate. Its MEMBERS are not
 * stored — they are resolved live by `GET /dynamic-groups/{id}/machines`. `property_value === ""` means
 * "any value". Mirror the Go struct's JSON tags exactly.
 */
export interface DynamicGroup {
  id: string;
  name: string;
  property_key: string;
  property_value: string;
}

/** The body of `createDynamicGroup`. `propertyValue` is optional (empty = "any value"). */
export interface CreateDynamicGroupInput {
  name: string;
  propertyKey: string;
  propertyValue?: string;
}

/**
 * A STATIC machine group (docs/01 §4) — the `machine_group` row that is the RBAC scope unit and the
 * container a machine belongs to (its `group_id`). Distinct from a {@link DynamicGroup} (a saved
 * predicate). Mirrors the Go `MachineGroup` (id + name; names are not unique).
 */
export interface MachineGroup {
  id: string;
  name: string;
  /**
   * The parent group (docs/62: nested groups, access inherited downward). Absent on an older control plane;
   * `null` for a top-level group — AND for a group whose parent the caller cannot see (the server hides it).
   * The console builds paths only from the groups it was given (lib/group_tree.ts).
   */
  parent_id?: string | null;
}

/** The body of `createMachineGroup`. */
export interface CreateMachineGroupInput {
  name: string;
  /** Create under this group (a subgroup). Omitted or null = top level; sent only when set, for older servers. */
  parentId?: string | null;
}

/**
 * A machine group's concurrent-session cap (docs/01 §5 seat metering, loop 78). Mirrors the Go
 * `GroupSessionCap` is one machine group's session policy — TWO independent settings that share a row:
 * `max_concurrent_sessions` (0 = unlimited by group) and `enforce_view_only` (every session on a machine in
 * this group is admitted VIEW-ONLY, enforced by the AGENT via a control-plane-signed session policy the
 * technician cannot decline — docs/01 §5, loops 79/80; distinct from the technician's own view-only toggle,
 * which they may simply switch off again).
 *
 * `allow_backstage_under_view_only` is the third setting (migration 0040): the explicit per-group opt-out
 * that lets a view-only group still be issued BACKSTAGE grants — the remote shell and the tool panels — for
 * deliberate unattended maintenance. FALSE, the default, means the control plane REFUSES to mint a backstage
 * grant for machines in this group, which is what makes the "view only" label mean watch-only full stop.
 *
 * `prohibit_recording` is the fourth setting (migration 0043): when true the control plane mints
 * `allow_recording: false` into every signed session policy for this group, and the agent refuses
 * `StartRecording`. FALSE, the default, allows recording. The DB field is named for the RESTRICTION
 * (zero-value = permissive) so that a newly-added group row naturally permits recording; the signed-policy
 * field is named for the PERMISSION (`allow_recording`) for the same zero-value reason. Both spellings are
 * correct; do not unify them.
 *
 * `require_recording` is the fifth setting (migration 0044): when true the control plane mints
 * `require_recording: true` into every signed session policy for this group. The viewer auto-starts
 * recording and the agent refuses `StopRecording`. FALSE, the default, leaves recording optional.
 * Cannot be true at the same time as `prohibit_recording` — the API returns 400.
 *
 * It is named for the PERMISSION and not for the protection on purpose, and this mirror must keep that shape.
 * The PUT is a full overwrite, so a caller that omits the field writes `false` — and `false` has to be the
 * PROTECTED state, or every client that predates the field would silently switch the protection off on
 * whichever group it edited (docs/14 §0.1).
 *
 * `listGroupSessionPolicies` returns only the groups that have a row — i.e. those where an admin has set
 * SOMETHING. A group that is absent is uncapped AND not view-only. (Name kept as `GroupSessionCap` to avoid
 * churning every call site; it is no longer only a cap.)
 */
export interface GroupSessionCap {
  group_id: string;
  max_concurrent_sessions: number;
  enforce_view_only: boolean;
  allow_backstage_under_view_only: boolean;
  prohibit_recording: boolean;
  require_recording: boolean;
  /** Per-group hard session time limit in seconds; 0 = unlimited (migration 0045). */
  max_session_duration_seconds: number;
  /** Per-group idle timeout in seconds; 0 = unlimited (migration 0046). */
  max_idle_seconds: number;
}

const GROUP_POLICY_COUNT_FIELDS = ["max_concurrent_sessions", "max_session_duration_seconds", "max_idle_seconds"] as const;
const GROUP_POLICY_FLAG_FIELDS = [
  "enforce_view_only",
  "allow_backstage_under_view_only",
  "prohibit_recording",
  "require_recording",
] as const;

/**
 * One group's EFFECTIVE (own + inherited) policy as the control plane computed it: the merged values plus a
 * `conflict` reason when the hierarchy requires and prohibits recording. Seat-cap group ids are not carried.
 */
export type GroupEffectivePolicy = Omit<Partial<GroupSessionCap>, "group_id"> & { group_id?: string; conflict?: string };

/** GET /machine-groups/session-policies: the SET rows plus, from a current server, the effective map. */
export interface GroupSessionPolicyView {
  policies: GroupSessionCap[];
  /** group_id → effective policy for every group the caller manages; null when the server predates it. */
  effective: Readonly<Record<string, GroupEffectivePolicy>> | null;
}

function isGroupEffectivePolicy(v: unknown): v is GroupEffectivePolicy {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  if (r.conflict !== undefined && typeof r.conflict !== "string") return false;
  for (const k of GROUP_POLICY_COUNT_FIELDS) {
    const x = r[k];
    if (x !== undefined && !(typeof x === "number" && Number.isSafeInteger(x) && x >= 0)) return false;
  }
  for (const k of GROUP_POLICY_FLAG_FIELDS) {
    const x = r[k];
    if (x !== undefined && typeof x !== "boolean") return false;
  }
  return true;
}

/**
 * Whether a `policies` row from GET /machine-groups/session-policies is well-formed: a string `group_id`,
 * and every setting that is PRESENT has its server type (counts are whole numbers ≥ 0, flags are booleans).
 * Absent settings are allowed — an older control plane omits what it does not store.
 */
export function isGroupSessionPolicyRow(row: unknown): row is GroupSessionCap {
  if (row === null || typeof row !== "object") return false;
  const r = row as Record<string, unknown>;
  if (typeof r.group_id !== "string") return false;
  for (const k of GROUP_POLICY_COUNT_FIELDS) {
    const v = r[k];
    if (v !== undefined && !(typeof v === "number" && Number.isSafeInteger(v) && v >= 0)) return false;
  }
  for (const k of GROUP_POLICY_FLAG_FIELDS) {
    const v = r[k];
    if (v !== undefined && typeof v !== "boolean") return false;
  }
  return true;
}

/**
 * An API token (docs/01 §8): a tenant-admin-minted, capability-scoped bearer credential for
 * programmatic access. The plaintext secret is NEVER in this metadata — it exists only in the
 * one-time {@link CreatedAPIToken.token} returned by `createAPIToken`. `expires_at`/`revoked_at`
 * are null when the token never expires / is still active. Mirror the Go struct's JSON tags.
 */
export interface APIToken {
  id: string;
  name: string;
  capabilities: string[];
  created_by?: string;
  created_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
}

/** The body of `createAPIToken`. `expiresInDays` omitted/0 mints a token that never expires. */
export interface CreateAPITokenInput {
  name: string;
  capabilities: string[];
  expiresInDays?: number;
}

/** The result of `createAPIToken`: the metadata plus the plaintext secret, shown ONCE, here. */
export interface CreatedAPIToken {
  token: string;
  apiToken: APIToken;
}

/**
 * An enrollment token (docs/01 §4/§6): a group-scoped bearer secret an installer redeems to enroll a
 * NEW agent into the tenant. Only metadata here — the plaintext is the one-time {@link
 * CreatedEnrollmentToken.token}. `revoked` is true once cancelled; `uses`/`max_uses` bound redemptions.
 * Mirrors the Go `EnrollmentToken` (enrollment.go) field for field.
 */
export interface EnrollmentToken {
  id: string;
  tenant_id: string;
  group_id: string;
  created_by?: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  uses: number;
  revoked: boolean;
}

/** The body of `createEnrollmentToken`. `ttlSeconds`/`maxUses` omitted → the server defaults. */
export interface CreateEnrollmentTokenInput {
  groupId: string;
  ttlSeconds?: number;
  maxUses?: number;
}

/** The result of `createEnrollmentToken`: the metadata plus the plaintext secret, shown ONCE, here. */
export interface CreatedEnrollmentToken {
  token: string;
  enrollmentToken: EnrollmentToken;
}

/**
 * A registered webhook endpoint (docs/01 §8): receives a POST for every matching management-plane
 * audit event. The `secret` field is withheld from all GET responses; only {@link CreatedTenantWebhook}
 * exposes it, exactly once, at creation time.
 */
export interface TenantWebhook {
  id: string;
  url: string;
  events: string[]; // empty = subscribe to all events
  created_at: string;
}

/** Input for `createWebhook`. Omit `events` or pass `[]` to subscribe to every event. */
export interface CreateWebhookInput {
  url: string;
  events?: string[];
}

/** The result of `createWebhook`: the webhook metadata plus the signing secret, shown ONCE. */
export interface CreatedTenantWebhook extends TenantWebhook {
  secret: string;
}

/**
 * One entry in the webhook delivery ring buffer. Returned by `listWebhookDeliveries`.
 * Records are ephemeral (cleared on server restart) and intended for debugging purposes.
 */
export interface WebhookDeliveryRecord {
  webhook_id: string;
  event: string;
  attempted_at: string; // ISO-8601 UTC
  attempt: number; // 1 (initial) or 2 (retry)
  success: boolean;
  status_code: number; // 0 when no HTTP response was received
  duration_ms: number;
  error: string; // empty string on success
}

/**
 * Build the `GET /machines` path, appending the property-filter query ONLY when a key is present. Pure
 * so the encoding (URI-encode both segments; omit an empty value so it means "any value") is pinned by
 * a test and can never drift from the server's `property_key`/`property_value` query params.
 */
export function machinesListPath(filter?: MachinePropertyFilter): string {
  const key = (filter?.propertyKey ?? "").trim();
  if (key === "") return "/machines";
  let path = `/machines?property_key=${encodeURIComponent(key)}`;
  const value = filter?.propertyValue ?? "";
  if (value !== "") path += `&property_value=${encodeURIComponent(value)}`;
  return path;
}

/**
 * One remote-support session (Go `SessionRecord`, session_record.go). `machine_id` is the machine
 * PRIMARY KEY; `machine_device_id` is the stable agent identity. `ended_at` is absent while the
 * session is live. `granted_caps` may be `null` (Go marshals a nil slice as JSON null) when the
 * technician carried no backstage tier.
 */
export interface SessionRecord {
  id: string;
  tenant_id: string;
  machine_id: string;
  technician_id: string;
  started_at: string;
  ended_at?: string;
  consent_policy: string;
  granted_caps: string[] | null;
  machine_group_id: string;
  machine_device_id: string;
  machine_name: string;
  /** Tenant-chosen friendly name (machine.alias, migration 0032); "" when unset. */
  machine_alias: string;
  /** Free-text operator note (docs/01 §7); "" when unset. Set via {@link ConsoleApi.setSessionNote}. */
  note: string;
  /**
   * The session's central recording (docs/63), present ONLY when one exists AND the caller holds view_recordings
   * over the machine's group; absent otherwise (the server never signals existence to anyone else).
   */
  recording_id?: string;
}

/**
 * One management-plane audit entry (Go `MgmtAuditEvent`, mgmtaudit.go). Optional fields carry
 * `omitempty` server-side, so they are absent (not null) when empty; `metadata` is raw JSON.
 */
export interface MgmtAuditEvent {
  id: string;
  tenant_id: string;
  actor_user_id?: string;
  action: string;
  target_kind?: string;
  target_id?: string;
  occurred_at: string;
  /** The trusted client address the request came from (omitempty: absent for events written outside a request). */
  source_ip?: string;
  metadata?: unknown;
}

/**
 * Audit search (docs/01 §5). A non-empty `action`/`targetKind`/`actor` narrows by exact match;
 * `since`/`until` (RFC3339) bound a CLOSED time range [since, until]; empty/whitespace fields do not
 * filter. Mirrors the Go `AuditFilter` — the server applies the filter BEFORE the limit, so `limit`
 * bounds the matching events.
 */
export interface AuditListFilter {
  action?: string;
  targetKind?: string;
  /** Exact actor_user_id (a user id, or an API-token id). */
  actor?: string;
  /** RFC3339 lower bound, inclusive (occurred_at >= since). */
  since?: string;
  /** RFC3339 upper bound, inclusive (occurred_at <= until). */
  until?: string;
}

/**
 * Build the `GET /audit` path with the limit + optional filter query. Pure so the parameter names
 * (`limit`, `action`, `target_kind`, `actor`, `since`, `until`) and the "omit empty" rule are pinned
 * by a test and cannot drift from the server. Empty filter fields are omitted so they mean "no
 * filter", not "match empty".
 */
/** Append the shared audit filter (action/target_kind/actor/since/until), omitting empty fields. */
function appendAuditFilterParams(params: URLSearchParams, filter?: AuditListFilter): void {
  const action = (filter?.action ?? "").trim();
  if (action !== "") params.set("action", action);
  const targetKind = (filter?.targetKind ?? "").trim();
  if (targetKind !== "") params.set("target_kind", targetKind);
  const actor = (filter?.actor ?? "").trim();
  if (actor !== "") params.set("actor", actor);
  const since = (filter?.since ?? "").trim();
  if (since !== "") params.set("since", since);
  const until = (filter?.until ?? "").trim();
  if (until !== "") params.set("until", until);
}

export function auditListPath(limit?: number, filter?: AuditListFilter): string {
  const params = new URLSearchParams();
  if (limit !== undefined) params.set("limit", String(limit));
  appendAuditFilterParams(params, filter);
  const qs = params.toString();
  return qs === "" ? "/audit" : `/audit?${qs}`;
}

/**
 * One row of the §5 Reports audit summary: an action and how many events (matching the filter) carried
 * it. Mirrors the Go `AuditActionCount`.
 */
export interface AuditActionCount {
  action: string;
  count: number;
}

/**
 * One row of the §5 "sessions by machine" activity report: a machine and how many remote-support
 * sessions it has had. Mirrors the Go `MachineSessionCount`. `machine_group_id` is carried for parity
 * with the server row (the server already narrowed to the caller's groups); the view keys off
 * `machine_name` + `count`.
 */
export interface MachineSessionCount {
  machine_id: string;
  machine_name: string;
  machine_group_id: string;
  count: number;
  /** Total COMPLETED session time on this machine, in whole seconds (open sessions contribute 0). */
  total_seconds: number;
}

/**
 * One row of the §5 "sessions by technician" report (`GET /reports/sessions-by-technician`): a technician
 * and how many remote-support sessions they ran, plus their total completed session time. Already narrowed
 * (server-side) to the caller's viewable groups and aggregated per technician. The technician is identified
 * by id; the console resolves it to an email for display (the server denormalizes no user name).
 */
export interface TechnicianSessionCount {
  technician_id: string;
  count: number;
  /** Total COMPLETED session time for this technician, in whole seconds (open sessions contribute 0). */
  total_seconds: number;
}

/**
 * The since/until window for a §5 session-activity report (RFC3339, inclusive). Empty/absent = unbounded on
 * that side. Mirrors the server's `SessionSummaryFilter` (a CLOSED [since, until] range on the session start).
 */
export interface SessionReportFilter {
  since?: string;
  until?: string;
}

/**
 * Build a session-report path (`base`) with the optional `?since=`/`?until=` window, omitting empty fields so
 * they mean "no bound" not "match empty". Pure so the param names (`since`, `until`) are pinned by a test and
 * cannot drift from the server (shared with the audit report's since/until via the same server parse).
 */
export function sessionReportPath(base: string, filter?: SessionReportFilter): string {
  const params = new URLSearchParams();
  const since = (filter?.since ?? "").trim();
  if (since !== "") params.set("since", since);
  const until = (filter?.until ?? "").trim();
  if (until !== "") params.set("until", until);
  const qs = params.toString();
  return qs === "" ? base : `${base}?${qs}`;
}

/**
 * Build the `GET /audit/summary` path with the same optional filter as {@link auditListPath} (no limit —
 * a summary is bounded by the number of distinct actions). Pure so the param names are pinned by a test.
 */
export function auditSummaryPath(filter?: AuditListFilter): string {
  const params = new URLSearchParams();
  appendAuditFilterParams(params, filter);
  const qs = params.toString();
  return qs === "" ? "/audit/summary" : `/audit/summary?${qs}`;
}

/**
 * The signaling coordinates `POST /sessions` returns alongside the record (M2 / ADR-002):
 * the rendezvous WS URL (env `CP_SIGNALING_URL` server-side) plus the short-TTL signed ticket
 * the viewer presents in `connect_request`. Absent when the control plane has no grant issuer.
 */
export interface SessionSignaling {
  url: string;
  device_id: string;
  session_id: string;
  ticket: SignedSessionTicket;
}

/** Full `POST /sessions` response: the persisted record plus optional signaling coordinates. */
export interface StartedSession {
  session: SessionRecord;
  signaling?: SessionSignaling;
  /** The control-plane-signed session ACCESS policy for this session (docs/01 §3/§5, loops 79/80).
   *  Absent when the control plane has no grant issuer wired (dev). */
  session_policy?: SessionAccessPolicy;
}

/**
 * An open guest help request (docs/64): an ENROLLED machine asked for a technician. `note` is the guest
 * machine's own text and must only ever be rendered as plain text under the label "from the guest's
 * machine" (`note_source`); `requested_from: "machine"` says it is an enrolled-device assertion relayed by
 * signaling, never proof of a person or of consent. `online` is absent when presence is unknown.
 */
export interface HelpRequest {
  id: string;
  machine_id: string;
  machine_name: string;
  machine_alias?: string;
  /** The machine's CURRENT group. */
  group_id: string;
  note: string;
  note_source: string;
  requested_from: string;
  status: string;
  created_at: string;
  expires_at: string;
  online?: boolean;
  can_accept: boolean;
}

/** A session transfer / escalation offer (docs/51). Names are resolved server-side. */
export type SessionTransferState =
  | "pending" | "releasing" | "accepted" | "failed" | "cancelled" | "expired" | "superseded";
export interface SessionTransfer {
  id: string;
  session_id: string;
  machine_id: string;
  group_id?: string;
  from_user_id: string;
  /** Absent = escalated to anyone who may start sessions in the machine's group. */
  to_user_id?: string;
  note: string;
  state: SessionTransferState;
  created_at: string;
  expires_at: string;
  releasing_at?: string;
  accepted_by?: string;
  new_session_id?: string;
  failure_reason?: string;
  machine_name?: string;
  from_name?: string;
  to_name?: string;
  accepted_by_name?: string;
}
export interface TransferCandidate { id: string; email: string; display_name: string }
export interface TransferCandidates { candidates: TransferCandidate[]; group: { id: string; name?: string } }

/**
 * What the control plane decided this session may do, signed with its long-term key. `signed` is the
 * opaque `SignedSessionPolicy` JSON to hand the agent verbatim via `Control::InstallSessionPolicy`;
 * `access` ("view_only" | "control") is the same level in the clear, for the console's own display —
 * it is NOT authoritative, the signed blob is.
 */
export interface SessionAccessPolicy {
  access: string;
  signed: string;
}

/**
 * One renewal of an unattended session's LEASE (`POST /sessions/{id}/policy`, docs/25 F03).
 *
 * The same signed artifact as {@link SessionAccessPolicy} plus the two numbers a renewing console
 * needs. It is minted only while the control plane still authorizes the session: once an
 * administrator ends it — or the principal is disabled, the tenant suspended, or the machine
 * quarantined — the endpoint refuses, this console has nothing left to install, and the agent tears
 * the session down when the last lease expires. That refusal is the whole revocation mechanism.
 */
export interface SessionLease {
  access: string;
  signed: string;
  /** How long this lease is valid, as a DURATION — so the next renewal can be scheduled without the
   *  browser's clock having to agree with the control plane's. Schedule at a fraction of it. */
  lease_ttl_ms: number;
  /** The same instant on the CONTROL PLANE's clock. For display and logging only; never subtract
   *  `Date.now()` from it to decide when to renew, because the two clocks are not the same clock. */
  expires_at_ms: number;
}

/**
 * A control-plane-signed ELEVATION GRANT for one command (docs/01 §3, loop 87). `signed` is the
 * opaque JSON to hand the agent verbatim via `Control::ElevatedRun`; the other fields are the same
 * facts in the clear, for the console's own display and logging — they are NOT authoritative, the
 * signed blob is.
 *
 * SINGLE USE, by design: the agent burns `elevation_id` when it runs the command, so the console
 * mints a fresh grant per elevated command. That is what makes every elevated command its own
 * audited `session.elevation_minted` event rather than one "elevation was granted" per session.
 */
export interface SessionElevation {
  elevation_id: string;
  /** "linked_elevated" — the interactive user's full admin token. Never SYSTEM. */
  token: string;
  expires_at_ms: number;
  signed: string;
}

/** The deployment modes 0001_core.sql's CHECK accepts (Go `ValidDeploymentMode`). */
export type DeploymentMode = "saas" | "self_hosted";

/** One tenant row (Go `Tenant`, tenant.go). */
export interface Tenant {
  id: string;
  slug: string;
  name: string;
  deployment_mode: DeploymentMode;
  created_at: string;
  disabled: boolean;
}

/** What the console needs to know about the caller's platform-operator standing (GET /platform/me).
 *  `mfa_ok`: the session's second factor is recent enough to read the platform listing (12 h);
 *  `mfa_fresh`: recent enough for a lifecycle change (15 min). Anything else reads as all-false. */
export interface PlatformWhoami {
  operator: boolean;
  mfa_ok: boolean;
  mfa_fresh: boolean;
}

/** One tenant as the platform operator sees it (Go `PlatformTenant`, platform.go). */
export interface PlatformTenant {
  id: string;
  slug: string;
  name: string;
  deployment_mode: DeploymentMode;
  created_at: string;
  /** Set when the tenant is suspended. */
  disabled_at?: string;
  user_count: number;
  /** The tenant has machines whose agents do not enforce session leases: a suspension cannot bound
   *  sessions already running on them. */
  unleased_machines: boolean;
}

/** One hostname assignment as the platform operator sees it (Go `HostnameAssignment`, hostname.go). A released row keeps
 *  its host in quarantine until `quarantined_until`; every release/reactivate leaves a row, so the list is the history. */
export interface HostnameAssignment {
  id: string;
  host: string;
  tenant_id: string;
  kind: string;
  state: "pending" | "active" | "released";
  created_by: string;
  created_at: string;
  activated_at?: string;
  released_at?: string;
  released_by?: string;
  quarantined_until?: string;
}

/** An automated finding (Go `HostFinding`): a warning the operator must acknowledge by code, with a reason. */
export interface PlatformFinding {
  code: string;
  message: string;
}

/** One immutable branding revision (Go `BrandingRevision`, brandrev.go); the logo travels beside it, not in it. */
export interface BrandingRevisionView {
  id: string;
  seq: number;
  product_name: string;
  accent_color: string;
  support_text: string;
  support_contact: { kind: string; value: string };
  logo_sha256: string;
  has_logo: boolean;
  normalized_hash: string;
  created_by: string;
  created_at: string;
}

/** GET /platform/tenants/{id}/branding/review: the draft exactly as stored and what an approval binds. */
export interface BrandingReviewView {
  tenant_id: string;
  draft: BrandingRevisionView | null;
  published_revision_id: string;
  published_revision_hash: string;
  published_assignment_id: string;
  assignment: { id: string; host: string; state: string } | null;
  review_generation: number;
}

export interface BrandingReviewResult {
  review: BrandingReviewView;
  /** The draft's logo (a PNG the server re-encoded), base64; "" for none. */
  logo_png_base64: string;
  findings: PlatformFinding[];
}

/** The body of POST /platform/tenants/{id}/branding/approve (docs/66 2a.3, 2c.2, 2h). */
export interface BrandingApproveRequest {
  revision_id: string;
  normalized_hash: string;
  assignment_id: string;
  review_generation: number;
  acknowledge: string[];
  override_reason: string;
}

/** Shared Toolbox (docs/design-shared-toolbox.md). */
export type ToolboxShell = "powershell" | "cmd";
export type ToolboxRunAs = "system" | "user";
export type ToolboxScope = "shared" | "personal";

/** One saved script as the console sees it (Go `toolboxItemView`). */
export interface ToolboxItem {
  id: string;
  name: string;
  description: string;
  scope: ToolboxScope;
  shell: ToolboxShell;
  run_as: ToolboxRunAs;
  body: string;
  body_sha256: string;
  version: number;
  updated_at: string;
  /** The caller owns this (personal) item. */
  mine: boolean;
}

/** GET /toolbox: the items plus what the caller may do and the size limits the server enforces. */
export interface ToolboxListing {
  items: ToolboxItem[];
  canManageShared: boolean;
  maxPowerShellBytes: number;
  maxCmdUnits: number;
}

/** Editable fields of a toolbox item (scope is fixed at creation). */
export interface ToolboxItemInput {
  name: string;
  description: string;
  shell: ToolboxShell;
  run_as: ToolboxRunAs;
  body: string;
}

/** POST /toolbox/{id}/runs: the audited run request and the exact command to send. */
export interface ToolboxRunGrant {
  request_id: string;
  shell: ToolboxShell;
  run_as: ToolboxRunAs;
  command: string;
}

/** Input for {@link ConsoleApiClient.createTenant}. `deploymentMode` defaults server-side to "saas". */
export interface CreateTenantInput {
  slug: string;
  name: string;
  deploymentMode?: DeploymentMode;
}

/** The attended-session lifecycle states (Go attended.go / migrations/0013's CHECK). */
export type AttendedState =
  | "pending" // code minted, not yet redeemed by a guest
  | "redeemed" // guest ran `agent_host attend`, awaiting the consent prompt
  | "consented" // guest accepted — the connect gate is open
  | "declined" // guest refused — terminal
  | "active" // technician connected at least once
  | "ended" // ended by the technician — terminal
  | "expired"; // code/session TTL ran out — terminal

/**
 * One attended (on-demand) session (Go `AttendedSession`, attended.go). Optional fields carry
 * `omitempty`/pointers server-side, so they are ABSENT when unset — `device_id` only exists once
 * a guest has redeemed the code.
 */
/** Outcome of a guest-initiated permanent install attempt (set via POST /promote-complete). */
export interface AttendedPromoteResult {
  success: boolean;
  error?: string;
  at: string;
}

export interface AttendedSessionRecord {
  id: string;
  tenant_id: string;
  group_id: string;
  technician_id: string;
  device_id?: string;
  state: AttendedState;
  reason?: string;
  consent_user?: string;
  created_at: string;
  expires_at: string;
  redeemed_at?: string;
  consented_at?: string;
  ended_at?: string;
  /** Result of the guest's permanent-install attempt; absent until the guest calls /promote-complete. */
  promote_result?: AttendedPromoteResult;
}

/**
 * `POST /attended-sessions` response. The code appears ONCE, here (only its hash is stored):
 * `code` is the grouped display form ("XXXX-XXXX-…"), `join_code` the raw form the guest CLI
 * takes, `join_url` the fragment link ("/join#<code>" — fragment so the code never hits logs).
 */
export interface CreatedAttendedSession {
  session: AttendedSessionRecord;
  code: string;
  join_code: string;
  join_url: string;
}

/**
 * `POST /attended-sessions/{id}/connect` response — the consent gate. Succeeds only once the
 * guest consented; the `signaling` envelope is the SAME shape the brokered connect path consumes.
 */
export interface ConnectedAttendedSession {
  session: AttendedSessionRecord;
  signaling: SessionSignaling;
  /** The signed session ACCESS policy, when the attended session's group enforces view-only
   *  (docs/01 §5). An attended machine is ephemeral but NOT group-less — redemption enrolls it into
   *  the invite's group — so a per-group mandate applies here exactly as it does to a normal session. */
  session_policy?: SessionAccessPolicy;
}

/**
 * Decode an optional `session_policy` envelope from a session-start-like response.
 *
 * Shared by `startBrokeredSession` and `connectAttendedSession` deliberately: they are the TWO paths
 * that can open a live session, and a per-group view-only mandate has to hold on both. Having one
 * decoder means a future third path cannot quietly ship without it, and the two cannot drift.
 *
 * Absent/null → `undefined` (the group enforces nothing, or no issuer is wired). Present but
 * malformed → THROWS: silently ignoring it would run the session unrestricted while the console
 * believed a mandate was in force, which is the same failure as never reading it at all.
 */
function parseSessionAccessPolicy(body: unknown, action: string): SessionAccessPolicy | undefined {
  const raw = (body as Record<string, unknown> | null)?.session_policy;
  if (raw === undefined || raw === null) return undefined;
  const p = raw as { access?: unknown; signed?: unknown };
  if (typeof p.access !== "string" || typeof p.signed !== "string" || p.signed === "") {
    throw new ConsoleApiError(200, `could not ${action}: malformed response (bad "session_policy")`, "server");
  }
  return { access: p.access, signed: p.signed };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Coarse classification of a control-plane failure, so callers can branch without status math. */
export type ConsoleApiErrorKind =
  | "bad_request" // 400 — malformed/missing fields
  | "unauthenticated" // 401 — no/expired session cookie: log in first
  | "forbidden" // 403 — authenticated but capability denied (rbac.go writeDenied)
  | "not_found" // 404 — unknown machine/session id
  | "conflict" // 409 — e.g. tenant slug already in use
  | "server"; // 5xx / anything else, including malformed success bodies

/** Map an HTTP status to its {@link ConsoleApiErrorKind}. */
export function errorKindFor(status: number): ConsoleApiErrorKind {
  switch (status) {
    case 400:
      return "bad_request";
    case 401:
      return "unauthenticated";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    default:
      return "server";
  }
}

/** A typed failure from the console API, carrying the status + kind and the body's `error` reason. */
export class ConsoleApiError extends Error {
  readonly status: number;
  readonly kind: ConsoleApiErrorKind;
  /** The body's machine-readable `code` when the server sent one (e.g. `step_up_required`), else its `error`
  * field verbatim (e.g. `playback_pending`, `expired`), else empty. */
  readonly code: string;
  /** The parsed JSON error body, when there was one: the platform review answers 409 `findings` and a hostname
   *  assignment 409 `warnings` with the list the operator must acknowledge, and only the body carries it. */
  readonly body?: Record<string, unknown>;
  /** The body's `field` when the server named the input it refused (`{field, error}`, e.g. the branding fields), else "". */
  readonly field: string;
  constructor(
    status: number,
    message: string,
    kind: ConsoleApiErrorKind = errorKindFor(status),
    code = "",
    body?: Record<string, unknown>,
    field = "",
  ) {
    super(message);
    this.name = "ConsoleApiError";
    this.status = status;
    this.kind = kind;
    this.code = code;
    this.body = body;
    this.field = field;
  }
}

// ---------------------------------------------------------------------------
// CSRF double-submit hook
// ---------------------------------------------------------------------------

/** The non-httpOnly cookie the control plane's double-submit CSRF scheme sets. */
export const CSRF_COOKIE_NAME = "rmt_csrf";
/** The header mutating requests echo {@link CSRF_COOKIE_NAME}'s value into. */
export const CSRF_HEADER_NAME = "X-CSRF-Token";

/**
 * The admin warnings from GET /managed-installer in deployment-pass mode (docs/48). Untrusted
 * server JSON: only strings are kept, at most 4 of at most 400 characters each; anything else
 * (a baked server, an older server) yields none.
 */
export function parseInstallerWarnings(body: unknown): string[] {
  const pass = (body as { deployment_pass?: { warnings?: unknown } } | null)?.deployment_pass;
  const raw = pass?.warnings;
  if (!Array.isArray(raw)) return [];
  return raw.filter((w): w is string => typeof w === "string" && w.length > 0).slice(0, 4).map((w) => w.slice(0, 400));
}

/**
 * Extract the `rmt_csrf` value from a `document.cookie`-shaped string, or null when absent. Pure,
 * so it is unit-testable without a DOM; the client feeds it the real `document.cookie`.
 */
export function csrfTokenFrom(cookies: string): string | null {
  // Prefer the host-only production cookie even if a sibling planted a legacy cookie first.
  const parts = cookies.split(";");
  const name = parts.some((p) => p.trim().startsWith("__Host-" + CSRF_COOKIE_NAME + "="))
    ? "__Host-" + CSRF_COOKIE_NAME : CSRF_COOKIE_NAME;
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const raw = part.slice(eq + 1).trim();
    if (raw === "") return null;
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw; // not URI-encoded — use as-is
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/**
 * Body of `POST /audit/ingest` — mirror of Go `auditIngestRequest`. The events stay `unknown` here;
 * `lib/audit_forward.ts` owns their shape (see {@link ConsoleApi.ingestAudit}).
 */
export interface AuditIngestBody {
  session_id: string;
  events: unknown[];
}

/** Response of `POST /audit/ingest` — mirror of Go `auditIngestResponse`. */
export interface AuditIngestResult {
  accepted: number;
  tail_seq: number;
  tail_hash: string;
}

/**
 * The method surface the console panels program against (and tests fake). `ConsoleApiClient` is
 * the HTTP implementation; the broker milestone extends this seam with session-ticket handling.
 */
export interface ConsoleApi {
  ssoInfo(tenantSlug: string): Promise<SSOInfo>;
  getSSO(): Promise<SSOSettings>;
  putSSO(body: SSOSettingsInput): Promise<SSOSettings>;
  /** Whether this session's step-up is still fresh enough for the SSO actions (no code needed). */
  ssoStepUpFresh(): Promise<boolean>;
  /** The signed-in user's own email, for the "Signed in as" line. */
  me(): Promise<MeInfo>;
  /** Call stepUp first; these endpoints never receive the authenticator code. */
  startSSOLink(): Promise<{ url: string }>;
  startSSOTest(): Promise<{ url: string }>;
  unlinkSSO(): Promise<void>;
  completeSSOTotp(pendingId: string, code: string): Promise<SSOTotpResult>;
  managedInstallerAvailable(): Promise<boolean>;
  /** Deployment-pass warnings for admins (docs/48): a lapsed or soon-lapsing pass. Optional so
   *  fakes without pass mode need not implement it. */
  managedInstallerWarnings?(): Promise<string[]>;
  downloadManagedInstaller(groupId: string, signal: AbortSignal): Promise<Blob>;
  /** `filter` narrows the fleet to machines carrying a custom property (docs/01 §4); omit for all. */
  listMachines(filter?: MachinePropertyFilter): Promise<MachineRecord[]>;
  /**
   * Like {@link listMachines} but keeps the envelope's `presence_known` flag, so a caller can tell
   * "everything is offline" apart from "the presence feed is down". Accepts the same optional
   * property filter as `listMachines`. Prefer this for panels that need to show online status.
   */
  listMachinesWithPresence(filter?: MachinePropertyFilter): Promise<MachineListing>;
  /** Set a machine's lifecycle status (active|quarantined|retired). POST /machines/{id}/status — CapManageMachines. */
  setMachineStatus(machineId: string, status: string): Promise<MachineRecord>;
  /** Apply one status to MANY machines (docs/01 §4). POST /machines/bulk-status — CapManageMachines,
   *  group-scoped per machine; returns a per-machine result (partial success is normal). */
  bulkSetMachineStatus(machineIds: readonly string[], status: string): Promise<BulkStatusResult[]>;
  /** Reassign MANY machines to ONE target group (docs/01 §4). POST /machines/bulk-group — CapManageMachines
   *  on the TARGET group (blanket) AND on each machine's current group (per-machine); partial results. */
  bulkSetMachineGroup(machineIds: readonly string[], groupId: string): Promise<BulkStatusResult[]>;
  /** Reassign a machine to a different group (docs/01 §4). POST /machines/{id}/group — CapManageMachines on
   *  BOTH the machine's current group AND the target group (two-way, no-escalation). */
  setMachineGroup(machineId: string, groupId: string): Promise<MachineRecord>;
  /** Set (or clear, with "") a machine's tenant-chosen friendly name. PATCH /machines/{id}/alias —
   *  CapManageMachines for the machine's group. Returns the updated machine. */
  setMachineAlias(machineId: string, alias: string): Promise<MachineRecord>;
  /** Set (or clear, with "") a machine's free-text operator note. PATCH /machines/{id}/note —
   *  CapManageMachines for the machine's group. Returns the updated machine. */
  setMachineNote(machineId: string, note: string): Promise<MachineRecord>;
  /** Every custom property on a machine (by PRIMARY KEY). GET /machines/{id}/properties. */
  listMachineProperties(machineId: string): Promise<MachineProperty[]>;
  /** Idempotent upsert of one property key. PUT /machines/{id}/properties/{key} body `{ value }`. */
  setMachineProperty(machineId: string, key: string, value: string): Promise<MachineProperty>;
  /** Remove one property key. DELETE /machines/{id}/properties/{key}; throws not_found for a gone key. */
  deleteMachineProperty(machineId: string, key: string): Promise<void>;
  /** The tenant's sessions, newest first, narrowed to the caller's viewable groups server-side. GET /sessions
   *  — CapViewSessions. Optional since/until window on the session start (docs/01 §5, same as the reports). */
  listSessions(filter?: SessionReportFilter): Promise<SessionRecord[]>;
  /**
   * The tenant's CURRENTLY OPEN sessions (ended_at absent) — a subset of {@link listSessions}.
   * Used to annotate the machine listing with "session active" badges. Requires CapViewSessions;
   * callers that lack it receive no badges (the call rejects and the caller degrades gracefully).
   */
  listLiveSessions(): Promise<SessionRecord[]>;
  /** `machineDeviceId` is the machine's DEVICE id (`MachineRecord.device_id`), not its PK. */
  startSession(machineDeviceId: string): Promise<SessionRecord>;
  /**
   * Like {@link startSession} but returns the FULL response — the record plus the `signaling`
   * envelope (URL + signed session ticket) the brokered connect path presents (M2). `signal`
   * cancels the request mid-flight (passed by callers that time-bound the connect attempt).
   */
  /** `opts.access: "view_only"` starts an OBSERVER session (observer design v2); omitted = control. */
  startBrokeredSession(machineDeviceId: string, signal?: AbortSignal, opts?: { access?: "view_only" }): Promise<StartedSession>;
  mintSessionElevation(sessionId: string): Promise<SessionElevation>;
  /** Renew a live unattended session's LEASE (docs/25 F03). POST /sessions/{id}/policy. Refused once
   *  the session has ended; that refusal is what makes a central "End session" terminate the
   *  session's remote access without the controller's cooperation. `signal` cancels the request
   *  mid-flight (used by the renewer's per-attempt timeout and stop/switch cancellation). */
  renewSessionPolicy(sessionId: string, signal?: AbortSignal): Promise<SessionLease>;
  endSession(sessionId: string): Promise<SessionRecord>;
  /** Session transfer / escalation (docs/51). Offer S1 to a colleague, or (no `toUserId`) to anyone who
   *  may start sessions in the machine's group. S1's holder only. */
  offerSessionTransfer(sessionId: string, opts?: { toUserId?: string; note?: string }): Promise<SessionTransfer>;
  /** Who S1's holder may name: GET /sessions/{id}/transfer-candidates. */
  sessionTransferCandidates(sessionId: string): Promise<TransferCandidates>;
  /** The sender withdraws a pending offer. */
  cancelSessionTransfer(transferId: string): Promise<SessionTransfer>;
  /** Offers the caller could accept (addressed to them, or escalations in their groups). */
  listIncomingTransfers(): Promise<SessionTransfer[]>;
  /** Open guest help requests this user may act on (GET /help-requests; docs/64). */
  listHelpRequests(): Promise<HelpRequest[]>;
  /**
   * Accept a help request (POST /help-requests/{id}/accept): the server creates the bound session through
   * the same admission as `POST /sessions` and answers with that response. `opId` is the idempotency key
   * a retry reuses, so a lost response returns the SAME session. 409 states surface as ConsoleApiError
   * messages carrying the server's text.
   */
  acceptHelpRequest(requestId: string, opId?: string): Promise<StartedSession>;
  /** One offer's status. The acceptor's read also completes the hand-off once the agent confirms. */
  getSessionTransfer(transferId: string): Promise<SessionTransfer>;
  /** Claim an offer: pending -> releasing. The new session exists once the state is `accepted`. */
  acceptSessionTransfer(transferId: string): Promise<SessionTransfer>;
  /** The new session's ticket, minted exactly as `POST /sessions` mints one. Acceptor only. */
  sessionTransferTicket(transferId: string): Promise<StartedSession>;
  /** Overwrite a session's free-text operator note (docs/01 §7). PATCH /sessions/{id}/note — CapEndSession. */
  setSessionNote(sessionId: string, note: string): Promise<SessionRecord>;
  /** `limit` omitted → the server default (200). `filter` narrows by action/target_kind (docs/01 §5). */
  listAudit(limit?: number, filter?: AuditListFilter): Promise<MgmtAuditEvent[]>;
  /** Per-action audit-event counts for the Reports view (docs/01 §5). GET /audit/summary — CapViewAudit. */
  auditSummary(filter?: AuditListFilter): Promise<AuditActionCount[]>;
  /** Per-machine session counts for the Reports view (docs/01 §5). GET /reports/sessions-by-machine —
   *  CapViewSessions, group-scoped like the session list. */
  sessionsByMachine(filter?: SessionReportFilter): Promise<MachineSessionCount[]>;
  /** Per-technician session counts + total time (docs/01 §5). GET /reports/sessions-by-technician —
   *  CapViewSessions, narrowed to the caller's viewable groups BEFORE aggregation. Optional since/until window. */
  sessionsByTechnician(filter?: SessionReportFilter): Promise<TechnicianSessionCount[]>;
  listTenants(): Promise<Tenant[]>;
  /** The caller's platform-operator standing. GET /platform/me; never throws for a non-operator. */
  platformWhoami(): Promise<PlatformWhoami>;
  /** Every tenant, for the platform operator. GET /platform/tenants (403 unless an operator with recent MFA). */
  listPlatformTenants(): Promise<PlatformTenant[]>;
  /** Provision a tenant. POST /platform/tenants (platform operator, MFA within 15 minutes; 409 = slug taken). */
  createTenant(input: CreateTenantInput): Promise<Tenant>;
  /** Suspend or resume a tenant. POST /platform/tenants/{id}/suspend|resume; `confirmSlug` must equal its slug. */
  setTenantSuspended(id: string, suspended: boolean, confirmSlug: string, reason: string): Promise<Tenant>;
  /** A tenant's hostname history, newest rows last. GET /platform/tenants/{id}/hostnames (operator, MFA within 12 h). */
  listTenantHostnames(tenantId: string): Promise<HostnameAssignment[]>;
  /** Assign a hostname (creates a PENDING assignment). POST /platform/tenants/{id}/hostnames. A 409 with `body.warnings`
   *  means look-alike warnings: send again with every code in `acknowledge` and a reason. */
  assignHostname(tenantId: string, host: string, acknowledge?: readonly string[], overrideReason?: string): Promise<HostnameAssignment>;
  /** Pending -> active, same id. POST /platform/hostnames/{id}/activate. */
  activateHostname(id: string): Promise<HostnameAssignment>;
  /** End an assignment; its host is quarantined (30 days at least). POST /platform/hostnames/{id}/release. */
  releaseHostname(id: string, reason: string): Promise<HostnameAssignment>;
  /** A NEW assignment for a released host (pending, or active with `activate`). POST /platform/hostnames/{id}/reactivate. */
  reactivateHostname(id: string, activate: boolean): Promise<HostnameAssignment>;
  /** The draft join-page branding of a tenant, as stored, with the automated findings. GET /platform/tenants/{id}/branding/review. */
  getBrandingReview(tenantId: string): Promise<BrandingReviewResult>;
  /** Publish the reviewed draft. POST .../branding/approve. 409 `stale` = the tenant changed something since the review;
   *  409 `findings` = unacknowledged findings (`body.findings`). */
  approveBranding(tenantId: string, req: BrandingApproveRequest): Promise<void>;
  /** Clear what guests see (they get the neutral page). POST .../branding/withdraw. */
  withdrawBranding(tenantId: string, reason: string): Promise<void>;
  /** Re-prove the second factor inside this session. POST /auth/step-up (204; 409 = sign in again). */
  stepUp(code: string): Promise<void>;
  /** Request a reinstall or uninstall directive for ONE machine (docs/65). POST /machines/{id}/directives. An
   *  uninstall needs `confirm` (the machine's name) and a fresh step-up (403 code step_up_required). */
  requestDirective(machineId: string, kind: DirectiveKind, confirm?: string): Promise<AgentDirective>;
  /** Forget a RETIRED machine for good (docs/65 sec. 8): it takes the same tombstone a confirmed removal does and
   *  any directive still active on it is closed. POST /machines/{id}/forget. `confirm` is the machine's name and a
   *  fresh step-up is needed (403 code step_up_required); an already removed machine answers outcome
   *  "already_removed". Nothing is uninstalled on the machine. */
  forgetMachine(machineId: string, confirm: string): Promise<ForgetMachineResult>;
  /** A machine's directives, newest first as the server returns them. GET /machines/{id}/directives. */
  listMachineDirectives(machineId: string): Promise<AgentDirective[]>;
  /** Every ACTIVE directive the caller may act on (their machines' current groups), newest first, following
   *  the server's (before, before_id) keyset cursor for at most `maxPages` pages (default 5). `hasMore` is true
   *  when the budget ran out while the server still offered a cursor: never a silent truncation.
   *  GET /directives?state=active (403 unless the caller holds remove_agent). */
  listActiveDirectives(opts?: { maxPages?: number }): Promise<ActiveDirectiveList>;
  /** Approve a directive (second approver; fresh step-up). POST /directives/{id}/approve. */
  approveDirective(id: string): Promise<AgentDirective>;
  /** Cancel a still-requested directive. POST /directives/{id}/cancel. */
  cancelDirective(id: string, reason?: string): Promise<AgentDirective>;
  /** The tenant's directive policy. GET /tenant/directive-policy (403 unless the caller holds remove_agent). */
  getDirectivePolicy(): Promise<DirectivePolicy>;
  /** Set the policy. PUT /tenant/directive-policy (Owner, fresh step-up). */
  setDirectivePolicy(requireSecondApprover: boolean): Promise<DirectivePolicy>;
  /** The caller's toolbox: shared items plus their own personal ones. GET /toolbox (start_session). */
  listToolbox(): Promise<ToolboxListing>;
  /** POST /toolbox. A shared item needs manage_toolbox; 409 = name taken in that scope. */
  createToolboxItem(scope: ToolboxScope, input: ToolboxItemInput): Promise<ToolboxItem>;
  /** PUT /toolbox/{id}. 409 = changed since loaded (or name taken); 404 = not visible. */
  updateToolboxItem(id: string, expectedVersion: number, input: ToolboxItemInput): Promise<ToolboxItem>;
  /** DELETE /toolbox/{id}?expected_version=N. */
  deleteToolboxItem(id: string, expectedVersion: number): Promise<void>;
  /** POST /toolbox/{id}/runs: authorize + audit a run request on the caller's live session; returns
   *  the exact command to send as RunCommand. 409 = view-only / ended / item changed. */
  requestToolboxRun(id: string, sessionId: string, expectedVersion: number): Promise<ToolboxRunGrant>;
  /** Authorize + centrally audit an ad-hoc command against a held session, returning the exact command
   *  text to send (POST /sessions/{id}/command-run). The grant's shape matches a toolbox run. */
  requestCommandRun(sessionId: string, shell: ToolboxShell, runAs: ToolboxRunAs, body: string): Promise<ToolboxRunGrant>;
  /** The tenant's IP allow-list + the caller's current source IP (docs/01 §10). GET /tenant/ip-allowlist. */
  getTenantIPAllowlist(): Promise<TenantIPAllowlist>;
  /** Add one source CIDR. POST /tenant/ip-allowlist; throws (400) if the add would lock the caller out. */
  addTenantIPAllowlistEntry(cidr: string): Promise<void>;
  /** Remove one source CIDR. DELETE /tenant/ip-allowlist?cidr=; throws (400) lock-out, not_found for a gone entry. */
  deleteTenantIPAllowlistEntry(cidr: string): Promise<void>;
  /** The tenant's users (docs/01 §5, management view). GET /users — CapManageUsers. */
  listUsers(): Promise<UserSummary[]>;
  /** The assignable preset roles + the capabilities each grants (docs/01 §5). GET /roles — CapManageRoles.
   *  A read-only reference so an admin can see what a role permits before assigning it. */
  listRoles(): Promise<RoleCatalogEntry[]>;
  /** Invite/create a user with an initial role. POST /users — CapManageUsers + no-escalation; throws (409) on a duplicate email. */
  createUser(input: CreateUserInput): Promise<UserSummary>;
  /** Enable/disable a user's access. POST /users/{id}/(disable|enable) — CapManageUsers + hierarchy. */
  setUserDisabled(id: string, disabled: boolean): Promise<void>;
  /** Sign a user out of ALL sessions (force re-login) WITHOUT disabling. POST /users/{id}/sign-out —
   *  CapManageUsers + hierarchy. Resolves to how many sessions were revoked. */
  signOutUser(id: string): Promise<number>;
  /** Clear the login-throttle counters for a user locked out by too many failed attempts.
   *  DELETE /users/{id}/lockout — CapManageUsers + hierarchy. Source-IP budget is NOT cleared. */
  clearUserLockout(id: string): Promise<void>;
  /** Assign a user's role (replace with one tenant-wide preset). POST /users/{id}/role — CapManageRoles + no-escalation. */
  setUserRole(id: string, role: string, opts?: SetUserRoleOptions): Promise<void>;
  /**
   * Mint a single-use first-password / reset link for a user (docs/01 §5). POST /users/{id}/password-reset
   * — CapManageUsers + a caller-password STEP-UP (the caller re-proves their own password, so a stolen
   * session cannot mint a takeover link) + the no-escalation hierarchy. Returns the plaintext token ONCE.
   * `password` is the CALLER's own current password; `ttlSeconds` optionally overrides the link lifetime.
   */
  issuePasswordReset(id: string, password: string, ttlSeconds?: number): Promise<IssuedSetupLink>;
  /** Cancel every outstanding setup link for a user. DELETE /users/{id}/password-reset — CapManageUsers. Returns the count revoked. */
  revokePasswordReset(id: string): Promise<number>;
  /**
   * Redeem a setup link: set the user's password (docs/01 §5). PUBLIC POST /auth/password/redeem — the
   * token in the body IS the authorization, no session is issued. Throws (403) on a bad/spent token, (400)
   * with the joined policy reasons when the new password is too weak.
   */
  redeemPasswordReset(token: string, newPassword: string): Promise<RedeemSetupResult>;
  /**
   * Change the authenticated user's own password (docs/01 §10). POST /me/password — requires the
   * CURRENT password as a step-up; throws (403) on wrong current password, (400) on policy violations
   * or a reused password. On success the server rotates all sessions and issues a new session cookie,
   * so the browser stays logged in with the new credential automatically.
   */
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  /** Change this user's login email with password step-up; rotates the session cookie. */
  changeEmail(currentPassword: string, newEmail: string): Promise<string>;
  /**
   * Begin TOTP 2FA enrollment (docs/01 §10). POST /auth/totp/enroll — requires the current password
   * for a FIRST enrollment, or a current TOTP code for re-enrollment. Returns the base32 secret and
   * an otpauth URI the user enters into their authenticator app. Complete with confirmTotp().
   */
  enrollTotp(stepUp: { password?: string; code?: string }): Promise<{ secret: string; otpauth_uri: string }>;
  /**
   * Confirm TOTP enrollment by presenting a code against the pending secret. POST /auth/totp/confirm —
   * throws (403) on a wrong or already-spent code. On success the pending secret becomes the enforced
   * second factor for all future logins.
   */
  confirmTotp(code: string): Promise<void>;
  /** The tenant's white-label branding (docs/01 §9). GET /tenant/branding — any authenticated member. */
  getTenantBranding(): Promise<TenantBranding>;
  /** Set the tenant's branding. PUT /tenant/branding (CapManageTenant); throws (400) on an invalid value. */
  setTenantBranding(branding: TenantBranding): Promise<TenantBranding>;
  /** The PUBLIC join-page branding state (docs/66 2h): draft, published, hostname, live. GET /tenant/branding/revisions — any member. */
  getBrandingRevisions(): Promise<BrandingRevisionsView>;
  /** Submit the public join-page branding as a new immutable revision (waits for operator approval). POST /tenant/branding/revisions — Owner; `created:false` when nothing changed. */
  createBrandingRevision(input: BrandRevisionInput): Promise<BrandRevisionResult>;
  /** The tenant's session policy — concurrency cap + max session age (docs/01 §5). GET /tenant/session-policy. */
  getSessionPolicy(): Promise<SessionPolicy>;
  /** Set the session policy (0 = no limit for either field). PUT /tenant/session-policy (CapManageTenant); throws (400) if out of range. */
  setSessionPolicy(policy: SessionPolicy): Promise<SessionPolicy>;
  /** The tenant's 2FA enforcement policy (docs/01 §10). GET /tenant/security-policy. */
  getTenantSecurityPolicy(): Promise<TenantSecurityPolicy>;
  /** Set the 2FA enforcement policy. PUT /tenant/security-policy (CapManageTenant); throws (400) if caller lacks TOTP enrollment (anti-lockout). */
  setTenantSecurityPolicy(policy: TenantSecurityPolicy): Promise<TenantSecurityPolicy>;
  /** Central recording policy (docs/63 D5). GET /tenant/recording-policy — manage_tenant or view_recordings. */
  getRecordingPolicy(): Promise<RecordingPolicy>;
  /** Per-artifact request counts from the Caddy log (docs/68). GET /platform/reach?from&to — operator, MFA within 12 h (403 otherwise). */
  getPlatformReach(from: string, to: string): Promise<ReachReport>;
  /** This tenant's own adoption counts (docs/68). GET /adoption — manage_tenant (403 otherwise). */
  getAdoption(): Promise<Adoption>;
  /** PUT /tenant/recording-policy — manage_tenant (Owner). The body carries EVERY field; the server refuses less. */
  setRecordingPolicy(body: RecordingPolicyBody): Promise<RecordingPolicy>;
  /** Completed recordings, newest first (docs/63 §6.1). GET /recordings — view_recordings, group-scoped. */
  listRecordings(opts?: { limit?: number; cursor?: string; sessionId?: string; machineId?: string }): Promise<RecordingPage>;
  /** GET /recordings/{id}. */
  getRecording(id: string): Promise<RecordingDetail>;
  /** GET /recordings/{id}/playlist — audited as "playback started"; 409/410/503 carry the reason in `code`. */
  getRecordingPlaylist(id: string): Promise<RecordingPlaylist>;
  /** The control-plane base URL (same origin as the console), for stream and download links. */
  readonly base: string;
  /**
   * Operator-configured expected agent version (docs/01 §6). GET /agent-version.
   * When configured=false the operator has not set AGENT_PUBLISHED_VERSION and the console
   * must suppress outdated badges — absence of a target is not an assertion of currency.
   */
  getPublishedAgentVersion(): Promise<AgentVersionInfo>;
  /** The tenant's saved dynamic groups (docs/01 §4). GET /dynamic-groups. */
  listDynamicGroups(): Promise<DynamicGroup[]>;
  /** Create a dynamic group. POST /dynamic-groups; throws (409) if the name is taken. */
  createDynamicGroup(input: CreateDynamicGroupInput): Promise<DynamicGroup>;
  /** Delete a dynamic group. DELETE /dynamic-groups/{id}; throws not_found for a gone group. */
  deleteDynamicGroup(id: string): Promise<void>;
  /** Resolve a dynamic group's members LIVE (narrow-only). GET /dynamic-groups/{id}/machines. */
  resolveDynamicGroup(id: string): Promise<MachineRecord[]>;
  /** The tenant's STATIC machine groups (the RBAC scope unit). GET /machine-groups — CapViewMachines. */
  listMachineGroups(): Promise<MachineGroup[]>;
  /** Create a static machine group. POST /machine-groups — CapManageGroups; throws (400) on an empty/too-long/control-char name. */
  createMachineGroup(input: CreateMachineGroupInput): Promise<MachineGroup>;
  /**
   * Move a group under another group, or to the top level with `null` (docs/62 §3). POST
   * /machine-groups/{id}/move `{parent_id}` — 403 (not allowed to manage both groups), 404, 409 with the
   * server's reason (would create a cycle, nests too deep, a policy conflict); the reason is in the message.
   */
  moveMachineGroup(id: string, parentId: string | null): Promise<void>;
  /** Rename a machine group. PATCH /machine-groups/{id} — CapManageGroups; throws (404) if gone, (400) on a bad name. */
  renameMachineGroup(id: string, name: string): Promise<MachineGroup>;
  /** Delete a machine group. DELETE /machine-groups/{id} — CapManageGroups; throws (409) if it still has machines/dependents, (404) if gone. */
  deleteMachineGroup(id: string): Promise<void>;
  /** Per-group concurrent-session caps that are SET (unset groups omitted). GET /machine-groups/session-policies — CapManageGroups. */
  listGroupSessionPolicies(): Promise<GroupSessionCap[]>;
  /**
   * The same read plus the server-computed effective policy per managed group (GET /machine-groups/session-policies).
   * Optional so a client built before it keeps working; the panel falls back to a browser-side merge without it.
   */
  listGroupSessionPolicyView?(): Promise<GroupSessionPolicyView>;
  /**
   * Overwrite a group's session policy — ALL FOUR of the concurrency cap (0 = unlimited by group), the
   * view-only mandate, the backstage opt-out, and the recording ban. PUT /machine-groups/{id}/session-policy
   * — CapManageGroups; throws (404) if the group is gone, (400) on a bad value.
   *
   * A full overwrite, not a patch: the server writes every field from the body, so a caller must send the
   * settings it wants to KEEP as well as the one it is changing. That is what makes "turn view-only off"
   * expressible at all — and it is also why every boolean field here is required rather than optional. An
   * optional field would let a call site omit it, and omitting it writes `false`; that happens to be the
   * SAFE value today, but a required field is what stops the next setting from being dropped by a call site
   * that never heard of it.
   */
  setGroupSessionPolicy(
    groupId: string,
    policy: {
      max_concurrent_sessions: number;
      enforce_view_only: boolean;
      allow_backstage_under_view_only: boolean;
      prohibit_recording: boolean;
      require_recording: boolean;
      max_session_duration_seconds: number;
      max_idle_seconds: number;
    },
  ): Promise<GroupSessionCap>;
  /** The tenant's API tokens (metadata only — never the secret). GET /api-tokens. Owner-only. */
  listAPITokens(): Promise<APIToken[]>;
  /** Mint an API token. POST /api-tokens; the plaintext secret is returned ONCE. Owner-only. */
  createAPIToken(input: CreateAPITokenInput): Promise<CreatedAPIToken>;
  /** Revoke an API token. DELETE /api-tokens/{id}; throws not_found for a gone token. Owner-only. */
  revokeAPIToken(id: string): Promise<void>;
  /** The tenant's enrollment tokens for deploying agents (metadata only). GET /enrollment-tokens — CapManageEnrollment. */
  listEnrollmentTokens(): Promise<EnrollmentToken[]>;
  /** Mint an enrollment token for a group; the plaintext is returned ONCE. POST /enrollment-tokens — CapManageEnrollment for the group. */
  createEnrollmentToken(input: CreateEnrollmentTokenInput): Promise<CreatedEnrollmentToken>;
  /** Revoke an enrollment token (idempotent). POST /enrollment-tokens/{id}/revoke; throws not_found for a gone token. */
  revokeEnrollmentToken(id: string): Promise<void>;
  /** Mint an attended session + one-time code for `groupId` (docs/12). Code is returned ONCE. */
  listAttendedSessions(offset?: number): Promise<{ sessions: AttendedSessionRecord[]; has_more: boolean }>;
  createAttendedSession(groupId: string, reason?: string): Promise<CreatedAttendedSession>;
  /** Poll one attended session's state (the panel's consent watch). */
  getAttendedSession(id: string): Promise<AttendedSessionRecord>;
  /**
   * The consent gate: mint the session ticket + signaling coordinates. Throws a
   * `kind === "conflict"` {@link ConsoleApiError} while the guest has not consented yet.
   */
  connectAttendedSession(id: string): Promise<ConnectedAttendedSession>;
  /** Stash an enrollment token for the guest to pick up and become a permanent agent. */
  promoteAttendedSession(id: string): Promise<void>;
  endAttendedSession(id: string): Promise<AttendedSessionRecord>;
  /**
   * Forward a batch of backstage/file-transfer audit events to `POST /audit/ingest` (H2, ADR-008).
   *
   * It belongs on THIS client rather than on a bare `fetch` because the endpoint sits behind the
   * same auth → tenant → CSRF chain as every other protected route: the session cookie and the
   * `X-CSRF-Token` echo come from `request`, so the forwarder never has to know about either.
   *
   * The events are `unknown[]` on purpose. Their wire contract is owned by `lib/audit_forward.ts`
   * (which mirrors the Rust and Go structs field for field); re-declaring it here would create a
   * second definition free to drift from the one the hash chain is actually computed over.
   */
  ingestAudit(body: AuditIngestBody, opts?: { keepalive?: boolean }): Promise<AuditIngestResult>;
  /** The tenant's webhook endpoints (metadata, no secrets). GET /tenant/webhooks — Owner-only. */
  listWebhooks(): Promise<TenantWebhook[]>;
  /** Register a webhook endpoint. POST /tenant/webhooks; the signing secret is returned ONCE. Owner-only. */
  createWebhook(input: CreateWebhookInput): Promise<CreatedTenantWebhook>;
  /** Remove a webhook endpoint (idempotent). DELETE /tenant/webhooks/{id} — Owner-only. */
  deleteWebhook(id: string): Promise<void>;
  /**
   * Recent delivery records for a webhook (last 50, newest-first). Ephemeral — cleared on server
   * restart. Returns an empty array when no deliveries have been attempted or the webhook is not found.
   * GET /tenant/webhooks/{id}/deliveries — Owner-only.
   */
  listWebhookDeliveries(webhookId: string): Promise<WebhookDeliveryRecord[]>;
}

export interface ConsoleApiClientOptions {
  /** Base URL / path prefix for the control plane. Default: the `/cp` dev-proxy prefix. */
  baseUrl?: string;
  /** Injectable fetch (defaults to the global `fetch`); the unit tests pass a fake. */
  fetch?: FetchLike;
  /**
   * Source of the cookie string the CSRF hook reads (defaults to `document.cookie`; empty in a
   * DOM-less environment). Tests inject a fixed string.
   */
  cookies?: () => string;
}

/** Typed HTTP client for the management-console endpoints. See the module doc for the contract. */
export class ConsoleApiClient implements ConsoleApi {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly cookies: () => string;
  private adoptedCsrf: { token: string; cookieBefore: string | null } | null = null;

  constructor(opts: ConsoleApiClientOptions = {}) {
    // Strip a trailing slash so `${baseUrl}/machines` never doubles up.
    this.baseUrl = (opts.baseUrl ?? DEFAULT_CONTROL_PLANE_URL).replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? ((input, init) => fetch(input, init));
    this.cookies = opts.cookies ?? (() => (typeof document === "undefined" ? "" : document.cookie));
  }

  /** The resolved base URL (for diagnostics/tests). */
  get base(): string {
    return this.baseUrl;
  }

  async ssoInfo(tenantSlug: string): Promise<SSOInfo> {
    const body = await this.request(`/auth/sso-info?tenant=${encodeURIComponent(tenantSlug)}`, "discover SSO", { method: "GET" });
    const providers = (body as Partial<SSOInfo> | null)?.providers;
    if (!Array.isArray(providers) || !providers.every(p => p && typeof p.id === "string" && typeof p.label === "string")) {
      throw new ConsoleApiError(200, "could not discover SSO: malformed response", "server");
    }
    return { providers: providers.map(p => ({ id: p.id, label: p.label })) };
  }

  async getSSO(): Promise<SSOSettings> {
    return ssoSettingsFrom(await this.request("/tenant/sso", "get SSO settings", { method: "GET" }));
  }

  async putSSO(input: SSOSettingsInput): Promise<SSOSettings> {
    const body: SSOSettingsInput = {
      entra_tenant_id: input.entra_tenant_id, client_id: input.client_id,
      enabled: input.enabled, trust_entra_mfa: input.trust_entra_mfa,
    };
    // Blank means keep the stored secret; the strict server decoder rejects an empty secret.
    if (input.client_secret !== undefined && input.client_secret !== "") body.client_secret = input.client_secret;
    return ssoSettingsFrom(await this.request("/tenant/sso", "save SSO settings", { method: "PUT", body }));
  }

  async ssoStepUpFresh(): Promise<boolean> {
    const body = await this.request("/auth/oidc/step-up-status", "check verification", { method: "GET" });
    return (body as { fresh?: unknown } | null)?.fresh === true;
  }

  async me(): Promise<MeInfo> {
    const body = await this.request("/me", "read the signed-in user", { method: "GET" });
    const b = (body ?? {}) as {
      email?: unknown;
      user_id?: unknown;
      capabilities?: unknown;
      access_expired?: unknown;
      access_expires_at?: unknown;
      access_window?: unknown;
      access_window_varies?: unknown;
      access_outside_window?: unknown;
    };
    if (typeof b.email !== "string" || b.email === "") {
      throw new ConsoleApiError(200, "could not read the signed-in user: malformed response", "server");
    }
    // docs/56/57: an older server sends none of the access fields, which reads as "not restricted".
    return {
      email: b.email,
      userId: typeof b.user_id === "string" && b.user_id !== "" ? b.user_id : null,
      capabilities: readMeCapabilities(b.capabilities),
      accessExpired: b.access_expired === true,
      accessExpiresAt: typeof b.access_expires_at === "string" ? b.access_expires_at : null,
      accessWindow: readWindow(b.access_window),
      accessWindowVaries: b.access_window_varies === true,
      accessOutsideWindow: b.access_outside_window === true,
    };
  }

  private async startSSO(mode: "link" | "test"): Promise<{ url: string }> {
    const body = await this.request(`/auth/oidc/${mode}/start`, `start SSO ${mode}`, { method: "POST" });
    const url = (body as { url?: unknown } | null)?.url;
    if (typeof url !== "string" || url === "") {
      throw new ConsoleApiError(200, `could not start SSO ${mode}: malformed response`, "server");
    }
    return { url };
  }

  startSSOLink(): Promise<{ url: string }> { return this.startSSO("link"); }
  startSSOTest(): Promise<{ url: string }> { return this.startSSO("test"); }

  async unlinkSSO(): Promise<void> {
    await this.request("/auth/oidc/unlink", "unlink Microsoft account", { method: "POST" });
  }

  async completeSSOTotp(pendingId: string, code: string): Promise<SSOTotpResult> {
    const body = await this.request("/auth/oidc/totp", "complete Microsoft sign-in", {
      method: "POST", public: true, body: { pending_id: pendingId, totp_code: code },
    });
    const r = body as Partial<SSOTotpResult> | null;
    if (!r || typeof r.user_id !== "string" || typeof r.tenant_id !== "string" ||
        typeof r.expires_at !== "string" || typeof r.csrf_token !== "string" || !r.csrf_token ||
        typeof r.return_path !== "string") {
      throw new ConsoleApiError(200, "could not complete Microsoft sign-in: malformed response", "server");
    }
    // Like password login, subsequent requests read the server-issued CSRF cookie. Adopt the
    // JSON token too, so the first mutation cannot race cookie visibility in an embedded browser.
    this.adoptedCsrf = { token: r.csrf_token, cookieBefore: csrfTokenFrom(this.cookies()) };
    return r as SSOTotpResult;
  }

  async managedInstallerAvailable(): Promise<boolean> {
    const body = await this.request("/managed-installer", "check installer availability", { method: "GET" });
    return (body as { available?: unknown } | null)?.available === true;
  }

  async managedInstallerWarnings(): Promise<string[]> {
    const body = await this.request("/managed-installer", "check installer status", { method: "GET" });
    return parseInstallerWarnings(body);
  }

  async downloadManagedInstaller(groupId: string, signal: AbortSignal): Promise<Blob> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const csrf = csrfTokenFrom(this.cookies());
    if (csrf) headers[CSRF_HEADER_NAME] = csrf;
    const response = await this.fetchImpl(`${this.baseUrl}/managed-installer`, {
      method: "POST", credentials: "include", cache: "no-store", headers,
      body: JSON.stringify({ group_id: groupId }), signal,
    });
    if (!response.ok) throw await this.toError(response, "download installer");
    if (response.headers.get("content-type")?.split(";")[0].trim() !== "application/zip" || !response.body) {
      await response.body?.cancel();
      throw new Error("The server did not return an installer bundle.");
    }
    // Two bounded 128 MiB release artifacts plus small ZIP/provisioning overhead.
    const limit = 257 * 1024 * 1024;
    const reader = response.body.getReader();
    const parts: Uint8Array<ArrayBuffer>[] = [];
    let size = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > limit) throw new Error("The installer bundle exceeds the download limit.");
        parts.push(value as Uint8Array<ArrayBuffer>);
      }
      if (size === 0) throw new Error("The installer bundle was empty.");
      return new Blob(parts, { type: "application/zip" });
    } catch (error) {
      await reader.cancel().catch(() => {});
      throw error;
    } finally { reader.releaseLock(); }
  }

  async listMachines(filter?: MachinePropertyFilter): Promise<MachineRecord[]> {
    return this.getList<MachineRecord>(machinesListPath(filter), "machines", "list machines");
  }

  async listMachinesWithPresence(filter?: MachinePropertyFilter): Promise<MachineListing> {
    const body = await this.request(machinesListPath(filter), "list machines", { method: "GET" });
    const envelope = body as Record<string, unknown> | null;
    const rows = envelope?.machines;
    if (!Array.isArray(rows)) {
      throw new ConsoleApiError(200, `could not list machines: malformed response (no "machines")`, "server");
    }
    // A server that omits the flag (an older control plane) is treated as "unknown", which is the
    // conservative reading: better to say status is unavailable than to assert it.
    return { machines: rows as MachineRecord[], presenceKnown: envelope?.presence_known === true };
  }

  async setMachineStatus(machineId: string, status: string): Promise<MachineRecord> {
    const body = await this.request(
      `/machines/${encodeURIComponent(machineId)}/status`,
      "set machine status",
      { method: "POST", body: { status } },
    );
    return this.pluck<MachineRecord>(body, "machine", "set machine status");
  }

  async setMachineGroup(machineId: string, groupId: string): Promise<MachineRecord> {
    const body = await this.request(
      `/machines/${encodeURIComponent(machineId)}/group`,
      "set machine group",
      { method: "POST", body: { group_id: groupId } },
    );
    return this.pluck<MachineRecord>(body, "machine", "set machine group");
  }

  async setMachineAlias(machineId: string, alias: string): Promise<MachineRecord> {
    const body = await this.request(
      `/machines/${encodeURIComponent(machineId)}/alias`,
      "set machine alias",
      { method: "PATCH", body: { alias } },
    );
    return this.pluck<MachineRecord>(body, "machine", "set machine alias");
  }

  async setMachineNote(machineId: string, note: string): Promise<MachineRecord> {
    const body = await this.request(
      `/machines/${encodeURIComponent(machineId)}/note`,
      "set machine note",
      { method: "PATCH", body: { note } },
    );
    return this.pluck<MachineRecord>(body, "machine", "set machine note");
  }

  async bulkSetMachineStatus(
    machineIds: readonly string[],
    status: string,
  ): Promise<BulkStatusResult[]> {
    const op = "bulk set machine status";
    const body = await this.request("/machines/bulk-status", op, {
      method: "POST",
      body: { machine_ids: machineIds, status },
    });
    const rows = (body as Record<string, unknown> | null)?.results;
    if (!Array.isArray(rows)) {
      throw new ConsoleApiError(200, `could not ${op}: malformed response (no "results")`, "server");
    }
    return rows as BulkStatusResult[];
  }

  async bulkSetMachineGroup(
    machineIds: readonly string[],
    groupId: string,
  ): Promise<BulkStatusResult[]> {
    const op = "bulk set machine group";
    const body = await this.request("/machines/bulk-group", op, {
      method: "POST",
      body: { machine_ids: machineIds, group_id: groupId },
    });
    const rows = (body as Record<string, unknown> | null)?.results;
    if (!Array.isArray(rows)) {
      throw new ConsoleApiError(200, `could not ${op}: malformed response (no "results")`, "server");
    }
    return rows as BulkStatusResult[];
  }

  async listMachineProperties(machineId: string): Promise<MachineProperty[]> {
    return this.getList<MachineProperty>(
      `/machines/${encodeURIComponent(machineId)}/properties`,
      "properties",
      "list machine properties",
    );
  }

  async setMachineProperty(machineId: string, key: string, value: string): Promise<MachineProperty> {
    const body = await this.request(
      `/machines/${encodeURIComponent(machineId)}/properties/${encodeURIComponent(key)}`,
      "set machine property",
      { method: "PUT", body: { value } },
    );
    return this.pluck<MachineProperty>(body, "property", "set machine property");
  }

  async deleteMachineProperty(machineId: string, key: string): Promise<void> {
    await this.request(
      `/machines/${encodeURIComponent(machineId)}/properties/${encodeURIComponent(key)}`,
      "delete machine property",
      { method: "DELETE" },
    );
  }

  async listSessions(filter?: SessionReportFilter): Promise<SessionRecord[]> {
    return this.getList<SessionRecord>(sessionReportPath("/sessions", filter), "sessions", "list sessions");
  }

  async listLiveSessions(): Promise<SessionRecord[]> {
    // `ended_at` is absent while a session is live. Use `== null` (not `=== undefined`) to also
    // handle the case where Go serializes a nil *time.Time as JSON `null` rather than omitting it
    // entirely — both mean "no end time yet". A non-empty string means the session has ended.
    const all = await this.listSessions();
    return all.filter((s) => s.ended_at == null);
  }

  async startSession(machineDeviceId: string): Promise<SessionRecord> {
    return (await this.startBrokeredSession(machineDeviceId)).session;
  }

  async startBrokeredSession(machineDeviceId: string, signal?: AbortSignal, opts?: { access?: "view_only" }): Promise<StartedSession> {
    const body = await this.request("/sessions", "start session", {
      method: "POST",
      body: { machine_id: machineDeviceId, ...(opts?.access ? { access: opts.access } : {}) },
      signal,
    });
    return this.parseStartedSession(body, "start session");
  }

  /** Decode a `POST /sessions`-shaped body. The transfer ticket endpoint answers the same shape. */
  private parseStartedSession(body: unknown, action: string): StartedSession {
    const session = this.pluck<SessionRecord>(body, "session", action);
    // `signaling` is optional (absent when the control plane has no issuer wired); a present
    // envelope must at least carry the coordinates the connect path needs.
    const signaling = (body as Record<string, unknown> | null)?.signaling as
      | SessionSignaling
      | undefined;
    if (signaling !== undefined && (typeof signaling !== "object" || signaling === null)) {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (bad "signaling")`, "server");
    }
    // The signed SESSION ACCESS POLICY (docs/01 §3/§5, loops 79/80). Optional for the same reason
    // `signaling` is — a control plane with no grant issuer wired mints none — but when it IS present the
    // viewer must forward it to the agent, so a malformed one is an error rather than a silent drop.
    //
    // Reading it here is load-bearing: this method is the ONLY place a start response is decoded, so a
    // field that is not plucked here does not exist for the rest of the app no matter how many types
    // declare it. (It was missed exactly that way — every layer above compiled and every test passed
    // while the policy was silently dropped and the whole feature was inert.)
    const sessionPolicy = parseSessionAccessPolicy(body, action);
    return {
      session,
      ...(signaling ? { signaling } : {}),
      ...(sessionPolicy ? { session_policy: sessionPolicy } : {}),
    };
  }

  /**
   * Mint ONE single-use elevation grant for a live session (`POST /sessions/{id}/elevation`).
   *
   * Every field is required and validated. A partially-decoded grant is worse than none: the caller
   * would forward a blob the agent refuses, having already spent a `session.elevation_minted` audit
   * event, and the technician would see a refusal with no local explanation.
   */
  async mintSessionElevation(sessionId: string): Promise<SessionElevation> {
    const body = await this.request(
      `/sessions/${encodeURIComponent(sessionId)}/elevation`,
      "elevate session",
      { method: "POST" },
    );
    const raw = (body as Record<string, unknown> | null)?.elevation as
      | Record<string, unknown>
      | undefined;
    if (
      !raw ||
      typeof raw.elevation_id !== "string" ||
      typeof raw.token !== "string" ||
      typeof raw.expires_at_ms !== "number" ||
      typeof raw.signed !== "string" ||
      raw.signed === ""
    ) {
      throw new ConsoleApiError(
        200,
        'could not elevate session: malformed response (bad "elevation")',
        "server",
      );
    }
    return {
      elevation_id: raw.elevation_id,
      token: raw.token,
      expires_at_ms: raw.expires_at_ms,
      signed: raw.signed,
    };
  }

  /**
   * Renew a live unattended session's LEASE (`POST /sessions/{id}/policy`, docs/25 F03).
   *
   * Every field is required and validated, for the same reason `mintSessionElevation` validates
   * every field: a partially-decoded lease would be forwarded to the agent, refused there, and the
   * session would end for a reason with no local explanation.
   */
  async renewSessionPolicy(sessionId: string, signal?: AbortSignal): Promise<SessionLease> {
    const body = await this.request(
      `/sessions/${encodeURIComponent(sessionId)}/policy`,
      "renew session lease",
      { method: "POST", signal },
    );
    const raw = (body as Record<string, unknown> | null)?.session_policy as
      | Record<string, unknown>
      | undefined;
    if (
      !raw ||
      typeof raw.access !== "string" ||
      typeof raw.signed !== "string" ||
      raw.signed === "" ||
      typeof raw.lease_ttl_ms !== "number" ||
      raw.lease_ttl_ms <= 0 ||
      typeof raw.expires_at_ms !== "number"
    ) {
      throw new ConsoleApiError(
        200,
        'could not renew session lease: malformed response (bad "session_policy")',
        "server",
      );
    }
    return {
      access: raw.access,
      signed: raw.signed,
      lease_ttl_ms: raw.lease_ttl_ms,
      expires_at_ms: raw.expires_at_ms,
    };
  }

  async endSession(sessionId: string): Promise<SessionRecord> {
    const body = await this.request(
      `/sessions/${encodeURIComponent(sessionId)}/end`,
      "end session",
      { method: "POST", keepalive: true },
    );
    return this.pluck<SessionRecord>(body, "session", "end session");
  }

  async offerSessionTransfer(sessionId: string, opts?: { toUserId?: string; note?: string }): Promise<SessionTransfer> {
    const body = await this.request(`/sessions/${encodeURIComponent(sessionId)}/transfer`, "offer the session", {
      method: "POST",
      body: { to_user_id: opts?.toUserId ?? "", note: opts?.note ?? "" },
    });
    return this.pluckTransfer(body, "offer the session");
  }

  async sessionTransferCandidates(sessionId: string): Promise<TransferCandidates> {
    const action = "list transfer candidates";
    const body = await this.request(`/sessions/${encodeURIComponent(sessionId)}/transfer-candidates`, action, { method: "GET" });
    const rec = body as Record<string, unknown> | null;
    const group = rec?.group as Record<string, unknown> | undefined;
    if (!Array.isArray(rec?.candidates) || typeof group !== "object" || group === null || typeof group.id !== "string") {
      throw new ConsoleApiError(200, `could not ${action}: malformed response`, "server");
    }
    return {
      candidates: (rec.candidates as TransferCandidate[]).filter((c) => typeof c?.id === "string"),
      group: { id: group.id, ...(typeof group.name === "string" ? { name: group.name } : {}) },
    };
  }

  async cancelSessionTransfer(transferId: string): Promise<SessionTransfer> {
    const body = await this.request(`/session-transfers/${encodeURIComponent(transferId)}`, "cancel the transfer", { method: "DELETE" });
    return this.pluckTransfer(body, "cancel the transfer");
  }

  async listIncomingTransfers(): Promise<SessionTransfer[]> {
    return this.getList<SessionTransfer>("/session-transfers/incoming", "transfers", "list incoming transfers");
  }

  async listHelpRequests(): Promise<HelpRequest[]> {
    return this.getList<HelpRequest>("/help-requests", "requests", "list help requests");
  }

  async acceptHelpRequest(requestId: string, opId?: string): Promise<StartedSession> {
    const action = "accept the help request";
    const body = await this.request(`/help-requests/${encodeURIComponent(requestId)}/accept`, action, {
      method: "POST",
      ...(opId ? { body: { op_id: opId } } : {}),
    });
    return this.parseStartedSession(body, action);
  }

  async getSessionTransfer(transferId: string): Promise<SessionTransfer> {
    const body = await this.request(`/session-transfers/${encodeURIComponent(transferId)}`, "read the transfer", { method: "GET" });
    return this.pluckTransfer(body, "read the transfer");
  }

  async acceptSessionTransfer(transferId: string): Promise<SessionTransfer> {
    const body = await this.request(`/session-transfers/${encodeURIComponent(transferId)}/accept`, "accept the transfer", { method: "POST" });
    return this.pluckTransfer(body, "accept the transfer");
  }

  async sessionTransferTicket(transferId: string): Promise<StartedSession> {
    const action = "connect to the transferred session";
    const body = await this.request(`/session-transfers/${encodeURIComponent(transferId)}/ticket`, action, { method: "POST" });
    return this.parseStartedSession(body, action);
  }

  private pluckTransfer(body: unknown, action: string): SessionTransfer {
    const t = this.pluck<SessionTransfer>(body, "transfer", action);
    if (typeof t.id !== "string" || typeof t.state !== "string") {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (bad "transfer")`, "server");
    }
    return t;
  }

  async setSessionNote(sessionId: string, note: string): Promise<SessionRecord> {
    const body = await this.request(
      `/sessions/${encodeURIComponent(sessionId)}/note`,
      "set session note",
      { method: "PATCH", body: { note } },
    );
    return this.pluck<SessionRecord>(body, "session", "set session note");
  }

  async listAudit(limit?: number, filter?: AuditListFilter): Promise<MgmtAuditEvent[]> {
    return this.getList<MgmtAuditEvent>(auditListPath(limit, filter), "events", "list audit events");
  }

  async auditSummary(filter?: AuditListFilter): Promise<AuditActionCount[]> {
    return this.getList<AuditActionCount>(auditSummaryPath(filter), "summary", "summarize audit");
  }

  async sessionsByMachine(filter?: SessionReportFilter): Promise<MachineSessionCount[]> {
    return this.getList<MachineSessionCount>(
      sessionReportPath("/reports/sessions-by-machine", filter),
      "sessions_by_machine",
      "summarize sessions by machine",
    );
  }

  async sessionsByTechnician(filter?: SessionReportFilter): Promise<TechnicianSessionCount[]> {
    return this.getList<TechnicianSessionCount>(
      sessionReportPath("/reports/sessions-by-technician", filter),
      "sessions_by_technician",
      "summarize sessions by technician",
    );
  }

  async listTenants(): Promise<Tenant[]> {
    return this.getList<Tenant>("/tenants", "tenants", "list tenants");
  }

  async platformWhoami(): Promise<PlatformWhoami> {
    const body = (await this.request("/platform/me", "check platform access", { method: "GET" })) as Record<string, unknown> | null;
    // Only an explicit true grants anything in the UI; the server decides every operation anyway.
    return {
      operator: body?.operator === true,
      mfa_ok: body?.mfa_ok === true,
      mfa_fresh: body?.mfa_fresh === true,
    };
  }

  async listPlatformTenants(): Promise<PlatformTenant[]> {
    return this.getList<PlatformTenant>("/platform/tenants", "tenants", "list tenants");
  }

  async createTenant(input: CreateTenantInput): Promise<Tenant> {
    const req: Record<string, string> = { slug: input.slug, name: input.name };
    if (input.deploymentMode) req.deployment_mode = input.deploymentMode;
    const body = await this.request("/platform/tenants", "create tenant", { method: "POST", body: req });
    return this.pluck<Tenant>(body, "tenant", "create tenant");
  }

  async setTenantSuspended(id: string, suspended: boolean, confirmSlug: string, reason: string): Promise<Tenant> {
    const verb = suspended ? "suspend" : "resume";
    const body = await this.request(`/platform/tenants/${encodeURIComponent(id)}/${verb}`, `${verb} tenant`, {
      method: "POST",
      body: { confirm_slug: confirmSlug, reason },
    });
    return this.pluck<Tenant>(body, "tenant", `${verb} tenant`);
  }

  async listTenantHostnames(tenantId: string): Promise<HostnameAssignment[]> {
    return this.getList<HostnameAssignment>(`/platform/tenants/${encodeURIComponent(tenantId)}/hostnames`, "hostnames", "list hostnames");
  }

  async assignHostname(tenantId: string, host: string, acknowledge: readonly string[] = [], overrideReason = ""): Promise<HostnameAssignment> {
    const body = await this.request(`/platform/tenants/${encodeURIComponent(tenantId)}/hostnames`, "assign the hostname", {
      method: "POST",
      body: { host, acknowledge, override_reason: overrideReason },
    });
    return this.pluck<HostnameAssignment>(body, "hostname", "assign the hostname");
  }

  async activateHostname(id: string): Promise<HostnameAssignment> {
    const body = await this.request(`/platform/hostnames/${encodeURIComponent(id)}/activate`, "activate the hostname", { method: "POST", body: {} });
    return this.pluck<HostnameAssignment>(body, "hostname", "activate the hostname");
  }

  async releaseHostname(id: string, reason: string): Promise<HostnameAssignment> {
    const body = await this.request(`/platform/hostnames/${encodeURIComponent(id)}/release`, "release the hostname", { method: "POST", body: { reason } });
    return this.pluck<HostnameAssignment>(body, "hostname", "release the hostname");
  }

  async reactivateHostname(id: string, activate: boolean): Promise<HostnameAssignment> {
    const body = await this.request(`/platform/hostnames/${encodeURIComponent(id)}/reactivate`, "reactivate the hostname", { method: "POST", body: { activate } });
    return this.pluck<HostnameAssignment>(body, "hostname", "reactivate the hostname");
  }

  async getBrandingReview(tenantId: string): Promise<BrandingReviewResult> {
    const body = await this.request(`/platform/tenants/${encodeURIComponent(tenantId)}/branding/review`, "load the branding review", { method: "GET" });
    const o = body as Record<string, unknown> | null;
    const review = this.pluck<BrandingReviewView>(body, "review", "load the branding review");
    const findings = o?.findings;
    if (!Array.isArray(findings)) throw new ConsoleApiError(200, `could not load the branding review: malformed response (no "findings")`, "server");
    return { review, logo_png_base64: typeof o?.logo_png_base64 === "string" ? o.logo_png_base64 : "", findings: findings as PlatformFinding[] };
  }

  async approveBranding(tenantId: string, req: BrandingApproveRequest): Promise<void> {
    await this.request(`/platform/tenants/${encodeURIComponent(tenantId)}/branding/approve`, "approve the branding", { method: "POST", body: req });
  }

  async withdrawBranding(tenantId: string, reason: string): Promise<void> {
    await this.request(`/platform/tenants/${encodeURIComponent(tenantId)}/branding/withdraw`, "withdraw the branding", { method: "POST", body: { reason } });
  }

  async stepUp(code: string): Promise<void> {
    await this.request("/auth/step-up", "verify your code", { method: "POST", body: { code } });
  }

  async requestDirective(machineId: string, kind: DirectiveKind, confirm?: string): Promise<AgentDirective> {
    const body: Record<string, string> = { kind };
    if (confirm !== undefined) body.confirm = confirm;
    const res = await this.request(`/machines/${encodeURIComponent(machineId)}/directives`, "request the agent action", { method: "POST", body });
    return this.pluck<AgentDirective>(res, "directive", "request the agent action");
  }

  async forgetMachine(machineId: string, confirm: string): Promise<ForgetMachineResult> {
    const res = await this.request(`/machines/${encodeURIComponent(machineId)}/forget`, "forget the machine", { method: "POST", body: { confirm } });
    const body = res as { outcome?: unknown; closed_directives?: unknown } | null;
    if (body?.outcome !== "forgotten" && body?.outcome !== "already_removed") {
      throw new ConsoleApiError(200, `could not forget the machine: malformed response (no outcome)`, "server");
    }
    return {
      outcome: body.outcome,
      machine: this.pluck<MachineRecord>(res, "machine", "forget the machine"),
      closed_directives: Array.isArray(body.closed_directives) ? (body.closed_directives as AgentDirective[]) : [],
    };
  }

  async listMachineDirectives(machineId: string): Promise<AgentDirective[]> {
    return this.getList<AgentDirective>(`/machines/${encodeURIComponent(machineId)}/directives`, "directives", "list agent directives");
  }

  async listActiveDirectives(opts?: { maxPages?: number }): Promise<ActiveDirectiveList> {
    const out: ActiveDirective[] = [];
    const maxPages = Math.max(1, opts?.maxPages ?? 5);
    let before = "";
    let beforeId = "";
    for (let page = 0; page < maxPages; page++) {
      const q = before ? `&before=${encodeURIComponent(before)}&before_id=${encodeURIComponent(beforeId)}` : "";
      const body = await this.request(`/directives?state=active${q}`, "list pending removals", { method: "GET" });
      const rows = (body as Record<string, unknown> | null)?.directives;
      if (!Array.isArray(rows)) throw new ConsoleApiError(200, `could not list pending removals: malformed response (no "directives")`, "server");
      out.push(...(rows as ActiveDirective[]));
      const next = (body as { next_before?: unknown }).next_before;
      const nextId = (body as { next_before_id?: unknown }).next_before_id;
      if (typeof next !== "string" || next === "") return { rows: out, hasMore: false };
      if (typeof nextId !== "string" || nextId === "") {
        throw new ConsoleApiError(200, `could not list pending removals: malformed response (next_before without next_before_id)`, "server");
      }
      before = next;
      beforeId = nextId;
    }
    return { rows: out, hasMore: true };
  }

  async approveDirective(id: string): Promise<AgentDirective> {
    const res = await this.request(`/directives/${encodeURIComponent(id)}/approve`, "approve the removal", { method: "POST", body: {} });
    return this.pluck<AgentDirective>(res, "directive", "approve the removal");
  }

  async cancelDirective(id: string, reason?: string): Promise<AgentDirective> {
    const res = await this.request(`/directives/${encodeURIComponent(id)}/cancel`, "cancel the removal", { method: "POST", body: { reason: reason ?? "" } });
    return this.pluck<AgentDirective>(res, "directive", "cancel the removal");
  }

  async getDirectivePolicy(): Promise<DirectivePolicy> {
    const res = await this.request("/tenant/directive-policy", "read the removal policy", { method: "GET" });
    return this.pluck<DirectivePolicy>(res, "policy", "read the removal policy");
  }

  async setDirectivePolicy(requireSecondApprover: boolean): Promise<DirectivePolicy> {
    const res = await this.request("/tenant/directive-policy", "save the removal policy", { method: "PUT", body: { require_second_approver: requireSecondApprover } });
    return this.pluck<DirectivePolicy>(res, "policy", "save the removal policy");
  }

  async listToolbox(): Promise<ToolboxListing> {
    const body = (await this.request("/toolbox", "list the toolbox", { method: "GET" })) as Record<string, unknown> | null;
    const items = body?.items;
    if (!Array.isArray(items)) {
      throw new ConsoleApiError(200, `could not list the toolbox: malformed response (no "items")`, "server");
    }
    return {
      items: items as ToolboxItem[],
      canManageShared: body?.can_manage_shared === true,
      maxPowerShellBytes: typeof body?.max_powershell_bytes === "number" ? body.max_powershell_bytes : 16384,
      maxCmdUnits: typeof body?.max_cmd_units === "number" ? body.max_cmd_units : 7800,
    };
  }

  async createToolboxItem(scope: ToolboxScope, input: ToolboxItemInput): Promise<ToolboxItem> {
    const body = await this.request("/toolbox", "save the toolbox item", { method: "POST", body: { ...input, scope } });
    return this.pluck<ToolboxItem>(body, "item", "save the toolbox item");
  }

  async updateToolboxItem(id: string, expectedVersion: number, input: ToolboxItemInput): Promise<ToolboxItem> {
    const body = await this.request(`/toolbox/${encodeURIComponent(id)}`, "save the toolbox item", {
      method: "PUT",
      body: { ...input, expected_version: expectedVersion },
    });
    return this.pluck<ToolboxItem>(body, "item", "save the toolbox item");
  }

  async deleteToolboxItem(id: string, expectedVersion: number): Promise<void> {
    await this.request(`/toolbox/${encodeURIComponent(id)}?expected_version=${expectedVersion}`, "delete the toolbox item", {
      method: "DELETE",
    });
  }

  async requestToolboxRun(id: string, sessionId: string, expectedVersion: number): Promise<ToolboxRunGrant> {
    const body = (await this.request(`/toolbox/${encodeURIComponent(id)}/runs`, "run the toolbox item", {
      method: "POST",
      body: { session_id: sessionId, expected_version: expectedVersion },
    })) as Record<string, unknown> | null;
    const command = body?.command;
    const shell = body?.shell;
    const runAs = body?.run_as;
    if (typeof command !== "string" || (shell !== "powershell" && shell !== "cmd") || (runAs !== "system" && runAs !== "user")) {
      throw new ConsoleApiError(200, "could not run the toolbox item: malformed response", "server");
    }
    return { request_id: String(body?.request_id ?? ""), shell, run_as: runAs, command };
  }

  async requestCommandRun(sessionId: string, shell: ToolboxShell, runAs: ToolboxRunAs, body: string): Promise<ToolboxRunGrant> {
    const resp = (await this.request(`/sessions/${encodeURIComponent(sessionId)}/command-run`, "run the command", {
      method: "POST",
      body: { shell, run_as: runAs, body },
    })) as Record<string, unknown> | null;
    const command = resp?.command;
    const gotShell = resp?.shell;
    const gotRunAs = resp?.run_as;
    if (typeof command !== "string" || (gotShell !== "powershell" && gotShell !== "cmd") || (gotRunAs !== "system" && gotRunAs !== "user")) {
      throw new ConsoleApiError(200, "could not run the command: malformed response", "server");
    }
    return { request_id: String(resp?.request_id ?? ""), shell: gotShell, run_as: gotRunAs, command };
  }

  async getTenantIPAllowlist(): Promise<TenantIPAllowlist> {
    const body = await this.request("/tenant/ip-allowlist", "get ip allow-list", { method: "GET" });
    const obj = body as Record<string, unknown> | null;
    const cidrs = obj?.cidrs;
    if (!Array.isArray(cidrs)) {
      throw new ConsoleApiError(200, `could not get ip allow-list: malformed response (no "cidrs")`, "server");
    }
    const yourIp = typeof obj?.your_ip === "string" ? obj.your_ip : "";
    return { cidrs: cidrs as string[], yourIp };
  }

  async addTenantIPAllowlistEntry(cidr: string): Promise<void> {
    await this.request("/tenant/ip-allowlist", "add ip allow-list entry", { method: "POST", body: { cidr } });
  }

  async deleteTenantIPAllowlistEntry(cidr: string): Promise<void> {
    // The CIDR rides a query param (it contains a '/', so it cannot be a path segment).
    await this.request(
      `/tenant/ip-allowlist?cidr=${encodeURIComponent(cidr)}`,
      "remove ip allow-list entry",
      { method: "DELETE" },
    );
  }

  async listUsers(): Promise<UserSummary[]> {
    return this.getList<UserSummary>("/users", "users", "list users");
  }

  async listRoles(): Promise<RoleCatalogEntry[]> {
    return this.getList<RoleCatalogEntry>("/roles", "roles", "list roles");
  }

  async createUser(input: CreateUserInput): Promise<UserSummary> {
    const payload: Record<string, unknown> = {
      email: input.email,
      display_name: input.displayName,
      role: input.role,
    };
    // Only send scoped_group_ids when groups are chosen: omitting it invites a tenant-wide user, and
    // sending an explicit [] would also be tenant-wide — either way the default is all groups.
    if (input.scopedGroupIds && input.scopedGroupIds.length > 0) {
      payload.scoped_group_ids = input.scopedGroupIds;
    }
    if (input.expiresAt) payload.expires_at = input.expiresAt;
    if (input.accessWindow) payload.access_window = input.accessWindow;
    const body = await this.request("/users", "create user", { method: "POST", body: payload });
    return this.pluck<UserSummary>(body, "user", "create user");
  }

  async setUserDisabled(id: string, disabled: boolean): Promise<void> {
    const action = disabled ? "disable" : "enable";
    await this.request(`/users/${encodeURIComponent(id)}/${action}`, `${action} user`, { method: "POST" });
  }

  async signOutUser(id: string): Promise<number> {
    const body = await this.request(`/users/${encodeURIComponent(id)}/sign-out`, "sign out user", {
      method: "POST",
    });
    return (body as { revoked?: number } | null)?.revoked ?? 0;
  }

  async clearUserLockout(id: string): Promise<void> {
    await this.request(`/users/${encodeURIComponent(id)}/lockout`, "clear user lockout", {
      method: "DELETE",
    });
  }

  /**
   * Set a user's role. `opts.expiresAt` (docs/56): OMITTED (undefined) preserves the stored expiry,
   * `null` makes access permanent, an RFC 3339 string sets when it ends. Only send it when the operator
   * changed it, so an unchanged, already-past expiry is preserved rather than rejected. `opts.accessWindow`
   * (docs/57) follows the same rule (null = any time). `opts.scopedGroupIds` sends the scope explicitly
   * (a user whose memberships differ must state scope, expiry and window together).
   */
  async setUserRole(id: string, role: string, opts?: SetUserRoleOptions): Promise<void> {
    const body: Record<string, unknown> = { role };
    if (opts && opts.expiresAt !== undefined) body.expires_at = opts.expiresAt;
    if (opts && opts.accessWindow !== undefined) body.access_window = opts.accessWindow;
    if (opts && opts.scopedGroupIds !== undefined) body.scoped_group_ids = opts.scopedGroupIds;
    await this.request(`/users/${encodeURIComponent(id)}/role`, "set user role", {
      method: "POST",
      body,
    });
  }

  async issuePasswordReset(id: string, password: string, ttlSeconds?: number): Promise<IssuedSetupLink> {
    const body: Record<string, unknown> = { password };
    if (ttlSeconds !== undefined) body.ttl_seconds = ttlSeconds;
    const env = (await this.request(`/users/${encodeURIComponent(id)}/password-reset`, "issue setup link", {
      method: "POST",
      body,
    })) as Record<string, unknown>;
    const credentialToken = this.pluck<CredentialToken>(env, "credential_token", "issue setup link");
    if (typeof env.token !== "string") {
      throw new ConsoleApiError(200, 'could not issue setup link: malformed response (no "token")', "server");
    }
    return { token: env.token, credentialToken, firstProvision: env.first_provision === true };
  }

  async revokePasswordReset(id: string): Promise<number> {
    const env = (await this.request(`/users/${encodeURIComponent(id)}/password-reset`, "revoke setup links", {
      method: "DELETE",
    })) as Record<string, unknown>;
    return typeof env.revoked === "number" ? env.revoked : 0;
  }

  async redeemPasswordReset(token: string, newPassword: string): Promise<RedeemSetupResult> {
    const env = (await this.request("/auth/password/redeem", "set password", {
      method: "POST",
      body: { token, new_password: newPassword },
    })) as Record<string, unknown>;
    return {
      changed: env.changed === true,
      sessions_revoked: typeof env.sessions_revoked === "number" ? env.sessions_revoked : 0,
    };
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request("/me/password", "change password", {
      method: "POST",
      body: { current_password: currentPassword, new_password: newPassword },
    });
  }

  async changeEmail(currentPassword: string, newEmail: string): Promise<string> {
    const result = (await this.request("/me/email", "change login email", {
      method: "POST",
      body: { current_password: currentPassword, new_email: newEmail },
    })) as Record<string, unknown> | null;
    if (result?.changed !== true || typeof result.email !== "string" || result.email === "") {
      throw new ConsoleApiError(200, "Could not confirm the email change. Check your account before trying again.", "server");
    }
    return result.email;
  }

  async enrollTotp(stepUp: { password?: string; code?: string }): Promise<{ secret: string; otpauth_uri: string }> {
    const body: Record<string, string> = {};
    if (stepUp.password) body.password = stepUp.password;
    if (stepUp.code) body.code = stepUp.code;
    const result = await this.request("/auth/totp/enroll", "enroll TOTP", {
      method: "POST",
      body,
    });
    const obj = result as Record<string, unknown> | null;
    return {
      secret: typeof obj?.secret === "string" ? obj.secret : "",
      otpauth_uri: typeof obj?.otpauth_uri === "string" ? obj.otpauth_uri : "",
    };
  }

  async confirmTotp(code: string): Promise<void> {
    await this.request("/auth/totp/confirm", "confirm TOTP enrollment", {
      method: "POST",
      body: { code },
    });
  }

  async getTenantBranding(): Promise<TenantBranding> {
    const body = await this.request("/tenant/branding", "get branding", { method: "GET" });
    return brandingFrom(body);
  }

  async setTenantBranding(branding: TenantBranding): Promise<TenantBranding> {
    const body = await this.request("/tenant/branding", "set branding", {
      method: "PUT",
      body: { product_name: branding.product_name, accent_color: branding.accent_color, logo_data_uri: branding.logo_data_uri },
    });
    return brandingFrom(body);
  }

  async getBrandingRevisions(): Promise<BrandingRevisionsView> {
    const body = await this.request("/tenant/branding/revisions", "get the public join page branding", { method: "GET" });
    const view = parseBrandingRevisions(body);
    if (view === null) throw new ConsoleApiError(200, "could not get the public join page branding: malformed response", "server");
    return view;
  }

  async createBrandingRevision(input: BrandRevisionInput): Promise<BrandRevisionResult> {
    const body = await this.request("/tenant/branding/revisions", "submit the public join page", { method: "POST", body: input });
    const result = parseBrandRevisionResult(body);
    if (result === null) throw new ConsoleApiError(200, "could not submit the public join page: malformed response", "server");
    return result;
  }

  async getSessionPolicy(): Promise<SessionPolicy> {
    const body = await this.request("/tenant/session-policy", "get session policy", { method: "GET" });
    return sessionPolicyFrom(body, "get session policy");
  }

  async setSessionPolicy(policy: SessionPolicy): Promise<SessionPolicy> {
    const body = await this.request("/tenant/session-policy", "set session policy", {
      method: "PUT",
      body: {
        max_concurrent_sessions: policy.max_concurrent_sessions,
        max_session_seconds: policy.max_session_seconds,
      },
    });
    return sessionPolicyFrom(body, "set session policy");
  }

  async getTenantSecurityPolicy(): Promise<TenantSecurityPolicy> {
    const body = await this.request("/tenant/security-policy", "get security policy", { method: "GET" });
    return tenantSecurityPolicyFrom(body, "get security policy");
  }

  async getPlatformReach(from: string, to: string): Promise<ReachReport> {
    const body = await this.request(`/platform/reach?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`, "read the request report", { method: "GET" });
    const r = parseReachReport(body);
    if (r === null) throw new ConsoleApiError(200, "could not read the request report: malformed response", "server");
    return r;
  }

  async getAdoption(): Promise<Adoption> {
    const a = parseAdoption(await this.request("/adoption", "read the adoption counts", { method: "GET" }));
    if (a === null) throw new ConsoleApiError(200, "could not read the adoption counts: malformed response", "server");
    return a;
  }

  async getRecordingPolicy(): Promise<RecordingPolicy> {
    const body = await this.request("/tenant/recording-policy", "read the recording policy", { method: "GET" });
    const p = parseRecordingPolicy(body);
    if (p === null) throw new ConsoleApiError(200, "could not read the recording policy: malformed response", "server");
    return p;
  }

  async setRecordingPolicy(policy: RecordingPolicyBody): Promise<RecordingPolicy> {
    // Every field, spelled out: never spread an object that might carry (or lack) more.
    const body = await this.request("/tenant/recording-policy", "save the recording policy", {
      method: "PUT",
      body: {
        retention_days: policy.retention_days,
        max_recording_bytes: policy.max_recording_bytes,
        quota_bytes: policy.quota_bytes,
      },
    });
    const p = parseRecordingPolicy(body);
    if (p === null) throw new ConsoleApiError(200, "could not save the recording policy: malformed response", "server");
    return p;
  }

  async listRecordings(opts: { limit?: number; cursor?: string; sessionId?: string; machineId?: string } = {}): Promise<RecordingPage> {
    const q = new URLSearchParams();
    if (opts.limit !== undefined) q.set("limit", String(opts.limit));
    if (opts.cursor) q.set("cursor", opts.cursor);
    if (opts.sessionId) q.set("session_id", opts.sessionId);
    if (opts.machineId) q.set("machine_id", opts.machineId);
    const qs = q.toString();
    const body = await this.request(`/recordings${qs ? `?${qs}` : ""}`, "list recordings", { method: "GET" });
    const page = parseRecordingPage(body);
    if (page === null) throw new ConsoleApiError(200, "could not list recordings: malformed response", "server");
    return page;
  }

  async getRecording(id: string): Promise<RecordingDetail> {
    const body = await this.request(`/recordings/${encodeURIComponent(id)}`, "read the recording", { method: "GET" });
    const d = parseRecordingDetail(body);
    if (d === null) throw new ConsoleApiError(200, "could not read the recording: malformed response", "server");
    return d;
  }

  async getRecordingPlaylist(id: string): Promise<RecordingPlaylist> {
    const body = await this.request(`/recordings/${encodeURIComponent(id)}/playlist`, "load the playlist", { method: "GET" });
    const p = parseRecordingPlaylist(body);
    if (p === null) throw new ConsoleApiError(200, "could not load the playlist: malformed response", "server");
    return p;
  }

  async setTenantSecurityPolicy(policy: TenantSecurityPolicy): Promise<TenantSecurityPolicy> {
    const body = await this.request("/tenant/security-policy", "set security policy", {
      method: "PUT",
      body: { require_2fa: policy.require_2fa },
    });
    return tenantSecurityPolicyFrom(body, "set security policy");
  }

  async getPublishedAgentVersion(): Promise<AgentVersionInfo> {
    const body = await this.request("/agent-version", "get published agent version", { method: "GET" });
    const obj = body as Record<string, unknown> | null;
    const configured = obj?.configured === true;
    const version = typeof obj?.version === "string" ? obj.version : undefined;
    return { configured, version };
  }

  async listDynamicGroups(): Promise<DynamicGroup[]> {
    return this.getList<DynamicGroup>("/dynamic-groups", "groups", "list dynamic groups");
  }

  async createDynamicGroup(input: CreateDynamicGroupInput): Promise<DynamicGroup> {
    const req: Record<string, string> = { name: input.name, property_key: input.propertyKey };
    if (input.propertyValue !== undefined) req.property_value = input.propertyValue;
    const body = await this.request("/dynamic-groups", "create dynamic group", { method: "POST", body: req });
    return this.pluck<DynamicGroup>(body, "group", "create dynamic group");
  }

  async deleteDynamicGroup(id: string): Promise<void> {
    await this.request(`/dynamic-groups/${encodeURIComponent(id)}`, "delete dynamic group", { method: "DELETE" });
  }

  async resolveDynamicGroup(id: string): Promise<MachineRecord[]> {
    return this.getList<MachineRecord>(
      `/dynamic-groups/${encodeURIComponent(id)}/machines`,
      "machines",
      "resolve dynamic group",
    );
  }

  async listMachineGroups(): Promise<MachineGroup[]> {
    return this.getList<MachineGroup>("/machine-groups", "machine_groups", "list machine groups");
  }

  async createMachineGroup(input: CreateMachineGroupInput): Promise<MachineGroup> {
    const body = await this.request("/machine-groups", "create machine group", {
      method: "POST",
      // parent_id only when a subgroup is asked for, so a create at the top level is byte-identical to what
      // an older control plane (no nesting) accepts.
      body: input.parentId ? { name: input.name, parent_id: input.parentId } : { name: input.name },
    });
    return this.pluck<MachineGroup>(body, "machine_group", "create machine group");
  }

  async moveMachineGroup(id: string, parentId: string | null): Promise<void> {
    await this.request(`/machine-groups/${encodeURIComponent(id)}/move`, "move machine group", {
      method: "POST",
      body: { parent_id: parentId },
    });
  }

  async renameMachineGroup(id: string, name: string): Promise<MachineGroup> {
    const body = await this.request(`/machine-groups/${encodeURIComponent(id)}`, "rename machine group", {
      method: "PATCH",
      body: { name },
    });
    return this.pluck<MachineGroup>(body, "machine_group", "rename machine group");
  }

  async deleteMachineGroup(id: string): Promise<void> {
    await this.request(`/machine-groups/${encodeURIComponent(id)}`, "delete machine group", { method: "DELETE" });
  }

  async listGroupSessionPolicies(): Promise<GroupSessionCap[]> {
    return (await this.listGroupSessionPolicyView()).policies;
  }

  async listGroupSessionPolicyView(): Promise<GroupSessionPolicyView> {
    const action = "list group session policies";
    const body = await this.request("/machine-groups/session-policies", action, { method: "GET" });
    const rows = (body as Record<string, unknown> | null)?.["policies"];
    if (!Array.isArray(rows)) {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (no "policies")`, "server");
    }
    // The console seeds an editable draft from every row, and the PUT is a full overwrite. A row with a
    // wrong-typed setting would be seeded as that setting's zero value and written back on the next save,
    // so a malformed row fails the whole read (the panel then renders "unknown" and refuses to submit).
    // An ABSENT field is accepted: a control plane that predates the setting stores nothing for it, and the
    // zero value is exactly what it enforces.
    if (!rows.every(isGroupSessionPolicyRow)) {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (bad policy row)`, "server");
    }
    // `effective` is absent on a server that predates it (null); PRESENT but malformed fails the read rather
    // than silently falling back to the browser merge, which cannot see a hidden ancestor.
    const rawEffective = (body as Record<string, unknown>)["effective"];
    let effective: Record<string, GroupEffectivePolicy> | null = null;
    if (rawEffective !== undefined && rawEffective !== null) {
      if (typeof rawEffective !== "object" || Array.isArray(rawEffective)) {
        throw new ConsoleApiError(200, `could not ${action}: malformed response (bad effective map)`, "server");
      }
      effective = {};
      for (const [id, v] of Object.entries(rawEffective)) {
        if (!isGroupEffectivePolicy(v)) {
          throw new ConsoleApiError(200, `could not ${action}: malformed response (bad effective policy)`, "server");
        }
        effective[id] = v;
      }
    }
    return { policies: rows, effective };
  }

  async setGroupSessionPolicy(
    groupId: string,
    policy: {
      max_concurrent_sessions: number;
      enforce_view_only: boolean;
      allow_backstage_under_view_only: boolean;
      prohibit_recording: boolean;
      require_recording: boolean;
      max_session_duration_seconds: number;
      max_idle_seconds: number;
    },
  ): Promise<GroupSessionCap> {
    const body = await this.request(
      `/machine-groups/${encodeURIComponent(groupId)}/session-policy`,
      "set group session policy",
      {
        // Every field is spelled out rather than spreading `policy`, so adding a setting to the server
        // without adding it here is a TYPE ERROR at this line rather than a field that silently reverts to
        // its zero value on the next save. The PUT is a full overwrite; there is no such thing as "not
        // sending" one of these.
        method: "PUT",
        body: {
          max_concurrent_sessions: policy.max_concurrent_sessions,
          enforce_view_only: policy.enforce_view_only,
          allow_backstage_under_view_only: policy.allow_backstage_under_view_only,
          prohibit_recording: policy.prohibit_recording,
          require_recording: policy.require_recording,
          max_session_duration_seconds: policy.max_session_duration_seconds,
          max_idle_seconds: policy.max_idle_seconds,
        },
      },
    );
    // The Go handler returns the policy object flat (no envelope key), so pluck<T> does not apply.
    // A non-null object check makes the Promise<GroupSessionCap> contract honest: a 204 body or a null
    // would silently return a typed lie without this guard.
    if (!body || typeof body !== "object") {
      throw new ConsoleApiError(200, "could not set group session policy: malformed response", "server");
    }
    return body as GroupSessionCap;
  }

  async listAPITokens(): Promise<APIToken[]> {
    return this.getList<APIToken>("/api-tokens", "api_tokens", "list api tokens");
  }

  async createAPIToken(input: CreateAPITokenInput): Promise<CreatedAPIToken> {
    const req: Record<string, unknown> = { name: input.name, capabilities: input.capabilities };
    if (input.expiresInDays !== undefined) req.expires_in_days = input.expiresInDays;
    const body = await this.request("/api-tokens", "create api token", { method: "POST", body: req });
    const apiToken = this.pluck<APIToken>(body, "api_token", "create api token");
    const env = body as Record<string, unknown>;
    if (typeof env.token !== "string") {
      throw new ConsoleApiError(200, 'could not create api token: malformed response (no "token")', "server");
    }
    return { token: env.token, apiToken };
  }

  async revokeAPIToken(id: string): Promise<void> {
    await this.request(`/api-tokens/${encodeURIComponent(id)}`, "revoke api token", { method: "DELETE" });
  }

  async listEnrollmentTokens(): Promise<EnrollmentToken[]> {
    return this.getList<EnrollmentToken>("/enrollment-tokens", "enrollment_tokens", "list enrollment tokens");
  }

  async createEnrollmentToken(input: CreateEnrollmentTokenInput): Promise<CreatedEnrollmentToken> {
    const req: Record<string, unknown> = { group_id: input.groupId };
    if (input.ttlSeconds !== undefined) req.ttl_seconds = input.ttlSeconds;
    if (input.maxUses !== undefined) req.max_uses = input.maxUses;
    const body = await this.request("/enrollment-tokens", "create enrollment token", { method: "POST", body: req });
    const enrollmentToken = this.pluck<EnrollmentToken>(body, "enrollment_token", "create enrollment token");
    const env = body as Record<string, unknown>;
    if (typeof env.token !== "string") {
      throw new ConsoleApiError(200, 'could not create enrollment token: malformed response (no "token")', "server");
    }
    return { token: env.token, enrollmentToken };
  }

  async revokeEnrollmentToken(id: string): Promise<void> {
    await this.request(
      `/enrollment-tokens/${encodeURIComponent(id)}/revoke`,
      "revoke enrollment token",
      { method: "POST" },
    );
  }

  async listWebhooks(): Promise<TenantWebhook[]> {
    return this.getList<TenantWebhook>("/tenant/webhooks", "webhooks", "list webhooks");
  }

  async createWebhook(input: CreateWebhookInput): Promise<CreatedTenantWebhook> {
    const body = await this.request("/tenant/webhooks", "create webhook", {
      method: "POST",
      body: { url: input.url, events: input.events ?? [] },
    });
    const wh = this.pluck<Record<string, unknown>>(body, "webhook", "create webhook");
    if (typeof wh.secret !== "string") {
      throw new ConsoleApiError(200, 'could not create webhook: malformed response (no "secret")', "server");
    }
    return wh as unknown as CreatedTenantWebhook;
  }

  async deleteWebhook(id: string): Promise<void> {
    await this.request(`/tenant/webhooks/${encodeURIComponent(id)}`, "delete webhook", { method: "DELETE" });
  }

  async listWebhookDeliveries(webhookId: string): Promise<WebhookDeliveryRecord[]> {
    const body = await this.request(
      `/tenant/webhooks/${encodeURIComponent(webhookId)}/deliveries`,
      "list webhook deliveries",
      { method: "GET" },
    );
    const arr = (body as Record<string, unknown>)["deliveries"];
    if (!Array.isArray(arr)) return [];
    return arr as WebhookDeliveryRecord[];
  }

  async createAttendedSession(groupId: string, reason?: string): Promise<CreatedAttendedSession> {
    const body = await this.request("/attended-sessions", "create attended session", {
      method: "POST",
      body: { group_id: groupId, reason: reason ?? "" },
    });
    const session = this.pluck<AttendedSessionRecord>(body, "session", "create attended session");
    const env = body as Record<string, unknown>;
    if (
      typeof env.code !== "string" ||
      typeof env.join_code !== "string" ||
      typeof env.join_url !== "string"
    ) {
      throw new ConsoleApiError(
        200,
        'could not create attended session: malformed response (no "code")',
        "server",
      );
    }
    return { session, code: env.code, join_code: env.join_code, join_url: env.join_url };
  }

  async listAttendedSessions(offset = 0): Promise<{ sessions: AttendedSessionRecord[]; has_more: boolean }> {
    const body = await this.request(`/attended-sessions?limit=50&offset=${offset}`, "list attended sessions", { method: "GET" });
    const sessions = this.pluck<AttendedSessionRecord[]>(body, "sessions", "list attended sessions");
    const more = (body as Record<string, unknown>).has_more;
    if (!Array.isArray(sessions) || typeof more !== "boolean") {
      throw new ConsoleApiError(200, "could not list attended sessions: malformed response", "server");
    }
    return { sessions, has_more: more };
  }

  async getAttendedSession(id: string): Promise<AttendedSessionRecord> {
    const body = await this.request(
      `/attended-sessions/${encodeURIComponent(id)}`,
      "get attended session",
      { method: "GET" },
    );
    return this.pluck<AttendedSessionRecord>(body, "session", "get attended session");
  }

  async connectAttendedSession(id: string): Promise<ConnectedAttendedSession> {
    const body = await this.request(
      `/attended-sessions/${encodeURIComponent(id)}/connect`,
      "connect attended session",
      { method: "POST" },
    );
    const session = this.pluck<AttendedSessionRecord>(body, "session", "connect attended session");
    const signaling = this.pluck<SessionSignaling>(body, "signaling", "connect attended session");
    // Same shape and the same reason as startBrokeredSession: this is the ONLY place the attended
    // connect response is decoded, so a field not read here does not exist for the rest of the app.
    // A malformed policy is an error rather than a silent drop — dropping it would run the session
    // unrestricted while the console believed a mandate was in force.
    const policy = parseSessionAccessPolicy(body, "connect attended session");
    return policy ? { session, signaling, session_policy: policy } : { session, signaling };
  }

  async promoteAttendedSession(id: string): Promise<void> {
    await this.request(
      `/attended-sessions/${encodeURIComponent(id)}/promote`,
      "promote attended session",
      { method: "POST" },
    );
  }

  async endAttendedSession(id: string): Promise<AttendedSessionRecord> {
    const body = await this.request(
      `/attended-sessions/${encodeURIComponent(id)}/end`,
      "end attended session",
      { method: "POST" },
    );
    return this.pluck<AttendedSessionRecord>(body, "session", "end attended session");
  }

  async ingestAudit(body: AuditIngestBody, opts: { keepalive?: boolean } = {}): Promise<AuditIngestResult> {
    const res = await this.request("/audit/ingest", "forward audit events", {
      method: "POST",
      body,
      // The teardown batch (see AuditForwarder.flush): completes even if the page is unloading.
      keepalive: opts.keepalive,
    });
    const env = (res ?? {}) as Record<string, unknown>;
    return {
      accepted: typeof env.accepted === "number" ? env.accepted : 0,
      tail_seq: typeof env.tail_seq === "number" ? env.tail_seq : 0,
      tail_hash: typeof env.tail_hash === "string" ? env.tail_hash : "",
    };
  }

  // -- internals ------------------------------------------------------------

  /**
   * Issue one request and parse its JSON body. The control plane enforces CSRF double-submit on all
   * cookie-authenticated mutations (csrf.go): this method reads `rmt_csrf` and echoes it as
   * `X-CSRF-Token`; a missing or wrong token is rejected 403.
   */
  private async request(
    path: string,
    action: string,
    opts: { method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; body?: unknown; keepalive?: boolean; signal?: AbortSignal; public?: boolean },
  ): Promise<unknown> {
    const headers: Record<string, string> = {};
    const init: RequestInit = { method: opts.method, credentials: "include" };
    if (opts.keepalive) init.keepalive = true;
    if (opts.signal) init.signal = opts.signal;
    if (opts.body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    if (opts.method !== "GET" && !opts.public) {
      const cookie = csrfTokenFrom(this.cookies());
      // Once the cookie changes, it owns later rotations (password/email changes and logout).
      if (this.adoptedCsrf && cookie !== this.adoptedCsrf.cookieBefore) this.adoptedCsrf = null;
      const token = this.adoptedCsrf?.token ?? cookie;
      if (token) headers[CSRF_HEADER_NAME] = token;
    }
    if (Object.keys(headers).length > 0) init.headers = headers;

    const res = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    if (!res.ok) throw await this.toError(res, action);
    if (res.status === 204) return null; // No Content — no body to parse
    try {
      return (await res.json()) as unknown;
    } catch {
      throw new ConsoleApiError(res.status, `could not ${action}: malformed response body`, "server");
    }
  }

  /** GET an envelope and return its array under `key`, or a typed malformed-body failure. */
  private async getList<T>(path: string, key: string, action: string): Promise<T[]> {
    const body = await this.request(path, action, { method: "GET" });
    const rows = (body as Record<string, unknown> | null)?.[key];
    if (!Array.isArray(rows)) {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (no "${key}")`, "server");
    }
    return rows as T[];
  }

  /** Return the object under `key` in an envelope, or a typed malformed-body failure. */
  private pluck<T>(body: unknown, key: string, action: string): T {
    const value = (body as Record<string, unknown> | null)?.[key];
    if (value === null || typeof value !== "object") {
      throw new ConsoleApiError(200, `could not ${action}: malformed response (no "${key}")`, "server");
    }
    return value as T;
  }

  /** Build a {@link ConsoleApiError} from a non-2xx response, preferring the body's `error` field. */
  private async toError(res: Response, action: string): Promise<ConsoleApiError> {
    let detail = "";
    let code: string | undefined;
    let field = "";
    let parsed: Record<string, unknown> | undefined;
    try {
      const body = (await res.json()) as { error?: unknown; code?: unknown; field?: unknown };
      if (typeof body.error === "string") detail = body.error;
      if (typeof body.code === "string") code = body.code;
      if (typeof body.field === "string") field = body.field;
      if (body && typeof body === "object" && !Array.isArray(body)) parsed = body as Record<string, unknown>;
    } catch {
      /* non-JSON body — fall back to the status text */
    }
    const suffix = detail || res.statusText || `HTTP ${res.status}`;
    return new ConsoleApiError(res.status, `could not ${action}: ${suffix}`, errorKindFor(res.status), code ?? detail, parsed, field);
  }
}
