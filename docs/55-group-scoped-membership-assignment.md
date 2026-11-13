# docs/55 — Group-scoped membership assignment

> **STATUS: SHIPPED — backend and console group-scope UI are both shipped and deployed.** Decided:
> group scope first; docs/54 property-value scoping deferred. Design and implementation were
> independently reviewed (the review moved validation into the handler). Tests: pure
> no-escalation (mutation-proven), fake + pg-under-RLS round-trips, e2e escalation denial, preserve-on-
> absent, validation, pg preserve-across-deletion.
>
> **Phase 2 (console UI), as built:** `UserSummary` now exposes the
> effective `scoped_group_ids` (fake + pg, via a per-user CTE: any tenant-wide membership → all, else
> union); the Users panel shows a **Scope** column (names via machine-groups, "All groups" when empty)
> and the invite form has a group checkbox picker; `createUser` sends `scoped_group_ids` only when
> groups are chosen (never an explicit `[]` that could read as a deliberate widen). Editing an existing
> user's scope is left to the role `<select>`, which sends only `{role}` and so the backend PRESERVES
> the scope — no re-widen. Pure helpers (`scopeLabel`, `toggleGroup`) unit-tested; tsc + vitest + build
> green.


docs/01 §7 P1 custom-properties, role-scoping — the GROUP-scope half (property-value scope stays parked
in docs/54). Decided 2026-10-29: expose group-scoped memberships first.

## 1. Why this is small: the foundations already compose with group scope
- Enforcement exists: `RequireMachine(c, groupID)` → `AllowsInGroup` → per-membership `allows(c) &&
  Scope.Covers(groupID)`. Listing filters per-machine by `AllowsInGroup(CapViewMachines, m.GroupID)`.
- Persistence/resolution exists: `membership.scoped_group_ids`; `GrantFor` maps `{}` → AllGroups, else
  `Groups(ids…)`.
- No-escalation ALREADY composes: `canAdministerUser(actor, target)` iterates every capability and
  requires `actorScope.Includes(targetScope)` (via `ScopeFor`/`Includes`). A tenant-wide actor Includes
  any scope; a group-scoped actor Includes only subsets of its own groups; a group scope never Includes
  AllGroups. So assigning a scope the actor doesn't fully cover is ALREADY denied.
- Group REASSIGNMENT is already two-way: `handleSetMachineGroup` requires CapManageMachines on BOTH the
  source and destination group — a scoped operator cannot grab/dump a machine across a group
  boundary. (So the docs/54 R1 group-transition hole is already closed.)

**The ONLY gap:** the operator-facing assignment path. `SetUserRole`/`CreateUser` ALWAYS write
`scoped_group_ids = '{}'` (tenant-wide). Nobody can create a group-scoped membership.

## 2. The change
- Request bodies gain optional `scoped_group_ids: []string` (absent/empty = tenant-wide = today). On
  `POST /users/{id}/role` and `POST /users`.
- Store signatures become explicit (fail-closed; a caller must state the scope):
  `SetUserRole(ctx, tenant, userID, role, scopedGroupIDs []string)` and
  `CreateUser(ctx, …, role, scopedGroupIDs []string)`. nil/empty → `'{}'` (tenant-wide), else write the
  ids into `scoped_group_ids`. Fake + pg kept in lockstep (fake-and-pg-must-agree).
- VALIDATION before the write: every id must be a real machine group in the tenant (reuse
  `ListMachineGroups`, like `handleSetMachineGroup`), else 404 "unknown machine group". This stops a
  typo minting a membership scoped to a nonexistent group AND stops a composite-FK 500.
- NO-ESCALATION: build `newGrant` with `NewMembership(role, Groups(scopedGroupIDs…))` (empty → AllGroups)
  and keep BOTH existing guards: `canAdministerUser(actor, targetCurrent)` AND
  `canAdministerUser(actor, newGrant)`. The second now carries the scope, so the existing
  `Includes` logic enforces "cannot assign broader than you hold" for FREE — a scoped admin assigning
  tenant-wide (empty ids) is denied because its scope does not Include AllGroups.
- AUDIT: `user.role_set` / `user.created` metadata gains `scoped_group_ids` (the assigned scope).

## 3. Decisions / non-goals (stated so the review can push back)
- **Session revocation on scope change: NOT in this increment, matching the EXISTING role-change
  behaviour.** Authorization is re-resolved from the DB per request (`GrantFor`), so a narrowed user's
  CONSOLE access shrinks on their next request immediately. A live remote-control SESSION rides a signed
  ticket and would continue until it ends — but this is a PRE-EXISTING property of role DOWNGRADES too
  (HandleSetUserRole does not revoke sessions today). Comprehensive "revoke live sessions + issued
  elevation/transfer tickets on any authority reduction" is a separate, cross-cutting improvement that
  should cover role changes AND scope changes together; scoping it into this feature would be
  inconsistent and larger than the feature. Flagged and documented as a known limitation.
- **The request's `scoped_group_ids` is AUTHORITATIVE (absent = tenant-wide).** Because SetUserRole
  REPLACES the membership, a console that omits the field re-widens a previously-scoped user to
  tenant-wide. That is explicit in the API (the admin chose it), not silent — but the console (phase 2)
  MUST send the intended scope. Noted so the UI is built to pre-fill the current scope.
- **Phase 1 = backend (API + store + enforcement + tests). Phase 2 = console UI** (group picker on the
  role/invite forms, pre-filled with current scope). The backend is the security-critical core and is
  independently useful (automation / the public API can assign scope).

## 4. Tests (pg-under-RLS + fake parity + mutation)
- Fake/pg parity: `SetUserRole`/`CreateUser` with group ids writes `scoped_group_ids`; `GrantFor` reads
  it back as a group-scoped membership (round-trip, under RLS on pg).
- No-escalation (the crux): a group-A-scoped admin CAN assign {A}; CANNOT assign {A,B}, {B}, or tenant-wide
  (empty) — 403 each; a tenant-wide admin can assign any valid scope. ASYMMETRIC cases (assign {A} vs {B})
  to catch swapped wiring. Mutation: drop guard #2 → the escalation cases must go green→red.
- Validation: an unknown group id → 404; a mix of known+unknown → 404 (atomic, nothing written).
- Enforcement end-to-end: a user scoped to group-A sees only group-A machines in GET /machines and is
  refused RequireMachine ops on a group-B machine (already covered by existing scope tests; add one that
  the ASSIGNED scope actually takes effect through the real assignment path).
- NEGATIVE control: an assignment with empty scoped_group_ids behaves exactly as today (tenant-wide) — no
  behaviour change when the feature is unused.

## 5. Open questions for the design review
1. Is wiring scope through SetUserRole/CreateUser + the existing canAdministerUser(actor,newGrant) a
   COMPLETE no-escalation story, or is there an assignment path that bypasses it (OIDC JIT provisioning,
   bootstrap, platform admin, API-token principals)?
2. Is deferring session/ticket revocation on scope-narrowing acceptable for this increment given role
   downgrades already behave that way, or must scope-narrowing revoke now?
3. Any validation gap (duplicate ids, group deleted between validate and write, RLS on the group lookup)?

---
## 6. Design-review repairs (review verdict: guards sound; these land before/with the code)

**R1 (high) — absent scope must NOT widen.** The original "absent = tenant-wide" was the bug. Fix:
- `SetUserRole` request `scoped_group_ids` is OPTIONAL (`*[]string`): **absent → PRESERVE the target's
  CURRENT scope** (read from targetGrant); **present empty `[]` → tenant-wide (explicit, deliberate)**;
  present non-empty → that scope. So an old console that never sends the field re-roles a user WITHOUT
  changing their scope — no silent widening. `CreateUser` keeps its tenant-wide default (a new user has
  no scope to preserve).
- "Current scope" = from the target's existing memberships: if ANY is AllGroups → preserve tenant-wide;
  else the UNION of their group ids. Add `GroupScope.GroupIDs() []string` (nil when All) + a grant helper.

**R2 (medium) — never silently '{}'; integrity.** `scoped_group_ids` is `uuid[]` (migration 0001).
- Write EXACTLY the requested/preserved ids; an empty result is tenant-wide ONLY when explicitly asked,
  never as a side effect.
- Group DELETION is safe as-is: a group is deletable only when EMPTY (409 otherwise + machine.group_id FK),
  and the uuid[] has no cascade — so a deleted group leaves a DANGLING id that `Covers` finds no machine
  for (deny), and the array is NOT rewritten to '{}'. No trigger that strips ids (that could empty→widen).
- Validation (UX + typo safety, not the security boundary): reject non-uuid ids (400); DEDUPE; validate
  every id is a known group in the tenant via ListMachineGroups (unknown → 404). A concurrent deletion
  between validate and write is harmless (dangling id = deny), so no hard TOCTOU guarantee is needed —
  the security rests on never-auto-empty, which holds.

**R3 — scope only narrows MACHINE-scoped caps.** Tenant-level endpoints gated on `Require(cap)` (ManageUsers,
ViewAudit tenant-wide, ManageTenant, …) stay tenant-wide even for a scoped membership — group scope narrows
only the machine-group-scoped checks (`RequireMachine`/`AllowsInGroup`). Document this boundary; it is
correct (a group-scoped technician still can't, e.g., manage tenant billing). Tests assert a group-scoped
membership does NOT lose tenant-wide caps it legitimately holds, and DOES narrow machine ops.

**R4 — writer inventory + bootstrap.** Confirmed writers: CreateUser (invite handler + bootstrap owner),
SetUserRole. OIDC does not write memberships (no CreateUser/INSERT; binds existing users). API tokens
cannot reach these (apiTokenGrantableCaps excludes CapManageRoles/CapManageUsers). Bootstrap mints the
first OWNER with no actor — the intentional trusted exception (tenant-wide). A test asserts no other
membership INSERT exists (grep-style source test) so a future writer can't skip the guard silently.

**Added tests (from the review):** mixed-capability + multiple-membership grants; guard#1 current-target
denial (actor cannot edit a user whose current authority exceeds theirs); preserve-on-absent (role change
keeps scope); explicit-empty widens only for an authorized actor; dangling-id-is-deny-not-tenant-wide;
dedupe + non-uuid rejection; tenant-wide-cap-retained-under-scope.
