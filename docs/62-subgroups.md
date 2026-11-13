# docs/62 — Nested machine subgroups with downward-inherited access (design)

The design extends flat machine groups with
**nested groups, access inherited downward** (a scope on a parent covers every descendant), a child can
never widen access, moves re-evaluate scope, depth cap ~4. Mapped by four read-only surveys (schema/RLS,
Go authz, console UI, docs) before designing; the touch-point table there is reproduced in §8.

## 1. What the maps established

- `machine_group (id, tenant_id, parent_id, name, created_at)` already has `parent_id` (0001:95) — a
  PLAIN single-column FK, `ON DELETE SET NULL`, written by nothing. A plain FK bypasses RLS on write, so
  as it stands a parent could be another tenant's group.
- Scope is `membership.scoped_group_ids uuid[]` (`'{}'` = tenant-wide); elements are unvalidated, and a
  dangling id is a deliberate safe deny.
- **Group access is decided in Go, not in RLS.** Every RLS policy is tenant-only; no SQL function or
  policy knows a user or a scope. The one decision point is `GroupScope.Covers` (rbac.go), reached via
  `Grant.AllowsInGroup` / `RequireMachine`; grants are built in exactly one reader, `GrantFor` (pg) and
  its fake twin (docs/56 §4 made that a rule). So "enforced like today's group checks" means: the tree's
  STRUCTURE is enforced in the database; the ACCESS decision stays in `GrantFor` + `Covers`. A user-aware
  RLS policy would be new machinery (a per-request scope GUC, policies on machine/attended/session
  tables) and is explicitly out of scope — the same enforcement point as every group check today.
- One reader bypasses `Covers`: the pg attended-session list pushes `scope.groups` into SQL.
- Session policy (`group_session_policy`) is one row per group, read by exact group at six call sites;
  seat caps count the admission-time `session_record.group_id` snapshot by exact group.
- Group CRUD and group policy are gated tenant-wide by `Require(CapManageGroups)` (a deliberate tenant-wide authorization boundary).

## 2. Decisions

**D1 — Hierarchy = `parent_id` + a recursive closure function** (not a materialized path or closure
table): groups per tenant are few and depth ≤ 4, so a recursive walk is cheap, and moves are a single
UPDATE with nothing to rewrite (a path/closure table makes every move a fragile subtree rewrite).

**D2 — Structure is enforced in the database** (migration 0065):
- `parent_id` becomes a composite FK `(tenant_id, parent_id) → machine_group (tenant_id, id)`
  `ON DELETE RESTRICT` (no cross-tenant parent; deleting a parent with children is refused — never
  silently re-rooted, which would change who can see the subtree).
- `CHECK (parent_id IS DISTINCT FROM id)`; index on `(tenant_id, parent_id)`.
- A `BEFORE INSERT OR UPDATE OF parent_id` trigger that (a) takes a per-tenant transaction advisory lock
  (two concurrent reparents cannot each pass the cycle check in isolation and together form a cycle),
  (b) walks up from the new parent and refuses if it reaches the row itself (cycle), (c) refuses if
  `depth(new parent) + 1 + height(moved subtree) > 4` (depth cap: a root is level 1, max level 4).
  Error codes are distinct SQLSTATEs the Go side maps to 409 with a reason ("would create a cycle",
  "subgroups nest at most 4 levels").
- Before adding the constraint the migration asserts no existing row has a non-null `parent_id`
  (nothing writes it; if any does, the migration fails loudly instead of guessing).
- `cp_group_subtree(p_tenant uuid, p_roots uuid[]) RETURNS uuid[]` — STABLE, `SET search_path`,
  tenant-pinned, returns the roots plus every descendant (recursive CTE, depth-bounded). Dangling roots
  return nothing for themselves (still a safe deny). `cp_group_ancestors(p_tenant, p_group)` for policy.

**D3 — Scope inheritance is resolved once, at grant load.** `GroupScope` gains a second set:
`assigned` (what is stored — the ids an admin chose) and `covered` (assigned + all descendants).
- `GrantFor` / `StoredGrantFor` select `cp_group_subtree(m.tenant_id, m.scoped_group_ids)` beside
  `scoped_group_ids`; the fake computes the same from its group store (one shared pure helper,
  `subtreeOf(parentOf map, roots)`, used by the fake and by unit tests).
- `Covers`, `Includes`, `ScopeFor`, the attended list use `covered`. `GroupIDs()` and
  `AssignmentScope()` (persistence: "preserve the scope on a role edit") and `sameScope` (homogeneity)
  keep using `assigned` — the stored array is never rewritten, so a reparent never leaves a stale
  expansion behind and never empties an array (empty = tenant-wide = a silent widen).
- Because `covered` is downward-closed, every existing comparison becomes ancestor-aware for free:
  an actor scoped to P `Includes` a target scoped to child C; one scoped to C never includes P or a
  sibling; assigning {C} is within an actor scoped to {P}; assigning {P} is not within one scoped to {C}.
- Freshness: grants are re-read per request (and per lease renewal, ~10 s), so a move takes effect on
  the next request. Unattended sessions whose scope a move removed end at their next renewal (≤ ~32 s,
  the existing docs/56 stance); attended sessions are unaffected, as today.

**D4 — Session policy is the STRICTEST merge along the ancestor chain** (a child can tighten, never
loosen). One resolver, `EffectivePolicy(tenant, group)`, replaces the exact-group read at all six call
sites. Merge: `view_only`, `prohibit_recording`, `require_recording` OR; durations = minimum non-zero;
`allow_backstage_under_view_only` (an opt-OUT of a restriction) is AND (true only if every level that
sets view-only also allows it — never widened by a child); seat cap = the minimum, and **each ancestor's
cap counts the admitted sessions of its whole subtree** (the snapshot group of every live session,
mapped to its ancestors at admission time; both stores). A policy editor shows the inherited effective
values next to the group's own row so an admin sees why a child is stricter than its own settings.

**D5 — Who may build the tree.** Creating, renaming and deleting groups keep `Require(CapManageGroups)`.
NEW for structure changes, because a reparent moves every machine in the subtree into someone else's
scope: create-under-P requires the actor's `CapManageGroups` scope to cover P; a reparent of G under P
requires it to cover G AND P (and the old parent); making G a root requires a tenant-wide grant. A
tenant-wide holder is unaffected. Each create/reparent writes a management audit event
(`group_created` with parent, `group_reparented` with old and new parent).

**D6 — Visibility.** A technician sees the groups their scope covers. A child-scoped technician does NOT
see the ancestors (no access, and no name leak); the console builds paths from the groups it can see,
so their subtree root renders as a top-level group. API tokens are tenant-wide and see the full tree.

**D7 — Deleting a group with subgroups is refused (409),** like deleting a group with machines. No
auto-move.

**D8 — Not changed:** dynamic groups (a separate property-filter concept; the UI never calls them
subgroups); enrollment (a token for P enrolls into P only); `session_record.group_id` /
`session_transfer.group_id` stay admission-time snapshots (documented, not followed through moves);
names stay non-unique (path labels disambiguate).

## 2a. Binding authorization contracts — these supersede §2 where they differ

- **R1 Assignment authorization ≠ effective containment.** A dangling id expands to nothing, so comparing
  only covered sets would let any scoped actor "include" `{missing-id}` — and a later group with that id
  would activate it. Rules: (a) a NEWLY submitted scope must name existing groups of this tenant (resolved
  through the same tenant-pinned resolver; dangling/cross-tenant → 400); (b) escalation checks compare the
  TARGET's ASSIGNED ids against the ACTOR's COVERED set (`Includes(other)` = `other.assigned ⊆ s.covered`;
  assigned ids exist, and covered is downward-closed, so this covers their subtrees); (c) a preserved
  dangling id on an unrelated edit stays (safe deny) and is not something a scoped actor "includes", so only a
  tenant-wide actor can administer such a user; (d) `All` is never derived from an empty covered set — a
  scope whose roots all dangle is scoped and covers nothing.
- **R2 Authorize against the CURRENT tree.** Hierarchy mutations (create-under, reparent, delete) run in one
  transaction: take the tenant tree lock (`pg_advisory_xact_lock` on a tenant-derived key) → read the current
  ancestry → reload the actor's memberships IN that transaction → authorize → mutate. Assignment edits and
  machine moves, whose authorization depends on the tree, capture the tenant's `group_tree_version` (bumped by
  every hierarchy mutation, read with the grant) and their write is conditional on it being unchanged
  (else 409 "groups changed, retry"). The fake does the same under its single mutex.
- **R3 Scoped group managers.** `Require(CapManageGroups)` only tests capability presence; a scoped holder
  can today rename/delete any group. Now: rename, delete and policy edits require `AllowsInGroup(
  CapManageGroups, the group)`; creating a ROOT group or moving a group to root requires
  `ScopeFor(CapManageGroups).All`; create-under-P requires covering P; reparent requires covering G, the old
  parent and the new parent. Machine moves keep requiring `CapManageMachines` over BOTH source and destination
  (so creating an accessible child is not an acquisition path). The public API routes apply the same rules
  (API tokens are tenant-wide).
- **R4 Unsatisfiable policy denies.** Strictest-merge can yield `require_recording && prohibit_recording`.
  `EffectivePolicy` reports it as `Conflict` and admission/grant minting DENY with that reason; policy edits
  and reparents that would create a conflict for any descendant are refused (409) where detectable, and the
  runtime denial stays as the fail-closed backstop. `allow_backstage_under_view_only` is effective-true only
  when NO ancestor-or-self that enforces view-only has it false; dormant values on non-view-only rows never
  become restrictions.
- **R5 Trigger completeness.** `id` and `tenant_id` of `machine_group` are immutable (a BEFORE UPDATE guard
  raises). The structure trigger is VOLATILE, SECURITY INVOKER, schema-qualified, `SET search_path =
  pg_catalog, public`; it takes the same tenant tree lock FIRST, then reads (under READ COMMITTED each
  statement in the function takes a fresh snapshot, so it sees the committed result of the transaction that
  held the lock before it). It runs in the caller's tenant context (RLS shows exactly that tenant's rows,
  which are the only legal ancestors). Tested: concurrent opposing moves (A under B ‖ B under A), insertion
  under a concurrently moved subtree.
- **R6 Atomic migration.** In one transaction: `LOCK TABLE machine_group IN SHARE ROW EXCLUSIVE MODE`, assert
  no non-null `parent_id`, drop the old SET NULL FK, add the composite FK as `NO ACTION` (checked at statement
  end — so a tenant-delete CASCADE that removes parent and children together succeeds, while deleting a lone
  parent with children fails), the CHECK, the index, the guard and structure triggers. Tested: tenant
  deletion with a tree; direct parent deletion refused.
- **R7 Seat caps.** Displayed effective cap = minimum POSITIVE value (0 = unlimited). Enforcement: EVERY
  ancestor-or-self with a cap is checked against ITS OWN subtree's live count (current ancestry), inside the
  existing per-tenant admission lock so sibling admissions cannot oversubscribe a shared ancestor. A move that
  puts a subtree over a cap does not end live sessions; new admissions are refused until under cap.
- **R8 Fake parity.** The fake recomputes covered sets on EVERY effective and stored grant read from a
  tenant-filtered snapshot of its group store, into freshly allocated maps (never cached, never shared with
  the persisted assignment). Lock order: group store before auth store, everywhere.
- **R9 Visibility of parent ids.** A group's `parent_id` is returned only when the parent is itself visible to
  the caller; otherwise `null`. Construction/mutation paths audited for the new semantics: grant building
  (pg + fake, effective + stored), `Groups(...)` call sites for submitted scopes, scope serialization,
  assignment handlers, machine move (single + bulk), enrollment-token create, attended list, transfer
  candidates, public API adapters, and every direct `.groups` access. The users effective-scope CTE remains
  an ASSIGNED-scope display summary and is never used for authorization.
- **StoredGrantFor expands too** (admin containment needs current coverage) while keeping assigned ids and
  expired memberships as administrative data; it never authorizes the actor.

## 3. API

- `MachineGroup` gains `parent_id` (nullable). `POST /machine-groups` accepts optional `parent_id`.
- `POST /machine-groups/{id}/move` `{ "parent_id": uuid|null }` → 200 | 403 | 404 | 409 (cycle / depth /
  cross-tenant parent).
- Public API v1: `parent_id` added to the group object and accepted on create; additive only
  (pinned envelope keys unchanged); move exposed as the same verb.

## 4. Console

- One shared `groupTree` helper: depth-first order, indent level, path label ("Acme › Site A › Lab"),
  built only from visible groups; used by every picker (machine move, enrollment, attended, users scope,
  policies) so name collisions never merge.
- Groups panel: indented tree, "New subgroup" on a row, a "Move…" action with a parent picker that
  excludes the group's own subtree, a text filter that keeps the ancestors of matches.
- Users panel scope labels say "Site A (and subgroups)".

## 5. Tests (fake and pg must agree — run the same suite against both)

- Asymmetric scope cases: scope {P} covers C and grandchild; scope {C} does not cover P or sibling S;
  scope {S} covers neither; a dangling id covers nothing; tenant-wide covers all.
- `Includes` / escalation: an actor on {P} may assign {C}; an actor on {C} may not assign {P} or {S}.
- Structure: cycle refused (incl. two concurrent reparents — pg only, two connections), depth 5
  refused (both for create and for a move that brings a tall subtree under a deep parent), cross-tenant
  parent refused by the FK, delete-with-children 409, create-under-P / move authorization (D5).
- Policy merge: parent require_recording + child none ⇒ required; child cannot clear parent view-only;
  backstage opt-out cannot be widened by a child; seat cap on P counts sessions in C.
- Attended list (pg path that bypassed `Covers`): a P-scoped user lists C's sessions; a C-scoped user
  does not list P's.
- Every new guard mutation-checked (turn the trigger's cycle walk off → the cycle test fails, etc.).
- Viewer: tree helper unit tests (order, path, hidden ancestors, filter keeps ancestors); e2e for
  create-subgroup, move, and the scope label.

## 6. Stages (one deploy at the end — the policy merge must ship with the inheritance)

- **A** migration 0065 + subtree/ancestor functions + `GroupScope` covered/assigned + `GrantFor` (pg +
  fake) + attended list + tests.
- **B** `EffectivePolicy` + seat-cap subtree counting + group CRUD/move API + D5 authorization + audit
  events + public API.
- **C** console tree helper, Groups panel, pickers, scope labels, e2e.

## 7. Risks accepted

- A reparent is a scope change for everyone above it; it is gated (D5) and audited, and takes effect on
  the next request. Live unattended sessions follow within one renewal.
- The seat-cap subtree count reads the CURRENT ancestry of the snapshot group; a move between admission
  and the count can shift which ancestor a live session is charged to. Same class as today's
  snapshot-vs-live trade; acceptable at this scale.

## 8. Touch points (from the survey)

Schema `machine_group.parent_id` · `membership.scoped_group_ids` (unchanged storage) · `rbac.go`
`GroupScope`/`Covers`/`Includes`/`ScopeFor`/`AssignmentScope`/`GroupIDs`/`sameScope` · `pgstore.go`
`GrantFor`, `StoredGrantFor`, users effective-scope CTE (stays on stored ids, labelled in the UI) ·
`authstore_mem.go` grant building · `pgstore_attended.go` `List` · group store (pg + fake
`machinegroup.go`) create/move/delete · `http.go` group handlers, group list visibility · session policy
call sites (`http_session_admission.go`, `session_authz.go`, `http_elevation.go`, `http.go`,
`http_attended.go`) · seat counting (`pgstore_dataplane.go`, fake `session_record.go`) · session
transfer candidate lookup (`http_session_transfer.go`: must find holders scoped to ancestors — goes
through grants, verify) · `publicapi.go` · console: `console_api.ts`, `MachineGroupsPanel.tsx`,
`MachinesPanel.tsx`, `EnrollmentTokensPanel.tsx`, `AttendedPanel.tsx`, `UsersPanel.tsx`,
`AccessPanel.tsx`, `user_scope.ts`, `console_panels.ts`, help text.
