# docs/59 — Public API v1: write operations + real body schemas

Status: shipped (implemented and deployed).

docs/01 §10 "Public HTTP API" (P1), remaining gap: "request/response body SCHEMAS in the spec…; write
operations". Design-first because API tokens performing writes is authorization-bearing surface.
Grounded in a four-mapper read of `publicapi.go`, `apitoken*.go`, the console write handlers, and
`publicapi_test.go` (2026-10-30).

## 1. Scope

Add to `/api/v1` (token-authenticated, Bearer `rmt_api_…`):

| Route | Aliases console handler | Cap | Success |
|---|---|---|---|
| POST `/machine-groups` | `handleCreateMachineGroup` | manage_groups | 201 `{"machine_group":…}` |
| PATCH `/machine-groups/{id}` | `handleRenameMachineGroup` | manage_groups | 200 `{"machine_group":…}` |
| POST `/machine-groups/{id}/move` | `handleMoveMachineGroup` (docs/62) | manage_groups | 200 `{"machine_group":…}` (409 cycle / depth / unknown parent / changed tree) |
| DELETE `/machine-groups/{id}` | `handleDeleteMachineGroup` | manage_groups | 200 (409 while in use: machines, subgroups or enrollment tokens) |
| POST `/machines/{id}/group` | `handleSetMachineGroup` | manage_machines | 200 `{"machine":…}` |
| POST `/machines/bulk-group` | `handleBulkSetMachineGroup` | manage_machines | 200 `{"results":[…]}` **partial success** |
| PUT `/machines/{id}/properties/{key}` | property set handler | manage_machines | 200 `{"property":…}` |
| DELETE `/machines/{id}/properties/{key}` | property delete handler | manage_machines | 200 `{"deleted":true,"key":…}` |

**Stays excluded (by design, restated, not weakened):** interactive-session creation, user management,
anything calling `FindUserByID(p.UserID)` or writing `p.UserID` into an FK — token principals are not
app_users (apitoken.go:40-62). `apiTokenGrantableCaps` is **not widened** (apitoken_test.go:159 pins it);
both needed caps (manage_machines, manage_groups) are already grantable. CapManageTenant stays excluded
(no token self-propagation).

## 2. Mechanism: alias, never re-implement

The existing `publicAPIRoutes()` table drives BOTH mux registration and the OpenAPI document, so spec
and surface cannot drift. Write rows point at the SAME `*Server` console handlers, inheriting:
- group create/rename/delete: tenant-wide `Require(CapManageGroups)`, name validation, 404/409 semantics;
- move-machine: **two-way** `RequireMachine(CapManageMachines, …)` on the CURRENT group then the TARGET
  group (http.go ~1815/1828) — never trusted from the body;
- bulk-group: blanket target precondition once, per-machine current-group checks, cap 200, per-machine
  `{machine_id, ok, error}` results;
- property set/delete: machine resolved by PK, gated on its REAL group; key ≤128 bytes, value ≤4096;
- audit: every mutation records its mgmt-audit action with `ActorUserID = p.UserID` (for a token, the
  token id — an opaque actor; safe, already how token reads audit). Audit-write failure stays a 500
  AFTER the committed mutation (house behavior), which makes **POST group create non-idempotent on
  retry** (names are not unique) — documented in the spec, not papered over.

Bearer requests are CSRF-exempt (csrf.go); no bypass keyed on path prefix is added.

## 3. Route-table + spec-builder changes

`publicAPIRoute` gains: `SuccessStatus int`, `RequestSchema map[string]any` (nil for GET/DELETE-no-body),
`ResponseSchemas map[int]map[string]any` (real shapes for 200/201 plus the route's documented 400/404/409),
replacing the hard-coded generic 200. `buildOpenAPIDocument`:
- parse ALL `{name}` placeholders for path parameters (today one hard-coded `id`; `{key}` must be
  documented or the spec is invalid);
- emit `requestBody` when `RequestSchema` is set;
- keep envelope keys EXACT (`machine_group`, `machine`, `results`, `property`, `deleted`) — the console
  depends on them and v1 additivity forbids reshaping;
- document bulk partial success explicitly: HTTP 200 even when some machines failed; duplicate ids are
  processed twice (second is a no-op); per-item `"could not record audit"` can appear after a committed move;
- update `info.description` + the file-header and `Method` field comments: no longer "read-only"; the
  human-only exclusions stay stated. The spec stays public/unauthenticated (Cache-Control max-age=300),
  so schemas carry structure only, never tenant data.
- do NOT rename/refactor `handlePublicAPISpec`'s encode line — nostore_test.go:108 pins its source text.

Body-size tiers: add `/api/v1/machines/bulk-group` to the exact-path bulk tier (bufferTenantBody), so the
alias gets the same 1 MiB bound as the console route.

## 4. Tests (the contract is the point)

- **Replace, don't delete, the read-only invariant** (publicapi_test.go:19): new rule asserted over the
  table — GET routes carry view caps; non-GET routes carry a cap that `IsAPITokenGrantableCapability`
  AND is in {manage_machines, manage_groups}. The "public surface cannot outgrow what a token may hold"
  guard survives the transition.
- Mounted/enforced tests get per-route fixtures: sample bodies, `{id}`→seeded id, `{key}`→seeded key,
  expected statuses (201 create; 400 nil body on body-carrying routes — still distinguished from the
  ServeMux plain-text 404). The capability-enforcement positive case for move-machine seeds real
  machines+groups in a strict store (the permissive dev store resolves any id).
- **New spec test:** every operation has non-generic schemas (no bare `{"type":"object"}`), every
  declared path param appears in the path, and requestBody exists exactly on body-carrying routes.
- **Mixed-credential pin:** a request with BOTH a session cookie and a Bearer token on a mutating
  /api/v1 route — assert current behavior explicitly (csrf keys on the cookie; the authenticator reads
  the header first) so the two can never silently disagree; if they CAN disagree today, refuse that
  combination at the public-API layer instead.
- PG/RLS: one test driving a write route end-to-end as a token principal under Postgres (audit row
  recorded with the token id; cross-tenant id → 404).

## 5. Residual risks, stated (not solved here)

- **Tokens are tenant-wide** (`AllGroups`, apitoken_auth.go:48): a manage_machines token can move ANY
  machine in its tenant. Group-scoped tokens need a schema + mint-API change — out of scope; the spec
  text says the token's caps apply tenant-wide.
- **No per-time rate limit on token writes** (bulk is capped per-request at 200 only). A leaked
  manage_* token now has write blast radius. Follow-up candidate: a limiter keyed on token id
  (identity-scoped, per the "rate limiter as the off switch" lesson) — not added silently here.
- Tokens ignore user disable/expiry/windows by design (docs/56); revocation + expires_at remain the
  controls. Write ops raise what that means — worth one line in the console's token UI later.
- Audit actor-kind: a token's mgmt-audit rows show an actor id that matches no app_user. If an
  "actor_kind" marker is wanted, it goes in NEW metadata keys only — the canonical hash preimage
  (mgmtaudit_canonical.go) must not change.

## 5a. Design-review repairs (independent review: no escalation found; test plan strengthened)

- **R1 — pin the operation set, not capability labels.** The grantable-cap rule bounds labels; it would
  not catch an excluded route (machine status/note) added under manage_machines, nor a wrong handler
  bound to a row (registration does not enforce the table's Capability — the handler does). Repair: a
  test pins the EXACT (method, path, operationId, capability) tuple set — 6 reads + 7 writes, no
  additions, omissions or duplicates — and enforcement is proven behaviorally through the mounted
  routes, never inferred from table metadata. Account for ServeMux's implicit HEAD on GET routes.
- **R2 — behavioral write tests, per route.** A 400-on-missing-body probe can pass with the wrong
  handler bound or no mutation performed. Repair: for EACH write, a valid token request through the
  real auth chain → exact success status/envelope → independent read-back of the persisted mutation →
  the audit row's action + token actor id; a token LACKING the one capability is denied AND state is
  proven unchanged; bulk verifies per-item outcomes against persisted state.
- **R3 — pin mixed-credential behavior** (cookie + Bearer): missing/invalid cookie CSRF proof rejects
  WITHOUT mutation; with valid CSRF the request still executes as ONLY the token (tenant, caps, audit
  actor); an invalid recognized token fails closed, never falling back to the cookie. Correct any stale
  comment claiming the cookie wins. Refusing the combination is optional policy, not a required repair.
- **R4 — retry semantics in the spec for ALL writes:** the committed-mutation-then-500 (audit failure)
  outcome is documented for PUT/DELETE too, not just POST create; a failed bulk item may still mean a
  committed move.
- **R5 — delegation note at mint:** today Owner-only minting (each granted cap held by the minter)
  bounds token writes to the minter's authority. If minting is ever widened, `Allows(cap)` alone does
  not prove authority to DELEGATE that cap tenant-wide — a comment at the mint site records this.
- Reviewer note kept: tokens already pass the protected chain on the UNVERSIONED console routes; this
  work establishes the versioned, documented contract rather than new capability. Delete-group cleanup,
  `applyBulkGroupOne`, and `resolveMachineForProperties` get read in full during implementation (they
  were truncated in the review packet).

## 6. Out of scope

Machine alias/note/status, bulk-status, enrollment-token minting (grantable but not in the stated gap);
session/user routes (human-only); group-scoped tokens; rate limiting; SDK generation.

## 7. Amendment — nested groups (docs/62, 2026-10-31): `parent_id` and the move verb

Additive only; the pinned envelope keys (`machine_group`, `machine_groups`, …) are unchanged.

- **`parent_id` on the group object.** Every group in `listMachineGroups`, and in the create / rename / move
  responses, carries `parent_id` (string, or `null` for a top-level group). It is `null` as well when the parent
  is not visible to the caller (docs/62 R9) — an API token is tenant-wide and always sees the full tree.
- **`createMachineGroup` accepts an optional `parent_id`** (absent or `null` = top-level). An unknown parent, or a
  result nested deeper than 4 levels (a root is level 1), answers **409** and creates nothing.
- **New operation `moveMachineGroup` — `POST /api/v1/machine-groups/{id}/move`, body `{"parent_id": <uuid>|null}`**
  (`parent_id` must be present; `null` makes the group top-level). Capability `manage_groups` — already token-
  grantable, so `apiTokenGrantableCaps` is still not widened. The same handler and audit trail as the console
  (`machine_group.reparented`, carrying the old and new parent). 200 with the updated group; 404 unknown group;
  409 for a cycle, a depth over 4, an unknown or other-tenant parent, a move that would leave a group in the
  subtree with contradictory recording policies, or a group tree that changed under the request.
- **`deleteMachineGroup`** now also answers 409 while the group has **subgroups** (never an auto-move).
- **Authorization is unchanged for a token.** Docs/62 R3 narrows scoped *users* (create-under-P needs coverage of P,
  a root needs a tenant-wide grant, a move needs the group, its old parent and the new parent); a token's grant is
  tenant-wide, so every one of those holds whenever `manage_groups` is. The pinned surface test
  (`publicapi_test.go`) lists the new route, its fixture proves the persisted reparent and that a denial leaves
  the tree alone.

## 8. Recordings are NOT part of this API (docs/63)

Central session recordings are deliberately **not token-accessible**. The agent upload routes
(`/agent/recordings…`) are agent-signed root routes outside `/api/v1`, are absent from the OpenAPI document, and
authenticate by Ed25519 signature, not bearer token. The console routes R1b adds (list, detail, playlist, stream,
download) are gated on `CapViewRecordings`, which is excluded from `apiTokenGrantableCaps` — a token can neither hold
nor be minted with it (asserted in `recording_rbac_test.go`) — and they also refuse any principal that authenticated
with an API token (`Principal.APIToken`), whatever it holds (asserted in `recording_console_test.go`). The tenant policy
routes (`/tenant/recording-policy`, `CapManageTenant` / `CapViewRecordings`) refuse tokens the same way. No `/api/v1`
alias will be added for them (docs/63 §6.1).
