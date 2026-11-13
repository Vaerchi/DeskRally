# 67 — SECURITY DEFINER functions should not be owned by a superuser (design note)

Status: **shipped: implemented in migration 0076 and deployed.** Follow-up to a review finding (H1,
2026-11-03), whose immediate hazard migration 0074 closed. See "What was built" at the end for the deviations from this
design.

## The problem 0074 did not remove

The control plane's application role `rmt_app` is deliberately weak: NOSUPERUSER, NOBYPASSRLS, DML only, every
tenant-scoped table under FORCE ROW LEVEL SECURITY (0005). A few lookups must happen *before* a tenant is known: a session
token, an attended code, an enrollment token, a tenant slug, an API token. Those go through SECURITY DEFINER functions, which
run as their **owner**. Before 0076 the owner is the migration role, and in a typical deployment that role (`rmt`) is **rolsuper and
bypassrls**.

So every definer function is a door from `rmt_app` to a superuser. H1 was one way through it: a search_path without a trailing
pg_temp let a caller's TEMP VIEW stand in for a table, and a function in that view ran as the owner. 0074 fixed every function's
path and its test stops a new function regressing. The blast radius is unchanged, though. Any future defect in a definer
function hands the caller a superuser, not just an RLS bypass. Examples are dynamic SQL built from an argument, a missed
qualification in a new function, or a PostgreSQL bug in this area.

## Proposal

A dedicated owner role for the definer functions, with exactly the rights they use:

- `rmt_definer`: NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION. It needs **BYPASSRLS**, because bypassing RLS
  for pre-tenant lookups is the reason these functions exist. Only a superuser can grant BYPASSRLS, and the migration runs as
  one, so the migration can.
- Table privileges granted per table, derived from what the functions touch. These are mostly SELECT, plus the narrow
  INSERT/UPDATEs some functions do: token consume, touch last_seen, attended consent, tenant creation. No ownership of any table,
  so it cannot ALTER, DROP or disable RLS.
- Every SECURITY DEFINER routine in `public`: `ALTER ROUTINE … OWNER TO rmt_definer`. The canonical search_path stays as 0074
  set it.
- Optionally, a split later: a read-only `rmt_definer_read` for the pure lookups and a writer for the rest. That's only worth it if
  the privilege inventory shows a clean split.

Result: a defect in a definer function yields "read/write these tables across tenants", not "superuser on the database server"
(COPY … PROGRAM, file access, new roles, extensions).

## How to build it safely

1. **Derive, do not hand-list.** As in 0074, find the routines from `pg_proc` (prosecdef, schema public, not an extension member).
   The privilege set comes from a test that exercises every function, not from reading bodies.
2. **The fixture trap.** The per-test fixture (`resetSchemaWith` in pgstore_test.go) applies migrations piecemeal, as the
   superuser test role. If the ownership migration is not applied there, every store test runs the functions as a superuser and
   a missing GRANT surfaces only in production. Either apply the ownership step at the end of every fixture, or run the store
   suites once against a fully migrated database through the real runner, like `TestPgEveryDefinerFunctionPutsPgTempLast` does.
3. **Tests.**
   - Every definer routine's owner is `rmt_definer`.
   - `rmt_definer` is not superuser.
   - The role's table privileges equal an expected set exactly, so a new GRANT is a deliberate test change.
   - The whole pg suite passes with the functions owned by it.
4. **Deploy.** It is one migration; no application change is needed, and rollback is `ALTER ROUTINE … OWNER TO rmt`. Before the GO,
   run the definer inventory on the target database read-only, as for 0074.

## Not in scope

Removing superuser from the migration role itself (a separate hardening: the migration role needs DDL, not SUPERUSER, once the
extensions are installed), and coturn/Caddy privileges (security audit #19).

## What was built (0076)

- `migrations/0076_definer_owner.sql`: refuses to run unless the migration role is a superuser; creates `rmt_definer`
  idempotently, pins `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS` every run, removes any role
  membership; `GRANT USAGE ON SCHEMA public`; one-line table GRANTs (24 tables, see the file and the privilege table in
  its header); then, derived from `pg_proc` like 0074, `ALTER ROUTINE ... OWNER TO rmt_definer` for every definer routine
  in `public` that is not an extension member (43 after 0075). A definer routine elsewhere is refused and the migration
  rolls back. A second run changes nothing. It also revokes CREATE on schema `public` from PUBLIC (PostgreSQL 14's default would
  otherwise let `rmt_definer` plant objects there; a no-op on 15+). A PRE-EXISTING `rmt_definer` is REFUSED (the whole
  file rolls back, nothing is cleaned) if it has any membership in either direction, owns anything but routines, or holds
  ANY explicit privilege beyond the table grants: schema (other than USAGE on public), database, tablespace, routine it does
  not own, sequence/view/any relation outside public tables, column, type, language, large object, foreign data wrapper or
  server, parameter (PG15+), or a default-privilege entry. Table grants it held before must be among the ones 0076 grants
  (same privilege, no grant option). Afterwards its EFFECTIVE `CREATE` on every non-system schema and on the database
  must be false (a direct grant survives `REVOKE ... FROM PUBLIC`, so the ACLs are read, not assumed). A new role
  (the typical case) passes every check.
- No sequence, column-level or function grants are needed. Definer-to-definer calls (`cp_platform_check`,
  `cp_hostname_lock_tenant`, ...) need none (same owner), advisory locks need none, and `ALTER OWNER` needs no CREATE
  on schema `public` because the migration role is a superuser, so `rmt_definer` has none. One trigger function IS a
  definer (`cp_snapshot_attended_audit_key`, 0042, BEFORE UPDATE OF device_id on `attended_session`): the derived
  ALTER moves it like the rest, and its read of `machine` is covered by the SELECT grant. It needs no extra grant.
- `ALTER OWNER` rewrote only the owner's own ACL entries: EXECUTE for PUBLIC and `rmt_app` is identical before and
  after (tested by comparing the normalised ACLs and the effective `has_function_privilege` results).
- Privileges were derived from the routine bodies and confirmed empirically: the whole control-plane suite passes
  with the routines owned by `rmt_definer` (no further grant was needed). Table-level grants were chosen over column
  grants; the table list is the deliberate surface.

### The fixture trap, closed

`definer_owner_fixture_test.go` hooks `execScriptErr`: after any fixture script that creates a table or a definer
function, `ownDefinersLikeProduction` creates the role, applies 0076's own GRANT lines (parsed from the migration, so
the suite runs the real grants) to the tables that exist so far, and hands every definer routine to `rmt_definer`.
Every `apply*Migration` helper goes through `execScript`, so none can be missed. Databases made by
`freshMigrationDatabase` are skipped: they use the real runner. `TestPgFixtureRunsDefinersAsRmtDefiner` fails if the
fixture leaves a definer function superuser-owned, and revokes a grant (SELECT on `tenant`, UPDATE on `user_session`,
SELECT on `api_token`) to prove the store call then fails with `permission denied` instead of silently working.

### Tests (`definer_owner_pgstore_test.go`, fresh database, real runner)

Every application definer routine is owned by `rmt_definer` (the guard for 0077+: a new definer function must end
with `ALTER ROUTINE ... OWNER TO rmt_definer`); role attributes, no ownership, no memberships; privileges equal an
EXPECTED list exactly (including no column, schema, sequence, function or database grants); EXECUTE ACLs, bodies and
settings unchanged; the 0074 temp-view shadow attack still inert; a planted definer function owned by `rmt_definer`
cannot create a role or `COPY ... TO PROGRAM` (its superuser-owned twin can create a role: the premise); non-superuser
migration role refused with a clear message; a definer routine in another schema refused with no partial apply;
re-run is a no-op. Each was mutation-tested (fixture ownership off, a grant removed, an extra grant, LOGIN, NOBYPASSRLS,
one routine skipped, ownership not applied, superuser check removed): every mutation fails the suite.

### Deploy note

The GO needs a rehearsal first: restore a live dump to a scratch server, run the migration as the production migration
role, then the application smoke (login, session, attended redeem, enrollment, platform console, hostname/branding)
against it. Rollback is in docs/10 (owner back to the migration role, then drop `rmt_definer`). `rmt_definer` is
cluster-wide: a restore into a cluster where it already exists with other attributes is repaired by the pin step.
A restore into a NEW cluster needs the role first, or the dump's `OWNER TO rmt_definer` / `GRANT ... TO rmt_definer`
lines fail and the functions stay superuser-owned: docs/22 section 3 has the pre-step and the post-restore check.
Rollback commands act on ONE database; roles are cluster-wide, so run them in every database of the cluster
(rehearsal copies included) before `DROP ROLE`.

### Deviations from the design

- The privilege set came from the bodies plus a full-suite run, not from a separate per-function exercising test.
- The optional read/write split (`rmt_definer_read`) was not done: only 10 of the 24 tables get write grants, and every
  one of the write routines also reads, so there is no clean split.
