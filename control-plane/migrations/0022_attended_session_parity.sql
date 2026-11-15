-- Bring `attended_session` up to the same tenant-isolation posture as every other tenant-scoped
-- table. Three divergences, all introduced by 0013 and all MEASURED against the live schema before
-- this file was written:
--
--   1. NO composite (tenant_id, group_id) FOREIGN KEY. `machine` (0001_core.sql:137) and
--      `enrollment_token` (0011) both carry one, and 0001's comment says why it exists: it closes
--      "a cross-tenant group-assignment hole RLS alone would not catch on writes". Measured:
--        machine           → FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group(tenant_id, id)
--        enrollment_token  → FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group(tenant_id, id)
--        attended_session  → (tenant FK only)
--      RLS confines a row to the pinned tenant; it does NOT check that the group named in that row
--      belongs to the same tenant. That is exactly what the composite FK is for, which is why the
--      other two have it.
--
--   2. The tenant-isolation policy passes `missing_ok => true`. It is the ONLY policy in the whole
--      migration set that does. Measured as `rmt_app` with no tenant pinned, on a DB carrying the
--      full 0001..0021 chain:
--        SELECT count(*) FROM machine;           → ERROR: unrecognized configuration parameter
--        SELECT count(*) FROM enrollment_token;  → ERROR: unrecognized configuration parameter
--        SELECT count(*) FROM attended_session;  → returns a count, silently
--      A missing tenant pin is a BUG — a request that reached the database without going through
--      the binder. On every other table that bug is loud. Here it degraded into "no rows", which
--      reads like an empty tenant and can send a caller down a path built for "there is nothing
--      here" when the truth is "we do not know who is asking".
--
--   3. FORCE ROW LEVEL SECURITY is not set. Measured (pg_class.relforcerowsecurity):
--        machine=t  enrollment_token=t  audit_event=t  attended_session=f
--      Without FORCE, the table OWNER bypasses the policy. The application connects as `rmt_app`,
--      not the owner, so this is defence in depth rather than a live hole — but it is the same
--      defence in depth its siblings have, and the asymmetry is what makes a reviewer assume a
--      reason exists.
--
-- WHY TIGHTENING THE POLICY IS SAFE FOR THE PUBLIC GUEST PATHS — this is the load-bearing check, and
-- 0013's own comment is what made it look risky. The attended guest routes are deliberately
-- PRE-TENANT: the guest holds a code or an attend token and no principal, so nothing is pinned. They
-- reach the table only through `cp_attended_redeem`, `cp_attended_by_token` and `cp_attended_consent`,
-- which are SECURITY DEFINER. Measured: all three are owned by `postgres`, which has
-- rolbypassrls = t (and rolsuper = t), so they bypass row security ENTIRELY and never evaluate this
-- policy. `missing_ok` was therefore never what kept them working, and removing it cannot break them.
-- 0021's `machine` INSERT inside `cp_attended_redeem` already depends on that same BYPASSRLS and
-- works, which is independent confirmation.
--
-- Existing data: verified 0 rows in `attended_session` whose (tenant_id, group_id) does not resolve
-- to a machine_group, so ADD CONSTRAINT validates cleanly. A deployment with ended sessions
-- referencing a since-deleted group would fail here — that is the correct, loud outcome, and the fix
-- is to reconcile those rows rather than to skip the constraint.

-- 1. Cross-tenant group-assignment guard, matching machine and enrollment_token.
--    machine_group already carries UNIQUE (tenant_id, id) (0001_core.sql:98 — a comment there says it
--    exists precisely so a child FK can carry tenant_id), so no new index is needed.
ALTER TABLE attended_session
    ADD CONSTRAINT attended_session_tenant_id_group_id_fkey
    FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group (tenant_id, id);

-- 2. Restore the loud-failure form. A policy's USING expression cannot be altered in place, so the
--    policy is dropped and recreated with the same name and the same semantics minus `missing_ok`.
DROP POLICY IF EXISTS attended_session_tenant_isolation ON attended_session;
CREATE POLICY attended_session_tenant_isolation ON attended_session
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- 3. Match every sibling's defence in depth.
ALTER TABLE attended_session FORCE ROW LEVEL SECURITY;
