-- 0034_group_session_policy.sql — per-machine-group concurrent-session limits (docs/01 §5 seat metering).
--
-- Loop 56 (0029) gave each TENANT a cap on how many remote-support sessions it may hold OPEN at once.
-- This adds a second, finer axis: a cap PER machine group, so an admin can bound a department/site to N
-- concurrent sessions independently of the tenant-wide ceiling. Both caps are enforced together, atomically,
-- at POST /sessions (control-plane/pgstore_dataplane.go StartSessionWithinLimit) under the SAME per-tenant
-- advisory lock, so a burst of concurrent starts can overshoot neither.
--
-- Two changes:
--
--   1. session_record.group_id — the group the session was ADMITTED against, snapshotted at start. This is
--      DELIBERATELY distinct from the machine's LIVE group (which the read path still derives by JOINing
--      machine, for reports/RBAC display): a session consumes a seat in the group it started under, and
--      moving the machine to another group mid-session must NOT silently move its open seat. The per-group
--      count reads THIS column, so the in-memory fake (which counts the same snapshot on the record) and the
--      pg store agree by construction — no mid-session-move divergence. Nullable: a group-less/ephemeral
--      session is simply uncapped by group. No FK — it is a soft snapshot, independent of the group's later
--      life (rename/delete/reassign leave prior seats counted where they were admitted).
--
--   2. group_session_policy — one cap row per (tenant, group). Mirrors tenant_session_policy (0029): RLS by
--      app.current_tenant, FORCE RLS, GRANT to rmt_app. The composite FK to machine_group(tenant_id, id) is
--      what makes a cross-tenant write impossible (a plain FK to a global id would let one tenant name
--      another tenant's group id; the composite FK to (tenant_id, id) cannot, because RLS hides the other
--      tenant's row so its (tenant_id, id) pair is absent) — see the machine/enrollment_token precedent in
--      0001/0022 and the "composite FK closes cross-tenant write" note.

ALTER TABLE session_record ADD COLUMN group_id uuid;

COMMENT ON COLUMN session_record.group_id IS
    'Snapshot of the machine group the session was admitted against, for per-group seat counting; '
    'distinct from the machine''s live group (JOIN-derived on read). Nullable = uncapped by group.';

-- Backfill the snapshot for sessions that are ALREADY OPEN when this migration runs. Without it every
-- session open across the upgrade carries a NULL group_id, which the per-group count skips -- so for as
-- long as those sessions last a group could hold more open seats than its cap allows, and an operator
-- setting a cap would see it under-count with no indication why.
--
-- The machine's CURRENT group is used as the admitted-against group. That is an approximation -- these
-- sessions started before anything recorded the real admission group, so it is the only evidence there is
-- -- but it is strictly better than NULL: it is right for every session whose machine has not been moved,
-- and it is the same value a fresh session for that machine would snapshot right now.
--
-- Scoped to OPEN sessions only. Closed ones are history: nothing counts their seats, and rewriting them
-- would corrupt the per-group reports by attributing a finished session to a group it may never have run
-- under. tenant_id is matched too, so the join cannot cross a tenant boundary.
UPDATE session_record s
   SET group_id = m.group_id
  FROM machine m
 WHERE s.machine_id = m.id
   AND s.tenant_id  = m.tenant_id
   AND s.ended_at IS NULL
   AND s.group_id IS NULL
   AND m.group_id IS NOT NULL;

CREATE TABLE group_session_policy (
    tenant_id                uuid    NOT NULL,
    group_id                 uuid    NOT NULL,
    max_concurrent_sessions  integer NOT NULL DEFAULT 0
                                 CHECK (max_concurrent_sessions >= 0 AND max_concurrent_sessions <= 100000),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE group_session_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_session_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_session_policy
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON group_session_policy TO rmt_app;
  END IF;
END $$;
