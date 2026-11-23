-- machine_property — operator-set key/value custom fields on an enrolled machine (docs/01 §4,
-- "Custom properties / fields for grouping, search, and role scoping"). This first cut is the
-- storage + CRUD surface: display/automation metadata a technician sets on a machine ("site=HQ",
-- "rack=R7"). Nothing AUTHORIZES on a property — RBAC still scopes on machine.group_id, exactly as
-- the console-enrichment fields on `machine` (migrations/0017) already state — so a property can
-- never widen anyone's reach. Grouping/search/role-scoping BY property is a later layer on top of
-- this table.
--
-- WHY A COMPOSITE FK, NOT A PLAIN ONE. Every row carries tenant_id and is confined by the standard
-- tenant_isolation RLS policy below, so a caller can only ever SEE their own tenant's rows. But RLS
-- alone does NOT stop a caller from WRITING a property row that names ANOTHER tenant's machine by its
-- primary key: the WITH CHECK only proves the row's tenant_id equals the pinned tenant, and a plain
-- `machine_id REFERENCES machine(id)` is satisfied by that machine's global PK regardless of whose
-- tenant it lives in (FK integrity checks run as the table owner and bypass RLS on the referenced
-- table). The result would be an orphan property tagged to tenant A but pointing at tenant B's
-- machine PK — a cross-tenant write RLS cannot catch. The COMPOSITE FK
-- (tenant_id, machine_id) -> machine(tenant_id, id) closes it: the referenced (tenant_id, id) pair
-- simply does not exist for another tenant's machine, so the write RAISES a foreign_key_violation.
-- This is the SAME defence, for the same reason, that `machine` itself uses for its group_id
-- (0001_core.sql:135-137: "Composite FK guarantees a machine's group lives in the SAME tenant …,
-- closing a cross-tenant group-assignment hole RLS alone would not catch on writes") and that
-- enrollment_token uses for its group_id.
--
-- machine's PK is (id) alone, so a composite FK to it needs a matching UNIQUE on the referenced
-- columns — exactly the `UNIQUE (tenant_id, id)` trick machine_group carries (0001_core.sql:98)
-- precisely so `machine` can FK to it with a tenant_id. We add the same to `machine` here.
ALTER TABLE machine ADD CONSTRAINT machine_tenant_id_uniq UNIQUE (tenant_id, id);

CREATE TABLE machine_property (
    tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    machine_id  uuid        NOT NULL,
    key         text        NOT NULL,
    value       text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    -- One row per (tenant, machine, key); SetProperty upserts on exactly this key.
    PRIMARY KEY (tenant_id, machine_id, key),
    -- The load-bearing tenant-consistency guarantee (see header). ON DELETE CASCADE so a retired
    -- machine's properties die with it rather than orphaning (session_record CASCADEs from machine
    -- the same way).
    FOREIGN KEY (tenant_id, machine_id) REFERENCES machine (tenant_id, id) ON DELETE CASCADE
);

-- Supports the per-machine list (WHERE machine_id = $1) that backs GET /machines/{id}/properties.
CREATE INDEX machine_property_machine_idx ON machine_property (tenant_id, machine_id);

-- =====================================================================================
-- Row-Level Security — the same contract as every other tenant-scoped table (0001_core.sql).
-- FORCE so even the table owner obeys it. No second arg to current_setting: an unpinned query
-- RAISES rather than leaking (fail-closed), matching machine's own policy (0001_core.sql) — NOT the
-- `,true` missing_ok form 0013 uses for its pre-tenant guest paths.
-- =====================================================================================
ALTER TABLE machine_property ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_property FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON machine_property
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Explicit grant (belt-and-suspenders over 0005's default privileges), guarded so this file also
-- applies to a schema built without the role — and re-runnable, since resetSchema drops the table
-- with its per-object grants (0023's pattern).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON machine_property TO rmt_app;
    END IF;
END
$$;

COMMENT ON TABLE machine_property IS
    'Operator-set key/value custom fields on an enrolled machine (docs/01 §4). Display/automation '
    'metadata only — nothing authorizes on it (RBAC scopes on machine.group_id). The composite FK '
    '(tenant_id, machine_id) -> machine(tenant_id, id) makes a property inseparable from a machine in '
    'the SAME tenant, closing a cross-tenant write RLS alone would not catch.';
