-- dynamic_group — a SAVED, NAMED machine-property predicate that resolves to a LIVE set of machines
-- (docs/01 §4 "Custom properties / custom fields for grouping" — the GROUPING layer on top of the
-- per-machine properties of migration 0024 and the fleet property-search of loop 35).
--
-- A dynamic group is NOT a membership table: it stores only a predicate (property_key [+ optional
-- property_value]). Its members are computed on demand by intersecting `MachineIDsWithProperty(key,
-- value)` with the machines the caller may already see — the SAME "narrow-only, never widen" resolution
-- `GET /machines?property_key=` uses (handleListMachines). So a dynamic group can never reveal a machine
-- the caller could not already list, and it needs no FK to `machine` — it only references its tenant.
--
-- `property_value = ''` means "any value" (matches the MachineIDsWithProperty semantics), so a group
-- keyed on `site` (empty value) = "every machine that has a `site` property, whatever its value".

CREATE TABLE dynamic_group (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name           text        NOT NULL,
    property_key   text        NOT NULL,
    property_value text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- One dynamic group per name per tenant, CASE-INSENSITIVELY: "HQ" and "hq" are the same group, so the
-- console never lists confusing near-duplicates. A plain UNIQUE(tenant_id, name) on a `text` column is
-- byte-wise (case-SENSITIVE) under the default collation, which would let "HQ"/"hq" coexist and diverge
-- from the InMemory fake (which dedupes with strings.EqualFold). A functional unique index on
-- lower(name) makes production match that intent — and a case-only duplicate INSERT RAISES 23505, which
-- PgDynamicGroupStore maps to ErrDynamicGroupNameTaken. This index also serves the per-tenant lookups.
CREATE UNIQUE INDEX dynamic_group_name_ci_uniq ON dynamic_group (tenant_id, lower(name));

-- =====================================================================================
-- Row-Level Security — the same fail-closed contract as every other tenant-scoped table
-- (0001_core.sql / 0025_tenant_ip_allowlist.sql). FORCE so even the table owner obeys it; no second
-- arg to current_setting, so an UNPINNED query RAISES rather than leaking (fail-closed).
-- =====================================================================================
ALTER TABLE dynamic_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_group FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON dynamic_group
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Explicit grant (belt-and-suspenders over 0005's default privileges), guarded so this file also
-- applies to a schema built without the role — and re-runnable, since resetSchema drops the table. No
-- UPDATE: a dynamic group is create/delete only (edit = delete + recreate), like tenant_ip_allowlist.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, DELETE ON dynamic_group TO rmt_app;
    END IF;
END
$$;

COMMENT ON TABLE dynamic_group IS
    'A saved, named machine-property predicate (docs/01 §4 grouping). Members are resolved on demand by '
    'intersecting MachineIDsWithProperty(key,value) with the caller''s visible machines (narrow-only) — '
    'no membership rows, no FK to machine. Managed under CapManageGroups; resolved under CapViewMachines.';
