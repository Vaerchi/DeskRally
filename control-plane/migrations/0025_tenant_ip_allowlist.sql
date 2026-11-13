-- tenant_ip_allowlist — per-tenant source-IP restriction on the authenticated console/host API
-- (docs/01 §10 "IP allow-listing for admin/host access", the per-tenant SaaS layer over the
-- deployment-wide CP_ADMIN_IP_ALLOWLIST guard added in loop 36). Each MSP restricts its OWN admins
-- and technicians to a set of source networks: when a tenant has one or more allow-list entries, an
-- authenticated request whose source IP is not covered is refused 403.
--
-- WHERE IT IS ENFORCED, AND WHY NOT AT THE EDGE. The deployment-wide allow-list runs as the OUTERMOST
-- middleware, before auth, because it needs no identity. A PER-TENANT list cannot: the tenant is
-- unknown until auth resolves the principal. So this list is enforced by a small middleware that runs
-- AFTER authMiddleware/tenantMiddleware (the tenant is pinned, the CIDRs read RLS-scoped). An EMPTY
-- list means NO restriction (open) — the backward-compatible default, so a tenant that never
-- configures one is unaffected.
--
-- WHY NO COMPOSITE FK (unlike machine_property/0024). This table has no child relationship to another
-- tenant-owned row — it references only tenant(id) — so the standard tenant_isolation RLS policy is
-- the whole tenant-scoping story: a caller only ever SEES or WRITES their own tenant's rows, and there
-- is no second table whose PK a malicious write could borrow across tenants.

CREATE TABLE tenant_ip_allowlist (
    tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    -- A canonical CIDR (a bare IP is normalized to /32 or /128 by the handler before it is stored),
    -- so equality de-duplicates and the enforcement re-parse is exact.
    cidr        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- One row per (tenant, cidr); re-adding an entry already present is idempotent (INSERT ... ON
    -- CONFLICT DO NOTHING). ON DELETE CASCADE from tenant so a removed tenant's list dies with it.
    PRIMARY KEY (tenant_id, cidr)
);

-- =====================================================================================
-- Row-Level Security — the same fail-closed contract as every other tenant-scoped table
-- (0001_core.sql / 0024_machine_property.sql). FORCE so even the table owner obeys it; no second arg
-- to current_setting, so an UNPINNED query RAISES rather than leaking (fail-closed).
-- =====================================================================================
ALTER TABLE tenant_ip_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_ip_allowlist FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant_ip_allowlist
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Explicit grant (belt-and-suspenders over 0005's default privileges), guarded so this file also
-- applies to a schema built without the role — and re-runnable, since resetSchema drops the table with
-- its per-object grants. No UPDATE: entries are add/remove only, never mutated in place.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, DELETE ON tenant_ip_allowlist TO rmt_app;
    END IF;
END
$$;

COMMENT ON TABLE tenant_ip_allowlist IS
    'Per-tenant source-IP allow-list for the authenticated console/host API (docs/01 §10). Empty = '
    'open (no restriction). Enforced AFTER auth, once the tenant is known; the deployment-wide '
    'CP_ADMIN_IP_ALLOWLIST guard runs at the edge. Managed under CapManageTenant with an anti-lockout '
    'safeguard that refuses a change excluding the acting admin''s own current source IP.';
