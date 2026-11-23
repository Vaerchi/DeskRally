-- Tenant provisioning + management-audit hardening.
--
-- 1) cp_create_tenant — the privileged tenant-provisioning surface.
--
--    0001_core.sql: "Tenant provisioning runs as a privileged job that bypasses RLS." The
--    tenant table's policy is `id = current_setting('app.current_tenant')`, so the RLS-subject
--    application role (rmt_app, 0005) can never INSERT a tenant row other than the one it is
--    already pinned to — which is exactly right for every path EXCEPT provisioning a NEW
--    tenant (the SaaS signup / operator surface behind POST /tenants + CapManageTenant).
--    Like the 0003 auth bootstrap, that one narrow operation is exposed as a SECURITY DEFINER
--    function: it executes with the OWNER's privileges (apply this migration as the same
--    admin/owner role as 0003, i.e. one that bypasses RLS), takes only the new tenant's
--    attributes, and returns the created id. The Go handler gates it on CapManageTenant
--    BEFORE calling; the function itself stays self-limiting (a pure INSERT of a fresh row —
--    it cannot read or touch existing tenants).
--
-- 2) audit_event append-only for rmt_app.
--
--    Mirrors 0005's backstage_audit_event rule: the management-plane audit trail (who enrolled
--    what, who started which session) must not be editable by the app role — INSERT + SELECT
--    only; retention/purge runs as a separate privileged job. Guarded on the role existing so
--    this file also applies cleanly to a schema where 0005 has not (yet) been run.

-- Returns the created row (not just the id): under RLS the caller cannot re-read the NEW
-- tenant's row from its pinned connection, so the row's DB-assigned fields (id, created_at)
-- must come back from the provisioning call itself.
CREATE FUNCTION cp_create_tenant(p_slug text, p_name text, p_mode text)
    RETURNS tenant
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    INSERT INTO tenant (slug, name, deployment_mode)
    VALUES (p_slug, p_name, p_mode)
    RETURNING *;
$$;

-- Same grant posture as the 0003 bootstrap functions: EXECUTE to PUBLIC (the app role name is
-- deployment-specific); authorization for WHO may provision lives in the Go handler
-- (CapManageTenant), and the function's only power is inserting a brand-new tenant row.
GRANT EXECUTE ON FUNCTION cp_create_tenant(text, text, text) TO PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE UPDATE, DELETE ON audit_event FROM rmt_app;
    END IF;
END
$$;
