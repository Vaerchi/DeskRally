-- cp_list_tenant_max_ages() — cross-tenant helper for the background session reaper.
--
-- The background reaper periodically reaps expired session_record rows for all tenants that have a
-- configured max_session_seconds. It needs to know WHICH tenants to sweep, but tenant_session_policy
-- (like all tenant-scoped tables) enforces FORCE ROW LEVEL SECURITY: a query from rmt_app without
-- app.current_tenant set returns no rows. This function runs SECURITY DEFINER (as the schema owner,
-- who bypasses RLS) to answer that cross-tenant question — exactly the same pattern as cp_create_tenant
-- and cp_enrollment_token_redeem.
--
-- The function returns only the two columns the reaper needs (no policy details leak beyond what the
-- reaper requires). REVOKE on PUBLIC / GRANT to rmt_app only, following every other cp_* function.
CREATE OR REPLACE FUNCTION cp_list_tenant_max_ages()
RETURNS TABLE(tenant_id uuid, max_session_seconds integer)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT tenant_id, max_session_seconds
    FROM tenant_session_policy
    WHERE max_session_seconds > 0
$$;

REVOKE ALL ON FUNCTION cp_list_tenant_max_ages() FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT EXECUTE ON FUNCTION cp_list_tenant_max_ages() TO rmt_app;
  END IF;
END $$;
