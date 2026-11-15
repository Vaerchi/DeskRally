-- Enrollment redemption must respect tenant suspension. Replaces the function created in
-- migrations/0007_enrollment.sql; everything else about it (SECURITY DEFINER, pinned search_path,
-- one atomic validate-and-consume UPDATE, undifferentiated "no row" for every failure) is unchanged.
--
-- WHY: cp_resolve_tenant_by_slug (0003) already refuses a tenant with `disabled_at` set, so
-- suspending a tenant locks its humans out of the console immediately. Redemption checked only the
-- token — not the tenant — so an enrollment token minted BEFORE the suspension kept working: agents
-- carried on being enrolled into a disabled tenant, silently growing a fleet nobody could see or
-- manage, and each one obtains a device id + pinned key that the rest of the system treats as
-- legitimate. Suspension has to mean the same thing on every path that admits a new principal.
--
-- The tenant check is inside the same statement as the use-count increment, so a suspension that
-- lands concurrently with a redemption serializes on the row lock like every other condition here:
-- either the UPDATE sees the active tenant and consumes a use, or it matches nothing and the
-- redemption fails closed. It can never half-happen.
CREATE OR REPLACE FUNCTION cp_enrollment_token_redeem(p_token_hash bytea)
    RETURNS SETOF enrollment_token
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE enrollment_token et
    SET uses = et.uses + 1
    WHERE et.token_hash = p_token_hash
      AND et.revoked_at IS NULL
      AND et.expires_at > now()
      AND et.uses < et.max_uses
      AND EXISTS (
          SELECT 1 FROM tenant t
          WHERE t.id = et.tenant_id
            AND t.disabled_at IS NULL
      )
    RETURNING et.*;
$$;

-- CREATE OR REPLACE keeps the existing grant, but restate it so applying this file to a database
-- that never had 0007 (a fresh install replaying migrations in order still gets 0007 first, but a
-- test harness may not) leaves the same posture as every other cp_* bootstrap function.
GRANT EXECUTE ON FUNCTION cp_enrollment_token_redeem(bytea) TO PUBLIC;
