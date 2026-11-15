-- 0061: cp_session_ticket_redeem stamps session_record.redeemed_at (docs/51, session transfer).
--
-- Separate from 0060 because it redefines the redemption function, which must run after 0023 (its return
-- type is the ledger table) and after 0055 (which it extends), while 0060's columns are needed by every
-- session read (the test schema applies 0060 always, and 0023 + 0061 only where the ledger is used).
--
-- BASED ON 0055's DEFINITION, which is what production runs, and it keeps all three of 0055's guarantees:
--   * the SHARED tenant_issuance advisory lock: cp_platform_set_suspended takes it EXCLUSIVELY, so a
--     redemption either commits before a suspension or sees it;
--   * the suspended-tenant guard (tenant.disabled_at IS NULL): a suspended tenant redeems NOTHING;
--   * SET search_path = pg_catalog, public, pg_temp and schema-qualified tables (SECURITY DEFINER
--     hardening: pg_temp last, built-ins first).
-- (The first version of this file was written from 0023's original and dropped all three. Caught before
-- deploy, 2026-10-22; platform_pgstore_test.go now applies 0061 AFTER 0055, in production order, so the
-- suspension tests run against this function.)
--
-- What it adds: on a NEW redemption only, it stamps session_record.redeemed_at, so "signaling vouched for
-- this session" (transfer offer gate) and "this session's ticket was already redeemed" (transfer ticket
-- endpoint) stay answerable after the ledger row is reaped. session_record has FORCE ROW LEVEL SECURITY
-- and its policy reads current_setting('app.current_tenant') WITHOUT a default; production's owner is a
-- superuser and bypasses it, but on a non-superuser owner the UPDATE would raise and take every
-- redemption with it, so the redeeming tenant is pinned, transaction-locally, first. It touches exactly
-- the one (tenant, session) row.
CREATE OR REPLACE FUNCTION cp_session_ticket_redeem(
        p_tenant_id  uuid,
        p_session_id uuid,
        p_device_id  text,
        p_expires_at timestamptz)
    RETURNS SETOF session_ticket_redemption
    LANGUAGE plpgsql
    VOLATILE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    r public.session_ticket_redemption;
BEGIN
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('tenant_issuance:' || p_tenant_id::text, 0));
    FOR r IN
        WITH reaped AS (
            DELETE FROM public.session_ticket_redemption
            WHERE expires_at < now() - interval '1 hour'
        )
        INSERT INTO public.session_ticket_redemption (tenant_id, session_id, device_id, expires_at)
        SELECT p_tenant_id, p_session_id, p_device_id, p_expires_at
         WHERE EXISTS (SELECT 1 FROM public.tenant t WHERE t.id = p_tenant_id AND t.disabled_at IS NULL)
        ON CONFLICT (tenant_id, session_id) DO NOTHING
        RETURNING *
    LOOP
        PERFORM set_config('app.current_tenant', p_tenant_id::text, true);
        UPDATE public.session_record SET redeemed_at = now()
         WHERE tenant_id = p_tenant_id AND id = p_session_id AND redeemed_at IS NULL;
        RETURN NEXT r;
    END LOOP;
END
$$;
