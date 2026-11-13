-- 0055: platform operator (coordination/designs/platform-operator-view-v2.md + v3/v4/v5 deltas,
-- Codex-accepted 2026-10-16).
--
-- WHAT. One deployment hosts independent businesses as separate tenants. The platform operator (named
-- users of one configured platform tenant) can list tenant metadata and create / suspend / resume
-- tenants. Nothing here reads or writes a customer's users, machines, sessions or audit content; the
-- per-tenant RLS policies are unchanged.
--
-- WHO. Not "every Owner of the platform tenant": a per-user grant (platform_operator) written only by
-- the owner role through the controlplane CLI. rmt_app can neither read nor write these tables; it
-- reaches them only through the cp_platform_* SECURITY DEFINER functions below, each of which first
-- runs cp_platform_check (grant + interactive session + MFA freshness bound to the user's CURRENT
-- mfa_generation).
--
-- MFA: the generation columns are in 0054; this file's check requires the session's recorded
-- generation to equal the user's current one.
--
-- TRUST BOUNDARY (documented, Codex): app.current_tenant is set by the application. These checks
-- contain handler bugs and wrong-connection mistakes; they do not contain arbitrary SQL executed as
-- rmt_app, which could also set the tenant context. Audit for these actions is written by the Go
-- orchestration in the SAME transaction (design deviation accepted by Codex 2026-10-16), so the
-- functions are called only from that path.
--
-- tenant_create: cp_create_tenant (0006, EXECUTE to PUBLIC) let any connection create tenants. It is
-- kept for the owner-role bootstrap CLI but no longer executable by PUBLIC or rmt_app; the API path is
-- cp_platform_create_tenant.

CREATE TABLE IF NOT EXISTS platform_config (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    set_at     timestamptz NOT NULL DEFAULT now(),
    set_by     text NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_operator (
    user_id     uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    granted_by  text NOT NULL,
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE
);

-- 0005's default privileges would hand rmt_app DML on any new table; these two are owner-only.
REVOKE ALL ON platform_config   FROM PUBLIC;
REVOKE ALL ON platform_operator FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE ALL ON platform_config   FROM rmt_app;
        REVOKE ALL ON platform_operator FROM rmt_app;
        REVOKE EXECUTE ON FUNCTION cp_create_tenant(text, text, text) FROM rmt_app;
    END IF;
END
$$;
REVOKE EXECUTE ON FUNCTION cp_create_tenant(text, text, text) FROM PUBLIC;

-- The platform check. Raises (does not return false) so no caller can forget to test the result.
-- p_max_mfa_age: 12 hours for reads, 15 minutes for lifecycle mutations (decided by the caller
-- function, never by the application).
CREATE OR REPLACE FUNCTION cp_platform_check(p_user uuid, p_session uuid, p_max_mfa_age interval)
    RETURNS uuid
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_platform uuid;
    v_ctx      text := current_setting('app.current_tenant', true);
BEGIN
    SELECT c.tenant_id INTO v_platform FROM public.platform_config c WHERE c.singleton;
    IF v_platform IS NULL THEN
        RAISE EXCEPTION 'platform: no platform tenant configured' USING ERRCODE = '42501';
    END IF;
    IF v_ctx IS NULL OR v_ctx = '' OR v_ctx::uuid <> v_platform THEN
        RAISE EXCEPTION 'platform: caller is not in the platform tenant' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM public.platform_operator o
          JOIN public.app_user u     ON u.id = o.user_id AND u.tenant_id = o.tenant_id
          JOIN public.tenant t       ON t.id = u.tenant_id
          JOIN public.user_totp z    ON z.user_id = u.id AND z.tenant_id = u.tenant_id
          JOIN public.user_session s ON s.user_id = u.id AND s.tenant_id = u.tenant_id
         WHERE o.user_id = p_user
           AND o.tenant_id = v_platform
           AND u.disabled_at IS NULL
           AND t.disabled_at IS NULL
           AND z.confirmed_at IS NOT NULL
           AND u.mfa_generation > 0
           AND s.id = p_session
           AND s.revoked_at IS NULL
           AND s.expires_at > now()
           AND s.mfa_verified_at IS NOT NULL
           AND s.mfa_verified_at > now() - p_max_mfa_age
           AND s.mfa_generation = u.mfa_generation
    ) THEN
        RAISE EXCEPTION 'platform: not an operator, or the session lacks a current second-factor verification'
            USING ERRCODE = '42501';
    END IF;
    RETURN v_platform;
END
$$;

-- For the console only: is this caller an operator, and is its session's MFA fresh enough for a
-- mutation? Never raises for a non-operator; reveals nothing about any other user or tenant.
CREATE OR REPLACE FUNCTION cp_platform_whoami(p_user uuid, p_session uuid)
    RETURNS TABLE (operator boolean, mfa_ok boolean, mfa_fresh boolean)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_ctx      uuid;
    v_operator boolean;
    v_ok       boolean := false;
    v_fresh    boolean := false;
BEGIN
    -- Compare tenant ids as uuids (any valid spelling), and treat an unset/malformed context as none.
    BEGIN
        v_ctx := NULLIF(current_setting('app.current_tenant', true), '')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        v_ctx := NULL;
    END;
    -- Operator = holds the grant in the configured platform tenant, enabled, and this request runs
    -- in that tenant. Whether the SESSION is MFA-verified is reported separately so the console can
    -- ask for a step-up instead of hiding the panel.
    SELECT EXISTS (
        SELECT 1
          FROM public.platform_config c
          JOIN public.platform_operator o ON o.tenant_id = c.tenant_id
          JOIN public.app_user u ON u.id = o.user_id AND u.tenant_id = o.tenant_id
          JOIN public.tenant t ON t.id = u.tenant_id
         WHERE c.singleton AND o.user_id = p_user AND u.disabled_at IS NULL AND t.disabled_at IS NULL
           AND v_ctx IS NOT NULL AND c.tenant_id = v_ctx
    ) INTO v_operator;
    IF v_operator THEN
        BEGIN
            PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
            v_ok := true;
            PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
            v_fresh := true;
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END IF;
    RETURN QUERY SELECT v_operator, v_ok, v_fresh;
END
$$;

-- Tenant metadata for the operator. Only the tenant row and a user count leave this function.
CREATE OR REPLACE FUNCTION cp_platform_list_tenants(p_user uuid, p_session uuid)
    RETURNS TABLE (id uuid, slug text, name text, deployment_mode text, created_at timestamptz,
                   disabled_at timestamptz, user_count bigint, unleased_machines boolean)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
    RETURN QUERY
        SELECT t.id, t.slug, t.name, t.deployment_mode, t.created_at, t.disabled_at,
               (SELECT count(*) FROM public.app_user u WHERE u.tenant_id = t.id),
               -- Needed to judge whether a suspension is complete (v4): agents that do not enforce
               -- session leases keep running sessions until they end.
               EXISTS (SELECT 1 FROM public.machine m
                        WHERE m.tenant_id = t.id AND NOT m.require_session_policy)
          FROM public.tenant t
         ORDER BY t.created_at, t.slug;
END
$$;

CREATE OR REPLACE FUNCTION cp_platform_create_tenant(p_user uuid, p_session uuid, p_slug text,
                                                      p_name text, p_mode text)
    RETURNS public.tenant
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_row public.tenant;
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    INSERT INTO public.tenant (slug, name, deployment_mode)
    VALUES (p_slug, p_name, p_mode)
    RETURNING * INTO v_row;
    RETURN v_row;
END
$$;

-- Suspend (p_suspended) or resume a CUSTOMER tenant. The UPDATE takes the tenant row lock first; lease
-- and ticket issuance hold FOR SHARE on their own tenant row (v5), so issuance is ordered before the
-- commit or sees disabled_at. lock_timeout bounds the wait for that row lock.
CREATE OR REPLACE FUNCTION cp_platform_set_suspended(p_user uuid, p_session uuid, p_tenant uuid,
                                                      p_suspended boolean)
    RETURNS public.tenant
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_platform uuid;
    v_row      public.tenant;
BEGIN
    v_platform := public.cp_platform_check(p_user, p_session, interval '15 minutes');
    IF p_tenant = v_platform THEN
        RAISE EXCEPTION 'platform: the platform tenant cannot be suspended' USING ERRCODE = '42501';
    END IF;
    PERFORM set_config('lock_timeout', '5000', true);
    -- Wait for every in-flight issuance for this tenant (they hold the SHARED lock on this key for the
    -- whole request, issuance_guard.go), and keep new ones out until this transaction commits; they
    -- then read disabled_at and are refused. Same key text as issuanceLockKey.
    PERFORM pg_advisory_xact_lock(hashtextextended('tenant_issuance:' || p_tenant::text, 0));
    UPDATE public.tenant t
       SET disabled_at = CASE WHEN p_suspended THEN COALESCE(t.disabled_at, now()) ELSE NULL END
     WHERE t.id = p_tenant
    RETURNING * INTO v_row;
    IF v_row.id IS NULL THEN
        RAISE EXCEPTION 'platform: no such tenant' USING ERRCODE = 'P0002';
    END IF;
    RETURN v_row;
END
$$;

-- Agents of a suspended tenant are refused at registration (v4 item 1).
CREATE OR REPLACE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey
    FROM public.machine m
    JOIN public.tenant t ON t.id = m.tenant_id
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
      AND (NOT m.ephemeral OR m.expires_at IS NULL OR m.expires_at > now())
      AND t.disabled_at IS NULL
$$;

-- A session ticket minted before a suspension cannot be brokered after it (v4 item 1): the shared
-- redemption ledger records nothing for a suspended tenant, which signaling treats as "not
-- redeemable" and refuses the connect_request. Signature, columns and grants are unchanged from 0023.
--
-- Serialized with the suspension exactly like issuance (control-plane/issuance_guard.go): the SHARED
-- transaction-level lock on the tenant's issuance key is taken first and held until this redemption
-- commits, and the tenant is read by a LATER statement, so under READ COMMITTED it sees any suspension
-- that committed while we waited. cp_platform_set_suspended holds the EXCLUSIVE lock on the same key,
-- so a redemption either commits before the suspension can, or reads the suspension. (A single SQL
-- statement would read the tenant from a snapshot taken before a concurrent suspension committed.)
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
BEGIN
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('tenant_issuance:' || p_tenant_id::text, 0));
    RETURN QUERY
    WITH reaped AS (
        DELETE FROM public.session_ticket_redemption
        WHERE expires_at < now() - interval '1 hour'
    )
    INSERT INTO public.session_ticket_redemption (tenant_id, session_id, device_id, expires_at)
    SELECT p_tenant_id, p_session_id, p_device_id, p_expires_at
     WHERE EXISTS (SELECT 1 FROM public.tenant t WHERE t.id = p_tenant_id AND t.disabled_at IS NULL)
    ON CONFLICT (tenant_id, session_id) DO NOTHING
    RETURNING *;
END
$$;

REVOKE ALL ON FUNCTION cp_platform_check(uuid, uuid, interval)                    FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_whoami(uuid, uuid)                             FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_list_tenants(uuid, uuid)                       FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_create_tenant(uuid, uuid, text, text, text)    FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_set_suspended(uuid, uuid, uuid, boolean)       FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        -- cp_platform_check is called only from the other functions (definer context).
        REVOKE ALL ON FUNCTION cp_platform_check(uuid, uuid, interval) FROM rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_whoami(uuid, uuid)                          TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_list_tenants(uuid, uuid)                    TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_create_tenant(uuid, uuid, text, text, text) TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_set_suspended(uuid, uuid, uuid, boolean)    TO rmt_app;
    END IF;
END
$$;
