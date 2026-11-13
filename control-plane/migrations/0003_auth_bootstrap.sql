-- Control-plane auth bootstrap — the privileged, RLS-bypassing lookups that necessarily run
-- BEFORE a tenant can be pinned on the request connection.
--
-- Why this exists (read the RLS strategy note in 0001_core.sql first):
--   Every tenant-scoped query runs on a connection whose current tenant has been pinned with
--       SELECT set_config('app.current_tenant', '<uuid>', true);
--   and current_setting('app.current_tenant') RAISES when unset, so a query can never run
--   unscoped. But two lookups have a chicken-and-egg problem — they are how the tenant is
--   discovered in the first place, so the GUC cannot yet be set:
--     1. login: resolve a tenant SLUG (from the URL / login form) to its tenant id.
--     2. request auth: resolve an opaque SESSION TOKEN to its row (which carries tenant_id),
--        before we know which tenant the caller belongs to.
--   0001_core.sql already states "tenant provisioning runs as a privileged job that bypasses
--   RLS"; these functions are that same privileged bootstrap surface, kept as narrow as
--   possible: each takes an exact, high-entropy or public key (a slug or a token hash) and
--   returns just enough to then pin the tenant for every subsequent RLS-scoped query.
--
-- SECURITY: these are SECURITY DEFINER, so they execute with the privileges of the OWNER.
-- They bypass RLS only when that owner is a role with the BYPASSRLS attribute (a superuser,
-- or a dedicated bypass role) — apply this migration as such a role, exactly as tenant
-- provisioning is. The application (RLS-enforced) role needs only EXECUTE on them. search_path
-- is pinned on each function (SECURITY DEFINER hardening) so the body cannot be hijacked.

-- Resolve an active tenant's id from its slug. Returns NULL when no such active tenant exists;
-- the caller MUST treat NULL as "unknown tenant" and fail login closed.
CREATE FUNCTION cp_resolve_tenant_by_slug(p_slug text)
    RETURNS uuid
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT id FROM tenant WHERE slug = p_slug AND disabled_at IS NULL;
$$;

-- Resolve a session by the SHA-256 of its bearer token. Returns the whole row (including
-- tenant_id, expiry, and revocation) so the auth layer can enforce them and then pin the
-- tenant for the follow-up user/grant lookups. Expiry/revocation are checked in Go so the
-- caller can distinguish the cases; this function only performs the RLS-bypassing read.
CREATE FUNCTION cp_session_by_token(p_token_hash bytea)
    RETURNS SETOF user_session
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT * FROM user_session WHERE token_hash = p_token_hash LIMIT 1;
$$;

-- Revoke the session for a token hash (logout / forced sign-out). Idempotent.
CREATE FUNCTION cp_session_revoke(p_token_hash bytea)
    RETURNS void
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE user_session SET revoked_at = now()
    WHERE token_hash = p_token_hash AND revoked_at IS NULL;
$$;

-- Refresh last-seen for a session (best-effort activity tracking on each validated request).
CREATE FUNCTION cp_session_touch_last_seen(p_token_hash bytea, p_at timestamptz)
    RETURNS void
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE user_session SET last_seen = p_at WHERE token_hash = p_token_hash;
$$;

-- The application role executes these; it never reads tenant/user_session directly for the
-- pre-tenant bootstrap. (Grant to PUBLIC since the app role name is deployment-specific; the
-- functions are self-limiting — they key on an exact slug or token hash only.)
GRANT EXECUTE ON FUNCTION cp_resolve_tenant_by_slug(text)            TO PUBLIC;
GRANT EXECUTE ON FUNCTION cp_session_by_token(bytea)                 TO PUBLIC;
GRANT EXECUTE ON FUNCTION cp_session_revoke(bytea)                   TO PUBLIC;
GRANT EXECUTE ON FUNCTION cp_session_touch_last_seen(bytea, timestamptz) TO PUBLIC;
