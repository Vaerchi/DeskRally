-- api_token — a tenant-admin-minted, capability-scoped BEARER credential for PROGRAMMATIC
-- access to the console API (docs/01 §8). Unlike a login session it is long-lived, carries an
-- explicit capability SUBSET chosen at mint (never a role), and belongs to no human user: it is
-- its own principal. Authenticate (apitoken_auth.go) builds a Grant straight from `capabilities`
-- and sets UserID = the token id, so the token survives staff turnover and can never borrow a
-- user's role.
--
-- Same credential hygiene as enrollment/session/credential tokens: only the SHA-256 of the
-- bearer secret is stored, so a database read never yields a usable token. Resolution at auth
-- time is PRE-TENANT — the bearer secret IS the identity, no tenant is pinned yet — so it goes
-- through the SECURITY DEFINER cp_api_token_resolve function, exactly like cp_session_by_token
-- (0003) and cp_enrollment_token_redeem (0007).
--
-- WHAT A TOKEN MAY CARRY is deliberately a SUBSET of the capability set, enforced in Go
-- (apiTokenGrantableCaps): fleet management + reporting only. Interactive-session and
-- user/tenant-administration capabilities are NOT grantable to a token, because those paths key
-- on a real accountable human — session_record.technician_id is a NOT NULL FK to app_user, the
-- password-reset path reloads the actor user, and CapManageTenant would let a token mint further
-- tokens. A token id is not an app_user id, so those would fail anyway; excluding them at mint
-- turns a confusing runtime failure into a clear 400 and keeps the boundary auditable.
CREATE TABLE api_token (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name          text NOT NULL,
    token_hash    bytea NOT NULL,                    -- SHA-256 of the "rmt_api_…" bearer secret
    capabilities  text[] NOT NULL,                   -- the exact capability subset this token carries
    -- created_by is the minting user id, recorded as OPAQUE data (no FK): auth attributes token
    -- actions to the token itself, and the api_token.mint audit event already ties token → minter.
    -- Mirrors the "opaque recorded identifier" posture 0016 gave audit_event.actor_user_id.
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,                       -- NULL = never expires (revocation is the control)
    revoked_at    timestamptz,
    -- Globally unique because auth resolves by hash BEFORE any tenant is known, exactly like the
    -- enrollment/credential token hashes. A 256-bit hash collision across tenants is impossible.
    UNIQUE (token_hash)
);
CREATE INDEX idx_api_token_tenant ON api_token (tenant_id, created_at DESC);

-- =====================================================================================
-- RLS: the same tenant-isolation posture as every other tenant-scoped table (0001 note).
-- Mint/list/revoke run tenant-pinned (withTenant) so the policy confines them; only the
-- SECURITY DEFINER resolver below is allowed to read across tenants, and only by exact hash.
-- =====================================================================================
ALTER TABLE api_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_token
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Guarded grant: the migration also runs in the DB-gated tests, where rmt_app may not exist.
-- UPDATE is needed for revoke (soft: sets revoked_at); DELETE for a future hard purge.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON api_token TO rmt_app;
  END IF;
END $$;

-- Resolve-at-auth-time. STABLE + read-only: API tokens are MULTI-use, so unlike the single-use
-- enrollment/credential tokens this never consumes — it just returns the live row. A row is
-- returned only when the token is live: not revoked, not past its (optional) expiry, and the
-- owning tenant not suspended (disabled_at) — the enrollment/credential lesson (0011, 0020) that
-- a credential minted before a suspension must not outlive it. Every failure — unknown, revoked,
-- expired, suspended tenant — returns NO ROW and is indistinguishable to the caller, which is
-- unauthenticated by construction (the token is the only thing it presented).
--
-- SECURITY DEFINER hardening as in 0003/0007/0020: applied as the RLS-bypassing owner role, with
-- search_path pinned so the body cannot be hijacked, EXECUTE granted to PUBLIC because the app
-- role name is deployment-specific.
CREATE FUNCTION cp_api_token_resolve(p_token_hash bytea)
    RETURNS SETOF api_token
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT a.*
    FROM api_token a
    WHERE a.token_hash = p_token_hash
      AND a.revoked_at IS NULL
      AND (a.expires_at IS NULL OR a.expires_at > now())
      AND EXISTS (SELECT 1 FROM tenant t WHERE t.id = a.tenant_id AND t.disabled_at IS NULL);
$$;
GRANT EXECUTE ON FUNCTION cp_api_token_resolve(bytea) TO PUBLIC;
