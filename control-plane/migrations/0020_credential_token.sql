-- Credential-setup tokens — the FIRST-PASSWORD and ADMIN-RESET path.
--
-- WHY THIS EXISTS. `POST /me/password` (auth.go HandleChangePassword) deliberately answers 409 when
-- the account has no `user_credential` row, and that refusal is correct: with no stored hash there
-- is nothing to verify the caller against, so "set my first password" from a live session would be
-- authorized by the session ALONE — exactly the credential most likely to have been stolen. The
-- result, though, was that an account with no password had no way to ever get one, and an account
-- whose owner forgot theirs had no way to recover: the tenant had a locked door and no key.
--
-- This table is the key: a single-use, expiring, hash-at-rest bearer secret that an administrator
-- mints for a NAMED user and that the user redeems, unauthenticated, to set a password. It is the
-- same shape as `enrollment_token` (0001_core.sql + 0007) for the same reasons —
--
--   * only the SHA-256 lands in the row, so a database read never yields a usable credential;
--   * redemption is necessarily PRE-TENANT (the redeemer has no session — that is the point), so it
--     goes through a SECURITY DEFINER function keyed on the exact hash, like cp_session_by_token
--     (0003) and cp_enrollment_token_redeem (0011);
--   * validate-and-consume is ONE atomic UPDATE, so two racing redemptions cannot both win.
--
-- WHAT A REDEEMED TOKEN DOES NOT DO, and this is the load-bearing part of the design:
--
--   * It does NOT touch `user_totp`. A reset re-provisions the FIRST factor only, so an
--     administrator cannot use one to strip 2FA off an account and walk into it — the account owner's
--     second factor still stands between them. Any future "clear my 2FA" path must therefore be its
--     own audited operation and must NOT be folded in here.
--   * It does NOT mint a session. Whoever redeems the link has proven possession of the link and
--     nothing else; handing them a session would both skip TOTP and reward a stolen link with
--     immediate access. They set a password and then log in like anyone else, through the one place
--     that enforces the second factor.
--
-- A live token is a standing account-takeover primitive for whoever holds it, so it is bounded on
-- every axis the schema can bound it on: single use (`consumed_at`), short-lived (`expires_at`,
-- CredentialTokenTTL = 1h by default), revocable, and superseded — minting a new token for a user
-- revokes that user's outstanding ones IN THE SAME TRANSACTION, so "re-send the link" cannot leave
-- two live links behind.

CREATE TABLE user_credential_token (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenant(id)   ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL,                       -- SHA-256 of the bearer secret; never the secret
    created_by  uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,                          -- NULL until redeemed; single-use
    revoked_at  timestamptz,                          -- superseded by a newer mint, or explicitly cancelled
    -- GLOBALLY unique, not per-tenant: redemption looks the token up by hash alone, before any
    -- tenant is known (that is what makes it the pre-tenant path), so the hash must identify at most
    -- one row across the whole deployment. `UNIQUE (tenant_id, token_hash)` — enrollment_token's
    -- shape, which is only reachable through the same by-hash lookup — would permit two tenants to
    -- hold the same hash and make that lookup ambiguous.
    UNIQUE (token_hash)
);

-- AT MOST ONE LIVE LINK PER USER, enforced by the database rather than only intended by the code.
--
-- The application serializes mints with a per-user advisory lock (PgCredentialTokenStore.Mint), but
-- a lock only orders the writers that take it. Under READ COMMITTED the supersede UPDATE cannot see
-- a concurrent uncommitted INSERT, so without this index two mints racing for the same user leave
-- TWO live account-takeover links behind while the administrator believes there is one. This is the
-- backstop that turns that into a constraint violation instead — the same role
-- uq_backstage_audit_tenant_ingest plays for the ingest counter in 0019.
--
-- The predicate is (not consumed, not revoked) and deliberately says nothing about `expires_at`: an
-- index predicate must be IMMUTABLE, and `expires_at > now()` is not — it would change truth value
-- with the clock, which no index can represent. Expired-but-unredeemed rows therefore remain in the
-- index and continue to occupy their user's one live slot until superseded or revoked. That is the
-- conservative direction (a mint supersedes them explicitly) and it is why the redeem functions
-- below check expiry themselves rather than relying on this predicate.
CREATE UNIQUE INDEX uq_user_credential_token_one_live
    ON user_credential_token (tenant_id, user_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

-- =====================================================================================
-- Row-Level Security — the same contract as every tenant-scoped table (0001_core.sql).
-- The management-plane operations (mint, revoke) run tenant-pinned and are confined by this
-- policy; redemption cannot be, which is precisely why it runs through the SECURITY DEFINER
-- functions below instead of touching the table directly.
-- =====================================================================================
ALTER TABLE user_credential_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credential_token FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON user_credential_token
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- =====================================================================================
-- The pre-tenant redemption pair. SECURITY DEFINER + pinned search_path, exactly as 0003 /
-- 0006 / 0011 do it.
--
-- WHY TWO FUNCTIONS RATHER THAN ONE. Consuming the token is irreversible, and the password the
-- redeemer supplies still has to clear the complexity policy — which cannot be evaluated without
-- the account's own email/display name, because the policy refuses a password that echoes them.
-- A single consume-then-validate would therefore burn the user's one-shot link every time they
-- typed a password the policy rejects, and the only remedy would be to ask an administrator for
-- another link. `peek` resolves the token to its user WITHOUT consuming it so the policy can be
-- applied first; `consume` is still the atomic gate that decides whether the write happens, and it
-- re-evaluates every condition, so nothing is trusted across the gap between the two calls.
--
-- Both apply the SAME validity predicate, and both extend it beyond the token's own columns:
--
--   * the owning tenant must not be suspended — the lesson of 0011, where an enrollment token
--     minted before a suspension kept admitting new agents into a tenant nobody could see. A
--     credential token is the same kind of thing: it admits a new credential.
--   * the target user must not be disabled — otherwise disabling an account would leave any
--     outstanding link as a working back door into it.
--
-- Every failure — unknown, expired, consumed, revoked, disabled user, suspended tenant — returns
-- NO ROW and is indistinguishable to the caller, which is unauthenticated by construction.
-- =====================================================================================
CREATE FUNCTION cp_credential_token_peek(p_token_hash bytea)
    RETURNS SETOF user_credential_token
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT ct.*
    FROM user_credential_token ct
    WHERE ct.token_hash  = p_token_hash
      AND ct.consumed_at IS NULL
      AND ct.revoked_at  IS NULL
      AND ct.expires_at  > now()
      AND EXISTS (SELECT 1 FROM app_user u WHERE u.id = ct.user_id   AND u.disabled_at IS NULL)
      AND EXISTS (SELECT 1 FROM tenant   t WHERE t.id = ct.tenant_id AND t.disabled_at IS NULL);
$$;

-- The single atomic validate-and-consume. Concurrent redemptions of the same token serialize on
-- the row lock and re-evaluate `consumed_at IS NULL`, so exactly one wins and the loser is
-- indistinguishable from an invalid token — no read-then-write window, mirroring
-- cp_enrollment_token_redeem.
CREATE FUNCTION cp_credential_token_consume(p_token_hash bytea)
    RETURNS SETOF user_credential_token
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE user_credential_token ct
    SET consumed_at = now()
    WHERE ct.token_hash  = p_token_hash
      AND ct.consumed_at IS NULL
      AND ct.revoked_at  IS NULL
      AND ct.expires_at  > now()
      AND EXISTS (SELECT 1 FROM app_user u WHERE u.id = ct.user_id   AND u.disabled_at IS NULL)
      AND EXISTS (SELECT 1 FROM tenant   t WHERE t.id = ct.tenant_id AND t.disabled_at IS NULL)
    RETURNING ct.*;
$$;

-- Same grant posture as every other cp_* bootstrap function: EXECUTE to PUBLIC, because the
-- application role's name is deployment-specific. Both are self-limiting — they key on an exact
-- 256-bit token hash and return only that row.
GRANT EXECUTE ON FUNCTION cp_credential_token_peek(bytea)    TO PUBLIC;
GRANT EXECUTE ON FUNCTION cp_credential_token_consume(bytea) TO PUBLIC;

COMMENT ON TABLE user_credential_token IS
    'Single-use, expiring bearer secrets that let a named user set their FIRST password or replace '
    'a forgotten one. Only the SHA-256 is stored. Redeeming one NEVER touches user_totp and NEVER '
    'issues a session, so it re-provisions the FIRST factor only: it cannot strip an account''s '
    'second factor, and an account that has one is still protected by it afterwards. It is NOT a '
    'claim that the link cannot lead to access — for an account with no second factor, whoever '
    'holds the link sets the password and can then log in, which is what the endpoint is FOR. What '
    'bounds that is who may mint one: CapManageUsers, a re-proof of the minter''s own password, no '
    'self-targeting, and a per-(capability, group) subset rule against the target''s authority.';
