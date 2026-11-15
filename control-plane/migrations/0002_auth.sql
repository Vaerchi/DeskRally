-- Control-plane local authentication — credentials, TOTP 2FA, and server-side sessions.
--
-- Extends migrations/0001_core.sql. Local (username/password) login is the first-class auth
-- path for self-hosted and the fallback for SaaS; OIDC/Zitadel federation (app_user.external_subject)
-- lands later and coexists — a user may have a local credential, a federated identity, or both.
--
-- Every table here is tenant-scoped and obeys the SAME Row-Level Security contract as
-- 0001_core.sql: tenant_id on every row, ENABLE + FORCE RLS, and a tenant_isolation policy of
--     USING (tenant_id = current_setting('app.current_tenant')::uuid)
-- so a forgotten WHERE clause can never leak another MSP's credentials or sessions. Read the
-- RLS strategy note at the top of 0001_core.sql before touching anything below.
--
-- Secrets discipline (docs/03-roadmap.md risk table — CVE-2024-1709 is the cautionary tale):
--   * user_credential stores only an argon2id PHC hash — never a plaintext password.
--   * user_session stores only the SHA-256 of the bearer token (like enrollment_token) — the
--     plaintext token is shown to the client once at login and is otherwise unrecoverable.
--   * user_totp stores the shared secret; it is a credential. The application layer should
--     encrypt it at rest (envelope/KMS) before insert. This migration keeps it as bytea and
--     does not itself provide encryption.

-- -------------------------------------------------------------------------------------
-- user_credential — a user's local password. One row per user (1:1 with app_user). Users
-- authenticated purely via OIDC have no row here.
-- -------------------------------------------------------------------------------------
CREATE TABLE user_credential (
    user_id       uuid PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    tenant_id     uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    password_hash text NOT NULL,                 -- argon2id PHC string ($argon2id$v=19$...)
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Keeps the credential in the same tenant as its user; RLS + this FK close the write hole.
    UNIQUE (tenant_id, user_id)
);

-- -------------------------------------------------------------------------------------
-- user_totp — a user's TOTP (RFC 6238) 2FA enrollment. One row per user. `confirmed_at` is
-- NULL until the user proves possession with a valid code; login only enforces confirmed
-- enrollments, so a half-finished enrollment never locks anyone out.
-- -------------------------------------------------------------------------------------
CREATE TABLE user_totp (
    user_id       uuid PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    tenant_id     uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    secret        bytea NOT NULL,                -- base32 shared secret; encrypt at rest (app layer)
    algorithm     text NOT NULL DEFAULT 'SHA1',
    digits        int  NOT NULL DEFAULT 6,
    period_secs   int  NOT NULL DEFAULT 30,
    created_at    timestamptz NOT NULL DEFAULT now(),
    confirmed_at  timestamptz,                   -- NULL until first valid code verified
    UNIQUE (tenant_id, user_id)
);

-- -------------------------------------------------------------------------------------
-- user_session — a server-side login session. Only the token hash is stored; expiry and
-- revocation are checked on every request, so access can be cut immediately (unlike a
-- stateless JWT). Mirrors enrollment_token's hash-only, expiring, revocable shape.
-- -------------------------------------------------------------------------------------
CREATE TABLE user_session (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL,                 -- SHA-256 of the opaque bearer token
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen    timestamptz,
    revoked_at   timestamptz,
    source_ip    inet,
    user_agent   text,
    UNIQUE (tenant_id, token_hash)
);
CREATE INDEX idx_user_session_user    ON user_session (tenant_id, user_id);
CREATE INDEX idx_user_session_expires ON user_session (expires_at);

-- =====================================================================================
-- Enable + FORCE Row-Level Security and attach the tenant-isolation policy — identical
-- contract to every table in 0001_core.sql.
-- =====================================================================================
ALTER TABLE user_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credential FORCE  ROW LEVEL SECURITY;
ALTER TABLE user_totp       ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_totp       FORCE  ROW LEVEL SECURITY;
ALTER TABLE user_session    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_session    FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON user_credential
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON user_totp
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON user_session
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
