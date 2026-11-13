-- 0057: Console SSO, Entra profile (accepted design v3 + v3.1).
--
-- Connection locks fence configuration changes against issuance and linking. Versions are never
-- reset: changing a connection invalidates every outstanding authority issued against its version.
-- Composite foreign keys matter because foreign-key checks bypass RLS: an in-tenant write must
-- not name another tenant's user, originating session, or attempt. Secrets and PKCE verifiers are
-- encrypted by the store with TOTPCipher; neither plaintext belongs in a database backup.
--
-- Idempotent. Existing app_user / user_session policies and table grants cover their new columns.

CREATE TABLE IF NOT EXISTS tenant_oidc (
    tenant_id          uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    profile            text NOT NULL CHECK (profile IN ('entra')),
    entra_tenant_id    uuid NOT NULL,
    client_id          uuid NOT NULL,
    client_secret_enc  bytea NOT NULL CHECK (octet_length(client_secret_enc) > 0),
    enabled            boolean NOT NULL DEFAULT false,
    trust_entra_mfa    boolean NOT NULL DEFAULT false,
    version            bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    last_test_version  bigint NULL,
    last_test_at       timestamptz NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid NULL,
    CONSTRAINT tenant_oidc_updater_same_tenant FOREIGN KEY (tenant_id, updated_by)
        REFERENCES app_user (tenant_id, id)
);

ALTER TABLE app_user ADD COLUMN IF NOT EXISTS oidc_issuer text NULL;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS oidc_subject text NULL;
ALTER TABLE user_session ADD COLUMN IF NOT EXISTS login_method text NOT NULL DEFAULT 'password';
ALTER TABLE user_session ADD COLUMN IF NOT EXISTS oidc_connection_version bigint NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'app_user_oidc_pair') THEN
        ALTER TABLE app_user ADD CONSTRAINT app_user_oidc_pair
            CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'app_user_oidc_identity_key') THEN
        ALTER TABLE app_user ADD CONSTRAINT app_user_oidc_identity_key
            UNIQUE (tenant_id, oidc_issuer, oidc_subject);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_session_login_method_check') THEN
        ALTER TABLE user_session ADD CONSTRAINT user_session_login_method_check
            CHECK (login_method IN ('password', 'oidc'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_session_oidc_version_check') THEN
        ALTER TABLE user_session ADD CONSTRAINT user_session_oidc_version_check
            CHECK ((login_method = 'oidc') = (oidc_connection_version IS NOT NULL));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_session_tenant_user_id_key') THEN
        ALTER TABLE user_session ADD CONSTRAINT user_session_tenant_user_id_key
            UNIQUE (tenant_id, user_id, id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS oidc_login_attempt (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    key_hash            bytea NOT NULL CHECK (octet_length(key_hash) = 32),
    state_hash          bytea NOT NULL CHECK (octet_length(state_hash) = 32),
    nonce               text NOT NULL CHECK (nonce <> ''),
    code_verifier_enc   bytea NOT NULL CHECK (octet_length(code_verifier_enc) > 0),
    mode                text NOT NULL CHECK (mode IN ('login', 'link', 'test')),
    user_id             uuid NULL,
    session_id          uuid NULL,
    epoch_baseline      timestamptz NULL,
    connection_version  bigint NOT NULL CHECK (connection_version >= 1),
    profile             text NOT NULL CHECK (profile = 'entra'),
    redirect_uri        text NOT NULL,
    return_path         text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    used_at             timestamptz NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, state_hash),
    CHECK ((mode = 'login' AND user_id IS NULL AND session_id IS NULL AND epoch_baseline IS NULL)
        OR (mode IN ('link', 'test') AND user_id IS NOT NULL AND session_id IS NOT NULL)),
    CONSTRAINT oidc_attempt_user_same_tenant FOREIGN KEY (tenant_id, user_id)
        REFERENCES app_user (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oidc_attempt_session_same_user FOREIGN KEY (tenant_id, user_id, session_id)
        REFERENCES user_session (tenant_id, user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oidc_login_attempt_created ON oidc_login_attempt (created_at);

CREATE TABLE IF NOT EXISTS oidc_pending_mfa (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id             uuid NOT NULL,
    attempt_id          uuid NOT NULL,
    issuer              text NOT NULL CHECK (issuer <> ''),
    subject             text NOT NULL CHECK (subject <> ''),
    epoch_baseline      timestamptz NULL,
    connection_version  bigint NOT NULL CHECK (connection_version >= 1),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    used_at             timestamptz NULL,
    UNIQUE (tenant_id, attempt_id),
    CONSTRAINT oidc_pending_user_same_tenant FOREIGN KEY (tenant_id, user_id)
        REFERENCES app_user (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT oidc_pending_attempt_same_tenant FOREIGN KEY (tenant_id, attempt_id)
        REFERENCES oidc_login_attempt (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oidc_pending_mfa_created ON oidc_pending_mfa (created_at);

-- FORCE is required even for table owners; every store operation pins app.current_tenant.
ALTER TABLE tenant_oidc ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_oidc FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_oidc;
CREATE POLICY tenant_isolation ON tenant_oidc
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
ALTER TABLE oidc_login_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_login_attempt FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON oidc_login_attempt;
CREATE POLICY tenant_isolation ON oidc_login_attempt
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
ALTER TABLE oidc_pending_mfa ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_pending_mfa FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON oidc_pending_mfa;
CREATE POLICY tenant_isolation ON oidc_pending_mfa
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_oidc, oidc_login_attempt, oidc_pending_mfa TO rmt_app;
    END IF;
END
$$;
