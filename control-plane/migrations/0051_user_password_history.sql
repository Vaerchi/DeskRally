-- Password history — prevent reuse of recent passwords (docs/01 §10).
--
-- Each row is a RETIRED credential hash: a password that was REPLACED when the account owner
-- changed their password. The table stores at most `passwordHistoryDepth` rows per user (the
-- application trims after each insert). The current active credential stays in user_credential;
-- only the retired ones live here.
--
-- RLS design:
--   - tenant_id is the RLS discriminant (same pattern as every other per-tenant table).
--   - FORCE ROW LEVEL SECURITY means the rmt_app role cannot bypass the policy even when it
--     is the table owner (it is not; the table is owned by the schema owner).
--   - The composite index on (tenant_id, user_id, recorded_at DESC) makes the per-user trim
--     and the per-user history lookup both index-only scans.
--
-- Security note: PHC strings are opaque from the outside — there is no way to recover the
-- plaintext from a stored hash. The history check works by running argon2id against the
-- candidate plaintext and comparing the Verify result, exactly as login does. Storing the
-- old hashes is therefore no more sensitive than the current user_credential row.

CREATE TABLE user_password_history (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    phc_hash    TEXT        NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE user_password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_password_history FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON user_password_history
    USING     (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX user_password_history_user_idx
    ON user_password_history (tenant_id, user_id, recorded_at DESC);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, DELETE ON user_password_history TO rmt_app;
    GRANT USAGE, SELECT ON SEQUENCE user_password_history_id_seq TO rmt_app;
  END IF;
END $$;
