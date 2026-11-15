-- tenant_session_policy — per-tenant concurrency limits (docs/01 §5: "concurrent-license / seat
-- metering"). One row per tenant (tenant_id is the PK); an absent row — or a zero limit — means
-- UNLIMITED. Kept in its own table (like tenant_branding/0028 and tenant_ip_allowlist/0025) rather
-- than a column on `tenant`, so the core tenant row stays lean, the setting is optional, and a
-- DEV/first-use tenant can acquire a policy by UPSERT without its `tenant` row having to exist.
--
-- max_concurrent_sessions caps how many session_record rows a tenant may hold OPEN (ended_at IS NULL)
-- at once. 0 = unlimited (the default); enforcement is at POST /sessions, serialized per tenant by a
-- pg_advisory_xact_lock so a burst of concurrent starts cannot each read "under the limit" and all win.
--
-- Same tenant-isolation posture as every other tenant-scoped table (0001 note): mutations run
-- tenant-pinned (withTenant), and the RLS policy confines read + write to the caller's tenant.
CREATE TABLE tenant_session_policy (
    tenant_id                uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    max_concurrent_sessions  integer NOT NULL DEFAULT 0
                                 CHECK (max_concurrent_sessions >= 0),
    updated_at               timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_session_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_session_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_session_policy
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_session_policy TO rmt_app;
  END IF;
END $$;
