-- tenant_branding — per-tenant white-label settings (docs/01 §9): a product name shown in the
-- console title/header and an accent colour applied to the console theme. One row per tenant (the
-- tenant_id is the PK); an absent row means "use the product defaults". Kept in its own table rather
-- than columns on `tenant` so the core tenant row stays lean and branding is optional.
--
-- Same tenant-isolation posture as every other tenant-scoped table (0001 note): mutations run
-- tenant-pinned (withTenant), and the RLS policy confines read + write to the caller's tenant.
CREATE TABLE tenant_branding (
    tenant_id     uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    product_name  text NOT NULL DEFAULT '',   -- empty = the default product name
    accent_color  text NOT NULL DEFAULT '',   -- empty = the default accent; else a #rrggbb hex
    updated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_branding
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_branding TO rmt_app;
  END IF;
END $$;
