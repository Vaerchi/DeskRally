CREATE TABLE machine_field (
    tenant_id uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    key text NOT NULL,
    id uuid NOT NULL UNIQUE,
    label text NOT NULL,
    type text NOT NULL CHECK (type IN ('text', 'number', 'date', 'choice', 'boolean')),
    choices text[],
    position int NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (CASE WHEN type = 'choice'
                THEN choices IS NOT NULL AND cardinality(choices) BETWEEN 1 AND 64
                ELSE choices IS NULL END),
    PRIMARY KEY (tenant_id, key)
);

CREATE TABLE machine_field_order (
    tenant_id uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    revision bigint NOT NULL
);

ALTER TABLE machine_field ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_field FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON machine_field
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

ALTER TABLE machine_field_order ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_field_order FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON machine_field_order
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON machine_field, machine_field_order TO rmt_app;
    END IF;
END
$$;
