CREATE TABLE machine_lan (
    tenant_id    uuid        NOT NULL,
    machine_id   uuid        NOT NULL,
    mac          macaddr     NOT NULL,
    ipv4_network cidr        NOT NULL,
    gateway_mac  macaddr,
    received_at  timestamptz NOT NULL,
    PRIMARY KEY (machine_id, mac, ipv4_network),
    FOREIGN KEY (tenant_id, machine_id) REFERENCES machine (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX machine_lan_received_at_idx ON machine_lan (received_at);

CREATE TABLE machine_lan_state (
    tenant_id        uuid   NOT NULL,
    machine_id       uuid   PRIMARY KEY,
    epoch            bigint NOT NULL DEFAULT 0,
    epoch_incarnation uuid,
    epoch_generation bigint,
    last_seq         bigint NOT NULL DEFAULT 0,
    last_digest      bytea,
    last_received_at timestamptz,
    FOREIGN KEY (tenant_id, machine_id) REFERENCES machine (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE machine_lan ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_lan FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON machine_lan
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

ALTER TABLE machine_lan_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_lan_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON machine_lan_state
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE TABLE signaling_incarnation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    id        uuid,
    revision  bigint NOT NULL
);
INSERT INTO signaling_incarnation (id, revision) VALUES (NULL, 0);
REVOKE ALL ON signaling_incarnation FROM PUBLIC;

UPDATE role
   SET capabilities = capabilities || ARRAY['wake_machine']
 WHERE tenant_id IS NULL
   AND key IN ('owner', 'admin', 'technician')
   AND NOT ('wake_machine' = ANY(capabilities));

-- Preserve the 0068 lookup predicates and the definer ownership installed by 0076.
DROP FUNCTION cp_machine_identity_by_device_id(text);
CREATE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea, status text, ephemeral boolean)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey, m.status, m.ephemeral
    FROM public.machine m
    JOIN public.tenant t ON t.id = m.tenant_id
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
      AND (NOT m.ephemeral OR m.expires_at IS NULL OR m.expires_at > now())
      AND t.disabled_at IS NULL
      AND m.status <> 'removed'
$$;
ALTER ROUTINE cp_machine_identity_by_device_id(text) OWNER TO rmt_definer;
GRANT EXECUTE ON FUNCTION cp_machine_identity_by_device_id(text) TO PUBLIC;

-- The hourly job has no tenant context. Give its definer reach over expired
-- facts through this count-only function. The ordering watermark is separate.
GRANT SELECT (received_at) ON TABLE machine_lan TO rmt_definer;
GRANT DELETE ON TABLE machine_lan TO rmt_definer;
CREATE FUNCTION cp_purge_stale_lan_facts(p_cutoff timestamptz)
    RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    deleted bigint;
BEGIN
    DELETE FROM public.machine_lan WHERE received_at < p_cutoff;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END
$$;
ALTER ROUTINE cp_purge_stale_lan_facts(timestamptz) OWNER TO rmt_definer;
REVOKE ALL ON FUNCTION cp_purge_stale_lan_facts(timestamptz) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON machine_lan, machine_lan_state TO rmt_app;
        REVOKE ALL ON signaling_incarnation FROM rmt_app;
        GRANT SELECT, UPDATE (id, revision) ON signaling_incarnation TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_purge_stale_lan_facts(timestamptz) TO rmt_app;
    END IF;
END
$$;
