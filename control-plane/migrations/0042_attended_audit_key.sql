-- Keep the redemption-pinned public key after ephemeral machine cleanup, so a late
-- final audit batch can still be authenticated. The guest supplies this key at redemption.
ALTER TABLE attended_session ADD COLUMN IF NOT EXISTS agent_pubkey text NOT NULL DEFAULT '';
UPDATE attended_session a SET agent_pubkey = encode(m.pubkey, 'hex')
FROM machine m WHERE a.device_id = m.device_id AND a.tenant_id = m.tenant_id AND a.agent_pubkey = '' AND m.pubkey IS NOT NULL;

CREATE OR REPLACE FUNCTION cp_snapshot_attended_audit_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.device_id IS DISTINCT FROM OLD.device_id AND NEW.device_id IS NOT NULL THEN
        SELECT encode(m.pubkey, 'hex') INTO NEW.agent_pubkey
        FROM public.machine m WHERE m.device_id = NEW.device_id AND m.tenant_id = NEW.tenant_id;
        IF NEW.agent_pubkey IS NULL THEN
            RAISE EXCEPTION 'attended redemption has no pinned machine key';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION cp_snapshot_attended_audit_key() FROM PUBLIC;
DROP TRIGGER IF EXISTS attended_audit_key_snapshot ON attended_session;
CREATE TRIGGER attended_audit_key_snapshot BEFORE UPDATE OF device_id ON attended_session
FOR EACH ROW EXECUTE FUNCTION cp_snapshot_attended_audit_key();
