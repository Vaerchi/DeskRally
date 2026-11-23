-- 0070: the final-ack lookup (docs/65 sec. 2b, operator decision 2026-11-01).
--
-- After the MSI uninstall a SYSTEM helper sends the final signed `complete` (or `failed`) acknowledgement and
-- only then deletes its device key. If the control plane applied `complete` (machine -> removed, the D-C9
-- tombstone) but the response was lost, the helper could never learn that: every normal channel goes through
-- device registration, and a removed device is (correctly, absolutely) refused there.
--
-- POST /agent/directives/{id}/final-ack is the one narrow public route for that. Its only credential is the
-- device-key SIGNATURE, verified against the STORED row. The route has no tenant context to pin RLS to (the
-- caller names only the directive id), so this exact-purpose SECURITY DEFINER read resolves the directive
-- to its tenant, device, key fingerprint, state and the machine's stored public key. It:
--   * answers ONLY for kind 'uninstall' (a reinstall directive is indistinguishable from an unknown id);
--   * deliberately does NOT filter on machine.status: a REMOVED machine must still be answerable here,
--     because confirming an applied removal is the whole point. The tombstone itself is untouched - the
--     identity function (0068) and cp_machine_key_removed still refuse the device on every other path;
--   * writes nothing; the apply goes through the ordinary tenant-pinned store (RLS, audit, locks);
--   * returns the database clock so the 7-day window is judged on one clock.
-- Redefinition note: this is a NEW function; no earlier definition exists to drop a guard from.

CREATE OR REPLACE FUNCTION cp_directive_final_ack_target(p_id uuid)
    RETURNS TABLE (tenant_id uuid, device_id text, key_fp text, kind text, state text,
                   updated_at timestamptz, db_now timestamptz, pubkey bytea)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT d.tenant_id, d.device_id, d.key_fp, d.kind, d.state, d.updated_at, now(), m.pubkey
    FROM public.agent_directive d
    JOIN public.machine m ON m.tenant_id = d.tenant_id AND m.id = d.machine_id
    WHERE d.id = p_id
      AND d.kind = 'uninstall'
$$;

REVOKE ALL ON FUNCTION cp_directive_final_ack_target(uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT EXECUTE ON FUNCTION cp_directive_final_ack_target(uuid) TO rmt_app;
    END IF;
END
$$;
