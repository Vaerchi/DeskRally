-- Attended (on-demand) redemption must respect tenant suspension.
--
-- This applies 0011's rule to the one redeem path that never got it. 0011 said it plainly:
--
--     "Suspension has to mean the same thing on every path that admits a new principal."
--
-- and 0020_credential_token.sql cites it as settled ("the lesson of 0011"). But 0013's
-- `cp_attended_redeem` — written AFTER 0011 — checks only the code: pending, unexpired, and that is
-- all. It then INSERTs a `machine` row with a pinned pubkey and hands back a device id, which is
-- exactly "admitting a new principal": the rest of the system treats that device as legitimate, the
-- signaling server will authenticate it (RMTAGENTAUTHv1), and a technician can be brokered to it.
--
-- So an attended code minted before a suspension kept working after it. Suspension already locks the
-- tenant's humans out of the console (cp_resolve_tenant_by_slug, 0003) and already blocks unattended
-- enrollment (0011) — this was the remaining door, and it is the one that needs no console session
-- at all, only a code someone was given earlier.
--
-- The check goes in the same statement that takes the row lock, so a suspension landing concurrently
-- with a redemption serializes on that lock exactly like every other condition: either the SELECT
-- sees an active tenant and the redemption proceeds, or it matches nothing and fails closed. It can
-- never half-happen — no machine row without a valid session transition, and no transition without a
-- machine row.
--
-- The failure stays UNDIFFERENTIATED (an empty result, which the Go handler maps to the generic
-- ErrAttendedInvalid → 403 "invalid attended code"), matching every other failure here. A guest must
-- not be able to tell "wrong code" from "right code, suspended tenant": that distinction leaks
-- whether a code was ever valid, and the guest can do nothing with either answer.
--
-- CREATE OR REPLACE, so the GRANT from 0013 is preserved; it is restated below for a harness that
-- applies this file without 0013 having run in the same session, matching 0011's precedent.

CREATE OR REPLACE FUNCTION cp_attended_redeem(p_code_hash bytea, p_pubkey bytea, p_name text,
                                              p_device_id text, p_token_hash bytea, p_machine_expires timestamptz)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE s attended_session%ROWTYPE;
BEGIN
    SELECT * INTO s FROM attended_session a
        WHERE a.code_hash = p_code_hash AND a.state = 'pending' AND now() < a.expires_at
          AND EXISTS (
              SELECT 1 FROM tenant t
              WHERE t.id = a.tenant_id
                AND t.disabled_at IS NULL
          )
        FOR UPDATE OF a;
    IF NOT FOUND THEN
        RETURN;                       -- caller maps empty → ErrAttendedInvalid (generic)
    END IF;
    INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, ephemeral, expires_at)
        VALUES (s.tenant_id, p_device_id, s.group_id, p_name, p_pubkey, true, p_machine_expires);
    UPDATE attended_session
        SET state = 'redeemed', device_id = p_device_id, token_hash = p_token_hash, redeemed_at = now()
        WHERE id = s.id;
    RETURN QUERY SELECT s.id, s.tenant_id, s.group_id, p_device_id;
END $$;

GRANT EXECUTE ON FUNCTION cp_attended_redeem(bytea, bytea, text, text, bytea, timestamptz) TO PUBLIC;
