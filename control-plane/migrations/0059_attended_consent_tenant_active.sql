-- 0059: a guest cannot ACCEPT an attended session once its tenant is suspended (docs/37 D3).
--
-- 0021 made the initial redemption refuse a suspended tenant, but a token redeemed BEFORE the
-- suspension could still be consented afterwards: cp_attended_consent matched on the token alone.
-- The suspended tenant's technicians cannot sign in to connect, so this opened no access, but it left
-- the guest-side state machine advancing for a tenant that is switched off.
--
-- The policy docs/37 asked for, deliberately narrow:
--   * ACCEPT requires an active tenant;
--   * DECLINE always works — refusing support must never be blocked;
--   * status (cp_attended_by_token) is unchanged, so a guest can still learn the session ended.
-- Same signature, so CREATE OR REPLACE keeps the PUBLIC execute grant from 0013.
CREATE OR REPLACE FUNCTION cp_attended_consent(p_token_hash bytea, p_accept boolean, p_consent_user text)
    RETURNS SETOF attended_session
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE attended_session
    SET state        = CASE WHEN p_accept THEN 'consented' ELSE 'declined' END,
        consent_user = CASE WHEN p_accept THEN p_consent_user ELSE consent_user END,
        consented_at = CASE WHEN p_accept THEN now() ELSE consented_at END
    WHERE token_hash = p_token_hash AND state = 'redeemed'
      AND (NOT p_accept OR EXISTS (
            SELECT 1 FROM tenant t WHERE t.id = attended_session.tenant_id AND t.disabled_at IS NULL))
    RETURNING *;
$$;
