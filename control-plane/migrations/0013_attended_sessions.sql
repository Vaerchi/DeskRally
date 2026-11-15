-- Attended (on-demand) support sessions — docs/12-attended-sessions-contract.md.
--
-- An attended session is a CONSENT-GATED, TIME-BOXED, EPHEMERAL enrollment. It reuses the existing
-- authorization gates unchanged: the guest is an ordinary agent whose ephemeral Ed25519 key is
-- pinned in `machine` and resolved via cp_machine_identity_by_device_id (RMTAGENTAUTHv1), and the
-- technician presents an ordinary RMTTICKETv1 session ticket. So this migration adds NO new signed
-- preimage — the one-time code is a hashed bearer secret, like an enrollment token.

-- 1. `machine` gains an ephemeral flavour. Permanent (unattended) machines keep ephemeral=false,
--    expires_at=NULL and are untouched by the defaults. An attended guest is ephemeral=true with a
--    short expiry, hidden from the fleet listing and reaped after the session.
ALTER TABLE machine ADD COLUMN ephemeral  boolean     NOT NULL DEFAULT false;
ALTER TABLE machine ADD COLUMN expires_at timestamptz NULL;
CREATE INDEX machine_ephemeral_expiry_idx ON machine (expires_at) WHERE ephemeral;

-- 2. Identity resolution must REFUSE an expired ephemeral machine, so the signaling server will not
--    authenticate a guest whose attended session has lapsed. Permanent machines (ephemeral=false)
--    are unaffected. This CREATE OR REPLACE is byte-compatible with 0010's signature; it only adds
--    the expiry predicate. (In production migrations apply in order, so 0013 wins over 0010.)
CREATE OR REPLACE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey
    FROM machine m
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
      AND (NOT m.ephemeral OR m.expires_at IS NULL OR m.expires_at > now())
$$;

-- 3. The attended session record. code_hash / promote_token are bearer material handled like
--    enrollment tokens: the code is SHA-256'd at rest and never returned after mint; the promote
--    token (a normal enrollment-token plaintext) is stashed only between /promote and the guest's
--    next /status poll. token_hash authenticates the guest's own callbacks (consent/status/end).
CREATE TABLE attended_session (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL REFERENCES tenant(id),
    group_id      uuid NOT NULL,
    technician_id uuid NOT NULL,
    code_hash     bytea NOT NULL,
    token_hash    bytea NULL,
    device_id     text  NULL,
    state         text  NOT NULL DEFAULT 'pending'
                  CHECK (state IN ('pending','redeemed','consented','declined','active','ended','expired')),
    reason        text  NOT NULL DEFAULT '',
    consent_user  text  NOT NULL DEFAULT '',
    promote_token text  NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    redeemed_at   timestamptz NULL,
    consented_at  timestamptz NULL,
    ended_at      timestamptz NULL
);
CREATE UNIQUE INDEX attended_session_code_hash_idx ON attended_session (code_hash);
CREATE INDEX attended_session_tenant_idx ON attended_session (tenant_id, created_at DESC);
CREATE INDEX attended_session_token_idx ON attended_session (token_hash) WHERE token_hash IS NOT NULL;

ALTER TABLE attended_session ENABLE ROW LEVEL SECURITY;
-- Tenant isolation, same shape as every other tenant-scoped table (0001). The guest-facing paths
-- (redeem/consent/status) run PRE-TENANT via SECURITY DEFINER functions below, so they bypass this
-- deliberately; the technician-facing reads/writes go through RLS like sessions and enrollment.
CREATE POLICY attended_session_tenant_isolation ON attended_session
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
GRANT SELECT, INSERT, UPDATE ON attended_session TO rmt_app;
GRANT SELECT, INSERT, UPDATE ON machine TO rmt_app;  -- idempotent-safe; ephemeral machines are machine rows

-- 4. Redemption — PRE-TENANT and atomic, mirroring cp_enrollment_token_redeem (0007): the code is
--    the only authorization, so the tenant is unknown at this moment. One transaction validates the
--    code (pending + unexpired), mints the ephemeral machine (device_id chosen by the CALLER, which
--    is the server-side handler — never the redeemer), pins the guest pubkey, records the guest's
--    attend-token hash, and advances the session to 'redeemed'. An invalid code matches no row and
--    the function returns nothing; the Go handler fails closed with one generic error.
CREATE FUNCTION cp_attended_redeem(p_code_hash bytea, p_pubkey bytea, p_name text,
                                   p_device_id text, p_token_hash bytea, p_machine_expires timestamptz)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
DECLARE s attended_session%ROWTYPE;
BEGIN
    SELECT * INTO s FROM attended_session
        WHERE code_hash = p_code_hash AND state = 'pending' AND now() < expires_at
        FOR UPDATE;
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

-- 5. Guest callback resolution by attend-token hash — also PRE-TENANT (the guest is not a tenant
--    principal; it holds only its attend token). Returns the row the Go handler needs to record
--    consent, hand over a promote token, or report end. Cross-tenant-blind by construction: the
--    token hash is a 256-bit secret, so it identifies exactly one session.
CREATE FUNCTION cp_attended_by_token(p_token_hash bytea)
    RETURNS SETOF attended_session
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT * FROM attended_session WHERE token_hash = p_token_hash
$$;
GRANT EXECUTE ON FUNCTION cp_attended_by_token(bytea) TO PUBLIC;

-- 6. Consent / decline by attend token — atomic transition out of 'redeemed'.
CREATE FUNCTION cp_attended_consent(p_token_hash bytea, p_accept boolean, p_consent_user text)
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
    RETURNING *;
$$;
GRANT EXECUTE ON FUNCTION cp_attended_consent(bytea, boolean, text) TO PUBLIC;
