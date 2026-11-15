-- 0081 — the redemption row-lock wait drops from 50 ms to 20 ms (docs/66 2b.5; release gate step 4 finding).
--
-- The docs/66 release gate measured the "concurrent loser" class (a code whose row another transaction holds)
-- against every other rejected class. With a 50 ms lock_timeout the loser's lookup alone took 57-65 ms (tails near
-- 120 ms under concurrency), longer than the 60 ms common rejection floor, so that class answered measurably later
-- (p95 +30 ms) than "no such code". The doc's rule is that the floor exceeds the slowest rejection class, and
-- floor + jitter may not exceed 100 ms (2b.4), so the wait must shrink instead. 20 ms keeps the purpose of a
-- bounded wait (a guest whose code is briefly held by an unrelated write still usually succeeds; SKIP LOCKED would
-- refuse them) while leaving the lookup well under the floor on Linux and on Windows' coarser timers.
--
-- REDEFINED FROM ITS LATEST DEFINITION (0071; 0076 only changed the owner, and CREATE OR REPLACE keeps the owner
-- and grants). The only changes are the timeout value and the "capped at" comment.

-- 4. Scoped redemption (docs/66 2a.1, 2b.4, 2b.5)
-- ---------------------------------------------------------------------------------------------------
-- p_unscoped is decided in Go from CONFIGURATION ONLY (the default host and the explicit legacy list). When it
-- is false the code must belong to the tenant that CURRENTLY holds p_host as an ACTIVE assignment; the check is
-- part of the same statement that takes the row lock, so release / reassignment / suspension serialize with the
-- redemption exactly like every other condition. No active assignment, a pending or released one, a foreign
-- tenant's code, an expired or spent code, a suspended tenant and a lock timeout ALL produce the same empty
-- result (the caller's generic invalid-code answer).
--
-- Bounded lock wait (2b.5): SKIP LOCKED is NOT used (it would turn a valid code into "invalid" whenever any
-- unrelated transaction held the row). The wait is capped at 20 ms (0081; was 50 ms); a timeout is the same generic rejection and
-- is documented as transient.
CREATE OR REPLACE FUNCTION cp_attended_redeem_scoped(p_code_hash bytea, p_pubkey bytea, p_name text,
                                                     p_device_id text, p_token_hash bytea, p_machine_expires timestamptz,
                                                     p_host text, p_unscoped boolean)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    s attended_session%ROWTYPE;
    v_prev_timeout text := current_setting('lock_timeout');
    v_host_tenant  uuid;
BEGIN
    BEGIN
        PERFORM set_config('lock_timeout', '20', true);
        -- LOCK ORDER: the ACTIVE ASSIGNMENT first (FOR SHARE, which conflicts with release's UPDATE), then the code
        -- row, both held until this transaction ends (through consumption). A release therefore either committed
        -- before we looked (we see state <> 'active' after re-evaluation of the locked row and refuse) or waits
        -- for this redemption to finish. It can never commit between our check and the consumption of the code.
        IF NOT p_unscoped THEN
            SELECT h.tenant_id INTO v_host_tenant FROM tenant_hostname_assignment h
                WHERE h.host = p_host AND h.state = 'active'
                FOR SHARE OF h;
            IF v_host_tenant IS NULL THEN
                PERFORM set_config('lock_timeout', v_prev_timeout, true);
                RETURN;
            END IF;
        END IF;
        SELECT * INTO s FROM attended_session a
            WHERE a.code_hash = p_code_hash AND a.state = 'pending' AND now() < a.expires_at
              AND EXISTS (
                  SELECT 1 FROM tenant t
                  WHERE t.id = a.tenant_id
                    AND t.disabled_at IS NULL
              )
              AND (p_unscoped OR a.tenant_id = v_host_tenant)
            FOR UPDATE OF a;
    EXCEPTION WHEN lock_not_available THEN
        RETURN;                       -- transient, and the same generic answer as any invalid code
    END;
    PERFORM set_config('lock_timeout', v_prev_timeout, true);
    IF s.id IS NULL THEN                -- (not FOUND: PERFORM above reset it)
        RETURN;                       -- caller maps empty -> ErrAttendedInvalid (generic)
    END IF;
    INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, ephemeral, expires_at)
        VALUES (s.tenant_id, p_device_id, s.group_id, p_name, p_pubkey, true, p_machine_expires);
    UPDATE attended_session
        SET state = 'redeemed', device_id = p_device_id, token_hash = p_token_hash, redeemed_at = now()
        WHERE id = s.id;
    RETURN QUERY SELECT s.id, s.tenant_id, s.group_id, p_device_id;
END $$;
