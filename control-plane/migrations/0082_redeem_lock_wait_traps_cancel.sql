-- 0082 — the bounded redemption lock wait also traps query_canceled (docs/66 §2p).
--
-- The release gate's redeem soaks saw the 20 ms lock wait end, about 4 times in 165,000, with SQLSTATE 57014
-- ("canceling statement due to user request") instead of 55P03, with no client cancel sent; the PostgreSQL log
-- places it "while locking tuple ... in relation attended_session". The inner block trapped only
-- lock_not_available, so 57014 escaped and the handler answered 500 for a valid-but-locked code, a distinct answer
-- where every rejection must be one. The trap now covers query_canceled too, but ONLY around the bounded lock wait
-- (the assignment FOR SHARE and the code-row FOR UPDATE): a cancel anywhere else in the function (the machine
-- INSERT, the session UPDATE) still raises, so an operator cancel or a statement_timeout outside the lock section is
-- still an error and not an "invalid code" (Codex review r1 of the Go-side mapping, which was too broad and was
-- reverted). A cancel inside the lock section is the documented transient rejection: nothing has been written yet,
-- the code is not consumed, and a retry succeeds.
--
-- REDEFINED FROM ITS LATEST DEFINITION (0081). The only change is the EXCEPTION clause and its comment.

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
    EXCEPTION WHEN lock_not_available OR query_canceled THEN
        RETURN;                       -- transient (a lock timeout, or a cancel inside the lock wait: 0082), the generic answer
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
