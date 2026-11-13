-- Session-ticket redemption ledger — makes an RMTTICKETv1 session ticket single-use across the
-- WHOLE deployment, not merely within one signaling process.
--
-- WHY THIS EXISTS. server/signaling/ticket.go already refuses a replayed ticket, but it does so
-- from `spentTickets`, an in-memory map owned by one process. Two consequences, both measured
-- before this file was written and now pinned by
-- server/signaling/ticketredeem_test.go TestBrokerRejectsTicketRedeemedAtAnotherInstance:
--
--   * TWO SIGNALING REPLICAS behind a load balancer each keep their own map, so a captured ticket
--     brokers once per replica;
--   * a RESTART empties the map, so a captured ticket brokers again on the same address.
--
-- A ticket is a bearer credential with a ~2-minute TTL (sessionTicketTTL), so the exposure is
-- bounded — this is a LOW-severity replay window, not an authentication hole — but "single-use"
-- was being claimed and was only true per process. This table is where the claim becomes true:
-- the issuer of the ticket is also the keeper of its one redemption.
--
-- WHAT THE KEY IS, AND WHAT IT IS NOT. `(tenant_id, session_id)` mirrors the ticket's own binding:
-- claims.tenant_id + claims.session_id, both covered by the Ed25519 signature the signaling server
-- verifies before it ever calls this. There is deliberately NO foreign key to `session_record`:
-- `claims.session_id` names a `session_record` for an unattended session (http.go handleStartSession)
-- but an `attended_session` for an on-demand one (http_attended.go handleConnectAttended), and a FK
-- to either would refuse to record half the fleet's redemptions. The FK to `tenant` is safe because
-- both paths mint tickets for a real tenant.
--
-- SEE ALSO the FAILURE POSTURE, which lives with the caller (server/signaling/ticketredeem.go):
-- signaling proceeds on its LOCAL verdict when this ledger is unreachable, and only a definitive
-- "already redeemed" refuses a broker. That is the opposite of the device-identity lookup's
-- fail-closed posture, and the reasoning for the asymmetry is written into that file's header.

CREATE TABLE session_ticket_redemption (
    tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    session_id  uuid        NOT NULL,
    -- The device the redeemed ticket named. Not part of the key — the ticket is single-use whatever
    -- it targets — but an operator looking at a refused replay needs to know which machine somebody
    -- was trying to reach, and the row is the only place that survives the signaling log.
    device_id   text        NOT NULL DEFAULT '',
    redeemed_at timestamptz NOT NULL DEFAULT now(),
    -- The TICKET's own exp_ms. It is what makes the row disposable: once past it, verifyTicket
    -- refuses the ticket on expiry alone, so remembering the redemption buys nothing.
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);

-- Supports the opportunistic reap inside cp_session_ticket_redeem below.
CREATE INDEX session_ticket_redemption_expiry_idx ON session_ticket_redemption (expires_at);

-- =====================================================================================
-- Row-Level Security — the same contract as every other tenant-scoped table (0001_core.sql).
-- Redemption itself cannot be confined by it (it runs pre-tenant, from a service-token-gated
-- internal route), which is exactly why it goes through the SECURITY DEFINER function below
-- rather than touching the table directly. The policy governs every OTHER reader: a future
-- console view, an operator query as rmt_app, anything that arrives through the binder.
-- =====================================================================================
ALTER TABLE session_ticket_redemption ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_ticket_redemption FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON session_ticket_redemption
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Explicit grant (belt-and-suspenders over 0005's default privileges), guarded so this file also
-- applies to a schema without the role — and re-runnable, since resetSchema drops the table with
-- its per-object grants. No UPDATE: a redemption is a recorded fact, never amended. DELETE is for
-- expiry only.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, DELETE ON session_ticket_redemption TO rmt_app;
    END IF;
END
$$;

-- =====================================================================================
-- The redeem function. SECURITY DEFINER + pinned search_path, exactly as 0003 / 0007 / 0020 do it:
-- the caller is the signaling server, which holds no tenant principal (it belongs to no tenant), so
-- no `app.current_tenant` is pinned and the policy above cannot be satisfied.
--
-- ATOMICITY IS THE WHOLE POINT, and it is why this is ONE statement. A SELECT-then-INSERT would be
-- wrong even inside a single transaction: under READ COMMITTED the SELECT cannot see a concurrent
-- UNCOMMITTED insert, so two replicas redeeming the same ticket at the same instant would both read
-- "not redeemed" and both broker — reproducing, at a shorter window, the very defect this table
-- exists to close. `INSERT ... ON CONFLICT DO NOTHING RETURNING` makes check-and-record a single
-- indivisible step: the loser of the race conflicts on the primary key, inserts nothing, and returns
-- NO ROW. That empty result is the definitive "already redeemed" the caller maps to a refusal.
-- (Same trap, same shape as uq_user_credential_token_one_live in 0020.)
--
-- THE REAP. This deployment has no background job (see 0015's note), so expired rows are cleared
-- opportunistically, in the same statement — a data-modifying CTE always runs to completion,
-- exactly once, independently of the main query. The window is `expires_at < now() - 1 hour`, far
-- beyond the 2-minute ticket TTL, and the generosity is load-bearing rather than lazy: it
-- guarantees the reaped set can never intersect a ticket that could still verify, so the DELETE can
-- never race the INSERT into deleting the very row a live replay should have conflicted with. This
-- is the same "an entry can be dropped once the ticket it names is expired" argument that lets the
-- in-memory spentTickets map prune on every consume.
-- =====================================================================================
CREATE FUNCTION cp_session_ticket_redeem(
        p_tenant_id  uuid,
        p_session_id uuid,
        p_device_id  text,
        p_expires_at timestamptz)
    RETURNS SETOF session_ticket_redemption
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    WITH reaped AS (
        DELETE FROM session_ticket_redemption
        WHERE expires_at < now() - interval '1 hour'
    )
    INSERT INTO session_ticket_redemption (tenant_id, session_id, device_id, expires_at)
    VALUES (p_tenant_id, p_session_id, p_device_id, p_expires_at)
    ON CONFLICT (tenant_id, session_id) DO NOTHING
    RETURNING *;
$$;

-- Same grant posture as every other cp_* function: EXECUTE to PUBLIC, because the application
-- role's name is deployment-specific. Self-limiting — it records one exact (tenant, session) pair
-- and returns only that row.
GRANT EXECUTE ON FUNCTION cp_session_ticket_redeem(uuid, uuid, text, timestamptz) TO PUBLIC;

COMMENT ON TABLE session_ticket_redemption IS
    'One row per REDEEMED session ticket: the shared ledger that makes an RMTTICKETv1 ticket '
    'single-use across every signaling replica and across restarts, which a per-process map cannot. '
    'A row here is NOT an authorization record — the ticket''s signature, tenant binding, device '
    'binding and expiry are all checked by the signaling server before redemption is even '
    'attempted. It records only that the one rendezvous the ticket authorized has been spent.';
