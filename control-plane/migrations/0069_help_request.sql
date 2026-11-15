-- 0069: guest-initiated help requests from enrolled machines (docs/64, contracts H-C1..H-C7).
--
-- An enrolled agent that holds an authenticated signaling socket may ask for help; signaling forwards
-- the request, with the identity it already verified, to the control plane. This file adds the request
-- ledger and the per-device op_id dedup ledger. (0066 is reserved by the recordings branch.)
--
--   help_request      one row per request. status: open | accepted | cancelled | expired. The
--                     group the machine had at creation is kept in group_id for display ONLY: every
--                     list and mutation authorizes against the machine's CURRENT group (H-C5), so
--                     moving a machine re-scopes visibility without touching this row.
--   help_request_op   (device, op_id) -> request_id for 24 hours (H-C3), so an agent that lost the
--                     response retries the same op_id and gets the same request back.
--
-- Every reference is TENANT-QUALIFIED. A plain foreign key bypasses RLS on write, so a row could
-- otherwise name another tenant's machine, session or user; the composite (tenant_id, x) keys close
-- that. machine, session_record and app_user already carry UNIQUE (tenant_id, id) (0024, 0060, 0056).
--
-- "One OPEN request per machine" is the partial unique index below; the control plane also serializes
-- creation per tenant under an advisory lock (tenant open-cap admission), but the index is what makes
-- the invariant true under any interleaving. A session is bound to AT MOST one request, and a request
-- to at most one session (uq_help_request_session): the id of a request can never be attached to a
-- second session.
--
-- Idempotent.

CREATE TABLE IF NOT EXISTS help_request (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    machine_id    uuid        NOT NULL,
    device_id     text        NOT NULL,
    group_id      uuid,                                   -- the machine's group at creation: informational only
    note          text        NOT NULL DEFAULT '' CHECK (char_length(note) <= 200),
    status        text        NOT NULL CHECK (status IN ('open', 'accepted', 'cancelled', 'expired')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    closed_at     timestamptz,                            -- set on every transition out of 'open'
    accepted_by   uuid,
    accepted_at   timestamptz,
    accept_op     text        CHECK (accept_op IS NULL OR char_length(accept_op) BETWEEN 1 AND 64),
    session_id    uuid,
    cancel_reason text        CHECK (cancel_reason IS NULL OR char_length(cancel_reason) <= 64),
    CONSTRAINT help_request_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT help_request_state_shape CHECK (
        (status = 'open'     AND closed_at IS NULL     AND accepted_by IS NULL AND session_id IS NULL) OR
        (status = 'accepted' AND closed_at IS NOT NULL AND accepted_by IS NOT NULL AND session_id IS NOT NULL) OR
        (status IN ('cancelled', 'expired') AND closed_at IS NOT NULL AND session_id IS NULL)),
    FOREIGN KEY (tenant_id, machine_id) REFERENCES machine        (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id)   REFERENCES machine_group  (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, accepted_by) REFERENCES app_user      (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, session_id) REFERENCES session_record (tenant_id, id) ON DELETE CASCADE
);

-- delivery: the persisted outcome of issuing an accepted request's session ticket. An accept sets 'pending'; the
-- accepting handler marks it 'delivered' once the ticket is minted, or CLAIMS it (reopen / cancel) when issuing
-- fails. Both are compare-and-swap on 'pending', so a session is never ended after it was delivered and a
-- request is never reopened under a delivered session (review r2 #4). NULL = legacy / not accepted.
ALTER TABLE help_request ADD COLUMN IF NOT EXISTS delivery text
    CHECK (delivery IS NULL OR delivery IN ('pending', 'delivered'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_help_request_one_open_per_machine
    ON help_request (tenant_id, machine_id) WHERE status = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS uq_help_request_session
    ON help_request (tenant_id, session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_help_request_device_created
    ON help_request (tenant_id, device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_help_request_tenant_created
    ON help_request (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_help_request_open_expiry
    ON help_request (expires_at) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_help_request_closed
    ON help_request (closed_at) WHERE status <> 'open';

CREATE TABLE IF NOT EXISTS help_request_op (
    tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    device_id  text        NOT NULL,
    op_id      text        NOT NULL CHECK (char_length(op_id) BETWEEN 1 AND 64),
    request_id uuid        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, device_id, op_id),
    FOREIGN KEY (tenant_id, request_id) REFERENCES help_request (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_help_request_op_created ON help_request_op (created_at);

--   help_request_call per-device CALL counter, one row per (device, UTC hour): every create call (replay,
--                     already-open or fresh) bumps it in its own committed transaction BEFORE any other work,
--                     so a device that loops on a replayed or already-open op_id is metered too (H-C2).
CREATE TABLE IF NOT EXISTS help_request_call (
    tenant_id uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    device_id text        NOT NULL,
    bucket    timestamptz NOT NULL,
    n         integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, device_id, bucket)
);
CREATE INDEX IF NOT EXISTS idx_help_request_call_bucket ON help_request_call (bucket);

ALTER TABLE help_request    ENABLE ROW LEVEL SECURITY;
ALTER TABLE help_request    FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON help_request;
CREATE POLICY tenant_isolation ON help_request
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

ALTER TABLE help_request_call ENABLE ROW LEVEL SECURITY;
ALTER TABLE help_request_call FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON help_request_call;
CREATE POLICY tenant_isolation ON help_request_call
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

ALTER TABLE help_request_op ENABLE ROW LEVEL SECURITY;
ALTER TABLE help_request_op FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON help_request_op;
CREATE POLICY tenant_isolation ON help_request_op
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Which tenants have work for the background sweep (expire due requests, prune closed ones, prune the
-- op ledger)? A cross-tenant question RLS would answer with nothing, so it is a SECURITY DEFINER
-- function returning ONLY tenant ids, the same shape as cp_list_tenant_max_ages (0050).
CREATE OR REPLACE FUNCTION cp_help_request_due_tenants(
        p_now           timestamptz,
        p_closed_before timestamptz,
        p_op_before     timestamptz)
    RETURNS TABLE(tenant_id uuid)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog, pg_temp
AS $$
    SELECT DISTINCT r.tenant_id FROM public.help_request r
     WHERE (r.status = 'open' AND r.expires_at <= p_now)
        OR (r.status <> 'open' AND r.closed_at < p_closed_before)
    UNION
    SELECT DISTINCT o.tenant_id FROM public.help_request_op o WHERE o.created_at < p_op_before
    UNION
    SELECT DISTINCT c.tenant_id FROM public.help_request_call c WHERE c.bucket < p_op_before
$$;

REVOKE ALL ON FUNCTION cp_help_request_due_tenants(timestamptz, timestamptz, timestamptz) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON help_request, help_request_op, help_request_call TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_help_request_due_tenants(timestamptz, timestamptz, timestamptz) TO rmt_app;
    END IF;
END
$$;
