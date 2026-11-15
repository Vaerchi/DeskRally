-- 0060: session transfer / escalation (docs/51 §3, §7, §8, §9 — design accepted, v4).
--
-- A technician hands a live unattended session (S1) to a colleague or to anyone who may start
-- sessions in the machine's group. The handoff is two sessions, not a mutation: S1 ends and S2 (the
-- receiver's) starts, linked by session_record.transferred_from. This file adds the offer ledger and
-- the three session_record columns the protocol needs.
--
-- Every reference is TENANT-QUALIFIED. A plain foreign key bypasses RLS on write, so an offer could
-- otherwise name another tenant's session, machine, group or user; the composite (tenant_id, x) keys
-- close that, which is why this file first makes sure the parent tables carry the UNIQUE (tenant_id,
-- id) a composite FK needs. Each ALTER is guarded so the file is idempotent and also applies to a
-- schema where 0024 / 0056 (which add two of these keys) have already run.

-- Existence is judged by the COLUMNS, not a constraint name: 0024 adds machine's key unguarded under its own
-- name, so this file must neither collide with it nor duplicate it, whichever order they run in.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
            ('machine'::regclass, 'machine_tenant_id_key'),
            ('app_user'::regclass, 'app_user_tenant_id_id_key'),
            ('session_record'::regclass, 'session_record_tenant_id_id_key')) v(rel, name)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint c
            WHERE c.conrelid = r.rel AND c.contype IN ('u', 'p')
              AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
                   FROM unnest(c.conkey) k JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k)
                  = ARRAY['id', 'tenant_id'])
        THEN
            EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I UNIQUE (tenant_id, id)', r.rel, r.name);
        END IF;
    END LOOP;
END
$$;

-- S2 -> S1 link, how S1 ended, and when the AGENT said S1 no longer exists on the machine.
--   transferred_from  the session this one was handed over from (NULL for an ordinary start).
--   end_reason        'transferred' for an S1 closed by a transfer (NULL = as before).
--   agent_ended_at    set ONLY by the authenticated docs/49 end report; the first report wins and
--                     duplicates never move it. It is the one authoritative statement that the
--                     previous session is gone, so it is what lets S2 start (docs/51 §8).
ALTER TABLE session_record
    ADD COLUMN IF NOT EXISTS transferred_from uuid,
    ADD COLUMN IF NOT EXISTS end_reason       text,
    ADD COLUMN IF NOT EXISTS agent_ended_at   timestamptz,
    -- Durable 'signaling vouched for this session' marker (set by cp_session_ticket_redeem below). The
    -- redemption ledger is pruned an hour after a ticket expires, so it cannot answer for older sessions.
    ADD COLUMN IF NOT EXISTS redeemed_at      timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'session_record_transferred_from_fk') THEN
        ALTER TABLE session_record ADD CONSTRAINT session_record_transferred_from_fk
            FOREIGN KEY (tenant_id, transferred_from) REFERENCES session_record (tenant_id, id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS session_transfer (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    session_id     uuid        NOT NULL,                 -- S1, the session being handed off
    machine_id     uuid        NOT NULL,                 -- derived from S1, never from the request
    group_id       uuid,                                 -- the machine's group when the offer was made
    from_user_id   uuid        NOT NULL,                 -- S1's holder, derived from S1
    to_user_id     uuid,                                 -- NULL = escalate to anyone in the group
    note           text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    state          text        NOT NULL CHECK (state IN
                       ('pending', 'releasing', 'accepted', 'failed', 'cancelled', 'expired', 'superseded')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,                 -- created_at + 5 min; applies to 'pending' only
    releasing_at   timestamptz,                          -- when the acceptor claimed it (the 60 s clock)
    accepted_by    uuid,
    new_session_id uuid,                                 -- S2
    failure_reason text        CHECK (failure_reason IS NULL OR length(failure_reason) <= 500),

    FOREIGN KEY (tenant_id, session_id)     REFERENCES session_record (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, machine_id)     REFERENCES machine        (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id)       REFERENCES machine_group  (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, new_session_id) REFERENCES session_record (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, from_user_id)   REFERENCES app_user       (tenant_id, id),
    FOREIGN KEY (tenant_id, to_user_id)     REFERENCES app_user       (tenant_id, id),
    FOREIGN KEY (tenant_id, accepted_by)    REFERENCES app_user       (tenant_id, id),

    -- docs/51 §9.1: what each state requires, so no code path can leave a half-formed row.
    CONSTRAINT session_transfer_state_fields CHECK (
        (state = 'pending'   AND accepted_by IS NULL AND new_session_id IS NULL AND failure_reason IS NULL) OR
        (state = 'releasing' AND accepted_by IS NOT NULL AND releasing_at IS NOT NULL AND new_session_id IS NULL) OR
        (state = 'accepted'  AND accepted_by IS NOT NULL AND new_session_id IS NOT NULL) OR
        (state = 'failed'    AND failure_reason IS NOT NULL) OR
        (state IN ('cancelled', 'expired', 'superseded') AND new_session_id IS NULL)
    )
);

-- At most ONE live transfer per session: a pending offer or one being released. A second offer for the
-- same session either supersedes the pending one (inside the offer transaction) or is refused 409
-- while one is releasing.
CREATE UNIQUE INDEX IF NOT EXISTS session_transfer_one_live
    ON session_transfer (tenant_id, session_id) WHERE state IN ('pending', 'releasing');

-- The incoming / outgoing listings and the timeout sweep.
CREATE INDEX IF NOT EXISTS session_transfer_live_by_tenant
    ON session_transfer (tenant_id, state, expires_at) WHERE state IN ('pending', 'releasing');
CREATE INDEX IF NOT EXISTS session_transfer_by_new_session
    ON session_transfer (tenant_id, new_session_id) WHERE new_session_id IS NOT NULL;

-- RLS and grants mirror session_record (0001 / 0005).
ALTER TABLE session_transfer ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_transfer FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON session_transfer;
CREATE POLICY tenant_isolation ON session_transfer
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON session_transfer TO rmt_app;
    END IF;
END
$$;

COMMENT ON TABLE session_transfer IS
    'One offer to hand a live unattended session to a colleague or a group (docs/51). pending -> '
    'releasing (accepted; waiting for the agent to report the old session ended) -> accepted (new '
    'session admitted) | failed. An offer id is never a bearer credential: every transition '
    're-derives the caller''s authority.';
