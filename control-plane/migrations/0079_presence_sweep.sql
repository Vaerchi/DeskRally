-- 0079 — the control plane records machine.last_seen on its own schedule, not only when a console looks.
--
-- Until now the ONLY writer of machine.last_seen was GET /machines (annotatePresence -> TouchLastSeen):
-- a machine was stamped when some console user of ITS tenant happened to list machines while it was
-- online. A machine that was online all week while nobody opened the console was never stamped, so
-- "offline since" was wrong and the Adoption card's "active in the last 30 days" undercounted
-- (docs/68 section 8 notes this). The fix is a background sweep in the control plane: every few
-- minutes it reads the same signaling presence feed and stamps every online device it knows.
--
-- The feed is CROSS-TENANT and the sweep has no tenant to pin, so the write cannot go through RLS the
-- way TouchLastSeen does. cp_presence_stamp is the narrowest cross-tenant write that does the job:
--   * it writes ONE column, last_seen, and rmt_definer gets UPDATE on that column only (not the row);
--   * it matches by device_id, which is globally unique (0008), so an id stamps at most one machine;
--   * it returns only a COUNT, and the only caller is the control plane's own sweeper. It reveals
--     nothing about which tenant owns an id, and rmt_app could already stamp its own tenant's rows;
--   * the stamp only moves FORWARD (the same `last_seen < p_at` guard as TouchLastSeen), and is
--     clamped to the database's now(), so a signaling clock running ahead cannot pin last_seen in
--     the future (where the forward-only guard would then freeze it);
--   * the id list is bounded (100000 per call; the Go side sends 5000 at a time).
-- Nothing authorizes on last_seen: it is display (the console's "offline since") and the Adoption
-- count only. The machine_directive_guard trigger fires on UPDATE OF status, group_id, not on this.
--
-- ROLLBACK: DROP FUNCTION cp_presence_stamp(text[], timestamptz);
--           REVOKE UPDATE (last_seen) ON machine FROM rmt_definer;
-- The sweeper logs the failure and the console path keeps stamping exactly as before.

GRANT UPDATE (last_seen) ON TABLE machine TO rmt_definer;

CREATE OR REPLACE FUNCTION cp_presence_stamp(p_device_ids text[], p_at timestamptz)
    RETURNS integer
    LANGUAGE plpgsql
    VOLATILE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_at timestamptz := LEAST(p_at, now());
    v_n  integer;
BEGIN
    IF p_device_ids IS NULL OR p_at IS NULL THEN
        RETURN 0;
    END IF;
    IF cardinality(p_device_ids) > 100000 THEN
        RAISE EXCEPTION 'presence: at most 100000 device ids per call' USING ERRCODE = '22023';
    END IF;
    UPDATE public.machine m
       SET last_seen = v_at
     WHERE m.device_id = ANY(p_device_ids)
       AND (m.last_seen IS NULL OR m.last_seen < v_at);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END
$$;

REVOKE ALL ON FUNCTION cp_presence_stamp(text[], timestamptz) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT EXECUTE ON FUNCTION cp_presence_stamp(text[], timestamptz) TO rmt_app;
    END IF;
END
$$;

-- docs/67: every application definer routine is owned by rmt_definer.
ALTER ROUTINE cp_presence_stamp(text[], timestamptz) OWNER TO rmt_definer;

COMMENT ON COLUMN machine.last_seen IS
    'Last time the signaling presence feed reported this device connected. NULL = never seen online '
    'since this column existed. Written by the control plane, never by the agent: on each console '
    'presence read (tenant-scoped, TouchLastSeen) and by the background presence sweep '
    '(cp_presence_stamp, 0079).';
