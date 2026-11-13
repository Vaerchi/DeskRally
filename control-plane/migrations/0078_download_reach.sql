-- 0078 — private download / update reach counts (docs/68). Two small tables that hold ONLY COUNTS, a role
-- that may write nothing else, and one read path for the platform operator.
--
-- WHAT IS (NOT) STORED. download_daily holds one row per (UTC day, artifact, class): request counts, a
-- completed-download count that is NULL when the artifact size was unknown, a unique-ish client count that is
-- only a cardinality (never a client hash), the bytes served, and a flag saying the unique-ish figure is a lower bound.
-- It has no column that could hold an IP address, a User-Agent or a client hash, and the ingest job (reach/) never
-- sends one. download_ingest_cursor holds how far each log segment has been read (docs/68 section 4, option A).
-- Neither table is tenant-scoped: downloads are anonymous and belong to the platform.
--
-- WHO CAN TOUCH THEM.
--   * `rmt_reach_ingest` (NOLOGIN here; the deployment gives it a password and LOGIN, see
--     docs/20 section 16) has SELECT/INSERT/UPDATE/DELETE on these two tables and NOTHING else. SELECT is needed
--     by the upsert (it adds to the stored count) and DELETE by the retention sweep (rows older than 25 months,
--     cursors of segments that have been gone for 60 days).
--   * rmt_app (the control plane) gets NO privilege on either table. 0005's default privileges grant every new
--     table to it, so they are revoked below. It reads the report only through cp_platform_downloads, below.
--   * rmt_definer (docs/67), which owns that function, gets SELECT on download_daily and nothing on the cursor
--     table. The line is written one-per-line like 0076's so the test fixture applies the REAL grant.
--
-- cp_platform_downloads calls cp_platform_check first (operator grant + interactive session + MFA within 12 h,
-- the same gate as cp_platform_list_tenants), then returns the rows of a bounded range (at most 400 days; the
-- handler bounds it too). An API token has no session id and so can never pass the check.
--
-- OPT-IN, SHIPS OFF. A routine deploy only creates the two EMPTY tables, the NOLOGIN role and the function; the
-- ingest service is a compose profile that is not started by default (docs/20 section 16).
--
-- ROLLBACK: DROP FUNCTION cp_platform_downloads(uuid, uuid, date, date); DROP TABLE download_ingest_cursor,
-- download_daily; DROP ROLE rmt_reach_ingest (after REVOKE ALL ... FROM it).

CREATE TABLE download_daily (
    day        date    NOT NULL,
    artifact   text    NOT NULL CHECK (length(artifact) BETWEEN 1 AND 128),
    class      text    NOT NULL CHECK (class IN ('human', 'update', 'other', 'noise')),
    requests   integer NOT NULL DEFAULT 0 CHECK (requests >= 0),
    completed  integer NULL CHECK (completed >= 0),   -- NULL = the artifact size was not known: unknown, not zero
    uniq       integer NULL CHECK (uniq >= 0),        -- a cardinality only; NULL = no figure (non-human rows)
    bytes      bigint  NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    partial    boolean NOT NULL DEFAULT false,        -- uniq is a lower bound (restart, missing salt, capped set)
    PRIMARY KEY (day, artifact, class)
);

CREATE TABLE download_ingest_cursor (
    file_id      text        PRIMARY KEY CHECK (file_id ~ '^[0-9a-f]{32}$'),   -- hash of the segment's first-line server timestamp text (no client data)
    last_name    text        NOT NULL CHECK (length(last_name) <= 255),         -- informational
    byte_offset  bigint      NOT NULL CHECK (byte_offset >= 0),
    complete     boolean     NOT NULL DEFAULT false,                            -- a rolled segment read to its end: never opened again (docs/68 Codex round 2)
    updated_at   timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_reach_ingest') THEN
        BEGIN
            CREATE ROLE rmt_reach_ingest NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;   -- a concurrent migration created it first
        END;
    END IF;
END
$$;
-- Pin everything but LOGIN, which the deployment sets (and a re-run of this migration must not undo).
ALTER ROLE rmt_reach_ingest WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT USAGE ON SCHEMA public TO rmt_reach_ingest;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE download_daily          TO rmt_reach_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE download_ingest_cursor  TO rmt_reach_ingest;

-- rmt_definer owns cp_platform_downloads (below); it needs to read the counts and nothing more.
GRANT SELECT ON TABLE download_daily TO rmt_definer;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_app') THEN
        -- 0005's default privileges just granted these to rmt_app; the control plane must not read them directly.
        REVOKE ALL ON TABLE download_daily, download_ingest_cursor FROM rmt_app;
    END IF;
END
$$;

-- The operator's read. search_path ends in pg_temp (0074); the body qualifies every name.
CREATE OR REPLACE FUNCTION cp_platform_downloads(p_user uuid, p_session uuid, p_from date, p_to date)
    RETURNS TABLE (day date, artifact text, class text, requests integer, completed integer,
                   uniq integer, bytes bigint, partial boolean)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
    -- Both ends are inclusive, so p_to - p_from = 399 is a 400-day report.
    IF p_from IS NULL OR p_to IS NULL OR p_to < p_from OR p_to - p_from >= 400 THEN
        RAISE EXCEPTION 'platform: the report range must be 1 to 400 days' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        SELECT d.day, d.artifact, d.class, d.requests, d.completed, d.uniq, d.bytes, d.partial
          FROM public.download_daily d
         WHERE d.day >= p_from AND d.day <= p_to
         ORDER BY d.day, d.class, d.artifact;
END
$$;

REVOKE ALL ON FUNCTION cp_platform_downloads(uuid, uuid, date, date) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT EXECUTE ON FUNCTION cp_platform_downloads(uuid, uuid, date, date) TO rmt_app;
    END IF;
END
$$;

-- docs/67: every application definer routine is owned by rmt_definer.
ALTER ROUTINE cp_platform_downloads(uuid, uuid, date, date) OWNER TO rmt_definer;
