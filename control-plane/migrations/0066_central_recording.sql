-- 0066: central session-recording storage, stage R1 (docs/63, with the §2a "Review r1" contracts).
--
-- (0065 is deliberately skipped: it is reserved by the parallel subgroups change.)
--
-- WHAT LIVES WHERE. The recording BYTES live on a volume, never in Postgres (D3); these tables hold
-- the index, the upload state machine, the quota reservation and the tombstones. Every path on the
-- volume is derived from the ids below (tenant_id / id / upload_id) and from nothing else.
--
-- TENANT ISOLATION. Same contract as every other tenant table (0001 note): tenant_id on every row,
-- ENABLE + FORCE RLS, USING/WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid). Every
-- reference to another tenant-scoped row is a COMPOSITE (tenant_id, x) foreign key, because a plain FK
-- is satisfied by the parent's global PK whoever owns it and so bypasses RLS on write. machine and
-- session_record already carry UNIQUE (tenant_id, id) (0024 / 0060).
--
-- TOMBSTONES (C2). A row that reaches expired / deleted / abandoned / refused is KEPT: the application
-- role has no DELETE grant, and a trigger forbids any transition out of a terminal state, so a create
-- for a recording id that was ever used can never resurrect it. Create-time metadata is immutable
-- (trigger), expires_at can only move EARLIER (C10: retries and replays never extend retention).
--
-- NO CASCADE FROM machine / session_record. A recording row must outlive neither deletion silently; the
-- composite FKs are NO ACTION, so deleting a machine that still has a recording is refused instead of
-- erasing the tombstone. (Only ephemeral attended-session machines are ever deleted, and attended
-- sessions cannot record.) Deleting a whole tenant still cascades through tenant(id).
--
-- POLICY, FAIL-CLOSED (D5). tenant_recording_policy.retention_days = 0 means "do not store centrally"
-- and is the default for a tenant with no row; storing is switched ON only by a positive
-- retention_days written by an explicit PUT that carries every field (the API refuses a body that omits
-- or does not name them), so a stale full-overwrite client — one that predates the setting, or sends a
-- body without it — can only ever leave storage OFF, never turn it on. The column defaults here are the
-- OFF/safe ones.
--
-- Idempotent: IF NOT EXISTS / OR REPLACE / DROP … IF EXISTS throughout.

-- The composite FKs below need UNIQUE (tenant_id, id) on machine and session_record. 0024 / 0060 add
-- them; this guard (existence judged by COLUMNS, as in 0060, so it neither collides with nor duplicates
-- them) keeps this file correct on a schema where those have not run.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
            ('machine'::regclass, 'machine_tenant_id_key'),
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

CREATE TABLE IF NOT EXISTS tenant_recording_policy (
    tenant_id           uuid        PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    -- 0 = do not store (default); otherwise days of retention counted from evidence_complete.
    retention_days      integer     NOT NULL DEFAULT 0
                            CHECK (retention_days = 0 OR retention_days BETWEEN 1 AND 365),
    -- Per-recording cap, never above the agent's own 1 GiB ceiling.
    max_recording_bytes bigint      NOT NULL DEFAULT 1073741824
                            CHECK (max_recording_bytes BETWEEN 1 AND 1073741824),
    -- Tenant total, counted over reservations (so it holds while uploads are in flight).
    quota_bytes         bigint      NOT NULL DEFAULT 21474836480
                            CHECK (quota_bytes BETWEEN 0 AND 1125899906842624),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_recording_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_recording_policy FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_recording_policy;
CREATE POLICY tenant_isolation ON tenant_recording_policy
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE TABLE IF NOT EXISTS session_recording (
    tenant_id            uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    id                   uuid        NOT NULL,                 -- the AGENT-chosen recording id
    session_id           uuid        NOT NULL,
    machine_id           uuid        NOT NULL,                 -- derived from the signing device, never the body
    upload_id            uuid        NOT NULL,                 -- server-chosen; names .incoming/<upload_id>
    enrollment_fp        bytea       NOT NULL CHECK (octet_length(enrollment_fp) = 32),
    generation           bigint      NOT NULL CHECK (generation >= 1),
    state                text        NOT NULL CHECK (state IN
                             ('uploading', 'evidence_complete', 'playback_ready', 'playback_failed',
                              'expired', 'deleted', 'abandoned', 'refused')),
    segment_count        integer     NOT NULL CHECK (segment_count BETWEEN 1 AND 64),
    declared_bytes       bigint      NOT NULL CHECK (declared_bytes BETWEEN 1 AND 1073741824),
    -- Durable quota reservation made at create: both stored copies + AEAD overhead + slack. Counted
    -- against the tenant quota and the server disk floor until the row is deleted/abandoned/refused.
    reserved_bytes       bigint      NOT NULL CHECK (reserved_bytes >= 0),
    key_id               bigint      NOT NULL CHECK (key_id > 0),
    wrapped_dek          bytea       NOT NULL CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 256),
    retention_days       integer     NOT NULL CHECK (retention_days BETWEEN 0 AND 365), -- policy snapshot at create
    finish_failures      integer     NOT NULL DEFAULT 0 CHECK (finish_failures >= 0),
    -- Set at evidence_complete (C4). Two labels only; never "verified".
    provenance           text        CHECK (provenance IN ('matches_session_audit', 'no_matching_stop_event')),
    matched_audit_seq    bigint,
    -- Agent-attested metadata from the finish call (stored and shown; truncation/dropped are compared
    -- with the session audit event for provenance).
    truncated            text        CHECK (truncated IS NULL OR char_length(truncated) <= 64),
    dropped_frames       bigint      CHECK (dropped_frames IS NULL OR dropped_frames >= 0),
    frames               bigint      CHECK (frames IS NULL OR frames >= 0),
    payload_bytes        bigint      CHECK (payload_bytes IS NULL OR payload_bytes >= 0),
    created_at           timestamptz NOT NULL DEFAULT now(),
    state_changed_at     timestamptz NOT NULL DEFAULT now(),
    evidence_complete_at timestamptz,
    expires_at           timestamptz,                          -- evidence_complete_at + retention (SERVER time, C10)
    expired_at           timestamptz,
    deleted_at           timestamptz,

    PRIMARY KEY (tenant_id, id),
    UNIQUE (upload_id),
    CONSTRAINT session_recording_session_same_tenant FOREIGN KEY (tenant_id, session_id)
        REFERENCES session_record (tenant_id, id),
    CONSTRAINT session_recording_machine_same_tenant FOREIGN KEY (tenant_id, machine_id)
        REFERENCES machine (tenant_id, id),
    -- What each state requires, so no code path can leave a half-formed row.
    CONSTRAINT session_recording_state_fields CHECK (
        (state IN ('uploading', 'abandoned', 'refused')
            AND evidence_complete_at IS NULL AND expires_at IS NULL AND provenance IS NULL
            AND expired_at IS NULL AND deleted_at IS NULL)
        OR (state IN ('evidence_complete', 'playback_ready', 'playback_failed')
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NULL AND deleted_at IS NULL)
        OR (state = 'expired'
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NOT NULL AND deleted_at IS NULL)
        OR (state = 'deleted'
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NOT NULL AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS session_recording_session ON session_recording (tenant_id, session_id);
CREATE INDEX IF NOT EXISTS session_recording_machine ON session_recording (tenant_id, machine_id);
CREATE INDEX IF NOT EXISTS session_recording_state   ON session_recording (state) WHERE state NOT IN ('deleted', 'abandoned', 'refused');

CREATE TABLE IF NOT EXISTS session_recording_segment (
    tenant_id        uuid    NOT NULL,
    recording_id     uuid    NOT NULL,
    idx              integer NOT NULL CHECK (idx BETWEEN 0 AND 63),
    declared_len     bigint  NOT NULL CHECK (declared_len BETWEEN 1 AND 1073741824),
    -- Plaintext bytes durably committed (fsynced) to the incoming generation. Advances ONLY under the
    -- row lock, only by the next chunk (C2).
    committed_offset bigint  NOT NULL DEFAULT 0,
    -- Server-computed sha256 of the plaintext, set at finish.
    sha256           text    CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, recording_id, idx),
    CONSTRAINT session_recording_segment_parent FOREIGN KEY (tenant_id, recording_id)
        REFERENCES session_recording (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT session_recording_segment_offset CHECK (committed_offset BETWEEN 0 AND declared_len)
);

-- Guard: create metadata is immutable; state moves only along the C2 machine; terminal states are final;
-- retention can only be shortened.
CREATE OR REPLACE FUNCTION session_recording_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_catalog
AS $$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.id <> OLD.id OR NEW.session_id <> OLD.session_id
       OR NEW.machine_id <> OLD.machine_id OR NEW.upload_id <> OLD.upload_id
       OR NEW.enrollment_fp <> OLD.enrollment_fp OR NEW.generation <> OLD.generation
       OR NEW.segment_count <> OLD.segment_count OR NEW.declared_bytes <> OLD.declared_bytes
       OR NEW.reserved_bytes <> OLD.reserved_bytes OR NEW.key_id <> OLD.key_id
       OR NEW.wrapped_dek <> OLD.wrapped_dek OR NEW.retention_days <> OLD.retention_days
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'session_recording: create-time metadata is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.state <> OLD.state THEN
        IF NOT (
               (OLD.state = 'uploading'         AND NEW.state IN ('evidence_complete', 'abandoned', 'refused'))
            OR (OLD.state = 'evidence_complete' AND NEW.state IN ('playback_ready', 'playback_failed', 'expired'))
            OR (OLD.state = 'playback_ready'    AND NEW.state IN ('playback_failed', 'expired'))
            OR (OLD.state = 'playback_failed'   AND NEW.state IN ('playback_ready', 'expired'))
            OR (OLD.state = 'expired'           AND NEW.state = 'deleted')
        ) THEN
            RAISE EXCEPTION 'session_recording: illegal state transition % -> %', OLD.state, NEW.state
                USING ERRCODE = '23514';
        END IF;
        NEW.state_changed_at := now();
    END IF;
    IF OLD.expires_at IS NOT NULL AND NEW.expires_at IS DISTINCT FROM OLD.expires_at
       AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at) THEN
        RAISE EXCEPTION 'session_recording: expires_at may only move earlier' USING ERRCODE = '23514';
    END IF;
    IF OLD.evidence_complete_at IS NOT NULL AND NEW.evidence_complete_at IS DISTINCT FROM OLD.evidence_complete_at THEN
        RAISE EXCEPTION 'session_recording: evidence_complete_at is write-once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS session_recording_guard ON session_recording;
CREATE TRIGGER session_recording_guard BEFORE UPDATE ON session_recording
    FOR EACH ROW EXECUTE FUNCTION session_recording_guard();

CREATE OR REPLACE FUNCTION session_recording_segment_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_catalog
AS $$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.recording_id <> OLD.recording_id OR NEW.idx <> OLD.idx
       OR NEW.declared_len <> OLD.declared_len THEN
        RAISE EXCEPTION 'session_recording_segment: declared metadata is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS session_recording_segment_guard ON session_recording_segment;
CREATE TRIGGER session_recording_segment_guard BEFORE UPDATE ON session_recording_segment
    FOR EACH ROW EXECUTE FUNCTION session_recording_segment_guard();

ALTER TABLE session_recording         ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_recording         FORCE  ROW LEVEL SECURITY;
ALTER TABLE session_recording_segment ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_recording_segment FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON session_recording;
CREATE POLICY tenant_isolation ON session_recording
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON session_recording_segment;
CREATE POLICY tenant_isolation ON session_recording_segment
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- The application role can read, insert and update; it can NEVER delete a recording row (tombstones).
-- The explicit REVOKE is load-bearing: 0005 sets ALTER DEFAULT PRIVILEGES so that every table created
-- later is born with DELETE granted to rmt_app, and a GRANT that merely omits DELETE would not take it
-- away (measured: DELETE FROM session_recording succeeded as rmt_app before this REVOKE existed).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE ON session_recording, session_recording_segment TO rmt_app;
        REVOKE DELETE, TRUNCATE ON session_recording, session_recording_segment FROM rmt_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_recording_policy TO rmt_app;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Narrow cross-tenant helpers for the background sweeper (C6). Like cp_list_tenant_max_ages (0050)
-- they are SECURITY DEFINER with a FIXED search_path, EXECUTE revoked from PUBLIC and granted to the
-- app role only, and they return only what the sweeper needs — never key material, never the
-- recording's session or machine.
-- ---------------------------------------------------------------------------------------------

-- Every NON-TERMINAL recording, with the tenant's CURRENT retention (0 when none/off). The sweeper
-- decides expiry from this (shortening retention applies to existing rows on the next sweep; turning
-- storage off lets them expire on their stored schedule), and the orphan pass treats anything on disk
-- that is not named here as an orphan to QUARANTINE (never delete).
CREATE OR REPLACE FUNCTION cp_recording_sweep_list()
RETURNS TABLE(tenant_id uuid, id uuid, upload_id uuid, state text, created_at timestamptz,
              evidence_complete_at timestamptz, expires_at timestamptz, expired_at timestamptz,
              policy_retention_days integer)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT r.tenant_id, r.id, r.upload_id, r.state, r.created_at, r.evidence_complete_at, r.expires_at,
           r.expired_at, COALESCE(p.retention_days, 0)
    FROM session_recording r
    LEFT JOIN tenant_recording_policy p ON p.tenant_id = r.tenant_id
    WHERE r.state NOT IN ('deleted', 'abandoned', 'refused')
$$;

REVOKE ALL ON FUNCTION cp_recording_sweep_list() FROM PUBLIC;

-- Bytes that live uploads have reserved but not yet written, over ALL tenants: what the server disk
-- floor is measured against (C3: "against reservations, not instantaneous free space").
CREATE OR REPLACE FUNCTION cp_recording_global_unwritten()
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT COALESCE(SUM(GREATEST(r.reserved_bytes - COALESCE(w.written, 0), 0)), 0)::bigint
    FROM session_recording r
    LEFT JOIN (SELECT s.tenant_id, s.recording_id, SUM(s.committed_offset) AS written
               FROM session_recording_segment s GROUP BY s.tenant_id, s.recording_id) w
           ON w.tenant_id = r.tenant_id AND w.recording_id = r.id
    WHERE r.state IN ('uploading', 'evidence_complete')
$$;

REVOKE ALL ON FUNCTION cp_recording_global_unwritten() FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT EXECUTE ON FUNCTION cp_recording_sweep_list() TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_recording_global_unwritten() TO rmt_app;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Capability preset (D6). Follows 0038: role.capabilities is documentation of the preset (rbac.go's
-- rolePresets is what is enforced at runtime), kept truthful here. view_recordings goes to Owner,
-- Admin and Auditor — NOT Technician, NOT ReadOnly, and it is not API-token grantable (rbac.go).
-- ---------------------------------------------------------------------------------------------
UPDATE role
   SET capabilities = capabilities || ARRAY['view_recordings']
 WHERE tenant_id IS NULL
   AND key IN ('owner', 'admin', 'auditor')
   AND NOT ('view_recordings' = ANY(capabilities));
