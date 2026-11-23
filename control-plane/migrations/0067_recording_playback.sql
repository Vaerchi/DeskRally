-- 0067: central session-recording storage, stage R1b — the playback (WebM) copy's metadata (docs/63 D7,
-- §2a C7). Evidence completeness and playback readiness are SEPARATE: the muxer's outcome lives in the
-- row's state (playback_ready / playback_failed, already part of 0066's machine) and in these columns; a
-- muxer failure never touches the evidence copy or its digests.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS, DROP CONSTRAINT IF EXISTS before ADD).
--
-- Why a separate migration rather than editing 0066: 0066 may already have been applied to development
-- databases; a changed migration file is a different migration. These columns are all NULL until the
-- muxer succeeds, so every existing row stays valid.

ALTER TABLE session_recording ADD COLUMN IF NOT EXISTS playback_error text;
ALTER TABLE session_recording ADD COLUMN IF NOT EXISTS playback_at    timestamptz;

-- The muxer's failure reason is a CLOSED set of codes (recording_webm.go Mux*), never text derived from
-- the recording: it is stored, shown to operators and returned by the API.
ALTER TABLE session_recording DROP CONSTRAINT IF EXISTS session_recording_playback_error_code;
ALTER TABLE session_recording ADD CONSTRAINT session_recording_playback_error_code CHECK (
    playback_error IS NULL OR playback_error IN
        ('invalid_ivf', 'limit_exceeded', 'time_budget', 'io_error', 'inconsistent_ivf', 'internal'));

-- Per-segment playback copy. All six are set together (at playback_ready) or not at all.
-- NOTE the explicit IS NOT NULL terms: a CHECK passes when its expression is NULL, and
-- `webm_len >= 1 AND width BETWEEN ...` is NULL (not false) when width is NULL — so a half-filled row would
-- have slipped through a check that only compared the values. Measured against Postgres 16 before fixing.
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS webm_len    bigint;
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS width       integer;
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS height      integer;
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS start_ms    bigint;
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS duration_ms bigint;
ALTER TABLE session_recording_segment ADD COLUMN IF NOT EXISTS frames      bigint;

ALTER TABLE session_recording_segment DROP CONSTRAINT IF EXISTS session_recording_segment_playback_fields;
ALTER TABLE session_recording_segment ADD CONSTRAINT session_recording_segment_playback_fields CHECK (
    (webm_len IS NULL AND width IS NULL AND height IS NULL AND start_ms IS NULL AND duration_ms IS NULL AND frames IS NULL)
    OR (webm_len IS NOT NULL AND width IS NOT NULL AND height IS NOT NULL
        AND start_ms IS NOT NULL AND duration_ms IS NOT NULL AND frames IS NOT NULL
        AND webm_len >= 1 AND width BETWEEN 1 AND 8192 AND height BETWEEN 1 AND 8192
        AND start_ms >= 0 AND duration_ms >= 0 AND frames >= 1));

-- List paging (newest completed first) walks (tenant, evidence_complete_at DESC, id DESC).
CREATE INDEX IF NOT EXISTS session_recording_list ON session_recording (tenant_id, evidence_complete_at DESC, id DESC)
    WHERE evidence_complete_at IS NOT NULL;
