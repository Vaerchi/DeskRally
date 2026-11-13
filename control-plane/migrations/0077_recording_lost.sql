-- 0077: central session-recording storage, R4 — the 'lost' state (docs/63 §2a C6/C11, §10 R4).
--
-- WHY. The recordings volume is outside the backup contract (C11): a database restore can bring back rows
-- whose files are gone. Such a row must never be served as playback and must say so honestly. The
-- operator-run reconciliation (RECORDING_RECONCILE_MODE=1, docs/22 restore drill) moves a row whose blob
-- is missing to 'lost' and, if the files reappear (a later volume restore), back again.
--
-- THE MACHINE. Only the three states that PROMISE evidence on disk can become lost:
-- evidence_complete, playback_ready, playback_failed (uploading holds only .incoming; expired is already
-- being unlinked, so a missing file there is the goal; deleted/abandoned/refused hold nothing).
--   <promising state> -> lost          lost_from records which one, lost_at when
--   lost -> <promising state>          the files came back (restore-on-reappear), reconcile mode only
--   lost -> expired                    retention still applies: a lost row ages out like any other,
--                                      then expired -> deleted as always (nothing to unlink)
-- lost_from / lost_at are kept as history after a restore, an expiry or any later transition (state is the
-- truth; they say it was once lost). The trigger refuses every change to them except the transition INTO lost;
-- the CHECKs below tie them to each other and require them on a lost row, never forbid them elsewhere.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, DROP CONSTRAINT IF EXISTS before ADD, CREATE OR REPLACE.
-- RLS, grants and the no-DELETE tombstone rule are untouched (same table, same policies).

ALTER TABLE session_recording ADD COLUMN IF NOT EXISTS lost_from text;
ALTER TABLE session_recording ADD COLUMN IF NOT EXISTS lost_at   timestamptz;

ALTER TABLE session_recording DROP CONSTRAINT IF EXISTS session_recording_lost_from_check;
ALTER TABLE session_recording ADD CONSTRAINT session_recording_lost_from_check CHECK (
    lost_from IS NULL OR lost_from IN ('evidence_complete', 'playback_ready', 'playback_failed'));

-- Inline column CHECK from 0066 (auto-named <table>_<column>_check).
ALTER TABLE session_recording DROP CONSTRAINT IF EXISTS session_recording_state_check;
ALTER TABLE session_recording ADD CONSTRAINT session_recording_state_check CHECK (state IN
    ('uploading', 'evidence_complete', 'playback_ready', 'playback_failed', 'lost',
     'expired', 'deleted', 'abandoned', 'refused'));

-- What each state requires (0066's constraint, with the lost branch added and nothing else changed).
-- lost_from and lost_at are both set or both null, and a lost row has them.
ALTER TABLE session_recording DROP CONSTRAINT IF EXISTS session_recording_state_fields;
ALTER TABLE session_recording ADD CONSTRAINT session_recording_state_fields CHECK (
    ((lost_from IS NULL) = (lost_at IS NULL))
    AND (
        (state IN ('uploading', 'abandoned', 'refused')
            AND evidence_complete_at IS NULL AND expires_at IS NULL AND provenance IS NULL
            AND expired_at IS NULL AND deleted_at IS NULL)
        OR (state IN ('evidence_complete', 'playback_ready', 'playback_failed')
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NULL AND deleted_at IS NULL)
        OR (state = 'lost'
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NULL AND deleted_at IS NULL AND lost_from IS NOT NULL)
        OR (state = 'expired'
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NOT NULL AND deleted_at IS NULL)
        OR (state = 'deleted'
            AND evidence_complete_at IS NOT NULL AND expires_at IS NOT NULL AND provenance IS NOT NULL
            AND expired_at IS NOT NULL AND deleted_at IS NOT NULL)
    ));

-- The guard, redefined from its LATEST definition (0066; no later migration touches it) with exactly
-- two changes: the lost transitions, and lost_from/lost_at made write-once-per-loss (changeable only by the
-- transition into lost), and nothing else.
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
            OR (OLD.state = 'evidence_complete' AND NEW.state IN ('playback_ready', 'playback_failed', 'expired', 'lost'))
            OR (OLD.state = 'playback_ready'    AND NEW.state IN ('playback_failed', 'expired', 'lost'))
            OR (OLD.state = 'playback_failed'   AND NEW.state IN ('playback_ready', 'expired', 'lost'))
            OR (OLD.state = 'lost'              AND NEW.state IN ('evidence_complete', 'playback_ready', 'playback_failed', 'expired'))
            OR (OLD.state = 'expired'           AND NEW.state = 'deleted')
        ) THEN
            RAISE EXCEPTION 'session_recording: illegal state transition % -> %', OLD.state, NEW.state
                USING ERRCODE = '23514';
        END IF;
        NEW.state_changed_at := now();
    END IF;
    -- lost_from / lost_at are the loss HISTORY and are set only by the transition INTO lost (naming the state it
    -- came from, stamped), judged independently of whether the state changed: any other change to either column
    -- is refused, so a restore, an expiry, or a plain UPDATE can neither rewrite nor clear them. (A later
    -- second loss re-enters lost and legitimately restamps.)
    IF NEW.state = 'lost' AND OLD.state <> 'lost' THEN
        IF NEW.lost_from IS DISTINCT FROM OLD.state OR NEW.lost_at IS NULL THEN
            RAISE EXCEPTION 'session_recording: entering lost must name the state it was lost from and when' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.lost_from IS DISTINCT FROM OLD.lost_from OR NEW.lost_at IS DISTINCT FROM OLD.lost_at THEN
        RAISE EXCEPTION 'session_recording: lost_from / lost_at change only with the transition into lost' USING ERRCODE = '23514';
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
