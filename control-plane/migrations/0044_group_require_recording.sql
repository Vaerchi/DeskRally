-- 0044_group_require_recording.sql — per-machine-group mandatory recording policy.
--
-- The companion to 0043's `prohibit_recording` (which bans recording on a group). This adds
-- `require_recording`: a group where every session MUST be recorded from the first frame —
-- the "automatic extended auditing" half of docs/01 §5's "allow_recording / require_recording"
-- backlog item.
--
-- Zero-value safety: `false` = recording is NOT required (backward-compatible default). A group with
-- `require_recording = true` causes the control plane to include `require_recording = true` in the
-- SIGNED session policy, which the agent enforces by auto-starting a recording on policy install and
-- refusing `StopRecording` for the session's lifetime.
--
-- Constraint: `require_recording = true` AND `prohibit_recording = true` is a contradiction
-- (one mandates recording, the other bans it). Enforced in two places:
--   1. Application layer: NormalizeGroupSessionPolicy in group_session_policy.go rejects the
--      combination at PUT time with a 400 so operators get a clear error message.
--   2. Schema layer: the CHECK constraint below is the last line of defence against a direct DB
--      write (admin CLI, migration script, psql) that bypasses the handler and would strand the
--      group in a contradictory state that the control plane would then serve to agents.

ALTER TABLE group_session_policy
    ADD COLUMN require_recording BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE group_session_policy
    ADD CONSTRAINT group_session_policy_no_recording_conflict
    CHECK (NOT (require_recording AND prohibit_recording));

COMMENT ON COLUMN group_session_policy.require_recording IS
    'When true, every session on a machine in this group is recorded automatically from the first '
    'frame and the technician cannot stop the recording. The control plane mints require_recording '
    'into the signed session policy; the agent enforces it. '
    'Mutually exclusive with prohibit_recording — both the application layer and a schema CHECK '
    'constraint reject both being true simultaneously.';
