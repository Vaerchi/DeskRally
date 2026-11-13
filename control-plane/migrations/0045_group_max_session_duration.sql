-- 0045: per-group maximum session duration (in seconds; 0 = unlimited).
--
-- Allows an admin to mandate that sessions on machines in a group end automatically after at most
-- N seconds. 0 — the default — preserves the current unlimited behaviour. The field is unsigned
-- in intent (negative durations are nonsensical) but Postgres INT is signed. A CHECK (>= 0) makes
-- the schema self-defending against direct SQL writes that bypass the application layer; the
-- application layer also rejects negative and out-of-range values (NormalizeGroupSessionPolicy).
-- The upper bound (86400s = 24h) is a product decision kept in Go alone, not in the schema,
-- because it may change without a migration.
--
-- Does NOT affect migration 0034's IsDefault logic directly — IsDefault tests this column via Go
-- (MaxSessionDurationSeconds == 0).
--
-- Compatible: the DEFAULT 0 means existing rows read as "unlimited" on first scan (no disruption),
-- and the column is NOT NULL so all future Scans require it — the three-place rule for pgstore
-- columns applies immediately (Get + Set + List must all touch this column; see
-- pgstore_group_session_policy.go's header comment).

ALTER TABLE group_session_policy
    ADD COLUMN max_session_duration_seconds INTEGER NOT NULL DEFAULT 0
        CHECK (max_session_duration_seconds >= 0);
