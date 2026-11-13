-- Extend tenant_session_policy (0029) with a per-tenant MAX SESSION AGE (docs/01 §5). A remote-support
-- session left OPEN (session_record.ended_at IS NULL) longer than this is REAPED — its ended_at is
-- stamped — so it stops holding a seat against the concurrency cap. This closes the seat-metering leak:
-- the agent's own max_session_secs tears down the live stream but never ends the control-plane record, so
-- an abandoned session would otherwise pin a seat forever.
--
-- Seconds (matching the agent's max_session_secs). 0 = no maximum (the default); an absent policy row is
-- likewise "no maximum". The reap runs at POST /sessions, before the concurrency count, so a burst that
-- would have been blocked by stale sessions self-heals on the next start.
ALTER TABLE tenant_session_policy
    ADD COLUMN max_session_seconds integer NOT NULL DEFAULT 0
        CHECK (max_session_seconds >= 0);
