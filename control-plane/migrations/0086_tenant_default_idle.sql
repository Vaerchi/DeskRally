-- Extend tenant_session_policy (0029) with the organization's default idle timeout in seconds.
--
-- The default applies when the machine group's resolved idle timeout is zero. A zero default
-- means sessions without a group timeout have no idle limit.
--
-- No new grants: rmt_app already has SELECT/INSERT/UPDATE on the table (0029) and RLS confines it per tenant.
--
-- ROLLBACK: ALTER TABLE tenant_session_policy DROP COLUMN default_max_idle_seconds;
ALTER TABLE tenant_session_policy
    ADD COLUMN default_max_idle_seconds integer NOT NULL DEFAULT 0
        CHECK (default_max_idle_seconds >= 0 AND default_max_idle_seconds <= 3600);
