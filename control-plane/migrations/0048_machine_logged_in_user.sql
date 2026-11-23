-- 0048_machine_logged_in_user.sql — live presence: the interactive Windows user on each machine
-- (docs/01 §4 Access Panel "Missing: the last-USER field").
--
-- The agent queries WTSQuerySessionInformationW(WTS_CURRENT_SESSION, WTSUserName) +
-- WTSDomainName on every register_agent and announces it as `logged_in_user` (e.g. "CORP\alice"
-- or "alice"). The control plane refreshes this column through the same presence-feed hop it
-- uses for machine.os and machine.agent_version:
--
--   * Only agents that actually reported produce a write — an empty value means "said nothing"
--     and the stored value is left alone (a silent agent can never blank a name).
--   * NOT write-once: the value changes on every interactive user log-in / log-out cycle.
--   * DISPLAY ONLY — nothing in the authorization path reads this column.
--
-- The DEFAULT '' keeps existing rows consistent with the code's "empty string = no user
-- observed yet" convention (the same as machine.os pre-enrollment).
ALTER TABLE machine ADD COLUMN logged_in_user TEXT NOT NULL DEFAULT '';

-- No new GRANT needed: rmt_app already holds SELECT, INSERT, UPDATE on the machine table
-- (migrations/0001_core.sql). The standard tenant_isolation RLS policy already covers all
-- columns, including this new one, without amendment.
