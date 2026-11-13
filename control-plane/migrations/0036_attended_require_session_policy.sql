-- 0036_attended_require_session_policy.sql — close the redeem/connect SAMPLING WINDOW on the attended
-- path (docs/01 §5; the trust-model arc, loops 79-83).
--
-- Loop 82 gave the attended guest a way to opt into the provisional view-only floor: POST
-- /attended-sessions/redeem answers `require_session_policy: true` when the invite's group enforces
-- view-only, and the guest then opens the session VIEW-ONLY until a signed policy verifies. But the two
-- halves of that decision are read at DIFFERENT MOMENTS:
--
--   * the floor INSTRUCTION is sampled at REDEEM (the guest is told, once, and starts);
--   * whether a policy is MINTED is decided at CONNECT, from the group's state right then.
--
-- Clear `enforce_view_only` in between and the guest is left holding an instruction nothing will ever
-- discharge: it opened floored, no policy arrives, and it stays view-only for the session's whole life with
-- nothing on screen explaining why. (The opposite order is benign — flipped ON after redeem, the guest never
-- opted in, and connect still mints, so a cooperative viewer is restricted exactly as before.)
--
-- The fix needs no new agent behaviour, only MEMORY: record on the attended session that this guest was told
-- to floor, and then mint at connect whenever that flag is set — carrying the group's CURRENT level. An
-- `access=control` policy is precisely what the agent's ratchet already accepts to discharge a PROVISIONAL
-- floor (and only a provisional one: a floor that arrived as a verified view_only policy is not liftable).
-- So the flag turns "was told to floor" into a promise the control plane always keeps.
--
-- Written from Go, not from cp_attended_redeem, deliberately. The thing being recorded is the REDEEM
-- HANDLER's decision — issuer key pinned AND a policy store wired AND the group enforcing — and two of those
-- three are invisible to SQL. Keeping this an ALTER TABLE also avoids a real ordering hazard: several tests
-- apply 0021/0022 (which CREATE OR REPLACE cp_attended_redeem) AFTER the attended migration, so a function
-- body changed here would be silently reverted, while an added column cannot be.
--
-- DEFAULT false is the correct historical value: a row created before this column existed was never told to
-- floor. No backfill. No GRANT either — 0013's table-level grant to rmt_app covers new columns.

ALTER TABLE attended_session
    ADD COLUMN require_session_policy boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN attended_session.require_session_policy IS
    'True when redemption told this guest to open the session VIEW-ONLY until a signed policy verifies. '
    'Read at connect: a session flagged here is ALWAYS minted a policy, carrying the group''s current '
    'access level, so clearing the group mandate mid-session discharges the floor instead of stranding it.';
