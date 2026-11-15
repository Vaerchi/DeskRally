-- 0053: remembered sessions — 30-day absolute / 7-day idle for desktop "remember me" opt-in.
--
-- WHY THIS EXISTS. The desktop app supports Windows Hello unlock, which implies a session that
-- survives across reboots without re-entering a password. A remembered session is explicitly opted
-- in at login (POST /auth/login { "remember_device": true }) AFTER full password + TOTP
-- verification. It is NOT tied to any native attestation: the opt-in is server-side and the UA
-- is not a security boundary. The server enforces both limits from the persisted flag alone.
--
-- LIMITS (fixed, not configurable — a configurable maximum is just a knob a misconfiguration
-- sets to infinity):
--   * Absolute lifetime:  30 days from creation (ExpiresAt — same enforcement as ordinary sessions)
--   * Idle timeout:       7 days (SessionManager.Validate uses the persisted flag to choose)
--
-- Ordinary sessions (remembered = false) keep their existing limits:
--   * Absolute:  12 hours (DefaultSessionTTL)
--   * Idle:      30 minutes (DefaultSessionIdleTTL)
--
-- PASSWORD / EMAIL CHANGE. Both handlers revoke all sessions and issue a replacement via
-- SessionManager.Issue (the ordinary path). The replacement session carries remembered = false.
-- Re-opting in to "remember device" requires a new login — this is deliberate: the remembered
-- flag is an explicit opt-in the user makes AT LOGIN, not a property of the account. Rotating a
-- credential is a security-sensitive moment, and issuing a long-lived session automatically there
-- would undermine the "sign out everywhere" protection that rotation provides.
--
-- RLS: no new policy. user_session already has ENABLE + FORCE ROW LEVEL SECURITY with its
-- tenant_isolation policy (0002_auth.sql). The new column rides on the existing policy.
-- 0005_app_role.sql grants rmt_app DML on the TABLE, covering columns added later.
--
-- cp_session_by_token (0003_auth_bootstrap.sql) is RETURNS SETOF user_session with SELECT *,
-- so it carries the new column automatically — no change to the bootstrap function or its grants.
--
-- Idempotent (IF NOT EXISTS) so re-applying the migration set is safe.

ALTER TABLE user_session ADD COLUMN IF NOT EXISTS remembered boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN user_session.remembered IS
    'True when the login explicitly opted in to a remembered (long-lived) session at login time '
    '(POST /auth/login {"remember_device": true}), after full password + TOTP verification. '
    'The session manager enforces a fixed 30-day absolute TTL and 7-day idle timeout for these '
    'sessions, versus the ordinary 12h / 30-min defaults. Set only at session creation; never '
    'promoted retroactively. The client UA is never trusted for this decision — only this persisted '
    'flag is consulted. Password or email changes issue an ordinary replacement session (remembered '
    '= false); re-opting in requires a new login.';
