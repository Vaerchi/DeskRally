-- 0054: durable second-factor generation + session-bound MFA verification (platform-operator design v3,
-- Codex-accepted 2026-10-16). Split from the platform objects (0055) because PgUserStore's projection
-- and the session store read these columns on every authentication.
--
-- app_user.mfa_generation comes from a dedicated sequence and is replaced with nextval() whenever the
-- user's second factor changes (confirm, replace), so a value is never reused. A session records the
-- generation its TOTP code was verified against (user_session.mfa_generation) and when
-- (mfa_verified_at); the update is conditional on that generation still being current. A session
-- from before enrollment, before a re-enrollment, or never MFA-verified, therefore never counts.
-- RLS: no new policy; the columns ride on app_user / user_session's existing policies and grants.

CREATE SEQUENCE IF NOT EXISTS mfa_generation_seq AS bigint MINVALUE 1;

ALTER TABLE app_user ADD COLUMN IF NOT EXISTS mfa_generation bigint NOT NULL DEFAULT 0;
COMMENT ON COLUMN app_user.mfa_generation IS
    'Replaced with nextval(mfa_generation_seq) whenever the second factor changes (confirm, remove, '
    'reset). 0 = never had one. Never reused. A session is MFA-verified only for the generation it '
    'recorded (user_session.mfa_generation).';

ALTER TABLE user_session ADD COLUMN IF NOT EXISTS mfa_verified_at timestamptz;
ALTER TABLE user_session ADD COLUMN IF NOT EXISTS mfa_generation bigint;
COMMENT ON COLUMN user_session.mfa_verified_at IS
    'When a TOTP code was last verified IN this session (login or step-up). NULL = never.';
COMMENT ON COLUMN user_session.mfa_generation IS
    'app_user.mfa_generation the code was verified against. Stale after any second-factor change.';

-- Existing confirmed enrollments get a generation now. Sessions predate the columns, so none is
-- MFA-verified until its user logs in again or steps up.
UPDATE app_user u
   SET mfa_generation = nextval('mfa_generation_seq')
 WHERE u.mfa_generation = 0
   AND EXISTS (SELECT 1 FROM user_totp t
                WHERE t.user_id = u.id AND t.tenant_id = u.tenant_id AND t.confirmed_at IS NOT NULL);
