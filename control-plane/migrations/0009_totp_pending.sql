-- TOTP re-enrollment gets a PENDING slot, so arming a new authenticator can never disarm 2FA.
-- Extends migrations/0002_auth.sql.
--
-- WHY: POST /auth/totp/enroll used to overwrite `secret` and NULL `confirmed_at` (the upsert in
-- PgUserStore.SetTOTP). Because login only enforces a CONFIRMED enrollment, a single enroll call
-- that was never confirmed — an abandoned re-enroll, or one made by whoever holds a stolen session
-- cookie or an XSS foothold — permanently downgraded the account to password-only, silently.
--
-- With `pending_secret`, enrollment writes ONLY the pending slot: the confirmed secret keeps
-- enforcing 2FA until a valid code for the pending one is presented, at which point
-- cp-side ConfirmPendingTOTP promotes pending → secret and stamps confirmed_at. Re-enrolling while
-- a confirmed secret exists additionally requires a valid CURRENT code (auth.go), so a session
-- compromise cannot be converted into a persistent authentication downgrade.
--
-- No RLS work is needed: user_totp already has ENABLE + FORCE RLS and the tenant_isolation policy
-- from 0002, and 0005 grants rmt_app DML on all tables (column privileges are not per-column).

ALTER TABLE user_totp ADD COLUMN pending_secret bytea;

COMMENT ON COLUMN user_totp.pending_secret IS
    'Unconfirmed re-enrollment secret. Promoted into `secret` (and confirmed_at stamped) only when '
    'the user proves possession with a valid code; NULL otherwise. Never enforced at login.';
