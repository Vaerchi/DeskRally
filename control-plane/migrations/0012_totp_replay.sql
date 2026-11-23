-- TOTP codes become single-use (RFC 6238 §5.2). Extends migrations/0002_auth.sql.
--
-- WHY: verification accepts the whole ±skew window (control-plane/totp.go), so with a 30-second
-- period and one step of drift each code is valid for about 90 seconds — and nothing recorded that
-- a code had already been spent. One observed code (shoulder-surfed, phished into a real login,
-- read from a proxy log, or replayed from a captured request) therefore authenticated repeatedly
-- for the rest of that window. RFC 6238 §5.2 is explicit that a previously accepted OTP must be
-- rejected.
--
-- `last_step` is the RFC 4226 counter (unix_time / period) of the most recent code this user
-- successfully authenticated with. Login accepts a code only when its step is STRICTLY GREATER,
-- and the compare-and-set is one UPDATE ... WHERE last_step < $step, so two concurrent logins
-- presenting the same code cannot both win: the second matches no row and fails closed.
--
-- Deliberately monotonic and NOT reset when the secret is replaced: time only moves forward, so
-- refusing steps at or before the last accepted one never rejects a genuinely fresh code from a
-- later time step, and keeping it monotonic means a re-enrollment cannot be used to rewind the
-- replay window.
--
-- No RLS work is needed: user_totp already has ENABLE + FORCE RLS and the tenant_isolation policy
-- from 0002, and 0005 grants rmt_app DML on all tables (column privileges are not per-column).

ALTER TABLE user_totp ADD COLUMN last_step bigint;

COMMENT ON COLUMN user_totp.last_step IS
    'RFC 4226 counter of the most recently accepted login code. A code whose step is <= this value '
    'is a replay and MUST be rejected (RFC 6238 §5.2). NULL until the first TOTP login.';
