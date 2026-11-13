-- Credential epoch on user_session — closes the password-change TOCTOU.
--
-- THE RACE THIS EXISTS FOR (recorded in HandleChangePassword's doc comment before it was fixed):
-- a login and a password change are separate transactions, and nothing tied a session row to the
-- credential version that authorized it. So this interleaving produced a live session authenticated
-- by a password that had just been retired:
--
--     T1  login       reads user_credential  → password_hash H_old
--     T2  change      UPDATE user_credential → H_new              (commits)
--     T3  change      UPDATE user_session SET revoked_at = now()  (commits — sees no new row yet)
--     T4  login       INSERT user_session                          (lands AFTER the revocation)
--
-- The session inserted at T4 is revoked by nothing, expires in 12 hours, and was authorized by the
-- password the account owner was rotating precisely because they believed it compromised. The
-- window is about one argon2id verification (~100 ms at 64 MiB). Neither reordering nor re-revoking
-- closes it: a revocation happens at SOME instant, and the racing INSERT can always land after it.
--
-- THE FIX is to stop reasoning about instants and compare VERSIONS instead. `user_credential`
-- already carries `updated_at` (0002_auth.sql), which changes on every password write. A session
-- records the credential version it was issued against — read from the SAME row that returned the
-- password hash, so the two cannot disagree — and every authenticated request rejects a session
-- whose recorded version is older than the credential's current one.
--
-- Applied to the timeline above: the T4 session carries the T1 epoch, the credential now carries
-- the T2 epoch, and the very first request that session makes is refused. The racing INSERT still
-- happens; it just produces a session that can never be used.
--
-- WHY A COLUMN RATHER THAN A JOIN. `Authenticate` already loads the user on every request
-- (SessionAuthenticator), so the credential's current epoch is in hand for free; only the session's
-- OWN epoch needed somewhere to live. That makes the check a comparison of two values the request
-- already holds — no extra query on the authentication hot path.
--
-- RLS: no new policy. The column is added to `user_session`, which already has ENABLE + FORCE ROW
-- LEVEL SECURITY and its tenant_isolation policy from 0002_auth.sql. `cp_session_by_token`
-- (0003_auth_bootstrap.sql) is `RETURNS SETOF user_session` and selects `*`, so it carries the new
-- column with no change. No new grants either: 0005_app_role.sql grants rmt_app DML on the TABLE,
-- which covers a column added later.
--
-- Idempotent (IF NOT EXISTS) so re-applying the migration set is safe.

ALTER TABLE user_session ADD COLUMN IF NOT EXISTS credential_epoch timestamptz;

-- NO BACKFILL, DELIBERATELY. Applying this migration signs out everyone who is currently logged in
-- with a local password, exactly once. That is the intended cost.
--
-- The first draft did backfill, setting each live session's epoch to the credential's CURRENT
-- updated_at, and argued it was safe because a password change revokes every session — so a session
-- still live must postdate the last change. The argument does not hold:
--
--   * `HandleChangePassword` writes the credential and revokes in SEPARATE transactions, and it
--     returns 500 if the revocation fails AFTER the password is already changed. Those orphans are
--     live sessions on a retired password — the exact thing this column exists to refuse.
--   * A session created by the pre-0018 race is indistinguishable from a legitimate one at
--     migration time. Backfilling would stamp it "current" and grant it the rest of its 12 hours,
--     laundering the very sessions the fix was written for.
--
-- More simply: for a pre-0018 session we do not KNOW which credential version authorized it, and
-- writing a value we do not know is a fabrication. `credential_epoch` means "the version this
-- session was authorized by"; asserting the current version because it is convenient would make the
-- column lie in precisely the case that matters. Leaving it NULL says what is true — unknown — and
-- `CredentialEpochMatches` treats unknown as older than any credential, so it fails CLOSED.
--
-- Users with no `user_credential` row (federated-only, or not yet provisioned) keep working with no
-- special case: their credential epoch is also zero, NULL compares equal to it, and the moment a
-- first password IS provisioned their epoch advances and those sessions are correctly refused.
--
-- Operator note: schedule this with a maintenance window or announce a re-login, like any other
-- forced-logout security change. There is nothing to roll back — signing in again is the remedy.

COMMENT ON COLUMN user_session.credential_epoch IS
    'user_credential.updated_at as it was READ IN THE SAME QUERY that returned the password hash '
    'this session was authorized by. Every authenticated request refuses a session whose epoch is '
    'older than the credential''s current updated_at, which is what stops a login racing a password '
    'change from producing a session authorized by the retired password. NULL = the version is '
    'UNKNOWN (a session predating migration 0018, deliberately not backfilled) or the user has no '
    'local credential; the application treats NULL as older than any credential, so it fails closed.';
