-- 0062: expiring access (docs/56).
--
-- A membership may carry an expiry. NULL = never expires, which every existing row keeps (no backfill).
-- A membership whose expires_at has passed grants NOTHING: GrantFor (pgstore.go): the single place a
-- principal's grant is resolved, on every authenticated request and every session-lease renewal -
-- filters `expires_at IS NULL OR expires_at > statement_timestamp()`. The admin paths read the STORED
-- rows (expired included) so expiry never lowers who may edit a user (docs/56 sec. 4).
--
-- No index: GrantFor reads one user's handful of rows through idx_membership_user.

ALTER TABLE membership ADD COLUMN expires_at timestamptz;

COMMENT ON COLUMN membership.expires_at IS
    'docs/56: when this membership stops granting (NULL = never). Enforced by GrantFor on the DB clock; '
    'Owner memberships never carry one (handler + the permanent-Owner invariant).';
