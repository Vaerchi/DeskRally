-- Enrollment-token redemption — the privileged, RLS-bypassing redeem that necessarily runs
-- BEFORE a tenant can be pinned on the request connection.
--
-- Redemption is UNAUTHENTICATED: an installer presents only the bearer secret, so at that
-- moment the tenant is unknown — the token IS the identity. This is exactly the 0003 bootstrap
-- shape (cp_session_by_token): a SECURITY DEFINER function keyed on the SHA-256 of a
-- high-entropy secret, returning just enough (the row, which carries tenant_id + group_id) for
-- the caller to then run every follow-up write tenant-pinned.
--
-- ATOMICITY: validation (not revoked, not expired, uses remaining) and the use-count increment
-- are ONE UPDATE ... WHERE ... RETURNING. Concurrent redemptions of a max_uses token serialize
-- on the row lock and re-evaluate the WHERE clause, so the limit can never be exceeded — no
-- read-then-write window. An invalid token (unknown, revoked, expired, or exhausted) matches
-- no row and the function returns nothing; Go fails closed with one generic "invalid" error and
-- deliberately cannot learn WHICH check failed.
--
-- SECURITY DEFINER hardening as in 0003/0006: apply as the RLS-bypassing owner role,
-- search_path pinned so the body cannot be hijacked.
CREATE FUNCTION cp_enrollment_token_redeem(p_token_hash bytea)
    RETURNS SETOF enrollment_token
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    UPDATE enrollment_token
    SET uses = uses + 1
    WHERE token_hash = p_token_hash
      AND revoked_at IS NULL
      AND expires_at > now()
      AND uses < max_uses
    RETURNING *;
$$;

-- Same grant posture as the 0003/0006 bootstrap functions: EXECUTE to PUBLIC (the app role
-- name is deployment-specific). The function is self-limiting — it keys on an exact token hash
-- only, and the Go handler is the gate for everything that follows.
GRANT EXECUTE ON FUNCTION cp_enrollment_token_redeem(bytea) TO PUBLIC;
