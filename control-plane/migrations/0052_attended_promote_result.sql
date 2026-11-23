-- 0052: attended promote result — durable storage for the guest's install outcome.
--
-- The four nullable columns track:
--   promote_requested_at: when the technician first stashed a promote token for the CURRENT
--                         attempt. Set by SetPromoteToken(non-empty); cleared by SetPromoteToken("")
--                         (explicit revocation). NOT cleared by End() — an install that began
--                         before session end may still report its result within the grace window.
--   promote_result_success, promote_result_error, promote_result_at: the guest-reported outcome
--                         for the current attempt. Cleared by SetPromoteToken(non-empty) on retry
--                         so the UI sees the new attempt's result, not the previous one.
--
-- Attempt binding invariants enforced by cp_attended_set_promote_result:
--   1. promote_requested_at IS NULL → FALSE (no promote was authorized, or it was revoked)
--   2. state IN ('pending','redeemed') → FALSE (no promote could have been requested)
--   3. promote_result_at IS NOT NULL → FALSE (already written; first completion wins)
--   4. state = 'ended' AND now() > ended_at + 30 min → FALSE (post-end grace expired)
--
-- RLS: attended_session already has a tenant-isolation policy (0013). The SET is keyed by attend
-- token (pre-tenant, like cp_attended_consent), so it must use a SECURITY DEFINER function.
--
-- Migration is idempotent: IF NOT EXISTS guards prevent re-run failures in dev reset cycles.

ALTER TABLE attended_session
    ADD COLUMN IF NOT EXISTS promote_requested_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS promote_result_success BOOLEAN,
    ADD COLUMN IF NOT EXISTS promote_result_error   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS promote_result_at      TIMESTAMPTZ,
    -- Minted by SetPromoteToken on each new or retry attempt; compared by cp_attended_set_promote_result
    -- to bind a result to the exact attempt that produced it. A delayed old attempt's result must carry
    -- the nonce it received via status poll; a mismatch → FALSE (conflict) before no-overwrite fires.
    ADD COLUMN IF NOT EXISTS promote_attempt_nonce  TEXT NOT NULL DEFAULT '';

-- cp_attended_set_promote_result: atomically record the guest's install outcome, keyed by attend
-- token (the same pre-tenant token the guest holds for consent/status callbacks).
--
-- Returns:
--   TRUE  = result written successfully
--   FALSE = conflict: no authorized promote, nonce mismatch, result already written, or grace expired
--   NULL  = invalid/unknown token (caller maps → ErrAttendedInvalid)
--
-- Attempt binding (evaluated in order):
--   • promote_requested_at IS NULL → revoked or never issued → FALSE
--   • state IN ('pending','redeemed') → impossible to have promoted → FALSE
--   • p_attempt_nonce != promote_attempt_nonce → old attempt, nonce mismatch → FALSE
--     (a delayed old result must not claim the slot of a new attempt whose nonce is different)
--   • promote_result_at IS NOT NULL → first completion wins, no overwrite → FALSE
--   • state != 'ended' AND promote_requested_at < now() - 24h → attempt is stale → FALSE
--     (for sessions still active but holding an ancient promote_requested_at)
--   • state='ended' AND now() > ended_at + 30 min → post-end grace expired → FALSE
--
-- SECURITY DEFINER so the UPDATE bypasses the tenant-isolation RLS policy: the guest holds only
-- its attend token and has no tenant context, exactly as with cp_attended_consent/cp_attended_by_token.
CREATE OR REPLACE FUNCTION cp_attended_set_promote_result(
    p_token_hash   bytea,
    p_success      boolean,
    p_error        text,
    p_attempt_nonce text
) RETURNS boolean
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = public, pg_catalog
AS $$
DECLARE
    s attended_session%ROWTYPE;
BEGIN
    SELECT * INTO s FROM attended_session WHERE token_hash = p_token_hash FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;   -- unknown or expired token → ErrAttendedInvalid at the handler
    END IF;
    -- A result is only valid when a promote was actually authorized and not revoked.
    -- promote_requested_at IS NULL means either the promote was never issued (consented/active
    -- sessions with no SetPromoteToken call) or it was explicitly revoked (SetPromoteToken("")).
    IF s.promote_requested_at IS NULL THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    -- pending/redeemed: a promote could not have been requested in these states.
    IF s.state IN ('pending', 'redeemed') THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    -- Attempt identity: the nonce the guest received via its status poll must match the one minted
    -- when SetPromoteToken was called. A delayed old attempt carries the old nonce; if the technician
    -- re-issued (new nonce), the old attempt's result is rejected here BEFORE the no-overwrite guard
    -- can wrongly block the new attempt's result. Both "" values are treated as matching (pre-nonce
    -- server and pre-nonce client, for migration compatibility — they cannot have different nonces).
    IF s.promote_attempt_nonce != '' AND p_attempt_nonce != s.promote_attempt_nonce THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    -- First completion wins: do not overwrite an already-written result.
    -- This prevents a stale first-attempt result from overwriting a second attempt's success,
    -- and prevents the same guest calling promote-complete multiple times from corrupting the record.
    IF s.promote_result_at IS NOT NULL THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    -- Age bound for sessions that haven't ended: if the promote was requested more than 24 hours
    -- ago and the session is still active, the attempt is too old to be the current one.
    -- Ended sessions use the 30-minute post-end grace instead (below).
    IF s.state != 'ended' AND now() > s.promote_requested_at + INTERVAL '24 hours' THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    -- Bounded post-end grace: an ended session accepts results for up to 30 minutes after ended_at.
    -- Beyond that window the install is either complete (and already reported) or lost entirely.
    IF s.state = 'ended' AND s.ended_at IS NOT NULL AND now() > s.ended_at + INTERVAL '30 minutes' THEN
        RETURN FALSE;  -- → ErrAttendedPromoteCompleteConflict
    END IF;
    UPDATE attended_session
       SET promote_result_success = p_success,
           promote_result_error   = p_error,
           promote_result_at      = now()
     WHERE token_hash = p_token_hash;
    RETURN TRUE;
END $$;

GRANT EXECUTE ON FUNCTION cp_attended_set_promote_result(bytea, boolean, text, text) TO PUBLIC;
