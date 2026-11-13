-- 0016_audit_chain_integrity.sql — close two ways the management audit chain (0014) can be made
-- to lie, both found by an adversarial "false tamper" review of the chain shipped in 0014.
--
-- Background: the chain's whole value is that GET /audit/verify answers "has anything been
-- altered?" truthfully. It fails in BOTH directions if the schema lets a hashed field change
-- without the hash changing (false POSITIVE — verify cries tamper on an honest trail) or lets a
-- row hide from the walk (false NEGATIVE — verify says "intact, fully covered" over a planted
-- row). 0006 revokes UPDATE/DELETE on audit_event from rmt_app, so a false positive is
-- PERMANENT: nothing can ever repair the row back into agreement with its hash.

-- =====================================================================================
-- 1. actor_user_id must never be rewritten under the chain.
-- =====================================================================================
-- 0001_core.sql declared `actor_user_id uuid REFERENCES app_user(id) ON DELETE SET NULL`, and
-- actor_user_id is INSIDE the hashed preimage (mgmtaudit_canonical.go). So deleting any app_user
-- makes PostgreSQL's referential-action trigger run
--     UPDATE audit_event SET actor_user_id = NULL WHERE actor_user_id = <that user>
-- on every audit row that user ever generated. That UPDATE runs with the referencing table's
-- OWNER privileges and bypasses RLS, so neither 0006's REVOKE nor the tenant policy stops it —
-- and it leaves seq/prev_hash/hash untouched. Verify then re-hashes lpStr("") where lpStr(uuid)
-- was hashed, and reports "a field was altered" forever, for that event and every event after it.
-- Ordinary user offboarding (or a GDPR erasure) would silently destroy the tenant's audit
-- attestation.
--
-- The fix is to DROP the foreign key rather than re-point it at NO ACTION. An audit trail records
-- WHAT HAPPENED, and that record must outlive the actor: NO ACTION would instead make every
-- audited user undeletable, turning the audit trail into a retention lock on app_user. Dropping
-- the FK makes actor_user_id an opaque recorded identifier — exactly what target_id already is in
-- this same table (`target_id uuid` has never had a FK). A dangling actor id is the correct
-- outcome: the event genuinely was performed by that principal, whether or not the row survives.
--
-- Note the surviving FK, `tenant_id ... ON DELETE CASCADE`, is SAFE for this purpose: it deletes
-- whole rows rather than rewriting a hashed field, so it cannot produce a false tamper (deleting
-- a tenant removes its chain entirely, which is the intended semantic).
ALTER TABLE audit_event DROP CONSTRAINT IF EXISTS audit_event_actor_user_id_fkey;

COMMENT ON COLUMN audit_event.actor_user_id IS
    'The principal that performed the action. Deliberately NOT a foreign key: this value is '
    'covered by the mgmt-audit v1 hash, so any referential action that rewrote it (e.g. '
    'ON DELETE SET NULL) would permanently false-tamper the chain. See 0016.';

-- =====================================================================================
-- 2. A chained row must not be able to hide from the walk.
-- =====================================================================================
-- 0014 constrained seq only by the all-or-none CHECK and UNIQUE(tenant_id, seq) — nothing
-- required it to be non-negative. Every read path that the tamper-evidence story rests on starts
-- its cursor at -1 and filters `seq > cursor`, so a row planted at seq = -1 is invisible to
-- GET /audit/verify AND to the NDJSON export, while CountUnchained (which looks for seq IS NULL)
-- does not report it either. The result: a planted row that GET /audit lists as a genuine event
-- while verify reports {ok:true, unchained_events:0} — a clean bill of health over forged data,
-- which is worse than no chain at all. That is precisely the "privileged writer" threat 0014
-- names as its reason to exist.
ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_seq_nonneg CHECK (seq IS NULL OR seq >= 0);

-- Shape guards on the chain fields themselves, so a row cannot be planted with a syntactically
-- impossible link that the walker would have to interpret. Genesis carries prev_hash = '' by
-- convention (MgmtGenesisPrevHash); every other link is lower-hex SHA-256.
ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_hash_format CHECK (hash IS NULL OR hash ~ '^[0-9a-f]{64}$');
ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_prev_hash_format CHECK (
        prev_hash IS NULL OR prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$'
    );
