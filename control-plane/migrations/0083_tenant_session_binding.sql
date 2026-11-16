-- Extend tenant_session_policy (0029) with the tenant's SESSION BINDING policy (docs/69 3.8 step 4, 8.1).
--
--   warn    (the default, and what an absent row means): a session the console cannot verify continues, marked
--           "not verified" in the session tab.
--   require: a session that cannot be verified is refused: the control plane refuses it when the trust material
--           cannot be issued, and the console ends it when the agent's proof is missing or wrong.
--
-- Every tenant starts at warn (Ed, 2026-11-15). The operator flips a tenant to require once its fleet runs the
-- enforcing agent (1.3.31+). The control plane treats an unreadable value as require (docs/69 3.6), and the CHECK
-- keeps any other value out of the column.
--
-- No new grants: rmt_app already has SELECT/INSERT/UPDATE on the table (0029) and RLS confines it per tenant.
--
-- ROLLBACK: ALTER TABLE tenant_session_policy DROP COLUMN session_binding;
ALTER TABLE tenant_session_policy
    ADD COLUMN session_binding text NOT NULL DEFAULT 'warn'
        CONSTRAINT tenant_session_policy_session_binding_chk CHECK (session_binding IN ('warn', 'require'));
