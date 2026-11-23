-- Preserve the agent signature separately from the canonical v1 event hash.
-- Empty fields identify legacy/self-attested records; migration cannot authenticate history.
ALTER TABLE backstage_audit_event ADD COLUMN IF NOT EXISTS agent_pubkey text NOT NULL DEFAULT '';
ALTER TABLE backstage_audit_event ADD COLUMN IF NOT EXISTS agent_signature text NOT NULL DEFAULT '';
