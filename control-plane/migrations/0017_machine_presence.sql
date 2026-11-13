-- Machine record enrichment for the access panel (docs/01 §4).
--
-- The console's machine list needs three facts the `machine` table never carried:
--
--   1. PRESENCE — "is this agent online right now". The authoritative answer lives in the
--      signaling registry (an agent is online exactly when the broker could reach it), which the
--      control plane now reads through the service-token-gated GET /internal/presence
--      (server/signaling/presence.go). That is a LIVE read; this column is its DURABLE shadow.
--
--      Why persist it at all when the live feed exists: the live feed answers "up NOW" and nothing
--      else. The moment an agent disconnects it simply vanishes from the registry, so "offline for
--      3 hours" — the fact a technician actually acts on — is unanswerable from the feed alone, and
--      is lost entirely when signaling restarts. Recording last_seen on every presence read turns
--      an instantaneous signal into a history without any agent-side change.
--
--   2. OS — captured at enrollment (POST /enroll/redeem), because that is the one moment the agent
--      is already talking to the control plane and already reporting facts about itself. Kept as
--      free text: it is a display label, never anything authorization keys on.
--
--   3. The machine's GROUP NAME, which the API previously exposed only as a raw uuid. That needs no
--      column — machine_group.name already exists and is joined at read time.
--
-- RLS: no new policy. Both columns are added to `machine`, which already has ENABLE + FORCE ROW
-- LEVEL SECURITY and its tenant_isolation policy from 0001_core.sql, so every read and write of
-- them is confined to the pinned tenant exactly like the rest of the row. No new grants either:
-- 0005_app_role.sql grants rmt_app DML on the TABLE, and a column added later is covered by it.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS) so re-applying the migration set is safe.

ALTER TABLE machine ADD COLUMN IF NOT EXISTS last_seen timestamptz;
ALTER TABLE machine ADD COLUMN IF NOT EXISTS os        text NOT NULL DEFAULT '';

-- The access panel's default view is "online first, then most-recently-seen", scoped to a tenant.
CREATE INDEX IF NOT EXISTS idx_machine_last_seen ON machine (tenant_id, last_seen DESC);

COMMENT ON COLUMN machine.last_seen IS
    'Last time the signaling presence feed reported this device connected. NULL = never seen online '
    'since this column existed. Written by the control plane on each presence read, never by the agent.';
COMMENT ON COLUMN machine.os IS
    'Free-text OS label reported by the agent at enrollment. Display only — never authorization input.';
