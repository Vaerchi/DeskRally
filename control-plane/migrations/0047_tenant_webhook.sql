-- 0047_tenant_webhook.sql — per-tenant webhook endpoints for event-driven automation
-- (docs/01 §8 "Webhooks / event-driven triggers", P1 backlog item).
--
-- Operators register one or more HTTPS endpoints (webhooks) that receive a POST request when
-- management-plane audit events occur. The canonical use case is MSP automation: create a
-- ticketing-system ticket when a session starts, send a Slack notification when a recording
-- ends, etc. Each webhook has:
--
--   url     — the HTTPS endpoint to deliver to (validated at the app layer, max 2048 chars).
--   secret  — a 32-byte random value (hex-encoded, 64 chars), generated server-side and
--             returned ONCE at creation. Never returned again by the API. Stored plaintext
--             so the control plane can compute HMAC-SHA256(body, secret) on each delivery.
--   events  — the audit action strings to subscribe to (e.g. '{"session.start","session.end"}').
--             An empty array means "all events". Validated at the app layer (max 20 items).
--
-- DELIVERY. The dispatcher fires an HTTP POST with:
--   Content-Type: application/json
--   X-DeskRally-Signature: sha256=<hex(HMAC-SHA256(body, secret))>
--   X-DeskRally-Webhook-ID: <webhook id>
-- The body is the MgmtAuditEvent JSON. On non-2xx or network failure the dispatcher retries
-- once after 1 s and then gives up (fire-and-forget; no persistent delivery queue).
--
-- LIMITS (app layer): max 10 webhooks per tenant; max 20 events per webhook; URL max 2048 chars.
-- Not enforced in DB because they are product limits that may change without a migration.
--
-- SECRET DESIGN. We store the secret in plaintext because the HMAC signing key must be
-- recoverable to compute the signature on each delivery. The secret is NOT a user credential;
-- it is a SIGNING KEY. It never appears in GET /tenant/webhooks responses — only in the
-- 201 body at creation, like enrollment-token plaintext (0013) and API-token secrets (0016).
-- A db-level SECURITY DEFINER function is not used because the secret column is access-gated
-- by the standard RLS tenant_isolation policy (only rmt_app with the correct GUC can read it).
--
-- RLS. The standard tenant_isolation policy is applied (same as every other tenant-scoped
-- table since 0001_core.sql). The FK ON DELETE CASCADE removes all webhooks when the tenant
-- is deleted. Cross-tenant write isolation is enforced by the RLS policy's WITH CHECK clause.

CREATE TABLE tenant_webhook (
    id         UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    url        TEXT        NOT NULL CHECK (char_length(url) <= 2048),
    secret     TEXT        NOT NULL,
    events     TEXT[]      NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id)
);

-- RLS — every read and write is scoped to the current tenant's rows.
ALTER TABLE tenant_webhook ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_webhook
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Grant — conditional so the migration runs cleanly on a fresh DB without the rmt_app role.
-- No UPDATE: webhooks are immutable after creation; change = delete and re-create.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, DELETE ON tenant_webhook TO rmt_app;
  END IF;
END $$;
