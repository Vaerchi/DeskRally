-- Backstage audit-chain central storage (Milestone H2).
--
-- The agent builds a SHA-256 hash-chained audit trail per backstage session
-- (agent/src/backstage/audit.rs) and returns each event to the controller in the backstage
-- Envelope. H2 forwards that chain to the control plane, which stores it here — append-only and
-- tamper-evident — via POST /audit/ingest. This is the management-plane's copy of the agent-side
-- schema in agent/migrations/0001_backstage_audit.sql; it lives in the control-plane DB and obeys
-- the SAME Row-Level Security contract as every table in 0001_core.sql / 0002_auth.sql:
--     tenant_id on every row, ENABLE + FORCE RLS, and
--       USING/WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid)
-- so a forgotten WHERE clause can never leak or cross-write another MSP's audit trail.
--
-- Tamper-evidence stored here = chain LINKAGE: the per-session monotonic `seq` plus the
-- `prev_hash`/`hash` pointer chain. On ingest the control plane verifies each batch links onto the
-- stored tail (or starts a fresh chain at seq 0 with an empty prev_hash) and rejects reorderings,
-- deletions, gaps, and replays. UNIQUE(session_id, seq) is the DB backstop against a replayed or
-- concurrent duplicate. Cross-language CONTENT re-hashing (Go recomputing Rust's SHA-256 preimage
-- byte-for-byte to prove the fields themselves were not altered) SHIPPED in H2b — see
-- control-plane/audit_canonical.go and verifyLinkage; this paragraph used to say it was deferred.
--
-- Migration 0019 adds `ingest_seq`, the per-tenant append counter the SIEM export pages on. `seq`
-- restarts at 0 for every session, so it can order a chain but never the tenant's trail.

-- -------------------------------------------------------------------------------------
-- backstage_audit_event — one forwarded agent audit event. Append-only: the application is
-- granted INSERT/SELECT only (never UPDATE/DELETE); retention/purge runs as a separate privileged
-- job. `session_id` is the agent's backstage session id; it is intentionally NOT a foreign key to
-- session_record so audit can be ingested independently of management-plane session brokering.
-- -------------------------------------------------------------------------------------
CREATE TABLE backstage_audit_event (
    id             uuid        NOT NULL,                 -- the agent's event id (AuditEvent.id)
    tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    session_id     uuid        NOT NULL,                 -- agent backstage session id
    seq            bigint      NOT NULL,                 -- per-session monotonic sequence (from seq 0)
    technician_id  uuid        NOT NULL,
    machine_id     uuid        NOT NULL,
    -- Agent monotonic clock, epoch milliseconds, stored verbatim so the exact value that fed the
    -- hash preimage is preserved for H2b content re-hashing (a timestamptz would lose that).
    occurred_at_ms bigint      NOT NULL,
    action         jsonb       NOT NULL,                 -- serialized AuditAction (no secrets)
    outcome        jsonb       NOT NULL,                 -- Ok | Denied{reason} | Failed{error}
    prev_hash      text        NOT NULL,                 -- hex SHA-256 of the predecessor ("" at seq 0)
    hash           text        NOT NULL,                 -- hex SHA-256 of this event
    -- Control-plane receipt clock, distinct from the agent's occurred_at_ms.
    ingested_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, session_id, seq),
    -- The chain backstop: a session's seq is unique, so a replayed/edited batch cannot re-insert.
    UNIQUE (session_id, seq)
);

-- Hot query path: "show me everything on this machine, newest first" and per-session replay.
CREATE INDEX idx_backstage_audit_machine_time ON backstage_audit_event (tenant_id, machine_id, occurred_at_ms DESC);
CREATE INDEX idx_backstage_audit_session_seq  ON backstage_audit_event (session_id, seq);

-- =====================================================================================
-- Row-Level Security — identical contract to 0001_core.sql / 0002_auth.sql.
-- =====================================================================================
ALTER TABLE backstage_audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE backstage_audit_event FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON backstage_audit_event
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Append-only from the application's perspective: grant INSERT/SELECT, never UPDATE/DELETE, to the
-- app role once it exists (role grants belong in a later migration, matching 0001/0002 convention).
