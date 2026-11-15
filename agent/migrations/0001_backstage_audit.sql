-- Backstage audit trail — server-side (relay/control-plane) schema.
--
-- Follows the data-layer decision in docs/02-architecture.md: one Postgres schema, every
-- tenant-scoped row carries tenant_id, and Row-Level Security makes cross-tenant reads
-- impossible even if application code has a bug. Self-hosted deployment is simply one tenant.
--
-- The agent emits hash-chained events (see agent/src/backstage/audit.rs). The relay persists
-- them here and may forward to a customer SIEM. The chain hash lets an auditor prove the log
-- was not altered after the fact; storing it also lets us reject a replayed/edited batch.

CREATE TABLE backstage_session (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    machine_id      uuid NOT NULL,
    technician_id   uuid NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    ended_at        timestamptz,
    -- Capabilities the grant carried, for after-the-fact review of what was permitted.
    granted_caps    text[] NOT NULL,
    source_ip       inet,
    consent_policy  text NOT NULL DEFAULT 'unattended'
);

CREATE TABLE backstage_audit_event (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL,
    session_id          uuid NOT NULL REFERENCES backstage_session(id),
    -- Per-session monotonic sequence; a gap proves a deletion.
    seq                 bigint NOT NULL,
    technician_id       uuid NOT NULL,
    machine_id          uuid NOT NULL,
    occurred_at         timestamptz NOT NULL,   -- agent clock
    received_at         timestamptz NOT NULL DEFAULT now(),  -- relay receipt clock
    action              jsonb NOT NULL,          -- serialized AuditAction (no secrets)
    outcome             jsonb NOT NULL,          -- Ok | Denied{reason} | Failed{error}
    prev_hash           text NOT NULL,
    hash                text NOT NULL,
    UNIQUE (session_id, seq)
);

-- Hot query path: "show me everything a technician did on this machine, newest first."
CREATE INDEX idx_audit_machine_time ON backstage_audit_event (tenant_id, machine_id, occurred_at DESC);
CREATE INDEX idx_audit_session_seq  ON backstage_audit_event (session_id, seq);
-- Query inside the JSON action, e.g. all ProcessKill events.
CREATE INDEX idx_audit_action_kind  ON backstage_audit_event ((action ->> 'kind'));

-- Shell transcripts can be large and are append-heavy; keep them in their own partitioned
-- table so transcript volume never degrades the event index. (Partition DDL omitted from the
-- sketch — partition by month on occurred_at.)
CREATE TABLE backstage_shell_chunk (
    id            bigserial PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    session_id    uuid NOT NULL,
    shell_id      uuid NOT NULL,
    seq           bigint NOT NULL,
    direction     text NOT NULL CHECK (direction IN ('input','output')),
    occurred_at   timestamptz NOT NULL,
    data          bytea NOT NULL          -- raw VT bytes; render with a headless xterm for review
);
CREATE INDEX idx_shell_chunk_lookup ON backstage_shell_chunk (session_id, shell_id, seq);

-- ---------------------------------------------------------------------------------------
-- Row-Level Security: the cross-tenant safety net. Every connection sets the current tenant
-- (SET app.current_tenant = '<uuid>') and can only ever see its own rows.
-- ---------------------------------------------------------------------------------------
ALTER TABLE backstage_session       ENABLE ROW LEVEL SECURITY;
ALTER TABLE backstage_audit_event   ENABLE ROW LEVEL SECURITY;
ALTER TABLE backstage_shell_chunk   ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_session ON backstage_session
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_event ON backstage_audit_event
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation_shell ON backstage_shell_chunk
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Audit is append-only from the application's perspective: grant INSERT/SELECT, never
-- UPDATE/DELETE, to the app role. Retention/purge runs as a separate privileged job.
-- (Role grants belong in a later migration once the app roles exist.)
