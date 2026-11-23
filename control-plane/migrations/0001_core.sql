-- Control-plane core schema — multi-tenant management API.
--
-- Implements docs/02-architecture.md ADR-003: ONE Postgres schema, shared by every
-- tenant, with a tenant_id on every tenant-scoped row and PostgreSQL Row-Level Security
-- as the cross-tenant safety net. Self-hosted is exactly one tenant row — the same code,
-- the same schema, no `if self_hosted` branches.
--
-- =====================================================================================
-- ROW-LEVEL SECURITY STRATEGY (read this before touching any table below)
-- =====================================================================================
-- Every request runs on a connection whose current tenant has been pinned with
--     SET LOCAL app.current_tenant = '<uuid>';
-- issued by the tenant middleware (see http.go) inside the request transaction. Every
-- tenant-scoped table then carries a policy of the exact form:
--     USING (tenant_id = current_setting('app.current_tenant')::uuid)
-- so the database itself filters every SELECT/UPDATE/DELETE to the caller's tenant. A
-- bug in application code (a forgotten `WHERE tenant_id = ...`) can therefore never leak
-- another MSP's machines or audit trail: RLS makes the cross-tenant row invisible.
--
-- Rules that keep this guarantee honest:
--   * The application connects as a NON-superuser, NON-owner role. RLS is bypassed by
--     table owners and superusers (unless FORCE ROW LEVEL SECURITY is set), so the app
--     role must be neither. We additionally FORCE RLS on every table so that even the
--     owner is subject to it — defense in depth against a mis-scoped connection.
--   * `current_setting('app.current_tenant')` with no second arg RAISES if the GUC was
--     never set. That is intentional: a query that reaches the DB without the tenant
--     middleware having run fails loudly instead of returning every tenant's rows.
--   * WITH CHECK mirrors USING on writable tables so a row can never be INSERTed or
--     UPDATEed into a different tenant than the one currently pinned.
--   * The `tenant` table itself is scoped to `id = current_setting(...)`, so a tenant can
--     only ever read its own tenant row. Tenant provisioning runs as a privileged job
--     that bypasses RLS.
--   * `role` holds global preset roles (tenant_id IS NULL) plus optional per-tenant
--     custom roles; its policy admits either, so presets are visible to everyone while
--     custom roles stay tenant-private.
-- =====================================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

-- -------------------------------------------------------------------------------------
-- tenant — the isolation anchor. Self-hosted deployments have exactly one row here.
-- -------------------------------------------------------------------------------------
CREATE TABLE tenant (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            text NOT NULL UNIQUE,          -- URL/config-safe short name
    name            text NOT NULL,
    deployment_mode text NOT NULL DEFAULT 'saas'   -- 'saas' | 'self_hosted'
                        CHECK (deployment_mode IN ('saas', 'self_hosted')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    disabled_at     timestamptz
);

-- -------------------------------------------------------------------------------------
-- app_user — a human principal within a tenant. Authenticated via OIDC (Zitadel); the
-- external identity provider's subject is stored so sessions map back to a user row.
-- -------------------------------------------------------------------------------------
CREATE TABLE app_user (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    external_subject  text,                        -- OIDC `sub`; NULL until first login
    email             text NOT NULL,
    display_name      text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    disabled_at       timestamptz,
    UNIQUE (tenant_id, email),
    UNIQUE (tenant_id, external_subject)
);

-- -------------------------------------------------------------------------------------
-- role — capability preset. The five preset rows (tenant_id IS NULL) are seeded below and
-- are the source of truth mirrored by rbac.go. Custom per-tenant roles may be added later
-- with tenant_id set. `capabilities` is the authoritative capability list for the role.
-- -------------------------------------------------------------------------------------
CREATE TABLE role (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid REFERENCES tenant(id) ON DELETE CASCADE,  -- NULL = global preset
    key           text NOT NULL,                  -- 'owner' | 'admin' | ...
    name          text NOT NULL,
    is_preset     boolean NOT NULL DEFAULT false,
    capabilities  text[] NOT NULL DEFAULT '{}',   -- capability keys (see rbac.go)
    created_at    timestamptz NOT NULL DEFAULT now()
);
-- A preset key is globally unique; a custom key is unique within its tenant.
CREATE UNIQUE INDEX role_preset_key   ON role (key) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX role_tenant_key   ON role (tenant_id, key) WHERE tenant_id IS NOT NULL;

-- -------------------------------------------------------------------------------------
-- machine_group — the unit RBAC scopes against. A membership may be limited to one or
-- more groups; a machine belongs to exactly one group. Groups may be nested (a tree) and
-- are used both for machines and for grouping sessions.
-- -------------------------------------------------------------------------------------
CREATE TABLE machine_group (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    parent_id   uuid REFERENCES machine_group(id) ON DELETE SET NULL,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)                         -- lets machine FK carry tenant_id too
);

-- -------------------------------------------------------------------------------------
-- membership — binds a user to a role within a tenant, optionally scoped to a subset of
-- machine groups. An empty `scoped_group_ids` means "all groups in the tenant"; a
-- non-empty array limits the grant to those groups (see Grant.RequireMachine in rbac.go).
-- -------------------------------------------------------------------------------------
CREATE TABLE membership (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id           uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id           uuid NOT NULL REFERENCES role(id),
    scoped_group_ids  uuid[] NOT NULL DEFAULT '{}',  -- '{}' = all groups (tenant-wide)
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, role_id)
);
CREATE INDEX idx_membership_user ON membership (tenant_id, user_id);

-- -------------------------------------------------------------------------------------
-- machine — an enrolled agent endpoint. `device_id` is the stable agent identity
-- (ADR-002: agents get stable IDs, not IPs); `pubkey` is the agent's long-term Ed25519
-- public key (ADR-004), registered at enrollment and pinned thereafter.
-- -------------------------------------------------------------------------------------
CREATE TABLE machine (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    device_id    text NOT NULL,                    -- stable agent identity
    group_id     uuid NOT NULL,
    hostname     text NOT NULL DEFAULT '',
    os           text NOT NULL DEFAULT '',
    pubkey       bytea NOT NULL,                   -- Ed25519 long-term public key
    last_seen    timestamptz,
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    status       text NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'quarantined', 'retired')),
    UNIQUE (tenant_id, device_id),
    -- Composite FK guarantees a machine's group lives in the SAME tenant as the machine,
    -- closing a cross-tenant group-assignment hole RLS alone would not catch on writes.
    FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group (tenant_id, id)
);
CREATE INDEX idx_machine_group ON machine (tenant_id, group_id);

-- -------------------------------------------------------------------------------------
-- enrollment_token — a bearer secret an installer presents to enroll a new agent into a
-- tenant + group. Only a hash is stored; the plaintext is shown once at creation.
-- -------------------------------------------------------------------------------------
CREATE TABLE enrollment_token (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    group_id    uuid NOT NULL,
    token_hash  bytea NOT NULL,                    -- SHA-256 of the bearer secret
    created_by  uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    max_uses    int NOT NULL DEFAULT 1,
    uses        int NOT NULL DEFAULT 0,
    revoked_at  timestamptz,
    UNIQUE (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, group_id) REFERENCES machine_group (tenant_id, id)
);

-- -------------------------------------------------------------------------------------
-- session_record — one remote-support session. High-volume + time-series; ADR-003 says
-- keep audit/session/metrics in partitioned tables so volume never degrades the console.
-- Partition DDL is omitted from this first cut (partition by month on started_at).
-- -------------------------------------------------------------------------------------
CREATE TABLE session_record (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    machine_id     uuid NOT NULL REFERENCES machine(id) ON DELETE CASCADE,
    technician_id  uuid NOT NULL REFERENCES app_user(id),
    started_at     timestamptz NOT NULL DEFAULT now(),
    ended_at       timestamptz,
    consent_policy text NOT NULL DEFAULT 'unattended',
    source_ip      inet,
    granted_caps   text[] NOT NULL DEFAULT '{}'    -- capabilities the session carried
);
CREATE INDEX idx_session_machine_time ON session_record (tenant_id, machine_id, started_at DESC);

-- -------------------------------------------------------------------------------------
-- audit_event — append-only management-plane audit (distinct from the agent's backstage
-- audit in agent/migrations/0001_backstage_audit.sql). Records who did what in the console:
-- role changes, enrollment, machine retirement, etc.
-- -------------------------------------------------------------------------------------
CREATE TABLE audit_event (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    actor_user_id  uuid REFERENCES app_user(id) ON DELETE SET NULL,
    action         text NOT NULL,                  -- e.g. 'machine.enroll', 'user.role_grant'
    target_kind    text,                           -- 'machine' | 'user' | 'role' | ...
    target_id      uuid,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    source_ip      inet,
    metadata       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_tenant_time  ON audit_event (tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_action       ON audit_event (tenant_id, action);

-- =====================================================================================
-- Enable + FORCE Row-Level Security on every table, then attach the tenant-isolation
-- policy. FORCE makes even the table owner obey the policy (see strategy note above).
-- =====================================================================================
ALTER TABLE tenant           ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant           FORCE  ROW LEVEL SECURITY;
ALTER TABLE app_user         ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_user         FORCE  ROW LEVEL SECURITY;
ALTER TABLE role             ENABLE ROW LEVEL SECURITY;
ALTER TABLE role             FORCE  ROW LEVEL SECURITY;
ALTER TABLE machine_group    ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_group    FORCE  ROW LEVEL SECURITY;
ALTER TABLE membership       ENABLE ROW LEVEL SECURITY;
ALTER TABLE membership       FORCE  ROW LEVEL SECURITY;
ALTER TABLE machine          ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine          FORCE  ROW LEVEL SECURITY;
ALTER TABLE enrollment_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_token FORCE  ROW LEVEL SECURITY;
ALTER TABLE session_record   ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_record   FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_event      ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event      FORCE  ROW LEVEL SECURITY;

-- The tenant row is visible only to itself.
CREATE POLICY tenant_isolation ON tenant
    USING       (id = current_setting('app.current_tenant')::uuid)
    WITH CHECK  (id = current_setting('app.current_tenant')::uuid);

-- Standard tenant-scoped tables: read + write confined to the pinned tenant.
CREATE POLICY tenant_isolation ON app_user
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON machine_group
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON membership
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON machine
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON enrollment_token
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON session_record
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY tenant_isolation ON audit_event
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- role: global presets (tenant_id IS NULL) are readable by everyone; custom roles are
-- tenant-private. Writes are confined to the caller's tenant (presets are seeded by a
-- privileged migration/job, never by the app role).
CREATE POLICY tenant_isolation ON role
    USING (tenant_id IS NULL
           OR tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- =====================================================================================
-- Preset roles — the authoritative source mirrored by rbac.go's rolePresets. Capability
-- keys MUST stay in sync with the Capability constants in rbac.go.
-- =====================================================================================
INSERT INTO role (tenant_id, key, name, is_preset, capabilities) VALUES
  (NULL, 'owner', 'Owner', true, ARRAY[
      'manage_tenant','manage_users','manage_roles','manage_groups',
      'view_machines','manage_machines','deploy_agent','enroll_machine','manage_enrollment',
      'start_session','end_session','backstage_shell','transfer_files',
      'view_sessions','view_audit'
  ]),
  (NULL, 'admin', 'Admin', true, ARRAY[
      'manage_users','manage_roles','manage_groups',
      'view_machines','manage_machines','deploy_agent','enroll_machine','manage_enrollment',
      'start_session','end_session','backstage_shell','transfer_files',
      'view_sessions','view_audit'
  ]),
  (NULL, 'technician', 'Technician', true, ARRAY[
      'view_machines','deploy_agent',
      'start_session','end_session','backstage_shell','transfer_files',
      'view_sessions'
  ]),
  (NULL, 'readonly', 'ReadOnly', true, ARRAY[
      'view_machines','view_sessions'
  ]),
  (NULL, 'auditor', 'Auditor', true, ARRAY[
      'view_machines','view_sessions','view_audit'
  ]);
