-- 0056: Shared Toolbox v1 (docs/design-shared-toolbox.md, Codex-accepted 2026-10-16).
--
-- A tenant's library of saved scripts. owner_user_id NULL = SHARED (managed with manage_toolbox);
-- otherwise PERSONAL to that user. Scope and owner are immutable after creation (no UPDATE path
-- touches them). Personal visibility is NOT an RLS concern (RLS is per tenant): every store query
-- carries `owner_user_id IS NULL OR owner_user_id = <caller>`, and the tests pin it.
--
-- The body is code. Its shape rules (strict UTF-8, no U+0000, cmd single line and at most 7 800
-- UTF-16 units, PowerShell at most 16 384 bytes) are enforced in Go, which can count UTF-16 units;
-- the CHECK below is a per-shell BYTE backstop sized so no valid body can trip it (7 800 units x at
-- most 4 UTF-8 bytes = 31 200).
--
-- The composite FK (tenant_id, owner_user_id) -> app_user(tenant_id, id) pins a personal item's
-- owner to the same tenant: a plain FK to app_user(id) would let a write name another tenant's user,
-- because FK checks bypass RLS. app_user gains the UNIQUE (tenant_id, id) the FK needs.
--
-- Idempotent.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'app_user_tenant_id_id_key') THEN
        ALTER TABLE app_user ADD CONSTRAINT app_user_tenant_id_id_key UNIQUE (tenant_id, id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS toolbox_item (
    id            uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    owner_user_id uuid        NULL,
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    description   text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    shell         text        NOT NULL CHECK (shell IN ('powershell', 'cmd')),
    run_as        text        NOT NULL CHECK (run_as IN ('system', 'user')),
    body          text        NOT NULL,
    body_sha256   text        NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    version       bigint      NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by    uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    uuid        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT toolbox_item_body_bytes CHECK (
        (shell = 'powershell' AND octet_length(body) BETWEEN 1 AND 16384) OR
        (shell = 'cmd'        AND octet_length(body) BETWEEN 1 AND 31200)),
    CONSTRAINT toolbox_item_owner_same_tenant FOREIGN KEY (tenant_id, owner_user_id)
        REFERENCES app_user (tenant_id, id) ON DELETE CASCADE
);

-- One name per scope: shared names are unique among shared items, personal names per owner.
CREATE UNIQUE INDEX IF NOT EXISTS toolbox_item_name
    ON toolbox_item (tenant_id, coalesce(owner_user_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));

ALTER TABLE toolbox_item ENABLE ROW LEVEL SECURITY;
ALTER TABLE toolbox_item FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON toolbox_item;
CREATE POLICY tenant_isolation ON toolbox_item
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON toolbox_item TO rmt_app;
    END IF;
END
$$;
