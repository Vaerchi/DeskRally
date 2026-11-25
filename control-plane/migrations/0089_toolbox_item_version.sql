-- Toolbox version history (decision 2026-11-24): every saved version of an item's script, so an edit can be compared
-- and a previous body restored. A row is written in the SAME transaction as the item insert/update (pgstore_toolbox.go),
-- so the newest row always equals the item. Deleting an item deletes its history. At most the newest 50 versions per
-- item are kept (pruned in the update transaction).
--
-- Bodies live here, not in the audit trail: audit events are forwarded to webhooks and archives, and a script body
-- does not belong in either.

-- The composite FK needs UNIQUE (tenant_id, id) on toolbox_item: a plain FK to toolbox_item(id) would let a write name
-- another tenant's item, because FK checks bypass RLS (same reasoning as 0056 for app_user).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'toolbox_item_tenant_id_id_key') THEN
        ALTER TABLE toolbox_item ADD CONSTRAINT toolbox_item_tenant_id_id_key UNIQUE (tenant_id, id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS toolbox_item_version (
    tenant_id     uuid        NOT NULL,
    item_id       uuid        NOT NULL,
    version       bigint      NOT NULL CHECK (version >= 1),
    name          text        NOT NULL,
    description   text        NOT NULL,
    shell         text        NOT NULL,
    run_as        text        NOT NULL,
    body          text        NOT NULL,
    body_sha256   text        NOT NULL,
    saved_by      uuid        NULL,
    saved_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, item_id, version),
    CONSTRAINT toolbox_item_version_item FOREIGN KEY (tenant_id, item_id)
        REFERENCES toolbox_item (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE toolbox_item_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE toolbox_item_version FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON toolbox_item_version;
CREATE POLICY tenant_isolation ON toolbox_item_version
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
GRANT SELECT, INSERT, DELETE ON toolbox_item_version TO rmt_app;

-- Existing items start their history at their current version.
INSERT INTO toolbox_item_version (tenant_id, item_id, version, name, description, shell, run_as, body, body_sha256, saved_at)
SELECT tenant_id, id, version, name, description, shell, run_as, body, body_sha256, updated_at
FROM toolbox_item
ON CONFLICT DO NOTHING;
