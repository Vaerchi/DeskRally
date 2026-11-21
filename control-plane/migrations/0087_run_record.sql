CREATE TABLE run_record (
    tenant_id         uuid        NOT NULL,
    request_id        uuid        PRIMARY KEY,
    session_id        uuid        NOT NULL,
    machine_id        uuid        NOT NULL,
    device_id         text        NOT NULL,
    device_key_sha256 bytea       CHECK (length(device_key_sha256) = 32),
    technician_id     uuid        NOT NULL,
    source            text        NOT NULL CHECK (source IN ('toolbox', 'command')),
    item_id           uuid,
    item_name         text,
    item_version      bigint,
    item_scope        text        CHECK (item_scope IN ('shared', 'personal')),
    item_owner_id     uuid,
    shell             text        NOT NULL CHECK (shell IN ('powershell', 'cmd')),
    run_as            text        NOT NULL CHECK (run_as IN ('system', 'user')),
    exec_sha256       bytea       NOT NULL CHECK (length(exec_sha256) = 32),
    requested_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    outcome           text        CHECK (outcome IN ('exited', 'timed_out', 'start_failed')),
    exit_code         integer,
    truncated         boolean,
    finished_at       timestamptz,
    receipt_digest    bytea       CHECK (length(receipt_digest) = 32),
    completed_at      timestamptz,
    FOREIGN KEY (tenant_id, machine_id) REFERENCES machine (tenant_id, id),
    FOREIGN KEY (tenant_id, session_id) REFERENCES session_record (tenant_id, id),
    CHECK (
        (source = 'command' AND item_id IS NULL AND item_name IS NULL AND item_version IS NULL
            AND item_scope IS NULL AND item_owner_id IS NULL) OR
        (source = 'toolbox' AND item_id IS NOT NULL AND item_name IS NOT NULL AND item_version IS NOT NULL
            AND item_scope IS NOT NULL AND (item_scope = 'personal') = (item_owner_id IS NOT NULL))
    ),
    CHECK (
        (outcome IS NULL AND exit_code IS NULL AND truncated IS NULL AND finished_at IS NULL
            AND receipt_digest IS NULL AND completed_at IS NULL) OR
        (outcome IS NOT NULL AND truncated IS NOT NULL AND finished_at IS NOT NULL
            AND receipt_digest IS NOT NULL AND completed_at IS NOT NULL
            AND (outcome = 'start_failed') = (exit_code IS NULL)
            AND (outcome <> 'start_failed' OR NOT truncated))
    )
);

CREATE INDEX run_record_by_machine ON run_record (tenant_id, machine_id, requested_at DESC, request_id DESC);
CREATE INDEX run_record_by_item ON run_record (tenant_id, item_id, requested_at DESC, request_id DESC)
    WHERE item_id IS NOT NULL;
CREATE INDEX run_record_by_session ON run_record (tenant_id, session_id);

CREATE FUNCTION check_run_record_session_machine() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.session_record s
        WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.session_id AND s.machine_id = NEW.machine_id
    ) THEN
        RAISE EXCEPTION 'run session does not belong to its machine' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER run_record_session_machine
    BEFORE INSERT OR UPDATE OF tenant_id, session_id, machine_id ON run_record
    FOR EACH ROW EXECUTE FUNCTION check_run_record_session_machine();

ALTER TABLE run_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_record FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON run_record
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE ON run_record TO rmt_app;
        REVOKE DELETE, TRUNCATE ON run_record FROM rmt_app;
    END IF;
END
$$;
