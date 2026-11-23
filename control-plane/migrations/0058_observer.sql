-- 0058: View-only observers (accepted design v1 + v2).
-- Preset capabilities mirror rbac.go; custom roles must opt in explicitly.
UPDATE role
   SET capabilities = array_append(capabilities, 'observe_session')
 WHERE tenant_id IS NULL
   AND 'start_session' = ANY(capabilities)
   AND NOT ('observe_session' = ANY(capabilities));

-- Access belongs to the session, independently of the machine's current group mandate.
-- Existing sessions retain their legacy control admission mode.
ALTER TABLE session_record
    ADD COLUMN IF NOT EXISTS access text NOT NULL DEFAULT 'control';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'session_record'::regclass
                     AND conname = 'session_record_access_check') THEN
        ALTER TABLE session_record ADD CONSTRAINT session_record_access_check
            CHECK (access IN ('control', 'view_only'));
    END IF;
END
$$;

-- Supports the observer count under the existing tenant start lock. Existing session_record
-- RLS and grants cover the column; no new tenant access or mutation path is introduced.
CREATE INDEX IF NOT EXISTS session_record_open_observers
    ON session_record (tenant_id, machine_id)
    WHERE ended_at IS NULL AND access = 'view_only';
