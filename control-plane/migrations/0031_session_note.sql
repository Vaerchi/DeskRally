-- 0031_session_note.sql — a free-text operator NOTE on a remote-support session (docs/01 §7).
--
-- One note per session_record (an annotation for handoffs / audit context), settable by a
-- session operator after the fact. NOT NULL DEFAULT '' so every existing row is valid without a
-- backfill and the pg projection can scan the column unconditionally. session_record already
-- carries tenant_id and its RLS policy (0001_core.sql), so the note inherits tenant isolation with
-- no new policy. The column is part of PgSessionRecordStore's SELECT projection, so this migration
-- is applied WITH the core in the test harness (like 0017/0018), not opt-in per test.

ALTER TABLE session_record ADD COLUMN note text NOT NULL DEFAULT '';
