-- 0033_machine_note.sql — a free-text operator NOTE on a machine (docs/01 §4).
--
-- One free-text annotation per machine (operator context / handoff: "RAID degraded, monitor", "CEO's
-- laptop — handle with care"). Distinct from machine.alias (a short display NAME, migrations/0032) and
-- from machine_property (structured key/value, migrations/0024) — this is unstructured prose. NOT NULL
-- DEFAULT '' so every existing row is valid without a backfill and the pg projection can scan the column
-- unconditionally; an EMPTY note means "no note". machine already carries tenant_id and its RLS policy
-- (0001_core.sql), so the note inherits tenant isolation with no new policy. The column is part of
-- PgMachineStore's SELECT projections, so this migration is applied WITH the core in the test harness
-- (like 0017/0018/0031/0032), not opt-in per test. Set via PATCH /machines/{id}/note (CapManageMachines).

ALTER TABLE machine ADD COLUMN note text NOT NULL DEFAULT '';
