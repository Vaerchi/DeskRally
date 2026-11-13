-- 0032_machine_alias.sql — a tenant-chosen friendly NAME for a machine (docs/01 §4).
--
-- The agent reports its hostname into machine.hostname (Machine.Name), which is immutable from the
-- console. This adds a separate, tenant-OWNED display label the console prefers when set — a "friendly
-- name" the way ScreenConnect lets you rename a machine — without ever overwriting the reported
-- hostname (so a re-enrollment that refreshes the hostname does not clobber the operator's label).
-- NOT NULL DEFAULT '' so every existing row is valid without a backfill and the pg projection can scan
-- the column unconditionally; an EMPTY alias means "show the hostname". machine already carries
-- tenant_id and its RLS policy (0001_core.sql), so the alias inherits tenant isolation with no new
-- policy. The column is part of PgMachineStore's SELECT projections, so this migration is applied WITH
-- the core in the test harness (like 0017/0018/0031), not opt-in per test.

ALTER TABLE machine ADD COLUMN alias text NOT NULL DEFAULT '';
