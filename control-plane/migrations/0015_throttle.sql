-- 0015_throttle.sql — shared online-guessing counters (store-backed Throttle).
--
-- throttle.go's counters were per-process, so a multi-replica deployment divided the effective
-- login/TOTP/redeem budget by the replica count (each replica granted its own FreeAttempts).
-- This table is the shared budget every replica meters against (PgThrottleStore,
-- pgstore_throttle.go). The THROTTLE POLICY (free attempts, doubling backoff, caps) stays in Go —
-- the table stores only key → (failures, last_failure, locked_until).
--
-- DELIBERATELY NO RLS and NO tenant_id: throttle keys are pre-tenant by nature — login keys embed
-- the RAW request slug (no tenant is resolved yet, and an unresolvable slug still consumes
-- budget), and per-IP keys have no tenant at all. The rows carry only failure counters keyed by
-- namespaced strings ("login:acct:…", "redeem:ip:…"); rmt_app reads/writes them directly on the
-- pool (no bound tenant connection exists on these public paths). Long keys are stored as a
-- SHA-256 digest form by the Go store, bounding row/index width against attacker-minted keys.
--
-- Expiry is a WHERE-clause predicate + opportunistic DELETE (the repo has no background reaper):
-- an entry idle past the configured Reset with no live lock is semantically absent — Bump
-- restarts it at 1, and Cleanup (run on the metered failure path) deletes such rows.

CREATE TABLE throttle_counter (
    key          text PRIMARY KEY,
    failures     integer     NOT NULL DEFAULT 0,
    last_failure timestamptz NOT NULL,
    locked_until timestamptz           -- NULL = no live lockout
);

-- Cleanup scan: DELETE ... WHERE last_failure < $stale (AND lock expired).
CREATE INDEX idx_throttle_counter_idle ON throttle_counter (last_failure);

-- rmt_app operates the counters directly. Explicit grant (belt-and-suspenders over 0005's
-- default privileges), guarded so this file also applies to a schema without the role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON throttle_counter TO rmt_app;
    END IF;
END
$$;
